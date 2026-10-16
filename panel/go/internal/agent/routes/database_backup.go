package routes

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// DatabaseBackupDumpRequest is POST /db-backups/dump.
type DatabaseBackupDumpRequest struct {
	ContainerName string  `json:"container_name"`
	DbName        string  `json:"db_name"`
	DbType        string  `json:"db_type"`
	User          string  `json:"user"`
	Password      string  `json:"password"`
	EncryptionKey *string `json:"encryption_key"`
}

// DatabaseBackupRestoreRequest is POST /db-backups/{db_name}/restore/{filename}.
type DatabaseBackupRestoreRequest struct {
	ContainerName string  `json:"container_name"`
	DbType        string  `json:"db_type"`
	User          string  `json:"user"`
	Password      string  `json:"password"`
	EncryptionKey *string `json:"encryption_key"`
}

func registerDatabaseBackup(r *Router) {
	r.Handle("POST /db-backups/dump", databaseBackupDump)
	// `dump` is a legal database name. Go's mux falls through to the
	// {db_name} pattern for DELETE /db-backups/dump (axum needed an explicit
	// static-path delete there), so the purge answers it with db_name="dump".
	r.Handle("DELETE /db-backups/{db_name}", databaseBackupPurge)
	r.Handle("GET /db-backups/{db_name}/list", databaseBackupList)
	r.Handle("DELETE /db-backups/{db_name}/{filename}", databaseBackupRemove)
	r.Handle("GET /db-backups/{db_name}/{filename}/path", databaseBackupGetPath)
	r.Handle("POST /db-backups/{db_name}/restore/{filename}", databaseBackupRestore)
}

// databaseBackupPasswordOK: ≤128 bytes, no NUL/CR/LF (empty allowed here).
func databaseBackupPasswordOK(pw string) bool {
	return len(pw) <= 128 && !strings.ContainsAny(pw, "\x00\n\r")
}

// databaseBackupDump: POST /db-backups/dump — dump a database.
func databaseBackupDump(w http.ResponseWriter, r *http.Request) {
	var req DatabaseBackupDumpRequest
	if !securityDecodeStrict(w, r, &req, "container_name", "db_name", "db_type", "user", "password") {
		return
	}
	// The dump-directory predicate (shared with every door onto that
	// directory) is a superset of the generic validator, so nothing this door
	// used to accept is refused. Container and user keep the generic one.
	switch {
	case !services.DatabaseBackupIsDbDirName(req.DbName):
		writeErr(w, http.StatusBadRequest, "Invalid database name")
		return
	case !isValidName(req.ContainerName):
		writeErr(w, http.StatusBadRequest, "Invalid container name")
		return
	case !isValidName(req.User):
		writeErr(w, http.StatusBadRequest, "Invalid user name")
		return
	case !databaseBackupPasswordOK(req.Password):
		writeErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	var info services.BackupsBackupInfo
	var err error
	switch req.DbType {
	case "mysql", "mariadb":
		info, err = services.DatabaseBackupDumpMysql(req.ContainerName, req.DbName, req.User, req.Password)
	case "postgres", "postgresql":
		info, err = services.DatabaseBackupDumpPostgres(req.ContainerName, req.DbName, req.User, req.Password)
	case "mongo", "mongodb":
		info, err = services.DatabaseBackupDumpMongo(req.ContainerName, req.DbName)
	default:
		writeErr(w, http.StatusBadRequest, "Unsupported database type")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Encrypt if a key was provided (same byte format as the Rust agent).
	if req.EncryptionKey != nil && *req.EncryptionKey != "" {
		fpath, err := services.DatabaseBackupGetBackupPath(req.DbName, info.Filename)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		encPath, err := services.EncryptionEncryptFile(fpath, *req.EncryptionKey)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		fi, err := os.Stat(encPath)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Encrypted file: %v", err))
			return
		}
		info.Filename += ".enc"
		info.SizeBytes = uint64(fi.Size())
	}
	writeJSON(w, http.StatusOK, info)
}

// databaseBackupList: GET /db-backups/{db_name}/list.
func databaseBackupList(w http.ResponseWriter, r *http.Request) {
	dbName := r.PathValue("db_name")
	if !services.DatabaseBackupIsDbDirName(dbName) {
		writeErr(w, http.StatusBadRequest, "Invalid database name")
		return
	}
	list, err := services.DatabaseBackupListDbBackups(dbName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// databaseBackupRemove: DELETE /db-backups/{db_name}/{filename}.
func databaseBackupRemove(w http.ResponseWriter, r *http.Request) {
	dbName := r.PathValue("db_name")
	if !services.DatabaseBackupIsDbDirName(dbName) {
		writeErr(w, http.StatusBadRequest, "Invalid database name")
		return
	}
	if err := services.DatabaseBackupDeleteDbBackup(dbName, r.PathValue("filename")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// databaseBackupRestore: POST /db-backups/{db_name}/restore/{filename}.
func databaseBackupRestore(w http.ResponseWriter, r *http.Request) {
	dbName, filename := r.PathValue("db_name"), r.PathValue("filename")
	var req DatabaseBackupRestoreRequest
	if !securityDecodeStrict(w, r, &req, "container_name", "db_type", "user", "password") {
		return
	}
	switch {
	case !services.DatabaseBackupIsDbDirName(dbName):
		writeErr(w, http.StatusBadRequest, "Invalid database name")
		return
	case !isValidName(req.ContainerName):
		writeErr(w, http.StatusBadRequest, "Invalid container name")
		return
	case !isValidName(req.User):
		writeErr(w, http.StatusBadRequest, "Invalid user name")
		return
	case !databaseBackupPasswordOK(req.Password):
		writeErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	fpath, err := services.DatabaseBackupGetBackupPath(dbName, filename)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	// Decrypt first if the file is encrypted.
	restorePath := fpath
	if strings.HasSuffix(fpath, ".enc") {
		if req.EncryptionKey == nil || *req.EncryptionKey == "" {
			writeErr(w, http.StatusBadRequest, "Encryption key required for encrypted backup")
			return
		}
		restorePath, err = services.EncryptionDecryptFile(fpath, *req.EncryptionKey)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	switch req.DbType {
	case "mysql", "mariadb":
		err = services.DatabaseBackupRestoreMysql(req.ContainerName, dbName, req.User, req.Password, restorePath)
	case "postgres", "postgresql":
		err = services.DatabaseBackupRestorePostgres(req.ContainerName, dbName, req.User, req.Password, restorePath)
	case "mongo", "mongodb":
		err = services.DatabaseBackupRestoreMongo(req.ContainerName, dbName, restorePath)
	default:
		err = fmt.Errorf("Unsupported database type")
	}
	// Clean up the decrypted temp file if we created one.
	if restorePath != fpath {
		os.Remove(restorePath)
	}
	// ⛔ 422, not 500: everything that fails here fails because of the FILE the
	// caller named (truncated, never gzipped, wrong engine, SQL the database
	// rejects). The panel keeps an agent's sentence only for 4xx; a 500 turned
	// psql's "relation already exists" into an incident id.
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "db_name": dbName, "filename": filename, "db_type": req.DbType,
	})
}

// databaseBackupGetPath: GET /db-backups/{db_name}/{filename}/path.
func databaseBackupGetPath(w http.ResponseWriter, r *http.Request) {
	dbName := r.PathValue("db_name")
	if !services.DatabaseBackupIsDbDirName(dbName) {
		writeErr(w, http.StatusBadRequest, "Invalid database name")
		return
	}
	p, err := services.DatabaseBackupGetBackupPath(dbName, r.PathValue("filename"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"path": p})
}

// databaseBackupPurge: DELETE /db-backups/{db_name} — drop a dump directory
// nothing owns any more. Whether it is unowned is the PANEL's question (the
// name is unique only per site); this end answers only for what it did.
func databaseBackupPurge(w http.ResponseWriter, r *http.Request) {
	dbName := r.PathValue("db_name")
	if !services.DatabaseBackupIsDbDirName(dbName) {
		writeErr(w, http.StatusBadRequest, "Invalid database name")
		return
	}
	rep, err := services.DatabaseBackupPurgeDir(dbName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": rep.Removed, "kept": rep.Kept, "dir_removed": rep.DirRemoved})
}
