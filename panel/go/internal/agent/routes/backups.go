package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/sitelock"
)

// BackupsSiteDbBody is the optional create/restore body naming the site's
// databases. The agent cannot resolve these itself (no access to the panel's
// databases table), so the backend passes them with decrypted credentials.
// Absent body ⇒ files only, exactly as before.
type BackupsSiteDbBody struct {
	Databases []services.BackupsDbSpec `json:"databases"`
}

// BackupsRestoreFileRequest is POST /backups/{domain}/restore-file/{filename}.
type BackupsRestoreFileRequest struct {
	Path string `json:"path"`
}

func registerBackups(r *Router) {
	r.Handle("POST /backups/{domain}/create", backupsCreate)
	r.Handle("GET /backups/{domain}/list", backupsList)
	r.Handle("GET /backups/{domain}/browse/{filename}", backupsBrowse)
	r.Handle("POST /backups/{domain}/restore/{filename}", backupsRestore)
	r.Handle("POST /backups/{domain}/restore-file/{filename}", backupsRestoreFile)
	r.Handle("DELETE /backups/{domain}/{filename}", backupsRemove)
}

// backupsOptionalDbBody mirrors axum's Option<Json<T>>: no Content-Type ⇒
// None (files only); otherwise the body must be valid JSON of the right
// shape, and each database entry needs every non-default serde field.
func backupsOptionalDbBody(w http.ResponseWriter, r *http.Request) ([]services.BackupsDbSpec, bool) {
	if r.Header.Get("Content-Type") == "" {
		return nil, true
	}
	var raw json.RawMessage
	if !decodeJSON(w, r, &raw) {
		return nil, false
	}
	fail := func(msg string) ([]services.BackupsDbSpec, bool) {
		http.Error(w, "Failed to deserialize the JSON body into the target type: "+msg, http.StatusUnprocessableEntity)
		return nil, false
	}
	var shape struct {
		Databases []map[string]json.RawMessage `json:"databases"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return fail(err.Error())
	}
	for _, d := range shape.Databases {
		for _, k := range []string{"container_name", "db_name", "db_type", "user"} {
			if v, ok := d[k]; !ok || strings.TrimSpace(string(v)) == "null" {
				return fail(fmt.Sprintf("databases: missing field `%s`", k))
			}
		}
	}
	var body BackupsSiteDbBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return fail(err.Error())
	}
	return body.Databases, true
}

// backupsCreate: POST /backups/{domain}/create.
func backupsCreate(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	dbs, ok := backupsOptionalDbBody(w, r)
	if !ok {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	info, err := services.BackupsCreateBackup(domain, dbs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// backupsList: GET /backups/{domain}/list.
func backupsList(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	list, err := services.BackupsListBackups(domain)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// backupsRestore: POST /backups/{domain}/restore/{filename}.
//
// Files back but a database not is reported as a FAILURE (500) carrying the
// full report — the site's files have already been replaced and the
// operator has to know.
func backupsRestore(w http.ResponseWriter, r *http.Request) {
	domain, filename := r.PathValue("domain"), r.PathValue("filename")
	dbs, ok := backupsOptionalDbBody(w, r)
	if !ok {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	// Held through the extraction+chown: a restore must not interleave with
	// e.g. a concurrent hardening apply on the same site's files.
	defer sitelock.LockSite(domain)()

	report, err := services.BackupsRestoreBackup(domain, filename, dbs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The --no-same-owner extraction leaves the site root:root — unwritable
	// by the www-data app until this runs.
	backupsChownRestoredTree("/var/www/" + domain)

	payload := map[string]any{
		"files_restored":       report.FilesRestored,
		"databases_in_archive": report.DatabasesInArchive,
		"databases_restored":   report.DatabasesRestored,
		"databases_failed":     report.DatabasesFailed,
		"success":              report.Ok(),
	}
	if !report.Ok() {
		// A plain-language summary under the key every client reads for
		// errors, so a caller that only prints `error` still gets the reason.
		parts := make([]string, 0, len(report.DatabasesFailed))
		for _, f := range report.DatabasesFailed {
			parts = append(parts, f.DbName+": "+f.Error)
		}
		detail := strings.Join(parts, "; ")
		if report.FilesRestored {
			payload["error"] = fmt.Sprintf("The site's files were restored, but %d database(s) were NOT: %s", len(report.DatabasesFailed), detail)
		} else {
			payload["error"] = "Restore failed: " + detail
		}
		writeJSON(w, http.StatusInternalServerError, payload)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

// backupsBrowse: GET /backups/{domain}/browse/{filename} — list archive members.
func backupsBrowse(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	files, err := services.BackupsListBackupFiles(domain, r.PathValue("filename"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files, "count": len(files)})
}

// backupsRestoreFile: POST /backups/{domain}/restore-file/{filename}.
func backupsRestoreFile(w http.ResponseWriter, r *http.Request) {
	domain, filename := r.PathValue("domain"), r.PathValue("filename")
	var body BackupsRestoreFileRequest
	if !securityDecodeStrict(w, r, &body, "path") {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	// Held through extraction+chown, same as backupsRestore.
	defer sitelock.LockSite(domain)()

	if err := services.BackupsRestoreSingleFile(domain, filename, body.Path); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Same gap as backupsRestore — the extracted member comes back root-owned.
	backupsChownRestoredTree("/var/www/" + domain)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "restored_path": body.Path})
}

// backupsRemove: DELETE /backups/{domain}/{filename}.
func backupsRemove(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	if err := services.BackupsDeleteBackup(domain, r.PathValue("filename")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// backupsChownRestoredTree hands a restored site back to the web server
// without exposing .git. A blanket `chown -R www-data` would also hand the
// app .git/config and .git/hooks, which the next git deploy reads and
// executes as root. So: everything except .git to www-data, then .git
// explicitly re-secured to root.
func backupsChownRestoredTree(target string) {
	ctx := context.Background()
	if entries, err := os.ReadDir(target); err == nil {
		for _, e := range entries {
			if e.Name() == ".git" {
				continue
			}
			_, _ = safecmd.Exec(ctx, "chown", "-R", "www-data:www-data", filepath.Join(target, e.Name()))
		}
	}
	gitDir := target + "/.git"
	if _, err := os.Stat(gitDir); err == nil {
		_, _ = safecmd.Exec(ctx, "chown", "-R", "root:root", gitDir)
		_, _ = safecmd.Exec(ctx, "chmod", "-R", "go-rwx", gitDir)
	}
}
