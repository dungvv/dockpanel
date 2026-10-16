package routes

import (
	"net/http"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// BackupVerifySiteRequest is POST /backups/verify/site.
type BackupVerifySiteRequest struct {
	Domain   string `json:"domain"`
	Filename string `json:"filename"`
}

// BackupVerifyDbRequest is POST /backups/verify/database.
type BackupVerifyDbRequest struct {
	DbType   string `json:"db_type"`
	DbName   string `json:"db_name"`
	Filename string `json:"filename"`
}

// BackupVerifyVolumeRequest is POST /backups/verify/volume.
type BackupVerifyVolumeRequest struct {
	ContainerName string `json:"container_name"`
	Filename      string `json:"filename"`
}

func registerBackupVerify(r *Router) {
	r.Handle("POST /backups/verify/site", backupVerifySite)
	r.Handle("POST /backups/verify/database", backupVerifyDatabase)
	r.Handle("POST /backups/verify/volume", backupVerifyVolume)
}

// backupVerifyFilenameOK: non-empty, no "..", no "/".
func backupVerifyFilenameOK(f string) bool {
	return f != "" && !strings.Contains(f, "..") && !strings.Contains(f, "/")
}

// backupVerifySite: POST /backups/verify/site.
func backupVerifySite(w http.ResponseWriter, r *http.Request) {
	var req BackupVerifySiteRequest
	if !securityDecodeStrict(w, r, &req, "domain", "filename") {
		return
	}
	if !isValidDomain(req.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	if !backupVerifyFilenameOK(req.Filename) {
		writeErr(w, http.StatusBadRequest, "Invalid filename")
		return
	}
	res, err := services.BackupVerifyVerifySiteBackup(req.Domain, req.Filename)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// backupVerifyDatabase: POST /backups/verify/database — restore into a temp container.
func backupVerifyDatabase(w http.ResponseWriter, r *http.Request) {
	var req BackupVerifyDbRequest
	if !securityDecodeStrict(w, r, &req, "db_type", "db_name", "filename") {
		return
	}
	res, err := services.BackupVerifyVerifyDbBackup(req.DbType, req.DbName, req.Filename)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// backupVerifyVolume: POST /backups/verify/volume.
func backupVerifyVolume(w http.ResponseWriter, r *http.Request) {
	var req BackupVerifyVolumeRequest
	if !securityDecodeStrict(w, r, &req, "container_name", "filename") {
		return
	}
	res, err := services.BackupVerifyVerifyVolumeBackup(req.ContainerName, req.Filename)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
