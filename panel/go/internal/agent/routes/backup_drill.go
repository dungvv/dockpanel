package routes

import (
	"net/http"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// BackupDrillSiteRequest is POST /backups/drill/site.
type BackupDrillSiteRequest struct {
	Domain   string `json:"domain"`
	Filename string `json:"filename"`
}

// BackupDrillDbRequest is POST /backups/drill/db.
type BackupDrillDbRequest struct {
	DbType   string `json:"db_type"`
	DbName   string `json:"db_name"`
	Filename string `json:"filename"`
}

// BackupDrillVolumeRequest is POST /backups/drill/volume.
type BackupDrillVolumeRequest struct {
	ContainerName string `json:"container_name"`
	Filename      string `json:"filename"`
}

func registerBackupDrill(r *Router) {
	r.Handle("POST /backups/drill/site", backupDrillSite)
	r.Handle("POST /backups/drill/db", backupDrillDb)
	r.Handle("POST /backups/drill/volume", backupDrillVolume)
}

// backupDrillSite: POST /backups/drill/site — end-to-end site drill.
func backupDrillSite(w http.ResponseWriter, r *http.Request) {
	var req BackupDrillSiteRequest
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
	res, err := services.BackupDrillDrillSiteBackup(req.Domain, req.Filename)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// backupDrillDb: POST /backups/drill/db — scratch engine + full restore + row probe.
func backupDrillDb(w http.ResponseWriter, r *http.Request) {
	var req BackupDrillDbRequest
	if !securityDecodeStrict(w, r, &req, "db_type", "db_name", "filename") {
		return
	}
	// Whitelist mirrors the engines we know how to spin.
	switch req.DbType {
	case "mysql", "mariadb", "postgres", "postgresql":
	default:
		writeErr(w, http.StatusBadRequest, "Unsupported db_type")
		return
	}
	res, err := services.BackupDrillDrillDbBackup(req.DbType, req.DbName, req.Filename)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// backupDrillVolume: POST /backups/drill/volume — scratch volume + restore + read-test probe.
func backupDrillVolume(w http.ResponseWriter, r *http.Request) {
	var req BackupDrillVolumeRequest
	if !securityDecodeStrict(w, r, &req, "container_name", "filename") {
		return
	}
	if req.ContainerName == "" || req.Filename == "" {
		writeErr(w, http.StatusBadRequest, "container_name and filename required")
		return
	}
	res, err := services.BackupDrillDrillVolumeBackup(req.ContainerName, req.Filename)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
