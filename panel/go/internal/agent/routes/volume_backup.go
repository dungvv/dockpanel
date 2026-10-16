package routes

import (
	"net/http"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// VolumeBackupRequest is POST /volume-backups/create.
type VolumeBackupRequest struct {
	VolumeName    string `json:"volume_name"`
	ContainerName string `json:"container_name"`
}

// VolumeBackupRestoreRequest is POST /volume-backups/{container_name}/restore/{filename}.
type VolumeBackupRestoreRequest struct {
	VolumeName string `json:"volume_name"`
}

func registerVolumeBackup(r *Router) {
	r.Handle("POST /volume-backups/create", volumeBackupCreate)
	r.Handle("GET /volume-backups/{container_name}/list", volumeBackupList)
	r.Handle("POST /volume-backups/{container_name}/restore/{filename}", volumeBackupRestore)
	r.Handle("DELETE /volume-backups/{container_name}/{filename}", volumeBackupRemove)
}

// volumeBackupCreate: POST /volume-backups/create — back up a Docker volume.
func volumeBackupCreate(w http.ResponseWriter, r *http.Request) {
	var req VolumeBackupRequest
	if !securityDecodeStrict(w, r, &req, "volume_name", "container_name") {
		return
	}
	switch {
	case req.VolumeName == "" || req.ContainerName == "":
		writeErr(w, http.StatusBadRequest, "volume_name and container_name required")
		return
	// Validate names: injection / path traversal.
	case !isValidName(req.VolumeName):
		writeErr(w, http.StatusBadRequest, "Invalid volume name")
		return
	case !isValidName(req.ContainerName):
		writeErr(w, http.StatusBadRequest, "Invalid container name")
		return
	}
	info, err := services.VolumeBackupBackupVolume(req.VolumeName, req.ContainerName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// volumeBackupList: GET /volume-backups/{container_name}/list.
func volumeBackupList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("container_name")
	if !isValidName(name) {
		writeErr(w, http.StatusBadRequest, "Invalid container name")
		return
	}
	list, err := services.VolumeBackupListVolumeBackups(name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// volumeBackupRestore: POST /volume-backups/{container_name}/restore/{filename}.
func volumeBackupRestore(w http.ResponseWriter, r *http.Request) {
	name, filename := r.PathValue("container_name"), r.PathValue("filename")
	var req VolumeBackupRestoreRequest
	if !securityDecodeStrict(w, r, &req, "volume_name") {
		return
	}
	if !isValidName(name) {
		writeErr(w, http.StatusBadRequest, "Invalid container name")
		return
	}
	if !isValidName(req.VolumeName) {
		writeErr(w, http.StatusBadRequest, "Invalid volume name")
		return
	}
	if err := services.VolumeBackupRestoreVolume(req.VolumeName, name, filename); err != nil {
		// The panel lists archives from its own DB while they live on another
		// host, so "gone since you were shown it" is an expected disagreement,
		// not an agent fault — a 5xx would arrive as an incident id.
		status := http.StatusInternalServerError
		switch err.Error() {
		case "Backup file not found":
			status = http.StatusNotFound
		case "Invalid backup filename":
			status = http.StatusBadRequest
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// volumeBackupRemove: DELETE /volume-backups/{container_name}/{filename}.
func volumeBackupRemove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("container_name")
	if !isValidName(name) {
		writeErr(w, http.StatusBadRequest, "Invalid container name")
		return
	}
	if err := services.VolumeBackupDeleteVolumeBackup(name, r.PathValue("filename")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}
