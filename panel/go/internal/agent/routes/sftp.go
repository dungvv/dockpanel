package routes

// Agent-side endpoints for per-site SFTP accounts (GH #108). Thin: the
// provisioning/teardown logic lives in services/sftp_accounts.go.

import (
	"net/http"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type sftpEnableRequest struct {
	UID int32 `json:"uid"`
	GID int32 `json:"gid"`
}

type sftpDisableRequest struct {
	UID int32 `json:"uid"`
	GID int32 `json:"gid"`
	// Decided by the backend from the sites table, never re-derived here.
	LastSftpSite bool `json:"last_sftp_site"`
}

type sftpSetPasswordRequest struct {
	UID      int32  `json:"uid"`
	Password string `json:"password"`
}

// sftpEnable: POST /sftp/sites/{domain}/enable.
func sftpEnable(w http.ResponseWriter, r *http.Request) {
	var b sftpEnableRequest
	if !nginxDecodeStrict(w, r, &b, "uid", "gid") {
		return
	}
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	if err := services.SftpAccountsProvision(domain, b.UID, b.GID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// sftpDisable: POST /sftp/sites/{domain}/disable.
func sftpDisable(w http.ResponseWriter, r *http.Request) {
	var b sftpDisableRequest
	if !nginxDecodeStrict(w, r, &b, "uid", "gid", "last_sftp_site") {
		return
	}
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	if err := services.SftpAccountsDeprovision(domain, b.UID, b.GID, b.LastSftpSite); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// sftpSetPassword: POST /sftp/sites/{domain}/password.
func sftpSetPassword(w http.ResponseWriter, r *http.Request) {
	var b sftpSetPasswordRequest
	if !nginxDecodeStrict(w, r, &b, "uid", "password") {
		return
	}
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	if len(b.Password) < 12 { // bytes, like Rust's str::len
		writeErr(w, http.StatusBadRequest, "Password must be at least 12 characters")
		return
	}
	if err := services.SftpAccountsSetPassword(b.UID, b.Password); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// registerSftp mounts src/routes/sftp.rs.
func registerSftp(r *Router) {
	r.Handle("POST /sftp/sites/{domain}/enable", sftpEnable)
	r.Handle("POST /sftp/sites/{domain}/disable", sftpDisable)
	r.Handle("POST /sftp/sites/{domain}/password", sftpSetPassword)
}
