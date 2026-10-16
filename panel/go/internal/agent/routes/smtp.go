package routes

import (
	"net/http"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type smtpConfigureRequest struct {
	Host       string  `json:"host"`
	Port       uint16  `json:"port"`
	Username   string  `json:"username"`
	Password   string  `json:"password"`
	From       string  `json:"from"`
	FromName   *string `json:"from_name"`
	Encryption *string `json:"encryption"`
}

type smtpTestRequest struct {
	To       string  `json:"to"`
	From     string  `json:"from"`
	FromName *string `json:"from_name"`
}

func registerSmtp(r *Router) {
	r.Handle("POST /smtp/configure", smtpConfigure)
	r.Handle("POST /smtp/test", smtpTestEmail)
}

func smtpOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

// smtpConfigure: POST /smtp/configure — write msmtp config and PHP sendmail path.
func smtpConfigure(w http.ResponseWriter, r *http.Request) {
	var b smtpConfigureRequest
	if !securityDecodeStrict(w, r, &b, "host", "port", "username", "password", "from") {
		return
	}
	if b.Host == "" {
		writeErr(w, http.StatusBadRequest, "Host is required")
		return
	}
	if err := services.SmtpConfigure(b.Host, b.Port, b.Username, b.Password, b.From,
		smtpOr(b.FromName, "DockPanel"), smtpOr(b.Encryption, "starttls")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// smtpTestEmail: POST /smtp/test — send a test email.
func smtpTestEmail(w http.ResponseWriter, r *http.Request) {
	var b smtpTestRequest
	if !securityDecodeStrict(w, r, &b, "to", "from") {
		return
	}
	if b.To == "" || !strings.Contains(b.To, "@") {
		writeErr(w, http.StatusBadRequest, "Valid email address required")
		return
	}
	msg, err := services.SmtpSendTest(b.To, b.From, smtpOr(b.FromName, "DockPanel"))
	if err != nil {
		// A host with no msmtp is a precondition, not a fault; the panel only
		// preserves the sentence when the status says so.
		status := http.StatusInternalServerError
		if err.Error() == services.SmtpMsmtpMissing {
			status = http.StatusFailedDependency
		} else if strings.Contains(err.Error(), "must not contain newlines") {
			status = http.StatusBadRequest
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}
