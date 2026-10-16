package routes

import (
	"net/http"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type wordpressInstallRequest struct {
	URL        string `json:"url"`
	Title      string `json:"title"`
	AdminUser  string `json:"admin_user"`
	AdminPass  string `json:"admin_pass"`
	AdminEmail string `json:"admin_email"`
	DbName     string `json:"db_name"`
	DbUser     string `json:"db_user"`
	DbPass     string `json:"db_pass"`
	DbHost     string `json:"db_host"`
}

func registerWordpress(r *Router) {
	r.Handle("GET /wordpress/{domain}/detect", wordpressDetect)
	r.Handle("GET /wordpress/{domain}/info", wordpressInfo)
	r.Handle("GET /wordpress/{domain}/plugins", wordpressPlugins)
	r.Handle("GET /wordpress/{domain}/themes", wordpressThemes)
	r.Handle("POST /wordpress/{domain}/install", wordpressInstall)
	r.Handle("POST /wordpress/{domain}/promote-https", wordpressPromoteHttps)
	r.Handle("POST /wordpress/{domain}/update/{target}", wordpressUpdate)
	r.Handle("POST /wordpress/{domain}/plugin/{action}", wordpressPluginAction)
	r.Handle("POST /wordpress/{domain}/theme/{action}", wordpressThemeAction)
	r.Handle("GET /wordpress/{domain}/auto-update", wordpressGetAutoUpdate)
	r.Handle("POST /wordpress/{domain}/auto-update", wordpressSetAutoUpdate)
	r.Handle("POST /wordpress/{domain}/vuln-scan", wordpressVulnScan)
	r.Handle("GET /wordpress/{domain}/security-check", wordpressSecurityCheck)
	r.Handle("POST /wordpress/{domain}/harden", wordpressHarden)
	r.Handle("POST /wordpress/{domain}/update-with-rollback", wordpressUpdateWithRollback)
}

// wordpressDomain validates the path domain, writing 400 on failure. Handlers
// with a body decode it FIRST: axum runs the Json extractor before the handler.
func wordpressDomain(w http.ResponseWriter, r *http.Request) (string, bool) {
	d := r.PathValue("domain")
	if !isValidDomain(d) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return "", false
	}
	return d, true
}

// wordpressReply writes v (200) or the error with errStatus.
func wordpressReply(w http.ResponseWriter, v any, err error, errStatus int) {
	if err != nil {
		writeErr(w, errStatus, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func wordpressOkMsg(msg string) map[string]any { return map[string]any{"ok": true, "message": msg} }

func wordpressDetect(w http.ResponseWriter, r *http.Request) {
	if d, ok := wordpressDomain(w, r); ok {
		writeJSON(w, http.StatusOK, map[string]bool{"detected": services.WordpressDetect(d)})
	}
}

func wordpressInfo(w http.ResponseWriter, r *http.Request) {
	d, ok := wordpressDomain(w, r)
	if !ok {
		return
	}
	if !services.WordpressDetect(d) {
		writeJSON(w, http.StatusOK, map[string]bool{"installed": false})
		return
	}
	v, err := services.WordpressInfo(d)
	wordpressReply(w, v, err, http.StatusInternalServerError)
}

func wordpressPlugins(w http.ResponseWriter, r *http.Request) {
	if d, ok := wordpressDomain(w, r); ok {
		v, err := services.WordpressPlugins(d)
		wordpressReply(w, v, err, http.StatusInternalServerError)
	}
}

func wordpressThemes(w http.ResponseWriter, r *http.Request) {
	if d, ok := wordpressDomain(w, r); ok {
		v, err := services.WordpressThemes(d)
		wordpressReply(w, v, err, http.StatusInternalServerError)
	}
}

// wordpressPromoteHttps: POST /wordpress/{domain}/promote-https.
//
// SslEnableSslForSite already promotes sites that exist when their cert
// arrives; this covers a cert that landed mid-install. The target URL is
// derived from the path domain, never accepted from the caller — a settable
// siteurl is a site-takeover primitive.
func wordpressPromoteHttps(w http.ResponseWriter, r *http.Request) {
	d, ok := wordpressDomain(w, r)
	if !ok {
		return
	}
	outcome := services.WordpressPromoteSiteUrlToHttps(d)
	if msg, failed := outcome.Failure(); failed {
		writeErr(w, http.StatusInternalServerError, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"canonical_url": outcome})
}

func wordpressInstall(w http.ResponseWriter, r *http.Request) {
	var b wordpressInstallRequest
	if !securityDecodeStrict(w, r, &b, "url", "title", "admin_user", "admin_pass", "admin_email", "db_name", "db_user", "db_pass", "db_host") {
		return
	}
	d, ok := wordpressDomain(w, r)
	if !ok {
		return
	}
	msg, err := services.WordpressInstall(d, b.URL, b.Title, b.AdminUser, b.AdminPass, b.AdminEmail, b.DbName, b.DbUser, b.DbPass, b.DbHost)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, wordpressOkMsg(msg))
}

func wordpressUpdate(w http.ResponseWriter, r *http.Request) {
	d, ok := wordpressDomain(w, r)
	if !ok {
		return
	}
	var fn func(string) (string, error)
	switch r.PathValue("target") {
	case "core":
		fn = services.WordpressUpdateCore
	case "plugins":
		fn = services.WordpressUpdateAllPlugins
	case "themes":
		fn = services.WordpressUpdateAllThemes
	default:
		writeErr(w, http.StatusUnprocessableEntity, "Invalid target. Use: core, plugins, themes")
		return
	}
	msg, err := fn(d)
	wordpressReply(w, wordpressOkMsg(msg), err, http.StatusUnprocessableEntity)
}

func wordpressSlugAction(w http.ResponseWriter, r *http.Request, fn func(domain, name, action string) (string, error)) {
	var b struct {
		Name string `json:"name"`
	}
	if !securityDecodeStrict(w, r, &b, "name") {
		return
	}
	d, ok := wordpressDomain(w, r)
	if !ok {
		return
	}
	msg, err := fn(d, b.Name, r.PathValue("action"))
	wordpressReply(w, wordpressOkMsg(msg), err, http.StatusUnprocessableEntity)
}

func wordpressPluginAction(w http.ResponseWriter, r *http.Request) {
	wordpressSlugAction(w, r, services.WordpressPluginAction)
}

func wordpressThemeAction(w http.ResponseWriter, r *http.Request) {
	wordpressSlugAction(w, r, services.WordpressThemeAction)
}

func wordpressGetAutoUpdate(w http.ResponseWriter, r *http.Request) {
	if d, ok := wordpressDomain(w, r); ok {
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": services.WordpressIsAutoUpdateEnabled(d)})
	}
}

func wordpressSetAutoUpdate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled bool `json:"enabled"`
	}
	if !securityDecodeStrict(w, r, &b, "enabled") {
		return
	}
	d, ok := wordpressDomain(w, r)
	if !ok {
		return
	}
	err := services.WordpressSetAutoUpdate(d, b.Enabled)
	wordpressReply(w, map[string]bool{"ok": true}, err, http.StatusInternalServerError)
}

// wordpressVulnScan: POST /wordpress/{domain}/vuln-scan. Errors are 422: the
// panel passes an agent's sentence through only on a 4xx and replaces
// anything else with an incident reference.
func wordpressVulnScan(w http.ResponseWriter, r *http.Request) {
	if d, ok := wordpressDomain(w, r); ok {
		v, err := services.WpVulnerabilityScanSite(d)
		wordpressReply(w, v, err, http.StatusUnprocessableEntity)
	}
}

func wordpressSecurityCheck(w http.ResponseWriter, r *http.Request) {
	if d, ok := wordpressDomain(w, r); ok {
		v, err := services.WpVulnerabilityCheckSecurity(d)
		wordpressReply(w, v, err, http.StatusInternalServerError)
	}
}

func wordpressHarden(w http.ResponseWriter, r *http.Request) {
	var body any
	if !decodeJSON(w, r, &body) {
		return
	}
	d, ok := wordpressDomain(w, r)
	if !ok {
		return
	}
	var fixes []string
	if obj, ok := body.(map[string]any); ok {
		if arr, ok := obj["fixes"].([]any); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok {
					fixes = append(fixes, s)
				}
			}
		}
	}
	if len(fixes) == 0 {
		writeErr(w, http.StatusBadRequest, "No fixes specified")
		return
	}
	v, err := services.WpVulnerabilityApplyHardening(d, fixes)
	wordpressReply(w, v, err, http.StatusInternalServerError)
}

func wordpressUpdateWithRollback(w http.ResponseWriter, r *http.Request) {
	if d, ok := wordpressDomain(w, r); ok {
		v, err := services.WordpressUpdateWithRollback(d)
		wordpressReply(w, v, err, http.StatusInternalServerError)
	}
}
