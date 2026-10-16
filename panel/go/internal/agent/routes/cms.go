package routes

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type cmsInstallRequest struct {
	Cms        string  `json:"cms"`
	Title      *string `json:"title"`
	AdminUser  *string `json:"admin_user"`
	AdminPass  *string `json:"admin_pass"`
	AdminEmail *string `json:"admin_email"`
	DbName     *string `json:"db_name"`
	DbUser     *string `json:"db_user"`
	DbPass     *string `json:"db_pass"`
	DbHost     *string `json:"db_host"`
}

func registerCms(r *Router) {
	r.Handle("POST /cms/{domain}/install", cmsInstall)
}

func cmsAllASCII(s string, extra string) bool {
	for _, c := range s {
		if !isASCIIAlnum(c) && !strings.ContainsRune(extra, c) {
			return false
		}
	}
	return true
}

func cmsIsValidDbIdentifier(s string) bool {
	return s != "" && len(s) <= 64 && cmsAllASCII(s, "_-")
}

// cmsIsValidDbHost: hostname-charset allow-list, ':' for an optional port. A
// '#' here is worse than in db_pass — parse_url() silently truncates the host
// into a fragment, pointing drush at the wrong database host with no error.
func cmsIsValidDbHost(s string) bool {
	return s != "" && len(s) <= 255 && cmsAllASCII(s, ".-:")
}

func cmsInstall(w http.ResponseWriter, r *http.Request) {
	var b cmsInstallRequest
	if !securityDecodeStrict(w, r, &b, "cms") {
		return
	}
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	bad := func(msg string) { writeErr(w, http.StatusBadRequest, msg) }
	if b.DbName != nil && !cmsIsValidDbIdentifier(*b.DbName) {
		bad("Invalid db_name")
		return
	}
	if b.DbUser != nil && !cmsIsValidDbIdentifier(*b.DbUser) {
		bad("Invalid db_user")
		return
	}
	if b.AdminEmail != nil && strings.Count(*b.AdminEmail, "@") != 1 {
		bad("Invalid admin_email")
		return
	}
	// db_pass: no newlines/NUL, and none of '#' '/' '?' — drush gets
	// `mysql://user:pass@host/db` and PHP's parse_url() (no urldecode on
	// Drupal's path) fails on them; percent-encoding would reach the driver
	// as a literal "%23".
	if b.DbPass != nil && (*b.DbPass == "" || strings.ContainsAny(*b.DbPass, "\n\r\x00#/?")) {
		bad("Invalid db_pass")
		return
	}
	if b.AdminPass != nil && (*b.AdminPass == "" || strings.ContainsAny(*b.AdminPass, "\n\r\x00")) {
		bad("Invalid admin_pass")
		return
	}
	if b.DbHost != nil && !cmsIsValidDbHost(*b.DbHost) {
		bad("Invalid db_host")
		return
	}
	title := "My Site"
	if b.Title != nil {
		title = *b.Title
	}

	// need returns the required fields in order, or writes 400 for the first
	// missing one.
	need := func(names ...string) ([]string, bool) {
		fields := map[string]*string{
			"db_name": b.DbName, "db_user": b.DbUser, "db_pass": b.DbPass, "db_host": b.DbHost,
			"admin_user": b.AdminUser, "admin_pass": b.AdminPass, "admin_email": b.AdminEmail,
		}
		var out []string
		for _, n := range names {
			if fields[n] == nil {
				bad(n + " is required")
				return nil, false
			}
			out = append(out, *fields[n])
		}
		return out, true
	}
	db := []string{"db_name", "db_user", "db_pass", "db_host"}
	admin := []string{"admin_user", "admin_pass", "admin_email"}

	var msg string
	var err error
	switch b.Cms {
	case "laravel", "codeigniter":
		v, ok := need(db...)
		if !ok {
			return
		}
		if b.Cms == "laravel" {
			msg, err = services.CmsInstallLaravel(domain, v[0], v[1], v[2], v[3], title)
		} else {
			msg, err = services.CmsInstallCodeigniter(domain, v[0], v[1], v[2], v[3], title)
		}
	case "drupal", "joomla":
		v, ok := need(append(db, admin...)...)
		if !ok {
			return
		}
		if b.Cms == "drupal" {
			msg, err = services.CmsInstallDrupal(domain, v[0], v[1], v[2], v[3], title, v[4], v[5], v[6])
		} else {
			msg, err = services.CmsInstallJoomla(domain, v[0], v[1], v[2], v[3], title, v[4], v[5], v[6])
		}
	case "symfony":
		msg, err = services.CmsInstallSymfony(domain, title)
	default:
		bad(fmt.Sprintf("Unsupported CMS: %s. Use: laravel, drupal, joomla, symfony, codeigniter", b.Cms))
		return
	}
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "message": msg})
}
