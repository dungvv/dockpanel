package routes

import (
	"net/http"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// traefikInstall: POST /traefik/install.
func traefikInstall(st *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := nginxDecodeValue(w, r)
		if !ok {
			return
		}
		email, ok := nginxFieldStr(body, "acme_email")
		if !ok {
			email = "admin@localhost"
		}
		s, err := services.TraefikInstall(r.Context(), st.Docker, email)
		if err != nil {
			nginxPlain(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s)
	}
}

// traefikUninstall: POST /traefik/uninstall.
func traefikUninstall(st *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := services.TraefikUninstall(r.Context(), st.Docker); err != nil {
			nginxPlain(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

// traefikStatus: GET /traefik/status.
func traefikStatus(st *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, services.TraefikGetStatus(r.Context(), st.Docker))
	}
}

// traefikAddRoute: POST /traefik/route — write a dynamic route for an app.
func traefikAddRoute(w http.ResponseWriter, r *http.Request) {
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	domain, ok := nginxFieldStr(body, "domain")
	if !ok {
		nginxPlain(w, http.StatusBadRequest, "Missing 'domain'")
		return
	}
	port64, ok := nginxFieldU64(body, "port")
	if !ok {
		nginxPlain(w, http.StatusBadRequest, "Missing 'port'")
		return
	}
	port := uint16(port64) // Rust `as u16` truncates the same way
	ssl, ok := nginxField(body, "ssl").(bool)
	if !ok {
		ssl = true
	}
	if err := services.TraefikWriteRouteConfig(domain, port, ssl); err != nil {
		nginxPlain(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": domain, "port": port, "ssl": ssl})
}

// traefikRemoveRoute: DELETE /traefik/route.
func traefikRemoveRoute(w http.ResponseWriter, r *http.Request) {
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	domain, ok := nginxFieldStr(body, "domain")
	if !ok {
		nginxPlain(w, http.StatusBadRequest, "Missing 'domain'")
		return
	}
	services.TraefikRemoveRouteConfig(domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": domain})
}

// registerTraefik mounts src/routes/traefik.rs.
func registerTraefik(r *Router) {
	r.Handle("POST /traefik/install", traefikInstall(r.State))
	r.Handle("POST /traefik/uninstall", traefikUninstall(r.State))
	r.Handle("GET /traefik/status", traefikStatus(r.State))
	r.Handle("POST /traefik/route", traefikAddRoute)
	r.Handle("DELETE /traefik/route", traefikRemoveRoute)
}
