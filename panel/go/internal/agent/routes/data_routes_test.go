package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// dataRoutesMux registers every data-group route on one mux: Go's ServeMux
// panics on conflicting patterns, so this also proves they coexist.
func dataRoutesMux() *http.ServeMux {
	r := &Router{Auth: http.NewServeMux(), Public: http.NewServeMux()}
	for _, reg := range []func(*Router){registerDatabase, registerBackups, registerRemoteBackup,
		registerDatabaseBackup, registerVolumeBackup, registerBackupVerify, registerBackupDrill} {
		reg(r)
	}
	return r.Auth
}

func dataRoutesDo(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// `dump` is a legal database name: DELETE /db-backups/dump must reach the
// purge (axum answered 405, then 500, before the explicit static route).
func TestDeleteDbBackupsDumpReachesThePurge(t *testing.T) {
	w := dataRoutesDo(dataRoutesMux(), "DELETE", "/db-backups/dump", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"dir_removed":false`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := dataRoutesDo(dataRoutesMux(), "DELETE", "/db-backups/a.b", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("dotted name: %d", w.Code)
	}
}

func TestDataRoutesValidateBeforeActing(t *testing.T) {
	mux := dataRoutesMux()
	cases := []struct {
		method, path, body string
		code               int
		msg                string
	}{
		{"POST", "/backups/upload", `{"filepath":"/var/backups/dockpanel/../../etc/shadow","destination":{"type":"s3"}}`, 400, "Invalid backup filepath"},
		{"POST", "/backups/upload", `{"filepath":"/var/backups/dockpanel/x","destination":{}}`, 422, "missing field `type`"},
		{"POST", "/backups/upload", `{"filepath":"/var/backups/dockpanel/x","destination":{"type":"s3"}}`, 400, "Missing bucket"},
		{"POST", "/databases/query", `{"container":"other","engine":"mysql","user":"u","password":"p","database":"d","sql":"select 1"}`, 400, "Invalid container name"},
		{"POST", "/databases/reset-password", `{"container":"dockpanel-db-x","engine":"mysql","user":"u","old_password":"a\nb","new_password":"c"}`, 400, "Invalid old_password"},
		{"POST", "/db-backups/dump", `{"container_name":"c","db_name":"d","db_type":"mysql","user":"u"}`, 422, "missing field `password`"},
		{"POST", "/backups/verify/site", `{"domain":"example.com","filename":"../x"}`, 400, "Invalid filename"},
		{"POST", "/backups/drill/db", `{"db_type":"oracle","db_name":"d","filename":"f"}`, 400, "Unsupported db_type"},
		{"GET", "/backups/bad_domain/list", ``, 400, "Invalid domain format"},
		{"POST", "/volume-backups/create", `{"volume_name":"","container_name":"c"}`, 400, "volume_name and container_name required"},
	}
	for _, c := range cases {
		w := dataRoutesDo(mux, c.method, c.path, c.body)
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.msg) {
			t.Errorf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
	}
}
