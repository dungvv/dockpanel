package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// dockerRoutesMux registers the docker-group routes on one mux: ServeMux
// panics on conflicting patterns, so this also proves they coexist.
func dockerRoutesMux() *http.ServeMux {
	r := &Router{State: &State{}, Auth: http.NewServeMux(), Public: http.NewServeMux()}
	for _, reg := range []func(*Router){registerDockerApps, registerImageScan, registerSbom} {
		reg(r)
	}
	return r.Auth
}

func dockerRoutesDo(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	dockerRoutesMux().ServeHTTP(w, req)
	return w
}

// Every guard here fires before Docker is contacted.
func TestDockerAppsRoutesValidateBeforeActing(t *testing.T) {
	cases := []struct {
		method, path, body string
		code               int
		msg                string
	}{
		{"POST", "/apps/zzz/stop", "", 400, "Invalid container ID"},
		{"DELETE", "/apps/not-hex!", "", 400, "Invalid container ID"},
		{"DELETE", "/apps/images/--help", "", 400, "Invalid image ID"},
		{"POST", "/apps/deploy", `{"template_id":"ghost","name":"-bad","port":1}`, 400, "Invalid app name"},
		{"POST", "/apps/deploy", `{"template_id":"ghost","name":"ok","port":1,"domain":"nodot"}`, 400, "Invalid domain format"},
		{"POST", "/apps/deploy", `{"template_id":"ghost","name":"ok","port":1,"tls_mode":"provided","tls_certificate":"x","use_traefik":true}`, 400, "cannot be served through Traefik"},
		{"POST", "/apps/deploy", `{"template_id":"ghost","name":"ok"}`, 422, "missing field `port`"},
		{"POST", "/apps/stack/action", `{"stack_id":"s","action":"explode"}`, 400, "Action must be start, stop, restart, or remove"},
		{"POST", "/apps/registry-login", `{"server":"","username":"u","password":"p"}`, 400, "Server and username required"},
		{"POST", "/apps/registry-login", `{"server":"-x","username":"u","password":"p"}`, 400, "Invalid registry server"},
		{"POST", "/apps/registry-logout", `{}`, 400, "Server required"},
		{"POST", "/apps/compose/parse", `{"yaml":"services:\n  bad:\n    image: x:1\n    privileged: true\n"}`, 400, "privileged mode is not allowed"},
		{"POST", "/apps/compose/deploy", `{"yaml":"services:\n  a:\n    image: x:1\n","domain":"a.example.com"}`, 400, "publishes no host port"},
		{"POST", "/image-scan/scan", `{"image":"img;rm -rf /"}`, 400, "disallowed characters"},
		{"POST", "/sbom/scan", `{"image":""}`, 400, "Invalid image reference"},
	}
	for _, c := range cases {
		w := dockerRoutesDo(c.method, c.path, c.body)
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.msg) {
			t.Errorf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
	}
}

func TestComposeValidateReportsWithoutDeploying(t *testing.T) {
	w := dockerRoutesDo("POST", "/apps/compose/validate", `{"yaml":"services:\n  db:\n    image: postgres\n    user: \"1000\"\n"}`)
	body := w.Body.String()
	for _, want := range []string{`"valid":true`, "Using ':latest' tag", "Database service without volumes", "No restart policy", "'user:' is not supported"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in %s", want, body)
		}
	}
}

func TestSnapshotTagsAreForceNamespaced(t *testing.T) {
	s := func(v string) *string { return &v }
	for _, c := range []struct {
		in   *string
		want string
	}{
		{nil, "dockpanel-snapshot:42"},
		{s("v1.2"), "dockpanel-snapshot:v1.2"},
		{s("dockpanel-snapshot:x"), "dockpanel-snapshot:x"},
		{s("nginx:latest; rm"), "dockpanel-snapshot:nginxlatestrm"},
		{s(":::"), "dockpanel-snapshot:42"},
	} {
		if got := dockerAppsSnapshotTag(c.in, 42); got != c.want {
			t.Errorf("%v → %s", c.in, got)
		}
	}
}

func TestSensitiveEnvIsMaskedButTheCataloguesOwnNonSecretsAreNot(t *testing.T) {
	for k, want := range map[string]bool{
		"DB_PASSWORD": true, "API_KEY": true, "KEYCLOAK_ADMIN": false, "NEXTAUTH_URL": false, "PUID": false,
	} {
		if dockerAppsIsSensitive(k) != want {
			t.Errorf("%s: want %v", k, want)
		}
	}
}

func TestGpuLinesKeepCommasInTheName(t *testing.T) {
	g := dockerAppsParseGpuLine("0, NVIDIA A100, PCIe, 40960, 100, 40860, 3, 0, 31, 35.5, 250.00, [N/A], 535.1, P0")
	if g["name"] != "NVIDIA A100, PCIe" || g["memory_total_mb"] != uint64(40960) || g["fan_speed_pct"] != nil || g["performance_state"] != "P0" {
		t.Fatal(g)
	}
	if f := dockerAppsParseGpuLine("1, Short"); f["name"] != "Short" || f["temperature_c"] != nil {
		t.Fatal(f)
	}
}
