package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flosch/pongo2/v6"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/templates"
)

// ── template parity with the Rust tree ──────────────────────────────────

func TestEmbeddedTemplatesMatchTheRustCopies(t *testing.T) {
	rustDir := "../../../../agent/src/templates/nginx"
	if _, err := os.Stat(rustDir); err != nil {
		t.Skip("Rust template tree not present")
	}
	for _, n := range NginxTemplateNames {
		want, err := os.ReadFile(filepath.Join(rustDir, n))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := templates.FS.ReadFile("nginx/" + n)
		if string(got) != string(want) {
			t.Errorf("%s differs from the Rust copy", n)
		}
	}
}

// Goldens were rendered by Tera 1.20.1 (the Rust agent's engine) from
// testdata/nginx_golden/cases.json; pongo2 must reproduce them byte for byte.
func TestTemplatesRenderLikeTera(t *testing.T) {
	raw, err := os.ReadFile("testdata/nginx_golden/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name     string         `json:"name"`
		Template string         `json:"template"`
		Ctx      map[string]any `json:"ctx"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	set := NginxInitTemplates()
	for _, c := range cases {
		ctx := pongo2.Context{}
		for k, v := range c.Ctx {
			if f, ok := v.(float64); ok {
				v = int(f) // Tera receives integers
			}
			ctx[k] = v
		}
		got, err := nginxRender(set, c.Template, ctx)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		want, _ := os.ReadFile("testdata/nginx_golden/" + c.Name + ".golden")
		if got != string(want) {
			t.Errorf("%s: pongo2 output differs from Tera\n--- got ---\n%s\n--- want ---\n%s", c.Name, got, want)
		}
	}
}

func TestRenderSiteConfigValidatesAndPicksTemplates(t *testing.T) {
	set := NginxInitTemplates()
	s := func(v string) *string { return &v }
	tr := true
	for _, bad := range []*NginxSiteConfig{
		{Runtime: "static", Root: s("/var/www/../etc")},
		{Runtime: "php", PhpSocket: s("unix:/run/php/x;evil.sock")},
		{Runtime: "static", SslCert: s("relative.pem")},
		{Runtime: "static", SslKey: s("/a b")},
		{Runtime: "static", CustomNginx: s("include /etc/passwd;")},
	} {
		if _, err := NginxRenderSiteConfig(set, "a.example", bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	out, err := NginxRenderSiteConfig(set, "a.example", &NginxSiteConfig{Runtime: "node", Ssl: &tr,
		CspPolicy: s(`x" always; location /p { }`)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "proxy_pass http://127.0.0.1:3000;") || !strings.Contains(out, "/etc/dockpanel/ssl/a.example/fullchain.pem") {
		t.Errorf("node+ssl render wrong:\n%s", out)
	}
	if strings.Contains(out, `x" always`) {
		t.Error("CSP was not sanitized")
	}
}

// ── where a rendered vhost lands ────────────────────────────────────────

func nginxScratch(t *testing.T) string { return t.TempDir() }

func TestASiteWithNothingParkedIsWrittenIntoService(t *testing.T) {
	dir := nginxScratch(t)
	in, parked := filepath.Join(dir, "a.example.conf"), filepath.Join(dir, "a.example.conf.disabled")
	os.WriteFile(in, []byte("server {}"), 0o644)
	tg := NginxVhostTargetBetween(in, parked)
	if tg.Path != in || !tg.Live {
		t.Fatalf("a live site still owes nginx a test and a reload: %+v", tg)
	}
}

func TestAParkedBodyTakesTheWriteAndTheSiteStaysOffline(t *testing.T) {
	dir := nginxScratch(t)
	in, parked := filepath.Join(dir, "b.example.conf"), filepath.Join(dir, "b.example.conf.disabled")
	os.WriteFile(in, []byte("return 503;"), 0o644)
	os.WriteFile(parked, []byte("server { listen 80; }"), 0o644)
	tg := NginxVhostTargetBetween(in, parked)
	if tg.Path == in || tg.Path != parked || tg.Live {
		t.Fatalf("got %+v", tg)
	}
}

func TestTheStubIsLeftAloneEvenWhenTheParkedBodyIsEmpty(t *testing.T) {
	dir := nginxScratch(t)
	in, parked := filepath.Join(dir, "d.example.conf"), filepath.Join(dir, "d.example.conf.disabled")
	os.WriteFile(in, []byte("return 503;"), 0o644)
	os.WriteFile(parked, nil, 0o644)
	if tg := NginxVhostTargetBetween(in, parked); tg.Live || tg.Path != parked {
		t.Fatalf("got %+v", tg)
	}
}

func TestTheMaintenanceResponseAnswersWhereTheSiteAnswered(t *testing.T) {
	l := NginxListenerLines("server {\n    listen 203.0.113.10:80;\n    listen [::]:80;\n    server_name a.example;\n    root /var/www/a.example/public;\n}\n")
	if !strings.Contains(l, "listen 203.0.113.10:80;") || !strings.Contains(l, "listen [::]:80;") {
		t.Fatalf("the site's own address must come across: %s", l)
	}
	if strings.Contains(l, "server_name") || strings.Contains(l, "root ") {
		t.Fatal("only listeners and certificates travel")
	}
}

func TestATlsSiteCanStillSayItIsDisabledOverHttps(t *testing.T) {
	l := NginxListenerLines("server {\n    listen 203.0.113.10:80;\n    server_name a.example;\n}\nserver {\n    listen 203.0.113.10:443 ssl;\n    listen [::]:443 ssl;\n    ssl_certificate /etc/ssl/a/fullchain.pem;\n    ssl_certificate_key /etc/ssl/a/privkey.pem;\n    ssl_protocols TLSv1.2 TLSv1.3;\n}\n")
	for _, w := range []string{"listen 203.0.113.10:443 ssl;", "ssl_certificate /etc/ssl/a/fullchain.pem;", "ssl_certificate_key /etc/ssl/a/privkey.pem;"} {
		if !strings.Contains(l, w) {
			t.Errorf("missing %q", w)
		}
	}
	if strings.Contains(l, "ssl_protocols") {
		t.Error("ssl_protocols must not travel")
	}
}

func TestARepeatedListenerIsEmittedOnce(t *testing.T) {
	if n := strings.Count(NginxListenerLines("server {\n    listen [::]:80;\n}\nserver {\n    listen [::]:80;\n}\n"), "listen [::]:80;"); n != 1 {
		t.Fatalf("got %d", n)
	}
}

func TestBothPathsComeFromOneFunctionSoTheyCannotDrift(t *testing.T) {
	in, parked := NginxVhostPathsFor("c.example", true)
	if !strings.HasSuffix(in, "/sites-enabled/c.example.conf") || !strings.HasSuffix(parked, "/sites-available/c.example.conf.disabled") || in == parked {
		t.Fatal(in, parked)
	}
}

func TestTheRhelFamilyHasNoSecondDirectorySoBothPathsShareConfD(t *testing.T) {
	in, parked := NginxVhostPathsFor("c.example", false)
	if in != "/etc/nginx/conf.d/c.example.conf" || parked != "/etc/nginx/conf.d/c.example.conf.disabled" {
		t.Fatal(in, parked)
	}
	if strings.HasSuffix(parked, ".conf") {
		t.Fatal("the parked name must fall outside nginx's own glob")
	}
}

// ── static-vhost deny retrofit ──────────────────────────────────────────

const nginxStaticVhost = "server {\n    listen 80;\n    server_name a.example;\n    root /var/www/a.example/public;\n    index index.html index.htm;\n\n    location / {\n        try_files $uri $uri/ =404;\n    }\n}\n"

func TestRetrofitPatchesAStaticVhostOnceAndOnlyOnce(t *testing.T) {
	p, ok := NginxPatchStaticVhost(nginxStaticVhost)
	if !ok {
		t.Fatal("a static vhost is a candidate")
	}
	for _, w := range []string{`location ~ /\.(?!well-known)`, `location ~ \.php$`, "location ~ ^/sites/.*/private/", "try_files $uri $uri/ =404;", "root /var/www/a.example/public;"} {
		if !strings.Contains(p, w) {
			t.Errorf("missing %q", w)
		}
	}
	if _, ok := NginxPatchStaticVhost(p); ok {
		t.Error("second pass must not be a candidate")
	}
	if n := strings.Count(p, "deny all;"); n != 3 {
		t.Errorf("deny count %d", n)
	}
}

func TestRetrofitAddsOnlyTheDenyAnEarlierVersionMissed(t *testing.T) {
	v2682, _ := NginxPatchStaticVhost(nginxStaticVhost)
	stale := strings.Replace(v2682, "\n    # drupal's private file store: no dot segment and no .php suffix, so\n    # neither deny above covers it.\n    location ~ ^/sites/.*/private/ {\n        deny all;\n    }\n", "", 1)
	if strings.Contains(stale, "sites/.*/private") || strings.Count(stale, "deny all;") != 2 {
		t.Fatal("fixture must model a v2.68.2 body")
	}
	up, ok := NginxPatchStaticVhost(stale)
	if !ok || strings.Count(up, "deny all;") != 3 || strings.Count(up, `location ~ /\.(?!well-known)`) != 1 ||
		strings.Count(up, `location ~ \.php$`) != 1 || strings.Count(up, "location ~ ^/sites/.*/private/") != 1 {
		t.Fatalf("bad upgrade:\n%s", up)
	}
	if _, ok := NginxPatchStaticVhost(up); ok {
		t.Fatal("not idempotent")
	}
}

func TestRetrofitNeverReturnsABodyItAddedNothingTo(t *testing.T) {
	commented := strings.Replace(nginxStaticVhost, "    index index.html index.htm;\n", "    index index.html index.htm; # set by hand\n", 1)
	for _, body := range []string{commented, nginxStaticVhost} {
		if out, ok := NginxPatchStaticVhost(body); ok && !strings.Contains(out, "deny all;") {
			t.Fatal("returned a patched body with no deny in it")
		}
	}
}

func TestRetrofitSkipsPhpAndNonStaticVhosts(t *testing.T) {
	if _, ok := NginxPatchStaticVhost("server {\n    index index.html index.htm;\n    location ~ \\.php$ {\n        fastcgi_pass unix:/run/php/php8.3-fpm.sock;\n    }\n}\n"); ok {
		t.Error("php vhost patched")
	}
	if _, ok := NginxPatchStaticVhost("server {\n    location / {\n        proxy_pass http://127.0.0.1:3000;\n    }\n}\n"); ok {
		t.Error("proxy vhost patched")
	}
}

// ── custom_nginx per-statement validation ───────────────────────────────

func TestCustomNginxBlocksSemicolonChainedDirective(t *testing.T) {
	for _, s := range []string{
		"sendfile on; access_log /var/www/victim/public/shell.php;",
		"gzip on; return 301 https://evil$request_uri;",
		"add_header X y; proxy_pass http://169.254.169.254/;",
		"client_max_body_size 10m; error_log /tmp/x;",
	} {
		if nginxValidateCustom(s) == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestCustomNginxAllowsBenignStatements(t *testing.T) {
	for _, s := range []string{"proxy_read_timeout 120s;", "gzip_types text/css application/json;", "add_header X-Frame-Options SAMEORIGIN;", "",
		"add_header X-Extra 1;", "gzip_types application/wasm;", "expires 1d;"} {
		if err := nginxValidateCustom(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"location / { root /etc; }", "# sneaky"} {
		if nginxValidateCustom(s) == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestCustomNginxRefusesWhatTheTemplateAlreadySets(t *testing.T) {
	for _, s := range []string{"client_max_body_size 20m;", "gzip on;", "gzip_min_length 512;", "  Client_Max_Body_Size 50m;", "proxy_read_timeout 60s; gzip off;"} {
		err := nginxValidateCustom(s)
		if err == nil || !strings.Contains(err.Error(), "already sets") {
			t.Errorf("%q -> %v", s, err)
		}
	}
}

func TestHeaderSanitizeStripsBreakoutChars(t *testing.T) {
	if got := nginxSanitizeHeaderValue("default-src 'self'; script-src 'self'"); got != "default-src 'self'; script-src 'self'" {
		t.Error(got)
	}
	if got := nginxSanitizeHeaderValue(`x" always; location /p { }`); got != "x always; location /p  " {
		t.Errorf("%q", got)
	}
	if strings.ContainsAny(nginxSanitizeHeaderValue(`a"b\c{d}`), `"\`) {
		t.Error("quote/backslash survived")
	}
}
