package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/flosch/pongo2/v6"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/templates"
)

// NginxSiteConfig is the vhost description the panel sends (Rust:
// routes::nginx::SiteConfig). It lives in services because the SSL, Docker-app
// and git-build services render vhosts too, and services cannot import routes.
type NginxSiteConfig struct {
	// Site runtime: "static", "php", "proxy", "node", "python".
	Runtime string `json:"runtime"`
	// Document root base (default /var/www).
	Root *string `json:"root"`
	// Upstream port (proxy/node/python/Docker sites).
	ProxyPort *uint16 `json:"proxy_port"`
	// PHP-FPM socket (unix:/run/php/...).
	PhpSocket *string `json:"php_socket"`
	Ssl       *bool   `json:"ssl"`
	SslCert   *string `json:"ssl_cert"`
	SslKey    *string `json:"ssl_key"`
	// Requests per second per IP (nil = no limit).
	RateLimit   *uint32 `json:"rate_limit"`
	MaxUploadMb *uint32 `json:"max_upload_mb"`
	// PHP memory_limit / pm.max_children for the per-site pool.
	PhpMemoryMb   *uint32 `json:"php_memory_mb"`
	PhpMaxWorkers *uint32 `json:"php_max_workers"`
	// Whitelisted directives injected into the server block.
	CustomNginx *string `json:"custom_nginx"`
	// "laravel", "wordpress", "drupal", "joomla", "symfony", "codeigniter", "magento", "generic".
	PhpPreset  *string `json:"php_preset"`
	AppCommand *string `json:"app_command"`
	// FastCGI / Redis object cache (PHP only).
	FastcgiCache *bool  `json:"fastcgi_cache"`
	RedisCache   *bool  `json:"redis_cache"`
	RedisDb      *int32 `json:"redis_db"`
	// WAF (ModSecurity): mode "detection" or "prevention".
	WafEnabled *bool   `json:"waf_enabled"`
	WafMode    *string `json:"waf_mode"`
	// Header values, rendered into `add_header … "<value>" always;`.
	CspPolicy         *string `json:"csp_policy"`
	PermissionsPolicy *string `json:"permissions_policy"`
	// "off", "rate-limit", "challenge", "block".
	BotProtection *string `json:"bot_protection"`
	// PHP-FPM pool identity for SFTP-enabled sites (see sftp_accounts). nil
	// keeps the shared www-data identity.
	PoolUser  *string `json:"pool_user"`
	PoolGroup *string `json:"pool_group"`
}

// NginxCmdOutput is the result of `nginx -t`.
type NginxCmdOutput struct {
	Success bool
	Stdout  string
	Stderr  string
}

// NginxPlaceholderMarker is the one sentence that identifies the filler page
// as ours. A constant because the page is WRITTEN when a site is created and
// READ back when a git deploy decides whether a document root holds a real
// site or only our filler; a deploy that adopted a page it merely guessed was
// ours would delete an operator's file.
const NginxPlaceholderMarker = "Site is ready. Upload your files to replace this page."

// NginxPlaceholderPage is the filler page written into a new site's document root.
func NginxPlaceholderPage(domain string) string {
	return "<!DOCTYPE html><html><head><title>" + domain + "</title></head>" +
		"<body><h1>Welcome to " + domain + "</h1>" +
		"<p>" + NginxPlaceholderMarker + "</p></body></html>"
}

// NginxIsPlaceholderPage reports whether path is a file the panel wrote as
// filler. Keyed on content, never on the name; an unreadable file is,
// deliberately, not ours.
func NginxIsPlaceholderPage(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && strings.Contains(string(b), NginxPlaceholderMarker)
}

// NginxDocumentRootFor is the directory nginx actually serves for a site.
// Every template renders `root {{ root }}/{{ domain }}/public` for static and
// PHP; only proxying runtimes are served from the site directory itself. Two
// callers used to disagree (put_site vs the migration importer), producing
// vhosts whose document root did not exist.
func NginxDocumentRootFor(siteDir, runtime string) string {
	switch runtime {
	case "proxy", "node", "python":
		return siteDir
	}
	return siteDir + "/public"
}

// NginxSitesDirFor picks the vhost directory for the box's nginx convention.
// Debian ships sites-enabled; the RHEL family has neither directory and
// includes conf.d/*.conf — every site write there used to fail ENOENT. Split
// from NginxSitesDir so tests exercise both conventions without nginx.
func NginxSitesDirFor(usesSitesEnabled bool) string {
	if usesSitesEnabled {
		return "/etc/nginx/sites-enabled"
	}
	return "/etc/nginx/conf.d"
}

func nginxUsesSitesEnabled() bool {
	fi, err := os.Stat("/etc/nginx/sites-enabled")
	return err == nil && fi.IsDir()
}

// NginxSitesDir is the directory nginx reads site vhosts from on THIS box.
func NginxSitesDir() string { return NginxSitesDirFor(nginxUsesSitesEnabled()) }

// NginxParkedDirFor is where a disabled site's vhost is parked — the SAME
// directory as NginxSitesDirFor on RHEL. A caller scanning both must skip the
// second scan when they are equal, or it double-counts every match.
func NginxParkedDirFor(usesSitesEnabled bool) string {
	if usesSitesEnabled {
		return "/etc/nginx/sites-available"
	}
	return NginxSitesDirFor(false)
}

// NginxParkedDir is the parked directory on THIS box.
func NginxParkedDir() string { return NginxParkedDirFor(nginxUsesSitesEnabled()) }

// NginxDomainIsHttps reports whether this box actually serves domain over
// HTTPS. Not a guess: the agent wrote the vhost, and the template emits a
// `listen …443 ssl` only when a certificate is in place. Traefik's route is
// asked first, since then there is no nginx vhost to read. (Issue #96: TLS
// terminated at an external proxy used to print https:// links.)
func NginxDomainIsHttps(domain string) bool {
	if tls, ok := TraefikRouteIsTls(domain); ok {
		return tls
	}
	b, err := os.ReadFile(fmt.Sprintf("%s/%s.conf", NginxSitesDir(), domain))
	if err != nil {
		return false
	}
	for _, line := range nginxLines(string(b)) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "listen ") && strings.Contains(line, "443") && strings.Contains(line, "ssl") {
			return true
		}
	}
	return false
}

// NginxVhostTarget is where a vhost write lands. Disabling a site parks its
// real body beside the live path and leaves a stub in service; writing a fresh
// render into service would put a deliberately-offline site back online.
type NginxVhostTarget struct {
	Path string
	// Live: the write reaches nginx, so a config test and reload are owed —
	// and only then may the caller say the site was configured.
	Live bool
}

// NginxListenerLines returns the listen/ssl_certificate(_key) lines of a
// vhost, deduplicated and indented. The maintenance response used to hardcode
// `listen 80;` while templates bind `listen <ip>:80;`, so the stub sat on the
// wildcard socket and was never consulted: the disabled site kept serving.
// Copying the addresses (and cert lines, which a `listen …443 ssl` needs)
// makes the stub answer exactly where the site did.
func NginxListenerLines(vhost string) string {
	var seen []string
	var out strings.Builder
	for _, line := range nginxLines(vhost) {
		t := strings.TrimSpace(line)
		wanted := strings.HasPrefix(t, "listen ") || strings.HasPrefix(t, "ssl_certificate ") ||
			strings.HasPrefix(t, "ssl_certificate_key ")
		if !wanted || nginxContains(seen, t) {
			continue
		}
		seen = append(seen, t)
		out.WriteString("    " + t + "\n")
	}
	return out.String()
}

// NginxVhostTargetBetween decides between the in-service and the parked path.
// Five writers (settings changes, git deploys, cert provisioning, the renewal
// loop…) used to write straight into service, re-enabling disabled sites. It
// also keeps the parked copy current, so re-enabling restores the site as it
// is rather than as it was frozen.
func NginxVhostTargetBetween(inService, parked string) NginxVhostTarget {
	if _, err := os.Stat(parked); err == nil {
		return NginxVhostTarget{Path: parked}
	}
	return NginxVhostTarget{Path: inService, Live: true}
}

// NginxVhostPathsFor returns (in-service, parked) for domain. The parked path
// must never be included by nginx: sites-available on Debian; on RHEL the same
// conf.d with a `.disabled` suffix nginx's `*.conf` glob cannot match.
func NginxVhostPathsFor(domain string, usesSitesEnabled bool) (string, string) {
	dir := NginxSitesDirFor(usesSitesEnabled)
	if usesSitesEnabled {
		return fmt.Sprintf("%s/%s.conf", dir, domain),
			fmt.Sprintf("/etc/nginx/sites-available/%s.conf.disabled", domain)
	}
	return fmt.Sprintf("%s/%s.conf", dir, domain), fmt.Sprintf("%s/%s.conf.disabled", dir, domain)
}

// NginxVhostPaths returns (in-service, parked) for domain on this box. One
// spelling, so the parked file always has readers.
func NginxVhostPaths(domain string) (string, string) {
	return NginxVhostPathsFor(domain, nginxUsesSitesEnabled())
}

// NginxVhostTargetFor is where a freshly rendered vhost for domain must go.
func NginxVhostTargetFor(domain string) NginxVhostTarget {
	in, parked := NginxVhostPaths(domain)
	return NginxVhostTargetBetween(in, parked)
}

// NginxRestoreOrRemove undoes a vhost write: put previous back if there was
// one (tmp+rename, so a crash cannot leave a truncated vhost), otherwise
// remove the file we created. Returns whether a previous config was restored.
// Every writer that replaces a vhost and then validates must funnel its
// failure path through here: `nginx -t` is whole-server, so an unrelated
// broken vhost used to cost the edited site its own config.
func NginxRestoreOrRemove(configPath string, previous *string) bool {
	if previous == nil {
		_ = os.Remove(configPath)
		return false
	}
	tmp := configPath + ".restore"
	err := os.WriteFile(tmp, []byte(*previous), 0o644)
	if err == nil {
		err = os.Rename(tmp, configPath)
	}
	if err != nil {
		_ = os.Remove(tmp)
		slog.Error(fmt.Sprintf("Failed to restore the previous nginx config at %s (%d bytes) — this domain may now have no vhost",
			configPath, len(*previous)))
		return false
	}
	return true
}

// NginxRestoreNote is appended to an error so the operator learns whether the
// previous configuration survived.
func NginxRestoreNote(restored bool) string {
	if restored {
		return " (the previous configuration for this domain was restored)"
	}
	return ""
}

// nginxStaticIndex identifies the static branch in BOTH templates. One
// constant: writing it twice produced the v2.68.2 defect.
const nginxStaticIndex = "index index.html index.htm;"

// nginxStaticDenies pairs each deny block with the marker proving it is
// already present, so a vhost patched by an earlier version gains only what
// it lacks. Regex locations win over prefix ones regardless of order.
var nginxStaticDenies = [][2]string{
	{"location ~ /\\.(?!well-known)", "\n" +
		"    # Retrofitted: a site switched from php to static keeps its application\n" +
		"    # source in the same docroot. Every deny here exists in the php presets.\n" +
		"    location ~ /\\.(?!well-known) {\n" +
		"        deny all;\n" +
		"    }\n"},
	{"location ~ \\.php$", "\n" +
		"    location ~ \\.php$ {\n" +
		"        deny all;\n" +
		"    }\n"},
	{"location ~ ^/sites/.*/private/", "\n" +
		"    # drupal's private file store: no dot segment and no .php suffix, so\n" +
		"    # neither deny above covers it.\n" +
		"    location ~ ^/sites/.*/private/ {\n" +
		"        deny all;\n" +
		"    }\n"},
}

// NginxPatchStaticVhost returns the body with any missing static denies added,
// or ok=false when nothing is missing (idempotent). Candidates render the
// static branch and carry no FastCGI handler. ⚠ The candidacy test and the
// insertion test must be the SAME whole-line test: a substring candidacy with
// a whole-line insertion once rewrote files with zero denies and logged them
// as retrofitted — a false green on an unprotected site.
func NginxPatchStaticVhost(body string) (string, bool) {
	lines := nginxLines(body)
	hasIndex := false
	for _, l := range lines {
		if strings.TrimSpace(l) == nginxStaticIndex {
			hasIndex = true
			break
		}
	}
	if !hasIndex || strings.Contains(body, "fastcgi_pass") {
		return "", false
	}
	var missing strings.Builder
	for _, d := range nginxStaticDenies {
		if !strings.Contains(body, d[0]) {
			missing.WriteString(d[1])
		}
	}
	if missing.Len() == 0 {
		return "", false
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		if strings.TrimSpace(l) == nginxStaticIndex {
			out[i] = l + "\n" + missing.String()
		} else {
			out[i] = l
		}
	}
	return strings.Join(out, "\n"), true
}

// NginxRetrofitStaticDenies retrofits the static branch's denies onto vhosts
// already on disk. v2.68.0 fixed the template, but nothing re-renders on
// upgrade, so a site switched php→static kept serving wp-config.php/.env as
// text; the update.sh retrofit only reached the panel host. The agent owns the
// vhost dir on every box. Declines to run if `nginx -t` already fails — the
// check is whole-server, so it could not tell its change from an existing fault.
func NginxRetrofitStaticDenies(ctx context.Context) {
	dir := NginxSitesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type cand struct{ path, previous, patched string }
	var candidates []cand
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) != ".conf" || name == "dockpanel-panel.conf" {
			continue
		}
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if patched, ok := NginxPatchStaticVhost(string(b)); ok {
			candidates = append(candidates, cand{path, string(b), patched})
		}
	}
	if len(candidates) == 0 || ctx.Err() != nil {
		return
	}

	// Refuse to touch anything on a box whose nginx is already unhappy.
	if out, err := NginxTestConfig(); err != nil || !out.Success {
		slog.Warn(fmt.Sprintf("Skipping the static-vhost deny retrofit on %d vhost(s): nginx -t already fails, "+
			"so a post-edit check could not tell my change from the existing fault", len(candidates)))
		return
	}

	var written []cand
	for _, c := range candidates {
		tmp := strings.TrimSuffix(c.path, ".conf") + ".conf.retrofit"
		err := os.WriteFile(tmp, []byte(c.patched), 0o644)
		if err == nil {
			err = os.Rename(tmp, c.path)
		}
		if err != nil {
			_ = os.Remove(tmp)
			slog.Warn("Could not retrofit denies onto " + c.path)
			continue
		}
		written = append(written, c)
	}
	if len(written) == 0 {
		return
	}

	if out, err := NginxTestConfig(); err == nil && out.Success {
		names := make([]string, len(written))
		for i, c := range written {
			names[i] = filepath.Base(c.path)
		}
		slog.Info(fmt.Sprintf("Retrofitted dotfile/.php denies onto %d static vhost(s): %s", len(written), strings.Join(names, ", ")))
		_ = NginxReload()
		return
	}
	for _, c := range written {
		prev := c.previous
		NginxRestoreOrRemove(c.path, &prev)
	}
	slog.Error(fmt.Sprintf("nginx -t rejected the static-vhost deny retrofit — all %d file(s) reverted, sites untouched", len(written)))
}

// nginxDetectBindIP finds the primary outbound interface IP for listen
// directives ("" → templates fall back to a wildcard listen). Connecting a
// UDP socket sends nothing.
func nginxDetectBindIP() string {
	c, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok && a.IP.String() != "127.0.0.1" {
		return a.IP.String()
	}
	return ""
}

// ── templates ───────────────────────────────────────────────────────────

// nginxTeraReplace rewrites Tera's keyword-argument filter call
// `replace(from="x", to="y")`, which pongo2 cannot parse, into the
// single-argument registered filter `tera_replace:"x|y"`. The embedded files
// stay byte-identical to the Rust ones; only the in-memory source is adapted.
var nginxTeraReplace = regexp.MustCompile(`\|\s*replace\(from="([^"|\\]*)",\s*to="([^"|\\]*)"\)`)

// nginxTemplateLoader serves the embedded templates to pongo2, adapted from
// Tera syntax and wrapped in autoescape-off: Tera only escapes
// .html/.htm/.xml, so a `.conf` render is never escaped, while pongo2
// escapes by default (and its switch is process-global).
type nginxTemplateLoader struct{}

func (nginxTemplateLoader) Abs(_, name string) string { return name }

func (nginxTemplateLoader) Get(path string) (io.Reader, error) {
	b, err := templates.FS.ReadFile("nginx/" + path)
	if err != nil {
		return nil, err
	}
	src := nginxTeraReplace.ReplaceAllString(string(b), `|tera_replace:"$1|$2"`)
	return strings.NewReader("{% autoescape off %}" + src + "{% endautoescape %}"), nil
}

var nginxFilterOnce sync.Once

func nginxRegisterFilters() {
	nginxFilterOnce.Do(func() {
		if pongo2.FilterExists("tera_replace") {
			return
		}
		_ = pongo2.RegisterFilter("tera_replace", func(in, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
			from, to, _ := strings.Cut(param.String(), "|")
			return pongo2.AsValue(strings.ReplaceAll(in.String(), from, to)), nil
		})
	})
}

// NginxTemplateNames are the templates NginxInitTemplates loads.
var NginxTemplateNames = []string{"http.conf", "https.conf", "proxy.conf"}

// NginxInitTemplates parses the embedded nginx templates; it panics on a
// broken template, like the Rust `expect`.
func NginxInitTemplates() *pongo2.TemplateSet {
	nginxRegisterFilters()
	set := pongo2.NewSet("nginx", nginxTemplateLoader{})
	for _, n := range NginxTemplateNames {
		if _, err := set.FromCache(n); err != nil {
			panic(fmt.Sprintf("Failed to load %s template: %v", n, err))
		}
	}
	return set
}

func nginxRender(set *pongo2.TemplateSet, name string, ctx pongo2.Context) (string, error) {
	tpl, err := set.FromCache(name)
	if err != nil {
		return "", err
	}
	return tpl.Execute(ctx)
}

// ── validation ──────────────────────────────────────────────────────────

// nginxIsSafePath validates a filesystem path rendered into nginx config
// (root, ssl_cert, ssl_key).
func nginxIsSafePath(path string) bool {
	if path == "" || strings.Contains(path, "..") || strings.ContainsRune(path, 0) || !strings.HasPrefix(path, "/") {
		return false
	}
	for _, c := range path {
		if !nginxIsASCIIAlnum(c) && !strings.ContainsRune("/-_.", c) {
			return false
		}
	}
	return true
}

func nginxIsASCIIAlnum(c rune) bool {
	return c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9')
}

// nginxAllowedDirectives may appear in custom_nginx.
var nginxAllowedDirectives = []string{
	"client_max_body_size", "gzip", "gzip_types", "gzip_min_length", "proxy_read_timeout",
	"proxy_connect_timeout", "proxy_send_timeout", "send_timeout", "keepalive_timeout",
	"server_tokens", "add_header", "expires", "tcp_nodelay", "tcp_nopush", "sendfile",
	"types_hash_max_size",
}

// nginxDangerousDirectives are refused by prefix, case-insensitively.
var nginxDangerousDirectives = []string{
	"lua_", "perl_", "proxy_pass", "return", "rewrite", "access_log", "error_log",
	"load_module", "include", "alias",
}

// nginxAlreadySetByTheTemplate: directives the template writes at server
// level, which nginx refuses twice in one context. The custom block lands in
// that same server block, so accepting one produced a config nginx rejects
// (a test once pinned `client_max_body_size 20m;` as valid). add_header and
// gzip_types append and expires is location-only, so those stay allowed.
var nginxAlreadySetByTheTemplate = [][2]string{
	{"client_max_body_size", "Change the site's maximum upload size instead — that is the control that writes it."},
	{"gzip", "Compression is already enabled for every site."},
	{"gzip_min_length", "Compression is already enabled for every site, with a 256-byte floor."},
}

// nginxValidateCustom refuses dangerous content and allows only whitelisted
// directives. nginx separates statements with ';', so EVERY statement on a
// line is validated: checking only the first token let
// "sendfile on; access_log /var/www/victim/public/shell.php;" through
// (cross-tenant log-poisoning file write / RCE).
func nginxValidateCustom(custom string) error {
	if strings.TrimSpace(custom) == "" {
		return nil
	}
	if strings.ContainsAny(custom, "{}") {
		return errors.New("Custom nginx config must not contain '{' or '}' (server block escape)")
	}
	for _, line := range nginxLines(custom) {
		lt := strings.TrimSpace(line)
		if lt == "" {
			continue
		}
		if strings.HasPrefix(lt, "#") {
			return errors.New("Custom nginx config must not contain comment lines starting with '#'")
		}
		for _, stmt := range strings.Split(lt, ";") {
			t := strings.TrimSpace(stmt)
			if t == "" {
				continue
			}
			if strings.HasPrefix(t, "#") {
				return errors.New("Custom nginx config must not contain comment lines starting with '#'")
			}
			lower := strings.ToLower(t)
			for _, d := range nginxDangerousDirectives {
				if strings.HasPrefix(lower, d) {
					return fmt.Errorf("Custom nginx config contains forbidden directive: %s", d)
				}
			}
			directive := ""
			if f := strings.Fields(t); len(f) > 0 {
				directive = strings.ToLower(f[0])
			}
			if directive == "" {
				continue
			}
			if !nginxContains(nginxAllowedDirectives, directive) {
				return fmt.Errorf("Custom nginx directive '%s' is not in the allowed list. Allowed: %s",
					directive, strings.Join(nginxAllowedDirectives, ", "))
			}
			for _, a := range nginxAlreadySetByTheTemplate {
				if a[0] == directive {
					return fmt.Errorf("The site's own configuration already sets '%s' — nginx refuses a "+
						"duplicate and the whole site would fail to load. %s", directive, a[1])
				}
			}
		}
	}
	return nil
}

// nginxSanitizeHeaderValue strips characters that would break out of an
// `add_header Name "<value>" always;` directive. The backend validates too;
// this is defense in depth at the root-owned render choke point.
func nginxSanitizeHeaderValue(v string) string {
	return strings.Map(func(c rune) rune {
		switch c {
		case '"', '\\', '\n', '\r', 0, '{', '}':
			return -1
		}
		return c
	}, v)
}

// nginxIsSafePhpSocket validates a PHP-FPM socket path.
func nginxIsSafePhpSocket(socket string) bool {
	if !strings.HasPrefix(socket, "unix:/") || !strings.HasSuffix(socket, ".sock") ||
		strings.Contains(socket, "..") || strings.ContainsRune(socket, 0) {
		return false
	}
	for _, c := range socket[5:] {
		if !nginxIsASCIIAlnum(c) && !strings.ContainsRune("/-_.", c) {
			return false
		}
	}
	return true
}

func nginxStr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

func nginxBool(p *bool) bool { return p != nil && *p }

// NginxRenderSiteConfig renders the vhost for a site.
func NginxRenderSiteConfig(set *pongo2.TemplateSet, domain string, cfg *NginxSiteConfig) (string, error) {
	if cfg.Root != nil && !nginxIsSafePath(*cfg.Root) {
		return "", errors.New("Invalid root path")
	}
	if cfg.PhpSocket != nil && !nginxIsSafePhpSocket(*cfg.PhpSocket) {
		return "", errors.New("Invalid PHP socket path")
	}
	if cfg.SslCert != nil && !nginxIsSafePath(*cfg.SslCert) {
		return "", errors.New("Invalid SSL certificate path")
	}
	if cfg.SslKey != nil && !nginxIsSafePath(*cfg.SslKey) {
		return "", errors.New("Invalid SSL key path")
	}
	if cfg.CustomNginx != nil {
		if err := nginxValidateCustom(*cfg.CustomNginx); err != nil {
			return "", err
		}
	}

	rateLimit, maxUpload := uint32(0), uint32(64)
	if cfg.RateLimit != nil {
		rateLimit = *cfg.RateLimit
	}
	if cfg.MaxUploadMb != nil {
		maxUpload = *cfg.MaxUploadMb
	}
	redisDb := int32(0)
	if cfg.RedisDb != nil {
		redisDb = *cfg.RedisDb
	}
	ssl := nginxBool(cfg.Ssl)
	ctx := pongo2.Context{
		"domain":         domain,
		"root":           nginxStr(cfg.Root, "/var/www"),
		"bind_ip":        nginxDetectBindIP(),
		"runtime":        cfg.Runtime,
		"rate_limit":     int(rateLimit),
		"max_upload_mb":  int(maxUpload),
		"custom_nginx":   nginxStr(cfg.CustomNginx, ""),
		"fastcgi_cache":  nginxBool(cfg.FastcgiCache) && cfg.Runtime == "php",
		"redis_cache":    nginxBool(cfg.RedisCache) && cfg.Runtime == "php",
		"redis_db":       int(redisDb),
		"waf_enabled":    nginxBool(cfg.WafEnabled),
		"waf_mode":       nginxStr(cfg.WafMode, "detection"),
		"csp_policy":     nginxSanitizeHeaderValue(nginxStr(cfg.CspPolicy, "")),
		"bot_protection": nginxStr(cfg.BotProtection, "off"),
		"ssl":            ssl,
		"permissions_policy": nginxSanitizeHeaderValue(
			nginxStr(cfg.PermissionsPolicy, "camera=(), microphone=(), geolocation=()")),
	}
	if ssl {
		ctx["ssl_cert"] = nginxStr(cfg.SslCert, fmt.Sprintf("/etc/dockpanel/ssl/%s/fullchain.pem", domain))
		ctx["ssl_key"] = nginxStr(cfg.SslKey, fmt.Sprintf("/etc/dockpanel/ssl/%s/privkey.pem", domain))
	}

	plain := "http.conf"
	switch cfg.Runtime {
	case "proxy", "node", "python":
		port := uint16(3000)
		if cfg.ProxyPort != nil {
			port = *cfg.ProxyPort
		}
		ctx["proxy_port"] = int(port)
		// Node/Python use the same proxy template as "proxy".
		ctx["runtime"] = "proxy"
		plain = "proxy.conf"
	case "php":
		ctx["php_socket"] = nginxStr(cfg.PhpSocket, "unix:/run/php/php-fpm.sock")
		ctx["php_preset"] = nginxStr(cfg.PhpPreset, "generic")
	}
	if ssl {
		return nginxRender(set, "https.conf", ctx)
	}
	return nginxRender(set, plain, ctx)
}

// NginxWritePhpPoolConfig writes a per-site PHP-FPM pool with resource
// limits. Debian layout only (/etc/php/{v}/fpm/pool.d); absent tree (RHEL, or
// PHP not installed) is a silent no-op, degrading to the shared pool.
// poolOwner is (user, group) for SFTP-enabled sites, which own their content
// under their own uid — www-data would lose write access. nil = www-data.
func NginxWritePhpPoolConfig(domain, phpVersion string, memoryMb, maxWorkers uint32, poolOwner *[2]string) error {
	poolDir := fmt.Sprintf("/etc/php/%s/fpm/pool.d", phpVersion)
	if _, err := os.Stat(poolDir); err != nil {
		return nil
	}
	poolName := strings.ReplaceAll(domain, ".", "_")
	user, group := "www-data", "www-data"
	if poolOwner != nil {
		user, group = poolOwner[0], poolOwner[1]
	}
	cfg := fmt.Sprintf(`[%[1]s]
user = %[2]s
group = %[3]s
listen = /run/php/php%[4]s-fpm-%[1]s.sock
listen.owner = %[2]s
listen.group = %[3]s
listen.mode = 0660

pm = dynamic
pm.max_children = %[5]d
pm.start_servers = %[6]d
pm.min_spare_servers = 1
pm.max_spare_servers = %[7]d
pm.max_requests = 500

php_admin_value[memory_limit] = %[8]dM
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 64M
php_admin_value[max_execution_time] = 300
`, poolName, user, group, phpVersion, maxWorkers, min(2, maxWorkers), min(3, maxWorkers), memoryMb)

	poolPath := fmt.Sprintf("%s/%s.conf", poolDir, poolName)
	if err := os.WriteFile(poolPath, []byte(cfg), 0o644); err != nil {
		return fmt.Errorf("Failed to write FPM pool config: %v", err)
	}
	slog.Info(fmt.Sprintf("PHP-FPM pool config written: %s (user=%s, workers=%d, memory=%dM)", poolPath, user, maxWorkers, memoryMb))
	return nil
}

// NginxReloadPhpFpm reloads php{v}-fpm. A failed reload is not fatal (the
// pool applies on the next restart); only a failure to run errors.
func NginxReloadPhpFpm(phpVersion string) error {
	service := fmt.Sprintf("php%s-fpm", phpVersion)
	out, err := safecmd.Exec(context.Background(), "systemctl", "reload", service)
	if err != nil {
		return fmt.Errorf("Failed to reload %s: %v", service, err)
	}
	if out.Success() {
		slog.Info(service + " reloaded")
	} else {
		slog.Warn(fmt.Sprintf("%s reload failed (will apply on restart): %s", service, out.Stderr))
	}
	return nil
}

// NginxTestConfig runs `nginx -t` (30s timeout).
func NginxTestConfig() (NginxCmdOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "nginx", "-t")
	if errors.Is(err, context.DeadlineExceeded) {
		return NginxCmdOutput{}, errors.New("nginx -t timed out")
	}
	if err != nil {
		return NginxCmdOutput{}, err
	}
	return NginxCmdOutput{Success: out.Success(), Stdout: nginxLossy(out.Stdout), Stderr: nginxLossy(out.Stderr)}, nil
}

// NginxReload reloads nginx gracefully (30s timeout).
func NginxReload() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "nginx", "-s", "reload")
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("Nginx reload timed out")
	}
	if err != nil {
		return fmt.Errorf("Failed to execute nginx: %v", err)
	}
	if !out.Success() {
		stderr := nginxLossy(out.Stderr)
		slog.Error("Nginx reload failed: " + stderr)
		return fmt.Errorf("Nginx reload failed: %s", stderr)
	}
	slog.Info("Nginx reloaded successfully")
	return nil
}

// ── small shared helpers (used by the other web-group files) ────────────

// nginxLines splits like Rust's str::lines: on '\n', dropping one trailing
// '\r' per line and the empty piece after a final newline.
func nginxLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	parts := strings.Split(s, "\n")
	for i, p := range parts {
		parts[i] = strings.TrimSuffix(p, "\r")
	}
	return parts
}

// nginxLossy mirrors String::from_utf8_lossy.
func nginxLossy(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

func nginxContains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func nginxExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// nginxIOErr strips Go's "op path:" prefix so messages read like Rust's
// io::Error display ("No such file or directory (os error 2)" aside).
func nginxIOErr(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	return err
}
