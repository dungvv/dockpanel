package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/sitelock"
)

const (
	wordpressWpCli  = "/usr/local/bin/wp"
	wordpressWpRoot = "/var/www"
)

func wordpressLossy(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

func wordpressSitePath(domain string) (string, error) {
	if domain == "" || strings.Contains(domain, "..") || strings.Contains(domain, "/") {
		return "", fmt.Errorf("Invalid domain")
	}
	for _, c := range domain {
		if !(c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') || c == '.' || c == '-') {
			return "", fmt.Errorf("Invalid domain")
		}
	}
	return wordpressWpRoot + "/" + domain + "/public", nil
}

// wordpressChownSite fixes ownership after wp-cli wrote files (best effort).
func wordpressChownSite(path string) {
	_, _ = safecmd.Exec(context.Background(), "chown", "-R", "www-data:www-data", path)
}

// WordpressEnsureCli ensures wp-cli is installed at /usr/local/bin/wp.
func WordpressEnsureCli() error {
	if _, err := os.Stat(wordpressWpCli); err == nil {
		return nil
	}
	// curl writes to /usr/local/bin which isn't in the agent's ReadWritePaths
	// under ProtectSystem=strict — must run unsandboxed.
	out, err := safecmd.NewUnsandboxed("curl").Arg("-sS", "-L", "-o", wordpressWpCli,
		"https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar").Output(context.Background())
	if err != nil {
		return fmt.Errorf("Download failed: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("Failed to download wp-cli: %s", strings.TrimSpace(wordpressLossy(out.Stderr)))
	}
	_, _ = safecmd.NewUnsandboxed("chmod").Arg("+x", wordpressWpCli).Output(context.Background())
	return nil
}

// wordpressWp runs a wp-cli command, returning stdout on success. Uses
// --skip-plugins --skip-themes to prevent RCE from compromised plugins loading
// PHP during admin operations.
func wordpressWp(domain string, args ...string) (string, error) {
	return wordpressWpInner(domain, args, true)
}

// wordpressWpWithPlugins: for commands that need plugin/theme loading (list).
func wordpressWpWithPlugins(domain string, args ...string) (string, error) {
	return wordpressWpInner(domain, args, false)
}

func wordpressWpInner(domain string, args []string, skipPlugins bool) (string, error) {
	path, err := wordpressSitePath(domain)
	if err != nil {
		return "", err
	}
	return WordpressWpAtRoot(path, args, skipPlugins)
}

// WordpressWpAtRoot runs wp-cli against an EXPLICIT filesystem root.
//
// Every wp-cli invocation goes through here: one place decides the binary,
// EnsureCli, --allow-root (the agent runs as root and wp-cli refuses without
// it) and the skip policy. A hand-rolled second copy once ran `php` against a
// phar nothing ever wrote and omitted --allow-root, so both arms failed and
// the vulnerability scan reported a clean site.
//
// Bounded at 600s and killed on expiry: unbounded, a stalled download or a
// locked wp_options table blocked the request forever and left the child
// running orphaned.
func WordpressWpAtRoot(root string, args []string, skipPlugins bool) (string, error) {
	if err := WordpressEnsureCli(); err != nil {
		return "", err
	}
	argv := append(append([]string{}, args...), "--allow-root", "--path="+root)
	if skipPlugins {
		argv = append(argv, "--skip-plugins", "--skip-themes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, wordpressWpCli, argv...)
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("wp-cli timed out")
	}
	if err != nil {
		return "", fmt.Errorf("wp-cli error: %v", err)
	}
	if !out.Success() {
		return "", fmt.Errorf("%s", strings.TrimSpace(wordpressLossy(out.Stderr)))
	}
	return strings.TrimSpace(wordpressLossy(out.Stdout)), nil
}

// WordpressDetect reports whether WordPress is installed at the document root.
func WordpressDetect(domain string) bool {
	path, err := wordpressSitePath(domain)
	if err != nil {
		return false
	}
	_, err = os.Stat(path + "/wp-config.php")
	return err == nil
}

// WordpressInfo returns the WP version and update availability.
func WordpressInfo(domain string) (map[string]any, error) {
	version, err := wordpressWp(domain, "core", "version")
	if err != nil {
		return nil, err
	}
	check, _ := wordpressWp(domain, "core", "check-update", "--format=json")
	var updates []map[string]any
	_ = json.Unmarshal([]byte(check), &updates)
	var updateAvailable any
	if len(updates) > 0 {
		if v, ok := updates[0]["version"].(string); ok {
			updateAvailable = v
		}
	}
	return map[string]any{"installed": true, "version": version, "update_available": updateAvailable}, nil
}

func wordpressListJSON(domain, kind string) (any, error) {
	out, err := wordpressWpWithPlugins(domain, kind, "list", "--format=json")
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		return nil, fmt.Errorf("Parse error: %v", err)
	}
	return v, nil
}

// WordpressPlugins lists plugins (needs plugin loading for accurate status).
func WordpressPlugins(domain string) (any, error) { return wordpressListJSON(domain, "plugin") }

// WordpressThemes lists themes (needs theme loading for accurate status).
func WordpressThemes(domain string) (any, error) { return wordpressListJSON(domain, "theme") }

func wordpressRunAndChown(domain string, args ...string) (string, error) {
	result, err := wordpressWp(domain, args...)
	if err != nil {
		return "", err
	}
	path, err := wordpressSitePath(domain)
	if err != nil {
		return "", err
	}
	wordpressChownSite(path)
	return result, nil
}

// WordpressUpdateCore updates WordPress core.
func WordpressUpdateCore(domain string) (string, error) {
	return wordpressRunAndChown(domain, "core", "update")
}

// WordpressUpdateAllPlugins updates all plugins.
func WordpressUpdateAllPlugins(domain string) (string, error) {
	return wordpressRunAndChown(domain, "plugin", "update", "--all")
}

// WordpressUpdateAllThemes updates all themes.
func WordpressUpdateAllThemes(domain string) (string, error) {
	return wordpressRunAndChown(domain, "theme", "update", "--all")
}

// wordpressIsValidWpSlug: alphanumeric, hyphens, underscores only. Rejects
// URLs, flags, and shell metacharacters.
func wordpressIsValidWpSlug(name string) bool {
	if name == "" || len(name) > 200 || strings.HasPrefix(name, "-") || strings.Contains(name, "://") {
		return false
	}
	for _, c := range name {
		if !(c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// WordpressPluginAction: activate, deactivate, update, delete, install.
func WordpressPluginAction(domain, name, action string) (string, error) {
	if !wordpressIsValidWpSlug(name) {
		return "", fmt.Errorf("Invalid plugin name. Only alphanumeric, hyphens, and underscores allowed.")
	}
	switch action {
	case "activate", "deactivate", "update", "delete", "install":
	default:
		return "", fmt.Errorf("Unknown action: %s", action)
	}
	return wordpressSlugAction(domain, "plugin", name, action)
}

// WordpressThemeAction: activate, update, delete, install.
func WordpressThemeAction(domain, name, action string) (string, error) {
	if !wordpressIsValidWpSlug(name) {
		return "", fmt.Errorf("Invalid theme name. Only alphanumeric, hyphens, and underscores allowed.")
	}
	switch action {
	case "activate", "update", "delete", "install":
	default:
		return "", fmt.Errorf("Unknown action: %s", action)
	}
	return wordpressSlugAction(domain, "theme", name, action)
}

func wordpressSlugAction(domain, kind, name, action string) (string, error) {
	result, err := wordpressWp(domain, kind, action, name)
	if err != nil {
		return "", err
	}
	if action == "install" || action == "update" {
		path, err := wordpressSitePath(domain)
		if err != nil {
			return "", err
		}
		wordpressChownSite(path)
	}
	return result, nil
}

// WordpressInstall installs WordPress from scratch.
func WordpressInstall(domain, url, title, adminUser, adminPass, adminEmail, dbName, dbUser, dbPass, dbHost string) (string, error) {
	if err := WordpressEnsureCli(); err != nil {
		return "", err
	}
	path, err := wordpressSitePath(domain)
	if err != nil {
		return "", err
	}
	// Ensure document root exists before wp-cli tries to write.
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", fmt.Errorf("Failed to create site directory %s: %v", path, err)
	}
	if _, err := wordpressWp(domain, "core", "download", "--force"); err != nil {
		return "", err
	}

	// These two calls carry credential args and keep their own error text;
	// same 600s bound + kill as WordpressWpAtRoot.
	run := func(label, failPrefix string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
		defer cancel()
		args = append(args, "--skip-plugins", "--skip-themes", "--allow-root", "--path="+path)
		out, err := safecmd.Exec(ctx, wordpressWpCli, args...)
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("%s timed out", label)
		}
		if err != nil {
			return fmt.Errorf("%s: %v", label, err)
		}
		if !out.Success() {
			return fmt.Errorf("%s: %s", failPrefix, strings.TrimSpace(wordpressLossy(out.Stderr)))
		}
		return nil
	}
	if err := run("wp config create", "Config create failed", "config", "create",
		"--dbname="+dbName, "--dbuser="+dbUser, "--dbpass="+dbPass, "--dbhost="+dbHost); err != nil {
		return "", err
	}
	if err := run("wp core install", "Core install failed", "core", "install",
		"--url="+url, "--title="+title, "--admin_user="+adminUser,
		"--admin_password="+adminPass, "--admin_email="+adminEmail); err != nil {
		return "", err
	}

	wordpressChownSite(path)
	// `config create` leaves wp-config.php at the umask default (644) —
	// tighten to 640 so other local accounts cannot read DB credentials. (Every
	// site still shares www-data, so this does not isolate tenants' PHP pools.)
	_, _ = safecmd.Exec(context.Background(), "chmod", "640", path+"/wp-config.php")
	return "WordPress installed successfully", nil
}

// WordpressCanonicalUrlOutcome is what happened to a site's stored canonical
// URL when its certificate landed. Comparable; the zero value is Untouched.
// JSON: "untouched" | "promoted" | {"failed": msg} (Rust serde snake_case enum).
type WordpressCanonicalUrlOutcome struct {
	kind uint8 // 0 untouched, 1 promoted, 2 failed
	msg  string
}

var (
	// WordpressCanonicalUrlUntouched: no WordPress here, or its URL is not ours to change.
	WordpressCanonicalUrlUntouched = WordpressCanonicalUrlOutcome{}
	// WordpressCanonicalUrlPromoted: siteurl/home moved from plain HTTP to HTTPS.
	WordpressCanonicalUrlPromoted = WordpressCanonicalUrlOutcome{kind: 1}
)

// WordpressCanonicalUrlFailed: wp-cli refused. The certificate is live and
// nginx now redirects to it, but the site still tells every visitor to use HTTP.
func WordpressCanonicalUrlFailed(msg string) WordpressCanonicalUrlOutcome {
	return WordpressCanonicalUrlOutcome{kind: 2, msg: msg}
}

// Failure returns the failure message, if this is the failed variant.
func (o WordpressCanonicalUrlOutcome) Failure() (string, bool) { return o.msg, o.kind == 2 }

// MarshalJSON matches serde's externally tagged snake_case enum.
func (o WordpressCanonicalUrlOutcome) MarshalJSON() ([]byte, error) {
	switch o.kind {
	case 1:
		return []byte(`"promoted"`), nil
	case 2:
		return json.Marshal(map[string]string{"failed": o.msg})
	}
	return []byte(`"untouched"`), nil
}

// WordpressHttpsPromotionTarget returns the replacement only when the stored
// value is exactly the plain-HTTP form of this vhost's own domain — the state
// DockPanel creates when it installs a site before the certificate exists.
// Any other value (another host, a sub-path, already HTTPS) was chosen by the
// operator and is left alone: promoting it would silently repoint a site.
func WordpressHttpsPromotionTarget(current, domain string) (string, bool) {
	current = strings.TrimRight(strings.TrimSpace(current), "/")
	if strings.EqualFold(current, "http://"+domain) {
		return "https://" + domain, true
	}
	return "", false
}

// WordpressPromoteSiteUrlToHttps moves a WordPress site's canonical URL from
// HTTP to HTTPS once a certificate is in place. Once nginx redirects to HTTPS
// the stored URL decides every generated link and redirect, so this finishes
// the job rather than being a cosmetic tidy-up.
func WordpressPromoteSiteUrlToHttps(domain string) WordpressCanonicalUrlOutcome {
	if !WordpressDetect(domain) {
		return WordpressCanonicalUrlUntouched
	}
	changed := false
	for _, option := range []string{"siteurl", "home"} {
		current, err := wordpressWp(domain, "option", "get", option)
		if err != nil {
			return WordpressCanonicalUrlFailed(fmt.Sprintf("read %s: %v", option, err))
		}
		target, ok := WordpressHttpsPromotionTarget(current, domain)
		if !ok {
			continue
		}
		if _, err := wordpressWp(domain, "option", "update", option, target); err != nil {
			return WordpressCanonicalUrlFailed(fmt.Sprintf("update %s: %v", option, err))
		}
		changed = true
	}
	if changed {
		return WordpressCanonicalUrlPromoted
	}
	return WordpressCanonicalUrlUntouched
}

// wordpressAutoUpdateMarker is the comment a site's auto-update cron line ends
// with. Compared with wordpressLineMarkedFor, never Contains: the marker sits
// at the end of the line, so `# wp-auto-update-example.com` is a substring of
// `# wp-auto-update-example.community`, and toggling (or deleting) one site
// silently stripped the other's security updates.
func wordpressAutoUpdateMarker(domain string) string { return "# wp-auto-update-" + domain }

func wordpressLineMarkedFor(line, marker string) bool {
	return strings.HasSuffix(strings.TrimRightFunc(line, unicode.IsSpace), marker)
}

// WordpressSetAutoUpdate sets or removes the auto-update cron line.
func WordpressSetAutoUpdate(domain string, enabled bool) error {
	path, err := wordpressSitePath(domain)
	if err != nil {
		return err
	}
	marker := wordpressAutoUpdateMarker(domain)
	cronLine := fmt.Sprintf("0 3 * * * %[1]s core update --skip-plugins --skip-themes --allow-root --path=%[2]s > /dev/null 2>&1 && "+
		"%[1]s plugin update --all --skip-plugins --skip-themes --allow-root --path=%[2]s > /dev/null 2>&1 && "+
		"%[1]s theme update --all --skip-plugins --skip-themes --allow-root --path=%[2]s > /dev/null 2>&1 "+
		"%[3]s", wordpressWpCli, path, marker)

	// FAIL-CLOSED read: a failed `crontab -l` collapsed to "" once rewrote
	// root's entire crontab down to this one line.
	current, err := CrontabRead()
	if err != nil {
		return err
	}
	var kept []string
	for _, l := range LogsLines([]byte(current)) {
		if !wordpressLineMarkedFor(l, marker) {
			kept = append(kept, l)
		}
	}
	next := strings.Join(kept, "\n")
	if next != "" && !strings.HasSuffix(next, "\n") {
		next += "\n"
	}
	if enabled {
		next += cronLine + "\n"
	}
	return CrontabWrite(next)
}

// WordpressIsAutoUpdateEnabled checks the auto-update cron line, anchored for
// the same reason as the removal (delete_site trusts this answer).
func WordpressIsAutoUpdateEnabled(domain string) bool {
	marker := wordpressAutoUpdateMarker(domain)
	out, err := safecmd.Exec(context.Background(), "crontab", "-l", "-u", "root")
	if err != nil {
		return false
	}
	for _, l := range LogsLines(out.Stdout) {
		if wordpressLineMarkedFor(l, marker) {
			return true
		}
	}
	return false
}

// WordpressCreateUpdateSnapshot creates a pre-update snapshot (files + DB).
func WordpressCreateUpdateSnapshot(domain string) (string, error) {
	if _, err := wordpressSitePath(domain); err != nil {
		return "", err
	}
	snapshotDir := "/var/backups/dockpanel/wp-snapshots/" + domain
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return "", fmt.Errorf("Create snapshot dir: %v", err)
	}
	ts := time.Now().UTC().Format("20060102_150405")
	snapshotPath := fmt.Sprintf("%s/pre-update-%s.tar.gz", snapshotDir, ts)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tar, err := safecmd.Exec(ctx, "tar", "czf", snapshotPath, "-C", "/var/www", domain+"/public")
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("Snapshot tar timed out")
	}
	if err != nil {
		return "", fmt.Errorf("Snapshot tar: %v", err)
	}
	if !tar.Success() {
		return "", fmt.Errorf("Snapshot failed: %s", wordpressTakeChars(wordpressLossy(tar.Stderr), 200))
	}

	dbName, _ := wordpressWp(domain, "config", "get", "DB_NAME")
	if strings.TrimSpace(dbName) != "" {
		_, _ = wordpressWp(domain, "db", "export", fmt.Sprintf("%s/pre-update-%s.sql", snapshotDir, ts), "--quiet")
	}

	// Keep the last 5 snapshots.
	if entries, err := os.ReadDir(snapshotDir); err == nil {
		var names []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tar.gz") {
				names = append(names, e.Name())
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		for i := 5; i < len(names); i++ {
			p := filepath.Join(snapshotDir, names[i])
			_ = os.Remove(p)
			// Rust: path.with_extension("").with_extension("sql") —
			// x.tar.gz → x.tar → x.sql.
			_ = os.Remove(strings.TrimSuffix(p, ".tar.gz") + ".sql")
		}
	}
	slog.Info(fmt.Sprintf("WP update snapshot created for %s: %s", domain, snapshotPath))
	return snapshotPath, nil
}

func wordpressTakeChars(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// WordpressRollbackFromSnapshot restores a site from a snapshot.
func WordpressRollbackFromSnapshot(domain, snapshotPath string) error {
	if _, err := os.Stat(snapshotPath); err != nil {
		return fmt.Errorf("Snapshot file not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "tar", "xzf", snapshotPath, "-C", "/var/www")
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("Rollback timed out")
	}
	if err != nil {
		return fmt.Errorf("Rollback tar: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("Rollback tar extraction failed")
	}
	sqlPath := strings.ReplaceAll(snapshotPath, ".tar.gz", ".sql")
	if _, err := os.Stat(sqlPath); err == nil {
		_, _ = wordpressWp(domain, "db", "import", sqlPath, "--quiet")
	}
	wordpressChownSite("/var/www/" + domain + "/public")
	slog.Info(fmt.Sprintf("WP rollback completed for %s from %s", domain, snapshotPath))
	return nil
}

// WordpressHealthCheck checks WordPress responds to wp-cli, run as www-data.
func WordpressHealthCheck(domain string) bool {
	path, _ := wordpressSitePath(domain)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "sudo", "-u", "www-data", wordpressWpCli, "eval", "echo 'OK';",
		"--skip-plugins", "--skip-themes", "--allow-root", "--path="+path)
	return err == nil && out.Success() && strings.Contains(wordpressLossy(out.Stdout), "OK")
}

// WordpressUpdateWithRollback updates WordPress with snapshot + rollback.
//
// The site lock is held for the whole snapshot→update→rollback sequence: a
// rollback restores the snapshot unconditionally, so any concurrent write into
// the docroot (hardening, a restore, a staging sync) would be discarded.
func WordpressUpdateWithRollback(domain string) (map[string]any, error) {
	defer sitelock.LockSite(domain)()

	log := []string{}
	if !WordpressHealthCheck(domain) {
		return nil, fmt.Errorf("Site failed pre-update health check — skipping update")
	}
	log = append(log, "Pre-update health check: passed")

	snapshot, err := WordpressCreateUpdateSnapshot(domain)
	if err != nil {
		return nil, err
	}
	log = append(log, "Snapshot created")

	coreBefore, _ := wordpressWp(domain, "core", "version")
	okStr := func(err error) string {
		if err == nil {
			return "ok"
		}
		return "failed"
	}
	_, coreErr := wordpressWp(domain, "core", "update")
	_, pluginsErr := wordpressWp(domain, "plugin", "update", "--all")
	_, themesErr := wordpressWp(domain, "theme", "update", "--all")
	log = append(log, fmt.Sprintf("Updates: core=%s, plugins=%s, themes=%s", okStr(coreErr), okStr(pluginsErr), okStr(themesErr)))

	wordpressChownSite("/var/www/" + domain + "/public")

	healthy := WordpressHealthCheck(domain)
	if !healthy {
		log = append(log, "Post-update health check: FAILED — rolling back")
		if err := WordpressRollbackFromSnapshot(domain, snapshot); err != nil {
			log = append(log, fmt.Sprintf("Rollback failed: %v", err))
			slog.Error(fmt.Sprintf("WP rollback failed for %s: %v", domain, err))
		} else {
			log = append(log, "Rollback completed successfully")
			slog.Warn(fmt.Sprintf("WP update for %s rolled back due to health check failure", domain))
		}
	} else {
		log = append(log, "Post-update health check: passed")
	}
	coreAfter, _ := wordpressWp(domain, "core", "version")

	return map[string]any{
		"domain":      domain,
		"healthy":     healthy,
		"rolled_back": !healthy,
		"core_before": strings.TrimSpace(coreBefore),
		"core_after":  strings.TrimSpace(coreAfter),
		"snapshot":    snapshot,
		"log":         log,
	}, nil
}
