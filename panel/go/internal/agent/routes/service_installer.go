package routes

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// serviceInstallerUnicodeMapping rides the BINARY instead of distro packaging:
// modsecurity.conf declares `SecUnicodeMapFile unicode.mapping 20127` and
// ModSecurity refuses a file it cannot parse, so an absent/empty one fails
// `nginx -t` the first time a site enables the WAF (issue #92: Debian 13's
// libmodsecurity3t64 ships none). Vendored from upstream ModSecurity
// (panel/agent/assets/unicode.mapping).
//
//go:embed unicode.mapping
var serviceInstallerUnicodeMapping string

const serviceInstallerMappingPath = "/etc/modsecurity/unicode.mapping"

func registerServiceInstaller(r *Router) {
	r.Handle("GET /services/install-status", serviceInstallerInstallStatus)
	r.Handle("POST /services/install/php", serviceInstallerInstallPhp)
	r.Handle("POST /services/install/certbot", serviceInstallerInstallCertbot)
	r.Handle("POST /services/install/ufw", serviceInstallerInstallUfw)
	r.Handle("POST /services/install/fail2ban", serviceInstallerInstallFail2ban)
	r.Handle("POST /services/install/powerdns", serviceInstallerInstallPowerdns)
	r.Handle("POST /services/install/redis", serviceInstallerInstallRedis)
	r.Handle("POST /services/install/nodejs", serviceInstallerInstallNodejs)
	r.Handle("POST /services/install/composer", serviceInstallerInstallComposer)
	r.Handle("POST /services/install/sshpass", serviceInstallerInstallSshpass)
	r.Handle("POST /services/uninstall/php", serviceInstallerUninstallPhp)
	r.Handle("POST /services/uninstall/certbot", serviceInstallerUninstallCertbot)
	r.Handle("POST /services/uninstall/ufw", serviceInstallerUninstallUfw)
	r.Handle("POST /services/uninstall/fail2ban", serviceInstallerUninstallFail2ban)
	r.Handle("POST /services/uninstall/powerdns", serviceInstallerUninstallPowerdns)
	r.Handle("POST /services/uninstall/redis", serviceInstallerUninstallRedis)
	r.Handle("POST /services/uninstall/nodejs", serviceInstallerUninstallNodejs)
	r.Handle("POST /services/uninstall/composer", serviceInstallerUninstallComposer)
	r.Handle("POST /services/install/waf", serviceInstallerInstallWaf)
	r.Handle("POST /services/uninstall/waf", serviceInstallerUninstallWaf)
	r.Handle("POST /services/install/cloudflared", serviceInstallerInstallCloudflared)
	r.Handle("POST /services/uninstall/cloudflared", serviceInstallerUninstallCloudflared)
	r.Handle("POST /services/cloudflared/configure", serviceInstallerConfigureCloudflared)
	r.Handle("GET /services/cloudflared/status", serviceInstallerCloudflaredStatus)
}

// ── helpers ─────────────────────────────────────────────────────────────

func serviceInstallerOk(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

func serviceInstallerLossy(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

func serviceInstallerTake(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// serviceInstallerRun runs a sandboxed command bounded by timeout; ok=false
// when it could not run or timed out.
func serviceInstallerRun(timeout time.Duration, bin string, args ...string) (safecmd.Output, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := safecmd.Exec(ctx, bin, args...)
	return out, err == nil
}

func serviceInstallerSystemctl(timeout time.Duration, args ...string) {
	serviceInstallerRun(timeout, "systemctl", args...)
}

// serviceInstallerSh runs `sh -c script` OUTSIDE the sandbox, bounded.
func serviceInstallerSh(timeout time.Duration, script string) (safecmd.Output, error) {
	return safecmd.NewUnsandboxed("sh").Arg("-c", script).OutputWithTimeout(timeout)
}

func serviceInstallerStdout(timeout time.Duration, bin string, args ...string) string {
	out, ok := serviceInstallerRun(timeout, bin, args...)
	if !ok {
		return ""
	}
	return strings.TrimSpace(serviceInstallerLossy(out.Stdout))
}

// serviceInstallerRefuse writes 501 with why when the box has no installer.
func serviceInstallerRefuse(w http.ResponseWriter, what string) bool {
	if why := services.PkgNoInstallerReason(what); why != "" {
		writeErr(w, http.StatusNotImplemented, why)
		return true
	}
	return false
}

// serviceInstallerIsInstalled: package presence on dpkg and rpm alike (this
// once shelled out to dpkg and answered false on the whole RHEL family).
func serviceInstallerIsInstalled(pkg string) bool { return services.PkgIsInstalled(pkg) }

func serviceInstallerIsActive(svc string) bool {
	out, ok := serviceInstallerRun(120*time.Second, "systemctl", "is-active", "--quiet", svc)
	return ok && out.Success()
}

func serviceInstallerWhich(cmd string) bool {
	out, ok := serviceInstallerRun(120*time.Second, "which", cmd)
	return ok && out.Success()
}

func serviceInstallerIsUfwActive() bool {
	out, ok := serviceInstallerRun(120*time.Second, "ufw", "status")
	return ok && strings.Contains(serviceInstallerLossy(out.Stdout), "Status: active")
}

func serviceInstallerDetectPhpVersion() (string, bool) {
	out, ok := serviceInstallerRun(120*time.Second, "php", "-r", "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")
	if !ok || !out.Success() {
		return "", false
	}
	return strings.TrimSpace(serviceInstallerLossy(out.Stdout)), true
}

// serviceInstallerDetectAvailablePhp: the distro default first (`apt-cache
// depends php-fpm` names the real package — the old fixed list topped out at
// 8.3 and fell back to a php8.3 no repo could satisfy), then newest-first.
func serviceInstallerDetectAvailablePhp() (string, bool) {
	if out, ok := serviceInstallerRun(120*time.Second, "apt-cache", "depends", "php-fpm"); ok && out.Success() {
		for _, line := range services.LogsLines(out.Stdout) {
			rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Depends: php")
			if !ok {
				continue
			}
			if v, ok := strings.CutSuffix(rest, "-fpm"); ok && v != "" && strings.Trim(v, "0123456789.") == "" {
				return v, true
			}
		}
	}
	for _, v := range []string{"8.5", "8.4", "8.3", "8.2", "8.1"} {
		if out, ok := serviceInstallerRun(120*time.Second, "apt-cache", "show", "php"+v+"-fpm"); ok && out.Success() {
			return v, true
		}
	}
	return "", false
}

// ── Status ──────────────────────────────────────────────────────────────

func serviceInstallerInstallStatus(w http.ResponseWriter, _ *http.Request) {
	anyOf := func(f func(string) bool, names ...string) bool {
		for _, n := range names {
			if f(n) {
				return true
			}
		}
		return false
	}
	pdnsInstalled := serviceInstallerIsInstalled("pdns-server")
	pdnsRunning := serviceInstallerIsActive("pdns")
	// Keep in lock-step with php.go's allowed versions: every installer path
	// installs php{ver}-fpm directly, never the metapackage.
	phpInstalled := anyOf(serviceInstallerIsInstalled, "php-fpm", "php8.5-fpm", "php8.4-fpm", "php8.3-fpm", "php8.2-fpm", "php8.1-fpm")
	// Debian names the unit per version; the RHEL family has a single php-fpm.
	phpRunning := anyOf(serviceInstallerIsActive, "php8.5-fpm", "php8.4-fpm", "php8.3-fpm", "php8.2-fpm", "php8.1-fpm", "php-fpm")
	certbot := serviceInstallerWhich("certbot")
	ufw := serviceInstallerWhich("ufw")
	ufwActive := serviceInstallerIsUfwActive()
	f2b := serviceInstallerIsInstalled("fail2ban")
	f2bRunning := serviceInstallerIsActive("fail2ban")
	var phpVersion any
	if v, ok := serviceInstallerDetectPhpVersion(); ok {
		phpVersion = v
	}
	redis := serviceInstallerWhich("redis-server") || serviceInstallerIsInstalled("redis-server")
	redisRunning := serviceInstallerIsActive("redis-server")
	node := serviceInstallerWhich("node")
	composer := serviceInstallerWhich("composer")
	// Noble renamed libmodsecurity3 → libmodsecurity3t64 (time_t-64 ABI).
	_, confErr := os.Stat("/etc/modsecurity/modsecurity.conf")
	waf := confErr == nil && (serviceInstallerIsInstalled("libmodsecurity3") || serviceInstallerIsInstalled("libmodsecurity3t64"))
	cf := serviceInstallerWhich("cloudflared")
	cfRunning := serviceInstallerIsActive("cloudflared")
	// sshpass is a binary the backup path execs, not a daemon.
	sshpass := serviceInstallerWhich("sshpass")

	type m = map[string]any
	writeJSON(w, http.StatusOK, m{
		"php":         m{"installed": phpInstalled, "running": phpRunning, "version": phpVersion},
		"certbot":     m{"installed": certbot},
		"ufw":         m{"installed": ufw, "active": ufwActive},
		"fail2ban":    m{"installed": f2b, "running": f2bRunning},
		"powerdns":    m{"installed": pdnsInstalled, "running": pdnsRunning},
		"redis":       m{"installed": redis, "running": redisRunning},
		"nodejs":      m{"installed": node},
		"composer":    m{"installed": composer},
		"waf":         m{"installed": waf},
		"cloudflared": m{"installed": cf, "running": cfRunning},
		"sshpass":     m{"installed": sshpass},
	})
}

// ── PHP ─────────────────────────────────────────────────────────────────

func serviceInstallerInstallPhp(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Installing PHP") {
		return
	}
	slog.Info("Installing PHP...")

	// dnf resolves php-fpm to the NON-modular base package unless a module
	// stream is enabled first — on Rocky 9 that is EOL PHP 8.0, installed
	// silently under a green status (s266).
	var version string
	if streams := services.PkgPhpStreams(); len(streams) == 0 {
		v, ok := serviceInstallerDetectAvailablePhp()
		if !ok {
			v = "8.3"
		}
		version = v
	} else {
		// Honour the distro's newest stream; apt-cache cannot answer here.
		version = streams[0]
		if err := services.PkgEnablePhpStream(version); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Could not select PHP %s: %v", version, err))
			return
		}
	}

	// Core first (must succeed), then only extensions with a real candidate:
	// one uninstallable name fails the whole transaction on apt and dnf alike.
	if err := services.PkgInstall([]string{"php" + version + "-fpm", "php" + version + "-cli"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("PHP install failed: %v", err))
		return
	}
	var exts []string
	for _, e := range []string{"mysql", "pgsql", "sqlite3", "curl", "gd", "mbstring", "xml", "zip", "bcmath", "intl", "readline", "opcache"} {
		exts = append(exts, "php"+version+"-"+e)
	}
	skipped, err := services.PkgInstallAvailable(exts)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("PHP extension install failed: %v", err))
		return
	}
	if len(skipped) > 0 {
		// Not a failure: 8.5 absorbed opcache; RHEL ships curl/sqlite3 in php-common.
		slog.Info("PHP extensions with no candidate here, skipped: " + strings.Join(skipped, " "))
	}

	// The UNIT name is a separate translation from the PACKAGE name.
	unit := services.PkgServiceName("php" + version + "-fpm")
	serviceInstallerSystemctl(120*time.Second, "enable", unit)
	serviceInstallerSystemctl(120*time.Second, "start", unit)
	slog.Info(fmt.Sprintf("PHP %s installed (unit %s)", version, unit))
	serviceInstallerOk(w, fmt.Sprintf("PHP %s with FPM installed and started", version))
}

func serviceInstallerUninstallPhp(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Removing PHP") {
		return
	}
	slog.Info("Uninstalling PHP...")
	version, ok := serviceInstallerDetectPhpVersion()
	if !ok {
		version = "8.3"
	}
	unit := services.PkgServiceName("php" + version + "-fpm")
	serviceInstallerSystemctl(120*time.Second, "stop", unit)
	serviceInstallerSystemctl(120*time.Second, "disable", unit)

	// The glob is family-specific and NOT routed through PkgRemove, which
	// translates NAMES; a glob through the map would match nothing.
	var cmd string
	if services.PkgManager() == services.PkgMgrRpm {
		cmd = "dnf remove -y 'php-*'"
	} else {
		cmd = fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get purge -y php%s-* && apt-get autoremove -y", version)
	}
	out, err := serviceInstallerSh(300*time.Second, cmd)
	if err != nil {
		if strings.Contains(err.Error(), "timed out") {
			writeErr(w, http.StatusInternalServerError, "PHP uninstall timed out after 300s")
		} else {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("PHP uninstall failed: %v", err))
		}
		return
	}
	if !out.Success() {
		writeErr(w, http.StatusInternalServerError, "PHP uninstall failed: "+serviceInstallerTake(serviceInstallerLossy(out.Stderr), 300))
		return
	}
	slog.Info(fmt.Sprintf("PHP %s uninstalled", version))
	serviceInstallerOk(w, fmt.Sprintf("PHP %s purged and removed", version))
}

// ── Certbot ─────────────────────────────────────────────────────────────

func serviceInstallerInstallCertbot(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Installing Certbot") {
		return
	}
	slog.Info("Installing Certbot...")

	// RHEL: EPEL packages certbot and its nginx plugin directly; the snap→pip
	// ladder below is a Debian/Ubuntu strategy for a 4.x certbot with ARI.
	if services.PkgManager() == services.PkgMgrRpm {
		if err := services.PkgInstall([]string{"certbot", "python3-certbot-nginx"}); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Certbot install failed: %v", err))
			return
		}
		// EPEL ships a renewal timer with the package.
		serviceInstallerSystemctl(30*time.Second, "enable", "--now", "certbot-renew.timer")
		slog.Info("Certbot installed from EPEL with the nginx plugin")
		serviceInstallerOk(w, "Certbot installed with the nginx plugin and automatic renewal")
		return
	}

	// Remove an old apt certbot first to avoid conflicts.
	_, _ = serviceInstallerSh(120*time.Second, "systemctl stop certbot.timer 2>/dev/null; systemctl disable certbot.timer 2>/dev/null; DEBIAN_FRONTEND=noninteractive apt-get purge -y certbot python3-certbot-nginx 2>/dev/null; true")

	// snap gets certbot 4.x (ARI for 45-day certs); pip is the fallback.
	out, err := serviceInstallerSh(300*time.Second, "snap install --classic certbot && ln -sf /snap/bin/certbot /usr/bin/certbot")
	if err == nil && out.Success() {
		// The nginx plugin is non-fatal — certbot still works without it.
		_, _ = serviceInstallerSh(120*time.Second, "snap set certbot trust-plugin-with-root=ok && snap install certbot-nginx")
		slog.Info("Certbot installed via snap (4.x with ARI support)")
		serviceInstallerSystemctl(30*time.Second, "enable", "snap.certbot.renew.timer")
		serviceInstallerSystemctl(30*time.Second, "start", "snap.certbot.renew.timer")
		serviceInstallerOk(w, "Certbot 4.x installed via snap with nginx plugin and auto-renewal (ARI-ready for 45-day certs)")
		return
	}

	slog.Warn("Snap certbot failed, falling back to pip...")
	out, err = serviceInstallerSh(300*time.Second, "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv && "+
		"python3 -m venv /opt/certbot && "+
		"/opt/certbot/bin/pip install --upgrade pip && "+
		"/opt/certbot/bin/pip install certbot certbot-nginx && "+
		"ln -sf /opt/certbot/bin/certbot /usr/bin/certbot")
	if err == nil && out.Success() {
		slog.Info("Certbot installed via pip")
		timer := "[Unit]\nDescription=Certbot renewal timer\n\n[Timer]\nOnCalendar=*-*-* 00,12:00:00\nRandomizedDelaySec=3600\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
		svc := "[Unit]\nDescription=Certbot renewal\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/certbot renew --quiet --deploy-hook \"systemctl reload nginx\"\n"
		_ = os.WriteFile("/etc/systemd/system/certbot.timer", []byte(timer), 0o644)
		_ = os.WriteFile("/etc/systemd/system/certbot.service", []byte(svc), 0o644)
		serviceInstallerSystemctl(30*time.Second, "daemon-reload")
		serviceInstallerSystemctl(30*time.Second, "enable", "certbot.timer")
		serviceInstallerSystemctl(30*time.Second, "start", "certbot.timer")
		serviceInstallerOk(w, "Certbot installed via pip with nginx plugin and auto-renewal timer")
		return
	}
	writeErr(w, http.StatusInternalServerError, "Certbot install failed: both snap and pip methods failed")
}

func serviceInstallerUninstallCertbot(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Removing Certbot") {
		return
	}
	slog.Info("Uninstalling Certbot...")
	// Every renewal timer certbot might have arrived with (apt/pip, snap, EPEL).
	for _, t := range []string{"certbot.timer", "snap.certbot.renew.timer", "certbot-renew.timer"} {
		serviceInstallerSystemctl(30*time.Second, "stop", t)
		serviceInstallerSystemctl(30*time.Second, "disable", t)
	}
	_, _ = serviceInstallerSh(120*time.Second, "snap remove certbot 2>/dev/null; snap remove certbot-nginx 2>/dev/null; true")
	if _, err := os.Stat("/opt/certbot"); err == nil {
		_ = os.RemoveAll("/opt/certbot")
		_ = os.Remove("/etc/systemd/system/certbot.timer")
		_ = os.Remove("/etc/systemd/system/certbot.service")
		serviceInstallerSystemctl(30*time.Second, "daemon-reload")
	}
	// Best-effort: snap/pip may already have removed it.
	_ = services.PkgRemove([]string{"certbot", "python3-certbot-nginx"})
	_ = os.Remove("/usr/bin/certbot")
	slog.Info("Certbot uninstalled")
	serviceInstallerOk(w, "Certbot and auto-renewal timer removed")
}

// ── UFW ─────────────────────────────────────────────────────────────────

// serviceInstallerInstallUfw installs UFW on Debian/Ubuntu only, DELIBERATELY:
// RHEL boots with firewalld enforcing and UFW beside it produced the s265
// outage (80/443 "open" in the filter nobody consulted). Ports are opened via
// services.Firewall*, which speaks to whichever filter runs.
func serviceInstallerInstallUfw(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Installing UFW") {
		return
	}
	if why := services.PkgUfwRefusalReason(); why != "" {
		writeErr(w, http.StatusNotImplemented, why)
		return
	}
	slog.Info("Installing UFW...")
	if err := services.PkgInstall([]string{"ufw"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("UFW install failed: %v", err))
		return
	}
	serviceInstallerRun(120*time.Second, "ufw", "default", "deny", "incoming")
	serviceInstallerRun(120*time.Second, "ufw", "default", "allow", "outgoing")
	// Through the firewall service so the result is a fact, not an assumption.
	failed := services.FirewallAllowTcpPorts([]string{"22", "80", "443", "587", "993"})
	serviceInstallerRun(120*time.Second, "ufw", "--force", "enable")
	if len(failed) > 0 {
		slog.Warn("UFW installed but these ports could not be opened: " + strings.Join(failed, " "))
		serviceInstallerOk(w, "UFW installed, but these ports could not be opened: "+strings.Join(failed, ", "))
		return
	}
	slog.Info("UFW installed and enabled with default rules")
	serviceInstallerOk(w, "UFW installed — SSH, HTTP, HTTPS, SMTP, IMAPS ports opened")
}

// serviceInstallerUninstallUfw is allowed on every family: on RHEL it is the
// cleanup for boxes an old setup.sh left with ufw beside firewalld.
func serviceInstallerUninstallUfw(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Removing UFW") {
		return
	}
	slog.Info("Uninstalling UFW...")
	serviceInstallerRun(120*time.Second, "ufw", "disable")
	if err := services.PkgRemove([]string{"ufw"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("UFW uninstall failed: %v", err))
		return
	}
	slog.Info("UFW uninstalled")
	serviceInstallerOk(w, "UFW disabled and removed")
}

// ── Fail2Ban ────────────────────────────────────────────────────────────

const serviceInstallerJailConfig = `[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true

[nginx-limit-req]
enabled = true

[postfix]
enabled = true

[dovecot]
enabled = true
`

func serviceInstallerInstallFail2ban(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Installing Fail2Ban") {
		return
	}
	slog.Info("Installing Fail2Ban...")
	if err := services.PkgInstall([]string{"fail2ban"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Fail2Ban install failed: %v", err))
		return
	}
	_ = os.WriteFile("/etc/fail2ban/jail.local", []byte(serviceInstallerJailConfig), 0o644)
	serviceInstallerSystemctl(120*time.Second, "enable", "fail2ban")
	serviceInstallerSystemctl(120*time.Second, "restart", "fail2ban")
	slog.Info("Fail2Ban installed with default jails")
	serviceInstallerOk(w, "Fail2Ban installed with SSH, Nginx, Postfix, Dovecot jails")
}

func serviceInstallerUninstallFail2ban(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Removing Fail2Ban") {
		return
	}
	slog.Info("Uninstalling Fail2Ban...")
	serviceInstallerSystemctl(120*time.Second, "stop", "fail2ban")
	serviceInstallerSystemctl(120*time.Second, "disable", "fail2ban")
	if err := services.PkgRemove([]string{"fail2ban"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Fail2Ban uninstall failed: %v", err))
		return
	}
	_ = os.Remove("/etc/fail2ban/jail.local")
	slog.Info("Fail2Ban uninstalled")
	serviceInstallerOk(w, "Fail2Ban stopped and purged with jail config removed")
}

// ── PowerDNS ────────────────────────────────────────────────────────────

// serviceInstallerPdnsLocalAddresses returns addresses pdns should bind, or
// "" to leave it on 0.0.0.0. Ubuntu's systemd-resolved stub owns
// 127.0.0.53/54:53, so a wildcard bind crash-loops; then pdns is pinned to the
// real interface addresses. pdns's own sockets (apt's postinst starts it) do
// not count as foreign.
func serviceInstallerPdnsLocalAddresses() string {
	listeners := ""
	if out, ok := serviceInstallerRun(120*time.Second, "ss", "-tulnpH", "sport", "=", ":53"); ok {
		listeners = serviceInstallerLossy(out.Stdout)
	}
	busy := false
	for _, l := range services.LogsLines([]byte(listeners)) {
		if strings.TrimSpace(l) != "" && !strings.Contains(l, "pdns") {
			busy = true
		}
	}
	if !busy {
		return ""
	}
	out, ok := serviceInstallerRun(120*time.Second, "ip", "-o", "addr", "show", "scope", "global")
	if !ok {
		return ""
	}
	var addrs []string
	for _, l := range services.LogsLines(out.Stdout) {
		if f := strings.Fields(l); len(f) > 3 {
			addr, _, _ := strings.Cut(f[3], "/")
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) == 0 {
		return ""
	}
	// Loopback for local tooling; 127.0.0.1 never collides with .53/.54.
	return strings.Join(append(addrs, "127.0.0.1"), ",")
}

// serviceInstallerPasswordFromURL mirrors Rust's split-based parse:
// scheme://user:pw@host → pw (non-empty).
func serviceInstallerPasswordFromURL(url string) (string, bool) {
	parts := strings.Split(url, "://")
	if len(parts) < 2 {
		return "", false
	}
	creds := strings.Split(parts[1], "@")[0]
	f := strings.Split(creds, ":")
	if len(f) < 2 || f[1] == "" {
		return "", false
	}
	return f[1], true
}

// serviceInstallerPanelDbPassword reads the panel's PostgreSQL password:
// env overrides first, then DATABASE_URL in /etc/dockpanel/api.env (written
// by setup.sh, mode 600).
func serviceInstallerPanelDbPassword() (string, bool) {
	if pw := os.Getenv("PANEL_DB_PASSWORD"); pw != "" {
		return pw, true
	}
	if pw, ok := serviceInstallerPasswordFromURL(os.Getenv("DATABASE_URL")); ok {
		return pw, true
	}
	b, err := os.ReadFile("/etc/dockpanel/api.env")
	if err != nil || !utf8.Valid(b) {
		return "", false
	}
	for _, l := range services.LogsLines(b) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "DATABASE_URL="); ok {
			return serviceInstallerPasswordFromURL(strings.Trim(v, `"'`))
		}
	}
	return "", false
}

// serviceInstallerPdnsIsActive polls: a failing pdns is restarted by systemd,
// so one probe can catch it mid-`activating` and read as healthy.
func serviceInstallerPdnsIsActive() bool {
	for range 10 {
		state, _ := serviceInstallerRunNoTimeout("systemctl", "is-active", "pdns")
		if state == "active" {
			return true
		}
		if state == "failed" || state == "inactive" {
			return false
		}
		time.Sleep(time.Second)
	}
	return false
}

func serviceInstallerRunNoTimeout(bin string, args ...string) (string, bool) {
	out, err := safecmd.Exec(context.Background(), bin, args...)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(serviceInstallerLossy(out.Stdout)), true
}

// serviceInstallerPdnsFailureDetail is the most useful journal line for the
// operator-facing error.
func serviceInstallerPdnsFailureDetail() string {
	out, err := safecmd.Exec(context.Background(), "journalctl", "-u", "pdns", "--no-pager", "-n", "40", "-o", "cat")
	if err == nil {
		lines := services.LogsLines(out.Stdout)
		for i := len(lines) - 1; i >= 0; i-- {
			l := lines[i]
			if strings.Contains(l, "Fatal error") || strings.Contains(l, "Unable to bind") || strings.Contains(l, "error") {
				return serviceInstallerTake(strings.TrimSpace(l), 300)
			}
		}
	}
	return "check `journalctl -u pdns` for details"
}

// serviceInstallerWritePdnsConf writes /etc/powerdns/pdns.conf through the
// unsandboxed hatch: `apt-get purge pdns-server` deletes /etc/powerdns, which
// detaches its ReadWritePaths bind mount for the agent's lifetime, so a
// direct write fails EROFS on every reinstall. Staged 0600 under
// /var/lib/dockpanel (it carries the API key / DB password, kept off argv) and
// removed on every exit path.
func serviceInstallerWritePdnsConf(contents string) (int, string) {
	const staged = "/var/lib/dockpanel/pdns.conf.staged"
	status, msg := serviceInstallerStageAndInstallPdnsConf(staged, contents)
	_ = os.Remove(staged)
	return status, msg
}

func serviceInstallerStageAndInstallPdnsConf(staged, contents string) (int, string) {
	f, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return http.StatusInternalServerError, fmt.Sprintf("Failed to stage pdns.conf: %v", err)
	}
	_, err = f.WriteString(contents)
	_ = f.Close()
	if err != nil {
		return http.StatusInternalServerError, fmt.Sprintf("Failed to stage pdns.conf: %v", err)
	}
	out, err := serviceInstallerSh(60*time.Second,
		"mkdir -p /etc/powerdns && install -o root -g pdns -m 640 "+staged+" /etc/powerdns/pdns.conf")
	if err != nil {
		if strings.Contains(err.Error(), "timed out") {
			return http.StatusInternalServerError, "Writing pdns.conf timed out"
		}
		return http.StatusInternalServerError, fmt.Sprintf("Failed to write pdns.conf: %v", err)
	}
	if !out.Success() {
		return http.StatusInternalServerError, "Failed to write pdns.conf: " +
			serviceInstallerTake(strings.TrimSpace(serviceInstallerLossy(out.Stderr)), 300)
	}
	return 0, ""
}

const serviceInstallerSqliteSetup = `set -e; mkdir -p /var/lib/powerdns; ` +
	`if [ ! -s /var/lib/powerdns/pdns.sqlite3 ]; then ` +
	`SCHEMA=''; ` +
	`for c in /usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql ` +
	`/usr/share/doc/pdns/schema.sqlite3.sql ` +
	`/usr/share/pdns-backend-sqlite3/schema.sqlite3.sql ` +
	`/usr/share/doc/pdns-backend-sqlite/schema.sqlite3.sql; do ` +
	`if [ -f "$c" ]; then SCHEMA="$c"; break; fi; ` +
	`if [ -f "$c.gz" ]; then SCHEMA="$c.gz"; break; fi; ` +
	`done; ` +
	`if [ -z "$SCHEMA" ]; then ` +
	`echo 'PowerDNS SQLite schema not found in any known location' >&2; exit 1; ` +
	`fi; ` +
	`case "$SCHEMA" in ` +
	`*.gz) zcat "$SCHEMA" | sqlite3 /var/lib/powerdns/pdns.sqlite3 ;; ` +
	`*)    sqlite3 /var/lib/powerdns/pdns.sqlite3 < "$SCHEMA" ;; ` +
	`esac; ` +
	`if ! sqlite3 /var/lib/powerdns/pdns.sqlite3 ` +
	`'SELECT 1 FROM domains LIMIT 1;' >/dev/null 2>&1; then ` +
	`echo 'PowerDNS SQLite schema loaded but the domains table is missing' >&2; exit 1; ` +
	`fi; ` +
	`fi; ` +
	`chown -R pdns:pdns /var/lib/powerdns`

const serviceInstallerPdnsAPI = `
# HTTP API
api=yes
api-key=%s
webserver=yes
webserver-address=127.0.0.1
webserver-port=8081
webserver-allow-from=127.0.0.1

# SOA defaults
default-soa-content=ns1.@ hostmaster.@ 0 10800 3600 604800 3600
`

func serviceInstallerAlnum(n int) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[k.Int64()]
	}
	return string(b)
}

func serviceInstallerInstallPowerdns(w http.ResponseWriter, r *http.Request) {
	if serviceInstallerRefuse(w, "Installing PowerDNS") {
		return
	}
	// Optional {"backend": "sqlite"|"pgsql"}; absent/empty/invalid → pgsql
	// (older panels POST no body). SQLite drops the dependency on the panel's
	// containerized PostgreSQL that broke installs in issue #63.
	body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	var parsed struct {
		Backend any `json:"backend"`
	}
	useSqlite := json.Unmarshal(body, &parsed) == nil && parsed.Backend == "sqlite"
	backend := "pgsql"
	if useSqlite {
		backend = "sqlite"
	}
	slog.Info(fmt.Sprintf("Installing PowerDNS (backend=%s)...", backend))

	// Backend package names differ by family; PkgInstall translates them.
	pkgs := []string{"pdns-server", "pdns-backend-pgsql"}
	if useSqlite {
		pkgs = []string{"pdns-server", "pdns-backend-sqlite3", "sqlite3"}
	}
	if err := services.PkgInstall(pkgs); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("PowerDNS install failed: %v", err))
		return
	}
	apiKey := serviceInstallerAlnum(32)

	var conf string
	if useSqlite {
		// /var/lib/powerdns is not in ReadWritePaths → unsandboxed. The schema
		// path is distro-specific; a miss must FAIL, not skip — a skip left an
		// empty DB and a DNS server that answers nothing under a green install.
		out, err := serviceInstallerSh(120*time.Second, serviceInstallerSqliteSetup)
		if err != nil {
			if strings.Contains(err.Error(), "timed out") {
				writeErr(w, http.StatusInternalServerError, "PowerDNS SQLite schema load timed out")
			} else {
				writeErr(w, http.StatusInternalServerError, fmt.Sprintf("SQLite setup failed: %v", err))
			}
			return
		}
		if !out.Success() {
			writeErr(w, http.StatusInternalServerError, "PowerDNS SQLite setup failed: "+serviceInstallerTake(serviceInstallerLossy(out.Stderr), 300))
			return
		}
		conf = "# DockPanel PowerDNS configuration (SQLite backend)\nlaunch=gsqlite3\ngsqlite3-database=/var/lib/powerdns/pdns.sqlite3\n" +
			fmt.Sprintf(serviceInstallerPdnsAPI, apiKey)
	} else {
		// Create the pdns database in the panel's PostgreSQL container.
		out, ok := serviceInstallerRun(120*time.Second, "docker", "exec", "dockpanel-postgres", "psql", "-U", "dockpanel", "-lqt")
		if !ok || !strings.Contains(serviceInstallerLossy(out.Stdout), "pdns") {
			serviceInstallerRun(120*time.Second, "docker", "exec", "dockpanel-postgres", "psql", "-U", "dockpanel", "-c", "CREATE DATABASE pdns;")
			const schema = "/usr/share/doc/pdns-backend-pgsql/schema.pgsql.sql"
			if _, err := os.Stat(schema); err == nil {
				_, _ = serviceInstallerSh(120*time.Second, "cat "+schema+" | docker exec -i dockpanel-postgres psql -U dockpanel -d pdns")
			}
		}
		// The agent unit has no EnvironmentFile, so env lookups always fell
		// through to a random password matching no role; read the real one.
		pw, ok := serviceInstallerPanelDbPassword()
		if !ok {
			writeErr(w, http.StatusInternalServerError, "Could not read the panel database password from /etc/dockpanel/api.env — "+
				"install PowerDNS with the SQLite backend instead, or repair DATABASE_URL")
			return
		}
		conf = "# DockPanel PowerDNS configuration\nlaunch=gpgsql\ngpgsql-host=127.0.0.1\ngpgsql-port=5450\ngpgsql-dbname=pdns\ngpgsql-user=dockpanel\ngpgsql-password=" +
			pw + "\n" + fmt.Sprintf(serviceInstallerPdnsAPI, apiKey)
	}

	if addrs := serviceInstallerPdnsLocalAddresses(); addrs != "" {
		slog.Info("Port 53 already in use — binding PowerDNS to " + addrs)
		conf += "\n# Port 53 was already claimed at install time (systemd-resolved stub\n" +
			"# listener on 127.0.0.53/127.0.0.54 on Ubuntu), so bind explicitly.\n" +
			"local-address=" + addrs + "\n"
	}
	if status, msg := serviceInstallerWritePdnsConf(conf); status != 0 {
		writeErr(w, status, msg)
		return
	}

	// A pdns that never comes up must not be reported as installed.
	serviceInstallerSystemctl(120*time.Second, "reset-failed", "pdns")
	serviceInstallerSystemctl(120*time.Second, "enable", "pdns")
	serviceInstallerSystemctl(120*time.Second, "restart", "pdns")
	if !serviceInstallerPdnsIsActive() {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf(
			"PowerDNS was installed and configured (%s backend) but the service failed to start: %s", backend, serviceInstallerPdnsFailureDetail()))
		return
	}
	slog.Info(fmt.Sprintf("PowerDNS installed with API key (backend=%s)", backend))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": fmt.Sprintf("PowerDNS installed and configured (%s backend)", backend),
		"api_url": "http://127.0.0.1:8081",
		"api_key": apiKey,
		"backend": backend,
	})
}

func serviceInstallerUninstallPowerdns(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Removing PowerDNS") {
		return
	}
	slog.Info("Uninstalling PowerDNS...")
	// The unit is literally `pdns` on BOTH families (Debian's PACKAGE is
	// pdns-server), so deliberately NOT through PkgServiceName.
	serviceInstallerSystemctl(120*time.Second, "stop", "pdns")
	serviceInstallerSystemctl(120*time.Second, "disable", "pdns")
	if err := services.PkgRemove([]string{"pdns-server", "pdns-backend-pgsql", "pdns-backend-sqlite3"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("PowerDNS uninstall failed: %v", err))
		return
	}
	// Keep the database — the user may want their DNS records.
	_ = os.Remove("/etc/powerdns/pdns.conf")
	slog.Info("PowerDNS uninstalled (database preserved)")
	serviceInstallerOk(w, "PowerDNS purged and config removed (database preserved)")
}

// ── Redis / Node.js / Composer / sshpass ────────────────────────────────

func serviceInstallerInstallRedis(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Installing Redis") {
		return
	}
	slog.Info("Installing Redis...")
	services.PkgRefreshIndex()
	if err := services.PkgInstall([]string{"redis-server"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Redis install failed: %v", err))
		return
	}
	// Package and unit are both `redis` on RHEL; separate maps translate them.
	unit := services.PkgServiceName("redis-server")
	serviceInstallerSystemctl(120*time.Second, "enable", unit)
	serviceInstallerSystemctl(120*time.Second, "start", unit)
	verified := strings.ToUpper(serviceInstallerStdout(10*time.Second, "redis-cli", "ping")) == "PONG"
	slog.Info(fmt.Sprintf("Redis installed, ping verified: %v", verified))
	serviceInstallerOk(w, "Redis installed and started")
}

func serviceInstallerUninstallRedis(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Removing Redis") {
		return
	}
	slog.Info("Uninstalling Redis...")
	unit := services.PkgServiceName("redis-server")
	serviceInstallerSystemctl(120*time.Second, "stop", unit)
	serviceInstallerSystemctl(120*time.Second, "disable", unit)
	if err := services.PkgRemove([]string{"redis-server"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Redis uninstall failed: %v", err))
		return
	}
	slog.Info("Redis uninstalled")
	serviceInstallerOk(w, "Redis stopped and purged")
}

func serviceInstallerInstallNodejs(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Installing Node.js") {
		return
	}
	slog.Info("Installing Node.js...")
	// NodeSource publishes a per-family setup script; PkgAddRepo picks it.
	if err := services.PkgAddRepo(services.PkgRepoNodeSource); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("NodeSource repository setup failed: %v", err))
		return
	}
	if err := services.PkgInstall([]string{"nodejs"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Node.js install failed: %v", err))
		return
	}
	ver := serviceInstallerStdout(10*time.Second, "node", "--version")
	slog.Info(fmt.Sprintf("Node.js %s installed", ver))
	serviceInstallerOk(w, fmt.Sprintf("Node.js %s with npm installed", ver))
}

func serviceInstallerUninstallNodejs(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Removing Node.js") {
		return
	}
	slog.Info("Uninstalling Node.js...")
	if err := services.PkgRemove([]string{"nodejs"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Node.js uninstall failed: %v", err))
		return
	}
	// On whichever family added it (this once removed only the apt file).
	services.PkgRemoveRepo(services.PkgRepoNodeSource)
	slog.Info("Node.js uninstalled")
	serviceInstallerOk(w, "Node.js purged and nodesource repo removed")
}

func serviceInstallerInstallComposer(w http.ResponseWriter, _ *http.Request) {
	slog.Info("Installing Composer...")
	out, err := serviceInstallerSh(300*time.Second, "curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer")
	if err != nil {
		if strings.Contains(err.Error(), "timed out") {
			writeErr(w, http.StatusInternalServerError, "Composer install timed out after 300s")
		} else {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Composer install failed: %v", err))
		}
		return
	}
	if !out.Success() {
		writeErr(w, http.StatusInternalServerError, "Composer install failed: "+serviceInstallerTake(serviceInstallerLossy(out.Stderr), 300))
		return
	}
	slog.Info("Composer installed: " + serviceInstallerStdout(10*time.Second, "composer", "--version"))
	serviceInstallerOk(w, "Composer installed globally at /usr/local/bin/composer")
}

// serviceInstallerUninstallComposer removes the binary unsandboxed:
// /usr/local/bin is read-only under ProtectSystem=strict.
func serviceInstallerUninstallComposer(w http.ResponseWriter, _ *http.Request) {
	slog.Info("Uninstalling Composer...")
	out, err := safecmd.NewUnsandboxed("rm").Arg("-f", "/usr/local/bin/composer").OutputWithTimeout(120 * time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "timed out") {
			writeErr(w, http.StatusInternalServerError, "Composer uninstall timed out")
		} else {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Composer uninstall failed: %v", err))
		}
		return
	}
	if !out.Success() {
		writeErr(w, http.StatusInternalServerError, "Composer uninstall failed: "+serviceInstallerTake(serviceInstallerLossy(out.Stderr), 300))
		return
	}
	slog.Info("Composer uninstalled")
	serviceInstallerOk(w, "Composer binary removed from /usr/local/bin")
}

// serviceInstallerInstallSshpass installs sshpass for password-authenticated
// SFTP backup destinations (boxes predating install-agent.sh's install of it;
// update.sh never installs packages — issue #93).
func serviceInstallerInstallSshpass(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Installing sshpass") {
		return
	}
	slog.Info("Installing sshpass...")
	// The population this route exists for has a months-stale index.
	services.PkgRefreshIndex()
	if err := services.PkgInstall([]string{"sshpass"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("sshpass install failed: %v", err))
		return
	}
	// Report what the backup path depends on: the binary on PATH.
	if !serviceInstallerWhich("sshpass") {
		writeErr(w, http.StatusInternalServerError, "The sshpass package reported a successful install but no sshpass binary is on "+
			"PATH. Password-authenticated SFTP destinations will still fail from this server.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "sshpass installed. Password-authenticated SFTP backup destinations can " +
			"now run from this server.",
	})
}

// ── WAF (ModSecurity3 + OWASP CRS) ──────────────────────────────────────

const serviceInstallerModsecConf = `# ModSecurity base config (managed by DockPanel)
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecResponseBodyAccess Off
SecTmpDir /tmp/
SecDataDir /tmp/
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/modsecurity/modsec_audit.log
SecArgumentSeparator &
SecCookieFormat 0
SecUnicodeMapFile unicode.mapping 20127
SecStatusEngine Off
`

func serviceInstallerBigFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Size() > 1024
}

func serviceInstallerInstallWaf(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Installing the WAF") {
		return
	}
	slog.Info("Installing WAF (ModSecurity3 + OWASP CRS)...")

	// Debian needs both names; RHEL's single nginx-mod-modsecurity covers both.
	services.PkgRefreshIndex()
	if err := services.PkgInstall([]string{"libmodsecurity3", "libnginx-mod-http-modsecurity"}); err != nil {
		writeErr(w, http.StatusInternalServerError,
			fmt.Sprintf("WAF install failed (libmodsecurity3 or the nginx module is not available): %v", err))
		return
	}
	for _, d := range []string{"/etc/modsecurity", "/etc/modsecurity/sites", "/var/log/modsecurity"} {
		_ = os.MkdirAll(d, 0o755)
	}

	const crsDir = "/etc/modsecurity/crs"
	if _, err := os.Stat(crsDir + "/crs-setup.conf"); err != nil {
		out, err := serviceInstallerSh(120*time.Second, fmt.Sprintf("cd /tmp && "+
			"curl -sL https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.25.0.tar.gz -o crs.tar.gz && "+
			"tar xzf crs.tar.gz && "+
			"rm -rf %[1]s && "+
			"mv coreruleset-4.25.0 %[1]s && "+
			"cp %[1]s/crs-setup.conf.example %[1]s/crs-setup.conf && "+
			"rm -f crs.tar.gz", crsDir))
		if err == nil && out.Success() {
			slog.Info("OWASP CRS v4.25.0 downloaded")
		} else {
			slog.Warn("OWASP CRS download failed — WAF will work without rules")
		}
	}

	if err := os.WriteFile("/etc/modsecurity/modsecurity.conf", []byte(serviceInstallerModsecConf), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Write modsec config: %v", err))
		return
	}

	// Prefer a REAL system copy (>1 KiB — an empty file looks installed and
	// is worse than none), else the embedded one.
	if !serviceInstallerBigFile(serviceInstallerMappingPath) {
		contents := serviceInstallerUnicodeMapping
		for _, p := range []string{"/usr/share/modsecurity/unicode.mapping", "/usr/share/modsecurity-crs/unicode.mapping", "/etc/nginx/modsecurity/unicode.mapping"} {
			if serviceInstallerBigFile(p) {
				if b, err := os.ReadFile(p); err == nil && utf8.Valid(b) {
					contents = string(b)
				}
				break
			}
		}
		if err := os.WriteFile(serviceInstallerMappingPath, []byte(contents), 0o644); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Write unicode.mapping: %v", err))
			return
		}
	}
	// Assert what the later nginx reload depends on instead of assuming (#45).
	b, err := os.ReadFile(serviceInstallerMappingPath)
	if err == nil && !utf8.Valid(b) {
		err = fmt.Errorf("stream did not contain valid UTF-8")
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("unicode.mapping unreadable after install: %v", err))
		return
	}
	if !strings.Contains(string(b), "20127") {
		writeErr(w, http.StatusInternalServerError, "unicode.mapping is present but does not define code page 20127, "+
			"which modsecurity.conf requires — the WAF would fail nginx -t "+
			"the first time a site enabled it")
		return
	}

	if out, ok := serviceInstallerRun(10*time.Second, "nginx", "-t"); !ok || !out.Success() {
		slog.Warn("nginx -t failed after WAF install — module may need manual load_module directive")
	}
	slog.Info("WAF installed (ModSecurity3 + OWASP CRS)")
	serviceInstallerOk(w, "WAF installed: ModSecurity3 with OWASP Core Rule Set v4.25.0")
}

func serviceInstallerUninstallWaf(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Removing the WAF") {
		return
	}
	slog.Info("Uninstalling WAF...")
	dir := services.NginxSitesDir()
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			p := dir + "/" + e.Name()
			b, err := os.ReadFile(p)
			if err != nil || !utf8.Valid(b) || !strings.Contains(string(b), "modsecurity") {
				continue
			}
			var kept []string
			for _, l := range services.LogsLines(b) {
				if !strings.Contains(l, "modsecurity") {
					kept = append(kept, l)
				}
			}
			_ = os.WriteFile(p, []byte(strings.Join(kept, "\n")), 0o644)
		}
	}
	serviceInstallerRun(10*time.Second, "nginx", "-s", "reload")
	// All three Debian spellings collapse onto the single RHEL package.
	if err := services.PkgRemove([]string{"libnginx-mod-http-modsecurity", "libmodsecurity3", "libmodsecurity3t64"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("WAF uninstall failed: %v", err))
		return
	}
	// Config goes, logs stay.
	_ = os.RemoveAll("/etc/modsecurity")
	slog.Info("WAF uninstalled")
	serviceInstallerOk(w, "WAF (ModSecurity3) uninstalled")
}

// ── Cloudflare Tunnel ───────────────────────────────────────────────────

func serviceInstallerInstallCloudflared(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Installing Cloudflare Tunnel") {
		return
	}
	slog.Info("Installing cloudflared...")
	// The codename lookup lives in PkgAddRepo's apt branch only (no RHEL
	// release has VERSION_CODENAME); it also removes a half-written repo file.
	if err := services.PkgAddRepo(services.PkgRepoCloudflared); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("cloudflared repository setup failed: %v", err))
		return
	}
	if err := services.PkgInstall([]string{"cloudflared"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("cloudflared install failed: %v", err))
		return
	}
	_ = os.MkdirAll("/etc/cloudflared", 0o755)
	version := serviceInstallerStdout(5*time.Second, "cloudflared", "version")
	slog.Info("cloudflared installed: " + version)
	serviceInstallerOk(w, "cloudflared installed: "+version)
}

func serviceInstallerUninstallCloudflared(w http.ResponseWriter, _ *http.Request) {
	if serviceInstallerRefuse(w, "Removing Cloudflare Tunnel") {
		return
	}
	slog.Info("Uninstalling cloudflared...")
	serviceInstallerSystemctl(30*time.Second, "stop", "cloudflared")
	serviceInstallerSystemctl(30*time.Second, "disable", "cloudflared")
	if err := services.PkgRemove([]string{"cloudflared"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("cloudflared uninstall failed: %v", err))
		return
	}
	services.PkgRemoveRepo(services.PkgRepoCloudflared)
	_ = os.RemoveAll("/etc/cloudflared")
	slog.Info("cloudflared uninstalled")
	serviceInstallerOk(w, "cloudflared uninstalled")
}

// serviceInstallerValidToken: base64-like only — no newlines, format
// specifiers or shell metacharacters.
func serviceInstallerValidToken(t string) bool {
	if len(t) < 50 || len(t) > 4096 {
		return false
	}
	for _, c := range t {
		if !isASCIIAlnum(c) && !strings.ContainsRune("-_.=", c) {
			return false
		}
	}
	return true
}

// serviceInstallerConfigureCloudflared: POST /services/cloudflared/configure.
func serviceInstallerConfigureCloudflared(w http.ResponseWriter, r *http.Request) {
	var body any
	if !decodeJSON(w, r, &body) {
		return
	}
	token := ""
	if obj, ok := body.(map[string]any); ok {
		token, _ = obj["token"].(string)
	}
	if token == "" {
		writeErr(w, http.StatusBadRequest, "Missing tunnel token")
		return
	}
	if !serviceInstallerValidToken(token) {
		writeErr(w, http.StatusBadRequest, "Invalid tunnel token format")
		return
	}
	_ = os.MkdirAll("/etc/cloudflared", 0o755)

	// Token in a root-only 0600 EnvironmentFile: not world-readable in the
	// unit, not on the process command line (cloudflared reads TUNNEL_TOKEN).
	const tokenEnv = "/etc/cloudflared/token.env"
	f, err := os.OpenFile(tokenEnv, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err == nil {
		_, err = f.WriteString("TUNNEL_TOKEN=" + token + "\n")
		_ = f.Close()
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Write token file: %v", err))
		return
	}
	// Harden even if the file already existed with a looser mode.
	_ = os.Chmod(tokenEnv, 0o600)

	unit := "[Unit]\nDescription=Cloudflare Tunnel\nAfter=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\nType=simple\nEnvironmentFile=" + tokenEnv + "\nExecStart=/usr/bin/cloudflared tunnel run\n" +
		"Restart=on-failure\nRestartSec=5\nLimitNOFILE=65536\n\n[Install]\nWantedBy=multi-user.target\n"
	if err := os.WriteFile("/etc/systemd/system/cloudflared.service", []byte(unit), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Write service: %v", err))
		return
	}
	serviceInstallerSystemctl(10*time.Second, "daemon-reload")
	serviceInstallerSystemctl(10*time.Second, "enable", "cloudflared")
	serviceInstallerSystemctl(15*time.Second, "restart", "cloudflared")
	time.Sleep(2 * time.Second)
	running := serviceInstallerIsActive("cloudflared")
	slog.Info(fmt.Sprintf("Cloudflare Tunnel configured, running: %v", running))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "running": running})
}

// serviceInstallerCloudflaredStatus: GET /services/cloudflared/status.
func serviceInstallerCloudflaredStatus(w http.ResponseWriter, _ *http.Request) {
	installed := serviceInstallerWhich("cloudflared")
	running := serviceInstallerIsActive("cloudflared")
	var version any
	if installed {
		if out, ok := serviceInstallerRun(5*time.Second, "cloudflared", "version"); ok {
			version = strings.TrimSpace(serviceInstallerLossy(out.Stdout))
		}
	}
	_, err := os.Stat("/etc/systemd/system/cloudflared.service")
	writeJSON(w, http.StatusOK, map[string]any{
		"installed": installed, "running": running, "version": version, "configured": err == nil,
	})
}
