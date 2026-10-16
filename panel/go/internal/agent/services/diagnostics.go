// Server diagnostics: nginx, resources, services, SSL expiry, log patterns and
// security checks, plus the one-click fixes the panel offers for them.

package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// DiagnosticsFinding is one diagnostic result.
type DiagnosticsFinding struct {
	ID           string  `json:"id"`
	Category     string  `json:"category"`
	Severity     string  `json:"severity"` // critical, warning, info
	Title        string  `json:"title"`
	Description  string  `json:"description"`
	FixAvailable bool    `json:"fix_available"`
	FixID        *string `json:"fix_id"`
}

// DiagnosticsReport is the consolidated report.
type DiagnosticsReport struct {
	Findings []DiagnosticsFinding `json:"findings"`
	Summary  DiagnosticsSummary   `json:"summary"`
}

// DiagnosticsSummary counts findings by severity.
type DiagnosticsSummary struct {
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

func diagnosticsFix(s string) *string { return &s }

// diagnosticsLossy mirrors String::from_utf8_lossy.
func diagnosticsLossy(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

// diagnosticsLines mirrors Rust str::lines: split on \n, strip a trailing \r,
// no trailing empty line.
func diagnosticsLines(s string) []string {
	if s == "" {
		return nil
	}
	ls := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i, l := range ls {
		ls[i] = strings.TrimSuffix(l, "\r")
	}
	return ls
}

// diagnosticsTrimEndMatches mirrors Rust trim_end_matches(&str): strips the
// suffix repeatedly.
func diagnosticsTrimEndMatches(s, suffix string) string {
	for strings.HasSuffix(s, suffix) {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
}

// diagnosticsExec runs bin with a timeout. err is non-nil when it could not
// run or timed out (the Rust `Ok(Ok(o))` arm is err == nil).
func diagnosticsExec(timeout time.Duration, bin string, args ...string) (safecmd.Output, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return safecmd.Exec(ctx, bin, args...)
}

// DiagnosticsRun runs all diagnostic checks concurrently and returns a
// consolidated report.
func DiagnosticsRun() DiagnosticsReport {
	checks := []func() []DiagnosticsFinding{
		diagnosticsCheckNginx,
		diagnosticsCheckResources,
		diagnosticsCheckServices,
		diagnosticsCheckSslExpiry,
		diagnosticsCheckLogPatterns,
		diagnosticsCheckSecurity,
	}
	results := make([][]DiagnosticsFinding, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func() { defer wg.Done(); results[i] = c() }()
	}
	wg.Wait()

	findings := []DiagnosticsFinding{}
	for _, r := range results {
		findings = append(findings, r...)
	}
	var s DiagnosticsSummary
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			s.Critical++
		case "warning":
			s.Warning++
		case "info":
			s.Info++
		}
	}
	s.Total = len(findings)
	return DiagnosticsReport{Findings: findings, Summary: s}
}

// ── Nginx Checks ─────────────────────────────────────────────────────────

func diagnosticsCheckNginx() []DiagnosticsFinding {
	var findings []DiagnosticsFinding

	// 1. nginx -t  (config validation)
	out, err := diagnosticsExec(10*time.Second, "nginx", "-t")
	if err != nil {
		findings = append(findings, DiagnosticsFinding{
			ID: "nginx-not-found", Category: "nginx", Severity: "critical",
			Title:       "Nginx not installed or unreachable",
			Description: "Could not run nginx -t to validate configuration.",
		})
	} else {
		stderr := diagnosticsLossy(out.Stderr)
		lines := diagnosticsLines(stderr)
		hasFatal := strings.Contains(stderr, "[emerg]") || strings.Contains(stderr, "[error]") ||
			strings.Contains(stderr, "[crit]") || strings.Contains(stderr, "[alert]")
		var warnLines []string
		for _, l := range lines {
			if strings.Contains(l, "[warn]") {
				warnLines = append(warnLines, l)
			}
		}

		switch {
		case hasFatal:
			// Real failure — nginx config is broken
			var errLines []string
			for _, l := range lines {
				if strings.Contains(l, "[emerg]") || strings.Contains(l, "[error]") || strings.Contains(l, "[crit]") {
					errLines = append(errLines, l)
				}
			}
			findings = append(findings, DiagnosticsFinding{
				ID: "nginx-config-invalid", Category: "nginx", Severity: "critical",
				Title:       "Nginx configuration is invalid",
				Description: "nginx -t: " + strings.Join(errLines[:min(3, len(errLines))], " "),
			})
		case len(warnLines) > 0:
			// Warnings only — nginx works fine, cosmetic issues
			plural := "s"
			if len(warnLines) == 1 {
				plural = ""
			}
			var descs []string
			for _, w := range warnLines[:min(3, len(warnLines))] {
				parts := strings.Split(w, "[warn]")
				descs = append(descs, strings.TrimSpace(parts[len(parts)-1]))
			}
			findings = append(findings, DiagnosticsFinding{
				ID: "nginx-config-warnings", Category: "nginx", Severity: "info",
				Title:       fmt.Sprintf("Nginx has %d configuration warning%s", len(warnLines), plural),
				Description: strings.Join(descs, "; "),
			})
		case !out.Success():
			// Unknown failure
			findings = append(findings, DiagnosticsFinding{
				ID: "nginx-config-invalid", Category: "nginx", Severity: "critical",
				Title: "Nginx configuration is invalid",
				Description: fmt.Sprintf("nginx -t exited with code %d: %s", out.ExitCode,
					strings.Join(lines[:min(3, len(lines))], " ")),
			})
		}
	}

	// 2. Check for site configs without matching root directory
	dir := NginxSitesDir()
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			filename := e.Name()
			if filename == "default" || filename == "dockpanel-panel.conf" || filename == "dockpanel.dev.conf" {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, filename))
			if err != nil || !utf8.Valid(raw) {
				continue
			}
			content := string(raw)

			// Extract root directive
			for _, line := range diagnosticsLines(content) {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "root ") && !strings.HasPrefix(trimmed, "root /var/www/html") {
					rootPath := strings.TrimSpace(strings.TrimRight(strings.TrimPrefix(trimmed, "root "), ";"))
					if rootPath != "" {
						if _, err := os.Stat(rootPath); err != nil {
							domain := diagnosticsTrimEndMatches(filename, ".conf")
							findings = append(findings, DiagnosticsFinding{
								ID: "nginx-missing-root-" + domain, Category: "nginx", Severity: "warning",
								Title:        "Missing document root for " + domain,
								Description:  fmt.Sprintf("Root directory %s does not exist", rootPath),
								FixAvailable: true,
								FixID:        diagnosticsFix("create-root:" + rootPath),
							})
						}
					}
					break
				}
			}

			// Check for duplicate server_name across configs
			// (lightweight: just flag if server_name is "_")
			for _, l := range diagnosticsLines(content) {
				t := strings.TrimSpace(l)
				if strings.HasPrefix(t, "server_name") && strings.Contains(t, " _ ") {
					findings = append(findings, DiagnosticsFinding{
						ID: "nginx-default-server-" + filename, Category: "nginx", Severity: "info",
						Title:       "Default server block in " + filename,
						Description: "Config uses catch-all server_name _",
					})
					break
				}
			}
		}
	}

	return findings
}

// ── Resource Checks ──────────────────────────────────────────────────────

func diagnosticsCheckResources() []DiagnosticsFinding {
	var findings []DiagnosticsFinding

	// Disk usage
	if out, err := diagnosticsExec(5*time.Second, "df", "--output=pcent", "/"); err == nil {
		if ls := diagnosticsLines(diagnosticsLossy(out.Stdout)); len(ls) > 1 {
			if pct, err := strconv.ParseUint(strings.TrimRight(strings.TrimSpace(ls[1]), "%"), 10, 32); err == nil {
				if pct >= 95 {
					findings = append(findings, DiagnosticsFinding{
						ID: "disk-critical", Category: "resources", Severity: "critical",
						Title:        fmt.Sprintf("Disk usage critical: %d%%", pct),
						Description:  "Root filesystem is almost full. Services may fail.",
						FixAvailable: true, FixID: diagnosticsFix("clean-logs"),
					})
				} else if pct >= 85 {
					findings = append(findings, DiagnosticsFinding{
						ID: "disk-warning", Category: "resources", Severity: "warning",
						Title:        fmt.Sprintf("Disk usage high: %d%%", pct),
						Description:  "Root filesystem is getting full. Consider cleanup.",
						FixAvailable: true, FixID: diagnosticsFix("clean-logs"),
					})
				}
			}
		}
	}

	// Memory and swap usage (Rust ran `free -m` twice; one run answers both).
	if out, err := diagnosticsExec(5*time.Second, "free", "-m"); err == nil {
		lines := diagnosticsLines(diagnosticsLossy(out.Stdout))
		for _, l := range lines {
			if !strings.HasPrefix(l, "Mem:") {
				continue
			}
			if parts := strings.Fields(l); len(parts) >= 3 {
				total, err := strconv.ParseFloat(parts[1], 64)
				if err != nil {
					total = 1
				}
				used, err := strconv.ParseFloat(parts[2], 64)
				if err != nil {
					used = 0
				}
				pct := diagnosticsSatU32(used / total * 100)
				if pct >= 95 {
					findings = append(findings, DiagnosticsFinding{
						ID: "memory-critical", Category: "resources", Severity: "critical",
						Title:       fmt.Sprintf("Memory usage critical: %d%%", pct),
						Description: fmt.Sprintf("%.0f MB used of %.0f MB. OOM killer may activate.", used, total),
					})
				} else if pct >= 85 {
					findings = append(findings, DiagnosticsFinding{
						ID: "memory-warning", Category: "resources", Severity: "warning",
						Title:       fmt.Sprintf("Memory usage high: %d%%", pct),
						Description: fmt.Sprintf("%.0f MB used of %.0f MB", used, total),
					})
				}
			}
			break
		}
		for _, l := range lines {
			if !strings.HasPrefix(l, "Swap:") {
				continue
			}
			if parts := strings.Fields(l); len(parts) >= 2 {
				total, err := strconv.ParseFloat(parts[1], 64)
				if err != nil {
					total = 0
				}
				if total == 0 {
					findings = append(findings, DiagnosticsFinding{
						ID: "no-swap", Category: "resources", Severity: "info",
						Title:       "No swap configured",
						Description: "System has no swap space. Low-memory situations may cause OOM kills.",
					})
				}
			}
			break
		}
	}

	// Load average vs CPU count
	if loadavg, err := os.ReadFile("/proc/loadavg"); err == nil {
		parts := strings.Fields(string(loadavg))
		if cpus, err := diagnosticsNumCpus(); len(parts) > 0 && err == nil {
			if load, err := strconv.ParseFloat(parts[0], 64); err == nil {
				if load > float64(cpus)*2 {
					findings = append(findings, DiagnosticsFinding{
						ID: "load-critical", Category: "resources", Severity: "critical",
						Title:       fmt.Sprintf("System load very high: %.1f (on %d CPUs)", load, cpus),
						Description: "Load average is more than 2x the CPU count.",
					})
				} else if load > float64(cpus) {
					findings = append(findings, DiagnosticsFinding{
						ID: "load-warning", Category: "resources", Severity: "warning",
						Title:       fmt.Sprintf("System load elevated: %.1f (on %d CPUs)", load, cpus),
						Description: "Load average exceeds CPU count.",
					})
				}
			}
		}
	}

	return findings
}

// diagnosticsSatU32 mirrors Rust's saturating `f64 as u32` (NaN → 0).
func diagnosticsSatU32(f float64) uint32 {
	switch {
	case f != f || f <= 0:
		return 0
	case f >= 4294967295:
		return 4294967295
	}
	return uint32(f)
}

func diagnosticsNumCpus() (int, error) {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0, err
	}
	return max(strings.Count(string(b), "processor\t:"), 1), nil
}

// ── Service Health Checks ────────────────────────────────────────────────

func diagnosticsServiceActive(service string) bool {
	out, err := diagnosticsExec(5*time.Second, "systemctl", "is-active", "--quiet", service)
	return err == nil && out.Success()
}

func diagnosticsCheckServices() []DiagnosticsFinding {
	var findings []DiagnosticsFinding

	for _, s := range [][2]string{{"nginx", "Web server"}, {"docker", "Docker engine"}} {
		service, label := s[0], s[1]
		if !diagnosticsServiceActive(service) {
			findings = append(findings, DiagnosticsFinding{
				ID: "service-down-" + service, Category: "services", Severity: "critical",
				Title:        label + " is not running",
				Description:  fmt.Sprintf("systemctl reports %s is not active", service),
				FixAvailable: true, FixID: diagnosticsFix("restart-service:" + service),
			})
		}
	}

	// Check optional services
	for _, s := range [][2]string{{"fail2ban", "Intrusion prevention"}, {"ufw", "Firewall"}} {
		service, label := s[0], s[1]
		if !diagnosticsServiceActive(service) {
			findings = append(findings, DiagnosticsFinding{
				ID: "service-inactive-" + service, Category: "services", Severity: "info",
				Title:        fmt.Sprintf("%s (%s) is not active", label, service),
				Description:  fmt.Sprintf("%s is not running — recommended for security", service),
				FixAvailable: true, FixID: diagnosticsFix("restart-service:" + service),
			})
		}
	}

	return findings
}

// ── SSL Expiry Checks ────────────────────────────────────────────────────

func diagnosticsCheckSslExpiry() []DiagnosticsFinding {
	var findings []DiagnosticsFinding
	const sslDir = "/etc/dockpanel/ssl"

	entries, err := os.ReadDir(sslDir)
	if err != nil {
		return findings
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		domain := e.Name()
		certPath := sslDir + "/" + domain + "/fullchain.pem"

		// Check if cert expires within 7 days
		check7d, err := diagnosticsExec(5*time.Second, "openssl", "x509", "-checkend", "604800", "-noout", "-in", certPath)
		if err != nil {
			continue
		}
		if !check7d.Success() {
			// Get expiry date for the message
			expiry := "within 7 days"
			if exp, ok := diagnosticsCertExpiry(certPath); ok {
				expiry = exp
			}
			findings = append(findings, DiagnosticsFinding{
				ID: "ssl-expiring-" + domain, Category: "ssl", Severity: "critical",
				Title:        "SSL certificate expiring soon: " + domain,
				Description:  "Certificate expires " + expiry,
				FixAvailable: true, FixID: diagnosticsFix("renew-ssl:" + domain),
			})
			continue
		}

		// Check if cert expires within 30 days
		check30d, err := diagnosticsExec(5*time.Second, "openssl", "x509", "-checkend", "2592000", "-noout", "-in", certPath)
		if err != nil {
			continue
		}
		if !check30d.Success() {
			expiry := "within 30 days"
			if exp, ok := diagnosticsCertExpiry(certPath); ok {
				expiry = exp
			}
			findings = append(findings, DiagnosticsFinding{
				ID: "ssl-expiring-" + domain, Category: "ssl", Severity: "warning",
				Title:        "SSL certificate expiring: " + domain,
				Description:  "Certificate expires " + expiry,
				FixAvailable: true, FixID: diagnosticsFix("renew-ssl:" + domain),
			})
		}
	}

	return findings
}

func diagnosticsCertExpiry(certPath string) (string, bool) {
	out, err := diagnosticsExec(5*time.Second, "openssl", "x509", "-enddate", "-noout", "-in", certPath)
	if err != nil {
		return "", false
	}
	return strings.CutPrefix(strings.TrimSpace(diagnosticsLossy(out.Stdout)), "notAfter=")
}

// ── Log Pattern Analysis ─────────────────────────────────────────────────

func diagnosticsCount(lines []string, subs ...string) int {
	n := 0
	for _, l := range lines {
		for _, s := range subs {
			if strings.Contains(l, s) {
				n++
				break
			}
		}
	}
	return n
}

func diagnosticsCheckLogPatterns() []DiagnosticsFinding {
	var findings []DiagnosticsFinding

	// Check nginx error log for repeated errors (last 200 lines)
	if out, err := diagnosticsExec(10*time.Second, "tail", "-n", "200", "/var/log/nginx/error.log"); err == nil {
		lines := diagnosticsLines(diagnosticsLossy(out.Stdout))

		// Count 502 Bad Gateway errors
		if n := diagnosticsCount(lines, "connect() failed", "upstream prematurely closed"); n >= 5 {
			findings = append(findings, DiagnosticsFinding{
				ID: "log-502-errors", Category: "logs", Severity: "warning",
				Title:       fmt.Sprintf("%d upstream connection failures in recent logs", n),
				Description: "Nginx is having trouble connecting to upstream services (PHP-FPM, proxy targets).",
			})
		}

		// Count permission denied errors
		if n := diagnosticsCount(lines, "Permission denied", "forbidden"); n >= 3 {
			findings = append(findings, DiagnosticsFinding{
				ID: "log-permission-errors", Category: "logs", Severity: "warning",
				Title:       fmt.Sprintf("%d permission errors in nginx logs", n),
				Description: "Check file permissions on site document roots.",
			})
		}
	}

	// Check the auth log for brute force patterns (last 500 lines). The RHEL
	// family logs the same sshd events to /var/log/secure, not
	// /var/log/auth.log — this used to hardcode the Debian path, so this
	// finding never fired on a RHEL box, whatever the actual login traffic.
	if out, err := diagnosticsExec(10*time.Second, "tail", "-n", "500", LogsResolveAuthLogPath()); err == nil {
		failed := diagnosticsCount(diagnosticsLines(diagnosticsLossy(out.Stdout)), "Failed password", "Invalid user")
		if failed >= 50 {
			findings = append(findings, DiagnosticsFinding{
				ID: "log-ssh-bruteforce", Category: "logs", Severity: "critical",
				Title:        fmt.Sprintf("%d failed SSH login attempts in recent logs", failed),
				Description:  "Possible brute force attack. Ensure fail2ban is active.",
				FixAvailable: true, FixID: diagnosticsFix("restart-service:fail2ban"),
			})
		} else if failed >= 10 {
			findings = append(findings, DiagnosticsFinding{
				ID: "log-ssh-failures", Category: "logs", Severity: "warning",
				Title:       fmt.Sprintf("%d failed SSH login attempts in recent logs", failed),
				Description: "Monitor for brute force patterns.",
			})
		}
	}

	// Check syslog for OOM killer activity
	if out, err := diagnosticsExec(10*time.Second, "tail", "-n", "500", "/var/log/syslog"); err == nil {
		if n := diagnosticsCount(diagnosticsLines(diagnosticsLossy(out.Stdout)), "oom-kill", "Out of memory"); n > 0 {
			findings = append(findings, DiagnosticsFinding{
				ID: "log-oom-kills", Category: "logs", Severity: "critical",
				Title:       fmt.Sprintf("%d OOM killer event(s) in recent syslog", n),
				Description: "The system ran out of memory and killed processes. Consider adding swap or upgrading RAM.",
			})
		}
	}

	return findings
}

// ── Security Checks ──────────────────────────────────────────────────────

// diagnosticsSshdDirective returns the first non-comment line (trimmed) that
// starts with prefix.
func diagnosticsSshdDirective(content, prefix string) (string, bool) {
	for _, l := range diagnosticsLines(content) {
		t := strings.TrimSpace(l)
		if !strings.HasPrefix(t, "#") && strings.HasPrefix(t, prefix) {
			return l, true
		}
	}
	return "", false
}

func diagnosticsCheckSecurity() []DiagnosticsFinding {
	var findings []DiagnosticsFinding

	// SSH password authentication enabled?
	if raw, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil && utf8.Valid(raw) {
		content := string(raw)
		passwordAuth := "yes"
		if l, ok := diagnosticsSshdDirective(content, "PasswordAuthentication"); ok {
			if f := strings.Fields(l); len(f) > 1 {
				passwordAuth = f[1]
			}
		}
		// ASCII case-insensitive (eq_ignore_ascii_case): 3 bytes rules out
		// Unicode folds like "yeſ".
		if len(passwordAuth) == 3 && strings.EqualFold(passwordAuth, "yes") {
			findings = append(findings, DiagnosticsFinding{
				ID: "ssh-password-auth", Category: "security", Severity: "warning",
				Title:       "SSH password authentication is enabled",
				Description: "Key-based authentication is more secure. Consider disabling PasswordAuthentication.",
			})
		}

		// SSH on default port 22?
		port := uint64(22)
		if l, ok := diagnosticsSshdDirective(content, "Port "); ok {
			if f := strings.Fields(l); len(f) > 1 {
				if p, err := strconv.ParseUint(f[1], 10, 16); err == nil {
					port = p
				}
			}
		}
		if port == 22 {
			findings = append(findings, DiagnosticsFinding{
				ID: "ssh-default-port", Category: "security", Severity: "info",
				Title:       "SSH running on default port 22",
				Description: "Changing SSH port reduces automated scanning noise (not a security fix, but reduces log spam).",
			})
		}
	}

	// Firewall active? This used to ask ufw specifically, so on the whole RHEL
	// family — firewalld running, ufw usually not installed — it raised
	// "Firewall (ufw) is not active" on boxes that were firewalled perfectly
	// well, naming a tool the operator does not have.
	if FirewallDetect() == FirewallNone {
		findings = append(findings, DiagnosticsFinding{
			ID: "firewall-inactive", Category: "security", Severity: "warning",
			Title:       "No firewall is active",
			Description: "Neither firewalld nor ufw is running — all ports are exposed to the internet.",
		})
	}

	// Unattended upgrades?
	if _, err := os.Stat("/etc/apt/apt.conf.d/20auto-upgrades"); err != nil {
		findings = append(findings, DiagnosticsFinding{
			ID: "no-auto-updates", Category: "security", Severity: "info",
			Title:       "Automatic security updates not configured",
			Description: "Consider enabling unattended-upgrades for automatic security patches.",
		})
	}

	return findings
}

// ── One-Click Fixes ──────────────────────────────────────────────────────

// DiagnosticsApplyFix applies a one-click fix by ID ("action:target"). The
// error text is returned to the panel verbatim.
func DiagnosticsApplyFix(fixID string) (string, error) {
	action, target, _ := strings.Cut(fixID, ":")

	switch action {
	case "restart-service":
		if target == "" {
			return "", errors.New("No service specified")
		}
		// Validate service name. systemd unit names can legitimately contain
		// dots (php8.3-fpm, containerd.service, ...) — a validator rejecting
		// dots silently broke every PHP-FPM restart on Debian/Ubuntu hosts.
		for _, c := range target {
			if !diagnosticsIsASCIIAlnum(c) && c != '-' && c != '_' && c != '.' {
				return "", errors.New("Invalid service name")
			}
		}

		// Resolve the actual systemd unit(s). The panel sends a friendly
		// "php-fpm" because it can't know which PHP version(s) are installed;
		// expand version-less aliases by enumerating loaded units.
		services := []string{target}
		if target == "php-fpm" {
			// Every loaded `php<ver>-fpm.service` (Debian/Ubuntu) or a plain
			// `php-fpm.service` (some distros); restart all of them.
			list, err := diagnosticsExec(10*time.Second, "systemctl",
				"list-units", "--type=service", "--no-legend", "--plain", "--full")
			if errors.Is(err, context.DeadlineExceeded) {
				return "", errors.New("Failed to enumerate services: timed out")
			} else if err != nil {
				return "", fmt.Errorf("Failed to enumerate services: %v", err)
			}
			services = nil
			for _, l := range diagnosticsLines(diagnosticsLossy(list.Stdout)) {
				f := strings.Fields(l)
				if len(f) == 0 {
					continue
				}
				n := diagnosticsTrimEndMatches(f[0], ".service")
				if n == "php-fpm" || (strings.HasPrefix(n, "php") && strings.HasSuffix(n, "-fpm")) {
					services = append(services, n)
				}
			}
			if len(services) == 0 {
				return "", errors.New("No PHP-FPM service installed on this host")
			}
		}

		var succeeded []string
		for _, svc := range services {
			out, err := diagnosticsExec(30*time.Second, "systemctl", "restart", svc)
			if errors.Is(err, context.DeadlineExceeded) {
				return "", fmt.Errorf("Restart of %s timed out", svc)
			} else if err != nil {
				return "", fmt.Errorf("Failed to run systemctl: %v", err)
			}
			if !out.Success() {
				return "", fmt.Errorf("Failed to restart %s: %s", svc, diagnosticsLossy(out.Stderr))
			}
			succeeded = append(succeeded, svc)
		}
		return "Restarted: " + strings.Join(succeeded, ", "), nil

	case "create-root":
		if target == "" {
			return "", errors.New("No path specified")
		}
		// Validate path starts with expected prefix. A prefix check alone let
		// "/var/www/../etc/x" through, so `..` is refused outright.
		if strings.Contains(target, "..") || strings.ContainsRune(target, 0) {
			return "", errors.New("Path must be under /var/www/ or /etc/dockpanel/sites/")
		}
		if !strings.HasPrefix(target, "/var/www/") && !strings.HasPrefix(target, "/etc/dockpanel/sites/") {
			return "", errors.New("Path must be under /var/www/ or /etc/dockpanel/sites/")
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			return "", fmt.Errorf("Failed to create directory: %v", err)
		}

		// Create a default index.html
		index := target + "/index.html"
		if _, err := os.Stat(index); err != nil {
			_ = os.WriteFile(index, []byte("<h1>Site coming soon</h1>\n"), 0o644)
		}

		// Set ownership to www-data (Rust had no timeout here).
		_, _ = safecmd.Exec(context.Background(), "chown", "-R", "www-data:www-data", target)

		return "Created document root: " + target, nil

	case "clean-logs":
		// Truncate large log files to free disk
		var freed uint64
		for _, log := range []string{"/var/log/nginx/access.log", "/var/log/nginx/error.log", "/var/log/syslog"} {
			if st, err := os.Stat(log); err == nil && st.Size() > 100*1024*1024 { // > 100MB
				freed += uint64(st.Size())
				_ = os.WriteFile(log, nil, 0o644)
			}
		}

		// Also truncate any log file > 500MB anywhere in /var/log (no timeout
		// in Rust either).
		if out, err := safecmd.Exec(context.Background(), "find",
			"/var/log", "-name", "*.log", "-size", "+500M", "-type", "f"); err == nil {
			for _, p := range diagnosticsLines(diagnosticsLossy(out.Stdout)) {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if st, err := os.Stat(p); err == nil {
					freed += uint64(st.Size())
					_ = os.WriteFile(p, nil, 0o644)
					slog.Info(fmt.Sprintf("Truncated oversized log: %s (%.0f MB)", p, float64(st.Size())/1024/1024))
				}
			}
		}

		// Also clean up old journal entries
		_, _ = diagnosticsExec(10*time.Second, "journalctl", "--vacuum-size=100M")

		if freed > 0 {
			return fmt.Sprintf("Cleaned %.0f MB of log files", float64(freed)/1024/1024), nil
		}
		return "No oversized log files found. Ran journal vacuum.", nil

	// Clean /tmp files older than 7 days
	case "clean-tmp":
		out, err := diagnosticsExec(30*time.Second, "find", "/tmp", "-type", "f", "-mtime", "+7", "-delete")
		if errors.Is(err, context.DeadlineExceeded) {
			return "", errors.New("Tmp cleanup timed out")
		} else if err != nil {
			return "", fmt.Errorf("Failed to clean /tmp: %v", err)
		}
		if out.Success() {
			return "Cleaned /tmp files older than 7 days", nil
		}
		stderr := []rune(diagnosticsLossy(out.Stderr))
		return "Tmp cleanup completed with warnings: " + string(stderr[:min(200, len(stderr))]), nil

	// Reclaim only what DockPanel does NOT manage.
	//
	// This replaces `docker system prune -af --volumes`, which removed every
	// stopped container, every image not held by a RUNNING container, and
	// every unattached volume. That was catastrophic rather than aggressive:
	//   * a container the panel put to SLEEP is a stopped container, so the
	//     panel deleted the app it intended to wake (`wake` only issues
	//     `docker start` on an id that no longer exists);
	//   * removing that container detached its volumes, which the same command
	//     then reclaimed, so the tenant's data went with it;
	//   * a locally built image (git deploys, every rollback target) has no
	//     registry to be pulled back from.
	// `dockpanel.managed=true` is the label the panel puts on everything it
	// creates (same evidence services/ownership uses). `docker-prune` is the
	// OLD id and is deliberately routed here, so an older panel pointed at a
	// newer agent cannot get the destructive behaviour back by name.
	case "docker-reclaim", "docker-prune":
		if action == "docker-prune" {
			slog.Warn("docker-prune is deprecated and now performs a SCOPED reclaim; " +
				"the caller is an older panel. Upgrade the panel to use docker-reclaim.")
		}
		var freed []string
		reclaimed := func(out safecmd.Output) (string, bool) {
			if !out.Success() {
				return "", false
			}
			for _, l := range diagnosticsLines(diagnosticsLossy(out.Stdout)) {
				if strings.Contains(l, "reclaimed") {
					return l, true
				}
			}
			return "", false
		}

		// Dangling images only: never `-a`, so an image backing a stopped
		// (slept, or merely crashed) container is untouched.
		out, err := diagnosticsExec(60*time.Second, "docker",
			"image", "prune", "-f", "--filter", "label!=dockpanel.managed=true")
		if errors.Is(err, context.DeadlineExceeded) {
			return "", errors.New("Docker image prune timed out")
		} else if err == nil {
			if l, ok := reclaimed(out); ok {
				freed = append(freed, l)
			}
		}

		// Build cache is never a live resource — safe to reclaim in full.
		out, err = diagnosticsExec(60*time.Second, "docker", "builder", "prune", "-f")
		if errors.Is(err, context.DeadlineExceeded) {
			return "", errors.New("Docker builder prune timed out")
		} else if err == nil {
			if l, ok := reclaimed(out); ok {
				freed = append(freed, "build cache: "+l)
			}
		}

		// Networks the panel did not create and nothing is attached to.
		_, _ = diagnosticsExec(30*time.Second, "docker",
			"network", "prune", "-f", "--filter", "label!=dockpanel.managed=true")

		// NOTE: volumes are deliberately NOT reclaimed. An unattached volume is
		// indistinguishable from a volume whose container is stopped, and the
		// panel stops containers on purpose. Volume reclamation belongs to an
		// explicit, itemised operator action, not to a disk alert.
		if len(freed) == 0 {
			return "Reclaimed unmanaged Docker resources (nothing to free)", nil
		}
		return "Reclaimed unmanaged Docker resources — " + strings.Join(freed, "; "), nil

	case "clean-cache":
		// Clear nginx fastcgi/proxy cache for a specific domain
		if target == "" {
			return "", errors.New("No domain specified for cache purge")
		}
		// Validate target is a safe domain name (alphanumeric, dots, hyphens)
		for _, c := range target {
			if !diagnosticsIsASCIIAlnum(c) && c != '.' && c != '-' {
				return "", errors.New("Invalid domain name for cache purge")
			}
		}

		var cleaned uint64
		// Common nginx cache directories
		for _, dir := range []string{
			"/var/cache/nginx/" + target,
			"/var/cache/nginx/fastcgi/" + target,
			"/tmp/nginx-cache/" + target,
		} {
			if _, err := os.Stat(dir); err != nil {
				continue
			}
			if entries, err := os.ReadDir(dir); err == nil {
				for _, e := range entries {
					if info, err := e.Info(); err == nil {
						cleaned += uint64(info.Size())
					}
				}
			}
			_ = os.RemoveAll(dir)
			_ = os.MkdirAll(dir, 0o755)
		}

		if cleaned > 0 {
			return fmt.Sprintf("Purged %.0f KB of cache for %s", float64(cleaned)/1024, target), nil
		}
		return fmt.Sprintf("No cache found for %s (directories checked: /var/cache/nginx/)", target), nil
	}
	return "", fmt.Errorf("Unknown fix action: %s", action)
}

func diagnosticsIsASCIIAlnum(c rune) bool {
	return c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9')
}
