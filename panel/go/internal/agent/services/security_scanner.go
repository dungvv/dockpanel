package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/client"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

type SecurityScannerScanResult struct {
	Findings   []SecurityScannerFinding  `json:"findings"`
	FileHashes []SecurityScannerFileHash `json:"file_hashes"`
}

type SecurityScannerFinding struct {
	CheckType   string  `json:"check_type"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	FilePath    *string `json:"file_path"`
	Remediation *string `json:"remediation"`
}

type SecurityScannerFileHash struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
	Size uint64 `json:"size"`
}

func securityScannerStr(s string) *string { return &s }

// securityScannerIntegrityFiles are critical system files tracked for
// integrity changes.
var securityScannerIntegrityFiles = []string{
	"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
	"/etc/hosts", "/etc/crontab", "/etc/nginx/nginx.conf",
}

// securityScannerMalwarePatterns are common malware patterns in PHP files.
var securityScannerMalwarePatterns = [][2]string{
	{`eval\s*\(\s*base64_decode`, "eval(base64_decode()) — obfuscated code execution"},
	{`eval\s*\(\s*gzinflate`, "eval(gzinflate()) — compressed payload execution"},
	{`eval\s*\(\s*str_rot13`, "eval(str_rot13()) — obfuscated code"},
	{`eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)`, "eval() with user input — remote code execution"},
	{`preg_replace\s*\(.*/e`, "preg_replace with /e modifier — code execution"},
	{`assert\s*\(\s*\$_`, "assert() with user input — code injection"},
	{`system\s*\(\s*\$_`, "system() with user input — command injection"},
	{`passthru\s*\(\s*\$_`, "passthru() with user input — command injection"},
	{`shell_exec\s*\(\s*\$_`, "shell_exec() with user input — command injection"},
	{`exec\s*\(\s*\$_`, "exec() with user input — command injection"},
}

// securityScannerSuspiciousFiles are filenames that indicate web shells.
var securityScannerSuspiciousFiles = []string{
	"c99.php", "r57.php", "wso.php", "b374k.php", "alfa.php",
	"webshell.php", "shell.php", "cmd.php", "backdoor.php",
	".htaccess.bak", "wp-config.php.bak",
}

// securityScannerSecretPattern is one hardcoded-secret signature. pattern is
// a POSIX ERE for `grep -E` (DFA, no backtracking — no ReDoS even on
// adversarial input); ci = case-insensitive. The matched VALUE is never
// copied into a Finding — only file, line and label — so a scan result
// cannot itself leak (or, once backed up, archive) a live credential.
type securityScannerSecretPattern struct {
	pattern, label, severity string
	ci                       bool
}

// High-precision signatures: vendor-prefixed formats plus a labeled
// `key = "value"` heuristic that only fires on a quoted literal from a
// secret-shaped alphabet (so getenv(...) / "${VAR}" don't match).
var securityScannerSecretPatterns = []securityScannerSecretPattern{
	{`-----BEGIN [A-Z ]*PRIVATE KEY`, "private key (PEM)", "critical", false},
	{`AKIA[0-9A-Z]{16}`, "AWS access key ID", "critical", false},
	{`AIza[0-9A-Za-z_-]{35}`, "Google API key", "critical", false},
	{`sk_live_[0-9a-zA-Z]{24,}`, "Stripe live secret key", "critical", false},
	{`gh[pousr]_[0-9A-Za-z]{36,}`, "GitHub token", "critical", false},
	{`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`, "SendGrid API key", "critical", false},
	{`xox[baprs]-[0-9A-Za-z-]{10,}`, "Slack token", "warning", false},
	{`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, "hardcoded JWT", "warning", false},
	{`(mysql|postgres|postgresql|mongodb|redis|amqp)://[^:@/[:space:]]*:[^@/[:space:]]+@`, "database URI with embedded password", "warning", true},
	{`(api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password)['"]?[[:space:]]*(=>?|:)[[:space:]]*['"][A-Za-z0-9_./+=-]{8,}['"]`, "hardcoded credential assignment", "warning", true},
}

// File types scanned for secrets. `.env*` is deliberately NOT included: an
// env file is the CORRECT home for a secret (and nginx blocks dotfiles).
var securityScannerSecretIncludeGlobs = []string{
	"*.php", "*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs", "*.py", "*.rb",
	"*.go", "*.java", "*.cs", "*.yml", "*.yaml", "*.json", "*.xml", "*.ini",
	"*.conf", "*.properties", "*.sh", "*.inc", "*.pem", "*.key",
}

// Third-party code (not the tenant's secrets, and huge) plus VCS/build noise.
var securityScannerSecretExcludeDirs = []string{
	"node_modules", "vendor", ".git", ".svn", "bower_components",
	"cache", ".cache", "dist", "build",
}

// Machine-generated lockfiles and minified bundles: only false positives.
var securityScannerSecretExcludeFiles = []string{
	"package-lock.json", "yarn.lock", "composer.lock", "*.min.js", "*.min.css",
}

// SecurityScannerRunFullScan runs every scan concurrently: file integrity,
// malware, ports, SSL, container vulns, security headers, webroot secrets.
func SecurityScannerRunFullScan() SecurityScannerScanResult {
	var wg sync.WaitGroup
	var integrity []SecurityScannerFileHash
	parts := make([][]SecurityScannerFinding, 6)
	scans := []func() []SecurityScannerFinding{
		securityScannerScanMalware, securityScannerScanOpenPorts, securityScannerScanSslExpiry,
		securityScannerScanContainerVulnerabilities, securityScannerScanSecurityHeaders, securityScannerScanSecrets,
	}
	wg.Add(len(scans) + 1)
	go func() { defer wg.Done(); integrity = securityScannerScanFileIntegrity() }()
	for i, f := range scans {
		go func() { defer wg.Done(); parts[i] = f() }()
	}
	wg.Wait()
	findings := []SecurityScannerFinding{}
	for _, p := range parts {
		findings = append(findings, p...)
	}
	return SecurityScannerScanResult{Findings: findings, FileHashes: integrity}
}

// securityScannerExec runs bin within d; ok=false on timeout or spawn error.
func securityScannerExec(d time.Duration, bin string, args ...string) (safecmd.Output, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	out, err := safecmd.Exec(ctx, bin, args...)
	return out, err == nil
}

func securityScannerScanFileIntegrity() []SecurityScannerFileHash {
	hashes := []SecurityScannerFileHash{}
	for _, p := range securityScannerIntegrityFiles {
		st, err := os.Stat(p)
		if err != nil {
			continue // file doesn't exist
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(b)
		hashes = append(hashes, SecurityScannerFileHash{Path: p, Hash: hex.EncodeToString(sum[:]), Size: uint64(st.Size())})
	}
	return hashes
}

func securityScannerScanMalware() []SecurityScannerFinding {
	var findings []SecurityScannerFinding
	roots := []string{"/var/www", "/etc/dockpanel/sites"}
	for _, root := range roots {
		out, ok := securityScannerExec(60*time.Second, "find", root, "-maxdepth", "5", "-type", "f", "-name", "*.php")
		if !ok {
			continue
		}
		for _, line := range LogsLines(out.Stdout) {
			name := line[strings.LastIndexByte(line, '/')+1:]
			if slices.Contains(securityScannerSuspiciousFiles, name) {
				findings = append(findings, SecurityScannerFinding{
					CheckType: "malware", Severity: "critical",
					Title:       "Suspicious file: " + name,
					Description: "Known web shell filename detected at " + line,
					FilePath:    securityScannerStr(line),
					Remediation: securityScannerStr("Inspect and remove this file immediately"),
				})
			}
		}
	}
	for _, root := range roots {
		for _, pd := range securityScannerMalwarePatterns {
			out, ok := securityScannerExec(30*time.Second, "grep", "-rlE", pd[0], "--include=*.php", root)
			if !ok {
				continue
			}
			lines := LogsLines(out.Stdout)
			for _, file := range lines[:min(len(lines), 10)] { // max 10 per pattern
				if file != "" {
					findings = append(findings, SecurityScannerFinding{
						CheckType: "malware", Severity: "critical", Title: pd[1],
						Description: "Malware pattern found in " + file,
						FilePath:    securityScannerStr(file),
						Remediation: securityScannerStr("Review this file for malicious code"),
					})
				}
			}
		}
	}
	return findings
}

// securityScannerExpectedPorts are "ports DockPanel itself puts here", so an
// entry outlives its listener as a blind spot: 9090 was dropped with the
// loopback forwarding listener that bound it, and anything there now is
// genuinely not ours (Prometheus/Cockpit will show one new finding — that is
// the scanner working).
var securityScannerExpectedPorts = []uint16{22, 25, 80, 443, 993, 995, 3080, 5432, 5450}

func securityScannerScanOpenPorts() []SecurityScannerFinding {
	out, ok := securityScannerExec(10*time.Second, "ss", "-tlnp")
	if !ok {
		return nil
	}
	return securityScannerParseOpenPorts(LogsLines(out.Stdout))
}

func securityScannerParseOpenPorts(lines []string) []SecurityScannerFinding {
	var findings []SecurityScannerFinding
	seen := map[uint16]bool{}
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		// *:port, 0.0.0.0:port, [::]:port, 127.0.0.1:port
		local := parts[3]
		p, err := strconv.ParseUint(local[strings.LastIndexByte(local, ':')+1:], 10, 16)
		if err != nil {
			continue
		}
		port := uint16(p)
		// Expected, ephemeral, already-seen (seen is recorded even when
		// skipped below, as in the original).
		if slices.Contains(securityScannerExpectedPorts, port) || port >= 32768 || seen[port] {
			continue
		}
		seen[port] = true
		if strings.HasPrefix(local, "127.") || strings.HasPrefix(local, "[::1]") {
			continue // loopback-only
		}
		process := parts[len(parts)-1]
		if strings.Contains(process, "docker-proxy") || strings.Contains(process, "containerd") {
			continue // Docker-managed
		}
		findings = append(findings, SecurityScannerFinding{
			CheckType: "open_port", Severity: "warning",
			Title:       fmt.Sprintf("Unexpected open port: %d", port),
			Description: fmt.Sprintf("Port %d is listening (%s)", port, process),
			Remediation: securityScannerStr(fmt.Sprintf("If this port is not needed, close it with: ufw deny %d/tcp", port)),
		})
	}
	return findings
}

func securityScannerScanSslExpiry() []SecurityScannerFinding {
	const sslDir = "/etc/dockpanel/ssl"
	ents, err := os.ReadDir(sslDir)
	if err != nil {
		return nil
	}
	var findings []SecurityScannerFinding
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		domain := e.Name()
		cert := sslDir + "/" + domain + "/fullchain.pem"
		out, ok := securityScannerExec(10*time.Second, "openssl", "x509", "-enddate", "-noout", "-in", cert)
		if !ok || !out.Success() {
			continue
		}
		// notAfter=Mar 15 12:00:00 2026 GMT
		date, found := strings.CutPrefix(strings.TrimSpace(securityLossy(out.Stdout)), "notAfter=")
		if !found {
			continue
		}
		check, ok := securityScannerExec(5*time.Second, "openssl", "x509", "-checkend", "2592000", "-noout", "-in", cert) // 30 days
		if !ok || check.Success() {
			continue
		}
		check7, ok := securityScannerExec(5*time.Second, "openssl", "x509", "-checkend", "604800", "-noout", "-in", cert) // 7 days
		if !ok {
			continue
		}
		severity := "warning"
		if !check7.Success() {
			severity = "critical"
		}
		findings = append(findings, SecurityScannerFinding{
			CheckType: "ssl_expiry", Severity: severity,
			Title:       "SSL certificate expiring: " + domain,
			Description: "Certificate expires " + date,
			FilePath:    securityScannerStr(cert),
			Remediation: securityScannerStr("Renew the SSL certificate from the panel"),
		})
	}
	return findings
}

// securityScannerScanContainerVulnerabilities scans DockPanel-managed images:
// grype first (if installed), docker scout as fallback.
func securityScannerScanContainerVulnerabilities() []SecurityScannerFinding {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return nil
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	res, err := cli.ContainerList(ctx, client.ContainerListOptions{
		Filters: make(client.Filters).Add("label", "dockpanel.managed=true"),
	})
	cancel()
	if err != nil {
		return nil
	}
	var findings []SecurityScannerFinding
	scanned := map[string]bool{}
	for _, c := range res.Items {
		image := c.Image
		if image == "" || scanned[image] {
			continue
		}
		scanned[image] = true

		if out, ok := securityScannerExec(120*time.Second, "grype", image, "-o", "json", "--only-fixed"); ok && out.Success() {
			if f, ok := securityScannerGrypeFinding(image, out.Stdout); ok {
				findings = append(findings, f)
			}
			continue // grype worked, skip docker scout
		}

		out, ok := securityScannerExec(120*time.Second, "docker", "scout", "quickview", image)
		if !ok {
			continue
		}
		stdout := securityLossy(out.Stdout)
		// Parse "X critical, Y high" from output.
		hasCritical := strings.Contains(stdout, "critical") && !strings.Contains(stdout, "0C")
		hasHigh := strings.Contains(stdout, "high") && !strings.Contains(stdout, "0H")
		if !hasCritical && !hasHigh {
			continue
		}
		severity := "warning"
		if hasCritical {
			severity = "critical"
		}
		desc := ""
		for _, l := range LogsLines(out.Stdout) {
			if strings.Contains(l, "critical") || strings.Contains(l, "high") {
				desc = strings.TrimSpace(l)
				break
			}
		}
		findings = append(findings, SecurityScannerFinding{
			CheckType: "container_vuln", Severity: severity,
			Title:       fmt.Sprintf("Image %s has known vulnerabilities", image),
			Description: desc,
			FilePath:    securityScannerStr(image),
			Remediation: securityScannerStr("Update the base image and rebuild"),
		})
	}
	return findings
}

// securityScannerGrypeFinding summarises a grype JSON report; ok=false when
// there is nothing critical/high (or the report is unparseable).
func securityScannerGrypeFinding(image string, stdout []byte) (SecurityScannerFinding, bool) {
	var report map[string]any
	if json.Unmarshal([]byte(securityLossy(stdout)), &report) != nil {
		return SecurityScannerFinding{}, false
	}
	matches, ok := report["matches"].([]any)
	if !ok {
		return SecurityScannerFinding{}, false
	}
	critical, high := 0, 0
	for _, m := range matches {
		mm, _ := m.(map[string]any)
		v, _ := mm["vulnerability"].(map[string]any)
		switch s, _ := v["severity"].(string); s {
		case "Critical":
			critical++
		case "High":
			high++
		}
	}
	if critical == 0 && high == 0 {
		return SecurityScannerFinding{}, false
	}
	severity := "warning"
	if critical > 0 {
		severity = "critical"
	}
	total := len(matches)
	return SecurityScannerFinding{
		CheckType: "container_vuln", Severity: severity,
		Title:       fmt.Sprintf("Image %s: %d vulnerabilities (%d critical, %d high)", image, total, critical, high),
		Description: fmt.Sprintf("%d known vulnerabilities with fixes available", total),
		FilePath:    securityScannerStr(image),
		Remediation: securityScannerStr("Update the base image to the latest version and rebuild"),
	}, true
}

var securityScannerRequiredHeaders = [][2]string{
	{"Strict-Transport-Security", "HSTS protects against protocol downgrade attacks"},
	{"X-Content-Type-Options", "Prevents MIME-type sniffing"},
	{"X-Frame-Options", "Prevents clickjacking attacks"},
	{"Content-Security-Policy", "Prevents XSS and data injection attacks"},
}

// securityScannerScanSecurityHeaders checks nginx site configs for headers.
func securityScannerScanSecurityHeaders() []SecurityScannerFinding {
	dir := NginxSitesDir()
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var findings []SecurityScannerFinding
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".conf") || name == "dockpanel.dev.conf" {
			continue // non-site configs
		}
		domain := name
		for strings.HasSuffix(domain, ".conf") {
			domain = strings.TrimSuffix(domain, ".conf")
		}
		path := filepath.Join(dir, name)
		b, _ := os.ReadFile(path)
		content := securityLossy(b)
		for _, h := range securityScannerRequiredHeaders {
			if !strings.Contains(content, h[0]) {
				findings = append(findings, SecurityScannerFinding{
					CheckType: "security_headers", Severity: "info",
					Title:       fmt.Sprintf("Missing %s header on %s", h[0], domain),
					Description: h[1],
					FilePath:    securityScannerStr(path),
					Remediation: securityScannerStr(fmt.Sprintf("Add 'add_header %s \"...\" always;' to the nginx config", h[0])),
				})
			}
		}
	}
	return findings
}

// securityScannerScanSecrets scans every site's webroot for hardcoded secrets
// that belong in an environment variable. The VALUE is never recorded.
func securityScannerScanSecrets() []SecurityScannerFinding {
	return securityScannerScanSecretsIn([]string{"/var/www"})
}

// securityScannerScanSecretsIn: one bounded grep per pattern. `-r` (not
// `-R`) means grep does NOT descend into symlinked directories, so a
// tenant-planted symlink cannot redirect the scan outside its webroot.
func securityScannerScanSecretsIn(roots []string) []SecurityScannerFinding {
	var findings []SecurityScannerFinding
	for _, root := range roots {
		if st, err := os.Stat(root); err != nil || !st.IsDir() {
			continue
		}
		for _, pat := range securityScannerSecretPatterns {
			// -m 1: first match per file is enough, and it caps grep's stdout
			// so a tenant file with millions of matching lines can't balloon
			// the root agent's memory. The context kills a timed-out grep.
			args := []string{"-rnE", "-m", "1"}
			if pat.ci {
				args = append(args, "-i")
			}
			for _, g := range securityScannerSecretIncludeGlobs {
				args = append(args, "--include="+g)
			}
			for _, d := range securityScannerSecretExcludeDirs {
				args = append(args, "--exclude-dir="+d)
			}
			for _, f := range securityScannerSecretExcludeFiles {
				args = append(args, "--exclude="+f)
			}
			// -e so a leading `-` (the PEM header) is never taken as a flag.
			args = append(args, "-e", pat.pattern, root)
			out, ok := securityScannerExec(30*time.Second, "grep", args...)
			if !ok {
				continue // timed out, grep missing, or spawn failure
			}
			// grep exits 1 on no match, 2 on error; both yield nothing. Only
			// stdout is read and the matched content is never surfaced.
			lines := LogsLines(out.Stdout)
			for _, line := range lines[:min(len(lines), 50)] { // 50 files/pattern
				file, lineno, ok := securityScannerParseGrepMatch(line)
				if !ok {
					continue
				}
				findings = append(findings, SecurityScannerFinding{
					CheckType: "secret_leak", Severity: pat.severity,
					Title: "Exposed secret: " + pat.label,
					Description: fmt.Sprintf("A %s was found in %s at line %d. "+
						"The secret value itself is intentionally not recorded by the scanner.", pat.label, file, lineno),
					FilePath: securityScannerStr(file),
					Remediation: securityScannerStr("Move the secret out of the webroot into an environment variable " +
						"(a .env file is not served by DockPanel's nginx) and rotate the exposed credential."),
				})
			}
		}
	}
	return findings
}

// securityScannerParseGrepMatch parses one `grep -rn` line
// (`<path>:<lineno>:<content>`) into (path, lineno), DISCARDING the content
// so a matched secret can never reach a Finding. The leftmost `:<digits>:`
// is always at or before the true separator, so commit to it and stop —
// scanning further could pull a `:<digits>:` inside CONTENT (and the secret)
// into the path. An overflowing line number saturates rather than failing
// and skipping forward (the redaction-leak fix).
func securityScannerParseGrepMatch(line string) (string, uint32, bool) {
	for from := 0; ; {
		rel := strings.IndexByte(line[from:], ':')
		if rel < 0 {
			return "", 0, false
		}
		colon := from + rel
		after := line[colon+1:]
		n := 0
		for n < len(after) && after[n] >= '0' && after[n] <= '9' {
			n++
		}
		if n > 0 && strings.HasPrefix(after[n:], ":") {
			v, err := strconv.ParseUint(after[:n], 10, 32)
			if err != nil {
				v = math.MaxUint32
			}
			return line[:colon], uint32(v), true
		}
		from = colon + 1
	}
}
