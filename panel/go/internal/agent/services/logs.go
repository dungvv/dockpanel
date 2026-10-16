package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// LogsResolveAuthLogPath returns the file sshd (and other PAM-based auth)
// actually logs to on this box. Debian/Ubuntu writes /var/log/auth.log; the
// RHEL family (CentOS/Rocky/AlmaLinux/Fedora — a first-class setup.sh target)
// writes the same events to /var/log/secure instead. Call sites used to not
// check which one exists, so a RHEL box silently looked like a quiet Debian box.
func LogsResolveAuthLogPath() string {
	if logsExists("/var/log/auth.log") {
		return "/var/log/auth.log"
	}
	return "/var/log/secure"
}

// logsExists mirrors Rust Path::exists (follows symlinks, any error → false).
func logsExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// LogsResolveLogPath resolves a log type string to the corresponding file
// path. Validates domain names to prevent path traversal.
func LogsResolveLogPath(logType string) (string, error) {
	// Site-specific log types: "nginx_access:{domain}" or "nginx_error:{domain}"
	if domain, ok := strings.CutPrefix(logType, "nginx_access:"); ok {
		if err := logsValidateDomain(domain); err != nil {
			return "", err
		}
		return "/var/log/nginx/" + domain + ".access.log", nil
	}
	if domain, ok := strings.CutPrefix(logType, "nginx_error:"); ok {
		if err := logsValidateDomain(domain); err != nil {
			return "", err
		}
		return "/var/log/nginx/" + domain + ".error.log", nil
	}
	// Site-specific PHP-FPM error logs
	if domain, ok := strings.CutPrefix(logType, "php_error:"); ok {
		if err := logsValidateDomain(domain); err != nil {
			return "", err
		}
		// PHP-FPM site errors land in the nginx error log by default
		return "/var/log/nginx/" + domain + ".error.log", nil
	}

	switch logType {
	case "nginx_access":
		return "/var/log/nginx/access.log", nil
	case "nginx_error":
		return "/var/log/nginx/error.log", nil
	case "syslog":
		return "/var/log/syslog", nil
	case "auth":
		return LogsResolveAuthLogPath(), nil
	case "php_fpm":
		// Find the active PHP-FPM log
		if entries, err := os.ReadDir("/var/log"); err == nil {
			for _, e := range entries {
				if name := e.Name(); strings.HasPrefix(name, "php") && strings.HasSuffix(name, "-fpm.log") {
					return "/var/log/" + name, nil
				}
			}
		}
		return "/var/log/php-fpm.log", nil
	}
	return "", fmt.Errorf("Unknown log type: %s", logType)
}

// logsValidateDomain: no slashes, no "..", only alphanumeric, hyphens, dots.
func logsValidateDomain(domain string) error {
	if domain == "" {
		return errors.New("Domain cannot be empty")
	}
	if strings.ContainsAny(domain, `/\`) || strings.Contains(domain, "..") {
		return errors.New("Invalid domain: path traversal denied")
	}
	for _, c := range domain {
		if !(c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.')) {
			return errors.New("Invalid domain: only alphanumeric, hyphens, and dots allowed")
		}
	}
	return nil
}

// LogsLines splits like Rust str::lines on lossily-decoded UTF-8: "\n" or
// "\r\n" terminators, no trailing empty line.
func LogsLines(b []byte) []string {
	s := strings.ToValidUTF8(string(b), "�")
	if s == "" {
		return []string{}
	}
	parts := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	last := len(parts) - 1
	for i := range parts {
		// The unterminated final line keeps a bare trailing '\r' (Rust ≥1.77).
		if i < last || strings.HasSuffix(s, "\n") {
			parts[i] = strings.TrimSuffix(parts[i], "\r")
		}
	}
	return parts
}

// LogsReadLog reads the last N lines from a log file, with an optional
// case-insensitive text filter ("" = no filter).
func LogsReadLog(ctx context.Context, logType string, lines int, filter string) ([]string, error) {
	path, err := LogsResolveLogPath(logType)
	if err != nil {
		return nil, err
	}
	if !logsExists(path) {
		return nil, fmt.Errorf("Log file not found: %s", path)
	}

	// Cap lines to a reasonable maximum
	lines = min(lines, 10_000)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "tail", "-n", strconv.Itoa(lines), path)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, errors.New("Log read timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to read log: %v", err)
	}
	if !out.Success() {
		return nil, fmt.Errorf("tail failed: %s", strings.ToValidUTF8(string(out.Stderr), "�"))
	}

	all := LogsLines(out.Stdout)
	if filter == "" {
		return all, nil
	}
	lower := strings.ToLower(filter)
	res := []string{}
	for _, l := range all {
		if strings.Contains(strings.ToLower(l), lower) {
			res = append(res, l)
		}
	}
	return res, nil
}

// LogsSearchLog searches a log file with grep, returning matching lines
// capped at maxResults.
func LogsSearchLog(ctx context.Context, logType, pattern string, maxResults int) ([]string, error) {
	// Validate pattern: length limit to prevent ReDoS, reject null bytes
	if len(pattern) > 500 {
		return nil, errors.New("Pattern too long (max 500 characters)")
	}
	if strings.Contains(pattern, "\x00") {
		return nil, errors.New("Pattern contains invalid characters")
	}

	path, err := LogsResolveLogPath(logType)
	if err != nil {
		return nil, err
	}
	if !logsExists(path) {
		return nil, fmt.Errorf("Log file not found: %s", path)
	}

	maxResults = min(maxResults, 5000)

	// `--` ends options, so a pattern starting with "-" is a pattern.
	// grep -iF: case-insensitive fixed-string matching (no regex), which
	// eliminates ReDoS risk from user-supplied patterns.
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "grep", "-iF", "-m", strconv.Itoa(maxResults), "--", pattern, path)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, errors.New("Search timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("grep failed: %v", err)
	}
	// grep returns exit code 1 for "no matches" — not an error
	if !out.Success() && out.ExitCode != 1 {
		return nil, fmt.Errorf("grep error: %s", strings.ToValidUTF8(string(out.Stderr), "�"))
	}
	return LogsLines(out.Stdout), nil
}
