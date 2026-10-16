package services

import (
	"reflect"
	"strings"
	"testing"
)

func TestLogsResolveLogPath(t *testing.T) {
	ok := map[string]string{
		"nginx_access":             "/var/log/nginx/access.log",
		"nginx_error":              "/var/log/nginx/error.log",
		"syslog":                   "/var/log/syslog",
		"nginx_access:example.com": "/var/log/nginx/example.com.access.log",
		"nginx_error:example.com":  "/var/log/nginx/example.com.error.log",
		"php_error:example.com":    "/var/log/nginx/example.com.error.log",
	}
	for in, want := range ok {
		if got, err := LogsResolveLogPath(in); err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	if got, _ := LogsResolveLogPath("auth"); got != "/var/log/auth.log" && got != "/var/log/secure" {
		t.Errorf("auth: %q", got)
	}
	bad := map[string]string{
		"nginx_access:":              "Domain cannot be empty",
		"nginx_access:../etc/passwd": "path traversal denied",
		"nginx_error:a/b":            "path traversal denied",
		`php_error:a\b`:              "path traversal denied",
		"nginx_access:a..b":          "path traversal denied",
		"nginx_access:a b":           "only alphanumeric",
		"nginx_access:é.com":         "only alphanumeric",
		"/etc/shadow":                "Unknown log type: /etc/shadow",
		"":                           "Unknown log type",
	}
	for in, want := range bad {
		if _, err := LogsResolveLogPath(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err %v, want %q", in, err, want)
		}
	}
}

func TestLogsLines(t *testing.T) {
	cases := map[string][]string{
		"":         {},
		"a":        {"a"},
		"a\n":      {"a"},
		"a\r\nb\n": {"a", "b"},
		"a\n\nb":   {"a", "", "b"},
		"a\nb\r":   {"a", "b\r"},
		"\n":       {""},
	}
	for in, want := range cases {
		if got := LogsLines([]byte(in)); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestLogsSearchLogPatternChecks(t *testing.T) {
	if _, err := LogsSearchLog(t.Context(), "syslog", strings.Repeat("a", 501), 10); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("long pattern: %v", err)
	}
	if _, err := LogsSearchLog(t.Context(), "syslog", "a\x00b", 10); err == nil || !strings.Contains(err.Error(), "invalid characters") {
		t.Errorf("NUL pattern: %v", err)
	}
	if _, err := LogsReadLog(t.Context(), "bogus", 10, ""); err == nil || !strings.Contains(err.Error(), "Unknown log type") {
		t.Errorf("unknown type: %v", err)
	}
}
