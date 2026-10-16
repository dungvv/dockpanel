package services

import (
	"math"
	"testing"
)

// Refusals must never reach a command or the filesystem.
func TestDiagnosticsApplyFixRefusals(t *testing.T) {
	for id, want := range map[string]string{
		"restart-service":              "No service specified",
		"restart-service:nginx;reboot": "Invalid service name",
		"restart-service:a b":          "Invalid service name",
		"create-root":                  "No path specified",
		"create-root:/etc/passwd":      "Path must be under /var/www/ or /etc/dockpanel/sites/",
		"clean-cache":                  "No domain specified for cache purge",
		"clean-cache:../../etc":        "Invalid domain name for cache purge",
		"clean-cache:a/b":              "Invalid domain name for cache purge",
		"rm-rf:/":                      "Unknown fix action: rm-rf",
		"":                             "Unknown fix action: ",
	} {
		_, err := DiagnosticsApplyFix(id)
		if err == nil || err.Error() != want {
			t.Errorf("%q: got %v want %q", id, err, want)
		}
	}
}

func TestDiagnosticsHelpers(t *testing.T) {
	if got := diagnosticsLines("a\r\nb\n"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("lines: %q", got)
	}
	if got := diagnosticsTrimEndMatches("x.conf.conf", ".conf"); got != "x" {
		t.Errorf("trim: %q", got)
	}
	if diagnosticsSatU32(math.NaN()) != 0 || diagnosticsSatU32(1e20) != 4294967295 || diagnosticsSatU32(42.9) != 42 {
		t.Error("satU32")
	}
}
