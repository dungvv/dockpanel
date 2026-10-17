package api

import (
	"os"
	"strings"
	"testing"
)

// Builds stamp the version from VERSION via -ldflags; the in-source default
// is what `go run`/tests report, so it must not drift from that file.
func TestDefaultVersionMatchesVersionFile(t *testing.T) {
	b, err := os.ReadFile("../../../../VERSION")
	if err != nil {
		t.Skip("VERSION not found:", err)
	}
	if want := strings.TrimSpace(string(b)); Version != want {
		t.Fatalf("api.Version = %q, VERSION file says %q", Version, want)
	}
}
