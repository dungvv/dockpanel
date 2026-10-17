package services

import (
	"os"
	"strings"
	"testing"
)

// See internal/api/version_test.go: the default must match VERSION.
func TestDefaultAgentVersionMatchesVersionFile(t *testing.T) {
	b, err := os.ReadFile("../../../../../VERSION")
	if err != nil {
		t.Skip("VERSION not found:", err)
	}
	if want := strings.TrimSpace(string(b)); AgentVersion != want {
		t.Fatalf("AgentVersion = %q, VERSION file says %q", AgentVersion, want)
	}
}
