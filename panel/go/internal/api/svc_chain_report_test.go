package api

import (
	"os"
	"testing"
)

// chain_report.rs has no tests of its own; this pins the embedded template
// to the Rust tree's include_str! source while both exist.
func TestChainReportTemplateMatchesRustTree(t *testing.T) {
	want, err := os.ReadFile("../../../backend/templates/chain-report.typ")
	if err != nil {
		t.Skip("Rust tree not present")
	}
	if string(want) != chainReportTemplateTyp {
		t.Fatal("templates/chain-report.typ differs from panel/backend/templates/chain-report.typ")
	}
}
