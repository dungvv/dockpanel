package api

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAlertRunbookDefaultsFifteenRunbooksLoaded(t *testing.T) {
	if len(AlertRunbookDefaultsDefaults) != 15 {
		t.Fatalf("expected 15 default runbooks, got %d", len(AlertRunbookDefaultsDefaults))
	}
}

func TestAlertRunbookDefaultsAlertTypesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range AlertRunbookDefaultsDefaults {
		if seen[d.AlertType] {
			t.Fatalf("duplicate alert_type: %s", d.AlertType)
		}
		seen[d.AlertType] = true
	}
}

func TestAlertRunbookDefaultsEverySeverityIsValid(t *testing.T) {
	for _, d := range AlertRunbookDefaultsDefaults {
		switch d.Severity {
		case "info", "warning", "critical":
		default:
			t.Fatalf("invalid severity '%s' on %s", d.Severity, d.AlertType)
		}
	}
}

func TestAlertRunbookDefaultsEveryRunbookHasContent(t *testing.T) {
	for _, d := range AlertRunbookDefaultsDefaults {
		if len(d.RunbookMd) <= 100 {
			t.Errorf("%s runbook is suspiciously short (%d chars)", d.AlertType, len(d.RunbookMd))
		}
		for _, s := range []string{"First check", "Common causes", "Escalation"} {
			if !strings.Contains(d.RunbookMd, s) {
				t.Errorf("%s runbook missing '%s' section", d.AlertType, s)
			}
		}
	}
}

func TestAlertRunbookDefaultsSeverityLadderMatchesDesign(t *testing.T) {
	got := map[string]bool{}
	for _, d := range AlertRunbookDefaultsDefaults {
		if d.Severity == "critical" {
			got[d.AlertType] = true
		}
	}
	want := []string{"offline", "service_down", "container_crashloop", "backup_failure", "gpu_temperature"}
	if len(got) != len(want) {
		t.Fatalf("critical severity set drifted from design §2: %v", got)
	}
	for _, w := range want {
		if !got[w] {
			t.Fatalf("critical severity set drifted from design §2: missing %s", w)
		}
	}
}

func TestAlertRunbookDefaultsFindDefaultWorksForKnownAndUnknown(t *testing.T) {
	if AlertRunbookDefaultsFindDefault("offline") == nil {
		t.Fatal("offline missing")
	}
	if AlertRunbookDefaultsFindDefault("does_not_exist") != nil {
		t.Fatal("unknown type found")
	}
}

// The embedded copies must stay byte-identical to the Rust tree's
// include_str! sources while both exist.
func TestAlertRunbookDefaultsMatchRustTree(t *testing.T) {
	rust := "../../../backend/runbooks"
	if _, err := os.Stat(rust); err != nil {
		t.Skip("Rust tree not present")
	}
	files, _ := filepath.Glob(filepath.Join(rust, "*.md"))
	if len(files) != len(AlertRunbookDefaultsDefaults) {
		t.Fatalf("Rust tree has %d runbooks, Go embeds %d", len(files), len(AlertRunbookDefaultsDefaults))
	}
	for _, f := range files {
		want, _ := os.ReadFile(f)
		got, err := alertRunbookDefaultsFS.ReadFile("runbooks/" + filepath.Base(f))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("runbooks/%s differs from the Rust tree", filepath.Base(f))
		}
	}
}
