package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// cli-io-crate-audit §C: backup health must count only site-backup domain
// dirs under the backup root, never the agent's own subsystem roots, ops
// dumps in db/, or dot-staging dirs (once inflated counts ~9x / ~50000x).
func TestPinCliIoCrateAuditSiteBackupDirs(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"example.com", "databases", "volumes", "wp-snapshots", "snapshots", "db", ".staging"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d, "f"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, reserved := range []string{"databases", "volumes", "wp-snapshots", "snapshots", "db", ".staging"} {
		if isSiteBackupDir(reserved) {
			t.Errorf("isSiteBackupDir(%q) = true, want false", reserved)
		}
	}
	if !isSiteBackupDir("example.com") {
		t.Error(`isSiteBackupDir("example.com") = false, want true`)
	}
	if n, _ := countFiles(root, true); n != 1 {
		t.Errorf("countFiles(root, onlySiteDirs=true) = %d, want 1", n)
	}
	if n := countDirs(root, true); n != 1 {
		t.Errorf("countDirs(root, onlySiteDirs=true) = %d, want 1", n)
	}
	// Control: unscoped counting still sees everything (databases/volumes
	// roots are counted unscoped and must stay so).
	if n, _ := countFiles(root, false); n != 7 {
		t.Errorf("countFiles(root, onlySiteDirs=false) = %d, want 7", n)
	}
}
