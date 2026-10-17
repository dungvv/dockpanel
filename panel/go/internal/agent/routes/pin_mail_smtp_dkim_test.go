package routes

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// tests/mail-smtp-dkim-pin-e2e.sh §B: both DKIM tables are derived from the
// keys on disk, so no caller can let them drift from what was published.
func TestPinMailSmtpDkimTablesAreDerivedFromTheKeysOnDisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "example.com"), 0o755); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "example.com", "default.private")
	for _, f := range []string{key, filepath.Join(dir, "example.com", "default.txt")} {
		if err := os.WriteFile(f, []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keyLines, signLines, err := mailDkimTableLines(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"default._domainkey.example.com example.com:default:" + key}; !slices.Equal(keyLines, want) {
		t.Errorf("key.table = %q, want %q", keyLines, want)
	}
	// Every address of the domain signs with its key.
	if want := []string{"*@example.com default._domainkey.example.com"}; !slices.Equal(signLines, want) {
		t.Errorf("signing.table = %q, want %q", signLines, want)
	}
}

// §C: a listener the firewall drops is not an install.
func TestPinMailSmtpDkimMailPortsCoverEveryListener(t *testing.T) {
	for _, p := range []string{"25", "587", "993", "143"} {
		if !slices.Contains(mailPorts, p) {
			t.Errorf("port %s missing from mailPorts %v", p, mailPorts)
		}
	}
}
