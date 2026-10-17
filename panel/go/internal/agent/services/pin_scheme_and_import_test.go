package services

// Behaviour arms retired from tests/scheme-and-import-pin-e2e.sh §B: the
// migration parsers must emit inventory paths the importer can join onto the
// archive root (relative, never containing the root, databases carrying their
// directory), and the importer and put_site must agree on the document root.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pinSchemeTouch(t *testing.T, root string, rel ...string) {
	t.Helper()
	for _, r := range rel {
		p := filepath.Join(root, r)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPinSchemeAndImportParsersEmitArchiveRelativePaths(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		files []string
		parse func(context.Context, string, string) (MigrationInventory, error)
	}{
		{"cpanel", []string{"homedir/public_html/index.php", "mysql/shop.sql"}, migrationParseCpanel},
		{"plesk", []string{"domains/a.com/httpdocs/index.html", "databases/shop.sql"}, migrationParsePlesk},
		{"hestiacp", []string{"web/b.com/public_html/index.html", "db/shop.sql.gz"}, migrationParseHestiacp},
	}
	for _, c := range cases {
		root := t.TempDir()
		pinSchemeTouch(t, root, c.files...)
		inv, err := c.parse(ctx, "id", root)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(inv.Sites) == 0 || len(inv.Databases) == 0 {
			t.Fatalf("%s: parsed nothing: %+v", c.name, inv)
		}
		for _, s := range inv.Sites {
			// The importer rejects an absolute path as traversal, and joins
			// the rest onto the root — so the root must not already be in it.
			if strings.HasPrefix(s.DocRoot, "/") || strings.Contains(s.DocRoot, root) {
				t.Errorf("%s: doc_root %q is not archive-relative", c.name, s.DocRoot)
			}
			if fi, err := os.Stat(filepath.Join(root, s.DocRoot)); err != nil || !fi.IsDir() {
				t.Errorf("%s: doc_root %q does not resolve under the archive root", c.name, s.DocRoot)
			}
		}
		for _, d := range inv.Databases {
			// A bare filename resolves one level above where it was found.
			if !strings.Contains(d.File, "/") || strings.HasPrefix(d.File, "/") {
				t.Errorf("%s: database file %q carries no archive-relative directory", c.name, d.File)
			}
			if _, err := os.Stat(filepath.Join(root, d.File)); err != nil {
				t.Errorf("%s: database file %q does not resolve under the archive root", c.name, d.File)
			}
		}
	}
}

func TestPinSchemeAndImportDocumentRootFollowsTheRuntime(t *testing.T) {
	for rt, want := range map[string]string{
		"proxy": "/var/www/a.com", "node": "/var/www/a.com", "python": "/var/www/a.com",
		"php": "/var/www/a.com/public", "static": "/var/www/a.com/public",
	} {
		if got := NginxDocumentRootFor("/var/www/a.com", rt); got != want {
			t.Errorf("%s: got %s want %s", rt, got, want)
		}
	}
}
