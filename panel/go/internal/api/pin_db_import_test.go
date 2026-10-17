package api

import (
	"strings"
	"testing"
)

// db-import-pin-e2e.sh B4c/B4e/B4f/E4b: the panel's importability rule is a
// pure function, refuses encrypted panel backups (naming Backup Manager, the
// door that CAN restore them) and refuses a MongoDB archive for a SQL engine.
func TestPinDbImportBlockedReason(t *testing.T) {
	enc := rtDatabasesImportBlockedReason("wp-20260722-120000.sql.gz.enc", "mysql")
	if enc == "" || !strings.Contains(enc, "Backup Manager") {
		t.Errorf(".enc must be refused and point at Backup Manager: %q", enc)
	}
	for _, eng := range []string{"mysql", "mariadb", "postgres"} {
		if rtDatabasesImportBlockedReason("wp-20260722-120000.archive.gz", eng) == "" {
			t.Errorf("a MongoDB archive must be refused for %s", eng)
		}
		if r := rtDatabasesImportBlockedReason("wp-20260722-120000.sql.gz", eng); r != "" {
			t.Errorf(".sql.gz must import into %s: %q", eng, r)
		}
	}
	if r := rtDatabasesImportBlockedReason("wp-20260722-120000.archive.gz", "mongo"); r != "" {
		t.Errorf("a MongoDB archive must import into mongo: %q", r)
	}
	if rtDatabasesImportBlockedReason("wp-20260722-120000.sql.gz", "mongodb") == "" {
		t.Error("a SQL dump must be refused for MongoDB")
	}
}
