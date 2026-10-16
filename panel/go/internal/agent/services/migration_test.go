package services

import "testing"

// Paths travel to the importer relative to the archive root; anything not
// inside it (or the root itself) is nil, never an absolute path.
func TestMigrationRelativeTo(t *testing.T) {
	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	for _, c := range [][3]string{
		{"/x/root/domains/a.com/httpdocs", "/x/root", "domains/a.com/httpdocs"},
		{"/x/root", "/x/root", "<nil>"},
		{"/x/rootling/a", "/x/root", "<nil>"},
		{"/y/a", "/x/root", "<nil>"},
	} {
		if got := str(migrationRelativeTo(c[0], c[1])); got != c[2] {
			t.Errorf("%s rel %s: got %s want %s", c[0], c[1], got, c[2])
		}
	}
}

func TestMigrationIDAndSQLName(t *testing.T) {
	if migrationIsValidID("../x") || migrationIsValidID("") || !migrationIsValidID("0f8e-AB") {
		t.Fatal("migration id validation")
	}
	if n, ok := migrationSQLName("shop.sql.gz"); !ok || n != "shop" {
		t.Fatalf("got %q %v", n, ok)
	}
	if _, ok := migrationSQLName("readme.txt"); ok {
		t.Fatal("non-sql accepted")
	}
}

func TestStagingValidateDomain(t *testing.T) {
	for _, d := range []string{"", "../x", "a/b", "a\\b", "a b", "a;b"} {
		if stagingValidateDomain(d) == nil {
			t.Errorf("%q must be rejected", d)
		}
	}
	if stagingValidateDomain("staging.example.com") != nil {
		t.Error("a real domain must pass")
	}
}
