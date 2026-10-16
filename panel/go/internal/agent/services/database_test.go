package services

import (
	"strings"
	"testing"
)

func TestTenantRoleSqlIsNonSuperuser(t *testing.T) {
	sql := databaseTenantRoleSQL("blog_db", "secret")
	for _, want := range []string{"NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", `CREATE ROLE "blog_db"`} {
		if !strings.Contains(sql[0], want) {
			t.Errorf("missing %s: %s", want, sql[0])
		}
	}
	// The space-prefixed token excludes NOSUPERUSER.
	if strings.Contains(sql[0], " SUPERUSER") {
		t.Error("grants superuser")
	}
	if !strings.Contains(sql[1], `ALTER DATABASE "blog_db" OWNER TO "blog_db"`) || !strings.Contains(sql[2], `ALTER SCHEMA public OWNER TO "blog_db"`) {
		t.Error(sql)
	}
}

func TestTenantRoleSqlEscapesPasswordQuote(t *testing.T) {
	if sql := databaseTenantRoleSQL("app", "a'b"); !strings.Contains(sql[0], "PASSWORD 'a''b'") {
		t.Error(sql[0])
	}
}

func TestStringEscapesDifferPerEngine(t *testing.T) {
	if got := databaseMysqlStringEscape(`a\'b`); got != `a\\''b` {
		t.Error(got)
	}
	if got := databasePgStringEscape(`a\'b`); got != `a\''b` {
		t.Error(got)
	}
}

func TestParseCsvAndTsv(t *testing.T) {
	cols, rows := databaseParseCsv("id,name\n1,\"a, \"\"b\"\"\nc\"\n")
	if len(cols) != 2 || len(rows) != 1 || rows[0][1] != "a, \"b\"\nc" {
		t.Fatalf("%v %q", cols, rows)
	}
	if cols, rows := databaseParseCsv("INSERT 0 1\n"); len(cols) != 0 || len(rows) != 0 {
		t.Fatal("command tag treated as data")
	}
	cols, rows = databaseParseTsv("a\tb\n1\t2\n\n")
	if len(cols) != 2 || len(rows) != 1 {
		t.Fatalf("%v %v", cols, rows)
	}
}

// The real-Docker reconcile test (creates disposable containers + network)
// is not ported as a unit test: it needs a Docker daemon. Covered by the
// Rust #[ignore]d test's e2e equivalent.
