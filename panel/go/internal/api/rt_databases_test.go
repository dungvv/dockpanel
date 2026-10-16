package api

import (
	"strings"
	"testing"
)

func TestRtDatabasesRemoteAccessNamesStayInTheStreamSlugAlphabet(t *testing.T) {
	for in, want := range map[string]string{"blog": "db-blog", "app_db": "db-app-db", "MY_DATA": "db-my-data"} {
		if got := rtDatabasesProxyNameForDb(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
	n := rtDatabasesProxyNameForDb(strings.Repeat("x", 60))
	if len(n) > 48 || strings.HasSuffix(n, "-") {
		t.Errorf("got %q", n)
	}
}

func TestRtDatabasesReservedDbNamesRejectedCaseInsensitive(t *testing.T) {
	for _, n := range []string{"postgres", "Postgres", "TEMPLATE1", "template0", "mysql", "information_schema", "performance_schema", "sys"} {
		if !rtDatabasesIsReservedDbName(n) {
			t.Errorf("%s should be reserved", n)
		}
	}
	for _, n := range []string{"blog", "app_db", "wordpress", "shop", "my_data"} {
		if rtDatabasesIsReservedDbName(n) {
			t.Errorf("%s should be allowed", n)
		}
	}
}
