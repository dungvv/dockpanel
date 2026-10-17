package api

import (
	"strings"
	"testing"
)

// db-schema-browser-pin-e2e.sh C1–C3: ONE validator guards the interpolated
// schema/index statements, and it is the strict one — exactly [A-Za-z0-9_].
func TestPinDbSchemaBrowserTableNameValidatorIsStrict(t *testing.T) {
	for _, ok := range []string{"users", "wp_posts", "T2", "a_b_9"} {
		if !rtDatabasesIsSafeTableName(ok) {
			t.Errorf("%q must be accepted", ok)
		}
	}
	for _, bad := range []string{"", "a-b", "a b", "a'b", "a;b", "a.b", "tablé", "a`b", strings.Repeat("a", 129)} {
		if rtDatabasesIsSafeTableName(bad) {
			t.Errorf("%q must be refused (it is interpolated into SQL)", bad)
		}
	}
}
