package api

import "testing"

func TestBackupSchedulerFieldMatches(t *testing.T) {
	cases := []struct {
		field string
		v     uint32
		want  bool
	}{
		{"*", 0, true}, {"*", 59, true},
		{"5", 5, true}, {"5", 6, false},
		{"*/5", 0, true}, {"*/5", 15, true}, {"*/5", 13, false},
		{"1,5,10", 5, true}, {"1,5,10", 6, false},
		{"1-5", 3, true}, {"1-5", 6, false},
	}
	for _, c := range cases {
		if got := backupSchedulerFieldMatches(c.field, c.v); got != c.want {
			t.Errorf("fieldMatches(%q, %d) = %v", c.field, c.v, got)
		}
	}
}
