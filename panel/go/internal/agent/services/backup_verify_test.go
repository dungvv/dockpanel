package services

import (
	"strings"
	"testing"
)

func backupVerifyChk(name string, passed bool) BackupVerifyVerificationCheck {
	return BackupVerifyVerificationCheck{Name: name, Passed: passed}
}

// extract_success + file_count are CRITICAL, has_entry_point informational.
// The old `checks_passed >= checks_run - 1` slack passed a corrupt archive.
func TestSiteBackupVerdict(t *testing.T) {
	cases := []struct {
		name   string
		checks []BackupVerifyVerificationCheck
		want   bool
	}{
		{"fails when extract fails", []BackupVerifyVerificationCheck{backupVerifyChk("file_exists", true), backupVerifyChk("extract_success", false)}, false},
		{"fails on empty archive", []BackupVerifyVerificationCheck{backupVerifyChk("file_exists", true), backupVerifyChk("extract_success", true), backupVerifyChk("file_count", false), backupVerifyChk("has_entry_point", false)}, false},
		{"passes when only entry point missing", []BackupVerifyVerificationCheck{backupVerifyChk("file_exists", true), backupVerifyChk("extract_success", true), backupVerifyChk("file_count", true), backupVerifyChk("has_entry_point", false)}, true},
		{"passes all critical", []BackupVerifyVerificationCheck{backupVerifyChk("file_exists", true), backupVerifyChk("extract_success", true), backupVerifyChk("file_count", true), backupVerifyChk("has_entry_point", true)}, true},
	}
	for _, c := range cases {
		if got := backupVerifySiteBackupPassed(c.checks); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

// The verify/drill names are interpolated into a path: no separator.
func TestVerifyNamesRefuseSeparators(t *testing.T) {
	for _, n := range []string{"", "a/b", "/etc", strings.Repeat("x", 129)} {
		if backupVerifyIsValidName(n) {
			t.Errorf("%q accepted", n)
		}
	}
	if !backupVerifyIsValidName("wp-20260101-000000.sql.gz") {
		t.Error("a minted dump name refused")
	}
}
