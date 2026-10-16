package services

import (
	"strings"
	"testing"
)

func TestOnlyWhatTheCertificateAuthoritySaidIsMarked(t *testing.T) {
	// The classification the panel's 422 rests on: a CA refusal carries the
	// marker; a local disk fault does not.
	ca := SslCaDeclined + "The CA did not validate the challenge: timeout"
	if !strings.HasPrefix(ca, SslCaDeclined) {
		t.Fatal("CA refusal must carry the marker")
	}
	if strings.HasPrefix("Failed to write cert: No space left on device (os error 28)", SslCaDeclined) {
		t.Fatal("a local fault must not carry the marker")
	}
}

// Superset, never narrower: no name may lose a door by the swap.
func TestDumpDirNameNeverRefusesWhatTheSharedValidatorAccepts(t *testing.T) {
	for _, n := range []string{"wp_main", "db-legacy", "a", strings.Repeat("x", 64)} {
		if !DatabaseBackupIsDbDirName(n) {
			t.Errorf("%s must not lose a door", n)
		}
	}
	if !DatabaseBackupIsDbDirName("_wp") {
		t.Error("no rule about the first character")
	}
}

// Not "blocks traversal" — cannot express it.
func TestDumpDirNameCannotSpellATraversalAtAll(t *testing.T) {
	for _, n := range []string{".", "..", "../etc", "a/b", "a.b", "", strings.Repeat("x", 65)} {
		if DatabaseBackupIsDbDirName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestAPurgeTakesOnlyTheDumpsThisModuleMinted(t *testing.T) {
	for _, n := range []string{"wp-20260821-140302.sql.gz", "wp-20260821-140302.sql.gz.enc", "wp-20260821-140302.archive.gz"} {
		if !databaseBackupIsMintedDumpName("wp", n) {
			t.Errorf("%s is ours", n)
		}
	}
	// Hand-placed (every one passes the import door's test), another
	// database's, or an extension we do not write.
	for _, n := range []string{"dump.sql.gz", "wp.sql.gz", "wp-before-upgrade.sql.gz", "wp-2026.sql.gz",
		"other-20260821-140302.sql.gz", "wp-20260821-140302.tar"} {
		if databaseBackupIsMintedDumpName("wp", n) {
			t.Errorf("%s is not ours", n)
		}
	}
}

func TestPurgeRefusesANameItCannotValidate(t *testing.T) {
	for _, n := range []string{".", "..", "a/b"} {
		if _, err := DatabaseBackupPurgeDir(n); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestPurgeOfAnAbsentDirectoryIsAQuietSuccess(t *testing.T) {
	r, err := DatabaseBackupPurgeDir("nosuchdatabase_forpurgetest")
	if err != nil || r.Removed != 0 || r.DirRemoved {
		t.Fatalf("got %+v %v", r, err)
	}
}

func TestSafeDbIdentifierRejectsTraversal(t *testing.T) {
	for _, n := range []string{"..", "../etc", "a/../b", "foo/bar", "-leadingdash", ""} {
		if databaseBackupIsSafeDbIdentifier(n) {
			t.Errorf("%q accepted", n)
		}
	}
	for _, n := range []string{"wordpress", "my_db-01", "dockpanel-db-wordpress"} {
		if !databaseBackupIsSafeDbIdentifier(n) {
			t.Errorf("%q rejected", n)
		}
	}
}

func TestSafeFilenameRejectsTraversalAndBadExt(t *testing.T) {
	for _, n := range []string{"../evil.sql.gz", "a/b.sql.gz", "dump.txt"} {
		if databaseBackupIsSafeFilename(n) {
			t.Errorf("%q accepted", n)
		}
	}
	for _, n := range []string{"wordpress-20260722-120000.sql.gz", "db-20260722-120000.archive.gz.enc"} {
		if !databaseBackupIsSafeFilename(n) {
			t.Errorf("%q rejected", n)
		}
	}
}

// The listing offers exactly what the opener accepts.
func TestTheListingOffersExactlyWhatTheOpenerAccepts(t *testing.T) {
	for _, ok := range []string{"wordpress-20260722-120000.sql.gz", "wordpress-20260722-120000.archive.gz",
		"wordpress-20260722-120000.sql.gz.enc", "wordpress-20260722-120000.archive.gz.enc"} {
		if !databaseBackupIsSafeFilename(ok) {
			t.Errorf("%s must be openable", ok)
		}
	}
	for _, bad := range []string{"dump.sql", "dump.zip", "backup.tar.gz", "notes.txt", "dump"} {
		if databaseBackupIsSafeFilename(bad) {
			t.Errorf("%s must not be listed as a backup", bad)
		}
	}
}

// ⛔ `scp "my dump.sql.gz"` produces a right-extension name with a space.
func TestANameWithASpaceIsReportedRatherThanOffered(t *testing.T) {
	name := "my dump.sql.gz"
	if databaseBackupIsSafeFilename(name) {
		t.Fatal("a space must keep it out of the listing")
	}
	why := databaseBackupUnusableReason("wordpress", name)
	if !strings.Contains(why, "character") || !strings.Contains(why, "my_dump.sql.gz") {
		t.Fatalf("must name the problem and a pasteable fix: %s", why)
	}
	if !databaseBackupIsSafeFilename(databaseBackupSanitiseSuggestion(name)) {
		t.Fatal("the suggested name must itself be acceptable")
	}
}

func TestUnusableReasonNamesTheFileAndTheFix(t *testing.T) {
	plain := databaseBackupUnusableReason("wordpress", "dump.sql")
	if !strings.Contains(plain, "gzip") || !strings.Contains(plain, "/var/backups/dockpanel/databases/wordpress/dump.sql") {
		t.Errorf("plain: %s", plain)
	}
	if zip := databaseBackupUnusableReason("wordpress", "backup.zip"); !strings.Contains(zip, "unzip") {
		t.Errorf("zip: %s", zip)
	}
	archive := databaseBackupUnusableReason("wordpress", "cpanel-full.tar.gz")
	if !strings.Contains(archive, "Migration") || strings.Contains(archive, "gzip ") {
		t.Errorf("archive: %s", archive)
	}
	other := databaseBackupUnusableReason("wordpress", "notes.txt")
	if !strings.Contains(other, ".sql.gz") || strings.Contains(other, ".enc") {
		t.Errorf("other: %s", other)
	}
}
