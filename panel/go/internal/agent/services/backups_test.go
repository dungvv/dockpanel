package services

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func backupsModeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// The defect: a 0755 tree of 0644 dumps is readable by any uid — on a panel
// host that is www-data, which runs every tenant's PHP.
func TestAWorldReadableBackupTreeIsRepaired(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "db"), 0o755)
	os.WriteFile(filepath.Join(root, "dockpanel-db-x.sql.gz"), []byte("dump"), 0o644)
	os.WriteFile(filepath.Join(root, "db/nested.sql.gz"), []byte("dump"), 0o644)
	for p, m := range map[string]os.FileMode{
		root: 0o755, filepath.Join(root, "db"): 0o755,
		filepath.Join(root, "dockpanel-db-x.sql.gz"): 0o644, filepath.Join(root, "db/nested.sql.gz"): 0o644,
	} {
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
	}
	// The arm only means something if the tree really is exposed first.
	if backupsModeOf(t, filepath.Join(root, "dockpanel-db-x.sql.gz")) != 0o644 {
		t.Fatal("setup did not land")
	}
	backupsSecureTreeAt(root)
	for p, want := range map[string]os.FileMode{
		root: 0o700, filepath.Join(root, "db"): 0o700,
		filepath.Join(root, "dockpanel-db-x.sql.gz"): 0o600, filepath.Join(root, "db/nested.sql.gz"): 0o600,
	} {
		if got := backupsModeOf(t, p); got != want {
			t.Errorf("%s: mode %o, want %o", p, got, want)
		}
	}
}

// Never chmod THROUGH a symlink: a writer could aim a root chmod anywhere.
func TestSecureTreeDoesNotFollowASymlinkOutOfTheTree(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("not ours"), 0o644)
	os.Chmod(outside, 0o644)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	// Non-vacuity: the link resolves.
	if b, _ := os.ReadFile(filepath.Join(root, "link")); string(b) != "not ours" {
		t.Fatal("link does not resolve")
	}
	backupsSecureTreeAt(root)
	if got := backupsModeOf(t, outside); got != 0o644 {
		t.Fatalf("chmod followed a symlink out of the backup tree: %o", got)
	}
}

// backupsTestSite points the three roots at a temp dir and creates a site
// with one marker file.
func backupsTestSite(t *testing.T, tag string) (domain, root string) {
	t.Helper()
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar not available")
	}
	base := t.TempDir()
	oldW, oldB, oldS := backupsWebrootRoot, backupsRoot, backupsStagingRoot
	backupsWebrootRoot, backupsRoot, backupsStagingRoot = filepath.Join(base, "www"), filepath.Join(base, "backups"), filepath.Join(base, "backups/.staging")
	t.Cleanup(func() { backupsWebrootRoot, backupsRoot, backupsStagingRoot = oldW, oldB, oldS })
	domain = "dp-pin-" + tag + ".invalid"
	root = filepath.Join(backupsWebrootRoot, domain)
	os.MkdirAll(root, 0o755)
	os.WriteFile(filepath.Join(root, "index.html"), []byte("<h1>marker</h1>"), 0o644)
	return domain, root
}

func backupsMembers(t *testing.T, archive string) string {
	out, err := exec.Command("tar", "tzf", archive).Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func backupsSpec(name, typ string) BackupsDbSpec {
	// A container that does not exist: the dump fails without a live
	// database — what is under test is how the failure is REPORTED.
	return BackupsDbSpec{ContainerName: "dp-pin-absent-" + name, DbName: name, DbType: typ, User: "pinuser", Password: "pinpass"}
}

// handmadeArchive builds a v1 archive: site files plus a payload with the
// given manifest (and optionally a dump file).
func backupsHandmadeArchive(t *testing.T, domain, siteRoot, name string, manifest map[string]any, dump string) {
	t.Helper()
	stage := t.TempDir()
	os.MkdirAll(filepath.Join(stage, BackupsPayloadDir, "db"), 0o755)
	if dump != "" {
		os.WriteFile(filepath.Join(stage, BackupsPayloadDir, "db", dump), []byte("not-a-real-dump"), 0o644)
	}
	raw, _ := json.Marshal(manifest)
	os.WriteFile(filepath.Join(stage, BackupsPayloadDir, "manifest.json"), raw, 0o644)
	os.MkdirAll(backupsDir(domain), 0o700)
	cmd := exec.Command("tar", "czf", filepath.Join(backupsDir(domain), name), "-C", siteRoot, ".", "-C", stage, BackupsPayloadDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tar: %v %s", err, out)
	}
}

// A site with no databases must produce exactly the archive it always did.
func TestNoDatabasesProducesAFilesOnlyArchive(t *testing.T) {
	domain, _ := backupsTestSite(t, "nodb")
	info, err := BackupsCreateBackup(domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	listing := backupsMembers(t, filepath.Join(backupsDir(domain), info.Filename))
	if !strings.Contains(listing, "./index.html") {
		t.Errorf("site files must be in the archive: %s", listing)
	}
	if strings.Contains(listing, BackupsPayloadDir) {
		t.Errorf("no-database archive must carry no payload dir: %s", listing)
	}
	if len(info.DatabasesIncluded) != 0 || len(info.DatabasesFailed) != 0 {
		t.Error("files-only backup reported databases")
	}
	if info.Sha256 == nil || len(*info.Sha256) != 64 {
		t.Error("integrity hash missing")
	}
	// Omitted from the JSON for a files-only backup.
	raw, _ := json.Marshal(info)
	if strings.Contains(string(raw), "databases_") || strings.Contains(string(raw), "unsupported") {
		t.Errorf("empty fields must be omitted: %s", raw)
	}
}

// A database that cannot be dumped is REPORTED, never silently dropped.
func TestAFailedDumpIsReportedNotSwallowed(t *testing.T) {
	domain, _ := backupsTestSite(t, "faildump")
	info, err := BackupsCreateBackup(domain, []BackupsDbSpec{backupsSpec("pinmissing", "postgres")})
	if err != nil {
		t.Fatalf("backup still succeeds for the files: %v", err)
	}
	if len(info.DatabasesIncluded) != 0 {
		t.Error("a database that could not be dumped must not be listed as included")
	}
	if len(info.DatabasesFailed) != 1 || info.DatabasesFailed[0].DbName != "pinmissing" || info.DatabasesFailed[0].Error == "" {
		t.Fatalf("the failure must be reported with a reason: %+v", info.DatabasesFailed)
	}
}

// A site that already owns the reserved path is refused rather than shadowed.
func TestReservedPathCollisionRefusesThePayload(t *testing.T) {
	domain, root := backupsTestSite(t, "collide")
	os.MkdirAll(filepath.Join(root, BackupsPayloadDir), 0o755)
	info, err := BackupsCreateBackup(domain, []BackupsDbSpec{backupsSpec("pincollide", "postgres")})
	if err != nil {
		t.Fatal(err)
	}
	if len(info.DatabasesFailed) != 1 || !strings.Contains(info.DatabasesFailed[0].Error, "reserved") {
		t.Fatalf("the collision must be named: %+v", info.DatabasesFailed)
	}
}

// Restoring a pre-v2.34.0 archive still works and reports no database.
func TestRestoringAFilesOnlyArchiveStillWorks(t *testing.T) {
	domain, root := backupsTestSite(t, "oldarchive")
	info, err := BackupsCreateBackup(domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(root, "index.html"))
	report, err := BackupsRestoreBackup(domain, info.Filename, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !report.FilesRestored || report.DatabasesInArchive != 0 || !report.Ok() {
		t.Fatalf("report: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(root, "index.html")); err != nil {
		t.Error("the file marker must come back")
	}
	// Vec fields serialize as [] (never null).
	raw, _ := json.Marshal(report)
	if !strings.Contains(string(raw), `"databases_restored":[]`) || !strings.Contains(string(raw), `"databases_failed":[]`) {
		t.Errorf("empty vecs must be []: %s", raw)
	}
}

// The payload never lands in the document root, and a database that cannot
// be restored makes the restore a failure.
func TestPayloadNeverLandsInTheWebrootAndAMissingTargetFails(t *testing.T) {
	domain, root := backupsTestSite(t, "payload")
	backupsHandmadeArchive(t, domain, root, "handmade-20260726-000000.tar.gz", map[string]any{
		"schema": 1, "domain": domain, "created_at": "2026-07-26T00:00:00Z",
		"databases": []any{map[string]any{"db_name": "pinwp", "db_type": "postgres", "file": "pinwp.sql.gz", "size_bytes": 15}},
	}, "pinwp.sql.gz")
	report, err := BackupsRestoreBackup(domain, "handmade-20260726-000000.tar.gz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !report.FilesRestored || report.DatabasesInArchive != 1 || len(report.DatabasesFailed) != 1 || report.Ok() {
		t.Fatalf("report: %+v", report)
	}
	if _, err := os.Lstat(filepath.Join(root, BackupsPayloadDir)); err == nil {
		t.Fatal("database dumps must never be extracted into the document root")
	}
}

// The single-file restore must refuse the database payload explicitly.
func TestSingleFileRestoreRefusesTheDatabasePayload(t *testing.T) {
	domain, _ := backupsTestSite(t, "singlefile")
	info, err := BackupsCreateBackup(domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []string{".dockpanel-backup/db/x.sql.gz", "./.dockpanel-backup/db/x.sql.gz", ".dockpanel-backup"} {
		err := BackupsRestoreSingleFile(domain, info.Filename, attempt)
		if err == nil || !strings.Contains(err.Error(), "database dumps") {
			t.Errorf("must refuse %q with a reason, got %v", attempt, err)
		}
	}
	if err := BackupsRestoreSingleFile(domain, info.Filename, "index.html"); err != nil {
		t.Fatalf("a normal file still restores: %v", err)
	}
}

// manifest.json's `file` is attacker-controlled; an absolute path must be
// refused before it is ever touched.
func TestRestoreRefusesAManifestDumpFileThatEscapesDbDir(t *testing.T) {
	domain, root := backupsTestSite(t, "unsafedumpfile")
	backupsHandmadeArchive(t, domain, root, "handmade-unsafefile.tar.gz", map[string]any{
		"schema": 1, "domain": domain, "created_at": "2026-07-26T00:00:00Z",
		"databases": []any{map[string]any{"db_name": "pinunsafe", "db_type": "postgres", "file": "/etc/passwd", "size_bytes": 15}},
	}, "")
	report, err := BackupsRestoreBackup(domain, "handmade-unsafefile.tar.gz", []BackupsDbSpec{backupsSpec("pinunsafe", "postgres")})
	if err != nil {
		t.Fatal(err)
	}
	if !report.FilesRestored || len(report.DatabasesFailed) != 1 || !strings.Contains(report.DatabasesFailed[0].Error, "unsafe") {
		t.Fatalf("the unsafe path must be refused: %+v", report)
	}
}

// The payload member can itself be a symlink; extraction must refuse it.
func TestExtractPayloadRefusesWhenThePayloadMemberIsASymlink(t *testing.T) {
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar not available")
	}
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "manifest.json"), []byte("{}"), 0o644)
	src := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(src, BackupsPayloadDir)); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "p.tar.gz")
	if out, err := exec.Command("tar", "czf", archive, "-C", src, BackupsPayloadDir).CombinedOutput(); err != nil {
		t.Fatalf("tar: %v %s", err, out)
	}
	_, err := backupsExtractPayload(archive, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("must refuse a symlinked payload member, got %v", err)
	}
}

func TestReportOkRequiresBothHalves(t *testing.T) {
	r := BackupsRestoreReport{FilesRestored: true}
	if !r.Ok() {
		t.Fatal("files only, no failures: ok")
	}
	r.DatabasesFailed = append(r.DatabasesFailed, BackupsDbFailure{DbName: "x", Error: "boom"})
	if r.Ok() {
		t.Fatal("files restored + database failed is a FAILURE")
	}
	if (&BackupsRestoreReport{}).Ok() {
		t.Fatal("nothing restored is not ok")
	}
}
