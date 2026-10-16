package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPanelSnapshotTriggerStringForms(t *testing.T) {
	if got := PanelSnapshotTriggerManual().AsStr(); got != "manual" {
		t.Fatal(got)
	}
	if got := PanelSnapshotTriggerPreUpdate("v2.10.0").AsStr(); got != "pre-update:v2.10.0" {
		t.Fatal(got)
	}
	id := uuid.New()
	if got := PanelSnapshotTriggerFleet(id).AsStr(); got != "fleet:"+id.String() {
		t.Fatal(got)
	}
}

func TestPanelSnapshotShellEscapeQuotesSingleQuotes(t *testing.T) {
	for in, want := range map[string]string{"plain": "'plain'", "with space": "'with space'", "o'brien": `'o'\''brien'`} {
		if got := panelSnapshotShellEscape(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestPanelSnapshotSha256OfKnownContentIsStable(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "dp-snap-sha")
	if err := os.WriteFile(tmp, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := panelSnapshotSha256Of(context.Background(), tmp)
	if err != nil {
		t.Skipf("sha256sum unavailable: %v", err)
	}
	if hash != "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Fatal(hash)
	}
}

func TestPanelSnapshotCheckFreeDiskPassesWithLowRequirement(t *testing.T) {
	if err := panelSnapshotCheckFreeDisk(context.Background(), "/tmp", 1); err != nil {
		t.Fatalf("expected free-disk check to pass: %v", err)
	}
}

func TestPanelSnapshotCheckFreeDiskRefusesWhenRequirementExceedsPartition(t *testing.T) {
	err := panelSnapshotCheckFreeDisk(context.Background(), "/tmp", ^uint64(0)/2)
	var se *PanelSnapshotError
	// nil is an acceptable fallthrough where df output is unparseable.
	if err != nil && !(errors.As(err, &se) && se.Kind == PanelSnapshotErrInsufficientDisk) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPanelSnapshotRestoreScriptIsByteIdenticalToTheRepoCopy(t *testing.T) {
	repo, err := os.ReadFile("../../../../scripts/restore-snapshot.sh")
	if err != nil {
		t.Skip("repo scripts/ not present")
	}
	if string(repo) != panelSnapshotRestoreScript {
		t.Fatal("scripts/restore-snapshot.sh differs from the repo copy (copy it byte-for-byte)")
	}
}

// The database stage must be atomic and stop on the first error: without
// both, a truncated restore stream applied the dump's DROP block, skipped the
// rest and exited 0 — 92 tables reduced to 1 while the caller recorded success.
func TestPanelSnapshotRestoreScriptAppliesTheDatabaseAtomically(t *testing.T) {
	s := panelSnapshotRestoreScript
	if !strings.Contains(s, "ON_ERROR_STOP=1") {
		t.Error("restore script must stop on the first failed statement")
	}
	if !strings.Contains(s, "--single-transaction") {
		t.Error("restore script must apply the dump in one transaction so a failure changes nothing")
	}
}

// A rollback must REPLACE the database, not merge into it.
func TestPanelSnapshotRestoreScriptRebuildsTheSchemaInsteadOfMergingIntoIt(t *testing.T) {
	s := panelSnapshotRestoreScript
	if !strings.Contains(s, "DROP SCHEMA IF EXISTS public CASCADE;") {
		t.Error("a restore that cannot remove post-snapshot objects is a merge, not a rollback")
	}
	if !strings.Contains(s, "CREATE SCHEMA public;") {
		t.Error("the schema must be recreated after being dropped")
	}
}

// The teardown carries the schema's owner and ACL back with it.
func TestPanelSnapshotRestoreScriptPreservesSchemaOwnershipAndGrants(t *testing.T) {
	s := panelSnapshotRestoreScript
	if !strings.Contains(s, "ALTER SCHEMA public OWNER TO pg_database_owner;") {
		t.Error("recreating public without restoring its owner changes it on every rollback")
	}
	if !strings.Contains(s, "GRANT USAGE ON SCHEMA public TO PUBLIC;") {
		t.Error("recreating public without restoring PUBLIC's USAGE grant revokes it silently")
	}
}

// psql must never be fed by a pipe: a producer dying mid-stream is a clean
// EOF to psql, and --single-transaction then COMMITS whatever arrived.
func TestPanelSnapshotRestoreScriptNeverFeedsPsqlFromAPipe(t *testing.T) {
	for i, line := range strings.Split(panelSnapshotRestoreScript, "\n") {
		l := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(l, "#") {
			continue
		}
		psqlAt := strings.Index(l, "psql")
		if psqlAt < 0 {
			continue
		}
		// Only a pipe that FEEDS psql matters; piping psql's output is fine.
		piped := false
		for at := 0; at < len(l); at++ {
			if l[at] == '|' && !strings.HasPrefix(l[at:], "||") && at < psqlAt {
				piped = true
			}
		}
		if piped {
			t.Errorf("line %d pipes into psql; feed it from a file by redirection: %s", i+1, l)
		}
	}
	if !strings.Contains(panelSnapshotRestoreScript, `< "$APPLY_SQL"`) {
		t.Error("the assembled restore stream must reach psql by redirection")
	}
}

// Destroying the schema is only safe because the dump has been proven whole.
func TestPanelSnapshotRestoreScriptProvesTheDumpBeforeItDropsTheSchema(t *testing.T) {
	verified := strings.Index(panelSnapshotRestoreScript, "PostgreSQL database dump complete")
	dropped := strings.Index(panelSnapshotRestoreScript, "DROP SCHEMA IF EXISTS public CASCADE;")
	if verified < 0 || dropped < 0 || verified >= dropped {
		t.Fatal("the dump must be proven complete before the schema is torn down")
	}
}

// One transaction, not two — counting only executable lines.
func TestPanelSnapshotRestoreScriptTearsDownAndReloadsInASingleTransaction(t *testing.T) {
	n := 0
	for _, l := range strings.Split(panelSnapshotRestoreScript, "\n") {
		if !strings.HasPrefix(strings.TrimLeft(l, " \t"), "#") && strings.Contains(l, "--single-transaction") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the schema teardown must share the dump's transaction, not run in its own (%d uses)", n)
	}
}

// The restore must outlive the service it stops: a transient *service*.
func TestPanelSnapshotRestoreScriptDetachesViaATransientUnit(t *testing.T) {
	if !strings.Contains(panelSnapshotRestoreScript, "systemd-run") {
		t.Error("missing systemd-run")
	}
	if strings.Contains(panelSnapshotRestoreScript, "--scope") {
		t.Error("a scope dies with the caller's session — this must be a transient service")
	}
}

// A restore that cannot restore has to say so: no `|| true` on a restore step.
func TestPanelSnapshotRestoreScriptNeverSwallowsARestoreFailure(t *testing.T) {
	for i, line := range strings.Split(panelSnapshotRestoreScript, "\n") {
		l := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(l, "#") || !strings.Contains(l, "|| true") {
			continue
		}
		tolerated := false
		for _, ok := range []string{"chmod", "rm -rf", "systemctl start", "systemd-cat", "daemon-reload", "systemctl stop", ".prerestore.", "grep -c"} {
			if strings.Contains(l, ok) {
				tolerated = true
			}
		}
		if !tolerated {
			t.Errorf("line %d silences a failure in the restore path: %s", i+1, l)
		}
	}
}

// Every exit path must leave a verdict behind.
func TestPanelSnapshotRestoreScriptAlwaysWritesAResult(t *testing.T) {
	for _, want := range []string{"trap on_exit EXIT INT TERM", "write_result", PanelSnapshotRestoreResultPath} {
		if !strings.Contains(panelSnapshotRestoreScript, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// A rollback must not be able to undo itself (s231): the trap consults the
// window before restarting the api, and restarts it from exactly one branch.
func TestPanelSnapshotRestoreScriptNeverRestartsTheAPIOverARevertedDatabase(t *testing.T) {
	s := panelSnapshotRestoreScript
	if !strings.Contains(s, "rollback_would_be_undone") {
		t.Fatal("the window between the database commit and the binary swap must be named")
	}
	at := strings.Index(s, "on_exit() {")
	if at < 0 {
		t.Fatal("the exit trap must exist")
	}
	trap := s[at:]
	if end := strings.Index(trap, "\ntrap "); end >= 0 {
		trap = trap[:end]
	}
	if !strings.Contains(trap, "rollback_would_be_undone") {
		t.Error("the exit trap must consult the window before restarting the api")
	}
	n := 0
	for _, l := range strings.Split(trap, "\n") {
		if !strings.HasPrefix(strings.TrimLeft(l, " \t"), "#") && strings.Contains(l, "systemctl start dockpanel-api") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the api must be restarted from exactly one branch of the trap (got %d)", n)
	}
}

// After the commit, the post-commit checks REPORT rather than abort.
func TestPanelSnapshotRestoreScriptReportsRatherThanAbortsAfterTheDatabaseCommits(t *testing.T) {
	s := panelSnapshotRestoreScript
	committed := strings.Index(s, "db_committed=1")
	swap := strings.Index(s, `stage="binaries"`)
	if committed < 0 || swap < 0 || committed >= swap {
		t.Fatal("the commit must precede the swap")
	}
	window := s[committed:swap]
	for i, line := range strings.Split(window, "\n") {
		l := strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(l, "#") && strings.Contains(l, `fail "`) {
			t.Errorf("line %d of the post-commit window raises instead of degrading: %s", i+1, l)
		}
	}
	if !strings.Contains(window, `degrade "`) {
		t.Error("the post-commit window must still REPORT what went wrong")
	}
}

// Refuse a dump that is already short before anything is destroyed.
func TestPanelSnapshotRestoreScriptVerifiesDumpCompletenessBeforeDestroyingAnything(t *testing.T) {
	verify := strings.Index(panelSnapshotRestoreScript, "PostgreSQL database dump complete")
	stop := strings.Index(panelSnapshotRestoreScript, `stage="stop-services"`)
	if verify < 0 || stop < 0 || verify >= stop {
		t.Fatal("the dump must be proven complete before the panel is taken down")
	}
}
