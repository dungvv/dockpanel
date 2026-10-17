package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// unattended-host-scope §E4/E5: retention retires a backup row ONLY when its
// archive is actually gone from THIS host. Both refusals return before the
// DELETE, so a nil pool proves the row is never touched (reaching execSQL
// would panic).

// E5 — a backup living on another server cannot be retired by a local unlink:
// the row is kept and the local file of the same name is not touched.
func TestPinUnattendedHostScopePrunePolicyBackupRefusesOtherServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	row, local := uuid.New(), uuid.New()
	if autoHealerPrunePolicyBackup(context.Background(), nil, "database_backups", uuid.New(), path, &row, &local) {
		t.Fatal("a backup on another server was reported retired")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the local unlink ran for another server's backup: %v", err)
	}
}

// E4 — a failed unlink (anything but "already gone") keeps the row, which is
// the only record of where the archive is.
func TestPinUnattendedHostScopePrunePolicyBackupKeepsRowOnFailedUnlink(t *testing.T) {
	dir := t.TempDir()
	// A non-empty directory: os.Remove refuses it (ENOTEMPTY), even as root.
	if err := os.WriteFile(filepath.Join(dir, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	local := uuid.New()
	if autoHealerPrunePolicyBackup(context.Background(), nil, "volume_backups", uuid.New(), dir, &local, &local) {
		t.Fatal("the row was retired although the archive could not be removed")
	}
}

// Control for both tests above: with the archive removable and the row local,
// the call DOES reach the DELETE — and the nil pool panics there. Without this,
// a refusal that silently moved after the DELETE (whose error also returns
// false) would leave both tests green.
func TestPinUnattendedHostScopePrunePolicyBackupNilPoolReachesDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	local := uuid.New()
	defer func() {
		if recover() == nil {
			t.Fatal("the DELETE was not reached with a nil pool — the refusal tests above prove nothing")
		}
	}()
	autoHealerPrunePolicyBackup(context.Background(), nil, "database_backups", uuid.New(), path, &local, &local)
}
