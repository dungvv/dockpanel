package routes

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// rename-carries-backups §A: exactly two domain-keyed trees, each named once
// with an old and a new path. A third tree must arrive with its test.
func TestPinRenameCarriesBackupsTreesAreTheArchiveRootAndWpSnapshots(t *testing.T) {
	got := nginxDomainBackupTrees("old.test", "new.test")
	want := [][2]string{
		{"/var/backups/dockpanel/old.test", "/var/backups/dockpanel/new.test"},
		{"/var/backups/dockpanel/wp-snapshots/old.test", "/var/backups/dockpanel/wp-snapshots/new.test"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("trees = %v", got)
	}
}

// §C5/C6: only NotFound counts as free; doubt (unreadable / not a directory)
// counts as occupied.
func TestPinRenameCarriesBackupsOnlyNotFoundIsFree(t *testing.T) {
	d := t.TempDir()
	if nginxDirIsOccupied(filepath.Join(d, "absent")) {
		t.Error("a missing directory must read as free")
	}
	empty := filepath.Join(d, "empty")
	_ = os.Mkdir(empty, 0o755)
	if nginxDirIsOccupied(empty) {
		t.Error("an empty directory must read as free")
	}
	full := filepath.Join(d, "full")
	_ = os.Mkdir(full, 0o755)
	_ = os.WriteFile(filepath.Join(full, "a.tar.gz"), nil, 0o600)
	if !nginxDirIsOccupied(full) {
		t.Error("a directory holding a file must read as occupied")
	}
	notDir := filepath.Join(d, "file")
	_ = os.WriteFile(notDir, []byte("x"), 0o600)
	if !nginxDirIsOccupied(notDir) {
		t.Error("something that cannot be listed must count as occupied (doubt keeps files apart)")
	}
}

// §D2: the undo puts trees back most-recent-first. Two chained moves a→b→c
// only unwind to a in reverse order.
func TestPinRenameCarriesBackupsUndoIsMostRecentFirst(t *testing.T) {
	d := t.TempDir()
	a, b, c := filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")
	_ = os.Mkdir(a, 0o755)
	if err := os.Rename(a, b); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(b, c); err != nil {
		t.Fatal(err)
	}
	nginxUndoBackupCarry([][2]string{{a, b}, {b, c}}, "old.test")
	if !nginxExists(a) || nginxExists(b) || nginxExists(c) {
		t.Fatalf("undo did not unwind to the original tree (a=%v b=%v c=%v)", nginxExists(a), nginxExists(b), nginxExists(c))
	}
}
