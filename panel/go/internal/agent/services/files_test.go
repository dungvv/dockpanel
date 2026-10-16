package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func filesTmpBase(t *testing.T) string {
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The sandbox-escape primitive: a DANGLING symlink leaf must be rejected, or
// create/upload would write THROUGH it as root.
func TestRejectsDanglingSymlinkLeaf(t *testing.T) {
	base := filesTmpBase(t)
	os.Symlink("/nonexistent-dp-escape-target-xyz", filepath.Join(base, "evil"))
	if r, err := filesResolveWithin(base, "evil"); err == nil {
		t.Fatalf("dangling symlink leaf must be rejected, got %s", r)
	}
	os.Symlink("/etc/cron.d/dp-pwn-xyz", filepath.Join(base, "evil2"))
	if _, err := filesResolveWithin(base, "evil2"); err == nil {
		t.Fatal("cron.d vector accepted")
	}
	os.MkdirAll(filepath.Join(base, "pub"), 0o755)
	os.Symlink("/etc/dp-passwd-xyz", filepath.Join(base, "pub/link"))
	if _, err := filesResolveWithin(base, "pub/link"); err == nil {
		t.Fatal("nested dangling link accepted")
	}
}

func TestRejectsLiveSymlinkEscapingRoot(t *testing.T) {
	base := filesTmpBase(t)
	os.Symlink("/etc", filepath.Join(base, "etclink"))
	for _, p := range []string{"etclink", "etclink/passwd"} {
		if _, err := filesResolveWithin(base, p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}

func TestRejectsDotdotTraversal(t *testing.T) {
	base := filesTmpBase(t)
	for _, p := range []string{"../../etc/passwd", "a/../../../etc/passwd", "..", "x/..", "nope/../../.."} {
		if r, err := filesResolveWithin(base, p); err == nil {
			t.Errorf("%s accepted as %s", p, r)
		}
	}
}

func TestRejectsNul(t *testing.T) {
	base := filesTmpBase(t)
	if _, err := filesResolveWithin(base, "a\x00b"); err == nil {
		t.Fatal("NUL accepted")
	}
}

func TestAllowsNewFiles(t *testing.T) {
	base := filesTmpBase(t)
	if r, err := filesResolveWithin(base, "newfile.txt"); err != nil || !strings.HasPrefix(r, base) {
		t.Fatal(r, err)
	}
	os.MkdirAll(filepath.Join(base, "wp-content"), 0o755)
	r, err := filesResolveWithin(base, "wp-content/x.php")
	if err != nil || !strings.HasPrefix(r, base) || !strings.HasSuffix(r, "wp-content/x.php") {
		t.Fatal(r, err)
	}
	if r, err := filesResolveWithin(base, "/"); err != nil || r != base {
		t.Fatal("root listing must resolve to the base", r, err)
	}
}

// A legit in-root symlink dir (current -> releases/v1) must still allow creates.
func TestAllowsCreateThroughInRootSymlinkDir(t *testing.T) {
	base := filesTmpBase(t)
	os.MkdirAll(filepath.Join(base, "releases/v1"), 0o755)
	os.Symlink(filepath.Join(base, "releases/v1"), filepath.Join(base, "current"))
	if r, err := filesResolveWithin(base, "current/new.txt"); err != nil || !strings.HasPrefix(r, base) {
		t.Fatal(r, err)
	}
}

func TestWriteFileHandlesLongBasename(t *testing.T) {
	base := filesTmpBase(t)
	target := filepath.Join(base, strings.Repeat("a", 230))
	if err := FilesWriteFile(target, "hello"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "hello" {
		t.Fatal(string(b))
	}
}

func TestListDirectoryIsRelativeAndDirsFirst(t *testing.T) {
	base := filesTmpBase(t)
	os.WriteFile(filepath.Join(base, "a.txt"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(base, "z/inner"), 0o755)
	got, err := FilesListDirectory(base, base)
	if err != nil || len(got) != 2 || got[0].Name != "z" || !got[0].IsDir || got[1].Path != "a.txt" {
		t.Fatalf("%+v %v", got, err)
	}
	sub, _ := FilesListDirectory(filepath.Join(base, "z"), base)
	if len(sub) != 1 || sub[0].Path != "z/inner" {
		t.Fatalf("%+v", sub)
	}
}
