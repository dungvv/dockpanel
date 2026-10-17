package services

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// volume-backup-scope-leak §B/§C: the restore script must refuse a corrupt
// archive AND an empty-but-valid one before it wipes the volume, and still
// restore a real one. Run for real with sh+tar against scratch dirs standing
// in for the container's /backup and /volume mounts.
func TestPinVolumeBackupScopeLeakRestoreScriptGuardsTheWipe(t *testing.T) {
	for _, bin := range []string{"sh", "tar"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " not available")
		}
	}
	run := func(t *testing.T, archive func(path, work string)) (vol string, code int, stderr string) {
		t.Helper()
		bdir, vol, work := t.TempDir(), t.TempDir(), t.TempDir()
		archive(filepath.Join(bdir, "b.tar.gz"), work)
		_ = os.WriteFile(filepath.Join(vol, "keep.txt"), []byte("live"), 0o644)
		script := strings.ReplaceAll(volumeBackupRestoreScript("b.tar.gz"), "/backup/", bdir+"/")
		script = strings.ReplaceAll(script, "/volume", vol)
		cmd := exec.Command("sh", "-c", script)
		var se strings.Builder
		cmd.Stderr = &se
		err := cmd.Run()
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return vol, code, se.String()
	}
	tarOf := func(t *testing.T, path, dir string) {
		t.Helper()
		if out, err := exec.Command("tar", "czf", path, "-C", dir, ".").CombinedOutput(); err != nil {
			t.Fatalf("tar: %v %s", err, out)
		}
	}
	untouched := func(t *testing.T, vol string) {
		t.Helper()
		if b, err := os.ReadFile(filepath.Join(vol, "keep.txt")); err != nil || string(b) != "live" {
			t.Fatal("the live volume was wiped")
		}
	}

	t.Run("empty archive", func(t *testing.T) {
		vol, code, se := run(t, func(p, work string) {
			// A gzip-valid tar with zero members: `tar tzf` exits 0 on it.
			if out, err := exec.Command("sh", "-c", "tar cf - -T /dev/null | gzip > "+p).CombinedOutput(); err != nil {
				t.Fatalf("empty tar: %v %s", err, out)
			}
		})
		if code != 3 || !strings.Contains(se, "archive is empty") {
			t.Fatalf("code=%d stderr=%q", code, se)
		}
		untouched(t, vol)
	})
	t.Run("corrupt archive", func(t *testing.T) {
		vol, code, se := run(t, func(p, work string) { _ = os.WriteFile(p, []byte("not a gzip stream"), 0o644) })
		if code != 3 || !strings.Contains(se, "corrupt or truncated") {
			t.Fatalf("code=%d stderr=%q", code, se)
		}
		untouched(t, vol)
	})
	t.Run("real archive", func(t *testing.T) {
		vol, code, se := run(t, func(p, work string) {
			_ = os.WriteFile(filepath.Join(work, "restored.txt"), []byte("backup"), 0o644)
			tarOf(t, p, work)
		})
		if code != 0 {
			t.Fatalf("code=%d stderr=%q", code, se)
		}
		if _, err := os.Stat(filepath.Join(vol, "keep.txt")); err == nil {
			t.Error("old content must be replaced")
		}
		if b, err := os.ReadFile(filepath.Join(vol, "restored.txt")); err != nil || string(b) != "backup" {
			t.Error("archive content must be restored")
		}
	})
}
