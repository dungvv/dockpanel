package services

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/sitelock"
)

const volumeBackupDir = "/var/backups/dockpanel/volumes"

func volumeBackupIsSafeFilename(name string) bool { return backupsIsSafeFilename(name) }

func volumeBackupDirFor(containerName string) string { return volumeBackupDir + "/" + containerName }

// VolumeBackupBackupVolume backs up a Docker volume by running a temporary
// alpine container that mounts the volume read-only and tars its contents.
func VolumeBackupBackupVolume(volumeName, containerName string) (BackupsBackupInfo, error) {
	destDir := volumeBackupDirFor(containerName)
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return BackupsBackupInfo{}, fmt.Errorf("Failed to create backup dir: %v", err)
	}
	filename := fmt.Sprintf("%s-%s-%s.tar.gz", containerName, volumeName, backupsStamp(time.Now()))
	fpath := filepath.Join(destDir, filename)

	out, timedOut, err := backupsRun(600*time.Second, "docker",
		"run", "--rm",
		"-v", volumeName+":/volume:ro",
		"-v", destDir+":/backup",
		"alpine:3.19",
		"tar", "czf", "/backup/"+filename, "-C", "/volume", ".")
	if timedOut {
		return BackupsBackupInfo{}, errors.New("Volume backup timed out (10 minutes)")
	}
	if err != nil {
		return BackupsBackupInfo{}, fmt.Errorf("Failed to run volume backup: %v", err)
	}
	if !out.Success() {
		os.Remove(fpath)
		return BackupsBackupInfo{}, fmt.Errorf("Volume backup failed: %s", backupsLossy(out.Stderr))
	}
	fi, err := os.Stat(fpath)
	if err != nil {
		return BackupsBackupInfo{}, fmt.Errorf("Failed to read backup metadata: %v", err)
	}
	sum := backupsComputeFileSha256(fpath)
	slog.Info(fmt.Sprintf("Volume backup created: %s (%d bytes, hash: %s)", filename, fi.Size(), backupsOrNA(sum)))
	return BackupsBackupInfo{
		Filename: filename, SizeBytes: uint64(fi.Size()),
		CreatedAt: backupsDisplayTime(time.Now()), Sha256: sum,
	}, nil
}

// volumeBackupRestoreScript validates the archive in full BEFORE wiping the
// live volume. The old unconditional `rm -rf` destroyed the volume and THEN
// failed the extract on a truncated/corrupt backup — irreversible. `tar tzf`
// walks the whole archive (gzip CRC, truncation) without touching /volume; a
// SEPARATE `tar tzf | wc -l` (kept apart so an early SIGPIPE can never mask a
// mid-listing failure) requires at least one member, since tar exits 0 on an
// empty archive. filename is volumeBackupIsSafeFilename-validated (alnum and
// -_. only), so interpolating it into the shell is safe.
func volumeBackupRestoreScript(filename string) string {
	return fmt.Sprintf("tar tzf /backup/%[1]s >/dev/null 2>&1 || { echo 'backup archive is corrupt or truncated — volume left untouched' >&2; exit 3; }; "+
		"n=$(tar tzf /backup/%[1]s 2>/dev/null | wc -l); [ $n -gt 0 ] || { echo 'backup archive is empty — volume left untouched' >&2; exit 3; }; "+
		"rm -rf /volume/* /volume/..?* /volume/.[!.]* 2>/dev/null; tar xzf /backup/%[1]s -C /volume", filename)
}

// VolumeBackupRestoreVolume restores a Docker volume from a backup.
func VolumeBackupRestoreVolume(volumeName, containerName, filename string) error {
	// Held for the whole operation: an rm-rf-then-extract against a live,
	// possibly-mounted volume must not interleave with another operation on
	// it. Keyed outside the domain namespace (there is no domain here).
	unlock := sitelock.LockSite("volume:" + volumeName)
	defer unlock()

	if !volumeBackupIsSafeFilename(filename) {
		return errors.New("Invalid backup filename")
	}
	dir := volumeBackupDirFor(containerName)
	if _, err := os.Stat(filepath.Join(dir, filename)); err != nil {
		return errors.New("Backup file not found")
	}
	out, timedOut, err := backupsRun(600*time.Second, "docker",
		"run", "--rm",
		"-v", volumeName+":/volume",
		"-v", dir+":/backup:ro",
		"alpine:3.19",
		"sh", "-c", volumeBackupRestoreScript(filename))
	if timedOut {
		return errors.New("Volume restore timed out (10 minutes)")
	}
	if err != nil {
		return fmt.Errorf("Failed to run volume restore: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("Volume restore failed: %s", backupsLossy(out.Stderr))
	}
	slog.Info(fmt.Sprintf("Volume restored: %s to %s", filename, volumeName))
	return nil
}

// VolumeBackupListVolumeBackups lists volume backups for a container.
func VolumeBackupListVolumeBackups(containerName string) ([]BackupsBackupInfo, error) {
	return backupsListDir(volumeBackupDirFor(containerName), func(e os.DirEntry, _ *BackupsBackupInfo) bool {
		return strings.HasSuffix(e.Name(), ".tar.gz")
	})
}

// VolumeBackupDeleteVolumeBackup deletes a volume backup file.
func VolumeBackupDeleteVolumeBackup(containerName, filename string) error {
	if !volumeBackupIsSafeFilename(filename) {
		return errors.New("Invalid backup filename")
	}
	fpath := filepath.Join(volumeBackupDirFor(containerName), filename)
	if _, err := os.Stat(fpath); err != nil {
		return errors.New("Backup file not found")
	}
	if err := os.Remove(fpath); err != nil {
		return fmt.Errorf("Failed to delete backup: %v", err)
	}
	slog.Info(fmt.Sprintf("Volume backup deleted: %s for %s", filename, containerName))
	return nil
}
