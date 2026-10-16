package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

const (
	backupsBackupDir = "/var/backups/dockpanel"
	backupsWebroot   = "/var/www"
	// Where database dumps are staged while an archive is being built or
	// unpacked. Must live under a path the agent unit lists in ReadWritePaths.
	backupsStagingRootDir = "/var/backups/dockpanel/.staging"
)

// The three roots are package vars ONLY so tests can run hermetically under a
// temp dir (the real paths need root and a provisioned box). Nothing in
// production code reassigns them.
var (
	backupsWebrootRoot = backupsWebroot
	backupsRoot        = backupsBackupDir
	backupsStagingRoot = backupsStagingRootDir
)

// BackupsPayloadDir is the directory inside the archive holding everything
// DockPanel adds to a site backup beyond the webroot. Deliberately NOT under
// "./" so it is a distinct top-level member that can be extracted (and
// excluded) on its own.
const BackupsPayloadDir = ".dockpanel-backup"

// backupsManifestSchema: bump when the payload layout changes in a way a
// reader must know about.
const backupsManifestSchema = 1

// BackupsSecureBackupTree makes the whole backup tree root-only, repairing
// what is already on disk.
//
// Everything under /var/backups/dockpanel is a restorable copy of something
// secret: the panel's own database (servers.agent_token in CLEARTEXT — the
// Bearer credential for every agent endpoint and the HMAC key for root-PTY
// tickets), every tenant's database dump and every site archive.
//
// The tree was created 0755 and writers left files 0644; on a panel host that
// also serves sites, www-data (every tenant's PHP) could read them — measured
// 17 of 17 files readable at v2.87.0. The directory bit is the load-bearing
// half (at 0700 nothing below is reachable by a non-root uid); the file bits
// are defence in depth. Repairing on every start (not only fixing writers) is
// deliberate: three writers produce these files (agent, auto-healer, a root
// crontab line) and existing installs must be fixed too. Idempotent and cheap.
func BackupsSecureBackupTree() {
	backupsSecureTreeAt(backupsRoot)
}

// backupsSecureTreeAt is the body of BackupsSecureBackupTree, parameterized
// on the root so tests never share the real one (a shared root once let a
// test pass against a deliberately broken tighten()).
func backupsSecureTreeAt(root string) {
	// tighten compares before writing so a correct tree costs one stat per
	// entry. Never follows a symlink: chmod would apply to its target, which
	// a writer could have aimed anywhere.
	tighten := func(path string, want os.FileMode) {
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 {
			return
		}
		if fi.Mode().Perm() != want {
			_ = os.Chmod(path, want)
		}
	}
	var loosened uint32
	var walk func(dir string)
	walk = func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			path := filepath.Join(dir, e.Name())
			fi, err := os.Lstat(path)
			if err != nil || fi.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if fi.IsDir() {
				if fi.Mode().Perm() != 0o700 {
					loosened++
				}
				tighten(path, 0o700)
				walk(path)
			} else {
				if fi.Mode().Perm()&0o007 != 0 {
					loosened++
				}
				tighten(path, 0o600)
			}
		}
	}

	if _, err := os.Stat(root); err != nil {
		return
	}
	tighten(root, 0o700)
	walk(root)
	if loosened > 0 {
		slog.Warn(fmt.Sprintf("Tightened %d world-readable entries under %s — a backup there "+
			"carries the panel database, which holds agent tokens in cleartext", loosened, root))
	}
}

// BackupsDbSpec is a database the panel wants dumped into (or restored from)
// a site backup. The agent cannot read the panel's databases table, so the
// backend resolves them and passes decrypted credentials.
type BackupsDbSpec struct {
	ContainerName string `json:"container_name"`
	DbName        string `json:"db_name"`
	DbType        string `json:"db_type"`
	User          string `json:"user"`
	Password      string `json:"password"`
}

// BackupsDbFailure is a database that could not be dumped or restored, and
// why. Never swallowed — a backup that silently lost a database is the defect
// this whole path exists to close.
type BackupsDbFailure struct {
	DbName string `json:"db_name"`
	Error  string `json:"error"`
}

// BackupsManifestDb is one dump inside the payload.
type BackupsManifestDb struct {
	DbName    string  `json:"db_name"`
	DbType    string  `json:"db_type"`
	File      string  `json:"file"` // file name inside <payload>/db/
	SizeBytes uint64  `json:"size_bytes"`
	Sha256    *string `json:"sha256,omitempty"`
}

// BackupsManifest is <payload>/manifest.json.
type BackupsManifest struct {
	Schema    uint32              `json:"schema"`
	Domain    string              `json:"domain"`
	CreatedAt string              `json:"created_at"`
	Databases []BackupsManifestDb `json:"databases"`
}

// BackupsBackupInfo describes one backup file (site, database and volume
// backups share it).
type BackupsBackupInfo struct {
	Filename  string  `json:"filename"`
	SizeBytes uint64  `json:"size_bytes"`
	CreatedAt string  `json:"created_at"`
	Sha256    *string `json:"sha256,omitempty"`
	// Databases whose dump is inside this archive. Omitted for a files-only
	// backup (every archive before v2.34.0).
	DatabasesIncluded []string `json:"databases_included,omitempty"`
	// Databases the panel asked for that are NOT in the archive.
	DatabasesFailed []BackupsDbFailure `json:"databases_failed,omitempty"`
	// Why a file in a backup directory cannot be used, and how to fix it.
	// Omitted when absent so site/volume responses are byte-identical to
	// before; only the database listing sets it, for a file it would
	// otherwise have silently dropped.
	Unsupported *string `json:"unsupported,omitempty"`
}

// BackupsRestoreReport is what a restore actually did. Ok() is the only thing
// callers should treat as success — files back but database not is a failure
// with a partially-changed site, not a success with a footnote.
type BackupsRestoreReport struct {
	FilesRestored      bool               `json:"files_restored"`
	DatabasesInArchive int                `json:"databases_in_archive"`
	DatabasesRestored  []string           `json:"databases_restored"`
	DatabasesFailed    []BackupsDbFailure `json:"databases_failed"`
}

// Ok reports full success.
func (r *BackupsRestoreReport) Ok() bool {
	return r.FilesRestored && len(r.DatabasesFailed) == 0
}

func backupsNewRestoreReport() BackupsRestoreReport {
	return BackupsRestoreReport{DatabasesRestored: []string{}, DatabasesFailed: []BackupsDbFailure{}}
}

// backupsStamp is chrono's "%Y%m%d-%H%M%S" in UTC.
func backupsStamp(t time.Time) string { return t.UTC().Format("20060102-150405") }

// backupsDisplayTime is chrono's "%Y-%m-%d %H:%M:%S" in UTC.
func backupsDisplayTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") }

// backupsMakeStaging creates a root-only staging dir. The dumps inside are
// the site's entire content in plaintext.
func backupsMakeStaging(tag string) (string, error) {
	dir := filepath.Join(backupsStagingRoot, tag)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("Failed to create staging dir: %v", err)
	}
	_ = os.Chmod(dir, 0o700)
	// The parent is shared by every staged backup; keep it closed too.
	_ = os.Chmod(backupsStagingRoot, 0o700)
	return dir, nil
}

// backupsStageOneDump dumps one database and moves it into the archive
// payload, reusing the hardened per-engine dump paths.
func backupsStageOneDump(spec *BackupsDbSpec, destDir string) (BackupsManifestDb, error) {
	var info BackupsBackupInfo
	var err error
	switch spec.DbType {
	case "mysql", "mariadb":
		info, err = DatabaseBackupDumpMysql(spec.ContainerName, spec.DbName, spec.User, spec.Password)
	case "postgres", "postgresql":
		info, err = DatabaseBackupDumpPostgres(spec.ContainerName, spec.DbName, spec.User, spec.Password)
	case "mongo", "mongodb":
		info, err = DatabaseBackupDumpMongo(spec.ContainerName, spec.DbName)
	default:
		return BackupsManifestDb{}, fmt.Errorf("Unsupported database engine '%s'", spec.DbType)
	}
	if err != nil {
		return BackupsManifestDb{}, err
	}
	// dump_* writes into the per-database backup tree; move it into the
	// payload so it does not also surface as a standalone database backup.
	src, err := DatabaseBackupGetBackupPath(spec.DbName, info.Filename)
	if err != nil {
		return BackupsManifestDb{}, err
	}
	if err := os.Rename(src, filepath.Join(destDir, info.Filename)); err != nil {
		return BackupsManifestDb{}, fmt.Errorf("Failed to stage dump for %s: %v", spec.DbName, err)
	}
	return BackupsManifestDb{
		DbName: spec.DbName, DbType: spec.DbType, File: info.Filename,
		SizeBytes: info.SizeBytes, Sha256: info.Sha256,
	}, nil
}

// backupsIsSafeFilename validates a backup filename (no path traversal).
func backupsIsSafeFilename(name string) bool {
	return name != "" && !strings.Contains(name, "/") && !strings.Contains(name, "..") &&
		strings.HasSuffix(name, ".tar.gz") && backupsSafeChars(name)
}

// backupsSafeChars: ASCII alphanumeric, '-', '_', '.' only.
func backupsSafeChars(name string) bool {
	for _, c := range name {
		if !backupsIsASCIIAlnum(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func backupsIsASCIIAlnum(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func backupsDir(domain string) string { return filepath.Join(backupsRoot, domain) }

// backupsRun runs a bounded command; timedOut reports the deadline fired (the
// child is killed — the Rust kill_on_drop contract), which callers report as
// a timeout, never as an ordinary failure.
func backupsRun(timeout time.Duration, bin string, args ...string) (out safecmd.Output, timedOut bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err = safecmd.Exec(ctx, bin, args...)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, true, nil
	}
	return out, false, err
}

func backupsLossy(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

// BackupsCreateBackup archives the site's webroot plus a dump of each
// database the panel passes in. With no databases the archive is
// byte-for-byte what it always was.
func BackupsCreateBackup(domain string, databases []BackupsDbSpec) (BackupsBackupInfo, error) {
	siteRoot := filepath.Join(backupsWebrootRoot, domain)
	if _, err := os.Stat(siteRoot); err != nil {
		return BackupsBackupInfo{}, fmt.Errorf("Site root does not exist: %s", siteRoot)
	}
	destDir := backupsDir(domain)
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return BackupsBackupInfo{}, fmt.Errorf("Failed to create backup dir: %v", err)
	}

	timestamp := backupsStamp(time.Now())
	filename := domain + "-" + timestamp + ".tar.gz"
	fpath := filepath.Join(destDir, filename)

	// ── Stage database dumps into the archive payload ──
	staging := ""
	included := []string{}
	failed := []BackupsDbFailure{}

	if len(databases) > 0 {
		if _, err := os.Lstat(filepath.Join(siteRoot, BackupsPayloadDir)); err == nil {
			// The site itself owns a path we would have to shadow. Refuse the
			// payload rather than produce an archive whose restore is ambiguous.
			for _, spec := range databases {
				failed = append(failed, BackupsDbFailure{
					DbName: spec.DbName,
					Error:  fmt.Sprintf("site root contains a reserved '%s' path; database not included", BackupsPayloadDir),
				})
			}
		} else {
			stage, err := backupsMakeStaging(domain + "-" + timestamp)
			if err != nil {
				return BackupsBackupInfo{}, err
			}
			dbDir := filepath.Join(stage, BackupsPayloadDir, "db")
			if err := os.MkdirAll(dbDir, 0o700); err != nil {
				os.RemoveAll(stage)
				return BackupsBackupInfo{}, fmt.Errorf("Failed to create payload dir: %v", err)
			}
			manifestDbs := []BackupsManifestDb{}
			for i := range databases {
				spec := &databases[i]
				entry, err := backupsStageOneDump(spec, dbDir)
				if err != nil {
					slog.Warn(fmt.Sprintf("Backup for %s: database %s not included: %v", domain, spec.DbName, err))
					failed = append(failed, BackupsDbFailure{DbName: spec.DbName, Error: err.Error()})
					continue
				}
				included = append(included, spec.DbName)
				manifestDbs = append(manifestDbs, entry)
			}
			manifest := BackupsManifest{
				Schema: backupsManifestSchema, Domain: domain,
				CreatedAt: SslRFC3339(time.Now()), Databases: manifestDbs,
			}
			raw, err := json.MarshalIndent(manifest, "", "  ")
			if err != nil {
				os.RemoveAll(stage)
				return BackupsBackupInfo{}, fmt.Errorf("Failed to serialize manifest: %v", err)
			}
			if err := os.WriteFile(filepath.Join(stage, BackupsPayloadDir, "manifest.json"), raw, 0o600); err != nil {
				os.RemoveAll(stage)
				return BackupsBackupInfo{}, fmt.Errorf("Failed to write manifest: %v", err)
			}
			staging = stage
		}
	}

	tarArgs := []string{"czf", fpath, "-C", siteRoot, "."}
	if staging != "" {
		tarArgs = append(tarArgs, "-C", staging, BackupsPayloadDir)
	}
	// The context kills tar on timeout, so it never keeps running against the
	// staged plaintext copy removed below.
	out, timedOut, err := backupsRun(300*time.Second, "tar", tarArgs...)

	// The staged dumps are a full plaintext copy of the site's data — remove
	// them whatever happened to tar.
	if staging != "" {
		_ = os.RemoveAll(staging)
	}
	if timedOut {
		return BackupsBackupInfo{}, errors.New("Backup timed out (5 minutes)")
	}
	if err != nil {
		return BackupsBackupInfo{}, fmt.Errorf("Failed to run tar: %v", err)
	}
	if !out.Success() {
		os.Remove(fpath)
		return BackupsBackupInfo{}, fmt.Errorf("Backup failed: %s", backupsLossy(out.Stderr))
	}

	fi, err := os.Stat(fpath)
	if err != nil {
		return BackupsBackupInfo{}, fmt.Errorf("Failed to read backup metadata: %v", err)
	}
	size := uint64(fi.Size())
	// Warn if backup exceeds 5GB — may indicate a bloated site or logs in webroot.
	const sizeWarn = 5 * 1024 * 1024 * 1024
	if size > sizeWarn {
		slog.Warn(fmt.Sprintf("Backup for %s is very large: %.2f GB (%s). Consider cleaning up the site directory.",
			domain, float64(size)/(1024.0*1024.0*1024.0), filename))
	}

	// SHA256 of the backup file for the integrity chain.
	sum := backupsComputeFileSha256(fpath)
	slog.Info(fmt.Sprintf("Backup created: %s (%d bytes, hash: %s, databases: %d included / %d failed)",
		filename, size, backupsOrNA(sum), len(included), len(failed)))

	return BackupsBackupInfo{
		Filename: filename, SizeBytes: size, CreatedAt: backupsDisplayTime(time.Now()),
		Sha256: sum, DatabasesIncluded: included, DatabasesFailed: failed,
	}, nil
}

func backupsOrNA(s *string) string {
	if s == nil {
		return "N/A"
	}
	return *s
}

// backupsComputeFileSha256 hashes a file for the backup integrity chain
// (site / database / volume). nil when the file cannot be read. Hex output is
// identical to the `sha256sum` the Rust agent shelled out to.
func backupsComputeFileSha256(path string) *string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil
	}
	s := hex.EncodeToString(h.Sum(nil))
	return &s
}

// backupsListDir lists files in dir; keep decides which names are reported and
// may set Unsupported. Newest first.
func backupsListDir(dir string, keep func(e os.DirEntry, info *BackupsBackupInfo) bool) ([]BackupsBackupInfo, error) {
	out := []BackupsBackupInfo{}
	if _, err := os.Stat(dir); err != nil {
		return out, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("Read dir error: %v", err)
	}
	for _, e := range entries {
		info := BackupsBackupInfo{Filename: e.Name()}
		if !keep(e, &info) {
			continue
		}
		if fi, err := os.Stat(filepath.Join(dir, e.Name())); err == nil {
			info.SizeBytes = uint64(fi.Size())
			info.CreatedAt = backupsDisplayTime(fi.ModTime())
		}
		out = append(out, info)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

// BackupsListBackups lists backups for a domain.
func BackupsListBackups(domain string) ([]BackupsBackupInfo, error) {
	return backupsListDir(backupsDir(domain), func(e os.DirEntry, _ *BackupsBackupInfo) bool {
		return strings.HasSuffix(e.Name(), ".tar.gz")
	})
}

// backupsExtractPayload pulls the DockPanel payload out of an archive into
// stage, if it has one. (nil, nil) for an archive that predates the payload —
// a normal, expected shape.
func backupsExtractPayload(archive, stage string) (*BackupsManifest, error) {
	out, timedOut, err := backupsRun(300*time.Second, "tar",
		"xzf", archive, "--no-same-owner", "--no-same-permissions", "-C", stage, BackupsPayloadDir)
	if timedOut {
		return nil, errors.New("Reading backup payload timed out (5 minutes)")
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to run tar: %v", err)
	}
	payloadDir := filepath.Join(stage, BackupsPayloadDir)
	manifestPath := filepath.Join(payloadDir, "manifest.json")

	if !out.Success() {
		stderr := backupsLossy(out.Stderr)
		// GNU tar's way of saying "this archive simply doesn't have that member".
		if strings.Contains(stderr, "Not found in archive") || strings.Contains(stderr, "not found in archive") {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read backup payload: %s", stderr)
	}

	// The archive's top-level payload member can itself be a symlink — tar
	// extracts it as asked, and plain file reads below would follow it.
	// Refuse rather than read manifest.json through a link this backup does
	// not own.
	if fi, err := os.Lstat(payloadDir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("Backup payload '%s' is a symlink, not a directory — refusing to read it", BackupsPayloadDir)
	}
	if _, err := os.Stat(manifestPath); err != nil {
		return nil, nil
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read backup manifest: %v", err)
	}
	var m BackupsManifest
	if err := backupsStrictManifest(raw, &m); err != nil {
		return nil, fmt.Errorf("Backup manifest is unreadable: %v", err)
	}
	if m.Schema > backupsManifestSchema {
		return nil, fmt.Errorf("Backup was made by a newer DockPanel (manifest schema %d, this agent understands %d). Update this server before restoring it.",
			m.Schema, backupsManifestSchema)
	}
	return &m, nil
}

// backupsStrictManifest mirrors serde: schema/domain/created_at and each
// database's db_name/db_type/file/size_bytes are required.
func backupsStrictManifest(raw []byte, m *BackupsManifest) error {
	var top struct {
		Schema    *uint32 `json:"schema"`
		Domain    *string `json:"domain"`
		CreatedAt *string `json:"created_at"`
		Databases []struct {
			DbName    *string `json:"db_name"`
			DbType    *string `json:"db_type"`
			File      *string `json:"file"`
			SizeBytes *uint64 `json:"size_bytes"`
		} `json:"databases"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return err
	}
	switch {
	case top.Schema == nil:
		return errors.New("missing field `schema`")
	case top.Domain == nil:
		return errors.New("missing field `domain`")
	case top.CreatedAt == nil:
		return errors.New("missing field `created_at`")
	}
	for _, d := range top.Databases {
		if d.DbName == nil || d.DbType == nil || d.File == nil || d.SizeBytes == nil {
			return errors.New("missing field in databases entry")
		}
	}
	return json.Unmarshal(raw, m)
}

// BackupsRestoreBackup restores a backup to the site's webroot, then any
// databases the archive carries. Files first, databases last: the per-engine
// restore paths roll back on failure, so a database that fails to load
// leaves the live data as it was.
func BackupsRestoreBackup(domain, filename string, databases []BackupsDbSpec) (BackupsRestoreReport, error) {
	if !backupsIsSafeFilename(filename) {
		return BackupsRestoreReport{}, errors.New("Invalid backup filename")
	}
	fpath := filepath.Join(backupsDir(domain), filename)
	if _, err := os.Stat(fpath); err != nil {
		return BackupsRestoreReport{}, errors.New("Backup file not found")
	}
	siteRoot := filepath.Join(backupsWebrootRoot, domain)
	if err := os.MkdirAll(siteRoot, 0o755); err != nil {
		return BackupsRestoreReport{}, fmt.Errorf("Failed to create site root: %v", err)
	}
	stage, err := backupsMakeStaging("restore-" + domain + "-" + backupsStamp(time.Now()))
	if err != nil {
		return BackupsRestoreReport{}, err
	}
	report, err := backupsRestoreInner(domain, filename, fpath, siteRoot, stage, databases)
	// The staged dumps are the site's data in plaintext — never leave them behind.
	_ = os.RemoveAll(stage)
	return report, err
}

func backupsRestoreInner(domain, filename, fpath, siteRoot, stage string, databases []BackupsDbSpec) (BackupsRestoreReport, error) {
	report := backupsNewRestoreReport()

	// 1. Pull the database payload out FIRST, so it never lands in the webroot.
	manifest, err := backupsExtractPayload(fpath, stage)
	if err != nil {
		return report, err
	}
	var manifestDbs []BackupsManifestDb
	if manifest != nil {
		manifestDbs = manifest.Databases
	}
	report.DatabasesInArchive = len(manifestDbs)

	// 2. Restore the files. Full overwrite; --no-same-owner prevents uid/gid
	//    hijacking. The payload is excluded so a site restored from a v1
	//    archive does not gain a directory of database dumps under its
	//    document root.
	out, timedOut, err := backupsRun(300*time.Second, "tar",
		"xzf", fpath, "--no-same-owner", "--no-same-permissions",
		"--exclude", BackupsPayloadDir, "--exclude", BackupsPayloadDir+"/*",
		"-C", siteRoot)
	if timedOut {
		return report, errors.New("Restore timed out (5 minutes)")
	}
	if err != nil {
		return report, fmt.Errorf("Failed to run tar: %v", err)
	}
	if !out.Success() {
		return report, fmt.Errorf("Restore failed: %s", backupsLossy(out.Stderr))
	}

	// Verify the restore produced a non-empty site directory.
	ents, _ := os.ReadDir(siteRoot)
	if len(ents) == 0 {
		return report, errors.New("Restore completed but site directory is empty")
	}
	report.FilesRestored = true

	// 3. Restore each database the archive carries.
	dbDir := filepath.Join(stage, BackupsPayloadDir, "db")
	for _, entry := range manifestDbs {
		var spec *BackupsDbSpec
		for i := range databases {
			if databases[i].DbName == entry.DbName {
				spec = &databases[i]
				break
			}
		}
		if spec == nil {
			// The caller sent no credentials at all (the CLI cannot resolve
			// them), or the site genuinely no longer has that database.
			var msg string
			if len(databases) == 0 {
				msg = fmt.Sprintf("this archive contains a dump of '%s', but the caller supplied no database credentials, so it could not be restored", entry.DbName)
			} else {
				msg = fmt.Sprintf("the archive contains a dump of '%s' but no such database is attached to this site now; restore it from the Databases page", entry.DbName)
			}
			report.DatabasesFailed = append(report.DatabasesFailed, BackupsDbFailure{DbName: entry.DbName, Error: msg})
			continue
		}

		// entry.File comes from manifest.json inside the archive being restored
		// — attacker-controlled once an archive exists. An absolute or
		// traversal-shaped value would point the dump path at an arbitrary
		// file this root agent can read. Reject before joining.
		if entry.File == "" || strings.Contains(entry.File, "/") || strings.Contains(entry.File, "..") || filepath.IsAbs(entry.File) {
			report.DatabasesFailed = append(report.DatabasesFailed, BackupsDbFailure{
				DbName: entry.DbName, Error: "the manifest names an unsafe dump filename; refusing to restore it",
			})
			continue
		}
		dumpPath := filepath.Join(dbDir, entry.File)
		if _, err := os.Stat(dumpPath); err != nil {
			report.DatabasesFailed = append(report.DatabasesFailed, BackupsDbFailure{
				DbName: entry.DbName, Error: "the manifest lists this database but its dump is missing from the archive",
			})
			continue
		}

		var rerr error
		switch spec.DbType {
		case "mysql", "mariadb":
			rerr = DatabaseBackupRestoreMysql(spec.ContainerName, spec.DbName, spec.User, spec.Password, dumpPath)
		case "postgres", "postgresql":
			rerr = DatabaseBackupRestorePostgres(spec.ContainerName, spec.DbName, spec.User, spec.Password, dumpPath)
		case "mongo", "mongodb":
			rerr = DatabaseBackupRestoreMongo(spec.ContainerName, spec.DbName, dumpPath)
		default:
			rerr = fmt.Errorf("Unsupported database engine '%s'", spec.DbType)
		}
		if rerr != nil {
			slog.Error(fmt.Sprintf("Restore for %s: database %s failed: %v", domain, entry.DbName, rerr))
			report.DatabasesFailed = append(report.DatabasesFailed, BackupsDbFailure{DbName: entry.DbName, Error: rerr.Error()})
			continue
		}
		report.DatabasesRestored = append(report.DatabasesRestored, entry.DbName)
	}

	slog.Info(fmt.Sprintf("Backup restored: %s for %s (%d entries, databases: %d restored / %d failed of %d in archive)",
		filename, domain, len(ents), len(report.DatabasesRestored), len(report.DatabasesFailed), report.DatabasesInArchive))
	return report, nil
}

// BackupsListBackupFiles lists files in a backup archive (max 500 entries).
func BackupsListBackupFiles(domain, filename string) ([]string, error) {
	if !backupsIsSafeFilename(filename) {
		return nil, errors.New("Invalid backup filename")
	}
	fpath := filepath.Join(backupsDir(domain), filename)
	if _, err := os.Stat(fpath); err != nil {
		return nil, errors.New("Backup file not found")
	}
	out, timedOut, err := backupsRun(30*time.Second, "tar", "tzf", fpath)
	if timedOut {
		return nil, errors.New("Listing timed out (30s)")
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to run tar: %v", err)
	}
	if !out.Success() {
		return nil, fmt.Errorf("Failed to list archive: %s", backupsLossy(out.Stderr))
	}
	files := LogsLines(out.Stdout)
	if len(files) > 500 {
		files = files[:500]
	}
	return files, nil
}

// BackupsRestoreSingleFile restores one member of a backup archive.
func BackupsRestoreSingleFile(domain, filename, filePath string) error {
	if !backupsIsSafeFilename(filename) {
		return errors.New("Invalid backup filename")
	}
	if filePath == "" {
		return errors.New("File path cannot be empty")
	}
	if strings.Contains(filePath, "..") {
		return errors.New("File path must not contain '..'")
	}
	if strings.HasPrefix(filePath, "/") {
		return errors.New("File path must not start with '/'")
	}
	// Never hand back the database payload through the single-file path: the
	// dumps are the site's content in plaintext and the target is a publicly
	// served document root. That payload members carry no "./" prefix (so tar
	// would not match them anyway) is an accident the guard must not rely on.
	normalized := strings.TrimPrefix(filePath, "./")
	if normalized == BackupsPayloadDir || strings.HasPrefix(normalized, BackupsPayloadDir+"/") {
		return fmt.Errorf("'%s' holds this backup's database dumps and cannot be restored into the site directory; restore the whole backup instead", BackupsPayloadDir)
	}
	backupPath := filepath.Join(backupsDir(domain), filename)
	if _, err := os.Stat(backupPath); err != nil {
		return errors.New("Backup file not found")
	}
	target := filepath.Join(backupsWebrootRoot, domain)
	extract := filePath
	if !strings.HasPrefix(extract, "./") {
		extract = "./" + extract
	}
	out, timedOut, err := backupsRun(60*time.Second, "tar",
		"xzf", backupPath, "--no-same-owner", "--no-same-permissions", "-C", target, extract)
	if timedOut {
		return errors.New("Restore timed out (60s)")
	}
	if err != nil {
		return fmt.Errorf("Failed to run tar: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("Single-file restore failed: %s", backupsLossy(out.Stderr))
	}
	slog.Info(fmt.Sprintf("Single file restored from %s: %s for %s", filename, filePath, domain))
	return nil
}

// BackupsDeleteBackup deletes a backup file.
func BackupsDeleteBackup(domain, filename string) error {
	if !backupsIsSafeFilename(filename) {
		return errors.New("Invalid backup filename")
	}
	fpath := filepath.Join(backupsDir(domain), filename)
	if _, err := os.Stat(fpath); err != nil {
		return errors.New("Backup file not found")
	}
	if err := os.Remove(fpath); err != nil {
		return fmt.Errorf("Failed to delete backup: %v", err)
	}
	slog.Info(fmt.Sprintf("Backup deleted: %s for %s", filename, domain))
	return nil
}
