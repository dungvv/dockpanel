package api

// Port of panel/backend/src/services/panel_snapshot.rs.
//
// Phase 4 W4: persistent panel snapshots.
//
// Builds tar.gz triplets containing:
//
//	binaries/     — agent + api + cli binary copies
//	db/           — gzipped pg_dump of the DockPanel database
//	etc/          — copy of /etc/dockpanel
//	metadata.json — provenance (from_version, trigger, operator)
//
// Stored in /var/backups/dockpanel/snapshots/. The orchestrator creates one
// BEFORE invoking update.sh; the file outlives the .bak triplet that update.sh
// deletes on a successful health check, giving operators an after-the-fact
// rollback path.
//
// This module is the IO layer only. systemctl stop/start choreography around
// restores lives in the orchestrator so this service stays usable for
// one-shot "snapshot now" admin actions without state-machine coupling.

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	panelSnapshotSnapshotDir      = "/var/backups/dockpanel/snapshots"
	panelSnapshotStagingDirParent = "/var/backups/dockpanel/.snapshot-staging"
	// Refuse to create a snapshot if the target partition has less than this
	// many bytes free. A typical snapshot is ~150-300 MB; 2 GiB keeps the
	// partition healthy even if a sweep is lagging.
	panelSnapshotMinFreeBytes uint64 = 2 * 1024 * 1024 * 1024
)

// Retention: never delete the most-recent PanelSnapshotRetentionMin
// snapshots, even if all are older than PanelSnapshotRetentionDays. Protects
// against "broke weeks ago, only just noticed" scenarios.
const (
	PanelSnapshotRetentionMin  int64 = 3
	PanelSnapshotRetentionDays int64 = 7
)

type PanelSnapshotTriggerKind int

const (
	PanelSnapshotTriggerKindManual PanelSnapshotTriggerKind = iota
	PanelSnapshotTriggerKindPreUpdate
	// Fleet is reserved for future per-server fleet snapshot tagging.
	PanelSnapshotTriggerKindFleet
)

// PanelSnapshotTrigger is the Rust SnapshotTrigger enum.
type PanelSnapshotTrigger struct {
	Kind          PanelSnapshotTriggerKind
	TargetVersion string    // PreUpdate
	ServerID      uuid.UUID // Fleet
}

func PanelSnapshotTriggerManual() PanelSnapshotTrigger {
	return PanelSnapshotTrigger{Kind: PanelSnapshotTriggerKindManual}
}

func PanelSnapshotTriggerPreUpdate(targetVersion string) PanelSnapshotTrigger {
	return PanelSnapshotTrigger{Kind: PanelSnapshotTriggerKindPreUpdate, TargetVersion: targetVersion}
}

func PanelSnapshotTriggerFleet(serverID uuid.UUID) PanelSnapshotTrigger {
	return PanelSnapshotTrigger{Kind: PanelSnapshotTriggerKindFleet, ServerID: serverID}
}

func (t PanelSnapshotTrigger) AsStr() string {
	switch t.Kind {
	case PanelSnapshotTriggerKindPreUpdate:
		return "pre-update:" + t.TargetVersion
	case PanelSnapshotTriggerKindFleet:
		return "fleet:" + t.ServerID.String()
	default:
		return "manual"
	}
}

type PanelSnapshotMeta struct {
	ID          uuid.UUID
	FilePath    string
	SizeBytes   uint64
	SHA256      string
	FromVersion string
}

type PanelSnapshotErrorKind int

const (
	PanelSnapshotErrDirInit PanelSnapshotErrorKind = iota
	PanelSnapshotErrInsufficientDisk
	PanelSnapshotErrSubprocess
	PanelSnapshotErrIo
	PanelSnapshotErrDb
	PanelSnapshotErrNotFound
	PanelSnapshotErrFileMissing
	PanelSnapshotErrSha256Mismatch
)

// PanelSnapshotError is the Rust SnapshotError enum; only the fields of its
// Kind are set.
type PanelSnapshotError struct {
	Kind                PanelSnapshotErrorKind
	Msg                 string // DirInit
	Available, Required uint64 // InsufficientDisk
	Cmd, Stderr         string // Subprocess
	Err                 error  // Io, Db
	ID                  uuid.UUID
	Path                string // FileMissing
	Expected, Actual    string // Sha256Mismatch
}

func (e *PanelSnapshotError) Error() string {
	switch e.Kind {
	case PanelSnapshotErrDirInit:
		return "snapshot dir cannot be initialized: " + e.Msg
	case PanelSnapshotErrInsufficientDisk:
		return fmt.Sprintf("insufficient disk space: %d bytes available, %d required", e.Available, e.Required)
	case PanelSnapshotErrSubprocess:
		return fmt.Sprintf("subprocess `%s` failed: %s", e.Cmd, e.Stderr)
	case PanelSnapshotErrIo:
		return fmt.Sprintf("io error: %v", e.Err)
	case PanelSnapshotErrDb:
		return fmt.Sprintf("db error: %v", e.Err)
	case PanelSnapshotErrNotFound:
		return fmt.Sprintf("snapshot %s not found", e.ID)
	case PanelSnapshotErrFileMissing:
		return "snapshot file missing on disk: " + e.Path
	default:
		return fmt.Sprintf("sha256 mismatch: expected %s, got %s", e.Expected, e.Actual)
	}
}

func (e *PanelSnapshotError) Unwrap() error { return e.Err }

func panelSnapshotIo(err error) error { return &PanelSnapshotError{Kind: PanelSnapshotErrIo, Err: err} }
func panelSnapshotDbErr(err error) error {
	return &PanelSnapshotError{Kind: PanelSnapshotErrDb, Err: err}
}
func panelSnapshotSubprocess(cmd, stderr string) error {
	return &PanelSnapshotError{Kind: PanelSnapshotErrSubprocess, Cmd: cmd, Stderr: stderr}
}

// panelSnapshotStatus runs cmd like tokio's Command::status (stdio
// inherited): a spawn failure is an Io error, otherwise the exit status
// rendered as Rust's ExitStatus Display ("exit status: N").
func panelSnapshotStatus(cmd *exec.Cmd) (ok bool, status string, err error) {
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	runErr := cmd.Run()
	var ee *exec.ExitError
	if runErr != nil && !errors.As(runErr, &ee) {
		return false, "", panelSnapshotIo(runErr)
	}
	ps := cmd.ProcessState
	if ps == nil {
		return false, "", panelSnapshotIo(runErr)
	}
	if code := ps.ExitCode(); code >= 0 {
		return code == 0, fmt.Sprintf("exit status: %d", code), nil
	}
	return false, "signal: " + ps.String(), nil
}

// PanelSnapshotCreateSnapshot builds a snapshot of the current panel state
// (binaries + DB dump + etc). Writes to a .tmp file first, computes sha256,
// renames to final, then inserts the DB row. If any earlier step fails, no row
// is written and the .tmp file is cleaned up.
func PanelSnapshotCreateSnapshot(ctx context.Context, db *pgxpool.Pool, trigger PanelSnapshotTrigger, operator *string) (*PanelSnapshotMeta, error) {
	if err := panelSnapshotEnsureDirs(); err != nil {
		return nil, err
	}
	if err := panelSnapshotCheckFreeDisk(ctx, panelSnapshotSnapshotDir, panelSnapshotMinFreeBytes); err != nil {
		return nil, err
	}

	snapshotID := uuid.New()
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	finalName := fmt.Sprintf("panel-snapshot-%s.tar.gz", timestamp)
	finalPath := filepath.Join(panelSnapshotSnapshotDir, finalName)
	tmpPath := filepath.Join(panelSnapshotSnapshotDir, finalName+".tmp")
	stagingDir := filepath.Join(panelSnapshotStagingDirParent, snapshotID.String())

	// Best-effort cleanup of any stale .tmp from a prior crashed run.
	_ = os.Remove(tmpPath)
	_ = os.RemoveAll(stagingDir)

	sizeBytes, sha, fromVersion, err := panelSnapshotBuildInner(ctx, snapshotID, stagingDir, tmpPath, finalPath, trigger, operator)

	// Always sweep staging dir, success or fail.
	_ = os.RemoveAll(stagingDir)

	if err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}

	// Persist DB row only after the file is in its final location.
	if _, err := execSQL(ctx, db,
		"INSERT INTO panel_snapshots "+
			"(id, file_path, from_version, trigger, operator, size_bytes, sha256) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7)",
		snapshotID, finalPath, fromVersion, trigger.AsStr(), operator, int64(sizeBytes), sha); err != nil {
		// DB row didn't land — remove the file so we don't leak orphans.
		_ = os.Remove(finalPath)
		return nil, panelSnapshotDbErr(err)
	}

	slog.Info(fmt.Sprintf("Created panel snapshot %s at %s (%d bytes, sha256: %s)",
		snapshotID, finalPath, sizeBytes, sha[:min(16, len(sha))]))

	return &PanelSnapshotMeta{ID: snapshotID, FilePath: finalPath, SizeBytes: sizeBytes, SHA256: sha, FromVersion: fromVersion}, nil
}

func panelSnapshotBuildInner(ctx context.Context, snapshotID uuid.UUID, stagingDir, tmpPath, finalPath string,
	trigger PanelSnapshotTrigger, operator *string) (uint64, string, string, error) {
	// Layout staging dir: binaries/ db/ etc/ metadata.json
	for _, d := range []string{"binaries", "db", "etc"} {
		if err := os.MkdirAll(filepath.Join(stagingDir, d), 0o777); err != nil {
			return 0, "", "", panelSnapshotIo(err)
		}
	}

	// Copy binaries. Size + perms aren't security-critical inside the tar
	// (extraction restores from the tar entries).
	for _, bin := range []string{"dockpanel-agent", "dockpanel-api", "dockpanel"} {
		src := "/usr/local/bin/" + bin
		if _, err := os.Stat(src); err != nil {
			slog.Warn(fmt.Sprintf("snapshot: binary %s not found, skipping", src))
			continue
		}
		if err := panelSnapshotCopyFile(src, filepath.Join(stagingDir, "binaries", bin)); err != nil {
			return 0, "", "", panelSnapshotIo(err)
		}
	}

	// Dump DB via docker exec.
	//
	// `set -o pipefail` is load-bearing, not style. The exit status of
	// `pg_dump | gzip` is gzip's, and gzip compresses a truncated stream and
	// exits 0 — so a pg_dump that died halfway produced a short dump, this
	// check passed, and the snapshot was stored with a valid sha256 over
	// incomplete contents. A backup that cannot be restored is worse than no
	// backup, because the operator believes they are covered.
	dumpPath := filepath.Join(stagingDir, "db", "dump.sql.gz")
	ok, status, err := panelSnapshotStatus(safeCommand(ctx, "bash", "-c", fmt.Sprintf(
		"set -o pipefail; docker exec dockpanel-postgres pg_dump -U dockpanel --clean --if-exists dockpanel | gzip > %s",
		panelSnapshotShellEscape(dumpPath))))
	if err != nil {
		return 0, "", "", err
	}
	if !ok {
		return 0, "", "", panelSnapshotSubprocess("pg_dump", "exit status "+status)
	}

	// And prove what we just wrote is a whole dump before we let it become a
	// snapshot. pg_dump emits this marker as its last line; its absence means
	// the dump is short no matter what the exit statuses claimed.
	//
	// Wider than the marker's current position on purpose — see the same
	// check in restore-snapshot.sh. A trailing `\unrestrict` line added by
	// PostgreSQL's August-2025 minors left the marker 5 lines from the end
	// with zero margin.
	tail, err := safeCommand(ctx, "bash", "-c", fmt.Sprintf("gunzip -c %s | tail -20", panelSnapshotShellEscape(dumpPath))).Output()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return 0, "", "", panelSnapshotIo(err)
	}
	if !strings.Contains(strings.ToValidUTF8(string(tail), "�"), "PostgreSQL database dump complete") {
		return 0, "", "", panelSnapshotSubprocess("pg_dump",
			"database dump is incomplete (completion marker absent) — "+
				"refusing to store a snapshot that could not be restored")
	}

	// Copy /etc/dockpanel into staging. The tree is small; `cp -a` preserves
	// permissions cleanly.
	ok, status, err = panelSnapshotStatus(safeCommand(ctx, "sh", "-c",
		"cp -a /etc/dockpanel/. "+panelSnapshotShellEscape(filepath.Join(stagingDir, "etc"))))
	if err != nil {
		return 0, "", "", err
	}
	if !ok {
		return 0, "", "", panelSnapshotSubprocess("cp etc", "exit status "+status)
	}

	fromVersion := Version
	metadata, _ := json.MarshalIndent(map[string]any{
		"snapshot_id":  snapshotID.String(),
		"from_version": fromVersion,
		"created_at":   time.Now().UTC().Format("2006-01-02T15:04:05.999999999-07:00"),
		"trigger":      trigger.AsStr(),
		"operator":     operator,
	}, "", "  ")
	if err := os.WriteFile(filepath.Join(stagingDir, "metadata.json"), metadata, 0o666); err != nil {
		return 0, "", "", panelSnapshotIo(err)
	}

	// Build tarball: tar -C <staging> -czf <tmp> . — -C makes entries
	// relative ("binaries/" not "<staging>/binaries/").
	ok, status, err = panelSnapshotRunCmdWithTimeout(ctx, "tar", []string{"-C", stagingDir, "-czf", tmpPath, "."}, 300*time.Second)
	if err != nil {
		return 0, "", "", err
	}
	if !ok {
		return 0, "", "", panelSnapshotSubprocess("tar -czf", "exit status "+status)
	}

	fi, err := os.Stat(tmpPath)
	if err != nil {
		return 0, "", "", panelSnapshotIo(err)
	}
	sha, err := panelSnapshotSha256Of(ctx, tmpPath)
	if err != nil {
		return 0, "", "", err
	}

	// Tighten BEFORE the rename, so the tarball is never observable at the
	// final path with a permissive mode. It carries api.env (JWT_SECRET, DB
	// password), agent.token and the agent TLS key — tar created it 0644.
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return 0, "", "", panelSnapshotIo(err)
	}
	// Atomic rename — the tar.gz only becomes "real" once this succeeds.
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return 0, "", "", panelSnapshotIo(err)
	}
	return uint64(fi.Size()), sha, fromVersion, nil
}

// panelSnapshotCopyFile is tokio::fs::copy (contents + permission bits).
func panelSnapshotCopyFile(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, b, fi.Mode().Perm()); err != nil {
		return err
	}
	return os.Chmod(dst, fi.Mode().Perm())
}

// panelSnapshotRestoreScript is the restore procedure, embedded at compile
// time. Kept as a real file so it is reviewable and testable, but compiled in
// rather than read from disk: /opt/dockpanel is not guaranteed to exist, and
// a repo-side script the binary merely *hopes* is in sync is a drift trap.
// scripts/restore-snapshot.sh here is a byte-identical copy of the repo's
// scripts/restore-snapshot.sh (a test diffs them).
//
//go:embed scripts/restore-snapshot.sh
var panelSnapshotRestoreScript string

// PanelSnapshotRestoreResultPath is where the restore writes its verdict.
// Read back by PanelSnapshotLastRestoreResult after the api has been
// restarted by the restore itself.
const PanelSnapshotRestoreResultPath = "/var/lib/dockpanel/last-restore.json"
const panelSnapshotRestoreScriptPath = "/var/lib/dockpanel/restore-snapshot.sh"

// PanelSnapshotSpawnRestore validates a snapshot and hands the restore to a
// detached, PID1-owned process.
//
// Returns as soon as the restore has been *started* — it cannot be awaited,
// because the first thing it does is stop the api process this code runs in.
// Everything cheap to check (row exists, file present, sha256 matches) is
// checked HERE, so the operator gets a real 4xx instead of a 202 then silence.
//
// History, because the shape of this function is the fix: the restore used
// to run inline in the HTTP handler. It outlived the 300s request timeout, the
// dropped request broke the `gunzip | psql` pipe, psql read that as a clean
// end of input and exited 0, and the code recorded success while the database
// had been reduced to 1 of its 92 tables.
func PanelSnapshotSpawnRestore(ctx context.Context, db *pgxpool.Pool, snapshotID uuid.UUID) error {
	snapshot, err := queryOpt[PanelSnapshot](ctx, db, "SELECT * FROM panel_snapshots WHERE id = $1", snapshotID)
	if err != nil {
		return panelSnapshotDbErr(err)
	}
	if snapshot == nil {
		return &PanelSnapshotError{Kind: PanelSnapshotErrNotFound, ID: snapshotID}
	}
	if _, err := os.Stat(snapshot.FilePath); err != nil {
		return &PanelSnapshotError{Kind: PanelSnapshotErrFileMissing, Path: snapshot.FilePath}
	}

	// Verify before we hand off. The script re-verifies (it is the one that
	// acts), but failing here turns a corrupt snapshot into a synchronous
	// error the operator sees immediately.
	actual, err := panelSnapshotSha256Of(ctx, snapshot.FilePath)
	if err != nil {
		return err
	}
	if actual != snapshot.SHA256 {
		return &PanelSnapshotError{Kind: PanelSnapshotErrSha256Mismatch, Expected: snapshot.SHA256, Actual: actual}
	}

	// NB: rolled_back_at is deliberately NOT stamped here. The restore
	// replaces panel_snapshots with the snapshot's own copy of itself, so a
	// stamp written now is overwritten and lost, and this process no longer
	// exists afterwards. The restore records it itself.
	if err := os.MkdirAll("/var/lib/dockpanel", 0o777); err != nil {
		return panelSnapshotIo(err)
	}
	if err := os.WriteFile(panelSnapshotRestoreScriptPath, []byte(panelSnapshotRestoreScript), 0o666); err != nil {
		return panelSnapshotIo(err)
	}
	if err := os.Chmod(panelSnapshotRestoreScriptPath, 0o700); err != nil {
		return panelSnapshotIo(err)
	}

	// A PID1-owned transient SERVICE, not a scope and not a bare child: this
	// process is about to stop dockpanel-api.service, which is
	// KillMode=control-group, so anything still inside that cgroup dies with
	// it. `--scope` is created in the caller's context and dies with it.
	ok, status, err := panelSnapshotStatus(safeCommand(ctx, "systemd-run",
		"--quiet",
		"--collect",
		fmt.Sprintf("--unit=dockpanel-snapshot-restore-%s", snapshotID),
		"--setenv=DOCKPANEL_RESTORE_DETACHED=1",
		fmt.Sprintf("--setenv=DOCKPANEL_SNAPSHOT_ID=%s", snapshotID),
		"--setenv=DOCKPANEL_SNAPSHOT_TARBALL="+snapshot.FilePath,
		"--setenv=DOCKPANEL_SNAPSHOT_SHA256="+snapshot.SHA256,
		"bash",
		panelSnapshotRestoreScriptPath,
	))
	if err != nil {
		return err
	}
	if !ok {
		return panelSnapshotSubprocess("systemd-run (snapshot restore)",
			"could not start the detached restore unit: exit status "+status)
	}

	slog.Info(fmt.Sprintf("Snapshot restore %s handed to transient unit "+
		"dockpanel-snapshot-restore-%s; this process will be stopped by it", snapshotID, snapshotID))
	return nil
}

// PanelSnapshotLastRestoreResult is the verdict written by the last detached
// restore, if any. The restore restarts the api, so this file is how the
// operator finds out what happened; it is written on EVERY exit path.
func PanelSnapshotLastRestoreResult() any {
	raw, err := os.ReadFile(PanelSnapshotRestoreResultPath)
	if err != nil {
		return nil
	}
	v, err := agentDecodeJSON(raw)
	if err != nil {
		return nil
	}
	return v
}

// PanelSnapshotListSnapshots lists snapshots newest-first.
func PanelSnapshotListSnapshots(ctx context.Context, db *pgxpool.Pool) ([]PanelSnapshot, error) {
	rows, err := queryAll[PanelSnapshot](ctx, db, "SELECT * FROM panel_snapshots ORDER BY created_at DESC")
	if err != nil {
		return nil, panelSnapshotDbErr(err)
	}
	return rows, nil
}

// PanelSnapshotDeleteSnapshot removes file then DB row. File-first so the row
// always reflects on-disk reality.
func PanelSnapshotDeleteSnapshot(ctx context.Context, db *pgxpool.Pool, snapshotID uuid.UUID) error {
	snapshot, err := queryOpt[PanelSnapshot](ctx, db, "SELECT * FROM panel_snapshots WHERE id = $1", snapshotID)
	if err != nil {
		return panelSnapshotDbErr(err)
	}
	if snapshot == nil {
		return &PanelSnapshotError{Kind: PanelSnapshotErrNotFound, ID: snapshotID}
	}
	_ = os.Remove(snapshot.FilePath)
	if _, err := execSQL(ctx, db, "DELETE FROM panel_snapshots WHERE id = $1", snapshotID); err != nil {
		return panelSnapshotDbErr(err)
	}
	return nil
}

// PanelSnapshotRetentionSweep keeps the most-recent PanelSnapshotRetentionMin
// regardless of age and deletes those older than PanelSnapshotRetentionDays
// beyond that floor. Returns the count removed.
func PanelSnapshotRetentionSweep(ctx context.Context, db *pgxpool.Pool) (uint32, error) {
	rows, err := queryAll[PanelSnapshot](ctx, db, "SELECT * FROM panel_snapshots ORDER BY created_at DESC")
	if err != nil {
		return 0, panelSnapshotDbErr(err)
	}
	var removed uint32
	cutoff := time.Now().Add(-time.Duration(PanelSnapshotRetentionDays) * 24 * time.Hour)
	for i, snap := range rows {
		if int64(i) < PanelSnapshotRetentionMin || !snap.CreatedAt.Before(cutoff) {
			continue
		}
		// File-first; if file delete fails, leave the row for retry.
		if err := os.Remove(snap.FilePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn(fmt.Sprintf("retention sweep: failed to delete %s: %v — keeping row", snap.FilePath, err))
			continue
		}
		if _, err := execSQL(ctx, db, "DELETE FROM panel_snapshots WHERE id = $1", snap.ID); err == nil {
			removed++
		}
	}
	if removed > 0 {
		slog.Info(fmt.Sprintf("Snapshot retention sweep removed %d aged snapshot(s)", removed))
	}
	return removed, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────

func panelSnapshotEnsureDirs() error {
	for _, d := range []string{panelSnapshotSnapshotDir, panelSnapshotStagingDirParent} {
		if err := os.MkdirAll(d, 0o777); err != nil {
			return &PanelSnapshotError{Kind: PanelSnapshotErrDirInit, Msg: fmt.Sprintf("%s: %v", d, err)}
		}
	}
	// A panel snapshot bundles /etc/dockpanel: api.env (JWT_SECRET + the
	// Postgres password), agent.token, and the agent's TLS private key. The
	// directories defaulted to 0755 and the tarballs to 0644, so any local
	// user could read the signing secret and mint an admin JWT. Lock the
	// directories down here and each tarball at creation; harden
	// retroactively so boxes with old-mode snapshots are fixed on the next one.
	for _, d := range []string{panelSnapshotSnapshotDir, panelSnapshotStagingDirParent} {
		_ = os.Chmod(d, 0o700)
	}
	if entries, err := os.ReadDir(panelSnapshotSnapshotDir); err == nil {
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".gz" {
				_ = os.Chmod(filepath.Join(panelSnapshotSnapshotDir, e.Name()), 0o600)
			}
		}
	}
	return nil
}

// panelSnapshotCheckFreeDisk refuses if the partition holding path has fewer
// than required bytes free. Shells out to `df -B1 --output=avail`; if df is
// unavailable the check fails open (warns but allows) so a stripped-down
// install still gets snapshots.
func panelSnapshotCheckFreeDisk(ctx context.Context, path string, required uint64) error {
	out, err := safeCommand(ctx, "df", "-B1", "--output=avail", path).Output()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		slog.Warn(fmt.Sprintf("df failed: %v — skipping free-disk check", err))
		return nil
	}
	lines := strings.Split(strings.ToValidUTF8(string(out), "�"), "\n")
	if len(lines) > 1 {
		if bytes, perr := strconv.ParseUint(strings.TrimSpace(strings.TrimSuffix(lines[1], "\r")), 10, 64); perr == nil {
			if bytes < required {
				return &PanelSnapshotError{Kind: PanelSnapshotErrInsufficientDisk, Available: bytes, Required: required}
			}
			return nil
		}
	}
	slog.Warn("df output unparseable — skipping free-disk check")
	return nil
}

func panelSnapshotSha256Of(ctx context.Context, path string) (string, error) {
	cmd := safeCommand(ctx, "sha256sum", path)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return "", panelSnapshotIo(err)
	}
	if err != nil {
		return "", panelSnapshotSubprocess("sha256sum", strings.ToValidUTF8(stderr.String(), "�"))
	}
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return "", panelSnapshotSubprocess("sha256sum", "no digest in stdout")
	}
	return f[0], nil
}

func panelSnapshotRunCmdWithTimeout(ctx context.Context, binary string, args []string, timeout time.Duration) (bool, string, error) {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ok, status, err := panelSnapshotStatus(safeCommand(tctx, binary, args...))
	if errors.Is(tctx.Err(), context.DeadlineExceeded) {
		return false, "", panelSnapshotSubprocess(binary, fmt.Sprintf("timed out after %ds", int(timeout.Seconds())))
	}
	return ok, status, err
}

// panelSnapshotShellEscape is a minimal shell-escape for filesystem paths.
// Paths are constructed under our own roots (no user input), but quoting
// prevents accidental whitespace problems.
func panelSnapshotShellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
