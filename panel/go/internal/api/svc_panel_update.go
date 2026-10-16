package api

// Port of panel/backend/src/services/panel_update.rs — Phase 4 W4 panel
// self-update orchestrator.
//
// Lifts scripts/update.sh's SSH-only flow into a panel-UI action. Does NOT
// reimplement the binary swap or rollback — those live in update.sh and are
// battle-tested. The orchestrator:
//
//  1. Creates a persistent snapshot (svc_panel_snapshot).
//  2. Shells out to update.sh with DOCKPANEL_NO_SELF_REFRESH=1 +
//     DOCKPANEL_VERSION=$target so one subprocess does the work.
//  3. Tracks state in two places: the in-process PanelUpdateState (fast guard
//     against concurrent applies in one process lifetime) and panel_snapshots
//     rows (cross-restart truth — the api dies mid-swap when update.sh
//     restarts services).
//  4. On the next boot, PanelUpdateFinalizePendingOnStartup closes in-flight
//     rows with to_version = this binary. Equal from/to ⇒ rollback happened.
//
// Operator-triggered rollback is PanelUpdateRollbackToSnapshot (binaries + DB
// + /etc/dockpanel, services bounced), gated behind a destructive confirm.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// panelUpdateScript: setup.sh + update.sh both lay the tree under /opt/dockpanel.
const panelUpdateScript = "/opt/dockpanel/scripts/update.sh"

// panelUpdateInFlightWindowMin: a snapshot row is "in flight" with
// to_version NULL and created inside this window; older unfinalized rows are
// dead and don't block new applies.
//
// Manual snapshots are excluded everywhere this predicate is used: they keep
// to_version NULL forever by design, so counting them made a safety snapshot
// look like an update in progress — and let the abandoned-sweep stamp them
// 'abandoned', which current_state then reported as a successful update to
// "abandoned".
const panelUpdateInFlightWindowMin = 15

// panelUpdateLogTailMax bounds the captured update.sh line kept in memory.
const panelUpdateLogTailMax = 64

// panelUpdateResultPath is where update.sh records what actually happened.
//
// The ONLY honest channel for the local path, structurally: update.sh
// re-execs into a PID1-owned transient unit with `exec systemd-run` and no
// `--wait`, so the child spawned here exits 0 within milliseconds (~29 ms
// against an update that ran 54 s). That zero describes the handoff, never the
// work. The agent side (last-agent-update.json) and the restore path
// (last-restore.json) learned this first; this sibling never had it, so a run
// that failed BEFORE the api was stopped left no trace the operator could see.
const panelUpdateResultPath = "/var/lib/dockpanel/last-panel-update.json"

// panelUpdateResultWatch: how long to watch for update.sh's verdict after the
// handoff. Matches the child-wait budget; past it, the in-flight window and
// the boot-time finalizer take over.
const panelUpdateResultWatch = 900 * time.Second

// PanelUpdateLastPanelUpdateResult is the verdict update.sh left behind, or
// nil. Permissive by construction — a half-written or absent file reads as
// "no verdict", never as a failure.
func PanelUpdateLastPanelUpdateResult() any {
	raw, err := os.ReadFile(panelUpdateResultPath)
	if err != nil {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return nil
	}
	return v
}

type panelUpdateVerdict struct {
	OK     bool
	Stage  string
	Detail string
}

// panelUpdateVerdictSince: a verdict for a run that finished at or after
// since. The bound stops a PREVIOUS update's verdict being read as this one's
// — the file is overwritten in place.
func panelUpdateVerdictSince(since time.Time) *panelUpdateVerdict {
	v := PanelUpdateLastPanelUpdateResult()
	if v == nil {
		return nil
	}
	return panelUpdateVerdictFromValue(v, since)
}

// panelUpdateVerdictFromValue is the parsing half, split out so it is tested
// against the exact bytes update.sh writes (the writer is shell, the reader is
// Go — a fixture invented on this side would pin the invention).
func panelUpdateVerdictFromValue(v any, since time.Time) *panelUpdateVerdict {
	fs, ok := jsonStr(jsonGet(v, "finished_at"))
	if !ok {
		return nil
	}
	finished, err := time.Parse(time.RFC3339Nano, fs)
	if err != nil {
		return nil
	}
	// One second of slack: the file carries whole seconds, so a run that
	// starts and fails inside the same second would otherwise be discarded.
	if finished.Add(time.Second).Before(since) {
		return nil
	}
	okv, isBool := jsonBool(jsonGet(v, "ok"))
	if !isBool {
		return nil
	}
	stage, has := jsonStr(jsonGet(v, "stage"))
	if !has {
		stage = "unknown"
	}
	detail, has := jsonStr(jsonGet(v, "detail"))
	if !has {
		detail = "no detail recorded"
	}
	return &panelUpdateVerdict{OK: okv, Stage: stage, Detail: detail}
}

// ── State ────────────────────────────────────────────────────────────────

// PanelUpdateUpdateState is the Rust `#[serde(tag = "state")]` enum. Kind is
// one of idle | in_flight | succeeded | rolled_back | failed; only that
// variant's fields are serialized.
type PanelUpdateUpdateState struct {
	Kind string
	// in_flight: update.sh is executing. The orchestrator may not survive the
	// api binary swap, so the DB row is the durable signal.
	TargetVersion string
	SnapshotID    uuid.UUID
	StartedAt     time.Time
	LastLogLine   *string
	// succeeded: reconstructed from the snapshot row after the api reboots
	// into the new version (from != to).
	FromVersion string
	ToVersion   string
	CompletedAt time.Time
	// rolled_back: update.sh's in-flight .bak rollback fired and the api came
	// back on the original binary.
	AttemptedVersion string
	// failed: the orchestrator failed before update.sh could run.
	Reason string
	At     time.Time
}

func (s PanelUpdateUpdateState) MarshalJSON() ([]byte, error) {
	var v any
	switch s.Kind {
	case "in_flight":
		v = struct {
			State         string    `json:"state"`
			TargetVersion string    `json:"target_version"`
			SnapshotID    uuid.UUID `json:"snapshot_id"`
			StartedAt     time.Time `json:"started_at"`
			LastLogLine   *string   `json:"last_log_line"`
		}{s.Kind, s.TargetVersion, s.SnapshotID, s.StartedAt, s.LastLogLine}
	case "succeeded":
		v = struct {
			State       string    `json:"state"`
			FromVersion string    `json:"from_version"`
			ToVersion   string    `json:"to_version"`
			CompletedAt time.Time `json:"completed_at"`
		}{s.Kind, s.FromVersion, s.ToVersion, s.CompletedAt}
	case "rolled_back":
		v = struct {
			State            string    `json:"state"`
			AttemptedVersion string    `json:"attempted_version"`
			SnapshotID       uuid.UUID `json:"snapshot_id"`
			CompletedAt      time.Time `json:"completed_at"`
		}{s.Kind, s.AttemptedVersion, s.SnapshotID, s.CompletedAt}
	case "failed":
		v = struct {
			State  string    `json:"state"`
			Reason string    `json:"reason"`
			At     time.Time `json:"at"`
		}{s.Kind, s.Reason, s.At}
	default:
		v = struct {
			State string `json:"state"`
		}{"idle"}
	}
	return rtWsMetricsMarshal(v), nil
}

func panelUpdateIdle() PanelUpdateUpdateState { return PanelUpdateUpdateState{Kind: "idle"} }

// PanelUpdateStateHandle is Arc<RwLock<UpdateState>>.
type PanelUpdateStateHandle struct {
	mu sync.RWMutex
	s  PanelUpdateUpdateState
}

func PanelUpdateNewStateHandle() *PanelUpdateStateHandle {
	return &PanelUpdateStateHandle{s: panelUpdateIdle()}
}

func (h *PanelUpdateStateHandle) get() PanelUpdateUpdateState {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.s
}

func (h *PanelUpdateStateHandle) set(s PanelUpdateUpdateState) {
	h.mu.Lock()
	h.s = s
	h.mu.Unlock()
}

// PanelUpdateState is the process's orchestrator state (Rust
// AppState.panel_update_state — module-owned per PORTING.md).
var PanelUpdateState = PanelUpdateNewStateHandle()

// ── Validation ───────────────────────────────────────────────────────────

func panelUpdateAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// PanelUpdateValidateTargetVersion accepts vX.Y.Z, X.Y.Z, vX.Y.Z-rc.N,
// X.Y.Z-rc.N. No other shapes.
func PanelUpdateValidateTargetVersion(v string) bool {
	v = strings.TrimLeft(v, "v")
	core, suffix, hasSuffix := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if !panelUpdateAllDigits(p) {
			return false
		}
	}
	if hasSuffix {
		n, ok := strings.CutPrefix(suffix, "rc.")
		if !ok || !panelUpdateAllDigits(n) {
			return false
		}
	}
	return true
}

// ── Errors ───────────────────────────────────────────────────────────────

type PanelUpdateErrKind int

const (
	PanelUpdateErrInvalidTargetVersion PanelUpdateErrKind = iota
	PanelUpdateErrAlreadyInFlight
	PanelUpdateErrScriptMissing
	PanelUpdateErrSnapshot
	PanelUpdateErrSpawn
	PanelUpdateErrDb
)

// PanelUpdateOrchestratorError is the Rust OrchestratorError. Msg carries the
// variant's string payload; Err the wrapped snapshot/spawn/db error (Unwrap
// exposes it, so errors.Is against snapshot sentinels works through it).
type PanelUpdateOrchestratorError struct {
	Kind PanelUpdateErrKind
	Msg  string
	Err  error
}

func (e *PanelUpdateOrchestratorError) Error() string {
	switch e.Kind {
	case PanelUpdateErrInvalidTargetVersion:
		return "invalid target version: " + e.Msg
	case PanelUpdateErrAlreadyInFlight:
		return "another update is already in flight (check /api/update/status)"
	case PanelUpdateErrScriptMissing:
		return "update script not found at " + e.Msg
	case PanelUpdateErrSnapshot:
		return fmt.Sprintf("snapshot failed: %v", e.Err)
	case PanelUpdateErrSpawn:
		return fmt.Sprintf("failed to spawn update.sh: %v", e.Err)
	}
	return fmt.Sprintf("db error: %v", e.Err)
}

func (e *PanelUpdateOrchestratorError) Unwrap() error { return e.Err }

// ── Public API ───────────────────────────────────────────────────────────

func panelUpdateParseTargetFromTrigger(trigger string) (string, bool) {
	return strings.CutPrefix(trigger, "pre-update:")
}

// PanelUpdateCurrentState resolves the current state. In-memory Idle may be a
// lie if a prior process died mid-update, so the DB is cross-checked.
func PanelUpdateCurrentState(ctx context.Context, h *PanelUpdateStateHandle, db *pgxpool.Pool) PanelUpdateUpdateState {
	if s := h.get(); s.Kind != "idle" {
		return s
	}
	// Manual snapshots never carry a to_version, so they must be excluded or a
	// safety snapshot would masquerade as an update in progress.
	cutoff := time.Now().Add(-panelUpdateInFlightWindowMin * time.Minute)
	if snap, err := queryOpt[PanelSnapshot](ctx, db,
		"SELECT * FROM panel_snapshots "+
			"WHERE to_version IS NULL AND trigger <> 'manual' AND created_at > $1 "+
			"ORDER BY created_at DESC LIMIT 1", cutoff); err == nil && snap != nil {
		target, _ := panelUpdateParseTargetFromTrigger(snap.Trigger)
		return PanelUpdateUpdateState{Kind: "in_flight", TargetVersion: target, SnapshotID: snap.ID, StartedAt: snap.CreatedAt}
	}

	// The newest finalized snapshot says whether the last update succeeded or
	// rolled back (read-only summary for the UI).
	if snap, err := queryOpt[PanelSnapshot](ctx, db,
		"SELECT * FROM panel_snapshots "+
			"WHERE to_version IS NOT NULL "+
			"ORDER BY created_at DESC LIMIT 1"); err == nil && snap != nil {
		from := snap.FromVersion
		to := ""
		if snap.ToVersion != nil {
			to = *snap.ToVersion
		}
		attempted, ok := panelUpdateParseTargetFromTrigger(snap.Trigger)
		if !ok {
			attempted = to
		}
		if to == from && attempted != from {
			return PanelUpdateUpdateState{Kind: "rolled_back", AttemptedVersion: attempted, SnapshotID: snap.ID, CompletedAt: snap.CreatedAt}
		}
		if to != from {
			// The row is stamped by whichever binary booted after the swap —
			// ~30s BEFORE update.sh's health check decides whether the new build
			// is good. On a rollback the new api stamps itself "succeeded", then
			// fails its health check and is replaced; nothing revisits the row,
			// so the panel reported success to a version it is demonstrably not
			// running (lab: to_version=2.11.3 beside current_version=2.11.2 in
			// ONE response). The running binary is ground truth.
			if to != Version {
				return PanelUpdateUpdateState{Kind: "rolled_back", AttemptedVersion: to, SnapshotID: snap.ID, CompletedAt: snap.CreatedAt}
			}
			return PanelUpdateUpdateState{Kind: "succeeded", FromVersion: from, ToVersion: to, CompletedAt: snap.CreatedAt}
		}
	}
	return panelUpdateIdle()
}

// PanelUpdateStartPanelUpdate starts the self-update: validate + in-flight
// guard, snapshot (trigger=pre-update:<target>), spawn update.sh detached in
// its own process group, and stream its output into last_log_line. Returns
// the InFlight state; progress is observed by polling PanelUpdateCurrentState.
func PanelUpdateStartPanelUpdate(ctx context.Context, h *PanelUpdateStateHandle, db *pgxpool.Pool, targetVersion string, operator *string) (PanelUpdateUpdateState, error) {
	targetVersion = strings.TrimSpace(targetVersion)
	if !PanelUpdateValidateTargetVersion(targetVersion) {
		return PanelUpdateUpdateState{}, &PanelUpdateOrchestratorError{Kind: PanelUpdateErrInvalidTargetVersion, Msg: targetVersion}
	}
	if _, err := os.Stat(panelUpdateScript); err != nil {
		return PanelUpdateUpdateState{}, &PanelUpdateOrchestratorError{Kind: PanelUpdateErrScriptMissing, Msg: panelUpdateScript}
	}

	// TOCTOU fix (v2.216.0 audit): the guard used to be read-check-then-later-
	// write with create_snapshot's multi-minute pipeline inside the gap, so a
	// double-click, a retry or two admin sessions both spawned an update.
	// Reserve InFlight atomically under ONE lock acquisition before any async
	// work; nil snapshot id until the real one exists; released on failure so
	// a legitimate retry isn't locked out by this call's own failed attempt.
	reservedAt := time.Now().UTC()
	h.mu.Lock()
	if h.s.Kind == "in_flight" {
		h.mu.Unlock()
		return PanelUpdateUpdateState{}, &PanelUpdateOrchestratorError{Kind: PanelUpdateErrAlreadyInFlight}
	}
	h.s = PanelUpdateUpdateState{Kind: "in_flight", TargetVersion: targetVersion, SnapshotID: uuid.Nil, StartedAt: reservedAt}
	h.mu.Unlock()

	// Same exclusion as PanelUpdateCurrentState: a manual snapshot is not an
	// update and must not lock out what an operator does right after taking it.
	cutoff := time.Now().Add(-panelUpdateInFlightWindowMin * time.Minute)
	n, err := queryScalar[int64](ctx, db,
		"SELECT COUNT(*) FROM panel_snapshots "+
			"WHERE to_version IS NULL AND trigger <> 'manual' AND created_at > $1", cutoff)
	if err != nil {
		// (Rust's `?` here returned without releasing the reservation.)
		return PanelUpdateUpdateState{}, &PanelUpdateOrchestratorError{Kind: PanelUpdateErrDb, Err: err}
	}
	if n > 0 {
		h.set(panelUpdateIdle())
		return PanelUpdateUpdateState{}, &PanelUpdateOrchestratorError{Kind: PanelUpdateErrAlreadyInFlight}
	}

	// Pre-update snapshot. On failure release the reservation — nothing started.
	meta, err := PanelSnapshotCreateSnapshot(ctx, db, PanelSnapshotTriggerPreUpdate(targetVersion), operator)
	if err != nil {
		h.set(panelUpdateIdle())
		return PanelUpdateUpdateState{}, &PanelUpdateOrchestratorError{Kind: PanelUpdateErrSnapshot, Err: err}
	}

	startedAt := reservedAt
	inFlight := PanelUpdateUpdateState{Kind: "in_flight", TargetVersion: targetVersion, SnapshotID: meta.ID, StartedAt: startedAt}
	h.set(inFlight)

	// Detached process group so `systemctl stop dockpanel-api` (issued by
	// update.sh) doesn't propagate SIGTERM to the script. Not bound to any
	// request context: nothing may kill it.
	cmd := safeCommand(context.Background(), "bash", panelUpdateScript)
	cmd.Env = append(cmd.Env,
		"INSTALL_FROM_RELEASE=1",
		"DOCKPANEL_NO_SELF_REFRESH=1",
		// update.sh concatenates DOCKPANEL_VERSION straight into the release
		// URL and documents it as vX.Y.Z, but the poller stores the version
		// with the `v` stripped. Passed verbatim it built
		// releases/download/2.11.2/…, a 404 — every self-update died at the
		// first curl (exit 22) before any swap. Re-add the prefix here.
		"DOCKPANEL_VERSION=v"+strings.TrimLeft(targetVersion, "v"),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err1 := cmd.StdoutPipe()
	stderr, err2 := cmd.StderrPipe()
	if err := errors.Join(err1, err2); err != nil {
		return PanelUpdateUpdateState{}, &PanelUpdateOrchestratorError{Kind: PanelUpdateErrSpawn, Err: err}
	}
	if err := cmd.Start(); err != nil {
		return PanelUpdateUpdateState{}, &PanelUpdateOrchestratorError{Kind: PanelUpdateErrSpawn, Err: err}
	}

	snapshotID := meta.ID
	go func() {
		bg := context.Background()
		panelUpdateStreamOutput(h, stdout, stderr)
		// We may not reach here — update.sh kills the api midway. A NON-zero
		// exit is real information: the script (or PID1) refused outright, so
		// the update definitively did not happen. A ZERO exit means only that
		// the work was handed off — it is never "the work succeeded", because
		// `exec systemd-run` without `--wait` returns the moment PID1 accepts
		// the job (lesson #49).
		waited := make(chan error, 1)
		go func() { waited <- cmd.Wait() }()
		handedOff := false
		select {
		case err := <-waited:
			var ee interface{ ExitCode() int }
			switch {
			case err == nil:
				slog.Info(fmt.Sprintf("update.sh (target %s) child exited with exit status: 0", targetVersion))
				handedOff = true
			case errors.As(err, &ee):
				slog.Info(fmt.Sprintf("update.sh (target %s) child exited with %v", targetVersion, err))
				slog.Error(fmt.Sprintf("update.sh (target %s) could not start (%v) — panel left on the previous version", targetVersion, err))
			default:
				slog.Warn(fmt.Sprintf("update.sh wait failed: %v", err))
			}
		case <-time.After(panelUpdateResultWatch):
			slog.Warn("update.sh wait timed out after 15min")
		}

		// Ask the updater what happened, not the process that launched it. If
		// the update SUCCEEDS this loop never finishes: update.sh stops
		// dockpanel-api (this process) and the next boot's finalizer closes the
		// row. The case rescued is a failure BEFORE the api is stopped, where no
		// restart will ever come to close anything.
		var verdict *panelUpdateVerdict
		if handedOff {
			deadline := time.Now().Add(panelUpdateResultWatch)
			for time.Now().Before(deadline) {
				if v := panelUpdateVerdictSince(startedAt); v != nil {
					verdict = v
					break
				}
				time.Sleep(5 * time.Second)
			}
		}
		switch {
		case verdict != nil && verdict.OK:
			// Recorded success while this process is somehow alive. Leave the
			// row: the restart proves a version change, and the finalizer reads
			// it from the running binary.
			slog.Info(fmt.Sprintf("update.sh (target %s) recorded success; awaiting restart", targetVersion))
		case verdict != nil:
			slog.Error(fmt.Sprintf("update.sh (target %s) FAILED at stage '%s': %s", targetVersion, verdict.Stage, verdict.Detail))
			panelUpdateFinalizeFailedUpdate(bg, db, h, snapshotID)
		default:
			// No verdict and no restart: PID1 refused the handoff, or the
			// updater died too hard to write its result. Both leave the panel
			// on its starting version and a row nothing else will ever close.
			slog.Error(fmt.Sprintf("update.sh (target %s) left no verdict and this process was never restarted — treating the update as failed", targetVersion))
			panelUpdateFinalizeFailedUpdate(bg, db, h, snapshotID)
		}
	}()

	return inFlight, nil
}

// panelUpdateFinalizeFailedUpdate closes out an update that did not land:
// back to Idle, and to_version = the version STILL running, which
// PanelUpdateCurrentState reads as RolledBack. Without it the operator stared
// at an in-flight update until the 15-minute window lapsed.
func panelUpdateFinalizeFailedUpdate(ctx context.Context, db *pgxpool.Pool, h *PanelUpdateStateHandle, snapshotID uuid.UUID) {
	h.set(panelUpdateIdle())
	if _, err := execSQL(ctx, db,
		"UPDATE panel_snapshots SET to_version = $1 WHERE id = $2 AND to_version IS NULL", Version, snapshotID); err != nil {
		slog.Warn("failed to finalize failed-update snapshot: " + err.Error())
	}
}

// panelUpdateStreamOutput streams update.sh stdout + stderr into
// last_log_line until both pipes hit EOF (typically: the api is being killed).
func panelUpdateStreamOutput(h *PanelUpdateStateHandle, stdout, stderr io.Reader) {
	var wg sync.WaitGroup
	pump := func(r io.Reader, warn bool) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSuffix(sc.Text(), "\r")
			if line == "" {
				continue
			}
			panelUpdateUpdateLastLog(h, line)
			if warn {
				slog.Warn(line, "target", "panel_update")
			} else {
				slog.Info(line, "target", "panel_update")
			}
		}
	}
	wg.Add(2)
	go pump(stdout, false)
	go pump(stderr, true)
	wg.Wait()
}

func panelUpdateUpdateLastLog(h *PanelUpdateStateHandle, line string) {
	if len(line) > panelUpdateLogTailMax*4 {
		if r := []rune(line); len(r) > panelUpdateLogTailMax*4 {
			line = string(r[:panelUpdateLogTailMax*4])
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.s.Kind == "in_flight" {
		l := line
		h.s.LastLogLine = &l
	}
}

// PanelUpdateRollbackToSnapshot validates the snapshot, then hands the whole
// restore (stop services, database, binaries, /etc, start services) to a
// detached PID1-owned unit and returns. It CANNOT be awaited: the restore
// stops this very process. The outcome is read back from
// PanelSnapshotLastRestoreResult once the panel is up again.
//
// Until v2.11.5 the restore ran INLINE in the handler: it raced the 300s HTTP
// timeout (a restore measured 394.9s), dropping it broke `gunzip | psql`,
// which psql read as a normal end of input and exited 0 — and the database
// was left with 1 of 92 tables while the panel reported success. Now the work
// is detached and the database stage is atomic and verified.
func PanelUpdateRollbackToSnapshot(ctx context.Context, h *PanelUpdateStateHandle, db *pgxpool.Pool, snapshotID uuid.UUID) error {
	// Concurrent-apply guard (v2.216.0 audit): rollback used to carry NO check
	// against an in-flight update, racing update.sh's binary swap against
	// restore-snapshot.sh's on the same files. Held for the restore's duration.
	h.mu.Lock()
	if h.s.Kind == "in_flight" {
		h.mu.Unlock()
		return &PanelUpdateOrchestratorError{Kind: PanelUpdateErrAlreadyInFlight}
	}
	h.s = PanelUpdateUpdateState{Kind: "in_flight", TargetVersion: "rollback:" + snapshotID.String(), SnapshotID: snapshotID, StartedAt: time.Now().UTC()}
	h.mu.Unlock()
	// Everything cheap is validated synchronously (row, file, sha256) so the
	// operator gets a real 4xx now rather than a 202 and a file to hunt for.
	if err := PanelSnapshotSpawnRestore(ctx, db, snapshotID); err != nil {
		// Validation failed before any file operation — release. A restore past
		// validation ends this process or resolves via the startup finalizer.
		h.set(panelUpdateIdle())
		return &PanelUpdateOrchestratorError{Kind: PanelUpdateErrSnapshot, Err: err}
	}
	return nil
}

// PanelUpdateFinalizePendingOnStartup closes in-flight snapshot rows with
// to_version = this binary. Equal from/to = update.sh rolled back; differing =
// a successful apply.
func PanelUpdateFinalizePendingOnStartup(ctx context.Context, db *pgxpool.Pool) {
	cutoff := time.Now().Add(-panelUpdateInFlightWindowMin * time.Minute)
	pending, err := queryAll[PanelSnapshot](ctx, db,
		"SELECT * FROM panel_snapshots "+
			"WHERE to_version IS NULL AND trigger <> 'manual' AND created_at > $1 "+
			"ORDER BY created_at ASC", cutoff)
	if err != nil {
		slog.Warn("finalize_pending: read failed: " + err.Error())
		return
	}
	for _, snap := range pending {
		if _, err := execSQL(ctx, db, "UPDATE panel_snapshots SET to_version = $1 WHERE id = $2", Version, snap.ID); err != nil {
			slog.Warn(fmt.Sprintf("finalize_pending: row %s update failed: %v", snap.ID, err))
			continue
		}
		if Version == snap.FromVersion {
			slog.Warn(fmt.Sprintf("Snapshot %s finalized as rolled-back (process restarted on pre-update version %s)", snap.ID, Version))
		} else {
			slog.Info(fmt.Sprintf("Snapshot %s finalized as succeeded (%s -> %s)", snap.ID, snap.FromVersion, Version))
		}
	}
	// Mark older abandoned in-flight rows so they don't block apply forever.
	// Manual snapshots are exempt — stamping one 'abandoned' made it the newest
	// finalized row, read as a completed update to a version called "abandoned".
	if _, err := execSQL(ctx, db,
		"UPDATE panel_snapshots SET to_version = 'abandoned' "+
			"WHERE to_version IS NULL AND trigger <> 'manual' AND created_at <= $1", cutoff); err != nil {
		slog.Warn("finalize_pending: abandoned-sweep failed: " + err.Error())
	}
}

// ── Fleet (§4.5) ─────────────────────────────────────────────────────────
//
// Operator-initiated rolling update across the remote agents: oldest
// agent_version first (servers unseen for 5 min excluded), POST /panel/update
// to each, wait for it to RUN the target, record per-server progress in
// fleet_update_runs.progress. Halts on first failure unless told otherwise.
// Per design memo §3.D5, include_panel defaults false: the fleet rolls first,
// the panel itself last.

type PanelUpdateFleetPlanRow struct {
	ServerID     uuid.UUID `json:"server_id"`
	Name         string    `json:"name"`
	AgentVersion *string   `json:"agent_version"`
}

type PanelUpdateFleetProgressRow struct {
	ServerID   uuid.UUID `json:"server_id"`
	Status     string    `json:"status"` // pending | updating | succeeded | failed | skipped
	DurationMs *int64    `json:"duration_ms"`
	Error      *string   `json:"error"`
}

// PanelUpdateBuildFleetPlan: oldest version first, ties by last_seen_at desc;
// skips servers staler than 5 minutes and those already at the target.
//
// isAdmin widens `user_id = $1` to the whole fleet — servers.user_id names
// whoever registered the row, not a tenant boundary. Without it (v2.216.0
// audit) a fleet run silently skipped every server a DIFFERENT admin had
// registered, with nothing saying the plan was incomplete.
func PanelUpdateBuildFleetPlan(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, isAdmin bool, targetVersion string) ([]PanelUpdateFleetPlanRow, error) {
	targetClean := strings.TrimLeft(targetVersion, "v")
	// NOT ordered in SQL: agent_version is text, so postgres would put 2.9.0
	// AFTER 2.10.0 and roll the newest box first while calling it the oldest.
	rows, err := queryAll[Tup3[uuid.UUID, string, *string]](ctx, db,
		"SELECT id, name, agent_version FROM servers "+
			"WHERE ($2 OR user_id = $1) "+
			"AND last_seen_at > NOW() - INTERVAL '5 minutes' "+
			"AND is_local = false "+
			"ORDER BY last_seen_at DESC", userID, isAdmin)
	if err != nil {
		return nil, err
	}
	plan := []PanelUpdateFleetPlanRow{}
	for _, r := range rows {
		if r.C != nil && strings.TrimLeft(*r.C, "v") == targetClean {
			continue
		}
		plan = append(plan, PanelUpdateFleetPlanRow{ServerID: r.A, Name: r.B, AgentVersion: r.C})
	}
	// Oldest first, unknown version first (never reported = most suspect).
	// The stable sort keeps last_seen_at DESC within a version.
	sort.SliceStable(plan, func(i, j int) bool {
		a, b := PanelUpdateSemverKey(plan[i].AgentVersion), PanelUpdateSemverKey(plan[j].AgentVersion)
		return slices.Compare(a[:], b[:]) < 0
	})
	return plan, nil
}

// PanelUpdateSemverKey is a sortable key for X.Y.Z (optionally v-prefixed):
// [present, major, minor, patch]; nil sorts first. Unparseable parts read as
// 0, which keeps a malformed row from jumping to the end of the queue. Compare
// with slices.Compare(a[:], b[:]).
func PanelUpdateSemverKey(v *string) [4]uint64 {
	if v == nil {
		return [4]uint64{}
	}
	core := strings.TrimLeft(*v, "v")
	core, _, _ = strings.Cut(core, "-")
	parts := strings.Split(core, ".")
	k := [4]uint64{1}
	for i := 0; i < 3 && i < len(parts); i++ {
		p := parts[i]
		if len(p) > 1 && p[0] == '+' { // Rust's u64 parse accepts a leading '+'
			p = p[1:]
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err == nil {
			k[i+1] = n
		}
	}
	return k
}

func panelUpdateProgressJSON(p []PanelUpdateFleetProgressRow) json.RawMessage {
	b, err := json.Marshal(p)
	if err != nil {
		return json.RawMessage("[]")
	}
	return b
}

// PanelUpdateCreateFleetRun inserts the fleet_update_runs row; the caller then
// spawns PanelUpdateExecuteFleetPlan.
func PanelUpdateCreateFleetRun(ctx context.Context, db *pgxpool.Pool, targetVersion string, plan []PanelUpdateFleetPlanRow, haltOnFailure, includePanel bool, startedBy *uuid.UUID) (uuid.UUID, error) {
	planJSON, err := json.Marshal(append([]PanelUpdateFleetPlanRow{}, plan...))
	if err != nil {
		planJSON = []byte("[]")
	}
	progress := make([]PanelUpdateFleetProgressRow, 0, len(plan))
	for _, p := range plan {
		progress = append(progress, PanelUpdateFleetProgressRow{ServerID: p.ServerID, Status: "pending"})
	}
	return queryScalar[uuid.UUID](ctx, db,
		"INSERT INTO fleet_update_runs "+
			"(target_version, plan, progress, halt_on_failure, include_panel, started_by) "+
			"VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
		targetVersion, json.RawMessage(planJSON), panelUpdateProgressJSON(progress), haltOnFailure, includePanel, startedBy)
}

// PanelUpdateExecuteFleetPlan walks the plan, updates each server, records
// progress and the terminal outcome. Long-running — run in a goroutine.
// includePanel non-nil = also self-update the panel once the fleet fully
// succeeded.
func PanelUpdateExecuteFleetPlan(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, runID uuid.UUID, plan []PanelUpdateFleetPlanRow, targetVersion string, haltOnFailure bool, includePanel *PanelUpdateStateHandle) {
	progress := make([]PanelUpdateFleetProgressRow, len(plan))
	for i, p := range plan {
		progress[i] = PanelUpdateFleetProgressRow{ServerID: p.ServerID, Status: "pending"}
	}
	persist := func() {
		_, _ = execSQL(ctx, db, "UPDATE fleet_update_runs SET progress = $1 WHERE id = $2", panelUpdateProgressJSON(progress), runID)
	}
	anyFailed, halted := false, false
	for i, row := range plan {
		if halted {
			progress[i].Status = "skipped"
			continue
		}
		started := time.Now()
		progress[i].Status = "updating"
		persist()
		err := panelUpdateUpdateOneServer(ctx, agents, row.ServerID, targetVersion)
		ms := time.Since(started).Milliseconds()
		progress[i].DurationMs = &ms
		if err == nil {
			progress[i].Status = "succeeded"
		} else {
			progress[i].Status = "failed"
			e := err.Error()
			progress[i].Error = &e
			anyFailed = true
			if haltOnFailure {
				halted = true
			}
		}
		persist()
	}
	outcome := "success"
	if anyFailed {
		outcome = "partial"
		if halted {
			outcome = "halted"
		}
	}
	_, _ = execSQL(ctx, db, "UPDATE fleet_update_runs SET finished_at = NOW(), outcome = $1 WHERE id = $2", outcome, runID)
	slog.Info(fmt.Sprintf("Fleet update run %s completed with outcome %s", runID, outcome))

	// include_panel was stored on the run row and read by nothing — the
	// checkbox was inert since v2.10.0. Honoured now, and only when every
	// member made it: updating the panel on top of a half-rolled fleet is the
	// one ordering the design rules out.
	if includePanel == nil {
		return
	}
	if anyFailed {
		slog.Warn(fmt.Sprintf("Fleet run %s: include_panel was requested but the fleet did not fully succeed (%s) — leaving the panel on its current version", runID, outcome))
		return
	}
	if _, err := PanelUpdateStartPanelUpdate(ctx, includePanel, db, targetVersion, nil); err != nil {
		slog.Error(fmt.Sprintf("Fleet run %s: fleet complete but the panel self-update could not start: %v", runID, err))
	} else {
		slog.Info(fmt.Sprintf("Fleet run %s: fleet complete, panel self-update to %s started", runID, targetVersion))
	}
}

// panelUpdateUpdateOneServer POSTs /panel/update, then waits for the agent to
// actually be RUNNING the target. Returns nil only on that observation.
//
// It used to trust the agent's own `/panel/update/status` "succeeded" — a
// process-local state set from systemd-run's exit status, which is 0 the
// instant PID1 accepts the job: the s232 lab recorded a member as succeeded in
// 5.1s while it never left 2.11.2. A restart is a step, not an outcome (lesson
// #49); the only honest evidence is the version the agent reports for itself
// afterwards (W4 design §4.5: "Polls /health for the new version").
func panelUpdateUpdateOneServer(ctx context.Context, agents *AgentRegistry, serverID uuid.UUID, targetVersion string) error {
	handle, err := agents.ForServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("agent handle: %v", err)
	}
	// Normalise to the vX.Y.Z tag spelling here, as the local path does: a bare
	// `2.11.4` reached the agent verbatim and update.sh built a 404 URL. The
	// agent's own bare-semver heal does not rescue it — fleet targets are by
	// definition OLDER builds whose on-disk update.sh predates it.
	normalized := "v" + strings.TrimLeft(targetVersion, "v")
	if _, err := handle.Post(ctx, "/panel/update", map[string]any{"target_version": normalized}); err != nil {
		raw := err.Error()
		// Agents before 2.11.8 could only run the PANEL updater, absent on an
		// agent-only box; say what to do instead of naming a missing path.
		if strings.Contains(raw, "update script not found") {
			return fmt.Errorf("this agent is too old to be updated from the panel (it looks for the panel "+
				"updater, which agent-only boxes do not have). Re-run install-agent.sh on it "+
				"once to reach 2.11.8+, after which fleet updates work — original error: %s", raw)
		}
		return fmt.Errorf("POST /panel/update: %s", raw)
	}

	// ~10 min: the agent downloads a ~21MB binary, restarts, comes back.
	targetClean := strings.TrimLeft(targetVersion, "v")
	deadline := time.Now().Add(600 * time.Second)
	lastSeen := ""
	for time.Now().Before(deadline) {
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
		// GROUND TRUTH first: /health is served by whichever binary is running.
		// Connection errors are expected (the agent restarts itself) and are
		// never failure.
		if health, err := handle.Get(ctx, "/health"); err == nil {
			if v, ok := jsonStr(jsonGet(health, "version")); ok {
				lastSeen = v
				if strings.TrimLeft(v, "v") == targetClean {
					return nil
				}
			}
		}
		// The agent's own report is trusted only when it says something went
		// WRONG — a claim it can make honestly, unlike success.
		if resp, err := handle.Get(ctx, "/panel/update/status"); err == nil {
			state, _ := jsonStr(jsonGet(resp, "state"))
			if state == "failed" || state == "rolled_back" {
				reason, ok := jsonStr(jsonGet(resp, "reason"))
				if !ok {
					reason = "unspecified"
				}
				return fmt.Errorf("agent reported %s: %s", state, reason)
			}
		}
	}
	if lastSeen == "" {
		lastSeen = "nothing"
	}
	return fmt.Errorf("timed out after 10min — agent still reports version %s, wanted %s", lastSeen, targetClean)
}
