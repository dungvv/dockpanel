// Phase 4 W4: agent-side panel-update receiver.
//
// When the central panel orchestrator pushes a fleet update to a remote
// server, it POSTs /panel/update here. This handler hands the work to a
// PID1-owned transient unit and returns immediately; the orchestrator then
// confirms the outcome from /health, not from anything this file says about
// itself.
//
// Distinct from routes/updates (OS-package apt-get management); this is panel
// self-update specifically.
//
// What this used to do, and why it was wrong (s232, measured on a lab):
// it ran /opt/dockpanel/scripts/update.sh. Two defects, and the second is why
// the first could not just be patched by shipping the repo:
//
//  1. install-agent.sh never creates /opt/dockpanel. Every fleet update against
//     a real agent-only box died in 166 ms with `500: update script not found`,
//     and that installer is the only documented way to add a remote server — so
//     the feature never worked on any box it targeted.
//  2. update.sh is the *panel* updater: it wants a git repo, a postgres
//     container, an API, a frontend, nginx. Planting the repo and re-running it
//     produced `No such container: dockpanel-postgres` → `Database backup
//     failed, aborting upgrade` — one second *after* the panel had recorded the
//     server as succeeded, because update.sh re-execs itself into a transient
//     unit with `exec systemd-run` (no --wait), so the child this file waits on
//     exits 0 the moment PID1 *accepts* the job. Status was being derived from
//     the wrong process (lesson #49), and fixing only (1) would have converted a
//     loud safe failure into a silent false success on every box in a fleet
//     (lesson #50).
//
// So: agent boxes get an agent-only update (scripts/agent-self-update.sh,
// embedded below), full panel installs keep update.sh, and success is never
// inferred from a child's exit status.

package routes

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// panelUpdateUpdateScript is the panel updater, present only on full DockPanel installs.
const panelUpdateUpdateScript = "/opt/dockpanel/scripts/update.sh"

// panelUpdateAPIBin is present on a full install only; used to tell a panel box from an agent box.
const panelUpdateAPIBin = "/usr/local/bin/dockpanel-api"

// panelUpdateAgentUpdateScript is the agent-only updater. Compiled in rather
// than read from disk for the same reason the restore procedure is (lessons
// #35/#38): a remote agent box has no repo, and a script the running binary
// merely hopes is in sync is drift. Kept byte-identical to
// scripts/agent-self-update.sh (enforced by a test).
//
//go:embed agent-self-update.sh
var panelUpdateAgentUpdateScript string

const panelUpdateAgentUpdateScriptPath = "/var/lib/dockpanel/agent-self-update.sh"

// panelUpdateAgentUpdateResultPath is where agent-self-update.sh records what
// actually happened. Read back after the restart it performs, because the
// agent's in-memory state does not survive its own update. A var only so
// tests can point it at a scratch file.
var panelUpdateAgentUpdateResultPath = "/var/lib/dockpanel/last-agent-update.json"

// Kinds of panelUpdateAgentUpdateState (serde tag "state", snake_case).
const (
	panelUpdateIdle      = "idle"
	panelUpdateInFlight  = "in_flight"
	panelUpdateSucceeded = "succeeded"
	panelUpdateFailed    = "failed"
)

// panelUpdateAgentUpdateState mirrors the Rust tagged enum AgentUpdateState;
// only the fields belonging to Kind are meaningful.
type panelUpdateAgentUpdateState struct {
	Kind string
	// in_flight
	TargetVersion string
	StartedAt     time.Time
	LastLogLine   *string
	// succeeded
	Version     string
	CompletedAt time.Time
	// failed
	Reason string
	At     time.Time
}

// toValue renders the state exactly as serde's internally-tagged enum would.
func (s panelUpdateAgentUpdateState) toValue() map[string]any {
	switch s.Kind {
	case panelUpdateInFlight:
		return map[string]any{
			"state":          panelUpdateInFlight,
			"target_version": s.TargetVersion,
			"started_at":     panelUpdateRFC3339(s.StartedAt),
			"last_log_line":  s.LastLogLine,
		}
	case panelUpdateSucceeded:
		return map[string]any{
			"state":        panelUpdateSucceeded,
			"version":      s.Version,
			"completed_at": panelUpdateRFC3339(s.CompletedAt),
		}
	case panelUpdateFailed:
		return map[string]any{
			"state":  panelUpdateFailed,
			"reason": s.Reason,
			"at":     panelUpdateRFC3339(s.At),
		}
	}
	return map[string]any{"state": panelUpdateIdle}
}

// panelUpdateRFC3339 formats like chrono's DateTime<Utc> serde output
// (SecondsFormat::AutoSi, "Z"): fraction of 0, 3, 6 or 9 digits.
func panelUpdateRFC3339(t time.Time) string {
	t = t.UTC()
	ns := t.Nanosecond()
	layout := "2006-01-02T15:04:05Z07:00"
	switch {
	case ns == 0:
	case ns%1_000_000 == 0:
		layout = "2006-01-02T15:04:05.000Z07:00"
	case ns%1_000 == 0:
		layout = "2006-01-02T15:04:05.000000Z07:00"
	default:
		layout = "2006-01-02T15:04:05.000000000Z07:00"
	}
	return t.Format(layout)
}

// Process-local state, and deliberately only ever a *negative* signal plus a
// progress window. An update restarts this process, so this state cannot
// outlive the thing it describes; the orchestrator confirms success from
// /health (which is what the W4 design §4.5 said to do all along). Nothing
// here may report succeeded on its own authority — that is exactly the bug
// this file shipped with.
var (
	panelUpdateMu  sync.Mutex
	panelUpdateCur = panelUpdateAgentUpdateState{Kind: panelUpdateIdle}
)

func panelUpdateSetFailed(reason string) {
	panelUpdateMu.Lock()
	panelUpdateCur = panelUpdateAgentUpdateState{Kind: panelUpdateFailed, Reason: reason, At: time.Now().UTC()}
	panelUpdateMu.Unlock()
}

type panelUpdateRequest struct {
	TargetVersion string `json:"target_version"`
}

type panelUpdateApplyResponse struct {
	Accepted      bool   `json:"accepted"`
	TargetVersion string `json:"target_version"`
}

// The phone-home timer (services) cannot import routes, so it reaches the one
// shared launcher and the destructive-retry check through these hooks.
func init() {
	services.PhoneHomeStartAgentSelfUpdate = panelUpdateStartAgentSelfUpdate
	services.PhoneHomeTargetAlreadyFailedDestructively = panelUpdateTargetAlreadyFailedDestructively
}

// panelUpdateValidateTargetVersion is a hand-rolled validator (matches the
// backend's validate_target_version).
func panelUpdateValidateTargetVersion(v string) bool {
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

// panelUpdateAllDigits: non-empty and ASCII digits only.
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

// panelUpdateApply: POST /panel/update — kick off the update with the target
// version. Caller polls /panel/update/status.
//
// A thin HTTP shell over panelUpdateStartAgentSelfUpdate, which is shared with
// the agent's own periodic update check. There is exactly one implementation
// of "start an update on this box", so the timer cannot drift into a second,
// weaker one — which is precisely what it used to be (s233).
func panelUpdateApply(w http.ResponseWriter, r *http.Request) {
	var body panelUpdateRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	target := strings.TrimSpace(body.TargetVersion)
	if err := panelUpdateStartAgentSelfUpdate(target); err != nil {
		status := http.StatusInternalServerError
		var se *panelUpdateStartUpdateError
		if errors.As(err, &se) {
			status = se.statusCode()
		}
		// axum (StatusCode, String): plain-text body, not the JSON error shape.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, panelUpdateApplyResponse{Accepted: true, TargetVersion: target})
}

// Kinds of panelUpdateStartUpdateError.
const (
	panelUpdateErrInvalid = iota
	panelUpdateErrInFlight
	panelUpdateErrInternal
)

// panelUpdateStartUpdateError says why an update could not be started. The
// HTTP path maps these to status codes; the timer path logs them.
type panelUpdateStartUpdateError struct {
	kind int
	msg  string // Invalid: the target; Internal: the message
}

func (e *panelUpdateStartUpdateError) statusCode() int {
	switch e.kind {
	case panelUpdateErrInvalid:
		return http.StatusBadRequest
	case panelUpdateErrInFlight:
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

func (e *panelUpdateStartUpdateError) Error() string {
	switch e.kind {
	case panelUpdateErrInvalid:
		return "invalid target_version: " + e.msg
	case panelUpdateErrInFlight:
		return "an update is already in flight"
	}
	return e.msg
}

type panelUpdateMode int

const (
	// panelUpdateModeFullPanel: box has an API binary and the panel updater — update the whole panel.
	panelUpdateModeFullPanel panelUpdateMode = iota
	// panelUpdateModeAgentOnly: agent-only box (install-agent.sh). Update just the agent binary.
	panelUpdateModeAgentOnly
)

func panelUpdatePathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// panelUpdateStartAgentSelfUpdate starts an update of this box to target, and
// returns as soon as the work has been handed to PID1. Never blocks on the
// update itself and never reports success — the caller confirms from /health
// and from the updater's own verdict file.
//
// Shared by the panel-driven fleet path (POST /panel/update) and the agent's
// own periodic check, so both get the same validation, the same liveness
// guard, and the same checksum-verified, health-verified, rollback-capable
// updater. Returns nil or a *panelUpdateStartUpdateError.
func panelUpdateStartAgentSelfUpdate(target string) error {
	target = strings.TrimSpace(target)
	if !panelUpdateValidateTargetVersion(target) {
		return &panelUpdateStartUpdateError{kind: panelUpdateErrInvalid, msg: target}
	}
	// A full panel install keeps the panel updater (it has an API, a frontend
	// and a database to move). Everything else — i.e. every box added with
	// install-agent.sh, which is the entire fleet population — gets the
	// agent-only updater, which needs nothing from /opt.
	mode := panelUpdateModeAgentOnly
	if panelUpdatePathExists(panelUpdateUpdateScript) && panelUpdatePathExists(panelUpdateAPIBin) {
		mode = panelUpdateModeFullPanel
	}

	// Already-in-flight guard. It has to ask whether the in-flight run is
	// actually still running: an updater that fails inside its own transient
	// unit never restarts this process, so in_flight would otherwise stick for
	// the life of the agent and every later attempt — including the one fixing
	// the operator's typo — would be refused 409 for ever (s232 lab).
	//
	// It also serialises the timer against an operator-driven fleet run: two
	// updates must never race for the same binary.
	//
	// Checking and claiming happen under ONE lock acquisition. Split in two,
	// two callers could both observe "not in flight" and both spawn an
	// updater. The agent's own timer (s233) is a second, independent caller
	// that can fire at any moment, including the moment an operator starts a
	// fleet run — making a dormant race reachable is lesson #50, so the state
	// may not change between the question and the claim.
	panelUpdateMu.Lock()
	if s := panelUpdateCur; s.Kind == panelUpdateInFlight && !panelUpdateRunHasFinished(s.StartedAt) {
		panelUpdateMu.Unlock()
		return &panelUpdateStartUpdateError{kind: panelUpdateErrInFlight}
	}
	panelUpdateCur = panelUpdateAgentUpdateState{Kind: panelUpdateInFlight, TargetVersion: target, StartedAt: time.Now().UTC()}
	panelUpdateMu.Unlock()

	// Materialise the embedded updater before returning, so a box that cannot
	// even write it gets a real error instead of a silent no-op.
	if mode == panelUpdateModeAgentOnly {
		if err := panelUpdateWriteAgentUpdateScript(); err != nil {
			panelUpdateMu.Lock()
			panelUpdateCur = panelUpdateAgentUpdateState{Kind: panelUpdateIdle}
			panelUpdateMu.Unlock()
			return &panelUpdateStartUpdateError{kind: panelUpdateErrInternal, msg: fmt.Sprintf("could not stage the agent updater: %v", err)}
		}
	}

	go panelUpdateRunUpdateSubprocess(target, mode)
	return nil
}

func panelUpdateWriteAgentUpdateScript() error {
	if err := os.MkdirAll("/var/lib/dockpanel", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(panelUpdateAgentUpdateScriptPath, []byte(panelUpdateAgentUpdateScript), 0o700); err != nil {
		return err
	}
	// WriteFile's mode only applies on creation; force it on an existing file.
	return os.Chmod(panelUpdateAgentUpdateScriptPath, 0o700)
}

func panelUpdateRunUpdateSubprocess(target string, mode panelUpdateMode) {
	// Both updaters restart dockpanel-agent.service, and that unit is
	// KillMode=control-group — so anything still in this process's cgroup when
	// that happens is SIGTERMed mid-update. PID1 has to own the work (lesson
	// #47). update.sh self-detaches the same way; doing it here too means the
	// agent path does not depend on the remote box's copy of a script being
	// new enough to protect itself.
	unit := fmt.Sprintf("dockpanel-agent-update-%d", time.Now().UnixMilli())
	args := []string{"--quiet", "--collect", "--unit=" + unit, "--setenv=DOCKPANEL_VERSION=" + target}
	switch mode {
	case panelUpdateModeFullPanel:
		args = append(args,
			"--setenv=INSTALL_FROM_RELEASE=1",
			"--setenv=DOCKPANEL_NO_SELF_REFRESH=1",
			"--setenv=DOCKPANEL_UPDATE_DETACHED=1",
			"bash", panelUpdateUpdateScript)
	case panelUpdateModeAgentOnly:
		args = append(args,
			"--setenv=DOCKPANEL_AGENT_UPDATE_DETACHED=1",
			"bash", panelUpdateAgentUpdateScriptPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
	defer cancel()
	cmd := safecmd.Command(ctx, "systemd-run", args...)
	stdout, err1 := cmd.StdoutPipe()
	stderr, err2 := cmd.StderrPipe()
	if err := errors.Join(err1, err2); err != nil {
		panelUpdateSetFailed(fmt.Sprintf("spawn failed: %v", err))
		return
	}
	if err := cmd.Start(); err != nil {
		panelUpdateSetFailed(fmt.Sprintf("spawn failed: %v", err))
		return
	}

	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		panelUpdateEachLine(stdout, func(line string) {
			slog.Info(line, "target", "panel_update")
			panelUpdateMu.Lock()
			if panelUpdateCur.Kind == panelUpdateInFlight {
				l := line
				if r := []rune(l); len(r) > 256 {
					l = string(r[:256])
				}
				panelUpdateCur.LastLogLine = &l
			}
			panelUpdateMu.Unlock()
		})
	}()
	go func() {
		defer readers.Done()
		panelUpdateEachLine(stderr, func(line string) { slog.Warn(line, "target", "panel_update") })
	}()
	// exec requires all pipe reads to finish before Wait.
	readers.Wait()
	err := cmd.Wait()

	// systemd-run without --wait returns as soon as PID1 has ACCEPTED the job —
	// measured at ~120 ms, while the real update runs for minutes and may fail
	// outright. So a zero exit here means "the work was handed off", never "the
	// work succeeded", and this function must not promote it to succeeded. It
	// used to, and the panel therefore reported a fleet member as updated one
	// second before that member's updater aborted (lesson #49).
	//
	// A NON-zero exit is still real information: PID1 refused the job, so
	// nothing is running and the update definitively did not happen.
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		panelUpdateSetFailed("updater did not return within 15min")
	case cmd.ProcessState != nil:
		status := cmd.ProcessState
		if !status.Success() {
			panelUpdateSetFailed(fmt.Sprintf("could not start the update unit (%s)", panelUpdateExitStatus(status)))
		}
		// Success case: stay in_flight. Either this process is replaced by the
		// restart (state resets to idle and /health carries the truth), or the
		// updater's own result file explains the failure.
	default:
		panelUpdateSetFailed(fmt.Sprintf("wait error: %v", err))
	}
}

// panelUpdateEachLine calls fn for every non-empty line of r.
func panelUpdateEachLine(r io.Reader, fn func(string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			fn(line)
		}
	}
	// Drain the rest so the child never blocks on a full pipe.
	_, _ = io.Copy(io.Discard, r)
}

// panelUpdateExitStatus renders like Rust's unix ExitStatus Display.
func panelUpdateExitStatus(ps *os.ProcessState) string {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return fmt.Sprintf("signal: %d (%s)", int(ws.Signal()), ws.Signal())
	}
	return fmt.Sprintf("exit status: %d", ps.ExitCode())
}

// panelUpdateReadAgentUpdateResult reads the updater's verdict file as a JSON
// object; nil if absent or unparseable.
func panelUpdateReadAgentUpdateResult() map[string]any {
	raw, err := os.ReadFile(panelUpdateAgentUpdateResultPath)
	if err != nil {
		return nil
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

// panelUpdateLastAgentUpdateResult reads the agent-only updater's verdict
// file. This is the record that survives the restart the update performs,
// which the in-memory state by definition cannot. ok=true: version is the
// target that landed. ok=false: stage/reason of the failure. found=false if
// no update has ever run here.
func panelUpdateLastAgentUpdateResult() (found, ok bool, version, stage, reason string) {
	v := panelUpdateReadAgentUpdateResult()
	if v == nil {
		return
	}
	field := func(k, d string) string {
		if s, isStr := v[k].(string); isStr {
			return s
		}
		return d
	}
	b, isBool := v["ok"].(bool)
	if !isBool {
		return
	}
	if b {
		return true, true, strings.TrimLeft(field("target_version", ""), "v"), "", ""
	}
	return true, false, "", field("stage", "unknown"), field("reason", "agent update failed")
}

// panelUpdatePostSwapStages are the stages agent-self-update.sh can only reach
// once it has ALREADY replaced the binary. A failure at one of these has cost
// a download, a swap and two restarts of this service; a failure before them
// cost a download at most. "unit" belongs here even though it replaces a text
// file rather than the binary: it runs AFTER the swap, so a run that died in
// it has already left a new binary on disk, and it can itself leave a unit the
// agent cannot start under. Retrying that unattended is the loop this list
// exists to stop.
var panelUpdatePostSwapStages = []string{"swap", "unit", "restart", "verify-running", "rollback"}

// panelUpdateTargetAlreadyFailedDestructively: did a previous run already fail
// this exact target *after* replacing the binary? Returns the stage and reason
// if so.
//
// This exists to stop an unattended retry loop. The agent's timer decides to
// update by comparing the panel's target against its own version — and a
// failed update leaves its version unchanged, so that comparison stays true
// for ever. With a target that cannot come up on this box, the timer would
// otherwise re-run the whole destructive sequence indefinitely: download,
// swap, restart, fail the health poll, roll back, restart again. And because
// the rollback restarts the process, the loop begins again at its *initial*
// delay rather than the 6-hour one — so the pathological case would repeat
// roughly HOURLY, on every box in the fleet, for ever.
//
// Deliberately NOT consulted by panelUpdateStartAgentSelfUpdate: an operator
// starting a fleet update is making an explicit decision and must be able to
// override this. Only the unattended path refuses.
func panelUpdateTargetAlreadyFailedDestructively(target string) (string, bool) {
	v := panelUpdateReadAgentUpdateResult()
	if v == nil {
		return "", false
	}
	if ok, isBool := v["ok"].(bool); !isBool || ok {
		return "", false
	}
	recorded, isStr := v["target_version"].(string)
	if !isStr || strings.TrimLeft(recorded, "v") != strings.TrimLeft(target, "v") {
		return "", false
	}
	stage, isStr := v["stage"].(string)
	if !isStr || !slices.Contains(panelUpdatePostSwapStages, stage) {
		return "", false
	}
	reason, isStr := v["reason"].(string)
	if !isStr {
		reason = "no reason recorded"
	}
	return fmt.Sprintf("stage %s: %s", stage, reason), true
}

// panelUpdateRunHasFinished: has the run that began at startedAt already
// reached a verdict?
//
// This is the one predicate that decides both "may a new update start" and
// "does the verdict on disk describe the run we are being asked about". The
// in-memory state cannot answer either on its own: a successful update
// replaces this process (so the state resets and says nothing), and a failure
// inside the transient unit never touches it at all.
//
// A verdict older than the run's start belongs to a previous run and is
// ignored.
//
// The comparison is at WHOLE-SECOND resolution on both sides, and that is
// load-bearing. The verdict's `at` is written by the shell updater with
// `date +%S` — whole seconds — while startedAt has sub-second precision.
// Comparing them directly means a run that reaches its verdict *inside the
// same wall-clock second it began* is judged stale — so the state stays
// in_flight for ever and every later attempt is refused 409. The FASTEST
// failures hit it every time: a 404 download resolves in ~0.25s, so a
// mistyped or unreleased target would reliably wedge the box (s233 lab).
// Flooring startedAt to its second makes a verdict written in the same second
// count as belonging to this run.
func panelUpdateRunHasFinished(startedAt time.Time) bool {
	v := panelUpdateReadAgentUpdateResult()
	if v == nil {
		return false
	}
	at, isStr := v["at"].(string)
	if !isStr {
		return false
	}
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return false
	}
	return t.Unix() >= startedAt.Unix()
}

// panelUpdateStatus: GET /panel/update/status — a *negative* signal plus a
// progress window.
//
// idle after the update restarts this process, which is why the caller must
// treat the running version (always included below, and on /health) as the
// authority on whether an update landed. What this endpoint can say reliably
// is that something FAILED: either in-process, or — across the restart — from
// the updater's own result file.
func panelUpdateStatus(w http.ResponseWriter, _ *http.Request) {
	panelUpdateMu.Lock()
	s := panelUpdateCur
	if s.LastLogLine != nil {
		l := *s.LastLogLine
		s.LastLogLine = &l
	}
	panelUpdateMu.Unlock()
	value := s.toValue()

	// Consult the updater's verdict whenever it describes THIS run, not only
	// once the process has restarted. A failure that stops before the restart
	// (a target release that does not exist, say) leaves this state in_flight
	// for ever, and the caller would then wait out its whole 10-minute deadline
	// and report a timeout — when the real, actionable reason had been on disk
	// one second in (s232 lab).
	verdictApplies := false
	switch s.Kind {
	case panelUpdateIdle:
		verdictApplies = true
	case panelUpdateInFlight:
		verdictApplies = panelUpdateRunHasFinished(s.StartedAt)
	}

	if verdictApplies {
		found, ok, version, stage, reason := panelUpdateLastAgentUpdateResult()
		switch {
		case found && !ok:
			value = map[string]any{
				"state":  panelUpdateFailed,
				"reason": fmt.Sprintf("%s (stage %s)", reason, stage),
			}
		// The one place succeeded may be constructed, and note WHERE it comes
		// from: the updater's on-disk verdict AND the version this very
		// process reports for itself. It is a statement about the binary that
		// is executing, not a prediction made by the process that launched
		// the update. A panel too old to check /health still gets a truthful
		// answer from this.
		case found && ok && version == services.AgentVersion:
			value = panelUpdateAgentUpdateState{Kind: panelUpdateSucceeded, Version: version, CompletedAt: time.Now().UTC()}.toValue()
		}
	}

	value["running_version"] = services.AgentVersion
	writeJSON(w, http.StatusOK, value)
}

func registerPanelUpdate(r *Router) {
	r.Handle("POST /panel/update", panelUpdateApply)
	r.Handle("GET /panel/update/status", panelUpdateStatus)
}
