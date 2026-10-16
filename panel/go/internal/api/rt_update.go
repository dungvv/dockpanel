package api

// Port of panel/backend/src/routes/update.rs — Phase 4 W4 panel self-update,
// snapshot and fleet admin API. Every endpoint is admin-gated.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtUpdateRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/update/status", h(rtUpdateGetStatus))
	r.Handle("POST /api/update/apply", h(rtUpdateApplyUpdate))
	r.Handle("POST /api/update/manual-check", h(rtUpdateManualCheck))
	r.Handle("POST /api/update/rollback", h(rtUpdateRollback))
	r.Handle("GET /api/update/channel", h(rtUpdateGetChannel))
	r.Handle("PUT /api/update/channel", h(rtUpdatePutChannel))
	r.Handle("GET /api/snapshots", h(rtUpdateListSnapshotsRoute))
	r.Handle("POST /api/snapshots", h(rtUpdateCreateSnapshotRoute))
	r.Handle("DELETE /api/snapshots/{id}", h(rtUpdateDeleteSnapshotRoute))
	r.Handle("GET /api/update/fleet", h(rtUpdateListFleetRuns))
	r.Handle("POST /api/update/fleet", h(rtUpdateApplyFleet))
	r.Handle("GET /api/update/fleet/{id}", h(rtUpdateGetFleetRun))
}

// ── Status & state ───────────────────────────────────────────────────────

// rtUpdateStatusResponse flattens the state (serde `#[serde(flatten)]`) and
// appends the rest. LastRestore / LastPanelUpdate are omitted when nil.
//
// LastRestore: a restore stops and restarts this process, so its outcome
// cannot come back through the request that started it — it writes a result
// file, surfaced here (a failed rollback never looks like no rollback).
// LastPanelUpdate: same reason, and the ONLY channel for an update that failed
// before the api was stopped — nothing restarts, so nothing else reports it.
type rtUpdateStatusResponse struct {
	State            PanelUpdateUpdateState
	CurrentVersion   string
	AvailableVersion *string
	Channel          string
	LastRestore      any
	LastPanelUpdate  any
}

func (s rtUpdateStatusResponse) MarshalJSON() ([]byte, error) {
	st, _ := s.State.MarshalJSON()
	var b bytes.Buffer
	b.Write(bytes.TrimSuffix(st, []byte("}")))
	field := func(k string, v any) {
		b.WriteString(`,"` + k + `":`)
		b.Write(rtWsMetricsMarshal(v))
	}
	field("current_version", s.CurrentVersion)
	field("available_version", s.AvailableVersion)
	field("channel", s.Channel)
	if s.LastRestore != nil {
		field("last_restore", s.LastRestore)
	}
	if s.LastPanelUpdate != nil {
		field("last_panel_update", s.LastPanelUpdate)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func rtUpdateSetting(r *http.Request, st *AppState, key, ctxName string) (*string, error) {
	v, err := queryScalarOpt[string](r.Context(), st.DB, "SELECT value FROM settings WHERE key = '"+key+"'")
	if err != nil {
		return nil, internalError(ctxName, err)
	}
	return v, nil
}

// rtUpdateGetStatus: GET /api/update/status.
func rtUpdateGetStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	s := PanelUpdateCurrentState(r.Context(), PanelUpdateState, st.DB)
	avail, err := rtUpdateSetting(r, st, "update_available_version", "update status")
	if err != nil {
		return err
	}
	ch, err := rtUpdateSetting(r, st, "update_channel", "update status")
	if err != nil {
		return err
	}
	channel := "stable"
	if ch != nil {
		channel = *ch
	}
	writeJSON(w, http.StatusOK, rtUpdateStatusResponse{
		State:            s,
		CurrentVersion:   Version,
		AvailableVersion: avail,
		Channel:          channel,
		LastRestore:      PanelSnapshotLastRestoreResult(),
		LastPanelUpdate:  PanelUpdateLastPanelUpdateResult(),
	})
	return nil
}

// ── Apply update ─────────────────────────────────────────────────────────

type rtUpdateApplyInput struct {
	TargetVersion string `json:"target_version"`
}

type rtUpdateApplyResponse struct {
	Accepted bool                   `json:"accepted"`
	State    PanelUpdateUpdateState `json:"state"`
}

// rtUpdateRejectApplyTarget: why an apply target is refused, or "" for a
// genuine upgrade. Split out so the rules are testable without a database.
// The direction rule is the one this route always claimed and never enforced:
// matching the advertised row is not enough, because the row can name a
// release OLDER than the running panel (upgraded by hand, not reconciled yet),
// and update.sh installs whatever tag it is handed, in either direction.
func rtUpdateRejectApplyTarget(targetClean, advertised, current string) string {
	if advertised == "" {
		return "no update is currently available — run /api/update/manual-check first"
	}
	if strings.TrimLeft(advertised, "v") != targetClean {
		return "target_version does not match the advertised update — refresh and retry"
	}
	if !TelemetryCollectorIsNewerRelease(targetClean, current) {
		return fmt.Sprintf("refusing to apply v%s: this panel already runs v%s, and this "+
			"endpoint only moves forward. To go back to an earlier release, restore a snapshot "+
			"via /api/update/rollback.", targetClean, current)
	}
	return ""
}

// rtUpdateApplyUpdate: POST /api/update/apply. Only versions the poller has
// surfaced, and only ahead of what is installed — no arbitrary tag jumps or
// downgrades here (downgrade = rollback to a snapshot, a separate route).
func rtUpdateApplyUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var body rtUpdateApplyInput
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	adv, err := rtUpdateSetting(r, st, "update_available_version", "apply update")
	if err != nil {
		return err
	}
	advertised := ""
	if adv != nil {
		advertised = *adv
	}
	if reason := rtUpdateRejectApplyTarget(strings.TrimLeft(body.TargetVersion, "v"), advertised, Version); reason != "" {
		return apiErr(http.StatusBadRequest, reason)
	}

	email := c.Email
	newState, err := PanelUpdateStartPanelUpdate(context.WithoutCancel(r.Context()), PanelUpdateState, st.DB, body.TargetVersion, &email)
	if err != nil {
		var oe *PanelUpdateOrchestratorError
		if errors.As(err, &oe) {
			switch oe.Kind {
			case PanelUpdateErrInvalidTargetVersion:
				return apiErr(http.StatusBadRequest, oe.Error())
			case PanelUpdateErrAlreadyInFlight:
				return apiErr(http.StatusConflict, oe.Error())
			case PanelUpdateErrScriptMissing:
				return apiErr(http.StatusInternalServerError, oe.Error())
			}
		}
		return internalError("apply update", err)
	}
	writeJSON(w, http.StatusAccepted, rtUpdateApplyResponse{Accepted: true, State: newState})
	return nil
}

// ── Manual poll ──────────────────────────────────────────────────────────

type rtUpdateManualCheckResponse struct {
	CheckedAt        string  `json:"checked_at"`
	AvailableVersion *string `json:"available_version"`
}

// rtUpdateManualCheck: POST /api/update/manual-check.
func rtUpdateManualCheck(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	TelemetryCollectorCheckForUpdatesManual(r.Context(), st.DB)
	adv, err := rtUpdateSetting(r, st, "update_available_version", "manual check")
	if err != nil {
		return err
	}
	// The poll clears a row it has overtaken, but returns early when GitHub is
	// unreachable — and then the untouched row would come back as this check's
	// own finding, telling the operator who doubted the banner that a live
	// check had just confirmed it.
	if adv != nil && !TelemetryCollectorIsNewerRelease(*adv, Version) {
		adv = nil
	}
	writeJSON(w, http.StatusOK, rtUpdateManualCheckResponse{
		CheckedAt:        telemetryCollectorRFC3339(time.Now()),
		AvailableVersion: adv,
	})
	return nil
}

// ── Rollback ─────────────────────────────────────────────────────────────

type rtUpdateRollbackInput struct {
	SnapshotID uuid.UUID `json:"snapshot_id"`
}

type rtUpdateRollbackResponse struct {
	Accepted   bool      `json:"accepted"`
	SnapshotID uuid.UUID `json:"snapshot_id"`
}

// rtUpdateRollback: POST /api/update/rollback.
func rtUpdateRollback(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	var body rtUpdateRollbackInput
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := PanelUpdateRollbackToSnapshot(context.WithoutCancel(r.Context()), PanelUpdateState, st.DB, body.SnapshotID); err != nil {
		var oe *PanelUpdateOrchestratorError
		if errors.As(err, &oe) && oe.Kind == PanelUpdateErrSnapshot {
			switch rtUpdateSnapshotErrKind(err) {
			case PanelSnapshotErrNotFound:
				return apiErr(http.StatusNotFound, err.Error())
			case PanelSnapshotErrFileMissing:
				return apiErr(http.StatusGone, err.Error())
			}
		}
		return internalError("rollback", err)
	}
	writeJSON(w, http.StatusAccepted, rtUpdateRollbackResponse{Accepted: true, SnapshotID: body.SnapshotID})
	return nil
}

// rtUpdateSnapshotErrKind is the SnapshotError variant inside err, or -1.
func rtUpdateSnapshotErrKind(err error) PanelSnapshotErrorKind {
	var se *PanelSnapshotError
	if errors.As(err, &se) {
		return se.Kind
	}
	return -1
}

// ── Channel ──────────────────────────────────────────────────────────────

type rtUpdateChannelResponse struct {
	Channel string `json:"channel"`
}

// rtUpdateGetChannel: GET /api/update/channel.
func rtUpdateGetChannel(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	ch, err := rtUpdateSetting(r, st, "update_channel", "get channel")
	if err != nil {
		return err
	}
	channel := "stable"
	if ch != nil {
		channel = *ch
	}
	writeJSON(w, http.StatusOK, rtUpdateChannelResponse{Channel: channel})
	return nil
}

type rtUpdateChannelInput struct {
	Channel string `json:"channel"`
}

// rtUpdatePutChannel: PUT /api/update/channel.
func rtUpdatePutChannel(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	var body rtUpdateChannelInput
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	channel := strings.TrimSpace(body.Channel)
	if err := UpdateChannelValidate(channel); err != nil {
		return apiErr(http.StatusBadRequest, err.Error())
	}
	if _, err := execSQL(r.Context(), st.DB,
		"INSERT INTO settings (key, value) VALUES ('update_channel', $1) "+
			"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", channel); err != nil {
		return internalError("put channel", err)
	}
	writeJSON(w, http.StatusOK, rtUpdateChannelResponse{Channel: channel})
	return nil
}

// ── Snapshots ────────────────────────────────────────────────────────────

// rtUpdateListSnapshotsRoute: GET /api/snapshots.
func rtUpdateListSnapshotsRoute(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	rows, err := PanelSnapshotListSnapshots(r.Context(), st.DB)
	if err != nil {
		return internalError("list snapshots", err)
	}
	if rows == nil {
		rows = []PanelSnapshot{}
	}
	writeJSON(w, http.StatusOK, rows)
	return nil
}

// rtUpdateDeleteSnapshotRoute: DELETE /api/snapshots/{id}.
func rtUpdateDeleteSnapshotRoute(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := PanelSnapshotDeleteSnapshot(r.Context(), st.DB, id); err != nil {
		if rtUpdateSnapshotErrKind(err) == PanelSnapshotErrNotFound {
			return apiErr(http.StatusNotFound, err.Error())
		}
		return internalError("delete snapshot", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtUpdateCreateSnapshotRoute: POST /api/snapshots. The optional body
// ({"label": …}) was extracted as Option<Json<…>> — any body, or none, is
// accepted — and then never used, so it is not read at all.
func rtUpdateCreateSnapshotRoute(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	email := c.Email
	meta, err := PanelSnapshotCreateSnapshot(r.Context(), st.DB, PanelSnapshotTriggerManual(), &email)
	if err != nil {
		return internalError("create snapshot", err)
	}
	row, err := queryOne[PanelSnapshot](r.Context(), st.DB, "SELECT * FROM panel_snapshots WHERE id = $1", meta.ID)
	if err != nil {
		return internalError("create snapshot read", err)
	}
	writeJSON(w, http.StatusCreated, row)
	return nil
}

// ── Fleet update ─────────────────────────────────────────────────────────

type rtUpdateFleetApplyInput struct {
	TargetVersion string `json:"target_version"`
	// Absent → true (serde default = default_true).
	HaltOnFailure *bool `json:"halt_on_failure"`
	IncludePanel  bool  `json:"include_panel" serde:"default"`
}

func rtUpdateDefaultTrue() bool { return true }

func (in *rtUpdateFleetApplyInput) halt() bool {
	if in.HaltOnFailure == nil {
		return rtUpdateDefaultTrue()
	}
	return *in.HaltOnFailure
}

type rtUpdateFleetApplyResponse struct {
	RunID    uuid.UUID `json:"run_id"`
	PlanSize int       `json:"plan_size"`
}

// rtUpdateApplyFleet: POST /api/update/fleet.
func rtUpdateApplyFleet(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var body rtUpdateFleetApplyInput
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if !PanelUpdateValidateTargetVersion(body.TargetVersion) {
		return apiErr(http.StatusBadRequest, "invalid target_version (must be vX.Y.Z[-rc.N])")
	}

	// v2.216.0 audit fix: include_panel used to reach the panel self-update with
	// only the shape check above — none of apply's direction/advertised-match
	// guard, so this path could downgrade the panel to any syntactically valid
	// version. Fail closed here rather than silently regress the panel.
	if body.IncludePanel {
		adv, err := rtUpdateSetting(r, st, "update_available_version", "fleet apply (panel direction check)")
		if err != nil {
			return err
		}
		advertised := ""
		if adv != nil {
			advertised = *adv
		}
		if reason := rtUpdateRejectApplyTarget(strings.TrimLeft(body.TargetVersion, "v"), advertised, Version); reason != "" {
			return apiErr(http.StatusBadRequest, reason)
		}
	}

	plan, err := PanelUpdateBuildFleetPlan(r.Context(), st.DB, c.Sub, c.Role == "admin", body.TargetVersion)
	if err != nil {
		return internalError("fleet plan", err)
	}
	if len(plan) == 0 {
		return apiErr(http.StatusBadRequest, "no reachable servers needing update — fleet plan is empty")
	}
	halt := body.halt()
	runID, err := PanelUpdateCreateFleetRun(r.Context(), st.DB, body.TargetVersion, plan, halt, body.IncludePanel, &c.Sub)
	if err != nil {
		return internalError("fleet create run", err)
	}
	// Passing the handle is what makes "include this panel" do anything — it
	// was persisted and read by nobody until s232.
	var panelHandle *PanelUpdateStateHandle
	if body.IncludePanel {
		panelHandle = PanelUpdateState
	}
	go PanelUpdateExecuteFleetPlan(context.WithoutCancel(r.Context()), st.DB, st.Agents, runID, plan, body.TargetVersion, halt, panelHandle)

	writeJSON(w, http.StatusAccepted, rtUpdateFleetApplyResponse{RunID: runID, PlanSize: len(plan)})
	return nil
}

// rtUpdateGetFleetRun: GET /api/update/fleet/{id}.
func rtUpdateGetFleetRun(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	row, err := queryOpt[FleetUpdateRun](r.Context(), st.DB, "SELECT * FROM fleet_update_runs WHERE id = $1", id)
	if err != nil {
		return internalError("fleet run", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "fleet run not found")
	}
	writeJSON(w, http.StatusOK, row)
	return nil
}

// rtUpdateListFleetRuns: GET /api/update/fleet (any query string accepted).
func rtUpdateListFleetRuns(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	rows, err := queryAll[FleetUpdateRun](r.Context(), st.DB, "SELECT * FROM fleet_update_runs ORDER BY started_at DESC LIMIT 100")
	if err != nil {
		return internalError("list fleet runs", err)
	}
	writeJSON(w, http.StatusOK, rows)
	return nil
}
