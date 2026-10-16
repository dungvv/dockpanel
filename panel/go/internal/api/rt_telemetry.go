package api

// Port of panel/backend/src/routes/telemetry.rs — local telemetry events and
// the update advertisement (all admin only).

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtTelemetryRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/telemetry/events", h(rtTelemetryListEvents))
	r.Handle("DELETE /api/telemetry/events", h(rtTelemetryClearEvents))
	r.Handle("GET /api/telemetry/stats", h(rtTelemetryStats))
	r.Handle("GET /api/telemetry/config", h(rtTelemetryGetConfig))
	r.Handle("PUT /api/telemetry/config", h(rtTelemetryUpdateConfig))
	r.Handle("GET /api/telemetry/preview", h(rtTelemetryPreview))
	r.Handle("GET /api/telemetry/export", h(rtTelemetryExportReport))
	r.Handle("POST /api/telemetry/send", h(rtTelemetrySendNow))
	r.Handle("GET /api/telemetry/update-status", h(rtTelemetryUpdateStatus))
	r.Handle("POST /api/telemetry/check-updates", h(rtTelemetryCheckUpdates))
}

// ── List Events ────────────────────────────────────────────────────────

type rtTelemetryListParams struct {
	Limit     *int64  `json:"limit"`
	Offset    *int64  `json:"offset"`
	Category  *string `json:"category"`
	EventType *string `json:"event_type"`
}

type rtTelemetryEventRow struct {
	ID        uuid.UUID       `db:"id"`
	EventType string          `db:"event_type"`
	Category  string          `db:"category"`
	Message   string          `db:"message"`
	Context   json.RawMessage `db:"context"`
	SentAt    *time.Time      `db:"sent_at"`
	CreatedAt time.Time       `db:"created_at"`
}

// rtTelemetryListEvents: GET /api/telemetry/events.
func rtTelemetryListEvents(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	var p rtTelemetryListParams
	if err := decodeQuery(r, &p); err != nil {
		return err
	}
	limit, offset := paginate(p.Limit, p.Offset)
	ctx := r.Context()

	const cols = "SELECT id, event_type, category, message, context, sent_at, created_at FROM telemetry_events "
	var rows []rtTelemetryEventRow
	var total int64
	var err error
	switch {
	case p.Category != nil:
		rows, err = queryAll[rtTelemetryEventRow](ctx, st.DB, cols+"WHERE category = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3", *p.Category, limit, offset)
		if err != nil {
			return internalError("list telemetry events", err)
		}
		if total, err = queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM telemetry_events WHERE category = $1", *p.Category); err != nil {
			return internalError("count telemetry events", err)
		}
	case p.EventType != nil:
		rows, err = queryAll[rtTelemetryEventRow](ctx, st.DB, cols+"WHERE event_type = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3", *p.EventType, limit, offset)
		if err != nil {
			return internalError("list telemetry events", err)
		}
		if total, err = queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM telemetry_events WHERE event_type = $1", *p.EventType); err != nil {
			return internalError("count telemetry events", err)
		}
	default:
		rows, err = queryAll[rtTelemetryEventRow](ctx, st.DB, cols+"ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset)
		if err != nil {
			return internalError("list telemetry events", err)
		}
		if total, err = queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM telemetry_events"); err != nil {
			return internalError("count telemetry events", err)
		}
	}
	events := make([]map[string]any, 0, len(rows))
	for _, e := range rows {
		events = append(events, map[string]any{
			"id": e.ID, "event_type": e.EventType, "category": e.Category, "message": e.Message,
			"context": telemetryCollectorValue(e.Context), "sent_at": e.SentAt, "created_at": e.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "total": total})
	return nil
}

// ── Stats ──────────────────────────────────────────────────────────────

// rtTelemetryStats: GET /api/telemetry/stats.
func rtTelemetryStats(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	ctx := r.Context()
	byCategory, err := queryAll[Tup2[string, int64]](ctx, st.DB,
		"SELECT category, COUNT(*) FROM telemetry_events "+
			"GROUP BY category ORDER BY count DESC")
	if err != nil {
		return internalError("telemetry stats", err)
	}
	byType, err := queryAll[Tup2[string, int64]](ctx, st.DB,
		"SELECT event_type, COUNT(*) FROM telemetry_events "+
			"GROUP BY event_type ORDER BY count DESC")
	if err != nil {
		return internalError("telemetry stats", err)
	}
	var counts [3]int64
	for i, q := range []string{
		"SELECT COUNT(*) FROM telemetry_events WHERE sent_at IS NULL",
		"SELECT COUNT(*) FROM telemetry_events",
		"SELECT COUNT(*) FROM telemetry_events WHERE created_at > NOW() - INTERVAL '24 hours'",
	} {
		if counts[i], err = queryScalar[int64](ctx, st.DB, q); err != nil {
			return internalError("telemetry stats", err)
		}
	}
	cats := make([]map[string]any, 0, len(byCategory))
	for _, c := range byCategory {
		cats = append(cats, map[string]any{"category": c.A, "count": c.B})
	}
	types := make([]map[string]any, 0, len(byType))
	for _, t := range byType {
		types = append(types, map[string]any{"type": t.A, "count": t.B})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": counts[1], "unsent": counts[0], "last_24h": counts[2],
		"by_category": cats, "by_type": types,
	})
	return nil
}

// ── Config ─────────────────────────────────────────────────────────────

// rtTelemetrySettingsMap reads keys into a map plus whether the stored
// update_available_version is newer than this binary.
func rtTelemetrySettingsMap(ctx context.Context, st *AppState, keys []string, ctxName string) (map[string]any, bool, error) {
	rows, err := queryAll[Tup2[string, string]](ctx, st.DB, "SELECT key, value FROM settings WHERE key = ANY($1)", keys)
	if err != nil {
		return nil, false, internalError(ctxName, err)
	}
	m := map[string]any{}
	avail := false
	for _, kv := range rows {
		if kv.A == "update_available_version" {
			avail = TelemetryCollectorIsNewerRelease(kv.B, Version)
		}
		m[kv.A] = kv.B
	}
	return m, avail, nil
}

// rtTelemetryGetConfig: GET /api/telemetry/config.
func rtTelemetryGetConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	config, avail, err := rtTelemetrySettingsMap(r.Context(), st, []string{
		"telemetry_enabled", "telemetry_endpoint", "telemetry_installation_id",
		"update_available_version", "update_release_notes", "update_release_url", "update_checked_at",
	}, "get telemetry config")
	if err != nil {
		return err
	}
	config["current_version"] = Version
	// Derived here so no client compares versions itself — and so a stored row
	// that is not newer than this binary stops rendering a banner. The raw row
	// stays: it is what was last seen on GitHub; update_available is what it
	// means for this panel.
	config["update_available"] = avail
	writeJSON(w, http.StatusOK, config)
	return nil
}

type rtTelemetryConfigUpdate struct {
	TelemetryEnabled  *string `json:"telemetry_enabled"`
	TelemetryEndpoint *string `json:"telemetry_endpoint"`
}

// rtTelemetryUpdateConfig: PUT /api/telemetry/config.
func rtTelemetryUpdateConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var body rtTelemetryConfigUpdate
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if ep := body.TelemetryEndpoint; ep != nil {
		// Empty is valid — "disable remote telemetry".
		if *ep != "" && !strings.HasPrefix(*ep, "https://") {
			return apiErr(http.StatusBadRequest, "Telemetry endpoint must use HTTPS")
		}
		if len(*ep) > 512 {
			return apiErr(http.StatusBadRequest, "Endpoint URL too long (max 512 chars)")
		}
	}
	if en := body.TelemetryEnabled; en != nil && *en != "true" && *en != "false" {
		return apiErr(http.StatusBadRequest, "telemetry_enabled must be 'true' or 'false'")
	}

	ctx := r.Context()
	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return internalError("update telemetry config", err)
	}
	defer tx.Rollback(ctx)
	if body.TelemetryEnabled != nil {
		if _, err := execSQL(ctx, tx,
			"INSERT INTO settings (key, value) VALUES ('telemetry_enabled', $1) "+
				"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", *body.TelemetryEnabled); err != nil {
			return internalError("update telemetry config", err)
		}
	}
	if body.TelemetryEndpoint != nil {
		if _, err := execSQL(ctx, tx,
			"INSERT INTO settings (key, value) VALUES ('telemetry_endpoint', $1) "+
				"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", *body.TelemetryEndpoint); err != nil {
			return internalError("update telemetry config", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return internalError("commit telemetry config", err)
	}
	slog.Info("Telemetry config updated", "user", c.Email)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
	return nil
}

// ── Preview / Export ───────────────────────────────────────────────────

func rtTelemetryUnsent(ctx context.Context, st *AppState, limit int) ([]telemetryCollectorEventRow, error) {
	return queryAll[telemetryCollectorEventRow](ctx, st.DB,
		"SELECT id, event_type, category, message, context, created_at "+
			"FROM telemetry_events WHERE sent_at IS NULL "+
			"ORDER BY created_at ASC LIMIT "+strconv.Itoa(limit))
}

// rtTelemetryPreview: GET /api/telemetry/preview.
//
// Deliberately NO per-request server scope: telemetry_events has no server
// dimension — every row comes from the PANEL host's own agent. Taking the
// caller's X-Server-Id (which the frontend sends on every request) paired a
// fleet MEMBER's hostname, kernel and service list with the PANEL's events,
// under a note asserting it is exactly what would be sent. The events are
// panel-local, so the system block must be too.
func rtTelemetryPreview(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	ctx := r.Context()
	agent := st.Agents.Local()
	events, err := rtTelemetryUnsent(ctx, st, 50)
	if err != nil {
		return internalError("preview telemetry", err)
	}
	system, err := agent.Get(ctx, "/telemetry/system-info")
	if err != nil {
		return agentError("get telemetry system info", err)
	}
	installationID := "not yet generated"
	if v, _ := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'telemetry_installation_id'"); v != nil {
		installationID = *v
	}
	batch := telemetryCollectorBatch(events)
	writeJSON(w, http.StatusOK, map[string]any{
		"system":            system,
		"installation_id":   installationID,
		"dockpanel_version": Version,
		"events":            batch,
		"event_count":       len(batch),
		"note":              "The events below are exactly what would be sent, PII stripped. The \"system\" block above is local diagnostic context for your review — the actual outbound payload's system info is only { dockpanel_version, installation_id }, never host details.",
	})
	return nil
}

// rtTelemetryExportReport: GET /api/telemetry/export — panel-local for the
// same reason as preview.
func rtTelemetryExportReport(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	ctx := r.Context()
	agent := st.Agents.Local()
	events, err := rtTelemetryUnsent(ctx, st, 500)
	if err != nil {
		return internalError("export telemetry", err)
	}
	sys, err := agent.Get(ctx, "/telemetry/system-info")
	if err != nil {
		sys = map[string]any{}
	}
	batch := telemetryCollectorBatch(events)
	writeJSON(w, http.StatusOK, map[string]any{
		"dockpanel_version": Version,
		"export_date":       telemetryCollectorRFC3339(time.Now()),
		"system":            sys,
		"events":            batch,
		"event_count":       len(batch),
	})
	return nil
}

// ── Send Now ───────────────────────────────────────────────────────────

// rtTelemetrySendNow: POST /api/telemetry/send — send pending events in the
// background.
func rtTelemetrySendNow(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	ep, err := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'telemetry_endpoint'")
	if err != nil {
		return internalError("get telemetry endpoint", err)
	}
	if ep == nil || *ep == "" {
		return apiErr(http.StatusBadRequest, "No telemetry endpoint configured")
	}
	enabled, _ := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'telemetry_enabled'")
	if enabled == nil || *enabled != "true" {
		return apiErr(http.StatusBadRequest, "Telemetry is not enabled")
	}
	endpoint := *ep
	go TelemetryCollectorSendPendingEventsPublic(context.WithoutCancel(ctx), st.DB, endpoint)
	slog.Info("Telemetry manual send triggered", "user", c.Email)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Sending telemetry events in background"})
	return nil
}

// ── Clear Events ───────────────────────────────────────────────────────

type rtTelemetryClearParams struct {
	BeforeDays *int64 `json:"before_days"`
}

// rtTelemetryClearEvents: DELETE /api/telemetry/events.
func rtTelemetryClearEvents(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var p rtTelemetryClearParams
	if err := decodeQuery(r, &p); err != nil {
		return err
	}
	days := int64(0)
	if p.BeforeDays != nil {
		days = *p.BeforeDays
	}
	days = min(max(days, 0), 3650)
	var deleted int64
	if days > 0 {
		deleted, err = queryScalar[int64](r.Context(), st.DB,
			"WITH d AS (DELETE FROM telemetry_events WHERE created_at < NOW() - ($1 || ' days')::interval RETURNING 1) SELECT COUNT(*) FROM d",
			strconv.FormatInt(days, 10))
	} else {
		deleted, err = queryScalar[int64](r.Context(), st.DB,
			"WITH d AS (DELETE FROM telemetry_events RETURNING 1) SELECT COUNT(*) FROM d")
	}
	if err != nil {
		return internalError("clear telemetry events", err)
	}
	slog.Info("Telemetry events cleared", "user", c.Email, "deleted", deleted)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": deleted})
	return nil
}

// ── Update Status ──────────────────────────────────────────────────────

// rtTelemetryUpdateStatus: GET /api/telemetry/update-status.
//
// A row proves only that a check once found something; it is an update only
// while it names a release newer than the binary answering. Does NOT delete
// the row — a GET must not mutate; clearing is the collector's job.
func rtTelemetryUpdateStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	result, has, err := rtTelemetrySettingsMap(r.Context(), st, []string{
		"update_available_version", "update_release_notes", "update_release_url", "update_checked_at",
	}, "get update status")
	if err != nil {
		return err
	}
	result["current_version"] = Version
	result["update_available"] = has
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtTelemetryCheckUpdates: POST /api/telemetry/check-updates — runs the poll
// inline and reports what it found. It used to spawn the check and answer
// "started" first, which under `hold` was success for a poll that never
// contacted GitHub. "Check Now" is an explicit request, and hold suppresses
// AUTOMATIC polling only — same bypass as /api/update/manual-check. Bounded by
// the collector's 15s HTTP timeout.
func rtTelemetryCheckUpdates(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	TelemetryCollectorCheckForUpdatesManual(r.Context(), st.DB)
	avail, err := queryScalarOpt[string](r.Context(), st.DB, "SELECT value FROM settings WHERE key = 'update_available_version'")
	if err != nil {
		return internalError("check updates", err)
	}
	if avail != nil && !TelemetryCollectorIsNewerRelease(*avail, Version) {
		avail = nil
	}
	slog.Info("Manual update check triggered", "user", c.Email)
	msg := "No update available — you are on the latest version."
	if avail != nil {
		msg = "Update available: v" + *avail
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": msg, "available_version": avail})
	return nil
}
