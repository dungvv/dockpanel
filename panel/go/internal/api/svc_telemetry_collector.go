package api

// Port of panel/backend/src/services/telemetry_collector.rs.
//
// Responsibilities (all scoped to THIS host — see TelemetryCollectorRun):
//  1. Periodically collects diagnostics from the PANEL HOST's own agent
//  2. Stores error/warning events in telemetry_events
//  3. Sends unsent events to the configured remote endpoint (opt-in)
//  4. Cleans up old events past retention
//  5. Checks GitHub Releases for DockPanel updates

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	telemetryCollectorCheckInterval       = time.Hour
	telemetryCollectorUpdateCheckInterval = 6 * time.Hour
	telemetryCollectorRetentionDays       = 30
	telemetryCollectorMaxBatchSize        = int64(50)
	telemetryCollectorReleasesLatestURL   = "https://api.github.com/repos/ovexro/dockpanel/releases/latest"
	telemetryCollectorReleasesListURL     = "https://api.github.com/repos/ovexro/dockpanel/releases?per_page=20"
)

// telemetryCollectorRFC3339 is chrono's `to_rfc3339()`: UTC, `+00:00`, and
// 0/3/6/9 fractional digits (SecondsFormat::AutoSi).
func telemetryCollectorRFC3339(t time.Time) string {
	t = t.UTC()
	ns := t.Nanosecond()
	frac := ""
	switch {
	case ns == 0:
	case ns%1_000_000 == 0:
		frac = fmt.Sprintf(".%03d", ns/1_000_000)
	case ns%1_000 == 0:
		frac = fmt.Sprintf(".%06d", ns/1_000)
	default:
		frac = fmt.Sprintf(".%09d", ns)
	}
	return t.Format("2006-01-02T15:04:05") + frac + "+00:00"
}

// telemetryCollectorValue decodes a jsonb column as serde_json::Value would
// re-emit it (keys sorted, numbers verbatim); nil on NULL/garbage.
func telemetryCollectorValue(raw json.RawMessage) any {
	if len(raw) == 0 {
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

// TelemetryCollectorRecordEvent records a telemetry event (callable from
// anywhere). context is any JSON-marshalable value.
func TelemetryCollectorRecordEvent(ctx context.Context, db *pgxpool.Pool, eventType, category, message string, evContext any) {
	b, err := json.Marshal(evContext)
	if err != nil {
		b = []byte("null")
	}
	if _, err := execSQL(ctx, db,
		"INSERT INTO telemetry_events (event_type, category, message, context) "+
			"VALUES ($1, $2, $3, $4)", eventType, category, message, json.RawMessage(b)); err != nil {
		slog.Warn("Failed to record telemetry event: " + err.Error())
	}
}

// TelemetryCollectorRun is the supervised loop. LOCAL BY INTENT, and takes the
// registry to say so out loud: it diagnoses the panel host itself (its own
// agent's /health and /diagnostics, the version of this binary) — not a fleet
// question — so it calls agents.Local() rather than resolving a server.
func TelemetryCollectorRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	// Before anything sleeps: update.sh upgrades the binaries but never touches
	// settings, so on the first boot after an upgrade the stored advertisement
	// still names the version now running — and the first poll is 6h away.
	telemetryCollectorReconcileStoredUpdate(ctx, db)

	// Stagger start to avoid a thundering herd with other services.
	select {
	case <-time.After(120 * time.Second):
	case <-ctx.Done():
		slog.Info("Telemetry collector shutting down")
		return
	}

	check := time.NewTicker(telemetryCollectorCheckInterval)
	defer check.Stop()
	// The update ticker's first (immediate) tick is skipped.
	update := time.NewTicker(telemetryCollectorUpdateCheckInterval)
	defer update.Stop()

	// tokio::time::interval fires immediately.
	telemetryCollectorCollectAndProcess(ctx, db, agents.Local())
	for {
		select {
		case <-check.C:
			telemetryCollectorCollectAndProcess(ctx, db, agents.Local())
		case <-update.C:
			telemetryCollectorCheckForUpdates(ctx, db)
		case <-ctx.Done():
			slog.Info("Telemetry collector shutting down")
			return
		}
	}
}

func telemetryCollectorCollectAndProcess(ctx context.Context, db *pgxpool.Pool, agent *AgentClient) {
	telemetryCollectorCollectAgentHealth(ctx, db, agent)
	if telemetryCollectorGetSetting(ctx, db, "telemetry_enabled") == "true" {
		if endpoint := telemetryCollectorGetSetting(ctx, db, "telemetry_endpoint"); endpoint != "" {
			telemetryCollectorSendPendingEvents(ctx, db, endpoint)
		}
	}
	telemetryCollectorCleanupOldEvents(ctx, db)
}

func telemetryCollectorCollectAgentHealth(ctx context.Context, db *pgxpool.Pool, agent *AgentClient) {
	if _, err := agent.Get(ctx, "/health"); err != nil {
		TelemetryCollectorRecordEvent(ctx, db, "error", "agent", "Agent unreachable: "+err.Error(), map[string]any{})
	}
	report, err := agent.Get(ctx, "/diagnostics")
	if err != nil {
		return
	}
	checks, _ := jsonArr(jsonGet(report, "checks"))
	for _, check := range checks {
		sev, _ := jsonStr(jsonGet(check, "severity"))
		if sev != "critical" && sev != "error" {
			continue
		}
		title, ok := jsonStr(jsonGet(check, "title"))
		if !ok {
			title = "Unknown issue"
		}
		category, ok := jsonStr(jsonGet(check, "category"))
		if !ok {
			category = "general"
		}
		// Deduplicate: not the same issue twice within 6 hours.
		exists, err := queryScalar[bool](ctx, db,
			"SELECT EXISTS(SELECT 1 FROM telemetry_events "+
				"WHERE category = $1 AND message = $2 "+
				"AND created_at > NOW() - INTERVAL '6 hours')", category, title)
		if err != nil {
			exists = false
		}
		if !exists {
			TelemetryCollectorRecordEvent(ctx, db, "error", category, title, check)
		}
	}
}

// TelemetryCollectorSendPendingEventsPublic lets routes trigger a manual send.
func TelemetryCollectorSendPendingEventsPublic(ctx context.Context, db *pgxpool.Pool, endpoint string) {
	telemetryCollectorSendPendingEvents(ctx, db, endpoint)
}

type telemetryCollectorEventRow struct {
	ID        uuid.UUID       `db:"id"`
	EventType string          `db:"event_type"`
	Category  string          `db:"category"`
	Message   string          `db:"message"`
	Context   json.RawMessage `db:"context"`
	CreatedAt time.Time       `db:"created_at"`
}

// telemetryCollectorBatch is the outbound/preview shape of events, PII stripped.
func telemetryCollectorBatch(events []telemetryCollectorEventRow) []map[string]any {
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{
			"id":         e.ID.String(),
			"event_type": e.EventType,
			"category":   e.Category,
			"message":    e.Message,
			"context":    TelemetryCollectorStripPII(telemetryCollectorValue(e.Context)),
			"created_at": telemetryCollectorRFC3339(e.CreatedAt),
		})
	}
	return out
}

func telemetryCollectorSendPendingEvents(ctx context.Context, db *pgxpool.Pool, endpoint string) {
	if !strings.HasPrefix(endpoint, "https://") {
		slog.Warn("Telemetry endpoint must use HTTPS, skipping send")
		return
	}
	events, _ := queryAll[telemetryCollectorEventRow](ctx, db,
		"SELECT id, event_type, category, message, context, created_at "+
			"FROM telemetry_events WHERE sent_at IS NULL "+
			"ORDER BY created_at ASC LIMIT $1", telemetryCollectorMaxBatchSize)
	if len(events) == 0 {
		return
	}
	installationID := telemetryCollectorGetOrCreateInstallationID(ctx, db)
	payload := map[string]any{
		"system": map[string]any{
			"dockpanel_version": Version,
			"installation_id":   installationID,
		},
		"events":  telemetryCollectorBatch(events),
		"sent_at": telemetryCollectorRFC3339(time.Now()),
	}
	body := rtWsMetricsMarshal(payload)

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		slog.Warn("Telemetry send failed: " + err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DockPanel/"+Version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if reqCtx.Err() != nil {
			slog.Warn("Telemetry send timed out")
		} else {
			slog.Warn("Telemetry send failed: " + err.Error())
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		text, _ := io.ReadAll(resp.Body)
		slog.Warn(fmt.Sprintf("Telemetry endpoint returned status %s: %s", resp.Status, text))
		return
	}
	ids := make([]uuid.UUID, 0, len(events))
	for _, e := range events {
		ids = append(ids, e.ID)
	}
	_, _ = execSQL(ctx, db, "UPDATE telemetry_events SET sent_at = NOW() WHERE id = ANY($1)", ids)
	slog.Info(fmt.Sprintf("Telemetry: sent %d events to endpoint", len(ids)))
}

var telemetryCollectorPIIKeys = []string{
	"ip", "email", "username", "password", "token", "secret", "domain",
	"hostname", "path", "user_id", "api_key", "auth", "session", "cookie",
	"phone", "address", "cert", "private_key", "url",
}

// TelemetryCollectorStripPII redacts any object key that contains a PII
// marker (case-insensitive), recursively, before anything is sent remotely.
func TelemetryCollectorStripPII(v any) any {
	switch t := v.(type) {
	case map[string]any:
		clean := make(map[string]any, len(t))
		for k, val := range t {
			lk := strings.ToLower(k)
			redact := false
			for _, p := range telemetryCollectorPIIKeys {
				if strings.Contains(lk, p) {
					redact = true
					break
				}
			}
			if redact {
				clean[k] = "[redacted]"
			} else {
				clean[k] = TelemetryCollectorStripPII(val)
			}
		}
		return clean
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = TelemetryCollectorStripPII(e)
		}
		return out
	}
	return v
}

// telemetryCollectorReadUpdateChannel: "stable" when missing/unrecognised.
func telemetryCollectorReadUpdateChannel(ctx context.Context, db *pgxpool.Pool) string {
	v, _ := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = 'update_channel'")
	if v != nil {
		switch *v {
		case "stable", "candidate", "hold":
			return *v
		}
	}
	return "stable"
}

// telemetryCollectorCheckForUpdates honours update_channel: stable →
// /releases/latest; candidate → the newest of /releases (includes
// prereleases); hold → skip entirely. Both "Check Now" routes bypass the hold
// via TelemetryCollectorCheckForUpdatesManual — hold pins automatic polling,
// not an operator who has just asked to look.
func telemetryCollectorCheckForUpdates(ctx context.Context, db *pgxpool.Pool) {
	ch := telemetryCollectorReadUpdateChannel(ctx, db)
	if ch == "hold" {
		slog.Debug("Update poll skipped: channel=hold")
		return
	}
	telemetryCollectorCheckForUpdatesInner(ctx, db, ch)
}

// TelemetryCollectorCheckForUpdatesManual always polls (hold → stable scan).
func TelemetryCollectorCheckForUpdatesManual(ctx context.Context, db *pgxpool.Pool) {
	ch := telemetryCollectorReadUpdateChannel(ctx, db)
	if ch == "hold" {
		ch = "stable"
	}
	telemetryCollectorCheckForUpdatesInner(ctx, db, ch)
}

func telemetryCollectorCheckForUpdatesInner(ctx context.Context, db *pgxpool.Pool, channel string) {
	u := telemetryCollectorReleasesLatestURL
	if channel == "candidate" {
		u = telemetryCollectorReleasesListURL
	}
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "DockPanel/"+Version)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if reqCtx.Err() != nil {
			slog.Debug("GitHub releases check timed out")
		} else {
			slog.Debug("GitHub releases check failed: " + err.Error())
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		slog.Debug("GitHub releases check returned " + resp.Status)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var release any
	if dec.Decode(&release) != nil {
		return
	}
	// Candidate returns an ARRAY (GitHub pre-sorts by published_at desc);
	// stable a single object.
	if channel == "candidate" {
		arr, _ := jsonArr(release)
		if len(arr) == 0 {
			return // no releases yet
		}
		release = arr[0]
	}

	tag, _ := jsonStr(jsonGet(release, "tag_name"))
	latest := strings.TrimLeft(tag, "v")

	// One decision covers every not-newer shape (empty tag, older than
	// installed, already running, unparseable): all CLEAR the advertisement.
	// Until v2.53.0 only byte-equality cleared it, so a merely-older row
	// survived every poll and the panel offered an update to a version behind
	// itself (#98).
	if telemetryCollectorAdvertisementIsStale(latest, Version) {
		telemetryCollectorClearUpdateAdvertisement(ctx, db)
		telemetryCollectorRecordUpdateCheckTime(ctx, db)
		return
	}

	notes, _ := jsonStr(jsonGet(release, "body"))
	if r := []rune(notes); len(r) > 4000 {
		notes = string(r[:4000]) // limit stored release notes
	}
	releaseURL, _ := jsonStr(jsonGet(release, "html_url"))
	for _, kv := range [][2]string{
		{"update_available_version", latest},
		{"update_release_notes", notes},
		{"update_release_url", releaseURL},
	} {
		_, _ = execSQL(ctx, db,
			"INSERT INTO settings (key, value) VALUES ($1, $2) "+
				"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", kv[0], kv[1])
	}
	telemetryCollectorRecordUpdateCheckTime(ctx, db)
	slog.Info(fmt.Sprintf("DockPanel update available (%s channel): v%s -> v%s", channel, Version, latest))
}

// telemetryCollectorReconcileStoredUpdate drops an advertisement the running
// binary already caught up with, once at start: update.sh never writes
// settings, so every operator saw "vX is available (current: vX)" for six
// hours after every upgrade. DB only — no GitHub request.
func telemetryCollectorReconcileStoredUpdate(ctx context.Context, db *pgxpool.Pool) {
	adv := telemetryCollectorGetSetting(ctx, db, "update_available_version")
	if adv == "" || !telemetryCollectorAdvertisementIsStale(adv, Version) {
		return
	}
	slog.Info(fmt.Sprintf("Clearing stale update advertisement v%s — this panel runs v%s", adv, Version))
	telemetryCollectorClearUpdateAdvertisement(ctx, db)
}

// telemetryCollectorClearUpdateAdvertisement deletes the three keys that make
// the UI offer an update. update_checked_at survives: the check happened.
func telemetryCollectorClearUpdateAdvertisement(ctx context.Context, db *pgxpool.Pool) {
	_, _ = execSQL(ctx, db,
		"DELETE FROM settings WHERE key IN ('update_available_version', 'update_release_notes', 'update_release_url')")
}

// telemetryCollectorRecordUpdateCheckTime: "checked Xs ago", for polls that
// found nothing as much as for those that found a release.
func telemetryCollectorRecordUpdateCheckTime(ctx context.Context, db *pgxpool.Pool) {
	_, _ = execSQL(ctx, db,
		"INSERT INTO settings (key, value) VALUES ('update_checked_at', $1) "+
			"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", telemetryCollectorRFC3339(time.Now()))
}

// telemetryCollectorAdvertisementIsStale: a stored update_available_version
// must go whenever it is not strictly newer than what is running.
func telemetryCollectorAdvertisementIsStale(stored, current string) bool {
	return !TelemetryCollectorIsNewerRelease(stored, current)
}

// TelemetryCollectorIsNewerRelease: latest is a strictly newer release than
// current. The single comparison behind the poller, the start-up reconcile,
// the read-side update_available flags and the apply guard — one rule, so the
// four surfaces cannot disagree about whether an update exists.
func TelemetryCollectorIsNewerRelease(latest, current string) bool {
	if strings.TrimSpace(latest) == "" {
		return false
	}
	lk, lp := telemetryCollectorReleaseKey(latest)
	ck, cp := telemetryCollectorReleaseKey(current)
	if c := telemetryCollectorCmpKey(lk, ck); c != 0 {
		return c > 0
	}
	return lp > cp
}

func telemetryCollectorCmpKey(a, b [4]uint64) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// telemetryCollectorReleaseKey layers on PanelUpdateSemverKey so the update
// surfaces and the fleet queue parse X.Y.Z the same way (junk tolerance
// included: `2.52.0-rc.1` is 2.52.0, never 2.52.1). The fleet queue wants an
// rc to sort with its GA; the update path needs the other half of SemVer —
// `2.53.0-rc.1` precedes `2.53.0`, and rc.2 beats rc.1 — so the suffix comes
// back as a second component: GA = max, rc.N = N, any other suffix = 0.
func telemetryCollectorReleaseKey(v string) ([4]uint64, uint64) {
	v = strings.TrimSpace(v)
	pre := uint64(math.MaxUint64)
	if _, suffix, ok := strings.Cut(v, "-"); ok {
		pre = 0
		if n, ok := strings.CutPrefix(suffix, "rc."); ok {
			if p, err := strconv.ParseUint(n, 10, 64); err == nil {
				pre = p
			}
		}
	}
	return PanelUpdateSemverKey(&v), pre
}

func telemetryCollectorCleanupOldEvents(ctx context.Context, db *pgxpool.Pool) {
	_, _ = execSQL(ctx, db, "DELETE FROM telemetry_events WHERE created_at < NOW() - $1::interval",
		fmt.Sprintf("%d days", telemetryCollectorRetentionDays))
}

func telemetryCollectorGetOrCreateInstallationID(ctx context.Context, db *pgxpool.Pool) string {
	if v, _ := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = 'telemetry_installation_id'"); v != nil {
		return *v
	}
	id := uuid.NewString()
	_, _ = execSQL(ctx, db,
		"INSERT INTO settings (key, value) VALUES ('telemetry_installation_id', $1) "+
			"ON CONFLICT (key) DO NOTHING", id)
	return id
}

func telemetryCollectorGetSetting(ctx context.Context, db *pgxpool.Pool, key string) string {
	v, _ := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = $1", key)
	if v == nil {
		return ""
	}
	return *v
}
