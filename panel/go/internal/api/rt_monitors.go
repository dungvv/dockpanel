package api

// routes/monitors.rs — uptime monitors, certificate dashboards, maintenance
// windows, the legacy public status page and the heartbeat receiver.

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtMonitorsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/monitors", h(rtMonitorsList))
	r.Handle("POST /api/monitors", h(rtMonitorsCreate))
	r.Handle("GET /api/monitors/certificates", h(rtMonitorsCertificateDashboard))
	r.Handle("GET /api/admin/certificates", h(rtMonitorsCertificateDashboardForAdmin))
	r.Handle("GET /api/monitors/maintenance", h(rtMonitorsListMaintenance))
	r.Handle("POST /api/monitors/maintenance", h(rtMonitorsCreateMaintenance))
	r.Handle("DELETE /api/monitors/maintenance/{id}", h(rtMonitorsDeleteMaintenance))
	r.Handle("PUT /api/monitors/{id}", h(rtMonitorsUpdate))
	r.Handle("DELETE /api/monitors/{id}", h(rtMonitorsRemove))
	r.Handle("GET /api/monitors/{id}/checks", h(rtMonitorsChecks))
	r.Handle("GET /api/monitors/{id}/incidents", h(rtMonitorsIncidents))
	r.Handle("GET /api/monitors/{id}/uptime", h(rtMonitorsUptimeStats))
	r.Handle("GET /api/monitors/{id}/chart", h(rtMonitorsResponseChart))
	r.Handle("POST /api/monitors/{id}/check", h(rtMonitorsForceCheck))
	// Public (no auth).
	r.Handle("GET /api/status-page", h(rtMonitorsStatusPage))
	// Heartbeat (no auth — the monitor validates by id + token).
	r.Handle("POST /api/heartbeat/{monitor_id}/{token}", h(rtMonitorsHeartbeat))
}

type rtMonitorsPaginationQuery struct {
	Limit  *int64 `json:"limit"`
	Offset *int64 `json:"offset"`
}

type rtMonitorsMonitor struct {
	ID                 uuid.UUID       `json:"id" db:"id"`
	UserID             uuid.UUID       `json:"user_id" db:"user_id"`
	SiteID             *uuid.UUID      `json:"site_id" db:"site_id"`
	URL                string          `json:"url" db:"url"`
	Name               string          `json:"name" db:"name"`
	CheckInterval      int32           `json:"check_interval" db:"check_interval"`
	Status             string          `json:"status" db:"status"`
	LastCheckedAt      *time.Time      `json:"last_checked_at" db:"last_checked_at"`
	LastResponseTime   *int32          `json:"last_response_time" db:"last_response_time"`
	LastStatusCode     *int32          `json:"last_status_code" db:"last_status_code"`
	Enabled            bool            `json:"enabled" db:"enabled"`
	AlertEmail         bool            `json:"alert_email" db:"alert_email"`
	AlertSlackURL      *string         `json:"alert_slack_url" db:"alert_slack_url"`
	AlertDiscordURL    *string         `json:"alert_discord_url" db:"alert_discord_url"`
	MonitorType        string          `json:"monitor_type" db:"monitor_type"`
	Port               *int32          `json:"port" db:"port"`
	Keyword            *string         `json:"keyword" db:"keyword"`
	KeywordMustContain bool            `json:"keyword_must_contain" db:"keyword_must_contain"`
	CustomHeaders      json.RawMessage `json:"custom_headers" db:"custom_headers"`
	HeartbeatToken     *string         `json:"heartbeat_token" db:"heartbeat_token"`
	CreatedAt          time.Time       `json:"created_at" db:"created_at"`
}

type rtMonitorsCreateMonitor struct {
	URL                string           `json:"url"`
	Name               string           `json:"name"`
	SiteID             *uuid.UUID       `json:"site_id"`
	CheckInterval      *int32           `json:"check_interval"`
	AlertEmail         *bool            `json:"alert_email"`
	AlertSlackURL      *string          `json:"alert_slack_url"`
	AlertDiscordURL    *string          `json:"alert_discord_url"`
	MonitorType        *string          `json:"monitor_type"`
	Port               *int32           `json:"port"`
	Keyword            *string          `json:"keyword"`
	KeywordMustContain *bool            `json:"keyword_must_contain"`
	CustomHeaders      *json.RawMessage `json:"custom_headers"`
}

type rtMonitorsUpdateMonitor struct {
	Name               *string          `json:"name"`
	URL                *string          `json:"url"`
	CheckInterval      *int32           `json:"check_interval"`
	Enabled            *bool            `json:"enabled"`
	AlertEmail         *bool            `json:"alert_email"`
	AlertSlackURL      *string          `json:"alert_slack_url"`
	AlertDiscordURL    *string          `json:"alert_discord_url"`
	MonitorType        *string          `json:"monitor_type"`
	Port               *int32           `json:"port"`
	Keyword            *string          `json:"keyword"`
	KeywordMustContain *bool            `json:"keyword_must_contain"`
	CustomHeaders      *json.RawMessage `json:"custom_headers"`
}

// rtMonitorsDecryptMonitorAlertURLs: alert_slack_url/alert_discord_url are
// encrypted at rest. The caller reading their own monitor back is the
// same-account case DecryptCredentialOrLegacy exists for.
func rtMonitorsDecryptMonitorAlertURLs(m *rtMonitorsMonitor, jwtSecret string) {
	if m.AlertSlackURL != nil {
		v := SecretsCryptoDecryptCredentialOrLegacy(*m.AlertSlackURL, jwtSecret)
		m.AlertSlackURL = &v
	}
	if m.AlertDiscordURL != nil {
		v := SecretsCryptoDecryptCredentialOrLegacy(*m.AlertDiscordURL, jwtSecret)
		m.AlertDiscordURL = &v
	}
}

// rtMonitorsTrimHostPrefixes is Rust's
// trim_start_matches("tcp://").trim_start_matches("ping://").
func rtMonitorsTrimHostPrefixes(s string) string {
	for strings.HasPrefix(s, "tcp://") {
		s = s[len("tcp://"):]
	}
	for strings.HasPrefix(s, "ping://") {
		s = s[len("ping://"):]
	}
	return s
}

func rtMonitorsKnownType(t string) bool {
	return t == "http" || t == "tcp" || t == "ping" || t == "heartbeat"
}

func rtMonitorsEmpty(p *string) bool { return p == nil || *p == "" }

// rtMonitorsList is GET /api/monitors.
func rtMonitorsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var params rtMonitorsPaginationQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	limit, offset := paginate(params.Limit, params.Offset)
	monitors, err := queryAll[rtMonitorsMonitor](r.Context(), st.DB,
		"SELECT * FROM monitors WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3", claims.Sub, limit, offset)
	if err != nil {
		return internalError("list monitors", err)
	}
	for i := range monitors {
		rtMonitorsDecryptMonitorAlertURLs(&monitors[i], st.Config.JWTSecret)
	}
	writeJSON(w, http.StatusOK, monitors)
	return nil
}

// rtMonitorsCreate is POST /api/monitors.
func rtMonitorsCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtMonitorsCreateMonitor
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	monitorType := "http"
	if body.MonitorType != nil {
		monitorType = *body.MonitorType
	}
	if !rtMonitorsKnownType(monitorType) {
		return apiErr(http.StatusBadRequest, "monitor_type must be 'http', 'tcp', 'ping', or 'heartbeat'")
	}

	url := strings.TrimSpace(body.URL)
	switch monitorType {
	case "http":
		if url == "" || (!strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://")) {
			return apiErr(http.StatusBadRequest, "URL must start with http:// or https://")
		}
		// SSRF protection: block internal URLs.
		if err := validateURLNotInternal(ctx, url); err != nil {
			return apiErr(http.StatusBadRequest, "Invalid monitor URL: "+err.Error())
		}
	case "tcp", "ping":
		// Same SSRF boundary as the HTTP lane, on the bare host these store: a
		// tcp monitor to 127.0.0.1:22 is an internal port probe.
		if url == "" {
			return apiErr(http.StatusBadRequest, "Host/URL is required")
		}
		host := rtMonitorsTrimHostPrefixes(url)
		port := int32(80)
		if body.Port != nil {
			port = *body.Port
		}
		if err := validateHostNotInternal(ctx, host, uint16(min(max(port, 0), 65535))); err != nil {
			return apiErr(http.StatusBadRequest, "Invalid monitor host: "+err.Error())
		}
	default:
		// heartbeat: passive, but still needs an identifier.
		if url == "" {
			return apiErr(http.StatusBadRequest, "Host/URL is required")
		}
	}

	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 100 {
		return apiErr(http.StatusBadRequest, "Name must be 1-100 characters")
	}

	interval := int32(60)
	if body.CheckInterval != nil {
		interval = *body.CheckInterval
	}
	interval = min(max(interval, 30), 3600)

	// Inherit alert URLs from the global alert rules if not provided.
	slackURL, discordURL := body.AlertSlackURL, body.AlertDiscordURL
	if rtMonitorsEmpty(slackURL) || rtMonitorsEmpty(discordURL) {
		global, _ := queryOpt[Tup2[*string, *string]](ctx, st.DB,
			"SELECT notify_slack_url, notify_discord_url FROM alert_rules WHERE user_id = $1 AND server_id IS NULL LIMIT 1", claims.Sub)
		if global != nil {
			// Ciphertext at rest — decrypt before the SSRF check below, which
			// needs a real URL, not base64.
			dec := func(p *string) *string {
				if p == nil {
					return nil
				}
				v := SecretsCryptoDecryptCredentialOrLegacy(*p, st.Config.JWTSecret)
				return &v
			}
			if rtMonitorsEmpty(slackURL) {
				slackURL = dec(global.A)
			}
			if rtMonitorsEmpty(discordURL) {
				discordURL = dec(global.B)
			}
		}
	}

	// SSRF protection on per-monitor alert webhooks (parity with
	// alerts.rs::upsert_rules; inherited values were vetted but are cheap to
	// re-check).
	if !rtMonitorsEmpty(slackURL) {
		if err := validateURLNotInternal(ctx, *slackURL); err != nil {
			return apiErr(http.StatusBadRequest, "Invalid Slack alert URL: "+err.Error())
		}
	}
	if !rtMonitorsEmpty(discordURL) {
		if err := validateURLNotInternal(ctx, *discordURL); err != nil {
			return apiErr(http.StatusBadRequest, "Invalid Discord alert URL: "+err.Error())
		}
	}

	// Limit monitors per user (50).
	count, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM monitors WHERE user_id = $1", claims.Sub)
	if err != nil {
		return internalError("create monitors", err)
	}
	if count >= 50 {
		return apiErr(http.StatusBadRequest, "Monitor limit reached (50)")
	}

	// Encrypt at rest, after SSRF validation ran on the plaintext. Empty
	// stays empty (fresh row, no "leave alone" case).
	encryptOpt := func(v *string) (*string, error) {
		if v == nil || *v == "" {
			return v, nil
		}
		s, err := SecretsCryptoEncryptCredential(*v, st.Config.JWTSecret)
		if err != nil {
			return nil, internalError("encrypt monitor alert URL", err)
		}
		return &s, nil
	}
	encSlack, err := encryptOpt(slackURL)
	if err != nil {
		return err
	}
	encDiscord, err := encryptOpt(discordURL)
	if err != nil {
		return err
	}

	alertEmail := body.AlertEmail == nil || *body.AlertEmail
	mustContain := body.KeywordMustContain == nil || *body.KeywordMustContain
	monitor, err := queryOne[rtMonitorsMonitor](ctx, st.DB,
		"INSERT INTO monitors (user_id, site_id, url, name, check_interval, alert_email, alert_slack_url, alert_discord_url, monitor_type, port, keyword, keyword_must_contain, custom_headers) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *",
		claims.Sub, body.SiteID, url, name, interval, alertEmail, encSlack, encDiscord, monitorType, body.Port, body.Keyword, mustContain, rtMonitorsJSONArg(body.CustomHeaders))
	if err != nil {
		return internalError("create monitors", err)
	}
	rtMonitorsDecryptMonitorAlertURLs(&monitor, st.Config.JWTSecret)
	writeJSON(w, http.StatusCreated, monitor)
	return nil
}

// rtMonitorsJSONArg binds an Option<Value>: nil → SQL NULL, else the JSON text.
func rtMonitorsJSONArg(v *json.RawMessage) any {
	if v == nil {
		return nil
	}
	return string(*v)
}

// rtMonitorsUpdate is PUT /api/monitors/{id}.
func rtMonitorsUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtMonitorsUpdateMonitor
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	existing, err := queryOpt[rtMonitorsMonitor](ctx, st.DB, "SELECT * FROM monitors WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("update monitors", err)
	}
	if existing == nil {
		return apiErr(http.StatusNotFound, "Monitor not found")
	}

	// A type change must be to a known type — create checked, update did
	// not, so a monitor could fall through the check dispatcher.
	if body.MonitorType != nil && !rtMonitorsKnownType(*body.MonitorType) {
		return apiErr(http.StatusBadRequest, "monitor_type must be 'http', 'tcp', 'ping', or 'heartbeat'")
	}

	// SSRF: validate a new URL/host against the EFFECTIVE type after this
	// update — otherwise switching http→tcp, or setting a host on a tcp
	// monitor, skips the guard create enforces.
	effectiveType := existing.MonitorType
	if body.MonitorType != nil {
		effectiveType = *body.MonitorType
	}
	if body.URL != nil {
		trimmed := strings.TrimSpace(*body.URL)
		switch effectiveType {
		case "http":
			if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
				if err := validateURLNotInternal(ctx, trimmed); err != nil {
					return apiErr(http.StatusBadRequest, "Invalid monitor URL: "+err.Error())
				}
			}
		case "tcp", "ping":
			if trimmed != "" {
				host := rtMonitorsTrimHostPrefixes(trimmed)
				port := int32(80)
				if body.Port != nil {
					port = *body.Port
				} else if existing.Port != nil {
					port = *existing.Port
				}
				if err := validateHostNotInternal(ctx, host, uint16(min(max(port, 0), 65535))); err != nil {
					return apiErr(http.StatusBadRequest, "Invalid monitor host: "+err.Error())
				}
			}
		}
	}

	if !rtMonitorsEmpty(body.AlertSlackURL) {
		if err := validateURLNotInternal(ctx, *body.AlertSlackURL); err != nil {
			return apiErr(http.StatusBadRequest, "Invalid Slack alert URL: "+err.Error())
		}
	}
	if !rtMonitorsEmpty(body.AlertDiscordURL) {
		if err := validateURLNotInternal(ctx, *body.AlertDiscordURL); err != nil {
			return apiErr(http.StatusBadRequest, "Invalid Discord alert URL: "+err.Error())
		}
	}

	// Encrypt at rest. nil = "leave the stored value alone" (the COALESCE
	// depends on it), "" = "clear it".
	encryptOpt := func(v *string) (*string, error) {
		if v == nil || *v == "" {
			return v, nil
		}
		s, err := SecretsCryptoEncryptCredential(*v, st.Config.JWTSecret)
		if err != nil {
			return nil, internalError("encrypt monitor alert URL", err)
		}
		return &s, nil
	}
	encSlack, err := encryptOpt(body.AlertSlackURL)
	if err != nil {
		return err
	}
	encDiscord, err := encryptOpt(body.AlertDiscordURL)
	if err != nil {
		return err
	}
	var interval *int32
	if body.CheckInterval != nil {
		v := min(max(*body.CheckInterval, 30), 3600)
		interval = &v
	}

	monitor, err := queryOne[rtMonitorsMonitor](ctx, st.DB,
		"UPDATE monitors SET "+
			"name = COALESCE($2, name), "+
			"url = COALESCE($3, url), "+
			"check_interval = COALESCE($4, check_interval), "+
			"enabled = COALESCE($5, enabled), "+
			"alert_email = COALESCE($6, alert_email), "+
			"alert_slack_url = COALESCE($7, alert_slack_url), "+
			"alert_discord_url = COALESCE($8, alert_discord_url), "+
			"monitor_type = COALESCE($9, monitor_type), "+
			"port = COALESCE($10, port), "+
			"keyword = COALESCE($11, keyword), "+
			"keyword_must_contain = COALESCE($12, keyword_must_contain), "+
			"custom_headers = COALESCE($13, custom_headers) "+
			"WHERE id = $1 RETURNING *",
		id, body.Name, body.URL, interval, body.Enabled, body.AlertEmail, encSlack, encDiscord,
		body.MonitorType, body.Port, body.Keyword, body.KeywordMustContain, rtMonitorsJSONArg(body.CustomHeaders))
	if err != nil {
		return internalError("update monitors", err)
	}
	rtMonitorsDecryptMonitorAlertURLs(&monitor, st.Config.JWTSecret)
	writeJSON(w, http.StatusOK, monitor)
	return nil
}

// rtMonitorsRemove is DELETE /api/monitors/{id}.
func rtMonitorsRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM monitors WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("remove monitors", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Monitor not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

type rtMonitorsCheckRecord struct {
	ID           uuid.UUID `json:"id" db:"id"`
	StatusCode   *int32    `json:"status_code" db:"status_code"`
	ResponseTime *int32    `json:"response_time" db:"response_time"`
	Error        *string   `json:"error" db:"error"`
	CheckedAt    time.Time `json:"checked_at" db:"checked_at"`
}

// rtMonitorsOwned is the shared "verify ownership" preamble: claims, id, and
// a 404 when the caller does not own the monitor.
func rtMonitorsOwned(st *AppState, r *http.Request, ctxName string) (uuid.UUID, error) {
	claims, err := st.authUser(r)
	if err != nil {
		return uuid.Nil, err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return uuid.Nil, err
	}
	exists, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB, "SELECT id FROM monitors WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return uuid.Nil, internalError(ctxName, err)
	}
	if exists == nil {
		return uuid.Nil, apiErr(http.StatusNotFound, "Monitor not found")
	}
	return id, nil
}

// rtMonitorsChecks is GET /api/monitors/{id}/checks — recent check history.
func rtMonitorsChecks(st *AppState, w http.ResponseWriter, r *http.Request) error {
	id, err := rtMonitorsOwned(st, r, "checks")
	if err != nil {
		return err
	}
	records, err := queryAll[rtMonitorsCheckRecord](r.Context(), st.DB,
		"SELECT id, status_code, response_time, error, checked_at FROM monitor_checks WHERE monitor_id = $1 ORDER BY checked_at DESC LIMIT 100", id)
	if err != nil {
		return internalError("checks", err)
	}
	writeJSON(w, http.StatusOK, records)
	return nil
}

type rtMonitorsIncident struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	MonitorID  uuid.UUID  `json:"monitor_id" db:"monitor_id"`
	StartedAt  time.Time  `json:"started_at" db:"started_at"`
	ResolvedAt *time.Time `json:"resolved_at" db:"resolved_at"`
	Cause      *string    `json:"cause" db:"cause"`
}

// rtMonitorsIncidents is GET /api/monitors/{id}/incidents.
func rtMonitorsIncidents(st *AppState, w http.ResponseWriter, r *http.Request) error {
	id, err := rtMonitorsOwned(st, r, "incidents")
	if err != nil {
		return err
	}
	records, err := queryAll[rtMonitorsIncident](r.Context(), st.DB,
		"SELECT id, monitor_id, started_at, resolved_at, cause FROM incidents WHERE monitor_id = $1 ORDER BY started_at DESC LIMIT 50", id)
	if err != nil {
		return internalError("incidents", err)
	}
	writeJSON(w, http.StatusOK, records)
	return nil
}

// rtMonitorsUptimeCalc is the percentage rounded to 2 decimals; 100 with no data.
func rtMonitorsUptimeCalc(data *Tup2[int64, int64]) float64 {
	if data == nil || data.B <= 0 {
		return 100.0
	}
	return math.Round(float64(data.A)/float64(data.B)*10000.0) / 100.0
}

// rtMonitorsUptimeStats is GET /api/monitors/{id}/uptime.
func rtMonitorsUptimeStats(st *AppState, w http.ResponseWriter, r *http.Request) error {
	id, err := rtMonitorsOwned(st, r, "uptime stats")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// Successful check: HTTP 200-499 or TCP status_code=0 (no error = success).
	window := func(interval, ctxName string) (*Tup2[int64, int64], error) {
		v, err := queryOpt[Tup2[int64, int64]](ctx, st.DB,
			"SELECT COUNT(*) FILTER (WHERE status_code IS NOT NULL AND error IS NULL), COUNT(*) "+
				"FROM monitor_checks WHERE monitor_id = $1 AND checked_at > NOW() - INTERVAL '"+interval+"'", id)
		if err != nil {
			return nil, internalError(ctxName, err)
		}
		return v, nil
	}
	day, err := window("24 hours", "uptime stats 24h")
	if err != nil {
		return err
	}
	week, err := window("7 days", "uptime stats 7d")
	if err != nil {
		return err
	}
	month, err := window("30 days", "uptime stats 30d")
	if err != nil {
		return err
	}
	avg, err := queryScalarOpt[*float64](ctx, st.DB,
		"SELECT AVG(response_time)::float8 FROM monitor_checks WHERE monitor_id = $1 AND checked_at > NOW() - INTERVAL '24 hours' AND status_code IS NOT NULL", id)
	if err != nil {
		return internalError("uptime stats avg response", err)
	}
	avgMs := 0.0
	if avg != nil && *avg != nil {
		avgMs = **avg
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"uptime_24h":      rtMonitorsUptimeCalc(day),
		"uptime_7d":       rtMonitorsUptimeCalc(week),
		"uptime_30d":      rtMonitorsUptimeCalc(month),
		"avg_response_ms": int32(math.Round(avgMs)),
	})
	return nil
}

// rtMonitorsResponseChart is GET /api/monitors/{id}/chart.
func rtMonitorsResponseChart(st *AppState, w http.ResponseWriter, r *http.Request) error {
	id, err := rtMonitorsOwned(st, r, "response chart")
	if err != nil {
		return err
	}
	points, err := queryAll[Tup2[int32, time.Time]](r.Context(), st.DB,
		"SELECT response_time, checked_at FROM monitor_checks "+
			"WHERE monitor_id = $1 AND checked_at > NOW() - INTERVAL '24 hours' AND status_code IS NOT NULL "+
			"ORDER BY checked_at ASC", id)
	if err != nil {
		return internalError("response chart points", err)
	}
	data := make([]map[string]any, 0, len(points))
	for _, p := range points {
		data = append(data, map[string]any{"time": p.B.Unix(), "ms": p.A})
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": data})
	return nil
}

// rtMonitorsForceCheck is POST /api/monitors/{id}/check.
func rtMonitorsForceCheck(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "UPDATE monitors SET last_checked_at = NOW() - INTERVAL '1 hour' WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("force check", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Monitor not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Check will run within 60 seconds"})
	return nil
}

// rtMonitorsStatusPage is GET /api/status-page — public (no auth).
func rtMonitorsStatusPage(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	// The one gate every unauthenticated status-page route passes through.
	if err := PublicStatusRequireEnabled(ctx, st.DB); err != nil {
		return err
	}

	// SECURITY (s430): unauthenticated, so the query MUST be scoped to the
	// status page's owner. It once used an unscoped `WHERE enabled = true`
	// ("no user filter — this is public"), serving every OTHER tenant's
	// monitor names/statuses to an anonymous caller — two releases after the
	// identical bug was fixed in incidents::public_status_page. Same owner
	// resolution as that sibling.
	ownerID := PublicStatusResolveCurrentStatusPageOwner(ctx, st.DB)

	// The error is propagated, and on THIS route that is the point: an empty
	// list renders as a status page with nothing wrong on it — the most
	// reassuring page, served exactly when a reader suspects something is.
	type row = Tup5[string, string, string, *int32, *time.Time]
	var monitors []row
	if ownerID != nil {
		var err error
		monitors, err = queryAll[row](ctx, st.DB,
			"SELECT name, url, status, last_response_time, last_checked_at FROM monitors WHERE enabled = true AND user_id = $1 ORDER BY name", *ownerID)
		if err != nil {
			return internalError("status page monitors", err)
		}
	}
	items := make([]map[string]any, 0, len(monitors))
	allUp := true
	for _, m := range monitors {
		// URL dropped deliberately — never published.
		items = append(items, map[string]any{"name": m.A, "status": m.C, "response_time": m.D, "last_checked": m.E})
		if m.C != "up" {
			allUp = false
		}
	}
	status := "degraded"
	if allUp {
		status = "operational"
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "monitors": items, "updated_at": time.Now().UTC()})
	return nil
}

// rtMonitorsExpiryStatus is the one severity ladder both certificate lists
// use. nil days is "unknown" — a missing expiry once became 999 days and the
// green OK badge, the most reassuring answer produced by an absence of
// information (every certificate the panel did not issue arrives that way).
//
// renewalFailing sits BELOW expired (the outage already happened) and ABOVE
// everything else: "the renewal is failing" is a fact where unknown is its
// absence, and critical/warning/ok say when the cert dies while this says
// nothing is coming to save it. Every other rung is a function of the clock
// alone, so a failing renewal used to read ok for 300 days.
func rtMonitorsExpiryStatus(daysLeft *int64, renewalFailing bool) string {
	switch {
	case daysLeft != nil && *daysLeft < 0:
		return "expired"
	case renewalFailing:
		return "renewal_failed"
	case daysLeft == nil:
		return "unknown"
	case *daysLeft <= 7:
		return "critical"
	case *daysLeft <= 30:
		return "warning"
	default:
		return "ok"
	}
}

// rtMonitorsRenewalFailingSites returns the sites among siteIDs whose
// renewal is currently failing — keyed on the state_keys
// NotificationsRenewalSuccessClears accepts (those that say a renewal DID NOT
// HAPPEN), not a re-listed copy free to drift. The other three describe the
// installed cert, not a failure. status = 'firing' ONLY: ResolveAlert
// matches firing in every arm, so an acknowledged alert is never resolved by
// a later success and would pin the rung on forever. Scoped by site_id alone
// (the ids ARE the scope); a user/server arm would reproduce the shape that
// made ResolveAlert miss the security scanner's server-less rows.
func rtMonitorsRenewalFailingSites(r *http.Request, st *AppState, siteIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	out := map[uuid.UUID]bool{}
	if len(siteIDs) == 0 {
		return out, nil
	}
	keys := []string{}
	for _, k := range NotificationsSslRenewalKeyAll {
		if NotificationsRenewalSuccessClears(k) {
			keys = append(keys, k)
		}
	}
	rows, err := queryAll[uuid.UUID](r.Context(), st.DB,
		"SELECT DISTINCT site_id FROM alerts "+
			"WHERE alert_type = 'ssl_renewal_failure' AND status = 'firing' "+
			"AND site_id = ANY($1) AND state_key = ANY($2)", siteIDs, keys)
	if err != nil {
		return nil, internalError("renewal failure lookup", err)
	}
	for _, id := range rows {
		out[id] = true
	}
	return out, nil
}

// rtMonitorsRenewalFailingStacksForUser is the stacks sibling, scoped by
// user_id: certificate_dashboard has no server scope, and alerts.user_id is
// always the stack's real owner (renew_stack_certificate resolves it).
func rtMonitorsRenewalFailingStacksForUser(r *http.Request, st *AppState, userID uuid.UUID, domains []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(domains) == 0 {
		return out, nil
	}
	keys := make([]string, 0, len(domains))
	for _, d := range domains {
		keys = append(keys, SecurityScannerStackRenewalStateKey(d))
	}
	rows, err := queryAll[string](r.Context(), st.DB,
		"SELECT DISTINCT state_key FROM alerts "+
			"WHERE alert_type = 'ssl_renewal_failure' AND status = 'firing' "+
			"AND user_id = $1 AND state_key = ANY($2)", userID, keys)
	if err != nil {
		return nil, internalError("stack renewal failure lookup", err)
	}
	for _, k := range rows {
		out[k] = true
	}
	return out, nil
}

// rtMonitorsDaysLeft is chrono's (expiry - now).num_days() (truncating).
func rtMonitorsDaysLeft(expiry *time.Time, now time.Time) *int64 {
	if expiry == nil {
		return nil
	}
	d := int64(expiry.Sub(now) / (24 * time.Hour))
	return &d
}

// rtMonitorsCertificateDashboard is GET /api/monitors/certificates.
//
// No requireAdmin: the query is WHERE user_id = $1, so the gate never
// decided WHAT this returns, only WHO is refused their own rows — while the
// Dashboard tile linking here (user-scoped) showed the same certificates.
func rtMonitorsCertificateDashboard(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	type siteCertRow = Tup5[uuid.UUID, string, bool, *time.Time, *time.Time]
	certs, err := queryAll[siteCertRow](ctx, st.DB,
		"SELECT id, domain, ssl_enabled, ssl_expiry, ssl_renewal_at FROM sites WHERE user_id = $1 AND ssl_enabled = true ORDER BY ssl_expiry ASC NULLS LAST", claims.Sub)
	if err != nil {
		return internalError("certificate list", err)
	}

	// An unknown expiry is "unknown", not "ok" (see rtMonitorsExpiryStatus).
	now := time.Now()
	ids := make([]uuid.UUID, 0, len(certs))
	for _, c := range certs {
		ids = append(ids, c.A)
	}
	failing, err := rtMonitorsRenewalFailingSites(r, st, ids)
	if err != nil {
		return err
	}
	items := make([]map[string]any, 0, len(certs))
	for _, c := range certs {
		days := rtMonitorsDaysLeft(c.D, now)
		// stack_id is null on every site row but always on the wire, so the
		// page never sees it appear/disappear. renewal_at is the CA-suggested
		// ARI window start (RFC 9773) stored by the auto-healer.
		items = append(items, map[string]any{
			"site_id": c.A, "stack_id": nil, "domain": c.B, "expiry": c.D, "days_left": days,
			"status": rtMonitorsExpiryStatus(days, failing[c.A]), "renewal_at": c.E,
		})
	}

	// The caller's own Compose stacks, ACME-mode only through
	// effective_tls_mode — the same rule the admin list and alert ladder use.
	type stackRow = Tup5[uuid.UUID, string, *time.Time, *string, *string]
	stacks, err := queryAll[stackRow](ctx, st.DB,
		"SELECT id, domain, ssl_expiry, tls_mode, ssl_email FROM docker_stacks WHERE user_id = $1 AND domain IS NOT NULL", claims.Sub)
	if err != nil {
		return internalError("certificate list stacks", err)
	}
	var acme []stackRow
	var domains []string
	for _, s := range stacks {
		if rtStacksEffectiveTlsMode(s.D, s.E) == "acme" {
			acme = append(acme, s)
			domains = append(domains, s.B)
		}
	}
	failingStacks, err := rtMonitorsRenewalFailingStacksForUser(r, st, claims.Sub, domains)
	if err != nil {
		return err
	}
	for _, s := range acme {
		days := rtMonitorsDaysLeft(s.C, now)
		items = append(items, map[string]any{
			"site_id": nil, "stack_id": s.A, "domain": s.B, "expiry": s.C, "days_left": days,
			"status": rtMonitorsExpiryStatus(days, failingStacks[SecurityScannerStackRenewalStateKey(s.B)]),
			// docker_stacks has no ssl_renewal_at (ARI is per sites row).
			"renewal_at": nil,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": items})
	return nil
}

// rtMonitorsCertificateDashboardForAdmin is GET /api/admin/certificates —
// every certificate on this server, admin only. A SEPARATE route (like
// /api/admin/sites) so a per-caller list can never quietly return other
// people's rows.
//
// Why it exists: the agent's diagnostics walks /etc/dockpanel/ssl on the
// host and raised findings (with a Fix button) about certificates that
// appeared on no list an admin could open. So this returns every SSL site on
// this server with its owner, plus every certificate on disk no row explains
// (DNS-01 wildcard apex, Docker app certs, hand-installed). host_scan reports
// whether the disk was actually read — an older agent cannot enumerate, and
// the page must say so rather than imply completeness.
func rtMonitorsCertificateDashboardForAdmin(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	type adminCertRow = Tup5[uuid.UUID, string, *time.Time, *string, *time.Time]
	certs, err := queryAll[adminCertRow](ctx, st.DB,
		"SELECT s.id, s.domain, s.ssl_expiry, u.email AS owner_email, s.ssl_renewal_at "+
			"FROM sites s LEFT JOIN users u ON u.id = s.user_id "+
			"WHERE s.server_id = $1 AND s.ssl_enabled = true "+
			"ORDER BY s.ssl_expiry ASC NULLS LAST", serverID)
	if err != nil {
		return internalError("admin certificate list", err)
	}

	now := time.Now()
	ids := make([]uuid.UUID, 0, len(certs))
	for _, c := range certs {
		ids = append(ids, c.A)
	}
	failing, err := rtMonitorsRenewalFailingSites(r, st, ids)
	if err != nil {
		return err
	}
	items := make([]map[string]any, 0, len(certs))
	for _, c := range certs {
		days := rtMonitorsDaysLeft(c.C, now)
		items = append(items, map[string]any{
			"site_id": c.A,
			// Always on the wire, even null: absent reaches TypeScript as
			// undefined, and undefined !== null would hand every site row the
			// stack control.
			"stack_id":    nil,
			"domain":      c.B,
			"expiry":      c.C,
			"days_left":   days,
			"status":      rtMonitorsExpiryStatus(days, failing[c.A]),
			"owner_email": c.D,
			"managed":     true,
			"renewal_at":  c.E,
		})
	}

	// Every stack on this host with a domain, read ONCE (the disk walk asks
	// "is this a stack's?" per directory). ssl_expiry is for the offline arm.
	type stackRow = Tup5[uuid.UUID, string, *string, *string, *time.Time]
	stacks, err := queryAll[stackRow](ctx, st.DB,
		"SELECT id, domain, tls_mode, ssl_email, ssl_expiry FROM docker_stacks WHERE server_id = $1 AND domain IS NOT NULL", serverID)
	if err != nil {
		return internalError("admin certificate list stacks", err)
	}

	// Stack renewal alerts carry site_id NULL and are keyed by
	// stack_renewal_state_key(domain) under this server, so the site lookup
	// can never match them; scoped by server + state_key instead.
	failingStacks := map[string]bool{}
	if len(stacks) > 0 {
		keys := make([]string, 0, len(stacks))
		for _, s := range stacks {
			keys = append(keys, SecurityScannerStackRenewalStateKey(s.B))
		}
		rows, err := queryAll[string](ctx, st.DB,
			"SELECT DISTINCT state_key FROM alerts "+
				"WHERE alert_type = 'ssl_renewal_failure' AND status = 'firing' "+
				"AND server_id = $1 AND state_key = ANY($2)", serverID, keys)
		if err != nil {
			return internalError("stack renewal failure lookup", err)
		}
		for _, k := range rows {
			failingStacks[k] = true
		}
	}

	// Only an ACME stack is ours: a `provided` stack serves its cert from the
	// registry, and the file under /etc/dockpanel/ssl is a LEFTOVER — offering
	// to renew it, or stamping its expiry, would describe a cert the stack
	// does not serve.
	acmeStack := func(domain string) *stackRow {
		for i := range stacks {
			s := &stacks[i]
			if strings.EqualFold(s.B, domain) && rtStacksEffectiveTlsMode(s.C, s.D) == "acme" {
				return s
			}
		}
		return nil
	}

	// Best-effort, and its failure is REPORTED, not swallowed.
	hostScan := true
	v, err := agent.Get(ctx, "/ssl/certificates")
	if err == nil {
		known := map[string]bool{}
		for _, c := range certs {
			known[c.B] = true
		}
		arr, _ := jsonArr(v)
		for _, c := range arr {
			domain, ok := jsonStr(jsonGet(c, "domain"))
			if !ok || known[domain] {
				continue
			}
			var days *int64
			if d, ok := jsonI64(jsonGet(c, "days_remaining")); ok {
				days = &d
			}
			var expiry *time.Time
			if s, ok := jsonStr(jsonGet(c, "not_after")); ok {
				expiry = parseAgentCertExpiry(s)
			}
			stack := acmeStack(domain)
			var stackID *uuid.UUID
			if stack != nil {
				stackID = &stack.A
				// BOOTSTRAP: the agent's walk is the only thing that knows a
				// stack cert's expiry; record it so the offline arm has
				// something to fall back on. Best-effort (a GET must not fail
				// on bookkeeping) and only when it actually MOVED — otherwise
				// every page load writes one UPDATE per stack cert forever.
				if expiry != nil && (stack.E == nil || !stack.E.Equal(*expiry)) {
					_, _ = execSQL(ctx, st.DB, "UPDATE docker_stacks SET ssl_expiry = $1 WHERE id = $2", *expiry, stack.A)
				}
			}
			items = append(items, map[string]any{
				"site_id":     nil,
				"stack_id":    stackID,
				"domain":      domain,
				"expiry":      expiry,
				"days_left":   days,
				"status":      rtMonitorsExpiryStatus(days, failingStacks[SecurityScannerStackRenewalStateKey(domain)]),
				"issuer":      jsonGet(c, "issuer"),
				"owner_email": nil,
				// On disk, belonging to no site and no ACME stack: nothing here
				// can renew or remove it, and the page says so.
				"managed":    false,
				"renewal_at": nil,
			})
		}
	} else {
		slog.Warn(fmt.Sprintf("Admin certificate list: this server's agent could not enumerate certificates (%v) — falling back to what the panel recorded", err))
		// THE OFFLINE ANSWER, and why docker_stacks.ssl_expiry exists: without
		// it every stack certificate VANISHED from this page while the agent
		// was down — exactly when an operator is looking. These rows are the
		// panel's own record: no issuer, no control, marked stale.
		for _, s := range stacks {
			if rtStacksEffectiveTlsMode(s.C, s.D) != "acme" || s.E == nil {
				continue
			}
			days := rtMonitorsDaysLeft(s.E, now)
			items = append(items, map[string]any{
				"site_id":     nil,
				"stack_id":    s.A,
				"domain":      s.B,
				"expiry":      s.E,
				"days_left":   days,
				"status":      rtMonitorsExpiryStatus(days, failingStacks[SecurityScannerStackRenewalStateKey(s.B)]),
				"issuer":      nil,
				"owner_email": nil,
				"managed":     true,
				// The one thing this row must not do is look like a live read.
				"stale":      true,
				"renewal_at": nil,
			})
		}
		hostScan = false
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": items, "host_scan": hostScan})
	return nil
}

// rtMonitorsCreateMaintenance is POST /api/monitors/maintenance. Windows are
// per-caller in all three statements, and what a window does is silence
// THAT caller's alerts — which any site owner with alerts may need.
func rtMonitorsCreateMaintenance(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	name, ok := jsonStr(jsonGet(body, "name"))
	if !ok {
		name = "Maintenance"
	}
	startsAt, _ := jsonStr(jsonGet(body, "starts_at"))
	endsAt, _ := jsonStr(jsonGet(body, "ends_at"))
	if startsAt == "" || endsAt == "" {
		return apiErr(http.StatusBadRequest, "starts_at and ends_at required")
	}
	id, err := queryScalar[uuid.UUID](r.Context(), st.DB,
		"INSERT INTO maintenance_windows (user_id, name, starts_at, ends_at) VALUES ($1, $2, $3::timestamptz, $4::timestamptz) RETURNING id",
		claims.Sub, name, startsAt, endsAt)
	if err != nil {
		return internalError("create maintenance", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
	return nil
}

// rtMonitorsListMaintenance is GET /api/monitors/maintenance. The error is
// propagated because an empty list is not neutral: uptime skips every
// monitor of a user with an active window, so a failed read showed no
// windows while one was still muting alerting — and hid the delete control.
func rtMonitorsListMaintenance(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	windows, err := queryAll[Tup4[uuid.UUID, string, time.Time, time.Time]](r.Context(), st.DB,
		"SELECT id, name, starts_at, ends_at FROM maintenance_windows WHERE user_id = $1 ORDER BY starts_at DESC LIMIT 20", claims.Sub)
	if err != nil {
		return internalError("maintenance windows", err)
	}
	now := time.Now()
	items := make([]map[string]any, 0, len(windows))
	for _, m := range windows {
		active := !now.Before(m.C) && !now.After(m.D)
		items = append(items, map[string]any{"id": m.A, "name": m.B, "starts_at": m.C, "ends_at": m.D, "active": active})
	}
	writeJSON(w, http.StatusOK, map[string]any{"windows": items})
	return nil
}

// rtMonitorsDeleteMaintenance is DELETE /api/monitors/maintenance/{id}.
// `AND user_id = $2` is the authorization. The result is checked: a window
// that outlives its "deleted" message leaves the whole account with no uptime
// checks or alerts, and finishing maintenance early to resume exactly those
// is the ordinary reason to press delete.
func rtMonitorsDeleteMaintenance(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM maintenance_windows WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("delete maintenance window", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "That maintenance window no longer exists, or it belongs to another account. Monitoring is unchanged — reload the list before retrying.")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtMonitorsHeartbeat is POST /api/heartbeat/{monitor_id}/{token} (no auth).
func rtMonitorsHeartbeat(st *AppState, w http.ResponseWriter, r *http.Request) error {
	monitorID, err := pathUUID(r, "monitor_id")
	if err != nil {
		return err
	}
	token := r.PathValue("token")
	ctx := r.Context()
	monitor, err := queryOpt[Tup3[uuid.UUID, string, *string]](ctx, st.DB,
		"SELECT id, COALESCE(name, ''), heartbeat_token FROM monitors WHERE id = $1 AND monitor_type = 'heartbeat'", monitorID)
	if err != nil {
		return internalError("heartbeat monitor lookup", err)
	}
	if monitor == nil {
		return apiErr(http.StatusNotFound, "Monitor not found")
	}
	if monitor.C == nil || *monitor.C != token {
		return apiErr(http.StatusUnauthorized, "Invalid heartbeat token")
	}
	_, _ = execSQL(ctx, st.DB, "INSERT INTO monitor_checks (monitor_id, status_code, response_time, checked_at) VALUES ($1, 200, 0, NOW())", monitorID)
	_, _ = execSQL(ctx, st.DB, "UPDATE monitors SET status = 'up', last_checked_at = NOW(), last_response_time = 0, last_status_code = 200 WHERE id = $1", monitorID)
	_, _ = execSQL(ctx, st.DB, "UPDATE incidents SET resolved_at = NOW() WHERE monitor_id = $1 AND resolved_at IS NULL", monitorID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}
