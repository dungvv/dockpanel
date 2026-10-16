package api

// Port of panel/backend/src/routes/prometheus.rs — the Prometheus /metrics
// scrape endpoint and its admin toggle.
//
// Disabled by default. The admin enables it and a scrape token is generated
// once; Prometheus is configured with bearer-token auth:
//
//	scrape_configs:
//	  - job_name: 'dockpanel'
//	    metrics_path: /api/metrics
//	    bearer_token: dpms_...
//	    static_configs:
//	      - targets: ['panel.example.com']
//
// Disabled → /api/metrics is 404 (the endpoint is not advertised). Enabled but
// the token is wrong or missing → 401. Constant-time comparison of the SHA-256
// hashed token.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

func rtPrometheusRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/metrics", h(rtPrometheusScrape))
	r.Handle("GET /api/prometheus/settings", h(rtPrometheusGetSettings))
	r.Handle("POST /api/prometheus/settings", h(rtPrometheusUpdateSettings))
}

type rtPrometheusScrapeQuery struct {
	Token *string `json:"token"`
}

// rtPrometheusScrape: GET /api/metrics. No JWT; gated by the scrape token.
func rtPrometheusScrape(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var q rtPrometheusScrapeQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	enabled, tokenHash, err := rtPrometheusReadSettings(r.Context(), st)
	if err != nil {
		return internalError("read prometheus settings", err)
	}
	if !enabled {
		return apiErr(http.StatusNotFound, "Not Found")
	}
	if tokenHash == nil || *tokenHash == "" {
		return apiErr(http.StatusUnauthorized, "No scrape token configured")
	}
	stored := *tokenHash

	// Header first, else ?token=. An EMPTY bearer does not fall through to the
	// query (Rust `.or(q.token)` only applies when the header is absent).
	var provided string
	have := false
	if auth, ok := rtAgentCheckinHeaderStr(r, "Authorization"); ok {
		if t, ok := strings.CutPrefix(auth, "Bearer "); ok {
			provided, have = t, true
		}
	}
	if !have && q.Token != nil {
		provided, have = *q.Token, true
	}
	if !have || provided == "" {
		return apiErr(http.StatusUnauthorized, "Scrape token required")
	}

	sum := sha256.Sum256([]byte(provided))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(stored)) != 1 {
		return apiErr(http.StatusUnauthorized, "Invalid scrape token")
	}

	body := PrometheusExporterRender(r.Context(), st.DB)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
	return nil
}

// ── Admin surface ───────────────────────────────────────────────────────

type rtPrometheusPromSettings struct {
	Enabled         bool    `json:"enabled"`
	TokenConfigured bool    `json:"token_configured"`
	TokenPrefix     *string `json:"token_prefix"`
}

// rtPrometheusGetSettings: GET /api/prometheus/settings.
func rtPrometheusGetSettings(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	enabled, tokenHash, err := rtPrometheusReadSettings(r.Context(), st)
	if err != nil {
		return internalError("read prometheus settings", err)
	}
	prefix, err := queryScalarOpt[string](r.Context(), st.DB, "SELECT value FROM settings WHERE key = 'prometheus_token_prefix'")
	if err != nil {
		return internalError("read prometheus prefix", err)
	}
	if prefix != nil && *prefix == "" {
		prefix = nil
	}
	writeJSON(w, http.StatusOK, rtPrometheusPromSettings{
		Enabled:         enabled,
		TokenConfigured: tokenHash != nil && *tokenHash != "",
		TokenPrefix:     prefix,
	})
	return nil
}

type rtPrometheusUpdateSettingsReq struct {
	Enabled     bool `json:"enabled"`
	RotateToken bool `json:"rotate_token" serde:"default"`
}

// rtPrometheusUpdateSettings: POST /api/prometheus/settings — enable/disable
// and/or rotate the token. First enable with no token auto-generates one so
// the admin doesn't have to flip two switches.
func rtPrometheusUpdateSettings(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtPrometheusUpdateSettingsReq
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	existing, err := queryScalarOpt[string](r.Context(), st.DB, "SELECT value FROM settings WHERE key = 'prometheus_token_hash'")
	if err != nil {
		return internalError("read existing prometheus token", err)
	}
	needNew := body.RotateToken || (body.Enabled && (existing == nil || *existing == ""))

	var newToken *string
	if needNew {
		token := rtPrometheusGenerateToken()
		sum := sha256.Sum256([]byte(token))
		if err := rtPrometheusWriteKV(r.Context(), st, "prometheus_token_hash", hex.EncodeToString(sum[:])); err != nil {
			return internalError("save prometheus token hash", err)
		}
		if err := rtPrometheusWriteKV(r.Context(), st, "prometheus_token_prefix", token[:14]); err != nil {
			return internalError("save prometheus token prefix", err)
		}
		newToken = &token
	}
	en := "false"
	if body.Enabled {
		en = "true"
	}
	if err := rtPrometheusWriteKV(r.Context(), st, "prometheus_enabled", en); err != nil {
		return internalError("save prometheus enabled", err)
	}
	msg := "Settings saved."
	if newToken != nil {
		msg = "Save this token — it won't be shown again."
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token": newToken, "message": msg})
	return nil
}

// ── Helpers ─────────────────────────────────────────────────────────────

// rtPrometheusGenerateToken: 256 bits via two UUIDs. "dpms_" = DockPanel
// Metrics Scrape.
func rtPrometheusGenerateToken() string {
	return "dpms_" + strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
}

func rtPrometheusReadSettings(ctx context.Context, st *AppState) (bool, *string, error) {
	rows, err := queryAll[Tup2[string, string]](ctx, st.DB,
		"SELECT key, value FROM settings "+
			"WHERE key IN ('prometheus_enabled', 'prometheus_token_hash')")
	if err != nil {
		return false, nil, err
	}
	enabled := false
	var tokenHash *string
	for _, kv := range rows {
		switch kv.A {
		case "prometheus_enabled":
			enabled = kv.B == "true"
		case "prometheus_token_hash":
			v := kv.B
			tokenHash = &v
		}
	}
	return enabled, tokenHash, nil
}

func rtPrometheusWriteKV(ctx context.Context, st *AppState, key, value string) error {
	_, err := execSQL(ctx, st.DB,
		"INSERT INTO settings (key, value) VALUES ($1, $2) "+
			"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()", key, value)
	return err
}
