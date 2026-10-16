package api

// Port of panel/backend/src/routes/cdn.rs.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const rtCdnBunnyAPI = "https://api.bunny.net"

// rtCdnCdnZone is the cdn_zones row. api_key is never serialized.
type rtCdnCdnZone struct {
	ID          uuid.UUID `db:"id" json:"id"`
	UserID      uuid.UUID `db:"user_id" json:"user_id"`
	Domain      string    `db:"domain" json:"domain"`
	Provider    string    `db:"provider" json:"provider"`
	PullZoneID  *string   `db:"pull_zone_id" json:"pull_zone_id"`
	APIKey      string    `db:"api_key" json:"-"`
	OriginURL   *string   `db:"origin_url" json:"origin_url"`
	CdnHostname *string   `db:"cdn_hostname" json:"cdn_hostname"`
	Enabled     bool      `db:"enabled" json:"enabled"`
	CacheTTL    int32     `db:"cache_ttl" json:"cache_ttl"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

// rtCdnCdnZoneView is the public-safe view (no api_key, no user_id).
type rtCdnCdnZoneView struct {
	ID          uuid.UUID `json:"id"`
	Domain      string    `json:"domain"`
	Provider    string    `json:"provider"`
	PullZoneID  *string   `json:"pull_zone_id"`
	OriginURL   *string   `json:"origin_url"`
	CdnHostname *string   `json:"cdn_hostname"`
	Enabled     bool      `json:"enabled"`
	CacheTTL    int32     `json:"cache_ttl"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func rtCdnView(z rtCdnCdnZone) rtCdnCdnZoneView {
	return rtCdnCdnZoneView{z.ID, z.Domain, z.Provider, z.PullZoneID, z.OriginURL, z.CdnHostname, z.Enabled, z.CacheTTL, z.CreatedAt, z.UpdatedAt}
}

type rtCdnCreateCdnZoneRequest struct {
	Domain      string  `json:"domain"`
	Provider    *string `json:"provider"`
	APIKey      string  `json:"api_key"`
	PullZoneID  *string `json:"pull_zone_id"`
	OriginURL   *string `json:"origin_url"`
	CdnHostname *string `json:"cdn_hostname"`
}

type rtCdnUpdateCdnZoneRequest struct {
	Enabled     *bool   `json:"enabled"`
	CacheTTL    *int32  `json:"cache_ttl"`
	OriginURL   *string `json:"origin_url"`
	CdnHostname *string `json:"cdn_hostname"`
}

type rtCdnPurgeCacheRequest struct {
	URLs *[]string `json:"urls"`
}

func rtCdnRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/cdn/zones", h(rtCdnListZones))
	r.Handle("POST /api/cdn/zones", h(rtCdnCreateZone))
	r.Handle("PUT /api/cdn/zones/{id}", h(rtCdnUpdateZone))
	r.Handle("DELETE /api/cdn/zones/{id}", h(rtCdnDeleteZone))
	r.Handle("POST /api/cdn/zones/{id}/purge", h(rtCdnPurgeCache))
	r.Handle("GET /api/cdn/zones/{id}/stats", h(rtCdnZoneStats))
	r.Handle("POST /api/cdn/zones/{id}/test", h(rtCdnTestCredentials))
	r.Handle("GET /api/cdn/zones/{id}/pull-zones", h(rtCdnListPullZones))
}

// rtCdnGetZone gets a CDN zone. De-scoped for admin oversight (s239 DNS
// treatment): any admin manages any zone. Every caller is admin-gated via
// requireAdmin at the handler entry.
func rtCdnGetZone(st *AppState, r *http.Request, zoneID uuid.UUID) (rtCdnCdnZone, error) {
	z, err := queryOpt[rtCdnCdnZone](r.Context(), st.DB, "SELECT * FROM cdn_zones WHERE id = $1", zoneID)
	if err != nil {
		return rtCdnCdnZone{}, internalError("cdn zone", err)
	}
	if z == nil {
		return rtCdnCdnZone{}, apiErr(http.StatusNotFound, "CDN zone not found")
	}
	return *z, nil
}

// rtCdnBunnyHeaders: the stored BunnyCDN key is encrypted at rest (see
// create). Decrypt here — the single choke point every Bunny caller funnels
// through — so no read site can forget to, exactly as cfHeaders does for the
// Cloudflare half. The legacy fallback returns any pre-encryption plaintext
// value (and a freshly-entered key during validation) unchanged.
func rtCdnBunnyHeaders(apiKey string) http.Header {
	apiKey = SecretsCryptoDecryptCredentialFromEnv(apiKey)
	h := http.Header{}
	if headerValueOK(apiKey) {
		h.Set("AccessKey", apiKey)
	}
	h.Set("Content-Type", "application/json")
	return h
}

// rtCdnSend is a reqwest::Client::new() request with a whole-request timeout.
// It returns the response with its body fully read.
func rtCdnSend(ctx context.Context, method, u string, h http.Header, body any, timeout time.Duration) (*http.Response, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range h {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, b, err
}

// rtCdnStatusDisplay is reqwest StatusCode's Display ("401 Unauthorized").
func rtCdnStatusDisplay(code int) string {
	t := http.StatusText(code)
	if t == "" {
		t = "<unknown status code>"
	}
	return fmt.Sprintf("%d %s", code, t)
}

// rtCdnPointerOr is `v.pointer(path).unwrap_or(def)`: a present null stays
// null, only an absent key falls back.
func rtCdnPointerOr(v any, def any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return def
		}
		if v, ok = m[k]; !ok {
			return def
		}
	}
	return v
}

func rtCdnIsSuccess(code int) bool { return code >= 200 && code < 300 }

// GET /api/cdn/zones — List CDN zones for the current user.
func rtCdnListZones(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	zones, err := queryAll[rtCdnCdnZone](r.Context(), st.DB, "SELECT * FROM cdn_zones ORDER BY created_at DESC LIMIT 100")
	if err != nil {
		return internalError("list cdn zones", err)
	}
	out := make([]rtCdnCdnZoneView, 0, len(zones))
	for _, z := range zones {
		out = append(out, rtCdnView(z))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// POST /api/cdn/zones — Add a CDN zone.
func rtCdnCreateZone(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtCdnCreateCdnZoneRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	if strings.TrimSpace(body.Domain) == "" {
		return apiErr(http.StatusBadRequest, "Domain is required")
	}
	if strings.TrimSpace(body.APIKey) == "" {
		return apiErr(http.StatusBadRequest, "API key is required")
	}
	provider := "bunnycdn"
	if body.Provider != nil {
		provider = *body.Provider
	}
	if provider != "bunnycdn" && provider != "cloudflare" {
		return apiErr(http.StatusBadRequest, "Provider must be 'bunnycdn' or 'cloudflare'")
	}

	// Validate API key by testing connectivity
	if provider == "bunnycdn" {
		resp, _, err := rtCdnSend(r.Context(), "GET", rtCdnBunnyAPI+"/pullzone", rtCdnBunnyHeaders(body.APIKey), nil, 10*time.Second)
		if err != nil && resp == nil {
			slog.Warn("BunnyCDN API test failed: " + err.Error())
			return apiErr(http.StatusBadRequest, "Failed to connect to BunnyCDN API. Check your API key.")
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return apiErr(http.StatusBadRequest, "Invalid BunnyCDN API key")
		}
	}

	// Encrypt before it reaches the row. SECURITY.md and README.md both
	// promise every stored credential is AES-256-GCM at rest; this column was
	// one of three that were not. Reads go through rtCdnBunnyHeaders /
	// cfHeaders, which both decrypt and tolerate a legacy plaintext value — so
	// existing rows keep working and there is no migration.
	apiKeyEnc, err := SecretsCryptoEncryptCredential(strings.TrimSpace(body.APIKey), st.Config.JWTSecret)
	if err != nil {
		return internalError("encrypt cdn api key", err)
	}

	zone, err := queryOne[rtCdnCdnZone](r.Context(), st.DB,
		"INSERT INTO cdn_zones (user_id, domain, provider, api_key, pull_zone_id, origin_url, cdn_hostname) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
		c.Sub, strings.TrimSpace(body.Domain), provider, apiKeyEnc, body.PullZoneID, body.OriginURL, body.CdnHostname)
	if err != nil {
		return internalError("create cdn zone", err)
	}

	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "cdn.create", new("cdn"), &zone.Domain, &provider, nil, c.KeyID)

	writeJSON(w, http.StatusCreated, rtCdnView(zone))
	return nil
}

// PUT /api/cdn/zones/{id} — Update CDN zone settings.
func rtCdnUpdateZone(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtCdnUpdateCdnZoneRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	zone, err := rtCdnGetZone(st, r, id)
	if err != nil {
		return err
	}

	enabled := zone.Enabled
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	cacheTTL := zone.CacheTTL
	if body.CacheTTL != nil {
		cacheTTL = *body.CacheTTL
	}
	cacheTTL = min(max(cacheTTL, 0), 31536000)
	originURL := zone.OriginURL
	if body.OriginURL != nil {
		originURL = body.OriginURL
	}
	cdnHostname := zone.CdnHostname
	if body.CdnHostname != nil {
		cdnHostname = body.CdnHostname
	}

	updated, err := queryOne[rtCdnCdnZone](r.Context(), st.DB,
		"UPDATE cdn_zones SET enabled = $1, cache_ttl = $2, origin_url = $3, cdn_hostname = $4, updated_at = NOW() "+
			"WHERE id = $5 RETURNING *",
		enabled, cacheTTL, originURL, cdnHostname, id)
	if err != nil {
		return internalError("update cdn zone", err)
	}

	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "cdn.update", new("cdn"), &zone.Domain, nil, nil, c.KeyID)

	writeJSON(w, http.StatusOK, rtCdnView(updated))
	return nil
}

// DELETE /api/cdn/zones/{id} — Remove CDN zone.
func rtCdnDeleteZone(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	zone, err := rtCdnGetZone(st, r, id)
	if err != nil {
		return err
	}

	if _, err := execSQL(r.Context(), st.DB, "DELETE FROM cdn_zones WHERE id = $1", id); err != nil {
		return internalError("delete cdn zone", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "cdn.delete", new("cdn"), &zone.Domain, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(r.Context(), st.DB, "cdn.delete", &c.Email, ip, new("cdn"), &zone.Domain, nil, nil, "warning", c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtCdnURLHost is url::Url::parse(u).host_str(): ok=false when u is not an
// absolute URL.
func rtCdnURLHost(u string) (string, bool) {
	p, err := url.Parse(u)
	if err != nil || p.Scheme == "" {
		return "", false
	}
	h := p.Hostname()
	if p.Scheme == "http" || p.Scheme == "https" {
		h = strings.ToLower(h)
	}
	return h, true
}

// POST /api/cdn/zones/{id}/purge — Purge CDN cache.
func rtCdnPurgeCache(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtCdnPurgeCacheRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	zone, err := rtCdnGetZone(st, r, id)
	if err != nil {
		return err
	}

	// Validate purge URLs belong to this zone's domain (prevent SSRF)
	if body.URLs != nil {
		if len(*body.URLs) > 100 {
			return apiErr(http.StatusBadRequest, "Maximum 100 URLs per purge request")
		}
		for _, u := range *body.URLs {
			host, ok := rtCdnURLHost(u)
			if !ok {
				return apiErr(http.StatusBadRequest, "Invalid purge URL")
			}
			if !strings.HasSuffix(host, zone.Domain) && host != zone.Domain {
				return apiErr(http.StatusBadRequest, "Purge URL does not match zone domain")
			}
		}
	}

	// Validate pull_zone_id format (alphanumeric/hex only)
	if zone.PullZoneID != nil {
		for _, ch := range *zone.PullZoneID {
			if !isASCIIAlnum(ch) {
				return apiErr(http.StatusBadRequest, "Invalid pull zone ID format")
			}
		}
	}

	switch zone.Provider {
	case "bunnycdn":
		if zone.PullZoneID == nil {
			return apiErr(http.StatusBadRequest, "Pull zone ID not configured")
		}
		resp, text, err := rtCdnSend(r.Context(), "POST", fmt.Sprintf("%s/pullzone/%s/purgeCache", rtCdnBunnyAPI, *zone.PullZoneID), rtCdnBunnyHeaders(zone.APIKey), nil, 15*time.Second)
		if err != nil && resp == nil {
			slog.Warn("BunnyCDN purge failed: " + err.Error())
			return apiErr(http.StatusBadGateway, "Failed to purge BunnyCDN cache")
		}
		if !rtCdnIsSuccess(resp.StatusCode) {
			slog.Warn(fmt.Sprintf("BunnyCDN purge HTTP %d: %s", resp.StatusCode, text))
			return apiErr(http.StatusBadGateway, fmt.Sprintf("BunnyCDN returned HTTP %d", resp.StatusCode))
		}
	case "cloudflare":
		if zone.PullZoneID == nil {
			return apiErr(http.StatusBadRequest, "Cloudflare zone ID not configured")
		}
		var purge any = map[string]any{"purge_everything": true}
		if body.URLs != nil {
			purge = map[string]any{"files": *body.URLs}
		}
		resp, _, err := rtCdnSend(r.Context(), "POST", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/purge_cache", *zone.PullZoneID), cfHeaders(zone.APIKey, nil), purge, 15*time.Second)
		if err != nil && resp == nil {
			slog.Warn("Cloudflare purge failed: " + err.Error())
			return apiErr(http.StatusBadGateway, "Failed to purge Cloudflare cache")
		}
		if !rtCdnIsSuccess(resp.StatusCode) {
			return apiErr(http.StatusBadGateway, fmt.Sprintf("Cloudflare returned HTTP %d", resp.StatusCode))
		}
	default:
		return apiErr(http.StatusBadRequest, "Unknown CDN provider")
	}

	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "cdn.purge", new("cdn"), &zone.Domain, &zone.Provider, nil, c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Cache purged successfully"})
	return nil
}

// GET /api/cdn/zones/{id}/stats — Get CDN bandwidth/request stats.
func rtCdnZoneStats(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	zone, err := rtCdnGetZone(st, r, id)
	if err != nil {
		return err
	}

	switch zone.Provider {
	case "bunnycdn":
		if zone.PullZoneID == nil {
			return apiErr(http.StatusBadRequest, "Pull zone ID not configured")
		}
		// Get statistics for the last 30 days
		now := time.Now().UTC()
		dateFrom := now.Add(-30 * 24 * time.Hour).Format("2006-01-02T00:00:00Z")
		dateTo := now.Format("2006-01-02T23:59:59Z")
		resp, raw, err := rtCdnSend(r.Context(), "GET", fmt.Sprintf("%s/statistics?dateFrom=%s&dateTo=%s&pullZone=%s", rtCdnBunnyAPI, dateFrom, dateTo, *zone.PullZoneID), rtCdnBunnyHeaders(zone.APIKey), nil, 15*time.Second)
		if err != nil && resp == nil {
			slog.Warn("BunnyCDN stats failed: " + err.Error())
			return apiErr(http.StatusBadGateway, "Failed to fetch BunnyCDN stats")
		}
		if !rtCdnIsSuccess(resp.StatusCode) {
			return apiErr(http.StatusBadGateway, fmt.Sprintf("BunnyCDN returned HTTP %d", resp.StatusCode))
		}
		b, perr := agentDecodeJSON(raw)
		if err == nil {
			err = perr
		}
		if err != nil {
			slog.Warn("BunnyCDN stats parse error: " + err.Error())
			return apiErr(http.StatusBadGateway, "Invalid response from BunnyCDN")
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"provider":           "bunnycdn",
			"period":             "30d",
			"total_bandwidth":    rtCdnPointerOr(b, 0, "TotalBandwidthUsed"),
			"total_requests":     rtCdnPointerOr(b, 0, "TotalRequestsServed"),
			"cache_hit_rate":     rtCdnPointerOr(b, json.Number("0.0"), "CacheHitRate"),
			"bandwidth_cached":   jsonGet(b, "BandwidthCachedChart"),
			"bandwidth_uncached": jsonGet(b, "BandwidthUncachedChart"),
			"requests_served":    jsonGet(b, "RequestsServedChart"),
		})
		return nil
	case "cloudflare":
		if zone.PullZoneID == nil {
			return apiErr(http.StatusBadRequest, "Cloudflare zone ID not configured")
		}
		// Get analytics for the last 30 days
		resp, raw, err := rtCdnSend(r.Context(), "GET", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/analytics/dashboard?since=-43200&continuous=true", *zone.PullZoneID), cfHeaders(zone.APIKey, nil), nil, 15*time.Second)
		if err != nil && resp == nil {
			slog.Warn("Cloudflare stats failed: " + err.Error())
			return apiErr(http.StatusBadGateway, "Failed to fetch Cloudflare stats")
		}
		var b any
		if err == nil {
			b, err = agentDecodeJSON(raw)
		}
		if err != nil {
			slog.Warn("Cloudflare stats parse error: " + err.Error())
			return apiErr(http.StatusBadGateway, "Invalid response from Cloudflare")
		}
		totals := rtCdnPointerOr(b, map[string]any{}, "result", "totals")
		writeJSON(w, http.StatusOK, map[string]any{
			"provider":         "cloudflare",
			"period":           "30d",
			"total_bandwidth":  rtCdnPointerOr(totals, 0, "bandwidth", "all"),
			"total_requests":   rtCdnPointerOr(totals, 0, "requests", "all"),
			"cached_bandwidth": rtCdnPointerOr(totals, 0, "bandwidth", "cached"),
			"threats":          rtCdnPointerOr(totals, 0, "threats", "all"),
			"page_views":       rtCdnPointerOr(totals, 0, "pageviews", "all"),
		})
		return nil
	default:
		return apiErr(http.StatusBadRequest, "Unknown CDN provider")
	}
}

// POST /api/cdn/zones/{id}/test — Test CDN API credentials.
func rtCdnTestCredentials(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	zone, err := rtCdnGetZone(st, r, id)
	if err != nil {
		return err
	}

	switch zone.Provider {
	case "bunnycdn":
		resp, _, err := rtCdnSend(r.Context(), "GET", rtCdnBunnyAPI+"/pullzone", rtCdnBunnyHeaders(zone.APIKey), nil, 10*time.Second)
		if err != nil && resp == nil {
			slog.Warn("CDN credentials test failed: " + err.Error())
			return apiErr(http.StatusBadGateway, "CDN API connection failed")
		}
		if rtCdnIsSuccess(resp.StatusCode) {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "BunnyCDN API key is valid"})
		} else {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "BunnyCDN returned HTTP " + rtCdnStatusDisplay(resp.StatusCode)})
		}
		return nil
	case "cloudflare":
		resp, raw, err := rtCdnSend(r.Context(), "GET", "https://api.cloudflare.com/client/v4/user/tokens/verify", cfHeaders(zone.APIKey, nil), nil, 10*time.Second)
		if err != nil && resp == nil {
			slog.Warn("CDN credentials test failed: " + err.Error())
			return apiErr(http.StatusBadGateway, "CDN API connection failed")
		}
		b, _ := agentDecodeJSON(raw)
		success, _ := jsonBool(jsonGet(b, "success"))
		msg := "Cloudflare API token is invalid"
		if success {
			msg = "Cloudflare API token is valid"
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": success, "message": msg})
		return nil
	default:
		return apiErr(http.StatusBadRequest, "Unknown CDN provider")
	}
}

// GET /api/cdn/zones/{id}/pull-zones — List available pull zones from the provider.
func rtCdnListPullZones(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	zone, err := rtCdnGetZone(st, r, id)
	if err != nil {
		return err
	}

	switch zone.Provider {
	case "bunnycdn":
		resp, raw, err := rtCdnSend(r.Context(), "GET", rtCdnBunnyAPI+"/pullzone", rtCdnBunnyHeaders(zone.APIKey), nil, 10*time.Second)
		if err != nil && resp == nil {
			return apiErr(http.StatusBadGateway, "Failed to list pull zones: "+err.Error())
		}
		if !rtCdnIsSuccess(resp.StatusCode) {
			return apiErr(http.StatusBadGateway, "Failed to list BunnyCDN pull zones")
		}
		b, perr := agentDecodeJSON(raw)
		if err != nil || perr != nil {
			b = []any{}
		}
		// Extract just the useful fields
		zones := []any{}
		if arr, ok := jsonArr(b); ok {
			for _, z := range arr {
				zones = append(zones, map[string]any{
					"id":             jsonGet(z, "Id"),
					"name":           jsonGet(z, "Name"),
					"origin_url":     jsonGet(z, "OriginUrl"),
					"hostnames":      jsonGet(z, "Hostnames"),
					"bandwidth_used": jsonGet(z, "MonthlyBandwidthUsed"),
					"enabled":        jsonGet(z, "Enabled"),
				})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"pull_zones": zones})
		return nil
	case "cloudflare":
		// For Cloudflare, list zones
		resp, raw, err := rtCdnSend(r.Context(), "GET", "https://api.cloudflare.com/client/v4/zones?per_page=50", cfHeaders(zone.APIKey, nil), nil, 10*time.Second)
		if err != nil && resp == nil {
			return apiErr(http.StatusBadGateway, "Failed to list zones: "+err.Error())
		}
		b, _ := agentDecodeJSON(raw)
		zones := []any{}
		if arr, ok := jsonArr(jsonGet(b, "result")); ok {
			for _, z := range arr {
				zones = append(zones, map[string]any{
					"id":     jsonGet(z, "id"),
					"name":   jsonGet(z, "name"),
					"status": jsonGet(z, "status"),
					"plan":   jsonGet(z, "plan", "name"),
				})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"pull_zones": zones})
		return nil
	default:
		return apiErr(http.StatusBadRequest, "Unknown CDN provider")
	}
}
