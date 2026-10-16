package api

// Port of panel/backend/src/routes/wordpress.rs — WordPress management and
// toolkit endpoints.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtWordpressRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/wordpress/sites", h(rtWordpressAllWpSites))
	r.Handle("POST /api/wordpress/bulk-update", h(rtWordpressBulkUpdate))
	r.Handle("GET /api/wordpress/vuln-scan-settings", h(rtWordpressGetScanSettings))
	r.Handle("PUT /api/wordpress/vuln-scan-settings", h(rtWordpressUpdateScanSettings))
	r.Handle("POST /api/sites/{id}/wordpress/vuln-scan", h(rtWordpressVulnScan))
	r.Handle("GET /api/sites/{id}/wordpress/security-check", h(rtWordpressSecurityCheck))
	r.Handle("GET /api/sites/{id}/wordpress/hardening-history", h(rtWordpressHardeningHistory))
	r.Handle("POST /api/sites/{id}/wordpress/harden", h(rtWordpressWpHarden))
	r.Handle("GET /api/sites/{id}/wordpress", h(rtWordpressInfo))
	r.Handle("POST /api/sites/{id}/wordpress/install", h(rtWordpressInstall))
	r.Handle("GET /api/sites/{id}/wordpress/plugins", h(rtWordpressPlugins))
	r.Handle("GET /api/sites/{id}/wordpress/themes", h(rtWordpressThemes))
	r.Handle("POST /api/sites/{id}/wordpress/update/{target}", h(rtWordpressUpdate))
	r.Handle("POST /api/sites/{id}/wordpress/plugin/{action}", h(rtWordpressPluginAction))
	r.Handle("POST /api/sites/{id}/wordpress/theme/{action}", h(rtWordpressThemeAction))
	r.Handle("POST /api/sites/{id}/wordpress/auto-update", h(rtWordpressSetAutoUpdate))
	r.Handle("POST /api/sites/{id}/wordpress/update-safe", h(rtWordpressUpdateSafe))
}

// ── Vulnerability-scan settings ──
// Companion to image_scans' settings pair — same shape, same "off by default"
// posture, distinct keys because this schedule sweeps WordPress sites.

type rtWordpressWpScanSettings struct {
	Enabled       bool  `json:"enabled"`
	IntervalHours int32 `json:"interval_hours"`
}

type rtWordpressUpdateWpScanSettings struct {
	Enabled       bool  `json:"enabled"`
	IntervalHours int32 `json:"interval_hours"`
}

// rtWordpressReadWpScanSettings returns (enabled, interval_hours).
func rtWordpressReadWpScanSettings(ctx context.Context, db Querier) (bool, int32, error) {
	rows, err := queryAll[Tup2[string, string]](ctx, db,
		"SELECT key, value FROM settings WHERE key IN ('wp_vuln_scan_enabled', 'wp_vuln_scan_interval_hours')")
	if err != nil {
		return false, 0, err
	}
	enabled, hours := false, int32(24)
	for _, kv := range rows {
		switch kv.A {
		case "wp_vuln_scan_enabled":
			enabled = kv.B == "true"
		case "wp_vuln_scan_interval_hours":
			n, err := strconv.ParseInt(kv.B, 10, 32)
			if err != nil {
				n = 24
			}
			hours = int32(n)
		}
	}
	return enabled, hours, nil
}

// rtWordpressGetScanSettings is GET /api/wordpress/vuln-scan-settings.
func rtWordpressGetScanSettings(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	enabled, hours, err := rtWordpressReadWpScanSettings(r.Context(), st.DB)
	if err != nil {
		return internalError("read wp scan settings", err)
	}
	writeJSON(w, http.StatusOK, rtWordpressWpScanSettings{Enabled: enabled, IntervalHours: hours})
	return nil
}

// rtWordpressUpdateScanSettings is PUT /api/wordpress/vuln-scan-settings.
func rtWordpressUpdateScanSettings(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtWordpressUpdateWpScanSettings
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	if body.IntervalHours < 1 || body.IntervalHours > 720 {
		return apiErr(http.StatusBadRequest, "interval_hours must be 1..=720")
	}
	enabled := "false"
	if body.Enabled {
		enabled = "true"
	}
	for _, kv := range [][2]string{
		{"wp_vuln_scan_enabled", enabled},
		{"wp_vuln_scan_interval_hours", strconv.Itoa(int(body.IntervalHours))},
	} {
		if _, err := execSQL(r.Context(), st.DB, "INSERT INTO settings (key, value) VALUES ($1, $2) "+
			"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", kv[0], kv[1]); err != nil {
			return internalError("save wp scan setting", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtWordpressWpVulnStateKey is the state_key a site's WordPress vulnerability
// alert fires and resolves under. Mirrors image_scans' key: alerts.state_key
// is VARCHAR(100) and a domain is not a validated field, so the same
// truncate-then-hash shape applies rather than let a long domain silently fail
// the INSERT and swallow the alert.
func rtWordpressWpVulnStateKey(domain string) string {
	const maxLen = 100
	readable := "wp_vuln:" + domain
	if len(readable) <= maxLen {
		return readable
	}
	sum := sha256.Sum256([]byte(domain))
	digest := hex.EncodeToString(sum[:])
	const prefix = "wp_vuln:"
	budget := maxLen - len(prefix) - 17
	keep := []rune(domain)
	if len(keep) > budget {
		keep = keep[:budget]
	}
	return prefix + string(keep) + "-" + digest[:16]
}

// rtWordpressScanAndStore runs a WordPress vulnerability scan via the agent,
// persists it, and fires or resolves the alert it implies. Shared by the
// manual endpoint and the background sweep (WpVulnScannerRun) — before the
// sweep, a critical CVE in a plugin nobody clicked Scan on stayed invisible.
func rtWordpressScanAndStore(ctx context.Context, db *pgxpool.Pool, siteID, userID uuid.UUID, domain string, agent AgentHandle) (any, error) {
	res, err := agent.Post(ctx, "/wordpress/"+domain+"/vuln-scan", nil)
	if err != nil {
		return nil, agentError("Vulnerability scan", err)
	}
	i32 := func(k string) int32 { n, _ := jsonI64(jsonGet(res, k)); return int32(n) }
	total, critical, high := i32("total_vulns"), i32("critical_count"), i32("high_count")

	data, _ := json.Marshal(res)
	if _, err := execSQL(ctx, db,
		"INSERT INTO wp_vuln_scans (site_id, domain, total_vulns, critical_count, high_count, scan_data) VALUES ($1, $2, $3, $4, $5, $6)",
		siteID, domain, total, critical, high, json.RawMessage(data)); err != nil {
		slog.Warn(fmt.Sprintf("Failed to store scan result: %v", err))
	}

	// Resolve-then-fire, mirroring image_scans: every scan first clears what
	// the LAST scan of this site raised, then raises a new one only if THIS
	// scan is still dirty. To the site's OWNER, not "every admin" — a
	// WordPress site belongs to one user.
	stateKey := rtWordpressWpVulnStateKey(domain)
	NotificationsResolveAlert(ctx, db, userID, nil, &siteID, "wp_vuln_scan", stateKey,
		"WordPress vulnerability alert resolved: "+domain,
		fmt.Sprintf("A later scan of %s found no critical or high severity plugin vulnerability — the earlier alert no longer applies.", domain))
	if critical > 0 || high > 0 {
		severity := "warning"
		if critical > 0 {
			severity = "critical"
		}
		NotificationsFireAlert(ctx, db, userID, nil, &siteID, "wp_vuln_scan", stateKey, severity,
			fmt.Sprintf("WordPress scan: %d critical, %d high on %s", critical, high, domain),
			fmt.Sprintf("A vulnerability scan of %s found %d critical, %d high severity plugin issues. Review in the WordPress toolkit.", domain, critical, high))
	}
	return res, nil
}

// rtWordpressSiteRow is a site the caller may act on (SiteCallerPredicate).
func rtWordpressSiteRow(ctx context.Context, st *AppState, id uuid.UUID, c *Claims, what string) (*Site, error) {
	site, err := queryOpt[Site](ctx, st.DB, "SELECT s.* FROM sites s WHERE "+SiteCallerPredicate, id, c.Sub)
	if err != nil {
		return nil, internalError(what, err)
	}
	if site == nil {
		return nil, apiErr(http.StatusNotFound, "Site not found")
	}
	return site, nil
}

// rtWordpressSiteCall is the AuthUser + Path(id) + site-agent prologue.
func rtWordpressSiteCall(st *AppState, r *http.Request) (*Claims, uuid.UUID, error) {
	c, err := st.authUser(r)
	if err != nil {
		return nil, uuid.Nil, err
	}
	id, err := pathUUID(r, "id")
	return c, id, err
}

// rtWordpressInfo is GET /api/sites/{id}/wordpress — detect WP + info +
// auto-update status.
func rtWordpressInfo(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtWordpressSiteCall(st, r)
	if err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	resp, err := agent.Get(r.Context(), "/wordpress/"+domain+"/info")
	if err != nil {
		slog.Warn(fmt.Sprintf("WordPress info failed for %s: %v", domain, err))
		return apiErr(http.StatusBadGateway, "WordPress service unavailable")
	}
	auto, err := agent.Get(r.Context(), "/wordpress/"+domain+"/auto-update")
	if err != nil {
		auto = map[string]any{"enabled": false}
	}
	enabled := any(false)
	if m, ok := auto.(map[string]any); ok {
		if v, ok := m["enabled"]; ok {
			enabled = v
		}
	}
	// serde_json IndexMut: null becomes an object; any other non-object panics.
	result, ok := resp.(map[string]any)
	if !ok {
		if resp != nil {
			return internalError("wordpress info", "agent answered a non-object")
		}
		result = map[string]any{}
	}
	result["auto_update"] = enabled
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtWordpressInstall is POST /api/sites/{id}/wordpress/install.
func rtWordpressInstall(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtWordpressSiteCall(st, r)
	if err != nil {
		return err
	}
	var body json.RawMessage
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	resp, err := agent.Post(r.Context(), "/wordpress/"+domain+"/install", body)
	if err != nil {
		return agentError("WordPress", err)
	}
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "wordpress.install", new("site"), &domain, nil, nil, c.KeyID)
	writeJSON(w, http.StatusCreated, resp)
	return nil
}

// rtWordpressList serves the plugin/theme listings.
func rtWordpressList(st *AppState, w http.ResponseWriter, r *http.Request, what string) error {
	c, id, err := rtWordpressSiteCall(st, r)
	if err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	resp, err := agent.Get(r.Context(), "/wordpress/"+domain+"/"+what)
	if err != nil {
		slog.Warn(fmt.Sprintf("WordPress %s failed for %s: %v", what, domain, err))
		return apiErr(http.StatusBadGateway, "WordPress service unavailable")
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// rtWordpressPlugins is GET /api/sites/{id}/wordpress/plugins.
func rtWordpressPlugins(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtWordpressList(st, w, r, "plugins")
}

// rtWordpressThemes is GET /api/sites/{id}/wordpress/themes.
func rtWordpressThemes(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtWordpressList(st, w, r, "themes")
}

// rtWordpressUpdate is POST /api/sites/{id}/wordpress/update/{target}.
func rtWordpressUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtWordpressSiteCall(st, r)
	if err != nil {
		return err
	}
	target := r.PathValue("target")
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	if !slices.Contains([]string{"core", "plugins", "themes"}, target) {
		return apiErr(http.StatusBadRequest, "Invalid target")
	}
	resp, err := agent.Post(r.Context(), fmt.Sprintf("/wordpress/%s/update/%s", domain, target), nil)
	if err != nil {
		return agentError("WordPress", err)
	}
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "wordpress.update."+target, new("site"), &domain, nil, nil, c.KeyID)
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// rtWordpressAction serves the plugin/theme actions.
func rtWordpressAction(st *AppState, w http.ResponseWriter, r *http.Request, kind string, allowed []string, invalid string) error {
	c, id, err := rtWordpressSiteCall(st, r)
	if err != nil {
		return err
	}
	action := r.PathValue("action")
	var body json.RawMessage
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if !slices.Contains(allowed, action) {
		return apiErr(http.StatusBadRequest, invalid)
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	resp, err := agent.Post(r.Context(), fmt.Sprintf("/wordpress/%s/%s/%s", domain, kind, action), body)
	if err != nil {
		return agentError("WordPress", err)
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// rtWordpressPluginAction is POST /api/sites/{id}/wordpress/plugin/{action}.
func rtWordpressPluginAction(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtWordpressAction(st, w, r, "plugin", []string{"activate", "deactivate", "delete", "update"}, "Invalid plugin action")
}

// rtWordpressThemeAction is POST /api/sites/{id}/wordpress/theme/{action}.
func rtWordpressThemeAction(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtWordpressAction(st, w, r, "theme", []string{"activate", "delete", "update"}, "Invalid theme action")
}

// rtWordpressSetAutoUpdate is POST /api/sites/{id}/wordpress/auto-update.
func rtWordpressSetAutoUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtWordpressSiteCall(st, r)
	if err != nil {
		return err
	}
	var body json.RawMessage
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	resp, err := agent.Post(r.Context(), "/wordpress/"+domain+"/auto-update", body)
	if err != nil {
		return agentError("WordPress", err)
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// ── WordPress Toolkit endpoints ──

// rtWordpressAllWpSites is GET /api/wordpress/sites. No admin check — the
// query filters by user_id so owners only see their own sites.
func rtWordpressAllWpSites(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	sites, err := queryAll[Tup2[uuid.UUID, string]](r.Context(), st.DB,
		"SELECT id, domain FROM sites WHERE user_id = $1 AND server_id = $2 ORDER BY domain", c.Sub, serverID)
	if err != nil {
		return internalError("all wp sites", err)
	}
	wpSites := []any{}
	for _, s := range sites {
		siteID, domain := s.A, s.B
		// Quick detect, bounded at 5s.
		dctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		info, err := agent.Get(dctx, "/wordpress/"+domain+"/info")
		cancel()
		if err != nil {
			continue
		}
		version, ok := jsonStr(jsonGet(info, "version"))
		if !ok {
			version = "unknown"
		}
		updateAvailable, _ := jsonBool(jsonGet(info, "update_available"))
		scan, _ := queryOpt[Tup2[int32, int32]](r.Context(), st.DB,
			"SELECT total_vulns, critical_count FROM wp_vuln_scans WHERE site_id = $1 ORDER BY scanned_at DESC LIMIT 1", siteID)
		vulns, crit := int32(0), int32(0)
		if scan != nil {
			vulns, crit = scan.A, scan.B
		}
		wpSites = append(wpSites, map[string]any{
			"site_id": siteID, "domain": domain, "wp_version": version,
			"update_available": updateAvailable, "vulns": vulns, "critical_vulns": crit,
		})
	}
	writeJSON(w, http.StatusOK, wpSites)
	return nil
}

type rtWordpressBulkUpdateRequest struct {
	SiteIDs []uuid.UUID `json:"site_ids"`
	Target  string      `json:"target"`
}

// rtWordpressBulkUpdate is POST /api/wordpress/bulk-update.
func rtWordpressBulkUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body rtWordpressBulkUpdateRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	if !slices.Contains([]string{"plugins", "themes", "core", "all"}, body.Target) {
		return apiErr(http.StatusBadRequest, "Target must be plugins, themes, core, or all")
	}
	if len(body.SiteIDs) > 50 {
		return apiErr(http.StatusBadRequest, "Maximum 50 sites per bulk update")
	}
	results := []any{}
	for _, siteID := range body.SiteIDs {
		d, _ := queryScalarOpt[string](r.Context(), st.DB,
			"SELECT s.domain FROM sites s WHERE "+SiteCallerPredicate+" AND s.server_id = $3", siteID, c.Sub, serverID)
		if d == nil {
			results = append(results, map[string]any{"site_id": siteID, "ok": false, "message": "Site not found"})
			continue
		}
		domain := *d
		res, err := agent.Post(r.Context(), fmt.Sprintf("/wordpress/%s/update/%s", domain, body.Target), nil)
		if err != nil {
			results = append(results, map[string]any{"site_id": siteID, "domain": domain, "ok": false, "message": err.Error()})
			continue
		}
		updated, _ := jsonI64(jsonGet(res, "updated"))
		results = append(results, map[string]any{"site_id": siteID, "domain": domain, "ok": true, "updated": updated})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
	return nil
}

// rtWordpressVulnScan is POST /api/sites/{id}/wordpress/vuln-scan.
func rtWordpressVulnScan(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtWordpressSiteCall(st, r)
	if err != nil {
		return err
	}
	site, err := rtWordpressSiteRow(r.Context(), st, id, c, "vuln scan")
	if err != nil {
		return err
	}
	agent, err := agentForSiteServer(r.Context(), st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}
	res, err := rtWordpressScanAndStore(r.Context(), st.DB, id, site.UserID, site.Domain, agent)
	if err != nil {
		return err
	}
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "wordpress.vuln_scan", new("site"), &site.Domain, nil, nil, c.KeyID)
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtWordpressSecurityCheck is GET /api/sites/{id}/wordpress/security-check.
func rtWordpressSecurityCheck(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtWordpressSiteCall(st, r)
	if err != nil {
		return err
	}
	site, err := rtWordpressSiteRow(r.Context(), st, id, c, "security check")
	if err != nil {
		return err
	}
	agent, err := agentForSiteServer(r.Context(), st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), "/wordpress/"+site.Domain+"/security-check")
	if err != nil {
		return agentError("Security check", err)
	}

	// Persist one row per check, like the sibling wp_vuln_scans table — this
	// one never got its own writer, so every hardening check was a pure live
	// round-trip with no history. UPSERT on (site_id, check_name) so a re-check
	// updates the row rather than accumulating one per run.
	if checks, ok := jsonArr(res); ok {
		for _, check := range checks {
			name, ok1 := jsonStr(jsonGet(check, "name"))
			status, ok2 := jsonStr(jsonGet(check, "status"))
			if !ok1 || !ok2 {
				continue
			}
			details, _ := jsonStr(jsonGet(check, "description"))
			if _, err := execSQL(r.Context(), st.DB,
				"INSERT INTO wp_hardening (site_id, check_name, status, details, checked_at) "+
					"VALUES ($1, $2, $3, $4, NOW()) "+
					"ON CONFLICT (site_id, check_name) DO UPDATE SET "+
					"status = EXCLUDED.status, details = EXCLUDED.details, checked_at = EXCLUDED.checked_at",
				id, name, status, details); err != nil {
				slog.Warn(fmt.Sprintf("Failed to persist wp_hardening row for %s: %v", name, err))
			}
		}
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtWordpressHardeningHistoryRow is the last persisted result per check.
//
// security_check has written wp_hardening on every run since the migration
// that created it — but nothing ever read it back, so "come back next week and
// there is no record" stayed true. This is the read half.
type rtWordpressHardeningHistoryRow struct {
	CheckName string    `json:"check_name" db:"check_name"`
	Status    string    `json:"status" db:"status"`
	Details   *string   `json:"details" db:"details"`
	CheckedAt time.Time `json:"checked_at" db:"checked_at"`
}

// rtWordpressHardeningHistory is GET /api/sites/{id}/wordpress/hardening-history.
func rtWordpressHardeningHistory(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtWordpressSiteCall(st, r)
	if err != nil {
		return err
	}
	site, err := rtWordpressSiteRow(r.Context(), st, id, c, "hardening history")
	if err != nil {
		return err
	}
	rows, err := queryAll[rtWordpressHardeningHistoryRow](r.Context(), st.DB,
		"SELECT check_name, status, details, checked_at FROM wp_hardening "+
			"WHERE site_id = $1 ORDER BY check_name", site.ID)
	if err != nil {
		return internalError("hardening history", err)
	}
	writeJSON(w, http.StatusOK, rows)
	return nil
}

// rtWordpressWpHarden is POST /api/sites/{id}/wordpress/harden.
func rtWordpressWpHarden(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtWordpressSiteCall(st, r)
	if err != nil {
		return err
	}
	var body json.RawMessage
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	site, err := rtWordpressSiteRow(r.Context(), st, id, c, "wp harden")
	if err != nil {
		return err
	}
	agent, err := agentForSiteServer(r.Context(), st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), "/wordpress/"+site.Domain+"/harden", body)
	if err != nil {
		return agentError("Security hardening", err)
	}
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "wordpress.harden", new("site"), &site.Domain, nil, nil, c.KeyID)
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtWordpressUpdateSafe is POST /api/sites/{id}/wordpress/update-safe —
// update with snapshot + auto-rollback.
func rtWordpressUpdateSafe(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtWordpressSiteCall(st, r)
	if err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	res, err := agent.PostLong(r.Context(), "/wordpress/"+domain+"/update-with-rollback", nil, 300)
	if err != nil {
		return agentError("WP safe update", err)
	}
	action := "wordpress.update.safe"
	if rb, _ := jsonBool(jsonGet(res, "rolled_back")); rb {
		action = "wordpress.update.rollback"
	}
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, action, new("site"), &domain, nil, nil, c.KeyID)
	writeJSON(w, http.StatusOK, res)
	return nil
}
