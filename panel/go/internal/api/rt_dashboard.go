package api

// Port of panel/backend/src/routes/dashboard.rs.

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"
)

func rtDashboardRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/dashboard/intelligence", h(rtDashboardIntelligence))
	r.Handle("GET /api/dashboard/metrics-history", h(rtDashboardMetricsHistory))
	r.Handle("GET /api/dashboard/gpu-metrics-history", h(rtDashboardGpuMetricsHistory))
	r.Handle("GET /api/dashboard/docker", h(rtDashboardDockerSummary))
	r.Handle("GET /api/dashboard/timeline", h(rtDashboardTimeline))
	r.Handle("GET /api/dashboard/fleet", h(rtDashboardFleetOverview))
}

func rtDashboardSSLSeverity(daysLeft int64) string {
	switch {
	case daysLeft <= 3:
		return "critical"
	case daysLeft <= 7:
		return "warning"
	case daysLeft <= 30:
		return "info"
	}
	return "ok"
}

func rtDashboardPlural(n int64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func rtDashboardSevOrd(s string) int {
	switch s {
	case "critical":
		return 0
	case "warning":
		return 1
	}
	return 2
}

func rtDashboardRound1(v float64) float64 { return math.Round(v*10) / 10 }

// rtDashboardIntelligence: GET /api/dashboard/intelligence — health score, top
// issues, SSL countdowns.
func rtDashboardIntelligence(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	ctx := r.Context()

	// 1. Firing alerts (scoped to the user).
	firingCount, err := queryScalar[int64](ctx, st.DB,
		"SELECT COUNT(*) FROM alerts WHERE status = 'firing' "+
			"AND (server_id = $1 OR server_id IS NULL) AND user_id = $2", serverID, c.Sub)
	if err != nil {
		return internalError("intelligence", err)
	}
	// 2. Acknowledged alerts.
	ackCount, err := queryScalar[int64](ctx, st.DB,
		"SELECT COUNT(*) FROM alerts WHERE status = 'acknowledged' "+
			"AND (server_id = $1 OR server_id IS NULL) AND user_id = $2", serverID, c.Sub)
	if err != nil {
		return internalError("intelligence", err)
	}

	// 3. SSL expiry — the user's sites AND their compose stacks. Both feed the
	//    SAME ssl_countdowns list, so stacks count in the health score and the
	//    recommendations below with no further change.
	sslSites, err := queryAll[Tup2[string, *time.Time]](ctx, st.DB,
		"SELECT domain, ssl_expiry FROM sites WHERE ssl_enabled = TRUE AND ssl_expiry IS NOT NULL AND server_id = $1 AND user_id = $2 ORDER BY ssl_expiry ASC LIMIT 5",
		serverID, c.Sub)
	if err != nil {
		return internalError("intelligence", err)
	}
	// tls_mode/ssl_email come along only to apply the SAME "an ACME stack is
	// ours" rule the certificate dashboard and the expiry check enforce — a
	// `provided` stack's expiry isn't the panel's certificate to warn about.
	sslStacks, err := queryAll[Tup5[uuid.UUID, string, *time.Time, *string, *string]](ctx, st.DB,
		"SELECT id, domain, ssl_expiry, tls_mode, ssl_email FROM docker_stacks "+
			"WHERE ssl_expiry IS NOT NULL AND domain IS NOT NULL AND server_id = $1 AND user_id = $2 "+
			"ORDER BY ssl_expiry ASC LIMIT 5", serverID, c.Sub)
	if err != nil {
		return internalError("intelligence", err)
	}

	now := time.Now()
	type countdown struct {
		expiry   time.Time
		domain   string
		daysLeft int64
		severity string
		v        map[string]any
	}
	mk := func(domain string, expiry *time.Time, stackID any) countdown {
		var days int64
		at := now
		if expiry != nil {
			days = int64(expiry.Sub(now) / (24 * time.Hour))
			at = *expiry
		}
		sev := rtDashboardSSLSeverity(days)
		return countdown{at, domain, days, sev, map[string]any{
			"domain":    domain,
			"days_left": days,
			"severity":  sev,
			"expiry":    expiry,
			// Always on the wire, even as null — a field present on some rows
			// and absent on others reaches TypeScript as `undefined`, and
			// `undefined !== null` is true.
			"stack_id": stackID,
		}}
	}
	var countdowns []countdown
	for _, s := range sslSites {
		countdowns = append(countdowns, mk(s.A, s.B, nil))
	}
	for _, s := range sslStacks {
		if rtStacksEffectiveTlsMode(s.D, s.E) == "acme" {
			countdowns = append(countdowns, mk(s.B, s.C, s.A))
		}
	}
	// Soonest first regardless of source table, then the top 5.
	sort.SliceStable(countdowns, func(i, j int) bool { return countdowns[i].expiry.Before(countdowns[j].expiry) })
	if len(countdowns) > 5 {
		countdowns = countdowns[:5]
	}
	sslCountdowns := make([]map[string]any, 0, len(countdowns))
	for _, cd := range countdowns {
		sslCountdowns = append(sslCountdowns, cd.v)
	}

	// 4. Top issues.
	topIssues, err := queryAll[Tup4[string, string, string, time.Time]](ctx, st.DB,
		"SELECT title, severity, alert_type, created_at FROM alerts "+
			"WHERE status IN ('firing', 'acknowledged') "+
			"AND (server_id = $1 OR server_id IS NULL) AND user_id = $2 "+
			"ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, created_at DESC LIMIT 5",
		serverID, c.Sub)
	if err != nil {
		return internalError("intelligence", err)
	}
	issues := make([]map[string]any, 0, len(topIssues))
	for _, t := range topIssues {
		issues = append(issues, map[string]any{"title": t.A, "severity": t.B, "type": t.C, "since": t.D})
	}

	// Every read below is HOST-level, not tenant-level: the agent's own
	// diagnostics, backup freshness, the last security scan. Sections 1-4 are
	// `user_id = $2` for everyone. These three each reached a non-admin once
	// (`/diagnostics` is AdminUser on its own route; stale_backups counted every
	// tenant's sites; security_scans has no user column) — so the scope is
	// decided ONCE here.
	hostScoped := c.Role == "admin"
	// A non-admin's id, or NULL for an admin — the `$2 IS NULL OR` arm keeps
	// this ONE query instead of two divergent ones.
	var tenant *uuid.UUID
	if !hostScoped {
		tenant = &c.Sub
	}

	// 5. Diagnostics (admin only — must not be the way around AdminUser).
	var diagnostics any
	if hostScoped {
		if d, err := agent.Get(ctx, "/diagnostics"); err == nil {
			diagnostics = d
		}
	}

	// 6. Sites with no backup in 7 days. A row whose upload to its destination
	//    failed does NOT count: it is on local disk only, the one place a disk
	//    failure takes with it — the case this tile warns about.
	staleBackups, err := queryScalar[int64](ctx, st.DB,
		"SELECT COUNT(*) FROM sites s WHERE s.status = 'active' AND s.server_id = $1 "+
			"AND ($2::uuid IS NULL OR s.user_id = $2) "+
			"AND NOT EXISTS (SELECT 1 FROM backups b WHERE b.site_id = s.id AND b.created_at > NOW() - INTERVAL '7 days' "+
			"AND (b.destination_id IS NULL OR b.uploaded))", serverID, tenant)
	if err != nil {
		staleBackups = 0
	}

	// 7. Latest security scan. security_scans has NO user column, so a
	//    non-admin simply does not get a host scan result.
	var scanCrits, scanWarns int32
	if hostScoped {
		if f, err := queryOpt[Tup2[int32, int32]](ctx, st.DB,
			"SELECT critical_count, warning_count FROM security_scans "+
				"WHERE server_id = $1 AND status = 'completed' ORDER BY created_at DESC LIMIT 1", serverID); err == nil && f != nil {
			scanCrits, scanWarns = f.A, f.B
		}
	}

	// 8. Open incidents (user-level, not server-level).
	openIncidents, err := queryScalar[int64](ctx, st.DB,
		"SELECT COUNT(*) FROM managed_incidents "+
			"WHERE user_id = $1 AND status NOT IN ('resolved', 'postmortem')", c.Sub)
	if err != nil {
		openIncidents = 0
	}

	// 9. Health score (0-100).
	diagCritical, _ := jsonI64(jsonGet(diagnostics, "summary", "critical"))
	diagWarning, _ := jsonI64(jsonGet(diagnostics, "summary", "warning"))
	score := int64(100)
	score -= firingCount * 15  // each firing alert
	score -= ackCount * 5      // each acknowledged alert
	score -= diagCritical * 20 // each critical diagnostic
	score -= diagWarning * 5   // each warning diagnostic
	for _, cd := range countdowns {
		switch cd.severity {
		case "critical":
			score -= 15
		case "warning":
			score -= 5
		}
	}
	score -= staleBackups * 5      // per site with stale backups
	score -= int64(scanCrits) * 10 // per critical finding
	score -= int64(scanWarns) * 3  // per warning finding
	score -= openIncidents * 10    // per active incident
	score = min(max(score, 0), 100)
	grade := "F"
	switch {
	case score >= 90:
		grade = "A"
	case score >= 75:
		grade = "B"
	case score >= 60:
		grade = "C"
	case score >= 40:
		grade = "D"
	}

	// 10. Recommendations.
	recs := []map[string]any{}
	rec := func(sev, msg, action string) {
		recs = append(recs, map[string]any{"severity": sev, "message": msg, "action": action})
	}
	if staleBackups > 0 {
		rec("warning", fmt.Sprintf("%d site(s) have no backup in the last 7 days", staleBackups), "backup")
	}
	if scanCrits > 0 {
		rec("critical", fmt.Sprintf("Security scan found %d critical vulnerabilit%s", scanCrits, rtDashboardPlural(int64(scanCrits), "y", "ies")), "security")
	}
	if scanWarns > 0 {
		rec("warning", fmt.Sprintf("Security scan found %d warning%s", scanWarns, rtDashboardPlural(int64(scanWarns), "", "s")), "security")
	}
	if openIncidents > 0 {
		sev := "warning"
		if openIncidents >= 3 {
			sev = "critical"
		}
		rec(sev, fmt.Sprintf("%d active incident%s require attention", openIncidents, rtDashboardPlural(openIncidents, "", "s")), "incidents")
	}
	for _, cd := range countdowns {
		if cd.daysLeft <= 14 {
			sev := "warning"
			if cd.daysLeft <= 3 {
				sev = "critical"
			}
			rec(sev, fmt.Sprintf("SSL certificate for %s expires in %d day%s", cd.domain, cd.daysLeft, rtDashboardPlural(cd.daysLeft, "", "s")), "ssl")
		}
	}
	if firingCount > 0 {
		rec("critical", fmt.Sprintf("%d alert%s currently firing", firingCount, rtDashboardPlural(firingCount, "", "s")), "alerts")
	}
	if diagCritical > 0 {
		rec("critical", fmt.Sprintf("%d critical diagnostic issue%s detected", diagCritical, rtDashboardPlural(diagCritical, "", "s")), "diagnostics")
	}
	// Critical first, then warning.
	sort.SliceStable(recs, func(i, j int) bool {
		return rtDashboardSevOrd(recs[i]["severity"].(string)) < rtDashboardSevOrd(recs[j]["severity"].(string))
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"health_score":        score,
		"grade":               grade,
		"firing_alerts":       firingCount,
		"acknowledged_alerts": ackCount,
		"open_incidents":      openIncidents,
		"stale_backups":       staleBackups,
		"scan_critical":       scanCrits,
		"scan_warnings":       scanWarns,
		"ssl_countdowns":      sslCountdowns,
		"top_issues":          issues,
		"recommendations":     recs,
		"diagnostics":         diagnostics,
	})
	return nil
}

// rtDashboardDockerSummary: GET /api/dashboard/docker. Admin only, and it has
// to be: it asks the agent for `/apps`, the SAME call docker_apps::list_apps
// gates with require_admin — containers are not tenant-scoped at all.
func rtDashboardDockerSummary(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	var apps []any
	if res, err := agent.Get(r.Context(), "/apps"); err == nil {
		apps, _ = jsonArr(res)
	}
	running := 0
	for _, a := range apps {
		if s, _ := jsonStr(jsonGet(a, "status")); s == "running" {
			running++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": len(apps), "running": running, "stopped": len(apps) - running})
	return nil
}

func rtDashboardTenant(c *Claims) *uuid.UUID {
	if c.Role == "admin" {
		return nil
	}
	return &c.Sub
}

// rtDashboardMetricsHistory: GET /api/dashboard/metrics-history — CPU/mem/disk
// in 15-minute buckets over 24h.
//
// ⚠ SECURITY (s432): was unconditionally scoped to servers the caller
// registered — servers.user_id names whoever registered the row, not a tenant
// boundary. This route serves every role, so an admin gets the widened
// `$1::uuid IS NULL OR` fleet-wide read while a non-admin keeps seeing only the
// servers they hold.
func rtDashboardMetricsHistory(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	rows, err := queryAll[Tup4[float64, float64, float64, time.Time]](r.Context(), st.DB,
		"SELECT "+
			"AVG(cpu_pct)::float8 AS cpu_pct, "+
			"AVG(mem_pct)::float8 AS mem_pct, "+
			"AVG(disk_pct)::float8 AS disk_pct, "+
			"date_trunc('hour', created_at) + "+
			"(EXTRACT(minute FROM created_at)::int / 15) * INTERVAL '15 minutes' AS bucket "+
			"FROM metrics_history "+
			"WHERE created_at > NOW() - INTERVAL '24 hours' "+
			"AND server_id IN (SELECT id FROM servers WHERE $1::uuid IS NULL OR user_id = $1) "+
			"GROUP BY bucket "+
			"ORDER BY bucket ASC", rtDashboardTenant(c))
	if err != nil {
		return internalError("metrics history", err)
	}
	points := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		points = append(points, map[string]any{
			"cpu":  rtDashboardRound1(p.A),
			"mem":  rtDashboardRound1(p.B),
			"disk": rtDashboardRound1(p.C),
			"time": p.D.UTC().Format("15:04"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": points})
	return nil
}

type rtDashboardGPURow struct {
	GPUIndex    int16     `db:"gpu_index"`
	Utilization float64   `db:"utilization"`
	MemUsed     float64   `db:"mem_used"`
	MemTotal    float64   `db:"mem_total"`
	Temp        *float64  `db:"temp"`
	Power       *float64  `db:"power"`
	Bucket      time.Time `db:"bucket"`
}

// rtDashboardGpuMetricsHistory: GET /api/dashboard/gpu-metrics-history.
// ⚠ SECURITY (s432): same scoping fix as rtDashboardMetricsHistory.
func rtDashboardGpuMetricsHistory(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	rows, err := queryAll[rtDashboardGPURow](r.Context(), st.DB,
		"SELECT "+
			"gpu_index, "+
			"AVG(utilization_pct)::float8 AS utilization, "+
			"AVG(memory_used_mb)::float8 AS mem_used, "+
			"AVG(memory_total_mb)::float8 AS mem_total, "+
			"AVG(temperature_c)::float8 AS temp, "+
			"AVG(power_draw_w)::float8 AS power, "+
			"date_trunc('hour', created_at) + "+
			"(EXTRACT(minute FROM created_at)::int / 15) * INTERVAL '15 minutes' AS bucket "+
			"FROM gpu_metrics_history "+
			"WHERE created_at > NOW() - INTERVAL '24 hours' "+
			"AND server_id IN (SELECT id FROM servers WHERE $1::uuid IS NULL OR user_id = $1) "+
			"GROUP BY gpu_index, bucket "+
			"ORDER BY bucket ASC, gpu_index ASC", rtDashboardTenant(c))
	if err != nil {
		return internalError("gpu metrics history", err)
	}
	opt := func(v *float64) any {
		if v == nil {
			return nil
		}
		return rtDashboardRound1(*v)
	}
	points := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		vram := 0.0
		if p.MemTotal > 0 {
			vram = p.MemUsed / p.MemTotal * 100
		}
		points = append(points, map[string]any{
			"gpu_index":     p.GPUIndex,
			"utilization":   rtDashboardRound1(p.Utilization),
			"vram_pct":      rtDashboardRound1(vram),
			"vram_used_mb":  math.Round(p.MemUsed),
			"vram_total_mb": math.Round(p.MemTotal),
			"temperature":   opt(p.Temp),
			"power":         opt(p.Power),
			"time":          p.Bucket.UTC().Format("15:04"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": points})
	return nil
}

// rtDashboardTimeline: GET /api/dashboard/timeline — deploys, backups,
// incidents, alerts and scans merged newest-first.
// ⚠ SECURITY (s432): admins get the fleet-wide feed via `$1::uuid IS NULL OR`;
// a non-admin is unchanged.
func rtDashboardTimeline(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	tenant := rtDashboardTenant(c)
	events := []map[string]any{}
	add := func(typ string, detail, target any, at time.Time) {
		events = append(events, map[string]any{
			"type": typ, "detail": detail, "target": target, "created_at": telemetryCollectorRFC3339(at),
		})
	}

	deploys, _ := queryAll[Tup3[string, *string, time.Time]](ctx, st.DB,
		"SELECT dl.status, s.domain, dl.created_at "+
			"FROM deploy_logs dl "+
			"JOIN sites s ON s.id = dl.site_id "+
			"WHERE ($1::uuid IS NULL OR s.user_id = $1) "+
			"ORDER BY dl.created_at DESC LIMIT 10", tenant)
	for _, d := range deploys {
		add("deploy", d.A, d.B, d.C)
	}

	backups, _ := queryAll[Tup3[string, *string, time.Time]](ctx, st.DB,
		"SELECT b.filename, s.domain, b.created_at "+
			"FROM backups b "+
			"JOIN sites s ON s.id = b.site_id "+
			"WHERE ($1::uuid IS NULL OR s.user_id = $1) "+
			"ORDER BY b.created_at DESC LIMIT 10", tenant)
	for _, b := range backups {
		add("backup", b.A, b.B, b.C)
	}

	// Incidents: matches fleet_overview's own active_incidents count.
	incidents, _ := queryAll[Tup3[string, string, time.Time]](ctx, st.DB,
		"SELECT severity, title, created_at FROM managed_incidents "+
			"WHERE ($1::uuid IS NULL OR user_id = $1) ORDER BY created_at DESC LIMIT 10", tenant)
	for _, i := range incidents {
		add("incident", i.A, i.B, i.C)
	}

	alerts, _ := queryAll[Tup3[string, string, time.Time]](ctx, st.DB,
		"SELECT severity, title, created_at FROM alerts "+
			"WHERE ($1::uuid IS NULL OR user_id = $1) "+
			"AND (server_id IS NULL OR server_id IN (SELECT id FROM servers WHERE $1::uuid IS NULL OR user_id = $1)) "+
			"ORDER BY created_at DESC LIMIT 10", tenant)
	for _, a := range alerts {
		add("alert", a.A, a.B, a.C)
	}

	scans, _ := queryAll[Tup3[int32, int32, time.Time]](ctx, st.DB,
		"SELECT critical_count, warning_count, created_at FROM security_scans "+
			"WHERE server_id IN (SELECT id FROM servers WHERE $1::uuid IS NULL OR user_id = $1) "+
			"ORDER BY created_at DESC LIMIT 5", tenant)
	for _, s := range scans {
		add("security", fmt.Sprintf("%d critical, %d warnings", s.A, s.B), "Security Scan", s.C)
	}

	sort.SliceStable(events, func(i, j int) bool {
		return events[i]["created_at"].(string) > events[j]["created_at"].(string)
	})
	if len(events) > 30 {
		events = events[:30]
	}
	writeJSON(w, http.StatusOK, events)
	return nil
}

type rtDashboardFleetRow struct {
	ID           uuid.UUID `db:"id"`
	Name         string    `db:"name"`
	IPAddress    *string   `db:"ip_address"`
	FiringAlerts int64     `db:"firing_alerts"`
	SiteCount    int64     `db:"site_count"`
	DBCount      int64     `db:"db_count"`
	CPUPct       *float32  `db:"cpu_pct"`
	MemPct       *float32  `db:"mem_pct"`
	DiskPct      *float32  `db:"disk_pct"`
}

// rtDashboardFleetOverview: GET /api/dashboard/fleet — unified health across
// EVERY server on the install (admin only).
//
// ⚠ SECURITY (s430): was `WHERE s.user_id = $1` — so a second admin opened the
// Fleet dashboard to zero servers despite reaching every one through every
// other route. Every caller here is an admin, so the fleet is the whole fleet.
func rtDashboardFleetOverview(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	ctx := r.Context()
	// One query instead of the old 5-per-server N+1 loop.
	rows, err := queryAll[rtDashboardFleetRow](ctx, st.DB,
		"SELECT s.id, s.name, s.ip_address, "+
			"COALESCE(a.firing, 0) AS firing_alerts, "+
			"COALESCE(si.cnt, 0) AS site_count, "+
			"COALESCE(d.cnt, 0) AS db_count, "+
			"m.cpu_pct, m.mem_pct, m.disk_pct "+
			"FROM servers s "+
			"LEFT JOIN LATERAL (SELECT COUNT(*) AS firing FROM alerts WHERE server_id = s.id AND status = 'firing') a ON true "+
			"LEFT JOIN LATERAL (SELECT COUNT(*) AS cnt FROM sites WHERE server_id = s.id AND status = 'active') si ON true "+
			"LEFT JOIN LATERAL (SELECT COUNT(*) AS cnt FROM databases WHERE site_id IN (SELECT id FROM sites WHERE server_id = s.id)) d ON true "+
			"LEFT JOIN LATERAL (SELECT cpu_pct, mem_pct, disk_pct FROM metrics_history WHERE server_id = s.id ORDER BY created_at DESC LIMIT 1) m ON true "+
			"ORDER BY s.name")
	if err != nil {
		return internalError("fleet overview", err)
	}
	activeIncidents, err := queryScalar[int64](ctx, st.DB,
		"SELECT COUNT(*) FROM managed_incidents WHERE status NOT IN ('resolved', 'postmortem')")
	if err != nil {
		activeIncidents = 0
	}

	// MCP status: records an operator fills in from Settings → Services. Shown
	// here so the view an operator gets is also what an agent gets from this
	// endpoint's own MCP tool (get_fleet_dashboard).
	mcp, _ := queryAll[Tup2[string, string]](ctx, st.DB,
		"SELECT key, value FROM settings WHERE key IN ('mcp_server_enabled', 'mcp_bind_mode')")
	mcpEnabled, mcpBind, bindSet := false, "loopback", false
	for _, kv := range mcp {
		if kv.A == "mcp_server_enabled" && kv.B == "true" {
			mcpEnabled = true
		}
		if kv.A == "mcp_bind_mode" && !bindSet {
			mcpBind, bindSet = kv.B, true
		}
	}

	var totalFiring, totalSites int64
	fleet := make([]map[string]any, 0, len(rows))
	for _, s := range rows {
		totalFiring += s.FiringAlerts
		totalSites += s.SiteCount
		status := "healthy"
		if s.FiringAlerts > 0 {
			status = "warning"
		}
		fleet = append(fleet, map[string]any{
			"id": s.ID, "name": s.Name, "ip_address": s.IPAddress,
			"firing_alerts": s.FiringAlerts, "active_incidents": activeIncidents,
			"sites": s.SiteCount, "databases": s.DBCount,
			"cpu_pct": s.CPUPct, "mem_pct": s.MemPct, "disk_pct": s.DiskPct,
			"status": status,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":         fleet,
		"total_servers":   len(rows),
		"total_firing":    totalFiring,
		"total_incidents": activeIncidents,
		"total_sites":     totalSites,
		"mcp":             map[string]any{"enabled": mcpEnabled, "bind_mode": mcpBind},
	})
	return nil
}
