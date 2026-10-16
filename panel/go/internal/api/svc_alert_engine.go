package api

// Port of panel/backend/src/services/alert_engine.rs.

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertEngineRun is the background task: checks all alert conditions every
// 60 seconds until ctx (shutdown) is cancelled.
func AlertEngineRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	slog.Info("Alert engine started")

	// Initial delay (respects shutdown)
	select {
	case <-time.After(30 * time.Second):
	case <-ctx.Done():
		slog.Info("Alert engine shutting down gracefully (during initial delay)")
		return
	}

	// tokio::time::interval fires immediately, then every period.
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	var tickCount uint64
	for {
		tickCount++
		// A tick, once started, runs to completion as the Rust select! arm
		// did: cancelling mid-tick could leave an alert_state row stamped
		// 'firing' with no page sent, which silences it for good.
		alertEngineTick(context.WithoutCancel(ctx), db, agents, tickCount)

		select {
		case <-ticker.C:
		case <-ctx.Done():
			slog.Info("Alert engine shutting down gracefully")
			return
		}
	}
}

func alertEngineTick(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, tickCount uint64) {
	// Whose alerts are silenced right now. Loaded ONCE per tick and handed to
	// every check, the way uptime does it — the alternative is one query per
	// server per alert type.
	maint := alertEngineMaintenanceUsers(ctx, db)

	alertEngineCheckResourceThresholds(ctx, db, maint)
	alertEngineCheckServerOffline(ctx, db, maint)
	alertEngineCheckSslExpiry(ctx, db, maint)
	alertEngineCheckStackSslExpiry(ctx, db, maint)
	alertEngineCheckRegisteredCertExpiry(ctx, db, maint)

	// The agent-driven checks run once PER ONLINE SERVER. Until v2.58.0 all
	// three asked the panel's own agent and labelled the answers with the
	// OLDEST `servers` row, selected by ascending creation date and commented
	// "the local server", which it is only on an install that never added
	// one. On a fleet that is the panel's GPUs, the panel's services and the
	// panel's containers filed under whichever server was registered first.
	fleet := agents.OnlineFleet(ctx)

	for i := range fleet {
		member := &fleet[i]
		// One skip covers all three: every alert these raise is addressed to
		// member.UserID and nobody else.
		if maint[member.UserID] {
			continue
		}

		alertEngineCheckGpuThresholds(ctx, db, member)

		// Service health every 2 minutes (every other tick)
		if tickCount%2 == 0 {
			alertEngineCheckServiceHealth(ctx, db, member)
		}

		// GAP 8: Docker container health every 2 minutes (offset from service health)
		if tickCount%2 == 1 {
			alertEngineCheckContainerHealth(ctx, db, member)
		}
	}

	// GAP 9: Escalate unacknowledged firing alerts older than 15 minutes
	alertEngineCheckEscalations(ctx, db)

	// Purge old resolved alerts (keep 30 days) — every hour
	if tickCount%60 == 0 {
		_, _ = execSQL(ctx, db,
			"DELETE FROM alerts WHERE status = 'resolved' AND resolved_at < NOW() - INTERVAL '30 days'")
	}
}

// ─── Maintenance Windows ────────────────────────────────────────────────

// alertEngineMaintenanceUsers is the set of users with an open maintenance
// window at this instant.
//
// The panel offers a button labelled *Silence Alerts*. Until this existed the
// only service that honoured it was uptime, which owns 5 of the 19 alert
// types; this engine owns the other 14 and had never read the table. So the
// alerts a planned maintenance is certain to cause — offline, service_down,
// container_down — were precisely the ones that still paged.
//
// ⚠ The set is applied at each check's SOURCE, never at the fire. That is not
// a style preference. checkServerOffline selects the servers that have no
// firing row and then writes one; checkThreshold and the SSL ladder stamp
// alert_state beside their fire. Suppressing at the fire would leave those
// stamps claiming the operator was paged while nothing was sent, and the
// condition would never page again — the permanent silence that
// fireAlertWithRetry's own contract exists to prevent. Skipping the row before
// any of that runs means the condition is still true on the first tick after
// the window closes, and pages then.
//
// The six types raised elsewhere (backup_failure, backup_verification_failed,
// cron_failure, security, image_scan, ssl_renewal_failure) are deliberately
// NOT suppressed: each report is the result of a specific run (a backup, a
// cron job, a scan), not a standing condition THIS engine re-evaluates on its
// own 60-second loop. A run that happens to fall inside a maintenance window
// is not deferred to the next tick the way a standing condition is;
// suppressing it here would lose that run's result outright.
func alertEngineMaintenanceUsers(ctx context.Context, db *pgxpool.Pool) map[uuid.UUID]bool {
	out := map[uuid.UUID]bool{}
	ids, _ := queryAll[uuid.UUID](ctx, db,
		"SELECT DISTINCT user_id FROM maintenance_windows "+
			"WHERE starts_at <= NOW() AND ends_at >= NOW()")
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// ─── Alert Fire with Retry ──────────────────────────────────────────────

// alertEngineFireAlertWithRetry fires an alert with retry (2 attempts, 3s
// delay between).
//
// Returns whether the alert was actually recorded. Callers that write a dedup
// stamp MUST gate it on this: stamping after a failed fire silences the
// condition permanently, because the stamp says "already paged" while nothing
// was ever delivered and no `alerts` row exists for checkEscalations to
// re-page from.
func alertEngineFireAlertWithRetry(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID, siteID *uuid.UUID, alertType, stateKey, severity, title, message string) bool {
	for attempt := 0; attempt < 2; attempt++ {
		fired, err := NotificationsTryFireAlert(ctx, db, userID, serverID, siteID, alertType, stateKey, severity, title, message)
		if err == nil && !fired {
			// `false` is not a fire. The operator has this type switched off,
			// so TryFireAlert wrote no `alerts` row, rang no bell and sent
			// nothing — and the two things below both have to know that.
			//
			// Returning true here published the outage on the operator's
			// PUBLIC status page (the incident is created
			// visible_on_status_page = TRUE) for the one alert type they had
			// asked not to hear about, and it also satisfied this function's
			// own contract, so the SSL ladder stamped last_warned_day for a
			// page that never happened. Because sslDecision only fires a rung
			// TIGHTER than the one stamped, that rung was then gone for good —
			// re-enabling the type did not bring it back.
			//
			// Retrying is pointless too: the answer is a stored preference,
			// not a transient error, so this returns rather than looping.
			return false
		}
		if err == nil {
			// Auto-create managed incident for critical alerts.
			// GAP 11: Check for existing active incident before creating a new one.
			if severity == "critical" || alertType == "offline" || alertType == "service_down" {
				incidentSeverity := "major"
				if severity == "critical" {
					incidentSeverity = "critical"
				}

				// Already an active incident for this user within the last 5 minutes?
				existing, _ := queryScalarOpt[uuid.UUID](ctx, db,
					"SELECT id FROM managed_incidents "+
						"WHERE user_id = $1 "+
						"AND status NOT IN ('resolved', 'postmortem') "+
						"AND created_at > NOW() - INTERVAL '5 minutes' "+
						"LIMIT 1", userID)

				if existing != nil {
					// Append as incident update instead of creating a duplicate incident
					_, _ = execSQL(ctx, db,
						"INSERT INTO incident_updates (incident_id, status, message, author_email) "+
							"VALUES ($1, 'investigating', $2, 'system')",
						*existing, fmt.Sprintf("Related %s alert: %s", alertType, message))
					slog.Info(fmt.Sprintf("Correlated alert to existing incident %s: %s", *existing, title))
				} else {
					// No recent active incident — create a new one. RETURNING id
					// binds the follow-up update to the row we just wrote; the
					// previous re-lookup matched on `title` alone across the
					// whole table, so two tenants whose servers share a name
					// (the default hostname, "vps", "web") could have the update
					// land on the OTHER tenant's investigating incident.
					newIncident, _ := queryScalarOpt[uuid.UUID](ctx, db,
						"INSERT INTO managed_incidents (user_id, title, status, severity, description, visible_on_status_page) "+
							"VALUES ($1, $2, 'investigating', $3, $4, TRUE) RETURNING id",
						userID, title, incidentSeverity, message)
					if newIncident != nil {
						_, _ = execSQL(ctx, db,
							"INSERT INTO incident_updates (incident_id, status, message, author_email) "+
								"VALUES ($1, 'investigating', $2, 'system')",
							*newIncident, fmt.Sprintf("Auto-created from %s alert: %s", alertType, message))
					}
				}
			}
			return true
		}

		slog.Warn(fmt.Sprintf("Alert fire attempt %d failed: %v", attempt+1, err))
		if attempt == 1 {
			// Both attempts failed — log to system_logs
			details := err.Error()
			SystemLogLogEvent(ctx, db, "error", "alert_engine", "Failed to fire alert: "+title, &details)
		}
		if attempt < 1 {
			time.Sleep(3 * time.Second)
		}
	}
	return false
}

// ─── Resource Thresholds (CPU / Memory / Disk) ─────────────────────────

type alertEngineServerMetrics struct {
	ID           uuid.UUID `db:"id"`
	UserID       uuid.UUID `db:"user_id"`
	Name         string    `db:"name"`
	CPUUsage     *float32  `db:"cpu_usage"`
	MemUsedMB    *int64    `db:"mem_used_mb"`
	RAMMB        *int32    `db:"ram_mb"`
	DiskUsagePct *float32  `db:"disk_usage_pct"`
}

func alertEngineCheckResourceThresholds(ctx context.Context, db *pgxpool.Pool, maint map[uuid.UUID]bool) {
	servers, err := queryAll[alertEngineServerMetrics](ctx, db,
		"SELECT id, user_id, name, cpu_usage, mem_used_mb, ram_mb, disk_usage_pct "+
			"FROM servers WHERE status = 'online'")
	if err != nil {
		slog.Error(fmt.Sprintf("Alert engine: server query error: %v", err))
		return
	}

	for i := range servers {
		server := &servers[i]
		if maint[server.UserID] {
			continue
		}

		cpuThresh, cpuDur, memThresh, memDur, diskThresh, cooldown, _ :=
			NotificationsGetThresholds(ctx, db, server.UserID, &server.ID)

		// CPU
		if server.CPUUsage != nil {
			cpu := *server.CPUUsage
			alertEngineCheckThreshold(ctx, db, server, "cpu", float64(cpu), float64(cpuThresh), cpuDur, cooldown,
				fmt.Sprintf("CPU at %.0f%% on %s", cpu, server.Name),
				fmt.Sprintf("CPU usage has been above %d%% for %d minutes on server %s", cpuThresh, cpuDur, server.Name))
		}

		// Memory
		if server.MemUsedMB != nil && server.RAMMB != nil {
			used, total := *server.MemUsedMB, *server.RAMMB
			if total > 0 {
				pct := (float64(used) / float64(total)) * 100.0
				alertEngineCheckThreshold(ctx, db, server, "memory", pct, float64(memThresh), memDur, cooldown,
					fmt.Sprintf("Memory at %.0f%% on %s", pct, server.Name),
					fmt.Sprintf("Memory usage has been above %d%% for %d minutes on server %s", memThresh, memDur, server.Name))
			}
		}

		// Disk (no duration — disk doesn't fluctuate rapidly)
		if server.DiskUsagePct != nil {
			disk := *server.DiskUsagePct
			alertEngineCheckThreshold(ctx, db, server, "disk", float64(disk), float64(diskThresh),
				1, // fire immediately
				cooldown,
				fmt.Sprintf("Disk at %.0f%% on %s", disk, server.Name),
				fmt.Sprintf("Disk usage is above %d%% on server %s", diskThresh, server.Name))
		}

		// GAP 6: Disk-full forecast — check if disk will be full within 48
		// hours based on trend. Bounded by TIME, not by row count. `LIMIT 60`
		// against a 30s collector cadence is a ~30-minute window, and
		// diskFullForecast requires 6 hours — so the forecast this guide
		// advertises ("full within 48 hours") could never fire, for any
		// input, on any install. Proven on a live box: 20,159 rows at a
		// measured 30.0s mean gap, and `alerts` held 0 disk_forecast rows
		// against 7 for memory_leak, which runs the identical query without
		// the time gate. 12h at 30s is ~1440 rows; the LIMIT stays as a bound
		// on a stalled or backfilled collector, not as the window itself.
		diskTrend, err := queryAll[Tup2[float32, time.Time]](ctx, db,
			"SELECT disk_pct, created_at FROM metrics_history "+
				"WHERE server_id = $1 AND created_at > NOW() - INTERVAL '12 hours' "+
				"ORDER BY created_at DESC LIMIT 1440", server.ID)
		if err != nil {
			diskTrend = nil
		}

		// Both trend alerts below run through claimTrendFire/clearTrendAlert
		// rather than calling fireAlertWithRetry directly: the condition holds
		// across many consecutive 60s ticks, and an ungated fire on every tick
		// meant one page per minute to every channel plus one never-purged
		// `alerts` row per minute for a single event — and, because nothing
		// ever resolved them, a checkEscalations re-page every 30 minutes
		// forever.
		//
		// That storm was live for memory_leak. disk_forecast was UNREACHABLE
		// and had never fired: a row-count LIMIT against a 30s cadence could
		// not span the 6-hour minimum. The query is now time-bounded, so the
		// forecast is reachable — which is exactly why the gate below matters
		// rather than being belt-and-braces. It is the thing standing between
		// a real forecast and the per-minute page storm memory_leak
		// demonstrated.
		if hoursToFull, ratePerHour, currentPct, ok := alertEngineDiskFullForecast(diskTrend); ok {
			if alertEngineClaimTrendFire(ctx, db, server.ID, "disk_forecast", cooldown) {
				severity := "warning"
				if hoursToFull < 12.0 {
					severity = "critical"
				}
				alertEngineFireAlertWithRetry(ctx, db, server.UserID, &server.ID, nil, "disk_forecast", "", severity,
					fmt.Sprintf("Disk will be full in %.0f hours on %s", hoursToFull, server.Name),
					fmt.Sprintf("At the current growth rate of %.1f%%/hour, disk will be full in approximately %.0f hours. Current usage: %.1f%%",
						ratePerHour, hoursToFull, currentPct))
			}
		} else {
			alertEngineClearTrendAlert(ctx, db, server.UserID, server.ID, "disk_forecast",
				"Disk fill forecast cleared on "+server.Name,
				fmt.Sprintf("Disk usage on server %s is no longer trending toward full within 48 hours.", server.Name))
		}

		// GAP 7: Memory leak detection — sustained upward trend in memory usage
		memTrend, err := queryAll[float32](ctx, db,
			"SELECT mem_pct FROM metrics_history "+
				"WHERE server_id = $1 ORDER BY created_at DESC LIMIT 60", server.ID)
		if err != nil {
			memTrend = nil
		}

		if increase, olderAvg, recentAvg, ok := alertEngineMemoryLeakTrend(memTrend); ok {
			if alertEngineClaimTrendFire(ctx, db, server.ID, "memory_leak", cooldown) {
				alertEngineFireAlertWithRetry(ctx, db, server.UserID, &server.ID, nil, "memory_leak", "", "warning",
					"Possible memory leak detected on "+server.Name,
					fmt.Sprintf("Memory usage has risen %.1f%% in the last hour (from %.1f%% to %.1f%%). "+
						"This sustained increase suggests a memory leak.", increase, olderAvg, recentAvg))
			}
		} else {
			alertEngineClearTrendAlert(ctx, db, server.UserID, server.ID, "memory_leak",
				"Memory leak signal cleared on "+server.Name,
				fmt.Sprintf("Memory usage on server %s is no longer trending upward.", server.Name))
		}
	}
}

// alertEngineDiskFullForecast is the GAP 6 predicate: (hoursToFull,
// ratePerHour, currentPct, true) while the disk is forecast to fill within 48
// hours, ok=false once the trend clears. trend is newest-first.
//
// The query's 12-hour gate means a healthy collector supplies ~12 hours of
// trend, so the 6-hour floor below is reachable; the LIMIT 1440 is a bound on
// a stalled collector rather than the window itself.
//
// What still keeps it quiet on a healthy box is the second gate, doing the
// work it was designed to do: a disk under 60% is not on a runway to full.
//
// Skip the forecast on fresh installs / short trend windows. Linear
// extrapolation over 30-60 minutes catches the install-time write spike
// (binaries, frontend tarball, postgres init, container layers) and predicts
// "disk full in 9 hours" at <5% real usage. Require:
//   - at least 6 hours of trend data (so the install spike has bled out), AND
//   - current disk usage already over 60% (so we're actually on a runway to a
//     real full disk, not extrapolating from noise on an empty box).
func alertEngineDiskFullForecast(trend []Tup2[float32, time.Time]) (float64, float64, float64, bool) {
	if len(trend) < 10 {
		return 0, 0, 0, false
	}
	newest, oldest := trend[0], trend[len(trend)-1]
	// chrono num_seconds truncates to whole seconds.
	hoursDiff := float64(int64(newest.B.Sub(oldest.B)/time.Second)) / 3600.0
	if hoursDiff < 6.0 || newest.A < 60.0 {
		return 0, 0, 0, false
	}
	ratePerHour := (float64(newest.A) - float64(oldest.A)) / hoursDiff
	if ratePerHour <= 0.0 {
		return 0, 0, 0, false
	}
	hoursToFull := (100.0 - float64(newest.A)) / ratePerHour
	if hoursToFull <= 0.0 || hoursToFull >= 48.0 {
		return 0, 0, 0, false
	}
	return hoursToFull, ratePerHour, float64(newest.A), true
}

// alertEngineMemoryLeakTrend is the GAP 7 predicate: (increase, olderAvg,
// recentAvg, true) while memory shows a sustained climb (>10 points over the
// trend window and above 60%), ok=false once it flattens or falls back.
func alertEngineMemoryLeakTrend(trend []float32) (float64, float64, float64, bool) {
	if len(trend) < 30 {
		return 0, 0, 0, false
	}
	var recent, older float64
	for _, m := range trend[:10] {
		recent += float64(m)
	}
	for _, m := range trend[20:30] {
		older += float64(m)
	}
	recentAvg, olderAvg := recent/10.0, older/10.0
	increase := recentAvg - olderAvg
	if increase > 10.0 && recentAvg > 60.0 {
		return increase, olderAvg, recentAvg, true
	}
	return 0, 0, 0, false
}

type alertEngineStateRow = Tup3[string, int32, *time.Time]

func alertEngineCheckThreshold(ctx context.Context, db *pgxpool.Pool, server *alertEngineServerMetrics, alertType string, currentValue, threshold float64, requiredDuration, cooldownMinutes int32, title, message string) {
	exceeds := currentValue > threshold

	// Get or create alert state
	st, _ := queryOpt[alertEngineStateRow](ctx, db,
		"SELECT current_state, consecutive_count, last_notified_at "+
			"FROM alert_state WHERE server_id = $1 AND alert_type = $2 AND state_key = ''",
		server.ID, alertType)
	currentState, consecutive, lastNotified := "ok", int32(0), (*time.Time)(nil)
	if st != nil {
		currentState, consecutive, lastNotified = st.A, st.B, st.C
	}

	if exceeds {
		newCount := consecutive + 1

		// Upsert state — PostgreSQL serializes concurrent ON CONFLICT upserts.
		// The ::int4 casts stand in for the INT4 parameter types sqlx sent;
		// with server-inferred types `$3 >= $4` alone would resolve to text.
		_, _ = execSQL(ctx, db,
			"INSERT INTO alert_state (server_id, alert_type, state_key, current_state, consecutive_count, fired_at) "+
				"VALUES ($1, $2, '', CASE WHEN $3::int4 >= $4::int4 THEN 'firing' ELSE 'pending' END, $3, "+
				"CASE WHEN $3 >= $4 THEN NOW() ELSE NULL END) "+
				"ON CONFLICT (server_id, alert_type, state_key) WHERE server_id IS NOT NULL "+
				"DO UPDATE SET consecutive_count = $3, "+
				"current_state = CASE WHEN $3 >= $4 THEN 'firing' ELSE alert_state.current_state END, "+
				"fired_at = CASE WHEN $3 >= $4 AND alert_state.current_state != 'firing' THEN NOW() ELSE alert_state.fired_at END",
			server.ID, alertType, newCount, requiredDuration)

		// Fire alert if threshold duration met and not already notified within cooldown
		if newCount >= requiredDuration && (currentState != "firing" || alertEnginePastCooldown(lastNotified, cooldownMinutes)) {
			severity := "warning"
			if currentValue > threshold*1.1 {
				severity = "critical"
			}

			// checkThreshold's own alert_state rows are keyed '' — these are
			// conditions of the server as a whole, not of an entity on it.
			alertEngineFireAlertWithRetry(ctx, db, server.UserID, &server.ID, nil, alertType, "", severity, title, message)

			// Update last_notified
			_, _ = execSQL(ctx, db,
				"UPDATE alert_state SET last_notified_at = NOW() "+
					"WHERE server_id = $1 AND alert_type = $2 AND state_key = ''",
				server.ID, alertType)
		}
	} else if currentState == "firing" {
		// Value dropped below threshold — resolve
		_, _ = execSQL(ctx, db,
			"UPDATE alert_state SET current_state = 'ok', consecutive_count = 0, fired_at = NULL, last_notified_at = NULL "+
				"WHERE server_id = $1 AND alert_type = $2 AND state_key = ''",
			server.ID, alertType)

		NotificationsResolveAlert(ctx, db, server.UserID, &server.ID, nil, alertType, "",
			fmt.Sprintf("%s recovered on %s", strings.ToUpper(alertType), server.Name),
			fmt.Sprintf("%s usage has returned to normal (%.0f%%) on server %s", alertType, currentValue, server.Name))
	} else if consecutive > 0 {
		// Below threshold and not firing — reset counter
		_, _ = execSQL(ctx, db,
			"UPDATE alert_state SET consecutive_count = 0 "+
				"WHERE server_id = $1 AND alert_type = $2 AND state_key = ''",
			server.ID, alertType)
	}
}

func alertEnginePastCooldown(lastNotified *time.Time, cooldownMinutes int32) bool {
	if lastNotified == nil {
		return true
	}
	return int64(time.Since(*lastNotified)/time.Minute) >= int64(cooldownMinutes)
}

// alertEngineClaimTrendFire is the fire-gate for the trend-derived alerts
// (memory_leak, disk_forecast), which have no per-sample state machine of
// their own the way checkThreshold does.
//
// Returns true at most once per cooldownMinutes window while the condition
// holds. The claim and the stamp are one statement, so two engines racing the
// same window can't both page — whichever loses the ON CONFLICT sees the fresh
// last_notified_at and returns no row.
//
// The gate is purely time-based: it deliberately does NOT re-arm just because
// the state row reads 'ok'. These predicates sit on a threshold (memory_leak
// needs recentAvg > 60.0), so a server plateaued at the boundary flips the
// condition on and off with ordinary jitter. Re-arming on the 'ok' transition
// would let that flap page once per tick with the cooldown never applying —
// reintroducing, through the gate meant to stop it, the exact storm this
// function exists to prevent.
func alertEngineClaimTrendFire(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, alertType string, cooldownMinutes int32) bool {
	// A rule with cooldown_minutes <= 0 re-arms on every tick, which is
	// exactly the storm this gate exists to stop — floor it at one tick.
	cooldown := max(cooldownMinutes, 1)

	claimed, err := queryScalarOpt[uuid.UUID](ctx, db,
		"INSERT INTO alert_state (server_id, alert_type, state_key, current_state, fired_at, last_notified_at) "+
			"VALUES ($1, $2, '', 'firing', NOW(), NOW()) "+
			"ON CONFLICT (server_id, alert_type, state_key) WHERE server_id IS NOT NULL "+
			"DO UPDATE SET current_state = 'firing', "+
			"fired_at = COALESCE(alert_state.fired_at, NOW()), "+
			"last_notified_at = NOW() "+
			"WHERE alert_state.last_notified_at IS NULL "+
			"OR alert_state.last_notified_at < NOW() - make_interval(mins => $3) "+
			"RETURNING id",
		serverID, alertType, cooldown)
	return err == nil && claimed != nil
}

// alertEngineClearTrendAlert resolves a trend-derived alert once its
// condition clears.
//
// Without this the `alerts` row stays status = 'firing' forever: the hourly
// purge only deletes resolved rows, and checkEscalations keeps re-paging
// on-call every 30 minutes for a leak that recovered or a disk that stopped
// filling. Sends the recovery notification only on the actual transition, so a
// steady-state server doesn't emit a "recovered" page every tick.
//
// last_notified_at is deliberately PRESERVED: it is the cooldown clock
// claimTrendFire reads, and clearing it here would let a flapping predicate
// re-page on the very next tick. Keeping it caps a flap at one fire plus one
// recovery per cooldown window — once a re-fire is suppressed the state row
// stays 'ok', so this UPDATE matches nothing and no second recovery page is
// sent either.
func alertEngineClearTrendAlert(ctx context.Context, db *pgxpool.Pool, userID, serverID uuid.UUID, alertType, title, message string) {
	n, err := execSQL(ctx, db,
		"UPDATE alert_state SET current_state = 'ok', fired_at = NULL "+
			"WHERE server_id = $1 AND alert_type = $2 AND state_key = '' AND current_state = 'firing'",
		serverID, alertType)
	if err == nil && n > 0 {
		NotificationsResolveAlert(ctx, db, userID, &serverID, nil, alertType, "", title, message)
	}
}

// ─── GPU Thresholds ─────────────────────────────────────────────────────

func alertEngineCheckGpuThresholds(ctx context.Context, db *pgxpool.Pool, member *AgentFleetMember) {
	gpuInfo, err := member.Agent.Get(ctx, "/apps/gpu-info")
	if err != nil {
		return
	}

	if b, _ := jsonBool(jsonGet(gpuInfo, "available")); !b {
		return
	}
	gpus, ok := jsonArr(jsonGet(gpuInfo, "gpus"))
	if !ok || len(gpus) == 0 {
		return
	}

	serverID, userID, serverName := member.ID, member.UserID, member.Name

	gpuUtilThresh, gpuUtilDur, gpuTempThresh, gpuVramThresh, cooldown :=
		NotificationsGetGpuThresholds(ctx, db, userID, &serverID)

	for _, gpu := range gpus {
		idx, _ := jsonI64(jsonGet(gpu, "index"))
		name, ok := jsonStr(jsonGet(gpu, "name"))
		if !ok {
			name = "GPU"
		}
		util, _ := jsonF64(jsonGet(gpu, "utilization_gpu_pct"))
		temp, hasTemp := jsonF64(jsonGet(gpu, "temperature_c"))
		memUsed, _ := jsonF64(jsonGet(gpu, "memory_used_mb"))
		memTotal, ok := jsonF64(jsonGet(gpu, "memory_total_mb"))
		if !ok {
			memTotal = 1.0
		}
		vramPct := 0.0
		if memTotal > 0.0 {
			vramPct = (memUsed / memTotal) * 100.0
		}

		statePrefix := fmt.Sprintf("gpu_%d", idx)

		// GPU utilization threshold (with duration, like CPU)
		alertEngineCheckGpuMetric(ctx, db, serverID, userID, serverName,
			statePrefix+"_util", "gpu_utilization",
			util, float64(gpuUtilThresh), gpuUtilDur, cooldown,
			fmt.Sprintf("GPU %d (%s) at %.0f%% on %s", idx, name, util, serverName),
			fmt.Sprintf("GPU %d (%s) utilization above %d%% for %d minutes on %s", idx, name, gpuUtilThresh, gpuUtilDur, serverName))

		// GPU temperature threshold (fire immediately, like disk)
		if hasTemp {
			alertEngineCheckGpuMetric(ctx, db, serverID, userID, serverName,
				statePrefix+"_temp", "gpu_temperature",
				temp, float64(gpuTempThresh), 1, cooldown,
				fmt.Sprintf("GPU %d (%s) at %.0f°C on %s", idx, name, temp, serverName),
				fmt.Sprintf("GPU %d (%s) temperature above %d°C on %s. Current: %.0f°C", idx, name, gpuTempThresh, serverName, temp))
		}

		// VRAM threshold (fire immediately)
		alertEngineCheckGpuMetric(ctx, db, serverID, userID, serverName,
			statePrefix+"_vram", "gpu_vram",
			vramPct, float64(gpuVramThresh), 1, cooldown,
			fmt.Sprintf("GPU %d (%s) VRAM at %.0f%% on %s", idx, name, vramPct, serverName),
			fmt.Sprintf("GPU %d (%s) VRAM above %d%% on %s. Used: %.0f/%.0f MB", idx, name, gpuVramThresh, serverName, memUsed, memTotal))
	}
}

// alertEngineCheckGpuMetric is the generic GPU metric threshold check using
// the existing alert_state machine.
func alertEngineCheckGpuMetric(ctx context.Context, db *pgxpool.Pool, serverID, userID uuid.UUID, serverName, stateKey, alertType string, currentValue, threshold float64, requiredDuration, cooldownMinutes int32, title, message string) {
	exceeds := currentValue > threshold

	st, _ := queryOpt[alertEngineStateRow](ctx, db,
		"SELECT current_state, consecutive_count, last_notified_at "+
			"FROM alert_state WHERE server_id = $1 AND alert_type = $2 AND state_key = $3",
		serverID, alertType, stateKey)
	currentState, consecutive, lastNotified := "ok", int32(0), (*time.Time)(nil)
	if st != nil {
		currentState, consecutive, lastNotified = st.A, st.B, st.C
	}

	if exceeds {
		newCount := consecutive + 1

		// ::int4 casts: see alertEngineCheckThreshold.
		_, _ = execSQL(ctx, db,
			"INSERT INTO alert_state (server_id, alert_type, state_key, current_state, consecutive_count, fired_at) "+
				"VALUES ($1, $2, $3, CASE WHEN $4::int4 >= $5::int4 THEN 'firing' ELSE 'pending' END, $4, "+
				"CASE WHEN $4 >= $5 THEN NOW() ELSE NULL END) "+
				"ON CONFLICT (server_id, alert_type, state_key) WHERE server_id IS NOT NULL "+
				"DO UPDATE SET consecutive_count = $4, "+
				"current_state = CASE WHEN $4 >= $5 THEN 'firing' ELSE alert_state.current_state END, "+
				"fired_at = CASE WHEN $4 >= $5 AND alert_state.current_state != 'firing' THEN NOW() ELSE alert_state.fired_at END",
			serverID, alertType, stateKey, newCount, requiredDuration)

		if newCount >= requiredDuration && (currentState != "firing" || alertEnginePastCooldown(lastNotified, cooldownMinutes)) {
			severity := "warning"
			if currentValue > threshold*1.1 {
				severity = "critical"
			}

			alertEngineFireAlertWithRetry(ctx, db, userID, &serverID, nil, alertType, stateKey, severity, title, message)

			_, _ = execSQL(ctx, db,
				"UPDATE alert_state SET last_notified_at = NOW() "+
					"WHERE server_id = $1 AND alert_type = $2 AND state_key = $3",
				serverID, alertType, stateKey)
		}
	} else if currentState == "firing" {
		_, _ = execSQL(ctx, db,
			"UPDATE alert_state SET current_state = 'ok', consecutive_count = 0, fired_at = NULL, last_notified_at = NULL "+
				"WHERE server_id = $1 AND alert_type = $2 AND state_key = $3",
			serverID, alertType, stateKey)

		typeLabel := alertType
		switch alertType {
		case "gpu_utilization":
			typeLabel = "GPU utilization"
		case "gpu_temperature":
			typeLabel = "GPU temperature"
		case "gpu_vram":
			typeLabel = "GPU VRAM"
		}
		NotificationsResolveAlert(ctx, db, userID, &serverID, nil, alertType, stateKey,
			fmt.Sprintf("%s recovered on %s", typeLabel, serverName),
			fmt.Sprintf("%s has returned to normal (%.0f) on server %s", typeLabel, currentValue, serverName))
	} else if consecutive > 0 {
		_, _ = execSQL(ctx, db,
			"UPDATE alert_state SET consecutive_count = 0 "+
				"WHERE server_id = $1 AND alert_type = $2 AND state_key = $3",
			serverID, alertType, stateKey)
	}
}

// ─── Server Offline ─────────────────────────────────────────────────────

func alertEngineCheckServerOffline(ctx context.Context, db *pgxpool.Pool, maint map[uuid.UUID]bool) {
	// Find servers that just went offline (status = offline, no firing alert state yet)
	offline, err := queryAll[Tup3[uuid.UUID, uuid.UUID, string]](ctx, db,
		"SELECT s.id, s.user_id, s.name FROM servers s "+
			"WHERE s.status = 'offline' "+
			"AND NOT EXISTS ( "+
			"SELECT 1 FROM alert_state "+
			"WHERE server_id = s.id AND alert_type = 'offline' AND current_state = 'firing' "+
			")")
	if err != nil {
		return
	}

	for _, o := range offline {
		serverID, userID, name := o.A, o.B, o.C
		// Before the firing row is written, not after: this loop's own query
		// excludes anything already firing, so a row stamped without a page
		// would never page again.
		if maint[userID] {
			continue
		}

		// Create firing state — PostgreSQL serializes concurrent ON CONFLICT upserts
		_, _ = execSQL(ctx, db,
			"INSERT INTO alert_state (server_id, alert_type, state_key, current_state, fired_at, last_notified_at) "+
				"VALUES ($1, 'offline', '', 'firing', NOW(), NOW()) "+
				"ON CONFLICT (server_id, alert_type, state_key) WHERE server_id IS NOT NULL "+
				"DO UPDATE SET current_state = 'firing', fired_at = NOW(), last_notified_at = NOW()",
			serverID)

		alertEngineFireAlertWithRetry(ctx, db, userID, &serverID, nil, "offline", "", "critical",
			fmt.Sprintf("Server %s is offline", name),
			fmt.Sprintf("Server %s has stopped responding and is now marked offline. Last seen more than 2 minutes ago.", name))
	}

	// Check for servers that came back online (state firing but server now online)
	recovered, err := queryAll[Tup3[uuid.UUID, uuid.UUID, string]](ctx, db,
		"SELECT s.id, s.user_id, s.name FROM servers s "+
			"JOIN alert_state ast ON ast.server_id = s.id "+
			"WHERE s.status = 'online' AND ast.alert_type = 'offline' AND ast.current_state = 'firing'")
	if err != nil {
		return
	}

	for _, rc := range recovered {
		serverID, userID, name := rc.A, rc.B, rc.C
		_, _ = execSQL(ctx, db,
			"UPDATE alert_state SET current_state = 'ok', fired_at = NULL, last_notified_at = NULL "+
				"WHERE server_id = $1 AND alert_type = 'offline'",
			serverID)

		NotificationsResolveAlert(ctx, db, userID, &serverID, nil, "offline", "",
			fmt.Sprintf("Server %s is back online", name),
			fmt.Sprintf("Server %s has reconnected and is responding normally.", name))
	}
}

// ─── SSL Expiry ─────────────────────────────────────────────────────────

// alertEngineSslNeverWarned is the last_warned_day sentinel for "this site
// has never been paged". Every real warning day is far below it, so the first
// crossing always pages.
const alertEngineSslNeverWarned int64 = 999

// alertEngineSslExpiredWarnDay is the dedup key for the EXPIRED page. Tighter
// than any configurable warning day (those are >= 0), so an expired cert pages
// once and then stays quiet instead of re-firing on every 60s tick until
// someone renews it.
const alertEngineSslExpiredWarnDay int64 = -1

type alertEngineSslActionKind int

const (
	// alertEngineSslNothing: nothing to do.
	alertEngineSslNothing alertEngineSslActionKind = iota
	// alertEngineSslResolve: certificate moved back past the rung we last
	// paged at — it was renewed.
	alertEngineSslResolve
	// alertEngineSslFire: page at WarnDay (the dedup key to stamp on success).
	alertEngineSslFire
)

// alertEngineSslAction is what checkSslExpiry should do for one site this tick.
type alertEngineSslAction struct {
	Kind     alertEngineSslActionKind
	WarnDay  int64
	Severity string
}

// alertEngineSslDecision is the SSL warning ladder, extracted so the
// lifecycle is testable without a DB. warningDays must be descending (see
// alertEngineParseSslWarningDays).
func alertEngineSslDecision(daysLeft int64, expired bool, lastWarnedDay int64, warningDays []int64) alertEngineSslAction {
	// Renewed past the rung we last paged at → resolve. Nothing used to
	// resolve an ssl_expiry row, so a cert renewed weeks ago left a 'firing'
	// row that checkEscalations re-paged every 30 minutes forever and the
	// purge (resolved-only) never collected.
	//
	// The test is against lastWarnedDay, NOT against the widest configured
	// rung: a cert renewed back to a value still inside the warning window (a
	// 90-day renewal under a '90' config, or a short-lived ACME profile whose
	// whole validity sits below the widest rung) is still a renewal. Gating on
	// the widest rung would leave exactly those sites ratcheting downward
	// across renewals until no rung — not even the EXPIRED sentinel — could
	// ever fire again. Ticking down normally can never satisfy this, since
	// daysLeft only falls.
	//
	// `!expired` is load-bearing. daysLeft truncates toward zero, so for the
	// whole first 24 hours after a lapse it reads 0 while the stamp written by
	// the EXPIRED page is -1 — and `0 > -1` would read as "renewed". That
	// alternates EXPIRED page / false-recovery page once per tick for a day,
	// which is precisely the storm this exists to kill. An expired certificate
	// is never a renewed one.
	if !expired && lastWarnedDay != alertEngineSslNeverWarned && daysLeft > lastWarnedDay {
		return alertEngineSslAction{Kind: alertEngineSslResolve}
	}

	// The TIGHTEST rung crossed, not the first one listed. The old loop broke
	// on the first config entry satisfying `daysLeft <= warnDay`, so with the
	// default descending '30,14,7,3,1' it always picked 30 and the
	// `warnDay < lastWarnedDay` test then blocked every later rung — one
	// warning per certificate, ever, instead of the configured ladder.
	var warnDay int64
	if expired {
		warnDay = alertEngineSslExpiredWarnDay
	} else {
		found := false
		for _, d := range warningDays {
			if daysLeft <= d && (!found || d < warnDay) {
				warnDay, found = d, true
			}
		}
		if !found {
			return alertEngineSslAction{Kind: alertEngineSslNothing}
		}
	}

	if warnDay >= lastWarnedDay {
		return alertEngineSslAction{Kind: alertEngineSslNothing} // already paged at this rung or a tighter one
	}

	severity := "info"
	if expired || daysLeft <= 3 {
		severity = "critical"
	} else if daysLeft <= 7 {
		severity = "warning"
	}

	return alertEngineSslAction{Kind: alertEngineSslFire, WarnDay: warnDay, Severity: severity}
}

// alertEngineDaysLeft is (expiry - now): expired is decided on the SIGNED
// duration, daysLeft is chrono num_days (truncated toward zero).
func alertEngineDaysLeft(expiry, now time.Time) (int64, bool) {
	remaining := expiry.Sub(now)
	return int64(remaining / (24 * time.Hour)), remaining < 0
}

// alertEngineLastWarnedDay reads metadata.last_warned_day, else the sentinel.
func alertEngineLastWarnedDay(meta *json.RawMessage) int64 {
	if meta == nil {
		return alertEngineSslNeverWarned
	}
	v, err := agentDecodeJSON(*meta)
	if err != nil {
		return alertEngineSslNeverWarned
	}
	if d, ok := jsonI64(jsonGet(v, "last_warned_day")); ok {
		return d
	}
	return alertEngineSslNeverWarned
}

func alertEngineCheckSslExpiry(ctx context.Context, db *pgxpool.Pool, maint map[uuid.UUID]bool) {
	sites, err := queryAll[Tup4[uuid.UUID, uuid.UUID, string, time.Time]](ctx, db,
		"SELECT s.id, s.user_id, s.domain, s.ssl_expiry "+
			"FROM sites s WHERE s.ssl_enabled = TRUE AND s.ssl_expiry IS NOT NULL")
	if err != nil {
		return
	}

	now := time.Now().UTC()

	for _, s := range sites {
		siteID, userID, domain, sslExpiry := s.A, s.B, s.C, s.D
		if maint[userID] {
			continue
		}

		// Expiry is decided on the SIGNED duration, not on num_days(), which
		// truncates toward zero: a certificate that lapsed anything under 24
		// hours ago still reports daysLeft = 0. Reading expiry off that meant
		// the EXPIRED page could not fire for a full day after the cert went
		// invalid — and by then rung 1 was already consumed, so browsers
		// showed a security warning for 24 hours with no notification on any
		// channel.
		daysLeft, expired := alertEngineDaysLeft(sslExpiry, now)

		_, _, _, _, _, _, sslDaysStr := NotificationsGetThresholds(ctx, db, userID, nil)
		warningDays := alertEngineParseSslWarningDays(sslDaysStr)

		// The tightest rung this site has already been paged at. Read once per
		// site — the expired branch needs it too.
		meta, _ := queryScalarOpt[json.RawMessage](ctx, db,
			"SELECT COALESCE(metadata, '{}') FROM alert_state "+
				"WHERE site_id = $1 AND alert_type = 'ssl_expiry' AND state_key = ''", siteID)
		lastWarnedDay := alertEngineLastWarnedDay(meta)

		action := alertEngineSslDecision(daysLeft, expired, lastWarnedDay, warningDays)

		if action.Kind == alertEngineSslResolve {
			_, _ = execSQL(ctx, db,
				"UPDATE alert_state SET current_state = 'ok', last_notified_at = NULL, metadata = NULL "+
					"WHERE site_id = $1 AND alert_type = 'ssl_expiry' AND state_key = ''", siteID)

			NotificationsResolveAlert(ctx, db, userID, nil, &siteID, "ssl_expiry", "",
				"SSL certificate renewed for "+domain,
				fmt.Sprintf("The SSL certificate for %s is valid again — %d days remaining.", domain, daysLeft))
			continue
		}
		if action.Kind != alertEngineSslFire {
			continue
		}

		// Stamp the dedup key ONLY if the page actually landed. A transient DB
		// error inside fireAlertWithRetry used to still advance
		// last_warned_day, which permanently silenced the site: the stamp
		// claims the rung was paged, but no notification went out and no
		// `alerts` row exists for checkEscalations to re-page from. Skipping
		// the stamp makes the next 60s tick retry.
		if !alertEngineFireSslAlert(ctx, db, userID, siteID, domain, daysLeft, expired, action.Severity) {
			slog.Warn(fmt.Sprintf("SSL alert for %s could not be recorded; leaving the warning ladder unstamped so the next tick retries", domain))
			continue
		}

		// Update state with last_warned_day — PostgreSQL serializes concurrent ON CONFLICT upserts
		_, _ = execSQL(ctx, db,
			"INSERT INTO alert_state (site_id, alert_type, state_key, current_state, last_notified_at, metadata) "+
				"VALUES ($1, 'ssl_expiry', '', 'firing', NOW(), $2) "+
				"ON CONFLICT (site_id, alert_type, state_key) WHERE site_id IS NOT NULL "+
				"DO UPDATE SET current_state = 'firing', last_notified_at = NOW(), metadata = $2",
			siteID, alertEngineWarnMeta(action.WarnDay))
	}
}

func alertEngineWarnMeta(warnDay int64) json.RawMessage {
	b, _ := json.Marshal(map[string]int64{"last_warned_day": warnDay})
	return b
}

// alertEngineCheckStackSslExpiry is checkSslExpiry's sibling for Docker
// Compose stacks. Reuses sslDecision and parseSslWarningDays UNCHANGED — the
// ladder is a pure function of days-left / expired / last-warned-day / rungs,
// and neither cares what kind of row it is deciding for.
//
// ACME-mode only, through effective_tls_mode: a `provided` stack serves its
// certificate from the TLS registry, and a stale ssl_expiry on such a row is
// not the panel's cert to alert on — the same rule
// certificate_dashboard_for_admin and renew_stack_certificate already enforce.
//
// Keyed by (server_id, "ssl_expiry", stack_ssl_expiry_state_key(domain)).
// alert_state/alerts carry no docker_stack_id column, only server_id —
// mirroring stack_renewal_state_key's own reasoning — so the domain has to be
// IN the key or two stacks on one server would share one dedup bucket. Reuses
// alert_type = "ssl_expiry" rather than inventing a second type, so a stack's
// warning inherits the SAME alert_ssl_expiry toggle and ssl_warning_days rungs
// a site's certificate already uses — an operator configures "how many days
// before I'm warned" once, not per certificate kind.
func alertEngineCheckStackSslExpiry(ctx context.Context, db *pgxpool.Pool, maint map[uuid.UUID]bool) {
	type stackRow struct {
		ID        uuid.UUID `db:"id"`
		UserID    uuid.UUID `db:"user_id"`
		ServerID  uuid.UUID `db:"server_id"`
		Domain    string    `db:"domain"`
		SSLExpiry time.Time `db:"ssl_expiry"`
		TLSMode   *string   `db:"tls_mode"`
		SSLEmail  *string   `db:"ssl_email"`
	}
	stacks, err := queryAll[stackRow](ctx, db,
		"SELECT id, user_id, server_id, domain, ssl_expiry, tls_mode, ssl_email "+
			"FROM docker_stacks WHERE domain IS NOT NULL AND ssl_expiry IS NOT NULL")
	if err != nil {
		return
	}

	now := time.Now().UTC()

	for _, s := range stacks {
		userID, serverID, domain := s.UserID, s.ServerID, s.Domain
		if maint[userID] {
			continue
		}

		if rtStacksEffectiveTlsMode(s.TLSMode, s.SSLEmail) != "acme" {
			continue
		}

		daysLeft, expired := alertEngineDaysLeft(s.SSLExpiry, now)

		_, _, _, _, _, _, sslDaysStr := NotificationsGetThresholds(ctx, db, userID, nil)
		warningDays := alertEngineParseSslWarningDays(sslDaysStr)

		stateKey := SecurityScannerStackSslExpiryStateKey(domain)

		meta, _ := queryScalarOpt[json.RawMessage](ctx, db,
			"SELECT COALESCE(metadata, '{}') FROM alert_state "+
				"WHERE server_id = $1 AND alert_type = 'ssl_expiry' AND state_key = $2",
			serverID, stateKey)
		lastWarnedDay := alertEngineLastWarnedDay(meta)

		action := alertEngineSslDecision(daysLeft, expired, lastWarnedDay, warningDays)

		if action.Kind == alertEngineSslResolve {
			_, _ = execSQL(ctx, db,
				"UPDATE alert_state SET current_state = 'ok', last_notified_at = NULL, metadata = NULL "+
					"WHERE server_id = $1 AND alert_type = 'ssl_expiry' AND state_key = $2",
				serverID, stateKey)

			NotificationsResolveAlert(ctx, db, userID, &serverID, nil, "ssl_expiry", stateKey,
				"SSL certificate renewed for "+domain,
				fmt.Sprintf("The SSL certificate for %s is valid again — %d days remaining.", domain, daysLeft))
			continue
		}
		if action.Kind != alertEngineSslFire {
			continue
		}

		// Same unstamped-on-failure discipline as checkSslExpiry: only stamp
		// the dedup key if the page actually landed, so a transient DB error
		// retries on the next tick instead of permanently silencing the stack.
		if !alertEngineFireStackSslAlert(ctx, db, userID, serverID, stateKey, domain, daysLeft, expired, action.Severity) {
			slog.Warn(fmt.Sprintf("Stack SSL alert for %s could not be recorded; leaving the warning ladder unstamped so the next tick retries", domain))
			continue
		}

		_, _ = execSQL(ctx, db,
			"INSERT INTO alert_state (server_id, alert_type, state_key, current_state, last_notified_at, metadata) "+
				"VALUES ($1, 'ssl_expiry', $2, 'firing', NOW(), $3) "+
				"ON CONFLICT (server_id, alert_type, state_key) WHERE server_id IS NOT NULL "+
				"DO UPDATE SET current_state = 'firing', last_notified_at = NOW(), metadata = $3",
			serverID, stateKey, alertEngineWarnMeta(action.WarnDay))
	}
}

// alertEngineCheckRegisteredCertExpiry is the sibling for a REGISTERED
// (uploaded, non agent-managed) certificate in tls_certificates — the one
// population neither of the two above can see: checkSslExpiry only reads
// sites.ssl_expiry (ACME-issued, single-site certs) and checkStackSslExpiry
// deliberately SKIPS a provided-mode stack's ssl_expiry. A certificate served
// through the registry has its real expiry in tls_certificates.not_after, and
// until this nothing ever read it on a schedule; the only visibility was an
// operator opening the certificate dashboard and reading days_left themselves.
//
// Scoped to certificates a stack is ACTUALLY SERVING right now
// (docker_stacks.tls_certificate_id), not every row in the registry. An
// operator who uploaded a certificate ahead of assigning it to anything is not
// yet exposing traffic through it, so there is nothing to page about.
func alertEngineCheckRegisteredCertExpiry(ctx context.Context, db *pgxpool.Pool, maint map[uuid.UUID]bool) {
	type certRow struct {
		ID       uuid.UUID `db:"id"`
		UserID   uuid.UUID `db:"user_id"`
		ServerID uuid.UUID `db:"server_id"`
		Alias    string    `db:"alias"`
		DNSNames []string  `db:"dns_names"`
		NotAfter time.Time `db:"not_after"`
	}
	certs, err := queryAll[certRow](ctx, db,
		"SELECT DISTINCT tc.id, tc.user_id, tc.server_id, tc.alias, tc.dns_names, tc.not_after "+
			"FROM tls_certificates tc "+
			"JOIN docker_stacks ds ON ds.tls_certificate_id = tc.id "+
			"WHERE tc.not_after IS NOT NULL")
	if err != nil {
		return
	}

	now := time.Now().UTC()

	for _, c := range certs {
		userID, serverID := c.UserID, c.ServerID
		if maint[userID] {
			continue
		}

		displayName := c.Alias
		if len(c.DNSNames) > 0 {
			displayName = c.DNSNames[0]
		}

		daysLeft, expired := alertEngineDaysLeft(c.NotAfter, now)

		_, _, _, _, _, _, sslDaysStr := NotificationsGetThresholds(ctx, db, userID, nil)
		warningDays := alertEngineParseSslWarningDays(sslDaysStr)

		stateKey := SecurityScannerRegisteredCertExpiryStateKey(c.Alias)

		meta, _ := queryScalarOpt[json.RawMessage](ctx, db,
			"SELECT COALESCE(metadata, '{}') FROM alert_state "+
				"WHERE server_id = $1 AND alert_type = 'ssl_expiry' AND state_key = $2",
			serverID, stateKey)
		lastWarnedDay := alertEngineLastWarnedDay(meta)

		action := alertEngineSslDecision(daysLeft, expired, lastWarnedDay, warningDays)

		if action.Kind == alertEngineSslResolve {
			_, _ = execSQL(ctx, db,
				"UPDATE alert_state SET current_state = 'ok', last_notified_at = NULL, metadata = NULL "+
					"WHERE server_id = $1 AND alert_type = 'ssl_expiry' AND state_key = $2",
				serverID, stateKey)

			NotificationsResolveAlert(ctx, db, userID, &serverID, nil, "ssl_expiry", stateKey,
				"Registered certificate renewed for "+displayName,
				fmt.Sprintf("The registered certificate \"%s\" is valid again — %d days remaining.", displayName, daysLeft))
			continue
		}
		if action.Kind != alertEngineSslFire {
			continue
		}

		// Same unstamped-on-failure discipline as checkStackSslExpiry: only
		// stamp the dedup key if the page actually landed.
		if !alertEngineFireStackSslAlert(ctx, db, userID, serverID, stateKey, displayName, daysLeft, expired, action.Severity) {
			slog.Warn(fmt.Sprintf("Registered-certificate SSL alert for %s could not be recorded; leaving the warning ladder unstamped so the next tick retries", displayName))
			continue
		}

		_, _ = execSQL(ctx, db,
			"INSERT INTO alert_state (server_id, alert_type, state_key, current_state, last_notified_at, metadata) "+
				"VALUES ($1, 'ssl_expiry', $2, 'firing', NOW(), $3) "+
				"ON CONFLICT (server_id, alert_type, state_key) WHERE server_id IS NOT NULL "+
				"DO UPDATE SET current_state = 'firing', last_notified_at = NOW(), metadata = $3",
			serverID, stateKey, alertEngineWarnMeta(action.WarnDay))
	}
}

// alertEngineParseSslWarningDays parses alert_rules.ssl_warning_days into a
// descending, de-duplicated list of non-negative rungs. Falls back to the
// shipped default when the column is empty or entirely unparseable, so a bad
// value can't silence SSL alerting.
func alertEngineParseSslWarningDays(raw string) []int64 {
	days := []int64{}
	for _, s := range strings.Split(raw, ",") {
		// strconv.ParseInt matches str::parse::<i64> (optional sign, digits only).
		if d, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && d >= 0 {
			days = append(days, d)
		}
	}
	slices.SortFunc(days, func(a, b int64) int { return cmp.Compare(b, a) })
	days = slices.Compact(days)
	if len(days) == 0 {
		days = []int64{30, 14, 7, 3, 1}
	}
	return days
}

// alertEngineSslAlertCopy is the title + message for an SSL-expiry ladder
// page. expired is passed explicitly rather than inferred from daysLeft <= 0:
// daysLeft is truncated toward zero, so a still-valid certificate with up to
// 23 hours left also reads 0 and used to be announced as already EXPIRED.
//
// Shared by the site and stack ladders — the copy depends only on the domain
// and how much time is left, never on what kind of row is expiring.
func alertEngineSslAlertCopy(domain string, daysLeft int64, expired bool) (string, string) {
	var window string
	switch {
	case daysLeft <= 0:
		window = "less than a day"
	case daysLeft == 1:
		window = "1 day"
	default:
		window = fmt.Sprintf("%d days", daysLeft)
	}

	if expired {
		return "SSL certificate EXPIRED for " + domain,
			fmt.Sprintf("The SSL certificate for %s has expired. Visitors will see security warnings. Renew immediately.", domain)
	}
	return fmt.Sprintf("SSL certificate expires in %s for %s", window, domain),
		fmt.Sprintf("The SSL certificate for %s will expire in %s. Please renew it before it expires.", domain, window)
}

func alertEngineFireSslAlert(ctx context.Context, db *pgxpool.Pool, userID, siteID uuid.UUID, domain string, daysLeft int64, expired bool, severity string) bool {
	title, message := alertEngineSslAlertCopy(domain, daysLeft, expired)
	return alertEngineFireAlertWithRetry(ctx, db, userID, nil, &siteID, "ssl_expiry", "", severity, title, message)
}

// alertEngineFireStackSslAlert is fireSslAlert's sibling for a Compose stack.
// A stack alert has no site_id — a docker_stacks row has no sites row to point
// at — so this fires with server_id set and a domain-derived state_key instead
// of the site ladder's site_id + empty key.
func alertEngineFireStackSslAlert(ctx context.Context, db *pgxpool.Pool, userID, serverID uuid.UUID, stateKey, domain string, daysLeft int64, expired bool, severity string) bool {
	title, message := alertEngineSslAlertCopy(domain, daysLeft, expired)
	return alertEngineFireAlertWithRetry(ctx, db, userID, &serverID, nil, "ssl_expiry", stateKey, severity, title, message)
}

// ─── Service Health ─────────────────────────────────────────────────────

func alertEngineCheckServiceHealth(ctx context.Context, db *pgxpool.Pool, member *AgentFleetMember) {
	val, err := member.Agent.Get(ctx, "/services/health")
	if err != nil {
		slog.Debug(fmt.Sprintf("Service health check skipped: %v", err))
		return
	}
	services, ok := jsonArr(val)
	if !ok {
		return
	}

	serverID, userID, serverName := member.ID, member.UserID, member.Name

	for _, svc := range services {
		name, _ := jsonStr(jsonGet(svc, "name"))
		status, ok := jsonStr(jsonGet(svc, "status"))
		if !ok {
			status = "unknown"
		}

		if name == "" || status == "not_installed" || status == "disabled" {
			continue
		}

		if status == "stopped" || status == "failed" {
			// Skip alerting if auto-healer recently handled this service
			// (within 5 minutes) — ON THIS HOST. The writer of these rows has
			// stamped server_id since v2.58.0 and its own cooldown reads it
			// back, but this reader was left matching on target_name alone, so
			// a heal of `nginx` on one server silenced the service_down alert
			// for `nginx` on every other server for five minutes. Service names
			// are the least distinctive key in the fleet — every host has an
			// `nginx` — so this is the shape that goes wrong the moment a
			// second server exists.
			recentlyHealed, _ := queryScalarOpt[int64](ctx, db,
				"SELECT COUNT(*) FROM activity_logs "+
					"WHERE action = 'auto_heal.restart_service' "+
					"AND target_name = $1 AND server_id = $2 "+
					"AND created_at > NOW() - INTERVAL '5 minutes'",
				name, serverID)
			if recentlyHealed != nil && *recentlyHealed > 0 {
				slog.Debug(fmt.Sprintf("Alert engine: skipping %s alert (auto-healer recently handled it)", name))
				continue
			}

			// Check if already firing
			state, _ := queryScalarOpt[string](ctx, db,
				"SELECT current_state FROM alert_state "+
					"WHERE server_id = $1 AND alert_type = 'service_down' AND state_key = $2",
				serverID, name)

			if state == nil || *state != "firing" {
				// PostgreSQL serializes concurrent ON CONFLICT upserts
				_, _ = execSQL(ctx, db,
					"INSERT INTO alert_state (server_id, alert_type, state_key, current_state, fired_at, last_notified_at) "+
						"VALUES ($1, 'service_down', $2, 'firing', NOW(), NOW()) "+
						"ON CONFLICT (server_id, alert_type, state_key) WHERE server_id IS NOT NULL "+
						"DO UPDATE SET current_state = 'firing', fired_at = NOW(), last_notified_at = NOW()",
					serverID, name)

				alertEngineFireAlertWithRetry(ctx, db, userID, &serverID, nil, "service_down", name, "critical",
					fmt.Sprintf("Service %s is %s on %s", name, status, serverName),
					fmt.Sprintf("The %s service is %s on server %s. This may cause site downtime.", name, status, serverName))
			}
		} else if status == "running" {
			// Check if was previously firing — resolve
			state, _ := queryScalarOpt[string](ctx, db,
				"SELECT current_state FROM alert_state "+
					"WHERE server_id = $1 AND alert_type = 'service_down' AND state_key = $2",
				serverID, name)

			if state != nil && *state == "firing" {
				_, _ = execSQL(ctx, db,
					"UPDATE alert_state SET current_state = 'ok', fired_at = NULL, last_notified_at = NULL "+
						"WHERE server_id = $1 AND alert_type = 'service_down' AND state_key = $2",
					serverID, name)

				NotificationsResolveAlert(ctx, db, userID, &serverID, nil, "service_down", name,
					fmt.Sprintf("Service %s recovered on %s", name, serverName),
					fmt.Sprintf("The %s service is running again on server %s.", name, serverName))
			}
		}
	}
}

// ─── GAP 8: Docker Container Health ──────────────────────────────────────

// alertEngineFiringState reports whether alert_state reads 'firing' for key.
func alertEngineFiringState(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, alertType, stateKey string) bool {
	s, _ := queryScalarOpt[string](ctx, db,
		"SELECT current_state FROM alert_state "+
			"WHERE server_id = $1 AND alert_type = $2 AND state_key = $3",
		serverID, alertType, stateKey)
	return s != nil && *s == "firing"
}

func alertEngineCheckContainerHealth(ctx context.Context, db *pgxpool.Pool, member *AgentFleetMember) {
	// Stamped BEFORE the snapshot, because the walk below awaits a database and
	// notification round-trip per container: an expectation recorded by an
	// operator mid-walk is NEWER than this evidence and must survive it.
	observedAt := time.Now().UTC()

	val, err := member.Agent.Get(ctx, "/apps")
	if err != nil {
		slog.Debug(fmt.Sprintf("Container health check skipped: %v", err))
		return
	}
	containers, ok := jsonArr(val)
	if !ok {
		return
	}

	serverID, userID := member.ID, member.UserID

	// Containers this host is holding stopped ON PURPOSE. Loaded once per
	// member rather than queried per container, which would multiply this
	// sweep's round-trips by the app count.
	expectedStopped := ExpectedStopsExpectedOnServer(ctx, db, serverID)

	// Every container this host still reports, whatever its state. Reaching
	// this line means the agent answered with a well-formed array, so a name
	// absent from it is genuinely absent from the host — see the sweep at the
	// end of this function.
	observed := map[string]bool{}
	observedNames := []string{}
	for _, c := range containers {
		if n, ok := jsonStr(jsonGet(c, "name")); ok && !observed[n] {
			observed[n] = true
			observedNames = append(observedNames, n)
		}
	}

	for _, c := range containers {
		name, ok := jsonStr(jsonGet(c, "name"))
		if !ok {
			name = "unknown"
		}
		state, _ := jsonStr(jsonGet(c, "status"))
		health, hasHealth := jsonStr(jsonGet(c, "health"))
		unhealthy := hasHealth && health == "unhealthy"

		// ── The expectation is cleared from OBSERVATION, above the ladder ──
		//
		// Docker running this container is what falsifies "a stop is
		// expected", and that fact is independent of the healthcheck. The
		// recovery arm below is `running && health != unhealthy` and sits
		// under the unhealthy arm, so a container that comes back up with a
		// failing healthcheck — the ordinary case for something that was
		// stopped BECAUSE it was misbehaving — would never reach it, keep its
		// expectation for ever, and be suppressed when it finally died.
		// `restarting`, `paused` and `created` have no arm at all. So the clear
		// is keyed on the one thing that matters: this container is not
		// stopped.
		if state != "exited" && state != "dead" && expectedStopped[name] {
			ExpectedStopsClearIfOlderThan(ctx, db, serverID, name, observedAt)
		}

		switch {
		case state == "exited" || state == "dead":
			// ⛔ A stop the panel carried out is not an outage. Skipping the
			// WHOLE branch — not just the fire — is deliberate: the
			// alert_state row is written 'firing' immediately above the fire,
			// and the branch is guarded by `!= firing`, so stamping the row
			// while sending nothing would leave this container claiming it had
			// paged and silently suppress every future container_down for that
			// name. A live instance of exactly that tombstone (see the stale
			// sweep below) was still firing four months later.
			if expectedStopped[name] {
				continue
			}

			if !alertEngineFiringState(ctx, db, serverID, "container_down", name) {
				_, _ = execSQL(ctx, db,
					"INSERT INTO alert_state (server_id, alert_type, state_key, current_state, fired_at, last_notified_at) "+
						"VALUES ($1, 'container_down', $2, 'firing', NOW(), NOW()) "+
						"ON CONFLICT (server_id, alert_type, state_key) WHERE server_id IS NOT NULL "+
						"DO UPDATE SET current_state = 'firing', fired_at = NOW(), last_notified_at = NOW()",
					serverID, name)

				alertEngineFireAlertWithRetry(ctx, db, userID, &serverID, nil, "container_down", name,
					// The severity this product DECLARES for this alert: the
					// runbook defaults list container_down under "Info", and the
					// runbook attached to every one of these notifications says
					// a planned `docker stop` is normal operational use, so we
					// don't page on it, and "Don't page on this alone". It was
					// raised at "critical", which is the string the incident
					// branch gates on — so a container going down opened a
					// CRITICAL incident on the operator's public status page,
					// contradicting the runbook in the same email.
					"info",
					fmt.Sprintf("Container '%s' is %s", name, state),
					fmt.Sprintf("Docker container '%s' has stopped (state: %s). It may need to be restarted.", name, state))
			}
		case state == "restarting":
			// Container in restart loop
			if !alertEngineFiringState(ctx, db, serverID, "container_crashloop", name) {
				_, _ = execSQL(ctx, db,
					"INSERT INTO alert_state (server_id, alert_type, state_key, current_state, fired_at, last_notified_at) "+
						"VALUES ($1, 'container_crashloop', $2, 'firing', NOW(), NOW()) "+
						"ON CONFLICT (server_id, alert_type, state_key) WHERE server_id IS NOT NULL "+
						"DO UPDATE SET current_state = 'firing', fired_at = NOW(), last_notified_at = NOW()",
					serverID, name)

				alertEngineFireAlertWithRetry(ctx, db, userID, &serverID, nil, "container_crashloop", name, "critical",
					fmt.Sprintf("Container '%s' is crash-looping", name),
					fmt.Sprintf("Docker container '%s' is in a restart loop (state: restarting), indicating repeated crashes.", name))
			}
		case unhealthy:
			// Container running but health check failing
			if !alertEngineFiringState(ctx, db, serverID, "container_unhealthy", name) {
				_, _ = execSQL(ctx, db,
					"INSERT INTO alert_state (server_id, alert_type, state_key, current_state, fired_at, last_notified_at) "+
						"VALUES ($1, 'container_unhealthy', $2, 'firing', NOW(), NOW()) "+
						"ON CONFLICT (server_id, alert_type, state_key) WHERE server_id IS NOT NULL "+
						"DO UPDATE SET current_state = 'firing', fired_at = NOW(), last_notified_at = NOW()",
					serverID, name)

				alertEngineFireAlertWithRetry(ctx, db, userID, &serverID, nil, "container_unhealthy", name, "warning",
					fmt.Sprintf("Container '%s' is unhealthy", name),
					fmt.Sprintf("Docker container '%s' health check is failing.", name))
			}
		case state == "running" && !unhealthy:
			// Container is healthy — resolve any previous container alerts
			for _, alertType := range []string{"container_down", "container_unhealthy", "container_crashloop"} {
				if alertEngineFiringState(ctx, db, serverID, alertType, name) {
					_, _ = execSQL(ctx, db,
						"UPDATE alert_state SET current_state = 'ok', fired_at = NULL, last_notified_at = NULL "+
							"WHERE server_id = $1 AND alert_type = $2 AND state_key = $3",
						serverID, alertType, name)

					NotificationsResolveAlert(ctx, db, userID, &serverID, nil, alertType, name,
						fmt.Sprintf("Container '%s' recovered", name),
						fmt.Sprintf("Docker container '%s' is running and healthy again.", name))
				}
			}
		}
	}

	// A REMOVED container never appears in /apps again, so neither the fire
	// branches nor the recovered branch above can ever run for it and its row
	// stays `firing` for ever. Not theoretical: this panel carried a
	// container_down row for a container deleted on 2026-03-23, still `firing`
	// four months later, with ZERO matching `alerts` rows ever written —
	// because the fire branches skip a key that already reads `firing`, that
	// one row had silently suppressed every future alert for that container
	// name. Retention cannot clear it either; both purges only delete
	// status = 'resolved'.
	//
	// Threading this check makes the sweep both possible and necessary: the
	// subject is now "the containers THIS member reports", so absence from
	// that list is a fact about one host rather than about the whole fleet.
	stale, _ := queryAll[Tup2[string, string]](ctx, db,
		"SELECT alert_type, state_key FROM alert_state "+
			"WHERE server_id = $1 AND current_state = 'firing' "+
			"AND alert_type IN ('container_down', 'container_unhealthy', 'container_crashloop')",
		serverID)

	for _, s := range stale {
		alertType, stateKey := s.A, s.B
		if observed[stateKey] {
			continue
		}

		_, _ = execSQL(ctx, db,
			"UPDATE alert_state SET current_state = 'ok', fired_at = NULL, last_notified_at = NULL "+
				"WHERE server_id = $1 AND alert_type = $2 AND state_key = $3",
			serverID, alertType, stateKey)

		NotificationsResolveAlert(ctx, db, userID, &serverID, nil, alertType, stateKey,
			fmt.Sprintf("Container '%s' is no longer present", stateKey),
			fmt.Sprintf("Docker container '%s' is no longer reported by %s. Its alert state has been "+
				"cleared so a container of that name can raise an alert again.", stateKey, member.Name))

		slog.Info(fmt.Sprintf("Alert engine: cleared stale %s state for absent container %s on %s", alertType, stateKey, member.Name))
	}

	// The same absence, one table over — and it had no sweep at all.
	//
	// The clear above the ladder runs from OBSERVING a container alive, so a
	// REMOVED container never reaches it: its expectation row outlives it, and
	// the next container to claim that name inherits the silence. Removing an
	// app and redeploying it under the same name is the supported way to
	// rebuild one while keeping its data, so the container that inherits it is
	// the one the operator has just been trying to repair — and if it fails to
	// start, this engine skips its container_down, the auto-heal restart leg
	// skips it, and the Apps page files it under "stopped on purpose", naming
	// whoever stopped the container that no longer exists.
	//
	// The removal doors clear their own row, which is exact and has no window.
	// This sweep is what covers a removal the panel did not perform — `docker
	// rm` on the box — and any door added later.
	ExpectedStopsClearAbsent(ctx, db, serverID, observedNames, observedAt)
}

// ─── GAP 9: Alert Escalation ────────────────────────────────────────────

type alertEngineEscalationKind int

const (
	// alertEngineEscSkip: not eligible this tick, and its sort position must not move.
	alertEngineEscSkip alertEngineEscalationKind = iota
	// alertEngineEscTerminal: nothing to page, but stamp it so it rotates to
	// the back of the window.
	alertEngineEscTerminal
	// alertEngineEscAdvance: page step Index and record it as the chain's new position.
	alertEngineEscAdvance
	// alertEngineEscRepeatLast: the chain is spent — page its last step
	// again, leaving the position.
	alertEngineEscRepeatLast
)

// alertEngineEscalationAction is what a policy-driven row should do on this
// tick.
//
// Extracted as a pure function for the same reason sslDecision is: the loop
// that used to hold this inline needed a live pool, a live policy and a firing
// alert to exercise, so nothing exercised it, and the branch that decided an
// exhausted chain should fall silent for ever was never once run in a test.
// The arithmetic is the whole behaviour; keep it reachable.
type alertEngineEscalationAction struct {
	Kind  alertEngineEscalationKind
	Index int
}

// alertEngineEscalationDecision: after is each step's after_minutes, in chain
// order. sinceEscalated is minutes since this row was last paged, nil if it
// never has been.
func alertEngineEscalationDecision(after []int64, currentIndex int, elapsedMinutes int64, sinceEscalated *int64) alertEngineEscalationAction {
	if len(after) == 0 {
		return alertEngineEscalationAction{Kind: alertEngineEscTerminal}
	}

	// Highest step past the current position whose threshold has been
	// crossed. Walking from the end jumps straight to the furthest-eligible
	// rung rather than creeping one rung per tick.
	for i := len(after) - 1; i >= 0; i-- {
		if i <= currentIndex {
			break
		}
		if after[i] <= elapsedMinutes {
			return alertEngineEscalationAction{Kind: alertEngineEscAdvance, Index: i}
		}
	}

	// Spent. It must not go quiet — that made a policy strictly worse than no
	// policy at all — so it drops onto the cadence an unattached rule gets.
	// Skip, not Terminal: a spent chain is no longer terminal for anything, so
	// stamping it here would only push its own clock forward and delay the
	// first fallback page past the fifteen minutes the cadence promises. It
	// cannot starve the sweep window either — a row this young sorts to the
	// back of the least-recently-paged ordering by its created_at alone.
	if elapsedMinutes < 15 {
		return alertEngineEscalationAction{Kind: alertEngineEscSkip}
	}
	if sinceEscalated != nil && *sinceEscalated < 30 {
		return alertEngineEscalationAction{Kind: alertEngineEscSkip}
	}
	return alertEngineEscalationAction{Kind: alertEngineEscRepeatLast}
}

// alertEngineEscalationSweepLimit bounds the sweep. The query used to be
// unbounded, and every row cost 3-5 DB round-trips per 60s tick (policy lookup
// + runbook + base URL) *before* any eligibility check — so a pile-up of
// never-resolving firing rows turned the escalation pass into
// self-amplifying load on the shared pool.
//
// Ordered least-recently-paged first, NOT newest-first. Any fixed window over
// a sorted-by-age list can starve: newest-first drops an old unacknowledged
// critical out of the window once enough newer rows exist, and oldest-first
// does the reverse. COALESCE(escalated_at, created_at) makes it a fair
// rotation instead — paging a row stamps escalated_at, which sends it to the
// back, so every eligible row is serviced in turn and none can be crowded out
// indefinitely. Rows never paged sort by age, and a brand-new row is not
// eligible for 15 minutes anyway, by which point it competes on equal terms.
const alertEngineEscalationSweepLimit int64 = 500

// alertEngineCheckEscalations re-notifies for unacknowledged firing alerts.
//
// Phase 4 W3: two paths.
//
//   - When the owning alert_rules row has escalation_policy_id IS NULL, the
//     pre-W3 behaviour is preserved exactly: re-page every 30 min for alerts
//     older than 15 min. The W3 ship also folds in the W2 runbook payload here
//     — bare send_notification was leaving the runbook excerpt + URL out of
//     escalation pages even though try_fire_alert carried them on the
//     original fire.
//
//   - When escalation_policy_id IS NOT NULL, the policy chain drives
//     (after_minutes, route) steps. Each minute we advance to the highest step
//     whose after_minutes <= alert age AND whose index is strictly greater
//     than alerts.escalation_step_index. Once the last step has fired the
//     chain stays exhausted, but the alert does NOT go quiet: it drops onto
//     the same 30-minute cadence an unattached rule gets, paging the last
//     rung's route until it is acknowledged or resolved.
//
//     That fallback is the whole point. Terminating for good made attaching a
//     policy strictly worse than attaching none — and the policy editor seeded
//     one step by default, so the ordinary outcome of building a policy was a
//     single page on a firing critical and then silence. The operator-facing
//     documentation has always promised a repeating cadence for every alert;
//     this is the path that makes that true.
func alertEngineCheckEscalations(ctx context.Context, db *pgxpool.Pool) {
	type escalationRow struct {
		ID                  uuid.UUID  `db:"id"`
		UserID              uuid.UUID  `db:"user_id"`
		ServerID            *uuid.UUID `db:"server_id"`
		AlertType           string     `db:"alert_type"`
		Severity            string     `db:"severity"`
		Title               string     `db:"title"`
		Message             string     `db:"message"`
		CreatedAt           time.Time  `db:"created_at"`
		EscalationStepIndex int32      `db:"escalation_step_index"`
		EscalatedAt         *time.Time `db:"escalated_at"`
	}

	rows, err := queryAll[escalationRow](ctx, db,
		"SELECT id, user_id, server_id, alert_type, severity, title, message, "+
			"created_at, escalation_step_index, escalated_at "+
			"FROM alerts "+
			"WHERE status = 'firing' AND acknowledged_at IS NULL "+
			"AND created_at > NOW() - INTERVAL '7 days' "+
			"ORDER BY COALESCE(escalated_at, created_at) ASC "+
			"LIMIT $1", alertEngineEscalationSweepLimit)
	if err != nil {
		slog.Debug(fmt.Sprintf("Escalation query skipped: %v", err))
		return
	}

	if int64(len(rows)) == alertEngineEscalationSweepLimit {
		slog.Warn(fmt.Sprintf("Escalation sweep hit its %d-row cap — older unacknowledged "+
			"alerts were not considered this tick; acknowledge or resolve the backlog", alertEngineEscalationSweepLimit))
	}

	now := time.Now().UTC()

	// Per-tick memoization. Firing alerts cluster hard on a few users, servers
	// and alert types, so these turn O(rows) queries into O(distinct keys).
	type ownerKey struct {
		user, server uuid.UUID
		hasServer    bool
	}
	keyOf := func(u uuid.UUID, s *uuid.UUID) ownerKey {
		if s == nil {
			return ownerKey{user: u}
		}
		return ownerKey{u, *s, true}
	}
	type enabledKey struct {
		owner     ownerKey
		alertType string
	}
	policyCache := map[ownerKey]*uuid.UUID{}
	stepsCache := map[uuid.UUID][]EscalationStep{}
	type runbookPayload struct{ excerpt, url *string }
	runbookCache := map[string]runbookPayload{}
	// Same shape, for the per-type disable switch.
	enabledCache := map[enabledKey]bool{}

	// Rows the policy branch declines to page because the chain is exhausted
	// (or the policy has no steps). They can never page again, but they keep
	// the oldest sort key, so under the least-recently-paged ordering they
	// would pin the head of the window forever and crowd out live alerts.
	// Stamped in one batch below so they rotate to the back. Only the POLICY
	// branch may do this: the NULL-policy branch reads escalated_at for its
	// 30-minute re-page rule, so stamping a not-yet-eligible row there would
	// delay its first page.
	terminalIDs := []uuid.UUID{}

	for i := range rows {
		row := &rows[i]
		owner := keyOf(row.UserID, row.ServerID)

		// The operator can switch an alert type off. Until now that switch had
		// exactly ONE caller — inside try_fire_alert — so it governed only
		// whether a row was ever RECORDED, and said nothing about a row already
		// firing when the switch was flipped. This sweep selects on
		// status = 'firing' alone and is provenance-blind, so the one control
		// meaning "do not tell me about this" left the alert re-paging every
		// thirty minutes until it aged out of the seven-day window above.
		//
		// ⚠ Skipped WITHOUT stamping escalated_at. Stamping would rotate the
		// row to the back of the least-recently-paged ordering — which is what
		// terminalIDs exists for — but escalated_at means *this row was paged
		// at this time*, and writing it for a page that was never sent is
		// exactly the harm maintenanceUsers documents: a stamp claiming the
		// operator was told. A re-enabled type pages on the NEXT tick, not
		// thirty minutes after one.
		//
		// ⚠ Scope: is_alert_enabled returns true for any type it has no column
		// for, so this narrows paging for the mapped types ONLY. Every other
		// type escalates exactly as before.
		ek := enabledKey{owner, row.AlertType}
		enabled, ok := enabledCache[ek]
		if !ok {
			enabled = NotificationsIsAlertEnabled(ctx, db, row.UserID, row.ServerID, row.AlertType)
			enabledCache[ek] = enabled
		}
		if !enabled {
			slog.Debug(fmt.Sprintf("Alert type '%s' is switched off for this owner — skipping escalation for alert %s", row.AlertType, row.ID))
			continue
		}

		policyID, ok := policyCache[owner]
		if !ok {
			policyID = NotificationsGetUserPolicyID(ctx, db, row.UserID, row.ServerID)
			policyCache[owner] = policyID
		}

		// Decide first, work second: everything below this (runbook load, HTML
		// build, dispatch) is skipped for rows that don't page this tick.
		var step EscalationStep
		nextIndex := -1 // -1 = Rust None
		if policyID == nil {
			// Pre-W3 default cadence: 15 min unack threshold, 30 min re-page.
			if now.Sub(row.CreatedAt) < 15*time.Minute {
				continue
			}
			if row.EscalatedAt != nil && now.Sub(*row.EscalatedAt) < 30*time.Minute {
				continue
			}

			// Fan out via the alert owner's channels — same audience as
			// try_fire_alert's NULL-policy path. dispatch_escalation_step
			// handles per-user mute checks and (W2 repair) carries the runbook
			// payload.
			step = EscalationStep{AfterMinutes: 0, Route: "all_channels"}
		} else {
			pid := *policyID
			steps, ok := stepsCache[pid]
			if !ok {
				steps = NotificationsLoadEscalationSteps(ctx, db, pid)
				stepsCache[pid] = steps
			}
			if len(steps) == 0 {
				slog.Warn(fmt.Sprintf("Alert %s references escalation_policy %s with empty steps; skipping", row.ID, pid))
				terminalIDs = append(terminalIDs, row.ID)
				continue
			}

			elapsedMinutes := int64(now.Sub(row.CreatedAt) / time.Minute)
			// `as usize` on a negative i32 wraps huge, which never advances.
			currentIndex := int(row.EscalationStepIndex)
			if currentIndex < 0 {
				currentIndex = math.MaxInt
			}
			after := make([]int64, len(steps))
			for j, s := range steps {
				after[j] = int64(s.AfterMinutes)
			}
			var sinceEscalated *int64
			if row.EscalatedAt != nil {
				m := int64(now.Sub(*row.EscalatedAt) / time.Minute)
				sinceEscalated = &m
			}

			switch d := alertEngineEscalationDecision(after, currentIndex, elapsedMinutes, sinceEscalated); d.Kind {
			case alertEngineEscAdvance:
				step, nextIndex = steps[d.Index], d.Index
			case alertEngineEscRepeatLast:
				// The chain is spent. It used to stop here for good, which made
				// attaching a policy strictly worse than attaching none: an
				// unattached rule re-pages an unacknowledged alert every 30
				// minutes for as long as the sweep can still see it, and the
				// shipped operator documentation promises exactly that, without
				// qualification, for every alert. A policy built to be paged
				// HARDER cannot be the thing that stops paging you — and the
				// editor seeds a single-step policy, so the ordinary outcome was
				// one page and then silence.
				//
				// The LAST rung's route, not the default fan-out: those are the
				// destinations the operator chose for the worst case, and this
				// is the worst case. The index stays put, so the chain stays
				// spent and only the clock advances.
				step = steps[len(steps)-1]
			case alertEngineEscTerminal:
				terminalIDs = append(terminalIDs, row.ID)
				continue
			default: // Skip
				continue
			}
		}

		rb, ok := runbookCache[row.AlertType]
		if !ok {
			e, u := NotificationsLoadRunbookPayload(ctx, db, row.AlertType)
			rb = runbookPayload{e, u}
			runbookCache[row.AlertType] = rb
		}

		// Single-sourced with try_fire_alert's own initial-page HTML
		// (severity_color) so an escalated warning does not read as an
		// escalated critical — the row's OWN stored severity, not a hardcoded
		// red for every re-page.
		escColor := NotificationsSeverityColor(row.Severity)
		escSubject := "[ESCALATED] " + row.Title
		html := fmt.Sprintf("<div style=\"font-family:sans-serif;max-width:600px;margin:0 auto\">"+
			"<h2 style=\"color:%[1]s\">[ESCALATED] %[2]s</h2>"+
			"<p>%[3]s</p>"+
			"<p style=\"color:%[1]s;font-weight:bold\">This alert has not been acknowledged. Please investigate immediately.</p>"+
			"<p style=\"color:#6b7280;font-size:14px\">Time: %[4]s</p>"+
			"</div>",
			escColor, row.Title, row.Message, now.Format("2006-01-02 15:04:05 UTC"))

		NotificationsDispatchEscalationStep(ctx, db, row.UserID, row.ServerID, row.AlertType, &step,
			escSubject, row.Message, html, row.Severity, rb.excerpt, rb.url)

		if nextIndex < 0 {
			_, _ = execSQL(ctx, db, "UPDATE alerts SET escalated_at = $1 WHERE id = $2", now, row.ID)
			slog.Info("Escalated unacknowledged alert (default cadence): " + row.Title)
		} else {
			_, _ = execSQL(ctx, db,
				"UPDATE alerts SET escalation_step_index = $1, escalated_at = $2 WHERE id = $3",
				int32(nextIndex), now, row.ID)
			slog.Info(fmt.Sprintf("Escalated alert (policy step %d): %s", nextIndex, row.Title))
		}
	}

	// One statement, not one per row — these are precisely the rows we did
	// NOT want to spend per-row work on. Marking them "considered" moves them
	// off the head of the least-recently-paged ordering so a pile of exhausted
	// policy alerts (a cron failing every 5 minutes, say — nothing resolves
	// those) cannot fill the window and starve a fresh critical out of it.
	if len(terminalIDs) > 0 {
		_, _ = execSQL(ctx, db, "UPDATE alerts SET escalated_at = $1 WHERE id = ANY($2)", now, terminalIDs)
	}
}
