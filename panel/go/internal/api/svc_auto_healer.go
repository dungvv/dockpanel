package api

// Port of panel/backend/src/services/auto_healer.rs.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AutoHealerSslRenewalsSuccess is the cumulative count of auto-healer SSL
// renewal attempts that succeeded, published by the Prometheus exporter as
// dockpanel_cert_renewals_total{result="success"}. In-process (resets across
// restart — Prometheus increase() handles the reset).
var AutoHealerSslRenewalsSuccess atomic.Uint64

// AutoHealerSslRenewalsFailure: {result="failure"}.
var AutoHealerSslRenewalsFailure atomic.Uint64

// autoHealerRFC3339 is chrono's to_rfc3339 (+00:00, fraction only when set).
func autoHealerRFC3339(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.999999999-07:00")
}

// AutoHealerRun is the background task: auto-heals common issues when
// detected. Runs every 120 seconds (offset from alert engine to spread load).
//
// Takes the fleet registry and NOT the panel's local AgentClient,
// deliberately. Every leg of this loop reads rows that name a host and then
// writes through an agent, so there is no legitimate reason for it to hold a
// handle to this box in particular. Until v2.80.0 it held both, and the two
// legs given the local client were the two that acted on the wrong machine.
func AutoHealerRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	slog.Info("Auto-healer started")

	// Initial delay (90s offset from alert engine's 30s, respects shutdown).
	if !securityScannerSleep(ctx, 90*time.Second) {
		slog.Info("Auto-healer shutting down gracefully (during initial delay)")
		return
	}

	// Track when we last ran retention cleanup (once per day).
	var lastRetention time.Time // zero: due on the first tick

	ticker := time.NewTicker(120 * time.Second)
	defer ticker.Stop()
	first := true
	for {
		// tokio interval: the first tick fires immediately.
		if !first {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				slog.Info("Auto-healer shutting down gracefully")
				return
			}
		}
		first = false

		// Data retention cleanup runs daily regardless of auto-heal setting.
		if lastRetention.IsZero() || time.Since(lastRetention) >= 86400*time.Second {
			autoHealerRunRetentionCleanup(ctx, db)
			lastRetention = time.Now()
		}

		// Only run auto-healing if enabled globally.
		if autoHealerIsEnabled(ctx, db) {
			autoHealerAutoRestartServices(ctx, db, agents)
			autoHealerAutoCleanDisk(ctx, db, agents)
			autoHealerAutoRenewSsl(ctx, db, agents)
			autoHealerAutoSleepIdleContainers(ctx, db, agents)
		}

		// Security hardening tasks share the healer's 2-minute tick but NOT
		// its switch: auto_heal_enabled names auto-healing, and until v2.46.0
		// turning it off also silently stopped suspicious-event ingestion,
		// auto-lockdown expiry and canary monitoring.
		autoHealerSecurityIngestSuspiciousEvents(ctx, db)
		autoHealerSecurityCheckLockdownExpiry(ctx, db)
		if SecurityHardeningGetSettingBool(ctx, db, "security_canary_enabled", true) {
			autoHealerSecurityCheckCanaryFiles(ctx, db)
		}
	}
}

// autoHealerIsEnabled: is auto-healing enabled in settings?
func autoHealerIsEnabled(ctx context.Context, db *pgxpool.Pool) bool {
	v, _ := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = 'auto_heal_enabled'")
	return v != nil && *v == "true"
}

type autoHealerAlertHostRow struct {
	ServerID   uuid.UUID `db:"server_id"`
	StateKey   string    `db:"state_key"`
	UserID     uuid.UUID `db:"user_id"`
	ServerName string    `db:"name"`
}

// autoHealerAutoRestartServices restarts crashed services and containers —
// on the host they crashed on.
//
// Every read here used to be fleet-blind and the restart always went to the
// panel's own agent; the alert engine mislabelled rows the same way, so the
// two bugs cancelled. **Two bugs that cancel are two bugs.** Now:
//   - Each firing service is healed on its own agent (ForServer), driven by a
//     JOIN that carries the server the row already names.
//   - The cooldown is real, and per server. It counted activity_logs rows
//     written with the nil uuid, which violates fk_activity_logs_user, so the
//     count was always 0 and a crash-looping service was restarted every 120s
//     for ever. ⚠ This ARMS the exhaustion path: 3 failed restarts in 30
//     minutes opens a managed incident and stops healing until it recovers.
//   - Recovery is scoped too, to the server it actually recovered on.
func autoHealerAutoRestartServices(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	// Recovery check: if an exhausted service is now running, clear the state.
	exhaustedRows, _ := queryAll[autoHealerAlertHostRow](ctx, db,
		"SELECT a.server_id, a.state_key, s.user_id, s.name "+
			"FROM alert_state a JOIN servers s ON s.id = a.server_id "+
			"WHERE a.alert_type = 'service_down' AND a.current_state = 'exhausted' "+
			"AND a.server_id IS NOT NULL")

	// Group by host so /services/health is asked once per machine.
	type group struct {
		ownerID    uuid.UUID
		serverName string
		services   []string
	}
	byServer := map[uuid.UUID]*group{}
	var order []uuid.UUID
	for _, r := range exhaustedRows {
		g, ok := byServer[r.ServerID]
		if !ok {
			g = &group{ownerID: r.UserID, serverName: r.ServerName}
			byServer[r.ServerID] = g
			order = append(order, r.ServerID)
		}
		g.services = append(g.services, r.StateKey)
	}

	for _, serverID := range order {
		g := byServer[serverID]
		agent, err := agents.ForServer(ctx, serverID)
		if err != nil {
			slog.Debug(fmt.Sprintf("Auto-healer: no agent for %s (%s): %v", g.serverName, serverID, err))
			continue
		}
		health, err := agent.Get(ctx, "/services/health")
		if err != nil {
			continue
		}
		services, ok := jsonArr(health)
		if !ok {
			continue
		}
		for _, serviceName := range g.services {
			running := false
			for _, svc := range services {
				n, _ := jsonStr(jsonGet(svc, "name"))
				s, _ := jsonStr(jsonGet(svc, "status"))
				if n == serviceName && s == "running" {
					running = true
					break
				}
			}
			if !running {
				continue
			}
			// Service recovered! Clear exhausted state.
			_, _ = execSQL(ctx, db,
				"DELETE FROM alert_state WHERE server_id = $1 AND alert_type = 'service_down' AND state_key = $2 AND current_state = 'exhausted'",
				serverID, serviceName)
			slog.Info(fmt.Sprintf("Auto-healer: %s recovered on %s, cleared exhausted state", serviceName, g.serverName))

			// Resolve the incident the alert engine opened for THIS service on
			// THIS box, matched by its exact generated title and scoped to the
			// owner. It used to be `title LIKE '%<service>%'` with no user_id,
			// silently resolving tenant incidents mid-outage.
			_, _ = execSQL(ctx, db,
				"UPDATE managed_incidents SET status = 'resolved', updated_at = NOW() "+
					"WHERE user_id = $1 AND title IN ($2, $3) "+
					"AND status NOT IN ('resolved', 'postmortem')",
				g.ownerID,
				fmt.Sprintf("Service %s is stopped on %s", serviceName, g.serverName),
				fmt.Sprintf("Service %s is failed on %s", serviceName, g.serverName))

			NotificationsNotifyPanel(ctx, db, nil, "Service recovered: "+serviceName,
				fmt.Sprintf("%s is running again on %s after auto-healer exhaustion. Monitoring resumed.", serviceName, g.serverName),
				"info", "auto_heal", new("/incidents"))

			SystemLogLogEvent(ctx, db, "info", "auto_healer",
				serviceName+" recovered from exhausted state, monitoring resumed", nil)
		}
	}

	// Firing service_down alerts, each carrying the server it fired on. The
	// row is the authority on the host.
	firing, err := queryAll[autoHealerAlertHostRow](ctx, db,
		"SELECT a.server_id, a.state_key, s.user_id, s.name "+
			"FROM alert_state a JOIN servers s ON s.id = a.server_id "+
			"WHERE a.alert_type = 'service_down' AND a.current_state = 'firing' "+
			"AND a.state_key != '' AND a.server_id IS NOT NULL")
	if err != nil {
		return
	}

	for _, row := range firing {
		serverID, serviceName, userID, serverName := row.ServerID, row.StateKey, row.UserID, row.ServerName
		if serviceName == "" {
			continue
		}
		agent, err := agents.ForServer(ctx, serverID)
		if err != nil {
			slog.Debug(fmt.Sprintf("Auto-healer: no agent for %s (%s): %v", serverName, serverID, err))
			continue
		}

		// GAP 12: give up after 3 attempts in 30 minutes. Scoped to this
		// server: a crash loop on one box must not exhaust healing for a
		// healthy namesake on another.
		restartCount, _ := queryScalar[int64](ctx, db,
			"SELECT COUNT(*) FROM activity_logs "+
				"WHERE action = 'auto_heal.restart_service' "+
				"AND target_name = $1 AND server_id = $2 "+
				"AND created_at > NOW() - INTERVAL '30 minutes'", serviceName, serverID)

		if restartCount >= 3 {
			slog.Warn(fmt.Sprintf("Auto-healer gave up on %s after 3 restarts in 30 minutes", serviceName))

			// The owner and name come from the row's own server — it used to
			// be the oldest servers row, so a member's crash loop opened an
			// incident naming the panel, on the panel owner's status page.
			incidentTitle := fmt.Sprintf("Auto-healer exhausted: %s keeps crashing on %s", serviceName, serverName)
			incidentMsg := fmt.Sprintf("%s has been restarted 3 times in 30 minutes on %s without recovering. Manual intervention required.",
				serviceName, serverName)

			_, _ = execSQL(ctx, db,
				"INSERT INTO managed_incidents (user_id, title, status, severity, description, visible_on_status_page) "+
					"VALUES ($1, $2, 'investigating', 'critical', $3, TRUE)",
				userID, incidentTitle, incidentMsg)

			if channels := NotificationsGetUserChannels(ctx, db, userID, nil); channels != nil {
				subject := "[CRITICAL] Auto-healer gave up on " + serviceName
				html := fmt.Sprintf("<div style=\"font-family:sans-serif;max-width:600px;margin:0 auto\">"+
					"<h2 style=\"color:#ef4444\">%s</h2>"+
					"<p>%s</p>"+
					"<p style=\"color:#ef4444;font-weight:bold\">Automatic restarts have been exhausted. Manual intervention is required.</p>"+
					"<p style=\"color:#6b7280;font-size:14px\">Time: %s</p>"+
					"</div>", subject, incidentMsg, time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
				NotificationsSendNotification(ctx, db, channels, subject, incidentMsg, html)
			}

			NotificationsNotifyPanel(ctx, db, nil, "Auto-healer exhausted: "+serviceName,
				serviceName+" keeps crashing after 3 restart attempts. Manual intervention required.",
				"critical", "auto_heal", new("/incidents"))

			SystemLogLogEvent(ctx, db, "error", "auto_healer",
				fmt.Sprintf("Gave up on %s: 3 restarts in 30 minutes without recovery", serviceName), new(incidentMsg))

			// Clear the firing state so we don't keep trying — on THIS server
			// only. Unscoped, giving up on a member's nginx also stopped the
			// panel's own nginx from ever being healed again.
			_, _ = execSQL(ctx, db,
				"UPDATE alert_state SET current_state = 'exhausted' "+
					"WHERE server_id = $1 AND alert_type = 'service_down' AND state_key = $2 AND current_state = 'firing'",
				serverID, serviceName)
			continue
		}

		// 10-minute cooldown between attempts.
		recentHeal, _ := queryScalarOpt[int64](ctx, db,
			"SELECT COUNT(*) FROM activity_logs "+
				"WHERE action = 'auto_heal.restart_service' "+
				"AND target_name = $1 AND server_id = $2 "+
				"AND created_at > NOW() - INTERVAL '10 minutes'", serviceName, serverID)
		if recentHeal != nil && *recentHeal > 0 {
			slog.Debug(fmt.Sprintf("Auto-heal: skipping %s (recently attempted)", serviceName))
			continue
		}

		slog.Info(fmt.Sprintf("Auto-heal: restarting service %s on %s (attempt %d of 3 in 30m window)", serviceName, serverName, restartCount+1))

		result, rerr := agent.Post(ctx, "/diagnostics/fix", map[string]any{"fix_id": "restart-service:" + serviceName})
		success := rerr == nil
		details := ""
		if success {
			details = securityScannerJSONString(result)
		} else {
			details = rerr.Error()
			SystemLogLogEvent(ctx, db, "error", "auto_healer", "Failed to restart service: "+serviceName, new(details))
		}

		// Written against the server's OWNER, not the nil uuid, and stamped
		// with the server. This row IS the cooldown gate read above.
		ActivityLogActivityOnServer(ctx, db, userID, "auto-healer", "auto_heal.restart_service",
			new("service"), new(serviceName),
			new(fmt.Sprintf("server=%s success=%t, result=%s", serverName, success, details)),
			nil, new(serverID), nil)

		// If the restart succeeded, update alert_state to ok and resolve
		// firing alerts so the alert engine doesn't re-fire before its next
		// health check confirms recovery.
		if success {
			_, _ = execSQL(ctx, db,
				"UPDATE alert_state SET current_state = 'ok', fired_at = NULL, last_notified_at = NULL "+
					"WHERE server_id = $1 AND alert_type = 'service_down' AND state_key = $2 AND current_state = 'firing'",
				serverID, serviceName)
			NotificationsResolveAlert(ctx, db, userID, new(serverID), nil, "service_down", serviceName,
				fmt.Sprintf("Service %s auto-healed on %s", serviceName, serverName),
				fmt.Sprintf("The %s service was automatically restarted by auto-healer on server %s.", serviceName, serverName))
			slog.Info(fmt.Sprintf("Auto-heal: service %s restarted successfully on %s, alert resolved", serviceName, serverName))
		}
	}

	// Auto-restart exited/dead Docker containers, on every online server.
	//
	// ⚠ This block had never run once: the agent's /apps entries carry
	// `status` and `container_id`; this asked for `state` and `id`, and a
	// missing JSON field reads as an empty string.
	for _, member := range agents.OnlineFleet(ctx) {
		containers, err := member.Agent.Get(ctx, "/apps")
		if err != nil {
			continue
		}
		arr, ok := jsonArr(containers)
		if !ok {
			continue
		}

		// A container the panel stopped on purpose is not something to heal —
		// otherwise the operator's deliberate Stop is undone within 120s,
		// SILENTLY. It is also the half that makes auto-sleep work at all.
		expectedStopped := ExpectedStopsExpectedOnServer(ctx, db, member.ID)

		for _, c := range arr {
			name := securityScannerStrOr(jsonGet(c, "name"), "")
			state := securityScannerStrOr(jsonGet(c, "status"), "")
			containerID := securityScannerStrOr(jsonGet(c, "container_id"), "")
			if (state != "exited" && state != "dead") || name == "" || containerID == "" {
				continue
			}
			if _, expected := expectedStopped[name]; expected {
				continue
			}

			restarts, _ := queryScalar[int64](ctx, db,
				"SELECT COUNT(*) FROM activity_logs "+
					"WHERE action = 'auto_heal.container_restart' AND target_name = $1 AND server_id = $2 "+
					"AND created_at > NOW() - INTERVAL '30 minutes'", name, member.ID)
			if restarts >= 3 {
				slog.Warn(fmt.Sprintf("Auto-healer gave up on container %s on %s after 3 restarts in 30 minutes", name, member.Name))
				continue
			}

			recent, _ := queryScalar[int64](ctx, db,
				"SELECT COUNT(*) FROM activity_logs "+
					"WHERE action = 'auto_heal.container_restart' AND target_name = $1 AND server_id = $2 "+
					"AND created_at > NOW() - INTERVAL '10 minutes'", name, member.ID)
			if recent > 0 {
				continue
			}

			slog.Info(fmt.Sprintf("Auto-heal: restarting container %s on %s (attempt %d of 3)", name, member.Name, restarts+1))

			_, rerr := member.Agent.Post(ctx, "/apps/"+containerID+"/restart", nil)
			success := rerr == nil
			ActivityLogActivityOnServer(ctx, db, member.UserID, "auto-healer", "auto_heal.container_restart",
				new("container"), new(name),
				new(fmt.Sprintf("server=%s success=%t, state=%s", member.Name, success, state)),
				nil, new(member.ID), nil)
			if success {
				slog.Info(fmt.Sprintf("Auto-healer: restarted container %s on %s", name, member.Name))
			} else {
				slog.Warn(fmt.Sprintf("Auto-healer: failed to restart container %s on %s", name, member.Name))
			}
		}
	}
}

// autoHealerAutoCleanDisk frees disk space on servers whose disk alert is
// firing — on THOSE servers.
//
// This used to read one firing `disk` row with no server predicate and send
// the fixes to the local agent, so ANY member crossing its threshold made the
// panel host clean and prune ITSELF, forever (proven: member at 93%, panel
// at 18%, and the panel lost a tenant's container and image). Now each
// firing server is healed on its own agent; the cooldown is real (written
// against the server's owner); and recovery goes through resolve_alert, so
// the alerts row does not stay firing (and unpurgeable) for ever.
func autoHealerAutoCleanDisk(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	firing, _ := queryAll[Tup3[uuid.UUID, uuid.UUID, string]](ctx, db,
		"SELECT a.server_id, s.user_id, s.name "+
			"FROM alert_state a JOIN servers s ON s.id = a.server_id "+
			"WHERE a.alert_type = 'disk' AND a.current_state = 'firing' "+
			"AND a.server_id IS NOT NULL")

	for _, f := range firing {
		serverID, userID, serverName := f.A, f.B, f.C

		// Cooldown is per server, keyed on server_id like the other gates in
		// this file (it used to key on target_name holding the UUID as text).
		// One-time effect on upgrade: old-convention rows no longer suppress,
		// so a host may clean its logs once more than the hour allows.
		recent, _ := queryScalarOpt[int64](ctx, db,
			"SELECT COUNT(*) FROM activity_logs "+
				"WHERE action = 'auto_heal.clean_logs' AND server_id = $1 "+
				"AND created_at > NOW() - INTERVAL '1 hour'", serverID)
		if recent != nil && *recent > 0 {
			continue
		}

		agent, err := agents.ForServer(ctx, serverID)
		if err != nil {
			// Refuse rather than fall back to the local agent: falling back is
			// precisely the defect.
			slog.Warn(fmt.Sprintf("Auto-heal: disk alert firing on %s (%s) but its "+
				"agent is unreachable (%v) — NOT cleaning. Refusing to act on a "+
				"different host.", serverName, serverID, err))
			continue
		}

		slog.Info(fmt.Sprintf("Auto-heal: cleaning logs on %s to free disk space", serverName))
		_, cerr := agent.Post(ctx, "/diagnostics/fix", map[string]any{"fix_id": "clean-logs:all"})
		success := cerr == nil

		// This row is both the cooldown gate and the operator's only record.
		ActivityLogActivityOnServer(ctx, db, userID, "auto-healer", "auto_heal.clean_logs",
			new("server"), new(serverName),
			new(fmt.Sprintf("server=%s success=%t", serverName, success)),
			nil, new(serverID), nil)
		if !success {
			continue
		}

		slog.Info(fmt.Sprintf("Auto-heal: cleaning /tmp files older than 7 days on %s", serverName))
		_, _ = agent.Post(ctx, "/diagnostics/fix", map[string]any{"fix_id": "clean-tmp:all"})

		// The reclaim is opt-in and scoped (docker-reclaim in the agent): it
		// never removes anything DockPanel manages or a tenant is sleeping.
		if autoHealerReclaimEnabled(ctx, db) {
			slog.Info(fmt.Sprintf("Auto-heal: reclaiming unmanaged Docker resources on %s", serverName))
			_, _ = agent.Post(ctx, "/diagnostics/fix", map[string]any{"fix_id": "docker-reclaim:all"})
		}

		// Hand recovery back to the alert engine, scoped to THIS server.
		_, _ = execSQL(ctx, db,
			"UPDATE alert_state SET current_state = 'ok', consecutive_count = 0, "+
				"fired_at = NULL, last_notified_at = NULL "+
				"WHERE server_id = $1 AND alert_type = 'disk' AND current_state = 'firing'", serverID)

		NotificationsResolveAlert(ctx, db, userID, new(serverID), nil, "disk", "",
			"DISK recovered on "+serverName,
			"Automatic disk cleanup freed space on server "+serverName)

		slog.Info(fmt.Sprintf("Auto-heal: disk cleanup succeeded on %s, alert resolved", serverName))

		extra := ""
		if autoHealerReclaimEnabled(ctx, db) {
			extra = " + unmanaged Docker resources"
		}
		NotificationsNotifyPanel(ctx, db, nil, "Disk cleanup completed",
			fmt.Sprintf("Automatic disk cleanup ran on %s (logs + /tmp%s)", serverName, extra),
			"info", "auto_heal", new("/system"))
	}
}

// autoHealerReclaimEnabled: has the operator opted into reclaiming unused
// Docker resources during a disk heal? Defaults to **false**: the previous
// behaviour ran `docker system prune -af --volumes` on a consent screen that
// said "cleans logs".
func autoHealerReclaimEnabled(ctx context.Context, db *pgxpool.Pool) bool {
	v, _ := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = 'auto_heal_docker_reclaim'")
	return v != nil && *v == "true"
}

// autoHealerSslRenewalBlocked raises an alert when a certificate cannot even
// be *attempted*. This is the failure that hides best: issuance has a
// fallback contact address, so the box looks fine — and sixty days later the
// renewal loop reaches this branch every two minutes and says nothing anybody
// reads. Deduped to one alert per site per twelve hours.
func autoHealerSslRenewalBlocked(ctx context.Context, db *pgxpool.Pool, userID, siteID uuid.UUID, domain, reason string) {
	NotificationsFireAlertDeduped(ctx, db, userID, nil, new(siteID), "ssl_renewal_failure",
		NotificationsSslRenewalKeyBlocked, "critical",
		"SSL renewal blocked: "+domain,
		fmt.Sprintf("DockPanel cannot renew the certificate for %s: %s. "+
			"Until this is fixed the certificate will expire and the site will "+
			"stop loading. Set a contact address under Settings → SSL, or on the "+
			"site owner's account.", domain, reason),
		12)
}

// autoHealerSslDns01DeclinedAlert announces a DNS-01 certificate the panel
// DECLINED to renew while there is still time to fix the cause. ⚠ NOT
// autoHealerSslRenewalBlocked: "blocked", critical and "set a contact
// address" are all false here.
func autoHealerSslDns01DeclinedAlert(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID *uuid.UUID, siteID uuid.UUID, domain, reason string) {
	NotificationsFireAlertDeduped(ctx, db, userID, serverID, new(siteID), "ssl_renewal_failure",
		NotificationsSslRenewalKeyDns01Declined, "warning",
		fmt.Sprintf("SSL certificate for %s needs a Cloudflare zone", domain),
		reason, 12)
}

// autoHealerSslDns01DowngradedAlert announces a DNS-01 certificate downgraded
// to a single name on purpose, in its last week. critical is right — names
// stopped being covered — but never "renewal failed": a certificate WAS
// installed.
func autoHealerSslDns01DowngradedAlert(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID *uuid.UUID, siteID uuid.UUID, domain, losing string) {
	NotificationsFireAlertDeduped(ctx, db, userID, serverID, new(siteID), "ssl_renewal_failure",
		NotificationsSslRenewalKeyDns01Downgraded, "critical",
		"SSL certificate downgraded: "+domain,
		fmt.Sprintf("The certificate for %s covered %s and could not be re-ordered over "+
			"DNS-01 before it expired, so DockPanel issued a single-name certificate for "+
			"%s instead. Any other name it covered is no longer covered. Add the "+
			"Cloudflare zone and API token under DNS management, then re-issue from the "+
			"site's SSL tab.", domain, losing, domain),
		12)
}

type autoHealerRenewRow struct {
	ID                  uuid.UUID  `db:"id"`
	Domain              string     `db:"domain"`
	UserID              uuid.UUID  `db:"user_id"`
	Runtime             string     `db:"runtime"`
	ProxyPort           *int32     `db:"proxy_port"`
	PHPVersion          *string    `db:"php_version"`
	RootPath            *string    `db:"root_path"`
	SSLExpiry           time.Time  `db:"ssl_expiry"`
	SSLRenewalAt        *time.Time `db:"ssl_renewal_at"`
	SSLRenewalCheckedAt *time.Time `db:"ssl_renewal_checked_at"`
	SSLProfile          *string    `db:"ssl_profile"`
	ServerID            uuid.UUID  `db:"server_id"`
}

// autoHealerAutoRenewSsl auto-renews SSL certs using ACME Renewal
// Information (RFC 9773) when available, falling back to a profile-aware
// static threshold. Two phases per site: ARI refresh (store the CA's
// suggested window), then renewal when that window — or the fallback
// threshold — has passed. The agent passes the prior PEM as the ARI
// `replaces` hint, so the CA sees a continuous issuance chain.
func autoHealerAutoRenewSsl(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	// 45-day window picks up short-lived and 45-day-profile certs with lead
	// time; ARI trims this further.
	//
	// s.server_id names the host that actually serves this site, and the
	// renewal runs against THAT host's agent. Until v2.80.0 this loop used
	// the panel's own AgentClient: members' certificates expired on live
	// sites, and a local success wrote the LOCAL certificate's expiry onto the
	// remote site's row, leaving a guaranteed outage behind a green panel.
	sites, err := queryAll[autoHealerRenewRow](ctx, db,
		"SELECT s.id, s.domain, s.user_id, s.runtime, s.proxy_port, s.php_version, s.root_path, "+
			"s.ssl_expiry, s.ssl_renewal_at, s.ssl_renewal_checked_at, s.ssl_profile, "+
			"s.server_id "+
			"FROM sites s "+
			"WHERE s.ssl_enabled = TRUE AND s.ssl_expiry IS NOT NULL "+
			"AND s.ssl_expiry < NOW() + INTERVAL '45 days'")
	if err != nil {
		return
	}

	now := time.Now()
	for _, row := range sites {
		domain, siteID, userID, serverID := row.Domain, row.ID, row.UserID, row.ServerID

		// Resolve the host from the ROW before anything else. Every leg below
		// writes; an unreachable server is a reason to retry next tick, never
		// a reason to act somewhere else.
		agent, err := agents.ForServer(ctx, serverID)
		if err != nil {
			slog.Warn(fmt.Sprintf("Auto-heal: site %s lives on server %s, which is "+
				"unreachable (%v) — skipping SSL renewal this cycle. Refusing to "+
				"renew a certificate through a different host.", domain, serverID, err))
			continue
		}

		// ⛔ A renewal is a REPLACEMENT — see the same guard in the security
		// scanner. nil means "not proven foreign" and must still renew.
		if issuer := foreignCertIssuer(ctx, agent, domain); issuer != nil {
			slog.Info(fmt.Sprintf("Auto-heal: NOT renewing %s — the installed certificate was issued "+
				"by %s, not by DockPanel. Renewing would replace it.", domain, *issuer))
			continue
		}

		sslRenewalAt := row.SSLRenewalAt
		ownerEmail, oerr := queryScalarOpt[string](ctx, db, "SELECT email FROM users WHERE id = $1", userID)
		if oerr != nil || ownerEmail == nil {
			slog.Warn(fmt.Sprintf("Auto-heal: cannot renew SSL for %s — owner email not found", domain))
			autoHealerSslRenewalBlocked(ctx, db, userID, siteID, domain,
				"the site's owner account has no email address on file")
			continue
		}
		// Resolve through the SAME path issuance uses, so the panel-wide
		// acme_contact_email rescue is not limited to human-triggered issuance.
		email, rerr := rtSslResolveAcmeContact(ctx, db, *ownerEmail)
		if rerr != nil {
			slog.Warn(fmt.Sprintf("Auto-heal: cannot renew SSL for %s — %v", domain, rerr))
			autoHealerSslRenewalBlocked(ctx, db, userID, siteID, domain, rerr.Error())
			continue
		}

		// Phase 1 — refresh ARI suggestion if stale or missing. Profile-aware
		// cooldown so shortlived certs poll the CA more often.
		needsARI := row.SSLRenewalCheckedAt == nil || now.Sub(*row.SSLRenewalCheckedAt) > autoHealerProfileCooldown(row.SSLProfile)
		if needsARI {
			ariPath := fmt.Sprintf("/ssl/%s/renewal-info?email=%s", domain,
				strings.ReplaceAll(url.QueryEscape(email), "+", "%20"))
			v, err := agent.Get(ctx, ariPath)
			if err != nil {
				slog.Debug(fmt.Sprintf("ARI fetch for %s failed: %v", domain, err))
			} else {
				var when *time.Time
				if s, ok := jsonStr(jsonGet(v, "suggestion", "renewal_at")); ok {
					if t, err := time.Parse(time.RFC3339, s); err == nil {
						when = new(t.UTC())
					}
				}
				_, _ = execSQL(ctx, db,
					"UPDATE sites "+
						"SET ssl_renewal_at = $1, ssl_renewal_checked_at = NOW(), updated_at = NOW() "+
						"WHERE id = $2", when, siteID)
				if when != nil {
					sslRenewalAt = when
				}
			}
		}

		// Decide if this cert is due for renewal.
		var due bool
		if sslRenewalAt != nil {
			due = !sslRenewalAt.After(now)
		} else {
			due = row.SSLExpiry.Sub(now) <= autoHealerFallbackRenewalMargin(row.SSLProfile)
		}
		if !due {
			continue
		}

		// Profile-aware cooldown prevents hammering the CA if renewal keeps
		// failing. cooldownHours is a typed integer — safe to interpolate.
		cooldownHours := int64(autoHealerProfileCooldown(row.SSLProfile) / time.Hour)
		recent, _ := queryScalarOpt[int64](ctx, db, fmt.Sprintf(
			"SELECT COUNT(*) FROM activity_logs "+
				"WHERE action = 'auto_heal.renew_ssl' "+
				"AND target_name = $1 "+
				"AND created_at > NOW() - INTERVAL '%d hours'", cooldownHours), domain)
		if recent != nil && *recent > 0 {
			continue
		}

		slog.Info("Auto-heal: renewing SSL for " + domain)

		agentBody := map[string]any{"email": email, "runtime": row.Runtime}
		if row.ProxyPort != nil {
			agentBody["proxy_port"] = *row.ProxyPort
		}
		if row.PHPVersion != nil {
			agentBody["php_socket"] = fmt.Sprintf("unix:/run/php/php%s-fpm.sock", *row.PHPVersion)
		}
		if row.RootPath != nil {
			agentBody["root"] = *row.RootPath
		}
		if row.SSLProfile != nil {
			agentBody["profile"] = *row.SSLProfile
		}

		// WHICH CHALLENGE ISSUED THIS CERTIFICATE decides which door renews it.
		full, _ := queryOpt[Site](ctx, db, "SELECT * FROM sites WHERE id = $1", siteID)
		if full == nil {
			continue
		}
		daysRemaining := int64(row.SSLExpiry.Sub(now) / (24 * time.Hour))
		plan := renewalPlan(ctx, db, full, &daysRemaining)

		// A DNS-01 certificate whose zone we cannot reach is REFUSED while
		// there is still time to fix the cause, and downgraded on purpose only
		// inside its last week. ⛔ This refusal ALERTS — unlike the bare-log
		// foreign-issuer stop above, a precedent it must not inherit.
		if plan.Kind == RenewRefuse {
			// ⚠ A DIFFERENT sentence from the foreign-issuer stop, on purpose.
			slog.Warn(fmt.Sprintf("Auto-heal: DNS-01 renewal declined for %s — %s", domain, plan.Reason))
			autoHealerSslDns01DeclinedAlert(ctx, db, userID, new(serverID), siteID, domain, plan.Reason)
			continue
		}

		// ⛔ PostLong, not Post: plain Post caps at 60s, a wildcard DNS-01
		// order budgets ~260s in the agent alone — a false failure here skips
		// the expiry write and the vhost rebuild while the agent succeeds.
		var result any
		var oerr2 error
		if plan.Kind == RenewDNS01 {
			result, oerr2 = rtSslRenewOverDns01(ctx, db, agents.JWTSecret(), agent, plan.Subject, plan.Wildcard, plan.ZoneID, userID, row.SSLProfile)
		} else {
			result, oerr2 = agent.PostLong(ctx, "/ssl/"+domain+"/renew", agentBody, rtSslDns01OrderTimeoutSecs)
		}
		success := oerr2 == nil
		details := ""
		if success {
			details = securityScannerJSONString(result)
		} else {
			details = oerr2.Error()
		}

		// THIS ROW IS THE COOLDOWN. Until v2.60.0 it passed the nil uuid,
		// fk_activity_logs_user rejected it, COUNT(*) was permanently 0 and a
		// certificate DockPanel cannot renew was re-ordered from the CA every
		// 120 seconds, for ever — real load on Let's Encrypt. Named against the
		// site's OWNER and stamped with the site's server.
		ActivityLogActivityOnServer(ctx, db, userID, "auto-healer", "auto_heal.renew_ssl",
			new("site"), new(domain),
			new(fmt.Sprintf("site_id=%s, success=%t, result=%s", siteID, success, details)),
			nil, new(serverID), nil)

		if success {
			if s, ok := jsonStr(jsonGet(result, "expiry")); ok {
				if expiry := parseAgentCertExpiry(s); expiry != nil {
					// Clear ssl_renewal_at so the next cycle re-fetches ARI
					// against the fresh cert.
					_, _ = execSQL(ctx, db,
						"UPDATE sites SET ssl_expiry = $1, ssl_renewal_at = NULL, "+
							"ssl_renewal_checked_at = NULL, updated_at = NOW() WHERE id = $2", *expiry, siteID)
				}
			}
			// Only after success: a failed HTTP-01 attempt on an unrecorded row
			// must stay unrecorded.
			rtSslRecordRenewalProvenance(ctx, db, siteID, domain, plan)
			if plan.Kind == RenewLastResortHTTP01 {
				autoHealerSslDns01DowngradedAlert(ctx, db, userID, new(serverID), siteID, domain, plan.Losing)
			}
			slog.Info("Auto-heal: SSL renewed for " + domain)

			// AFTER the downgrade alert deliberately: that one describes the
			// certificate this success installed, and this does not touch its key.
			NotificationsResolveSslRenewalFailure(ctx, db, userID, siteID, domain)

			// Re-render the full vhost so the renewal preserves WAF / CSP /
			// Permissions-Policy / rate-limit / custom_nginx / bot-protection.
			if s, err := queryOne[Site](ctx, db, "SELECT * FROM sites WHERE id = $1", siteID); err == nil {
				// A disabled site is not rebuilt by an unattended loop.
				if !s.Enabled {
					slog.Info(fmt.Sprintf("Auto-heal: renewed SSL for %s but skipped the vhost rebuild — the site is disabled", s.Domain))
				} else if _, err := agent.Put(ctx, "/nginx/sites/"+s.Domain, rtSitesBuildNginxBody(&s)); err != nil {
					slog.Warn(fmt.Sprintf("Auto-heal: full vhost rebuild after renewal failed for %s: %v", s.Domain, err))
				}
			}

			AutoHealerSslRenewalsSuccess.Add(1)

			NotificationsNotifyPanel(ctx, db, nil, "SSL renewed: "+domain,
				fmt.Sprintf("SSL certificate for %s was automatically renewed", domain),
				"info", "ssl", new("/monitoring?tab=certificates"))
		} else {
			// The server this alert names is the one the SITE is on — it used
			// to be the oldest servers row (the panel), so an admin who had
			// switched the picker to the affected member could not see it.
			// Deduped: the cooldown is one hour for short-lived profiles.
			NotificationsFireAlertDeduped(ctx, db, userID, new(serverID), new(siteID), "ssl_renewal_failure",
				NotificationsSslRenewalKeyFailed, "critical",
				"SSL renewal failed: "+domain,
				fmt.Sprintf("Auto-healer failed to renew the SSL certificate for %s: %s. "+
					"The certificate may expire soon — check the domain configuration and DNS.", domain, details),
				12)
			SystemLogLogEvent(ctx, db, "error", "auto_healer", "SSL renewal failed for "+domain, new(details))
			slog.Warn(fmt.Sprintf("Auto-heal: SSL renewal failed for %s: %s", domain, details))
			AutoHealerSslRenewalsFailure.Add(1)
		}
	}
}

// autoHealerFallbackRenewalMargin is the renewal margin when the CA doesn't
// advertise ARI: shortlived (~6d) renews at 2d remaining; tlsserver (45d)
// at 15d; classic/unknown at 30d, safe across 90d/64d/45d horizons.
func autoHealerFallbackRenewalMargin(profile *string) time.Duration {
	switch {
	case profile != nil && *profile == "shortlived":
		return 2 * 24 * time.Hour
	case profile != nil && *profile == "tlsserver":
		return 15 * 24 * time.Hour
	default:
		return 30 * 24 * time.Hour
	}
}

// autoHealerProfileCooldown is the per-profile cooldown for ARI re-fetch +
// post-attempt retry: shortlived polls tighter so a failed attempt near
// expiry doesn't burn the whole window; longer profiles stay at 6h.
func autoHealerProfileCooldown(profile *string) time.Duration {
	if profile != nil && *profile == "shortlived" {
		return time.Hour
	}
	return 6 * time.Hour
}

// autoHealerSendWeeklyDigest sends a summary email to all admins on Mondays.
func autoHealerSendWeeklyDigest(ctx context.Context, db *pgxpool.Pool) {
	if time.Now().UTC().Weekday() != time.Monday {
		return
	}
	count := func(sql string) int64 {
		n, _ := queryScalar[int64](ctx, db, sql)
		return n
	}
	alerts7d := count("SELECT COUNT(*) FROM alerts WHERE created_at > NOW() - INTERVAL '7 days'")
	backups7d := count("SELECT COUNT(*) FROM backups WHERE created_at > NOW() - INTERVAL '7 days'")
	incidents7d := count("SELECT COUNT(*) FROM managed_incidents WHERE created_at > NOW() - INTERVAL '7 days'")
	deploys7d := count("SELECT COUNT(*) FROM deploy_logs WHERE created_at > NOW() - INTERVAL '7 days'")
	scans7d := count("SELECT COUNT(*) FROM security_scans WHERE created_at > NOW() - INTERVAL '7 days'")

	bodyHTML := fmt.Sprintf(`<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #4f46e5;">DockPanel Weekly Summary</h2>
            <p>Here's what happened in the last 7 days:</p>
            <table style="border-collapse: collapse; width: 100%%; margin: 16px 0;">
                <tr><td style="padding: 8px; border-bottom: 1px solid #e5e7eb; font-weight: 600;">Alerts</td><td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">%d</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #e5e7eb; font-weight: 600;">Backups</td><td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">%d</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #e5e7eb; font-weight: 600;">Incidents</td><td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">%d</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #e5e7eb; font-weight: 600;">Deploys</td><td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">%d</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #e5e7eb; font-weight: 600;">Security Scans</td><td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">%d</td></tr>
            </table>
            <p style="color: #6b7280; font-size: 14px;">Log in to your DockPanel dashboard for full details.</p>
        </div>`, alerts7d, backups7d, incidents7d, deploys7d, scans7d)

	admins, _ := queryAll[string](ctx, db, "SELECT email FROM users WHERE role = 'admin'")
	for _, email := range admins {
		if err := EmailSendEmail(ctx, db, email, "DockPanel Weekly Summary", bodyHTML); err != nil {
			slog.Warn(fmt.Sprintf("Weekly digest email to %s failed: %v", email, err))
		}
	}
	if len(admins) > 0 {
		slog.Info(fmt.Sprintf("Weekly digest sent to %d admin(s): %d alerts, %d backups, %d incidents, %d deploys",
			len(admins), alerts7d, backups7d, incidents7d, deploys7d))
	}
}

// autoHealerPrunePolicyBackup retires one backup: remove the archive, then
// the row that names it. Serves all three retention sweeps (backups,
// database_backups, volume_backups).
//
// The row is the ONLY record of where the archive lives, so it is deleted
// last and only when the archive is genuinely gone. Two cases keep it:
//   - The backup belongs to another server: a local unlink cannot reach it,
//     and deleting the row would orphan the archive with no record of where.
//   - The unlink failed for a reason other than "already gone" — exactly when
//     the operator most needs the row to still say what is on disk.
//
// Returns true when the backup was actually retired.
func autoHealerPrunePolicyBackup(ctx context.Context, db *pgxpool.Pool, table string, id uuid.UUID, filepath string, rowServer, localServer *uuid.UUID) bool {
	if rowServer != nil && localServer != nil && *rowServer != *localServer {
		slog.Warn(fmt.Sprintf("Retention: %s %s belongs to server %s, not this host — "+
			"keeping the row. A local unlink cannot reach it, and deleting the row "+
			"would orphan the archive with no record of where it is.", table, id, *rowServer))
		return false
	}
	if err := os.Remove(filepath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn(fmt.Sprintf("Retention: could not remove %s (%v) — keeping the %s row "+
			"so the archive stays accounted for.", filepath, err, table))
		return false
	}
	// `table` is a compile-time literal from this file, never user input.
	if _, err := execSQL(ctx, db, fmt.Sprintf("DELETE FROM %s WHERE id = $1", table), id); err != nil {
		slog.Warn(fmt.Sprintf("Retention: removed %s but could not delete %s %s: %v", filepath, table, id, err))
		return false
	}
	return true
}

// autoHealerExecCount runs a retention DELETE and returns rows affected (0 on
// error), the `.ok().map(rows_affected).unwrap_or(0)` shape.
func autoHealerExecCount(ctx context.Context, db *pgxpool.Pool, sql string) int64 {
	n, _ := execSQL(ctx, db, sql)
	return n
}

// autoHealerRunRetentionCleanup removes old records to keep the database lean.
func autoHealerRunRetentionCleanup(ctx context.Context, db *pgxpool.Pool) {
	slog.Info("Running data retention cleanup...")

	// GAP 33: Weekly digest — summary email on Mondays during cleanup cycle.
	autoHealerSendWeeklyDigest(ctx, db)

	// Phase 4 W4: panel snapshot retention (keep last 3; delete older than 7
	// days beyond that floor; file first, row only if the file went).
	if n, err := PanelSnapshotRetentionSweep(ctx, db); err != nil {
		slog.Warn(fmt.Sprintf("Retention cleanup (panel_snapshots) failed: %v", err))
	} else if n > 0 {
		slog.Info(fmt.Sprintf("Retention: removed %d aged panel snapshot(s)", n))
	}

	// GAP 67: configurable retention periods (fall back to defaults).
	settings, _ := queryAll[Tup2[string, string]](ctx, db, "SELECT key, value FROM settings WHERE key LIKE 'retention_%'")
	get := func(key string, def int64) int64 {
		for _, s := range settings {
			if s.A == key {
				if v, err := strconv.ParseInt(s.B, 10, 64); err == nil {
					return v
				}
				return def
			}
		}
		return def
	}
	activityDays := get("retention_activity_days", 365)
	systemLogDays := get("retention_system_log_days", 30)
	alertDays := get("retention_alert_days", 90)
	scanDays := get("retention_scan_days", 90)
	webhookDays := get("retention_webhook_days", 7)
	notificationDays := get("retention_notification_days", 30)
	monitorDays := get("retention_monitor_days", 7)

	// The day counts are typed integers — safe to interpolate.
	for _, d := range []struct {
		sql, table, okMsg string
	}{
		{fmt.Sprintf("DELETE FROM monitor_checks WHERE checked_at < NOW() - INTERVAL '%d days'", monitorDays),
			"monitor_checks", fmt.Sprintf("old monitor_checks (>%d days)", monitorDays)},
		{fmt.Sprintf("DELETE FROM alerts WHERE status = 'resolved' AND created_at < NOW() - INTERVAL '%d days'", alertDays),
			"alerts", fmt.Sprintf("old resolved alerts (>%d days)", alertDays)},
		{fmt.Sprintf("DELETE FROM activity_logs WHERE created_at < NOW() - INTERVAL '%d days'", activityDays),
			"activity_logs", fmt.Sprintf("old activity_logs (>%d days)", activityDays)},
		{fmt.Sprintf("DELETE FROM system_logs WHERE created_at < NOW() - INTERVAL '%d days'", systemLogDays),
			"system_logs", fmt.Sprintf("old system_logs (>%d days)", systemLogDays)},
	} {
		n, err := execSQL(ctx, db, d.sql)
		if err != nil {
			slog.Warn(fmt.Sprintf("Retention cleanup (%s) failed: %v", d.table, err))
		} else if n > 0 {
			slog.Info(fmt.Sprintf("Retention: deleted %d %s", n, d.okMsg))
		}
	}

	if n := autoHealerExecCount(ctx, db, fmt.Sprintf("DELETE FROM extension_events WHERE delivered_at < NOW() - INTERVAL '%d days'", scanDays)); n > 0 {
		slog.Info(fmt.Sprintf("Retention: deleted %d extension events (>%d days)", n, scanDays))
	}
	// GAP 18: Webhook gateway deliveries.
	if n := autoHealerExecCount(ctx, db, fmt.Sprintf("DELETE FROM webhook_deliveries WHERE received_at < NOW() - INTERVAL '%d days'", webhookDays)); n > 0 {
		slog.Info(fmt.Sprintf("Retention: deleted %d webhook deliveries (>%d days)", n, webhookDays))
	}
	if n := autoHealerExecCount(ctx, db, fmt.Sprintf("DELETE FROM backup_verifications WHERE created_at < NOW() - INTERVAL '%d days'", scanDays)); n > 0 {
		slog.Info(fmt.Sprintf("Retention: deleted %d backup verifications (>%d days)", n, scanDays))
	}
	// User sessions: 24h since last seen (JWT expires after 2h; stale records).
	if n := autoHealerExecCount(ctx, db, "DELETE FROM user_sessions WHERE last_seen_at < NOW() - INTERVAL '24 hours'"); n > 0 {
		slog.Info(fmt.Sprintf("Retention: deleted %d expired user sessions (>24h)", n))
	}
	if n := autoHealerExecCount(ctx, db, fmt.Sprintf("DELETE FROM panel_notifications WHERE created_at < NOW() - INTERVAL '%d days'", notificationDays)); n > 0 {
		slog.Info(fmt.Sprintf("Retention: deleted %d panel notifications (>%d days)", n, notificationDays))
	}
	// GAP 66: expired token blacklist entries.
	if n := autoHealerExecCount(ctx, db, "DELETE FROM token_blacklist WHERE expires_at < NOW()"); n > 0 {
		slog.Info(fmt.Sprintf("Retention: deleted %d expired token blacklist entries", n))
	}
	// Expired terminal shares (older than 1 hour, timestamp prefix in value).
	if n := autoHealerExecCount(ctx, db,
		"DELETE FROM settings WHERE key LIKE 'terminal_share_%' AND "+
			"CAST(SPLIT_PART(value, '|', 1) AS BIGINT) < EXTRACT(EPOCH FROM NOW()) - 3600"); n > 0 {
		slog.Info(fmt.Sprintf("Retention: deleted %d expired terminal shares (>1 hour)", n))
	}

	// ── Backup Retention Enforcement ──
	// A retention sweep unlinks a path on THIS filesystem, so it may only act
	// on rows whose backup was written here.
	localServerID, _ := queryScalarOpt[uuid.UUID](ctx, db, "SELECT id FROM servers WHERE is_local = TRUE LIMIT 1")

	// `backups` carries no server of its own: the owning host is the site's.
	// sites.server_id is NOT NULL and read as a plain uuid on purpose — a NULL
	// fails the query and prunes nothing, where a pointer would reach the
	// guard as nil, which skips and unlinks locally. Only one of those
	// destroys a record.
	type schedRow struct {
		ID             uuid.UUID `db:"id"`
		SiteID         uuid.UUID `db:"site_id"`
		RetentionCount int32     `db:"retention_count"`
		Domain         string    `db:"domain"`
		ServerID       uuid.UUID `db:"server_id"`
	}
	schedules, _ := queryAll[schedRow](ctx, db,
		"SELECT bs.id, bs.site_id, bs.retention_count, s.domain, s.server_id "+
			"FROM backup_schedules bs JOIN sites s ON s.id = bs.site_id "+
			"WHERE bs.retention_count > 0")

	var totalPruned uint64
	for _, s := range schedules {
		excess, _ := queryAll[Tup2[uuid.UUID, string]](ctx, db,
			"SELECT id, filename FROM backups WHERE site_id = $1 "+
				"ORDER BY created_at DESC OFFSET $2", s.SiteID, s.RetentionCount)
		for _, e := range excess {
			path := fmt.Sprintf("/var/backups/dockpanel/%s/%s", s.Domain, e.B)
			if autoHealerPrunePolicyBackup(ctx, db, "backups", e.A, path, new(s.ServerID), localServerID) {
				totalPruned++
			}
		}
	}
	if totalPruned > 0 {
		slog.Info(fmt.Sprintf("Retention: pruned %d backups exceeding retention_count limits", totalPruned))
	}

	// Backup policies (database_backups + volume_backups).
	policies, _ := queryAll[Tup2[uuid.UUID, int32]](ctx, db,
		"SELECT id, retention_count FROM backup_policies WHERE retention_count > 0")
	for _, p := range policies {
		// Retention is per DATABASE, not per policy: OFFSET n over a policy's
		// whole history kept n backups in TOTAL, so four of five databases
		// ended up with none.
		excessDB, _ := queryAll[Tup4[uuid.UUID, string, string, *uuid.UUID]](ctx, db,
			"SELECT id, filename, db_name, server_id FROM ( "+
				"SELECT id, filename, db_name, server_id, "+
				"ROW_NUMBER() OVER (PARTITION BY database_id ORDER BY created_at DESC) AS rn "+
				"FROM database_backups WHERE policy_id = $1 "+
				") ranked WHERE rn > $2", p.A, p.B)
		for _, e := range excessDB {
			// backup_dir nests per database; the old path omitted it, so the
			// unlink never matched while the DELETE ran anyway.
			path := fmt.Sprintf("/var/backups/dockpanel/databases/%s/%s", e.C, e.B)
			if autoHealerPrunePolicyBackup(ctx, db, "database_backups", e.A, path, e.D, localServerID) {
				totalPruned++
			}
		}
		// Same shape for volumes: per container+volume, nested per container.
		excessVol, _ := queryAll[Tup4[uuid.UUID, string, string, *uuid.UUID]](ctx, db,
			"SELECT id, filename, container_name, server_id FROM ( "+
				"SELECT id, filename, container_name, server_id, "+
				"ROW_NUMBER() OVER (PARTITION BY container_id, volume_name ORDER BY created_at DESC) AS rn "+
				"FROM volume_backups WHERE policy_id = $1 "+
				") ranked WHERE rn > $2", p.A, p.B)
		for _, e := range excessVol {
			path := fmt.Sprintf("/var/backups/dockpanel/volumes/%s/%s", e.C, e.B)
			if autoHealerPrunePolicyBackup(ctx, db, "volume_backups", e.A, path, e.D, localServerID) {
				totalPruned++
			}
		}
	}
	if totalPruned > 0 {
		slog.Info(fmt.Sprintf("Retention: total %d excess backups pruned (schedules + policies)", totalPruned))
	}

	// ── Security Enhancement Retention ──
	if n := autoHealerExecCount(ctx, db, "DELETE FROM suspicious_events WHERE created_at < NOW() - INTERVAL '90 days'"); n > 0 {
		slog.Info(fmt.Sprintf("Retention: deleted %d old suspicious_events (>90 days)", n))
	}

	// Old session recordings (>30 days).
	recDir := "/var/lib/dockpanel/recordings"
	if entries, err := os.ReadDir(recDir); err == nil {
		var recDeleted uint64
		cutoff := time.Now().Add(-30 * 86400 * time.Second)
		for _, e := range entries {
			if created, ok := autoHealerCreated(e); ok && created.Before(cutoff) {
				_ = os.Remove(filepath.Join(recDir, e.Name()))
				recDeleted++
			}
		}
		if recDeleted > 0 {
			slog.Info(fmt.Sprintf("Retention: deleted %d old session recordings (>30 days)", recDeleted))
		}
	}

	// Old audit log files (>365 days). The delete result is not discarded:
	// under a hand-set append-only attribute unlink is refused even for root,
	// and every delete would fail forever with nothing reported — the first
	// symptom a disk alert a year after install. created() falls back to
	// modified() (equivalent for a daily append-only log).
	auditDir := "/var/lib/dockpanel/audit"
	if entries, err := os.ReadDir(auditDir); err == nil {
		cutoff := time.Now().Add(-365 * 86400 * time.Second)
		var auditDeleted uint64
		var auditFailed []string
		for _, e := range entries {
			stamp, ok := autoHealerCreated(e)
			if !ok || !stamp.Before(cutoff) {
				continue
			}
			p := filepath.Join(auditDir, e.Name())
			if err := os.Remove(p); err != nil {
				auditFailed = append(auditFailed, fmt.Sprintf("%s (%v)", p, err))
			} else {
				auditDeleted++
			}
		}
		if auditDeleted > 0 {
			slog.Info(fmt.Sprintf("Retention: deleted %d old audit log files (>365 days)", auditDeleted))
		}
		if len(auditFailed) > 0 {
			slog.Warn(fmt.Sprintf("Retention: %d audit log file(s) older than 365 days could NOT be removed "+
				"[%s] — if %s carries the append-only attribute, unlink is denied "+
				"even to root; clear it with `chattr -a %s` and the next sweep "+
				"will succeed", len(auditFailed), strings.Join(auditFailed, ", "), auditDir, auditDir))
		}
	}

	// DB auto-backup: direct pg_dump (doesn't need an agent).
	if SecurityHardeningGetSettingBool(ctx, db, "security_db_backup_enabled", true) {
		slog.Info("Triggering DockPanel DB auto-backup...")
		// `bash` and `set -o pipefail` are load-bearing (lesson #51): the exit
		// status of `pg_dump | gzip` is gzip's, and gzip compresses a truncated
		// stream and exits 0. `umask 077` is load-bearing too: without it this
		// dump — the whole panel database — lands 0644 on a host that also runs
		// other people's PHP as www-data.
		backupFile := fmt.Sprintf("/var/backups/dockpanel/dockpanel-db-%s.sql.gz", time.Now().UTC().Format("20060102_150405"))
		cmd := safeCommand(ctx, "bash", "-c",
			"set -o pipefail; umask 077; docker exec dockpanel-postgres pg_dump -U dockpanel dockpanel | gzip > "+backupFile)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		var exitErr interface{ ExitCode() int }
		switch {
		case err == nil:
			// A zero exit is not the success condition — a whole dump is
			// (lesson #51 rule 4). pg_dump emits this marker last. This gates
			// the prune below: pruning after a corrupt backup would evict a
			// GOOD one to make room for a useless one.
			tail, _ := safeCommand(ctx, "bash", "-c", "gunzip -c "+backupFile+" | tail -20").Output()
			if !strings.Contains(string(tail), "PostgreSQL database dump complete") {
				slog.Warn(fmt.Sprintf("DB auto-backup discarded: %s is incomplete "+
					"(completion marker absent) — keeping earlier backups", backupFile))
				_ = os.Remove(backupFile)
				return
			}
			slog.Info("DockPanel DB auto-backup completed")
			// Cleanup old backups (keep 7).
			if entries, err := os.ReadDir("/var/backups/dockpanel"); err == nil {
				var names []string
				for _, e := range entries {
					if strings.HasPrefix(e.Name(), "dockpanel-db-") {
						names = append(names, e.Name())
					}
				}
				sort.Sort(sort.Reverse(sort.StringSlice(names)))
				for i, n := range names {
					if i >= 7 {
						_ = os.Remove(filepath.Join("/var/backups/dockpanel", n))
					}
				}
			}
		case errors.As(err, &exitErr):
			slog.Warn("DB auto-backup failed: " + stderr.String())
		default:
			slog.Warn(fmt.Sprintf("DB auto-backup failed: %v", err))
		}
	}
}

// autoHealerCreated is the entry's creation time. Go's FileInfo has no birth
// time, so this is the modification time — the fallback the audit sweep
// already used; recordings and audit logs are written once and only appended.
func autoHealerCreated(e os.DirEntry) (time.Time, bool) {
	info, err := e.Info()
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}

// ── Security Hardening Background Tasks ──

// autoHealerSecurityIngestSuspiciousEvents ingests suspicious events written
// by the agent (JSONL), records each, then truncates the file.
func autoHealerSecurityIngestSuspiciousEvents(ctx context.Context, db *pgxpool.Pool) {
	const path = "/var/lib/dockpanel/suspicious-events.jsonl"
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return
	}
	// Truncate the file immediately to avoid re-processing.
	_ = os.WriteFile(path, nil, 0o666)

	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event any
		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}
		eventType := securityScannerStrOr(jsonGet(event, "event_type"), "unknown")
		actorEmail := securityScannerOptStr(jsonGet(event, "actor_email"))
		command := securityScannerOptStr(jsonGet(event, "command"))
		domain := securityScannerStrOr(jsonGet(event, "domain"), "")

		// The agent stamps every line with the time the command actually ran.
		// Ingesting a backlog as NOW collapses months into one instant and
		// trips the "N events in M minutes" rule on the first tick. An absent
		// or unparseable stamp falls back to now (the safe direction).
		var occurredAt *time.Time
		if s, ok := jsonStr(jsonGet(event, "timestamp")); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				occurredAt = new(t.UTC())
			}
		}
		details := fmt.Sprintf("domain=%s, command=%s", domain, securityScannerDerefOr(command, "-"))

		// A REFUSED command is audited but does NOT count toward auto-lockdown:
		// the agent's blocklist contains a bare ".." SUBSTRING (it refuses
		// `echo "done..."`), so ordinary tenants produce refusals by accident,
		// and counting them would turn a blunt blocklist into a self-inflicted
		// 24-hour outage. The operator still sees each one in the audit log.
		locked := false
		if eventType != "terminal.blocked_command" {
			locked = SecurityHardeningRecordSuspiciousEventAt(ctx, db, eventType, actorEmail, nil, new(details), occurredAt)
		}

		SecurityHardeningAuditLog(ctx, db, eventType, actorEmail, nil,
			new("terminal"), new(domain), new(details), nil, "warning", nil)

		if locked {
			SecurityHardeningAlertLockdown(ctx, db,
				fmt.Sprintf("Suspicious terminal command by %s on %s: %s",
					securityScannerDerefOr(actorEmail, "?"), domain, securityScannerDerefOr(command, "?")),
				"auto")
		}
		count++
	}
	if count > 0 {
		slog.Warn(fmt.Sprintf("Ingested %d suspicious terminal events from agent", count))
	}
}

// AutoHealerCanaryWatchPaths is every path this process watches for canary
// access, newest set first. The last four are the pre-v2.132.0 set — a box
// armed by hand before then still carries them, and dropping them would
// silently stop watching a tripwire somebody relies on. /etc/.dockpanel-canary
// is watchable but NOT plantable (bare /etc is read-only to the agent under
// ProtectSystem=strict).
var AutoHealerCanaryWatchPaths = [7]string{
	"/etc/dockpanel/.dockpanel-canary",
	"/var/lib/dockpanel/.dockpanel-canary",
	"/var/backups/dockpanel/.dockpanel-canary",
	"/var/www/.dockpanel-canary",
	"/etc/.dockpanel-canary",
	"/root/.dockpanel-canary",
	"/home/.dockpanel-canary",
}

// AutoHealerCanaryPlantable is the subset the agent will actually plant.
// ⚠ Mirrors CANARY_PLANT_PATHS in the agent; canary-arm-pin-e2e.sh asserts
// they stay identical and inside the agent unit's ReadWritePaths=.
var AutoHealerCanaryPlantable = [4]string{
	"/etc/dockpanel/.dockpanel-canary",
	"/var/lib/dockpanel/.dockpanel-canary",
	"/var/backups/dockpanel/.dockpanel-canary",
	"/var/www/.dockpanel-canary",
}

// AutoHealerSandboxMaskedPrefixes are paths this process can never observe:
// ProtectHome=yes replaces /home and /root with an empty read-only mount. A
// masked path reports NotFound (the namespace has nothing there), not
// PermissionDenied — which is why this list exists rather than an error arm.
var AutoHealerSandboxMaskedPrefixes = [2]string{"/root/", "/home/"}

// AutoHealerCanaryKind is what this process can currently see at one path.
// Three outcomes, not two: Masked looks exactly like Absent to stat.
type AutoHealerCanaryKind int

const (
	AutoHealerCanaryWatching AutoHealerCanaryKind = iota
	AutoHealerCanaryAbsent
	AutoHealerCanaryMasked
	// AutoHealerCanaryUnreadable: may exist and we cannot see it — a blind
	// spot rather than an all-clear. Err carries the reason.
	AutoHealerCanaryUnreadable
)

// AutoHealerCanaryState is Rust's CanaryState enum.
type AutoHealerCanaryState struct {
	Kind AutoHealerCanaryKind
	Err  string
}

// AsStr is CanaryState::as_str.
func (s AutoHealerCanaryState) AsStr() string {
	switch s.Kind {
	case AutoHealerCanaryWatching:
		return "watching"
	case AutoHealerCanaryAbsent:
		return "absent"
	case AutoHealerCanaryMasked:
		return "masked"
	default:
		return "unreadable"
	}
}

// autoHealerIOError renders an error like Rust's io::Error Display
// ("Permission denied (os error 13)").
func autoHealerIOError(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		msg := errno.Error()
		if msg != "" {
			msg = strings.ToUpper(msg[:1]) + msg[1:]
		}
		return fmt.Sprintf("%s (os error %d)", msg, int(errno))
	}
	return err.Error()
}

// AutoHealerClassifyCanary is the ONE place a canary path is classified. The
// two-minute checker and the Settings status endpoint both call it: if the
// screen classified a path differently from the sweeper, the panel would
// report a tripwire armed while the thing that raises the alarm skipped it.
func AutoHealerClassifyCanary(path string) (AutoHealerCanaryState, os.FileInfo) {
	info, err := os.Stat(path)
	if err == nil {
		return AutoHealerCanaryState{Kind: AutoHealerCanaryWatching}, info
	}
	for _, p := range AutoHealerSandboxMaskedPrefixes {
		if strings.HasPrefix(path, p) {
			return AutoHealerCanaryState{Kind: AutoHealerCanaryMasked}, nil
		}
	}
	if errors.Is(err, fs.ErrNotExist) {
		return AutoHealerCanaryState{Kind: AutoHealerCanaryAbsent}, nil
	}
	return AutoHealerCanaryState{Kind: AutoHealerCanaryUnreadable, Err: autoHealerIOError(err)}, nil
}

// autoHealerAtime is MetadataExt::atime. Read by field name so this file
// builds on every GOOS (Linux: Atim, Darwin/BSD: Atimespec).
func autoHealerAtime(info os.FileInfo) int64 {
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return 0
	}
	for _, name := range []string{"Atim", "Atimespec"} {
		if f := v.FieldByName(name); f.IsValid() {
			if sec := f.FieldByName("Sec"); sec.IsValid() {
				return sec.Int()
			}
		}
	}
	return 0
}

var (
	autoHealerCanaryWarned  atomic.Bool
	autoHealerCanaryPartial atomic.Bool
)

// autoHealerSecurityCheckCanaryFiles checks canary files for access (Feature
// 12): atime is compared against a stored baseline; an increase means
// somebody read the file.
func autoHealerSecurityCheckCanaryFiles(ctx context.Context, db *pgxpool.Pool) {
	paths := AutoHealerCanaryWatchPaths

	// How many canaries this tick could actually examine. A tripwire with
	// nothing on the wire reports "all clear" forever — and until v2.132.0
	// nothing planted these files, so the shipped default was zero armed
	// paths everywhere, indistinguishable from "armed and quiet".
	examined := 0
	var masked, absent []string

	for _, path := range paths {
		state, meta := AutoHealerClassifyCanary(path)
		switch state.Kind {
		case AutoHealerCanaryMasked:
			masked = append(masked, path)
			continue
		case AutoHealerCanaryAbsent:
			absent = append(absent, path)
			continue
		case AutoHealerCanaryUnreadable:
			slog.Warn(fmt.Sprintf("Canary %s exists or may exist but is unreadable (%s); "+
				"it is NOT being monitored", path, state.Err))
			continue
		}
		examined++

		atime := autoHealerAtime(meta)
		key := "canary_atime_" + strings.ReplaceAll(path, "/", "_")
		stored, _ := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = $1", key)
		var storedAtime int64
		if stored != nil {
			storedAtime, _ = strconv.ParseInt(*stored, 10, 64)
		}

		if storedAtime == 0 {
			// First run: store current atime as baseline.
			_, _ = execSQL(ctx, db,
				"INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
				key, strconv.FormatInt(atime, 10))
			continue
		}
		if atime <= storedAtime {
			continue
		}

		// Canary was accessed! Alert immediately.
		slog.Error(fmt.Sprintf("CANARY TRIGGERED: %s was accessed (atime changed from %d to %d)", path, storedAtime, atime))

		SecurityHardeningAuditLog(ctx, db, "canary.triggered", nil, nil,
			new("canary"), new(path),
			new("Canary file accessed at "+autoHealerRFC3339(time.Unix(atime, 0))),
			nil, "critical", nil)

		// Record as suspicious event (may trigger auto-lockdown).
		SecurityHardeningRecordSuspiciousEvent(ctx, db, "canary.triggered", nil, nil,
			new(fmt.Sprintf("Canary file %s was accessed", path)))

		admins, _ := queryAll[uuid.UUID](ctx, db, "SELECT id FROM users WHERE role = 'admin'")
		subject := "🚨 CANARY TRIGGERED: " + path
		message := fmt.Sprintf("A canary file was accessed on the server!\n"+
			"File: %s\n"+
			"This indicates unauthorized filesystem exploration.\n"+
			"Check forensic snapshot and audit log immediately.", path)
		html := fmt.Sprintf("<h2 style='color:red'>Canary File Triggered</h2>"+
			"<p><strong>File:</strong> %s</p>"+
			"<p>This indicates unauthorized filesystem exploration.</p>"+
			"<p>Check forensic snapshot and audit log immediately.</p>", path)
		for _, adminID := range admins {
			if ch := NotificationsGetUserChannels(ctx, db, adminID, nil); ch != nil {
				NotificationsSendNotification(ctx, db, ch, subject, message, html)
			}
		}

		// The loop above is empty until somebody configures a destination, so
		// the tripwire could fire on a stock install and be seen by no one. A
		// tripwire you have to go looking for is not a tripwire.
		NotificationsNotifyPanel(ctx, db, nil, subject, message, "critical", "security", new("/security?tab=audit"))

		_, _ = execSQL(ctx, db, "UPDATE settings SET value = $1 WHERE key = $2", strconv.FormatInt(atime, 10), key)
	}

	dash := func(s []string) string {
		if len(s) == 0 {
			return "-"
		}
		return strings.Join(s, ", ")
	}
	// Not armed at all: say so once per process, at WARN — otherwise the
	// feature's only behaviour on a stock install is silence, identical to a
	// working tripwire.
	if examined == 0 {
		if !autoHealerCanaryWarned.Swap(true) {
			slog.Warn(fmt.Sprintf("Canary file monitoring is enabled but NOT ARMED — 0 of %d canary paths are "+
				"being watched, so no alert can ever fire. %d are absent and can be planted "+
				"from Settings > Security Hardening > Arm canary files (%s); %d cannot be "+
				"watched by this process at all under ProtectHome= and planting them would "+
				"not help (%s). Arm them, or turn the setting off so the panel stops "+
				"implying a tripwire exists.", len(paths), len(absent), dash(absent), len(masked), dash(masked)))
		}
	} else if len(masked) > 0 {
		// Partially armed used to look identical to fully armed.
		if !autoHealerCanaryPartial.Swap(true) {
			slog.Warn(fmt.Sprintf("Canary monitoring is PARTIAL — watching %d of %d paths. %d cannot be "+
				"observed by this process under ProtectHome= (%s), so an intruder reading them "+
				"raises no alert.", examined, len(paths), len(masked), strings.Join(masked, ", ")))
		}
	}
}

// autoHealerSecurityCheckLockdownExpiry auto-expires a lockdown after 24h.
func autoHealerSecurityCheckLockdownExpiry(ctx context.Context, db *pgxpool.Pool) {
	row, _ := queryOpt[Tup2[bool, *time.Time]](ctx, db, "SELECT active, triggered_at FROM lockdown_state WHERE id = 1")
	if row == nil || !row.A || row.B == nil {
		return
	}
	hoursLocked := int64(time.Since(*row.B) / time.Hour)
	if hoursLocked >= 24 {
		SecurityHardeningDeactivateLockdown(ctx, db, "auto-expire (24h)")
		SecurityHardeningAuditLog(ctx, db, "lockdown.auto_expire", nil, nil,
			new("system"), nil, new(fmt.Sprintf("Lockdown auto-expired after %dh", hoursLocked)),
			nil, "info", nil)
		slog.Info(fmt.Sprintf("Lockdown auto-expired after %dh", hoursLocked))
	}
}

// autoHealerAutoSleepIdleContainers stops containers idle beyond their
// configured threshold.
func autoHealerAutoSleepIdleContainers(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	// server_id (added in v2.80.0) is what makes this loop fleet-correct.
	// Before it, every leg ran against the panel's own agent and auto-sleep
	// was quietly inoperative for every fleet member.
	type cfgRow struct {
		ContainerID       string     `db:"container_id"`
		ContainerName     string     `db:"container_name"`
		Domain            *string    `db:"domain"`
		SleepAfterMinutes int32      `db:"sleep_after_minutes"`
		ServerID          *uuid.UUID `db:"server_id"`
		GPUEnabled        bool       `db:"gpu_enabled"`
	}
	configs, _ := queryAll[cfgRow](ctx, db,
		"SELECT container_id, container_name, domain, sleep_after_minutes, server_id, gpu_enabled "+
			"FROM container_sleep_config "+
			"WHERE auto_sleep_enabled = true AND is_sleeping = false")
	if len(configs) == 0 {
		return
	}

	now := time.Now()
	for _, c := range configs {
		// Resolve the host from the row. A NULL means a writer that does not
		// set the column yet — refuse rather than fall back to this box, the
		// behaviour that made the bug invisible.
		if c.ServerID == nil {
			slog.Warn(fmt.Sprintf("Auto-sleep: %s has no server recorded — skipping. "+
				"Guessing a host here would stop a container on the wrong machine.", c.ContainerName))
			continue
		}
		agent, err := agents.ForServer(ctx, *c.ServerID)
		if err != nil {
			slog.Warn(fmt.Sprintf("Auto-sleep: %s lives on server %s, which is "+
				"unreachable (%v) — skipping this cycle rather than acting on "+
				"a different host.", c.ContainerName, *c.ServerID, err))
			continue
		}

		// Real traffic counts as activity, and it is the only thing that
		// should. Without this, "idle" meant "nobody used the *panel*", and a
		// container serving requests every few seconds was stopped out from
		// under its users. Ask nginx when the domain last answered.
		if c.Domain != nil && *c.Domain != "" {
			if res, err := agent.Get(ctx, "/nginx/last-activity/"+*c.Domain); err == nil {
				// null = unknown (no access log yet), not idle.
				if secs, ok := jsonU64(jsonGet(res, "seconds_ago")); ok {
					seen := time.Now().Add(-time.Duration(int64(secs)) * time.Second)
					_, _ = execSQL(ctx, db,
						"UPDATE container_sleep_config SET last_activity_at = $2 "+
							"WHERE container_id = $1 "+
							"AND (last_activity_at IS NULL OR last_activity_at < $2)", c.ContainerID, seen)
				}
			}
		}

		// A GPU workload doing headless compute is invisible to the nginx
		// check above; a process this agent attributes to this container's
		// name counts as activity exactly like HTTP traffic does.
		if c.GPUEnabled {
			if gpu, err := agent.Get(ctx, "/apps/gpu-info"); err == nil {
				active := false
				if procs, ok := jsonArr(jsonGet(gpu, "processes")); ok {
					for _, p := range procs {
						if n, ok := jsonStr(jsonGet(p, "container_name")); ok && n == c.ContainerName {
							active = true
							break
						}
					}
				}
				if active {
					_, _ = execSQL(ctx, db,
						"UPDATE container_sleep_config SET last_activity_at = NOW() WHERE container_id = $1", c.ContainerID)
				}
			}
		}

		last, _ := queryScalarOpt[*time.Time](ctx, db,
			"SELECT last_activity_at FROM container_sleep_config WHERE container_id = $1", c.ContainerID)

		idle := false
		if last != nil && *last != nil {
			idle = int64(now.Sub(**last)/time.Minute) >= int64(c.SleepAfterMinutes)
		} else if res, err := agent.Get(ctx, "/apps"); err == nil {
			// No activity recorded yet — first run: if it is running, record
			// activity and skip; if not, nothing to sleep.
			if apps, ok := jsonArr(res); ok {
				for _, a := range apps {
					id, _ := jsonStr(jsonGet(a, "container_id"))
					st, _ := jsonStr(jsonGet(a, "status"))
					if id == c.ContainerID && st == "running" {
						_, _ = execSQL(ctx, db,
							"UPDATE container_sleep_config SET last_activity_at = NOW() WHERE container_id = $1", c.ContainerID)
						break
					}
				}
			}
		}
		if !idle {
			continue
		}

		slog.Info(fmt.Sprintf("Auto-sleeping idle container: %s (%s)", c.ContainerName, c.ContainerID))
		if _, err := agent.Post(ctx, "/apps/"+c.ContainerID+"/stop", nil); err != nil {
			slog.Warn(fmt.Sprintf("Failed to auto-sleep container %s: %v", c.ContainerName, err))
			continue
		}
		_, _ = execSQL(ctx, db,
			"UPDATE container_sleep_config SET is_sleeping = true, last_slept_at = NOW(), "+
				"total_sleeps = total_sleeps + 1, updated_at = NOW() "+
				"WHERE container_id = $1", c.ContainerID)

		// No person initiates an auto-sleep, so the actor is NULL.
		ExpectedStopsRecord(ctx, db, *c.ServerID, c.ContainerName, ExpectedStopsReasonAutoSleep, nil)
		ExpectedStopsResolveOpenContainerDown(ctx, db, *c.ServerID, c.ContainerName)

		// No user initiates it and container_sleep_config names no owner, so
		// this genuinely has no user — which is what NULL is for. It passed the
		// nil uuid, so the insert was rejected and no audit record existed.
		ActivityLogActivitySystem(ctx, db, "auto-sleeper", "container.auto_sleep",
			new("container"), new(c.ContainerName),
			new(fmt.Sprintf("Idle %d+ minutes", c.SleepAfterMinutes)), nil, nil)

		NotificationsNotifyPanel(ctx, db, nil, "Auto-Sleep",
			fmt.Sprintf("Container %s auto-slept (idle %d+ min)", c.ContainerName, c.SleepAfterMinutes),
			"info", "system", new("/apps"))
	}
}
