package api

// Port of panel/backend/src/services/security_scanner.rs.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// securityScannerOptStr is `v.as_str()` as an Option: nil unless v is a string.
func securityScannerOptStr(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

// securityScannerStrOr is `v.as_str().unwrap_or(def)`.
func securityScannerStrOr(v any, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

// securityScannerJSONString is serde_json::Value::to_string.
func securityScannerJSONString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// securityScannerSleep waits d or until ctx is cancelled (false).
func securityScannerSleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// SecurityScannerRun is the background task: weekly security scans,
// automatically, on every server.
//
// This scanner's subject is a MACHINE, not a row — it asks an agent what it
// found — so there was no per-row server_id to thread and it needs the fleet
// loop instead. Until v2.58.0 it asked the panel's own agent once a week and
// recorded the answer with a NULL host, so a fleet's members were never
// scanned at all: not mislabelled, simply never looked at.
func SecurityScannerRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	slog.Info("Security scanner background task started (weekly)")

	// Initial delay: 5 minutes after startup (respects shutdown).
	if !securityScannerSleep(ctx, 300*time.Second) {
		slog.Info("Security scanner shutting down gracefully (during initial delay)")
		return
	}

	for {
		for _, member := range agents.OnlineFleet(ctx) {
			// Is THIS server due? The cadence gate used to be fleet-wide, which
			// on a fleet meant the first host scanned satisfied it for every
			// other host. It also counted rows of ANY status, so a single failed
			// or interrupted scan bought a whole week of no scanning at all.
			// Only a COMPLETED scan proves the machine was looked at.
			recent, _ := queryScalarOpt[int64](ctx, db,
				"SELECT COUNT(*) FROM security_scans "+
					"WHERE server_id = $1 AND status = 'completed' "+
					"AND created_at > NOW() - INTERVAL '7 days'", member.ID)
			if recent == nil || *recent == 0 {
				slog.Info("Running scheduled weekly security scan on " + member.Name)
				securityScannerRunScan(ctx, db, member, agents.JWTSecret())
			}
		}

		// Check every 6 hours if a weekly scan is due (respects shutdown).
		if !securityScannerSleep(ctx, 6*3600*time.Second) {
			slog.Info("Security scanner shutting down gracefully")
			return
		}
	}
}

func securityScannerRunScan(ctx context.Context, db *pgxpool.Pool, member AgentFleetMember, jwtSecret string) {
	agent := member.Agent

	// Create scan record, naming the host it is a scan OF.
	scanID, err := queryScalar[uuid.UUID](ctx, db,
		"INSERT INTO security_scans (server_id, scan_type, status) VALUES ($1, 'full', 'running') RETURNING id",
		member.ID)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to create scan record: %v", err))
		return
	}

	result, err := agent.Post(ctx, "/security/scan", nil)
	if err != nil {
		slog.Error(fmt.Sprintf("Security scan failed: %v", err))
		SystemLogLogEvent(ctx, db, "error", "security_scanner", "Scheduled security scan failed", new(err.Error()))
		_, _ = execSQL(ctx, db, "UPDATE security_scans SET status = 'failed', completed_at = NOW() WHERE id = $1", scanID)
		return
	}

	findings, hasFindings := jsonArr(jsonGet(result, "findings"))
	fileHashes, hasHashes := jsonArr(jsonGet(result, "file_hashes"))

	var critical, warning, info int32
	if hasFindings {
		for _, f := range findings {
			severity := securityScannerStrOr(jsonGet(f, "severity"), "info")
			switch severity {
			case "critical":
				critical++
			case "warning":
				warning++
			default:
				info++
			}
			_, _ = execSQL(ctx, db,
				"INSERT INTO security_findings (scan_id, check_type, severity, title, description, file_path, remediation) "+
					"VALUES ($1, $2, $3, $4, $5, $6, $7)",
				scanID,
				securityScannerStrOr(jsonGet(f, "check_type"), ""),
				severity,
				securityScannerStrOr(jsonGet(f, "title"), ""),
				securityScannerOptStr(jsonGet(f, "description")),
				securityScannerOptStr(jsonGet(f, "file_path")),
				securityScannerOptStr(jsonGet(f, "remediation")))
		}
	}

	// File integrity check against baselines.
	if hasHashes {
		for _, h := range fileHashes {
			path := securityScannerStrOr(jsonGet(h, "path"), "")
			hash := securityScannerStrOr(jsonGet(h, "hash"), "")
			size, _ := jsonI64(jsonGet(h, "size"))

			// One row per (server, path) now that the upsert below actually
			// upserts, so this is a keyed lookup rather than "whichever of the
			// eighteen duplicates the heap returned first".
			oldHash, _ := queryScalarOpt[string](ctx, db,
				"SELECT sha256_hash FROM file_integrity_baselines "+
					"WHERE server_id = $1 AND file_path = $2", member.ID, path)
			if oldHash != nil && *oldHash != hash {
				_, _ = execSQL(ctx, db,
					"INSERT INTO security_findings (scan_id, check_type, severity, title, description, file_path, remediation) "+
						"VALUES ($1, 'file_integrity', 'warning', $2, $3, $4, 'Verify this change was intentional')",
					scanID, "File modified: "+path, fmt.Sprintf("Hash changed from %s to %s", *oldHash, hash), path)
				warning++
			}

			// Binding the host is what ARMS this upsert. The arbiter named a
			// column the INSERT never supplied, and a NULL never conflict-matches,
			// so DO UPDATE had never executed and the baseline never advanced
			// past the first scan.
			_, _ = execSQL(ctx, db,
				"INSERT INTO file_integrity_baselines (server_id, file_path, sha256_hash, file_size) "+
					"VALUES ($1, $2, $3, $4) "+
					"ON CONFLICT (server_id, file_path) DO UPDATE SET sha256_hash = $3, file_size = $4, updated_at = NOW()",
				member.ID, path, hash, size)
		}
	}

	total := critical + warning + info
	_, _ = execSQL(ctx, db,
		"UPDATE security_scans SET status = 'completed', completed_at = NOW(), "+
			"findings_count = $1, critical_count = $2, warning_count = $3, info_count = $4 "+
			"WHERE id = $5", total, critical, warning, info, scanID)

	slog.Info(fmt.Sprintf("Security scan completed: %d findings (%d critical, %d warning, %d info)", total, critical, warning, info))

	// Give any Docker App deployed BEFORE migration 20260905180000 an owner
	// row, so this same scan's own ssl_expiry auto-fix below can find it.
	securityScannerReconcileDockerAppDomains(ctx, db, member)

	// Auto-fix safe findings (non-destructive only).
	if hasFindings {
		SecurityScannerAutoFixSafeFindings(ctx, db, member, findings, jwtSecret)
	}

	// Keep only last 90 days of scans.
	_, _ = execSQL(ctx, db, "DELETE FROM security_findings WHERE scan_id IN (SELECT id FROM security_scans WHERE created_at < NOW() - INTERVAL '90 days')")
	_, _ = execSQL(ctx, db, "DELETE FROM security_scans WHERE created_at < NOW() - INTERVAL '90 days'")

	// Auto-resolve prior firing security alerts so the new scan's result is
	// the single source of truth. Scoped to the scanned host: a clean scan on
	// one machine must not silently close another machine's alerts. Routed
	// through resolve_alert (mirroring how sendScanAlerts fires per admin) so a
	// clearing finding sends the same mute-aware "Resolved: …" notice every
	// other alert type gets — a raw UPDATE cleared the row with nobody told.
	resolveAdmins, _ := queryAll[uuid.UUID](ctx, db, "SELECT id FROM users WHERE role = 'admin'")
	resolvedTitle := "Security alert resolved on " + member.Name
	resolvedMessage := fmt.Sprintf("A later scan of %s found no matching security issue — the earlier alert no longer applies.", member.Name)
	for _, userID := range resolveAdmins {
		NotificationsResolveAlert(ctx, db, userID, new(member.ID), nil, "security", "", resolvedTitle, resolvedMessage)
	}
	// resolve_alert only clears status = 'firing'. Security's own dashboard
	// bookkeeping additionally wants an acknowledged-then-fixed row off the
	// Alerts list; nothing notifies on that transition either way, so it stays
	// a narrowly-scoped direct UPDATE rather than a second, silent resolve path.
	_, _ = execSQL(ctx, db,
		"UPDATE alerts SET status = 'resolved', resolved_at = NOW() "+
			"WHERE alert_type = 'security' AND server_id = $1 AND status = 'acknowledged'", member.ID)

	if critical > 0 || warning > 0 {
		securityScannerSendScanAlerts(ctx, db, member, critical, warning, total)
	} else {
		NotificationsNotifyPanel(ctx, db, nil, "Security scan: all clear",
			"No vulnerabilities or issues detected on "+member.Name, "info", "security", new("/security"))
	}
}

// securityScannerSslRenewalDeclinedAlert: a renewal DockPanel deliberately
// did not perform, because the certificate is not one it issued.
//
// Deliberately NOT ssl_renewal_alert: "SSL renewal failed", "could not renew
// it automatically" and severity critical are all false here. Nothing failed;
// the panel declined, correctly, to overwrite somebody else's certificate.
// Paging that operator would train them to ignore the alert that means their
// site is about to go dark. Same alert_type, so routing/dedupe are unchanged.
func securityScannerSslRenewalDeclinedAlert(ctx context.Context, db *pgxpool.Pool, userID, siteID uuid.UUID, domain, issuer string) {
	NotificationsFireAlertDeduped(ctx, db, userID, nil, new(siteID), "ssl_renewal_failure",
		NotificationsSslRenewalKeyDeclined, "warning",
		fmt.Sprintf("SSL certificate for %s needs renewing by you", domain),
		fmt.Sprintf("The certificate for %s is expiring, and DockPanel did not renew it "+
			"because it did not issue it: it was issued by %s. Renewing here would "+
			"have replaced your certificate with a Let's Encrypt one. Renew it wherever it "+
			"was issued and upload the replacement under the site's SSL tab.", domain, issuer),
		12)
}

// securityScannerSslRenewalAlert raises an alert when a certificate this
// scanner found to be expiring cannot be renewed. Deduped per site so the
// six-hourly scan cannot stack duplicates alongside the auto-healer's own.
func securityScannerSslRenewalAlert(ctx context.Context, db *pgxpool.Pool, userID, siteID uuid.UUID, domain, reason string) {
	NotificationsFireAlertDeduped(ctx, db, userID, nil, new(siteID), "ssl_renewal_failure",
		NotificationsSslRenewalKeyFailed, "critical",
		"SSL renewal failed: "+domain,
		fmt.Sprintf("The certificate for %s is expiring and DockPanel could not renew "+
			"it automatically: %s. The site will stop loading when the "+
			"certificate expires.", domain, reason),
		12)
}

// securityScannerSslDns01DeclinedAlert: a DNS-01 certificate this loop
// DECLINED to renew, while the cause is still fixable. Not the failure
// helper — that says "SSL renewal failed" and pages critical; neither is
// true of a refusal the panel made on purpose.
func securityScannerSslDns01DeclinedAlert(ctx context.Context, db *pgxpool.Pool, userID, siteID uuid.UUID, domain, reason string) {
	NotificationsFireAlertDeduped(ctx, db, userID, nil, new(siteID), "ssl_renewal_failure",
		NotificationsSslRenewalKeyDns01Declined, "warning",
		fmt.Sprintf("SSL certificate for %s needs a Cloudflare zone", domain),
		reason, 12)
}

// securityScannerSslDns01DowngradedAlert: a DNS-01 certificate downgraded to
// a single name on purpose, in its last week. critical, because names stopped
// being covered — but never worded as a failure: a certificate WAS installed.
func securityScannerSslDns01DowngradedAlert(ctx context.Context, db *pgxpool.Pool, userID, siteID uuid.UUID, domain, losing string) {
	NotificationsFireAlertDeduped(ctx, db, userID, nil, new(siteID), "ssl_renewal_failure",
		NotificationsSslRenewalKeyDns01Downgraded, "critical",
		"SSL certificate downgraded: "+domain,
		fmt.Sprintf("The certificate for %s covered %s and could not be re-ordered over "+
			"DNS-01 before it expired, so DockPanel issued a single-name certificate for "+
			"%s instead. Any other name it covered is no longer covered.", domain, losing, domain),
		12)
}

// securityScannerReconcileDockerAppDomains gives every currently-deployed
// Docker App with a domain an owner row in docker_app_domains, if it doesn't
// already have one.
//
// Migration 20260905180000 only writes this table going FORWARD
// (docker_apps::deploy's INSERT). An app deployed before it, or restored from
// a backup taken before it, never gets a row and stays invisible to
// securityScannerRenewDockerAppCertificate. A Docker app has no pre-existing
// row to backfill ("Docker apps are not rows"), so recovering one means asking
// the agent what is actually running.
//
// Deliberately conservative: tls_mode/ssl_email are left NULL (unknown) so a
// reconciled row can never be mistaken for a confirmed ACME certificate and
// trigger a renewal over an operator-provided one. ON CONFLICT DO NOTHING: an
// existing row carries real deploy-time values and must never be clobbered.
// Runs once per scheduled scan so a row lost to a DB restore self-heals.
func securityScannerReconcileDockerAppDomains(ctx context.Context, db *pgxpool.Pool, member AgentFleetMember) {
	apps, err := member.Agent.Get(ctx, "/apps")
	if err != nil {
		slog.Warn(fmt.Sprintf("Docker-app SSL reconciliation skipped for %s: could not list apps (%v)", member.Name, err))
		return
	}
	arr, ok := jsonArr(apps)
	if !ok {
		return
	}
	for _, app := range arr {
		domain, ok := jsonStr(jsonGet(app, "domain"))
		if !ok || domain == "" {
			continue
		}
		name, ok := jsonStr(jsonGet(app, "name"))
		if !ok {
			continue
		}
		uidStr, _ := jsonStr(jsonGet(app, "user_id"))
		userID, err := uuid.Parse(uidStr)
		if err != nil {
			// No dockpanel.user.id label — a deployment old enough to predate
			// that label too. Nothing safe to attribute the row to.
			slog.Debug(fmt.Sprintf("Docker-app SSL reconciliation: skipping %s on %s — no owning user_id label", name, member.Name))
			continue
		}
		_, _ = execSQL(ctx, db,
			"INSERT INTO docker_app_domains (user_id, server_id, app_name, domain) "+
				"VALUES ($1, $2, $3, $4) "+
				"ON CONFLICT (server_id, domain) DO NOTHING",
			userID, member.ID, name, domain)
	}
}

type securityScannerSiteRow struct {
	ID         uuid.UUID `db:"id"`
	Runtime    string    `db:"runtime"`
	ProxyPort  *int32    `db:"proxy_port"`
	PHPVersion *string   `db:"php_version"`
	RootPath   *string   `db:"root_path"`
	UserID     uuid.UUID `db:"user_id"`
	SSLProfile *string   `db:"ssl_profile"`
}

// SecurityScannerAutoFixSafeFindings auto-fixes safe findings after a scan
// completes. Only fixes things that are SAFE to fix automatically (SSL
// renewal). Never auto-fixes malware, open ports, or config changes that
// could break things. jwtSecret is the key stored credentials are encrypted
// under, so a DNS-01 renewal here can open the Cloudflare token that ISSUED
// the certificate — this loop has no AppState and no session.
func SecurityScannerAutoFixSafeFindings(ctx context.Context, db *pgxpool.Pool, member AgentFleetMember, findings []any, jwtSecret string) {
	agent := member.Agent
	for _, f := range findings {
		switch securityScannerStrOr(jsonGet(f, "check_type"), "") {
		case "ssl_expiry":
			// Extract domain from the title: "SSL certificate expiring: example.com"
			title := securityScannerStrOr(jsonGet(f, "title"), "")
			domain, ok := strings.CutPrefix(title, "SSL certificate expiring: ")
			if !ok || domain == "" {
				continue
			}

			// Look up site details ON THE HOST THAT RAISED THE FINDING. A
			// domain is unique only per server (idx_sites_domain_server), so a
			// lookup on the name alone can hand back another host's row: this
			// renewed with the other host's config, wrote the new expiry onto
			// the other host's row, and pushed that host's vhost through THIS
			// host's agent. Unattended, on the scan loop's own schedule.
			site, _ := queryOpt[securityScannerSiteRow](ctx, db,
				"SELECT s.id, s.runtime, s.proxy_port, s.php_version, s.root_path, s.user_id, "+
					"s.ssl_profile "+
					"FROM sites s WHERE s.domain = $1 AND s.server_id = $2 AND s.ssl_enabled = TRUE",
				domain, member.ID)
			if site == nil {
				// The subject came from the agent's FILESYSTEM walk of
				// /etc/dockpanel/ssl, which is where a Compose stack's — and a
				// Docker app's — ACME certificate also lands. Neither can ever
				// own a sites row, so this read cannot match either; until
				// v2.161.0 they fell out here with no log, alert or renewal.
				if !securityScannerRenewStackCertificate(ctx, db, member, domain) &&
					!securityScannerRenewDockerAppCertificate(ctx, db, member, domain) {
					slog.Info(fmt.Sprintf("Auto-fix: %s is expiring on %s but matches neither a site, a "+
						"Compose stack, nor a Docker app on that host — nothing here can "+
						"renew it", domain, member.Name))
				}
				continue
			}
			siteID, userID := site.ID, site.UserID

			ownerEmail, _ := queryScalarOpt[string](ctx, db, "SELECT email FROM users WHERE id = $1", userID)
			if ownerEmail == nil {
				slog.Warn(fmt.Sprintf("Auto-fix: cannot renew SSL for %s — owner email not found", domain))
				securityScannerSslRenewalAlert(ctx, db, userID, siteID, domain,
					"the site's owner account has no email address on file")
				continue
			}

			// Resolve through the SAME path issuance uses. Without this the
			// panel-wide acme_contact_email rescue applies only when a human
			// clicks, so a box whose owner address cannot be an ACME contact
			// issues fine and then silently fails to renew ~60 days later.
			email, rerr := rtSslResolveAcmeContact(ctx, db, *ownerEmail)
			if rerr != nil {
				slog.Warn(fmt.Sprintf("Auto-fix: cannot renew SSL for %s — %v", domain, rerr))
				securityScannerSslRenewalAlert(ctx, db, userID, siteID, domain, rerr.Error())
				continue
			}

			// ⛔ DO NOT REPLACE A CERTIFICATE THIS PRODUCT DID NOT ISSUE.
			//
			// This is the ONLY automatic renewal on a stock install, reached
			// with no opt-in. The finding comes from the agent walking
			// /etc/dockpanel/ssl with `openssl -checkend`, which never looks at
			// the issuer — so an uploaded commercial/Origin-CA/corporate
			// certificate was silently replaced by a full ACME order a month
			// before expiry, every week, on every install.
			//
			// nil means "not proven foreign" (unreachable agent, unreadable
			// cert) and MUST still renew: refusing on doubt would let a genuine
			// Let's Encrypt certificate lapse.
			if issuer := foreignCertIssuer(ctx, agent, domain); issuer != nil {
				slog.Info(fmt.Sprintf("Auto-fix: NOT renewing %s — the installed certificate was "+
					"issued by %s, not by DockPanel. Renewing would replace it.", domain, *issuer))
				securityScannerSslRenewalDeclinedAlert(ctx, db, userID, siteID, domain, *issuer)
				continue
			}

			slog.Info("Auto-fix: renewing expiring SSL certificate for " + domain)

			agentBody := map[string]any{"email": email, "runtime": site.Runtime}
			if site.ProxyPort != nil {
				agentBody["proxy_port"] = *site.ProxyPort
			}
			if site.PHPVersion != nil {
				agentBody["php_socket"] = fmt.Sprintf("unix:/run/php/php%s-fpm.sock", *site.PHPVersion)
			}
			if site.RootPath != nil {
				agentBody["root"] = *site.RootPath
			}
			// The site's chosen certificate profile travels with the renewal.
			// Omitting it does not fail: the CA quietly issues its DEFAULT
			// profile, the column keeps naming the retired choice, and the
			// cooldown/margin helpers keep reading that stale column.
			if site.SSLProfile != nil {
				agentBody["profile"] = *site.SSLProfile
			}

			// WHICH CHALLENGE ISSUED THIS CERTIFICATE decides which door renews
			// it. /ssl/provision/{domain} is the HTTP-01 provisioner, single
			// identifier — for a zone-apex wildcard that file is the shared
			// certificate every sibling vhost in the zone is serving.
			full, _ := queryOpt[Site](ctx, db, "SELECT * FROM sites WHERE id = $1", siteID)
			if full == nil {
				continue
			}
			var daysRemaining *int64
			if full.SSLExpiry != nil {
				daysRemaining = new(int64(time.Until(*full.SSLExpiry) / (24 * time.Hour)))
			}
			plan := renewalPlan(ctx, db, full, daysRemaining)

			if plan.Kind == RenewRefuse {
				// ⚠ A DIFFERENT sentence from the foreign-issuer stop above, so
				// neither stop can satisfy the arm written for the other.
				slog.Warn(fmt.Sprintf("Auto-fix: DNS-01 renewal declined for %s — %s", domain, plan.Reason))
				securityScannerSslDns01DeclinedAlert(ctx, db, userID, siteID, domain, plan.Reason)
				continue
			}

			// ⛔ PostLong with the shared budget, not Post. Plain Post caps at
			// 60s and a wildcard DNS-01 order budgets ~260s in the agent alone.
			var result any
			var oerr error
			if plan.Kind == RenewDNS01 {
				result, oerr = rtSslRenewOverDns01(ctx, db, jwtSecret, agent, plan.Subject, plan.Wildcard, plan.ZoneID, userID, site.SSLProfile)
			} else {
				result, oerr = agent.PostLong(ctx, "/ssl/provision/"+domain, agentBody, rtSslDns01OrderTimeoutSecs)
			}
			if oerr != nil {
				slog.Warn(fmt.Sprintf("Auto-fix: SSL renewal failed for %s: %v", domain, oerr))
				// The auto-healer alerts when its own renewal fails; this path
				// used to end at the log line, so visibility depended on which
				// loop reached the certificate first.
				securityScannerSslRenewalAlert(ctx, db, userID, siteID, domain, oerr.Error())
				continue
			}
			slog.Info("Auto-fix: SSL renewed successfully for " + domain)

			// Record the certificate we just installed. This path used to drop
			// the agent's expiry, so the dashboard countdown ran to zero and
			// check_ssl_expiry walked the whole warning ladder on a certificate
			// that had renewed perfectly — and could never recover. All three
			// columns move together: a surviving ssl_renewal_at is an ARI window
			// computed for the certificate this one just replaced.
			rawExpiry := jsonGet(result, "expiry")
			var expiry *time.Time
			if s, ok := jsonStr(rawExpiry); ok {
				expiry = parseAgentCertExpiry(s)
			}
			if expiry != nil {
				_, _ = execSQL(ctx, db,
					"UPDATE sites SET ssl_expiry = $1, ssl_renewal_at = NULL, "+
						"ssl_renewal_checked_at = NULL, updated_at = NOW() WHERE id = $2", *expiry, siteID)
			} else {
				slog.Warn(fmt.Sprintf("Auto-fix: renewed %s but could not read the new expiry "+
					"from the agent (raw: %v) — the countdown and the expiry "+
					"alert will keep describing the retired certificate", domain, rawExpiry))
			}

			// Only after success: a failed HTTP-01 attempt on an unrecorded
			// row must stay unrecorded — the likeliest reason it failed is that
			// this site cannot answer HTTP-01, the case that made DNS-01 right.
			rtSslRecordRenewalProvenance(ctx, db, siteID, domain, plan)
			if plan.Kind == RenewLastResortHTTP01 {
				securityScannerSslDns01DowngradedAlert(ctx, db, userID, siteID, domain, plan.Losing)
			}

			// A renewal that succeeded disproves the alerts saying one had
			// not, and leaves the downgrade alert above alone.
			NotificationsResolveSslRenewalFailure(ctx, db, userID, siteID, domain)

			// Preserve the site's full config (WAF/CSP/Permissions-Policy/
			// rate-limit/custom_nginx/bot-protection) — the agent's provision
			// only renders a subset. Best-effort. Keyed on the id resolved
			// above, never the domain (unique only per server).
			if s, err := queryOne[Site](ctx, db, "SELECT * FROM sites WHERE id = $1", siteID); err == nil {
				// A site the operator disabled must not be put back into
				// service by a renewal nobody watched — the rebuild used to be
				// written straight over the maintenance response. Agents from
				// v2.74.0 park the body instead, but an agent is only updated
				// when somebody updates it; declining here makes the fix arrive
				// with the PANEL. (Retracted at v2.145.0: "nothing is lost by
				// skipping" was false — the skip is right only because a
				// disabled site is not serving.)
				if !s.Enabled {
					slog.Info(fmt.Sprintf("Auto-fix: renewed SSL for %s but skipped the vhost rebuild — the site is disabled", s.Domain))
				} else if _, err := agent.Put(ctx, "/nginx/sites/"+s.Domain, rtSitesBuildNginxBody(&s)); err != nil {
					slog.Warn(fmt.Sprintf("Auto-fix: full vhost rebuild after SSL renewal failed for %s: %v", s.Domain, err))
				}
			}

			SystemLogLogEvent(ctx, db, "info", "security_scanner", "Auto-renewed SSL certificate for "+domain, nil)

		case "security_headers":
			// Logged as recommendation only: headers are already in nginx
			// templates — this finding means custom config. Don't auto-fix.
			slog.Info("Auto-fix: security headers — logged as recommendation for " +
				securityScannerStrOr(jsonGet(f, "title"), "unknown"))

		default:
			// Don't auto-fix: malware, open_port, container_vuln, file_integrity.
		}
	}
}

// SecurityScannerStackRenewalStateKey is the state_key a stack renewal
// failure both FIRES and RESOLVES under.
//
// ⛔ ONE spelling, computed in ONE place, called by both sides. A fire and a
// resolve that spell the key separately are a severed pair: the alert fires,
// the resolve misses, and it pages every thirty minutes for a week about a
// certificate that is already healthy.
//
// The domain has to be IN the key: fire_alert_deduped dedups on (alert_type,
// site_id, state_key) and ignores server_id, so with site_id NULL every
// failing stack on every host would share one twelve-hour bucket.
func SecurityScannerStackRenewalStateKey(domain string) string {
	return securityScannerStackDomainStateKey(NotificationsSslRenewalKeyFailed, domain)
}

// SecurityScannerStackSslExpiryStateKey is the state_key a stack's
// SSL-expiry warning ladder fires and resolves under (alert_engine's
// check_stack_ssl_expiry). alert_state/alerts have no docker_stack_id column,
// so two stacks on one server sharing an empty key would collide.
func SecurityScannerStackSslExpiryStateKey(domain string) string {
	return securityScannerStackDomainStateKey("expiry", domain)
}

// securityScannerTruncatedKey is the shared truncate-then-hash logic.
//
// ⚠ alerts.state_key is VARCHAR(100). A hostname may be 253 bytes, so the
// obvious format overflows the column and the INSERT fails — the alert then
// silently never fires at all. When the readable form does not fit, the name
// is truncated AND a digest of the WHOLE name is appended: truncation alone
// would collide two long siblings into one bucket.
//
// ⚠ Taken by CHARACTER, not by byte: this domain is a directory name read off
// disk, not a validated field, so a byte slice could split a multi-byte
// sequence.
func securityScannerTruncatedKey(prefix, name string) string {
	const max = 100
	readable := prefix + name
	if len(readable) <= max {
		return readable
	}
	sum := sha256.Sum256([]byte(name))
	digest := hex.EncodeToString(sum[:])
	budget := max - len(prefix) - 17
	keep := name
	if utf8.RuneCountInString(name) > budget {
		keep = string([]rune(name)[:budget])
	}
	// 16 hex characters of SHA-256 — collision-free for any realistic number
	// of domains on one panel, and keeps enough of the name to be recognisable.
	return fmt.Sprintf("%s%s-%s", prefix, keep, digest[:16])
}

// securityScannerStackDomainStateKey: ⛔ ONE spelling per kind, called by
// both the fire and the resolve side of whichever ladder uses it.
func securityScannerStackDomainStateKey(kind, domain string) string {
	return securityScannerTruncatedKey("stack:"+kind+":", domain)
}

// SecurityScannerDockerAppRenewalStateKey is the Docker-app sibling of
// SecurityScannerStackRenewalStateKey. A stack: and an app: prefix must never
// collide: the two renewal doors run independently and must not share a
// dedup bucket.
func SecurityScannerDockerAppRenewalStateKey(domain string) string {
	return securityScannerDockerAppDomainStateKey(NotificationsSslRenewalKeyFailed, domain)
}

func securityScannerDockerAppDomainStateKey(kind, domain string) string {
	return securityScannerTruncatedKey("app:"+kind+":", domain)
}

// SecurityScannerRegisteredCertExpiryStateKey is the state_key a REGISTERED
// certificate's SSL-expiry ladder fires and resolves under
// (alert_engine::check_registered_cert_expiry). Keyed on the certificate's
// alias: it may cover several SANs and has no single domain, and alias is
// unique per (server_id, alias).
func SecurityScannerRegisteredCertExpiryStateKey(alias string) string {
	return securityScannerTruncatedKey("cert:expiry:", alias)
}

// securityScannerAgentAtLeastStackRenewal is the agent version gate both
// in-place renewal doors share. An agent older than 2.161.0 parses `runtime`
// as required and answers 422 to the body they send — on every weekly scan.
// Read from /health, the route every agent has always carried. Returns the
// reported version for the log line.
func securityScannerAgentAtLeastStackRenewal(ctx context.Context, agent AgentHandle) (bool, *string) {
	var reported *string
	if v, err := agent.Get(ctx, "/health"); err == nil {
		reported = securityScannerOptStr(jsonGet(v, "version"))
	}
	if reported == nil {
		return false, nil
	}
	have := PanelUpdateSemverKey(reported)
	need := PanelUpdateSemverKey(new(rtTlsCertificatesStackRenewalMinAgent))
	return slices.Compare(have[:], need[:]) >= 0, reported
}

func securityScannerDerefOr(s *string, def string) string {
	if s == nil {
		return def
	}
	return *s
}

// securityScannerContact is `ssl_email.map(str::trim).filter(non-empty)`.
func securityScannerContact(e *string) (string, bool) {
	if e == nil {
		return "", false
	}
	t := strings.TrimSpace(*e)
	return t, t != ""
}

// securityScannerRenewStackCertificate renews the ACME certificate of a
// Compose STACK whose domain the site loop could not resolve.
//
// A SIBLING of the site path, deliberately — not a helper both call. Until
// v2.161.0 nothing re-ordered a stack's certificate on a schedule:
// docker_stacks carries no renewal columns, so every sites-keyed renewer is
// structurally blind to it, while the agent's weekly walk DID raise the
// finding — the operator was warned and then met two dead ends.
//
// Returns whether domain matched a docker_stacks row at all — NOT whether the
// renewal succeeded. false means "keep looking" (try a Docker app next).
func securityScannerRenewStackCertificate(ctx context.Context, db *pgxpool.Pool, member AgentFleetMember, domain string) bool {
	// 1. Resolve ON THE HOST THAT RAISED THE FINDING. ⛔ lower(domain),
	//    matching idx_docker_stacks_domain and domain_claim::find_occupant.
	type stackRow struct {
		ID       uuid.UUID `db:"id"`
		UserID   uuid.UUID `db:"user_id"`
		SSLEmail *string   `db:"ssl_email"`
		TLSMode  *string   `db:"tls_mode"`
	}
	stack, _ := queryOpt[stackRow](ctx, db,
		"SELECT id, user_id, ssl_email, tls_mode "+
			"FROM docker_stacks WHERE lower(domain) = lower($1) AND server_id = $2",
		domain, member.ID)
	if stack == nil {
		return false
	}
	stackID, userID := stack.ID, stack.UserID

	// 2. THE MODE GUARD. A `provided` stack serves an operator-supplied
	//    certificate from the registry; ordering for that domain would at best
	//    leave a second unused certificate on disk. ⛔ Reuse effective_tls_mode
	//    — the NULL⇒ssl_email rule must have ONE spelling.
	mode := rtStacksEffectiveTlsMode(stack.TLSMode, stack.SSLEmail)
	if mode != "acme" {
		// info, not debug: this branch DECLINES to act on a critical finding
		// the operator sees every week.
		slog.Info(fmt.Sprintf("Auto-fix: not renewing %s — the stack's TLS mode is '%s', not ACME. "+
			"The expiring file under /etc/dockpanel/ssl is a leftover; the stack serves its "+
			"registered certificate from the registry.", domain, mode))
		return true
	}

	// The agent's RenewRequest.email is required, so a blank address is a 422
	// rather than a renewal — reachable when the column literally says acme.
	contact, ok := securityScannerContact(stack.SSLEmail)
	if !ok {
		slog.Warn(fmt.Sprintf("Auto-fix: cannot renew %s — the stack is in ACME mode with no ssl_email, "+
			"and the agent requires a contact address to place an order", domain))
		return true
	}

	// 3. Agent version gate. ⛔ A warning and nothing else: an alert would page
	//    the operator weekly for ever about a machine that is merely behind.
	if okv, reported := securityScannerAgentAtLeastStackRenewal(ctx, member.Agent); !okv {
		slog.Warn(fmt.Sprintf("Auto-fix: not renewing the Compose stack certificate for %s — %s reports agent "+
			"%s, and renewing a stack in place needs %s or later. Update that server's agent.",
			domain, member.Name, securityScannerDerefOr(reported, "no readable version"), rtTlsCertificatesStackRenewalMinAgent))
		return true
	}

	// 3b. THE ISSUER GUARD — what is actually on disk, not what the row
	//     claims. A purchased certificate reaches that path by more than one
	//     route (upload_cert is keyed on domain, a former site leaves files
	//     behind, a hand install), and the registry migration backfilled every
	//     stack with a non-blank ssl_email to acme. nil means "not proven
	//     foreign" and MUST still renew.
	if issuer := foreignCertIssuer(ctx, member.Agent, domain); issuer != nil {
		slog.Info(fmt.Sprintf("Auto-fix: NOT renewing the Compose stack certificate for %s — the installed "+
			"certificate was issued by %s, not by DockPanel. Renewing would replace it.", domain, *issuer))
		return true
	}

	// 4. THE COOLDOWN, counting the rows step 6 writes. Its own action string
	//    (sharing auto_heal.renew_ssl would let one loop mute the other), and
	//    ⛔ SERVER-SCOPED: name-only made two hosts carrying the same domain
	//    share one six-hour budget.
	recent, _ := queryScalarOpt[int64](ctx, db,
		"SELECT COUNT(*) FROM activity_logs "+
			"WHERE action = 'auto_fix.renew_stack_ssl' "+
			"AND target_name = $1 "+
			"AND server_id = $2 "+
			"AND created_at > NOW() - INTERVAL '6 hours'", domain, member.ID)
	if recent != nil && *recent > 0 {
		return true
	}

	slog.Info("Auto-fix: renewing the Compose stack certificate for " + domain)

	// 5. Act. NO `runtime` key: that absence is the contract with the agent's
	//    in-place branch, which reloads nginx rather than re-rendering a vhost
	//    the panel cannot describe. No `profile` — docker_stacks has none.
	//    ⛔ PostLong with the shared budget, not Post.
	result, rerr := member.Agent.PostLong(ctx, "/ssl/"+domain+"/renew",
		map[string]any{"email": contact}, rtSslDns01OrderTimeoutSecs)
	success := rerr == nil

	// 6. Record — AND THIS ROW IS THE COOLDOWN step 4 counts. Named against
	//    the STACK'S OWN user_id (the nil uuid violated fk_activity_logs_user,
	//    so the gate counted 0 for ever) and written on BOTH outcomes.
	details := ""
	if success {
		details = securityScannerJSONString(result)
	} else {
		details = rerr.Error()
	}
	ActivityLogActivityOnServer(ctx, db, userID, "security-scanner", "auto_fix.renew_stack_ssl",
		new("stack"), new(domain),
		new(fmt.Sprintf("stack_id=%s, success=%t, result=%s", stackID, success, details)),
		nil, new(member.ID), nil)

	if success {
		slog.Info("Auto-fix: Compose stack certificate renewed for " + domain)

		// ⛔ THE PARSE IS MANDATORY: the agent prints the `time` crate's
		// Display, a STRING; ssl_expiry is TIMESTAMPTZ. A failed UPDATE is NOT
		// a failed renewal — the certificate is already on disk.
		raw := jsonGet(result, "expiry")
		var expiry *time.Time
		if s, ok := jsonStr(raw); ok {
			expiry = parseAgentCertExpiry(s)
		}
		if expiry != nil {
			if _, err := execSQL(ctx, db, "UPDATE docker_stacks SET ssl_expiry = $1 WHERE id = $2", *expiry, stackID); err != nil {
				slog.Warn(fmt.Sprintf("Auto-fix: renewed %s but could not record its expiry: %v", domain, err))
			}
		} else {
			// Wire-format drift; the renewal succeeded, only bookkeeping did not.
			slog.Info(fmt.Sprintf("Auto-fix: renewed %s but the agent's expiry was unreadable: %v", domain, raw))
		}
		SystemLogLogEvent(ctx, db, "info", "security_scanner",
			"Auto-renewed the Compose stack SSL certificate for "+domain, nil)

		// ⛔ A SUCCESS MUST CLEAR THE FAILURE IT FOLLOWS, or a previous week's
		// transient failure pages every thirty minutes for seven days about a
		// healthy certificate. Fired with server_id = member.ID, so
		// resolve_alert matches on the same four columns; the key comes from
		// the shared function.
		NotificationsResolveAlert(ctx, db, userID, new(member.ID), nil, "ssl_renewal_failure",
			SecurityScannerStackRenewalStateKey(domain),
			"SSL renewal recovered: "+domain,
			fmt.Sprintf("DockPanel renewed the certificate for the Compose stack on %s. "+
				"The earlier renewal failure is resolved.", domain))
	} else {
		slog.Warn(fmt.Sprintf("Auto-fix: Compose stack SSL renewal failed for %s: %v", domain, rerr))
		// 7. site_id nil — there is no sites row. The key names the domain,
		//    because fire_alert_deduped ignores server_id.
		NotificationsFireAlertDeduped(ctx, db, userID, new(member.ID), nil, "ssl_renewal_failure",
			SecurityScannerStackRenewalStateKey(domain), "critical",
			"SSL renewal failed: "+domain,
			fmt.Sprintf("The certificate for the Compose stack on %s is expiring and DockPanel "+
				"could not renew it automatically: %s. The stack will stop loading over "+
				"HTTPS when the certificate expires. Redeploying the stack reissues it.", domain, details),
			12)
	}
	return true
}

// securityScannerRenewDockerAppCertificate is the Docker-app sibling of
// securityScannerRenewStackCertificate — same contract (returns whether
// domain matched a docker_app_domains row), same reason for existing.
func securityScannerRenewDockerAppCertificate(ctx context.Context, db *pgxpool.Pool, member AgentFleetMember, domain string) bool {
	// 1. Resolve, ON THE HOST THAT RAISED THE FINDING.
	type appRow struct {
		ID       uuid.UUID `db:"id"`
		UserID   uuid.UUID `db:"user_id"`
		AppName  string    `db:"app_name"`
		SSLEmail *string   `db:"ssl_email"`
		TLSMode  *string   `db:"tls_mode"`
	}
	app, _ := queryOpt[appRow](ctx, db,
		"SELECT id, user_id, app_name, ssl_email, tls_mode "+
			"FROM docker_app_domains WHERE lower(domain) = lower($1) AND server_id = $2",
		domain, member.ID)
	if app == nil {
		return false
	}
	appID, userID, appName := app.ID, app.UserID, app.AppName

	// 1b. THE RECONCILED-ROW GUARD — a NULL tls_mode can only come from the
	//     reconciliation pass; deploy always binds a real value. Decline (never
	//     renew on unconfirmed ownership), but say why.
	if app.TLSMode == nil {
		slog.Info(fmt.Sprintf("Auto-fix: not renewing %s — Docker app %s's TLS ownership was "+
			"reconciled from an already-running container, and its certificate mode was never "+
			"recorded at deploy time. Redeploy the app (or confirm ownership manually) to enable "+
			"auto-renewal.", domain, appName))
		return true
	}

	// 2. THE MODE GUARD — identical reasoning to the stack arm.
	mode := rtStacksEffectiveTlsMode(app.TLSMode, app.SSLEmail)
	if mode != "acme" {
		slog.Info(fmt.Sprintf("Auto-fix: not renewing %s — Docker app %s's TLS mode is '%s', not "+
			"ACME. The expiring file under /etc/dockpanel/ssl is a leftover; the app serves its "+
			"registered certificate from the registry.", domain, appName, mode))
		return true
	}

	contact, ok := securityScannerContact(app.SSLEmail)
	if !ok {
		slog.Warn(fmt.Sprintf("Auto-fix: cannot renew %s — Docker app %s is in ACME mode with no "+
			"ssl_email, and the agent requires a contact address to place an order", domain, appName))
		return true
	}

	// 3. Agent version gate — the renewal below omits `runtime` for the same
	//    reason a stack's does.
	if okv, reported := securityScannerAgentAtLeastStackRenewal(ctx, member.Agent); !okv {
		slog.Warn(fmt.Sprintf("Auto-fix: not renewing the Docker app certificate for %s — %s reports agent "+
			"%s, and renewing in place needs %s or later. Update that server's agent.",
			domain, member.Name, securityScannerDerefOr(reported, "no readable version"), rtTlsCertificatesStackRenewalMinAgent))
		return true
	}

	// 3b. THE ISSUER GUARD — same reasoning as the stack arm.
	if issuer := foreignCertIssuer(ctx, member.Agent, domain); issuer != nil {
		slog.Info(fmt.Sprintf("Auto-fix: NOT renewing the Docker app certificate for %s — the installed "+
			"certificate was issued by %s, not by DockPanel. Renewing would replace it.", domain, *issuer))
		return true
	}

	// 4. THE COOLDOWN, counting the rows step 6 writes. Its own action string.
	recent, _ := queryScalarOpt[int64](ctx, db,
		"SELECT COUNT(*) FROM activity_logs "+
			"WHERE action = 'auto_fix.renew_docker_app_ssl' "+
			"AND target_name = $1 "+
			"AND server_id = $2 "+
			"AND created_at > NOW() - INTERVAL '6 hours'", domain, member.ID)
	if recent != nil && *recent > 0 {
		return true
	}

	slog.Info("Auto-fix: renewing the Docker app certificate for " + domain)

	// 5. Act. NO `runtime` key — see the version gate.
	result, rerr := member.Agent.PostLong(ctx, "/ssl/"+domain+"/renew",
		map[string]any{"email": contact}, rtSslDns01OrderTimeoutSecs)
	success := rerr == nil

	// 6. Record — AND THIS ROW IS THE COOLDOWN. Written on BOTH outcomes.
	details := ""
	if success {
		details = securityScannerJSONString(result)
	} else {
		details = rerr.Error()
	}
	ActivityLogActivityOnServer(ctx, db, userID, "security-scanner", "auto_fix.renew_docker_app_ssl",
		new("app"), new(domain),
		new(fmt.Sprintf("app_id=%s, success=%t, result=%s", appID, success, details)),
		nil, new(member.ID), nil)

	if success {
		slog.Info("Auto-fix: Docker app certificate renewed for " + domain)
		// No ssl_expiry write — docker_app_domains has no such column; the
		// next weekly scan re-derives everything from the filesystem.
		SystemLogLogEvent(ctx, db, "info", "security_scanner",
			"Auto-renewed the Docker app SSL certificate for "+domain, nil)
		NotificationsResolveAlert(ctx, db, userID, new(member.ID), nil, "ssl_renewal_failure",
			SecurityScannerDockerAppRenewalStateKey(domain),
			"SSL renewal recovered: "+domain,
			fmt.Sprintf("DockPanel renewed the certificate for the Docker app on %s. The "+
				"earlier renewal failure is resolved.", domain))
	} else {
		slog.Warn(fmt.Sprintf("Auto-fix: Docker app SSL renewal failed for %s: %v", domain, rerr))
		NotificationsFireAlertDeduped(ctx, db, userID, new(member.ID), nil, "ssl_renewal_failure",
			SecurityScannerDockerAppRenewalStateKey(domain), "critical",
			"SSL renewal failed: "+domain,
			fmt.Sprintf("The certificate for the Docker app on %s is expiring and DockPanel "+
				"could not renew it automatically: %s. The app will stop loading over HTTPS "+
				"when the certificate expires. Redeploying the app reissues it.", domain, details),
			12)
	}
	return true
}

func securityScannerSendScanAlerts(ctx context.Context, db *pgxpool.Pool, member AgentFleetMember, critical, warning, total int32) {
	admins, _ := queryAll[Tup2[uuid.UUID, string]](ctx, db, "SELECT id, email FROM users WHERE role = 'admin'")

	severity := "warning"
	if critical > 0 {
		severity = "critical"
	}
	title := fmt.Sprintf("Security scan on %s: %d critical, %d warning findings", member.Name, critical, warning)
	message := fmt.Sprintf("A scheduled security scan of %s completed with %d total findings (%d critical, %d warning). "+
		"Review the scan results in the Security section.", member.Name, total, critical, warning)

	// One alert per admin, naming the scanned server — without it the operator
	// gets identical alerts from every machine and cannot tell which is on fire.
	for _, a := range admins {
		NotificationsFireAlert(ctx, db, a.A, new(member.ID), nil, "security", "", severity, title, message)
	}
}
