package api

// Port of panel/backend/src/services/security_hardening.rs — post-incident
// enhancements:
//   - Geo-IP lookup for login/register alerting (Feature 1)
//   - Immutable security audit log writes (Feature 7)
//   - Suspicious event tracking + auto-lockdown (Feature 4/9)
//   - Lockdown state management (Feature 9/11)
//   - Tamper-resistant file logging (Feature 6)

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// securityHardeningGeoClient is the shared HTTP client for geo-IP lookups
// (reuses connections).
var securityHardeningGeoClient = &http.Client{Timeout: 5 * time.Second}

// ── Geo-IP Lookup (Feature 1) ───────────────────────────────────────────

// SecurityHardeningGeoInfo is what ip-api.com tells us about an address.
type SecurityHardeningGeoInfo struct {
	Country string `json:"country"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	Proxy   bool   `json:"proxy"`
	Hosting bool   `json:"hosting"`
	Query   string `json:"query"`
}

// SecurityHardeningLookupGeoIP looks up geo-IP information for an IP address.
// Uses ip-api.com free tier (45 req/min, no key needed). Returns nil on
// failure (non-blocking, best-effort).
func SecurityHardeningLookupGeoIP(ctx context.Context, ip string) *SecurityHardeningGeoInfo {
	// Skip private/local IPs
	if ip == "unknown" || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "172.") || ip == "127.0.0.1" || ip == "::1" {
		return &SecurityHardeningGeoInfo{Country: "Local", City: "LAN", ISP: "Private Network", Query: ip}
	}

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,city,isp,proxy,hosting,query", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := securityHardeningGeoClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var data map[string]any
	if json.NewDecoder(resp.Body).Decode(&data) != nil {
		return nil
	}
	if s, _ := data["status"].(string); s != "success" {
		return nil
	}
	str := func(k, def string) string {
		if s, ok := data[k].(string); ok {
			return s
		}
		return def
	}
	proxy, _ := data["proxy"].(bool)
	hosting, _ := data["hosting"].(bool)
	return &SecurityHardeningGeoInfo{
		Country: str("country", ""), City: str("city", ""), ISP: str("isp", ""),
		Proxy: proxy, Hosting: hosting, Query: str("query", ip),
	}
}

// ── Immutable Audit Log (Feature 7) ─────────────────────────────────────

// SecurityHardeningAuditLog writes to the immutable security audit log.
// This table has a PostgreSQL trigger preventing UPDATE/DELETE.
func SecurityHardeningAuditLog(ctx context.Context, db *pgxpool.Pool, eventType string, actorEmail, actorIP,
	targetType, targetName, details *string, geo *SecurityHardeningGeoInfo, severity string, apiKeyID *uuid.UUID) {
	var country, city, isp *string
	if geo != nil {
		country, city, isp = &geo.Country, &geo.City, &geo.ISP
	}
	if _, err := db.Exec(ctx,
		"INSERT INTO security_audit_log "+
			"(event_type, actor_email, actor_ip, target_type, target_name, details, "+
			"geo_country, geo_city, geo_isp, severity, api_key_id) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
		eventType, actorEmail, actorIP, targetType, targetName, details, country, city, isp, severity, apiKeyID); err != nil {
		slog.Warn(fmt.Sprintf("Failed to write security audit log: %v", err))
	}

	// Feature 6: Also write to tamper-resistant file log
	securityHardeningWriteToAuditFile(eventType, actorEmail, actorIP, details, severity)
}

// ── Tamper-Resistant File Logging (Feature 6) ───────────────────────────

// securityHardeningAuditDir should have chattr +a set.
var securityHardeningAuditDir = "/var/lib/dockpanel/audit"

// securityHardeningWriteToAuditFile appends the entry to an append-only file
// on disk.
func securityHardeningWriteToAuditFile(eventType string, actorEmail, actorIP, details *string, severity string) {
	dir := securityHardeningAuditDir
	_ = os.MkdirAll(dir, 0o755)

	now := time.Now().UTC()
	path := fmt.Sprintf("%s/audit-%s.log", dir, now.Format("2006-01-02"))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	or := func(p *string) string {
		if p == nil {
			return "-"
		}
		return *p
	}
	ts := now.Format("2006-01-02T15:04:05.999999999-07:00")
	_, _ = fmt.Fprintf(f, "%s\t%s\t%s\t%s\t%s\t%s\n", ts, severity, eventType, or(actorEmail), or(actorIP), or(details))
}

// ── Suspicious Event Tracking (Feature 4/9) ─────────────────────────────

// SecurityHardeningRecordSuspiciousEvent records a suspicious event and checks
// whether the auto-lockdown threshold is reached. Returns true if lockdown was
// triggered.
//
// Events detected in-process are stamped now. Events that were queued on disk
// before the panel could read them pass the time they actually happened — see
// SecurityHardeningRecordSuspiciousEventAt.
func SecurityHardeningRecordSuspiciousEvent(ctx context.Context, db *pgxpool.Pool, eventType string, actorEmail, actorIP, details *string) bool {
	return SecurityHardeningRecordSuspiciousEventAt(ctx, db, eventType, actorEmail, actorIP, details, nil)
}

// SecurityHardeningRecordSuspiciousEventAt is RecordSuspiciousEvent for an
// event whose occurrence time is known and is NOT now.
//
// The auto-lockdown rule is "N events within M minutes", counted over
// created_at. Stamping an ingested backlog with NOW() collapses however long
// it took to accumulate into a single instant, so a queue that built up over
// months is counted as one burst and trips the threshold the moment it is
// read. That is exactly what happens on upgrade to 2.46.0: before it,
// suspicious-event ingestion sat under auto_heal_enabled (seeded false), so on
// a stock install the agent wrote suspicious-events.jsonl and nothing drained
// it; the first tick after upgrading would replay the whole file as if it
// were simultaneous and lock every non-admin out for 24h. The agent has always
// written a per-event timestamp; honouring it means an old backlog lands
// outside the window and a genuine burst still trips the rule.
func SecurityHardeningRecordSuspiciousEventAt(ctx context.Context, db *pgxpool.Pool, eventType string, actorEmail, actorIP, details *string, occurredAt *time.Time) bool {
	// COALESCE keeps the column default for the nil case rather than
	// duplicating "now" here.
	_, _ = db.Exec(ctx,
		"INSERT INTO suspicious_events (event_type, actor_email, actor_ip, details, created_at) "+
			"VALUES ($1, $2, $3, $4, COALESCE($5, NOW()))",
		eventType, actorEmail, actorIP, details, occurredAt)

	threshold := SecurityHardeningGetSettingI64(ctx, db, "security_lockdown_threshold", 5)
	windowMins := SecurityHardeningGetSettingI64(ctx, db, "security_lockdown_window_minutes", 10)

	count, err := queryScalar[int64](ctx, db,
		"SELECT COUNT(*) FROM suspicious_events "+
			"WHERE created_at > NOW() - make_interval(mins => $1)", int32(windowMins))
	if err != nil {
		count = 0
	}

	if count >= threshold {
		// Check if already locked down
		locked, err := queryScalarOpt[bool](ctx, db, "SELECT active FROM lockdown_state WHERE id = 1")
		if err != nil {
			locked = nil
		}
		if locked == nil || !*locked {
			reason := fmt.Sprintf("Auto-lockdown: %d suspicious events in %d minutes (threshold: %d)", count, windowMins, threshold)
			SecurityHardeningActivateLockdown(ctx, db, "auto", reason)
			SecurityHardeningAuditLog(ctx, db, "lockdown.auto", nil, nil, new("system"), nil, &reason, nil, "critical", nil)
			return true
		}
	}
	return false
}

// ── Lockdown Management (Feature 9/11) ──────────────────────────────────

// SecurityHardeningActivateLockdown activates lockdown mode.
func SecurityHardeningActivateLockdown(ctx context.Context, db *pgxpool.Pool, triggeredBy, reason string) {
	_, _ = db.Exec(ctx,
		"UPDATE lockdown_state SET "+
			"active = TRUE, triggered_by = $1, triggered_at = NOW(), reason = $2, "+
			"terminals_disabled = TRUE, registration_disabled = TRUE, non_admin_blocked = TRUE, "+
			"unlocked_at = NULL, unlocked_by = NULL "+
			"WHERE id = 1", triggeredBy, reason)
	slog.Error(fmt.Sprintf("🔒 LOCKDOWN ACTIVATED: %s — %s", triggeredBy, reason))
}

// SecurityHardeningDeactivateLockdown deactivates lockdown mode (admin only).
func SecurityHardeningDeactivateLockdown(ctx context.Context, db *pgxpool.Pool, adminEmail string) {
	_, _ = db.Exec(ctx,
		"UPDATE lockdown_state SET "+
			"active = FALSE, unlocked_at = NOW(), unlocked_by = $1 "+
			"WHERE id = 1", adminEmail)
	slog.Info("🔓 LOCKDOWN DEACTIVATED by " + adminEmail)
}

// SecurityHardeningIsLockedDown reports whether the system is in lockdown.
func SecurityHardeningIsLockedDown(ctx context.Context, db *pgxpool.Pool) bool {
	v, err := queryScalarOpt[bool](ctx, db, "SELECT active FROM lockdown_state WHERE id = 1")
	return err == nil && v != nil && *v
}

// SecurityHardeningGetLockdownState returns the lockdown state details.
func SecurityHardeningGetLockdownState(ctx context.Context, db *pgxpool.Pool) map[string]any {
	row, err := queryOpt[Tup4[bool, *string, *time.Time, *string]](ctx, db,
		"SELECT active, triggered_by, triggered_at, reason FROM lockdown_state WHERE id = 1")
	if err != nil || row == nil {
		return map[string]any{"active": false}
	}
	return map[string]any{
		"active":       row.A,
		"triggered_by": row.B,
		"triggered_at": row.C,
		"reason":       row.D,
	}
}

// ── Geo-IP Alert Notification (Feature 1) ───────────────────────────────

// SecurityHardeningAlertSuspiciousIP sends an alert to all admin notification
// channels about a suspicious login/register. event is "Login" or
// "Registration".
func SecurityHardeningAlertSuspiciousIP(ctx context.Context, db *pgxpool.Pool, event, email, ip string, geo *SecurityHardeningGeoInfo) {
	proxyTag := ""
	if geo.Proxy || geo.Hosting {
		proxyTag = " ⚠️ PROXY/VPN/DATACENTER"
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.999999999-07:00")
	subject := fmt.Sprintf("🚨 Security Alert: %s from new IP%s", event, proxyTag)
	message := fmt.Sprintf("User: %s\nIP: %s\nCountry: %s\nCity: %s\nISP: %s%s\nTime: %s",
		email, ip, geo.Country, geo.City, geo.ISP, proxyTag, now)
	html := fmt.Sprintf("<h2>Security Alert: %s</h2>"+
		"<p><strong>User:</strong> %s</p>"+
		"<p><strong>IP:</strong> %s</p>"+
		"<p><strong>Location:</strong> %s, %s</p>"+
		"<p><strong>ISP:</strong> %s%s</p>"+
		"<p><strong>Time:</strong> %s</p>",
		event, email, ip, geo.Country, geo.City, geo.ISP, proxyTag, now)

	// Send to all admin users' notification channels
	admins, _ := queryAll[uuid.UUID](ctx, db, "SELECT id FROM users WHERE role = 'admin'")
	for _, adminID := range admins {
		if ch := NotificationsGetUserChannels(ctx, db, adminID, nil); ch != nil {
			NotificationsSendNotification(ctx, db, ch, subject, message, html)
		}
	}

	// The panel notification goes through notify_panel like every other one.
	// It used to be a hand-written INSERT here, which left out the `link`
	// column (so this — the largest class of notification on a live panel —
	// could never be clickable) and the broadcast (so it never arrived without
	// a page reload). A raw INSERT into a table with defaults succeeds whatever
	// you leave out of the column list.
	severity := "warning"
	if geo.Proxy || geo.Hosting {
		severity = "critical"
	}
	NotificationsNotifyPanel(ctx, db, nil, subject, message, severity, "security", new("/security?tab=audit"))
}

// SecurityHardeningAlertLockdown sends an emergency lockdown notification to
// all admin channels.
func SecurityHardeningAlertLockdown(ctx context.Context, db *pgxpool.Pool, reason, triggeredBy string) {
	subject := "🔒 EMERGENCY: System Lockdown Activated"
	message := fmt.Sprintf("DockPanel has entered lockdown mode.\n"+
		"Triggered by: %s\n"+
		"Reason: %s\n"+
		"All terminals disabled. Registration blocked.\n"+
		"Admin action required to unlock.", triggeredBy, reason)
	html := fmt.Sprintf("<h2 style='color:red'>🔒 System Lockdown</h2>"+
		"<p><strong>Triggered by:</strong> %s</p>"+
		"<p><strong>Reason:</strong> %s</p>"+
		"<p>All terminals disabled. Registration blocked. Admin action required.</p>", triggeredBy, reason)

	admins, _ := queryAll[uuid.UUID](ctx, db, "SELECT id FROM users WHERE role = 'admin'")
	for _, adminID := range admins {
		if ch := NotificationsGetUserChannels(ctx, db, adminID, nil); ch != nil {
			NotificationsSendNotification(ctx, db, ch, subject, message, html)
		}
	}

	// …and to the panel itself. get_user_channels returns nothing for a user
	// with no alert_rules row — every user until somebody saves a destination —
	// so on a stock install the most disruptive thing this panel can do to
	// itself, locking every non-admin out for 24 hours, announced itself to
	// nobody but a security_audit_log tab an operator has to think to visit.
	NotificationsNotifyPanel(ctx, db, nil, subject, message, "critical", "security", new("/security?tab=lockdown"))
}

// ── Helpers ─────────────────────────────────────────────────────────────

// SecurityHardeningGetSettingI64 reads an integer setting, def when absent or
// unparseable.
func SecurityHardeningGetSettingI64(ctx context.Context, db *pgxpool.Pool, key string, def int64) int64 {
	v, err := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = $1", key)
	if err != nil || v == nil {
		return def
	}
	n, err := strconv.ParseInt(*v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

// SecurityHardeningGetSettingBool reads a boolean setting ("true" = true), def
// when absent.
func SecurityHardeningGetSettingBool(ctx context.Context, db *pgxpool.Pool, key string, def bool) bool {
	v, err := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = $1", key)
	if err != nil || v == nil {
		return def
	}
	return *v == "true"
}
