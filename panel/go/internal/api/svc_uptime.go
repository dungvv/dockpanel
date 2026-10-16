package api

// services/uptime.rs — the uptime monitor background service (HTTP / TCP /
// ping / heartbeat checks, incidents, alerts, status-page notices).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type uptimeMonitorRow struct {
	ID                 uuid.UUID       `db:"id"`
	UserID             uuid.UUID       `db:"user_id"`
	SiteID             *uuid.UUID      `db:"site_id"`
	URL                string          `db:"url"`
	Name               string          `db:"name"`
	Status             string          `db:"status"`
	AlertEmail         bool            `db:"alert_email"`
	AlertSlackURL      *string         `db:"alert_slack_url"`
	AlertDiscordURL    *string         `db:"alert_discord_url"`
	MonitorType        string          `db:"monitor_type"`
	Port               *int32          `db:"port"`
	Keyword            *string         `db:"keyword"`
	KeywordMustContain bool            `db:"keyword_must_contain"`
	CheckInterval      int32           `db:"check_interval"`
	LastCheckedAt      *time.Time      `db:"last_checked_at"`
	CustomHeaders      json.RawMessage `db:"custom_headers"`
}

// UptimeRun checks every enabled monitor periodically until ctx is cancelled.
func UptimeRun(ctx context.Context, db *pgxpool.Pool) {
	slog.Info("Uptime monitor started")
	StatusNoticesStartWorker(db)

	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	var tickCount uint64
	first := true
	for {
		// tokio::time::interval fires immediately, then every period.
		if !first {
			select {
			case <-t.C:
			case <-ctx.Done():
				slog.Info("Uptime monitor shutting down gracefully")
				return
			}
		}
		first = false
		if ctx.Err() != nil {
			slog.Info("Uptime monitor shutting down gracefully")
			return
		}
		tickCount++

		// Due monitors (HTTP/TCP/ping) + all heartbeat monitors.
		monitors, err := queryAll[uptimeMonitorRow](ctx, db,
			"SELECT id, user_id, site_id, url, name, status, alert_email, alert_slack_url, alert_discord_url, "+
				"monitor_type, port, keyword, keyword_must_contain, check_interval, last_checked_at, custom_headers "+
				"FROM monitors WHERE enabled = TRUE AND "+
				"(monitor_type = 'heartbeat' OR last_checked_at IS NULL OR last_checked_at < NOW() - (check_interval || ' seconds')::interval)")
		if err != nil {
			slog.Error(fmt.Sprintf("Uptime monitor query error: %v", err))
			continue
		}

		// Batch-load users in maintenance windows (avoid N+1 per monitor).
		maint, _ := queryAll[uuid.UUID](ctx, db, "SELECT DISTINCT user_id FROM maintenance_windows WHERE starts_at <= NOW() AND ends_at >= NOW()")

		// Concurrently, max 10 at a time; drain fully before the next tick.
		sem := make(chan struct{}, 10)
		var wg sync.WaitGroup
		for i := range monitors {
			m := &monitors[i]
			if slices.Contains(maint, m.UserID) {
				continue
			}
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer func() { <-sem; wg.Done() }()
				defer func() {
					if p := recover(); p != nil {
						slog.Error(fmt.Sprintf("uptime check for %s panicked: %v", m.Name, p))
					}
				}()
				uptimeCheckMonitor(ctx, m, db)
			}()
		}
		wg.Wait()

		// Purge old data hourly (every 60th tick).
		if tickCount%60 == 0 {
			if _, err := execSQL(ctx, db, "DELETE FROM monitor_checks WHERE checked_at < NOW() - INTERVAL '24 hours'"); err != nil {
				slog.Error(fmt.Sprintf("Failed to purge old monitor checks: %v", err))
			}
			if _, err := execSQL(ctx, db, "DELETE FROM metrics WHERE recorded_at < NOW() - INTERVAL '7 days'"); err != nil {
				slog.Error(fmt.Sprintf("Failed to purge old metrics: %v", err))
			}
		}
	}
}

func uptimeStrOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

// uptimeCheckMonitor checks one monitor, records the result and handles
// status transitions.
func uptimeCheckMonitor(ctx context.Context, m *uptimeMonitorRow, db *pgxpool.Pool) {
	// Heartbeat monitors are passive — check for a missed beat.
	if m.MonitorType == "heartbeat" {
		uptimeCheckHeartbeat(ctx, m, db)
		return
	}

	var statusCode *int32
	var checkErr *string
	var newStatus string
	var responseTime int32
	switch m.MonitorType {
	case "tcp":
		statusCode, checkErr, newStatus, responseTime = uptimeCheckTCP(ctx, m)
	case "ping":
		statusCode, checkErr, newStatus, responseTime = uptimeCheckPing(ctx, m)
	default:
		statusCode, checkErr, newStatus, responseTime = uptimeCheckHTTP(ctx, m)
	}

	if _, err := execSQL(ctx, db, "INSERT INTO monitor_checks (monitor_id, status_code, response_time, error) VALUES ($1, $2, $3, $4)",
		m.ID, statusCode, responseTime, checkErr); err != nil {
		slog.Error(fmt.Sprintf("Failed to insert monitor check for %s: %v", m.Name, err))
	}
	if _, err := execSQL(ctx, db, "UPDATE monitors SET status = $1, last_checked_at = NOW(), last_response_time = $2, last_status_code = $3 WHERE id = $4",
		newStatus, responseTime, statusCode, m.ID); err != nil {
		slog.Error(fmt.Sprintf("Failed to update monitor status for %s: %v", m.Name, err))
	}

	// GAP 29: response-time degradation alerting (up but >5s → warning).
	//
	// The original statement could not succeed in any database (column
	// `subject` that does not exist, NOT NULL `title` omitted, an unreferenced
	// $2) and its error was discarded, so no slow-response alert ever existed.
	// The title carries no measured value so a site slow for an hour raises
	// one alert; the figure lives in the message.
	if newStatus == "up" && responseTime > 5000 {
		// Dedup on state_key (the monitor id), not the title: the title has
		// the monitor's NAME, so renaming a slow monitor used to raise a
		// second alert and strand the first. Guard-then-fire replaced an
		// atomic INSERT … WHERE NOT EXISTS — safe because a monitor is never
		// checked twice concurrently (each tick drains fully). Firing goes
		// through TryFireAlert so it gets the bell/SSE entry, channel
		// delivery, escalation and the per-type mute like every producer.
		stateKey := m.ID.String()
		alreadyFiring, err := queryScalar[bool](ctx, db,
			"SELECT EXISTS(SELECT 1 FROM alerts WHERE alert_type = 'slow_response' AND status = 'firing' AND user_id = $1 AND state_key = $2)",
			m.UserID, stateKey)
		if err != nil {
			alreadyFiring = false
		}
		if !alreadyFiring {
			if _, err := NotificationsTryFireAlert(ctx, db, m.UserID, nil, m.SiteID, "slow_response", stateKey, "warning",
				"Slow response: "+m.Name,
				fmt.Sprintf("Response time %dms exceeds 5000ms threshold for %s", responseTime, m.URL)); err != nil {
				slog.Error(fmt.Sprintf("Failed to record slow-response alert for %s: %v", m.Name, err))
			}
		}
		slog.Warn(fmt.Sprintf("Monitor %s (%s) slow response: %dms", m.Name, m.URL, responseTime))
		details := fmt.Sprintf("URL: %s, threshold: 5000ms", m.URL)
		SystemLogLogEvent(ctx, db, "warning", "uptime", fmt.Sprintf("Slow response: %s (%dms)", m.Name, responseTime), &details)
	} else if newStatus == "up" {
		// The recovery half, absent since the alert was first written. A
		// firing row with no resolve path blinds the dedup guard above and
		// keeps check_escalations paging about a site that got faster hours
		// ago. ResolveAlert no-ops when nothing fires (one indexed UPDATE).
		NotificationsResolveAlert(ctx, db, m.UserID, nil, m.SiteID, "slow_response", m.ID.String(),
			"Slow response resolved: "+m.Name,
			fmt.Sprintf("Response time is back to %dms, under the 5000ms threshold, for %s", responseTime, m.URL))
	}

	switch {
	case newStatus == "down" && m.Status != "down":
		// Just went down — incident + alerts.
		cause := uptimeStrOr(checkErr, "Unknown error")
		if _, err := execSQL(ctx, db, "INSERT INTO incidents (monitor_id, cause, alerted) VALUES ($1, $2, TRUE)", m.ID, cause); err != nil {
			slog.Error(fmt.Sprintf("Failed to create incident for %s: %v", m.Name, err))
		}
		slog.Warn(fmt.Sprintf("Monitor %s (%s) is DOWN: %s", m.Name, m.URL, cause))
		SystemLogLogEvent(ctx, db, "warning", "uptime", fmt.Sprintf("Monitor down: %s (%s)", m.Name, m.URL), &cause)
		uptimeSendAlerts(ctx, db, m, fmt.Sprintf("%s is down: %s", m.Name, cause), "critical")
		// GAP 3: auto-create a managed incident for the status page.
		_ = uptimeCreateAutoIncident(ctx, db, m, cause)
		// GAP 19: notify status page subscribers.
		uptimeNotifyStatusSubscribers(m.Name, "investigating", fmt.Sprintf("%s is experiencing issues: %s", m.Name, cause), m.UserID)
	case newStatus == "up" && m.Status == "down":
		// Just recovered.
		if _, err := execSQL(ctx, db, "UPDATE incidents SET resolved_at = NOW() WHERE monitor_id = $1 AND resolved_at IS NULL", m.ID); err != nil {
			slog.Error(fmt.Sprintf("Failed to resolve incident for %s: %v", m.Name, err))
		}
		uptimeResolveAutoIncident(ctx, db, m)
		uptimeNotifyStatusSubscribers(m.Name, "resolved", m.Name+" is back online", m.UserID)
		slog.Info(fmt.Sprintf("Monitor %s (%s) is back UP", m.Name, m.URL))
		uptimeSendAlerts(ctx, db, m, fmt.Sprintf("%s is back up (%dms)", m.Name, responseTime), "info")
	}
}

func uptimeMillis(start time.Time) int32 { return int32(time.Since(start).Milliseconds()) }

func uptimeI32(v int32) *int32   { return &v }
func uptimeStr(s string) *string { return &s }

// uptimeCheckTCP connects to host:port with a timeout.
func uptimeCheckTCP(ctx context.Context, m *uptimeMonitorRow) (*int32, *string, string, int32) {
	host := m.URL
	for strings.HasPrefix(host, "tcp://") {
		host = strings.TrimPrefix(host, "tcp://")
	}
	port := uint16(80)
	if m.Port != nil {
		port = uint16(*m.Port)
	}
	// SSRF re-validation at check time (parity with check_http): a low-TTL
	// record can flip internal after write, and /settings/import rows bypass
	// the create-path guard. Resolved and pinned to the SAME address — dialing
	// host:port again would let the OS resolve a second time, independently.
	addr, err := resolveValidated(ctx, host, port)
	if err != nil {
		return nil, uptimeStr("Host blocked: " + err.Error()), "down", 0
	}
	start := time.Now()
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	rt := uptimeMillis(start)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, uptimeStr("TCP connection timed out"), "down", rt
		}
		return nil, uptimeStr("TCP connection failed: " + err.Error()), "down", rt
	}
	conn.Close()
	return uptimeI32(0), nil, "up", rt
}

// uptimeCheckPing runs the system ping against the validated address.
func uptimeCheckPing(ctx context.Context, m *uptimeMonitorRow) (*int32, *string, string, int32) {
	host := m.URL
	for strings.HasPrefix(host, "ping://") {
		host = strings.TrimPrefix(host, "ping://")
	}
	// SSRF re-validation (reachability of an internal host is itself the
	// disclosure), pinned to the checked address: ping would otherwise do its
	// own, independent lookup.
	addr, err := resolveValidated(ctx, host, 0)
	if err != nil {
		return nil, uptimeStr("Host blocked: " + err.Error()), "down", 0
	}
	target := addr.Addr().String()
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := safeCommand(cctx, "ping", "-c", "1", "-W", "5", target).Output()
	rt := uptimeMillis(start)
	if err != nil {
		return nil, uptimeStr("Ping failed or timed out"), "down", rt
	}
	// Parse "time=X.XX ms".
	pingTime := rt
	if _, after, ok := strings.Cut(string(out), "time="); ok {
		if f := strings.Fields(after); len(f) > 0 {
			if ms, err := strconv.ParseFloat(f[0], 64); err == nil {
				pingTime = int32(ms)
			}
		}
	}
	return uptimeI32(0), nil, "up", pingTime
}

// uptimeCheckHeartbeat (dead man's switch) alerts when no ping arrived
// within 2x the interval.
func uptimeCheckHeartbeat(ctx context.Context, m *uptimeMonitorRow, db *pgxpool.Pool) {
	expected := time.Duration(max(m.CheckInterval, 60)) * time.Second
	last := time.Now()
	if m.LastCheckedAt != nil {
		last = *m.LastCheckedAt
	}
	if time.Since(last) <= expected*2 || m.Status == "down" {
		return
	}
	if _, err := execSQL(ctx, db, "INSERT INTO monitor_checks (monitor_id, status_code, response_time, error) VALUES ($1, NULL, 0, $2)", m.ID, "Heartbeat missed"); err != nil {
		slog.Error(fmt.Sprintf("Failed to insert heartbeat miss check for %s: %v", m.Name, err))
	}
	if _, err := execSQL(ctx, db, "UPDATE monitors SET status = 'down', last_checked_at = NOW(), last_response_time = 0, last_status_code = NULL WHERE id = $1", m.ID); err != nil {
		slog.Error(fmt.Sprintf("Failed to update heartbeat monitor status for %s: %v", m.Name, err))
	}
	if _, err := execSQL(ctx, db, "INSERT INTO incidents (monitor_id, cause, alerted) VALUES ($1, $2, TRUE)", m.ID, "Heartbeat missed — no ping received"); err != nil {
		slog.Error(fmt.Sprintf("Failed to create heartbeat incident for %s: %v", m.Name, err))
	}
	slog.Warn(fmt.Sprintf("Monitor %s (%s) heartbeat missed", m.Name, m.URL))
	SystemLogLogEvent(ctx, db, "warning", "uptime", fmt.Sprintf("Heartbeat missed: %s (%s)", m.Name, m.URL), uptimeStr("No heartbeat received within expected interval"))
	uptimeSendAlerts(ctx, db, m, m.Name+" heartbeat missed — no ping received", "critical")
}

// uptimeDescribeCheckError describes a failed HTTP check WITHOUT
// republishing the monitor's own URL. The client error names the URL; that
// string becomes incidents.cause, managed_incidents.description and the
// "Auto-detected: …" timeline entry, and /api/status-page/public serves two
// of those to anyone. Monitor URLs routinely carry a token in the query, the
// status-page guide promises URLs are not published, and the other public
// handler drops the URL deliberately.
//
// Unwrapping *url.Error (reqwest's without_url) alone is not the repair; the
// useful part is the cause chain (connection refused, invalid certificate),
// so that is kept and the final scrub removes the address wherever it still
// appears — a TLS hostname mismatch names the host inside a lower layer.
// Residual, deliberate: the certificate's own declared names are not
// scrubbed (a property of what the target presented, not of the URL).
func uptimeDescribeCheckError(err error, rawURL string) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return uptimeRedactMonitorTarget(err.Error(), rawURL)
}

// uptimeRedactMonitorTarget removes a monitor's own address from a message.
// Three needles, longest first: the URL as written, the URL as normalised
// (a bare http://host prints with a trailing slash), and the bare host. The
// host is a substring of both URLs, so replacing it first would strand the
// path and query beside the marker.
func uptimeRedactMonitorTarget(msg, rawURL string) string {
	needles := []string{strings.TrimSpace(rawURL)}
	if u, err := url.Parse(strings.TrimSpace(rawURL)); err == nil && u.Scheme != "" && u.Host != "" {
		n := *u
		if n.Path == "" {
			n.Path = "/"
		}
		needles = append(needles, n.String())
		if h := u.Hostname(); h != "" {
			needles = append(needles, h)
		}
	}
	slices.SortStableFunc(needles, func(a, b string) int { return len(b) - len(a) })
	for _, n := range needles {
		// Four characters is the shortest thing worth calling an address;
		// below that a needle is likelier part of an unrelated word.
		if len(n) >= 4 && strings.Contains(msg, n) {
			msg = strings.ReplaceAll(msg, n, "(url withheld)")
		}
	}
	return msg
}

// uptimeCheckRedirect follows up to 5 redirects (http→https etc.) but NEVER
// to an internal address — a bare limit would follow a redirect-to-internal
// (SSRF/oracle). A literal-IP target is caught here outright; hostname hops
// are also re-validated at dial time by validatingDialContext (the lookup the
// transport actually connects with), so there is no TOCTOU left. An
// over-limit chain is a network error (→ "down"), not a spurious 3xx.
func uptimeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 5 {
		return errors.New("too many redirects")
	}
	port := uint16(80)
	if p := req.URL.Port(); p != "" {
		if n, err := strconv.ParseUint(p, 10, 16); err == nil {
			port = uint16(n)
		}
	} else if req.URL.Scheme == "https" {
		port = 443
	}
	if hostResolvesInternalBlocking(req.URL.Hostname(), port) {
		return errors.New("redirect to internal address blocked")
	}
	return nil
}

// uptimeValidHeaderName is http::HeaderName::from_bytes (RFC 7230 token).
func uptimeValidHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// uptimeValidHeaderValue is http::HeaderValue::from_str: visible ASCII,
// space and tab only.
func uptimeValidHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == '\t' || c >= 32 && c < 127) {
			return false
		}
	}
	return true
}

// uptimeCheckHTTP is the HTTP check with optional keyword and custom
// headers. The request is pinned to the EXACT address the SSRF check
// approved via a fresh per-call client (a shared client's resolver would
// re-resolve independently of the check).
func uptimeCheckHTTP(ctx context.Context, m *uptimeMonitorRow) (*int32, *string, string, int32) {
	host, port, err := urlAuthority(m.URL)
	if err != nil {
		return nil, uptimeStr("URL blocked: " + err.Error()), "down", 0
	}
	// SSRF re-validation at check time (rebind; imported monitors bypass the
	// create guard). Done BEFORE the timing window so its DNS lookup does not
	// inflate response_time.
	tr, err := pinnedTransport(ctx, host, port)
	if err != nil {
		return nil, uptimeStr("URL blocked: " + err.Error()), "down", 0
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: uptimeCheckRedirect}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.URL, nil)
	if err != nil {
		return nil, uptimeStr(uptimeRedactMonitorTarget(err.Error(), m.URL)), "down", uptimeMillis(start)
	}
	if len(m.CustomHeaders) > 0 {
		var hm map[string]any
		if json.Unmarshal(m.CustomHeaders, &hm) == nil {
			for k, v := range hm {
				if s, ok := v.(string); ok && uptimeValidHeaderName(k) && uptimeValidHeaderValue(s) {
					req.Header.Add(k, s)
				}
			}
		}
	}

	resp, err := client.Do(req)
	rt := uptimeMillis(start)
	if err != nil {
		return nil, uptimeStr(uptimeDescribeCheckError(err, m.URL)), "down", rt
	}
	defer resp.Body.Close()
	code := int32(resp.StatusCode)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &code, uptimeStr(fmt.Sprintf("HTTP %d", code)), "down", rt
	}

	if m.Keyword != nil && *m.Keyword != "" {
		// Bound the body read: an attacker-controlled target could otherwise
		// stream an unbounded body into memory (shared-process OOM on small
		// VPSes). 2 MiB covers real pages while capping peak memory at
		// ~2 MiB × 10 concurrent checks. Lossy UTF-8 (an ASCII keyword
		// always matches).
		const maxBody = 2 * 1024 * 1024
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		body := strings.ToValidUTF8(string(buf), "�")
		contains := strings.Contains(body, *m.Keyword)
		must := m.KeywordMustContain
		if must != contains {
			msg := fmt.Sprintf("Keyword '%s' found in response (should not be present)", *m.Keyword)
			if must {
				msg = fmt.Sprintf("Keyword '%s' not found in response", *m.Keyword)
			}
			return &code, &msg, "down", rt
		}
	}
	return &code, nil, "up", rt
}

// uptimeSendAlerts delivers a monitor state change to the owner's external
// channels AND the panel's notification centre. The panel half was missing
// entirely, so a site going down reached email/Slack/Discord/PagerDuty and
// never the bell. Channels here are per-monitor, so no alert_rules gate.
func uptimeSendAlerts(ctx context.Context, db *pgxpool.Pool, m *uptimeMonitorRow, message, severity string) {
	var email *string
	if m.AlertEmail {
		email, _ = queryScalarOpt[string](ctx, db, "SELECT email FROM users WHERE id = $1", m.UserID)
	}
	extra, _ := queryOpt[Tup2[*string, *string]](ctx, db,
		"SELECT notify_pagerduty_key, notify_webhook_url FROM alert_rules WHERE user_id = $1 AND server_id IS NULL", m.UserID)
	var pdKey, webhook *string
	if extra != nil {
		pdKey, webhook = extra.A, extra.B
	}
	// All four are encrypted at rest; only the pool is in scope, so decrypt
	// the way GetUserChannels does.
	dec := func(p *string) *string {
		if p == nil {
			return nil
		}
		s := SecretsCryptoDecryptCredentialFromEnv(*p)
		return &s
	}
	channels := &NotificationsNotifyChannels{
		Email: email, SlackURL: dec(m.AlertSlackURL), DiscordURL: dec(m.AlertDiscordURL),
		PagerdutyKey: dec(pdKey), WebhookURL: dec(webhook),
	}
	subject := "DockPanel Alert: " + m.Name
	html := fmt.Sprintf("<h2>Monitor Alert</h2><p><strong>%s</strong></p><p>URL: %s</p><p>Time: %s</p>",
		message, m.URL, time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	NotificationsSendNotification(ctx, db, channels, subject, message, html)

	// Addressed to the monitor's owner (who asked to be told), not every admin.
	link := "/monitoring?tab=monitors"
	NotificationsNotifyPanel(ctx, db, &m.UserID, subject, message, severity, "monitor", &link)
}

// uptimeCreateAutoIncident (GAP 3) opens a managed incident when a monitor
// goes down.
func uptimeCreateAutoIncident(ctx context.Context, db *pgxpool.Pool, m *uptimeMonitorRow, cause string) error {
	userID, err := queryScalarOpt[uuid.UUID](ctx, db, "SELECT user_id FROM monitors WHERE id = $1", m.ID)
	if err != nil || userID == nil {
		return nil
	}
	incidentID, err := queryScalar[uuid.UUID](ctx, db,
		"INSERT INTO managed_incidents (user_id, title, status, severity, description, visible_on_status_page) VALUES ($1, $2, 'investigating', 'major', $3, TRUE) RETURNING id",
		*userID, m.Name+" is down", cause)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to create managed incident: %v", err))
		return err
	}
	_, _ = execSQL(ctx, db, "INSERT INTO incident_updates (incident_id, status, message, author_email) VALUES ($1, 'investigating', $2, 'system')",
		incidentID, "Auto-detected: "+cause)
	// Link to status page components via the monitor.
	_, _ = execSQL(ctx, db, "INSERT INTO managed_incident_components (incident_id, component_id) SELECT $1, cm.component_id FROM status_page_component_monitors cm WHERE cm.monitor_id = $2 ON CONFLICT DO NOTHING",
		incidentID, m.ID)
	slog.Info(fmt.Sprintf("Auto-incident created for monitor %s (incident %s)", m.Name, incidentID))
	return nil
}

// uptimeResolveAutoIncident (GAP 3) resolves the auto-incident on recovery,
// scoped to the monitor's OWNER: names are per-tenant and unremarkable, so
// title alone let one tenant's recovery resolve another's open incident and
// post "recovered automatically" onto their public status page.
func uptimeResolveAutoIncident(ctx context.Context, db *pgxpool.Pool, m *uptimeMonitorRow) {
	ids, _ := queryAll[uuid.UUID](ctx, db,
		"SELECT id FROM managed_incidents WHERE title = $1 AND user_id = $2 AND status != 'resolved' AND status != 'postmortem'",
		m.Name+" is down", m.UserID)
	for _, id := range ids {
		_, _ = execSQL(ctx, db, "INSERT INTO incident_updates (incident_id, status, message, author_email) VALUES ($1, 'resolved', 'Monitor recovered automatically', 'system')", id)
		_, _ = execSQL(ctx, db, "UPDATE managed_incidents SET status = 'resolved', resolved_at = NOW(), updated_at = NOW() WHERE id = $1", id)
	}
	if len(ids) > 0 {
		slog.Info(fmt.Sprintf("Auto-resolved %d managed incident(s) for monitor %s", len(ids), m.Name))
	}
}

// uptimeNotifyStatusSubscribers (GAP 19) hands off to the status-notice
// worker — never inline in the check, never a detached per-event goroutine.
func uptimeNotifyStatusSubscribers(monitorName, status, message string, ownerID uuid.UUID) {
	StatusNoticesEnqueue(monitorName, fmt.Sprintf("[Status Update] %s — %s", monitorName, status), message, ownerID)
}
