package api

// services/notifications.rs — alert fan-out (email, Slack, Discord,
// PagerDuty, generic webhook), the panel notification center + its SSE
// broadcast, and the alert fire/resolve helpers.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yuin/goldmark"
	gmhtml "github.com/yuin/goldmark/renderer/html"
)

// notificationsNoRedirect: do NOT follow redirects. The notify_*_url values
// are vetted by validateURLNotInternal only at write time, so a public URL
// that 3xx-redirects to http://127.0.0.1 / 169.254.169.254 would otherwise
// exfiltrate to / probe an internal address. Parity with
// webhook_gateway.rs::http_client.
func notificationsNoRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// notificationsHTTPClient is the shared client (reuses connections) — used
// for PagerDuty's fixed endpoint; user-supplied URLs go through
// notificationsPostUserWebhook's pinned per-call client instead.
var notificationsHTTPClient = sync.OnceValue(func() *http.Client {
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: notificationsNoRedirect}
})

// notificationsRFC3339 is chrono's to_rfc3339(): "+00:00" offset, fractional
// seconds in 0/3/6/9 digits (SecondsFormat::AutoSi).
func notificationsRFC3339(t time.Time) string {
	t = t.UTC()
	ns := t.Nanosecond()
	frac := ""
	switch {
	case ns == 0:
	case ns%1_000_000 == 0:
		frac = fmt.Sprintf(".%03d", ns/1_000_000)
	case ns%1_000 == 0:
		frac = fmt.Sprintf(".%06d", ns/1_000)
	default:
		frac = fmt.Sprintf(".%09d", ns)
	}
	return t.Format("2006-01-02T15:04:05") + frac + "+00:00"
}

// notificationsPostJSON POSTs payload with a 10s per-request timeout and
// returns the status code.
func notificationsPostJSON(ctx context.Context, c *http.Client, url string, payload any) (int, error) {
	body, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// notificationsPostUserWebhook POSTs a JSON payload to a user-supplied
// Slack/Discord/webhook URL, re-validating it against SSRF at SEND time
// (DNS-rebinding defense — the write-time check can be defeated by a low-TTL
// record that flips to an internal IP before the alert fires). The request is
// pinned to the EXACT address that validation approved via a fresh per-call
// client, so no independent re-resolution happens. Mirrors
// webhook_gateway.rs::forward_to_route. Re-validation is bounded by 3s so a
// slow/hostile resolver cannot serialize the alert path; fail-closed.
func notificationsPostUserWebhook(ctx context.Context, url string, payload any) {
	host, port, err := urlAuthority(url)
	if err != nil {
		slog.Warn(fmt.Sprintf("Notification webhook blocked at send time (SSRF/DNS-rebind?): %v", err))
		return
	}
	vctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	tr, err := pinnedTransport(vctx, host, port)
	cancel()
	if err != nil {
		if errors.Is(vctx.Err(), context.DeadlineExceeded) {
			slog.Warn("Notification webhook URL validation timed out; skipping send")
		} else {
			slog.Warn(fmt.Sprintf("Notification webhook blocked at send time (SSRF/DNS-rebind?): %v", err))
		}
		return
	}
	defer tr.CloseIdleConnections()
	pinned := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: notificationsNoRedirect}
	status, err := notificationsPostJSON(ctx, pinned, url, payload)
	if err != nil {
		slog.Warn(fmt.Sprintf("Notification webhook send failed: %v", err))
	} else if status < 200 || status > 299 {
		slog.Warn(fmt.Sprintf("Notification webhook returned %d %s: %s", status, http.StatusText(status), url))
	}
}

func notificationsPostPagerDuty(ctx context.Context, payload any) {
	status, err := notificationsPostJSON(ctx, notificationsHTTPClient(), "https://events.pagerduty.com/v2/enqueue", payload)
	if err != nil {
		slog.Warn(fmt.Sprintf("PagerDuty alert send failed: %v", err))
	} else if status < 200 || status > 299 {
		slog.Warn(fmt.Sprintf("PagerDuty alert returned %d %s", status, http.StatusText(status)))
	}
}

// ── Real-time notification broadcast (SSE) ─────────────────────────────────

// notificationsNotifTx is the global broadcast for real-time delivery,
// registered once at startup.
var notificationsNotifTx atomic.Pointer[Broadcast[PanelNotification]]

// NotificationsInitNotifBroadcast registers the broadcast (called once at startup).
func NotificationsInitNotifBroadcast(tx *Broadcast[PanelNotification]) {
	notificationsNotifTx.CompareAndSwap(nil, tx)
}

// NotificationsNotifyChannels are the channels an alert is delivered to.
type NotificationsNotifyChannels struct {
	Email        *string
	SlackURL     *string
	DiscordURL   *string
	PagerdutyKey *string
	WebhookURL   *string
	// Comma-separated alert types to suppress from external channels (Gap #69).
	MutedTypes string
}

func notificationsSetting(ctx context.Context, db *pgxpool.Pool, key string) *string {
	v, err := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = $1", key)
	if err != nil {
		return nil
	}
	return v
}

func notificationsApplyTemplate(tmpl, subject, message, severity string) string {
	// Sequential, like Rust's chained .replace(): a substituted value
	// containing a later placeholder is itself substituted.
	s := strings.ReplaceAll(tmpl, "{{title}}", subject)
	s = strings.ReplaceAll(s, "{{message}}", message)
	s = strings.ReplaceAll(s, "{{severity}}", severity)
	return strings.ReplaceAll(s, "{{timestamp}}", notificationsRFC3339(time.Now()))
}

// notificationsFormatMessage (Gap #70): a custom template from settings, or
// the default per-channel format.
func notificationsFormatMessage(ctx context.Context, db *pgxpool.Pool, channel, subject, message, severity string) string {
	if tmpl := notificationsSetting(ctx, db, "notif_template_"+channel); tmpl != nil && *tmpl != "" {
		return notificationsApplyTemplate(*tmpl, subject, message, severity)
	}
	switch channel {
	case "slack":
		return fmt.Sprintf("*%s*\n%s", subject, message)
	case "discord":
		return fmt.Sprintf("**%s**\n%s", subject, message)
	default:
		return fmt.Sprintf("%s\n\n%s", subject, message)
	}
}

// notificationsDeriveSeverity guesses a severity from the subject line. Only
// NotificationsSendNotification still uses it — every fired-alert path has a
// REAL stored severity and passes it in; SendNotification's callers
// (resolve/git-deploy/security-hardening/auto-healer/status-notice/uptime)
// have none, so the subject text is the best available signal for them.
func notificationsDeriveSeverity(subject string) string {
	switch {
	case strings.Contains(subject, "FAIL") || strings.Contains(subject, "down") || strings.Contains(subject, "critical"):
		return "critical"
	case strings.Contains(subject, "warning"):
		return "warning"
	case strings.Contains(subject, "Resolved") || strings.Contains(subject, "back up"):
		return "info"
	default:
		return "error"
	}
}

// NotificationsSeverityColor is the HTML colour for a stored severity —
// single-sourced so the initial page and its escalation re-page can never
// disagree (the escalation path once hardcoded critical-red for everything).
func NotificationsSeverityColor(severity string) string {
	switch severity {
	case "critical":
		return "#ef4444"
	case "warning":
		return "#f59e0b"
	default:
		return "#3b82f6"
	}
}

func notificationsEventAction(subject string) string {
	if strings.Contains(subject, "Resolved") || strings.Contains(subject, "back up") {
		return "resolve"
	}
	return "trigger"
}

// NotificationsSendNotification sends via every configured channel.
func NotificationsSendNotification(ctx context.Context, db *pgxpool.Pool, channels *NotificationsNotifyChannels, subject, message, bodyHTML string) {
	severity := notificationsDeriveSeverity(subject)

	// Email — custom template via notif_template_email.
	if channels.Email != nil {
		html := bodyHTML
		if tmpl := notificationsSetting(ctx, db, "notif_template_email"); tmpl != nil && *tmpl != "" {
			html = notificationsApplyTemplate(*tmpl, subject, message, severity)
		}
		if err := EmailSendEmail(ctx, db, *channels.Email, subject, html); err != nil {
			slog.Warn(fmt.Sprintf("Alert email failed: %v", err))
		}
	}

	if channels.SlackURL != nil && *channels.SlackURL != "" {
		text := notificationsFormatMessage(ctx, db, "slack", subject, message, severity)
		notificationsPostUserWebhook(ctx, *channels.SlackURL, map[string]any{"text": text})
	}

	if channels.DiscordURL != nil && *channels.DiscordURL != "" {
		content := notificationsFormatMessage(ctx, db, "discord", subject, message, severity)
		notificationsPostUserWebhook(ctx, *channels.DiscordURL, map[string]any{"content": content})
	}

	// PagerDuty Events API v2.
	if channels.PagerdutyKey != nil && *channels.PagerdutyKey != "" {
		notificationsPostPagerDuty(ctx, map[string]any{
			"routing_key":  *channels.PagerdutyKey,
			"event_action": notificationsEventAction(subject),
			"payload": map[string]any{
				"summary":        subject,
				"source":         "DockPanel",
				"severity":       severity,
				"custom_details": map[string]any{"message": message},
			},
		})
	}

	// Generic webhook (GAP 31).
	if channels.WebhookURL != nil && *channels.WebhookURL != "" {
		custom := notificationsFormatMessage(ctx, db, "webhook", subject, message, severity)
		notificationsPostUserWebhook(ctx, *channels.WebhookURL, map[string]any{
			"title":     subject,
			"message":   custom,
			"severity":  severity,
			"timestamp": notificationsRFC3339(time.Now()),
			"source":    "dockpanel",
		})
	}
}

// notificationsPanelBaseURL: settings → env → "" (for "Open runbook" links).
func notificationsPanelBaseURL(ctx context.Context, db *pgxpool.Pool) string {
	if u := notificationsSetting(ctx, db, "base_url"); u != nil && *u != "" {
		return strings.TrimRight(*u, "/")
	}
	if s := os.Getenv("BASE_URL"); s != "" {
		return strings.TrimRight(s, "/")
	}
	return ""
}

// NotificationsLoadRunbookPayload (Phase 4 W3) builds the runbook excerpt +
// URL for an alert type: (nil, nil) when no runbook exists; (excerpt, nil)
// when no base_url is configured. Shared by TryFireAlert and
// alert_engine::check_escalations so re-pages carry the same payload.
func NotificationsLoadRunbookPayload(ctx context.Context, db *pgxpool.Pool, alertType string) (*string, *string) {
	rb := AlertRunbooksGetRunbook(ctx, db, alertType)
	if rb == nil {
		return nil, nil
	}
	ex := AlertRunbooksExcerpt(rb.RunbookMd, 280)
	if base := notificationsPanelBaseURL(ctx, db); base != "" {
		u := fmt.Sprintf("%s/alerts/runbooks/%s", base, alertType)
		return &ex, &u
	}
	return &ex, nil
}

// NotificationsSendNotificationWithRunbook (Phase 4 W2) is used by
// TryFireAlert and check_escalations; non-alert callers stay on
// SendNotification. severity is the caller's OWN stored value (the one bound
// to the alerts INSERT), not re-derived from the subject.
//
// Per channel: email gets the rendered markdown appended to bodyHTML;
// slack/discord get a link + 280-char excerpt; pagerduty gets runbook_url +
// runbook_excerpt in custom_details; webhook gets them as top-level keys.
func NotificationsSendNotificationWithRunbook(ctx context.Context, db *pgxpool.Pool, channels *NotificationsNotifyChannels, subject, message, bodyHTML, severity string, runbookExcerpt, runbookURL *string) {
	if channels.Email != nil {
		runbookHTML := ""
		if runbookExcerpt != nil {
			runbookHTML = notificationsRenderRunbookHTML(*runbookExcerpt)
		}
		urlStr := ""
		if runbookURL != nil {
			urlStr = *runbookURL
		}
		var html string
		if tmpl := notificationsSetting(ctx, db, "notif_template_email"); tmpl != nil && *tmpl != "" {
			html = strings.ReplaceAll(strings.ReplaceAll(notificationsApplyTemplate(*tmpl, subject, message, severity),
				"{{runbook_excerpt}}", runbookHTML), "{{runbook_url}}", urlStr)
		} else {
			html = notificationsAppendRunbookToHTML(bodyHTML, runbookHTML, urlStr)
		}
		if err := EmailSendEmail(ctx, db, *channels.Email, subject, html); err != nil {
			slog.Warn(fmt.Sprintf("Alert email failed: %v", err))
		}
	}

	// Slack — `*Runbook:* <url|view>\n_excerpt_`.
	if channels.SlackURL != nil && *channels.SlackURL != "" {
		text := notificationsFormatMessage(ctx, db, "slack", subject, message, severity)
		if runbookExcerpt != nil {
			if runbookURL != nil {
				text += fmt.Sprintf("\n\n*Runbook:* <%s|view>\n_%s_", *runbookURL, *runbookExcerpt)
			} else {
				text += fmt.Sprintf("\n\n*Runbook:* _%s_", *runbookExcerpt)
			}
		}
		notificationsPostUserWebhook(ctx, *channels.SlackURL, map[string]any{"text": text})
	}

	// Discord — `**Runbook:** [view](url)\n*excerpt*`.
	if channels.DiscordURL != nil && *channels.DiscordURL != "" {
		content := notificationsFormatMessage(ctx, db, "discord", subject, message, severity)
		if runbookExcerpt != nil {
			if runbookURL != nil {
				content += fmt.Sprintf("\n\n**Runbook:** [view](%s)\n*%s*", *runbookURL, *runbookExcerpt)
			} else {
				content += fmt.Sprintf("\n\n**Runbook:** *%s*", *runbookExcerpt)
			}
		}
		notificationsPostUserWebhook(ctx, *channels.DiscordURL, map[string]any{"content": content})
	}

	if channels.PagerdutyKey != nil && *channels.PagerdutyKey != "" {
		details := map[string]any{"message": message}
		if runbookExcerpt != nil {
			details["runbook_excerpt"] = *runbookExcerpt
		}
		if runbookURL != nil {
			details["runbook_url"] = *runbookURL
		}
		notificationsPostPagerDuty(ctx, map[string]any{
			"routing_key":  *channels.PagerdutyKey,
			"event_action": notificationsEventAction(subject),
			"payload": map[string]any{
				"summary":        subject,
				"source":         "DockPanel",
				"severity":       severity,
				"custom_details": details,
			},
		})
	}

	if channels.WebhookURL != nil && *channels.WebhookURL != "" {
		custom := notificationsFormatMessage(ctx, db, "webhook", subject, message, severity)
		payload := map[string]any{
			"title":     subject,
			"message":   custom,
			"severity":  severity,
			"timestamp": notificationsRFC3339(time.Now()),
			"source":    "dockpanel",
		}
		if runbookExcerpt != nil {
			payload["runbook_excerpt"] = *runbookExcerpt
		}
		if runbookURL != nil {
			payload["runbook_url"] = *runbookURL
		}
		notificationsPostUserWebhook(ctx, *channels.WebhookURL, payload)
	}
}

// notificationsMarkdown is CommonMark without extensions, like
// pulldown_cmark::Parser::new. pulldown-cmark's push_html passes raw HTML
// through (runbooks are admin-authored), so goldmark is told the same with
// WithUnsafe — otherwise it would replace it with "<!-- raw HTML omitted -->".
var notificationsMarkdown = goldmark.New(goldmark.WithRendererOptions(gmhtml.WithUnsafe()))

// notificationsRenderRunbookHTML renders markdown to HTML; recovered
// defensively (admin-authored input is trusted but the parser is third-party)
// with escaped raw text as the fallback.
func notificationsRenderRunbookHTML(md string) (out string) {
	defer func() {
		if recover() != nil {
			slog.Warn("markdown renderer panicked rendering runbook; falling back to raw text")
			out = notificationsHTMLEscape(md)
		}
	}()
	var buf bytes.Buffer
	if err := notificationsMarkdown.Convert([]byte(md), &buf); err != nil {
		return notificationsHTMLEscape(md)
	}
	return buf.String()
}

func notificationsHTMLEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func notificationsAppendRunbookToHTML(bodyHTML, runbookHTML, runbookURL string) string {
	if runbookHTML == "" {
		return bodyHTML
	}
	link := ""
	if runbookURL != "" {
		link = fmt.Sprintf("<p style=\"margin:16px 0 8px\"><a href=\"%s\" style=\"color:#3b82f6;text-decoration:none;font-weight:600\">Open runbook in panel →</a></p>", runbookURL)
	}
	return bodyHTML +
		"<hr style=\"margin:24px 0;border:none;border-top:1px solid #e5e7eb\"/>" +
		"<h3 style=\"font-family:sans-serif;color:#111827;margin:0 0 12px\">Runbook</h3>" +
		"<div style=\"font-family:sans-serif;color:#374151;line-height:1.5\">" + runbookHTML + "</div>" +
		link
}

type notificationsRuleRow = Tup6[bool, *string, *string, *string, *string, string]

const notificationsRuleCols = "SELECT notify_email, notify_slack_url, notify_discord_url, notify_pagerduty_key, notify_webhook_url, muted_types "

// NotificationsGetUserChannels returns a user's channels from alert_rules:
// the server-specific row first, else the global (server_id IS NULL) row.
func NotificationsGetUserChannels(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID *uuid.UUID) *NotificationsNotifyChannels {
	var rule *notificationsRuleRow
	if serverID != nil {
		rule, _ = queryOpt[notificationsRuleRow](ctx, db, notificationsRuleCols+"FROM alert_rules WHERE user_id = $1 AND server_id = $2", userID, *serverID)
	}
	if rule == nil {
		rule, _ = queryOpt[notificationsRuleRow](ctx, db, notificationsRuleCols+"FROM alert_rules WHERE user_id = $1 AND server_id IS NULL", userID)
	}
	if rule == nil {
		return nil
	}
	// These four are encrypted at rest (alerts.rs::upsert_rules). This
	// function has only the pool (no AppState/jwt_secret) — exactly the
	// context decrypt_credential_from_env documents itself for.
	dec := func(p *string) *string {
		if p == nil {
			return nil
		}
		s := SecretsCryptoDecryptCredentialFromEnv(*p)
		return &s
	}
	var email *string
	if rule.A {
		email, _ = queryScalarOpt[string](ctx, db, "SELECT email FROM users WHERE id = $1", userID)
	}
	return &NotificationsNotifyChannels{
		Email: email, SlackURL: dec(rule.B), DiscordURL: dec(rule.C),
		PagerdutyKey: dec(rule.D), WebhookURL: dec(rule.E), MutedTypes: rule.F,
	}
}

// NotificationsGetUserPolicyID (Phase 4 W3): the escalation_policy_id for a
// user/server — specific row wins, global row is the fallback, none → nil.
func NotificationsGetUserPolicyID(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID *uuid.UUID) *uuid.UUID {
	if serverID != nil {
		specific, err := queryScalarOpt[*uuid.UUID](ctx, db, "SELECT escalation_policy_id FROM alert_rules WHERE user_id = $1 AND server_id = $2", userID, *serverID)
		if err == nil && specific != nil {
			// Specific row existed: its policy (possibly NULL = "no policy")
			// stands; only fall back when the specific row is absent.
			return *specific
		}
	}
	global, err := queryScalarOpt[*uuid.UUID](ctx, db, "SELECT escalation_policy_id FROM alert_rules WHERE user_id = $1 AND server_id IS NULL", userID)
	if err != nil || global == nil {
		return nil
	}
	return *global
}

// NotificationsLoadEscalationSteps (Phase 4 W3) decodes a policy's steps;
// empty on any failure.
func NotificationsLoadEscalationSteps(ctx context.Context, db *pgxpool.Pool, policyID uuid.UUID) []EscalationStep {
	raw, err := queryScalarOpt[json.RawMessage](ctx, db, "SELECT steps FROM escalation_policies WHERE id = $1", policyID)
	if err != nil || raw == nil {
		return []EscalationStep{}
	}
	var steps []EscalationStep
	if err := decodeJSONBytes(*raw, &steps); err != nil {
		slog.Warn(fmt.Sprintf("Failed to decode escalation_policy %s steps: %v", policyID, err))
		return []EscalationStep{}
	}
	return steps
}

// NotificationsDispatchEscalationStep (Phase 4 W3) resolves a step's route to
// users and pages each one's channels. alertOwnerID (alerts.user_id) is the
// fallback "channels of record".
func NotificationsDispatchEscalationStep(ctx context.Context, db *pgxpool.Pool, alertOwnerID uuid.UUID, alertOwnerServerID *uuid.UUID, alertType string, step *EscalationStep, subject, message, bodyHTML, severity string, runbookExcerpt, runbookURL *string) {
	route := step.Route
	toOwner := func() bool {
		return notificationsFanoutToUser(ctx, db, alertOwnerID, alertOwnerServerID, alertType, subject, message, bodyHTML, severity, runbookExcerpt, runbookURL)
	}
	if url, ok := strings.CutPrefix(route, "webhook:"); ok {
		// A step-level webhook has no user behind it, so the suppression that
		// applies is the alert owner's. This branch once synthesized an EMPTY
		// list, making the one route that never consults a user the one route
		// a mute could not reach — the settings grid names webhooks among what
		// a mute silences.
		if owner := NotificationsGetUserChannels(ctx, db, alertOwnerID, alertOwnerServerID); owner != nil && notificationsIsTypeMuted(owner, alertType) {
			slog.Debug(fmt.Sprintf("Alert type '%s' muted by the alert owner — skipping escalation webhook step", alertType))
			return
		}
		// Only webhook_url: the step names one destination.
		NotificationsSendNotificationWithRunbook(ctx, db, &NotificationsNotifyChannels{WebhookURL: &url}, subject, message, bodyHTML, severity, runbookExcerpt, runbookURL)
		return
	}

	if route == "all_channels" {
		// Fan out to the alert's owner — pre-W3 default behaviour.
		toOwner()
		return
	}

	// on_call_schedule:<uuid> or user:<uuid> → user IDs.
	users := OnCallRouteToUserIds(ctx, db, route)
	if len(users) == 0 {
		// Fail OPEN to the owner rather than dropping the page. An
		// unresolvable route (deleted schedule, emptied rota, deleted user,
		// malformed shape) used to swallow the notification — including the
		// INITIAL page of a critical alert, since try_fire_alert dispatches
		// step 0 and returns. A degraded delivery beats a missed outage.
		slog.Warn(fmt.Sprintf("dispatch_escalation_step: route %s resolved to no users — falling back to the alert owner's channels", route))
		toOwner()
		return
	}
	delivered := false
	for _, uid := range users {
		if notificationsFanoutToUser(ctx, db, uid, alertOwnerServerID, alertType, subject, message, bodyHTML, severity, runbookExcerpt, runbookURL) {
			delivered = true
		}
	}
	if !delivered {
		// Routed users exist but none has any notification configuration —
		// same effect as an unresolvable route (nobody paged). Degrade to the owner.
		slog.Warn(fmt.Sprintf("dispatch_escalation_step: no routed user for %s has notification channels — falling back to the alert owner", route))
		toOwner()
	}
}

// NotificationsSuppressibleAlertTypes is every alert type an operator can
// suppress from external channels. The Settings grid renders exactly this
// vocabulary and both write paths validate against it. It drifted once (a
// hand-written ten vs twenty producers — the missing half being the one that
// pages at 3am), so membership is every alert type the panel raises, pinned
// against the producers' call sites. slow_response is included: its recovery
// notice goes through the fan-out, and uptime's firing half now calls
// try_fire_alert too, so both halves honour the list.
var NotificationsSuppressibleAlertTypes = []string{
	"cpu",
	"memory",
	"disk",
	"disk_forecast",
	"memory_leak",
	"offline",
	"service_down",
	"container_down",
	"container_crashloop",
	"container_unhealthy",
	"gpu_utilization",
	"gpu_temperature",
	"gpu_vram",
	"backup_failure",
	"backup_verification_failed",
	"cron_failure",
	"ssl_expiry",
	"ssl_renewal_failure",
	"security",
	"image_scan",
	"wp_vuln_scan",
	"slow_response",
}

// NotificationsUnknownSuppressibleTypes returns the tokens of a stored
// suppression list that name no suppressible type — returned, not dropped: a
// value that persists and suppresses nothing is indistinguishable from a
// working mute. Write paths reject a non-empty result.
func NotificationsUnknownSuppressibleTypes(raw string) []string {
	out := []string{}
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s != "" && !slices.Contains(NotificationsSuppressibleAlertTypes, s) {
			out = append(out, s)
		}
	}
	return out
}

// notificationsIsTypeMuted (Gap #69) is single-sourced so a mute means the
// same on both edges of an alert's life: it once applied when firing and not
// when resolving, so a muted type still delivered "Resolved: X" for an X the
// operator was never told about.
func notificationsIsTypeMuted(c *NotificationsNotifyChannels, alertType string) bool {
	if c.MutedTypes == "" {
		return false
	}
	for _, t := range strings.Split(c.MutedTypes, ",") {
		if strings.TrimSpace(t) == alertType {
			return true
		}
	}
	return false
}

// notificationsFanoutToUser sends to one user's channels with their own mute
// applied. Returns whether the user was a SERVICEABLE destination: a
// deliberate mute counts (an escalation must not override chosen silence);
// only "no notification configuration at all" returns false.
func notificationsFanoutToUser(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID *uuid.UUID, alertType, subject, message, bodyHTML, severity string, runbookExcerpt, runbookURL *string) bool {
	channels := NotificationsGetUserChannels(ctx, db, userID, serverID)
	if channels == nil {
		// alert_rules rows exist only once a user opens alert settings, so a
		// valid rota member often has none — common, not corrupt.
		slog.Warn(fmt.Sprintf("No notification channels configured for user %s — cannot deliver '%s' page to them", userID, alertType))
		return false
	}
	if notificationsIsTypeMuted(channels, alertType) {
		slog.Debug(fmt.Sprintf("Alert type '%s' muted for routed user %s — skipping external channels", alertType, userID))
		return true
	}
	NotificationsSendNotificationWithRunbook(ctx, db, channels, subject, message, bodyHTML, severity, runbookExcerpt, runbookURL)
	return true
}

// NotificationsIsAlertEnabled: is this alert type enabled for the user?
// Default true when no rules exist.
func NotificationsIsAlertEnabled(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID *uuid.UUID, alertType string) bool {
	var column string
	switch alertType {
	case "cpu":
		column = "alert_cpu"
	case "memory":
		column = "alert_memory"
	case "disk":
		column = "alert_disk"
	case "offline":
		column = "alert_offline"
	case "backup_failure":
		column = "alert_backup_failure"
	case "ssl_expiry":
		column = "alert_ssl_expiry"
	case "service_down":
		column = "alert_service_health"
	case "gpu_utilization", "gpu_temperature", "gpu_vram":
		column = "alert_gpu"
	default:
		return true
	}
	// column comes from the fixed list above — safe to interpolate.
	var res *bool
	if serverID != nil {
		res, _ = queryScalarOpt[bool](ctx, db, fmt.Sprintf("SELECT %s FROM alert_rules WHERE user_id = $1 AND server_id = $2", column), userID, *serverID)
	}
	if res == nil {
		res, _ = queryScalarOpt[bool](ctx, db, fmt.Sprintf("SELECT %s FROM alert_rules WHERE user_id = $1 AND server_id IS NULL", column), userID)
	}
	return res == nil || *res
}

type notificationsThresholdRow struct {
	CPUThreshold    int32  `db:"cpu_threshold"`
	CPUDuration     int32  `db:"cpu_duration"`
	MemoryThreshold int32  `db:"memory_threshold"`
	MemoryDuration  int32  `db:"memory_duration"`
	DiskThreshold   int32  `db:"disk_threshold"`
	CooldownMinutes int32  `db:"cooldown_minutes"`
	SSLWarningDays  string `db:"ssl_warning_days"`
}

const notificationsThresholdSQL = "SELECT cpu_threshold, cpu_duration, memory_threshold, memory_duration, disk_threshold, cooldown_minutes, ssl_warning_days FROM alert_rules WHERE user_id = $1 AND server_id "

// NotificationsGetThresholds returns (cpu_threshold, cpu_duration,
// mem_threshold, mem_duration, disk_threshold, cooldown, ssl_days).
func NotificationsGetThresholds(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID *uuid.UUID) (int32, int32, int32, int32, int32, int32, string) {
	var row *notificationsThresholdRow
	if serverID != nil {
		row, _ = queryOpt[notificationsThresholdRow](ctx, db, notificationsThresholdSQL+"= $2", userID, *serverID)
	}
	if row == nil {
		// serverID == nil means "the user's global rule" — what
		// check_ssl_expiry asks for (SSL is site-scoped). This arm once
		// returned nothing, so a configured ssl_warning_days was never read.
		row, _ = queryOpt[notificationsThresholdRow](ctx, db, notificationsThresholdSQL+"IS NULL", userID)
	}
	if row == nil {
		return 90, 5, 90, 5, 85, 60, "30,14,7,3,1"
	}
	return row.CPUThreshold, row.CPUDuration, row.MemoryThreshold, row.MemoryDuration, row.DiskThreshold, row.CooldownMinutes, row.SSLWarningDays
}

// NotificationsGetGpuThresholds returns (gpu_util_threshold,
// gpu_util_duration, gpu_temp_threshold, gpu_vram_threshold, cooldown).
func NotificationsGetGpuThresholds(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID *uuid.UUID) (int32, int32, int32, int32, int32) {
	type gpuRow = Tup5[int32, int32, int32, int32, int32]
	const q = "SELECT gpu_util_threshold, gpu_util_duration, gpu_temp_threshold, gpu_vram_threshold, cooldown_minutes FROM alert_rules WHERE user_id = $1 AND server_id "
	var row *gpuRow
	if serverID != nil {
		row, _ = queryOpt[gpuRow](ctx, db, q+"= $2", userID, *serverID)
		if row == nil {
			row, _ = queryOpt[gpuRow](ctx, db, q+"IS NULL", userID)
		}
	}
	if row == nil {
		return 95, 5, 85, 95, 60
	}
	return row.A, row.B, row.C, row.D, row.E
}

// NotificationsFireAlert fires an alert ignoring errors. stateKey names the
// entity (container, service, GPU index) and MUST equal the key the caller
// writes to alert_state.state_key; "" for a server-wide condition. Required
// rather than defaulted so a new alert type cannot inherit the unscoped
// behaviour by saying nothing (see ResolveAlert).
func NotificationsFireAlert(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID, siteID *uuid.UUID, alertType, stateKey, severity, title, message string) {
	_, _ = NotificationsTryFireAlert(ctx, db, userID, serverID, siteID, alertType, stateKey, severity, title, message)
}

// SSL renewal state keys raised under alert_type "ssl_renewal_failure".
//
// Both SSL loops raise FIVE+ different conditions under that one type, and
// FireAlertDeduped dedups on (alert_type, site_id, state_key). With one
// whole-server key, whichever fired first muted the rest for twelve hours —
// and RenewalPlan::Refuse alerts every 12h while the downgrade it ends in
// fires in the cert's last week, always inside the window that hid it. Keyed
// per CONDITION (site_id already names the certificate), so the two loops
// still collapse to ONE alert for the same condition on the same site.
const (
	// The installed certificate was issued by somebody else. Announced, not failed.
	NotificationsSslRenewalKeyDeclined = "declined"
	// A renewal was attempted and failed.
	NotificationsSslRenewalKeyFailed = "failed"
	// A renewal could not be attempted at all (configuration problem).
	NotificationsSslRenewalKeyBlocked = "blocked"
	// A DNS-01 renewal refused while there is still time to fix the zone.
	NotificationsSslRenewalKeyDns01Declined = "dns01_declined"
	// A DNS-01 certificate downgraded to a single name in its last week.
	NotificationsSslRenewalKeyDns01Downgraded = "dns01_downgraded"
	// A mail host's certificate was NOT issued because it would have
	// overwritten one covering more names. Deliberately not BLOCKED: they say
	// opposite things about the SAME site_id, and sharing a key would let one
	// mute the other for twelve hours.
	NotificationsSslRenewalKeyMailHostConflict = "mail_host_conflict"
)

// NotificationsSslRenewalKeyAll is every key above. A new key MUST be added
// here too, or NotificationsRenewalSuccessClears never considers it.
var NotificationsSslRenewalKeyAll = [6]string{
	NotificationsSslRenewalKeyDeclined,
	NotificationsSslRenewalKeyFailed,
	NotificationsSslRenewalKeyBlocked,
	NotificationsSslRenewalKeyDns01Declined,
	NotificationsSslRenewalKeyDns01Downgraded,
	NotificationsSslRenewalKeyMailHostConflict,
}

// NotificationsRenewalSuccessClears: does a SUCCESSFUL renewal disprove the
// alert raised under key? Three keys say a renewal DID NOT HAPPEN; the other
// three describe the certificate installed NOW. The fall-through is false, so
// a later key is not resolved until somebody decides it should be — an
// unresolved alert is visible, a wrongly resolved one is silence.
func NotificationsRenewalSuccessClears(key string) bool {
	switch key {
	case NotificationsSslRenewalKeyFailed, NotificationsSslRenewalKeyBlocked, NotificationsSslRenewalKeyDns01Declined:
		return true
	}
	return false
}

// NotificationsResolveSslRenewalFailure clears the ssl_renewal_failure
// alerts a SUCCESSFUL renewal disproves. ssl_renewal_failure never learned to
// resolve itself, so a cert that failed, was fixed and renewed left the
// critical alert firing forever (retention only collects resolved rows).
//
// Only FAILED/BLOCKED/DNS01_DECLINED. DNS01_DOWNGRADED stays: the names really
// are uncovered, and it is RAISED on this same success path while
// FireAlertDeduped windows on created_at regardless of status — resolving it
// would swallow its own re-fire. DECLINED (someone else's cert) and
// MAIL_HOST_CONFLICT remain true after a renewal too.
//
// Scoped by site with serverID nil ON PURPOSE: ResolveAlert picks its arm on
// serverID first, and the security scanner fires with no server while the
// auto-healer fires with one — only the site arm matches both shapes.
// ResolveAlert no-ops when nothing is firing.
func NotificationsResolveSslRenewalFailure(ctx context.Context, db *pgxpool.Pool, userID, siteID uuid.UUID, domain string) {
	for _, key := range NotificationsSslRenewalKeyAll {
		if !NotificationsRenewalSuccessClears(key) {
			continue
		}
		NotificationsResolveAlert(ctx, db, userID, nil, &siteID, "ssl_renewal_failure", key,
			"SSL renewal recovered: "+domain,
			fmt.Sprintf("The certificate for %s renewed successfully, so the earlier renewal alert no longer applies.", domain))
	}
}

// NotificationsFireAlertDeduped fires unless the same (type, site, key)
// already fired within withinHours. The certificate loops run every two
// minutes; an unconditional alert from them is a flood, and a flood is how a
// real alert gets muted. Deduping against the alerts table avoids a second
// piece of state that can disagree with the first. Scoped by state_key too:
// two certificates on one site are two subjects.
func NotificationsFireAlertDeduped(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID, siteID *uuid.UUID, alertType, stateKey, severity, title, message string, withinHours int64) {
	// withinHours is a typed int64 — safe to interpolate, and it keeps
	// Postgres from inferring a parameter type inside an interval expression.
	recent, err := queryScalarOpt[int64](ctx, db, fmt.Sprintf(
		"SELECT COUNT(*) FROM alerts WHERE alert_type = $1 AND site_id IS NOT DISTINCT FROM $2 AND state_key = $3 AND created_at > NOW() - INTERVAL '%d hours'",
		withinHours), alertType, siteID, stateKey)
	if err == nil && recent != nil && *recent > 0 {
		return
	}
	NotificationsFireAlert(ctx, db, userID, serverID, siteID, alertType, stateKey, severity, title, message)
}

// NotificationsTryFireAlert fires an alert. (true, nil): a row was written
// and the fan-out ran. (false, nil): the operator switched this type off in
// alert_rules, so NOTHING happened.
//
// The two once collapsed into one answer, and both readers were wrong for a
// disabled type: fire_alert_with_retry auto-creates a managed_incidents row
// visible on the PUBLIC status page (so "do not tell me" told everybody), and
// the SSL ladder gates its last_warned_day stamp on it, so a disabled
// ssl_expiry burned rungs that re-enabling never brought back.
func NotificationsTryFireAlert(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID, siteID *uuid.UUID, alertType, stateKey, severity, title, message string) (bool, error) {
	if !NotificationsIsAlertEnabled(ctx, db, userID, serverID, alertType) {
		return false, nil
	}

	// state_key mirrors alert_state.state_key so the resolve path can target
	// this exact entity's row.
	if _, err := execSQL(ctx, db,
		"INSERT INTO alerts (user_id, server_id, site_id, alert_type, state_key, severity, title, message) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		userID, serverID, siteID, alertType, stateKey, severity, title, message); err != nil {
		return false, fmt.Errorf("Failed to record alert: %v", err)
	}

	// Panel notification center (bell icon) — notify all admins.
	link := "/monitoring?tab=alerts"
	NotificationsNotifyPanel(ctx, db, nil, title, message, severity, "alert", &link)

	subject := "DockPanel Alert: " + title
	html := fmt.Sprintf("<div style=\"font-family:sans-serif;max-width:600px;margin:0 auto\">"+
		"<h2 style=\"color:%s\">%s</h2>"+
		"<p>%s</p>"+
		"<p style=\"color:#6b7280;font-size:14px\">Time: %s</p>"+
		"</div>",
		NotificationsSeverityColor(severity), title, message, time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	// Phase 4 W2 + W3: runbook attachment, shared with check_escalations.
	runbookExcerpt, runbookURL := NotificationsLoadRunbookPayload(ctx, db, alertType)

	// Phase 4 W3: an escalation policy pages only step 0's route (e.g. the
	// current on-call user). NULL policy keeps the pre-W3 behaviour exactly.
	if pid := NotificationsGetUserPolicyID(ctx, db, userID, serverID); pid != nil {
		steps := NotificationsLoadEscalationSteps(ctx, db, *pid)
		if len(steps) > 0 {
			NotificationsDispatchEscalationStep(ctx, db, userID, serverID, alertType, &steps[0], subject, message, html, severity, runbookExcerpt, runbookURL)
			return true, nil
		}
		slog.Warn(fmt.Sprintf("Alert rule references escalation_policy %s with empty/invalid steps — falling back to default channel fan-out", pid))
	}

	notificationsFanoutToUser(ctx, db, userID, serverID, alertType, subject, message, html, severity, runbookExcerpt, runbookURL)
	return true, nil
}

// NotificationsNotifyPanel inserts into the panel notification center (bell)
// and broadcasts via SSE. userID nil notifies all admins.
func NotificationsNotifyPanel(ctx context.Context, db *pgxpool.Pool, userID *uuid.UUID, title, message, severity, category string, link *string) {
	if userID != nil {
		notificationsInsertAndBroadcast(ctx, db, *userID, title, message, severity, category, link)
		return
	}
	admins, _ := queryAll[uuid.UUID](ctx, db, "SELECT id FROM users WHERE role = 'admin'")
	for _, id := range admins {
		notificationsInsertAndBroadcast(ctx, db, id, title, message, severity, category, link)
	}
}

// notificationsInsertAndBroadcast writes one recipient's row, then broadcasts
// what was written. A failed INSERT once vanished silently (the one class of
// message whose job is reporting failure); it still is not returned — a
// caller reporting a deploy result must not fail because of it — but is
// logged at error. The SSE payload carries the RETURNING id/created_at (and
// read_at) so a live list can prepend it instead of re-fetching.
func notificationsInsertAndBroadcast(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, title, message, severity, category string, link *string) {
	row, err := queryOne[Tup2[uuid.UUID, time.Time]](ctx, db,
		"INSERT INTO panel_notifications (user_id, title, message, severity, category, link) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at",
		userID, title, message, severity, category, link)
	if err != nil {
		slog.Error(fmt.Sprintf("notification not stored for %s (%s/%s): %s — %v", userID, category, severity, title, err))
		return
	}
	if tx := notificationsNotifTx.Load(); tx != nil {
		b, _ := json.Marshal(map[string]any{
			"id":         row.A,
			"title":      title,
			"message":    message,
			"severity":   severity,
			"category":   category,
			"link":       link,
			"read_at":    nil,
			"created_at": row.B.UTC(),
		})
		tx.Send(PanelNotification{UserID: userID, Payload: string(b)})
	}
}

// NotificationsResolveAlert resolves a firing alert and sends a recovery
// notice. stateKey MUST be the key the matching fire used: alert_state is
// keyed (server_id, alert_type, state_key), and an UPDATE keyed only on
// (user, server, type) once let one container's recovery resolve every
// sibling's alert — whose alert_state stayed firing, so a transition-driven
// engine never re-announced them. The recovery page is sent only when a row
// was actually resolved: "Resolved: X" for something never firing is a false
// all-clear, and two auto_healer callers reach here without checking.
func NotificationsResolveAlert(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, serverID, siteID *uuid.UUID, alertType, stateKey, title, message string) {
	// The third arm: monitors.site_id is nullable, so a bare-URL monitor fires
	// with both ids NULL; a non-empty key IS the scope. Both ids NULL and an
	// empty key is still a refusal (it would match every server-wide alert).
	var query string
	switch {
	case serverID != nil:
		query = "UPDATE alerts SET status = 'resolved', resolved_at = NOW() WHERE user_id = $1 AND server_id = $2 AND alert_type = $3 AND state_key = $4 AND status = 'firing'"
	case siteID != nil:
		query = "UPDATE alerts SET status = 'resolved', resolved_at = NOW() WHERE user_id = $1 AND site_id = $2 AND alert_type = $3 AND state_key = $4 AND status = 'firing'"
	case stateKey != "":
		// $2::uuid is cast because this arm references it for nothing else,
		// and an untypeable parameter is how the slow-response INSERT stayed
		// dead for months (see uptime).
		query = "UPDATE alerts SET status = 'resolved', resolved_at = NOW() WHERE user_id = $1 AND $2::uuid IS NULL AND alert_type = $3 AND state_key = $4 AND status = 'firing'"
	default:
		slog.Warn(fmt.Sprintf("resolve_alert called for '%s' with no server_id, no site_id and no state_key — refusing to resolve unscoped", alertType))
		return
	}
	scope := serverID
	if scope == nil {
		scope = siteID
	}
	resolved, err := execSQL(ctx, db, query, userID, scope, alertType, stateKey)
	if err != nil {
		// A failed UPDATE must not become a recovery page.
		slog.Warn(fmt.Sprintf("resolve_alert UPDATE failed for '%s' key '%s': %v", alertType, stateKey, err))
		return
	}
	if resolved == 0 {
		slog.Debug(fmt.Sprintf("resolve_alert: nothing firing for '%s' key '%s' — no recovery notice sent", alertType, stateKey))
		return
	}

	// Honour the same per-type mute the firing path honours.
	if channels := NotificationsGetUserChannels(ctx, db, userID, serverID); channels != nil {
		if notificationsIsTypeMuted(channels, alertType) {
			slog.Debug(fmt.Sprintf("Alert type '%s' muted for user %s — skipping recovery notice", alertType, userID))
		} else {
			html := fmt.Sprintf("<div style=\"font-family:sans-serif;max-width:600px;margin:0 auto\">"+
				"<h2 style=\"color:#10b981\">%s</h2>"+
				"<p>%s</p>"+
				"<p style=\"color:#6b7280;font-size:14px\">Time: %s</p>"+
				"</div>", title, message, time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
			NotificationsSendNotification(ctx, db, channels, "DockPanel Resolved: "+title, message, html)
		}
	}

	link := "/monitoring?tab=alerts"
	NotificationsNotifyPanel(ctx, db, &userID, "Resolved: "+title, message, "info", "alert", &link)
}
