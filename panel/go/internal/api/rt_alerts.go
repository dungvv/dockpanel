package api

// Port of panel/backend/src/routes/alerts.rs.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

func rtAlertsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/alerts", h(rtAlertsList))
	r.Handle("GET /api/alerts/summary", h(rtAlertsSummary))
	// ServeMux cannot hold both PUT /api/alerts/runbooks/{alert_type} and
	// PUT /api/alerts/{id}/acknowledge (matchit preferred the static
	// segment), so one pattern dispatches in matchit's order.
	r.Handle("PUT /api/alerts/{a}/{b}", h(rtAlertsPutDispatch))
	r.Handle("GET /api/alert-rules", h(rtAlertsGetRules))
	r.Handle("PUT /api/alert-rules", h(rtAlertsUpdateRules))
	r.Handle("PUT /api/alert-rules/{server_id}", h(rtAlertsUpdateServerRules))
	r.Handle("DELETE /api/alert-rules/{server_id}", h(rtAlertsDeleteServerRules))
	r.Handle("PUT /api/alert-rules/{rule_id}/escalation-policy", h(rtAlertsAttachEscalationPolicy))
	r.Handle("GET /api/alerts/runbooks", h(rtAlertsListRunbooksRoute))
	r.Handle("POST /api/alerts/runbooks/apply-defaults", h(rtAlertsApplyDefaults))
	r.Handle("GET /api/alerts/runbooks/{alert_type}", h(rtAlertsGetRunbookRoute))
	r.Handle("DELETE /api/alerts/runbooks/{alert_type}", h(rtAlertsDeleteRunbook))
}

// rtAlertsPutDispatch: `runbooks` as the first segment is the static route
// and wins; otherwise the second segment names the action.
func rtAlertsPutDispatch(st *AppState, w http.ResponseWriter, r *http.Request) error {
	a, b := r.PathValue("a"), r.PathValue("b")
	switch {
	case a == "runbooks":
		r.SetPathValue("alert_type", b)
		return rtAlertsPutRunbook(st, w, r)
	case b == "acknowledge":
		r.SetPathValue("id", a)
		return rtAlertsAcknowledge(st, w, r)
	case b == "resolve":
		r.SetPathValue("id", a)
		return rtAlertsResolve(st, w, r)
	}
	w.WriteHeader(http.StatusNotFound)
	return nil
}

type rtAlertsAlertQuery struct {
	Status    *string `json:"status"`
	AlertType *string `json:"alert_type"`
	Limit     *int64  `json:"limit"`
}

type rtAlertsAlertRow struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	ServerID       *uuid.UUID `json:"server_id" db:"server_id"`
	SiteID         *uuid.UUID `json:"site_id" db:"site_id"`
	AlertType      string     `json:"alert_type" db:"alert_type"`
	Severity       string     `json:"severity" db:"severity"`
	Title          string     `json:"title" db:"title"`
	Message        string     `json:"message" db:"message"`
	Status         string     `json:"status" db:"status"`
	NotifiedAt     time.Time  `json:"notified_at" db:"notified_at"`
	ResolvedAt     *time.Time `json:"resolved_at" db:"resolved_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at" db:"acknowledged_at"`
	// Phase 4 W3: actor who ack'd (NULL on legacy rows + un-ack'd alerts).
	AcknowledgedBy *uuid.UUID `json:"acknowledged_by" db:"acknowledged_by"`
	// Resolved via LEFT JOIN users — surfaces email for the UI's "Ack by"
	// column without forcing the frontend into N+1 lookups.
	AcknowledgedByEmail *string `json:"acknowledged_by_email" db:"acknowledged_by_email"`
	// Phase 4 W3: optional free-text note from the actor (500-char cap).
	AcknowledgedComment *string `json:"acknowledged_comment" db:"acknowledged_comment"`
	// Phase 4 W3: position in the policy chain — 0 means initial fire.
	EscalationStepIndex int32     `json:"escalation_step_index" db:"escalation_step_index"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
}

// rtAlertsList is GET /api/alerts — list alerts with optional filters.
func rtAlertsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var q rtAlertsAlertQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	limit := int64(100)
	if q.Limit != nil {
		limit = *q.Limit
	}
	limit = min(limit, 500)

	// Build dynamic query — scoped to the caller, then to the ServerScope
	// server. NULL server_id is admitted: backup_failure, cron_failure,
	// security-scan and ssl_expiry alerts are fired with server_id = None (they
	// are site- or account-scoped), and a bare `server_id = $2` predicate hid
	// that entire class from the list and the summary permanently — including
	// criticals — while the bell, external channels and the escalation engine
	// all still paged for them. Deleting a server also NULLs the column
	// (ON DELETE SET NULL), which used to make its alert history vanish.
	// LEFT JOIN users resolves acknowledged_by → email for the UI without
	// forcing N+1 fetches from the frontend.
	sql := "SELECT a.id, a.server_id, a.site_id, a.alert_type, a.severity, a.title, " +
		"a.message, a.status, a.notified_at, a.resolved_at, a.acknowledged_at, " +
		"a.acknowledged_by, u.email AS acknowledged_by_email, " +
		"a.acknowledged_comment, a.escalation_step_index, a.created_at " +
		"FROM alerts a " +
		"LEFT JOIN users u ON u.id = a.acknowledged_by " +
		"WHERE a.user_id = $1 AND (a.server_id = $2 OR a.server_id IS NULL)"
	args := []any{claims.Sub, serverID}
	paramIdx := 3

	if q.Status != nil {
		sql += fmt.Sprintf(" AND a.status = $%d", paramIdx)
		paramIdx++
		args = append(args, *q.Status)
	}
	if q.AlertType != nil {
		sql += fmt.Sprintf(" AND a.alert_type = $%d", paramIdx)
		args = append(args, *q.AlertType)
	}

	sql += fmt.Sprintf(" ORDER BY a.created_at DESC LIMIT %d", limit)

	alerts, err := queryAll[rtAlertsAlertRow](r.Context(), st.DB, sql, args...)
	if err != nil {
		return internalError("list alerts", err)
	}
	writeJSON(w, http.StatusOK, alerts)
	return nil
}

// rtAlertsSummary is GET /api/alerts/summary — count of alerts by status.
func rtAlertsSummary(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	// Same NULL-server_id admission as list() — the two must agree or the
	// badge count contradicts the rows underneath it.
	counts, err := queryAll[Tup2[string, int64]](r.Context(), st.DB,
		"SELECT status, COUNT(*) FROM alerts "+
			"WHERE user_id = $1 AND (server_id = $2 OR server_id IS NULL) "+
			"AND created_at > NOW() - INTERVAL '30 days' "+
			"GROUP BY status", claims.Sub, serverID)
	if err != nil {
		return internalError("summary", err)
	}

	find := func(s string) int64 {
		for _, c := range counts {
			if c.A == s {
				return c.B
			}
		}
		return 0
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"firing":       find("firing"),
		"acknowledged": find("acknowledged"),
		"resolved":     find("resolved"),
	})
	return nil
}

// rtAlertsAcknowledgePayload (Phase 4 W3) is the optional payload for
// acknowledge. An empty body still works — Option<Json<…>> is None when no
// content-type is sent, so older clients that PUT with no body keep working.
type rtAlertsAcknowledgePayload struct {
	Comment *string `json:"comment"`
}

// rtAlertsAcknowledge is PUT /api/alerts/{id}/acknowledge.
//
// Phase 4 W3: stores the acting user (claims.Sub) on the row plus an optional
// 500-char comment. Older clients that PUT with no body still work — the only
// state difference is acknowledged_by instead of NULL.
func rtAlertsAcknowledge(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	// axum 0.8 Option<Json<T>>: no Content-Type → None; any Content-Type is
	// then held to Json<T>'s rules (non-JSON → 415, bad body → 400/422).
	var payload rtAlertsAcknowledgePayload
	if _, present := r.Header["Content-Type"]; present {
		if err := decodeJSON(r, &payload); err != nil {
			return err
		}
	}
	var comment *string
	if payload.Comment != nil {
		if c := strings.TrimSpace(*payload.Comment); c != "" {
			comment = &c
		}
	}
	if comment != nil {
		// Char count, not byte length — the cap is "what the operator typed."
		if utf8.RuneCountInString(*comment) > 500 {
			return apiErr(http.StatusBadRequest, "Comment cannot exceed 500 characters")
		}
	}

	n, err := execSQL(r.Context(), st.DB,
		"UPDATE alerts SET status = 'acknowledged', acknowledged_at = NOW(), "+
			"acknowledged_by = $3, acknowledged_comment = $4 "+
			"WHERE id = $1 AND user_id = $2 AND status = 'firing'",
		id, claims.Sub, claims.Sub, comment)
	if err != nil {
		return internalError("acknowledge", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Alert not found or already handled")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtAlertsResolve is PUT /api/alerts/{id}/resolve — manually resolve an alert.
func rtAlertsResolve(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB,
		"UPDATE alerts SET status = 'resolved', resolved_at = NOW() "+
			"WHERE id = $1 AND user_id = $2 AND status IN ('firing', 'acknowledged')",
		id, claims.Sub)
	if err != nil {
		return internalError("resolve", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Alert not found or already resolved")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

type rtAlertsAlertRuleRow struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	ServerID           *uuid.UUID `json:"server_id" db:"server_id"`
	CPUThreshold       int32      `json:"cpu_threshold" db:"cpu_threshold"`
	CPUDuration        int32      `json:"cpu_duration" db:"cpu_duration"`
	MemoryThreshold    int32      `json:"memory_threshold" db:"memory_threshold"`
	MemoryDuration     int32      `json:"memory_duration" db:"memory_duration"`
	DiskThreshold      int32      `json:"disk_threshold" db:"disk_threshold"`
	AlertCPU           bool       `json:"alert_cpu" db:"alert_cpu"`
	AlertMemory        bool       `json:"alert_memory" db:"alert_memory"`
	AlertDisk          bool       `json:"alert_disk" db:"alert_disk"`
	AlertOffline       bool       `json:"alert_offline" db:"alert_offline"`
	AlertBackupFailure bool       `json:"alert_backup_failure" db:"alert_backup_failure"`
	AlertSSLExpiry     bool       `json:"alert_ssl_expiry" db:"alert_ssl_expiry"`
	AlertServiceHealth bool       `json:"alert_service_health" db:"alert_service_health"`
	SSLWarningDays     string     `json:"ssl_warning_days" db:"ssl_warning_days"`
	NotifyEmail        bool       `json:"notify_email" db:"notify_email"`
	NotifySlackURL     *string    `json:"notify_slack_url" db:"notify_slack_url"`
	NotifyDiscordURL   *string    `json:"notify_discord_url" db:"notify_discord_url"`
	CooldownMinutes    int32      `json:"cooldown_minutes" db:"cooldown_minutes"`
	NotifyPagerdutyKey *string    `json:"notify_pagerduty_key" db:"notify_pagerduty_key"`
	NotifyWebhookURL   *string    `json:"notify_webhook_url" db:"notify_webhook_url"`
	// Comma-separated alert types to suppress from external channels (Gap #69)
	MutedTypes string `json:"muted_types" db:"muted_types"`
	// GPU alert thresholds (Phase 2 #2)
	GPUUtilThreshold int32 `json:"gpu_util_threshold" db:"gpu_util_threshold"`
	GPUUtilDuration  int32 `json:"gpu_util_duration" db:"gpu_util_duration"`
	GPUTempThreshold int32 `json:"gpu_temp_threshold" db:"gpu_temp_threshold"`
	GPUVramThreshold int32 `json:"gpu_vram_threshold" db:"gpu_vram_threshold"`
	AlertGPU         bool  `json:"alert_gpu" db:"alert_gpu"`
	// Phase 4 W3: escalation policy attached to this rule. NULL = pre-W3
	// hardcoded cadence (15 min unack → 30 min re-page).
	EscalationPolicyID *uuid.UUID `json:"escalation_policy_id" db:"escalation_policy_id"`
}

// rtAlertsGetRules is GET /api/alert-rules — the caller's alert rules.
func rtAlertsGetRules(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	rules, err := queryAll[rtAlertsAlertRuleRow](r.Context(), st.DB,
		"SELECT id, server_id, cpu_threshold, cpu_duration, memory_threshold, memory_duration, "+
			"disk_threshold, alert_cpu, alert_memory, alert_disk, alert_offline, "+
			"alert_backup_failure, alert_ssl_expiry, alert_service_health, "+
			"ssl_warning_days, notify_email, notify_slack_url, notify_discord_url, cooldown_minutes, "+
			"notify_pagerduty_key, notify_webhook_url, muted_types, "+
			"gpu_util_threshold, gpu_util_duration, gpu_temp_threshold, gpu_vram_threshold, alert_gpu, "+
			"escalation_policy_id "+
			"FROM alert_rules WHERE user_id = $1 ORDER BY server_id NULLS FIRST LIMIT 500", claims.Sub)
	if err != nil {
		return internalError("get rules", err)
	}

	// These four columns are encrypted at rest (EncryptCredential in
	// upsertRules below); the caller reading their OWN rule row back to
	// pre-fill the settings form is the expected, same-account case
	// DecryptCredentialOrLegacy exists for.
	dec := func(p *string) *string {
		if p == nil {
			return nil
		}
		v := SecretsCryptoDecryptCredentialOrLegacy(*p, st.Config.JWTSecret)
		return &v
	}
	for i := range rules {
		rules[i].NotifySlackURL = dec(rules[i].NotifySlackURL)
		rules[i].NotifyDiscordURL = dec(rules[i].NotifyDiscordURL)
		rules[i].NotifyPagerdutyKey = dec(rules[i].NotifyPagerdutyKey)
		rules[i].NotifyWebhookURL = dec(rules[i].NotifyWebhookURL)
	}
	writeJSON(w, http.StatusOK, rules)
	return nil
}

type rtAlertsUpdateRulesBody struct {
	CPUThreshold       *int32  `json:"cpu_threshold"`
	CPUDuration        *int32  `json:"cpu_duration"`
	MemoryThreshold    *int32  `json:"memory_threshold"`
	MemoryDuration     *int32  `json:"memory_duration"`
	DiskThreshold      *int32  `json:"disk_threshold"`
	AlertCPU           *bool   `json:"alert_cpu"`
	AlertMemory        *bool   `json:"alert_memory"`
	AlertDisk          *bool   `json:"alert_disk"`
	AlertOffline       *bool   `json:"alert_offline"`
	AlertBackupFailure *bool   `json:"alert_backup_failure"`
	AlertSSLExpiry     *bool   `json:"alert_ssl_expiry"`
	AlertServiceHealth *bool   `json:"alert_service_health"`
	SSLWarningDays     *string `json:"ssl_warning_days"`
	NotifyEmail        *bool   `json:"notify_email"`
	NotifySlackURL     *string `json:"notify_slack_url"`
	NotifyDiscordURL   *string `json:"notify_discord_url"`
	CooldownMinutes    *int32  `json:"cooldown_minutes"`
	NotifyPagerdutyKey *string `json:"notify_pagerduty_key"`
	NotifyWebhookURL   *string `json:"notify_webhook_url"`
	// Comma-separated alert types to suppress from external channels (Gap #69)
	MutedTypes *string `json:"muted_types"`
	// GPU alert thresholds (Phase 2 #2)
	GPUUtilThreshold *int32 `json:"gpu_util_threshold"`
	GPUUtilDuration  *int32 `json:"gpu_util_duration"`
	GPUTempThreshold *int32 `json:"gpu_temp_threshold"`
	GPUVramThreshold *int32 `json:"gpu_vram_threshold"`
	AlertGPU         *bool  `json:"alert_gpu"`
}

// rtAlertsUpdateRules is PUT /api/alert-rules — create or update global alert rules.
func rtAlertsUpdateRules(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtAlertsUpdateRulesBody
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	return rtAlertsUpsertRules(st, w, r, claims.Sub, nil, &body)
}

// rtAlertsUpdateServerRules is PUT /api/alert-rules/{server_id} — create or
// update per-server alert rules.
//
// ⚠ SECURITY (s433): server_id comes from the URL, not from anything scoped to
// the caller — without an ownership check here, any authenticated user could
// PUT rules for a server_id they don't own. upsertRules's own existence lookup
// is `WHERE user_id = $1 AND server_id = $2`, so a non-owner's write was never
// actually overwriting the real owner's row — it was silently INSERTing a
// second, independent row for that server_id (alert_rules only enforces
// UNIQUE(user_id, server_id), not UNIQUE(server_id)), a stray row
// drift's fetch_alert_rules had to defend against (s432).
//
// This does NOT widen for role == "admin", unlike the read routes s432 fixed —
// and that's not an inconsistency, it's a different axis entirely: a single
// resource resolved by a caller-supplied ID (this route, ServerScope,
// metrics' server_metrics, servers' own single-server writes) never widens for
// anyone, admin included — an account only acts on what it's the registered
// owner of. What widens is a FLEET-WIDE AGGREGATE with no mandatory
// per-resource ID (dashboard's fleet_overview/metrics_history/
// gpu_metrics_history/timeline, drift) — there an admin legitimately needs the
// whole install's data in one read. SiteCallerPredicate's admin arm looks like
// a third case (a WRITE that DOES widen) but isn't a counterexample — it's
// site-specific: a site's owner (often a `client` account) and the admin who
// registered the underlying SERVER are legitimately different people, which
// this route has no equivalent of.
func rtAlertsUpdateServerRules(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, err := pathUUID(r, "server_id")
	if err != nil {
		return err
	}
	var body rtAlertsUpdateRulesBody
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	owns, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB,
		"SELECT id FROM servers WHERE id = $1 AND user_id = $2", serverID, claims.Sub)
	if err != nil {
		return internalError("check server ownership", err)
	}
	if owns == nil {
		return apiErr(http.StatusNotFound, "Server not found")
	}
	return rtAlertsUpsertRules(st, w, r, claims.Sub, &serverID, &body)
}

func rtAlertsUpsertRules(st *AppState, w http.ResponseWriter, r *http.Request, userID uuid.UUID, serverID *uuid.UUID, body *rtAlertsUpdateRulesBody) error {
	ctx := r.Context()
	// SSRF protection: validate notification webhook URLs
	for _, c := range []struct {
		v     *string
		label string
	}{{body.NotifyWebhookURL, "webhook"}, {body.NotifySlackURL, "Slack"}, {body.NotifyDiscordURL, "Discord"}} {
		if c.v != nil && *c.v != "" {
			if err := validateURLNotInternal(ctx, *c.v); err != nil {
				return apiErr(http.StatusBadRequest, fmt.Sprintf("Invalid %s URL: %s", c.label, err))
			}
		}
	}

	// Encrypt at rest — validated above on PLAINTEXT (SSRF check needs a real
	// URL), encrypted here before it ever reaches SQL. nil means "leave the
	// stored value alone" (the COALESCE below depends on that), "" means
	// "clear it", so both are passed through unencrypted; only a genuine
	// non-empty value is encrypted. Read back via DecryptCredentialOrLegacy in
	// getRules above.
	encErr := error(nil)
	encryptOpt := func(v *string) *string {
		if v == nil || *v == "" || encErr != nil {
			return v
		}
		s, err := SecretsCryptoEncryptCredential(*v, st.Config.JWTSecret)
		if err != nil {
			encErr = internalError("encrypt notification credential", err)
			return nil
		}
		return &s
	}
	encSlackURL := encryptOpt(body.NotifySlackURL)
	encDiscordURL := encryptOpt(body.NotifyDiscordURL)
	encPagerdutyKey := encryptOpt(body.NotifyPagerdutyKey)
	encWebhookURL := encryptOpt(body.NotifyWebhookURL)
	if encErr != nil {
		return encErr
	}

	// A suppression list is matched token-for-token against the alert type on
	// the fan-out, so a token that names nothing suppresses nothing. Stored
	// unchecked it then echoed back on every read as though it had worked, and
	// the operator kept being paged by a type their own settings showed as
	// off. Reject it here, naming the token, rather than accept a setting that
	// cannot do what it says.
	if body.MutedTypes != nil {
		if unknown := NotificationsUnknownSuppressibleTypes(*body.MutedTypes); len(unknown) > 0 {
			return apiErr(http.StatusBadRequest, fmt.Sprintf(
				"Unknown alert type(s) in muted_types: %s. Suppressible types are: %s",
				strings.Join(unknown, ", "), strings.Join(NotificationsSuppressibleAlertTypes, ", ")))
		}
	}

	// Check if rule exists (partial unique indexes don't work with ON CONFLICT)
	var existing *uuid.UUID
	var err error
	if serverID != nil {
		existing, err = queryScalarOpt[uuid.UUID](ctx, st.DB,
			"SELECT id FROM alert_rules WHERE user_id = $1 AND server_id = $2", userID, serverID)
	} else {
		existing, err = queryScalarOpt[uuid.UUID](ctx, st.DB,
			"SELECT id FROM alert_rules WHERE user_id = $1 AND server_id IS NULL", userID)
	}
	if err != nil {
		return internalError("check alert rule exists", err)
	}

	var query string
	if existing != nil {
		// `$2::uuid IS NULL` (always true here) only gives the otherwise
		// unreferenced $2 a type: sqlx sent parameter types, pgx lets the
		// server infer them, and an unreferenced parameter cannot be inferred.
		whereClause := "WHERE user_id = $1 AND server_id IS NULL AND $2::uuid IS NULL"
		if serverID != nil {
			whereClause = "WHERE user_id = $1 AND server_id = $2"
		}
		query = "UPDATE alert_rules SET " +
			"cpu_threshold = COALESCE($3, cpu_threshold), " +
			"cpu_duration = COALESCE($4, cpu_duration), " +
			"memory_threshold = COALESCE($5, memory_threshold), " +
			"memory_duration = COALESCE($6, memory_duration), " +
			"disk_threshold = COALESCE($7, disk_threshold), " +
			"alert_cpu = COALESCE($8, alert_cpu), " +
			"alert_memory = COALESCE($9, alert_memory), " +
			"alert_disk = COALESCE($10, alert_disk), " +
			"alert_offline = COALESCE($11, alert_offline), " +
			"alert_backup_failure = COALESCE($12, alert_backup_failure), " +
			"alert_ssl_expiry = COALESCE($13, alert_ssl_expiry), " +
			"alert_service_health = COALESCE($14, alert_service_health), " +
			"ssl_warning_days = COALESCE($15, ssl_warning_days), " +
			"notify_email = COALESCE($16, notify_email), " +
			"notify_slack_url = COALESCE($17, notify_slack_url), " +
			"notify_discord_url = COALESCE($18, notify_discord_url), " +
			"cooldown_minutes = COALESCE($19, cooldown_minutes), " +
			"notify_pagerduty_key = COALESCE($20, notify_pagerduty_key), " +
			"notify_webhook_url = COALESCE($21, notify_webhook_url), " +
			"muted_types = COALESCE($22, muted_types), " +
			"gpu_util_threshold = COALESCE($23, gpu_util_threshold), " +
			"gpu_util_duration = COALESCE($24, gpu_util_duration), " +
			"gpu_temp_threshold = COALESCE($25, gpu_temp_threshold), " +
			"gpu_vram_threshold = COALESCE($26, gpu_vram_threshold), " +
			"alert_gpu = COALESCE($27, alert_gpu), " +
			"updated_at = NOW() " +
			whereClause
	} else {
		query = "INSERT INTO alert_rules (user_id, server_id, " +
			"cpu_threshold, cpu_duration, memory_threshold, memory_duration, disk_threshold, " +
			"alert_cpu, alert_memory, alert_disk, alert_offline, alert_backup_failure, " +
			"alert_ssl_expiry, alert_service_health, ssl_warning_days, " +
			"notify_email, notify_slack_url, notify_discord_url, cooldown_minutes, " +
			"notify_pagerduty_key, notify_webhook_url, muted_types, " +
			"gpu_util_threshold, gpu_util_duration, gpu_temp_threshold, gpu_vram_threshold, alert_gpu) " +
			"VALUES ($1, $2, " +
			"COALESCE($3, 90), COALESCE($4, 5), COALESCE($5, 90), COALESCE($6, 5), COALESCE($7, 85), " +
			"COALESCE($8, TRUE), COALESCE($9, TRUE), COALESCE($10, TRUE), COALESCE($11, TRUE), " +
			"COALESCE($12, TRUE), COALESCE($13, TRUE), COALESCE($14, TRUE), COALESCE($15, '30,14,7,3,1'), " +
			"COALESCE($16, TRUE), $17, $18, COALESCE($19, 60), $20, $21, COALESCE($22, ''), " +
			"COALESCE($23, 95), COALESCE($24, 5), COALESCE($25, 85), COALESCE($26, 95), COALESCE($27, TRUE))"
	}

	if _, err := execSQL(ctx, st.DB, query,
		userID, serverID,
		body.CPUThreshold, body.CPUDuration, body.MemoryThreshold, body.MemoryDuration, body.DiskThreshold,
		body.AlertCPU, body.AlertMemory, body.AlertDisk, body.AlertOffline, body.AlertBackupFailure,
		body.AlertSSLExpiry, body.AlertServiceHealth, body.SSLWarningDays, body.NotifyEmail,
		encSlackURL, encDiscordURL, body.CooldownMinutes, encPagerdutyKey, encWebhookURL,
		body.MutedTypes, body.GPUUtilThreshold, body.GPUUtilDuration, body.GPUTempThreshold,
		body.GPUVramThreshold, body.AlertGPU,
	); err != nil {
		return internalError("update server rules", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtAlertsAttachPolicy (Phase 4 W3): policy_id = null clears the attachment
// (rule reverts to the pre-W3 hardcoded cadence).
type rtAlertsAttachPolicy struct {
	PolicyID *uuid.UUID `json:"policy_id"`
}

// rtAlertsAttachEscalationPolicy is PUT /api/alert-rules/{rule_id}/escalation-policy
// — admin: attach or detach an escalation policy on a single rule.
// Admin-only because mis-attaching a policy can route 3 AM pages to the wrong
// on-call user.
//
// ⚠ SECURITY (s437): rule_id came from the URL under plain AdminUser (role
// only) with NO ownership check at all — any admin on the install could
// re-point ANY other tenant's alert rule at ANY escalation policy (including
// one they don't own, since the old existence check was also unscoped). Same
// shape as updateServerRules/deleteServerRules (s433): a single resource
// resolved by a caller-supplied ID never widens for admin, admin included.
func rtAlertsAttachEscalationPolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	ruleID, err := pathUUID(r, "rule_id")
	if err != nil {
		return err
	}
	var body rtAlertsAttachPolicy
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	ownsRule, err := queryScalarOpt[uuid.UUID](ctx, st.DB,
		"SELECT id FROM alert_rules WHERE id = $1 AND user_id = $2", ruleID, claims.Sub)
	if err != nil {
		return internalError("check alert rule ownership", err)
	}
	if ownsRule == nil {
		return apiErr(http.StatusNotFound, "Alert rule not found")
	}

	// If setting (not clearing), verify the policy exists AND is owned by the
	// same tenant so the FK violation surfaces as a 400 instead of a 500, and
	// so a rule can never be pointed at another tenant's policy.
	if body.PolicyID != nil {
		exists, err := queryScalar[bool](ctx, st.DB,
			"SELECT EXISTS(SELECT 1 FROM escalation_policies WHERE id = $1 AND user_id = $2)",
			*body.PolicyID, claims.Sub)
		if err != nil {
			return internalError("check policy exists", err)
		}
		if !exists {
			return apiErr(http.StatusBadRequest, "Policy not found")
		}
	}
	n, err := execSQL(ctx, st.DB,
		"UPDATE alert_rules SET escalation_policy_id = $2, updated_at = NOW() "+
			"WHERE id = $1 AND user_id = $3",
		ruleID, body.PolicyID, claims.Sub)
	if err != nil {
		return internalError("attach policy", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Alert rule not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtAlertsDeleteServerRules is DELETE /api/alert-rules/{server_id} — remove a
// server-specific override.
//
// ⚠ SECURITY/HONESTY (s433): the DELETE itself was already scoped
// `WHERE user_id = $1 AND server_id = $2`, so a non-owner could never remove
// the real owner's row — but with no upfront ownership check on server_id, a
// request naming a server the caller doesn't own (or that doesn't exist)
// matched 0 rows and still answered {"ok": true}, same as a real deletion.
// Checked the same way updateServerRules does, so this route is honest about
// which requests actually did something.
func rtAlertsDeleteServerRules(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, err := pathUUID(r, "server_id")
	if err != nil {
		return err
	}
	owns, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB,
		"SELECT id FROM servers WHERE id = $1 AND user_id = $2", serverID, claims.Sub)
	if err != nil {
		return internalError("check server ownership", err)
	}
	if owns == nil {
		return apiErr(http.StatusNotFound, "Server not found")
	}

	if _, err := execSQL(r.Context(), st.DB,
		"DELETE FROM alert_rules WHERE user_id = $1 AND server_id = $2", claims.Sub, serverID); err != nil {
		return internalError("delete server rules", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// ---------------------------------------------------------------------------
// Runbooks (Phase 4 W2)
//
// Markdown-per-alert-type, attached to fired alerts and rendered into
// notification payloads. Admin-only. Resolution is DB-row-then-default —
// fresh installs still produce useful payloads from the defaults without the
// operator having to click "Seed missing default runbooks" first.
// ---------------------------------------------------------------------------

const rtAlertsRunbookMdMaxBytes = 50 * 1024

type rtAlertsRunbookUpsert struct {
	RunbookMd       string `json:"runbook_md"`
	SeverityDefault string `json:"severity_default"`
}

type rtAlertsApplyDefaultsResponse struct {
	Inserted []string `json:"inserted"`
	Skipped  []string `json:"skipped"`
}

// rtAlertsListRunbooksRoute is GET /api/alerts/runbooks — every known
// runbook: the union of DB rows and compile-time defaults; defaults with no DB
// row yet are flagged is_default = true.
func rtAlertsListRunbooksRoute(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, AlertRunbooksListRunbooks(r.Context(), st.DB))
	return nil
}

// rtAlertsGetRunbookRoute is GET /api/alerts/runbooks/{alert_type}.
func rtAlertsGetRunbookRoute(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	rb := AlertRunbooksGetRunbook(r.Context(), st.DB, r.PathValue("alert_type"))
	if rb == nil {
		return apiErr(http.StatusNotFound, "no runbook for alert_type")
	}
	writeJSON(w, http.StatusOK, rb)
	return nil
}

// rtAlertsPutRunbook is PUT /api/alerts/runbooks/{alert_type} — upsert. Sets
// updated_by from auth.
func rtAlertsPutRunbook(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	alertType := r.PathValue("alert_type")
	var body rtAlertsRunbookUpsert
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if len(body.RunbookMd) > rtAlertsRunbookMdMaxBytes {
		return apiErr(http.StatusRequestEntityTooLarge, "runbook_md exceeds 50KB")
	}
	switch body.SeverityDefault {
	case "info", "warning", "critical":
	default:
		return apiErr(http.StatusBadRequest, "severity_default must be info, warning, or critical")
	}
	if alertType == "" || len(alertType) > 64 {
		return apiErr(http.StatusBadRequest, "invalid alert_type")
	}

	if _, err := execSQL(r.Context(), st.DB,
		"INSERT INTO alert_runbooks (alert_type, runbook_md, severity_default, updated_by, updated_at) "+
			"VALUES ($1, $2, $3, $4, NOW()) "+
			"ON CONFLICT (alert_type) DO UPDATE SET "+
			"runbook_md = EXCLUDED.runbook_md, "+
			"severity_default = EXCLUDED.severity_default, "+
			"updated_by = EXCLUDED.updated_by, "+
			"updated_at = NOW()",
		alertType, body.RunbookMd, body.SeverityDefault, claims.Sub); err != nil {
		return internalError("upsert runbook", err)
	}

	rb := AlertRunbooksGetRunbook(r.Context(), st.DB, alertType)
	if rb == nil {
		return internalError("read-back runbook after upsert", errors.New("missing row"))
	}
	writeJSON(w, http.StatusOK, rb)
	return nil
}

// rtAlertsDeleteRunbook is DELETE /api/alerts/runbooks/{alert_type} — remove
// the DB row → the next read falls back to the default.
func rtAlertsDeleteRunbook(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	alertType := r.PathValue("alert_type")
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM alert_runbooks WHERE alert_type = $1", alertType)
	if err != nil {
		return internalError("delete runbook", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deleted":    n > 0,
		"alert_type": alertType,
	})
	return nil
}

// rtAlertsApplyDefaults is POST /api/alerts/runbooks/apply-defaults —
// insert-or-skip from the defaults. **Never overwrites operator edits**
// (ON CONFLICT DO NOTHING).
func rtAlertsApplyDefaults(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	resp := rtAlertsApplyDefaultsResponse{Inserted: []string{}, Skipped: []string{}}

	for _, d := range AlertRunbookDefaultsDefaults {
		n, err := execSQL(r.Context(), st.DB,
			"INSERT INTO alert_runbooks (alert_type, runbook_md, severity_default, updated_by, updated_at) "+
				"VALUES ($1, $2, $3, $4, NOW()) "+
				"ON CONFLICT (alert_type) DO NOTHING",
			d.AlertType, d.RunbookMd, d.Severity, claims.Sub)
		if err != nil {
			return internalError("apply runbook defaults", err)
		}
		if n == 1 {
			resp.Inserted = append(resp.Inserted, d.AlertType)
		} else {
			resp.Skipped = append(resp.Skipped, d.AlertType)
		}
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}
