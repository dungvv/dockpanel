package api

// Port of panel/backend/src/routes/settings.rs.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type rtSettingsSettingRow struct {
	Key   string `db:"key"`
	Value string `db:"value"`
}

// rtSettingsAllowedKeys is the single writable-settings whitelist, shared by
// update and import. It used to be spelled out separately in each, and the
// two had drifted: import's copy was missing the registration gates and every
// security_* toggle, so an export→import silently dropped your security
// posture while claiming to use "the same whitelist as update()".
//
// A key belongs here when an operator is meant to change it. Every entry must
// also have a control in the panel (tests/settings-controls-pin-e2e.sh §9) and
// be read by something (§1).
var rtSettingsAllowedKeys = []string{
	"panel_name", "smtp_host", "smtp_port", "smtp_username", "smtp_password",
	"smtp_from", "smtp_from_name", "smtp_encryption",
	"agent_auto_update_enabled",
	"pdns_api_url", "pdns_api_key",
	"auto_heal_enabled", "auto_heal_docker_reclaim", "status_page_enabled", "enforce_2fa",
	"logo_url", "accent_color",
	"oauth_google_client_id", "oauth_google_client_secret",
	"oauth_github_client_id", "oauth_github_client_secret",
	"oauth_gitlab_client_id", "oauth_gitlab_client_secret",
	"oauth_auto_create", "hide_branding",
	"reverse_proxy",
	// Gap #70: Customizable notification templates
	"notif_template_email", "notif_template_slack",
	"notif_template_discord", "notif_template_webhook",
	// Telemetry
	"telemetry_enabled", "telemetry_endpoint",
	// Registration + approval gates (read by rt_auth)
	"self_registration_enabled", "security_approval_required",
	// Security toggles (read by svc_security_hardening)
	"security_geo_alert_enabled", "security_session_recording",
	"security_db_backup_enabled", "security_canary_enabled",
	"security_lockdown_threshold", "security_lockdown_window_minutes",
	"security_site_rate_limit",
	// Access gates that were readable-but-unsettable until v2.46.0: the login
	// IP allowlist and the server-terminal kill switch.
	"allowed_panel_ips", "server_terminal_disabled",
	// The panel's own public URL, read by notifications to build the "Open
	// runbook" link every alert carries. It was read from this table but
	// absent from this list and the settings page, so every alert shipped
	// without its runbook link on every install that did not set an env var
	// no UI mentions.
	"base_url",
	// Data-retention windows (read by auto_healer's retention cleanup via
	// key LIKE retention_%). The reader existed since GAP 67 but no key was
	// ever settable, so every install was stuck at the hardcoded defaults.
	"retention_activity_days", "retention_system_log_days", "retention_alert_days",
	"retention_scan_days", "retention_webhook_days", "retention_notification_days",
	"retention_monitor_days",
	// AI-assisted build/deploy failure diagnosis (BYO API key, default off).
	"ai_diagnosis_enabled", "ai_diagnosis_provider", "ai_diagnosis_model", "ai_diagnosis_api_key",
	// MCP server. Nothing reads these yet — the MCP server's real on/off
	// state is its systemd unit and bind address in /etc/dockpanel/mcp.env.
	// These are a record an operator fills in so Settings can show accurate
	// status instead of nothing — not a live switch.
	"mcp_server_enabled", "mcp_bind_mode",
}

// rtSettingsSensitiveKeys are masked in the GET response and encrypted at
// rest, alongside every key ending _client_secret. One list: the credential
// re-encryption sweep asserts its SQL predicate covers every key here.
var rtSettingsSensitiveKeys = []string{"smtp_password", "pdns_api_key", "ai_diagnosis_api_key"}

// rtSettingsIsSensitiveKey: SENSITIVE_KEYS plus every _client_secret key.
// list() used to hand-duplicate this as hardcoded comparisons, so a key added
// to the list alone encrypted on write but came back as raw ciphertext, not
// ********, on read.
func rtSettingsIsSensitiveKey(key string) bool {
	return slices.Contains(rtSettingsSensitiveKeys, key) || strings.HasSuffix(key, "_client_secret")
}

var rtSettingsRetentionKeys = []string{
	"retention_activity_days", "retention_system_log_days", "retention_alert_days",
	"retention_scan_days", "retention_webhook_days", "retention_notification_days",
	"retention_monitor_days",
}

func rtSettingsRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("GET /api/settings", h(rtSettingsList))
	r.Handle("PUT /api/settings", h(rtSettingsUpdate))
	r.Handle("GET /api/settings/export", h(rtSettingsExportConfig))
	r.Handle("POST /api/settings/import", h(rtSettingsImportConfig))
	r.Handle("GET /api/settings/recording-coverage", h(rtSettingsRecordingCoverage))
	r.Handle("POST /api/settings/smtp/test", h(rtSettingsTestEmail))
	r.Handle("POST /api/settings/test-webhook", h(rtSettingsTestWebhook))
	r.Handle("GET /api/settings/health", h(rtSettingsHealth))
	r.Handle("POST /api/settings/credentials/reencrypt", h(rtSettingsReencryptCredentials))
	r.Handle("GET /api/branding", h(rtSettingsBranding))
}

// rtSettingsList — GET /api/settings: all settings as a map (admin only).
func rtSettingsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	rows, err := queryAll[rtSettingsSettingRow](r.Context(), st.DB, "SELECT key, value FROM settings")
	if err != nil {
		return internalError("list settings", err)
	}
	m := make(map[string]string, len(rows))
	for _, row := range rows {
		if rtSettingsIsSensitiveKey(row.Key) && row.Value != "" {
			m[row.Key] = "********"
		} else {
			m[row.Key] = row.Value
		}
	}
	writeJSON(w, http.StatusOK, m)
	return nil
}

// rtSettingsUpdate — PUT /api/settings: upsert settings (admin only).
//
// No ServerScope. Every key here is panel-global, so X-Server-Id never had a
// bearing on what this writes. It did have two wrong effects: it chose which
// single host received the SMTP configuration (decrypted password included),
// and because ServerScope resolves the agent eagerly, saving ANY setting
// returned 502 whenever the member selected in the picker was down.
func rtSettingsUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var body map[string]string
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	for key := range body {
		if !slices.Contains(rtSettingsAllowedKeys, key) {
			return apiErr(http.StatusBadRequest, "Unknown setting: "+key)
		}
	}

	// Reject a malformed IP allowlist BEFORE storing it: every entry must be
	// one panelIPAllowed can match, or the operator locks themselves out and
	// the only way back is editing the settings table by hand.
	if list, ok := body["allowed_panel_ips"]; ok {
		for _, e := range strings.Split(list, ",") {
			e = strings.TrimSpace(e)
			if e != "" && !validPanelIPEntry(e) {
				return apiErr(http.StatusBadRequest, "Invalid IP or CIDR in allowed_panel_ips: "+e)
			}
		}
	}

	if u, ok := body["logo_url"]; ok {
		if u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "/") {
			return apiErr(http.StatusBadRequest, "logo_url must be an HTTP(S) URL or relative path")
		}
	}

	// Unlike logo_url a relative value is useless here: the reader builds a
	// link that leaves the panel (email, chat) where nothing supplies an
	// origin. Empty stays legal — the documented "no link" state.
	if u, ok := body["base_url"]; ok {
		t := strings.TrimSpace(u)
		if t != "" && !strings.HasPrefix(t, "https://") && !strings.HasPrefix(t, "http://") {
			return apiErr(http.StatusBadRequest, "base_url must be an absolute HTTP(S) URL, e.g. https://panel.example.com")
		}
	}

	// Each retention window must be a positive integer day-count; the reader
	// would silently fall back to its default on a bad value.
	for _, key := range rtSettingsRetentionKeys {
		if v, ok := body[key]; ok {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 1 || n > 3650 {
				return apiErr(http.StatusBadRequest, key+" must be an integer between 1 and 3650")
			}
		}
	}

	if c, ok := body["accent_color"]; ok && c != "" {
		valid := strings.HasPrefix(c, "#") && len(c) <= 9 && rtSettingsAllHex(c[1:])
		valid = valid || strings.HasPrefix(c, "rgb") || strings.HasPrefix(c, "hsl")
		if !valid {
			return apiErr(http.StatusBadRequest, "accent_color must be a valid hex color (#rrggbb), rgb(), or hsl()")
		}
	}

	// Update all settings atomically in a transaction
	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return internalError("update settings", err)
	}
	defer tx.Rollback(ctx)
	for key, value := range body {
		// Don't overwrite real secrets with the mask placeholder
		if rtSettingsIsSensitiveKey(key) && value == "********" {
			continue
		}
		store := value
		if rtSettingsIsSensitiveKey(key) && value != "" {
			enc, err := SecretsCryptoEncryptCredential(value, st.Config.JWTSecret)
			if err != nil {
				return apiErr(http.StatusInternalServerError, "Encryption failed: "+err.Error())
			}
			store = enc
		}
		if _, err := execSQL(ctx, tx,
			"INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) "+
				"ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()", key, store); err != nil {
			return internalError("update settings", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return internalError("update settings", err)
	}

	slog.Info(fmt.Sprintf("Settings updated by %s: %d keys", claims.Email, len(body)))
	resp := map[string]any{"ok": true}

	// If SMTP keys were updated, push config to every host that sends mail
	smtpKeys := []string{"smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_from", "smtp_from_name", "smtp_encryption"}
	touched := false
	for k := range body {
		if slices.Contains(smtpKeys, k) {
			touched = true
		}
	}
	if touched {
		rows, err := queryAll[rtSettingsSettingRow](ctx, st.DB, "SELECT key, value FROM settings WHERE key LIKE 'smtp_%'")
		if err != nil {
			return internalError("update settings", err)
		}
		m := map[string]string{}
		for _, row := range rows {
			m[row.Key] = row.Value
		}
		if host := m["smtp_host"]; host != "" {
			portStr, ok := m["smtp_port"]
			if !ok {
				portStr = "587"
			}
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				port = 587
			}
			or := func(k, def string) string {
				if v, ok := m[k]; ok {
					return v
				}
				return def
			}
			// Decrypt smtp_password before sending to agent
			pw := SecretsCryptoDecryptCredentialOrLegacy(m["smtp_password"], st.Config.JWTSecret)
			agentBody := map[string]any{
				"host": host, "port": port, "username": m["smtp_username"], "password": pw,
				"from": m["smtp_from"], "from_name": or("smtp_from_name", "DockPanel"),
				"encryption": or("smtp_encryption", "starttls"),
			}
			push := rtSettingsPushSMTPToFleet(ctx, st, agentBody)
			if wmsg := push.warning(); wmsg != nil {
				slog.Warn(*wmsg)
				resp["warning"] = *wmsg
			}
			resp["smtp"] = push.toJSON()
		}
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func rtSettingsAllHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// rtSettingsSMTPPush is where the SMTP configuration actually landed, host by
// host. Three lists rather than a ratio, because the three outcomes are three
// different problems and only a NAME is actionable.
type rtSettingsSMTPPush struct {
	// Hosts that took the configuration.
	configured []string
	// Hosts that were asked and refused, with the agent's reason.
	failed [][2]string
	// Hosts the registry would not resolve an agent for, with their status.
	notAsked [][2]string
}

func (p *rtSettingsSMTPPush) total() int { return len(p.configured) + len(p.failed) + len(p.notAsked) }

// warning is one sentence for the operator, or nil when every host took it.
// "Saved" on its own is the claim that has to stop being made: the settings
// write always succeeds, and it was the only part the old response described.
func (p *rtSettingsSMTPPush) warning() *string {
	if len(p.failed) == 0 && len(p.notAsked) == 0 {
		return nil
	}
	listed := func(v [][2]string) string {
		parts := make([]string, len(v))
		for i, e := range v {
			parts[i] = fmt.Sprintf("%s (%s)", e[0], e[1])
		}
		return strings.Join(parts, ", ")
	}
	var parts []string
	if len(p.failed) > 0 {
		parts = append(parts, "rejected by "+listed(p.failed))
	}
	if len(p.notAsked) > 0 {
		parts = append(parts, "never reached "+listed(p.notAsked))
	}
	s := fmt.Sprintf("SMTP settings saved, but they reached only %d of %d servers — %s. "+
		"Mail sent from the others will keep using whatever they were last given; "+
		"save SMTP again once they are back online.", len(p.configured), p.total(), strings.Join(parts, "; "))
	return &s
}

func (p *rtSettingsSMTPPush) toJSON() map[string]any {
	failed := make([]any, 0, len(p.failed))
	for _, f := range p.failed {
		failed = append(failed, map[string]any{"server": f[0], "error": f[1]})
	}
	notAsked := make([]any, 0, len(p.notAsked))
	for _, n := range p.notAsked {
		notAsked = append(notAsked, map[string]any{"server": n[0], "status": n[1]})
	}
	configured := p.configured
	if configured == nil {
		configured = []string{}
	}
	return map[string]any{"configured": configured, "failed": failed, "not_asked": notAsked}
}

// rtSettingsPushSMTPToFleet pushes the SMTP configuration at every member.
//
// The setting is panel-global, so its destination is too. It used to post to
// the one agent ServerScope resolved from X-Server-Id: the DECRYPTED password
// landed on whichever box the picker showed, and every other member was never
// configured — mail from them failed for ever, reported by a log line.
//
// ⚠ This is the panel's ONLY caller of the agent's /smtp/configure. Nothing
// re-pushes on check-in or registration, so a member offline at save time
// stays unconfigured until SMTP is saved again — which is why a host that
// could not be asked comes back as a named result instead of being skipped.
func rtSettingsPushSMTPToFleet(ctx context.Context, st *AppState, agentBody map[string]any) *rtSettingsSMTPPush {
	fleet := st.Agents.OnlineFleet(ctx)
	push := &rtSettingsSMTPPush{}
	asked := make([]uuid.UUID, 0, len(fleet))
	for _, m := range fleet {
		asked = append(asked, m.ID)
		if _, err := m.Agent.Post(ctx, "/smtp/configure", agentBody); err != nil {
			slog.Warn(fmt.Sprintf("SMTP configure failed on %s (%s): %v", m.Name, m.ID, err))
			push.failed = append(push.failed, [2]string{m.Name, err.Error()})
		} else {
			push.configured = append(push.configured, m.Name)
		}
	}
	// OnlineFleet yields only servers that are online AND resolve to an agent.
	// An operator pressing Save is entitled to know a registered server was
	// left out, so the skipped ones are counted by difference — no second
	// predicate to drift from the first.
	rows, _ := queryAll[Tup2[string, string]](ctx, st.DB,
		"SELECT name, status FROM servers WHERE NOT (id = ANY($1)) ORDER BY name", asked)
	for _, row := range rows {
		push.notAsked = append(push.notAsked, [2]string{row.A, row.B})
	}
	return push
}

// rtSettingsTestEmail — POST /api/settings/smtp/test (admin only).
//
// Deliberately single-host, unlike the save: a test asks whether ONE host can
// send, and fanning it out would put N copies in the operator's inbox. It is
// only defensible while the answer says which host it came from, so the reply
// names it.
func rtSettingsTestEmail(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body map[string]string
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	to, ok := body["to"]
	if !ok {
		to = claims.Email
	}
	if to == "" || !strings.Contains(to, "@") {
		return apiErr(http.StatusBadRequest, "Valid email address required")
	}

	rows, err := queryAll[rtSettingsSettingRow](ctx, st.DB, "SELECT key, value FROM settings WHERE key LIKE 'smtp_%'")
	if err != nil {
		return internalError("test email", err)
	}
	m := map[string]string{}
	for _, row := range rows {
		m[row.Key] = row.Value
	}
	from := m["smtp_from"]
	fromName, ok := m["smtp_from_name"]
	if !ok {
		fromName = "DockPanel"
	}
	if from == "" {
		return apiErr(http.StatusBadRequest, "SMTP not configured — save SMTP settings first")
	}

	// Resolved before the send so the answer can be attributed; a missing
	// name is left off rather than guessed.
	serverName, err := queryScalarOpt[string](ctx, st.DB, "SELECT name FROM servers WHERE id = $1", serverID)
	if err != nil {
		serverName = nil
	}

	result, err := agent.Post(ctx, "/smtp/test", map[string]any{"to": to, "from": from, "from_name": fromName})
	if err != nil {
		return agentError("SMTP test email", err)
	}
	message, ok := jsonStr(jsonGet(result, "message"))
	if !ok {
		message = "Email sent"
	}
	if serverName != nil {
		message = fmt.Sprintf("%s (sent from %s)", message, *serverName)
	}

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "smtp.test", new("settings"), nil, &to, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": message, "server": serverName})
	return nil
}

// rtSettingsTestWebhook — POST /api/settings/test-webhook: test Slack/Discord.
func rtSettingsTestWebhook(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	var body map[string]string
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	u, ok := body["url"]
	if !ok {
		return apiErr(http.StatusBadRequest, "URL required")
	}
	service, ok := body["service"]
	if !ok {
		service = "webhook"
	}
	if u == "" || !strings.HasPrefix(u, "https://") {
		return apiErr(http.StatusBadRequest, "Invalid webhook URL")
	}

	// SSRF: the destination is user-supplied; block internal addresses. The
	// client is PINNED to the address this check approves — a shared client's
	// resolver would look the host up a second, independent time for the real
	// connection, reopening the validate/connect gap.
	host, port, err := urlAuthority(u)
	if err != nil {
		return apiErr(http.StatusBadRequest, "Invalid webhook URL: "+err.Error())
	}
	var payload map[string]any
	if service == "slack" {
		payload = map[string]any{"text": "DockPanel test notification — your Slack webhook is working!"}
	} else {
		payload = map[string]any{"content": "DockPanel test notification — your Discord webhook is working!"}
	}
	tr, err := pinnedTransport(r.Context(), host, port)
	if err != nil {
		return apiErr(http.StatusBadRequest, "Invalid webhook URL: "+err.Error())
	}
	client := &http.Client{
		Transport: tr, Timeout: 10 * time.Second,
		// Refuse redirects: a public destination that 3xx-redirects to an
		// internal address would otherwise bypass the SSRF check.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, u, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return apiErr(http.StatusBadGateway, "Webhook request failed: "+err.Error())
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return apiErr(http.StatusBadGateway, "Webhook returned "+rtSettingsStatusText(resp.StatusCode))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": service + " test sent"})
	return nil
}

// rtSettingsStatusText is reqwest's StatusCode Display: "404 Not Found".
func rtSettingsStatusText(code int) string {
	if t := http.StatusText(code); t != "" {
		return fmt.Sprintf("%d %s", code, t)
	}
	return strconv.Itoa(code)
}

// rtSettingsOAuthProviders lists providers with a non-empty client id.
func rtSettingsOAuthProviders(ctx context.Context, st *AppState) []string {
	rows, _ := queryAll[Tup2[string, string]](ctx, st.DB, "SELECT key, value FROM settings WHERE key LIKE 'oauth_%_client_id' AND value != ''")
	out := []string{}
	for _, row := range rows {
		if s, ok := strings.CutPrefix(row.A, "oauth_"); ok {
			if s, ok := strings.CutSuffix(s, "_client_id"); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// rtSettingsBranding — GET /api/branding: public branding (login page and
// authenticated users). Reseller branding if the caller belongs to one,
// otherwise global settings.
func rtSettingsBranding(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	rows, err := queryAll[Tup2[string, string]](ctx, st.DB,
		"SELECT key, value FROM settings WHERE key IN ('panel_name', 'logo_url', 'accent_color', 'hide_branding')")
	if err != nil {
		return internalError("branding", err)
	}
	m := map[string]string{}
	for _, row := range rows {
		m[row.A] = row.B
	}
	globalName, ok := m["panel_name"]
	if !ok {
		globalName = "DockPanel"
	}
	globalLogo, globalAccent := m["logo_url"], m["accent_color"]
	hide, ok := m["hide_branding"]
	globalHide := ok && hide == "true"

	// GAP 41: authenticated user belonging to a reseller with custom branding
	token, ok := bearerToken(r)
	if !ok {
		token, ok = cookieToken(r)
	}
	if ok {
		// Ignore errors — unauthenticated users just get global branding.
		if c, err := decodeJWT(token, st.Config.JWTSecret); err == nil {
			rb, err := queryOpt[Tup4[*string, *string, *string, bool]](ctx, st.DB,
				"SELECT rp.logo_url, rp.accent_color, rp.panel_name, rp.hide_branding "+
					"FROM reseller_profiles rp "+
					"JOIN users u ON u.reseller_id = rp.user_id "+
					"WHERE u.id = $1", c.Sub)
			if err == nil && rb != nil && (rb.A != nil || rb.B != nil || rb.C != nil || rb.D) {
				or := func(p *string, def string) string {
					if p != nil {
						return *p
					}
					return def
				}
				writeJSON(w, http.StatusOK, map[string]any{
					"panel_name": or(rb.C, globalName), "logo_url": or(rb.A, globalLogo),
					"accent_color": or(rb.B, globalAccent), "hide_branding": rb.D,
					"oauth_providers": rtSettingsOAuthProviders(ctx, st),
				})
				return nil
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"panel_name": globalName, "logo_url": globalLogo, "accent_color": globalAccent,
		"hide_branding": globalHide, "oauth_providers": rtSettingsOAuthProviders(ctx, st),
	})
	return nil
}

// rtSettingsExportConfig — GET /api/settings/export: settings, alert rules,
// monitors, backup schedules and policies as JSON (Gap #71).
func rtSettingsExportConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	rows, err := queryAll[rtSettingsSettingRow](ctx, st.DB, "SELECT key, value FROM settings")
	if err != nil {
		return internalError("export config", err)
	}
	m := map[string]string{}
	for _, row := range rows {
		if row.Key != "smtp_password" && row.Key != "pdns_api_key" && !strings.HasSuffix(row.Key, "_client_secret") {
			m[row.Key] = row.Value
		}
	}

	// Alert rules (user's own only, exclude webhook secrets)
	type alertRule struct {
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
		CooldownMinutes    int32      `json:"cooldown_minutes" db:"cooldown_minutes"`
		MutedTypes         string     `json:"muted_types" db:"muted_types"`
		GPUUtilThreshold   int32      `json:"gpu_util_threshold" db:"gpu_util_threshold"`
		GPUUtilDuration    int32      `json:"gpu_util_duration" db:"gpu_util_duration"`
		GPUTempThreshold   int32      `json:"gpu_temp_threshold" db:"gpu_temp_threshold"`
		GPUVramThreshold   int32      `json:"gpu_vram_threshold" db:"gpu_vram_threshold"`
		AlertGPU           bool       `json:"alert_gpu" db:"alert_gpu"`
	}
	alertRules, err := queryAll[alertRule](ctx, st.DB,
		"SELECT server_id, cpu_threshold, cpu_duration, memory_threshold, memory_duration, "+
			"disk_threshold, alert_cpu, alert_memory, alert_disk, alert_offline, "+
			"alert_backup_failure, alert_ssl_expiry, alert_service_health, "+
			"ssl_warning_days, notify_email, cooldown_minutes, muted_types, "+
			"gpu_util_threshold, gpu_util_duration, gpu_temp_threshold, gpu_vram_threshold, alert_gpu "+
			"FROM alert_rules WHERE user_id = $1 ORDER BY server_id NULLS FIRST", claims.Sub)
	if err != nil {
		alertRules = []alertRule{}
	}

	// Monitors (no secrets)
	type monitor struct {
		Name          string  `json:"name" db:"name"`
		URL           string  `json:"url" db:"url"`
		MonitorType   string  `json:"monitor_type" db:"monitor_type"`
		CheckInterval int32   `json:"check_interval" db:"check_interval"`
		Keyword       *string `json:"keyword" db:"keyword"`
	}
	monitors, err := queryAll[monitor](ctx, st.DB,
		"SELECT name, url, monitor_type, check_interval, keyword "+
			"FROM monitors WHERE user_id = $1 ORDER BY name", claims.Sub)
	if err != nil {
		monitors = []monitor{}
	}

	type schedule struct {
		SiteID         uuid.UUID `json:"site_id" db:"site_id"`
		Schedule       string    `json:"schedule" db:"schedule"`
		RetentionCount int32     `json:"retention_count" db:"retention_count"`
		Enabled        bool      `json:"enabled" db:"enabled"`
	}
	schedules, err := queryAll[schedule](ctx, st.DB, "SELECT site_id, schedule, retention_count, enabled FROM backup_schedules")
	if err != nil {
		schedules = []schedule{}
	}

	type policy struct {
		Name              string `json:"name" db:"name"`
		Schedule          string `json:"schedule" db:"schedule"`
		BackupSites       bool   `json:"backup_sites" db:"backup_sites"`
		BackupDatabases   bool   `json:"backup_databases" db:"backup_databases"`
		BackupVolumes     bool   `json:"backup_volumes" db:"backup_volumes"`
		RetentionCount    int32  `json:"retention_count" db:"retention_count"`
		Encrypt           bool   `json:"encrypt" db:"encrypt"`
		VerifyAfterBackup bool   `json:"verify_after_backup" db:"verify_after_backup"`
	}
	policies, err := queryAll[policy](ctx, st.DB,
		"SELECT name, schedule, backup_sites, backup_databases, backup_volumes, "+
			"retention_count, encrypt, verify_after_backup "+
			"FROM backup_policies WHERE user_id = $1 ORDER BY name", claims.Sub)
	if err != nil {
		policies = []policy{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"settings": m, "alert_rules": alertRules, "monitors": monitors,
		"backup_schedules": schedules, "backup_policies": policies,
		"exported_at": time.Now().UTC().Format("2006-01-02T15:04:05.999999999-07:00"),
	})
	return nil
}

// rtSettingsI64Or is `.and_then(as_i64).unwrap_or(def) as i32`.
func rtSettingsI64Or(v any, key string, def int64) int32 {
	if n, ok := jsonI64(jsonGet(v, key)); ok {
		return int32(n)
	}
	return int32(def)
}

func rtSettingsBoolOr(v any, key string, def bool) bool {
	if b, ok := jsonBool(jsonGet(v, key)); ok {
		return b
	}
	return def
}

func rtSettingsStrOr(v any, key, def string) string {
	if s, ok := jsonStr(jsonGet(v, key)); ok {
		return s
	}
	return def
}

// rtSettingsImportConfig — POST /api/settings/import.
func rtSettingsImportConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	// serde_json::Value: numbers kept exact so as_i64 sees integers.
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var body any
	_ = dec.Decode(&body)
	ctx := r.Context()
	settingsObj, ok := jsonObj(jsonGet(body, "settings"))
	if !ok {
		return apiErr(http.StatusBadRequest, "Invalid format: missing 'settings' object")
	}

	// Filtered through the same whitelist as update() — literally the same
	// list now, not a second copy that drifts away from it.
	imported, skipped := 0, 0
	for key, value := range settingsObj {
		if !slices.Contains(rtSettingsAllowedKeys, key) {
			skipped++
			continue
		}
		val, ok := value.(string)
		if !ok {
			continue
		}
		store := val
		if rtSettingsIsSensitiveKey(key) && val != "" {
			if enc, err := SecretsCryptoEncryptCredential(val, st.Config.JWTSecret); err == nil {
				store = enc
			}
		}
		_, _ = execSQL(ctx, st.DB,
			"INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) "+
				"ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()", key, store)
		imported++
	}

	var alertRulesImported, mutedTypesDropped int64
	if rules, ok := jsonArr(jsonGet(body, "alert_rules")); ok {
		for _, rule := range rules {
			cpuT := rtSettingsI64Or(rule, "cpu_threshold", 90)
			cpuD := rtSettingsI64Or(rule, "cpu_duration", 5)
			memT := rtSettingsI64Or(rule, "memory_threshold", 90)
			memD := rtSettingsI64Or(rule, "memory_duration", 5)
			diskT := rtSettingsI64Or(rule, "disk_threshold", 90)
			aCPU := rtSettingsBoolOr(rule, "alert_cpu", true)
			aMem := rtSettingsBoolOr(rule, "alert_memory", true)
			aDisk := rtSettingsBoolOr(rule, "alert_disk", true)
			aOff := rtSettingsBoolOr(rule, "alert_offline", true)
			// ⚠ `true`, matching the schema (NOT NULL DEFAULT TRUE). These
			// three defaulted FALSE, so a config written by an older version,
			// hand-edited, or produced elsewhere silently switched off backup,
			// SSL-expiry and service-health alerting on import — with no UI
			// widget to notice, and alert_ssl_expiry off also consumed the
			// expiry ladder's rungs, so the effect outlived the import.
			aBackup := rtSettingsBoolOr(rule, "alert_backup_failure", true)
			aSSL := rtSettingsBoolOr(rule, "alert_ssl_expiry", true)
			aHealth := rtSettingsBoolOr(rule, "alert_service_health", true)
			sslDays := rtSettingsStrOr(rule, "ssl_warning_days", "14")
			notifyEmail := rtSettingsBoolOr(rule, "notify_email", true)
			cooldown := rtSettingsI64Or(rule, "cooldown_minutes", 15)
			// A restored suppression list can name a type this version no
			// longer pages about. Kept verbatim it would suppress nothing while
			// reading back as though it worked, so drop the dead tokens and
			// count them — salvage the row rather than fail the whole restore.
			mutedRaw := rtSettingsStrOr(rule, "muted_types", "")
			dead := NotificationsUnknownSuppressibleTypes(mutedRaw)
			mutedTypesDropped += int64(len(dead))
			var keep []string
			for _, s := range strings.Split(mutedRaw, ",") {
				s = strings.TrimSpace(s)
				if s != "" && !slices.Contains(dead, s) {
					keep = append(keep, s)
				}
			}
			muted := strings.Join(keep, ",")

			var serverID *uuid.UUID
			if s, ok := jsonStr(jsonGet(rule, "server_id")); ok {
				if id, err := uuid.Parse(s); err == nil {
					serverID = &id
				}
			}
			var err error
			if serverID != nil {
				_, err = execSQL(ctx, st.DB,
					"INSERT INTO alert_rules (user_id, server_id, cpu_threshold, cpu_duration, "+
						"memory_threshold, memory_duration, disk_threshold, alert_cpu, alert_memory, "+
						"alert_disk, alert_offline, alert_backup_failure, alert_ssl_expiry, "+
						"alert_service_health, ssl_warning_days, notify_email, cooldown_minutes, muted_types) "+
						"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) "+
						"ON CONFLICT (user_id, server_id) DO UPDATE SET "+
						"cpu_threshold=$3, cpu_duration=$4, memory_threshold=$5, memory_duration=$6, "+
						"disk_threshold=$7, alert_cpu=$8, alert_memory=$9, alert_disk=$10, "+
						"alert_offline=$11, alert_backup_failure=$12, alert_ssl_expiry=$13, "+
						"alert_service_health=$14, ssl_warning_days=$15, notify_email=$16, "+
						"cooldown_minutes=$17, muted_types=$18",
					claims.Sub, *serverID, cpuT, cpuD, memT, memD, diskT, aCPU, aMem, aDisk, aOff,
					aBackup, aSSL, aHealth, sslDays, notifyEmail, cooldown, muted)
			} else {
				_, err = execSQL(ctx, st.DB,
					"INSERT INTO alert_rules (user_id, cpu_threshold, cpu_duration, "+
						"memory_threshold, memory_duration, disk_threshold, alert_cpu, alert_memory, "+
						"alert_disk, alert_offline, alert_backup_failure, alert_ssl_expiry, "+
						"alert_service_health, ssl_warning_days, notify_email, cooldown_minutes, muted_types) "+
						"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) "+
						"ON CONFLICT DO NOTHING",
					claims.Sub, cpuT, cpuD, memT, memD, diskT, aCPU, aMem, aDisk, aOff,
					aBackup, aSSL, aHealth, sslDays, notifyEmail, cooldown, muted)
			}
			if err == nil {
				alertRulesImported++
			}
		}
	}

	var monitorsImported int64
	if mons, ok := jsonArr(jsonGet(body, "monitors")); ok {
		for _, m := range mons {
			name := rtSettingsStrOr(m, "name", "")
			u := rtSettingsStrOr(m, "url", "")
			mtype := rtSettingsStrOr(m, "monitor_type", "http")
			interval := rtSettingsI64Or(m, "check_interval", 60)
			var keyword *string
			if s, ok := jsonStr(jsonGet(m, "keyword")); ok {
				keyword = &s
			}
			if name == "" || u == "" {
				continue
			}
			// SSRF: validate the URL for any type the uptime dispatcher will
			// HTTP-fetch (anything but tcp/ping/heartbeat), parity with the
			// create path the import loop otherwise bypasses. Skip an
			// offending row rather than failing the whole import.
			if mtype != "tcp" && mtype != "ping" && mtype != "heartbeat" && validateURLNotInternal(ctx, u) != nil {
				continue
			}
			if _, err := execSQL(ctx, st.DB,
				"INSERT INTO monitors (user_id, name, url, monitor_type, check_interval, keyword) "+
					"VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
				claims.Sub, name, u, mtype, interval, keyword); err == nil {
				monitorsImported++
			}
		}
	}

	var schedulesImported int64
	if scheds, ok := jsonArr(jsonGet(body, "backup_schedules")); ok {
		for _, s := range scheds {
			sid, ok := jsonStr(jsonGet(s, "site_id"))
			if !ok {
				continue
			}
			siteID, err := uuid.Parse(sid)
			if err != nil {
				continue
			}
			if _, err := execSQL(ctx, st.DB,
				"INSERT INTO backup_schedules (site_id, schedule, retention_count, enabled) "+
					"VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
				siteID, rtSettingsStrOr(s, "schedule", "0 2 * * *"), rtSettingsI64Or(s, "retention_count", 7),
				rtSettingsBoolOr(s, "enabled", true)); err == nil {
				schedulesImported++
			}
		}
	}

	var policiesImported int64
	if pols, ok := jsonArr(jsonGet(body, "backup_policies")); ok {
		for _, p := range pols {
			name := rtSettingsStrOr(p, "name", "")
			if name == "" {
				continue
			}
			if _, err := execSQL(ctx, st.DB,
				"INSERT INTO backup_policies (user_id, name, schedule, backup_sites, backup_databases, "+
					"backup_volumes, retention_count, encrypt, verify_after_backup) "+
					"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
				claims.Sub, name, rtSettingsStrOr(p, "schedule", "0 2 * * *"),
				rtSettingsBoolOr(p, "backup_sites", true), rtSettingsBoolOr(p, "backup_databases", true),
				rtSettingsBoolOr(p, "backup_volumes", false), rtSettingsI64Or(p, "retention_count", 7),
				rtSettingsBoolOr(p, "encrypt", false), rtSettingsBoolOr(p, "verify_after_backup", false)); err == nil {
				policiesImported++
			}
		}
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "settings.import", new("settings"), nil, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "settings.import", &claims.Email, ip, new("settings"), nil, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "imported": imported, "skipped": skipped,
		"alert_rules_imported": alertRulesImported, "muted_types_dropped": mutedTypesDropped,
		"monitors_imported": monitorsImported, "schedules_imported": schedulesImported,
		"policies_imported": policiesImported,
	})
	return nil
}

// rtSettingsRecordingGateMinAgent is the agent release in which the
// terminal-recording toggle began to be honoured. Before it, the agent opened
// a .cast for every session unconditionally.
const rtSettingsRecordingGateMinAgent = "2.46.0"

// rtSettingsRecordingCoverage — GET /api/settings/recording-coverage: which
// registered servers will actually obey the recording toggle.
//
// The toggle is one settings row, but each agent enforces it via a signed
// claim in the terminal ticket, and an agent older than 2.46.0 ignores that
// claim and keeps recording. Reporting "disabled" while a member still
// records is a control whose confirmation ends the investigation; this lets
// the UI name the uncovered servers instead.
func rtSettingsRecordingCoverage(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	rows, err := queryAll[Tup3[string, *string, bool]](ctx, st.DB, "SELECT name, agent_version, is_local FROM servers ORDER BY is_local DESC, name")
	if err != nil {
		return internalError("recording coverage", err)
	}

	// servers.agent_version is written by a REMOTE agent's check-in. The local
	// agent never checks in (unix socket), so its row is permanently NULL —
	// "unknown, assume lagging" would warn on every single-server install, and
	// an always-on warning is one operators learn to scroll past. So ask it:
	// /health is the only answer that describes what is actually running.
	var localVersion *string
	if v, err := agent.Get(ctx, "/health"); err == nil {
		if s, ok := jsonStr(jsonGet(v, "version")); ok {
			localVersion = &s
		}
	}

	minKey := PanelUpdateSemverKey(new(rtSettingsRecordingGateMinAgent))
	lagging := []any{}
	for _, row := range rows {
		v := row.B
		if row.C && localVersion != nil {
			v = localVersion
		}
		// A remote server that has never checked in still counts as lagging:
		// an unverified claim is exactly what this endpoint stops making.
		have := PanelUpdateSemverKey(v)
		if slices.Compare(have[:], minKey[:]) < 0 {
			shown := "unknown"
			if v != nil {
				shown = *v
			}
			lagging = append(lagging, map[string]any{"name": row.A, "agent_version": shown})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"min_agent_version": rtSettingsRecordingGateMinAgent, "lagging": lagging})
	return nil
}

// rtSettingsHealth — GET /api/settings/health (admin only).
func rtSettingsHealth(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	dbStatus := "ok"
	if _, err := st.DB.Exec(ctx, "SELECT 1"); err != nil {
		dbStatus = "error"
	}
	agentStatus := "ok"
	if _, err := agent.Get(ctx, "/health"); err != nil {
		agentStatus = "error"
	}
	writeJSON(w, http.StatusOK, map[string]any{"db": dbStatus, "agent": agentStatus, "uptime": rtSettingsUptime("/proc/uptime")})
	return nil
}

// rtSettingsUptime formats the system uptime from /proc/uptime.
func rtSettingsUptime(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	var secs float64
	if f := strings.Fields(string(b)); len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			secs = v
		}
	}
	days := uint64(secs / 86400)
	hours := uint64(rtSettingsFmod(secs, 86400) / 3600)
	minutes := uint64(rtSettingsFmod(secs, 3600) / 60)
	if days > 0 {
		return fmt.Sprintf("%d days, %dh %dm", days, hours, minutes)
	}
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

func rtSettingsFmod(a, b float64) float64 { return a - b*float64(int64(a/b)) }

// rtSettingsReencryptCredentials — POST /api/settings/credentials/reencrypt:
// rewrite every stored credential under the current primary key.
//
// The operator-facing half of the SECRETS_ENCRYPTION_KEY story: the decrypt
// chain tries every derivation a value could have been written under, so
// changing the variable is survivable — but until rows are rewritten the
// install leans on a fallback arm. Idempotent and safe to re-run; a row no
// candidate key can open is reported `unreadable` and **left exactly as it
// is** — overwriting the only copy of a ciphertext we cannot read would turn a
// recoverable state into a permanent one.
func rtSettingsReencryptCredentials(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	reports := CredentialReencryptAll(ctx, st.DB, st.Config.JWTSecret)
	var rewritten, unreadable, examined, raced int64
	for _, rep := range reports {
		rewritten += rep.Rewritten
		unreadable += rep.Unreadable
		examined += rep.Examined
		raced += rep.Raced
	}

	ip := clientIP(r)
	details := fmt.Sprintf("examined %d, rewritten %d, unreadable %d, raced %d", examined, rewritten, unreadable, raced)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "settings.credentials.reencrypt", new("settings"), nil, &details, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "settings.credentials.reencrypt", &claims.Email, ip, new("settings"), nil, &details, nil, "warning", claims.KeyID)

	if unreadable > 0 {
		slog.Error(fmt.Sprintf("credential re-encryption finished with %d unreadable value(s) — those rows "+
			"were left untouched. They were encrypted with a key this process cannot derive; "+
			"restoring the previous %s is the way back.", unreadable, SecretsCryptoEncryptionKeyEnv))
	}
	if raced > 0 {
		// Not an error: a normal write beat the sweep to a row and the CAS
		// guard correctly skipped it. Re-running re-keys it.
		slog.Warn(fmt.Sprintf("credential re-encryption skipped %d row(s) that changed concurrently — run it again to pick them up", raced))
	}

	if reports == nil {
		reports = []*CredentialReencryptSubjectReport{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"examined": examined, "rewritten": rewritten, "unreadable": unreadable, "raced": raced,
		"subjects": reports,
		// Which surfaces this sweep claims to cover, so "did it touch my X?"
		// is answered in the response rather than in someone's memory.
		"covered_modules": CredentialReencryptCoveredModuleNames(),
		"swept_subjects":  CredentialReencryptSweptSubjects(),
	})
	return nil
}
