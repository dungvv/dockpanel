package api

// Port of panel/backend/src/routes/terminal.rs — the terminal ticket mint and
// the shared-output pages. There is no WebSocket here: the browser dials the
// agent's /terminal/ws directly with the ticket minted below; the panel
// deliberately does not proxy it (see requireLocalAgentScope).

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtTerminalRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/terminal/token", h(rtTerminalWsToken))
	r.Handle("POST /api/terminal/share", h(rtTerminalShareOutput))
	r.Handle("GET /api/terminal/shares", h(rtTerminalListShares))
	r.Handle("DELETE /api/terminal/share/{id}", h(rtTerminalRevokeShare))
	// Public (no auth).
	r.Handle("GET /api/terminal/shared/{id}", h(rtTerminalViewShared))
}

type rtTerminalTerminalQuery struct {
	SiteID *string `json:"site_id"`
}

// rtTerminalServerShellScope marks a ticket as a server (root) shell. Not a
// valid domain — the `@` is rejected by the agent's own domain validation — so
// it cannot collide with a site's name.
const rtTerminalServerShellScope = "@server"

// rtTerminalLockdownTerminalState is the lockdown row's terminal switch, as
// (lockdown_active, terminals_disabled).
//
// BOTH columns, never one of them. activate_lockdown writes
// terminals_disabled = TRUE with active = TRUE, but deactivate_lockdown clears
// only `active` — nothing ever writes the terminal column back to FALSE, and
// the migration declares it DEFAULT TRUE while seeding active = FALSE. A gate
// keyed on terminals_disabled alone would refuse every shell on a fresh install
// and for ever after the first unlock — a kill switch with no off position.
// `active` makes the flag mean anything at a given moment; the flag says
// whether THIS lockdown reaches terminals. SecurityHardeningIsLockedDown reads
// `active` and stops, which is right for login/site creation and wrong here.
func rtTerminalLockdownTerminalState(ctx context.Context, db *pgxpool.Pool) (bool, bool) {
	row, err := queryOpt[Tup2[bool, *bool]](ctx, db, "SELECT active, terminals_disabled FROM lockdown_state WHERE id = 1")
	if err != nil || row == nil {
		// No singleton row (migration not run, or deleted): IsLockedDown
		// answers `false` there, and disagreeing would mean a panel
		// mid-migration has no terminals rather than no lockdown.
		return false, false
	}
	// A NULL under an ACTIVE lockdown is not evidence terminals were meant to
	// stay open, so it is not read as permission.
	disabled := true
	if row.B != nil {
		disabled = *row.B
	}
	return row.A, disabled
}

// rtTerminalTerminalsLockedDown: a lockdown is active AND it disabled
// terminals. It closes the doors that CREATE something (ticket mint, share
// writer) plus the unauthenticated viewer; revoke/list stay open — they are
// the remedy, and withdrawing them during a lockdown would remove it at the
// same moment as the risk.
func rtTerminalTerminalsLockedDown(ctx context.Context, db *pgxpool.Pool) bool {
	active, disabled := rtTerminalLockdownTerminalState(ctx, db)
	return active && disabled
}

// rtTerminalWsToken: GET /api/terminal/token — a 60-second ticket signed with
// the agent token (the raw agent token is never exposed).
func rtTerminalWsToken(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var q rtTerminalTerminalQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	ctx := r.Context()

	// The lockdown's terminal switch. This is THE door into a shell: the
	// browser dials the agent directly, so nothing downstream can refuse — a
	// ticket signed with the agent's token opens the shell. The panic button
	// revokes every session but lets an admin log back in (correct); what made
	// that dangerous was that logging back in also restored the ability to mint
	// a fresh root shell seconds after the button promised shells had stopped.
	// Above every other check, because the sweep it belongs to kills SITE shells
	// too — refusing one while minting the other would half-honour the flag in
	// the direction that helps an intruder.
	if rtTerminalTerminalsLockedDown(ctx, st.DB) {
		return apiErr(http.StatusServiceUnavailable,
			"System is in lockdown mode. Terminal access is disabled until an "+
				"administrator unlocks the panel (Security → Lockdown).")
	}

	// Answer here rather than minting a ticket the receiving agent must reject.
	if err := requireLocalAgentScope(ctx, st, serverID, "The web terminal"); err != nil {
		return err
	}

	// Server-level terminal requires admin. Load-bearing (v2.75.0: it once
	// guarded only the MINTING of a site-less ticket and a site owner could drop
	// the scope and reach a root shell). Name the thing that works instead of
	// reading like a dead end.
	if q.SiteID == nil && c.Role != "admin" {
		return apiErr(http.StatusForbidden,
			"The server shell is available to administrators only. "+
				"Choose one of your own sites in the selector to open a shell inside it.")
	}

	// Server terminal switched off via settings (e.g. demo mode).
	if q.SiteID == nil {
		disabled, err := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'server_terminal_disabled'")
		if err != nil {
			return internalError("ws token", err)
		}
		if disabled != nil && *disabled == "true" {
			// The page cannot read this setting itself, so this sentence is the
			// only thing that says the shell is off by choice, not broken.
			return apiErr(http.StatusForbidden,
				"The server shell is switched off for this panel "+
					"(Settings → Security → Server terminal). Per-site shells are unaffected.")
		}
	}

	var domain *string
	if q.SiteID != nil {
		siteID, err := uuid.Parse(*q.SiteID)
		if err != nil {
			return apiErr(http.StatusBadRequest, "Invalid site_id")
		}
		d, err := queryScalarOpt[string](ctx, st.DB, "SELECT s.domain FROM sites s WHERE "+SiteCallerPredicate, siteID, c.Sub)
		if err != nil {
			return internalError("ws token", err)
		}
		if d == nil {
			return apiErr(http.StatusForbidden, "Site not found or not owned by you")
		}
		domain = d
	}

	// `record` rides INSIDE the signed ticket because the browser dials the
	// agent directly — as a query param the user could suppress the recording
	// of their own session.
	record := SecurityHardeningGetSettingBool(ctx, st.DB, "security_session_recording", true)
	// `scope` is the authorisation decision, signed — the fix for a real
	// escalation: the agent once read the scope from a `?domain=` param the
	// browser controls, and an EMPTY domain spawns a root shell with no
	// privilege drop. domain is set only for an ownership-checked site shell
	// and nil only on the admin-gated server-shell branch.
	scope := rtTerminalServerShellScope
	if domain != nil {
		scope = *domain
	}
	ticket := jwt.MapClaims{
		"sub":     c.Email,
		"purpose": "terminal",
		"exp":     time.Now().Add(60 * time.Second).Unix(),
		"record":  record,
		"scope":   scope,
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, ticket).SignedString([]byte(agent.Token()))
	if err != nil {
		return internalError("ws token", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "domain": domain})
	return nil
}

// rtTerminalShareTTLSecs is a share's stated lifetime: one hour.
const rtTerminalShareTTLSecs int64 = 3600

// rtTerminalValidShareID: shareOutput mints exactly 12 hex characters. The
// revoke path always checked that; the public viewer never did.
func rtTerminalValidShareID(id string) bool {
	if len(id) != 12 {
		return false
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// rtTerminalShareLifetime splits a stored share into (created_at,
// seconds_left, owner_id, content); ok=false when expired or untimestamped.
//
// BOTH readers go through here. They used to disagree: the operator's list
// skipped anything past its hour while the public viewer clamped to zero and
// rendered the content anyway — root terminal output on an unauthenticated URL
// until a daily retention sweep. Expiry is decided by whoever answers.
//
// owner_id (the creating admin's sub) scopes list/revoke so one admin cannot
// enumerate another's root output. A pre-owner row has no second `|` and
// parses with owner "" — invisible to list/revoke until it expires (fail
// closed). The viewer never reads owner: link access is unauthenticated by
// design.
func rtTerminalShareLifetime(raw string, now int64) (int64, int64, string, string, bool) {
	var created int64
	rest := raw
	if ts, after, ok := strings.Cut(raw, "|"); ok {
		created, _ = strconv.ParseInt(ts, 10, 64)
		rest = after
	}
	owner, content := "", rest
	if o, after, ok := strings.Cut(rest, "|"); ok {
		owner, content = o, after
	}
	// A timestamp that will not parse cannot show life left, so gets none.
	if created <= 0 {
		return 0, 0, "", "", false
	}
	remaining := rtTerminalShareTTLSecs - (now - created)
	if remaining <= 0 {
		return 0, 0, "", "", false
	}
	return created, remaining, owner, content, true
}

// rtTerminalShareOutput: POST /api/terminal/share — save output for sharing
// (1 hour).
func rtTerminalShareOutput(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	// A share is an UNAUTHENTICATED public URL holding up to 500KB of root
	// output; the panic button deletes every existing one. Deleting handles
	// what exists; this handles what arrives next — only together do the two
	// halves close the door.
	if rtTerminalTerminalsLockedDown(r.Context(), st.DB) {
		return apiErr(http.StatusServiceUnavailable,
			"System is in lockdown mode. Terminal output cannot be shared while "+
				"the panel is locked down.")
	}
	content, _ := jsonStr(jsonGet(body, "content"))
	if content == "" || len(content) > 500_000 {
		return apiErr(http.StatusBadRequest, "Content required (max 500KB)")
	}
	shareID := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	// Timestamp + owner prefix: crash-resilient cleanup and per-admin scoping.
	value := strconv.FormatInt(time.Now().Unix(), 10) + "|" + c.Sub.String() + "|" + content
	_, _ = execSQL(r.Context(), st.DB,
		"INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
		"terminal_share_"+shareID, value)
	writeJSON(w, http.StatusOK, map[string]any{"share_id": shareID, "url": "/api/terminal/shared/" + shareID})
	return nil
}

// rtTerminalRevokeShare: DELETE /api/terminal/share/{id}.
func rtTerminalRevokeShare(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	if !rtTerminalValidShareID(id) {
		return apiErr(http.StatusBadRequest, "Invalid share ID")
	}
	// Scoped to the calling admin's own share. 0 rows covers "doesn't exist",
	// "expired" AND "another admin's" — never distinguishable (as in the viewer).
	n, err := execSQL(r.Context(), st.DB,
		"DELETE FROM settings WHERE key = $1 AND split_part(value, '|', 2) = $2",
		"terminal_share_"+id, c.Sub.String())
	if err != nil {
		return internalError("revoke share", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Share not found or already expired")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "share_id": id})
	return nil
}

// rtTerminalListShares: GET /api/terminal/shares — the caller's active shares.
func rtTerminalListShares(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	rows, err := queryAll[Tup2[string, string]](r.Context(), st.DB, "SELECT key, value FROM settings WHERE key LIKE 'terminal_share_%'")
	if err != nil {
		return internalError("list shares", err)
	}
	now := time.Now().Unix()
	me := c.Sub.String()
	shares := []map[string]any{}
	for _, kv := range rows {
		shareID := strings.TrimPrefix(kv.A, "terminal_share_")
		// Expired/unparsable: retention collects it; the viewer agrees.
		created, remaining, owner, _, ok := rtTerminalShareLifetime(kv.B, now)
		if !ok || owner != me {
			continue
		}
		shares = append(shares, map[string]any{
			"share_id":           shareID,
			"created_at":         created,
			"expires_in_seconds": remaining,
			"url":                "/api/terminal/shared/" + shareID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": shares})
	return nil
}

// rtTerminalViewShared: GET /api/terminal/shared/{id} — public, no auth.
func rtTerminalViewShared(st *AppState, w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	// No authentication, so the id is the only credential.
	if !rtTerminalValidShareID(id) {
		return apiErr(http.StatusNotFound, "Share expired or not found")
	}
	// A manual lockdown does not delete shares, and this route has no auth —
	// during a declared emergency an anonymous URL still serving root output is
	// exactly what the lockdown is about. Same status and sentence as an
	// unknown id, so the reply neither distinguishes ids nor announces the
	// emergency (the lockdown is panel-wide, so uniformity leaks nothing).
	if rtTerminalTerminalsLockedDown(r.Context(), st.DB) {
		return apiErr(http.StatusNotFound, "Share expired or not found")
	}
	raw, _ := queryScalarOpt[string](r.Context(), st.DB, "SELECT value FROM settings WHERE key = $1", "terminal_share_"+id)
	if raw == nil {
		return apiErr(http.StatusNotFound, "Share expired or not found")
	}
	// Expiry enforced HERE, on the way out — an expired row answers exactly
	// like one that never existed.
	_, remaining, _, content, ok := rtTerminalShareLifetime(*raw, time.Now().Unix())
	if !ok {
		return apiErr(http.StatusNotFound, "Share expired or not found")
	}
	escaped := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(content)
	html := strings.NewReplacer("{escaped}", escaped, "{remaining}", strconv.FormatInt(remaining, 10)).Replace(rtTerminalSharedHTML)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, html)
	return nil
}

// rtTerminalSharedHTML is the viewer page; {escaped} and {remaining} are
// substituted in one pass.
const rtTerminalSharedHTML = `
"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>DockPanel — Shared Terminal Output</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#0f0f17;color:#cdd6f4;font-family:'JetBrains Mono',monospace;min-height:100vh}
.container{max-width:1200px;margin:0 auto;padding:24px 20px}
.header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px;padding-bottom:16px;border-bottom:1px solid #313244}
.brand{display:flex;align-items:center;gap:12px}
.brand-name{font-size:14px;font-weight:500;color:#a6adc8;letter-spacing:0.1em;text-transform:uppercase}
.badge{display:inline-flex;align-items:center;gap:6px;background:rgba(243,139,168,0.1);border:1px solid rgba(243,139,168,0.13);color:#f38ba8;font-size:11px;font-weight:500;padding:4px 12px;border-radius:20px;text-transform:uppercase;letter-spacing:0.05em}
.badge::before{content:'';width:6px;height:6px;background:#f38ba8;border-radius:50%;animation:pulse-dot 2s ease-in-out infinite}
@keyframes pulse-dot{0%,100%{opacity:1}50%{opacity:0.4}}
.actions{display:flex;align-items:center;gap:8px}
.btn{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:6px;font-size:12px;font-family:inherit;cursor:pointer;border:1px solid #45475a;background:#1e1e2e;color:#cdd6f4;transition:all 0.15s}
.btn:hover{background:#313244;border-color:#585b70}
.expiry{font-size:12px;color:#6c7086;display:flex;align-items:center;gap:6px}
.expiry-time{color:#f9e2af;font-weight:500}
.terminal-wrap{background:#1e1e2e;border:1px solid #313244;border-radius:8px;overflow:hidden}
.terminal-bar{display:flex;align-items:center;gap:8px;padding:10px 16px;background:#181825;border-bottom:1px solid #313244}
.dots{display:flex;gap:6px}
.dot{width:10px;height:10px;border-radius:50%;background:#45475a}
.dot:nth-child(1){background:#f38ba8}
.dot:nth-child(2){background:#f9e2af}
.dot:nth-child(3){background:#a6e3a1}
.terminal-title{color:#6c7086;font-size:11px;flex:1;text-align:center}
pre{padding:16px 20px;margin:0;white-space:pre-wrap;word-wrap:break-word;font-size:13px;line-height:1.6;overflow-x:auto;max-height:80vh;overflow-y:auto}
pre::-webkit-scrollbar{width:6px;height:6px}
pre::-webkit-scrollbar-track{background:#1e1e2e}
pre::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
pre::-webkit-scrollbar-thumb:hover{background:#585b70}
.footer{margin-top:16px;text-align:center;color:#45475a;font-size:11px}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(100px);background:#a6e3a1;color:#1e1e2e;padding:8px 20px;border-radius:6px;font-size:12px;font-weight:500;opacity:0;transition:all 0.3s ease;pointer-events:none;z-index:100}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}
@media(max-width:600px){.container{padding:12px}.header{flex-direction:column;align-items:flex-start}pre{font-size:11px;padding:12px}}
</style></head><body>
<div class="container">
  <div class="header">
    <div class="brand">
      <span class="brand-name">DockPanel</span>
      <span class="badge">Read-Only Snapshot</span>
    </div>
    <div class="actions">
      <button class="btn" onclick="copyOutput()" id="copyBtn">Copy All</button>
      <div class="expiry">Expires in <span class="expiry-time" id="countdown">--:--</span></div>
    </div>
  </div>
  <div class="terminal-wrap">
    <div class="terminal-bar">
      <div class="dots"><span class="dot"></span><span class="dot"></span><span class="dot"></span></div>
      <span class="terminal-title">shared terminal output</span>
    </div>
    <pre id="output">{escaped}</pre>
  </div>
  <div class="footer">Shared via DockPanel &mdash; self-hosted server management</div>
</div>
<div class="toast" id="toast">Copied to clipboard</div>
<script>
function copyOutput(){
  var text=document.getElementById('output').textContent;
  if(navigator.clipboard){
    navigator.clipboard.writeText(text).then(function(){showToast('Copied to clipboard')}).catch(function(){fallbackCopy(text)});
  }else{fallbackCopy(text)}
}
function fallbackCopy(t){var a=document.createElement('textarea');a.value=t;a.style.position='fixed';a.style.opacity='0';document.body.appendChild(a);a.select();try{document.execCommand('copy');showToast('Copied to clipboard')}catch(e){showToast('Copy failed')}document.body.removeChild(a)}
function showToast(msg){var el=document.getElementById('toast');el.textContent=msg;el.classList.add('show');setTimeout(function(){el.classList.remove('show')},2000)}
(function(){
  var remaining={remaining};
  var el=document.getElementById('countdown');
  function update(){
    if(remaining<=0){el.textContent='Expired';el.style.color='#f38ba8';return}
    var m=Math.floor(remaining/60);var s=remaining%60;
    el.textContent=m+':'+(s<10?'0':'')+s;
    remaining--;
    setTimeout(update,1000);
  }
  update();
})();
</script>
</body></html>`
