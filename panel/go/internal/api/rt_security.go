package api

// Port of panel/backend/src/routes/security.rs.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

func rtSecurityRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("GET /api/security/overview", h(rtSecurityOverview))
	r.Handle("GET /api/security/firewall", h(rtSecurityFirewallStatus))
	r.Handle("POST /api/security/firewall/rules", h(rtSecurityAddFirewallRule))
	r.Handle("DELETE /api/security/firewall/rules/{number}", h(rtSecurityDeleteFirewallRule))
	r.Handle("GET /api/security/fail2ban", h(rtSecurityFail2banStatus))
	// SSH Hardening
	r.Handle("POST /api/security/ssh/disable-password", h(rtSecuritySSHAction("/security/ssh/disable-password", "security.ssh_disable_password", false)))
	r.Handle("POST /api/security/ssh/enable-password", h(rtSecuritySSHAction("/security/ssh/enable-password", "security.ssh_enable_password", false)))
	r.Handle("POST /api/security/ssh/disable-root", h(rtSecuritySSHAction("/security/ssh/disable-root", "security.ssh_disable_root", false)))
	r.Handle("POST /api/security/ssh/change-port", h(rtSecuritySSHAction("/security/ssh/change-port", "security.ssh_change_port", true)))
	// Fail2Ban Management
	r.Handle("POST /api/security/fail2ban/unban", h(rtSecurityFail2banPost("/security/fail2ban/unban")))
	r.Handle("POST /api/security/fail2ban/ban", h(rtSecurityFail2banPost("/security/fail2ban/ban")))
	r.Handle("GET /api/security/fail2ban/{jail}/banned", h(rtSecurityFail2banBanned))
	r.Handle("POST /api/security/fix", h(rtSecurityApplySecurityFix))
	r.Handle("GET /api/security/login-audit", h(rtSecurityLoginAudit))
	r.Handle("POST /api/security/panel-jail/setup", h(rtSecuritySetupPanelJail))
	r.Handle("GET /api/security/panel-jail/status", h(rtSecurityPanelJailStatus))
	r.Handle("GET /api/security/canary-status", h(rtSecurityCanaryStatus))
	r.Handle("POST /api/security/canary/arm", h(rtSecurityCanaryArm))
	r.Handle("GET /api/security/report", h(rtSecurityComplianceReport))
	// Security Hardening (post-incident features)
	r.Handle("GET /api/security/lockdown", h(rtSecurityLockdownStatus))
	r.Handle("POST /api/security/lockdown/activate", h(rtSecurityLockdownActivate))
	r.Handle("POST /api/security/lockdown/deactivate", h(rtSecurityLockdownDeactivate))
	r.Handle("POST /api/security/panic", h(rtSecurityPanicButton))
	r.Handle("POST /api/security/forensic-snapshot", h(rtSecurityForensicSnapshot))
	r.Handle("GET /api/security/audit-log", h(rtSecurityAuditLogList))
	r.Handle("GET /api/security/suspicious-events", h(rtSecuritySuspiciousEventsList))
	r.Handle("GET /api/security/recordings", h(rtSecurityRecordingsList))
	r.Handle("GET /api/security/pending-users", h(rtSecurityPendingUsers))
	r.Handle("POST /api/security/users/{id}/approve", h(rtSecurityApproveUser))
	r.Handle("GET /api/security/unverified-users", h(rtSecurityUnverifiedUsers))
	r.Handle("POST /api/security/users/{id}/verify-email", h(rtSecurityVerifyUserEmail))
}

// rtSecurityHTMLEscape escapes a value for interpolation into the compliance
// report's HTML. Findings come from filesystem paths under scanned websites —
// an attacker who compromises any hosted site can name a file so its path
// becomes a stored-XSS payload the admin's browser runs on the report.
var rtSecurityHTMLEscape = strings.NewReplacer(
	"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
).Replace

// rtSecurityAdminScope is the AdminUser + ServerScope extractor pair.
func rtSecurityAdminScope(st *AppState, r *http.Request) (*Claims, uuid.UUID, AgentHandle, error) {
	c, err := st.adminUser(r)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	id, agent, err := st.serverScope(r)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	return c, id, agent, nil
}

// rtSecurityProxyGet is the read-only agent passthrough shape.
func rtSecurityProxyGet(path, ctxMsg string) func(*AppState, http.ResponseWriter, *http.Request) error {
	return func(st *AppState, w http.ResponseWriter, r *http.Request) error {
		_, _, agent, err := rtSecurityAdminScope(st, r)
		if err != nil {
			return err
		}
		result, err := agent.Get(r.Context(), path)
		if err != nil {
			return agentError(ctxMsg, err)
		}
		writeJSON(w, http.StatusOK, result)
		return nil
	}
}

var (
	// GET /api/security/overview
	rtSecurityOverview = rtSecurityProxyGet("/security/overview", "Security overview")
	// GET /api/security/firewall
	rtSecurityFirewallStatus = rtSecurityProxyGet("/security/firewall", "Firewall status")
	// GET /api/security/fail2ban
	rtSecurityFail2banStatus = rtSecurityProxyGet("/security/fail2ban", "Fail2ban status")
	// GET /api/security/panel-jail/status
	rtSecurityPanelJailStatus = rtSecurityProxyGet("/security/panel-jail/status", "Panel jail")
)

// rtSecurityLogBoth writes the activity row and the immutable audit row the
// mutating handlers record.
func rtSecurityLogBoth(ctx context.Context, st *AppState, c *Claims, ip *string, action string, targetType, targetName, details *string, severity string) {
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, action, targetType, targetName, details, ip, c.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, action, new(c.Email), ip, targetType, targetName, details, nil, severity, c.KeyID)
}

type rtSecurityFirewallRuleRequest struct {
	Port   uint16  `json:"port"`
	Proto  *string `json:"proto"`
	Action *string `json:"action"`
	From   *string `json:"from"`
}

// rtSecurityAddFirewallRule is POST /api/security/firewall/rules.
func rtSecurityAddFirewallRule(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtSecurityAdminScope(st, r)
	if err != nil {
		return err
	}
	var body rtSecurityFirewallRuleRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if body.Port == 0 {
		return apiErr(http.StatusBadRequest, "Port must be between 1 and 65535")
	}
	proto := "tcp"
	if body.Proto != nil {
		proto = *body.Proto
	}
	if !slices.Contains([]string{"tcp", "udp", "tcp/udp"}, proto) {
		return apiErr(http.StatusBadRequest, "Protocol must be tcp, udp, or tcp/udp")
	}
	action := "allow"
	if body.Action != nil {
		action = *body.Action
	}
	if !slices.Contains([]string{"allow", "deny", "reject"}, action) {
		return apiErr(http.StatusBadRequest, "Action must be allow, deny, or reject")
	}
	result, err := agent.Post(r.Context(), "/security/firewall/rules", map[string]any{
		"port": body.Port, "proto": proto, "action": action, "from": body.From,
	})
	if err != nil {
		return agentError("Add firewall rule", err)
	}
	rule := fmt.Sprintf("%d/%s", body.Port, proto)
	rtSecurityLogBoth(r.Context(), st, claims, clientIP(r), "firewall.add", new("firewall"), new(rule), nil, "warning")
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtSecurityDeleteFirewallRule is DELETE /api/security/firewall/rules/{number}.
func rtSecurityDeleteFirewallRule(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	raw := r.PathValue("number")
	number, perr := strconv.ParseUint(raw, 10, 64)
	if perr != nil {
		return rejection(http.StatusBadRequest, fmt.Sprintf("Invalid URL: Cannot parse `%s` to a `usize`", raw))
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if _, err := agent.Delete(r.Context(), fmt.Sprintf("/security/firewall/rules/%d", number)); err != nil {
		return agentError("Delete firewall rule", err)
	}
	rtSecurityLogBoth(r.Context(), st, claims, clientIP(r), "firewall.delete",
		new("firewall"), new(fmt.Sprintf("rule #%d", number)), nil, "warning")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtSecuritySSHAction is the four POST /api/security/ssh/* handlers. Only
// change-port takes a body (Json<Value>, forwarded as-is).
func rtSecuritySSHAction(path, action string, withBody bool) func(*AppState, http.ResponseWriter, *http.Request) error {
	return func(st *AppState, w http.ResponseWriter, r *http.Request) error {
		claims, _, agent, err := rtSecurityAdminScope(st, r)
		if err != nil {
			return err
		}
		var body any
		if withBody {
			var raw json.RawMessage
			if err := decodeJSON(r, &raw); err != nil {
				return err
			}
			body = raw
		}
		if _, err := agent.Post(r.Context(), path, body); err != nil {
			return agentError("SSH config", err)
		}
		rtSecurityLogBoth(r.Context(), st, claims, clientIP(r), action, nil, nil, nil, "warning")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return nil
	}
}

// rtSecurityFail2banPost is POST /api/security/fail2ban/{unban,ban}.
func rtSecurityFail2banPost(path string) func(*AppState, http.ResponseWriter, *http.Request) error {
	return func(st *AppState, w http.ResponseWriter, r *http.Request) error {
		_, _, agent, err := rtSecurityAdminScope(st, r)
		if err != nil {
			return err
		}
		var body json.RawMessage
		if err := decodeJSON(r, &body); err != nil {
			return err
		}
		if _, err := agent.Post(r.Context(), path, body); err != nil {
			return agentError("Fail2Ban", err)
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return nil
	}
}

// rtSecurityFail2banBanned is GET /api/security/fail2ban/{jail}/banned.
func rtSecurityFail2banBanned(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	jail := r.PathValue("jail")
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	valid := jail != ""
	for _, c := range jail {
		if !(c < 0x80 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') || c == '-' || c == '_') {
			valid = false
		}
	}
	if !valid {
		return apiErr(http.StatusBadRequest, "Invalid jail name")
	}
	result, err := agent.Get(r.Context(), "/security/fail2ban/"+jail+"/banned")
	if err != nil {
		return agentError("Fail2Ban", err)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

type rtSecurityTarget struct {
	ID      uuid.UUID
	Name    string
	IsLocal bool
	Agent   AgentHandle
}

// rtSecurityFleetTargets is the subject list login_audit and panic_button
// settled on: OnlineFleet (what every fleet sweeper uses) plus the
// caller-selected server even when it is not online, because that host is the
// one these endpoints always answered for and must not silently stop
// answering for. Also returns the census of every non-pending server, so the
// members never dialled can be named rather than omitted.
func rtSecurityFleetTargets(ctx context.Context, st *AppState, serverID uuid.UUID, agent AgentHandle) ([]Tup4[uuid.UUID, string, string, bool], []rtSecurityTarget) {
	census, _ := queryAll[Tup4[uuid.UUID, string, string, bool]](ctx, st.DB,
		"SELECT id, name, status, is_local FROM servers WHERE status != 'pending' "+
			"ORDER BY is_local DESC, name ASC")
	var targets []rtSecurityTarget
	for _, m := range st.Agents.OnlineFleet(ctx) {
		targets = append(targets, rtSecurityTarget{m.ID, m.Name, m.IsLocal, m.Agent})
	}
	if !slices.ContainsFunc(targets, func(t rtSecurityTarget) bool { return t.ID == serverID }) {
		name, isLocal := "selected server", false
		for _, c := range census {
			if c.A == serverID {
				name, isLocal = c.B, c.D
				break
			}
		}
		targets = append(targets, rtSecurityTarget{serverID, name, isLocal, agent})
	}
	return census, targets
}

// rtSecurityFanOut runs f against every target concurrently (join_all).
func rtSecurityFanOut(targets []rtSecurityTarget, f func(t rtSecurityTarget) (any, error)) ([]any, []error) {
	res := make([]any, len(targets))
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Go(func() { res[i], errs[i] = f(t) })
	}
	wg.Wait()
	return res, errs
}

// rtSecurityLoginAudit is GET /api/security/login-audit — recent login
// attempts (panel + SSH).
func rtSecurityLoginAudit(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, serverID, agent, err := rtSecurityAdminScope(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()

	// Panel logins from activity_logs. user_email and ip_address are the only
	// way this table identifies anything: the login writers pass NULL
	// target_type/target_name, so the target_name this used to select as
	// "user" was NULL on every row ever written.
	panelLogins, perr := queryAll[Tup5[string, string, string, *string, time.Time]](ctx, st.DB,
		"SELECT action, COALESCE(details, ''), user_email, ip_address, created_at "+
			"FROM activity_logs "+
			"WHERE action IN ('auth.login', 'auth.login_failed', 'auth.2fa_verify') "+
			"ORDER BY created_at DESC LIMIT 50")

	// Distinguish "no panel logins" from "we could not read the table": an
	// empty login-attempt list is the single most calming thing this endpoint
	// can display. A flag rather than a hard failure, so a broken panel query
	// does not also cost the operator the SSH half.
	panelQueryFailed := perr != nil
	if perr != nil {
		slog.Warn(fmt.Sprintf("login audit: panel login query failed — showing SSH half only: %v", perr))
		panelLogins = nil
	}
	panel := make([]any, 0, len(panelLogins))
	for _, p := range panelLogins {
		panel = append(panel, map[string]any{
			"type":    "panel",
			"action":  p.A,
			"details": p.B,
			"user":    p.C,
			"ip":      p.D,
			// "unknown_user" is exactly the enumeration signature — surfaced
			// as its own flag so the UI need not parse a free-text field.
			"unknown_user": p.B == "unknown_user",
			"time":         p.E,
			"success":      !strings.Contains(p.A, "failed"),
		})
	}

	// SSH logins from EVERY member of the fleet, not whichever one the caller
	// has selected: the panel half is panel-wide, and a brute-force campaign
	// against a member's sshd was invisible unless the operator happened to
	// have that member picked. A member not asked is named, never omitted —
	// "could not ask" and "nothing to report" read identically on screen
	// while meaning opposite things.
	census, targets := rtSecurityFleetTargets(ctx, st, serverID, agent)

	// Concurrently, bounded at 15s each: AgentHandle.Get caps at 60s, which is
	// indefensible for a table that loads with a page — a single wedged
	// member would hold the whole view for a minute.
	results, errs := rtSecurityFanOut(targets, func(t rtSecurityTarget) (any, error) {
		c, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		v, err := t.Agent.Get(c, "/security/login-audit")
		if err != nil && errors.Is(c.Err(), context.DeadlineExceeded) {
			return nil, errors.New("agent did not answer within 15s")
		}
		return v, err
	})

	ssh := []any{}
	sshServers := make([]any, 0, max(len(census), len(targets)))
	unreachable := []any{}
	unreachableNames := []string{}
	reached := 0

	for i, t := range targets {
		if errs[i] != nil {
			why := errs[i].Error()
			slog.Warn(fmt.Sprintf("login audit: %s (%s) did not answer — its SSH logins are missing from this view: %s", t.Name, t.ID, why))
			sshServers = append(sshServers, map[string]any{
				"server_id": t.ID, "server_name": t.Name, "is_local": t.IsLocal,
				"reached": false, "entries": nil, "error": why,
			})
			unreachable = append(unreachable, map[string]any{"server_id": t.ID, "server_name": t.Name, "reason": why})
			unreachableNames = append(unreachableNames, t.Name)
			continue
		}
		entries, _ := jsonArr(jsonGet(results[i], "entries"))
		for _, entry := range entries {
			// Stamp the host onto every row: `time` is a syslog stamp with no
			// year, so the origin is the only thing that tells two
			// identical-looking failed logins apart.
			if obj, ok := jsonObj(entry); ok {
				obj["server_id"] = t.ID
				obj["server_name"] = t.Name
				obj["is_local"] = t.IsLocal
			}
			ssh = append(ssh, entry)
		}
		reached++
		sshServers = append(sshServers, map[string]any{
			"server_id": t.ID, "server_name": t.Name, "is_local": t.IsLocal,
			"reached": true, "entries": len(entries),
		})
	}

	// Members never dialled: from the reader's side the fact is identical —
	// that machine's auth.log was not read.
	for _, c := range census {
		if slices.ContainsFunc(targets, func(t rtSecurityTarget) bool { return t.ID == c.A }) {
			continue
		}
		why := "server is not online — not asked"
		if c.C == "online" {
			why = "no reachable agent configured for this server"
		}
		sshServers = append(sshServers, map[string]any{
			"server_id": c.A, "server_name": c.B, "is_local": c.D,
			"reached": false, "entries": nil, "error": why,
		})
		unreachable = append(unreachable, map[string]any{"server_id": c.A, "server_name": c.B, "reason": why})
		unreachableNames = append(unreachableNames, c.B)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		// Legacy pair — same names, same types; `ssh` now concatenates every
		// host that answered, each row carrying its origin.
		"panel": panel,
		"ssh":   ssh,
		// ssh_partial is the one field a client must not ignore: true whenever
		// at least one machine's auth.log went unread.
		"ssh_partial":             len(unreachable) > 0,
		"ssh_servers":             sshServers,
		"ssh_servers_total":       len(sshServers),
		"ssh_servers_reached":     reached,
		"ssh_servers_unreachable": len(unreachable),
		"ssh_unreachable_servers": unreachable,
		"ssh_unreachable_names":   unreachableNames,
		// The panel half can only fail outright; this says whether it did.
		"panel_query_failed": panelQueryFailed,
	})
	return nil
}

// rtSecuritySetupPanelJail is POST /api/security/panel-jail/setup.
func rtSecuritySetupPanelJail(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtSecurityAdminScope(st, r)
	if err != nil {
		return err
	}
	if _, err := agent.Post(r.Context(), "/security/panel-jail/setup", nil); err != nil {
		return agentError("Panel jail", err)
	}
	rtSecurityLogBoth(r.Context(), st, claims, clientIP(r), "security.panel_jail_setup", nil, nil, nil, "info")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtSecurityCanaryStatus is GET /api/security/canary-status — what the
// tripwire is actually watching.
//
// Deliberately does NOT take ServerScope: the canary check runs inside this
// process and stats THIS host's filesystem, so the only honest answer is
// about this host. Accepting X-Server-Id would report a fleet member as armed
// on the strength of the panel's own files.
func rtSecurityCanaryStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	enabled := SecurityHardeningGetSettingBool(r.Context(), st.DB, "security_canary_enabled", true)

	paths := []any{}
	watching, armable := 0, 0
	for _, path := range AutoHealerCanaryWatchPaths {
		state, _ := AutoHealerClassifyCanary(path)
		if state.Kind == AutoHealerCanaryWatching {
			watching++
		}
		// Only an ABSENT path the agent can actually write is offerable: a
		// masked path stays masked however many times it is planted.
		plantable := slices.Contains(AutoHealerCanaryPlantable[:], path)
		if plantable && state.Kind == AutoHealerCanaryAbsent {
			armable++
		}
		var detail *string
		switch state.Kind {
		case AutoHealerCanaryUnreadable:
			detail = new(state.Err)
		case AutoHealerCanaryMasked:
			detail = new("masked by ProtectHome= in this unit; planting it would not help")
		}
		paths = append(paths, map[string]any{
			"path": path, "state": state.AsStr(), "plantable": plantable, "detail": detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  enabled,
		"watching": watching,
		"total":    len(AutoHealerCanaryWatchPaths),
		"armable":  armable,
		"paths":    paths,
	})
	return nil
}

// rtSecurityCanaryArm is POST /api/security/canary/arm — plant the canary
// files the agent can write. Local-only for the same reason as canary
// status. Both halves of the agent's per-path answer are passed through: the
// version that swallowed refusals is what let the feature ship watching
// nothing.
func rtSecurityCanaryArm(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	result, err := st.Agents.Local().Post(ctx, "/security/canary/setup", nil)
	if err != nil {
		return agentError("Arm canary files", err)
	}
	armed, _ := jsonU64(jsonGet(result, "armed"))
	total, _ := jsonU64(jsonGet(result, "total"))

	// Drop the stored access-time baseline for every path just (re)written.
	// Planting moves atime, and the checker treats any increase as an
	// intrusion: arming a host with four existing canaries raised four
	// critical events — one short of the default auto-lockdown threshold.
	// Deleting the key puts the checker back on its first-run branch. It
	// cannot hide a real intrusion: only paths the agent just created clear.
	if created, ok := jsonArr(jsonGet(result, "created")); ok {
		for _, e := range created {
			path, ok := jsonStr(jsonGet(e, "path"))
			if !ok {
				continue
			}
			_, _ = execSQL(ctx, st.DB, "DELETE FROM settings WHERE key = $1",
				"canary_atime_"+strings.ReplaceAll(path, "/", "_"))
		}
	}

	details := fmt.Sprintf("Armed %d of %d canary files", armed, total)
	rtSecurityLogBoth(ctx, st, claims, clientIP(r), "security.canary_armed", new("canary"), nil, new(details), "warning")
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtSecurityApplySecurityFix is POST /api/security/fix.
func rtSecurityApplySecurityFix(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtSecurityAdminScope(st, r)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return err
	}
	result, err := agent.Post(r.Context(), "/security/fix", raw)
	if err != nil {
		return agentError("Security fix", err)
	}
	var body any
	_ = json.Unmarshal(raw, &body)
	fixType := securityScannerStrOr(jsonGet(body, "fix_type"), "unknown")
	target := securityScannerStrOr(jsonGet(body, "target"), "unknown")
	rtSecurityLogBoth(r.Context(), st, claims, clientIP(r), "security.fix."+fixType, new("security"), new(target), nil, "warning")
	writeJSON(w, http.StatusOK, result)
	return nil
}

const rtSecurityReportTemplate = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>DockPanel Security Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 40px 20px; background: #0a0a0a; color: #e5e5e5; }
h1 { color: #22c55e; font-size: 24px; }
h2 { color: #a3a3a3; font-size: 16px; text-transform: uppercase; letter-spacing: 2px; margin-top: 40px; border-bottom: 1px solid #333; padding-bottom: 8px; }
.score { font-size: 72px; font-weight: bold; color: {score_color}; }
.grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 20px 0; }
.card { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 16px; }
.card .label { font-size: 12px; color: #737373; text-transform: uppercase; letter-spacing: 1px; }
.card .value { font-size: 20px; font-weight: bold; margin-top: 4px; }
.pass { color: #22c55e; }
.fail { color: #ef4444; }
table { width: 100%; border-collapse: collapse; background: #1a1a1a; border: 1px solid #333; border-radius: 8px; overflow: hidden; }
th { text-align: left; padding: 8px; background: #111; color: #737373; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
.footer { margin-top: 40px; color: #525252; font-size: 12px; text-align: center; }
</style></head><body>
<h1>DockPanel Security Report</h1>
<p style="color:#737373;">Generated: {scan_date}</p>

<h2>Security Score</h2>
<p class="score">{score}/100</p>

<h2>Infrastructure Status</h2>
<div class="grid">
<div class="card"><div class="label">Firewall (UFW)</div><div class="value {fw_class}">{fw_label}</div></div>
<div class="card"><div class="label">Fail2Ban</div><div class="value {f2b_class}">{f2b_label}</div></div>
<div class="card"><div class="label">SSH Password Auth</div><div class="value {ssh_pw_class}">{ssh_pw_label}</div></div>
<div class="card"><div class="label">SSH Root Login</div><div class="value {ssh_root_class}">{ssh_root_label}</div></div>
<div class="card"><div class="label">SSH Port</div><div class="value">{ssh_port}</div></div>
<div class="card"><div class="label">SSL Certificates</div><div class="value">{ssl_count}</div></div>
</div>

<h2>Scan Summary</h2>
<div class="grid">
<div class="card"><div class="label">Total Findings</div><div class="value">{total}</div></div>
<div class="card"><div class="label">Critical</div><div class="value fail">{critical}</div></div>
<div class="card"><div class="label">Warning</div><div class="value" style="color:#f59e0b;">{warning}</div></div>
</div>

<h2>Findings Detail</h2>
<table>
<thead><tr><th>Severity</th><th>Finding</th><th>Description</th><th>Remediation</th></tr></thead>
<tbody>{findings_html}</tbody>
</table>
{no_findings}

<div class="footer">
<p>Generated by DockPanel Security Scanner</p>
</div>
</body></html>`

// rtSecurityComplianceReport is GET /api/security/report — security
// compliance report (HTML).
func rtSecurityComplianceReport(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, serverID, agent, err := rtSecurityAdminScope(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()

	// The latest scan OF THIS SERVER. It used to pair this agent's live
	// overview with whichever server's scan finished most recently — a
	// compliance document built to be filed and forwarded, describing two
	// machines as one.
	type scanRow struct {
		ID            uuid.UUID  `db:"id"`
		Status        string     `db:"status"`
		FindingsCount int32      `db:"findings_count"`
		CriticalCount int32      `db:"critical_count"`
		WarningCount  int32      `db:"warning_count"`
		InfoCount     int32      `db:"info_count"`
		CompletedAt   *time.Time `db:"completed_at"`
	}
	scan, err := queryOpt[scanRow](ctx, st.DB,
		"SELECT id, status, findings_count, critical_count, warning_count, info_count, completed_at "+
			"FROM security_scans WHERE server_id = $1 AND status = 'completed' "+
			"ORDER BY completed_at DESC LIMIT 1", serverID)
	if err != nil {
		return internalError("compliance report scan lookup", err)
	}

	overview, oerr := agent.Get(ctx, "/security/overview")
	if oerr != nil {
		overview = nil
	}

	// description is read as a plain string, as the Rust tuple did: a NULL
	// fails the query and the report shows no findings.
	var findings []Tup5[string, string, string, *string, *string]
	if scan != nil {
		findings, _ = queryAll[Tup5[string, string, string, *string, *string]](ctx, st.DB,
			"SELECT severity, title, description, file_path, remediation FROM security_findings "+
				"WHERE scan_id = $1 ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END", scan.ID)
	}

	score := int32(-1)
	scanDate := "No scan available"
	var total, critical, warning int32
	if scan != nil {
		score = max(100-scan.CriticalCount*20-scan.WarningCount*5, 0)
		if scan.CompletedAt != nil {
			scanDate = scan.CompletedAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		total, critical, warning = scan.FindingsCount, scan.CriticalCount, scan.WarningCount
	}

	boolOr := func(k string, def bool) bool {
		if b, ok := jsonBool(jsonGet(overview, k)); ok {
			return b
		}
		return def
	}
	u64Or := func(k string, def uint64) uint64 {
		if n, ok := jsonU64(jsonGet(overview, k)); ok {
			return n
		}
		return def
	}
	fwActive := boolOr("firewall_active", false)
	f2bRunning := boolOr("fail2ban_running", false)
	sshPw := boolOr("ssh_password_auth", true)
	sshRoot := boolOr("ssh_root_login", true)
	sshPort := u64Or("ssh_port", 22)
	sslCount := u64Or("ssl_certs_count", 0)

	var fh strings.Builder
	for _, f := range findings {
		color := "#3b82f6"
		switch f.A {
		case "critical":
			color = "#ef4444"
		case "warning":
			color = "#f59e0b"
		}
		remediation := ""
		if f.E != nil {
			remediation = rtSecurityHTMLEscape(*f.E)
		}
		fmt.Fprintf(&fh, "<tr><td style=\"padding:8px;border-bottom:1px solid #333;\"><span style=\"color:%s;font-weight:bold;\">%s</span></td>"+
			"<td style=\"padding:8px;border-bottom:1px solid #333;\">%s</td>"+
			"<td style=\"padding:8px;border-bottom:1px solid #333;\">%s</td>"+
			"<td style=\"padding:8px;border-bottom:1px solid #333;\">%s</td></tr>",
			color, rtSecurityHTMLEscape(f.A), rtSecurityHTMLEscape(f.B), rtSecurityHTMLEscape(f.C), remediation)
	}

	scoreColor := "#ef4444"
	if score >= 80 {
		scoreColor = "#22c55e"
	} else if score >= 50 {
		scoreColor = "#f59e0b"
	}
	noFindings := ""
	if len(findings) == 0 {
		noFindings = "<p style=\"color:#525252;\">No findings — run a security scan first.</p>"
	}
	pick := func(good bool, a, b string) string {
		if good {
			return a
		}
		return b
	}

	html := strings.NewReplacer(
		"{score_color}", scoreColor,
		"{scan_date}", scanDate,
		"{score}", strconv.Itoa(int(score)),
		"{fw_class}", pick(fwActive, "pass", "fail"),
		"{fw_label}", pick(fwActive, "Active", "Inactive"),
		"{f2b_class}", pick(f2bRunning, "pass", "fail"),
		"{f2b_label}", pick(f2bRunning, "Running", "Stopped"),
		"{ssh_pw_class}", pick(!sshPw, "pass", "fail"),
		"{ssh_pw_label}", pick(!sshPw, "Disabled", "Enabled"),
		"{ssh_root_class}", pick(!sshRoot, "pass", "fail"),
		"{ssh_root_label}", pick(!sshRoot, "Disabled", "Enabled"),
		"{ssh_port}", strconv.FormatUint(sshPort, 10),
		"{ssl_count}", strconv.FormatUint(sslCount, 10),
		"{total}", strconv.Itoa(int(total)),
		"{critical}", strconv.Itoa(int(critical)),
		"{warning}", strconv.Itoa(int(warning)),
		"{findings_html}", fh.String(),
		"{no_findings}", noFindings,
	).Replace(rtSecurityReportTemplate)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
	return nil
}

// ── Security Hardening Endpoints (Features 9, 10, 11, 8) ──

// rtSecurityLockdownStatus is GET /api/security/lockdown.
func rtSecurityLockdownStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	lockdown := SecurityHardeningGetLockdownState(r.Context(), st.DB)

	// get_lockdown_state says whether a lockdown is on and why — none of what
	// it DOES. Two fields, because they answer two different questions:
	// terminals_disabled is the stored value (TRUE on a never-locked panel —
	// the migration DEFAULT — and still TRUE after an unlock), so on its own it
	// is not "can anyone open a shell right now". terminals_blocked is, and it
	// is computed by the same function the terminal ticket mint calls, so the
	// page and the gate cannot drift apart.
	if lockdown != nil {
		active, terminalsDisabled := rtTerminalLockdownTerminalState(r.Context(), st.DB)
		lockdown["terminals_disabled"] = terminalsDisabled
		lockdown["terminals_blocked"] = active && terminalsDisabled
	}
	writeJSON(w, http.StatusOK, lockdown)
	return nil
}

// rtSecurityLockdownActivate is POST /api/security/lockdown/activate.
func rtSecurityLockdownActivate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	reason := securityScannerStrOr(jsonGet(body, "reason"), "Manual admin lockdown")
	ctx := r.Context()
	SecurityHardeningActivateLockdown(ctx, st.DB, "admin", reason)
	SecurityHardeningAuditLog(ctx, st.DB, "lockdown.manual", new(claims.Email), nil,
		new("system"), nil, new(reason), nil, "critical", claims.KeyID)
	SecurityHardeningAlertLockdown(ctx, st.DB, reason, "admin:"+claims.Email)
	writeJSON(w, http.StatusOK, map[string]any{"status": "locked", "reason": reason})
	return nil
}

// rtSecurityLockdownDeactivate is POST /api/security/lockdown/deactivate.
func rtSecurityLockdownDeactivate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	SecurityHardeningDeactivateLockdown(r.Context(), st.DB, claims.Email)
	SecurityHardeningAuditLog(r.Context(), st.DB, "lockdown.deactivate", new(claims.Email), nil,
		new("system"), nil, nil, nil, "info", claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "unlocked"})
	return nil
}

// rtSecurityPanicButton is POST /api/security/panic — the emergency panic
// button (Feature 11). Kills all terminal sessions, blocks non-admins,
// disables registration.
func rtSecurityPanicButton(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, err := rtSecurityAdminScope(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	const reason = "PANIC BUTTON pressed by admin"

	SecurityHardeningActivateLockdown(ctx, st.DB, "panic", reason)

	// Kill terminal sessions on EVERY member of the fleet, not just the one
	// selected in the picker. Every other leg here is panel-global; the kill
	// was the one leg scoped to a single host, so on a fleet the panic button
	// reported success while live root shells kept running elsewhere.
	//
	// "Unreachable" means exactly one thing: NOBODY KILLED ANYTHING ON THAT
	// MACHINE. Offline members and members whose agent will not resolve are
	// deliberately not dialled (a dead host costs a full timeout on the button
	// pressed in a hurry) but they are named, and one of them is enough to
	// make the legacy agent_reached false for the whole call.
	census, targets := rtSecurityFleetTargets(ctx, st, serverID, agent)

	// Concurrently, 15s each: far more than a SIGKILL sweep needs, far less
	// than the client's 120s default. An unconfirmed host reported NOW beats a
	// confirmation two minutes from now.
	results, errs := rtSecurityFanOut(targets, func(t rtSecurityTarget) (any, error) {
		return t.Agent.PostLong(ctx, "/security/kill-terminals", map[string]any{}, 15)
	})

	var terminalsTotal, rootTotal uint64
	reached := 0
	serverResults := make([]any, 0, max(len(census), len(targets)))
	unreachable := []any{}
	unreachableNames := []string{}
	u64p := func(v any) *uint64 {
		if n, ok := jsonU64(v); ok {
			return &n
		}
		return nil
	}

	for i, t := range targets {
		if errs[i] != nil {
			why := errs[i].Error()
			slog.Error(fmt.Sprintf("PANIC: %s (%s) did not kill terminals — root shells may still be live there: %s", t.Name, t.ID, why))
			serverResults = append(serverResults, map[string]any{
				"server_id": t.ID, "server_name": t.Name, "is_local": t.IsLocal,
				"reached": false, "terminals_killed": nil, "server_terminals_killed": nil, "error": why,
			})
			unreachable = append(unreachable, map[string]any{"server_id": t.ID, "server_name": t.Name, "reason": why})
			unreachableNames = append(unreachableNames, t.Name)
			continue
		}
		v := results[i]
		killed := u64p(jsonGet(v, "killed"))
		root := u64p(jsonGet(v, "server_terminals_killed"))
		if killed != nil {
			terminalsTotal += *killed
		}
		if root != nil {
			rootTotal += *root
		}
		reached++
		serverResults = append(serverResults, map[string]any{
			"server_id": t.ID, "server_name": t.Name, "is_local": t.IsLocal,
			"reached": true, "terminals_killed": killed, "server_terminals_killed": root,
			"registered": u64p(jsonGet(v, "registered")),
		})
	}

	// Members never dialled: from the operator's side identical — not swept.
	for _, c := range census {
		if slices.ContainsFunc(targets, func(t rtSecurityTarget) bool { return t.ID == c.A }) {
			continue
		}
		why := "server is not online — not dialled"
		if c.C == "online" {
			why = "no reachable agent configured for this server"
		}
		slog.Error(fmt.Sprintf("PANIC: %s (%s) not swept (%s) — root shells may still be live there", c.B, c.A, why))
		serverResults = append(serverResults, map[string]any{
			"server_id": c.A, "server_name": c.B, "is_local": c.D,
			"reached": false, "terminals_killed": nil, "server_terminals_killed": nil, "error": why,
		})
		unreachable = append(unreachable, map[string]any{"server_id": c.A, "server_name": c.B, "reason": why})
		unreachableNames = append(unreachableNames, c.B)
	}

	serversTotal := len(serverResults)
	// Legacy field, now fleet-wide: true only if NOTHING was left unswept.
	agentReached := len(unreachable) == 0 && reached > 0
	// Legacy fields, now fleet totals; still null when no host answered.
	var terminalsKilled, serverTerminalsKilled *uint64
	if reached > 0 {
		terminalsKilled, serverTerminalsKilled = new(terminalsTotal), new(rootTotal)
	}

	// Revoke every issued session. Lockdown is enforced at the doors and
	// nothing tests it against an already-minted token, so the stolen admin
	// session that got an intruder their shell would keep working. This logs
	// the pressing admin out too; during a panic that is the correct trade.
	_, rerr := execSQL(ctx, st.DB,
		"INSERT INTO settings (key, value, updated_at) VALUES ('sessions_revoked_at', $1, NOW()) "+
			"ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()", autoHealerRFC3339(time.Now()))
	revoked := rerr == nil
	if revoked {
		st.setSessionsRevokedAt(time.Now().Unix())
	}

	// Disable self-registration at DB level.
	_, _ = execSQL(ctx, st.DB, "INSERT INTO settings (key, value) VALUES ('self_registration_enabled', 'false') ON CONFLICT (key) DO UPDATE SET value = 'false'")

	// Revoke every terminal share. A share is an UNAUTHENTICATED public URL
	// holding up to 500KB of terminal output, and lockdown does not reach it —
	// without this the intruder's own share kept serving while the UI said
	// "all sessions revoked".
	sharesRevoked, _ := execSQL(ctx, st.DB, "DELETE FROM settings WHERE key LIKE 'terminal_share_%'")

	// Audit + alert both carry the un-swept host list: the response is the
	// most detailed account of this event and also the shortest-lived (the
	// revocation above logs the admin out), so these two are where "which
	// machines did we fail to cover" survives for the incident review.
	var outcome string
	if len(unreachableNames) == 0 {
		outcome = fmt.Sprintf("%s — all %d server(s) swept, %d terminal(s) killed (%d server/root)",
			reason, serversTotal, terminalsTotal, rootTotal)
	} else {
		outcome = fmt.Sprintf("%s — %d/%d server(s) swept, %d terminal(s) killed (%d server/root). NOT SWEPT, root shells may still be live: %s",
			reason, reached, serversTotal, terminalsTotal, rootTotal, strings.Join(unreachableNames, ", "))
	}
	SecurityHardeningAuditLog(ctx, st.DB, "panic", new(claims.Email), nil,
		new("system"), nil, new(outcome), nil, "critical", claims.KeyID)
	SecurityHardeningAlertLockdown(ctx, st.DB, outcome, "panic:"+claims.Email)

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "panic_activated",
		// Legacy trio — same names, same types, now fleet-wide in meaning.
		"agent_reached":           agentReached,
		"terminals_killed":        terminalsKilled,
		"server_terminals_killed": serverTerminalsKilled,
		// Fleet detail: each unreachable entry is a machine on which root
		// terminals may still be running.
		"servers_total":         serversTotal,
		"servers_reached":       reached,
		"servers_unreachable":   len(unreachable),
		"server_results":        serverResults,
		"unreachable_servers":   unreachable,
		"sessions_revoked":      revoked,
		"shares_revoked":        sharesRevoked,
		"registration_disabled": true,
		"lockdown_active":       true,
	})
	return nil
}

// rtSecurityForensicSnapshot is POST /api/security/forensic-snapshot
// (Feature 10).
func rtSecurityForensicSnapshot(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtSecurityAdminScope(st, r)
	if err != nil {
		return err
	}
	result, err := agent.Get(r.Context(), "/security/forensic-snapshot")
	if err != nil {
		return agentError("Forensic snapshot", err)
	}
	SecurityHardeningAuditLog(r.Context(), st.DB, "forensic.snapshot", new(claims.Email), nil,
		new("system"), nil, new("Forensic snapshot captured"), nil, "info", claims.KeyID)
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtSecurityQueryI64 is Query<HashMap<String,String>> + `.parse().ok()`: the
// last value for a key wins, and an unparseable value is absent.
func rtSecurityQueryI64(r *http.Request, key string) (int64, bool) {
	vals := r.URL.Query()[key]
	if len(vals) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(vals[len(vals)-1], 10, 64)
	return n, err == nil
}

func rtSecurityLimitOffset(r *http.Request) (int64, int64) {
	limit, ok := rtSecurityQueryI64(r, "limit")
	if !ok {
		limit = 100
	}
	offset, _ := rtSecurityQueryI64(r, "offset")
	return min(limit, 500), offset
}

// rtSecurityAuditLogList is GET /api/security/audit-log — query the
// immutable audit log.
func rtSecurityAuditLogList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	limit, offset := rtSecurityLimitOffset(r)
	type row struct {
		ID         uuid.UUID `db:"id"`
		EventType  string    `db:"event_type"`
		ActorEmail *string   `db:"actor_email"`
		ActorIP    *string   `db:"actor_ip"`
		TargetType *string   `db:"target_type"`
		TargetName *string   `db:"target_name"`
		Details    *string   `db:"details"`
		GeoCountry *string   `db:"geo_country"`
		GeoCity    *string   `db:"geo_city"`
		GeoISP     *string   `db:"geo_isp"`
		Severity   string    `db:"severity"`
		CreatedAt  time.Time `db:"created_at"`
	}
	const cols = "SELECT id, event_type, actor_email, actor_ip, target_type, target_name, details, geo_country, geo_city, geo_isp, severity, created_at "
	var rows []row
	var err error
	if sev := r.URL.Query()["severity"]; len(sev) > 0 {
		rows, err = queryAll[row](r.Context(), st.DB,
			cols+"FROM security_audit_log WHERE severity = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
			sev[len(sev)-1], limit, offset)
	} else {
		rows, err = queryAll[row](r.Context(), st.DB,
			cols+"FROM security_audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset)
	}
	if err != nil {
		return internalError("audit log list", err)
	}
	out := make([]any, 0, len(rows))
	for _, x := range rows {
		out = append(out, map[string]any{
			"id": x.ID, "event_type": x.EventType, "actor_email": x.ActorEmail, "actor_ip": x.ActorIP,
			"target_type": x.TargetType, "target_name": x.TargetName, "details": x.Details,
			"geo_country": x.GeoCountry, "geo_city": x.GeoCity, "geo_isp": x.GeoISP,
			"severity": x.Severity, "created_at": x.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// rtSecuritySuspiciousEventsList is GET /api/security/suspicious-events —
// the feed behind auto-lockdown. Its only reader used to be a bare COUNT(*)
// tripping the threshold: an admin could see the lockdown fire and never see
// what happened.
func rtSecuritySuspiciousEventsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	limit, offset := rtSecurityLimitOffset(r)
	rows, err := queryAll[Tup6[uuid.UUID, string, *string, *string, *string, time.Time]](r.Context(), st.DB,
		"SELECT id, event_type, actor_email, actor_ip, details, created_at "+
			"FROM suspicious_events ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return internalError("suspicious events list", err)
	}
	out := make([]any, 0, len(rows))
	for _, x := range rows {
		out = append(out, map[string]any{
			"id": x.A, "event_type": x.B, "actor_email": x.C, "actor_ip": x.D,
			"details": x.E, "created_at": x.F,
		})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// rtSecurityRecordingsList is GET /api/security/recordings — terminal
// session recordings (Feature 5).
func rtSecurityRecordingsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	type rec struct {
		created *string
		v       map[string]any
	}
	var recs []rec
	if entries, err := os.ReadDir("/var/lib/dockpanel/recordings"); err == nil {
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			var created *string
			if t, ok := autoHealerCreated(e); ok {
				created = new(autoHealerRFC3339(t))
			}
			recs = append(recs, rec{created, map[string]any{
				"filename": e.Name(), "size_bytes": info.Size(), "created": created,
			}})
		}
	}
	// Newest first; Option ordering puts entries with no time last.
	slices.SortStableFunc(recs, func(a, b rec) int {
		switch {
		case a.created == nil && b.created == nil:
			return 0
		case a.created == nil:
			return 1
		case b.created == nil:
			return -1
		}
		return strings.Compare(*b.created, *a.created)
	})
	out := make([]any, 0, len(recs))
	for _, x := range recs {
		out = append(out, x.v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"recordings": out})
	return nil
}

// rtSecurityApproveUser is POST /api/security/users/{id}/approve (Feature 8).
func rtSecurityApproveUser(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	userID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB,
		"UPDATE users SET approved = TRUE, approved_at = NOW(), approved_by = $1 WHERE id = $2", claims.Sub, userID)
	if err != nil {
		return internalError("approve user", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "User not found")
	}
	SecurityHardeningAuditLog(r.Context(), st.DB, "user.approve", new(claims.Email), nil,
		new("user"), new(userID.String()), nil, nil, "info", claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "approved"})
	return nil
}

// rtSecurityPendingUsers is GET /api/security/pending-users (Feature 8).
func rtSecurityPendingUsers(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	users, err := queryAll[Tup3[uuid.UUID, string, time.Time]](r.Context(), st.DB,
		"SELECT id, email, created_at FROM users WHERE approved = FALSE ORDER BY created_at DESC LIMIT 500")
	if err != nil {
		return internalError("pending users", err)
	}
	out := make([]any, 0, len(users))
	for _, u := range users {
		out = append(out, map[string]any{"id": u.A, "email": u.B, "created_at": u.C})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// rtSecurityVerifyUserEmail is POST /api/security/users/{id}/verify-email —
// mark an address verified without sending mail (#100).
//
// The recovery door for a verification that can never complete: login
// refuses an unverified account whenever smtp_host is set, and every
// self-service exit needs working mail. An operator whose SMTP is broken
// cannot mail their way out of a mail problem. This is the `approved`
// override, one column over.
func rtSecurityVerifyUserEmail(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	userID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	// Clearing the token alongside the flag, as the token and reset doors
	// always have: a redeemable link must not outlive the verification.
	n, err := execSQL(r.Context(), st.DB,
		"UPDATE users SET email_verified = TRUE, email_token = NULL, updated_at = NOW() WHERE id = $1", userID)
	if err != nil {
		return internalError("verify user email", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "User not found")
	}
	SecurityHardeningAuditLog(r.Context(), st.DB, "user.email_verify", new(claims.Email), nil,
		new("user"), new(userID.String()), nil, nil, "info", claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "verified"})
	return nil
}

// rtSecurityUnverifiedUsers is GET /api/security/unverified-users (#100).
// can_self_verify FALSE means no token exists, so this override is the ONLY
// way in short of a database edit.
func rtSecurityUnverifiedUsers(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	users, err := queryAll[Tup5[uuid.UUID, string, string, bool, time.Time]](r.Context(), st.DB,
		"SELECT id, email, role, (email_token IS NOT NULL) AS can_self_verify, created_at "+
			"FROM users WHERE email_verified = FALSE ORDER BY created_at DESC LIMIT 500")
	if err != nil {
		return internalError("unverified users", err)
	}
	out := make([]any, 0, len(users))
	for _, u := range users {
		out = append(out, map[string]any{
			"id": u.A, "email": u.B, "role": u.C, "can_self_verify": u.D, "created_at": u.E,
		})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
