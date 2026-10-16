package api

// Port of panel/backend/src/routes/system.rs.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtSystemRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("GET /api/health", h(rtSystemHealth))
	r.Handle("GET /api/system/info", h(rtSystemProxyGet("/system/info", "System info")))
	// System Updates
	r.Handle("GET /api/system/updates", h(rtSystemProxyGet("/system/updates", "System updates")))
	r.Handle("POST /api/system/updates/apply", h(rtSystemUpdatesApply))
	r.Handle("GET /api/system/updates/count", h(rtSystemProxyGet("/system/updates/count", "Update count")))
	r.Handle("POST /api/system/reboot", h(rtSystemReboot))
	r.Handle("GET /api/system/disk-io", h(rtSystemProxyGet("/system/disk-io", "Disk I/O")))
	r.Handle("POST /api/system/cleanup", h(rtSystemDiskCleanup))
	r.Handle("POST /api/system/hostname", h(rtSystemChangeHostname))
	// SSH Keys
	r.Handle("GET /api/ssh-keys", h(rtSystemProxyGet("/ssh-keys", "SSH keys")))
	r.Handle("POST /api/ssh-keys", h(rtSystemAddSSHKey))
	r.Handle("DELETE /api/ssh-keys/{fingerprint}", h(rtSystemRemoveSSHKey))
	// Auto-Updates
	r.Handle("GET /api/auto-updates/status", h(rtSystemProxyGet("/auto-updates/status", "Auto-updates")))
	r.Handle("POST /api/auto-updates/enable", h(rtSystemAutoUpdates("/auto-updates/enable", "Enable auto-updates", "auto-updates.enable")))
	r.Handle("POST /api/auto-updates/disable", h(rtSystemAutoUpdates("/auto-updates/disable", "Disable auto-updates", "auto-updates.disable")))
	// Service installers
	r.Handle("GET /api/services/install-status", h(rtSystemProxyGet("/services/install-status", "Install status")))
	for _, s := range rtSystemServices {
		r.Handle("POST /api/services/"+s.path, h(rtSystemInstall(s.name, "/services/"+s.path)))
	}
	r.Handle("POST /api/services/install/powerdns", h(rtSystemInstallPowerdns))
	r.Handle("GET /api/services/install/{install_id}/log", h(rtSystemInstallLog))
	r.Handle("POST /api/services/uninstall/powerdns", h(rtSystemUninstallPowerdns))
	// Traefik Reverse Proxy
	r.Handle("POST /api/traefik/install", h(rtSystemTraefikInstall))
	r.Handle("POST /api/traefik/uninstall", h(rtSystemTraefikUninstall))
	r.Handle("GET /api/traefik/status", h(rtSystemProxyGet("/traefik/status", "Traefik status")))
	// Agent Diagnostics proxy
	r.Handle("GET /api/agent/diagnostics", h(rtSystemProxyGet("/diagnostics", "Diagnostics")))
	r.Handle("POST /api/agent/diagnostics/fix", h(rtSystemDiagnosticsFix))
	r.Handle("GET /api/agent/recommendations", h(rtSystemProxyGet("/diagnostics/recommendations", "Recommendations")))
}

// rtSystemServices are the installers/uninstallers that all funnel through
// rtSystemInstallServiceWithLog: (route/agent path suffix, display name).
var rtSystemServices = []struct{ path, name string }{
	{"install/php", "PHP"},
	{"install/certbot", "Certbot"},
	{"install/ufw", "UFW Firewall"},
	{"install/fail2ban", "Fail2Ban"},
	{"install/redis", "Redis"},
	{"install/nodejs", "Node.js"},
	{"install/composer", "Composer"},
	// sshpass for password-authenticated SFTP backup destinations. ServerScope
	// rather than a server_id in the body: this runs a package transaction as
	// root, so the target must be a server the caller is proven to own. #93.
	{"install/sshpass", "sshpass"},
	{"install/waf", "WAF (ModSecurity)"},
	{"install/cloudflared", "Cloudflare Tunnel"},
	{"uninstall/php", "PHP (uninstall)"},
	{"uninstall/certbot", "Certbot (uninstall)"},
	{"uninstall/ufw", "UFW Firewall (uninstall)"},
	{"uninstall/fail2ban", "Fail2Ban (uninstall)"},
	{"uninstall/redis", "Redis (uninstall)"},
	{"uninstall/nodejs", "Node.js (uninstall)"},
	{"uninstall/composer", "Composer (uninstall)"},
	{"uninstall/waf", "WAF (uninstall)"},
	{"uninstall/cloudflared", "Cloudflare Tunnel (uninstall)"},
}

// rtSystemAdminScope is the AdminUser + ServerScope extractor pair.
func rtSystemAdminScope(st *AppState, r *http.Request) (*Claims, uuid.UUID, AgentHandle, error) {
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

// rtSystemProxyGet is the admin-only read passthrough to the scoped agent.
func rtSystemProxyGet(path, ctxMsg string) func(*AppState, http.ResponseWriter, *http.Request) error {
	return func(st *AppState, w http.ResponseWriter, r *http.Request) error {
		_, _, agent, err := rtSystemAdminScope(st, r)
		if err != nil {
			return err
		}
		data, err := agent.Get(r.Context(), path)
		if err != nil {
			return agentError(ctxMsg, err)
		}
		writeJSON(w, http.StatusOK, data)
		return nil
	}
}

// rtSystemHealth is GET /api/health — public health check (includes DB
// connectivity).
func rtSystemHealth(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := execSQL(r.Context(), st.DB, "SELECT 1"); err == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok", "service": "dockpanel-api", "version": Version,
		})
	} else {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "degraded", "db": "unreachable", "service": "dockpanel-api", "version": Version,
		})
	}
	return nil
}

// rtSystemDiagnosticsFix is POST /api/agent/diagnostics/fix — apply a
// one-click fix.
//
// Mostly a proxy, with ONE fix the agent cannot perform and the panel can.
// `renew-ssl:{domain}` was a button that could only fail: the agent offers it
// on every certificate inside 30 days but has no arm for it, so it fell
// through to "Unknown fix action" — a 500, i.e. an incident id the operator
// retried. Renewal needs the site's runtime, root, PHP version and an ACME
// contact, all in the panel's database, so the panel takes the fix — which is
// also what makes it ARRIVE (an agent is only updated when somebody updates
// it). A certificate with no sites row now gets a sentence, not an incident id.
func rtSystemDiagnosticsFix(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, err := rtSystemAdminScope(st, r)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return err
	}
	var body any
	_ = json.Unmarshal(raw, &body)
	fixID := securityScannerStrOr(jsonGet(body, "fix_id"), "")
	ctx := r.Context()

	if domain, ok := strings.CutPrefix(fixID, "renew-ssl:"); ok {
		// Two statements on purpose, here rather than behind a helper, because
		// this handler chooses a destination. The first names the row ON THE
		// HOST THAT RAISED THE FINDING (sites.domain is unique only per
		// server); the second re-reads it through SiteCallerPredicate, the
		// shared authorisation — reuse carries the mechanism, never the gate.
		siteID, err := queryScalarOpt[uuid.UUID](ctx, st.DB,
			"SELECT id FROM sites WHERE domain = $1 AND server_id = $2", domain, serverID)
		if err != nil {
			return internalError("diagnostics ssl fix lookup", err)
		}
		if siteID == nil {
			// A certificate with no sites row. ⚠ It must NOT claim the cert
			// came from outside DockPanel: the agent issues certificates for
			// Docker apps, stacks, Git deploys and mail domains, none of which
			// is a sites row. So the refusal names what the panel found.
			//
			// Deliberately not server-scoped: mail_domains.server_id was NULL
			// on every panel-created row for months and git_deploys.domain is
			// nullable — naming the owner approximately beats naming nothing
			// precisely.
			claimedBy, _ := queryScalarOpt[string](ctx, st.DB,
				"SELECT 'mail domain' FROM mail_domains WHERE domain = $1 "+
					"UNION ALL SELECT 'Git deploy' FROM git_deploys WHERE domain = $1 "+
					"UNION ALL SELECT 'Docker app' FROM container_sleep_config WHERE domain = $1 "+
					"UNION ALL SELECT 'Compose stack' FROM docker_stacks WHERE lower(domain) = lower($1) "+
					"LIMIT 1", domain)

			// A stack's answer depends on its TLS MODE: "redeploy reissues it"
			// is true of an acme stack and FALSE of a provided one. ⛔ Read
			// through effective_tls_mode, never a CASE in SQL — one spelling.
			var stackMode *string
			if claimedBy != nil && *claimedBy == "Compose stack" {
				row, _ := queryOpt[Tup2[*string, *string]](ctx, st.DB,
					"SELECT tls_mode, ssl_email FROM docker_stacks WHERE lower(domain) = lower($1)", domain)
				if row != nil {
					stackMode = new(rtStacksEffectiveTlsMode(row.A, row.B))
				}
			}

			var tail string
			switch {
			case claimedBy != nil && stackMode != nil && *stackMode != "acme":
				tail = "A Compose stack in this panel uses that name, but it serves a registered " +
					"certificate rather than a Let's Encrypt one — so this expiring file is a " +
					"leftover from before that change, and nothing renews it because nothing " +
					"serves it. Removing it is safe; the stack is unaffected."
			case claimedBy != nil:
				tail = fmt.Sprintf("A %s in this panel uses that name, and DockPanel issued this "+
					"certificate for it — but only certificates attached to a SITE can be "+
					"renewed from here. Redeploy that %s to reissue it.", *claimedBy, *claimedBy)
			default:
				tail = "No site, mail domain, Git deploy, Docker app or Compose stack in " +
					"this panel claims that name — so this is a certificate DockPanel " +
					"does not manage, such as a DNS-01 wildcard or one installed by " +
					"hand, and it is renewed wherever it was issued."
			}
			return apiErr(http.StatusUnprocessableEntity,
				fmt.Sprintf("No site named %s is registered on this server. %s", domain, tail))
		}

		site, err := queryOpt[Site](ctx, st.DB, "SELECT s.* FROM sites s WHERE "+SiteCallerPredicate, *siteID, claims.Sub)
		if err != nil {
			return internalError("diagnostics ssl fix", err)
		}
		if site == nil {
			return apiErr(http.StatusNotFound, "Site not found")
		}

		// The renewal's own {ok, domain} body is dropped: the Diagnostics
		// screen reads {success, message}. The error return is load-bearing —
		// a PRECONDITION_FAILED or an agent 4xx reaches the operator as that
		// sentence instead of a reference id.
		if _, err := rtSslRenewForSite(ctx, st, site, claims.Sub, claims.Email); err != nil {
			return err
		}
		ActivityLogActivityOnServer(ctx, st.DB, claims.Sub, claims.Email, "diagnostics.fix",
			new("renew-ssl"), new(domain), nil, nil, new(serverID), claims.KeyID)
		writeJSON(w, http.StatusOK, map[string]any{
			"success": true,
			"message": "Renewed the certificate for " + domain,
		})
		return nil
	}

	data, err := agent.Post(ctx, "/diagnostics/fix", raw)
	if err != nil {
		return agentError("Diagnostics fix", err)
	}
	action, target, found := strings.Cut(fixID, ":")
	var targetP *string
	if found {
		targetP = new(target)
	} else {
		action = fixID
	}
	ActivityLogActivityOnServer(ctx, st.DB, claims.Sub, claims.Email, "diagnostics.fix",
		new(action), targetP, nil, nil, new(serverID), claims.KeyID)
	writeJSON(w, http.StatusOK, data)
	return nil
}

// rtSystemDiskCleanup is POST /api/system/cleanup (admin only).
func rtSystemDiskCleanup(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtSystemAdminScope(st, r)
	if err != nil {
		return err
	}
	data, err := agent.Post(r.Context(), "/system/cleanup", nil)
	if err != nil {
		return agentError("Disk cleanup", err)
	}
	ActivityLogActivity(r.Context(), st.DB, claims.Sub, claims.Email, "system.cleanup", nil, nil, nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, data)
	return nil
}

// rtSystemChangeHostname is POST /api/system/hostname (admin only).
func rtSystemChangeHostname(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtSystemAdminScope(st, r)
	if err != nil {
		return err
	}
	var body json.RawMessage
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	data, err := agent.Post(r.Context(), "/system/hostname", body)
	if err != nil {
		return agentError("Hostname change", err)
	}
	ActivityLogActivity(r.Context(), st.DB, claims.Sub, claims.Email, "system.hostname_change", nil, nil, nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, data)
	return nil
}

// rtSystemUpdateStreamIdleTimeoutSecs is how long an update stream may stay
// *silent* before it is declared wedged. Not a budget for the update — apt
// may take as long as it takes; it only has to say something every ten
// minutes, which covers the quietest legitimate stretches.
const rtSystemUpdateStreamIdleTimeoutSecs = 600

// rtSystemUpdateLogRetention is how long a finished update's log is kept for
// late SSE reconnects. The browser replays full history on reconnect, so this
// window is what lets an operator who lost the connection come back and still
// learn whether the update succeeded. At 60s it was shorter than that gap.
const rtSystemUpdateLogRetention = 900 * time.Second

// rtSystemEmit appends one provisioning step.
func rtSystemEmit(st *AppState, id uuid.UUID, step, label, status string, msg *string) {
	st.ProvisionLogs.Emit(id, ProvisionStep{Step: step, Label: label, Status: status, Message: msg})
}

// rtSystemUpdatesApply is POST /api/system/updates/apply — apply package
// updates (admin only). Returns install_id for SSE progress via
// /api/services/install/{id}/log; the agent streams apt output as NDJSON,
// forwarded line by line.
func rtSystemUpdatesApply(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtSystemAdminScope(st, r)
	if err != nil {
		return err
	}
	var body json.RawMessage
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	installID := uuid.New()
	// 256: this forwards apt output line by line, not a dozen coarse steps.
	st.ProvisionLogs.Register(installID, claims.Sub, 256)

	userID, email, keyID := claims.Sub, claims.Email, claims.KeyID
	ctx := context.WithoutCancel(r.Context())
	go func() {
		rtSystemEmit(st, installID, "update", "Applying system updates", "in_progress", nil)

		onLine := func(v any) {
			switch securityScannerStrOr(jsonGet(v, "type"), "") {
			case "line":
				if line := securityScannerStrOr(jsonGet(v, "line"), ""); line != "" {
					rtSystemEmit(st, installID, "line", line, "in_progress", nil)
				}
			case "done":
				ok, _ := jsonBool(jsonGet(v, "success"))
				updateStatus, completeLabel, completeStatus := "error", "Updates finished with errors", "error"
				if ok {
					updateStatus, completeLabel, completeStatus = "done", "Updates applied", "done"
				}
				rtSystemEmit(st, installID, "update", "Applying system updates", updateStatus, nil)
				rtSystemEmit(st, installID, "complete", completeLabel, completeStatus, nil)
			}
		}

		if err := agent.PostLongNDJSON(ctx, "/system/updates/apply", body, rtSystemUpdateStreamIdleTimeoutSecs, onLine); err != nil {
			rtSystemEmit(st, installID, "update", "Failed to apply updates", "error", new(err.Error()))
			rtSystemEmit(st, installID, "complete", "Update failed", "error", nil)
		} else {
			ActivityLogActivity(ctx, st.DB, userID, email, "system.updates.apply",
				new("system"), new("packages"), nil, nil, keyID)
		}

		time.Sleep(rtSystemUpdateLogRetention)
		st.ProvisionLogs.Remove(installID)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{"install_id": installID, "message": "Updates started"})
	return nil
}

// rtSystemReboot is POST /api/system/reboot (admin only).
func rtSystemReboot(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtSystemAdminScope(st, r)
	if err != nil {
		return err
	}
	data, err := agent.Post(r.Context(), "/system/reboot", nil)
	if err != nil {
		return agentError("System reboot", err)
	}
	ActivityLogActivity(r.Context(), st.DB, claims.Sub, claims.Email, "system.reboot",
		new("system"), new("server"), nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, data)
	return nil
}

// rtSystemInstallAgentTimeoutSecs is how long the panel gives the agent to
// finish an install. Deliberately far above the agent's own 300s
// INSTALL_TIMEOUT, because the agent does work either side of that clock. It
// used to be 60s: the agent finished the install while this side had already
// written "agent request timed out" into the log the operator was watching —
// a caller timeout shorter than the callee's bounds nothing, it only decides
// which side describes the outcome.
const rtSystemInstallAgentTimeoutSecs = 900

// rtSystemInstallServiceWithLog is the generic service install/uninstall with
// a provisioning log (async SSE). Every install and uninstall route plus both
// PHP routes funnel through here.
//
// Returns the (202, body) pair for the caller to write — rt_sites' PHP routes
// share it. A nil agentBody is the Rust None: no request body at all.
func rtSystemInstallServiceWithLog(ctx context.Context, st *AppState, agent AgentHandle,
	claimsSub uuid.UUID, claimsEmail, serviceName, agentPath string, agentBody map[string]any) (int, any, error) {
	installID := uuid.New()
	st.ProvisionLogs.Register(installID, claimsSub, 32)

	var body any // a typed nil map would serialize as `null`
	if agentBody != nil {
		body = agentBody
	}
	ctx = context.WithoutCancel(ctx)
	go func() {
		label := "Installing " + serviceName
		rtSystemEmit(st, installID, "install", label, "in_progress", nil)

		resp, err := agent.PostLong(ctx, agentPath, body, rtSystemInstallAgentTimeoutSecs)
		if err != nil {
			rtSystemEmit(st, installID, "install", label, "error", new(err.Error()))
			rtSystemEmit(st, installID, "complete", "Install failed", "error", nil)
			slog.Error(fmt.Sprintf("Service install failed: %s: %v", serviceName, err))
		} else {
			// A 200 is not the same as a success: for PHP the agent judges an
			// install by whether FPM opened its socket, an honest 200 carrying
			// success:false. Absent means success — most installers answer
			// {"ok": true} with no such field.
			ok := true
			if b, has := jsonBool(jsonGet(resp, "success")); has {
				ok = b
			}
			// The agent also answers 200 for "already installed" and carries
			// the distinction in `message`; pass it through.
			detail := securityScannerOptStr(jsonGet(resp, "message"))
			status := "error"
			if ok {
				status = "done"
			}
			rtSystemEmit(st, installID, "install", label, status, detail)
			if ok {
				rtSystemEmit(st, installID, "complete", serviceName+" installed", "done", detail)
				slog.Info("Service installed: " + serviceName)
			} else {
				rtSystemEmit(st, installID, "complete", serviceName+" did not finish", "error", detail)
				slog.Warn("Service install reported failure: " + serviceName)
			}
			// Logged either way: an attempt that did not finish is the entry
			// most worth finding later.
			ActivityLogActivity(ctx, st.DB, claimsSub, claimsEmail, "service.install",
				new("system"), new(serviceName), nil, nil, nil)
		}

		time.Sleep(30 * time.Second)
		st.ProvisionLogs.Remove(installID)
	}()

	return http.StatusAccepted, map[string]any{
		"install_id": installID,
		"message":    serviceName + " installation started",
	}, nil
}

// rtSystemInstall is every POST /api/services/{install,uninstall}/<svc>
// except PowerDNS.
func rtSystemInstall(serviceName, agentPath string) func(*AppState, http.ResponseWriter, *http.Request) error {
	return func(st *AppState, w http.ResponseWriter, r *http.Request) error {
		claims, _, agent, err := rtSystemAdminScope(st, r)
		if err != nil {
			return err
		}
		status, res, err := rtSystemInstallServiceWithLog(r.Context(), st, agent, claims.Sub, claims.Email, serviceName, agentPath, nil)
		if err != nil {
			return err
		}
		writeJSON(w, status, res)
		return nil
	}
}

// rtSystemInstallLog is GET /api/services/install/{install_id}/log — SSE
// stream of install progress.
//
// Despite the path, this is the panel's general provisioning stream (backup,
// restore, site-deploy, mail-install and system-update ids too), so it cannot
// authorize by feature — and it used to authorize by nothing, handing any
// key's log (including another tenant's cleartext CMS admin password) to any
// admin. Ownership is now checked per key, which is strictly narrower than
// "anyone with the admin role" and lets a non-admin read the job they started.
func rtSystemInstallLog(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	installID, err := pathUUID(r, "install_id")
	if err != nil {
		return err
	}
	history, live, unsub, err := st.ProvisionLogs.Open(installID, claims.Sub, "No active install")
	if err != nil {
		return err
	}
	defer unsub()
	// The stream ends once the job's entry is dropped, the client leaves, or
	// the panel shuts down — an install in progress at shutdown can still run
	// well past the graceful-drain window.
	rtSitesServeSSE(st, w, r, history, live)
	return nil
}

// rtSystemAddSSHKey is POST /api/ssh-keys.
func rtSystemAddSSHKey(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtSystemAdminScope(st, r)
	if err != nil {
		return err
	}
	var body json.RawMessage
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	result, err := agent.Post(r.Context(), "/ssh-keys", body)
	if err != nil {
		return agentError("Add SSH key", err)
	}
	rtSecurityLogBoth(r.Context(), st, claims, clientIP(r), "ssh.key.add", new("system"), nil, nil, "warning")
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtSystemRemoveSSHKey is DELETE /api/ssh-keys/{fingerprint}.
func rtSystemRemoveSSHKey(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	fingerprint := r.PathValue("fingerprint")
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	result, err := agent.Delete(r.Context(), "/ssh-keys/"+fingerprint)
	if err != nil {
		return agentError("Remove SSH key", err)
	}
	rtSecurityLogBoth(r.Context(), st, claims, clientIP(r), "ssh.key.remove", new("system"), nil, nil, "warning")
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtSystemAutoUpdates is POST /api/auto-updates/{enable,disable}.
func rtSystemAutoUpdates(path, ctxMsg, action string) func(*AppState, http.ResponseWriter, *http.Request) error {
	return func(st *AppState, w http.ResponseWriter, r *http.Request) error {
		claims, _, agent, err := rtSystemAdminScope(st, r)
		if err != nil {
			return err
		}
		result, err := agent.Post(r.Context(), path, nil)
		if err != nil {
			return agentError(ctxMsg, err)
		}
		ActivityLogActivity(r.Context(), st.DB, claims.Sub, claims.Email, action, new("system"), nil, nil, nil, claims.KeyID)
		writeJSON(w, http.StatusOK, result)
		return nil
	}
}

// The "Panel IP Whitelist" proxy that stood here was removed in v2.90.0: it
// wrote a file on the agent host that nothing ever read. The real IP
// restriction is a setting enforced at every session-minting door.

// rtSystemInstallPowerdns is POST /api/services/install/powerdns.
func rtSystemInstallPowerdns(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, err := rtSystemAdminScope(st, r)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(raw) > maxJSONBody {
		return rejection(http.StatusRequestEntityTooLarge, "Failed to buffer the request body: length limit exceeded")
	}
	ctx := r.Context()

	// pdns_api_url/pdns_api_key live in the global settings table, but
	// installation is per server. Installing on a second server would silently
	// overwrite the first server's credentials and orphan every zone.
	// pdns_server_id records the owner; absent = no install yet or a
	// grandfathered pre-check install (not blocked).
	owner, err := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'pdns_server_id'")
	if err != nil {
		return internalError("check pdns owner", err)
	}
	if owner != nil {
		if ownerID, perr := uuid.Parse(*owner); perr == nil && ownerID != serverID {
			name, err := queryScalarOpt[string](ctx, st.DB, "SELECT name FROM servers WHERE id = $1", ownerID)
			if err != nil {
				return internalError("look up pdns owner server", err)
			}
			label := ownerID.String()
			if name != nil {
				label = *name
			}
			return apiErr(http.StatusConflict, fmt.Sprintf(
				"PowerDNS is already configured for server '%s'. Uninstall it there first — installing on a second server would overwrite those credentials and orphan its DNS zones.", label))
		}
	}

	// Optional {"backend":"sqlite"|"pgsql"} forwarded to the agent (#63).
	// Absent/invalid → no body, so the agent applies its pgsql default.
	var forwardBody any
	var parsed any
	if json.Unmarshal(raw, &parsed) == nil {
		if b, ok := jsonStr(jsonGet(parsed, "backend")); ok && (b == "sqlite" || b == "pgsql") {
			forwardBody = map[string]any{"backend": b}
		}
	}

	installID := uuid.New()
	st.ProvisionLogs.Register(installID, claims.Sub, 32)
	userID, email, keyID, ip := claims.Sub, claims.Email, claims.KeyID, clientIP(r)
	bg := context.WithoutCancel(ctx)

	go func() {
		rtSystemEmit(st, installID, "install", "Installing PowerDNS", "in_progress", nil)
		// PostLong: an apt install plus a service start; 60s is no budget.
		result, err := agent.PostLong(bg, "/services/install/powerdns", forwardBody, 900)
		if err != nil {
			rtSystemEmit(st, installID, "install", "Installing PowerDNS", "error", new(err.Error()))
			rtSystemEmit(st, installID, "complete", "Install failed", "error", nil)
			slog.Error(fmt.Sprintf("Service install failed: PowerDNS: %v", err))
		} else {
			// Auto-save API URL and key (encrypted) to settings.
			apiURL, okU := jsonStr(jsonGet(result, "api_url"))
			apiKey, okK := jsonStr(jsonGet(result, "api_key"))
			if okU && okK {
				_, _ = execSQL(bg, st.DB, "INSERT INTO settings (key, value, updated_at) VALUES ('pdns_api_url', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()", apiURL)
				enc, eerr := SecretsCryptoEncryptCredential(apiKey, st.Config.JWTSecret)
				if eerr != nil {
					enc = apiKey
				}
				_, _ = execSQL(bg, st.DB, "INSERT INTO settings (key, value, updated_at) VALUES ('pdns_api_key', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()", enc)
				_, _ = execSQL(bg, st.DB, "INSERT INTO settings (key, value, updated_at) VALUES ('pdns_server_id', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()", serverID.String())
			}
			rtSystemEmit(st, installID, "install", "Installing PowerDNS", "done", nil)
			rtSystemEmit(st, installID, "complete", "PowerDNS installed", "done", nil)
			ActivityLogActivity(bg, st.DB, userID, email, "service.install", new("system"), new("powerdns"), nil, ip, keyID)
			SecurityHardeningAuditLog(bg, st.DB, "service.install", new(email), ip,
				new("system"), new("powerdns"), nil, nil, "warning", keyID)
			slog.Info("Service installed: PowerDNS")
		}
		time.Sleep(30 * time.Second)
		st.ProvisionLogs.Remove(installID)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{"install_id": installID, "message": "PowerDNS installation started"})
	return nil
}

// rtSystemUninstallPowerdns is POST /api/services/uninstall/powerdns. Custom
// (not the shared helper) because a successful uninstall must also free the
// pdns_server_id slot install guards on — otherwise this server would stay
// the recorded owner and block installing PowerDNS anywhere else.
func rtSystemUninstallPowerdns(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, err := rtSystemAdminScope(st, r)
	if err != nil {
		return err
	}
	installID := uuid.New()
	st.ProvisionLogs.Register(installID, claims.Sub, 32)
	userID, email, keyID, ip := claims.Sub, claims.Email, claims.KeyID, clientIP(r)
	bg := context.WithoutCancel(r.Context())

	go func() {
		rtSystemEmit(st, installID, "install", "Uninstalling PowerDNS", "in_progress", nil)
		if _, err := agent.PostLong(bg, "/services/uninstall/powerdns", nil, rtSystemInstallAgentTimeoutSecs); err != nil {
			rtSystemEmit(st, installID, "install", "Uninstalling PowerDNS", "error", new(err.Error()))
			rtSystemEmit(st, installID, "complete", "Uninstall failed", "error", nil)
			slog.Error(fmt.Sprintf("Service uninstall failed: PowerDNS: %v", err))
		} else {
			// Clear the saved credentials only if THIS server is the recorded
			// owner (or none was ever recorded). Uninstalling on a server that
			// never owned the install must not wipe another server's live
			// credentials; an unreadable owner clears nothing.
			owner, oerr := queryScalarOpt[string](bg, st.DB, "SELECT value FROM settings WHERE key = 'pdns_server_id'")
			owned := false
			switch {
			case oerr != nil:
			case owner == nil:
				owned = true
			default:
				id, perr := uuid.Parse(*owner)
				owned = perr != nil || id == serverID
			}
			if owned {
				_, _ = execSQL(bg, st.DB, "DELETE FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key', 'pdns_server_id')")
			}
			rtSystemEmit(st, installID, "install", "Uninstalling PowerDNS", "done", nil)
			rtSystemEmit(st, installID, "complete", "PowerDNS uninstalled", "done", nil)
			ActivityLogActivity(bg, st.DB, userID, email, "service.uninstall", new("system"), new("powerdns"), nil, ip, keyID)
			SecurityHardeningAuditLog(bg, st.DB, "service.uninstall", new(email), ip,
				new("system"), new("powerdns"), nil, nil, "warning", keyID)
			slog.Info("Service uninstalled: PowerDNS")
		}
		time.Sleep(30 * time.Second)
		st.ProvisionLogs.Remove(installID)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{"install_id": installID, "message": "PowerDNS uninstallation started"})
	return nil
}

// rtSystemTraefikInstall is POST /api/traefik/install.
func rtSystemTraefikInstall(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtSystemAdminScope(st, r)
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	acmeEmail := securityScannerStrOr(jsonGet(body, "acme_email"), "admin@localhost")
	ctx := r.Context()
	result, err := agent.Post(ctx, "/traefik/install", map[string]any{"acme_email": acmeEmail})
	if err != nil {
		return agentError("Traefik install", err)
	}
	_, _ = execSQL(ctx, st.DB, "INSERT INTO settings (key, value, updated_at) VALUES ('reverse_proxy', 'traefik', NOW()) ON CONFLICT (key) DO UPDATE SET value = 'traefik', updated_at = NOW()")
	rtSecurityLogBoth(ctx, st, claims, clientIP(r), "traefik.install", new("system"), nil, nil, "warning")
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtSystemTraefikUninstall is POST /api/traefik/uninstall.
func rtSystemTraefikUninstall(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtSystemAdminScope(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	result, err := agent.Post(ctx, "/traefik/uninstall", nil)
	if err != nil {
		return agentError("Traefik uninstall", err)
	}
	// Revert to nginx.
	_, _ = execSQL(ctx, st.DB, "INSERT INTO settings (key, value, updated_at) VALUES ('reverse_proxy', 'nginx', NOW()) ON CONFLICT (key) DO UPDATE SET value = 'nginx', updated_at = NOW()")
	rtSecurityLogBoth(ctx, st, claims, clientIP(r), "traefik.uninstall", new("system"), nil, nil, "warning")
	writeJSON(w, http.StatusOK, result)
	return nil
}
