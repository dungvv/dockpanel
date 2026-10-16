package api

// Port of panel/backend/src/routes/mail.rs.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Data types ──────────────────────────────────────────────────────────

type rtMailMailDomain struct {
	ID            uuid.UUID `db:"id" json:"id"`
	Domain        string    `db:"domain" json:"domain"`
	DkimSelector  string    `db:"dkim_selector" json:"dkim_selector"`
	DkimPublicKey *string   `db:"dkim_public_key" json:"dkim_public_key"`
	CatchAll      *string   `db:"catch_all" json:"catch_all"`
	Enabled       bool      `db:"enabled" json:"enabled"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
}

type rtMailMailAccount struct {
	ID                   uuid.UUID `db:"id" json:"id"`
	DomainID             uuid.UUID `db:"domain_id" json:"domain_id"`
	Email                string    `db:"email" json:"email"`
	DisplayName          *string   `db:"display_name" json:"display_name"`
	QuotaMB              int32     `db:"quota_mb" json:"quota_mb"`
	Enabled              bool      `db:"enabled" json:"enabled"`
	ForwardTo            *string   `db:"forward_to" json:"forward_to"`
	AutoresponderEnabled bool      `db:"autoresponder_enabled" json:"autoresponder_enabled"`
	AutoresponderSubject *string   `db:"autoresponder_subject" json:"autoresponder_subject"`
	AutoresponderBody    *string   `db:"autoresponder_body" json:"autoresponder_body"`
	CreatedAt            time.Time `db:"created_at" json:"created_at"`
}

type rtMailMailAlias struct {
	ID               uuid.UUID `db:"id" json:"id"`
	DomainID         uuid.UUID `db:"domain_id" json:"domain_id"`
	SourceEmail      string    `db:"source_email" json:"source_email"`
	DestinationEmail string    `db:"destination_email" json:"destination_email"`
	CreatedAt        time.Time `db:"created_at" json:"created_at"`
}

type rtMailCreateDomainRequest struct {
	Domain string `json:"domain"`
}

type rtMailUpdateDomainRequest struct {
	CatchAll *string `json:"catch_all"`
	Enabled  *bool   `json:"enabled"`
}

type rtMailCreateAccountRequest struct {
	Email       string  `json:"email"`
	Password    string  `json:"password"`
	DisplayName *string `json:"display_name"`
	QuotaMB     *int32  `json:"quota_mb"`
}

type rtMailUpdateAccountRequest struct {
	Password             *string `json:"password"`
	DisplayName          *string `json:"display_name"`
	QuotaMB              *int32  `json:"quota_mb"`
	Enabled              *bool   `json:"enabled"`
	ForwardTo            *string `json:"forward_to"`
	AutoresponderEnabled *bool   `json:"autoresponder_enabled"`
	AutoresponderSubject *string `json:"autoresponder_subject"`
	AutoresponderBody    *string `json:"autoresponder_body"`
}

type rtMailCreateAliasRequest struct {
	SourceEmail      string `json:"source_email"`
	DestinationEmail string `json:"destination_email"`
}

func rtMailRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/mail/status", h(rtMailMailStatus))
	r.Handle("POST /api/mail/install", h(rtMailMailInstall))
	r.Handle("POST /api/mail/uninstall", h(rtMailMailUninstall))
	r.Handle("GET /api/mail/domains", h(rtMailListDomains))
	r.Handle("POST /api/mail/domains", h(rtMailCreateDomain))
	r.Handle("PUT /api/mail/domains/{id}", h(rtMailUpdateDomain))
	r.Handle("DELETE /api/mail/domains/{id}", h(rtMailDeleteDomain))
	r.Handle("GET /api/mail/domains/{id}/dns", h(rtMailDomainDns))
	r.Handle("GET /api/mail/domains/{id}/accounts", h(rtMailListAccounts))
	r.Handle("POST /api/mail/domains/{id}/accounts", h(rtMailCreateAccount))
	r.Handle("PUT /api/mail/domains/{id}/accounts/{account_id}", h(rtMailUpdateAccount))
	r.Handle("DELETE /api/mail/domains/{id}/accounts/{account_id}", h(rtMailDeleteAccount))
	r.Handle("GET /api/mail/domains/{id}/aliases", h(rtMailListAliases))
	r.Handle("POST /api/mail/domains/{id}/aliases", h(rtMailCreateAlias))
	r.Handle("DELETE /api/mail/domains/{id}/aliases/{alias_id}", h(rtMailDeleteAlias))
	r.Handle("GET /api/mail/queue", h(rtMailGetQueue))
	r.Handle("POST /api/mail/queue/flush", h(rtMailFlushQueue))
	r.Handle("DELETE /api/mail/queue/{queue_id}", h(rtMailDeleteQueued))
	r.Handle("POST /api/mail/rspamd/install", h(rtMailRspamdInstall))
	r.Handle("GET /api/mail/rspamd/status", h(rtMailRspamdStatus))
	r.Handle("POST /api/mail/rspamd/toggle", h(rtMailRspamdToggle))
	r.Handle("POST /api/mail/webmail/install", h(rtMailWebmailInstall))
	r.Handle("GET /api/mail/webmail/status", h(rtMailWebmailStatus))
	r.Handle("POST /api/mail/webmail/remove", h(rtMailWebmailRemove))
	r.Handle("POST /api/mail/relay/configure", h(rtMailRelayConfigure))
	r.Handle("GET /api/mail/relay/status", h(rtMailRelayStatus))
	r.Handle("POST /api/mail/relay/remove", h(rtMailRelayRemove))
	r.Handle("GET /api/mail/domains/{id}/dns-check", h(rtMailDnsCheck))
	r.Handle("GET /api/mail/domains/{id}/preflight", h(rtMailPreflight))
	r.Handle("GET /api/mail/logs", h(rtMailMailLogs))
	r.Handle("GET /api/mail/storage", h(rtMailMailStorage))
	r.Handle("GET /api/mail/blacklist-check", h(rtMailBlacklistCheck))
	r.Handle("POST /api/mail/rate-limit/set", h(rtMailRateLimitSet))
	r.Handle("GET /api/mail/rate-limit/status", h(rtMailRateLimitStatus))
	r.Handle("POST /api/mail/rate-limit/remove", h(rtMailRateLimitRemove))
	r.Handle("POST /api/mail/backup", h(rtMailMailboxBackup))
	r.Handle("POST /api/mail/restore", h(rtMailMailboxRestore))
	r.Handle("GET /api/mail/backups", h(rtMailMailboxBackups))
	r.Handle("POST /api/mail/backups/delete", h(rtMailMailboxBackupDelete))
	r.Handle("GET /api/mail/tls/status", h(rtMailTlsStatus))
	r.Handle("POST /api/mail/tls/enforce", h(rtMailTlsEnforce))
}

// ── Extractor + agent passthrough shapes ─────────────────────────────────

// rtMailAdminScope is (AdminUser, ServerScope).
func rtMailAdminScope(st *AppState, r *http.Request) (*Claims, uuid.UUID, AgentHandle, error) {
	c, err := st.adminUser(r)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	sid, agent, err := st.serverScope(r)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	return c, sid, agent, nil
}

// rtMailAgentGet is the "AdminUser + ServerScope → agent.get(path) → Json"
// passthrough most read endpoints here are.
func rtMailAgentGet(st *AppState, w http.ResponseWriter, r *http.Request, path, ctxName string) error {
	_, _, agent, err := rtMailAdminScope(st, r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), path)
	if err != nil {
		return agentError(ctxName, err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtMailAgentPostBody is "AdminUser + ServerScope [+ HeaderMap] + Json<Value> →
// agent.post(path, body)". It returns the agent's answer for the caller to
// shape.
func rtMailAgentPostBody(st *AppState, r *http.Request, path, ctxName string, withBody bool) (*Claims, any, error) {
	c, _, agent, err := rtMailAdminScope(st, r)
	if err != nil {
		return nil, nil, err
	}
	var body any
	if withBody {
		if err := decodeJSON(r, &body); err != nil {
			return nil, nil, err
		}
	}
	res, err := agent.Post(r.Context(), path, body)
	if err != nil {
		return nil, nil, agentError(ctxName, err)
	}
	return c, res, nil
}

func rtMailOK(w http.ResponseWriter) error {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

func rtMailLog(r *http.Request, st *AppState, c *Claims, action string, ip *string) {
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, action, nil, nil, nil, ip, c.KeyID)
}

func rtMailAudit(r *http.Request, st *AppState, c *Claims, action string, targetType, targetName, details, ip *string) {
	SecurityHardeningAuditLog(r.Context(), st.DB, action, &c.Email, ip, targetType, targetName, details, nil, "warning", c.KeyID)
}

// ── Mail server status + installation ────────────────────────────────────

// GET /api/mail/status
func rtMailMailStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtMailAgentGet(st, w, r, "/mail/status", "Mail status")
}

// rtMailSyncFailureReason is the `error` sentence of a sync refusal.
func rtMailSyncFailureReason(err error) string {
	var ae *ApiError
	if errors.As(err, &ae) {
		if m, ok := ae.Body.(map[string]any); ok {
			if s, ok := m["error"].(string); ok {
				return s
			}
		}
	}
	return "the panel could not apply it"
}

// rtMailRunInstall is the shared shape of install/uninstall: 202 + install_id
// for SSE progress tracking, the work in a detached task.
func rtMailRunInstall(st *AppState, w http.ResponseWriter, r *http.Request, uninstall bool) error {
	c, serverID, agent, err := rtMailAdminScope(st, r)
	if err != nil {
		return err
	}
	installID := uuid.New()
	st.ProvisionLogs.Register(installID, c.Sub, 32)

	db := st.DB
	userID, email, keyID := c.Sub, c.Email, c.KeyID
	ctx := context.WithoutCancel(r.Context())

	go func() {
		emit := func(step, label, status string, msg *string) {
			st.ProvisionLogs.Emit(installID, ProvisionStep{Step: step, Label: label, Status: status, Message: msg})
		}

		if uninstall {
			emit("uninstall", "Uninstalling mail server", "in_progress", nil)
			if _, err := agent.PostLong(ctx, "/mail/uninstall", nil, 900); err != nil {
				emit("uninstall", "Uninstalling mail server", "error", new(err.Error()))
				emit("complete", "Uninstall failed", "error", nil)
				slog.Error("Mail server uninstall failed: " + err.Error())
			} else {
				emit("uninstall", "Uninstalling mail server", "done", nil)
				emit("complete", "Mail server uninstalled", "done", nil)
				ActivityLogActivity(ctx, db, userID, email, "mail.server.uninstall", new("mail"), nil, nil, nil, keyID)
				slog.Info("Mail server uninstalled")
			}
		} else {
			emit("install", "Installing mail server", "in_progress", nil)

			// PostLong, not Post. This installs six apt packages and then
			// restarts three services; the default 60s budget is shorter than the
			// work on any ordinary uplink, so the operator was told the install
			// had FAILED while apt carried on underneath and finished (#110).
			if _, err := agent.PostLong(ctx, "/mail/install", nil, 900); err != nil {
				emit("install", "Installing mail server", "error", new(err.Error()))
				emit("complete", "Install failed", "error", nil)
				slog.Error("Mail server install failed: " + err.Error())
			} else {
				emit("install", "Installing mail server", "done", nil)

				// Rebuild the maps the installer just armed against. Every OTHER
				// writer of mail state syncs; the installer was the one path that
				// did not, so a box that re-ran it kept whatever the map file
				// already held and stayed unprotected until its next change.
				//
				// The 202 went out before this task started, so a failure has to
				// surface as a step — which is also why the CONFLICT precondition
				// is reported rather than fatal here: the install itself
				// succeeded, and the remedy is to assign those domains and retry.
				emit("sync", "Applying mail configuration", "in_progress", nil)
				if err := rtMailSyncMailConfig(ctx, db, serverID, agent); err != nil {
					reason := rtMailSyncFailureReason(err)
					slog.Warn(fmt.Sprintf("Mail server installed on %s, but its configuration was not applied: %s", serverID, reason))
					emit("sync", "Applying mail configuration", "error", new(fmt.Sprintf(
						"Mail server installed, but its configuration was not applied: "+
							"%s Mail stays as it was until this is resolved or the "+
							"next mailbox or domain change re-applies it.", reason)))
				} else {
					emit("sync", "Applying mail configuration", "done", nil)
				}

				emit("complete", "Mail server installed", "done", nil)
				ActivityLogActivity(ctx, db, userID, email, "mail.server.install", new("mail"), nil, nil, nil, keyID)
				slog.Info("Mail server installed")
			}
		}

		time.Sleep(60 * time.Second)
		st.ProvisionLogs.Remove(installID)
	}()

	msg := "Mail server installation started"
	if uninstall {
		msg = "Mail server uninstall started"
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"install_id": installID, "message": msg})
	return nil
}

// POST /api/mail/install — Returns 202 + install_id for SSE progress tracking.
func rtMailMailInstall(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtMailRunInstall(st, w, r, false)
}

// POST /api/mail/uninstall — Uninstall mail server (admin only).
func rtMailMailUninstall(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtMailRunInstall(st, w, r, true)
}

// ── Domain routes ───────────────────────────────────────────────────────

// GET /api/mail/domains — the mail domains on the server in scope.
//
// This read had no server term and no ownership term of any kind: it returned
// every mail domain in the installation to every administrator. TWO BRANCHES,
// and they authorise differently on purpose — OWNERSHIP authorises and the
// server term only SCOPES:
//
//   - Administrator: serverScope has already proved the caller owns the server
//     it names, so the server term is the authorisation for this branch.
//   - Site owner (GitHub #106): the same ownership test
//     rtMailMailDomainCallerPredicate applies per row, inlined because a list
//     has no {id} to bind. Deliberately NOT scoped by $1: serverScope's
//     header-absent branch resolves the LOCAL server, and a non-administrator
//     never sends the header, so constraining by $1 would blank the list for a
//     client whose site is on a fleet member — while the per-domain handlers,
//     which resolve the host from the ROW, would happily serve them.
//
// ⚠ The OR between the branches is parenthesised, and that is load-bearing:
// AND binds tighter than OR in SQL.
//
// ⚠ server_id IS NULL stays visible, deliberately: a row that names no server
// belongs to nobody, and hiding it would remove it from the only screen that
// can see it while rtMailSyncMailConfig keeps refusing every rebuild because it
// exists. Listed, it reaches the handlers, which answer 409 naming the problem.
func rtMailListDomains(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	domains, err := queryAll[rtMailMailDomain](r.Context(), st.DB,
		"SELECT md.id, md.domain, md.dkim_selector, md.dkim_public_key, md.catch_all, "+
			"md.enabled, md.created_at FROM mail_domains md WHERE ("+
			"EXISTS (SELECT 1 FROM users u WHERE u.id = $2 AND u.role = 'admin') "+
			"AND (md.server_id = $1 OR md.server_id IS NULL)) "+
			"OR (EXISTS ("+
			"SELECT 1 FROM sites s WHERE s.server_id = md.server_id "+
			"AND lower(s.domain) = md.domain AND s.user_id = $2) "+
			"AND NOT EXISTS ("+
			"SELECT 1 FROM sites s2 WHERE s2.server_id = md.server_id "+
			"AND lower(s2.domain) = md.domain AND s2.user_id <> $2)) "+
			"ORDER BY md.domain LIMIT 500",
		serverID, c.Sub)
	if err != nil {
		return internalError("list domains", err)
	}
	writeJSON(w, http.StatusOK, domains)
	return nil
}

func rtMailIsDuplicate(err error) bool { return strings.Contains(err.Error(), "duplicate") }

// POST /api/mail/domains
func rtMailCreateDomain(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, serverID, agent, err := rtMailAdminScope(st, r)
	if err != nil {
		return err
	}
	var body rtMailCreateDomainRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	domain := strings.ToLower(strings.TrimSpace(body.Domain))
	if !isValidDomain(domain) {
		return apiErr(http.StatusBadRequest, "Invalid domain name")
	}

	// Generate DKIM keys via agent
	var privateKey, publicKey *string
	if resp, err := agent.Post(ctx, "/mail/dkim/generate", map[string]any{"domain": domain, "selector": "dockpanel"}); err != nil {
		slog.Warn(fmt.Sprintf("DKIM generation failed for %s: %v", domain, err))
	} else {
		if s, ok := jsonStr(jsonGet(resp, "private_key")); ok {
			privateKey = &s
		}
		if s, ok := jsonStr(jsonGet(resp, "public_key")); ok {
			publicKey = &s
		}
	}

	// Encrypt the DKIM private key before storing
	var encryptedPrivateKey *string
	if privateKey != nil {
		enc, err := SecretsCryptoEncryptCredential(*privateKey, st.Config.JWTSecret)
		if err != nil {
			return apiErr(http.StatusInternalServerError, "Encryption failed: "+err.Error())
		}
		encryptedPrivateKey = &enc
	}

	// ⚠ server_id is written HERE and nowhere else, and this is the only
	// handler in the module where the caller's selection is the right
	// authority: creation is the moment the operator CHOOSES a host. Every
	// sibling handler derives it from the row. (The column was never bound
	// before, so every mail domain created since the multi-server migration
	// was stored naming no server at all, and the per-server unique index could
	// not reject a duplicate.)
	mailDomain, err := queryOne[rtMailMailDomain](ctx, st.DB,
		"INSERT INTO mail_domains (domain, dkim_private_key, dkim_public_key, server_id) "+
			"VALUES ($1, $2, $3, $4) RETURNING id, domain, dkim_selector, dkim_public_key, catch_all, enabled, created_at",
		domain, encryptedPrivateKey, publicKey, serverID)
	if err != nil {
		if rtMailIsDuplicate(err) {
			return apiErr(http.StatusConflict, "Domain already exists")
		}
		return internalError("create domain", err)
	}

	// Configure Postfix/Dovecot via agent
	_, _ = agent.Post(ctx, "/mail/domains/configure", map[string]any{"domain": domain})

	// ── Auto-DNS: create MX, A, SPF, DMARC, DKIM records ─────────────────
	//
	// serverID travels with the domain into the background task. It is the
	// value just written onto the row, so the records describe the machine the
	// mailboxes were actually created on — not whichever box this process runs
	// on, which is what published a member's A record pointing at the panel.
	bg := context.WithoutCancel(ctx)
	db, userID, userEmail := st.DB, c.Sub, c.Email
	go func() {
		if err := rtMailAutoCreateMailDns(bg, db, agent, userID, userEmail, domain, serverID, publicKey); err != nil {
			slog.Warn(fmt.Sprintf("Auto-DNS for mail domain %s failed: %v", domain, err))
		}
	}()

	// ── Say who this just handed the mailboxes to ────────────────────────
	//
	// The claim system is DIRECTIONAL and only one direction was guarded.
	// Since #106 derives mailbox control from site ownership, this INSERT is an
	// entitlement-granting write: whoever owns the same-named site on this
	// server now holds every mailbox and every password hash on it. That is the
	// intended flow — it is how an operator gives a customer their mail — so
	// this must NOT refuse. What was missing is that the grant was SILENT; it is
	// now named in the activity record and in the log.
	grantee, gerr := queryScalarOpt[string](ctx, st.DB,
		"SELECT u.email FROM sites s JOIN users u ON u.id = s.user_id "+
			"WHERE s.server_id = $1 AND lower(s.domain) = $2 AND u.role <> 'admin' LIMIT 1",
		serverID, domain)
	if gerr != nil {
		grantee = nil
	}
	if grantee != nil {
		slog.Info(fmt.Sprintf("Mail domain %s created over a site owned by %s — that account now "+
			"manages its mailboxes (GitHub #106)", domain, *grantee))
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "mail.domain.create", new("mail"), &domain, grantee, ip, c.KeyID)
	rtMailAudit(r, st, c, "mail.domain.create", new("mail"), &domain, grantee, ip)

	writeJSON(w, http.StatusCreated, mailDomain)
	return nil
}

// PUT /api/mail/domains/{id}
func rtMailUpdateDomain(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtMailUpdateDomainRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	// WHICH DOMAIN and WHICH HOST both come from the row. Resolving before any
	// write means an un-scoped or unreachable host is refused with nothing
	// half-applied behind it.
	domain, serverID, agent, err := rtMailMailDomainAgentForCaller(ctx, st, id, c)
	if err != nil {
		return err
	}

	if body.CatchAll != nil {
		catchAll := *body.CatchAll
		if catchAll != "" && !rtMailIsWellformedAddress(catchAll, "/") {
			return apiErr(http.StatusBadRequest, "Invalid catch-all email address")
		}
		var v *string
		if catchAll != "" {
			v = &catchAll
		}
		if _, err := execSQL(ctx, st.DB, "UPDATE mail_domains SET catch_all = $1, updated_at = NOW() WHERE id = $2", v, id); err != nil {
			return internalError("update domain", err)
		}
	}
	if body.Enabled != nil {
		if _, err := execSQL(ctx, st.DB, "UPDATE mail_domains SET enabled = $1, updated_at = NOW() WHERE id = $2", *body.Enabled, id); err != nil {
			return internalError("update domain", err)
		}
	}

	// Push the catch_all/enabled change into Postfix/Dovecot — previously
	// written to the DB only, so it had no effect until an unrelated change.
	if err := rtMailSyncMailConfig(ctx, st.DB, serverID, agent); err != nil {
		return err
	}

	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "mail.domain.update", new("mail"), &domain, nil, nil, c.KeyID)
	return rtMailOK(w)
}

// DELETE /api/mail/domains/{id}
func rtMailDeleteDomain(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// Resolved before the row is gone, because the row is the only thing that
	// knows which host to strip the domain from.
	domain, serverID, agent, err := rtMailMailDomainAgentForCaller(ctx, st, id, c)
	if err != nil {
		return err
	}

	// Fetch DKIM selector before deletion (needed for DNS cleanup)
	dkimSelector := "dockpanel"
	if sel, err := queryScalarOpt[string](ctx, st.DB, "SELECT dkim_selector FROM mail_domains WHERE id = $1", id); err == nil && sel != nil {
		dkimSelector = *sel
	}

	// Remove from Postfix/Dovecot via agent
	_, _ = agent.Post(ctx, "/mail/domains/remove", map[string]any{"domain": domain})

	if _, err := execSQL(ctx, st.DB, "DELETE FROM mail_domains WHERE id = $1", id); err != nil {
		return internalError("delete domain", err)
	}

	// Rebuild the maps from the remaining rows so the deleted domain's
	// mailboxes stop authenticating and receiving immediately — the agent's
	// /mail/domains/remove only drops the DKIM key and defers map cleanup to
	// this sync. serverID was captured above: the row no longer exists.
	if err := rtMailSyncMailConfig(ctx, st.DB, serverID, agent); err != nil {
		return err
	}

	// ── Auto-DNS cleanup: delete MX, A, SPF, DMARC, DKIM records ─────────
	bg := context.WithoutCancel(ctx)
	db, userID := st.DB, c.Sub
	go func() {
		if err := rtMailAutoDeleteMailDns(bg, db, userID, domain, dkimSelector); err != nil {
			slog.Warn(fmt.Sprintf("Auto-DNS cleanup for mail domain %s failed: %v", domain, err))
		}
	}()

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "mail.domain.delete", new("mail"), &domain, nil, ip, c.KeyID)
	rtMailAudit(r, st, c, "mail.domain.delete", new("mail"), &domain, nil, ip)
	return rtMailOK(w)
}

// GET /api/mail/domains/{id}/dns — Required DNS records for email
func rtMailDomainDns(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// The same read the two DNS-verification endpoints use, so the tab that
	// tells you what to create and the checks that tell you whether you created
	// it can never describe two different domains — and it asks whether this
	// caller may see the domain at all.
	domain, selector, dkimPub, serverID, err := rtMailMailDomainIdentity(ctx, st.DB, id, c)
	if err != nil {
		return err
	}

	// The MAIL DOMAIN'S HOST's public address — not this process's, and not the
	// agent's hostname. A nil here is not a write, so it does not have to
	// refuse — but it must not substitute this box either, because an operator
	// following the instruction would create the wrong record by hand. Fall
	// back to a placeholder that names no machine at all.
	serverIP := "your-server-ip"
	if ip := publicIPForServer(ctx, st.DB, serverID); ip != nil && *ip != "" {
		serverIP = *ip
	}

	records := []any{}
	for _, rec := range PrerequisitesMailRecords(domain, selector, dkimPub, serverIP) {
		desc := ""
		if rec.Purpose != nil {
			desc = *rec.Purpose
		}
		records = append(records, map[string]any{
			"type":        rec.RecordType,
			"name":        rec.Fqdn,
			"content":     rec.Value,
			"description": desc,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "records": records})
	return nil
}

// ── Account routes ──────────────────────────────────────────────────────

// GET /api/mail/domains/{id}/accounts
//
// The mailboxes are listed only after the DOMAIN has been resolved through the
// caller predicate. mail_accounts has no server column and no owner column —
// it reaches both only through domain_id — so the domain is the only place
// this question can be asked. Resolving first rather than joining is
// deliberate: a joined query would answer an unauthorised caller with an empty
// list ("this domain has no mailboxes") — the failure that looks like success.
func rtMailListAccounts(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	domainID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if _, _, _, _, err := rtMailMailDomainIdentity(r.Context(), st.DB, domainID, c); err != nil {
		return err
	}
	accounts, err := queryAll[rtMailMailAccount](r.Context(), st.DB,
		"SELECT id, domain_id, email, display_name, quota_mb, enabled, forward_to, "+
			"autoresponder_enabled, autoresponder_subject, autoresponder_body, created_at "+
			"FROM mail_accounts WHERE domain_id = $1 ORDER BY email", domainID)
	if err != nil {
		return internalError("list accounts", err)
	}
	writeJSON(w, http.StatusOK, accounts)
	return nil
}

// POST /api/mail/domains/{id}/accounts
func rtMailCreateAccount(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	domainID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtMailCreateAccountRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	// The domain's own row decides both whether this caller may add a mailbox
	// to it and which host the mailbox is created on.
	domain, serverID, agent, err := rtMailMailDomainAgentForCaller(ctx, st, domainID, c)
	if err != nil {
		return err
	}

	email := strings.ToLower(strings.TrimSpace(body.Email))
	if !strings.HasSuffix(email, "@"+domain) {
		return apiErr(http.StatusBadRequest, "Email must end with @"+domain)
	}
	if !rtMailIsWellformedAddress(email, "") {
		return apiErr(http.StatusBadRequest, "Email address contains invalid characters")
	}
	if len(body.Password) < 8 {
		return apiErr(http.StatusBadRequest, "Password must be at least 8 characters")
	}

	// Hash in a scheme THIS server's Dovecot can verify — Argon2id where it is
	// built in, bcrypt where it is not. "THIS server" means the domain's host:
	// asking the switcher's agent could read Argon2id support off a Debian box
	// and write the credential to a Rocky one that cannot verify it.
	schemes := rtMailAgentPasswordSchemes(ctx, agent)
	passwordHash, err := rtMailDovecotPasswordHashFor(body.Password, schemes)
	if err != nil {
		return internalError("hash mail password", err)
	}

	// Clamp quota to a sane range (1 MB .. 1 TB): 0/negative would write a
	// garbage rule into the Dovecot userdb; an unbounded value removes the quota.
	quota := int32(1024)
	if body.QuotaMB != nil {
		quota = *body.QuotaMB
	}
	quota = min(max(quota, 1), 1_048_576)

	account, err := queryOne[rtMailMailAccount](ctx, st.DB,
		"INSERT INTO mail_accounts (domain_id, email, password_hash, display_name, quota_mb) "+
			"VALUES ($1, $2, $3, $4, $5) "+
			"RETURNING id, domain_id, email, display_name, quota_mb, enabled, forward_to, "+
			"autoresponder_enabled, autoresponder_subject, autoresponder_body, created_at",
		domainID, email, passwordHash, body.DisplayName, quota)
	if err != nil {
		if rtMailIsDuplicate(err) {
			return apiErr(http.StatusConflict, "Email account already exists")
		}
		return internalError("create account", err)
	}

	// Sync with Postfix/Dovecot via agent
	if err := rtMailSyncMailConfig(ctx, st.DB, serverID, agent); err != nil {
		return err
	}

	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "mail.account.create", new("mail"), &email, nil, nil, c.KeyID)

	writeJSON(w, http.StatusCreated, account)
	return nil
}

// rtMailPairPath reads Path<(Uuid, Uuid)>: {id} plus the second segment.
func rtMailPairPath(r *http.Request, second string) (uuid.UUID, uuid.UUID, error) {
	a, err := pathUUID(r, "id")
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	b, err := pathUUID(r, second)
	return a, b, err
}

// PUT /api/mail/domains/{domain_id}/accounts/{id}
func rtMailUpdateAccount(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	domainID, accountID, err := rtMailPairPath(r, "account_id")
	if err != nil {
		return err
	}
	var body rtMailUpdateAccountRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	// The mailbox reaches its host through the domain that owns it. This is the
	// sharpest of the account handlers: it can REPLACE a password hash.
	email, serverID, agent, err := rtMailMailAccountAgentForCaller(ctx, st, domainID, accountID, c)
	if err != nil {
		return err
	}

	set := func(col string, v any) error {
		if _, err := execSQL(ctx, st.DB, "UPDATE mail_accounts SET "+col+" = $1, updated_at = NOW() WHERE id = $2", v, accountID); err != nil {
			return internalError("update account", err)
		}
		return nil
	}

	if body.Password != nil {
		if len(*body.Password) < 8 {
			return apiErr(http.StatusBadRequest, "Password must be at least 8 characters")
		}
		// Same scheme selection as creation — a password CHANGE that reverts to
		// Argon2id on a box that cannot verify it locks the user out of a
		// mailbox that was working (#92b: count the call sites).
		schemes := rtMailAgentPasswordSchemes(ctx, agent)
		hash, err := rtMailDovecotPasswordHashFor(*body.Password, schemes)
		if err != nil {
			return internalError("hash mail password", err)
		}
		if err := set("password_hash", hash); err != nil {
			return err
		}
	}
	if body.DisplayName != nil {
		if err := set("display_name", *body.DisplayName); err != nil {
			return err
		}
	}
	if body.QuotaMB != nil {
		// Clamp to a sane range (1 MB .. 1 TB) — 0/negative writes a broken Dovecot quota rule.
		if err := set("quota_mb", min(max(*body.QuotaMB, 1), 1_048_576)); err != nil {
			return err
		}
	}
	if body.Enabled != nil {
		if err := set("enabled", *body.Enabled); err != nil {
			return err
		}
	}
	if body.ForwardTo != nil {
		forward := *body.ForwardTo
		if forward != "" && !rtMailIsWellformedAddress(forward, "") {
			return apiErr(http.StatusBadRequest, "Invalid forwarding email address")
		}
		var v *string
		if forward != "" {
			v = &forward
		}
		if err := set("forward_to", v); err != nil {
			return err
		}
	}
	if body.AutoresponderEnabled != nil {
		if err := set("autoresponder_enabled", *body.AutoresponderEnabled); err != nil {
			return err
		}
	}
	if body.AutoresponderSubject != nil {
		if err := set("autoresponder_subject", *body.AutoresponderSubject); err != nil {
			return err
		}
	}
	if body.AutoresponderBody != nil {
		if err := set("autoresponder_body", *body.AutoresponderBody); err != nil {
			return err
		}
	}

	if err := rtMailSyncMailConfig(ctx, st.DB, serverID, agent); err != nil {
		return err
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "mail.account.update", new("mail"), &email, nil, ip, c.KeyID)
	rtMailAudit(r, st, c, "mail.account.update", new("mail"), &email, nil, ip)
	return rtMailOK(w)
}

// DELETE /api/mail/domains/{domain_id}/accounts/{id}
func rtMailDeleteAccount(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	domainID, accountID, err := rtMailPairPath(r, "account_id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// Resolved before the DELETE, so the host is taken from the row while the
	// row still exists — and so a mailbox on a machine this administrator does
	// not operate is refused rather than removed.
	email, serverID, agent, err := rtMailMailAccountAgentForCaller(ctx, st, domainID, accountID, c)
	if err != nil {
		return err
	}
	if _, err := execSQL(ctx, st.DB, "DELETE FROM mail_accounts WHERE id = $1", accountID); err != nil {
		return internalError("delete account", err)
	}
	if err := rtMailSyncMailConfig(ctx, st.DB, serverID, agent); err != nil {
		return err
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "mail.account.delete", new("mail"), &email, nil, ip, c.KeyID)
	rtMailAudit(r, st, c, "mail.account.delete", new("mail"), &email, nil, ip)
	return rtMailOK(w)
}

// ── Alias routes ────────────────────────────────────────────────────────

// GET /api/mail/domains/{id}/aliases
//
// Same reasoning as rtMailListAccounts: resolve the domain first so an
// invisible domain 404s, then list. An alias row exposes a forwarding
// destination, which is a real mailbox address.
func rtMailListAliases(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	domainID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if _, _, _, _, err := rtMailMailDomainIdentity(r.Context(), st.DB, domainID, c); err != nil {
		return err
	}
	aliases, err := queryAll[rtMailMailAlias](r.Context(), st.DB,
		"SELECT id, domain_id, source_email, destination_email, created_at "+
			"FROM mail_aliases WHERE domain_id = $1 ORDER BY source_email", domainID)
	if err != nil {
		return internalError("list aliases", err)
	}
	writeJSON(w, http.StatusOK, aliases)
	return nil
}

// POST /api/mail/domains/{id}/aliases
func rtMailCreateAlias(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	domainID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtMailCreateAliasRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	// This handler previously read no row at all — it INSERTed straight against
	// the {id} path segment and let the foreign key decide whether the domain
	// existed. Resolving the domain answers both who may write and which host.
	domain, serverID, agent, err := rtMailMailDomainAgentForCaller(ctx, st, domainID, c)
	if err != nil {
		return err
	}

	source := strings.ToLower(strings.TrimSpace(body.SourceEmail))
	destination := strings.ToLower(strings.TrimSpace(body.DestinationEmail))

	// The alias source must belong to the domain it is being filed under.
	// Postfix applies an alias to any address it accepts, so an alias filed
	// under a domain the caller may write to could otherwise redirect mail
	// addressed to a DIFFERENT domain on the same host, to any destination.
	// Rejected at the door: the agent's sync is all-or-nothing.
	if !strings.HasSuffix(source, "@"+domain) {
		return apiErr(http.StatusBadRequest, "Alias source must end with @"+domain)
	}
	if !rtMailIsWellformedAddress(source, "") {
		return apiErr(http.StatusBadRequest, "Alias source contains invalid characters")
	}
	// Destination may be a comma-separated list of targets (matches the agent's
	// alias validation) — so every ELEMENT is checked.
	if !rtMailIsWellformedAddressList(destination, "") {
		return apiErr(http.StatusBadRequest, "Alias destination contains invalid characters")
	}

	alias, err := queryOne[rtMailMailAlias](ctx, st.DB,
		"INSERT INTO mail_aliases (domain_id, source_email, destination_email) "+
			"VALUES ($1, $2, $3) RETURNING *",
		domainID, source, destination)
	if err != nil {
		if rtMailIsDuplicate(err) {
			return apiErr(http.StatusConflict, "Alias already exists")
		}
		return internalError("create alias", err)
	}

	if err := rtMailSyncMailConfig(ctx, st.DB, serverID, agent); err != nil {
		return err
	}

	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "mail.alias.create", new("mail"), &alias.SourceEmail, &alias.DestinationEmail, nil, c.KeyID)

	writeJSON(w, http.StatusCreated, alias)
	return nil
}

// DELETE /api/mail/domains/{domain_id}/aliases/{id}
func rtMailDeleteAlias(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	domainID, aliasID, err := rtMailPairPath(r, "alias_id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// Scoping the alias to the {domain_id} path segment is carried by the
	// shared resolver's md.id = $1 term over the join.
	source, serverID, agent, err := rtMailMailAliasAgentForCaller(ctx, st, domainID, aliasID, c)
	if err != nil {
		return err
	}
	if _, err := execSQL(ctx, st.DB, "DELETE FROM mail_aliases WHERE id = $1 AND domain_id = $2", aliasID, domainID); err != nil {
		return internalError("delete alias", err)
	}
	if err := rtMailSyncMailConfig(ctx, st.DB, serverID, agent); err != nil {
		return err
	}
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "mail.alias.delete", new("mail"), &source, nil, nil, c.KeyID)
	return rtMailOK(w)
}

// ── Mail queue ──────────────────────────────────────────────────────────

// GET /api/mail/queue
func rtMailGetQueue(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, err := rtMailAdminScope(st, r)
	if err != nil {
		return err
	}
	// Return empty queue if mail server isn't installed (avoids 502 spam on dashboard)
	res, err := agent.Get(r.Context(), "/mail/queue")
	if err != nil {
		res = map[string]any{"queue": []any{}, "count": 0}
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// POST /api/mail/queue/flush
func rtMailFlushQueue(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, res, err := rtMailAgentPostBody(st, r, "/mail/queue/flush", "Flush mail queue", false)
	if err != nil {
		return err
	}
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "mail.queue.flush", new("mail"), nil, nil, nil, c.KeyID)
	writeJSON(w, http.StatusOK, res)
	return nil
}

// DELETE /api/mail/queue/{id}
func rtMailDeleteQueued(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, _, agent, err := rtMailAdminScope(st, r)
	if err != nil {
		return err
	}
	queueID := r.PathValue("queue_id")
	res, err := agent.Post(r.Context(), "/mail/queue/delete", map[string]any{"id": queueID})
	if err != nil {
		return agentError("Delete queued message", err)
	}
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "mail.queue.delete", new("mail"), &queueID, nil, nil, c.KeyID)
	writeJSON(w, http.StatusOK, res)
	return nil
}

// ── Auto-DNS helpers for mail domains ───────────────────────────────────

// rtMailExtractParentDomain extracts the parent/root domain from a subdomain:
// "mail.example.com" → "example.com", "example.com" → "example.com".
func rtMailExtractParentDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

// A local detect_public_ip() used to sit here. It is gone rather than
// re-signatured: its only effect was to make a call site read "the server's
// IP" when the function underneath answers "THIS PROCESS's IP", and that
// ambiguity is precisely the defect — so the callers spell publicIPForServer
// in full, and the server it is asking about is visible in the argument.

// rtMailMailCertBlocker is what occupies the certificate file, in the words the
// operator is shown.
type rtMailMailCertBlocker int

const (
	// rtMailMailCertBlockerWildcard: a DockPanel-issued DNS-01 certificate that
	// also covers subdomains.
	rtMailMailCertBlockerWildcard rtMailMailCertBlocker = iota + 1
	// rtMailMailCertBlockerForeign: a certificate DockPanel did not issue
	// (uploaded, commercial, Origin CA).
	rtMailMailCertBlockerForeign
)

// rtMailMailCertVerdict decides whether issuing a mail-host certificate would
// destroy names: refuse=false is Issue, refuse=true is Refuse(blocker).
//
// A mail host genuinely needs a certificate, and the agent route that issues
// one writes fullchain.pem unconditionally. That path is not the mail host's
// private property: a site of the same name reads it, and so does a DNS-01
// **wildcard**, which rt_ssl stores under the ZONE APEX — the very name a mail
// domain is normally created at. Issuing a single-name HTTP-01 certificate
// over that file replaces one covering *.example.com with one covering
// example.com alone, and every sibling vhost reading that file starts serving
// a certificate that does not cover it.
//
// ⚠ Two inputs, and neither is redundant. foreignIssuer cannot see the case
// that leads the harm: foreignCertIssuer collapses *ours* and *we could not
// tell* into one nil, so an LE-issued wildcard answers nil. The columns cannot
// see the other case: an uploaded commercial or Origin-CA certificate carries
// no ssl_wildcard and no ssl_challenge of ours.
//
// Issue deliberately includes the ordinary shape the mail entitlement is
// built on — a site and its mailboxes sharing one name, holding a single-name
// certificate that a re-issue merely refreshes.
func rtMailMailCertVerdict(sslEnabled bool, sslWildcard *bool, sslChallenge, foreignIssuer *string) (rtMailMailCertBlocker, bool) {
	// A site not serving TLS has no certificate here to lose. The issuer probe
	// is not consulted in this state on purpose: a stale file left behind by a
	// revoked certificate is not something the operator is still serving.
	if !sslEnabled {
		return 0, false
	}
	if (sslWildcard != nil && *sslWildcard) || (sslChallenge != nil && *sslChallenge == "dns-01") {
		return rtMailMailCertBlockerWildcard, true
	}
	if foreignIssuer != nil {
		return rtMailMailCertBlockerForeign, true
	}
	return 0, false
}

// rtMailSleep is tokio::time::sleep that still ends on cancellation.
func rtMailSleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// rtMailProvisionMailHostCert issues the mail host's certificate, unless doing
// so would destroy one.
//
// Both auto-DNS providers reached this through byte-identical blocks. They are
// one function now: a guard applied to one leg and not the other is the
// sibling-call drift this project has shipped three times.
func rtMailProvisionMailHostCert(ctx context.Context, db *pgxpool.Pool, agent AgentHandle, userID uuid.UUID, userEmail, domain string, serverID uuid.UUID) {
	// Wait briefly for DNS propagation before attempting ACME HTTP-01
	rtMailSleep(ctx, 5*time.Second)

	site, err := queryOpt[Tup5[uuid.UUID, uuid.UUID, bool, *bool, *string]](ctx, db,
		"SELECT id, user_id, ssl_enabled, ssl_wildcard, ssl_challenge "+
			"FROM sites WHERE lower(domain) = lower($1) AND server_id = $2", domain, serverID)
	if err != nil {
		site = nil
	}

	// ⛔ ASKED FOR EVERY MAIL HOST, not only for one that owns a site row — and
	// that placement is the whole repair. The issuer question used to live
	// INSIDE the site branch, so it asked nothing at all for a domain with no
	// sites row — exactly the population (Compose stacks, Docker apps) with no
	// other protection here. Still skipped when the ROW already settles it: a
	// wildcard or a DNS-01 site is decided from its columns alone, and this is
	// a round trip to the box.
	settledByRow := false
	if site != nil {
		settledByRow = !(site.C && !(site.D != nil && *site.D) && !(site.E != nil && *site.E == "dns-01"))
	}
	var foreign *string
	if !settledByRow {
		foreign = foreignCertIssuer(ctx, agent, domain)
	}

	if site != nil {
		if blocker, refuse := rtMailMailCertVerdict(site.C, site.D, site.E, foreign); refuse {
			rtMailAnnounceMailCertConflict(ctx, db, domain, &site.A, site.B, serverID, blocker)
			return
		}
	} else if foreign != nil {
		// No sites row exists for this domain (a Compose stack or Docker app
		// claimed it). The caller's own userID (the admin who configured mail
		// for this domain) stands in as the alert's owner — a real id from the
		// call chain, not an invented one.
		rtMailAnnounceMailCertConflict(ctx, db, domain, nil, userID, serverID, rtMailMailCertBlockerForeign)
		return
	}

	if _, err := agent.Post(ctx, "/ssl/provision/"+domain, map[string]any{"email": userEmail, "runtime": "static"}); err != nil {
		slog.Warn(fmt.Sprintf("Auto-SSL (mail): failed for %s: %v — provision manually", domain, err))
		return
	}
	slog.Info("Auto-SSL (mail): provisioned certificate for " + domain)
	// ⛔ The agent does not patch a vhost for a certificate — it re-renders the
	// whole file from what we just sent, which is runtime "static" with no
	// root, no limits and no hardening. Right for a mail host, a catastrophe
	// for a WEBSITE of the same name (measured at s398: a PHP site re-rendered
	// static, 403 on every PHP request, limit_req_zone gone). So put the site's
	// real configuration back afterwards, exactly as the SSL doors do.
	rtSslRebuildVhostForDomain(ctx, db, agent, domain, serverID)
}

// rtMailAnnounceMailCertConflict tells the operator a certificate was
// deliberately NOT issued. Silence here would be the worst outcome: the mail
// host simply has no certificate, which looks exactly like an ACME failure.
func rtMailAnnounceMailCertConflict(ctx context.Context, db *pgxpool.Pool, domain string, siteID *uuid.UUID, siteOwner, serverID uuid.UUID, blocker rtMailMailCertBlocker) {
	var because string
	if blocker == rtMailMailCertBlockerWildcard {
		because = fmt.Sprintf("the site %s holds a DNS-01 certificate that also covers its "+
			"subdomains. Issuing a single-name certificate for the mail host "+
			"would replace it, and every subdomain reading the same file would "+
			"start serving a certificate that does not cover it", domain)
	} else {
		because = fmt.Sprintf("the certificate installed for %s was not issued by DockPanel. "+
			"Issuing over it would destroy a certificate somebody installed "+
			"deliberately", domain)
	}
	slog.Warn(fmt.Sprintf("Auto-SSL (mail): declined to provision for %s — %s", domain, because))

	// No sites row for a Compose stack or Docker app domain, so there is no
	// SSL tab to send the operator to.
	remedy := "If the mail host needs one of its own, replace the certificate deliberately at its " +
		"source (the Compose stack or template that manages it) — DockPanel will not do it " +
		"automatically."
	if siteID != nil {
		remedy = "If the mail host needs one of its own, issue it deliberately from the site's SSL tab, " +
			"where the consequences are shown before anything is replaced."
	}

	NotificationsFireAlertDeduped(ctx, db, siteOwner, &serverID, siteID,
		"ssl_renewal_failure", NotificationsSslRenewalKeyMailHostConflict, "warning",
		"Mail certificate not issued: "+domain,
		fmt.Sprintf("DockPanel did not issue a certificate for the mail host %s, because "+
			"%s. Mail for this domain will use the certificate already installed. "+
			"%s", domain, because, remedy),
		12)
}

type rtMailZoneRow = Tup4[string, *string, *string, *string]

// rtMailPdnsSettings reads pdns_api_url / pdns_api_key (decrypted from env).
func rtMailPdnsSettings(ctx context.Context, db *pgxpool.Pool) (string, string, bool) {
	rows, _ := queryAll[Tup2[string, string]](ctx, db,
		"SELECT key, value FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key')")
	var u, k *string
	for i := range rows {
		switch rows[i].A {
		case "pdns_api_url":
			if u == nil {
				u = &rows[i].B
			}
		case "pdns_api_key":
			if k == nil {
				k = &rows[i].B
			}
		}
	}
	if u == nil || k == nil {
		return "", "", false
	}
	return *u, SecretsCryptoDecryptCredentialFromEnv(*k), true
}

// rtMailAutoCreateMailDns auto-creates DNS records (MX, A, SPF, DMARC, DKIM)
// for a new mail domain. Runs in a background task — errors are logged, not
// returned to the user.
//
// serverID is the host the domain was created on. It is what the A record and
// the SPF ip4: term resolve to; without it this published the PANEL's address
// for a domain on a fleet member — a record that resolves, answers, and points
// mail at a machine that never sees it.
func rtMailAutoCreateMailDns(ctx context.Context, db *pgxpool.Pool, agent AgentHandle, userID uuid.UUID, userEmail, domain string, serverID uuid.UUID, dkimPublicKey *string) error {
	parent := rtMailExtractParentDomain(domain)

	// Look up DNS zone for the parent domain
	zone, err := queryOpt[rtMailZoneRow](ctx, db,
		"SELECT provider, cf_zone_id, cf_api_token, cf_api_email FROM dns_zones WHERE domain = $1 AND user_id = $2",
		parent, userID)
	if err != nil {
		return err
	}
	if zone == nil {
		slog.Info(fmt.Sprintf("No DNS zone found for %s — skipping auto-DNS for mail domain %s", parent, domain))
		return nil
	}

	// A WRITE, so a host we cannot resolve stops it. Every record below is
	// derived from this one value; substituting this process's address would
	// publish a record that resolves and answers on the wrong machine, which
	// is strictly worse than no records at all. The whole set is refused, not
	// just the two records that carry the address: a partial publish would
	// leave a domain advertising a mail host that resolves to nothing.
	ip := publicIPForServer(ctx, db, &serverID)
	if ip == nil || *ip == "" {
		return fmt.Errorf("no public address is recorded for server %s (it may not have checked "+
			"in yet), so NO DNS records were published for %s — create them by hand "+
			"from the domain's DNS tab once the server reports an address", serverID, domain)
	}
	serverIP := *ip

	// THE record set — the same one the DNS tab shows and the prerequisite
	// check verifies. (It used to be spelled inline here and again in the DNS
	// tab, and the two had drifted into two different mail topologies.)
	records := PrerequisitesMailRecords(domain, PrerequisitesDefaultDkimSelector, dkimPublicKey, serverIP)

	switch zone.A {
	case "cloudflare":
		if zone.B == nil || zone.C == nil {
			return errors.New("Cloudflare zone missing zone_id or token")
		}
		headers := cfHeaders(*zone.C, zone.D)
		cfURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", *zone.B)

		for _, rec := range records {
			// MX priority is a separate field in the Cloudflare API, not part of
			// the content string.
			content := rec.Value
			var priority *uint16
			if rec.RecordType == "MX" {
				first, rest, found := strings.Cut(rec.Value, " ")
				pri := uint16(10)
				if n, err := strconv.ParseUint(first, 10, 16); err == nil {
					pri = uint16(n)
				}
				priority = &pri
				if found {
					content = rest
				}
			}
			body := map[string]any{
				"type":    rec.RecordType,
				"name":    rec.Fqdn,
				"content": content,
				"ttl":     1,
				// Every mail record must be DNS-only: SMTP cannot traverse the
				// Cloudflare proxy, so an orange-clouded mail host is unreachable.
				"proxied": false,
			}
			if priority != nil {
				body["priority"] = *priority
			}
			_, _, _ = rtCdnSend(ctx, "POST", cfURL, headers, body, 0)
			slog.Info(fmt.Sprintf("Auto-DNS (mail): created %s record %s for %s", rec.RecordType, rec.Fqdn, domain))
		}

		// ── Auto-SSL: provision certificate for the mail domain ───────────
		rtMailProvisionMailHostCert(ctx, db, agent, userID, userEmail, domain, serverID)
	case "powerdns":
		pdnsURL, key, ok := rtMailPdnsSettings(ctx, db)
		if !ok {
			return errors.New("PowerDNS not configured")
		}
		zoneFqdn := rtDnsFqdn(parent)

		// Same record set as the Cloudflare branch, in PowerDNS's rrset shape:
		// names are fully qualified with a trailing dot, MX priority stays inside
		// the content string, and TXT values must arrive quoted.
		rrsets := make([]any, 0, len(records))
		for _, rec := range records {
			content := rec.Value
			switch rec.RecordType {
			case "TXT":
				content = `"` + rec.Value + `"`
			case "MX":
				// "10 mail.example.com" → "10 mail.example.com."
				if i := strings.LastIndex(rec.Value, " "); i >= 0 {
					content = rec.Value[:i] + " " + rec.Value[i+1:] + "."
				}
			}
			rrsets = append(rrsets, map[string]any{
				"name": rec.Fqdn + ".", "type": rec.RecordType, "ttl": 300, "changetype": "REPLACE",
				"records": []any{map[string]any{"content": content, "disabled": false}},
			})
		}

		h := http.Header{}
		h.Set("X-API-Key", key)
		resp, text, err := rtCdnSend(ctx, "PATCH", rtDnsPdnsZoneURL(pdnsURL, zoneFqdn), h, map[string]any{"rrsets": rrsets}, 0)
		switch {
		case resp == nil:
			return fmt.Errorf("PowerDNS API error: %v", err)
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			slog.Info("Auto-DNS (mail/PowerDNS): created all records for " + domain)
		default:
			return fmt.Errorf("PowerDNS error: %s", text)
		}

		// ── Auto-SSL for PowerDNS ────────────────────────────────────────
		rtMailProvisionMailHostCert(ctx, db, agent, userID, userEmail, domain, serverID)
	}
	return nil
}

// rtMailAutoDeleteMailDns auto-deletes all DNS records for a removed mail
// domain. Runs in a background task — errors are logged, not returned.
func rtMailAutoDeleteMailDns(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, domain, dkimSelector string) error {
	parent := rtMailExtractParentDomain(domain)

	zone, err := queryOpt[rtMailZoneRow](ctx, db,
		"SELECT provider, cf_zone_id, cf_api_token, cf_api_email FROM dns_zones WHERE domain = $1 AND user_id = $2",
		parent, userID)
	if err != nil {
		return err
	}
	if zone == nil {
		slog.Info(fmt.Sprintf("No DNS zone found for %s — skipping DNS cleanup for mail domain %s", parent, domain))
		return nil
	}

	switch zone.A {
	case "cloudflare":
		if zone.B == nil || zone.C == nil {
			return errors.New("Cloudflare zone missing zone_id or token")
		}
		zoneID := *zone.B
		headers := cfHeaders(*zone.C, zone.D)

		// Collect all record names we need to clean up. These mirror exactly
		// what rtMailAutoCreateMailDns publishes (apex A + MX + SPF, _dmarc,
		// DKIM) — keep the two lists in step, or removing a domain leaves
		// records behind.
		names := []string{domain, "_dmarc." + domain, dkimSelector + "._domainkey." + domain}
		for _, name := range names {
			// Query all record types for this name (A, MX, TXT, CNAME, etc.)
			listURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s&per_page=50", zoneID, name)
			resp, raw, err := rtCdnSend(ctx, "GET", listURL, headers, nil, 0)
			if resp == nil || err != nil {
				continue
			}
			data, err := agentDecodeJSON(raw)
			if err != nil {
				continue
			}
			recs, _ := jsonArr(jsonGet(data, "result"))
			for _, rec := range recs {
				rid, ok := jsonStr(jsonGet(rec, "id"))
				if !ok {
					continue
				}
				_, _, _ = rtCdnSend(ctx, "DELETE", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, rid), headers, nil, 0)
				rtype := rtSslStrOr(jsonGet(rec, "type"), "?")
				slog.Info(fmt.Sprintf("Auto-DNS cleanup (mail): deleted %s record for %s", rtype, name))
			}
		}
	case "powerdns":
		if pdnsURL, key, ok := rtMailPdnsSettings(ctx, db); ok {
			zoneFqdn := rtDnsFqdn(parent)
			domainFqdn := domain + "."
			dmarcFqdn := "_dmarc." + domain + "."
			dkimFqdn := dkimSelector + "._domainkey." + domain + "."
			rrsets := map[string]any{"rrsets": []any{
				map[string]any{"name": domainFqdn, "type": "A", "changetype": "DELETE"},
				map[string]any{"name": domainFqdn, "type": "MX", "changetype": "DELETE"},
				map[string]any{"name": domainFqdn, "type": "TXT", "changetype": "DELETE"},
				map[string]any{"name": dmarcFqdn, "type": "TXT", "changetype": "DELETE"},
				map[string]any{"name": dkimFqdn, "type": "TXT", "changetype": "DELETE"},
			}}
			h := http.Header{}
			h.Set("X-API-Key", key)
			_, _, _ = rtCdnSend(ctx, "PATCH", rtDnsPdnsZoneURL(pdnsURL, zoneFqdn), h, rrsets, 0)
			slog.Info("Auto-DNS cleanup (mail/PowerDNS): deleted all records for " + domain)
		}
	}
	return nil
}

// ── Rspamd spam filter ───────────────────────────────────────────────────

// POST /api/mail/rspamd/install
func rtMailRspamdInstall(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, _, agent, err := rtMailAdminScope(st, r)
	if err != nil {
		return err
	}
	if _, err := agent.PostLong(r.Context(), "/mail/rspamd/install", nil, 900); err != nil {
		return agentError("Rspamd", err)
	}
	rtMailLog(r, st, c, "mail.rspamd_install", nil)
	return rtMailOK(w)
}

// GET /api/mail/rspamd/status
func rtMailRspamdStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtMailAgentGet(st, w, r, "/mail/rspamd/status", "Rspamd")
}

// POST /api/mail/rspamd/toggle
func rtMailRspamdToggle(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, _, err := rtMailAgentPostBody(st, r, "/mail/rspamd/toggle", "Rspamd", true); err != nil {
		return err
	}
	return rtMailOK(w)
}

// ── Webmail (Roundcube) ─────────────────────────────────────────────────

// POST /api/mail/webmail/install
func rtMailWebmailInstall(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, _, agent, err := rtMailAdminScope(st, r)
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	res, err := agent.PostLong(r.Context(), "/mail/webmail/install", body, 900)
	if err != nil {
		return agentError("Webmail", err)
	}
	rtMailLog(r, st, c, "mail.webmail_install", nil)
	writeJSON(w, http.StatusOK, res)
	return nil
}

// GET /api/mail/webmail/status
func rtMailWebmailStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtMailAgentGet(st, w, r, "/mail/webmail/status", "Webmail")
}

// POST /api/mail/webmail/remove
func rtMailWebmailRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, _, err := rtMailAgentPostBody(st, r, "/mail/webmail/remove", "Webmail", false)
	if err != nil {
		return err
	}
	rtMailLog(r, st, c, "mail.webmail_remove", nil)
	return rtMailOK(w)
}

// ── SMTP Relay ──────────────────────────────────────────────────────────

// POST /api/mail/relay/configure
func rtMailRelayConfigure(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, _, err := rtMailAgentPostBody(st, r, "/mail/relay/configure", "SMTP relay", true)
	if err != nil {
		return err
	}
	ip := clientIP(r)
	rtMailLog(r, st, c, "mail.relay_configure", ip)
	rtMailAudit(r, st, c, "mail.relay_configure", nil, nil, nil, ip)
	return rtMailOK(w)
}

// GET /api/mail/relay/status
func rtMailRelayStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtMailAgentGet(st, w, r, "/mail/relay/status", "SMTP relay")
}

// POST /api/mail/relay/remove
func rtMailRelayRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, _, err := rtMailAgentPostBody(st, r, "/mail/relay/remove", "SMTP relay", false)
	if err != nil {
		return err
	}
	rtMailLog(r, st, c, "mail.relay_remove", nil)
	return rtMailOK(w)
}

// ── DNS Verification ─────────────────────────────────────────────────────

// rtMailMailDomainIdentity loads a mail domain's identity for the read paths,
// and decides in the same query whether this caller may see it.
//
// Two questions, one row, because they have the same answer source: the
// identity half (name, DKIM selector, public key) is what the DNS tab and the
// two verification endpoints describe; the authorisation half is
// rtMailMailDomainCallerPredicate, the same predicate every mutating handler
// resolves through.
//
// It also returns the domain's HOST — a pointer, because the predicate admits a
// row that names no server, and a read must not turn that into a 404 for a
// domain that plainly exists. Unlike rtMailMailDomainAgentForCaller this
// resolves NO agent, and that is the point: a read must not fail because the
// host is unreachable.
func rtMailMailDomainIdentity(ctx context.Context, db Querier, id uuid.UUID, c *Claims) (string, string, *string, *uuid.UUID, error) {
	row, err := queryOpt[Tup4[string, *string, *string, *uuid.UUID]](ctx, db,
		"SELECT md.domain, md.dkim_selector, md.dkim_public_key, md.server_id "+
			"FROM mail_domains md WHERE "+rtMailMailDomainCallerPredicate, id, c.Sub)
	if err != nil {
		return "", "", nil, nil, internalError("mail domain", err)
	}
	if row == nil {
		return "", "", nil, nil, apiErr(http.StatusNotFound, "Domain not found")
	}
	selector := PrerequisitesDefaultDkimSelector
	if row.B != nil {
		selector = *row.B
	}
	return row.A, selector, row.C, row.D, nil
}

// rtMailServerIPOrEmpty is `public_ip_for_server(..).await.unwrap_or_default()`.
func rtMailServerIPOrEmpty(ctx context.Context, db *pgxpool.Pool, serverID *uuid.UUID) string {
	if ip := publicIPForServer(ctx, db, serverID); ip != nil {
		return *ip
	}
	return ""
}

// GET /api/mail/domains/{id}/dns-check — Verify DNS records are propagated.
//
// This endpoint predates the prerequisite layer and checked only that records
// of the right *kind* existed: MX passed on any MX at all (including a Google
// Workspace one), SPF on any v=spf1 string (including one that forbids this
// server), DKIM on contains("p=") without comparing our key, and the A record
// was not checked at all. It now delegates to the prerequisite checker, which
// compares against the records we actually publish, while keeping this
// response shape so the existing Mail DNS tab keeps working.
func rtMailDnsCheck(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	domain, selector, dkimPub, serverID, err := rtMailMailDomainIdentity(ctx, st.DB, id, c)
	if err != nil {
		return err
	}

	// Compare against the address of the machine this domain's mail RUNS ON,
	// not the panel's. An unresolvable host degrades to "" ON PURPOSE: the
	// checker treats that as "we could not determine the expected address" and
	// the projection below renders `unknown` — an honest "we can't tell"
	// instead of a confident, wrong "misconfigured".
	serverIP := rtMailServerIPOrEmpty(ctx, st.DB, serverID)

	verdict := PrerequisitesCheckMailDnsPublished(ctx, domain, selector, dkimPub, serverIP)

	// Project the structured verdict onto the legacy per-record shape.
	var records []PrerequisitesDnsRecordHint
	if verdict.Remediation != nil && verdict.Remediation.Kind == PrerequisitesRemediationDnsRecords {
		records = verdict.Remediation.Records
	} else {
		// Satisfied (or undeterminable) results carry no remediation; re-derive
		// the set so the tab always lists every record rather than going blank.
		records = PrerequisitesMailRecords(domain, selector, dkimPub, serverIP)
	}
	allSatisfied := verdict.State == PrerequisitesPrereqStateSatisfied

	checks := make([]any, 0, len(records))
	pass := 0
	for _, rec := range records {
		// `present` is nil only when the lookup itself couldn't run — report
		// that as unknown, never as a failure.
		var status string
		switch {
		case rec.Present != nil && *rec.Present:
			status = "pass"
		case rec.Present != nil:
			status = "fail"
		case allSatisfied:
			status = "pass"
		default:
			status = "unknown"
		}
		if status == "pass" {
			pass++
		}
		desc := ""
		if rec.Purpose != nil {
			desc = *rec.Purpose
		}
		checks = append(checks, map[string]any{
			"type":        rtMailLabelFor(rec),
			"status":      status,
			"host":        rec.Fqdn,
			"value":       rec.Value,
			"description": desc,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"domain":     domain,
		"checks":     checks,
		"pass_count": pass,
		"total":      len(checks),
		"all_pass":   pass == len(checks),
		// The structured verdict, for surfaces that render the guidance layer
		// properly rather than the legacy pass/fail list.
		"prereq": verdict,
	})
	return nil
}

// rtMailLabelFor is the short name the DNS tab shows for a record — "SPF"
// reads better than "TXT".
func rtMailLabelFor(r PrerequisitesDnsRecordHint) string {
	switch {
	case strings.HasPrefix(r.Value, "v=spf1"):
		return "SPF"
	case strings.HasPrefix(r.Value, "v=DMARC1"):
		return "DMARC"
	case strings.HasPrefix(r.Value, "v=DKIM1"):
		return "DKIM"
	case r.RecordType == "MX":
		return "MX"
	}
	return "A"
}

// GET /api/mail/domains/{id}/preflight — The mail domain's prerequisites.
//
// Same host, same nil handling and same reasoning as rtMailDnsCheck — this is
// the structured face of the identical evaluation.
func rtMailPreflight(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	domain, selector, dkimPub, serverID, err := rtMailMailDomainIdentity(ctx, st.DB, id, c)
	if err != nil {
		return err
	}
	serverIP := rtMailServerIPOrEmpty(ctx, st.DB, serverID)
	checks := PrerequisitesMailEvaluate(ctx, domain, selector, dkimPub, serverIP)
	writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "checks": checks})
	return nil
}

// ── Mail Logs & Storage (agent proxies) ──────────────────────────────────

// GET /api/mail/logs — Parse mail.log for recent activity and stats.
func rtMailMailLogs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtMailAgentGet(st, w, r, "/mail/logs", "Mail logs")
}

// GET /api/mail/storage — Get storage usage for all mailboxes.
func rtMailMailStorage(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtMailAgentGet(st, w, r, "/mail/storage", "Mail storage")
}

// ── Blacklist / Reputation Check ────────────────────────────────────────

var rtMailBlacklists = [][2]string{
	{"zen.spamhaus.org", "Spamhaus"},
	{"bl.spamcop.net", "SpamCop"},
	{"b.barracudacentral.org", "Barracuda"},
	{"dnsbl.sorbs.net", "SORBS"},
	{"spam.dnsbl.sorbs.net", "SORBS Spam"},
	{"cbl.abuseat.org", "CBL"},
	{"dnsbl-1.uceprotect.net", "UCEPROTECT L1"},
	{"psbl.surriel.com", "PSBL"},
}

// rtMailDnsblAnswer classifies a DNSxL lookup's addresses: 1 = the zone
// answered with a listing, 0 = the zone answered "not listed", -1 = the zone
// refused us (RFC 5782's 127.255.255.0/24 refusal range).
func rtMailDnsblAnswer(addrs []net.IP) int {
	listing, refusal := false, false
	for _, a := range addrs {
		v4 := a.To4()
		if v4 == nil || v4[0] != 127 {
			continue
		}
		if v4[1] == 255 && v4[2] == 255 {
			refusal = true
		} else {
			listing = true
		}
	}
	switch {
	case listing:
		return 1
	case refusal:
		return -1
	}
	return 0
}

// rtMailDnsblAsk resolves host; a failed lookup is "not listed" (NXDOMAIN),
// which only the control below licenses reading as such.
func rtMailDnsblAsk(ctx context.Context, host string) int {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return 0
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return rtMailDnsblAnswer(ips)
}

// GET /api/mail/blacklist-check — Check a server's IP against email blacklists.
//
// Reputation belongs to the ADDRESS THAT SENDS THE MAIL, so this asks about
// the server in scope — not about the process answering the request. On a
// fleet member those never match, and the widget used to report this box's
// listings under a member's mail page: a genuinely blacklisted member read as
// clean, the direction that costs deliverability silently. serverScope
// supplies the host and, with it, the ownership check.
func rtMailBlacklistCheck(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, serverID, _, err := rtMailAdminScope(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	// No address, no check. A DNSBL answer about a DIFFERENT machine is not a
	// weaker answer, it is an answer to a question nobody asked.
	ipp := publicIPForServer(ctx, st.DB, &serverID)
	if ipp == nil || *ipp == "" {
		return apiErr(http.StatusConflict, "No public address is recorded for this server yet, so its blacklist status "+
			"cannot be checked. It is reported by the agent at check-in.")
	}
	ip := *ipp

	// Reverse the IP for DNSBL lookup
	parts := strings.Split(ip, ".")
	slices.Reverse(parts)
	reversed := strings.Join(parts, ".")

	// A DNSxL says "listed" with an A record and "not listed" with NXDOMAIN, so
	// a bare "did it resolve" scored every resolver outage, timeout and retired
	// zone as a clean bill of health — and scored a refusal (127.255.255.0/24,
	// which is an A record) as a LISTING. So: read the ANSWER, and probe each
	// zone with the RFC 5782 §5 test address, which every DNSxL must list. When
	// that control does not come back as a listing, this zone told us nothing
	// about this IP, whatever the subject lookup returned.
	results := make([]map[string]any, len(rtMailBlacklists))
	var wg sync.WaitGroup
	for i, bl := range rtMailBlacklists {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The control and the subject go out together: the pair is one
			// measurement.
			var subject, control int
			var inner sync.WaitGroup
			inner.Add(2)
			go func() { defer inner.Done(); subject = rtMailDnsblAsk(ctx, reversed+"."+bl[0]) }()
			go func() { defer inner.Done(); control = rtMailDnsblAsk(ctx, "2.0.0.127."+bl[0]) }()
			inner.Wait()

			// A confirmed listing needs no control: it is positive evidence about
			// THIS address. The control only licenses reading NXDOMAIN as "not
			// listed" rather than as "nobody answered".
			var checked bool
			var listed any
			switch {
			case subject == 1:
				checked, listed = true, true
			case subject == 0 && control == 1:
				checked, listed = true, false
			}
			results[i] = map[string]any{"rbl": bl[0], "name": bl[1], "checked": checked, "listed": listed}
		}()
	}
	wg.Wait()

	listedCount, checkedCount := 0, 0
	for _, res := range results {
		if res["listed"] == true {
			listedCount++
		}
		if res["checked"] == true {
			checkedCount++
		}
	}

	// A single confirmed listing is real evidence and outranks any number of
	// zones we could not reach. "clean" is reserved for the case where every
	// zone was actually asked — anything less is `unknown`.
	status := "unknown"
	if listedCount > 0 {
		status = "listed"
	} else if checkedCount == len(results) {
		status = "clean"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ip":            ip,
		"results":       results,
		"listed_count":  listedCount,
		"checked_count": checkedCount,
		"total_count":   len(results),
		"status":        status,
		// Kept for wire compatibility, and now it means what it says: a clean
		// of false no longer implies a listing.
		"clean": status == "clean",
	})
	return nil
}

// ── Rate Limiting ───────────────────────────────────────────────────────

// POST /api/mail/rate-limit/set
func rtMailRateLimitSet(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, _, err := rtMailAgentPostBody(st, r, "/mail/rate-limit/set", "Rate limit", true)
	if err != nil {
		return err
	}
	rtMailLog(r, st, c, "mail.rate_limit_set", nil)
	return rtMailOK(w)
}

// GET /api/mail/rate-limit/status
func rtMailRateLimitStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtMailAgentGet(st, w, r, "/mail/rate-limit/status", "Rate limit")
}

// POST /api/mail/rate-limit/remove
func rtMailRateLimitRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, _, err := rtMailAgentPostBody(st, r, "/mail/rate-limit/remove", "Rate limit", false)
	if err != nil {
		return err
	}
	rtMailLog(r, st, c, "mail.rate_limit_remove", nil)
	return rtMailOK(w)
}

// ── Mailbox Backup/Restore ──────────────────────────────────────────────

// POST /api/mail/backup
func rtMailMailboxBackup(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, res, err := rtMailAgentPostBody(st, r, "/mail/backup", "Mailbox backup", true)
	if err != nil {
		return err
	}
	rtMailLog(r, st, c, "mail.backup", nil)
	writeJSON(w, http.StatusOK, res)
	return nil
}

// POST /api/mail/restore
func rtMailMailboxRestore(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, res, err := rtMailAgentPostBody(st, r, "/mail/restore", "Mailbox restore", true)
	if err != nil {
		return err
	}
	rtMailLog(r, st, c, "mail.restore", nil)
	writeJSON(w, http.StatusOK, res)
	return nil
}

// GET /api/mail/backups
func rtMailMailboxBackups(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtMailAgentGet(st, w, r, "/mail/backups", "Mailbox backups")
}

// POST /api/mail/backups/delete
func rtMailMailboxBackupDelete(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, _, err := rtMailAgentPostBody(st, r, "/mail/backups/delete", "Delete backup", true)
	if err != nil {
		return err
	}
	ip := clientIP(r)
	rtMailLog(r, st, c, "mail.backup_delete", ip)
	rtMailAudit(r, st, c, "mail.backup_delete", nil, nil, nil, ip)
	return rtMailOK(w)
}

// ── TLS Enforcement ─────────────────────────────────────────────────────

// GET /api/mail/tls/status
func rtMailTlsStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtMailAgentGet(st, w, r, "/mail/tls/status", "TLS status")
}

// POST /api/mail/tls/enforce
func rtMailTlsEnforce(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, _, err := rtMailAgentPostBody(st, r, "/mail/tls/enforce", "TLS enforce", true)
	if err != nil {
		return err
	}
	ip := clientIP(r)
	rtMailLog(r, st, c, "mail.tls_enforce", ip)
	rtMailAudit(r, st, c, "mail.tls_enforce", nil, nil, nil, ip)
	return rtMailOK(w)
}

// ── Helpers ─────────────────────────────────────────────────────────────

// rtMailMailDomainCallerPredicate is the one predicate that decides whether a
// caller may act on a mail domain.
//
// Binds $1 = the mail domain id, $2 = the caller's own id — the same two
// parameters, in the same order, as SiteCallerPredicate, so a query that joins
// another table onto mail_domains can add its own bind as $3.
//
// TWO ways to satisfy it: administer the machine the row names (is_local, or a
// member this same administrator registered), or own the site of the same name
// on that machine. Before this, each mail handler loaded its row with a bare
// `WHERE id = $1` and the only boundary was the X-Server-Id header check.
//
// ⚠ A row naming NO server is admitted DELIBERATELY, INSIDE the administrator
// arm: admitting it hands the row to agentForSiteServer, which refuses it by
// name with a 409, and rtMailSyncMailConfig's precondition tells the operator
// to backfill. Excluding it would collapse both into a 404 for a domain that
// plainly exists.
//
// ⚠ The role is read from users.role in the DATABASE, not from the token: a
// JWT keeps asserting whatever role it was minted with until it expires.
//
// ── The site-owner arm (GitHub #106) ── The server term is the whole
// boundary: sites and mail_domains are unique on (domain, server_id), not on
// domain. lower(s.domain) compares, and the NOT EXISTS clause is why that is
// safe — no OTHER account may own a case-variant of the name on that server:
// one owner, or nobody, failing CLOSED on legacy mixed-case data. A
// normalising migration was considered and REJECTED (it would raise duplicate
// keys on exactly the installs with the problem). Site ownership alone
// authorises; what a non-administrator may not do is CREATE the pairing.
const rtMailMailDomainCallerPredicate = "md.id = $1 AND (EXISTS (" +
	"SELECT 1 FROM users u WHERE u.id = $2 AND u.role = 'admin' AND (" +
	"md.server_id IS NULL OR EXISTS (" +
	"SELECT 1 FROM servers sv WHERE sv.id = md.server_id " +
	"AND (sv.is_local OR sv.user_id = u.id)))) " +
	"OR (EXISTS (" +
	"SELECT 1 FROM sites s WHERE s.server_id = md.server_id " +
	"AND lower(s.domain) = md.domain AND s.user_id = $2) " +
	"AND NOT EXISTS (" +
	"SELECT 1 FROM sites s2 WHERE s2.server_id = md.server_id " +
	"AND lower(s2.domain) = md.domain AND s2.user_id <> $2)))"

// rtMailResolveHost turns a row's (name, server) into its agent: a host that
// will not resolve is REFUSED rather than quietly replaced with this one.
func rtMailResolveHost(ctx context.Context, st *AppState, serverID *uuid.UUID, domain string) (uuid.UUID, AgentHandle, error) {
	agent, err := agentForSiteServer(ctx, st, serverID, domain)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if serverID == nil {
		// Unreachable today — agentForSiteServer refuses a nil server id.
		// Written as a branch so that if that refusal is ever softened, this
		// becomes a 409 instead of a panic.
		return uuid.Nil, nil, apiErr(http.StatusConflict, "This mail domain is not associated with a server")
	}
	return *serverID, agent, nil
}

// rtMailMailDomainAgentForCaller resolves a mail domain the caller may act
// on, AND the agent for the host it is actually configured on. "Which server
// did the browser have selected" and "which server is this mail domain on"
// are different questions; the row is the authority.
func rtMailMailDomainAgentForCaller(ctx context.Context, st *AppState, domainID uuid.UUID, c *Claims) (string, uuid.UUID, AgentHandle, error) {
	row, err := queryOpt[Tup2[string, *uuid.UUID]](ctx, st.DB,
		"SELECT md.domain, md.server_id FROM mail_domains md WHERE "+rtMailMailDomainCallerPredicate, domainID, c.Sub)
	if err != nil {
		return "", uuid.Nil, nil, internalError("resolve mail domain for caller", err)
	}
	if row == nil {
		return "", uuid.Nil, nil, apiErr(http.StatusNotFound, "Domain not found")
	}
	sid, agent, err := rtMailResolveHost(ctx, st, row.B, row.A)
	return row.A, sid, agent, err
}

// rtMailMailAccountAgentForCaller resolves a mailbox the caller may act on,
// and the host of the domain it belongs to. Keeping md.id = $1 against the
// {domain_id} path segment preserves the pairing check: a mismatched (domain,
// account) pair resolves to nothing and 404s.
func rtMailMailAccountAgentForCaller(ctx context.Context, st *AppState, domainID, accountID uuid.UUID, c *Claims) (string, uuid.UUID, AgentHandle, error) {
	row, err := queryOpt[Tup3[string, string, *uuid.UUID]](ctx, st.DB,
		"SELECT a.email, md.domain, md.server_id FROM mail_accounts a "+
			"JOIN mail_domains md ON md.id = a.domain_id "+
			"WHERE a.id = $3 AND "+rtMailMailDomainCallerPredicate, domainID, c.Sub, accountID)
	if err != nil {
		return "", uuid.Nil, nil, internalError("resolve mail account for caller", err)
	}
	if row == nil {
		return "", uuid.Nil, nil, apiErr(http.StatusNotFound, "Account not found")
	}
	sid, agent, err := rtMailResolveHost(ctx, st, row.C, row.B)
	return row.A, sid, agent, err
}

// rtMailMailAliasAgentForCaller: same shape and reasoning as the account
// resolver, against mail_aliases.
func rtMailMailAliasAgentForCaller(ctx context.Context, st *AppState, domainID, aliasID uuid.UUID, c *Claims) (string, uuid.UUID, AgentHandle, error) {
	row, err := queryOpt[Tup3[string, string, *uuid.UUID]](ctx, st.DB,
		"SELECT al.source_email, md.domain, md.server_id FROM mail_aliases al "+
			"JOIN mail_domains md ON md.id = al.domain_id "+
			"WHERE al.id = $3 AND "+rtMailMailDomainCallerPredicate, domainID, c.Sub, aliasID)
	if err != nil {
		return "", uuid.Nil, nil, internalError("resolve mail alias for caller", err)
	}
	if row == nil {
		return "", uuid.Nil, nil, apiErr(http.StatusNotFound, "Alias not found")
	}
	sid, agent, err := rtMailResolveHost(ctx, st, row.C, row.B)
	return row.A, sid, agent, err
}

// rtMailMailSyncPayload collects the mail configuration THAT ONE SERVER
// hosts, in the shape /mail/sync consumes. mail_accounts and mail_aliases have
// no server column, so they reach one through mail_domains.server_id.
func rtMailMailSyncPayload(ctx context.Context, db Querier, serverID uuid.UUID) (map[string]any, error) {
	domains, err := queryAll[Tup3[string, bool, *string]](ctx, db,
		"SELECT domain, enabled, catch_all FROM mail_domains WHERE server_id = $1 ORDER BY domain", serverID)
	if err != nil {
		return nil, err
	}
	accounts, err := queryAll[Tup5[string, string, int32, bool, *string]](ctx, db,
		"SELECT a.email, a.password_hash, a.quota_mb, a.enabled, a.forward_to "+
			"FROM mail_accounts a JOIN mail_domains md ON md.id = a.domain_id "+
			"WHERE md.server_id = $1 ORDER BY a.email", serverID)
	if err != nil {
		return nil, err
	}
	aliases, err := queryAll[Tup2[string, string]](ctx, db,
		"SELECT al.source_email, al.destination_email "+
			"FROM mail_aliases al JOIN mail_domains md ON md.id = al.domain_id "+
			"WHERE md.server_id = $1 ORDER BY al.source_email", serverID)
	if err != nil {
		return nil, err
	}
	d := make([]any, 0, len(domains))
	for _, x := range domains {
		d = append(d, map[string]any{"domain": x.A, "enabled": x.B, "catch_all": x.C})
	}
	a := make([]any, 0, len(accounts))
	for _, x := range accounts {
		a = append(a, map[string]any{"email": x.A, "password_hash": x.B, "quota_mb": x.C, "enabled": x.D, "forward_to": x.E})
	}
	al := make([]any, 0, len(aliases))
	for _, x := range aliases {
		al = append(al, map[string]any{"source": x.A, "destination": x.B})
	}
	return map[string]any{"domains": d, "accounts": a, "aliases": al}, nil
}

// rtMailSyncMailConfig rebuilds ONE server's Postfix/Dovecot maps from the
// rows that name that server.
//
// It used to read every mail row in the installation and send it to the
// caller's X-Server-Id host: every mailbox's password_hash in the panel
// written into one host's maps, and an edit made with member B selected
// published member A's tenants' credentials onto B. The server id now comes
// from the row being edited, and the rows from that same server.
//
// Why an un-scoped domain stops the whole rebuild: /mail/sync REBUILDS the
// maps, it does not merge. A filtered payload that omits an un-scoped domain
// living on the target box would DELETE its mailboxes, and a NULL server_id is
// the absence of evidence, not evidence of the local box. So the rebuild
// refuses while any such row exists — a precondition on the DATA, fatal where
// an unreachable agent is not.
func rtMailSyncMailConfig(ctx context.Context, db Querier, serverID uuid.UUID, agent AgentHandle) error {
	unscoped, err := queryScalar[int64](ctx, db, "SELECT COUNT(*) FROM mail_domains WHERE server_id IS NULL")
	if err != nil {
		return internalError("count unscoped mail domains", err)
	}
	if unscoped > 0 {
		slog.Error(fmt.Sprintf("Refusing to rebuild mail maps on server %s: %d mail domain(s) "+
			"name no server. A rebuild that omits them would delete their mailboxes from "+
			"whichever box actually hosts them, and nothing here can tell which box that is. "+
			"Backfill mail_domains.server_id.", serverID, unscoped))
		return apiErr(http.StatusConflict, fmt.Sprintf(
			"%d mail domain(s) are not assigned to a server, so mail configuration "+
				"cannot be applied to any server without risking the removal of live mailboxes. "+
				"The change was saved. Assign every mail domain to a server, then retry.", unscoped))
	}

	// Everything past the precondition stays best-effort: a transient database
	// blip or an agent that is down must not turn a saved change into a 500.
	payload, err := rtMailMailSyncPayload(ctx, db, serverID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Mail sync for server %s: gathering configuration failed: %v", serverID, err))
		return nil
	}
	if _, err := agent.Post(ctx, "/mail/sync", payload); err != nil {
		slog.Warn(fmt.Sprintf("Mail sync for server %s: agent rejected the rebuild: %v", serverID, err))
	}
	return nil
}

// rtMailIsValidMailAddress accepts only the address character set the agent's
// sync accepts (ASCII alphanumeric plus @ . _ - +, and any char in
// extraAllowed). Anything outside it makes the agent reject the ENTIRE sync
// batch — and because callers discard the sync result, one bad row would
// silently freeze all future Postfix/Dovecot updates. (s236 audit.)
func rtMailIsValidMailAddress(addr, extraAllowed string) bool {
	if addr == "" || len(addr) > 255 {
		return false
	}
	for _, c := range addr {
		if !(isASCIIAlnum(c) || strings.ContainsRune("@._-+", c) || strings.ContainsRune(extraAllowed, c)) {
			return false
		}
	}
	return true
}

// rtMailIsWellformedAddress is rtMailIsValidMailAddress plus the structure
// the address must actually have.
//
// The character-set check tests the WHOLE STRING for non-emptiness, not the
// local part, and that gap was the root of two measured defects:
//   - "@example.com" passes, and keys the same virtual_mailbox_maps entry as
//     the domain's catch-all; postmap keeps the first (accounts are) and the
//     agent discards the warning, so creating that mailbox silently VOIDS an
//     administrator-only setting.
//   - "..@example.com" passes, and the maildir resolves to /var/vmail, one
//     level ABOVE the domain directory; chown -R then walks the whole tree on
//     every sync.
//
// The rule is deliberately narrow — non-empty local part, non-empty domain,
// exactly one @, and a local part that is not made only of dots — so it
// cannot reject a mailbox an install already has.
func rtMailIsWellformedAddress(addr, extraAllowed string) bool {
	if !rtMailIsValidMailAddress(addr, extraAllowed) || strings.Count(addr, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(addr, "@")
	// "." and ".." are directory entries, not mailboxes; "" is a map key.
	return local != "" && domain != "" && strings.Trim(local, ".") != ""
}

// rtMailIsWellformedAddressList: every element of a comma-separated
// destination list must be a real address. Checking the string as a whole let
// a bare local name ride along beside a valid address into virtual_alias_maps.
func rtMailIsWellformedAddressList(list, extraAllowed string) bool {
	if strings.TrimSpace(list) == "" {
		return false
	}
	for _, e := range strings.Split(list, ",") {
		if !rtMailIsWellformedAddress(strings.TrimSpace(e), extraAllowed) {
			return false
		}
	}
	return true
}

// rtMailDovecotPasswordHash hashes a mailbox password for Dovecot using
// Argon2id, in Dovecot's {ARGON2ID} scheme form — the same Argon2id KDF the
// panel uses for its own user accounts.
//
// The previous implementation emitted an unsalted-round SHA512 hex digest
// labelled {SHA512-CRYPT}: neither a real crypt(3) SHA-512 hash — so every
// mailbox login failed — nor an adequate KDF (confirmed live with
// `doveadm pw -t`, s236).
func rtMailDovecotPasswordHash(password string) (string, error) {
	phc, err := hashPassword(password)
	if err != nil {
		return "", err
	}
	return "{ARGON2ID}" + phc, nil
}

// rtMailDovecotPasswordHashFor hashes a mailbox password in a scheme the
// TARGET BOX's Dovecot can verify.
//
// Argon2 is a BUILD OPTION, not a version: Rocky 9.8 ships Dovecot 2.3.16
// compiled without libsodium, so every login fails with `Unknown scheme
// ARGON2ID` while the panel reports the account created (s268). So the scheme
// is chosen from what the agent reports: ARGON2ID when available (unchanged on
// Debian/Ubuntu), BLF-CRYPT (bcrypt) otherwise. An empty `supported` means the
// agent could not tell — keep the strong default; hashing is not the place to
// guess a downgrade.
func rtMailDovecotPasswordHashFor(password string, supported []string) (string, error) {
	knows := func(s string) bool {
		return slices.ContainsFunc(supported, func(x string) bool { return strings.EqualFold(x, s) })
	}
	if len(supported) == 0 || knows("ARGON2ID") {
		return rtMailDovecotPasswordHash(password)
	}
	return "{BLF-CRYPT}" + rtMailBcryptCrypt(password), nil
}

// rtMailBcryptCrypt is the bcrypt credential Dovecot's BLF-CRYPT scheme reads.
// Cost 10 matches Dovecot's own `doveadm pw -s BLF-CRYPT` default.
func rtMailBcryptCrypt(password string) string {
	h, err := bcryptHash(password, 10)
	if err != nil {
		return ""
	}
	return h
}

// rtMailAgentPasswordSchemes asks the agent which password schemes its Dovecot
// can verify. An unreachable agent returns an empty list, and
// rtMailDovecotPasswordHashFor keeps the strong default in that case.
func rtMailAgentPasswordSchemes(ctx context.Context, agent AgentHandle) []string {
	v, err := agent.Get(ctx, "/mail/status")
	if err != nil {
		return nil
	}
	arr, _ := jsonArr(jsonGet(v, "password_schemes"))
	out := []string{}
	for _, x := range arr {
		if s, ok := jsonStr(x); ok {
			out = append(out, rtMailASCIIUpper(s))
		}
	}
	return out
}

func rtMailASCIIUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
