package api

// Port of panel/backend/src/routes/sites.rs.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtSitesRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/sites", h(rtSitesList))
	r.Handle("POST /api/sites", h(rtSitesCreate))
	// Read-only, admin-only, and the ONLY site read that looks past user_id.
	// It is what makes POST /api/sites/{id}/transfer reversible.
	r.Handle("GET /api/admin/sites", h(rtSitesListForAdmin))
	r.Handle("GET /api/sites/{id}", h(rtSitesGetOne))
	r.Handle("DELETE /api/sites/{id}", h(rtSitesRemove))
	r.Handle("GET /api/sites/{id}/provision-log", h(rtSitesProvisionLog))
	r.Handle("PUT /api/sites/{id}/php", h(rtSitesSwitchPhp))
	r.Handle("PUT /api/sites/{id}/runtime", h(rtSitesSwitchRuntime))
	r.Handle("PUT /api/sites/{id}/limits", h(rtSitesUpdateLimits))
	r.Handle("GET /api/sites/{id}/bandwidth-usage", h(rtSitesBandwidthUsage))
	r.Handle("PUT /api/sites/{id}/domain", h(rtSitesRenameDomain))
	r.Handle("POST /api/sites/{id}/transfer", h(rtSitesTransfer))
	r.Handle("PUT /api/sites/{id}/toggle", h(rtSitesToggleEnabled))
	r.Handle("PUT /api/sites/{id}/fastcgi-cache", h(rtSitesToggleFastcgiCache))
	r.Handle("POST /api/sites/{id}/fastcgi-cache/purge", h(rtSitesPurgeFastcgiCache))
	r.Handle("PUT /api/sites/{id}/redis-cache", h(rtSitesToggleRedisCache))
	r.Handle("POST /api/sites/{id}/redis-cache/purge", h(rtSitesPurgeRedisCache))
	r.Handle("POST /api/sites/{id}/sftp/enable", h(rtSitesEnableSftp))
	r.Handle("POST /api/sites/{id}/sftp/disable", h(rtSitesDisableSftp))
	r.Handle("POST /api/sites/{id}/sftp/reset-password", h(rtSitesResetSftpPassword))
	r.Handle("PUT /api/sites/{id}/waf", h(rtSitesToggleWaf))
	r.Handle("GET /api/sites/{id}/waf/logs", h(rtSitesWafLogs))
	r.Handle("POST /api/sites/{id}/optimize-images", h(rtSitesOptimizeImages))
	r.Handle("PUT /api/sites/{id}/security-headers", h(rtSitesUpdateSecurityHeaders))
	r.Handle("PUT /api/sites/{id}/bot-protection", h(rtSitesToggleBotProtection))
	r.Handle("GET /api/php/versions", h(rtSitesPhpVersions))
	r.Handle("POST /api/php/install", h(rtSitesPhpInstall))
	r.Handle("POST /api/php/uninstall", h(rtSitesPhpUninstall))
	r.Handle("GET /api/sites/{id}/redirects", h(rtSitesListRedirects))
	r.Handle("POST /api/sites/{id}/redirects", h(rtSitesAddRedirect))
	r.Handle("POST /api/sites/{id}/redirects/remove", h(rtSitesRemoveRedirect))
	r.Handle("GET /api/sites/{id}/password-protect", h(rtSitesListProtected))
	r.Handle("POST /api/sites/{id}/password-protect", h(rtSitesAddPasswordProtect))
	r.Handle("POST /api/sites/{id}/password-protect/remove", h(rtSitesRemovePasswordProtect))
	r.Handle("GET /api/sites/{id}/aliases", h(rtSitesListAliases))
	r.Handle("POST /api/sites/{id}/aliases", h(rtSitesAddAlias))
	r.Handle("POST /api/sites/{id}/aliases/remove", h(rtSitesRemoveAlias))
	r.Handle("GET /api/sites/{id}/access-logs", h(rtSitesAccessLogs))
	r.Handle("GET /api/sites/{id}/stats", h(rtSitesSiteStats))
	r.Handle("GET /api/sites/{id}/php-errors", h(rtSitesPhpErrors))
	r.Handle("GET /api/sites/{id}/health", h(rtSitesHealthCheck))
	r.Handle("GET /api/sites/{id}/health-summary", h(rtSitesHealthSummary))
	r.Handle("POST /api/sites/{id}/clone", h(rtSitesCloneSite))
	r.Handle("POST /api/sites/{id}/ssl/upload", h(rtSitesUploadSsl))
	r.Handle("GET /api/sites/{id}/env", h(rtSitesGetEnvVars))
	r.Handle("PUT /api/sites/{id}/env", h(rtSitesSetEnvVars))
	r.Handle("GET /api/php/extensions/{version}", h(rtSitesPhpExtensions))
	r.Handle("POST /api/php/extensions/install", h(rtSitesInstallPhpExtension))
}

// rtSitesSiteForCallerAll is `SELECT s.*` over SiteCallerPredicate — the
// full-row read used by every per-site handler in this module.
const rtSitesSiteForCallerAll = "SELECT s.* FROM sites s WHERE " + SiteCallerPredicate

// rtSitesSiteRateLimit is the effective per-user site-creation ceiling per
// hour, shared by every handler that writes a `sites` row so they cannot
// drift. `security_site_rate_limit` holds the count; 0 means no limit; an
// absent row falls back to the seeded default of 3. (Crate-visible since the
// staging module became the third caller — it was private while two of the
// site-creating handlers lived here, which is precisely why the third was
// written with no ceiling at all.)
func rtSitesSiteRateLimit(ctx context.Context, db *pgxpool.Pool) int64 {
	n := SecurityHardeningGetSettingI64(ctx, db, "security_site_rate_limit", 3)
	if n <= 0 {
		return 1<<63 - 1
	}
	return n
}

// rtSitesReserveResellerSiteSlot atomically reserves one site slot against
// the owner's reseller quota; the conditional UPDATE … RETURNING closes the
// check-then-increment TOCTOU. true = a slot was reserved (release it on a
// later failure), false = no reseller (nothing to enforce), 403 = exhausted.
// Mirrors databases::reserve_reseller_db_slot.
func rtSitesReserveResellerSiteSlot(ctx context.Context, st *AppState, userID uuid.UUID) (bool, error) {
	reserved, err := queryScalarOpt[int32](ctx, st.DB,
		"UPDATE reseller_profiles SET used_sites = used_sites + 1, updated_at = NOW() "+
			"WHERE user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL) "+
			"AND (max_sites IS NULL OR used_sites < max_sites) "+
			"RETURNING 1", userID)
	if err != nil {
		return false, internalError("reserve reseller site quota", err)
	}
	if reserved != nil {
		return true, nil
	}
	has, err := queryScalarOpt[uuid.UUID](ctx, st.DB,
		"SELECT rp.user_id FROM reseller_profiles rp "+
			"WHERE rp.user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL)", userID)
	if err != nil {
		return false, internalError("reserve reseller site quota", err)
	}
	if has != nil {
		return false, apiErr(http.StatusForbidden, "Reseller site quota exceeded")
	}
	return false, nil
}

// rtSitesReleaseResellerSiteSlot releases a reserved slot (compensating
// decrement) on a later failure.
func rtSitesReleaseResellerSiteSlot(ctx context.Context, st *AppState, userID uuid.UUID) {
	_, _ = execSQL(ctx, st.DB,
		"UPDATE reseller_profiles SET used_sites = GREATEST(used_sites - 1, 0), updated_at = NOW() "+
			"WHERE user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL)", userID)
}

// rtSitesBackupCarryMinAgent is the agent release in which a domain rename
// began carrying the site's backup trees with it. Before it, the archives
// stayed on disk under the old name while the panel kept listing rows that no
// longer resolved to a file.
const rtSitesBackupCarryMinAgent = "2.142.0"

// rtSitesEmitStep emits a provisioning step to the log's history + channel.
func rtSitesEmitStep(st *AppState, siteID uuid.UUID, step, label, status string, message *string) {
	st.ProvisionLogs.Emit(siteID, ProvisionStep{Step: step, Label: label, Status: status, Message: message})
}

// rtSitesStoreSiteSecret stores a credential DockPanel generated on the
// user's behalf into the site's auto-created vault, encrypted with the same
// key the Secrets Manager decrypts with (so it is actually retrievable).
//
// Best-effort by design — provisioning must not fail because bookkeeping did —
// but every failure is logged at error level: the failure this exists to kill
// was a password generated, handed to wp-cli, and dropped on the floor beside
// an empty vault with nothing said anywhere.
func rtSitesStoreSiteSecret(ctx context.Context, db *pgxpool.Pool, jwtSecret string, vaultID uuid.UUID, key, value, description string) bool {
	encrypted, err := SecretsCryptoEncrypt(value, SecretsCryptoVaultKeyPrimary(jwtSecret))
	if err != nil {
		slog.Error(fmt.Sprintf("Auto-vault: could not encrypt '%s': %v", key, err))
		return false
	}
	if _, err := execSQL(ctx, db,
		"INSERT INTO secrets (vault_id, key, encrypted_value, description, secret_type, updated_by) "+
			"VALUES ($1, $2, $3, $4, 'password', 'dockpanel') "+
			"ON CONFLICT (vault_id, key) DO UPDATE SET "+
			"encrypted_value = EXCLUDED.encrypted_value, "+
			"description = EXCLUDED.description, "+
			"version = secrets.version + 1, "+
			"updated_at = NOW()",
		vaultID, key, encrypted, description); err != nil {
		slog.Error(fmt.Sprintf("Auto-vault: could not store '%s': %v", key, err))
		return false
	}
	return true
}

// rtSitesRandAlnum is rand::distr::Alphanumeric from a CSPRNG.
func rtSitesRandAlnum(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 0, n)
	buf := make([]byte, 1)
	for len(out) < n {
		_, _ = rand.Read(buf)
		if buf[0] < 248 { // 248 = 62*4: reject to stay unbiased
			out = append(out, alphabet[buf[0]%62])
		}
	}
	return string(out)
}

// rtSitesSleep sleeps d (the Rust tasks did not watch shutdown either; the
// process exit ends them).
func rtSitesSleep(d time.Duration) { time.Sleep(d) }

// rtSitesDecodeValue is Json<serde_json::Value>: any JSON, numbers kept exact.
func rtSitesDecodeValue(r *http.Request) (any, error) {
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return nil, err
	}
	return agentDecodeJSON(raw)
}

// rtSitesObj is `value["k"] = …` on a serde_json::Value: null becomes an
// object; any other non-object panicked in Rust (→ 500 here).
func rtSitesObj(v any, what string) (map[string]any, error) {
	if v == nil {
		return map[string]any{}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, internalError(what, "cannot index a non-object JSON value")
	}
	return m, nil
}

// rtSitesSiteByCaller reads the full row of a site the caller may act on.
func rtSitesSiteByCaller(ctx context.Context, st *AppState, id uuid.UUID, c *Claims, what, missing string) (*Site, error) {
	site, err := queryOpt[Site](ctx, st.DB, rtSitesSiteForCallerAll, id, c.Sub)
	if err != nil {
		return nil, internalError(what, err)
	}
	if site == nil {
		return nil, apiErr(http.StatusNotFound, missing)
	}
	return site, nil
}

// rtSitesSiteAndAgent is the full row plus the agent for the host it runs on.
func rtSitesSiteAndAgent(ctx context.Context, st *AppState, id uuid.UUID, c *Claims, what string) (*Site, AgentHandle, error) {
	site, err := rtSitesSiteByCaller(ctx, st, id, c, what, "Site not found")
	if err != nil {
		return nil, nil, err
	}
	agent, err := agentForSiteServer(ctx, st, site.ServerID, site.Domain)
	if err != nil {
		return nil, nil, err
	}
	return site, agent, nil
}

// rtSitesAuthID is the AuthUser + Path(id) prologue.
func rtSitesAuthID(st *AppState, r *http.Request) (*Claims, uuid.UUID, error) {
	c, err := st.authUser(r)
	if err != nil {
		return nil, uuid.Nil, err
	}
	id, err := pathUUID(r, "id")
	return c, id, err
}

type rtSitesListQuery struct {
	Limit  *int64 `json:"limit"`
	Offset *int64 `json:"offset"`
}

type rtSitesCreateSiteRequest struct {
	Domain     string  `json:"domain"`
	Runtime    *string `json:"runtime"`
	ProxyPort  *int32  `json:"proxy_port"`
	PHPVersion *string `json:"php_version"`
	PHPPreset  *string `json:"php_preset"`
	// Start command for node/python runtimes (e.g. "npm start").
	AppCommand *string `json:"app_command"`
	// One-click CMS install.
	CMS           *string `json:"cms"`
	SiteTitle     *string `json:"site_title"`
	AdminEmail    *string `json:"admin_email"`
	AdminUser     *string `json:"admin_user"`
	AdminPassword *string `json:"admin_password"`
}

// rtSitesList is GET /api/sites — the caller's sites on the server in scope.
//
// Scoped to the caller with no role branch — the single ownership axis the
// `client` role rests on. See rtSitesListForAdmin for the one read allowed to
// look past it.
func rtSitesList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var p rtSitesListQuery
	if err := decodeQuery(r, &p); err != nil {
		return err
	}
	limit, offset := paginate(p.Limit, p.Offset)
	sites, err := queryAll[Site](r.Context(), st.DB,
		"SELECT * FROM sites WHERE user_id = $1 AND server_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
		c.Sub, serverID, limit, offset)
	if err != nil {
		return internalError("list sites", err)
	}
	writeJSON(w, http.StatusOK, sites)
	return nil
}

// rtSitesAdminSiteRow is one site as an admin sees it on the all-sites view.
// Deliberately NOT Site: a struct that carried an owner would sooner or later
// be handed to a per-site handler that must keep asking "is this yours?". This
// projection holds only what the list renders.
type rtSitesAdminSiteRow struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	Domain       string     `json:"domain" db:"domain"`
	Runtime      string     `json:"runtime" db:"runtime"`
	Status       string     `json:"status" db:"status"`
	Enabled      bool       `json:"enabled" db:"enabled"`
	SSLEnabled   bool       `json:"ssl_enabled" db:"ssl_enabled"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	ParentSiteID *uuid.UUID `json:"parent_site_id" db:"parent_site_id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	OwnerEmail   *string    `json:"owner_email" db:"owner_email"`
	OwnerRole    *string    `json:"owner_role" db:"owner_role"`
}

// rtSitesListForAdmin is GET /api/admin/sites — every site on this server,
// with its owner. Admin only.
//
// This route exists because transfer was a one-way door: the moment an admin
// handed a site to a client, the row left their list, get_one answered 404,
// and the Transfer control (rendered only on the site's page) became
// unreachable (#51). It is a READ only; acting on such sites is decided by
// SiteCallerPredicate.
func rtSitesListForAdmin(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var p rtSitesListQuery
	if err := decodeQuery(r, &p); err != nil {
		return err
	}
	limit, offset := paginate(p.Limit, p.Offset)
	sites, err := queryAll[rtSitesAdminSiteRow](r.Context(), st.DB,
		"SELECT s.id, s.domain, s.runtime, s.status, s.enabled, s.ssl_enabled, "+
			"s.created_at, s.parent_site_id, s.user_id, "+
			"u.email AS owner_email, u.role AS owner_role "+
			"FROM sites s LEFT JOIN users u ON u.id = s.user_id "+
			"WHERE s.server_id = $1 ORDER BY s.created_at DESC LIMIT $2 OFFSET $3",
		serverID, limit, offset)
	if err != nil {
		return internalError("list sites for admin", err)
	}
	writeJSON(w, http.StatusOK, sites)
	return nil
}

// rtSitesRateLimitMsg is the rate-limit refusal shared by create and clone.
func rtSitesRateLimitMsg(maxSites int64) error {
	return apiErr(http.StatusTooManyRequests, fmt.Sprintf("Site creation rate limit: max %d sites per hour. "+
		"An administrator can change this in Settings > Account > Security Hardening "+
		"(\"Site Creation Rate Limit\"); set it to 0 to remove the limit.", maxSites))
}

// rtSitesPHPSocket is a VERSION CARRIER, not a literal path: the backend
// cannot know the target distro, so the agent resolves the real socket
// (Debian or RHEL's unversioned one) before touching a filesystem path.
func rtSitesPHPSocket(v string) string { return "unix:/run/php/php" + v + "-fpm.sock" }

// rtSitesCreate is POST /api/sites.
func rtSitesCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body rtSitesCreateSiteRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}

	// Feature 9: block site creation during lockdown.
	if SecurityHardeningIsLockedDown(ctx, st.DB) {
		return apiErr(http.StatusServiceUnavailable, "System is in lockdown mode")
	}

	// Feature 3: rate limit (max N per user per hour). The setting is a COUNT,
	// not a flag: until v2.46.0 it was read as a bool, so the seeded '3' read
	// as false and the limit became 999 — the seed disabled the very feature
	// it configures. 0 = off.
	{
		maxSites := rtSitesSiteRateLimit(ctx, st.DB)
		recent, err := queryScalar[int64](ctx, st.DB,
			"SELECT COUNT(*) FROM sites WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 hour'", c.Sub)
		if err != nil {
			recent = 0
		}
		if recent >= maxSites {
			// Feature 4: record as suspicious event.
			SecurityHardeningRecordSuspiciousEvent(ctx, st.DB, "site.rate_limit_hit", &c.Email, nil,
				new(fmt.Sprintf("User tried to create site #%d in 1 hour", recent+1)))
			return rtSitesRateLimitMsg(maxSites)
		}
	}

	// Format, reserved and every ownership check, in one call. body.Domain is
	// not used for the claim past this point; the normalised form is stored.
	domain, err := DomainClaimEnsureClaimable(ctx, st.DB, st.Agents, body.Domain, r, DomainClaimHolderNew, c.Role)
	if err != nil {
		return err
	}

	runtime := rtLogsOr(body.Runtime, "static")
	if !slices.Contains([]string{"static", "php", "proxy", "node", "python"}, runtime) {
		return apiErr(http.StatusBadRequest, "Runtime must be static, php, proxy, node, or python")
	}
	if runtime == "proxy" && body.ProxyPort == nil {
		return apiErr(http.StatusBadRequest, "proxy_port is required for proxy runtime")
	}

	// An explicitly-supplied proxy port, unvalidated, renders as
	// `proxy_pass http://127.0.0.1:<port>` (loopback SSRF) and is fed to the
	// auto-firewall `ufw deny <port>/tcp`, which would clobber a global allow
	// (deny 443 → box-wide outage). Auto-allocated ports skip this.
	if body.ProxyPort != nil {
		port := *body.ProxyPort
		if !rtSitesIsSafeProxyPort(port) {
			return apiErr(http.StatusBadRequest, "proxy_port must be between 1024 and 65535 and not a reserved/system port")
		}
		taken, err := queryScalarOpt[uuid.UUID](ctx, st.DB,
			"SELECT id FROM sites WHERE proxy_port = $1 AND server_id = $2 AND user_id <> $3", port, serverID, c.Sub)
		if err != nil {
			return internalError("proxy port check", err)
		}
		if taken != nil {
			return apiErr(http.StatusConflict, "That port is already in use by another site on this server")
		}
	}

	// Node/Python require app_command.
	if (runtime == "node" || runtime == "python") && (body.AppCommand == nil || strings.TrimSpace(*body.AppCommand) == "") {
		return apiErr(http.StatusBadRequest, "app_command is required for node/python runtime")
	}

	// Validate app_command: reject shell injection, newlines, and
	// non-whitelisted prefixes.
	if body.AppCommand != nil {
		cmd := *body.AppCommand
		if strings.ContainsAny(cmd, "\n\r\x00") {
			return apiErr(http.StatusBadRequest, "app_command must not contain newlines or null bytes")
		}
		if strings.ContainsAny(cmd, "`$|;&<>\\!{}") {
			return apiErr(http.StatusBadRequest, "app_command contains forbidden characters")
		}
		if strings.Contains(cmd, "..") {
			return apiErr(http.StatusBadRequest, "app_command must not contain '..'")
		}
		if len(cmd) > 1024 {
			return apiErr(http.StatusBadRequest, "app_command too long")
		}
		hasPrefix := func(ps ...string) bool {
			return slices.ContainsFunc(ps, func(p string) bool { return strings.HasPrefix(cmd, p) })
		}
		bare := !strings.Contains(cmd, " ")
		if runtime == "node" && !(hasPrefix("node ", "npm ", "npx ", "yarn ", "pnpm ") || bare) {
			return apiErr(http.StatusBadRequest, "app_command for node must start with node/npm/npx/yarn/pnpm or be a bare filename")
		}
		if runtime == "python" && !(hasPrefix("python", "gunicorn ", "uvicorn ", "flask ", "django") || bare) {
			return apiErr(http.StatusBadRequest, "app_command for python must start with python/gunicorn/uvicorn/flask/django or be a bare filename")
		}
	}

	if body.PHPPreset != nil && !slices.Contains([]string{"generic", "laravel", "wordpress", "drupal", "joomla", "symfony", "codeigniter", "magento"}, *body.PHPPreset) {
		return apiErr(http.StatusBadRequest, "php_preset must be one of: generic, laravel, wordpress, drupal, joomla, symfony, codeigniter, magento")
	}

	// Domain uniqueness was checked by DomainClaimEnsureClaimable above.

	// Reseller quota (fast-path UX pre-check; the atomic reserve is below).
	if err := rtResellerDashboardCheckResellerQuota(ctx, st.DB, c.Sub, "sites"); err != nil {
		return err
	}

	// Reseller server isolation: a user under a reseller may only use
	// allocated servers.
	userReseller, err := queryScalarOpt[*uuid.UUID](ctx, st.DB, "SELECT reseller_id FROM users WHERE id = $1", c.Sub)
	if err != nil {
		return internalError("reseller check", err)
	}
	if userReseller != nil && *userReseller != nil {
		allowed, err := queryScalarOpt[uuid.UUID](ctx, st.DB,
			"SELECT id FROM reseller_servers WHERE reseller_id = $1 AND server_id = $2", **userReseller, serverID)
		if err != nil {
			return internalError("reseller server check", err)
		}
		if allowed == nil {
			return apiErr(http.StatusForbidden, "This server is not allocated to your reseller account")
		}
	}

	// Insert the site with status "creating" inside a transaction.
	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return apiErr(http.StatusInternalServerError, "Transaction start failed: "+err.Error())
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	// Auto-allocate a port for node/python: the first free one in 5000-5999 on
	// THIS server. The uniqueness index behind it (idx_sites_proxy_port_server)
	// is scoped the same way; while it was global this first-fit picked 5000 on
	// every server whose own set was empty and the INSERT rejected it.
	effectivePort := body.ProxyPort
	if (runtime == "node" || runtime == "python") && body.ProxyPort == nil {
		effectivePort, err = queryScalarOpt[int32](ctx, tx,
			"SELECT s.port FROM generate_series(5000, 5999) AS s(port) "+
				"WHERE s.port NOT IN (SELECT proxy_port FROM sites WHERE proxy_port IS NOT NULL AND server_id = $1) "+
				"LIMIT 1", serverID)
		if err != nil {
			return internalError("create sites", err)
		}
	}

	site, err := queryOne[Site](ctx, tx,
		"INSERT INTO sites (user_id, server_id, domain, runtime, status, proxy_port, php_version, php_preset, app_command) "+
			"VALUES ($1, $2, $3, $4, 'creating', $5, $6, $7, $8) RETURNING *",
		c.Sub, serverID, domain, runtime, effectivePort, body.PHPVersion, rtLogsOr(body.PHPPreset, "generic"), body.AppCommand)
	if err != nil {
		msg := err.Error()
		// Two unique indexes can reject this INSERT and they mean opposite
		// things; collapsing both into "Domain already exists" sent whoever
		// hit the port one to go and look at DNS.
		switch {
		case strings.Contains(msg, "idx_sites_proxy_port_server"):
			return apiErr(http.StatusConflict, "That proxy port is already in use on this server")
		case strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique"):
			return apiErr(http.StatusConflict, "Domain already exists")
		default:
			return apiErr(http.StatusInternalServerError, msg)
		}
	}

	// The provisioning log carries the generated CMS admin password on its
	// "credentials" step, so the owner recorded here is what keeps it from any
	// other account.
	st.ProvisionLogs.Register(site.ID, c.Sub, 64)
	siteID := site.ID
	rtSitesEmitStep(st, siteID, "nginx", "Configuring web server", "in_progress", nil)

	agentBody := map[string]any{"runtime": runtime}
	if effectivePort != nil {
		agentBody["proxy_port"] = *effectivePort
	}
	if body.AppCommand != nil {
		agentBody["app_command"] = *body.AppCommand
	}
	if body.PHPVersion != nil {
		agentBody["php_socket"] = rtSitesPHPSocket(*body.PHPVersion)
	}
	if body.PHPPreset != nil {
		agentBody["php_preset"] = *body.PHPPreset
	}
	agentBody["fastcgi_cache"] = false
	agentBody["redis_cache"] = false
	agentBody["redis_db"] = 0
	agentBody["waf_enabled"] = false
	agentBody["waf_mode"] = "detection"

	// Atomically reserve the reseller slot BEFORE the agent creates the vhost —
	// closes the TOCTOU without orphaning an nginx config on a quota race (the
	// open tx rolls back the uncommitted row if this rejects).
	slotReserved, err := rtSitesReserveResellerSiteSlot(ctx, st, c.Sub)
	if err != nil {
		return err
	}

	if _, aerr := agent.Put(ctx, "/nginx/sites/"+body.Domain, agentBody); aerr != nil {
		// Agent call failed — the deferred rollback undoes the INSERT.
		slog.Error(fmt.Sprintf("Agent error creating site %s: %v", body.Domain, aerr))
		SystemLogLogEvent(ctx, st.DB, "error", "api", "Site creation failed: "+body.Domain, new(aerr.Error()))
		_ = tx.Rollback(context.WithoutCancel(ctx))
		if slotReserved {
			rtSitesReleaseResellerSiteSlot(ctx, st, c.Sub)
		}
		rtSitesEmitStep(st, siteID, "nginx", "Configuring web server", "error", new("Agent error: "+aerr.Error()))
		rtSitesEmitStep(st, siteID, "complete", "Provisioning failed", "error", nil)
		go func() {
			rtSitesSleep(30 * time.Second)
			st.ProvisionLogs.Remove(siteID)
		}()
		return agentError("Site configuration", aerr)
	}

	rtSitesEmitStep(st, siteID, "nginx", "Configuring web server", "done", nil)

	// Commit so the site record is persisted (monitors, backups, SSL need it).
	if err := tx.Commit(ctx); err != nil {
		if slotReserved {
			rtSitesReleaseResellerSiteSlot(ctx, st, c.Sub)
		}
		return apiErr(http.StatusInternalServerError, "Transaction commit failed: "+err.Error())
	}

	if _, err := execSQL(ctx, st.DB, "UPDATE sites SET status = 'active', updated_at = NOW() "+
		"WHERE id = $1 AND status = 'creating'", site.ID); err != nil {
		return internalError("create sites", err)
	}
	updated, err := queryOne[Site](ctx, st.DB, "SELECT * FROM sites WHERE id = $1", site.ID)
	if err != nil {
		return internalError("create sites", err)
	}

	// GAP 50: block direct external access to the proxy port (only localhost
	// via nginx).
	if effectivePort != nil {
		_, _ = agent.Post(ctx, "/security/firewall/rules", map[string]any{
			"port": uint16(*effectivePort), "proto": "tcp", "action": "deny", "from": nil,
		})
		slog.Info(fmt.Sprintf("Auto-firewall: blocked external access to port %d for %s", *effectivePort, body.Domain))
	}

	slog.Info(fmt.Sprintf("Site created: %s (%s)", body.Domain, runtime))
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.create", new("site"), &body.Domain, &runtime, clientIP(r), c.KeyID)
	NotificationsNotifyPanel(ctx, st.DB, &c.Sub, "Site created: "+body.Domain, fmt.Sprintf("New %s site is now active", runtime),
		"info", "site", new("/sites/"+site.ID.String()))
	ExtensionsFireEvent(st.DB, "site.created", map[string]any{
		"site_id": site.ID, "domain": site.Domain, "runtime": site.Runtime,
	})

	// Reseller counter already incremented atomically by the reserve above.
	// Auto-monitor creation is disabled: on fresh installs without DNS, an
	// auto-created monitor immediately shows "down", which confuses new users.

	bg := context.WithoutCancel(ctx)

	// Auto-create a backup schedule for every new site (daily 3 AM, 7 kept).
	go func() {
		_, _ = execSQL(bg, st.DB, "INSERT INTO backup_schedules (site_id, schedule, retention_count, enabled) "+
			"VALUES ($1, '0 3 * * *', 7, true) ON CONFLICT (site_id) DO NOTHING", siteID)
		slog.Info("Auto-backup: created daily schedule for new site")
	}()

	// GAP 6: auto-create the site's secrets vault — INLINE, so its id is
	// available to the CMS installer below. It was fire-and-forget until
	// v2.28.0, and the CMS task raced it — part of why the auto-generated
	// admin password was never stored anywhere and the vault sat empty.
	siteVaultID, verr := queryScalarOpt[uuid.UUID](ctx, st.DB,
		"INSERT INTO secret_vaults (user_id, name, description, site_id) "+
			"VALUES ($1, $2, $3, $4) RETURNING id",
		c.Sub, body.Domain+" secrets", "Auto-created vault for "+body.Domain, site.ID)
	if verr != nil {
		slog.Warn(fmt.Sprintf("Auto-vault: could not create vault for %s: %v", body.Domain, verr))
		siteVaultID = nil
	}
	if siteVaultID != nil {
		slog.Info("Auto-vault: created for " + body.Domain)
	}

	// GAP 15: auto-create a paused uptime monitor (activates after SSL).
	go func() {
		_, _ = execSQL(bg, st.DB,
			"INSERT INTO monitors (user_id, site_id, url, name, check_interval, status, enabled, monitor_type) "+
				"VALUES ($1, $2, $3, $4, 60, 'pending', FALSE, 'http') ON CONFLICT DO NOTHING",
			c.Sub, siteID, "https://"+body.Domain, body.Domain)
		slog.Info("Auto-monitor: created (paused) for " + body.Domain)
	}()

	// GAP 4: auto-create a status page component if the status page is on.
	go rtSitesAutoStatusComponent(bg, st, c.Sub, body.Domain, "", "status page config for auto-component")

	// Auto-DNS: an A record if the user has a DNS zone for this domain —
	// publishing THIS server's address, not the panel's (see
	// publicIPForServer): on a fleet the record used to point every member's
	// site at the panel, unreachable at the very name just claimed for it.
	go rtSitesAutoDNSCreate(bg, st, siteID, body.Domain, c.Sub, serverID)

	// Decided up front: the SSL task's outcome channel goes to whichever
	// branch owns the terminal step.
	cmsType := rtLogsOr(body.CMS, "")
	needsDB := slices.Contains([]string{"wordpress", "laravel", "drupal", "joomla", "codeigniter"}, cmsType)
	needsInstall := slices.Contains([]string{"wordpress", "laravel", "drupal", "joomla", "symfony", "codeigniter"}, cmsType)

	// Auto-SSL in the background. Resolve the ACME contact BEFORE spawning: a
	// contact in a reserved TLD (admin@box.test) makes Let's Encrypt refuse the
	// account, and before s253 that failed four times in total silence.
	sslEmail, cerr := rtSslResolveAcmeContact(ctx, st.DB, c.Email)
	if cerr != nil {
		slog.Warn(fmt.Sprintf("Auto-SSL skipped for %s: %v", body.Domain, cerr))
		rtSitesEmitStep(st, siteID, "ssl", "SSL certificate", "error", new(cerr.Error()))
		sslEmail = ""
	}
	// Lets the terminal step report what actually happened instead of
	// asserting success on a timer (s252 F2). Closed without a value = the
	// sender was dropped.
	sslRx := make(chan bool, 1)
	go rtSitesAutoSSL(bg, st, agent, siteID, body.Domain, sslEmail, runtime, body.PHPVersion, body.ProxyPort, body.PHPPreset, sslRx)

	if needsInstall {
		job := rtSitesCMSJob{
			agent: agent, siteID: siteID, domain: body.Domain, name: cmsType,
			title: rtLogsOr(body.SiteTitle, body.Domain), email: rtLogsOr(body.AdminEmail, "admin@example.com"),
			user: rtLogsOr(body.AdminUser, "admin"), needsDB: needsDB, vaultID: siteVaultID,
			// Whether WE generated the password decides whether the user has
			// any other copy of it. If they typed one, don't echo it back.
			passGenerated: body.AdminPassword == nil,
		}
		job.label = map[string]string{"wordpress": "WordPress", "laravel": "Laravel", "drupal": "Drupal",
			"joomla": "Joomla", "symfony": "Symfony", "codeigniter": "CodeIgniter"}[cmsType]
		if body.AdminPassword != nil {
			job.pass = *body.AdminPassword
		} else {
			job.pass = rtSitesRandAlnum(16)
		}
		go rtSitesInstallCMS(bg, st, job, sslRx)
	} else {
		// Non-CMS site: the terminal step reports the SSL outcome rather than
		// assuming it. This used to sleep a flat 12s and declare "Site ready"
		// while Auto-SSL was still retrying behind that claim (s252 F2).
		go func() {
			// Bounded: the full retry ladder runs ~7.5 minutes; past the bound
			// we say HTTPS is still in progress, which is true.
			switch v, ok := rtSitesAwait(sslRx, 75*time.Second); {
			case ok && v:
				rtSitesEmitStep(st, siteID, "complete", "Site ready", "done", nil)
			case ok && !v:
				rtSitesEmitStep(st, siteID, "complete", "Site created — HTTPS not configured", "error",
					new("The site is served over HTTP. Open the site's SSL section for the reason and to retry."))
			default:
				// Sender dropped, or out of patience: unknown either way.
				rtSitesEmitStep(st, siteID, "complete", "Site created — HTTPS still in progress", "done",
					new("DockPanel is still trying to issue a certificate. The site's SSL section shows the result."))
			}
			rtSitesSleep(30 * time.Second)
			st.ProvisionLogs.Remove(siteID)
		}()
	}

	writeJSON(w, http.StatusCreated, updated)
	return nil
}

// rtSitesAwait receives from a oneshot within d: (value, true) when sent,
// (false, false) on timeout or a dropped sender.
func rtSitesAwait(ch <-chan bool, d time.Duration) (bool, bool) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case v, ok := <-ch:
		return v, ok
	case <-t.C:
		return false, false
	}
}

// rtSitesAutoStatusComponent adds a status page component for a new site if
// the owner's status page is enabled.
func rtSitesAutoStatusComponent(ctx context.Context, st *AppState, userID uuid.UUID, domain, logSuffix, what string) {
	enabled, err := queryScalarOpt[bool](ctx, st.DB, "SELECT enabled FROM status_page_config WHERE user_id = $1", userID)
	if err != nil {
		slog.Warn(fmt.Sprintf("DB error checking %s: %v", what, err))
		enabled = nil
	}
	if enabled != nil && *enabled {
		_, _ = execSQL(ctx, st.DB, "INSERT INTO status_page_components (user_id, name, description, group_name) "+
			"VALUES ($1, $2, $3, 'Sites')", userID, domain, "Auto-created for "+domain)
		slog.Info(fmt.Sprintf("Auto-component: created status page component for %s%s", logSuffix, domain))
	}
}

// rtSitesParentDomain is the auto-DNS zone guess: the last two labels of a
// splitn(3, '.') — kept exactly as Rust computed it.
func rtSitesParentDomain(d string) string {
	parts := strings.SplitN(d, ".", 3)
	if len(parts) >= 3 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return d
}

type rtSitesDNSZone struct {
	Provider   string  `db:"provider"`
	CfZoneID   *string `db:"cf_zone_id"`
	CfAPIToken *string `db:"cf_api_token"`
	CfAPIEmail *string `db:"cf_api_email"`
}

// rtSitesPDNSSettings reads the PowerDNS URL and (decrypted) key.
func rtSitesPDNSSettings(ctx context.Context, db *pgxpool.Pool) (string, string, bool) {
	rows, _ := queryAll[Tup2[string, string]](ctx, db, "SELECT key, value FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key')")
	var url, keyEnc *string
	for _, kv := range rows {
		v := kv.B
		switch kv.A {
		case "pdns_api_url":
			if url == nil {
				url = &v
			}
		case "pdns_api_key":
			if keyEnc == nil {
				keyEnc = &v
			}
		}
	}
	if url == nil || keyEnc == nil {
		return "", "", false
	}
	return *url, SecretsCryptoDecryptCredentialFromEnv(*keyEnc), true
}

// rtSitesSendJSON fires a best-effort JSON request (reqwest::Client::new()).
func rtSitesSendJSON(ctx context.Context, method, url string, h http.Header, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range h {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

// rtSitesAutoDNSCreate creates the site's A record in the owner's zone.
func rtSitesAutoDNSCreate(ctx context.Context, st *AppState, siteID uuid.UUID, domain string, userID, serverID uuid.UUID) {
	parent := rtSitesParentDomain(domain)
	zone, err := queryOpt[rtSitesDNSZone](ctx, st.DB,
		"SELECT provider, cf_zone_id, cf_api_token, cf_api_email FROM dns_zones WHERE domain = $1 AND user_id = $2", parent, userID)
	if err != nil {
		slog.Warn(fmt.Sprintf("DB error fetching DNS zone for auto-DNS on site create: %v", err))
		return
	}
	if zone == nil {
		return
	}
	ip := publicIPForServer(ctx, st.DB, &serverID)
	if ip == nil {
		// Refusing is the whole point: an A record naming the wrong machine is
		// worse than no record, because it resolves and answers.
		rtSitesEmitStep(st, siteID, "dns", "Creating DNS record", "failed", new("could not determine this server's public address"))
		return
	}
	serverIP := *ip
	switch zone.Provider {
	case "cloudflare":
		if zone.CfZoneID != nil && zone.CfAPIToken != nil {
			resp, err := rtSitesSendJSON(ctx, http.MethodPost, "https://api.cloudflare.com/client/v4/zones/"+*zone.CfZoneID+"/dns_records",
				cfHeaders(*zone.CfAPIToken, zone.CfAPIEmail),
				map[string]any{"type": "A", "name": domain, "content": serverIP, "proxied": true, "ttl": 1})
			if err == nil {
				resp.Body.Close()
			}
			slog.Info(fmt.Sprintf("Auto-DNS: created A record %s → %s", domain, serverIP))
			rtSitesEmitStep(st, siteID, "dns", "Creating DNS record", "done", nil)
		}
	case "powerdns":
		if url, key, ok := rtSitesPDNSSettings(ctx, st.DB); ok {
			zfqdn := parent
			if !strings.HasSuffix(zfqdn, ".") {
				zfqdn += "."
			}
			resp, err := rtSitesSendJSON(ctx, http.MethodPatch, url+"/api/v1/servers/localhost/zones/"+zfqdn,
				http.Header{"X-Api-Key": {key}},
				map[string]any{"rrsets": []any{map[string]any{"name": domain + ".", "type": "A", "ttl": 300, "changetype": "REPLACE",
					"records": []any{map[string]any{"content": serverIP, "disabled": false}}}}})
			if err == nil {
				resp.Body.Close()
			}
			slog.Info(fmt.Sprintf("Auto-DNS (PowerDNS): created A record %s → %s", domain, serverIP))
			rtSitesEmitStep(st, siteID, "dns", "Creating DNS record", "done", nil)
		}
	}
}

// rtSitesAutoSSL provisions a Let's Encrypt certificate with backoff (3s,
// 30s, 2m, 5m) and reports the outcome on tx.
func rtSitesAutoSSL(ctx context.Context, st *AppState, agent AgentHandle, siteID uuid.UUID, domain, email, runtime string, phpVersion *string, proxyPort *int32, phpPreset *string, tx chan<- bool) {
	defer close(tx)
	// Empty means the contact could not be resolved; the reason is already a
	// step, so don't burn four retries against an order the CA will refuse.
	if email == "" {
		tx <- false
		return
	}
	var phpSocket *string
	if phpVersion != nil {
		phpSocket = new(rtSitesPHPSocket(*phpVersion))
	}
	delays := []int{3, 30, 120, 300}
	for i, delay := range delays {
		rtSitesSleep(time.Duration(delay) * time.Second)
		rtSitesEmitStep(st, siteID, "ssl", "Provisioning SSL certificate", "in_progress", nil)
		body := map[string]any{"email": email, "runtime": runtime, "php_socket": phpSocket, "proxy_port": proxyPort}
		if phpPreset != nil {
			body["php_preset"] = *phpPreset
		}
		res, err := agent.Post(ctx, "/ssl/provision/"+domain, body)
		if err != nil {
			if i == len(delays)-1 {
				// Say WHY — this used to read "Skipped", which described
				// neither the four attempts nor their cause.
				slog.Info(fmt.Sprintf("Auto-SSL failed for %s after %d attempts: %v", domain, i+1, err))
				rtSitesEmitStep(st, siteID, "ssl", "SSL certificate", "error", new(fmt.Sprintf(
					"Could not issue a certificate after %d attempts: %v. "+
						"The site is served over HTTP; open the site's SSL section to retry.", i+1, err)))
				tx <- false
			} else {
				slog.Info(fmt.Sprintf("Auto-SSL attempt %d for %s failed, retrying in %ds", i+1, domain, delays[i+1]))
			}
			continue
		}
		slog.Info(fmt.Sprintf("Auto-SSL provisioned for %s (attempt %d)", domain, i+1))
		rtSitesEmitStep(st, siteID, "ssl", "Provisioning SSL certificate", "done", nil)

		// The body above carries the runtime, root and PHP socket but NOT the
		// per-site limits or hardening fields — and the agent re-renders the
		// whole vhost from it. This task retries with delays, so a limit set in
		// between would be dropped. Cheaper to put the row back.
		rtSslRebuildVhostForSite(ctx, st.DB, agent, siteID)

		var expiry *time.Time
		if s, ok := jsonStr(jsonGet(res, "expiry")); ok {
			expiry = parseAgentCertExpiry(s)
		}
		certPath, _ := jsonStr(jsonGet(res, "cert_path"))
		keyPath, _ := jsonStr(jsonGet(res, "key_path"))

		// ⚠ This statement records provenance too (profile, challenge, subject,
		// wildcard, zone), like the deliberate issuance doors: it used to write
		// four columns, leaving a NULL profile the cooldown and margin helpers
		// then read. This door is always HTTP-01 for the site's own domain,
		// never a wildcard.
		_, _ = execSQL(ctx, st.DB,
			"UPDATE sites SET ssl_enabled = true, ssl_cert_path = $1, ssl_key_path = $2, "+
				"ssl_expiry = $3, ssl_profile = NULL, "+
				"ssl_challenge = 'http-01', ssl_cert_subject = $5, ssl_wildcard = FALSE, "+
				"ssl_dns_zone_id = NULL, updated_at = NOW() WHERE id = $4",
			certPath, keyPath, expiry, siteID, domain)
		// Activate paused monitors now that SSL works.
		_, _ = execSQL(ctx, st.DB,
			"UPDATE monitors SET enabled = TRUE WHERE site_id = $1 AND enabled = FALSE AND status = 'pending'", siteID)
		tx <- true
		return
	}
}

// rtSitesCMSJob is the one-click CMS/framework install's inputs.
type rtSitesCMSJob struct {
	agent                    AgentHandle
	siteID                   uuid.UUID
	domain, name, label      string
	title, email, user, pass string
	needsDB, passGenerated   bool
	vaultID                  *uuid.UUID
}

// rtSitesInstallCMS creates the database (if needed), installs the
// CMS/framework, takes custody of the generated credentials, and emits the
// terminal step from the real install + SSL outcome.
func rtSitesInstallCMS(ctx context.Context, st *AppState, j rtSitesCMSJob, sslRx <-chan bool) {
	emit := func(step, label, status string, msg *string) { rtSitesEmitStep(st, j.siteID, step, label, status, msg) }
	jwtSecret := st.Config.JWTSecret
	dbName := strings.NewReplacer(".", "_", "-", "_").Replace(j.domain)
	dbUser := dbName
	dbPassword := rtSitesRandAlnum(20)

	// 1. Create the database (if needed).
	dbHost := ""
	if j.needsDB {
		emit("database", "Creating MySQL database", "in_progress", nil)
		resp, err := j.agent.Post(ctx, "/databases", map[string]any{"engine": "mysql", "name": dbName, "password": dbPassword})
		if err != nil {
			slog.Error(fmt.Sprintf("%s DB creation failed for %s: %v", j.label, j.domain, err))
			emit("database", "Creating MySQL database", "error", new(fmt.Sprintf("Database creation failed: %v", err)))
			emit("complete", "Provisioning failed", "error", nil)
			rtSitesSleep(30 * time.Second)
			st.ProvisionLogs.Remove(j.siteID)
			return
		}
		p64, ok := jsonU64(jsonGet(resp, "port"))
		if !ok {
			p64 = 3306
		}
		port := uint16(p64)
		cid, _ := jsonStr(jsonGet(resp, "container_id"))
		emit("database", "Creating MySQL database", "done", nil)
		dbHost = fmt.Sprintf("127.0.0.1:%d", port)

		enc, err := SecretsCryptoEncryptCredential(dbPassword, jwtSecret)
		if err != nil {
			enc = dbPassword
		}
		// The site id is already in hand — this used to resolve it again from
		// the domain, which is unique only per server, so on a fleet holding the
		// same domain twice the database (credentials included) could attach to
		// ANOTHER owner's site row.
		_, _ = execSQL(ctx, st.DB,
			"INSERT INTO databases (site_id, engine, name, db_user, db_password_enc, container_id, port) "+
				"VALUES ($1, 'mysql', $2, $3, $4, $5, $6) "+
				"ON CONFLICT DO NOTHING",
			j.siteID, dbName, dbUser, enc, cid, int32(port))

		emit("db_init", "Waiting for database engine", "in_progress", nil)
		// Wait for MariaDB to be fully ready (TCP connects before MySQL is).
		for range 20 {
			rtSitesSleep(2 * time.Second)
			cmd := safeCommand(ctx, "php", "-r", "try { new PDO(getenv('DSN'), getenv('DB_USER'), getenv('DB_PASS')); echo 'OK'; } catch(Exception $e) { echo 'FAIL'; }")
			cmd.Env = append(cmd.Env, "DSN=mysql:host="+dbHost+";dbname="+dbName, "DB_USER="+dbUser, "DB_PASS="+dbPassword)
			if out, _ := cmd.Output(); strings.Contains(string(out), "OK") {
				break
			}
		}
		emit("db_init", "Database engine ready", "done", nil)
	}

	// 2. Install the CMS/framework.
	installOK := true
	emit("install", "Installing "+j.label, "in_progress", nil)

	// Install at the scheme the site can serve RIGHT NOW. Auto-SSL may yet
	// fail (DNS not pointed at the box is the ordinary first site); committing
	// WordPress to https regardless left it 302ing to a scheme with no
	// certificate. The promotion below moves it across once there is one.
	var err error
	if j.name == "wordpress" {
		_, err = j.agent.Post(ctx, "/wordpress/"+j.domain+"/install", map[string]any{
			"url": "http://" + j.domain, "title": j.title, "admin_user": j.user, "admin_pass": j.pass,
			"admin_email": j.email, "db_name": dbName, "db_user": dbUser, "db_pass": dbPassword, "db_host": dbHost,
		})
	} else {
		_, err = j.agent.Post(ctx, "/cms/"+j.domain+"/install", map[string]any{
			"cms": j.name, "title": j.title, "admin_user": j.user, "admin_pass": j.pass,
			"admin_email": j.email, "db_name": dbName, "db_user": dbUser, "db_pass": dbPassword, "db_host": dbHost,
		})
	}
	if err != nil {
		slog.Error(fmt.Sprintf("%s install failed for %s: %v", j.label, j.domain, err))
		installOK = false
		emit("install", "Installing "+j.label, "error", new(fmt.Sprintf("%s install failed: %v", j.label, err)))
	} else {
		slog.Info(fmt.Sprintf("%s installed on %s", j.label, j.domain))
		emit("install", "Installing "+j.label, "done", nil)

		// Take custody of the credentials we just generated. The form says
		// "Auto-generated if blank"; before v2.28.0 the password went to wp-cli
		// and nowhere else, locking the user out of the site they just made.
		if j.vaultID != nil {
			vid := *j.vaultID
			storedPass := rtSitesStoreSiteSecret(ctx, st.DB, jwtSecret, vid, j.name+"_admin_password", j.pass,
				fmt.Sprintf("%s admin password for %s", j.label, j.domain))
			rtSitesStoreSiteSecret(ctx, st.DB, jwtSecret, vid, j.name+"_admin_user", j.user,
				fmt.Sprintf("%s admin username for %s", j.label, j.domain))
			if j.needsDB {
				rtSitesStoreSiteSecret(ctx, st.DB, jwtSecret, vid, "database_password", dbPassword, "Database password for "+dbName)
			}
			// Reveal a password we generated exactly once, at creation. It is
			// also in the vault, and the provisioning stream is owner-scoped.
			credLabel := j.label + " admin credentials"
			switch {
			case storedPass && j.passGenerated:
				emit("credentials", credLabel, "done", new(fmt.Sprintf(
					"Username %s · password %s — saved to the \"%s secrets\" vault. "+
						"Copy it now; this is the only time it is shown here.", j.user, j.pass, j.domain)))
			case storedPass:
				emit("credentials", credLabel, "done", new(fmt.Sprintf("Saved to the \"%s secrets\" vault.", j.domain)))
			default:
				emit("credentials", credLabel, "error", new("Could not be saved to the site vault — "+
					"reset the admin password from the site's tools."))
			}
		}

		// Auto-create the WordPress system cron. No `> /dev/null 2>&1`: the
		// agent's cron filter blocks "> /dev/", and this row bypasses that
		// filter — so the product wrote a job its own guard rejects and every
		// later cron sync failed for the whole box. cron discards output on
		// its own when MAILTO is empty.
		if j.name == "wordpress" {
			go func() {
				_, _ = execSQL(ctx, st.DB, "INSERT INTO crons (site_id, label, command, schedule, enabled) "+
					"VALUES ($1, 'WordPress Cron', $2, '*/15 * * * *', true)",
					j.siteID, "cd /var/www/"+j.domain+"/public && php wp-cron.php")
				slog.Info("Auto-cron: created WordPress cron for " + j.domain)
			}()
		}
	}

	// The terminal step must report what happened — it used to say "Site
	// ready" unconditionally, including over a failed install and over a site
	// whose auto-SSL failed. Bounded wait; past it HTTPS is "in progress".
	sslOK, got := rtSitesAwait(sslRx, 45*time.Second)
	switch {
	case !installOK:
		emit("complete", fmt.Sprintf("Site created — %s install failed", j.label), "error",
			new("The site and its database exist, but the application was not installed. See the failed step above."))
	case got && sslOK:
		// The certificate can land while the install is still running, when
		// there is no WordPress whose URL the agent could move. Ask again now;
		// a no-op if the agent already did it.
		var perr error
		if j.name == "wordpress" {
			_, perr = j.agent.Post(ctx, "/wordpress/"+j.domain+"/promote-https", nil)
		}
		if perr == nil {
			emit("complete", "Site ready", "done", nil)
		} else {
			// HTTPS is live and nginx redirects to it, but the site's own
			// links still say HTTP — "ready" would be the same false claim.
			slog.Warn(fmt.Sprintf("Canonical URL promotion failed for %s: %v", j.domain, perr))
			emit("complete", j.label+" installed — HTTPS live, site still set to HTTP", "error", new(fmt.Sprintf(
				"The certificate is installed, but the site's address could not be switched to HTTPS: %v. "+
					"Update the site address in %s settings.", perr, j.label)))
		}
	case got:
		emit("complete", j.label+" installed — HTTPS not configured", "error",
			new("The site is served over HTTP. See the SSL step above for the reason, and retry from the site's SSL section."))
	default:
		emit("complete", j.label+" installed — HTTPS still in progress", "done",
			new("DockPanel is still trying to issue a certificate. The site's SSL section shows the result."))
	}
	rtSitesSleep(30 * time.Second)
	st.ProvisionLogs.Remove(j.siteID)
}

// rtSitesProvisionLog is GET /api/sites/{id}/provision-log — SSE stream of
// provisioning steps.
func rtSitesProvisionLog(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	exists, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB, "SELECT s.id FROM sites s WHERE "+SiteCallerPredicate, id, c.Sub)
	if err != nil {
		return internalError("provision log", err)
	}
	if exists == nil {
		return apiErr(http.StatusNotFound, "Site not found")
	}
	// The row check above is kept as well as the per-key owner check: this is
	// the one stream that deliberately carries a credential, worth two
	// independent reasons to refuse rather than one.
	history, live, unsub, err := st.ProvisionLogs.Open(id, c.Sub, "No active provisioning for this site")
	if err != nil {
		return err
	}
	defer unsub()
	rtSitesServeSSE(st, w, r, history, live)
	return nil
}

// rtSitesServeSSE writes the snapshot, then live steps, with a 15s ":ping"
// keep-alive (axum KeepAlive::text("ping")). It ends when the channel closes
// (the job finished and its entry was dropped), the client goes away, or the
// panel shuts down — a job in progress at shutdown can outlive the drain.
func rtSitesServeSSE(st *AppState, w http.ResponseWriter, r *http.Request, history []ProvisionStep, live <-chan ProvisionStep) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flush := func() {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	send := func(s ProvisionStep) bool {
		b, err := json.Marshal(s)
		if err != nil {
			return true
		}
		_, err = fmt.Fprintf(w, "data: %s\n\n", b)
		flush()
		return err == nil
	}
	for _, s := range history {
		if !send(s) {
			return
		}
	}
	flush()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case s, ok := <-live:
			if !ok || !send(s) {
				return
			}
		case <-ping.C:
			if _, err := io.WriteString(w, ":ping\n\n"); err != nil {
				return
			}
			flush()
		case <-r.Context().Done():
			return
		case <-st.Shutdown.Done():
			return
		}
	}
}

// rtSitesGetOne is GET /api/sites/{id}. The two arms of SiteCallerPredicate
// for the whole row: this is the read the site's own page makes, so it decides
// whether an administrator can open a site at all (#51).
func rtSitesGetOne(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	site, err := rtSitesSiteByCaller(r.Context(), st, id, c, "get_one sites", "Site not found")
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, site)
	return nil
}

// rtSitesPHPVersions are the PHP versions this panel accepts from a client —
// one list for both handlers. Deliberately a second copy of the agent's own
// list: this side must reject a bad version before it spawns anything, and
// cannot ask an agent that may be a release behind.
var rtSitesPHPVersions = []string{"8.1", "8.2", "8.3", "8.4", "8.5"}

func rtSitesInvalidPHP() error {
	return apiErr(http.StatusBadRequest, "Invalid PHP version. Allowed: "+strings.Join(rtSitesPHPVersions, ", "))
}

type rtSitesSwitchPhpRequest struct {
	Version string `json:"version"`
}

// rtSitesSwitchPhp is PUT /api/sites/{id}/php.
func rtSitesSwitchPhp(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	var body rtSitesSwitchPhpRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	version := strings.TrimSpace(body.Version)
	if !slices.Contains(rtSitesPHPVersions, version) {
		return rtSitesInvalidPHP()
	}
	site, agent, err := rtSitesSiteAndAgent(ctx, st, id, c, "switch php")
	if err != nil {
		return err
	}
	if site.Runtime != "php" {
		return apiErr(http.StatusBadRequest, "PHP version can only be changed on PHP sites")
	}

	// Rebuild the FULL vhost with only php_version changed — a hand-rolled
	// partial body silently dropped the site's WAF / CSP / Permissions-Policy /
	// bot-protection on every PHP switch.
	u := *site
	u.PHPVersion = &version
	if _, err := agent.Put(ctx, "/nginx/sites/"+site.Domain, rtSitesBuildNginxBody(&u)); err != nil {
		return agentError("Nginx update", err)
	}
	updated, err := queryOne[Site](ctx, st.DB, "UPDATE sites SET php_version = $1, updated_at = NOW() WHERE id = $2 RETURNING *", version, id)
	if err != nil {
		return internalError("switch php", err)
	}
	slog.Info(fmt.Sprintf("PHP version switched to %s for %s", version, site.Domain))
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.php_switch", new("site"), &site.Domain, &version, nil, c.KeyID)
	writeJSON(w, http.StatusOK, updated)
	return nil
}

// rtSitesSwitchableRuntimes are the runtimes a site may be switched BETWEEN —
// deliberately only two. proxy/node/python need a proxy_port (and node/python
// an app_command through create's prefix whitelist), and the agent maps those
// three to the site directory itself while static and php BOTH map to
// {site_dir}/public — so static⇄php is purely a vhost rebuild, while anything
// involving a proxying runtime also moves the document root out from under
// the operator's files. Issue #99 asked for html→PHP; the other half is a
// separate feature.
var rtSitesSwitchableRuntimes = []string{"static", "php"}

type rtSitesSwitchRuntimeRequest struct {
	Runtime string `json:"runtime"`
	// Required when switching TO php. Ignored when switching to static.
	PHPVersion *string `json:"php_version"`
}

// rtSitesSwitchRuntime is PUT /api/sites/{id}/runtime.
func rtSitesSwitchRuntime(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	var body rtSitesSwitchRuntimeRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	target := strings.TrimSpace(body.Runtime)
	both := strings.Join(rtSitesSwitchableRuntimes, " and ")
	if !slices.Contains(rtSitesSwitchableRuntimes, target) {
		return apiErr(http.StatusBadRequest, fmt.Sprintf("Runtime can only be switched between %s. Changing to or from a proxying "+
			"runtime moves the document root and is not supported here.", both))
	}
	site, agent, err := rtSitesSiteAndAgent(ctx, st, id, c, "switch runtime")
	if err != nil {
		return err
	}
	if !slices.Contains(rtSitesSwitchableRuntimes, site.Runtime) {
		return apiErr(http.StatusBadRequest, fmt.Sprintf("This site runs the '%s' runtime. Only %s sites can be switched.", site.Runtime, both))
	}
	if site.Runtime == target {
		return apiErr(http.StatusBadRequest, fmt.Sprintf("Site is already running the '%s' runtime", target))
	}

	// A PHP target needs a version, STATED rather than guessed: a site that
	// was PHP once still carries its old php_version, and silently reusing it
	// would switch the operator onto a version they never chose.
	var phpVersion *string
	if target == "php" {
		v := ""
		if body.PHPVersion != nil {
			v = strings.TrimSpace(*body.PHPVersion)
		}
		if v == "" {
			return apiErr(http.StatusBadRequest, "php_version is required when switching to the PHP runtime")
		}
		if !slices.Contains(rtSitesPHPVersions, v) {
			return rtSitesInvalidPHP()
		}
		phpVersion = &v
	}

	// Rebuild the FULL vhost with only the runtime (and PHP version) changed.
	// The agent's put_site already refuses a PHP version the server lacks,
	// writes the pool, reloads PHP-FPM, and re-points nginx only once the pool
	// socket exists — the fail-safe that stops a switch from 502-ing the site.
	u := *site
	u.Runtime = target
	u.PHPVersion = phpVersion
	if _, err := agent.Put(ctx, "/nginx/sites/"+site.Domain, rtSitesBuildNginxBody(&u)); err != nil {
		return agentError("Nginx update", err)
	}
	// Only after the vhost is live: a failed agent write leaves the row
	// describing what is really being served.
	updated, err := queryOne[Site](ctx, st.DB, "UPDATE sites SET runtime = $1, php_version = $2, updated_at = NOW() "+
		"WHERE id = $3 RETURNING *", target, phpVersion, id)
	if err != nil {
		return internalError("switch runtime", err)
	}
	slog.Info(fmt.Sprintf("Runtime switched %s -> %s for %s", site.Runtime, target, site.Domain))
	details := fmt.Sprintf("%s -> %s", site.Runtime, target)
	if phpVersion != nil {
		details += " " + *phpVersion
	}
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.runtime_switch", new("site"), &site.Domain, &details, nil, c.KeyID)
	writeJSON(w, http.StatusOK, updated)
	return nil
}

// rtSitesScopedGet is an AuthUser + ServerScope GET passthrough.
func rtSitesScopedGet(st *AppState, w http.ResponseWriter, r *http.Request, path, what string) error {
	if _, err := st.authUser(r); err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), path)
	if err != nil {
		return agentError(what, err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtSitesPhpVersions is GET /api/php/versions (proxy to agent).
func rtSitesPhpVersions(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesScopedGet(st, w, r, "/php/versions", "Site agent operation")
}

type rtSitesInstallPhpRequest struct {
	Version string `json:"version"`
}

// rtSitesPhpPackage serves php_install / php_uninstall: accepted, not
// performed — 202 { install_id } and the outcome over the Services page's
// /api/services/install/{id}/log SSE. Installing PHP can take minutes, past
// the panel's own 300s timeout, so holding the request open could only ever
// time out the installs that needed the most time.
func rtSitesPhpPackage(st *AppState, w http.ResponseWriter, r *http.Request, suffix, path string) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body rtSitesInstallPhpRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if c.Role != "admin" {
		return apiErr(http.StatusForbidden, "Admin only")
	}
	// Rejected here as well as on the agent: this side answers 202 before it
	// has heard from anything, so an unchecked version would be reported as
	// "started" and only contradicted later, inside a log.
	if !slices.Contains(rtSitesPHPVersions, body.Version) {
		return rtSitesInvalidPHP()
	}
	status, res, err := rtSystemInstallServiceWithLog(r.Context(), st, agent, c.Sub, c.Email,
		"PHP "+body.Version+suffix, path, map[string]any{"version": body.Version})
	if err != nil {
		return err
	}
	writeJSON(w, status, res)
	return nil
}

// rtSitesPhpInstall is POST /api/php/install (admin only).
func rtSitesPhpInstall(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesPhpPackage(st, w, r, "", "/php/install")
}

// rtSitesPhpUninstall is POST /api/php/uninstall (admin only). The agent
// budgets 300s for the purge; this side used to give it 60, which cancelled
// only the account of a destructive operation, not the operation.
func rtSitesPhpUninstall(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesPhpPackage(st, w, r, " (uninstall)", "/php/uninstall")
}

type rtSitesUpdateLimitsRequest struct {
	RateLimit     *int32  `json:"rate_limit"`
	MaxUploadMB   *int32  `json:"max_upload_mb"`
	PHPMemoryMB   *int32  `json:"php_memory_mb"`
	PHPMaxWorkers *int32  `json:"php_max_workers"`
	CustomNginx   *string `json:"custom_nginx"`
	// NULL = unlimited, mirroring rate_limit: the settings form always echoes
	// this back, so its absence means "unlimited", never "leave as was".
	BandwidthQuotaMB *int32 `json:"bandwidth_quota_mb"`
}

// rtSitesUpdateLimits is PUT /api/sites/{id}/limits.
func rtSitesUpdateLimits(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	var body rtSitesUpdateLimitsRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	site, agent, err := rtSitesSiteAndAgent(ctx, st, id, c, "update limits")
	if err != nil {
		return err
	}
	if rl := body.RateLimit; rl != nil && (*rl < 1 || *rl > 10000) {
		return apiErr(http.StatusBadRequest, "Rate limit must be between 1 and 10000")
	}
	maxUpload := rtLogsOr(body.MaxUploadMB, site.MaxUploadMB)
	if maxUpload < 1 || maxUpload > 10240 {
		return apiErr(http.StatusBadRequest, "Max upload must be between 1 and 10240 MB")
	}
	phpMemory := rtLogsOr(body.PHPMemoryMB, site.PHPMemoryMB)
	if phpMemory < 32 || phpMemory > 4096 {
		return apiErr(http.StatusBadRequest, "PHP memory must be between 32 and 4096 MB")
	}
	phpWorkers := rtLogsOr(body.PHPMaxWorkers, site.PHPMaxWorkers)
	if phpWorkers < 1 || phpWorkers > 100 {
		return apiErr(http.StatusBadRequest, "PHP workers must be between 1 and 100")
	}
	if body.CustomNginx != nil && *body.CustomNginx != "" {
		if msg := isSafeNginxConfig(*body.CustomNginx); msg != "" {
			return apiErr(http.StatusBadRequest, msg)
		}
	}
	if q := body.BandwidthQuotaMB; q != nil && *q < 1 {
		return apiErr(http.StatusBadRequest, "Bandwidth quota must be at least 1 MB")
	}

	// A quota edit that lifts a site out of over-quota territory shouldn't
	// leave it disabled until the traffic scheduler's next tick (up to 5
	// minutes) notices — recover it here, in the same request.
	recovering := false
	if site.BandwidthSuspendedAt != nil {
		if body.BandwidthQuotaMB == nil {
			recovering = true
		} else {
			used, _ := queryScalarOpt[int64](ctx, st.DB,
				"SELECT bytes_used FROM site_traffic_usage WHERE site_id = $1 AND year_month = $2",
				id, time.Now().UTC().Format("2006-01"))
			u := int64(0)
			if used != nil {
				u = *used
			}
			recovering = u <= int64(*body.BandwidthQuotaMB)*1024*1024
		}
	}
	newEnabled, newSuspendedAt := site.Enabled, site.BandwidthSuspendedAt
	if recovering {
		newEnabled, newSuspendedAt = true, nil
	}

	updated, err := queryOne[Site](ctx, st.DB,
		"UPDATE sites SET rate_limit = $1, max_upload_mb = $2, php_memory_mb = $3, php_max_workers = $4, "+
			"custom_nginx = $5, bandwidth_quota_mb = $6, enabled = $7, bandwidth_suspended_at = $8, "+
			"updated_at = NOW() WHERE id = $9 RETURNING *",
		body.RateLimit, maxUpload, phpMemory, phpWorkers, body.CustomNginx, body.BandwidthQuotaMB, newEnabled, newSuspendedAt, id)
	if err != nil {
		return internalError("update limits", err)
	}

	// Rebuild the FULL vhost from the post-update row (new limits AND the
	// site's WAF/CSP/Permissions-Policy/bot-protection).
	if _, err := agent.Put(ctx, "/nginx/sites/"+site.Domain, rtSitesBuildNginxBody(&updated)); err != nil {
		return agentError("Resource limits", err)
	}
	if recovering {
		if _, err := agent.Post(ctx, "/nginx/sites/"+site.Domain+"/enable", nil); err != nil {
			slog.Warn(fmt.Sprintf("Bandwidth quota update: failed to re-enable %s at the agent after lifting suspension: %v", site.Domain, err))
		} else {
			ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.bandwidth_suspension_lifted", new("site"), &site.Domain,
				new("quota raised or removed"), nil, c.KeyID)
		}
	}
	slog.Info("Resource limits updated for " + site.Domain)
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.limits", new("site"), &site.Domain, nil, nil, c.KeyID)
	writeJSON(w, http.StatusOK, updated)
	return nil
}

// rtSitesBandwidthUsage is GET /api/sites/{id}/bandwidth-usage — this
// month's bytes against quota, suspension state, and up to 12 months.
func rtSitesBandwidthUsage(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	site, err := rtSitesSiteByCaller(ctx, st, id, c, "bandwidth usage", "Site not found")
	if err != nil {
		return err
	}
	yearMonth := time.Now().UTC().Format("2006-01")
	used, err := queryScalarOpt[int64](ctx, st.DB,
		"SELECT bytes_used FROM site_traffic_usage WHERE site_id = $1 AND year_month = $2", id, yearMonth)
	if err != nil {
		return internalError("bandwidth usage", err)
	}
	history, err := queryAll[Tup2[string, int64]](ctx, st.DB,
		"SELECT year_month, bytes_used FROM site_traffic_usage WHERE site_id = $1 "+
			"ORDER BY year_month DESC LIMIT 12", id)
	if err != nil {
		return internalError("bandwidth usage", err)
	}
	hist := make([]any, 0, len(history))
	for _, h := range history {
		hist = append(hist, map[string]any{"year_month": h.A, "bytes_used": h.B})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"quota_mb":              site.BandwidthQuotaMB,
		"used_bytes_this_month": rtLogsOr(used, 0),
		"suspended_at":          site.BandwidthSuspendedAt,
		"year_month":            yearMonth,
		"history":               hist,
	})
	return nil
}

// rtSitesRemove is DELETE /api/sites/{id} — delete a site and everything it owns.
func rtSitesRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	site, err := rtSitesSiteByCaller(ctx, st, id, c, "remove sites", "Site not found")
	if err != nil {
		return err
	}
	// Every destructive step below names this site by DOMAIN and runs on
	// whichever host this handle points at. Taking it from the caller's
	// selection aimed a fleet member's databases, firewall rule, Redis index
	// and webroot at the panel host — and the firewall arm is not
	// domain-namespaced, so it could match an unrelated rule. The row names
	// the host.
	agent, err := agentForSiteServer(ctx, st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}

	// Pre-delete backup: BEFORE anything destructive runs. It used to sit after
	// `DELETE /nginx/sites/{domain}` (which removes the site root), so it
	// failed 100% of the time into a discarded result — the "backup before
	// permanent deletion" had never written a byte. Still best-effort, but a
	// failure is now LOGGED, and the databases are included (still alive here).
	dbs := rtBackupsSiteDatabasesFor(ctx, st, id)
	if info, err := agent.Post(ctx, "/backups/"+site.Domain+"/create", map[string]any{"reason": "pre-delete", "databases": dbs.Specs}); err != nil {
		slog.Warn(fmt.Sprintf("Pre-delete backup for %s FAILED — continuing with deletion: %v", site.Domain, err))
	} else {
		name, ok := jsonStr(jsonGet(info, "filename"))
		if !ok {
			name = "(unnamed)"
		}
		slog.Info(fmt.Sprintf("Pre-delete backup for %s created: %s", site.Domain, name))
	}

	// Remove database containers before CASCADE deletes the records. The NAME
	// is carried too: a dump directory is keyed by it and exists whether or not
	// a container still runs — selecting only the container id is why site
	// deletion left every dump on disk.
	databases, _ := queryAll[Tup2[string, *string]](ctx, st.DB, "SELECT name, container_id FROM databases WHERE site_id = $1", id)

	// Remote-access stream proxies die before the containers they point at:
	// their rows cascade away below, but the nginx files and firewall rules
	// live on the agent. Abort on failure — a surviving listener would be a
	// public port the panel no longer records.
	proxies, _ := queryAll[Tup2[string, int32]](ctx, st.DB,
		"SELECT p.name, p.listen_port FROM tcp_proxies p "+
			"JOIN databases d ON d.id = p.database_id WHERE d.site_id = $1", id)
	for _, p := range proxies {
		if _, err := agent.Delete(ctx, fmt.Sprintf("/nginx/streams/%s?listen_port=%d", p.A, p.B)); err != nil {
			return agentError("Database remote access removal", err)
		}
	}
	for _, d := range databases {
		if d.B == nil || *d.B == "" {
			continue
		}
		if _, err := agent.Delete(ctx, "/databases/"+*d.B); err != nil {
			slog.Warn(fmt.Sprintf("Failed to remove database container %s: %v", *d.B, err))
		}
	}

	// GAP 50: remove the deny rule for the proxy port.
	if site.ProxyPort != nil {
		port := *site.ProxyPort
		if fw, err := agent.Get(ctx, "/security/firewall"); err == nil {
			rules, _ := jsonArr(jsonGet(fw, "rules"))
			for _, rule := range rules {
				rp, _ := jsonStr(jsonGet(rule, "port"))
				ra, _ := jsonStr(jsonGet(rule, "action"))
				if rp == fmt.Sprintf("%d/tcp", port) && strings.Contains(strings.ToLower(ra), "deny") {
					if num, ok := jsonU64(jsonGet(rule, "number")); ok {
						_, _ = agent.Delete(ctx, fmt.Sprintf("/security/firewall/rules/%d", num))
						slog.Info(fmt.Sprintf("Auto-firewall: removed deny rule for port %d", port))
					}
				}
			}
		}
	}

	// Flush the site's Redis DB if Redis cache was enabled.
	if site.RedisCache {
		if _, err := agent.Post(ctx, "/nginx/sites/"+site.Domain+"/redis/purge", map[string]any{"redis_db": site.RedisDB}); err != nil {
			slog.Warn(fmt.Sprintf("Best-effort Redis purge failed for %s: %v", site.Domain, err))
		}
	}

	// Tear down the SFTP account BEFORE the directory goes, which keeps
	// deprovision's contract simple (it always fully reverts the box).
	if site.SFTPEnabled && site.SFTPUID != nil && site.SFTPGID != nil {
		others, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM sites WHERE sftp_enabled = true AND id != $1", id)
		if err != nil {
			others = 1 // fail toward NOT removing the shared sshd drop-in
		}
		if _, err := agent.Post(ctx, "/sftp/sites/"+site.Domain+"/disable", map[string]any{
			"uid": *site.SFTPUID, "gid": *site.SFTPGID, "last_sftp_site": others == 0,
		}); err != nil {
			slog.Warn(fmt.Sprintf("SFTP teardown failed for %s during site deletion — continuing: %v", site.Domain, err))
		}
	}

	// Remove nginx config + SSL + PHP pool + site files + logs.
	if _, err := agent.Delete(ctx, "/nginx/sites/"+site.Domain); err != nil {
		return agentError("Site removal", err)
	}

	// Remove crontab entries before CASCADE deletes the rows.
	crons, _ := queryAll[uuid.UUID](ctx, st.DB, "SELECT id FROM crons WHERE site_id = $1", id)
	for _, cronID := range crons {
		if _, err := agent.Delete(ctx, "/crons/remove/"+cronID.String()); err != nil {
			slog.Warn(fmt.Sprintf("Failed to remove crontab entry %s: %v", cronID, err))
		}
	}

	// Monitors linked to this site (FK is SET NULL, not CASCADE).
	_, _ = execSQL(ctx, st.DB, "DELETE FROM monitors WHERE site_id = $1", id)

	// Status page components matching this domain — scoped to the owner.
	// The name is free text with no unique constraint; without user_id this
	// deleted every OTHER account's component of the same name.
	_, _ = execSQL(ctx, st.DB, "DELETE FROM status_page_components WHERE name = $1 AND user_id = $2", site.Domain, c.Sub)

	// Delete from DB (CASCADE removes databases, backups, crons, etc.).
	if _, err := execSQL(ctx, st.DB, "DELETE FROM sites WHERE id = $1", id); err != nil {
		return internalError("remove sites", err)
	}

	// Take each database's dumps with it, now that the cascade has removed the
	// rows that would otherwise answer "is this name still in use" about
	// themselves.
	//
	// ⛔ THE ORDER IS THE GUARD. Above the DELETE every name is still claimed —
	// by the row being deleted — so the probe answers "shared", nothing is
	// purged, and the log reads like a correct decision. This is pinned.
	for _, d := range databases {
		rtDatabasesPurgeDumpsIfUnclaimed(ctx, st, agent, d.A, site.ServerID)
	}

	// Decrement the reseller site counter.
	_, _ = execSQL(ctx, st.DB,
		"UPDATE reseller_profiles SET used_sites = GREATEST(used_sites - 1, 0), updated_at = NOW() "+
			"WHERE user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL)", c.Sub)

	slog.Info("Site deleted: " + site.Domain)
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.delete", new("site"), &site.Domain, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "site.delete", &c.Email, ip, new("site"), &site.Domain, nil, nil, "critical", c.KeyID)

	// Deliberately unlinked: this notification's subject no longer exists,
	// and an unresolvable link silently lands on the Dashboard.
	NotificationsNotifyPanel(ctx, st.DB, &c.Sub, "Site deleted: "+site.Domain,
		"Site and all associated resources have been removed", "info", "site", nil)
	ExtensionsFireEvent(st.DB, "site.deleted", map[string]any{"domain": site.Domain})

	// Auto-cleanup DNS record (best-effort). Reads the address of the host the
	// site actually ran on: the cleanup deletes only a record whose content
	// matches it, so the PANEL's address left a fleet member's record dangling
	// — a subdomain-takeover surface, not merely untidy.
	go rtSitesAutoDNSDelete(context.WithoutCancel(ctx), st, site.Domain, c.Sub, site.ServerID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": site.Domain})
	return nil
}

// rtSitesAutoDNSDelete removes a deleted site's A record from the owner's zone.
func rtSitesAutoDNSDelete(ctx context.Context, st *AppState, domain string, userID uuid.UUID, serverID *uuid.UUID) {
	parent := rtSitesParentDomain(domain)
	zone, err := queryOpt[rtSitesDNSZone](ctx, st.DB,
		"SELECT provider, cf_zone_id, cf_api_token, cf_api_email FROM dns_zones WHERE domain = $1 AND user_id = $2", parent, userID)
	if err != nil {
		slog.Warn(fmt.Sprintf("DB error fetching DNS zone for auto-cleanup on site delete: %v", err))
		return
	}
	if zone == nil {
		return
	}
	ip := publicIPForServer(ctx, st.DB, serverID)
	if ip == nil {
		slog.Warn(fmt.Sprintf("Auto-DNS cleanup: could not resolve the public address of the server %s lived on — leaving the record in place rather than deleting one that may belong to another host", domain))
		return
	}
	serverIP := *ip
	switch zone.Provider {
	case "cloudflare":
		if zone.CfZoneID == nil || zone.CfAPIToken == nil {
			return
		}
		zid := *zone.CfZoneID
		h := cfHeaders(*zone.CfAPIToken, zone.CfAPIEmail)
		// Find the A record for this domain.
		resp, err := rtSitesSendJSON(ctx, http.MethodGet, "https://api.cloudflare.com/client/v4/zones/"+zid+"/dns_records?type=A&name="+domain, h, nil)
		if err != nil {
			return
		}
		raw, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			return
		}
		data, err := agentDecodeJSON(raw)
		if err != nil {
			return
		}
		records, _ := jsonArr(jsonGet(data, "result"))
		for _, rec := range records {
			rid, ok1 := jsonStr(jsonGet(rec, "id"))
			content, ok2 := jsonStr(jsonGet(rec, "content"))
			if ok1 && ok2 && content == serverIP {
				if dr, err := rtSitesSendJSON(ctx, http.MethodDelete, "https://api.cloudflare.com/client/v4/zones/"+zid+"/dns_records/"+rid, h, nil); err == nil {
					dr.Body.Close()
				}
				slog.Info("Auto-DNS cleanup: deleted A record " + domain)
			}
		}
	case "powerdns":
		if url, key, ok := rtSitesPDNSSettings(ctx, st.DB); ok {
			zfqdn := parent
			if !strings.HasSuffix(zfqdn, ".") {
				zfqdn += "."
			}
			resp, err := rtSitesSendJSON(ctx, http.MethodPatch, url+"/api/v1/servers/localhost/zones/"+zfqdn,
				http.Header{"X-Api-Key": {key}},
				map[string]any{"rrsets": []any{map[string]any{"name": domain + ".", "type": "A", "ttl": 300, "changetype": "DELETE", "records": []any{}}}})
			if err == nil {
				resp.Body.Close()
			}
			slog.Info("Auto-DNS cleanup (PowerDNS): deleted A record " + domain)
		}
	}
}

// ── Redirect rules, password protection, aliases (proxy to agent) ──

// rtSitesSiteGet is AuthUser + Path(id) + a GET on the site's own agent.
func rtSitesSiteGet(st *AppState, w http.ResponseWriter, r *http.Request, path func(domain string) string, what string) error {
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), path(domain))
	if err != nil {
		return agentError(what, err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtSitesSitePostRaw is AuthUser + Path(id) + Json<Value> forwarded as-is.
func rtSitesSitePostRaw(st *AppState, w http.ResponseWriter, r *http.Request, path func(domain string) string, what string) error {
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	var body json.RawMessage
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), path(domain), body)
	if err != nil {
		return agentError(what, err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtSitesShellMeta is the metacharacter set redirect/protect inputs refuse.
const rtSitesShellMeta = ";|&$`'\"\\\n\r\x00"

// rtSitesListRedirects is GET /api/sites/{id}/redirects.
func rtSitesListRedirects(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesSiteGet(st, w, r, func(d string) string { return "/nginx/redirects/" + d }, "Redirects")
}

type rtSitesAddRedirectBody struct {
	Source       string `json:"source"`
	Target       string `json:"target"`
	RedirectType string `json:"redirect_type" serde:"default"`
}

// rtSitesAddRedirect is POST /api/sites/{id}/redirects.
func rtSitesAddRedirect(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	body := rtSitesAddRedirectBody{RedirectType: "301"}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	// Source: must start with / and carry no shell metacharacters.
	if !strings.HasPrefix(body.Source, "/") || strings.ContainsAny(body.Source, rtSitesShellMeta) {
		return apiErr(http.StatusBadRequest, "Invalid redirect source: must start with / and contain no shell metacharacters")
	}
	// Target: an http(s) URL or a path.
	if !(strings.HasPrefix(body.Target, "http://") || strings.HasPrefix(body.Target, "https://") || strings.HasPrefix(body.Target, "/")) {
		return apiErr(http.StatusBadRequest, "Invalid redirect target: must be a URL (http/https) or path (starts with /)")
	}
	if strings.ContainsAny(body.Target, rtSitesShellMeta) {
		return apiErr(http.StatusBadRequest, "Invalid redirect target: contains shell metacharacters")
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), "/nginx/redirects/add", map[string]any{
		"domain": domain, "source": body.Source, "target": body.Target, "redirect_type": body.RedirectType,
	})
	if err != nil {
		return agentError("Redirects", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtSitesRemoveRedirect is POST /api/sites/{id}/redirects/remove.
func rtSitesRemoveRedirect(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesSitePostRaw(st, w, r, func(d string) string { return "/nginx/redirects/" + d + "/remove" }, "Redirects")
}

// rtSitesListProtected is GET /api/sites/{id}/password-protect.
func rtSitesListProtected(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesSiteGet(st, w, r, func(d string) string { return "/nginx/password-protect/" + d }, "Password protection")
}

type rtSitesPasswordProtectBody struct {
	Path     string `json:"path"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// rtSitesAddPasswordProtect is POST /api/sites/{id}/password-protect.
func rtSitesAddPasswordProtect(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	var body rtSitesPasswordProtectBody
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	// Path: no traversal, no shell metacharacters.
	if strings.Contains(body.Path, "..") || strings.ContainsAny(body.Path, rtSitesShellMeta) {
		return apiErr(http.StatusBadRequest, "Invalid path: must not contain '..' or shell metacharacters")
	}
	// Username: alphanumeric (Unicode, as char::is_alphanumeric) + _ and -.
	if body.Username == "" || strings.ContainsFunc(body.Username, func(c rune) bool {
		return !(unicode.IsLetter(c) || unicode.IsNumber(c) || c == '_' || c == '-')
	}) {
		return apiErr(http.StatusBadRequest, "Invalid username: must be alphanumeric (underscores and hyphens allowed)")
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), "/nginx/password-protect", map[string]any{
		"domain": domain, "path": body.Path, "username": body.Username, "password": body.Password,
	})
	if err != nil {
		return agentError("Password protection", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtSitesRemovePasswordProtect is POST /api/sites/{id}/password-protect/remove.
func rtSitesRemovePasswordProtect(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesSitePostRaw(st, w, r, func(d string) string { return "/nginx/password-protect/" + d + "/remove" }, "Password protection")
}

// rtSitesListAliases is GET /api/sites/{id}/aliases.
func rtSitesListAliases(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesSiteGet(st, w, r, func(d string) string { return "/nginx/aliases/" + d }, "Domain aliases")
}

type rtSitesAddAliasBody struct {
	Alias string `json:"alias"`
}

// rtSitesAddAlias is POST /api/sites/{id}/aliases.
func rtSitesAddAlias(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	var body rtSitesAddAliasBody
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if !isValidDomain(body.Alias) {
		return apiErr(http.StatusBadRequest, "Invalid alias: must be a valid domain name")
	}
	// The host is needed as a VALUE, so both come from the row: taking the id
	// from the caller's selection ran the collision check against one machine
	// while the alias was written on another.
	type row struct {
		Domain   string     `db:"domain"`
		ServerID *uuid.UUID `db:"server_id"`
	}
	site, err := queryOpt[row](ctx, st.DB, "SELECT s.domain, s.server_id FROM sites s WHERE "+SiteCallerPredicate, id, c.Sub)
	if err != nil {
		return internalError("add alias", err)
	}
	if site == nil {
		return apiErr(http.StatusNotFound, "Site not found")
	}
	agent, err := agentForSiteServer(ctx, st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}
	// An alias becomes a server_name on the caller's own vhost: without this
	// guard any tenant could attach ANOTHER tenant's (or the panel's) live
	// domain and hijack its traffic / intercept its ACME HTTP-01 challenge.
	alias, err := rtSitesEnsureDomainAvailable(ctx, st, body.Alias, r, c.Role)
	if err != nil {
		return err
	}
	res, err := agent.Post(ctx, "/nginx/aliases/add", map[string]any{"domain": site.Domain, "alias": alias})
	if err != nil {
		return agentError("Domain aliases", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtSitesRemoveAlias is POST /api/sites/{id}/aliases/remove.
func rtSitesRemoveAlias(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesSitePostRaw(st, w, r, func(d string) string { return "/nginx/aliases/" + d + "/remove" }, "Domain aliases")
}

// ── Access logs, traffic stats, PHP errors, health ──

// rtSitesAccessLogs is GET /api/sites/{id}/access-logs.
func rtSitesAccessLogs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	params := rtLogsQueryMap(r)
	lines, ok := params["lines"]
	if !ok {
		lines = "200"
	}
	logType, ok := params["type"]
	if !ok {
		logType = "access"
	}
	return rtSitesSiteGet(st, w, r, func(d string) string {
		return fmt.Sprintf("/nginx/site-logs/%s?lines=%s&log_type=%s", d, lines, logType)
	}, "Site logs")
}

// rtSitesSiteStats is GET /api/sites/{id}/stats.
func rtSitesSiteStats(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesSiteGet(st, w, r, func(d string) string { return "/nginx/site-stats/" + d }, "Site stats")
}

// rtSitesPhpErrors is GET /api/sites/{id}/php-errors.
func rtSitesPhpErrors(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesSiteGet(st, w, r, func(d string) string { return "/nginx/php-errors/" + d }, "PHP errors")
}

// rtSitesHealthCheck is GET /api/sites/{id}/health — is the site responding?
func rtSitesHealthCheck(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	domain, err := siteDomainForCaller(ctx, st, id, c)
	if err != nil {
		return err
	}
	ssl, _ := queryScalarOpt[bool](ctx, st.DB, "SELECT ssl_enabled FROM sites WHERE id = $1", id)
	url := "http://" + domain
	if ssl != nil && *ssl {
		url = "https://" + domain
	}

	start := time.Now()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(url)
	elapsed := uint32(time.Since(start).Milliseconds())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"healthy": false, "status": 0, "response_time_ms": elapsed, "error": err.Error(), "url": url,
		})
		return nil
	}
	resp.Body.Close()
	writeJSON(w, http.StatusOK, map[string]any{
		"healthy": resp.StatusCode < 500, "status": resp.StatusCode, "response_time_ms": elapsed, "url": url,
	})
	return nil
}

// rtSitesHealthSummary is GET /api/sites/{id}/health-summary — composite
// site health score.
func rtSitesHealthSummary(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	site, err := queryOpt[Tup3[string, bool, *time.Time]](ctx, st.DB,
		"SELECT s.domain, s.ssl_enabled, s.ssl_expiry FROM sites s WHERE "+SiteCallerPredicate, id, c.Sub)
	if err != nil {
		return internalError("health summary", err)
	}
	if site == nil {
		return apiErr(http.StatusNotFound, "Site not found")
	}
	domain, sslEnabled, sslExpiry := site.A, site.B, site.C
	now := time.Now()

	var sslDays *int64
	if sslExpiry != nil {
		sslDays = new(int64(sslExpiry.Sub(now) / (24 * time.Hour)))
	}

	lastBackup, err := queryScalarOpt[time.Time](ctx, st.DB,
		"SELECT created_at FROM backups WHERE site_id = $1 ORDER BY created_at DESC LIMIT 1", id)
	if err != nil {
		return internalError("health summary backup check", err)
	}
	var backupHours *int64
	if lastBackup != nil {
		backupHours = new(int64(now.Sub(*lastBackup) / time.Hour))
	}

	monitor, err := queryOpt[Tup3[string, *int32, bool]](ctx, st.DB,
		"SELECT status, last_response_time, enabled FROM monitors WHERE site_id = $1 ORDER BY created_at DESC LIMIT 1", id)
	if err != nil {
		return internalError("health summary monitor check", err)
	}
	var monitorStatus *string
	var responseTime *int32
	monitorEnabled := false
	if monitor != nil {
		monitorStatus, responseTime, monitorEnabled = &monitor.A, monitor.B, monitor.C
	}

	score := rtSitesHealthScore(sslEnabled, sslDays, backupHours, monitorStatus, responseTime, monitorEnabled)
	writeJSON(w, http.StatusOK, map[string]any{
		"domain":           domain,
		"ssl_status":       map[string]any{"enabled": sslEnabled, "days_until_expiry": sslDays},
		"backup_freshness": map[string]any{"last_backup": lastBackup, "hours_since": backupHours},
		"uptime": map[string]any{
			"status": monitorStatus, "response_time_ms": responseTime, "monitor_enabled": monitorEnabled,
		},
		"score": score,
	})
	return nil
}

// rtSitesHealthScore computes the 0-100 composite score.
func rtSitesHealthScore(sslEnabled bool, sslDays, backupHours *int64, monitorStatus *string, responseTime *int32, monitorEnabled bool) int32 {
	score := int32(100)
	// No SSL: -25; expired -25, <7 days -15, <30 days -5.
	if !sslEnabled {
		score -= 25
	} else if sslDays != nil {
		switch d := *sslDays; {
		case d < 0:
			score -= 25
		case d < 7:
			score -= 15
		case d < 30:
			score -= 5
		}
	}
	// Stale backup: none at all -30, >48h -20, >24h -10.
	switch {
	case backupHours == nil:
		score -= 30
	case *backupHours > 48:
		score -= 20
	case *backupHours > 24:
		score -= 10
	}
	// Monitor down: -20; slow response -15/-10/-5.
	if monitorStatus != nil && *monitorStatus == "down" {
		score -= 20
	}
	if responseTime != nil {
		switch rt := *responseTime; {
		case rt > 5000:
			score -= 15
		case rt > 2000:
			score -= 10
		case rt > 1000:
			score -= 5
		}
	}
	// No monitor at all, or disabled: -5.
	if monitorStatus == nil || !monitorEnabled {
		score -= 5
	}
	return max(score, 0)
}

// ── Site cloning ──

// rtSitesCloneSite is POST /api/sites/{id}/clone — clone a site to a new domain.
func rtSitesCloneSite(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	body, err := rtSitesDecodeValue(r)
	if err != nil {
		return err
	}
	targetDomain, ok := jsonStr(jsonGet(body, "domain"))
	if !ok {
		return apiErr(http.StatusBadRequest, "Target domain required")
	}
	if !isValidDomain(targetDomain) {
		return apiErr(http.StatusBadRequest, "Invalid target domain format")
	}
	source, err := rtSitesSiteByCaller(ctx, st, id, c, "clone site", "Source site not found")
	if err != nil {
		return err
	}

	// A clone is ONE agent operation (/nginx/clone-site reads the source
	// docroot and writes the target on the same box), so when the source lives
	// elsewhere there is no host that can do it — and the old code asked the
	// SELECTED one after reserving quota and inserting the row, leaving the
	// caller owning a site whose files never arrived. Refuse up front.
	if source.ServerID == nil || *source.ServerID != serverID {
		return apiErr(http.StatusConflict, "This site lives on a different server. Select that server to clone it — "+
			"cloning across servers is not supported yet.")
	}

	// Clone creates a brand-new site and must enforce the SAME admission
	// controls create() does — it used to bypass lockdown, the rate limit, the
	// reseller quota, the reserved-domain block and the cross-table uniqueness
	// check, even overwriting another tenant's git-deployed domain.
	if SecurityHardeningIsLockedDown(ctx, st.DB) {
		return apiErr(http.StatusServiceUnavailable, "System is in lockdown mode")
	}
	maxSites := rtSitesSiteRateLimit(ctx, st.DB)
	recent, err := queryScalar[int64](ctx, st.DB,
		"SELECT COUNT(*) FROM sites WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 hour'", c.Sub)
	if err != nil {
		recent = 0
	}
	if recent >= maxSites {
		return rtSitesRateLimitMsg(maxSites)
	}
	targetDomain, err = rtSitesEnsureDomainAvailable(ctx, st, targetDomain, r, c.Role)
	if err != nil {
		return err
	}
	// Reserve the quota slot AFTER the fallible domain checks so a rejected
	// clone cannot leak one; release it if the INSERT fails. If a later agent
	// step fails, the row persists and legitimately holds the slot.
	slotReserved, err := rtSitesReserveResellerSiteSlot(ctx, st, c.Sub)
	if err != nil {
		return err
	}

	newSite, err := queryOne[Site](ctx, st.DB,
		"INSERT INTO sites (user_id, server_id, domain, runtime, status, php_version, root_path, rate_limit, max_upload_mb, php_memory_mb, php_max_workers, php_preset, app_command) "+
			"VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *",
		c.Sub, serverID, targetDomain, source.Runtime, source.PHPVersion, source.RootPath, source.RateLimit,
		source.MaxUploadMB, source.PHPMemoryMB, source.PHPMaxWorkers, source.PHPPreset, source.AppCommand)
	if err != nil {
		if slotReserved {
			rtSitesReleaseResellerSiteSlot(ctx, st, c.Sub)
		}
		if msg := err.Error(); strings.Contains(msg, "duplicate") || strings.Contains(msg, "unique") {
			return apiErr(http.StatusConflict, "A site with this domain already exists")
		}
		return internalError("clone site", err)
	}

	// Clone files via the agent.
	if _, err := agent.Post(ctx, "/nginx/clone-site", map[string]any{"source_domain": source.Domain, "target_domain": targetDomain}); err != nil {
		return agentError("Clone", err)
	}

	// Set up nginx for the new site.
	nginxBody := map[string]any{"runtime": source.Runtime, "root": "/var/www"}
	if source.ProxyPort != nil {
		nginxBody["proxy_port"] = *source.ProxyPort
	}
	if source.PHPVersion != nil {
		nginxBody["php_socket"] = rtSitesPHPSocket(*source.PHPVersion)
	}
	if source.PHPPreset != nil {
		nginxBody["php_preset"] = *source.PHPPreset
	}
	nginxBody["fastcgi_cache"] = source.FastCGICache
	nginxBody["redis_cache"] = source.RedisCache
	nginxBody["redis_db"] = source.RedisDB
	nginxBody["waf_enabled"] = source.WAFEnabled
	nginxBody["waf_mode"] = source.WAFMode
	if _, err := agent.Put(ctx, "/nginx/sites/"+targetDomain, nginxBody); err != nil {
		return agentError("Nginx config", err)
	}

	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.clone", new("site"), &targetDomain, &source.Domain, nil, c.KeyID)
	// Reseller site counter already incremented atomically by the reserve above.
	ExtensionsFireEvent(st.DB, "site.created", map[string]any{
		"site_id": newSite.ID, "domain": targetDomain, "runtime": source.Runtime, "cloned_from": source.Domain,
	})

	bg := context.WithoutCancel(ctx)
	newID, userID := newSite.ID, c.Sub
	// Auto-create the backup schedule (daily 3 AM, 7 kept).
	go func() {
		_, _ = execSQL(bg, st.DB, "INSERT INTO backup_schedules (site_id, schedule, retention_count, enabled) "+
			"VALUES ($1, '0 3 * * *', 7, true) ON CONFLICT (site_id) DO NOTHING", newID)
		slog.Info("Auto-backup: created daily schedule for cloned site")
	}()
	// Auto-create the secrets vault.
	go func() {
		_, _ = execSQL(bg, st.DB, "INSERT INTO secret_vaults (user_id, name, description, site_id) "+
			"VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
			userID, targetDomain+" secrets", "Auto-created vault for "+targetDomain, newID)
		slog.Info("Auto-vault: created for cloned site " + targetDomain)
	}()
	// Auto-create a status page component if enabled.
	go rtSitesAutoStatusComponent(bg, st, userID, targetDomain, "cloned site ", "status page config for cloned site auto-component")

	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "site_id": newSite.ID, "domain": targetDomain})
	return nil
}

// ── Custom SSL upload ──

// rtSitesUploadSsl is POST /api/sites/{id}/ssl/upload.
func rtSitesUploadSsl(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	body, err := rtSitesDecodeValue(r)
	if err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(ctx, st, id, c)
	if err != nil {
		return err
	}
	agentBody, err := rtSitesObj(body, "ssl upload")
	if err != nil {
		return err
	}
	agentBody["domain"] = domain
	uploaded, err := agent.Post(ctx, "/ssl/upload", agentBody)
	if err != nil {
		return agentError("SSL upload", err)
	}

	// Record WHAT was installed, not merely THAT something was. This wrote
	// ssl_enabled alone, while every downstream reader (Dashboard SSL tile,
	// alert_engine's expiry ladder, auto_healer) filters on ssl_expiry IS NOT
	// NULL — so an operator-supplied certificate, the kind nobody renews for
	// you, was invisible to the countdown, the pager and the healer alike.
	var certPath, keyPath *string
	if s, ok := jsonStr(jsonGet(uploaded, "cert_path")); ok {
		certPath = &s
	}
	if s, ok := jsonStr(jsonGet(uploaded, "key_path")); ok {
		keyPath = &s
	}
	// Prefer the expiry the upload reported; /ssl/status is the compatibility
	// path for an agent older than this release (every agent carries it).
	var expiry *time.Time
	if s, ok := jsonStr(jsonGet(uploaded, "expiry")); ok {
		expiry = parseAgentCertExpiry(s)
	}
	if expiry == nil {
		if status, err := agent.Get(ctx, "/ssl/status/"+domain); err == nil {
			if s, ok := jsonStr(jsonGet(status, "not_after")); ok {
				expiry = parseAgentCertExpiry(s)
			}
		} else {
			slog.Warn(fmt.Sprintf("Uploaded certificate for %s is installed, but its expiry could not be read back: %v", domain, err))
		}
	}
	if expiry == nil {
		slog.Warn(fmt.Sprintf("Uploaded certificate for %s stored with no new expiry — the previous value is kept rather than cleared, so the site stays visible to the expiry ladder and the auto-healer", domain))
	}

	// The provenance columns describe how the PANEL ordered the certificate
	// this upload replaced; both renewal doors and the auto-healer read them,
	// so leaving them would apply a retired certificate's terms to whatever
	// was just installed. Cleared, not preserved — unlike the three COALESCEd
	// siblings, where keeping a known value beats erasing it.
	if _, err := execSQL(ctx, st.DB,
		"UPDATE sites SET ssl_enabled = true, ssl_cert_path = COALESCE($1, ssl_cert_path), "+
			"ssl_key_path = COALESCE($2, ssl_key_path), ssl_expiry = COALESCE($3, ssl_expiry), "+
			"ssl_profile = NULL, "+
			"ssl_challenge = NULL, ssl_cert_subject = NULL, ssl_wildcard = NULL, "+
			"ssl_dns_zone_id = NULL, "+
			"ssl_renewal_at = NULL, ssl_renewal_checked_at = NULL, updated_at = NOW() WHERE id = $4",
		certPath, keyPath, expiry, id); err != nil {
		slog.Warn(fmt.Sprintf("Failed to record uploaded certificate for site %s: %v", id, err))
	}

	// Re-render the FULL vhost from the DB row. The agent's /ssl/upload knows
	// only {domain, certificate, private_key} and invents the rest — WAF off,
	// no CSP, no custom_nginx, and an unversioned php-fpm.sock that exists on
	// no modern Debian/Ubuntu, i.e. a 502. Provision/renew/force-renew got this
	// compensation in v2.18.0; upload was the missed fourth sibling.
	rtSslRebuildVhostAfterSsl(ctx, st, agent, id)

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "ssl.upload", new("site"), &domain, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "ssl.upload", &c.Email, ip, new("site"), &domain, nil, nil, "warning", c.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// ── PHP extensions ──

// rtSitesPhpExtensions is GET /api/php/extensions/{version}.
func rtSitesPhpExtensions(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesScopedGet(st, w, r, "/php/extensions/"+r.PathValue("version"), "PHP extensions")
}

// rtSitesInstallPhpExtension is POST /api/php/extensions/install — a
// package-level op on the shared server, admin-only like php_install.
func rtSitesInstallPhpExtension(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body json.RawMessage
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if c.Role != "admin" {
		return apiErr(http.StatusForbidden, "Admin only")
	}
	if _, err := agent.Post(r.Context(), "/php/extensions/install", body); err != nil {
		return agentError("PHP extension", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// ── Environment variables ──

// rtSitesGetEnvVars is GET /api/sites/{id}/env.
func rtSitesGetEnvVars(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtSitesSiteGet(st, w, r, func(d string) string { return "/nginx/env/" + d }, "Env vars")
}

// rtSitesSetEnvVars is PUT /api/sites/{id}/env.
func rtSitesSetEnvVars(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	var body json.RawMessage
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	if _, err := agent.Put(r.Context(), "/nginx/env/"+domain, body); err != nil {
		return agentError("Env vars", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtSitesSemverAtLeast is panel_update::semver_key(reported) >=
// semver_key(Some(min)): a missing version sorts first; "v" and any
// "-suffix" are ignored; unparseable parts read as 0.
func rtSitesSemverAtLeast(reported *string, minVersion string) bool {
	key := func(v *string) [4]uint64 {
		if v == nil {
			return [4]uint64{}
		}
		core := strings.TrimLeft(*v, "v")
		core, _, _ = strings.Cut(core, "-")
		k := [4]uint64{1}
		for i, p := range strings.SplitN(core, ".", 4) {
			if i < 3 {
				k[i+1], _ = strconv.ParseUint(p, 10, 64)
			}
		}
		return k
	}
	a, b := key(reported), key(&minVersion)
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

// rtSitesRenameDomain is PUT /api/sites/{id}/domain.
func rtSitesRenameDomain(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	body, err := rtSitesDecodeValue(r)
	if err != nil {
		return err
	}
	// ⚠ Renaming rewrites this site's vhost, so both the claim check and the
	// write must name the host the ROW does, not the caller's selection.
	site, agent, err := rtSitesSiteAndAgent(ctx, st, id, c, "rename domain")
	if err != nil {
		return err
	}
	requested, _ := jsonStr(jsonGet(body, "new_domain"))
	requested = strings.TrimSpace(requested)

	// Format, reserved, and every owner — including Docker apps, which the
	// agent's 8-step rename would have walked straight over (it checks that
	// the SOURCE vhost exists, never that the DESTINATION is free).
	newDomain, err := DomainClaimEnsureClaimable(ctx, st.DB, st.Agents, requested, r, DomainClaimHolderSite(id), c.Role)
	if err != nil {
		return err
	}
	if newDomain == DomainClaimNormalise(site.Domain) {
		return apiErr(http.StatusBadRequest, "New domain is the same as current domain")
	}
	oldDomain := site.Domain

	// An agent older than the carry release renames everything else and
	// silently leaves every backup tree behind under the old name, answering
	// success either way. Refuse — only for a site that actually has archives
	// to lose, which keeps a mid-upgrade fleet usable.
	backupRows, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM backups WHERE site_id = $1", id)
	if err != nil {
		backupRows = 0
	}
	carries := false
	if backupRows > 0 {
		var reported *string
		if health, err := agent.Get(ctx, "/health"); err == nil {
			if v, ok := jsonStr(jsonGet(health, "version")); ok {
				reported = &v
			}
		}
		if !rtSitesSemverAtLeast(reported, rtSitesBackupCarryMinAgent) {
			ver := "an unknown version"
			if reported != nil {
				ver = *reported
			}
			return apiErr(http.StatusPreconditionFailed, fmt.Sprintf(
				"This site has %d backup(s) and the agent on its server reports "+
					"%s, which does not move a site's archives when the domain changes — they "+
					"would be left on disk under %s where nothing can restore them. "+
					"Update that server's agent to %s or later, then "+
					"rename.", backupRows, ver, oldDomain, rtSitesBackupCarryMinAgent))
		}
		carries = true
	}

	if _, err := agent.Post(ctx, "/nginx/sites/"+oldDomain+"/rename", map[string]any{"new_domain": newDomain}); err != nil {
		return agentError("Domain rename", err)
	}

	// ⛔ ssl_cert_path/ssl_key_path MUST move with the domain: the agent just
	// renamed /etc/dockpanel/ssl/{old} to {new}, and build_nginx_body sends
	// the column verbatim on the next rebuild — a stale path re-pointed nginx
	// at a directory that is gone. ⚠ Scoped to the OLD domain's own directory:
	// a DNS-01 wildcard's path names the ZONE and must not be rewritten.
	oldLike := "/etc/dockpanel/ssl/" + oldDomain + "/%"
	if _, err := execSQL(ctx, st.DB,
		"UPDATE sites SET domain = $1, "+
			"ssl_cert_path = CASE WHEN ssl_cert_path LIKE $3 "+
			"THEN '/etc/dockpanel/ssl/' || $1 || '/fullchain.pem' ELSE ssl_cert_path END, "+
			"ssl_key_path = CASE WHEN ssl_key_path LIKE $4 "+
			"THEN '/etc/dockpanel/ssl/' || $1 || '/privkey.pem' ELSE ssl_key_path END, "+
			"updated_at = NOW() WHERE id = $2",
		newDomain, id, oldLike, oldLike); err != nil {
		return internalError("rename domain", err)
	}

	// The agent renamed each archive's `{old}-` prefix to `{new}-`, so the rows
	// follow — both sides derive the same prefix from the same two domains.
	if carries {
		n, err := execSQL(ctx, st.DB,
			"UPDATE backups SET filename = $1 || substring(filename from $3) "+
				"WHERE site_id = $2 AND filename LIKE $4",
			newDomain+"-", id, int32(len(oldDomain)+2), oldDomain+"-%")
		if err != nil {
			slog.Error(fmt.Sprintf("Rename %s to %s: the archives moved but their rows could "+
				"not be re-prefixed (%v). Every backup row for this site now names a file that "+
				"is not there.", oldDomain, newDomain, err))
		} else {
			slog.Info(fmt.Sprintf("Rename %s to %s: re-prefixed %d backup row(s)", oldDomain, newDomain, n))
		}
		// The carry is the one step whose success can be checked from outside,
		// version-independently: anything still listed under the old name was
		// left behind. The agent answers with a bare array, not {backups: …}.
		if v, err := agent.Get(ctx, "/backups/"+oldDomain+"/list"); err == nil {
			if left, _ := jsonArr(v); len(left) > 0 {
				slog.Error(fmt.Sprintf("Rename %s to %s completed, but the agent still "+
					"lists %d backup(s) under %s — the carry did not take "+
					"everything and those archives are unreachable from the panel.", oldDomain, newDomain, len(left), oldDomain))
			}
		} else {
			slog.Warn(fmt.Sprintf("Could not confirm the backup carry for %s: %v", oldDomain, err))
		}
	}

	// Monitors keep whatever scheme they had: rebuilding the URL as https
	// unconditionally switched a monitor onto a scheme nobody asked for.
	_, _ = execSQL(ctx, st.DB, "UPDATE monitors SET name = $1, "+
		"url = CASE WHEN url LIKE 'http://%' THEN 'http://' || $1 ELSE 'https://' || $1 END "+
		"WHERE site_id = $2", newDomain, id)
	// Owner-scoped, like remove's delete: without user_id a rename renamed
	// every other account's component that shared the old domain string.
	_, _ = execSQL(ctx, st.DB, "UPDATE status_page_components SET name = $1 WHERE name = $2 AND user_id = $3", newDomain, oldDomain, c.Sub)

	slog.Info(fmt.Sprintf("Domain renamed: %s → %s", oldDomain, newDomain))
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.rename_domain", new("site"), &newDomain, &oldDomain, nil, c.KeyID)
	NotificationsNotifyPanel(ctx, st.DB, &c.Sub, fmt.Sprintf("Domain renamed: %s → %s", oldDomain, newDomain),
		"Site domain has been updated", "info", "site", new("/sites/"+id.String()))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "old_domain": oldDomain, "new_domain": newDomain})
	return nil
}

// rtSitesToggleBody is the AuthUser + Path + Json<Value> + full-row prologue
// of the toggles.
func rtSitesToggleBody(st *AppState, r *http.Request, what string) (*Claims, uuid.UUID, any, *Site, AgentHandle, error) {
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return nil, id, nil, nil, nil, err
	}
	body, err := rtSitesDecodeValue(r)
	if err != nil {
		return nil, id, nil, nil, nil, err
	}
	site, agent, err := rtSitesSiteAndAgent(r.Context(), st, id, c, what)
	return c, id, body, site, agent, err
}

func rtSitesEnabledField(body any) (bool, error) {
	b, ok := jsonBool(jsonGet(body, "enabled"))
	if !ok {
		return false, apiErr(http.StatusBadRequest, "Missing 'enabled' boolean field")
	}
	return b, nil
}

func rtSitesWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

// rtSitesToggleEnabled is PUT /api/sites/{id}/toggle — enable or disable a
// site without deleting it.
func rtSitesToggleEnabled(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, body, site, agent, err := rtSitesToggleBody(st, r, "toggle site")
	if err != nil {
		return err
	}
	enabled, err := rtSitesEnabledField(body)
	if err != nil {
		return err
	}
	if enabled == site.Enabled {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": enabled,
			"message": rtSitesWord(enabled, "Site is already enabled", "Site is already disabled")})
		return nil
	}
	action := rtSitesWord(enabled, "enable", "disable")
	if _, err := agent.Post(ctx, "/nginx/sites/"+site.Domain+"/"+action, nil); err != nil {
		return agentError("Toggle site", err)
	}
	// A manual re-enable also clears bandwidth_suspended_at, or the traffic
	// scheduler would treat the site as still suspended (never re-checking
	// its quota) though a human just turned it back on.
	if _, err := execSQL(ctx, st.DB,
		"UPDATE sites SET enabled = $1, bandwidth_suspended_at = CASE WHEN $1 THEN NULL ELSE bandwidth_suspended_at END, "+
			"updated_at = NOW() WHERE id = $2", enabled, id); err != nil {
		return internalError("toggle site", err)
	}
	label := rtSitesWord(enabled, "enabled", "disabled")
	slog.Info(fmt.Sprintf("Site %s %s", site.Domain, label))
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site."+label, new("site"), &site.Domain, nil, nil, c.KeyID)
	NotificationsNotifyPanel(ctx, st.DB, &c.Sub, fmt.Sprintf("Site %s: %s", label, site.Domain),
		"Site has been "+label, "info", "site", new("/sites/"+id.String()))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": enabled})
	return nil
}

// rtSitesToggleFastcgiCache is PUT /api/sites/{id}/fastcgi-cache.
func rtSitesToggleFastcgiCache(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, body, site, agent, err := rtSitesToggleBody(st, r, "toggle fastcgi cache")
	if err != nil {
		return err
	}
	if site.Runtime != "php" {
		return apiErr(http.StatusBadRequest, "FastCGI cache is only available for PHP sites")
	}
	enabled, err := rtSitesEnabledField(body)
	if err != nil {
		return err
	}
	if enabled == site.FastCGICache {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "fastcgi_cache": enabled,
			"message": rtSitesWord(enabled, "FastCGI cache is already enabled", "FastCGI cache is already disabled")})
		return nil
	}
	// Rebuild the FULL vhost with only fastcgi_cache changed.
	u := *site
	u.FastCGICache = enabled
	if _, err := agent.Put(ctx, "/nginx/sites/"+site.Domain, rtSitesBuildNginxBody(&u)); err != nil {
		return agentError("FastCGI cache", err)
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE sites SET fastcgi_cache = $1, updated_at = NOW() WHERE id = $2", enabled, id); err != nil {
		return internalError("toggle fastcgi cache", err)
	}
	action := rtSitesWord(enabled, "enabled", "disabled")
	slog.Info(fmt.Sprintf("FastCGI cache %s for %s", action, site.Domain))
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.fastcgi_cache."+action, new("site"), &site.Domain, nil, nil, c.KeyID)
	NotificationsNotifyPanel(ctx, st.DB, &c.Sub, fmt.Sprintf("FastCGI cache %s: %s", action, site.Domain),
		"FastCGI cache has been "+action, "info", "site", new("/sites/"+id.String()))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "fastcgi_cache": enabled})
	return nil
}

// rtSitesPurgeFastcgiCache is POST /api/sites/{id}/fastcgi-cache/purge.
func rtSitesPurgeFastcgiCache(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	site, agent, err := rtSitesSiteAndAgent(ctx, st, id, c, "purge fastcgi cache")
	if err != nil {
		return err
	}
	if !site.FastCGICache {
		return apiErr(http.StatusBadRequest, "FastCGI cache is not enabled for this site")
	}
	if _, err := agent.Post(ctx, "/nginx/sites/"+site.Domain+"/cache/purge", nil); err != nil {
		return agentError("Purge cache", err)
	}
	slog.Info("FastCGI cache purged for " + site.Domain)
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.fastcgi_cache.purge", new("site"), &site.Domain, nil, nil, c.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "FastCGI cache purged for " + site.Domain})
	return nil
}

// rtSitesToggleRedisCache is PUT /api/sites/{id}/redis-cache.
func rtSitesToggleRedisCache(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, body, site, agent, err := rtSitesToggleBody(st, r, "toggle redis cache")
	if err != nil {
		return err
	}
	if site.Runtime != "php" {
		return apiErr(http.StatusBadRequest, "Redis object cache is only available for PHP sites")
	}
	enabled, err := rtSitesEnabledField(body)
	if err != nil {
		return err
	}
	if enabled == site.RedisCache {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redis_cache": enabled,
			"message": rtSitesWord(enabled, "Redis cache is already enabled", "Redis cache is already disabled")})
		return nil
	}

	// Assign a unique Redis DB number (1-15) when enabling.
	redisDB := int32(0)
	if enabled {
		used, err := queryAll[int32](ctx, st.DB, "SELECT redis_db FROM sites WHERE redis_cache = true AND id != $1", id)
		if err != nil {
			return internalError("redis db allocation", err)
		}
		for n := int32(1); n <= 15 && redisDB == 0; n++ {
			if !slices.Contains(used, n) {
				redisDB = n
			}
		}
		if redisDB == 0 {
			return apiErr(http.StatusConflict, "All Redis DB slots (1-15) are in use")
		}
		if _, err := agent.Post(ctx, "/nginx/sites/"+site.Domain+"/redis/enable", map[string]any{
			"redis_db": redisDB, "php_preset": site.PHPPreset,
		}); err != nil {
			return agentError("Redis cache enable", err)
		}
	} else if _, err := agent.Post(ctx, "/nginx/sites/"+site.Domain+"/redis/disable", nil); err != nil {
		return agentError("Redis cache disable", err)
	}

	// Rebuild the FULL vhost with only the redis settings changed.
	u := *site
	u.RedisCache, u.RedisDB = enabled, redisDB
	if _, err := agent.Put(ctx, "/nginx/sites/"+site.Domain, rtSitesBuildNginxBody(&u)); err != nil {
		return agentError("Redis nginx config", err)
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE sites SET redis_cache = $1, redis_db = $2, updated_at = NOW() WHERE id = $3", enabled, redisDB, id); err != nil {
		return internalError("toggle redis cache", err)
	}
	action := rtSitesWord(enabled, "enabled", "disabled")
	slog.Info(fmt.Sprintf("Redis cache %s for %s (db: %d)", action, site.Domain, redisDB))
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.redis_cache."+action, new("site"), &site.Domain, nil, nil, c.KeyID)
	NotificationsNotifyPanel(ctx, st.DB, &c.Sub, fmt.Sprintf("Redis cache %s: %s", action, site.Domain),
		fmt.Sprintf("Redis object cache has been %s (DB %d)", action, redisDB), "info", "site", new("/sites/"+id.String()))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redis_cache": enabled, "redis_db": redisDB})
	return nil
}

// rtSitesPurgeRedisCache is POST /api/sites/{id}/redis-cache/purge.
func rtSitesPurgeRedisCache(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	site, agent, err := rtSitesSiteAndAgent(ctx, st, id, c, "purge redis cache")
	if err != nil {
		return err
	}
	if !site.RedisCache {
		return apiErr(http.StatusBadRequest, "Redis cache is not enabled for this site")
	}
	if _, err := agent.Post(ctx, "/nginx/sites/"+site.Domain+"/redis/purge", map[string]any{"redis_db": site.RedisDB}); err != nil {
		return agentError("Purge Redis", err)
	}
	slog.Info(fmt.Sprintf("Redis cache purged for %s (db: %d)", site.Domain, site.RedisDB))
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.redis_cache.purge", new("site"), &site.Domain, nil, nil, c.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Redis cache purged for " + site.Domain})
	return nil
}

// rtSitesAuditSite writes the activity + warning audit pair the SFTP and
// security toggles share.
func rtSitesAuditSite(ctx context.Context, st *AppState, c *Claims, r *http.Request, action, domain string) {
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, action, new("site"), &domain, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, action, &c.Email, ip, new("site"), &domain, nil, nil, "warning", c.KeyID)
}

// rtSitesEnableSftp is POST /api/sites/{id}/sftp/enable — provision a
// per-site SFTP account. The one explicit, operator-triggered step that
// re-owns an existing site's content directory. uid/gid come from
// sftp_id_seq, an atomic sequence rather than a racy MAX(sftp_uid)+1.
func rtSitesEnableSftp(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	if SecurityHardeningIsLockedDown(ctx, st.DB) {
		return apiErr(http.StatusServiceUnavailable, "System is in lockdown mode")
	}
	site, err := rtSitesSiteByCaller(ctx, st, id, c, "enable sftp", "Site not found")
	if err != nil {
		return err
	}
	if site.SFTPEnabled {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sftp_enabled": true, "message": "SFTP is already enabled for this site"})
		return nil
	}
	agent, err := agentForSiteServer(ctx, st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}
	allocated, err := queryScalar[int32](ctx, st.DB, "SELECT nextval('sftp_id_seq')::int")
	if err != nil {
		return internalError("allocate sftp uid", err)
	}
	uid, gid := allocated, allocated
	if _, err := agent.Post(ctx, "/sftp/sites/"+site.Domain+"/enable", map[string]any{"uid": uid, "gid": gid}); err != nil {
		return agentError("SFTP enable", err)
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE sites SET sftp_enabled = true, sftp_uid = $1, sftp_gid = $2, updated_at = NOW() WHERE id = $3", uid, gid, id); err != nil {
		return internalError("enable sftp", err)
	}
	// Rebuild the vhost so the PHP-FPM pool picks up the new owner.
	u := *site
	u.SFTPEnabled, u.SFTPUID, u.SFTPGID = true, &uid, &gid
	if _, err := agent.Put(ctx, "/nginx/sites/"+site.Domain, rtSitesBuildNginxBody(&u)); err != nil {
		return agentError("SFTP nginx/pool rebuild", err)
	}
	slog.Info(fmt.Sprintf("SFTP enabled for %s (uid=%d)", site.Domain, uid))
	rtSitesAuditSite(ctx, st, c, r, "site.sftp.enabled", site.Domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sftp_enabled": true})
	return nil
}

// rtSitesDisableSftp is POST /api/sites/{id}/sftp/disable — tear down the
// account and revert the content directory to the shared www-data identity.
func rtSitesDisableSftp(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	site, err := rtSitesSiteByCaller(ctx, st, id, c, "disable sftp", "Site not found")
	if err != nil {
		return err
	}
	if !site.SFTPEnabled {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sftp_enabled": false, "message": "SFTP is already disabled for this site"})
		return nil
	}
	if site.SFTPUID == nil || site.SFTPGID == nil {
		return internalError("disable sftp", ErrRowNotFound)
	}
	uid, gid := *site.SFTPUID, *site.SFTPGID
	agent, err := agentForSiteServer(ctx, st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}
	others, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM sites WHERE sftp_enabled = true AND id != $1", id)
	if err != nil {
		others = 1 // fail toward NOT removing the shared sshd drop-in
	}

	// Revert the PHP-FPM pool BEFORE tearing down the account: `userdel`
	// refuses a uid with a running process, and the old pool's workers still
	// run under it. The other order silently failed the account removal every
	// time behind a clean "disabled" response.
	u := *site
	u.SFTPEnabled = false
	if _, err := agent.Put(ctx, "/nginx/sites/"+site.Domain, rtSitesBuildNginxBody(&u)); err != nil {
		return agentError("SFTP nginx/pool revert", err)
	}
	if _, err := agent.Post(ctx, "/sftp/sites/"+site.Domain+"/disable", map[string]any{"uid": uid, "gid": gid, "last_sftp_site": others == 0}); err != nil {
		return agentError("SFTP disable", err)
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE sites SET sftp_enabled = false, updated_at = NOW() WHERE id = $1", id); err != nil {
		return internalError("disable sftp", err)
	}
	slog.Info("SFTP disabled for " + site.Domain)
	rtSitesAuditSite(ctx, st, c, r, "site.sftp.disabled", site.Domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sftp_enabled": false})
	return nil
}

// rtSitesResetSftpPassword is POST /api/sites/{id}/sftp/reset-password.
// Always generates, never accepts a value; no column stores it — once this
// response leaves, the plaintext exists only in the operator's clipboard.
func rtSitesResetSftpPassword(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	site, err := rtSitesSiteByCaller(ctx, st, id, c, "reset sftp password", "Site not found")
	if err != nil {
		return err
	}
	if !site.SFTPEnabled {
		return apiErr(http.StatusBadRequest, "SFTP is not enabled for this site")
	}
	if site.SFTPUID == nil {
		return internalError("reset sftp password", ErrRowNotFound)
	}
	agent, err := agentForSiteServer(ctx, st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}
	password := uuid.New().String()
	if _, err := agent.Post(ctx, "/sftp/sites/"+site.Domain+"/password", map[string]any{"uid": *site.SFTPUID, "password": password}); err != nil {
		return agentError("SFTP password reset", err)
	}
	slog.Info("SFTP password reset for " + site.Domain)
	rtSitesAuditSite(ctx, st, c, r, "site.sftp.password_reset", site.Domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "password": password})
	return nil
}

// rtSitesToggleWaf is PUT /api/sites/{id}/waf — toggle WAF and set its mode.
func rtSitesToggleWaf(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, body, site, agent, err := rtSitesToggleBody(st, r, "toggle waf")
	if err != nil {
		return err
	}
	enabled, ok := jsonBool(jsonGet(body, "enabled"))
	if !ok {
		return apiErr(http.StatusBadRequest, "Missing 'enabled' boolean")
	}
	mode, ok := jsonStr(jsonGet(body, "mode"))
	if !ok {
		mode = "detection"
	}
	if mode != "detection" && mode != "prevention" {
		return apiErr(http.StatusBadRequest, "Mode must be 'detection' or 'prevention'")
	}
	if enabled {
		if _, err := agent.Post(ctx, "/nginx/sites/"+site.Domain+"/waf/configure", map[string]any{"mode": mode}); err != nil {
			return agentError("WAF configure", err)
		}
	}
	// Rebuild the FULL vhost with only the WAF settings changed.
	u := *site
	u.WAFEnabled, u.WAFMode = enabled, mode
	if _, err := agent.Put(ctx, "/nginx/sites/"+site.Domain, rtSitesBuildNginxBody(&u)); err != nil {
		return agentError("WAF nginx config", err)
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE sites SET waf_enabled = $1, waf_mode = $2, updated_at = NOW() WHERE id = $3", enabled, mode, id); err != nil {
		return internalError("toggle waf", err)
	}
	action := "disabled"
	if enabled {
		action = "enabled (" + mode + ")"
	}
	slog.Info(fmt.Sprintf("WAF %s for %s", action, site.Domain))
	rtSitesAuditSite(ctx, st, c, r, "site.waf."+rtSitesWord(enabled, "enabled", "disabled"), site.Domain)
	NotificationsNotifyPanel(ctx, st.DB, &c.Sub, fmt.Sprintf("WAF %s: %s", action, site.Domain),
		"Web Application Firewall has been "+action, "info", "site", new("/sites/"+id.String()))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "waf_enabled": enabled, "waf_mode": mode})
	return nil
}

// rtSitesWafLogs is GET /api/sites/{id}/waf/logs — recent WAF events.
func rtSitesWafLogs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	site, agent, err := rtSitesSiteAndAgent(ctx, st, id, c, "waf logs")
	if err != nil {
		return err
	}
	res, err := agent.Get(ctx, "/nginx/sites/"+site.Domain+"/waf/logs?limit=50")
	if err != nil {
		return agentError("WAF logs", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtSitesOptimizeImages is POST /api/sites/{id}/optimize-images — convert
// site images to WebP/AVIF.
func rtSitesOptimizeImages(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, _, body, site, agent, err := rtSitesToggleBody(st, r, "optimize images")
	if err != nil {
		return err
	}
	format, ok := jsonStr(jsonGet(body, "format"))
	if !ok {
		format = "webp"
	}
	quality, ok := jsonU64(jsonGet(body, "quality"))
	if !ok {
		quality = 80
	}
	if format != "webp" && format != "avif" {
		return apiErr(http.StatusBadRequest, "Format must be 'webp' or 'avif'")
	}
	// The agent cannot know where the files are without the runtime:
	// node/python/proxy serve from the site root, static and php from public/.
	res, err := agent.PostLong(ctx, "/nginx/sites/"+site.Domain+"/optimize-images",
		map[string]any{"format": format, "quality": quality, "runtime": site.Runtime}, 300)
	if err != nil {
		return agentError("Image optimization", err)
	}
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.optimize_images", new("site"), &site.Domain, &format, nil, c.KeyID)
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtSitesIsSafeProxyPort refuses reserved/system/panel ports: choosing one
// enables loopback SSRF (proxy_pass http://127.0.0.1:<port>) into internal
// services AND lets the auto-firewall `ufw deny <port>/tcp` clobber a global
// allow rule (deny 443 → box-wide HTTPS outage).
func rtSitesIsSafeProxyPort(port int32) bool {
	reserved := []int32{22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379,
		27017, 11211, 3080, 8443, 9443, 2019}
	return port >= 1024 && port <= 65535 && !slices.Contains(reserved, port)
}

// rtSitesEnsureDomainAvailable is the thin adapter for clone and add_alias
// over DomainClaimEnsureClaimable — the checks themselves live there, where
// every domain-introducing path calls them.
func rtSitesEnsureDomainAvailable(ctx context.Context, st *AppState, domain string, r *http.Request, role string) (string, error) {
	return DomainClaimEnsureClaimable(ctx, st.DB, st.Agents, domain, r, DomainClaimHolderNew, role)
}

// rtSitesBuildNginxBody builds the full nginx agent body from a Site. Shared
// by every config-rebuild path.
func rtSitesBuildNginxBody(site *Site) map[string]any {
	body := map[string]any{
		"runtime":            site.Runtime,
		"fastcgi_cache":      site.FastCGICache,
		"redis_cache":        site.RedisCache,
		"redis_db":           site.RedisDB,
		"waf_enabled":        site.WAFEnabled,
		"waf_mode":           site.WAFMode,
		"rate_limit":         site.RateLimit,
		"max_upload_mb":      site.MaxUploadMB,
		"php_memory_mb":      site.PHPMemoryMB,
		"php_max_workers":    site.PHPMaxWorkers,
		"csp_policy":         site.CSPPolicy,
		"permissions_policy": site.PermissionsPolicy,
		"bot_protection":     site.BotProtection,
	}
	if site.PHPPreset != nil {
		body["php_preset"] = *site.PHPPreset
	}
	if site.CustomNginx != nil {
		body["custom_nginx"] = *site.CustomNginx
	}
	if site.PHPVersion != nil {
		body["php_socket"] = rtSitesPHPSocket(*site.PHPVersion)
	}
	if site.SSLEnabled {
		body["ssl"] = true
		if site.SSLCertPath != nil {
			body["ssl_cert"] = *site.SSLCertPath
		}
		if site.SSLKeyPath != nil {
			body["ssl_key"] = *site.SSLKeyPath
		}
	}
	if site.Runtime == "proxy" || site.Runtime == "node" || site.Runtime == "python" {
		body["proxy_port"] = site.ProxyPort
	}
	if site.SFTPEnabled && site.SFTPUID != nil && site.SFTPGID != nil {
		// Duplicated (not shared) on the agent in
		// services::sftp_accounts::{sftp_username, sftp_groupname}, which
		// creates these Linux accounts. Keep both byte-for-byte identical, or
		// the panel names the wrong pool owner.
		body["pool_user"] = fmt.Sprintf("sftp%d", *site.SFTPUID)
		body["pool_group"] = fmt.Sprintf("sftpg%d", *site.SFTPGID)
	}
	return body
}

// rtSitesUpdateSecurityHeaders is PUT /api/sites/{id}/security-headers.
func rtSitesUpdateSecurityHeaders(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, body, site, agent, err := rtSitesToggleBody(st, r, "security headers")
	if err != nil {
		return err
	}
	var csp, perms *string
	if s, ok := jsonStr(jsonGet(body, "csp_policy")); ok {
		csp = &s
	}
	if s, ok := jsonStr(jsonGet(body, "permissions_policy")); ok {
		perms = &s
	}
	// Both render verbatim into `add_header … "<value>" always;`, so a `"`
	// (or `\`/brace) breaks out and injects root-run nginx directives.
	// isSafeHeaderValue keeps `;` (a real CSP needs it).
	if csp != nil {
		if len(*csp) > 4096 {
			return apiErr(http.StatusBadRequest, "CSP policy must be under 4KB")
		}
		if !isSafeHeaderValue(*csp) {
			return apiErr(http.StatusBadRequest, "CSP policy contains invalid characters")
		}
	}
	if perms != nil {
		if len(*perms) > 2048 {
			return apiErr(http.StatusBadRequest, "Permissions-Policy must be under 2KB")
		}
		if !isSafeHeaderValue(*perms) {
			return apiErr(http.StatusBadRequest, "Permissions-Policy contains invalid characters")
		}
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE sites SET csp_policy = $1, permissions_policy = $2, updated_at = NOW() WHERE id = $3", csp, perms, id); err != nil {
		return internalError("security headers", err)
	}
	u := *site
	u.CSPPolicy, u.PermissionsPolicy = csp, perms
	if _, err := agent.Put(ctx, "/nginx/sites/"+site.Domain, rtSitesBuildNginxBody(&u)); err != nil {
		return agentError("Security headers nginx config", err)
	}
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.security_headers", new("site"), &site.Domain, nil, nil, c.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csp_policy": csp, "permissions_policy": perms})
	return nil
}

// rtSitesToggleBotProtection is PUT /api/sites/{id}/bot-protection.
func rtSitesToggleBotProtection(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, body, site, agent, err := rtSitesToggleBody(st, r, "bot protection")
	if err != nil {
		return err
	}
	mode, ok := jsonStr(jsonGet(body, "mode"))
	if !ok {
		mode = "off"
	}
	if !slices.Contains([]string{"off", "rate-limit", "challenge", "block"}, mode) {
		return apiErr(http.StatusBadRequest, "Mode must be 'off', 'rate-limit', 'challenge', or 'block'")
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE sites SET bot_protection = $1, updated_at = NOW() WHERE id = $2", mode, id); err != nil {
		return internalError("bot protection", err)
	}
	u := *site
	u.BotProtection = mode
	if _, err := agent.Put(ctx, "/nginx/sites/"+site.Domain, rtSitesBuildNginxBody(&u)); err != nil {
		return agentError("Bot protection nginx config", err)
	}
	rtSitesAuditSite(ctx, st, c, r, "site.bot_protection."+mode, site.Domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "bot_protection": mode})
	return nil
}

type rtSitesTransferSiteRequest struct {
	// The new owner, by email: the operator is reading a list of people, not
	// a list of UUIDs.
	Email string `json:"email"`
}

// rtSitesOwnershipDenormalizedTables are the tables that keep their own copy
// of user_id beside a site_id — derived, not remembered: every table carrying
// BOTH. Everything else reaches its owner THROUGH site_id. A row left behind
// keeps the previous owner able to act on part of a site, and nothing would
// report it.
var rtSitesOwnershipDenormalizedTables = [4]string{"alerts", "monitors", "secret_vaults", "whmcs_service_map"}

// rtSitesTransfer is POST /api/sites/{id}/transfer — hand a site to another
// account. Admin only.
//
// DockPanel has one ownership axis, sites.user_id, and every ownership-scoped
// read says `WHERE user_id = $1`; moving the row moves the site completely,
// which is why this is a transfer rather than an ACL (#51). ⚠ EXCLUSIVE: the
// previous owner loses the site, admin included (list_for_admin is the way
// back). One transaction: a half-transferred site is worse than a failed one.
func rtSitesTransfer(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, id, err := rtSitesAuthID(st, r)
	if err != nil {
		return err
	}
	var body rtSitesTransferSiteRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if c.Role != "admin" {
		return apiErr(http.StatusForbidden, "Admin only")
	}
	site, err := queryOpt[Tup3[uuid.UUID, string, uuid.UUID]](ctx, st.DB, "SELECT id, domain, user_id FROM sites WHERE id = $1", id)
	if err != nil {
		return internalError("load site", err)
	}
	if site == nil {
		return apiErr(http.StatusNotFound, "Site not found")
	}
	siteID, domain, previousOwner := site.A, site.B, site.C

	email := strings.ToLower(strings.TrimSpace(body.Email))
	recipient, err := queryOpt[Tup2[uuid.UUID, string]](ctx, st.DB, "SELECT id, role FROM users WHERE lower(email) = $1", email)
	if err != nil {
		return internalError("load recipient", err)
	}
	if recipient == nil {
		return apiErr(http.StatusNotFound, "No account with that email")
	}
	newOwner, newRole := recipient.A, recipient.B
	if newOwner == previousOwner {
		return apiErr(http.StatusConflict, "That account already owns this site")
	}
	// A suspended account must not be handed a live site: its every request
	// is rejected, so the site would land somewhere nobody can reach.
	if newRole == "suspended" {
		return apiErr(http.StatusConflict, "That account is suspended. Restore it before transferring a site to it.")
	}

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return internalError("begin transfer", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	// ⚠ A STAGING ENVIRONMENT IS A SECOND sites ROW, AND IT USED TO STAY
	// BEHIND: the departed owner kept a shell inside a full copy of the new
	// owner's docroot (wp-config.php included) and the push-to-production
	// control that writes it OVER the live site. Staging cannot nest, so one
	// `OR parent_site_id` is the whole tree.
	movedIDs, err := queryAll[uuid.UUID](ctx, tx,
		"UPDATE sites SET user_id = $1 WHERE id = $2 OR parent_site_id = $2 RETURNING id", newOwner, siteID)
	if err != nil {
		return internalError("transfer site", err)
	}
	moved := map[string]any{}
	for _, table := range rtSitesOwnershipDenormalizedTables {
		// The table name comes from a const array, never from a request.
		// Keyed on the ids actually moved, so the staging row's dependents
		// move too — the same split one level down otherwise.
		n, err := execSQL(ctx, tx, fmt.Sprintf("UPDATE %s SET user_id = $1 WHERE site_id = ANY($2)", table), newOwner, movedIDs)
		if err != nil {
			return internalError("transfer dependent rows", err)
		}
		moved[table] = n
	}
	if err := tx.Commit(ctx); err != nil {
		return internalError("commit transfer", err)
	}

	details := fmt.Sprintf("%s -> %s (%s)", previousOwner, newOwner, email)
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "site.transfer", new("site"), &domain, &details, clientIP(r), c.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "site.transfer", &c.Email, clientIP(r), new("site"), &domain, &details, nil, "critical", c.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "domain": domain, "previous_owner": previousOwner, "new_owner": newOwner, "dependent_rows_moved": moved,
	})
	return nil
}
