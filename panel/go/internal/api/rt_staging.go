package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

func rtStagingRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/sites/{id}/staging", h(rtStagingGetStaging))
	r.Handle("POST /api/sites/{id}/staging", h(rtStagingCreate))
	r.Handle("DELETE /api/sites/{id}/staging", h(rtStagingDestroy))
	r.Handle("POST /api/sites/{id}/staging/sync", h(rtStagingSyncToStaging))
	r.Handle("POST /api/sites/{id}/staging/push", h(rtStagingPushToProd))
}

type rtStagingCreateStagingRequest struct {
	// Custom staging domain (optional). Defaults to staging.{parent_domain}.
	Domain *string `json:"domain"`
	// Explicit opt-in past the shared-database warning below. Defaults to
	// false/absent so the warning is the default outcome for any site that
	// has one, not an opt-out a caller has to know to avoid.
	AcknowledgeSharedDatabase bool `json:"acknowledge_shared_database" serde:"default"`
}

// rtStagingGetSite resolves a site this caller may act on, as a full row —
// through the shared SiteCallerPredicate, not an owner-only copy.
func rtStagingGetSite(ctx context.Context, st *AppState, id uuid.UUID, claims *Claims) (*Site, error) {
	site, err := queryOpt[Site](ctx, st.DB, "SELECT s.* FROM sites s WHERE "+SiteCallerPredicate, id, claims.Sub)
	if err != nil {
		return nil, internalError("resolve site for caller", err)
	}
	if site == nil {
		return nil, apiErr(http.StatusNotFound, "Site not found")
	}
	return site, nil
}

// rtStagingStagingOf loads the staging row of a parent site (nil when none).
func rtStagingStagingOf(ctx context.Context, st *AppState, id uuid.UUID, what string) (*Site, error) {
	s, err := queryOpt[Site](ctx, st.DB, "SELECT * FROM sites WHERE parent_site_id = $1", id)
	if err != nil {
		return nil, internalError(what, err)
	}
	return s, nil
}

func rtStagingFmtServer(id *uuid.UUID) string {
	if id == nil {
		return "None"
	}
	return fmt.Sprintf("Some(%s)", id)
}

// rtStagingSameHostAgent resolves the one agent that can move files between a
// site and its staging environment.
//
// `/staging/sync` is an rsync from `/var/www/{source}` into `/var/www/{target}`
// on whichever host is asked, so the operation only exists on a machine that
// holds both paths. Each row names its own host, and the pair has to agree.
//
// `create` now inherits the parent's `server_id`, but it once stamped the row
// with the caller's scope, and those rows are still in every database that ran
// that version. This guard catches them and stays: an invariant nothing
// enforces at write time is an invariant that comes back.
//
// When the two disagree there is nothing to choose between — one of the paths
// is not there. Substituting either host would rsync one machine's document
// root into a directory belonging to a different site. Reported as a conflict
// rather than not-found because the data is inconsistent, not absent.
func rtStagingSameHostAgent(ctx context.Context, st *AppState, parent, staging *Site) (AgentHandle, error) {
	same := (parent.ServerID == nil && staging.ServerID == nil) ||
		(parent.ServerID != nil && staging.ServerID != nil && *parent.ServerID == *staging.ServerID)
	if !same {
		slog.Warn(fmt.Sprintf("Refusing to move files between %s and %s: their rows name different servers "+
			"(%s vs %s)", parent.Domain, staging.Domain, rtStagingFmtServer(parent.ServerID), rtStagingFmtServer(staging.ServerID)))
		return nil, apiErr(http.StatusConflict, "This site and its staging environment are on different servers")
	}
	return agentForSiteServer(ctx, st, staging.ServerID, staging.Domain)
}

// rtStagingCreate — POST /api/sites/{id}/staging: create a staging environment.
//
//  1. Validate parent site (must be active, not already a staging site)
//  2. Generate or validate staging domain
//  3. Create site record with parent_site_id
//  4. Create nginx config via agent
//  5. Clone files from production
//
// Takes no ServerScope, and that is NOT the usual exception for a handler
// that creates a row. A brand-new site or stack has a free choice of machine;
// a staging environment does not: it exists to be rsynced to and from its
// parent's document root, and an rsync is one machine's work. Its host is a
// property of the parent, so it is inherited, not read from the header.
// (Stamping the caller's scope is where the divergence rtStagingSameHostAgent
// refuses used to be manufactured.)
func rtStagingCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtStagingCreateStagingRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	// A staging environment is a `sites` row, and a handler creating a site
	// must enforce the SAME admission controls create() does — otherwise it is
	// a create() with none of the guards. The per-parent uniqueness check
	// bounds a tenant to one staging per parent, but not per tenant: an
	// account holding N sites could mint N more rows, each with a vhost and a
	// cloned document root, during a declared lockdown. Both guards are the
	// sibling's own: the same predicate, status, and shared ceiling.
	if SecurityHardeningIsLockedDown(ctx, st.DB) {
		return apiErr(http.StatusServiceUnavailable, "System is in lockdown mode")
	}
	{
		maxSites := rtSitesSiteRateLimit(ctx, st.DB)
		recent, _ := queryScalar[int64](ctx, st.DB,
			"SELECT COUNT(*) FROM sites WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 hour'", claims.Sub)
		if recent >= maxSites {
			details := fmt.Sprintf("User tried to create staging site #%d in 1 hour", recent+1)
			SecurityHardeningRecordSuspiciousEvent(ctx, st.DB, "site.rate_limit_hit", &claims.Email, nil, &details)
			return apiErr(http.StatusTooManyRequests, fmt.Sprintf("Site creation rate limit: max %d sites per hour. "+
				"An administrator can change this in Settings > Account > Security Hardening "+
				"(\"Site Creation Rate Limit\"); set it to 0 to remove the limit.", maxSites))
		}
	}

	parent, err := rtStagingGetSite(ctx, st, id, claims)
	if err != nil {
		return err
	}
	if parent.Status != "active" {
		return apiErr(http.StatusBadRequest, "Parent site must be active")
	}
	if parent.ParentSiteID != nil {
		return apiErr(http.StatusBadRequest, "Cannot create staging from a staging site")
	}

	// Staging only ever clones FILES (`/staging/clone` is an rsync of
	// `/var/www/{domain}` — there is no database anywhere in the agent-side
	// staging surface). For a DB-backed site the staging environment reads and
	// writes the SAME live production database from the moment it's created.
	// Block by default rather than silently let an operator corrupt production
	// data through what looks like a sandbox; `acknowledge_shared_database` is
	// the explicit, informed override.
	if !body.AcknowledgeSharedDatabase {
		hasDatabase, err := queryScalarOpt[int32](ctx, st.DB, "SELECT 1 FROM databases WHERE site_id = $1 LIMIT 1", id)
		if err != nil {
			return internalError("create staging", err)
		}
		if hasDatabase != nil {
			return apiErr(http.StatusConflict, "This site has an attached database. Staging only clones files — the "+
				"database is NOT isolated, so changes made on staging read and write the "+
				"LIVE production database immediately, not a copy.")
		}
	}

	// Check if staging already exists for this site
	existing, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM sites WHERE parent_site_id = $1", id)
	if err != nil {
		return internalError("create staging", err)
	}
	if existing != nil {
		return apiErr(http.StatusConflict, "A staging environment already exists for this site")
	}

	// The parent's host, for the rest of this handler: the claim, the vhost,
	// the file clone and the new row's `server_id` all have to be the machine
	// production is already on. `server_id` is NOT NULL in the schema, so a
	// row predating the backfill would fail on the INSERT — refuse it here,
	// with the reason, instead.
	if parent.ServerID == nil {
		slog.Warn(fmt.Sprintf("Refusing to create staging for %s: its row names no server", parent.Domain))
		return apiErr(http.StatusConflict, "This site is not associated with a server")
	}
	serverID := *parent.ServerID
	agent, err := agentForSiteServer(ctx, st, &serverID, parent.Domain)
	if err != nil {
		return err
	}

	// Determine staging domain. `body.domain` is arbitrary — NOT required to be
	// a subdomain of the parent — so this is a full domain claim by an ordinary
	// tenant and must pass the same guard as every other one (reserved
	// domains, git deploys, Docker apps — not just `sites`).
	requested := "staging." + parent.Domain
	if body.Domain != nil && *body.Domain != "" {
		requested = *body.Domain
	}
	stagingDomain, err := DomainClaimEnsureClaimable(ctx, st.DB, st.Agents, requested, r, DomainClaimHolderNew, claims.Role)
	if err != nil {
		return err
	}

	// Staging always lands on the parent's own server, and
	// `idx_sites_proxy_port_server` is UNIQUE on (proxy_port, server_id) — so
	// copying `parent.proxy_port` collides with the parent's OWN row every
	// time, for every proxy/node/python site. Allocate staging its own port
	// the way sites create auto-allocates for node/python
	// (`generate_series(5000, 5999)` scoped to this server).
	var stagingProxyPort *int32
	if parent.ProxyPort != nil {
		port, err := queryScalarOpt[int32](ctx, st.DB,
			"SELECT s.port FROM generate_series(5000, 5999) AS s(port) "+
				"WHERE s.port NOT IN (SELECT proxy_port FROM sites WHERE proxy_port IS NOT NULL AND server_id = $1) "+
				"LIMIT 1", serverID)
		if err != nil {
			return internalError("create staging", err)
		}
		if port == nil {
			return apiErr(http.StatusConflict, "No free port available for this staging environment on this server")
		}
		stagingProxyPort = port
	}

	// Insert staging site
	staging, err := queryOne[Site](ctx, st.DB,
		"INSERT INTO sites (user_id, server_id, domain, runtime, status, proxy_port, php_version, app_command, parent_site_id) "+
			"VALUES ($1, $2, $3, $4, 'creating', $5, $6, $7, $8) RETURNING *",
		claims.Sub, serverID, stagingDomain, parent.Runtime, stagingProxyPort, parent.PHPVersion, parent.AppCommand, id)
	if err != nil {
		// `idx_sites_parent_unique` adjudicates the race the SELECT-then-INSERT
		// check above cannot: the loser sees the same "already exists" message
		// rather than a generic 500.
		if strings.Contains(err.Error(), "idx_sites_parent_unique") {
			return apiErr(http.StatusConflict, "A staging environment already exists for this site")
		}
		return internalError("create staging", err)
	}

	// Build agent request to create nginx config (same as regular site creation)
	agentBody := map[string]any{"runtime": parent.Runtime}
	if stagingProxyPort != nil {
		agentBody["proxy_port"] = *stagingProxyPort
	}
	if parent.PHPVersion != nil {
		agentBody["php_socket"] = fmt.Sprintf("unix:/run/php/php%s-fpm.sock", *parent.PHPVersion)
	}
	// Without this, node/python staging never started its app service: the
	// agent's put_site requires BOTH `app_command` AND `proxy_port`.
	if parent.AppCommand != nil {
		agentBody["app_command"] = *parent.AppCommand
	}

	if _, err := agent.Put(ctx, "/nginx/sites/"+stagingDomain, agentBody); err != nil {
		slog.Error(fmt.Sprintf("Agent error creating staging site %s: %v", stagingDomain, err))
		_, _ = execSQL(ctx, st.DB, "UPDATE sites SET status = 'error', updated_at = NOW() WHERE id = $1", staging.ID)
		return agentError("Staging configuration", err)
	}

	// Clone files from production to staging
	_, cloneErr := agent.Post(ctx, "/staging/clone", map[string]any{
		"source": parent.Domain,
		"target": stagingDomain,
	})

	// Status reflects whether the clone actually happened. Both branches used
	// to write 'active', so a failed clone looked identical to a working one
	// everywhere except `synced_at`.
	updateSQL := "UPDATE sites SET status = 'active', synced_at = NOW(), updated_at = NOW() WHERE id = $1 RETURNING *"
	if cloneErr != nil {
		slog.Warn(fmt.Sprintf("File clone failed for staging %s: Err(%v)", stagingDomain, cloneErr))
		updateSQL = "UPDATE sites SET status = 'error', updated_at = NOW() WHERE id = $1 RETURNING *"
	}

	updated, err := queryOne[Site](ctx, st.DB, updateSQL, staging.ID)
	if err != nil {
		return internalError("create staging", err)
	}

	slog.Info(fmt.Sprintf("Staging created: %s → %s (%s)", parent.Domain, stagingDomain, parent.Runtime))
	targetType := "site"
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "staging.create",
		&targetType, &stagingDomain, &parent.Domain, nil, claims.KeyID)

	writeJSON(w, http.StatusCreated, updated)
	return nil
}

// rtStagingGetStaging — GET /api/sites/{id}/staging: get the staging site for
// a production site.
//
// Takes no ServerScope: the staging row names its own host, and that is the
// only host whose disk this may be measured on.
func rtStagingGetStaging(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// Verify parent site ownership
	if _, err := rtStagingGetSite(ctx, st, id, claims); err != nil {
		return err
	}

	s, err := rtStagingStagingOf(ctx, st, id, "get staging")
	if err != nil {
		return err
	}
	if s == nil {
		writeJSON(w, http.StatusOK, map[string]any{"exists": false})
		return nil
	}

	// A disk-usage figure is a measurement of one specific machine. Read
	// through the caller's handle it measured whichever host the request was
	// scoped to — some other box's `/var/www/{domain}`. A wrong number here is
	// worse than no number, because a wrong number is believed.
	agent, err := agentForSiteServer(ctx, st, s.ServerID, s.Domain)
	if err != nil {
		return err
	}

	// Get disk usage
	var usage uint64
	if v, err := agent.Post(ctx, "/staging/disk-usage", map[string]any{"domain": s.Domain}); err == nil {
		usage, _ = jsonU64(jsonGet(v, "bytes"))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"exists":           true,
		"site":             s,
		"disk_usage_bytes": usage,
	})
	return nil
}

// rtStagingSyncToStaging — POST /api/sites/{id}/staging/sync: sync production
// files → staging.
//
// Takes no ServerScope: both directories in this copy are named by rows, and
// the rows decide which machine holds them.
func rtStagingSyncToStaging(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	parent, err := rtStagingGetSite(ctx, st, id, claims)
	if err != nil {
		return err
	}
	staging, err := rtStagingStagingOf(ctx, st, id, "sync to staging")
	if err != nil {
		return err
	}
	if staging == nil {
		return apiErr(http.StatusNotFound, "No staging environment found")
	}

	// Production is the source and staging is the target, and both paths have
	// to exist on the host that does the copying.
	agent, err := rtStagingSameHostAgent(ctx, st, parent, staging)
	if err != nil {
		return err
	}
	if _, err := agent.Post(ctx, "/staging/sync", map[string]any{
		"source": parent.Domain,
		"target": staging.Domain,
	}); err != nil {
		return agentError("Staging sync", err)
	}

	// Update synced_at timestamp
	if _, err := execSQL(ctx, st.DB, "UPDATE sites SET synced_at = NOW(), updated_at = NOW() WHERE id = $1", staging.ID); err != nil {
		return internalError("sync to staging", err)
	}

	msg := fmt.Sprintf("Synced %s → %s", parent.Domain, staging.Domain)
	slog.Info(msg)
	targetType, details := "site", fmt.Sprintf("%s → %s", parent.Domain, staging.Domain)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "staging.sync",
		&targetType, &staging.Domain, &details, nil, claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
	return nil
}

// rtStagingPushToProd — POST /api/sites/{id}/staging/push: push staging files
// → production.
//
// Takes no ServerScope: the rows decide the host, and this direction writes
// over a live production document root, so the host had better be the right one.
func rtStagingPushToProd(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	parent, err := rtStagingGetSite(ctx, st, id, claims)
	if err != nil {
		return err
	}
	staging, err := rtStagingStagingOf(ctx, st, id, "push to prod")
	if err != nil {
		return err
	}
	if staging == nil {
		return apiErr(http.StatusNotFound, "No staging environment found")
	}

	// Same pairing as the sync, reversed: staging is the source, production the target.
	agent, err := rtStagingSameHostAgent(ctx, st, parent, staging)
	if err != nil {
		return err
	}
	if _, err := agent.Post(ctx, "/staging/sync", map[string]any{
		"source": staging.Domain,
		"target": parent.Domain,
	}); err != nil {
		return agentError("Staging push", err)
	}

	msg := fmt.Sprintf("Pushed %s → %s", staging.Domain, parent.Domain)
	slog.Info(msg)
	ip := clientIP(r)
	targetType, details := "site", fmt.Sprintf("%s → %s", staging.Domain, parent.Domain)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "staging.push",
		&targetType, &staging.Domain, &details, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "staging.push", &claims.Email, ip,
		&targetType, &staging.Domain, &details, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
	return nil
}

// rtStagingDestroy — DELETE /api/sites/{id}/staging: delete the staging environment.
//
// Takes no ServerScope. rtStagingGetSite authorises the PARENT, and the row
// this then deletes is a different one that carries its own `server_id`.
func rtStagingDestroy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if _, err := rtStagingGetSite(ctx, st, id, claims); err != nil {
		return err
	}
	staging, err := rtStagingStagingOf(ctx, st, id, "destroy")
	if err != nil {
		return err
	}
	if staging == nil {
		return apiErr(http.StatusNotFound, "No staging environment found")
	}

	// The two calls below are a vhost removal and `/staging/delete-files`,
	// which on the agent is `remove_dir_all("/var/www/{domain}")` with no
	// ownership check of its own. The panel alone decides which machine loses
	// a document root, and it once decided from the caller's request header
	// while the authority sat unread in the row — on a fleet a delete reached
	// whichever box the operator's scope pointed at, and reported success.
	agent, err := agentForSiteServer(ctx, st, staging.ServerID, staging.Domain)
	if err != nil {
		return err
	}

	// Remove nginx config
	if _, err := agent.Delete(ctx, "/nginx/sites/"+staging.Domain); err != nil {
		return agentError("Staging removal", err)
	}

	// Delete site files. The row deleted below is the ONLY thing that marks
	// this domain as occupied (domain_claim checks the DB, never the
	// filesystem) — so on failure the row must NOT be deleted, or the domain
	// becomes re-claimable by anyone while the previous tenant's files
	// (`wp-config.php`, `.env`, …) are still on disk.
	if _, err := agent.Post(ctx, "/staging/delete-files", map[string]any{"domain": staging.Domain}); err != nil {
		slog.Error(fmt.Sprintf("Staging destroy: file cleanup failed for %s — keeping the site row so the "+
			"domain stays claimed rather than releasing it over leftover files: %v", staging.Domain, err))
		_, _ = execSQL(ctx, st.DB, "UPDATE sites SET status = 'error', updated_at = NOW() WHERE id = $1", staging.ID)
		return agentError("Staging file cleanup", err)
	}

	// Delete from DB
	if _, err := execSQL(ctx, st.DB, "DELETE FROM sites WHERE id = $1", staging.ID); err != nil {
		return internalError("destroy", err)
	}

	slog.Info("Staging deleted: " + staging.Domain)
	ip := clientIP(r)
	targetType := "site"
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "staging.delete",
		&targetType, &staging.Domain, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "staging.delete", &claims.Email, ip,
		&targetType, &staging.Domain, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": staging.Domain})
	return nil
}
