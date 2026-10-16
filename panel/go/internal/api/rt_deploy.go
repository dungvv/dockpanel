package api

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtDeployRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/sites/{id}/deploy", h(rtDeployGetConfig))
	r.Handle("PUT /api/sites/{id}/deploy", h(rtDeploySetConfig))
	r.Handle("DELETE /api/sites/{id}/deploy", h(rtDeployRemoveConfig))
	r.Handle("POST /api/sites/{id}/deploy/trigger", h(rtDeployTrigger))
	r.Handle("POST /api/sites/{id}/deploy/keygen", h(rtDeployKeygen))
	r.Handle("GET /api/sites/{id}/deploy/logs", h(rtDeployLogs))
	r.Handle("GET /api/sites/{id}/deploy/releases", h(rtDeployListReleases))
	r.Handle("POST /api/sites/{id}/deploy/rollback/{release_id}", h(rtDeployRollbackRelease))
	r.Handle("POST /api/webhooks/deploy/{site_id}/{secret}", h(rtDeployWebhook))
}

type rtDeployDeployConfig struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	SiteID          uuid.UUID  `json:"site_id" db:"site_id"`
	RepoURL         string     `json:"repo_url" db:"repo_url"`
	Branch          string     `json:"branch" db:"branch"`
	DeployScript    string     `json:"deploy_script" db:"deploy_script"`
	AutoDeploy      bool       `json:"auto_deploy" db:"auto_deploy"`
	WebhookSecret   string     `json:"webhook_secret" db:"webhook_secret"`
	DeployKeyPublic *string    `json:"deploy_key_public" db:"deploy_key_public"`
	DeployKeyPath   *string    `json:"deploy_key_path" db:"deploy_key_path"`
	LastDeploy      *time.Time `json:"last_deploy" db:"last_deploy"`
	LastStatus      *string    `json:"last_status" db:"last_status"`
	AtomicDeploy    bool       `json:"atomic_deploy" db:"atomic_deploy"`
	KeepReleases    int32      `json:"keep_releases" db:"keep_releases"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

type rtDeployDeployLog struct {
	ID          uuid.UUID `json:"id" db:"id"`
	SiteID      uuid.UUID `json:"site_id" db:"site_id"`
	CommitHash  *string   `json:"commit_hash" db:"commit_hash"`
	Status      string    `json:"status" db:"status"`
	Output      *string   `json:"output" db:"output"`
	TriggeredBy string    `json:"triggered_by" db:"triggered_by"`
	DurationMs  *int32    `json:"duration_ms" db:"duration_ms"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type rtDeploySetDeployRequest struct {
	RepoURL      string  `json:"repo_url"`
	Branch       *string `json:"branch"`
	DeployScript *string `json:"deploy_script"`
	AutoDeploy   *bool   `json:"auto_deploy"`
	AtomicDeploy *bool   `json:"atomic_deploy"`
	KeepReleases *int32  `json:"keep_releases"`
}

type rtDeployReleaseInfo struct {
	ID         string  `json:"id"`
	Active     bool    `json:"active"`
	CommitHash *string `json:"commit_hash"`
	CreatedAt  string  `json:"created_at"`
}

type rtDeployLogsQuery struct {
	Limit  *int64 `json:"limit"`
	Offset *int64 `json:"offset"`
}

// rtDeployActiveIncidentsSQL counts active critical/major incidents.
const rtDeployActiveIncidentsSQL = "SELECT COUNT(*) FROM managed_incidents " +
	"WHERE status NOT IN ('resolved', 'postmortem') " +
	"AND severity IN ('critical', 'major')"

// rtDeployErrMessage reads the `error` field of an ApiError body (Rust
// `body.0.get("error")`).
func rtDeployErrMessage(err error) string {
	var ae *ApiError
	if errors.As(err, &ae) {
		if m, ok := ae.Body.(map[string]any); ok {
			if s, ok := m["error"].(string); ok {
				return s
			}
		}
	}
	return "Unknown error"
}

// rtDeployGetConfig — GET /api/sites/{id}/deploy: get deploy config.
func rtDeployGetConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if _, err := siteDomainForCaller(r.Context(), st, id, claims); err != nil {
		return err
	}
	config, err := queryOpt[rtDeployDeployConfig](r.Context(), st.DB, "SELECT * FROM deploy_configs WHERE site_id = $1", id)
	if err != nil {
		return internalError("get config", err)
	}
	// Deploy.tsx builds the webhook URL to paste into the git host from this
	// field on every load, so it must decrypt, not stay masked.
	if config != nil {
		config.WebhookSecret = SecretsCryptoDecryptCredentialOrLegacy(config.WebhookSecret, st.Config.JWTSecret)
	}
	writeJSON(w, http.StatusOK, config)
	return nil
}

// rtDeploySetConfig — PUT /api/sites/{id}/deploy: set/update deploy config.
func rtDeploySetConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtDeploySetDeployRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	domain, err := siteDomainForCaller(ctx, st, id, claims)
	if err != nil {
		return err
	}

	if strings.TrimSpace(body.RepoURL) == "" {
		return apiErr(http.StatusBadRequest, "Repository URL is required")
	}

	branch := "main"
	if body.Branch != nil {
		branch = *body.Branch
	}
	deployScript := ""
	if body.DeployScript != nil {
		deployScript = *body.DeployScript
	}
	if deployScript != "" {
		if msg := isSafeShellCommand(deployScript); msg != "" {
			return apiErr(http.StatusBadRequest, msg)
		}
	}
	autoDeploy := body.AutoDeploy != nil && *body.AutoDeploy
	atomicDeploy := body.AtomicDeploy != nil && *body.AtomicDeploy
	keepReleases := int32(5)
	if body.KeepReleases != nil {
		keepReleases = *body.KeepReleases
	}
	keepReleases = min(max(keepReleases, 2), 20)
	webhookSecret := strings.ReplaceAll(uuid.NewString(), "-", "")
	// Only used on first INSERT — ON CONFLICT's DO UPDATE never touches this
	// column, so an existing config keeps its original secret (see the
	// decrypt-what-came-back below rather than trusting this local value).
	encryptedWebhookSecret, err := SecretsCryptoEncryptCredential(webhookSecret, st.Config.JWTSecret)
	if err != nil {
		return apiErr(http.StatusInternalServerError, fmt.Sprintf("Encryption failed: %v", err))
	}

	config, err := queryOne[rtDeployDeployConfig](ctx, st.DB,
		"INSERT INTO deploy_configs (site_id, repo_url, branch, deploy_script, auto_deploy, webhook_secret, atomic_deploy, keep_releases) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "+
			"ON CONFLICT (site_id) DO UPDATE SET "+
			"repo_url = $2, branch = $3, deploy_script = $4, auto_deploy = $5, atomic_deploy = $7, keep_releases = $8, updated_at = NOW() "+
			"RETURNING *",
		id, strings.TrimSpace(body.RepoURL), branch, deployScript, autoDeploy, encryptedWebhookSecret, atomicDeploy, keepReleases)
	if err != nil {
		return internalError("set config", err)
	}

	// Decrypt whatever the row actually holds (freshly written on an INSERT,
	// or the pre-existing secret on an update-conflict).
	config.WebhookSecret = SecretsCryptoDecryptCredentialOrLegacy(config.WebhookSecret, st.Config.JWTSecret)

	slog.Info(fmt.Sprintf("Deploy config set for %s: %s", domain, body.RepoURL))
	targetType := "deploy"
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "deploy.config",
		&targetType, &domain, &body.RepoURL, nil, claims.KeyID)

	writeJSON(w, http.StatusOK, config)
	return nil
}

// rtDeployRemoveConfig — DELETE /api/sites/{id}/deploy: remove deploy config.
func rtDeployRemoveConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if _, err := siteDomainForCaller(r.Context(), st, id, claims); err != nil {
		return err
	}
	if _, err := execSQL(r.Context(), st.DB, "DELETE FROM deploy_configs WHERE site_id = $1", id); err != nil {
		return internalError("remove config", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtDeployTrigger — POST /api/sites/{id}/deploy/trigger: trigger a deployment
// (async with SSE).
func rtDeployTrigger(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()

	// Check for active critical/major incidents — block deploy during outage
	activeIncidents, _ := queryScalar[int64](ctx, st.DB, rtDeployActiveIncidentsSQL)
	if activeIncidents > 0 {
		return apiErr(http.StatusConflict,
			"Deploy blocked: active critical/major incident in progress. Resolve the incident first.")
	}

	// The same rule the webhook path follows: this clones a repository into
	// the site's webroot and runs its build script as root on whichever host
	// it is handed. Both need the site's own row, not the caller's scope.
	domain, agent, err := siteAgentForCaller(ctx, st, id, claims)
	if err != nil {
		return err
	}

	config, err := queryOpt[rtDeployDeployConfig](ctx, st.DB, "SELECT * FROM deploy_configs WHERE site_id = $1", id)
	if err != nil {
		return internalError("trigger", err)
	}
	if config == nil {
		return apiErr(http.StatusNotFound, "No deploy config found")
	}

	deployID := uuid.New()
	st.ProvisionLogs.Register(deployID, claims.Sub, 32)

	db := st.DB
	userID, email, keyID := claims.Sub, claims.Email, claims.KeyID

	go func() {
		bg := context.WithoutCancel(ctx)
		emit := func(step, label, status string, msg *string) {
			st.ProvisionLogs.Emit(deployID, ProvisionStep{Step: step, Label: label, Status: status, Message: msg})
		}
		ifOK := func(ok bool, a, b string) string {
			if ok {
				return a
			}
			return b
		}

		emit("deploy", "Running deployment", "in_progress", nil)

		log, err := rtDeployExecuteDeploy(bg, db, agent, id, domain, config, "manual")
		if err == nil {
			ok := log.Status == "success"
			var msg *string
			if log.Output != nil {
				m := string([]rune(*log.Output)[:min(500, len([]rune(*log.Output)))])
				msg = &m
			}
			emit("deploy", "Running deployment", ifOK(ok, "done", "error"), msg)
			emit("complete", ifOK(ok, "Deployment complete", "Deployment failed"), ifOK(ok, "done", "error"), nil)

			targetType := "deploy"
			ActivityLogActivity(bg, db, userID, email, "deploy.trigger",
				&targetType, &domain, log.CommitHash, &log.Status, keyID)
		} else {
			msg := rtDeployErrMessage(err)
			emit("deploy", "Running deployment", "error", &msg)
			emit("complete", "Deployment failed", "error", nil)
		}

		time.Sleep(60 * time.Second)
		st.ProvisionLogs.Remove(deployID)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"deploy_id": deployID,
		"message":   "Deployment started",
	})
	return nil
}

// rtDeployKeygen — POST /api/sites/{id}/deploy/keygen: generate deploy key.
func rtDeployKeygen(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	domain, agent, err := siteAgentForCaller(ctx, st, id, claims)
	if err != nil {
		return err
	}

	result, err := agent.Post(ctx, "/deploy/keygen", map[string]any{"domain": domain})
	if err != nil {
		return agentError("Deploy key generation", err)
	}
	publicKey, _ := jsonStr(jsonGet(result, "public_key"))
	keyPath, _ := jsonStr(jsonGet(result, "key_path"))

	// Store in deploy config
	if _, err := execSQL(ctx, st.DB,
		"UPDATE deploy_configs SET deploy_key_public = $1, deploy_key_path = $2, updated_at = NOW() WHERE site_id = $3",
		publicKey, keyPath, id); err != nil {
		return internalError("keygen", err)
	}

	writeJSON(w, http.StatusOK, map[string]any{"public_key": publicKey})
	return nil
}

// rtDeployLogs — GET /api/sites/{id}/deploy/logs: list deploy logs.
func rtDeployLogs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var params rtDeployLogsQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	if _, err := siteDomainForCaller(r.Context(), st, id, claims); err != nil {
		return err
	}
	limit, offset := paginate(params.Limit, params.Offset)
	logs, err := queryAll[rtDeployDeployLog](r.Context(), st.DB,
		"SELECT * FROM deploy_logs WHERE site_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
		id, limit, offset)
	if err != nil {
		return internalError("logs", err)
	}
	writeJSON(w, http.StatusOK, logs)
	return nil
}

// rtDeployWebhook — POST /api/webhooks/deploy/{site_id}/{secret}: webhook
// endpoint (no auth).
func rtDeployWebhook(st *AppState, w http.ResponseWriter, r *http.Request) error {
	siteID, err := pathUUID(r, "site_id")
	if err != nil {
		return err
	}
	secret := r.PathValue("secret")
	ctx := r.Context()

	// Validate Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.Contains(contentType, "application/json") {
		return apiErr(http.StatusBadRequest, "Content-Type must be application/json")
	}

	// Rate limit: max WebhookAttemptLimit failed attempts per site per hour
	st.WebhookMu.Lock()
	now := time.Now()
	entry, ok := st.WebhookAttempts[siteID]
	if !ok || now.Sub(entry.Start) >= time.Hour {
		// New, or window expired: reset
		entry = RateWindow{Count: 0, Start: now}
	}
	st.WebhookAttempts[siteID] = entry
	limited := entry.Count >= WebhookAttemptLimit
	st.WebhookMu.Unlock()
	if limited {
		return apiErr(http.StatusTooManyRequests, "Rate limit exceeded. Try again later.")
	}

	// Fetch the deploy config by site_id only (the secret is compared in
	// constant time below)
	config, err := queryOpt[rtDeployDeployConfig](ctx, st.DB,
		"SELECT * FROM deploy_configs WHERE site_id = $1 AND auto_deploy = true", siteID)
	if err != nil {
		return internalError("webhook", err)
	}
	if config == nil {
		return apiErr(http.StatusNotFound, "Invalid webhook")
	}

	storedSecret := SecretsCryptoDecryptCredentialOrLegacy(config.WebhookSecret, st.Config.JWTSecret)

	// Constant-time secret comparison
	if subtle.ConstantTimeCompare([]byte(secret), []byte(storedSecret)) != 1 {
		// Record failed attempt
		st.WebhookMu.Lock()
		now := time.Now()
		entry, ok := st.WebhookAttempts[siteID]
		if !ok {
			entry = RateWindow{Count: 0, Start: now}
		}
		if now.Sub(entry.Start) >= time.Hour {
			entry = RateWindow{Count: 1, Start: now}
		} else {
			entry.Count++
		}
		st.WebhookAttempts[siteID] = entry
		st.WebhookMu.Unlock()
		return apiErr(http.StatusNotFound, "Invalid webhook")
	}

	// Get domain AND the server the site lives on. `sites.server_id` is NOT
	// NULL, so the row always names its machine.
	siteRow, err := queryOpt[Tup2[string, uuid.UUID]](ctx, st.DB, "SELECT domain, server_id FROM sites WHERE id = $1", siteID)
	if err != nil {
		return internalError("webhook", err)
	}
	domain := ""
	if siteRow != nil {
		domain = siteRow.A
	}

	// Check for active critical/major incidents — skip webhook deploy during outage
	activeIncidents, _ := queryScalar[int64](ctx, st.DB, rtDeployActiveIncidentsSQL)
	if activeIncidents > 0 {
		slog.Warn(fmt.Sprintf("Deploy blocked for %s: active incident in progress", domain))
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Deploy skipped: active incident"})
		return nil
	}

	// Resolve the agent for the server this SITE lives on. A webhook has no
	// authenticated caller and therefore no ServerScope, which is why this
	// used to take the local agent — but the site row names its server, and
	// deploying a remote tenant's site onto the panel host writes their files
	// and their vhost on the wrong machine.
	if siteRow == nil {
		return apiErr(http.StatusNotFound, "Invalid webhook")
	}
	siteServerID := siteRow.B
	agent, err := st.Agents.ForServer(ctx, siteServerID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Webhook deploy for %s refused: its server %s is "+
			"unreachable (%v) — refusing to deploy on a different host", domain, siteServerID, err))
		return apiErr(http.StatusBadGateway, "Deploy target server is unreachable")
	}

	// Execute deploy in background (webhook should return quickly)
	db := st.DB
	go func() {
		_, _ = rtDeployExecuteDeploy(context.WithoutCancel(ctx), db, agent, siteID, domain, config, "webhook")
	}()

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Deployment triggered"})
	return nil
}

// rtDeployExecuteDeploy executes a deployment: git clone/pull + run script.
func rtDeployExecuteDeploy(ctx context.Context, db *pgxpool.Pool, agent AgentHandle, siteID uuid.UUID,
	domain string, config *rtDeployDeployConfig, triggeredBy string) (*rtDeployDeployLog, error) {
	// Pre-deploy backup: snapshot before deploying (best-effort, don't block deploy on failure)
	_, _ = agent.Post(ctx, fmt.Sprintf("/backups/%s/create", domain), map[string]any{"reason": "pre-deploy"})
	slog.Info(fmt.Sprintf("Pre-deploy backup requested for %s", domain))

	var deployScript *string
	if config.DeployScript != "" {
		deployScript = &config.DeployScript
	}
	agentBody := map[string]any{
		"domain":        domain,
		"repo_url":      config.RepoURL,
		"branch":        config.Branch,
		"deploy_script": deployScript,
		"key_path":      config.DeployKeyPath,
	}

	// Choose atomic or standard deploy path
	var result any
	var err error
	if config.AtomicDeploy {
		agentBody["keep_releases"] = config.KeepReleases
		if result, err = agent.Post(ctx, "/deploy/atomic", agentBody); err != nil {
			return nil, agentError("Atomic deploy execution", err)
		}
	} else {
		if result, err = agent.Post(ctx, "/deploy/run", agentBody); err != nil {
			return nil, agentError("Deploy execution", err)
		}
	}

	success, _ := jsonBool(jsonGet(result, "success"))
	output, _ := jsonStr(jsonGet(result, "output"))
	var commitHash *string
	if s, ok := jsonStr(jsonGet(result, "commit_hash")); ok {
		commitHash = &s
	}
	durationU, _ := jsonU64(jsonGet(result, "duration_ms"))
	durationMs := int32(durationU) // `as i32`: wraps, as Rust does
	status := "failed"
	if success {
		status = "success"
	}

	// GAP 26: Auto-rollback on failed deploy — restore from most recent pre-deploy backup
	if !success {
		latestBackup, _ := queryScalarOpt[string](ctx, db,
			"SELECT filename FROM backups WHERE site_id = $1 ORDER BY created_at DESC LIMIT 1", siteID)
		if latestBackup != nil {
			filename := *latestBackup
			// Validate filename has no path separators or traversal
			if strings.Contains(filename, "/") || strings.Contains(filename, "..") || strings.Contains(filename, "\x00") {
				slog.Warn(fmt.Sprintf("Auto-rollback: suspicious backup filename '%s' for %s, skipping", filename, domain))
			} else {
				restorePath := fmt.Sprintf("/backups/%s/restore/%s", domain, filename)
				if _, err := agent.Post(ctx, restorePath, nil); err != nil {
					slog.Warn(fmt.Sprintf("Auto-rollback failed for %s: %v", domain, err))
				} else {
					slog.Info(fmt.Sprintf("Auto-rollback: restored %s for %s after failed deploy", filename, domain))
				}
			}
		} else {
			slog.Warn(fmt.Sprintf("Auto-rollback: no backup found for %s, skipping restore", domain))
		}
	}

	if success {
		// GAP 56: Auto-run database migrations for Laravel sites after successful deploy
		preset, _ := queryScalarOpt[*string](ctx, db, "SELECT php_preset FROM sites WHERE id = $1", siteID)
		if preset != nil && *preset != nil && **preset == "laravel" && isValidDomain(domain) {
			if _, err := agent.Post(ctx, fmt.Sprintf("/sites/%s/laravel-migrate", domain), nil); err != nil {
				slog.Warn(fmt.Sprintf("Post-deploy: Laravel migrations failed for %s: %v", domain, err))
			} else {
				slog.Info(fmt.Sprintf("Post-deploy: Laravel migrations run for %s", domain))
			}
		}

		// GAP 37: Post-deploy cache invalidation — clear nginx fastcgi cache for the domain
		_, _ = agent.Post(ctx, "/diagnostics/fix", map[string]any{"fix_id": "clean-cache:" + domain})
		slog.Info(fmt.Sprintf("Post-deploy cache invalidation requested for %s", domain))

		// Post-deploy health check: verify site is responding after successful deploy
		sslEnabled, err := queryScalarOpt[bool](ctx, db, "SELECT ssl_enabled FROM sites WHERE id = $1", siteID)
		if err != nil {
			return nil, internalError("deploy ssl check", err)
		}
		if err := rtDeployHealthCheck(ctx, db, siteID, domain, sslEnabled != nil && *sslEnabled); err != nil {
			return nil, err
		}

		// GAP 5: Auto-inject secrets from linked vault after successful deploy
		rtDeployAutoInject(ctx, db, agent, siteID, domain)
	}

	// Record log
	log, err := queryOne[rtDeployDeployLog](ctx, db,
		"INSERT INTO deploy_logs (site_id, commit_hash, status, output, triggered_by, duration_ms) "+
			"VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
		siteID, commitHash, status, output, triggeredBy, durationMs)
	if err != nil {
		return nil, internalError("webhook", err)
	}

	// Update deploy config status
	_, _ = execSQL(ctx, db,
		"UPDATE deploy_configs SET last_deploy = NOW(), last_status = $1, updated_at = NOW() WHERE site_id = $2",
		status, siteID)

	commitDbg := "None"
	if commitHash != nil {
		commitDbg = fmt.Sprintf("Some(%q)", *commitHash)
	}
	slog.Info(fmt.Sprintf("Deploy %s for %s (commit: %s, trigger: %s)", status, domain, commitDbg, triggeredBy))

	// Panel notification center
	userID, err := queryScalarOpt[uuid.UUID](ctx, db, "SELECT user_id FROM sites WHERE id = $1", siteID)
	if err != nil {
		return nil, internalError("deploy notification user lookup", err)
	}
	link := fmt.Sprintf("/sites/%s", siteID)
	if success {
		NotificationsNotifyPanel(ctx, db, userID, "Deploy complete: "+domain, "Site deployment completed successfully", "info", "deploy", &link)
	} else {
		NotificationsNotifyPanel(ctx, db, userID, "Deploy failed: "+domain, output, "critical", "deploy", &link)
	}

	return &log, nil
}

// rtDeployHealthCheck: after a successful deploy, verify the site responds.
// A 5xx or no answer raises a panel warning (the deploy itself stays a
// success).
func rtDeployHealthCheck(ctx context.Context, db *pgxpool.Pool, siteID uuid.UUID, domain string, useSSL bool) error {
	time.Sleep(3 * time.Second)
	checkURL := "http://" + domain
	if useSSL {
		checkURL = "https://" + domain
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	link := fmt.Sprintf("/sites/%s", siteID)
	notify := func(title, msg string) error {
		userID, err := queryScalarOpt[uuid.UUID](ctx, db, "SELECT user_id FROM sites WHERE id = $1", siteID)
		if err != nil {
			return internalError("deploy health check user lookup", err)
		}
		NotificationsNotifyPanel(ctx, db, userID, title, msg, "warning", "deploy", &link)
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		return nil // Rust: the client failed to build → no check
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn(fmt.Sprintf("Post-deploy health check FAILED for %s: %v", domain, err))
		return notify(fmt.Sprintf("Deploy warning: %s unreachable", domain),
			fmt.Sprintf("Deploy succeeded but the site is not responding: %v", err))
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		slog.Warn(fmt.Sprintf("Post-deploy health check FAILED for %s: HTTP %d", domain, resp.StatusCode))
		return notify(fmt.Sprintf("Deploy warning: %s returning HTTP %d", domain, resp.StatusCode),
			fmt.Sprintf("Deploy succeeded but the site is returning HTTP %d. Check your application logs.", resp.StatusCode))
	}
	slog.Info(fmt.Sprintf("Post-deploy health check OK for %s: HTTP %d", domain, resp.StatusCode))
	return nil
}

// rtDeployAutoInject — GAP 5: inject auto-inject vault secrets into the site's
// env after a successful deploy.
func rtDeployAutoInject(ctx context.Context, db *pgxpool.Pool, agent AgentHandle, siteID uuid.UUID, domain string) {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return
	}
	// The vault is NOT encrypted under the JWT secret — it is encrypted under
	// the key derived from it, as every writer (and the manual "Inject"
	// button, which runs this same query and PUTs the same body) does. This
	// path once passed the raw JWT secret, so every decrypt failed, and
	// nothing could report it: AES-GCM authenticates, so a wrong key yields an
	// error, which was thrown away; env_pairs stayed empty and the only log
	// line sat inside `if !env_pairs.is_empty()`. A documented feature was
	// inert and silent at the same time.
	// Read path — DecryptVault tries every source the value could have been
	// written under. Deriving ONE source is the shape that made adding
	// SECRETS_ENCRYPTION_KEY strand every vault secret.
	injectRows, _ := queryAll[Tup2[string, string]](ctx, db,
		"SELECT s.key, s.encrypted_value FROM secrets s "+
			"JOIN secret_vaults v ON v.id = s.vault_id AND v.site_id = $1 "+
			"WHERE s.auto_inject = TRUE", siteID)
	if len(injectRows) == 0 {
		return
	}
	envPairs := []any{}
	undecryptable := 0
	for _, row := range injectRows {
		value, err := SecretsCryptoDecryptVault(row.B, jwtSecret)
		if err != nil {
			// The NAME is enough to act on; never the ciphertext and never the
			// key. Skipping quietly is what hid the wrong key material here.
			undecryptable++
			slog.Warn(fmt.Sprintf("Auto-inject: could not decrypt secret %s for %s: %v", row.A, domain, err))
			continue
		}
		envPairs = append(envPairs, map[string]any{"key": row.A, "value": value})
	}
	if len(envPairs) > 0 {
		if _, err := agent.Put(ctx, "/nginx/env/"+domain, map[string]any{"vars": envPairs}); err != nil {
			slog.Warn(fmt.Sprintf("Auto-inject: the agent refused the env write for %s: %v", domain, err))
		} else {
			slog.Info(fmt.Sprintf("Auto-injected %d secrets into %s after deploy", len(envPairs), domain))
		}
	} else if undecryptable > 0 {
		slog.Warn(fmt.Sprintf("Auto-inject: all %d auto-inject secrets for %s "+
			"failed to decrypt — nothing was injected", undecryptable, domain))
	}
}

// rtDeployListReleases — GET /api/sites/{id}/deploy/releases: list releases
// for an atomic deploy site.
func rtDeployListReleases(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	domain, agent, err := siteAgentForCaller(ctx, st, id, claims)
	if err != nil {
		return err
	}
	result, err := agent.Get(ctx, "/deploy/releases/"+domain)
	if err != nil {
		return agentError("List releases", err)
	}
	// serde_json::from_value(..).unwrap_or_default(): any shape mismatch → [].
	releases := []rtDeployReleaseInfo{}
	if b, err := json.Marshal(result); err == nil {
		var parsed []rtDeployReleaseInfo
		if decodeJSONBytes(b, &parsed) == nil && parsed != nil {
			releases = parsed
		}
	}
	writeJSON(w, http.StatusOK, releases)
	return nil
}

// rtDeployRollbackRelease — POST /api/sites/{id}/deploy/rollback/{release_id}:
// roll back to a specific release.
func rtDeployRollbackRelease(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	releaseID := r.PathValue("release_id")
	ctx := r.Context()
	domain, agent, err := siteAgentForCaller(ctx, st, id, claims)
	if err != nil {
		return err
	}

	result, err := agent.Post(ctx, "/deploy/activate", map[string]any{
		"domain":     domain,
		"release_id": releaseID,
	})
	if err != nil {
		return agentError("Rollback release", err)
	}

	// Record rollback in deploy logs
	_, _ = execSQL(ctx, st.DB,
		"INSERT INTO deploy_logs (site_id, commit_hash, status, output, triggered_by, duration_ms) "+
			"VALUES ($1, $2, 'success', $3, 'rollback', 0)",
		id, releaseID, "Rolled back to release "+releaseID)

	targetType, status := "deploy", "success"
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "deploy.rollback",
		&targetType, &domain, &releaseID, &status, claims.KeyID)

	// Reload nginx to pick up any config changes
	_, _ = agent.Post(ctx, "/nginx/reload", nil)

	writeJSON(w, http.StatusOK, result)
	return nil
}
