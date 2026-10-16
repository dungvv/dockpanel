package api

// Port of panel/backend/src/routes/docker_apps.rs — Docker apps (templates,
// compose, images, registries), container policies and auto-sleep.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtDockerAppsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/container-policies", h(rtDockerAppsListPolicies))
	r.Handle("POST /api/container-policies", h(rtDockerAppsCreatePolicy))
	r.Handle("GET /api/container-policies/{user_id}", h(rtDockerAppsGetPolicy))
	r.Handle("PUT /api/container-policies/{user_id}", h(rtDockerAppsUpdatePolicy))
	r.Handle("DELETE /api/container-policies/{user_id}", h(rtDockerAppsDeletePolicy))
	r.Handle("GET /api/container-policies/{user_id}/usage", h(rtDockerAppsPolicyUsage))

	r.Handle("GET /api/apps/updates", h(rtDockerAppsCheckUpdates))
	r.Handle("GET /api/apps/gpu-info", h(rtDockerAppsGpuInfo))
	r.Handle("GET /api/apps/templates", h(rtDockerAppsListTemplates))
	r.Handle("GET /api/apps/preflight", h(rtDockerAppsPreflight))
	r.Handle("POST /api/apps/deploy", h(rtDockerAppsDeploy))
	r.Handle("GET /api/apps/deploy/{deploy_id}/log", h(rtDockerAppsDeployLog))
	r.Handle("POST /api/apps/compose/validate", h(rtDockerAppsComposeValidate))
	r.Handle("POST /api/apps/compose/parse", h(rtDockerAppsComposeParse))
	r.Handle("POST /api/apps/compose/deploy", h(rtDockerAppsComposeDeploy))
	r.Handle("GET /api/apps/registries", h(rtDockerAppsListRegistries))
	r.Handle("POST /api/apps/registry-login", h(rtDockerAppsRegistryLogin))
	r.Handle("POST /api/apps/registry-logout", h(rtDockerAppsRegistryLogout))
	r.Handle("GET /api/apps/images", h(rtDockerAppsListImages))
	r.Handle("POST /api/apps/images/prune", h(rtDockerAppsPruneImages))
	r.Handle("DELETE /api/apps/images/{id}", h(rtDockerAppsRemoveImage))
	r.Handle("GET /api/apps", h(rtDockerAppsListApps))
	r.Handle("DELETE /api/apps/{container_id}", h(rtDockerAppsRemoveApp))
	r.Handle("POST /api/apps/{container_id}/stop", h(rtDockerAppsStopApp))
	r.Handle("POST /api/apps/{container_id}/start", h(rtDockerAppsStartApp))
	r.Handle("POST /api/apps/{container_id}/restart", h(rtDockerAppsRestartApp))
	r.Handle("GET /api/apps/{container_id}/logs", h(rtDockerAppsAppLogs))
	r.Handle("GET /api/apps/{container_id}/env", h(rtDockerAppsAppEnv))
	r.Handle("PUT /api/apps/{container_id}/env", h(rtDockerAppsUpdateEnv))
	r.Handle("POST /api/apps/{container_id}/update", h(rtDockerAppsUpdateApp))
	r.Handle("GET /api/apps/{container_id}/stats", h(rtDockerAppsContainerStats))
	r.Handle("GET /api/apps/{container_id}/shell-info", h(rtDockerAppsShellInfo))
	r.Handle("POST /api/apps/{container_id}/exec", h(rtDockerAppsExecCommand))
	r.Handle("GET /api/apps/{container_id}/ollama/models", h(rtDockerAppsOllamaListModels))
	r.Handle("POST /api/apps/{container_id}/ollama/pull", h(rtDockerAppsOllamaPullModel))
	r.Handle("POST /api/apps/{container_id}/ollama/delete", h(rtDockerAppsOllamaDeleteModel))
	r.Handle("GET /api/apps/{container_id}/volumes", h(rtDockerAppsContainerVolumes))
	r.Handle("POST /api/apps/{container_id}/snapshot", h(rtDockerAppsSnapshotContainer))
	r.Handle("PUT /api/apps/{container_id}/image", h(rtDockerAppsUpdateImage))
	r.Handle("PUT /api/apps/{container_id}/limits", h(rtDockerAppsUpdateLimits))
	r.Handle("GET /api/apps/sleep-status", h(rtDockerAppsSleepStatusList))
	r.Handle("GET /api/apps/{container_id}/sleep-config", h(rtDockerAppsGetSleepConfig))
	r.Handle("PUT /api/apps/{container_id}/sleep-config", h(rtDockerAppsUpdateSleepConfig))
	r.Handle("POST /api/apps/{container_id}/wake", h(rtDockerAppsWakeContainer))
	r.Handle("POST /api/apps/{container_id}/sleep", h(rtDockerAppsSleepContainer))
	r.Handle("POST /api/apps/{container_id}/activity-ping", h(rtDockerAppsActivityPing))
}

// ── Shared plumbing ─────────────────────────────────────────────────────

// rtDockerAppsAdmin is the common prologue of the admin + scoped handlers:
// AuthUser, then ServerScope, then require_admin (the Rust extractor order).
func rtDockerAppsAdmin(st *AppState, r *http.Request) (*Claims, uuid.UUID, AgentHandle, error) {
	claims, err := st.authUser(r)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	return claims, serverID, agent, requireAdmin(claims.Role)
}

// rtDockerAppsContainer is rtDockerAppsAdmin plus the {container_id} check.
func rtDockerAppsContainer(st *AppState, r *http.Request) (*Claims, uuid.UUID, AgentHandle, string, error) {
	claims, serverID, agent, err := rtDockerAppsAdmin(st, r)
	if err != nil {
		return nil, uuid.Nil, nil, "", err
	}
	cid := r.PathValue("container_id")
	if !isValidContainerID(cid) {
		return nil, uuid.Nil, nil, "", apiErr(http.StatusBadRequest, "Invalid container ID")
	}
	return claims, serverID, agent, cid, nil
}

// rtDockerAppsValueBody is Json<serde_json::Value>: any JSON, numbers kept
// exact (as_u64 must see an integer, not a float64).
func rtDockerAppsValueBody(r *http.Request) (any, error) {
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return nil, err
	}
	return agentDecodeJSON(raw)
}

// rtDockerAppsPassthrough answers with the agent's JSON or its error.
func rtDockerAppsPassthrough(w http.ResponseWriter, res any, err error, context string) error {
	if err != nil {
		return agentError(context, err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// ── Templates & allow-list ──────────────────────────────────────────────

// rtDockerAppsListTemplates is GET /api/apps/templates.
func rtDockerAppsListTemplates(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, err := rtDockerAppsAdmin(st, r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), "/apps/templates")
	return rtDockerAppsPassthrough(w, res, err, "Docker apps")
}

// rtDockerAppsImageAllowedBy: does image satisfy one of the comma-separated
// entries of an allowed_images policy?
//
// Deliberately not a substring test — `contains` would let an entry of
// `nginx` admit `evil/nginx-backdoor`. An entry matches when it is the whole
// reference, the repository the reference tags or digests, or ends in `/*`
// and names a repository prefix (`ghcr.io/myorg/*`).
func rtDockerAppsImageAllowedBy(allowed, image string) bool {
	for _, entry := range strings.Split(allowed, ",") {
		entry = strings.TrimSpace(entry)
		switch {
		case entry == "*":
			return true
		case entry == "":
			continue
		}
		if prefix, ok := strings.CutSuffix(entry, "/*"); ok {
			if image == prefix || strings.HasPrefix(image, prefix+"/") {
				return true
			}
			continue
		}
		if image == entry {
			return true
		}
		if rest, ok := strings.CutPrefix(image, entry); ok && (strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, "@")) {
			return true
		}
	}
	return false
}

// rtDockerAppsEnforceAllowedImages refuses any image the caller's container
// policy does not allow. Doors that receive an image reference directly —
// change-image, compose, stacks — call this so a restriction the operator
// set is not simply absent there.
func rtDockerAppsEnforceAllowedImages(ctx context.Context, db Querier, userID uuid.UUID, images []string) error {
	if len(images) == 0 {
		return nil
	}
	allowed, err := queryScalarOpt[*string](ctx, db, "SELECT allowed_images FROM container_policies WHERE user_id = $1", userID)
	if err != nil {
		return internalError("container policy check", err)
	}
	if allowed == nil || *allowed == nil || strings.TrimSpace(**allowed) == "" {
		return nil
	}
	for _, image := range images {
		if !rtDockerAppsImageAllowedBy(**allowed, image) {
			return apiErr(http.StatusForbidden, image+" is not in the images you are allowed to deploy")
		}
	}
	return nil
}

// ── Deploy ──────────────────────────────────────────────────────────────

type rtDockerAppsDeployRequest struct {
	TemplateID string             `json:"template_id"`
	Name       string             `json:"name"`
	Port       uint16             `json:"port"`
	Env        *map[string]string `json:"env"`
	Domain     *string            `json:"domain"`
	SslEmail   *string            `json:"ssl_email"`
	// Set when TLS is terminated by a proxy in front of this server, so the
	// panel must not attempt Let's Encrypt. Leaving ssl_email empty does not
	// decline (the operator's address is substituted). A back-compat alias
	// for tls_mode = "none"; an explicit tls_mode wins.
	ExternalTLS bool `json:"external_tls" serde:"default"`
	// "none" | "acme" | "provided". Absent = legacy inference. The agent's
	// /apps/deploy has accepted this (and tls_certificate) since TlsIntent was
	// built for stacks — the panel simply never sent it for a template app.
	TlsMode *string `json:"tls_mode"`
	// Registry alias; provided mode only.
	TlsCertificate *string `json:"tls_certificate"`
	MemoryMB       *uint64 `json:"memory_mb"`
	CPUPercent     *uint64 `json:"cpu_percent"`
	GpuEnabled     bool    `json:"gpu_enabled" serde:"default"`
}

// rtDockerAppsDeploy is POST /api/apps/deploy — deploy from a template,
// asynchronously, with SSE progress.
func rtDockerAppsDeploy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body rtDockerAppsDeployRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()

	if !isValidName(body.Name) {
		return apiErr(http.StatusBadRequest, "Invalid app name")
	}
	if body.Port == 0 {
		return apiErr(http.StatusBadRequest, "Port must be between 1 and 65535")
	}
	env := map[string]string{}
	if body.Env != nil && *body.Env != nil {
		env = *body.Env
	}
	// Env vars: max 50, max 4KB per value.
	if body.Env != nil {
		if len(env) > 50 {
			return apiErr(http.StatusBadRequest, "Too many environment variables (max 50)")
		}
		for k, v := range env {
			if k == "" || len(k) > 255 {
				return apiErr(http.StatusBadRequest, "Invalid environment variable name")
			}
			if len(v) > 4096 {
				return apiErr(http.StatusBadRequest, "Environment variable value too large (max 4KB)")
			}
		}
	}

	// ── Unconditional resource clamp (s237 audit) ── mirrors update_limits so
	// a deploy is bounded even with no container_policies row; the per-user
	// policy below is an ADDITIONAL, tighter ceiling.
	if m := body.MemoryMB; m != nil && (*m < 4 || *m > 65536) {
		return apiErr(http.StatusBadRequest, "memory_mb must be between 4 and 65536")
	}
	if c := body.CPUPercent; c != nil && (*c == 0 || *c > 10000) {
		return apiErr(http.StatusBadRequest, "cpu_percent must be between 1 and 10000")
	}

	// ── Container policy enforcement ──
	policy, err := queryOpt[Tup4[int32, int64, int32, *string]](ctx, st.DB,
		"SELECT max_containers, max_memory_mb, max_cpu_percent, allowed_images FROM container_policies WHERE user_id = $1",
		claims.Sub)
	if err != nil {
		return internalError("container policy check", err)
	}
	if policy != nil {
		maxContainers, maxMemory, maxCPU, allowedImages := policy.A, policy.B, policy.C, policy.D
		// Count the containers this CALLER owns (every other admin's used to
		// count against this one's cap). Fail CLOSED on the target: an agent
		// error OR a non-array answer refuses rather than bypassing the quota.
		appsJSON, err := agent.Get(ctx, "/apps")
		if err != nil {
			return agentError("container count check", err)
		}
		if _, ok := jsonArr(appsJSON); !ok {
			return apiErr(http.StatusBadGateway, "Could not verify container count")
		}
		count := rtDockerAppsCountOwnedBy(appsJSON, claims.Sub)
		// The quota is per USER, not per machine — fold in the caller's
		// containers on every OTHER online server. Best-effort: an unreachable
		// peer only undercounts; the target is exempt from that leniency.
		for _, m := range st.Agents.OnlineFleet(ctx) {
			if m.ID == serverID {
				continue
			}
			if peer, err := m.Agent.Get(ctx, "/apps"); err == nil {
				count += rtDockerAppsCountOwnedBy(peer, claims.Sub)
			}
		}
		if count >= int(maxContainers) {
			return apiErr(http.StatusForbidden, fmt.Sprintf("Container limit reached (%d)", maxContainers))
		}
		if m := body.MemoryMB; m != nil && int64(*m) > maxMemory {
			return apiErr(http.StatusForbidden, fmt.Sprintf("Memory exceeds policy limit (%dMB)", maxMemory))
		}
		if c := body.CPUPercent; c != nil && int32(*c) > maxCPU {
			return apiErr(http.StatusForbidden, fmt.Sprintf("CPU exceeds policy limit (%d%%)", maxCPU))
		}
		// Allowed images. This used to test template_id.contains(entry) — the
		// catalogue id, never an image reference — so a policy naming an image
		// matched nothing. The template id is still accepted EXACTLY, so a
		// policy written against the old behaviour keeps working.
		if allowedImages != nil && *allowedImages != "" {
			allowed := *allowedImages
			byID := false
			for _, a := range strings.Split(allowed, ",") {
				if a = strings.TrimSpace(a); a == "*" || a == body.TemplateID {
					byID = true
					break
				}
			}
			if !byID {
				img := rtImageScansResolveTemplateImage(ctx, agent, body.TemplateID)
				switch {
				case img == nil:
					// Fail closed: a policy restricting images cannot be
					// honoured against an image we could not determine.
					return apiErr(http.StatusForbidden, "Could not determine this template's image, and a policy restricts "+
						"which images you may deploy")
				case !rtDockerAppsImageAllowedBy(allowed, *img):
					return apiErr(http.StatusForbidden, *img+" is not in the images you are allowed to deploy")
				}
			}
		}
	}

	// ── Prerequisite gate ── the same checks the deploy form ran. Enforcing by
	// CALLING the checker keeps the sentence the user was shown and the one
	// they are refused with identical. Only blocking results refuse.
	{
		intent := PrerequisitesAppsAppDeployIntent{
			TemplateID: body.TemplateID, Name: body.Name, Port: body.Port, Env: env, MemoryMB: body.MemoryMB,
		}
		specs := rtDockerAppsTemplateEnvSpecs(ctx, agent, body.TemplateID)
		facts := rtDockerAppsGatherAppFacts(ctx, st.DB, agent, serverID, body.Port)
		results := PrerequisitesAppsEvaluate(&intent, specs, &facts)
		if b := PrerequisitesFirstBlocker(results); b != nil {
			return apiErr(http.StatusPreconditionFailed, b.Title+" — "+b.Detail)
		}
	}

	// Image scan deploy gate (no-op unless opted in), scoped to the server
	// being deployed TO.
	if err := rtImageScansPreflightGate(ctx, st.DB, serverID, agent, body.TemplateID); err != nil {
		return err
	}

	deployID := uuid.New()
	// Register the log and its owner in one step (ownership for SSE access).
	st.ProvisionLogs.Register(deployID, claims.Sub, 32)

	// Until this check the domain was put on the wire unexamined: no reserved
	// block, no conflict query against sites/git_deploys — an app could take
	// over a live site's vhost or the panel's own hostname. It must happen
	// HERE: the task below creates a DNS A record before the agent is called.
	var deployDomain *string
	if body.Domain != nil && *body.Domain != "" {
		d, err := DomainClaimEnsureClaimable(ctx, st.DB, st.Agents, *body.Domain, r, DomainClaimHolderNew, claims.Role)
		if err != nil {
			return err
		}
		deployDomain = &d
	}
	// Requesting a certificate is the right default, but it has to be
	// declinable: behind an upstream TLS terminator every deploy spent an
	// ACME attempt that could not succeed.
	var deploySslEmail *string
	if !body.ExternalTLS {
		deploySslEmail = body.SslEmail
		if deploySslEmail == nil {
			deploySslEmail = new(claims.Email)
		}
	}

	reverseProxy, err := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'reverse_proxy'")
	if err != nil {
		return internalError("docker app reverse proxy setting", err)
	}
	useTraefik := reverseProxy != nil && *reverseProxy == "traefik"

	// The mode is decided once, before provisioning starts — reusing stacks'
	// RequestedTlsMode/PlanTls so a template app gets the SAME provided-mode
	// validation rather than a drifting copy. No domain means nothing to
	// secure; an explicit mode with no domain is refused by the plan.
	reqMode, err := rtStacksRequestedTlsMode(body.TlsMode)
	if err != nil {
		return err
	}
	var mode string
	switch {
	case reqMode != nil:
		mode = *reqMode
	case deployDomain == nil, body.ExternalTLS:
		mode = "none"
	default:
		mode = rtStacksEffectiveTlsMode(nil, deploySslEmail)
	}
	tls, err := rtStacksPlanTls(ctx, st.DB, agent, mode, deployDomain, deploySslEmail, body.TlsCertificate, claims.Sub, serverID)
	if err != nil {
		return err
	}

	agentBody := map[string]any{
		"template_id": body.TemplateID,
		"name":        body.Name,
		"port":        body.Port,
		"env":         env,
		"user_id":     claims.Sub.String(),
		"gpu_enabled": body.GpuEnabled,
		"tls_mode":    tls.Mode,
	}
	if deployDomain != nil {
		agentBody["domain"] = *deployDomain
	}
	if e := tls.DeployEmail(); e != nil {
		agentBody["ssl_email"] = *e
	}
	if tls.Alias != nil {
		agentBody["tls_certificate"] = *tls.Alias
	}
	if body.MemoryMB != nil {
		agentBody["memory_mb"] = *body.MemoryMB
	}
	if body.CPUPercent != nil {
		agentBody["cpu_percent"] = *body.CPUPercent
	}
	if useTraefik {
		agentBody["use_traefik"] = true
	}

	go rtDockerAppsDeployTask(st, agent, rtDockerAppsDeployJob{
		deployID: deployID, userID: claims.Sub, email: claims.Email, keyID: claims.KeyID,
		serverID: serverID, appName: body.Name, template: body.TemplateID,
		domain: deployDomain, sslEmail: deploySslEmail, tlsMode: tls.Mode,
		gpuEnabled: body.GpuEnabled, agentBody: agentBody,
	})

	writeJSON(w, http.StatusAccepted, map[string]any{"deploy_id": deployID, "message": "Deployment started"})
	return nil
}

type rtDockerAppsDeployJob struct {
	deployID, userID uuid.UUID
	email            string
	keyID            *uuid.UUID
	// The host this app is deployed to — the A record published below must
	// name THAT machine, not the panel (see publicIPForServer).
	serverID          uuid.UUID
	appName, template string
	domain, sslEmail  *string
	tlsMode           string
	gpuEnabled        bool
	agentBody         map[string]any
}

// rtDockerAppsSidecarTemplates carry a docker-socket-proxy sidecar and are
// password-protected once live on a domain (see the deploy task).
var rtDockerAppsSidecarTemplates = []string{"dozzle"}

func rtDockerAppsDeployTask(st *AppState, agent AgentHandle, j rtDockerAppsDeployJob) {
	ctx := context.Background()
	db := st.DB
	emit := func(step, label, status string, msg *string) {
		st.ProvisionLogs.Emit(j.deployID, ProvisionStep{Step: step, Label: label, Status: status, Message: msg})
	}

	// Step 1: auto-create the DNS record if a domain is provided.
	if j.domain != nil {
		domain := *j.domain
		emit("dns", "Creating DNS record", "in_progress", nil)
		parent := rtDockerAppsParentDomain(domain)

		type zoneRow struct {
			ID         uuid.UUID `db:"id"`
			Provider   string    `db:"provider"`
			CfZoneID   *string   `db:"cf_zone_id"`
			CfAPIToken *string   `db:"cf_api_token"`
			CfAPIEmail *string   `db:"cf_api_email"`
		}
		zone, _ := queryOpt[zoneRow](ctx, db,
			"SELECT id, provider, cf_zone_id, cf_api_token, cf_api_email FROM dns_zones WHERE domain = $1 AND user_id = $2",
			parent, j.userID)
		if zone == nil {
			emit("dns", "Creating DNS record", "error", new(fmt.Sprintf("No DNS zone found for %s — create record manually", parent)))
		} else {
			serverIP := publicIPForServer(ctx, db, &j.serverID)
			if serverIP == nil {
				// No record beats a record naming the wrong machine: that one
				// resolves, and answers with someone else's app.
				emit("dns", "Creating DNS record", "failed", new("could not determine this server's public address"))
				return
			}
			switch zone.Provider {
			case "cloudflare":
				if zone.CfZoneID != nil && zone.CfAPIToken != nil {
					rtDockerAppsCloudflareCreate(ctx, emit, *zone.CfZoneID, *zone.CfAPIToken, zone.CfAPIEmail, domain, *serverIP)
				}
			case "powerdns":
				rtDockerAppsPowerDNSCreate(ctx, db, emit, parent, domain, *serverIP)
			}
		}
	}

	// Step 2: pull image + deploy container (+ proxy + SSL by the agent).
	emit("pull", "Pulling Docker image", "in_progress", nil)
	result, err := agent.Post(ctx, "/apps/deploy", j.agentBody)
	if err != nil {
		// This one arm catches every way a deploy can fail — image resolve,
		// create, start, proxy, volume repair — and once filed all of them
		// under the pull step, sending operators to audit a registry that had
		// answered perfectly. Resolve the pull step honestly and report on a
		// step that names no phase; the agent's message already says what
		// happened.
		emit("pull", "Pulling Docker image", "pending", nil)
		emit("deploy", "Deploying app", "error", new(err.Error()))
		emit("complete", "Deploy failed", "error", nil)
		slog.Error(fmt.Sprintf("App deploy failed: %s (%s): %v", j.appName, j.template, err))
		SystemLogLogEvent(ctx, db, "error", "api", fmt.Sprintf("App deploy failed: %s (%s)", j.appName, j.template), new(err.Error()))
	} else {
		rtDockerAppsDeploySucceeded(ctx, st, agent, j, result, emit)
	}

	time.Sleep(30 * time.Second)
	st.ProvisionLogs.Remove(j.deployID)
}

func rtDockerAppsDeploySucceeded(ctx context.Context, st *AppState, agent AgentHandle, j rtDockerAppsDeployJob, result any, emit func(step, label, status string, msg *string)) {
	db := st.DB
	emit("pull", "Pulling Docker image", "done", nil)
	emit("start", "Starting container", "done", nil)

	hasSSL, _ := jsonBool(jsonGet(result, "ssl"))
	if j.domain != nil {
		obj, _ := jsonObj(result)
		_, hasProxy := obj["proxy"]
		if hasProxy {
			emit("proxy", "Configuring reverse proxy", "done", nil)
		}
		if hasSSL {
			emit("ssl", "Provisioning SSL certificate", "done", nil)
		} else if hasProxy {
			emit("ssl", "SSL certificate", "error", new("Skipped — can be provisioned later"))
		}
	}

	// Password-protect any sidecar-backed app once it's live on a domain. The
	// sidecar's docker-socket-proxy restricts WHAT the app can do to the
	// host's Docker daemon, but nothing gated WHO can reach the app itself —
	// Dozzle's own auth needs a mounted users.yml or a forward-proxy header
	// scheme, neither reachable through template env vars. nginx auth_basic
	// closes it at the layer DockPanel controls (the same htpasswd mechanism
	// as Sites' password-protect), called directly since a docker app has no
	// `sites` row. KNOWN GAP: the generated password is shown once (and
	// logged to system_logs as a backup) with no reset UI yet.
	isSidecar := false
	for _, t := range rtDockerAppsSidecarTemplates {
		isSidecar = isSidecar || t == j.template
	}
	if isSidecar && j.domain != nil {
		domain := *j.domain
		const authUsername = "admin"
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		authPassword := hex.EncodeToString(buf)
		if _, err := agent.Post(ctx, "/nginx/password-protect", map[string]any{
			"domain": domain, "path": "/", "username": authUsername, "password": authPassword,
		}); err == nil {
			msg := fmt.Sprintf("Username: %s — Password: %s (shown once here and logged to System Logs — save it now)", authUsername, authPassword)
			emit("auth", "Password-protecting the app", "done", &msg)
			SystemLogLogEvent(ctx, db, "warning", "api",
				fmt.Sprintf("Auto-generated password protection for %s (%s)", j.appName, domain), &msg)
		} else {
			emit("auth", "Password-protecting the app", "error", new(fmt.Sprintf(
				"Could not password-protect this app: %v — it is reachable with NO login until this is fixed by hand", err)))
			slog.Error(fmt.Sprintf("Failed to password-protect sidecar app %s (%s): %v", j.appName, domain, err))
		}
	}

	emit("complete", "App deployed", "done", nil)

	suffix := ""
	if j.domain != nil {
		suffix = " → " + *j.domain
	}
	slog.Info(fmt.Sprintf("App deployed: %s (%s)%s", j.appName, j.template, suffix))
	ActivityLogActivity(ctx, db, j.userID, j.email, "app.deploy", new("app"), new(j.appName), new(j.template), nil, j.keyID)
	ExtensionsFireEvent(db, "app.deployed", map[string]any{"name": j.appName, "domain": j.domain})

	// Give the domain an owner row so SSL renewal can find it (see migration
	// 20260905180000_docker_app_ssl_domains.sql). Written regardless of the
	// mode, so the renewal fallback can see a none/provided app and decline
	// to touch it rather than reading it as "never deployed".
	if j.domain != nil {
		_, _ = execSQL(ctx, db,
			"INSERT INTO docker_app_domains "+
				"(user_id, server_id, app_name, domain, ssl_email, tls_mode) "+
				"VALUES ($1, $2, $3, $4, $5, $6) "+
				"ON CONFLICT (server_id, domain) DO UPDATE SET "+
				"user_id = EXCLUDED.user_id, app_name = EXCLUDED.app_name, "+
				"ssl_email = EXCLUDED.ssl_email, tls_mode = EXCLUDED.tls_mode, "+
				"updated_at = NOW()",
			j.userID, j.serverID, j.appName, *j.domain, j.sslEmail, j.tlsMode)
	}

	// Seed container_sleep_config's gpu_enabled the moment it is knowable —
	// nothing else records GPU passthrough, so auto-sleep could not tell a GPU
	// workload from an idle web app. auto_sleep_enabled and
	// sleep_after_minutes are deliberately NOT in the UPDATE SET: an admin's
	// own choice must survive a redeploy.
	if cid, ok := jsonStr(jsonGet(result, "container_id")); ok {
		_, _ = execSQL(ctx, db,
			"INSERT INTO container_sleep_config "+
				"(container_id, container_name, domain, gpu_enabled, auto_sleep_enabled, sleep_after_minutes, last_activity_at, server_id) "+
				"VALUES ($1, $2, $3, $4, false, 30, NOW(), $5) "+
				"ON CONFLICT (container_id) DO UPDATE SET "+
				"gpu_enabled = $4, container_name = $2, domain = $3, server_id = $5, updated_at = NOW()",
			cid, j.appName, j.domain, j.gpuEnabled, j.serverID)
	}

	// GAP 12: auto-create a monitor for an app with a domain — on the scheme
	// this deploy actually produced, so a deploy that just said SSL was
	// skipped does not get a monitor that can only ever fail.
	if j.domain != nil {
		domain := *j.domain
		scheme := "http"
		if hasSSL {
			scheme = "https"
		}
		_, _ = execSQL(ctx, db,
			"INSERT INTO monitors (user_id, url, name, check_interval, status, enabled, monitor_type) "+
				"VALUES ($1, $2, $3, 60, 'pending', TRUE, 'http') ON CONFLICT DO NOTHING",
			j.userID, scheme+"://"+domain, fmt.Sprintf("%s (%s)", j.appName, domain))
		// Auto-create a status page component.
		_, _ = execSQL(ctx, db,
			"INSERT INTO status_page_components (user_id, name, description, group_name) "+
				"SELECT $1, $2, $3, 'Docker Apps' WHERE EXISTS (SELECT 1 FROM status_page_config WHERE user_id = $1 AND enabled = TRUE)",
			j.userID, j.appName, "Docker app: "+j.appName)
	}
}

// rtDockerAppsParentDomain extracts the zone a record lives in
// ("mail.dockpanel.dev" → "dockpanel.dev"), with splitn(3, '.') semantics.
func rtDockerAppsParentDomain(domain string) string {
	parts := strings.SplitN(domain, ".", 3)
	if len(parts) >= 3 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return domain
}

// rtDockerAppsDoJSON sends a JSON request with the default client
// (reqwest::Client::new()).
func rtDockerAppsDoJSON(ctx context.Context, method, url string, h http.Header, body any) (*http.Response, error) {
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

func rtDockerAppsCloudflareCreate(ctx context.Context, emit func(string, string, string, *string), zoneID, token string, email *string, domain, serverIP string) {
	resp, err := rtDockerAppsDoJSON(ctx, http.MethodPost,
		"https://api.cloudflare.com/client/v4/zones/"+zoneID+"/dns_records", cfHeaders(token, email),
		map[string]any{"type": "A", "name": domain, "content": serverIP, "proxied": true, "ttl": 1})
	if err != nil {
		emit("dns", "Creating DNS record", "error", new(fmt.Sprintf("DNS API error: %v — create manually", err)))
		return
	}
	defer resp.Body.Close()
	var body any
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	_ = dec.Decode(&body)
	if ok, _ := jsonBool(jsonGet(body, "success")); ok {
		emit("dns", "Creating DNS record", "done", nil)
		slog.Info(fmt.Sprintf("Auto-DNS: created A record %s → %s", domain, serverIP))
		return
	}
	msg, ok := jsonStr(jsonGet(body, "errors", 0, "message"))
	if !ok {
		msg = "Unknown error"
	}
	emit("dns", "Creating DNS record", "error", new(fmt.Sprintf("DNS failed: %s — create manually", msg)))
	slog.Warn(fmt.Sprintf("Auto-DNS failed for %s: %s", domain, msg))
}

// rtDockerAppsPowerDNSSettings reads (url, decrypted key) when both exist.
func rtDockerAppsPowerDNSSettings(ctx context.Context, db *pgxpool.Pool) (string, string, bool) {
	rows, _ := queryAll[Tup2[string, string]](ctx, db,
		"SELECT key, value FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key')")
	var url, keyEnc *string
	for _, kv := range rows {
		switch kv.A {
		case "pdns_api_url":
			url = &kv.B
		case "pdns_api_key":
			keyEnc = &kv.B
		}
	}
	if url == nil || keyEnc == nil {
		return "", "", false
	}
	return *url, SecretsCryptoDecryptCredentialFromEnv(*keyEnc), true
}

func rtDockerAppsPowerDNSCreate(ctx context.Context, db *pgxpool.Pool, emit func(string, string, string, *string), parent, domain, serverIP string) {
	url, key, ok := rtDockerAppsPowerDNSSettings(ctx, db)
	if !ok {
		emit("dns", "Creating DNS record", "error", new("PowerDNS not configured — create record manually"))
		return
	}
	zoneFQDN := parent
	if !strings.HasSuffix(zoneFQDN, ".") {
		zoneFQDN += "."
	}
	resp, err := rtDockerAppsDoJSON(ctx, http.MethodPatch, url+"/api/v1/servers/localhost/zones/"+zoneFQDN,
		http.Header{"X-Api-Key": {key}},
		map[string]any{"rrsets": []any{map[string]any{
			"name": domain + ".", "type": "A", "ttl": 300, "changetype": "REPLACE",
			"records": []any{map[string]any{"content": serverIP, "disabled": false}},
		}}})
	if err != nil {
		emit("dns", "Creating DNS record", "error", new(fmt.Sprintf("PowerDNS API error: %v — create manually", err)))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		emit("dns", "Creating DNS record", "done", nil)
		slog.Info(fmt.Sprintf("Auto-DNS (PowerDNS): created A record %s → %s", domain, serverIP))
		return
	}
	text, _ := io.ReadAll(resp.Body)
	emit("dns", "Creating DNS record", "error", new(fmt.Sprintf("PowerDNS error: %s — create manually", text)))
}

// ── Deploy preflight (the guidance layer's Docker-apps vertical) ────────

// rtDockerAppsContainerNamePrefix is the prefix the agent adds when it names
// an app's container (`dockpanel-app-{name}`).
const rtDockerAppsContainerNamePrefix = "dockpanel-app-"

type rtDockerAppsPreflightQuery struct {
	TemplateID string  `json:"template_id"`
	Name       string  `json:"name" serde:"default"`
	Port       uint16  `json:"port" serde:"default"`
	MemoryMB   *uint64 `json:"memory_mb"`
	// NAMES of env vars the form has a non-empty value for. Only names travel:
	// a preflight run as the user typed a database password would otherwise
	// put it in a query string, the access log and the browser history.
	FilledEnv string `json:"filled_env" serde:"default"`
}

// rtDockerAppsGatherAppFacts gathers what the app checks need in as few agent
// round-trips as possible, and never lets a missing fact become a refusal.
func rtDockerAppsGatherAppFacts(ctx context.Context, db *pgxpool.Pool, agent AgentHandle, serverID uuid.UUID, port uint16) PrerequisitesAppsHostFacts {
	facts := PrerequisitesAppsHostFacts{}

	// The agent reports the CONTAINER name (`dockpanel-app-pg-ok`) while the
	// user types the bare app name (`pg-ok`); comparing them directly made the
	// collision check permanently inert. Strip the prefix.
	if apps, err := agent.Get(ctx, "/apps"); err == nil {
		arr, _ := jsonArr(apps)
		for _, app := range arr {
			raw, ok := jsonStr(jsonGet(app, "name"))
			if !ok {
				continue
			}
			name := strings.TrimPrefix(raw, rtDockerAppsContainerNamePrefix)
			facts.TakenNames = append(facts.TakenNames, name)
			if p, ok := jsonU64(jsonGet(app, "port")); ok {
				facts.UsedPorts = append(facts.UsedPorts, PrerequisitesAppsPortHolder{
					Port: uint16(p), Description: fmt.Sprintf("the app `%s`", name),
				})
			}
		}
	}

	// Sites that proxy to a local port hold one too — but only on the host
	// these facts describe. Fleet-wide, a port taken on another machine was
	// refused here, more often the larger the fleet grew.
	sitePorts, _ := queryAll[Tup2[*int32, string]](ctx, db,
		"SELECT proxy_port, domain FROM sites WHERE proxy_port IS NOT NULL AND server_id = $1", serverID)
	for _, sp := range sitePorts {
		if sp.A != nil && *sp.A > 0 && *sp.A <= 65535 {
			facts.UsedPorts = append(facts.UsedPorts, PrerequisitesAppsPortHolder{
				Port: uint16(*sp.A), Description: "the site " + sp.B,
			})
		}
	}

	if info, err := agent.Get(ctx, "/system/info"); err == nil {
		if v, ok := jsonU64(jsonGet(info, "mem_total_mb")); ok {
			facts.MemTotalMB = &v
		}
		if v, ok := jsonU64(jsonGet(info, "mem_used_mb")); ok {
			facts.MemUsedMB = &v
		}
	}

	// The host's own verdict on the port. An agent older than v2.29.0 has no
	// such route, so this stays nil and the check degrades to unknown — a
	// member we cannot interrogate must not be a member we refuse.
	if port > 0 {
		if v, err := agent.Get(ctx, fmt.Sprintf("/system/port-check?port=%d", port)); err == nil {
			if b, ok := jsonBool(jsonGet(v, "free")); ok {
				facts.PortProbeFree = &b
			}
		}
	}
	return facts
}

// rtDockerAppsTemplateEnvSpecs reads a template's declared env vars from the
// agent's catalogue.
func rtDockerAppsTemplateEnvSpecs(ctx context.Context, agent AgentHandle, templateID string) []PrerequisitesAppsAppEnvSpec {
	specs := []PrerequisitesAppsAppEnvSpec{}
	templates, err := agent.Get(ctx, "/apps/templates")
	if err != nil {
		return specs
	}
	arr, _ := jsonArr(templates)
	for _, t := range arr {
		if id, ok := jsonStr(jsonGet(t, "id")); !ok || id != templateID {
			continue
		}
		vars, _ := jsonArr(jsonGet(t, "env_vars"))
		for _, v := range vars {
			s := func(k string) string { x, _ := jsonStr(jsonGet(v, k)); return x }
			b := func(k string) bool { x, _ := jsonBool(jsonGet(v, k)); return x }
			label := s("label")
			if label == "" {
				label = s("name")
			}
			specs = append(specs, PrerequisitesAppsAppEnvSpec{
				Name: s("name"), Label: label, Default: s("default"), Required: b("required"), Secret: b("secret"),
			})
		}
		break
	}
	return specs
}

// rtDockerAppsIntentFromQuery builds the intent the checks evaluate. filled_env
// carries only NAMES, so the required-env check sees a placeholder rather than
// the secret itself; it only ever tests emptiness.
func rtDockerAppsIntentFromQuery(q *rtDockerAppsPreflightQuery) PrerequisitesAppsAppDeployIntent {
	env := map[string]string{}
	for _, s := range strings.Split(q.FilledEnv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			env[s] = "set"
		}
	}
	return PrerequisitesAppsAppDeployIntent{TemplateID: q.TemplateID, Name: q.Name, Port: q.Port, Env: env, MemoryMB: q.MemoryMB}
}

// rtDockerAppsPreflight is GET /api/apps/preflight — evaluate the
// prerequisites for an intended deploy while they are still cheap to fix.
func rtDockerAppsPreflight(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var q rtDockerAppsPreflightQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()
	intent := rtDockerAppsIntentFromQuery(&q)
	specs := rtDockerAppsTemplateEnvSpecs(ctx, agent, q.TemplateID)
	facts := rtDockerAppsGatherAppFacts(ctx, st.DB, agent, serverID, q.Port)
	results := PrerequisitesAppsEvaluate(&intent, specs, &facts)
	writeJSON(w, http.StatusOK, map[string]any{"checks": results, "blocked": PrerequisitesFirstBlocker(results) != nil})
	return nil
}

// rtDockerAppsDeployLog is GET /api/apps/deploy/{deploy_id}/log — SSE stream
// of deploy progress.
//
// The admin exemption is gone: this map is one keyspace shared with site
// provisioning, whose stream carries a generated CMS password, so "has the
// admin role" was never a licence to read another tenant's log.
func rtDockerAppsDeployLog(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	deployID, err := pathUUID(r, "deploy_id")
	if err != nil {
		return err
	}
	snapshot, ch, unsub, err := st.ProvisionLogs.Open(deployID, claims.Sub, "No active deploy")
	if err != nil {
		return err
	}
	defer unsub()
	rtDockerAppsServeSSE(st, w, r, snapshot, ch)
	return nil
}

// rtDockerAppsServeSSE writes axum's Sse: each step as `data: <json>`, a
// `:ping` keep-alive every 15s, ending when the channel closes (the deploy
// finished and its entry was dropped), the client leaves, or the panel shuts
// down — a deploy in progress can outlive the graceful-drain window.
func rtDockerAppsServeSSE(st *AppState, w http.ResponseWriter, r *http.Request, snapshot []ProvisionStep, ch <-chan ProvisionStep) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	send := func(s string) bool {
		if _, err := io.WriteString(w, s); err != nil {
			return false
		}
		if fl != nil {
			fl.Flush()
		}
		return true
	}
	for _, step := range snapshot {
		if !send("data: " + extensionsJSON(step) + "\n\n") {
			return
		}
	}
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case step, ok := <-ch:
			if !ok || !send("data: "+extensionsJSON(step)+"\n\n") {
				return
			}
		case <-ping.C:
			if !send(":ping\n\n") {
				return
			}
		case <-r.Context().Done():
			return
		case <-st.Shutdown.Done():
			return
		}
	}
}

// ── Listing & lifecycle ─────────────────────────────────────────────────

// rtDockerAppsListApps is GET /api/apps.
func rtDockerAppsListApps(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, serverID, agent, err := rtDockerAppsAdmin(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	result, err := agent.Get(ctx, "/apps")
	if err != nil {
		return agentError("Docker apps", err)
	}

	// Annotate each container with WHY it is stopped, if the panel stopped
	// it. Carried on this already-server-scoped payload because
	// container_expected_stops is keyed by server. Without it the Apps page
	// calls every stopped container "crashed", including ones the panel
	// stopped itself.
	reasons := ExpectedStopsReasonsOnServer(ctx, st.DB, serverID)
	if len(reasons) > 0 {
		arr, _ := jsonArr(result)
		for _, app := range arr {
			obj, ok := jsonObj(app)
			if !ok {
				continue
			}
			name, _ := jsonStr(obj["name"])
			for _, rs := range reasons {
				if rs.A != name {
					continue
				}
				obj["expected_stop_reason"] = rs.B
				if rs.C != nil {
					obj["expected_stop_by"] = *rs.C
				}
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtDockerAppsResolveContainerName resolves a caller-supplied container id to
// the name the agent reports.
//
// Docker resolves an id PREFIX, so the short form `docker ps` prints works on
// every verb — but the alert engine keys on the full name, so writing the
// caller's string would record a row nothing can ever match. nil when not in
// the listing: a MISSING expectation costs one spurious alert, a MIS-KEYED one
// costs permanent silence.
func rtDockerAppsResolveContainerName(ctx context.Context, agent AgentHandle, containerID string) *string {
	apps, err := agent.Get(ctx, "/apps")
	if err != nil {
		return nil
	}
	arr, ok := jsonArr(apps)
	if !ok {
		return nil
	}
	// An exact id wins outright; otherwise a prefix match only if UNIQUE — an
	// ambiguous prefix resolves to nothing, not to whichever is listed first.
	var hits []string
	for _, app := range arr {
		id, ok := jsonStr(jsonGet(app, "container_id"))
		if !ok {
			continue
		}
		name, ok := jsonStr(jsonGet(app, "name"))
		if !ok {
			continue
		}
		if id == containerID {
			return &name
		}
		if strings.HasPrefix(id, containerID) {
			hits = append(hits, name)
		}
	}
	if len(hits) == 1 {
		return &hits[0]
	}
	return nil
}

// rtDockerAppsStopApp is POST /api/apps/{container_id}/stop.
func rtDockerAppsStopApp(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	if _, err := agent.Post(ctx, "/apps/"+cid+"/stop", nil); err != nil {
		return agentError("Container stop", err)
	}
	// Recorded only AFTER the stop succeeds: recording first and having the
	// agent refuse would mark a running container expectedly stopped, and its
	// next genuine crash would be suppressed.
	if name := rtDockerAppsResolveContainerName(ctx, agent, cid); name != nil {
		ExpectedStopsRecord(ctx, st.DB, serverID, *name, ExpectedStopsReasonOperatorStop, new(claims.Email))
		ExpectedStopsResolveOpenContainerDown(ctx, st.DB, serverID, *name)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "container.stop", new("container"), new(cid), nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtDockerAppsStartApp is POST /api/apps/{container_id}/start.
func rtDockerAppsStartApp(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	if _, err := agent.Post(ctx, "/apps/"+cid+"/start", nil); err != nil {
		return agentError("Container start", err)
	}
	// Immediacy only — the alert engine clears this within a sweep anyway,
	// but the Apps page stops saying "stopped intentionally" at once.
	if name := rtDockerAppsResolveContainerName(ctx, agent, cid); name != nil {
		ExpectedStopsClear(ctx, st.DB, serverID, *name)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "container.start", new("container"), new(cid), nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtDockerAppsRestartApp is POST /api/apps/{container_id}/restart.
func rtDockerAppsRestartApp(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	if _, err := agent.Post(ctx, "/apps/"+cid+"/restart", nil); err != nil {
		return agentError("Container restart", err)
	}
	if name := rtDockerAppsResolveContainerName(ctx, agent, cid); name != nil {
		ExpectedStopsClear(ctx, st.DB, serverID, *name)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "container.restart", new("container"), new(cid), nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtDockerAppsAppLogs is GET /api/apps/{container_id}/logs.
func rtDockerAppsAppLogs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), "/apps/"+cid+"/logs")
	return rtDockerAppsPassthrough(w, res, err, "Container logs")
}

// rtDockerAppsUpdateApp is POST /api/apps/{container_id}/update — pull the
// latest image and recreate, asynchronously with SSE progress.
func rtDockerAppsUpdateApp(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	deployID := uuid.New()
	st.ProvisionLogs.Register(deployID, claims.Sub, 32)
	userID, email, keyID := claims.Sub, claims.Email, claims.KeyID

	go func() {
		ctx := context.Background()
		db := st.DB
		emit := func(step, label, status string, msg *string) {
			st.ProvisionLogs.Emit(deployID, ProvisionStep{Step: step, Label: label, Status: status, Message: msg})
		}
		emit("pull", "Pulling latest image", "in_progress", nil)

		// Recorded BEFORE the recreate starts (the opposite of stop): the
		// point of this call is to interrupt a running container via a
		// remove-then-create, and the healer's 120s tick must be blind to that
		// gap from the moment it opens — or it may "heal" a container
		// mid-recreate. Cleared unconditionally below, success or failure, or
		// a refused update would suppress the container's next real crash.
		containerName := rtDockerAppsResolveContainerName(ctx, agent, cid)
		if containerName != nil {
			ExpectedStopsRecord(ctx, db, serverID, *containerName, ExpectedStopsReasonRecreate, &email)
		}

		// PostLong: this pulls an image AND may copy an app's data out of its
		// writable layer onto a bind mount — neither fits 60s on a modest
		// uplink, and a slow success would read as failure.
		result, err := agent.PostLong(ctx, "/apps/"+cid+"/update", nil, 900)
		if err != nil {
			// This arm catches every way the update can fail; it once filed all
			// of them under the pull step, and later left that step spinning
			// under a red "Update failed" for ever. `pending`: pull, recreate
			// and migrate are one agent call, so the panel genuinely does not
			// know whether the image arrived.
			emit("pull", "Pulling latest image", "pending", nil)
			emit("update", "Updating app", "error", new(err.Error()))
			emit("complete", "Update failed", "error", nil)
			slog.Error(fmt.Sprintf("App update failed: %s: %v", cid, err))
		} else {
			blueGreen, _ := jsonBool(jsonGet(result, "blue_green"))
			strs := func(k string) []string {
				arr, _ := jsonArr(jsonGet(result, k))
				out := []string{}
				for _, v := range arr {
					if s, ok := jsonStr(v); ok {
						out = append(out, s)
					}
				}
				return out
			}
			migrated := strs("migrated_volumes")
			emit("pull", "Pulling latest image", "done", nil)
			if len(migrated) > 0 {
				emit("migrate", "Moved app data onto persistent storage", "done", new(
					"This app was deployed before DockPanel gave it a persistent "+
						"volume, so its data lived inside the container and would have "+
						"been lost on this update. It has been copied to durable storage "+
						"and will survive future updates: "+strings.Join(migrated, ", ")))
			}
			if repaired := strs("repaired_volumes"); len(repaired) > 0 {
				emit("repair", "Repaired file ownership on the app's data", "done", new(
					"DockPanel v2.111.0 to v2.113.1 moved this app's data onto "+
						"persistent storage but left every file owned by root, so an app "+
						"that does not run as root could not write it — if this one has "+
						"been failing to start since it was last updated, that is why. "+
						"Ownership has been given back to the account the app runs as: "+strings.Join(repaired, ", ")))
			}
			if blueGreen {
				emit("health", "Health check passed", "done", nil)
				emit("swap", "Traffic swapped (zero-downtime)", "done", nil)
				emit("cleanup", "Old container removed", "done", nil)
				emit("complete", "App updated (zero-downtime)", "done", nil)
			} else {
				emit("recreate", "Recreating container", "done", nil)
				emit("complete", "App updated", "done", nil)
			}
			if newID, ok := jsonStr(jsonGet(result, "container_id")); ok {
				rtDockerAppsRekeySleepConfig(ctx, db, cid, newID)
			}
			ActivityLogActivity(ctx, db, userID, email, "app.update", new("app"), new(cid), nil, nil, keyID)
			bg := ""
			if blueGreen {
				bg = " (blue-green)"
			}
			slog.Info(fmt.Sprintf("App updated%s: %s", bg, cid))
		}

		if containerName != nil {
			ExpectedStopsClear(ctx, db, serverID, *containerName)
		}
		time.Sleep(60 * time.Second)
		st.ProvisionLogs.Remove(deployID)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{"deploy_id": deployID, "message": "Update started"})
	return nil
}

// rtDockerAppsAppEnv is GET /api/apps/{container_id}/env.
func rtDockerAppsAppEnv(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), "/apps/"+cid+"/env")
	return rtDockerAppsPassthrough(w, res, err, "Container env")
}

// rtDockerAppsRecreate runs a recreate-shaped agent call with the expected
// stop recorded before and cleared after, then re-keys the sleep config.
//
// It runs on a context that the client cannot cancel (the Rust spawned
// task): the browser is proxied through Cloudflare's ~100s origin budget,
// inside the 900s this can take, and a cut connection must not cancel the
// agent call mid-recreate.
func rtDockerAppsRecreate(ctx context.Context, st *AppState, agent AgentHandle, serverID uuid.UUID, cid, email string, call func(ctx context.Context) (any, error), errCtx string) (any, error) {
	ctx = context.WithoutCancel(ctx)
	containerName := rtDockerAppsResolveContainerName(ctx, agent, cid)
	if containerName != nil {
		ExpectedStopsRecord(ctx, st.DB, serverID, *containerName, ExpectedStopsReasonRecreate, &email)
	}
	result, err := call(ctx)
	if containerName != nil {
		ExpectedStopsClear(ctx, st.DB, serverID, *containerName)
	}
	if err != nil {
		return nil, agentError(errCtx, err)
	}
	if newID, ok := jsonStr(jsonGet(result, "container_id")); ok {
		rtDockerAppsRekeySleepConfig(ctx, st.DB, cid, newID)
	}
	return result, nil
}

// rtDockerAppsUpdateEnv is PUT /api/apps/{container_id}/env.
func rtDockerAppsUpdateEnv(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, err := rtDockerAppsAdmin2(st, r)
	if err != nil {
		return err
	}
	body, err := rtDockerAppsValueBody(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	cid := r.PathValue("container_id")
	if !isValidContainerID(cid) {
		return apiErr(http.StatusBadRequest, "Invalid container ID")
	}

	// Same bounds the deploy door has always enforced. This door never had
	// them because the edit dialog could only send existing keys; it can
	// compose arbitrary keys now, so the asymmetry is indefensible.
	if env, ok := jsonObj(jsonGet(body, "env")); ok {
		if len(env) > 50 {
			return apiErr(http.StatusBadRequest, "Too many environment variables (max 50)")
		}
		for k, v := range env {
			if k == "" || len(k) > 255 {
				return apiErr(http.StatusBadRequest, "Invalid environment variable name")
			}
			// Docker splits on the first `=`, so a key containing one silently
			// becomes a different variable; this door takes keys from a text
			// input.
			if strings.ContainsAny(k, "=\x00") {
				return apiErr(http.StatusBadRequest, "Environment variable name may not contain '=' or a null byte")
			}
			if s, ok := jsonStr(v); ok && len(s) > 4096 {
				return apiErr(http.StatusBadRequest, "Environment variable value too large (max 4KB)")
			}
		}
	}

	// Long verb: saving env recreates the container and may first copy the
	// app's data onto a bind mount (#110).
	ctx := r.Context()
	result, err := rtDockerAppsRecreate(ctx, st, agent, serverID, cid, claims.Email, func(ctx context.Context) (any, error) {
		return agent.PutLong(ctx, "/apps/"+cid+"/env", body, 900)
	}, "Update env")
	if err != nil {
		return err
	}
	ActivityLogActivity(context.WithoutCancel(ctx), st.DB, claims.Sub, claims.Email, "app.update_env", new("app"), new(cid), nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtDockerAppsAdmin2 is the AuthUser + ServerScope prologue WITHOUT the role
// check, for handlers whose Json body is extracted before require_admin.
func rtDockerAppsAdmin2(st *AppState, r *http.Request) (*Claims, uuid.UUID, AgentHandle, error) {
	claims, err := st.authUser(r)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	return claims, serverID, agent, nil
}

// rtDockerAppsWithBody is the prologue of {container_id} handlers that take a
// Json<Value>: AuthUser, ServerScope, Json, then require_admin and the id
// check (the Rust order).
func rtDockerAppsWithBody(st *AppState, r *http.Request, checkID bool) (*Claims, uuid.UUID, AgentHandle, any, error) {
	claims, serverID, agent, err := rtDockerAppsAdmin2(st, r)
	if err != nil {
		return nil, uuid.Nil, nil, nil, err
	}
	body, err := rtDockerAppsValueBody(r)
	if err != nil {
		return nil, uuid.Nil, nil, nil, err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return nil, uuid.Nil, nil, nil, err
	}
	if checkID && !isValidContainerID(r.PathValue("container_id")) {
		return nil, uuid.Nil, nil, nil, apiErr(http.StatusBadRequest, "Invalid container ID")
	}
	return claims, serverID, agent, body, nil
}

// rtDockerAppsContainerStats is GET /api/apps/{container_id}/stats.
func rtDockerAppsContainerStats(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), "/apps/"+cid+"/stats")
	return rtDockerAppsPassthrough(w, res, err, "Container stats")
}

// rtDockerAppsUpdateImage is PUT /api/apps/{container_id}/image — change an
// app's image tag.
func rtDockerAppsUpdateImage(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, body, err := rtDockerAppsWithBody(st, r, true)
	if err != nil {
		return err
	}
	cid := r.PathValue("container_id")
	ctx := r.Context()

	s, _ := jsonStr(jsonGet(body, "image"))
	image := strings.TrimSpace(s)
	if image == "" {
		return apiErr(http.StatusBadRequest, "image is required (e.g., postgres:17)")
	}
	if len(image) > 256 || strings.Contains(image, " ") || strings.Contains(image, "\x00") {
		return apiErr(http.StatusBadRequest, "Invalid image format")
	}

	// The operator is naming an image to run — the same question deploy asks,
	// about the same host. Unlike update_app this is not a re-pull of the
	// running reference, so the stored scan is of the image being INTRODUCED.
	if err := rtImageScansPreflightGateImage(ctx, st.DB, serverID, agent, image); err != nil {
		return err
	}
	if err := rtDockerAppsEnforceAllowedImages(ctx, st.DB, claims.Sub, []string{image}); err != nil {
		return err
	}

	// Long verb, detached like update_env: another recreate behind a
	// connection Cloudflare will cut at ~100s.
	result, err := rtDockerAppsRecreate(ctx, st, agent, serverID, cid, claims.Email, func(ctx context.Context) (any, error) {
		return agent.PostLong(ctx, "/apps/"+cid+"/change-image", map[string]any{"image": image}, 900)
	}, "Change image")
	if err != nil {
		return err
	}
	ActivityLogActivity(context.WithoutCancel(ctx), st.DB, claims.Sub, claims.Email, "app.change_image", new("app"), new(cid), new(image), nil, claims.KeyID)
	slog.Info(fmt.Sprintf("App image changed: %s → %s", cid, image))
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtDockerAppsUpdateLimits is PUT /api/apps/{container_id}/limits.
func rtDockerAppsUpdateLimits(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, body, err := rtDockerAppsWithBody(st, r, true)
	if err != nil {
		return err
	}
	cid := r.PathValue("container_id")
	var memoryMB, cpuPercent *uint64
	if v, ok := jsonU64(jsonGet(body, "memory_mb")); ok {
		memoryMB = &v
	}
	if v, ok := jsonU64(jsonGet(body, "cpu_percent")); ok {
		cpuPercent = &v
	}
	if memoryMB == nil && cpuPercent == nil {
		return apiErr(http.StatusBadRequest, "At least one of memory_mb or cpu_percent is required")
	}
	if memoryMB != nil && (*memoryMB < 4 || *memoryMB > 65536) {
		return apiErr(http.StatusBadRequest, "memory_mb must be between 4 and 65536")
	}
	if cpuPercent != nil && (*cpuPercent == 0 || *cpuPercent > 10000) {
		return apiErr(http.StatusBadRequest, "cpu_percent must be between 1 and 10000")
	}
	ctx := r.Context()
	result, err := agent.Post(ctx, "/apps/"+cid+"/update-limits", map[string]any{"memory_mb": memoryMB, "cpu_percent": cpuPercent})
	if err != nil {
		return agentError("Update limits", err)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "app.update_limits", new("app"), new(cid), nil, nil, claims.KeyID)
	slog.Info(fmt.Sprintf("App limits updated: %s (mem: %s MB, cpu: %s%%)", cid, rtDockerAppsDebugOpt(memoryMB), rtDockerAppsDebugOpt(cpuPercent)))
	writeJSON(w, http.StatusOK, result)
	return nil
}

func rtDockerAppsDebugOpt(v *uint64) string {
	if v == nil {
		return "None"
	}
	return fmt.Sprintf("Some(%d)", *v)
}

// rtDockerAppsLockdownErr is the lockdown refusal shared by the two shell
// doors.
func rtDockerAppsLockdownErr() error {
	return apiErr(http.StatusServiceUnavailable,
		"System is in lockdown mode. Container shell access is disabled until "+
			"an administrator unlocks the panel (Security → Lockdown).")
}

// rtDockerAppsShellInfo is GET /api/apps/{container_id}/shell-info.
//
// Gated on the lockdown like exec: the agent answers by running `docker exec
// <id> which bash`, so it is command execution on the host and the step
// right before opening a shell.
func rtDockerAppsShellInfo(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if rtTerminalTerminalsLockedDown(r.Context(), st.DB) {
		return rtDockerAppsLockdownErr()
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	cid := r.PathValue("container_id")
	if !isValidContainerID(cid) {
		return apiErr(http.StatusBadRequest, "Invalid container ID")
	}
	res, err := agent.Get(r.Context(), "/apps/"+cid+"/shell-info")
	return rtDockerAppsPassthrough(w, res, err, "Shell info")
}

// rtDockerAppsExecCommand is POST /api/apps/{container_id}/exec.
//
// Until v2.110.0 the lockdown closed the Terminal page but not this door —
// the Apps console, which the agent runs as `docker exec <id> sh -c <cmd>` —
// while GET /api/security/lockdown told the page terminals were blocked.
// require_admin is not the mitigation it looks like: a lockdown is declared
// precisely when an admin session is believed compromised. Placed above the
// role gate, and calling the terminal module's own predicate so the doors
// cannot answer differently.
func rtDockerAppsExecCommand(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	body, err := rtDockerAppsValueBody(r)
	if err != nil {
		return err
	}
	if rtTerminalTerminalsLockedDown(r.Context(), st.DB) {
		return rtDockerAppsLockdownErr()
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	cid := r.PathValue("container_id")
	if !isValidContainerID(cid) {
		return apiErr(http.StatusBadRequest, "Invalid container ID")
	}
	res, err := agent.Post(r.Context(), "/apps/"+cid+"/exec", body)
	return rtDockerAppsPassthrough(w, res, err, "Container exec")
}

// ─── Ollama model management ────────────────────────────────────────────

// rtDockerAppsOllamaListModels is GET /api/apps/{container_id}/ollama/models.
func rtDockerAppsOllamaListModels(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), "/apps/"+cid+"/ollama/models")
	return rtDockerAppsPassthrough(w, res, err, "Ollama list models")
}

// rtDockerAppsOllamaPullModel is POST /api/apps/{container_id}/ollama/pull.
func rtDockerAppsOllamaPullModel(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, body, err := rtDockerAppsWithBody(st, r, true)
	if err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), "/apps/"+r.PathValue("container_id")+"/ollama/pull", body)
	return rtDockerAppsPassthrough(w, res, err, "Ollama pull model")
}

// rtDockerAppsOllamaDeleteModel is POST /api/apps/{container_id}/ollama/delete.
func rtDockerAppsOllamaDeleteModel(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, body, err := rtDockerAppsWithBody(st, r, true)
	if err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), "/apps/"+r.PathValue("container_id")+"/ollama/delete", body)
	return rtDockerAppsPassthrough(w, res, err, "Ollama delete model")
}

// rtDockerAppsContainerVolumes is GET /api/apps/{container_id}/volumes.
func rtDockerAppsContainerVolumes(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), "/apps/"+cid+"/volumes")
	return rtDockerAppsPassthrough(w, res, err, "Container volumes")
}

// ── Registries & images ─────────────────────────────────────────────────

// rtDockerAppsRegistryLogin is POST /api/apps/registry-login.
func rtDockerAppsRegistryLogin(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, body, err := rtDockerAppsWithBody(st, r, false)
	if err != nil {
		return err
	}
	ctx := r.Context()
	result, err := agent.Post(ctx, "/apps/registry-login", body)
	if err != nil {
		return agentError("Registry login", err)
	}
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "app.registry_login", new("registry"), nil, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "app.registry_login", new(claims.Email), ip, new("registry"), nil, nil, nil, "warning", claims.KeyID)
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtDockerAppsListRegistries is GET /api/apps/registries.
func rtDockerAppsListRegistries(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, err := rtDockerAppsAdmin(st, r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), "/apps/registries")
	return rtDockerAppsPassthrough(w, res, err, "List registries")
}

// rtDockerAppsRegistryLogout is POST /api/apps/registry-logout.
func rtDockerAppsRegistryLogout(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, body, err := rtDockerAppsWithBody(st, r, false)
	if err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), "/apps/registry-logout", body)
	return rtDockerAppsPassthrough(w, res, err, "Registry logout")
}

// rtDockerAppsListImages is GET /api/apps/images.
func rtDockerAppsListImages(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, err := rtDockerAppsAdmin(st, r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), "/apps/images")
	return rtDockerAppsPassthrough(w, res, err, "Docker images")
}

// rtDockerAppsPruneImages is POST /api/apps/images/prune.
func rtDockerAppsPruneImages(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtDockerAppsAdmin(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	result, err := agent.Post(ctx, "/apps/images/prune", nil)
	if err != nil {
		return agentError("Prune images", err)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "app.prune_images", new("docker"), nil, nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtDockerAppsRemoveImage is DELETE /api/apps/images/{id}.
func rtDockerAppsRemoveImage(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, err := rtDockerAppsAdmin(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	id := r.PathValue("id")
	result, err := agent.Delete(ctx, "/apps/images/"+id)
	if err != nil {
		return agentError("Remove image", err)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "app.remove_image", new("docker"), new(id), nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtDockerAppsSnapshotContainer is POST /api/apps/{container_id}/snapshot.
func rtDockerAppsSnapshotContainer(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, _, agent, body, err := rtDockerAppsWithBody(st, r, true)
	if err != nil {
		return err
	}
	ctx := r.Context()
	cid := r.PathValue("container_id")
	result, err := agent.Post(ctx, "/apps/"+cid+"/snapshot", body)
	if err != nil {
		return agentError("Container snapshot", err)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "app.snapshot", new("app"), new(cid), nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, result)
	return nil
}

// ── Compose ─────────────────────────────────────────────────────────────

// rtDockerAppsComposeYAML reads body["yaml"] with the 64KB cap.
func rtDockerAppsComposeYAML(body any) (string, error) {
	yaml, ok := jsonStr(jsonGet(body, "yaml"))
	if !ok {
		return "", apiErr(http.StatusBadRequest, "Missing 'yaml' field")
	}
	if len(yaml) > 65536 {
		return "", apiErr(http.StatusBadRequest, "YAML too large (max 64KB)")
	}
	return yaml, nil
}

// rtDockerAppsComposeValidate is POST /api/apps/compose/validate.
func rtDockerAppsComposeValidate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, body, err := rtDockerAppsWithBody(st, r, false)
	if err != nil {
		return err
	}
	yaml, err := rtDockerAppsComposeYAML(body)
	if err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), "/apps/compose/validate", map[string]any{"yaml": yaml})
	return rtDockerAppsPassthrough(w, res, err, "Compose validate")
}

// rtDockerAppsComposeParse is POST /api/apps/compose/parse.
func rtDockerAppsComposeParse(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, body, err := rtDockerAppsWithBody(st, r, false)
	if err != nil {
		return err
	}
	yaml, err := rtDockerAppsComposeYAML(body)
	if err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), "/apps/compose/parse", map[string]any{"yaml": yaml})
	return rtDockerAppsPassthrough(w, res, err, "Compose parse")
}

// rtDockerAppsComposeDeploy is POST /api/apps/compose/deploy.
func rtDockerAppsComposeDeploy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, body, err := rtDockerAppsWithBody(st, r, false)
	if err != nil {
		return err
	}
	yaml, err := rtDockerAppsComposeYAML(body)
	if err != nil {
		return err
	}
	// Container escape vectors.
	if msg := validateComposeYAML(yaml); msg != "" {
		return apiErr(http.StatusBadRequest, msg)
	}
	// A compose file is a list of images to run, so the deploy gate applies to
	// every one — refused before the agent is asked to do anything.
	ctx := r.Context()
	images := composeImages(yaml)
	if err := rtDockerAppsEnforceAllowedImages(ctx, st.DB, claims.Sub, images); err != nil {
		return err
	}
	for _, image := range images {
		if err := rtImageScansPreflightGateImage(ctx, st.DB, serverID, agent, image); err != nil {
			return err
		}
	}
	result, err := agent.Post(ctx, "/apps/compose/deploy", map[string]any{"yaml": yaml})
	if err != nil {
		return agentError("Docker deploy", err)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "app.compose_deploy", new("app"), nil, new("compose"), nil, claims.KeyID)
	writeJSON(w, http.StatusCreated, result)
	return nil
}

// rtDockerAppsRemoveApp is DELETE /api/apps/{container_id}.
func rtDockerAppsRemoveApp(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()

	// Resolved BEFORE the removal: afterwards there is nothing to inspect, and
	// a removed container is never listed again, so the engine can never
	// clear its expectation — this is the one door that can.
	removedName := rtDockerAppsResolveContainerName(ctx, agent, cid)

	result, err := agent.Delete(ctx, "/apps/"+cid)
	if err != nil {
		return agentError("Container removal", err)
	}
	// Only after the removal succeeded — clearing first and having the agent
	// refuse would un-suppress a still deliberately stopped container.
	if removedName != nil {
		ExpectedStopsClear(ctx, st.DB, serverID, *removedName)
	}

	if domainRemoved, ok := jsonStr(jsonGet(result, "domain_removed")); ok {
		// The SSL-renewal ownership row must not outlive the app, or a future
		// app reusing the domain would inherit a stranger's renewal history.
		_, _ = execSQL(ctx, st.DB,
			"DELETE FROM docker_app_domains WHERE server_id = $1 AND lower(domain) = lower($2)",
			serverID, domainRemoved)
		// Auto-cleanup of the DNS record, matched against the address of the
		// host the app was removed FROM: the panel's address never matched a
		// member's record, leaving a dangling A record — a takeover surface.
		go rtDockerAppsDNSCleanup(st.DB, claims.Sub, serverID, domainRemoved)
	}

	slog.Info("App removed: " + cid)
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "app.remove", new("app"), new(cid), nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "app.remove", new(claims.Email), ip, new("app"), new(cid), nil, nil, "warning", claims.KeyID)
	ExtensionsFireEvent(st.DB, "app.removed", map[string]any{"container_id": cid})

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

func rtDockerAppsDNSCleanup(db *pgxpool.Pool, userID, serverID uuid.UUID, domain string) {
	ctx := context.Background()
	parent := rtDockerAppsParentDomain(domain)
	type zoneRow struct {
		Provider   string  `db:"provider"`
		CfZoneID   *string `db:"cf_zone_id"`
		CfAPIToken *string `db:"cf_api_token"`
		CfAPIEmail *string `db:"cf_api_email"`
	}
	zone, err := queryOpt[zoneRow](ctx, db,
		"SELECT provider, cf_zone_id, cf_api_token, cf_api_email FROM dns_zones WHERE domain = $1 AND user_id = $2",
		parent, userID)
	if err != nil {
		slog.Warn(fmt.Sprintf("DB error fetching DNS zone for docker app cleanup: %v", err))
		return
	}
	if zone == nil {
		return
	}
	serverIP := publicIPForServer(ctx, db, &serverID)
	if serverIP == nil {
		slog.Warn(fmt.Sprintf("Auto-DNS cleanup: could not resolve the public address of the server %s was removed from — leaving the record in place rather than deleting one that may belong to another host", domain))
		return
	}
	switch zone.Provider {
	case "cloudflare":
		if zone.CfZoneID == nil || zone.CfAPIToken == nil {
			return
		}
		zid := *zone.CfZoneID
		headers := cfHeaders(*zone.CfAPIToken, zone.CfAPIEmail)
		resp, err := rtDockerAppsDoJSON(ctx, http.MethodGet,
			"https://api.cloudflare.com/client/v4/zones/"+zid+"/dns_records?type=A&name="+domain, headers, nil)
		if err != nil {
			return
		}
		var data any
		dec := json.NewDecoder(resp.Body)
		dec.UseNumber()
		derr := dec.Decode(&data)
		resp.Body.Close()
		if derr != nil {
			return
		}
		records, _ := jsonArr(jsonGet(data, "result"))
		for _, rec := range records {
			rid, ok1 := jsonStr(jsonGet(rec, "id"))
			content, ok2 := jsonStr(jsonGet(rec, "content"))
			if ok1 && ok2 && content == *serverIP {
				if resp, err := rtDockerAppsDoJSON(ctx, http.MethodDelete,
					"https://api.cloudflare.com/client/v4/zones/"+zid+"/dns_records/"+rid, headers, nil); err == nil {
					resp.Body.Close()
				}
				slog.Info("Auto-DNS cleanup: deleted A record for app domain " + domain)
			}
		}
	case "powerdns":
		url, key, ok := rtDockerAppsPowerDNSSettings(ctx, db)
		if !ok {
			return
		}
		zfqdn := parent
		if !strings.HasSuffix(zfqdn, ".") {
			zfqdn += "."
		}
		if resp, err := rtDockerAppsDoJSON(ctx, http.MethodPatch, url+"/api/v1/servers/localhost/zones/"+zfqdn,
			http.Header{"X-Api-Key": {key}},
			map[string]any{"rrsets": []any{map[string]any{"name": domain + ".", "type": "A", "ttl": 300, "changetype": "DELETE", "records": []any{}}}}); err == nil {
			resp.Body.Close()
		}
		slog.Info("Auto-DNS cleanup (PowerDNS): deleted A record for app domain " + domain)
	}
}

// rtDockerAppsCheckUpdates is GET /api/apps/updates.
func rtDockerAppsCheckUpdates(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, err := rtDockerAppsAdmin(st, r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), "/apps/update-check")
	return rtDockerAppsPassthrough(w, res, err, "Update check")
}

// rtDockerAppsGpuInfo is GET /api/apps/gpu-info.
func rtDockerAppsGpuInfo(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, _, agent, err := rtDockerAppsAdmin(st, r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), "/apps/gpu-info")
	return rtDockerAppsPassthrough(w, res, err, "GPU info")
}

// ─── Container isolation policies (admin) ───────────────────────────────

// rtDockerAppsAppOwner: a container carries its owner — deploy stamps the
// admin's id onto the dockpanel.user.id label and /apps reads it back as
// user_id. A container with no (or a malformed) label has no owner and is
// excluded from every user's count, not folded into anyone's.
func rtDockerAppsAppOwner(app any) *uuid.UUID {
	s, ok := jsonStr(jsonGet(app, "user_id"))
	if !ok {
		return nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &id
}

func rtDockerAppsCountOwnedBy(apps any, userID uuid.UUID) int {
	arr, _ := jsonArr(apps)
	n := 0
	for _, a := range arr {
		if o := rtDockerAppsAppOwner(a); o != nil && *o == userID {
			n++
		}
	}
	return n
}

// rtDockerAppsFleetUsageByUser is one fleet walk producing every user's
// container count at once, so a page of N policies does not walk the fleet N
// times. Best effort per host: an unreachable member undercounts (visible via
// `unreachable`) rather than blocking or lying about the total. Returns
// (by_user, servers_counted, servers_unreachable, unowned).
func rtDockerAppsFleetUsageByUser(ctx context.Context, st *AppState) (map[uuid.UUID]int, int, int, int) {
	byUser := map[uuid.UUID]int{}
	unowned, unreachable := 0, 0
	fleet := st.Agents.OnlineFleet(ctx)
	for _, m := range fleet {
		apps, err := m.Agent.Get(ctx, "/apps")
		if err != nil {
			unreachable++
			slog.Warn(fmt.Sprintf("Container quota: %s did not answer (%v) — the usage figures are a floor", m.Name, err))
			continue
		}
		arr, _ := jsonArr(apps)
		for _, a := range arr {
			if o := rtDockerAppsAppOwner(a); o != nil {
				byUser[*o]++
			} else {
				unowned++
			}
		}
	}
	return byUser, len(fleet) - unreachable, unreachable, unowned
}

type rtDockerAppsPolicyRequest struct {
	UserID        *uuid.UUID `json:"user_id"`
	MaxContainers *int32     `json:"max_containers"`
	MaxMemoryMB   *int64     `json:"max_memory_mb"`
	MaxCPUPercent *int32     `json:"max_cpu_percent"`
	// network_isolation removed (s238): written + displayed but read by
	// nothing at deploy — a false security control. A stale frontend sending
	// it is ignored.
	AllowedImages *string `json:"allowed_images"`
}

// rtDockerAppsListPolicies is GET /api/container-policies.
func rtDockerAppsListPolicies(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()
	type policyRow struct {
		ID            uuid.UUID `db:"id"`
		UserID        uuid.UUID `db:"user_id"`
		MaxContainers int32     `db:"max_containers"`
		MaxMemoryMB   int64     `db:"max_memory_mb"`
		MaxCPUPercent int32     `db:"max_cpu_percent"`
		AllowedImages *string   `db:"allowed_images"`
		CreatedAt     time.Time `db:"created_at"`
		UpdatedAt     time.Time `db:"updated_at"`
	}
	policies, err := queryAll[policyRow](ctx, st.DB,
		"SELECT cp.id, cp.user_id, cp.max_containers, cp.max_memory_mb, cp.max_cpu_percent, "+
			"cp.allowed_images, cp.created_at, cp.updated_at "+
			"FROM container_policies cp ORDER BY cp.created_at DESC")
	if err != nil {
		return internalError("list container policies", err)
	}

	// One fleet walk for every row on this page.
	byUser, counted, unreachable, unowned := rtDockerAppsFleetUsageByUser(ctx, st)

	items := make([]any, 0, len(policies))
	for _, p := range policies {
		email, _ := queryScalarOpt[string](ctx, st.DB, "SELECT email FROM users WHERE id = $1", p.UserID)
		items = append(items, map[string]any{
			"id":              p.ID,
			"user_id":         p.UserID,
			"user_email":      email,
			"max_containers":  p.MaxContainers,
			"max_memory_mb":   p.MaxMemoryMB,
			"max_cpu_percent": p.MaxCPUPercent,
			"allowed_images":  p.AllowedImages,
			"created_at":      p.CreatedAt,
			"updated_at":      p.UpdatedAt,
			"used":            byUser[p.UserID],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policies":            items,
		"servers_counted":     counted,
		"servers_unreachable": unreachable,
		"unowned_containers":  unowned,
	})
	return nil
}

// rtDockerAppsCreatePolicy is POST /api/container-policies.
func rtDockerAppsCreatePolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtDockerAppsPolicyRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	if body.UserID == nil {
		return apiErr(http.StatusBadRequest, "user_id is required")
	}
	userID := *body.UserID
	maxContainers := min(max(rtDockerAppsOr(body.MaxContainers, 10), 1), 1000)
	maxMemory := min(max(rtDockerAppsOr(body.MaxMemoryMB, 4096), 128), 1_048_576)
	maxCPU := min(max(rtDockerAppsOr(body.MaxCPUPercent, 400), 10), 10000)

	// allowed_images: comma-separated, max 4KB.
	if body.AllowedImages != nil && len(*body.AllowedImages) > 4096 {
		return apiErr(http.StatusBadRequest, "allowed_images too long")
	}
	ctx := r.Context()
	exists, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM users WHERE id = $1", userID)
	if err != nil {
		return internalError("verify user", err)
	}
	if exists == nil {
		return apiErr(http.StatusNotFound, "User not found")
	}
	id, err := queryScalar[uuid.UUID](ctx, st.DB,
		"INSERT INTO container_policies (user_id, max_containers, max_memory_mb, max_cpu_percent, allowed_images) "+
			"VALUES ($1, $2, $3, $4, $5) "+
			"ON CONFLICT (user_id) DO UPDATE SET "+
			"max_containers = EXCLUDED.max_containers, max_memory_mb = EXCLUDED.max_memory_mb, "+
			"max_cpu_percent = EXCLUDED.max_cpu_percent, "+
			"allowed_images = EXCLUDED.allowed_images, updated_at = NOW() "+
			"RETURNING id",
		userID, maxContainers, maxMemory, maxCPU, body.AllowedImages)
	if err != nil {
		return internalError("create container policy", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "container_policy.created",
		new("container_policy"), new(userID.String()), nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "container_policy.created", new(claims.Email), ip,
		new("container_policy"), new(userID.String()), nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "id": id})
	return nil
}

func rtDockerAppsOr[T any](p *T, def T) T {
	if p != nil {
		return *p
	}
	return def
}

// rtDockerAppsGetPolicy is GET /api/container-policies/{user_id}. Users can
// see their own policy; admins any.
func rtDockerAppsGetPolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	userID, err := pathUUID(r, "user_id")
	if err != nil {
		return err
	}
	if claims.Sub != userID {
		if err := requireAdmin(claims.Role); err != nil {
			return err
		}
	}
	type row struct {
		ID            uuid.UUID `db:"id"`
		MaxContainers int32     `db:"max_containers"`
		MaxMemoryMB   int64     `db:"max_memory_mb"`
		MaxCPUPercent int32     `db:"max_cpu_percent"`
		AllowedImages *string   `db:"allowed_images"`
		UpdatedAt     time.Time `db:"updated_at"`
	}
	p, err := queryOpt[row](r.Context(), st.DB,
		"SELECT id, max_containers, max_memory_mb, max_cpu_percent, allowed_images, updated_at "+
			"FROM container_policies WHERE user_id = $1", userID)
	if err != nil {
		return internalError("get container policy", err)
	}
	if p == nil {
		writeJSON(w, http.StatusOK, map[string]any{"policy": nil})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":              p.ID,
		"user_id":         userID,
		"max_containers":  p.MaxContainers,
		"max_memory_mb":   p.MaxMemoryMB,
		"max_cpu_percent": p.MaxCPUPercent,
		"allowed_images":  p.AllowedImages,
		"updated_at":      p.UpdatedAt,
	})
	return nil
}

// rtDockerAppsUpdatePolicy is PUT /api/container-policies/{user_id}.
func rtDockerAppsUpdatePolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	userID, err := pathUUID(r, "user_id")
	if err != nil {
		return err
	}
	var body rtDockerAppsPolicyRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	clamp32 := func(p *int32, lo, hi int32) *int32 {
		if p == nil {
			return nil
		}
		return new(min(max(*p, lo), hi))
	}
	var mem *int64
	if body.MaxMemoryMB != nil {
		mem = new(min(max(*body.MaxMemoryMB, 128), 1_048_576))
	}
	ctx := r.Context()
	n, err := execSQL(ctx, st.DB,
		"UPDATE container_policies SET "+
			"max_containers = COALESCE($1, max_containers), "+
			"max_memory_mb = COALESCE($2, max_memory_mb), "+
			"max_cpu_percent = COALESCE($3, max_cpu_percent), "+
			"allowed_images = CASE WHEN $4 = '' THEN NULL ELSE COALESCE($4, allowed_images) END, "+
			"updated_at = NOW() "+
			"WHERE user_id = $5",
		clamp32(body.MaxContainers, 1, 1000), mem, clamp32(body.MaxCPUPercent, 10, 10000), body.AllowedImages, userID)
	if err != nil {
		return internalError("update container policy", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Policy not found for this user")
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "container_policy.updated",
		new("container_policy"), new(userID.String()), nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "container_policy.updated", new(claims.Email), ip,
		new("container_policy"), new(userID.String()), nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtDockerAppsDeletePolicy is DELETE /api/container-policies/{user_id}
// (reverts to no limits).
func rtDockerAppsDeletePolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	userID, err := pathUUID(r, "user_id")
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM container_policies WHERE user_id = $1", userID)
	if err != nil {
		return internalError("delete container policy", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Policy not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtDockerAppsPolicyUsage is GET /api/container-policies/{user_id}/usage.
//
// Counted across the FLEET (the quota is per USER; per-box counting let one
// account run max_containers on every host) AND scoped to the requested user
// (it once summed the whole fleet whoever was asked about). Best-effort per
// host — a display figure — with servers_unreachable saying it is a floor.
func rtDockerAppsPolicyUsage(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	userID, err := pathUUID(r, "user_id")
	if err != nil {
		return err
	}
	// The extractor stays for the ownership check it performs on the way in.
	if _, _, err := st.serverScope(r); err != nil {
		return err
	}
	if claims.Sub != userID {
		if err := requireAdmin(claims.Role); err != nil {
			return err
		}
	}
	ctx := r.Context()
	policy, err := queryOpt[Tup3[int32, int64, int32]](ctx, st.DB,
		"SELECT max_containers, max_memory_mb, max_cpu_percent FROM container_policies WHERE user_id = $1", userID)
	if err != nil {
		return internalError("policy usage", err)
	}
	byUser, counted, unreachable, unowned := rtDockerAppsFleetUsageByUser(ctx, st)
	used := byUser[userID]

	if policy == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"containers":          map[string]any{"used": used, "max": nil},
			"has_policy":          false,
			"servers_counted":     counted,
			"servers_unreachable": unreachable,
			"unowned_containers":  unowned,
		})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"containers":          map[string]any{"used": used, "max": policy.A},
		"memory_mb":           map[string]any{"max": policy.B},
		"cpu_percent":         map[string]any{"max": policy.C},
		"has_policy":          true,
		"servers_counted":     counted,
		"servers_unreachable": unreachable,
		"unowned_containers":  unowned,
	})
	return nil
}

// ─── Container auto-sleep / scale to zero ───────────────────────────────

// rtDockerAppsRekeySleepConfig: update/change-image/edit-env recreate the
// container, minting a NEW id under the same name, while
// container_sleep_config is keyed on container_id alone — without this the
// row becomes unreachable and an operator who enabled auto-sleep silently
// loses it on an ordinary update. Best-effort: the recreate already
// succeeded, so a failure logs loudly rather than failing the request.
func rtDockerAppsRekeySleepConfig(ctx context.Context, db *pgxpool.Pool, oldID, newID string) {
	if oldID == newID || newID == "" {
		return
	}
	if _, err := execSQL(ctx, db, "UPDATE container_sleep_config SET container_id = $1 WHERE container_id = $2", newID, oldID); err != nil {
		slog.Error(fmt.Sprintf("Failed to re-key sleep config after container recreate (%s -> %s): %v", oldID, newID, err))
	}
}

type rtDockerAppsSleepConfigRequest struct {
	AutoSleepEnabled  *bool  `json:"auto_sleep_enabled"`
	SleepAfterMinutes *int32 `json:"sleep_after_minutes"`
}

// rtDockerAppsGetSleepConfig is GET /api/apps/{container_id}/sleep-config.
func rtDockerAppsGetSleepConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	cid := r.PathValue("container_id")
	if !isValidContainerID(cid) {
		return apiErr(http.StatusBadRequest, "Invalid container ID")
	}
	type row struct {
		AutoSleepEnabled  bool       `db:"auto_sleep_enabled"`
		SleepAfterMinutes int32      `db:"sleep_after_minutes"`
		IsSleeping        bool       `db:"is_sleeping"`
		LastSleptAt       *time.Time `db:"last_slept_at"`
		LastWokenAt       *time.Time `db:"last_woken_at"`
		TotalSleeps       int32      `db:"total_sleeps"`
	}
	c, err := queryOpt[row](r.Context(), st.DB,
		"SELECT auto_sleep_enabled, sleep_after_minutes, is_sleeping, last_slept_at, last_woken_at, total_sleeps "+
			"FROM container_sleep_config WHERE container_id = $1", cid)
	if err != nil {
		return internalError("get sleep config", err)
	}
	if c == nil {
		writeJSON(w, http.StatusOK, map[string]any{"auto_sleep_enabled": false, "sleep_after_minutes": 30, "is_sleeping": false})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"auto_sleep_enabled":  c.AutoSleepEnabled,
		"sleep_after_minutes": c.SleepAfterMinutes,
		"is_sleeping":         c.IsSleeping,
		"last_slept_at":       c.LastSleptAt,
		"last_woken_at":       c.LastWokenAt,
		"total_sleeps":        c.TotalSleeps,
	})
	return nil
}

// rtDockerAppsUpdateSleepConfig is PUT /api/apps/{container_id}/sleep-config.
func rtDockerAppsUpdateSleepConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, err := rtDockerAppsAdmin2(st, r)
	if err != nil {
		return err
	}
	var body rtDockerAppsSleepConfigRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	cid := r.PathValue("container_id")
	if !isValidContainerID(cid) {
		return apiErr(http.StatusBadRequest, "Invalid container ID")
	}
	ctx := r.Context()
	minutes := min(max(rtDockerAppsOr(body.SleepAfterMinutes, 30), 5), 1440)
	enabled := rtDockerAppsOr(body.AutoSleepEnabled, false)

	// Resolve container name and domain from the agent.
	containerName := cid
	var domain *string
	if apps, err := agent.Get(ctx, "/apps"); err == nil {
		arr, _ := jsonArr(apps)
		for _, app := range arr {
			if id, _ := jsonStr(jsonGet(app, "container_id")); id == cid {
				if n, ok := jsonStr(jsonGet(app, "name")); ok {
					containerName = n
				}
				if d, ok := jsonStr(jsonGet(app, "domain")); ok {
					domain = &d
				}
				break
			}
		}
	}

	// server_id is bound because the sleeper reads it to decide which host to
	// ask and stop on. Omitting it would not look broken — the migration
	// backfilled every existing row — until the first container configured
	// after the upgrade carried NULL and was skipped by a sleeper that
	// (correctly) refuses to guess a host. That is how mail_domains.server_id
	// came to be NULL on every panel-created row for five months.
	if _, err := execSQL(ctx, st.DB,
		"INSERT INTO container_sleep_config (container_id, container_name, domain, auto_sleep_enabled, sleep_after_minutes, last_activity_at, server_id) "+
			"VALUES ($1, $2, $3, $4, $5, NOW(), $6) "+
			"ON CONFLICT (container_id) DO UPDATE SET "+
			"auto_sleep_enabled = $4, sleep_after_minutes = $5, container_name = $2, domain = $3, server_id = $6, updated_at = NOW()",
		cid, containerName, domain, enabled, minutes, serverID); err != nil {
		return internalError("update sleep config", err)
	}

	action := "container.auto_sleep_disabled"
	if enabled {
		action = "container.auto_sleep_enabled"
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, action, new("container"), new(containerName), nil, nil, claims.KeyID)

	// Report whether the loop that honours this setting is running at all: the
	// sleeper is a step inside the auto-healer, off by default and configured
	// elsewhere, so enabling auto-sleep on a fresh install answered `ok` and
	// did nothing, for ever, silently.
	v, _ := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'auto_heal_enabled'")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "auto_heal_enabled": v != nil && *v == "true"})
	return nil
}

// rtDockerAppsWakeContainer is POST /api/apps/{container_id}/wake.
func rtDockerAppsWakeContainer(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	if _, err := agent.Post(ctx, "/apps/"+cid+"/start", nil); err != nil {
		return agentError("Wake container", err)
	}
	// The start already succeeded, so a DB hiccup must not fail the request —
	// but a swallowed error left is_sleeping desynced for ever (the sweeper
	// only reconciles rows it believes awake). Log it.
	if _, err := execSQL(ctx, st.DB,
		"UPDATE container_sleep_config SET is_sleeping = false, last_woken_at = NOW(), "+
			"last_activity_at = NOW(), updated_at = NOW() WHERE container_id = $1", cid); err != nil {
		slog.Warn(fmt.Sprintf("Failed to persist wake state for container %s: %v — is_sleeping may now disagree with reality", cid, err))
	}
	if name := rtDockerAppsResolveContainerName(ctx, agent, cid); name != nil {
		ExpectedStopsClear(ctx, st.DB, serverID, *name)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "container.wake", new("container"), new(cid), nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtDockerAppsSleepContainer is POST /api/apps/{container_id}/sleep.
func rtDockerAppsSleepContainer(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, serverID, agent, cid, err := rtDockerAppsContainer(st, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	if _, err := agent.Post(ctx, "/apps/"+cid+"/stop", nil); err != nil {
		return agentError("Sleep container", err)
	}
	// Same reasoning as wake: never fail the request, but log the desync.
	if _, err := execSQL(ctx, st.DB,
		"UPDATE container_sleep_config SET is_sleeping = true, last_slept_at = NOW(), "+
			"total_sleeps = total_sleeps + 1, updated_at = NOW() WHERE container_id = $1", cid); err != nil {
		slog.Warn(fmt.Sprintf("Failed to persist sleep state for container %s: %v — is_sleeping may now disagree with reality", cid, err))
	}
	if name := rtDockerAppsResolveContainerName(ctx, agent, cid); name != nil {
		ExpectedStopsRecord(ctx, st.DB, serverID, *name, ExpectedStopsReasonManualSleep, new(claims.Email))
		ExpectedStopsResolveOpenContainerDown(ctx, st.DB, serverID, *name)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "container.manual_sleep", new("container"), new(cid), nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtDockerAppsActivityPing is POST /api/apps/{container_id}/activity-ping —
// an admin-only manual bump of a container's auto-sleep timer. NOT an nginx
// keepalive (nginx cannot hold a JWT); admin-gated so a non-admin cannot
// defeat auto-sleep on an arbitrary container.
func rtDockerAppsActivityPing(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	cid := r.PathValue("container_id")
	ok := cid != "" && len(cid) <= 64
	for _, c := range cid {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			ok = false
		}
	}
	if !ok {
		return apiErr(http.StatusBadRequest, "Invalid container ID")
	}
	_, _ = execSQL(r.Context(), st.DB, "UPDATE container_sleep_config SET last_activity_at = NOW() WHERE container_id = $1", cid)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtDockerAppsSleepStatusList is GET /api/apps/sleep-status (admin overview).
func rtDockerAppsSleepStatusList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	type row struct {
		ContainerID       string     `db:"container_id" json:"container_id"`
		ContainerName     string     `db:"container_name" json:"container_name"`
		Domain            *string    `db:"domain" json:"domain"`
		AutoSleepEnabled  bool       `db:"auto_sleep_enabled" json:"auto_sleep_enabled"`
		SleepAfterMinutes int32      `db:"sleep_after_minutes" json:"sleep_after_minutes"`
		IsSleeping        bool       `db:"is_sleeping" json:"is_sleeping"`
		LastSleptAt       *time.Time `db:"last_slept_at" json:"last_slept_at"`
		LastWokenAt       *time.Time `db:"last_woken_at" json:"last_woken_at"`
		TotalSleeps       int32      `db:"total_sleeps" json:"total_sleeps"`
	}
	configs, err := queryAll[row](r.Context(), st.DB,
		"SELECT container_id, container_name, domain, auto_sleep_enabled, sleep_after_minutes, "+
			"is_sleeping, last_slept_at, last_woken_at, total_sleeps "+
			"FROM container_sleep_config ORDER BY container_name")
	if err != nil {
		return internalError("sleep status list", err)
	}
	// json! objects serialize with sorted keys; build maps to match.
	items := make([]any, 0, len(configs))
	for _, c := range configs {
		b, _ := json.Marshal(c)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		items = append(items, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"configs": items})
	return nil
}
