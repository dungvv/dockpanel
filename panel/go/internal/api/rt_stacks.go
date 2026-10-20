package api

// Port of panel/backend/src/routes/stacks.rs — Compose stacks.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtStacksRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/stacks", h(rtStacksList))
	r.Handle("POST /api/stacks", h(rtStacksCreate))
	r.Handle("GET /api/stacks/{id}", h(rtStacksGetOne))
	r.Handle("PUT /api/stacks/{id}", h(rtStacksUpdate))
	r.Handle("DELETE /api/stacks/{id}", h(rtStacksRemove))
	r.Handle("POST /api/stacks/{id}/start", h(rtStacksStart))
	r.Handle("POST /api/stacks/{id}/stop", h(rtStacksStop))
	r.Handle("POST /api/stacks/{id}/restart", h(rtStacksRestart))
	// The Certificates page's control for a stack's certificate. A stack has
	// no `sites` row, so the site-shaped renew route could never address one.
	r.Handle("POST /api/stacks/{id}/renew-ssl", h(rtStacksRenewSsl))
}

// rtStacksStackSelect is the row plus the alias of the certificate it
// references, if any. A LEFT JOIN because most stacks reference none, and the
// alias is what the API and the deploy body speak — the id never leaves the
// panel.
const rtStacksStackSelect = "SELECT s.id, s.user_id, s.server_id, s.name, s.yaml, s.service_count, " +
	"s.domain, s.ssl_email, s.tls_mode, s.tls_certificate_id, " +
	"c.alias AS tls_certificate, s.created_at, s.updated_at " +
	"FROM docker_stacks s " +
	"LEFT JOIN tls_certificates c ON c.id = s.tls_certificate_id"

// rtStacksTlsModes is the one vocabulary for how a stack's domain is served.
// Pinned cross-tree: the migration's CHECK, the agent's request parser and the
// SPA's select all carry these three words.
var rtStacksTlsModes = [3]string{"none", "acme", "provided"}

// rtStacksEffectiveTlsMode is the mode a stack is in, from what the row says.
//
// The stored value wins. A NULL is a row written by an older binary, and for
// such a row the address is the mode, exactly as the agent always inferred it:
// a non-blank ssl_email means Let's Encrypt, anything else plain HTTP.
func rtStacksEffectiveTlsMode(tlsMode, sslEmail *string) string {
	if tlsMode != nil {
		for _, m := range rtStacksTlsModes {
			if m == *tlsMode {
				return m
			}
		}
	}
	if sslEmail != nil && strings.TrimSpace(*sslEmail) != "" {
		return "acme"
	}
	return "none"
}

// rtStacksRequestedTlsMode is a requested mode, normalised, or a 400 for a
// word outside the vocabulary. nil in (or blank) means "the client did not
// say" — the caller decides what that means. Reused by docker_apps' deploy
// for template apps.
func rtStacksRequestedTlsMode(raw *string) (*string, error) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil, nil
	}
	lowered := rtStacksASCIILower(strings.TrimSpace(*raw))
	for _, m := range rtStacksTlsModes {
		if m == lowered {
			return &m, nil
		}
	}
	return nil, apiErr(http.StatusBadRequest, "tls_mode must be one of none, acme or provided")
}

// rtStacksTlsPlan is everything the panel decides about a stack's TLS before
// touching the agent.
type rtStacksTlsPlan struct {
	Mode string
	// The address that will be STORED, in every mode. What the agent is SENT
	// is DeployEmail, which withholds it outside acme mode.
	SslEmail *string
	// The alias, provided mode only.
	Alias *string
	// The registry row, provided mode only — resolved AND checked for coverage.
	CertificateID *uuid.UUID
}

// DeployEmail is the address the AGENT is handed. Only an ACME order needs
// one, and an agent older than the stored mode still infers the mode FROM the
// address — so a none/provided stack is sent none, or that agent would order
// the certificate the operator switched off.
func (p *rtStacksTlsPlan) DeployEmail() *string {
	if p.Mode == "acme" {
		return p.SslEmail
	}
	return nil
}

// rtStacksASCIILower is str::to_ascii_lowercase (non-ASCII left alone, so a
// Kelvin sign never folds into a valid alias).
func rtStacksASCIILower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func rtStacksTrimmed(s *string) *string {
	if s == nil {
		return nil
	}
	if t := strings.TrimSpace(*s); t != "" {
		return &t
	}
	return nil
}

// rtStacksPlanTls turns a mode, an address and an alias into a plan, refusing
// every combination that cannot be served — before any row is written or any
// container touched.
//
// Provided mode is the door that reaches the agent: the alias must name a row
// on this server (400), the agent must be new enough to honour the mode at all
// (412, fail-closed), and the certificate must actually cover the domain — the
// agent's answer passes through unchanged (#104 binding point 3: SAN
// validation at claim time). Reused by docker_apps' template deploy.
func rtStacksPlanTls(ctx context.Context, db *pgxpool.Pool, agent AgentHandle, mode string, domain, sslEmail, alias *string, userID, serverID uuid.UUID) (*rtStacksTlsPlan, error) {
	email := rtStacksTrimmed(sslEmail)
	if mode == "none" {
		return &rtStacksTlsPlan{Mode: mode, SslEmail: email}, nil
	}
	d := rtStacksTrimmed(domain)
	if d == nil {
		return nil, apiErr(http.StatusBadRequest, "a TLS mode needs a domain")
	}
	if mode == "acme" {
		if email == nil {
			return nil, apiErr(http.StatusBadRequest, "Let's Encrypt mode needs an ssl_email for the ACME account")
		}
		return &rtStacksTlsPlan{Mode: mode, SslEmail: email}, nil
	}

	// provided
	a := rtStacksTrimmed(alias)
	if a == nil {
		return nil, apiErr(http.StatusBadRequest, "provided mode needs the alias of a registered certificate")
	}
	lowered := rtStacksASCIILower(*a)
	if !rtTlsCertificatesIsValidCertAlias(lowered) {
		return nil, apiErr(http.StatusBadRequest,
			"Alias must be 1-64 lowercase letters, digits or hyphens, starting and ending with a letter or digit")
	}
	certID, err := rtTlsCertificatesCertificateIdForAlias(ctx, db, lowered, userID, serverID)
	if err != nil {
		return nil, err
	}
	if err := rtTlsCertificatesRequireAgentAtLeast(ctx, agent, rtTlsCertificatesProvidedTlsMinAgent, "Serving a registered certificate"); err != nil {
		return nil, err
	}
	if _, err := agent.Post(ctx, "/ssl/registry/"+lowered+"/covers", map[string]any{"domain": *d}); err != nil {
		return nil, agentError("Certificate coverage check", err)
	}
	return &rtStacksTlsPlan{Mode: mode, SslEmail: email, Alias: &lowered, CertificateID: &certID}, nil
}

// rtStacksProvidedTlsRefusal is why a provided-mode deploy did not end in an
// HTTPS vhost, if it did not.
//
// The agent never fails a deploy over its vhost: a refused TLS leg is a
// warning inside a 200. For Let's Encrypt that is right — the certificate can
// be ordered later. For a registered certificate it is the outage this
// feature exists to prevent, so the caller turns this into a 502.
func rtStacksProvidedTlsRefusal(deployResult any) *string {
	if b, ok := jsonBool(jsonGet(deployResult, "ssl")); ok && b {
		return nil
	}
	// The agent puts the reason in proxy_warning and sets tls_refused beside it
	// as a boolean FLAG, never the sentence.
	if s, ok := jsonStr(jsonGet(deployResult, "proxy_warning")); ok {
		return &s
	}
	if s, ok := jsonStr(jsonGet(deployResult, "tls_refused")); ok {
		return &s
	}
	return new("the agent did not report an HTTPS vhost for the domain")
}

// rtStacksStack is a docker_stacks row.
type rtStacksStack struct {
	ID     uuid.UUID `db:"id" json:"id"`
	UserID uuid.UUID `db:"user_id" json:"user_id"`
	// The host this stack's containers actually run on. Every agent call about
	// a stack has to be aimed by it — a caller's ServerScope says which machine
	// the operator is looking at, never which machine the stack is on.
	// NOT NULL in the schema (backfilled by the multi-server migration).
	ServerID     uuid.UUID `db:"server_id" json:"server_id"`
	Name         string    `db:"name" json:"name"`
	Yaml         string    `db:"yaml" json:"yaml"`
	ServiceCount int32     `db:"service_count" json:"service_count"`
	Domain       *string   `db:"domain" json:"domain"`
	SslEmail     *string   `db:"ssl_email" json:"ssl_email"`
	// As stored; NULL on a row an older binary wrote. Read through
	// rtStacksEffectiveTlsMode, never directly.
	TlsMode          *string    `db:"tls_mode" json:"tls_mode"`
	TlsCertificateID *uuid.UUID `db:"tls_certificate_id" json:"tls_certificate_id"`
	// The certificate's alias, joined in by rtStacksStackSelect. Defaulted so
	// the create path's INSERT … RETURNING (no join) still maps.
	TlsCertificate *string   `db:"tls_certificate,default" json:"tls_certificate"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time `db:"updated_at" json:"updated_at"`
}

type rtStacksCreateStackRequest struct {
	Name string `json:"name"`
	Yaml string `json:"yaml"`
	// Optional domain to front the stack with.
	Domain *string `json:"domain"`
	// ACME address, acme mode only.
	SslEmail *string `json:"ssl_email"`
	// "none" | "acme" | "provided". Absent = derived from the address.
	TlsMode *string `json:"tls_mode"`
	// Registry alias, provided mode only.
	TlsCertificate *string `json:"tls_certificate"`
}

type rtStacksUpdateStackRequest struct {
	Yaml string `json:"yaml"`
	// Absent means KEEP the stored domain; an explicit null or blank vacates
	// it. Before the mode was stored, an omitted domain silently tore the
	// vhost down on an edit that was about something else. (Rust
	// Option<Option<String>> via explicit_option: nil = absent, "null" = null.)
	Domain json.RawMessage `json:"domain" serde:"default"`
	// ACME address. Absent means KEEP the stored one — it used to mean
	// "clear", and omitting it rewrote a certificated stack's vhost without
	// its :443 block, behind a year of HSTS.
	SslEmail *string `json:"ssl_email"`
	// Absent means keep the stored mode.
	TlsMode *string `json:"tls_mode"`
	// Absent means keep the stored alias.
	TlsCertificate *string `json:"tls_certificate"`
}

// rtStacksDeployedServiceStates: did anything in the stack actually come up?
// The agent reports per-service outcomes inside a 200, so a caller that only
// checks the HTTP status believes a stack deployed when none of it did.
func rtStacksDeployedServiceStates(deployResult any) (running, total int, errs []string) {
	services, _ := jsonArr(jsonGet(deployResult, "services"))
	total = len(services)
	errs = []string{}
	for _, s := range services {
		if st, _ := jsonStr(jsonGet(s, "status")); st == "running" {
			running++
		}
		name, ok := jsonStr(jsonGet(s, "name"))
		if !ok {
			name = "service"
		}
		if e, ok := jsonStr(jsonGet(s, "error")); ok {
			errs = append(errs, name+": "+e)
		}
	}
	return running, total, errs
}

// rtStacksClaimStackDomain normalises + claims a stack's domain, or clears it.
func rtStacksClaimStackDomain(ctx context.Context, st *AppState, r *http.Request, domain *string, holder DomainClaimHolder, role string) (*string, error) {
	raw := rtStacksTrimmed(domain)
	if raw == nil {
		return nil, nil
	}
	claimed, err := DomainClaimEnsureClaimable(ctx, st.DB, st.Agents, *raw, r, holder, role)
	if err != nil {
		return nil, err
	}
	return &claimed, nil
}

// rtStacksServicesFor filters an /apps listing to one stack's containers.
func rtStacksServicesFor(apps any, stackID uuid.UUID) (services []any, running int) {
	arr, _ := jsonArr(apps)
	services = []any{}
	id := stackID.String()
	for _, a := range arr {
		if s, ok := jsonStr(jsonGet(a, "stack_id")); ok && s == id {
			services = append(services, a)
			if st, _ := jsonStr(jsonGet(a, "status")); st == "running" {
				running++
			}
		}
	}
	return services, running
}

// rtStacksClearRemoved forgets the expected-stop row of every container an
// /apps/stack/action answer reports removed: the expectation is keyed on
// (server_id, container_name) and would otherwise outlive the container and
// silence the next one to claim the name.
func rtStacksClearRemoved(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, body any) {
	results, _ := jsonArr(jsonGet(body, "results"))
	for _, r := range results {
		if s, _ := jsonStr(jsonGet(r, "status")); s == "removed" {
			if name, ok := jsonStr(jsonGet(r, "name")); ok {
				ExpectedStopsClear(ctx, db, serverID, name)
			}
		}
	}
}

// AgentStackTimeoutSecs bounds one stack deploy or stack action. The agent
// pulls, creates, starts and confirms every service in a single call, ~1.5-3s
// each, so a plain Post's 60s cut a 37-service stack off halfway through —
// the update then rolled back to the previous definition, every time.
const AgentStackTimeoutSecs = 600

// rtStacksAgentPost is the agent call for whole-stack work (deploy, remove,
// start/stop/restart): long pool, AgentStackTimeoutSecs budget.
func rtStacksAgentPost(ctx context.Context, agent AgentHandle, path string, body any) (any, error) {
	return agent.PostLong(ctx, path, body, AgentStackTimeoutSecs)
}

func rtStacksOr(s *string, def string) string {
	if s != nil {
		return *s
	}
	return def
}

// rtStacksList is GET /api/stacks — the caller's stacks on the scoped server.
func rtStacksList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()
	stacks, err := queryAll[rtStacksStack](ctx, st.DB,
		rtStacksStackSelect+" WHERE s.user_id = $1 AND s.server_id = $2 ORDER BY s.created_at DESC",
		claims.Sub, serverID)
	if err != nil {
		return internalError("list stacks", err)
	}

	// Live container status from the agent.
	apps, err := agent.Get(ctx, "/apps")
	if err != nil {
		apps = []any{}
	}

	result := make([]any, 0, len(stacks))
	for _, s := range stacks {
		services, running := rtStacksServicesFor(apps, s.ID)
		total := len(services)
		status := "partial"
		switch {
		case total == 0:
			status = "removed"
		case running == total:
			status = "running"
		case running == 0:
			status = "stopped"
		}
		result = append(result, map[string]any{
			"id":              s.ID,
			"name":            s.Name,
			"service_count":   s.ServiceCount,
			"domain":          s.Domain,
			"ssl_email":       s.SslEmail,
			"tls_mode":        rtStacksEffectiveTlsMode(s.TlsMode, s.SslEmail),
			"tls_certificate": s.TlsCertificate,
			"running":         running,
			"total":           total,
			"status":          status,
			"services":        services,
			"created_at":      s.CreatedAt,
			"updated_at":      s.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtStacksGetOne is GET /api/stacks/{id}. Takes no ServerScope: unlike list,
// it reads one known row and must follow that row to its host.
func rtStacksGetOne(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()
	stack, err := queryOpt[rtStacksStack](ctx, st.DB, rtStacksStackSelect+" WHERE s.id = $1 AND s.user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("get_one stacks", err)
	}
	if stack == nil {
		return apiErr(http.StatusNotFound, "Stack not found")
	}

	// /apps is one machine's inventory and the stack_id label exists only on
	// the host that deployed it. Asked of any other host the endpoint answered
	// `running: 0, services: []` for a stack that was up — the shape of an
	// outage, arrived at without one.
	agent, err := agentForSiteServer(ctx, st, &stack.ServerID, rtStacksOr(stack.Domain, stack.Name))
	if err != nil {
		return err
	}
	apps, err := agent.Get(ctx, "/apps")
	if err != nil {
		apps = []any{}
	}
	services, running := rtStacksServicesFor(apps, stack.ID)

	writeJSON(w, http.StatusOK, map[string]any{
		"id":              stack.ID,
		"name":            stack.Name,
		"yaml":            stack.Yaml,
		"service_count":   stack.ServiceCount,
		"domain":          stack.Domain,
		"ssl_email":       stack.SslEmail,
		"tls_mode":        rtStacksEffectiveTlsMode(stack.TlsMode, stack.SslEmail),
		"tls_certificate": stack.TlsCertificate,
		"running":         running,
		"total":           len(services),
		"services":        services,
		"created_at":      stack.CreatedAt,
		"updated_at":      stack.UpdatedAt,
	})
	return nil
}

// rtStacksCreate is POST /api/stacks — create and deploy a new stack.
func rtStacksCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body rtStacksCreateStackRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()

	if strings.TrimSpace(body.Name) == "" || len(body.Name) > 100 {
		return apiErr(http.StatusBadRequest, "Invalid stack name")
	}
	if len(body.Yaml) > 65536 {
		return apiErr(http.StatusBadRequest, "YAML too large (max 64KB)")
	}
	// The container-escape validator once guarded only compose/deploy, so the
	// endpoint the UI actually posts to skipped it. The agent re-rejects these
	// itself, but a defence only one of two doors performs is one refactor
	// away from being no defence.
	if msg := validateComposeYAML(body.Yaml); msg != "" {
		return apiErr(http.StatusBadRequest, msg)
	}

	// …and the same is true of the deploy gate. Judged before the domain is
	// claimed and before any row is written, so a refusal leaves nothing.
	images := composeImages(body.Yaml)
	if err := rtDockerAppsEnforceAllowedImages(ctx, st.DB, claims.Sub, images); err != nil {
		return err
	}
	for _, image := range images {
		if err := rtImageScansPreflightGateImage(ctx, st.DB, serverID, agent, image); err != nil {
			return err
		}
	}

	// The mode is decided here, once, and stored: a client that predates the
	// field is read the way the agent always read it, from the address.
	req, err := rtStacksRequestedTlsMode(body.TlsMode)
	if err != nil {
		return err
	}
	mode := rtStacksEffectiveTlsMode(nil, body.SslEmail)
	if req != nil {
		mode = *req
	}

	domain, err := rtStacksClaimStackDomain(ctx, st, r, body.Domain, DomainClaimHolderNew, claims.Role)
	if err != nil {
		return err
	}

	// Everything TLS is settled — including the agent's answer to "does this
	// certificate cover this domain" — before a row or container exists.
	tls, err := rtStacksPlanTls(ctx, st.DB, agent, mode, domain, body.SslEmail, body.TlsCertificate, claims.Sub, serverID)
	if err != nil {
		return err
	}

	parsed, err := agent.Post(ctx, "/apps/compose/parse", map[string]any{"yaml": body.Yaml})
	if err != nil {
		return agentError("Compose parse", err)
	}
	arr, _ := jsonArr(parsed)
	serviceCount := int32(len(arr))

	// Create the DB record first to get the stack id.
	stack, err := queryOne[rtStacksStack](ctx, st.DB,
		"INSERT INTO docker_stacks (user_id, server_id, name, yaml, service_count, domain, "+
			"ssl_email, tls_mode, tls_certificate_id) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) "+
			"RETURNING id, user_id, server_id, name, yaml, service_count, domain, ssl_email, "+
			"tls_mode, tls_certificate_id, created_at, updated_at",
		claims.Sub, serverID, body.Name, body.Yaml, serviceCount, domain, tls.SslEmail, tls.Mode, tls.CertificateID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return apiErr(http.StatusConflict, "A stack with this name already exists")
		}
		return internalError("create stacks", err)
	}

	// Deploy with the stack_id label.
	deployResult, err := rtStacksAgentPost(ctx, agent, "/apps/compose/deploy", map[string]any{
		"yaml":            body.Yaml,
		"stack_id":        stack.ID.String(),
		"domain":          domain,
		"ssl_email":       tls.DeployEmail(),
		"tls_mode":        tls.Mode,
		"tls_certificate": tls.Alias,
	})
	if err != nil {
		// Roll back the DB record on deploy failure.
		go func() {
			_, _ = execSQL(context.Background(), st.DB, "DELETE FROM docker_stacks WHERE id = $1", stack.ID)
		}()
		return agentError("Stack deploy", err)
	}

	// A stack where nothing came up is not a stack. Keeping the row gave the
	// operator an entry with no containers (and another on every retry), and
	// the domain claim would have outlived the deploy.
	running, total, errs := rtStacksDeployedServiceStates(deployResult)
	if total > 0 && running == 0 {
		_, _ = execSQL(ctx, st.DB, "DELETE FROM docker_stacks WHERE id = $1", stack.ID)
		return apiErr(http.StatusBadGateway, "No service in the stack stayed running, so it was not saved. "+strings.Join(errs, " | "))
	}

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "stack.create",
		new("stack"), new(stack.Name), nil, nil, claims.KeyID)

	// The containers are up and the row is kept — but a registered certificate
	// that did not reach the vhost is the domain serving plain HTTP behind
	// HSTS. Say so, and leave the stack so the operator can fix and redeploy.
	if tls.Mode == "provided" {
		if reason := rtStacksProvidedTlsRefusal(deployResult); reason != nil {
			return apiErr(http.StatusBadGateway, fmt.Sprintf(
				"The stack %s is running, but its domain was not put behind the registered "+
					"certificate: %s. Fix the cause and redeploy the stack.", stack.Name, *reason))
		}
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":              stack.ID,
		"name":            stack.Name,
		"service_count":   serviceCount,
		"domain":          domain,
		"tls_mode":        tls.Mode,
		"tls_certificate": tls.Alias,
		"running":         running,
		"total":           total,
		"deploy_result":   deployResult,
	})
	return nil
}

// No ServerScope on the three verbs: rtStacksAction resolves the host from
// the row it authorises.

// rtStacksStart is POST /api/stacks/{id}/start.
func rtStacksStart(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtStacksActionHandler(st, w, r, "start")
}

// rtStacksStop is POST /api/stacks/{id}/stop.
func rtStacksStop(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtStacksActionHandler(st, w, r, "stop")
}

// rtStacksRestart is POST /api/stacks/{id}/restart.
func rtStacksRestart(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtStacksActionHandler(st, w, r, "restart")
}

func rtStacksActionHandler(st *AppState, w http.ResponseWriter, r *http.Request, action string) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	res, err := rtStacksAction(r.Context(), st, claims, id, action)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtStacksRemove is DELETE /api/stacks/{id} — remove all services and delete
// the stack.
func rtStacksRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()

	row, err := queryOpt[Tup4[uuid.UUID, string, *string, *uuid.UUID]](ctx, st.DB,
		"SELECT id, name, domain, server_id FROM docker_stacks WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("remove stacks", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Stack not found")
	}
	name, domain, serverID := row.B, row.C, row.D

	// This deletes the row whatever the agent says, so aiming it at the wrong
	// host would report success, drop the record, and leave the real host's
	// containers running with nothing naming them. Resolve from the row and
	// refuse if that host is unreachable.
	agent, err := agentForSiteServer(ctx, st, serverID, rtStacksOr(domain, name))
	if err != nil {
		return err
	}

	// A stack's own database (GH #64) MUST be torn down BEFORE the
	// /apps/stack/action remove below: that call removes the stack's Docker
	// network as its LAST step, and Docker refuses to remove a network with an
	// attached endpoint — the database container joins that network, so
	// removing it afterwards silently orphaned the network (live-caught). It
	// also carries dockpanel.db.* labels, so the stack action never removes it
	// itself; the databases row goes by ON DELETE CASCADE, which never touches
	// the live container. Best-effort, like the stack's own containers.
	//
	// Stream proxies die before the containers they front: the tcp_proxies
	// rows cascade with the databases, but the nginx files and firewall rules
	// live on the agent.
	proxies, _ := queryAll[Tup2[string, int32]](ctx, st.DB,
		"SELECT p.name, p.listen_port FROM tcp_proxies p "+
			"JOIN databases d ON d.id = p.database_id WHERE d.stack_id = $1", id)
	// Unlike the containers below, a failure here aborts: the rows cascade
	// away, so a surviving listener would be a public port nobody records.
	for _, p := range proxies {
		if _, err := agent.Delete(ctx, fmt.Sprintf("/nginx/streams/%s?listen_port=%d", p.A, p.B)); err != nil {
			return agentError("Database remote access removal", err)
		}
	}

	ownedDBs, _ := queryAll[*string](ctx, st.DB, "SELECT container_id FROM databases WHERE stack_id = $1", id)
	for _, cid := range ownedDBs {
		if cid != nil && *cid != "" {
			if _, err := agent.Delete(ctx, "/databases/"+*cid); err != nil {
				slog.Warn(fmt.Sprintf("Could not remove stack %s's database container %s: %v", id, *cid, err))
			}
		}
	}

	// Remove all containers, and the vhost/certs the stack was fronted by. The
	// agent proves ownership of each before deleting it.
	result, actionErr := rtStacksAgentPost(ctx, agent, "/apps/stack/action", map[string]any{
		"stack_id": id.String(),
		"action":   "remove",
		"domain":   domain,
	})

	// Forget the expectation for every container the agent reports gone — it
	// would outlive the stack and silence the next container to claim the name.
	if serverID != nil && actionErr == nil {
		rtStacksClearRemoved(ctx, st.DB, *serverID, result)
	}

	// Delete the DB record even if container removal had partial failures.
	if _, err := execSQL(ctx, st.DB, "DELETE FROM docker_stacks WHERE id = $1", id); err != nil {
		return internalError("remove stacks", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "stack.remove",
		new("stack"), new(name), nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "stack.remove", new(claims.Email), ip,
		new("stack"), new(name), nil, nil, "warning", claims.KeyID)

	var agentResult any // Option<Value>: null when the agent call failed
	if actionErr == nil {
		agentResult = result
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name, "agent_result": agentResult})
	return nil
}

// rtStacksUpdate is PUT /api/stacks/{id} — redeploy with a new definition.
//
// The stored YAML is the only copy of a stack's definition. It used to be
// overwritten after the redeploy unconditionally, so a redeploy where every
// service failed (still a 200) replaced the last-known-good file. The old
// definition is now held until the new one is known to run, and restored when
// it does not.
func rtStacksUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtStacksUpdateStackRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	var bodyDomain **string // nil = absent; *nil = explicit null
	if len(body.Domain) > 0 {
		var d *string
		if err := json.Unmarshal(body.Domain, &d); err != nil {
			return rejection(http.StatusUnprocessableEntity, "Failed to deserialize the JSON body into the target type: domain: "+err.Error())
		}
		bodyDomain = &d
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()

	if len(body.Yaml) > 65536 {
		return apiErr(http.StatusBadRequest, "YAML too large (max 64KB)")
	}
	if msg := validateComposeYAML(body.Yaml); msg != "" {
		return apiErr(http.StatusBadRequest, msg)
	}

	// Keep what we are about to replace — and read the host off the same row.
	// The TLS columns come along because an edit that says nothing about TLS
	// keeps them; the alias is read through the join because the request
	// speaks aliases.
	type prevRow struct {
		Yaml     string    `db:"yaml"`
		Domain   *string   `db:"domain"`
		SslEmail *string   `db:"ssl_email"`
		Name     string    `db:"name"`
		ServerID uuid.UUID `db:"server_id"`
		TlsMode  *string   `db:"tls_mode"`
		Alias    *string   `db:"alias"`
	}
	prev, err := queryOpt[prevRow](ctx, st.DB,
		"SELECT s.yaml, s.domain, s.ssl_email, s.name, s.server_id, s.tls_mode, c.alias "+
			"FROM docker_stacks s LEFT JOIN tls_certificates c ON c.id = s.tls_certificate_id "+
			"WHERE s.id = $1 AND s.user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("update stacks", err)
	}
	if prev == nil {
		return apiErr(http.StatusNotFound, "Stack not found")
	}
	previousMode := rtStacksEffectiveTlsMode(prev.TlsMode, prev.SslEmail)

	// Absent means KEEP, for all four (the #104 fix: an edit used to forward
	// the request's address verbatim and took the certificate off a stack).
	requestedMode, err := rtStacksRequestedTlsMode(body.TlsMode)
	if err != nil {
		return err
	}
	requestedDomain := prev.Domain
	if bodyDomain != nil {
		requestedDomain = *bodyDomain
	}
	sslEmail := rtStacksTrimmed(body.SslEmail)
	if sslEmail == nil {
		sslEmail = prev.SslEmail
	}
	alias := rtStacksTrimmed(body.TlsCertificate)
	if alias == nil {
		alias = prev.Alias
	}

	// Everything from here down is one machine's work, and the row says which
	// machine. Taking it from the request let an edit tear the stack down on
	// one host and stand it up on another, desynchronising the record from the
	// thing it describes — the next delete then went to the old host, found
	// nothing, reported success and dropped the record, leaving containers on
	// a machine no handler can reach, holding a domain nothing will renew.
	agent, err := agentForSiteServer(ctx, st, &prev.ServerID, rtStacksOr(prev.Domain, prev.Name))
	if err != nil {
		return err
	}

	// An edit can introduce new images, so it is a deploy as far as the gate
	// is concerned — judged against the stack's OWN host and before the
	// teardown, so a refusal leaves the running stack untouched.
	images := composeImages(body.Yaml)
	if err := rtDockerAppsEnforceAllowedImages(ctx, st.DB, claims.Sub, images); err != nil {
		return err
	}
	for _, image := range images {
		if err := rtImageScansPreflightGateImage(ctx, st.DB, prev.ServerID, agent, image); err != nil {
			return err
		}
	}

	// Holder Stack(id) so a stack keeps its own domain across an edit.
	domain, err := rtStacksClaimStackDomain(ctx, st, r, requestedDomain, DomainClaimHolderStack(id), claims.Role)
	if err != nil {
		return err
	}

	// A stack with no domain has no vhost: a vacated domain resolves to none
	// unless the request names a mode, which the plan then refuses in words.
	var mode string
	switch {
	case requestedMode != nil:
		mode = *requestedMode
	case domain != nil:
		mode = previousMode
	default:
		mode = "none"
	}

	// Same gate and coverage check as create, BEFORE the teardown.
	tls, err := rtStacksPlanTls(ctx, st.DB, agent, mode, domain, sslEmail, alias, claims.Sub, prev.ServerID)
	if err != nil {
		return err
	}

	parsed, err := agent.Post(ctx, "/apps/compose/parse", map[string]any{"yaml": body.Yaml})
	if err != nil {
		return agentError("Compose parse", err)
	}
	arr, _ := jsonArr(parsed)
	serviceCount := int32(len(arr))

	// Remove old containers. The vhost only comes down when the domain is
	// actually changing — tearing it down on every edit would drop the site
	// for as long as the redeploy takes.
	var vacating *string
	if prev.Domain != nil && (domain == nil || *domain != *prev.Domain) {
		vacating = prev.Domain
	}
	if removed, err := rtStacksAgentPost(ctx, agent, "/apps/stack/action", map[string]any{
		"stack_id": id.String(),
		"action":   "remove",
		"domain":   vacating,
	}); err == nil {
		// These come straight back under the SAME names within one sweep, so
		// the engine's absence sweep can never clear them.
		rtStacksClearRemoved(ctx, st.DB, prev.ServerID, removed)
	}

	restore := func() {
		rtStacksRestorePrevious(ctx, st.DB, prev.ServerID, agent, id, prev.Yaml, prev.Domain, prev.SslEmail, previousMode, prev.Alias)
	}
	deployResult, err := rtStacksAgentPost(ctx, agent, "/apps/compose/deploy", map[string]any{
		"yaml":            body.Yaml,
		"stack_id":        id.String(),
		"domain":          domain,
		"ssl_email":       tls.DeployEmail(),
		"tls_mode":        tls.Mode,
		"tls_certificate": tls.Alias,
	})
	if err != nil {
		restore()
		return agentError("Stack redeploy (previous definition restored)", err)
	}

	running, total, errs := rtStacksDeployedServiceStates(deployResult)
	if total > 0 && running == 0 {
		restore()
		return apiErr(http.StatusBadGateway, "No service in the new definition stayed running — the previous stack was "+
			"redeployed and the saved YAML is unchanged. "+strings.Join(errs, " | "))
	}

	// Only now is the new definition worth keeping. ssl_expiry describes the
	// certificate serving THIS ROW'S DOMAIN in ACME mode; when either changes
	// the recorded date stops being about anything this row owns, so it
	// becomes NULL ("not recorded") until the next certificate read.
	// ⛔ Kept, deliberately, when neither changed — blanking on every edit
	// would erase the one answer the offline view has. `vacating` is already
	// this file's spelling of "the domain moved".
	keepsExpiry := tls.Mode == "acme" && vacating == nil
	if _, err := execSQL(ctx, st.DB,
		"UPDATE docker_stacks SET yaml = $1, service_count = $2, domain = $3, ssl_email = $4, "+
			"tls_mode = $5, tls_certificate_id = $6, "+
			"ssl_expiry = CASE WHEN $8 THEN ssl_expiry ELSE NULL END, "+
			"updated_at = NOW() WHERE id = $7",
		body.Yaml, serviceCount, domain, tls.SslEmail, tls.Mode, tls.CertificateID, id, keepsExpiry); err != nil {
		return internalError("update stacks", err)
	}

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "stack.update",
		new("stack"), new(prev.Name), nil, nil, claims.KeyID)

	// Same as create: a provided-mode domain without its HTTPS vhost is an
	// outage, not a note.
	if tls.Mode == "provided" {
		if reason := rtStacksProvidedTlsRefusal(deployResult); reason != nil {
			return apiErr(http.StatusBadGateway, fmt.Sprintf(
				"The stack %s is running with the new definition, but its domain was "+
					"not put behind the registered certificate: %s. Fix the cause and "+
					"redeploy the stack.", prev.Name, *reason))
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"service_count":   serviceCount,
		"domain":          domain,
		"tls_mode":        tls.Mode,
		"tls_certificate": tls.Alias,
		"running":         running,
		"total":           total,
		"deploy_result":   deployResult,
	})
	return nil
}

// rtStacksRestorePrevious puts the stack back the way it was after a failed
// edit. Best effort — if this also fails the operator still has the stored
// YAML. Carries the previous TLS mode and alias too: a restore that sent only
// the address would put a provided-certificate stack back as plain HTTP.
func rtStacksRestorePrevious(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, agent AgentHandle, id uuid.UUID, yaml string, domain, sslEmail *string, tlsMode string, tlsCertificate *string) {
	if removed, err := rtStacksAgentPost(ctx, agent, "/apps/stack/action", map[string]any{"stack_id": id.String(), "action": "remove"}); err == nil {
		rtStacksClearRemoved(ctx, db, serverID, removed)
	}
	var email *string
	if tlsMode == "acme" {
		email = sslEmail
	}
	if _, err := rtStacksAgentPost(ctx, agent, "/apps/compose/deploy", map[string]any{
		"yaml":            yaml,
		"stack_id":        id.String(),
		"domain":          domain,
		"ssl_email":       email,
		"tls_mode":        tlsMode,
		"tls_certificate": tlsCertificate,
	}); err != nil {
		slog.Error(fmt.Sprintf("Stack %s: the update failed AND the previous definition could not be "+
			"redeployed (%v). The saved YAML is still the previous one.", id, err))
	} else {
		slog.Info(fmt.Sprintf("Stack %s: restored the previous definition after a failed update", id))
	}
}

// rtStacksAction is the shared seam for start/stop/restart.
//
// Takes no agent, deliberately: the ownership check is the same lookup that
// names the host, so the guard and the resolver are one query and no caller
// can supply a handle that disagrees with what was just authorised. Aimed at
// the header-named host, a stop matched no `stack_id` label and returned a
// perfectly successful 200 while the containers kept running elsewhere.
func rtStacksAction(ctx context.Context, st *AppState, claims *Claims, id uuid.UUID, action string) (any, error) {
	if err := requireAdmin(claims.Role); err != nil {
		return nil, err
	}
	owned, err := queryOpt[Tup3[string, *string, uuid.UUID]](ctx, st.DB,
		"SELECT name, domain, server_id FROM docker_stacks WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return nil, internalError("stack action", err)
	}
	if owned == nil {
		return nil, apiErr(http.StatusNotFound, "Stack not found")
	}
	name, domain, serverID := owned.A, owned.B, owned.C
	agent, err := agentForSiteServer(ctx, st, &serverID, rtStacksOr(domain, name))
	if err != nil {
		return nil, err
	}
	result, err := rtStacksAgentPost(ctx, agent, "/apps/stack/action", map[string]any{"stack_id": id.String(), "action": action})
	if err != nil {
		return nil, agentError("Stack "+action, err)
	}

	// Stopping a stack is a deliberate stop, N times over: every compose
	// service is a full container_down subject, and one click on a
	// five-service stack produced five criticals correlated into ONE public
	// incident. The agent's per-container results[] lets the expectation be
	// recorded only for the ones that actually stopped.
	results, _ := jsonArr(jsonGet(result, "results"))
	for _, r := range results {
		cname, ok := jsonStr(jsonGet(r, "name"))
		if !ok {
			continue
		}
		switch s, _ := jsonStr(jsonGet(r, "status")); s {
		case "stopped":
			ExpectedStopsRecord(ctx, st.DB, serverID, cname, ExpectedStopsReasonStackStop, new(claims.Email))
			ExpectedStopsResolveOpenContainerDown(ctx, st.DB, serverID, cname)
		// `removed` clears too: a row left behind would suppress a future
		// container that reuses the name.
		case "started", "restarted", "removed":
			ExpectedStopsClear(ctx, st.DB, serverID, cname)
		}
	}
	return result, nil
}

// rtStacksRenewSsl is POST /api/stacks/{id}/renew-ssl — reissue a stack's
// ACME certificate on the operator's say-so.
//
// A SIBLING of the scanner's renew_stack_certificate, deliberately not an
// extraction: the scanner writes the activity row that IS its cooldown and
// fires/clears an alert; this one owes a REFUSAL WITH A SENTENCE.
func rtStacksRenewSsl(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()

	stack, err := queryOpt[rtStacksStack](ctx, st.DB, rtStacksStackSelect+" WHERE s.id = $1", id)
	if err != nil {
		return internalError("stack renew ssl", err)
	}
	if stack == nil {
		return apiErr(http.StatusNotFound, "Stack not found")
	}
	d := rtStacksTrimmed(stack.Domain)
	if d == nil {
		return apiErr(http.StatusBadRequest, "This stack has no domain, so there is no certificate to renew.")
	}
	domain := *d

	// ⛔ Dispatch through the row's OWN server: a domain is unique only per
	// server, so the caller's host would write a certificate on the wrong
	// machine.
	agent, err := agentForSiteServer(ctx, st, &stack.ServerID, domain)
	if err != nil {
		return err
	}

	mode := rtStacksEffectiveTlsMode(stack.TlsMode, stack.SslEmail)
	if mode != "acme" {
		return apiErr(http.StatusUnprocessableEntity, fmt.Sprintf(
			"%s is served in '%s' mode, not ACME. DockPanel reissues only the "+
				"Let's Encrypt certificates it obtains itself — a registered certificate is "+
				"replaced from the Certificates page, and a stack with no TLS has nothing to "+
				"renew.", domain, mode))
	}
	contact := rtStacksTrimmed(stack.SslEmail)
	if contact == nil {
		return apiErr(http.StatusPreconditionFailed,
			"This stack is in ACME mode with no contact address, and a certificate authority "+
				"will not accept an order without one. Add an address to the stack first.")
	}

	// ⛔ THE ISSUER GUARD. The mode is a DATABASE COLUMN; what is about to be
	// overwritten is a FILE the column knows nothing about, and the registry
	// migration backfilled every stack with an address to `acme`. nil means
	// "not proven foreign" and MUST proceed — refusing on an agent hiccup
	// would let a real certificate lapse.
	if issuer := foreignCertIssuer(ctx, agent, domain); issuer != nil {
		return apiErr(http.StatusUnprocessableEntity, fmt.Sprintf(
			"The certificate on %s was not issued by DockPanel (issuer: %s). "+
				"Reissuing would replace it with a Let's Encrypt certificate. Renew it wherever "+
				"it was issued, or install a replacement under Certificates.", domain, *issuer))
	}

	// The agent must be new enough to accept a renewal that describes no
	// vhost (frozen at the release that taught it that).
	if err := rtTlsCertificatesRequireAgentAtLeast(ctx, agent, rtTlsCertificatesStackRenewalMinAgent,
		"Renewing a Compose stack's certificate"); err != nil {
		return err
	}

	// ⛔ NO `runtime` KEY: its absence is the contract with the agent's
	// in-place branch. Only the agent knows the stack's published port, so a
	// runtime sent from here would publish a proxy vhost with no upstream.
	result, err := agent.PostLong(ctx, "/ssl/"+domain+"/renew", map[string]any{"email": *contact}, rtSslDns01OrderTimeoutSecs)
	if err != nil {
		return agentError("SSL renewal", err)
	}

	// Same parse as every other door: the agent prints a `time` Display and
	// the column is TIMESTAMPTZ.
	var expiry *time.Time
	if s, ok := jsonStr(jsonGet(result, "expiry")); ok {
		expiry = parseAgentCertExpiry(s)
	}
	if expiry != nil {
		_, _ = execSQL(ctx, st.DB, "UPDATE docker_stacks SET ssl_expiry = $1 WHERE id = $2", *expiry, id)
	}

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "stack.renew_ssl",
		new("stack"), new(domain), new("stack_id="+id.String()), nil, claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": domain, "expiry": expiry})
	return nil
}
