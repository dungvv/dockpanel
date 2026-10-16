package api

// Port of panel/backend/src/routes/git_deploys.rs — git-push deployments:
// CRUD, manual/webhook/scheduled/approved build+deploy, rollback, previews,
// lifecycle (stop/start/restart/logs), deploy approvals.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rtGitDeploysPreBuildSpliceMinAgent: an agent older than this still has the
// vulnerable `/git/pre-build-hook` host-exec route compiled in (and no
// `pre_build_cmd` handling in `/git/auto-detect`), so a pre-build command
// configured against it would silently do nothing or hit a route that no
// longer exists. Refused up front via require_agent_at_least, mirroring
// PROVIDED_TLS_MIN_AGENT.
const rtGitDeploysPreBuildSpliceMinAgent = "2.182.0"

// rtGitDeploysGitDeploySelect is the row plus the alias of the certificate it
// references, if any — a LEFT JOIN because most deploys reference none, and
// the alias is what the API and the deploy body speak; the id never leaves
// the panel. `id`/`user_id`/`server_id` are ambiguous once joined against
// `tls_certificates`, so every caller must qualify its WHERE clause with `d.`.
const rtGitDeploysGitDeploySelect = "SELECT d.id, d.user_id, d.server_id, d.name, d.repo_url, " +
	"d.branch, d.dockerfile, d.container_port, d.host_port, d.domain, d.env_vars, " +
	"d.auto_deploy, d.webhook_secret, d.deploy_key_public, d.deploy_key_path, " +
	"d.container_id, d.image_tag, d.status, d.memory_mb, d.cpu_percent, d.ssl_email, " +
	"d.pre_build_cmd, d.post_deploy_cmd, d.build_args, d.build_context, d.last_deploy, " +
	"d.last_commit, d.created_at, d.updated_at, d.github_token, d.deploy_cron, " +
	"d.deploy_protected, d.build_method, d.preview_ttl_hours, d.scheduled_deploy_at, " +
	"d.tls_mode, d.tls_certificate_id, d.volumes, c.alias AS tls_certificate " +
	"FROM git_deploys d LEFT JOIN tls_certificates c ON c.id = d.tls_certificate_id"

// The deploy lock every build door takes: flip status to 'building' iff not
// already building. The old guard queried git_deploy_history for a status
// that is NEVER written there, so it never fired. A losing concurrent caller
// gets 0 rows; a crashed deploy self-heals after 30 min (longer than the
// worst-case clone+build+deploy, so a running build never releases its own lock).
const rtGitDeploysLockSQL = "UPDATE git_deploys SET status = 'building', updated_at = NOW() " +
	"WHERE id = $1 AND (status IS DISTINCT FROM 'building' OR updated_at < NOW() - INTERVAL '30 minutes')"

const rtGitDeploysActiveIncidentsSQL = "SELECT COUNT(*) FROM managed_incidents " +
	"WHERE status NOT IN ('resolved', 'postmortem') " +
	"AND severity IN ('critical', 'major')"

// rtGitDeploysStripContainerPrefix: git_previews.container_name is stored WITH
// the `dockpanel-git-` prefix that the agent's `/git/cleanup` re-adds. Passing
// the stored value verbatim yields a double-prefixed name that matches no
// container, so the teardown silently no-ops and leaks the container/image/
// nginx/SSL/repo dir while the DB frees its port. Every preview-cleanup caller
// MUST route the stored name through this (lesson #70).
func rtGitDeploysStripContainerPrefix(stored string) string {
	return strings.TrimPrefix(stored, "dockpanel-git-")
}

// rtGitDeploysPreviewScopePrefix is the container-name prefix a preview is
// created under from v2.55.0 on. `.` is the whole point: isValidName rejects
// it, so no *deployment* can be named into this space. Before the split, a
// preview of config C on branch B was `dockpanel-git-{C}-pr-{slug(B)}` — the
// container of a deployment named `{C}-pr-{slug(B)}`.
const rtGitDeploysPreviewScopePrefix = "pr."

// rtGitDeploysPreviewCleanupTarget turns a stored container_name into the
// (name, scope) pair the agent needs. Rows written before the split carry the
// old unscoped name and are torn down in the old space — `preview_legacy`,
// which refuses any container whose labels say it is a deployment.
// Recomputing the name from the branch would be a second answer to a question
// the row already answers.
func rtGitDeploysPreviewCleanupTarget(stored string) (string, string) {
	bare := rtGitDeploysStripContainerPrefix(stored)
	if name, ok := strings.CutPrefix(bare, rtGitDeploysPreviewScopePrefix); ok {
		return name, "preview"
	}
	return bare, "preview_legacy"
}

// rtGitDeploysPreviewCleanupBody is the one body every preview teardown sends
// to `POST /git/cleanup`. Five call sites (TTL sweep, stuck sweep, manual
// delete, unauthenticated branch-delete webhook, parent removal) had drifted
// into three spellings, one of which double-prefixed the name into a no-op.
// `domain`/`host_port` come from the row because the agent reads them off the
// container, which is exactly what is missing when a crashed preview is swept.
func rtGitDeploysPreviewCleanupBody(containerName string, domain *string, hostPort *int32) any {
	name, scope := rtGitDeploysPreviewCleanupTarget(containerName)
	body := map[string]any{"name": name, "scope": scope}
	if domain != nil && *domain != "" {
		body["domain"] = *domain
	}
	if hostPort != nil && *hostPort >= 0 && *hostPort <= 65535 {
		body["host_port"] = *hostPort
	}
	return body
}

// rtGitDeploysDNSLabel converts a branch name into a DNS-label-safe slug:
// lowercase, every run of chars outside [a-z0-9] collapses to one '-',
// leading/trailing '-' trimmed. An underscore branch like `feature_login`
// would otherwise fail the agent's domain validation and the preview would
// silently fail. Falls back to "preview" if nothing alphanumeric remains.
func rtGitDeploysDNSLabel(s string) string {
	var out strings.Builder
	prevDash := false
	for _, r := range s {
		lowered := strings.ToLower(string(r))
		if r == 'İ' { // Rust's to_lowercase yields "i̇" here
			lowered = "i\u0307"
		}
		for _, c := range lowered {
			if c < 0x80 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				out.WriteRune(c)
				prevDash = false
			} else if !prevDash {
				out.WriteByte('-')
				prevDash = true
			}
		}
	}
	slug := strings.Trim(out.String(), "-")
	if slug == "" {
		return "preview"
	}
	return slug
}

// rtGitDeploysParseU32 is Rust's `str::parse::<u32>` (which accepts one '+').
func rtGitDeploysParseU32(s string) (uint32, bool) {
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "+"), 10, 32)
	return uint32(v), err == nil
}

// rtGitDeploysIsValidCronField validates one crontab field against exactly
// the surface the executor (deploy_scheduler::matches_field) accepts: a comma
// list of `*`, `*/N` (N>0), `a-b`, or a number. Format-only — a validator
// stricter than the executor rejects working crons on edit.
func rtGitDeploysIsValidCronField(field string) bool {
	if field == "" {
		return false
	}
	for _, part := range strings.Split(field, ",") {
		ok := part == "" || // scheduler skips empty comma segments; don't be stricter
			part == "*"
		if !ok {
			if n, has := strings.CutPrefix(part, "*/"); has {
				v, good := rtGitDeploysParseU32(n)
				ok = good && v > 0
			}
		}
		if !ok {
			if a, b, has := strings.Cut(part, "-"); has {
				_, okA := rtGitDeploysParseU32(a)
				_, okB := rtGitDeploysParseU32(b)
				ok = okA && okB
			}
		}
		if !ok {
			_, ok = rtGitDeploysParseU32(part)
		}
		if !ok {
			return false
		}
	}
	return true
}

// rtGitDeploysIsValidCron: AT LEAST 5 whitespace-separated fields (the
// scheduler reads the first 5 and ignores extras — a 6-field "seconds" cron
// still fires), each of the first 5 valid.
func rtGitDeploysIsValidCron(expr string) bool {
	parts := strings.Fields(expr)
	if len(parts) < 5 {
		return false
	}
	for _, f := range parts[:5] {
		if !rtGitDeploysIsValidCronField(f) {
			return false
		}
	}
	return true
}

type rtGitDeploysGitDeploy struct {
	ID              uuid.UUID       `db:"id" json:"id"`
	UserID          uuid.UUID       `db:"user_id" json:"user_id"`
	ServerID        uuid.UUID       `db:"server_id" json:"server_id"`
	Name            string          `db:"name" json:"name"`
	RepoURL         string          `db:"repo_url" json:"repo_url"`
	Branch          string          `db:"branch" json:"branch"`
	Dockerfile      string          `db:"dockerfile" json:"dockerfile"`
	ContainerPort   int32           `db:"container_port" json:"container_port"`
	HostPort        int32           `db:"host_port" json:"host_port"`
	Domain          *string         `db:"domain" json:"domain"`
	EnvVars         json.RawMessage `db:"env_vars" json:"env_vars"`
	AutoDeploy      bool            `db:"auto_deploy" json:"auto_deploy"`
	WebhookSecret   string          `db:"webhook_secret" json:"webhook_secret"`
	DeployKeyPublic *string         `db:"deploy_key_public" json:"deploy_key_public"`
	DeployKeyPath   *string         `db:"deploy_key_path" json:"deploy_key_path"`
	ContainerID     *string         `db:"container_id" json:"container_id"`
	ImageTag        *string         `db:"image_tag" json:"image_tag"`
	Status          string          `db:"status" json:"status"`
	MemoryMB        *int32          `db:"memory_mb" json:"memory_mb"`
	CPUPercent      *int32          `db:"cpu_percent" json:"cpu_percent"`
	SslEmail        *string         `db:"ssl_email" json:"ssl_email"`
	PreBuildCmd     *string         `db:"pre_build_cmd" json:"pre_build_cmd"`
	PostDeployCmd   *string         `db:"post_deploy_cmd" json:"post_deploy_cmd"`
	BuildArgs       json.RawMessage `db:"build_args" json:"build_args"`
	BuildContext    string          `db:"build_context" json:"build_context"`
	LastDeploy      *time.Time      `db:"last_deploy" json:"last_deploy"`
	LastCommit      *string         `db:"last_commit" json:"last_commit"`
	CreatedAt       time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time       `db:"updated_at" json:"updated_at"`
	GithubToken     *string         `db:"github_token" json:"github_token"`
	DeployCron      *string         `db:"deploy_cron" json:"deploy_cron"`
	DeployProtected bool            `db:"deploy_protected" json:"deploy_protected"`
	BuildMethod     string          `db:"build_method" json:"build_method"`
	PreviewTTLHours int32           `db:"preview_ttl_hours" json:"preview_ttl_hours"`
	// Scheduled one-time deploy.
	ScheduledDeployAt *time.Time `db:"scheduled_deploy_at" json:"scheduled_deploy_at"`
	// How the domain is served, as stored. NULL on a row an older binary
	// wrote; read through rtStacksEffectiveTlsMode, never directly.
	TlsMode *string `db:"tls_mode" json:"tls_mode"`
	// The registered certificate a provided-mode deploy serves.
	TlsCertificateID *uuid.UUID `db:"tls_certificate_id" json:"tls_certificate_id"`
	// Container paths bind-mounted durably under GIT_DATA_DIR/{name} on the
	// agent (#118). Never sent to a preview deploy.
	Volumes json.RawMessage `db:"volumes" json:"volumes"`
	// The certificate's alias, joined in by the SELECT. Defaulted so the plain
	// `RETURNING *` of create/update (no join) still maps; both set it by hand.
	TlsCertificate *string `db:"tls_certificate,default" json:"tls_certificate"`
}

type rtGitDeploysGitPreview struct {
	ID            uuid.UUID `db:"id" json:"id"`
	GitDeployID   uuid.UUID `db:"git_deploy_id" json:"git_deploy_id"`
	Branch        string    `db:"branch" json:"branch"`
	ContainerName string    `db:"container_name" json:"container_name"`
	ContainerID   *string   `db:"container_id" json:"container_id"`
	HostPort      int32     `db:"host_port" json:"host_port"`
	Domain        *string   `db:"domain" json:"domain"`
	Status        string    `db:"status" json:"status"`
	CommitHash    *string   `db:"commit_hash" json:"commit_hash"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
}

// rtGitDeploysDeployBody is everything `POST /git/deploy` carries, as one
// struct so adding a field to the agent's DeployRequest forces every caller
// to say what it passes for it.
type rtGitDeploysDeployBody struct {
	Name          string
	ImageTag      string
	ContainerPort int32
	HostPort      int32
	EnvVars       any // decoded env_vars JSONB
	Domain        *string
	MemoryMB      *int32
	CPUPercent    *int32
	// The address the AGENT is handed. Only for `acme` — pass through
	// rtGitDeploysDeployTLSEmail, never config.SslEmail directly.
	SslEmail *string
	// The effective mode, sent on every deploy so the agent no longer infers
	// it from ssl_email presence alone.
	TlsMode *string
	// Registered-certificate alias, `provided` mode only.
	TlsCertificate *string
	// "deploy" or "preview". Not defaulted on purpose: an omitted scope is
	// how a preview came to be able to name a deployment's container.
	Scope string
	// ALWAYS empty for a preview; the agent refuses a non-empty list for any
	// scope but "deploy" as the actual boundary.
	Volumes []string
}

// rtGitDeploysDeployTLSEmail: only an ACME order needs an address, and an
// agent still infers the mode from ssl_email presence when an older panel
// sends no tls_mode — so a `none`/`provided` deploy must never forward it.
func rtGitDeploysDeployTLSEmail(mode string, sslEmail *string) *string {
	if mode == "acme" {
		return sslEmail
	}
	return nil
}

// rtGitDeploysEnvObject coerces env_vars into the object of strings the agent
// deserializes (HashMap<String, String>). The JSONB column is unconstrained,
// and passing a number through would fail the WHOLE deploy at the agent's
// deserializer. Scalars are stringified; null/array/object dropped.
//
// (GH #94: the key sent is `env`, the one the agent has always read — four
// call sites once sent `env_vars`, which the agent dropped, so every git
// deploy started with no environment while every layer reported success.
// Exactly one key is sent: serde rejects a field plus its alias as duplicate.)
func rtGitDeploysEnvObject(envVars any) map[string]any {
	out := map[string]any{}
	obj, ok := envVars.(map[string]any)
	if !ok {
		return out
	}
	for k, v := range obj {
		switch t := v.(type) {
		case string:
			out[k] = t
		case json.Number:
			out[k] = t.String()
		case bool:
			out[k] = strconv.FormatBool(t)
		}
	}
	return out
}

// rtGitDeploysIsValidVolumePath: a persistent-volume path is CONTAINER-path
// only (#118); the host side is always derived by the agent. Mirrors the
// agent's own is_valid_volume_path — this is the friendly check, the agent's
// copy is the security floor.
func rtGitDeploysIsValidVolumePath(path string) bool {
	if !strings.HasPrefix(path, "/") || len(path) <= 1 || len(path) > 200 ||
		strings.Contains(path, "..") || strings.Contains(path, "//") {
		return false
	}
	for _, c := range path {
		if !(c < 0x80 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') ||
			c == '/' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

const rtGitDeploysMaxVolumes = 10

// rtGitDeploysValidateVolumes returns the refusal message, "" when valid.
func rtGitDeploysValidateVolumes(volumes []string) string {
	if len(volumes) > rtGitDeploysMaxVolumes {
		return "Too many volumes declared (max 10)"
	}
	for _, v := range volumes {
		if !rtGitDeploysIsValidVolumePath(v) {
			return "Invalid volume path: must be an absolute container path with no '..' or '//'"
		}
	}
	sorted := slices.Clone(volumes)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(volumes) {
		return "Duplicate volume path"
	}
	return ""
}

// rtGitDeploysVolumesVec coerces the volumes JSONB into []string, dropping
// non-string entries rather than failing the whole deploy.
func rtGitDeploysVolumesVec(v any) []string {
	out := []string{}
	arr, _ := v.([]any)
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// rtGitDeploysJSON decodes a JSONB column like serde_json::Value (numbers as
// json.Number); nil on null/garbage.
func rtGitDeploysJSON(raw json.RawMessage) any {
	if !json.Valid(raw) {
		return nil
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return nil
	}
	return v
}

func rtGitDeploysBuildDeployBody(b rtGitDeploysDeployBody) map[string]any {
	body := map[string]any{
		"name":           b.Name,
		"image_tag":      b.ImageTag,
		"container_port": b.ContainerPort,
		"host_port":      b.HostPort,
		"env":            rtGitDeploysEnvObject(b.EnvVars),
		"scope":          b.Scope,
	}
	if len(b.Volumes) > 0 {
		body["volumes"] = b.Volumes
	}
	// Clearing a field is the empty string on the wire, so Some("") arrives
	// here. Blank is absent for both: a blank domain would have the agent
	// write a vhost named ".conf", a blank ssl_email an ACME order with no
	// account address. Guard the value, not the Option.
	if b.Domain != nil && strings.TrimSpace(*b.Domain) != "" {
		body["domain"] = *b.Domain
	}
	if b.MemoryMB != nil {
		body["memory_mb"] = *b.MemoryMB
	}
	if b.CPUPercent != nil {
		body["cpu_percent"] = *b.CPUPercent
	}
	if b.SslEmail != nil && strings.TrimSpace(*b.SslEmail) != "" {
		body["ssl_email"] = *b.SslEmail
	}
	if b.TlsMode != nil {
		body["tls_mode"] = *b.TlsMode
	}
	if b.TlsCertificate != nil {
		body["tls_certificate"] = *b.TlsCertificate
	}
	return body
}

// rtGitDeploysConfigDeployBody is the production deploy body built from a row
// — shared by manual/webhook/approved, scheduled and rollback deploys.
func rtGitDeploysConfigDeployBody(c *rtGitDeploysGitDeploy, imageTag, mode string) map[string]any {
	return rtGitDeploysBuildDeployBody(rtGitDeploysDeployBody{
		Name:           c.Name,
		ImageTag:       imageTag,
		ContainerPort:  c.ContainerPort,
		HostPort:       c.HostPort,
		EnvVars:        rtGitDeploysJSON(c.EnvVars),
		Domain:         c.Domain,
		MemoryMB:       c.MemoryMB,
		CPUPercent:     c.CPUPercent,
		SslEmail:       rtGitDeploysDeployTLSEmail(mode, c.SslEmail),
		TlsMode:        &mode,
		TlsCertificate: c.TlsCertificate,
		Scope:          "deploy",
		Volumes:        rtGitDeploysVolumesVec(rtGitDeploysJSON(c.Volumes)),
	})
}

type rtGitDeploysGitDeployHistory struct {
	ID            uuid.UUID `db:"id" json:"id"`
	GitDeployID   uuid.UUID `db:"git_deploy_id" json:"git_deploy_id"`
	CommitHash    string    `db:"commit_hash" json:"commit_hash"`
	CommitMessage *string   `db:"commit_message" json:"commit_message"`
	ImageTag      string    `db:"image_tag" json:"image_tag"`
	Status        string    `db:"status" json:"status"`
	Output        *string   `db:"output" json:"output"`
	TriggeredBy   string    `db:"triggered_by" json:"triggered_by"`
	DurationMs    *int32    `db:"duration_ms" json:"duration_ms"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
}

type rtGitDeploysCreateRequest struct {
	Name          string             `json:"name"`
	RepoURL       string             `json:"repo_url"`
	Branch        *string            `json:"branch"`
	Dockerfile    *string            `json:"dockerfile"`
	ContainerPort *int32             `json:"container_port"`
	Domain        *string            `json:"domain"`
	EnvVars       *map[string]string `json:"env_vars"`
	AutoDeploy    *bool              `json:"auto_deploy"`
	MemoryMB      *int32             `json:"memory_mb"`
	CPUPercent    *int32             `json:"cpu_percent"`
	SslEmail      *string            `json:"ssl_email"`
	// none / acme / provided — absent means derive it from ssl_email presence.
	TlsMode *string `json:"tls_mode"`
	// The registered-certificate alias, provided mode only.
	TlsCertificate  *string            `json:"tls_certificate"`
	PreBuildCmd     *string            `json:"pre_build_cmd"`
	PostDeployCmd   *string            `json:"post_deploy_cmd"`
	BuildArgs       *map[string]string `json:"build_args"`
	BuildContext    *string            `json:"build_context"`
	GithubToken     *string            `json:"github_token"`
	DeployCron      *string            `json:"deploy_cron"`
	DeployProtected *bool              `json:"deploy_protected"`
	PreviewTTLHours *int32             `json:"preview_ttl_hours"`
	Volumes         *[]string          `json:"volumes"`
}

type rtGitDeploysUpdateRequest struct {
	RepoURL       *string            `json:"repo_url"`
	Branch        *string            `json:"branch"`
	Dockerfile    *string            `json:"dockerfile"`
	ContainerPort *int32             `json:"container_port"`
	Domain        *string            `json:"domain"`
	EnvVars       *map[string]string `json:"env_vars"`
	AutoDeploy    *bool              `json:"auto_deploy"`
	MemoryMB      *int32             `json:"memory_mb"`
	CPUPercent    *int32             `json:"cpu_percent"`
	SslEmail      *string            `json:"ssl_email"`
	// Absent means keep the stored mode.
	TlsMode *string `json:"tls_mode"`
	// Absent keeps the stored alias; "" clears it (only meaningful if the
	// resulting mode is not provided).
	TlsCertificate  *string            `json:"tls_certificate"`
	PreBuildCmd     *string            `json:"pre_build_cmd"`
	PostDeployCmd   *string            `json:"post_deploy_cmd"`
	BuildArgs       *map[string]string `json:"build_args"`
	BuildContext    *string            `json:"build_context"`
	GithubToken     *string            `json:"github_token"`
	DeployCron      *string            `json:"deploy_cron"`
	DeployProtected *bool              `json:"deploy_protected"`
	PreviewTTLHours *int32             `json:"preview_ttl_hours"`
	// Absent keeps the stored list; the frontend always sends the full list
	// (including [] to clear it).
	Volumes *[]string `json:"volumes"`
}

func rtGitDeploysPtr[T any](v T) *T { return &v }

// rtGitDeploysASCIILower is Rust's to_ascii_lowercase (non-ASCII untouched).
func rtGitDeploysASCIILower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}, s)
}

// rtGitDeploysRevealSecrets masks the github token and decrypts the webhook
// secret — GitDeploys.tsx builds the webhook URL from it on every load.
func rtGitDeploysRevealSecrets(st *AppState, d *rtGitDeploysGitDeploy) {
	rtGitDeploysMaskGithubToken(d)
	d.WebhookSecret = SecretsCryptoDecryptCredentialOrLegacy(d.WebhookSecret, st.Config.JWTSecret)
}

// rtGitDeploysLoadOwned is the GIT_DEPLOY_SELECT owner lookup most handlers
// open with: 404 "Git deploy not found" when absent.
func rtGitDeploysLoadOwned(ctx context.Context, st *AppState, id, userID uuid.UUID, errCtx string) (*rtGitDeploysGitDeploy, error) {
	d, err := queryOpt[rtGitDeploysGitDeploy](ctx, st.DB, rtGitDeploysGitDeploySelect+" WHERE d.id = $1 AND d.user_id = $2", id, userID)
	if err != nil {
		return nil, internalError(errCtx, err)
	}
	if d == nil {
		return nil, apiErr(http.StatusNotFound, "Git deploy not found")
	}
	return d, nil
}

// rtGitDeploysRowAgent resolves the agent for the server the row LIVES ON —
// see rtGitDeploysRemove for why the caller's ServerScope is the wrong authority.
func rtGitDeploysRowAgent(ctx context.Context, st *AppState, serverID uuid.UUID, domain *string, name string) (AgentHandle, error) {
	label := name
	if domain != nil {
		label = *domain
	}
	return agentForSiteServer(ctx, st, &serverID, label)
}

// GET /api/git-deploys — List all git deploys for the current user.
func rtGitDeploysList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	deploys, err := queryAll[rtGitDeploysGitDeploy](r.Context(), st.DB,
		rtGitDeploysGitDeploySelect+" WHERE d.user_id = $1 AND d.server_id = $2 ORDER BY d.created_at DESC LIMIT 200",
		claims.Sub, serverID)
	if err != nil {
		return internalError("list git_deploys", err)
	}
	for i := range deploys {
		rtGitDeploysRevealSecrets(st, &deploys[i])
	}
	if deploys == nil {
		deploys = []rtGitDeploysGitDeploy{}
	}
	writeJSON(w, http.StatusOK, deploys)
	return nil
}

// POST /api/git-deploys — Create a new git deploy configuration.
func rtGitDeploysCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	// The ServerScope extraction stays even though the handle is unused:
	// extracting it IS the check that the caller owns the server they named,
	// and server_id is what the new row records as its host.
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body rtGitDeploysCreateRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}

	if !isValidName(body.Name) {
		return apiErr(http.StatusBadRequest, "Invalid deploy name")
	}
	if strings.TrimSpace(body.RepoURL) == "" {
		return apiErr(http.StatusBadRequest, "Repository URL is required")
	}
	if err := validateRepoURLNotInternal(ctx, body.RepoURL); err != nil {
		return apiErr(http.StatusBadRequest, "Invalid repository URL: "+err.Error())
	}

	// Auto-allocate host_port: first gap in 7000-7999 (scoped to this server).
	used, err := queryAll[int32](ctx, st.DB, "SELECT host_port FROM git_deploys WHERE server_id = $1 ORDER BY host_port", serverID)
	if err != nil {
		return internalError("create git_deploys", err)
	}
	hostPort := int32(-1)
	for p := int32(7000); p <= 7999; p++ {
		if !slices.Contains(used, p) {
			hostPort = p
			break
		}
	}
	if hostPort < 0 {
		return apiErr(http.StatusConflict, "No available ports in range 7000-7999")
	}

	secretBytes := make([]byte, 32)
	_, _ = rand.Read(secretBytes)
	webhookSecret := hex.EncodeToString(secretBytes)
	encryptedWebhookSecret, err := SecretsCryptoEncryptCredential(webhookSecret, st.Config.JWTSecret)
	if err != nil {
		return apiErr(http.StatusInternalServerError, "Encryption failed: "+err.Error())
	}

	branch := "main"
	if body.Branch != nil {
		branch = *body.Branch
	}
	dockerfile := "Dockerfile"
	if body.Dockerfile != nil {
		dockerfile = *body.Dockerfile
	}
	containerPort := int32(3000)
	if body.ContainerPort != nil {
		containerPort = *body.ContainerPort
	}
	autoDeploy := body.AutoDeploy != nil && *body.AutoDeploy
	envVars := json.RawMessage(`{}`)
	if body.EnvVars != nil {
		envVars, _ = json.Marshal(*body.EnvVars)
	}
	buildArgs := json.RawMessage(`{}`)
	if body.BuildArgs != nil {
		buildArgs, _ = json.Marshal(*body.BuildArgs)
	}
	buildContext := "."
	if body.BuildContext != nil {
		buildContext = *body.BuildContext
	}
	deployProtected := body.DeployProtected != nil && *body.DeployProtected
	previewTTL := int32(24)
	if body.PreviewTTLHours != nil {
		previewTTL = *body.PreviewTTLHours
	}

	// Validate pre_build_cmd and post_deploy_cmd for command injection.
	if body.PreBuildCmd != nil && strings.TrimSpace(*body.PreBuildCmd) != "" {
		if msg := isSafeShellCommand(*body.PreBuildCmd); msg != "" {
			return apiErr(http.StatusBadRequest, "pre_build_cmd: "+msg)
		}
	}
	if body.PostDeployCmd != nil && strings.TrimSpace(*body.PostDeployCmd) != "" {
		if msg := isSafeShellCommand(*body.PostDeployCmd); msg != "" {
			return apiErr(http.StatusBadRequest, "post_deploy_cmd: "+msg)
		}
	}
	// Prevent path traversal.
	if strings.Contains(buildContext, "..") || strings.HasPrefix(buildContext, "/") {
		return apiErr(http.StatusBadRequest, "build_context must not contain '..' or start with '/'")
	}
	// Reject unparseable crons that would be stored and mis-scheduled.
	if body.DeployCron != nil && strings.TrimSpace(*body.DeployCron) != "" && !rtGitDeploysIsValidCron(*body.DeployCron) {
		return apiErr(http.StatusBadRequest, "Invalid deploy_cron: expected at least 5 crontab fields")
	}

	volumes := []string{}
	if body.Volumes != nil {
		volumes = *body.Volumes
	}
	if msg := rtGitDeploysValidateVolumes(volumes); msg != "" {
		return apiErr(http.StatusBadRequest, msg)
	}
	volumesJSON, _ := json.Marshal(volumes)

	// Format, reserved and every owner — see services::domain_claim. The two
	// conflict queries once inlined here are the ones update never grew, which
	// is how a deploy could be RENAMED onto a domain it could not be CREATED on.
	// A blank box stays NULL: `remove` falls back on the name only for NULL.
	var domain *string
	if body.Domain != nil && *body.Domain != "" {
		d, err := DomainClaimEnsureClaimable(ctx, st.DB, st.Agents, *body.Domain, r, DomainClaimHolderNew, claims.Role)
		if err != nil {
			return err
		}
		domain = &d
	}

	// Encrypted at rest; set_github_status decrypts. Also refuses the mask
	// sentinel, so a client echoing back ●●●●●●●● cannot overwrite a token.
	githubTokenEnc, err := rtGitDeploysEncryptStoredToken(body.GithubToken, st.Config.JWTSecret)
	if err != nil {
		return err
	}

	// Resolve TLS mode/certificate before the row is written — the DB-only
	// half of stacks::plan_tls. A git deploy's create never talks to the
	// agent (the deploy is a separate, later action), so the SAN-coverage
	// check stays where the domain is actually served: the agent re-asks it
	// at every deploy regardless, and a claim-time check would only narrow,
	// never close, the drift window.
	requested, err := rtStacksRequestedTlsMode(body.TlsMode)
	if err != nil {
		return err
	}
	mode := ""
	if requested != nil {
		mode = *requested
	} else {
		mode = rtStacksEffectiveTlsMode(nil, body.SslEmail)
	}
	var tlsCertificateID *uuid.UUID
	var resolvedAlias *string
	switch mode {
	case "acme":
		if body.SslEmail == nil || strings.TrimSpace(*body.SslEmail) == "" {
			return apiErr(http.StatusBadRequest, "Let's Encrypt mode needs an ssl_email for the ACME account")
		}
	case "provided":
		if domain == nil {
			return apiErr(http.StatusBadRequest, "a TLS mode needs a domain")
		}
		if body.TlsCertificate == nil || strings.TrimSpace(*body.TlsCertificate) == "" {
			return apiErr(http.StatusBadRequest, "tls_mode provided needs tls_certificate — the alias of a registered certificate")
		}
		alias := rtGitDeploysASCIILower(strings.TrimSpace(*body.TlsCertificate))
		if !rtTlsCertificatesIsValidCertAlias(alias) {
			return apiErr(http.StatusBadRequest, "Alias must be 1-64 lowercase letters, digits or hyphens, starting and ending with a letter or digit")
		}
		certID, err := rtTlsCertificatesCertificateIdForAlias(ctx, st.DB, alias, claims.Sub, serverID)
		if err != nil {
			return err
		}
		tlsCertificateID, resolvedAlias = &certID, &alias
	default:
		mode = "none"
	}

	// The form posts the same object to create and update, so these arrive
	// blank rather than absent. NULL is the stored spelling of "not set" on
	// this table, so the blank is normalised away here.
	deploy, err := queryOne[rtGitDeploysGitDeploy](ctx, st.DB,
		"INSERT INTO git_deploys (user_id, server_id, name, repo_url, branch, dockerfile, container_port, host_port, domain, env_vars, auto_deploy, webhook_secret, memory_mb, cpu_percent, ssl_email, pre_build_cmd, post_deploy_cmd, build_args, build_context, github_token, deploy_cron, deploy_protected, preview_ttl_hours, tls_mode, tls_certificate_id, volumes) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26) "+
			"RETURNING *",
		claims.Sub, serverID, body.Name, strings.TrimSpace(body.RepoURL), branch, dockerfile, containerPort, hostPort,
		domain, envVars, autoDeploy, encryptedWebhookSecret, body.MemoryMB, body.CPUPercent,
		rtGitDeploysBlankToNone(body.SslEmail), rtGitDeploysBlankToNone(body.PreBuildCmd), rtGitDeploysBlankToNone(body.PostDeployCmd),
		buildArgs, buildContext, githubTokenEnc, rtGitDeploysBlankToNone(body.DeployCron), deployProtected, previewTTL,
		mode, tlsCertificateID, json.RawMessage(volumesJSON))
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return apiErr(http.StatusConflict, "A deploy with this name already exists")
		}
		return internalError("create git_deploys", err)
	}
	// RETURNING * has no join to read the alias through.
	deploy.TlsCertificate = resolvedAlias

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "git_deploy.create",
		rtGitDeploysPtr("git_deploy"), &body.Name, nil, nil, claims.KeyID)

	// GAP 13: auto-create a webhook gateway endpoint for this git deploy.
	gwToken := strings.ReplaceAll(uuid.New().String(), "-", "")
	_, _ = execSQL(ctx, st.DB,
		"INSERT INTO webhook_endpoints (user_id, name, description, token, verify_mode) "+
			"VALUES ($1, $2, $3, $4, 'none')",
		claims.Sub, "Git: "+body.Name, fmt.Sprintf("Auto-created for git deploy '%s'", body.Name), gwToken)

	rtGitDeploysRevealSecrets(st, &deploy)
	writeJSON(w, http.StatusCreated, deploy)
	return nil
}

// GET /api/git-deploys/{id} — Get a single git deploy.
func rtGitDeploysGetOne(st *AppState, w http.ResponseWriter, r *http.Request) error {
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
	deploy, err := rtGitDeploysLoadOwned(r.Context(), st, id, claims.Sub, "get_one git_deploys")
	if err != nil {
		return err
	}
	rtGitDeploysRevealSecrets(st, deploy)
	writeJSON(w, http.StatusOK, deploy)
	return nil
}

type rtGitDeploysUpdateExisting struct {
	Domain          *string   `db:"domain"`
	DeployCron      *string   `db:"deploy_cron"`
	DeployProtected bool      `db:"deploy_protected"`
	ServerID        uuid.UUID `db:"server_id"`
	SslEmail        *string   `db:"ssl_email"`
	TlsMode         *string   `db:"tls_mode"`
	Alias           *string   `db:"alias"`
}

// PUT /api/git-deploys/{id} — Update a git deploy configuration.
func rtGitDeploysUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtGitDeploysUpdateRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}

	// Ownership + current values, so only values that actually CHANGE are
	// validated (grandfathering rows that predate these guards). The
	// protection flag is fetched only to tell "changed it" from "re-sent it";
	// server_id/ssl_email/tls_mode/alias so an edit that says nothing about
	// TLS keeps the CURRENT effective mode.
	cur, err := queryOpt[rtGitDeploysUpdateExisting](ctx, st.DB,
		"SELECT d.domain, d.deploy_cron, d.deploy_protected, d.server_id, d.ssl_email, "+
			"d.tls_mode, c.alias "+
			"FROM git_deploys d LEFT JOIN tls_certificates c ON c.id = d.tls_certificate_id "+
			"WHERE d.id = $1 AND d.user_id = $2",
		id, claims.Sub)
	if err != nil {
		return internalError("update git_deploys", err)
	}
	if cur == nil {
		return apiErr(http.StatusNotFound, "Git deploy not found")
	}
	previousMode := rtStacksEffectiveTlsMode(cur.TlsMode, cur.SslEmail)

	// Validate domain ONLY when it changes — with the full claim, because a
	// domain that could not be created could once still be renamed onto.
	var domain *string
	switch d := body.Domain; {
	case d != nil && *d != "" && (cur.Domain == nil || *d != *cur.Domain):
		// No agent here: the claim asks the registry, so a rename no longer
		// 502s merely because the target box is mid-reboot.
		claimed, err := DomainClaimEnsureClaimable(ctx, st.DB, st.Agents, *d, r, DomainClaimHolderGitDeploy(id), claims.Role)
		if err != nil {
			return err
		}
		domain = &claimed
	case d != nil && strings.TrimSpace(*d) == "" && cur.Domain != nil && strings.TrimSpace(*cur.Domain) != "":
		// Emptying the box is REFUSED. The clear leg needs the domain column
		// to accept a '' sentinel and every Option-shaped reader re-checked —
		// `remove` falls back on the name only for NULL. A rename now moves
		// the deploy cleanly via /git/release-domain below.
		return apiErr(http.StatusBadRequest, fmt.Sprintf(
			"Removing the domain is not supported yet: the vhost for %s would be left "+
				"without a replacement to put in its place. Entering a DIFFERENT domain now "+
				"moves the deploy cleanly — the old vhost and its certificate are taken down "+
				"for you — or delete the deploy to remove it entirely.",
			*cur.Domain))
	default:
		domain = d
	}

	if c := body.DeployCron; c != nil && strings.TrimSpace(*c) != "" && (cur.DeployCron == nil || *c != *cur.DeployCron) && !rtGitDeploysIsValidCron(*c) {
		return apiErr(http.StatusBadRequest, "Invalid deploy_cron: expected at least 5 crontab fields")
	}
	if body.PreBuildCmd != nil && strings.TrimSpace(*body.PreBuildCmd) != "" {
		if msg := isSafeShellCommand(*body.PreBuildCmd); msg != "" {
			return apiErr(http.StatusBadRequest, "pre_build_cmd: "+msg)
		}
	}
	if body.PostDeployCmd != nil && strings.TrimSpace(*body.PostDeployCmd) != "" {
		if msg := isSafeShellCommand(*body.PostDeployCmd); msg != "" {
			return apiErr(http.StatusBadRequest, "post_deploy_cmd: "+msg)
		}
	}
	// SSRF: an edit can point an existing deploy at a NEW repo.
	if body.RepoURL != nil && strings.TrimSpace(*body.RepoURL) != "" {
		if err := validateRepoURLNotInternal(ctx, *body.RepoURL); err != nil {
			return apiErr(http.StatusBadRequest, "Invalid repository URL: "+err.Error())
		}
	}

	var envVars, buildArgs, volumes any
	if body.EnvVars != nil {
		b, _ := json.Marshal(*body.EnvVars)
		envVars = json.RawMessage(b)
	}
	if body.BuildArgs != nil {
		b, _ := json.Marshal(*body.BuildArgs)
		buildArgs = json.RawMessage(b)
	}
	if body.Volumes != nil {
		if msg := rtGitDeploysValidateVolumes(*body.Volumes); msg != "" {
			return apiErr(http.StatusBadRequest, msg)
		}
		b, _ := json.Marshal(*body.Volumes)
		volumes = json.RawMessage(b)
	}

	githubTokenEnc, err := rtGitDeploysEncryptStoredToken(body.GithubToken, st.Config.JWTSecret)
	if err != nil {
		return err
	}

	// Absent means KEEP, for both mode and alias — the stacks::update fix for
	// the identical bug (an edit silent on TLS took the certificate off).
	requested, err := rtStacksRequestedTlsMode(body.TlsMode)
	if err != nil {
		return err
	}
	mode := previousMode
	if requested != nil {
		mode = *requested
	}
	effectiveSslEmail := cur.SslEmail
	if body.SslEmail != nil {
		if *body.SslEmail == "" {
			effectiveSslEmail = nil
		} else {
			effectiveSslEmail = body.SslEmail
		}
	}
	effectiveDomain := domain
	if effectiveDomain == nil {
		effectiveDomain = cur.Domain
	}
	effectiveDomainPresent := effectiveDomain != nil && strings.TrimSpace(*effectiveDomain) != ""
	var tlsCertificateID *uuid.UUID
	var resolvedAlias *string
	switch mode {
	case "acme":
		if effectiveSslEmail == nil || strings.TrimSpace(*effectiveSslEmail) == "" {
			return apiErr(http.StatusBadRequest, "Let's Encrypt mode needs an ssl_email for the ACME account")
		}
	case "provided":
		if !effectiveDomainPresent {
			return apiErr(http.StatusBadRequest, "a TLS mode needs a domain")
		}
		var alias string
		if body.TlsCertificate != nil && strings.TrimSpace(*body.TlsCertificate) != "" {
			alias = strings.TrimSpace(*body.TlsCertificate)
		} else if cur.Alias != nil {
			alias = *cur.Alias
		} else {
			return apiErr(http.StatusBadRequest, "tls_mode provided needs tls_certificate — the alias of a registered certificate")
		}
		alias = rtGitDeploysASCIILower(alias)
		if !rtTlsCertificatesIsValidCertAlias(alias) {
			return apiErr(http.StatusBadRequest, "Alias must be 1-64 lowercase letters, digits or hyphens, starting and ending with a letter or digit")
		}
		certID, err := rtTlsCertificatesCertificateIdForAlias(ctx, st.DB, alias, claims.Sub, cur.ServerID)
		if err != nil {
			return err
		}
		tlsCertificateID, resolvedAlias = &certID, &alias
	default:
		mode = "none"
	}

	// THREE states on the wire: key absent → NULL → COALESCE keeps; "" → CASE
	// writes NULL; v → v. The empty string is a WIRE sentinel, never stored:
	// `remove` reads the domain with unwrap_or(&name), so a stored '' would
	// hand the agent an empty site identifier. `domain` is deliberately NOT
	// in this list (see the refusal above), nor `github_token` (the GET masks
	// it, so the box is blank on every ordinary edit).
	deploy, err := queryOne[rtGitDeploysGitDeploy](ctx, st.DB,
		"UPDATE git_deploys SET "+
			"repo_url = COALESCE($1, repo_url), "+
			"branch = COALESCE($2, branch), "+
			"dockerfile = COALESCE($3, dockerfile), "+
			"container_port = COALESCE($4, container_port), "+
			"domain = COALESCE($5, domain), "+
			"env_vars = COALESCE($6, env_vars), "+
			"auto_deploy = COALESCE($7, auto_deploy), "+
			"memory_mb = $8, "+
			"cpu_percent = $9, "+
			"ssl_email = CASE WHEN $10 = '' THEN NULL ELSE COALESCE($10, ssl_email) END, "+
			"pre_build_cmd = CASE WHEN $11 = '' THEN NULL ELSE COALESCE($11, pre_build_cmd) END, "+
			"post_deploy_cmd = CASE WHEN $12 = '' THEN NULL ELSE COALESCE($12, post_deploy_cmd) END, "+
			"build_args = COALESCE($13, build_args), "+
			"build_context = COALESCE($14, build_context), "+
			"github_token = COALESCE($15, github_token), "+
			"deploy_cron = CASE WHEN $16 = '' THEN NULL ELSE COALESCE($16, deploy_cron) END, "+
			"deploy_protected = COALESCE($17, deploy_protected), "+
			"preview_ttl_hours = COALESCE($18, preview_ttl_hours), "+
			"tls_mode = $19, "+
			"tls_certificate_id = $20, "+
			"volumes = COALESCE($21, volumes), "+
			"updated_at = NOW() "+
			"WHERE id = $22 AND user_id = $23 "+
			"RETURNING *",
		body.RepoURL, body.Branch, body.Dockerfile, body.ContainerPort, domain, envVars, body.AutoDeploy,
		body.MemoryMB, body.CPUPercent, body.SslEmail, body.PreBuildCmd, body.PostDeployCmd, buildArgs,
		body.BuildContext, githubTokenEnc, body.DeployCron, body.DeployProtected, body.PreviewTTLHours,
		mode, tlsCertificateID, volumes, id, claims.Sub)
	if err != nil {
		return internalError("update git_deploys", err)
	}
	deploy.TlsCertificate = resolvedAlias

	// A RENAME walked away from a vhost that is still serving — another
	// tenant could claim the old name and be answered by this app. Asked of
	// the agent (only the box sees whether the old vhost still points at THIS
	// container's port; services::ownership fails closed). Fire-and-forget:
	// the rename is committed, and a box mid-reboot must not 502 the save.
	if domain != nil && cur.Domain != nil {
		newDomain, oldDomain := *domain, *cur.Domain
		if strings.TrimSpace(oldDomain) != "" && oldDomain != newDomain {
			agent, aerr := agentForSiteServer(ctx, st, &deploy.ServerID, oldDomain)
			if aerr == nil {
				if _, e := agent.Post(ctx, "/git/release-domain", map[string]any{"domain": oldDomain, "host_port": deploy.HostPort}); e != nil {
					slog.Warn(fmt.Sprintf("Renamed git deploy '%s' to %s but could not release %s on its host: %v. The old vhost may still be serving.", deploy.Name, newDomain, oldDomain, e))
				}
			} else {
				slog.Warn(fmt.Sprintf("Renamed git deploy '%s' to %s but its host was unreachable, so %s was not released: %v", deploy.Name, newDomain, oldDomain, aerr))
			}
		}
	}

	// Turning review off removes a control; it goes to the immutable audit
	// log (refuses UPDATE/DELETE). Both directions are recorded.
	if deploy.DeployProtected != cur.DeployProtected {
		verb, severity := "disabled", "warning"
		if deploy.DeployProtected {
			verb, severity = "enabled", "info"
		}
		SecurityHardeningAuditLog(ctx, st.DB, "git_deploy.protection_changed", &claims.Email, clientIP(r),
			rtGitDeploysPtr("git_deploy"), &deploy.Name, rtGitDeploysPtr("Deploy approval requirement "+verb),
			nil, severity, claims.KeyID)
	}

	// Switching protection OFF must resolve anything still waiting on it: a
	// stale pending row would sit one click from a production deploy under a
	// deployment the same screen calls unprotected. Resolved, not deleted —
	// 'cancelled' is distinct from a colleague's 'rejected'.
	if !deploy.DeployProtected {
		if _, err := execSQL(ctx, st.DB,
			"UPDATE deploy_approvals SET status = 'cancelled', resolved_at = NOW() "+
				"WHERE deploy_id = $1 AND status = 'pending'", id); err != nil {
			slog.Warn(fmt.Sprintf("Failed to cancel pending approvals for %s: %v", id, err))
		}
	}

	rtGitDeploysRevealSecrets(st, &deploy)
	writeJSON(w, http.StatusOK, deploy)
	return nil
}

// DELETE /api/git-deploys/{id} — Remove a git deploy and its container.
func rtGitDeploysRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	row, err := queryOpt[Tup3[string, *string, uuid.UUID]](ctx, st.DB,
		"SELECT name, domain, server_id FROM git_deploys WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("remove git_deploys", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Git deploy not found")
	}
	name, domain, serverID := row.A, row.B, row.C

	// WHICH HOST comes from the row, not the caller's X-Server-Id. `name` is
	// unique only PER SERVER while the agent's checkout path is keyed by name
	// alone, so the wrong box finds the same-named neighbour and acts on IT —
	// `/git/cleanup` deletes container, image, vhost, cert and checkout. The
	// calls below are checked and this refuses rather than deleting records
	// for containers the server did not confirm it removed. An unreachable
	// host REFUSES; the fallback to this box was the defect.
	agent, err := rtGitDeploysRowAgent(ctx, st, serverID, domain, name)
	if err != nil {
		return err
	}

	// Tear previews down while the rows that name them still exist (the FK
	// cascade below removes them, after which nothing knows they exist).
	previews, _ := queryAll[Tup3[string, *string, int32]](ctx, st.DB,
		"SELECT container_name, domain, host_port FROM git_previews WHERE git_deploy_id = $1", id)
	standing := []string{}
	for _, p := range previews {
		if _, e := agent.Post(ctx, "/git/cleanup", rtGitDeploysPreviewCleanupBody(p.A, p.B, &p.C)); e != nil {
			slog.Warn(fmt.Sprintf("Failed to tear down preview %s of git deploy %s: %v", p.A, name, e))
			standing = append(standing, p.A)
		}
	}
	if len(previews) > 0 && len(standing) == 0 {
		slog.Info(fmt.Sprintf("Removed %d preview container(s) alongside git deploy %s", len(previews), name))
	}

	// The deployment's own teardown — checked too; discarding it was the same
	// defect as the loop above.
	if _, e := agent.Post(ctx, "/git/cleanup", map[string]any{"name": name, "scope": "deploy"}); e != nil {
		slog.Warn(fmt.Sprintf("Failed to tear down git deploy %s: %v", name, e))
		standing = append(standing, name)
	}

	// REFUSE, and name what is still up. Retryable by construction:
	// `/git/cleanup` answers Ok for a container already gone.
	if len(standing) > 0 {
		return apiErr(http.StatusConflict, fmt.Sprintf(
			"The server did not confirm teardown of %s. Nothing was deleted — these "+
				"records are the only thing that can still find those containers, their "+
				"ports and their vhosts. Retry once the server answers.",
			strings.Join(standing, ", ")))
	}

	// CASCADE deletes history.
	if _, err := execSQL(ctx, st.DB, "DELETE FROM git_deploys WHERE id = $1", id); err != nil {
		return internalError("remove git_deploys", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "git_deploy.remove",
		rtGitDeploysPtr("git_deploy"), &name, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "git_deploy.remove", &claims.Email, ip,
		rtGitDeploysPtr("git_deploy"), &name, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// POST /api/git-deploys/{id}/deploy — Trigger a build+deploy (async with SSE progress).
func rtGitDeploysDeploy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}

	// Block deploys during an active critical/major incident.
	if n, _ := queryScalar[int64](ctx, st.DB, rtGitDeploysActiveIncidentsSQL); n > 0 {
		return apiErr(http.StatusConflict, "Deploy blocked: active critical/major incident in progress. Resolve the incident first.")
	}

	config, err := rtGitDeploysLoadOwned(ctx, st, id, claims.Sub, "deploy")
	if err != nil {
		return err
	}

	// Protected deploy: require approval from another admin. One pending
	// request per deployment, not per click — the conflict clause lands on a
	// partial unique index, so the collapse is atomic and rows-affected
	// honestly answers "did I file one, or was one already waiting?".
	if config.DeployProtected {
		n, err := execSQL(ctx, st.DB,
			"INSERT INTO deploy_approvals (deploy_id, requested_by) VALUES ($1, $2) "+
				"ON CONFLICT DO NOTHING", id, claims.Sub)
		if err != nil {
			return internalError("deploy", err)
		}
		filed := n > 0
		// Only a NEW request is worth waking every administrator for.
		message := "This deployment already has a request waiting in Pending Approvals; another admin has not resolved it yet."
		if filed {
			NotificationsNotifyPanel(ctx, st.DB, nil, "Deploy approval needed",
				fmt.Sprintf("Deploy to %s requires approval", config.Name),
				"warning", "deploy", rtGitDeploysPtr("/git-deploys"))
			message = "Deploy requires approval from another admin — the request is now waiting in Pending Approvals."
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending_approval", "message": message})
		return nil
	}

	// Host from the row (see remove). Resolved HERE: an unreachable host must
	// not stop a protected deploy being QUEUED (above, no agent), and must not
	// come after the lock, which would strand 'building' for 30 minutes.
	agent, err := rtGitDeploysRowAgent(ctx, st, config.ServerID, config.Domain, config.Name)
	if err != nil {
		return err
	}

	// A DB error is a 500, NOT mistaken for "already in progress".
	n, err := execSQL(ctx, st.DB, rtGitDeploysLockSQL, id)
	if err != nil {
		return internalError("deploy lock", err)
	}
	if n == 0 {
		return apiErr(http.StatusConflict, "Deploy already in progress")
	}

	deployID := uuid.New()
	st.ProvisionLogs.Register(deployID, claims.Sub, 32)
	rtGitDeploysSpawnDeployTask(st, agent, deployID, *config, claims.Sub, claims.Email, "manual")

	writeJSON(w, http.StatusAccepted, map[string]any{"deploy_id": deployID, "message": "Deployment started"})
	return nil
}

// GET /api/git-deploys/deploy/{deploy_id}/log — SSE stream of deploy progress.
func rtGitDeploysDeployLog(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	deployID, err := pathUUID(r, "deploy_id")
	if err != nil {
		return err
	}
	// Absence from the owner map is a refusal, not a pass — the old
	// fall-through streamed other features' logs to any signed-in account.
	snapshot, ch, unsub, err := st.ProvisionLogs.Open(deployID, claims.Sub, "No active deploy")
	if err != nil {
		return err
	}
	defer unsub()
	rtGitDeploysServeSSE(st, w, r, snapshot, ch)
	return nil
}

// rtGitDeploysServeSSE is axum's Sse + KeepAlive(15s, "ping"): history first,
// then live steps until the channel closes (the log was removed). Also races
// the panel's shutdown signal — a deploy can run past the graceful drain.
func rtGitDeploysServeSSE(st *AppState, w http.ResponseWriter, r *http.Request, snapshot []ProvisionStep, ch <-chan ProvisionStep) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	send := func(s string) bool {
		if _, err := io.WriteString(w, s); err != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}
	event := func(step ProvisionStep) bool {
		b, err := json.Marshal(step)
		if err != nil {
			return true
		}
		return send("data: " + string(b) + "\n\n")
	}
	for _, s := range snapshot {
		if !event(s) {
			return
		}
	}
	if flusher != nil {
		flusher.Flush()
	}
	var shutdown <-chan struct{}
	if st.Shutdown != nil {
		shutdown = st.Shutdown.Done()
	}
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case s, ok := <-ch:
			if !ok || !event(s) {
				return
			}
		case <-ping.C:
			if !send(":ping\n\n") {
				return
			}
		case <-r.Context().Done():
			return
		case <-shutdown:
			return
		}
	}
}

// GET /api/git-deploys/{id}/history — List deploy history.
func rtGitDeploysHistory(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	exists, err := queryOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM git_deploys WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("history", err)
	}
	if exists == nil {
		return apiErr(http.StatusNotFound, "Git deploy not found")
	}
	entries, err := queryAll[rtGitDeploysGitDeployHistory](ctx, st.DB,
		"SELECT * FROM git_deploy_history WHERE git_deploy_id = $1 ORDER BY created_at DESC LIMIT 50", id)
	if err != nil {
		return internalError("history", err)
	}
	if entries == nil {
		entries = []rtGitDeploysGitDeployHistory{}
	}
	writeJSON(w, http.StatusOK, entries)
	return nil
}

// POST /api/git-deploys/{id}/history/{history_id}/explain — BYO-API-key AI
// root-cause diagnosis for one failed deploy. Off by default and per-request:
// never fires on its own, only when an operator with a configured provider
// clicks the button.
func rtGitDeploysExplainHistory(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	historyID, err := pathUUID(r, "history_id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	deploy, err := queryOpt[Tup2[uuid.UUID, string]](ctx, st.DB, "SELECT id, name FROM git_deploys WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("explain_history: load deploy", err)
	}
	if deploy == nil {
		return apiErr(http.StatusNotFound, "Git deploy not found")
	}
	entry, err := queryOpt[rtGitDeploysGitDeployHistory](ctx, st.DB, "SELECT * FROM git_deploy_history WHERE id = $1 AND git_deploy_id = $2", historyID, id)
	if err != nil {
		return internalError("explain_history: load history entry", err)
	}
	if entry == nil {
		return apiErr(http.StatusNotFound, "Deploy history entry not found")
	}
	if entry.Status != "failed" {
		return apiErr(http.StatusBadRequest, "Only failed deploys can be explained")
	}
	if entry.Output == nil || strings.TrimSpace(*entry.Output) == "" {
		return apiErr(http.StatusBadRequest, "This deploy has no captured output to diagnose")
	}
	config, err := AiDiagnosisLoadConfig(ctx, st.DB, st.Config.JWTSecret)
	if err != nil {
		return err
	}
	if config == nil {
		return apiErr(http.StatusBadRequest, "AI diagnosis is not configured. Set a provider and API key in Settings → Services.")
	}
	fc := AiDiagnosisFailureContext{
		SiteName:   deploy.B,
		CommitHash: entry.CommitHash,
		ImageTag:   entry.ImageTag,
		Output:     *entry.Output,
	}
	if entry.CommitMessage != nil {
		fc.CommitMessage = *entry.CommitMessage
	}
	explanation, err := AiDiagnosisExplainFailure(ctx, config, &fc)
	if err != nil {
		return err
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "git_deploy.ai_explain",
		rtGitDeploysPtr("git_deploy"), &fc.SiteName,
		rtGitDeploysPtr(fmt.Sprintf("history=%s provider=%s", historyID, config.Provider)), nil, claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"explanation": explanation, "provider": config.Provider})
	return nil
}

// rtGitDeploysEmitter returns the provision-log emit closure for one deploy.
func rtGitDeploysEmitter(pl *ProvisionLogs, id uuid.UUID) func(step, label, status string, msg *string) {
	return func(step, label, status string, msg *string) {
		pl.Emit(id, ProvisionStep{Step: step, Label: label, Status: status, Message: msg})
	}
}

func rtGitDeploysMarkFailed(ctx context.Context, db *pgxpool.Pool, id uuid.UUID) {
	if _, err := execSQL(ctx, db, "UPDATE git_deploys SET status = 'failed', updated_at = NOW() WHERE id = $1", id); err != nil {
		slog.Warn(fmt.Sprintf("Failed to update git deploy status: %v", err))
	}
}

func rtGitDeploysElapsedMs(started time.Time) int32 { return int32(time.Since(started).Milliseconds()) }

func rtGitDeploysShort(s string) string { return s[:min(7, len(s))] }

// POST /api/git-deploys/{id}/rollback/{history_id} — Rollback to a previous image.
func rtGitDeploysRollback(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	historyID, err := pathUUID(r, "history_id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	config, err := rtGitDeploysLoadOwned(ctx, st, id, claims.Sub, "rollback")
	if err != nil {
		return err
	}
	hist, err := queryOpt[rtGitDeploysGitDeployHistory](ctx, st.DB, "SELECT * FROM git_deploy_history WHERE id = $1 AND git_deploy_id = $2", historyID, id)
	if err != nil {
		return internalError("rollback", err)
	}
	if hist == nil {
		return apiErr(http.StatusNotFound, "History entry not found")
	}

	// Host from the row: hist.image_tag names an image in THIS server's local
	// store — pointed elsewhere it fails, or starts a same-tagged neighbour
	// image under the neighbour's name. Resolved before the lock so an
	// unreachable host cannot strand 'building'.
	agent, err := rtGitDeploysRowAgent(ctx, st, config.ServerID, config.Domain, config.Name)
	if err != nil {
		return err
	}

	// The same lock the other build doors take: this one used to write the
	// status unconditionally, so a rollback could start on top of a build.
	n, err := execSQL(ctx, st.DB, rtGitDeploysLockSQL, id)
	if err != nil {
		return internalError("rollback lock", err)
	}
	if n == 0 {
		return apiErr(http.StatusConflict, "A deploy or rollback is already in progress")
	}

	deployID := uuid.New()
	st.ProvisionLogs.Register(deployID, claims.Sub, 32)

	db, logs := st.DB, st.ProvisionLogs
	userID, email, keyID := claims.Sub, claims.Email, claims.KeyID
	cfg := *config
	rollbackImage, rollbackCommit := hist.ImageTag, hist.CommitHash

	go func() {
		ctx := context.Background()
		started := time.Now()
		emit := rtGitDeploysEmitter(logs, deployID)

		// Skip clone+build — straight to deploy with the historical image.
		emit("deploy", "Rolling back container", "in_progress", nil)

		mode := rtStacksEffectiveTlsMode(cfg.TlsMode, cfg.SslEmail)
		// An agent too old to honour tls_mode/tls_certificate drops both and
		// infers the mode from ssl_email — withheld in provided mode — so it
		// would roll this deploy back onto plain HTTP with no warning.
		if mode == "provided" {
			if e := rtTlsCertificatesRequireAgentAtLeast(ctx, agent, rtTlsCertificatesProvidedTlsMinAgent, "Serving a registered certificate"); e != nil {
				msg := rtGitDeploysAPIErrorMessage(e, "request refused")
				emit("deploy", "Rolling back container", "error", &msg)
				emit("complete", "Rollback failed", "error", nil)
				if _, dbErr := execSQL(ctx, db,
					"INSERT INTO git_deploy_history (git_deploy_id, commit_hash, image_tag, status, output, triggered_by, duration_ms) "+
						"VALUES ($1, $2, $3, 'failed', $4, 'rollback', $5)",
					id, rollbackCommit, rollbackImage, msg, rtGitDeploysElapsedMs(started)); dbErr != nil {
					slog.Warn(fmt.Sprintf("Failed to record git deploy rollback history: %v", dbErr))
				}
				rtGitDeploysMarkFailed(ctx, db, id)
				slog.Error(fmt.Sprintf("Git deploy rollback refused: %s: %s", cfg.Name, msg))
				NotificationsNotifyPanel(ctx, db, &userID, "Rollback failed: "+cfg.Name, msg, "critical", "deploy", rtGitDeploysPtr("/git-deploys"))
				logs.Remove(deployID)
				return
			}
		}

		result, e := agent.PostLong(ctx, "/git/deploy", rtGitDeploysConfigDeployBody(&cfg, rollbackImage, mode), 120)
		if e == nil {
			if bg, _ := jsonBool(jsonGet(result, "blue_green")); bg {
				emit("deploy", "Rolling back container", "done", rtGitDeploysPtr("Zero-downtime swap"))
			} else {
				emit("deploy", "Rolling back container", "done", nil)
			}
			emit("complete", "Rollback complete", "done", nil)

			containerID, _ := jsonStr(jsonGet(result, "container_id"))
			if _, dbErr := execSQL(ctx, db,
				"INSERT INTO git_deploy_history (git_deploy_id, commit_hash, commit_message, image_tag, status, output, triggered_by, duration_ms) "+
					"VALUES ($1, $2, $3, $4, 'success', $5, 'rollback', $6)",
				id, rollbackCommit, "Rollback to "+rtGitDeploysShort(rollbackCommit), rollbackImage,
				"Rolled back to image "+rollbackImage, rtGitDeploysElapsedMs(started)); dbErr != nil {
				slog.Warn(fmt.Sprintf("Failed to record git deploy rollback history: %v", dbErr))
			}
			if _, dbErr := execSQL(ctx, db,
				"UPDATE git_deploys SET status = 'running', container_id = $1, image_tag = $2, last_deploy = NOW(), last_commit = $3, updated_at = NOW() WHERE id = $4",
				containerID, rollbackImage, rollbackCommit, id); dbErr != nil {
				slog.Warn(fmt.Sprintf("Failed to update git deploy status: %v", dbErr))
			}
			slog.Info(fmt.Sprintf("Git deploy rollback success: %s → %s", cfg.Name, rollbackImage))
			ActivityLogActivity(ctx, db, userID, email, "git_deploy.rollback",
				rtGitDeploysPtr("git_deploy"), &cfg.Name, &rollbackImage, nil, keyID)
			NotificationsNotifyPanel(ctx, db, &userID, "Rollback complete: "+cfg.Name,
				"Rolled back to "+rtGitDeploysShort(rollbackCommit), "info", "deploy", rtGitDeploysPtr("/git-deploys"))
		} else {
			msg := e.Error()
			emit("deploy", "Rolling back container", "error", &msg)
			emit("complete", "Rollback failed", "error", nil)
			if _, dbErr := execSQL(ctx, db,
				"INSERT INTO git_deploy_history (git_deploy_id, commit_hash, image_tag, status, output, triggered_by, duration_ms) "+
					"VALUES ($1, $2, $3, 'failed', $4, 'rollback', $5)",
				id, rollbackCommit, rollbackImage, msg, rtGitDeploysElapsedMs(started)); dbErr != nil {
				slog.Warn(fmt.Sprintf("Failed to record git deploy rollback history: %v", dbErr))
			}
			rtGitDeploysMarkFailed(ctx, db, id)
			slog.Error(fmt.Sprintf("Git deploy rollback failed: %s: %s", cfg.Name, msg))
			NotificationsNotifyPanel(ctx, db, &userID, "Rollback failed: "+cfg.Name, msg, "critical", "deploy", rtGitDeploysPtr("/git-deploys"))
		}

		time.Sleep(60 * time.Second)
		logs.Remove(deployID)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{"deploy_id": deployID, "message": "Rollback started"})
	return nil
}

// POST /api/git-deploys/{id}/keygen — Generate SSH deploy key.
func rtGitDeploysKeygen(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	row, err := queryOpt[Tup3[string, *string, uuid.UUID]](ctx, st.DB,
		"SELECT name, domain, server_id FROM git_deploys WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("keygen", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Git deploy not found")
	}
	// The key is minted on the machine that will USE it (host from the row):
	// a panel-host keypair never reaches the server that clones, and on a
	// name collision could overwrite the neighbour's key.
	agent, err := rtGitDeploysRowAgent(ctx, st, row.C, row.B, row.A)
	if err != nil {
		return err
	}
	result, err := agent.Post(ctx, "/git/keygen", map[string]any{"name": row.A})
	if err != nil {
		return agentError("Deploy key generation", err)
	}
	publicKey, _ := jsonStr(jsonGet(result, "public_key"))
	keyPath, _ := jsonStr(jsonGet(result, "key_path"))
	if _, err := execSQL(ctx, st.DB,
		"UPDATE git_deploys SET deploy_key_public = $1, deploy_key_path = $2, updated_at = NOW() WHERE id = $3",
		publicKey, keyPath, id); err != nil {
		return internalError("keygen", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"public_key": publicKey})
	return nil
}

// rtGitDeploysExpectedStopKey is the name the agent's container actually
// carries — the key container_expected_stops and the alert engine use. The
// stored name is BARE; the agent adds `dockpanel-git-` for the deploy scope
// (the one the lifecycle trio uses), so the prefix belongs HERE exactly once.
func rtGitDeploysExpectedStopKey(name string) string { return "dockpanel-git-" + name }

// rtGitDeploysLifecycle is the shared head of stop/start/restart/logs:
// owner-scoped row + the agent for the server it lives on. Host from the row:
// the trio addresses the container purely by name, unique only per server,
// so the switcher deciding the host would stop the panel host's same-named
// container and write 'stopped' onto the row of the one still running.
func rtGitDeploysLifecycle(st *AppState, r *http.Request, errCtx string) (*Claims, *rtGitDeploysGitDeploy, AgentHandle, error) {
	claims, err := st.authUser(r)
	if err != nil {
		return nil, nil, nil, err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return nil, nil, nil, err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return nil, nil, nil, err
	}
	config, err := rtGitDeploysLoadOwned(r.Context(), st, id, claims.Sub, errCtx)
	if err != nil {
		return nil, nil, nil, err
	}
	agent, err := rtGitDeploysRowAgent(r.Context(), st, config.ServerID, config.Domain, config.Name)
	if err != nil {
		return nil, nil, nil, err
	}
	return claims, config, agent, nil
}

func rtGitDeploysSetStatus(ctx context.Context, db *pgxpool.Pool, id uuid.UUID, status string) {
	q := "UPDATE git_deploys SET status = 'running', updated_at = NOW() WHERE id = $1"
	if status == "stopped" {
		q = "UPDATE git_deploys SET status = 'stopped', updated_at = NOW() WHERE id = $1"
	}
	if _, err := execSQL(ctx, db, q, id); err != nil {
		slog.Warn(fmt.Sprintf("Failed to update git deploy status: %v", err))
	}
}

// POST /api/git-deploys/{id}/stop
func rtGitDeploysStop(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, config, agent, err := rtGitDeploysLifecycle(st, r, "stop")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if _, err := agent.Post(ctx, "/git/stop", map[string]any{"name": config.Name}); err != nil {
		return agentError("Stop container", err)
	}
	// The FIFTH deliberate stop door. ⛔ Despite the v2.150.0 changelog the
	// auto-healer never restarted a git container: list_deployed_apps keeps
	// only containers with `dockpanel.app.template`, which a git container
	// lacks, so the healer and container_down alerting never see one
	// (v2.150.1 corrects the claim). This recording is INERT today and
	// clear_absent sweeps it next tick — kept deliberately (pinned by
	// expected-stop-pin-e2e.sh §E7) for the day a git container enters /apps.
	// Recorded only AFTER the agent call succeeds.
	containerName := rtGitDeploysExpectedStopKey(config.Name)
	ExpectedStopsRecord(ctx, st.DB, config.ServerID, containerName, ExpectedStopsReasonOperatorStop, &claims.Email)
	ExpectedStopsResolveOpenContainerDown(ctx, st.DB, config.ServerID, containerName)
	rtGitDeploysSetStatus(ctx, st.DB, config.ID, "stopped")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// POST /api/git-deploys/{id}/start
func rtGitDeploysStart(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, config, agent, err := rtGitDeploysLifecycle(st, r, "start")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if _, err := agent.Post(ctx, "/git/start", map[string]any{"name": config.Name}); err != nil {
		return agentError("Start container", err)
	}
	// Symmetry with stop: without it a start followed by a genuine crash
	// inside one poll window stays suppressed.
	ExpectedStopsClear(ctx, st.DB, config.ServerID, rtGitDeploysExpectedStopKey(config.Name))
	rtGitDeploysSetStatus(ctx, st.DB, config.ID, "running")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// POST /api/git-deploys/{id}/restart
func rtGitDeploysRestart(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, config, agent, err := rtGitDeploysLifecycle(st, r, "restart")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if _, err := agent.Post(ctx, "/git/restart", map[string]any{"name": config.Name}); err != nil {
		return agentError("Restart container", err)
	}
	rtGitDeploysSetStatus(ctx, st.DB, config.ID, "running")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// GET /api/git-deploys/{id}/logs — host from the row: asked of the wrong box
// it returns the same-named neighbour's stdout as if it were this one's.
func rtGitDeploysContainerLogs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, config, agent, err := rtGitDeploysLifecycle(st, r, "container logs")
	if err != nil {
		return err
	}
	result, err := agent.Post(r.Context(), "/git/logs", map[string]any{"name": config.Name})
	if err != nil {
		return agentError("Container logs", err)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

// POST /api/webhooks/git/{id}/{secret} — Webhook endpoint (no auth).
func rtGitDeploysWebhook(st *AppState, w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	secret := r.PathValue("secret")
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(rawBody) > maxJSONBody {
		return rejection(http.StatusRequestEntityTooLarge, "Failed to buffer the request body: length limit exceeded")
	}
	ctx := r.Context()

	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.Contains(contentType, "application/json") {
		return apiErr(http.StatusBadRequest, "Content-Type must be application/json")
	}

	// Rate limit: max WebhookAttemptLimit failed attempts per deploy per hour.
	st.WebhookMu.Lock()
	now := time.Now()
	entry, ok := st.WebhookAttempts[id]
	if !ok || now.Sub(entry.Start) >= time.Hour {
		entry = RateWindow{Count: 0, Start: now}
		st.WebhookAttempts[id] = entry
	}
	limited := entry.Count >= WebhookAttemptLimit
	st.WebhookMu.Unlock()
	if limited {
		return apiErr(http.StatusTooManyRequests, "Rate limit exceeded. Try again later.")
	}

	config, err := queryOpt[rtGitDeploysGitDeploy](ctx, st.DB, rtGitDeploysGitDeploySelect+" WHERE d.id = $1", id)
	if err != nil {
		return internalError("webhook", err)
	}
	if config == nil {
		return apiErr(http.StatusNotFound, "Invalid webhook")
	}

	stored := SecretsCryptoDecryptCredentialOrLegacy(config.WebhookSecret, st.Config.JWTSecret)
	// Constant-time secret comparison via SHA256 hash.
	provided, want := sha256.Sum256([]byte(secret)), sha256.Sum256([]byte(stored))
	if subtle.ConstantTimeCompare(provided[:], want[:]) != 1 {
		st.WebhookMu.Lock()
		now := time.Now()
		e, ok := st.WebhookAttempts[id]
		if !ok {
			e = RateWindow{Count: 0, Start: now}
		}
		if now.Sub(e.Start) >= time.Hour {
			e = RateWindow{Count: 1, Start: now}
		} else {
			e.Count++
		}
		st.WebhookAttempts[id] = e
		st.WebhookMu.Unlock()
		return apiErr(http.StatusNotFound, "Invalid webhook")
	}

	if !config.AutoDeploy {
		return apiErr(http.StatusBadRequest, "Auto-deploy is not enabled for this project")
	}

	if n, _ := queryScalar[int64](ctx, st.DB, rtGitDeploysActiveIncidentsSQL); n > 0 {
		slog.Warn(fmt.Sprintf("Deploy blocked for %s: active incident in progress", config.Name))
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Deploy skipped: active incident"})
		return nil
	}

	// Branch from the GitHub/GitLab push payload.
	payload := rtGitDeploysJSON(rawBody)
	pushBranch := ""
	if ref, ok := jsonStr(jsonGet(payload, "ref")); ok {
		if b, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
			pushBranch = b
		}
	}

	// A webhook has no authenticated caller and so no ServerScope — the ROW is
	// the authority. A push to a deployment on a remote server must not build,
	// replace containers and rewrite vhosts on the panel host.
	agent, err := st.Agents.ForServer(ctx, config.ServerID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Webhook deploy for %s refused: its server %s is unreachable (%v) — refusing to deploy on a different host", config.Name, config.ServerID, err))
		return apiErr(http.StatusBadGateway, "Deploy target server is unreachable")
	}

	// Branch deletion (GitHub sends after=0000... on delete).
	deleted, _ := jsonBool(jsonGet(payload, "deleted"))
	if !deleted {
		if after, ok := jsonStr(jsonGet(payload, "after")); ok && strings.Trim(after, "0") == "" {
			deleted = true
		}
	}
	if deleted {
		row, err := queryOpt[Tup4[uuid.UUID, string, *string, int32]](ctx, st.DB,
			"SELECT id, container_name, domain, host_port FROM git_previews WHERE git_deploy_id = $1 AND branch = $2",
			config.ID, pushBranch)
		if err != nil {
			slog.Warn(fmt.Sprintf("Failed to query git preview for cleanup: %v", err))
			row = nil
		}
		previewRetained := false
		if row != nil {
			// Reached with NO authentication, and a `deleted: true` payload
			// names the branch — the sharpest preview-teardown call site, the
			// one that most needs to address the preview's own space.
			if _, e := agent.Post(ctx, "/git/cleanup", rtGitDeploysPreviewCleanupBody(row.B, row.C, &row.D)); e == nil {
				if _, err := execSQL(ctx, st.DB, "DELETE FROM git_previews WHERE id = $1", row.A); err != nil {
					slog.Warn(fmt.Sprintf("Failed to delete preview record for %s: %v", row.B, err))
				}
				slog.Info("Cleaned up preview for deleted branch: " + pushBranch)
			} else {
				// KEEP THE ROW: it is the only record that this container,
				// port and vhost exist; retiring it hands the port to the next
				// push and hides the container from the sweep, the list and
				// Delete Preview. Deleting a branch is nobody's retryable
				// action, and on an install with preview_ttl_hours = 0 the
				// operator's button is the only way back.
				previewRetained = true
				slog.Warn(fmt.Sprintf("Failed to tear down preview %s for deleted branch %s: %v. Keeping the git_previews row so the cleanup sweep retries rather than orphaning the container.", row.B, pushBranch, e))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":               true,
			"action":           "branch_deleted",
			"branch":           pushBranch,
			"preview_retained": previewRetained,
		})
		return nil
	}

	if pushBranch != "" && pushBranch != config.Branch {
		// Preview deployment for non-configured branches. Report what actually
		// happened, still as a 200: the delivery itself succeeded and a
		// non-2xx would put GitHub into retry over a decision that will not
		// change on a retry.
		if reason := rtGitDeploysHandlePreviewDeploy(ctx, st, agent, config, pushBranch); reason != "" {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false,
				"message": fmt.Sprintf("No preview deploy for branch '%s': %s", pushBranch, reason)})
		} else {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true,
				"message": fmt.Sprintf("Preview deploy triggered for branch '%s'", pushBranch)})
		}
		return nil
	}

	n, err := execSQL(ctx, st.DB, rtGitDeploysLockSQL, id)
	if err != nil {
		return internalError("webhook deploy lock", err)
	}
	if n == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Deploy already in progress, skipping"})
		return nil
	}

	deployID := uuid.New()
	// No claims here — the log belongs to the git deploy's owner.
	st.ProvisionLogs.Register(deployID, config.UserID, 32)

	email := ""
	if e, err := queryScalarOpt[string](ctx, st.DB, "SELECT email FROM users WHERE id = $1", config.UserID); err != nil {
		slog.Warn(fmt.Sprintf("Failed to fetch user email for webhook deploy: %v", err))
	} else if e != nil {
		email = *e
	}

	rtGitDeploysSpawnDeployTask(st, agent, deployID, *config, config.UserID, email, "webhook")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Deploy triggered"})
	return nil
}

// rtGitDeploysHealthCheck verifies the deployed site responds (post-deploy).
func rtGitDeploysHealthCheck(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, domain, mode string) {
	time.Sleep(3 * time.Second)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(rtGitDeploysDeployURL(domain, mode))
	if err != nil {
		slog.Warn(fmt.Sprintf("Post-deploy health check FAILED for %s: %v", domain, err))
		NotificationsNotifyPanel(ctx, db, &userID,
			fmt.Sprintf("Deploy warning: %s unreachable", domain),
			fmt.Sprintf("Deploy succeeded but the site is not responding: %v", err),
			"warning", "deploy", rtGitDeploysPtr("/git-deploys"))
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		slog.Warn(fmt.Sprintf("Post-deploy health check FAILED for %s: HTTP %d", domain, resp.StatusCode))
		NotificationsNotifyPanel(ctx, db, &userID,
			fmt.Sprintf("Deploy warning: %s returning HTTP %d", domain, resp.StatusCode),
			fmt.Sprintf("Deploy succeeded but the site is returning HTTP %d. Check your application logs.", resp.StatusCode),
			"warning", "deploy", rtGitDeploysPtr("/git-deploys"))
	} else {
		slog.Info(fmt.Sprintf("Post-deploy health check OK for %s: HTTP %d", domain, resp.StatusCode))
	}
}

// rtGitDeploysActualMode prefers what the agent actually served over what was
// requested. A refused registered certificate is not a failed deploy (the
// container runs) but IS the outage this feature exists to prevent if nobody
// notices, so it is surfaced as its own warning; every https-vs-http decision
// afterwards resolves through deployURL fed THIS mode.
func rtGitDeploysActualMode(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, result any, mode, name, logPrefix string) string {
	if refused, ok := jsonBool(jsonGet(result, "tls_refused")); ok && refused {
		reason, ok := jsonStr(jsonGet(result, "proxy_warning"))
		if !ok {
			reason = "the agent did not report an HTTPS vhost for the domain"
		}
		slog.Warn(fmt.Sprintf("%s %s: registered certificate not applied: %s", logPrefix, name, reason))
		NotificationsNotifyPanel(ctx, db, &userID,
			fmt.Sprintf("Deploy warning: %s certificate not applied", name),
			reason, "warning", "deploy", rtGitDeploysPtr("/git-deploys"))
		return "none"
	}
	if ssl, ok := jsonBool(jsonGet(result, "ssl")); ok && !ssl {
		return "none"
	}
	return mode
}

// rtGitDeploysSpawnDeployTask spawns the background clone → build → deploy.
func rtGitDeploysSpawnDeployTask(st *AppState, agent AgentHandle, deployID uuid.UUID, config rtGitDeploysGitDeploy, userID uuid.UUID, email, triggered string) {
	logs, db := st.ProvisionLogs, st.DB
	deployName, gitDeployID := config.Name, config.ID

	go func() {
		ctx := context.Background()
		started := time.Now()
		mode := rtStacksEffectiveTlsMode(config.TlsMode, config.SslEmail)
		emit := rtGitDeploysEmitter(logs, deployID)
		finish := func() {
			time.Sleep(60 * time.Second)
			logs.Remove(deployID)
		}
		var domainURL *string
		if config.Domain != nil {
			domainURL = rtGitDeploysPtr(rtGitDeploysDeployURL(*config.Domain, mode))
		}

		// GitHub pending status.
		if config.GithubToken != nil && *config.GithubToken != "" {
			go rtGitDeploysSetGithubStatus(*config.GithubToken, config.RepoURL, "HEAD", "pending", domainURL)
		}

		// Pre-deploy backup (best-effort, never blocks the deploy).
		if config.Domain != nil {
			emit("backup", "Pre-deploy backup", "in_progress", nil)
			_, _ = agent.Post(ctx, fmt.Sprintf("/backups/%s/create", *config.Domain), map[string]any{"reason": "pre-deploy"})
			emit("backup", "Pre-deploy backup", "done", nil)
			slog.Info("Pre-deploy backup requested for " + *config.Domain)
		}

		cloneBody := map[string]any{"name": config.Name, "repo_url": config.RepoURL, "branch": config.Branch}
		if config.DeployKeyPath != nil {
			cloneBody["key_path"] = *config.DeployKeyPath
		}

		// Step 1: Clone.
		emit("clone", "Cloning repository", "in_progress", nil)
		cloneResult, e := agent.PostLong(ctx, "/git/clone", cloneBody, 300)
		if e != nil {
			msg := e.Error()
			emit("clone", "Cloning repository", "error", &msg)
			emit("complete", "Deploy failed", "error", nil)
			if _, dbErr := execSQL(ctx, db,
				"INSERT INTO git_deploy_history (git_deploy_id, commit_hash, image_tag, status, output, triggered_by, duration_ms) "+
					"VALUES ($1, 'unknown', '', 'failed', $2, $3, $4)",
				gitDeployID, "Clone failed: "+msg, triggered, rtGitDeploysElapsedMs(started)); dbErr != nil {
				slog.Warn(fmt.Sprintf("Failed to record git deploy history: %v", dbErr))
			}
			rtGitDeploysMarkFailed(ctx, db, gitDeployID)
			slog.Error(fmt.Sprintf("Git deploy clone failed: %s: %s", deployName, msg))
			finish()
			return
		}
		emit("clone", "Cloning repository", "done", nil)
		commitHash, ok := jsonStr(jsonGet(cloneResult, "commit_hash"))
		if !ok {
			commitHash = "unknown"
		}
		var commitMessage *string
		if m, ok := jsonStr(jsonGet(cloneResult, "commit_message")); ok {
			commitMessage = &m
		}
		commitMessageStr := ""
		if commitMessage != nil {
			commitMessageStr = *commitMessage
		}

		// docker-compose.yml found → compose deployment path.
		composeResult, cerr := agent.Post(ctx, "/git/compose-check", map[string]any{"name": config.Name, "build_context": config.BuildContext})
		if cerr != nil {
			composeResult = nil
		}
		if isCompose, _ := jsonBool(jsonGet(composeResult, "found")); isCompose {
			emit("compose", "Deploying with Docker Compose", "in_progress", nil)
			yaml, _ := jsonStr(jsonGet(composeResult, "content"))

			if reason := rtGitDeploysComposeDeployRefusal(ctx, db, agent, config.ServerID, config.UserID, yaml); reason != "" {
				emit("compose", "Docker Compose refused", "error", &reason)
				slog.Warn(fmt.Sprintf("Git deploy %s: compose refused: %s", deployName, reason))
				rtGitDeploysRecordFailedHistory(ctx, db, gitDeployID, commitHash, commitMessageStr, reason, triggered)
				rtGitDeploysMarkFailed(ctx, db, gitDeployID)
				logs.Remove(deployID)
				return
			}

			if cerr := rtGitDeploysComposeDeploy(ctx, agent, yaml, config.ID); cerr == "" {
				emit("compose", "Docker Compose deployed", "done", nil)
				emit("complete", "Deploy complete (Compose)", "done", nil)
				if _, dbErr := execSQL(ctx, db, "INSERT INTO git_deploy_history (git_deploy_id, commit_hash, commit_message, image_tag, status, output, triggered_by, duration_ms) VALUES ($1, $2, $3, 'compose', 'success', 'Deployed via Docker Compose', $4, $5)",
					gitDeployID, commitHash, commitMessage, triggered, rtGitDeploysElapsedMs(started)); dbErr != nil {
					slog.Warn(fmt.Sprintf("Failed to record git deploy history: %v", dbErr))
				}
				if _, dbErr := execSQL(ctx, db, "UPDATE git_deploys SET status = 'running', build_method = 'compose', last_deploy = NOW(), last_commit = $1, updated_at = NOW() WHERE id = $2",
					commitHash, gitDeployID); dbErr != nil {
					slog.Warn(fmt.Sprintf("Failed to update git deploy status: %v", dbErr))
				}
				slog.Info(fmt.Sprintf("Git deploy (compose) success: %s (%s)", deployName, commitHash))
				ActivityLogActivity(ctx, db, userID, email, "git_deploy.compose", rtGitDeploysPtr("git_deploy"), &deployName, &commitHash, rtGitDeploysPtr("success"), nil)
			} else {
				emit("compose", "Docker Compose deploy failed", "error", &cerr)
				emit("complete", "Deploy failed", "error", nil)
				if _, dbErr := execSQL(ctx, db, "INSERT INTO git_deploy_history (git_deploy_id, commit_hash, commit_message, image_tag, status, output, triggered_by, duration_ms) VALUES ($1, $2, $3, '', 'failed', $4, $5, $6)",
					gitDeployID, commitHash, commitMessage, "Compose failed: "+cerr, triggered, rtGitDeploysElapsedMs(started)); dbErr != nil {
					slog.Warn(fmt.Sprintf("Failed to record git deploy history: %v", dbErr))
				}
				rtGitDeploysMarkFailed(ctx, db, gitDeployID)
			}
			finish()
			return // Skip single-container deployment path
		}

		// A pre-build command skips Nixpacks entirely and goes straight to
		// auto-detect, so the command always gets spliced into the Dockerfile
		// DockPanel controls — never silently discarded on a Nixpacks-success
		// path the way the old host-exec pre-build-hook was.
		var preBuildCmd *string
		if config.PreBuildCmd != nil && strings.TrimSpace(*config.PreBuildCmd) != "" {
			preBuildCmd = config.PreBuildCmd
		}
		if preBuildCmd != nil {
			if e := rtTlsCertificatesRequireAgentAtLeast(ctx, agent, rtGitDeploysPreBuildSpliceMinAgent,
				"Pre-build commands (now built into the Docker image, not run on the host)"); e != nil {
				msg := rtGitDeploysAPIErrorMessage(e, "request refused")
				emit("detect", "Detecting build method", "error", &msg)
				emit("complete", "Deploy failed", "error", nil)
				rtGitDeploysRecordFailedHistory(ctx, db, gitDeployID, commitHash, commitMessageStr, msg, triggered)
				rtGitDeploysMarkFailed(ctx, db, gitDeployID)
				slog.Error(fmt.Sprintf("Git deploy refused: %s: %s", deployName, msg))
				finish()
				return
			}
		}

		// Nixpacks first (skipped for a pre-build command), then auto-detect.
		var nixpacksImage *string
		emit("detect", "Detecting build method", "in_progress", nil)
		var nixpacksResult any
		nixpacksOK := false
		if preBuildCmd == nil {
			if res, e := agent.PostLong(ctx, "/git/nixpacks-build", map[string]any{
				"name":          config.Name,
				"commit_hash":   commitHash,
				"build_context": config.BuildContext,
				"env_vars":      config.EnvVars,
			}, 660); e == nil {
				nixpacksResult, nixpacksOK = res, true
			}
		}
		if nixpacksOK {
			if s, ok := jsonStr(jsonGet(nixpacksResult, "image_tag")); ok {
				nixpacksImage = &s
			}
			emit("detect", "Built with Nixpacks", "done", nil)
			if _, dbErr := execSQL(ctx, db, "UPDATE git_deploys SET build_method = 'nixpacks', updated_at = NOW() WHERE id = $1", gitDeployID); dbErr != nil {
				slog.Warn(fmt.Sprintf("Failed to update git deploy build method: %v", dbErr))
			}
		} else {
			result, e := agent.Post(ctx, "/git/auto-detect", map[string]any{
				"name": config.Name, "dockerfile": config.Dockerfile, "build_context": config.BuildContext,
				"pre_build_cmd": preBuildCmd,
			})
			if e != nil {
				msg := e.Error()
				emit("detect", "No Dockerfile and auto-detect failed", "error", &msg)
				emit("complete", "Deploy failed", "error", nil)
				if _, dbErr := execSQL(ctx, db, "INSERT INTO git_deploy_history (git_deploy_id, commit_hash, commit_message, image_tag, status, output, triggered_by, duration_ms) VALUES ($1, $2, $3, '', 'failed', $4, $5, $6)",
					gitDeployID, commitHash, commitMessage, "Auto-detect failed: "+msg, triggered, rtGitDeploysElapsedMs(started)); dbErr != nil {
					slog.Warn(fmt.Sprintf("Failed to record git deploy history: %v", dbErr))
				}
				rtGitDeploysMarkFailed(ctx, db, gitDeployID)
				finish()
				return
			}
			if auto, _ := jsonBool(jsonGet(result, "auto_generated")); auto {
				emit("detect", "Auto-detected project type", "done", nil)
				if _, dbErr := execSQL(ctx, db, "UPDATE git_deploys SET build_method = 'auto-detect', updated_at = NOW() WHERE id = $1", gitDeployID); dbErr != nil {
					slog.Warn(fmt.Sprintf("Failed to update git deploy build method: %v", dbErr))
				}
			} else {
				emit("detect", "Using existing Dockerfile", "done", nil)
				if _, dbErr := execSQL(ctx, db, "UPDATE git_deploys SET build_method = 'dockerfile', updated_at = NOW() WHERE id = $1", gitDeployID); dbErr != nil {
					slog.Warn(fmt.Sprintf("Failed to update git deploy build method: %v", dbErr))
				}
			}
			if preBuildCmd != nil {
				if applied, _ := jsonBool(jsonGet(result, "pre_build_applied")); applied {
					emit("pre_build", "Pre-build command folded into Docker build", "done", nil)
				} else {
					var note *string
					if s, ok := jsonStr(jsonGet(result, "pre_build_note")); ok {
						note = &s
					}
					emit("pre_build", "Pre-build command not applied", "error", note)
				}
			}
		}

		// Step 2: Build (skipped if Nixpacks already built the image).
		var imageTag string
		if nixpacksImage != nil {
			emit("build", "Image built by Nixpacks", "done", nil)
			imageTag = *nixpacksImage
		} else {
			emit("build", "Building Docker image", "in_progress", nil)
			result, e := agent.PostLong(ctx, "/git/build", map[string]any{
				"name":          config.Name,
				"dockerfile":    config.Dockerfile,
				"commit_hash":   commitHash,
				"build_args":    config.BuildArgs,
				"build_context": config.BuildContext,
			}, 660)
			if e != nil {
				msg := e.Error()
				emit("build", "Building Docker image", "error", &msg)
				emit("complete", "Deploy failed", "error", nil)
				if _, dbErr := execSQL(ctx, db,
					"INSERT INTO git_deploy_history (git_deploy_id, commit_hash, commit_message, image_tag, status, output, triggered_by, duration_ms) "+
						"VALUES ($1, $2, $3, $4, 'failed', $5, $6, $7)",
					gitDeployID, commitHash, commitMessage, "", "Build failed: "+msg, triggered, rtGitDeploysElapsedMs(started)); dbErr != nil {
					slog.Warn(fmt.Sprintf("Failed to record git deploy history: %v", dbErr))
				}
				rtGitDeploysMarkFailed(ctx, db, gitDeployID)
				slog.Error(fmt.Sprintf("Git deploy build failed: %s: %s", deployName, msg))
				finish()
				return
			}
			emit("build", "Building Docker image", "done", nil)
			if s, ok := jsonStr(jsonGet(result, "image_tag")); ok {
				imageTag = s
			} else {
				imageTag = "unknown"
			}
		}

		// Step 3: Deploy.
		emit("deploy", "Deploying container", "in_progress", nil)

		// An old agent drops tls_mode/tls_certificate and infers the mode from
		// the withheld ssl_email — plain HTTP with no warning. Refused here.
		if mode == "provided" {
			if e := rtTlsCertificatesRequireAgentAtLeast(ctx, agent, rtTlsCertificatesProvidedTlsMinAgent, "Serving a registered certificate"); e != nil {
				msg := rtGitDeploysAPIErrorMessage(e, "request refused")
				emit("deploy", "Deploying container", "error", &msg)
				emit("complete", "Deploy failed", "error", nil)
				rtGitDeploysRecordFailedHistory(ctx, db, gitDeployID, commitHash, commitMessageStr, msg, triggered)
				rtGitDeploysMarkFailed(ctx, db, gitDeployID)
				slog.Error(fmt.Sprintf("Git deploy refused: %s: %s", deployName, msg))
				finish()
				return
			}
		}

		result, e := agent.PostLong(ctx, "/git/deploy", rtGitDeploysConfigDeployBody(&config, imageTag, mode), 120)
		if e != nil {
			msg := e.Error()
			emit("deploy", "Deploying container", "error", &msg)
			emit("complete", "Deploy failed", "error", nil)
			if _, dbErr := execSQL(ctx, db,
				"INSERT INTO git_deploy_history (git_deploy_id, commit_hash, commit_message, image_tag, status, output, triggered_by, duration_ms) "+
					"VALUES ($1, $2, $3, $4, 'failed', $5, $6, $7)",
				gitDeployID, commitHash, commitMessage, imageTag, "Deploy failed: "+msg, triggered, rtGitDeploysElapsedMs(started)); dbErr != nil {
				slog.Warn(fmt.Sprintf("Failed to record git deploy history: %v", dbErr))
			}
			rtGitDeploysMarkFailed(ctx, db, gitDeployID)
			slog.Error(fmt.Sprintf("Git deploy failed: %s: %s", deployName, msg))
			ActivityLogActivity(ctx, db, userID, email, "git_deploy.deploy", rtGitDeploysPtr("git_deploy"), &deployName, &commitHash, rtGitDeploysPtr("failed"), nil)
			NotificationsNotifyPanel(ctx, db, &userID, "Deploy failed: "+deployName, msg, "critical", "deploy", rtGitDeploysPtr("/git-deploys"))

			if config.GithubToken != nil && *config.GithubToken != "" && commitHash != "unknown" {
				go rtGitDeploysSetGithubStatus(*config.GithubToken, config.RepoURL, commitHash, "failure", domainURL)
			}
			go func() {
				channels := NotificationsGetUserChannels(ctx, db, userID, nil)
				if channels == nil {
					return
				}
				subject := "Deploy FAILED: " + deployName
				message := fmt.Sprintf("Git deploy '%s' failed (commit: %s): %s", deployName, commitHash, msg)
				html := fmt.Sprintf("<div style=\"font-family:sans-serif\"><h2 style=\"color:#ef4444\">Deploy Failed</h2>"+
					"<p><strong>%s</strong> deployment failed.</p>"+
					"<p>Commit: <code>%s</code></p>"+
					"<p>Error: %s</p>"+
					"<p style=\"color:#6b7280;font-size:14px\">Time: %s</p></div>",
					deployName, commitHash, msg, time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
				NotificationsSendNotification(ctx, db, channels, subject, message, html)
			}()
			finish()
			return
		}

		blueGreen, _ := jsonBool(jsonGet(result, "blue_green"))
		if blueGreen {
			emit("deploy", "Deploying container", "done", rtGitDeploysPtr("Zero-downtime swap"))
		} else {
			emit("deploy", "Deploying container", "done", nil)
		}
		emit("complete", "Deploy complete", "done", nil)
		containerID, _ := jsonStr(jsonGet(result, "container_id"))
		duration := rtGitDeploysElapsedMs(started)
		actualMode := rtGitDeploysActualMode(ctx, db, userID, result, mode, deployName, "Git deploy")

		output := "Deployed successfully"
		if blueGreen {
			output = "Deployed with zero-downtime swap"
		}
		if _, dbErr := execSQL(ctx, db,
			"INSERT INTO git_deploy_history (git_deploy_id, commit_hash, commit_message, image_tag, status, output, triggered_by, duration_ms) "+
				"VALUES ($1, $2, $3, $4, 'success', $5, $6, $7)",
			gitDeployID, commitHash, commitMessage, imageTag, output, triggered, duration); dbErr != nil {
			slog.Warn(fmt.Sprintf("Failed to record git deploy history: %v", dbErr))
		}
		if _, dbErr := execSQL(ctx, db,
			"UPDATE git_deploys SET status = 'running', container_id = $1, image_tag = $2, last_deploy = NOW(), last_commit = $3, updated_at = NOW() WHERE id = $4",
			containerID, imageTag, commitHash, gitDeployID); dbErr != nil {
			slog.Warn(fmt.Sprintf("Failed to update git deploy status: %v", dbErr))
		}
		slog.Info(fmt.Sprintf("Git deploy success: %s (%s)", deployName, commitHash))
		ActivityLogActivity(ctx, db, userID, email, "git_deploy.deploy", rtGitDeploysPtr("git_deploy"), &deployName, &commitHash, rtGitDeploysPtr("success"), nil)
		NotificationsNotifyPanel(ctx, db, &userID, "Deploy complete: "+deployName, "Commit: "+commitHash, "info", "deploy", rtGitDeploysPtr("/git-deploys"))

		// Post-deploy hook.
		if config.PostDeployCmd != nil && strings.TrimSpace(*config.PostDeployCmd) != "" {
			emit("post_deploy", "Running post-deploy hook", "in_progress", nil)
			res, e := agent.PostLong(ctx, "/git/hook", map[string]any{"name": config.Name, "command": *config.PostDeployCmd}, 330)
			if e != nil {
				emit("post_deploy", "Post-deploy hook failed", "error", rtGitDeploysPtr(e.Error()))
			} else if ok, _ := jsonBool(jsonGet(res, "success")); ok {
				emit("post_deploy", "Post-deploy hook complete", "done", nil)
			} else {
				out, _ := jsonStr(jsonGet(res, "output"))
				emit("post_deploy", "Post-deploy hook failed", "error", &out)
			}
		}

		// Deploy notification.
		go func() {
			channels := NotificationsGetUserChannels(ctx, db, userID, nil)
			if channels == nil {
				return
			}
			subject := "Deploy successful: " + deployName
			message := fmt.Sprintf("Git deploy '%s' deployed successfully (commit: %s)", deployName, commitHash)
			html := fmt.Sprintf("<div style=\"font-family:sans-serif\"><h2 style=\"color:#22c55e\">Deploy Successful</h2>"+
				"<p><strong>%s</strong> deployed successfully.</p>"+
				"<p>Commit: <code>%s</code></p>"+
				"<p style=\"color:#6b7280;font-size:14px\">Time: %s</p></div>",
				deployName, commitHash, time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
			NotificationsSendNotification(ctx, db, channels, subject, message, html)
		}()

		// GitHub commit status — success.
		if config.GithubToken != nil && *config.GithubToken != "" && commitHash != "unknown" {
			var target *string
			if config.Domain != nil {
				target = rtGitDeploysPtr(rtGitDeploysDeployURL(*config.Domain, actualMode))
			}
			go rtGitDeploysSetGithubStatus(*config.GithubToken, config.RepoURL, commitHash, "success", target)
		}

		if config.Domain != nil {
			rtGitDeploysHealthCheck(ctx, db, userID, *config.Domain, actualMode)
		}

		// Auto-rollback monitor: watch the container for 2 minutes. The
		// rollback redeploys the app AS CONFIGURED (env, limits, TLS,
		// volumes) — it once rebuilt from four fields alone, so a crash
		// rollback came back unconfigured and unbounded (GH #94).
		go func() {
			for range 8 {
				time.Sleep(15 * time.Second)
				if _, e := agent.Post(ctx, "/git/logs", map[string]any{"name": config.Name, "lines": 1}); e == nil {
					continue // container is responding — alive
				}
				slog.Warn(fmt.Sprintf("Auto-rollback: container dockpanel-git-%s may have crashed, checking...", config.Name))
				prev, err := queryOpt[Tup2[string, string]](ctx, db,
					"SELECT image_tag, commit_hash FROM git_deploy_history "+
						"WHERE git_deploy_id = $1 AND status = 'success' AND image_tag != $2 "+
						"ORDER BY created_at DESC LIMIT 1",
					gitDeployID, imageTag)
				if err != nil {
					slog.Warn(fmt.Sprintf("Failed to fetch previous deploy for rollback: %v", err))
				}
				if prev != nil {
					prevImage, prevCommit := prev.A, prev.B
					slog.Warn(fmt.Sprintf("Auto-rollback: rolling back %s to %s", deployName, prevImage))
					if _, e := agent.PostLong(ctx, "/git/deploy", rtGitDeploysConfigDeployBody(&config, prevImage, mode), 120); e == nil {
						if _, dbErr := execSQL(ctx, db,
							"INSERT INTO git_deploy_history (git_deploy_id, commit_hash, image_tag, status, output, triggered_by) "+
								"VALUES ($1, $2, $3, 'success', 'Auto-rollback after container crash', 'auto-rollback')",
							gitDeployID, prevCommit, prevImage); dbErr != nil {
							slog.Warn(fmt.Sprintf("Failed to record git deploy auto-rollback history: %v", dbErr))
						}
						if _, dbErr := execSQL(ctx, db, "UPDATE git_deploys SET image_tag = $1, last_commit = $2, updated_at = NOW() WHERE id = $3",
							prevImage, prevCommit, gitDeployID); dbErr != nil {
							slog.Warn(fmt.Sprintf("Failed to update git deploy status: %v", dbErr))
						}
						if channels := NotificationsGetUserChannels(ctx, db, userID, nil); channels != nil {
							subject := "Auto-rollback: " + deployName
							message := fmt.Sprintf("Container '%s' crashed after deploy. Auto-rolled back to %s.", deployName, prevCommit)
							html := fmt.Sprintf("<div style=\"font-family:sans-serif\"><h2 style=\"color:#f59e0b\">Auto-Rollback</h2>"+
								"<p>Container <strong>%s</strong> crashed after deployment.</p>"+
								"<p>Automatically rolled back to commit <code>%s</code>.</p></div>", deployName, prevCommit)
							NotificationsSendNotification(ctx, db, channels, subject, message, html)
						}
						ActivityLogActivity(ctx, db, userID, email, "git_deploy.auto_rollback",
							rtGitDeploysPtr("git_deploy"), &deployName, &prevCommit, nil, nil)
						NotificationsNotifyPanel(ctx, db, &userID, "Auto-rollback: "+deployName,
							"Deploy failed, rolled back to previous version", "warning", "deploy", rtGitDeploysPtr("/git-deploys"))
						slog.Info(fmt.Sprintf("Auto-rollback complete: %s → %s", deployName, prevImage))
					}
				}
				return // stop monitoring after rollback
			}
			slog.Info(fmt.Sprintf("Auto-rollback monitor: %s healthy for 2 minutes, monitoring stopped", deployName))
		}()

		finish()
	}()
}

// rtGitDeploysComposeDeploy runs `/apps/compose/deploy` and reports the
// failure sentence, "" on success.
func rtGitDeploysComposeDeploy(ctx context.Context, agent AgentHandle, yaml string, stackID uuid.UUID) string {
	res, err := agent.PostLong(ctx, "/apps/compose/deploy", map[string]any{"yaml": yaml, "stack_id": stackID.String()}, 660)
	if err != nil {
		return err.Error()
	}
	return rtGitDeploysComposeOutcome(res)
}

// rtGitDeploysComposeOutcome answers "did this deploy happen?" from the
// agent's per-service report. deploy_compose reports each service INSIDE a
// 200, so taking the HTTP status as the answer wrote 'running' over a deploy
// in which nothing came up (the SECOND compose deploy collides with its own
// container names). Shares stacks::deployed_service_states so the two paths
// cannot drift. ⚠ total == 0 is NOT a failure: an empty report cannot tell
// "nothing came up" from "agent too old to say". "" = ok.
func rtGitDeploysComposeOutcome(deployResult any) string {
	running, total, errs := rtStacksDeployedServiceStates(deployResult)
	if total > 0 && running == 0 {
		detail := "the agent reported no reason"
		if len(errs) > 0 {
			detail = strings.Join(errs, " | ")
		}
		return "no service in the compose file stayed running — " + detail
	}
	return ""
}

// rtGitDeploysDroppedServiceRefusal refuses a compose file whose services
// name no image, rather than deploying the rest and calling that success: the
// compose engine drops every service it cannot resolve to a registry image,
// which in a repo with a Dockerfile is exactly the application. ⚠ Kept OUT of
// compose_deploy_refusal's body: the gate census in
// deploy-gate-coverage-pin-e2e.sh attributes a preflight_gate_image call to the
// nearest fn within 40 lines above it.
func rtGitDeploysDroppedServiceRefusal(yaml string) string {
	dropped := composeServicesWithoutImage(yaml)
	if len(dropped) == 0 {
		return ""
	}
	it, them := "they", "them"
	if len(dropped) == 1 {
		it, them = "it", "it"
	}
	return fmt.Sprintf("this repository's compose file gives no image for %s, and DockPanel's Compose support "+
		"runs registry images rather than building them — %s would be skipped and the deploy "+
		"would come up without %s. Either name an already-built image for each of them, or "+
		"remove the compose file: without it this deployment builds your Dockerfile and also "+
		"gets the domain, the certificate, zero-downtime swaps, preview environments and "+
		"rollback.", strings.Join(dropped, ", "), it, them)
}

// rtGitDeploysComposeDeployRefusal is everything a Compose document must
// satisfy before a git deploy hands it to an agent: the repo's own
// docker-compose.yml is a deploy door like any other (CVE threshold, image
// policy, validate_compose_yaml). Returns the sentence to report, "" = go —
// callers are background tasks with no error to propagate.
func rtGitDeploysComposeDeployRefusal(ctx context.Context, db *pgxpool.Pool, agent AgentHandle, serverID, userID uuid.UUID, yaml string) string {
	if msg := validateComposeYAML(yaml); msg != "" {
		return msg
	}
	if reason := rtGitDeploysDroppedServiceRefusal(yaml); reason != "" {
		return reason
	}
	images := composeImages(yaml)
	if err := rtDockerAppsEnforceAllowedImages(ctx, db, userID, images); err != nil {
		return rtGitDeploysAPIErrorMessage(err, "refused")
	}
	for _, image := range images {
		if err := rtImageScansPreflightGateImage(ctx, db, serverID, agent, image); err != nil {
			return rtGitDeploysAPIErrorMessage(err, "refused")
		}
	}
	return ""
}

// rtGitDeploysGithubTokenMask is the eight filled circles mask_github_token
// substitutes — named once so the mask and the guard cannot drift apart.
const rtGitDeploysGithubTokenMask = "●●●●●●●●"

// rtGitDeploysMaskRepoCredentials replaces credentials embedded in a repo
// URL's authority with a placeholder. The agent accepts
// `https://TOKEN@github.com/me/app.git` and nothing strips it; this stops the
// panel handing it to a reader who is not its owner (the approval list).
func rtGitDeploysMaskRepoCredentials(url string) string {
	// Split on the authority, not on the first '@': a path may contain one.
	scheme, rest, ok := strings.Cut(url, "://")
	if !ok {
		return url
	}
	end := strings.IndexByte(rest, '/')
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	at := strings.LastIndexByte(authority, '@')
	if at < 0 {
		return url
	}
	return scheme + "://•••" + authority[at:] + tail
}

// rtGitDeploysBlankToNone: the wire spells "not set" as "", this table NULL.
func rtGitDeploysBlankToNone(v *string) *string {
	if v == nil || strings.TrimSpace(*v) == "" {
		return nil
	}
	return v
}

// rtGitDeploysAPIErrorMessage is the human sentence out of an ApiError, for
// fire-and-forget tasks that cannot propagate it.
func rtGitDeploysAPIErrorMessage(err error, fallback string) string {
	var ae *ApiError
	if errors.As(err, &ae) {
		if m, ok := ae.Body.(map[string]any); ok {
			if s, ok := m["error"].(string); ok {
				return s
			}
		}
	}
	return fallback
}

// rtGitDeploysEncryptStoredToken encrypts a submitted GitHub token. nil passes
// through (update's COALESCE keeps the stored one). The mask sentinel ALSO
// maps to nil: a client submitting the form it was served sends the mask
// back, and storing it would replace a working token with eight circles
// (v2.48.3 shipped this class of bug once) — closed here by construction.
func rtGitDeploysEncryptStoredToken(submitted *string, jwtSecret string) (*string, error) {
	if submitted == nil || *submitted == "" || *submitted == rtGitDeploysGithubTokenMask {
		return nil, nil
	}
	enc, err := SecretsCryptoEncryptCredential(*submitted, jwtSecret)
	if err != nil {
		return nil, internalError("encrypt github token", err)
	}
	return &enc, nil
}

func rtGitDeploysMaskGithubToken(d *rtGitDeploysGitDeploy) {
	if d.GithubToken != nil && *d.GithubToken != "" {
		d.GithubToken = rtGitDeploysPtr(rtGitDeploysGithubTokenMask)
	}
}

// rtGitDeploysDeployURL is the URL a deploy's domain is actually reachable on,
// keyed on the EFFECTIVE mode — provided mode withholds ssl_email, so a scheme
// decision keyed on it would report provided as HTTP; assuming https
// everywhere made the health check call a plain-HTTP deploy unreachable.
func rtGitDeploysDeployURL(domain, tlsMode string) string {
	scheme := "http"
	if tlsMode == "acme" || tlsMode == "provided" {
		scheme = "https"
	}
	return scheme + "://" + domain
}

// rtGitDeploysSetGithubStatus sets a GitHub commit status. Takes the finished
// URL so every caller goes through deployURL. The token is encrypted at rest
// and this is the single place that opens it (the legacy fallback returns a
// pre-encryption plaintext token unchanged).
func rtGitDeploysSetGithubStatus(token, repoURL, sha, state string, targetURL *string) {
	token = SecretsCryptoDecryptCredentialFromEnv(token)
	owner, repo, ok := rtGitDeploysParseGithubRepo(repoURL)
	if !ok {
		return // Not a GitHub URL
	}
	target := ""
	if targetURL != nil {
		target = *targetURL
	}
	description := "Deploy status update"
	switch state {
	case "success":
		description = "Deployed successfully via DockPanel"
	case "failure":
		description = "Deploy failed"
	case "pending":
		description = "Deploying..."
	}
	body, _ := json.Marshal(map[string]any{
		"state": state, "target_url": target, "description": description, "context": "dockpanel/deploy",
	})
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://api.github.com/repos/%s/%s/statuses/%s", owner, repo, sha), bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "DockPanel")
	req.Header.Set("Content-Type", "application/json")
	if resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req); err == nil {
		resp.Body.Close()
	}
}

func rtGitDeploysParseGithubRepo(url string) (string, string, bool) {
	for _, prefix := range []string{"https://github.com/", "git@github.com:"} {
		if rest, ok := strings.CutPrefix(url, prefix); ok {
			clean := rest
			for strings.HasSuffix(clean, ".git") {
				clean = strings.TrimSuffix(clean, ".git")
			}
			if parts := strings.SplitN(clean, "/", 2); len(parts) == 2 {
				return parts[0], parts[1], true
			}
		}
	}
	return "", "", false
}

// rtGitDeploysTriggerDeployTask is a deploy from the scheduler (no SSE, no
// provision logs). Runs synchronously; ctx is detached so a cancelled caller
// cannot strand 'building' mid-deploy.
func rtGitDeploysTriggerDeployTask(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, gitDeployID, userID uuid.UUID, triggeredBy string) {
	ctx = context.WithoutCancel(ctx)
	if n, _ := queryScalar[int64](ctx, db, rtGitDeploysActiveIncidentsSQL); n > 0 {
		slog.Warn(fmt.Sprintf("Scheduled deploy blocked for %s: active incident in progress", gitDeployID))
		return
	}

	// Config FIRST — before the lock — so a fetch error (or a row deleted
	// since the scheduler listed it) cannot strand 'building'.
	config, err := queryOpt[rtGitDeploysGitDeploy](ctx, db, rtGitDeploysGitDeploySelect+" WHERE d.id = $1", gitDeployID)
	if err != nil || config == nil {
		return
	}
	mode := rtStacksEffectiveTlsMode(config.TlsMode, config.SslEmail)
	var domainURL *string
	if config.Domain != nil {
		domainURL = rtGitDeploysPtr(rtGitDeploysDeployURL(*config.Domain, mode))
	}

	// The agent for the server this deployment LIVES ON. It used to be the
	// local agent, decided before the row was read: with `name` unique only
	// per server and checkouts keyed by name, a member's cron deploy ran on
	// the panel host and built the WRONG repository into a same-named
	// checkout. Refuse rather than fall back — the fallback is the defect.
	agent, err := agents.ForServer(ctx, config.ServerID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Scheduled deploy skipped for %s (%s): its server %s is unreachable (%v) — NOT deploying. Refusing to act on a different host.", config.Name, gitDeployID, config.ServerID, err))
		return
	}

	email := ""
	if e, err := queryScalarOpt[string](ctx, db, "SELECT email FROM users WHERE id = $1", userID); err != nil {
		slog.Warn(fmt.Sprintf("DB error fetching user email for git deploy: %v", err))
	} else if e != nil {
		email = *e
	}

	// Lock AFTER the config fetch above.
	n, err := execSQL(ctx, db, rtGitDeploysLockSQL, gitDeployID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Scheduled deploy lock failed for %s: %v", gitDeployID, err))
		return
	}
	if n == 0 {
		slog.Warn(fmt.Sprintf("Scheduled deploy skipped for %s: deploy already in progress", gitDeployID))
		return
	}

	started := time.Now()
	hasToken := config.GithubToken != nil && *config.GithubToken != ""
	if hasToken {
		rtGitDeploysSetGithubStatus(*config.GithubToken, config.RepoURL, "HEAD", "pending", domainURL)
	}

	if config.Domain != nil {
		_, _ = agent.Post(ctx, fmt.Sprintf("/backups/%s/create", *config.Domain), map[string]any{"reason": "pre-deploy"})
		slog.Info("Pre-deploy backup requested for " + *config.Domain)
	}

	cloneBody := map[string]any{"name": config.Name, "repo_url": config.RepoURL, "branch": config.Branch}
	if config.DeployKeyPath != nil {
		cloneBody["key_path"] = *config.DeployKeyPath
	}
	cloneResult, err := agent.PostLong(ctx, "/git/clone", cloneBody, 300)
	if err != nil {
		slog.Error(fmt.Sprintf("Scheduled deploy clone failed: %s: %v", config.Name, err))
		rtGitDeploysRecordFailedHistory(ctx, db, gitDeployID, "unknown", "", "Clone failed: "+err.Error(), triggeredBy)
		rtGitDeploysMarkFailed(ctx, db, gitDeployID)
		return
	}
	commitHash, ok := jsonStr(jsonGet(cloneResult, "commit_hash"))
	if !ok {
		commitHash = "unknown"
	}
	commitMessage, _ := jsonStr(jsonGet(cloneResult, "commit_message"))

	if composeResult, err := agent.Post(ctx, "/git/compose-check", map[string]any{"name": config.Name, "build_context": config.BuildContext}); err == nil {
		if isCompose, _ := jsonBool(jsonGet(composeResult, "found")); isCompose {
			yaml, _ := jsonStr(jsonGet(composeResult, "content"))
			if reason := rtGitDeploysComposeDeployRefusal(ctx, db, agent, config.ServerID, config.UserID, yaml); reason != "" {
				slog.Warn(fmt.Sprintf("Git deploy %s: compose refused: %s", gitDeployID, reason))
				rtGitDeploysRecordFailedHistory(ctx, db, gitDeployID, commitHash, commitMessage, reason, triggeredBy)
				rtGitDeploysMarkFailed(ctx, db, gitDeployID)
				return
			}
			if cerr := rtGitDeploysComposeDeploy(ctx, agent, yaml, config.ID); cerr == "" {
				if _, dbErr := execSQL(ctx, db, "INSERT INTO git_deploy_history (git_deploy_id, commit_hash, commit_message, image_tag, status, output, triggered_by, duration_ms) VALUES ($1, $2, $3, 'compose', 'success', 'Deployed via Docker Compose', $4, $5)",
					gitDeployID, commitHash, commitMessage, triggeredBy, rtGitDeploysElapsedMs(started)); dbErr != nil {
					slog.Warn(fmt.Sprintf("Failed to record git deploy history: %v", dbErr))
				}
				if _, dbErr := execSQL(ctx, db, "UPDATE git_deploys SET status = 'running', build_method = 'compose', last_deploy = NOW(), last_commit = $1, updated_at = NOW() WHERE id = $2",
					commitHash, gitDeployID); dbErr != nil {
					slog.Warn(fmt.Sprintf("Failed to update git deploy status: %v", dbErr))
				}
				slog.Info(fmt.Sprintf("Deploy success (compose/%s): %s (%s)", triggeredBy, config.Name, commitHash))
				ActivityLogActivity(ctx, db, userID, email, "git_deploy.compose", rtGitDeploysPtr("git_deploy"), &config.Name, &commitHash, &triggeredBy, nil)
			} else {
				slog.Error(fmt.Sprintf("Compose deploy failed (%s): %s: %s", triggeredBy, config.Name, cerr))
				rtGitDeploysRecordFailedHistory(ctx, db, gitDeployID, commitHash, commitMessage, "Compose failed: "+cerr, triggeredBy)
				rtGitDeploysMarkFailed(ctx, db, gitDeployID)
			}
			return // Skip single-container path
		}
	}

	// A pre-build command skips Nixpacks — mirrors spawn's twin block.
	var preBuildCmd *string
	if config.PreBuildCmd != nil && strings.TrimSpace(*config.PreBuildCmd) != "" {
		preBuildCmd = config.PreBuildCmd
	}
	if preBuildCmd != nil {
		if e := rtTlsCertificatesRequireAgentAtLeast(ctx, agent, rtGitDeploysPreBuildSpliceMinAgent,
			"Pre-build commands (now built into the Docker image, not run on the host)"); e != nil {
			msg := rtGitDeploysAPIErrorMessage(e, "request refused")
			rtGitDeploysRecordFailedHistory(ctx, db, gitDeployID, commitHash, commitMessage, msg, triggeredBy)
			rtGitDeploysMarkFailed(ctx, db, gitDeployID)
			slog.Error(fmt.Sprintf("Scheduled deploy refused (%s): %s: %s", triggeredBy, config.Name, msg))
			return
		}
	}

	var nixpacksImage *string
	nixpacksOK := false
	var nixpacksResult any
	if preBuildCmd == nil {
		if res, e := agent.PostLong(ctx, "/git/nixpacks-build", map[string]any{
			"name":          config.Name,
			"commit_hash":   commitHash,
			"build_context": config.BuildContext,
			"env_vars":      config.EnvVars,
		}, 660); e == nil {
			nixpacksResult, nixpacksOK = res, true
		}
	}
	if nixpacksOK {
		if s, ok := jsonStr(jsonGet(nixpacksResult, "image_tag")); ok {
			nixpacksImage = &s
		}
		slog.Info("Nixpacks build succeeded for " + config.Name)
		if _, dbErr := execSQL(ctx, db, "UPDATE git_deploys SET build_method = 'nixpacks', updated_at = NOW() WHERE id = $1", gitDeployID); dbErr != nil {
			slog.Warn(fmt.Sprintf("Failed to update git deploy build method: %v", dbErr))
		}
	} else {
		result, e := agent.Post(ctx, "/git/auto-detect", map[string]any{
			"name": config.Name, "dockerfile": config.Dockerfile, "build_context": config.BuildContext,
			"pre_build_cmd": preBuildCmd,
		})
		if e != nil {
			slog.Error(fmt.Sprintf("Auto-detect failed (%s): %s: %v", triggeredBy, config.Name, e))
			rtGitDeploysRecordFailedHistory(ctx, db, gitDeployID, commitHash, commitMessage, "Auto-detect failed: "+e.Error(), triggeredBy)
			rtGitDeploysMarkFailed(ctx, db, gitDeployID)
			return
		}
		if preBuildCmd != nil {
			note, _ := jsonStr(jsonGet(result, "pre_build_note"))
			if applied, _ := jsonBool(jsonGet(result, "pre_build_applied")); applied {
				slog.Info("Pre-build command folded into Docker build for " + config.Name)
			} else {
				slog.Warn(fmt.Sprintf("Pre-build command not applied for %s: %s", config.Name, note))
			}
		}
		// Refresh the lock's self-heal clock before the (up to 900s) build:
		// this path has no updated_at bump since the lock, so a long build
		// could cross the 30-min window and let a concurrent trigger in.
		if _, dbErr := execSQL(ctx, db, "UPDATE git_deploys SET build_method = 'dockerfile', updated_at = NOW() WHERE id = $1", gitDeployID); dbErr != nil {
			slog.Warn(fmt.Sprintf("Failed to update git deploy build method: %v", dbErr))
		}
	}

	var imageTag string
	if nixpacksImage != nil {
		imageTag = *nixpacksImage
	} else {
		r, e := agent.PostLong(ctx, "/git/build", map[string]any{
			"name": config.Name, "dockerfile": config.Dockerfile, "commit_hash": commitHash,
			"build_args": config.BuildArgs, "build_context": config.BuildContext,
		}, 660)
		if e != nil {
			slog.Error(fmt.Sprintf("Scheduled deploy build failed: %s: %v", config.Name, e))
			rtGitDeploysRecordFailedHistory(ctx, db, gitDeployID, commitHash, commitMessage, "Build failed: "+e.Error(), triggeredBy)
			rtGitDeploysMarkFailed(ctx, db, gitDeployID)
			if hasToken && commitHash != "unknown" {
				rtGitDeploysSetGithubStatus(*config.GithubToken, config.RepoURL, commitHash, "failure", domainURL)
			}
			return
		}
		if s, ok := jsonStr(jsonGet(r, "image_tag")); ok {
			imageTag = s
		} else {
			imageTag = "unknown"
		}
	}

	if mode == "provided" {
		if e := rtTlsCertificatesRequireAgentAtLeast(ctx, agent, rtTlsCertificatesProvidedTlsMinAgent, "Serving a registered certificate"); e != nil {
			msg := rtGitDeploysAPIErrorMessage(e, "request refused")
			rtGitDeploysRecordFailedHistory(ctx, db, gitDeployID, commitHash, commitMessage, msg, triggeredBy)
			rtGitDeploysMarkFailed(ctx, db, gitDeployID)
			slog.Error(fmt.Sprintf("Scheduled deploy refused (%s): %s: %s", triggeredBy, config.Name, msg))
			return
		}
	}

	result, err := agent.PostLong(ctx, "/git/deploy", rtGitDeploysConfigDeployBody(config, imageTag, mode), 120)
	if err != nil {
		rtGitDeploysRecordFailedHistory(ctx, db, gitDeployID, commitHash, commitMessage, "Deploy failed: "+err.Error(), triggeredBy)
		rtGitDeploysMarkFailed(ctx, db, gitDeployID)
		if hasToken && commitHash != "unknown" {
			rtGitDeploysSetGithubStatus(*config.GithubToken, config.RepoURL, commitHash, "failure", domainURL)
		}
		slog.Error(fmt.Sprintf("Deploy failed (%s): %s: %v", triggeredBy, config.Name, err))
		return
	}
	containerID, _ := jsonStr(jsonGet(result, "container_id"))
	duration := rtGitDeploysElapsedMs(started)
	actualMode := rtGitDeploysActualMode(ctx, db, userID, result, mode, config.Name, "Scheduled deploy")

	if _, dbErr := execSQL(ctx, db,
		"INSERT INTO git_deploy_history (git_deploy_id, commit_hash, commit_message, image_tag, status, triggered_by, duration_ms) VALUES ($1, $2, $3, $4, 'success', $5, $6)",
		gitDeployID, commitHash, commitMessage, imageTag, triggeredBy, duration); dbErr != nil {
		slog.Warn(fmt.Sprintf("Failed to record git deploy history: %v", dbErr))
	}
	if _, dbErr := execSQL(ctx, db, "UPDATE git_deploys SET status = 'running', container_id = $1, image_tag = $2, last_deploy = NOW(), last_commit = $3, updated_at = NOW() WHERE id = $4",
		containerID, imageTag, commitHash, gitDeployID); dbErr != nil {
		slog.Warn(fmt.Sprintf("Failed to update git deploy status: %v", dbErr))
	}

	if config.PostDeployCmd != nil && strings.TrimSpace(*config.PostDeployCmd) != "" {
		_, _ = agent.PostLong(ctx, "/git/hook", map[string]any{"name": config.Name, "command": *config.PostDeployCmd}, 330)
	}

	if hasToken && commitHash != "unknown" {
		var target *string
		if config.Domain != nil {
			target = rtGitDeploysPtr(rtGitDeploysDeployURL(*config.Domain, actualMode))
		}
		rtGitDeploysSetGithubStatus(*config.GithubToken, config.RepoURL, commitHash, "success", target)
	}

	if channels := NotificationsGetUserChannels(ctx, db, userID, nil); channels != nil {
		subject := fmt.Sprintf("Deploy successful: %s (%s)", config.Name, triggeredBy)
		msg := fmt.Sprintf("Git deploy '%s' deployed successfully (commit: %s)", config.Name, commitHash)
		NotificationsSendNotification(ctx, db, channels, subject, msg, msg)
	}

	slog.Info(fmt.Sprintf("Deploy success (%s): %s (%s)", triggeredBy, config.Name, commitHash))
	ActivityLogActivity(ctx, db, userID, email, "git_deploy.deploy", rtGitDeploysPtr("git_deploy"), &config.Name, &commitHash, &triggeredBy, nil)

	if config.Domain != nil {
		rtGitDeploysHealthCheck(ctx, db, userID, *config.Domain, actualMode)
	}
}

func rtGitDeploysRecordFailedHistory(ctx context.Context, db *pgxpool.Pool, gitDeployID uuid.UUID, commitHash, commitMessage, output, triggeredBy string) {
	if _, err := execSQL(ctx, db,
		"INSERT INTO git_deploy_history (git_deploy_id, commit_hash, commit_message, image_tag, status, output, triggered_by) VALUES ($1, $2, $3, '', 'failed', $4, $5)",
		gitDeployID, commitHash, commitMessage, output, triggeredBy); err != nil {
		slog.Warn(fmt.Sprintf("Failed to record git deploy history: %v", err))
	}
}

// rtGitDeploysHandlePreviewDeploy handles a push to a non-configured branch.
// Returns the reason the push was NOT taken up ("" when it was). Four things
// abandon a preview BEFORE the build task is spawned, and the webhook used to
// answer "triggered" for all of them. The fourth — a failed git_previews
// upsert — matters most: every status write is keyed on the row, so with no
// row they all match zero rows, and a preview that built, bound a port and
// took a vhost was recorded nowhere. Nothing on the box reaps a rowless preview.
func rtGitDeploysHandlePreviewDeploy(ctx context.Context, st *AppState, agent AgentHandle, config *rtGitDeploysGitDeploy, branch string) string {
	branchSlug := rtGitDeploysDNSLabel(branch)
	if len(branchSlug) > 50 { // safety limit
		return fmt.Sprintf("branch name '%s' is too long to form a preview host name", branch)
	}

	// Allocate preview port (scoped to this server via git_deploys).
	used, _ := queryAll[int32](ctx, st.DB,
		"SELECT gp.host_port FROM git_previews gp "+
			"JOIN git_deploys gd ON gd.id = gp.git_deploy_id "+
			"WHERE gd.server_id = $1", config.ServerID)
	port := int32(-1)
	for p := int32(8000); p <= 8999; p++ {
		if !slices.Contains(used, p) {
			port = p
			break
		}
	}
	if port < 0 {
		slog.Warn("No preview ports available")
		return "no preview port is free — 8000-8999 are all in use"
	}

	// The preview's own name space. Before v2.55.0 this was the container
	// name of a DEPLOYMENT called `{config}-pr-{slug}`, and both halves are
	// reachable by whoever can push (the webhook has no auth), so a push
	// could blue-green a stranger's production container out of existence.
	previewName := config.Name + "-pr-" + branchSlug
	containerName := "dockpanel-git-" + rtGitDeploysPreviewScopePrefix + previewName

	// A row written before the split names its container in the OLD space;
	// the upsert below overwrites it, so tear it down first or it is orphaned.
	prev, _ := queryOpt[Tup3[string, *string, int32]](ctx, st.DB,
		"SELECT container_name, domain, host_port FROM git_previews "+
			"WHERE git_deploy_id = $1 AND branch = $2", config.ID, branch)
	if prev != nil && prev.A != containerName {
		slog.Info(fmt.Sprintf("Preview %s predates the preview name space; tearing it down before deploying %s", prev.A, containerName))
		if _, e := agent.Post(ctx, "/git/cleanup", rtGitDeploysPreviewCleanupBody(prev.A, prev.B, &prev.C)); e != nil {
			// ABANDON THIS PUSH: overwriting the row is what orphans the
			// container; leaving it keeps it findable and the next push retries.
			slog.Warn(fmt.Sprintf("Failed to tear down predecessor preview %s: %v. Leaving the git_previews row pointing at it and skipping this preview deploy — overwriting the row here is what orphans the container.", prev.A, e))
			return fmt.Sprintf("the previous preview container %s could not be torn down, so this push was not taken up — retry once the server answers", prev.A)
		}
	}

	// The preview domain's leftmost label comes from a PUSHED BRANCH NAME on
	// an unauthenticated door — a branch called `www` used to synthesise
	// www.example.com and replace that vhost. A collision deploys the preview
	// without a domain. isReservedDomain, not ...For: the Host header here is
	// chosen by whoever calls the webhook.
	var previewDomain *string
	if config.Domain != nil {
		candidate := branchSlug + "." + *config.Domain
		previewDomain = &candidate
		taken := isReservedDomain(candidate)
		if !taken {
			occ, _ := DomainClaimFindOccupant(ctx, st.DB, st.Agents, candidate, DomainClaimHolderGitDeploy(config.ID))
			taken = occ != nil
		}
		if taken {
			slog.Warn(fmt.Sprintf("Preview for branch '%s' would have claimed %s, which is already served on this server — deploying the preview without a domain", branch, candidate))
			previewDomain = nil
		}
	}

	// A refusal, not a warning: the row is the only record that the
	// container, port, vhost and certificate below exist. The reason is
	// echoed into an unauthenticated response, so it carries no DB detail.
	if _, err := execSQL(ctx, st.DB,
		"INSERT INTO git_previews (git_deploy_id, server_id, branch, container_name, host_port, domain, status) "+
			"VALUES ($1, $2, $3, $4, $5, $6, 'deploying') "+
			"ON CONFLICT (git_deploy_id, branch) DO UPDATE SET status = 'deploying', server_id = $2, container_name = $4, host_port = $5, updated_at = NOW()",
		config.ID, config.ServerID, branch, containerName, port, previewDomain); err != nil {
		slog.Warn(fmt.Sprintf("Failed to upsert git preview record for branch '%s': %v", branch, err))
		return "the preview could not be recorded, so it was not deployed — retry the push"
	}

	db := st.DB
	cfg := *config
	// A provided-mode certificate names the PARENT domain; passed through and
	// left to the agent's own SAN re-check — anything narrower falls back to
	// plain HTTP, never a hard failure over a preview's TLS.
	mode := rtStacksEffectiveTlsMode(cfg.TlsMode, cfg.SslEmail)
	var githubTarget *string
	if previewDomain != nil {
		githubTarget = rtGitDeploysPtr(rtGitDeploysDeployURL(*previewDomain, mode))
	}
	hasToken := cfg.GithubToken != nil && *cfg.GithubToken != ""
	status := func(sha, state string) {
		if hasToken {
			rtGitDeploysSetGithubStatus(*cfg.GithubToken, cfg.RepoURL, sha, state, githubTarget)
		}
	}
	markFailed := func(ctx context.Context) {
		if _, err := execSQL(ctx, db, "UPDATE git_previews SET status = 'failed' WHERE git_deploy_id = $1 AND branch = $2", cfg.ID, branch); err != nil {
			slog.Warn(fmt.Sprintf("Failed to update git preview status: %v", err))
		}
	}

	go func() {
		ctx := context.Background()
		status("HEAD", "pending")

		cloneBody := map[string]any{"name": previewName, "repo_url": cfg.RepoURL, "branch": branch, "scope": "preview"}
		if cfg.DeployKeyPath != nil {
			cloneBody["key_path"] = *cfg.DeployKeyPath
		}
		cloneResult, err := agent.PostLong(ctx, "/git/clone", cloneBody, 300)
		if err != nil {
			slog.Error(fmt.Sprintf("Preview clone failed: %s/%s: %v", cfg.Name, branch, err))
			markFailed(ctx)
			status("HEAD", "failure")
			return
		}
		commitHash, ok := jsonStr(jsonGet(cloneResult, "commit_hash"))
		if !ok {
			commitHash = "unknown"
		}

		buildResult, err := agent.PostLong(ctx, "/git/build", map[string]any{
			"name":          previewName,
			"dockerfile":    cfg.Dockerfile,
			"commit_hash":   commitHash,
			"build_args":    cfg.BuildArgs,
			"build_context": cfg.BuildContext,
			"scope":         "preview",
		}, 660)
		if err != nil {
			slog.Error(fmt.Sprintf("Preview build failed: %s/%s: %v", cfg.Name, branch, err))
			markFailed(ctx)
			status(commitHash, "failure")
			return
		}
		imageTag, ok := jsonStr(jsonGet(buildResult, "image_tag"))
		if !ok {
			imageTag = "unknown"
		}

		// memory_mb/cpu_percent deliberately not inherited: previews have
		// always run unbounded. volumes ALWAYS empty: a throwaway PR container
		// must never gain durable storage (#118) — TTL teardown would then
		// destroy real data. The agent refuses it too; this never even tries.
		deployBody := rtGitDeploysBuildDeployBody(rtGitDeploysDeployBody{
			Name:          previewName,
			ImageTag:      imageTag,
			ContainerPort: cfg.ContainerPort,
			HostPort:      port,
			EnvVars:       rtGitDeploysJSON(cfg.EnvVars),
			Domain:        previewDomain,
			// Pass SSL email so preview environments get HTTPS.
			SslEmail:       rtGitDeploysDeployTLSEmail(mode, cfg.SslEmail),
			TlsMode:        &mode,
			TlsCertificate: cfg.TlsCertificate,
			Scope:          "preview",
		})

		if mode == "provided" {
			if e := rtTlsCertificatesRequireAgentAtLeast(ctx, agent, rtTlsCertificatesProvidedTlsMinAgent, "Serving a registered certificate"); e != nil {
				slog.Error(fmt.Sprintf("Preview deploy refused: %s/%s: %s", cfg.Name, branch, rtGitDeploysAPIErrorMessage(e, "request refused")))
				markFailed(ctx)
				status(commitHash, "failure")
				return
			}
		}

		result, err := agent.PostLong(ctx, "/git/deploy", deployBody, 120)
		if err != nil {
			slog.Error(fmt.Sprintf("Preview deploy failed: %s/%s: %v", cfg.Name, branch, err))
			markFailed(ctx)
			status(commitHash, "failure")
			return
		}
		cid, _ := jsonStr(jsonGet(result, "container_id"))
		// Record the name the AGENT says it created: an older agent ignores
		// the scope and creates the unscoped name.
		created, _ := jsonStr(jsonGet(result, "container_name"))
		if created == "" {
			created = "dockpanel-git-" + previewName
		}
		if _, err := execSQL(ctx, db, "UPDATE git_previews SET status = 'running', container_id = $1, commit_hash = $2, container_name = $3 WHERE git_deploy_id = $4 AND branch = $5",
			cid, commitHash, created, cfg.ID, branch); err != nil {
			slog.Warn(fmt.Sprintf("Failed to update git preview status: %v", err))
		}
		slog.Info(fmt.Sprintf("Preview deployed: %s/%s -> port %d", cfg.Name, branch, port))
		status(commitHash, "success")
	}()

	return ""
}

// GET /api/git-deploys/{id}/previews — List preview deployments.
func rtGitDeploysListPreviews(st *AppState, w http.ResponseWriter, r *http.Request) error {
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
	previews, err := queryAll[rtGitDeploysGitPreview](r.Context(), st.DB,
		"SELECT p.* FROM git_previews p JOIN git_deploys g ON p.git_deploy_id = g.id WHERE g.id = $1 AND g.user_id = $2 ORDER BY p.created_at DESC LIMIT 500",
		id, claims.Sub)
	if err != nil {
		return internalError("list previews", err)
	}
	if previews == nil {
		previews = []rtGitDeploysGitPreview{}
	}
	writeJSON(w, http.StatusOK, previews)
	return nil
}

// DELETE /api/git-deploys/{id}/previews/{preview_id} — Delete a preview.
func rtGitDeploysDeletePreview(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	previewID, err := pathUUID(r, "preview_id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	// g.server_id: the preview runs where its PARENT lives. Preview names are
	// derived from deploy name + branch, so two servers running one repo
	// produce identical names — the wrong host destroys the neighbour's.
	row, err := queryOpt[Tup4[string, *string, int32, uuid.UUID]](ctx, st.DB,
		"SELECT p.container_name, p.domain, p.host_port, g.server_id FROM git_previews p JOIN git_deploys g ON p.git_deploy_id = g.id WHERE p.id = $1 AND g.id = $2 AND g.user_id = $3",
		previewID, id, claims.Sub)
	if err != nil {
		return internalError("delete preview", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Preview not found")
	}
	agent, err := rtGitDeploysRowAgent(ctx, st, row.D, row.B, row.A)
	if err != nil {
		return err
	}
	if _, e := agent.Post(ctx, "/git/cleanup", rtGitDeploysPreviewCleanupBody(row.A, row.B, &row.C)); e != nil {
		// KEEP THE ROW and SAY SO — this door used to answer ok over a failed
		// teardown, after deleting the row needed to retry. The agent's own
		// sentence travels only on a 4xx.
		slog.Warn(fmt.Sprintf("Failed to tear down preview %s: %v", row.A, e))
		status, detail, ok := agentActionable(e)
		if !ok {
			status, detail = http.StatusBadGateway, "the server did not answer"
		}
		return apiErr(status, fmt.Sprintf(
			"Could not tear down preview %s: %s. The preview was "+
				"kept — its record is the only thing that can still find that container, "+
				"its port and its vhost. Retry once the server answers.", row.A, detail))
	}
	if _, err := execSQL(ctx, st.DB, "DELETE FROM git_previews WHERE id = $1", previewID); err != nil {
		slog.Warn(fmt.Sprintf("Failed to delete git preview record: %v", err))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// POST /api/git-deploys/{id}/schedule — Schedule a one-time deploy.
func rtGitDeploysScheduleDeploy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	existing, err := queryOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM git_deploys WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("schedule deploy", err)
	}
	if existing == nil {
		return apiErr(http.StatusNotFound, "Git deploy not found")
	}
	deployAt, ok := jsonStr(jsonGet(body, "deploy_at"))
	if !ok {
		return apiErr(http.StatusBadRequest, "deploy_at is required (ISO 8601 timestamp)")
	}
	scheduledAt, err := time.Parse(time.RFC3339, deployAt)
	if err != nil {
		return apiErr(http.StatusBadRequest, "Invalid deploy_at format — use ISO 8601 (e.g., 2026-03-23T02:00:00Z)")
	}
	scheduledAt = scheduledAt.UTC()
	if !scheduledAt.After(time.Now()) {
		return apiErr(http.StatusBadRequest, "deploy_at must be in the future")
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE git_deploys SET scheduled_deploy_at = $1, updated_at = NOW() WHERE id = $2", scheduledAt, id); err != nil {
		return internalError("schedule deploy", err)
	}
	slog.Info(fmt.Sprintf("Scheduled one-time deploy for git deploy %s at %s", id, scheduledAt))
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "git_deploy.schedule",
		rtGitDeploysPtr("git_deploy"), rtGitDeploysPtr(id.String()), &deployAt, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "scheduled_deploy_at": scheduledAt})
	return nil
}

// DELETE /api/git-deploys/{id}/schedule — Cancel a scheduled deploy.
func rtGitDeploysCancelScheduledDeploy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	existing, err := queryOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM git_deploys WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("cancel scheduled deploy", err)
	}
	if existing == nil {
		return apiErr(http.StatusNotFound, "Git deploy not found")
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE git_deploys SET scheduled_deploy_at = NULL, updated_at = NOW() WHERE id = $1", id); err != nil {
		return internalError("cancel scheduled deploy", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// ── Deploy Approvals ────────────────────────────────────────────────────────

type rtGitDeploysApprovalRow struct {
	ID          uuid.UUID `db:"id"`
	DeployID    uuid.UUID `db:"deploy_id"`
	RequestedBy uuid.UUID `db:"requested_by"`
	Status      string    `db:"status"`
	Name        string    `db:"name"`
	Email       string    `db:"email"`
	RepoURL     string    `db:"repo_url"`
	Branch      string    `db:"branch"`
	CreatedAt   time.Time `db:"created_at"`
}

// GET /api/deploy-approvals — List pending deploy approvals.
//
// Scoped to the machines this administrator operates. require_admin alone is
// not a boundary. The predicate cannot be `g.user_id = sub`: deploy() is the
// only writer and requested_by is ALWAYS the owner, and approving your own
// request is refused — that would delete the feature while reading as a
// tighter guard. So: this machine, or a server they registered (the
// SITE_CALLER_PREDICATE admin arm), with u.role read from the DATABASE (a JWT
// keeps its minted role until expiry). g.deploy_protected is in the predicate
// so a request whose flag was switched off is never offered. Requester email
// and repo/branch travel with the row because a signature without them is
// not a review.
func rtGitDeploysListApprovals(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	rows, err := queryAll[rtGitDeploysApprovalRow](r.Context(), st.DB,
		"SELECT da.id, da.deploy_id, da.requested_by, da.status, g.name, "+
			"u2.email, g.repo_url, g.branch, da.created_at "+
			"FROM deploy_approvals da "+
			"JOIN git_deploys g ON g.id = da.deploy_id "+
			"JOIN users u2 ON u2.id = da.requested_by "+
			"WHERE da.status = 'pending' AND g.deploy_protected AND EXISTS ("+
			"SELECT 1 FROM users u, servers sv WHERE u.id = $1 AND u.role = 'admin' "+
			"AND sv.id = g.server_id AND (sv.is_local OR sv.user_id = u.id)) "+
			"ORDER BY da.created_at DESC",
		claims.Sub)
	if err != nil {
		return internalError("list approvals", err)
	}
	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		result = append(result, map[string]any{
			"id":                 row.ID,
			"deploy_id":          row.DeployID,
			"requested_by":       row.RequestedBy,
			"requested_by_email": row.Email,
			"status":             row.Status,
			"deploy_name":        row.Name,
			// The ONE place a deploy's URL crosses an ownership boundary;
			// masking in the SPA would still leave the token in this body.
			"repo_url":   rtGitDeploysMaskRepoCredentials(row.RepoURL),
			"branch":     row.Branch,
			"created_at": row.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

// POST /api/deploy-approvals/{id}/approve — Approve a pending deploy.
func rtGitDeploysApproveDeploy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	approvalID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	// Same machine-scoped predicate as list_approvals; unscoped, any admin
	// could sign off on another tenant's protected deploy.
	row, err := queryOpt[Tup3[uuid.UUID, uuid.UUID, string]](ctx, st.DB,
		"SELECT da.deploy_id, da.requested_by, da.status "+
			"FROM deploy_approvals da "+
			"JOIN git_deploys g ON g.id = da.deploy_id "+
			"WHERE da.id = $1 AND EXISTS ("+
			"SELECT 1 FROM users u, servers sv WHERE u.id = $2 AND u.role = 'admin' "+
			"AND sv.id = g.server_id AND (sv.is_local OR sv.user_id = u.id))",
		approvalID, claims.Sub)
	if err != nil {
		return internalError("approve deploy", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Approval not found")
	}
	deployID, requestedBy, status := row.A, row.B, row.C
	if status != "pending" {
		return apiErr(http.StatusConflict, "Approval already "+status)
	}
	if requestedBy == claims.Sub {
		return apiErr(http.StatusForbidden, "Cannot approve your own deploy request")
	}

	// Config + host BEFORE consuming the approval, so an unreachable host
	// leaves it pending and retryable. Pinned to requested_by (the owner
	// deploy() verified): a deployment that changed hands fails closed.
	config, err := queryOpt[rtGitDeploysGitDeploy](ctx, st.DB, rtGitDeploysGitDeploySelect+" WHERE d.id = $1 AND d.user_id = $2", deployID, requestedBy)
	if err != nil {
		return internalError("approve deploy", err)
	}
	if config == nil {
		return apiErr(http.StatusNotFound, "Git deploy not found")
	}
	// The flag is re-read: an owner may have cleared it since filing.
	if !config.DeployProtected {
		return apiErr(http.StatusConflict, "Deploy protection is no longer enabled on this deployment; the request is obsolete")
	}
	// The build runs where the deployment lives — not where the APPROVER's
	// switcher points.
	agent, err := rtGitDeploysRowAgent(ctx, st, config.ServerID, config.Domain, config.Name)
	if err != nil {
		return err
	}
	// The SAME lock deploy() takes, BEFORE the approval is consumed, so a
	// losing caller leaves the request retryable.
	n, err := execSQL(ctx, st.DB, rtGitDeploysLockSQL, deployID)
	if err != nil {
		return internalError("deploy lock", err)
	}
	if n == 0 {
		return apiErr(http.StatusConflict, "Deploy already in progress")
	}
	if _, err := execSQL(ctx, st.DB,
		"UPDATE deploy_approvals SET status = 'approved', approved_by = $1, resolved_at = NOW() WHERE id = $2",
		claims.Sub, approvalID); err != nil {
		return internalError("approve deploy", err)
	}

	newDeployID := uuid.New()
	// Owned by the approver: new_deploy_id is returned only in this response,
	// so the approver is the only party who can ever open the stream.
	st.ProvisionLogs.Register(newDeployID, claims.Sub, 32)
	rtGitDeploysSpawnDeployTask(st, agent, newDeployID, *config, requestedBy, claims.Email, "approved")

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":    "approved",
		"deploy_id": newDeployID,
		"message":   "Deploy approved and started",
	})
	return nil
}

// POST /api/deploy-approvals/{id}/reject — Reject a pending deploy. Same
// boundary: unscoped, rejection is the denial-of-service twin of approve.
func rtGitDeploysRejectDeploy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	approvalID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	status, err := queryOpt[string](ctx, st.DB,
		"SELECT da.status FROM deploy_approvals da "+
			"JOIN git_deploys g ON g.id = da.deploy_id "+
			"WHERE da.id = $1 AND EXISTS ("+
			"SELECT 1 FROM users u, servers sv WHERE u.id = $2 AND u.role = 'admin' "+
			"AND sv.id = g.server_id AND (sv.is_local OR sv.user_id = u.id))",
		approvalID, claims.Sub)
	if err != nil {
		return internalError("reject deploy", err)
	}
	if status == nil {
		return apiErr(http.StatusNotFound, "Approval not found")
	}
	if *status != "pending" {
		return apiErr(http.StatusConflict, "Approval already "+*status)
	}
	if _, err := execSQL(ctx, st.DB,
		"UPDATE deploy_approvals SET status = 'rejected', approved_by = $1, resolved_at = NOW() WHERE id = $2",
		claims.Sub, approvalID); err != nil {
		return internalError("reject deploy", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "rejected", "message": "Deploy request rejected"})
	return nil
}

// rtGitDeploysRegister registers every git_deploys route of routes::router().
// The webhook is unauthenticated by virtue of its handler taking no auth
// extractor (same router as the rest, as in Rust).
func rtGitDeploysRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("GET /api/git-deploys", h(rtGitDeploysList))
	r.Handle("POST /api/git-deploys", h(rtGitDeploysCreate))
	r.Handle("GET /api/git-deploys/{id}", h(rtGitDeploysGetOne))
	r.Handle("PUT /api/git-deploys/{id}", h(rtGitDeploysUpdate))
	r.Handle("DELETE /api/git-deploys/{id}", h(rtGitDeploysRemove))
	r.Handle("POST /api/git-deploys/{id}/deploy", h(rtGitDeploysDeploy))
	r.Handle("POST /api/git-deploys/{id}/rollback/{history_id}", h(rtGitDeploysRollback))
	r.Handle("GET /api/git-deploys/{id}/history", h(rtGitDeploysHistory))
	r.Handle("POST /api/git-deploys/{id}/history/{history_id}/explain", h(rtGitDeploysExplainHistory))
	r.Handle("POST /api/git-deploys/{id}/keygen", h(rtGitDeploysKeygen))
	r.Handle("POST /api/git-deploys/{id}/stop", h(rtGitDeploysStop))
	r.Handle("POST /api/git-deploys/{id}/start", h(rtGitDeploysStart))
	r.Handle("POST /api/git-deploys/{id}/restart", h(rtGitDeploysRestart))
	r.Handle("GET /api/git-deploys/{id}/logs", h(rtGitDeploysContainerLogs))
	r.Handle("GET /api/git-deploys/{id}/previews", h(rtGitDeploysListPreviews))
	r.Handle("DELETE /api/git-deploys/{id}/previews/{preview_id}", h(rtGitDeploysDeletePreview))
	r.Handle("POST /api/git-deploys/{id}/schedule", h(rtGitDeploysScheduleDeploy))
	r.Handle("DELETE /api/git-deploys/{id}/schedule", h(rtGitDeploysCancelScheduledDeploy))
	r.Handle("GET /api/git-deploys/deploy/{deploy_id}/log", h(rtGitDeploysDeployLog))
	r.Handle("POST /api/webhooks/git/{id}/{secret}", h(rtGitDeploysWebhook))
	r.Handle("GET /api/deploy-approvals", h(rtGitDeploysListApprovals))
	r.Handle("POST /api/deploy-approvals/{id}/approve", h(rtGitDeploysApproveDeploy))
	r.Handle("POST /api/deploy-approvals/{id}/reject", h(rtGitDeploysRejectDeploy))
}
