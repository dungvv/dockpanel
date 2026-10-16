package routes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// gitBuildAllowedPreBuild is the pre-build hook whitelist.
var gitBuildAllowedPreBuild = []string{
	"npm install",
	"npm ci",
	"yarn install",
	"pnpm install",
	"composer install",
	"bundle install",
	"pip install -r requirements.txt",
	"pip3 install -r requirements.txt",
	"cargo build --release",
}

// gitBuildIsValidRepoURL: allowed protocols only, never an option-looking
// string (git would parse a leading '-' as a flag).
func gitBuildIsValidRepoURL(u string) bool {
	if strings.HasPrefix(u, "-") || strings.HasPrefix(u, "file://") || strings.HasPrefix(u, "ext://") {
		return false
	}
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") ||
		strings.HasPrefix(u, "ssh://") || strings.HasPrefix(u, "git@")
}

func gitBuildIsValidBranch(branch string) bool {
	return !strings.HasPrefix(branch, "-") && !strings.Contains(branch, "..")
}

// gitBuildIsSafeNginxDomain is the security floor for a domain that becomes
// an nginx file path and an unescaped `server_name` written as root: only
// [A-Za-z0-9._-], no "..". Blocks traversal and directive injection while
// still permitting a benign '_' (grandfathered/preview values) — deliberately
// looser than RFC validity, which the backend enforces on new values.
func gitBuildIsSafeNginxDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || strings.Contains(domain, "..") {
		return false
	}
	for _, c := range domain {
		if !isASCIIAlnum(c) && c != '.' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func gitBuildIsValidDockerfile(p string) bool {
	return !strings.Contains(p, "..") && !strings.HasPrefix(p, "/")
}

func gitBuildIsValidBuildContext(p string) bool {
	return !strings.Contains(p, "..") && !strings.HasPrefix(p, "/")
}

// gitBuildIsValidVolumePath: a volume is CONTAINER-path only — the host side
// is always derived under the git data dir. `..` is rejected here, before
// MkdirAll ever sees it: that walks `..` with the OS's own resolution and can
// create a directory OUTSIDE the prefix before the later canonicalize + prefix
// check runs.
func gitBuildIsValidVolumePath(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) <= 1 || len(p) > 200 || strings.Contains(p, "..") || strings.Contains(p, "//") {
		return false
	}
	for _, c := range p {
		if !isASCIIAlnum(c) && !strings.ContainsRune("/_-.", c) {
			return false
		}
	}
	return true
}

// gitBuildMaxVolumes bounds an operator-editable list.
const gitBuildMaxVolumes = 10

func gitBuildValidateVolumes(volumes []string) error {
	if len(volumes) > gitBuildMaxVolumes {
		return errors.New("too many volumes declared (max 10)")
	}
	for _, v := range volumes {
		if !gitBuildIsValidVolumePath(v) {
			return errors.New("invalid volume path: must be an absolute container path with no '..' or '//'")
		}
	}
	sorted := slices.Clone(volumes)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(volumes) {
		return errors.New("duplicate volume path")
	}
	return nil
}

func gitBuildIsValidImageTag(tag string) bool {
	return strings.HasPrefix(tag, "dockpanel-git-") && !strings.Contains(tag, "/")
}

// gitBuildScopeOf: every git endpoint addresses one of two disjoint name
// spaces. A preview used to be `{config}-pr-{branch}`, a name a deployment
// can legally have, so a pushed branch could name a stranger's production
// container; Scoped puts previews behind a `.`, which isValidName rejects.
// Absent/unknown means deploy, so an older panel works unchanged.
func gitBuildScopeOf(raw string) services.OwnershipGitScope {
	return services.OwnershipGitScopeFromWire(raw)
}

func registerGitBuild(r *Router) {
	r.Handle("POST /git/clone", gitBuildClone)
	r.Handle("POST /git/build", gitBuildBuild)
	r.Handle("POST /git/deploy", func(w http.ResponseWriter, req *http.Request) { gitBuildDeploy(r.State, w, req) })
	r.Handle("POST /git/keygen", gitBuildKeygen)
	r.Handle("POST /git/cleanup", gitBuildCleanup)
	r.Handle("POST /git/release-domain", gitBuildReleaseDomain)
	r.Handle("POST /git/prune", gitBuildPrune)
	r.Handle("POST /git/stop", func(w http.ResponseWriter, req *http.Request) { gitBuildLifecycle(r.State, w, req, "stop") })
	r.Handle("POST /git/start", func(w http.ResponseWriter, req *http.Request) { gitBuildLifecycle(r.State, w, req, "start") })
	r.Handle("POST /git/restart", func(w http.ResponseWriter, req *http.Request) { gitBuildLifecycle(r.State, w, req, "restart") })
	r.Handle("POST /git/logs", func(w http.ResponseWriter, req *http.Request) { gitBuildLogs(r.State, w, req) })
	r.Handle("POST /git/hook", gitBuildHook)
	r.Handle("POST /git/auto-detect", gitBuildAutoDetect)
	r.Handle("POST /git/compose-check", gitBuildComposeCheck)
	r.Handle("POST /git/nixpacks-build", gitBuildNixpacks)
}

type gitBuildCloneRequest struct {
	Name    string  `json:"name"`
	RepoURL string  `json:"repo_url"`
	Branch  string  `json:"branch"`
	KeyPath *string `json:"key_path"`
	Scope   string  `json:"scope"`
}

// gitBuildClone: POST /git/clone — clone or pull a repository.
func gitBuildClone(w http.ResponseWriter, r *http.Request) {
	var b gitBuildCloneRequest
	if !nginxDecodeStrict(w, r, &b, "name", "repo_url", "branch") {
		return
	}
	if !isValidName(b.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid name")
		return
	}
	if b.RepoURL == "" {
		writeErr(w, http.StatusBadRequest, "Missing repo_url")
		return
	}
	if !gitBuildIsValidRepoURL(b.RepoURL) {
		writeErr(w, http.StatusBadRequest, "Invalid repo_url: must use https://, http://, ssh://, or git@ protocol")
		return
	}
	if !gitBuildIsValidBranch(b.Branch) {
		writeErr(w, http.StatusBadRequest, "Invalid branch name")
		return
	}
	name := gitBuildScopeOf(b.Scope).Scoped(b.Name)
	// Redacted: an https repo_url may embed a token as userinfo.
	slog.Info(fmt.Sprintf("Git clone: %s from %s (%s)", name, gitBuildRedactURL(b.RepoURL), b.Branch))
	res, err := services.GitBuildCloneOrPull(context.WithoutCancel(r.Context()), name, b.RepoURL, b.Branch, b.KeyPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"commit_hash": res.CommitHash, "commit_message": res.CommitMessage})
}

// gitBuildRedactURL hides a URL's userinfo for logging — a token is often
// the username (https://TOKEN@github.com/...), which url.Redacted keeps.
func gitBuildRedactURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		u.User = url.User("redacted")
		return u.String()
	}
	return raw
}

type gitBuildBuildRequest struct {
	Name         string            `json:"name"`
	Dockerfile   *string           `json:"dockerfile"`
	CommitHash   string            `json:"commit_hash"`
	BuildArgs    map[string]string `json:"build_args"`
	BuildContext *string           `json:"build_context"`
	Scope        string            `json:"scope"`
}

func gitBuildOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

// gitBuildBuild: POST /git/build — build an image from the cloned repo.
func gitBuildBuild(w http.ResponseWriter, r *http.Request) {
	var b gitBuildBuildRequest
	if !nginxDecodeStrict(w, r, &b, "name", "commit_hash") {
		return
	}
	dockerfile, buildContext := gitBuildOr(b.Dockerfile, "Dockerfile"), gitBuildOr(b.BuildContext, ".")
	if !isValidName(b.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid name")
		return
	}
	if !gitBuildIsValidDockerfile(dockerfile) {
		writeErr(w, http.StatusBadRequest, "Invalid dockerfile path")
		return
	}
	if !gitBuildIsValidBuildContext(buildContext) {
		writeErr(w, http.StatusBadRequest, "Invalid build_context path")
		return
	}
	name := gitBuildScopeOf(b.Scope).Scoped(b.Name)
	slog.Info(fmt.Sprintf("Git build: %s (commit: %s)", name, b.CommitHash))
	// Build args may carry secrets: they go to docker as argv of the build
	// (as in Rust) but are never logged here.
	res, err := services.GitBuildBuildImage(context.WithoutCancel(r.Context()), name, dockerfile, b.CommitHash, b.BuildArgs, buildContext)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"image_tag": res.ImageTag, "output": res.Output})
}

type gitBuildDeployRequest struct {
	Name          string `json:"name"`
	ImageTag      string `json:"image_tag"`
	ContainerPort uint16 `json:"container_port"`
	HostPort      uint16 `json:"host_port"`
	// The runtime environment. Both spellings are accepted on purpose: this
	// endpoint read `env` while every panel caller sent `env_vars`, and a
	// silent default turned that into a deploy with no environment (GH #94).
	// Sending both is refused, as serde rejects a field and its alias.
	Env            map[string]string `json:"env"`
	EnvVars        map[string]string `json:"env_vars"`
	Domain         *string           `json:"domain"`
	MemoryMb       *uint64           `json:"memory_mb"`
	CpuPercent     *uint64           `json:"cpu_percent"`
	SslEmail       *string           `json:"ssl_email"`
	TlsMode        *string           `json:"tls_mode"`
	TlsCertificate *string           `json:"tls_certificate"`
	Scope          string            `json:"scope"`
	// Container paths to bind-mount durably; absent from older panels.
	Volumes []string `json:"volumes"`
}

// gitBuildDeploy: POST /git/deploy — run a container from a built image.
func gitBuildDeploy(st *State, w http.ResponseWriter, r *http.Request) {
	var b gitBuildDeployRequest
	if !nginxDecodeStrict(w, r, &b, "name", "image_tag", "container_port", "host_port") {
		return
	}
	if b.Env != nil && b.EnvVars != nil {
		http.Error(w, "Failed to deserialize the JSON body into the target type: duplicate field `env`", http.StatusUnprocessableEntity)
		return
	}
	env := b.Env
	if env == nil {
		env = b.EnvVars
	}
	if !isValidName(b.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid name")
		return
	}
	if !gitBuildIsValidImageTag(b.ImageTag) {
		writeErr(w, http.StatusBadRequest, "Invalid image_tag: must start with dockpanel-git- and not contain /")
		return
	}
	if b.ContainerPort == 0 || b.HostPort == 0 {
		writeErr(w, http.StatusBadRequest, "Invalid port")
		return
	}
	// Defense-in-depth: the domain becomes a root-written nginx path and
	// server_name — block injection/traversal even if the backend were
	// bypassed.
	if b.Domain != nil && *b.Domain != "" && !gitBuildIsSafeNginxDomain(*b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	if err := gitBuildValidateVolumes(b.Volumes); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	scope := gitBuildScopeOf(b.Scope)
	// Previews must never gain durable storage: TTL teardown would then
	// destroy real data. Enforced here, the boundary a request crosses, not
	// trusted to the panel.
	if scope != services.OwnershipGitScopeDeploy && len(b.Volumes) > 0 {
		writeErr(w, http.StatusBadRequest, "volumes are not supported for preview deployments")
		return
	}
	name := scope.Scoped(b.Name)

	// Decide the TLS shape BEFORE anything runs: a mode that cannot be
	// honoured is refused with nothing done. useTraefik is false: a git
	// deploy has exactly one reverse-proxy path (nginx).
	tls, err := services.DockerAppsTlsIntentFromRequest(b.TlsMode, b.SslEmail, b.TlsCertificate, false)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info(fmt.Sprintf("Git deploy: %s (image: %s, port: %d→%d)", name, b.ImageTag, b.HostPort, b.ContainerPort))

	// Not cancelled with the request: a dropped connection must not abort a
	// blue-green swap halfway.
	res, err := services.GitBuildDeployOrUpdate(context.WithoutCancel(r.Context()), name, scope, b.ImageTag,
		b.ContainerPort, b.HostPort, env, b.Domain, st.Templates, b.MemoryMb, b.CpuPercent, tls, b.Volumes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{
		"container_id": res.ContainerID,
		"blue_green":   res.BlueGreen,
		// What was ACTUALLY created, so the panel records a name rather than
		// predicting one (agents and panels update independently).
		"container_name": "dockpanel-git-" + name,
	}
	// Absent entirely for a blue-green update, which never touched TLS.
	if res.Ssl != nil {
		resp["ssl"] = *res.Ssl
	}
	if res.TlsMode != nil {
		resp["tls_mode"] = *res.TlsMode
	}
	if res.TlsCertificate != nil {
		resp["tls_certificate"] = *res.TlsCertificate
	}
	if res.TlsWarning != nil {
		resp["proxy_warning"] = *res.TlsWarning
		// Only a refused REGISTERED certificate is the outage this flag keys
		// on (an ACME failure can still be ordered later).
		if res.TlsMode != nil && *res.TlsMode == "provided" {
			resp["tls_refused"] = true
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type gitBuildNameRequest struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

// gitBuildKeygen: POST /git/keygen — generate an SSH deploy key.
func gitBuildKeygen(w http.ResponseWriter, r *http.Request) {
	var b gitBuildNameRequest
	if !nginxDecodeStrict(w, r, &b, "name") {
		return
	}
	if !isValidName(b.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid name")
		return
	}
	pub, path, err := services.DeployGenerateDeployKey(r.Context(), b.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"public_key": pub, "key_path": path})
}

type gitBuildCleanupRequest struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
	// What the PANEL believes the vhost and port are — a fallback for a
	// container that is already gone (a preview swept after a crash), not an
	// override: the port must still match the vhost before anything goes.
	Domain   *string `json:"domain"`
	HostPort *uint16 `json:"host_port"`
}

// gitBuildCleanup: POST /git/cleanup — remove container, vhost, certs, volumes.
func gitBuildCleanup(w http.ResponseWriter, r *http.Request) {
	var b gitBuildCleanupRequest
	if !nginxDecodeStrict(w, r, &b, "name") {
		return
	}
	if !isValidName(b.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid name")
		return
	}
	if b.Domain != nil && *b.Domain != "" && !gitBuildIsSafeNginxDomain(*b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	scope := gitBuildScopeOf(b.Scope)
	if err := services.GitBuildCleanupContainer(context.WithoutCancel(r.Context()), scope.Scoped(b.Name), scope, b.Domain, b.HostPort); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

type gitBuildReleaseDomainRequest struct {
	Domain string `json:"domain"`
	// Without it the ownership check cannot tell "still ours" from
	// "re-claimed since", and fails CLOSED (the vhost stays).
	HostPort *uint16 `json:"host_port"`
}

// gitBuildReleaseDomain: POST /git/release-domain — the rename half of
// /git/cleanup, behind the same ownership gate.
func gitBuildReleaseDomain(w http.ResponseWriter, r *http.Request) {
	var b gitBuildReleaseDomainRequest
	if !nginxDecodeStrict(w, r, &b, "domain") {
		return
	}
	if b.Domain == "" || !gitBuildIsSafeNginxDomain(b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	services.GitBuildReleaseDomainArtifacts(b.Domain, b.HostPort)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

type gitBuildPruneRequest struct {
	Name  string `json:"name"`
	Keep  *uint  `json:"keep"`
	Scope string `json:"scope"`
}

// gitBuildPrune: POST /git/prune — remove old images, keeping the last N.
func gitBuildPrune(w http.ResponseWriter, r *http.Request) {
	var b gitBuildPruneRequest
	if !nginxDecodeStrict(w, r, &b, "name") {
		return
	}
	if !isValidName(b.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid name")
		return
	}
	keep := uint(5)
	if b.Keep != nil {
		keep = *b.Keep
	}
	pruned, err := services.GitBuildPruneImages(r.Context(), gitBuildScopeOf(b.Scope).Scoped(b.Name), int(keep))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pruned": pruned})
}

// gitBuildLifecycle: POST /git/{stop,start,restart} (30s cap).
func gitBuildLifecycle(st *State, w http.ResponseWriter, r *http.Request, op string) {
	var b gitBuildNameRequest
	if !nginxDecodeStrict(w, r, &b, "name") {
		return
	}
	if !isValidName(b.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid name")
		return
	}
	containerName := "dockpanel-git-" + gitBuildScopeOf(b.Scope).Scoped(b.Name)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	t10 := 10
	var err error
	switch op {
	case "stop":
		_, err = st.Docker.ContainerStop(ctx, containerName, client.ContainerStopOptions{Timeout: &t10})
	case "start":
		_, err = st.Docker.ContainerStart(ctx, containerName, client.ContainerStartOptions{})
	default:
		_, err = st.Docker.ContainerRestart(ctx, containerName, client.ContainerRestartOptions{Timeout: &t10})
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		writeErr(w, http.StatusGatewayTimeout, fmt.Sprintf("docker %s timed out (30s)", op))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

type gitBuildLogsRequest struct {
	Name  string `json:"name"`
	Lines *uint  `json:"lines"`
	Scope string `json:"scope"`
}

// gitBuildLogs: POST /git/logs — the container's last N log lines. A read
// error ends the stream quietly, as in Rust.
func gitBuildLogs(st *State, w http.ResponseWriter, r *http.Request) {
	var b gitBuildLogsRequest
	if !nginxDecodeStrict(w, r, &b, "name") {
		return
	}
	if !isValidName(b.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid name")
		return
	}
	lines := uint(200)
	if b.Lines != nil {
		lines = *b.Lines
	}
	containerName := "dockpanel-git-" + gitBuildScopeOf(b.Scope).Scoped(b.Name)
	writeJSON(w, http.StatusOK, map[string]any{"logs": gitBuildReadLogs(r.Context(), st.Docker, containerName, lines)})
}

func gitBuildReadLogs(ctx context.Context, docker *client.Client, containerName string, lines uint) string {
	rc, err := docker.ContainerLogs(ctx, containerName, client.ContainerLogsOptions{
		ShowStdout: true, ShowStderr: true, Tail: strconv.FormatUint(uint64(lines), 10),
	})
	if err != nil {
		return ""
	}
	defer rc.Close()
	raw, _ := io.ReadAll(rc)
	// Multiplexed unless the container has a TTY; fall back to raw then.
	var buf bytes.Buffer
	if _, err := stdcopy.StdCopy(&buf, &buf, bytes.NewReader(raw)); err != nil {
		return strings.ToValidUTF8(string(raw), "�")
	}
	return strings.ToValidUTF8(buf.String(), "�")
}

type gitBuildHookRequest struct {
	Name    string `json:"name"`
	Command string `json:"command"`
	Scope   string `json:"scope"`
}

// gitBuildHook: POST /git/hook — run a command inside the container.
func gitBuildHook(w http.ResponseWriter, r *http.Request) {
	var b gitBuildHookRequest
	if !nginxDecodeStrict(w, r, &b, "name", "command") {
		return
	}
	if !isValidName(b.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid name")
		return
	}
	if b.Command == "" {
		writeErr(w, http.StatusBadRequest, "Empty command")
		return
	}
	if !services.CommandFilterIsSafeHookCommand(b.Command) {
		writeErr(w, http.StatusBadRequest, "Command contains disallowed characters or patterns")
		return
	}
	containerName := "dockpanel-git-" + gitBuildScopeOf(b.Scope).Scoped(b.Name)
	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "docker", "exec", containerName, "sh", "-c", b.Command)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		writeErr(w, http.StatusGatewayTimeout, "Hook timed out (300s)")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	combined := strings.ToValidUTF8(string(out.Stdout), "�") + strings.ToValidUTF8(string(out.Stderr), "�")
	writeJSON(w, http.StatusOK, map[string]any{
		"success": out.Success(),
		"output":  gitBuildTruncate(combined, 50_000, "...\n[truncated]"),
	})
}

func gitBuildTruncate(s string, max int, suffix string) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + suffix
}

type gitBuildAutoDetectRequest struct {
	Name         string  `json:"name"`
	Dockerfile   *string `json:"dockerfile"`
	BuildContext *string `json:"build_context"`
	// Whitelisted install command folded into the generated Dockerfile's RUN
	// line. Replaces the removed /git/pre-build-hook host-exec route: it never
	// touches a host shell.
	PreBuildCmd *string `json:"pre_build_cmd"`
}

func gitBuildContextDir(name, buildContext string) string {
	dir := "/var/lib/dockpanel/git/" + name
	if buildContext != "." {
		dir += "/" + buildContext
	}
	return dir
}

// gitBuildAutoDetect: POST /git/auto-detect — generate a Dockerfile if missing.
func gitBuildAutoDetect(w http.ResponseWriter, r *http.Request) {
	var b gitBuildAutoDetectRequest
	if !nginxDecodeStrict(w, r, &b, "name") {
		return
	}
	dockerfile, buildContext := gitBuildOr(b.Dockerfile, "Dockerfile"), gitBuildOr(b.BuildContext, ".")
	if !isValidName(b.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid name")
		return
	}
	if !gitBuildIsValidBuildContext(buildContext) {
		writeErr(w, http.StatusBadRequest, "Invalid build_context path")
		return
	}
	var preBuild *string
	if b.PreBuildCmd != nil && strings.TrimSpace(*b.PreBuildCmd) != "" {
		preBuild = b.PreBuildCmd
		if !slices.Contains(gitBuildAllowedPreBuild, *preBuild) {
			writeErr(w, http.StatusBadRequest, "Command not allowed. Permitted commands: npm install, npm ci, yarn install, pnpm install, composer install, bundle install, pip install -r requirements.txt, pip3 install -r requirements.txt, cargo build --release")
			return
		}
	}
	_, statErr := os.Stat(filepath.Join(gitBuildContextDir(b.Name, buildContext), dockerfile))
	originalExists := statErr == nil

	df, applied, note, err := services.GitBuildAutoGenerateDockerfile(b.Name, dockerfile, buildContext, preBuild)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dockerfile":        df,
		"auto_generated":    !originalExists,
		"pre_build_applied": applied,
		"pre_build_note":    note,
	})
}

type gitBuildComposeCheckRequest struct {
	Name         string  `json:"name"`
	BuildContext *string `json:"build_context"`
}

// gitBuildComposeCheck: POST /git/compose-check — does the repo ship compose?
func gitBuildComposeCheck(w http.ResponseWriter, r *http.Request) {
	var b gitBuildComposeCheckRequest
	if !nginxDecodeStrict(w, r, &b, "name") {
		return
	}
	buildContext := gitBuildOr(b.BuildContext, ".")
	if !isValidName(b.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid name")
		return
	}
	if !gitBuildIsValidBuildContext(buildContext) {
		writeErr(w, http.StatusBadRequest, "Invalid build_context path")
		return
	}
	dir := gitBuildContextDir(b.Name, buildContext)
	for _, f := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, nginxErrText(err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"found": true, "file": f, "content": string(content)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"found": false})
}

// gitBuildNixpacks: POST /git/nixpacks-build. Errors are plain text, as the
// Rust handler's (StatusCode, String).
func gitBuildNixpacks(w http.ResponseWriter, r *http.Request) {
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	str := func(k string) (string, bool) { s, ok := nginxField(body, k).(string); return s, ok }
	name, ok := str("name")
	if !ok {
		nginxPlain(w, http.StatusBadRequest, "name required")
		return
	}
	if !isValidName(name) {
		nginxPlain(w, http.StatusBadRequest, "Invalid name")
		return
	}
	commit, ok := str("commit_hash")
	if !ok {
		commit = "latest"
	}
	buildContext, ok := str("build_context")
	if !ok {
		buildContext = "."
	}
	if strings.Contains(buildContext, "..") || strings.HasPrefix(buildContext, "/") {
		nginxPlain(w, http.StatusBadRequest, "Invalid build_context path")
		return
	}
	// Both spellings, as /git/deploy accepts both (GH #94).
	rawEnv := nginxField(body, "env_vars")
	if rawEnv == nil {
		rawEnv = nginxField(body, "env")
	}
	env := map[string]string{}
	if m, ok := rawEnv.(map[string]any); ok {
		for k, v := range m {
			if s, ok := v.(string); ok {
				env[k] = s
			}
		}
	}
	tag, out, err := services.GitBuildNixpacksBuild(context.WithoutCancel(r.Context()), name, commit, buildContext, env)
	if err != nil {
		nginxPlain(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"image_tag": tag, "output": out, "build_method": "nixpacks"})
}
