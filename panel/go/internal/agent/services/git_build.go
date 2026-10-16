package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/flosch/pongo2/v6"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/sitelock"
)

const gitBuildBaseDir = "/var/lib/dockpanel/git"

// gitBuildDataDir is where a Git Deploy's PERSISTENT VOLUMES live —
// deliberately separate from gitBuildBaseDir, which holds the checkout/build
// context and is wiped and re-cloned on every deploy. Mirrors
// docker_apps' APP_DATA_DIR: a directory per deploy, one subdirectory per
// declared container path.
const gitBuildDataDir = "/var/lib/dockpanel/git-data"

// GitBuildCloneResult is what a clone/pull produced.
type GitBuildCloneResult struct {
	CommitHash    string `json:"commit_hash"`
	CommitMessage string `json:"commit_message"`
}

// GitBuildBuildResult is what a docker build produced.
type GitBuildBuildResult struct {
	ImageTag string `json:"image_tag"`
	Output   string `json:"output"`
}

// GitBuildDeployResult is what a deploy did. The TLS fields are nil for a
// blue-green update, which swaps only the backend port on the existing vhost
// and never re-renders it, so whatever certificate story the domain had is
// untouched and there is nothing new to report. Set for a fresh deploy or a
// stop/recreate that rendered a vhost — mirrors docker_apps' expose_domain
// response shape so the panel's provided_tls_refusal check works unchanged.
type GitBuildDeployResult struct {
	ContainerID    string
	BlueGreen      bool
	Ssl            *bool
	TlsMode        *string
	TlsCertificate *string
	TlsWarning     *string
}

// gitBuildTlsOutcome is what securing a domain actually achieved.
type gitBuildTlsOutcome struct {
	ssl            bool
	tlsMode        string
	tlsCertificate *string
	warning        *string
}

func gitBuildDocker() (*client.Client, error) {
	c, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("Docker connect failed: %v", err)
	}
	return c, nil
}

func gitBuildExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// GitBuildCloneOrPull clones or pulls into /var/lib/dockpanel/git/{name}/:
// `--depth 50` for a clone, `fetch + reset --hard` for a pull.
func GitBuildCloneOrPull(ctx context.Context, name, repoURL, branch string, keyPath *string) (GitBuildCloneResult, error) {
	repoDir := gitBuildBaseDir + "/" + name
	gitDir := repoDir + "/.git"

	// SSRF: this process is the one that actually dials repo_url (the panel's
	// own check at write time runs on a different host, often much earlier).
	if err := SsrfGuardValidateRepoURLNotInternal(repoURL); err != nil {
		return GitBuildCloneResult{}, err
	}

	env := []string{"GIT_TERMINAL_PROMPT=0"}
	if keyPath != nil {
		ssh, err := DeploySshCommand(*keyPath)
		if err != nil {
			return GitBuildCloneResult{}, err
		}
		env = append(env, "GIT_SSH_COMMAND="+ssh)
	}

	if gitBuildExists(gitDir) {
		// The context kills git on timeout; an orphaned `git fetch` would hold
		// .git/index.lock against every later attempt on this repo.
		fetch, err := deployRun(ctx, 120*time.Second, "", env, "git", "-C", repoDir, "fetch", "origin", branch)
		if errors.Is(err, deployErrTimeout) {
			return GitBuildCloneResult{}, errors.New("git fetch timed out (120s)")
		}
		if err != nil {
			return GitBuildCloneResult{}, fmt.Errorf("git fetch failed: %v", err)
		}
		if !fetch.Success() {
			return GitBuildCloneResult{}, fmt.Errorf("git fetch failed: %s", nginxLossy(fetch.Stderr))
		}
		reset, err := deployRun(ctx, 0, "", nil, "git", "-C", repoDir, "reset", "--hard", "origin/"+branch)
		if err != nil {
			return GitBuildCloneResult{}, fmt.Errorf("git reset failed: %v", err)
		}
		if !reset.Success() {
			return GitBuildCloneResult{}, fmt.Errorf("git reset failed: %s", nginxLossy(reset.Stderr))
		}
		slog.Info(fmt.Sprintf("Git repo pulled: %s (branch %s)", name, branch))
	} else {
		if err := os.MkdirAll(repoDir, 0o755); err != nil {
			return GitBuildCloneResult{}, fmt.Errorf("Failed to create repo dir: %v", nginxIOErr(err))
		}
		// Same orphan-on-timeout concern as the fetch above.
		clone, err := deployRun(ctx, 300*time.Second, "", env, "git",
			"clone", "--branch", branch, "--single-branch", "--depth", "50", repoURL, repoDir)
		if errors.Is(err, deployErrTimeout) {
			return GitBuildCloneResult{}, errors.New("git clone timed out (300s)")
		}
		if err != nil {
			return GitBuildCloneResult{}, fmt.Errorf("git clone failed: %v", err)
		}
		if !clone.Success() {
			_ = os.RemoveAll(repoDir) // partial clone
			return GitBuildCloneResult{}, fmt.Errorf("git clone failed: %s", nginxLossy(clone.Stderr))
		}
		slog.Info(fmt.Sprintf("Git repo cloned: %s (branch %s)", name, branch))
	}

	hash, err := deployRun(ctx, 0, "", nil, "git", "-C", repoDir, "rev-parse", "--short", "HEAD")
	if err != nil {
		return GitBuildCloneResult{}, fmt.Errorf("Failed to get commit hash: %v", err)
	}
	if !hash.Success() {
		return GitBuildCloneResult{}, errors.New("Failed to read commit hash")
	}
	res := GitBuildCloneResult{CommitHash: strings.TrimSpace(nginxLossy(hash.Stdout))}

	msg, err := deployRun(ctx, 0, "", nil, "git", "-C", repoDir, "log", "-1", "--format=%s")
	if err != nil {
		return GitBuildCloneResult{}, fmt.Errorf("Failed to get commit message: %v", err)
	}
	if msg.Success() {
		res.CommitMessage = strings.TrimSpace(nginxLossy(msg.Stdout))
	}
	return res, nil
}

// gitBuildTruncate cuts s to max bytes (on a rune boundary) plus suffix.
func gitBuildTruncate(s string, max int, suffix string) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// GitBuildBuildImage builds dockpanel-git-{name}:{commit} (+ :latest) from the
// checkout with BuildKit, build args and a custom build context.
func GitBuildBuildImage(ctx context.Context, name, dockerfilePath, commitHash string, buildArgs map[string]string, buildContext string) (GitBuildBuildResult, error) {
	deployDir := gitBuildBaseDir + "/" + name
	imageName := "dockpanel-git-" + name
	imageTag := imageName + ":" + commitHash
	latestTag := imageName + ":latest"

	if strings.Contains(buildContext, "..") {
		return GitBuildBuildResult{}, errors.New("Build context must not contain '..'")
	}
	contextDir := deployDir
	fullDockerfile := dockerfilePath
	if buildContext != "." {
		contextDir = deployDir + "/" + buildContext
		fullDockerfile = buildContext + "/" + dockerfilePath
	}
	if !gitBuildExists(contextDir) {
		return GitBuildBuildResult{}, fmt.Errorf("Build context directory not found: %s", buildContext)
	}
	slog.Info(fmt.Sprintf("Building image %s from %s (context: %s)", imageTag, deployDir, buildContext))

	args := []string{"build", "--cache-from", latestTag}
	keys := make([]string, 0, len(buildArgs))
	for k := range buildArgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "--build-arg", k+"="+buildArgs[k])
	}
	args = append(args, "-t", imageTag, "-t", latestTag, "-f", fullDockerfile, contextDir)

	// 900s, not 600s: the build also carries any pre-build install step the
	// operator configured (folded into a RUN line — see
	// GitBuildAutoGenerateDockerfile), absorbing that step's old 300s budget.
	// The context kills docker build on timeout.
	build, err := deployRun(ctx, 900*time.Second, deployDir, []string{"DOCKER_BUILDKIT=1"}, "docker", args...)
	if errors.Is(err, deployErrTimeout) {
		return GitBuildBuildResult{}, errors.New("docker build timed out (900s)")
	}
	if err != nil {
		return GitBuildBuildResult{}, fmt.Errorf("docker build failed: %v", err)
	}
	output := gitBuildTruncate(nginxLossy(build.Stdout)+nginxLossy(build.Stderr), 100_000, "...\n[output truncated]")
	if !build.Success() {
		return GitBuildBuildResult{}, fmt.Errorf("docker build failed:\n%s", output)
	}
	slog.Info("Image built successfully: " + imageTag)
	return GitBuildBuildResult{ImageTag: imageTag, Output: output}, nil
}

func gitBuildProxyConfig(hostPort uint16) NginxSiteConfig {
	p := hostPort
	return NginxSiteConfig{Runtime: "proxy", ProxyPort: &p}
}

func gitBuildStr(s string) *string { return &s }

// gitBuildApplyTls puts a domain in front of a git deploy's local port,
// secured the way tls asks — the same guarantee a Docker/Compose deploy has:
// "provided" renders straight to HTTPS through the registered certificate and
// is the ONLY arm that reads it, "acme" orders a Let's Encrypt certificate,
// "none" is the plain-HTTP proxy.
//
// Unlike expose_domain, a refused "provided" certificate falls back to plain
// HTTP rather than leaving the vhost untouched: both call sites only reach
// here when there is nothing to protect (a brand new container's first vhost,
// or a domain that just changed), so falling back leaves the deploy reachable
// with the refusal surfaced as a warning — never a silent downgrade of a live
// certificate (blue-green never reaches this function).
func gitBuildApplyTls(ctx context.Context, templates *pongo2.TemplateSet, domain string, hostPort uint16, tls DockerAppsTlsIntent) (gitBuildTlsOutcome, error) {
	switch tls.Kind {
	case DockerAppsTlsProvided:
		alias := tls.Alias
		certPath, keyPath := SslRegistryPaths(alias)
		pemBytes, err := os.ReadFile(certPath)
		if err != nil {
			e := nginxIOErr(err)
			slog.Warn(fmt.Sprintf("Git deploy: %s names registered certificate %s, which is not on this server (%v); falling back to plain HTTP", domain, alias, e))
			if err := gitBuildSetupNginxProxy(templates, domain, hostPort); err != nil {
				return gitBuildTlsOutcome{}, err
			}
			return gitBuildTlsOutcome{tlsMode: "provided", tlsCertificate: gitBuildStr(alias),
				warning: gitBuildStr(fmt.Sprintf("no certificate named %s is registered on this server (%v); served over plain HTTP instead. Register the certificate and redeploy.", alias, e))}, nil
		}
		// Re-asked here: the panel checked at claim time, but the pairing on
		// disk may have been replaced since.
		if _, err := SslCertCoversDomain(string(pemBytes), domain); err != nil {
			slog.Warn(fmt.Sprintf("Git deploy: registered certificate %s does not cover %s: %v", alias, domain, err))
			if err := gitBuildSetupNginxProxy(templates, domain, hostPort); err != nil {
				return gitBuildTlsOutcome{}, err
			}
			return gitBuildTlsOutcome{tlsMode: "provided", tlsCertificate: gitBuildStr(alias),
				warning: gitBuildStr(fmt.Sprintf("the registered certificate %s cannot serve %s: %v Served over plain HTTP instead.", alias, domain, err))}, nil
		}
		// Rendered with the registry paths named outright — NOT through
		// SslEnableSslForSite, which hardcodes the per-domain tree.
		cfg := gitBuildProxyConfig(hostPort)
		t := true
		cfg.Ssl, cfg.SslCert, cfg.SslKey = &t, &certPath, &keyPath
		rendered, err := NginxRenderSiteConfig(templates, domain, &cfg)
		if err != nil {
			return gitBuildTlsOutcome{}, fmt.Errorf("Failed to render nginx config: %v", err)
		}
		target := NginxVhostTargetFor(domain)
		previous := gitBuildReadOpt(target.Path)
		if err := gitBuildWriteVhost(target.Path, rendered); err != nil {
			return gitBuildTlsOutcome{}, err
		}
		ok := gitBuildTlsOutcome{ssl: true, tlsMode: "provided", tlsCertificate: gitBuildStr(alias)}
		if !target.Live {
			slog.Info(fmt.Sprintf("Git deploy: %s is disabled, saved the HTTPS route (certificate %s) to its parked configuration", domain, alias))
			return ok, nil
		}
		if out, err := NginxTestConfig(); err == nil && out.Success {
			_ = NginxReload()
			slog.Info(fmt.Sprintf("Git deploy: %s -> port %d over registered certificate %s", domain, hostPort, alias))
			return ok, nil
		}
		restored := NginxRestoreOrRemove(target.Path, previous)
		return gitBuildTlsOutcome{}, fmt.Errorf("Nginx config test failed for %s%s", domain, NginxRestoreNote(restored))

	case DockerAppsTlsAcme:
		if err := gitBuildSetupNginxProxy(templates, domain, hostPort); err != nil {
			return gitBuildTlsOutcome{}, err
		}
		// DNS propagation wait.
		for i := 0; i < 6; i++ {
			if i > 0 {
				time.Sleep(5 * time.Second)
			}
			if c, err := net.DialTimeout("tcp", net.JoinHostPort(domain, "80"), 10*time.Second); err == nil {
				c.Close()
				break
			}
		}
		account, err := SslLoadOrCreateAccount(tls.Email)
		if err != nil {
			slog.Warn(fmt.Sprintf("Auto-SSL: ACME account failed for %s: %v", domain, err))
			return gitBuildTlsOutcome{tlsMode: "acme", warning: gitBuildStr(fmt.Sprintf("ACME account setup failed: %v", err))}, nil
		}
		if _, err := SslProvisionCert(ctx, account, domain, nil); err != nil {
			slog.Warn(fmt.Sprintf("Auto-SSL: cert provisioning failed for %s: %v", domain, err))
			return gitBuildTlsOutcome{tlsMode: "acme", warning: gitBuildStr(fmt.Sprintf("certificate provisioning failed: %v", err))}, nil
		}
		cfg := gitBuildProxyConfig(hostPort)
		if _, err := SslEnableSslForSite(templates, domain, &cfg); err == nil {
			slog.Info("Auto-SSL: certificate provisioned for " + domain)
			return gitBuildTlsOutcome{ssl: true, tlsMode: "acme"}, nil
		}
		return gitBuildTlsOutcome{tlsMode: "acme",
			warning: gitBuildStr(fmt.Sprintf("certificate provisioned for %s but enabling it on the vhost failed", domain))}, nil
	}
	if err := gitBuildSetupNginxProxy(templates, domain, hostPort); err != nil {
		return gitBuildTlsOutcome{}, err
	}
	return gitBuildTlsOutcome{tlsMode: "none"}, nil
}

func gitBuildReadOpt(path string) *string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	s := string(b)
	return &s
}

// gitBuildWriteVhost writes tmp + rename so nginx never sees a half file.
func gitBuildWriteVhost(path, body string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return fmt.Errorf("Failed to write nginx config: %v", nginxIOErr(err))
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("Failed to activate nginx config: %v", nginxIOErr(err))
	}
	return nil
}

func gitBuildOutcomeResult(id string, o *gitBuildTlsOutcome) GitBuildDeployResult {
	r := GitBuildDeployResult{ContainerID: id}
	if o != nil {
		ssl, mode := o.ssl, o.tlsMode
		r.Ssl, r.TlsMode, r.TlsCertificate, r.TlsWarning = &ssl, &mode, o.tlsCertificate, o.warning
	}
	return r
}

// GitBuildDeployOrUpdate deploys or updates a container from a locally built
// image:
//   - new container: create + start, plus an nginx proxy when a domain is set;
//   - existing container with an unchanged domain + vhost: blue-green;
//   - otherwise: stop, remove, create, start.
//
// name arrives already scoped by OwnershipGitScope.Scoped; scope comes with
// it because the name alone cannot say whether the container found under it
// is this deployment's.
func GitBuildDeployOrUpdate(ctx context.Context, name string, scope OwnershipGitScope, imageTag string,
	containerPort, hostPort uint16, envVars map[string]string, domain *string, templates *pongo2.TemplateSet,
	memoryMb, cpuPercent *uint64, tls DockerAppsTlsIntent, volumes []string) (GitBuildDeployResult, error) {
	// Held for the whole deploy, including the internal blue-green swap —
	// gitBuildBlueGreenUpdate must never take this key itself (not reentrant).
	defer sitelock.LockSite("git-deploy:" + name)()

	docker, err := gitBuildDocker()
	if err != nil {
		return GitBuildDeployResult{}, err
	}
	defer docker.Close()

	containerName := "dockpanel-git-" + name
	envList := make([]string, 0, len(envVars))
	for k, v := range envVars {
		envList = append(envList, k+"="+v)
	}
	sort.Strings(envList)

	// dockpanel.git.kind is what a later run reads back to tell a
	// deployment's container from a preview's — a container is the one thing
	// here with no file to open and ask.
	labels := map[string]string{
		"dockpanel.managed":   "true",
		"dockpanel.type":      "git",
		"dockpanel.git.name":  name,
		OwnershipGitKindLabel: scope.Label(),
	}
	if domain != nil {
		labels["dockpanel.app.domain"] = *domain
	}

	// PERSISTENT VOLUMES: `volumes` is container-path only — the host side is
	// always {gitBuildDataDir}/{name}{path}, never operator-supplied (a bind of
	// / or /etc would be a container escape, and most free-form paths would
	// fail under ProtectSystem=strict anyway). The route refuses volumes for
	// any scope but Deploy — a preview must never gain durable storage.
	//
	// Fresh deploy: every path is new, so it is created and seeded from the
	// image. Existing container: already-bound paths are kept (never
	// re-seeded — that would stomp real data with shipped defaults) and newly
	// added ones are rescued from the old writable layer via `docker cp`
	// before that container is removed. Blue-green is refused whenever volumes
	// is non-empty: it would run old and new containers against the same host
	// paths during the health check, silently corrupting single-writer stores
	// like SQLite.
	hostConfig := gitBuildHostConfig(containerPort, hostPort)
	if memoryMb != nil && *memoryMb > 0 {
		hostConfig.Memory = int64(*memoryMb * 1024 * 1024)
		hostConfig.MemorySwap = int64(*memoryMb * 2 * 1024 * 1024)
	}
	if cpuPercent != nil && *cpuPercent > 0 && *cpuPercent <= 100 {
		hostConfig.CPUPeriod = 100_000
		hostConfig.CPUQuota = int64(*cpuPercent * 1000)
	}
	exposed := network.PortSet{gitBuildPort(containerPort): {}}

	existing := gitBuildFindContainer(ctx, docker, containerName, scope)

	// A container holding this name is not necessarily this deployment's.
	// Every branch below either force-removes it or repoints ITS domain at our
	// build, both irreversible — so refuse.
	if existing != nil && !existing.owner.MayDelete() {
		what := "deployment"
		if scope != OwnershipGitScopeDeploy {
			what = "preview"
		}
		return GitBuildDeployResult{}, fmt.Errorf("Refusing to deploy: the container %s already exists and does not belong to this %s (it reports %v). Nothing was changed. Rename this deployment or remove the existing container first.",
			containerName, what, existing.owner)
	}

	if existing == nil {
		slog.Info("Deploying new git container: " + containerName)
		if len(volumes) > 0 {
			binds, err := gitBuildFreshVolumeBinds(ctx, docker, name, imageTag, volumes)
			if err != nil {
				return GitBuildDeployResult{}, err
			}
			if len(binds) > 0 {
				hostConfig.Binds = binds
			}
		}
		id, err := gitBuildCreateAndStart(ctx, docker, containerName, imageTag, envList, labels, exposed, hostConfig)
		if err != nil {
			return GitBuildDeployResult{}, err
		}
		// A brand new container's vhost has nothing to downgrade.
		var outcome *gitBuildTlsOutcome
		if domain != nil {
			o, err := gitBuildApplyTls(ctx, templates, *domain, hostPort, tls)
			if err != nil {
				return GitBuildDeployResult{}, err
			}
			outcome = &o
		}
		return gitBuildOutcomeResult(id, outcome), nil
	}

	// Does the request still name the domain the running container was built
	// for? If not, blue-green is the wrong tool: it swaps the vhost of the OLD
	// domain, and the requested one would never get a server block.
	domainUnchanged := true
	if domain != nil {
		domainUnchanged = existing.domain != nil && *domain == *existing.domain
	}
	hasNginx := domainUnchanged && existing.domain != nil && existing.hostPort != nil &&
		gitBuildExists(fmt.Sprintf("%s/%s.conf", NginxSitesDir(), *existing.domain))

	// volumes empty is the persistent-state guard — see above; any declared
	// volume forces stop/recreate, as docker_apps' shares_persistent_state
	// decides for Docker Apps.
	if hasNginx && len(volumes) == 0 {
		slog.Info(fmt.Sprintf("Blue-green update for git app %s: domain=%s, old_port=%d", name, *existing.domain, *existing.hostPort))
		return gitBuildBlueGreenUpdate(ctx, docker, existing.id, containerName, imageTag, envList, labels,
			containerPort, *existing.hostPort, *existing.domain, hostConfig)
	}
	if hasNginx {
		slog.Info(fmt.Sprintf("Not using blue-green for %s: it has %d declared persistent volume(s). Using stop/start instead (brief downtime, no concurrent writers).", name, len(volumes)))
	}
	slog.Info(fmt.Sprintf("Replacing git container %s (stop/start; domain_unchanged=%v)", containerName, domainUnchanged))

	t10 := 10
	_, _ = docker.ContainerStop(ctx, existing.id, client.ContainerStopOptions{Timeout: &t10})

	// Stopped (flushed) but not yet removed: the only window in which data a
	// newly declared volume needs can be rescued from the writable layer. A
	// failure here MUST abort before the remove below.
	var existingBinds []string
	if info, err := docker.ContainerInspect(ctx, existing.id, client.ContainerInspectOptions{}); err == nil && info.Container.HostConfig != nil {
		existingBinds = info.Container.HostConfig.Binds
	}
	keptBinds := gitBuildKeptBinds(existingBinds, volumes)
	mounted := DockerAppsMountedDestinations(&container.HostConfig{Binds: keptBinds})
	var unmounted []string
	for _, v := range volumes {
		if !nginxContains(mounted, v) {
			unmounted = append(unmounted, v)
		}
	}
	if len(unmounted) > 0 {
		migrateConfig := &container.HostConfig{Binds: append([]string(nil), keptBinds...)}
		migrated, err := DockerAppsMigrateUnmountedVolumes(ctx, gitBuildDataDir, docker, existing.id, name, imageTag, unmounted, migrateConfig)
		if err != nil {
			return GitBuildDeployResult{}, fmt.Errorf("Aborting deploy of %s without removing the running container: %v. It is stopped and intact; start it again with `docker start %s`.", name, err, containerName)
		}
		keptBinds = migrateConfig.Binds
		slog.Info(fmt.Sprintf("Migrated %d volume(s) for %s onto %s: %s", len(migrated), name, gitBuildDataDir, strings.Join(migrated, ", ")))
	}
	if len(keptBinds) > 0 {
		hostConfig.Binds = keptBinds
	}

	_, _ = docker.ContainerRemove(ctx, existing.id, client.ContainerRemoveOptions{Force: true})

	id, err := gitBuildCreateAndStart(ctx, docker, containerName, imageTag, envList, labels, exposed, hostConfig)
	if err != nil {
		return GitBuildDeployResult{}, err
	}

	// The requested domain gets its server block here too, not only on a
	// first deploy — adding/changing a git app's domain used to write only the
	// label, and the hostname served nothing, permanently.
	//
	// The PREVIOUS domain's vhost is not touched here: this function cannot
	// prove it is still this deploy's. ⛔ But it is not harmless either — the
	// container keeps its host port across a rename, so the old vhost goes on
	// proxying to a LIVE app while the panel releases the name for another
	// tenant. That teardown is GitBuildReleaseDomainArtifacts, driven by the
	// panel's update handler, the only caller that knows both names.
	var outcome *gitBuildTlsOutcome
	if domain != nil {
		configPath := fmt.Sprintf("%s/%s.conf", NginxSitesDir(), *domain)
		if !domainUnchanged || !gitBuildExists(configPath) {
			// Neither trigger can name a path already serving THIS domain's
			// HTTPS, so the plain-HTTP fallback has nothing live to downgrade.
			o, err := gitBuildApplyTls(ctx, templates, *domain, hostPort, tls)
			if err != nil {
				return GitBuildDeployResult{}, err
			}
			outcome = &o
		}
	}
	return gitBuildOutcomeResult(id, outcome), nil
}

// gitBuildKeptBinds keeps the old container's binds whose destination is
// still declared — clearing a path un-mounts it from the next container
// without deleting the data on disk. The destination is the SECOND
// `:`-separated field so a `:mode` suffix cannot bleed into the comparison.
func gitBuildKeptBinds(existing, declared []string) []string {
	var kept []string
	for _, b := range existing {
		parts := strings.Split(b, ":")
		if len(parts) > 1 && nginxContains(declared, parts[1]) {
			kept = append(kept, b)
		}
	}
	return kept
}

func gitBuildPort(p uint16) network.Port {
	return network.MustParsePort(fmt.Sprintf("%d/tcp", p))
}

// gitBuildHostConfig: 127.0.0.1:{hostPort} -> {containerPort}/tcp, unless-stopped.
func gitBuildHostConfig(containerPort, hostPort uint16) *container.HostConfig {
	return &container.HostConfig{
		PortBindings: network.PortMap{gitBuildPort(containerPort): {{
			HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: fmt.Sprint(hostPort),
		}}},
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
	}
}

// gitBuildFreshVolumeBinds builds bind mounts for a BRAND NEW container — one
// directory per declared path under gitBuildDataDir, seeded from the image
// and chowned to its non-root user. Mirrors docker_apps' deploy_app loop
// (create → canonicalize → verify prefix → seed → chown → bind), deliberately
// not shared code with it. Only for a fresh deploy: seeding stomps real data.
func gitBuildFreshVolumeBinds(ctx context.Context, docker *client.Client, name, image string, volumes []string) ([]string, error) {
	owner := DockerAppsResolveVolumeOwner(ctx, docker, image)
	var binds []string
	for _, vol := range volumes {
		hostDir := gitBuildDataDir + "/" + name + vol
		if err := os.MkdirAll(hostDir, 0o755); err != nil {
			return nil, fmt.Errorf("Failed to create %s: %v", hostDir, nginxIOErr(err))
		}
		// The prefix check is what proves the path is ours, and it has to
		// happen after symlinks are resolved.
		resolved, err := filepath.EvalSymlinks(hostDir)
		if err == nil {
			resolved, err = filepath.Abs(resolved)
		}
		if err != nil {
			return nil, fmt.Errorf("Volume path %s inaccessible: %v", hostDir, nginxIOErr(err))
		}
		if !strings.HasPrefix(resolved, gitBuildDataDir+"/") {
			return nil, fmt.Errorf("Volume path %s escapes allowed prefix after canonicalization", hostDir)
		}
		// Seed and chown only AFTER the prefix check.
		DockerAppsSeedVolumeFromImage(ctx, docker, image, vol, resolved)
		if owner != nil {
			if err := DockerAppsChownTo(resolved, owner); err != nil {
				slog.Warn(fmt.Sprintf("Could not chown volume %s for %s: %v. The app may be unable to write its data directory.", resolved, name, err))
			}
		}
		binds = append(binds, resolved+":"+vol)
	}
	return binds, nil
}

// GitBuildReleaseDomainArtifacts takes down domain's vhost and certificates,
// but ONLY while they still belong to the container on hostPort — a vhost
// that no longer proxies to this port was re-claimed since, and removing it
// would be an outage for a third party. Shared by DELETE and RENAME so they
// cannot drift. ⚠ Deliberately infallible: every caller is finishing an
// operation the operator already asked for.
func GitBuildReleaseDomainArtifacts(domain string, hostPort *uint16) {
	configPath := fmt.Sprintf("%s/%s.conf", NginxSitesDir(), domain)
	if gitBuildExists(configPath) {
		if OwnershipAppVhost(configPath, hostPort).MayDelete() {
			_ = os.Remove(configPath)
			slog.Info("Removed nginx config: " + configPath)
			if out, err := NginxTestConfig(); err == nil && out.Success {
				_ = NginxReload()
			} else {
				slog.Warn("Nginx test failed after removing config for " + domain)
			}
		} else {
			slog.Warn(fmt.Sprintf("Leaving %s in place: it does not proxy to this container's port, so %s is now served by something else. This runs unattended — taking that down would be an outage nobody was present for.", configPath, domain))
		}
	}
	// SSL certificates — not if a wildcard is shared across the zone.
	sslDir := "/etc/dockpanel/ssl/" + domain
	if gitBuildExists(sslDir) {
		if OwnershipCertDirInUseElsewhere(domain) {
			slog.Warn(fmt.Sprintf("Leaving %s in place: another vhost still points at it.", sslDir))
		} else {
			_ = os.RemoveAll(sslDir)
			slog.Info("Removed SSL certs: " + sslDir)
		}
	}
}

// GitBuildCleanupContainer stops and removes a git container plus its vhost,
// certificates, checkout and volume dir. scope decides both the name space
// and what counts as proof the container is the caller's — PreviewLegacy
// reaches into the OLD shared space, where the container may be a production
// deployment that merely shares the name.
func GitBuildCleanupContainer(ctx context.Context, name string, scope OwnershipGitScope, knownDomain *string, knownPort *uint16) error {
	defer sitelock.LockSite("git-deploy:" + name)()

	docker, err := gitBuildDocker()
	if err != nil {
		return err
	}
	defer docker.Close()
	containerName := "dockpanel-git-" + name

	// Domain AND published port are read before removal: the port is what
	// proves the vhost is still this container's. The label alone is not —
	// a preview's domain is invisible to the panel's claim check, so a real
	// site can be created on it, and an unattended TTL sweep would then delete
	// that site's vhost.
	var domain *string
	var hostPort *uint16
	var dataDir *string
	if info, err := docker.ContainerInspect(ctx, containerName, client.ContainerInspectOptions{}); err == nil {
		var labels map[string]string
		if info.Container.Config != nil {
			labels = info.Container.Config.Labels
		}
		var livePort *uint16
		if info.Container.HostConfig != nil {
			livePort = DockerAppsExtractHostPort(info.Container.HostConfig)
		}
		owner := OwnershipGitContainer(labels, scope, knownPort, livePort)
		if !owner.MayDelete() {
			slog.Warn(fmt.Sprintf("Refusing to clean up %s: it reports %v for this %s request. Leaving the container, its vhost, its certificates and its checkout in place — a stale preview is untidy, and removing a running deployment is an outage nobody was present for.",
				containerName, owner, gitBuildScopeName(scope)))
			return nil
		}
		if d, ok := labels["dockpanel.app.domain"]; ok {
			domain = &d
		}
		hostPort = livePort
		// Ownership of the volume dir is decided by the container's OWN
		// binds, never its name — read now, since after the remove there is
		// nothing left to ask.
		if info.Container.HostConfig != nil {
			dataDir = gitBuildOwnedDataDir(name, info.Container.HostConfig.Binds)
		}
	} else {
		// Already gone: the caller's own record names the vhost and port; the
		// port still has to match the vhost, so this widens what can be
		// tidied, not what can be destroyed. No binds → no proof of a volume
		// dir: left alone rather than guessed from the name.
		domain, hostPort = knownDomain, knownPort
	}

	t10 := 10
	_, _ = docker.ContainerStop(ctx, containerName, client.ContainerStopOptions{Timeout: &t10})
	_, _ = docker.ContainerRemove(ctx, containerName, client.ContainerRemoveOptions{Force: true})
	slog.Info("Removed git container: " + containerName)

	if domain != nil {
		GitBuildReleaseDomainArtifacts(*domain, hostPort)
	}

	// The checkout is a re-clonable working copy, never the operator's data.
	repoDir := gitBuildBaseDir + "/" + name
	if gitBuildExists(repoDir) {
		_ = os.RemoveAll(repoDir)
		slog.Info("Removed git repo dir: " + repoDir)
	}
	if dataDir != nil && gitBuildExists(*dataDir) {
		_ = os.RemoveAll(*dataDir)
		slog.Info("Removed git volume dir: " + *dataDir)
	}
	return nil
}

func gitBuildScopeName(s OwnershipGitScope) string {
	switch s {
	case OwnershipGitScopePreview:
		return "Preview"
	case OwnershipGitScopePreviewLegacy:
		return "PreviewLegacy"
	}
	return "Deploy"
}

// gitBuildOwnedDataDir: which dir under gitBuildDataDir do this container's
// own binds prove it owns? A bind outside it yields nil, which refuses to
// delete rather than guess; a prefix stopping mid-segment never matches.
func gitBuildOwnedDataDir(name string, binds []string) *string {
	prefix := gitBuildDataDir + "/" + name
	for _, b := range binds {
		source, _, _ := strings.Cut(b, ":")
		if source == prefix || strings.HasPrefix(source, prefix+"/") {
			return &prefix
		}
	}
	return nil
}

// GitBuildPruneImages removes old images for a git app, keeping the newest
// keep; :latest is never pruned.
func GitBuildPruneImages(ctx context.Context, name string, keep int) ([]string, error) {
	prefix := "dockpanel-git-" + name
	out, err := deployRun(ctx, 0, "", nil, "docker", "images", "--format", "{{.Repository}}:{{.Tag}} {{.CreatedAt}}", prefix)
	if err != nil {
		return nil, fmt.Errorf("Failed to list images: %v", err)
	}
	if !out.Success() {
		return nil, fmt.Errorf("docker images failed: %s", nginxLossy(out.Stderr))
	}
	type img struct{ ref, created string }
	var images []img
	for _, line := range nginxLines(nginxLossy(out.Stdout)) {
		line = strings.TrimSpace(line)
		ref, created, ok := strings.Cut(line, " ")
		if !ok || strings.HasSuffix(ref, ":latest") || !strings.HasPrefix(ref, prefix) {
			continue
		}
		images = append(images, img{ref, created})
	}
	// Newest first.
	sort.SliceStable(images, func(i, j int) bool { return images[i].created > images[j].created })
	removed := []string{}
	if len(images) > keep {
		for _, im := range images[keep:] {
			rm, err := deployRun(ctx, 0, "", nil, "docker", "rmi", im.ref)
			switch {
			case err != nil:
				slog.Warn(fmt.Sprintf("Failed to prune image %s: %v", im.ref, err))
			case rm.Success():
				slog.Info("Pruned image: " + im.ref)
				removed = append(removed, im.ref)
			default:
				slog.Warn(fmt.Sprintf("Failed to prune image %s: %s", im.ref, nginxLossy(rm.Stderr)))
			}
		}
	}
	return removed, nil
}

// gitBuildNodeInstallRun: the whitelisted install command for a detected
// Node.js project. yarn/pnpm are not on node:20-alpine's PATH but corepack is.
func gitBuildNodeInstallRun(override *string, def string) (string, bool) {
	if override != nil {
		switch *override {
		case "npm install", "npm ci":
			return "RUN " + *override, true
		case "yarn install", "pnpm install":
			return "RUN corepack enable && " + *override, true
		}
	}
	return def, false
}

// gitBuildPipInstallRun: the default's --no-cache-dir is dropped when the
// operator's exact whitelisted string is used, so what they typed is what runs.
func gitBuildPipInstallRun(override *string, def string) (string, bool) {
	if override != nil && (*override == "pip install -r requirements.txt" || *override == "pip3 install -r requirements.txt") {
		return "RUN " + *override, true
	}
	return def, false
}

// GitBuildAutoGenerateDockerfile detects the language and writes a Dockerfile
// when none exists, optionally splicing a whitelisted install command (already
// checked against ALLOWED_PRE_BUILD by the route) in as a RUN line. That text
// only ever reaches a Dockerfile `docker build` executes — never a host shell.
//
// Returns (dockerfile path, whether the override applied, a note explaining a
// non-applied override or nil).
func GitBuildAutoGenerateDockerfile(name, dockerfilePath, buildContext string, override *string) (string, bool, *string, error) {
	deployDir := gitBuildBaseDir + "/" + name
	contextDir := deployDir
	if buildContext != "." {
		contextDir = deployDir + "/" + buildContext
	}
	has := func(f string) bool { return gitBuildExists(filepath.Join(contextDir, f)) }

	// Never splice into a Dockerfile we don't own — there is no way to know
	// where an install step belongs relative to its own COPY lines.
	if has(dockerfilePath) {
		var note *string
		if override != nil {
			note = gitBuildStr("repo already has a Dockerfile — add the install step as a RUN line there")
		}
		return dockerfilePath, false, note, nil
	}
	slog.Info(fmt.Sprintf("No Dockerfile found at %s in %s, auto-detecting...", dockerfilePath, contextDir))

	applied := false
	var note *string
	var generated string
	switch {
	case has("package.json"):
		pkgBytes, _ := os.ReadFile(filepath.Join(contextDir, "package.json"))
		pkg := string(pkgBytes)
		var install string
		switch {
		case strings.Contains(pkg, `"next"`):
			install, applied = gitBuildNodeInstallRun(override, "RUN npm install")
			generated = "FROM node:20-alpine AS builder\nWORKDIR /app\nCOPY package*.json ./\n" + install + "\nCOPY . .\nRUN npm run build\n\nFROM node:20-alpine\nWORKDIR /app\nCOPY --from=builder /app/.next ./.next\nCOPY --from=builder /app/node_modules ./node_modules\nCOPY --from=builder /app/package.json ./\nCOPY --from=builder /app/public ./public\nEXPOSE 3000\nCMD [\"npm\", \"start\"]\n"
		case strings.Contains(pkg, `"nuxt"`):
			install, applied = gitBuildNodeInstallRun(override, "RUN npm install")
			generated = "FROM node:20-alpine AS builder\nWORKDIR /app\nCOPY package*.json ./\n" + install + "\nCOPY . .\nRUN npm run build\n\nFROM node:20-alpine\nWORKDIR /app\nCOPY --from=builder /app/.output ./.output\nEXPOSE 3000\nCMD [\"node\", \".output/server/index.mjs\"]\n"
		case strings.Contains(pkg, `"build"`):
			// Generic Node.js with a build step (SPA/React/Vue).
			install, applied = gitBuildNodeInstallRun(override, "RUN npm install")
			generated = "FROM node:20-alpine AS builder\nWORKDIR /app\nCOPY package*.json ./\n" + install + "\nCOPY . .\nRUN npm run build\n\nFROM nginx:alpine\nCOPY --from=builder /app/dist /usr/share/nginx/html\nEXPOSE 80\n"
		default:
			install, applied = gitBuildNodeInstallRun(override, "RUN npm install --omit=dev")
			generated = "FROM node:20-alpine\nWORKDIR /app\nCOPY package*.json ./\n" + install + "\nCOPY . .\nEXPOSE 3000\nCMD [\"node\", \"index.js\"]\n"
		}
	case has("requirements.txt"):
		reqBytes, _ := os.ReadFile(filepath.Join(contextDir, "requirements.txt"))
		reqs := strings.ToLower(string(reqBytes))
		var install string
		install, applied = gitBuildPipInstallRun(override, "RUN pip install --no-cache-dir -r requirements.txt")
		switch {
		case strings.Contains(reqs, "django"):
			generated = "FROM python:3.12-slim\nWORKDIR /app\nCOPY requirements.txt .\n" + install + "\nCOPY . .\nRUN python manage.py collectstatic --noinput 2>/dev/null || true\nEXPOSE 8000\nCMD [\"gunicorn\", \"--bind\", \"0.0.0.0:8000\", \"--workers\", \"2\", \"config.wsgi:application\"]\n"
		case strings.Contains(reqs, "flask"):
			generated = "FROM python:3.12-slim\nWORKDIR /app\nCOPY requirements.txt .\n" + install + "\nCOPY . .\nEXPOSE 5000\nCMD [\"gunicorn\", \"--bind\", \"0.0.0.0:5000\", \"--workers\", \"2\", \"app:app\"]\n"
		default:
			generated = "FROM python:3.12-slim\nWORKDIR /app\nCOPY requirements.txt .\n" + install + "\nCOPY . .\nEXPOSE 8000\nCMD [\"python\", \"app.py\"]\n"
		}
	case has("go.mod"):
		// No ALLOWED_PRE_BUILD entry maps to this toolchain.
		if override != nil {
			note = gitBuildStr(fmt.Sprintf("'%s' has no matching install step for a Go project — ignored", *override))
		}
		generated = "FROM golang:1.24-alpine AS builder\nWORKDIR /app\nCOPY go.mod go.sum ./\nRUN go mod download\nCOPY . .\nRUN CGO_ENABLED=0 go build -o server .\n\nFROM alpine:3.20\nWORKDIR /app\nCOPY --from=builder /app/server .\nEXPOSE 8080\nCMD [\"./server\"]\n"
	case has("Cargo.toml"):
		// The default already IS the whitelisted command.
		applied = override != nil && *override == "cargo build --release"
		generated = "FROM rust:1.94-slim AS builder\nWORKDIR /app\nCOPY . .\nRUN cargo build --release\n\nFROM debian:bookworm-slim\nCOPY --from=builder /app/target/release/* /usr/local/bin/\nEXPOSE 8080\nCMD [\"app\"]\n"
	case has("composer.json"):
		// The installer bootstraps a global /usr/local/bin/composer so the
		// whitelisted "composer install" string is really what runs.
		install := "RUN composer install --no-dev --optimize-autoloader"
		if override != nil && *override == "composer install" {
			install, applied = "RUN composer install", true
		}
		generated = "FROM php:8.3-fpm-alpine\nRUN apk add --no-cache nginx\nWORKDIR /app\nCOPY . .\nRUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer\n" + install + "\nEXPOSE 80\nCMD [\"php\", \"-S\", \"0.0.0.0:80\", \"-t\", \"public\"]\n"
	case has("Gemfile"):
		install := "RUN bundle install --without development test"
		if override != nil && *override == "bundle install" {
			install, applied = "RUN bundle install", true
		}
		generated = "FROM ruby:3.3-slim\nWORKDIR /app\nCOPY Gemfile Gemfile.lock ./\n" + install + "\nCOPY . .\nEXPOSE 3000\nCMD [\"bundle\", \"exec\", \"rails\", \"server\", \"-b\", \"0.0.0.0\"]\n"
	case has("index.html"):
		// Static site — no install step exists.
		if override != nil {
			note = gitBuildStr(fmt.Sprintf("'%s' has no matching install step for a static site — ignored", *override))
		}
		generated = "FROM nginx:alpine\nCOPY . /usr/share/nginx/html\nEXPOSE 80\n"
	default:
		return "", false, nil, errors.New("No Dockerfile found and could not auto-detect project type. Supported: Node.js (package.json), Python (requirements.txt), Go (go.mod), Rust (Cargo.toml), PHP (composer.json), Ruby (Gemfile), Static (index.html)")
	}

	if override != nil && !applied && note == nil {
		note = gitBuildStr(fmt.Sprintf("'%s' doesn't apply to this project type — using the default install step", *override))
	}
	if err := os.WriteFile(filepath.Join(contextDir, "Dockerfile"), []byte(generated), 0o644); err != nil {
		return "", false, nil, fmt.Errorf("Failed to write generated Dockerfile: %v", nginxIOErr(err))
	}
	slog.Info(fmt.Sprintf("Auto-generated Dockerfile for %s in %s", name, contextDir))
	return "Dockerfile", applied, note, nil
}

// ── internal helpers ────────────────────────────────────────────────────

// gitBuildFound is what gitBuildFindContainer found — including who it says
// it belongs to: a name is not proof of ownership.
type gitBuildFound struct {
	id       string
	domain   *string
	hostPort *uint16
	owner    OwnershipOwner
}

func gitBuildFindContainer(ctx context.Context, docker *client.Client, containerName string, scope OwnershipGitScope) *gitBuildFound {
	list, err := docker.ContainerList(ctx, client.ContainerListOptions{
		All: true, Filters: make(client.Filters).Add("name", containerName),
	})
	if err != nil {
		return nil
	}
	// The name filter matches substrings; require the exact name.
	for _, c := range list.Items {
		exact := false
		for _, n := range c.Names {
			if strings.TrimLeft(n, "/") == containerName {
				exact = true
			}
		}
		if !exact || c.ID == "" {
			continue
		}
		f := &gitBuildFound{id: c.ID}
		if d, ok := c.Labels["dockpanel.app.domain"]; ok {
			f.domain = &d
		}
		for _, p := range c.Ports {
			if p.PublicPort != 0 {
				pp := p.PublicPort
				f.hostPort = &pp
				break
			}
		}
		// A deploy is judged by its label alone; the port arguments exist for
		// the legacy-preview space, which nothing may CREATE in.
		f.owner = OwnershipGitContainer(c.Labels, scope, nil, f.hostPort)
		return f
	}
	return nil
}

// gitBuildClearBlueLeftover clears an interrupted swap's leftover, if it is
// ours to clear; an error means abort rather than build on a stranger's
// container.
func gitBuildClearBlueLeftover(ctx context.Context, docker *client.Client, blueName string) error {
	info, err := docker.ContainerInspect(ctx, blueName, client.ContainerInspectOptions{})
	if err != nil {
		return nil // nothing there
	}
	var labels map[string]string
	if info.Container.Config != nil {
		labels = info.Container.Config.Labels
	}
	if owner := OwnershipBlueLeftover(labels); !owner.MayDelete() {
		return fmt.Errorf("A container named %s exists and is not managed by DockPanel (%v); refusing to force-remove it to make room for a blue-green swap", blueName, owner)
	}
	t5 := 5
	_, _ = docker.ContainerStop(ctx, blueName, client.ContainerStopOptions{Timeout: &t5})
	_, _ = docker.ContainerRemove(ctx, blueName, client.ContainerRemoveOptions{Force: true})
	return nil
}

func gitBuildContainerConfig(image string, env []string, labels map[string]string, exposed network.PortSet) *container.Config {
	cfg := &container.Config{Image: image, ExposedPorts: exposed, Labels: labels}
	if len(env) > 0 {
		cfg.Env = env
	}
	return cfg
}

func gitBuildCreateAndStart(ctx context.Context, docker *client.Client, containerName, image string, env []string,
	labels map[string]string, exposed network.PortSet, hostConfig *container.HostConfig) (string, error) {
	created, err := docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: containerName, Config: gitBuildContainerConfig(image, env, labels, exposed), HostConfig: hostConfig,
	})
	if err != nil {
		return "", fmt.Errorf("Failed to create container: %v", err)
	}
	if _, err := docker.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		// Never ran, so its anonymous volumes are empty: remove them too.
		_, _ = docker.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
		return "", fmt.Errorf("Failed to start container: %v", err)
	}
	slog.Info(fmt.Sprintf("Container started: %s (%s)", containerName, created.ID[:min(12, len(created.ID))]))
	return created.ID, nil
}

// gitBuildSetupNginxProxy writes a plain proxy vhost for domain → hostPort.
func gitBuildSetupNginxProxy(templates *pongo2.TemplateSet, domain string, hostPort uint16) error {
	cfg := gitBuildProxyConfig(hostPort)
	rendered, err := NginxRenderSiteConfig(templates, domain, &cfg)
	if err != nil {
		return fmt.Errorf("Failed to render nginx config: %v", err)
	}
	// A deploy to a site the operator took offline updates its parked body,
	// so it stays off the internet until somebody enables it.
	target := NginxVhostTargetFor(domain)
	// Snapshot first — a preview synthesises {branch}.{domain} from a pushed
	// branch name, so this path may already be somebody else's, and `nginx -t`
	// is whole-server (an unrelated broken vhost can fail it).
	previous := gitBuildReadOpt(target.Path)
	if err := gitBuildWriteVhost(target.Path, rendered); err != nil {
		return err
	}
	if !target.Live {
		slog.Info(fmt.Sprintf("Site %s is disabled: the deploy updated its parked configuration (proxy -> port %d) and nginx was not reloaded", domain, hostPort))
		return nil
	}
	if out, err := NginxTestConfig(); err == nil && out.Success {
		_ = NginxReload()
		slog.Info(fmt.Sprintf("Nginx proxy configured for %s -> port %d", domain, hostPort))
		return nil
	}
	restored := NginxRestoreOrRemove(target.Path, previous)
	return fmt.Errorf("Nginx config test failed for %s%s", domain, NginxRestoreNote(restored))
}

// gitBuildBlueGreenUpdate is the zero-downtime update behind nginx: start the
// stand-in (OwnershipBlueName) on a temp port, health-check it, swap
// proxy_pass, test + reload nginx, then promote. Any failure rolls back
// (remove the stand-in, restore nginx).
func gitBuildBlueGreenUpdate(ctx context.Context, docker *client.Client, oldID, containerName, image string, env []string,
	labels map[string]string, containerPort, oldPort uint16, domain string, base *container.HostConfig) (GitBuildDeployResult, error) {
	tempPort, err := DockerAppsFindFreePort()
	if err != nil {
		return GitBuildDeployResult{}, err
	}
	slog.Info(fmt.Sprintf("Blue-green update for %s: old_port=%d, temp_port=%d", containerName, oldPort, tempPort))

	blueName := OwnershipBlueName(containerName)
	if err := gitBuildClearBlueLeftover(ctx, docker, blueName); err != nil {
		return GitBuildDeployResult{}, err
	}

	hc := gitBuildHostConfig(containerPort, tempPort)
	hc.Memory, hc.MemorySwap, hc.CPUPeriod, hc.CPUQuota = base.Memory, base.MemorySwap, base.CPUPeriod, base.CPUQuota
	created, err := docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:       blueName,
		Config:     gitBuildContainerConfig(image, env, labels, network.PortSet{gitBuildPort(containerPort): {}}),
		HostConfig: hc,
	})
	if err != nil {
		return GitBuildDeployResult{}, fmt.Errorf("Failed to create blue container: %v", err)
	}
	newID := created.ID
	cleanup := func() {
		t5 := 5
		_, _ = docker.ContainerStop(ctx, newID, client.ContainerStopOptions{Timeout: &t5})
		_, _ = docker.ContainerRemove(ctx, newID, client.ContainerRemoveOptions{Force: true})
	}
	swapBack := func() { _ = DockerAppsSwapNginxProxyPort(domain, tempPort, oldPort) }

	if _, err := docker.ContainerStart(ctx, newID, client.ContainerStartOptions{}); err != nil {
		cleanup()
		return GitBuildDeployResult{}, fmt.Errorf("Failed to start blue container: %v", err)
	}
	if err := DockerAppsHealthCheckPort(ctx, tempPort, 30); err != nil {
		cleanup()
		return GitBuildDeployResult{}, fmt.Errorf("Blue container health check failed: %v", err)
	}
	if err := DockerAppsSwapNginxProxyPort(domain, oldPort, tempPort); err != nil {
		cleanup()
		return GitBuildDeployResult{}, fmt.Errorf("Nginx port swap failed: %v", err)
	}
	out, err := NginxTestConfig()
	switch {
	case err != nil:
		swapBack()
		cleanup()
		return GitBuildDeployResult{}, fmt.Errorf("Nginx test error: %v", err)
	case !out.Success:
		swapBack()
		cleanup()
		return GitBuildDeployResult{}, fmt.Errorf("Nginx config test failed: %s", out.Stderr)
	}
	if err := NginxReload(); err != nil {
		swapBack()
		cleanup()
		return GitBuildDeployResult{}, fmt.Errorf("Nginx reload failed: %v", err)
	}

	// Traffic now flows to the new container. Promote it — ORDER MATTERS. The
	// old order (destroy, then rename, both errors ignored) returned success
	// over a half-swapped host when the removal failed, arming the next deploy
	// to take the site down. So: free the name by a rename that destroys
	// nothing and can be undone; only once promotion is real is anything
	// removed.
	retired := containerName + ".retired"
	if _, err := docker.ContainerRename(ctx, oldID, client.ContainerRenameOptions{NewName: retired}); err != nil {
		swapBack()
		_ = NginxReload()
		cleanup()
		return GitBuildDeployResult{}, fmt.Errorf("Could not free the container name for promotion: %v. Rolled back — the previous container is still serving %s.", err, domain)
	}
	if _, err := docker.ContainerRename(ctx, newID, client.ContainerRenameOptions{NewName: containerName}); err != nil {
		// The name is free and the old container is untouched and running.
		_, _ = docker.ContainerRename(ctx, oldID, client.ContainerRenameOptions{NewName: containerName})
		swapBack()
		_ = NginxReload()
		cleanup()
		return GitBuildDeployResult{}, fmt.Errorf("Could not promote the new container: %v. Rolled back — the previous container is still serving %s.", err, domain)
	}

	// Promotion is committed; removing the retired container is housekeeping.
	t10 := 10
	_, _ = docker.ContainerStop(ctx, retired, client.ContainerStopOptions{Timeout: &t10})
	if _, err := docker.ContainerRemove(ctx, retired, client.ContainerRemoveOptions{Force: true}); err != nil {
		slog.Warn(fmt.Sprintf("Blue-green for %s promoted cleanly but %s could not be removed: %v. It is stopped and holds no port; remove it by hand.", containerName, retired, err))
	}
	slog.Info(fmt.Sprintf("Git app updated (blue-green, zero-downtime): %s, port %d -> %d", containerName, oldPort, tempPort))
	// Only the backend port changed — nothing new to report about TLS.
	return GitBuildDeployResult{ContainerID: newID, BlueGreen: true}, nil
}

// ── Nixpacks ────────────────────────────────────────────────────────────

// Where the agent keeps its own nixpacks copy and build cache. Both used to
// live outside the unit's ReadWritePaths (/usr/local/bin under
// ProtectSystem=strict), so the download failed "Read-only file system" and
// the Dockerfile-less path was unreachable on every hardened install.
const (
	gitBuildNixpacksDir       = "/var/lib/dockpanel/bin"
	gitBuildNixpacksBin       = "/var/lib/dockpanel/bin/nixpacks"
	gitBuildNixpacksCacheRoot = "/var/lib/dockpanel/nixpacks-cache"
)

var (
	gitBuildNixpacksMu   sync.Mutex
	gitBuildNixpacksDone bool
	gitBuildNixpacksPath *string
)

func gitBuildNixpacksSet(p *string) *string {
	gitBuildNixpacksDone, gitBuildNixpacksPath = true, p
	return p
}

// gitBuildValidNixpacksVersion: strictly vN.N… — the tag lands in a URL that
// is interpolated into a shell command.
func gitBuildValidNixpacksVersion(v string) bool {
	if !strings.HasPrefix(v, "v") || !strings.Contains(v, ".") {
		return false
	}
	for _, c := range v[1:] {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// GitBuildEnsureNixpacks returns the nixpacks binary, downloading it on first
// use. The answer (including "unavailable") is cached for the process.
func GitBuildEnsureNixpacks(ctx context.Context) *string {
	gitBuildNixpacksMu.Lock()
	defer gitBuildNixpacksMu.Unlock()
	if gitBuildNixpacksDone {
		return gitBuildNixpacksPath
	}
	// Our own copy first: it is outside SafePath, so `which` cannot see it.
	if fi, err := os.Stat(gitBuildNixpacksBin); err == nil && fi.Mode().IsRegular() {
		return gitBuildNixpacksSet(gitBuildStr(gitBuildNixpacksBin))
	}
	// Operator-provided, system-wide.
	if out, err := deployRun(ctx, 0, "", nil, "which", "nixpacks"); err == nil && out.Success() {
		return gitBuildNixpacksSet(gitBuildStr(strings.TrimSpace(nginxLossy(out.Stdout))))
	}

	slog.Info("Nixpacks not found, downloading...")
	arch := "x86_64"
	if runtime.GOARCH == "arm64" {
		arch = "aarch64"
	}
	// Latest release tag (no hardcoded version), validated strictly.
	version := "v1.30.0"
	if out, err := deployRun(ctx, 0, "", nil, "sh", "-c",
		`curl -sI https://github.com/railwayapp/nixpacks/releases/latest | grep -i '^location:' | sed 's|.*/tag/||' | tr -d '\r\n'`); err == nil {
		if v := strings.TrimSpace(nginxLossy(out.Stdout)); gitBuildValidNixpacksVersion(v) {
			version = v
		}
	}
	url := fmt.Sprintf("https://github.com/railwayapp/nixpacks/releases/download/%s/nixpacks-%s-%s-unknown-linux-musl.tar.gz", version, version, arch)
	slog.Info(fmt.Sprintf("Downloading nixpacks %s from %s", version, url))
	out, err := deployRun(ctx, 0, "", nil, "sh", "-c", fmt.Sprintf(
		"mkdir -p %s && curl -fsSL '%s' | tar xz -C %s && chmod +x %s",
		gitBuildNixpacksDir, url, gitBuildNixpacksDir, gitBuildNixpacksBin))
	switch {
	case err != nil:
		slog.Warn(fmt.Sprintf("Failed to download nixpacks: %v", err))
		return gitBuildNixpacksSet(nil)
	case !out.Success():
		slog.Warn("Failed to download nixpacks: " + nginxLossy(out.Stderr))
		return gitBuildNixpacksSet(nil)
	}
	slog.Info("Nixpacks installed to " + gitBuildNixpacksBin)
	return gitBuildNixpacksSet(gitBuildStr(gitBuildNixpacksBin))
}

// GitBuildNixpacksBuild builds an image with nixpacks (no Dockerfile needed).
// Returns (image tag, build output).
func GitBuildNixpacksBuild(ctx context.Context, name, commitHash, buildContext string, envVars map[string]string) (string, string, error) {
	bin := GitBuildEnsureNixpacks(ctx)
	if bin == nil {
		return "", "", errors.New("Nixpacks not available")
	}
	if strings.Contains(buildContext, "..") {
		return "", "", errors.New("Build context must not contain path traversal (..)")
	}
	imageTag := fmt.Sprintf("dockpanel-git-%s:%s", name, commitHash)
	contextDir := fmt.Sprintf("%s/%s/%s", gitBuildBaseDir, name, buildContext)
	cacheDir := gitBuildNixpacksCacheRoot + "/" + name
	_ = os.MkdirAll(cacheDir, 0o755)

	args := []string{"build", contextDir, "--name", imageTag, "--cache-key", name}
	keys := make([]string, 0, len(envVars))
	for k := range envVars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "--env", k+"="+envVars[k])
	}
	slog.Info(fmt.Sprintf("Nixpacks build: %s from %s (cache: %s)", imageTag, contextDir, cacheDir))

	out, err := deployRun(ctx, 600*time.Second, "", []string{"NIXPACKS_CACHE_DIR=" + cacheDir}, *bin, args...)
	if errors.Is(err, deployErrTimeout) {
		return "", "", errors.New("Nixpacks build timed out (600s)")
	}
	if err != nil {
		return "", "", fmt.Errorf("Nixpacks build failed to start: %v", err)
	}
	full := nginxLossy(out.Stdout) + "\n" + nginxLossy(out.Stderr)
	if !out.Success() {
		return "", "", fmt.Errorf("Nixpacks build failed:\n%s", full)
	}
	_, _ = deployRun(ctx, 0, "", nil, "docker", "tag", imageTag, fmt.Sprintf("dockpanel-git-%s:latest", name))
	slog.Info("Nixpacks build succeeded: " + imageTag)
	return imageTag, full, nil
}
