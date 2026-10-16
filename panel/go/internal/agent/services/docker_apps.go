package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/sitelock"
)

// DockerAppsAppDataDir is where a template app's persistent volumes are
// bind-mounted from.
//
// Named once because three places have to agree: the deploy that creates the
// directory, the prefix check that keeps a volume from escaping it, and the
// removal that decides whether this container is entitled to delete it.
const DockerAppsAppDataDir = "/var/lib/dockpanel/apps"

// DockerAppsContainerNamePrefix is what DockerAppsDeployApp puts in front of
// an app's name to make its container name.
//
// Named for the same reason as the directory above: the two are NOT the same
// string, and every recreate path has an `info.name` (the container) in hand
// while every path that touches data needs the app. Confusing the two is what
// put a migrated app's data somewhere the panel could not find it — see
// dockerAppsAppDataName.
const DockerAppsContainerNamePrefix = "dockpanel-app-"

// dockerAppsConnect mirrors bollard's connect_with_local_defaults: a fresh
// client per call, configured from the environment.
func dockerAppsConnect() (*client.Client, error) {
	docker, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("Docker connect failed: %v", err)
	}
	return docker, nil
}

// ── Container auto-update detection ────────────────────────────────

// DockerAppsImageUpdateInfo is one row of GET /apps/update-check.
type DockerAppsImageUpdateInfo struct {
	ContainerID     string  `json:"container_id"`
	Name            string  `json:"name"`
	Image           string  `json:"image"`
	CurrentDigest   *string `json:"current_digest"`
	RemoteDigest    *string `json:"remote_digest"`
	UpdateAvailable bool    `json:"update_available"`
	CheckError      *string `json:"check_error"`
}

type dockerAppsImageRef struct {
	registry   string
	repository string
	tag        string
}

// dockerAppsParseImageRef parses a Docker image reference into registry,
// repository, tag. Examples:
//
//	"redis:7-alpine"         → registry-1.docker.io / library/redis / 7-alpine
//	"grafana/grafana:latest" → registry-1.docker.io / grafana/grafana / latest
//	"ghcr.io/foo/bar:v1"     → ghcr.io / foo/bar / v1
func dockerAppsParseImageRef(image string) dockerAppsImageRef {
	// Strip any @sha256:... digest suffix
	image, _, _ = strings.Cut(image, "@")

	first, _, _ := strings.Cut(image, "/")
	hasRegistry := strings.Contains(image, "/") && (strings.Contains(first, ".") || strings.Contains(first, ":"))

	var reg, rest string
	switch {
	case hasRegistry:
		reg, rest, _ = strings.Cut(image, "/")
	case strings.Contains(image, "/"):
		reg, rest = "registry-1.docker.io", image
	default:
		reg, rest = "registry-1.docker.io", "library/"+image
	}

	repository, tag := rest, "latest"
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		repository, tag = rest[:i], rest[i+1:]
	}
	return dockerAppsImageRef{registry: reg, repository: repository, tag: tag}
}

// DockerAppsRegistryCredentialsFor looks up saved registry credentials for an
// image reference.
//
// `docker login` (agent route registry_login) runs through safecmd, which
// points DOCKER_CONFIG at safecmd.DockerConfigDir — so that is where a login
// actually lands, and every pull used to pass no credentials regardless,
// meaning a private-image template or compose deploy failed even immediately
// after a successful login. Returns nil for an unauthenticated/public pull.
func DockerAppsRegistryCredentialsFor(image string) *registry.AuthConfig {
	content, err := os.ReadFile(safecmd.DockerConfigDir + "/config.json")
	if err != nil {
		return nil
	}
	var config struct {
		Auths map[string]struct {
			Auth *string `json:"auth"`
		} `json:"auths"`
	}
	if json.Unmarshal(content, &config) != nil || config.Auths == nil {
		return nil
	}

	reg := dockerAppsParseImageRef(image).registry
	// dockerAppsParseImageRef resolves an unqualified image to
	// "registry-1.docker.io", but `docker login` (no host given) writes the
	// config under Docker Hub's legacy key — the two never match by equality.
	key := reg
	if reg == "registry-1.docker.io" || reg == "docker.io" {
		key = "https://index.docker.io/v1/"
	}

	entry, ok := config.Auths[key]
	if !ok {
		entry, ok = config.Auths[strings.TrimPrefix(strings.TrimPrefix(key, "https://"), "http://")]
	}
	if !ok || entry.Auth == nil {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(*entry.Auth)
	if err != nil {
		return nil
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return nil
	}
	return &registry.AuthConfig{Username: username, Password: password, ServerAddress: key}
}

// DockerAppsPullImage pulls image with the saved credentials for its registry
// and returns every error the pull reported (the request itself, or an
// errorDetail line in the progress stream) — the Go shape of draining
// bollard's create_image stream. Empty means the pull reported no error.
func DockerAppsPullImage(ctx context.Context, docker *client.Client, image string, creds *registry.AuthConfig) []string {
	opts := client.ImagePullOptions{}
	if creds != nil {
		buf, _ := json.Marshal(creds)
		opts.RegistryAuth = base64.URLEncoding.EncodeToString(buf)
	}
	resp, err := docker.ImagePull(ctx, image, opts)
	if err != nil {
		return []string{err.Error()}
	}
	defer resp.Close()
	var errs []string
	for msg, err := range resp.JSONMessages(ctx) {
		if err != nil {
			errs = append(errs, err.Error())
			break
		}
		if msg.Error != nil {
			errs = append(errs, msg.Error.Message)
		}
	}
	return errs
}

const dockerAppsManifestAccept = "application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json"

// dockerAppsRegistryDigest fetches the manifest digest from a Docker registry
// (Docker Hub, GHCR, or generic OCI).
func dockerAppsRegistryDigest(ctx context.Context, ref dockerAppsImageRef) (string, error) {
	hc := &http.Client{Timeout: 15 * time.Second}

	token := func(url, failMsg, parseMsg string) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", fmt.Errorf("%s: %v", failMsg, err)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return "", fmt.Errorf("%s: %v", failMsg, err)
		}
		defer resp.Body.Close()
		var t struct {
			Token *string `json:"token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
			return "", fmt.Errorf("%s: %v", parseMsg, err)
		}
		if t.Token == nil {
			return "", fmt.Errorf("%s: missing field `token`", parseMsg)
		}
		return *t.Token, nil
	}
	head := func(url, bearer, failMsg string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", failMsg, err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		req.Header.Set("Accept", dockerAppsManifestAccept)
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", failMsg, err)
		}
		resp.Body.Close()
		return resp, nil
	}

	switch ref.registry {
	case "registry-1.docker.io", "docker.io":
		// Docker Hub auth
		tok, err := token(fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", ref.repository),
			"Auth failed", "Auth parse")
		if err != nil {
			return "", err
		}
		resp, err := head(fmt.Sprintf("https://registry-1.docker.io/v2/%s/manifests/%s", ref.repository, ref.tag), tok, "Manifest fetch")
		if err != nil {
			return "", err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return "", fmt.Errorf("Registry HTTP %s", resp.Status)
		}
		return dockerAppsExtractDigest(resp)
	case "ghcr.io":
		// GitHub Container Registry
		tok, err := token(fmt.Sprintf("https://ghcr.io/token?service=ghcr.io&scope=repository:%s:pull", ref.repository),
			"GHCR auth", "GHCR auth parse")
		if err != nil {
			return "", err
		}
		resp, err := head(fmt.Sprintf("https://ghcr.io/v2/%s/manifests/%s", ref.repository, ref.tag), tok, "GHCR manifest")
		if err != nil {
			return "", err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return "", fmt.Errorf("GHCR HTTP %s", resp.Status)
		}
		return dockerAppsExtractDigest(resp)
	default:
		// Generic OCI registry — try anonymous access
		resp, err := head(fmt.Sprintf("https://%s/v2/%s/manifests/%s", ref.registry, ref.repository, ref.tag), "", "Registry")
		if err != nil {
			return "", err
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return "", errors.New("Auth required")
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return "", fmt.Errorf("HTTP %s", resp.Status)
		}
		return dockerAppsExtractDigest(resp)
	}
}

func dockerAppsExtractDigest(resp *http.Response) (string, error) {
	vals := resp.Header.Values("Docker-Content-Digest")
	if len(vals) == 0 {
		return "", errors.New("No digest header")
	}
	return vals[0], nil
}

// DockerAppsCheckImageUpdates checks all managed containers for available
// image updates by comparing local RepoDigests against registry manifests.
func DockerAppsCheckImageUpdates(ctx context.Context) ([]DockerAppsImageUpdateInfo, error) {
	docker, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("Docker connect: %v", err)
	}
	defer docker.Close()

	apps, err := DockerAppsListDeployedApps(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]DockerAppsImageUpdateInfo, 0, len(apps))

	for _, app := range apps {
		if app.Image == nil {
			noInfo := "No image info"
			results = append(results, DockerAppsImageUpdateInfo{
				ContainerID: app.ContainerID, Name: app.Name, Image: "unknown", CheckError: &noInfo,
			})
			continue
		}
		image := *app.Image

		// Get local image digest from RepoDigests
		var localDigest *string
		if info, err := docker.ImageInspect(ctx, image); err == nil && len(info.RepoDigests) > 0 {
			if _, d, ok := strings.Cut(info.RepoDigests[0], "@"); ok {
				localDigest = &d
			}
		}

		row := DockerAppsImageUpdateInfo{ContainerID: app.ContainerID, Name: app.Name, Image: image, CurrentDigest: localDigest}
		if digest, err := dockerAppsRegistryDigest(ctx, dockerAppsParseImageRef(image)); err == nil {
			row.RemoteDigest = &digest
			row.UpdateAvailable = localDigest != nil && *localDigest != digest
		} else {
			msg := err.Error()
			row.CheckError = &msg
		}
		results = append(results, row)
	}
	return results, nil
}

// dockerAppsTemplateDef is a catalogue row.
type dockerAppsTemplateDef struct {
	ID            string
	Name          string
	Description   string
	Category      string
	Image         string
	DefaultPort   uint16
	ContainerPort string
	EnvVars       []dockerAppsEnvVarDef
	Volumes       []string
}

type dockerAppsEnvVarDef struct {
	Name     string
	Label    string
	Default  string
	Required bool
	Secret   bool
}

// DockerAppsAppTemplate is the serializable template returned to API consumers.
type DockerAppsAppTemplate struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Category      string             `json:"category"`
	Image         string             `json:"image"`
	DefaultPort   uint16             `json:"default_port"`
	ContainerPort string             `json:"container_port"`
	EnvVars       []DockerAppsEnvVar `json:"env_vars"`
	Volumes       []string           `json:"volumes"`
	// True when the template materially benefits from GPU passthrough
	// (LLM/diffusion/ASR inference). The frontend badges the card and
	// pre-ticks the GPU toggle on the deploy form.
	GpuRecommended bool `json:"gpu_recommended"`
}

// dockerAppsGpuRecommendedTemplates: template IDs whose container materially
// benefits from GPU passthrough. A keyed list instead of a per-template field
// to avoid touching every catalogue row when this set evolves.
var dockerAppsGpuRecommendedTemplates = []string{
	"ollama",
	"localai",
	"vllm",
	"stable-diffusion-webui",
	"text-generation-webui",
	"whisper",
}

// dockerAppsDomainEnv is what a domain-derived env var should be filled in
// with.
//
// The variants are the shapes real apps ask for, and they are not
// interchangeable: n8n wants the bare host in N8N_HOST and a full URL in
// WEBHOOK_URL, and drone splits host and scheme across two variables the same
// way. A single "the app's URL" variant would be wrong for four of the eleven
// entries below.
type dockerAppsDomainEnv int

const (
	// Bare hostname — `example.com`.
	dockerAppsDomainEnvHost dockerAppsDomainEnv = iota
	// `https` or `http`, as a word.
	dockerAppsDomainEnvScheme
	// `https://example.com`, no trailing slash.
	dockerAppsDomainEnvURL
	// `https://example.com/`. Separate from Url because n8n concatenates
	// WEBHOOK_URL with a path and emits a double slash without it, while Ghost
	// rejects a trailing slash in `url`.
	dockerAppsDomainEnvURLSlash
	// Reverse-proxy hops between the client and the app.
	//
	// Always exactly 1: DockerAppsDeployApp binds every container to 127.0.0.1,
	// so the panel's own nginx is the only thing that can reach it, and that
	// nginx appends exactly one X-Forwarded-For entry (proxy.conf and
	// https.conf). An operator who puts Cloudflare in front adds a second entry;
	// the value still makes the app trust the proxy, it only shifts which entry
	// it reads as the client — right where it matters, imprecise where not.
	dockerAppsDomainEnvProxyHops
)

type dockerAppsDomainVar struct {
	name string
	kind dockerAppsDomainEnv
}

type dockerAppsDomainEnvEntry struct {
	templateID string
	vars       []dockerAppsDomainVar
}

// dockerAppsTemplateDomainEnv: env vars whose correct value is the domain the
// operator claimed on the deploy form.
//
// A keyed list rather than a per-template field for the reason given above
// dockerAppsGpuRecommendedTemplates.
//
// **Why this exists.** Every entry names a variable the app uses to build its
// OWN absolute URLs: webhook registrations, OAuth callbacks, password-reset
// links. Left at the catalogue's `localhost:<port>` default, the app comes up
// and serves fine — and every URL it hands out points somewhere the visitor's
// browser cannot follow. The deploy form has collected the domain all along;
// until this change the deploy used it for one container label and threw it
// away, and for n8n there was no field to retype it into (GitHub #111).
//
// An operator value that differs from the catalogue default always wins — see
// dockerAppsMergeDeployEnv. This only fills a field nobody filled in.
var dockerAppsTemplateDomainEnv = []dockerAppsDomainEnvEntry{
	// n8n declares no env vars at all, so all four of these are additions the
	// deploy form could not have offered. Without them n8n prints
	// `Editor is now accessible via: http://localhost:5678`, registers webhooks
	// against that address, and throws ERR_ERL_UNEXPECTED_X_FORWARDED_FOR on
	// every request because express-rate-limit does not trust the proxy.
	{"n8n", []dockerAppsDomainVar{
		{"N8N_HOST", dockerAppsDomainEnvHost},
		{"N8N_PROTOCOL", dockerAppsDomainEnvScheme},
		{"WEBHOOK_URL", dockerAppsDomainEnvURLSlash},
		{"N8N_PROXY_HOPS", dockerAppsDomainEnvProxyHops},
	}},
	{"ghost", []dockerAppsDomainVar{{"url", dockerAppsDomainEnvURL}}},
	{"plausible", []dockerAppsDomainVar{{"BASE_URL", dockerAppsDomainEnvURL}}},
	{"drone", []dockerAppsDomainVar{
		{"DRONE_SERVER_HOST", dockerAppsDomainEnvHost},
		{"DRONE_SERVER_PROTO", dockerAppsDomainEnvScheme},
	}},
	{"photoprism", []dockerAppsDomainVar{{"PHOTOPRISM_SITE_URL", dockerAppsDomainEnvURL}}},
	// Casdoor builds its OIDC issuer and OAuth redirect URLs from `origin`.
	{"casdoor", []dockerAppsDomainVar{{"origin", dockerAppsDomainEnvURL}}},
	{"graylog", []dockerAppsDomainVar{{"GRAYLOG_HTTP_EXTERNAL_URI", dockerAppsDomainEnvURLSlash}}},
}

func dockerAppsDomainEnvVars(templateID string) []dockerAppsDomainVar {
	for _, e := range dockerAppsTemplateDomainEnv {
		if e.templateID == templateID {
			return e.vars
		}
	}
	return nil
}

// dockerAppsNameValue is one (name, value) pair, kept ordered.
type dockerAppsNameValue struct{ name, value string }

// dockerAppsDomainEnvFor: the values dockerAppsTemplateDomainEnv resolves to
// for one deploy.
//
// `https` is not a guess. A claimed domain reaches the app through the panel's
// nginx either way: with external TLS the operator terminates TLS upstream, and
// without it the backend requests a certificate as part of the same deploy.
// Both paths are public https. The one optimistic case is a certificate that
// fails to issue — and an app on a domain with no certificate is already
// broken in more visible ways.
func dockerAppsDomainEnvFor(templateID, domain string) []dockerAppsNameValue {
	var out []dockerAppsNameValue
	for _, v := range dockerAppsDomainEnvVars(templateID) {
		var value string
		switch v.kind {
		case dockerAppsDomainEnvHost:
			value = domain
		case dockerAppsDomainEnvScheme:
			value = "https"
		case dockerAppsDomainEnvURL:
			value = "https://" + domain
		case dockerAppsDomainEnvURLSlash:
			value = "https://" + domain + "/"
		case dockerAppsDomainEnvProxyHops:
			value = "1"
		}
		out = append(out, dockerAppsNameValue{v.name, value})
	}
	return out
}

// dockerAppsMergeDeployEnv assembles a deploy's `KEY=value` list from the
// template's declared vars, what the operator submitted, and whatever
// dockerAppsDomainEnvFor derived. Pure so the precedence can be tested
// without Docker.
//
// Precedence, highest first:
//  1. An operator value that DIFFERS from the catalogue default — a deliberate
//     choice, and it wins even over a derived value.
//  2. The derived value, when this template has one for the name.
//  3. The operator's value (i.e. one equal to the default).
//  4. The catalogue default.
//
// Rule 1 is the load-bearing one. Without it, an operator who typed their own
// WEBHOOK_URL would have it silently overwritten by the domain — the same
// class of bug as shipping `localhost`, just pointing the other way.
func dockerAppsMergeDeployEnv(envVars []dockerAppsEnvVarDef, env map[string]string, derived []dockerAppsNameValue) []string {
	var envList []string
	declared := func(name string) bool {
		return slices.ContainsFunc(envVars, func(ev dockerAppsEnvVarDef) bool { return ev.Name == name })
	}
	for _, ev := range envVars {
		supplied, has := env[ev.Name]
		var value string
		if has && supplied != ev.Default {
			value = supplied
		} else {
			i := slices.IndexFunc(derived, func(d dockerAppsNameValue) bool { return d.name == ev.Name })
			switch {
			case i >= 0:
				value = derived[i].value
			case has:
				value = supplied
			default:
				value = ev.Default
			}
		}
		if value != "" {
			envList = append(envList, ev.Name+"="+value)
		}
	}
	// Include any extra env vars the user passed that aren't in the template.
	for k, v := range env {
		if !declared(k) {
			envList = append(envList, k+"="+v)
		}
	}
	// Derived vars the template does not declare at all. n8n is the reason
	// this loop exists: its catalogue row declares no env vars, so all four of
	// its domain-derived vars are additions no form field could have carried.
	// Skipped when the operator sent the key themselves — the extras loop
	// directly above already emitted it, and appending here as well would set
	// the variable twice.
	for _, d := range derived {
		if _, sent := env[d.name]; !declared(d.name) && !sent {
			envList = append(envList, d.name+"="+d.value)
		}
	}
	return envList
}

// dockerAppsIsDomainDerived: whether this template fills `name` in from the
// claimed domain — the flag the deploy form uses to tell the operator so,
// instead of showing a `localhost` default it is about to override.
func dockerAppsIsDomainDerived(templateID, name string) bool {
	return slices.ContainsFunc(dockerAppsDomainEnvVars(templateID), func(v dockerAppsDomainVar) bool { return v.name == name })
}

type dockerAppsTemplateCmdEntry struct {
	id   string
	args []string
}

// dockerAppsTemplateCmd: startup arguments for the templates whose image
// default CMD does not start a server. A keyed list rather than a
// per-template field for the reason given above
// dockerAppsGpuRecommendedTemplates.
//
// Absence is the meaningful default: an image whose entrypoint already serves
// must keep deciding its own startup, so upstream can change it without this
// catalogue silently overriding them.
//
// `minio` needs it because `minio/minio`'s default CMD is ["minio"], which
// prints usage and **exits 0**. Nothing crashes — the container simply has no
// supervised process, so `unless-stopped` restarts it forever at ExitCode 0
// (issue #101). `/data` is the path the template already mounts a volume at,
// so the served directory and the persisted directory are the same one; a
// `server` command pointed anywhere else would come up healthy and lose every
// object on restart.
var dockerAppsTemplateCmd = []dockerAppsTemplateCmdEntry{
	{"minio", []string{"server", "/data", "--console-address", ":9001"}},
	// Each entry below was established by RUNNING the image and observing it
	// both ways: with no command it exits, with this command it stays up and
	// answers on its port. `cloudflared`'s own default Cmd is ["version"], so
	// every deploy printed a version string and stopped; `tunnel run` reads
	// TUNNEL_TOKEN from the environment the template already collects, so the
	// token never has to reach the command line.
	{"cloudflared", []string{"tunnel", "run"}},
	{"ntfy", []string{"serve"}},
	{"trivy", []string{"server", "--listen", "0.0.0.0:8080"}},
	{"keycloak", []string{"start-dev"}},
	// Plausible's image entrypoint does not migrate. Upstream's own compose
	// file supplies this exact chain, and without it the app meets an empty
	// schema on first run. Copied verbatim from the compose published at the
	// version this catalogue now pins, not reconstructed from prose.
	{"plausible", []string{
		"sh",
		"-c",
		"/entrypoint.sh db createdb && /entrypoint.sh db migrate && /entrypoint.sh run",
	}},
}

// dockerAppsCatalogueCmdFor: the catalogue's command for whatever template a
// running container came from.
//
// A recreate has the container's RESOLVED Cmd in hand, which is the old
// image's default whenever the catalogue overrode nothing — so carrying that
// forward would pin a departing image's command onto its replacement. Going
// back to the template label instead gives the override where one exists and
// nothing where it does not, which is what lets the new image's own default
// apply.
func dockerAppsCatalogueCmdFor(labels map[string]string) []string {
	id, ok := labels["dockpanel.app.template"]
	if !ok {
		return nil
	}
	return dockerAppsTemplateCmdOf(id)
}

// dockerAppsTemplateCmdOf: the Cmd to give a template's container, if the
// catalogue overrides it (nil otherwise).
func dockerAppsTemplateCmdOf(id string) []string {
	for _, e := range dockerAppsTemplateCmd {
		if e.id == id {
			return slices.Clone(e.args)
		}
	}
	return nil
}

// dockerAppsDozzleProxyEnv: tecnativa/docker-socket-proxy's per-endpoint ACL,
// spelled out in full and deny-by-default rather than left to the image's own
// defaults — the same posture the deploy's `cap_drop: ALL` + explicit cap_add
// allowlist takes for every template container. CONTAINERS and INFO are the
// only two granted: Dozzle's entire purpose is listing containers and
// streaming their logs (CONTAINERS), and its client calls `GET /info` on every
// connect to populate the remote host's card and decide whether the host is
// "available" at all — verified live: with INFO=0 Dozzle logged `Failed to get
// docker info` on every deploy and reported the host `available:false`. /info
// returns daemon/host metadata only — no container, image or secret data — so
// granting it does not reopen the vector this sidecar exists to close.
// Nothing else Dozzle could ask for (exec, create, images/volumes/networks/
// swarm, or any POST at all) is enabled.
//
// ⚠ CONTAINERS=1 IS WIDER THAN "list and stream logs". The proxy's haproxy
// config grants it as a PATH PREFIX over the whole /containers/* family, so
// anything reachable on this sidecar's port also reaches
// `GET /containers/{id}/archive`, `/export`, `/attach/ws`, `/changes` and
// `/top`, none of which Dozzle calls. EXEC=0 stops a NEW process from being
// started, but reading files a running process already wrote is a materially
// different exposure EXEC=0 does not close. Accepted for now, not closed:
// narrowing it needs a custom haproxy.cfg keyed to a PINNED image version.
var dockerAppsDozzleProxyEnv = [][2]string{
	{"CONTAINERS", "1"},
	{"EVENTS", "1"},
	{"PING", "1"},
	{"VERSION", "1"},
	{"INFO", "1"},
	{"POST", "0"},
	{"EXEC", "0"},
	{"IMAGES", "0"},
	{"NETWORKS", "0"},
	{"VOLUMES", "0"},
	{"SERVICES", "0"},
	{"SWARM", "0"},
	{"SYSTEM", "0"},
	{"TASKS", "0"},
	{"BUILD", "0"},
	{"COMMIT", "0"},
	{"AUTH", "0"},
	{"SECRETS", "0"},
	{"CONFIGS", "0"},
	{"DISTRIBUTION", "0"},
	{"NODES", "0"},
	{"PLUGINS", "0"},
	{"SESSION", "0"},
	{"GRPC", "0"},
	{"ALLOW_START", "0"},
	{"ALLOW_STOP", "0"},
	{"ALLOW_RESTARTS", "0"},
	{"ALLOW_PAUSE", "0"},
	{"ALLOW_UNPAUSE", "0"},
}

// dockerAppsTemplateSidecar: templates whose catalogue entry alone cannot
// serve their purpose — they need a companion container holding a capability
// (Docker API access) this panel deliberately never hands the app container
// itself. A side table for the same reason dockerAppsTemplateCmd is one.
var dockerAppsTemplateSidecar = map[string]*AppSidecarSidecarDef{
	"dozzle": {
		// Pinned, not :latest — verified equal digests at pin time, so this is
		// a reproducibility change only: a proxy sitting in front of the Docker
		// socket is exactly the kind of thing that should not silently change
		// underneath a deploy.
		Image:        "tecnativa/docker-socket-proxy:v0.5.0",
		Alias:        "dockerproxy",
		Port:         2375,
		ProxyEnv:     dockerAppsDozzleProxyEnv,
		ClientEnvVar: "DOZZLE_REMOTE_HOST",
	},
}

// dockerAppsTemplateSidecarOf: the sidecar a template needs, if any.
func dockerAppsTemplateSidecarOf(id string) *AppSidecarSidecarDef {
	return dockerAppsTemplateSidecar[id]
}

// dockerAppsCatalogueSidecarFor: the sidecar a running container's template
// needs, read from the `dockpanel.app.template` label rather than the
// container's live network attachments — the panel's CURRENT policy for the
// template, not whatever the container happens to be doing right now.
func dockerAppsCatalogueSidecarFor(labels map[string]string) *AppSidecarSidecarDef {
	id, ok := labels["dockpanel.app.template"]
	if !ok {
		return nil
	}
	return dockerAppsTemplateSidecarOf(id)
}

// dockerAppsReattachSidecarIfAny attaches envList / the returned networking
// config to appName's sidecar network, if the template this container was
// deployed from has one — called from EVERY recreate path (update's
// stop/start fallback, blue-green, image change, env update), so an image swap
// or an env edit can never silently strand the app back on the default bridge,
// unable to resolve a sidecar it depends on. A no-op (nil, envList untouched)
// for every template without one.
func dockerAppsReattachSidecarIfAny(labels map[string]string, appName string, envList []string) ([]string, *network.NetworkingConfig) {
	sidecar := dockerAppsCatalogueSidecarFor(labels)
	if sidecar == nil {
		return envList, nil
	}
	envList = slices.DeleteFunc(envList, func(e string) bool { return strings.HasPrefix(e, sidecar.ClientEnvVar+"=") })
	envList = append(envList, sidecar.ClientEnvEntry())
	return envList, AppSidecarAttachConfig(appName)
}

// DockerAppsEnvVar is one deploy-form field.
type DockerAppsEnvVar struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Default  string `json:"default"`
	Required bool   `json:"required"`
	Secret   bool   `json:"secret"`
	// True when the deploy fills this in from the claimed domain, so the
	// deploy form can say so rather than presenting a `localhost` default it is
	// about to replace. See dockerAppsTemplateDomainEnv.
	DomainDerived bool `json:"domain_derived"`
}

// DockerAppsDeployResult is the outcome of a template deploy.
type DockerAppsDeployResult struct {
	ContainerID string `json:"container_id"`
	Name        string `json:"name"`
	Port        uint16 `json:"port"`
}

// DockerAppsUpdateResult is the outcome of POST /apps/{id}/update.
type DockerAppsUpdateResult struct {
	ContainerID string `json:"container_id"`
	BlueGreen   bool   `json:"blue_green"`
	// Container paths this update moved out of the writable layer and onto a
	// bind mount. Non-empty only for an app deployed before its template
	// declared the path — see DockerAppsMigrateUnmountedVolumes. Reported so
	// the operator learns their app just became durable.
	MigratedVolumes []string `json:"migrated_volumes"`
	// Host paths this update handed back to the uid the image runs as,
	// because an EARLIER release migrated them with `docker cp` and left every
	// file owned by root — see dockerAppsRepairRootOwnedVolumes. Non-empty only
	// on an install that was actually damaged.
	RepairedVolumes []string `json:"repaired_volumes"`
}

// DockerAppsDeployedApp is one row of GET /apps.
type DockerAppsDeployedApp struct {
	ContainerID string  `json:"container_id"`
	Name        string  `json:"name"`
	Template    string  `json:"template"`
	Status      string  `json:"status"`
	Port        *uint16 `json:"port"`
	Domain      *string `json:"domain"`
	// Whether this box serves `domain` over HTTPS, so the panel can link to
	// the scheme that actually answers instead of assuming https (issue #96 —
	// an operator terminating TLS upstream serves plain HTTP). Always false
	// when there is no domain.
	Ssl     bool     `json:"ssl"`
	Health  *string  `json:"health"`
	Image   *string  `json:"image"`
	Volumes []string `json:"volumes"`
	StackID *string  `json:"stack_id"`
	UserID  *string  `json:"user_id"`
}

// 79 of these entries pinned `:latest` — a deploy from the catalogue is not
// reproducible across two operators, or across the same operator's redeploy a
// month later, and the SSL/backup/scan machinery elsewhere in this project
// treats a container's image tag as meaningful metadata. 59 were re-pinned
// here to the SPECIFIC tag that resolves to the byte-identical manifest
// `:latest` already pointed to (every real per-architecture platform digest
// matched, attestation/SBOM sub-manifests excluded since those regenerate on
// every push independent of image content) — a zero-behavior-change pin,
// verified live against each registry, never guessed (a guessed version can
// be unpullable). The remaining 20 stay on `:latest` because no equivalent tag
// exists at all, checked live rather than assumed:
//   - erpnext, posthog, synapse: the registry's `:latest` build matches only a
//     branch/commit-hash tag (`develop`, `master`, a bare `sha-*`), never a
//     numbered release — pinning to one of those would look like a version
//     and mean nothing.
//   - activepieces, dashy, dify, flowise, focalboard, keydb, superset: no tag
//     in the registry (searched the 200 most-recently-pushed, or the full
//     history for smaller repos) shares `:latest`'s digest at all.
//   - audiobookshelf, changedetection, dragonflydb, homarr, homepage, huginn,
//     paperless-ngx, zipline: same, on ghcr.io/dragonflydb's own registry.
//   - curlimages/curl (the network-probe helper, not a catalogue template) was
//     deliberately left alone — a transient one-shot probe container is a
//     different risk profile from a long-running deployed app.
var dockerAppsTemplates = []dockerAppsTemplateDef{
	// WordPress, Drupal, Joomla, PrestaShop moved to Sites (native PHP install)
	{
		ID:            "ghost",
		Name:          "Ghost",
		Description:   "Professional publishing platform for blogs and newsletters",
		Category:      "CMS",
		Image:         "ghost:5",
		DefaultPort:   2368,
		ContainerPort: "2368/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{
				Name:     "url",
				Label:    "Site URL",
				Default:  "http://localhost:2368",
				Required: false,
				Secret:   false,
			},
			// Without these two the container could never start, and nothing here
			// said so. `ghost:5` sets NODE_ENV=production, and Ghost's production
			// default database client is MySQL — so a deploy dialled 127.0.0.1:3306
			// inside its own network namespace, got ECONNREFUSED, and exited 2. The
			// catalogue asked the operator for a Site URL and for nothing else, so
			// there was no field they could have filled in to prevent it.
			//
			// Measured, not reasoned: run as this catalogue declares it, the
			// container logs `connect ECONNREFUSED 127.0.0.1:3306` from
			// knex-migrator and stops. Ghost supports SQLite as a first-class
			// client, and the file below lands inside the volume this template
			// already persists — which is what the comment under `volumes` has
			// claimed all along.
			//
			// Left visible and editable rather than forced: an operator who wants
			// Ghost on a real MySQL changes these two fields instead of being
			// unable to.
			{
				Name:     "database__client",
				Label:    "Database Client",
				Default:  "sqlite3",
				Required: false,
				Secret:   false,
			},
			{
				Name:     "database__connection__filename",
				Label:    "SQLite Database File",
				Default:  "/var/lib/ghost/content/data/ghost.db",
				Required: false,
				Secret:   false,
			},
		},
		// Ghost keeps its database, themes and uploaded images here, and the image
		// declares it as a VOLUME. Undeclared, Docker satisfied that with an
		// ANONYMOUS volume — which `docker rm` leaves behind but the replacement
		// container never sees, so an update read as total data loss (#110).
		Volumes: []string{"/var/lib/ghost/content"},
	},
	{
		ID:            "azuracast",
		Name:          "AzuraCast",
		Description:   "Self-hosted web radio suite — station management, streaming, playlists, and listener stats in one all-in-one container",
		Category:      "Media",
		Image:         "ghcr.io/azuracast/azuracast:stable",
		DefaultPort:   8420,
		ContainerPort: "80/tcp",
		// AzuraCast runs its own MariaDB inside the container, and the database
		// refuses to initialise without a root password — it says so and stops.
		// The template declared NO environment at all, so there was no field an
		// operator could have filled in.
		//
		// Two failures were stacked here, and fixing either alone leaves it
		// broken: the empty bind mount over /var/azuracast also hid the fifteen
		// entries the image ships there, so supervisord could not even find the
		// paths it logs to. Seeding uncovered the database failure behind it.
		EnvVars: []dockerAppsEnvVarDef{{
			Name:     "MARIADB_ROOT_PASSWORD",
			Label:    "Database Root Password",
			Default:  "",
			Required: true,
			Secret:   true,
		}},
		Volumes: []string{"/var/azuracast"},
	},
	{
		ID:            "redis",
		Name:          "Redis",
		Description:   "In-memory data store for caching and message brokering",
		Category:      "Database",
		Image:         "redis:7-alpine",
		DefaultPort:   6379,
		ContainerPort: "6379/tcp",
		EnvVars:       nil,
		// The image declares /data as a VOLUME and Redis writes its RDB/AOF snapshots
		// there. This template is in the "Database" category and was the only one in it
		// with nothing declared, so every recreate started it from an empty dataset.
		Volumes: []string{"/data"},
	},
	{
		ID:            "adminer",
		Name:          "Adminer",
		Description:   "Lightweight database management UI supporting MySQL, PostgreSQL, SQLite",
		Category:      "Tools",
		Image:         "adminer:4",
		DefaultPort:   8081,
		ContainerPort: "8080/tcp",
		EnvVars:       nil,
		Volumes:       nil,
	},
	{
		ID:            "uptime-kuma",
		Name:          "Uptime Kuma",
		Description:   "Self-hosted monitoring tool with notifications and status pages",
		Category:      "Monitoring",
		Image:         "louislam/uptime-kuma:1",
		DefaultPort:   3001,
		ContainerPort: "3001/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/app/data"},
	},
	// Portainer withdrawn (v2.178.0) — same defect as Dozzle above: it needs the
	// host Docker socket to do anything (containers/images/volumes/networks
	// ARE the product) and `deploy_app` deliberately never mounts it. Unlike
	// Dozzle it does not crash-loop — its web UI starts and serves a login page
	// fine with no socket, then every real feature behind it fails — so it was
	// never caught by the weekly Template Census's start/respond check. See
	// FEATURES.md §Withdrawn Claims.
	{
		ID:            "n8n",
		Name:          "n8n",
		Description:   "Workflow automation tool with 200+ integrations",
		Category:      "Automation",
		Image:         "n8nio/n8n:1",
		DefaultPort:   5678,
		ContainerPort: "5678/tcp",
		// `N8N_BASIC_AUTH_USER` / `N8N_BASIC_AUTH_PASSWORD` used to live here. n8n
		// REMOVED basic auth in 1.0 and this template pins `n8nio/n8n:1`, so both were
		// inert — the deploy form offered an "Admin Password" field that protected
		// nothing and told the operator their instance was credentialed when it was
		// not. Ownership is established by creating the owner account on first visit.
		EnvVars: nil,
		// THE #110 PATH. n8n defaults to SQLite and keeps everything here —
		// database.sqlite (workflows, executions, the owner account), the credential
		// encryption key in .n8n/config, and any community nodes. The image declares NO
		// volume of its own, so with nothing declared here the whole lot lived in the
		// container's writable layer and `docker rm` deleted it: the reporter's n8n came
		// back at first-run state after pressing Update, and none of it was recoverable.
		Volumes: []string{"/home/node/.n8n"},
	},
	{
		ID:            "gitea",
		Name:          "Gitea",
		Description:   "Lightweight self-hosted Git service with issues, pull requests, and CI/CD",
		Category:      "Development",
		Image:         "gitea/gitea:1",
		DefaultPort:   3000,
		ContainerPort: "3000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data", "/etc/timezone"},
	},
	// ─── Databases ──────────────────────────────────────────────────
	{
		ID:            "postgres",
		Name:          "PostgreSQL",
		Description:   "Advanced open-source relational database",
		Category:      "Database",
		Image:         "postgres:16-alpine",
		DefaultPort:   5432,
		ContainerPort: "5432/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "POSTGRES_USER", Label: "Username", Default: "postgres", Required: true, Secret: false},
			{Name: "POSTGRES_PASSWORD", Label: "Password", Default: "", Required: true, Secret: true},
			{Name: "POSTGRES_DB", Label: "Database Name", Default: "app", Required: false, Secret: false},
		},
		Volumes: []string{"/var/lib/postgresql/data"},
	},
	{
		ID:            "mysql",
		Name:          "MySQL",
		Description:   "The world's most popular open-source relational database",
		Category:      "Database",
		Image:         "mysql:8",
		DefaultPort:   3306,
		ContainerPort: "3306/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "MYSQL_ROOT_PASSWORD", Label: "Root Password", Default: "", Required: true, Secret: true},
			{Name: "MYSQL_DATABASE", Label: "Database Name", Default: "app", Required: false, Secret: false},
			{Name: "MYSQL_USER", Label: "User", Default: "", Required: false, Secret: false},
			{Name: "MYSQL_PASSWORD", Label: "User Password", Default: "", Required: false, Secret: true},
		},
		Volumes: []string{"/var/lib/mysql"},
	},
	{
		ID:            "mariadb",
		Name:          "MariaDB",
		Description:   "Community-developed fork of MySQL with enhanced performance",
		Category:      "Database",
		Image:         "mariadb:11",
		DefaultPort:   3307,
		ContainerPort: "3306/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "MARIADB_ROOT_PASSWORD", Label: "Root Password", Default: "", Required: true, Secret: true},
			{Name: "MARIADB_DATABASE", Label: "Database Name", Default: "app", Required: false, Secret: false},
		},
		Volumes: []string{"/var/lib/mysql"},
	},
	{
		ID:            "mongo",
		Name:          "MongoDB",
		Description:   "Document-oriented NoSQL database for modern apps",
		Category:      "Database",
		Image:         "mongo:7",
		DefaultPort:   27017,
		ContainerPort: "27017/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "MONGO_INITDB_ROOT_USERNAME", Label: "Root Username", Default: "admin", Required: true, Secret: false},
			{Name: "MONGO_INITDB_ROOT_PASSWORD", Label: "Root Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/data/db"},
	},
	// ─── CMS & Content ──────────────────────────────────────────────
	{
		ID:            "directus",
		Name:          "Directus",
		Description:   "Open data platform — instant REST & GraphQL API for any SQL database",
		Category:      "CMS",
		Image:         "directus/directus:11",
		DefaultPort:   8055,
		ContainerPort: "8055/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "ADMIN_EMAIL", Label: "Admin Email", Default: "admin@example.com", Required: true, Secret: false},
			{Name: "ADMIN_PASSWORD", Label: "Admin Password", Default: "", Required: true, Secret: true},
			{Name: "SECRET", Label: "Secret Key", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/directus/uploads", "/directus/database"},
	},
	{
		ID:            "nextcloud",
		Name:          "Nextcloud",
		Description:   "Self-hosted productivity platform — files, calendar, contacts, and more",
		Category:      "Storage",
		Image:         "nextcloud:30",
		DefaultPort:   8082,
		ContainerPort: "80/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "NEXTCLOUD_ADMIN_USER", Label: "Admin Username", Default: "admin", Required: true, Secret: false},
			{Name: "NEXTCLOUD_ADMIN_PASSWORD", Label: "Admin Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/var/www/html"},
	},
	// ─── Monitoring & Analytics ─────────────────────────────────────
	{
		ID:            "grafana",
		Name:          "Grafana",
		Description:   "Open-source observability platform for metrics, logs, and traces",
		Category:      "Monitoring",
		Image:         "grafana/grafana:13.1",
		DefaultPort:   3002,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "GF_SECURITY_ADMIN_PASSWORD", Label: "Admin Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/var/lib/grafana"},
	},
	{
		ID:            "prometheus",
		Name:          "Prometheus",
		Description:   "Monitoring system and time-series database for metrics",
		Category:      "Monitoring",
		Image:         "prom/prometheus:v3",
		DefaultPort:   9090,
		ContainerPort: "9090/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/prometheus"},
	},
	{
		ID:          "plausible",
		Name:        "Plausible Analytics",
		Description: "Privacy-friendly alternative to Google Analytics",
		Category:    "Analytics",
		// Was `plausible/analytics:v2` — an image the publisher ABANDONED. Every
		// tag in that Docker Hub repository (`v2`, `v2.0`, `v2.0.0` and `latest`
		// alike) resolves to one digest last pushed on 2023-07-12, and nothing has
		// been published there since; the page carries no deprecation notice, so
		// it still reads as the current install path. Upstream moved to GHCR.
		Image:         "ghcr.io/plausible/community-edition:v3.2.1",
		DefaultPort:   8000,
		ContainerPort: "8000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "SECRET_KEY_BASE", Label: "Secret Key (64+ chars)", Default: "", Required: true, Secret: true},
			{Name: "BASE_URL", Label: "Site URL", Default: "http://localhost:8000", Required: true, Secret: false},
			// Plausible needs BOTH a Postgres and a ClickHouse, and this template
			// used to ask for neither. Its own `runtime.exs` defaults them to the
			// hostnames `plausible_db` and `plausible_events_db` — the service
			// names in upstream's compose file — which resolve to nothing in a
			// single-container deploy, so the app crashed on a connection pool
			// timeout and wrote an Erlang crash dump. The operator was never shown
			// a field that could have prevented it.
			//
			// Required and empty on purpose: there is no default that is not a
			// lie, and the deploy form makes a required field impossible to skip.
			{Name: "DATABASE_URL", Label: "PostgreSQL URL (required, external)", Default: "", Required: true, Secret: true},
			{Name: "CLICKHOUSE_DATABASE_URL", Label: "ClickHouse URL (required, external)", Default: "", Required: true, Secret: true},
		},
		Volumes: nil,
	},
	{
		ID:            "umami",
		Name:          "Umami",
		Description:   "Simple, privacy-focused website analytics",
		Category:      "Analytics",
		Image:         "ghcr.io/umami-software/umami:postgresql-v2.15.1",
		DefaultPort:   3003,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "DATABASE_URL", Label: "Postgres URL", Default: "", Required: true, Secret: true},
		},
		Volumes: nil,
	},
	{
		ID:            "matomo",
		Name:          "Matomo",
		Description:   "Google Analytics alternative that respects user privacy",
		Category:      "Analytics",
		Image:         "matomo:5",
		DefaultPort:   8083,
		ContainerPort: "80/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/var/www/html"},
	},
	// ─── Tools & Utilities ──────────────────────────────────────────
	{
		ID:            "pgadmin",
		Name:          "pgAdmin",
		Description:   "Web-based PostgreSQL management and administration tool",
		Category:      "Tools",
		Image:         "dpage/pgadmin4:8",
		DefaultPort:   5050,
		ContainerPort: "80/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PGADMIN_DEFAULT_EMAIL", Label: "Admin Email", Default: "admin@example.com", Required: true, Secret: false},
			{Name: "PGADMIN_DEFAULT_PASSWORD", Label: "Admin Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/var/lib/pgadmin"},
	},
	{
		ID:            "minio",
		Name:          "MinIO",
		Description:   "High-performance S3-compatible object storage",
		Category:      "Storage",
		Image:         "minio/minio:RELEASE.2025-09-07T16-13-09Z",
		DefaultPort:   9000,
		ContainerPort: "9000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "MINIO_ROOT_USER", Label: "Root User", Default: "minioadmin", Required: true, Secret: false},
			{Name: "MINIO_ROOT_PASSWORD", Label: "Root Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/data"},
	},
	{
		ID:            "vaultwarden",
		Name:          "Vaultwarden",
		Description:   "Lightweight Bitwarden-compatible password manager server",
		Category:      "Security",
		Image:         "vaultwarden/server:1.37.1",
		DefaultPort:   8084,
		ContainerPort: "80/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "ADMIN_TOKEN", Label: "Admin Token", Default: "", Required: false, Secret: true},
		},
		Volumes: []string{"/data"},
	},
	{
		ID:            "meilisearch",
		Name:          "Meilisearch",
		Description:   "Lightning-fast, typo-tolerant search engine",
		Category:      "Tools",
		Image:         "getmeili/meilisearch:v1",
		DefaultPort:   7700,
		ContainerPort: "7700/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "MEILI_MASTER_KEY", Label: "Master Key", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/meili_data"},
	},
	{
		ID:            "metabase",
		Name:          "Metabase",
		Description:   "Business intelligence and analytics dashboard builder",
		Category:      "Analytics",
		Image:         "metabase/metabase:v0.58-lts",
		DefaultPort:   3004,
		ContainerPort: "3000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/metabase-data"},
	},
	// ─── Communication ──────────────────────────────────────────────
	{
		ID:            "nocodb",
		Name:          "NocoDB",
		Description:   "Open-source Airtable alternative — turn any database into a spreadsheet",
		Category:      "Tools",
		Image:         "nocodb/nocodb:2026.08.2",
		DefaultPort:   8085,
		ContainerPort: "8080/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/usr/app/data"},
	},
	{
		ID:            "searxng",
		Name:          "SearXNG",
		Description:   "Privacy-respecting metasearch engine aggregating 70+ sources",
		Category:      "Tools",
		Image:         "searxng/searxng:latest",
		DefaultPort:   8086,
		ContainerPort: "8080/tcp",
		EnvVars:       nil,
		// SearXNG generates settings.yml — including its `secret_key` — into /etc/searxng
		// on first boot, and the image declares that path as a VOLUME. Only the config
		// half is declared here: /var/cache/searxng is a rebuildable cache and does not
		// need to survive anything.
		Volumes: []string{"/etc/searxng"},
	},
	{
		ID:            "jellyfin",
		Name:          "Jellyfin",
		Description:   "Free media server for movies, TV shows, music, and photos",
		Category:      "Media",
		Image:         "jellyfin/jellyfin:10",
		DefaultPort:   8096,
		ContainerPort: "8096/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/config", "/cache"},
	},
	{
		ID:            "code-server",
		Name:          "VS Code Server",
		Description:   "Run VS Code in the browser — full IDE accessible anywhere",
		Category:      "Development",
		Image:         "codercom/code-server:4.131.0",
		DefaultPort:   8443,
		ContainerPort: "8080/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PASSWORD", Label: "Access Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/home/coder"},
	},
	{
		ID:            "drone",
		Name:          "Drone CI",
		Description:   "Container-native CI/CD platform with pipeline-as-code",
		Category:      "Development",
		Image:         "drone/drone:2",
		DefaultPort:   8087,
		ContainerPort: "80/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "DRONE_SERVER_HOST", Label: "Server Host", Default: "localhost", Required: true, Secret: false},
			{Name: "DRONE_SERVER_PROTO", Label: "Protocol", Default: "http", Required: false, Secret: false},
			{Name: "DRONE_RPC_SECRET", Label: "RPC Secret", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/data"},
	},
	{
		ID:            "registry",
		Name:          "Docker Registry",
		Description:   "Private Docker image registry for storing and distributing container images",
		Category:      "Development",
		Image:         "registry:2",
		DefaultPort:   5000,
		ContainerPort: "5000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/var/lib/registry"},
	},
	{
		ID:            "mailpit",
		Name:          "Mailpit",
		Description:   "Email testing tool — catches outgoing emails for dev/testing",
		Category:      "Development",
		Image:         "axllent/mailpit:v1.30",
		DefaultPort:   8025,
		ContainerPort: "8025/tcp",
		EnvVars:       nil,
		Volumes:       nil,
	},
	{
		ID:            "pihole",
		Name:          "Pi-hole",
		Description:   "Network-wide ad blocker and DNS sinkhole",
		Category:      "Networking",
		Image:         "pihole/pihole:2024.07.0",
		DefaultPort:   8088,
		ContainerPort: "80/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "WEBPASSWORD", Label: "Web Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/etc/pihole", "/etc/dnsmasq.d"},
	},
	{
		ID:            "loki",
		Name:          "Grafana Loki",
		Description:   "Log aggregation system designed to work with Grafana",
		Category:      "Monitoring",
		Image:         "grafana/loki:3",
		DefaultPort:   3100,
		ContainerPort: "3100/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/loki"},
	},
	// ─── Wiki / Docs ─────────────────────────────────────────────
	{
		ID:            "wikijs",
		Name:          "Wiki.js",
		Description:   "Modern wiki engine with powerful features and beautiful interface",
		Category:      "Tools",
		Image:         "ghcr.io/requarks/wiki:2",
		DefaultPort:   3005,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "DB_TYPE", Label: "Database Type", Default: "sqlite", Required: false, Secret: false},
		},
		Volumes: []string{"/wiki/data"},
	},
	{
		ID:            "bookstack",
		Name:          "BookStack",
		Description:   "Simple, self-hosted platform for organizing and storing information",
		Category:      "Tools",
		Image:         "lscr.io/linuxserver/bookstack:26.05.4",
		DefaultPort:   6875,
		ContainerPort: "80/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "APP_URL", Label: "Application URL", Default: "", Required: true, Secret: false},
			{Name: "DB_HOST", Label: "Database Host", Default: "", Required: true, Secret: false},
			{Name: "DB_USER", Label: "Database User", Default: "bookstack", Required: false, Secret: false},
			{Name: "DB_PASS", Label: "Database Password", Default: "", Required: true, Secret: true},
			{Name: "DB_DATABASE", Label: "Database Name", Default: "bookstack", Required: false, Secret: false},
		},
		Volumes: []string{"/config"},
	},
	{
		ID:            "outline",
		Name:          "Outline",
		Description:   "Team knowledge base and wiki with a fast, beautiful editor",
		Category:      "Tools",
		Image:         "outlinewiki/outline:1.9",
		DefaultPort:   3006,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "SECRET_KEY", Label: "Secret Key", Default: "", Required: true, Secret: true},
			{Name: "URL", Label: "Application URL", Default: "", Required: true, Secret: false},
			{Name: "DATABASE_URL", Label: "Database URL", Default: "", Required: true, Secret: false},
			{Name: "REDIS_URL", Label: "Redis URL", Default: "redis://localhost:6379", Required: false, Secret: false},
		},
		Volumes: []string{"/var/lib/outline/data"},
	},
	// ─── Communication ───────────────────────────────────────────
	{
		ID:            "mattermost",
		Name:          "Mattermost",
		Description:   "Open-source Slack alternative for secure team collaboration",
		Category:      "Tools",
		Image:         "mattermost/mattermost-team-edition:release-11",
		DefaultPort:   8065,
		ContainerPort: "8065/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "MM_SQLSETTINGS_DATASOURCE", Label: "Database Connection String", Default: "", Required: true, Secret: false},
		},
		Volumes: []string{"/mattermost/config", "/mattermost/data", "/mattermost/logs"},
	},
	{
		ID:            "rocketchat",
		Name:          "Rocket.Chat",
		Description:   "Open-source team communication platform with channels, DMs, and video",
		Category:      "Tools",
		Image:         "rocketchat/rocket.chat:8.7.0",
		DefaultPort:   3007,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "MONGO_URL", Label: "MongoDB URL", Default: "", Required: true, Secret: false},
			{Name: "ROOT_URL", Label: "Root URL", Default: "", Required: true, Secret: false},
		},
		Volumes: []string{"/app/uploads"},
	},
	// ─── Media ───────────────────────────────────────────────────
	{
		ID:            "immich",
		Name:          "Immich",
		Description:   "High-performance self-hosted photo and video management",
		Category:      "Media",
		Image:         "ghcr.io/immich-app/immich-server:release",
		DefaultPort:   2283,
		ContainerPort: "3001/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "DB_HOSTNAME", Label: "Database Hostname", Default: "", Required: true, Secret: false},
			{Name: "DB_USERNAME", Label: "Database Username", Default: "immich", Required: false, Secret: false},
			{Name: "DB_PASSWORD", Label: "Database Password", Default: "", Required: true, Secret: true},
			{Name: "DB_DATABASE_NAME", Label: "Database Name", Default: "immich", Required: false, Secret: false},
			{Name: "REDIS_HOSTNAME", Label: "Redis Hostname", Default: "redis", Required: false, Secret: false},
		},
		Volumes: []string{"/usr/src/app/upload"},
	},
	{
		ID:            "photoprism",
		Name:          "PhotoPrism",
		Description:   "AI-powered photo management app for browsing, organizing, and sharing",
		Category:      "Media",
		Image:         "photoprism/photoprism:260728",
		DefaultPort:   2342,
		ContainerPort: "2342/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PHOTOPRISM_ADMIN_PASSWORD", Label: "Admin Password", Default: "", Required: true, Secret: true},
			{Name: "PHOTOPRISM_SITE_URL", Label: "Site URL", Default: "http://localhost:2342", Required: false, Secret: false},
		},
		Volumes: []string{"/photoprism/storage", "/photoprism/originals"},
	},
	// ─── Security ────────────────────────────────────────────────
	{
		ID:            "authentik",
		Name:          "Authentik",
		Description:   "Open-source identity provider with SSO, MFA, and user management",
		Category:      "Security",
		Image:         "ghcr.io/goauthentik/server:2024.12",
		DefaultPort:   9001,
		ContainerPort: "9000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "AUTHENTIK_SECRET_KEY", Label: "Secret Key", Default: "", Required: true, Secret: true},
			{Name: "AUTHENTIK_REDIS__HOST", Label: "Redis Host", Default: "redis", Required: false, Secret: false},
			{Name: "AUTHENTIK_POSTGRESQL__HOST", Label: "PostgreSQL Host", Default: "", Required: true, Secret: false},
			{Name: "AUTHENTIK_POSTGRESQL__PASSWORD", Label: "PostgreSQL Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/media", "/templates"},
	},
	{
		ID:            "keycloak",
		Name:          "Keycloak",
		Description:   "Open-source IAM with SSO, identity brokering, and social login. Requires 'start-dev' command override for dev mode.",
		Category:      "Security",
		Image:         "quay.io/keycloak/keycloak:26.7",
		DefaultPort:   8180,
		ContainerPort: "8080/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "KEYCLOAK_ADMIN", Label: "Admin Username", Default: "admin", Required: false, Secret: false},
			{Name: "KEYCLOAK_ADMIN_PASSWORD", Label: "Admin Password", Default: "", Required: true, Secret: true},
			{Name: "KC_DB", Label: "Database Type", Default: "postgres", Required: false, Secret: false},
			{Name: "KC_DB_URL", Label: "Database JDBC URL", Default: "", Required: true, Secret: false},
		},
		Volumes: nil,
	},
	{
		ID:            "casdoor",
		Name:          "Casdoor",
		Description:   "UI-first IAM / SSO server with OAuth 2.0, OIDC, SAML, CAS, LDAP and WebAuthn. Runs on SQLite by default; set the driver and data source for MySQL or PostgreSQL. First login is admin / 123 — change it immediately.",
		Category:      "Security",
		Image:         "casbin/casdoor:4.20.0",
		DefaultPort:   8007,
		ContainerPort: "8000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "driverName", Label: "Database Driver (sqlite, mysql, postgres)", Default: "sqlite", Required: false, Secret: false},
			{Name: "dataSourceName", Label: "Database Data Source", Default: "file:/data/casdoor.db?cache=shared", Required: false, Secret: false},
			{Name: "origin", Label: "Public URL", Default: "http://localhost:8007", Required: false, Secret: false},
		},
		Volumes: []string{"/data"},
	},
	// ─── Dev Tools ───────────────────────────────────────────────
	{
		ID:            "woodpecker",
		Name:          "Woodpecker CI",
		Description:   "Simple yet powerful CI/CD engine with great extensibility",
		Category:      "Development",
		Image:         "woodpeckerci/woodpecker-server:v3",
		DefaultPort:   8000,
		ContainerPort: "8000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "WOODPECKER_OPEN", Label: "Open Registration", Default: "true", Required: false, Secret: false},
			{Name: "WOODPECKER_ADMIN", Label: "Admin User", Default: "", Required: true, Secret: false},
			{Name: "WOODPECKER_HOST", Label: "Server Host URL", Default: "", Required: true, Secret: false},
			{Name: "WOODPECKER_AGENT_SECRET", Label: "Agent Secret", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/var/lib/woodpecker"},
	},
	{
		ID:            "sonarqube",
		Name:          "SonarQube",
		Description:   "Continuous code quality and security inspection platform",
		Category:      "Development",
		Image:         "sonarqube:10-community",
		DefaultPort:   9002,
		ContainerPort: "9000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "SONAR_JDBC_URL", Label: "JDBC URL", Default: "jdbc:h2:tcp://localhost/sonar", Required: false, Secret: false},
		},
		Volumes: []string{"/opt/sonarqube/data", "/opt/sonarqube/logs", "/opt/sonarqube/extensions"},
	},
	{
		ID:            "forgejo",
		Name:          "Forgejo",
		Description:   "Community-driven Git forge — lightweight Gitea fork with extra features",
		Category:      "Development",
		Image:         "codeberg.org/forgejo/forgejo:9",
		DefaultPort:   3009,
		ContainerPort: "3000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data", "/etc/timezone"},
	},
	// ─── Business / Productivity ─────────────────────────────────
	{
		ID:            "invoice-ninja",
		Name:          "Invoice Ninja",
		Description:   "Full-featured invoicing, payments, and expense tracking for freelancers",
		Category:      "Tools",
		Image:         "invoiceninja/invoiceninja:5",
		DefaultPort:   9003,
		ContainerPort: "80/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "APP_URL", Label: "Application URL", Default: "", Required: true, Secret: false},
			{Name: "APP_KEY", Label: "Application Key", Default: "", Required: true, Secret: true},
			{Name: "DB_HOST", Label: "Database Host", Default: "", Required: true, Secret: false},
			{Name: "DB_DATABASE", Label: "Database Name", Default: "ninja", Required: false, Secret: false},
			{Name: "DB_USERNAME", Label: "Database Username", Default: "ninja", Required: false, Secret: false},
			{Name: "DB_PASSWORD", Label: "Database Password", Default: "", Required: true, Secret: true},
		},
		// Confirmed on the published image (s449): the app root is
		// /var/www/app, not /var/app — the prior paths named a directory
		// that does not exist in the image at all, so `seed_volume_from_image`
		// (which only ever seeds an EMPTY bind) silently found nothing to
		// copy and every invoice-ninja deploy started with no `public`/
		// `storage` content Docker itself would otherwise have provided.
		// [[project_dockpanel_tech_debt_p185]] carry I.
		Volumes: []string{"/var/www/app/public", "/var/www/app/storage"},
	},
	{
		ID:            "erpnext",
		Name:          "ERPNext",
		Description:   "Open-source ERP for manufacturing, distribution, retail, and services",
		Category:      "Tools",
		Image:         "frappe/erpnext:latest",
		DefaultPort:   8080,
		ContainerPort: "8080/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/home/frappe/frappe-bench/sites"},
	},
	{
		ID:            "calcom",
		Name:          "Cal.com",
		Description:   "Open-source scheduling infrastructure for appointments and meetings",
		Category:      "Tools",
		Image:         "calcom/cal.com:v6.2.0",
		DefaultPort:   3010,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "DATABASE_URL", Label: "Database URL", Default: "", Required: true, Secret: false},
			{Name: "NEXTAUTH_SECRET", Label: "NextAuth Secret", Default: "", Required: true, Secret: true},
			{Name: "CALENDSO_ENCRYPTION_KEY", Label: "Encryption Key", Default: "", Required: true, Secret: true},
		},
		Volumes: nil,
	},
	// ─── Support ─────────────────────────────────────────────────
	{
		ID:            "chatwoot",
		Name:          "Chatwoot",
		Description:   "Open-source customer engagement platform with live chat and helpdesk",
		Category:      "Tools",
		Image:         "chatwoot/chatwoot:latest-ce",
		DefaultPort:   3011,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "SECRET_KEY_BASE", Label: "Secret Key Base", Default: "", Required: true, Secret: true},
			{Name: "FRONTEND_URL", Label: "Frontend URL", Default: "", Required: true, Secret: false},
			{Name: "POSTGRES_HOST", Label: "PostgreSQL Host", Default: "", Required: true, Secret: false},
			{Name: "POSTGRES_PASSWORD", Label: "PostgreSQL Password", Default: "", Required: true, Secret: true},
			{Name: "REDIS_URL", Label: "Redis URL", Default: "redis://redis:6379", Required: false, Secret: false},
		},
		Volumes: []string{"/app/storage"},
	},
	{
		ID:            "typebot",
		Name:          "Typebot",
		Description:   "Open-source chatbot builder with drag-and-drop visual editor",
		Category:      "Tools",
		Image:         "baptistearno/typebot-builder:2",
		DefaultPort:   3012,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "DATABASE_URL", Label: "Database URL", Default: "", Required: true, Secret: false},
			{Name: "NEXTAUTH_URL", Label: "NextAuth URL", Default: "", Required: true, Secret: false},
			{Name: "ENCRYPTION_SECRET", Label: "Encryption Secret", Default: "", Required: true, Secret: true},
		},
		Volumes: nil,
	},
	// Roundcube and Rspamd removed — use Mail → Webmail and Mail → Spam Filter instead
	// ─── AI / Machine Learning ──────────────────────────────────
	{
		ID:            "ollama",
		Name:          "Ollama",
		Description:   "Run large language models locally (Llama, Mistral, Gemma, Phi)",
		Category:      "AI",
		Image:         "ollama/ollama:0.33.3",
		DefaultPort:   11434,
		ContainerPort: "11434/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "OLLAMA_KEEP_ALIVE", Label: "Model idle timeout", Default: "5m", Required: false, Secret: false},
			{Name: "OLLAMA_NUM_PARALLEL", Label: "Max parallel requests", Default: "1", Required: false, Secret: false},
		},
		Volumes: []string{"/root/.ollama"},
	},
	{
		ID:            "open-webui",
		Name:          "Open WebUI",
		Description:   "ChatGPT-style web interface for Ollama and OpenAI-compatible APIs",
		Category:      "AI",
		Image:         "ghcr.io/open-webui/open-webui:main",
		DefaultPort:   3101,
		ContainerPort: "8080/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "OLLAMA_BASE_URL", Label: "Ollama URL", Default: "http://host.docker.internal:11434", Required: false, Secret: false},
		},
		Volumes: []string{"/app/backend/data"},
	},
	{
		ID:          "localai",
		Name:        "LocalAI",
		Description: "Self-hosted OpenAI-compatible API for running LLMs, image and audio generation",
		Category:    "AI",
		// GPU-aware default. Operators on CPU-only hosts can switch the image
		// to localai/localai:latest-cpu via the Image field on the deploy form.
		Image:         "localai/localai:latest-gpu-nvidia-cuda-12",
		DefaultPort:   8296,
		ContainerPort: "8080/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/build/models"},
	},
	// ─── Dashboards ─────────────────────────────────────────────
	{
		ID:            "homepage",
		Name:          "Homepage",
		Description:   "Highly customizable application dashboard with service integrations",
		Category:      "Tools",
		Image:         "ghcr.io/gethomepage/homepage:latest",
		DefaultPort:   3013,
		ContainerPort: "3000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/app/config"},
	},
	{
		ID:            "homarr",
		Name:          "Homarr",
		Description:   "Sleek server dashboard with drag-and-drop widgets and integrations",
		Category:      "Tools",
		Image:         "ghcr.io/homarr-labs/homarr:latest",
		DefaultPort:   7575,
		ContainerPort: "7575/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/appdata"},
	},
	{
		ID:            "dashy",
		Name:          "Dashy",
		Description:   "Feature-rich self-hosted dashboard for your homelab and cloud stack",
		Category:      "Tools",
		Image:         "lissy93/dashy:latest",
		DefaultPort:   4000,
		ContainerPort: "8080/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/app/user-data"},
	},
	// ─── Documents / Productivity ────────────────────────────────
	{
		ID:            "paperless-ngx",
		Name:          "Paperless-ngx",
		Description:   "Document management system that transforms physical documents into searchable archive",
		Category:      "Tools",
		Image:         "ghcr.io/paperless-ngx/paperless-ngx:latest",
		DefaultPort:   8010,
		ContainerPort: "8000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PAPERLESS_SECRET_KEY", Label: "Secret Key", Default: "", Required: true, Secret: true},
			{Name: "PAPERLESS_ADMIN_USER", Label: "Admin Username", Default: "admin", Required: false, Secret: false},
			{Name: "PAPERLESS_ADMIN_PASSWORD", Label: "Admin Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/usr/src/paperless/data", "/usr/src/paperless/media"},
	},
	{
		ID:            "stirling-pdf",
		Name:          "Stirling-PDF",
		Description:   "Self-hosted PDF manipulation tool with merge, split, convert, and OCR",
		Category:      "Tools",
		Image:         "frooodle/s-pdf:2.14.3",
		DefaultPort:   8182,
		ContainerPort: "8080/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/usr/share/tessdata", "/configs"},
	},
	{
		ID:            "actual-budget",
		Name:          "Actual Budget",
		Description:   "Privacy-focused local-first personal budgeting app",
		Category:      "Tools",
		Image:         "actualbudget/actual-server:26.9.0",
		DefaultPort:   5006,
		ContainerPort: "5006/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data"},
	},
	{
		ID:            "hedgedoc",
		Name:          "HedgeDoc",
		Description:   "Real-time collaborative Markdown editor for teams",
		Category:      "Tools",
		Image:         "quay.io/hedgedoc/hedgedoc:1.12.0",
		DefaultPort:   3014,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "CMD_DB_URL", Label: "Database URL", Default: "", Required: true, Secret: false},
			{Name: "CMD_SESSION_SECRET", Label: "Session Secret", Default: "", Required: true, Secret: true},
			{Name: "CMD_DOMAIN", Label: "Domain", Default: "", Required: false, Secret: false},
		},
		Volumes: []string{"/hedgedoc/public/uploads"},
	},
	{
		ID:            "vikunja",
		Name:          "Vikunja",
		Description:   "Open-source to-do and project management app (Todoist alternative)",
		Category:      "Tools",
		Image:         "vikunja/vikunja:2.6.0",
		DefaultPort:   3456,
		ContainerPort: "3456/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "VIKUNJA_SERVICE_JWTSECRET", Label: "JWT Secret", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/app/vikunja/files"},
	},
	{
		ID:            "memos",
		Name:          "Memos",
		Description:   "Privacy-first lightweight note-taking service (Google Keep alternative)",
		Category:      "Tools",
		Image:         "neosmemo/memos:stable",
		DefaultPort:   5230,
		ContainerPort: "5230/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/var/opt/memos"},
	},
	{
		ID:            "trilium",
		Name:          "Trilium Notes",
		Description:   "Hierarchical note-taking application with rich text, relations, and scripting",
		Category:      "Tools",
		Image:         "triliumnext/notes:v0.95.0",
		DefaultPort:   8383,
		ContainerPort: "8080/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/home/node/trilium-data"},
	},
	{
		ID:            "docuseal",
		Name:          "DocuSeal",
		Description:   "Open-source document signing platform (DocuSign alternative)",
		Category:      "Tools",
		Image:         "docuseal/docuseal:3.2.3",
		DefaultPort:   3015,
		ContainerPort: "3000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data"},
	},
	// ─── Media ──────────────────────────────────────────────────
	{
		ID:            "navidrome",
		Name:          "Navidrome",
		Description:   "Modern music server and streamer compatible with Subsonic/Airsonic clients",
		Category:      "Media",
		Image:         "deluan/navidrome:0.63.2",
		DefaultPort:   4533,
		ContainerPort: "4533/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data", "/music"},
	},
	{
		ID:            "audiobookshelf",
		Name:          "Audiobookshelf",
		Description:   "Self-hosted audiobook and podcast server with mobile apps",
		Category:      "Media",
		Image:         "ghcr.io/advplyr/audiobookshelf:latest",
		DefaultPort:   13378,
		ContainerPort: "80/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/config", "/metadata", "/audiobooks", "/podcasts"},
	},
	{
		ID:            "calibre-web",
		Name:          "Calibre-Web",
		Description:   "Web-based e-book library manager with OPDS feed and reading interface",
		Category:      "Media",
		Image:         "lscr.io/linuxserver/calibre-web:0.6.27",
		DefaultPort:   8283,
		ContainerPort: "8083/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PUID", Label: "User ID", Default: "1000", Required: false, Secret: false},
			{Name: "PGID", Label: "Group ID", Default: "1000", Required: false, Secret: false},
		},
		Volumes: []string{"/config", "/books"},
	},
	{
		ID:            "kavita",
		Name:          "Kavita",
		Description:   "Self-hosted digital library for manga, comics, and books",
		Category:      "Media",
		Image:         "jvmilazz0/kavita:0.9.1",
		DefaultPort:   5001,
		ContainerPort: "5000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/kavita/config", "/manga"},
	},
	{
		ID:            "plex",
		Name:          "Plex",
		Description:   "Media server for organizing and streaming movies, TV, music, and photos",
		Category:      "Media",
		Image:         "lscr.io/linuxserver/plex:1.43.3",
		DefaultPort:   32400,
		ContainerPort: "32400/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PUID", Label: "User ID", Default: "1000", Required: false, Secret: false},
			{Name: "PGID", Label: "Group ID", Default: "1000", Required: false, Secret: false},
			{Name: "PLEX_CLAIM", Label: "Plex Claim Token", Default: "", Required: false, Secret: true},
		},
		Volumes: []string{"/config", "/tv", "/movies"},
	},
	// ─── RSS / Link Management ──────────────────────────────────
	{
		ID:            "freshrss",
		Name:          "FreshRSS",
		Description:   "Self-hosted RSS feed aggregator with full-text search and mobile apps",
		Category:      "Tools",
		Image:         "freshrss/freshrss:1.29.1",
		DefaultPort:   8284,
		ContainerPort: "80/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/var/www/FreshRSS/data", "/var/www/FreshRSS/extensions"},
	},
	{
		ID:            "linkwarden",
		Name:          "Linkwarden",
		Description:   "Collaborative bookmark manager with archiving, tagging, and collections",
		Category:      "Tools",
		Image:         "ghcr.io/linkwarden/linkwarden:v2.16.2",
		DefaultPort:   3016,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "DATABASE_URL", Label: "Database URL", Default: "", Required: true, Secret: false},
			{Name: "NEXTAUTH_SECRET", Label: "NextAuth Secret", Default: "", Required: true, Secret: true},
			{Name: "NEXTAUTH_URL", Label: "NextAuth URL", Default: "", Required: true, Secret: false},
		},
		Volumes: []string{"/data/data"},
	},
	{
		ID:            "changedetection",
		Name:          "Changedetection.io",
		Description:   "Website change detection and monitoring with notifications",
		Category:      "Monitoring",
		Image:         "ghcr.io/dgtlmoon/changedetection.io:latest",
		DefaultPort:   5555,
		ContainerPort: "5000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/datastore"},
	},
	// ─── Recipes ────────────────────────────────────────────────
	{
		ID:            "tandoor",
		Name:          "Tandoor Recipes",
		Description:   "Recipe management and meal planning application",
		Category:      "Tools",
		Image:         "vabene1111/recipes:2.6.13",
		DefaultPort:   8285,
		ContainerPort: "8080/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "SECRET_KEY", Label: "Secret Key", Default: "", Required: true, Secret: true},
			{Name: "DB_ENGINE", Label: "DB Engine", Default: "django.db.backends.sqlite3", Required: false, Secret: false},
		},
		Volumes: []string{"/opt/recipes/mediafiles", "/opt/recipes/staticfiles"},
	},
	{
		ID:            "mealie",
		Name:          "Mealie",
		Description:   "Self-hosted recipe manager with meal planning, shopping lists, and API",
		Category:      "Tools",
		Image:         "ghcr.io/mealie-recipes/mealie:v3.25.1",
		DefaultPort:   9925,
		ContainerPort: "9000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "BASE_URL", Label: "Base URL", Default: "", Required: false, Secret: false},
		},
		Volumes: []string{"/app/data"},
	},
	// ─── Communication ──────────────────────────────────────────
	{
		ID:            "ntfy",
		Name:          "ntfy",
		Description:   "Simple push notification service using HTTP PUT/POST (UnifiedPush compatible)",
		Category:      "Tools",
		Image:         "binwiederhier/ntfy:v2.28.0",
		DefaultPort:   8286,
		ContainerPort: "80/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/var/cache/ntfy", "/etc/ntfy"},
	},
	{
		ID:            "gotify",
		Name:          "Gotify",
		Description:   "Simple server for sending and receiving push notifications via REST API",
		Category:      "Tools",
		Image:         "gotify/server:3.1.0",
		DefaultPort:   8287,
		ContainerPort: "80/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "GOTIFY_DEFAULTUSER_PASS", Label: "Admin Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/app/data"},
	},
	// ─── DNS ────────────────────────────────────────────────────
	{
		ID:            "adguard-home",
		Name:          "AdGuard Home",
		Description:   "Network-wide ad and tracker blocking DNS server with HTTPS filtering",
		Category:      "Networking",
		Image:         "adguard/adguardhome:v0.107.79",
		DefaultPort:   3017,
		ContainerPort: "3000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/opt/adguardhome/work", "/opt/adguardhome/conf"},
	},
	{
		ID:            "technitium-dns",
		Name:          "Technitium DNS",
		Description:   "Open-source authoritative and recursive DNS server with web admin panel",
		Category:      "Networking",
		Image:         "technitium/dns-server:15.4.0",
		DefaultPort:   5380,
		ContainerPort: "5380/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/etc/dns"},
	},
	// ─── Networking / Proxy ─────────────────────────────────────
	{
		ID:            "nginx-proxy-manager",
		Name:          "Nginx Proxy Manager",
		Description:   "Easy-to-use reverse proxy with free SSL and web-based management",
		Category:      "Networking",
		Image:         "jc21/nginx-proxy-manager:2.15.1",
		DefaultPort:   8181,
		ContainerPort: "81/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data", "/etc/letsencrypt"},
	},
	{
		ID:            "wireguard",
		Name:          "WireGuard",
		Description:   "Modern, fast VPN tunnel with easy configuration",
		Category:      "Networking",
		Image:         "lscr.io/linuxserver/wireguard:1.0.20260223",
		DefaultPort:   51820,
		ContainerPort: "51820/udp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PUID", Label: "User ID", Default: "1000", Required: false, Secret: false},
			{Name: "PGID", Label: "Group ID", Default: "1000", Required: false, Secret: false},
			{Name: "PEERS", Label: "Number of Peers", Default: "3", Required: false, Secret: false},
			{Name: "SERVERURL", Label: "Server URL/IP", Default: "", Required: true, Secret: false},
		},
		Volumes: []string{"/config"},
	},
	// ─── Monitoring (additional) ────────────────────────────────
	// Dozzle was withdrawn at v2.178.0 (#125 — it fatals with "Could not
	// connect to any Docker Engine" because `deploy_app` deliberately never
	// mounts the host Docker socket into any one-click app) and reinstated at
	// v2.179.0 behind a paired docker-socket-proxy sidecar instead — see
	// `TEMPLATE_SIDECAR` and `services::app_sidecar`. The socket is real, but
	// this container never touches it: the sidecar does, on a network
	// nothing else can reach.
	{
		ID:            "dozzle",
		Name:          "Dozzle",
		Description:   "Real-time Docker container log viewer with a clean web interface",
		Category:      "Monitoring",
		Image:         "amir20/dozzle:v10.9.2",
		DefaultPort:   9999,
		ContainerPort: "8080/tcp",
		EnvVars:       nil,
		Volumes:       nil,
	},
	{
		ID:            "glances",
		Name:          "Glances",
		Description:   "Cross-platform system monitoring tool with web interface and API",
		Category:      "Monitoring",
		Image:         "nicolargo/glances:latest-full",
		DefaultPort:   61208,
		ContainerPort: "61208/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "GLANCES_OPT", Label: "Glances Options", Default: "-w", Required: false, Secret: false},
		},
		Volumes: nil,
	},
	{
		ID:            "netdata",
		Name:          "Netdata",
		Description:   "Real-time infrastructure monitoring with zero configuration",
		Category:      "Monitoring",
		Image:         "netdata/netdata:stable",
		DefaultPort:   19999,
		ContainerPort: "19999/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/etc/netdata", "/var/lib/netdata", "/var/cache/netdata"},
	},
	// ─── Storage / Files ────────────────────────────────────────
	{
		ID:            "filebrowser",
		Name:          "File Browser",
		Description:   "Web-based file manager with sharing, users, and customization",
		Category:      "Storage",
		Image:         "filebrowser/filebrowser:v2.63.23",
		DefaultPort:   8288,
		ContainerPort: "80/tcp",
		EnvVars:       nil,
		// `/database`, not `/database/filebrowser.db` — the same file-declared-as-a
		// -volume mistake as Element Web, and here it got one step further before
		// failing: the container started, then exited with
		// `open /database/filebrowser.db: is a directory`.
		//
		// Repointed at the parent rather than dropped, because unlike Element Web
		// there IS something to keep here. File Browser creates its database
		// inside this directory, so mounting the directory persists the users,
		// shares and settings across an update — which is precisely what mounting
		// the file failed to do while looking like it did.
		Volumes: []string{"/srv", "/database"},
	},
	{
		ID:            "syncthing",
		Name:          "Syncthing",
		Description:   "Continuous file synchronization between devices (Dropbox alternative)",
		Category:      "Storage",
		Image:         "lscr.io/linuxserver/syncthing:2.1.3",
		DefaultPort:   8384,
		ContainerPort: "8384/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PUID", Label: "User ID", Default: "1000", Required: false, Secret: false},
			{Name: "PGID", Label: "Group ID", Default: "1000", Required: false, Secret: false},
		},
		Volumes: []string{"/config", "/data"},
	},
	// ─── Development (additional) ───────────────────────────────
	{
		ID:            "it-tools",
		Name:          "IT-Tools",
		Description:   "Collection of handy developer tools (JSON formatter, UUID generator, hash, base64, etc.)",
		Category:      "Development",
		Image:         "corentinth/it-tools:2024.10.22-7ca5933",
		DefaultPort:   8289,
		ContainerPort: "80/tcp",
		EnvVars:       nil,
		Volumes:       nil,
	},
	{
		ID:            "jenkins",
		Name:          "Jenkins",
		Description:   "Leading open-source CI/CD automation server",
		Category:      "Development",
		Image:         "jenkins/jenkins:lts",
		DefaultPort:   8290,
		ContainerPort: "8080/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/var/jenkins_home"},
	},
	// Woodpecker CI already exists above — skipped duplicate
	// ─── Databases (additional) ─────────────────────────────────
	{
		ID:            "clickhouse",
		Name:          "ClickHouse",
		Description:   "Column-oriented OLAP database for real-time analytics on large datasets",
		Category:      "Database",
		Image:         "clickhouse/clickhouse-server:26.8.2.7",
		DefaultPort:   8123,
		ContainerPort: "8123/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/var/lib/clickhouse", "/var/log/clickhouse-server"},
	},
	{
		ID:            "influxdb",
		Name:          "InfluxDB",
		Description:   "Time series database for metrics, events, and real-time analytics",
		Category:      "Database",
		Image:         "influxdb:2",
		DefaultPort:   8292,
		ContainerPort: "8086/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "DOCKER_INFLUXDB_INIT_MODE", Label: "Init Mode", Default: "setup", Required: false, Secret: false},
			{Name: "DOCKER_INFLUXDB_INIT_USERNAME", Label: "Admin Username", Default: "admin", Required: true, Secret: false},
			{Name: "DOCKER_INFLUXDB_INIT_PASSWORD", Label: "Admin Password", Default: "", Required: true, Secret: true},
			{Name: "DOCKER_INFLUXDB_INIT_ORG", Label: "Organization", Default: "myorg", Required: true, Secret: false},
			{Name: "DOCKER_INFLUXDB_INIT_BUCKET", Label: "Bucket Name", Default: "default", Required: true, Secret: false},
		},
		Volumes: []string{"/var/lib/influxdb2"},
	},
	{
		ID:            "valkey",
		Name:          "Valkey",
		Description:   "High-performance key/value datastore (community fork of Redis)",
		Category:      "Database",
		Image:         "valkey/valkey:8-alpine",
		DefaultPort:   6380,
		ContainerPort: "6379/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data"},
	},
	{
		ID:            "couchdb",
		Name:          "CouchDB",
		Description:   "Document-oriented NoSQL database with multi-master replication",
		Category:      "Database",
		Image:         "couchdb:3",
		DefaultPort:   5984,
		ContainerPort: "5984/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "COUCHDB_USER", Label: "Admin Username", Default: "admin", Required: true, Secret: false},
			{Name: "COUCHDB_PASSWORD", Label: "Admin Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/opt/couchdb/data"},
	},
	// ─── Security ───────────────────────────────────────────────
	{
		ID:            "crowdsec",
		Name:          "CrowdSec",
		Description:   "Collaborative security engine analyzing logs and sharing threat intelligence",
		Category:      "Security",
		Image:         "crowdsecurity/crowdsec:v1.8.1",
		DefaultPort:   6060,
		ContainerPort: "6060/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/etc/crowdsec", "/var/lib/crowdsec/data"},
	},
	// ─── Automation (additional) ────────────────────────────────
	{
		ID:            "node-red",
		Name:          "Node-RED",
		Description:   "Flow-based programming tool for wiring IoT, APIs, and online services",
		Category:      "Automation",
		Image:         "nodered/node-red:5.0.6",
		DefaultPort:   1880,
		ContainerPort: "1880/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data"},
	},
	{
		ID:            "activepieces",
		Name:          "Activepieces",
		Description:   "No-code workflow automation platform (Zapier alternative)",
		Category:      "Automation",
		Image:         "activepieces/activepieces:latest",
		DefaultPort:   8293,
		ContainerPort: "80/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "AP_ENGINE_EXECUTABLE_PATH", Label: "Engine Path", Default: "dist/packages/engine/main.js", Required: false, Secret: false},
			{Name: "AP_ENCRYPTION_KEY", Label: "Encryption Key", Default: "", Required: true, Secret: true},
			{Name: "AP_JWT_SECRET", Label: "JWT Secret", Default: "", Required: true, Secret: true},
			// Activepieces defaults to POSTGRES + a standalone Redis, neither of which
			// this single-container template deploys, so it could not start at all. The
			// embedded pair is what upstream documents for the one-container install —
			// and it is what makes the volume below meaningful, since PGLite is the
			// thing that writes into it. Both halves or neither.
			{Name: "AP_DB_TYPE", Label: "Database Mode", Default: "PGLITE", Required: false, Secret: false},
			{Name: "AP_REDIS_TYPE", Label: "Queue Mode", Default: "MEMORY", Required: false, Secret: false},
		},
		// PGLite's embedded Postgres and the local settings live here (AP_CONFIG_PATH
		// defaults to ~/.activepieces, and the image runs as root, so HOME is /root).
		Volumes: []string{"/root/.activepieces"},
	},
	// ─── CMS (additional) ───────────────────────────────────────
	{
		ID:            "wordpress-docker",
		Name:          "WordPress (Docker)",
		Description:   "World's most popular CMS as a Docker container with Apache and PHP",
		Category:      "CMS",
		Image:         "wordpress:6-apache",
		DefaultPort:   8294,
		ContainerPort: "80/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "WORDPRESS_DB_HOST", Label: "Database Host", Default: "", Required: true, Secret: false},
			{Name: "WORDPRESS_DB_USER", Label: "Database User", Default: "wordpress", Required: true, Secret: false},
			{Name: "WORDPRESS_DB_PASSWORD", Label: "Database Password", Default: "", Required: true, Secret: true},
			{Name: "WORDPRESS_DB_NAME", Label: "Database Name", Default: "wordpress", Required: true, Secret: false},
		},
		Volumes: []string{"/var/www/html"},
	},
	{
		ID:            "listmonk",
		Name:          "Listmonk",
		Description:   "High-performance self-hosted newsletter and mailing list manager",
		Category:      "CMS",
		Image:         "listmonk/listmonk:v6.2.0",
		DefaultPort:   9100,
		ContainerPort: "9000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "LISTMONK_app__address", Label: "Listen Address", Default: "0.0.0.0:9000", Required: false, Secret: false},
			{Name: "LISTMONK_db__host", Label: "DB Host", Default: "", Required: true, Secret: false},
			{Name: "LISTMONK_db__port", Label: "DB Port", Default: "5432", Required: false, Secret: false},
			{Name: "LISTMONK_db__user", Label: "DB User", Default: "listmonk", Required: false, Secret: false},
			{Name: "LISTMONK_db__password", Label: "DB Password", Default: "", Required: true, Secret: true},
			{Name: "LISTMONK_db__database", Label: "DB Name", Default: "listmonk", Required: false, Secret: false},
		},
		Volumes: []string{"/listmonk/uploads"},
	},
	// ─── Analytics (additional) ─────────────────────────────────
	{
		ID:            "shynet",
		Name:          "Shynet",
		Description:   "Privacy-friendly web analytics without cookies or JavaScript",
		Category:      "Analytics",
		Image:         "milesmcc/shynet:v0.13.1",
		DefaultPort:   8295,
		ContainerPort: "8080/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "DJANGO_SECRET_KEY", Label: "Secret Key", Default: "", Required: true, Secret: true},
			{Name: "DB_NAME", Label: "Database Name", Default: "shynet", Required: false, Secret: false},
		},
		Volumes: nil,
	},
	// ─── Image / Upload ─────────────────────────────────────────
	{
		ID:            "zipline",
		Name:          "Zipline",
		Description:   "ShareX/file upload server with URL shortening and image galleries",
		Category:      "Storage",
		Image:         "ghcr.io/diced/zipline:latest",
		DefaultPort:   3018,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "CORE_SECRET", Label: "Core Secret", Default: "", Required: true, Secret: true},
			{Name: "CORE_DATABASE_URL", Label: "Database URL", Default: "", Required: true, Secret: false},
		},
		Volumes: []string{"/zipline/uploads", "/zipline/public"},
	},
	// ─── Authentication ─────────────────────────────────────────
	{
		ID:            "authelia",
		Name:          "Authelia",
		Description:   "Single Sign-On and 2FA portal for securing web applications",
		Category:      "Security",
		Image:         "authelia/authelia:4.39.22",
		DefaultPort:   9091,
		ContainerPort: "9091/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/config"},
	},
	// ─── AI / Machine Learning (additional) ─────────────────────
	{
		ID:          "text-generation-webui",
		Name:        "Text Generation WebUI",
		Description: "Gradio web UI for running large language models (oobabooga)",
		Category:    "AI",
		// Pinned to stable default tag instead of nightly so deploys don't drift
		Image:         "atinoda/text-generation-webui:default",
		DefaultPort:   7861,
		ContainerPort: "7860/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "EXTRA_LAUNCH_ARGS", Label: "Extra Launch Args", Default: "--listen", Required: false, Secret: false},
		},
		Volumes: []string{"/app/models", "/app/characters", "/app/loras"},
	},
	{
		ID:            "whisper",
		Name:          "Whisper ASR",
		Description:   "OpenAI Whisper speech-to-text service with REST API",
		Category:      "AI",
		Image:         "onerahmet/openai-whisper-asr-webservice:v1.10.0",
		DefaultPort:   9300,
		ContainerPort: "9000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "ASR_MODEL", Label: "Model Size", Default: "base", Required: false, Secret: false},
		},
		Volumes: nil,
	},
	{
		ID:            "litellm",
		Name:          "LiteLLM Proxy",
		Description:   "Unified proxy for 100+ LLM APIs (OpenAI, Anthropic, Cohere, etc.)",
		Category:      "AI",
		Image:         "ghcr.io/berriai/litellm:main-latest",
		DefaultPort:   4100,
		ContainerPort: "4000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "LITELLM_MASTER_KEY", Label: "Master API Key", Default: "", Required: true, Secret: true},
		},
		Volumes: nil,
	},
	{
		ID:            "flowise",
		Name:          "Flowise",
		Description:   "Drag-and-drop LLM flow builder for LangChain applications",
		Category:      "AI",
		Image:         "flowiseai/flowise:latest",
		DefaultPort:   3020,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "FLOWISE_USERNAME", Label: "Username", Default: "admin", Required: false, Secret: false},
			{Name: "FLOWISE_PASSWORD", Label: "Password", Default: "", Required: false, Secret: true},
		},
		Volumes: []string{"/root/.flowise"},
	},
	{
		ID:            "langflow",
		Name:          "Langflow",
		Description:   "Visual framework for building multi-agent and RAG applications",
		Category:      "AI",
		Image:         "langflowai/langflow:1.12.0",
		DefaultPort:   7862,
		ContainerPort: "7860/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "LANGFLOW_AUTO_LOGIN", Label: "Auto Login", Default: "false", Required: false, Secret: false},
		},
		Volumes: []string{"/app/langflow"},
	},
	{
		ID:            "dify",
		Name:          "Dify",
		Description:   "Open-source LLM app development platform with RAG, agents, and workflows",
		Category:      "AI",
		Image:         "langgenius/dify-api:latest",
		DefaultPort:   5002,
		ContainerPort: "5001/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "SECRET_KEY", Label: "Secret Key", Default: "", Required: true, Secret: true},
			{Name: "DB_USERNAME", Label: "Database Username", Default: "dify", Required: true, Secret: false},
			{Name: "DB_PASSWORD", Label: "Database Password", Default: "", Required: true, Secret: true},
			{Name: "DB_HOST", Label: "Database Host", Default: "localhost", Required: true, Secret: false},
			{Name: "REDIS_HOST", Label: "Redis Host", Default: "localhost", Required: false, Secret: false},
		},
		Volumes: []string{"/app/api/storage"},
	},
	{
		ID:            "vllm",
		Name:          "vLLM",
		Description:   "High-throughput, memory-efficient LLM inference server with OpenAI-compatible API",
		Category:      "AI",
		Image:         "vllm/vllm-openai:v0.28.0",
		DefaultPort:   8000,
		ContainerPort: "8000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "MODEL", Label: "Model (HuggingFace ID)", Default: "meta-llama/Llama-3.2-1B-Instruct", Required: true, Secret: false},
			{Name: "HUGGING_FACE_HUB_TOKEN", Label: "HuggingFace Token (gated models)", Default: "", Required: false, Secret: true},
		},
		Volumes: []string{"/root/.cache/huggingface"},
	},
	// ─── Databases (new) ────────────────────────────────────────
	{
		ID:            "surrealdb",
		Name:          "SurrealDB",
		Description:   "Multi-model database for web, mobile, serverless, and backend (SQL, graph, document)",
		Category:      "Database",
		Image:         "surrealdb/surrealdb:v3.2.4",
		DefaultPort:   8300,
		ContainerPort: "8000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "SURREAL_USER", Label: "Root Username", Default: "root", Required: true, Secret: false},
			{Name: "SURREAL_PASS", Label: "Root Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/data"},
	},
	{
		ID:            "questdb",
		Name:          "QuestDB",
		Description:   "High-performance time series database with SQL support and built-in web console",
		Category:      "Database",
		Image:         "questdb/questdb:10.0.1",
		DefaultPort:   9009,
		ContainerPort: "9000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/var/lib/questdb"},
	},
	{
		ID:            "timescaledb",
		Name:          "TimescaleDB",
		Description:   "PostgreSQL extension for time-series data with automatic partitioning",
		Category:      "Database",
		Image:         "timescale/timescaledb:latest-pg16",
		DefaultPort:   5433,
		ContainerPort: "5432/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "POSTGRES_USER", Label: "Username", Default: "postgres", Required: true, Secret: false},
			{Name: "POSTGRES_PASSWORD", Label: "Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/var/lib/postgresql/data"},
	},
	{
		ID:            "keydb",
		Name:          "KeyDB",
		Description:   "Multi-threaded fork of Redis with active replication and flash storage support",
		Category:      "Database",
		Image:         "eqalpha/keydb:latest",
		DefaultPort:   6381,
		ContainerPort: "6379/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data"},
	},
	{
		ID:            "dragonflydb",
		Name:          "DragonflyDB",
		Description:   "Modern in-memory datastore compatible with Redis and Memcached APIs",
		Category:      "Database",
		Image:         "docker.dragonflydb.io/dragonflydb/dragonfly:latest",
		DefaultPort:   6382,
		ContainerPort: "6379/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data"},
	},
	{
		ID:            "cassandra",
		Name:          "Apache Cassandra",
		Description:   "Distributed wide-column NoSQL database for high availability at scale",
		Category:      "Database",
		Image:         "cassandra:5",
		DefaultPort:   9042,
		ContainerPort: "9042/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "CASSANDRA_CLUSTER_NAME", Label: "Cluster Name", Default: "DockPanelCluster", Required: false, Secret: false},
		},
		Volumes: []string{"/var/lib/cassandra"},
	},
	{
		ID:            "neo4j",
		Name:          "Neo4j",
		Description:   "Leading graph database for connected data with Cypher query language",
		Category:      "Database",
		Image:         "neo4j:5",
		DefaultPort:   7474,
		ContainerPort: "7474/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "NEO4J_AUTH", Label: "Auth (user/pass)", Default: "neo4j/changeme", Required: true, Secret: true},
		},
		Volumes: []string{"/data", "/logs"},
	},
	{
		ID:            "arangodb",
		Name:          "ArangoDB",
		Description:   "Multi-model database combining document, graph, and key-value in one engine",
		Category:      "Database",
		Image:         "arangodb:3.12",
		DefaultPort:   8529,
		ContainerPort: "8529/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "ARANGO_ROOT_PASSWORD", Label: "Root Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/var/lib/arangodb3", "/var/lib/arangodb3-apps"},
	},
	// ─── Development (new) ──────────────────────────────────────
	{
		ID:            "gitness",
		Name:          "Gitness",
		Description:   "Open-source developer platform with Git hosting, pipelines, and code review (by Harness)",
		Category:      "Development",
		Image:         "harness/gitness:3.0.0-beta.11",
		DefaultPort:   3030,
		ContainerPort: "3000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data"},
	},
	{
		ID:            "verdaccio",
		Name:          "Verdaccio",
		Description:   "Lightweight private npm proxy registry for hosting and caching packages",
		Category:      "Development",
		Image:         "verdaccio/verdaccio:6",
		DefaultPort:   4873,
		ContainerPort: "4873/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/verdaccio/storage", "/verdaccio/conf"},
	},
	{
		ID:            "nexus",
		Name:          "Nexus Repository",
		Description:   "Universal artifact repository manager for Maven, npm, Docker, and more",
		Category:      "Development",
		Image:         "sonatype/nexus3:3.96.0",
		DefaultPort:   8320,
		ContainerPort: "8081/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/nexus-data"},
	},
	{
		ID:            "buildkite-agent",
		Name:          "Buildkite Agent",
		Description:   "CI/CD agent that runs build jobs from the Buildkite platform",
		Category:      "Development",
		Image:         "buildkite/agent:3",
		DefaultPort:   8301,
		ContainerPort: "8080/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "BUILDKITE_AGENT_TOKEN", Label: "Agent Token", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/buildkite/builds"},
	},
	// ─── Media (new) ────────────────────────────────────────────
	{
		ID:            "jellyseerr",
		Name:          "Jellyseerr",
		Description:   "Media request management for Jellyfin, Emby, and Plex with auto-approval",
		Category:      "Media",
		Image:         "fallenbagel/jellyseerr:2.7.3",
		DefaultPort:   5055,
		ContainerPort: "5055/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/app/config"},
	},
	{
		ID:            "overseerr",
		Name:          "Overseerr",
		Description:   "Media request management and discovery tool for Plex ecosystems",
		Category:      "Media",
		Image:         "lscr.io/linuxserver/overseerr:v1.35.0-ls158",
		DefaultPort:   5056,
		ContainerPort: "5055/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PUID", Label: "User ID", Default: "1000", Required: false, Secret: false},
			{Name: "PGID", Label: "Group ID", Default: "1000", Required: false, Secret: false},
		},
		Volumes: []string{"/config"},
	},
	{
		ID:            "bazarr",
		Name:          "Bazarr",
		Description:   "Companion app for Sonarr and Radarr to manage and download subtitles",
		Category:      "Media",
		Image:         "lscr.io/linuxserver/bazarr:1.6.0",
		DefaultPort:   6767,
		ContainerPort: "6767/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PUID", Label: "User ID", Default: "1000", Required: false, Secret: false},
			{Name: "PGID", Label: "Group ID", Default: "1000", Required: false, Secret: false},
		},
		Volumes: []string{"/config", "/movies", "/tv"},
	},
	{
		ID:            "prowlarr",
		Name:          "Prowlarr",
		Description:   "Indexer manager and proxy for Sonarr, Radarr, Lidarr, and Readarr",
		Category:      "Media",
		Image:         "lscr.io/linuxserver/prowlarr:2.5.2",
		DefaultPort:   9696,
		ContainerPort: "9696/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PUID", Label: "User ID", Default: "1000", Required: false, Secret: false},
			{Name: "PGID", Label: "Group ID", Default: "1000", Required: false, Secret: false},
		},
		Volumes: []string{"/config"},
	},
	{
		ID:            "radarr",
		Name:          "Radarr",
		Description:   "Movie collection manager with automatic downloading and organization",
		Category:      "Media",
		Image:         "lscr.io/linuxserver/radarr:6.3.0",
		DefaultPort:   7878,
		ContainerPort: "7878/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PUID", Label: "User ID", Default: "1000", Required: false, Secret: false},
			{Name: "PGID", Label: "Group ID", Default: "1000", Required: false, Secret: false},
		},
		Volumes: []string{"/config", "/movies", "/downloads"},
	},
	{
		ID:            "sonarr",
		Name:          "Sonarr",
		Description:   "TV series collection manager with automatic downloading and organization",
		Category:      "Media",
		Image:         "lscr.io/linuxserver/sonarr:4.0.19",
		DefaultPort:   8989,
		ContainerPort: "8989/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PUID", Label: "User ID", Default: "1000", Required: false, Secret: false},
			{Name: "PGID", Label: "Group ID", Default: "1000", Required: false, Secret: false},
		},
		Volumes: []string{"/config", "/tv", "/downloads"},
	},
	{
		ID:            "lidarr",
		Name:          "Lidarr",
		Description:   "Music collection manager with automatic downloading and metadata management",
		Category:      "Media",
		Image:         "lscr.io/linuxserver/lidarr:3.1.0",
		DefaultPort:   8686,
		ContainerPort: "8686/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PUID", Label: "User ID", Default: "1000", Required: false, Secret: false},
			{Name: "PGID", Label: "Group ID", Default: "1000", Required: false, Secret: false},
		},
		Volumes: []string{"/config", "/music", "/downloads"},
	},
	// The Readarr template was withdrawn s342. LinuxServer's image for it publishes
	// an OCI index with ZERO manifests on both of its tags — `docker pull` exits 1
	// with "no matching manifest for linux/amd64", while the Sonarr and Radarr
	// controls return four manifests each. The upstream project is archived, last
	// pushed 2025-06-27, so there is nothing to repoint to. Same call as the four
	// withdrawn in v2.96.0.
	//
	// ⚠ This shape is invisible to a classifier that keys on the manifest's HTTP
	// status: the request succeeds with 200 and a well-formed index that happens
	// to be empty. v2.96.0's sweep classified by error MESSAGE and could not see
	// it. Any future resolvability check has to assert the index is NON-EMPTY.
	//
	// The exact reference is deliberately not spelled here — this file is the
	// subject of pins that grep raw source, and a name written in a comment
	// silently satisfies the absence arm meant to keep it gone.
	{
		ID:            "tautulli",
		Name:          "Tautulli",
		Description:   "Monitoring and tracking tool for Plex Media Server usage and statistics",
		Category:      "Media",
		Image:         "lscr.io/linuxserver/tautulli:2.18.1",
		DefaultPort:   8183,
		ContainerPort: "8181/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "PUID", Label: "User ID", Default: "1000", Required: false, Secret: false},
			{Name: "PGID", Label: "Group ID", Default: "1000", Required: false, Secret: false},
		},
		Volumes: []string{"/config"},
	},
	// ─── Monitoring (new) ───────────────────────────────────────
	{
		ID:            "checkmk",
		Name:          "Checkmk",
		Description:   "Infrastructure and application monitoring with auto-discovery and alerting",
		Category:      "Monitoring",
		Image:         "checkmk/check-mk-raw:2.3.0-latest",
		DefaultPort:   8303,
		ContainerPort: "5000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "CMK_PASSWORD", Label: "Admin Password", Default: "", Required: true, Secret: true},
			{Name: "CMK_SITE_ID", Label: "Site ID", Default: "cmk", Required: false, Secret: false},
		},
		Volumes: []string{"/omd/sites"},
	},
	{
		ID:            "graylog",
		Name:          "Graylog",
		Description:   "Centralized log management and analysis platform with alerting",
		Category:      "Monitoring",
		Image:         "graylog/graylog:6.1",
		DefaultPort:   9200,
		ContainerPort: "9000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "GRAYLOG_PASSWORD_SECRET", Label: "Password Secret (16+ chars)", Default: "", Required: true, Secret: true},
			{Name: "GRAYLOG_ROOT_PASSWORD_SHA2", Label: "Root Password SHA256 Hash", Default: "", Required: true, Secret: true},
			{Name: "GRAYLOG_HTTP_EXTERNAL_URI", Label: "External URI", Default: "http://localhost:9000/", Required: true, Secret: false},
			{Name: "GRAYLOG_MONGODB_URI", Label: "MongoDB URI", Default: "mongodb://mongo:27017/graylog", Required: true, Secret: false},
			{Name: "GRAYLOG_ELASTICSEARCH_HOSTS", Label: "Elasticsearch Hosts", Default: "http://elasticsearch:9200", Required: true, Secret: false},
		},
		Volumes: []string{"/usr/share/graylog/data"},
	},
	{
		ID:            "vector",
		Name:          "Vector",
		Description:   "High-performance observability data pipeline for logs, metrics, and traces",
		Category:      "Monitoring",
		Image:         "timberio/vector:latest-alpine",
		DefaultPort:   8304,
		ContainerPort: "8686/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/etc/vector", "/var/lib/vector"},
	},
	// ─── Productivity (new) ─────────────────────────────────────
	{
		ID:            "leantime",
		Name:          "Leantime",
		Description:   "Open-source project management system for non-project managers (lean methodology)",
		Category:      "Productivity",
		Image:         "leantime/leantime:3.9.8",
		DefaultPort:   8305,
		ContainerPort: "80/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "LEAN_DB_HOST", Label: "Database Host", Default: "", Required: true, Secret: false},
			{Name: "LEAN_DB_USER", Label: "Database User", Default: "leantime", Required: true, Secret: false},
			{Name: "LEAN_DB_PASSWORD", Label: "Database Password", Default: "", Required: true, Secret: true},
			{Name: "LEAN_DB_DATABASE", Label: "Database Name", Default: "leantime", Required: false, Secret: false},
		},
		Volumes: []string{"/var/www/html/public/userfiles", "/var/www/html/userfiles"},
	},
	{
		ID:            "focalboard",
		Name:          "Focalboard",
		Description:   "Open-source project management tool (Trello/Notion/Asana alternative by Mattermost)",
		Category:      "Productivity",
		Image:         "mattermost/focalboard:latest",
		DefaultPort:   8306,
		ContainerPort: "8000/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/opt/focalboard/data"},
	},
	{
		ID:            "joplin-server",
		Name:          "Joplin Server",
		Description:   "Sync server for Joplin note-taking app with sharing and collaboration",
		Category:      "Productivity",
		Image:         "joplin/server:3.7.1",
		DefaultPort:   22300,
		ContainerPort: "22300/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "APP_BASE_URL", Label: "Base URL", Default: "", Required: true, Secret: false},
			{Name: "DB_CLIENT", Label: "DB Client", Default: "pg", Required: false, Secret: false},
			{Name: "POSTGRES_HOST", Label: "PostgreSQL Host", Default: "", Required: true, Secret: false},
			{Name: "POSTGRES_PORT", Label: "PostgreSQL Port", Default: "5432", Required: false, Secret: false},
			{Name: "POSTGRES_DATABASE", Label: "Database Name", Default: "joplin", Required: false, Secret: false},
			{Name: "POSTGRES_USER", Label: "Database User", Default: "joplin", Required: true, Secret: false},
			{Name: "POSTGRES_PASSWORD", Label: "Database Password", Default: "", Required: true, Secret: true},
		},
		Volumes: nil,
	},
	// ─── Communication (new) ────────────────────────────────────
	{
		ID:            "element-web",
		Name:          "Element Web",
		Description:   "Feature-rich Matrix client for secure, decentralized communication",
		Category:      "Communication",
		Image:         "vectorim/element-web:v1.12.27",
		DefaultPort:   8307,
		ContainerPort: "80/tcp",
		EnvVars:       nil,
		// Was `/app/config.json` — a FILE. Every volume path here becomes a host
		// DIRECTORY that is bind-mounted over the container path, so Docker was
		// asked to mount a directory onto a file and refused: the container could
		// not be CREATED at all, and the deploy failed before anything started.
		// That is the loudest failure in this catalogue and it survived every
		// audit, because reading the entry tells you nothing — the string looks
		// exactly like the ones that work.
		//
		// Dropped rather than repointed. Element Web is a static single-page app;
		// its config.json ships in the image and there is no user data at that
		// path to preserve, so there is nothing a volume here would persist.
		Volumes: nil,
	},
	{
		ID:            "synapse",
		Name:          "Matrix Synapse",
		Description:   "Reference Matrix homeserver for decentralized, encrypted messaging",
		Category:      "Communication",
		Image:         "matrixdotorg/synapse:latest",
		DefaultPort:   8308,
		ContainerPort: "8008/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "SYNAPSE_SERVER_NAME", Label: "Server Name", Default: "", Required: true, Secret: false},
			{Name: "SYNAPSE_REPORT_STATS", Label: "Report Stats", Default: "no", Required: false, Secret: false},
		},
		Volumes: []string{"/data"},
	},
	// ─── Networking (new) ───────────────────────────────────────
	{
		ID:          "traefik",
		Name:        "Traefik",
		Description: "Cloud-native reverse proxy and load balancer with automatic HTTPS",
		Category:    "Networking",
		Image:       "traefik:v3",
		DefaultPort: 8309,
		// 80, not 8080. Traefik with no configuration creates exactly ONE
		// entryPoint — `http` on :80 — and the :8080 one only exists when
		// `--api.insecure`, ping, prometheus or the REST provider asks for it.
		// None of those are set here, so nothing ever listened on 8080 and the
		// published port answered connection-refused forever. The image's own
		// Dockerfile declares EXPOSE 80 and nothing else.
		//
		// The tempting fix — a start command passing `--api.insecure=true` — is
		// the wrong one, and this panel already wrote down why: `traefik.rs`
		// passes exactly that flag for the panel's OWN managed Traefik, above a
		// comment whose safety argument is that the port is bound to 127.0.0.1
		// and cannot be reached from outside. A catalogue template can be given a
		// domain and put behind the proxy, which breaks precisely that condition,
		// so the flag would publish an unauthenticated admin API.
		ContainerPort: "80/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/etc/traefik", "/letsencrypt"},
	},
	{
		ID:            "caddy",
		Name:          "Caddy",
		Description:   "Powerful web server with automatic HTTPS and easy configuration",
		Category:      "Networking",
		Image:         "caddy:2-alpine",
		DefaultPort:   8310,
		ContainerPort: "80/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/etc/caddy", "/data", "/config"},
	},
	{
		ID:            "cloudflared",
		Name:          "Cloudflare Tunnel",
		Description:   "Secure tunnel to expose local services to the internet via Cloudflare",
		Category:      "Networking",
		Image:         "cloudflare/cloudflared:2026.8.3",
		DefaultPort:   8311,
		ContainerPort: "8080/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "TUNNEL_TOKEN", Label: "Tunnel Token", Default: "", Required: true, Secret: true},
		},
		Volumes: nil,
	},
	{
		ID:            "tailscale",
		Name:          "Tailscale",
		Description:   "Zero-config mesh VPN built on WireGuard for secure private networking",
		Category:      "Networking",
		Image:         "tailscale/tailscale:v1.102.3",
		DefaultPort:   8312,
		ContainerPort: "41641/udp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "TS_AUTHKEY", Label: "Auth Key", Default: "", Required: true, Secret: true},
			{Name: "TS_HOSTNAME", Label: "Hostname", Default: "dockpanel", Required: false, Secret: false},
		},
		Volumes: []string{"/var/lib/tailscale"},
	},
	// ─── Storage (new) ──────────────────────────────────────────
	{
		ID:            "garage",
		Name:          "Garage",
		Description:   "Lightweight S3-compatible distributed object storage for self-hosting",
		Category:      "Storage",
		Image:         "dxflrs/garage:v2.3.0",
		DefaultPort:   3900,
		ContainerPort: "3900/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/var/lib/garage/data", "/var/lib/garage/meta", "/etc/garage"},
	},
	{
		ID:            "seaweedfs",
		Name:          "SeaweedFS",
		Description:   "Fast distributed storage system for billions of files with S3 API support",
		Category:      "Storage",
		Image:         "chrislusf/seaweedfs:4.45",
		DefaultPort:   9333,
		ContainerPort: "9333/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/data"},
	},
	// ─── Security (new) ─────────────────────────────────────────
	{
		ID:            "wazuh",
		Name:          "Wazuh Manager",
		Description:   "Open-source security platform for threat detection, compliance, and incident response",
		Category:      "Security",
		Image:         "wazuh/wazuh-manager:4.9.2",
		DefaultPort:   1514,
		ContainerPort: "1514/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/var/ossec/api/configuration", "/var/ossec/etc", "/var/ossec/logs", "/var/ossec/queue"},
	},
	{
		ID:            "trivy",
		Name:          "Trivy Server",
		Description:   "Comprehensive vulnerability scanner for containers, filesystems, and IaC",
		Category:      "Security",
		Image:         "aquasec/trivy:0.74.0",
		DefaultPort:   8313,
		ContainerPort: "8080/tcp",
		EnvVars:       nil,
		Volumes:       []string{"/root/.cache"},
	},
	// ─── Automation (new) ───────────────────────────────────────
	{
		ID:            "huginn",
		Name:          "Huginn",
		Description:   "System for building agents that perform automated tasks online (IFTTT alternative)",
		Category:      "Automation",
		Image:         "ghcr.io/huginn/huginn:latest",
		DefaultPort:   3021,
		ContainerPort: "3000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "HUGINN_DATABASE_ADAPTER", Label: "DB Adapter", Default: "mysql2", Required: false, Secret: false},
			{Name: "HUGINN_DATABASE_HOST", Label: "DB Host", Default: "", Required: true, Secret: false},
			{Name: "HUGINN_DATABASE_NAME", Label: "DB Name", Default: "huginn", Required: false, Secret: false},
			{Name: "HUGINN_DATABASE_USERNAME", Label: "DB Username", Default: "huginn", Required: true, Secret: false},
			{Name: "HUGINN_DATABASE_PASSWORD", Label: "DB Password", Default: "", Required: true, Secret: true},
		},
		Volumes: nil,
	},
	{
		ID:            "windmill",
		Name:          "Windmill",
		Description:   "Developer platform for building internal tools, workflows, and scripts as code",
		Category:      "Automation",
		Image:         "ghcr.io/windmill-labs/windmill:main",
		DefaultPort:   8314,
		ContainerPort: "8000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "DATABASE_URL", Label: "PostgreSQL URL", Default: "", Required: true, Secret: true},
		},
		Volumes: nil,
	},
	{
		ID:            "temporal",
		Name:          "Temporal Server",
		Description:   "Durable execution platform for reliable microservices and workflows",
		Category:      "Automation",
		Image:         "temporalio/auto-setup:1.29.3",
		DefaultPort:   8315,
		ContainerPort: "8233/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "DB", Label: "Database Type", Default: "postgresql", Required: false, Secret: false},
			{Name: "POSTGRES_SEEDS", Label: "PostgreSQL Host", Default: "", Required: true, Secret: false},
			{Name: "POSTGRES_USER", Label: "PostgreSQL User", Default: "temporal", Required: true, Secret: false},
			{Name: "POSTGRES_PWD", Label: "PostgreSQL Password", Default: "", Required: true, Secret: true},
		},
		Volumes: nil,
	},
	// ─── Analytics (new) ────────────────────────────────────────
	{
		ID:            "superset",
		Name:          "Apache Superset",
		Description:   "Modern data exploration and visualization platform with rich SQL editor",
		Category:      "Analytics",
		Image:         "apache/superset:latest",
		DefaultPort:   8321,
		ContainerPort: "8088/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "SUPERSET_SECRET_KEY", Label: "Secret Key", Default: "", Required: true, Secret: true},
			{Name: "ADMIN_USERNAME", Label: "Admin Username", Default: "admin", Required: false, Secret: false},
			{Name: "ADMIN_PASSWORD", Label: "Admin Password", Default: "", Required: true, Secret: true},
		},
		Volumes: []string{"/app/superset_home"},
	},
	{
		ID:            "redash",
		Name:          "Redash",
		Description:   "Connect to any data source, visualize, and share dashboards with your team",
		Category:      "Analytics",
		Image:         "redash/redash:8.0.0.b32245",
		DefaultPort:   5100,
		ContainerPort: "5000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "REDASH_DATABASE_URL", Label: "PostgreSQL URL", Default: "", Required: true, Secret: true},
			{Name: "REDASH_REDIS_URL", Label: "Redis URL", Default: "redis://redis:6379/0", Required: true, Secret: false},
			{Name: "REDASH_SECRET_KEY", Label: "Secret Key", Default: "", Required: true, Secret: true},
		},
		Volumes: nil,
	},
	{
		ID:            "posthog",
		Name:          "PostHog",
		Description:   "Open-source product analytics with session recording, feature flags, and A/B testing",
		Category:      "Analytics",
		Image:         "posthog/posthog:latest",
		DefaultPort:   8316,
		ContainerPort: "8000/tcp",
		EnvVars: []dockerAppsEnvVarDef{
			{Name: "SECRET_KEY", Label: "Secret Key", Default: "", Required: true, Secret: true},
			{Name: "DATABASE_URL", Label: "PostgreSQL URL", Default: "", Required: true, Secret: true},
			{Name: "REDIS_URL", Label: "Redis URL", Default: "redis://redis:6379/", Required: false, Secret: false},
		},
		Volumes: nil,
	},
}

// dockerAppsToAppTemplate converts a catalogue row to the serializable type.
func dockerAppsToAppTemplate(def *dockerAppsTemplateDef) DockerAppsAppTemplate {
	envVars := make([]DockerAppsEnvVar, 0, len(def.EnvVars))
	for _, ev := range def.EnvVars {
		envVars = append(envVars, DockerAppsEnvVar{
			Name:          ev.Name,
			Label:         ev.Label,
			Default:       ev.Default,
			Required:      ev.Required,
			Secret:        ev.Secret,
			DomainDerived: dockerAppsIsDomainDerived(def.ID, ev.Name),
		})
	}
	return DockerAppsAppTemplate{
		ID:             def.ID,
		Name:           def.Name,
		Description:    def.Description,
		Category:       def.Category,
		Image:          def.Image,
		DefaultPort:    def.DefaultPort,
		ContainerPort:  def.ContainerPort,
		EnvVars:        envVars,
		Volumes:        append([]string{}, def.Volumes...),
		GpuRecommended: slices.Contains(dockerAppsGpuRecommendedTemplates, def.ID),
	}
}

// dockerAppsTemplateByID returns the catalogue row for id, or nil.
func dockerAppsTemplateByID(id string) *dockerAppsTemplateDef {
	for i := range dockerAppsTemplates {
		if dockerAppsTemplates[i].ID == id {
			return &dockerAppsTemplates[i]
		}
	}
	return nil
}

// DockerAppsEnvMask is what `GET /apps/{id}/env` substitutes for a value it
// will not show.
//
// Exported because DockerAppsUpdateEnv has to recognise it coming back: the
// edit dialog is seeded from the masked read, so the mask is what a caller
// sends for every field they did not touch.
const DockerAppsEnvMask = "********"

// DockerAppsMergeEnvPreservingMasked merges the caller's environment over the
// container's own, treating DockerAppsEnvMask as "leave this one alone".
//
// `GET /apps/{id}/env` substitutes the mask for anything sensitive, the edit
// dialog is seeded from exactly that response and sends every field back, and
// **this container is the only place the real value is stored** — no table
// holds a Docker app's environment. Without this, saving the dialog wrote the
// literal `********` over every masked variable and then removed the container
// that held the original, which for Vaultwarden's ADMIN_TOKEN and
// code-server's PASSWORD is an auth downgrade to a published literal, and for
// Meilisearch a container that refuses to start after the original is gone.
//
// Returns the new `KEY=value` list and the names carried over (sorted), so the
// caller can say what it did rather than doing it silently.
func DockerAppsMergeEnvPreservingMasked(newEnv map[string]string, containerEnv []string) ([]string, []string) {
	existing := map[string]string{}
	for _, kv := range containerEnv {
		if k, v, ok := strings.Cut(kv, "="); ok {
			if _, seen := existing[k]; !seen {
				existing[k] = v
			}
		}
	}
	kept := []string{}
	envList := make([]string, 0, len(newEnv))
	for k, v := range newEnv {
		if v == DockerAppsEnvMask {
			if real, ok := existing[k]; ok {
				kept = append(kept, k)
				envList = append(envList, k+"="+real)
				continue
			}
		}
		envList = append(envList, k+"="+v)
	}
	sort.Strings(kept)
	return envList, kept
}

// DockerAppsCatalogueNonSecretEnv: env var names the shipped catalogue itself
// declares are NOT secret.
//
// The mask is chosen by substring — KEY, AUTH, TOKEN, SECRET, PASSWORD
// anywhere in the name — which is right for an unknown key and wrong for
// several we ship ourselves: KEYCLOAK_ADMIN is a username, NEXTAUTH_URL is a
// URL, AUTHENTIK_POSTGRESQL__HOST is a hostname. All three were shown as
// `********`, which is unreadable and — before the sentinel in
// DockerAppsUpdateEnv — unrecoverable once saved.
//
// A name is allowlisted only if EVERY template that declares it says
// `secret: false`, so a name reused as a secret elsewhere keeps its mask, and
// a name the catalogue has never heard of falls through to the substring test.
// The list can therefore only ever un-mask something we ourselves defined.
func DockerAppsCatalogueNonSecretEnv(name string) bool {
	seen := false
	for _, t := range dockerAppsTemplates {
		for _, v := range t.EnvVars {
			if v.Name == name {
				if v.Secret {
					return false
				}
				seen = true
			}
		}
	}
	return seen
}

// DockerAppsCatalogueSecretEnv is the counterpart `GET /apps/{id}/env` was
// missing: a catalogue-declared `secret: true` name that doesn't contain one
// of the route's substring patterns — e.g. DB_PASS, POSTGRES_PWD,
// DATABASE_URL — was returned in the clear.
func DockerAppsCatalogueSecretEnv(name string) bool {
	for _, t := range dockerAppsTemplates {
		for _, v := range t.EnvVars {
			if v.Name == name && v.Secret {
				return true
			}
		}
	}
	return false
}

// DockerAppsListTemplates returns all available app templates.
func DockerAppsListTemplates() []DockerAppsAppTemplate {
	out := make([]DockerAppsAppTemplate, 0, len(dockerAppsTemplates))
	for i := range dockerAppsTemplates {
		out = append(out, dockerAppsToAppTemplate(&dockerAppsTemplates[i]))
	}
	return out
}

// ── Volume ownership ───────────────────────────────────────────────

// DockerAppsVolumeOwner is who a template's volume directories have to
// belong to.
//
// The deploy creates each declared volume as a **root-owned** directory on the
// host and bind-mounts it. That is right for most images, which start as root
// and chown their own data directory in their entrypoint before dropping
// privileges — postgres, mysql and mongo all do exactly that.
//
// It is wrong for an image that declares a non-root Config.User, because that
// process starts **already dropped** and can never chown its way out: it
// cannot write the directory the template just mounted for it. Either the
// container exits with `Permission denied`, or — worse — it comes up healthy
// and silently persists nothing.
//
// Measured over the catalogue by reading every image's config: 42 of 148
// images run non-root, and 31 of those declare a volume.
type DockerAppsVolumeOwner struct {
	UID uint32
	// nil when no group could be resolved. The directory then keeps the group
	// it already has, which is enough — the owner can write either way.
	GID *uint32
	// The literal Config.User, so the log names what it acted on.
	Spec string
}

func (o *DockerAppsVolumeOwner) gidArg() int {
	if o.GID == nil {
		return -1 // "leave this one as it is"
	}
	return int(*o.GID)
}

// dockerAppsSplitUserSpec splits a Docker `User` spec into its user and group
// halves. Docker accepts `user`, `uid`, `user:group`, `uid:gid` and the mixed
// forms.
func dockerAppsSplitUserSpec(spec string) (string, *string) {
	if user, group, ok := strings.Cut(spec, ":"); ok {
		g := strings.TrimSpace(group)
		return strings.TrimSpace(user), &g
	}
	return strings.TrimSpace(spec), nil
}

// dockerAppsUserSpecIsRoot: does this Config.User mean root? An empty field
// does — it is simply unset, which is how most images ship.
func dockerAppsUserSpecIsRoot(spec string) bool {
	user, _ := dockerAppsSplitUserSpec(spec)
	return user == "" || user == "root" || user == "0"
}

// dockerAppsOctal parses a NUL/space-padded octal tar header field.
func dockerAppsOctal(field []byte) (uint64, bool) {
	s := strings.Trim(string(field), "\x00 ")
	if !utf8Valid(field) || s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 8, 64)
	return v, err == nil
}

func utf8Valid(b []byte) bool { return strings.ToValidUTF8(string(b), "�") == string(b) }

func dockerAppsDivCeil512(n uint64) uint64 { return (n + 511) / 512 * 512 }

// dockerAppsTarExtractFirstFile pulls one regular file's bytes out of a
// `docker cp` tar stream.
//
// A dependency-free reader for the only shape this ever asks for: one small
// file. A ustar header is 512 bytes, the size sits at offset 124 as octal
// ASCII, and the payload is padded to the next 512-byte boundary.
func dockerAppsTarExtractFirstFile(archive []byte) (string, bool) {
	offset := 0
	for offset+512 <= len(archive) {
		header := archive[offset : offset+512]
		// A zero block ends the archive.
		if bytes.Count(header, []byte{0}) == 512 {
			return "", false
		}
		size, ok := dockerAppsOctal(header[124:136])
		if !ok || size > uint64(len(archive)) {
			return "", false
		}
		body := offset + 512
		// '0' and NUL both mean "regular file"; skip anything else.
		if (header[156] == '0' || header[156] == 0) && size > 0 {
			end := body + int(size)
			if end > len(archive) {
				return "", false
			}
			content := archive[body:end]
			if !utf8Valid(content) {
				return "", false
			}
			return string(content), true
		}
		offset = body + int(dockerAppsDivCeil512(size))
	}
	return "", false
}

// dockerAppsPathComponents mirrors Rust's Path::components(): a leading "/"
// is its own component, "." is kept only as the very first component, empty
// segments (repeated or trailing slashes) vanish.
func dockerAppsPathComponents(p string) []string {
	var comps []string
	abs := strings.HasPrefix(p, "/")
	if abs {
		comps = append(comps, "/")
	}
	for i, part := range strings.Split(p, "/") {
		switch {
		case part == "":
		case part == ".":
			if i == 0 && !abs {
				comps = append(comps, ".")
			}
		default:
			comps = append(comps, part)
		}
	}
	return comps
}

// dockerAppsTarExtractInto unpacks a Docker copy-API tar into dest, dropping
// the archive's own leading path component, and returns what it wrote.
//
// ⚠ The archive comes from a THIRD PARTY's image, so every entry is checked to
// land inside dest before anything is written. An entry naming `..` or an
// absolute path is skipped, not sanitised — the only safe response to a tar
// that tries to escape is to not write it.
//
// Only regular files, directories and hard links to entries THIS archive
// already wrote are materialised. Symlinks are skipped: a link is a second
// way to name a path outside the destination, and no image's default config
// needs one to be useful.
func dockerAppsTarExtractInto(archive []byte, dest string) ([]string, error) {
	written := []string{}
	// Keyed by the entry's own archive-internal name (prefix-joined,
	// pre-leading-component-strip — the coordinate space a hardlink's linkname
	// is written in); value is where THIS archive put it on disk. A type-1
	// entry resolves against this, never the host filesystem.
	writtenByName := map[string]string{}
	offset := 0
	for offset+512 <= len(archive) {
		header := archive[offset : offset+512]
		if bytes.Count(header, []byte{0}) == 512 {
			break
		}
		field := func(from, to int) string {
			b := header[from:to]
			if i := bytes.IndexByte(b, 0); i >= 0 {
				b = b[:i]
			}
			return strings.ToValidUTF8(string(b), "�")
		}
		// POSIX ustar splits a path over 100 bytes across `name` (0..100) and
		// a `prefix` (345..500, joined with `/`) — reading `name` alone
		// silently truncates/misplaces any seeded path past 100 bytes.
		prefix := field(345, 500)
		name := field(0, 100)
		if prefix != "" {
			name = prefix + "/" + name
		}
		linkname := field(157, 257)
		size, _ := dockerAppsOctal(header[124:136])
		// Mode and ownership are NOT decoration. An image ships executable
		// entrypoints and per-user config, and an extractor that writes every
		// entry 0644 root:root hands the app a directory that looks right and
		// behaves wrong.
		//
		// ⚠ But the archive's mode is NOT copied verbatim. Only "was this
		// executable?" is carried across; the answer is then expressed as a
		// fixed safe mode. Reproducing an image's bits faithfully would let a
		// third party's image put a world-writable or setuid file into a data
		// directory on a host that runs other people's containers.
		mode, modeOK := dockerAppsOctal(header[100:108])
		executable := modeOK && mode&0o111 != 0
		uid, uidOK := dockerAppsOctal(header[108:116])
		gid, gidOK := dockerAppsOctal(header[116:124])
		body := offset + 512
		kind := header[156]

		// Drop the leading component: copying `/etc/caddy` yields `caddy/...`.
		comps := dockerAppsPathComponents(name)
		var relative []string
		if len(comps) > 1 {
			relative = comps[1:]
		}
		escapes := slices.ContainsFunc(relative, func(c string) bool { return c == ".." || c == "/" })

		if !escapes && len(relative) > 0 {
			target := filepath.Join(append([]string{dest}, relative...)...)
			materialised := false
			switch {
			case kind == '5':
				if err := os.MkdirAll(target, 0o755); err != nil {
					return written, err
				}
				materialised = true
			case kind == '0' || kind == 0:
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					return written, err
				}
				end := min(uint64(body)+size, uint64(len(archive)))
				start := min(uint64(body), end)
				if err := os.WriteFile(target, archive[start:end], 0o644); err != nil {
					return written, err
				}
				materialised = true
			case kind == '1':
				// Hard link. Resolve linkname ONLY against a path THIS
				// archive has already written, never the host filesystem — an
				// extractor willing to hard-link an arbitrary host path into
				// the target would hand the app a read primitive over anything
				// the agent's uid can see. Anything else is silently skipped.
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					return written, err
				}
				if src, ok := writtenByName[linkname]; ok {
					materialised = os.Link(src, target) == nil
				}
			}
			if materialised {
				safeMode := os.FileMode(0o644)
				if kind == '5' || executable {
					safeMode = 0o755
				}
				_ = os.Chmod(target, safeMode)
				if uidOK && gidOK {
					g := uint32(gid)
					_ = DockerAppsChownTo(target, &DockerAppsVolumeOwner{UID: uint32(uid), GID: &g})
				}
				writtenByName[name] = target
				written = append(written, target)
			}
		}
		offset = body + int(dockerAppsDivCeil512(size))
	}
	return written, nil
}

// dockerAppsDirIsEmpty reports (empty, readable).
func dockerAppsDirIsEmpty(dir string) (bool, bool) {
	f, err := os.Open(dir)
	if err != nil {
		return false, false
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, false
	}
	return len(names) == 0, true
}

// dockerAppsCopyOutOfImage creates (never starts) a probe container from
// image, reads path out of it with the copy API, and removes the probe. The
// bool is false when the read failed part-way.
func dockerAppsCopyOutOfImage(ctx context.Context, docker *client.Client, image, path, probePrefix, probeCmd string) ([]byte, bool, error) {
	created, err := docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: probePrefix + uuid.NewString(),
		Config: &container.Config{
			Image: image,
			// Never started; this only has to satisfy `create` for an image
			// that declares no command of its own.
			Cmd: []string{probeCmd},
		},
	})
	if err != nil {
		return nil, false, err
	}
	var buf []byte
	ok := true
	if res, err := docker.CopyFromContainer(ctx, created.ID, client.CopyFromContainerOptions{SourcePath: path}); err != nil {
		ok = false
	} else {
		buf, err = io.ReadAll(res.Content)
		res.Content.Close()
		if err != nil {
			ok = false
		}
	}
	// The probe is created with no HostConfig, so Docker materialises one
	// anonymous volume for every path the image declares as a VOLUME. Removing
	// it without the volumes flag orphans every one of them, on every call,
	// for ever. The flag removes ONLY anonymous volumes; named volumes and bind
	// sources are untouched (measured against the daemon).
	_, _ = docker.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{RemoveVolumes: true, Force: true})
	return buf, ok, nil
}

// DockerAppsSeedVolumeFromImage gives a bind-mounted directory the contents
// the image ships at that path.
//
// **This restores a Docker behaviour that binding opts out of.** When an
// empty NAMED volume is mounted over a path that has content in the image,
// Docker copies that content into the volume; when a BIND mount is used, it
// never does. This panel binds every declared volume — so it can hand the
// operator a directory they can see and back up — and in doing so silently
// deleted, from the container's point of view, every file its image shipped
// at that path.
//
// Proven rather than reasoned: the same `caddy:2` image, the same /etc/caddy,
// differing only in mount type — bind exits 1 with "open /etc/caddy/Caddyfile:
// no such file or directory", while a named volume comes up listening.
//
// Seeding from the IMAGE rather than from a starter file written here is the
// whole point: the image's own bytes are correct by construction and cost
// nothing to keep current.
//
// Two guards, both deliberate:
//   - it writes ONLY into a directory that is empty, so an operator's existing
//     data is never touched;
//   - a failure is logged and swallowed. Before this existed the directory was
//     empty, which is exactly where a failure leaves it.
func DockerAppsSeedVolumeFromImage(ctx context.Context, docker *client.Client, image, containerPath, hostDir string) {
	// Only ever seed an empty directory.
	if empty, ok := dockerAppsDirIsEmpty(hostDir); !ok || !empty {
		return
	}
	buf, ok, err := dockerAppsCopyOutOfImage(ctx, docker, image, containerPath, "dockpanel-seedprobe-", "dockpanel-seed-probe")
	if err != nil {
		slog.Debug(fmt.Sprintf("Could not create a seed probe for %s: %v", image, err))
		return
	}
	// The overwhelmingly common failure: the image ships nothing at this
	// path, which is normal and is not a problem.
	if !ok || len(buf) == 0 {
		return
	}
	written, err := dockerAppsTarExtractInto(buf, hostDir)
	switch {
	case err != nil:
		slog.Warn(fmt.Sprintf("Could not seed %s from %s:%s: %v", hostDir, image, containerPath, err))
	case len(written) > 0:
		// Ownership and modes come from the archive itself, entry by entry,
		// which is what Docker's own named-volume pre-population does.
		suffix := "ies"
		if len(written) == 1 {
			suffix = "y"
		}
		slog.Info(fmt.Sprintf("Seeded %d entr%s into %s from %s:%s — the image ships files there, and a bind mount would otherwise hide them",
			len(written), suffix, hostDir, image, containerPath))
	}
}

// dockerAppsReadFileFromImage reads one file out of an already-pulled image
// **without running it**. This is the only way to resolve a login name,
// because a name like `nonroot` is defined by the image's own /etc/passwd and
// by nothing on the host.
func dockerAppsReadFileFromImage(ctx context.Context, docker *client.Client, image, path string) (string, bool) {
	buf, _, err := dockerAppsCopyOutOfImage(ctx, docker, image, path, "dockpanel-userprobe-", "dockpanel-user-probe")
	if err != nil {
		return "", false
	}
	return dockerAppsTarExtractFirstFile(buf)
}

func dockerAppsParseU32(s string) (uint32, bool) {
	v, err := strconv.ParseUint(s, 10, 32)
	return uint32(v), err == nil
}

// dockerAppsPasswdLookup resolves a login name to (uid, gid) from an image's
// own /etc/passwd.
func dockerAppsPasswdLookup(passwd, name string) (uint32, uint32, bool) {
	for _, line := range strings.Split(passwd, "\n") {
		f := strings.Split(line, ":")
		if f[0] != name || len(f) < 4 {
			continue
		}
		uid, ok1 := dockerAppsParseU32(f[2])
		gid, ok2 := dockerAppsParseU32(f[3])
		if ok1 && ok2 {
			return uid, gid, true
		}
	}
	return 0, 0, false
}

// dockerAppsPasswdGidForUID finds the primary gid of a numeric uid in an
// image's own /etc/passwd.
func dockerAppsPasswdGidForUID(passwd string, uid uint32) (uint32, bool) {
	for _, line := range strings.Split(passwd, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		if u, ok := dockerAppsParseU32(f[2]); !ok || u != uid {
			continue
		}
		if gid, ok := dockerAppsParseU32(f[3]); ok {
			return gid, true
		}
	}
	return 0, false
}

// dockerAppsGroupLookup resolves a group name to a gid from an image's own
// /etc/group.
func dockerAppsGroupLookup(group, name string) (uint32, bool) {
	for _, line := range strings.Split(group, "\n") {
		f := strings.Split(line, ":")
		if f[0] != name || len(f) < 3 {
			continue
		}
		if gid, ok := dockerAppsParseU32(f[2]); ok {
			return gid, true
		}
	}
	return 0, false
}

// DockerAppsResolveVolumeOwner works out who a template's volume directories
// must belong to, or nil when the image runs as root and today's behaviour is
// already correct.
//
// ⚠ There is deliberately **no fallback**. Guessing a uid hands one tenant's
// data directory to a different account, and 0777 would put a world-writable
// directory on a host that runs other people's containers. When the spec
// cannot be resolved this returns nil and says so out loud, leaving the
// directory root-owned — the same state as before, but no longer silent.
func DockerAppsResolveVolumeOwner(ctx context.Context, docker *client.Client, image string) *DockerAppsVolumeOwner {
	info, err := docker.ImageInspect(ctx, image)
	if err != nil || info.Config == nil {
		return nil
	}
	spec := strings.TrimSpace(info.Config.User)
	if dockerAppsUserSpecIsRoot(spec) {
		return nil
	}
	userPart, groupPart := dockerAppsSplitUserSpec(spec)
	numericUID, isNumeric := dockerAppsParseU32(userPart)

	// /etc/passwd is needed to translate a login name, and to find the primary
	// group of a bare numeric uid. A `uid:gid` pair needs nothing from the image.
	var passwd string
	hasPasswd := false
	if !isNumeric || groupPart == nil {
		passwd, hasPasswd = dockerAppsReadFileFromImage(ctx, docker, image, "/etc/passwd")
	}

	var uid uint32
	var primaryGID *uint32
	if isNumeric {
		uid = numericUID
		if hasPasswd {
			if g, ok := dockerAppsPasswdGidForUID(passwd, uid); ok {
				primaryGID = &g
			}
		}
	} else {
		u, g, ok := uint32(0), uint32(0), false
		if hasPasswd {
			u, g, ok = dockerAppsPasswdLookup(passwd, userPart)
		}
		if !ok {
			slog.Warn(fmt.Sprintf("Image %s runs as non-root user %q which could not be resolved from its own /etc/passwd; "+
				"leaving volume directories root-owned. The app may be unable to write its data directory.", image, spec))
			return nil
		}
		uid, primaryGID = u, &g
	}

	gid := primaryGID
	if groupPart != nil {
		gid = nil
		if g, ok := dockerAppsParseU32(*groupPart); ok {
			gid = &g
		} else if group, ok := dockerAppsReadFileFromImage(ctx, docker, image, "/etc/group"); ok {
			if g, ok := dockerAppsGroupLookup(group, *groupPart); ok {
				gid = &g
			}
		}
	}
	return &DockerAppsVolumeOwner{UID: uid, GID: gid, Spec: spec}
}

// DockerAppsChownTo chowns a path, leaving the group alone when none was
// resolved.
//
// Deliberately **not** recursive. The owner of the directory is what lets the
// image create its own files underneath; recursing would rewrite ownership of
// data a previous deployment wrote, which is a bigger and riskier operation
// than the defect calls for.
func DockerAppsChownTo(path string, owner *DockerAppsVolumeOwner) error {
	if strings.ContainsRune(path, 0) {
		return errors.New("volume path contains a NUL byte")
	}
	return os.Chown(path, int(owner.UID), owner.gidArg())
}

// dockerAppsLchownTo chowns one path without ever following a symlink. An
// app's data directory may legitimately contain one, and following it would
// apply the app's uid to whatever is on the other end.
func dockerAppsLchownTo(path string, owner *DockerAppsVolumeOwner) error {
	if strings.ContainsRune(path, 0) {
		return errors.New("volume path contains a NUL byte")
	}
	return os.Lchown(path, int(owner.UID), owner.gidArg())
}

// dockerAppsChownMigratedTree gives the app ownership of every file the
// migration just wrote for it.
//
// **This is recursive, and DockerAppsChownTo is deliberately not. The
// difference is in what is underneath.** On the deploy path the directory may
// hold data an earlier deployment wrote. Here the caller has already REFUSED
// to proceed unless the directory was empty and has then filled it itself, so
// every path underneath is one we created seconds ago — bounded by
// construction.
//
// It has to happen, because `docker cp` does not preserve ownership on the
// way out of a container: it writes as the user running it — root, for the
// agent — and `--archive` does not change that (measured on docker 29.7.2).
// That was GitHub #110's second act: the update rescued the data and handed it
// back unwritable.
//
// Returns how many paths were changed, so the log can evidence the work.
func dockerAppsChownMigratedTree(root string, owner *DockerAppsVolumeOwner) (int, error) {
	stack := []string{root}
	touched := 0
	for len(stack) > 0 {
		path := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		// Lstat does not follow, so a symlink to a directory is chowned as a
		// link and never descended into.
		meta, err := os.Lstat(path)
		if err != nil {
			return touched, err
		}
		if err := dockerAppsLchownTo(path, owner); err != nil {
			return touched, err
		}
		touched++
		if meta.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				return touched, err
			}
			for _, e := range entries {
				stack = append(stack, filepath.Join(path, e.Name()))
			}
		}
	}
	return touched, nil
}

// dockerAppsRepairRootOwnedVolumes gives back what the broken migration took,
// on an install it already broke.
//
// v2.111.0 through v2.113.1 copied an app's data onto a bind mount with
// `docker cp` — which writes as root — and then chowned only the directory, so
// every file underneath came back owned by root and a non-root image could
// not write its own data (#110). v2.113.2 stopped that happening but could not
// undo it: the migration runs only for a volume that is MISSING, and the bad
// migration is precisely what supplied the mount.
//
// This runs on the recreate paths, where the container is stopped.
//
// **It chowns only entries currently owned by root, and only to the uid the
// image itself declares** — the narrowest rule that repairs what we did. A
// file owned by any third uid is left exactly as it was. Root-run images are
// skipped entirely (DockerAppsResolveVolumeOwner returns nil for them).
func dockerAppsRepairRootOwnedVolumes(ctx context.Context, docker *client.Client, image string, hc *container.HostConfig) []string {
	prefix := DockerAppsAppDataDir + "/"
	var sources []string
	for _, bind := range hc.Binds {
		src, _, _ := strings.Cut(bind, ":")
		if strings.HasPrefix(src, prefix) {
			sources = append(sources, src)
		}
	}
	if len(sources) == 0 {
		return []string{}
	}
	owner := DockerAppsResolveVolumeOwner(ctx, docker, image)
	if owner == nil {
		return []string{}
	}

	repaired := []string{}
	for _, src := range sources {
		// Canonicalize then re-check the prefix, exactly as every other writer
		// here does — the check only means anything after symlinks resolve.
		resolved, err := filepath.EvalSymlinks(src)
		if err != nil || !strings.HasPrefix(resolved, prefix) {
			continue
		}
		count, err := dockerAppsChownRootOwnedEntries(resolved, owner)
		switch {
		case err != nil:
			slog.Warn(fmt.Sprintf("Could not repair ownership under %s: %v", resolved, err))
		case count > 0:
			slog.Info(fmt.Sprintf("Repaired %s: %d root-owned path(s) given back to %d for image user %q — this app was "+
				"migrated by a release that left its data unwritable (#110)", resolved, count, owner.UID, owner.Spec))
			repaired = append(repaired, fmt.Sprintf("%s (%d)", resolved, count))
		}
	}
	return repaired
}

// dockerAppsOpenatNofollow opens name relative to dirFD (or unix.AT_FDCWD for
// an absolute path) WITHOUT following a symlink — ELOOP if the entry has
// become one since it was named. This is the primitive the whole walk below
// is built on: every helper resolves ONE path component against an
// already-open, already-verified parent, never a multi-component path string
// that could have a swapped ancestor.
func dockerAppsOpenatNofollow(dirFD int, name string, extra int) (int, error) {
	return unix.Openat(dirFD, name, unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_RDONLY|extra, 0)
}

// dockerAppsFstatatNofollow lstats one entry by NAME relative to an
// already-open parent — resolves nothing above dirFD, so a swapped ANCESTOR
// cannot redirect it.
func dockerAppsFstatatNofollow(dirFD int, name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	return st, err
}

// dockerAppsReadDirNames lists a directory's immediate child names through a
// DUPLICATE of dirFD, so this reads exactly the directory the caller already
// verified without relinquishing (or double-closing) the caller's own fd.
func dockerAppsReadDirNames(dirFD int) ([]string, error) {
	dup, err := unix.Dup(dirFD)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "")
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return names, nil
}

// dockerAppsChownRootOwnedEntries chowns every root-owned path under root,
// leaving every other owner alone.
//
// The top level is probed first and the walk is skipped when nothing there is
// root-owned, so a healthy app pays one directory read per update instead of a
// full tree walk.
//
// **Built around open file descriptors, not path strings (TOCTOU fix).** A
// stat-then-read-by-path walk re-resolves the same path twice; a process with
// write access to its own bind-mounted volume (every app, by construction) can
// swap a directory for a symlink to anywhere on the host between the two calls
// and have the second one follow it. Every primitive below resolves at most
// one component, always against an already-open parent fd
// (openat/fstatat/fchownat, all NOFOLLOW) — there is no window for a swap.
func dockerAppsChownRootOwnedEntries(root string, owner *DockerAppsVolumeOwner) (int, error) {
	if strings.ContainsRune(root, 0) {
		return 0, errors.New("path contains a NUL byte")
	}
	rootFD, err := dockerAppsOpenatNofollow(unix.AT_FDCWD, root, unix.O_DIRECTORY)
	if err != nil {
		return 0, err
	}
	var rootSt unix.Stat_t
	if err := unix.Fstat(rootFD, &rootSt); err != nil {
		unix.Close(rootFD)
		return 0, err
	}

	worthWalking := rootSt.Uid == 0
	if !worthWalking {
		names, err := dockerAppsReadDirNames(rootFD)
		if err != nil {
			unix.Close(rootFD)
			return 0, err
		}
		for _, name := range names {
			if st, err := dockerAppsFstatatNofollow(rootFD, name); err == nil && st.Uid == 0 {
				worthWalking = true
				break
			}
		}
	}
	if !worthWalking {
		unix.Close(rootFD)
		return 0, nil
	}

	changed := 0
	if rootSt.Uid == 0 {
		if err := unix.Fchown(rootFD, int(owner.UID), owner.gidArg()); err != nil {
			unix.Close(rootFD)
			return changed, err
		}
		changed++
	}

	// Each stack frame owns an open, O_NOFOLLOW-verified directory fd.
	// Depth-first, same order the original path-based walk used.
	stack := []int{rootFD}
	defer func() {
		for _, fd := range stack {
			unix.Close(fd)
		}
	}()
	for len(stack) > 0 {
		dirFD := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		err := func() error {
			defer unix.Close(dirFD)
			names, err := dockerAppsReadDirNames(dirFD)
			if err != nil {
				return err
			}
			for _, name := range names {
				st, err := dockerAppsFstatatNofollow(dirFD, name)
				if err != nil {
					// Gone, or unstattable, between listing and here — skip it
					// rather than error the whole walk out over one entry.
					continue
				}
				if uint32(st.Mode)&unix.S_IFMT == unix.S_IFDIR {
					// A directory's nlink counts its subdirectories — inherent,
					// not a hardlink-attack signal, so never a skip condition.
					// Always descend regardless of ownership: a root-owned FILE
					// may sit under a directory owned by the app itself.
					if st.Uid == 0 {
						if err := unix.Fchownat(dirFD, name, int(owner.UID), owner.gidArg(), unix.AT_SYMLINK_NOFOLLOW); err != nil {
							return err
						}
						changed++
					}
					childFD, err := dockerAppsOpenatNofollow(dirFD, name, unix.O_DIRECTORY)
					if err != nil {
						// Swapped for a symlink (or removed) between the fstatat
						// and this open — refuse rather than follow. The exact
						// race this closes.
						continue
					}
					stack = append(stack, childFD)
				} else if st.Uid == 0 {
					// A hardlinked entry's inode is shared with a name that may
					// sit outside this volume entirely; chowning it would
					// repaint that other name too. fs.protected_hardlinks=0
					// lets an unprivileged process hardlink to a file it does
					// not own, so a root-owned nlink>1 entry can be a planted
					// link to a real host file — skip it.
					if uint64(st.Nlink) > 1 {
						continue
					}
					if err := unix.Fchownat(dirFD, name, int(owner.UID), owner.gidArg(), unix.AT_SYMLINK_NOFOLLOW); err != nil {
						return err
					}
					changed++
				}
			}
			return nil
		}()
		if err != nil {
			return changed, err
		}
	}
	return changed, nil
}

// dockerAppsSatMulI64 is u64::saturating_mul(..).min(i64::MAX) as i64.
func dockerAppsSatMulI64(a, b uint64) int64 {
	const maxI64 = uint64(1<<63 - 1)
	if b != 0 && a > maxI64/b {
		return int64(maxI64)
	}
	return int64(min(a*b, maxI64))
}

var dockerAppsLoopback = netip.MustParseAddr("127.0.0.1")

// DockerAppsDeployApp deploys an app from a template: pull image, create
// container, start it.
func DockerAppsDeployApp(ctx context.Context, templateID, name string, port uint16, env map[string]string, domain *string,
	memoryMb, cpuPercent *uint64, userID *string, gpuEnabled bool, gpuIndices []uint32) (DockerAppsDeployResult, error) {
	// Refused before anything is pulled or created. An app called
	// `dockpanel-app-<something>` owns the very directory a recreate of the
	// app `<something>` migrated into on releases v2.111.0 through v2.113.3,
	// so the two would share one tree and deleting either would take the
	// other's data. The installs it already wrote cannot be un-written — so
	// the name is closed rather than left as a collision waiting to be found.
	if strings.HasPrefix(name, DockerAppsContainerNamePrefix) {
		return DockerAppsDeployResult{}, fmt.Errorf("'%s' is not an available app name: it collides with the container naming "+
			"this panel uses, and with the data directory of the app it would shadow. "+
			"Choose a name that does not begin with that prefix.", name)
	}

	template := dockerAppsTemplateByID(templateID)
	if template == nil {
		return DockerAppsDeployResult{}, fmt.Errorf("Unknown template: %s", templateID)
	}

	docker, err := dockerAppsConnect()
	if err != nil {
		return DockerAppsDeployResult{}, err
	}
	defer docker.Close()

	// Pull image (with timeout to prevent hanging on Docker daemon issues)
	pctx, cancel := context.WithTimeout(ctx, 300*time.Second)
	for _, e := range DockerAppsPullImage(pctx, docker, template.Image, DockerAppsRegistryCredentialsFor(template.Image)) {
		slog.Warn("Image pull warning: " + e)
	}
	timedOut := errors.Is(pctx.Err(), context.DeadlineExceeded)
	cancel()
	if timedOut {
		return DockerAppsDeployResult{}, fmt.Errorf("Image pull timed out for %s", template.Image)
	}

	containerName := DockerAppsContainerNamePrefix + name

	// Deploy this template's sidecar (if it has one) BEFORE creating the main
	// container, so a sidecar failure never leaves an app half-deployed with
	// no way to reach the capability it needs. See app_sidecar.go.
	sidecar := dockerAppsTemplateSidecarOf(template.ID)
	if sidecar != nil {
		if _, err := AppSidecarDeploy(ctx, docker, name, sidecar); err != nil {
			return DockerAppsDeployResult{}, err
		}
	}

	// Values this template wants filled in from the domain the operator
	// claimed. Empty for most templates, and for every deploy without a domain.
	var derived []dockerAppsNameValue
	if domain != nil {
		derived = dockerAppsDomainEnvFor(templateID, *domain)
	}

	// Build environment variables: merge template defaults with user-supplied values
	envList := dockerAppsMergeDeployEnv(template.EnvVars, env, derived)
	// Reasserted, not merely defaulted — see AppSidecarSidecarDef.ClientEnvEntry.
	if sidecar != nil {
		envList = slices.DeleteFunc(envList, func(e string) bool { return strings.HasPrefix(e, sidecar.ClientEnvVar+"=") })
		envList = append(envList, sidecar.ClientEnvEntry())
	}

	cport, err := network.ParsePort(template.ContainerPort)
	if err != nil {
		return DockerAppsDeployResult{}, fmt.Errorf("Failed to create container: %v", err)
	}
	portBindings := network.PortMap{
		cport: {{HostIP: dockerAppsLoopback, HostPort: strconv.Itoa(int(port))}},
	}

	// An image that runs as a non-root user starts already dropped and cannot
	// chown the directory we are about to create for it, so resolve who it
	// needs to be owned by before creating any. Root images resolve to nil and
	// are left exactly as they were.
	var volumeOwner *DockerAppsVolumeOwner
	if len(template.Volumes) > 0 {
		volumeOwner = DockerAppsResolveVolumeOwner(ctx, docker, template.Image)
	}

	// Volume binds — create dirs and canonicalize to prevent symlink TOCTOU
	var binds []string
	for _, vol := range template.Volumes {
		hostDir := fmt.Sprintf("%s/%s%s", DockerAppsAppDataDir, name, vol)
		// Create directory before canonicalize (it must exist)
		_ = os.MkdirAll(hostDir, 0o755)
		// Canonicalize to resolve any symlinks, then verify it's still under
		// the allowed prefix
		resolved, err := filepath.EvalSymlinks(hostDir)
		if err != nil {
			return DockerAppsDeployResult{}, fmt.Errorf("Volume path %s inaccessible: %v", hostDir, err)
		}
		if !strings.HasPrefix(resolved, DockerAppsAppDataDir+"/") {
			return DockerAppsDeployResult{}, fmt.Errorf("Volume path %s escapes allowed prefix after canonicalization", hostDir)
		}
		// Give the directory the files the image ships at this path, if it
		// ships any and the directory is empty. Docker does this for a named
		// volume and not for a bind, and this panel binds.
		//
		// AFTER the prefix check, for the same reason the chown below is: the
		// check is what proves the path is one of ours, and writing into a
		// directory is exactly what a symlink escape would want to borrow.
		DockerAppsSeedVolumeFromImage(ctx, docker, template.Image, vol, resolved)

		// Chown AFTER the prefix check, never before.
		if volumeOwner != nil {
			if err := DockerAppsChownTo(resolved, volumeOwner); err == nil {
				g := "unchanged"
				if volumeOwner.GID != nil {
					g = strconv.FormatUint(uint64(*volumeOwner.GID), 10)
				}
				slog.Info(fmt.Sprintf("Volume %s chowned to %d:%s for image user %q", resolved, volumeOwner.UID, g, volumeOwner.Spec))
			} else {
				slog.Warn(fmt.Sprintf("Could not chown volume %s to %d: %v. The app runs as %q and may be unable to write its data directory.",
					resolved, volumeOwner.UID, err, volumeOwner.Spec))
			}
		}
		binds = append(binds, resolved+":"+vol)
	}

	// NOTE: the one-click catalogue deliberately never mounts the host Docker
	// socket for ANY template's OWN container — it gives whatever runs with it
	// full host escape capabilities, not just Docker visibility, regardless of
	// who was allowed to trigger the deploy. Portainer needed it for its core
	// purpose and stays withdrawn — a read-only proxy would gut it and a
	// write-permitting one reopens the risk. Dozzle only ever needed to list
	// containers and read logs, so it was reinstated behind a
	// docker-socket-proxy sidecar that holds the real socket instead — see
	// dockerAppsTemplateSidecar / app_sidecar.go. An admin who wants a
	// different socket-mounted tool can still build one outside this
	// sandboxing entirely.

	hostConfig := &container.HostConfig{
		PortBindings:  portBindings,
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		SecurityOpt:   []string{"no-new-privileges:true"},
		CapDrop:       []string{"ALL"},
		CapAdd:        []string{"CHOWN", "SETUID", "SETGID", "NET_BIND_SERVICE", "DAC_OVERRIDE", "FOWNER", "SETFCAP"},
	}

	// Docker resource limits
	if memoryMb != nil && *memoryMb > 0 {
		// Saturating multiply: an absurd memory_mb must not wrap to a
		// garbage/negative limit; the backend also clamps to 4..=65536.
		hostConfig.Memory = dockerAppsSatMulI64(*memoryMb, 1024*1024)
		// Memory swap = 2x memory (allows some swap)
		hostConfig.MemorySwap = dockerAppsSatMulI64(*memoryMb, 2*1024*1024)
	}
	if cpuPercent != nil && *cpuPercent > 0 {
		// cpu_percent is % of ONE core (100 = 1.0 core); values > 100 request
		// multiple cores, so CPUQuota may exceed CPUPeriod. A `cpu <= 100`
		// bound once silently dropped the limit for any multi-core request →
		// the container ran with UNLIMITED CPU.
		hostConfig.CPUPeriod = 100_000
		hostConfig.CPUQuota = dockerAppsSatMulI64(*cpuPercent, 1000)
	}

	// GPU passthrough (requires NVIDIA Container Toolkit installed on host).
	// Two modes: all GPUs (Count -1) vs specific indices (DeviceIDs). Setting
	// both would be rejected by the daemon, so they're mutually exclusive.
	if gpuEnabled {
		req := container.DeviceRequest{
			Driver:       "nvidia",
			Capabilities: [][]string{{"gpu", "compute", "utility"}},
		}
		var logTarget string
		if len(gpuIndices) > 0 {
			ids := make([]string, 0, len(gpuIndices))
			for _, i := range gpuIndices {
				ids = append(ids, strconv.FormatUint(uint64(i), 10))
			}
			req.DeviceIDs = ids
			logTarget = fmt.Sprintf("specific GPU(s) [%s]", strings.Join(ids, ","))
		} else {
			req.Count = -1
			logTarget = "all available GPUs"
		}
		hostConfig.DeviceRequests = []container.DeviceRequest{req}
		// NOTE: GPU compute via the NVIDIA Container Toolkit does NOT need
		// CAP_SYS_ADMIN — the device request grants GPU access. Granting
		// SYS_ADMIN would reverse the cap_drop ALL hardening (mount(2)/cgroup
		// container→host escape), so it is deliberately NOT added.
		slog.Info(fmt.Sprintf("GPU passthrough enabled for container %s: %s", containerName, logTarget))
	}

	if len(binds) > 0 {
		hostConfig.Binds = binds
	}

	labels := map[string]string{
		"dockpanel.managed":      "true",
		"dockpanel.app.template": template.ID,
		"dockpanel.app.name":     name,
	}
	if domain != nil {
		labels["dockpanel.app.domain"] = *domain
	}
	if userID != nil {
		labels["dockpanel.user.id"] = *userID
	}

	config := &container.Config{
		Image: template.Image,
		// nil for all but a handful of templates, which leaves the image's own
		// CMD in charge. See dockerAppsTemplateCmd: without this the container
		// inherits a default that may print usage and exit 0 (#101).
		Cmd:          dockerAppsTemplateCmdOf(template.ID),
		Env:          envList,
		ExposedPorts: network.PortSet{cport: {}},
		Labels:       labels,
	}
	var netConfig *network.NetworkingConfig
	if sidecar != nil {
		// Attaches to the sidecar's private network instead of the default
		// bridge — the SAME config every recreate path applies via
		// dockerAppsReattachSidecarIfAny.
		netConfig = AppSidecarAttachConfig(name)
	}

	created, err := docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: containerName, Config: config, HostConfig: hostConfig, NetworkingConfig: netConfig,
	})
	if err != nil {
		// A sidecar deployed above and never given a main container is not a
		// partial app an operator could ever find or delete — take it and its
		// network with the failed deploy.
		if sidecar != nil {
			AppSidecarTeardown(ctx, name)
		}
		return DockerAppsDeployResult{}, fmt.Errorf("Failed to create container: %v", err)
	}

	if _, err := docker.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		// Clean up the orphaned container. It never started, so any anonymous
		// volume Docker gave it is empty by construction — take them with it.
		// Bind sources hold the app's real data and are not touched by the flag.
		_, _ = docker.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{RemoveVolumes: true, Force: true})
		if sidecar != nil {
			AppSidecarTeardown(ctx, name)
		}
		return DockerAppsDeployResult{}, fmt.Errorf("Failed to start container: %v", err)
	}

	slog.Info(fmt.Sprintf("App deployed: %s (template=%s, port=%d)", containerName, template.ID, port))
	return DockerAppsDeployResult{ContainerID: created.ID, Name: containerName, Port: port}, nil
}

// DockerAppsListDeployedApps lists all deployed apps (containers with the
// dockpanel.app.template label).
func DockerAppsListDeployedApps(ctx context.Context) ([]DockerAppsDeployedApp, error) {
	docker, err := dockerAppsConnect()
	if err != nil {
		return nil, err
	}
	defer docker.Close()

	list, err := docker.ContainerList(ctx, client.ContainerListOptions{
		All:     true,
		Filters: client.Filters{}.Add("label", "dockpanel.managed=true"),
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to list containers: %v", err)
	}

	apps := []DockerAppsDeployedApp{}
	for _, c := range list.Items {
		// Only include containers that have the app template label
		template, ok := c.Labels["dockpanel.app.template"]
		if c.Labels == nil || !ok || c.ID == "" {
			continue
		}
		var port *uint16
		for _, p := range c.Ports {
			if p.PublicPort != 0 {
				pp := p.PublicPort
				port = &pp
				break
			}
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimLeft(c.Names[0], "/")
		}
		var domain *string
		if d, ok := c.Labels["dockpanel.app.domain"]; ok {
			domain = &d
		}
		image := c.Image

		// Extract volume mounts
		volumes := []string{}
		for _, m := range c.Mounts {
			volumes = append(volumes, fmt.Sprintf("%s → %s", m.Source, m.Destination))
		}

		// Extract health from the human-readable status ("Up 2 hours (healthy)")
		var health *string
		for _, h := range [][2]string{{"(healthy)", "healthy"}, {"(unhealthy)", "unhealthy"}, {"(health: starting)", "starting"}} {
			if strings.Contains(c.Status, h[0]) {
				v := h[1]
				health = &v
				break
			}
		}

		app := DockerAppsDeployedApp{
			ContainerID: c.ID,
			Name:        name,
			Template:    template,
			Status:      string(c.State),
			Port:        port,
			Domain:      domain,
			Ssl:         domain != nil && NginxDomainIsHttps(*domain),
			Health:      health,
			Image:       &image,
			Volumes:     volumes,
		}
		if v, ok := c.Labels["dockpanel.stack_id"]; ok {
			app.StackID = &v
		}
		if v, ok := c.Labels["dockpanel.user.id"]; ok {
			app.UserID = &v
		}
		apps = append(apps, app)
	}
	return apps, nil
}

// dockerAppsCurrentAppName: this container's app name, read fresh from Docker
// — used by the power-action and removal paths to find a paired sidecar
// without assuming the caller already has the labels in hand. ok=false only
// when the container itself cannot be inspected, which every caller treats as
// "nothing to mirror": the main action is what the operator asked for.
func dockerAppsCurrentAppName(ctx context.Context, docker *client.Client, containerID string) (string, bool) {
	info, err := docker.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return "", false
	}
	var labels map[string]string
	if info.Container.Config != nil {
		labels = info.Container.Config.Labels
	}
	return dockerAppsAppDataName(labels, strings.TrimLeft(info.Container.Name, "/")), true
}

func dockerAppsSeconds(n int) *int { return &n }

// DockerAppsStopApp stops a running app container.
func DockerAppsStopApp(ctx context.Context, containerID string) error {
	docker, err := dockerAppsConnect()
	if err != nil {
		return err
	}
	defer docker.Close()
	if app, ok := dockerAppsCurrentAppName(ctx, docker, containerID); ok {
		AppSidecarMirrorStop(ctx, docker, app)
	}
	if _, err := docker.ContainerStop(ctx, containerID, client.ContainerStopOptions{Timeout: dockerAppsSeconds(10)}); err != nil {
		return fmt.Errorf("Failed to stop container: %v", err)
	}
	slog.Info("App container stopped: " + containerID)
	return nil
}

// DockerAppsStartApp starts a stopped app container.
func DockerAppsStartApp(ctx context.Context, containerID string) error {
	docker, err := dockerAppsConnect()
	if err != nil {
		return err
	}
	defer docker.Close()
	// Sidecar first: an app whose sidecar is still cold should not race its
	// own first connection attempt against it.
	if app, ok := dockerAppsCurrentAppName(ctx, docker, containerID); ok {
		AppSidecarMirrorStart(ctx, docker, app)
	}
	if _, err := docker.ContainerStart(ctx, containerID, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("Failed to start container: %v", err)
	}
	slog.Info("App container started: " + containerID)
	return nil
}

// DockerAppsRestartApp restarts an app container.
func DockerAppsRestartApp(ctx context.Context, containerID string) error {
	docker, err := dockerAppsConnect()
	if err != nil {
		return err
	}
	defer docker.Close()
	if app, ok := dockerAppsCurrentAppName(ctx, docker, containerID); ok {
		AppSidecarMirrorRestart(ctx, docker, app)
	}
	if _, err := docker.ContainerRestart(ctx, containerID, client.ContainerRestartOptions{Timeout: dockerAppsSeconds(10)}); err != nil {
		return fmt.Errorf("Failed to restart container: %v", err)
	}
	slog.Info("App container restarted: " + containerID)
	return nil
}

// dockerAppsReadLogs reads a container's stdout+stderr (last `tail` lines),
// demultiplexing the non-TTY stream format and passing a TTY's raw stream
// through, as bollard's LogOutput did.
func dockerAppsReadLogs(ctx context.Context, docker *client.Client, containerID, tail string) (string, error) {
	rc, err := docker.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: tail})
	if err != nil {
		return "", err
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}
	// A multiplexed frame starts {1|2, 0, 0, 0, size…}; anything else is a TTY.
	if len(raw) >= 8 && raw[0] <= 2 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 {
		var out bytes.Buffer
		if _, err := stdcopy.StdCopy(&out, &out, bytes.NewReader(raw)); err == nil {
			return strings.ToValidUTF8(out.String(), "�"), nil
		}
	}
	return strings.ToValidUTF8(string(raw), "�"), nil
}

// DockerAppsGetAppLogs returns container logs (last N lines).
func DockerAppsGetAppLogs(ctx context.Context, containerID string, tail int) (string, error) {
	docker, err := dockerAppsConnect()
	if err != nil {
		return "", err
	}
	defer docker.Close()
	logs, err := dockerAppsReadLogs(ctx, docker, containerID, strconv.Itoa(tail))
	if err != nil {
		return "", fmt.Errorf("Failed to read logs: %v", err)
	}
	return logs, nil
}

// DockerAppsFindFreePort finds a free port for the blue-green container by
// asking the OS.
func DockerAppsFindFreePort() (uint16, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("Failed to find free port: %v", err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port), nil
}

// DockerAppsHealthCheckPort waits for a container to accept TCP connections
// on a port.
func DockerAppsHealthCheckPort(ctx context.Context, port uint16, timeoutSecs uint64) error {
	deadline := time.Now().Add(time.Duration(timeoutSecs) * time.Second)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for {
		var d net.Dialer
		if conn, err := d.DialContext(ctx, "tcp", addr); err == nil {
			conn.Close()
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("Container failed health check on port %d after %ds", port, timeoutSecs)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Container failed health check on port %d after %ds", port, timeoutSecs)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// DockerAppsSwapNginxProxyPort swaps the proxy_pass port in an existing nginx
// config file.
func DockerAppsSwapNginxProxyPort(domain string, oldPort, newPort uint16) error {
	configPath := fmt.Sprintf("%s/%s.conf", NginxSitesDir(), domain)
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("Failed to read nginx config: %v", err)
	}
	oldPattern := fmt.Sprintf("proxy_pass http://127.0.0.1:%d;", oldPort)
	newPattern := fmt.Sprintf("proxy_pass http://127.0.0.1:%d;", newPort)
	if !strings.Contains(string(content), oldPattern) {
		return fmt.Errorf("Nginx config for %s does not contain proxy_pass on port %d", domain, oldPort)
	}
	newContent := strings.ReplaceAll(string(content), oldPattern, newPattern)

	// Atomic write
	tmpPath := configPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(newContent), 0o644); err != nil {
		return fmt.Errorf("Failed to write nginx config: %v", err)
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("Failed to rename nginx config: %v", err)
	}
	return nil
}

// DockerAppsExtractHostPort extracts the host port from a container's
// HostConfig port bindings (the first binding of an arbitrary port, as the
// Rust HashMap iteration did).
func DockerAppsExtractHostPort(hc *container.HostConfig) *uint16 {
	if hc == nil {
		return nil
	}
	for _, bindings := range hc.PortBindings {
		if len(bindings) == 0 {
			return nil
		}
		p, err := strconv.ParseUint(bindings[0].HostPort, 10, 16)
		if err != nil {
			return nil
		}
		port := uint16(p)
		return &port
	}
	return nil
}

// DockerAppsInspectHostPort is the same port DockerAppsExtractHostPort reads
// for removal, for a caller that only has a container id — a fresh inspect,
// so it works whether the container is running or stopped. The list API's
// port cannot substitute: it reports only a LIVE binding, empty for a stopped
// ("parked") container even though its HostConfig still carries it. nil means
// no recorded binding or the container is gone; a caller proving ownership of
// a vhost must treat both as "refuse to delete rather than guess".
func DockerAppsInspectHostPort(ctx context.Context, containerID string) *uint16 {
	docker, err := dockerAppsConnect()
	if err != nil {
		return nil
	}
	defer docker.Close()
	info, err := docker.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return nil
	}
	return DockerAppsExtractHostPort(info.Container.HostConfig)
}

// DockerAppsMountedDestinations returns the mount destinations this container
// already has, read from BOTH spellings: a `Binds` entry ("src:dst[:opts]")
// or a `Mounts` entry carrying a target. A census keyed on one is blind to
// the other, so this reads both and returns the union.
func DockerAppsMountedDestinations(hc *container.HostConfig) []string {
	dests := []string{}
	for _, bind := range hc.Binds {
		// The destination is the second field, so split from the left.
		if parts := strings.Split(bind, ":"); len(parts) > 1 && parts[1] != "" {
			dests = append(dests, parts[1])
		}
	}
	for _, m := range hc.Mounts {
		if m.Target != "" {
			dests = append(dests, m.Target)
		}
	}
	return dests
}

// dockerAppsUnmountedDeclaredVolumes: paths this container's own template
// calls persistent that nothing actually mounts.
//
// Empty for anything we are not entitled to touch: a container without
// dockpanel.managed=true, one whose template label names no template we ship,
// or one whose declared paths are all mounted already.
func dockerAppsUnmountedDeclaredVolumes(config *container.Config, hc *container.HostConfig) []string {
	if config == nil || config.Labels == nil {
		return nil
	}
	if config.Labels["dockpanel.managed"] != "true" {
		return nil
	}
	templateID, ok := config.Labels["dockpanel.app.template"]
	if !ok {
		return nil
	}
	var declared []string
	if t := dockerAppsTemplateByID(templateID); t != nil {
		declared = t.Volumes
	} else {
		// Not every managed container comes from the one-click catalogue, and
		// the ones that do not were getting no migration at all — see
		// dockerAppsNonCatalogueVolumes.
		declared = dockerAppsNonCatalogueVolumes(templateID)
	}
	mounted := DockerAppsMountedDestinations(hc)
	var out []string
	for _, vol := range declared {
		if !slices.Contains(mounted, vol) {
			out = append(out, vol)
		}
	}
	return out
}

// dockerAppsNonCatalogueVolumes: paths kept by a managed container whose
// template label names no catalogue row.
//
// The label is not proof of a template. The mail stack installs its webmail
// container with dockpanel.managed=true and a template label of its own, and
// nothing in the catalogue answers to that name — so every recreate door
// removed the container with its writable layer and everything in it (#110,
// against a container the panel installs itself: the webmail keeps accounts,
// identities, contacts and preferences in SQLite, and the image declares no
// volume to catch it).
//
// The path is measured: the image's entrypoint selects a local SQLite store
// under /var/roundcube/db whenever no database is configured by environment,
// and the mail stack configures none.
//
// A compose service is the other container that reaches here, and it is
// genuinely fine: its mounts come from the stack's own YAML. It returns no
// paths by falling through, and that is a decision rather than an oversight.
func dockerAppsNonCatalogueVolumes(templateID string) []string {
	switch templateID {
	case "roundcube":
		return []string{"/var/roundcube/db"}
	}
	return nil
}

// dockerAppsAppDataName: the app's own name — the one whose directory under
// DockerAppsAppDataDir holds its data.
//
// The deploy creates the container as `dockpanel-app-<app>` but writes its
// volume directories at `{AppDataDir}/<app>{vol}`. Every recreate path reads
// the CONTAINER name, and handing that straight to the migration landed a
// rescued app's data under a directory nothing else in the panel ever looks
// at — orphaned in silence.
//
// The label is the app's real name. Stripping the container prefix is the
// fallback for a container that somehow carries no label.
func dockerAppsAppDataName(labels map[string]string, containerName string) string {
	if name := labels["dockpanel.app.name"]; name != "" {
		return name
	}
	return strings.TrimPrefix(containerName, DockerAppsContainerNamePrefix)
}

// DockerAppsMigrateUnmountedVolumes carries an app's data out of the
// container's writable layer and onto a bind mount, on the way through a
// recreate.
//
// Every recreate path stops the container, `docker rm`s it and rebuilds the
// replacement from an inspect of the original — and `docker rm` deletes the
// writable layer. For a container with no mount covering the directory its
// app writes to, that layer IS the storage, so the recreate is unrecoverable
// deletion. GitHub #110 is exactly this. Declaring the volume fixes the NEXT
// deploy; this closes the other half — the destructive step becomes the
// repair. Limits, all deliberate:
//
//   - Only paths the container's OWN template declares and the container does
//     not mount. An operator who arranged their own bind keeps it.
//   - Only into a host directory that is absent or empty. A non-empty one is
//     somebody's data and this declines rather than merging into it.
//   - **Any failure is returned, and every caller must abort the recreate
//     before removing the container.** A migration that half-worked followed
//     by a `docker rm` would destroy the very data it was called to save.
func DockerAppsMigrateUnmountedVolumes(ctx context.Context, dataDir string, docker *client.Client, containerID, name, image string,
	missing []string, hc *container.HostConfig) ([]string, error) {
	migrated := []string{}
	if len(missing) == 0 {
		return migrated, nil
	}
	owner := DockerAppsResolveVolumeOwner(ctx, docker, image)
	binds := slices.Clone(hc.Binds)

	for _, vol := range missing {
		hostDir := fmt.Sprintf("%s/%s%s", dataDir, name, vol)
		if empty, ok := dockerAppsDirIsEmpty(hostDir); ok && !empty {
			return nil, fmt.Errorf("Refusing to migrate %s for %s: %s already exists and is not empty. "+
				"Move it aside and retry, or mount it yourself.", vol, name, hostDir)
		}
		if err := os.MkdirAll(hostDir, 0o755); err != nil {
			return nil, fmt.Errorf("Failed to create %s: %v", hostDir, err)
		}
		// Canonicalize then re-check the prefix, exactly as the deploy does.
		resolved, err := filepath.EvalSymlinks(hostDir)
		if err != nil {
			return nil, fmt.Errorf("Volume path %s inaccessible: %v", hostDir, err)
		}
		if !strings.HasPrefix(resolved, dataDir+"/") {
			return nil, fmt.Errorf("Volume path %s escapes allowed prefix after canonicalization", hostDir)
		}

		// `<container>:<path>/.` copies the CONTENTS of the directory, so the
		// data lands directly in the host directory.
		//
		// ⚠ It does NOT carry ownership across: `docker cp` out of a container
		// writes as the user running it — root, for the agent — and
		// `--archive` does not change it (both measured). The tree is therefore
		// chowned explicitly below. See #110.
		out, err := safecmd.Exec(ctx, "docker", "cp", containerID+":"+vol+"/.", resolved)
		if err != nil {
			return nil, fmt.Errorf("Failed to run docker cp for %s: %v", vol, err)
		}
		if !out.Success() {
			stderr := string(out.Stderr)
			// A path the image never created carries nothing to lose. Not a
			// failure — but the bind is still added, so the NEXT recreate has
			// somewhere durable to write.
			absent := strings.Contains(stderr, "No such container:path") ||
				strings.Contains(stderr, "no such file or directory") ||
				strings.Contains(stderr, "Could not find the file")
			if !absent {
				return nil, fmt.Errorf("Failed to copy %s out of %s: %s", vol, name, strings.TrimSpace(stderr))
			}
			slog.Info(fmt.Sprintf("Nothing to migrate at %s for %s — the path does not exist in the container; "+
				"mounting it empty so future updates preserve it", vol, name))
		}

		// Deliberately NOT fatal. Aborting here would strand the copy: the host
		// directory is now non-empty, so the refusal at the top of this loop
		// would decline every later attempt, turning a recoverable state into a
		// permanent one. As root, on a directory created moments ago, this does
		// not realistically fail — and if it does, it is logged at error.
		if owner != nil {
			if touched, err := dockerAppsChownMigratedTree(resolved, owner); err == nil {
				slog.Info(fmt.Sprintf("Migrated volume %s: %d path(s) chowned to %d for image user %q", resolved, touched, owner.UID, owner.Spec))
			} else {
				slog.Error(fmt.Sprintf("Could not chown migrated volume %s to %d: %v. The app runs as %q and WILL be unable to "+
					"write the data just rescued — chown the directory by hand and recreate the app.", resolved, owner.UID, err, owner.Spec))
			}
		}
		binds = append(binds, resolved+":"+vol)
		migrated = append(migrated, vol)
		slog.Info(fmt.Sprintf("Migrated %s%s onto %s — it now survives recreates", name, vol, resolved))
	}

	hc.Binds = binds
	return migrated, nil
}

// DockerAppsSharesPersistentState: does this container hold state that a
// second copy of it would fight over?
//
// Blue-green starts the replacement while the original is still serving, and
// for that window (up to 30s of health checking plus an nginx test and
// reload) two processes run against the SAME host paths, because the
// blue-green clone rewrites only port bindings. Harmless when the only state
// is the writable layer; data corruption when the state is a single-writer
// database in a bind mount. Postgres/MySQL/Mongo self-protect with a pidfile
// lock; **SQLite has no such lock**, so Ghost, Gitea, Bookstack and
// Vaultwarden would interleave writes silently. There is no way to ask an
// image whether it tolerates two writers, so "has a mount" reads as "assume
// it does not".
func DockerAppsSharesPersistentState(hc *container.HostConfig) bool {
	// VolumesFrom points at another container's mounts, which are shared by
	// definition. Anonymous volumes are deliberately NOT counted: Docker gives
	// the replacement its own.
	return len(hc.Binds) > 0 || len(hc.Mounts) > 0 || len(hc.VolumesFrom) > 0
}

// dockerAppsRecreateConfig is the Config every recreate path builds from the
// inspected original: image, env, exposed ports, labels, cmd, entrypoint and
// working dir carried; everything else left to the image.
func dockerAppsRecreateConfig(config *container.Config, image string, env []string, cmd, entrypoint []string) *container.Config {
	return &container.Config{
		Image:        image,
		Env:          env,
		ExposedPorts: config.ExposedPorts,
		Labels:       config.Labels,
		Cmd:          cmd,
		Entrypoint:   entrypoint,
		WorkingDir:   config.WorkingDir,
	}
}

// dockerAppsStopRemove stops (t seconds) and force-removes a container,
// keeping its volumes; errors ignored (rollback/cleanup paths).
func dockerAppsStopRemove(ctx context.Context, docker *client.Client, id string, t int) {
	_, _ = docker.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: dockerAppsSeconds(t)})
	_, _ = docker.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true})
}

// dockerAppsBlueGreenUpdate: start new container → health check → swap nginx
// → remove old. On ANY failure, rolls back and returns an error so the caller
// can fall back to stop/start.
func dockerAppsBlueGreenUpdate(ctx context.Context, docker *client.Client, oldContainerID, name string,
	config *container.Config, hc *container.HostConfig, domain string, oldPort uint16) (DockerAppsUpdateResult, error) {
	// Held for the full duration — every swap below (temp-port swap, and every
	// rollback arm) writes the same `{sites_dir}/{domain}.conf` file
	// expose/unexpose also lock. Single call site, no lock held by the caller,
	// so this cannot nest/deadlock.
	defer sitelock.LockSite(domain)()

	tempPort, err := DockerAppsFindFreePort()
	if err != nil {
		return DockerAppsUpdateResult{}, err
	}
	slog.Info(fmt.Sprintf("Blue-green update for %s: old_port=%d, temp_port=%d", name, oldPort, tempPort))

	// Build new host config with the temp port
	newHC := *hc
	newHC.PortBindings = network.PortMap{}
	for p, bindings := range hc.PortBindings {
		nb := slices.Clone(bindings)
		for i := range nb {
			nb[i].HostPort = strconv.Itoa(int(tempPort))
		}
		newHC.PortBindings[p] = nb
	}

	// The separator is `.` and not `-` because isValidName rejects `.`: an app
	// may legally be called `api-blue`, and `dockpanel-app-api-blue` was
	// therefore both its production container AND the stand-in for `api`.
	newName := OwnershipBlueName(name)

	// Clean up the leftover of a failed previous attempt — if it is ours.
	if info, err := docker.ContainerInspect(ctx, newName, client.ContainerInspectOptions{}); err == nil {
		var labels map[string]string
		if info.Container.Config != nil {
			labels = info.Container.Config.Labels
		}
		owner := OwnershipBlueLeftover(labels)
		if !owner.MayDelete() {
			return DockerAppsUpdateResult{}, fmt.Errorf("A container named %s exists and is not managed by DockPanel "+
				"(%s); refusing to force-remove it to make room for a blue-green swap", newName, owner)
		}
		dockerAppsStopRemove(ctx, docker, newName, 5)
	}

	// Keyed off the real app name, not newName — the sidecar and its network
	// are the app's, unaffected by the swap.
	appName := dockerAppsAppDataName(config.Labels, name)
	envList, netConfig := dockerAppsReattachSidecarIfAny(config.Labels, appName, slices.Clone(config.Env))

	created, err := docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:             newName,
		Config:           dockerAppsRecreateConfig(config, config.Image, envList, config.Cmd, config.Entrypoint),
		HostConfig:       &newHC,
		NetworkingConfig: netConfig,
	})
	if err != nil {
		return DockerAppsUpdateResult{}, fmt.Errorf("Failed to create blue container: %v", err)
	}
	newID := created.ID
	cleanupNew := func() { dockerAppsStopRemove(ctx, docker, newID, 5) }

	if _, err := docker.ContainerStart(ctx, newID, client.ContainerStartOptions{}); err != nil {
		_, _ = docker.ContainerRemove(ctx, newID, client.ContainerRemoveOptions{Force: true})
		return DockerAppsUpdateResult{}, fmt.Errorf("Failed to start blue container: %v", err)
	}

	// Health check the new container (30s timeout)
	if err := DockerAppsHealthCheckPort(ctx, tempPort, 30); err != nil {
		cleanupNew()
		return DockerAppsUpdateResult{}, fmt.Errorf("Blue container health check failed: %v", err)
	}

	// Swap nginx to point to the new container's port
	if err := DockerAppsSwapNginxProxyPort(domain, oldPort, tempPort); err != nil {
		cleanupNew()
		return DockerAppsUpdateResult{}, fmt.Errorf("Nginx port swap failed: %v", err)
	}

	// Test nginx config before reloading
	out, err := NginxTestConfig()
	switch {
	case err != nil:
		_ = DockerAppsSwapNginxProxyPort(domain, tempPort, oldPort)
		cleanupNew()
		return DockerAppsUpdateResult{}, fmt.Errorf("Nginx test error: %v", err)
	case !out.Success:
		// Rollback nginx + cleanup blue container
		_ = DockerAppsSwapNginxProxyPort(domain, tempPort, oldPort)
		cleanupNew()
		return DockerAppsUpdateResult{}, fmt.Errorf("Nginx config test failed: %s", out.Stderr)
	}
	if err := NginxReload(); err != nil {
		_ = DockerAppsSwapNginxProxyPort(domain, tempPort, oldPort)
		cleanupNew()
		return DockerAppsUpdateResult{}, fmt.Errorf("Nginx reload failed: %v", err)
	}

	// Traffic is now flowing to the new container. Promote it.
	//
	// ORDER MATTERS. The old order was destroy-then-rename with both results
	// discarded: when the removal failed the rename could not succeed — the
	// name was still taken — and the update returned success over a
	// half-swapped host (old alive under the real name, new alive as the
	// stand-in, nginx pointing at the stand-in). So: free the name first, by a
	// rename that destroys nothing and can be undone. Only once the promotion
	// is real does anything get removed.
	retiredName := name + ".retired"
	if _, err := docker.ContainerRename(ctx, oldContainerID, client.ContainerRenameOptions{NewName: retiredName}); err != nil {
		// Nothing has been destroyed. Put traffic back on the old container
		// and fail honestly.
		_ = DockerAppsSwapNginxProxyPort(domain, tempPort, oldPort)
		_ = NginxReload()
		cleanupNew()
		return DockerAppsUpdateResult{}, fmt.Errorf("Could not free the container name for promotion: %v. Rolled back — the previous "+
			"container is still serving %s.", err, domain)
	}

	if _, err := docker.ContainerRename(ctx, newID, client.ContainerRenameOptions{NewName: name}); err != nil {
		// The name is free and the old container is untouched and still
		// running — put it back under the real name.
		_, _ = docker.ContainerRename(ctx, oldContainerID, client.ContainerRenameOptions{NewName: name})
		_ = DockerAppsSwapNginxProxyPort(domain, tempPort, oldPort)
		_ = NginxReload()
		cleanupNew()
		return DockerAppsUpdateResult{}, fmt.Errorf("Could not promote the new container: %v. Rolled back — the previous container is "+
			"still serving %s.", err, domain)
	}

	// Promotion is committed. Removing the retired container is housekeeping:
	// a failure leaks a stopped container under a name nothing can be created
	// as, which is why it is safe to only log it.
	_, _ = docker.ContainerStop(ctx, retiredName, client.ContainerStopOptions{Timeout: dockerAppsSeconds(10)})
	if _, err := docker.ContainerRemove(ctx, retiredName, client.ContainerRemoveOptions{Force: true}); err != nil {
		slog.Warn(fmt.Sprintf("Blue-green for %s promoted cleanly but %s could not be removed: %v. It is stopped and holds no port; "+
			"remove it by hand.", name, retiredName, err))
	}

	slog.Info(fmt.Sprintf("App updated (blue-green, zero-downtime): %s, port %d → %d", name, oldPort, tempPort))
	return DockerAppsUpdateResult{
		ContainerID: newID,
		BlueGreen:   true,
		// Blue-green is only reached when nothing needed migrating.
		MigratedVolumes: []string{},
		RepairedVolumes: []string{},
	}, nil
}

// dockerAppsPullVerdict is what an update should do once the pull attempt
// has finished. Kept separate from Docker so all four cases can be unit
// tested: reaching them for real needs a registry that refuses.
type dockerAppsPullVerdict int

const (
	// The pull reported no error. Carry on.
	dockerAppsPullProceed dockerAppsPullVerdict = iota
	// The pull failed, but what the tag resolves to on this server is not
	// what the container is running — an update really is waiting on disk and
	// applying it is the point of the button.
	dockerAppsPullProceedFromLocal
	// The pull failed and the tag resolves to nothing on this server. The
	// recreate would remove a container that cannot then be rebuilt.
	dockerAppsPullRefuseMissing
	// The pull failed and the local copy is byte-for-byte what the container
	// is already running. Recreating spends an outage to arrive where it
	// started.
	dockerAppsPullRefuseNoChange
)

// dockerAppsDecidePull decides the verdict from three facts read out of
// Docker. runningImage being absent is treated as "not equal", which lands
// on ProceedFromLocal: the image exists locally, so nothing can be destroyed,
// and refusing on missing metadata would block an update that would work.
func dockerAppsDecidePull(pullError, localImage, runningImage *string) dockerAppsPullVerdict {
	if pullError == nil {
		return dockerAppsPullProceed
	}
	switch {
	case localImage == nil:
		return dockerAppsPullRefuseMissing
	case runningImage != nil && *localImage == *runningImage:
		return dockerAppsPullRefuseNoChange
	default:
		return dockerAppsPullProceedFromLocal
	}
}

// dockerAppsWasRunning reads `status`, not `running`: a PAUSED container
// reports running as well, and a paused app is not one the operator left up.
//
// A recreate that always starts the new container turns "update this app"
// into "update and start it", so pressing Update on something deliberately
// stopped brought it back up — on a host where it had been stopped for a
// reason.
func dockerAppsWasRunning(info *container.InspectResponse) bool {
	return info.State != nil && info.State.Status == container.StateRunning
}

// dockerAppsInspectForRecreate inspects a container and returns the pieces
// every recreate path needs, with the Rust error strings.
func dockerAppsInspectForRecreate(ctx context.Context, docker *client.Client, containerID string) (*container.InspectResponse, *container.Config, *container.HostConfig, string, error) {
	res, err := docker.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("Failed to inspect container: %v", err)
	}
	info := res.Container
	if info.Config == nil {
		return nil, nil, nil, "", errors.New("No container config found")
	}
	if info.HostConfig == nil {
		return nil, nil, nil, "", errors.New("No host config found")
	}
	return &info, info.Config, info.HostConfig, strings.TrimLeft(info.Name, "/"), nil
}

// DockerAppsUpdateApp updates an app by pulling the latest image. Uses
// blue-green deployment (zero-downtime) when the app has a domain with an
// nginx reverse proxy; falls back to stop/start otherwise.
func DockerAppsUpdateApp(ctx context.Context, containerID string) (DockerAppsUpdateResult, error) {
	docker, err := dockerAppsConnect()
	if err != nil {
		return DockerAppsUpdateResult{}, err
	}
	defer docker.Close()

	info, config, hc, name, err := dockerAppsInspectForRecreate(ctx, docker, containerID)
	if err != nil {
		return DockerAppsUpdateResult{}, err
	}
	wasRunning := dockerAppsWasRunning(info)
	// The image the container is actually running, which the verdict compares
	// against whatever the tag resolves to locally.
	var runningImage *string
	if info.Image != "" {
		runningImage = &info.Image
	}
	image := config.Image
	if image == "" {
		return DockerAppsUpdateResult{}, errors.New("No image found")
	}
	// The container is `dockpanel-app-<app>`; its DATA lives under the app's
	// own name.
	appName := dockerAppsAppDataName(config.Labels, name)

	// Anything this app's template calls persistent that the container does
	// not mount is living in the writable layer, which the recreate below
	// deletes (#110). Decided BEFORE choosing a strategy: migrating needs the
	// container stopped, which only the stop/start path gives us.
	unmounted := dockerAppsUnmountedDeclaredVolumes(config, hc)

	// Check if this app has a domain (nginx reverse proxy) for blue-green
	domain, hasDomain := config.Labels["dockpanel.app.domain"]
	oldPort := DockerAppsExtractHostPort(hc)

	// Pull the latest image
	slog.Info(fmt.Sprintf("Updating app %s: pulling %s", name, image))
	var pullError *string
	if errs := DockerAppsPullImage(ctx, docker, image, DockerAppsRegistryCredentialsFor(image)); len(errs) > 0 {
		pullError = &errs[len(errs)-1]
	}

	// A failed pull used to be one line in the agent's log, so the recreate
	// ran regardless: when the tag had gone away that spent a real outage
	// rebuilding the container from what was already on disk, and the
	// operator was told the app had updated. Decided before anything is
	// stopped, so a refusal costs the app nothing.
	var localImage *string
	if ii, err := docker.ImageInspect(ctx, image); err == nil && ii.ID != "" {
		localImage = &ii.ID
	}
	pullFailure := "unknown error"
	if pullError != nil {
		pullFailure = *pullError
	}
	switch dockerAppsDecidePull(pullError, localImage, runningImage) {
	case dockerAppsPullProceedFromLocal:
		slog.Warn(fmt.Sprintf("App %s: '%s' could not be pulled (%s), but the copy on this server differs from what the "+
			"container is running, so the update continues from it", name, image, pullFailure))
	case dockerAppsPullRefuseMissing:
		return DockerAppsUpdateResult{}, fmt.Errorf("'%s' could not be pulled and no copy of it exists on this server, so "+
			"%s was left untouched — recreating it would have removed a container that could not be rebuilt. The app is "+
			"still running. Pull error: %s", image, name, pullFailure)
	case dockerAppsPullRefuseNoChange:
		return DockerAppsUpdateResult{}, fmt.Errorf("'%s' could not be pulled, and the copy on this server is already what "+
			"%s is running, so there is nothing to update. The app is still running and was left untouched. Pull error: %s",
			image, name, pullFailure)
	}

	// Try blue-green if the app has a domain and a known port — and only if
	// running two copies of it at once cannot corrupt anything.
	if hasDomain && oldPort != nil {
		configPath := fmt.Sprintf("%s/%s.conf", NginxSitesDir(), domain)
		if len(unmounted) > 0 {
			slog.Info(fmt.Sprintf("Not using blue-green for %s: %d declared path(s) are unmounted and have to be migrated "+
				"out of the writable layer first, which needs the container stopped. Using stop/start instead.", name, len(unmounted)))
		} else if DockerAppsSharesPersistentState(hc) {
			slog.Info(fmt.Sprintf("Not using blue-green for %s: it has persistent mounts, and blue-green would run the old and "+
				"new containers against the same host paths for the length of the health check. Using stop/start instead "+
				"(brief downtime, no concurrent writers).", name))
		} else if !wasRunning {
			slog.Info(fmt.Sprintf("Not using blue-green for %s: it is stopped, and blue-green exists to avoid downtime for "+
				"something that is up. Using stop/start instead, which leaves it stopped.", name))
		} else if _, err := os.Stat(configPath); err == nil {
			result, err := dockerAppsBlueGreenUpdate(ctx, docker, containerID, name, config, hc, domain, *oldPort)
			if err == nil {
				return result, nil
			}
			slog.Warn(fmt.Sprintf("Blue-green failed for %s, falling back to stop/start: %v", name, err))
		}
	}

	// Fallback: stop old → migrate → remove → create new → start (brief downtime)
	_, _ = docker.ContainerStop(ctx, containerID, client.ContainerStopOptions{Timeout: dockerAppsSeconds(10)})

	// Stopped, so the app has flushed; not yet removed, so the data is still
	// reachable. The only window in which it can be rescued, and a failure
	// here MUST abort before the remove below.
	migrated, err := DockerAppsMigrateUnmountedVolumes(ctx, DockerAppsAppDataDir, docker, containerID, appName, image, unmounted, hc)
	if err != nil {
		return DockerAppsUpdateResult{}, fmt.Errorf("Aborting update of %s without removing it: %v. The container is stopped and "+
			"intact; start it again with `docker start %s`.", name, err, name)
	}

	// Same window, the other direction: give back ownership of data an
	// EARLIER release migrated and left root-owned. Not fatal — an app that is
	// already broken must not have its update refused as well.
	repaired := dockerAppsRepairRootOwnedVolumes(ctx, docker, image, hc)

	if _, err := docker.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{Force: true}); err != nil {
		return DockerAppsUpdateResult{}, fmt.Errorf("Failed to remove old container: %v", err)
	}

	envList, netConfig := dockerAppsReattachSidecarIfAny(config.Labels, appName, slices.Clone(config.Env))
	created, err := docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:             name,
		Config:           dockerAppsRecreateConfig(config, config.Image, envList, config.Cmd, config.Entrypoint),
		HostConfig:       hc,
		NetworkingConfig: netConfig,
	})
	if err != nil {
		return DockerAppsUpdateResult{}, fmt.Errorf("Failed to create updated container: %v", err)
	}

	if wasRunning {
		if _, err := docker.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
			return DockerAppsUpdateResult{}, fmt.Errorf("Failed to start updated container: %v", err)
		}
	} else {
		slog.Info(name + " was stopped before the update; leaving it stopped.")
	}

	if len(migrated) == 0 {
		slog.Info(fmt.Sprintf("App updated (stop/start): %s (%s)", name, image))
	} else {
		slog.Info(fmt.Sprintf("App updated (stop/start): %s (%s) — and %d path(s) migrated onto persistent storage: %s",
			name, image, len(migrated), strings.Join(migrated, ", ")))
	}
	if len(repaired) > 0 {
		slog.Info(fmt.Sprintf("App %s: ownership repaired on %d path(s) left root-owned by an earlier release: %s",
			name, len(repaired), strings.Join(repaired, ", ")))
	}
	return DockerAppsUpdateResult{ContainerID: created.ID, BlueGreen: false, MigratedVolumes: migrated, RepairedVolumes: repaired}, nil
}

// DockerAppsChangeContainerImage changes a managed container's image,
// preserving its full runtime configuration.
//
// An earlier implementation recreated the container with a bare
// `docker run -d --name X --volumes-from Y --network bridge <image>`, which
// dropped EVERY hardening flag the original deploy applied — cap_drop ALL +
// the minimal cap_add allowlist, no-new-privileges, the published
// `127.0.0.1:<port>` binding (so the nginx reverse proxy 502'd), the restart
// policy, the limits, the env vars, and the `dockpanel.managed` labels (so the
// container vanished from the panel). This recreates it with the same host
// config, labels, env and exposed ports, only swapping the image.
//
// The new image's own entrypoint and working dir apply, because a tag bump
// may legitimately change them and the deploy never overrode either. **Its
// command is a different case.** For the templates the catalogue gives an
// explicit command, the deploy sets it precisely because the image's own
// default does not serve (#101) — so the command is re-derived from the
// template label: a template with no override still gets the new image's
// default and one with an override keeps working.
func DockerAppsChangeContainerImage(ctx context.Context, containerID, newImage string) (string, error) {
	docker, err := dockerAppsConnect()
	if err != nil {
		return "", err
	}
	defer docker.Close()

	// Inspect the existing container to capture its full config before
	// touching it.
	info, config, hc, name, err := dockerAppsInspectForRecreate(ctx, docker, containerID)
	if err != nil {
		return "", err
	}
	wasRunning := dockerAppsWasRunning(info)
	if name == "" {
		return "", errors.New("Container not found")
	}
	oldImage := config.Image
	appName := dockerAppsAppDataName(config.Labels, name)
	unmounted := dockerAppsUnmountedDeclaredVolumes(config, hc)
	// Read the override off the template label rather than carrying the old
	// container's resolved Cmd forward (it may be the OLD image's default).
	catalogueCmd := dockerAppsCatalogueCmdFor(config.Labels)

	// Pull the new image. The stream may emit non-fatal warnings, so verify
	// the image exists locally afterwards rather than trusting it.
	errs := DockerAppsPullImage(ctx, docker, newImage, DockerAppsRegistryCredentialsFor(newImage))
	if _, err := docker.ImageInspect(ctx, newImage); err != nil {
		last := "image not found after pull"
		if len(errs) > 0 {
			last = errs[len(errs)-1]
		}
		return "", fmt.Errorf("Failed to pull image '%s': %s", newImage, last)
	}

	// Stop + remove the old container, KEEPING its volumes so data persists.
	// ⚠ Preserving VOLUMES is not preserving DATA: a container with no mount
	// keeps its state in the writable layer, and `docker rm` deletes that
	// regardless (#110). Migrate first, in the window where the container is
	// stopped but still exists, and abort without removing if that fails.
	_, _ = docker.ContainerStop(ctx, containerID, client.ContainerStopOptions{Timeout: dockerAppsSeconds(10)})
	if _, err := DockerAppsMigrateUnmountedVolumes(ctx, DockerAppsAppDataDir, docker, containerID, appName, oldImage, unmounted, hc); err != nil {
		return "", fmt.Errorf("Aborting image change for %s without removing it: %v. The container is stopped and intact; "+
			"start it again with `docker start %s`.", name, err, name)
	}

	// Repair against the image the container is about to RUN, not the one it
	// is leaving — the uid that has to be able to write this data is the new one.
	_ = dockerAppsRepairRootOwnedVolumes(ctx, docker, newImage, hc)
	if _, err := docker.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{Force: true}); err != nil {
		return "", fmt.Errorf("Failed to remove old container: %v", err)
	}

	envList, netConfig := dockerAppsReattachSidecarIfAny(config.Labels, appName, slices.Clone(config.Env))

	// Recreate with the SAME hardening/networking/limits/labels/env, only the
	// image changes.
	created, err := docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image:        newImage,
			Env:          envList,
			ExposedPorts: config.ExposedPorts,
			Labels:       config.Labels,
			Cmd:          catalogueCmd,
		},
		HostConfig:       hc,
		NetworkingConfig: netConfig,
	})
	if err != nil {
		return "", fmt.Errorf("Failed to create container with new image: %v", err)
	}

	if wasRunning {
		if _, err := docker.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
			return "", fmt.Errorf("Failed to start container with new image: %v", err)
		}
	} else {
		slog.Info(name + " was stopped before the image change; leaving it stopped.")
	}

	slog.Info(fmt.Sprintf("Image changed for %s: → %s (new: %s)", name, newImage, created.ID))
	return created.ID, nil
}

// DockerAppsGetAppEnv returns a container's environment as (key, value) pairs.
func DockerAppsGetAppEnv(ctx context.Context, containerID string) ([][2]string, error) {
	docker, err := dockerAppsConnect()
	if err != nil {
		return nil, err
	}
	defer docker.Close()
	res, err := docker.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("Failed to inspect container: %v", err)
	}
	out := [][2]string{}
	if res.Container.Config != nil {
		for _, entry := range res.Container.Config.Env {
			if k, v, ok := strings.Cut(entry, "="); ok {
				out = append(out, [2]string{k, v})
			}
		}
	}
	return out, nil
}

// DockerAppsRemovalIdentity is what a removal needs to know about a container
// *before* it is removed, so the cleanup that follows can prove it owns each
// thing it deletes. Read in one inspect because afterwards there is nothing
// left to ask. A missing field means "cannot prove it" — callers refuse.
type DockerAppsRemovalIdentity struct {
	// dockpanel.app.domain — the vhost, cert dir and logs are named after it.
	Domain *string
	// dockpanel.app.name — /var/lib/dockpanel/apps/{name} is named after it.
	Name *string
	// The published host port. The app's vhost proxy_passes to it, and it is
	// the only thing in that file identifying which container it fronts.
	HostPort *uint16
	// Whether this container actually bind-mounts out of the app directory.
	// A template deploy does; a compose service does not — its binds are
	// confined to /var/lib/dockpanel/compose/, so an identically-named compose
	// service was deleting a template app's data directory while owning
	// nothing under it.
	OwnsAppDir bool
	// The directory the container's own binds prove it owns. Read from the
	// binds rather than rebuilt from the name label, because releases v2.111.0
	// through v2.113.3 migrated data into a directory named for the CONTAINER.
	// A bind outside DockerAppsAppDataDir yields nil and nothing is removed.
	AppDir *string
}

// dockerAppsOwnedAppDir: which directory under DockerAppsAppDataDir do this
// container's own binds prove it owns?
//
// Two spellings are accepted, and only two: the one the deploy writes, and the
// one the migration wrote on v2.111.0–v2.113.3 (the container name). Anything
// else is refused, which keeps a compose service from deleting a template
// app's tree. The `{prefix}/` boundary is checked explicitly so a directory
// called `data` cannot answer for one called `database`.
func dockerAppsOwnedAppDir(name string, binds []string) *string {
	candidates := []string{
		DockerAppsAppDataDir + "/" + name,
		DockerAppsAppDataDir + "/" + DockerAppsContainerNamePrefix + name,
	}
	for _, bind := range binds {
		source, _, _ := strings.Cut(bind, ":")
		for _, dir := range candidates {
			if source == dir || strings.HasPrefix(source, dir+"/") {
				d := dir
				return &d
			}
		}
	}
	return nil
}

// DockerAppsGetRemovalIdentity gathers DockerAppsRemovalIdentity for
// containerID (Rust: removal_identity). Never fails: an unreachable Docker
// yields all-nil, which refuses every subsequent delete.
func DockerAppsGetRemovalIdentity(ctx context.Context, containerID string) DockerAppsRemovalIdentity {
	var id DockerAppsRemovalIdentity
	docker, err := dockerAppsConnect()
	if err != nil {
		return id
	}
	defer docker.Close()
	res, err := docker.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return id
	}
	info := res.Container
	if info.Config != nil && info.Config.Labels != nil {
		if v, ok := info.Config.Labels["dockpanel.app.domain"]; ok {
			id.Domain = &v
		}
		if v, ok := info.Config.Labels["dockpanel.app.name"]; ok {
			id.Name = &v
		}
	}
	if hc := info.HostConfig; hc != nil {
		id.HostPort = DockerAppsExtractHostPort(hc)
		// Ownership of the data directory is decided by the container's own
		// mounts, not by its name label.
		if id.Name != nil && hc.Binds != nil {
			id.AppDir = dockerAppsOwnedAppDir(*id.Name, hc.Binds)
			id.OwnsAppDir = id.AppDir != nil
		}
	}
	return id
}

// dockerAppsIsManagedLabels: true iff the labels mark the container
// dockpanel-managed. This is the boundary between panel-managed app containers
// and the panel's OWN infra (its postgres/api/agent containers carry no such
// label).
func dockerAppsIsManagedLabels(labels map[string]string) bool {
	return labels["dockpanel.managed"] == "true"
}

// DockerAppsRequireManaged guards an action-handler target: inspect the
// container and reject unless it is dockpanel-managed. Gives WRITE scope the
// same boundary the list READ path enforces, so an admin cannot act on the
// panel's own infrastructure containers by id (confused-deputy footgun). For
// the recreate paths this runs on the ORIGINAL container before any
// stop/remove, and the recreation preserves the label.
func DockerAppsRequireManaged(ctx context.Context, containerID string) error {
	docker, err := dockerAppsConnect()
	if err != nil {
		return err
	}
	defer docker.Close()
	res, err := docker.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return fmt.Errorf("Failed to inspect container: %v", err)
	}
	var labels map[string]string
	if res.Container.Config != nil {
		labels = res.Container.Config.Labels
	}
	if !dockerAppsIsManagedLabels(labels) {
		return errors.New("not a dockpanel-managed container")
	}
	return nil
}

// DockerAppsUpdateEnv updates a container's environment variables by
// recreating it with the new env.
func DockerAppsUpdateEnv(ctx context.Context, containerID string, newEnv map[string]string) (string, error) {
	docker, err := dockerAppsConnect()
	if err != nil {
		return "", err
	}
	defer docker.Close()

	info, config, hc, name, err := dockerAppsInspectForRecreate(ctx, docker, containerID)
	if err != nil {
		return "", err
	}
	wasRunning := dockerAppsWasRunning(info)
	image := config.Image
	appName := dockerAppsAppDataName(config.Labels, name)
	unmounted := dockerAppsUnmountedDeclaredVolumes(config, hc)

	// Build the new env list, carrying over anything sent back masked.
	envList, kept := DockerAppsMergeEnvPreservingMasked(newEnv, config.Env)
	if len(kept) > 0 {
		slog.Info(fmt.Sprintf("update_env for %s: %d masked value(s) carried over unchanged (%s)", containerID, len(kept), strings.Join(kept, ", ")))
	}

	// Stop, migrate anything living in the writable layer, then remove.
	// Editing one environment variable recreates the container, so this door
	// destroys an unmounted app's data exactly as thoroughly as Update does
	// (#110) — it just does not sound like it.
	_, _ = docker.ContainerStop(ctx, containerID, client.ContainerStopOptions{Timeout: dockerAppsSeconds(10)})
	if _, err := DockerAppsMigrateUnmountedVolumes(ctx, DockerAppsAppDataDir, docker, containerID, appName, image, unmounted, hc); err != nil {
		return "", fmt.Errorf("Aborting environment update for %s without removing it: %v. The container is stopped and intact; "+
			"start it again with `docker start %s`.", name, err, name)
	}
	_ = dockerAppsRepairRootOwnedVolumes(ctx, docker, image, hc)
	if _, err := docker.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{Force: true}); err != nil {
		return "", fmt.Errorf("Failed to remove old container: %v", err)
	}

	envList, netConfig := dockerAppsReattachSidecarIfAny(config.Labels, appName, envList)

	// Recreate with new env
	created, err := docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:             name,
		Config:           dockerAppsRecreateConfig(config, config.Image, envList, config.Cmd, config.Entrypoint),
		HostConfig:       hc,
		NetworkingConfig: netConfig,
	})
	if err != nil {
		return "", fmt.Errorf("Failed to create container: %v", err)
	}

	if wasRunning {
		if _, err := docker.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
			return "", fmt.Errorf("Failed to start container: %v", err)
		}
	} else {
		slog.Info(name + " was stopped before the env change; leaving it stopped.")
	}

	slog.Info(fmt.Sprintf("Container env updated: %s (%d vars)", name, len(newEnv)))
	return created.ID, nil
}

// DockerAppsRemoveApp stops and removes an app container (and its anonymous
// volumes, and its sidecar if any).
func DockerAppsRemoveApp(ctx context.Context, containerID string) error {
	docker, err := dockerAppsConnect()
	if err != nil {
		return err
	}
	defer docker.Close()

	// Read before removal — there is nothing left to ask afterwards, and this
	// is how the app's sidecar (if any) gets found and torn down alongside it.
	appName, hasName := dockerAppsCurrentAppName(ctx, docker, containerID)

	// Stop first (ignore error if already stopped)
	_, _ = docker.ContainerStop(ctx, containerID, client.ContainerStopOptions{Timeout: dockerAppsSeconds(10)})
	if _, err := docker.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{RemoveVolumes: true, Force: true}); err != nil {
		return fmt.Errorf("Failed to remove container: %v", err)
	}
	if hasName {
		AppSidecarTeardown(ctx, appName)
	}
	slog.Info("App container removed: " + containerID)
	return nil
}

// ── TLS intent (Rust: routes::docker_apps::TlsIntent) ──────────────
//
// Lives in services, not routes, because the git-build service resolves the
// same intent and services cannot import routes.

// DockerAppsTlsKind is which of the three TLS shapes an intent is.
type DockerAppsTlsKind int

const (
	// Plain HTTP, or TLS terminated upstream. The reporter's interim on #104.
	DockerAppsTlsNone DockerAppsTlsKind = iota
	// Order a Let's Encrypt certificate under Email.
	DockerAppsTlsAcme
	// Serve a certificate the operator registered under Alias.
	DockerAppsTlsProvided
)

// DockerAppsTlsIntent is how a domain claimed by a deploy is to be secured —
// the request's TLS fields resolved into one decision before anything runs.
//
// Until v2.160.0 the only signal was whether ssl_email was present, and a
// redeploy that omitted it silently rewrote the vhost without its :443 block.
// The mode is now STORED by the panel and sent on every deploy, so an absent
// address stops being the only signal. A nil mode keeps the old rule
// byte-for-byte, which is what an older panel still sends.
type DockerAppsTlsIntent struct {
	Kind  DockerAppsTlsKind
	Email string
	Alias string
}

// DockerAppsTlsIntentFromRequest resolves the wire fields. The error is the
// sentence a handler answers 400 with, and it is asked BEFORE any container
// runs.
//
// useTraefik refuses `provided` HERE, before any container runs — the same
// front-door discipline applied to a bad alias or a missing ssl_email.
// Traefik's file provider has no per-route certificate form, so a registered
// certificate can never be served through it regardless of which door the
// request came in by.
func DockerAppsTlsIntentFromRequest(tlsMode, sslEmail, alias *string, useTraefik bool) (DockerAppsTlsIntent, error) {
	if tlsMode == nil {
		// Legacy inference — an older panel that knows no mode. Presence and
		// not content, so nothing an old panel sends changes meaning.
		if sslEmail != nil {
			return DockerAppsTlsIntent{Kind: DockerAppsTlsAcme, Email: *sslEmail}, nil
		}
		return DockerAppsTlsIntent{Kind: DockerAppsTlsNone}, nil
	}
	switch *tlsMode {
	case "none":
		return DockerAppsTlsIntent{Kind: DockerAppsTlsNone}, nil
	case "acme":
		if sslEmail != nil && strings.TrimSpace(*sslEmail) != "" {
			return DockerAppsTlsIntent{Kind: DockerAppsTlsAcme, Email: *sslEmail}, nil
		}
		return DockerAppsTlsIntent{}, errors.New("tls_mode acme needs an ssl_email — the address the Let's Encrypt account is registered under")
	case "provided":
		switch {
		case alias == nil:
			return DockerAppsTlsIntent{}, errors.New("tls_mode provided needs tls_certificate — the alias of a registered certificate")
		case useTraefik:
			return DockerAppsTlsIntent{}, fmt.Errorf("tls_mode provided cannot be served through Traefik: its file provider has no "+
				"per-route certificate form for '%s'. Switch the reverse proxy to nginx, or use tls_mode acme or none.", *alias)
		case SslIsValidCertAlias(*alias):
			return DockerAppsTlsIntent{Kind: DockerAppsTlsProvided, Alias: *alias}, nil
		default:
			return DockerAppsTlsIntent{}, fmt.Errorf("'%s' is not a certificate alias — 1 to 64 lowercase letters, digits or "+
				"hyphens, starting and ending with a letter or digit", *alias)
		}
	default:
		return DockerAppsTlsIntent{}, fmt.Errorf("unknown tls_mode '%s': expected none, acme or provided", *tlsMode)
	}
}

// Mode is the vocabulary word this intent answers as.
func (t DockerAppsTlsIntent) Mode() string {
	switch t.Kind {
	case DockerAppsTlsAcme:
		return "acme"
	case DockerAppsTlsProvided:
		return "provided"
	}
	return "none"
}
