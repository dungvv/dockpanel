package services

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

const (
	traefikContainer = "dockpanel-traefik"
	traefikImage     = "traefik:v3.3"
	traefikNetwork   = "dockpanel-proxy"
	traefikConfigDir = "/etc/dockpanel/traefik"
)

// TraefikStatus is the wire shape of /traefik/status and /traefik/install.
type TraefikStatus struct {
	Installed    bool   `json:"installed"`
	Running      bool   `json:"running"`
	Version      string `json:"version"`
	DashboardURL string `json:"dashboard_url"`
}

func traefikRunningStatus() TraefikStatus {
	return TraefikStatus{Installed: true, Running: true, Version: traefikImage, DashboardURL: "http://127.0.0.1:8080"}
}

// TraefikEnsureNetwork creates the dockpanel-proxy bridge network if missing.
func TraefikEnsureNetwork(ctx context.Context, docker *client.Client) error {
	if _, err := docker.NetworkInspect(ctx, traefikNetwork, client.NetworkInspectOptions{}); err == nil {
		return nil
	}
	if _, err := docker.NetworkCreate(ctx, traefikNetwork, client.NetworkCreateOptions{Driver: "bridge"}); err != nil {
		return fmt.Errorf("Failed to create network: %v", err)
	}
	slog.Info("Created Docker network: " + traefikNetwork)
	return nil
}

// TraefikInstall installs and starts Traefik as a Docker container.
func TraefikInstall(ctx context.Context, docker *client.Client, acmeEmail string) (TraefikStatus, error) {
	if err := TraefikEnsureNetwork(ctx, docker); err != nil {
		return TraefikStatus{}, err
	}
	_ = os.MkdirAll(traefikConfigDir, 0o755)
	_ = os.MkdirAll(traefikConfigDir+"/dynamic", 0o755)
	// Restrictive permissions for the ACME storage directory.
	_ = os.Chmod(traefikConfigDir, 0o700)

	if info, err := docker.ContainerInspect(ctx, traefikContainer, client.ContainerInspectOptions{}); err == nil {
		if st := info.Container.State; st != nil && st.Running {
			return traefikRunningStatus(), nil
		}
		// Exists but not running — start it.
		if _, err := docker.ContainerStart(ctx, traefikContainer, client.ContainerStartOptions{}); err != nil {
			return TraefikStatus{}, fmt.Errorf("Failed to start Traefik: %v", err)
		}
		return traefikRunningStatus(), nil
	}

	pull, err := docker.ImagePull(ctx, traefikImage, client.ImagePullOptions{})
	if err == nil {
		err = pull.Wait(ctx)
	}
	if err != nil {
		return TraefikStatus{}, fmt.Errorf("Failed to pull Traefik image: %v", err)
	}

	// NOTE: --api.insecure=true exposes the dashboard on 8080 without auth;
	// safe only because it is bound to 127.0.0.1.
	cmd := []string{
		"--providers.docker=true",
		"--providers.docker.exposedByDefault=false",
		"--providers.docker.network=" + traefikNetwork,
		// File provider for dynamic route configs (apps deployed with Traefik).
		"--providers.file.directory=/etc/traefik/dynamic",
		"--providers.file.watch=true",
		"--entrypoints.web.address=:80",
		"--entrypoints.websecure.address=:443",
		"--certificatesresolvers.letsencrypt.acme.email=" + acmeEmail,
		"--certificatesresolvers.letsencrypt.acme.storage=/etc/traefik/acme.json",
		"--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web",
		"--api.dashboard=true",
		"--api.insecure=true",
		"--log.level=INFO",
	}
	// Traefik listens on 8880/8443 internally; nginx stays the front door on 80/443.
	loop := netip.MustParseAddr("127.0.0.1")
	bind := func(host string) []network.PortBinding {
		return []network.PortBinding{{HostIP: loop, HostPort: host}}
	}
	ports := network.PortMap{
		network.MustParsePort("80/tcp"):   bind("8880"),
		network.MustParsePort("443/tcp"):  bind("8443"),
		network.MustParsePort("8080/tcp"): bind("8080"),
	}
	_, err = docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: traefikContainer,
		Config: &container.Config{
			Image:  traefikImage,
			Cmd:    cmd,
			Labels: map[string]string{"dockpanel.managed": "true", "dockpanel.type": "traefik"},
		},
		HostConfig: &container.HostConfig{
			PortBindings: ports,
			Binds: []string{
				"/var/run/docker.sock:/var/run/docker.sock:ro",
				traefikConfigDir + ":/etc/traefik",
			},
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		},
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{traefikNetwork: {}},
		},
	})
	if err != nil {
		return TraefikStatus{}, fmt.Errorf("Failed to create Traefik container: %v", err)
	}
	if _, err := docker.ContainerStart(ctx, traefikContainer, client.ContainerStartOptions{}); err != nil {
		return TraefikStatus{}, fmt.Errorf("Failed to start Traefik: %v", err)
	}
	slog.Info("Traefik installed and running on 127.0.0.1:8880 (HTTP), 127.0.0.1:8443 (HTTPS), 127.0.0.1:8080 (dashboard)")
	return traefikRunningStatus(), nil
}

// TraefikUninstall removes the container, network and dynamic routes.
func TraefikUninstall(ctx context.Context, docker *client.Client) error {
	_, _ = docker.ContainerStop(ctx, traefikContainer, client.ContainerStopOptions{})
	_, _ = docker.ContainerRemove(ctx, traefikContainer, client.ContainerRemoveOptions{})
	// Ignore errors if containers are still connected.
	_, _ = docker.NetworkRemove(ctx, traefikNetwork, client.NetworkRemoveOptions{})
	_ = os.RemoveAll(traefikConfigDir + "/dynamic")
	slog.Info("Traefik uninstalled")
	return nil
}

// TraefikGetStatus reports whether Traefik is installed and running.
func TraefikGetStatus(ctx context.Context, docker *client.Client) TraefikStatus {
	info, err := docker.ContainerInspect(ctx, traefikContainer, client.ContainerInspectOptions{})
	if err != nil {
		return TraefikStatus{}
	}
	running := info.Container.State != nil && info.Container.State.Running
	s := TraefikStatus{Installed: true, Running: running, Version: traefikImage}
	if running {
		s.DashboardURL = "http://127.0.0.1:8080"
	}
	return s
}

// TraefikWriteRouteConfig writes a dynamic route file for an app; Traefik's
// file provider reloads it by itself.
func TraefikWriteRouteConfig(domain string, backendPort uint16, ssl bool) error {
	safe := TraefikRouteKey(domain)
	dir := traefikConfigDir + "/dynamic"
	_ = os.MkdirAll(dir, 0o755)
	var cfg string
	if ssl {
		cfg = fmt.Sprintf(`http:
  routers:
    %[1]s:
      rule: "Host(`+"`%[2]s`"+`)"
      entryPoints:
        - web
      middlewares:
        - "%[1]s-redirect"
      service: "%[1]s"
    %[1]s-secure:
      rule: "Host(`+"`%[2]s`"+`)"
      entryPoints:
        - websecure
      service: "%[1]s"
      tls:
        certResolver: "letsencrypt"
  middlewares:
    %[1]s-redirect:
      redirectScheme:
        scheme: "https"
  services:
    %[1]s:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:%[3]d"
`, safe, domain, backendPort)
	} else {
		cfg = fmt.Sprintf(`http:
  routers:
    %[1]s:
      rule: "Host(`+"`%[2]s`"+`)"
      entryPoints:
        - web
      service: "%[1]s"
  services:
    %[1]s:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:%[3]d"
`, safe, domain, backendPort)
	}
	if err := os.WriteFile(fmt.Sprintf("%s/%s.yml", dir, safe), []byte(cfg), 0o644); err != nil {
		return fmt.Errorf("Failed to write Traefik route config: %v", err)
	}
	slog.Info(fmt.Sprintf("Traefik route config written: %s → 127.0.0.1:%d (ssl=%t)", domain, backendPort, ssl))
	return nil
}

// TraefikRemoveRouteConfig removes the route file for domain, and the
// pre-v2.52.0 legacy-named file only when that file routes THIS domain: the
// legacy name of a-b.com is the live name of a.b.com (route_key doubles '-'),
// so deleting by name would take a different app down — on fresh installs too.
func TraefikRemoveRouteConfig(domain string) {
	path := traefikRouteConfigPath(domain)
	if nginxExists(path) {
		_ = os.Remove(path)
		slog.Info("Traefik route config removed: " + domain)
	}
	legacy := traefikLegacyRouteConfigPath(domain)
	if legacy != path && nginxExists(legacy) {
		if OwnershipTraefikRoute(legacy, domain).MayDelete() {
			_ = os.Remove(legacy)
			slog.Info("Traefik route config removed (legacy name): " + domain)
		} else {
			slog.Warn(fmt.Sprintf("Leaving %s in place: it does not route %s. Under the pre-v2.52.0 naming that "+
				"file is also the current name of another domain's route, and removing it would take that domain down.", legacy, domain))
		}
	}
}

// TraefikRouteKey is the router name / filename for domain. Mangling '.' to
// '-' alone is not injective (a.b.com vs a-b.com shared one file); escaping a
// literal '-' first makes it so.
func TraefikRouteKey(domain string) string {
	var b strings.Builder
	for _, c := range domain {
		switch c {
		case '-':
			b.WriteString("--")
		case '_':
			b.WriteString("__")
		case '.':
			b.WriteByte('-')
		case ':':
			b.WriteByte('_')
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

func traefikRouteConfigPath(domain string) string {
	return fmt.Sprintf("%s/dynamic/%s.yml", traefikConfigDir, TraefikRouteKey(domain))
}

// traefikLegacyRouteConfigPath is the pre-fix ambiguous path, read only for cleanup.
func traefikLegacyRouteConfigPath(domain string) string {
	safe := strings.ReplaceAll(strings.ReplaceAll(domain, ".", "-"), ":", "-")
	return fmt.Sprintf("%s/dynamic/%s.yml", traefikConfigDir, safe)
}

// TraefikRouteIsTls reports whether domain's Traefik route terminates TLS;
// ok=false when Traefik is not the proxy for it, so the caller asks nginx.
func TraefikRouteIsTls(domain string) (tls bool, ok bool) {
	b, err := os.ReadFile(traefikRouteConfigPath(domain))
	if err != nil {
		return false, false
	}
	return strings.Contains(string(b), "tls:"), true
}
