// Paired-sidecar deployments.
//
// A one-click template can need a companion container it must never talk to
// the outside world through directly — the motivating case is Dozzle (#125):
// it needs live Docker API access, and the deploy deliberately never mounts
// the host socket into ANY one-click app, because that is a full host-escape
// vector regardless of who was allowed to trigger the deploy. The fix is not
// to loosen that policy — it is to give the app a sidecar that holds the real
// socket and exposes only a filtered slice of its API over a network nothing
// else can reach: the industry-standard docker-socket-proxy pattern, which
// Dozzle's own docs recommend for exactly this situation.
//
// Shape: a dedicated bridge network per app, mirroring compose.go's per-stack
// network at app scope. The sidecar joins it under a fixed alias and
// publishes no host port; the main container joins the SAME network in place
// of the default bridge, so its existing host-port publish keeps working
// unchanged, and reaches the sidecar at `tcp://<alias>:<port>`. The sidecar is
// labelled `dockpanel.sidecar_of=<app>`, never `dockpanel.app.template`, so
// DockerAppsListDeployedApps's existing filter excludes it — the operator
// manages exactly one thing.

package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// AppSidecarSidecarDef is what a template's sidecar is and how the main
// container finds it.
type AppSidecarSidecarDef struct {
	Image string
	// Network alias the main container reaches this sidecar by, on the private
	// per-app network — safe to keep short and generic (e.g. "dockerproxy")
	// because the network holds only this one app-pair.
	Alias string
	// TCP port the sidecar listens on inside that network.
	Port uint16
	// Env vars the sidecar itself needs, written explicitly and
	// deny-by-default rather than left to the image's own defaults — see
	// dockerAppsDozzleProxyEnv for why every toggle is spelled out.
	ProxyEnv [][2]string
	// Env var the panel injects into the MAIN container so it finds this
	// sidecar. Never exposed as a user-editable field — pointing it anywhere
	// else defeats the sandboxing this whole module exists for.
	ClientEnvVar string
}

// ClientEnvEntry is the `KEY=value` entry the main container's env gets, on
// every deploy AND every recreate — reasserted, not merely defaulted, so an
// operator editing the app's env cannot silently disconnect it by touching a
// row that looks like ordinary configuration but is actually wiring.
func (s *AppSidecarSidecarDef) ClientEnvEntry() string {
	return fmt.Sprintf("%s=tcp://%s:%d", s.ClientEnvVar, s.Alias, s.Port)
}

// AppSidecarNetworkName is the private bridge network an app's sidecar (if
// any) lives on. A prefix distinct from DockerAppsContainerNamePrefix, so it
// can never collide with an app's own container name.
func AppSidecarNetworkName(appName string) string {
	return "dockpanel-appnet-" + appName
}

// appSidecarContainerName is the sidecar's own container name — a namespace
// disjoint from `dockpanel-app-*`, so no app name can ever collide with it.
func appSidecarContainerName(appName string) string {
	return "dockpanel-sidecar-" + appName
}

// AppSidecarDeploy creates the app's private network if it does not already
// exist, deploys the sidecar onto it, and returns the network name for the
// caller to attach its own container to.
//
// If the sidecar container is created but fails to start, it is removed here
// (mirrors the deploy's own orphan cleanup). A network created just before
// that failure is left in place — harmless, and reused on a retry.
func AppSidecarDeploy(ctx context.Context, docker *client.Client, appName string, sidecar *AppSidecarSidecarDef) (string, error) {
	netName := AppSidecarNetworkName(appName)

	if _, err := docker.NetworkInspect(ctx, netName, client.NetworkInspectOptions{}); err != nil {
		if _, err := docker.NetworkCreate(ctx, netName, client.NetworkCreateOptions{
			Driver: "bridge",
			Labels: map[string]string{"dockpanel.managed": "true"},
		}); err != nil {
			return "", fmt.Errorf("Failed to create app network %s: %v", netName, err)
		}
	}

	pctx, cancel := context.WithTimeout(ctx, 300*time.Second)
	for _, e := range DockerAppsPullImage(pctx, docker, sidecar.Image, nil) {
		slog.Warn("Sidecar image pull warning: " + e)
	}
	timedOut := errors.Is(pctx.Err(), context.DeadlineExceeded)
	cancel()
	if timedOut {
		return "", fmt.Errorf("Sidecar image pull timed out for %s", sidecar.Image)
	}

	env := make([]string, 0, len(sidecar.ProxyEnv))
	for _, kv := range sidecar.ProxyEnv {
		env = append(env, kv[0]+"="+kv[1])
	}

	created, err := docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: appSidecarContainerName(appName),
		Config: &container.Config{
			Image: sidecar.Image,
			Env:   env,
			Labels: map[string]string{
				"dockpanel.managed":    "true",
				"dockpanel.sidecar_of": appName,
			},
		},
		HostConfig: &container.HostConfig{
			Binds:         []string{"/var/run/docker.sock:/var/run/docker.sock:ro"},
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
			SecurityOpt:   []string{"no-new-privileges:true"},
			// No cap_add: this container touches no bind-mounted app data of
			// its own, so none of the CHOWN/SETUID/DAC_OVERRIDE grants the main
			// container's hardening needs apply — it only opens a unix socket
			// and serves HTTP over the private network above.
			CapDrop: []string{"ALL"},
		},
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				netName: {Aliases: []string{sidecar.Alias}},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("Failed to create sidecar container: %v", err)
	}

	if _, err := docker.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		_, _ = docker.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{RemoveVolumes: true, Force: true})
		return "", fmt.Errorf("Failed to start sidecar container: %v", err)
	}
	return netName, nil
}

// AppSidecarAttachConfig is the networking config that attaches a container
// to appName's sidecar network under its own alias. Used by the initial
// deploy and by every recreate path, so an image/env update can never
// silently drop the app back onto the default bridge.
func AppSidecarAttachConfig(appName string) *network.NetworkingConfig {
	return &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			AppSidecarNetworkName(appName): {Aliases: []string{appName}},
		},
	}
}

// AppSidecarFind returns the app's sidecar container id, if its template has
// one and it still exists.
func AppSidecarFind(ctx context.Context, docker *client.Client, appName string) (string, bool) {
	res, err := docker.ContainerInspect(ctx, appSidecarContainerName(appName), client.ContainerInspectOptions{})
	if err != nil || res.Container.ID == "" {
		return "", false
	}
	return res.Container.ID, true
}

// AppSidecarTeardown stops and removes an app's sidecar and its private
// network. Best-effort by design, mirroring ComposeRemoveStackNetwork: a
// network Docker still sees endpoints on refuses removal (the correct answer
// when something unexpected is still attached), and an app whose template has
// no sidecar simply has nothing here to remove.
func AppSidecarTeardown(ctx context.Context, appName string) {
	docker, err := client.New(client.FromEnv)
	if err != nil {
		return
	}
	defer docker.Close()

	name := appSidecarContainerName(appName)
	if _, err := docker.ContainerInspect(ctx, name, client.ContainerInspectOptions{}); err == nil {
		_, _ = docker.ContainerStop(ctx, name, client.ContainerStopOptions{Timeout: dockerAppsSeconds(10)})
		if _, err := docker.ContainerRemove(ctx, name, client.ContainerRemoveOptions{RemoveVolumes: true, Force: true}); err != nil {
			slog.Warn(fmt.Sprintf("Could not remove sidecar container %s: %v", name, err))
		}
	}

	netName := AppSidecarNetworkName(appName)
	info, err := docker.NetworkInspect(ctx, netName, client.NetworkInspectOptions{})
	if err != nil {
		return
	}
	if info.Network.Labels["dockpanel.managed"] != "true" {
		slog.Warn(fmt.Sprintf("Not removing network %s: no dockpanel.managed label", netName))
		return
	}
	if _, err := docker.NetworkRemove(ctx, netName, client.NetworkRemoveOptions{}); err != nil {
		slog.Warn(fmt.Sprintf("Could not remove app network %s: %v", netName, err))
	}
}

// AppSidecarMirrorStop mirrors a stop onto this app's sidecar, if it has one.
// Best-effort: the operator asked to stop their app — a sidecar that fails to
// stop is logged, never surfaced as the action's own error.
func AppSidecarMirrorStop(ctx context.Context, docker *client.Client, appName string) {
	if id, ok := AppSidecarFind(ctx, docker, appName); ok {
		if _, err := docker.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: dockerAppsSeconds(10)}); err != nil {
			slog.Warn(fmt.Sprintf("Could not stop sidecar for app %s: %v", appName, err))
		}
	}
}

// AppSidecarMirrorStart mirrors a start onto this app's sidecar, if it has one
// — run BEFORE the main container starts, so the sidecar is already reachable
// instead of making the app's first connection attempt race a cold start.
func AppSidecarMirrorStart(ctx context.Context, docker *client.Client, appName string) {
	if id, ok := AppSidecarFind(ctx, docker, appName); ok {
		if _, err := docker.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
			slog.Warn(fmt.Sprintf("Could not start sidecar for app %s: %v", appName, err))
		}
	}
}

// AppSidecarMirrorRestart mirrors a restart onto this app's sidecar, if it has
// one.
func AppSidecarMirrorRestart(ctx context.Context, docker *client.Client, appName string) {
	if id, ok := AppSidecarFind(ctx, docker, appName); ok {
		if _, err := docker.ContainerRestart(ctx, id, client.ContainerRestartOptions{Timeout: dockerAppsSeconds(10)}); err != nil {
			slog.Warn(fmt.Sprintf("Could not restart sidecar for app %s: %v", appName, err))
		}
	}
}
