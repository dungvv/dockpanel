# Traefik-First Installation Design

## Scope

New installations use Traefik as the public ingress on ports 80 and 443. Existing installations remain Nginx-public forever for this change: the update path detects the installation mode marker and does not rebind ports, rewrite vhosts, or install Traefik as a replacement.

Nginx remains installed on new machines as an internal host web server for static and PHP sites, including existing WAF, FastCGI cache, PHP-FPM, and site lifecycle behavior. Traefik terminates public HTTP/TLS and forwards host-backed traffic to Nginx on a private host port. Docker workloads are routed directly by Traefik through a shared Docker network.

This design does not introduce Docker Swarm/Kubernetes scheduling. A resource still belongs to one DockPanel `server_id` and runs on that server's Docker Engine.

## Installation Modes

`setup.sh` writes an immutable installation mode marker under `/etc/dockpanel/` only after the selected public proxy is healthy:

- `traefik` for a new Traefik-public installation.
- `nginx` for an existing/legacy Nginx-public installation, created by the compatibility path when no marker exists.

The default for a fresh installation is `traefik`. The update script reads the marker before touching proxy services. A legacy installation without a marker is treated as Nginx-public and receives the marker only after a safe, non-disruptive update step; it is never inferred to be Traefik from service presence.

The installer refuses a Traefik-first install when ports 80 or 443 are occupied by an unrelated process. It must not stop or overwrite an existing Nginx service during a fresh install.

## Runtime Topology

```text
Internet :80/:443
        |
        v
Traefik container (public entrypoints, ACME, Docker + file providers)
        |                         |
        | private host port       | dockpanel-proxy network
        v                         v
host Nginx :18080             Docker app containers
(static/PHP/WAF/cache)        (labels or generated file routes)
        |
        +-- PHP-FPM / site files
```

Traefik's container-to-host route must not use `127.0.0.1`, because that is the Traefik container itself. The installer creates a stable private Nginx listener and configures an explicit host-gateway address available from the Traefik container. The host port is not opened in the firewall and Nginx rejects public binding on that listener.

The panel's public routes are generated as Traefik file-provider routes to the existing local API/frontend services. Agent Unix-socket proxying remains an internal panel concern; Traefik forwards the panel's HTTP/WebSocket endpoint to the existing Nginx panel backend, preserving the current browser contract.

## Traefik Configuration

Traefik runs with:

- Docker provider, `exposedByDefault=false`, restricted to `dockpanel-proxy`.
- File provider watching the parent dynamic directory, mounted as a directory rather than a single file.
- `web` and `websecure` entrypoints on container ports 80 and 443, published to host ports 80 and 443.
- ACME HTTP-01 using `web`, with `acme.json` mode 0600 and persistent storage.
- Dashboard disabled from the public entrypoints; local administration uses an authenticated internal path or the existing agent status endpoint.
- No host Docker socket write access; the socket remains read-only.

Generated file routes use atomic replacement within the watched directory and validate domain ownership before deletion. Dynamic route service URLs for host-backed targets use the Traefik-reachable host gateway, never loopback.

Docker app routes use the shared `dockpanel-proxy` network. Container deployments attach routed workloads to that network and publish the selected internal container port through Traefik's Docker provider. Services not explicitly marked for exposure remain invisible.

## Site and Deployment Behavior

- Static/PHP sites continue to be rendered and managed by the existing Nginx service, but their public vhost is represented by one Traefik route to the internal Nginx listener.
- Node/Python/proxy workloads may either use the existing Nginx backend contract or be routed directly to a Docker/network endpoint; the first implementation preserves the existing site lifecycle and uses Nginx for host-managed sites.
- Docker template apps use Traefik routes when the installation mode is `traefik`.
- Compose services receive the shared proxy network and validated Traefik labels when a domain is configured. Unlabelled services are not exposed.
- Git deploys use Traefik dynamic routes in Traefik mode. Blue-green promotion rewrites the generated route's backend target and waits for the file provider to report a healthy route before retiring the old container. The Nginx-specific swap path remains the compatibility path for Nginx-mode installations.
- Registered certificates are represented in Traefik's dynamic TLS certificate configuration. Existing Nginx certificate files are not migrated automatically during this first-install-only change.

## Compatibility and Update Safety

Every proxy-mutating operation branches on the installation marker. Legacy Nginx mode preserves current Nginx rendering, reload, certificate, WAF, cache, and blue-green behavior. `update.sh` never changes a legacy machine's public listeners.

The new installer creates and validates all Traefik routes before declaring installation successful. On failure before marker creation it removes only resources created by the failed install and leaves an unrelated existing service untouched. The installer records a failure stage for diagnostics.

Backups include the Traefik static configuration, dynamic route directory, ACME storage metadata (not secrets in logs), installation marker, and the internal Nginx configuration needed to restore a new installation. Existing Nginx backup/restore behavior is unchanged.

## Security

- Ports 80/443 are the only public proxy ports.
- The internal Nginx port binds only to the host gateway/private interface and is firewall-blocked from external access.
- ACME and private keys remain mode 0600.
- Domain, port, router-name, and label inputs are validated before entering YAML or Docker configuration.
- Traefik dashboard is not exposed unauthenticated.
- Remote server routing remains scoped by `server_id`; this change does not create cross-server routing or scheduling.

## Verification

The implementation must leave focused checks for:

1. Fresh-install mode writes `traefik` only after successful health validation.
2. Legacy/no-marker mode remains Nginx-public and update code does not bind Traefik to 80/443.
3. Traefik host-backed routes never contain `127.0.0.1` as a container-side upstream.
4. Dynamic route names and YAML reject invalid domains/ports and remain collision-safe.
5. Compose services expose only explicit Traefik routes and attach to the proxy network.
6. Blue-green route replacement preserves the old backend when validation fails.
7. ACME storage and dashboard exposure satisfy the security contract.
8. Existing Nginx source/pin tests continue to pass.
