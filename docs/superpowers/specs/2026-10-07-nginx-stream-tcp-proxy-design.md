# Nginx Stream TCP Proxy Design

## Scope

Nginx remains the single public ingress on every DockPanel installation — HTTP and HTTPS traffic continue to terminate on the existing Nginx listeners exactly as they do today. No Traefik installation, no installation-mode marker, and no listener migration are introduced; the optional Traefik agent service stays an explicit, operator-chosen feature and is untouched by this change.

This change adds a new capability: TCP proxying through the Nginx `stream` module (`ngx_stream`). Two consumers use it:

- **Database remote access** — an operator can expose a panel-managed database container (site-owned or stack-owned, any supported engine) on a public TCP port for external clients such as `psql`, `mysql`, or a GUI client.
- **Generic TCP proxies** — an operator can define a standalone TCP forwarding rule from a public port on the panel host to an arbitrary `host:port` upstream (a Docker service, another machine, or an appliance).

This design does not introduce Docker Swarm/Kubernetes scheduling, SNI multiplexing, or L4 load balancing pools. A TCP proxy still belongs to one DockPanel `server_id` and forwards to exactly one upstream.

## Runtime Topology

```text
Internet :<public_tcp_port>            Internet :80/:443 (unchanged)
        |                                       |
        v                                       v
nginx stream { server { listen <port>      nginx http { server { ... } }
               proxy_pass <upstream>; }         (sites / panel / apps)
        |
        +--> 127.0.0.1:<loopback binding>  (panel-managed DB containers)
        +--> <container/service host>:<port> (operator-defined upstreams)
```

The `stream` block is a **top-level** Nginx context, a sibling of `http` — it cannot live inside `sites-enabled`/`conf.d`. The installer and updater create `/etc/nginx/dockpanel-streams/` and ensure the main `nginx.conf` contains exactly one:

```nginx
stream {
    include /etc/nginx/dockpanel-streams/*.conf;
}
```

Each managed TCP proxy is one file in that directory, written atomically and gated by `nginx -t` before reload — the same write/test/reload/rollback contract the existing vhost writers use.

## Upstream Model

Panel-managed database containers already publish their engine port bound to loopback only (`127.0.0.1:<host_port>` in `HostConfig.PortBindings`). A database TCP proxy therefore always renders `proxy_pass 127.0.0.1:<bound_port>;` — the container is never republished on a public interface, and no container recreation is required to toggle remote access.

Generic TCP proxies accept an operator-supplied `upstream_host:upstream_port`. The host may be a loopback-published port, a container-reachable address, or a remote host; it is validated syntactically (and IPv6-bracketed forms are normalized) at the API boundary. Because Nginx resolves `proxy_pass` upstreams at configuration-load time, the upstream should be a stable address — the panel documents this and re-renders the file when the operator edits the proxy.

Listen ports come from a managed range allocated by the backend and verified free on the agent (`find_free_port`-style bind check), never colliding with the HTTP listeners, panel ports, or the Docker ephemeral range.

## TLS Termination

A stream server may terminate TLS: `listen <port> ssl;` plus `ssl_certificate`/`ssl_certificate_key` referencing files from the existing certificate registry. Certificate selection is ownership-checked and keys are never copied — the rendered config references the registry paths in place. Plain-TCP proxies remain the default; TLS is opt-in per proxy.

## Data Model

A new `tcp_proxies` table (server-scoped, like every other managed resource):

- `id`, `server_id`, `name` (unique per server), `kind` (`database` | `generic`)
- `listen_port`, `upstream_host`, `upstream_port`
- `tls` boolean, `certificate_id` nullable FK
- `database_id` nullable FK for `kind = 'database'`

Deleting a proxy deletes its stream file, closes its firewall port, and removes the row; deleting a database removes its proxy via `ON DELETE CASCADE` plus an agent-side cleanup.

## Firewall and Security

- Opening a proxy calls the existing firewall service (`firewall::add_port` / `allow_tcp`); deleting it removes the rule. The loopback-bound database port itself is never exposed publicly — only the Nginx stream listener is.
- Listen ports are restricted to the managed range, must not already be bound, and are unique per server (enforced by the table and the agent's bind check).
- Proxy names map to filenames through a strict `[a-z0-9-]` slug; paths are confined to `/etc/nginx/dockpanel-streams/` and written as `root` with mode 0644.
- `nginx -t` runs before every reload; a rejected config is rolled back via the existing `restore_or_remove` mechanism and the API reports the exact `nginx -t` stderr.
- All inputs (name, ports, upstream host, certificate id) are validated at the agent boundary even though the backend validates too — the agent never trusts its caller.
- Proxy creation and deletion are audit-logged like other mutating routes.

## Compatibility and Update Safety

- Existing sites, panel vhost, WAF, cache, blue-green, and certificate flows are completely unchanged — `stream` config never touches the `http` context.
- `update.sh` adds the stream directory/include idempotently on machines that predate it; a machine where the stream module cannot be installed keeps working — TCP proxy creation then fails with a clear "stream module unavailable" error rather than breaking Nginx.
- If `nginx -t` already fails for unrelated reasons, the agent refuses to write stream configs (same precondition the vhost writers apply).
- The module is loaded per-distro: `libnginx-mod-stream` on Debian/Ubuntu, `nginx-mod-stream` on RHEL-family, and detection of builds where stream is compiled in (`nginx -V` contains `--with-stream`).

## Verification

The implementation must leave focused checks for:

1. `nginx.conf` gains exactly one top-level `stream { include ...; }` block across Debian and RHEL layouts, idempotent on re-run.
2. A rendered stream file contains `listen`, `proxy_pass`, and valid timeout directives; invalid names/ports/upstreams are rejected before any file is written.
3. Stream writes are atomic, `nginx -t`-gated, and rolled back on failure.
4. Database remote access reuses the container's existing loopback binding — no public Docker port publish is ever added.
5. Firewall rules are added on create and removed on delete; a failed delete still removes the stream file.
6. TLS proxies reference registry certificate paths without copying key material.
7. Backend routes enforce `server_id` scoping and authentication; the `tcp_proxies` migration is idempotent.
8. Existing Nginx pin tests and the full cargo test suite still pass.
