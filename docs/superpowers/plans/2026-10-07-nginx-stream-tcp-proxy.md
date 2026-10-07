# Nginx Stream TCP Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep Nginx as the single public ingress on every DockPanel installation and add TCP proxying via the `ngx_stream` module, so panel-managed databases can be exposed for remote clients and operators can define generic TCP forwarding rules — all terminated by host Nginx, gated by `nginx -t`, and managed through the panel UI.

**Architecture:** A top-level `stream { include /etc/nginx/dockpanel-streams/*.conf; }` block is added to `nginx.conf` by the installer/updater. The agent gains an `nginx_stream` service that renders one file per TCP proxy with the same atomic-write → `nginx -t` → reload → rollback contract the vhost writers use. Database proxies reuse the container's existing loopback-only port binding (`127.0.0.1:<port>`); generic proxies forward to a validated operator-supplied `host:port`. The backend stores proxies in a server-scoped `tcp_proxies` table and owns port allocation; the agent opens/closes firewall ports through the existing firewall service.

**Tech Stack:** Bash (`setup.sh`, `update.sh`, pin tests), Rust/Axum agent/backend, Bollard Docker API, PostgreSQL (sqlx migrations), React/TypeScript frontend.

**Spec:** `docs/superpowers/specs/2026-10-07-nginx-stream-tcp-proxy-design.md`

## Global Constraints

- Nginx remains the public HTTP/HTTPS ingress everywhere. This plan adds no Traefik install, no installation-mode marker, and no HTTP listener changes; the existing optional Traefik agent service is untouched.
- `stream` config lives only in top-level context, never inside `http`/`server` blocks or `sites-enabled`.
- Every managed stream file is written atomically into `/etc/nginx/dockpanel-streams/`, gated by `nginx -t`, and rolled back via `restore_or_remove` on failure.
- Database upstreams are always the container's existing `127.0.0.1` port binding — the agent must never add a public Docker port publish.
- Public listen ports come from a managed range (`40000`-`44999`), are unique per server, and are verified free by a bind check on the agent before writing config.
- Proxy names are a strict `[a-z0-9-]` slug; file paths are confined to the stream directory.
- TLS on a stream listener references certificate registry paths in place; key material is never copied or logged.
- Every mutating agent route re-validates all inputs (name, ports, upstream, certificate id) — the agent never trusts its caller.
- Firewall ports are opened on create and removed on delete through `firewall::add_port`/`remove_port`.
- No Docker Swarm, Kubernetes, SNI multiplexing, or L4 load-balancer pools are added.
- Every non-trivial change leaves one focused runnable test or pin assertion.

---

## File Map

- `scripts/setup.sh`: install the stream module package per distro, create `/etc/nginx/dockpanel-streams/`, insert the top-level `stream` block into `nginx.conf` idempotently.
- `scripts/update.sh`: same ensure logic for existing installs, safe when the module is unavailable.
- `panel/agent/src/services/nginx_stream.rs` (new): stream config rendering, validation, atomic write, `nginx -t` gate, reload, rollback, removal; module-availability detection.
- `panel/agent/src/routes/nginx_stream.rs` (new) and `routes/mod.rs`: create/list/delete TCP proxy endpoints with full input validation and firewall integration.
- `panel/agent/src/services/database.rs`: expose the container's loopback-bound port for stream upstream resolution.
- `panel/backend/migrations/<timestamp>_tcp_proxies.sql` (new): server-scoped table, unique `(server_id, name)` and `(server_id, listen_port)`, `database_id` FK cascade.
- `panel/backend/src/routes/tcp_proxies.rs` (new) and `databases.rs`: generic proxy CRUD, port allocation, database remote-access toggle; auth and `server_id` scoping.
- `panel/agent/src/services/ssl.rs` / certificate registry: resolve owned certificate paths for TLS stream listeners.
- `panel/frontend/src/pages/Databases.tsx` (+ optional `TcpProxies.tsx`, `main.tsx`): remote-access toggle UI and generic proxy management.
- `tests/nginx-stream-pin-e2e.sh` (new): source/fixture pins for the installer edits, render output, validation, and deletion semantics.
- `docs/guides/databases.md`, `README.md`, `FEATURES.md`: document remote access and TCP proxy behavior.

---

### Task 1: Install the stream module and top-level `stream` block

**Files:**
- Modify: `scripts/setup.sh` (`install_nginx` at ~line 698 and the `nginx.conf` normalization near lines 2231-2258).
- Modify: `scripts/update.sh` (the nginx/package ensure section).
- Create: `tests/nginx-stream-pin-e2e.sh`.

**Interfaces:**
- Produces `/etc/nginx/dockpanel-streams/` (root-owned, 0755) and exactly one `stream { include /etc/nginx/dockpanel-streams/*.conf; }` block in `nginx.conf`.
- Produces a `ensure_nginx_stream()` shell helper usable by both scripts; stream module installed via `libnginx-mod-stream` (apt) or `nginx-mod-stream` (dnf); skipped with a warning when `nginx -V` already shows `--with-stream`.

- [ ] **Step 1: Write failing source/fixture assertions**

Add to `tests/nginx-stream-pin-e2e.sh` (follow `tests/nginx-listen-pin-e2e.sh` conventions — fixtures in `mktemp -d`, no root, no `/etc` writes):

```bash
assert_contains() {
    local file="$1" needle="$2"
    grep -Fq "$needle" "$file" || {
        printf 'missing %s in %s\n' "$needle" "$file" >&2
        exit 1
    }
}

assert_contains "$SETUP" 'dockpanel-streams'
assert_contains "$SETUP" 'libnginx-mod-stream'
assert_contains "$SETUP" 'nginx-mod-stream'
assert_contains "$UPDATE" 'dockpanel-streams'
```

Plus a fixture test: run the extraction-able block-insertion logic against a Debian-style and a RHEL-style `nginx.conf` fixture and assert exactly one top-level `stream` block results, and a second run is a no-op.

Run: `bash tests/nginx-stream-pin-e2e.sh`
Expected: FAIL — no stream support exists.

- [ ] **Step 2: Implement `ensure_nginx_stream`**

Write the helper so it: detects a compiled-in stream module (`nginx -V`), installs the distro module package otherwise, creates the directory, inserts the `stream { include ...; }` block before the `http {` block (or appends at top level when no `http` anchor exists), and gates on `nginx -t` before reload. It must never duplicate the block on re-run.

- [ ] **Step 3: Run the focused pin test**

Run: `bash tests/nginx-stream-pin-e2e.sh`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add scripts/setup.sh scripts/update.sh tests/nginx-stream-pin-e2e.sh
git commit -m "feat: install nginx stream module and top-level include"
```

---

### Task 2: Agent `nginx_stream` service — render, validate, write, rollback

**Files:**
- Create: `panel/agent/src/services/nginx_stream.rs`; register in `panel/agent/src/services/mod.rs`.
- Test: `nginx_stream.rs` unit-test module and `tests/nginx-stream-pin-e2e.sh`.

**Interfaces:**
- `render_stream_server(name, listen_port, upstream_host, upstream_port, tls: Option<&TlsPaths>) -> Result<String, String>` produces one `server { listen <port> [ssl]; proxy_pass <host>:<port>; proxy_connect_timeout …; proxy_timeout …; }` block.
- `validate_proxy_name`, `validate_listen_port` (managed range only), `validate_upstream` (strict `host:port`, IPv6 bracket normalization) reject bad input before any file write.
- `write_stream_proxy` writes temp+rename into `/etc/nginx/dockpanel-streams/<name>.conf`, runs `test_config()`, reloads on success, and uses `restore_or_remove` on failure.
- `remove_stream_proxy` deletes the file, `nginx -t`, reload.
- `stream_available()` reports whether the module/include are present, so callers can fail with a clear message.

- [ ] **Step 1: Add failing unit tests for rendering and validation**

Tests assert: rendered block contains `listen 40001;` and `proxy_pass 127.0.0.1:5450;`; a TLS render adds `ssl` and cert paths; names like `../evil` or `a b` are rejected; ports outside the managed range are rejected; upstream `host:port` validation rejects missing port, out-of-range port, and empty host; IPv6 `[::1]:5432` normalizes correctly.

Run: `cargo test --manifest-path panel/agent/Cargo.toml nginx_stream`
Expected: FAIL — module does not exist.

- [ ] **Step 2: Implement render + validation + write lifecycle**

Reuse `test_config`, `reload`, `restore_or_remove` from `services/nginx.rs` rather than duplicating them. Keep the write refusal when `nginx -t` is already failing, mirroring the existing vhost precondition.

- [ ] **Step 3: Run tests**

Run:

```bash
cargo test --manifest-path panel/agent/Cargo.toml nginx_stream
bash tests/nginx-stream-pin-e2e.sh
```

Expected: PASS, no Docker daemon or root required.

- [ ] **Step 4: Commit**

```bash
git add panel/agent/src/services/nginx_stream.rs panel/agent/src/services/mod.rs tests/nginx-stream-pin-e2e.sh
git commit -m "feat: agent nginx stream proxy rendering and lifecycle"
```

---

### Task 3: Agent routes + backend `tcp_proxies` for generic TCP proxies

**Files:**
- Create: `panel/agent/src/routes/nginx_stream.rs`; register in `panel/agent/src/routes/mod.rs`.
- Create: `panel/backend/migrations/<timestamp>_tcp_proxies.sql` (follow `20260909000000_standalone_db_stacks.sql` conventions — concrete FK columns, CHECK constraints, `IF NOT EXISTS`).
- Create: `panel/backend/src/routes/tcp_proxies.rs`; register in `panel/backend/src/routes/mod.rs`.
- Test: Rust unit tests for allocation/validation, source pins.

**Interfaces:**
- Agent: `POST /nginx/streams` (name, listen_port, upstream_host, upstream_port, tls), `GET /nginx/streams`, `DELETE /nginx/streams/<name>` — all re-validated; delete returns success even when the file is already absent (idempotent).
- Agent opens `firewall::add_port(listen_port, "tcp")` only after `nginx -t`+reload succeed; delete calls `remove_port` and always removes the file.
- Backend: server-scoped CRUD on `tcp_proxies`; allocates the lowest free port in the managed range; enforces `kind='generic'` here (database kind arrives in Task 4).
- Table shape per spec: `id`, `server_id`, `name`, `kind`, `listen_port`, `upstream_host`, `upstream_port`, `tls`, `certificate_id`, `database_id`, created/updated timestamps.

- [ ] **Step 1: Add failing tests for allocation and route contract**

Backend unit test: port allocation skips used ports and stays in range; name/port uniqueness enforced per `server_id` (two servers may reuse a port). Pin: agent route file exists and delegates all writes through `nginx_stream` service (no inline config strings).

Run: `cargo test --manifest-path panel/backend/Cargo.toml tcp_proxies` and `cargo test --manifest-path panel/agent/Cargo.toml nginx_stream`
Expected: FAIL.

- [ ] **Step 2: Implement migration + backend routes**

Migration is additive and idempotent; routes authenticate, resolve the target `server_id`, forward to the agent, and persist rows only after the agent reports success. Delete removes the row only after agent-side file+firewall cleanup (or records the failure honestly).

- [ ] **Step 3: Implement agent routes**

Parse into typed structs, validate via Task 2 helpers, verify `listen_port` is free via a bind check, then delegate to `write_stream_proxy`; open the firewall port last. Never write a stream file when `stream_available()` is false — return a clear error.

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test --manifest-path panel/agent/Cargo.toml nginx_stream
cargo test --manifest-path panel/backend/Cargo.toml tcp_proxies
bash tests/nginx-stream-pin-e2e.sh
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add panel/agent/src/routes/nginx_stream.rs panel/agent/src/routes/mod.rs panel/backend/migrations panel/backend/src/routes/tcp_proxies.rs panel/backend/src/routes/mod.rs tests
git commit -m "feat: generic TCP proxy CRUD through nginx stream"
```

---

### Task 4: Database remote access via stream proxy

**Files:**
- Modify: `panel/agent/src/services/database.rs` (expose the loopback-bound port already present in `PortBindings`, e.g. a `loopback_port(container_id)` helper alongside `list_databases`' `public_port` read at ~line 309).
- Modify: `panel/agent/src/routes/nginx_stream.rs` or a `database.rs` agent route for the DB-proxy create/delete path.
- Modify: `panel/backend/src/routes/databases.rs` (remote-access enable/disable endpoints).
- Modify: `tcp_proxies` usage — `kind='database'`, `database_id` FK set.
- Test: Rust tests + `tests/database-icc-reconcile-and-file-download-pin-e2e.sh`-style pins or a dedicated section in `tests/nginx-stream-pin-e2e.sh`.

**Interfaces:**
- Enabling remote access on a database resolves its container's existing `127.0.0.1:<port>` binding and creates a `kind='database'` stream proxy `listen <public>` → `proxy_pass 127.0.0.1:<bound>`.
- The container is never republished on a public interface; no recreate is required.
- Disabling removes the stream file and firewall rule; deleting a database cascades the `tcp_proxies` row and the backend issues the agent-side cleanup.

- [ ] **Step 1: Add failing tests**

Unit test: given a container inspect shape with `127.0.0.1:5123 → 5432`, the helper returns `5123` and the render produces `proxy_pass 127.0.0.1:5123;`. Pin: no code path adds a `0.0.0.0` or empty-`host_ip` `PortBinding` when enabling remote access.

Run: `cargo test --manifest-path panel/agent/Cargo.toml database nginx_stream`
Expected: FAIL.

- [ ] **Step 2: Implement agent-side DB proxy path**

Resolve the bound port by inspecting the managed container (verify `dockpanel.managed=true` label); refuse when the container has no loopback binding rather than guessing. Write the stream proxy through Task 2/3 machinery with `kind='database'`.

- [ ] **Step 3: Implement backend toggle endpoints**

`POST /databases/<id>/remote-access` and `DELETE …/remote-access`: server-scoped, auth-checked, allocate a managed-range port on enable, persist `tcp_proxies` row with `database_id`, return the public `host:port` for the UI. On database delete, clean up the agent-side proxy before/while the row cascades.

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test --manifest-path panel/agent/Cargo.toml
cargo test --manifest-path panel/backend/Cargo.toml databases tcp_proxies
bash tests/nginx-stream-pin-e2e.sh
bash tests/database-icc-reconcile-and-file-download-pin-e2e.sh
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add panel/agent/src/services/database.rs panel/agent/src/routes panel/backend/src/routes tests
git commit -m "feat: database remote access through nginx stream"
```

---

### Task 5: TLS termination on stream listeners

**Files:**
- Modify: `panel/agent/src/services/nginx_stream.rs` (TLS render already stubbed in Task 2 — wire cert registry path resolution).
- Modify: `panel/agent/src/services/ssl.rs` and/or `routes/ssl_registry.rs` only at the "resolve owned cert paths" boundary.
- Modify: `panel/backend/src/routes/tcp_proxies.rs` (`certificate_id` validation, ownership).
- Test: Rust render/validation tests + pin assertions.

**Interfaces:**
- `tls: { certificate_id }` on create renders `listen <port> ssl;` + `ssl_certificate`/`ssl_certificate_key` pointing at the registry's existing files.
- Certificate must exist, be owned by the same server, and its key file must be readable by nginx without copying.
- Plain TCP remains the default; `certificate_id` required iff `tls=true`.

- [ ] **Step 1: Add failing TLS tests**

Render test asserts `ssl` listen flag and registry paths appear, and that no key material is embedded. Validation test: nonexistent/foreign `certificate_id` rejected; `tls=true` without certificate rejected.

Run: `cargo test --manifest-path panel/agent/Cargo.toml nginx_stream ssl`
Expected: FAIL.

- [ ] **Step 2: Implement certificate resolution and TLS render**

Reuse the existing certificate registry lookup; validate file existence and permissions at write time; keep ACME flows untouched.

- [ ] **Step 3: Run tests**

Run:

```bash
cargo test --manifest-path panel/agent/Cargo.toml nginx_stream ssl
cargo test --manifest-path panel/backend/Cargo.toml tcp_proxies
bash tests/nginx-stream-pin-e2e.sh
bash tests/certificate-registry-pin-e2e.sh
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add panel/agent/src/services/nginx_stream.rs panel/agent/src/services/ssl.rs panel/backend/src/routes/tcp_proxies.rs tests
git commit -m "feat: TLS termination for nginx stream proxies"
```

---

### Task 6: Panel UI — remote access and TCP proxy management

**Files:**
- Modify: `panel/frontend/src/pages/Databases.tsx` (remote-access card per database: enable toggle, public endpoint display, TLS flag).
- Create: `panel/frontend/src/pages/TcpProxies.tsx` (generic proxy list/create/delete) and register route in `panel/frontend/src/main.tsx` (follow `Databases` lazy-route pattern at ~lines 89/148) — or fold into an existing page if the nav structure favors it.
- Modify: shared API client types where frontend↔backend contracts are declared.
- Test: `npm run typecheck`, plus pin that the UI calls only the new backend routes.

**Interfaces:**
- Databases page shows `Remote access: <host>:<port>` with enable/disable and optional TLS picker bound to existing certificates.
- TCP proxies page lists name/listen port/upstream/TLS with create and delete forms; all fields validated client-side identically to server rules.

- [ ] **Step 1: Add failing contract pins**

Pin in `tests/nginx-stream-pin-e2e.sh`: frontend references `/tcp-proxies` (and the database remote-access endpoints) and no UI writes nginx config paths directly.

Run: `cd panel/frontend && npm run typecheck` (fails on missing API functions) and `bash tests/nginx-stream-pin-e2e.sh`
Expected: FAIL.

- [ ] **Step 2: Implement API client + Databases remote-access UI**

Add typed client calls; render the toggle and endpoint display; surface agent `nginx -t` errors verbatim in the UI error state.

- [ ] **Step 3: Implement TCP proxies page**

List, create (name/listen port/upstream/TLS/cert), delete with confirm; register lazy route and nav entry following existing conventions.

- [ ] **Step 4: Run checks**

Run:

```bash
cd panel/frontend && npm run typecheck && npm run build
bash tests/nginx-stream-pin-e2e.sh
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add panel/frontend/src tests
git commit -m "feat: remote access and TCP proxy UI"
```

---

### Task 7: Documentation and verification matrix

**Files:**
- Modify: `docs/guides/databases.md` (remote access section), `README.md`, `FEATURES.md` as appropriate.
- Create: `docs/guides/tcp-proxies.md` if the feature warrants a standalone guide (follow existing guide style).
- Modify: `tests/nginx-stream-pin-e2e.sh` (doc assertions).

**Interfaces:**
- Docs state: nginx is the sole ingress; TCP proxies use the stream module; managed port range; loopback-binding upstream model for databases; TLS option; firewall behavior; one proxy = one upstream (no pools).

- [ ] **Step 1: Add failing doc assertions**

Extend the pin test to require docs mention `stream`, the managed port range, loopback upstreams for databases, and the firewall open/close contract.

Run: `bash tests/nginx-stream-pin-e2e.sh`
Expected: FAIL until docs updated.

- [ ] **Step 2: Write documentation**

Update the three docs; include a worked `psql`/`mysql` example and the "stream module unavailable" failure mode.

- [ ] **Step 3: Run the full verification set**

Run:

```bash
bash tests/nginx-stream-pin-e2e.sh
bash tests/nginx-headers-pin-e2e.sh
bash tests/nginx-listen-pin-e2e.sh
bash tests/database-icc-reconcile-and-file-download-pin-e2e.sh
bash tests/certificate-registry-pin-e2e.sh
cargo test --manifest-path panel/agent/Cargo.toml
cargo test --manifest-path panel/backend/Cargo.toml
cd panel/frontend && npm run typecheck && npm run build
```

Expected: all PASS. Environment-limited checks (no Docker daemon, no nginx binary) are reported as skipped, not silently dropped.

- [ ] **Step 4: Commit**

```bash
git add docs README.md FEATURES.md tests
git commit -m "docs: document nginx stream TCP proxying"
```

---

## Self-Review Checklist

- [ ] Installer/updater stream-module enablement and idempotent `stream {}` include are covered by Task 1.
- [ ] Render/validate/atomic-write/`nginx -t`/rollback lifecycle is covered by Task 2.
- [ ] Generic TCP proxy CRUD, server scoping, port allocation, and firewall integration are covered by Task 3.
- [ ] Database remote access reusing loopback bindings (no public publish, no recreate) is covered by Task 4.
- [ ] TLS termination via certificate registry is covered by Task 5.
- [ ] UI for both consumers is covered by Task 6.
- [ ] Documentation and the full verification matrix are covered by Task 7.
- [ ] No task touches HTTP listeners, site vhosts, the panel vhost, or the optional Traefik service.
- [ ] No task introduces multi-node scheduling or cross-server routing.
- [ ] No placeholder words (`TBD`, `TODO`, `implement later`) are used as implementation instructions.
- [ ] All named functions and files match the current repository symbols or are explicitly introduced by an earlier task.
