# Porting dockpanel-agent from Rust to Go

Source of truth: `panel/agent/src` (Rust). Target: `panel/go` module
`github.com/ovexro/dockpanel/panel/go` (go 1.25). The Go agent must be a
**drop-in replacement**: the panel backend, the CLI, nginx and the installers
talk to it unchanged.

## Non-negotiables

1. **Wire compatibility.** Same paths, methods, status codes, JSON field names
   and shapes as the Rust serde output. Mirror `#[serde(rename…)]`,
   `skip_serializing_if`, `default`, and `Option` → `null` exactly (a Rust
   `Option<T>` without `skip_serializing_if` serializes as `null`, so the Go
   field must be a pointer/`any` WITHOUT `omitempty`). Error bodies are
   `{"error": "<msg>"}` with the same message text and status.
2. **Every safety check survives.** Path validation, name/domain validators,
   SSRF guard, command allow-lists, `..`/NUL rejection, constant-time compares,
   0600/0640 file modes, atomic temp-file+rename writes, nginx `-t` before
   reload with rollback, timeouts, locks. If the Rust code refuses something,
   the Go code refuses it the same way. When in doubt, port literally.
3. **No raw `exec.Command`.** Child processes go through `internal/agent/safecmd`
   (sanitised env, unsandboxed systemd-run path). Always pass a context with
   the same timeout the Rust code used; Rust `kill_on_drop(true)` maps to
   `exec.CommandContext` + context cancel.
4. **Keep the "why" comments** (condensed). They record production incidents;
   a Go reader needs them as much as a Rust reader did. Drop session/issue
   numbers only if they add nothing.
5. **Port the tests.** Every Rust `#[test]`/`#[tokio::test]` in a module
   becomes a Go test in the matching `_test.go` (table-driven where natural).
   Tests that `include_str!` their own Rust source to assert a textual property
   are ported to read the Go source file instead, asserting the equivalent
   property — or dropped with a one-line comment if the property is now
   enforced by the type system/compiler.

## Layout

```
panel/go/cmd/dockpanel-agent/main.go     daemon entry (mirrors src/main.rs)
panel/go/internal/agent/safecmd/          src/safe_cmd.rs
panel/go/internal/agent/sitelock/         src/site_lock.rs
panel/go/internal/agent/agenttls/         src/tls.rs
panel/go/internal/agent/services/         src/services/*.rs   — ONE flat package
panel/go/internal/agent/routes/           src/routes/*.rs     — ONE flat package
panel/go/internal/agent/templates/        copies of src/templates/** (go:embed)
```

`services` and `routes` are flat packages because the Rust services have
dependency cycles (nginx→traefik→ownership→nginx, ownership↔sftp_accounts,
backups↔database_backup) that Go packages cannot express.

**One Rust file → one Go file** with the same base name
(`services/docker_apps.rs` → `services/docker_apps.go`). Because the package is
shared by many files written in parallel, **every package-level identifier in
a file is prefixed with that module's CamelCase name**, exported or not:

- `services/nginx.rs::reload()` → `services.NginxReload()`
- `services/ssl.rs::struct CertInfo` → `services.SslCertInfo`
- private helper `fn parse_line` in logs.rs → `logsParseLine`
- constants: `NginxSitesDir`, `logsMaxLines`

If the name already starts with the prefix, do not double it
(`cpu_sampler.rs::CpuSampler` → `services.CpuSampler`). Exception: none. Collisions between parallel workers are the failure this
rule prevents. Calls into another module use that module's prefix
(`services.OwnershipChownSite(...)`). If the callee file does not exist yet
(another worker owns it), call the name the rule predicts and keep going — the
integration pass reconciles signatures.

## Routes

- Each `src/routes/<m>.rs` → `routes/<m>.go` exposing
  `func register<M>(r *Router)` and appended in `routes/router.go`'s
  `registrars` list (the integration pass adds the line; do not edit
  router.go concurrently — put your registrar name in your report).
- `Router.Handle("POST /nginx/sites/{domain}", h)` — Go 1.22 ServeMux
  patterns; axum `{x}` is the same syntax, axum `{*rest}` → `{rest...}`.
- Handlers: `func(w http.ResponseWriter, r *http.Request)`. Path params via
  `r.PathValue("domain")`. Query via `r.URL.Query()`.
- Helpers in `routes/http.go`: `writeJSON(w, status, v)`, `writeErr(w, status,
  msg)`, `decodeJSON(r, &v) bool` (writes the error itself on failure, same
  422/400 semantics as axum's Json extractor: malformed JSON → 400, wrong
  shape → 422, missing content-type → 415), `isValidDomain`, `isValidName`,
  `isValidContainerID`.
- Shared state: `*State` (see `routes/state.go`) — token, previous token,
  templates, docker client, cpu sampler, network snapshot.
- WebSockets (terminal, log stream): `github.com/coder/websocket`.
- Streaming NDJSON/SSE: flush after each line (`http.Flusher`).

## Library mapping

| Rust | Go |
|---|---|
| axum / axum-server | net/http (+ crypto/tls) |
| tokio::process | os/exec via safecmd |
| serde_json | encoding/json |
| serde_yaml_ng | go.yaml.in/yaml/v3 |
| tera | github.com/flosch/pongo2/v6 (templates kept byte-identical) |
| bollard | github.com/moby/moby/client (+ github.com/moby/moby/api/types) |
| sysinfo | github.com/shirou/gopsutil/v4 |
| instant-acme | golang.org/x/crypto/acme |
| rcgen / x509-parser / rustls | crypto/x509, crypto/tls (stdlib) |
| jsonwebtoken | github.com/golang-jwt/jwt/v5 |
| reqwest | net/http |
| sha2 / hmac / subtle / hex / base64 | crypto/*, encoding/* (stdlib) |
| rand / uuid | crypto/rand, github.com/google/uuid |
| rustix pty | github.com/creack/pty |
| libc / prctl | golang.org/x/sys/unix |
| sha-crypt | github.com/GehirnInc/crypt (sha512_crypt) |
| chrono / time | time |
| tracing | log/slog (target "audit" → slog attr `target=audit`) |

Do not add other dependencies without a reason in your report.

## Already provided — use, do not rewrite

- `safecmd`: `Command(ctx, bin, args...) *exec.Cmd` (sanitised env; append to
  `cmd.Env` for extras), `Run(ctx, cmd) (Output, error)`, `Exec(ctx, bin,
  args...) (Output, error)`, `Output{Stdout, Stderr []byte; ExitCode int}` +
  `.Success()`. Unsandboxed: `NewUnsandboxed(bin, "K=V"...)` → `.Arg(...)`,
  `.Output(ctx)`, `.OutputWithTimeout(d)`, `.SpawnStreaming(ctx)` →
  `*StreamingRun{Lines <-chan string}` + `.Wait() (int, error)`.
  `NewDockerEnvFile([2]string{"K","V"}...)` + `.Path()` + `defer .Close()`.
  `safecmd.DockerConfigDir`.
- `routes`: `Router.Handle(pattern, fn)`, `Router.HandlePublic`, `r.State`,
  `writeJSON`, `writeErr`, `decodeJSON`, `isValidDomain`, `isValidName`,
  `isValidContainerID`, `State.Token()`, `State.Docker`, `State.Cpu`,
  `State.Templates`, `State.NetMu`/`State.NetworkSnp`, `ConfigDir`.

## Process rules for parallel workers

- Touch ONLY the files assigned to you (plus their `_test.go`). Never edit
  `go.mod`/`go.sum`, `routes/router.go`, `routes/state.go`, `routes/http.go`,
  `safecmd`, or another worker's files. Need a new dependency or a change to a
  shared file? Say so in your report.
- All dependencies in the mapping table are already in go.mod.
- The flat packages will not compile until every worker is done. Check your
  own work with `gofmt -l` and `GOOS=linux go vet ./internal/agent/services/`
  (or `routes/`), and treat ONLY `undefined: <Prefix>…` errors whose prefix
  belongs to a module you do not own as acceptable. Everything else must be
  clean.
- Run tests in Linux when your package compiles:
  `docker run --rm -v "$PWD/../..":/src -w /src/panel/go golang:1.26 go test ./internal/agent/...`
- Report (≤400 words): files written, registrar function names, every
  cross-module function you CALL that you do not own (name + the signature you
  assumed), every behaviour you could not port faithfully, and test counts.
