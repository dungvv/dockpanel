# Porting dockpanel-api (panel backend) from Rust to Go

Source of truth: `panel/backend/src` (Rust, axum + sqlx/Postgres). Target:
`panel/go/internal/api` (package `api`) + `panel/go/cmd/dockpanel-api`.
Everything in `../agent/PORTING.md` applies — **read it first**: wire
compatibility (same paths, status codes, JSON field names/shapes, `Option` →
`null` without `omitempty`), every security check survives, keep the "why"
comments, port every test, no raw `exec.Command`. This file only adds what
differs for the API. Do NOT import `internal/agent/...` (separate binary).

## Layout — one flat package

`routes/*.rs` and `services/*.rs` import each other freely, so everything is
one package `api`:

| Rust | Go |
|---|---|
| `src/routes/<m>.rs` | `rt_<m>.go` (+ `rt_<m>_test.go`) |
| `src/services/<m>.rs` | `svc_<m>.go` (+ `_test.go`); a directory module (`prerequisites/`) → `svc_prerequisites*.go` |
| config/error/auth/helpers/models/safe_cmd/main.rs AppState, routes/mod.rs | `core_*.go` (done) |
| `services/agent.rs`, `services/secrets_crypto.rs` | `svc_agent.go`, `svc_secrets_crypto.go` (done) |
| `migrations/*.sql` | `migrations/` — byte-identical copies, `go:embed`; a test diffs them against the Rust tree. Add new migrations to BOTH trees while the Rust one exists. |

### Naming (the rule that prevents collisions between parallel workers)

- `svc_<m>.go`: every package-level identifier is prefixed with `<M>`
  (CamelCase of the module, exported) or `<m>` (lowerCamel, unexported):
  `services/alert_engine.rs::run` → `AlertEngineRun`, a private
  `fn parse_line` → `alertEngineParseLine`, a const → `alertEngineMaxRetries`.
- `rt_<m>.go`: every package-level identifier is prefixed with `rt<M>`:
  `routes/sites.rs::create` → `rtSitesCreate`, `struct CreateSiteRequest` →
  `rtSitesCreateSiteRequest`.
- CamelCase is per underscore part: `docker_apps` → `DockerApps`, `ssl` →
  `Ssl`, `on_call` → `OnCall`, `api_keys` → `ApiKeys`.
- Do not double a prefix (`backup_scheduler.rs::BackupScheduler` →
  `BackupScheduler`). Core identifiers are unprefixed — never add new ones.
- Calling a module that another worker owns: use the name the rule predicts
  and keep going; the integration pass reconciles signatures. List every such
  call in your report.

### Route registration

Each `rt_<m>.go` exposes `func rt<M>Register(r *Router)`. `core_router.go`'s
`registrars` list already names them in `routes::router()` order (commented);
do not edit it — the integration pass uncomments. Translate
`.route("/api/x/{id}", get(a).put(b))` into
`r.Handle("GET /api/x/{id}", rtXA)` + `r.Handle("PUT /api/x/{id}", rtXB)`;
axum `{*rest}` → `{rest...}`.

**Route conflicts.** Go's ServeMux panics where matchit silently preferred
the static segment. `TestRustRoutesRegisterWithoutConflict` registers every
Rust route; today exactly one pair conflicts:
`PUT /api/alerts/runbooks/{alert_type}` vs `PUT /api/alerts/{id}/acknowledge`
(and `/resolve`). `rt_alerts.go` must register ONE pattern
`PUT /api/alerts/{a}/{b}` and dispatch: `a == "runbooks"` → put_runbook(b),
else `b == "acknowledge"`/`"resolve"` → those handlers, else an empty 404.

## Core API (use, do not rewrite)

**Handlers**: `type Handler func(w http.ResponseWriter, r *http.Request) error`.
Return an `error` for every Rust `Err(...)`: `*ApiError` is written as its
JSON, an extractor rejection as text/plain, an `*AgentError` via
`agentError("agent call", e)` (prefer calling `agentError(ctx, e)` yourself
with the Rust context string), anything else as `internalError`. Write
success with `writeJSON(w, status, v)` (serde-identical: no HTML escaping, no
trailing newline) and `return nil`. `Router.St` is the `*AppState`.

**Errors** (`core_error.go`): `apiErr(status, msg)`, `apiErrCoded(status,
msg, code)`, `apiErrJSON(status, anyBody)`, `agentError(context, err)`,
`agentActionable(err) (status, msg, ok)`, `acmeOrderFailure(err) (msg, ok)`,
`dnsProviderFailure(err) (msg, ok)`, `upstreamError(service, err)`,
`internalError(context, err)`, `requireAdmin(role) error`,
`paginate(*int64, *int64) (limit, offset)`, `rejection(status, msg)`;
constants `CodeAgentUnreachable`, `CodeReauthRequired`, `CodeSessionInvalid`,
`CodePayloadTooLarge`, `CodeForeignCertificate`. All return `error` (never a
typed nil pointer), so `if err := requireAdmin(c.Role); err != nil { return err }`.

**Extractors** — call them first, in the Rust handler's argument order:
- `st.authUser(r) (*Claims, error)`, `st.adminUser(r)`, `st.resellerUser(r)`;
  `Result<AuthUser, ApiError>` = call and inspect the error yourself.
- `st.serverScope(r) (uuid.UUID, AgentHandle, error)` (ServerScope).
- `st.authenticateAgent(r) (uuid.UUID, error)`, `st.agentRateLimit(serverID) error`.
- `decodeJSON(r, &v) error` (Json<T>: 415/413/400/422). serde required-field
  semantics are enforced: a non-pointer field must be present and non-null
  unless tagged `serde:"default"` (#[serde(default)]); `Option<T>` → `*T`;
  `serde_json::Value` → `any` or `json.RawMessage`. `decodeJSONBytes(b, &v)`
  when you already hold the body (custom body limits).
- `decodeQuery(r, &v) error` (Query<T>, `json` tags as the field names).
- `pathUUID(r, "id") (uuid.UUID, error)`; other params `r.PathValue("x")`.
- `clientIP(r) *string`.

**Claims**: `Sub uuid.UUID, Email, Role string, Exp, Iat uint64, Jti *string,
KeyID *uuid.UUID`. Mint with `encodeJWT(&c, st.Config.JWTSecret)`, verify with
`decodeJWT(token, secret)`. Session plumbing: `st.blacklistAdd(jtis...)`,
`st.isBlacklisted(jti)`, `st.setSessionsRevokedAt(unix)`,
`st.sessionsRevokedAt()`, `st.revokeAllUserSessions(ctx, userID)` (ported
here from routes/auth.rs — rt_auth must call it, not re-port it).
Passwords: `hashPassword(pw)` (Argon2::default PHC), `verifyPassword(pw, phc)
(ok, err)` (`err` = unparseable hash → answer "Password hash error" 500),
`bcryptHash(pw, cost)` ($2b$, as the bcrypt crate), `bcryptVerify`.

**AppState** (`core_state.go`): `DB *pgxpool.Pool`, `Config *Config`
(`DatabaseURL, JWTSecret, AgentSocket, AgentToken, ListenAddr,
DBMaxConnections, BaseURL, CORSOrigins`), `Agent *AgentClient` (legacy local),
`Agents *AgentRegistry`, `LoginMu`+`LoginAttempts map[string][]time.Time`,
`TwofaMu`+`TwofaAttempts`, `WebhookMu`+`WebhookAttempts`,
`AgentRateMu`+`AgentRateLimits` (all `map[uuid.UUID]RateWindow{Count,
Start}`), `OAuthMu`+`OAuthStates map[string]OAuthState{Provider, Created}`,
`Notif *Broadcast[PanelNotification{UserID, Payload}]`, `ProvisionLogs`,
`Shutdown context.Context`. Rust's `passkey_challenges` and
`panel_update_state` are **module-owned**: declare them as a package-level var
in `rt_passkeys.go` / `svc_panel_update.go` (one process = one AppState).

**Provisioning logs** (Rust `provision_logs` + `deploy_owners`, one object):
`st.ProvisionLogs.Register(id, owner, capacity)`, `.Emit(id, ProvisionStep)
bool`, `.Remove(id)` (closes readers — the terminal step's `remove`),
`.Forget(id)`, `.Has(id)`, `.Open(id, caller, missingMsg) (history, <-chan
ProvisionStep, unsubscribe, error)`. `ProvisionStep{Step, Label, Status,
Message *string}` replaces `routes::sites::ProvisionStep`.

**Long-lived handlers** (SSE, websocket — `github.com/coder/websocket`):
select on `st.Shutdown.Done()` as well as `r.Context().Done()` (Rust
`shutdown_signal_fut`). Flush after every event. The 300s timeout stops once
headers are written or the connection is hijacked, as tower's did.

**Broadcast[T]** (tokio broadcast): `NewBroadcast[T](cap)`, `.Subscribe()
(<-chan T, unsubscribe)`, `.Send(v) int`, `.Close()`. A full subscriber
buffer drops the value for that subscriber (tokio "Lagged").

**DB** (`core_db.go`, pgx v5): `queryAll[T]`, `queryOne[T]` (`ErrRowNotFound`
= sqlx RowNotFound; map it yourself as the Rust did), `queryOpt[T]` (*T),
`queryScalar[T]`, `queryScalarOpt[T]` (`Option<Option<T>>` → `queryScalarOpt[*T]`),
`execSQL` (rows affected); all take `(ctx, q Querier, sql, args...)` where
`Querier` is the pool or a `pgx.Tx`. Struct rows map by `db:"col"` tag with
sqlx FromRow semantics (missing column = error, extra columns ignored,
`db:"col,default"`, `db:"-"`, embedded struct = flatten). Tuples
`(A, B)` → `Tup2[A, B]` … `Tup6` (fields `.A .B …`, positional). Types:
`Uuid`→`uuid.UUID`, `DateTime<Utc>`→`time.Time`, `Option`→pointer,
`Value`→`json.RawMessage`, `Vec<Uuid>`→`[]uuid.UUID`, `Vec<String>`→`[]string`,
`i32`→`int32`, `i64`→`int64`. Transactions: `tx, err := st.DB.Begin(ctx)` +
`defer tx.Rollback(ctx)` + `tx.Commit(ctx)` (sqlx drop = rollback).
Models in `core_models.go`: `User`, `Site`, `OnCallSchedule`,
`EscalationPolicy`, `EscalationStep`, `PanelSnapshot`, `FleetUpdateRun`,
`UpdateChannelValidate`.

**Agents** (`svc_agent.go`): `AgentHandle` interface — `Get(ctx, path)`,
`Post(ctx, path, body)` (body `nil` = Rust `None`), `Put`, `PutLong(ctx,
path, body, secs)`, `Delete`, `GetBytes(ctx, path) ([]byte, *string
contentDisposition, error)`, `PostLong(ctx, path, body, secs)`,
`PostLongNDJSON(ctx, path, body, idleSecs, onLine func(any))`, `Token()`.
Results are `serde_json::Value` as `any` (decoded with UseNumber): read them
with `jsonGet(v, "a", "b", 0)`, `jsonStr`, `jsonBool`, `jsonI64`, `jsonU64`,
`jsonF64`, `jsonArr`, `jsonObj`; pass them straight to `writeJSON` for a
passthrough. Errors are `*AgentError{Kind, Code, Msg}`
(`AgentErrConnection|Request|Response|Status|Parse|CircuitOpen|NotFound`).
Pass `r.Context()` from handlers (the Rust request future was dropped on
client disconnect); detached work uses `context.WithoutCancel`.
Registry: `st.Agents.ForServer(ctx, id)`, `.ForServerOrLocal(ctx, *id)`,
`.Local() *AgentClient`, `.LocalServerID() *uuid.UUID`, `.SetLocalServerID`,
`.Invalidate(id)`, `.OnlineServerIDs(ctx) []AgentServerRef{ID, IsLocal}`,
`.OnlineFleet(ctx) []AgentFleetMember{ID, UserID, Name, IsLocal, Agent}`,
`.JWTSecret()`. `AgentEnsureLocalServer`, `AgentDBRestoreTimeoutSecs`,
`AgentDrillTimeoutSecs`. `_, local := h.(*AgentClient)` matches
`AgentHandle::Local`.

**Secrets** (`svc_secrets_crypto.go`, fully ported): `SecretsCryptoEncrypt`,
`…Decrypt`, `…EncryptCredential`, `…DecryptCredential`, `…DecryptVault`,
`…ReencryptCredential`, `…ReencryptVault`, `…DecryptCredentialOrLegacy`,
`…DecryptCredentialFromEnv`, `…VaultKeySources`, `…VaultKeyPrimary`,
`…DeriveBackupEncryptionKeyV2`.

**Helpers** (`core_helpers.go`, `core_router.go`): `SiteCallerPredicate`,
`StackCallerPredicate`, `siteDomainForCaller`, `siteAgentForCaller`,
`agentForSiteServer`, `siteIDForOwnedDomain`, `AssignableRoles` (from
routes/users.rs — rt_users uses it), `suspendAccount`, `roleToRestore`,
`unsuspendAccount`, `hashAgentToken`, `cfHeaders(token, *email) http.Header`,
`validateURLNotInternal(ctx, url) error`, `validateHostNotInternal`,
`validateRepoURLNotInternal`, `urlAuthority`, `resolveValidated`,
`hostResolvesInternalBlocking`, `validatingDialContext` (Rust
`ValidatingResolver`: set it as an `http.Transport.DialContext`),
`pinnedTransport(ctx, host, port)` (Rust `pinned_client`: build your
`http.Client` around it), `panelIPAllowed`, `validPanelIPEntry`,
`detectPublicIP(ctx)`, `detectPublicIPCached`, `publicIPForServer`,
`parseAgentCertExpiry`, `DNS01LastResortDays`, `dns01LastResortDays`,
`renewalPlan` → `RenewalPlan{Kind: RenewHTTP01|RenewDNS01|RenewRefuse|
RenewLastResortHTTP01, …}`, `certProvenance` → `CertProvenance{Kind:
CertForeign|CertDockPanelIssued|CertUnknown, Issuer}`, `foreignCertIssuer`,
`requireLocalAgentScope`, `WebhookAttemptLimit`, `isValidDomain`,
`isReservedDomain`, `isReservedDomainFor(domain, r)`, `isSafeHeaderValue`,
`isValidName`, `isValidContainerID`, `isSafeRelativePath`,
`isSafeShellCommand(cmd) string`, `composeImages`,
`composeServicesWithoutImage`, `validateComposeYAML(y) string`,
`isSafeNginxConfig(c) string` (the three `-> Result<(), &str>` validators
return the message, `""` = ok). Child processes: `safeCommand(ctx, bin,
args...)` only.

## Background services and startup hooks

`Serve` (core_state.go) calls these predicted names — currently commented
TODOs, in main.rs order. Implement them with exactly these signatures (ctx is
the shutdown signal; return when it is cancelled; the supervisor restarts on
return/panic):

`BackupSchedulerRun(ctx, db *pgxpool.Pool, agents *AgentRegistry, jwtSecret string)`,
`ServerMonitorRun(ctx, db)`, `UptimeRun(ctx, db)`,
`SecurityScannerRun(ctx, db, agents)`, `ImageScannerRun(ctx, db, agents)`,
`WpVulnScannerRun(ctx, db, agents)`, `AlertEngineRun(ctx, db, agents)`,
`AutoHealerRun(ctx, db, agents)`, `MetricsCollectorRun(ctx, db, agents)`,
`DeploySchedulerRun(ctx, db, agents)`, `PreviewCleanupRun(ctx, db, agents)`,
`BackupVerifierRun(ctx, db, agents)`,
`BackupPolicyExecutorRun(ctx, db, agents, jwtSecret string)`,
`DrillSchedulerRun(ctx, db, agents)`,
`TrafficAccountingSchedulerRun(ctx, db, agents)`,
`TelemetryCollectorRun(ctx, db, agents)`.
Startup: `NotificationsInitNotifBroadcast(*Broadcast[PanelNotification])`,
`PanelUpdateFinalizePendingOnStartup(ctx, db)`,
`rtMigrationFinalizeAnalyzingOnStartup(ctx, db)`, `StatusNoticesStartWorker(db)`.
`--emit-guidance`: `PrerequisitesCopyManual() string`,
`PrerequisitesCopyFrontendModule() string`.
`env!("CARGO_PKG_VERSION")` → `Version`.

## Process rules for parallel workers

- Touch ONLY your `rt_<m>.go`/`svc_<m>.go` (+ tests). Never edit `go.mod`,
  `core_*.go`, `svc_agent.go`, `svc_secrets_crypto.go`, `PORTING.md` or
  another worker's files; need a change there → say so in your report.
- The package will not compile until every worker is done. Check with
  `gofmt -l ./internal/api` and `GOOS=linux go vet ./internal/api/`, treating
  ONLY `undefined: <name>` for names another module owns as acceptable.
- Tests (once it compiles): `docker run --rm -v "$PWD/../..":/src -v
  dp-gomod:/go/pkg/mod -w /src/panel/go golang:1.26 go test ./internal/api/...`;
  DB tests need `DATABASE_URL` (see `core_db_integration_test.go`).
- Report (≤400 words): files, registrar name, every cross-module call you
  assumed (name + signature), behaviour you could not port faithfully, test counts.
