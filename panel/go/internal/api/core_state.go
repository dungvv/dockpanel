package api

// The AppState from panel/backend/src/main.rs, the supervised background
// spawner, the periodic cleanup task, and the in-process broadcast/provision
// log plumbing (helpers.rs) that tokio::sync::broadcast provided.

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Version is the panel version (Rust: env!("CARGO_PKG_VERSION")). Set at
// build time with -ldflags "-X github.com/ovexro/dockpanel/panel/go/internal/api.Version=…".
var Version = "2.242.1"

// RateWindow is a (count, window_start) rate-limiter entry.
type RateWindow struct {
	Count uint32
	Start time.Time
}

// OAuthState is an OAuth CSRF state entry: provider name + creation time.
type OAuthState struct {
	Provider string
	Created  time.Time
}

// PanelNotification is one real-time panel notification (user id, payload).
type PanelNotification struct {
	UserID  uuid.UUID
	Payload string
}

// AppState is shared by every handler and background service. One per
// process. Module-owned in-process state that Rust also hung off AppState
// (passkey challenge store, panel-update orchestrator state) lives as a
// package-level var in that module's own file instead — see PORTING.md.
type AppState struct {
	DB     *pgxpool.Pool
	Config *Config
	// Agent is the legacy single-agent accessor (local). New code uses Agents.
	Agent *AgentClient
	// Agents dispatches to local or remote agents by server id.
	Agents *AgentRegistry

	LoginMu       sync.Mutex
	LoginAttempts map[string][]time.Time

	// Blacklisted JWT JTIs (logout, revocation). Entries expire naturally
	// after 2h; persisted in token_blacklist so they survive restart.
	blacklistMu    sync.RWMutex
	tokenBlacklist map[string]struct{}

	// 2FA verification attempts: user id → window.
	TwofaMu       sync.Mutex
	TwofaAttempts map[uuid.UUID]RateWindow
	// Deploy webhooks: site/deploy id → failed-attempt window.
	WebhookMu       sync.Mutex
	WebhookAttempts map[uuid.UUID]RateWindow
	// Agent endpoints: server id → request window.
	AgentRateMu     sync.Mutex
	AgentRateLimits map[uuid.UUID]RateWindow

	// Provisioning logs + their owners (Rust provision_logs + deploy_owners).
	ProvisionLogs *ProvisionLogs

	OAuthMu     sync.Mutex
	OAuthStates map[string]OAuthState

	// Real-time panel notification delivery (SSE).
	Notif *Broadcast[PanelNotification]

	// Cached sessions_revoked_at (epoch seconds): tokens with iat before it
	// are rejected. Updated when an admin calls revoke-all; avoids a DB query
	// per request.
	revokedMu sync.RWMutex
	revokedAt *int64

	// Shutdown is cancelled the instant SIGINT/SIGTERM arrives (the Rust
	// shutdown_tx broadcast). Background services get it as their ctx; every
	// handler that holds a connection open past one request/response (the
	// metrics websocket, every SSE stream) must also select on
	// Shutdown.Done(), or the graceful drain waits on a client that never
	// disconnects (helpers::shutdown_signal_fut).
	Shutdown context.Context
}

// NewAppState builds the state with empty in-memory maps.
func NewAppState(db *pgxpool.Pool, cfg *Config, agent *AgentClient, agents *AgentRegistry, shutdown context.Context) *AppState {
	return &AppState{
		DB: db, Config: cfg, Agent: agent, Agents: agents,
		LoginAttempts:   map[string][]time.Time{},
		tokenBlacklist:  map[string]struct{}{},
		TwofaAttempts:   map[uuid.UUID]RateWindow{},
		WebhookAttempts: map[uuid.UUID]RateWindow{},
		AgentRateLimits: map[uuid.UUID]RateWindow{},
		ProvisionLogs:   NewProvisionLogs(),
		OAuthStates:     map[string]OAuthState{},
		Notif:           NewBroadcast[PanelNotification](256),
		Shutdown:        shutdown,
	}
}

func (st *AppState) isBlacklisted(jti string) bool {
	st.blacklistMu.RLock()
	defer st.blacklistMu.RUnlock()
	_, ok := st.tokenBlacklist[jti]
	return ok
}

// blacklistAdd adds JTIs to the in-memory blacklist (callers persist them).
func (st *AppState) blacklistAdd(jtis ...string) {
	st.blacklistMu.Lock()
	for _, j := range jtis {
		st.tokenBlacklist[j] = struct{}{}
	}
	st.blacklistMu.Unlock()
}

func (st *AppState) blacklistLen() int {
	st.blacklistMu.RLock()
	defer st.blacklistMu.RUnlock()
	return len(st.tokenBlacklist)
}

func (st *AppState) blacklistReplace(jtis []string) {
	m := make(map[string]struct{}, len(jtis))
	for _, j := range jtis {
		m[j] = struct{}{}
	}
	st.blacklistMu.Lock()
	st.tokenBlacklist = m
	st.blacklistMu.Unlock()
}

func (st *AppState) sessionsRevokedAt() (int64, bool) {
	st.revokedMu.RLock()
	defer st.revokedMu.RUnlock()
	if st.revokedAt == nil {
		return 0, false
	}
	return *st.revokedAt, true
}

// setSessionsRevokedAt updates the cache (revoke-all, Panic Button).
func (st *AppState) setSessionsRevokedAt(ts int64) {
	st.revokedMu.Lock()
	st.revokedAt = &ts
	st.revokedMu.Unlock()
}

// LoadPersistedAuthState loads the token blacklist and sessions_revoked_at
// from the DB at startup (GAP 66: both survive restart).
func (st *AppState) LoadPersistedAuthState(ctx context.Context) {
	jtis, _ := queryAll[string](ctx, st.DB, "SELECT jti FROM token_blacklist WHERE expires_at > NOW()")
	if len(jtis) > 0 {
		st.blacklistReplace(jtis)
		slog.Info(fmt.Sprintf("Loaded %d blacklisted tokens from DB", len(jtis)))
	}
	v, _ := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'sessions_revoked_at'")
	if v != nil {
		if t, err := time.Parse(time.RFC3339Nano, *v); err == nil {
			st.setSessionsRevokedAt(t.Unix())
			slog.Info("Loaded sessions_revoked_at from DB")
		}
	}
}

// ── Broadcast (tokio::sync::broadcast) ─────────────────────────────────────

// Broadcast fans a value out to every current subscriber. Like tokio's
// channel, a slow subscriber does not block the sender: when its buffer is
// full the value is dropped for that subscriber (tokio reports Lagged and
// skips ahead — the observable effect is the same, missed values).
type Broadcast[T any] struct {
	mu     sync.Mutex
	cap    int
	subs   map[chan T]struct{}
	closed bool
}

func NewBroadcast[T any](capacity int) *Broadcast[T] {
	return &Broadcast[T]{cap: capacity, subs: map[chan T]struct{}{}}
}

// Subscribe returns a receive channel (closed when the broadcast closes) and
// an unsubscribe func the caller must defer.
func (b *Broadcast[T]) Subscribe() (<-chan T, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan T, b.cap)
	if b.closed {
		close(ch)
		return ch, func() {}
	}
	b.subs[ch] = struct{}{}
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
	}
}

// Send delivers v to every subscriber; returns how many received it.
func (b *Broadcast[T]) Send(v T) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for ch := range b.subs {
		select {
		case ch <- v:
			n++
		default:
		}
	}
	return n
}

// Close ends every subscriber's stream (dropping the last tokio Sender).
func (b *Broadcast[T]) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for ch := range b.subs {
		close(ch)
	}
	b.subs = nil
}

// ── Provisioning-log access control (helpers.rs) ───────────────────────────
//
// provision_logs is one process-wide map shared by nine unrelated features
// (service/mail installs, system updates, site provisioning, backups and
// restores, migration imports, container deploys, git deploys, rollbacks) —
// a single flat keyspace, so any endpoint that looks a caller-supplied uuid up
// in it could reach every other feature's stream unless it proved ownership
// itself. Five endpoints did that five different ways and the two weakest
// were open: any signed-in account could read another tenant's site
// provisioning stream, which carries a generated CMS admin password in
// cleartext for the couple of minutes the install takes. So ownership stops
// being each caller's job: a log cannot be created without an owner, and
// cannot be read except by that owner. (One mutex guards both maps, so the
// Rust logs-then-owners lock order is trivially kept.)

// ProvisionStep is a single provisioning step event (routes::sites::ProvisionStep).
type ProvisionStep struct {
	Step    string  `json:"step"`
	Label   string  `json:"label"`
	Status  string  `json:"status"` // "pending", "in_progress", "done", "error"
	Message *string `json:"message,omitempty"`
}

type provisionLog struct {
	history []ProvisionStep
	tx      *Broadcast[ProvisionStep]
	created time.Time
}

// ProvisionLogs is the id → (history, live channel, created) map plus its
// id → owner table.
type ProvisionLogs struct {
	mu     sync.Mutex
	logs   map[uuid.UUID]*provisionLog
	owners map[uuid.UUID]uuid.UUID
}

func NewProvisionLogs() *ProvisionLogs {
	return &ProvisionLogs{logs: map[uuid.UUID]*provisionLog{}, owners: map[uuid.UUID]uuid.UUID{}}
}

// Register creates a log and records its owner. capacity is the channel
// depth: fine-grained emitters (apt line-by-line) need far more than a dozen
// steps. Returns nothing on purpose — every feature emits through the map, so
// the terminal Remove actually closes every reader.
func (p *ProvisionLogs) Register(id, owner uuid.UUID, capacity int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.logs[id]; ok {
		old.tx.Close()
	}
	p.logs[id] = &provisionLog{tx: NewBroadcast[ProvisionStep](capacity), created: time.Now()}
	p.owners[id] = owner
}

// Emit appends a step to the history and sends it live. false when the log
// is gone (evicted or removed) — the step goes nowhere, as in Rust.
func (p *ProvisionLogs) Emit(id uuid.UUID, step ProvisionStep) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.logs[id]
	if !ok {
		return false
	}
	l.history = append(l.history, step)
	l.tx.Send(step)
	return true
}

// Remove drops the log (closing every reader) but keeps the owner row until
// the cleanup sweep, exactly like `logs.remove(&id)` in the features.
func (p *ProvisionLogs) Remove(id uuid.UUID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l, ok := p.logs[id]; ok {
		l.tx.Close()
		delete(p.logs, id)
	}
}

// Forget drops a log AND its owner — for callers that discard a log outright
// (deleting the migration it belongs to).
func (p *ProvisionLogs) Forget(id uuid.UUID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l, ok := p.logs[id]; ok {
		l.tx.Close()
		delete(p.logs, id)
	}
	delete(p.owners, id)
}

// Has reports whether a log is live.
func (p *ProvisionLogs) Has(id uuid.UUID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.logs[id]
	return ok
}

// Open resolves a log for caller: the history so far plus a live channel
// (and its unsubscribe). An id with no recorded owner is refused — a feature
// that adds a log without Register gets a stream nobody can read, which its
// author notices on the first run. "Not yours" and "no such log" return the
// same 404, or the endpoint is an oracle for which uuids are live jobs.
func (p *ProvisionLogs) Open(id, caller uuid.UUID, missing string) ([]ProvisionStep, <-chan ProvisionStep, func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	owner, owned := p.owners[id]
	l, ok := p.logs[id]
	if !ok || !owned || owner != caller {
		return nil, nil, nil, apiErr(404, missing)
	}
	ch, unsub := l.tx.Subscribe()
	return append([]ProvisionStep(nil), l.history...), ch, unsub, nil
}

// sweep evicts logs older than ttl and prunes owners whose log is gone.
func (p *ProvisionLogs) sweep(now time.Time, ttl time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, l := range p.logs {
		if now.Sub(l.created) >= ttl {
			l.tx.Close()
			delete(p.logs, id)
		}
	}
	for id := range p.owners {
		if _, ok := p.logs[id]; !ok {
			delete(p.owners, id)
		}
	}
}

// ── Supervised background tasks ────────────────────────────────────────────

// spawnSupervised runs f in a goroutine, restarting it with exponential
// backoff (1s doubling to 300s, reset after a 60s healthy run) when it
// returns or panics, until ctx (the shutdown signal) is cancelled.
func spawnSupervised(ctx context.Context, name string, f func(ctx context.Context)) {
	go func() {
		delay := time.Second
		const maxDelay = 300 * time.Second
		const healthy = 60 * time.Second
		for {
			started := time.Now()
			done := make(chan any, 1)
			go func() {
				defer func() { done <- recover() }()
				f(ctx)
			}()
			select {
			case p := <-done:
				if p != nil {
					slog.Error(fmt.Sprintf("Background task '%s' panicked: %v", name, p))
				} else {
					slog.Warn(fmt.Sprintf("Background task '%s' exited", name))
				}
				if time.Since(started) >= healthy {
					delay = time.Second
				}
				if ctx.Err() != nil {
					return
				}
				slog.Info(fmt.Sprintf("Restarting '%s' in %ds (backoff)", name, int(delay.Seconds())))
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
				delay = min(delay*2, maxDelay)
			case <-ctx.Done():
				slog.Info(fmt.Sprintf("Supervisor for '%s' received shutdown signal", name))
				return
			}
		}
	}()
}

// runCleanup is the 15-minute janitor for the token blacklist and every
// in-memory rate limiter / channel map.
func runCleanup(ctx context.Context, st *AppState) {
	t := time.NewTicker(900 * time.Second)
	defer t.Stop()
	for {
		// tokio::time::interval fires immediately, then every period.
		st.cleanupOnce(ctx, time.Now())
		select {
		case <-t.C:
		case <-ctx.Done():
			slog.Info("Cleanup task shutting down gracefully")
			return
		}
	}
}

func (st *AppState) cleanupOnce(ctx context.Context, now time.Time) {
	// Token blacklist: past 10000 entries, purge expired rows and reload.
	if n := st.blacklistLen(); n > 10000 {
		_, _ = execSQL(ctx, st.DB, "DELETE FROM token_blacklist WHERE expires_at <= NOW()")
		active, _ := queryAll[string](ctx, st.DB, "SELECT jti FROM token_blacklist WHERE expires_at > NOW()")
		st.blacklistReplace(active)
		slog.Info(fmt.Sprintf("Token blacklist cleaned: %d -> %d entries (reloaded from DB)", n, len(active)))
	}

	st.LoginMu.Lock()
	for k, ts := range st.LoginAttempts {
		kept := ts[:0]
		for _, t := range ts {
			if now.Sub(t) < 15*time.Minute {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(st.LoginAttempts, k)
		} else {
			st.LoginAttempts[k] = kept
		}
	}
	st.LoginMu.Unlock()

	st.TwofaMu.Lock()
	for k, w := range st.TwofaAttempts {
		if now.Sub(w.Start) >= 5*time.Minute {
			delete(st.TwofaAttempts, k)
		}
	}
	st.TwofaMu.Unlock()

	// The webhook limiter's window is an HOUR, not five minutes: both webhook
	// handlers roll a 3600s window and promise "max 10 attempts per hour", but
	// this janitor once shared the 2FA line and evicted after 300s, so a
	// caller got a fresh 10 every ~15 minutes. Retaining for an hour on an
	// UNAUTHENTICATED route (the pre-check inserts an entry keyed on a
	// caller-supplied UUID) is paired with a cap: a flood of invented ids parks
	// at count 0, so dropping zero-count entries above the cap sheds exactly
	// the flood and keeps every counter near its limit.
	st.WebhookMu.Lock()
	for k, w := range st.WebhookAttempts {
		if now.Sub(w.Start) >= time.Hour {
			delete(st.WebhookAttempts, k)
		}
	}
	if len(st.WebhookAttempts) > 10_000 {
		for k, w := range st.WebhookAttempts {
			if w.Count < WebhookAttemptLimit {
				delete(st.WebhookAttempts, k)
			}
		}
	}
	st.WebhookMu.Unlock()

	st.AgentRateMu.Lock()
	for k, w := range st.AgentRateLimits {
		if now.Sub(w.Start) >= 60*time.Second {
			delete(st.AgentRateLimits, k)
		}
	}
	st.AgentRateMu.Unlock()

	// Provisioning logs: the window must outlast the LONGEST job writing into
	// the map, because eviction silently detaches it (every remaining step,
	// including the terminal one, goes nowhere and the watching page waits for
	// a "complete" that can never be sent). A migration import budgets 300s
	// per site and 600s per database; an hour covers all of them. The owner
	// prune runs on EVERY tick, not only when this TTL evicted something —
	// features remove their own log 30-60s after the job, so a conditional
	// prune almost never ran and the owner map grew for the process lifetime.
	st.ProvisionLogs.sweep(now, time.Hour)

	// OAuth CSRF states older than 10 minutes.
	st.OAuthMu.Lock()
	for k, s := range st.OAuthStates {
		if now.Sub(s.Created) >= 10*time.Minute {
			delete(st.OAuthStates, k)
		}
	}
	st.OAuthMu.Unlock()
}

// ── Startup (main.rs) ──────────────────────────────────────────────────────

// EmitGuidance writes the generated guidance artefacts and returns
// (`dockpanel-api --emit-guidance <repo-root>`). The manual is *emitted* by
// the product rather than written alongside it, so the shipped binary can
// print its own documentation; guidance_manual_is_current fails when the
// committed files differ, which makes drift impossible rather than discouraged.
func EmitGuidance(root string) error {
	manual := filepath.Join(root, "docs/guides/prerequisites.md")
	module := filepath.Join(root, "panel/frontend/src/content/guidance.generated.ts")
	if err := os.MkdirAll(filepath.Dir(module), 0o755); err != nil {
		return err
	}
	// TODO(integration): uncomment once svc_prerequisites.go exists.
	// if err := os.WriteFile(manual, []byte(PrerequisitesCopyManual()), 0o644); err != nil {
	// 	return err
	// }
	// if err := os.WriteFile(module, []byte(PrerequisitesCopyFrontendModule()), 0o644); err != nil {
	// 	return err
	// }
	// fmt.Println("wrote " + manual)
	// fmt.Println("wrote " + module)
	// return nil
	return fmt.Errorf("guidance generation not ported yet (would write %s and %s)", manual, module)
}

// gracefulShutdownTimeout bounds the drain after a shutdown signal: a 78%
// cut from systemd's default 90s TimeoutStopSec — short enough to be a real
// bound, long enough that an ordinary slow request (agent calls carry up to
// 60s) isn't routinely cut off during a deploy.
const gracefulShutdownTimeout = 20 * time.Second

// connectDB connects with retry: the DB container may not be ready yet.
func connectDB(cfg *Config) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("Invalid DATABASE_URL: %w", err)
	}
	pc.MaxConns = int32(cfg.DBMaxConnections)
	pc.MinConns = 2
	// Slow-query logging (log_min_duration_statement) belongs in
	// postgresql.conf, not per connection; set it to 1000ms in production.
	pc.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET statement_timeout = '30000'")
		return err
	}
	const maxRetries = 5
	const retryDelay = 3 * time.Second
	for retries := 1; ; retries++ {
		pool, err := pgxpool.NewWithConfig(context.Background(), pc)
		if err == nil {
			// pgxpool connects lazily; Ping is the connect sqlx performed
			// (bounded like its 5s acquire_timeout).
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = pool.Ping(ctx)
			cancel()
			if err == nil {
				return pool, nil
			}
			pool.Close()
		}
		if retries >= maxRetries {
			return nil, fmt.Errorf("Failed to connect to database after %d attempts: %v", retries, err)
		}
		slog.Warn(fmt.Sprintf("Database not ready (attempt %d/%d): %v, retrying in %ds...", retries, maxRetries, err, int(retryDelay.Seconds())))
		time.Sleep(retryDelay)
	}
}

// Serve is main.rs after config: connect, migrate, build state, start the
// background services, serve until SIGINT/SIGTERM, drain, close the pool.
func Serve(cfg *Config) error {
	db, err := connectDB(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	migs, err := EmbeddedMigrations()
	if err == nil {
		err = RunMigrations(context.Background(), db, migs, true)
	}
	if err != nil {
		return fmt.Errorf("Failed to run database migrations: %w", err)
	}
	slog.Info("Database connected and migrations applied")

	agent := NewAgentClient(cfg.AgentSocket, cfg.AgentToken)
	agents := NewAgentRegistry(agent, db, cfg.JWTSecret)
	localID, err := AgentEnsureLocalServer(context.Background(), db, cfg.AgentToken, cfg.JWTSecret)
	if err != nil {
		return err
	}
	if localID != uuid.Nil {
		agents.SetLocalServerID(localID)
		slog.Info("Local server ID: " + localID.String())
	}

	// The shutdown broadcast: every background service and every long-lived
	// route handler watches this context.
	shutdown, cancelShutdown := context.WithCancel(context.Background())
	defer cancelShutdown()

	st := NewAppState(db, cfg, agent, agents, shutdown)
	// TODO(integration): register the broadcast so notify_panel() can send
	// without AppState.
	// NotificationsInitNotifBroadcast(st.Notif)
	st.LoadPersistedAuthState(context.Background())

	// TODO(integration): startup finalizers, in this order.
	// Phase 4 W4: close out in-flight panel-update rows from a previous
	// process lifetime (the api dies mid-binary-swap).
	// PanelUpdateFinalizePendingOnStartup(context.Background(), db)
	// Same argument, one table over: a restart takes running migration
	// analyses/imports with it, so any row still claiming to run is stale.
	// rtMigrationFinalizeAnalyzingOnStartup(context.Background(), db)

	// TODO(integration): status-page subscriber fan-out worker. Started here,
	// not from a service loop, because BOTH the uptime monitor and the
	// incidents handlers feed it and a request can arrive first. Idempotent.
	// StatusNoticesStartWorker(db)

	// TODO(integration): background services, in main.rs order. Each
	// <M>Run(ctx, …) returns when ctx (shutdown) is cancelled.
	// The scheduler decrypts DB credentials for site backups, so it needs
	// the restore path's secret; fleet-wide, so it gets the registry.
	// spawnSupervised(shutdown, "backup_scheduler", func(ctx context.Context) { BackupSchedulerRun(ctx, db, agents, cfg.JWTSecret) })
	// spawnSupervised(shutdown, "server_monitor", func(ctx context.Context) { ServerMonitorRun(ctx, db) })
	// spawnSupervised(shutdown, "uptime_monitor", func(ctx context.Context) { UptimeRun(ctx, db) })
	// Both scanners take a MACHINE as their subject: they sweep the fleet.
	// spawnSupervised(shutdown, "security_scanner", func(ctx context.Context) { SecurityScannerRun(ctx, db, agents) })
	// spawnSupervised(shutdown, "image_scanner", func(ctx context.Context) { ImageScannerRun(ctx, db, agents) })
	// spawnSupervised(shutdown, "wp_vuln_scanner", func(ctx context.Context) { WpVulnScannerRun(ctx, db, agents) })
	// GPU, service-health and container checks run per online server.
	// spawnSupervised(shutdown, "alert_engine", func(ctx context.Context) { AlertEngineRun(ctx, db, agents) })
	// The healer gets the REGISTRY and nothing else: the two legs that once
	// took the local client acted on the wrong machine.
	// spawnSupervised(shutdown, "auto_healer", func(ctx context.Context) { AutoHealerRun(ctx, db, agents) })
	// Reads every online server through its OWN agent (metrics_history).
	// spawnSupervised(shutdown, "metrics_collector", func(ctx context.Context) { MetricsCollectorRun(ctx, db, agents) })
	// spawnSupervised(shutdown, "deploy_scheduler", func(ctx context.Context) { DeploySchedulerRun(ctx, db, agents) })
	// spawnSupervised(shutdown, "preview_cleanup", func(ctx context.Context) { PreviewCleanupRun(ctx, db, agents) })
	// spawnSupervised(shutdown, "backup_verifier", func(ctx context.Context) { BackupVerifierRun(ctx, db, agents) })
	// spawnSupervised(shutdown, "backup_policy_executor", func(ctx context.Context) { BackupPolicyExecutorRun(ctx, db, agents, cfg.JWTSecret) })
	// A drill restores a backup on the server that owns it.
	// spawnSupervised(shutdown, "drill_scheduler", func(ctx context.Context) { DrillSchedulerRun(ctx, db, agents) })
	// spawnSupervised(shutdown, "traffic_accounting_scheduler", func(ctx context.Context) { TrafficAccountingSchedulerRun(ctx, db, agents) })
	// Local BY INTENT: it diagnoses the panel host itself (agents.Local()).
	// spawnSupervised(shutdown, "telemetry_collector", func(ctx context.Context) { TelemetryCollectorRun(ctx, db, agents) })

	// Periodic cleanup of the token blacklist and rate limiters (15 min).
	spawnSupervised(shutdown, "cleanup", func(ctx context.Context) { runCleanup(ctx, st) })

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("Failed to bind TCP listener: %w", err)
	}
	srv := &http.Server{Handler: NewHandler(st), ReadHeaderTimeout: 30 * time.Second}
	slog.Info(fmt.Sprintf("DockPanel API v%s listening on %s", Version, cfg.ListenAddr))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	select {
	case err := <-served:
		slog.Error(fmt.Sprintf("API server error: %v", err))
	case s := <-sig:
		if s == os.Interrupt {
			slog.Info("Received Ctrl+C, shutting down...")
		} else {
			slog.Info("Received SIGTERM, shutting down...")
		}
		// Broadcast to every background service AND every long-lived handler
		// the instant the signal arrives — not after the drain below, which
		// waits for those same connections; then a subscribed handler has the
		// window below to close itself.
		cancelShutdown()
		// Hard watchdog armed only now that shutdown was requested: an open
		// SSE stream or a stalled cleanup must not hold the process past
		// systemd's TimeoutStopSec.
		go func() {
			time.Sleep(gracefulShutdownTimeout)
			slog.Warn(fmt.Sprintf("Graceful shutdown did not finish within %ds of the shutdown signal (a long-lived connection or a stalled cleanup step is likely still open); forcing exit", int(gracefulShutdownTimeout.Seconds())))
			os.Exit(1)
		}()
		if err := srv.Shutdown(context.Background()); err != nil {
			slog.Error(fmt.Sprintf("API server error: %v", err))
		}
	}

	// Give whatever is still winding down a last moment before the pool
	// closes underneath it.
	time.Sleep(2 * time.Second)
	db.Close()
	slog.Info("Database connection pool closed")
	slog.Info("DockPanel API shut down gracefully")
	return nil
}
