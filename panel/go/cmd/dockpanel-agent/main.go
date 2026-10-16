// Command dockpanel-agent is the DockPanel host agent (Go port of
// panel/agent/src/main.rs): a root daemon serving the agent API on a unix
// socket and, optionally, a TLS TCP listener for remote panels.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/moby/moby/client"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/agenttls"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/routes"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

const socketPath = "/var/run/dockpanel/agent.sock"

func main() {
	// --print-unit emits the compiled-in systemd unit and exits. This is how
	// install-agent.sh obtains the unit for a fleet member: the unit travels
	// inside the binary it already downloads, so the two never disagree.
	// Handled before anything else runs.
	args := os.Args[1:]
	for _, a := range args {
		if a == "--print-unit" {
			fmt.Print(services.AgentUnit)
			os.Exit(0)
		}
	}
	// An unrecognised option must be an ERROR, not a daemon: older versions
	// ignored their arguments and bound the agent socket, so
	// `dockpanel-agent --anything` silently started a second agent — and an
	// installer asking an older binary for --print-unit hung for ever. Only
	// `--`-prefixed arguments are judged; bare ones keep their old behaviour.
	for _, a := range args {
		if strings.HasPrefix(a, "--") {
			fmt.Fprintf(os.Stderr, "dockpanel-agent: unknown option '%s'\n", a)
			fmt.Fprintln(os.Stderr, "The only option is --print-unit, which prints the systemd unit and exits.")
			fmt.Fprintln(os.Stderr, "Running it with no arguments starts the agent daemon.")
			os.Exit(2)
		}
	}

	setupLogging()

	for _, d := range []string{
		"/var/run/dockpanel", routes.ConfigDir, "/etc/dockpanel/ssl", "/var/backups/dockpanel",
		"/var/backups/dockpanel/databases", "/var/backups/dockpanel/volumes",
	} {
		_ = os.MkdirAll(d, 0o755)
	}

	// The backup tree is root-only, and this repairs what is already on disk:
	// MkdirAll above made these 0755 and every writer's redirect made files
	// 0644, so on a panel host that also serves sites the panel's own
	// database dump — agent tokens in cleartext — was readable by www-data,
	// the uid every hosted site's PHP runs as.
	services.BackupsSecureBackupTree()
	_ = os.MkdirAll("/var/www/acme/.well-known/acme-challenge", 0o755)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// One-shot idempotent migration: give static vhosts already on disk the
	// denies v2.68.0 added to the template. Nothing re-renders vhosts on
	// upgrade, so an already-switched site keeps serving its PHP source;
	// update.sh carries the same retrofit but an agent-only box never runs it.
	// Awaited deliberately: it must finish before vhost writes are served.
	services.NginxRetrofitStaticDenies(ctx)

	token := loadToken(filepath.Join(routes.ConfigDir, "agent.token"))

	templates := services.NginxInitTemplates()

	// CPU is sampled on its own fixed cadence rather than in handlers — a
	// per-request refresh measures the gap since some unrelated caller, which
	// is how an idle box could report ~99 %.
	cpu := services.NewCpuSampler()
	cpu.Spawn()

	docker, err := client.New(client.FromEnv)
	if err != nil {
		slog.Error("Failed to connect to Docker daemon: " + err.Error())
		os.Exit(1)
	}

	state := routes.NewState(token, templates, cpu, docker)
	handler := routes.Handler(state)

	_ = os.Remove(socketPath) // stale socket
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		slog.Error("Failed to bind Unix socket: " + err.Error())
		os.Exit(1)
	}
	// The socket must be reachable from nginx (www-data on Debian/Ubuntu,
	// nginx on RHEL) for the panel's proxy_pass to unix:.../agent.sock. The
	// unit's ExecStartPost used to do this but occasionally failed silently
	// on rapid restarts, leaving it 0600 root:root; it stays as a backstop.
	for _, name := range []string{"www-data", "nginx"} {
		if g, err := user.LookupGroup(name); err == nil {
			if gid, err := strconv.Atoi(g.Gid); err == nil {
				_ = os.Chown(socketPath, -1, gid) // group only
			}
			break
		}
	}
	_ = os.Chmod(socketPath, 0o660)

	// Load or generate the TLS cert now, so the fingerprint is available for
	// both the inbound TLS listener and the phone-home payload.
	tlsConfig, fingerprint, err := agenttls.LoadOrGenerate()
	if err != nil {
		slog.Error("Failed to load/generate agent TLS cert: " + err.Error())
		os.Exit(1)
	}
	slog.Info("Agent TLS cert fingerprint (SHA-256): " + fingerprint)

	// Bring a pre-existing /webmail/ nginx fragment up to the current
	// template: it is written only on the Install click, so an existing
	// install would otherwise never receive a fix. No-op when not installed.
	go routes.HealWebmailNginx(ctx)

	// Same shape for the agent's OWN unit: only installers write it, so the
	// binary (six-hourly self-update) carries it. No-op when bytes match.
	go services.AgentUnitHeal()

	if cfg := services.PhoneHomeConfigFromEnv(); cfg != nil {
		cfg.CertFingerprint = fingerprint
		go services.PhoneHomeRun(ctx, *cfg, cpu)
	}

	// A member used to ALSO serve the ENTIRE router on plaintext
	// 127.0.0.1:9090 for a command poller that could never execute anything.
	// Both are gone; a member is reached on :9443 with TLS + fingerprint
	// pinning, and locally on the unix socket. Do not reintroduce a plaintext
	// loopback copy of the whole router.

	// Multi-server: AGENT_LISTEN_TCP=0.0.0.0:9443 starts a TLS listener using
	// the self-signed cert; the panel pins its fingerprint on first checkin.
	if tcpAddr, ok := os.LookupEnv("AGENT_LISTEN_TCP"); ok {
		addr, err := netip.ParseAddrPort(tcpAddr)
		if err != nil {
			slog.Error(fmt.Sprintf("AGENT_LISTEN_TCP %s is not a valid socket address: %v", tcpAddr, err))
			os.Exit(1)
		}
		go func() {
			slog.Info(fmt.Sprintf("Agent TLS listener on %s (multi-server remote access)", addr))
			srv := &http.Server{Addr: addr.String(), Handler: handler, TLSConfig: tlsConfig}
			if err := srv.ListenAndServeTLS("", ""); err != nil {
				slog.Error("Multi-server TLS server error: " + err.Error())
			}
		}()
	}

	slog.Info(fmt.Sprintf("DockPanel Agent v%s listening on %s", services.AgentVersion, socketPath))

	srv := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		slog.Info("Received shutdown signal, shutting down...")
		// Like axum's graceful shutdown: stop accepting, wait for in-flight
		// requests with no deadline.
		_ = srv.Shutdown(context.Background())
		close(done)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Agent server error: " + err.Error())
	} else {
		<-done
	}
	slog.Info("DockPanel Agent shut down gracefully")
}

// loadToken prefers AGENT_TOKEN, then the token file, then generates one.
// The file always ends up 0600.
func loadToken(path string) string {
	var token string
	if env := strings.TrimSpace(os.Getenv("AGENT_TOKEN")); env != "" {
		// Sync env token to file so both sources stay consistent.
		_ = os.WriteFile(path, []byte(env), 0o600)
		_ = os.Chmod(path, 0o600)
		slog.Info("Using agent token from AGENT_TOKEN env var")
		token = env
	} else if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) != "" {
		token = strings.TrimSpace(string(b))
	} else {
		token = uuid.NewString()
		if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
			slog.Error("Failed to write agent token: " + err.Error())
			os.Exit(1)
		}
		_ = os.Chmod(path, 0o600)
		slog.Info("Generated new agent token (saved to " + path + ")")
	}
	// Ensure token file permissions are restrictive.
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm() != 0o600 {
		_ = os.Chmod(path, 0o600)
	}
	return token
}

// setupLogging: level from RUST_LOG (kept for unit/env compatibility; a bare
// level like "debug" — directive syntax falls back to info), JSON output when
// LOG_FORMAT=json.
func setupLogging() {
	level := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RUST_LOG"))) {
	case "trace", "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if os.Getenv("LOG_FORMAT") == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}
