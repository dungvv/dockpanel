package api

// Port of panel/backend/src/services/server_monitor.rs — marks servers offline
// when they stop checking in.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ServerMonitorRun sweeps every 120s (first sweep immediately).
func ServerMonitorRun(ctx context.Context, db *pgxpool.Pool) {
	slog.Info("Server health monitor started")
	t := time.NewTicker(120 * time.Second)
	defer t.Stop()
	for {
		serverMonitorSweep(ctx, db)
		select {
		case <-t.C:
		case <-ctx.Done():
			slog.Info("Server monitor shutting down gracefully")
			return
		}
	}
}

// serverMonitorSweep marks servers offline if last_seen_at > 2 minutes ago.
//
// is_local is exempt, deliberately. last_seen_at is written only by the
// check-in handler, which only a phoning-home MEMBER reaches, so the local
// row's value is NULL — and `NULL < …` is NULL, not true, so this sweep never
// matched it. That accident is now a stated rule: `status = 'online'` is the
// predicate of AgentRegistry.OnlineFleet AND the alert engine's resource
// query, so a two-minute stall in the panel's own agent would otherwise drop
// the panel host out of the security scanner, image scanner, alert engine and
// auto-healer at once. The panel's liveness is not a check-in. (Detecting a
// dead agent BESIDE a live API is deferred scope; it needs its own signal.)
func serverMonitorSweep(ctx context.Context, db *pgxpool.Pool) {
	n, err := execSQL(ctx, db,
		"UPDATE servers SET status = 'offline' "+
			"WHERE status = 'online' AND is_local = false "+
			"AND last_seen_at < NOW() - INTERVAL '2 minutes'")
	if err != nil {
		if ctx.Err() == nil {
			slog.Error(fmt.Sprintf("Server monitor error: %v", err))
		}
		return
	}
	if n > 0 {
		slog.Info(fmt.Sprintf("Marked %d server(s) as offline", n))
	}
}
