package api

// Port of panel/backend/src/services/drill_scheduler.rs.
//
// Phase 4 W1.2.d: Drill scheduler — runs every 60s, evaluates per-policy
// drill cron schedules, dispatches end-to-end drills against the latest
// db + volume backup tied to each due policy.
//
// Site backups don't carry `policy_id`, so they're not covered by this
// scheduler — BackupVerifierRun (every 6h) handles passive site verification
// instead. If site policy_id ever lands, this loop should pick up sites with
// no other change.

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type drillSchedulerDuePolicy struct {
	ID            uuid.UUID  `db:"id"`
	Name          string     `db:"name"`
	DrillSchedule string     `db:"drill_schedule"`
	LastDrillAt   *time.Time `db:"last_drill_at"`
	// Fallback host when a backup row carries no server of its own. NULL is
	// the only value the UI can produce (no server picker), so it is resolved
	// to the local server explicitly rather than meaning "whichever box runs
	// the scheduler".
	ServerID *uuid.UUID `db:"server_id"`
}

// DrillSchedulerRun: the policy query is fleet-wide, so this takes the
// REGISTRY — a drill restores a backup on the server that owns it. A drill on
// the wrong host certifies disaster recovery for a machine it never touched,
// and that certification feeds the chain-of-trust compliance report.
func DrillSchedulerRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	slog.Info("Drill scheduler started")
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		if err := drillSchedulerTick(ctx, db, agents); err != nil {
			slog.Error(fmt.Sprintf("Drill scheduler error: %v", err))
		}
		select {
		case <-t.C:
		case <-ctx.Done():
			slog.Info("Drill scheduler shutting down gracefully")
			return
		}
	}
}

func drillSchedulerTick(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) error {
	now := time.Now().UTC()
	policies, err := queryAll[drillSchedulerDuePolicy](ctx, db,
		"SELECT id, name, drill_schedule, last_drill_at, server_id "+
			"FROM backup_policies "+
			"WHERE enabled = TRUE AND drill_enabled = TRUE")
	if err != nil {
		return err
	}
	for i := range policies {
		p := &policies[i]
		if !drillSchedulerCronMatchesNow(p.DrillSchedule, now) {
			continue
		}
		// 90s debounce — same window as backup_policy_executor.
		if p.LastDrillAt != nil && int64(now.Sub(*p.LastDrillAt)/time.Second) < 90 {
			continue
		}
		slog.Info(fmt.Sprintf("Drill schedule due for policy '%s' (%s)", p.Name, p.ID))

		// Stamp last_drill_at only once a drill actually enqueues. Stamping
		// BEFORE dispatch made a policy whose server had been unreachable for
		// weeks read as "freshly drilled" every time its cron fired — the one
		// case a DR timestamp most needs to flag. The double-fire this used to
		// guard against is prevented by drillSchedulerHasRunningDrillForServer's
		// own backup_drills row, inserted synchronously in enqueueDrill.
		if drillSchedulerDispatchPolicyDrills(ctx, db, agents, p) {
			_, _ = execSQL(ctx, db, "UPDATE backup_policies SET last_drill_at = NOW() WHERE id = $1", p.ID)
		}
	}
	return nil
}

// drillSchedulerDispatchPolicyDrills dispatches this policy's db + volume
// drills together.
//
// The guard is consulted ONCE, here, for both legs — load-bearing: consulted
// per leg, the db leg's own `running` row would make the volume leg find the
// drill it had just triggered and return, so volume drills would never run
// again, silently. Checking once per policy keeps the cap (one policy's
// drills in flight per server) without a leg starving its sibling.
func drillSchedulerDispatchPolicyDrills(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, policy *drillSchedulerDuePolicy) bool {
	dbRow, _ := queryOpt[Tup5[uuid.UUID, *uuid.UUID, string, string, string]](ctx, db,
		"SELECT id, server_id, db_type, db_name, filename "+
			"FROM database_backups "+
			"WHERE policy_id = $1 "+
			"ORDER BY created_at DESC LIMIT 1", policy.ID)
	volRow, _ := queryOpt[Tup4[uuid.UUID, *uuid.UUID, string, string]](ctx, db,
		"SELECT id, server_id, container_name, filename "+
			"FROM volume_backups "+
			"WHERE policy_id = $1 "+
			"ORDER BY created_at DESC LIMIT 1", policy.ID)

	if dbRow == nil && volRow == nil {
		slog.Debug(fmt.Sprintf("No backups tied to policy %s; skipping drills", policy.ID))
		return false
	}

	// Which host owns this policy's drills: a backup row's own server_id wins;
	// the policy's is the fallback; with both absent the LOCAL server is named
	// explicitly — naming it is what makes the concurrency guard and the audit
	// row work at all.
	var sid *uuid.UUID
	if dbRow != nil && dbRow.B != nil {
		sid = dbRow.B
	} else if volRow != nil && volRow.B != nil {
		sid = volRow.B
	} else if policy.ServerID != nil {
		sid = policy.ServerID
	} else if l := agents.LocalServerID(); l != nil {
		sid = l
	} else {
		slog.Warn(fmt.Sprintf("Policy %s has no server and the local server id is not yet known "+
			"(setup incomplete) — skipping drills this tick.", policy.ID))
		return false
	}
	serverID := *sid

	agent, err := agents.ForServer(ctx, serverID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Skipping drills for policy %s — server %s is unreachable (%v). "+
			"Not drilling on a different host: a drill that runs elsewhere certifies "+
			"disaster recovery for a machine it never tested.", policy.ID, serverID, err))
		return false
	}

	if drillSchedulerHasRunningDrillForServer(ctx, db, serverID) {
		slog.Info(fmt.Sprintf("Skipping drills for policy %s — another drill is already running on server %s", policy.ID, serverID))
		return false
	}

	dispatched := false
	if dbRow != nil {
		drillSchedulerEnqueueDrill(ctx, db, agent, "database", dbRow.A, serverID,
			map[string]any{"db_type": dbRow.C, "db_name": dbRow.D, "filename": dbRow.E}, "/backups/drill/db")
		dispatched = true
	}
	if volRow != nil {
		drillSchedulerEnqueueDrill(ctx, db, agent, "volume", volRow.A, serverID,
			map[string]any{"container_name": volRow.C, "filename": volRow.D}, "/backups/drill/volume")
		dispatched = true
	}
	return dispatched
}

// drillSchedulerHasRunningDrillForServer: true if a drill is already in
// flight for this server.
//
// The age bound is not cosmetic: the completion UPDATE runs detached with no
// timeout, so a panel restart mid-drill strands a row at `running` forever;
// an unbounded count would let ONE stranded row disable DR verification for
// that machine permanently. A drill "running" for over two hours is not.
func drillSchedulerHasRunningDrillForServer(ctx context.Context, db *pgxpool.Pool, sid uuid.UUID) bool {
	n, err := queryScalar[int64](ctx, db,
		"SELECT COUNT(*) FROM backup_drills "+
			"WHERE server_id = $1 AND status IN ('pending', 'running') "+
			"AND started_at > NOW() - INTERVAL '2 hours'", sid)
	return err == nil && n > 0
}

// drillSchedulerEnqueueDrill inserts a `running` row in backup_drills and
// fires the agent call async. Mirrors the trigger_drill route's shape so
// on-demand and scheduled drills are indistinguishable in the audit trail.
func drillSchedulerEnqueueDrill(ctx context.Context, db *pgxpool.Pool, agent AgentHandle, backupType string,
	backupID, serverID uuid.UUID, body any, agentPath string) {
	// triggered_by NULL = scheduler-fired.
	drillID, err := queryScalar[uuid.UUID](ctx, db,
		"INSERT INTO backup_drills (backup_type, backup_id, server_id, status, started_at) "+
			"VALUES ($1, $2, $3, 'running', NOW()) RETURNING id", backupType, backupID, serverID)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to insert scheduled drill row: %v", err))
		return
	}

	bg := context.WithoutCancel(ctx)
	go func() {
		// Plain Post caps the WHOLE round trip at 60s, but the agent-side
		// restore is budgeted 220-360s — any non-trivial drill was killed by
		// that cap and reported a false DR failure on a healthy backup.
		data, err := agent.PostLong(bg, agentPath, body, AgentDrillTimeoutSecs)
		if err != nil {
			_, _ = execSQL(bg, db,
				"UPDATE backup_drills SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1",
				drillID, err.Error())
			return
		}
		drillSchedulerRecordResult(bg, db, drillID, data)
	}()
}

// drillSchedulerRecordResult writes an agent drill report onto its row.
func drillSchedulerRecordResult(ctx context.Context, db Querier, drillID uuid.UUID, data any) {
	passed, _ := jsonBool(jsonGet(data, "passed"))
	var httpStatus *int32
	if n, ok := jsonI64(jsonGet(data, "http_status")); ok {
		httpStatus = new(int32(n))
	}
	var bodyExcerpt, errorMessage *string
	if s, ok := jsonStr(jsonGet(data, "body_excerpt")); ok {
		bodyExcerpt = &s
	}
	if s, ok := jsonStr(jsonGet(data, "error_message")); ok {
		errorMessage = &s
	}
	durationMs, _ := jsonI64(jsonGet(data, "duration_ms"))
	status := "failed"
	if passed {
		status = "passed"
	}
	_, _ = execSQL(ctx, db,
		"UPDATE backup_drills SET "+
			"status = $2, http_status = $3, body_excerpt = $4, "+
			"error_message = $5, duration_ms = $6, completed_at = NOW() "+
			"WHERE id = $1",
		drillID, status, httpStatus, bodyExcerpt, errorMessage, int32(durationMs))
}

// ── 5-field cron parser (parity with backup_policy_executor) ────────────────

func drillSchedulerCronMatchesNow(schedule string, now time.Time) bool {
	f := strings.Fields(schedule)
	if len(f) != 5 {
		return false
	}
	return drillSchedulerFieldMatches(f[0], now.Minute()) &&
		drillSchedulerFieldMatches(f[1], now.Hour()) &&
		drillSchedulerFieldMatches(f[2], now.Day()) &&
		drillSchedulerFieldMatches(f[3], int(now.Month())) &&
		drillSchedulerFieldMatches(f[4], int(now.Weekday()))
}

func drillSchedulerParseI32(s string) (int, bool) {
	n, err := strconv.ParseInt(s, 10, 32)
	return int(n), err == nil
}

func drillSchedulerFieldMatches(field string, value int) bool {
	if field == "*" {
		return true
	}
	if stripped, ok := strings.CutPrefix(field, "*/"); ok {
		step, ok := drillSchedulerParseI32(stripped)
		return ok && step > 0 && value%step == 0
	}
	for part := range strings.SplitSeq(field, ",") {
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, ok1 := drillSchedulerParseI32(lo)
			h, ok2 := drillSchedulerParseI32(hi)
			if ok1 && ok2 && value >= l && value <= h {
				return true
			}
		} else if n, ok := drillSchedulerParseI32(part); ok && n == value {
			return true
		}
	}
	return false
}
