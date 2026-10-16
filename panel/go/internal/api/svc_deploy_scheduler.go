package api

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

// DeploySchedulerRun is the background service that checks for scheduled git
// deploys and triggers them.
func DeploySchedulerRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	slog.Info("Deploy scheduler started")

	// Initial delay (15s to let other services start first)
	select {
	case <-time.After(15 * time.Second):
	case <-ctx.Done():
		slog.Info("Deploy scheduler shutting down gracefully (during initial delay)")
		return
	}

	// tokio's interval fires its first tick immediately.
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		deploySchedulerCheckSchedules(ctx, db, agents)
		select {
		case <-ticker.C:
		case <-ctx.Done():
			slog.Info("Deploy scheduler shutting down gracefully")
			return
		}
	}
}

func deploySchedulerCheckSchedules(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	// Get all git deploys with a cron schedule.
	//
	// `server_id` is selected because this query is fleet-wide and always was:
	// it returns every cron deploy on every server, and the row is then acted
	// on by the agent of the ROW's server (until v2.57.0 it was always the
	// LOCAL one). `git_deploys.server_id` is NOT NULL, so there is no
	// ambiguity about which machine a row means.
	deploys, err := queryAll[Tup5[uuid.UUID, string, string, uuid.UUID, uuid.UUID]](ctx, db,
		"SELECT id, name, deploy_cron, user_id, server_id FROM git_deploys WHERE deploy_cron IS NOT NULL AND deploy_cron != '' AND status != 'deploying'")
	if err != nil {
		return
	}

	now := time.Now().UTC()

	for _, d := range deploys {
		id, name, cronExpr, userID, serverID := d.A, d.B, d.C, d.D, d.E
		if !deploySchedulerShouldRun(cronExpr, now) {
			continue
		}
		// Check if we already deployed in the last 59 seconds (prevent double-fire)
		recent, err := queryScalarOpt[int64](ctx, db,
			"SELECT COUNT(*) FROM git_deploy_history WHERE git_deploy_id = $1 AND created_at > NOW() - INTERVAL '59 seconds'", id)
		if err == nil && recent != nil && *recent > 0 {
			continue
		}

		slog.Info(fmt.Sprintf("Scheduled deploy triggered: %s on server %s (cron: %s)", name, serverID, cronExpr))

		// Trigger deploy via the extracted task function. It resolves the
		// agent from the ROW's own server_id and refuses when that server is
		// unreachable, so there is no path back to the local host here.
		rtGitDeploysTriggerDeployTask(ctx, db, agents, id, userID, "scheduled")
	}

	// GAP 58: Check for one-time scheduled deploys
	oneTime, err := queryAll[Tup4[uuid.UUID, string, uuid.UUID, uuid.UUID]](ctx, db,
		"SELECT id, name, user_id, server_id FROM git_deploys "+
			"WHERE scheduled_deploy_at IS NOT NULL "+
			"AND scheduled_deploy_at <= NOW() "+
			"AND status NOT IN ('building', 'deploying')")
	if err != nil {
		return
	}

	for _, d := range oneTime {
		id, name, userID, serverID := d.A, d.B, d.C, d.D
		// Reachability is checked BEFORE the schedule is cleared. A one-time
		// schedule is the operator's only copy of the instruction: clearing it
		// for a server we then decline to deploy to would silently discard it,
		// and unlike a cron row nothing would ever bring it back.
		if _, err := agents.ForServer(ctx, serverID); err != nil {
			slog.Warn(fmt.Sprintf("One-time scheduled deploy for %s (%s) left ARMED: its server "+
				"%s is unreachable (%v). Not deploying, not clearing the schedule.", name, id, serverID, err))
			continue
		}

		slog.Info(fmt.Sprintf("One-time scheduled deploy triggered: %s on server %s", name, serverID))

		// Clear the schedule first (prevent re-trigger). The result is CHECKED:
		// this UPDATE is the only thing standing between a one-time deploy and
		// an unbounded redeploy loop, because a successful run leaves the row
		// `running`, which the SELECT above does not exclude. Swallowing the
		// failure meant a row that could not be cleared redeployed production
		// every 60 seconds, for ever.
		n, err := execSQL(ctx, db, "UPDATE git_deploys SET scheduled_deploy_at = NULL, updated_at = NOW() WHERE id = $1", id)
		if err != nil {
			slog.Warn(fmt.Sprintf("Failed to clear scheduled_deploy_at for deploy %s: %v — NOT deploying, "+
				"because an uncleared schedule redeploys on every tick", id, err))
			continue
		}
		if n != 1 {
			// Another tick or an operator cleared it between the SELECT and
			// here. Whoever cleared it owns the deploy; do not double-fire.
			slog.Info(fmt.Sprintf("One-time deploy %s was already claimed — skipping", id))
			continue
		}

		// Trigger the deploy
		rtGitDeploysTriggerDeployTask(ctx, db, agents, id, userID, "scheduled-once")
	}
}

// deploySchedulerShouldRun is a simple cron check: "M H D M W" (minute hour
// day month weekday). True if `now` matches the cron expression.
func deploySchedulerShouldRun(cronExpr string, now time.Time) bool {
	parts := strings.Fields(cronExpr)
	if len(parts) < 5 {
		return false
	}
	now = now.UTC()
	dow := uint32(now.Weekday()) // %u: 1=Mon … 7=Sun
	if dow == 0 {
		dow = 7
	}
	return deploySchedulerMatchesField(parts[0], uint32(now.Minute())) &&
		deploySchedulerMatchesField(parts[1], uint32(now.Hour())) &&
		deploySchedulerMatchesField(parts[2], uint32(now.Day())) &&
		deploySchedulerMatchesField(parts[3], uint32(now.Month())) &&
		deploySchedulerMatchesField(parts[4], dow)
}

// deploySchedulerParseU32 is Rust's str::parse::<u32> (optional leading '+',
// digits only).
func deploySchedulerParseU32(s string) (uint32, bool) {
	s = strings.TrimPrefix(s, "+")
	if strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil
}

func deploySchedulerMatchesField(field string, value uint32) bool {
	if field == "*" {
		return true
	}
	// Handle */N (every N)
	if step, ok := strings.CutPrefix(field, "*/"); ok {
		if n, ok := deploySchedulerParseU32(step); ok {
			return n > 0 && value%n == 0
		}
	}
	// Handle comma-separated values
	for _, part := range strings.Split(field, ",") {
		// Handle range (e.g., 1-5)
		if startS, endS, isRange := strings.Cut(part, "-"); isRange {
			start, ok1 := deploySchedulerParseU32(startS)
			end, ok2 := deploySchedulerParseU32(endS)
			if ok1 && ok2 && value >= start && value <= end {
				return true
			}
		} else if v, ok := deploySchedulerParseU32(part); ok && v == value {
			return true
		}
	}
	return false
}
