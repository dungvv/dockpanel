package api

// Port of panel/backend/src/services/traffic_accounting_scheduler.rs —
// per-site monthly bandwidth accounting (GH #84): polls each site's agent for
// access-log bytes since the last checkpoint, accumulates a durable monthly
// total in site_traffic_usage, and auto-suspends (then auto-recovers) a site
// against its own bandwidth_quota_mb.
//
// Each site is independent, so one unreachable agent or slow parse never
// blocks the rest of the fleet (same shape as deploy/drill schedulers).

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type trafficAccountingSchedulerSite struct {
	ID                   uuid.UUID  `db:"id"`
	Domain               string     `db:"domain"`
	ServerID             uuid.UUID  `db:"server_id"`
	UserID               uuid.UUID  `db:"user_id"`
	Enabled              bool       `db:"enabled"`
	BandwidthQuotaMB     *int32     `db:"bandwidth_quota_mb"`
	BandwidthSuspendedAt *time.Time `db:"bandwidth_suspended_at"`
}

func trafficAccountingSchedulerMonthKey(t time.Time) string {
	return t.UTC().Format("2006-01")
}

// TrafficAccountingSchedulerRun: 25s initial delay, then every 5 minutes —
// prompt enough to enforce a hard quota without polling every agent's
// filesystem on every fleet tick like the 60s dispatch schedulers.
func TrafficAccountingSchedulerRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	slog.Info("Traffic accounting scheduler started")
	select {
	case <-time.After(25 * time.Second):
	case <-ctx.Done():
		slog.Info("Traffic accounting scheduler shutting down gracefully (during initial delay)")
		return
	}
	t := time.NewTicker(300 * time.Second)
	defer t.Stop()
	for {
		trafficAccountingSchedulerTick(ctx, db, agents)
		select {
		case <-t.C:
		case <-ctx.Done():
			slog.Info("Traffic accounting scheduler shutting down gracefully")
			return
		}
	}
}

func trafficAccountingSchedulerTick(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	sites, err := queryAll[trafficAccountingSchedulerSite](ctx, db,
		"SELECT id, domain, server_id, user_id, enabled, bandwidth_quota_mb, bandwidth_suspended_at "+
			"FROM sites")
	if err != nil {
		slog.Warn("Traffic accounting: failed to list sites: " + err.Error())
		return
	}
	ym := trafficAccountingSchedulerMonthKey(time.Now())
	for i := range sites {
		trafficAccountingSchedulerCollectOne(ctx, db, agents, &sites[i], ym)
	}
}

func trafficAccountingSchedulerCollectOne(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, site *trafficAccountingSchedulerSite, ym string) {
	agent, err := agents.ForServer(ctx, site.ServerID)
	if err != nil {
		return // unreachable this tick; next tick retries
	}
	path := "/nginx/site-traffic-delta/" + site.Domain
	if cp, _ := queryOpt[Tup2[int64, int64]](ctx, db,
		"SELECT log_inode, log_size FROM site_traffic_offsets WHERE site_id = $1", site.ID); cp != nil {
		path = fmt.Sprintf("/nginx/site-traffic-delta/%s?last_inode=%d&last_size=%d", site.Domain, cp.A, cp.B)
	}
	resp, err := agent.Get(ctx, path)
	if err != nil {
		slog.Warn(fmt.Sprintf("Traffic accounting: delta fetch failed for %s: %v", site.Domain, err))
		return
	}
	inode, _ := jsonI64(jsonGet(resp, "inode"))
	size, _ := jsonI64(jsonGet(resp, "size"))
	delta, _ := jsonI64(jsonGet(resp, "delta_bytes"))

	if _, err := execSQL(ctx, db,
		"INSERT INTO site_traffic_offsets (site_id, log_inode, log_size, updated_at) "+
			"VALUES ($1, $2, $3, NOW()) "+
			"ON CONFLICT (site_id) DO UPDATE SET log_inode = $2, log_size = $3, updated_at = NOW()",
		site.ID, inode, size); err != nil {
		slog.Warn(fmt.Sprintf("Traffic accounting: failed to persist checkpoint for %s: %v", site.Domain, err))
	}
	if delta > 0 {
		if _, err := execSQL(ctx, db,
			"INSERT INTO site_traffic_usage (site_id, year_month, bytes_used, updated_at) "+
				"VALUES ($1, $2, $3, NOW()) "+
				"ON CONFLICT (site_id, year_month) DO UPDATE "+
				"SET bytes_used = site_traffic_usage.bytes_used + $3, updated_at = NOW()",
			site.ID, ym, delta); err != nil {
			slog.Warn(fmt.Sprintf("Traffic accounting: failed to accumulate usage for %s: %v", site.Domain, err))
		}
	}

	if site.BandwidthQuotaMB == nil {
		// Quota raised to "unlimited" while still bandwidth-suspended — lift it
		// rather than leaving the site disabled for a limit that no longer exists.
		if site.BandwidthSuspendedAt != nil {
			trafficAccountingSchedulerRecover(ctx, db, agent, site, "quota removed")
		}
		return
	}
	quotaMB := *site.BandwidthQuotaMB
	if site.Enabled && site.BandwidthSuspendedAt == nil {
		used := int64(0)
		if u, err := queryScalarOpt[int64](ctx, db,
			"SELECT bytes_used FROM site_traffic_usage WHERE site_id = $1 AND year_month = $2", site.ID, ym); err == nil && u != nil {
			used = *u
		}
		if used > int64(quotaMB)*1024*1024 {
			trafficAccountingSchedulerSuspend(ctx, db, agent, site, used, quotaMB)
		}
	} else if site.BandwidthSuspendedAt != nil && trafficAccountingSchedulerMonthKey(*site.BandwidthSuspendedAt) != ym {
		trafficAccountingSchedulerRecover(ctx, db, agent, site, "new billing month")
	}
}

func trafficAccountingSchedulerSuspend(ctx context.Context, db *pgxpool.Pool, agent AgentHandle, site *trafficAccountingSchedulerSite, usedBytes int64, quotaMB int32) {
	if _, err := agent.Post(ctx, "/nginx/sites/"+site.Domain+"/disable", nil); err != nil {
		slog.Warn(fmt.Sprintf("Traffic accounting: auto-suspend failed to disable %s at the agent: %v", site.Domain, err))
		return // don't flip DB state if the agent-side disable didn't happen
	}
	if _, err := execSQL(ctx, db,
		"UPDATE sites SET enabled = false, bandwidth_suspended_at = NOW(), updated_at = NOW() WHERE id = $1", site.ID); err != nil {
		slog.Warn(fmt.Sprintf("Traffic accounting: auto-suspend DB update failed for %s: %v", site.Domain, err))
		return
	}
	usedMB := usedBytes / 1024 / 1024
	slog.Warn(fmt.Sprintf("Traffic accounting: auto-suspended %s — %d MB used of %d MB quota", site.Domain, usedMB, quotaMB))
	targetType, details := "site", fmt.Sprintf("%d MB used of %d MB monthly quota", usedMB, quotaMB)
	ActivityLogActivitySystem(ctx, db, "traffic_accounting_scheduler", "site.bandwidth_suspended",
		&targetType, &site.Domain, &details, nil, &site.ServerID)
	link := "/sites/" + site.ID.String()
	NotificationsNotifyPanel(ctx, db, &site.UserID,
		"Site suspended: "+site.Domain,
		fmt.Sprintf("%s exceeded its %d MB monthly bandwidth quota (%d MB used) and has "+
			"been automatically disabled. Raise the quota to restore it immediately, or it "+
			"restores automatically next month.", site.Domain, quotaMB, usedMB),
		"warning", "site", &link)
}

func trafficAccountingSchedulerRecover(ctx context.Context, db *pgxpool.Pool, agent AgentHandle, site *trafficAccountingSchedulerSite, reason string) {
	if _, err := agent.Post(ctx, "/nginx/sites/"+site.Domain+"/enable", nil); err != nil {
		slog.Warn(fmt.Sprintf("Traffic accounting: auto-recovery failed to enable %s at the agent: %v", site.Domain, err))
		return
	}
	if _, err := execSQL(ctx, db,
		"UPDATE sites SET enabled = true, bandwidth_suspended_at = NULL, updated_at = NOW() WHERE id = $1", site.ID); err != nil {
		slog.Warn(fmt.Sprintf("Traffic accounting: auto-recovery DB update failed for %s: %v", site.Domain, err))
		return
	}
	slog.Info(fmt.Sprintf("Traffic accounting: auto-recovered %s (%s)", site.Domain, reason))
	targetType := "site"
	ActivityLogActivitySystem(ctx, db, "traffic_accounting_scheduler", "site.bandwidth_suspension_lifted",
		&targetType, &site.Domain, &reason, nil, &site.ServerID)
	link := "/sites/" + site.ID.String()
	NotificationsNotifyPanel(ctx, db, &site.UserID,
		"Site re-enabled: "+site.Domain,
		fmt.Sprintf("%s has been automatically re-enabled (%s).", site.Domain, reason),
		"info", "site", &link)
}
