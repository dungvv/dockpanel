package api

// Port of panel/backend/src/services/wp_vuln_scanner.rs — background sweeper
// for WordPress vulnerability scans.
//
// Direct peer of image_scanner: iterates every site on every online fleet
// member, detects which are WordPress, and rescans any whose newest finding is
// older than the configured interval. Before this, wordpress::vuln_scan only
// ran when an operator opened a site's toolkit and clicked Scan — a
// critically-vulnerable plugin stayed invisible indefinitely otherwise, unlike
// Docker image scanning, which has carried a schedule and a
// fire_alert/resolve_alert lifecycle all along.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	wpVulnScannerCheckInterval   = 30 * time.Minute
	wpVulnScannerStartupDelay    = 10 * time.Minute
	wpVulnScannerWpDetectTimeout = 5 * time.Second
)

// wpVulnScannerSleep sleeps d or until ctx is cancelled (false).
func wpVulnScannerSleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// WpVulnScannerRun is the background loop; returns when ctx (shutdown) ends.
func WpVulnScannerRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	slog.Info("WordPress vuln scanner background task started")

	if !wpVulnScannerSleep(ctx, wpVulnScannerStartupDelay) {
		slog.Info("WordPress vuln scanner shutting down (initial delay)")
		return
	}

	for {
		for _, member := range agents.OnlineFleet(ctx) {
			if err := wpVulnScannerSweepOnce(ctx, db, member); err != nil {
				slog.Warn(fmt.Sprintf("WordPress vuln scanner sweep failed on %s: %v", member.Name, err))
			}
		}
		if !wpVulnScannerSleep(ctx, wpVulnScannerCheckInterval) {
			slog.Info("WordPress vuln scanner shutting down")
			return
		}
	}
}

func wpVulnScannerSweepOnce(ctx context.Context, db *pgxpool.Pool, member AgentFleetMember) error {
	agent := member.Agent
	enabled, intervalHours, err := rtWordpressReadWpScanSettings(ctx, db)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	if !enabled {
		return nil
	}
	intervalSecs := int64(max(intervalHours, 1)) * 3600

	sites, err := queryAll[Tup3[uuid.UUID, string, uuid.UUID]](ctx, db,
		"SELECT id, domain, user_id FROM sites WHERE server_id = $1 ORDER BY domain", member.ID)
	if err != nil {
		return fmt.Errorf("list sites: %w", err)
	}

	for _, s := range sites {
		siteID, domain, userID := s.A, s.B, s.C
		// Detect WordPress the same way wordpress::all_wp_sites does — a quick,
		// timeout-bounded probe, not an assumption from the site's runtime field
		// (sites are provisioned as generic PHP, WordPress is installed on top).
		dctx, cancel := context.WithTimeout(ctx, wpVulnScannerWpDetectTimeout)
		_, derr := agent.Get(dctx, "/wordpress/"+domain+"/info")
		cancel()
		if derr != nil {
			continue
		}

		last, err := queryScalarOpt[time.Time](ctx, db,
			"SELECT scanned_at FROM wp_vuln_scans WHERE site_id = $1 ORDER BY scanned_at DESC LIMIT 1", siteID)
		if err != nil {
			return fmt.Errorf("read last scan: %w", err)
		}
		if last != nil && int64(time.Since(*last).Seconds()) < intervalSecs {
			continue
		}

		slog.Info(fmt.Sprintf("WordPress vuln scanner: scanning %s on %s", domain, member.Name))
		if _, err := rtWordpressScanAndStore(ctx, db, siteID, userID, domain, agent); err != nil {
			slog.Warn(fmt.Sprintf("WordPress vuln scan failed for %s on %s: %v", domain, member.Name, err))
		}

		// Yield between scans so the agent isn't slammed — mirrors
		// image_scanner's own pacing.
		if !wpVulnScannerSleep(ctx, 5*time.Second) {
			return nil
		}
	}
	return nil
}
