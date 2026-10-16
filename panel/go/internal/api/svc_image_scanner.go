package api

// Port of panel/backend/src/services/image_scanner.rs — background sweeper
// for per-image vulnerability scans. Iterates the deduped set of images used
// by DockPanel-managed containers and rescans any whose newest finding is
// older than the configured interval. Distinct from the security scanner,
// which runs the full-server scan.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	imageScannerCheckInterval = 30 * time.Minute
	imageScannerStartupDelay  = 10 * time.Minute
)

// ImageScannerRun sweeps every online server's images, not just the panel's.
//
// Like the security scanner this asks a MACHINE what it is running, so it
// needs the fleet loop. It once hard-coded the local handle, so a member's
// images were never scanned while the Apps page badged them with whatever the
// panel had found for an image of the same name.
func ImageScannerRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	slog.Info("Image scanner background task started")
	select {
	case <-time.After(imageScannerStartupDelay):
	case <-ctx.Done():
		slog.Info("Image scanner shutting down (initial delay)")
		return
	}
	for {
		for _, m := range agents.OnlineFleet(ctx) {
			if err := imageScannerSweepOnce(ctx, db, m); err != nil {
				slog.Warn(fmt.Sprintf("Image scanner sweep failed on %s: %v", m.Name, err))
			}
		}
		select {
		case <-time.After(imageScannerCheckInterval):
		case <-ctx.Done():
			slog.Info("Image scanner shutting down")
			return
		}
	}
}

func imageScannerSweepOnce(ctx context.Context, db *pgxpool.Pool, m AgentFleetMember) error {
	enabled, _, _, intervalHours, err := rtImageScansReadSettings(ctx, db)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	if !enabled {
		return nil
	}

	// Distinct images from running DockPanel-managed apps.
	apps, err := m.Agent.Get(ctx, "/apps")
	if err != nil {
		return fmt.Errorf("list apps: %w", err)
	}
	arr, ok := jsonArr(apps)
	if !ok {
		return nil
	}
	images := map[string]struct{}{}
	for _, a := range arr {
		if img, ok := jsonStr(jsonGet(a, "image")); ok && img != "" {
			images[img] = struct{}{}
		}
	}
	if len(images) == 0 {
		return nil
	}

	interval := time.Duration(max(intervalHours, 1)) * time.Hour
	for image := range images {
		// Skip if a fresh enough scan exists FOR THIS SERVER. Unscoped, one
		// host's fresh scan of `postgres:16` suppressed the rescan on every
		// other host running it — indefinitely, since the suppressor keeps
		// refreshing itself.
		last, err := queryScalarOpt[time.Time](ctx, db,
			"SELECT scanned_at FROM image_scan_findings WHERE server_id = $1 AND image = $2 "+
				"ORDER BY scanned_at DESC LIMIT 1", m.ID, image)
		if err != nil {
			return fmt.Errorf("read last scan: %w", err)
		}
		// num_seconds() truncates, so compare whole seconds.
		if last != nil && int64(time.Since(*last)/time.Second) < int64(interval/time.Second) {
			continue
		}

		slog.Info(fmt.Sprintf("Image scanner: scanning %s on %s", image, m.Name))
		if _, err := rtImageScansScanAndStore(ctx, db, m.ID, m.Agent, image); err != nil {
			slog.Warn(fmt.Sprintf("Image scan failed for %s on %s: %v", image, m.Name, err))
		}

		// Yield between scans so the agent isn't slammed.
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}
