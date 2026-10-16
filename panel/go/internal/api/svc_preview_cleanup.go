package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PreviewCleanupRun is the background task that cleans up expired preview
// environments every 5 minutes.
func PreviewCleanupRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	slog.Info("Preview cleanup service started")

	// tokio's interval fires its first tick immediately.
	ticker := time.NewTicker(300 * time.Second) // 5 minutes
	defer ticker.Stop()
	for {
		if err := previewCleanupCleanupExpiredPreviews(ctx, db, agents); err != nil {
			slog.Warn(fmt.Sprintf("Preview cleanup error: %v", err))
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			slog.Info("Preview cleanup service shutting down")
			return
		}
	}
}

func previewCleanupCleanupExpiredPreviews(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) error {
	// Find expired previews: where updated_at + ttl_hours has passed. Join with
	// git_deploys to get preview_ttl_hours.
	//
	// `d.server_id` comes along for the ride. A preview belongs to exactly one
	// git deploy and that row's `server_id` is NOT NULL, so the JOIN is enough
	// to name the host. Without it the sweep read every server's previews and
	// tore down containers on whichever box the panel runs on: a container
	// name that exists on both hosts is destroyed on the wrong one, and the
	// row is then deleted as if the teardown had worked.
	//
	// `git_previews` also carries its own `server_id` (a unique index cannot
	// reach through a JOIN and the host_port index had to be scoped). The two
	// are written together and `git_deploys.server_id` is immutable, so they
	// cannot disagree; this query keeps reading the deploy's copy, which is
	// the one the teardown's authority derives from.
	expired, err := queryAll[Tup6[uuid.UUID, string, string, *string, int32, uuid.UUID]](ctx, db,
		"SELECT p.id, p.container_name, p.branch, p.domain, p.host_port, d.server_id "+
			"FROM git_previews p "+
			"JOIN git_deploys d ON d.id = p.git_deploy_id "+
			"WHERE p.status = 'running' "+
			"AND d.preview_ttl_hours > 0 "+
			"AND p.updated_at < NOW() - MAKE_INTERVAL(hours => d.preview_ttl_hours)")
	if err != nil {
		return err
	}

	for _, p := range expired {
		id, containerName, branch, domain, hostPort, serverID := p.A, p.B, p.C, p.D, p.E, p.F
		agent, err := agents.ForServer(ctx, serverID)
		if err != nil {
			// Keep the row, exactly as an agent-side failure does below: an
			// unreachable server is a reason to retry, never a reason to tear
			// the container down somewhere else.
			slog.Warn(fmt.Sprintf("Preview %s belongs to server %s, which is "+
				"unreachable (%v) — not cleaning up. Refusing to act on a different host.", containerName, serverID, err))
			continue
		}

		slog.Info(fmt.Sprintf("Cleaning up expired preview: %s (branch: %s) on server %s", containerName, branch, serverID))

		// One door for every preview teardown: it resolves the stored name into
		// the space it was created in, and carries the row's own domain and port
		// so the vhost can still be released when the container is already gone.
		body := rtGitDeploysPreviewCleanupBody(containerName, domain, &hostPort)
		if _, err := agent.Post(ctx, "/git/cleanup", body); err != nil {
			// KEEP THE ROW. It is the only record that this container, this
			// port and this vhost exist — deleting it anyway frees the port for
			// reallocation while the container still holds it, and leaves the
			// container invisible to every list, cleanup and delete path. The
			// sweep runs every five minutes and the agent reports success when
			// the container is already gone, so retrying is cheap and terminates.
			slog.Warn(fmt.Sprintf("Failed to cleanup preview container %s: %v. Keeping the "+
				"git_previews row so the next sweep retries rather than orphaning it.", containerName, err))
			continue
		}

		// Delete the preview record
		if _, err := execSQL(ctx, db, "DELETE FROM git_previews WHERE id = $1", id); err != nil {
			slog.Warn(fmt.Sprintf("Failed to delete preview record %s: %v", id, err))
		}
	}

	if len(expired) > 0 {
		slog.Info(fmt.Sprintf("Cleaned up %d expired previews", len(expired)))
	}

	// Also clean up stuck previews (deploying/failed for > 1 hour).
	//
	// `preview_ttl_hours = 0` is the documented opt-out from automatic preview
	// cleanup, and the TTL loop above honours it. This one once did not join
	// git_deploys at all, so the operator who switched auto-cleanup off still
	// had previews destroyed — an hour after a failed deploy, which is exactly
	// when the container is worth keeping to look at.
	stuck, err := queryAll[Tup5[uuid.UUID, string, *string, int32, uuid.UUID]](ctx, db,
		"SELECT p.id, p.container_name, p.domain, p.host_port, d.server_id FROM git_previews p "+
			"JOIN git_deploys d ON d.id = p.git_deploy_id "+
			"WHERE p.status IN ('deploying', 'failed') "+
			"AND d.preview_ttl_hours > 0 "+
			"AND p.updated_at < NOW() - INTERVAL '1 hour'")
	if err != nil {
		return err
	}

	for _, p := range stuck {
		id, containerName, domain, hostPort, serverID := p.A, p.B, p.C, p.D, p.E
		agent, err := agents.ForServer(ctx, serverID)
		if err != nil {
			slog.Warn(fmt.Sprintf("Stuck preview %s belongs to server %s, which is "+
				"unreachable (%v) — not cleaning up. Refusing to act on a different host.", containerName, serverID, err))
			continue
		}
		body := rtGitDeploysPreviewCleanupBody(containerName, domain, &hostPort)
		if _, err := agent.Post(ctx, "/git/cleanup", body); err != nil {
			slog.Warn(fmt.Sprintf("Failed to cleanup stuck preview container %s: %v. Keeping the "+
				"git_previews row so the next sweep retries rather than orphaning it.", containerName, err))
			continue
		}
		if _, err := execSQL(ctx, db, "DELETE FROM git_previews WHERE id = $1", id); err != nil {
			slog.Warn(fmt.Sprintf("Failed to delete stuck preview record %s: %v", id, err))
		}
	}

	return nil
}
