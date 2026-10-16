package api

// Port of panel/backend/src/services/backup_verifier.rs.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BackupVerifierRun runs the backup verifier — every 6 hours, picks
// unverified backups and verifies them.
//
// Every driving query is fleet-wide, so the verifier gets the REGISTRY: an
// archive is read on the host that wrote it. Verifying a member's backup
// against the panel's disk finds nothing, marks a good archive `failed`, and —
// because the driving queries skip any backup that already has a verification
// row — never looks at it again.
func BackupVerifierRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	slog.Info("Backup verifier started")

	// Initial delay: 5 minutes after startup.
	select {
	case <-time.After(300 * time.Second):
	case <-ctx.Done():
		slog.Info("Backup verifier shutting down (initial delay)")
		return
	}

	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		if err := backupVerifierTick(ctx, db, agents); err != nil {
			slog.Error(fmt.Sprintf("Backup verifier error: %v", err))
		}
		select {
		case <-t.C:
		case <-ctx.Done():
			slog.Info("Backup verifier shutting down gracefully")
			return
		}
	}
}

func backupVerifierTick(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) error {
	// Find policies that have verify_after_backup enabled.
	n, err := queryScalar[int64](ctx, db,
		"SELECT COUNT(*) FROM backup_policies WHERE verify_after_backup = TRUE AND enabled = TRUE")
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}

	// Pick up to 3 unverified site backups (last 7 days). `s.server_id` rides
	// the JOIN this query already makes; it is NOT NULL and a site never
	// moves hosts.
	siteBackups, err := queryAll[Tup4[uuid.UUID, string, string, uuid.UUID]](ctx, db,
		"SELECT b.id, s.domain, b.filename, s.server_id FROM backups b "+
			"JOIN sites s ON s.id = b.site_id "+
			"LEFT JOIN backup_verifications bv ON bv.backup_type = 'site' AND bv.backup_id = b.id "+
			"WHERE bv.id IS NULL AND b.created_at > NOW() - INTERVAL '7 days' "+
			"ORDER BY b.created_at DESC LIMIT 3")
	if err != nil {
		return err
	}
	for _, b := range siteBackups {
		backupVerifierVerifyOne(ctx, db, agents, b.D, "site", b.A, b.B, b.C, nil, nil)
	}

	// Database backups resolve their server through the site that owns the
	// database, not database_backups.server_id: that column is nullable and a
	// policy with no server writes NULL into it.
	dbBackups, err := queryAll[Tup5[uuid.UUID, string, string, string, uuid.UUID]](ctx, db,
		"SELECT db.id, db.db_type, db.db_name, db.filename, s.server_id FROM database_backups db "+
			"JOIN databases d ON d.id = db.database_id "+
			"JOIN sites s ON s.id = d.site_id "+
			"LEFT JOIN backup_verifications bv ON bv.backup_type = 'database' AND bv.backup_id = db.id "+
			"WHERE bv.id IS NULL AND db.created_at > NOW() - INTERVAL '7 days' "+
			"ORDER BY db.created_at DESC LIMIT 3")
	if err != nil {
		return err
	}
	for _, b := range dbBackups {
		backupVerifierVerifyOne(ctx, db, agents, b.E, "database", b.A, b.C, b.D, &b.B, nil)
	}

	// A volume backup has no site to join through, so vb.server_id is the
	// only handle. Rows written before create_volume_backup stopped stamping
	// "some online server" may carry a NULL id; those are skipped.
	volBackups, err := queryAll[Tup4[uuid.UUID, string, string, *uuid.UUID]](ctx, db,
		"SELECT vb.id, vb.container_name, vb.filename, vb.server_id FROM volume_backups vb "+
			"LEFT JOIN backup_verifications bv ON bv.backup_type = 'volume' AND bv.backup_id = vb.id "+
			"WHERE bv.id IS NULL AND vb.created_at > NOW() - INTERVAL '7 days' "+
			"ORDER BY vb.created_at DESC LIMIT 2")
	if err != nil {
		return err
	}
	for _, b := range volBackups {
		if b.D == nil {
			// Deliberately NOT ForServerOrLocal: defaulting an unplaceable row
			// to this host is the wrong-host read being removed. Leaving it
			// unverified keeps it eligible.
			slog.Warn(fmt.Sprintf("Volume backup %s (%s) has no server_id — leaving it "+
				"unverified rather than reading this host's disk for it.", b.A, b.C))
			continue
		}
		backupVerifierVerifyOne(ctx, db, agents, *b.D, "volume", b.A, b.B, b.C, nil, &b.B)
	}

	// "considered", not "verified": an unreachable server's row is skipped.
	if total := len(siteBackups) + len(dbBackups) + len(volBackups); total > 0 {
		slog.Info(fmt.Sprintf("Backup verifier: considered %d backups", total))
	}
	return nil
}

func backupVerifierVerifyOne(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, serverID uuid.UUID,
	backupType string, backupID uuid.UUID, name, filename string, dbType, containerName *string) {
	// Resolve BEFORE inserting the record. A verification row is written
	// 'running' and the driving queries skip any backup that already has one,
	// so a row created for a server we then decline to reach would burn this
	// backup's only chance of ever being verified.
	agent, err := agents.ForServer(ctx, serverID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Not verifying %s backup %s (%s): its server %s is unreachable (%v). "+
			"Leaving it unverified so a later tick can retry, rather than reading this host's disk for another host's archive.",
			backupType, filename, backupID, serverID, err))
		return
	}

	// server_id is bound: the row records which host actually read the archive.
	verifID, err := queryScalar[uuid.UUID](ctx, db,
		"INSERT INTO backup_verifications (backup_type, backup_id, server_id, status, started_at) "+
			"VALUES ($1, $2, $3, 'running', NOW()) RETURNING id", backupType, backupID, serverID)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to create verification record: %v", err))
		return
	}

	var data any
	switch backupType {
	case "site":
		data, err = agent.Post(ctx, "/backups/verify/site", map[string]any{"domain": name, "filename": filename})
	case "database":
		t := "postgres"
		if dbType != nil {
			t = *dbType
		}
		data, err = agent.Post(ctx, "/backups/verify/database", map[string]any{"db_type": t, "db_name": name, "filename": filename})
	case "volume":
		c := name
		if containerName != nil {
			c = *containerName
		}
		data, err = agent.Post(ctx, "/backups/verify/volume", map[string]any{"container_name": c, "filename": filename})
	default:
		return
	}

	if err != nil {
		errMsg := err.Error()
		_, _ = execSQL(ctx, db,
			"UPDATE backup_verifications SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1",
			verifID, errMsg)
		slog.Error(fmt.Sprintf("Verification failed for %s %s: %s", backupType, filename, errMsg))
		return
	}

	passed, _ := jsonBool(jsonGet(data, "passed"))
	checksRun, _ := jsonI64(jsonGet(data, "checks_run"))
	checksPassed, _ := jsonI64(jsonGet(data, "checks_passed"))
	durationMs, _ := jsonI64(jsonGet(data, "duration_ms"))
	details := jsonGet(data, "details")
	if details == nil {
		details = []any{}
	}
	status := "failed"
	if passed {
		status = "passed"
	}
	_, _ = execSQL(ctx, db,
		"UPDATE backup_verifications SET "+
			"status = $2, checks_run = $3, checks_passed = $4, "+
			"details = $5, duration_ms = $6, completed_at = NOW() "+
			"WHERE id = $1",
		verifID, status, int32(checksRun), int32(checksPassed), rtBackupDestinationsJSONArg(details), int32(durationMs))

	if !passed {
		// Fire alert for failed verification.
		if userID, err := queryScalarOpt[uuid.UUID](ctx, db, "SELECT id FROM users WHERE role = 'admin' LIMIT 1"); err == nil && userID != nil {
			NotificationsFireAlert(ctx, db, *userID, nil, nil,
				"backup_verification_failed", "", "warning",
				"Backup verification failed: "+name,
				fmt.Sprintf("The %s backup '%s' for %s failed verification (%d/%d checks passed).",
					backupType, filename, name, int32(checksPassed), int32(checksRun)))
		}
	}
	slog.Info(fmt.Sprintf("Verification %s: %s backup %s for %s", status, backupType, filename, name))
}
