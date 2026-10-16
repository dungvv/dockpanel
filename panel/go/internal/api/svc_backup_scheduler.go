package api

// Port of panel/backend/src/services/backup_scheduler.rs.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// backupSchedulerScheduleRow is the join of schedules + destinations + sites.
type backupSchedulerScheduleRow struct {
	ScheduleID     uuid.UUID `db:"schedule_id"`
	SiteID         uuid.UUID `db:"site_id"`
	Domain         string    `db:"domain"`
	Schedule       string    `db:"schedule"`
	RetentionCount int32     `db:"retention_count"`
	// The host that actually holds this site's files. NOT NULL and stable — a
	// site never moves between servers, so resolving the agent from it is safe.
	ServerID uuid.UUID `db:"server_id"`
	// Recorded on the `backups` row when the upload succeeds.
	DestID     *uuid.UUID `db:"dest_id"`
	DestDtype  *string    `db:"dest_dtype"`
	DestConfig any        `db:"dest_config"` // NULL scans as nil = Rust None
}

// BackupSchedulerRun is the backup scheduler loop — checks every 60 seconds
// for due schedules.
//
// The schedule query is fleet-wide, so this takes the REGISTRY: a site is
// backed up on the server that holds its files. Backing a member's site up
// against the panel's own /var/www either fails every night forever or —
// where the same domain legally exists on both hosts — silently archives the
// wrong machine's files and prunes the member's real off-site copies.
func BackupSchedulerRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, jwtSecret string) {
	slog.Info("Backup scheduler started")
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		if err := backupSchedulerTick(ctx, db, agents, jwtSecret); err != nil {
			slog.Error(fmt.Sprintf("Backup scheduler error: %v", err))
		}
		select {
		case <-t.C:
		case <-ctx.Done():
			slog.Info("Backup scheduler shutting down gracefully")
			return
		}
	}
}

func backupSchedulerTick(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, jwtSecret string) error {
	now := time.Now().UTC()

	// Fetch all enabled schedules with their destination and site info.
	rows, err := queryAll[backupSchedulerScheduleRow](ctx, db,
		"SELECT "+
			"bs.id as schedule_id, bs.site_id, s.domain, bs.schedule, bs.retention_count, "+
			"s.server_id, "+
			"bd.id as dest_id, bd.dtype as dest_dtype, bd.config as dest_config "+
			"FROM backup_schedules bs "+
			"JOIN sites s ON s.id = bs.site_id "+
			"LEFT JOIN backup_destinations bd ON bd.id = bs.destination_id "+
			"WHERE bs.enabled = true")
	if err != nil {
		return err
	}

	for i := range rows {
		row := &rows[i]
		if !backupSchedulerCronMatchesNow(row.Schedule, now) {
			continue
		}
		// Check if we already ran this minute (prevent double-runs).
		if last := backupSchedulerGetLastRun(ctx, db, row.ScheduleID); last != nil {
			if int64(now.Sub(*last)/time.Second) < 90 {
				continue
			}
		}

		slog.Info("Running scheduled backup for " + row.Domain)
		runErr := backupSchedulerRunScheduledBackup(ctx, db, agents, jwtSecret, row)

		status := "success"
		if runErr != nil {
			status = "failed"
			slog.Error(fmt.Sprintf("Scheduled backup failed for %s: %v", row.Domain, runErr))
			SystemLogLogEvent(ctx, db, "error", "backup_scheduler",
				"Scheduled backup failed for "+row.Domain, new(runErr.Error()))

			// Fire backup failure alert.
			if userID, err := queryScalarOpt[uuid.UUID](ctx, db, "SELECT user_id FROM sites WHERE id = $1", row.SiteID); err == nil && userID != nil {
				NotificationsFireAlert(ctx, db, *userID, nil, &row.SiteID, "backup_failure", "", "critical",
					"Backup failed: "+row.Domain,
					fmt.Sprintf("Scheduled backup for %s failed: %v", row.Domain, runErr))
			}
		}

		// Update last_run.
		_, _ = execSQL(ctx, db,
			"UPDATE backup_schedules SET last_run = NOW(), last_status = $1, updated_at = NOW() WHERE id = $2",
			status, row.ScheduleID)
	}
	return nil
}

func backupSchedulerGetLastRun(ctx context.Context, db *pgxpool.Pool, scheduleID uuid.UUID) *time.Time {
	v, err := queryScalarOpt[*time.Time](ctx, db, "SELECT last_run FROM backup_schedules WHERE id = $1", scheduleID)
	if err != nil || v == nil {
		return nil
	}
	return *v
}

func backupSchedulerRunScheduledBackup(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, jwtSecret string, row *backupSchedulerScheduleRow) error {
	// Resolve the site's OWN server before anything else. An error here routes
	// into tick's failure arm (failed status, system_log, critical alert) —
	// "refuse out loud". Never fall back to the local agent: the disk
	// pre-flight, the archive, the upload and the prune would all then act on
	// a host that does not hold this site.
	agent, err := agents.ForServer(ctx, row.ServerID)
	if err != nil {
		return fmt.Errorf("server %s is unreachable (%v) — refusing to back up %s on a different host", row.ServerID, err, row.Domain)
	}

	// 0. Pre-flight: check disk space via agent before creating backup.
	if sysInfo, err := agent.Get(ctx, "/system/info"); err == nil {
		diskPct, _ := jsonF64(jsonGet(sysInfo, "disk_usage_pct"))
		if diskPct > 90.0 {
			if userID, err := queryScalarOpt[uuid.UUID](ctx, db, "SELECT user_id FROM sites WHERE id = $1", row.SiteID); err == nil && userID != nil {
				NotificationsFireAlert(ctx, db, *userID, nil, &row.SiteID, "backup_failure", "", "warning",
					"Backup skipped (low disk): "+row.Domain,
					fmt.Sprintf("Scheduled backup for %s was skipped because disk usage is %.1f%% (>90%%). "+
						"Free up disk space to resume automatic backups.", row.Domain, diskPct))
			}
			SystemLogLogEvent(ctx, db, "warning", "backup_scheduler",
				fmt.Sprintf("Backup skipped for %s — disk at %.1f%%", row.Domain, diskPct), nil)
			return fmt.Errorf("Disk usage too high (%.1f%% > 90%%) — backup skipped", diskPct)
		}
	}

	// 1. Create backup via agent — WITH the site's databases. A scheduled
	// backup that quietly omitted them would be the exact defect v2.34.0
	// closed, surviving in the path people rely on most.
	siteDBs := rtBackupsSiteDatabaseSpecs(ctx, db, jwtSecret, row.SiteID)
	dbExpected := int32(siteDBs.Expected())
	agentBody := map[string]any{"databases": siteDBs.Specs}

	backupResult, err := agent.Post(ctx, fmt.Sprintf("/backups/%s/create", row.Domain), agentBody)
	if err != nil {
		return fmt.Errorf("Backup creation failed: %v", err)
	}

	incl, _ := jsonArr(jsonGet(backupResult, "databases_included"))
	dbIncluded := int32(len(incl))
	if dbIncluded < dbExpected {
		// Loud, because nobody is watching a scheduled run.
		missing := rtBackupsFailures(jsonGet(backupResult, "databases_failed"))
		slog.Error(fmt.Sprintf("Scheduled backup for %s is INCOMPLETE — %d of %d databases included: %s",
			row.Domain, dbIncluded, dbExpected, strings.Join(missing, "; ")))
		SystemLogLogEvent(ctx, db, "warning", "backup_scheduler", fmt.Sprintf(
			"Scheduled backup for %s does not contain %d of its %d database(s) — restoring it will not bring that content back",
			row.Domain, dbExpected-dbIncluded, dbExpected), nil)
	}

	filename, ok := jsonStr(jsonGet(backupResult, "filename"))
	if !ok {
		return errors.New("No filename in backup result")
	}
	sizeU, _ := jsonU64(jsonGet(backupResult, "size_bytes"))
	sizeBytes := int64(sizeU)
	// The agent computes this on every run; this path used to drop it, so a
	// site archived only by a schedule carried no hash (#114). The nullable
	// SELECT is deliberate: every row written before the fix has a NULL hash.
	sha256Hash, _ := jsonStr(jsonGet(backupResult, "sha256"))
	var previousHash *string
	if v, err := queryScalarOpt[*string](ctx, db,
		"SELECT sha256_hash FROM backups WHERE site_id = $1 ORDER BY created_at DESC LIMIT 1", row.SiteID); err != nil {
		slog.Warn(fmt.Sprintf("Scheduled backup for %s: could not read the previous hash: %v", row.Domain, err))
	} else if v != nil {
		previousHash = *v
	}
	filepath := fmt.Sprintf("/var/backups/dockpanel/%s/%s", row.Domain, filename)

	// Carries an exhausted upload past the INSERT. The archive still gets a
	// row — retention enumerates it and the hash chain hangs off it — but the
	// RUN still has to fail.
	var uploadFailed *string

	// 2. Upload to remote destination (if configured).
	uploadedRemote := false
	if row.DestDtype != nil && row.DestConfig != nil {
		dest := rtBackupDestinationsAgentDestinationPayload(*row.DestDtype, row.DestConfig)
		uploadBody := map[string]any{"filepath": filepath, "destination": dest}

		// Retry upload with exponential backoff: 5s, 15s, 30s.
		delays := []uint64{5, 15, 30}
		lastErr := ""
		uploaded := false
		for attempt, delay := range delays {
			// PostLong, not Post: Post caps every agent call at 60s while the
			// agent budgets 600s for this upload. A slow off-site copy had the
			// panel give up while the bytes DID land, retry twice more, record
			// local-only and alert. 660s so the AGENT's own timeout fires first.
			if _, err := agent.PostLong(ctx, "/backups/upload", uploadBody, 660); err == nil {
				uploaded = true
				break
			} else {
				lastErr = err.Error()
			}
			if attempt < len(delays)-1 {
				slog.Warn(fmt.Sprintf("Backup upload attempt %d failed for %s: %s — retrying in %ds", attempt+1, row.Domain, lastErr, delay))
				select {
				case <-time.After(time.Duration(delay) * time.Second):
				case <-ctx.Done():
				}
			}
		}

		if !uploaded {
			// All retries exhausted. Record the archive anyway, local-only:
			// skipping the INSERT left a full-site tarball nothing would ever
			// reap (retention enumerates rows), one per night while the
			// destination stays down. The run still fails via uploadFailed.
			SystemLogLogEvent(ctx, db, "error", "backup_scheduler",
				fmt.Sprintf("Backup upload failed for %s after 3 attempts", row.Domain), &lastErr)
			uploadFailed = &lastErr
		} else {
			// Prune old remote backups. The agent answers 200 with an
			// explanatory `message` when it cannot prune (SFTP); discarding it
			// meant retention read as enforced while remote copies piled up.
			pruneBody := map[string]any{
				"destination": dest,
				"domain":      row.Domain,
				"retention":   row.RetentionCount,
			}
			if resp, err := agent.Post(ctx, "/backups/prune", pruneBody); err == nil {
				if msg, ok := jsonStr(jsonGet(resp, "message")); ok {
					// "warning", not "warn" — only that spelling is filterable.
					SystemLogLogEvent(ctx, db, "warning", "backup_scheduler",
						"Remote retention was not enforced for "+row.Domain, &msg)
				}
			} else {
				slog.Warn(fmt.Sprintf("Remote prune failed for %s: %v", row.Domain, err))
			}
			uploadedRemote = true
		}
	}

	// 3. Record in DB only after successful creation and upload (if
	// configured).
	//
	// `uploaded` and `destination_id` are bound because a scheduled backup
	// with a destination used to ship off-site and then file itself as
	// local-only. destination_id is bound unconditionally: the only predicate
	// that distinguishes a failed upload is (destination_id IS NOT NULL AND
	// NOT uploaded) — what the policy executor already writes. chain_valid is
	// deliberately left to its column default.
	//
	// The error is checked because this row IS the backup as far as the
	// product is concerned; discarding it left 'success' over an archive with
	// no row.
	var shaArg *string
	if sha256Hash != "" {
		shaArg = &sha256Hash
	}
	if _, err := execSQL(ctx, db,
		"INSERT INTO backups (site_id, filename, size_bytes, databases_included, databases_expected, uploaded, destination_id, sha256_hash, previous_hash) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		row.SiteID, filename, sizeBytes, dbIncluded, dbExpected, uploadedRemote, row.DestID, shaArg, previousHash); err != nil {
		return fmt.Errorf("Backup created but could not be recorded: %v", err)
	}

	if uploadFailed != nil {
		return fmt.Errorf("Backup recorded local-only: upload failed after 3 attempts: %s", *uploadFailed)
	}
	slog.Info("Scheduled backup complete for " + row.Domain)
	return nil
}

// backupSchedulerCronMatchesNow checks if a cron expression matches now.
func backupSchedulerCronMatchesNow(schedule string, now time.Time) bool {
	parts := strings.Fields(schedule)
	if len(parts) != 5 {
		return false
	}
	return backupSchedulerFieldMatches(parts[0], uint32(now.Minute())) &&
		backupSchedulerFieldMatches(parts[1], uint32(now.Hour())) &&
		backupSchedulerFieldMatches(parts[2], uint32(now.Day())) &&
		backupSchedulerFieldMatches(parts[3], uint32(now.Month())) &&
		backupSchedulerFieldMatches(parts[4], uint32(now.Weekday()))
}

// backupSchedulerParseU32 is Rust's str::parse::<u32> (optional leading '+').
func backupSchedulerParseU32(s string) (uint32, bool) {
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "+"), 10, 32)
	return uint32(n), err == nil
}

// backupSchedulerFieldMatches checks if a single cron field matches a value.
func backupSchedulerFieldMatches(field string, value uint32) bool {
	if field == "*" {
		return true
	}
	// Handle */N (step).
	if step, ok := strings.CutPrefix(field, "*/"); ok {
		if s, ok := backupSchedulerParseU32(step); ok {
			return s > 0 && value%s == 0
		}
	}
	// Handle comma-separated values and ranges.
	for part := range strings.SplitSeq(field, ",") {
		if start, end, ok := strings.Cut(part, "-"); ok {
			s, ok1 := backupSchedulerParseU32(start)
			e, ok2 := backupSchedulerParseU32(end)
			if ok1 && ok2 && value >= s && value <= e {
				return true
			}
		} else if v, ok := backupSchedulerParseU32(part); ok && v == value {
			return true
		}
	}
	return false
}
