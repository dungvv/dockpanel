package api

// Port of panel/backend/src/services/backup_policy_executor.rs.
//
// GAP 1: Backup Policy Executor — runs every 60s, evaluates cron schedules,
// executes backup_policies across sites, databases, and volumes.

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type backupPolicyExecutorPolicyRow struct {
	ID                uuid.UUID  `db:"id"`
	UserID            uuid.UUID  `db:"user_id"`
	ServerID          *uuid.UUID `db:"server_id"`
	Name              string     `db:"name"`
	BackupSites       bool       `db:"backup_sites"`
	BackupDatabases   bool       `db:"backup_databases"`
	BackupVolumes     bool       `db:"backup_volumes"`
	Schedule          string     `db:"schedule"`
	DestinationID     *uuid.UUID `db:"destination_id"`
	RetentionCount    int32      `db:"retention_count"`
	Encrypt           bool       `db:"encrypt"`
	VerifyAfterBackup bool       `db:"verify_after_backup"`
	LastRun           *time.Time `db:"last_run"`
}

// backupPolicyExecutorDeriveBackupEncryptionKeyV1 is the v1 passphrase: a
// literal substring of JWT_SECRET.
//
// ⚠ SECURITY (s434): weak by construction — it hands anyone who learns a
// backup passphrase 32 bytes of the secret every session token is signed
// with. Kept ONLY so a backup written before v2 can still be decrypted. Never
// use it for a new encrypt; see SecretsCryptoDeriveBackupEncryptionKeyV2.
func backupPolicyExecutorDeriveBackupEncryptionKeyV1(jwtSecret string) string {
	return "backup-enc-" + jwtSecret[:min(32, len(jwtSecret))]
}

// BackupPolicyExecutorCurrentBackupKeyVersion is the key version every NEW
// encrypted backup is written with. Bump it — and add a new vN derivation
// plus a case below — if the derivation changes again. Never repurpose a
// number: database_backups.encryption_key_version permanently records which
// derivation produced that file.
const BackupPolicyExecutorCurrentBackupKeyVersion int16 = 2

// BackupPolicyExecutorDeriveBackupEncryptionKeyForVersion is the SINGLE SOURCE
// OF TRUTH for the passphrase used to encrypt AND decrypt policy-driven DB
// backups, for a SPECIFIC recorded version.
//
// The encrypt side and the restore side once derived the key from two
// incompatible sources (restore read a column nothing writes), so every
// encrypted DB backup was unrestorable (lesson #70). Restore reads the row's
// encryption_key_version rather than assuming the current one, so a backup
// written under an older derivation stays restorable.
func BackupPolicyExecutorDeriveBackupEncryptionKeyForVersion(version int16, jwtSecret string) string {
	if version == 1 {
		return backupPolicyExecutorDeriveBackupEncryptionKeyV1(jwtSecret)
	}
	// Unknown/future versions fall through to the current derivation rather
	// than panicking — a wrong passphrase then fails LOUDLY in openssl.
	return SecretsCryptoDeriveBackupEncryptionKeyV2(jwtSecret)
}

// BackupPolicyExecutorDeriveBackupEncryptionKey is the passphrase a NEW
// encrypted backup is written with. Restoring an EXISTING backup must use
// ...ForVersion with that row's recorded version instead.
func BackupPolicyExecutorDeriveBackupEncryptionKey(jwtSecret string) string {
	return BackupPolicyExecutorDeriveBackupEncryptionKeyForVersion(BackupPolicyExecutorCurrentBackupKeyVersion, jwtSecret)
}

// backupPolicyExecutorResolvedDestination is a policy's off-site destination,
// resolved once per run.
//
// destination_id used to be selected and NEVER read, so every policy-driven
// backup stayed on the machine it was protecting while the operator had
// chosen an off-site destination and been shown no sign it was ignored. A
// backup that only exists on the disk it is insuring is not a backup.
type backupPolicyExecutorResolvedDestination struct {
	ID uuid.UUID
	// The destination config with `type` folded in, exactly as the agent's
	// /backups/upload handler expects it.
	Payload any
}

func backupPolicyExecutorResolveDestination(ctx context.Context, db *pgxpool.Pool, policy *backupPolicyExecutorPolicyRow) *backupPolicyExecutorResolvedDestination {
	if policy.DestinationID == nil {
		return nil
	}
	id := *policy.DestinationID
	row, err := queryOpt[Tup2[string, any]](ctx, db, "SELECT dtype, config FROM backup_destinations WHERE id = $1", id)
	// Distinguish "deleted" from "we couldn't ask": both end local-only, but
	// collapsing them would send an operator hunting for a destination that
	// is still perfectly there.
	if err != nil {
		slog.Error(fmt.Sprintf("Policy '%s': could not read destination %s (%v) — backups will stay on this server", policy.Name, id, err))
		return nil
	}
	if row == nil {
		slog.Error(fmt.Sprintf("Policy '%s': destination %s no longer exists — backups will stay on this server", policy.Name, id))
		return nil
	}
	return &backupPolicyExecutorResolvedDestination{ID: id, Payload: rtBackupDestinationsAgentDestinationPayload(row.A, row.B)}
}

// backupPolicyExecutorUploadToDestination pushes one finished backup file off
// the box; true only when the bytes actually landed. Mirrors the scheduler's
// 5s/15s/30s ladder so the two paths fail the same way.
//
// Known gap: remote retention covers site backups only. The agent's
// /backups/prune is keyed on a site domain, so database and volume copies
// accumulate at the destination even though their LOCAL copies are pruned by
// auto_healer. A resource-agnostic prune needs an agent-side change.
func backupPolicyExecutorUploadToDestination(ctx context.Context, agent AgentHandle, dest *backupPolicyExecutorResolvedDestination, filepath, label string) bool {
	body := map[string]any{"filepath": filepath, "destination": dest.Payload}
	delays := []uint64{5, 15, 30}
	lastErr := ""
	for attempt, delay := range delays {
		// PostLong: plain Post caps the call at 60s while the agent budgets
		// 600s, so a slow-but-fine transfer was reported failed three times
		// over — and here that also trips destination_down for the rest of the
		// run and raises an incident about backups that had just uploaded.
		_, err := agent.PostLong(ctx, "/backups/upload", body, 660)
		if err == nil {
			return true
		}
		lastErr = err.Error()
		if attempt < len(delays)-1 {
			slog.Warn(fmt.Sprintf("Upload attempt %d failed for %s: %s — retrying in %ds", attempt+1, label, lastErr, delay))
			backupPolicyExecutorSleep(ctx, time.Duration(delay)*time.Second)
		}
	}
	slog.Error(fmt.Sprintf("Upload failed for %s after %d attempts: %s", label, len(delays), lastErr))
	return false
}

func backupPolicyExecutorSleep(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

// BackupPolicyExecutorRun is the executor loop — checks every 60 seconds for
// due policies. Fleet-wide policy query, so it takes the REGISTRY. Each leg
// resolves its own host: sites and databases per ROW, volumes per POLICY
// (their subject list comes from the agent, so there is no row to read).
//
// Left local, the volume leg tarred the PANEL's volumes, stamped each row
// with the member's server_id and reported success; auto_healer then refused
// to prune those rows, so retention was enforced on nothing.
func BackupPolicyExecutorRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, jwtSecret string) {
	slog.Info("Backup policy executor started")
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		if err := backupPolicyExecutorTick(ctx, db, agents, jwtSecret); err != nil {
			slog.Error(fmt.Sprintf("Backup policy executor error: %v", err))
		}
		select {
		case <-t.C:
		case <-ctx.Done():
			slog.Info("Backup policy executor shutting down gracefully")
			return
		}
	}
}

// backupPolicyExecutorLastStaleCheck tracks the last stale-backup check to
// avoid spamming (once per hour).
var backupPolicyExecutorLastStaleCheck atomic.Int64

func backupPolicyExecutorTick(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, jwtSecret string) error {
	now := time.Now().UTC()

	policies, err := queryAll[backupPolicyExecutorPolicyRow](ctx, db,
		"SELECT id, user_id, server_id, name, backup_sites, backup_databases, backup_volumes, "+
			"schedule, destination_id, retention_count, encrypt, verify_after_backup, last_run "+
			"FROM backup_policies WHERE enabled = TRUE")
	if err != nil {
		return err
	}

	for i := range policies {
		p := &policies[i]
		if !backupPolicyExecutorCronMatchesNow(p.Schedule, now) {
			continue
		}
		// Prevent double-runs within 90 seconds.
		if p.LastRun != nil && int64(now.Sub(*p.LastRun)/time.Second) < 90 {
			continue
		}
		slog.Info(fmt.Sprintf("Executing backup policy '%s' (%s)", p.Name, p.ID))
		backupPolicyExecutorExecutePolicy(ctx, db, agents, p, jwtSecret)
	}

	// Record backup storage metric for growth tracking. SUM(BIGINT) returns
	// NUMERIC in postgres — cast to bigint so it decodes into int64.
	if bytes, err := queryScalar[int64](ctx, db,
		"SELECT COALESCE(SUM(size_bytes), 0)::bigint FROM ( "+
			"SELECT size_bytes FROM backups UNION ALL "+
			"SELECT size_bytes FROM database_backups UNION ALL "+
			"SELECT size_bytes FROM volume_backups "+
			") t"); err == nil {
		_, _ = execSQL(ctx, db,
			"INSERT INTO system_logs (level, source, message) VALUES ('info', 'backup_storage', $1)",
			strconv.FormatInt(bytes, 10))
	}

	// Proactive backup freshness alerting — once per hour.
	nowTS := now.Unix()
	if nowTS-backupPolicyExecutorLastStaleCheck.Load() >= 3600 {
		backupPolicyExecutorLastStaleCheck.Store(nowTS)
		stale, err := queryAll[string](ctx, db,
			"SELECT s.domain FROM sites s WHERE s.status = 'active' "+
				"AND NOT EXISTS (SELECT 1 FROM backups b WHERE b.site_id = s.id AND b.created_at > NOW() - INTERVAL '48 hours' "+
				"AND (b.destination_id IS NULL OR b.uploaded))")
		if err != nil {
			stale = nil
		}
		if len(stale) > 0 {
			NotificationsNotifyPanel(ctx, db, nil,
				fmt.Sprintf("%d site(s) have stale backups", len(stale)),
				"These sites have no backup in 48+ hours: "+strings.Join(stale, ", "),
				"warning", "backup", new("/backup-orchestrator"))
			slog.Warn(fmt.Sprintf("Stale backup alert: %d sites without recent backups", len(stale)))
		}
	}
	return nil
}

func backupPolicyExecutorShaArg(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func backupPolicyExecutorDestID(d *backupPolicyExecutorResolvedDestination) *uuid.UUID {
	if d == nil {
		return nil
	}
	return &d.ID
}

func backupPolicyExecutorExecutePolicy(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, policy *backupPolicyExecutorPolicyRow, jwtSecret string) {
	successes, failures := 0, 0

	// Resolved once, not per file.
	destination := backupPolicyExecutorResolveDestination(ctx, db, policy)

	// A failed upload counts as a FAILURE (the policy reports partial/failed
	// and the alert fires) but the local file is still recorded: the sha256
	// chain breaks without the row, and retention enumerates rows.
	uploadFailures := 0

	// Circuit breaker: each upload retries three times (~50s), so a DOWN
	// destination would hold a forty-site policy in one tick for half an hour.
	// The first exhausted ladder is enough evidence; stop dialling this run.
	destinationDown := false

	// Remote retention is reported once per run, not once per resource.
	remotePruneWarned := false

	// The shared derivation keyed on the jwt secret handed to the executor —
	// the same one the restore path uses — NOT a separate env read that could
	// drift. This is what makes an encrypted backup restorable.
	var encryptionKey *string
	if policy.Encrypt {
		encryptionKey = new(BackupPolicyExecutorDeriveBackupEncryptionKey(jwtSecret))
	}

	// The key reaches the database dump and nothing else — the agent has no
	// encryption path for a site or volume archive. Say so per run: a site
	// archive carries a dump of every attached database, so an encrypted
	// policy ships that data both encrypted and not to the same destination.
	if policy.Encrypt && (policy.BackupSites || policy.BackupVolumes) {
		slog.Warn(fmt.Sprintf("Policy '%s': encryption applies to database dumps only — this policy's site/volume archives are stored and uploaded unencrypted", policy.Name))
	}

	// Backup sites.
	if policy.BackupSites {
		// server_id rides along: a site is archived on the host that holds
		// its files. NOT NULL, so there is no ambiguous case to default.
		sites, _ := queryAll[Tup3[uuid.UUID, string, uuid.UUID]](ctx, db,
			"SELECT id, domain, server_id FROM sites WHERE user_id = $1", policy.UserID)
		for _, s := range sites {
			siteID, domain, siteServerID := s.A, s.B, s.C
			// Never fall back to local: archiving a member's site against the
			// panel's /var/www fails forever or tars the wrong machine's files.
			agent, err := agents.ForServer(ctx, siteServerID)
			if err != nil {
				failures++
				slog.Warn(fmt.Sprintf("Policy '%s': skipping site %s — its server %s is unreachable (%v). Not archiving it on another host.",
					policy.Name, domain, siteServerID, err))
				continue
			}
			// WITH the site's databases — omitting them would reintroduce on
			// the automated path exactly the gap v2.34.0 closed.
			siteDBs := rtBackupsSiteDatabaseSpecs(ctx, db, jwtSecret, siteID)
			dbExpected := int32(siteDBs.Expected())
			agentBody := map[string]any{"databases": siteDBs.Specs}

			resp, err := agent.Post(ctx, "/backups/"+domain+"/create", agentBody)
			// Retry once on failure.
			if err != nil {
				backupPolicyExecutorSleep(ctx, 5*time.Second)
				resp, err = agent.Post(ctx, "/backups/"+domain+"/create", agentBody)
			}
			if err != nil {
				slog.Error(fmt.Sprintf("Policy '%s': site backup failed for %s (after retry): %v", policy.Name, domain, err))
				failures++
				continue
			}
			filename, _ := jsonStr(jsonGet(resp, "filename"))
			sizeU, _ := jsonU64(jsonGet(resp, "size_bytes"))
			// Same read the db and volume branches do (#114); before the upload.
			sha256Hash, _ := jsonStr(jsonGet(resp, "sha256"))
			var previousHash *string
			if v, err := queryScalarOpt[*string](ctx, db,
				"SELECT sha256_hash FROM backups WHERE site_id = $1 ORDER BY created_at DESC LIMIT 1", siteID); err == nil && v != nil {
				previousHash = *v
			}

			uploaded := false
			if destination != nil && !destinationDown {
				filepath := fmt.Sprintf("/var/backups/dockpanel/%s/%s", domain, filename)
				uploaded = backupPolicyExecutorUploadToDestination(ctx, agent, destination, filepath, "site "+domain)
				if uploaded {
					// Enforce remote retention too. The agent returns 200 with a
					// `message` when it cannot prune (SFTP); reported once per run.
					pr, err := agent.Post(ctx, "/backups/prune", map[string]any{
						"destination": destination.Payload,
						"domain":      domain,
						"retention":   policy.RetentionCount,
					})
					if err != nil {
						slog.Warn(fmt.Sprintf("Policy '%s': remote prune failed for %s: %v", policy.Name, domain, err))
					} else if msg, ok := jsonStr(jsonGet(pr, "message")); ok && !remotePruneWarned {
						remotePruneWarned = true
						// "warning", not "warn" — the API filters and counts on the former.
						SystemLogLogEvent(ctx, db, "warning", "backup_policy_executor",
							fmt.Sprintf("Policy '%s': remote retention was not enforced", policy.Name), &msg)
					}
				} else {
					uploadFailures++
					destinationDown = true
				}
			} else if destination != nil {
				// Breaker already open — count it, don't dial.
				uploadFailures++
			}

			// A backup the panel cannot record is one the operator cannot find
			// or restore. The realistic trigger is deleting a destination
			// mid-run, which makes every remaining insert an FK violation.
			incl, _ := jsonArr(jsonGet(resp, "databases_included"))
			if _, err := execSQL(ctx, db,
				"INSERT INTO backups (site_id, filename, size_bytes, destination_id, uploaded, databases_included, databases_expected, sha256_hash, previous_hash) "+
					"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
				siteID, filename, int64(sizeU), backupPolicyExecutorDestID(destination), uploaded,
				int32(len(incl)), dbExpected, backupPolicyExecutorShaArg(sha256Hash), previousHash); err != nil {
				slog.Error(fmt.Sprintf("Policy '%s': site backup for %s was created but could not be recorded: %v", policy.Name, domain, err))
				failures++
			} else {
				successes++
			}
		}
	}

	// Backup databases.
	if policy.BackupDatabases {
		// server_id comes from the owner join. Without it the panel would
		// `docker exec` whatever answers to `dockpanel-db-{name}` on ITS OWN
		// host, and that name is unique only per owner.
		//
		// LEFT JOIN both owner tables + COALESCE: a plain `JOIN sites`
		// silently dropped every stack-owned database (site_id IS NULL since
		// v2.242.0), so they got zero backup coverage with no error anywhere.
		dbs, _ := queryAll[Tup6[uuid.UUID, string, string, string, string, *uuid.UUID]](ctx, db,
			"SELECT d.id, d.name, d.engine, d.db_user, d.db_password_enc, "+
				"COALESCE(s.server_id, st.server_id) "+
				"FROM databases d "+
				"LEFT JOIN sites s ON d.site_id = s.id "+
				"LEFT JOIN docker_stacks st ON d.stack_id = st.id "+
				"WHERE COALESCE(s.user_id, st.user_id) = $1", policy.UserID)
		for _, d := range dbs {
			dbID, dbName, engine, user, passwordEnc := d.A, d.B, d.C, d.D, d.E
			if d.F == nil {
				failures++
				slog.Warn(fmt.Sprintf("Policy '%s': skipping database %s — its owner (site or stack) row has no server_id.", policy.Name, dbName))
				continue
			}
			dbServerID := *d.F
			agent, err := agents.ForServer(ctx, dbServerID)
			if err != nil {
				failures++
				slog.Warn(fmt.Sprintf("Policy '%s': skipping database %s — its server %s is unreachable (%v).", policy.Name, dbName, dbServerID, err))
				continue
			}
			password := SecretsCryptoDecryptCredentialOrLegacy(passwordEnc, jwtSecret)
			body := map[string]any{
				"container_name": "dockpanel-db-" + dbName,
				"db_name":        dbName,
				"db_type":        engine,
				"user":           user,
				"password":       password,
				"encryption_key": encryptionKey,
			}
			resp, err := agent.Post(ctx, "/db-backups/dump", body)
			if err != nil {
				backupPolicyExecutorSleep(ctx, 5*time.Second)
				resp, err = agent.Post(ctx, "/db-backups/dump", body)
			}
			if err != nil {
				slog.Error(fmt.Sprintf("Policy '%s': DB backup failed for %s (after retry): %v", policy.Name, dbName, err))
				failures++
				continue
			}
			filename, _ := jsonStr(jsonGet(resp, "filename"))
			sizeU, _ := jsonU64(jsonGet(resp, "size_bytes"))
			encrypted := encryptionKey != nil
			sha256Hash, _ := jsonStr(jsonGet(resp, "sha256"))
			var previousHash *string
			if v, err := queryScalarOpt[*string](ctx, db,
				"SELECT sha256_hash FROM database_backups WHERE database_id = $1 ORDER BY created_at DESC LIMIT 1", dbID); err == nil && v != nil {
				previousHash = *v
			}

			uploaded := false
			if destination != nil && !destinationDown {
				// database_backup's backup_dir nests per database.
				filepath := fmt.Sprintf("/var/backups/dockpanel/databases/%s/%s", dbName, filename)
				uploaded = backupPolicyExecutorUploadToDestination(ctx, agent, destination, filepath, "database "+dbName)
				if !uploaded {
					uploadFailures++
					destinationDown = true
				}
			} else if destination != nil {
				uploadFailures++
			}

			if _, err := execSQL(ctx, db,
				"INSERT INTO database_backups (database_id, server_id, filename, size_bytes, db_type, db_name, encrypted, encryption_key_version, policy_id, destination_id, uploaded, sha256_hash, previous_hash, chain_valid) "+
					"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, TRUE)",
				dbID, dbServerID, filename, int64(sizeU), engine, dbName, encrypted, BackupPolicyExecutorCurrentBackupKeyVersion, policy.ID,
				backupPolicyExecutorDestID(destination), uploaded, backupPolicyExecutorShaArg(sha256Hash), previousHash); err != nil {
				slog.Error(fmt.Sprintf("Policy '%s': DB backup for %s was created but could not be recorded: %v", policy.Name, dbName, err))
				failures++
			} else {
				successes++
			}
		}
	}

	// Backup volumes (Docker app volumes). Admin-only capability — the
	// enumeration below is fleet-wide with NO per-user scoping, so guard the
	// executor too against any legacy non-admin-owned policy.
	ownerIsAdmin := false
	if v, err := queryScalarOpt[bool](ctx, db, "SELECT role = 'admin' FROM users WHERE id = $1", policy.UserID); err == nil && v != nil {
		ownerIsAdmin = *v
	}
	if policy.BackupVolumes && !ownerIsAdmin {
		slog.Warn(fmt.Sprintf("Policy '%s': skipping volume backup — owner is not an admin", policy.Name))
	}
	if policy.BackupVolumes && ownerIsAdmin {
		s, f, u := backupPolicyExecutorBackupVolumes(ctx, db, agents, policy, destination, &destinationDown)
		successes += s
		failures += f
		uploadFailures += u
	}

	// An upload failure is NOT a backup failure — the file exists locally and
	// is counted in successes. It IS a disaster-recovery failure, so it
	// degrades the status and raises the alert.
	totalAttempted := successes + failures
	status := "failed"
	switch {
	case failures == 0 && uploadFailures == 0:
		status = "success"
	case successes > 0:
		status = "partial"
	}
	_, _ = execSQL(ctx, db,
		"UPDATE backup_policies SET last_run = NOW(), last_status = $2, updated_at = NOW() WHERE id = $1",
		policy.ID, status)

	slog.Info(fmt.Sprintf("Policy '%s' completed: %d successes, %d failures, %d not uploaded off-site (status: %s)",
		policy.Name, successes, failures, uploadFailures, status))

	// Kept in one place so the incident, the alert and the log agree.
	trouble := func(kind string) string {
		switch {
		case failures == 0:
			return fmt.Sprintf("%d of %d %s could not be uploaded to the configured destination — they exist only on this server.", uploadFailures, successes, kind)
		case uploadFailures == 0:
			return fmt.Sprintf("%d %s failed out of %d total", failures, kind, totalAttempted)
		default:
			return fmt.Sprintf("%d %s failed out of %d total, and %d more could not be uploaded off-site.", failures, kind, totalAttempted, uploadFailures)
		}
	}

	if failures > 0 || uploadFailures > 0 {
		// GAP 10: create a managed incident.
		title := fmt.Sprintf("Backup policy '%s' could not reach its destination", policy.Name)
		if failures > 0 {
			title = fmt.Sprintf("Backup policy '%s' had failures", policy.Name)
		}
		_, _ = execSQL(ctx, db,
			"INSERT INTO managed_incidents (user_id, title, status, severity, description, visible_on_status_page) "+
				"VALUES ($1, $2, 'investigating', 'major', $3, FALSE)",
			policy.UserID, title, trouble("backup(s)"))

		// An off-site copy that didn't happen is serious but recoverable on
		// the next run; don't page at the same urgency as a missing backup.
		severity := "warning"
		alertTitle := fmt.Sprintf("Backup policy '%s' kept its backups on this server", policy.Name)
		if failures > 0 {
			severity = "critical"
			alertTitle = fmt.Sprintf("Backup policy '%s' failed", policy.Name)
		}
		NotificationsFireAlert(ctx, db, policy.UserID, policy.ServerID, nil, "backup_failure", "", severity, alertTitle, trouble("backup(s)"))
	}

	// GAP 2: the backup_verifier service picks up newly created backups on its
	// next cycle (unverified, created in the last 7 days).
	if policy.VerifyAfterBackup && successes > 0 {
		slog.Info(fmt.Sprintf("Policy '%s': triggering post-backup verification", policy.Name))
	}
}

// backupPolicyExecutorBackupVolumes is the volume leg (Rust's labelled
// `'vol` block). Returns (successes, failures, uploadFailures).
func backupPolicyExecutorBackupVolumes(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry, policy *backupPolicyExecutorPolicyRow,
	destination *backupPolicyExecutorResolvedDestination, destinationDown *bool) (successes, failures, uploadFailures int) {
	// Volumes have no per-row host: the POLICY's server decides which agent.
	// When it names none (all the UI can produce), resolve the local server
	// EXPLICITLY and record that id. Recording the server actually reached is
	// the whole point: the two used to differ, which made auto_healer refuse
	// to prune these rows forever.
	sid := policy.ServerID
	if sid == nil {
		sid = agents.LocalServerID()
	}
	if sid == nil {
		slog.Warn(fmt.Sprintf("Policy '%s': skipping volume backup — no server on the policy and the "+
			"local server id is not yet known (setup incomplete).", policy.Name))
		return
	}
	volServerID := *sid
	agent, err := agents.ForServer(ctx, volServerID)
	if err != nil {
		failures++
		slog.Warn(fmt.Sprintf("Policy '%s': skipping volume backup — server %s is "+
			"unreachable (%v). Not tarring another host's volumes under its name.", policy.Name, volServerID, err))
		return
	}

	// Get Docker containers with volumes.
	apps, err := agent.Get(ctx, "/apps")
	if err != nil {
		slog.Error(fmt.Sprintf("Policy '%s': failed to list Docker apps for volume backup: %v", policy.Name, err))
		failures++
		return
	}
	appList, _ := jsonArr(apps)
	for _, app := range appList {
		containerName, _ := jsonStr(jsonGet(app, "name"))
		containerID, _ := jsonStr(jsonGet(app, "container_id"))
		if containerName == "" {
			continue
		}
		volResp, err := agent.Get(ctx, "/apps/"+containerID+"/volumes")
		if err != nil {
			continue
		}
		volumes, _ := jsonArr(volResp)
		for _, vol := range volumes {
			volName, _ := jsonStr(jsonGet(vol, "name"))
			if volName == "" {
				continue
			}
			body := map[string]any{"volume_name": volName, "container_name": containerName}
			resp, err := agent.Post(ctx, "/volume-backups/create", body)
			if err != nil {
				backupPolicyExecutorSleep(ctx, 5*time.Second)
				resp, err = agent.Post(ctx, "/volume-backups/create", body)
			}
			if err != nil {
				slog.Error(fmt.Sprintf("Policy '%s': volume backup failed for %s/%s (after retry): %v", policy.Name, containerName, volName, err))
				failures++
				continue
			}
			filename, _ := jsonStr(jsonGet(resp, "filename"))
			sizeU, _ := jsonU64(jsonGet(resp, "size_bytes"))
			sha256Hash, _ := jsonStr(jsonGet(resp, "sha256"))
			var previousHash *string
			if v, err := queryScalarOpt[*string](ctx, db,
				"SELECT sha256_hash FROM volume_backups WHERE container_id = $1 AND volume_name = $2 ORDER BY created_at DESC LIMIT 1",
				containerID, volName); err == nil && v != nil {
				previousHash = *v
			}

			uploaded := false
			if destination != nil && !*destinationDown {
				// volume_backup's backup_dir nests per container.
				filepath := fmt.Sprintf("/var/backups/dockpanel/volumes/%s/%s", containerName, filename)
				uploaded = backupPolicyExecutorUploadToDestination(ctx, agent, destination, filepath, "volume "+volName)
				if !uploaded {
					uploadFailures++
					*destinationDown = true
				}
			} else if destination != nil {
				uploadFailures++
			}

			if _, err := execSQL(ctx, db,
				"INSERT INTO volume_backups (container_id, container_name, server_id, volume_name, filename, size_bytes, policy_id, destination_id, uploaded, sha256_hash, previous_hash, chain_valid) "+
					"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE)",
				containerID, containerName, volServerID, volName, filename, int64(sizeU), policy.ID,
				backupPolicyExecutorDestID(destination), uploaded, backupPolicyExecutorShaArg(sha256Hash), previousHash); err != nil {
				slog.Error(fmt.Sprintf("Policy '%s': volume backup for %s/%s was created but could not be recorded: %v", policy.Name, containerName, volName, err))
				failures++
			} else {
				successes++
			}
		}
	}
	return
}

// backupPolicyExecutorCronMatchesNow is a simple 5-field cron matcher.
func backupPolicyExecutorCronMatchesNow(schedule string, now time.Time) bool {
	f := strings.Fields(schedule)
	if len(f) != 5 {
		return false
	}
	return backupPolicyExecutorFieldMatches(f[0], now.Minute()) &&
		backupPolicyExecutorFieldMatches(f[1], now.Hour()) &&
		backupPolicyExecutorFieldMatches(f[2], now.Day()) &&
		backupPolicyExecutorFieldMatches(f[3], int(now.Month())) &&
		backupPolicyExecutorFieldMatches(f[4], int(now.Weekday()))
}

func backupPolicyExecutorFieldMatches(field string, value int) bool {
	if field == "*" {
		return true
	}
	// Step: */N
	if step, ok := strings.CutPrefix(field, "*/"); ok {
		if n, err := strconv.ParseInt(step, 10, 32); err == nil {
			return n > 0 && value%int(n) == 0
		}
	}
	// List: 1,5,10 — Range: 1-5
	for part := range strings.SplitSeq(field, ",") {
		if start, end, ok := strings.Cut(part, "-"); ok {
			s, err1 := strconv.ParseInt(start, 10, 32)
			e, err2 := strconv.ParseInt(end, 10, 32)
			if err1 == nil && err2 == nil && value >= int(s) && value <= int(e) {
				return true
			}
		} else if v, err := strconv.ParseInt(part, 10, 32); err == nil && int(v) == value {
			return true
		}
	}
	return false
}
