package api

// Port of panel/backend/src/routes/backups.rs.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtBackupsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/sites/{id}/backups", h(rtBackupsList))
	r.Handle("POST /api/sites/{id}/backups", h(rtBackupsCreate))
	r.Handle("POST /api/sites/{id}/backups/{backup_id}/restore", h(rtBackupsRestore))
	r.Handle("DELETE /api/sites/{id}/backups/{backup_id}", h(rtBackupsRemove))
}

type rtBackupsBackupListQuery struct {
	Limit  *int64 `json:"limit"`
	Offset *int64 `json:"offset"`
}

type rtBackupsBackup struct {
	ID                uuid.UUID `json:"id" db:"id"`
	SiteID            uuid.UUID `json:"site_id" db:"site_id"`
	Filename          string    `json:"filename" db:"filename"`
	SizeBytes         int64     `json:"size_bytes" db:"size_bytes"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	DatabasesIncluded int32     `json:"databases_included" db:"databases_included"`
	DatabasesExpected int32     `json:"databases_expected" db:"databases_expected"`
}

// rtBackupsSiteDatabases is the set of databases attached to a site, ready to
// hand to the agent.
type rtBackupsSiteDatabases struct {
	// Specs the agent can act on, with decrypted credentials.
	Specs []any
	// Databases that exist as rows but cannot safely be touched, and why.
	// Counted as expected so a backup missing them never reads as complete.
	Unavailable []Tup2[string, string]
}

func (s rtBackupsSiteDatabases) Expected() int { return len(s.Specs) + len(s.Unavailable) }

// rtBackupsSiteDatabasesFor resolves a site's databases and decrypts their
// credentials. The agent has no access to the `databases` table, so this is
// the only place that can answer "what does backing up this site involve?".
func rtBackupsSiteDatabasesFor(ctx context.Context, st *AppState, siteID uuid.UUID) rtBackupsSiteDatabases {
	return rtBackupsSiteDatabaseSpecs(ctx, st.DB, st.Config.JWTSecret, siteID)
}

// rtBackupsSiteDatabaseSpecs is the same resolution for the schedulers, which
// hold a pool and a secret rather than an AppState.
//
// EVERY path that creates a site backup must go through this. A manual backup
// that includes the database while the SCHEDULED one silently does not would
// be the same defect this exists to close, hiding in the automated path.
func rtBackupsSiteDatabaseSpecs(ctx context.Context, db Querier, jwtSecret string, siteID uuid.UUID) rtBackupsSiteDatabases {
	rows, err := queryAll[Tup5[string, string, string, string, *string]](ctx, db,
		"SELECT name, engine, db_user, db_password_enc, container_id "+
			"FROM databases WHERE site_id = $1 ORDER BY name", siteID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Could not resolve databases for site %s: %v", siteID, err))
		rows = nil
	}
	out := rtBackupsSiteDatabases{Specs: []any{}}
	for _, r := range rows {
		name, engine, dbUser, passwordEnc, containerID := r.A, r.B, r.C, r.D, r.E
		// Mirror the get_db_info guard (v2.19.0 H1): a row with an EMPTY
		// container_id has no confirmed container of its own, and resolving it
		// by the non-unique name `dockpanel-db-{name}` could reach a container
		// that is not this tenant's. Never dump one — but never drop it
		// silently either; it is counted as expected and reported.
		if containerID == nil || *containerID == "" {
			out.Unavailable = append(out.Unavailable, Tup2[string, string]{name,
				"database is not fully provisioned yet (no container), so it could not be backed up"})
			continue
		}
		password := SecretsCryptoDecryptCredentialOrLegacy(passwordEnc, jwtSecret)
		out.Specs = append(out.Specs, map[string]any{
			"container_name": "dockpanel-db-" + name,
			"db_name":        name,
			"db_type":        engine,
			"user":           dbUser,
			"password":       password,
		})
	}
	return out
}

// rtBackupsStrings reads a JSON array of strings, skipping non-strings.
func rtBackupsStrings(v any) []string {
	out := []string{}
	arr, _ := jsonArr(v)
	for _, e := range arr {
		if s, ok := jsonStr(e); ok {
			out = append(out, s)
		}
	}
	return out
}

// rtBackupsFailures reads the agent's `databases_failed` [{db_name, error}].
func rtBackupsFailures(v any) []string {
	out := []string{}
	arr, _ := jsonArr(v)
	for _, f := range arr {
		name, ok := jsonStr(jsonGet(f, "db_name"))
		if !ok {
			continue
		}
		why, ok := jsonStr(jsonGet(f, "error"))
		if !ok {
			why = "unknown error"
		}
		out = append(out, name+": "+why)
	}
	return out
}

func rtBackupsEmitter(st *AppState, id uuid.UUID) func(step, label, status string, msg *string) {
	return func(step, label, status string, msg *string) {
		st.ProvisionLogs.Emit(id, ProvisionStep{Step: step, Label: label, Status: status, Message: msg})
	}
}

// rtBackupsCreate is POST /api/sites/{id}/backups — create a backup (async with SSE).
func rtBackupsCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, claims)
	if err != nil {
		return err
	}

	backupID := uuid.New()
	st.ProvisionLogs.Register(backupID, claims.Sub, 32)

	siteDBs := rtBackupsSiteDatabasesFor(r.Context(), st, id)
	dbExpected := int32(siteDBs.Expected())
	dbUnavailable := siteDBs.Unavailable
	agentBody := map[string]any{"databases": siteDBs.Specs}

	db := st.DB
	userID, email, keyID := claims.Sub, claims.Email, claims.KeyID
	ctx := context.WithoutCancel(r.Context())

	go func() {
		emit := rtBackupsEmitter(st, backupID)
		emit("backup", "Creating backup", "in_progress", nil)

		result, err := agent.Post(ctx, fmt.Sprintf("/backups/%s/create", domain), agentBody)
		if err != nil {
			emit("backup", "Creating backup", "error", new(err.Error()))
			emit("complete", "Backup failed", "error", nil)
			slog.Error(fmt.Sprintf("Backup creation failed for %s: %v", domain, err))
		} else {
			filename, _ := jsonStr(jsonGet(result, "filename"))
			sizeU, _ := jsonU64(jsonGet(result, "size_bytes"))
			sizeBytes := int64(sizeU)
			included := rtBackupsStrings(jsonGet(result, "databases_included"))
			failed := rtBackupsFailures(jsonGet(result, "databases_failed"))
			// Databases we refused to hand to the agent are missing from the
			// archive just the same, so they belong in the same report.
			for _, u := range dbUnavailable {
				failed = append(failed, u.A+": "+u.B)
			}

			// Feature 13: Backup integrity chain — compute hash and link to previous.
			sha256Hash, _ := jsonStr(jsonGet(result, "sha256"))
			// The nullable scan type is load-bearing: sha256_hash is NULLABLE,
			// so decoding it as a bare string turns the ordinary "predecessor
			// has no hash" case into a decode ERROR. Every row written before
			// v2.118.0 still has a NULL hash, and a failed `sha256sum` on the
			// agent still writes NULL today.
			var previousHash *string
			if v, err := queryScalarOpt[*string](ctx, db,
				"SELECT sha256_hash FROM backups WHERE site_id = $1 ORDER BY created_at DESC LIMIT 1", id); err != nil {
				slog.Warn(fmt.Sprintf("DB error fetching previous backup hash: %v", err))
			} else if v != nil {
				previousHash = *v
			}
			var shaArg *string
			if sha256Hash != "" {
				shaArg = &sha256Hash
			}

			_, recErr := execSQL(ctx, db,
				"INSERT INTO backups (site_id, filename, size_bytes, sha256_hash, previous_hash, chain_valid, databases_included, databases_expected) "+
					"VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7)",
				id, filename, sizeBytes, shaArg, previousHash, int32(len(included)), dbExpected)

			// An archive with no row is unreachable through the product: the
			// list and both restore paths look it up by row. Reporting the step
			// green over that failure is the one thing this live log must not
			// do. Deliberately NOT an early return — the tail removes the log.
			if recErr != nil {
				slog.Error(fmt.Sprintf("Backup created for site %s but could not be recorded: %v", id, recErr))
				emit("backup", "Backup created but could not be recorded", "error",
					new("The archive exists on the server but is not listed in the panel, so it cannot be restored from here."))
				emit("complete", "Backup not recorded", "error", new(filename))
			} else {
				emit("backup", "Creating backup", "done", nil)

				// Say what is actually in the archive. A backup missing a
				// database the site has is NOT a clean success.
				switch {
				case dbExpected == 0:
					emit("databases", "No databases attached to this site", "done", nil)
				case len(failed) == 0:
					emit("databases", "Databases included: "+strings.Join(included, ", "), "done", nil)
				default:
					emit("databases", "Databases NOT included in this backup", "error", new(strings.Join(failed, "; ")))
				}

				if len(failed) == 0 {
					emit("complete", "Backup created", "done", new(filename))
				} else {
					emit("complete", fmt.Sprintf(
						"Backup created WITHOUT %d of %d database(s) — restoring it will not bring their content back",
						len(failed), dbExpected), "error", new(filename))
				}

				slog.Info(fmt.Sprintf("Backup created: %s for %s (%d of %d databases included)", filename, domain, len(included), dbExpected))
				ActivityLogActivity(ctx, db, userID, email, "backup.create",
					new("backup"), new(domain), new(filename), nil, keyID)

				ExtensionsFireEvent(db, "backup.created", map[string]any{
					"site_id": id, "filename": filename,
					"databases_included": len(included),
					"databases_expected": dbExpected,
				})
			}
		}

		time.Sleep(60 * time.Second)
		st.ProvisionLogs.Remove(backupID)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"backup_id": backupID,
		"message":   "Backup creation started",
	})
	return nil
}

// rtBackupsList is GET /api/sites/{id}/backups.
func rtBackupsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var q rtBackupsBackupListQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	// Verify ownership.
	if _, err := siteDomainForCaller(r.Context(), st, id, claims); err != nil {
		return err
	}
	limit, offset := paginate(q.Limit, q.Offset)
	backups, err := queryAll[rtBackupsBackup](r.Context(), st.DB,
		"SELECT * FROM backups WHERE site_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3", id, limit, offset)
	if err != nil {
		return internalError("list backups", err)
	}
	writeJSON(w, http.StatusOK, backups)
	return nil
}

// rtBackupsRestore is POST /api/sites/{id}/backups/{backup_id}/restore (async with SSE).
func rtBackupsRestore(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	backupID, err := pathUUID(r, "backup_id")
	if err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, claims)
	if err != nil {
		return err
	}
	backup, err := queryOpt[rtBackupsBackup](r.Context(), st.DB,
		"SELECT * FROM backups WHERE id = $1 AND site_id = $2", backupID, id)
	if err != nil {
		return internalError("restore", err)
	}
	if backup == nil {
		return apiErr(http.StatusNotFound, "Backup not found")
	}

	restoreID := uuid.New()
	st.ProvisionLogs.Register(restoreID, claims.Sub, 32)

	siteDBs := rtBackupsSiteDatabasesFor(r.Context(), st, id)
	siteHasDBs := siteDBs.Expected() > 0
	agentBody := map[string]any{"databases": siteDBs.Specs}
	archiveHasDBs := backup.DatabasesIncluded > 0

	db := st.DB
	userID, email, keyID := claims.Sub, claims.Email, claims.KeyID
	filename := backup.Filename
	ip := clientIP(r)
	ctx := context.WithoutCancel(r.Context())

	go func() {
		emit := rtBackupsEmitter(st, restoreID)
		defer func() {
			time.Sleep(60 * time.Second)
			st.ProvisionLogs.Remove(restoreID)
		}()

		// Tell the operator BEFORE the destructive step what this archive can
		// and cannot give back. An archive made before v2.34.0 has no database
		// in it, and a site restored from one comes back with its old files
		// and its current content.
		if siteHasDBs && !archiveHasDBs {
			emit("databases", "This backup contains files only", "error", new(
				"It was made before DockPanel included databases in site backups, or its database dump failed. "+
					"Your site's database will NOT be restored and its content will stay as it is now. "+
					"Restore the database separately from the Databases page if that is what you need."))
		}

		emit("restore", "Restoring backup", "in_progress", nil)

		// The agent answers 500 with a structured report when it restored the
		// files but could not load a database — the body is the useful part.
		report, err := agent.Post(ctx, fmt.Sprintf("/backups/%s/restore/%s", domain, filename), agentBody)
		var ae *AgentError
		if err != nil && errors.As(err, &ae) && ae.Kind == AgentErrStatus {
			var v map[string]any
			d := json.NewDecoder(strings.NewReader(ae.Msg))
			d.UseNumber()
			if d.Decode(&v) == nil && v != nil {
				if _, ok := v["files_restored"]; ok {
					report, err = v, nil
				}
			}
			if err != nil {
				err = &AgentError{Kind: AgentErrStatus, Code: 500, Msg: ae.Msg}
			}
		}
		if err != nil {
			emit("restore", "Restoring backup", "error", new(err.Error()))
			emit("complete", "Restore failed", "error", nil)
			slog.Error(fmt.Sprintf("Backup restore failed for %s: %v", domain, err))
			return
		}

		filesRestored, ok := jsonBool(jsonGet(report, "files_restored"))
		if !ok {
			filesRestored = true
		}
		restored := rtBackupsStrings(jsonGet(report, "databases_restored"))
		failed := rtBackupsFailures(jsonGet(report, "databases_failed"))

		if len(failed) > 0 {
			// The dangerous state: files are already replaced.
			emit("restore", "Restore incomplete", "error", new(fmt.Sprintf(
				"The site's FILES have been restored, but %d database(s) could not be: %s. "+
					"The site is now running restored files against its previous database content.",
				len(failed), strings.Join(failed, "; "))))
			emit("complete", "Restore failed — files restored, database not", "error", nil)
			slog.Error(fmt.Sprintf("Restore incomplete for %s: files_restored=%v, database failures: %s",
				domain, filesRestored, strings.Join(failed, "; ")))
			ActivityLogActivity(ctx, db, userID, email, "backup.restore_partial",
				new("backup"), new(domain), new(filename), ip, keyID)
			SecurityHardeningAuditLog(ctx, db, "backup.restore_partial", new(email), ip,
				new("backup"), new(domain), new(filename), nil, "warning", keyID)
			return
		}

		if len(restored) == 0 {
			emit("restore", "Restoring backup", "done", nil)
		} else {
			emit("restore", fmt.Sprintf("Restored files and %d database(s): %s", len(restored), strings.Join(restored, ", ")), "done", nil)
		}

		// Post-restore: reload services to pick up restored files.
		emit("services", "Reloading services", "in_progress", nil)

		// Reload nginx to pick up any config changes.
		_, _ = agent.Post(ctx, "/diagnostics/fix", map[string]any{"fix_id": "restart-service:nginx"})

		// Restart PHP-FPM if the site uses PHP (clear OPcache).
		siteInfo, err := queryOpt[Tup2[string, *string]](ctx, db, "SELECT runtime, php_version FROM sites WHERE id = $1", id)
		if err != nil {
			slog.Warn(fmt.Sprintf("DB error fetching site info for post-restore reload: %v", err))
			siteInfo = nil
		}
		if siteInfo != nil && siteInfo.A == "php" && siteInfo.B != nil {
			_, _ = agent.Post(ctx, "/diagnostics/fix", map[string]any{
				"fix_id": fmt.Sprintf("restart-service:php%s-fpm", *siteInfo.B),
			})
		}

		// Invalidate nginx cache for this domain.
		_, _ = agent.Post(ctx, "/diagnostics/fix", map[string]any{"fix_id": "clean-cache:" + domain})

		emit("services", "Services reloaded", "done", nil)
		slog.Info("Post-restore service reload completed for " + domain)

		emit("complete", "Backup restored", "done", nil)
		slog.Info(fmt.Sprintf("Backup restored: %s for %s", filename, domain))
		ActivityLogActivity(ctx, db, userID, email, "backup.restore",
			new("backup"), new(domain), new(filename), ip, keyID)
		SecurityHardeningAuditLog(ctx, db, "backup.restore", new(email), ip,
			new("backup"), new(domain), new(filename), nil, "info", keyID)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"restore_id": restoreID,
		"message":    "Restore started",
	})
	return nil
}

// rtBackupsRemove is DELETE /api/sites/{id}/backups/{backup_id}.
func rtBackupsRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	backupID, err := pathUUID(r, "backup_id")
	if err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, claims)
	if err != nil {
		return err
	}
	backup, err := queryOpt[rtBackupsBackup](r.Context(), st.DB,
		"SELECT * FROM backups WHERE id = $1 AND site_id = $2", backupID, id)
	if err != nil {
		return internalError("remove backups", err)
	}
	if backup == nil {
		return apiErr(http.StatusNotFound, "Backup not found")
	}

	// Delete from agent (must succeed before DB deletion).
	if _, err := agent.Delete(r.Context(), fmt.Sprintf("/backups/%s/%s", domain, backup.Filename)); err != nil {
		return agentError("Backup deletion", err)
	}
	if _, err := execSQL(r.Context(), st.DB, "DELETE FROM backups WHERE id = $1", backupID); err != nil {
		return internalError("remove backups", err)
	}
	slog.Info(fmt.Sprintf("Backup deleted: %s for %s", backup.Filename, domain))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}
