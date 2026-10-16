package api

// Port of panel/backend/src/routes/backup_schedules.rs.

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtBackupSchedulesRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/sites/{id}/backup-schedule", h(rtBackupSchedulesGetSchedule))
	r.Handle("PUT /api/sites/{id}/backup-schedule", h(rtBackupSchedulesSetSchedule))
	r.Handle("DELETE /api/sites/{id}/backup-schedule", h(rtBackupSchedulesRemoveSchedule))
	r.Handle("GET /api/backup-setup-status", h(rtBackupSchedulesSetupStatus))
}

type rtBackupSchedulesBackupSchedule struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	SiteID         uuid.UUID  `json:"site_id" db:"site_id"`
	DestinationID  *uuid.UUID `json:"destination_id" db:"destination_id"`
	Schedule       string     `json:"schedule" db:"schedule"`
	RetentionCount int32      `json:"retention_count" db:"retention_count"`
	Enabled        bool       `json:"enabled" db:"enabled"`
	LastRun        *time.Time `json:"last_run" db:"last_run"`
	LastStatus     *string    `json:"last_status" db:"last_status"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

type rtBackupSchedulesSetScheduleRequest struct {
	DestinationID  uuid.UUID `json:"destination_id"`
	Schedule       string    `json:"schedule"`
	RetentionCount *int32    `json:"retention_count"`
	Enabled        *bool     `json:"enabled"`
}

// rtBackupSchedulesGetSchedule is GET /api/sites/{id}/backup-schedule.
func rtBackupSchedulesGetSchedule(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if _, err := siteDomainForCaller(r.Context(), st, id, claims); err != nil {
		return err
	}
	schedule, err := queryOpt[rtBackupSchedulesBackupSchedule](r.Context(), st.DB,
		"SELECT * FROM backup_schedules WHERE site_id = $1", id)
	if err != nil {
		return internalError("get schedule", err)
	}
	writeJSON(w, http.StatusOK, schedule)
	return nil
}

// rtBackupSchedulesSetSchedule is PUT /api/sites/{id}/backup-schedule —
// create or update.
func rtBackupSchedulesSetSchedule(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtBackupSchedulesSetScheduleRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	domain, err := siteDomainForCaller(r.Context(), st, id, claims)
	if err != nil {
		return err
	}

	// Validate schedule format.
	if len(strings.Fields(body.Schedule)) != 5 {
		return apiErr(http.StatusBadRequest, "Schedule must have 5 fields (minute hour day month weekday)")
	}

	// Verify the destination exists and is one this user may send backups to.
	//
	// The inner JOIN this replaced could never match: server_id is NULL on
	// every destination the panel ever made, so this answered 403 for every
	// destination that existed. A NULL server_id means unscoped — any user may
	// target it (destinations are admin-created; a site owner can upload to
	// one but never read it). A destination pinned to a server still has to
	// belong to this user. The rule lives once, next to the route that LISTS
	// the same set.
	destCheck, _ := queryScalarOpt[uuid.UUID](r.Context(), st.DB,
		"SELECT bd.id FROM backup_destinations bd "+
			"LEFT JOIN servers s ON bd.server_id = s.id "+
			"WHERE "+rtBackupDestinationsDestinationCallerPredicate+" AND bd.id = $2",
		claims.Sub, body.DestinationID)
	if destCheck == nil {
		return apiErr(http.StatusForbidden, "Destination not found or not owned by you")
	}

	retention := int32(7)
	if body.RetentionCount != nil {
		retention = *body.RetentionCount
	}
	retention = min(max(retention, 1), 365)
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}

	// Upsert (unique on site_id).
	schedule, err := queryOne[rtBackupSchedulesBackupSchedule](r.Context(), st.DB,
		"INSERT INTO backup_schedules (site_id, destination_id, schedule, retention_count, enabled) "+
			"VALUES ($1, $2, $3, $4, $5) "+
			"ON CONFLICT (site_id) DO UPDATE SET "+
			"destination_id = $2, schedule = $3, retention_count = $4, enabled = $5, updated_at = NOW() "+
			"RETURNING *",
		id, body.DestinationID, strings.TrimSpace(body.Schedule), retention, enabled)
	if err != nil {
		return internalError("set schedule", err)
	}

	slog.Info(fmt.Sprintf("Backup schedule set for %s: %s", domain, schedule.Schedule))
	ActivityLogActivity(r.Context(), st.DB, claims.Sub, claims.Email, "backup.schedule",
		new("backup"), new(domain), new(schedule.Schedule), nil, claims.KeyID)
	writeJSON(w, http.StatusOK, schedule)
	return nil
}

// rtBackupSchedulesRemoveSchedule is DELETE /api/sites/{id}/backup-schedule.
func rtBackupSchedulesRemoveSchedule(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	domain, err := siteDomainForCaller(r.Context(), st, id, claims)
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM backup_schedules WHERE site_id = $1", id)
	if err != nil {
		return internalError("remove schedule", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "No schedule found")
	}
	slog.Info("Backup schedule removed for " + domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

type rtBackupSchedulesBackupSetupStatus struct {
	HasSchedule bool `json:"has_schedule"`
	HasBackup   bool `json:"has_backup"`
}

// rtBackupSchedulesSetupStatus is GET /api/backup-setup-status — whether the
// caller has any backup schedule or any stored backup (site, database, or
// volume), for the Dashboard onboarding step "Set up backups".
func rtBackupSchedulesSetupStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	scheduleCount, err := queryScalar[int64](ctx, st.DB,
		"SELECT COUNT(*) FROM backup_schedules bs "+
			"JOIN sites s ON s.id = bs.site_id "+
			"WHERE s.user_id = $1", claims.Sub)
	if err != nil {
		return internalError("setup-status schedules", err)
	}
	siteBk, err := queryScalar[int64](ctx, st.DB,
		"SELECT COUNT(*) FROM backups b "+
			"JOIN sites s ON s.id = b.site_id "+
			"WHERE s.user_id = $1", claims.Sub)
	if err != nil {
		return internalError("setup-status backups", err)
	}
	dbBk, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM database_backups")
	if err != nil {
		return internalError("setup-status db_backups", err)
	}
	volBk, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM volume_backups")
	if err != nil {
		return internalError("setup-status volume_backups", err)
	}
	writeJSON(w, http.StatusOK, rtBackupSchedulesBackupSetupStatus{
		HasSchedule: scheduleCount > 0,
		HasBackup:   siteBk+dbBk+volBk > 0,
	})
	return nil
}
