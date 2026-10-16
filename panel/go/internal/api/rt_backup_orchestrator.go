package api

// Port of panel/backend/src/routes/backup_orchestrator.rs.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtBackupOrchestratorRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/backup-orchestrator/all", h(rtBackupOrchestratorListAllBackups))
	r.Handle("GET /api/backup-orchestrator/health", h(rtBackupOrchestratorHealth))
	r.Handle("GET /api/backup-orchestrator/preflight", h(rtBackupOrchestratorPreflight))
	r.Handle("GET /api/backup-orchestrator/policies", h(rtBackupOrchestratorListPolicies))
	r.Handle("POST /api/backup-orchestrator/policies", h(rtBackupOrchestratorCreatePolicy))
	r.Handle("POST /api/backup-orchestrator/policies/protect-all", h(rtBackupOrchestratorProtectAll))
	r.Handle("PUT /api/backup-orchestrator/policies/{id}", h(rtBackupOrchestratorUpdatePolicy))
	r.Handle("DELETE /api/backup-orchestrator/policies/{id}", h(rtBackupOrchestratorDeletePolicy))
	r.Handle("POST /api/backup-orchestrator/db-backup", h(rtBackupOrchestratorCreateDbBackup))
	r.Handle("GET /api/backup-orchestrator/db-backups", h(rtBackupOrchestratorListDbBackups))
	r.Handle("DELETE /api/backup-orchestrator/db-backups/{id}", h(rtBackupOrchestratorDeleteDbBackup))
	r.Handle("POST /api/backup-orchestrator/db-backups/{id}/restore", h(rtBackupOrchestratorRestoreDbBackup))
	r.Handle("POST /api/backup-orchestrator/volume-backup", h(rtBackupOrchestratorCreateVolumeBackup))
	r.Handle("GET /api/backup-orchestrator/volume-backups", h(rtBackupOrchestratorListVolumeBackups))
	r.Handle("POST /api/backup-orchestrator/volume-backups/{id}/restore", h(rtBackupOrchestratorRestoreVolumeBackup))
	r.Handle("POST /api/backup-orchestrator/verify", h(rtBackupOrchestratorTriggerVerify))
	r.Handle("GET /api/backup-orchestrator/verifications", h(rtBackupOrchestratorListVerifications))
	r.Handle("POST /api/backup-orchestrator/drill", h(rtBackupOrchestratorTriggerDrill))
	r.Handle("GET /api/backup-orchestrator/drills", h(rtBackupOrchestratorListDrills))
	r.Handle("GET /api/backup-orchestrator/chain-report/{kind}/{id}", h(rtBackupOrchestratorChainReportJSON))
	r.Handle("GET /api/backup-orchestrator/chain-report/{kind}/{id}/pdf", h(rtBackupOrchestratorChainReportPDF))
	r.Handle("GET /api/backup-orchestrator/storage-history", h(rtBackupOrchestratorStorageHistory))
}

// ── Types ───────────────────────────────────────────────────────────────────

type rtBackupOrchestratorBackupPolicy struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	UserID            uuid.UUID  `json:"user_id" db:"user_id"`
	ServerID          *uuid.UUID `json:"server_id" db:"server_id"`
	Name              string     `json:"name" db:"name"`
	BackupSites       bool       `json:"backup_sites" db:"backup_sites"`
	BackupDatabases   bool       `json:"backup_databases" db:"backup_databases"`
	BackupVolumes     bool       `json:"backup_volumes" db:"backup_volumes"`
	Schedule          string     `json:"schedule" db:"schedule"`
	DestinationID     *uuid.UUID `json:"destination_id" db:"destination_id"`
	RetentionCount    int32      `json:"retention_count" db:"retention_count"`
	Encrypt           bool       `json:"encrypt" db:"encrypt"`
	VerifyAfterBackup bool       `json:"verify_after_backup" db:"verify_after_backup"`
	Enabled           bool       `json:"enabled" db:"enabled"`
	DrillEnabled      bool       `json:"drill_enabled" db:"drill_enabled"`
	DrillSchedule     string     `json:"drill_schedule" db:"drill_schedule"`
	LastDrillAt       *time.Time `json:"last_drill_at" db:"last_drill_at"`
	LastRun           *time.Time `json:"last_run" db:"last_run"`
	LastStatus        *string    `json:"last_status" db:"last_status"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
}

type rtBackupOrchestratorCreatePolicyRequest struct {
	Name              string     `json:"name"`
	ServerID          *uuid.UUID `json:"server_id"`
	BackupSites       *bool      `json:"backup_sites"`
	BackupDatabases   *bool      `json:"backup_databases"`
	BackupVolumes     *bool      `json:"backup_volumes"`
	Schedule          *string    `json:"schedule"`
	DestinationID     *uuid.UUID `json:"destination_id"`
	RetentionCount    *int32     `json:"retention_count"`
	Encrypt           *bool      `json:"encrypt"`
	VerifyAfterBackup *bool      `json:"verify_after_backup"`
	Enabled           *bool      `json:"enabled"`
	DrillEnabled      *bool      `json:"drill_enabled"`
	DrillSchedule     *string    `json:"drill_schedule"`
}

// rtBackupOrchestratorDoubleOption distinguishes "the caller omitted this
// field" (Set false) from "the caller sent null" (Set true, Val nil).
//
// destination_id needs both: omitting it must preserve the attached
// destination, while sending null is how the operator detaches one. With a
// plain pointer the two are the same value, which is why a partial PUT used
// to silently NULL the very destination the preflight asks to attach.
type rtBackupOrchestratorDoubleOption struct {
	Set bool
	Val *uuid.UUID
}

func (d *rtBackupOrchestratorDoubleOption) UnmarshalJSON(b []byte) error {
	d.Set = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		d.Val = nil
		return nil
	}
	var u uuid.UUID
	if err := json.Unmarshal(b, &u); err != nil {
		return err
	}
	d.Val = &u
	return nil
}

func (d rtBackupOrchestratorDoubleOption) or(cur *uuid.UUID) *uuid.UUID {
	if d.Set {
		return d.Val
	}
	return cur
}

// rtBackupOrchestratorUpdatePolicyRequest is the PUT body. Separate from the
// create request because on create an absent field means "use the default",
// while on update it means "leave it as it is" — the same nil standing for two
// intentions is what made this endpoint destructive.
type rtBackupOrchestratorUpdatePolicyRequest struct {
	Name              string                           `json:"name"`
	ServerID          rtBackupOrchestratorDoubleOption `json:"server_id" serde:"default"`
	BackupSites       *bool                            `json:"backup_sites"`
	BackupDatabases   *bool                            `json:"backup_databases"`
	BackupVolumes     *bool                            `json:"backup_volumes"`
	Schedule          *string                          `json:"schedule"`
	DestinationID     rtBackupOrchestratorDoubleOption `json:"destination_id" serde:"default"`
	RetentionCount    *int32                           `json:"retention_count"`
	Encrypt           *bool                            `json:"encrypt"`
	VerifyAfterBackup *bool                            `json:"verify_after_backup"`
	Enabled           *bool                            `json:"enabled"`
	DrillEnabled      *bool                            `json:"drill_enabled"`
	DrillSchedule     *string                          `json:"drill_schedule"`
}

// rtBackupOrchestratorIsValidCron5 rejects obviously-invalid cron strings
// before they hit the DB. The scheduler's parser is 5-field
// whitespace-separated.
func rtBackupOrchestratorIsValidCron5(field string) bool {
	parts := strings.Fields(field)
	if len(parts) != 5 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 32 {
			return false
		}
	}
	return true
}

type rtBackupOrchestratorDatabaseBackup struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	DatabaseID uuid.UUID  `json:"database_id" db:"database_id"`
	ServerID   *uuid.UUID `json:"server_id" db:"server_id"`
	Filename   string     `json:"filename" db:"filename"`
	SizeBytes  int64      `json:"size_bytes" db:"size_bytes"`
	DbType     string     `json:"db_type" db:"db_type"`
	DbName     string     `json:"db_name" db:"db_name"`
	Encrypted  bool       `json:"encrypted" db:"encrypted"`
	// Which derivation actually produced this file's passphrase — restore
	// MUST use this, not the current version, or a backup written under an
	// older derivation becomes permanently unrestorable.
	EncryptionKeyVersion int16     `json:"encryption_key_version" db:"encryption_key_version"`
	Uploaded             bool      `json:"uploaded" db:"uploaded"`
	CreatedAt            time.Time `json:"created_at" db:"created_at"`
	Sha256Hash           *string   `json:"sha256_hash" db:"sha256_hash"`
	PreviousHash         *string   `json:"previous_hash" db:"previous_hash"`
}

type rtBackupOrchestratorVolumeBackup struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	ContainerID   string     `json:"container_id" db:"container_id"`
	ContainerName string     `json:"container_name" db:"container_name"`
	ServerID      *uuid.UUID `json:"server_id" db:"server_id"`
	VolumeName    string     `json:"volume_name" db:"volume_name"`
	Filename      string     `json:"filename" db:"filename"`
	SizeBytes     int64      `json:"size_bytes" db:"size_bytes"`
	Encrypted     bool       `json:"encrypted" db:"encrypted"`
	Uploaded      bool       `json:"uploaded" db:"uploaded"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	Sha256Hash    *string    `json:"sha256_hash" db:"sha256_hash"`
	PreviousHash  *string    `json:"previous_hash" db:"previous_hash"`
}

type rtBackupOrchestratorBackupVerification struct {
	ID           uuid.UUID       `json:"id" db:"id"`
	BackupType   string          `json:"backup_type" db:"backup_type"`
	BackupID     uuid.UUID       `json:"backup_id" db:"backup_id"`
	ServerID     *uuid.UUID      `json:"server_id" db:"server_id"`
	Status       string          `json:"status" db:"status"`
	ChecksRun    int32           `json:"checks_run" db:"checks_run"`
	ChecksPassed int32           `json:"checks_passed" db:"checks_passed"`
	Details      json.RawMessage `json:"details" db:"details"`
	ErrorMessage *string         `json:"error_message" db:"error_message"`
	DurationMs   *int32          `json:"duration_ms" db:"duration_ms"`
	StartedAt    *time.Time      `json:"started_at" db:"started_at"`
	CompletedAt  *time.Time      `json:"completed_at" db:"completed_at"`
	CreatedAt    time.Time       `json:"created_at" db:"created_at"`
}

type rtBackupOrchestratorBackupDrill struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	BackupType   string     `json:"backup_type" db:"backup_type"`
	BackupID     uuid.UUID  `json:"backup_id" db:"backup_id"`
	ServerID     *uuid.UUID `json:"server_id" db:"server_id"`
	TriggeredBy  *uuid.UUID `json:"triggered_by" db:"triggered_by"`
	Status       string     `json:"status" db:"status"`
	HTTPStatus   *int32     `json:"http_status" db:"http_status"`
	BodyExcerpt  *string    `json:"body_excerpt" db:"body_excerpt"`
	ErrorMessage *string    `json:"error_message" db:"error_message"`
	DurationMs   *int32     `json:"duration_ms" db:"duration_ms"`
	StartedAt    *time.Time `json:"started_at" db:"started_at"`
	CompletedAt  *time.Time `json:"completed_at" db:"completed_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

type rtBackupOrchestratorPaginationQuery struct {
	Limit  *int64 `json:"limit"`
	Offset *int64 `json:"offset"`
}

// ── Unified Backup View (fleet-wide) ────────────────────────────────────────

type rtBackupOrchestratorUnifiedBackupsQuery struct {
	Limit    *int64     `json:"limit"`
	Offset   *int64     `json:"offset"`
	Kind     *string    `json:"kind"`
	ServerID *uuid.UUID `json:"server_id"`
}

type rtBackupOrchestratorUnifiedBackupRow struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	Kind          string     `json:"kind" db:"kind"`
	ResourceID    *uuid.UUID `json:"resource_id" db:"resource_id"`
	ResourceName  string     `json:"resource_name" db:"resource_name"`
	Filename      string     `json:"filename" db:"filename"`
	SizeBytes     int64      `json:"size_bytes" db:"size_bytes"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	ServerID      *uuid.UUID `json:"server_id" db:"server_id"`
	ServerName    string     `json:"server_name" db:"server_name"`
	ServerIsLocal bool       `json:"server_is_local" db:"server_is_local"`
	Encrypted     bool       `json:"encrypted" db:"encrypted"`
	Uploaded      bool       `json:"uploaded" db:"uploaded"`
	ExtraType     *string    `json:"extra_type" db:"extra_type"`
}

type rtBackupOrchestratorUnifiedBackupsResponse struct {
	Items []rtBackupOrchestratorUnifiedBackupRow `json:"items"`
	Total int64                                  `json:"total"`
}

// ── Health Dashboard ────────────────────────────────────────────────────────

type rtBackupOrchestratorBackupHealth struct {
	TotalSiteBackups     int64                             `json:"total_site_backups"`
	TotalDbBackups       int64                             `json:"total_db_backups"`
	TotalVolumeBackups   int64                             `json:"total_volume_backups"`
	TotalStorageBytes    int64                             `json:"total_storage_bytes"`
	Last24hSuccess       int64                             `json:"last_24h_success"`
	Last24hFailed        int64                             `json:"last_24h_failed"`
	PoliciesActive       int64                             `json:"policies_active"`
	PoliciesTotal        int64                             `json:"policies_total"`
	VerificationsPassed  int64                             `json:"verifications_passed"`
	VerificationsFailed  int64                             `json:"verifications_failed"`
	OldestUnverifiedDays *int64                            `json:"oldest_unverified_days"`
	StaleBackups         []rtBackupOrchestratorStaleBackup `json:"stale_backups"`
	// SLA windowed view (W1.1): "of the last N backups, how many are verified?"
	SlaWindow         int64                           `json:"sla_window"`
	SlaVerified       int64                           `json:"sla_verified"`
	SlaFailed         int64                           `json:"sla_failed"`
	SlaPending        int64                           `json:"sla_pending"`
	VerifyLagP50Hours *float64                        `json:"verify_lag_p50_hours"`
	VerifyLagP95Hours *float64                        `json:"verify_lag_p95_hours"`
	PerServerSla      []rtBackupOrchestratorServerSla `json:"per_server_sla"`
	// The SLA figures above could not be computed. Zeroes then mean "not
	// measured", NOT "nothing to measure" — for six releases the card showed
	// its empty state on every install because a query referenced a column
	// that does not exist.
	SlaUnavailable bool `json:"sla_unavailable"`
	// Drill counts (Phase 4 W1.2): end-to-end restore probes in last 30d.
	DrillsPassed30d int64 `json:"drills_passed_30d"`
	DrillsFailed30d int64 `json:"drills_failed_30d"`
}

type rtBackupOrchestratorStaleBackup struct {
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	// nil = this resource has never been backed up — the worst case the list
	// reports, so it must be representable rather than a decode failure.
	LastBackup *time.Time `json:"last_backup"`
	DaysSince  *int64     `json:"days_since"`
}

type rtBackupOrchestratorServerSla struct {
	ServerID    *uuid.UUID `json:"server_id"`
	ServerName  string     `json:"server_name"`
	Verified    int64      `json:"verified"`
	Total       int64      `json:"total"`
	LagP95Hours *float64   `json:"lag_p95_hours"`
}

// rtBackupOrchestratorListAllBackups is GET /api/backup-orchestrator/all —
// unified backup list across site, database, and volume backups.
//
// Scoped, not truly fleet-wide despite the name: an admin sees the local
// server plus any server THEY registered. Before this fix AdminUser alone
// gated it, handing every admin the backup ids and resource names of the
// ENTIRE fleet — the discovery channel into the unscoped chain-report
// endpoints. A NULL server_id predates the fleet backfill and is treated as
// local, visible to every admin like any other local-server row.
func rtBackupOrchestratorListAllBackups(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var params rtBackupOrchestratorUnifiedBackupsQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	limit, offset := paginate(params.Limit, params.Offset)

	var kindFilter *string
	if params.Kind != nil {
		switch *params.Kind {
		case "site", "database", "volume":
			kindFilter = params.Kind
		default:
			return apiErr(http.StatusBadRequest, "kind must be one of: site, database, volume")
		}
	}

	// CTE unions the three backup tables into a common shape. Site backups
	// derive server_id from sites (backups has no server_id column).
	cte := "WITH unified AS ( " +
		"SELECT b.id, 'site'::text AS kind, b.site_id AS resource_id, s.domain AS resource_name, " +
		"b.filename, b.size_bytes, b.created_at, s.server_id, " +
		"FALSE AS encrypted, b.uploaded, NULL::text AS extra_type " +
		"FROM backups b JOIN sites s ON s.id = b.site_id " +
		"UNION ALL " +
		"SELECT db.id, 'database'::text, db.database_id, db.db_name, " +
		"db.filename, db.size_bytes, db.created_at, db.server_id, " +
		"db.encrypted, db.uploaded, db.db_type " +
		"FROM database_backups db " +
		"UNION ALL " +
		"SELECT vb.id, 'volume'::text, NULL::uuid, " +
		"(vb.container_name || ':' || vb.volume_name) AS resource_name, " +
		"vb.filename, vb.size_bytes, vb.created_at, vb.server_id, " +
		"vb.encrypted, vb.uploaded, NULL::text " +
		"FROM volume_backups vb " +
		")"

	items, err := queryAll[rtBackupOrchestratorUnifiedBackupRow](r.Context(), st.DB,
		cte+" SELECT u.id, u.kind, u.resource_id, u.resource_name, u.filename, u.size_bytes, "+
			"u.created_at, u.server_id, "+
			"COALESCE(srv.name, 'local') AS server_name, "+
			"COALESCE(srv.is_local, TRUE) AS server_is_local, "+
			"u.encrypted, u.uploaded, u.extra_type "+
			"FROM unified u LEFT JOIN servers srv ON srv.id = u.server_id "+
			"WHERE ($1::uuid IS NULL OR u.server_id = $1) "+
			"AND ($2::text IS NULL OR u.kind = $2) "+
			"AND (u.server_id IS NULL OR srv.is_local OR srv.user_id = $5) "+
			"ORDER BY u.created_at DESC LIMIT $3 OFFSET $4",
		params.ServerID, kindFilter, limit, offset, claims.Sub)
	if err != nil {
		return internalError("list all backups", err)
	}

	total, err := queryScalar[int64](r.Context(), st.DB,
		cte+" SELECT COUNT(*)::bigint FROM unified u LEFT JOIN servers srv ON srv.id = u.server_id "+
			"WHERE ($1::uuid IS NULL OR u.server_id = $1) "+
			"AND ($2::text IS NULL OR u.kind = $2) "+
			"AND (u.server_id IS NULL OR srv.is_local OR srv.user_id = $3) ",
		params.ServerID, kindFilter, claims.Sub)
	if err != nil {
		return internalError("list all backups count", err)
	}
	writeJSON(w, http.StatusOK, rtBackupOrchestratorUnifiedBackupsResponse{Items: items, Total: total})
	return nil
}

// rtBackupOrchestratorPreflight is GET /api/backup-orchestrator/preflight —
// backup prerequisites. Answers the question the Overview tab could not: will
// any of this survive losing the machine? One result per enabled policy, plus
// whether anything is scheduled at all.
func rtBackupOrchestratorPreflight(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	ctx := r.Context()
	sites, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM sites")
	if err != nil {
		return internalError("preflight", err)
	}
	destinations, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM backup_destinations")
	if err != nil {
		return internalError("preflight", err)
	}

	// LEFT JOIN so a policy pointing at a deleted destination is
	// distinguishable from one that never chose: destination_id set with a
	// NULL name.
	policies, err := queryAll[Tup3[string, *uuid.UUID, *string]](ctx, st.DB,
		"SELECT p.name, p.destination_id, d.name "+
			"FROM backup_policies p "+
			"LEFT JOIN backup_destinations d ON d.id = p.destination_id "+
			"WHERE p.enabled = TRUE ORDER BY p.created_at")
	if err != nil {
		return internalError("preflight policies", err)
	}

	checks := []any{PrerequisitesBackupsCheckAnyPolicyEnabled(len(policies), int(sites))}
	for _, p := range policies {
		checks = append(checks, PrerequisitesBackupsCheckBackupDestination(&PrerequisitesBackupsPolicyDestinationFacts{
			PolicyName:            p.A,
			DestinationExists:     p.B != nil && p.C != nil,
			DestinationID:         p.B,
			DestinationName:       p.C,
			DestinationsAvailable: int(destinations),
		}))
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": checks})
	return nil
}

// rtBackupOrchestratorHealth is GET /api/backup-orchestrator/health — the
// global backup health dashboard.
func rtBackupOrchestratorHealth(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	ctx := r.Context()
	db := st.DB
	count := func(sql string) (int64, error) {
		n, err := queryScalar[int64](ctx, db, sql)
		if err != nil {
			return 0, internalError("health", err)
		}
		return n, nil
	}
	sum := func(sql string) (int64, error) {
		n, err := queryScalar[*int64](ctx, db, sql)
		if err != nil {
			return 0, internalError("health", err)
		}
		if n == nil {
			return 0, nil
		}
		return *n, nil
	}

	var h rtBackupOrchestratorBackupHealth
	var err error
	if h.TotalSiteBackups, err = count("SELECT COUNT(*) FROM backups"); err != nil {
		return err
	}
	if h.TotalDbBackups, err = count("SELECT COUNT(*) FROM database_backups"); err != nil {
		return err
	}
	if h.TotalVolumeBackups, err = count("SELECT COUNT(*) FROM volume_backups"); err != nil {
		return err
	}
	// SUM(BIGINT) returns NUMERIC in postgres — cast back to bigint. Empty
	// rowsets give NULL; populated ones used to 500 until this cast.
	siteStorage, err := sum("SELECT SUM(size_bytes)::bigint FROM backups")
	if err != nil {
		return err
	}
	dbStorage, err := sum("SELECT SUM(size_bytes)::bigint FROM database_backups")
	if err != nil {
		return err
	}
	volStorage, err := sum("SELECT SUM(size_bytes)::bigint FROM volume_backups")
	if err != nil {
		return err
	}
	h.TotalStorageBytes = siteStorage + dbStorage + volStorage

	// Count successful schedules in last 24h.
	if h.Last24hSuccess, err = count("SELECT COUNT(*) FROM backup_schedules WHERE last_status = 'success' AND last_run > NOW() - INTERVAL '24 hours'"); err != nil {
		return err
	}
	if h.Last24hFailed, err = count("SELECT COUNT(*) FROM backup_schedules WHERE last_status = 'failed' AND last_run > NOW() - INTERVAL '24 hours'"); err != nil {
		return err
	}
	if h.PoliciesActive, err = count("SELECT COUNT(*) FROM backup_policies WHERE enabled = TRUE"); err != nil {
		return err
	}
	if h.PoliciesTotal, err = count("SELECT COUNT(*) FROM backup_policies"); err != nil {
		return err
	}
	if h.VerificationsPassed, err = count("SELECT COUNT(*) FROM backup_verifications WHERE status = 'passed'"); err != nil {
		return err
	}
	if h.VerificationsFailed, err = count("SELECT COUNT(*) FROM backup_verifications WHERE status = 'failed'"); err != nil {
		return err
	}

	// Find stale sites (no backup in > 7 days).
	//
	// The join admits only archives that landed where they were meant to: an
	// upload that exhausted its retries still writes a row, but it is not
	// off-site, so counting it would disarm this list for exactly the site
	// whose destination is down.
	//
	// last_backup is nullable because the HAVING clause deliberately admits
	// sites NEVER backed up; decoding that into a bare time failed the whole
	// fetch on the FIRST row (NULLS FIRST) and blanked the entire warning.
	staleSites, err := queryAll[Tup2[string, *time.Time]](ctx, db,
		"SELECT s.domain, MAX(b.created_at) as last_backup "+
			"FROM sites s LEFT JOIN backups b ON b.site_id = s.id "+
			"AND (b.destination_id IS NULL OR b.uploaded) "+
			"GROUP BY s.id, s.domain "+
			"HAVING MAX(b.created_at) IS NULL OR MAX(b.created_at) < NOW() - INTERVAL '7 days' "+
			"ORDER BY MAX(b.created_at) NULLS FIRST LIMIT 10")
	if err != nil {
		slog.Error(fmt.Sprintf("backup health: stale-site query failed: %v", err))
		staleSites = nil
	}
	now := time.Now()
	h.StaleBackups = []rtBackupOrchestratorStaleBackup{}
	for _, s := range staleSites {
		sb := rtBackupOrchestratorStaleBackup{ResourceType: "site", ResourceName: s.A, LastBackup: s.B}
		// nil = never backed up; days_since stays null rather than faked from
		// epoch so the UI can say so instead of printing "20789 days".
		if s.B != nil {
			sb.DaysSince = new(int64(now.Sub(*s.B) / (24 * time.Hour)))
		}
		h.StaleBackups = append(h.StaleBackups, sb)
	}

	// ── SLA windowed view (W1.1) ────────────────────────────────────────────
	// "Of the last N backups across all kinds, how many are verified?" Latest
	// verification per (kind, backup_id) wins.
	const slaWindow int64 = 30
	h.SlaWindow = slaWindow
	// `backups` has NO server_id column — a site reaches its server through
	// `sites`. Selecting it directly made this statement fail at PLAN time,
	// on every request, from the day the card shipped.
	sla, err := queryOne[Tup3[int64, int64, int64]](ctx, db,
		"WITH all_backups AS ( "+
			"SELECT b.id, b.created_at, s.server_id, 'site'::text AS kind "+
			"FROM backups b JOIN sites s ON s.id = b.site_id "+
			"UNION ALL "+
			"SELECT id, created_at, server_id, 'database'::text FROM database_backups "+
			"UNION ALL "+
			"SELECT id, created_at, server_id, 'volume'::text FROM volume_backups "+
			"), recent AS ( "+
			"SELECT * FROM all_backups ORDER BY created_at DESC LIMIT $1 "+
			"), latest_verif AS ( "+
			"SELECT DISTINCT ON (bv.backup_type, bv.backup_id) bv.backup_type, bv.backup_id, bv.status "+
			"FROM backup_verifications bv "+
			"JOIN recent r ON r.id = bv.backup_id AND r.kind = bv.backup_type "+
			"ORDER BY bv.backup_type, bv.backup_id, bv.created_at DESC "+
			") "+
			"SELECT "+
			"COUNT(*) FILTER (WHERE lv.status = 'passed')::bigint AS verified, "+
			"COUNT(*) FILTER (WHERE lv.status = 'failed')::bigint AS failed, "+
			"COUNT(*) FILTER (WHERE lv.status IS NULL OR lv.status IN ('pending','running'))::bigint AS pending "+
			"FROM recent r "+
			"LEFT JOIN latest_verif lv ON lv.backup_type = r.kind AND lv.backup_id = r.id", slaWindow)
	if err != nil {
		slog.Error(fmt.Sprintf("backup health: SLA window query failed: %v", err))
		h.SlaUnavailable = true
	} else {
		h.SlaVerified, h.SlaFailed, h.SlaPending = sla.A, sla.B, sla.C
	}

	// Verify lag percentiles: hours between backup creation and verification
	// completion, for backups created in the last 30 days that passed.
	if lag, err := queryOne[Tup2[*float64, *float64]](ctx, db,
		"WITH all_backups AS ( "+
			"SELECT id, created_at, 'site'::text AS kind FROM backups "+
			"UNION ALL "+
			"SELECT id, created_at, 'database'::text FROM database_backups "+
			"UNION ALL "+
			"SELECT id, created_at, 'volume'::text FROM volume_backups "+
			"), lags AS ( "+
			"SELECT EXTRACT(EPOCH FROM (bv.completed_at - ab.created_at)) / 3600.0 AS hours "+
			"FROM backup_verifications bv "+
			"JOIN all_backups ab ON ab.id = bv.backup_id AND ab.kind = bv.backup_type "+
			"WHERE bv.status = 'passed' "+
			"AND bv.completed_at IS NOT NULL "+
			"AND ab.created_at > NOW() - INTERVAL '30 days' "+
			") "+
			"SELECT "+
			"PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY hours)::float8 AS p50, "+
			"PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY hours)::float8 AS p95 "+
			"FROM lags"); err == nil {
		h.VerifyLagP50Hours, h.VerifyLagP95Hours = lag.A, lag.B
	}

	// Oldest unverified backup age in days (ignoring backups > 90d old).
	if v, err := queryScalar[*int64](ctx, db,
		"WITH all_backups AS ( "+
			"SELECT id, created_at, 'site'::text AS kind FROM backups "+
			"UNION ALL "+
			"SELECT id, created_at, 'database'::text FROM database_backups "+
			"UNION ALL "+
			"SELECT id, created_at, 'volume'::text FROM volume_backups "+
			") "+
			"SELECT EXTRACT(DAY FROM NOW() - MIN(ab.created_at))::bigint "+
			"FROM all_backups ab "+
			"LEFT JOIN backup_verifications bv "+
			"ON bv.backup_id = ab.id AND bv.backup_type = ab.kind AND bv.status = 'passed' "+
			"WHERE bv.id IS NULL "+
			"AND ab.created_at > NOW() - INTERVAL '90 days'"); err == nil {
		h.OldestUnverifiedDays = v
	}

	// Per-server SLA: same windowed view, grouped by server_id, over 30d so
	// the breakdown isn't dominated by whichever server backed up last.
	perServer, err := queryAll[Tup5[*uuid.UUID, string, int64, int64, *float64]](ctx, db,
		"WITH all_backups AS ( "+
			"SELECT b.id, b.created_at, s.server_id, 'site'::text AS kind "+
			"FROM backups b JOIN sites s ON s.id = b.site_id "+
			"UNION ALL "+
			"SELECT id, created_at, server_id, 'database'::text FROM database_backups "+
			"UNION ALL "+
			"SELECT id, created_at, server_id, 'volume'::text FROM volume_backups "+
			"), recent AS ( "+
			"SELECT * FROM all_backups WHERE created_at > NOW() - INTERVAL '30 days' "+
			"), latest_verif AS ( "+
			"SELECT DISTINCT ON (bv.backup_type, bv.backup_id) "+
			"bv.backup_type, bv.backup_id, bv.status, bv.completed_at "+
			"FROM backup_verifications bv "+
			"JOIN recent r ON r.id = bv.backup_id AND r.kind = bv.backup_type "+
			"ORDER BY bv.backup_type, bv.backup_id, bv.created_at DESC "+
			"), joined AS ( "+
			"SELECT r.server_id, r.created_at, lv.status, lv.completed_at "+
			"FROM recent r "+
			"LEFT JOIN latest_verif lv ON lv.backup_type = r.kind AND lv.backup_id = r.id "+
			") "+
			"SELECT "+
			"j.server_id, "+
			"COALESCE(s.name, '(local)') AS server_name, "+
			"COUNT(*) FILTER (WHERE j.status = 'passed')::bigint AS verified, "+
			"COUNT(*)::bigint AS total, "+
			"PERCENTILE_CONT(0.95) WITHIN GROUP ( "+
			"ORDER BY EXTRACT(EPOCH FROM (j.completed_at - j.created_at)) / 3600.0 "+
			") FILTER (WHERE j.status = 'passed' AND j.completed_at IS NOT NULL)::float8 AS lag_p95 "+
			"FROM joined j "+
			"LEFT JOIN servers s ON s.id = j.server_id "+
			"GROUP BY j.server_id, s.name "+
			"ORDER BY total DESC "+
			"LIMIT 20")
	if err != nil {
		slog.Error(fmt.Sprintf("backup health: per-server SLA query failed: %v", err))
		h.SlaUnavailable = true
		perServer = nil
	}
	h.PerServerSla = []rtBackupOrchestratorServerSla{}
	for _, p := range perServer {
		h.PerServerSla = append(h.PerServerSla, rtBackupOrchestratorServerSla{
			ServerID: p.A, ServerName: p.B, Verified: p.C, Total: p.D, LagP95Hours: p.E,
		})
	}

	// Drill counts (last 30d).
	if d, err := queryOne[Tup2[int64, int64]](ctx, db,
		"SELECT "+
			"COUNT(*) FILTER (WHERE status = 'passed')::bigint, "+
			"COUNT(*) FILTER (WHERE status = 'failed')::bigint "+
			"FROM backup_drills "+
			"WHERE created_at > NOW() - INTERVAL '30 days'"); err == nil {
		h.DrillsPassed30d, h.DrillsFailed30d = d.A, d.B
	}

	writeJSON(w, http.StatusOK, h)
	return nil
}

// ── Policies CRUD ───────────────────────────────────────────────────────────

// rtBackupOrchestratorListPolicies is GET /api/backup-orchestrator/policies.
func rtBackupOrchestratorListPolicies(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	policies, err := queryAll[rtBackupOrchestratorBackupPolicy](r.Context(), st.DB,
		"SELECT * FROM backup_policies WHERE user_id = $1 ORDER BY created_at DESC LIMIT 500", claims.Sub)
	if err != nil {
		return internalError("list policies", err)
	}
	writeJSON(w, http.StatusOK, policies)
	return nil
}

func rtBackupOrchestratorOr[T any](p *T, def T) T {
	if p != nil {
		return *p
	}
	return def
}

// rtBackupOrchestratorCreatePolicy is POST /api/backup-orchestrator/policies.
func rtBackupOrchestratorCreatePolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var req rtBackupOrchestratorCreatePolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	if req.Name == "" || len(req.Name) > 100 {
		return apiErr(http.StatusBadRequest, "Name must be 1-100 characters")
	}
	schedule := rtBackupOrchestratorOr(req.Schedule, "0 2 * * *")
	if !rtBackupOrchestratorIsValidCron5(schedule) {
		return apiErr(http.StatusBadRequest, "schedule must be a 5-field cron string")
	}
	drillSchedule := rtBackupOrchestratorOr(req.DrillSchedule, "0 4 * * 0")
	if !rtBackupOrchestratorIsValidCron5(drillSchedule) {
		return apiErr(http.StatusBadRequest, "drill_schedule must be a 5-field cron string")
	}
	retention := min(max(rtBackupOrchestratorOr(req.RetentionCount, 7), 1), 365)

	policy, err := queryOne[rtBackupOrchestratorBackupPolicy](r.Context(), st.DB,
		"INSERT INTO backup_policies (user_id, server_id, name, backup_sites, backup_databases, backup_volumes, "+
			"schedule, destination_id, retention_count, encrypt, verify_after_backup, enabled, "+
			"drill_enabled, drill_schedule) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) "+
			"RETURNING *",
		claims.Sub, req.ServerID, req.Name,
		rtBackupOrchestratorOr(req.BackupSites, true),
		rtBackupOrchestratorOr(req.BackupDatabases, true),
		rtBackupOrchestratorOr(req.BackupVolumes, false),
		schedule, req.DestinationID, retention,
		rtBackupOrchestratorOr(req.Encrypt, false),
		rtBackupOrchestratorOr(req.VerifyAfterBackup, false),
		rtBackupOrchestratorOr(req.Enabled, true),
		rtBackupOrchestratorOr(req.DrillEnabled, false),
		drillSchedule)
	if err != nil {
		return internalError("create policy", err)
	}

	ActivityLogActivity(r.Context(), st.DB, claims.Sub, claims.Email, "backup_policy.create",
		new("backup_policy"), new(req.Name), nil, nil, claims.KeyID)
	ExtensionsFireEvent(st.DB, "backup_policy.created", map[string]any{"policy_id": policy.ID, "name": req.Name})

	writeJSON(w, http.StatusCreated, policy)
	return nil
}

// rtBackupOrchestratorUpdatePolicy is PUT /api/backup-orchestrator/policies/{id}.
func rtBackupOrchestratorUpdatePolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req rtBackupOrchestratorUpdatePolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	// Verify ownership, and read the columns the UPDATE assigns
	// unconditionally so an omitted field keeps its current value.
	existing, err := queryOpt[Tup4[uuid.UUID, *uuid.UUID, *uuid.UUID, int32]](r.Context(), st.DB,
		"SELECT id, server_id, destination_id, retention_count FROM backup_policies WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("update policy", err)
	}
	if existing == nil {
		return apiErr(http.StatusNotFound, "Policy not found")
	}

	// Omitted -> keep. Explicit null -> clear. A value -> set.
	serverID := req.ServerID.or(existing.B)
	destinationID := req.DestinationID.or(existing.C)
	// Defaulting to 7 here meant an edit that did not mention retention
	// silently reset it — the same reset-on-omission class as the two above.
	retention := min(max(rtBackupOrchestratorOr(req.RetentionCount, existing.D), 1), 365)

	if req.Schedule != nil && *req.Schedule != "" && !rtBackupOrchestratorIsValidCron5(*req.Schedule) {
		return apiErr(http.StatusBadRequest, "schedule must be a 5-field cron string")
	}
	if req.DrillSchedule != nil && *req.DrillSchedule != "" && !rtBackupOrchestratorIsValidCron5(*req.DrillSchedule) {
		return apiErr(http.StatusBadRequest, "drill_schedule must be a 5-field cron string")
	}

	policy, err := queryOne[rtBackupOrchestratorBackupPolicy](r.Context(), st.DB,
		"UPDATE backup_policies SET "+
			"name = COALESCE(NULLIF($2, ''), name), "+
			"server_id = $3, "+
			"backup_sites = COALESCE($4, backup_sites), "+
			"backup_databases = COALESCE($5, backup_databases), "+
			"backup_volumes = COALESCE($6, backup_volumes), "+
			"schedule = COALESCE(NULLIF($7, ''), schedule), "+
			"destination_id = $8, "+
			"retention_count = $9, "+
			"encrypt = COALESCE($10, encrypt), "+
			"verify_after_backup = COALESCE($11, verify_after_backup), "+
			"enabled = COALESCE($12, enabled), "+
			"drill_enabled = COALESCE($13, drill_enabled), "+
			"drill_schedule = COALESCE(NULLIF($14, ''), drill_schedule), "+
			"updated_at = NOW() "+
			"WHERE id = $1 RETURNING *",
		id, req.Name, serverID, req.BackupSites, req.BackupDatabases, req.BackupVolumes,
		rtBackupOrchestratorOr(req.Schedule, ""), destinationID, retention,
		req.Encrypt, req.VerifyAfterBackup, req.Enabled, req.DrillEnabled,
		rtBackupOrchestratorOr(req.DrillSchedule, ""))
	if err != nil {
		return internalError("update policy", err)
	}
	writeJSON(w, http.StatusOK, policy)
	return nil
}

// rtBackupOrchestratorDeletePolicy is DELETE /api/backup-orchestrator/policies/{id}.
func rtBackupOrchestratorDeletePolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM backup_policies WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("delete policy", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Policy not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtBackupOrchestratorProtectAll is POST /api/backup-orchestrator/policies/protect-all
// — create a backup-everything policy.
func rtBackupOrchestratorProtectAll(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()
	const policyName = "Protect Everything"

	existing, err := queryScalarOpt[uuid.UUID](ctx, st.DB,
		"SELECT id FROM backup_policies WHERE user_id = $1 AND name = $2", claims.Sub, policyName)
	if err != nil {
		return internalError("protect all", err)
	}
	if existing != nil {
		return apiErr(http.StatusConflict, fmt.Sprintf("Policy '%s' already exists (id: %s)", policyName, *existing))
	}

	policy, err := queryOne[rtBackupOrchestratorBackupPolicy](ctx, st.DB,
		"INSERT INTO backup_policies (user_id, name, backup_sites, backup_databases, backup_volumes, "+
			"schedule, retention_count, encrypt, verify_after_backup, enabled) "+
			"VALUES ($1, $2, TRUE, TRUE, TRUE, '0 2 * * *', 7, FALSE, TRUE, TRUE) "+
			"RETURNING *", claims.Sub, policyName)
	if err != nil {
		return internalError("protect all", err)
	}

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "backup_policy.protect_all",
		new("backup_policy"), new(policyName), nil, nil, claims.KeyID)
	ExtensionsFireEvent(st.DB, "backup_policy.created", map[string]any{
		"policy_id": policy.ID, "name": policyName, "preset": "protect-all",
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":                  policy.ID,
		"name":                policyName,
		"schedule":            "0 2 * * *",
		"backup_sites":        true,
		"backup_databases":    true,
		"backup_volumes":      true,
		"retention_count":     7,
		"verify_after_backup": true,
	})
	return nil
}

// ── Database Backups ────────────────────────────────────────────────────────

type rtBackupOrchestratorCreateDbBackupRequest struct {
	DatabaseID uuid.UUID `json:"database_id"`
}

// rtBackupOrchestratorCreateDbBackup is POST /api/backup-orchestrator/db-backup.
func rtBackupOrchestratorCreateDbBackup(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var req rtBackupOrchestratorCreateDbBackupRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()

	// Fetch database details (join with sites for user ownership and server_id).
	row, err := queryOpt[Tup6[uuid.UUID, string, string, string, string, *uuid.UUID]](ctx, st.DB,
		"SELECT d.id, d.name, d.engine, d.db_user, d.db_password_enc, s.server_id "+
			"FROM databases d JOIN sites s ON d.site_id = s.id "+
			"WHERE d.id = $1 AND s.user_id = $2", req.DatabaseID, claims.Sub)
	if err != nil {
		return internalError("create db backup", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Database not found")
	}
	dbID, dbName, engine, user, passwordEnc, serverID := row.A, row.B, row.C, row.D, row.E, row.F

	// Dump on the host the SITE lives on. The dump used to go to whatever
	// agent the caller's server switcher named while the row was stamped with
	// s.server_id — written on host A, claiming host B. The verifier, the
	// drill scheduler and the retention pruner all act on the host the row
	// names, so a mislabelled archive is never verified, drilled or pruned.
	//
	// The credential is the sharper half: the body carries this database's
	// DECRYPTED password, so a stale server selection decided which machine
	// received it. Resolving before the decrypt keeps a refusal from ever
	// unwrapping it.
	agent, err := agentForSiteServer(ctx, st, serverID, "database "+dbName)
	if err != nil {
		return err
	}

	password := SecretsCryptoDecryptCredentialOrLegacy(passwordEnc, st.Config.JWTSecret)
	containerName := "dockpanel-db-" + dbName

	// Manual (ad-hoc) DB backups are not encrypted: only policy-driven backups
	// encrypt. The previous read of backup_destinations.encryption_key was dead
	// (nothing writes that column) and always yielded None.
	var encryptionKey *string

	result, err := agent.Post(ctx, "/db-backups/dump", map[string]any{
		"container_name": containerName,
		"db_name":        dbName,
		"db_type":        engine,
		"user":           user,
		"password":       password,
		"encryption_key": encryptionKey,
	})
	if err != nil {
		return agentError("Database backup", err)
	}

	filename, _ := jsonStr(jsonGet(result, "filename"))
	sizeU, _ := jsonU64(jsonGet(result, "size_bytes"))
	sizeBytes := int64(sizeU)
	encrypted := encryptionKey != nil

	// v2.8.2: integrity chain — same pattern as site backups.
	sha256Hash, _ := jsonStr(jsonGet(result, "sha256"))
	var previousHash *string
	if v, err := queryScalarOpt[*string](ctx, st.DB,
		"SELECT sha256_hash FROM database_backups WHERE database_id = $1 ORDER BY created_at DESC LIMIT 1", dbID); err == nil && v != nil {
		previousHash = *v
	}

	backup, err := queryOne[rtBackupOrchestratorDatabaseBackup](ctx, st.DB,
		"INSERT INTO database_backups (database_id, server_id, filename, size_bytes, db_type, db_name, encrypted, sha256_hash, previous_hash, chain_valid) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE) RETURNING *",
		dbID, serverID, filename, sizeBytes, engine, dbName, encrypted, backupPolicyExecutorShaArg(sha256Hash), previousHash)
	if err != nil {
		return internalError("create db backup", err)
	}

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "db_backup.create",
		new("database"), new(dbName), new(filename), nil, claims.KeyID)
	ExtensionsFireEvent(st.DB, "db_backup.created", map[string]any{
		"database": dbName, "filename": filename, "size_bytes": sizeBytes, "encrypted": encrypted,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         backup.ID,
		"filename":   filename,
		"size_bytes": sizeBytes,
		"encrypted":  encrypted,
	})
	return nil
}

// rtBackupOrchestratorListDbBackups is GET /api/backup-orchestrator/db-backups.
func rtBackupOrchestratorListDbBackups(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var params rtBackupOrchestratorPaginationQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	limit, offset := paginate(params.Limit, params.Offset)
	backups, err := queryAll[rtBackupOrchestratorDatabaseBackup](r.Context(), st.DB,
		"SELECT db.* FROM database_backups db "+
			"JOIN databases d ON d.id = db.database_id JOIN sites s ON d.site_id = s.id AND s.user_id = $1 "+
			"ORDER BY db.created_at DESC LIMIT $2 OFFSET $3", claims.Sub, limit, offset)
	if err != nil {
		return internalError("list db backups", err)
	}
	writeJSON(w, http.StatusOK, backups)
	return nil
}

func rtBackupOrchestratorUnsafeSegment(s string) bool {
	return strings.Contains(s, "/") || strings.Contains(s, "..") || strings.Contains(s, "\x00")
}

// rtBackupOrchestratorDeleteDbBackup is DELETE /api/backup-orchestrator/db-backups/{id}.
func rtBackupOrchestratorDeleteDbBackup(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	backup, err := queryOpt[rtBackupOrchestratorDatabaseBackup](ctx, st.DB,
		"SELECT db.* FROM database_backups db "+
			"JOIN databases d ON d.id = db.database_id JOIN sites s ON d.site_id = s.id AND s.user_id = $1 "+
			"WHERE db.id = $2", claims.Sub, id)
	if err != nil {
		return internalError("delete db backup", err)
	}
	if backup == nil {
		return apiErr(http.StatusNotFound, "Backup not found")
	}

	// Validate filename before constructing agent path (prevent path
	// traversal from stored data).
	if rtBackupOrchestratorUnsafeSegment(backup.Filename) {
		return apiErr(http.StatusBadRequest, "Invalid backup filename")
	}

	// Unlink the archive on the host that HOLDS it — the host its own row
	// names, not the caller's server switcher. Deleting through the caller's
	// scope asked some other machine to unlink a path it never had, and the
	// row was then deleted regardless: the real archive survived with its
	// only record destroyed — or, where the same dump name exists on both
	// hosts, the wrong machine's backup was destroyed instead.
	agent, err := agentForSiteServer(ctx, st, backup.ServerID, "database "+backup.DbName)
	if err != nil {
		return err
	}
	if _, err := agent.Delete(ctx, fmt.Sprintf("/db-backups/%s/%s", backup.DbName, backup.Filename)); err != nil {
		return agentError("Delete backup", err)
	}
	if _, err := execSQL(ctx, st.DB, "DELETE FROM database_backups WHERE id = $1", id); err != nil {
		return internalError("delete db backup", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtBackupOrchestratorRestoreDbBackup is POST /api/backup-orchestrator/db-backups/{id}/restore.
func rtBackupOrchestratorRestoreDbBackup(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	backup, err := queryOpt[rtBackupOrchestratorDatabaseBackup](ctx, st.DB,
		"SELECT db.* FROM database_backups db "+
			"JOIN databases d ON d.id = db.database_id JOIN sites s ON d.site_id = s.id AND s.user_id = $1 "+
			"WHERE db.id = $2", claims.Sub, id)
	if err != nil {
		return internalError("restore db backup", err)
	}
	if backup == nil {
		return apiErr(http.StatusNotFound, "Backup not found")
	}

	// One host governs BOTH directions: the agent reads the dump off its own
	// disk into its own `dockpanel-db-{name}` container. A container of that
	// name answers on every host running this database, so the caller's
	// machine would overwrite a live database the operator was not looking at
	// and report success. Pinned to backup.server_id, a restore lands on the
	// machine the dump came from or is refused.
	agent, err := agentForSiteServer(ctx, st, backup.ServerID, "database "+backup.DbName)
	if err != nil {
		return err
	}

	creds, err := queryOpt[Tup3[string, string, string]](ctx, st.DB,
		"SELECT d.engine, d.db_user, d.db_password_enc FROM databases d WHERE d.id = $1", backup.DatabaseID)
	if err != nil {
		return internalError("restore db backup", err)
	}
	if creds == nil {
		return apiErr(http.StatusNotFound, "Database not found")
	}
	user, passwordEnc := creds.B, creds.C
	password := SecretsCryptoDecryptCredentialOrLegacy(passwordEnc, st.Config.JWTSecret)
	containerName := "dockpanel-db-" + backup.DbName

	// Policy-encrypted backups use a key derived from the process JWT secret;
	// restore MUST use the SAME derivation (lesson #70).
	//
	// ⚠ s434: uses the row's OWN encryption_key_version, not the current
	// one — a backup written under v1 stays restorable only if restore
	// reproduces v1 for THAT row specifically.
	var encryptionKey *string
	if backup.Encrypted {
		encryptionKey = new(BackupPolicyExecutorDeriveBackupEncryptionKeyForVersion(backup.EncryptionKeyVersion, st.Config.JWTSecret))
	}
	body := map[string]any{
		"container_name": containerName,
		"db_type":        backup.DbType,
		"user":           user,
		"password":       password,
		"encryption_key": encryptionKey,
	}

	// Defense-in-depth (parity with delete): reject any traversal in the
	// stored db_name/filename before composing the agent path.
	if rtBackupOrchestratorUnsafeSegment(backup.Filename) || rtBackupOrchestratorUnsafeSegment(backup.DbName) {
		return apiErr(http.StatusBadRequest, "Invalid backup path")
	}

	// PostLong: Post was a 60-second budget on an operation the agent gives
	// 600, so any non-toy restore reported a timeout WHILE THE RESTORE CARRIED
	// ON SUCCEEDING inside the container — on the disaster-recovery path.
	result, err := agent.PostLong(ctx, fmt.Sprintf("/db-backups/%s/restore/%s", backup.DbName, backup.Filename), body, AgentDBRestoreTimeoutSecs)
	if err != nil {
		return agentError("Database restore", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "db_backup.restore",
		new("database"), new(backup.DbName), new(backup.Filename), ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "db_backup.restore", new(claims.Email), ip,
		new("database"), new(backup.DbName), new(backup.Filename), nil, "info", claims.KeyID)
	ExtensionsFireEvent(st.DB, "db_backup.restored", map[string]any{
		"database": backup.DbName, "filename": backup.Filename, "backup_id": id.String(),
	})

	writeJSON(w, http.StatusOK, result)
	return nil
}

// ── Volume Backups ──────────────────────────────────────────────────────────

type rtBackupOrchestratorCreateVolumeBackupRequest struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	VolumeName    string `json:"volume_name"`
}

// rtBackupOrchestratorCreateVolumeBackup is POST /api/backup-orchestrator/volume-backup.
func rtBackupOrchestratorCreateVolumeBackup(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	scopeServerID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var req rtBackupOrchestratorCreateVolumeBackupRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()

	// Validate container/volume names to prevent path traversal in agent URLs.
	if rtBackupOrchestratorUnsafeSegment(req.ContainerName) || len(req.ContainerName) > 128 {
		return apiErr(http.StatusBadRequest, "Invalid container name")
	}
	if rtBackupOrchestratorUnsafeSegment(req.VolumeName) || len(req.VolumeName) > 128 {
		return apiErr(http.StatusBadRequest, "Invalid volume name")
	}

	result, err := agent.Post(ctx, "/volume-backups/create", map[string]any{
		"volume_name":    req.VolumeName,
		"container_name": req.ContainerName,
	})
	if err != nil {
		return agentError("Volume backup", err)
	}
	filename, _ := jsonStr(jsonGet(result, "filename"))
	sizeU, _ := jsonU64(jsonGet(result, "size_bytes"))
	sizeBytes := int64(sizeU)

	// The row records the server the archive was actually written on — the
	// one ServerScope resolved the agent for, NOT "some online server". The
	// verifier and the drill scheduler read this column to decide where to act.
	serverID := &scopeServerID

	// v2.8.2: integrity chain, scoped by (container_id, volume_name) so
	// re-creating the same logical volume re-chains rather than forking.
	sha256Hash, _ := jsonStr(jsonGet(result, "sha256"))
	var previousHash *string
	if v, err := queryScalarOpt[*string](ctx, st.DB,
		"SELECT sha256_hash FROM volume_backups WHERE container_id = $1 AND volume_name = $2 ORDER BY created_at DESC LIMIT 1",
		req.ContainerID, req.VolumeName); err == nil && v != nil {
		previousHash = *v
	}

	backup, err := queryOne[rtBackupOrchestratorVolumeBackup](ctx, st.DB,
		"INSERT INTO volume_backups (container_id, container_name, server_id, volume_name, filename, size_bytes, sha256_hash, previous_hash, chain_valid) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE) RETURNING *",
		req.ContainerID, req.ContainerName, serverID, req.VolumeName, filename, sizeBytes,
		backupPolicyExecutorShaArg(sha256Hash), previousHash)
	if err != nil {
		return internalError("create volume backup", err)
	}

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "volume_backup.create",
		new("volume"), new(req.ContainerName), new(filename), nil, claims.KeyID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         backup.ID,
		"filename":   filename,
		"size_bytes": sizeBytes,
	})
	return nil
}

// rtBackupOrchestratorListVolumeBackups is GET /api/backup-orchestrator/volume-backups.
//
// Scoped the same way restore scopes its own lookup: this machine, or a
// server this operator added. It was a flat SELECT * showing every admin's
// volume-backup metadata to every other admin. A NULL server_id row is
// excluded by the JOIN, matching how restore refuses it outright.
func rtBackupOrchestratorListVolumeBackups(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var params rtBackupOrchestratorPaginationQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	limit, offset := paginate(params.Limit, params.Offset)
	backups, err := queryAll[rtBackupOrchestratorVolumeBackup](r.Context(), st.DB,
		"SELECT vb.* FROM volume_backups vb "+
			"JOIN servers sv ON sv.id = vb.server_id AND (sv.is_local OR sv.user_id = $1) "+
			"ORDER BY vb.created_at DESC LIMIT $2 OFFSET $3", claims.Sub, limit, offset)
	if err != nil {
		return internalError("list volume backups", err)
	}
	writeJSON(w, http.StatusOK, backups)
	return nil
}

// rtBackupOrchestratorRestoreVolumeBackup is POST /api/backup-orchestrator/volume-backups/{id}/restore.
func rtBackupOrchestratorRestoreVolumeBackup(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()

	// Look up the volume backup, scoped to the machines this operator runs.
	//
	// The scope had to land with the body fix below: the route used to send
	// no body, so it always failed closed (415) — and fixing only the body
	// would have made an UNSCOPED restore work for the first time, letting any
	// administrator unpack a backup over a live volume on a server somebody
	// else registered. u.role is read from the DATABASE, not claims.role,
	// because a JWT keeps asserting the role it was minted with. A NULL
	// server_id cannot satisfy the scope and 404s here.
	backup, err := queryOpt[rtBackupOrchestratorVolumeBackup](ctx, st.DB,
		"SELECT * FROM volume_backups vb WHERE vb.id = $1 AND EXISTS ("+
			"SELECT 1 FROM users u, servers sv WHERE u.id = $2 AND u.role = 'admin' "+
			"AND sv.id = vb.server_id AND (sv.is_local OR sv.user_id = u.id))", id, claims.Sub)
	if err != nil {
		return internalError("restore volume backup", err)
	}
	if backup == nil {
		return apiErr(http.StatusNotFound, "Volume backup not found")
	}

	// Source and destination are the same host: the agent unpacks a tar from
	// its own disk over its own Docker volume. Policy-driven archives are named
	// per container and volume, so through the caller's scope a machine would
	// unpack ITS OWN archive over ITS OWN live volume — a restore nobody asked
	// for, reported as the success of a different one.
	agent, err := agentForSiteServer(ctx, st, backup.ServerID, "volume "+backup.VolumeName)
	if err != nil {
		return err
	}

	// The body is not optional and never was: the agent's restore takes
	// Json<VolumeRestoreRequest> whose volume_name says which volume to unpack
	// over, and a body-less request was refused 415 in the transport layer.
	// The volume drill re-implements the restore rather than calling this
	// path, so a green drill says nothing about whether this one runs.
	result, err := agent.Post(ctx, fmt.Sprintf("/volume-backups/%s/restore/%s", backup.ContainerName, backup.Filename),
		map[string]any{"volume_name": backup.VolumeName})
	if err != nil {
		return agentError("Volume restore", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "volume_backup.restore",
		new("volume"), new(backup.ContainerName), new(backup.Filename), ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "volume_backup.restore", new(claims.Email), ip,
		new("volume"), new(backup.ContainerName), new(backup.Filename), nil, "info", claims.KeyID)
	ExtensionsFireEvent(st.DB, "volume_backup.restored", map[string]any{
		"container_name": backup.ContainerName, "volume_name": backup.VolumeName,
		"filename": backup.Filename, "backup_id": id.String(),
	})

	writeJSON(w, http.StatusOK, result)
	return nil
}

// ── Verification ────────────────────────────────────────────────────────────

// rtBackupOrchestratorAgentForBackup resolves the host a stored backup
// actually lives on, from the backup's own row.
//
// Verify and drill take nothing but (backup_type, backup_id), so both used
// whatever agent ServerScope handed over — reading one machine's disk for
// another machine's archive. For a drill it is worse: a drill RESTORES.
//
// Taken BEFORE the tracking row is inserted, for the same reason the
// verifier gives: a `running` row against a host we then decline to reach is
// a permanent record of work that never happened. The returned id is never
// nil — agentForSiteServer refuses the nil case.
func rtBackupOrchestratorAgentForBackup(ctx context.Context, st *AppState, backupType string, backupID uuid.UUID) (*uuid.UUID, AgentHandle, error) {
	// `backups` carries no server_id of its own — a site backup reaches its
	// host through the site.
	var sql string
	switch backupType {
	case "site":
		sql = "SELECT s.server_id FROM backups b JOIN sites s ON s.id = b.site_id WHERE b.id = $1"
	case "database":
		sql = "SELECT server_id FROM database_backups WHERE id = $1"
	case "volume":
		sql = "SELECT server_id FROM volume_backups WHERE id = $1"
	default:
		return nil, nil, apiErr(http.StatusBadRequest, "Invalid backup type")
	}
	row, err := queryScalarOpt[*uuid.UUID](ctx, st.DB, sql, backupID)
	if err != nil {
		return nil, nil, internalError("resolve backup host", err)
	}
	if row == nil {
		return nil, nil, apiErr(http.StatusNotFound, "Backup not found")
	}
	serverID := *row
	agent, err := agentForSiteServer(ctx, st, serverID, fmt.Sprintf("%s backup %s", backupType, backupID))
	if err != nil {
		return nil, nil, err
	}
	return serverID, agent, nil
}

type rtBackupOrchestratorVerifyRequest struct {
	BackupType string    `json:"backup_type"` // site, database, volume
	BackupID   uuid.UUID `json:"backup_id"`
}

// rtBackupOrchestratorDispatch loads the row a verify/drill needs and posts
// it to the agent. paths maps backup type → agent path; notFound maps backup
// type → the message for a vanished row; what names the action in logs.
func rtBackupOrchestratorDispatch(ctx context.Context, st *AppState, agent AgentHandle, backupType string, backupID uuid.UUID,
	paths, notFound map[string]string, what string, timeout uint64) (any, error) {
	var body map[string]any
	var dbErr error
	switch backupType {
	case "site":
		var row *Tup2[string, string]
		row, dbErr = queryOpt[Tup2[string, string]](ctx, st.DB,
			"SELECT s.domain, b.filename FROM backups b "+
				"JOIN sites s ON s.id = b.site_id WHERE b.id = $1", backupID)
		if row != nil {
			body = map[string]any{"domain": row.A, "filename": row.B}
		}
	case "database":
		var row *Tup3[string, string, string]
		row, dbErr = queryOpt[Tup3[string, string, string]](ctx, st.DB,
			"SELECT db_type, db_name, filename FROM database_backups WHERE id = $1", backupID)
		if row != nil {
			body = map[string]any{"db_type": row.A, "db_name": row.B, "filename": row.C}
		}
	case "volume":
		var row *Tup2[string, string]
		row, dbErr = queryOpt[Tup2[string, string]](ctx, st.DB,
			"SELECT container_name, filename FROM volume_backups WHERE id = $1", backupID)
		if row != nil {
			body = map[string]any{"container_name": row.A, "filename": row.B}
		}
	default:
		return nil, fmt.Errorf("%s", notFound[""])
	}
	if dbErr != nil {
		slog.Warn(fmt.Sprintf("DB error fetching %s backup for %s: %v", backupType, what, dbErr))
		return nil, fmt.Errorf("Database error: %v", dbErr)
	}
	if body == nil {
		return nil, fmt.Errorf("%s", notFound[backupType])
	}
	if timeout > 0 {
		return agent.PostLong(ctx, paths[backupType], body, timeout)
	}
	return agent.Post(ctx, paths[backupType], body)
}

// rtBackupOrchestratorTriggerVerify is POST /api/backup-orchestrator/verify.
func rtBackupOrchestratorTriggerVerify(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	var req rtBackupOrchestratorVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()

	// Read the archive on the host that holds it, resolved from the backup's
	// own row — backup_verifier always did; only the operator-pressed button
	// kept reading the switcher. This also makes an unsupported type a
	// synchronous 400 instead of a 202 followed by a `failed` row.
	serverID, agent, err := rtBackupOrchestratorAgentForBackup(ctx, st, req.BackupType, req.BackupID)
	if err != nil {
		return err
	}

	// server_id is bound: it names the host that actually read the archive.
	verification, err := queryOne[rtBackupOrchestratorBackupVerification](ctx, st.DB,
		"INSERT INTO backup_verifications (backup_type, backup_id, server_id, status, started_at) "+
			"VALUES ($1, $2, $3, 'running', NOW()) RETURNING *", req.BackupType, req.BackupID, serverID)
	if err != nil {
		return internalError("trigger verify", err)
	}

	verifID := verification.ID
	db := st.DB
	bg := context.WithoutCancel(ctx)
	go func() {
		data, err := rtBackupOrchestratorDispatch(bg, st, agent, req.BackupType, req.BackupID,
			map[string]string{"site": "/backups/verify/site", "database": "/backups/verify/database", "volume": "/backups/verify/volume"},
			map[string]string{"": "Invalid backup type", "site": "Backup not found", "database": "Database backup not found", "volume": "Volume backup not found"},
			"verification", 0)
		if err != nil {
			_, _ = execSQL(bg, db,
				"UPDATE backup_verifications SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1",
				verifID, err.Error())
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
		_, _ = execSQL(bg, db,
			"UPDATE backup_verifications SET "+
				"status = $2, checks_run = $3, checks_passed = $4, "+
				"details = $5, duration_ms = $6, completed_at = NOW() "+
				"WHERE id = $1",
			verifID, status, int32(checksRun), int32(checksPassed), rtBackupDestinationsJSONArg(details), int32(durationMs))
	}()

	writeJSON(w, http.StatusAccepted, verification)
	return nil
}

// rtBackupOrchestratorStorageHistory is GET /api/backup-orchestrator/storage-history
// — backup storage growth over the last 30 days.
func rtBackupOrchestratorStorageHistory(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	rows, err := queryAll[Tup2[string, string]](r.Context(), st.DB,
		"SELECT DATE(created_at)::TEXT as day, message "+
			"FROM system_logs "+
			"WHERE source = 'backup_storage' AND created_at > NOW() - INTERVAL '30 days' "+
			"ORDER BY created_at ASC")
	if err != nil {
		return internalError("storage history", err)
	}
	// Group by day, keep the last reading per day.
	daily := map[string]int64{}
	for _, row := range rows {
		if b, err := strconv.ParseInt(row.B, 10, 64); err == nil {
			daily[row.A] = b
		}
	}
	days := make([]string, 0, len(daily))
	for d := range daily {
		days = append(days, d)
	}
	sort.Strings(days)
	result := make([]any, 0, len(days))
	for _, d := range days {
		b := daily[d]
		result = append(result, map[string]any{
			"date":        d,
			"total_bytes": b,
			"total_mb":    int64(math.Round(float64(b) / 1_048_576.0)),
		})
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtBackupOrchestratorListVerifications is GET /api/backup-orchestrator/verifications.
func rtBackupOrchestratorListVerifications(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	var params rtBackupOrchestratorPaginationQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	limit, offset := paginate(params.Limit, params.Offset)
	v, err := queryAll[rtBackupOrchestratorBackupVerification](r.Context(), st.DB,
		"SELECT * FROM backup_verifications ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return internalError("list verifications", err)
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

// ── Drills (Phase 4 W1.2: end-to-end restore probes) ────────────────────────

type rtBackupOrchestratorDrillRequest struct {
	BackupType string    `json:"backup_type"` // site | database | volume
	BackupID   uuid.UUID `json:"backup_id"`
}

// rtBackupOrchestratorTriggerDrill is POST /api/backup-orchestrator/drill —
// an on-demand backup drill (site, database, volume).
func rtBackupOrchestratorTriggerDrill(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var req rtBackupOrchestratorDrillRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.BackupType != "site" && req.BackupType != "database" && req.BackupType != "volume" {
		return apiErr(http.StatusBadRequest, "Unsupported backup_type")
	}
	ctx := r.Context()

	// A drill is a real restore, so the host must come from the backup's row
	// and nowhere else. Through ServerScope, a deterministically-named db or
	// volume archive on the caller's machine would be restored over ITS OWN
	// live data and reported under the server the operator had selected.
	serverID, agent, err := rtBackupOrchestratorAgentForBackup(ctx, st, req.BackupType, req.BackupID)
	if err != nil {
		return err
	}

	// server_id is bound: drill_scheduler's concurrency guard counts running
	// drills BY SERVER, and a NULL from here was invisible to it, so two
	// restores could land on the same host at once.
	drill, err := queryOne[rtBackupOrchestratorBackupDrill](ctx, st.DB,
		"INSERT INTO backup_drills (backup_type, backup_id, server_id, triggered_by, status, started_at) "+
			"VALUES ($1, $2, $3, $4, 'running', NOW()) RETURNING *", req.BackupType, req.BackupID, serverID, claims.Sub)
	if err != nil {
		return internalError("trigger drill", err)
	}

	drillID := drill.ID
	db := st.DB
	bg := context.WithoutCancel(ctx)
	// PostLong: a plain Post caps the round trip at 60s, but the agent-side
	// restore is budgeted 220s (database) to 360s (volume).
	go func() {
		data, err := rtBackupOrchestratorDispatch(bg, st, agent, req.BackupType, req.BackupID,
			map[string]string{"site": "/backups/drill/site", "database": "/backups/drill/db", "volume": "/backups/drill/volume"},
			map[string]string{"": "Unsupported backup type", "site": "Site backup not found", "database": "Database backup not found", "volume": "Volume backup not found"},
			"drill", AgentDrillTimeoutSecs)
		if err != nil {
			_, _ = execSQL(bg, db,
				"UPDATE backup_drills SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1",
				drillID, err.Error())
			return
		}
		drillSchedulerRecordResult(bg, db, drillID, data)
	}()

	writeJSON(w, http.StatusAccepted, drill)
	return nil
}

type rtBackupOrchestratorDrillsResponse struct {
	Items []rtBackupOrchestratorBackupDrill `json:"items"`
	Total int64                             `json:"total"`
}

// rtBackupOrchestratorListDrills is GET /api/backup-orchestrator/drills.
func rtBackupOrchestratorListDrills(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	var params rtBackupOrchestratorPaginationQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	limit, offset := paginate(params.Limit, params.Offset)
	items, err := queryAll[rtBackupOrchestratorBackupDrill](r.Context(), st.DB,
		"SELECT * FROM backup_drills ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return internalError("list drills", err)
	}
	total, err := queryScalar[int64](r.Context(), st.DB, "SELECT COUNT(*) FROM backup_drills")
	if err != nil {
		return internalError("list drills count", err)
	}
	writeJSON(w, http.StatusOK, rtBackupOrchestratorDrillsResponse{Items: items, Total: total})
	return nil
}

// ── Chain-of-Trust Report (Phase 4 W1.3) ────────────────────────────────────
//
// v2.8.1 shipped site-only; v2.8.2 extends to db + volume. One
// buildChainReport(kind, id) dispatches on table; the typst template branches
// on backup.kind to render the right resource label.

type rtBackupOrchestratorChainReportBackup struct {
	// One of "site" | "database" | "volume". The typst template branches on this.
	Kind string    `json:"kind"`
	ID   uuid.UUID `json:"id"`
	// Domain for site, db_name for database, "container:volume" for volume.
	ResourceName string    `json:"resource_name"`
	Filename     string    `json:"filename"`
	SizeBytes    int64     `json:"size_bytes"`
	Sha256Hash   *string   `json:"sha256_hash"`
	PreviousHash *string   `json:"previous_hash"`
	CreatedAt    time.Time `json:"created_at"`
	// Kind-specific extras — exactly one set is populated.
	SiteID      *uuid.UUID `json:"site_id"`
	DatabaseID  *uuid.UUID `json:"database_id"`
	ContainerID *string    `json:"container_id"`
	VolumeName  *string    `json:"volume_name"`
	DbType      *string    `json:"db_type"`
}

type rtBackupOrchestratorChainReportVerification struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	Status       string     `json:"status" db:"status"`
	ChecksRun    int32      `json:"checks_run" db:"checks_run"`
	ChecksPassed int32      `json:"checks_passed" db:"checks_passed"`
	DurationMs   *int32     `json:"duration_ms" db:"duration_ms"`
	StartedAt    *time.Time `json:"started_at" db:"started_at"`
	CompletedAt  *time.Time `json:"completed_at" db:"completed_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	ErrorMessage *string    `json:"error_message" db:"error_message"`
}

type rtBackupOrchestratorChainReportDrill struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	Status       string     `json:"status" db:"status"`
	HTTPStatus   *int32     `json:"http_status" db:"http_status"`
	BodyExcerpt  *string    `json:"body_excerpt" db:"body_excerpt"`
	DurationMs   *int32     `json:"duration_ms" db:"duration_ms"`
	StartedAt    *time.Time `json:"started_at" db:"started_at"`
	CompletedAt  *time.Time `json:"completed_at" db:"completed_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	ErrorMessage *string    `json:"error_message" db:"error_message"`
}

// rtBackupOrchestratorChainIntegrity carries no validity verdict,
// deliberately. chain_valid is written TRUE by every INSERT, UPDATEd nowhere,
// and no verifier exists that could compute it. Re-adding a verdict field
// means building the verifier first.
type rtBackupOrchestratorChainIntegrity struct {
	VerificationsPassed int64 `json:"verifications_passed"`
	DrillsPassed        int64 `json:"drills_passed"`
}

type rtBackupOrchestratorChainReport struct {
	PanelVersion   string                                        `json:"panel_version"`
	GeneratedAt    time.Time                                     `json:"generated_at"`
	Backup         rtBackupOrchestratorChainReportBackup         `json:"backup"`
	Verifications  []rtBackupOrchestratorChainReportVerification `json:"verifications"`
	Drills         []rtBackupOrchestratorChainReportDrill        `json:"drills"`
	ChainIntegrity rtBackupOrchestratorChainIntegrity            `json:"chain_integrity"`
}

// rtBackupOrchestratorParseChainKind validates the {kind} segment, kept
// central so the JSON + PDF handlers don't drift.
func rtBackupOrchestratorParseChainKind(kind string) (string, error) {
	switch kind {
	case "site", "database", "volume":
		return kind, nil
	}
	return "", apiErr(http.StatusBadRequest, "kind must be one of: site, database, volume")
}

// rtBackupOrchestratorBuildChainReport builds a chain-of-trust report for any
// backup kind; 404 if it doesn't exist.
//
// Every branch joins `servers` and scopes by `sv.is_local OR sv.user_id =
// caller` — before this fix any admin could pull another admin's backup
// provenance as JSON or PDF. A NULL server_id fails closed via the JOIN.
func rtBackupOrchestratorBuildChainReport(ctx context.Context, st *AppState, kind string, backupID, callerID uuid.UUID) (*rtBackupOrchestratorChainReport, error) {
	var backup rtBackupOrchestratorChainReportBackup
	switch kind {
	case "site":
		type row struct {
			ID           uuid.UUID `db:"id"`
			SiteID       uuid.UUID `db:"site_id"`
			Domain       string    `db:"domain"`
			Filename     string    `db:"filename"`
			SizeBytes    int64     `db:"size_bytes"`
			Sha256Hash   *string   `db:"sha256_hash"`
			PreviousHash *string   `db:"previous_hash"`
			CreatedAt    time.Time `db:"created_at"`
		}
		r, err := queryOpt[row](ctx, st.DB,
			"SELECT b.id, b.site_id, s.domain, b.filename, b.size_bytes, "+
				"b.sha256_hash, b.previous_hash, b.created_at "+
				"FROM backups b JOIN sites s ON s.id = b.site_id "+
				"JOIN servers sv ON sv.id = s.server_id AND (sv.is_local OR sv.user_id = $2) "+
				"WHERE b.id = $1", backupID, callerID)
		if err != nil {
			return nil, internalError("chain report: load site backup", err)
		}
		if r == nil {
			return nil, apiErr(http.StatusNotFound, "Backup not found")
		}
		backup = rtBackupOrchestratorChainReportBackup{Kind: "site", ID: r.ID, ResourceName: r.Domain, Filename: r.Filename,
			SizeBytes: r.SizeBytes, Sha256Hash: r.Sha256Hash, PreviousHash: r.PreviousHash, CreatedAt: r.CreatedAt, SiteID: &r.SiteID}
	case "database":
		type row struct {
			ID           uuid.UUID `db:"id"`
			DatabaseID   uuid.UUID `db:"database_id"`
			DbName       string    `db:"db_name"`
			DbType       string    `db:"db_type"`
			Filename     string    `db:"filename"`
			SizeBytes    int64     `db:"size_bytes"`
			Sha256Hash   *string   `db:"sha256_hash"`
			PreviousHash *string   `db:"previous_hash"`
			CreatedAt    time.Time `db:"created_at"`
		}
		r, err := queryOpt[row](ctx, st.DB,
			"SELECT db.id, db.database_id, db.db_name, db.db_type, db.filename, db.size_bytes, "+
				"db.sha256_hash, db.previous_hash, db.created_at "+
				"FROM database_backups db "+
				"JOIN servers sv ON sv.id = db.server_id AND (sv.is_local OR sv.user_id = $2) "+
				"WHERE db.id = $1", backupID, callerID)
		if err != nil {
			return nil, internalError("chain report: load database backup", err)
		}
		if r == nil {
			return nil, apiErr(http.StatusNotFound, "Backup not found")
		}
		backup = rtBackupOrchestratorChainReportBackup{Kind: "database", ID: r.ID, ResourceName: r.DbName, Filename: r.Filename,
			SizeBytes: r.SizeBytes, Sha256Hash: r.Sha256Hash, PreviousHash: r.PreviousHash, CreatedAt: r.CreatedAt,
			DatabaseID: &r.DatabaseID, DbType: &r.DbType}
	case "volume":
		type row struct {
			ID            uuid.UUID `db:"id"`
			ContainerID   string    `db:"container_id"`
			ContainerName string    `db:"container_name"`
			VolumeName    string    `db:"volume_name"`
			Filename      string    `db:"filename"`
			SizeBytes     int64     `db:"size_bytes"`
			Sha256Hash    *string   `db:"sha256_hash"`
			PreviousHash  *string   `db:"previous_hash"`
			CreatedAt     time.Time `db:"created_at"`
		}
		r, err := queryOpt[row](ctx, st.DB,
			"SELECT vb.id, vb.container_id, vb.container_name, vb.volume_name, vb.filename, vb.size_bytes, "+
				"vb.sha256_hash, vb.previous_hash, vb.created_at "+
				"FROM volume_backups vb "+
				"JOIN servers sv ON sv.id = vb.server_id AND (sv.is_local OR sv.user_id = $2) "+
				"WHERE vb.id = $1", backupID, callerID)
		if err != nil {
			return nil, internalError("chain report: load volume backup", err)
		}
		if r == nil {
			return nil, apiErr(http.StatusNotFound, "Backup not found")
		}
		backup = rtBackupOrchestratorChainReportBackup{Kind: "volume", ID: r.ID, ResourceName: r.ContainerName + ":" + r.VolumeName,
			Filename: r.Filename, SizeBytes: r.SizeBytes, Sha256Hash: r.Sha256Hash, PreviousHash: r.PreviousHash, CreatedAt: r.CreatedAt,
			ContainerID: &r.ContainerID, VolumeName: &r.VolumeName}
	default:
		// parseChainKind already gates this — defensive only.
		return nil, apiErr(http.StatusBadRequest, "Unsupported backup kind")
	}

	verifications, err := queryAll[rtBackupOrchestratorChainReportVerification](ctx, st.DB,
		"SELECT id, status, checks_run, checks_passed, duration_ms, "+
			"started_at, completed_at, created_at, error_message "+
			"FROM backup_verifications "+
			"WHERE backup_type = $1 AND backup_id = $2 "+
			"ORDER BY created_at ASC", kind, backupID)
	if err != nil {
		return nil, internalError("chain report: load verifications", err)
	}
	drills, err := queryAll[rtBackupOrchestratorChainReportDrill](ctx, st.DB,
		"SELECT id, status, http_status, body_excerpt, duration_ms, "+
			"started_at, completed_at, created_at, error_message "+
			"FROM backup_drills "+
			"WHERE backup_type = $1 AND backup_id = $2 "+
			"ORDER BY created_at ASC", kind, backupID)
	if err != nil {
		return nil, internalError("chain report: load drills", err)
	}

	var vp, dp int64
	for _, v := range verifications {
		if v.Status == "passed" {
			vp++
		}
	}
	for _, d := range drills {
		if d.Status == "passed" {
			dp++
		}
	}
	return &rtBackupOrchestratorChainReport{
		PanelVersion:   Version,
		GeneratedAt:    time.Now().UTC(),
		Backup:         backup,
		Verifications:  verifications,
		Drills:         drills,
		ChainIntegrity: rtBackupOrchestratorChainIntegrity{VerificationsPassed: vp, DrillsPassed: dp},
	}, nil
}

// rtBackupOrchestratorShortID is the short backup id suffix for a filename.
func rtBackupOrchestratorShortID(id uuid.UUID) string { return id.String()[:8] }

// rtBackupOrchestratorSlug sanitises a name into a filesystem-safe slug for
// the PDF filename: keeps ASCII alnum, '-' and '.', collapses the rest to "-".
func rtBackupOrchestratorSlug(s string) string {
	var out strings.Builder
	lastDash := false
	for _, c := range s {
		if c < 0x80 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			out.WriteRune(c)
			lastDash = false
		} else if !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(out.String(), "-")
}

func rtBackupOrchestratorChainArgs(st *AppState, r *http.Request) (*rtBackupOrchestratorChainReport, error) {
	claims, err := st.adminUser(r)
	if err != nil {
		return nil, err
	}
	kindRaw := r.PathValue("kind")
	id, err := pathUUID(r, "id")
	if err != nil {
		return nil, err
	}
	kind, err := rtBackupOrchestratorParseChainKind(kindRaw)
	if err != nil {
		return nil, err
	}
	return rtBackupOrchestratorBuildChainReport(r.Context(), st, kind, id, claims.Sub)
}

// rtBackupOrchestratorChainReportJSON is GET /api/backup-orchestrator/chain-report/{kind}/{id}.
func rtBackupOrchestratorChainReportJSON(st *AppState, w http.ResponseWriter, r *http.Request) error {
	report, err := rtBackupOrchestratorChainArgs(st, r)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, report)
	return nil
}

// rtBackupOrchestratorChainReportPDF is GET .../chain-report/{kind}/{id}/pdf —
// rendered via typst. The first call lazy-installs typst; 503 if
// install/compile fails.
func rtBackupOrchestratorChainReportPDF(st *AppState, w http.ResponseWriter, r *http.Request) error {
	report, err := rtBackupOrchestratorChainArgs(st, r)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return internalError("chain report: serialize", err)
	}
	jsonValue, err := agentDecodeJSON(raw)
	if err != nil {
		return internalError("chain report: serialize", err)
	}
	pdf, err := ChainReportRenderChainReportPdf(r.Context(), jsonValue)
	if err != nil {
		slog.Warn(fmt.Sprintf("chain report pdf render failed: %v", err))
		return apiErr(http.StatusServiceUnavailable, fmt.Sprintf("PDF generation failed: %v", err))
	}
	filename := fmt.Sprintf("chain-report-%s-%s-%s.pdf", report.Backup.Kind,
		rtBackupOrchestratorSlug(report.Backup.ResourceName), rtBackupOrchestratorShortID(report.Backup.ID))
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdf)
	return nil
}
