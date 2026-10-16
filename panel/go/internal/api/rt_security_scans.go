package api

// Port of panel/backend/src/routes/security_scans.rs.

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func rtSecurityScansRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("POST /api/security/scan", h(rtSecurityScansTriggerScan))
	r.Handle("GET /api/security/scans", h(rtSecurityScansListScans))
	r.Handle("GET /api/security/scans/{id}", h(rtSecurityScansGetScan))
	r.Handle("GET /api/security/posture", h(rtSecurityScansPosture))
}

type rtSecurityScansScanRow struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	ScanType      string     `json:"scan_type" db:"scan_type"`
	Status        string     `json:"status" db:"status"`
	FindingsCount int32      `json:"findings_count" db:"findings_count"`
	CriticalCount int32      `json:"critical_count" db:"critical_count"`
	WarningCount  int32      `json:"warning_count" db:"warning_count"`
	InfoCount     int32      `json:"info_count" db:"info_count"`
	StartedAt     time.Time  `json:"started_at" db:"started_at"`
	CompletedAt   *time.Time `json:"completed_at" db:"completed_at"`
}

type rtSecurityScansFindingRow struct {
	ID          uuid.UUID `json:"id" db:"id"`
	CheckType   string    `json:"check_type" db:"check_type"`
	Severity    string    `json:"severity" db:"severity"`
	Title       string    `json:"title" db:"title"`
	Description *string   `json:"description" db:"description"`
	FilePath    *string   `json:"file_path" db:"file_path"`
	Remediation *string   `json:"remediation" db:"remediation"`
}

// rtSecurityScansTriggerScan is POST /api/security/scan — trigger a security
// scan (admin only).
func rtSecurityScansTriggerScan(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()
	db := st.DB

	// The scan record names the host that was scanned. This handler used to
	// resolve the right agent and throw the id away, so every manual scan was
	// filed against no server at all.
	scanID, err := queryScalar[uuid.UUID](ctx, db,
		"INSERT INTO security_scans (server_id, scan_type, status) VALUES ($1, 'full', 'running') RETURNING id", serverID)
	if err != nil {
		return internalError("trigger scan", err)
	}

	result, err := agent.Post(ctx, "/security/scan", nil)
	if err != nil {
		return agentError("Security scan", err)
	}

	findings, hasFindings := jsonArr(jsonGet(result, "findings"))
	fileHashes, hasHashes := jsonArr(jsonGet(result, "file_hashes"))

	var critical, warning, info int32
	if hasFindings {
		for _, f := range findings {
			severity := securityScannerStrOr(jsonGet(f, "severity"), "info")
			switch severity {
			case "critical":
				critical++
			case "warning":
				warning++
			default:
				info++
			}
			if _, err := execSQL(ctx, db,
				"INSERT INTO security_findings (scan_id, check_type, severity, title, description, file_path, remediation) "+
					"VALUES ($1, $2, $3, $4, $5, $6, $7)",
				scanID,
				securityScannerStrOr(jsonGet(f, "check_type"), ""),
				severity,
				securityScannerStrOr(jsonGet(f, "title"), ""),
				securityScannerOptStr(jsonGet(f, "description")),
				securityScannerOptStr(jsonGet(f, "file_path")),
				securityScannerOptStr(jsonGet(f, "remediation"))); err != nil {
				slog.Error(fmt.Sprintf("Failed to insert security finding: %v", err))
			}
		}
	}

	total := critical + warning + info
	if _, err := execSQL(ctx, db,
		"UPDATE security_scans SET status = 'completed', completed_at = NOW(), "+
			"findings_count = $1, critical_count = $2, warning_count = $3, info_count = $4 "+
			"WHERE id = $5", total, critical, warning, info, scanID); err != nil {
		slog.Error(fmt.Sprintf("Failed to update scan status: %v", err))
	}

	// ⛔ THIS ROW IS WHAT THE WEEKLY SCANNER'S OWN GATE COUNTS: it skips a host
	// for 7 days once ANY completed security_scans row exists for it, whoever
	// triggered it. Marking this one completed without also running the fix
	// pass below would buy the host a week of no automatic SSL/stack renewal.
	// The scheduled path and this handler must stay symmetric on that point.
	if hasFindings {
		member, _ := queryOpt[Tup3[uuid.UUID, string, bool]](ctx, db,
			"SELECT user_id, name, is_local FROM servers WHERE id = $1", serverID)
		if member != nil {
			SecurityScannerAutoFixSafeFindings(ctx, db, AgentFleetMember{
				ID: serverID, UserID: member.A, Name: member.B, IsLocal: member.C, Agent: agent,
			}, findings, st.Config.JWTSecret)
		}
	}

	// Store file integrity baselines.
	if hasHashes {
		for _, h := range fileHashes {
			path := securityScannerStrOr(jsonGet(h, "path"), "")
			hash := securityScannerStrOr(jsonGet(h, "hash"), "")
			size, _ := jsonI64(jsonGet(h, "size"))

			oldHash, err := queryScalarOpt[string](ctx, db,
				"SELECT sha256_hash FROM file_integrity_baselines "+
					"WHERE server_id = $1 AND file_path = $2", serverID, path)
			if err != nil {
				slog.Error(fmt.Sprintf("Failed to check file integrity baseline for %s: %v", path, err))
				oldHash = nil
			}
			if oldHash != nil && *oldHash != hash {
				// File changed — add a finding.
				if _, err := execSQL(ctx, db,
					"INSERT INTO security_findings (scan_id, check_type, severity, title, description, file_path, remediation) "+
						"VALUES ($1, 'file_integrity', 'warning', $2, $3, $4, 'Verify this change was intentional')",
					scanID, "File modified: "+path, fmt.Sprintf("Hash changed from %s to %s", *oldHash, hash), path); err != nil {
					slog.Error(fmt.Sprintf("Failed to insert file integrity finding: %v", err))
				}
				warning++
				if _, err := execSQL(ctx, db,
					"UPDATE security_scans SET findings_count = $1, warning_count = $2 WHERE id = $3",
					critical+warning+info, warning, scanID); err != nil {
					slog.Error(fmt.Sprintf("Failed to update scan counts: %v", err))
				}
			}

			// Binding the host is what ARMS this upsert — the arbiter named a
			// column the INSERT never supplied, and a NULL never conflict-matches.
			if _, err := execSQL(ctx, db,
				"INSERT INTO file_integrity_baselines (server_id, file_path, sha256_hash, file_size) "+
					"VALUES ($1, $2, $3, $4) "+
					"ON CONFLICT (server_id, file_path) DO UPDATE SET sha256_hash = $3, file_size = $4, updated_at = NOW()",
				serverID, path, hash, size); err != nil {
				slog.Error(fmt.Sprintf("Failed to upsert file integrity baseline: %v", err))
			}
		}
	}

	ActivityLogActivity(ctx, db, claims.Sub, claims.Email, "security.scan",
		new("security"), nil, new(fmt.Sprintf("%d findings, %d critical", total, critical)), nil, claims.KeyID)

	// Resolve any stale firing alert BEFORE deciding whether to raise a new
	// one — the scheduled scan's resolve-then-fire order. Without it, a manual
	// rescan to confirm a fix left the earlier alert firing (and the -15
	// health-score penalty) while the scan tiles updated instantly.
	//
	// ⚠ Looped over EVERY admin: the scheduled twin fires per admin, so a
	// multi-admin install can have one firing row PER ADMIN for this condition.
	admins, _ := queryAll[uuid.UUID](ctx, db, "SELECT id FROM users WHERE role = 'admin'")
	for _, userID := range admins {
		NotificationsResolveAlert(ctx, db, userID, new(serverID), nil, "security", "",
			"Security alert resolved",
			"A manual security scan found no matching issue — the earlier alert no longer applies.")
	}
	if _, err := execSQL(ctx, db,
		"UPDATE alerts SET status = 'resolved', resolved_at = NOW() "+
			"WHERE alert_type = 'security' AND server_id = $1 AND status = 'acknowledged'", serverID); err != nil {
		slog.Error(fmt.Sprintf("Failed to resolve acknowledged security alerts: %v", err))
	}

	if critical > 0 || warning > 0 {
		severity := "warning"
		if critical > 0 {
			severity = "critical"
		}
		NotificationsFireAlert(ctx, db, claims.Sub, new(serverID), nil, "security", "", severity,
			fmt.Sprintf("Security scan: %d critical, %d warning findings", critical, warning),
			fmt.Sprintf("A security scan completed with %d total findings (%d critical, %d warning). "+
				"Review the scan results in the Security section.", total, critical, warning))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":             scanID,
		"findings_count": critical + warning + info,
		"critical_count": critical,
		"warning_count":  warning,
		"info_count":     info,
	})
	return nil
}

const rtSecurityScansScanCols = "SELECT id, scan_type, status, findings_count, critical_count, warning_count, info_count, " +
	"started_at, completed_at FROM security_scans "

// rtSecurityScansListScans is GET /api/security/scans (admin only).
func rtSecurityScansListScans(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	// Now that scans name their host, the list shows the selected server's
	// history (the old predicate matched everything).
	scans, err := queryAll[rtSecurityScansScanRow](r.Context(), st.DB,
		rtSecurityScansScanCols+"WHERE server_id = $1 ORDER BY created_at DESC LIMIT 20", serverID)
	if err != nil {
		return internalError("list scans", err)
	}
	writeJSON(w, http.StatusOK, scans)
	return nil
}

// rtSecurityScansGetScan is GET /api/security/scans/{id} (admin only).
func rtSecurityScansGetScan(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	scanID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()
	// Scoped as well as id-keyed: the detail view is reached from the scoped
	// list, so answering for another host's scan would contradict the page.
	scan, err := queryOpt[rtSecurityScansScanRow](ctx, st.DB,
		rtSecurityScansScanCols+"WHERE id = $1 AND server_id = $2", scanID, serverID)
	if err != nil {
		return internalError("get scan", err)
	}
	if scan == nil {
		return apiErr(http.StatusNotFound, "Scan not found")
	}
	findings, err := queryAll[rtSecurityScansFindingRow](ctx, st.DB,
		"SELECT id, check_type, severity, title, description, file_path, remediation "+
			"FROM security_findings WHERE scan_id = $1 ORDER BY "+
			"CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, title", scanID)
	if err != nil {
		return internalError("get scan", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan": scan, "findings": findings})
	return nil
}

// rtSecurityScansPosture is GET /api/security/posture (admin only).
func rtSecurityScansPosture(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()
	latest, err := queryOpt[rtSecurityScansScanRow](ctx, st.DB,
		rtSecurityScansScanCols+"WHERE server_id = $1 AND status = 'completed' "+
			"ORDER BY completed_at DESC LIMIT 1", serverID)
	if err != nil {
		return internalError("posture", err)
	}
	totalScans, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM security_scans WHERE server_id = $1", serverID)
	if err != nil {
		return internalError("posture", err)
	}
	// Score: 100 base, -20 per critical, -5 per warning; -1 = no scan yet.
	score := int32(-1)
	if latest != nil {
		score = max(100-latest.CriticalCount*20-latest.WarningCount*5, 0)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"score":       score,
		"total_scans": totalScans,
		"latest_scan": latest,
	})
	return nil
}
