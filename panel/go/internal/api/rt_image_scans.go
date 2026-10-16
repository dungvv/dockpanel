package api

// Port of panel/backend/src/routes/image_scans.rs — per-image vulnerability
// scanning. Companion to security_scans (full-server scan); this module
// manages per-image results so the Apps page can badge individual containers
// and the deploy path can gate on a configurable severity threshold.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtImageScansRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/image-scan/settings", h(rtImageScansGetSettings))
	r.Handle("PUT /api/image-scan/settings", h(rtImageScansUpdateSettings))
	r.Handle("POST /api/image-scan/install", h(rtImageScansInstallScanner))
	r.Handle("POST /api/image-scan/uninstall", h(rtImageScansUninstallScanner))
	r.Handle("POST /api/image-scan/scan", h(rtImageScansScanImage))
	r.Handle("GET /api/image-scan/recent", h(rtImageScansListRecent))
	r.Handle("GET /api/apps/{name}/scan", h(rtImageScansGetAppScan))
	r.Handle("POST /api/apps/{name}/scan", h(rtImageScansScanApp))
}

type rtImageScansVuln struct {
	Cve              string  `json:"cve"`
	Severity         string  `json:"severity"`
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     *string `json:"fixed_version"`
	Description      *string `json:"description"`
}

type rtImageScansImageScanResult struct {
	Image           string             `json:"image"`
	Scanner         string             `json:"scanner"`
	CriticalCount   uint32             `json:"critical_count"`
	HighCount       uint32             `json:"high_count"`
	MediumCount     uint32             `json:"medium_count"`
	LowCount        uint32             `json:"low_count"`
	UnknownCount    uint32             `json:"unknown_count"`
	Vulnerabilities []rtImageScansVuln `json:"vulnerabilities"`
	ScannedAt       string             `json:"scanned_at"`
}

// rtImageScansScanFindingRow is the stored row; read positionally like the
// Rust tuple (columns in SELECT order).
type rtImageScansScanFindingRow struct {
	Image           string          `db:"image" json:"image"`
	Scanner         string          `db:"scanner" json:"scanner"`
	CriticalCount   int32           `db:"critical_count" json:"critical_count"`
	HighCount       int32           `db:"high_count" json:"high_count"`
	MediumCount     int32           `db:"medium_count" json:"medium_count"`
	LowCount        int32           `db:"low_count" json:"low_count"`
	UnknownCount    int32           `db:"unknown_count" json:"unknown_count"`
	Vulnerabilities json.RawMessage `db:"vulnerabilities" json:"vulnerabilities"`
	ScannedAt       time.Time       `db:"scanned_at" json:"scanned_at"`
}

type rtImageScansScanSettings struct {
	Enabled       bool   `json:"enabled"`
	OnDeploy      bool   `json:"on_deploy"`
	DeployGate    string `json:"deploy_gate"`
	IntervalHours int32  `json:"interval_hours"`
	Installed     bool   `json:"installed"`
}

type rtImageScansUpdateSettingsReq struct {
	Enabled       bool   `json:"enabled"`
	OnDeploy      bool   `json:"on_deploy"`
	DeployGate    string `json:"deploy_gate"`
	IntervalHours int32  `json:"interval_hours"`
}

// ── Settings helpers ────────────────────────────────────────────────────

// rtImageScansReadSettings returns (enabled, on_deploy, deploy_gate,
// interval_hours).
func rtImageScansReadSettings(ctx context.Context, db Querier) (bool, bool, string, int32, error) {
	rows, err := queryAll[Tup2[string, string]](ctx, db,
		"SELECT key, value FROM settings WHERE key IN "+
			"('image_scan_enabled', 'image_scan_on_deploy', 'image_scan_deploy_gate', 'image_scan_interval_hours')")
	if err != nil {
		return false, false, "", 0, err
	}
	enabled, onDeploy, gate, hours := false, false, "none", int32(24)
	for _, kv := range rows {
		switch kv.A {
		case "image_scan_enabled":
			enabled = kv.B == "true"
		case "image_scan_on_deploy":
			onDeploy = kv.B == "true"
		case "image_scan_deploy_gate":
			gate = kv.B
		case "image_scan_interval_hours":
			hours = 24
			if n, err := strconv.ParseInt(kv.B, 10, 32); err == nil {
				hours = int32(n)
			}
		}
	}
	return enabled, onDeploy, gate, hours, nil
}

func rtImageScansValidGate(g string) bool {
	switch g {
	case "none", "critical", "high", "medium":
		return true
	}
	return false
}

// rtImageScansExceedsThreshold: true if the result exceeds the configured
// deploy-gate threshold.
func rtImageScansExceedsThreshold(gate string, r *rtImageScansImageScanResult) bool {
	switch gate {
	case "critical":
		return r.CriticalCount > 0
	case "high":
		return r.CriticalCount > 0 || r.HighCount > 0
	case "medium":
		return r.CriticalCount > 0 || r.HighCount > 0 || r.MediumCount > 0
	}
	return false
}

// ── Routes ──────────────────────────────────────────────────────────────

// rtImageScansGetSettings is GET /api/image-scan/settings.
func rtImageScansGetSettings(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	enabled, onDeploy, gate, hours, err := rtImageScansReadSettings(r.Context(), st.DB)
	if err != nil {
		return internalError("read image scan settings", err)
	}
	installed := false
	if v, err := agent.Get(r.Context(), "/image-scan/status"); err == nil {
		installed, _ = jsonBool(jsonGet(v, "installed"))
	}
	writeJSON(w, http.StatusOK, rtImageScansScanSettings{
		Enabled: enabled, OnDeploy: onDeploy, DeployGate: gate, IntervalHours: hours, Installed: installed,
	})
	return nil
}

// rtImageScansUpdateSettings is PUT /api/image-scan/settings.
func rtImageScansUpdateSettings(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtImageScansUpdateSettingsReq
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	if !rtImageScansValidGate(body.DeployGate) {
		return apiErr(http.StatusBadRequest, "Invalid deploy_gate (none|critical|high|medium)")
	}
	if body.IntervalHours < 1 || body.IntervalHours > 720 {
		return apiErr(http.StatusBadRequest, "interval_hours must be 1..=720")
	}
	ctx := r.Context()
	boolStr := func(b bool) string {
		if b {
			return "true"
		}
		return "false"
	}
	for _, kv := range [][2]string{
		{"image_scan_enabled", boolStr(body.Enabled)},
		{"image_scan_on_deploy", boolStr(body.OnDeploy)},
		{"image_scan_deploy_gate", body.DeployGate},
	} {
		if _, err := execSQL(ctx, st.DB, "INSERT INTO settings (key, value) VALUES ($1, $2) "+
			"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", kv[0], kv[1]); err != nil {
			return internalError("save image scan setting", err)
		}
	}
	if _, err := execSQL(ctx, st.DB, "INSERT INTO settings (key, value) VALUES ('image_scan_interval_hours', $1) "+
		"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", strconv.Itoa(int(body.IntervalHours))); err != nil {
		return internalError("save image scan interval", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtImageScansInstallScanner is POST /api/image-scan/install.
func rtImageScansInstallScanner(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	res, err := agent.PostLong(r.Context(), "/image-scan/install", nil, 300)
	if err != nil {
		return agentError("install image scanner", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtImageScansUninstallScanner is POST /api/image-scan/uninstall.
func rtImageScansUninstallScanner(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), "/image-scan/uninstall", nil)
	if err != nil {
		return agentError("uninstall image scanner", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

type rtImageScansScanByImageRequest struct {
	Image string `json:"image"`
}

// rtImageScansScanImage is POST /api/image-scan/scan — scan an arbitrary
// image (ad-hoc).
func rtImageScansScanImage(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body rtImageScansScanByImageRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	res, err := rtImageScansScanAndStore(r.Context(), st.DB, serverID, agent, body.Image)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtImageScansScanApp is POST /api/apps/{name}/scan — scan the image used by
// a specific Docker app.
func rtImageScansScanApp(st *AppState, w http.ResponseWriter, r *http.Request) error {
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
	image, err := rtImageScansResolveAppImage(r.Context(), agent, r.PathValue("name"))
	if err != nil {
		return err
	}
	if image == nil {
		return apiErr(http.StatusNotFound, "App not found or has no image")
	}
	res, err := rtImageScansScanAndStore(r.Context(), st.DB, serverID, agent, *image)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtImageScansGetAppScan is GET /api/apps/{name}/scan — latest stored result
// for the app's image (null when none).
func rtImageScansGetAppScan(st *AppState, w http.ResponseWriter, r *http.Request) error {
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
	image, err := rtImageScansResolveAppImage(r.Context(), agent, r.PathValue("name"))
	if err != nil {
		return err
	}
	if image == nil {
		writeJSON(w, http.StatusOK, nil)
		return nil
	}
	// The app was resolved on the scoped server, so the scan must come from
	// the scoped server too. Reading by image alone answered with whichever
	// host scanned that name last — a badge about a container the operator is
	// not looking at.
	row, err := queryOpt[rtImageScansScanFindingRow](r.Context(), st.DB,
		"SELECT image, scanner, critical_count, high_count, medium_count, low_count, "+
			"unknown_count, vulnerabilities, scanned_at "+
			"FROM image_scan_findings "+
			"WHERE server_id = $1 AND image = $2 "+
			"ORDER BY scanned_at DESC LIMIT 1", serverID, *image)
	if err != nil {
		return internalError("fetch image scan", err)
	}
	writeJSON(w, http.StatusOK, row)
	return nil
}

// rtImageScansListRecent is GET /api/image-scan/recent — latest result for
// every scanned image ON THE SCOPED SERVER. It hydrates the Apps page's
// badges, keyed client-side into a Record<image, finding>, so a fleet-wide
// `DISTINCT ON (image)` collapsed every host's result for an image into one
// row, last writer wins, with nothing to notice but a wrong number.
func rtImageScansListRecent(st *AppState, w http.ResponseWriter, r *http.Request) error {
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
	rows, err := queryAll[rtImageScansScanFindingRow](r.Context(), st.DB,
		"SELECT DISTINCT ON (image) "+
			"image, scanner, critical_count, high_count, medium_count, low_count, "+
			"unknown_count, vulnerabilities, scanned_at "+
			"FROM image_scan_findings "+
			"WHERE server_id = $1 "+
			"ORDER BY image, scanned_at DESC", serverID)
	if err != nil {
		return internalError("list image scans", err)
	}
	writeJSON(w, http.StatusOK, rows)
	return nil
}

// ── Deploy preflight gate ───────────────────────────────────────────────

// rtImageScansPreflightGate is the soft deploy gate for a template: if a
// recent scan already shows the template's image exceeds the threshold,
// refuse; with no recent scan, allow and trigger a background scan so the
// next deploy of the image enforces the gate (no 30-180s block on first
// encounter).
//
// ⚠ Scoped to the DEPLOY TARGET: reading by image alone let a clean scan on
// one host wave a vulnerable image onto another, and a foreign row satisfied
// the 7-day freshness test so this host's arming scan never fired.
//
// ⚠ THE GATE HAS TO RUN ON EVERY DOOR THAT PUTS AN IMAGE ON THE HOST.
// rtImageScansPreflightGateImage does the work; keep new doors calling it
// (tests/deploy-gate-coverage-pin-e2e.sh enumerates them).
func rtImageScansPreflightGate(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, agent AgentHandle, templateID string) error {
	// Resolving the template costs an agent round trip, so ask whether the
	// gate is armed before paying for it.
	armed, err := rtImageScansGateIsArmed(ctx, db)
	if err != nil || !armed {
		return err
	}
	image := rtImageScansResolveTemplateImage(ctx, agent, templateID)
	if image == nil {
		return nil // unknown template, let deploy fail naturally
	}
	return rtImageScansPreflightGateImage(ctx, db, serverID, agent, *image)
}

// rtImageScansGateIsArmed: the operator switched the deploy gate on and gave
// it a threshold. Split out so a caller can skip expensive work for a gate
// that is off, which is the default.
func rtImageScansGateIsArmed(ctx context.Context, db Querier) (bool, error) {
	enabled, onDeploy, gate, _, err := rtImageScansReadSettings(ctx, db)
	if err != nil {
		return false, internalError("read scan settings for gate", err)
	}
	return enabled && onDeploy && gate != "none", nil
}

// rtImageScansPreflightGateImage is the gate itself, keyed on the image
// reference about to run. Called by the template deploy (via PreflightGate),
// update_image, compose_deploy, stacks create and update.
//
// ⚠ update_app deliberately does NOT call it: it re-pulls the SAME reference,
// so the only scan on file is of the image being replaced — gating on it
// would refuse precisely the update that fixes a vulnerable image.
func rtImageScansPreflightGateImage(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, agent AgentHandle, image string) error {
	enabled, onDeploy, gate, _, err := rtImageScansReadSettings(ctx, db)
	if err != nil {
		return internalError("read scan settings for gate", err)
	}
	if !enabled || !onDeploy || gate == "none" {
		return nil
	}

	// The most recent scan within 7 days.
	recent, err := queryOpt[Tup5[int32, int32, int32, int32, int32]](ctx, db,
		"SELECT critical_count, high_count, medium_count, low_count, unknown_count "+
			"FROM image_scan_findings "+
			"WHERE server_id = $1 AND image = $2 AND scanned_at > NOW() - INTERVAL '7 days' "+
			"ORDER BY scanned_at DESC LIMIT 1", serverID, image)
	if err != nil {
		return internalError("read recent scan", err)
	}
	if recent == nil {
		// Best-effort background scan so the next attempt is gated.
		bg := context.WithoutCancel(ctx)
		go func() {
			if _, err := rtImageScansScanAndStore(bg, db, serverID, agent, image); err != nil {
				slog.Warn(fmt.Sprintf("Background image scan failed for %s: %v", image, err))
			}
		}()
		return nil
	}
	res := rtImageScansImageScanResult{
		Image: image, Scanner: "grype",
		CriticalCount: uint32(recent.A), HighCount: uint32(recent.B), MediumCount: uint32(recent.C),
		LowCount: uint32(recent.D), UnknownCount: uint32(recent.E),
	}
	if rtImageScansExceedsThreshold(gate, &res) {
		return apiErr(http.StatusUnprocessableEntity, fmt.Sprintf(
			"Deploy blocked by image scan gate (%s): %d critical / %d high / %d medium in %s",
			gate, recent.A, recent.B, recent.C, image))
	}
	return nil
}

// rtImageScansResolveTemplateImage looks up a template's image string from
// the agent's template list.
func rtImageScansResolveTemplateImage(ctx context.Context, agent AgentHandle, templateID string) *string {
	templates, err := agent.Get(ctx, "/apps/templates")
	if err != nil {
		return nil
	}
	arr, _ := jsonArr(templates)
	for _, t := range arr {
		if id, ok := jsonStr(jsonGet(t, "id")); ok && id == templateID {
			if img, ok := jsonStr(jsonGet(t, "image")); ok {
				return &img
			}
			return nil
		}
	}
	return nil
}

// ── Internal helpers ────────────────────────────────────────────────────

// rtImageScansResolveAppImage looks up the Docker image of a running
// DockPanel-managed app by name (shared with rt_sboms, which had an
// identical private copy in Rust).
func rtImageScansResolveAppImage(ctx context.Context, agent AgentHandle, appName string) (*string, error) {
	apps, err := agent.Get(ctx, "/apps")
	if err != nil {
		return nil, agentError("list apps", err)
	}
	arr, ok := jsonArr(apps)
	if !ok {
		return nil, nil
	}
	for _, a := range arr {
		n, _ := jsonStr(jsonGet(a, "name"))
		if n == appName {
			if img, ok := jsonStr(jsonGet(a, "image")); ok {
				return &img, nil
			}
			return nil, nil
		}
	}
	return nil, nil
}

// rtImageScansStateKey is the state_key an image's vulnerability alert fires
// and resolves under.
//
// ⚠ alerts.state_key is VARCHAR(100), and a digest-pinned private-registry
// reference easily exceeds it: the INSERT then fails, fire_alert swallows
// the error, and the alert never fires at all. When the readable form does
// not fit, the image is truncated AND a digest of the WHOLE reference is
// appended, so two long images sharing a prefix never collide.
func rtImageScansStateKey(image string) string {
	const maxLen = 100
	readable := "image:" + image
	if len(readable) <= maxLen {
		return readable
	}
	sum := sha256.Sum256([]byte(image))
	digest := hex.EncodeToString(sum[:])
	const prefix = "image:"
	// ⚠ Taken by CHARACTER, not by byte — an image reference is not a
	// validated field, and a byte slice could land inside a multi-byte rune.
	budget := maxLen - len(prefix) - 17
	keep := []rune(image)
	if len(keep) > budget {
		keep = keep[:budget]
	}
	return prefix + string(keep) + "-" + digest[:16]
}

// rtImageScansScanAndStore runs a scan via the agent and persists the
// result. Used by the deploy gate and the background scheduler.
func rtImageScansScanAndStore(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, agent AgentHandle, image string) (*rtImageScansImageScanResult, error) {
	response, err := agent.PostLong(ctx, "/image-scan/scan", map[string]any{"image": image}, 240)
	if err != nil {
		return nil, agentError("scan image", err)
	}
	// serde_json::from_value: every field required (fixed_version /
	// description nullable), counts unsigned.
	raw, _ := json.Marshal(response)
	var result rtImageScansImageScanResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, internalError("parse scan response", err)
	}
	if msg := serdeRequired(raw, reflect.TypeFor[rtImageScansImageScanResult]()); msg != "" {
		return nil, internalError("parse scan response", msg)
	}
	vulnJSON, err := json.Marshal(result.Vulnerabilities)
	if err != nil {
		return nil, internalError("serialize vulns", err)
	}

	if _, err := execSQL(ctx, db,
		"INSERT INTO image_scan_findings "+
			"(server_id, image, scanner, critical_count, high_count, medium_count, low_count, unknown_count, vulnerabilities) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		serverID, result.Image, result.Scanner, int32(result.CriticalCount), int32(result.HighCount),
		int32(result.MediumCount), int32(result.LowCount), int32(result.UnknownCount), json.RawMessage(vulnJSON)); err != nil {
		return nil, internalError("store image scan", err)
	}

	// Trim history per (server, image) — keep the last 30. Per IMAGE alone, a
	// busy server's scans would evict a quiet server's ONLY row and blank its
	// badge despite it having been scanned.
	_, _ = execSQL(ctx, db,
		"DELETE FROM image_scan_findings WHERE server_id = $1 AND image = $2 AND id NOT IN "+
			"(SELECT id FROM image_scan_findings WHERE server_id = $1 AND image = $2 ORDER BY scanned_at DESC LIMIT 30)",
		serverID, result.Image)

	// Resolve-then-fire, mirroring the security scanner: every scan of this
	// (server, image) first clears whatever alert the LAST scan raised, then
	// raises a new one only if THIS scan is still dirty. Before this, a
	// critical CVE in a running container paged nobody — the only way to
	// notice was reading the Apps badge. Keyed per (server_id, image) so two
	// images or two hosts never resolve or suppress each other's alert, and
	// the 30-min sweep re-fires rather than stacking duplicates.
	admins, _ := queryAll[uuid.UUID](ctx, db, "SELECT id FROM users WHERE role = 'admin'")
	stateKey := rtImageScansStateKey(result.Image)
	for _, uid := range admins {
		NotificationsResolveAlert(ctx, db, uid, &serverID, nil, "image_scan", stateKey,
			"Image scan alert resolved: "+result.Image,
			fmt.Sprintf("A later scan of %s found no critical or high severity vulnerability — the earlier alert no longer applies.", result.Image))
	}
	if result.CriticalCount > 0 || result.HighCount > 0 {
		severity := "warning"
		if result.CriticalCount > 0 {
			severity = "critical"
		}
		title := fmt.Sprintf("Image scan: %d critical, %d high in %s", result.CriticalCount, result.HighCount, result.Image)
		message := fmt.Sprintf("A vulnerability scan of %s found %d critical, %d high, %d medium severity issues. Review in Apps.",
			result.Image, result.CriticalCount, result.HighCount, result.MediumCount)
		for _, uid := range admins {
			NotificationsFireAlert(ctx, db, uid, &serverID, nil, "image_scan", stateKey, severity, title, message)
		}
	}
	return &result, nil
}
