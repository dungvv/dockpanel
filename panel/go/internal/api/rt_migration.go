package api

// Port of panel/backend/src/routes/migration.rs — the Migration Wizard:
// analyse a cPanel/Plesk/HestiaCP backup, then import selected sites and
// databases from it, with an SSE progress stream.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtMigrationRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("POST /api/migration/analyze", h(rtMigrationAnalyze))
	r.Handle("GET /api/migration", h(rtMigrationList))
	r.Handle("GET /api/migration/{id}", h(rtMigrationGetOne))
	r.Handle("DELETE /api/migration/{id}", h(rtMigrationRemove))
	r.Handle("POST /api/migration/{id}/import", h(rtMigrationImport))
	r.Handle("GET /api/migration/{id}/progress", h(rtMigrationProgress))
}

// ── Request / Response types ─────────────────────────────────

type rtMigrationAnalyzeRequest struct {
	// A path already on the server's disk. Mutually exclusive with `url` —
	// exactly one of the two must be set.
	Path   string  `json:"path" serde:"default"`
	Source *string `json:"source"` // "cpanel", "plesk", "hestiacp"
	// Fetch the archive from this URL instead of requiring the operator SFTP
	// it up first. The agent downloads it into the same /var/backups/ tree a
	// manually-placed archive already had to live under, then analysis
	// proceeds exactly as before.
	URL *string `json:"url"`
}

type rtMigrationImportRequest struct {
	Sites     *[]rtMigrationImportSiteItem `json:"sites"`
	Databases *[]rtMigrationImportDbItem   `json:"databases"`
}

type rtMigrationImportSiteItem struct {
	Domain  string `json:"domain"`
	DocRoot string `json:"doc_root"`
	Runtime string `json:"runtime"`
}

type rtMigrationImportDbItem struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	Engine string `json:"engine"`
	// Which imported site this database belongs to.
	//
	// A `databases` row cannot exist without one — the column is NOT NULL
	// with no default — and a control-panel archive does not record the
	// association, so it has to come from the operator. Optional on the wire
	// because a single-site archive has only one possible answer; when the
	// run imports several sites and this is absent, the database is refused
	// rather than guessed at.
	SiteDomain *string `json:"site_domain"`
}

type rtMigrationMigration struct {
	ID            uuid.UUID        `json:"id" db:"id"`
	UserID        uuid.UUID        `json:"user_id" db:"user_id"`
	ServerID      *uuid.UUID       `json:"server_id" db:"server_id"`
	Source        string           `json:"source" db:"source"`
	Status        string           `json:"status" db:"status"`
	BackupPath    string           `json:"backup_path" db:"backup_path"`
	Inventory     *json.RawMessage `json:"inventory" db:"inventory"`
	SelectedItems *json.RawMessage `json:"selected_items" db:"selected_items"`
	Result        *json.RawMessage `json:"result" db:"result"`
	CreatedAt     time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at" db:"updated_at"`
}

// agentMigrationID is the agent-side migration id recorded in the inventory
// (`inventory.id`), needed for the agent's import/cleanup calls.
func (m *rtMigrationMigration) agentMigrationID() (string, bool) {
	if m.Inventory == nil {
		return "", false
	}
	var inv map[string]any
	if json.Unmarshal(*m.Inventory, &inv) != nil {
		return "", false
	}
	s, ok := inv["id"].(string)
	return s, ok
}

func rtMigrationStr(s string) *string { return &s }

// rtMigrationEmitStep reuses the shared provision logs, as sites.rs does.
func rtMigrationEmitStep(st *AppState, id uuid.UUID, step, label, status string, message *string) {
	st.ProvisionLogs.Emit(id, ProvisionStep{Step: step, Label: label, Status: status, Message: message})
}

// ── POST /api/migration/analyze ──────────────────────────────

// rtMigrationAnalyzeAgentTimeoutSecs is the panel-side budget for the agent's
// analyze call.
//
// Deliberately LONGER than the agent's own extraction budget so that when a
// giant archive runs out of time it is the *agent* that says so — naming the
// archive and the budget — instead of this side winning the race and
// reporting a contentless "agent request timed out". A caller timeout shorter
// than the callee's does not bound anything the callee did not already bound;
// it only replaces a real diagnosis with a generic one.
const rtMigrationAnalyzeAgentTimeoutSecs uint64 = 1860

// rtMigrationFetchAgentTimeoutSecs: same "60s longer than the agent's own
// ceiling" shape — the agent's FETCH_TIMEOUT_SECS is 1800s.
const rtMigrationFetchAgentTimeoutSecs uint64 = 1860

// rtMigrationFetchArchiveExtension is a best-effort archive extension for a
// URL-fetched file's on-disk name — cosmetic only. The agent's extractor
// tries gzip then plain tar regardless of what this names it; this only makes
// a failure message that echoes the path read like a real backup name
// instead of a bare UUID.
func rtMigrationFetchArchiveExtension(url string) string {
	lower := url
	if i := strings.IndexAny(url, "?#"); i >= 0 {
		lower = url[:i]
	}
	lower = strings.ToLower(lower)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return ".zip"
	case strings.HasSuffix(lower, ".tar"):
		return ".tar"
	default:
		return ".tar.gz"
	}
}

// rtMigrationEngineReadyTimeoutSecs: how long to wait for an imported
// database's engine to start answering.
//
// A fresh `mariadb:11` initialises its data directory behind a bootstrap
// server that refuses the application user, so "is the container running" is
// not "is the database usable". Generous, because the cost of waiting is a
// slower import and the cost of not waiting is an `Access denied` that sends
// the operator after a password that was always correct.
const rtMigrationEngineReadyTimeoutSecs = 120

// rtMigrationAnalyze analyzes a panel backup (cPanel/Plesk/HestiaCP).
//
// **Accepted, not performed.** Walking a cPanel archive is minutes of work for
// any real account, and every gateway between the browser and this handler
// gives up long before that (Cloudflare 100s, nginx 300s, the panel's own
// 300s timeout). Running the analysis inline therefore *guaranteed* a 524/504
// for precisely the archives the wizard exists to import (#91).
//
// So the row is inserted `analyzing`, the agent call moves to a goroutine, and
// this returns 202 immediately. The verdict lands in the row — `analyzed`
// with an inventory, or `failed` carrying the agent's real message — which is
// what GET /api/migration/{id} serves. That row outlives the request, the tab
// and a reload. It does not outlive the process, which is what
// rtMigrationFinalizeAnalyzingOnStartup exists to close out.
func rtMigrationAnalyze(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body rtMigrationAnalyzeRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	path := strings.TrimSpace(body.Path)
	var url *string
	if body.URL != nil {
		if u := strings.TrimSpace(*body.URL); u != "" {
			url = &u
		}
	}

	if path == "" && url == nil {
		return apiErr(http.StatusBadRequest, "A backup path, or a URL to fetch it from, is required")
	}
	if path != "" && url != nil {
		return apiErr(http.StatusBadRequest, "Provide either a path or a URL, not both")
	}
	if url != nil && !(strings.HasPrefix(*url, "http://") || strings.HasPrefix(*url, "https://")) {
		return apiErr(http.StatusBadRequest, "Only http:// and https:// URLs are supported")
	}

	source := "auto"
	if body.Source != nil {
		source = *body.Source
	}
	if !slices.Contains([]string{"auto", "cpanel", "plesk", "hestiacp"}, source) {
		return apiErr(http.StatusBadRequest, "Source must be auto, cpanel, plesk, or hestiacp")
	}

	// A URL fetch doesn't know its final on-disk path until the download
	// completes, but `backup_path` is populated from the moment the row exists
	// (every other reader of this table assumes that). Compute it
	// deterministically now — it doubles as the exact destination the agent
	// is told to write the file to.
	resolvedPath := path
	if url != nil {
		resolvedPath = fmt.Sprintf("/var/backups/dockpanel/migration-fetch/%s%s", uuid.New(), rtMigrationFetchArchiveExtension(*url))
	}

	// Create migration record (status = analyzing)
	migration, err := queryOne[rtMigrationMigration](r.Context(), st.DB,
		"INSERT INTO migrations (user_id, server_id, source, status, backup_path) "+
			"VALUES ($1, $2, $3, 'analyzing', $4) RETURNING *",
		claims.Sub, serverID, source, resolvedPath)
	if err != nil {
		return internalError("analyze", err)
	}

	db := st.DB
	migrationID := migration.ID
	userID, email, keyID := claims.Sub, claims.Email, claims.KeyID
	ctx := context.WithoutCancel(r.Context())

	go func() {
		failed := func(msg string) {
			_, _ = execSQL(ctx, db,
				"UPDATE migrations SET status = 'failed', result = $1, updated_at = NOW() "+
					"WHERE id = $2",
				map[string]any{"error": msg}, migrationID)
		}

		// A URL fetch happens first — a failure here is recorded the exact same
		// way an analyze failure is below, so the operator sees one consistent
		// "failed, here's why" in the row instead of this request hanging on a
		// slow remote host.
		if url != nil {
			if _, err := agent.PostLong(ctx, "/migration/fetch",
				map[string]any{"url": *url, "dest": resolvedPath}, rtMigrationFetchAgentTimeoutSecs); err != nil {
				slog.Error(fmt.Sprintf("Migration %s: fetch failed: %v", migrationID, err))
				failed(fmt.Sprintf("Could not fetch the archive: %v", err))
				return
			}
		}

		inventory, err := agent.PostLong(ctx, "/migration/analyze",
			map[string]any{"path": resolvedPath, "source": source}, rtMigrationAnalyzeAgentTimeoutSecs)
		if err != nil {
			// There is no HTTP response left to shape this into, so the agent's
			// own sentence goes into the row verbatim and the poller reads it
			// out of `result.error`. This is the ONLY place the reason for a
			// failed analysis is recorded — #90 was that reason being replaced
			// by a generic one on the way out.
			slog.Error(fmt.Sprintf("Migration %s: analysis failed: %v", migrationID, err))
			failed(err.Error())
			return
		}
		if _, err := execSQL(ctx, db,
			"UPDATE migrations SET status = 'analyzed', inventory = $1, updated_at = NOW() "+
				"WHERE id = $2", inventory, migrationID); err != nil {
			// The work is done and the panel cannot say so. Leaving the row
			// 'analyzing' would poll forever, so record the failure that the
			// operator can actually act on.
			slog.Error(fmt.Sprintf("Migration %s: inventory write failed: %v", migrationID, err))
			failed(fmt.Sprintf("Analysis finished but its result could not be saved: %v", err))
			return
		}
		slog.Info(fmt.Sprintf("Migration analyzed: %s (source: %s)", resolvedPath, source))
		ActivityLogActivity(ctx, db, userID, email, "migration.analyze",
			rtMigrationStr("migration"), &resolvedPath, &source, nil, keyID)
	}()

	writeJSON(w, http.StatusAccepted, migration)
	return nil
}

// rtMigrationFinalizeAnalyzingOnStartup closes out analyses that were in
// flight when the process died.
//
// The analysis runs in a goroutine, so a restart takes it with no chance to
// write its own verdict — and an `analyzing` row with nothing left to finish
// it is a spinner the operator can never clear. Same remedy as
// panel_update::finalize_pending_on_startup: on boot nothing is running, so
// every row still claiming to be is stale by definition. `importing` rows are
// swept too, for the same reason.
func rtMigrationFinalizeAnalyzingOnStartup(ctx context.Context, db *pgxpool.Pool) {
	// Two statuses, two different truths, so two sentences. Analysis only
	// reads the archive, so an interrupted one leaves nothing behind and
	// starting again is the whole remedy. An import MUTATES as it goes — it
	// writes nginx vhosts, `sites` rows and database containers one selection
	// at a time — so telling the operator to run it again would be telling
	// them to re-import over what already landed.
	sweeps := [2][2]string{
		{"analyzing", "The panel restarted while this archive was being analysed. Nothing was " +
			"changed on the server — analysis only reads — so run it again."},
		{"importing", "The panel restarted part-way through this import. Whatever had already " +
			"been imported is still there; the rest was not. Check Sites and Databases " +
			"for what landed before importing the remainder."},
	}
	for _, s := range sweeps {
		status, message := s[0], s[1]
		n, err := execSQL(ctx, db,
			"UPDATE migrations SET status = 'failed', "+
				"result = COALESCE(result, '{}'::jsonb) || $1::jsonb, updated_at = NOW() "+
				"WHERE status = $2",
			map[string]any{"error": message}, status)
		switch {
		case err != nil:
			slog.Warn(fmt.Sprintf("finalize_analyzing_on_startup: '%s' sweep failed: %v", status, err))
		case n > 0:
			slog.Warn(fmt.Sprintf("Closed out %d migration(s) left '%s' by a previous process", n, status))
		}
	}
}

// ── GET /api/migration/{id} ──────────────────────────────────

func rtMigrationOwned(r *http.Request, st *AppState, id, userID uuid.UUID, ctxName string) (*rtMigrationMigration, error) {
	m, err := queryOpt[rtMigrationMigration](r.Context(), st.DB, "SELECT * FROM migrations WHERE id = $1 AND user_id = $2", id, userID)
	if err != nil {
		return nil, internalError(ctxName, err)
	}
	if m == nil {
		return nil, apiErr(http.StatusNotFound, "Migration not found")
	}
	return m, nil
}

// rtMigrationGetOne gets a single migration record.
func rtMigrationGetOne(st *AppState, w http.ResponseWriter, r *http.Request) error {
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
	m, err := rtMigrationOwned(r, st, id, claims.Sub, "get_one migration")
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, m)
	return nil
}

// ── GET /api/migration ───────────────────────────────────────

// rtMigrationList lists all migrations for the current user.
func rtMigrationList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ms, err := queryAll[rtMigrationMigration](r.Context(), st.DB,
		"SELECT * FROM migrations WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50", claims.Sub)
	if err != nil {
		return internalError("list migration", err)
	}
	writeJSON(w, http.StatusOK, ms)
	return nil
}

// ── POST /api/migration/{id}/import ──────────────────────────

// rtMigrationImportResults is the `result` JSON an import writes.
type rtMigrationImportResults struct {
	SitesImported     []any    `json:"sites_imported"`
	SitesSkipped      []string `json:"sites_skipped"`
	DatabasesImported []any    `json:"databases_imported"`
	DatabasesFailed   []string `json:"databases_failed"`
	Errors            []string `json:"errors"`
}

// rtMigrationImport starts importing selected sites and databases from an
// analyzed migration.
//
// **The destination is the row's, not the picker's.** Everything below is a
// write against one specific machine: it publishes an nginx vhost for a live
// customer domain, claims that domain, inserts a `sites` row that names its
// host permanently, and creates database containers. The archive was unpacked
// and staged by the analyse step on the host that step ran against — which is
// why `analyze` records the server on the row. Reading the destination off
// the caller's server selection answered differently the moment an operator
// switched servers between analysing and importing: vhosts for somebody's
// live domains published on a machine that must not serve them, and then not
// one file copied, because the staged archive was on the other host.
func rtMigrationImport(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtMigrationImportRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()

	// The fourth handler that writes `sites` rows, and the only one that
	// writes them in bulk. Gated here, at the entry point, rather than in the
	// loop — a lockdown declared mid-import should not tear down a run already
	// in flight and leave half a migration behind.
	//
	// Deliberately WITHOUT the per-hour ceiling the other three carry: a bulk
	// import is an operator asking for exactly that, from a source they named.
	// A lockdown is the different question — whether the panel should be
	// creating anything at all right now.
	if SecurityHardeningIsLockedDown(ctx, st.DB) {
		return apiErr(http.StatusServiceUnavailable, "System is in lockdown mode")
	}

	// Verify migration exists, belongs to user, and is analyzed
	migration, err := rtMigrationOwned(r, st, id, claims.Sub, "import")
	if err != nil {
		return err
	}
	if migration.Status != "analyzed" {
		return apiErr(http.StatusBadRequest, fmt.Sprintf("Migration is '%s', expected 'analyzed'", migration.Status))
	}

	// Both halves of the destination come from the row: the id (written into
	// the `sites` rows and passed to the domain claim) and the handle (what
	// creates the vhosts and the database containers). Resolved BEFORE the
	// status moves to 'importing' — a migration refused here has not started.
	//
	// A row that names no server is refused rather than guessed at: the one
	// thing that must never happen to an older row is having a host chosen
	// for it by whoever opened the page. Not importing is recoverable,
	// importing onto the wrong machine is not.
	if migration.ServerID == nil {
		slog.Warn(fmt.Sprintf("Refusing to import migration %s: its row names no server", id))
		return apiErr(http.StatusConflict, "This migration is not associated with a server")
	}
	serverID := *migration.ServerID
	agent, err := agentForSiteServer(ctx, st, &serverID, migration.BackupPath)
	if err != nil {
		return err
	}

	var sites []rtMigrationImportSiteItem
	if body.Sites != nil {
		sites = *body.Sites
	}
	var databases []rtMigrationImportDbItem
	if body.Databases != nil {
		databases = *body.Databases
	}
	if len(sites) == 0 && len(databases) == 0 {
		return apiErr(http.StatusBadRequest, "Select at least one site or database to import")
	}

	// Store selected items and update status
	siteNames := make([]string, 0, len(sites))
	for _, s := range sites {
		siteNames = append(siteNames, s.Domain)
	}
	dbNames := make([]string, 0, len(databases))
	for _, d := range databases {
		dbNames = append(dbNames, d.Name)
	}
	selected := map[string]any{"sites": siteNames, "databases": dbNames}

	if _, err := execSQL(ctx, st.DB,
		"UPDATE migrations SET status = 'importing', selected_items = $1, updated_at = NOW() WHERE id = $2",
		selected, id); err != nil {
		return internalError("import", err)
	}

	// Extract the agent-side migration_id from the inventory (needed for agent import calls)
	agentMigrationID, ok := migration.agentMigrationID()
	if !ok {
		return apiErr(http.StatusInternalServerError, "Migration inventory missing agent ID")
	}

	// Registered only once nothing above can still bail. Creating the log
	// first meant the line above returned a 500 while leaving a log and an
	// owner behind for the whole TTL — and `progress` would then answer 200 on
	// a stream nothing would ever emit to.
	st.ProvisionLogs.Register(id, claims.Sub, 64)

	bg := context.WithoutCancel(ctx)
	userID, email, keyID := claims.Sub, claims.Email, claims.KeyID
	migrationSource := migration.Source
	// The imported domains are client-supplied and never reconciled against
	// what the analyse step found, so they get the same guard as any other
	// claim. The request is carried into the goroutine because the reserved-
	// domain check reads the Host header — BASE_URL is empty on a routine
	// install. The role is carried so the choke point sees a real role from
	// every caller (import is admin-only today).
	claimReq := r.Clone(bg)
	claimRole := claims.Role

	go rtMigrationRunImport(bg, st, id, serverID, agent, userID, email, keyID, agentMigrationID,
		migrationSource, claimReq, claimRole, sites, databases)

	writeJSON(w, http.StatusAccepted, map[string]any{"migration_id": id})
	return nil
}

func rtMigrationRunImport(ctx context.Context, st *AppState, id, serverID uuid.UUID, agent AgentHandle,
	userID uuid.UUID, email string, keyID *uuid.UUID, agentMigrationID, migrationSource string,
	claimReq *http.Request, claimRole string, sites []rtMigrationImportSiteItem, databases []rtMigrationImportDbItem) {
	db := st.DB
	results := rtMigrationImportResults{
		SitesImported: []any{}, SitesSkipped: []string{}, DatabasesImported: []any{},
		DatabasesFailed: []string{}, Errors: []string{},
	}
	totalSteps := len(sites) + len(databases)
	completed := 0
	emit := func(step, label, status string, msg *string) { rtMigrationEmitStep(st, id, step, label, status, msg) }

	// Every site row this run creates, in order. The databases loop needs one:
	// `databases.site_id` is NOT NULL. Recorded when the row lands rather than
	// when the whole site succeeds — a site whose files failed to copy still
	// has a valid row, and refusing its databases as well would punish them
	// for an unrelated failure.
	type importedSite struct {
		domain string
		id     uuid.UUID
	}
	var importedSites []importedSite

	// ── Import sites ──────────────────────────────────────
	for _, siteItem := range sites {
		domain := siteItem.Domain
		stepKey := "site_" + domain
		siteErr := func(msg string) {
			slog.Error(msg)
			emit(stepKey, "Site "+domain, "error", &msg)
			results.Errors = append(results.Errors, msg)
			completed++
		}

		emit(stepKey, "Importing site "+domain, "in_progress", nil)

		// Is this domain claimable? Same guard as every other path — which also
		// supplies the format and reserved-domain checks the import never had,
		// and extends "already exists" past the `sites` table to git deploys
		// and Docker apps. Note the ORDER below: the vhost is written before
		// the row is inserted, so a domain that slips past this is already on
		// disk by the time the INSERT could reject it.
		claimed, err := DomainClaimEnsureClaimable(ctx, db, st.Agents, domain, claimReq, DomainClaimHolderNew, claimRole)
		if err != nil {
			detail := "domain not available"
			var ae *ApiError
			if errors.As(err, &ae) {
				if s, ok := jsonGet(ae.Body, "error").(string); ok {
					detail = s
				}
			}
			emit(stepKey, "Site "+domain, "done", rtMigrationStr("Skipped ("+detail+")"))
			results.SitesSkipped = append(results.SitesSkipped, domain)
			completed++
			continue
		}
		domain = claimed

		// 1. Create nginx site via agent — except when the required config
		// simply cannot be known from a file-tree scan.
		//
		// The agent's detect_runtime only ever answers "php", "node", "python"
		// or "static". "php" needs a PHP-FPM socket and "node"/"python" need a
		// port AND a start command, none of which a cPanel/Plesk/HestiaCP
		// archive records. Sending `{"runtime": "php"}` with no `php_socket`
		// does NOT fail: the agent skips its validation and renders a default
		// socket path that does not exist under the versioned PHP-FPM
		// convention — an always-broken config reported as a success.
		// "node"/"python" are worse: without `proxy_port` the config defaults
		// to `proxy_pass http://127.0.0.1:3000` — pointing at nothing, or at
		// whatever unrelated thing listens on 3000.
		//
		// So: for "php", resolve a real, currently-running PHP-FPM version from
		// the server and send that socket. For "node"/"python" (and defensively
		// any other value, since this field is client-supplied) there is
		// nothing safe to send — serving it as "static" would expose the app's
		// raw source (`.env`, DB credentials) over HTTP. Skip the vhost; the
		// site row and file copy still land, so nothing imported is lost.
		runtime := siteItem.Runtime
		nginxBody := map[string]any{"runtime": runtime}
		var needsConfig *string

		if runtime == "php" {
			resp, err := agent.Get(ctx, "/php/versions")
			if err != nil {
				needsConfig = rtMigrationStr("could not check installed PHP versions on this server — set " +
					"the PHP version from the site's Settings after import")
			} else {
				var running *string
				versions, _ := jsonArr(jsonGet(resp, "versions"))
				for _, v := range versions {
					installed, _ := jsonBool(jsonGet(v, "installed"))
					fpm, _ := jsonBool(jsonGet(v, "fpm_running"))
					if installed && fpm {
						if s, ok := jsonStr(jsonGet(v, "version")); ok {
							running = &s
						}
						break
					}
				}
				if running != nil {
					nginxBody["php_socket"] = fmt.Sprintf("unix:/run/php/php%s-fpm.sock", *running)
				} else {
					needsConfig = rtMigrationStr("no running PHP-FPM version was found on this server — " +
						"install one and set it from the site's PHP Version " +
						"control after import")
				}
			}
		} else if runtime != "static" {
			needsConfig = rtMigrationStr(fmt.Sprintf("%s sites need a port and start command, which can't be "+
				"detected from the backup — set them from the site's Settings after import", runtime))
		}

		if needsConfig != nil {
			slog.Warn(fmt.Sprintf("Migration %s: site %s imported without a vhost: %s", id, domain, *needsConfig))
		} else if _, err := agent.Put(ctx, "/nginx/sites/"+domain, nginxBody); err != nil {
			siteErr(fmt.Sprintf("Nginx config failed for %s: %v", domain, err))
			continue
		}

		// 2. Insert site record into DB
		//
		// `server_id` is the migration row's, so the vhost, the claim, this
		// permanent binding and the file copy all name one machine. A site row
		// is what every later handler reads to decide which host to talk to.
		//
		// Status is 'error' rather than 'active' when no vhost was written —
		// nothing serves this domain yet, and 'active' would say otherwise.
		initialStatus := "active"
		if needsConfig != nil {
			initialStatus = "error"
		}
		siteID, err := queryScalar[uuid.UUID](ctx, db,
			"INSERT INTO sites (user_id, server_id, domain, runtime, status) "+
				"VALUES ($1, $2, $3, $4, $5) RETURNING id",
			userID, serverID, domain, runtime, initialStatus)
		if err != nil {
			siteErr(fmt.Sprintf("DB insert failed for %s: %v", domain, err))
			continue
		}

		importedSites = append(importedSites, importedSite{strings.ToLower(domain), siteID})

		// 3. Copy files via agent
		importBody := map[string]any{
			"migration_id": agentMigrationID,
			"domain":       domain,
			"source_dir":   siteItem.DocRoot,
			// Same runtime the vhost was just created with, so the files land
			// in the directory that vhost serves.
			"runtime": runtime,
		}
		if _, err := agent.PostLong(ctx, "/migration/import-site", importBody, 300); err != nil {
			siteErr(fmt.Sprintf("File import failed for %s: %v", domain, err))
			// Site record exists but files failed — mark as error status
			_, _ = execSQL(ctx, db, "UPDATE sites SET status = 'error', updated_at = NOW() WHERE id = $1", siteID)
			continue
		}

		doneMessage := "Imported"
		if needsConfig != nil {
			doneMessage = "Imported — needs configuration: " + *needsConfig
		}
		emit(stepKey, "Site "+domain, "done", &doneMessage)
		results.SitesImported = append(results.SitesImported, map[string]any{
			"domain":       domain,
			"site_id":      siteID,
			"needs_config": needsConfig,
		})
		if needsConfig != nil {
			results.Errors = append(results.Errors, domain+": "+*needsConfig)
		}

		completed++
		slog.Info(fmt.Sprintf("Migration %s: imported site %s (%d/%d)", id, domain, completed, totalSteps))
	}

	// ── Import databases ──────────────────────────────────
	for _, dbItem := range databases {
		dbName := dbItem.Name
		engine := dbItem.Engine
		stepKey := "db_" + dbName
		dbFailed := func(msg string, warn bool) {
			if warn {
				slog.Warn(msg)
			} else {
				slog.Error(msg)
			}
			emit(stepKey, "Database "+dbName, "error", &msg)
			results.DatabasesFailed = append(results.DatabasesFailed, dbName)
			results.Errors = append(results.Errors, msg)
			completed++
		}

		emit(stepKey, "Importing database "+dbName, "in_progress", nil)

		// ── Which site does this database belong to? ──
		//
		// Resolved BEFORE anything is created, because the answer decides
		// whether this database can be imported at all. `databases.site_id` is
		// NOT NULL, and the container is created first, so discovering that
		// after the fact leaves a running database the panel can never list,
		// reach or delete, holding a password that exists nowhere else.
		//
		// Explicit wins; a single-site run resolves itself; anything else is
		// refused with the reason, rather than attached to whichever site
		// happened to be imported first.
		var siteID *uuid.UUID
		if dbItem.SiteDomain != nil && strings.TrimSpace(*dbItem.SiteDomain) != "" {
			wanted := strings.ToLower(strings.TrimRight(strings.TrimSpace(*dbItem.SiteDomain), "."))
			for _, s := range importedSites {
				if s.domain == wanted {
					sid := s.id
					siteID = &sid
					break
				}
			}
			if siteID == nil {
				// Not imported in this run — but it may be a site the caller
				// already has ("import the site first, then the databases").
				// Through the shared helper, never a query of our own: a
				// private domain lookup here is the shape domain-claim §B2
				// forbids, because that is how paths came to disagree.
				siteID = siteIDForOwnedDomain(ctx, db, wanted, userID)
			}
		} else if len(importedSites) == 1 {
			sid := importedSites[0].id
			siteID = &sid
		}

		if siteID == nil {
			var msg string
			switch {
			case dbItem.SiteDomain != nil:
				msg = fmt.Sprintf("Database %s names a site that is not in this import and does not "+
					"already exist on this account. Nothing was created.", dbName)
			case len(importedSites) == 0:
				msg = fmt.Sprintf("Database %s was not imported: a database has to belong to a site, "+
					"and this run imported none. Import the site first, then run the database "+
					"import again. Nothing was created.", dbName)
			default:
				msg = fmt.Sprintf("Database %s was not imported: this run has %d sites and the archive "+
					"does not record which one owns it. Choose the site for it and import again. "+
					"Nothing was created.", dbName, len(importedSites))
			}
			dbFailed(msg, true)
			continue
		}

		// Generate password
		password := strings.ReplaceAll(uuid.NewString(), "-", "")

		// Find available port
		rangeStart, rangeEnd := int32(5433), int32(5500)
		if engine == "mysql" || engine == "mariadb" {
			rangeStart, rangeEnd = 3307, 3400
		}
		port, _ := queryScalarOpt[int32](ctx, db,
			"SELECT s.port FROM generate_series($1::int, $2::int) AS s(port) "+
				"WHERE s.port NOT IN (SELECT port FROM databases WHERE port IS NOT NULL) "+
				"LIMIT 1", rangeStart, rangeEnd)
		if port == nil {
			dbFailed("No available port for database "+dbName, false)
			continue
		}

		// Insert the DB record BEFORE calling the agent — mirrors
		// databases::create's own "insert first" pattern. The port SELECT above
		// is unlocked, so it cannot rule out a second concurrent picker on its
		// own; inserting first lets `idx_databases_port_unique` reject the
		// losing side's row before either one reaches the agent (and Docker is
		// asked to bind the same port twice).
		encryptedPassword, err := SecretsCryptoEncryptCredential(password, st.Config.JWTSecret)
		if err != nil {
			encryptedPassword = password
		}
		dbID, err := queryScalarOpt[uuid.UUID](ctx, db,
			"INSERT INTO databases (site_id, engine, name, db_user, db_password_enc, container_id, port) "+
				"VALUES ($1, $2, $3, $4, $5, '', $6) "+
				"ON CONFLICT ON CONSTRAINT databases_site_name_unique DO NOTHING RETURNING id",
			*siteID, engine, dbName, dbName, encryptedPassword, *port)
		switch {
		// `databases_site_name_unique` is named explicitly above, so a unique
		// violation reaching here can only be the OTHER unique index — a
		// concurrent picker won the same port first. Named separately because
		// it tells the operator the truth: retrying is expected to work.
		case err != nil && strings.Contains(err.Error(), "idx_databases_port_unique"):
			dbFailed(fmt.Sprintf("Port %d for database %s was claimed by a concurrent "+
				"operation — not imported. Retry the import for this database.", *port, dbName), true)
			continue
		case err != nil:
			dbFailed(fmt.Sprintf("Could not record database %s: %v", dbName, err), false)
			continue
		case dbID == nil:
			dbFailed(fmt.Sprintf("Database %s already exists on that site — not imported.", dbName), true)
			continue
		}

		// Create database container via agent. The row above holds this exact
		// port under a uniqueness guarantee, so this call — and Docker — are
		// the only thing left that can fail.
		resp, err := agent.Post(ctx, "/databases", map[string]any{
			"name": dbName, "engine": engine, "password": password, "port": *port,
		})
		if err != nil {
			dbFailed(fmt.Sprintf("Database container creation failed for %s: %v", dbName, err), false)
			// The row claimed this port and name but no container exists for
			// it — delete it (mirrors databases::create's agent-failure
			// cleanup) so a retry isn't blocked by a row for a database that
			// was never created.
			_, _ = execSQL(ctx, db, "DELETE FROM databases WHERE id = $1", *dbID)
			continue
		}
		containerID, _ := jsonStr(jsonGet(resp, "container_id"))
		containerName, _ := jsonStr(jsonGet(resp, "name"))

		// Record the real container_id now that the agent has returned one.
		// Not fatal if this write fails — the row and the container both exist
		// either way; this only affects later delete/restart lookups.
		if _, err := execSQL(ctx, db, "UPDATE databases SET container_id = $1 WHERE id = $2", containerID, *dbID); err != nil {
			slog.Error(fmt.Sprintf("Migration %s: database %s was created but its container_id "+
				"could not be recorded: %v", id, dbName, err))
		}

		// Wait for engine to be ready
		emit(stepKey, "Waiting for "+dbName+" engine", "in_progress", nil)

		// Poll until the engine answers, rather than sleeping a fixed five
		// seconds and hoping. `mariadb:11` runs a bootstrap server during
		// initialisation and does not accept the application user until that
		// finishes; the import then failed with `Access denied` — a
		// credentials message for a timing problem.
		probe := map[string]any{
			"container": containerName,
			"engine":    engine,
			"database":  dbName,
			"user":      dbName,
			"password":  password,
			"sql":       "SELECT 1",
		}
		deadline := time.Now().Add(rtMigrationEngineReadyTimeoutSecs * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			if _, err := agent.Post(ctx, "/databases/query", probe); err == nil {
				ready = true
				break
			}
			time.Sleep(2 * time.Second)
		}
		if !ready {
			slog.Warn(fmt.Sprintf("Migration %s: %s's engine did not answer within "+
				"%ds; importing anyway so the real error is reported rather than a timeout of our own",
				id, dbName, rtMigrationEngineReadyTimeoutSecs))
		}

		// Import SQL dump via agent
		importBody := map[string]any{
			"migration_id":   agentMigrationID,
			"sql_file":       dbItem.File,
			"container_name": containerName,
			"db_name":        dbName,
			"engine":         engine,
			"user":           dbName,
			"password":       password,
		}
		if _, err := agent.PostLong(ctx, "/migration/import-database", importBody, 600); err != nil {
			msg := fmt.Sprintf("SQL import failed for %s: %v", dbName, err)
			slog.Error(msg)
			emit(stepKey, "Database "+dbName, "error", &msg)
			results.DatabasesFailed = append(results.DatabasesFailed, dbName)
			results.Errors = append(results.Errors, msg)
		} else {
			emit(stepKey, "Database "+dbName, "done", rtMigrationStr("Imported"))
			results.DatabasesImported = append(results.DatabasesImported, map[string]any{"name": dbName, "port": *port})
		}

		completed++
		slog.Info(fmt.Sprintf("Migration %s: processed database %s (%d/%d)", id, dbName, completed, totalSteps))
	}

	// ── Finalize ──────────────────────────────────────────
	// Always "done" — errors are in the result JSON.
	_, _ = execSQL(ctx, db,
		"UPDATE migrations SET status = $1, result = $2, updated_at = NOW() WHERE id = $3",
		"done", results, id)

	ActivityLogActivity(ctx, db, userID, email, "migration.import",
		rtMigrationStr("migration"), &migrationSource, nil, nil, keyID)

	emit("complete", "Migration complete", "done", nil)
	slog.Info(fmt.Sprintf("Migration %s completed", id))

	// Keep the log channel alive for 60s so the frontend can catch up
	time.Sleep(60 * time.Second)
	st.ProvisionLogs.Remove(id)
}

// ── GET /api/migration/{id}/progress — SSE stream ────────────

// rtMigrationSSEKeepAlive is axum's KeepAlive interval for this stream.
const rtMigrationSSEKeepAlive = 15 * time.Second

// rtMigrationProgress is the SSE stream of migration import progress.
func rtMigrationProgress(st *AppState, w http.ResponseWriter, r *http.Request) error {
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
	// Verify ownership
	exists, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB, "SELECT id FROM migrations WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("progress", err)
	}
	if exists == nil {
		return apiErr(http.StatusNotFound, "Migration not found")
	}

	// As in sites::provision_log, the row check above is kept alongside the
	// per-key owner check.
	snapshot, rx, unsub, err := st.ProvisionLogs.Open(id, claims.Sub, "No active import for this migration")
	if err != nil {
		return err
	}
	defer unsub()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	send := func(chunk string) bool {
		if _, err := fmt.Fprint(w, chunk); err != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}
	event := func(step ProvisionStep) bool {
		data, _ := json.Marshal(step)
		return send("data: " + string(data) + "\n\n")
	}
	if flusher != nil {
		flusher.Flush()
	}

	// First yield snapshot events, then stream live updates
	for _, step := range snapshot {
		if !event(step) {
			return nil
		}
	}

	// The channel closes (and this stream ends) once the import finishes and
	// its entry is dropped — but an import in progress at shutdown can run
	// well past the graceful-drain window, so race the panel's own shutdown
	// signal too.
	ka := time.NewTimer(rtMigrationSSEKeepAlive)
	defer ka.Stop()
	for {
		select {
		case step, ok := <-rx:
			if !ok || !event(step) {
				return nil
			}
		case <-ka.C:
			if !send(": ping\n\n") {
				return nil
			}
		case <-r.Context().Done():
			return nil
		case <-st.Shutdown.Done():
			return nil
		}
		ka.Reset(rtMigrationSSEKeepAlive)
	}
}

// ── DELETE /api/migration/{id} ───────────────────────────────

// rtMigrationRemove deletes a migration record and cleans up temp files.
//
// The staging directory is on the host that unpacked the archive, which the
// row names — so that is where the cleanup goes, rather than wherever the
// server picker happens to be pointing. Sent to any other machine the call
// succeeds and does nothing, while the real extracted copy — a whole cPanel
// account's files — stays on disk with the record that could have found it
// now deleted.
func rtMigrationRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
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
	ctx := r.Context()
	migration, err := rtMigrationOwned(r, st, id, claims.Sub, "remove migration")
	if err != nil {
		return err
	}

	// Ask agent to clean up extracted temp files (best-effort)
	agentMigrationID, _ := migration.agentMigrationID()
	cleanupBody := map[string]any{"migration_id": agentMigrationID}

	// An unresolvable host is not fatal here, and that is the one place this
	// differs from the import. The record is panel state: it has to stay
	// deletable after the machine that staged it has been decommissioned. So
	// the cleanup is skipped and said out loud, rather than aimed at a host
	// that never had the files — the outcome that looks like success and is
	// not one.
	if agent, err := agentForSiteServer(ctx, st, migration.ServerID, migration.BackupPath); err == nil {
		if _, err := agent.Post(ctx, "/migration/cleanup", cleanupBody); err != nil {
			slog.Warn(fmt.Sprintf("Migration cleanup agent call failed for %s: %v", id, err))
		}
	} else {
		slog.Warn(fmt.Sprintf("Migration %s: deleting the record without cleaning up — the server it was "+
			"staged on could not be resolved, so the extracted files remain on that host", id))
	}

	// Delete from DB. Scoped by user_id like every other statement in this
	// file, rather than relying on the preceding SELECT's ownership check
	// still being valid.
	if _, err := execSQL(ctx, st.DB, "DELETE FROM migrations WHERE id = $1 AND user_id = $2", id, claims.Sub); err != nil {
		return internalError("remove migration", err)
	}

	// Remove any lingering provision log channel
	st.ProvisionLogs.Forget(id)

	slog.Info(fmt.Sprintf("Migration deleted: %s", id))
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "migration.delete",
		rtMigrationStr("migration"), nil, nil, nil, claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}
