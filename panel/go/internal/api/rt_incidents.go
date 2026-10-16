package api

// routes/incidents.rs — managed incidents, status page config/components/
// subscribers, and the enhanced public status page.

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtIncidentsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	// Public (no auth).
	r.Handle("GET /api/status-page/public", h(rtIncidentsPublicStatusPage))
	r.Handle("POST /api/status-page/subscribe", h(rtIncidentsSubscribe))
	// Both methods on purpose: the docs published DELETE while the route
	// accepted POST only (every documented call 405'd); POST stays because
	// the repo's own e2e calls it.
	r.Handle("POST /api/status-page/unsubscribe", h(rtIncidentsUnsubscribe))
	r.Handle("DELETE /api/status-page/unsubscribe", h(rtIncidentsUnsubscribe))
	// Incident management.
	r.Handle("GET /api/incidents", h(rtIncidentsList))
	r.Handle("POST /api/incidents", h(rtIncidentsCreate))
	r.Handle("GET /api/incidents/summary", h(rtIncidentsSummary))
	r.Handle("GET /api/incidents/{id}", h(rtIncidentsGetOne))
	r.Handle("PUT /api/incidents/{id}", h(rtIncidentsUpdate))
	r.Handle("DELETE /api/incidents/{id}", h(rtIncidentsRemove))
	r.Handle("GET /api/incidents/{id}/updates", h(rtIncidentsListUpdates))
	r.Handle("POST /api/incidents/{id}/updates", h(rtIncidentsPostUpdate))
	// Status page management.
	r.Handle("GET /api/status-page/config", h(rtIncidentsGetConfig))
	r.Handle("PUT /api/status-page/config", h(rtIncidentsUpdateConfig))
	r.Handle("GET /api/status-page/components", h(rtIncidentsListComponents))
	r.Handle("POST /api/status-page/components", h(rtIncidentsCreateComponent))
	r.Handle("DELETE /api/status-page/components/{id}", h(rtIncidentsDeleteComponent))
	r.Handle("GET /api/status-page/subscribers", h(rtIncidentsListSubscribers))
}

// ── Types ───────────────────────────────────────────────────────────────────

type rtIncidentsManagedIncident struct {
	ID                  uuid.UUID  `json:"id" db:"id"`
	UserID              uuid.UUID  `json:"user_id" db:"user_id"`
	Title               string     `json:"title" db:"title"`
	Status              string     `json:"status" db:"status"`
	Severity            string     `json:"severity" db:"severity"`
	Description         *string    `json:"description" db:"description"`
	StartedAt           time.Time  `json:"started_at" db:"started_at"`
	ResolvedAt          *time.Time `json:"resolved_at" db:"resolved_at"`
	Postmortem          *string    `json:"postmortem" db:"postmortem"`
	PostmortemPublished bool       `json:"postmortem_published" db:"postmortem_published"`
	VisibleOnStatusPage bool       `json:"visible_on_status_page" db:"visible_on_status_page"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
}

type rtIncidentsIncidentUpdate struct {
	ID          uuid.UUID `json:"id" db:"id"`
	IncidentID  uuid.UUID `json:"incident_id" db:"incident_id"`
	Status      string    `json:"status" db:"status"`
	Message     string    `json:"message" db:"message"`
	AuthorEmail *string   `json:"author_email" db:"author_email"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type rtIncidentsCreateIncidentRequest struct {
	Title               string       `json:"title"`
	Severity            *string      `json:"severity"`
	Description         *string      `json:"description"`
	Status              *string      `json:"status"`
	ComponentIDs        *[]uuid.UUID `json:"component_ids"`
	VisibleOnStatusPage *bool        `json:"visible_on_status_page"`
}

type rtIncidentsUpdateIncidentRequest struct {
	Title               *string `json:"title"`
	Status              *string `json:"status"`
	Severity            *string `json:"severity"`
	Description         *string `json:"description"`
	Message             *string `json:"message"`
	Postmortem          *string `json:"postmortem"`
	PostmortemPublished *bool   `json:"postmortem_published"`
	VisibleOnStatusPage *bool   `json:"visible_on_status_page"`
}

type rtIncidentsIncidentListQuery struct {
	Limit  *int64  `json:"limit"`
	Offset *int64  `json:"offset"`
	Status *string `json:"status"`
}

type rtIncidentsPostUpdateRequest struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

var rtIncidentsValidStatuses = []string{"investigating", "identified", "monitoring", "resolved", "postmortem"}
var rtIncidentsValidSeverities = []string{"minor", "major", "critical", "maintenance"}

// rtIncidentsClosedStatuses close an incident; everything else is open —
// the definition dashboard/deploy/git_deploys spell as
// `status NOT IN ('resolved', 'postmortem')`. Named so a count of open
// incidents cannot quietly mean a third thing.
var rtIncidentsClosedStatuses = []string{"resolved", "postmortem"}

func rtIncidentsStrOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

// ── Incident CRUD ───────────────────────────────────────────────────────────

// rtIncidentsList is GET /api/incidents.
func rtIncidentsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var params rtIncidentsIncidentListQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	limit, offset := paginate(params.Limit, params.Offset)
	var incidents []rtIncidentsManagedIncident
	if params.Status != nil {
		incidents, err = queryAll[rtIncidentsManagedIncident](r.Context(), st.DB,
			"SELECT * FROM managed_incidents WHERE user_id = $1 AND status = $2 ORDER BY started_at DESC LIMIT $3 OFFSET $4",
			claims.Sub, *params.Status, limit, offset)
	} else {
		incidents, err = queryAll[rtIncidentsManagedIncident](r.Context(), st.DB,
			"SELECT * FROM managed_incidents WHERE user_id = $1 ORDER BY started_at DESC LIMIT $2 OFFSET $3",
			claims.Sub, limit, offset)
	}
	if err != nil {
		return internalError("list incidents", err)
	}
	writeJSON(w, http.StatusOK, incidents)
	return nil
}

// rtIncidentsSummary is GET /api/incidents/summary. The sidebar badge once
// counted `?status=investigating` — one of THREE open statuses — so moving an
// incident to `identified` dropped it from the badge while the dashboard kept
// counting it. One place answers now.
func rtIncidentsSummary(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	counts, err := queryAll[Tup2[string, int64]](r.Context(), st.DB,
		"SELECT status, COUNT(*) FROM managed_incidents WHERE user_id = $1 GROUP BY status", claims.Sub)
	if err != nil {
		return internalError("incident summary", err)
	}
	byStatus := map[string]any{}
	var open int64
	for _, c := range counts {
		byStatus[c.A] = c.B
		if !slices.Contains(rtIncidentsClosedStatuses, c.A) {
			open += c.B
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"open": open, "by_status": byStatus})
	return nil
}

// rtIncidentsCreate is POST /api/incidents.
func rtIncidentsCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var req rtIncidentsCreateIncidentRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if req.Title == "" || len(req.Title) > 200 {
		return apiErr(http.StatusBadRequest, "Title must be 1-200 characters")
	}
	status := rtIncidentsStrOr(req.Status, "investigating")
	if !slices.Contains(rtIncidentsValidStatuses, status) {
		return apiErr(http.StatusBadRequest, "Invalid status")
	}
	severity := rtIncidentsStrOr(req.Severity, "major")
	if !slices.Contains(rtIncidentsValidSeverities, severity) {
		return apiErr(http.StatusBadRequest, "Invalid severity")
	}

	visible := req.VisibleOnStatusPage == nil || *req.VisibleOnStatusPage
	incident, err := queryOne[rtIncidentsManagedIncident](ctx, st.DB,
		"INSERT INTO managed_incidents (user_id, title, status, severity, description, visible_on_status_page) "+
			"VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
		claims.Sub, req.Title, status, severity, req.Description, visible)
	if err != nil {
		return internalError("create incidents", err)
	}

	// Link affected components.
	if req.ComponentIDs != nil {
		for _, cid := range *req.ComponentIDs {
			_, _ = execSQL(ctx, st.DB, "INSERT INTO managed_incident_components (incident_id, component_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", incident.ID, cid)
		}
	}

	// Initial update.
	_, _ = execSQL(ctx, st.DB, "INSERT INTO incident_updates (incident_id, status, message, author_email) VALUES ($1, $2, $3, $4)",
		incident.ID, status, rtIncidentsStrOr(req.Description, "Incident created"), claims.Email)

	rtIncidentsNotifySubscribers(incident.Title, status, rtIncidentsStrOr(req.Description, ""), incident.UserID)

	target := "incident"
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "incident.create", &target, &req.Title, nil, nil, claims.KeyID)

	ExtensionsFireEvent(st.DB, "incident.created", map[string]any{
		"incident_id": incident.ID, "title": req.Title, "severity": incident.Severity, "status": incident.Status,
	})

	link := "/incidents"
	NotificationsNotifyPanel(ctx, st.DB, &claims.Sub, "Incident: "+req.Title, rtIncidentsStrOr(req.Description, "New incident created"), severity, "incident", &link)

	writeJSON(w, http.StatusCreated, incident)
	return nil
}

// rtIncidentsGetOne is GET /api/incidents/{id} — incident with updates.
func rtIncidentsGetOne(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	incident, err := queryOpt[rtIncidentsManagedIncident](ctx, st.DB, "SELECT * FROM managed_incidents WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("get_one incidents", err)
	}
	if incident == nil {
		return apiErr(http.StatusNotFound, "Incident not found")
	}
	updates, err := queryAll[rtIncidentsIncidentUpdate](ctx, st.DB, "SELECT * FROM incident_updates WHERE incident_id = $1 ORDER BY created_at ASC LIMIT 500", id)
	if err != nil {
		return internalError("get_one incidents", err)
	}
	componentIDs, err := queryAll[uuid.UUID](ctx, st.DB, "SELECT component_id FROM managed_incident_components WHERE incident_id = $1", id)
	if err != nil {
		componentIDs = []uuid.UUID{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"incident": incident, "updates": updates, "component_ids": componentIDs})
	return nil
}

// rtIncidentsUpdate is PUT /api/incidents/{id}.
func rtIncidentsUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req rtIncidentsUpdateIncidentRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()

	existing, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM managed_incidents WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("update incidents", err)
	}
	if existing == nil {
		return apiErr(http.StatusNotFound, "Incident not found")
	}
	if req.Status != nil && !slices.Contains(rtIncidentsValidStatuses, *req.Status) {
		return apiErr(http.StatusBadRequest, "Invalid status")
	}
	if req.Severity != nil && !slices.Contains(rtIncidentsValidSeverities, *req.Severity) {
		return apiErr(http.StatusBadRequest, "Invalid severity")
	}

	// Reopening must clear resolved_at: the stamp once survived a move back
	// to a live status, so the public page said "Resolved <n> ago" for an
	// incident whose status said investigating. postmortem follows a
	// resolution and keeps it; nil/"" means another field is being edited.
	resolvedAtClause := ""
	switch rtIncidentsStrOr(req.Status, "") {
	case "resolved":
		resolvedAtClause = ", resolved_at = NOW()"
	case "investigating", "identified", "monitoring":
		resolvedAtClause = ", resolved_at = NULL"
	}

	query := "UPDATE managed_incidents SET " +
		"title = COALESCE(NULLIF($2, ''), title), " +
		"status = COALESCE(NULLIF($3, ''), status), " +
		"severity = COALESCE(NULLIF($4, ''), severity), " +
		"description = COALESCE($5, description), " +
		"postmortem = COALESCE($6, postmortem), " +
		"postmortem_published = COALESCE($7, postmortem_published), " +
		"visible_on_status_page = COALESCE($8, visible_on_status_page), " +
		"updated_at = NOW()" + resolvedAtClause + " " +
		"WHERE id = $1 RETURNING *"
	incident, err := queryOne[rtIncidentsManagedIncident](ctx, st.DB, query,
		id, rtIncidentsStrOr(req.Title, ""), rtIncidentsStrOr(req.Status, ""), rtIncidentsStrOr(req.Severity, ""),
		req.Description, req.Postmortem, req.PostmortemPublished, req.VisibleOnStatusPage)
	if err != nil {
		return internalError("update incidents", err)
	}

	// GAP 34: auto-populate a postmortem template on the move to postmortem.
	if req.Status != nil && *req.Status == "postmortem" && req.Postmortem == nil {
		currentPM, err := queryScalarOpt[*string](ctx, st.DB, "SELECT postmortem FROM managed_incidents WHERE id = $1", id)
		if err != nil {
			return internalError("incident postmortem check", err)
		}
		pmEmpty := currentPM == nil || *currentPM == nil || **currentPM == ""
		if pmEmpty {
			updates, _ := queryAll[Tup3[string, string, time.Time]](ctx, st.DB,
				"SELECT status, message, created_at FROM incident_updates WHERE incident_id = $1 ORDER BY created_at", id)
			lines := make([]string, 0, len(updates))
			for _, u := range updates {
				lines = append(lines, fmt.Sprintf("- **%s** [%s]: %s", u.C.UTC().Format("15:04 UTC"), u.A, u.B))
			}
			template := fmt.Sprintf("## Incident Postmortem\n\n"+
				"### Summary\n[Describe the incident]\n\n"+
				"### Timeline\n%s\n\n"+
				"### Root Cause\n[What caused this?]\n\n"+
				"### Resolution\n[How was it fixed?]\n\n"+
				"### Action Items\n- [ ] \n", strings.Join(lines, "\n"))
			_, _ = execSQL(ctx, st.DB, "UPDATE managed_incidents SET postmortem = $1 WHERE id = $2 AND (postmortem IS NULL OR postmortem = '')", template, id)
		}
	}

	// A status-change message becomes an update.
	if req.Message != nil {
		updateStatus := rtIncidentsStrOr(req.Status, incident.Status)
		_, _ = execSQL(ctx, st.DB, "INSERT INTO incident_updates (incident_id, status, message, author_email) VALUES ($1, $2, $3, $4)",
			id, updateStatus, *req.Message, claims.Email)
		rtIncidentsNotifySubscribers(incident.Title, updateStatus, *req.Message, incident.UserID)
	}

	// Re-fetch after the postmortem auto-populate to return the complete record.
	incident, err = queryOne[rtIncidentsManagedIncident](ctx, st.DB, "SELECT * FROM managed_incidents WHERE id = $1", id)
	if err != nil {
		return internalError("update incidents", err)
	}
	writeJSON(w, http.StatusOK, incident)
	return nil
}

// rtIncidentsRemove is DELETE /api/incidents/{id}.
func rtIncidentsRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM managed_incidents WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("remove incidents", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Incident not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtIncidentsPostUpdate is POST /api/incidents/{id}/updates.
func rtIncidentsPostUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req rtIncidentsPostUpdateRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()

	existing, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM managed_incidents WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("post update", err)
	}
	if existing == nil {
		return apiErr(http.StatusNotFound, "Incident not found")
	}
	if !slices.Contains(rtIncidentsValidStatuses, req.Status) {
		return apiErr(http.StatusBadRequest, "Invalid status")
	}

	if req.Status == "resolved" {
		_, _ = execSQL(ctx, st.DB, "UPDATE managed_incidents SET status = $2, resolved_at = NOW(), updated_at = NOW() WHERE id = $1", id, req.Status)

		// GAP 16: auto-resolve linked alerts when the incident is resolved.
		title, err := queryScalarOpt[string](ctx, st.DB, "SELECT title FROM managed_incidents WHERE id = $1", id)
		if err != nil {
			return internalError("incident auto-resolve title lookup", err)
		}
		if title != nil {
			// Scoped to the incident owner. alerts.title is auto-generated
			// ("Server vps is offline"), so a title-only match resolved every
			// other tenant's identically-titled firing alert and stopped
			// escalation on a live outage.
			_, _ = execSQL(ctx, st.DB,
				"UPDATE alerts SET status = 'resolved', resolved_at = NOW() WHERE title = $1 AND user_id = $2 AND status IN ('firing', 'acknowledged')",
				*title, claims.Sub)
		}

		// Clear status_override on linked components.
		_, _ = execSQL(ctx, st.DB,
			"UPDATE status_page_components SET status_override = NULL WHERE id IN (SELECT component_id FROM managed_incident_components WHERE incident_id = $1)", id)

		ExtensionsFireEvent(st.DB, "incident.resolved", map[string]any{"incident_id": id})

		if title != nil {
			link := "/incidents"
			NotificationsNotifyPanel(ctx, st.DB, &claims.Sub, "Resolved: "+*title, "Incident has been resolved", "info", "incident", &link)
		}
	} else {
		// Same reopen rule as PUT: a live status clears the resolution stamp,
		// postmortem keeps it. Both endpoints write the column.
		sql := "UPDATE managed_incidents SET status = $2, updated_at = NOW() WHERE id = $1"
		switch req.Status {
		case "investigating", "identified", "monitoring":
			sql = "UPDATE managed_incidents SET status = $2, resolved_at = NULL, updated_at = NOW() WHERE id = $1"
		}
		_, _ = execSQL(ctx, st.DB, sql, id, req.Status)
	}

	update, err := queryOne[rtIncidentsIncidentUpdate](ctx, st.DB,
		"INSERT INTO incident_updates (incident_id, status, message, author_email) VALUES ($1, $2, $3, $4) RETURNING *",
		id, req.Status, req.Message, claims.Email)
	if err != nil {
		return internalError("post update", err)
	}

	owner, err := queryOpt[Tup2[string, uuid.UUID]](ctx, st.DB, "SELECT title, user_id FROM managed_incidents WHERE id = $1", id)
	if err != nil {
		return internalError("incident notify title lookup", err)
	}
	if owner != nil {
		rtIncidentsNotifySubscribers(owner.A, req.Status, req.Message, owner.B)
	}
	writeJSON(w, http.StatusCreated, update)
	return nil
}

// rtIncidentsListUpdates is GET /api/incidents/{id}/updates.
func rtIncidentsListUpdates(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	existing, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM managed_incidents WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("list updates", err)
	}
	if existing == nil {
		return apiErr(http.StatusNotFound, "Incident not found")
	}
	updates, err := queryAll[rtIncidentsIncidentUpdate](ctx, st.DB, "SELECT * FROM incident_updates WHERE incident_id = $1 ORDER BY created_at ASC LIMIT 500", id)
	if err != nil {
		return internalError("list updates", err)
	}
	writeJSON(w, http.StatusOK, updates)
	return nil
}

// ── Status Page Config ──────────────────────────────────────────────────────

type rtIncidentsStatusPageConfig struct {
	ID                  uuid.UUID `json:"id" db:"id"`
	Title               string    `json:"title" db:"title"`
	Description         string    `json:"description" db:"description"`
	LogoURL             *string   `json:"logo_url" db:"logo_url"`
	AccentColor         string    `json:"accent_color" db:"accent_color"`
	ShowSubscribe       bool      `json:"show_subscribe" db:"show_subscribe"`
	ShowIncidentHistory bool      `json:"show_incident_history" db:"show_incident_history"`
	HistoryDays         int32     `json:"history_days" db:"history_days"`
	Enabled             bool      `json:"enabled" db:"enabled"`
}

type rtIncidentsUpdateConfigRequest struct {
	Title               *string `json:"title"`
	Description         *string `json:"description"`
	LogoURL             *string `json:"logo_url"`
	AccentColor         *string `json:"accent_color"`
	ShowSubscribe       *bool   `json:"show_subscribe"`
	ShowIncidentHistory *bool   `json:"show_incident_history"`
	HistoryDays         *int32  `json:"history_days"`
	Enabled             *bool   `json:"enabled"`
}

const rtIncidentsConfigCols = "id, title, description, logo_url, accent_color, show_subscribe, show_incident_history, history_days, enabled"

// rtIncidentsGetConfig is GET /api/status-page/config (auto-creates defaults).
func rtIncidentsGetConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	cfg, err := queryOpt[rtIncidentsStatusPageConfig](ctx, st.DB,
		"SELECT "+rtIncidentsConfigCols+" FROM status_page_config WHERE user_id = $1", claims.Sub)
	if err != nil {
		return internalError("get config", err)
	}
	if cfg == nil {
		c, err := queryOne[rtIncidentsStatusPageConfig](ctx, st.DB,
			"INSERT INTO status_page_config (user_id) VALUES ($1) RETURNING "+rtIncidentsConfigCols, claims.Sub)
		if err != nil {
			return internalError("get config", err)
		}
		cfg = &c
	}
	writeJSON(w, http.StatusOK, cfg)
	return nil
}

// rtIncidentsUpdateConfig is PUT /api/status-page/config.
func rtIncidentsUpdateConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var req rtIncidentsUpdateConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	// Ensure config exists. The conflict TARGET is load-bearing: without it
	// only a PK collision (gen_random_uuid) was absorbed, every PUT inserted
	// another row, and the UPDATE returned an arbitrary one — an operator
	// could untick Enabled, see false, and still be publishing.
	_, _ = execSQL(ctx, st.DB, "INSERT INTO status_page_config (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING", claims.Sub)

	// description/logo_url: "" now means clear, so an absent key stays nil
	// (collapsing it onto "" would blank fields a client did not send).
	// title/accent_color keep NULLIF: blank stays "leave it".
	cfg, err := queryOne[rtIncidentsStatusPageConfig](ctx, st.DB,
		"UPDATE status_page_config SET "+
			"title = COALESCE(NULLIF($2, ''), title), "+
			"description = CASE WHEN $3 = '' THEN NULL ELSE COALESCE($3, description) END, "+
			"logo_url = CASE WHEN $4 = '' THEN NULL ELSE COALESCE($4, logo_url) END, "+
			"accent_color = COALESCE(NULLIF($5, ''), accent_color), "+
			"show_subscribe = COALESCE($6, show_subscribe), "+
			"show_incident_history = COALESCE($7, show_incident_history), "+
			"history_days = COALESCE($8, history_days), "+
			"enabled = COALESCE($9, enabled), "+
			"updated_at = NOW() "+
			"WHERE user_id = $1 "+
			"RETURNING "+rtIncidentsConfigCols,
		claims.Sub, rtIncidentsStrOr(req.Title, ""), req.Description, req.LogoURL, rtIncidentsStrOr(req.AccentColor, ""),
		req.ShowSubscribe, req.ShowIncidentHistory, req.HistoryDays, req.Enabled)
	if err != nil {
		return internalError("update config", err)
	}
	writeJSON(w, http.StatusOK, cfg)
	return nil
}

// ── Status Page Components ──────────────────────────────────────────────────

type rtIncidentsStatusPageComponent struct {
	ID             uuid.UUID `json:"id" db:"id"`
	Name           string    `json:"name" db:"name"`
	Description    *string   `json:"description" db:"description"`
	SortOrder      int32     `json:"sort_order" db:"sort_order"`
	StatusOverride *string   `json:"status_override" db:"status_override"`
	GroupName      *string   `json:"group_name" db:"group_name"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

type rtIncidentsCreateComponentRequest struct {
	Name        string       `json:"name"`
	Description *string      `json:"description"`
	SortOrder   *int32       `json:"sort_order"`
	GroupName   *string      `json:"group_name"`
	MonitorIDs  *[]uuid.UUID `json:"monitor_ids"`
}

// rtIncidentsListComponents is GET /api/status-page/components.
func rtIncidentsListComponents(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	comps, err := queryAll[rtIncidentsStatusPageComponent](ctx, st.DB,
		"SELECT * FROM status_page_components WHERE user_id = $1 ORDER BY sort_order ASC, created_at ASC", claims.Sub)
	if err != nil {
		return internalError("list components", err)
	}
	result := make([]map[string]any, 0, len(comps))
	for _, c := range comps {
		mids, err := queryAll[uuid.UUID](ctx, st.DB, "SELECT monitor_id FROM status_page_component_monitors WHERE component_id = $1", c.ID)
		if err != nil {
			mids = []uuid.UUID{}
		}
		result = append(result, map[string]any{
			"id": c.ID, "name": c.Name, "description": c.Description, "sort_order": c.SortOrder,
			"status_override": c.StatusOverride, "group_name": c.GroupName, "monitor_ids": mids,
		})
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtIncidentsCreateComponent is POST /api/status-page/components.
func rtIncidentsCreateComponent(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var req rtIncidentsCreateComponentRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.Name == "" || len(req.Name) > 100 {
		return apiErr(http.StatusBadRequest, "Name must be 1-100 characters")
	}
	ctx := r.Context()
	sortOrder := int32(0)
	if req.SortOrder != nil {
		sortOrder = *req.SortOrder
	}
	comp, err := queryOne[rtIncidentsStatusPageComponent](ctx, st.DB,
		"INSERT INTO status_page_components (user_id, name, description, sort_order, group_name) VALUES ($1, $2, $3, $4, $5) RETURNING *",
		claims.Sub, req.Name, req.Description, sortOrder, req.GroupName)
	if err != nil {
		return internalError("create component", err)
	}
	if req.MonitorIDs != nil {
		for _, mid := range *req.MonitorIDs {
			_, _ = execSQL(ctx, st.DB, "INSERT INTO status_page_component_monitors (component_id, monitor_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", comp.ID, mid)
		}
	}
	writeJSON(w, http.StatusCreated, comp)
	return nil
}

// rtIncidentsDeleteComponent is DELETE /api/status-page/components/{id}.
func rtIncidentsDeleteComponent(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM status_page_components WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("delete component", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Component not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// ── Subscribers ─────────────────────────────────────────────────────────────

type rtIncidentsSubscribeRequest struct {
	Email string `json:"email"`
}

// rtIncidentsSubscribe is POST /api/status-page/subscribe (public, no auth).
func rtIncidentsSubscribe(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var req rtIncidentsSubscribeRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	// A disabled status page has no subscribers to take. Ungated, this wrote
	// attacker-supplied addresses as verified on installs that never enabled it.
	if err := PublicStatusRequireEnabled(ctx, st.DB); err != nil {
		return err
	}
	if req.Email == "" || !strings.Contains(req.Email, "@") || len(req.Email) > 255 {
		return apiErr(http.StatusBadRequest, "Invalid email address")
	}
	// s427: which tenant's page this visitor is looking at. nil means the
	// install has no users at all — unreachable on a running panel.
	ownerID := PublicStatusResolveCurrentStatusPageOwner(ctx, st.DB)
	if ownerID == nil {
		return internalError("subscribe", ErrRowNotFound)
	}
	token := strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := execSQL(ctx, st.DB,
		"INSERT INTO status_page_subscribers (owner_id, email, verify_token, verified) VALUES ($1, $2, $3, TRUE) ON CONFLICT (owner_id, email) DO NOTHING",
		*ownerID, req.Email, token); err != nil {
		return internalError("subscribe", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Subscribed to status updates"})
	return nil
}

// rtIncidentsUnsubscribe is DELETE (or POST) /api/status-page/unsubscribe (public).
func rtIncidentsUnsubscribe(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var req rtIncidentsSubscribeRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if err := PublicStatusRequireEnabled(ctx, st.DB); err != nil {
		return err
	}
	// s427: scoped to the page the visitor is looking at — IS NOT DISTINCT
	// FROM so a legacy row with an unresolvable owner (both NULL) still
	// matches. Unscoped, one tenant's page could remove another's subscriber.
	ownerID := PublicStatusResolveCurrentStatusPageOwner(ctx, st.DB)
	_, _ = execSQL(ctx, st.DB, "DELETE FROM status_page_subscribers WHERE email = $1 AND owner_id IS NOT DISTINCT FROM $2", req.Email, ownerID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtIncidentsListSubscribers is GET /api/status-page/subscribers (admin).
// s427: scoped to the calling admin's own owner_id, like every sibling admin
// endpoint — any admin could once read every tenant's subscriber list.
func rtIncidentsListSubscribers(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	rows, err := queryAll[Tup3[string, bool, time.Time]](r.Context(), st.DB,
		"SELECT email, verified, created_at FROM status_page_subscribers WHERE owner_id = $1 ORDER BY created_at DESC LIMIT 1000", claims.Sub)
	if err != nil {
		return internalError("list subscribers", err)
	}
	result := make([]map[string]any, 0, len(rows))
	for _, s := range rows {
		result = append(result, map[string]any{"email": s.A, "verified": s.B, "created_at": s.C})
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

// ── Enhanced Public Status Page ─────────────────────────────────────────────

type rtIncidentsPublicConfigRow struct {
	UserID              uuid.UUID `db:"user_id"`
	Title               string    `db:"title"`
	Description         string    `db:"description"`
	LogoURL             *string   `db:"logo_url"`
	AccentColor         string    `db:"accent_color"`
	ShowSubscribe       bool      `db:"show_subscribe"`
	ShowIncidentHistory bool      `db:"show_incident_history"`
	HistoryDays         int32     `db:"history_days"`
	Enabled             bool      `db:"enabled"`
}

// rtIncidentsComponentStatus derives a component's public status.
func rtIncidentsComponentStatus(override *string, monitorStatuses []string) string {
	switch {
	case override != nil:
		return *override
	case len(monitorStatuses) == 0:
		return "operational"
	case !slices.ContainsFunc(monitorStatuses, func(s string) bool { return s != "up" }):
		return "operational"
	case slices.Contains(monitorStatuses, "down"):
		return "major_outage"
	default:
		return "degraded"
	}
}

// rtIncidentsOverallStatus rolls component statuses up.
func rtIncidentsOverallStatus(statuses []string) string {
	switch {
	case !slices.ContainsFunc(statuses, func(s string) bool { return s != "operational" }):
		return "operational"
	case slices.Contains(statuses, "major_outage"):
		return "major_outage"
	default:
		return "degraded"
	}
}

// rtIncidentsPublicStatusPage is GET /api/status-page/public (no auth) —
// what /status actually fetches.
func rtIncidentsPublicStatusPage(st *AppState, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	// The one gate every unauthenticated status-page route passes through;
	// until v2.70.0 this endpoint was governed by nothing the operator UI writes.
	if err := PublicStatusRequireEnabled(ctx, st.DB); err != nil {
		return err
	}

	// ORDER BY is load-bearing: update_config once inserted a row per PUT, so
	// an install can carry duplicates and an unordered LIMIT 1 would let two
	// reads disagree.
	//
	// SECURITY (s418): every query below MUST be scoped to owner_id — the
	// tenant whose config row won this ORDER BY. Unscoped, one tenant's
	// components/incidents were served to every anonymous visitor of every
	// OTHER tenant's status page.
	cfg, err := queryOpt[rtIncidentsPublicConfigRow](ctx, st.DB,
		"SELECT user_id, title, description, logo_url, accent_color, show_subscribe, show_incident_history, history_days, enabled "+
			"FROM status_page_config ORDER BY created_at ASC, id ASC LIMIT 1")
	if err != nil {
		return internalError("public status page", err)
	}
	var ownerID *uuid.UUID
	c := rtIncidentsPublicConfigRow{
		Title: "Service Status", Description: "Current status of our services", AccentColor: "#22c55e",
		ShowSubscribe: true, ShowIncidentHistory: true, HistoryDays: 90, Enabled: true,
	}
	if cfg != nil {
		c = *cfg
		ownerID = &cfg.UserID
	}
	if !c.Enabled {
		return apiErr(http.StatusNotFound, "Status page is disabled")
	}

	components := []map[string]any{}
	var compStatuses []string
	if ownerID != nil {
		rows, _ := queryAll[Tup6[uuid.UUID, string, *string, int32, *string, *string]](ctx, st.DB,
			"SELECT id, name, description, sort_order, status_override, group_name "+
				"FROM status_page_components WHERE user_id = $1 ORDER BY sort_order ASC, created_at ASC", *ownerID)
		for _, comp := range rows {
			ms, _ := queryAll[string](ctx, st.DB,
				"SELECT m.status FROM monitors m "+
					"JOIN status_page_component_monitors cm ON cm.monitor_id = m.id "+
					"WHERE cm.component_id = $1 AND m.user_id = $2 AND m.enabled = TRUE", comp.A, *ownerID)
			status := rtIncidentsComponentStatus(comp.E, ms)
			compStatuses = append(compStatuses, status)
			components = append(components, map[string]any{
				"id": comp.A, "name": comp.B, "description": comp.C, "group": comp.F, "status": status,
			})
		}
	}
	overall := rtIncidentsOverallStatus(compStatuses)

	incidents := []map[string]any{}
	if ownerID != nil {
		// history_days bound as text: `$2 || ' days'` makes Postgres infer the
		// parameter as text, which pgx will not encode an int32 into.
		rows, _ := queryAll[rtIncidentsManagedIncident](ctx, st.DB,
			"SELECT * FROM managed_incidents WHERE user_id = $1 AND visible_on_status_page = TRUE "+
				"AND (status != 'resolved' OR resolved_at > NOW() - ($2 || ' days')::interval) "+
				"ORDER BY started_at DESC LIMIT 50", *ownerID, strconv.Itoa(int(c.HistoryDays)))
		for _, inc := range rows {
			updates, _ := queryAll[rtIncidentsIncidentUpdate](ctx, st.DB,
				"SELECT * FROM incident_updates WHERE incident_id = $1 ORDER BY created_at ASC LIMIT 500", inc.ID)
			// Projected field by field: IncidentUpdate carries author_email and
			// this endpoint answers with no login. These four are exactly what
			// PublicStatusPage.tsx declares.
			pub := make([]map[string]any, 0, len(updates))
			for _, u := range updates {
				pub = append(pub, map[string]any{"id": u.ID, "status": u.Status, "message": u.Message, "created_at": u.CreatedAt})
			}
			incidents = append(incidents, map[string]any{
				"id": inc.ID, "title": inc.Title, "status": inc.Status, "severity": inc.Severity,
				"started_at": inc.StartedAt, "resolved_at": inc.ResolvedAt, "updates": pub,
			})
		}
	}

	// Legacy monitor-based incidents (auto-detected downtime), owner-scoped.
	auto := []map[string]any{}
	if ownerID != nil {
		rows, _ := queryAll[Tup5[uuid.UUID, string, time.Time, *time.Time, *string]](ctx, st.DB,
			"SELECT i.id, m.name, i.started_at, i.resolved_at, i.cause "+
				"FROM incidents i JOIN monitors m ON m.id = i.monitor_id "+
				"WHERE m.user_id = $1 AND i.started_at > NOW() - INTERVAL '7 days' "+
				"ORDER BY i.started_at DESC LIMIT 20", *ownerID)
		for _, a := range rows {
			auto = append(auto, map[string]any{"id": a.A, "monitor_name": a.B, "started_at": a.C, "resolved_at": a.D, "cause": a.E})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"title":                 c.Title,
		"description":           c.Description,
		"logo_url":              c.LogoURL,
		"accent_color":          c.AccentColor,
		"show_subscribe":        c.ShowSubscribe,
		"show_incident_history": c.ShowIncidentHistory,
		"overall_status":        overall,
		"components":            components,
		"incidents":             incidents,
		"auto_incidents":        auto,
		"updated_at":            time.Now().UTC(),
	})
	return nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// rtIncidentsNotifySubscribers hands off to the status-notice worker. This
// once mailed an unbounded (attacker-grown) list serially INSIDE the HTTP
// handler, holding the request and a pool slot until done.
func rtIncidentsNotifySubscribers(title, status, message string, ownerID uuid.UUID) {
	StatusNoticesEnqueue(title, fmt.Sprintf("[Status Update] %s — %s", title, status),
		fmt.Sprintf("%s\nStatus: %s\n\n%s", title, status, message), ownerID)
}
