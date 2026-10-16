package api

// Port of panel/backend/src/routes/crons.rs.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtCronsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/sites/{id}/crons", h(rtCronsList))
	r.Handle("POST /api/sites/{id}/crons", h(rtCronsCreate))
	r.Handle("PUT /api/sites/{id}/crons/{cron_id}", h(rtCronsUpdate))
	r.Handle("DELETE /api/sites/{id}/crons/{cron_id}", h(rtCronsRemove))
	r.Handle("POST /api/sites/{id}/crons/{cron_id}/run", h(rtCronsRunNow))
}

type rtCronsListQuery struct {
	Limit  *int64 `json:"limit"`
	Offset *int64 `json:"offset"`
}

type rtCronsCreateCronRequest struct {
	Label    *string `json:"label"`
	Command  string  `json:"command"`
	Schedule string  `json:"schedule"`
}

type rtCronsUpdateCronRequest struct {
	Label    *string `json:"label"`
	Command  *string `json:"command"`
	Schedule *string `json:"schedule"`
	Enabled  *bool   `json:"enabled"`
}

type rtCronsCron struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	SiteID     uuid.UUID  `json:"site_id" db:"site_id"`
	Label      string     `json:"label" db:"label"`
	Command    string     `json:"command" db:"command"`
	Schedule   string     `json:"schedule" db:"schedule"`
	Enabled    bool       `json:"enabled" db:"enabled"`
	LastRun    *time.Time `json:"last_run" db:"last_run"`
	LastStatus *string    `json:"last_status" db:"last_status"`
	LastOutput *string    `json:"last_output" db:"last_output"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
}

// rtCronsSyncCronsToAgent syncs this site's crons to the agent's crontab.
//
// Sends EVERY cron of the site, disabled ones included, because the agent
// uses the payload to decide which crontab lines this sync owns. Sending only
// the enabled ones was indistinguishable from "this site has no disabled
// crons", and the agent compensated by stripping every `# dockpanel:` line on
// the box — every other site's jobs with them.
func rtCronsSyncCronsToAgent(ctx context.Context, st *AppState, agent AgentHandle, siteID uuid.UUID) error {
	crons, err := queryAll[rtCronsCron](ctx, st.DB, "SELECT * FROM crons WHERE site_id = $1", siteID)
	if err != nil {
		return internalError("unknown", err)
	}
	payload := make([]any, 0, len(crons))
	for _, c := range crons {
		payload = append(payload, map[string]any{
			"id": c.ID.String(), "command": c.Command, "schedule": c.Schedule, "label": c.Label, "enabled": c.Enabled,
		})
	}
	if _, err := agent.Post(ctx, "/crons/sync", payload); err != nil {
		return agentError("Cron sync", err)
	}
	return nil
}

// rtCronsList is GET /api/sites/{id}/crons.
func rtCronsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var p rtCronsListQuery
	if err := decodeQuery(r, &p); err != nil {
		return err
	}
	if _, err := siteDomainForCaller(r.Context(), st, id, c); err != nil {
		return err
	}
	limit, offset := paginate(p.Limit, p.Offset)
	crons, err := queryAll[rtCronsCron](r.Context(), st.DB,
		"SELECT * FROM crons WHERE site_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3", id, limit, offset)
	if err != nil {
		return internalError("list crons", err)
	}
	writeJSON(w, http.StatusOK, crons)
	return nil
}

// rtCronsCreate is POST /api/sites/{id}/crons.
func rtCronsCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtCronsCreateCronRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}

	// Validate command for injection.
	if strings.TrimSpace(body.Command) == "" {
		return apiErr(http.StatusBadRequest, "Command is required")
	}
	if msg := isSafeShellCommand(body.Command); msg != "" {
		return apiErr(http.StatusBadRequest, "Cron command: "+msg)
	}
	if strings.TrimSpace(body.Schedule) == "" {
		return apiErr(http.StatusBadRequest, "Schedule is required")
	}
	if len(strings.Fields(body.Schedule)) != 5 {
		return apiErr(http.StatusBadRequest, "Schedule must have 5 fields (minute hour day month weekday)")
	}
	label := rtLogsOr(body.Label, "")

	cron, err := queryOne[rtCronsCron](r.Context(), st.DB,
		"INSERT INTO crons (site_id, label, command, schedule) VALUES ($1, $2, $3, $4) RETURNING *",
		id, label, strings.TrimSpace(body.Command), strings.TrimSpace(body.Schedule))
	if err != nil {
		return internalError("create crons", err)
	}

	if err := rtCronsSyncCronsToAgent(r.Context(), st, agent, id); err != nil {
		return err
	}

	slog.Info(fmt.Sprintf("Cron created: %s for %s", cron.Schedule, domain))
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "cron.create", new("cron"), &domain, &label, nil, c.KeyID)
	writeJSON(w, http.StatusCreated, cron)
	return nil
}

// rtCronsPathIDs reads {id} and {cron_id}.
func rtCronsPathIDs(r *http.Request) (uuid.UUID, uuid.UUID, error) {
	id, err := pathUUID(r, "id")
	if err != nil {
		return id, id, err
	}
	cronID, err := pathUUID(r, "cron_id")
	return id, cronID, err
}

// rtCronsUpdate is PUT /api/sites/{id}/crons/{cron_id}.
func rtCronsUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, cronID, err := rtCronsPathIDs(r)
	if err != nil {
		return err
	}
	var body rtCronsUpdateCronRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}

	// Verify the cron belongs to this site.
	existing, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB, "SELECT id FROM crons WHERE id = $1 AND site_id = $2", cronID, id)
	if err != nil {
		return internalError("update crons", err)
	}
	if existing == nil {
		return apiErr(http.StatusNotFound, "Cron job not found")
	}
	if body.Command != nil && strings.TrimSpace(*body.Command) != "" {
		if msg := isSafeShellCommand(*body.Command); msg != "" {
			return apiErr(http.StatusBadRequest, "Cron command: "+msg)
		}
	}
	if body.Schedule != nil && len(strings.Fields(*body.Schedule)) != 5 {
		return apiErr(http.StatusBadRequest, "Schedule must have 5 fields")
	}

	cron, err := queryOne[rtCronsCron](r.Context(), st.DB,
		"UPDATE crons SET "+
			"label = COALESCE($1, label), "+
			"command = COALESCE($2, command), "+
			"schedule = COALESCE($3, schedule), "+
			"enabled = COALESCE($4, enabled), "+
			"updated_at = NOW() "+
			"WHERE id = $5 RETURNING *",
		body.Label, body.Command, body.Schedule, body.Enabled, cronID)
	if err != nil {
		return internalError("update crons", err)
	}

	// Re-sync every cron of the site.
	if err := rtCronsSyncCronsToAgent(r.Context(), st, agent, id); err != nil {
		return err
	}

	slog.Info(fmt.Sprintf("Cron updated: %s for %s", cronID, domain))
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "cron.update", new("cron"), &domain, &cron.Label, nil, c.KeyID)
	writeJSON(w, http.StatusOK, cron)
	return nil
}

// rtCronsRemove is DELETE /api/sites/{id}/crons/{cron_id}.
func rtCronsRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, cronID, err := rtCronsPathIDs(r)
	if err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM crons WHERE id = $1 AND site_id = $2", cronID, id)
	if err != nil {
		return internalError("remove crons", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Cron job not found")
	}

	// Remove from the agent crontab, then re-sync the rest.
	_, _ = agent.Delete(r.Context(), fmt.Sprintf("/crons/remove/%s", cronID))
	if err := rtCronsSyncCronsToAgent(r.Context(), st, agent, id); err != nil {
		return err
	}

	slog.Info(fmt.Sprintf("Cron deleted: %s for %s", cronID, domain))
	ip := clientIP(r)
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "cron.delete", new("cron"), &domain, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(r.Context(), st.DB, "cron.delete", &c.Email, ip, new("cron"), &domain, nil, nil, "warning", c.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtCronsRunNow is POST /api/sites/{id}/crons/{cron_id}/run.
func rtCronsRunNow(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, cronID, err := rtCronsPathIDs(r)
	if err != nil {
		return err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	cron, err := queryOpt[rtCronsCron](r.Context(), st.DB, "SELECT * FROM crons WHERE id = $1 AND site_id = $2", cronID, id)
	if err != nil {
		return internalError("run now", err)
	}
	if cron == nil {
		return apiErr(http.StatusNotFound, "Cron job not found")
	}

	res, err := agent.Post(r.Context(), "/crons/run", map[string]any{
		"id": cron.ID.String(), "command": cron.Command, "schedule": cron.Schedule,
	})
	if err != nil {
		return agentError("Cron execution", err)
	}
	success, _ := jsonBool(jsonGet(res, "success"))
	output, _ := jsonStr(jsonGet(res, "output"))
	status := "failed"
	if success {
		status = "success"
	}

	if _, err := execSQL(r.Context(), st.DB,
		"UPDATE crons SET last_run = NOW(), last_status = $1, last_output = $2, updated_at = NOW() WHERE id = $3",
		status, output, cronID); err != nil {
		return internalError("run now", err)
	}

	slog.Info(fmt.Sprintf("Cron executed manually: %s for %s — %s", cronID, domain, status))
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "cron.run", new("cron"), &domain, &cron.Label, &status, c.KeyID)

	// GAP 30: fire an alert on cron job failure.
	if !success {
		exitCode, ok := jsonI64(jsonGet(res, "exit_code"))
		if !ok {
			exitCode = -1
		}
		shown := output
		if len(shown) > 500 {
			shown = shown[:500]
		}
		NotificationsFireAlert(r.Context(), st.DB, c.Sub, nil, &id, "cron_failure", "", "warning",
			fmt.Sprintf("Cron failed: %s (exit %d)", cron.Label, exitCode),
			fmt.Sprintf("Cron job '%s' on %s failed with exit code %d.\nCommand: %s\nOutput: %s", cron.Label, domain, exitCode, cron.Command, shown))
		SystemLogLogEvent(r.Context(), st.DB, "warning", "cron",
			fmt.Sprintf("Cron failed: %s on %s", cron.Label, domain),
			new(fmt.Sprintf("exit_code=%d, command=%s", exitCode, cron.Command)))
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": success, "output": output, "status": status})
	return nil
}
