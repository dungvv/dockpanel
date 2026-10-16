package api

// Port of panel/backend/src/routes/on_call.rs.
//
// Phase 4 W3: on-call rotation admin API. Admin-only CRUD over
// on_call_schedules plus a /whoami endpoint that lets non-admin operators
// check whether they're currently on call without exposing the schedule
// layout to them.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtOnCallRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/on-call/schedules", h(rtOnCallListSchedules))
	r.Handle("POST /api/on-call/schedules", h(rtOnCallCreateSchedule))
	r.Handle("GET /api/on-call/schedules/{id}", h(rtOnCallGetSchedule))
	r.Handle("PUT /api/on-call/schedules/{id}", h(rtOnCallUpdateSchedule))
	r.Handle("DELETE /api/on-call/schedules/{id}", h(rtOnCallDeleteSchedule))
	r.Handle("GET /api/on-call/whoami", h(rtOnCallWhoami))
}

type rtOnCallMemberInfo struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`
}

// rtOnCallOnCallScheduleDto is the surface shape: members + current-rotation
// pointer resolved to {id, email} pairs so the UI can render email chips
// without N+1 round-trips.
type rtOnCallOnCallScheduleDto struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	CadenceDays int32     `json:"cadence_days"`
	AnchorAt    time.Time `json:"anchor_at"`
	// Members in rotation order. Orphan UUIDs (FK target deleted) appear with
	// email = "(deleted user)" so the operator can prune them.
	Members       []rtOnCallMemberInfo `json:"members"`
	CurrentOnCall *rtOnCallMemberInfo  `json:"current_on_call"`
	CreatedAt     time.Time            `json:"created_at"`
	UpdatedAt     time.Time            `json:"updated_at"`
}

type rtOnCallScheduleInput struct {
	Name        string      `json:"name"`
	Members     []uuid.UUID `json:"members"`
	CadenceDays int32       `json:"cadence_days"`
	// Optional anchor override. Defaults to NOW() on create; on update the
	// stored value is preserved when this field is absent so cadence math
	// doesn't drift every PUT.
	AnchorAt *time.Time `json:"anchor_at"`
}

// rtOnCallScheduleRow is the 7-column tuple every query here returns.
type rtOnCallScheduleRow struct {
	ID          uuid.UUID   `db:"id"`
	Name        string      `db:"name"`
	Members     []uuid.UUID `db:"members"`
	CadenceDays int32       `db:"cadence_days"`
	AnchorAt    time.Time   `db:"anchor_at"`
	CreatedAt   time.Time   `db:"created_at"`
	UpdatedAt   time.Time   `db:"updated_at"`
}

func rtOnCallLoadMemberEmails(ctx context.Context, db *pgxpool.Pool, ids []uuid.UUID) []rtOnCallMemberInfo {
	out := []rtOnCallMemberInfo{}
	if len(ids) == 0 {
		return out
	}
	rows, err := queryAll[Tup2[uuid.UUID, string]](ctx, db, "SELECT id, email FROM users WHERE id = ANY($1)", ids)
	if err != nil {
		rows = nil
	}

	// Preserve the schedule's stored ordering rather than DB row order.
	for _, id := range ids {
		email := "(deleted user)"
		for _, r := range rows {
			if r.A == id {
				email = r.B
				break
			}
		}
		out = append(out, rtOnCallMemberInfo{ID: id, Email: email})
	}
	return out
}

func rtOnCallScheduleToDto(ctx context.Context, db *pgxpool.Pool, row *rtOnCallScheduleRow) rtOnCallOnCallScheduleDto {
	memberInfo := rtOnCallLoadMemberEmails(ctx, db, row.Members)
	var current *rtOnCallMemberInfo
	if uid := OnCallResolveOnCallUser(ctx, db, row.ID, time.Now().UTC()); uid != nil {
		for _, m := range memberInfo {
			if m.ID == *uid {
				c := m
				current = &c
				break
			}
		}
	}
	return rtOnCallOnCallScheduleDto{
		ID:            row.ID,
		Name:          row.Name,
		CadenceDays:   row.CadenceDays,
		AnchorAt:      row.AnchorAt,
		Members:       memberInfo,
		CurrentOnCall: current,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
}

func rtOnCallValidateInput(input *rtOnCallScheduleInput) error {
	name := strings.TrimSpace(input.Name)
	if name == "" || utf8.RuneCountInString(name) > 200 {
		return apiErr(http.StatusBadRequest, "name must be 1-200 characters")
	}
	if len(input.Members) == 0 {
		return apiErr(http.StatusBadRequest, "members list cannot be empty")
	}
	seen := make(map[uuid.UUID]bool, len(input.Members))
	for _, m := range input.Members {
		if seen[m] {
			return apiErr(http.StatusBadRequest, "members list contains duplicate user IDs")
		}
		seen[m] = true
	}
	if input.CadenceDays < 1 || input.CadenceDays > 90 {
		return apiErr(http.StatusBadRequest, "cadence_days must be between 1 and 90")
	}
	return nil
}

// rtOnCallValidateMembersExist rejects a member UUID the caller may not page:
// anyone other than themselves, or a user they directly manage
// (users.reseller_id = caller) — the same self-or-managed boundary
// rt_escalation_policies' validateUserRoutes enforces for `user:<uuid>`
// escalation steps.
//
// ⚠ SECURITY: this used to only check the IDs existed, with no ownership
// term. A schedule's members feed straight into on_call_schedule:<uuid>
// escalation routing, so an admin could add ANY other user's UUID (trivially
// discoverable via GET /api/users, which lists every user on the install) as a
// rotation member of a schedule they own, and pages routed at that schedule
// would deliver to the victim's real email/Slack/Discord/PagerDuty/webhook —
// the exact sibling gap validateUserRoutes closed at s437 for the user: route,
// missed here because this table's own member list is a different path into
// the same sink.
func rtOnCallValidateMembersExist(ctx context.Context, db *pgxpool.Pool, members []uuid.UUID, ownerID uuid.UUID) error {
	found, err := queryScalar[int64](ctx, db,
		"SELECT COUNT(*) FROM users WHERE id = ANY($1) AND (id = $2 OR reseller_id = $2)",
		members, ownerID)
	if err != nil {
		return internalError("validate members", err)
	}
	if found != int64(len(members)) {
		return apiErr(http.StatusBadRequest, "one or more member IDs do not match existing users")
	}
	return nil
}

// rtOnCallListSchedules is GET /api/on-call/schedules — admin: list this
// tenant's rotation schedules.
//
// ⚠ SECURITY (s437): this table carried no user_id at all until this release —
// every route here gated on AdminUser (role) alone, so any admin on the
// install could list, read, write or delete every OTHER tenant's on-call
// rotations. Scoped the same way alerts/servers scope a caller-supplied
// resource: never widens for admin, admin included.
func rtOnCallListSchedules(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	rows, err := queryAll[rtOnCallScheduleRow](r.Context(), st.DB,
		"SELECT id, name, members, cadence_days, anchor_at, created_at, updated_at "+
			"FROM on_call_schedules WHERE user_id = $1 ORDER BY name ASC", claims.Sub)
	if err != nil {
		return internalError("list schedules", err)
	}
	out := make([]rtOnCallOnCallScheduleDto, 0, len(rows))
	for i := range rows {
		out = append(out, rtOnCallScheduleToDto(r.Context(), st.DB, &rows[i]))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// rtOnCallGetSchedule is GET /api/on-call/schedules/{id} — admin: fetch one
// rotation by id, scoped to the caller's own tenant.
func rtOnCallGetSchedule(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	row, err := queryOpt[rtOnCallScheduleRow](r.Context(), st.DB,
		"SELECT id, name, members, cadence_days, anchor_at, created_at, updated_at "+
			"FROM on_call_schedules WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("get schedule", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Schedule not found")
	}
	writeJSON(w, http.StatusOK, rtOnCallScheduleToDto(r.Context(), st.DB, row))
	return nil
}

// rtOnCallCreateSchedule is POST /api/on-call/schedules — admin: create a
// rotation, owned by the creating admin's own tenant.
func rtOnCallCreateSchedule(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var input rtOnCallScheduleInput
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if err := rtOnCallValidateInput(&input); err != nil {
		return err
	}
	if err := rtOnCallValidateMembersExist(r.Context(), st.DB, input.Members, claims.Sub); err != nil {
		return err
	}

	anchor := time.Now().UTC()
	if input.AnchorAt != nil {
		anchor = *input.AnchorAt
	}
	row, err := queryOne[rtOnCallScheduleRow](r.Context(), st.DB,
		"INSERT INTO on_call_schedules (user_id, name, members, cadence_days, anchor_at) "+
			"VALUES ($1, $2, $3, $4, $5) "+
			"RETURNING id, name, members, cadence_days, anchor_at, created_at, updated_at",
		claims.Sub, strings.TrimSpace(input.Name), input.Members, input.CadenceDays, anchor)
	if err != nil {
		return internalError("create schedule", err)
	}
	writeJSON(w, http.StatusOK, rtOnCallScheduleToDto(r.Context(), st.DB, &row))
	return nil
}

// rtOnCallUpdateSchedule is PUT /api/on-call/schedules/{id} — admin: update an
// existing rotation, scoped to the caller's own tenant.
func rtOnCallUpdateSchedule(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var input rtOnCallScheduleInput
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if err := rtOnCallValidateInput(&input); err != nil {
		return err
	}
	if err := rtOnCallValidateMembersExist(r.Context(), st.DB, input.Members, claims.Sub); err != nil {
		return err
	}

	var row *rtOnCallScheduleRow
	if input.AnchorAt != nil {
		row, err = queryOpt[rtOnCallScheduleRow](r.Context(), st.DB,
			"UPDATE on_call_schedules "+
				"SET name = $2, members = $3, cadence_days = $4, anchor_at = $5, updated_at = NOW() "+
				"WHERE id = $1 AND user_id = $6 "+
				"RETURNING id, name, members, cadence_days, anchor_at, created_at, updated_at",
			id, strings.TrimSpace(input.Name), input.Members, input.CadenceDays, *input.AnchorAt, claims.Sub)
	} else {
		// No anchor in payload → preserve existing anchor so cadence math
		// doesn't reset on every save (e.g. when only re-ordering members).
		row, err = queryOpt[rtOnCallScheduleRow](r.Context(), st.DB,
			"UPDATE on_call_schedules "+
				"SET name = $2, members = $3, cadence_days = $4, updated_at = NOW() "+
				"WHERE id = $1 AND user_id = $5 "+
				"RETURNING id, name, members, cadence_days, anchor_at, created_at, updated_at",
			id, strings.TrimSpace(input.Name), input.Members, input.CadenceDays, claims.Sub)
	}
	if err != nil {
		return internalError("update schedule", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Schedule not found")
	}
	writeJSON(w, http.StatusOK, rtOnCallScheduleToDto(r.Context(), st.DB, row))
	return nil
}

// rtOnCallRewriteRoute replaces every step routed at `route` with
// all_channels. ok=false when the stored steps do not decode (they are
// already inert for dispatch; leave a blob we can't round-trip alone);
// changed=false when nothing pointed at route.
func rtOnCallRewriteRoute(stepsJSON json.RawMessage, route string) (json.RawMessage, bool, bool) {
	var steps []EscalationStep
	if decodeJSONBytes(stepsJSON, &steps) != nil {
		return nil, false, false
	}
	changed := false
	for i := range steps {
		if steps[i].Route == route {
			steps[i].Route = "all_channels"
			changed = true
		}
	}
	if !changed {
		return nil, false, true
	}
	if steps == nil {
		steps = []EscalationStep{}
	}
	b, err := json.Marshal(steps)
	if err != nil {
		return nil, false, false
	}
	return b, true, true
}

// rtOnCallDeleteSchedule is DELETE /api/on-call/schedules/{id} — admin:
// remove a rotation.
//
// Escalation-policy steps routing to this schedule (on_call_schedule:<uuid>)
// are rewritten to all_channels in the same transaction as the delete. The
// reference lives inside a JSONB blob, so no FK can do it for us, and a
// dangling route is not inert: OnCallRouteToUserIds resolves it to zero users
// and the page is dropped — including the *initial* page, because
// try_fire_alert dispatches step 0 and returns. Every alert bound to the
// policy would stop reaching email/Slack/PagerDuty entirely.
//
// (An earlier version of this comment claimed an hourly alert_engine
// orphan-route sweep repaired these. No such sweep exists — the engine's only
// hourly task is the resolved-alert purge.)
//
// ⚠ SECURITY (s437): both the delete and the orphan-route sweep below are
// scoped to the caller's own tenant. Scoping the sweep matters even though
// validateScheduleRoutes (rt_escalation_policies) refuses to let a policy
// reference another tenant's schedule going forward — a delete must still
// never touch another tenant's rows, defense-in-depth against any pre-existing
// or future cross-tenant reference.
func rtOnCallDeleteSchedule(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return internalError("delete schedule", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Delete first so a request for a schedule that does not exist (or isn't
	// owned by this tenant) fails fast, without taking a lock on this tenant's
	// escalation_policies rows and rolling it back (an admin-UI double-submit
	// would otherwise lock every policy row twice). Same transaction either
	// way: if the rewrite below fails, the schedule is not deleted.
	n, err := execSQL(ctx, tx, "DELETE FROM on_call_schedules WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("delete schedule", err)
	}
	if n == 0 {
		// The deferred rollback undoes nothing — nothing was touched.
		return apiErr(http.StatusNotFound, "Schedule not found")
	}

	orphanRoute := fmt.Sprintf("on_call_schedule:%s", id)
	policies, err := queryAll[Tup2[uuid.UUID, json.RawMessage]](ctx, tx,
		"SELECT id, steps FROM escalation_policies WHERE user_id = $1 FOR UPDATE", claims.Sub)
	if err != nil {
		return internalError("delete schedule", err)
	}

	rewritten := 0
	for _, p := range policies {
		newSteps, changed, ok := rtOnCallRewriteRoute(p.B, orphanRoute)
		if !ok || !changed {
			continue
		}
		if _, err := execSQL(ctx, tx,
			"UPDATE escalation_policies SET steps = $1, updated_at = NOW() WHERE id = $2",
			newSteps, p.A); err != nil {
			return internalError("delete schedule", err)
		}
		rewritten++
	}

	if err := tx.Commit(ctx); err != nil {
		return internalError("delete schedule", err)
	}

	if rewritten > 0 {
		suffix := "ies"
		if rewritten == 1 {
			suffix = "y"
		}
		slog.Info(fmt.Sprintf("Deleted on-call schedule %s; rewrote routed steps in %d escalation polic%s to all_channels", id, rewritten, suffix))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"policies_rewritten": rewritten,
	})
	return nil
}

// rtOnCallScrubDeletedUser removes a deleted user from every on-call rota and
// rewrites any escalation step routed directly at them.
//
// Called from the user-delete path. Neither reference can be a foreign key —
// on_call_schedules.members is a UUID[] and escalation_policies.steps is
// JSONB — so nothing else cleans them up, and a dangling reference is not
// inert: the rotation still hands out the dead UUID and the page goes nowhere.
//
// Best-effort and non-fatal: a failure here must not block the delete, since
// the stale reference is strictly less harmful than a half-deleted user. Any
// route that ends up unroutable still degrades to the alert owner in
// NotificationsDispatchEscalationStep.
func rtOnCallScrubDeletedUser(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID) {
	n, err := execSQL(ctx, db,
		"UPDATE on_call_schedules SET members = array_remove(members, $1), updated_at = NOW() "+
			"WHERE $1 = ANY(members)", userID)
	switch {
	case err != nil:
		slog.Warn(fmt.Sprintf("Could not scrub deleted user %s from on-call rotas: %v", userID, err))
	case n > 0:
		slog.Info(fmt.Sprintf("Removed deleted user %s from %d on-call schedule(s)", userID, n))
	}

	deadRoute := fmt.Sprintf("user:%s", userID)
	policies, err := queryAll[Tup2[uuid.UUID, json.RawMessage]](ctx, db, "SELECT id, steps FROM escalation_policies")
	if err != nil {
		slog.Warn(fmt.Sprintf("Could not scan escalation policies for deleted user %s: %v", userID, err))
		return
	}

	for _, p := range policies {
		newSteps, changed, ok := rtOnCallRewriteRoute(p.B, deadRoute)
		if !ok || !changed {
			continue
		}
		if _, err := execSQL(ctx, db,
			"UPDATE escalation_policies SET steps = $1, updated_at = NOW() WHERE id = $2",
			newSteps, p.A); err != nil {
			slog.Warn(fmt.Sprintf("Could not rewrite policy %s for deleted user %s: %v", p.A, userID, err))
		} else {
			slog.Info(fmt.Sprintf("Rewrote escalation policy %s step routed at deleted user %s", p.A, userID))
		}
	}
}

// rtOnCallWhoami is GET /api/on-call/whoami — any authenticated user: am I
// currently on call? Returns the schedules where this user is the current
// rotation holder. Empty array = not on call right now.
func rtOnCallWhoami(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	schedules, err := queryAll[Tup5[uuid.UUID, string, []uuid.UUID, int32, time.Time]](r.Context(), st.DB,
		"SELECT id, name, members, cadence_days, anchor_at FROM on_call_schedules")
	if err != nil {
		return internalError("whoami", err)
	}

	out := []map[string]any{}
	now := time.Now().UTC()
	for _, s := range schedules {
		// Re-resolve via the helper rather than recompute inline so the math
		// stays in exactly one place.
		if uid := OnCallResolveOnCallUser(r.Context(), st.DB, s.A, now); uid != nil && *uid == claims.Sub {
			out = append(out, map[string]any{
				"schedule_id":   s.A,
				"schedule_name": s.B,
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
