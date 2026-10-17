package api

// Port of panel/backend/src/routes/escalation_policies.rs.
//
// Phase 4 W3: escalation policy admin API. Admin-only CRUD over
// escalation_policies. Policies are referenced from
// alert_rules.escalation_policy_id (nullable FK with ON DELETE SET NULL —
// removing a policy reverts every rule that used it back to the pre-W3
// hardcoded 15/30-min cadence).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtEscalationPoliciesRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/escalation-policies", h(rtEscalationPoliciesListPolicies))
	r.Handle("POST /api/escalation-policies", h(rtEscalationPoliciesCreatePolicy))
	r.Handle("GET /api/escalation-policies/{id}", h(rtEscalationPoliciesGetPolicy))
	r.Handle("PUT /api/escalation-policies/{id}", h(rtEscalationPoliciesUpdatePolicy))
	r.Handle("DELETE /api/escalation-policies/{id}", h(rtEscalationPoliciesDeletePolicy))
}

type rtEscalationPoliciesPolicyDto struct {
	ID        uuid.UUID       `json:"id" db:"id"`
	Name      string          `json:"name" db:"name"`
	Steps     json.RawMessage `json:"steps" db:"steps"`
	CreatedAt time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt time.Time       `json:"updated_at" db:"updated_at"`
	// How many alert_rules currently reference this policy. Surfaced in the
	// admin list so operators know what they're about to detach when they hit
	// Delete.
	UsedByRuleCount int64 `json:"used_by_rule_count" db:"used_by_rule_count,default"`
}

type rtEscalationPoliciesPolicyInput struct {
	Name  string           `json:"name"`
	Steps []EscalationStep `json:"steps"`
}

func rtEscalationPoliciesValidateInput(input *rtEscalationPoliciesPolicyInput) error {
	name := strings.TrimSpace(input.Name)
	if name == "" || utf8.RuneCountInString(name) > 200 {
		return apiErr(http.StatusBadRequest, "name must be 1-200 characters")
	}
	if len(input.Steps) == 0 {
		return apiErr(http.StatusBadRequest, "policy must contain at least one step")
	}
	if len(input.Steps) > 10 {
		return apiErr(http.StatusBadRequest, "policy cannot exceed 10 steps")
	}
	if input.Steps[0].AfterMinutes != 0 {
		return apiErr(http.StatusBadRequest, "first step must have after_minutes = 0")
	}

	// Strictly increasing after_minutes.
	for i := 1; i < len(input.Steps); i++ {
		if input.Steps[i].AfterMinutes <= input.Steps[i-1].AfterMinutes {
			return apiErr(http.StatusBadRequest, "after_minutes must strictly increase across steps")
		}
	}

	// Route shape validation.
	for i, step := range input.Steps {
		if err := rtEscalationPoliciesValidateRoute(step.Route); err != nil {
			return apiErr(http.StatusBadRequest, fmt.Sprintf("step %d: %s", i, err))
		}
	}
	return nil
}

func rtEscalationPoliciesValidateRoute(route string) error {
	if route == "all_channels" {
		return nil
	}
	if s, ok := strings.CutPrefix(route, "on_call_schedule:"); ok {
		if _, err := uuid.Parse(s); err != nil {
			return errors.New("invalid schedule UUID after on_call_schedule:")
		}
		return nil
	} else if s, ok := strings.CutPrefix(route, "user:"); ok {
		if _, err := uuid.Parse(s); err != nil {
			return errors.New("invalid user UUID after user:")
		}
		return nil
	} else if url, ok := strings.CutPrefix(route, "webhook:"); ok {
		if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
			return nil
		}
		return errors.New("webhook route must use http:// or https:// scheme")
	}
	return errors.New("route must be one of: on_call_schedule:<uuid>, user:<uuid>, all_channels, webhook:<url>")
}

// rtEscalationPoliciesValidateWebhookRoutes — SSRF: webhook:<url> routes
// reach the notification client (which refuses redirects), but the
// destination must still not resolve to an internal address — validateRoute
// only checks the scheme. It resolves DNS, so it runs at the create/update
// call site rather than inside validateInput. Parity with the alerts/monitors
// write paths.
func rtEscalationPoliciesValidateWebhookRoutes(ctx context.Context, input *rtEscalationPoliciesPolicyInput) error {
	for i, step := range input.Steps {
		if url, ok := strings.CutPrefix(step.Route, "webhook:"); ok {
			if err := validateURLNotInternal(ctx, url); err != nil {
				return apiErr(http.StatusBadRequest, fmt.Sprintf("step %d: webhook %s", i, err))
			}
		}
	}
	return nil
}

// rtEscalationPoliciesValidateScheduleRoutes rejects on_call_schedule:<uuid>
// routes pointing at a schedule that does not exist, OR that the caller
// doesn't own. validateRoute only parses the UUID, so a policy could be saved
// with a dangling rota reference — either by typo, or by the editor's
// read-modify-write racing a concurrent schedule delete and writing the stale
// steps back after deleteSchedule had already rewritten them. A dangling route
// is not inert: it resolves to zero users, which is why
// dispatch_escalation_step degrades to the alert owner's channels rather than
// dropping the page. This keeps it from being stored in the first place.
//
// ⚠ SECURITY (s437): the ownership half is new. Without it, a policy could
// legitimately reference — and therefore page — another tenant's on-call
// rotation, which now also carries its own user_id. "Does not exist" is used
// for the ownership-denied case too (not "not owned"), matching this
// codebase's convention of never confirming another tenant's resource exists
// to a caller who doesn't own it.
func rtEscalationPoliciesValidateScheduleRoutes(ctx context.Context, db *pgxpool.Pool, input *rtEscalationPoliciesPolicyInput, ownerID uuid.UUID) error {
	for i, step := range input.Steps {
		s, ok := strings.CutPrefix(step.Route, "on_call_schedule:")
		if !ok {
			continue
		}
		scheduleID, err := uuid.Parse(s)
		if err != nil {
			continue // shape already rejected by validateRoute
		}

		exists, err := queryScalarOpt[uuid.UUID](ctx, db,
			"SELECT id FROM on_call_schedules WHERE id = $1 AND user_id = $2", scheduleID, ownerID)
		if err != nil {
			return internalError("validate schedule routes", err)
		}
		if exists == nil {
			return apiErr(http.StatusBadRequest, fmt.Sprintf("step %d: on-call schedule %s does not exist", i, scheduleID))
		}
	}
	return nil
}

// rtEscalationPoliciesValidateUserRoutes rejects user:<uuid> routes pointing
// at a user the caller may not page: anyone other than themselves, or a user
// they directly manage (users.reseller_id = caller) — the same ownership shape
// list/create in rt_users deliberately do NOT enforce (the user directory is
// shared across every admin on the install), but paging someone is not
// browsing a directory.
//
// ⚠ SECURITY: validateRoute only parses the UUID as a shape check. Without
// this, ANY admin could route an escalation step at ANY other user's UUID —
// trivially discoverable via GET /api/users — then attach that policy to an
// alert rule they own and trigger it, delivering the alert's subject/message
// to that user's real email/Slack/Discord/PagerDuty/webhook with no consent
// and no way for the victim to trace who set it up. Exact sibling of the
// on_call_schedule: gap validateScheduleRoutes closed at s437.
func rtEscalationPoliciesValidateUserRoutes(ctx context.Context, db *pgxpool.Pool, input *rtEscalationPoliciesPolicyInput, ownerID uuid.UUID) error {
	for i, step := range input.Steps {
		s, ok := strings.CutPrefix(step.Route, "user:")
		if !ok {
			continue
		}
		targetID, err := uuid.Parse(s)
		if err != nil {
			continue // shape already rejected by validateRoute
		}
		if targetID == ownerID {
			continue // paging yourself needs no ownership check
		}

		managed, err := queryScalarOpt[uuid.UUID](ctx, db,
			"SELECT id FROM users WHERE id = $1 AND reseller_id = $2", targetID, ownerID)
		if err != nil {
			return internalError("validate user routes", err)
		}
		if managed == nil {
			return apiErr(http.StatusBadRequest, fmt.Sprintf("step %d: user %s does not exist", i, targetID))
		}
	}
	return nil
}

func rtEscalationPoliciesValidateAll(ctx context.Context, db *pgxpool.Pool, input *rtEscalationPoliciesPolicyInput, ownerID uuid.UUID) error {
	if err := rtEscalationPoliciesValidateInput(input); err != nil {
		return err
	}
	if err := rtEscalationPoliciesValidateWebhookRoutes(ctx, input); err != nil {
		return err
	}
	if err := rtEscalationPoliciesValidateScheduleRoutes(ctx, db, input, ownerID); err != nil {
		return err
	}
	return rtEscalationPoliciesValidateUserRoutes(ctx, db, input, ownerID)
}

// rtEscalationPoliciesListPolicies is GET /api/escalation-policies — admin:
// list this tenant's policies.
//
// ⚠ SECURITY (s437): this table carried no user_id at all until this release —
// every route here gated on AdminUser (role) alone, so any admin on the
// install could list, read, write or delete every OTHER tenant's escalation
// policies. Scoped the same way alerts/servers scope a caller-supplied
// resource: never widens for admin, admin included. used_by_rule_count's
// subquery needs no extra scoping beyond the outer p.user_id filter —
// alert_rules.escalation_policy_id can only point at a same-tenant policy now
// that attachEscalationPolicy (rt_alerts) checks both sides' ownership.
func rtEscalationPoliciesListPolicies(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	rows, err := queryAll[rtEscalationPoliciesPolicyDto](r.Context(), st.DB,
		"SELECT p.id, p.name, p.steps, p.created_at, p.updated_at, "+
			"COALESCE((SELECT COUNT(*) FROM alert_rules WHERE escalation_policy_id = p.id), 0) AS used_by_rule_count "+
			"FROM escalation_policies p WHERE p.user_id = $1 ORDER BY p.name ASC", claims.Sub)
	if err != nil {
		return internalError("list policies", err)
	}
	writeJSON(w, http.StatusOK, rows)
	return nil
}

// rtEscalationPoliciesGetPolicy is GET /api/escalation-policies/{id} — admin:
// fetch a single policy, scoped to the caller's own tenant.
func rtEscalationPoliciesGetPolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	row, err := queryOpt[rtEscalationPoliciesPolicyDto](r.Context(), st.DB,
		"SELECT p.id, p.name, p.steps, p.created_at, p.updated_at, "+
			"COALESCE((SELECT COUNT(*) FROM alert_rules WHERE escalation_policy_id = p.id), 0) AS used_by_rule_count "+
			"FROM escalation_policies p WHERE p.id = $1 AND p.user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("get policy", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Policy not found")
	}
	writeJSON(w, http.StatusOK, row)
	return nil
}

func rtEscalationPoliciesStepsJSON(steps []EscalationStep) (json.RawMessage, error) {
	b, err := json.Marshal(steps)
	if err != nil {
		return nil, internalError("serialize policy steps", err)
	}
	return b, nil
}

// rtEscalationPoliciesCreatePolicy is POST /api/escalation-policies — admin:
// create a policy, owned by the creating admin's own tenant.
func rtEscalationPoliciesCreatePolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var input rtEscalationPoliciesPolicyInput
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if err := rtEscalationPoliciesValidateAll(r.Context(), st.DB, &input, claims.Sub); err != nil {
		return err
	}
	stepsJSON, err := rtEscalationPoliciesStepsJSON(input.Steps)
	if err != nil {
		return err
	}

	row, err := queryOne[rtEscalationPoliciesPolicyDto](r.Context(), st.DB,
		"INSERT INTO escalation_policies (user_id, name, steps) "+
			"VALUES ($1, $2, $3) "+
			"RETURNING id, name, steps, created_at, updated_at, 0::bigint AS used_by_rule_count",
		claims.Sub, strings.TrimSpace(input.Name), stepsJSON)
	if err != nil {
		return internalError("create policy", err)
	}
	writeJSON(w, http.StatusOK, row)
	return nil
}

// rtEscalationPoliciesUpdatePolicy is PUT /api/escalation-policies/{id} —
// admin: replace a policy, scoped to the caller's own tenant.
func rtEscalationPoliciesUpdatePolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var input rtEscalationPoliciesPolicyInput
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if err := rtEscalationPoliciesValidateAll(r.Context(), st.DB, &input, claims.Sub); err != nil {
		return err
	}
	stepsJSON, err := rtEscalationPoliciesStepsJSON(input.Steps)
	if err != nil {
		return err
	}

	row, err := queryOpt[rtEscalationPoliciesPolicyDto](r.Context(), st.DB,
		"UPDATE escalation_policies "+
			"SET name = $2, steps = $3, updated_at = NOW() "+
			"WHERE id = $1 AND user_id = $4 "+
			"RETURNING id, name, steps, created_at, updated_at, "+
			// Qualified: a bare `id` here binds to alert_rules.id, which made the
			// count always 0 after an update (inherited from the Rust handler).
			"COALESCE((SELECT COUNT(*) FROM alert_rules WHERE escalation_policy_id = escalation_policies.id), 0) AS used_by_rule_count",
		id, strings.TrimSpace(input.Name), stepsJSON, claims.Sub)
	if err != nil {
		return internalError("update policy", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Policy not found")
	}
	writeJSON(w, http.StatusOK, row)
	return nil
}

// rtEscalationPoliciesDeletePolicy is DELETE /api/escalation-policies/{id} —
// admin: delete a policy, scoped to the caller's own tenant.
//
// alert_rules.escalation_policy_id is ON DELETE SET NULL, so any rule that
// referenced this policy reverts to the pre-W3 default cadence. In-flight
// alerts whose escalation_step_index > 0 keep their index but won't advance
// further (next tick finds no policy to chain against).
func rtEscalationPoliciesDeletePolicy(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB,
		"DELETE FROM escalation_policies WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("delete policy", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Policy not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}
