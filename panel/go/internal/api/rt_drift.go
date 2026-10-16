package api

// Phase 4 W5: fleet configuration-drift admin API (read-only).
//
// Two admin endpoints:
//   - `GET /api/drift/servers`               — the comparable server list (picker source).
//   - `GET /api/drift?reference=&targets=`   — the computed DriftReport.
//
// Pure reads from the hub DB — no writes, no scheduler, no remote agent call.
// Reconcile/push is deferred to W5.2 (see svc_drift.go).

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtDriftRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/drift/servers", h(rtDriftServers))
	r.Handle("GET /api/drift", h(rtDriftReport))
}

type rtDriftDriftServer struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	IsLocal      bool       `json:"is_local"`
	Status       string     `json:"status"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	AgentVersion *string    `json:"agent_version"`
}

// rtDriftServers — GET /api/drift/servers: comparable servers, local first.
// Drives the reference/target pickers in the UI.
//
// ⚠ SECURITY (s432): was `WHERE user_id = $1` — `servers.user_id` names
// whoever registered the row, not a tenant boundary. This route is admin-only,
// so there is no narrower case to preserve: the comparable servers are simply
// every server on the install.
func rtDriftServers(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	rows, err := queryAll[Tup6[uuid.UUID, string, bool, string, *time.Time, *string]](r.Context(), st.DB,
		"SELECT id, name, is_local, status, last_seen_at, agent_version "+
			"FROM servers ORDER BY is_local DESC, created_at DESC LIMIT 500")
	if err != nil {
		return internalError("drift servers", err)
	}
	out := make([]rtDriftDriftServer, 0, len(rows))
	for _, x := range rows {
		out = append(out, rtDriftDriftServer{ID: x.A, Name: x.B, IsLocal: x.C, Status: x.D, LastSeenAt: x.E, AgentVersion: x.F})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

type rtDriftDriftQuery struct {
	// Reference server. Defaults to the local server (or newest) when absent.
	Reference *uuid.UUID `json:"reference"`
	// Comma-separated target server ids. Absent → every other server.
	Targets *string `json:"targets"`
}

// rtDriftReport — GET /api/drift: compute the fleet configuration-drift report.
//
// ⚠ SECURITY (s432): the candidate-server query was `WHERE user_id = $1`, the
// same admin-scoping bug as rtDriftServers. Admin-only, so the comparable set
// is fleet-wide.
func rtDriftReport(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	var q rtDriftDriftQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	ctx := r.Context()

	// The comparable servers, local first — used to validate ids and to
	// default the reference/target selection.
	all, err := queryAll[uuid.UUID](ctx, st.DB,
		"SELECT id FROM servers ORDER BY is_local DESC, created_at DESC LIMIT 500")
	if err != nil {
		return internalError("drift server ids", err)
	}
	if len(all) == 0 {
		return apiErr(http.StatusBadRequest, "No servers available to compare")
	}
	valid := make(map[uuid.UUID]bool, len(all))
	for _, id := range all {
		valid[id] = true
	}

	reference := all[0] // local server (or newest) — ordered is_local DESC first
	if q.Reference != nil {
		if !valid[*q.Reference] {
			return apiErr(http.StatusNotFound, "Reference server not found")
		}
		reference = *q.Reference
	}

	targets := []uuid.UUID{}
	if q.Targets != nil && strings.TrimSpace(*q.Targets) != "" {
		seen := map[uuid.UUID]bool{}
		for _, part := range strings.Split(*q.Targets, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			id, err := uuid.Parse(p)
			if err != nil {
				return apiErr(http.StatusBadRequest, "Invalid target server id")
			}
			if id != reference && valid[id] && !seen[id] {
				seen[id] = true
				targets = append(targets, id)
			}
		}
	} else {
		for _, id := range all {
			if id != reference {
				targets = append(targets, id)
			}
		}
	}

	report, err := DriftBuildReport(ctx, st.DB, reference, targets)
	if err != nil {
		return internalError("drift report", err)
	}
	writeJSON(w, http.StatusOK, report)
	return nil
}
