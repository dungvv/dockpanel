package api

// Port of panel/backend/src/routes/agent_updates.rs — what version should a
// remote agent be running?
//
// What this used to be, and why it never worked (s233): it answered version /
// download_url / checksum from three settings rows that NOTHING ever wrote, and
// it required a user JWT from a caller that structurally cannot hold one (an
// agent has a token from its servers row) — so it 401'd on every request since
// v2.10.0. The failure was invisible: the agent read the error body as JSON,
// the missing version fell back to its own, and it concluded it was current.
//
// What it is now: one field, target_version, and no download plumbing.
// scripts/agent-self-update.sh derives arch, asset URL and digest ON THE BOX
// from the release's checksums.txt. null means "do nothing" — whenever agent
// auto-update is off or the channel is on hold. The switch is enforced HERE
// because there is no panel→agent config push: an agent only learns by asking.

import "net/http"

func rtAgentUpdatesRegister(r *Router) {
	r.Handle("GET /api/agent/version", func(w http.ResponseWriter, req *http.Request) error {
		return rtAgentUpdatesLatestVersion(r.St, w, req)
	})
}

// rtAgentUpdatesLatestVersion: GET /api/agent/version — authenticated with the
// agent's own servers-table token.
func rtAgentUpdatesLatestVersion(st *AppState, w http.ResponseWriter, r *http.Request) error {
	serverID, err := st.authenticateAgent(r)
	if err != nil {
		return err
	}
	if err := st.agentRateLimit(serverID); err != nil {
		return err
	}
	target, err := rtAgentUpdatesResolveAgentTarget(r, st)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"target_version": target})
	return nil
}

// rtAgentUpdatesResolveAgentTarget: nil = the agent must not update itself.
//
// The target is the release THIS PANEL is running, never "the newest tag on
// GitHub": an agent should not get ahead of the panel that drives it, and the
// release workflow builds the agent assets from the same tag.
func rtAgentUpdatesResolveAgentTarget(r *http.Request, st *AppState) (*string, error) {
	setting := func(key string) (*string, error) {
		v, err := queryScalarOpt[string](r.Context(), st.DB, "SELECT value FROM settings WHERE key = $1", key)
		if err != nil {
			return nil, internalError("agent target", err)
		}
		return v, nil
	}
	// Opt-in, and off unless explicitly switched on. Seeded 'false'.
	v, err := setting("agent_auto_update_enabled")
	if err != nil {
		return nil, err
	}
	if v == nil || *v != "true" {
		return nil, nil
	}
	// `hold` is the operator saying "nothing moves". It has to win over the
	// auto-update switch, or the one control that stops a fleet mid-incident
	// would not actually stop it.
	ch, err := setting("update_channel")
	if err != nil {
		return nil, err
	}
	if ch != nil && *ch == "hold" {
		return nil, nil
	}
	t := "v" + Version
	return &t, nil
}
