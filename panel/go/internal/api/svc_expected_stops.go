package api

// Port of panel/backend/src/services/expected_stops.rs.
//
// Deliberate container stops — the one place that records, reads and clears them.
//
// The alert engine cannot otherwise tell "the operator stopped this" from "this
// crashed": it sees exited/dead in a 120-second poll of the agent's /apps and
// fires container_down. Every writer that stops a managed container on purpose
// records a row here; the engine reads it before firing and deletes it the
// moment the container is observed in any state that is not exited/dead.
//
// Keyed on (server_id, container_name) — the same key alert_state uses for this
// alert type — never on container_id, which changes on every app Update
// (update_app/change_container_image/update_env re-create the container) and
// is not unique across a cloned fleet member. See the migration for the full
// reasoning.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Why a container is stopped. Stored verbatim so the UI can say it in words.
const (
	ExpectedStopsReasonOperatorStop = "operator_stop"
	ExpectedStopsReasonManualSleep  = "manual_sleep"
	ExpectedStopsReasonAutoSleep    = "auto_sleep"
	ExpectedStopsReasonStackStop    = "stack_stop"
	// ExpectedStopsReasonRecreate: Update/change-image/edit-env recreate the
	// container — `docker rm` then `docker create` (or its blue-green
	// equivalent) — which is genuinely exited/absent for part of that window
	// even though nobody asked it to stay down. Recorded BEFORE the agent call
	// starts, unlike every other reason here: those record only after a stop
	// has already succeeded, but a recreate's whole point is to interrupt a
	// running container on purpose, so the healer must be blind to the gap
	// from the moment it opens, not after.
	ExpectedStopsReasonRecreate = "recreate_in_progress"
)

// ExpectedStopsRecord records that this container was stopped on purpose.
//
// ⚠ Call this only AFTER the stop has actually succeeded. Recording it first
// and having the agent refuse would mark a still-RUNNING container as
// expectedly stopped, and the next genuine crash would be suppressed.
func ExpectedStopsRecord(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, containerName, reason string, actorEmail *string) {
	_, err := execSQL(ctx, db,
		"INSERT INTO container_expected_stops (server_id, container_name, reason, actor_email, stopped_at) "+
			"VALUES ($1, $2, $3, $4, NOW()) "+
			"ON CONFLICT (server_id, container_name) DO UPDATE SET "+
			"reason = $3, actor_email = $4, stopped_at = NOW()",
		serverID, containerName, reason, actorEmail)
	if err != nil {
		// Deliberately not fatal: failing to record an expectation costs a
		// spurious alert, while failing the operator's stop costs them the
		// action they asked for. But it must be visible — a silent miss here
		// looks exactly like the defect this table exists to fix.
		slog.Warn(fmt.Sprintf("Could not record expected stop for '%s' on server %s: %v", containerName, serverID, err))
	}
}

// ExpectedStopsClear forgets the expectation — the container is running
// again, or is being started.
func ExpectedStopsClear(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, containerName string) {
	_, _ = execSQL(ctx, db,
		"DELETE FROM container_expected_stops WHERE server_id = $1 AND container_name = $2",
		serverID, containerName)
}

// ExpectedStopsClearIfOlderThan clears from OBSERVATION, without racing a
// stop recorded mid-sweep.
//
// check_container_health takes ONE /apps snapshot and then walks it with
// awaited database and notification calls per container, so several seconds
// can pass between the observation and this call. In that window the operator
// may have pressed Stop. Deleting unconditionally would discard an expectation
// that is NEWER than the evidence being used to discard it, and the next sweep
// would then fire the alert this table exists to prevent.
//
// observedAt is stamped before the snapshot is fetched, so only an expectation
// that predates the observation is cleared.
func ExpectedStopsClearIfOlderThan(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, containerName string, observedAt time.Time) {
	_, _ = execSQL(ctx, db,
		"DELETE FROM container_expected_stops "+
			"WHERE server_id = $1 AND container_name = $2 AND stopped_at < $3",
		serverID, containerName, observedAt)
}

// ExpectedStopsClearAbsent forgets every expectation for a container this
// host no longer reports.
//
// ExpectedStopsClearIfOlderThan runs from OBSERVING a container alive, so it
// can only ever reach a container that still exists. A REMOVED one is never
// observed again in any state, and nothing else reaches its row: the engine
// keeps skipping its container_down branch, the auto-heal restart leg keeps
// skipping it, and the Apps page keeps calling it "stopped on purpose" and
// naming whoever stopped the container that is gone. Not for a container that
// is absent — for the NEXT container of that name, which is the one that
// crashed.
//
// Removing an app and redeploying it under the same name is the supported way
// to rebuild it while keeping its data (the data tree is keyed on the app's
// own name, not on the container), so the container this silences is not a
// corner case. It is the repair loop: stop it because it is misbehaving,
// remove it, redeploy it, and it is still misbehaving.
//
// alert_engine runs the identical sweep for alert_state at the same call site,
// for the identical reason and after an identical live incident that ran four
// months. This is that sweep's missing twin.
//
// ⚠ observed MUST be the host's complete listing, and an empty one does
// nothing. `container_name <> ALL('{}')` is true for every row, so a listing
// that is empty because the host could not be read would clear every
// expectation at once — and the next sweep would fire container_down for every
// container the operator had deliberately stopped, which is the defect this
// table was created to remove. An empty listing is the one observation that
// cannot tell "nothing is here" from "I can see nothing", and the cost of
// reading it wrong is not symmetric. A host with no containers has nothing for
// an expectation to suppress anyway; the removal doors clear their own row.
//
// `stopped_at < observed_at` is the guard ExpectedStopsClearIfOlderThan
// carries, for the same race: the snapshot is taken once and walked with
// awaited calls per container, so an expectation recorded inside that window
// is NEWER than the evidence being used to discard it.
func ExpectedStopsClearAbsent(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, observed []string, observedAt time.Time) {
	if len(observed) == 0 {
		return
	}
	_, _ = execSQL(ctx, db,
		"DELETE FROM container_expected_stops "+
			"WHERE server_id = $1 AND stopped_at < $2 AND container_name <> ALL($3)",
		serverID, observedAt, observed)
}

// ExpectedStopsExpectedOnServer is every container this host is expected to
// be holding stopped (a set).
//
// Loaded once per member per sweep rather than queried per container: the
// health check already walks every container the host reports, and a query
// each would multiply the sweep's database round-trips by the app count.
func ExpectedStopsExpectedOnServer(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID) map[string]bool {
	out := map[string]bool{}
	names, err := queryAll[string](ctx, db,
		"SELECT container_name FROM container_expected_stops WHERE server_id = $1", serverID)
	if err != nil {
		return out
	}
	for _, n := range names {
		out[n] = true
	}
	return out
}

// ExpectedStopsReasonsOnServer is the reason a container is stopped (plus who
// stopped it, if a person did) — (container_name, reason, actor_email) — for
// the operator-facing surfaces. actor_email is NULL for auto_sleep, which no
// person initiates.
func ExpectedStopsReasonsOnServer(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID) []Tup3[string, string, *string] {
	rows, err := queryAll[Tup3[string, string, *string]](ctx, db,
		"SELECT container_name, reason, actor_email FROM container_expected_stops WHERE server_id = $1",
		serverID)
	if err != nil {
		return []Tup3[string, string, *string]{}
	}
	return rows
}

// ExpectedStopsResolveOpenContainerDown closes out an alert the container had
// already raised before it was stopped.
//
// The sequence this exists for is the common one, and it is the reverse of the
// one the suppression models: the container CRASHES, container_down fires and
// an incident opens, and THEN the operator presses Stop to take it out of
// service while they investigate. From that moment the engine's exited arm is
// skipped, so nothing re-evaluates the row — the recovery arm cannot resolve
// it (the container is deliberately down) and the stale sweep cannot either
// (an exited container is still listed by the agent). The row would stay
// 'firing' for ever, escalating for seven days, with the incident published
// throughout.
//
// So recording an expectation is also a resolve point.
func ExpectedStopsResolveOpenContainerDown(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, containerName string) {
	owner, err := queryScalarOpt[uuid.UUID](ctx, db, "SELECT user_id FROM servers WHERE id = $1", serverID)
	if err != nil || owner == nil {
		return
	}
	userID := *owner

	firing, err := queryScalarOpt[string](ctx, db,
		"SELECT current_state FROM alert_state "+
			"WHERE server_id = $1 AND alert_type = 'container_down' AND state_key = $2",
		serverID, containerName)
	if err != nil || firing == nil || *firing != "firing" {
		return
	}

	_, _ = execSQL(ctx, db,
		"UPDATE alert_state SET current_state = 'ok', fired_at = NULL, last_notified_at = NULL "+
			"WHERE server_id = $1 AND alert_type = 'container_down' AND state_key = $2",
		serverID, containerName)

	NotificationsResolveAlert(ctx, db, userID, &serverID, nil, "container_down", containerName,
		fmt.Sprintf("Container '%s' was stopped deliberately", containerName),
		fmt.Sprintf("Docker container '%s' is stopped because it was asked to be. "+
			"The earlier alert has been resolved.", containerName))

	// NotificationsResolveAlert writes to `alerts` and nothing else — it has
	// no reference to managed_incidents — so an incident auto-opened for this
	// container would otherwise stay `investigating` on the public status page
	// until a human closed it by hand. Matched on the EXACT generated title for
	// both terminal states, never a LIKE, so a container whose name is a
	// prefix of another's cannot close its neighbour's incident.
	for _, state := range []string{"exited", "dead"} {
		_, _ = execSQL(ctx, db,
			"UPDATE managed_incidents SET status = 'resolved', resolved_at = NOW() "+
				"WHERE user_id = $1 AND title = $2 AND status NOT IN ('resolved', 'postmortem')",
			userID, fmt.Sprintf("Container '%s' is %s", containerName, state))
	}
}
