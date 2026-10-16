package api

// Port of panel/backend/src/services/on_call.rs.
//
// Phase 4 W3: on-call rotation + route resolution helpers.
//
// OnCallResolveOnCallUser does the cadence math against an on_call_schedules
// row. OnCallRouteToUserIds translates an EscalationStep.Route discriminated
// string into the set of user IDs whose alert_rules channels should receive a
// page.
//
// Both helpers are read-only — they never mutate state. Channel fanout and the
// actual notification dispatch live in svc_notifications.go.

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

// OnCallResolveOnCallUser computes which user is on call at `at` for the
// given schedule.
//
// Returns nil when the schedule doesn't exist, has no members, or the row is
// otherwise unusable. Callers should treat that as "no on-call user — fall
// through to other route shapes."
//
// Math: idx = ((at - anchor_at).days / cadence_days) mod members.len.
// anchor_at in the future folds back (negative elapsed days wrap).
func OnCallResolveOnCallUser(ctx context.Context, db Querier, scheduleID uuid.UUID, at time.Time) *uuid.UUID {
	row, err := queryOpt[Tup3[[]uuid.UUID, int32, time.Time]](ctx, db,
		"SELECT members, cadence_days, anchor_at "+
			"FROM on_call_schedules WHERE id = $1", scheduleID)
	if err != nil || row == nil {
		return nil
	}
	members, cadenceDays, anchorAt := row.A, row.B, row.C
	if len(members) == 0 || cadenceDays <= 0 {
		return nil
	}

	// chrono num_days truncates toward zero, as does Duration division.
	elapsedDays := int64(at.Sub(anchorAt) / (24 * time.Hour))
	idx := onCallRotationIndex(elapsedDays, int64(cadenceDays), len(members))
	m := members[idx]
	return &m
}

// onCallRotationIndex is (elapsed.div_euclid(cadence)).rem_euclid(n).
// Negative elapsed_days (anchor in future) and large positive values both
// need to land in [0, n).
func onCallRotationIndex(elapsedDays, cadenceDays int64, memberCount int) int {
	return int(onCallRemEuclid(onCallDivEuclid(elapsedDays, cadenceDays), int64(memberCount)))
}

func onCallDivEuclid(a, b int64) int64 {
	q := a / b
	if a%b < 0 {
		if b > 0 {
			q--
		} else {
			q++
		}
	}
	return q
}

func onCallRemEuclid(a, b int64) int64 {
	r := a % b
	if r < 0 {
		if b < 0 {
			r -= b
		} else {
			r += b
		}
	}
	return r
}

// OnCallRouteToUserIds translates a route discriminator into the set of user
// IDs whose alert_rules channels should receive the page.
//
//   - "on_call_schedule:<uuid>" — current on-call user at now.
//   - "user:<uuid>" — exactly that user.
//   - "all_channels" — empty. Caller falls back to the alert's owner.
//   - "webhook:<url>" — empty. Caller handles webhook directly.
//   - anything else — empty, debug-logged.
func OnCallRouteToUserIds(ctx context.Context, db Querier, route string) []uuid.UUID {
	if s, ok := strings.CutPrefix(route, "on_call_schedule:"); ok {
		schedID, err := uuid.Parse(s)
		if err != nil {
			slog.Debug("route_to_user_ids: invalid schedule uuid in " + route)
			return []uuid.UUID{}
		}
		if uid := OnCallResolveOnCallUser(ctx, db, schedID, time.Now().UTC()); uid != nil {
			return []uuid.UUID{*uid}
		}
		return []uuid.UUID{}
	} else if s, ok := strings.CutPrefix(route, "user:"); ok {
		uid, err := uuid.Parse(s)
		if err != nil {
			slog.Debug("route_to_user_ids: invalid user uuid in " + route)
			return []uuid.UUID{}
		}
		return []uuid.UUID{uid}
	} else if route == "all_channels" || strings.HasPrefix(route, "webhook:") {
		return []uuid.UUID{}
	}
	slog.Debug("route_to_user_ids: unknown route shape " + route)
	return []uuid.UUID{}
}
