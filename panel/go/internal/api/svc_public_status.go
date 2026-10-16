package api

// services/public_status.rs — the one gate the unauthenticated status-page
// surface passes through.
//
// Four routes answer with no authentication at all — /api/status-page,
// /api/status-page/public, /api/status-page/subscribe and
// /api/status-page/unsubscribe — and until v2.70.0 exactly ONE checked
// anything: monitors::status_page read settings.status_page_enabled and failed
// closed; incidents::public_status_page read status_page_config.enabled, which
// defaults TRUE (column and fallback) and no migration seeds, so it failed
// open on a fresh install; subscribe/unsubscribe read nothing, so anyone could
// add verified subscriber rows and delete others' on an install whose status
// page was never turned on. /status is served by public_status_page, so every
// install published its alert engine's output (service_down / disk incidents
// naming the operator's hosts) from first boot.
//
// So the publish decision lives here, in one function, and every
// unauthenticated status-page route calls it. status_page_config.enabled
// survives only as a secondary switch (hides the enhanced page) — no longer a
// publish decision, which is why its DEFAULT TRUE is now harmless.

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PublicStatusIsEnabled: is anything published on the unauthenticated
// status-page surface? Absent, unreadable, or anything other than the literal
// "true" is OFF — publishing operational state to the internet is never
// decided by a default, nor by a query that failed.
func PublicStatusIsEnabled(ctx context.Context, db *pgxpool.Pool) bool {
	v, err := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = 'status_page_enabled'")
	if err != nil {
		v = nil
	}
	return publicStatusMeansEnabled(v)
}

// publicStatusMeansEnabled is the decision itself, testable without a DB. nil
// covers both "no such setting" and "the query failed".
func publicStatusMeansEnabled(value *string) bool {
	return value != nil && *value == "true"
}

// PublicStatusRequireEnabled is the guard a public handler starts with. 404
// rather than 403 so a disabled status page is indistinguishable from an
// install that never had one (what the guide promises).
func PublicStatusRequireEnabled(ctx context.Context, db *pgxpool.Pool) error {
	if PublicStatusIsEnabled(ctx, db) {
		return nil
	}
	return apiErr(404, "Status page not enabled")
}

// PublicStatusResolveCurrentStatusPageOwner is the tenant
// incidents::public_status_page publishes — same tie-break, so
// subscribe/unsubscribe/list_subscribers agree with the public page on whose
// status page it is instead of treating status_page_subscribers as
// install-wide. Falls back to the install's first user when no
// status_page_config row exists (status_page_enabled lives on a different
// settings screen, so /subscribe is reachable before an admin ever touched
// status-page settings). nil only if users is empty.
func PublicStatusResolveCurrentStatusPageOwner(ctx context.Context, db *pgxpool.Pool) *uuid.UUID {
	if uid, err := queryScalarOpt[uuid.UUID](ctx, db, "SELECT user_id FROM status_page_config ORDER BY created_at ASC, id ASC LIMIT 1"); err == nil && uid != nil {
		return uid
	}
	uid, err := queryScalarOpt[uuid.UUID](ctx, db, "SELECT id FROM users ORDER BY created_at ASC LIMIT 1")
	if err != nil {
		return nil
	}
	return uid
}
