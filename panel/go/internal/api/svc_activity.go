package api

// services/activity.rs — the activity_logs writers.

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ActivityLogActivity records an action performed by userID. Errors are
// logged, never returned (an audit write must not fail the request).
func ActivityLogActivity(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, userEmail, action string, targetType, targetName, details, ipAddress *string, apiKeyID *uuid.UUID) {
	activityWriteRow(ctx, db, &userID, userEmail, action, targetType, targetName, details, ipAddress, nil, apiKeyID)
}

// ActivityLogActivityOnServer is ActivityLogActivity, naming the server the
// action was performed ON.
//
// activity_logs.server_id existed since the multi-server migration (indexed,
// with a FK) and until v2.58.0 nothing wrote or read it. An unattended action
// that acts on one machine and records a row indistinguishable from the same
// action on another is not an audit trail, and cannot carry a per-server
// cooldown: the auto-healer's service restarts counted target_name alone, so
// two hosts running a service of the same name shared one budget.
//
// Callers acting on the panel itself, or on nothing in particular, keep
// using ActivityLogActivity and leave the column NULL.
func ActivityLogActivityOnServer(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, userEmail, action string, targetType, targetName, details, ipAddress *string, serverID, apiKeyID *uuid.UUID) {
	activityWriteRow(ctx, db, &userID, userEmail, action, targetType, targetName, details, ipAddress, serverID, apiKeyID)
}

// ActivityLogActivitySystem is for an event NO USER initiated — an unattended
// service acting on its own schedule, or a request that failed before any
// account could be identified.
//
// activity_logs.user_id is nullable with an ON DELETE SET NULL FK, so NULL is
// the schema's sanctioned "nobody". uuid.Nil is not: it names a users row
// that cannot exist, fk_activity_logs_user rejects the insert (23503), the
// warning below swallows it and the row is silently lost. Four writers once
// reached for the nil uuid and none ever recorded anything; two read their own
// rows back as a rate-limit gate, so a COUNT(*) that could only return 0 stood
// in for a cooldown (see auto_healer's SSL renewal gate — the fix there is to
// name the site's real owner, not to use this function).
//
// Use only where there genuinely is no user. user_email is NOT NULL, so pass
// something an operator can read — the attempted login address, or the name
// of the service acting.
func ActivityLogActivitySystem(ctx context.Context, db *pgxpool.Pool, userEmail, action string, targetType, targetName, details, ipAddress *string, serverID *uuid.UUID) {
	// No authenticated request is involved — nothing to attribute to a key.
	activityWriteRow(ctx, db, nil, userEmail, action, targetType, targetName, details, ipAddress, serverID, nil)
}

// activityWriteRow is the single INSERT. user_id is optional here and nowhere
// else in the public API, so a caller has to choose between naming a user and
// declaring there isn't one rather than inventing a sentinel uuid.
func activityWriteRow(ctx context.Context, db *pgxpool.Pool, userID *uuid.UUID, userEmail, action string, targetType, targetName, details, ipAddress *string, serverID, apiKeyID *uuid.UUID) {
	if _, err := execSQL(ctx, db,
		"INSERT INTO activity_logs (user_id, user_email, action, target_type, target_name, details, ip_address, server_id, api_key_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		userID, userEmail, action, targetType, targetName, details, ipAddress, serverID, apiKeyID); err != nil {
		slog.Warn("Failed to log activity '" + action + "': " + err.Error())
	}
}
