package api

// Port of panel/backend/src/services/system_log.rs.

import (
	"context"

	"github.com/google/uuid"
)

// SystemLogLogEvent inserts a system log entry. Fire-and-forget — never fails
// the caller.
func SystemLogLogEvent(ctx context.Context, db Querier, level, source, message string, details *string) {
	_, _ = execSQL(ctx, db,
		"INSERT INTO system_logs (id, level, source, message, details) VALUES ($1, $2, $3, $4, $5)",
		uuid.New(), level, source, message, details)
}
