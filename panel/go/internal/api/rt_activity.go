package api

// routes/activity.rs — the admin audit feed.

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func rtActivityRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/activity", h(rtActivityList))
}

type rtActivityActivityQuery struct {
	Limit  *int64  `json:"limit"`
	Offset *int64  `json:"offset"`
	Action *string `json:"action"`
}

type rtActivityActivityLog struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     *uuid.UUID `json:"user_id" db:"user_id"`
	UserEmail  string     `json:"user_email" db:"user_email"`
	Action     string     `json:"action" db:"action"`
	TargetType *string    `json:"target_type" db:"target_type"`
	TargetName *string    `json:"target_name" db:"target_name"`
	Details    *string    `json:"details" db:"details"`
	IPAddress  *string    `json:"ip_address" db:"ip_address"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	// Which host the action happened on. Written since v2.58.0 but never
	// declared here, so SELECT * dropped it and the feed could not say which
	// of N machines an action ran on. NULL for a panel-wide action.
	ServerID *uuid.UUID `json:"server_id" db:"server_id"`
	// Resolved from the join so the operator reads a name, not a UUID. NULL
	// when the server row has since been deleted.
	ServerName *string `json:"server_name" db:"server_name"`
}

// rtActivityColumns: spelled out rather than SELECT * because the join adds
// a column not on activity_logs, and a * would silently ship any column a
// future migration adds.
const rtActivityColumns = "a.id, a.user_id, a.user_email, a.action, a.target_type, " +
	"a.target_name, a.details, a.ip_address, a.created_at, a.server_id, s.name AS server_name " +
	"FROM activity_logs a LEFT JOIN servers s ON s.id = a.server_id"

// rtActivityList is GET /api/activity — list activity logs (admin only).
func rtActivityList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	var params rtActivityActivityQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	limit := int64(50)
	if params.Limit != nil {
		limit = min(*params.Limit, 200)
	}
	offset := int64(0)
	if params.Offset != nil {
		offset = *params.Offset
	}

	var logs []rtActivityActivityLog
	var err error
	if params.Action != nil {
		// Category filtering ("site" matches "site.create", "site.delete").
		pattern := *params.Action + "%"
		logs, err = queryAll[rtActivityActivityLog](r.Context(), st.DB,
			fmt.Sprintf("SELECT %s WHERE a.action LIKE $1 ORDER BY a.created_at DESC LIMIT $2 OFFSET $3", rtActivityColumns),
			pattern, limit, offset)
	} else {
		logs, err = queryAll[rtActivityActivityLog](r.Context(), st.DB,
			fmt.Sprintf("SELECT %s ORDER BY a.created_at DESC LIMIT $1 OFFSET $2", rtActivityColumns),
			limit, offset)
	}
	if err != nil {
		return internalError("list activity", err)
	}
	writeJSON(w, http.StatusOK, logs)
	return nil
}
