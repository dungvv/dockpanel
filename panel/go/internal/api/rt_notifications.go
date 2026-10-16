package api

// routes/notifications.rs — the panel notification center (bell) API and
// its SSE stream.

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func rtNotificationsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/notifications", h(rtNotificationsList))
	r.Handle("GET /api/notifications/summary", h(rtNotificationsSummary))
	r.Handle("GET /api/notifications/unread-count", h(rtNotificationsUnreadCount))
	r.Handle("GET /api/notifications/stream", h(rtNotificationsStream))
	r.Handle("POST /api/notifications/{id}/read", h(rtNotificationsMarkRead))
	r.Handle("POST /api/notifications/read-all", h(rtNotificationsMarkAllRead))
	r.Handle("DELETE /api/notifications/read", h(rtNotificationsDeleteRead))
	r.Handle("DELETE /api/notifications/{id}", h(rtNotificationsDeleteOne))
}

type rtNotificationsNotificationRow struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	Title     string     `json:"title" db:"title"`
	Message   string     `json:"message" db:"message"`
	Severity  string     `json:"severity" db:"severity"`
	Category  string     `json:"category" db:"category"`
	Link      *string    `json:"link" db:"link"`
	ReadAt    *time.Time `json:"read_at" db:"read_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

// rtNotificationsListQuery: the handler once took none and the SQL ended in
// a bare LIMIT 50, leaving older rows unreachable while the badge counted
// unread without a limit — two numbers answering different questions.
type rtNotificationsListQuery struct {
	// Page size, clamped to 1..=200; absent means 50 (the old hardcoded limit).
	Limit *int64 `json:"limit"`
	// Keyset cursor: rows strictly older than this (keyset, not OFFSET,
	// because rows arrive at the head while you page). Parsed by hand —
	// decodeQuery has no timestamp support.
	Before *time.Time `json:"-"`
	// Exact category match, or absent for all.
	Category *string `json:"category"`
	// true restricts to unread.
	Unread *bool `json:"unread"`
}

// rtNotificationsList is GET /api/notifications — one page of the caller's
// notifications.
func rtNotificationsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var q rtNotificationsListQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	if vals, ok := r.URL.Query()["before"]; ok {
		t, err := time.Parse(time.RFC3339Nano, vals[0])
		if err != nil {
			return rejection(http.StatusBadRequest, fmt.Sprintf("Failed to deserialize query string: before: %v", err))
		}
		t = t.UTC()
		q.Before = &t
	}
	limit := int64(50)
	if q.Limit != nil {
		limit = min(max(*q.Limit, 1), 200)
	}

	// Every filter is bound; the optional ones are "$n IS NULL OR column =
	// $n" so the statement shape never changes. String-building a WHERE
	// clause would put a user-supplied category next to SQL.
	notifs, err := queryAll[rtNotificationsNotificationRow](r.Context(), st.DB,
		"SELECT id, title, message, severity, category, link, read_at, created_at "+
			"FROM panel_notifications "+
			"WHERE user_id = $1 "+
			"AND ($2::timestamptz IS NULL OR created_at < $2) "+
			"AND ($3::text IS NULL OR category = $3) "+
			"AND ($4::bool IS NOT TRUE OR read_at IS NULL) "+
			"ORDER BY created_at DESC LIMIT $5",
		claims.Sub, q.Before, q.Category, q.Unread, limit)
	if err != nil {
		return internalError("list notifications", err)
	}
	writeJSON(w, http.StatusOK, notifs)
	return nil
}

// rtNotificationsSummary is GET /api/notifications/summary. The page once
// derived "N unread" from its loaded rows while the bell used the server's
// COUNT, so the two could disagree; both read from here now.
func rtNotificationsSummary(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	tot, err := queryOne[Tup2[int64, int64]](r.Context(), st.DB,
		"SELECT COUNT(*), COUNT(*) FILTER (WHERE read_at IS NULL) FROM panel_notifications WHERE user_id = $1",
		claims.Sub)
	if err != nil {
		return internalError("notification summary", err)
	}
	cats, err := queryAll[Tup3[string, int64, int64]](r.Context(), st.DB,
		"SELECT category, COUNT(*), COUNT(*) FILTER (WHERE read_at IS NULL) FROM panel_notifications WHERE user_id = $1 GROUP BY category ORDER BY category",
		claims.Sub)
	if err != nil {
		return internalError("notification summary categories", err)
	}
	categories := make([]map[string]any, 0, len(cats))
	for _, c := range cats {
		categories = append(categories, map[string]any{"category": c.A, "total": c.B, "unread": c.C})
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": tot.A, "unread": tot.B, "categories": categories})
	return nil
}

// rtNotificationsUnreadCount is GET /api/notifications/unread-count.
func rtNotificationsUnreadCount(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	count, err := queryScalar[int64](r.Context(), st.DB,
		"SELECT COUNT(*) FROM panel_notifications WHERE user_id = $1 AND read_at IS NULL", claims.Sub)
	if err != nil {
		return internalError("unread count", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": count})
	return nil
}

// rtNotificationsMarkRead is POST /api/notifications/{id}/read.
func rtNotificationsMarkRead(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB,
		"UPDATE panel_notifications SET read_at = NOW() WHERE id = $1 AND user_id = $2 AND read_at IS NULL", id, claims.Sub)
	if err != nil {
		return internalError("mark read", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Notification not found or already read")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtNotificationsMarkAllRead is POST /api/notifications/read-all.
func rtNotificationsMarkAllRead(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if _, err := execSQL(r.Context(), st.DB,
		"UPDATE panel_notifications SET read_at = NOW() WHERE user_id = $1 AND read_at IS NULL", claims.Sub); err != nil {
		return internalError("mark all read", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtNotificationsDeleteOne is DELETE /api/notifications/{id}. There was no
// way to remove a notification at all (only the 30-day retention sweep).
func rtNotificationsDeleteOne(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM panel_notifications WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("delete notification", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Notification not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtNotificationsDeleteRead is DELETE /api/notifications/read — clear what
// was already read. read_at IS NOT NULL on purpose: "clear" must never
// discard something unseen. user_id = $1: each recipient of a broadcast has
// their own row, so one admin cannot clear another's copy.
func rtNotificationsDeleteRead(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM panel_notifications WHERE user_id = $1 AND read_at IS NOT NULL", claims.Sub)
	if err != nil {
		return internalError("clear read notifications", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": n})
	return nil
}

// rtNotificationsKeepAlive is axum's KeepAlive interval.
var rtNotificationsKeepAlive = 30 * time.Second

// rtNotificationsStream is GET /api/notifications/stream — SSE for real-time
// delivery, filtered to the caller's own events. Notif lives for the whole
// process, so the stream also ends on Shutdown — otherwise every open panel
// tab blocks the graceful drain.
func rtNotificationsStream(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	rx, unsub := st.Notif.Subscribe()
	defer unsub()

	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	ka := time.NewTicker(rtNotificationsKeepAlive)
	defer ka.Stop()
	for {
		select {
		case <-r.Context().Done():
			return nil
		case <-st.Shutdown.Done():
			return nil
		case <-ka.C:
			if _, err := io.WriteString(w, ":keepalive\n\n"); err != nil {
				return nil
			}
		case n, ok := <-rx:
			if !ok {
				return nil
			}
			if n.UserID != claims.Sub {
				continue // not for this user
			}
			if _, err := io.WriteString(w, rtNotificationsSSEData(n.Payload)); err != nil {
				return nil
			}
		}
		if err := rc.Flush(); err != nil {
			return nil
		}
		// axum resets the keep-alive timer on every event.
		ka.Reset(rtNotificationsKeepAlive)
	}
}

// rtNotificationsSSEData frames a payload as an SSE data event (axum
// Event::data). Payloads are json.Marshal output, which never contains a raw
// newline, so one data: line is the whole event.
func rtNotificationsSSEData(payload string) string { return "data: " + payload + "\n\n" }
