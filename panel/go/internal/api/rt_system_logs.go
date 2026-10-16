package api

// Port of panel/backend/src/routes/system_logs.rs.

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtSystemLogsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/system-logs", h(rtSystemLogsList))
	r.Handle("GET /api/system-logs/count", h(rtSystemLogsCount))
}

type rtSystemLogsLogParams struct {
	Level  *string `json:"level"`
	Source *string `json:"source"`
	Since  *string `json:"since"` // "1h", "24h", "7d", "30d"
	Limit  *int64  `json:"limit"`
	Offset *int64  `json:"offset"`
}

type rtSystemLogsSystemLog struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Level     string    `json:"level" db:"level"`
	Source    string    `json:"source" db:"source"`
	Message   string    `json:"message" db:"message"`
	Details   *string   `json:"details" db:"details"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// rtSystemLogsParseSince maps "1h", "24h", "7d", "30d" to a PostgreSQL
// interval string ("" = unknown).
func rtSystemLogsParseSince(since string) string {
	switch since {
	case "1h":
		return "1 hour"
	case "24h":
		return "24 hours"
	case "7d":
		return "7 days"
	case "30d":
		return "30 days"
	}
	return ""
}

// rtSystemLogsLevels are the levels this API can filter and count.
var rtSystemLogsLevels = []string{"error", "warning", "info"}

// rtSystemLogsMetricSource is a source that writes a METRIC into this table
// rather than a log line: backup_policy_executor inserts one row per 60s tick
// and backup_orchestrator reads them back as a 30-day series, so the rows must
// keep being written. But on this panel they outnumbered genuine entries
// 43,272 to 10, which put every real entry older than ~50 minutes below the
// fold. So the default listing hides them; the source is still SELECTABLE —
// a filter the operator cannot switch off is the same defect pointed the
// other way.
const rtSystemLogsMetricSource = "backup_storage"

// rtSystemLogsHideMetric is the condition hiding the metric rows, derived from
// the constant so the name the listing hides and the dropdown offers cannot
// drift. ⚠ A NARROWING: one that goes too far fails silently.
// tests/system-logs-scope-pin-e2e.sh pins both directions.
func rtSystemLogsHideMetric() string {
	return fmt.Sprintf("source <> '%s'", rtSystemLogsMetricSource)
}

func rtSystemLogsUnknownRange(since string) error {
	return apiErr(http.StatusBadRequest, fmt.Sprintf("Unknown range '%s' — expected 1h, 24h, 7d or 30d", since))
}

// rtSystemLogsList is GET /api/system-logs (admin only).
func rtSystemLogsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	var p rtSystemLogsLogParams
	if err := decodeQuery(r, &p); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}

	limit := int64(50)
	if p.Limit != nil {
		limit = *p.Limit
	}
	limit = min(max(limit, 1), 200)
	offset := int64(0)
	if p.Offset != nil {
		offset = max(*p.Offset, 0)
	}

	// ⚠ An unrecognised filter value is REFUSED, not ignored. Falling through
	// to "push no condition" returns the UNFILTERED list, indistinguishable
	// from "your filter matched a great many rows".
	var conds []string
	var args []any
	if p.Level != nil && *p.Level != "" {
		if !slices.Contains(rtSystemLogsLevels, *p.Level) {
			return apiErr(http.StatusBadRequest, fmt.Sprintf("Unknown level '%s' — expected one of %s", *p.Level, strings.Join(rtSystemLogsLevels, ", ")))
		}
		args = append(args, *p.Level)
		conds = append(conds, fmt.Sprintf("level = $%d", len(args)))
	}
	if p.Source != nil && *p.Source != "" {
		args = append(args, *p.Source)
		conds = append(conds, fmt.Sprintf("source = $%d", len(args)))
	} else {
		// No source named — hide the metric rows.
		conds = append(conds, rtSystemLogsHideMetric())
	}
	if p.Since != nil && *p.Since != "" {
		interval := rtSystemLogsParseSince(*p.Since)
		if interval == "" {
			return rtSystemLogsUnknownRange(*p.Since)
		}
		conds = append(conds, fmt.Sprintf("created_at > NOW() - INTERVAL '%s'", interval))
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	sql := fmt.Sprintf("SELECT id, level, source, message, details, created_at "+
		"FROM system_logs %s "+
		"ORDER BY created_at DESC "+
		"LIMIT $%d OFFSET $%d", where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	// ⚠ This used to swallow a DB failure as an empty list — "there are no
	// logs" and "we could not read the logs" became the same screen.
	logs, err := queryAll[rtSystemLogsSystemLog](r.Context(), st.DB, sql, args...)
	if err != nil {
		return internalError("list system logs", err)
	}
	writeJSON(w, http.StatusOK, logs)
	return nil
}

type rtSystemLogsCountParams struct {
	Since *string `json:"since"`
}

type rtSystemLogsLogCounts struct {
	Error   int64 `json:"error"`
	Warning int64 `json:"warning"`
	Info    int64 `json:"info"`
}

// rtSystemLogsCount is GET /api/system-logs/count (admin only).
func rtSystemLogsCount(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	var p rtSystemLogsCountParams
	if err := decodeQuery(r, &p); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	interval := "24 hours"
	if p.Since != nil && *p.Since != "" {
		if interval = rtSystemLogsParseSince(*p.Since); interval == "" {
			return rtSystemLogsUnknownRange(*p.Since)
		}
	}

	// The tiles count the same population the default listing shows, or the
	// "Info" tile reports one metric sample per minute and reads as activity.
	rows, err := queryAll[Tup2[string, int64]](r.Context(), st.DB, fmt.Sprintf(
		"SELECT level, COUNT(*) FROM system_logs "+
			"WHERE created_at > NOW() - INTERVAL '%s' AND %s "+
			"GROUP BY level", interval, rtSystemLogsHideMetric()))
	if err != nil {
		return internalError("count system logs", err)
	}
	var counts rtSystemLogsLogCounts
	for _, row := range rows {
		switch row.A {
		case "error":
			counts.Error = row.B
		case "warning":
			counts.Warning = row.B
		case "info":
			counts.Info = row.B
		}
	}
	writeJSON(w, http.StatusOK, counts)
	return nil
}
