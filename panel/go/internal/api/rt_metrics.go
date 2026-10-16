package api

// Port of panel/backend/src/routes/metrics.rs — per-server performance history.

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

func rtMetricsRegister(r *Router) {
	r.Handle("GET /api/servers/{id}/metrics", func(w http.ResponseWriter, req *http.Request) error {
		return rtMetricsServerMetrics(r.St, w, req)
	})
}

type rtMetricsMetricsQuery struct {
	MetricType *string `json:"metric_type"`
	Hours      *int32  `json:"hours"`
}

type rtMetricsMetricPoint struct {
	Value      float64   `json:"value" db:"value"`
	RecordedAt time.Time `json:"recorded_at" db:"recorded_at"`
}

// rtMetricsServerMetrics: GET /api/servers/{id}/metrics.
func rtMetricsServerMetrics(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var params rtMetricsMetricsQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	// Verify ownership
	exists, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB, "SELECT id FROM servers WHERE id = $1 AND user_id = $2", serverID, c.Sub)
	if err != nil {
		return internalError("server metrics", err)
	}
	if exists == nil {
		return apiErr(http.StatusNotFound, "Server not found")
	}

	hours := int32(24)
	if params.Hours != nil {
		hours = *params.Hours
	}
	hours = max(min(hours, 168), 1)
	metricType := "cpu"
	if params.MetricType != nil {
		metricType = *params.MetricType
	}
	hoursStr := strconv.Itoa(int(hours))

	points, err := queryAll[rtMetricsMetricPoint](r.Context(), st.DB,
		"SELECT value, recorded_at FROM metrics "+
			"WHERE server_id = $1 AND metric_type = $2 "+
			"AND recorded_at > NOW() - ($3 || ' hours')::interval "+
			"ORDER BY recorded_at ASC", serverID, metricType, hoursStr)
	if err != nil {
		return internalError("server metrics", err)
	}

	// Summary stats. (With no rows AVG is NULL, which does not decode into
	// f64 — the Rust handler answered 500 there too; kept as-is.)
	stats, err := queryOpt[Tup3[float64, float64, float64]](r.Context(), st.DB,
		"SELECT AVG(value), MIN(value), MAX(value) FROM metrics "+
			"WHERE server_id = $1 AND metric_type = $2 "+
			"AND recorded_at > NOW() - ($3 || ' hours')::interval", serverID, metricType, hoursStr)
	if err != nil {
		return internalError("server metrics", err)
	}
	var s Tup3[float64, float64, float64]
	if stats != nil {
		s = *stats
	}
	round1 := func(v float64) float64 { return math.Round(v*10) / 10 }
	writeJSON(w, http.StatusOK, map[string]any{
		"metric_type": metricType,
		"hours":       hours,
		"points":      points,
		"summary": map[string]any{
			"avg":   round1(s.A),
			"min":   round1(s.B),
			"max":   round1(s.C),
			"count": len(points),
		},
	})
	return nil
}
