package api

// Port of panel/backend/src/routes/logs.rs.

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func rtLogsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/sites/{id}/logs", h(rtLogsSiteLogs))
	r.Handle("GET /api/sites/{id}/logs/search", h(rtLogsSearchSiteLogs))
	r.Handle("GET /api/system/processes", h(rtLogsProcesses))
	r.Handle("GET /api/system/network", h(rtLogsNetwork))
	r.Handle("GET /api/logs", h(rtLogsSystemLogs))
	r.Handle("GET /api/logs/search", h(rtLogsSearchSystemLogs))
	r.Handle("GET /api/logs/stream/token", h(rtLogsStreamToken))
	r.Handle("GET /api/logs/stats", h(rtLogsLogStats))
	r.Handle("GET /api/logs/docker", h(rtLogsDockerLogContainers))
	r.Handle("GET /api/logs/docker/{container}", h(rtLogsDockerLogView))
	r.Handle("GET /api/logs/service/{service}", h(rtLogsServiceLogs))
	r.Handle("GET /api/logs/sizes", h(rtLogsLogSizes))
	r.Handle("POST /api/logs/truncate", h(rtLogsTruncateLog))
	r.Handle("POST /api/logs/check-errors", h(rtLogsCheckErrors))
}

// rtLogsURLEncode is the urlencoding crate's encode: everything but
// A-Za-z0-9 - . _ ~ is percent-encoded, space as %20 (not +). Shared by the
// rt_sites/rt_files/rt_logs ports.
func rtLogsURLEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// rtLogsQueryMap is Query<HashMap<String, String>>: the last value wins.
func rtLogsQueryMap(r *http.Request) map[string]string {
	m := map[string]string{}
	for k, v := range r.URL.Query() {
		m[k] = v[len(v)-1]
	}
	return m
}

type rtLogsLogQuery struct {
	LogType *string `json:"type"`
	Lines   *uint32 `json:"lines"`
	Filter  *string `json:"filter"`
}

type rtLogsSearchQuery struct {
	LogType *string `json:"type"`
	Pattern *string `json:"pattern"`
	Max     *uint32 `json:"max"`
}

type rtLogsStreamTokenQuery struct {
	SiteID  *string `json:"site_id"`
	LogType *string `json:"type"`
}

var rtLogsSystemTypes = []string{"nginx_access", "nginx_error", "syslog", "auth", "php_fpm"}

func rtLogsOr[T any](p *T, def T) T {
	if p != nil {
		return *p
	}
	return def
}

// rtLogsSystemLogs is GET /api/logs — system-wide logs (admin only).
func rtLogsSystemLogs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var q rtLogsLogQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	logType := rtLogsOr(q.LogType, "nginx_access")
	if !slices.Contains(rtLogsSystemTypes, logType) {
		return apiErr(http.StatusBadRequest, "Invalid log type")
	}
	lines := min(max(rtLogsOr(q.Lines, 100), 1), 1000)
	path := fmt.Sprintf("/logs?type=%s&lines=%d", logType, lines)
	if q.Filter != nil {
		path += "&filter=" + rtLogsURLEncode(*q.Filter)
	}
	res, err := agent.Get(r.Context(), path)
	if err != nil {
		return agentError("System logs", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtLogsSiteLogs is GET /api/sites/{id}/logs.
func rtLogsSiteLogs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var q rtLogsLogQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	// Asking the wrong host for a site's logs does not fail: that machine has
	// no vhost by this name, answers with nothing, and nothing is exactly what a
	// quiet site looks like. The row names the host.
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	logType := rtLogsOr(q.LogType, "access")
	if logType != "access" && logType != "error" {
		return apiErr(http.StatusBadRequest, "Invalid site log type")
	}
	lines := min(max(rtLogsOr(q.Lines, 100), 1), 1000)
	path := fmt.Sprintf("/logs/%s?type=%s&lines=%d", domain, logType, lines)
	if q.Filter != nil {
		path += "&filter=" + rtLogsURLEncode(*q.Filter)
	}
	res, err := agent.Get(r.Context(), path)
	if err != nil {
		return agentError("Site logs", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtLogsSearchSystemLogs is GET /api/logs/search (admin only).
func rtLogsSearchSystemLogs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var q rtLogsSearchQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	logType := rtLogsOr(q.LogType, "nginx_access")
	if !slices.Contains(rtLogsSystemTypes, logType) {
		return apiErr(http.StatusBadRequest, "Invalid log type")
	}
	pattern := rtLogsOr(q.Pattern, "")
	if pattern == "" {
		return apiErr(http.StatusBadRequest, "Pattern is required")
	}
	maxN := min(max(rtLogsOr(q.Max, 500), 1), 5000)
	res, err := agent.Get(r.Context(), fmt.Sprintf("/logs/search?type=%s&pattern=%s&max=%d", logType, rtLogsURLEncode(pattern), maxN))
	if err != nil {
		return agentError("System log search", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtLogsSearchSiteLogs is GET /api/sites/{id}/logs/search.
func rtLogsSearchSiteLogs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var q rtLogsSearchQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	// A search is the worse of the two readers to misdispatch: "no matching
	// lines" is a confident negative answer.
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	var fullType string
	switch rtLogsOr(q.LogType, "access") {
	case "access":
		fullType = "nginx_access:" + domain
	case "error":
		fullType = "nginx_error:" + domain
	default:
		return apiErr(http.StatusBadRequest, "Invalid site log type")
	}
	pattern := rtLogsOr(q.Pattern, "")
	if pattern == "" {
		return apiErr(http.StatusBadRequest, "Pattern is required")
	}
	maxN := min(max(rtLogsOr(q.Max, 500), 1), 5000)
	res, err := agent.Get(r.Context(), fmt.Sprintf("/logs/search?type=%s&pattern=%s&max=%d", rtLogsURLEncode(fullType), rtLogsURLEncode(pattern), maxN))
	if err != nil {
		return agentError("Site log search", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtLogsStreamToken is GET /api/logs/stream/token — a short-lived JWT for
// WebSocket log streaming.
//
// The ticket's `scope` (a site's domain, or `@system` for the admin-only host
// logs) rides INSIDE the signature, as the terminal ticket's does. The agent
// used to read the scope from `?domain=` and the type from `?type=`, both
// browser-controlled, so a site-scoped ticket dialled with `type=auth` and no
// domain streamed /var/log/auth.log. `@system` contains an `@`, which the
// agent's domain validation rejects, so it cannot collide with a real domain.
func rtLogsStreamToken(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var q rtLogsStreamTokenQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	// Answer here rather than minting a ticket the receiving agent must reject.
	if err := requireLocalAgentScope(r.Context(), st, serverID, "Live log streaming"); err != nil {
		return err
	}
	// System-level streaming requires admin.
	if q.SiteID == nil && c.Role != "admin" {
		return apiErr(http.StatusForbidden, "Admin access required for system log streaming")
	}

	var domain *string
	if q.SiteID != nil {
		siteID, perr := uuid.Parse(*q.SiteID)
		if perr != nil {
			return apiErr(http.StatusBadRequest, "Invalid site_id")
		}
		domain, err = queryScalarOpt[string](r.Context(), st.DB, "SELECT s.domain FROM sites s WHERE "+SiteCallerPredicate, siteID, c.Sub)
		if err != nil {
			return internalError("stream token", err)
		}
		if domain == nil {
			return apiErr(http.StatusNotFound, "Site not found")
		}
	}

	// The scope is the SIGNED decision, not `?domain=`/`?type=`.
	scope := "@system"
	if domain != nil {
		scope = *domain
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":     c.Email,
		"purpose": "log_stream",
		"exp":     time.Now().Add(60 * time.Second).Unix(),
		"scope":   scope,
	}).SignedString([]byte(agent.Token()))
	if err != nil {
		return internalError("stream token", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":  token,
		"domain": domain,
		"type":   rtLogsOr(q.LogType, "nginx_access"),
	})
	return nil
}

// rtLogsLogStats is GET /api/logs/stats — log aggregation stats for the
// server in scope (admin only).
//
// With `?domain=` it used to be neither authorised nor resolved: the
// parameter went straight into the agent path. A parameter is now a lookup
// key and nothing else; the domain that reaches the agent is the one read back
// off the row. The row read is pinned to the server in scope: a domain is only
// unique PER SERVER, and these stats grep one machine's nginx logs, so a site
// that lives elsewhere has no answer here — refused rather than answered with
// the zeroes a quiet site would produce.
func rtLogsLogStats(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	params := rtLogsQueryMap(r)
	domain := ""
	if requested, ok := params["domain"]; ok {
		id, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB, "SELECT id FROM sites WHERE domain = $1 AND server_id = $2", requested, serverID)
		if err != nil {
			return internalError("log stats", err)
		}
		// Identity first, then permission — the permission half is the one
		// shared decision, not a copy of it living here.
		if id == nil {
			return apiErr(http.StatusNotFound, "Site not found")
		}
		resolved, err := siteDomainForCaller(r.Context(), st, *id, c)
		if err != nil {
			return err
		}
		domain = "?domain=" + resolved
	}
	res, err := agent.Get(r.Context(), "/logs/stats"+domain)
	if err != nil {
		return agentError("Log stats", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtLogsAdminPassthrough serves the admin-only GET proxies.
func rtLogsAdminPassthrough(st *AppState, w http.ResponseWriter, r *http.Request, path, ctxMsg string) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), path)
	if err != nil {
		return agentError(ctxMsg, err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtLogsDockerLogContainers is GET /api/logs/docker (admin only).
func rtLogsDockerLogContainers(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtLogsAdminPassthrough(st, w, r, "/logs/docker", "Docker logs")
}

func rtLogsValidUnitName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !isASCIIAlnum(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// rtLogsNamedLogs serves the docker/service log views.
func rtLogsNamedLogs(st *AppState, w http.ResponseWriter, r *http.Request, param, invalid, prefix, defLines string) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	name := r.PathValue(param)
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	params := rtLogsQueryMap(r)
	if !rtLogsValidUnitName(name) {
		return apiErr(http.StatusBadRequest, invalid)
	}
	lines, ok := params["lines"]
	if !ok {
		lines = defLines
	}
	ctxMsg := "Docker logs"
	if param == "service" {
		ctxMsg = "Service logs"
	}
	res, err := agent.Get(r.Context(), fmt.Sprintf("%s/%s?lines=%s", prefix, name, lines))
	if err != nil {
		return agentError(ctxMsg, err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtLogsDockerLogView is GET /api/logs/docker/{container} (admin only).
func rtLogsDockerLogView(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtLogsNamedLogs(st, w, r, "container", "Invalid container name", "/logs/docker", "200")
}

// rtLogsServiceLogs is GET /api/logs/service/{service} (admin only).
func rtLogsServiceLogs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtLogsNamedLogs(st, w, r, "service", "Invalid service name", "/logs/service", "100")
}

// rtLogsLogSizes is GET /api/logs/sizes (admin only).
func rtLogsLogSizes(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtLogsAdminPassthrough(st, w, r, "/logs/sizes", "Log sizes")
}

// rtLogsTruncateLog is POST /api/logs/truncate (admin only).
func rtLogsTruncateLog(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body json.RawMessage
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if _, err := agent.Post(r.Context(), "/logs/truncate", body); err != nil {
		return agentError("Truncate", err)
	}
	ip := clientIP(r)
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "logs.truncate", nil, nil, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(r.Context(), st.DB, "logs.truncate", &c.Email, ip, nil, nil, nil, nil, "warning", c.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtLogsCheckErrors is POST /api/logs/check-errors — scan recent logs for
// error patterns (admin only).
func rtLogsCheckErrors(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	// Recent nginx error count.
	stats, _ := agent.Get(r.Context(), "/logs/stats")
	errors5xx, ok := jsonU64(jsonGet(stats, "errors_5xx"))
	if !ok {
		errors5xx = 0
	}
	total, ok := jsonU64(jsonGet(stats, "requests_total"))
	if !ok {
		total = 1
	}
	total = max(total, 1)
	rate := math.Round(float64(errors5xx)/float64(total)*100.0*10.0) / 10.0
	status := "ok"
	if rate > 5.0 && errors5xx > 10 {
		status = "warning"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"error_5xx":          errors5xx,
		"total_requests":     total,
		"error_rate_percent": rtLogsF64(rate),
		"threshold":          "5% error rate with >10 errors",
		"status":             status,
	})
	return nil
}

// rtLogsF64 marshals like serde_json's f64: a whole number keeps its ".0".
type rtLogsF64 float64

func (f rtLogsF64) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(float64(f))
	if err == nil && !strings.ContainsAny(string(b), ".eE") {
		b = append(b, ".0"...)
	}
	return b, err
}

// rtLogsProcesses is GET /api/system/processes (admin only).
func rtLogsProcesses(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtLogsAdminPassthrough(st, w, r, "/system/processes", "System processes")
}

// rtLogsNetwork is GET /api/system/network (admin only).
func rtLogsNetwork(st *AppState, w http.ResponseWriter, r *http.Request) error {
	return rtLogsAdminPassthrough(st, w, r, "/system/network", "Network stats")
}
