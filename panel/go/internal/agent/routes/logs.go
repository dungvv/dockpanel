package routes

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/golang-jwt/jwt/v5"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// logsActiveStreams caps concurrent log stream WebSocket connections.
var logsActiveStreams atomic.Int64

const logsMaxStreams = 10

func registerLogs(r *Router) {
	r.Handle("GET /logs", logsGetLogs)
	r.Handle("GET /logs/search", logsSearchLogs)
	r.Handle("GET /logs/stats", logsLogStats)
	r.Handle("GET /logs/docker", logsDockerContainers)
	r.Handle("GET /logs/docker/{container}", logsDockerLogs)
	r.Handle("GET /logs/service/{service}", logsServiceLogs)
	r.Handle("GET /logs/sizes", logsLogSizes)
	r.Handle("POST /logs/truncate", logsTruncateLog)
	r.Handle("GET /logs/{domain}", logsGetSiteLogs)
	// Outside auth middleware: validates its own JWT ticket via ?token=.
	r.HandlePublic("GET /logs/stream", func(w http.ResponseWriter, req *http.Request) {
		logsStreamHandler(r.State, w, req)
	})
}

// logsQueryOpt mirrors axum Query<Option<String>>: absent → (nil, true);
// a repeated key is a deserialize error (serde_urlencoded "duplicate field").
func logsQueryOpt(w http.ResponseWriter, r *http.Request, key string) (*string, bool) {
	vals := r.URL.Query()[key]
	switch len(vals) {
	case 0:
		return nil, true
	case 1:
		return &vals[0], true
	}
	http.Error(w, "Failed to deserialize query string: duplicate field `"+key+"`", http.StatusBadRequest)
	return nil, false
}

// logsParseUsize mirrors Rust usize::from_str (one optional leading '+').
func logsParseUsize(s string) (int, bool) {
	// ParseUint itself rejects a second sign, so "++5"/"+-5" still fail.
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "+"), 10, 63)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// logsQueryUsize mirrors axum Query<Option<usize>>: a malformed value is a
// 400 rejection, not a silent default.
func logsQueryUsize(w http.ResponseWriter, r *http.Request, key string, def int) (int, bool) {
	v, ok := logsQueryOpt(w, r, key)
	if !ok {
		return 0, false
	}
	if v == nil {
		return def, true
	}
	n, ok := logsParseUsize(*v)
	if !ok {
		http.Error(w, "Failed to deserialize query string: "+key+": invalid digit found in string", http.StatusBadRequest)
		return 0, false
	}
	return n, true
}

// logsQueryStr returns the query value or def when absent ("" stays "").
func logsQueryStr(w http.ResponseWriter, r *http.Request, key, def string) (string, bool) {
	v, ok := logsQueryOpt(w, r, key)
	if !ok {
		return "", false
	}
	if v == nil {
		return def, true
	}
	return *v, true
}

// logsGetLogs: GET /logs?type=nginx_access&lines=100&filter=404
func logsGetLogs(w http.ResponseWriter, r *http.Request) {
	logType, ok := logsQueryStr(w, r, "type", "syslog")
	if !ok {
		return
	}
	lines, ok := logsQueryUsize(w, r, "lines", 100)
	if !ok {
		return
	}
	filter, ok := logsQueryStr(w, r, "filter", "")
	if !ok {
		return
	}
	res, err := services.LogsReadLog(r.Context(), logType, lines, filter)
	if err != nil {
		e := err.Error()
		if strings.Contains(e, "not found") || strings.Contains(e, "Unknown log type") {
			writeErr(w, http.StatusNotFound, e)
		} else {
			writeErr(w, http.StatusInternalServerError, e)
		}
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// logsGetSiteLogs: GET /logs/{domain}?type=access&lines=100&filter=
func logsGetSiteLogs(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	shortType, ok := logsQueryStr(w, r, "type", "access")
	if !ok {
		return
	}
	lines, ok := logsQueryUsize(w, r, "lines", 100)
	if !ok {
		return
	}
	filter, ok := logsQueryStr(w, r, "filter", "")
	if !ok {
		return
	}

	var logType string
	switch shortType {
	case "access":
		logType = "nginx_access:" + domain
	case "error":
		logType = "nginx_error:" + domain
	default:
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("Invalid site log type: %s. Use 'access' or 'error'", shortType))
		return
	}

	res, err := services.LogsReadLog(r.Context(), logType, lines, filter)
	if err != nil {
		e := err.Error()
		if strings.Contains(e, "not found") || strings.Contains(e, "traversal") || strings.Contains(e, "Invalid domain") {
			writeErr(w, http.StatusBadRequest, e)
		} else {
			writeErr(w, http.StatusInternalServerError, e)
		}
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// logsSearchLogs: GET /logs/search?type=nginx_access&pattern=404&max=500
func logsSearchLogs(w http.ResponseWriter, r *http.Request) {
	logType, ok := logsQueryStr(w, r, "type", "nginx_access")
	if !ok {
		return
	}
	pattern, ok := logsQueryStr(w, r, "pattern", "")
	if !ok {
		return
	}
	maxN, ok := logsQueryUsize(w, r, "max", 500)
	if !ok {
		return
	}
	if pattern == "" {
		writeErr(w, http.StatusBadRequest, "Pattern is required")
		return
	}
	res, err := services.LogsSearchLog(r.Context(), logType, pattern, maxN)
	if err != nil {
		if e := err.Error(); strings.Contains(e, "not found") {
			writeErr(w, http.StatusNotFound, e)
		} else {
			writeErr(w, http.StatusUnprocessableEntity, e)
		}
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// logsStreamTicket is the signed log-stream ticket.
type logsStreamTicket struct {
	Sub     string
	Purpose string
	// Scope is the logs this ticket authorises: a site's domain, or "@system"
	// for the admin-only host logs. nil means a pre-fix panel that signed no
	// scope. This is the SIGNED decision the agent trusts instead of the
	// browser's ?domain=/?type= — trusting those let a site-scoped ticket
	// stream /var/log/auth.log by asking for type=auth with the domain omitted.
	Scope *string
}

// logsJWTLeeway is jsonwebtoken's default Validation leeway.
const logsJWTLeeway = 60

// logsValidateTicket mirrors jsonwebtoken 10 decode::<StreamTicket> with
// Validation::new(HS256), required spec claims {exp, sub}, validate_exp, and
// default settings: 60s leeway, nbf NOT checked, a token carrying `aud` is
// rejected (no audience configured), exp must be an unsigned integer. Then
// purpose must equal "log_stream". The key is the CURRENT agent token only.
func logsValidateTicket(tokenStr, secret string, now time.Time) (*logsStreamTicket, bool) {
	claims := jwt.MapClaims{}
	_, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithoutClaimsValidation(),
		jwt.WithJSONNumber(),
	).ParseWithClaims(tokenStr, claims, func(*jwt.Token) (any, error) { return []byte(secret), nil })
	if err != nil {
		return nil, false
	}
	if _, has := claims["aud"]; has {
		return nil, false
	}
	expN, ok := claims["exp"].(json.Number)
	if !ok {
		return nil, false
	}
	exp, err := strconv.ParseUint(expN.String(), 10, 64)
	if err != nil || int64(exp) < now.Unix()-logsJWTLeeway {
		return nil, false
	}
	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, false
	}
	purpose, ok := claims["purpose"].(string)
	if !ok || purpose != "log_stream" {
		return nil, false
	}
	t := &logsStreamTicket{Sub: sub, Purpose: purpose}
	switch s := claims["scope"].(type) {
	case nil:
	case string:
		t.Scope = &s
	default:
		return nil, false
	}
	return t, true
}

// logsResolveStreamType picks the log type a validated ticket may stream.
// Returns ("", false) when a site-scoped ticket asks for a non-site type.
func logsResolveStreamType(t *logsStreamTicket, requestedType string, domain *string) (string, bool) {
	// The log this stream serves is the SIGNED scope, never the ?domain=/?type=
	// params. A site ticket is pinned to its own domain AND to that site's own
	// log types, so it can never reach the host logs; the panel only mints
	// @system (host logs) for an admin. Reading these from the params was the
	// escalation: a site owner streamed /var/log/auth.log by asking for
	// type=auth with the domain omitted.
	if t.Scope == nil {
		// Legacy ticket from a pre-fix panel: no scope was signed. Fall back
		// to the old param-driven behaviour so an agent upgraded ahead of its
		// panel keeps working, and log it so an unscoped stream is visible.
		slog.Warn(fmt.Sprintf("Log stream ticket for %s carries no scope (pre-fix panel); "+
			"trusting ?domain=/?type= — upgrade the panel to bind the scope", t.Sub))
		if domain == nil {
			return requestedType, true
		}
		switch requestedType {
		case "access":
			return "nginx_access:" + *domain, true
		case "error":
			return "nginx_error:" + *domain, true
		}
		return requestedType, true
	}
	scope := *t.Scope
	if scope == "@system" {
		// Admin system ticket: the host logs. No domain to pin; honour the
		// requested system type and let LogsResolveLogPath allow-list it.
		return requestedType, true
	}
	// Site ticket: only this domain's own logs, and only site log types.
	switch requestedType {
	case "access":
		return "nginx_access:" + scope, true
	case "error":
		return "nginx_error:" + scope, true
	case "php_error", "php":
		return "php_error:" + scope, true
	}
	return "", false
}

// logsStreamHandler: GET /logs/stream — WebSocket endpoint for real-time log
// tailing. Auth via ?token= (short-lived JWT), ?type= for log type, ?domain=
// for site-specific (legacy tickets only).
func logsStreamHandler(st *State, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// axum's WebSocketUpgrade extractor rejects a non-upgrade request before
	// the handler body runs (so before the token check).
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "Connection header did not include 'upgrade'", http.StatusBadRequest)
		return
	}

	var ticket *logsStreamTicket
	if q.Has("token") {
		ticket, _ = logsValidateTicket(q.Get("token"), st.Token(), time.Now())
	}
	if ticket == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	requested := "nginx_access"
	if q.Has("type") {
		requested = q.Get("type")
	}
	var domain *string
	if q.Has("domain") {
		d := q.Get("domain")
		domain = &d
	}
	logType, ok := logsResolveStreamType(ticket, requested, domain)
	if !ok {
		http.Error(w, "Log type not permitted for a site-scoped stream", http.StatusForbidden)
		return
	}

	// Enforce concurrent stream limit
	if logsActiveStreams.Load() >= logsMaxStreams {
		http.Error(w, "Too many active log streams", http.StatusTooManyRequests)
		return
	}

	path, err := services.LogsResolveLogPath(logType)
	if err != nil {
		http.Error(w, "Invalid log type", http.StatusBadRequest)
		return
	}

	// InsecureSkipVerify disables coder/websocket's Origin check: axum does
	// none, and the browser's Origin is the panel host, not the agent's. Auth
	// is the signed ticket above.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	logsHandleStream(conn, path)
}

func logsHandleStream(conn *websocket.Conn, path string) {
	logsActiveStreams.Add(1)
	defer logsActiveStreams.Add(-1)
	defer conn.CloseNow()

	// Cancelled when the client goes away → kills tail (Rust kill_on_drop).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start tail -f with last 50 lines so the user sees recent context
	cmd := safecmd.Command(ctx, "tail", "-f", "-n", "50", path)
	stdout, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		_ = conn.Write(ctx, websocket.MessageText, []byte(fmt.Sprintf("Error: %v", err)))
		return
	}
	defer func() { cancel(); _ = cmd.Wait() }()

	// Client reader: coder/websocket answers pings itself while Read runs;
	// a close frame or a dead socket ends the stream.
	go func() {
		defer cancel()
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	rd := bufio.NewReader(stdout)
	for {
		line, err := rd.ReadString('\n')
		if line != "" {
			// Rust lines(): strip "\n" / "\r\n"; invalid UTF-8 ends the stream.
			if strings.HasSuffix(line, "\n") {
				line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
			}
			if !utf8.ValidString(line) {
				return
			}
			if conn.Write(ctx, websocket.MessageText, []byte(line)) != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// logsRound1 mirrors (x * 10.0).round() / 10.0 on MiB.
func logsRound1(size int64) float64 {
	return math.Round(float64(size)/1024/1024*10) / 10
}

type logsURLCount struct {
	URL   string `json:"url"`
	Count uint32 `json:"count"`
}

// logsComputeStats aggregates nginx access log lines.
func logsComputeStats(lines []string) map[string]any {
	statusMap := map[string]uint32{}
	urlMap := map[string]uint32{}
	errorsByHour := map[string]uint32{}
	var total uint32

	for _, line := range lines {
		if line == "" {
			continue
		}
		total++

		// Extract status code: after "HTTP/x.x" STATUS
		if parts := strings.Split(line, "\" "); len(parts) > 1 {
			status := ""
			if f := strings.Fields(parts[1]); len(f) > 0 {
				status = f[0]
			}
			statusMap[status]++

			// Track 5xx errors by hour
			if strings.HasPrefix(status, "5") {
				// Extract hour from log date [18/Mar/2026:14:30:00
				if dp := strings.Split(line, "["); len(dp) > 1 {
					if tp := strings.Split(dp[1], ":"); len(tp) > 1 {
						errorsByHour[tp[1]+":00"]++
					}
				}
			}
		}

		// Extract URL path
		if rl := strings.Split(line, "\""); len(rl) > 1 {
			if parts := strings.Fields(rl[1]); len(parts) > 1 {
				clean, _, _ := strings.Cut(parts[1], "?")
				if clean != "/favicon.ico" && !strings.HasPrefix(clean, "/api/") {
					urlMap[clean]++
				}
			}
		}
	}

	// Top 10 URLs
	top := make([]logsURLCount, 0, len(urlMap))
	for u, c := range urlMap {
		top = append(top, logsURLCount{u, c})
	}
	slices.SortFunc(top, func(a, b logsURLCount) int {
		if a.Count != b.Count {
			return int(b.Count) - int(a.Count)
		}
		return strings.Compare(a.URL, b.URL)
	})
	top = top[:min(10, len(top))]

	// Total 5xx errors
	var e5xx uint32
	for k, v := range statusMap {
		if strings.HasPrefix(k, "5") {
			e5xx += v
		}
	}
	return map[string]any{
		"requests_total":   total,
		"status_breakdown": statusMap,
		"top_urls":         top,
		"errors_5xx":       e5xx,
		"errors_per_hour":  errorsByHour,
	}
}

// logsLogStats: GET /logs/stats — parse nginx access log for aggregated stats.
func logsLogStats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := q.Get("domain")
	// Validate domain to prevent path traversal
	if domain != "" && !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	logPath := "/var/log/nginx/access.log"
	if domain != "" {
		logPath = "/var/log/nginx/" + domain + ".access.log"
	}

	if _, err := os.Stat(logPath); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"errors_per_hour":  map[string]any{},
			"top_urls":         []any{},
			"status_breakdown": map[string]any{},
			"requests_total":   0,
			"errors_5xx":       0,
		})
		return
	}

	// Read last 50000 lines
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "tail", "-n", "50000", logPath)
	if errors.Is(err, context.DeadlineExceeded) {
		writeErr(w, http.StatusGatewayTimeout, "Timeout reading log file")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logsComputeStats(services.LogsLines(out.Stdout)))
}

// logsDockerContainers: GET /logs/docker — list containers with the
// dockpanel.managed label.
//
// `-a` is load-bearing: without it only *running* containers were listed, so
// the crashed ones — the only containers anybody opens this page for — were
// exactly the ones missing from the picker. Docker keeps an exited
// container's logs until it is removed.
func logsDockerContainers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	names := []string{}
	if out, err := safecmd.Exec(ctx, "docker", "ps", "-a", "--filter", "label=dockpanel.managed=true", "--format", "{{.Names}}"); err == nil {
		for _, l := range services.LogsLines(out.Stdout) {
			if l != "" {
				names = append(names, l)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"containers": names})
}

// logsDockerLogs: GET /logs/docker/{container} — container logs.
func logsDockerLogs(w http.ResponseWriter, r *http.Request) {
	container := r.PathValue("container")
	valid := container != ""
	for _, c := range container {
		if !isASCIIAlnum(c) && c != '-' && c != '_' && c != '.' {
			valid = false
		}
	}
	if !valid {
		writeErr(w, http.StatusBadRequest, "Invalid container name")
		return
	}

	lines := 200
	if n, ok := logsParseUsize(r.URL.Query().Get("lines")); ok {
		lines = n
	}
	lines = min(lines, 1000)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "docker", "logs", "--tail", strconv.Itoa(lines), container)
	if errors.Is(err, context.DeadlineExceeded) {
		writeErr(w, http.StatusGatewayTimeout, "Timeout")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw := strings.ToValidUTF8(string(out.Stdout), "�") + strings.ToValidUTF8(string(out.Stderr), "�")
	// Strip ANSI escape sequences so the frontend doesn't render raw codes
	content := logsStripANSIEscapes(raw)
	writeJSON(w, http.StatusOK, map[string]any{
		"logs":  content,
		"lines": len(services.LogsLines([]byte(content))),
	})
}

// logsAllowedServices is the journalctl whitelist.
var logsAllowedServices = []string{
	"dockpanel-agent",
	"dockpanel-api",
	"nginx",
	"postfix",
	"dovecot",
	"fail2ban",
	"docker",
	"opendkim",
	"rspamd",
	"redis-server",
	"php8.3-fpm",
	"php8.2-fpm",
}

// logsServiceLogs: GET /logs/service/{service} — systemd logs via journalctl.
func logsServiceLogs(w http.ResponseWriter, r *http.Request) {
	service := r.PathValue("service")
	if !slices.Contains(logsAllowedServices, service) {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("Service '%s' not in allowed list", service))
		return
	}

	lines := 100
	if n, ok := logsParseUsize(r.URL.Query().Get("lines")); ok {
		lines = n
	}
	lines = min(lines, 500)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "journalctl", "-u", service, "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso")
	if errors.Is(err, context.DeadlineExceeded) {
		writeErr(w, http.StatusGatewayTimeout, "Timeout")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	content := strings.ToValidUTF8(string(out.Stdout), "�")
	writeJSON(w, http.StatusOK, map[string]any{
		"logs":    content,
		"service": service,
		"lines":   len(services.LogsLines(out.Stdout)),
	})
}

type logsFileSize struct {
	Path   string  `json:"path"`
	Label  string  `json:"label"`
	Size   int64   `json:"size"`
	SizeMB float64 `json:"size_mb"`
}

// logsLogSizes: GET /logs/sizes — log file sizes.
func logsLogSizes(w http.ResponseWriter, _ *http.Request) {
	logFiles := [][2]string{
		{"/var/log/nginx/access.log", "Nginx Access"},
		{"/var/log/nginx/error.log", "Nginx Error"},
		{"/var/log/syslog", "Syslog"},
		{services.LogsResolveAuthLogPath(), "Auth"},
		{"/var/log/mail.log", "Mail"},
	}

	files := []logsFileSize{}
	var total int64
	for _, f := range logFiles {
		var size int64
		if fi, err := os.Stat(f[0]); err == nil {
			size = fi.Size()
		}
		total += size
		files = append(files, logsFileSize{f[0], f[1], size, logsRound1(size)})
	}

	// Also check per-site logs
	if entries, err := os.ReadDir("/var/log/nginx"); err == nil {
		for _, e := range entries {
			name := e.Name()
			if strings.HasSuffix(name, ".access.log") && name != "access.log" {
				var size int64
				if fi, err := e.Info(); err == nil {
					size = fi.Size()
				}
				total += size
				domain := strings.TrimSuffix(name, ".access.log")
				files = append(files, logsFileSize{"/var/log/nginx/" + name, domain + " Access", size, logsRound1(size)})
			}
		}
	}

	// Sort by size descending
	slices.SortStableFunc(files, func(a, b logsFileSize) int {
		switch {
		case a.Size > b.Size:
			return -1
		case a.Size < b.Size:
			return 1
		}
		return 0
	})

	// Check logrotate status
	_, lrErr := os.Stat("/etc/logrotate.d/nginx")
	writeJSON(w, http.StatusOK, map[string]any{
		"files":       files,
		"total_bytes": total,
		"total_mb":    logsRound1(total),
		"logrotate":   lrErr == nil,
	})
}

// logsUnderVarLog mirrors Rust Path::starts_with("/var/log/"), which is
// component-wise (so "/var/log" itself matches, "/var/logx" does not).
func logsUnderVarLog(p string) bool {
	return p == "/var/log" || strings.HasPrefix(p, "/var/log/")
}

// logsTruncateLog: POST /logs/truncate — truncate (clear) a log file.
func logsTruncateLog(w http.ResponseWriter, r *http.Request) {
	var body any
	if !decodeJSON(w, r, &body) {
		return
	}
	path := ""
	if m, ok := body.(map[string]any); ok {
		path, _ = m["path"].(string)
	}

	// Only allow truncating under /var/log/
	if path == "" || !strings.HasPrefix(path, "/var/log/") || strings.Contains(path, "..") {
		writeErr(w, http.StatusBadRequest, "Invalid log path")
		return
	}

	// Canonicalize to resolve symlinks, then re-verify path is under /var/log/
	canonical, err := filepath.EvalSymlinks(path)
	if err == nil {
		canonical, err = filepath.Abs(canonical)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid path")
		return
	}
	if !logsUnderVarLog(canonical) {
		writeErr(w, http.StatusForbidden, "Path escapes /var/log/")
		return
	}

	// Verify it's a regular file, not a symlink
	fi, err := os.Lstat(path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Cannot stat file")
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		writeErr(w, http.StatusForbidden, "Symlinks not allowed")
		return
	}

	if err := os.WriteFile(canonical, nil, 0o666); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("Log file truncated: " + canonical)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// logsStripANSIEscapes strips ANSI escape sequences (colors, cursor movement,
// etc.): ESC[...X (CSI), ESC]...ST (OSC), and bare ESC+char.
func logsStripANSIEscapes(s string) string {
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		if rs[i] != '\x1b' {
			b.WriteRune(rs[i])
			continue
		}
		if i+1 >= len(rs) {
			continue
		}
		switch rs[i+1] {
		case '[':
			i++ // consume '['
			// Skip until a letter (the final byte of a CSI sequence)
			for i+1 < len(rs) {
				i++
				if ch := rs[i]; ch < 128 && (ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z') {
					break
				}
			}
		case ']':
			i++ // consume ']'
			// OSC sequence: skip until ST (ESC\ or BEL)
			for i+1 < len(rs) {
				i++
				if rs[i] == '\x07' {
					break
				}
				if rs[i] == '\x1b' {
					if i+1 < len(rs) && rs[i+1] == '\\' {
						i++
					}
					break
				}
			}
		default:
			i++ // skip one char after ESC
		}
	}
	return b.String()
}
