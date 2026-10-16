package api

// Router assembly (routes::router() + the main.rs layers) and the shared
// helpers that live in panel/backend/src/routes/mod.rs, plus the HTTP
// plumbing every rt_<m>.go uses: writeJSON, writeError, decodeJSON,
// decodeQuery, pathUUID.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"
)

// Handler is a route handler. Returning an error writes it (writeError):
// *ApiError as its JSON body, an extractor rejection as text/plain, an
// *AgentError via agentError, anything else as internalError. Return nil
// after writing a success response yourself.
type Handler func(w http.ResponseWriter, r *http.Request) error

// Router collects the API routes.
type Router struct {
	St  *AppState
	mux *http.ServeMux
}

// Handle registers a route. Patterns are Go 1.22 ServeMux patterns:
// `.route("/api/x/{id}", get(a).post(b))` becomes Handle("GET /api/x/{id}", a)
// and Handle("POST /api/x/{id}", b); axum `{*rest}` becomes `{rest...}`.
// Read params with r.PathValue (or pathUUID).
func (rt *Router) Handle(pattern string, h Handler) {
	rt.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			writeError(w, err)
		}
	})
}

// ServeHTTP answers unmatched paths like axum: 404/405 with an EMPTY body
// (405 keeps its Allow header) rather than Go's text bodies.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, pattern := rt.mux.Handler(r); pattern == "" {
		h.ServeHTTP(bodylessWriter{w}, r)
		return
	}
	rt.mux.ServeHTTP(w, r)
}

type bodylessWriter struct{ http.ResponseWriter }

func (b bodylessWriter) WriteHeader(code int) {
	b.Header().Del("Content-Type")
	b.Header().Del("X-Content-Type-Options")
	b.ResponseWriter.WriteHeader(code)
}
func (b bodylessWriter) Write(p []byte) (int, error) { return len(p), nil }

// registrars mirrors routes::router(), module by module in first-appearance
// order. The integration pass uncomments each line once rt_<m>.go exists.
var registrars = []func(*Router){
	rtAuthRegister,
	rtPasskeysRegister,
	rtDockerAppsRegister,
	rtUsersRegister,
	rtSitesRegister,
	rtSslRegister,
	rtFilesRegister,
	rtBackupsRegister,
	rtBackupDestinationsRegister,
	rtBackupSchedulesRegister,
	rtCronsRegister,
	rtLogsRegister,
	rtTerminalRegister,
	rtDatabasesRegister,
	rtTcpProxiesRegister,
	rtStacksRegister,
	rtTlsCertificatesRegister,
	rtGitDeploysRegister,
	rtSecurityRegister,
	rtSecurityScansRegister,
	rtImageScansRegister,
	rtSbomsRegister,
	rtSystemRegister,
	rtSettingsRegister,
	rtOauthRegister,
	rtCdnRegister,
	rtDnsRegister,
	rtWordpressRegister,
	rtDeployRegister,
	rtMonitorsRegister,
	rtBrandingAssetsRegister,
	rtIncidentsRegister,
	rtWebhookGatewayRegister,
	rtStagingRegister,
	rtAgentUpdatesRegister,
	rtAgentCheckinRegister,
	rtApiKeysRegister,
	rtExtensionsRegister,
	rtServersRegister,
	rtMetricsRegister,
	rtTeamsRegister,
	rtAlertsRegister,
	rtOnCallRegister,
	rtEscalationPoliciesRegister,
	rtUpdateRegister,
	rtDriftRegister,
	rtNotificationsRegister,
	rtBackupOrchestratorRegister,
	rtIacRegister,
	rtWhmcsRegister,
	rtSecretsRegister,
	rtDashboardRegister,
	rtWsMetricsRegister,
	rtPrometheusRegister,
	rtMailRegister,
	rtSystemLogsRegister,
	rtResellersRegister,
	rtResellerDashboardRegister,
	rtActivityRegister,
	rtTelemetryRegister,
	rtMigrationRegister,
}

// NewHandler builds the full API: every registrar's routes behind the
// main.rs layers — outermost request tracing, then the 300s timeout (504),
// then CORS.
func NewHandler(st *AppState) http.Handler {
	rt := &Router{St: st, mux: http.NewServeMux()}
	for _, reg := range registrars {
		reg(rt)
	}
	return traceTimeout(300*time.Second, cors(st.Config.CORSOrigins, rt))
}

// ── Middleware ─────────────────────────────────────────────────────────────

// cors is the tower-http CorsLayer main.rs configured.
//
// The frontend is served by nginx on the same origin as the API, so its
// calls need no CORS at all. CORS only governs other websites calling the
// API: with no CORS_ORIGINS every cross-origin request is denied; when
// configured, the list is whitelisted (and only then with credentials).
func cors(origins []string, next http.Handler) http.Handler {
	creds := len(origins) > 0
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Vary", "origin, access-control-request-method, access-control-request-headers")
		if o := r.Header.Get("Origin"); o != "" && slices.Contains(origins, o) {
			h.Set("Access-Control-Allow-Origin", o)
		}
		if creds {
			h.Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE")
			h.Set("Access-Control-Allow-Headers", "content-type,authorization,accept,x-server-id")
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// traceTimeout is TraceLayer + TimeoutLayer(504, 300s).
//
// tower's timeout bounds the time until the handler RETURNS ITS RESPONSE —
// a streaming body (SSE, websocket) runs on afterwards. The Go equivalent:
// the clock stops the moment headers are written or the connection is
// hijacked. If it fires first the client gets an empty 504 and the handler's
// context is cancelled; its later writes are discarded.
func traceTimeout(limit time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		slog.Debug("started processing request", "method", r.Method, "uri", r.URL.RequestURI())
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		tw := &timeoutWriter{w: w, h: http.Header{}}
		for k, v := range w.Header() {
			tw.h[k] = v
		}
		timer := time.AfterFunc(limit, func() {
			tw.mu.Lock()
			defer tw.mu.Unlock()
			if tw.wroteHeader || tw.hijacked {
				return
			}
			tw.timedOut = true
			tw.status = http.StatusGatewayTimeout
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusGatewayTimeout)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			cancel()
		})
		tw.stop = func() { timer.Stop() }
		next.ServeHTTP(tw, r.WithContext(ctx))
		timer.Stop()
		tw.mu.Lock()
		if !tw.wroteHeader && !tw.timedOut && !tw.hijacked {
			tw.writeHeaderLocked(http.StatusOK)
		}
		status := tw.status
		tw.mu.Unlock()
		slog.Debug("finished processing request", "latency", time.Since(start).String(), "status", status)
	})
}

type timeoutWriter struct {
	mu          sync.Mutex
	w           http.ResponseWriter
	h           http.Header // the handler's own map: never raced by the 504
	wroteHeader bool
	timedOut    bool
	hijacked    bool
	status      int
	stop        func()
}

func (t *timeoutWriter) Header() http.Header { return t.h }

func (t *timeoutWriter) writeHeaderLocked(code int) {
	if t.timedOut || t.wroteHeader {
		return
	}
	dst := t.w.Header()
	for k, v := range t.h {
		dst[k] = v
	}
	t.w.WriteHeader(code)
	if code >= 200 || code == http.StatusSwitchingProtocols {
		t.wroteHeader = true
		t.status = code
		if t.stop != nil {
			t.stop()
		}
	}
}

func (t *timeoutWriter) WriteHeader(code int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writeHeaderLocked(code)
}

func (t *timeoutWriter) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timedOut {
		return 0, http.ErrHandlerTimeout
	}
	t.writeHeaderLocked(http.StatusOK)
	return t.w.Write(p)
}

func (t *timeoutWriter) Flush() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timedOut {
		return
	}
	t.writeHeaderLocked(http.StatusOK)
	if f, ok := t.w.(http.Flusher); ok {
		f.Flush()
	}
}

func (t *timeoutWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timedOut {
		return nil, nil, http.ErrHandlerTimeout
	}
	hj, ok := t.w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack not supported")
	}
	t.hijacked = true
	if t.stop != nil {
		t.stop()
	}
	return hj.Hijack()
}

// ── Response writing ───────────────────────────────────────────────────────

// writeJSON writes v as JSON like axum's Json: no HTML escaping, no
// trailing newline.
func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		slog.Error("response serialization failed", "error", err)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

// writeError writes a handler's error (see Handler).
func writeError(w http.ResponseWriter, err error) {
	var ae *ApiError
	var pe *plainError
	var ge *AgentError
	switch {
	case errors.As(err, &ae):
		writeJSON(w, ae.Status, ae.Body)
	case errors.As(err, &pe):
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(pe.Status)
		_, _ = io.WriteString(w, pe.Msg)
	case errors.As(err, &ge):
		writeError(w, agentError("agent call", ge))
	default:
		writeError(w, internalError("request", err))
	}
}

// rejection is an axum extractor rejection (text/plain body).
func rejection(status int, msg string) error { return &plainError{Status: status, Msg: msg} }

// ── Extractors ─────────────────────────────────────────────────────────────

// maxJSONBody is axum's default 2 MB request body limit.
const maxJSONBody = 2 << 20

// decodeJSON is axum's Json<T> extractor into v (a pointer): missing or
// wrong content type → 415, oversize → 413, malformed JSON → 400, wrong
// shape → 422.
//
// serde semantics are kept for required fields: a non-pointer field without
// `serde:"default"` must be PRESENT (and not null) or the request is a 422 —
// encoding/json would silently zero it. Option<T> → pointer; #[serde(default)]
// → tag `serde:"default"`. Checked recursively through nested structs/slices.
func decodeJSON(r *http.Request, v any) error {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" && !(strings.HasPrefix(ct, "application/") && strings.HasSuffix(ct, "+json")) {
		return rejection(http.StatusUnsupportedMediaType, "Expected request with `Content-Type: application/json`")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(body) > maxJSONBody {
		return rejection(http.StatusRequestEntityTooLarge, "Failed to buffer the request body: length limit exceeded")
	}
	return decodeJSONBytes(body, v)
}

// decodeJSONBytes applies decodeJSON's parse/shape rules to a body already read.
func decodeJSONBytes(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		var syn *json.SyntaxError
		if errors.As(err, &syn) || errors.Is(err, io.ErrUnexpectedEOF) {
			return rejection(http.StatusBadRequest, "Failed to parse the request body as JSON: "+err.Error())
		}
		return rejection(http.StatusUnprocessableEntity, "Failed to deserialize the JSON body into the target type: "+err.Error())
	}
	if msg := serdeRequired(body, reflect.TypeOf(v).Elem()); msg != "" {
		return rejection(http.StatusUnprocessableEntity, "Failed to deserialize the JSON body into the target type: "+msg)
	}
	return nil
}

var (
	rawMessageType  = reflect.TypeFor[json.RawMessage]()
	unmarshalerType = reflect.TypeFor[json.Unmarshaler]()
)

// serdeRequired returns "" or a serde-style "missing field `x`" message.
func serdeRequired(raw []byte, t reflect.Type) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t.Kind() == reflect.Struct && !reflect.PointerTo(t).Implements(unmarshalerType):
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return ""
		}
		return serdeRequiredFields(obj, t)
	case t.Kind() == reflect.Slice && t != rawMessageType:
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil {
			return ""
		}
		for _, e := range arr {
			if m := serdeRequired(e, t.Elem()); m != "" {
				return m
			}
		}
	}
	return ""
}

func serdeRequiredFields(obj map[string]json.RawMessage, t reflect.Type) string {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
			if m := serdeRequiredFields(obj, f.Type); m != "" {
				return m
			}
			continue
		}
		if name == "" {
			name = f.Name
		}
		val, present := obj[name]
		isNull := present && bytes.Equal(bytes.TrimSpace(val), []byte("null"))
		optional := f.Type.Kind() == reflect.Pointer || f.Tag.Get("serde") == "default"
		nullable := optional || f.Type.Kind() == reflect.Interface || f.Type == rawMessageType
		if !present && !optional {
			return fmt.Sprintf("missing field `%s`", name)
		}
		if isNull && !nullable {
			return fmt.Sprintf("%s: invalid type: null", name)
		}
		if present && !isNull {
			if m := serdeRequired(val, f.Type); m != "" {
				return m
			}
		}
	}
	return ""
}

// decodeQuery is axum's Query<T> into v (a pointer to a struct whose fields
// carry `json` tags, as serde_urlencoded used the serde names). Supported
// field types: string, bool, ints, floats, uuid.UUID and pointers to them.
// Missing required fields (non-pointer without `serde:"default"`) and parse
// failures are 400 "Failed to deserialize query string: …".
func decodeQuery(r *http.Request, v any) error {
	q := r.URL.Query()
	rv := reflect.ValueOf(v).Elem()
	t := rv.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		vals, ok := q[name]
		if !ok {
			if f.Type.Kind() != reflect.Pointer && f.Tag.Get("serde") != "default" {
				return rejection(http.StatusBadRequest, fmt.Sprintf("Failed to deserialize query string: missing field `%s`", name))
			}
			continue
		}
		fv := rv.Field(i)
		if fv.Kind() == reflect.Pointer {
			fv.Set(reflect.New(fv.Type().Elem()))
			fv = fv.Elem()
		}
		if err := setQueryValue(fv, vals[0]); err != nil {
			return rejection(http.StatusBadRequest, fmt.Sprintf("Failed to deserialize query string: %s: %v", name, err))
		}
	}
	return nil
}

func setQueryValue(fv reflect.Value, s string) error {
	if fv.Type() == reflect.TypeFor[uuid.UUID]() {
		u, err := uuid.Parse(s)
		if err != nil {
			return err
		}
		fv.Set(reflect.ValueOf(u))
		return nil
	}
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(s)
	case reflect.Bool:
		b, err := strconv.ParseBool(s)
		if err != nil || (s != "true" && s != "false") {
			return fmt.Errorf("provided string was not `true` or `false`")
		}
		fv.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(s, 10, fv.Type().Bits())
		if err != nil {
			return errors.New("invalid digit found in string")
		}
		fv.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(s, 10, fv.Type().Bits())
		if err != nil {
			return errors.New("invalid digit found in string")
		}
		fv.SetUint(n)
	case reflect.Float32, reflect.Float64:
		n, err := strconv.ParseFloat(s, fv.Type().Bits())
		if err != nil {
			return errors.New("invalid float literal")
		}
		fv.SetFloat(n)
	default:
		return fmt.Errorf("unsupported query field type %s", fv.Type())
	}
	return nil
}

// pathUUID is a Path<Uuid> segment: 400 when it does not parse.
func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		return uuid.Nil, rejection(http.StatusBadRequest, "Invalid URL: UUID parsing failed: "+err.Error())
	}
	return id, nil
}

// ── Shared helpers from routes/mod.rs ──────────────────────────────────────

// clientIP (GAP 46) prefers x-real-ip (set by the trusted reverse proxy),
// falling back to the first x-forwarded-for entry.
func clientIP(r *http.Request) *string {
	v := r.Header.Values("X-Real-Ip")
	if len(v) == 0 {
		v = r.Header.Values("X-Forwarded-For")
	}
	if len(v) == 0 {
		return nil
	}
	first, _, _ := strings.Cut(v[0], ",")
	s := strings.TrimSpace(first)
	return &s
}

// WebhookAttemptLimit is the failed webhook-secret attempts tolerated per id
// inside the one-hour window both webhook handlers roll. THREE readers must
// agree — the two webhooks and the cleanup janitor, which sheds zero-count
// entries above its cap. They disagreed once (5-minute janitor vs one-hour
// handlers); a literal repeated in three files is how that happens.
const WebhookAttemptLimit uint32 = 10

// isValidDomain validates a domain name.
func isValidDomain(d string) bool {
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, part := range strings.Split(d, ".") {
		if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !isASCIIAlnum(c) && c != '-' {
				return false
			}
		}
	}
	return true
}

func isASCIIAlnum(c rune) bool {
	return c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9')
}

var reservedOnce = sync.OnceValues(func() (*string, []string) {
	host := panelHostFromBaseURL(os.Getenv("BASE_URL"))
	var zones []string
	for _, z := range strings.Split(os.Getenv("RESERVED_DOMAINS"), ",") {
		if z = strings.ToLower(strings.TrimSpace(z)); z != "" {
			zones = append(zones, z)
		}
	}
	return host, zones
})

// isReservedDomain: control-plane domains a tenant must never claim, alias
// onto, clone onto or rename onto — one guard shared by every
// domain-introducing path so they cannot drift.
//
// Derived from THIS install, not the vendor: until v2.31.0 it was a hardcoded
// triple of our own marketing domains, protecting nothing on a customer box.
// What needs protecting is the host the panel itself is served on — the vhost
// a tenant site would collide with to take over its server_name and phish the
// admin login (the s241 squat). **Exact host only**: the session cookie is
// host-scoped, and reserving subdomains would break a panel at an apex
// hosting blog.example.com. RESERVED_DOMAINS zones DO match subdomains.
func isReservedDomain(domain string) bool {
	host, zones := reservedOnce()
	return reservedMatch(domain, host, zones)
}

// panelHostFromBaseURL extracts the bare host from BASE_URL (or a Host
// header) — never the scheme, which does not describe how the vhost is served.
func panelHostFromBaseURL(base string) *string {
	b := strings.ToLower(strings.TrimSpace(base))
	hp := b
	if s, ok := strings.CutPrefix(b, "https://"); ok {
		hp = s
	} else if s, ok := strings.CutPrefix(b, "http://"); ok {
		hp = s
	}
	host, _, _ := strings.Cut(hp, "/")
	// Strip a :port, but never mangle a bare IPv6 literal.
	if strings.HasPrefix(host, "[") {
		host, _, _ = strings.Cut(host, "]")
		host = strings.TrimLeft(host, "[")
	} else {
		host, _, _ = strings.Cut(host, ":")
	}
	if host == "" {
		return nil
	}
	return &host
}

// isReservedDomainFor is isReservedDomain plus the host THIS request arrived
// on. **BASE_URL is not a reliable statement of the panel's hostname** — it is
// routinely empty on a box whose nginx serves a real domain, which made the
// s256 guard inert on the demo box (a site for the panel's own domain took
// over its server_name). The Host header is always right; it is
// attacker-controlled, but can only ever reserve MORE, never less.
func isReservedDomainFor(domain string, r *http.Request) bool {
	if isReservedDomain(domain) {
		return true
	}
	if r.Host == "" {
		return false
	}
	h := panelHostFromBaseURL(r.Host)
	return h != nil && reservedMatch(domain, h, nil)
}

// reservedMatch is the pure decision, testable without process env.
func reservedMatch(domain string, panelHost *string, zones []string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	if panelHost != nil && *panelHost == d {
		return true
	}
	for _, z := range zones {
		if d == z || strings.HasSuffix(d, "."+z) {
			return true
		}
	}
	return false
}

// isSafeHeaderValue validates a value rendered into an nginx
// `add_header Name "<value>" always;` (CSP / Permissions-Policy). Tera does
// not autoescape .conf, so an unescaped `"` (or trailing `\`) closes the
// quoted argument and injects directives. `;` is allowed — inert inside quotes.
func isSafeHeaderValue(v string) bool {
	return !strings.ContainsAny(v, "\"\\\n\r\x00{}")
}

// isValidName validates a resource name (database, app, …).
func isValidName(n string) bool {
	if n == "" || len(n) > 64 || !isASCIIAlnum(rune(n[0])) {
		return false
	}
	for _, c := range n {
		if !isASCIIAlnum(c) && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// isValidContainerID validates a Docker container id (hex, 1–64 chars).
func isValidContainerID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// isSafeRelativePath rejects traversal and injection in a user file path.
func isSafeRelativePath(p string) bool {
	return p != "" && !strings.Contains(p, "\x00") && !strings.Contains(p, "..") &&
		!strings.HasPrefix(p, "/") && !strings.Contains(p, "\\") && len(p) <= 4096
}

// normalizeForBlocklist reduces shell quoting/escaping so blocklist matching
// sees what the shell will run: `r'm' -rf /` and `w\get` contain no
// "rm -rf /"/"wget" substring, but `sh -c` strips the quotes before exec.
// Mirrors the agent's command_filter::normalize_for_blocklist.
func normalizeForBlocklist(cmd string) string {
	var b strings.Builder
	rs := []rune(cmd)
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '\'', '"':
		case '\\':
			if i+1 < len(rs) {
				i++
				b.WriteRune(rs[i])
			}
		default:
			b.WriteRune(rs[i])
		}
	}
	return b.String()
}

// runsOtherThanPairs reports a run of c whose length is not exactly 2.
func runsOtherThanPairs(s string, c byte) bool {
	for i := 0; i < len(s); {
		if s[i] != c {
			i++
			continue
		}
		start := i
		for i < len(s) && s[i] == c {
			i++
		}
		if i-start != 2 {
			return true
		}
	}
	return false
}

// isSafeShellCommand validates a command string (cron, pre_build,
// post_deploy) — all eventually shell-executed. Returns "" when safe.
func isSafeShellCommand(cmd string) string {
	switch {
	case strings.TrimSpace(cmd) == "":
		return "Command cannot be empty"
	case len(cmd) > 4096:
		return "Command too long (max 4096 chars)"
	case strings.Contains(cmd, "\x00"):
		return "Command must not contain null bytes"
	case strings.ContainsAny(cmd, "\n\r"):
		return "Command must not contain newlines"
	// A bare `;` always chains; a bare `|` or `&` chains just as effectively
	// ("id;whoami", "id|whoami", "id&whoami" ran both) — none was caught by
	// the verb-anchored patterns below. Only paired &&/|| stay legal.
	case strings.Contains(cmd, ";"):
		return "Command must not contain a bare ; (use && or || to chain)"
	case runsOtherThanPairs(cmd, '|'):
		return "Command must not contain a bare | (use || to chain)"
	case runsOtherThanPairs(cmd, '&'):
		return "Command must not contain a bare & (use && to chain)"
	}
	lower := strings.ToLower(normalizeForBlocklist(cmd))
	lists := []struct {
		pats []string
		msg  string
	}{
		{[]string{"`", "$(", "<(", "<<", "eval ", "exec ", "|sh", "|bash", "| sh", "| bash",
			";sh", ";bash", "; sh", "; bash", "/bin/sh", "/bin/bash"}, "Command contains dangerous shell injection pattern"},
		{[]string{"base64", "xxd", "openssl enc", "printf '\\x"}, "Command contains encoding bypass tool"},
		// "perl -E" can never match the lowercased string; kept verbatim from Rust.
		{[]string{"python -c", "python2 -c", "python3 -c", "perl -e", "perl -E", "ruby -e", "node -e", "php -r",
			"python -m http", "python3 -m http"}, "Command contains scripting interpreter with inline code"},
		{[]string{"curl ", "wget ", "nc ", "ncat ", "socat ", "telnet "}, "Command contains network exfiltration tool"},
		{[]string{"rm -rf /", "rm -rf /*", "mkfs", "dd if=", "> /dev/", "chmod 777 /", "shutdown", "reboot",
			"init 0", "init 6"}, "Command contains destructive operation"},
		{[]string{"useradd", "userdel", "usermod", "adduser", "chpasswd", "passwd", "/etc/shadow", "/etc/sudoers",
			"visudo", "chown root", "chmod +s", "chmod 4"}, "Command contains privilege escalation attempt"},
	}
	for _, l := range lists {
		for _, p := range l.pats {
			if strings.Contains(lower, p) {
				return l.msg
			}
		}
	}
	return ""
}

// ── Compose documents (parsed, never grepped: a string scan is bypassable
// with anchors, aliases and alternate quoting) ─────────────────────────────

// composeDoc parses yaml like serde_yaml_ng::from_str::<Value>: one document,
// no duplicate mapping keys. Aliases resolve; `<<` merge keys do NOT (the
// agent deserialises with the same semantics, so both sides agree that a
// service whose image arrives only through a merge key has no image).
func composeDoc(src string) (*yaml.Node, error) {
	dec := yaml.NewDecoder(strings.NewReader(src))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if err == io.EOF {
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null"}, nil
		}
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("more than one document")
	}
	n := yamlResolve(&doc)
	if yamlHasDuplicateKeys(n, map[*yaml.Node]bool{}) {
		return nil, errors.New("duplicate key")
	}
	return n, nil
}

func yamlResolve(n *yaml.Node) *yaml.Node {
	for n != nil && (n.Kind == yaml.AliasNode || n.Kind == yaml.DocumentNode) {
		if n.Kind == yaml.AliasNode {
			n = n.Alias
		} else if len(n.Content) > 0 {
			n = n.Content[0]
		} else {
			return nil
		}
	}
	return n
}

func yamlHasDuplicateKeys(n *yaml.Node, seen map[*yaml.Node]bool) bool {
	n = yamlResolve(n)
	if n == nil || seen[n] {
		return false
	}
	seen[n] = true
	if n.Kind == yaml.MappingNode {
		keys := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := yamlResolve(n.Content[i])
			if k != nil && k.Kind == yaml.ScalarNode {
				id := k.ShortTag() + ":" + k.Value
				if keys[id] {
					return true
				}
				keys[id] = true
			}
		}
	}
	for _, c := range n.Content {
		if yamlHasDuplicateKeys(c, seen) {
			return true
		}
	}
	return false
}

// yamlGet is Value::get(&str) on a mapping: nil when absent or not a mapping.
func yamlGet(n *yaml.Node, key string) *yaml.Node {
	n = yamlResolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := yamlResolve(n.Content[i]); k != nil && k.Kind == yaml.ScalarNode && k.ShortTag() == "!!str" && k.Value == key {
			return yamlResolve(n.Content[i+1])
		}
	}
	return nil
}

func yamlStr(n *yaml.Node) (string, bool) {
	if n = yamlResolve(n); n != nil && n.Kind == yaml.ScalarNode && n.ShortTag() == "!!str" {
		return n.Value, true
	}
	return "", false
}

func yamlIsNull(n *yaml.Node) bool {
	n = yamlResolve(n)
	return n != nil && n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
}

// yamlEach visits a mapping's (key, value) pairs.
func yamlEach(n *yaml.Node, f func(k, v *yaml.Node)) {
	if n = yamlResolve(n); n == nil || n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		f(yamlResolve(n.Content[i]), yamlResolve(n.Content[i+1]))
	}
}

func yamlSeq(n *yaml.Node) []*yaml.Node {
	if n = yamlResolve(n); n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]*yaml.Node, len(n.Content))
	for i, c := range n.Content {
		out[i] = yamlResolve(c)
	}
	return out
}

// composeImages is every image reference a Compose document would run, in
// declaration order — read here so the deploy gate can refuse before anything
// is claimed or sent to a host. A build:-only service has no reference to
// check and is skipped.
func composeImages(src string) []string {
	doc, err := composeDoc(src)
	if err != nil {
		return []string{}
	}
	out := []string{}
	yamlEach(yamlGet(doc, "services"), func(_, svc *yaml.Node) {
		if s, ok := yamlStr(yamlGet(svc, "image")); ok {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	})
	return out
}

// composeServicesWithoutImage names the services the agent will SILENTLY
// DROP — those whose image is missing or YAML null (the agent's typed
// Option<String> reads `image:` with no value as None). The deploy would come
// up missing exactly that part while every status says success. ⚠ An empty
// string is NOT reported: the agent tries to create a container from it, so
// refusing would refuse a file the agent still deploys.
func composeServicesWithoutImage(src string) []string {
	doc, err := composeDoc(src)
	if err != nil {
		return []string{}
	}
	out := []string{}
	yamlEach(yamlGet(doc, "services"), func(k, svc *yaml.Node) {
		img := yamlGet(svc, "image")
		if img == nil || yamlIsNull(img) {
			if name, ok := yamlStr(k); ok {
				out = append(out, name)
			}
		}
	})
	return out
}

// validateComposeYAML refuses dangerous directives. Returns "" when safe.
func validateComposeYAML(src string) string {
	doc, err := composeDoc(src)
	if err != nil {
		return "Invalid YAML syntax"
	}
	msg := ""
	yamlEach(yamlGet(doc, "services"), func(_, svc *yaml.Node) {
		if msg != "" {
			return
		}
		msg = composeServiceProblem(svc)
	})
	return msg
}

func composeServiceProblem(svc *yaml.Node) string {
	if p := yamlGet(svc, "privileged"); p != nil && p.Kind == yaml.ScalarNode && p.ShortTag() == "!!bool" {
		if b, _ := strconv.ParseBool(strings.ToLower(p.Value)); b {
			return "Compose: privileged mode is not allowed"
		}
	}
	for _, key := range []string{"network_mode", "pid", "ipc"} {
		if v, ok := yamlStr(yamlGet(svc, key)); ok && v == "host" {
			return "Compose: host namespace sharing is not allowed"
		}
	}
	dangerousCaps := []string{"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "ALL", "NET_RAW", "SYS_RAWIO", "SYS_MODULE", "DAC_OVERRIDE"}
	for _, c := range yamlSeq(yamlGet(svc, "cap_add")) {
		if s, ok := yamlStr(c); ok && slices.Contains(dangerousCaps, strings.ToUpper(s)) {
			return "Compose: dangerous capability not allowed"
		}
	}
	// Both short-form "host:container" and long-form {source: host}.
	for _, vol := range yamlSeq(yamlGet(svc, "volumes")) {
		source, ok := yamlStr(vol)
		if !ok {
			source, _ = yamlStr(yamlGet(vol, "source"))
		}
		if strings.Contains(source, "docker.sock") || strings.Contains(source, "/var/run/docker") {
			return "Compose: Docker socket mount is not allowed"
		}
		if strings.HasPrefix(source, "/:/") || strings.HasPrefix(source, "/:") || source == "/" {
			return "Compose: mounting host root is not allowed"
		}
		for _, s := range []string{"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/", "/home/"} {
			if strings.HasPrefix(source, s) || strings.Contains(source, ":"+s) {
				return "Compose: sensitive host path mount is not allowed"
			}
		}
	}
	for _, o := range yamlSeq(yamlGet(svc, "security_opt")) {
		if s, ok := yamlStr(o); ok && strings.Contains(strings.ToLower(s), "unconfined") {
			return "Compose: disabling security profiles is not allowed"
		}
	}
	// Present at all — even `devices:` with a null value — is refused.
	if yamlGet(svc, "devices") != nil {
		return "Compose: host device passthrough is not allowed"
	}
	return ""
}

// isSafeNginxConfig validates custom nginx directives. Returns "" when safe.
func isSafeNginxConfig(cfg string) string {
	if len(cfg) > 10240 {
		return "Custom nginx directives must be under 10KB"
	}
	if strings.Contains(cfg, "\x00") {
		return "Config contains null bytes"
	}
	lower := strings.ToLower(cfg)
	for _, d := range []string{
		"lua_", "content_by_lua", "access_by_lua", "rewrite_by_lua",
		"set_by_lua", "header_filter_by_lua", "body_filter_by_lua",
		"proxy_pass http://127.0.0.1", "proxy_pass http://localhost",
		"proxy_pass http://0.0.0.0", "proxy_pass http://[::1]",
		"proxy_pass http://169.254", // AWS metadata
		"proxy_pass http://metadata",
		"load_module", "include /etc/", "include /root/",
		"ssl_certificate /etc/shadow",
		"alias /etc/", "alias /root/", "alias /home/",
		"root /etc/", "root /root/", "root /home/",
		// File-writing directives: one was chained past the agent's per-line
		// whitelist via ';' to poison a log into another tenant's webroot.
		"access_log", "error_log",
	} {
		if strings.Contains(lower, d) {
			return "Custom nginx config contains dangerous directive"
		}
	}
	// Directives the site template already writes at SERVER level, into the
	// same block: nginx refuses a duplicate, and the agent's copy of this check
	// runs inside the template render, surfacing as a 502 reference. Refused
	// here so the reason survives (400 carries the text).
	for _, stmt := range strings.Split(cfg, ";") {
		directive := strings.ToLower(firstField(strings.TrimSpace(stmt)))
		switch directive {
		case "client_max_body_size":
			return "The site already sets 'client_max_body_size' — nginx refuses a " +
				"duplicate and the whole site would fail to load. Change the site's " +
				"maximum upload size instead; that is the control that writes it."
		case "gzip", "gzip_min_length":
			return "The site already enables gzip — nginx refuses a duplicate 'gzip' or " +
				"'gzip_min_length' and the whole site would fail to load. Compression " +
				"is on for every site already."
		}
	}
	return ""
}

// firstField is `split(char::is_whitespace).next()` (empty when s starts
// with whitespace, which TrimSpace has already ruled out).
func firstField(s string) string {
	if i := strings.IndexFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f' }); i >= 0 {
		return s[:i]
	}
	return s
}
