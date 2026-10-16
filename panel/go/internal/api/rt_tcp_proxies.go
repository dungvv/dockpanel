package api

// Port of panel/backend/src/routes/tcp_proxies.rs — generic TCP proxies
// terminated by the host nginx `stream` module.
//
// Each row is one public listen port on one server forwarding to one
// host:port upstream; the agent writes the actual `server {}` file under
// /etc/nginx/dockpanel-streams and owns the firewall rule. Database remote
// access (kind='database') lives in rt_databases — this file owns only the
// operator-defined generic kind and the shared port allocator.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Public listen ports come only from this range — kept clear of the HTTP
// listeners, the panel's own ports, the per-engine database pools, and the
// Docker ephemeral range. The agent re-checks the range independently.
const (
	rtTcpProxiesListenPortMin int32 = 40000
	rtTcpProxiesListenPortMax int32 = 44999
)

func rtTcpProxiesRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	// Generic forwards are admin-level; kind='database' rows are managed via
	// the databases remote-access endpoints.
	r.Handle("GET /api/tcp-proxies", h(rtTcpProxiesList))
	r.Handle("POST /api/tcp-proxies", h(rtTcpProxiesCreate))
	r.Handle("DELETE /api/tcp-proxies/{id}", h(rtTcpProxiesRemove))
}

type rtTcpProxiesTcpProxy struct {
	ID            uuid.UUID  `db:"id" json:"id"`
	ServerID      uuid.UUID  `db:"server_id" json:"server_id"`
	DatabaseID    *uuid.UUID `db:"database_id" json:"database_id"`
	CertificateID *uuid.UUID `db:"certificate_id" json:"certificate_id"`
	Name          string     `db:"name" json:"name"`
	Kind          string     `db:"kind" json:"kind"`
	ListenPort    int32      `db:"listen_port" json:"listen_port"`
	UpstreamHost  string     `db:"upstream_host" json:"upstream_host"`
	UpstreamPort  int32      `db:"upstream_port" json:"upstream_port"`
	TLS           bool       `db:"tls" json:"tls"`
	AllowCIDRs    []string   `db:"allow_cidrs" json:"allow_cidrs"`
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
}

type rtTcpProxiesListQuery struct {
	Limit  *int64 `json:"limit"`
	Offset *int64 `json:"offset"`
}

type rtTcpProxiesCreateProxyRequest struct {
	Name          string     `json:"name"`
	UpstreamHost  string     `json:"upstream_host"`
	UpstreamPort  int32      `json:"upstream_port"`
	TLS           bool       `json:"tls" serde:"default"`
	CertificateID *uuid.UUID `json:"certificate_id"`
	// Source IPs/CIDRs allowed to connect; empty means anyone.
	AllowCIDRs []string `json:"allow_cidrs" serde:"default"`
}

// rtTcpProxiesValidProxyName mirrors the agent's rule: the panel must refuse
// in its own words rather than relaying the agent's refusal for a form it
// just validated.
func rtTcpProxiesValidProxyName(name string) bool {
	if name == "" || len(name) > 48 || strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// rtTcpProxiesValidUpstreamHost mirrors the agent's normalize_upstream_host:
// an IP literal (IPv6 in brackets) or a hostname of letters/digits/dots/
// hyphens. Anything that would make proxy_pass more than one token never
// reaches the agent.
func rtTcpProxiesValidUpstreamHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" || len(h) > 253 {
		return false
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") && len(h) >= 2 {
		a, err := netip.ParseAddr(h[1 : len(h)-1])
		return err == nil && a.Is6() && a.Zone() == ""
	}
	if a, err := netip.ParseAddr(h); err == nil && a.Is4() {
		return true
	}
	digitsDots := true
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c == '.') {
			digitsDots = false
			break
		}
	}
	if digitsDots {
		return false // digits-and-dots that is not IPv4 is not a hostname
	}
	for _, c := range h {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return !strings.HasPrefix(h, ".") && !strings.HasPrefix(h, "-") &&
		!strings.HasSuffix(h, ".") && !strings.HasSuffix(h, "-") && !strings.Contains(h, "..")
}

// rtTcpProxiesAllocateListenPort is the first free public listen port on this
// server. generate_series finds the lowest gap; UNIQUE(server_id,
// listen_port) makes the insert itself the last word under concurrency.
func rtTcpProxiesAllocateListenPort(ctx context.Context, st *AppState, serverID uuid.UUID) (int32, error) {
	p, err := queryScalarOpt[int32](ctx, st.DB,
		"SELECT s.port FROM generate_series($1::int, $2::int) AS s(port) "+
			"WHERE s.port NOT IN (SELECT listen_port FROM tcp_proxies WHERE server_id = $3) "+
			"LIMIT 1", rtTcpProxiesListenPortMin, rtTcpProxiesListenPortMax, serverID)
	if err != nil {
		return 0, internalError("allocate TCP listen port", err)
	}
	if p == nil {
		return 0, apiErr(http.StatusInternalServerError, "No TCP proxy ports left in the managed range")
	}
	return *p, nil
}

// rtTcpProxiesCertificatePaths resolves a caller-supplied certificate on THIS
// server into the registry paths the agent writes into the stream config.
// Scoped to the caller (or an admin): a tenant enabling remote access on
// their database must not hang another user's certificate on the listener.
func rtTcpProxiesCertificatePaths(ctx context.Context, st *AppState, serverID, certificateID, userID uuid.UUID, isAdmin bool) (string, string, error) {
	row, err := queryOpt[Tup2[string, string]](ctx, st.DB,
		"SELECT cert_path, key_path FROM tls_certificates "+
			"WHERE id = $1 AND server_id = $2 AND (user_id = $3 OR $4)",
		certificateID, serverID, userID, isAdmin)
	if err != nil {
		return "", "", internalError("resolve certificate", err)
	}
	if row == nil {
		return "", "", apiErr(http.StatusBadRequest, "Certificate not found on this server")
	}
	return row.A, row.B, nil
}

// rtTcpProxiesCreateProxy is the shared create path: agent first, row second
// — a persisted row is truth about what exists, so the file must exist before
// the row does. rt_databases' remote access calls it with kind="database".
func rtTcpProxiesCreateProxy(
	ctx context.Context, st *AppState, agent AgentHandle,
	serverID, userID uuid.UUID, name, kind, upstreamHost string, upstreamPort int32,
	tls bool, certificateID, databaseID *uuid.UUID, containerID *string,
	callerIsAdmin bool, allowCIDRs []string,
) (*rtTcpProxiesTcpProxy, error) {
	cidrs := make([]string, 0, len(allowCIDRs))
	for _, a := range allowCIDRs {
		if a = strings.TrimSpace(a); a != "" {
			cidrs = append(cidrs, a)
		}
	}
	for _, a := range cidrs {
		if !validPanelIPEntry(a) {
			return nil, apiErr(http.StatusBadRequest, fmt.Sprintf("Invalid allowed source '%s' — use an IP or CIDR like 203.0.113.0/24", a))
		}
	}

	// Refuse a taken name/database BEFORE the agent call: the insert's unique
	// violation used to arrive after the agent had already written, and the
	// rollback below then deleted the live proxy's file. (The agent also
	// refuses to overwrite, which covers two requests racing past this.)
	taken, err := queryScalarOpt[uuid.UUID](ctx, st.DB,
		"SELECT id FROM tcp_proxies "+
			"WHERE (server_id = $1 AND name = $2) OR ($3::uuid IS NOT NULL AND database_id = $3)",
		serverID, name, databaseID)
	if err != nil {
		return nil, internalError("check tcp proxy name", err)
	}
	if taken != nil {
		if databaseID != nil {
			return nil, apiErr(http.StatusConflict, "Remote access is already enabled, or another database maps to the same proxy name")
		}
		return nil, apiErr(http.StatusConflict, "A TCP proxy with this name already exists on this server")
	}

	listenPort, err := rtTcpProxiesAllocateListenPort(ctx, st, serverID)
	if err != nil {
		return nil, err
	}

	agentBody := map[string]any{
		"name":        name,
		"listen_port": listenPort,
		"tls":         tls,
		"allow_cidrs": cidrs,
	}
	if containerID != nil {
		// Database kind: the agent reads the upstream off the container's own
		// loopback binding; what the panel believes about databases.port is
		// never put on the wire as authoritative.
		agentBody["container_id"] = *containerID
	} else {
		agentBody["upstream_host"] = upstreamHost
		agentBody["upstream_port"] = upstreamPort
	}
	if tls {
		if certificateID == nil {
			return nil, apiErr(http.StatusBadRequest, "tls requires certificate_id")
		}
		certPath, keyPath, err := rtTcpProxiesCertificatePaths(ctx, st, serverID, *certificateID, userID, callerIsAdmin)
		if err != nil {
			return nil, err
		}
		agentBody["cert_path"] = certPath
		agentBody["key_path"] = keyPath
	}

	agentResult, err := agent.Post(ctx, "/nginx/streams", agentBody)
	if err != nil {
		return nil, agentError("TCP proxy creation", err)
	}

	// Record the upstream the agent actually wrote — for container-backed
	// proxies that is the binding it inspected, not the hint we sent.
	rowHost, rowPort := upstreamHost, upstreamPort
	if u, ok := jsonStr(jsonGet(agentResult, "upstream")); ok {
		if i := strings.LastIndex(u, ":"); i >= 0 {
			rowHost = u[:i]
			if p, err := strconv.ParseInt(u[i+1:], 10, 32); err == nil {
				rowPort = int32(p)
			} else {
				rowPort = upstreamPort
			}
		}
	}

	row, err := queryOne[rtTcpProxiesTcpProxy](ctx, st.DB,
		"INSERT INTO tcp_proxies "+
			"(server_id, user_id, database_id, certificate_id, name, kind, listen_port, "+
			"upstream_host, upstream_port, tls, allow_cidrs) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) "+
			"RETURNING id, server_id, database_id, certificate_id, name, kind, "+
			"listen_port, upstream_host, upstream_port, tls, allow_cidrs, created_at",
		serverID, userID, databaseID, certificateID, name, kind, listenPort, rowHost, rowPort, tls, cidrs)
	if err != nil {
		// The agent already wrote the listener — remove it before the row
		// error escapes, or the box keeps a port the panel forgot.
		if _, e2 := agent.Delete(ctx, fmt.Sprintf("/nginx/streams/%s?listen_port=%d", name, listenPort)); e2 != nil {
			slog.Error(fmt.Sprintf("TCP proxy '%s' row insert failed AND agent cleanup failed: %v", name, e2))
		}
		if s := err.Error(); strings.Contains(s, "unique") || strings.Contains(s, "duplicate") {
			return nil, apiErr(http.StatusConflict, "Proxy name or port already in use on this server")
		}
		return nil, internalError("create tcp proxy", err)
	}
	return &row, nil
}

// rtTcpProxiesList is GET /api/tcp-proxies — this server's proxies visible
// to the caller.
func rtTcpProxiesList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var q rtTcpProxiesListQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	limit, offset := paginate(q.Limit, q.Offset)

	// Same admin-widening shape as databases::list — an admin of the server
	// sees its proxies even when a tenant owns the row.
	rows, err := queryAll[rtTcpProxiesTcpProxy](r.Context(), st.DB,
		"SELECT p.id, p.server_id, p.database_id, p.certificate_id, p.name, p.kind, "+
			"p.listen_port, p.upstream_host, p.upstream_port, p.tls, p.allow_cidrs, p.created_at "+
			"FROM tcp_proxies p "+
			"WHERE p.server_id = $1 "+
			"AND (p.user_id = $2 OR EXISTS (SELECT 1 FROM users u, servers sv "+
			"WHERE u.id = $2 AND u.role = 'admin' AND sv.id = p.server_id "+
			"AND (sv.is_local OR sv.user_id = u.id))) "+
			"ORDER BY p.created_at DESC LIMIT $3 OFFSET $4",
		serverID, claims.Sub, limit, offset)
	if err != nil {
		return internalError("list tcp proxies", err)
	}
	writeJSON(w, http.StatusOK, rows)
	return nil
}

// rtTcpProxiesCreate is POST /api/tcp-proxies — a generic TCP forward.
// Admin-only: a public listen port on the host is infrastructure, not a
// per-site resource.
func rtTcpProxiesCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body rtTcpProxiesCreateProxyRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	if !rtTcpProxiesValidProxyName(body.Name) {
		return apiErr(http.StatusBadRequest, "Proxy name must be 1-48 chars: lowercase letters, digits and '-'")
	}
	if !rtTcpProxiesValidUpstreamHost(body.UpstreamHost) {
		return apiErr(http.StatusBadRequest, "Invalid upstream host")
	}
	if body.UpstreamPort < 1 || body.UpstreamPort > 65535 {
		return apiErr(http.StatusBadRequest, "Invalid upstream port")
	}
	ctx := r.Context()
	row, err := rtTcpProxiesCreateProxy(ctx, st, agent, serverID, claims.Sub,
		strings.TrimSpace(body.Name), "generic", strings.TrimSpace(body.UpstreamHost), body.UpstreamPort,
		body.TLS, body.CertificateID, nil, nil, true, body.AllowCIDRs)
	if err != nil {
		return err
	}

	slog.Info(fmt.Sprintf("TCP proxy created: %s :%d -> %s:%d", row.Name, row.ListenPort, row.UpstreamHost, row.UpstreamPort))
	ActivityLogActivityOnServer(ctx, st.DB, claims.Sub, claims.Email, "tcp_proxy.create",
		new("tcp_proxy"), new(row.Name),
		new(fmt.Sprintf(":%d -> %s:%d", row.ListenPort, row.UpstreamHost, row.UpstreamPort)),
		nil, &serverID, claims.KeyID)

	writeJSON(w, http.StatusCreated, row)
	return nil
}

// rtTcpProxiesRemove is DELETE /api/tcp-proxies/{id} — remove the stream
// file, the firewall rule, and the row, in that order.
func rtTcpProxiesRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()

	row, err := queryOpt[Tup4[uuid.UUID, string, int32, *uuid.UUID]](ctx, st.DB,
		"SELECT id, name, listen_port, database_id FROM tcp_proxies "+
			"WHERE id = $1 AND server_id = $2", id, serverID)
	if err != nil {
		return internalError("find tcp proxy", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "TCP proxy not found")
	}
	pid, name, listenPort := row.A, row.B, row.C
	if row.D != nil {
		return apiErr(http.StatusConflict, "This proxy belongs to a database — disable its remote access instead")
	}

	// The file and the firewall rule go first: the row is the record of what
	// exists, so it leaves last — a deleted row pointing at a live listener
	// would be the panel lying about an open port.
	if _, err := agent.Delete(ctx, fmt.Sprintf("/nginx/streams/%s?listen_port=%d", name, listenPort)); err != nil {
		return agentError("TCP proxy removal", err)
	}
	if _, err := execSQL(ctx, st.DB, "DELETE FROM tcp_proxies WHERE id = $1", pid); err != nil {
		return internalError("delete tcp proxy", err)
	}

	slog.Info(fmt.Sprintf("TCP proxy deleted: %s (port %d)", name, listenPort))
	ActivityLogActivityOnServer(ctx, st.DB, claims.Sub, claims.Email, "tcp_proxy.delete",
		new("tcp_proxy"), new(name), new(fmt.Sprintf("port %d", listenPort)),
		nil, &serverID, claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
	return nil
}
