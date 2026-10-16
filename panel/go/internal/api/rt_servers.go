package api

// Port of panel/backend/src/routes/servers.rs — the fleet's server rows.

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtServersRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/servers", h(rtServersList))
	r.Handle("POST /api/servers", h(rtServersCreate))
	r.Handle("GET /api/servers/{id}", h(rtServersGetOne))
	r.Handle("PUT /api/servers/{id}", h(rtServersUpdate))
	r.Handle("DELETE /api/servers/{id}", h(rtServersRemove))
	r.Handle("POST /api/servers/{id}/test", h(rtServersTestConnection))
	r.Handle("POST /api/servers/{id}/rotate-token", h(rtServersRotateToken))
	r.Handle("POST /api/servers/{id}/rotate-cert-pin", h(rtServersRotateCertPin))
	r.Handle("GET /api/servers/{id}/uptime", h(rtServersUptime))
}

type rtServersCreateServerRequest struct {
	Name      string  `json:"name"`
	IPAddress *string `json:"ip_address"`
}

// rtServersServer is a servers row. AgentToken is never serialized: it is
// root on the agent.
type rtServersServer struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	Name            string     `json:"name" db:"name"`
	IPAddress       *string    `json:"ip_address" db:"ip_address"`
	AgentToken      string     `json:"-" db:"agent_token"`
	AgentURL        *string    `json:"agent_url" db:"agent_url"`
	Status          string     `json:"status" db:"status"`
	IsLocal         bool       `json:"is_local" db:"is_local"`
	LastSeenAt      *time.Time `json:"last_seen_at" db:"last_seen_at"`
	OSInfo          *string    `json:"os_info" db:"os_info"`
	CPUCores        *int32     `json:"cpu_cores" db:"cpu_cores"`
	RAMMB           *int32     `json:"ram_mb" db:"ram_mb"`
	DiskGB          *int32     `json:"disk_gb" db:"disk_gb"`
	AgentVersion    *string    `json:"agent_version" db:"agent_version"`
	CPUUsage        *float32   `json:"cpu_usage" db:"cpu_usage"`
	MemUsedMB       *int64     `json:"mem_used_mb" db:"mem_used_mb"`
	UptimeSecs      *int64     `json:"uptime_secs" db:"uptime_secs"`
	CertFingerprint *string    `json:"cert_fingerprint" db:"cert_fingerprint"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
}

func rtServersPtr[T any](v T) *T { return &v }

// rtServersList: GET /api/servers — the machines this caller may see.
//
// An administrator sees every machine; anybody else sees the ones they hold.
// This used to be `WHERE user_id = $1` for everyone, and servers.user_id names
// whoever happened to register the row — so a panel's SECOND administrator
// opened Servers to "No servers found", which reads as a broken install.
// Widening is safe because agent_token is never serialized. A non-admin is
// unchanged and still sees only rows it owns (for a client: none). The sibling
// reads (drift, dashboard aggregations) were closed by the same rule (s430/s432).
func rtServersList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	servers, err := queryAll[rtServersServer](r.Context(), st.DB,
		"SELECT * FROM servers WHERE ($2 OR user_id = $1) "+
			"ORDER BY is_local DESC, created_at DESC LIMIT 500",
		c.Sub, c.Role == "admin")
	if err != nil {
		return internalError("list servers", err)
	}
	writeJSON(w, http.StatusOK, servers)
	return nil
}

// rtServersCreate: POST /api/servers — register a remote server; returns the
// agent token and install script.
func rtServersCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var body rtServersCreateServerRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 100 {
		return apiErr(http.StatusBadRequest, "Name must be 1-100 characters")
	}
	ip := ""
	if body.IPAddress != nil {
		ip = strings.TrimSpace(*body.IPAddress)
	}

	agentToken := strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")

	// Default agent URL from IP (port 9443 for HTTPS agent)
	agentURL := ""
	if ip != "" {
		agentURL = "https://" + ip + ":9443"
	}
	agentTokenHash := hashAgentToken(agentToken)

	// The plaintext column is kept because the panel DIALS remote agents with
	// it (the hash only authenticates them inbound), so it is an outbound
	// credential and belongs under the at-rest promise: encrypted here,
	// decrypted at the single site that consumes it (AgentRegistry.ForServer).
	// A panel DB dump used to carry it in cleartext. The response still returns
	// the PLAINTEXT — the operator needs it for the install one-liner, and that
	// is the only time it is ever shown.
	agentTokenEnc, err := SecretsCryptoEncryptCredential(agentToken, st.Config.JWTSecret)
	if err != nil {
		return internalError("encrypt agent token", err)
	}

	var ipArg, urlArg *string
	if ip != "" {
		ipArg = &ip
	}
	if agentURL != "" {
		urlArg = &agentURL
	}
	server, err := queryOne[rtServersServer](r.Context(), st.DB,
		"INSERT INTO servers (user_id, name, ip_address, agent_token, agent_token_hash, agent_url, status, is_local) "+
			"VALUES ($1, $2, $3, $4, $5, $6, 'pending', false) RETURNING *",
		c.Sub, name, ipArg, agentTokenEnc, agentTokenHash, urlArg)
	if err != nil {
		return internalError("create servers", err)
	}

	// base_url is EMPTY on every IP-only install. Interpolating it produced
	// `curl -sSL /install-agent.sh … --panel-url  --token <tok>`, whose arg
	// parser swallows --token as the panel URL and dies; and an agent installed
	// without a panel URL never phones home, so the box is invisible to the
	// fleet plan's reachability gate forever. Say so and use a placeholder.
	baseURL := strings.TrimSpace(st.Config.BaseURL)
	var installScript string
	if baseURL != "" {
		u := strings.TrimRight(baseURL, "/")
		installScript = "curl -sSL " + u + "/install-agent.sh | sudo bash -s -- \\\n  --panel-url " + u +
			" \\\n  --token " + agentToken + " \\\n  --server-id " + server.ID.String()
	} else {
		installScript = "# This panel has no BASE_URL configured (it was installed without a domain).\n" +
			"# Replace https://PANEL-ADDRESS with the address this server can reach it on,\n" +
			"# in BOTH places — an agent installed without --panel-url never checks in, and\n" +
			"# a server that never checks in can never be picked up by a fleet update.\n" +
			"curl -sSL https://PANEL-ADDRESS/install-agent.sh | sudo bash -s -- \\\n  --panel-url https://PANEL-ADDRESS \\\n  --token " +
			agentToken + " \\\n  --server-id " + server.ID.String()
	}

	callerIP := clientIP(r)
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "server.create", rtServersPtr("server"), &name, nil, callerIP, c.KeyID)
	SecurityHardeningAuditLog(r.Context(), st.DB, "server.create", &c.Email, callerIP, rtServersPtr("server"), &name, nil, nil, "warning", c.KeyID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             server.ID,
		"name":           server.Name,
		"status":         server.Status,
		"agent_token":    agentToken,
		"install_script": installScript,
	})
	return nil
}

// rtServersOwned fetches a server row the caller registered, or 404.
func rtServersOwned(r *http.Request, st *AppState, id, sub uuid.UUID, ctxName string) (*rtServersServer, error) {
	s, err := queryOpt[rtServersServer](r.Context(), st.DB, "SELECT * FROM servers WHERE id = $1 AND user_id = $2", id, sub)
	if err != nil {
		return nil, internalError(ctxName, err)
	}
	if s == nil {
		return nil, apiErr(http.StatusNotFound, "Server not found")
	}
	return s, nil
}

// rtServersGetOne: GET /api/servers/{id}.
func rtServersGetOne(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	s, err := rtServersOwned(r, st, id, c.Sub, "get_one servers")
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, s)
	return nil
}

// rtServersRemove: DELETE /api/servers/{id} — cannot delete the local server.
func rtServersRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	s, err := rtServersOwned(r, st, id, c.Sub, "remove servers")
	if err != nil {
		return err
	}
	if s.IsLocal {
		return apiErr(http.StatusBadRequest, "Cannot delete the local server")
	}
	// Cascade delete removes sites, DBs, stacks, etc.
	if _, err := execSQL(r.Context(), st.DB, "DELETE FROM servers WHERE id = $1", id); err != nil {
		return internalError("remove servers", err)
	}
	st.Agents.Invalidate(id)

	ip := clientIP(r)
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "server.delete", rtServersPtr("server"), &s.Name, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(r.Context(), st.DB, "server.delete", &c.Email, ip, rtServersPtr("server"), &s.Name, nil, nil, "critical", c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": s.Name})
	return nil
}

// rtServersRotateCertPin: POST /api/servers/{id}/rotate-cert-pin — clear the
// stored TLS fingerprint so the next checkin re-captures it (TOFU). Use when a
// cert legitimately changed; otherwise a fingerprint change signals MITM and
// is refused at checkin.
func rtServersRotateCertPin(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	s, err := rtServersOwned(r, st, id, c.Sub, "rotate cert pin")
	if err != nil {
		return err
	}
	if _, err := execSQL(r.Context(), st.DB, "UPDATE servers SET cert_fingerprint = NULL WHERE id = $1", id); err != nil {
		return internalError("rotate cert pin", err)
	}
	// So a refreshed remote client is built the next time a route needs it.
	st.Agents.Invalidate(id)

	ip := clientIP(r)
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "server.rotate_cert_pin", rtServersPtr("server"), &s.Name, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(r.Context(), st.DB, "server.rotate_cert_pin", &c.Email, ip, rtServersPtr("server"), &s.Name, nil, nil, "warning", c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "Cert pin cleared — next agent checkin will re-capture the fingerprint (TOFU).",
	})
	return nil
}

// rtServersTestConnection: POST /api/servers/{id}/test.
func rtServersTestConnection(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	s, err := rtServersOwned(r, st, id, c.Sub, "test connection")
	if err != nil {
		return err
	}
	agent, err := st.Agents.ForServer(r.Context(), id)
	if err != nil {
		return apiErr(http.StatusBadGateway, err.Error())
	}
	resp, err := agent.Get(r.Context(), "/health")
	if err != nil {
		_, _ = execSQL(r.Context(), st.DB, "UPDATE servers SET status = 'offline' WHERE id = $1", id)
		return apiErr(http.StatusBadGateway, "Agent unreachable: "+err.Error())
	}
	version, ok := jsonStr(jsonGet(resp, "version"))
	if !ok {
		version = "unknown"
	}
	_, _ = execSQL(r.Context(), st.DB,
		"UPDATE servers SET status = 'online', last_seen_at = NOW(), agent_version = $1 WHERE id = $2", version, id)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "status": "online", "version": version, "name": s.Name,
	})
	return nil
}

// rtServersUpdate: PUT /api/servers/{id} — name/IP/URL.
func rtServersUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	s, err := rtServersOwned(r, st, id, c.Sub, "update servers")
	if err != nil {
		return err
	}
	name := s.Name
	if v, ok := jsonStr(jsonGet(body, "name")); ok {
		name = v
	}
	ip := s.IPAddress
	if v, ok := jsonStr(jsonGet(body, "ip_address")); ok {
		ip = &v
	}
	u := s.AgentURL
	if v, ok := jsonStr(jsonGet(body, "agent_url")); ok {
		u = &v
	}
	updated, err := queryOne[rtServersServer](r.Context(), st.DB,
		"UPDATE servers SET name = $1, ip_address = $2, agent_url = $3 WHERE id = $4 RETURNING *", name, ip, u, id)
	if err != nil {
		return internalError("update servers", err)
	}
	// So it picks up the new URL/token.
	st.Agents.Invalidate(id)

	callerIP := clientIP(r)
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "server.update", rtServersPtr("server"), &name, nil, callerIP, c.KeyID)
	SecurityHardeningAuditLog(r.Context(), st.DB, "server.update", &c.Email, callerIP, rtServersPtr("server"), &name, nil, nil, "warning", c.KeyID)

	writeJSON(w, http.StatusOK, updated)
	return nil
}

// rtServersAPIEnvPath is where the local install persists AGENT_TOKEN.
const rtServersAPIEnvPath = "/etc/dockpanel/api.env"

// rtServersReplaceAgentToken rewrites the AGENT_TOKEN= line (Rust
// `contents.lines().map(..).join("\n")`: line endings normalised, no trailing
// newline).
func rtServersReplaceAgentToken(contents, token string) string {
	contents = strings.TrimSuffix(contents, "\n")
	lines := strings.Split(contents, "\n")
	if contents == "" {
		lines = nil
	}
	for i, l := range lines {
		l = strings.TrimSuffix(l, "\r")
		if strings.HasPrefix(l, "AGENT_TOKEN=") {
			l = "AGENT_TOKEN=" + token
		}
		lines[i] = l
	}
	return strings.Join(lines, "\n")
}

// rtServersRotateToken: POST /api/servers/{id}/rotate-token — the agent mints
// the new token, then the hash (and encrypted dial-out copy) is stored.
func rtServersRotateToken(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if _, err := rtServersOwned(r, st, id, c.Sub, "rotate token"); err != nil {
		return err
	}
	agent, err := st.Agents.ForServer(r.Context(), id)
	if err != nil {
		return agentError("get agent", err)
	}
	resp, err := agent.Post(r.Context(), "/auth/rotate-token", map[string]any{})
	if err != nil {
		return agentError("rotate token", err)
	}
	newToken, ok := jsonStr(jsonGet(resp, "new_token"))
	if !ok {
		return apiErr(http.StatusInternalServerError, "Agent did not return new token")
	}

	newHash := hashAgentToken(newToken)
	newTokenEnc, err := SecretsCryptoEncryptCredential(newToken, st.Config.JWTSecret)
	if err != nil {
		return internalError("encrypt rotated agent token", err)
	}
	if _, err := execSQL(r.Context(), st.DB,
		"UPDATE servers SET agent_token = $1, agent_token_hash = $2 WHERE id = $3", newTokenEnc, newHash, id); err != nil {
		return internalError("rotate token", err)
	}
	st.Agents.Invalidate(id)

	// The local server: update the in-memory client token (so the API keeps
	// talking to its agent immediately) and api.env (survives restart).
	if local := st.Agents.LocalServerID(); local != nil && *local == id {
		st.Agents.Local().UpdateToken(newToken)
		if contents, err := os.ReadFile(rtServersAPIEnvPath); err == nil {
			updated := rtServersReplaceAgentToken(string(contents), newToken)
			if err := os.WriteFile(rtServersAPIEnvPath, []byte(updated), 0o600); err != nil {
				slog.Warn("Failed to update api.env with new token: " + err.Error())
			} else {
				slog.Info("Updated AGENT_TOKEN in " + rtServersAPIEnvPath)
			}
		}
	}

	ip := clientIP(r)
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "server.rotate_token", rtServersPtr("server"), nil, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(r.Context(), st.DB, "server.rotate_token", &c.Email, ip, rtServersPtr("server"), nil, nil, nil, "critical", c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Agent token rotated successfully"})
	return nil
}

type rtServersUptimeResponse struct {
	Buckets       []bool `json:"buckets"`
	WindowHours   int32  `json:"window_hours"`
	BucketMinutes int32  `json:"bucket_minutes"`
}

// rtServersUptime: GET /api/servers/{id}/uptime — 24h × 10min sparkline from
// metrics_history row presence; 144 buckets, oldest first.
func rtServersUptime(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	owned, err := queryScalarOpt[bool](r.Context(), st.DB, "SELECT TRUE FROM servers WHERE id = $1 AND user_id = $2", id, c.Sub)
	if err != nil {
		return internalError("check server ownership", err)
	}
	if owned == nil {
		return apiErr(http.StatusNotFound, "Server not found")
	}
	const bucketSecs, totalBuckets = int64(600), int64(144)
	rows, err := queryAll[int64](r.Context(), st.DB,
		"SELECT DISTINCT FLOOR(EXTRACT(EPOCH FROM created_at) / 600)::bigint AS bucket "+
			"FROM metrics_history "+
			"WHERE server_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'", id)
	if err != nil {
		return internalError("query uptime buckets", err)
	}
	online := map[int64]bool{}
	for _, b := range rows {
		online[b] = true
	}
	now := time.Now().Unix() / bucketSecs
	buckets := make([]bool, 0, totalBuckets)
	for b := now - totalBuckets + 1; b <= now; b++ {
		buckets = append(buckets, online[b])
	}
	writeJSON(w, http.StatusOK, rtServersUptimeResponse{Buckets: buckets, WindowHours: 24, BucketMinutes: 10})
	return nil
}
