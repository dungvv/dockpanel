package api

// Port of panel/backend/src/routes/agent_checkin.rs — the remote agent's
// phone-home. Its auth is its OWN (not authenticateAgent): server_id comes from
// the BODY, the row is fetched by id, and the token is compared in constant
// time.

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtAgentCheckinRegister(r *Router) {
	r.Handle("POST /api/agent/checkin", func(w http.ResponseWriter, req *http.Request) error {
		return rtAgentCheckinCheckin(r.St, w, req)
	})
}

type rtAgentCheckinCheckinRequest struct {
	ServerID     string   `json:"server_id"`
	OSInfo       *string  `json:"os_info"`
	Hostname     *string  `json:"hostname"`
	CPUCores     *int32   `json:"cpu_cores"`
	RAMMB        *int32   `json:"ram_mb"`
	DiskGB       *int32   `json:"disk_gb"`
	AgentVersion *string  `json:"agent_version"`
	DiskUsedGB   *int32   `json:"disk_used_gb"`
	DiskUsagePct *float32 `json:"disk_usage_pct"`
	// Live metrics (stored in the server record for dashboard display)
	CPUUsage   *float32 `json:"cpu_usage"`
	MemUsedMB  *int64   `json:"mem_used_mb"`
	UptimeSecs *int64   `json:"uptime_secs"`
	// Unix seconds from the agent. Replay prevention: >120s drift is refused.
	Timestamp *int64 `json:"timestamp"`
	// SHA-256 hex of the agent's inbound TLS cert. Captured on first checkin
	// (TOFU), validated afterwards. A mismatch is a potential MITM or a
	// re-provisioned agent; the admin must rotate the pin via
	// POST /api/servers/{id}/rotate-cert-pin.
	CertFingerprint *string `json:"cert_fingerprint"`
}

// rtAgentCheckinHeaderStr is `headers.get(name).and_then(|v| v.to_str().ok())`:
// a value with bytes outside visible ASCII reads as absent.
func rtAgentCheckinHeaderStr(r *http.Request, name string) (string, bool) {
	vals := r.Header.Values(name)
	if len(vals) == 0 {
		return "", false
	}
	v := vals[0]
	for i := 0; i < len(v); i++ {
		if b := v[i]; b != '\t' && (b < 0x20 || b >= 0x7f) {
			return "", false
		}
	}
	return v, true
}

func rtAgentCheckinIsHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// rtAgentCheckinCheckin: POST /api/agent/checkin — system info + heartbeat.
func rtAgentCheckinCheckin(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var body rtAgentCheckinCheckinRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	auth, _ := rtAgentCheckinHeaderStr(r, "Authorization")
	token, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok {
		return apiErr(http.StatusUnauthorized, "Missing authorization")
	}
	serverID, err := uuid.Parse(body.ServerID)
	if err != nil {
		return apiErr(http.StatusBadRequest, "Invalid server_id")
	}

	// Hash-based; plaintext fallback for unmigrated rows.
	tokenHash := hashAgentToken(token)
	existing, err := queryOpt[Tup2[*string, string]](r.Context(), st.DB,
		"SELECT agent_token_hash, agent_token FROM servers WHERE id = $1", serverID)
	if err != nil {
		return internalError("checkin", err)
	}
	if existing == nil {
		return apiErr(http.StatusNotFound, "Server not found")
	}
	// Constant-time comparison to prevent timing-based token brute force.
	var valid bool
	if existing.A != nil {
		valid = subtle.ConstantTimeCompare([]byte(*existing.A), []byte(tokenHash)) == 1
	} else {
		valid = subtle.ConstantTimeCompare([]byte(existing.B), []byte(token)) == 1
	}
	if !valid {
		return apiErr(http.StatusUnauthorized, "Invalid token")
	}

	// Replay prevention (>120s drift). Requests without a timestamp are
	// accepted for older agents.
	if body.Timestamp != nil {
		drift := time.Now().Unix() - *body.Timestamp
		if drift < 0 {
			drift = -drift
		}
		if drift > 120 {
			slog.Warn(fmt.Sprintf("Checkin rejected for server %s: timestamp drift %ds (limit 120s)", serverID, drift))
			return apiErr(http.StatusBadRequest, "Request timestamp too old")
		}
	}

	// Cert fingerprint pinning (Trust On First Use): nothing stored → capture;
	// match → no-op; differs → treat as MITM and refuse. The admin re-captures
	// via POST /api/servers/{id}/rotate-cert-pin.
	if body.CertFingerprint != nil {
		fp := strings.ToLower(strings.TrimSpace(*body.CertFingerprint))
		if !rtAgentCheckinIsHex64(fp) {
			return apiErr(http.StatusBadRequest, "cert_fingerprint must be a 64-char lowercase hex SHA-256")
		}
		stored, err := queryOne[*string](r.Context(), st.DB, "SELECT cert_fingerprint FROM servers WHERE id = $1", serverID)
		if err != nil {
			return internalError("checkin cert lookup", err)
		}
		switch {
		case stored == nil:
			if _, err := execSQL(r.Context(), st.DB, "UPDATE servers SET cert_fingerprint = $1 WHERE id = $2", fp, serverID); err != nil {
				return internalError("checkin cert capture", err)
			}
			slog.Info(fmt.Sprintf("Captured cert fingerprint for server %s: %s", serverID, fp))
		case subtle.ConstantTimeCompare([]byte(*stored), []byte(fp)) == 1:
			// Match — nothing to do.
		default:
			slog.Error(fmt.Sprintf("Checkin REJECTED for server %s: cert fingerprint mismatch (possible MITM or agent re-provisioned). Admin must rotate the pin.", serverID))
			return apiErr(http.StatusForbidden, "cert fingerprint mismatch — rotate the pin to accept a new cert")
		}
	}

	// Rate limit: max 120 requests per minute per server_id. Rust inlined an
	// identical copy of this window; the core helper is the same arithmetic on
	// the same map.
	if err := st.agentRateLimit(serverID); err != nil {
		return err
	}

	// Client IP — note: x-forwarded-for FIRST here, unlike clientIP.
	var ip *string
	if v, ok := rtAgentCheckinHeaderStr(r, "X-Forwarded-For"); ok {
		first, _, _ := strings.Cut(v, ",")
		s := strings.TrimSpace(first)
		ip = &s
	} else if v, ok := rtAgentCheckinHeaderStr(r, "X-Real-Ip"); ok {
		ip = &v
	}

	var memUsagePct *float32
	if body.MemUsedMB != nil && body.RAMMB != nil && *body.RAMMB > 0 {
		p := (float32(*body.MemUsedMB) / float32(*body.RAMMB)) * 100.0
		memUsagePct = &p
	}

	if _, err := execSQL(r.Context(), st.DB,
		"UPDATE servers SET "+
			"status = 'online', "+
			"last_seen_at = NOW(), "+
			"ip_address = COALESCE($2, ip_address), "+
			"os_info = COALESCE($3, os_info), "+
			"cpu_cores = COALESCE($4, cpu_cores), "+
			"ram_mb = COALESCE($5, ram_mb), "+
			"disk_gb = COALESCE($6, disk_gb), "+
			"agent_version = COALESCE($7, agent_version), "+
			"cpu_usage = COALESCE($8, cpu_usage), "+
			"mem_used_mb = COALESCE($9, mem_used_mb), "+
			"uptime_secs = COALESCE($10, uptime_secs), "+
			"disk_used_gb = COALESCE($11, disk_used_gb), "+
			"disk_usage_pct = COALESCE($12, disk_usage_pct), "+
			"mem_usage_pct = COALESCE($13, mem_usage_pct) "+
			"WHERE id = $1",
		serverID, ip, body.OSInfo, body.CPUCores, body.RAMMB, body.DiskGB, body.AgentVersion,
		body.CPUUsage, body.MemUsedMB, body.UptimeSecs, body.DiskUsedGB, body.DiskUsagePct, memUsagePct); err != nil {
		return internalError("checkin", err)
	}

	// Performance metrics time series.
	if body.CPUUsage != nil {
		_, _ = execSQL(r.Context(), st.DB, "INSERT INTO metrics (server_id, metric_type, value) VALUES ($1, 'cpu', $2)", serverID, float64(*body.CPUUsage))
	}
	if body.MemUsedMB != nil {
		_, _ = execSQL(r.Context(), st.DB, "INSERT INTO metrics (server_id, metric_type, value) VALUES ($1, 'memory_mb', $2)", serverID, float64(*body.MemUsedMB))
	}
	if body.DiskUsagePct != nil {
		_, _ = execSQL(r.Context(), st.DB, "INSERT INTO metrics (server_id, metric_type, value) VALUES ($1, 'disk_pct', $2)", serverID, float64(*body.DiskUsagePct))
	}

	// The server just checked in: it is online, so resolve its offline alert.
	_, _ = execSQL(r.Context(), st.DB,
		"UPDATE alert_state SET current_state = 'ok', fired_at = NULL, last_notified_at = NULL "+
			"WHERE server_id = $1 AND alert_type = 'offline' AND current_state = 'firing'", serverID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}
