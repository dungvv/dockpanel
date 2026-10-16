package api

// Port of panel/backend/src/routes/ws_metrics.rs — a WebSocket that pushes live
// host metrics every 5s.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

func rtWsMetricsRegister(r *Router) {
	r.Handle("GET /api/ws/metrics", func(w http.ResponseWriter, req *http.Request) error {
		return rtWsMetricsHandler(r.St, w, req)
	})
}

var rtWsMetricsConnections atomic.Int32

const rtWsMetricsMaxConnections = 50

type rtWsMetricsWsQuery struct {
	Token *string `json:"token"`
}

// rtWsMetricsClaimsNowInvalid is true once ANY check the handshake runs would
// now reject the claims — expiry, blacklist, global revocation. Shared by the
// handshake and the per-tick recheck so the two cannot drift.
func rtWsMetricsClaimsNowInvalid(st *AppState, c *Claims) bool {
	if int64(c.Exp) < time.Now().Unix() {
		return true
	}
	if c.Jti != nil && st.isBlacklisted(*c.Jti) {
		return true
	}
	if ts, ok := st.sessionsRevokedAt(); ok && int64(c.Iat) < ts {
		return true
	}
	return false
}

// rtWsMetricsExtractToken: the query param, else the `token` cookie.
func rtWsMetricsExtractToken(q *rtWsMetricsWsQuery, r *http.Request) (string, bool) {
	if q.Token != nil && *q.Token != "" {
		return *q.Token, true
	}
	if h, ok := rtAgentCheckinHeaderStr(r, "Cookie"); ok {
		for _, c := range strings.Split(h, ";") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(c), "token="); ok && v != "" {
				return v, true
			}
		}
	}
	return "", false
}

func rtWsMetricsHeaderHasToken(r *http.Request, name, token string) bool {
	for _, v := range r.Header.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// rtWsMetricsUpgradeRejection is axum's WebSocketUpgrade extractor, which ran
// (and could reject) before the handler body.
func rtWsMetricsUpgradeRejection(r *http.Request) error {
	switch {
	case r.Method != http.MethodGet:
		return rejection(http.StatusMethodNotAllowed, "Request method must be `GET`")
	case !rtWsMetricsHeaderHasToken(r, "Connection", "upgrade"):
		return rejection(http.StatusBadRequest, "Connection header did not include 'upgrade'")
	case !strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
		return rejection(http.StatusBadRequest, "`Upgrade` header did not include 'websocket'")
	case r.Header.Get("Sec-WebSocket-Version") != "13":
		return rejection(http.StatusBadRequest, "`Sec-WebSocket-Version` header did not include '13'")
	case r.Header.Get("Sec-WebSocket-Key") == "":
		return rejection(http.StatusBadRequest, "`Sec-WebSocket-Key` header missing")
	}
	return nil
}

// rtWsMetricsHandler: GET /api/ws/metrics. Authenticates via ?token=<jwt> or
// the cookie.
func rtWsMetricsHandler(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var q rtWsMetricsWsQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	if err := rtWsMetricsUpgradeRejection(r); err != nil {
		return err
	}

	token, ok := rtWsMetricsExtractToken(&q, r)
	if !ok {
		return rejection(http.StatusUnauthorized, "Missing authentication token")
	}
	claims, err := decodeJWT(token, st.Config.JWTSecret)
	if err != nil {
		return rejection(http.StatusUnauthorized, "Invalid or expired token")
	}
	if claims.Jti != nil && st.isBlacklisted(*claims.Jti) {
		return rejection(http.StatusUnauthorized, "Token has been revoked")
	}
	// Global session revocation. This handler decodes the JWT by hand rather
	// than through authUser, so without this it was the one authenticated
	// channel panic could not close: a stolen admin token could open a NEW
	// socket after the button and stream the process list until its own expiry
	// — a live view of the operator's incident response, for the intruder it
	// was pressed against. The comparison is deliberately IDENTICAL to
	// authUser's (two gates, one invariant).
	if ts, ok := st.sessionsRevokedAt(); ok && int64(claims.Iat) < ts {
		return rejection(http.StatusUnauthorized, "Session revoked. Please log in again.")
	}
	// Live host telemetry is admin-only — the equivalent REST endpoints all
	// require AdminUser, and serverScope's no-X-Server-Id fallback resolves the
	// local server WITHOUT a role check, so gate here.
	if claims.Role != "admin" {
		return rejection(http.StatusForbidden, "Admin access required")
	}

	if rtWsMetricsConnections.Add(1) > rtWsMetricsMaxConnections {
		rtWsMetricsConnections.Add(-1)
		return rejection(http.StatusTooManyRequests, "Too many WebSocket connections")
	}
	defer rtWsMetricsConnections.Add(-1)

	// axum's WebSocketUpgrade performs no Origin check; the JWT above is the
	// gate. Kept identical so a proxy that rewrites Host keeps working.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return nil // Accept already wrote the failure response.
	}
	rtWsMetricsHandleSocket(st, conn, agent, claims)
	return nil
}

func rtWsMetricsMarshal(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func rtWsMetricsHandleSocket(st *AppState, conn *websocket.Conn, agent AgentHandle, claims *Claims) {
	slog.Debug("WebSocket metrics client connected")
	// Shutdown must be able to win mid-cycle, not just at the top of the loop:
	// one agent.Get already budgets up to 60s, beyond the 20s drain window.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := context.AfterFunc(st.Shutdown, cancel)
	defer stop()

	// Incoming frames. coder/websocket closes the connection when a Read's
	// context expires, so the 5s wait is done here on the channel instead.
	// true = keep going (a data frame), false = close/error.
	// Its own context, cancelled only on return: a cancelled Read context makes
	// coder/websocket drop the connection, which would pre-empt the close frame
	// sent below on shutdown.
	readCtx, readCancel := context.WithCancel(context.Background())
	defer readCancel()
	frames := make(chan bool, 1)
	go func() {
		for {
			_, _, err := conn.Read(readCtx)
			select {
			case frames <- err == nil:
			case <-readCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

loop:
	for {
		// Re-validate every tick, not just at handshake: logout, the panic
		// button and blacklisting closed the door to NEW connections but left
		// an open socket streaming for as long as TCP stayed up — unbounded even
		// by the token's own expiry.
		if rtWsMetricsClaimsNowInvalid(st, claims) {
			slog.Info("WebSocket metrics: session no longer valid, closing")
			break
		}

		var wg sync.WaitGroup
		results := make([]any, 4)
		for i, p := range []string{"/system/info", "/system/processes", "/system/network", "/apps/gpu-info"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if v, err := agent.Get(ctx, p); err == nil {
					results[i] = v
				}
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			slog.Info("WebSocket metrics: shutdown signal received, closing")
			break
		}
		payload := map[string]any{
			"type":      "metrics",
			"system":    results[0],
			"processes": results[1],
			"network":   results[2],
			"gpu":       results[3],
		}
		if err := conn.Write(ctx, websocket.MessageText, rtWsMetricsMarshal(payload)); err != nil {
			break // client disconnected (or shutdown)
		}

		// Also check for incoming close frames: a close/error ends the loop, a
		// data frame or 5s of silence continues it.
		select {
		case ok := <-frames:
			if !ok {
				break loop
			}
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			slog.Info("WebSocket metrics: shutdown signal received, closing")
			break loop
		}
	}

	// Explicit close frame so the client doesn't linger. Timed: a black-holed
	// peer can stall this write on kernel retransmission, keeping this
	// connection — and the graceful drain waiting on it — alive past shutdown.
	done := make(chan struct{})
	go func() {
		_ = conn.Close(websocket.StatusNormalClosure, "")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = conn.CloseNow()
	}
	slog.Debug("WebSocket metrics client disconnected")
}
