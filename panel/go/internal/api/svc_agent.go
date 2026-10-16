package api

// Port of panel/backend/src/services/agent.rs: the local (unix socket) and
// remote (HTTPS, fingerprint-pinned) agent clients, the AgentHandle both
// satisfy, and the AgentRegistry that dispatches by server id.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// After this many consecutive failures requests fast-fail without
	// attempting a connection, for agentCircuitBreakerResetSecs.
	agentCircuitBreakerThreshold = 5
	agentCircuitBreakerResetSecs = 30
	// Concurrent quick requests (prevents FD exhaustion) / long operations.
	agentMaxConcurrentConnections = 20
	agentMaxLongConnections       = 5
	// Maximum response size from an agent (50MB).
	agentMaxResponseSize = 50 * 1024 * 1024
	// Effectively-disabled total timeout for streamed remote requests: the
	// real bound is the idle watchdog in agentDriveIdleBounded, which is the
	// correct thing to measure for a stream anyway.
	agentStreamTotalTimeout = 24 * time.Hour
)

// AgentDBRestoreTimeoutSecs is how long a database restore/import may occupy
// a request before the panel stops waiting.
//
// Deliberately BELOW the server's own 300s ceiling (the timeout middleware and
// nginx's proxy_read_timeout) rather than matched to the agent's 600s work
// budget: a handler that waited 600s would be cut off by its own server and
// answer a bodyless 504 no client can explain. Waiting slightly less means the
// timeout is OURS — and a timeout here does not mean the import failed, it
// means we stopped watching. agentError cannot make that distinction, so the
// callers of this constant handle AgentErrRequest themselves. ⚠ A panel behind
// Cloudflare's proxy is cut at 100s regardless.
const AgentDBRestoreTimeoutSecs = 270

// AgentDrillTimeoutSecs bounds a backup drill (scratch container, full
// restore, probe; the agent's slowest leg is 360s). Drills always run in a
// detached goroutine, so no 300s request ceiling applies — the only cost of
// headroom is how long a stuck drill occupies the long-op semaphore.
const AgentDrillTimeoutSecs = 420

// AgentErrorKind mirrors the Rust AgentError variants.
type AgentErrorKind int

const (
	AgentErrConnection AgentErrorKind = iota
	AgentErrRequest
	AgentErrResponse
	AgentErrStatus // Code + Msg (the raw body)
	AgentErrParse
	AgentErrCircuitOpen
	AgentErrNotFound
)

// AgentError is services::agent::AgentError. Pass it to agentError() — never
// stringify it into a 502, that is what threw away the agent's own 4xx.
type AgentError struct {
	Kind AgentErrorKind
	Code int // AgentErrStatus only
	Msg  string
}

func (e *AgentError) Error() string {
	switch e.Kind {
	case AgentErrConnection:
		return "agent connection failed: " + e.Msg
	case AgentErrRequest:
		return "agent request failed: " + e.Msg
	case AgentErrResponse:
		return "agent response error: " + e.Msg
	case AgentErrStatus:
		return fmt.Sprintf("agent returned %d: %s", e.Code, e.Msg)
	case AgentErrParse:
		return "agent response parse error: " + e.Msg
	case AgentErrCircuitOpen:
		return "agent circuit breaker open: " + e.Msg
	default:
		return "agent not found: " + e.Msg
	}
}

func agentErr(k AgentErrorKind, msg string) *AgentError { return &AgentError{Kind: k, Msg: msg} }

// agentCircuitBreaker is shared circuit-breaker + concurrency state.
type agentCircuitBreaker struct {
	sem          chan struct{}
	longSem      chan struct{}
	failures     atomic.Uint32
	lastFailUnix atomic.Uint64
}

func newAgentCircuitBreaker() *agentCircuitBreaker {
	return &agentCircuitBreaker{
		sem:     make(chan struct{}, agentMaxConcurrentConnections),
		longSem: make(chan struct{}, agentMaxLongConnections),
	}
}

func (cb *agentCircuitBreaker) check() error {
	f := cb.failures.Load()
	if f >= agentCircuitBreakerThreshold {
		now := uint64(time.Now().Unix())
		last := cb.lastFailUnix.Load()
		if now-last < agentCircuitBreakerResetSecs {
			return agentErr(AgentErrCircuitOpen, fmt.Sprintf(
				"agent unreachable (%d consecutive failures), retry in %ds", f, agentCircuitBreakerResetSecs-(now-last)))
		}
		slog.Info("agent circuit breaker half-open, allowing probe request")
	}
	return nil
}

func (cb *agentCircuitBreaker) recordSuccess() { cb.failures.Store(0) }
func (cb *agentCircuitBreaker) recordFailure() {
	cb.failures.Add(1)
	cb.lastFailUnix.Store(uint64(time.Now().Unix()))
}

// record applies the local clients' rule: success resets, only a Connection
// failure counts toward opening the breaker.
func (cb *agentCircuitBreaker) record(err error) {
	var ae *AgentError
	switch {
	case err == nil:
		cb.recordSuccess()
	case errors.As(err, &ae) && ae.Kind == AgentErrConnection:
		cb.recordFailure()
	}
}

// agentPermitWithin takes a permit within the caller's budget and returns
// what is left of it plus the release func.
//
// The budget a caller names is the time it has before something above it
// stops waiting (AgentDBRestoreTimeoutSecs is 270 so the 300s ceiling never
// fires first). Queuing outside that budget defeats it: the work started late,
// ran its full allowance on top, and the server cut the request off with a
// bodyless 504. So the wait is inside the budget, and a request that never got
// a permit says THAT rather than borrowing the sentence for work that overran.
func agentPermitWithin(ctx context.Context, sem chan struct{}, budget time.Duration, pool string) (time.Duration, func(), error) {
	start := time.Now()
	t := time.NewTimer(budget)
	defer t.Stop()
	select {
	case sem <- struct{}{}:
		return max(budget-time.Since(start), 0), func() { <-sem }, nil
	case <-t.C:
		return 0, nil, agentErr(AgentErrRequest, fmt.Sprintf(
			"timed out after %ds waiting for a free %s slot; the operation never started", int(budget.Seconds()), pool))
	case <-ctx.Done():
		return 0, nil, agentErr(AgentErrRequest, ctx.Err().Error())
	}
}

// agentDriveIdleBounded runs fn under an IDLE deadline rather than a total
// one: ticks is bumped per streamed line, the watchdog re-arms each window and
// only gives up if the counter did not move across a whole window — a slow
// but talking operation completes, a wedged one fails in bounded time.
func agentDriveIdleBounded(ctx context.Context, idleSecs uint64, ticks *atomic.Uint64, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- fn(ctx) }()
	idle := time.Duration(idleSecs) * time.Second
	for {
		before := ticks.Load()
		t := time.NewTimer(idle)
		select {
		case err := <-done:
			t.Stop()
			return err
		case <-t.C:
			// A result ready in the same instant reports itself, not "idle".
			select {
			case err := <-done:
				return err
			default:
			}
			if ticks.Load() == before {
				cancel()
				return agentErr(AgentErrRequest, fmt.Sprintf("agent stream produced no output for %ds", idleSecs))
			}
		}
	}
}

// AgentHandle is a handle to one agent, the same API regardless of transport
// (Rust enum AgentHandle::{Local, Remote}). `_, local := h.(*AgentClient)`
// is the Go spelling of matching the Local arm.
//
// JSON results are decoded with UseNumber into `any` (map[string]any,
// []any, json.Number, string, bool, nil) — the serde_json::Value equivalent;
// read them with the jsonGet/jsonStr/... helpers in core_helpers.go.
type AgentHandle interface {
	Get(ctx context.Context, path string) (any, error)
	Post(ctx context.Context, path string, body any) (any, error) // body nil = no body
	Put(ctx context.Context, path string, body any) (any, error)
	PutLong(ctx context.Context, path string, body any, timeoutSecs uint64) (any, error)
	Delete(ctx context.Context, path string) (any, error)
	// GetBytes returns the raw body and the Content-Disposition header, if any.
	GetBytes(ctx context.Context, path string) ([]byte, *string, error)
	PostLong(ctx context.Context, path string, body any, timeoutSecs uint64) (any, error)
	// PostLongNDJSON streams NDJSON; idleTimeoutSecs bounds SILENCE, not total
	// runtime. onLine is called once per parsed line.
	PostLongNDJSON(ctx context.Context, path string, body any, idleTimeoutSecs uint64, onLine func(any)) error
	Token() string
}

func agentDecodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, agentErr(AgentErrParse, err.Error())
	}
	// serde_json::from_slice rejects trailing non-whitespace.
	if _, err := dec.Token(); err != io.EOF {
		return nil, agentErr(AgentErrParse, "trailing characters")
	}
	return v, nil
}

func agentEncodeBody(body any) (io.Reader, error) {
	if body == nil {
		return http.NoBody, nil
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, agentErr(AgentErrRequest, "JSON serialize error: "+err.Error())
	}
	return bytes.NewReader(b), nil
}

// agentNDJSON reads newline-delimited JSON, calling onLine per parsed line;
// unparseable lines are skipped, a trailing partial line is parsed at EOF.
func agentNDJSON(r io.Reader, onLine func(any)) error {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if err == nil {
			line = strings.TrimSuffix(line, "\n")
			if line != "" {
				if v, perr := agentDecodeJSON([]byte(line)); perr == nil {
					onLine(v)
				}
			}
			continue
		}
		if err == io.EOF {
			if t := strings.TrimSpace(line); t != "" {
				if v, perr := agentDecodeJSON([]byte(t)); perr == nil {
					onLine(v)
				}
			}
			return nil
		}
		return agentErr(AgentErrResponse, err.Error())
	}
}

// ---------------------------------------------------------------------------
// AgentClient — the local agent over its unix socket
// ---------------------------------------------------------------------------

// AgentClient talks to the local agent via a Unix domain socket.
type AgentClient struct {
	socketPath string
	tokenMu    sync.RWMutex
	token      string
	cb         *agentCircuitBreaker
	http       *http.Client
}

// NewAgentClient builds the local client. One connection per request, as the
// Rust client handshakes a fresh hyper connection each time.
func NewAgentClient(socketPath, token string) *AgentClient {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	return &AgentClient{socketPath: socketPath, token: token, cb: newAgentCircuitBreaker(), http: &http.Client{Transport: tr}}
}

// Token is the current token (AgentClient::current_token).
func (c *AgentClient) Token() string {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.token
}

// UpdateToken replaces the agent token after rotation.
func (c *AgentClient) UpdateToken(t string) {
	c.tokenMu.Lock()
	c.token = t
	c.tokenMu.Unlock()
}

// do sends one request; failures to connect are Connection, everything after
// the connection is up is Request/Response.
func (c *AgentClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	rd, err := agentEncodeBody(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, rd)
	if err != nil {
		return nil, agentErr(AgentErrRequest, err.Error())
	}
	req.Header.Set("authorization", "Bearer "+c.Token())
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return nil, agentErr(AgentErrConnection, err.Error())
		}
		return nil, agentErr(AgentErrRequest, err.Error())
	}
	return resp, nil
}

// requestInner is request_inner: stream-limited body collection, non-2xx →
// Status, else JSON.
func (c *AgentClient) requestInner(ctx context.Context, method, path string, body any) (any, error) {
	resp, err := c.do(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, agentMaxResponseSize+1))
	if err != nil {
		return nil, agentErr(AgentErrResponse, err.Error())
	}
	if len(b) > agentMaxResponseSize {
		return nil, agentErr(AgentErrResponse, fmt.Sprintf("agent response too large (limit: %dMB)", agentMaxResponseSize/(1024*1024)))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &AgentError{Kind: AgentErrStatus, Code: resp.StatusCode, Msg: strings.ToValidUTF8(string(b), "�")}
	}
	return agentDecodeJSON(b)
}

// timed runs fn on the given pool within budget, then records the outcome.
func (c *AgentClient) timed(ctx context.Context, sem chan struct{}, pool string, budget time.Duration, timeoutMsg string, fn func(ctx context.Context) (any, error)) (any, error) {
	if err := c.cb.check(); err != nil {
		return nil, err
	}
	remaining, release, err := agentPermitWithin(ctx, sem, budget, pool)
	if err != nil {
		return nil, err
	}
	defer release()
	tctx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	v, err := fn(tctx)
	if err != nil && tctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
		err = agentErr(AgentErrRequest, timeoutMsg)
	}
	c.cb.record(err)
	return v, err
}

func (c *AgentClient) request(ctx context.Context, method, path string, body any) (any, error) {
	return c.timed(ctx, c.cb.sem, "connection", 60*time.Second, "agent request timed out after 60s",
		func(ctx context.Context) (any, error) { return c.requestInner(ctx, method, path, body) })
}

func (c *AgentClient) Get(ctx context.Context, path string) (any, error) {
	return c.request(ctx, "GET", path, nil)
}

func (c *AgentClient) Put(ctx context.Context, path string, body any) (any, error) {
	return c.request(ctx, "PUT", path, body)
}

// PutLong is PUT with an explicit timeout on the long pool: some PUTs do real
// work (editing an app's env recreates its container and may copy its data).
func (c *AgentClient) PutLong(ctx context.Context, path string, body any, timeoutSecs uint64) (any, error) {
	return c.timed(ctx, c.cb.longSem, "long operation", time.Duration(timeoutSecs)*time.Second,
		fmt.Sprintf("agent request timed out after %ds", timeoutSecs),
		func(ctx context.Context) (any, error) { return c.requestInner(ctx, "PUT", path, body) })
}

func (c *AgentClient) Delete(ctx context.Context, path string) (any, error) {
	return c.request(ctx, "DELETE", path, nil)
}

func (c *AgentClient) Post(ctx context.Context, path string, body any) (any, error) {
	return c.request(ctx, "POST", path, body)
}

// PostLong is POST with a custom timeout on a separate 5-permit pool so long
// ops (docker builds…) don't starve quick requests.
func (c *AgentClient) PostLong(ctx context.Context, path string, body any, timeoutSecs uint64) (any, error) {
	return c.timed(ctx, c.cb.longSem, "long operation", time.Duration(timeoutSecs)*time.Second,
		fmt.Sprintf("agent request timed out after %ds", timeoutSecs),
		func(ctx context.Context) (any, error) { return c.requestInner(ctx, "POST", path, body) })
}

// GetBytes is a GET returning raw bytes (file downloads), 120s budget.
func (c *AgentClient) GetBytes(ctx context.Context, path string) ([]byte, *string, error) {
	var cd *string
	v, err := c.timed(ctx, c.cb.sem, "connection", 120*time.Second, "agent request timed out after 120s",
		func(ctx context.Context) (any, error) {
			resp, err := c.do(ctx, "GET", path, nil)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if h := resp.Header.Get("content-disposition"); h != "" {
				cd = &h
			}
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, agentErr(AgentErrResponse, err.Error())
			}
			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				return nil, &AgentError{Kind: AgentErrStatus, Code: resp.StatusCode, Msg: strings.ToValidUTF8(string(b), "�")}
			}
			return b, nil
		})
	if err != nil {
		return nil, nil, err
	}
	return v.([]byte), cd, nil
}

// PostLongNDJSON is POST with a streamed NDJSON response.
//
// idleTimeoutSecs bounds **silence, not total runtime** — the clock is
// re-armed every time a line arrives. A flat cap cannot be set correctly for
// a stream: apt-get upgrade finishes in 40s on one box and legitimately runs
// for most of an hour on a slow link, so the old 300s ceiling failed the long
// ones while apt carried on underneath. Going quiet is the evidence, not time.
func (c *AgentClient) PostLongNDJSON(ctx context.Context, path string, body any, idleTimeoutSecs uint64, onLine func(any)) error {
	if err := c.cb.check(); err != nil {
		return err
	}
	// A stream has no total budget, so the queue wait is bounded by the same
	// idle figure: a stream that cannot start inside its own silence budget is
	// stalled, and saying so beats waiting for ever.
	_, release, err := agentPermitWithin(ctx, c.cb.longSem, time.Duration(idleTimeoutSecs)*time.Second, "long operation")
	if err != nil {
		return err
	}
	defer release()
	var ticks atomic.Uint64
	err = agentDriveIdleBounded(ctx, idleTimeoutSecs, &ticks, func(ctx context.Context) error {
		resp, err := c.do(ctx, "POST", path, body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return agentErr(AgentErrResponse, err.Error())
			}
			return &AgentError{Kind: AgentErrStatus, Code: resp.StatusCode, Msg: strings.ToValidUTF8(string(b), "�")}
		}
		return agentNDJSON(resp.Body, func(v any) { ticks.Add(1); onLine(v) })
	})
	c.cb.record(err)
	return err
}

// ---------------------------------------------------------------------------
// AgentRemoteClient — a fleet member's agent over HTTPS
// ---------------------------------------------------------------------------

// AgentRemoteClient talks to a remote agent via HTTP/HTTPS.
type AgentRemoteClient struct {
	baseURL string
	token   string
	http    *http.Client
	cb      *agentCircuitBreaker
}

// agentPinnedVerifier trusts exactly one self-signed cert, identified by the
// SHA-256 hex fingerprint of its DER encoding (TOFU: the panel captures it on
// the agent's first check-in). Go still verifies the handshake signature
// against that leaf even with InsecureSkipVerify, as rustls' verifier did.
func agentPinnedVerifier(expectedHex string) func([][]byte, [][]*x509.Certificate) error {
	expected := strings.ToLower(expectedHex)
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("agent presented no certificate")
		}
		sum := sha256.Sum256(raw[0])
		actual := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1 {
			return nil
		}
		return fmt.Errorf("agent cert fingerprint mismatch: expected %s, got %s", expected, actual)
	}
}

// NewAgentRemoteClient builds a client that optionally pins the agent's TLS
// cert. With a fingerprint, any cert whose DER SHA-256 differs is rejected —
// stronger than CA trust for self-signed agent certs. Without one, it falls
// back to the legacy AGENT_TLS_VERIFY=insecure flag so old agents (without
// fingerprint reporting) still work while their first check-in captures a pin.
func NewAgentRemoteClient(baseURL, token string, fingerprint *string) *AgentRemoteClient {
	tlsCfg := &tls.Config{}
	if fingerprint != nil {
		tlsCfg.InsecureSkipVerify = true // replaced by the pin check below
		tlsCfg.VerifyPeerCertificate = agentPinnedVerifier(*fingerprint)
	} else {
		insecure := os.Getenv("AGENT_TLS_VERIFY") == "insecure"
		if !insecure {
			slog.Warn(fmt.Sprintf("Remote agent %s has no pinned fingerprint — TLS will require a valid CA cert. If the agent is self-signed (default), wait for first checkin to capture the pin, or set AGENT_TLS_VERIFY=insecure temporarily.", baseURL))
		}
		tlsCfg.InsecureSkipVerify = insecure
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	tr.MaxIdleConnsPerHost = 5
	return &AgentRemoteClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		// Per-request deadlines come from contexts (60s default, see below).
		http: &http.Client{Transport: tr},
		cb:   newAgentCircuitBreaker(),
	}
}

func (c *AgentRemoteClient) Token() string { return c.token }

// sendError classifies a failed send and only counts the ones that mean
// "offline". ⚠ A timeout is not an unreachable agent: every remote failure
// used to become Connection, which trips the breaker and tells the operator
// "agent unreachable" about a busy agent answering perfectly well. An elapsed
// clock is a Request, which the breaker does not count.
func (c *AgentRemoteClient) sendError(err error) error {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return agentErr(AgentErrRequest, err.Error())
	}
	c.cb.recordFailure()
	return agentErr(AgentErrConnection, err.Error())
}

// send performs one request under timeout and returns status + body. Any
// response at all counts as success for the breaker (as reqwest's did).
func (c *AgentRemoteClient) send(ctx context.Context, method, path string, body any, timeout time.Duration, limit bool) (*http.Response, []byte, error) {
	rd, err := agentEncodeBody(body)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	if err != nil {
		return nil, nil, agentErr(AgentErrRequest, err.Error())
	}
	req.Header.Set("authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, c.sendError(err)
	}
	defer resp.Body.Close()
	c.cb.recordSuccess()
	var r io.Reader = resp.Body
	if limit {
		r = io.LimitReader(resp.Body, agentMaxResponseSize+1)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, agentErr(AgentErrResponse, err.Error())
	}
	if limit && len(b) > agentMaxResponseSize {
		return nil, nil, agentErr(AgentErrResponse, fmt.Sprintf("agent response too large: %d bytes", len(b)))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, &AgentError{Kind: AgentErrStatus, Code: resp.StatusCode, Msg: strings.ToValidUTF8(string(b), "�")}
	}
	return resp, b, nil
}

func (c *AgentRemoteClient) request(ctx context.Context, method, path string, body any) (any, error) {
	if err := c.cb.check(); err != nil {
		return nil, err
	}
	// 60s, matching this client's own request timeout, so the wait cannot
	// outlast the call it is waiting to make.
	_, release, err := agentPermitWithin(ctx, c.cb.sem, 60*time.Second, "connection")
	if err != nil {
		return nil, err
	}
	defer release()
	_, b, err := c.send(ctx, method, path, body, 60*time.Second, true)
	if err != nil {
		return nil, err
	}
	return agentDecodeJSON(b)
}

func (c *AgentRemoteClient) long(ctx context.Context, method, path string, body any, timeoutSecs uint64) (any, error) {
	if err := c.cb.check(); err != nil {
		return nil, err
	}
	// The LONG pool, matching the local twin. Taking the quick pool meant
	// agentMaxLongConnections bounded nothing on a fleet — every remote build,
	// import and restore competed with ordinary requests for the same permits.
	remaining, release, err := agentPermitWithin(ctx, c.cb.longSem, time.Duration(timeoutSecs)*time.Second, "long operation")
	if err != nil {
		return nil, err
	}
	defer release()
	_, b, err := c.send(ctx, method, path, body, remaining, false)
	if err != nil {
		return nil, err
	}
	return agentDecodeJSON(b)
}

func (c *AgentRemoteClient) Get(ctx context.Context, path string) (any, error) {
	return c.request(ctx, "GET", path, nil)
}
func (c *AgentRemoteClient) Post(ctx context.Context, path string, body any) (any, error) {
	return c.request(ctx, "POST", path, body)
}
func (c *AgentRemoteClient) Put(ctx context.Context, path string, body any) (any, error) {
	return c.request(ctx, "PUT", path, body)
}
func (c *AgentRemoteClient) Delete(ctx context.Context, path string) (any, error) {
	return c.request(ctx, "DELETE", path, nil)
}

// PutLong is the remote twin of AgentClient.PutLong.
func (c *AgentRemoteClient) PutLong(ctx context.Context, path string, body any, timeoutSecs uint64) (any, error) {
	return c.long(ctx, "PUT", path, body, timeoutSecs)
}

func (c *AgentRemoteClient) PostLong(ctx context.Context, path string, body any, timeoutSecs uint64) (any, error) {
	return c.long(ctx, "POST", path, body, timeoutSecs)
}

func (c *AgentRemoteClient) GetBytes(ctx context.Context, path string) ([]byte, *string, error) {
	if err := c.cb.check(); err != nil {
		return nil, nil, err
	}
	remaining, release, err := agentPermitWithin(ctx, c.cb.sem, 120*time.Second, "connection")
	if err != nil {
		return nil, nil, err
	}
	defer release()
	resp, b, err := c.send(ctx, "GET", path, nil, remaining, false)
	if err != nil {
		return nil, nil, err
	}
	var cd *string
	if h := resp.Header.Get("content-disposition"); h != "" {
		cd = &h
	}
	return b, cd, nil
}

// PostLongNDJSON is the remote streamed POST; idle-bounded like the local one.
func (c *AgentRemoteClient) PostLongNDJSON(ctx context.Context, path string, body any, idleTimeoutSecs uint64, onLine func(any)) error {
	if err := c.cb.check(); err != nil {
		return err
	}
	_, release, err := agentPermitWithin(ctx, c.cb.longSem, time.Duration(idleTimeoutSecs)*time.Second, "long operation")
	if err != nil {
		return err
	}
	defer release()
	var ticks atomic.Uint64
	err = agentDriveIdleBounded(ctx, idleTimeoutSecs, &ticks, func(ctx context.Context) error {
		rd, err := agentEncodeBody(body)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, agentStreamTotalTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+path, rd)
		if err != nil {
			return agentErr(AgentErrRequest, err.Error())
		}
		req.Header.Set("authorization", "Bearer "+c.token)
		if body != nil {
			req.Header.Set("content-type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return agentErr(AgentErrConnection, err.Error())
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return agentErr(AgentErrResponse, err.Error())
			}
			return &AgentError{Kind: AgentErrStatus, Code: resp.StatusCode, Msg: strings.ToValidUTF8(string(b), "�")}
		}
		return agentNDJSON(resp.Body, func(v any) { ticks.Add(1); onLine(v) })
	})
	// Success is recorded only once the stream actually completed: recording
	// it when headers arrived counted a connection that died mid-body as a
	// healthy round-trip.
	c.cb.record(err)
	return err
}

// ---------------------------------------------------------------------------
// AgentRegistry — local + remote agents, dispatched by server id
// ---------------------------------------------------------------------------

// AgentRegistry manages the local agent plus cached remote clients.
type AgentRegistry struct {
	local         *AgentClient
	localMu       sync.RWMutex
	localServerID *uuid.UUID
	cacheMu       sync.RWMutex
	remoteCache   map[uuid.UUID]*AgentRemoteClient
	db            *pgxpool.Pool
	// Key servers.agent_token is encrypted under. Held here because ForServer
	// is the single site that opens a stored dial-out token; an env read
	// inside the method would be a second source of truth for that key.
	jwtSecret string
}

func NewAgentRegistry(local *AgentClient, db *pgxpool.Pool, jwtSecret string) *AgentRegistry {
	return &AgentRegistry{local: local, remoteCache: map[uuid.UUID]*AgentRemoteClient{}, db: db, jwtSecret: jwtSecret}
}

// JWTSecret is the key stored credentials are encrypted under — exposed for
// the unattended renewal loops, which hold a registry and no AppState.
func (r *AgentRegistry) JWTSecret() string { return r.jwtSecret }

// SetLocalServerID is called once at startup after AgentEnsureLocalServer.
func (r *AgentRegistry) SetLocalServerID(id uuid.UUID) {
	r.localMu.Lock()
	r.localServerID = &id
	r.localMu.Unlock()
}

// LocalServerID is the local server's id, nil until registered.
func (r *AgentRegistry) LocalServerID() *uuid.UUID {
	r.localMu.RLock()
	defer r.localMu.RUnlock()
	if r.localServerID == nil {
		return nil
	}
	id := *r.localServerID
	return &id
}

// Local is the local agent (for services that act on the panel host itself).
func (r *AgentRegistry) Local() *AgentClient { return r.local }

// ForServer resolves the agent for serverID: Local when it is the local
// server, else a (cached) remote client.
func (r *AgentRegistry) ForServer(ctx context.Context, serverID uuid.UUID) (AgentHandle, error) {
	if id := r.LocalServerID(); id != nil && *id == serverID {
		return r.local, nil
	}
	r.cacheMu.RLock()
	c, ok := r.remoteCache[serverID]
	r.cacheMu.RUnlock()
	if ok {
		return c, nil
	}
	// is_local is read too, and agent_url as nullable, because the local row
	// has NEITHER a URL nor a fingerprint (nothing dials it over TCP).
	type row struct {
		AgentURL        *string `db:"agent_url"`
		AgentToken      string  `db:"agent_token"`
		CertFingerprint *string `db:"cert_fingerprint"`
		IsLocal         bool    `db:"is_local"`
	}
	rw, err := queryOpt[row](ctx, r.db,
		"SELECT agent_url, agent_token, cert_fingerprint, is_local FROM servers WHERE id = $1 AND status != 'pending'", serverID)
	if err != nil {
		return nil, agentErr(AgentErrConnection, "DB lookup failed: "+err.Error())
	}
	switch {
	case rw == nil:
		return nil, agentErr(AgentErrNotFound, "Server not found or still pending")
	case rw.IsLocal:
		// The local server reached without the short-circuit above — a real
		// state: AgentEnsureLocalServer returns uuid.Nil when no admin exists
		// yet, so nothing sets the cached id until setup completes. Without
		// this arm every background service resolving its OWN server on a
		// single-box install (the commonest deployment) would refuse to act.
		return r.local, nil
	case rw.AgentURL != nil && *rw.AgentURL != "":
		// The ONLY consumer of the stored dial-out token, encrypted at rest by
		// every writer; decrypt here, the single choke point. The legacy path
		// returns a pre-encryption plaintext token unchanged.
		token := SecretsCryptoDecryptCredentialOrLegacy(rw.AgentToken, r.jwtSecret)
		c := NewAgentRemoteClient(*rw.AgentURL, token, rw.CertFingerprint)
		r.cacheMu.Lock()
		r.remoteCache[serverID] = c
		r.cacheMu.Unlock()
		return c, nil
	default:
		return nil, agentErr(AgentErrNotFound, "Server has no agent_url configured")
	}
}

// ForServerOrLocal defaults to the local agent when serverID is nil.
func (r *AgentRegistry) ForServerOrLocal(ctx context.Context, serverID *uuid.UUID) (AgentHandle, error) {
	if serverID == nil {
		return r.local, nil
	}
	return r.ForServer(ctx, *serverID)
}

// Invalidate drops a cached remote client (after server update/delete).
func (r *AgentRegistry) Invalidate(serverID uuid.UUID) {
	r.cacheMu.Lock()
	delete(r.remoteCache, serverID)
	r.cacheMu.Unlock()
}

// AgentServerRef is one (id, is_local) row of OnlineServerIDs.
type AgentServerRef struct {
	ID      uuid.UUID `db:"id"`
	IsLocal bool      `db:"is_local"`
}

// OnlineServerIDs lists online servers, local first. Errors read as empty.
func (r *AgentRegistry) OnlineServerIDs(ctx context.Context) []AgentServerRef {
	rows, _ := queryAll[AgentServerRef](ctx, r.db,
		"SELECT id, is_local FROM servers WHERE status = 'online' ORDER BY is_local DESC")
	return rows
}

// AgentFleetMember is one online server, with the identity every row written
// about it must carry and the agent that can actually answer for it.
type AgentFleetMember struct {
	ID     uuid.UUID
	UserID uuid.UUID
	Name   string
	// True for the box the API runs on — load-bearing for anything writing a
	// row the check-in handler would otherwise have written (see metrics).
	IsLocal bool
	Agent   AgentHandle
}

// OnlineFleet is the subject list for a background service whose subject is
// a MACHINE rather than a row. **A server whose agent will not resolve is
// SKIPPED, never substituted** — reaching for ForServerOrLocal here is how a
// member's readings end up stamped with its id and taken from the panel.
func (r *AgentRegistry) OnlineFleet(ctx context.Context) []AgentFleetMember {
	type row struct {
		ID      uuid.UUID `db:"id"`
		UserID  uuid.UUID `db:"user_id"`
		Name    string    `db:"name"`
		IsLocal bool      `db:"is_local"`
	}
	rows, _ := queryAll[row](ctx, r.db,
		"SELECT id, user_id, name, is_local FROM servers WHERE status = 'online' ORDER BY is_local DESC")
	fleet := make([]AgentFleetMember, 0, len(rows))
	for _, rw := range rows {
		a, err := r.ForServer(ctx, rw.ID)
		if err != nil {
			slog.Debug(fmt.Sprintf("Fleet iteration: skipping %s (%s) — no agent: %v", rw.Name, rw.ID, err))
			continue
		}
		fleet = append(fleet, AgentFleetMember{ID: rw.ID, UserID: rw.UserID, Name: rw.Name, IsLocal: rw.IsLocal, Agent: a})
	}
	return fleet
}

// AgentEnsureLocalServer ensures the local server row exists and returns its
// id — uuid.Nil when no admin exists yet (registration is deferred to first
// setup/login). jwtSecret is threaded in, not read from env, because it is the
// key servers.agent_token is encrypted under.
func AgentEnsureLocalServer(ctx context.Context, db Querier, agentToken, jwtSecret string) (uuid.UUID, error) {
	// Encrypted at rest like every other stored credential, although the local
	// row is never dialled (ForServer short-circuits is_local) — so that "no
	// plaintext credential lives in this column" is true of every row.
	enc, err := SecretsCryptoEncryptCredential(agentToken, jwtSecret)
	if err != nil {
		slog.Error("could not encrypt the local agent token; storing it unencrypted", "error", err)
		enc = agentToken
	}
	hash := hashAgentToken(agentToken)

	if id, _ := queryScalarOpt[uuid.UUID](ctx, db, "SELECT id FROM servers WHERE is_local = true LIMIT 1"); id != nil {
		// Update token + hash if changed.
		_, _ = execSQL(ctx, db, "UPDATE servers SET agent_token = $1, agent_token_hash = $2, status = 'online' WHERE id = $3", enc, hash, *id)
		return *id, nil
	}
	admin, _ := queryScalarOpt[uuid.UUID](ctx, db, "SELECT id FROM users WHERE role = 'admin' ORDER BY created_at ASC LIMIT 1")
	if admin == nil {
		slog.Info("No users yet, deferring local server registration to first login")
		return uuid.Nil, nil
	}
	id, err := queryScalar[uuid.UUID](ctx, db,
		"INSERT INTO servers (id, user_id, name, agent_token, agent_token_hash, status, is_local) "+
			"VALUES (gen_random_uuid(), $1, 'This Server', $2, $3, 'online', true) RETURNING id",
		*admin, enc, hash)
	if err != nil {
		return uuid.Nil, fmt.Errorf("Failed to create local server row: %w", err)
	}
	slog.Info("Registered local server: " + id.String())
	return id, nil
}
