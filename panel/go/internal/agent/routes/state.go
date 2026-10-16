package routes

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/flosch/pongo2/v6"
	"github.com/google/uuid"
	"github.com/moby/moby/client"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// ConfigDir holds agent.token, ssl/, and the installer-written env files.
const ConfigDir = "/etc/dockpanel"

// tokenRotationGrace is how long the previous token stays valid after rotation.
const tokenRotationGrace = 60 * time.Second

// NetworkSnapshot holds network counters for rate calculation.
type NetworkSnapshot struct {
	Readings  map[string][2]uint64 // iface -> (rx_bytes, tx_bytes)
	Timestamp time.Time
}

// State is shared by every handler (Rust: routes::AppState).
type State struct {
	mu         sync.RWMutex
	token      string
	prevToken  string
	rotatedAt  time.Time
	Templates  *pongo2.TemplateSet
	Cpu        *services.CpuSampler
	Docker     *client.Client
	NetMu      sync.Mutex
	NetworkSnp *NetworkSnapshot
}

// NewState builds the shared state around the loaded token.
func NewState(token string, tpl *pongo2.TemplateSet, cpu *services.CpuSampler, docker *client.Client) *State {
	return &State{token: token, Templates: tpl, Cpu: cpu, Docker: docker}
}

// Token returns the current agent token.
func (s *State) Token() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

func (s *State) tokenValid(provided string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) == 1 {
		return true
	}
	return s.prevToken != "" && time.Since(s.rotatedAt) < tokenRotationGrace &&
		subtle.ConstantTimeCompare([]byte(provided), []byte(s.prevToken)) == 1
}

// authMiddleware requires `Authorization: Bearer <token>` on every route but
// /health, comparing in constant time. The previous token stays valid for
// tokenRotationGrace after a rotation.
func (s *State) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		provided, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !s.tokenValid(provided) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rotateToken: POST /auth/rotate-token — returns {"new_token": "..."}; the old
// token remains valid for the grace period.
func (s *State) rotateToken(w http.ResponseWriter, _ *http.Request) {
	newToken := uuid.NewString()
	path := filepath.Join(ConfigDir, "agent.token")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(newToken), 0o600); err != nil {
		slog.Error("Failed to write temp token file", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		slog.Error("Failed to rename token file", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_ = os.Chmod(path, 0o600)

	s.mu.Lock()
	s.prevToken, s.rotatedAt, s.token = s.token, time.Now(), newToken
	s.mu.Unlock()

	slog.Info("Agent token rotated successfully")
	writeJSON(w, http.StatusOK, map[string]string{"new_token": newToken})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush keeps streaming handlers working behind the recorder.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the real writer (hijack for WS).
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// auditMiddleware logs every state-modifying request (POST/PUT/DELETE).
func auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
			next.ServeHTTP(w, r)
			return
		}
		src := r.Header.Get("X-Forwarded-For")
		if src == "" {
			src = r.Header.Get("X-Real-IP")
		}
		if src == "" {
			src = "unknown"
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		attrs := []any{"target", "audit", "method", r.Method, "path", r.URL.Path, "source_ip", src, "status", rec.status}
		if rec.status < 400 {
			slog.Info("Request completed", attrs...)
		} else {
			slog.Warn("Request failed", attrs...)
		}
	})
}
