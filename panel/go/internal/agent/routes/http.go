package routes

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

// Router collects handlers; auth-exempt ones (terminal WS, log stream —
// they validate their own token from a query param) go on Public.
type Router struct {
	State  *State
	Auth   *http.ServeMux // behind audit + auth middleware
	Public *http.ServeMux // no middleware
}

// Handle registers an authenticated route, e.g. "POST /nginx/sites/{domain}".
func (r *Router) Handle(pattern string, h http.HandlerFunc) { r.Auth.HandleFunc(pattern, h) }

// HandlePublic registers a route outside the auth middleware.
func (r *Router) HandlePublic(pattern string, h http.HandlerFunc) { r.Public.HandleFunc(pattern, h) }

// writeJSON writes v as JSON with status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr writes the agent's error shape: {"error": msg}.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// maxBody mirrors axum's default 2 MB body limit for Json<T>.
const maxBody = 2 << 20

// decodeJSON reads the request body into v with axum Json<T> semantics:
// missing/wrong content-type → 415, syntax error → 400, wrong shape/type →
// 422. On failure it writes the response and returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" && !strings.HasSuffix(ct, "+json") {
		http.Error(w, "Expected request with `Content-Type: application/json`", http.StatusUnsupportedMediaType)
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "Failed to buffer the request body: length limit exceeded", http.StatusRequestEntityTooLarge)
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		var syn *json.SyntaxError
		if errors.As(err, &syn) || errors.Is(err, io.ErrUnexpectedEOF) {
			http.Error(w, "Failed to parse the request body as JSON: "+err.Error(), http.StatusBadRequest)
		} else {
			http.Error(w, "Failed to deserialize the JSON body into the target type: "+err.Error(), http.StatusUnprocessableEntity)
		}
		return false
	}
	return true
}

// isValidDomain validates a domain name (shared across route modules).
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

// isValidName validates a resource name (database, app, container, …).
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

// isValidContainerID validates a Docker container ID (hex, 1–64 chars).
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

func isASCIIAlnum(c rune) bool {
	return c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9')
}
