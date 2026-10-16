package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidators(t *testing.T) {
	for _, d := range []string{"example.com", "sub.example.com", "my-site.example.com"} {
		if !isValidDomain(d) {
			t.Errorf("valid domain rejected: %q", d)
		}
	}
	for _, d := range []string{"", "localhost", "../etc/passwd", "-bad.com"} {
		if isValidDomain(d) {
			t.Errorf("invalid domain accepted: %q", d)
		}
	}
	for _, n := range []string{"mydb", "my-app-123"} {
		if !isValidName(n) {
			t.Errorf("valid name rejected: %q", n)
		}
	}
	for _, n := range []string{"", "-bad", "has space"} {
		if isValidName(n) {
			t.Errorf("invalid name accepted: %q", n)
		}
	}
	if !isValidContainerID("abc123def456") || !isValidContainerID(strings.Repeat("a", 64)) {
		t.Error("valid container id rejected")
	}
	for _, id := range []string{"", "not-hex!", strings.Repeat("a", 65)} {
		if isValidContainerID(id) {
			t.Errorf("invalid container id accepted: %q", id)
		}
	}
}

func TestAuthAndRotationGrace(t *testing.T) {
	st := &State{token: "cur"}
	h := st.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	call := func(path, auth string) int {
		r := httptest.NewRequest("GET", path, nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if call("/health", "") != 204 {
		t.Error("/health must be exempt")
	}
	if call("/system/info", "") != 401 || call("/system/info", "cur") != 401 || call("/system/info", "Bearer x") != 401 {
		t.Error("missing/malformed/wrong token must be 401")
	}
	if call("/system/info", "Bearer cur") != 204 {
		t.Error("current token rejected")
	}
	st.prevToken, st.rotatedAt, st.token = "cur", time.Now(), "new"
	if call("/x", "Bearer cur") != 204 || call("/x", "Bearer new") != 204 {
		t.Error("both tokens must work inside the grace period")
	}
	st.rotatedAt = time.Now().Add(-2 * tokenRotationGrace)
	if call("/x", "Bearer cur") != 401 {
		t.Error("old token must die after the grace period")
	}
}

func TestDecodeJSONStatuses(t *testing.T) {
	var v struct {
		N int `json:"n"`
	}
	for _, c := range []struct {
		ct, body string
		want     int
	}{
		{"", `{"n":1}`, 415},
		{"application/json", `{"n":`, 400},
		{"application/json", `{"n":"x"}`, 422},
		{"application/json; charset=utf-8", `{"n":1}`, 200},
	} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(c.body))
		if c.ct != "" {
			r.Header.Set("Content-Type", c.ct)
		}
		w := httptest.NewRecorder()
		ok := decodeJSON(w, r, &v)
		got := w.Code
		if ok {
			got = 200
		}
		if got != c.want {
			t.Errorf("ct=%q body=%q: got %d want %d", c.ct, c.body, got, c.want)
		}
	}
}
