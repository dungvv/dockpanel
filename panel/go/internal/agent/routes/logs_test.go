package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/golang-jwt/jwt/v5"
)

func logsSign(t *testing.T, key string, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLogsValidateTicket(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"sub": "u1", "purpose": "log_stream", "exp": now.Unix() + 60, "scope": "example.com"}
	}
	tk, ok := logsValidateTicket(logsSign(t, "k", base()), "k", now)
	if !ok || tk.Sub != "u1" || tk.Scope == nil || *tk.Scope != "example.com" {
		t.Fatalf("valid ticket rejected: %+v %v", tk, ok)
	}
	c := base()
	delete(c, "scope")
	if tk, ok := logsValidateTicket(logsSign(t, "k", c), "k", now); !ok || tk.Scope != nil {
		t.Errorf("unscoped ticket: %+v %v", tk, ok)
	}
	c = base()
	c["exp"] = now.Unix() - 30 // within the 60s leeway
	if _, ok := logsValidateTicket(logsSign(t, "k", c), "k", now); !ok {
		t.Error("ticket within leeway rejected")
	}

	reject := map[string]func(jwt.MapClaims){
		"expired":       func(c jwt.MapClaims) { c["exp"] = now.Unix() - 61 },
		"no exp":        func(c jwt.MapClaims) { delete(c, "exp") },
		"float exp":     func(c jwt.MapClaims) { c["exp"] = float64(now.Unix()) + 0.5 },
		"no sub":        func(c jwt.MapClaims) { delete(c, "sub") },
		"wrong purpose": func(c jwt.MapClaims) { c["purpose"] = "terminal" },
		"no purpose":    func(c jwt.MapClaims) { delete(c, "purpose") },
		"aud present":   func(c jwt.MapClaims) { c["aud"] = "x" },
		"bad scope":     func(c jwt.MapClaims) { c["scope"] = 5 },
	}
	for name, mut := range reject {
		c := base()
		mut(c)
		if _, ok := logsValidateTicket(logsSign(t, "k", c), "k", now); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, ok := logsValidateTicket(logsSign(t, "other", base()), "k", now); ok {
		t.Error("wrong key accepted")
	}
	if _, ok := logsValidateTicket("garbage", "k", now); ok {
		t.Error("garbage accepted")
	}
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, base()).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, ok := logsValidateTicket(none, "k", now); ok {
		t.Error("alg=none accepted")
	}
}

func TestLogsResolveStreamType(t *testing.T) {
	s := func(v string) *string { return &v }
	cases := []struct {
		scope, domain *string
		req, want     string
		ok            bool
	}{
		// The escalation: a site ticket asking for host logs is refused.
		{s("example.com"), nil, "auth", "", false},
		{s("example.com"), s("other.com"), "nginx_access", "", false},
		{s("example.com"), s("other.com"), "access", "nginx_access:example.com", true},
		{s("example.com"), nil, "error", "nginx_error:example.com", true},
		{s("example.com"), nil, "php", "php_error:example.com", true},
		{s("example.com"), nil, "php_error", "php_error:example.com", true},
		{s("@system"), s("x.com"), "auth", "auth", true},
		{nil, s("a.com"), "access", "nginx_access:a.com", true},
		{nil, s("a.com"), "error", "nginx_error:a.com", true},
		{nil, s("a.com"), "syslog", "syslog", true},
		{nil, nil, "auth", "auth", true},
	}
	for i, c := range cases {
		got, ok := logsResolveStreamType(&logsStreamTicket{Sub: "u", Scope: c.scope}, c.req, c.domain)
		if got != c.want || ok != c.ok {
			t.Errorf("case %d: got %q,%v want %q,%v", i, got, ok, c.want, c.ok)
		}
	}
}

func TestLogsStreamHandlerRejects(t *testing.T) {
	st := NewState("k", nil, nil, nil)
	now := time.Now()
	site := logsSign(t, "k", jwt.MapClaims{"sub": "u", "purpose": "log_stream", "exp": now.Unix() + 60, "scope": "a.com"})
	cases := []struct {
		url  string
		code int
	}{
		{"/logs/stream", http.StatusUnauthorized},
		{"/logs/stream?token=bad", http.StatusUnauthorized},
		{"/logs/stream?token=" + site + "&type=auth", http.StatusForbidden},
		{"/logs/stream?token=" + site, http.StatusForbidden}, // default nginx_access is not a site type
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.url, nil)
		req.Header.Set("Upgrade", "websocket")
		rec := httptest.NewRecorder()
		logsStreamHandler(st, rec, req)
		if rec.Code != c.code {
			t.Errorf("%s: %d want %d", c.url, rec.Code, c.code)
		}
	}
	rec := httptest.NewRecorder()
	logsStreamHandler(st, rec, httptest.NewRequest("GET", "/logs/stream", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("non-upgrade: %d", rec.Code)
	}
}

func TestLogsComputeStats(t *testing.T) {
	lines := []string{
		`1.1.1.1 - - [18/Mar/2026:14:30:00 +0000] "GET /a?x=1 HTTP/1.1" 200 12 "-" "ua"`,
		`1.1.1.1 - - [18/Mar/2026:14:31:00 +0000] "GET /a HTTP/1.1" 502 12 "-" "ua"`,
		`1.1.1.1 - - [18/Mar/2026:15:00:00 +0000] "GET /favicon.ico HTTP/1.1" 500 1 "-" "ua"`,
		`1.1.1.1 - - [18/Mar/2026:15:00:00 +0000] "GET /api/x HTTP/1.1" 404 1 "-" "ua"`,
		``,
		`garbage`,
	}
	s := logsComputeStats(lines)
	if s["requests_total"].(uint32) != 5 || s["errors_5xx"].(uint32) != 2 {
		t.Fatalf("totals: %v", s)
	}
	if h := s["errors_per_hour"].(map[string]uint32); h["14:00"] != 1 || h["15:00"] != 1 {
		t.Errorf("hours: %v", h)
	}
	top := s["top_urls"].([]logsURLCount)
	if len(top) != 1 || top[0] != (logsURLCount{"/a", 2}) {
		t.Errorf("top: %v", top)
	}
}

func TestLogsStripANSIEscapes(t *testing.T) {
	cases := map[string]string{
		"plain":                   "plain",
		"\x1b[31mred\x1b[0m":      "red",
		"\x1b[2Jclear":            "clear",
		"\x1b]0;title\x07after":   "after",
		"\x1b]0;title\x1b\\after": "after",
		"a\x1bcb":                 "ab",
		"trailing\x1b":            "trailing",
		"\x1b[1;32mgréen\x1b[0m!": "gréen!",
	}
	for in, want := range cases {
		if got := logsStripANSIEscapes(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestLogsHelpers(t *testing.T) {
	for in, want := range map[string]int{"5": 5, "+5": 5, "0": 0} {
		if n, ok := logsParseUsize(in); !ok || n != want {
			t.Errorf("%q: %d %v", in, n, ok)
		}
	}
	for _, in := range []string{"", "-1", "++5", "+-5", "x", "1.5"} {
		if _, ok := logsParseUsize(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
	for p, want := range map[string]bool{"/var/log": true, "/var/log/x": true, "/var/logx": false, "/etc/passwd": false} {
		if logsUnderVarLog(p) != want {
			t.Errorf("%q", p)
		}
	}
	if logsRound1(1024*1024*3/2) != 1.5 || logsRound1(0) != 0 {
		t.Error("round")
	}
}

func TestLogsTruncateRejects(t *testing.T) {
	for body, code := range map[string]int{
		`{"path":"/etc/passwd"}`:            http.StatusBadRequest,
		`{"path":"/var/log/../etc/passwd"}`: http.StatusBadRequest,
		`{"path":""}`:                       http.StatusBadRequest,
		`[1]`:                               http.StatusBadRequest,
		`{"path":"/var/log/__nope__"}`:      http.StatusBadRequest,
	} {
		req := httptest.NewRequest("POST", "/logs/truncate", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		logsTruncateLog(rec, req)
		if rec.Code != code {
			t.Errorf("%s: %d want %d", body, rec.Code, code)
		}
	}
}

func TestLogsHandleStreamTails(t *testing.T) {
	f := t.TempDir() + "/x.log"
	if err := os.WriteFile(f, []byte("one\r\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		logsHandleStream(c, f)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"one", "two"} {
		_, b, err := c.Read(ctx)
		if err != nil || string(b) != want {
			t.Fatalf("got %q %v want %q", b, err, want)
		}
	}
	if n := logsActiveStreams.Load(); n != 1 {
		t.Errorf("active streams = %d", n)
	}
	c.Close(websocket.StatusNormalClosure, "")
	deadline := time.Now().Add(3 * time.Second)
	for logsActiveStreams.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := logsActiveStreams.Load(); n != 0 {
		t.Errorf("stream counter not released: %d", n)
	}
}
