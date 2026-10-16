package mcp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func ptr[T any](v T) *T { return &v }

func TestQuerySuffix(t *testing.T) {
	cases := []struct {
		pairs []kv
		want  string
	}{
		{nil, ""},
		{[]kv{{"limit", nil}}, ""},
		{[]kv{{"limit", num(ptr(uint32(5)))}, {"severity", nil}, {"q", ptr("a b&c")}}, "?limit=5&q=a+b%26c"},
		{[]kv{{"hours", num(ptr(int32(-1)))}}, "?hours=-1"},
	}
	for _, c := range cases {
		if got := querySuffix(c.pairs...); got != c.want {
			t.Errorf("querySuffix(%v) = %q, want %q", c.pairs, got, c.want)
		}
	}
	if seg("a/b") != "a%2Fb" {
		t.Errorf("path segment not escaped: %q", seg("a/b"))
	}
}

// setup points the package at temp config files and a fake panel API.
func setup(t *testing.T, token string, api http.HandlerFunc) {
	dir := t.TempDir()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	TokenPath = filepath.Join(dir, "mcp.token")
	APIEnvPath = filepath.Join(dir, "api.env")
	os.WriteFile(TokenPath, []byte(token+"\n"), 0o600)
	os.WriteFile(APIEnvPath, []byte("LISTEN_ADDR="+strings.TrimPrefix(srv.URL, "http://")+"\n"), 0o600)
}

func TestBearerGate(t *testing.T) {
	setup(t, "dp_secret", func(http.ResponseWriter, *http.Request) {})
	h := RequireBearerToken(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for hdr, want := range map[string]int{"": 401, "Bearer nope": 401, "dp_secret": 401, "Bearer dp_secret": 204} {
		r := httptest.NewRequest("POST", "/mcp", nil)
		if hdr != "" {
			r.Header.Set("Authorization", hdr)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("Authorization %q: got %d, want %d", hdr, w.Code, want)
		}
	}
	// Empty token file fails closed.
	os.WriteFile(TokenPath, []byte("  \n"), 0o600)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer ")
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("empty token file: got %d, want 401", w.Code)
	}
}

func TestToolCallsEndToEnd(t *testing.T) {
	var gotPath, gotAuth string
	setup(t, "dp_secret", func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.RequestURI(), r.Header.Get("Authorization")
		if strings.HasPrefix(r.URL.Path, "/api/users") {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"Admin only"}`))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	})

	ctx := context.Background()
	ct, st := sdk.NewInMemoryTransports()
	if _, err := NewServer("test").Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "t"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 40 {
		t.Errorf("tool count = %d, want 40", len(tools.Tools))
	}

	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "list_crons",
		Arguments: map[string]any{"site_id": "abc/1", "limit": 5}})
	if err != nil || res.IsError {
		t.Fatalf("list_crons: err=%v res=%+v", err, res)
	}
	if gotPath != "/api/sites/abc%2F1/crons?limit=5" || gotAuth != "Bearer dp_secret" {
		t.Errorf("upstream got %q auth %q", gotPath, gotAuth)
	}
	if txt := res.Content[0].(*sdk.TextContent).Text; !strings.Contains(txt, `"ok": true`) {
		t.Errorf("unexpected body %q", txt)
	}

	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "list_users", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].(*sdk.TextContent).Text, "Admin only") {
		t.Errorf("API error must surface as isError with the panel's message: %+v", res)
	}
}

// The Rust build once shipped rejecting every request nginx proxied, because
// the real Host header failed the SDK's localhost-only guard.
func TestHandlerAcceptsProxiedHost(t *testing.T) {
	setup(t, "dp_secret", func(w http.ResponseWriter, _ *http.Request) {})
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	r := httptest.NewRequest("POST", "https://panel.example.com/mcp", strings.NewReader(body))
	r.Host = "panel.example.com"
	// Arrives on the loopback listener, exactly as nginx's proxy_pass does.
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey,
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3081}))
	r.Header.Set("Authorization", "Bearer dp_secret")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	Handler("test").ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "dockpanel-mcp") {
		t.Fatalf("initialize via proxied Host: %d %s", w.Code, w.Body.String())
	}
}
