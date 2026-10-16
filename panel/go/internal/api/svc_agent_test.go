package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeAgent serves h on a unix socket and returns a client for it.
func fakeAgent(t *testing.T, h http.HandlerFunc) *AgentClient {
	t.Helper()
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); os.RemoveAll(dir) })
	return NewAgentClient(sock, "tok")
}

func kindOf(err error) AgentErrorKind {
	var ae *AgentError
	if !errors.As(err, &ae) {
		return -1
	}
	return ae.Kind
}

func TestLocalAgentRequestShapes(t *testing.T) {
	c := fakeAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/ok":
			if r.Method == "POST" && r.Header.Get("Content-Type") != "application/json" {
				w.WriteHeader(400)
				return
			}
			fmt.Fprint(w, `{"n":12345678901234567,"s":"x"}`)
		case "/refuse":
			w.WriteHeader(412)
			fmt.Fprint(w, `{"error":"WAF not installed"}`)
		case "/notjson":
			fmt.Fprint(w, "hello")
		case "/bytes":
			w.Header().Set("Content-Disposition", `attachment; filename="a.txt"`)
			fmt.Fprint(w, "raw\x00bytes")
		}
	})
	ctx := context.Background()
	v, err := c.Get(ctx, "/ok")
	if n, _ := jsonI64(jsonGet(v, "n")); err != nil || n != 12345678901234567 {
		t.Fatal(v, err)
	}
	if _, err := c.Post(ctx, "/ok", map[string]any{"a": 1}); err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(ctx, "/refuse")
	var ae *AgentError
	if !errors.As(err, &ae) || ae.Kind != AgentErrStatus || ae.Code != 412 || !strings.Contains(ae.Msg, "WAF") {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "/notjson"); kindOf(err) != AgentErrParse {
		t.Fatal(err)
	}
	b, cd, err := c.GetBytes(ctx, "/bytes")
	if err != nil || string(b) != "raw\x00bytes" || cd == nil || !strings.Contains(*cd, "a.txt") {
		t.Fatal(b, cd, err)
	}
	c.UpdateToken("rotated")
	if _, err := c.Get(ctx, "/ok"); kindOf(err) != AgentErrStatus {
		t.Fatal("the rotated token must be sent")
	}
}

func TestCircuitBreakerOpensOnConnectionFailures(t *testing.T) {
	c := NewAgentClient("/nonexistent/agent.sock", "tok")
	ctx := context.Background()
	for i := 0; i < agentCircuitBreakerThreshold; i++ {
		if _, err := c.Get(ctx, "/x"); kindOf(err) != AgentErrConnection {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := c.Get(ctx, "/x"); kindOf(err) != AgentErrCircuitOpen {
		t.Fatal(err)
	}
	if s, b := body(t, agentError("x", func() error { _, e := c.Get(ctx, "/x"); return e }())); s != 502 || b["code"] != CodeAgentUnreachable {
		t.Fatal(s, b)
	}
}

func TestLongPoolWaitIsInsideTheBudget(t *testing.T) {
	release := make(chan struct{})
	c := fakeAgent(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		fmt.Fprint(w, "{}")
	})
	defer close(release)
	for i := 0; i < agentMaxLongConnections; i++ {
		go c.PostLong(context.Background(), "/busy", nil, 30)
	}
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	_, err := c.PostLong(context.Background(), "/x", nil, 1)
	var ae *AgentError
	if !errors.As(err, &ae) || ae.Kind != AgentErrRequest || !strings.Contains(ae.Msg, "never started") || time.Since(start) > 3*time.Second {
		t.Fatal(err)
	}
}

func TestNDJSONIsIdleBounded(t *testing.T) {
	c := fakeAgent(t, func(w http.ResponseWriter, r *http.Request) {
		f := w.(http.Flusher)
		if r.URL.Path == "/talk" {
			for i := 0; i < 3; i++ {
				fmt.Fprintf(w, "{\"i\":%d}\nnot json\n", i)
				f.Flush()
				time.Sleep(600 * time.Millisecond) // > total idle budget overall, < per-window
			}
			fmt.Fprint(w, `{"i":3}`) // trailing line without newline
			return
		}
		fmt.Fprint(w, "{\"i\":0}\n")
		f.Flush()
		<-r.Context().Done() // goes quiet
	})
	var got []int64
	err := c.PostLongNDJSON(context.Background(), "/talk", nil, 1, func(v any) {
		n, _ := jsonI64(jsonGet(v, "i"))
		got = append(got, n)
	})
	if err != nil || len(got) != 4 {
		t.Fatal("a slow but talking stream completes", got, err)
	}
	err = c.PostLongNDJSON(context.Background(), "/quiet", nil, 1, func(any) {})
	var ae *AgentError
	if !errors.As(err, &ae) || ae.Kind != AgentErrRequest || !strings.Contains(ae.Msg, "no output for 1s") {
		t.Fatal(err)
	}
}

func TestRemoteClientPinsFingerprint(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer rt" {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	fp := strings.ToUpper(hex.EncodeToString(sum[:])) // compared case-insensitively
	c := NewAgentRemoteClient(srv.URL+"/", "rt", &fp)
	if v, err := c.Get(context.Background(), "/x"); err != nil || jsonGet(v, "ok") != true {
		t.Fatal(v, err)
	}
	wrong := strings.Repeat("0", 64)
	c = NewAgentRemoteClient(srv.URL, "rt", &wrong)
	if _, err := c.Get(context.Background(), "/x"); kindOf(err) != AgentErrConnection {
		t.Fatal("a fingerprint mismatch must fail the handshake", err)
	}
	// No pin and no AGENT_TLS_VERIFY=insecure → CA verification (fails here).
	os.Unsetenv("AGENT_TLS_VERIFY")
	c = NewAgentRemoteClient(srv.URL, "rt", nil)
	if _, err := c.Get(context.Background(), "/x"); err == nil {
		t.Fatal("self-signed cert accepted without a pin")
	}
}

func TestRegistryLocalShortCircuit(t *testing.T) {
	local := NewAgentClient("/x", "t")
	r := NewAgentRegistry(local, nil, "s")
	if r.LocalServerID() != nil {
		t.Fatal()
	}
	if h, _ := r.ForServerOrLocal(context.Background(), nil); h != AgentHandle(local) {
		t.Fatal("nil server → local")
	}
	id := [16]byte{1}
	r.SetLocalServerID(id)
	if h, err := r.ForServer(context.Background(), id); err != nil || h != AgentHandle(local) {
		t.Fatal(err)
	}
}
