package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// A raw HTTP/1.1 client that, like the Rust API's hyper client, sends no
// Host header: two keep-alive requests (one with a body), then checks both
// are served instead of being refused with 400.
func TestHostlessRequestsAreServed(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		io.WriteString(w, r.Method+" "+r.URL.Path+" host="+r.Host+" body="+string(body))
	})}
	go srv.Serve(hostFixListener{ln})
	defer srv.Close()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /health HTTP/1.1\r\n\r\n"+
		"POST /x HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}")
	br := bufio.NewReader(c)
	for _, want := range []string{"GET /health host=localhost body=", `POST /x host=localhost body={"a":1}`} {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || !strings.HasPrefix(string(got), want) {
			t.Fatalf("got %d %q, want 200 %q", resp.StatusCode, got, want)
		}
	}
}
