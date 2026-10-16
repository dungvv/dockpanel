package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
)

// hostFixListener accepts HTTP/1.1 requests that carry no Host header.
//
// The Rust panel API talks to the local agent over the unix socket with a
// hyper client that sends no Host header. axum accepted that; Go's
// net/http rejects it with "400 missing required Host header". A panel host
// whose agent self-updated to the Go build while its API is still the Rust
// one would lose every local agent call, so each request read from the
// socket is re-written with `Host: localhost` when it has none. After an
// Upgrade request (websocket) the connection is passed through raw.
type hostFixListener struct{ net.Listener }

func (l hostFixListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	go hostFixPump(c, pw)
	return &hostFixConn{Conn: c, r: pr}, nil
}

// hostFixConn reads the re-written request stream; writes go straight to
// the client.
type hostFixConn struct {
	net.Conn
	r *io.PipeReader
}

func (c *hostFixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *hostFixConn) Close() error {
	c.r.Close()
	return c.Conn.Close()
}

// hostFixPump parses requests off the raw connection and re-serialises them
// (body included, framing preserved) into w.
func hostFixPump(c net.Conn, w *io.PipeWriter) {
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			w.CloseWithError(err)
			return
		}
		if req.Host == "" {
			req.Host = "localhost"
		}
		upgrade := strings.EqualFold(req.Header.Get("Connection"), "upgrade") ||
			req.Header.Get("Upgrade") != ""
		// Write emits Host from req.Host and keeps Content-Length / chunked
		// framing. It closes req.Body when done.
		if err := req.Write(w); err != nil {
			w.CloseWithError(err)
			return
		}
		if upgrade {
			// Everything after an upgrade is the new protocol's bytes.
			_, err := br.WriteTo(w)
			w.CloseWithError(err)
			return
		}
	}
}
