// dockpanel-mcp serves the read-only MCP tool catalogue at /mcp.
package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/ovexro/dockpanel/panel/go/internal/mcp"
)

var version = "2.242.1"

const (
	mcpEnvPath        = "/etc/dockpanel/mcp.env"
	defaultListenAddr = "127.0.0.1:3081"
)

func main() {
	// Same LISTEN_ADDR= knob as api.env; loopback-only when absent.
	addr, ok := mcp.EnvValue(mcpEnvPath, "LISTEN_ADDR")
	if !ok {
		addr = defaultListenAddr
	}

	// One handler for both paths so sessions are shared.
	h := mcp.Handler(version)
	mux := http.NewServeMux()
	mux.Handle("/mcp", h)
	mux.Handle("/mcp/", h)

	slog.Info("dockpanel-mcp listening", "addr", addr, "path", "/mcp")
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}
