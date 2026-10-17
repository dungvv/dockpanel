// Command dockpanel-api is the DockPanel panel backend (Go port of
// panel/backend/src/main.rs): the HTTP API behind nginx, its migrations and
// its supervised background services.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/api"
)

// version is set by scripts/build-go.sh (-X main.version=…).
var version = ""

// The Rust API serialised every timestamp as DateTime<Utc> ("...Z"); pgx
// returns timestamptz in time.Local, so pin Local to UTC for the whole process.
func init() { time.Local = time.UTC }

func main() {
	if version != "" {
		api.Version = version
	}
	// Documentation generation runs before anything else is set up: it needs
	// no database, no config and no network, and a developer regenerating
	// docs should never risk touching a live system to do it.
	//
	// Usage: dockpanel-api --emit-guidance <repo-root>
	for i, a := range os.Args {
		if a == "--emit-guidance" {
			root := "."
			if i+1 < len(os.Args) {
				root = os.Args[i+1]
			}
			if err := api.EmitGuidance(root); err != nil {
				fmt.Fprintf(os.Stderr, "failed to emit guidance docs: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	setupLogging()

	cfg, err := api.ConfigFromEnv()
	if err != nil {
		if !errors.Is(err, api.ErrJWTSecretTooShort) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
	if err := api.Serve(cfg); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

// setupLogging: level from LOG_LEVEL (error|warn|info|debug, default info),
// falling back to RUST_LOG so units written by older installers keep their
// level; JSON output when LOG_FORMAT=json.
func setupLogging() {
	level := slog.LevelInfo
	lv := os.Getenv("LOG_LEVEL")
	if lv == "" {
		lv = os.Getenv("RUST_LOG")
	}
	switch strings.ToLower(strings.TrimSpace(lv)) {
	case "trace", "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if os.Getenv("LOG_FORMAT") == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}
