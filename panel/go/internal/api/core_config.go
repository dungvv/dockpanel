package api

// Port of panel/backend/src/config.rs.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config is loaded from the environment once at startup.
//
// (Rust zeroized the secrets on drop; Go's GC gives no such guarantee and
// the process holds them for its whole life anyway.)
type Config struct {
	DatabaseURL      string
	JWTSecret        string
	AgentSocket      string
	AgentToken       string
	ListenAddr       string
	DBMaxConnections uint32
	// BASE_URL defaults to EMPTY. It used to default to
	// "https://panel.example.com", which caused Secure cookies over HTTP.
	BaseURL     string
	CORSOrigins []string
}

// ErrJWTSecretTooShort is fatal: main prints its message and exits 1.
var ErrJWTSecretTooShort = errors.New("JWT_SECRET too short")

// configCORSOrigins parses CORS_ORIGINS (comma list, trimmed, empties
// dropped); unset/empty falls back to BASE_URL, or nothing when that is empty
// too (typical IP-based access — the UI is same-origin and needs no CORS).
func configCORSOrigins(raw, baseURL string) []string {
	if raw != "" {
		out := []string{}
		for _, o := range strings.Split(raw, ",") {
			if o = strings.TrimSpace(o); o != "" {
				out = append(out, o)
			}
		}
		return out
	}
	if baseURL == "" {
		return []string{}
	}
	return []string{baseURL}
}

// ConfigFromEnv mirrors Config::from_env. Missing required variables are
// errors (Rust panicked); a short JWT_SECRET prints the FATAL line and is
// ErrJWTSecretTooShort.
func ConfigFromEnv() (*Config, error) {
	jwt, ok := os.LookupEnv("JWT_SECRET")
	if !ok {
		return nil, errors.New("JWT_SECRET must be set")
	}
	if len(jwt) < 32 {
		fmt.Fprintf(os.Stderr, "FATAL: JWT_SECRET must be at least 32 characters (got %d). Generate with: openssl rand -hex 32\n", len(jwt))
		return nil, ErrJWTSecretTooShort
	}
	base := os.Getenv("BASE_URL")
	dbURL, ok := os.LookupEnv("DATABASE_URL")
	if !ok {
		return nil, errors.New("DATABASE_URL must be set")
	}
	agentToken, ok := os.LookupEnv("AGENT_TOKEN")
	if !ok {
		return nil, errors.New("AGENT_TOKEN must be set")
	}
	maxConns := uint32(20)
	if v, err := strconv.ParseUint(os.Getenv("DB_MAX_CONNECTIONS"), 10, 32); err == nil {
		maxConns = uint32(v)
	}
	return &Config{
		DatabaseURL:      dbURL,
		JWTSecret:        jwt,
		AgentSocket:      envOr("AGENT_SOCKET", "/var/run/dockpanel/agent.sock"),
		AgentToken:       agentToken,
		ListenAddr:       envOr("LISTEN_ADDR", "127.0.0.1:3080"),
		DBMaxConnections: maxConns,
		BaseURL:          base,
		CORSOrigins:      configCORSOrigins(os.Getenv("CORS_ORIGINS"), base),
	}, nil
}

func envOr(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}
