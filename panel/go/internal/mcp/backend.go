// Package mcp is dockpanel-mcp: a read-only MCP server whose every tool is a
// thin GET proxy onto the panel's REST API, authenticated with a `dp_` key.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Deliberately separate from the CLI's client: a different token file gives
// MCP-originated actions their own independently revocable API key.
var (
	APIEnvPath = "/etc/dockpanel/api.env"
	TokenPath  = "/etc/dockpanel/mcp.token"
)

var httpClient = &http.Client{Timeout: 60 * time.Second}

// LoadToken reads the shared secret used in both directions: inbound bearer
// auth and outbound calls to the panel API.
func LoadToken() (string, error) {
	notConfigured := fmt.Errorf("No panel API key configured at %s.\n"+
		"Mint one from the panel (Settings → API Keys → name it \"MCP server\"), "+
		"then save it to %s (root:root, mode 600).", TokenPath, TokenPath)
	raw, err := os.ReadFile(TokenPath)
	if err != nil {
		return "", notConfigured
	}
	// An empty leftover file must read as "not configured", not as a token
	// that 401s every call.
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", notConfigured
	}
	return token, nil
}

// EnvValue returns KEY= from a simple env file, or "" when absent.
func EnvValue(path, key string) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), key+"="); ok {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// baseURL follows the API's own LISTEN_ADDR so it always matches what the
// backend actually bound.
func baseURL() (string, error) {
	if _, err := os.Stat(APIEnvPath); err != nil {
		return "", fmt.Errorf("Cannot read %s: %v", APIEnvPath, err)
	}
	addr, ok := EnvValue(APIEnvPath, "LISTEN_ADDR")
	if !ok {
		return "", fmt.Errorf("%s has no LISTEN_ADDR — cannot reach the panel API", APIEnvPath)
	}
	return "http://" + addr, nil
}

// Get is the only verb this server ever issues: read-only by construction.
func Get(ctx context.Context, path, token string) (any, error) {
	base, err := baseURL()
	if err != nil {
		return nil, err
	}
	url := base + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Cannot reach the panel API at %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return nil, errors.New(e.Error)
		}
		return nil, fmt.Errorf("Panel API returned %s: %s", resp.Status, body)
	}
	if len(body) == 0 {
		return map[string]any{}, nil
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("Invalid JSON from panel API: %v\nBody: %s", err, body[:min(len(body), 200)])
	}
	return v, nil
}
