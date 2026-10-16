package mcp

import (
	"crypto/subtle"
	"net/http"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// RequireBearerToken is the real gate on /mcp. Tools authenticate their OWN
// outbound calls from a fixed file, so without this anyone reaching nginx
// would get the operator's admin-scoped access for free. The inbound caller
// must present the same `dp_` key saved in mcp.token.
func RequireBearerToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected, err := LoadToken()
		if err != nil {
			// Fail closed when the server is not configured yet.
			http.Error(w, "No panel API key configured — see /etc/dockpanel/mcp.token", http.StatusUnauthorized)
			return
		}
		provided, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			http.Error(w, "Missing or invalid bearer token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Handler is the full /mcp surface: bearer gate in front of the streamable
// HTTP transport. nginx forwards the real Host header, so the SDK's
// localhost-only DNS-rebinding guard would reject 100% of real traffic; the
// bearer check is the actual gate.
func Handler(version string) http.Handler {
	server := NewServer(version)
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server },
		&sdk.StreamableHTTPOptions{DisableLocalhostProtection: true})
	return RequireBearerToken(h)
}
