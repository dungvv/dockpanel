package routes

import (
	"net/http"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

func registerHealth(r *Router) {
	// Unauthenticated: authMiddleware lets /health through.
	r.Handle("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, struct {
			Status  string `json:"status"`
			Version string `json:"version"`
		}{"ok", services.AgentVersion})
	})
}
