package routes

import "net/http"

// registrars mirrors the .merge() list in src/main.rs. Each route file adds
// its register<M> here (the integration pass owns this list).
var registrars = []func(*Router){}

// Handler builds the agent's full HTTP surface: authenticated routes behind
// audit + auth middleware, plus the public ones that check their own token.
func Handler(st *State) http.Handler {
	r := &Router{State: st, Auth: http.NewServeMux(), Public: http.NewServeMux()}
	r.Handle("POST /auth/rotate-token", st.rotateToken)
	for _, reg := range registrars {
		reg(r)
	}
	protected := auditMiddleware(st.authMiddleware(r.Auth))
	root := http.NewServeMux()
	root.Handle("/", protected)
	// Public patterns are more specific than "/", so they win.
	root.Handle("/terminal/ws", r.Public)
	root.Handle("/logs/stream", r.Public)
	return root
}
