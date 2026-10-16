package routes

import (
	"net/http"
	"testing"
)

// The registry shares the /ssl prefix with the per-domain router, whose
// {domain} segment sits where `registry` does. Go's mux panics on an
// ambiguous pair at registration — so register every web-group router here,
// where a conflict fails a test instead of the daemon's start-up.
func TestTheRegistryRoutesMergeBesideThePerDomainSslRoutes(t *testing.T) {
	r := &Router{State: &State{}, Auth: http.NewServeMux(), Public: http.NewServeMux()}
	for _, reg := range []func(*Router){registerNginx, registerNginxStream, registerTraefik, registerFiles,
		registerSftp, registerPhp, registerSsl, registerSslRegistry} {
		reg(r)
	}
}
