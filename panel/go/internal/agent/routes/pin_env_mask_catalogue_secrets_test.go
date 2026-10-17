package routes

import (
	"testing"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// env-mask-catalogue-secrets-pin-e2e.sh §C: the 8 catalogue `secret: true`
// names the route's substring heuristic missed are masked by GET /apps/{id}/env.
func TestPinEnvMaskCatalogueSecretsTheMeasuredNamesAreMasked(t *testing.T) {
	for _, n := range []string{"DB_PASS", "POSTGRES_PWD", "SURREAL_PASS", "GOTIFY_DEFAULTUSER_PASS",
		"PLEX_CLAIM", "DATABASE_URL", "CLICKHOUSE_DATABASE_URL", "REDASH_DATABASE_URL"} {
		if !services.DockerAppsCatalogueSecretEnv(n) {
			t.Errorf("%s is not declared secret in the catalogue — not a real control case", n)
		}
		if !dockerAppsIsSensitive(n) {
			t.Errorf("%s is returned in the clear", n)
		}
	}
}
