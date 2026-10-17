package services

import (
	"slices"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

// app-data-persistence-pin-e2e.sh B3: every sharing spelling counts, so a
// container sharing state any of these ways never blue-greens.
func TestPinAppDataPersistenceEverySharingSpellingCounts(t *testing.T) {
	for name, hc := range map[string]*container.HostConfig{
		"binds":        {Binds: []string{"/srv/x:/data"}},
		"mounts":       {Mounts: []mount.Mount{{Target: "/data"}}},
		"volumes_from": {VolumesFrom: []string{"other"}},
	} {
		if !DockerAppsSharesPersistentState(hc) {
			t.Errorf("%s not counted as shared state", name)
		}
	}
	if DockerAppsSharesPersistentState(&container.HostConfig{}) {
		t.Fatal("a container with no mounts must still be allowed to blue-green")
	}
}

// §C1: the templates whose state lives inside the container declare where.
func TestPinAppDataPersistenceStatefulTemplatesDeclareTheirVolume(t *testing.T) {
	for id, path := range map[string]string{
		"n8n": "/home/node/.n8n", "ghost": "/var/lib/ghost/content", "redis": "/data",
		"searxng": "/etc/searxng", "activepieces": "/root/.activepieces",
	} {
		tpl := dockerAppsTemplateByID(id)
		if tpl == nil {
			t.Errorf("template %s missing", id)
			continue
		}
		if !slices.Contains(tpl.Volumes, path) {
			t.Errorf("%s does not declare %s (volumes %v) — a recreate loses its data (#110)", id, path, tpl.Volumes)
		}
	}
}

// §C2: n8n removed basic auth in 1.0; no template may offer the inert fields.
// §C3: activepieces ships the embedded DB/queue that make its volume meaningful.
func TestPinAppDataPersistenceCatalogueEnvShape(t *testing.T) {
	for _, tpl := range dockerAppsTemplates {
		for _, ev := range tpl.EnvVars {
			if strings.HasPrefix(ev.Name, "N8N_BASIC_AUTH") {
				t.Errorf("%s still declares %s", tpl.ID, ev.Name)
			}
		}
	}
	ap := dockerAppsTemplateByID("activepieces")
	if ap == nil {
		t.Fatal("activepieces missing")
	}
	defaults := map[string]string{}
	for _, ev := range ap.EnvVars {
		defaults[ev.Name] = ev.Default
	}
	if defaults["AP_DB_TYPE"] != "PGLITE" || defaults["AP_REDIS_TYPE"] != "MEMORY" {
		t.Fatalf("activepieces targets an external DB/queue it has none of: %v", defaults)
	}
}
