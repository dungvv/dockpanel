package api

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The panel advertises its OWN version as the agent's target, so the two
// binaries must ship the same version or the panel names a tag whose agent
// asset was never built (they were equal by convention only, s233).
func TestRtAgentUpdatesAgentAndAPIShipTheSameVersion(t *testing.T) {
	src, err := os.ReadFile("../agent/services/agent_unit.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`var AgentVersion = "([^"]+)"`).FindSubmatch(src)
	if m == nil {
		t.Fatal("no AgentVersion in agent_unit.go")
	}
	if agent := string(m[1]); agent != Version {
		t.Fatalf("dockpanel-api %s would advertise v%s as the agent target, but dockpanel-agent is %s — that tag has no agent asset", Version, Version, agent)
	}
}

// The three retired keys must not come back: a reader with no writer is what
// made this endpoint answer null on every install. Key names are assembled so
// this test does not match itself.
func TestRtAgentUpdatesDeadSettingsKeysAreGone(t *testing.T) {
	here, err := os.ReadFile("rt_agent_updates.go")
	if err != nil {
		t.Fatal(err)
	}
	settings, _ := os.ReadFile("rt_settings.go") // absent until its port lands
	for _, key := range []string{"agent_" + "download_url", "agent_" + "checksum", "agent_" + "latest_version"} {
		quoted := `"` + key + `"`
		if strings.Contains(string(settings), quoted) {
			t.Errorf("%s is still allowlisted in rt_settings.go — the update AND the import allowlist must both drop it", key)
		}
		// Prose may name them; code may not.
		for _, line := range strings.Split(string(here), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "//") {
				continue
			}
			if strings.Contains(l, quoted) {
				t.Errorf("%s is still read here: %s", key, l)
			}
		}
	}
}
