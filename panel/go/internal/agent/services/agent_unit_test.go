package services

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// The embedded copy must not drift from the file the installers deploy.
func TestAgentUnitIsByteIdenticalToTheInstalledFile(t *testing.T) {
	src, err := os.ReadFile("../../../../agent/dockpanel-agent.service")
	if os.IsNotExist(err) {
		t.Skip("panel/agent/dockpanel-agent.service absent")
	}
	if err != nil {
		t.Fatal(err)
	}
	if string(src) != AgentUnit {
		t.Fatal("services/dockpanel-agent.service drifted from panel/agent/dockpanel-agent.service — re-copy it")
	}
}

// The hardening the fleet spent eighteen releases without.
func TestAgentUnitCompiledUnitIsTheHardenedOne(t *testing.T) {
	for _, d := range []string{
		"NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
		"ProtectKernelTunables=yes", "ProtectControlGroups=yes", "RestrictSUIDSGID=yes",
		"LockPersonality=yes", "RestrictNamespaces=~user",
	} {
		if !strings.Contains(AgentUnit, d) {
			t.Errorf("the compiled-in unit lost %s", d)
		}
	}
	if strings.Contains(AgentUnit, "ProtectSystem=no") {
		t.Error("the compiled-in unit turns the sandbox off")
	}
}

// The `-` prefix lets one unit serve both fleet members (agent.env) and the
// panel box (no such file).
func TestAgentUnitEnvFileIsOptional(t *testing.T) {
	if !strings.Contains(AgentUnit, "EnvironmentFile=-/etc/dockpanel/agent.env") {
		t.Fatal("agent.env must be `-`-prefixed")
	}
}

func TestAgentUnitReadWritePathsStripsTheOptionalPrefix(t *testing.T) {
	p := AgentUnitReadWritePaths(AgentUnit)
	if !slices.Contains(p, "/etc/nginx") {
		t.Error("unprefixed entries must be listed")
	}
	if !slices.Contains(p, "/etc/apt") {
		t.Error("a `-`-prefixed entry still needs its directory created")
	}
	for _, x := range p {
		if strings.HasPrefix(x, "-") {
			t.Error("the `-` prefix must be stripped before mkdir")
		}
	}
}
