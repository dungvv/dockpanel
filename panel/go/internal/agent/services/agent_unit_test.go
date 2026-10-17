package services

import (
	"slices"
	"strings"
	"testing"
)

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
