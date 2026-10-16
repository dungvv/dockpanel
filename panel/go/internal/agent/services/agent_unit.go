// The agent's own systemd unit — one source, reconciled at startup.
//
// panel/agent/dockpanel-agent.service is the unit. setup.sh and update.sh
// deploy it by copying that exact file and derive their pre-mkdir list from
// its ReadWritePaths= line. install-agent.sh did not: it hand-wrote its own
// unit with systemd's four headline protection switches (new-privileges,
// system, home, private-tmp) turned off, no writable path list, and eight
// further hardening directives missing — and every remote fleet member ran
// that. (The disabled values are described, not quoted, deliberately:
// tests/sandbox-paths-pin-e2e.sh greps sources for them.)
//
// Fixing install-agent.sh alone reaches only NEW boxes: it runs once, and
// agent-self-update.sh swaps only the binary. The binary is what reaches every
// box (six-hourly self-update), so the unit rides the binary: AgentUnit is
// embedded from a byte-identical copy of the file the installers deploy, and
// AgentUnitHeal reconciles the on-disk unit against it at startup.
//
// Writing a hardened unit over an unhardened one could take a fleet offline
// at its next restart, so three guards, in order:
//  1. The directories are created first. An UNPREFIXED ReadWritePaths= entry
//     that does not exist fails the namespace mount and the unit does not
//     start at all (/etc/apt did this to every RPM box). /etc/nginx is
//     unprefixed and an agent-only box has no nginx.
//  2. PID1 is asked whether it accepted the file: after daemon-reload,
//     `systemctl show -p LoadError` reports what systemd actually thinks; a
//     non-empty LoadError restores the previous bytes and reloads again.
//  3. Nothing is restarted here. The new sandbox applies at the next start,
//     which the self-update performs anyway. An agent that restarted itself
//     out of its own cgroup could not observe its own failure.

package services

import (
	"context"
	_ "embed"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// AgentVersion is the agent's release version (Rust CARGO_PKG_VERSION).
// Overridable at build time with
// -ldflags "-X github.com/ovexro/dockpanel/panel/go/internal/agent/services.AgentVersion=...".
var AgentVersion = "2.242.1"

// AgentUnit is the canonical unit, embedded from a byte-identical copy of
// panel/agent/dockpanel-agent.service (a test pins the two together). The
// SINGLE source of this unit's contents — nothing else may spell it out.
//
//go:embed dockpanel-agent.service
var AgentUnit string

// agentUnitPath is where systemd reads the agent's unit on every install path.
const agentUnitPath = "/etc/systemd/system/dockpanel-agent.service"

// AgentUnitReadWritePaths lists the directories the unit's ReadWritePaths=
// names, with any `-` prefix stripped. Mirrors agent_rwp_dirs() in
// setup.sh/update.sh against the same source text.
func AgentUnitReadWritePaths(unit string) []string {
	var out []string
	for _, l := range strings.Split(unit, "\n") {
		v, ok := strings.CutPrefix(l, "ReadWritePaths=")
		if !ok {
			continue
		}
		for _, p := range strings.Fields(v) {
			p = strings.TrimPrefix(p, "-")
			if strings.HasPrefix(p, "/") {
				out = append(out, p)
			}
		}
	}
	return out
}

// AgentUnitHeal brings the on-disk unit up to the embedded one. No-op when
// the bytes already match (every panel box, and every fleet member from the
// second boot onward).
func AgentUnitHeal() {
	// Only ever reconcile a unit that is already there: writing one where
	// none exists would install the agent as a service on a box that chose
	// to run it some other way.
	cur, err := os.ReadFile(agentUnitPath)
	if err != nil {
		return
	}
	current := string(cur)
	if current == AgentUnit {
		return
	}

	// Guard 1 — the namespace mount. BEFORE the swap: a missing unprefixed
	// entry makes the agent unstartable, and then no agent is left to fix it.
	for _, dir := range AgentUnitReadWritePaths(AgentUnit) {
		if _, err := os.Stat(dir); err != nil {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				slog.Warn("agent unit heal: could not create " + dir + ": " + err.Error() + " — not swapping the unit")
				return
			}
		}
	}

	if err := os.WriteFile(agentUnitPath, []byte(AgentUnit), 0o644); err != nil {
		slog.Warn("agent unit heal: could not write " + agentUnitPath + ": " + err.Error())
		return
	}
	agentUnitSystemctl("daemon-reload")

	// Guard 2 — ask PID1 what it made of the file.
	out, _ := agentUnitSystemctl("show", "dockpanel-agent", "-p", "LoadError", "--value")
	if loadErr := strings.TrimSpace(string(out.Stdout)); loadErr != "" {
		slog.Error("agent unit heal: systemd rejected the new unit (" + loadErr + ") — restoring the previous one")
		_ = os.WriteFile(agentUnitPath, cur, 0o644)
		agentUnitSystemctl("daemon-reload")
		return
	}

	// Guard 3 — deliberately no restart.
	slog.Info("Healed " + agentUnitPath + " to the compiled-in unit (sandbox + ReadWritePaths); it takes effect at the next agent restart")
}

func agentUnitSystemctl(args ...string) (safecmd.Output, error) {
	// ponytail: Rust had no timeout here; 60 s bounds a wedged systemctl.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return safecmd.Exec(ctx, "systemctl", args...)
}
