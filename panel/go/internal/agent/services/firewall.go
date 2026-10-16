// Opening ports in the firewall this box is actually enforcing with.
//
// The agent only ever spoke `ufw`. On the RHEL family the running firewall is
// firewalld, so every `ufw allow` was either a no-op or landed in a rule set
// nothing was consulting — while the caller logged success anyway. setup.sh
// has the same distinction as FW_MGR; this is its agent-side counterpart.

package services

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// Firewall is the firewall this box is running.
type Firewall int

const (
	FirewallFirewalld Firewall = iota
	FirewallUfw
	// FirewallNone: no firewall is running. Opening a port is vacuously fine —
	// the port is already reachable — so callers should treat this as
	// success, or they will warn about a problem the box does not have.
	FirewallNone
)

var (
	firewallOnce sync.Once
	firewallFw   Firewall
)

// FirewallDetect is detected once per process. A firewall can in principle be
// installed while the agent runs, but every caller is a service installer,
// and the alternative is re-probing on every port.
func FirewallDetect() Firewall {
	firewallOnce.Do(func() {
		// firewalld first: when both are present it is the one whose nftables
		// rules the kernel is actually consulting on these distros.
		switch {
		case firewallRun("firewall-cmd", "--state"):
			firewallFw = FirewallFirewalld
		case firewallRun("ufw", "status"):
			firewallFw = FirewallUfw
		default:
			firewallFw = FirewallNone
		}
	})
	return firewallFw
}

// FirewallAllowTcp opens port/tcp and returns whether it is now allowed. The
// result is returned rather than discarded — a caller that logs "ports
// opened" without checking is stating something it does not know.
func FirewallAllowTcp(port string) bool {
	return FirewallAddPort(port, "tcp")
}

// FirewallReload applies staged firewalld rules. No-op elsewhere.
func FirewallReload() {
	if FirewallDetect() == FirewallFirewalld {
		firewallRun("firewall-cmd", "--reload")
	}
}

// FirewallAddPort opens port/proto — like FirewallAllowTcp but not tcp-only,
// for the Security page's own "add rule" feature.
func FirewallAddPort(port, proto string) bool {
	spec := port + "/" + proto
	switch FirewallDetect() {
	case FirewallFirewalld:
		// --permanent survives reboots but does nothing until reloaded; the
		// plain call applies now but is lost on restart. Both, then.
		permanent := firewallRun("firewall-cmd", "--permanent", "--add-port", spec)
		runtime := firewallRun("firewall-cmd", "--add-port", spec)
		return permanent && runtime
	case FirewallUfw:
		return firewallRun("ufw", "allow", spec)
	default:
		return true
	}
}

// FirewallRemovePort closes a port/proto previously opened with FirewallAddPort.
func FirewallRemovePort(port, proto string) bool {
	spec := port + "/" + proto
	switch FirewallDetect() {
	case FirewallFirewalld:
		permanent := firewallRun("firewall-cmd", "--permanent", "--remove-port", spec)
		runtime := firewallRun("firewall-cmd", "--remove-port", spec)
		return permanent && runtime
	case FirewallUfw:
		return firewallRun("ufw", "delete", "allow", spec)
	default:
		return true
	}
}

// FirewallRemoveService removes a firewalld service entry (e.g. ssh, http)
// from the default zone.
func FirewallRemoveService(name string) bool {
	if FirewallDetect() != FirewallFirewalld {
		return false
	}
	permanent := firewallRun("firewall-cmd", "--permanent", "--remove-service", name)
	runtime := firewallRun("firewall-cmd", "--remove-service", name)
	return permanent && runtime
}

// FirewallRichRuleSpec is the canonical firewall-cmd rich-rule spec for a
// port-scoped allow/deny, optionally source-restricted — firewalld's
// equivalent of a ufw rule with a deny action or a `from <source>` clause.
// Family is inferred from whether from looks like IPv6 (contains ':').
// from == "" means no source restriction (Rust None).
func FirewallRichRuleSpec(port, proto, action, from string) string {
	verdict := "accept"
	if strings.EqualFold(action, "deny") {
		verdict = "reject"
	}
	if from != "" {
		family := "ipv4"
		if strings.Contains(from, ":") {
			family = "ipv6"
		}
		return fmt.Sprintf(`rule family="%s" source address="%s" port port="%s" protocol="%s" %s`, family, from, port, proto, verdict)
	}
	return fmt.Sprintf(`rule family="ipv4" port port="%s" protocol="%s" %s`, port, proto, verdict)
}

// FirewallAddRichRule adds a rich rule built from FirewallRichRuleSpec.
func FirewallAddRichRule(port, proto, action, from string) bool {
	return FirewallAddRichRuleRaw(FirewallRichRuleSpec(port, proto, action, from))
}

// FirewallAddRichRuleRaw adds spec (--permanent + runtime).
func FirewallAddRichRuleRaw(spec string) bool {
	if FirewallDetect() != FirewallFirewalld {
		return false
	}
	permanent := firewallRun("firewall-cmd", "--permanent", "--add-rich-rule", spec)
	runtime := firewallRun("firewall-cmd", "--add-rich-rule", spec)
	return permanent && runtime
}

// FirewallRemoveRichRuleRaw removes a rich rule by its exact spec — pass back
// the line --list-rich-rules itself reported (not a rebuilt string), since
// firewalld's parser must resolve the text to the same stored rule.
func FirewallRemoveRichRuleRaw(spec string) bool {
	if FirewallDetect() != FirewallFirewalld {
		return false
	}
	permanent := firewallRun("firewall-cmd", "--permanent", "--remove-rich-rule", spec)
	runtime := firewallRun("firewall-cmd", "--remove-rich-rule", spec)
	return permanent && runtime
}

// FirewallAllowTcpPorts opens several ports and reports which ones failed,
// so the caller can say something true about the outcome.
func FirewallAllowTcpPorts(ports []string) []string {
	failed := []string{}
	for _, p := range ports {
		if !FirewallAllowTcp(p) {
			failed = append(failed, p)
		}
	}
	FirewallReload()
	return failed
}

func firewallRun(bin string, args ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, bin, args...)
	return err == nil && out.Success()
}
