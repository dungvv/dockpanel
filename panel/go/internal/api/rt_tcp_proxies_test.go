package api

import "testing"

func TestTcpProxiesProxyNamesMatchTheAgentRule(t *testing.T) {
	for _, ok := range []string{"db-main", "redis-1"} {
		if !rtTcpProxiesValidProxyName(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"", "Name", "a b", "../x", "-x", "x-", "x;y"} {
		if rtTcpProxiesValidProxyName(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestTcpProxiesUpstreamHostsMatchTheAgentRule(t *testing.T) {
	for _, ok := range []string{"127.0.0.1", "[::1]", "db.internal"} {
		if !rtTcpProxiesValidUpstreamHost(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"", "a b", "999.1.1.1", "-x", "x.", "a..b", "h;rm -rf"} {
		if rtTcpProxiesValidUpstreamHost(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}
