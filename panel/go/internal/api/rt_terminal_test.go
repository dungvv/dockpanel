package api

import "testing"

// Both readers (list and the public viewer) decide expiry through
// rtTerminalShareLifetime — an expired or untimestamped share is gone for both.
func TestRtTerminalShareLifetime(t *testing.T) {
	now := int64(10_000)
	if c, rem, owner, content, ok := rtTerminalShareLifetime("9000|u1|a|b", now); !ok || c != 9000 || rem != 2600 || owner != "u1" || content != "a|b" {
		t.Fatalf("got %d %d %q %q %v", c, rem, owner, content, ok)
	}
	// Pre-owner row: owner "" (fail closed for list/revoke).
	if _, _, owner, content, ok := rtTerminalShareLifetime("9000|text", now); !ok || owner != "" || content != "text" {
		t.Fatal("legacy row")
	}
	for _, raw := range []string{"6400|u|x", "junk|u|x", "no-pipe-at-all"} {
		if _, _, _, _, ok := rtTerminalShareLifetime(raw, now); ok {
			t.Fatalf("%q should be expired/unusable", raw)
		}
	}
}

func TestRtTerminalValidShareID(t *testing.T) {
	if !rtTerminalValidShareID("0123456789ab") || rtTerminalValidShareID("0123456789a") || rtTerminalValidShareID("0123456789ag") {
		t.Fatal()
	}
}

func TestRtServersReplaceAgentToken(t *testing.T) {
	got := rtServersReplaceAgentToken("A=1\r\nAGENT_TOKEN=old\nB=2\n", "new")
	if got != "A=1\nAGENT_TOKEN=new\nB=2" {
		t.Fatalf("%q", got)
	}
}
