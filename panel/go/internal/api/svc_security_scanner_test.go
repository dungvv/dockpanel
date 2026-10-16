package api

import (
	"strings"
	"testing"
)

// Extracting the shared helper must not change one character of the key — a
// live alert row for a currently-firing renewal failure already carries it.
func TestSecurityScannerStackRenewalStateKeyUnchangedByTheSharedHelperRefactor(t *testing.T) {
	if got := SecurityScannerStackRenewalStateKey("example.com"); got != "stack:failed:example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestSecurityScannerStateKeysTruncateAndHashLongNames(t *testing.T) {
	cases := []struct {
		prefix string
		key    func(string) string
		fill   string
	}{
		{"stack:failed:", SecurityScannerStackRenewalStateKey, "a"},
		{"stack:expiry:", SecurityScannerStackSslExpiryStateKey, "b"},
		{"cert:expiry:", SecurityScannerRegisteredCertExpiryStateKey, "c"},
		{"app:failed:", SecurityScannerDockerAppRenewalStateKey, "d"},
	}
	for _, c := range cases {
		key := c.key(strings.Repeat(c.fill, 200))
		if len(key) > 100 {
			t.Errorf("%s: state_key must fit alerts.state_key VARCHAR(100), got %d chars", c.prefix, len(key))
		}
		if !strings.HasPrefix(key, c.prefix) {
			t.Errorf("%s: got %q", c.prefix, key)
		}
	}
}

// The two ladders' keys must not collide for the SAME domain.
func TestSecurityScannerStackSslExpiryStateKeyIsDistinctFromTheRenewalKey(t *testing.T) {
	d := "example.com"
	if SecurityScannerStackRenewalStateKey(d) == SecurityScannerStackSslExpiryStateKey(d) {
		t.Fatal("keys collide")
	}
	if got := SecurityScannerStackSslExpiryStateKey(d); got != "stack:expiry:example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestSecurityScannerRegisteredCertExpiryStateKeyIsDistinctFromTheStackLadders(t *testing.T) {
	a := "example.com"
	k := SecurityScannerRegisteredCertExpiryStateKey(a)
	if k != "cert:expiry:example.com" {
		t.Fatalf("got %q", k)
	}
	if k == SecurityScannerStackSslExpiryStateKey(a) || k == SecurityScannerStackRenewalStateKey(a) {
		t.Fatal("cert key collides with a stack key")
	}
}
