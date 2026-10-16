package api

import (
	"strings"
	"testing"
)

// The grammar is shared with the agent by text, so both edges matter: the
// longest legal alias must pass and every shape that would not be a safe
// directory name must fail.
func TestTlsCertificatesAliasGrammarIsADNSLabel(t *testing.T) {
	for _, ok := range []string{"a", "wildcard-example-com", "corp2026", strings.Repeat("a", 64)} {
		if !rtTlsCertificatesIsValidCertAlias(ok) {
			t.Errorf("%q must be accepted", ok)
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", 65), "-leading", "trailing-", "Upper",
		"has.dot", "has/slash", "..", "under_score", "with space"} {
		if rtTlsCertificatesIsValidCertAlias(bad) {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// The version gate is pinned to the release that shipped the registry. A bump
// here would refuse every agent between the two releases for no reason; a
// drop would let an older agent downgrade a provided domain.
func TestTlsCertificatesProvidedTLSGateIsFrozen(t *testing.T) {
	if rtTlsCertificatesProvidedTlsMinAgent != "2.160.0" {
		t.Fatal(rtTlsCertificatesProvidedTlsMinAgent)
	}
}
