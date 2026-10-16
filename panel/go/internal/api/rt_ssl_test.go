package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// The exact address that broke every issuance on the s252 audit box.
func TestSslRejectsTheAddressThatBrokeTheAuditBox(t *testing.T) {
	err := rtSslValidateAcmeContact("admin@dockpanel.test")
	if err == nil || !strings.Contains(err.Error(), ".test") {
		t.Fatalf("error must name the offending TLD: %v", err)
	}
}

func TestSslRejectsTheOtherReservedTLDs(t *testing.T) {
	for _, a := range []string{"a@box.local", "a@box.internal", "a@box.localhost", "a@box.invalid",
		"a@host.example", "a@box.lan", "a@box.home", "a@box.corp"} {
		if rtSslValidateAcmeContact(a) == nil {
			t.Errorf("%s must be rejected", a)
		}
	}
}

func TestSslRejectsMalformedAddresses(t *testing.T) {
	for _, a := range []string{"", "   ", "admin", "admin@", "@example.com", "a@b@c.com", "admin@localhost"} {
		if rtSslValidateAcmeContact(a) == nil {
			t.Errorf("%q must be rejected", a)
		}
	}
}

func TestSslRejectsABareOrNumericTLD(t *testing.T) {
	for _, a := range []string{"admin@example.c", "admin@example.123", "admin@.com", "admin@example."} {
		if rtSslValidateAcmeContact(a) == nil {
			t.Errorf("%q must be rejected", a)
		}
	}
}

// The guard must not be stricter than the CA — these all issue fine today.
func TestSslAcceptsRealAddresses(t *testing.T) {
	for _, a := range []string{"admin@example.com", "admin@example.dev", "someone+le@example.co.uk",
		"a.b-c_d@sub.domain.io", "  spaced@example.com  "} {
		if err := rtSslValidateAcmeContact(a); err != nil {
			t.Errorf("%s must be accepted: %v", a, err)
		}
	}
}

func rtSslTestMessage(t *testing.T, err error) (int, string) {
	t.Helper()
	ae, ok := err.(*ApiError)
	if !ok {
		t.Fatalf("not an ApiError: %v", err)
	}
	m, _ := ae.Body.(map[string]any)
	s, _ := m["error"].(string)
	return ae.Status, s
}

func rtSslLabelled(code, reason string) error {
	b, _ := json.Marshal(map[string]any{"error": reason, "code": code})
	return &AgentError{Kind: AgentErrStatus, Code: 500, Msg: string(b)}
}

func TestSslAProviderRefusalNamesTheTokenAndNeverPort80(t *testing.T) {
	// ⚠ A SUBDOMAIN site, deliberately: site == zone cannot see a site/zone
	// confusion at all — every fixture here keeps them distinct.
	status, m := rtSslTestMessage(t, rtSslDns01FailureOr("blog.example.com", "example.com", false,
		rtSslLabelled("dns_provider_failed", "Cloudflare refused to create the challenge record")))
	if status != 422 {
		t.Fatal(status)
	}
	for _, want := range []string{"DNS:Edit", "the example.com zone"} {
		if !strings.Contains(m, want) {
			t.Errorf("%q missing: %s", want, m)
		}
	}
	// ⭐ THE POINT OF THE WHOLE UNIT: an operator is on THIS door precisely
	// because port 80 cannot be reached.
	for _, bad := range []string{"the blog.example.com zone", "port 80", "try again"} {
		if strings.Contains(m, bad) {
			t.Errorf("%q present: %s", bad, m)
		}
	}
}

func TestSslADeclinedOrderNamesTheChallengeRecordAndNeverPort80(t *testing.T) {
	status, m := rtSslTestMessage(t, rtSslDns01FailureOr("blog.example.com", "example.com", false,
		rtSslLabelled("acme_order_failed", "The CA did not validate the DNS-01 challenge")))
	if status != 422 {
		t.Fatal(status)
	}
	// #663: this branch also fires on a rate limit, so the advice must stay conditional.
	for _, want := range []string{"_acme-challenge", "the example.com zone", "If that is a validation failure"} {
		if !strings.Contains(m, want) {
			t.Errorf("%q missing: %s", want, m)
		}
	}
	for _, bad := range []string{"the blog.example.com zone", "port 80", "try again"} {
		if strings.Contains(m, bad) {
			t.Errorf("%q present: %s", bad, m)
		}
	}
}

func TestSslAWildcardNamesTheCertificateThatWasActuallyOrdered(t *testing.T) {
	_, m := rtSslTestMessage(t, rtSslDns01FailureOr("example.com", "example.com", true,
		rtSslLabelled("acme_order_failed", "The CA refused the certificate order")))
	if !strings.Contains(m, "*.example.com") {
		t.Fatal(m)
	}
}

func TestSslAWildcardProviderRefusalAlsoNamesTheWildcard(t *testing.T) {
	status, m := rtSslTestMessage(t, rtSslDns01FailureOr("example.com", "example.com", true,
		rtSslLabelled("dns_provider_failed", "Cloudflare refused to create the challenge record")))
	if status != 422 || !strings.Contains(m, "*.example.com") || !strings.Contains(m, "DNS:Edit") || strings.Contains(m, "port 80") {
		t.Fatal(status, m)
	}
}

func TestSslAnUnlabelledFaultKeepsItsIncidentID(t *testing.T) {
	status, m := rtSslTestMessage(t, rtSslDns01FailureOr("blog.example.com", "example.com", false,
		&AgentError{Kind: AgentErrStatus, Code: 500, Msg: `{"error":"Create cert dir: Permission denied"}`}))
	if status != 502 || !strings.Contains(m, "Reference:") {
		t.Fatal(status, m)
	}
}
