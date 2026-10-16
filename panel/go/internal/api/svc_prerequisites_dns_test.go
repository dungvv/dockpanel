package api

// Ported from services/prerequisites/dns.rs `tests`.

import (
	"context"
	"testing"
)

func TestPrerequisitesApexDomainsUseTheAtSign(t *testing.T) {
	if h, a := prerequisitesSplitRecordName("example.com"); h != "@" || a != "example.com" {
		t.Fatal(h, a)
	}
}

func TestPrerequisitesSubdomainsKeepOnlyTheirHostPart(t *testing.T) {
	if h, a := prerequisitesSplitRecordName("www.example.com"); h != "www" || a != "example.com" {
		t.Fatal(h, a)
	}
	if h, a := prerequisitesSplitRecordName("a.b.example.com"); h != "a.b" || a != "example.com" {
		t.Fatal(h, a)
	}
}

func TestPrerequisitesRejectsThingsThatAreNotDomains(t *testing.T) {
	for _, bad := range []string{"", "localhost", "no-dot", ".leading.com", "trailing.com.", "a b.com", "sp@ce.com"} {
		if prerequisitesLooksLikeADomain(bad) {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestPrerequisitesAcceptsOrdinaryDomains(t *testing.T) {
	for _, good := range []string{"example.com", "www.example.com", "a-b.example.co.uk", "x.y.z.example.io"} {
		if !prerequisitesLooksLikeADomain(good) {
			t.Errorf("%s must be accepted", good)
		}
	}
}

func TestPrerequisitesMalformedDomainIsUnknownNotAFailure(t *testing.T) {
	r := PrerequisitesCheckDnsPointsHere(context.Background(), "not-a-domain")
	if r.State != PrerequisitesPrereqStateUnknown || r.Blocks() {
		t.Fatal(r)
	}
}
