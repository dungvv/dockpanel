package api

// Ported from services/prerequisites/mail.rs `tests`.

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

const prereqPEM = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\nhkiG9w0B\n-----END PUBLIC KEY-----\n"

func prereqMailRecords() []PrerequisitesDnsRecordHint {
	pem := prereqPEM
	return PrerequisitesMailRecords("example.com", "dockpanel", &pem, "203.0.113.7")
}

func prereqOfType(t string) PrerequisitesDnsRecordHint {
	for _, r := range prereqMailRecords() {
		if r.RecordType == t {
			return r
		}
	}
	panic(t)
}

func prereqTxtStarting(prefix string) PrerequisitesDnsRecordHint {
	for _, r := range prereqMailRecords() {
		if strings.HasPrefix(r.Value, prefix) {
			return r
		}
	}
	panic(prefix)
}

const prereqIP = "203.0.113.7"

// ── the record set ────────────────────────────────────────────────────

// The pre-v2.29.0 bug: the DNS tab published the agent's hostname where an
// address belongs.
func TestPrerequisitesRecordSetUsesTheIPItIsGivenEverywhere(t *testing.T) {
	a := prereqOfType("A")
	if a.Value != prereqIP || a.Fqdn != "example.com" {
		t.Fatal(a)
	}
	if !strings.Contains(prereqTxtStarting("v=spf1").Value, "ip4:203.0.113.7") {
		t.Fatal("SPF must carry a real address")
	}
}

// The MX target and the A record have to name the same host.
func TestPrerequisitesMxTargetMatchesTheARecord(t *testing.T) {
	a, mx := prereqOfType("A"), prereqOfType("MX")
	if !strings.HasSuffix(mx.Value, a.Fqdn) {
		t.Fatalf("%s should point at %s", mx.Value, a.Fqdn)
	}
}

// The advised topology must be the one auto-DNS publishes and auto-SSL's
// HTTP-01 order depends on.
func TestPrerequisitesAdvisedMailHostIsTheApex(t *testing.T) {
	if prereqOfType("A").Fqdn != "example.com" || prereqOfType("MX").Value != "10 example.com" {
		t.Fatal()
	}
}

func TestPrerequisitesDkimRecordUsesTheDomainsOwnSelector(t *testing.T) {
	pem := prereqPEM
	for _, r := range PrerequisitesMailRecords("example.com", "s2026", &pem, prereqIP) {
		if strings.HasPrefix(r.Value, "v=DKIM1") {
			if r.Fqdn != "s2026._domainkey.example.com" || r.Name != "s2026._domainkey" {
				t.Fatal(r)
			}
			return
		}
	}
	t.Fatal("no DKIM record")
}

func TestPrerequisitesDomainWithNoDkimKeyGetsNoDkimRecord(t *testing.T) {
	blank := "  "
	if len(PrerequisitesMailRecords("example.com", "dockpanel", nil, prereqIP)) != 4 ||
		len(PrerequisitesMailRecords("example.com", "dockpanel", &blank, prereqIP)) != 4 {
		t.Fatal("a blank key is not a key")
	}
	if len(prereqMailRecords()) != 5 {
		t.Fatal()
	}
}

func TestPrerequisitesDkimTxtStripsPemArmourAndNewlines(t *testing.T) {
	v := PrerequisitesMailDkimTxtValue(prereqPEM)
	if !strings.HasPrefix(v, "v=DKIM1; k=rsa; p=MIIBIjANBgkq") || strings.Contains(v, "\n") || strings.Contains(v, "BEGIN") {
		t.Fatal(v)
	}
}

// ── the matcher: what the old check got wrong ─────────────────────────

// The headline regression: the old check passed on ANY `v=spf1`, so a domain
// that explicitly forbids this server reported "verified".
func TestPrerequisitesSpfForADifferentServerDoesNotSatisfyUs(t *testing.T) {
	spf := prereqTxtStarting("v=spf1")
	if prerequisitesMailRecordSatisfies(&spf, "v=spf1 ip4:198.51.100.1 -all", prereqIP) {
		t.Fatal()
	}
}

// …but an operator whose SPF is stricter or broader than ours is fine.
func TestPrerequisitesRicherSpfRecordStillSatisfiesUs(t *testing.T) {
	spf := prereqTxtStarting("v=spf1")
	if !prerequisitesMailRecordSatisfies(&spf, "v=spf1 a mx ip4:203.0.113.7 include:sendgrid.net -all", prereqIP) ||
		!prerequisitesMailRecordSatisfies(&spf, "v=spf1 mx -all", prereqIP) {
		t.Fatal()
	}
}

// The old check passed on any MX — including the one sending our mail elsewhere.
func TestPrerequisitesMxPointingAtAnotherProviderDoesNotSatisfyUs(t *testing.T) {
	mx := prereqOfType("MX")
	if prerequisitesMailRecordSatisfies(&mx, "1 aspmx.l.google.com.", prereqIP) {
		t.Fatal()
	}
	// A backup MX at another preference is still our host.
	if !prerequisitesMailRecordSatisfies(&mx, "10 example.com.", prereqIP) || !prerequisitesMailRecordSatisfies(&mx, "50 example.com", prereqIP) {
		t.Fatal()
	}
}

// Both topologies this product has ever produced must pass.
func TestPrerequisitesConventionalMailSubdomainIsAcceptedToo(t *testing.T) {
	mx := prereqOfType("MX")
	if !prerequisitesMailRecordSatisfies(&mx, "10 mail.example.com.", prereqIP) || !prerequisitesMailRecordSatisfies(&mx, "20 mail.example.com", prereqIP) {
		t.Fatal()
	}
}

// The old check accepted `contains("p=")`, so a stale key passed.
func TestPrerequisitesDifferentDkimKeyDoesNotSatisfyUs(t *testing.T) {
	dkim := prereqTxtStarting("v=DKIM1")
	if !prerequisitesMailRecordSatisfies(&dkim, dkim.Value, prereqIP) {
		t.Fatal()
	}
	if prerequisitesMailRecordSatisfies(&dkim, "v=DKIM1; k=rsa; p=SOMEOTHERKEYENTIRELY00000000000000000000000000000000", prereqIP) {
		t.Fatal()
	}
}

// Providers split long TXT values into quoted chunks.
func TestPrerequisitesQuotedAndSplitDkimValuesStillMatch(t *testing.T) {
	dkim := prereqTxtStarting("v=DKIM1")
	split := fmt.Sprintf(`"%s" "%s"`, dkim.Value[:40], dkim.Value[40:])
	if !prerequisitesMailRecordSatisfies(&dkim, split, prereqIP) {
		t.Fatal()
	}
}

func TestPrerequisitesAnyDmarcPolicyCountsAsPublished(t *testing.T) {
	dmarc := prereqTxtStarting("v=DMARC1")
	if !prerequisitesMailRecordSatisfies(&dmarc, "v=DMARC1; p=reject", prereqIP) || prerequisitesMailRecordSatisfies(&dmarc, "not-a-dmarc-record", prereqIP) {
		t.Fatal()
	}
}

func TestPrerequisitesARecordMustBeThisServer(t *testing.T) {
	a := prereqOfType("A")
	if !prerequisitesMailRecordSatisfies(&a, prereqIP, prereqIP) || prerequisitesMailRecordSatisfies(&a, "198.51.100.1", prereqIP) {
		t.Fatal()
	}
}

// ── the checks ────────────────────────────────────────────────────────

func TestPrerequisitesMissingDkimKeyWarnsButNeverBlocks(t *testing.T) {
	r := PrerequisitesMailCheckDkimKeyPresent("example.com", nil)
	if r.Blocks() || r.State != PrerequisitesPrereqStateUnsatisfied || r.Severity != PrerequisitesPrereqSeverityWarning {
		t.Fatal(r)
	}
	pem, blank := prereqPEM, "   "
	if PrerequisitesMailCheckDkimKeyPresent("example.com", &pem).State != PrerequisitesPrereqStateSatisfied {
		t.Fatal()
	}
	if PrerequisitesMailCheckDkimKeyPresent("example.com", &blank).State != PrerequisitesPrereqStateUnsatisfied {
		t.Fatal("a blank key is not a key")
	}
}

func TestPrerequisitesUnknownServerIPIsUnknownNotAFailure(t *testing.T) {
	pem := prereqPEM
	r := PrerequisitesCheckMailDnsPublished(context.Background(), "example.com", "dockpanel", &pem, "")
	if r.State != PrerequisitesPrereqStateUnknown || r.Blocks() {
		t.Fatal(r)
	}
}

// A name dig would parse as an option must never reach the command line.
func TestPrerequisitesHostileDomainNameIsNotLookedUp(t *testing.T) {
	evil := PrerequisitesNewDnsRecordHint("x", "-f/etc/passwd", "TXT", "v=spf1", "300")
	if _, ok := prerequisitesMailLookup(context.Background(), &evil); ok {
		t.Fatal()
	}
}

// Nothing on the mail surface is gated, so nothing here may ever block.
func TestPrerequisitesMailPrerequisitesNeverGateAControl(t *testing.T) {
	for _, r := range PrerequisitesMailEvaluate(context.Background(), "example.invalid", "dockpanel", nil, prereqIP) {
		if r.Blocks() {
			t.Errorf("%s must not block", r.Key)
		}
	}
}
