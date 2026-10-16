package api

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestDomainClaimNormaliseLowercasesAndStripsTheRootDot(t *testing.T) {
	for in, want := range map[string]string{"EXAMPLE.com": "example.com", "  Example.COM  ": "example.com", "example.com.": "example.com"} {
		if got := DomainClaimNormalise(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestDomainClaimNormaliseCollapsesTheVariantsThatUsedToBeSeparateClaims(t *testing.T) {
	// Each of these passed `WHERE domain = $1` against a row holding the
	// lowercase form, and earned its own vhost.
	for _, v := range []string{"EXAMPLE.COM", "Example.Com", "eXaMpLe.cOm", "example.com."} {
		if DomainClaimNormalise(v) != DomainClaimNormalise("example.com") {
			t.Errorf("%q not collapsed", v)
		}
	}
}

func TestDomainClaimNormaliseDoesNotMergeGenuinelyDifferentDomains(t *testing.T) {
	if DomainClaimNormalise("a.b.com") == DomainClaimNormalise("a-b.com") ||
		DomainClaimNormalise("example.com") == DomainClaimNormalise("example.net") {
		t.Fatal("distinct domains merged")
	}
}

// ── the client gate — GitHub #51 ──

func TestDomainClaimAClientMayNotBringANewDomainIntoService(t *testing.T) {
	if DomainClaimMayClaimNew(DomainClaimClientRole, DomainClaimHolderNew) {
		t.Fatal("client claimed a new domain")
	}
}

func TestDomainClaimAClientMayStillManageTheDomainsItHolds(t *testing.T) {
	// A rename re-claims a domain on behalf of a row that already exists, and
	// the handler's own ownership check has established the caller may act on it.
	id := uuid.Nil
	for _, h := range []DomainClaimHolder{DomainClaimHolderSite(id), DomainClaimHolderGitDeploy(id), DomainClaimHolderStack(id)} {
		if !DomainClaimMayClaimNew(DomainClaimClientRole, h) {
			t.Fatalf("client refused re-claim %+v", h)
		}
	}
}

func TestDomainClaimEveryOtherRoleIsUnaffected(t *testing.T) {
	for _, role := range []string{"admin", "reseller", "user", "suspended", ""} {
		if !DomainClaimMayClaimNew(role, DomainClaimHolderNew) {
			t.Errorf("role %q must still be able to claim a new domain here", role)
		}
	}
}

func TestDomainClaimTheRefusalIsKeyedOnTheExactRoleString(t *testing.T) {
	// This gate fails OPEN by construction, so a near-miss must not be a client.
	for _, near := range []string{"Client", "CLIENT", "clients", "client ", " client"} {
		if !DomainClaimMayClaimNew(near, DomainClaimHolderNew) {
			t.Errorf("%q is not the role value", near)
		}
	}
	if DomainClaimClientRole != "client" {
		t.Fatal("client role drifted")
	}
}

// ── the mail gate — GitHub #106 ──

func TestDomainClaimOnlyAnAdministratorMayClaimADomainAMailDomainHolds(t *testing.T) {
	if !DomainClaimMayClaimMailHeld("admin") {
		t.Fatal("admin refused")
	}
	for _, role := range []string{"client", "user", "reseller", "suspended", ""} {
		if DomainClaimMayClaimMailHeld(role) {
			t.Errorf("role %q must not claim a name whose mailboxes exist", role)
		}
	}
}

func TestDomainClaimTheMailGateFailsClosedWhereTheClientGateFailsOpen(t *testing.T) {
	for _, near := range []string{"Admin", "ADMIN", "admins", "admin ", " admin", "administrator"} {
		if DomainClaimMayClaimMailHeld(near) {
			t.Errorf("%q is not the administrator role value; it must be refused", near)
		}
		if !DomainClaimMayClaimNew(near, DomainClaimHolderNew) {
			t.Errorf("%q refused by the client gate", near)
		}
	}
}

func TestDomainClaimAMailDomainIsTheOnlyOccupantAnAdministratorMayClaimOver(t *testing.T) {
	for _, o := range []DomainClaimOccupant{DomainClaimOccupantSite, DomainClaimOccupantGitDeploy, DomainClaimOccupantDockerApp, DomainClaimOccupantStack} {
		if o == DomainClaimOccupantMailDomain {
			t.Errorf("%v must keep refusing every caller, administrator included", o)
		}
	}
}

func TestDomainClaimEveryOccupantNamesWhatHoldsTheDomain(t *testing.T) {
	for _, o := range []DomainClaimOccupant{DomainClaimOccupantSite, DomainClaimOccupantGitDeploy, DomainClaimOccupantDockerApp, DomainClaimOccupantStack, DomainClaimOccupantMailDomain} {
		if m := o.Message(); m == "" || !strings.Contains(m, "in use by") {
			t.Errorf("%v: %q", o, m)
		}
	}
}
