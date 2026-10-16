package api

// Ported from services/prerequisites/backups.rs `tests`.

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func prereqBackupFacts() PrerequisitesBackupsPolicyDestinationFacts {
	return PrerequisitesBackupsPolicyDestinationFacts{PolicyName: "Nightly"}
}

func TestPrerequisitesPolicyWithNoDestinationWarnsAndNeverBlocks(t *testing.T) {
	f := prereqBackupFacts()
	r := PrerequisitesBackupsCheckBackupDestination(&f)
	if r.State != PrerequisitesPrereqStateUnsatisfied || r.Blocks() {
		t.Fatal("local-only backups are a legitimate choice", r)
	}
	if r.Remediation == nil || r.Remediation.Kind != PrerequisitesRemediationLink {
		t.Fatal(r.Remediation)
	}
}

// The copy has to change, or someone with a destination already configured
// is told to go and create one.
func TestPrerequisitesAdviceDependsOnWhetherADestinationExistsToPick(t *testing.T) {
	f := prereqBackupFacts()
	f.DestinationsAvailable = 2
	r := PrerequisitesBackupsCheckBackupDestination(&f)
	if !strings.Contains(r.Detail, "already have 2") {
		t.Fatal(r.Detail)
	}
	if r.Remediation == nil || r.Remediation.Kind != PrerequisitesRemediationLink || r.Remediation.Label != "Choose a destination" {
		t.Fatal(r.Remediation)
	}
}

// The dangerous state: the operator DID configure off-site backups and the
// destination was deleted, so they believe this is handled and it is not.
func TestPrerequisitesDanglingDestinationIsCalledOutDifferently(t *testing.T) {
	f := prereqBackupFacts()
	f.DestinationID = &uuid.Nil
	r := PrerequisitesBackupsCheckBackupDestination(&f)
	if r.State != PrerequisitesPrereqStateUnsatisfied || !strings.Contains(r.Title, "no longer exists") {
		t.Fatal(r)
	}
}

func TestPrerequisitesLiveDestinationIsSatisfiedAndNamesIt(t *testing.T) {
	f := prereqBackupFacts()
	f.DestinationID, f.DestinationExists, f.DestinationName = &uuid.Nil, true, new(string)
	*f.DestinationName = "wasabi-eu"
	r := PrerequisitesBackupsCheckBackupDestination(&f)
	if r.State != PrerequisitesPrereqStateSatisfied || !strings.Contains(r.Detail, "wasabi-eu") {
		t.Fatal(r)
	}
}

func TestPrerequisitesSitesWithNoPolicyWarnButAnEmptyPanelDoesNot(t *testing.T) {
	if PrerequisitesBackupsCheckAnyPolicyEnabled(0, 3).State != PrerequisitesPrereqStateUnsatisfied {
		t.Fatal()
	}
	if PrerequisitesBackupsCheckAnyPolicyEnabled(0, 0).State != PrerequisitesPrereqStateUnknown {
		t.Fatal("a panel with no sites is not neglecting anything")
	}
	if PrerequisitesBackupsCheckAnyPolicyEnabled(1, 3).State != PrerequisitesPrereqStateSatisfied {
		t.Fatal()
	}
}

// The registry proves its templates *can* be filled; this proves these
// callers *do* fill them.
func TestPrerequisitesNoBackupCheckLeaksAnUnfilledPlaceholder(t *testing.T) {
	name := "wasabi-eu"
	live := prereqBackupFacts()
	live.DestinationID, live.DestinationExists, live.DestinationName = &uuid.Nil, true, &name
	dangling := prereqBackupFacts()
	dangling.DestinationID = &uuid.Nil
	withOptions := prereqBackupFacts()
	withOptions.DestinationsAvailable = 2
	// A live destination whose name we don't have — the fallback branch, the
	// one a placeholder would hide in.
	unnamed := live
	unnamed.DestinationName = nil
	empty := prereqBackupFacts()

	cases := []PrerequisitesPrereqResult{
		PrerequisitesBackupsCheckBackupDestination(&empty),
		PrerequisitesBackupsCheckBackupDestination(&live),
		PrerequisitesBackupsCheckBackupDestination(&dangling),
		PrerequisitesBackupsCheckBackupDestination(&withOptions),
		PrerequisitesBackupsCheckBackupDestination(&unnamed),
		PrerequisitesBackupsCheckAnyPolicyEnabled(0, 0),
		PrerequisitesBackupsCheckAnyPolicyEnabled(0, 3),
		PrerequisitesBackupsCheckAnyPolicyEnabled(2, 3),
	}
	for _, r := range cases {
		if strings.Contains(r.Title, "{") || strings.Contains(r.Detail, "{") {
			t.Errorf("unfilled placeholder: %s / %s", r.Title, r.Detail)
		}
	}
}

// Nothing on the backup surface gates a control.
func TestPrerequisitesBackupPrerequisitesNeverGateAControl(t *testing.T) {
	f := prereqBackupFacts()
	if PrerequisitesBackupsCheckBackupDestination(&f).Blocks() || PrerequisitesBackupsCheckAnyPolicyEnabled(0, 5).Blocks() {
		t.Fatal()
	}
}
