package api

// Port of services/prerequisites/backups.rs — the backups vertical, "will
// these backups survive losing this machine?"
//
// The cheapest check in the layer and the one with the worst failure mode. A
// backup policy with no destination writes its archives to
// /var/backups/dockpanel on the same disk it is insuring: it protects against
// a bad deploy or a dropped table, and against nothing else. Nothing said so
// anywhere — the Destination dropdown's empty value was silently accepted and
// the run reported `success`.
//
// Until v2.29.0 the executor selected `destination_id` and never read it, so
// choosing a destination made no difference either; that is fixed, which is
// what makes this check trustworthy rather than guidance that lies.

import (
	"strconv"

	"github.com/google/uuid"
)

// PrerequisitesBackupsPolicyDestinationFacts is what we know about one
// policy's off-site story.
type PrerequisitesBackupsPolicyDestinationFacts struct {
	PolicyName    string
	DestinationID *uuid.UUID
	// The destination row still exists. A policy can point at a deleted one.
	DestinationExists bool
	DestinationName   *string
	// How many destinations are configured panel-wide — decides whether the
	// fix is "pick one" or "create one".
	DestinationsAvailable int
}

// PrerequisitesBackupsCheckBackupDestination: does this backup policy send its
// backups anywhere off this server?
//
// Warning, not Blocking, and this one is worth defending. Local-only backups
// are a legitimate choice — plenty of people run a box whose real protection
// is their provider's snapshots, and refusing to save a policy without a
// destination would be the panel overriding a decision that is not its to
// make. What is *not* legitimate is making that choice by accident and never
// being told. A policy pointing at a destination that no longer exists is
// still a warning, but a different sentence: the operator did choose and the
// choice silently stopped applying.
func PrerequisitesBackupsCheckBackupDestination(facts *PrerequisitesBackupsPolicyDestinationFacts) PrerequisitesPrereqResult {
	name := facts.PolicyName
	check := PrerequisitesCopyBackupsDestCheck

	switch {
	case facts.DestinationID != nil && facts.DestinationExists:
		// Chose one, it's there. The only good outcome.
		dest := "its destination"
		if facts.DestinationName != nil {
			dest = *facts.DestinationName
		}
		return check.Result(PrerequisitesCopyBackupsDestUploads, [][2]string{{"policy", name}, {"destination", dest}})

	case facts.DestinationID != nil:
		// Chose one, it's gone. Materially worse than never having chosen: the
		// operator believes this is handled. The fix is on the POLICY, so the
		// link goes where the policy is edited (the destinations tab lists
		// destinations and cannot attach one).
		return check.Result(PrerequisitesCopyBackupsDestDeleted, [][2]string{{"policy", name}}).
			WithRemediation(PrerequisitesNewRemediationLink("Edit the policy", "/backup-orchestrator?tab=policies"))
	}

	// Never chose one. The advice differs by whether there is anything to pick
	// — telling someone to create a destination they already have is how
	// guidance loses its credibility. Two different actions, so two different
	// destinations: attaching one happens on the policy, creating one does not.
	if facts.DestinationsAvailable > 0 {
		return check.Result(PrerequisitesCopyBackupsDestLocalWithOptions,
			[][2]string{{"policy", name}, {"available", strconv.Itoa(facts.DestinationsAvailable)}}).
			WithRemediation(PrerequisitesNewRemediationLink("Choose a destination", "/backup-orchestrator?tab=policies"))
	}
	return check.Result(PrerequisitesCopyBackupsDestLocalNoOptions, [][2]string{{"policy", name}}).
		WithRemediation(PrerequisitesNewRemediationLink("Add a destination", "/backup-orchestrator?tab=destinations"))
}

// PrerequisitesBackupsCheckAnyPolicyEnabled: is anything being backed up at
// all? Distinct from the destination question and prior to it — a panel with
// zero enabled policies has nothing to send anywhere.
func PrerequisitesBackupsCheckAnyPolicyEnabled(enabledPolicies, sites int) PrerequisitesPrereqResult {
	check := PrerequisitesCopyBackupsPolicyCheck
	if sites == 0 {
		return check.Result(PrerequisitesCopyBackupsPolicyNothing, nil)
	}
	if enabledPolicies > 0 {
		return check.Result(PrerequisitesCopyBackupsPolicyRunning, [][2]string{{"count", strconv.Itoa(enabledPolicies)}})
	}
	return check.Result(PrerequisitesCopyBackupsPolicyNone, [][2]string{{"sites", strconv.Itoa(sites)}}).
		WithRemediation(PrerequisitesNewRemediationLink("Create a backup policy", "/backup-orchestrator?tab=policies"))
}
