package api

// Ported from services/prerequisites/apps.rs `tests`.

import (
	"strings"
	"testing"
)

func prereqIntent() *PrerequisitesAppsAppDeployIntent {
	return &PrerequisitesAppsAppDeployIntent{TemplateID: "postgres", Name: "postgres", Port: 5432, Env: map[string]string{}}
}

func prereqSpec(name, def string, required, secret bool) PrerequisitesAppsAppEnvSpec {
	return PrerequisitesAppsAppEnvSpec{Name: name, Label: name, Default: def, Required: required, Secret: secret}
}

func prereqU64(v uint64) *uint64 { return &v }
func prereqBool(v bool) *bool    { return &v }

// ── required env ──────────────────────────────────────────────────────

// The shipped shape of the 104 affected templates: required, no default.
func TestPrerequisitesRequiredVarWithNoDefaultAndNoValueBlocks(t *testing.T) {
	r := PrerequisitesAppsCheckRequiredEnv(prereqIntent(), []PrerequisitesAppsAppEnvSpec{prereqSpec("POSTGRES_PASSWORD", "", true, true)})
	if !r.Blocks() || !strings.Contains(r.Detail, "Generate") {
		t.Fatal("an all-secret set should block and offer generation", r)
	}
}

func TestPrerequisitesRequiredVarWithADefaultIsSatisfied(t *testing.T) {
	// The agent falls back to the default, so nothing is missing.
	if PrerequisitesAppsCheckRequiredEnv(prereqIntent(), []PrerequisitesAppsAppEnvSpec{prereqSpec("PUID", "1000", true, false)}).Blocks() {
		t.Fatal()
	}
}

func TestPrerequisitesOptionalVarNeverBlocks(t *testing.T) {
	if PrerequisitesAppsCheckRequiredEnv(prereqIntent(), []PrerequisitesAppsAppEnvSpec{prereqSpec("TZ", "", false, false)}).Blocks() {
		t.Fatal()
	}
}

// Whitespace is not a value: a container given `PASSWORD=" "` is
// misconfigured in a way the user did not intend.
func TestPrerequisitesWhitespaceDoesNotSatisfyARequiredVar(t *testing.T) {
	i := prereqIntent()
	i.Env["POSTGRES_PASSWORD"] = "   "
	if !PrerequisitesAppsCheckRequiredEnv(i, []PrerequisitesAppsAppEnvSpec{prereqSpec("POSTGRES_PASSWORD", "", true, true)}).Blocks() {
		t.Fatal()
	}
}

func TestPrerequisitesSuppliedValueSatisfiesTheCheck(t *testing.T) {
	i := prereqIntent()
	i.Env["POSTGRES_PASSWORD"] = "hunter2"
	if PrerequisitesAppsCheckRequiredEnv(i, []PrerequisitesAppsAppEnvSpec{prereqSpec("POSTGRES_PASSWORD", "", true, true)}).Blocks() {
		t.Fatal()
	}
}

// ── port ──────────────────────────────────────────────────────────────

func TestPrerequisitesPortHeldByAManagedAppBlocksAndNamesTheHolder(t *testing.T) {
	facts := &PrerequisitesAppsHostFacts{
		UsedPorts:     []PrerequisitesAppsPortHolder{{Port: 5432, Description: "the app `pg-old`"}},
		PortProbeFree: prereqBool(false),
	}
	r := PrerequisitesAppsCheckPortAvailable(prereqIntent(), facts)
	if !r.Blocks() || !strings.Contains(r.Detail, "pg-old") {
		t.Fatal("must name what holds the port", r)
	}
	if r.Remediation == nil || r.Remediation.Kind != PrerequisitesRemediationValue {
		t.Fatal(r.Remediation)
	}
}

// Nothing of ours holds it, but the host says the bind fails — still fatal.
func TestPrerequisitesPortHeldBySomethingUnmanagedStillBlocks(t *testing.T) {
	r := PrerequisitesAppsCheckPortAvailable(prereqIntent(), &PrerequisitesAppsHostFacts{PortProbeFree: prereqBool(false)})
	if !r.Blocks() || !strings.Contains(r.Detail, "managed by DockPanel") || len(r.Observed) != 0 {
		t.Fatal("we cannot name a holder we don't manage", r)
	}
}

// The fleet case: an agent too old to have /system/port-check. A check we
// cannot run must never turn into a refusal.
func TestPrerequisitesUnprobeablePortIsUnknownNotBlocked(t *testing.T) {
	r := PrerequisitesAppsCheckPortAvailable(prereqIntent(), &PrerequisitesAppsHostFacts{})
	if r.Blocks() || r.State != PrerequisitesPrereqStateUnknown {
		t.Fatal(r)
	}
}

func TestPrerequisitesFreePortIsSatisfied(t *testing.T) {
	if PrerequisitesAppsCheckPortAvailable(prereqIntent(), &PrerequisitesAppsHostFacts{PortProbeFree: prereqBool(true)}).State != PrerequisitesPrereqStateSatisfied {
		t.Fatal()
	}
}

// The suggestion must skip every port we know is taken, not merely the one asked for.
func TestPrerequisitesSuggestedPortSkipsAllKnownHolders(t *testing.T) {
	facts := &PrerequisitesAppsHostFacts{
		UsedPorts:     []PrerequisitesAppsPortHolder{{8080, "a"}, {8081, "b"}, {8082, "c"}},
		PortProbeFree: prereqBool(false),
	}
	i := prereqIntent()
	i.Port = 8080
	r := PrerequisitesAppsCheckPortAvailable(i, facts)
	if r.Remediation == nil || r.Remediation.Kind != PrerequisitesRemediationValue || r.Remediation.Value != "8083" {
		t.Fatal("expected a port suggestion", r.Remediation)
	}
}

// ── name ──────────────────────────────────────────────────────────────

func TestPrerequisitesTakenNameBlocksAndSuggestsTheNextFreeOne(t *testing.T) {
	r := PrerequisitesAppsCheckNameAvailable(prereqIntent(), &PrerequisitesAppsHostFacts{TakenNames: []string{"postgres", "postgres-2"}})
	if !r.Blocks() || r.Remediation == nil || r.Remediation.Value != "postgres-3" {
		t.Fatal(r)
	}
}

// A check that missed `Postgres` would hand the user a name that still collides.
func TestPrerequisitesNameCollisionIsCaseInsensitive(t *testing.T) {
	if !PrerequisitesAppsCheckNameAvailable(prereqIntent(), &PrerequisitesAppsHostFacts{TakenNames: []string{"POSTGRES"}}).Blocks() {
		t.Fatal()
	}
}

// TakenNames must hold the names the USER types, not the agent's
// `dockpanel-app-<name>` container names — feeding the prefixed form in
// compares two things that can never be equal (v2.29.0). The stripping lives
// in the docker_apps route; this pins the contract it must satisfy.
func TestPrerequisitesTakenNamesAreUserFacingNamesNotContainerNames(t *testing.T) {
	if PrerequisitesAppsCheckNameAvailable(prereqIntent(), &PrerequisitesAppsHostFacts{TakenNames: []string{"dockpanel-app-postgres"}}).Blocks() {
		t.Fatal("sanity: a prefixed name cannot match — which is exactly why the caller must strip it")
	}
	if !PrerequisitesAppsCheckNameAvailable(prereqIntent(), &PrerequisitesAppsHostFacts{TakenNames: []string{"postgres"}}).Blocks() {
		t.Fatal("the caller must pass stripped names, or this check is inert")
	}
}

// ── memory ────────────────────────────────────────────────────────────

func TestPrerequisitesMoreMemoryThanTheBoxHasWarnsButNeverBlocks(t *testing.T) {
	i := prereqIntent()
	i.MemoryMB = prereqU64(8192)
	r := PrerequisitesAppsCheckResourceHeadroom(i, &PrerequisitesAppsHostFacts{MemTotalMB: prereqU64(2048), MemUsedMB: prereqU64(900)})
	if r.Blocks() || r.State != PrerequisitesPrereqStateUnsatisfied {
		t.Fatal("over-committing memory is the operator's call", r)
	}
}

func TestPrerequisitesNoMemoryLimitMeansNothingToCheck(t *testing.T) {
	r := PrerequisitesAppsCheckResourceHeadroom(prereqIntent(), &PrerequisitesAppsHostFacts{MemTotalMB: prereqU64(2048), MemUsedMB: prereqU64(900)})
	if r.State != PrerequisitesPrereqStateUnknown {
		t.Fatal(r)
	}
}

func TestPrerequisitesLimitThatFitsInFreeMemoryIsSatisfied(t *testing.T) {
	i := prereqIntent()
	i.MemoryMB = prereqU64(512)
	if PrerequisitesAppsCheckResourceHeadroom(i, &PrerequisitesAppsHostFacts{MemTotalMB: prereqU64(2048), MemUsedMB: prereqU64(900)}).State != PrerequisitesPrereqStateSatisfied {
		t.Fatal()
	}
}

// ── the set ───────────────────────────────────────────────────────────

// The whole point of the gate: a deploy that would fail is refused before the
// image pull, and FirstBlocker names the reason.
func TestPrerequisitesEvaluateSurfacesTheFirstBlocker(t *testing.T) {
	facts := &PrerequisitesAppsHostFacts{
		UsedPorts:     []PrerequisitesAppsPortHolder{{5432, "the app `pg`"}},
		PortProbeFree: prereqBool(false),
	}
	results := PrerequisitesAppsEvaluate(prereqIntent(), []PrerequisitesAppsAppEnvSpec{prereqSpec("POSTGRES_PASSWORD", "", true, true)}, facts)
	if b := PrerequisitesFirstBlocker(results); b == nil || b.Key != "apps.required_env" {
		t.Fatal(b)
	}
}

// No check may leak an unfilled `{placeholder}`: the registry proves each
// template can be filled from its declared vars; this proves the callers pass them.
func TestPrerequisitesNoAppCheckLeaksAnUnfilledPlaceholder(t *testing.T) {
	taken := prereqIntent()
	taken.MemoryMB = prereqU64(8192)
	facts := &PrerequisitesAppsHostFacts{
		UsedPorts:     []PrerequisitesAppsPortHolder{{5432, "the app `pg`"}},
		TakenNames:    []string{"postgres"},
		MemTotalMB:    prereqU64(2048),
		MemUsedMB:     prereqU64(900),
		PortProbeFree: prereqBool(false),
	}
	specs := []PrerequisitesAppsAppEnvSpec{prereqSpec("POSTGRES_PASSWORD", "", true, true), prereqSpec("TZ", "", true, false)}
	cases := PrerequisitesAppsEvaluate(taken, specs, facts)
	// The other side of every branch: empty host, nothing probeable, a form
	// not filled in yet.
	blank := prereqIntent()
	blank.Name, blank.Port = "", 0
	cases = append(cases, PrerequisitesAppsEvaluate(blank, nil, &PrerequisitesAppsHostFacts{})...)
	cases = append(cases, PrerequisitesAppsCheckPortAvailable(prereqIntent(), &PrerequisitesAppsHostFacts{PortProbeFree: prereqBool(true)}))
	small, mid := prereqIntent(), prereqIntent()
	small.MemoryMB, mid.MemoryMB = prereqU64(64), prereqU64(1500)
	cases = append(cases,
		PrerequisitesAppsCheckResourceHeadroom(small, &PrerequisitesAppsHostFacts{MemTotalMB: prereqU64(2048), MemUsedMB: prereqU64(100)}),
		PrerequisitesAppsCheckResourceHeadroom(mid, &PrerequisitesAppsHostFacts{MemTotalMB: prereqU64(2048), MemUsedMB: prereqU64(1000)}))
	for _, r := range cases {
		if strings.Contains(r.Title, "{") || strings.Contains(r.Detail, "{") {
			t.Errorf("unfilled placeholder: %s / %s", r.Title, r.Detail)
		}
	}
}

func TestPrerequisitesCompleteIntentOnAHealthyHostBlocksOnNothing(t *testing.T) {
	i := prereqIntent()
	i.Env["POSTGRES_PASSWORD"] = "s3cret"
	i.MemoryMB = prereqU64(256)
	facts := &PrerequisitesAppsHostFacts{MemTotalMB: prereqU64(2048), MemUsedMB: prereqU64(400), PortProbeFree: prereqBool(true)}
	if PrerequisitesFirstBlocker(PrerequisitesAppsEvaluate(i, []PrerequisitesAppsAppEnvSpec{prereqSpec("POSTGRES_PASSWORD", "", true, true)}, facts)) != nil {
		t.Fatal()
	}
}
