package api

import (
	"encoding/json"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// update.sh as it will actually be shipped (deployed as a file, invoked by path).
func panelUpdateTestScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../../../scripts/update.sh")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The verdict file has to exist on both ends or it is not a channel.
func TestPanelUpdateUpdaterAndOrchestratorAgreeOnWhereTheVerdictLives(t *testing.T) {
	if !strings.Contains(panelUpdateTestScript(t), "last-panel-update.json") {
		t.Fatal("update.sh must record its outcome somewhere that outlives it")
	}
	if !strings.HasSuffix(panelUpdateResultPath, "last-panel-update.json") {
		t.Fatal("the orchestrator must read the file update.sh writes")
	}
}

// Every exit path leaves a verdict — that is what an EXIT trap is for.
func TestPanelUpdateUpdaterWritesAVerdictFromATrap(t *testing.T) {
	s := panelUpdateTestScript(t)
	for _, want := range []string{
		"trap _dockpanel_on_exit EXIT",
		`_dockpanel_write_result true "complete"`,
		`_dockpanel_write_result false "rollback"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("update.sh lacks %q", want)
		}
	}
}

// The detached unit must outlive the api it stops: --wait would block inside
// the cgroup being killed, --pipe would SIGPIPE the updater mid-swap. Counts
// EXECUTABLE lines only — the script documents why it avoids these flags.
func TestPanelUpdateUpdaterDoesNotWaitOnItsOwnDetachedUnit(t *testing.T) {
	s := panelUpdateTestScript(t)
	if !strings.Contains(s, "exec systemd-run") {
		t.Fatal("the updater must escape the api's control group")
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, forbidden := range []string{"--wait", "--pipe"} {
			if strings.Contains(line, forbidden) {
				t.Errorf("%s would tie the detached unit's life to the api being stopped: %s", forbidden, line)
			}
		}
	}
}

// A zero exit from the handoff must never be promoted to a success claim
// (lesson #49).
func TestPanelUpdateAZeroExitFromTheHandoffIsNotASuccessfulUpdate(t *testing.T) {
	src, err := os.ReadFile("svc_panel_update.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `never "the work succeeded"`) {
		t.Fatal("the reason a zero exit proves nothing must stay written down next to the code")
	}
	if !strings.Contains(string(src), "panelUpdateVerdictSince(") {
		t.Fatal("the outcome must be read from the updater's own record")
	}
}

// Captured verbatim from a real update.sh run (non-root, aborted at preflight).
const panelUpdateRealVerdict = `{"target_version":"v2.47.4","ok":false,"stage":"preflight","detail":"update aborted at stage 'preflight' with exit code 1","finished_at":"2026-07-28T17:33:32Z"}`

func panelUpdateTestValue(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPanelUpdateOrchestratorCanReadWhatTheUpdaterActuallyWrites(t *testing.T) {
	before, _ := time.Parse(time.RFC3339, "2026-07-28T17:30:00Z")
	v := panelUpdateVerdictFromValue(panelUpdateTestValue(t, panelUpdateRealVerdict), before)
	if v == nil {
		t.Fatal("a verdict from after the run must be read")
	}
	if v.OK || v.Stage != "preflight" || !strings.Contains(v.Detail, "exit code 1") {
		t.Fatalf("%+v", v)
	}
}

// A previous run's verdict is not this run's — the file is overwritten in place.
func TestPanelUpdateAStaleVerdictIsNotAttributedToANewRun(t *testing.T) {
	after, _ := time.Parse(time.RFC3339, "2026-07-28T18:00:00Z")
	if panelUpdateVerdictFromValue(panelUpdateTestValue(t, panelUpdateRealVerdict), after) != nil {
		t.Fatal("a verdict finished before the run started is not this run's")
	}
}

// Absent or half-written files read as "no verdict yet", never a failure.
func TestPanelUpdateAMissingOrTornVerdictIsNotAFailure(t *testing.T) {
	since := time.Now()
	for _, junk := range []string{
		`{}`,
		`{"ok": false}`,
		`{"finished_at": "not-a-date", "ok": false}`,
		`{"finished_at": "2026-07-28T17:33:32Z"}`,
	} {
		if panelUpdateVerdictFromValue(panelUpdateTestValue(t, junk), since) != nil {
			t.Errorf("incomplete verdict read as a verdict: %s", junk)
		}
	}
}

func TestPanelUpdateTargetVersionAcceptsCanonicalShapes(t *testing.T) {
	for _, v := range []string{"v2.10.0", "2.10.0", "v2.10.0-rc.1", "2.10.0-rc.12", "v10.20.30"} {
		if !PanelUpdateValidateTargetVersion(v) {
			t.Errorf("%q refused", v)
		}
	}
}

func TestPanelUpdateTargetVersionRejectsGarbage(t *testing.T) {
	for _, v := range []string{"", "v", "v2", "v2.10", "v2.10.0.1", "v2.10.0-alpha", "v2.10.0-rc", "v2.10.0-rc.", "v2.10.0-rc.a", "v2.10.0 ", "2.10.0; rm -rf /", "latest"} {
		if PanelUpdateValidateTargetVersion(v) {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestPanelUpdateParseTargetFromTriggerMatchesPreUpdate(t *testing.T) {
	if v, ok := panelUpdateParseTargetFromTrigger("pre-update:v2.10.0"); !ok || v != "v2.10.0" {
		t.Fatal(v)
	}
	if v, ok := panelUpdateParseTargetFromTrigger("pre-update:v2.10.0-rc.1"); !ok || v != "v2.10.0-rc.1" {
		t.Fatal(v)
	}
	for _, s := range []string{"manual", "fleet:6f1c2d0e-0000-4000-8000-000000000000"} {
		if _, ok := panelUpdateParseTargetFromTrigger(s); ok {
			t.Fatalf("%q parsed", s)
		}
	}
}

func panelUpdateTestPtr(s string) *string { return &s }

// Postgres sorting agent_version as text puts 2.9.0 AFTER 2.10.0 — the rolling
// update would start with the NEWEST box while claiming the oldest.
func TestPanelUpdateFleetPlanOrdersBySemverNotLexicographically(t *testing.T) {
	vs := []*string{panelUpdateTestPtr("2.10.0"), panelUpdateTestPtr("v2.9.0"), nil, panelUpdateTestPtr("2.11.7"), panelUpdateTestPtr("2.9.10")}
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := PanelUpdateSemverKey(vs[i]), PanelUpdateSemverKey(vs[j])
		return slices.Compare(a[:], b[:]) < 0
	})
	var got []string
	for _, v := range vs {
		if v == nil {
			got = append(got, "<nil>")
		} else {
			got = append(got, *v)
		}
	}
	if want := []string{"<nil>", "v2.9.0", "2.9.10", "2.10.0", "2.11.7"}; !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestPanelUpdateSemverKeyToleratesJunkWithoutReorderingTheQueue(t *testing.T) {
	cases := map[string][4]uint64{"v2.11.7-rc.3": {1, 2, 11, 7}, "garbage": {1, 0, 0, 0}, "2.11": {1, 2, 11, 0}}
	if PanelUpdateSemverKey(nil) != [4]uint64{} {
		t.Fatal("nil")
	}
	for in, want := range cases {
		if got := PanelUpdateSemverKey(panelUpdateTestPtr(in)); got != want {
			t.Errorf("%s → %v, want %v", in, got, want)
		}
	}
}

// settings' recording coverage compares against this key: the gate release
// itself counts as covered, and a never-checked-in server does NOT.
func TestPanelUpdateRecordingGateBoundarySortsTheWayCoverageDependsOn(t *testing.T) {
	gate := PanelUpdateSemverKey(panelUpdateTestPtr("2.46.0"))
	cmp := func(v *string) int { k := PanelUpdateSemverKey(v); return slices.Compare(k[:], gate[:]) }
	for _, v := range []*string{panelUpdateTestPtr("2.45.1"), panelUpdateTestPtr("2.9.0"), nil, panelUpdateTestPtr("unknown")} {
		if cmp(v) >= 0 {
			t.Errorf("%v must not be covered", v)
		}
	}
	for _, v := range []string{"2.46.0", "2.46.1", "v2.47.0", "2.100.0"} {
		if cmp(&v) < 0 {
			t.Errorf("%s must be covered", v)
		}
	}
}

// "Updated" is decided from what the agent is RUNNING (/health), never from
// what it says about itself (lesson #49, measured s232).
func TestPanelUpdateUpdateOneServerConfirmsFromGroundTruth(t *testing.T) {
	src, err := os.ReadFile("svc_panel_update.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	body = body[strings.Index(body, "func panelUpdateUpdateOneServer"):]
	healthAt := strings.Index(body, `handle.Get(ctx, "/health")`)
	okAt := strings.Index(body, "return nil")
	if healthAt < 0 || okAt < 0 {
		t.Fatal("no health probe or no success path")
	}
	if healthAt > okAt {
		t.Fatal("the only success path must be downstream of the health probe")
	}
	if strings.Contains(body, `"succeeded"`) {
		t.Fatal("a self-reported state string is not evidence an update landed")
	}
}

func TestPanelUpdateIdleStateHandleStartsIdle(t *testing.T) {
	if s := PanelUpdateNewStateHandle().get(); s.Kind != "idle" {
		t.Fatal(s.Kind)
	}
	b, _ := panelUpdateIdle().MarshalJSON()
	if string(b) != `{"state":"idle"}` {
		t.Fatal(string(b))
	}
}
