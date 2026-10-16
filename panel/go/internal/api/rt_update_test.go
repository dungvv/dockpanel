package api

import (
	"strings"
	"testing"
)

func TestRtUpdateChannelInputDefaultTrueHelper(t *testing.T) {
	if !rtUpdateDefaultTrue() {
		t.Fatal()
	}
}

func TestRtUpdateChannelValidateThroughRouteInput(t *testing.T) {
	if UpdateChannelValidate("nightly") == nil || UpdateChannelValidate("STABLE") == nil {
		t.Fatal("garbage channel accepted")
	}
	if UpdateChannelValidate("stable") != nil {
		t.Fatal("stable refused")
	}
}

func TestRtUpdateFleetInputSerdeDefaults(t *testing.T) {
	var in rtUpdateFleetApplyInput
	if err := decodeJSONBytes([]byte(`{"target_version":"v2.10.0"}`), &in); err != nil {
		t.Fatal(err)
	}
	if !in.halt() || in.IncludePanel {
		t.Fatalf("halt=%v include=%v", in.halt(), in.IncludePanel)
	}
}

func TestRtUpdateFleetInputSerdeOverrides(t *testing.T) {
	var in rtUpdateFleetApplyInput
	if err := decodeJSONBytes([]byte(`{"target_version":"v2.10.0","halt_on_failure":false,"include_panel":true}`), &in); err != nil {
		t.Fatal(err)
	}
	if in.halt() || !in.IncludePanel {
		t.Fatalf("halt=%v include=%v", in.halt(), in.IncludePanel)
	}
}

// #98's state: the panel runs 2.52.0, the row still advertises 2.49.0, and
// matching the row was the only guard — so the apply reinstalled a panel three
// releases behind.
func TestRtUpdateApplyRefusesATargetNoNewerThanTheRunningPanel(t *testing.T) {
	reason := rtUpdateRejectApplyTarget("2.49.0", "2.49.0", "2.52.0")
	if reason == "" {
		t.Fatal("a lower target must be refused")
	}
	if !strings.Contains(reason, "2.49.0") || !strings.Contains(reason, "2.52.0") || !strings.Contains(reason, "rollback") {
		t.Fatalf("refusal must name both versions and the way back: %s", reason)
	}
	if rtUpdateRejectApplyTarget("2.52.0", "2.52.0", "2.52.0") == "" {
		t.Fatal("reinstalling the running version is not an update")
	}
	if rtUpdateRejectApplyTarget("2.52.0-rc.1", "2.52.0-rc.1", "2.52.0") == "" {
		t.Fatal("an rc of the installed release is not an update")
	}
}

func TestRtUpdateApplyAcceptsTheAdvertisedUpgradeAndNothingElse(t *testing.T) {
	if r := rtUpdateRejectApplyTarget("2.53.0", "2.53.0", "2.52.0"); r != "" {
		t.Fatal(r)
	}
	for _, c := range [][3]string{{"2.99.0", "2.53.0", "2.52.0"}, {"2.53.0", "", "2.52.0"}} {
		if rtUpdateRejectApplyTarget(c[0], c[1], c[2]) == "" {
			t.Fatalf("%v accepted", c)
		}
	}
}

// The flattened status keeps the state's own fields at the top level and
// omits absent verdicts (skip_serializing_if).
func TestRtUpdateStatusResponseFlattens(t *testing.T) {
	b, err := rtUpdateStatusResponse{State: panelUpdateIdle(), CurrentVersion: "1.2.3", Channel: "stable"}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"state":"idle","current_version":"1.2.3","available_version":null,"channel":"stable"}`
	if string(b) != want {
		t.Fatalf("%s\nwant %s", b, want)
	}
}
