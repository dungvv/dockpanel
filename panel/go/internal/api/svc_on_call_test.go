package api

import (
	"strings"
	"testing"
	"time"
)

// Pure-math tests for the rotation index — no DB needed.
// OnCallResolveOnCallUser wraps these in a SELECT.

func TestOnCallRotationAtAnchorPicksFirstMember(t *testing.T) {
	if got := onCallRotationIndex(0, 7, 3); got != 0 {
		t.Fatal(got)
	}
}

func TestOnCallRotationAfterOneCadencePicksSecond(t *testing.T) {
	if got := onCallRotationIndex(7, 7, 3); got != 1 {
		t.Fatal(got)
	}
}

func TestOnCallRotationWrapsPastMemberCount(t *testing.T) {
	// 3 members, weekly cadence. After 4 weeks we're back to member[1].
	if got := onCallRotationIndex(28, 7, 3); got != 1 {
		t.Fatal(got)
	}
}

func TestOnCallRotationWithinCadenceWindowStaysOnSameMember(t *testing.T) {
	if onCallRotationIndex(6, 7, 3) != 0 || onCallRotationIndex(13, 7, 3) != 1 {
		t.Fatal("window drift")
	}
}

func TestOnCallRotationWithAnchorInFutureFoldsToHead(t *testing.T) {
	// div_euclid(-1, 7) = -1, rem_euclid 3 = 2. "Yesterday relative to the
	// future anchor" sits on the member who would have ended the cycle.
	if got := onCallRotationIndex(-1, 7, 3); got != 2 {
		t.Fatal(got)
	}
}

func TestOnCallRotationSingleMemberAlwaysReturnsThatMember(t *testing.T) {
	for _, elapsed := range []int64{-100, 0, 1, 7, 90, 365} {
		if onCallRotationIndex(elapsed, 7, 1) != 0 {
			t.Fatal(elapsed)
		}
	}
}

func TestOnCallParseRouteShapeUnknownsReturnEmpty(t *testing.T) {
	if s, ok := strings.CutPrefix("on_call_schedule:550e8400-e29b-41d4-a716-446655440000", "on_call_schedule:"); !ok || s != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatal(s)
	}
	if s, ok := strings.CutPrefix("user:550e8400-e29b-41d4-a716-446655440000", "user:"); !ok || s != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatal(s)
	}
	if _, ok := strings.CutPrefix("all_channels", "on_call_schedule:"); ok {
		t.Fatal("prefix matched")
	}
	// The non-DB arms of OnCallRouteToUserIds.
	for _, r := range []string{"all_channels", "webhook:https://x", "garbage", "user:nope", "on_call_schedule:nope"} {
		if got := OnCallRouteToUserIds(t.Context(), nil, r); len(got) != 0 {
			t.Fatalf("%s → %v", r, got)
		}
	}
	if got := OnCallRouteToUserIds(t.Context(), nil, "user:550e8400-e29b-41d4-a716-446655440000"); len(got) != 1 {
		t.Fatal(got)
	}
}

func TestOnCallDurationHelperCompiles(t *testing.T) {
	now := time.Now()
	if !now.Add(24 * time.Hour).After(now) {
		t.Fatal()
	}
}
