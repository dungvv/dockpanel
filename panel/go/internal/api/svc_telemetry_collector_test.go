package api

import (
	"reflect"
	"testing"
	"time"
)

// The decision is tested, not the SQL around it: #98 was a wrong verdict.

func TestTelemetryCollectorAReleaseOlderThanThisPanelClearsTheAdvertisement(t *testing.T) {
	if !telemetryCollectorAdvertisementIsStale("2.49.0", "2.52.0") || TelemetryCollectorIsNewerRelease("2.49.0", "2.52.0") {
		t.Fatal()
	}
}

func TestTelemetryCollectorTheRunningReleaseClearsTheAdvertisement(t *testing.T) {
	if !telemetryCollectorAdvertisementIsStale("2.53.0", "2.53.0") || TelemetryCollectorIsNewerRelease("2.53.0", "2.53.0") {
		t.Fatal()
	}
}

func TestTelemetryCollectorAnUnparseableOrEmptyTagClearsTheAdvertisement(t *testing.T) {
	for _, s := range []string{"", "garbage", "v"} {
		if !telemetryCollectorAdvertisementIsStale(s, "2.53.0") {
			t.Fatalf("%q not stale", s)
		}
	}
}

func TestTelemetryCollectorAGenuinelyNewerReleaseIsStored(t *testing.T) {
	for _, s := range []string{"2.54.0", "v2.54.0", "2.53.1", "3.0.0", "2.100.0"} {
		if !TelemetryCollectorIsNewerRelease(s, "2.53.0") {
			t.Fatalf("%s should be newer than 2.53.0", s)
		}
	}
	if telemetryCollectorAdvertisementIsStale("2.54.0", "2.53.0") {
		t.Fatal()
	}
}

// The old parser read "2.53.0-rc.1" as 2.53.1 — a phantom upgrade offered to
// every panel already on the GA release.
func TestTelemetryCollectorAReleaseCandidateOrdersBelowItsOwnGARelease(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"2.53.0-rc.1", "2.53.0", false},
		{"2.53.0", "2.53.0-rc.1", true},
		{"2.53.0-rc.2", "2.53.0-rc.1", true},
		{"2.53.0-rc.1", "2.53.0-rc.2", false},
		{"2.53.0-beta", "2.53.0", false},
	}
	for _, c := range cases {
		if got := TelemetryCollectorIsNewerRelease(c.a, c.b); got != c.want {
			t.Errorf("IsNewer(%s, %s) = %v", c.a, c.b, got)
		}
	}
	if !telemetryCollectorAdvertisementIsStale("2.53.0-rc.1", "2.53.0") {
		t.Fatal()
	}
}

func TestTelemetryCollectorTheReconcileAndThePollerAgreeOnEveryShape(t *testing.T) {
	for _, c := range [][2]string{{"2.49.0", "2.52.0"}, {"2.53.0", "2.53.0"}, {"2.54.0", "2.53.0"}, {"2.53.0-rc.1", "2.53.0"}, {"junk", "2.53.0"}} {
		if telemetryCollectorAdvertisementIsStale(c[0], c[1]) != !TelemetryCollectorIsNewerRelease(c[0], c[1]) {
			t.Fatalf("%v disagrees", c)
		}
	}
}

func TestTelemetryCollectorStripPII(t *testing.T) {
	in := map[string]any{"Email": "a@b", "nested": []any{map[string]any{"server_url": "x", "n": 1}}, "count": 2}
	want := map[string]any{"Email": "[redacted]", "nested": []any{map[string]any{"server_url": "[redacted]", "n": 1}}, "count": 2}
	if got := TelemetryCollectorStripPII(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

// chrono's to_rfc3339: +00:00 and 0/3/6/9 fractional digits.
func TestTelemetryCollectorRFC3339MatchesChrono(t *testing.T) {
	base := time.Date(2026, 7, 28, 17, 33, 32, 0, time.UTC)
	for ns, want := range map[int]string{
		0:         "2026-07-28T17:33:32+00:00",
		500000000: "2026-07-28T17:33:32.500+00:00",
		123456000: "2026-07-28T17:33:32.123456+00:00",
		1:         "2026-07-28T17:33:32.000000001+00:00",
	} {
		if got := telemetryCollectorRFC3339(base.Add(time.Duration(ns))); got != want {
			t.Errorf("%d → %s, want %s", ns, got, want)
		}
	}
}
