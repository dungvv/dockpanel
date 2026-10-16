package api

import (
	"testing"
	"time"
)

// chrono's to_rfc3339: "+00:00", fraction only when present, 3/6/9 digits.
func TestExtensionsRFC3339MatchesChrono(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for ns, want := range map[int]string{
		0:         "2026-01-02T03:04:05+00:00",
		120000000: "2026-01-02T03:04:05.120+00:00",
		123456000: "2026-01-02T03:04:05.123456+00:00",
		123456789: "2026-01-02T03:04:05.123456789+00:00",
	} {
		if got := ExtensionsRFC3339(base.Add(time.Duration(ns))); got != want {
			t.Errorf("%d: got %s want %s", ns, got, want)
		}
	}
}
