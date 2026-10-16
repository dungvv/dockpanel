package api

import (
	"testing"
	"time"
)

// No Rust tests exist for this module; this pins the cron matcher.
func TestDeploySchedulerShouldRun(t *testing.T) {
	// 2026-10-19 is a Monday (%u = 1).
	now := time.Date(2026, 10, 19, 3, 30, 0, 0, time.UTC)
	cases := map[string]bool{
		"30 3 * * *":     true,
		"30 3 * * 1":     true,
		"30 3 * * 7":     false,
		"*/15 * * * *":   true,
		"*/0 * * * *":    false,
		"0,30 1-5 * * *": true,
		"+30 3 * * *":    true,
		"31 3 * * *":     false,
		"30 3 * *":       false,
		"30 3 19 10 1-5": true,
	}
	for expr, want := range cases {
		if got := deploySchedulerShouldRun(expr, now); got != want {
			t.Errorf("%q: got %v want %v", expr, got, want)
		}
	}
	sunday := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	if !deploySchedulerShouldRun("0 0 * * 7", sunday) {
		t.Error("Sunday must be 7")
	}
}
