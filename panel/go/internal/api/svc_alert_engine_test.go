package api

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func alertEngineTEscAct(k alertEngineEscalationKind, i int) alertEngineEscalationAction {
	return alertEngineEscalationAction{Kind: k, Index: i}
}

var (
	alertEngineTEscSkip       = alertEngineTEscAct(alertEngineEscSkip, 0)
	alertEngineTEscTerminal   = alertEngineTEscAct(alertEngineEscTerminal, 0)
	alertEngineTEscRepeatLast = alertEngineTEscAct(alertEngineEscRepeatLast, 0)
)

func alertEngineTEscAdvance(i int) alertEngineEscalationAction {
	return alertEngineTEscAct(alertEngineEscAdvance, i)
}

func alertEngineTI64p(v int64) *int64 { return &v }

// THE REGRESSION. The policy editor seeds a chain with one step, and a
// one-step chain is exhausted from the first sweep. This used to be terminal
// for ever: the operator got the page that fired the alert and then silence.
func TestAlertEngineASpentChainKeepsPagingInsteadOfFallingSilent(t *testing.T) {
	if got := alertEngineEscalationDecision([]int64{0}, 0, 60, nil); got != alertEngineTEscRepeatLast {
		t.Fatal(got)
	}
	if got := alertEngineEscalationDecision([]int64{0}, 0, 600, alertEngineTI64p(31)); got != alertEngineTEscRepeatLast {
		t.Fatal(got)
	}
	if got := alertEngineEscalationDecision([]int64{0}, 0, 10_000, alertEngineTI64p(45)); got != alertEngineTEscRepeatLast {
		t.Fatal(got)
	}
}

// The fallback is the SAME cadence an unattached rule gets: nothing before
// 15 minutes, then every 30.
func TestAlertEngineTheFallbackMatchesTheUnattachedCadence(t *testing.T) {
	cases := []struct {
		elapsed int64
		since   *int64
		want    alertEngineEscalationAction
		msg     string
	}{
		{14, nil, alertEngineTEscSkip, "too young to page"},
		{15, nil, alertEngineTEscRepeatLast, "eligible at 15"},
		{60, alertEngineTI64p(29), alertEngineTEscSkip, "inside the 30-min window"},
		{60, alertEngineTI64p(30), alertEngineTEscRepeatLast, "the window has lapsed"},
	}
	for _, c := range cases {
		if got := alertEngineEscalationDecision([]int64{0}, 0, c.elapsed, c.since); got != c.want {
			t.Errorf("%s: got %v", c.msg, got)
		}
	}
}

// A row that is merely waiting must NOT be stamped.
func TestAlertEngineWaitingIsNotTheSameAsTerminal(t *testing.T) {
	got := alertEngineEscalationDecision([]int64{0}, 0, 60, alertEngineTI64p(5))
	if got == alertEngineTEscTerminal || got != alertEngineTEscSkip {
		t.Fatal(got)
	}
}

// The chain jumps to the furthest eligible rung rather than creeping.
func TestAlertEngineTheChainAdvancesToTheFurthestEligibleRung(t *testing.T) {
	chain := []int64{0, 15, 60}
	if got := alertEngineEscalationDecision(chain, 0, 16, nil); got != alertEngineTEscAdvance(1) {
		t.Fatal(got)
	}
	if got := alertEngineEscalationDecision(chain, 0, 90, nil); got != alertEngineTEscAdvance(2) {
		t.Fatal("jumps past rung 1", got)
	}
	if got := alertEngineEscalationDecision(chain, 1, 90, nil); got != alertEngineTEscAdvance(2) {
		t.Fatal(got)
	}
	if got := alertEngineEscalationDecision(chain, 2, 90, nil); got != alertEngineTEscRepeatLast {
		t.Fatal(got)
	}
}

// A rung already paged is never paged again by the chain.
func TestAlertEngineTheChainNeverWalksBackwards(t *testing.T) {
	chain := []int64{0, 15, 60}
	for _, elapsed := range []int64{16, 61, 600} {
		if got := alertEngineEscalationDecision(chain, 2, elapsed, nil); got.Kind == alertEngineEscAdvance {
			t.Fatalf("advanced to %d from a spent chain at %dm", got.Index, elapsed)
		}
	}
	if got := alertEngineEscalationDecision(chain, 1, 20, alertEngineTI64p(1)); got != alertEngineTEscSkip {
		t.Fatal("rung 2 not yet due and rung 1 already paged", got)
	}
}

func TestAlertEngineAnEmptyChainIsTerminal(t *testing.T) {
	if got := alertEngineEscalationDecision(nil, 0, 600, nil); got != alertEngineTEscTerminal {
		t.Fatal(got)
	}
}

func TestAlertEngineSslWarningDaysSortsDescendingAndDedupes(t *testing.T) {
	if got := alertEngineParseSslWarningDays("7, 30,14,7"); !slices.Equal(got, []int64{30, 14, 7}) {
		t.Fatal(got)
	}
}

func TestAlertEngineSslWarningDaysFallsBackWhenUnusable(t *testing.T) {
	// An empty, garbage, or all-negative column must not silence SSL alerting.
	for _, raw := range []string{"", "soon, later", "-5,-1"} {
		if got := alertEngineParseSslWarningDays(raw); !slices.Equal(got, []int64{30, 14, 7, 3, 1}) {
			t.Fatalf("%q → %v", raw, got)
		}
	}
}

func TestAlertEngineSslLadderPicksTheTightestRungCrossed(t *testing.T) {
	rungs := alertEngineParseSslWarningDays("30,14,7,3,1")
	tightest := func(daysLeft int64) (int64, bool) {
		var best int64
		found := false
		for _, d := range rungs {
			if daysLeft <= d && (!found || d < best) {
				best, found = d, true
			}
		}
		return best, found
	}
	for _, c := range []struct{ days, want int64 }{{29, 30}, {14, 14}, {10, 14}, {1, 1}} {
		if got, ok := tightest(c.days); !ok || got != c.want {
			t.Fatalf("%d → %d", c.days, got)
		}
	}
	if _, ok := tightest(31); ok {
		t.Fatal("31 crossed a rung")
	}
	// And sslDecision agrees on a fresh certificate.
	if a := alertEngineSslDecision(10, false, alertEngineSslNeverWarned, rungs); a.Kind != alertEngineSslFire || a.WarnDay != 14 {
		t.Fatal(a)
	}
}

type alertEngineTSslStep struct {
	days    int64
	expired bool
}

// alertEngineTWalk drives a certificate's whole life through sslDecision, threading
// last_warned_day exactly as the DB does.
func alertEngineTWalk(steps []alertEngineTSslStep, rungs []int64) []alertEngineSslAction {
	last := alertEngineSslNeverWarned
	out := []alertEngineSslAction{}
	for _, s := range steps {
		a := alertEngineSslDecision(s.days, s.expired, last, rungs)
		switch a.Kind {
		case alertEngineSslFire:
			last = a.WarnDay
		case alertEngineSslResolve:
			last = alertEngineSslNeverWarned
		}
		out = append(out, a)
	}
	return out
}

var alertEngineTSslNothing = alertEngineSslAction{Kind: alertEngineSslNothing}
var alertEngineTSslResolve = alertEngineSslAction{Kind: alertEngineSslResolve}

func alertEngineTIsFire(a alertEngineSslAction, warnDay int64) bool {
	return a.Kind == alertEngineSslFire && a.WarnDay == warnDay
}

func TestAlertEngineSslLadderPagesOncePerRungThenOnceOnExpiry(t *testing.T) {
	rungs := alertEngineParseSslWarningDays("30,14,7,3,1")
	life := []alertEngineTSslStep{{40, false}, {25, false}, {25, false}, {10, false}, {5, false}, {2, false}, {0, false}, {-1, true}, {-2, true}, {-3, true}}
	seen := alertEngineTWalk(life, rungs)

	fires := []int64{}
	for _, a := range seen {
		if a.Kind == alertEngineSslFire {
			fires = append(fires, a.WarnDay)
		}
	}
	// One page per rung crossed, then exactly ONE expired page.
	if !slices.Equal(fires, []int64{30, 14, 7, 3, 1, alertEngineSslExpiredWarnDay}) {
		t.Fatal(fires)
	}
	if seen[0] != alertEngineTSslNothing {
		t.Fatal("40 days is outside every rung")
	}
	if seen[2] != alertEngineTSslNothing {
		t.Fatal("same rung must not re-page")
	}
	if seen[8] != alertEngineTSslNothing || seen[9] != alertEngineTSslNothing {
		t.Fatal("expired must page once, not per tick")
	}
}

func TestAlertEngineSslExpiredCertPagesOnceAndNeverClaimsRenewal(t *testing.T) {
	rungs := alertEngineParseSslWarningDays("30,14,7,3,1")
	life := []alertEngineTSslStep{{1, false}}
	for i := 0; i < 6; i++ {
		life = append(life, alertEngineTSslStep{0, true}) // <24h since lapse
	}
	for i := 0; i < 3; i++ {
		life = append(life, alertEngineTSslStep{-1, true}) // >24h since lapse
	}
	seen := alertEngineTWalk(life, rungs)

	if !alertEngineTIsFire(seen[0], 1) {
		t.Fatal(seen[0])
	}
	if !alertEngineTIsFire(seen[1], -1) {
		t.Fatal("expired must page", seen[1])
	}
	for i, a := range seen[2:] {
		if a != alertEngineTSslNothing {
			t.Fatalf("tick %d must stay silent while expired: %v", i+2, a)
		}
	}
}

func TestAlertEngineSslExpiryUsesTheExpiredFlagNotTruncatedDays(t *testing.T) {
	rungs := alertEngineParseSslWarningDays("30,14,7,3,1")
	want := alertEngineSslAction{Kind: alertEngineSslFire, WarnDay: alertEngineSslExpiredWarnDay, Severity: "critical"}
	if got := alertEngineSslDecision(0, true, 1, rungs); got != want {
		t.Fatal("a cert that lapsed under 24h ago still reports days_left = 0 and must page", got)
	}
	// Still valid with under a day left, rung 1 already paged: stay quiet.
	if got := alertEngineSslDecision(0, false, 1, rungs); got != alertEngineTSslNothing {
		t.Fatal(got)
	}
}

func TestAlertEngineSslShortLivedCertDoesNotRatchetItselfSilent(t *testing.T) {
	rungs := alertEngineParseSslWarningDays("30,14,7,3,1")
	seen := alertEngineTWalk([]alertEngineTSslStep{{6, false}, {3, false}, {2, false}, {6, false}, {6, false}, {3, false}}, rungs)
	if !alertEngineTIsFire(seen[0], 7) || !alertEngineTIsFire(seen[1], 3) || seen[2] != alertEngineTSslNothing {
		t.Fatal(seen)
	}
	if seen[3] != alertEngineTSslResolve {
		t.Fatal("renewal inside the window is still a renewal", seen[3])
	}
	if !alertEngineTIsFire(seen[4], 7) || !alertEngineTIsFire(seen[5], 3) {
		t.Fatal("ladder must restart", seen)
	}
}

func TestAlertEngineSslRecoversFromAnExpiredStateOnRenewal(t *testing.T) {
	rungs := alertEngineParseSslWarningDays("30,14,7,3,1")
	seen := alertEngineTWalk([]alertEngineTSslStep{{-1, true}, {-2, true}, {89, false}, {89, false}}, rungs)
	if !alertEngineTIsFire(seen[0], -1) || seen[1] != alertEngineTSslNothing {
		t.Fatal(seen)
	}
	if seen[2] != alertEngineTSslResolve {
		t.Fatal("renewal after expiry must resolve")
	}
	if seen[3] != alertEngineTSslNothing {
		t.Fatal("and must not resolve twice")
	}
}

func TestAlertEngineSslSeverityEscalatesWithUrgency(t *testing.T) {
	rungs := alertEngineParseSslWarningDays("30,14,7,3,1")
	sev := func(d, last int64) string {
		a := alertEngineSslDecision(d, false, last, rungs)
		if a.Kind != alertEngineSslFire {
			t.Fatalf("expected a fire, got %v", a)
		}
		return a.Severity
	}
	if sev(25, alertEngineSslNeverWarned) != "info" || sev(6, 14) != "warning" || sev(2, 7) != "critical" {
		t.Fatal("severity ladder")
	}
}

func TestAlertEngineExpiredSentinelIsTighterThanEveryConfigurableRung(t *testing.T) {
	for _, d := range alertEngineParseSslWarningDays("30,14,7,3,1,0") {
		if !(alertEngineSslExpiredWarnDay < d) {
			t.Fatalf("rung %d must stay above the expired sentinel", d)
		}
	}
	if !(alertEngineSslExpiredWarnDay < alertEngineSslNeverWarned) {
		t.Fatal()
	}
}

func TestAlertEngineSslAlertCopyUnchangedByTheSharedHelperRefactor(t *testing.T) {
	title, message := alertEngineSslAlertCopy("example.com", 3, false)
	if title != "SSL certificate expires in 3 days for example.com" ||
		message != "The SSL certificate for example.com will expire in 3 days. Please renew it before it expires." {
		t.Fatal(title, message)
	}
	title, message = alertEngineSslAlertCopy("example.com", 1, false)
	if title != "SSL certificate expires in 1 day for example.com" || !strings.Contains(message, "will expire in 1 day.") {
		t.Fatal(title, message)
	}
	title, message = alertEngineSslAlertCopy("example.com", 0, true)
	if title != "SSL certificate EXPIRED for example.com" || !strings.Contains(message, "has expired") {
		t.Fatal(title, message)
	}
}

func alertEngineTTs(minutesAgo int64) time.Time {
	return time.Now().UTC().Add(-time.Duration(minutesAgo) * time.Minute)
}

func alertEngineTDiskTrend(newest float32, newestAgo int64, oldest float32, oldestAgo int64) []Tup2[float32, time.Time] {
	out := []Tup2[float32, time.Time]{}
	for i := 0; i < 9; i++ {
		out = append(out, Tup2[float32, time.Time]{newest, alertEngineTTs(newestAgo)})
	}
	return append(out, Tup2[float32, time.Time]{oldest, alertEngineTTs(oldestAgo)})
}

func TestAlertEngineDiskForecastNeedsALongEnoughWindowAndARealRunway(t *testing.T) {
	// 8h of trend, 70% -> 78%: 1%/h with 22% left = ~22h to full.
	hours, rate, pct, ok := alertEngineDiskFullForecast(alertEngineTDiskTrend(78, 0, 70, 480))
	if !ok {
		t.Fatal("should forecast")
	}
	if !(hours > 20 && hours < 24) || !(rate > 0.9 && rate < 1.1) || pct != 78 {
		t.Fatal(hours, rate, pct)
	}
	// Same slope inside a 30-minute window → nothing. The query-side window
	// gap is pinned elsewhere; this arm only covers the pure function.
	if _, _, _, ok := alertEngineDiskFullForecast(alertEngineTDiskTrend(78, 0, 70, 30)); ok {
		t.Fatal("short window forecast")
	}
	// Long window, but nowhere near full — nothing to forecast.
	if _, _, _, ok := alertEngineDiskFullForecast(alertEngineTDiskTrend(12, 0, 4, 480)); ok {
		t.Fatal("low disk forecast")
	}
}

func TestAlertEngineDiskForecastIgnoresFlatAndFallingDisks(t *testing.T) {
	if _, _, _, ok := alertEngineDiskFullForecast(alertEngineTDiskTrend(70, 0, 70, 480)); ok {
		t.Fatal("flat")
	}
	if _, _, _, ok := alertEngineDiskFullForecast(alertEngineTDiskTrend(70, 0, 90, 480)); ok {
		t.Fatal("falling")
	}
}

func TestAlertEngineDiskForecastNeedsTenSamples(t *testing.T) {
	two := []Tup2[float32, time.Time]{{78, alertEngineTTs(0)}, {70, alertEngineTTs(480)}}
	if _, _, _, ok := alertEngineDiskFullForecast(two); ok {
		t.Fatal()
	}
}

func TestAlertEngineMemoryLeakNeedsASustainedClimbAboveSixtyPercent(t *testing.T) {
	rep := func(v float32, n int) []float32 {
		out := make([]float32, n)
		for i := range out {
			out[i] = v
		}
		return out
	}
	// newest-first: samples 0..10 are "recent", 20..30 are "older".
	increase, older, recent, ok := alertEngineMemoryLeakTrend(append(rep(85, 20), rep(60, 10)...))
	if !ok || recent != 85 || older != 60 || increase != 25 {
		t.Fatal(increase, older, recent, ok)
	}
	// Same 25-point climb, but low absolute usage — not a leak worth paging.
	if _, _, _, ok := alertEngineMemoryLeakTrend(append(rep(35, 20), rep(10, 10)...)); ok {
		t.Fatal("low")
	}
	// High but steady.
	if _, _, _, ok := alertEngineMemoryLeakTrend(rep(85, 30)); ok {
		t.Fatal("steady")
	}
	// Not enough history yet.
	if _, _, _, ok := alertEngineMemoryLeakTrend(rep(85, 29)); ok {
		t.Fatal("short")
	}
}
