package api

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// upgrade-reach §D: the janitor must retain webhook attempts for the HOUR
// both webhook handlers roll (it once evicted on the 2FA 5-minute window, so a
// caller got a fresh allowance every ~15 minutes), cap that retention, and
// leave the 2FA limiter on its own 5-minute window.
func TestPinUpgradeReachWebhookJanitorWindow(t *testing.T) {
	st := testState()
	now := time.Now()
	recent, stale := uuid.New(), uuid.New()
	st.WebhookAttempts[recent] = RateWindow{Count: 3, Start: now.Add(-30 * time.Minute)}
	st.WebhookAttempts[stale] = RateWindow{Count: 3, Start: now.Add(-61 * time.Minute)}
	twofaOld, twofaNew := uuid.New(), uuid.New()
	st.TwofaAttempts[twofaOld] = RateWindow{Count: 3, Start: now.Add(-6 * time.Minute)}
	st.TwofaAttempts[twofaNew] = RateWindow{Count: 3, Start: now.Add(-4 * time.Minute)}

	st.cleanupOnce(context.Background(), now)

	if _, ok := st.WebhookAttempts[recent]; !ok {
		t.Fatal("a 30-minute-old webhook window was evicted — the 10/hour limit resets early")
	}
	if _, ok := st.WebhookAttempts[stale]; ok {
		t.Fatal("a webhook window older than an hour was kept")
	}
	if _, ok := st.TwofaAttempts[twofaOld]; ok {
		t.Fatal("the 2FA limiter must stay on its 5-minute window (6-minute entry kept)")
	}
	if _, ok := st.TwofaAttempts[twofaNew]; !ok {
		t.Fatal("a 4-minute-old 2FA window was evicted")
	}
}

func TestPinUpgradeReachWebhookJanitorCap(t *testing.T) {
	st := testState()
	now := time.Now()
	for range 10_001 {
		st.WebhookAttempts[uuid.New()] = RateWindow{Count: 0, Start: now.Add(-time.Minute)}
	}
	limited := uuid.New()
	st.WebhookAttempts[limited] = RateWindow{Count: WebhookAttemptLimit, Start: now.Add(-time.Minute)}

	st.cleanupOnce(context.Background(), now)

	if len(st.WebhookAttempts) != 1 {
		t.Fatalf("a flood of invented ids must be shed above the cap; %d entries remain", len(st.WebhookAttempts))
	}
	if _, ok := st.WebhookAttempts[limited]; !ok {
		t.Fatal("the cap shed a counter at its limit")
	}
}
