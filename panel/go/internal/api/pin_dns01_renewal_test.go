package api

import (
	"testing"
	"time"
)

// Retired from tests/dns01-renewal-pin-e2e.sh D2b. The DNS-01 last-resort rung
// is only reachable if it sits STRICTLY BELOW the profile's renewal margin:
// renewal does not begin until the margin, so a rung at or above it means
// Refuse is never returned for that profile. It failed for `shortlived` from
// the day the profile shipped (~160h certificates, a rung of seven days).
// Compared as two tables, so a deliberate re-tuning of either survives and the
// moment they cross goes red.
func TestPinDns01RenewalRungSitsBelowEveryProfileMargin(t *testing.T) {
	for _, p := range []*string{sp("shortlived"), sp("tlsserver"), sp("classic"), nil} {
		rung := time.Duration(dns01LastResortDays(p)) * 24 * time.Hour
		if margin := autoHealerFallbackRenewalMargin(p); rung >= margin {
			name := "<default>"
			if p != nil {
				name = *p
			}
			t.Errorf("%s: last-resort rung %v is not below the renewal margin %v — Refuse is unreachable", name, rung, margin)
		}
	}
}
