package api

import (
	"testing"
	"time"
)

// ssl-controls D5: an unknown expiry stays unknown (nil) all the way out of
// the certificate handlers — never a placeholder day count.
func TestPinSslControlsDaysLeftKeepsUnknown(t *testing.T) {
	now := time.Now()
	if got := rtMonitorsDaysLeft(nil, now); got != nil {
		t.Fatalf("nil expiry became %d days", *got)
	}
	exp := now.Add(10*24*time.Hour + time.Hour)
	if got := rtMonitorsDaysLeft(&exp, now); got == nil || *got != 10 {
		t.Fatalf("10-day expiry: %v", got)
	}
	if rtMonitorsExpiryStatus(rtMonitorsDaysLeft(nil, now), false) != "unknown" {
		t.Fatal("nil expiry not classified unknown")
	}
}
