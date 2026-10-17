package api

import "testing"

// Pins the certificate ladder's ORDER (tests/monitors-honest-reads-pin-e2e.sh
// §B): expired outranks a failing renewal (the outage already happened), and
// a failing renewal outranks unknown and every clock rung (they say when the
// cert dies; this says nothing is coming to save it). With the flag false the
// five original rungs are exactly the ladder that shipped before.
func TestPinMonitorsHonestReadsLadder(t *testing.T) {
	d := func(v int64) *int64 { return &v }
	cases := []struct {
		days    *int64
		failing bool
		want    string
	}{
		{d(-1), true, "expired"},
		{d(-1), false, "expired"},
		{nil, true, "renewal_failed"},
		{d(3), true, "renewal_failed"},
		{d(20), true, "renewal_failed"},
		{d(300), true, "renewal_failed"},
		{nil, false, "unknown"},
		{d(0), false, "critical"},
		{d(7), false, "critical"},
		{d(8), false, "warning"},
		{d(30), false, "warning"},
		{d(31), false, "ok"},
	}
	for _, c := range cases {
		if got := rtMonitorsExpiryStatus(c.days, c.failing); got != c.want {
			t.Errorf("days=%v failing=%v: got %q want %q", c.days, c.failing, got, c.want)
		}
	}
}
