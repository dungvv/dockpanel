package api

import (
	"testing"
	"time"
)

func TestAutoHealerProfileCooldown(t *testing.T) {
	cases := []struct {
		profile *string
		want    time.Duration
	}{
		{new("shortlived"), time.Hour},
		{new("tlsserver"), 6 * time.Hour},
		{new("classic"), 6 * time.Hour},
		{nil, 6 * time.Hour},
	}
	for _, c := range cases {
		if got := autoHealerProfileCooldown(c.profile); got != c.want {
			t.Errorf("%v: got %v want %v", c.profile, got, c.want)
		}
	}
}
