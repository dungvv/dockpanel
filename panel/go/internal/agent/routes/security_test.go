package routes

import (
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

func TestSecurityStatusFor(t *testing.T) {
	for e, want := range map[string]int{
		services.SecurityUfwMissing:                            424,
		"Invalid action 'x': must be 'allow' or 'deny'":        400,
		"Rule number must be >= 1":                             400,
		"Can only remove files under /var/www":                 400,
		"Unknown fix type: x":                                  400,
		"firewall-cmd failed to add the rule":                  500,
		"ufw failed: ERROR: Could not find a profile matching": 500,
	} {
		if got := securityStatusFor(e); got != want {
			t.Errorf("%q: %d want %d", e, got, want)
		}
	}
}

func TestSecurityChronoRfc3339(t *testing.T) {
	base := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	for ns, want := range map[int]string{
		0:         "2026-03-04T05:06:07+00:00",
		120000000: "2026-03-04T05:06:07.120+00:00",
		123456000: "2026-03-04T05:06:07.123456+00:00",
		123456789: "2026-03-04T05:06:07.123456789+00:00",
	} {
		if got := securityChronoRfc3339(base.Add(time.Duration(ns))); got != want {
			t.Errorf("%d: %s", ns, got)
		}
	}
}

func TestSecurityIoReason(t *testing.T) {
	err := fmt.Errorf("open x: %w", syscall.EROFS)
	if got := securityIoReason(err); got != "Read-only file system (os error 30)" {
		t.Fatal(got)
	}
}
