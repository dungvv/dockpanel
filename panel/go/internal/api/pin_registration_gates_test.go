package api

import (
	"slices"
	"testing"
)

// A registration gate with a toggle must also be saveable through PUT /api/settings,
// or the toggle 400s "Unknown setting" (tests/registration-gates-pin-e2e.sh §3).
func TestPinRegistrationGatesAllowlist(t *testing.T) {
	for _, k := range []string{"self_registration_enabled", "oauth_auto_create"} {
		if !slices.Contains(rtSettingsAllowedKeys, k) {
			t.Errorf("%s is not in rtSettingsAllowedKeys — its toggle would fail with 'Unknown setting'", k)
		}
	}
}
