package api

import "testing"

func TestPublicStatusTheLiteralTrueIsTheOnlyThingThatPublishes(t *testing.T) {
	v := "true"
	if !publicStatusMeansEnabled(&v) {
		t.Fatal("true must enable")
	}
}

// The shape a fresh install is in, and the one that used to publish.
func TestPublicStatusAnAbsentSettingIsOff(t *testing.T) {
	if publicStatusMeansEnabled(nil) {
		t.Fatal("absent must be off")
	}
}

// IsEnabled collapses a DB error into nil: a panel that cannot read its own
// settings must not conclude that it should publish.
func TestPublicStatusAQueryThatFailedIsOff(t *testing.T) {
	if publicStatusMeansEnabled(nil) {
		t.Fatal("failed query must be off")
	}
}

// Anything other than the exact literal is a refusal, not an invitation to guess.
func TestPublicStatusNothingTruthyButUnequalPublishes(t *testing.T) {
	for _, v := range []string{"", "false", "TRUE", "True", "1", "yes", "on", " true", "true "} {
		if publicStatusMeansEnabled(&v) {
			t.Errorf("%q must not enable the status page", v)
		}
	}
}
