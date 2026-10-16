package api

import (
	"reflect"
	"testing"
)

func driftJ(t *testing.T, s string) any {
	t.Helper()
	v, err := driftDecode([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDriftIdenticalConfigsHaveNoDiff(t *testing.T) {
	a := driftJ(t, `{"cpu_threshold": 90, "alert_cpu": true}`)
	b := driftJ(t, `{"cpu_threshold": 90, "alert_cpu": true}`)
	if d := DriftCompareConfig(a, b, driftNoSensitive); len(d) != 0 {
		t.Fatal(d)
	}
}

func TestDriftSingleFieldDifferenceIsReported(t *testing.T) {
	a := driftJ(t, `{"cpu_threshold": 90, "alert_cpu": true}`)
	b := driftJ(t, `{"cpu_threshold": 80, "alert_cpu": true}`)
	d := DriftCompareConfig(a, b, driftNoSensitive)
	if len(d) != 1 || d[0].Field != "cpu_threshold" || d[0].Sensitive ||
		!reflect.DeepEqual(d[0].Reference, driftJ(t, "90")) || !reflect.DeepEqual(d[0].Current, driftJ(t, "80")) {
		t.Fatal(d)
	}
}

func TestDriftSensitiveFieldDifferingValuesAreNotDrift(t *testing.T) {
	// Two different webhook URLs are both "set" — rotating a secret must not
	// read as drift, and the value must never surface.
	a := driftJ(t, `{"notify_slack_url": "https://hooks.slack.com/AAA"}`)
	b := driftJ(t, `{"notify_slack_url": "https://hooks.slack.com/BBB"}`)
	if d := DriftCompareConfig(a, b, driftAlertSensitive); len(d) != 0 {
		t.Fatal(d)
	}
}

func TestDriftSensitiveFieldSetVsUnsetIsDriftWithoutValue(t *testing.T) {
	a := driftJ(t, `{"notify_slack_url": "https://hooks.slack.com/AAA"}`)
	b := driftJ(t, `{"notify_slack_url": null}`)
	d := DriftCompareConfig(a, b, driftAlertSensitive)
	if len(d) != 1 || !d[0].Sensitive || d[0].Reference != "set" || d[0].Current != "unset" {
		t.Fatal(d)
	}
}

func TestDriftKeyPresentOnOneSideOnlyDiffsAgainstNull(t *testing.T) {
	d := DriftCompareConfig(driftJ(t, `{"waf_mode": "block"}`), driftJ(t, `{}`), driftNoSensitive)
	if len(d) != 1 || d[0].Field != "waf_mode" || d[0].Current != nil {
		t.Fatal(d)
	}
}

func TestDriftEmptyStringSecretCountsAsUnset(t *testing.T) {
	a := driftJ(t, `{"notify_discord_url": ""}`)
	b := driftJ(t, `{"notify_discord_url": null}`)
	if d := DriftCompareConfig(a, b, driftAlertSensitive); len(d) != 0 {
		t.Fatal(d)
	}
}

func TestDriftSingletonBothMissingIsInSync(t *testing.T) {
	r := DriftDiffSingleton(nil, nil, driftNoSensitive)
	if !r.InSync || r.FieldDiffs != nil {
		t.Fatal(r)
	}
}

func TestDriftSingletonReferenceOnlyIsDrift(t *testing.T) {
	r := DriftDiffSingleton(driftJ(t, `{"cpu_threshold": 90}`), nil, driftNoSensitive)
	if r.InSync || r.Note == nil || r.FieldDiffs != nil {
		t.Fatal(r)
	}
}

func TestDriftSingletonEqualRowsInSyncWithNoFieldDiffs(t *testing.T) {
	r := DriftDiffSingleton(driftJ(t, `{"cpu_threshold": 90}`), driftJ(t, `{"cpu_threshold": 90}`), driftNoSensitive)
	if !r.InSync || r.FieldDiffs != nil {
		t.Fatal(r)
	}
}

func TestDriftCollectionIdenticalSetsAreInSync(t *testing.T) {
	cfg := driftJ(t, `{"enabled": true}`)
	r := DriftDiffCollection([]DriftRow{{"a.com", cfg}}, []DriftRow{{"a.com", cfg}}, driftNoSensitive)
	if !r.InSync || len(r.OnlyHere) != 0 || len(r.OnlyReference) != 0 || len(r.ValueDiffs) != 0 {
		t.Fatal(r)
	}
}

func TestDriftCollectionPresenceAsymmetryIsBucketed(t *testing.T) {
	cfg := driftJ(t, `{"enabled": true}`)
	ref := []DriftRow{{"shared.com", cfg}, {"refonly.com", cfg}}
	cur := []DriftRow{{"shared.com", cfg}, {"hereonly.com", cfg}}
	r := DriftDiffCollection(ref, cur, driftNoSensitive)
	if !reflect.DeepEqual(r.OnlyHere, []string{"hereonly.com"}) ||
		!reflect.DeepEqual(r.OnlyReference, []string{"refonly.com"}) || len(r.ValueDiffs) != 0 || r.InSync {
		t.Fatal(r)
	}
}

func TestDriftCollectionSharedIdentityValueDiff(t *testing.T) {
	ref := []DriftRow{{"a.com", driftJ(t, `{"schedule": "0 3 * * *"}`)}}
	cur := []DriftRow{{"a.com", driftJ(t, `{"schedule": "0 5 * * *"}`)}}
	r := DriftDiffCollection(ref, cur, driftNoSensitive)
	if len(r.OnlyHere) != 0 || len(r.OnlyReference) != 0 || len(r.ValueDiffs) != 1 ||
		r.ValueDiffs[0].Identity != "a.com" || r.ValueDiffs[0].Fields[0].Field != "schedule" || r.InSync {
		t.Fatal(r)
	}
}

func TestDriftBackupCoverageInSyncRules(t *testing.T) {
	cases := []struct {
		m    DriftCoverageMetrics
		want bool
	}{
		{DriftCoverageMetrics{0, 0, 0, 0}, true},  // no sites → nothing to protect
		{DriftCoverageMetrics{5, 5, 0, 1}, true},  // all protected with a destination
		{DriftCoverageMetrics{5, 3, 2, 1}, false}, // an unprotected site
		{DriftCoverageMetrics{5, 5, 0, 0}, false}, // fully "backed up" but no destination
	}
	for _, c := range cases {
		if DriftCoverageInSync(c.m) != c.want {
			t.Errorf("%+v", c.m)
		}
	}
}
