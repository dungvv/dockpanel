package api

// Ported from services/prerequisites/mod.rs `tests`.

import (
	"encoding/json"
	"testing"
)

func prereqFixture(key string, s PrerequisitesPrereqState, sev PrerequisitesPrereqSeverity) PrerequisitesPrereqResult {
	return PrerequisitesPrereqResult{Key: key, State: s, Severity: sev, Observed: []string{}}
}

func prereqWarning(k string) PrerequisitesPrereqResult {
	return prereqFixture(k, PrerequisitesPrereqStateUnsatisfied, PrerequisitesPrereqSeverityWarning)
}
func prereqBlocking(k string) PrerequisitesPrereqResult {
	return prereqFixture(k, PrerequisitesPrereqStateUnsatisfied, PrerequisitesPrereqSeverityBlocking)
}
func prereqUnknown(k string) PrerequisitesPrereqResult {
	return prereqFixture(k, PrerequisitesPrereqStateUnknown, PrerequisitesPrereqSeverityInfo)
}

// A Warning must never gate a control — only Blocking does. The orange-cloud
// case: it looks unsatisfied but demonstrably works.
func TestPrerequisitesOnlyBlockingUnsatisfiedResultsGateAControl(t *testing.T) {
	if prereqWarning("t").Blocks() {
		t.Fatal("a warning must let the user proceed")
	}
	if !prereqBlocking("t").Blocks() {
		t.Fatal()
	}
	if prereqFixture("t", PrerequisitesPrereqStateSatisfied, PrerequisitesPrereqSeverityInfo).Blocks() {
		t.Fatal()
	}
	if prereqUnknown("t").Blocks() {
		t.Fatal("an undeterminable check must never block")
	}
}

func TestPrerequisitesFirstBlockerIgnoresWarningsAndUnknowns(t *testing.T) {
	set := []PrerequisitesPrereqResult{prereqWarning("a"), prereqUnknown("b"), prereqBlocking("c"), prereqBlocking("d")}
	if b := PrerequisitesFirstBlocker(set); b == nil || b.Key != "c" {
		t.Fatal(b)
	}
	if PrerequisitesFirstBlocker(set[:2]) != nil {
		t.Fatal()
	}
}

// The remediation shapes must round-trip as a tagged union — the frontend
// dispatches on `kind`, so a rename here is a silent renderer break.
func TestPrerequisitesRemediationSerializesWithAKindTag(t *testing.T) {
	var v map[string]any
	b, _ := json.Marshal(PrerequisitesNewRemediationValue("Free port", "8081", "port", false))
	_ = json.Unmarshal(b, &v)
	if v["kind"] != "value" || v["value"] != "8081" || v["applies_to"] != "port" || v["secret"] != false {
		t.Fatal(string(b))
	}

	b, _ = json.Marshal(PrerequisitesNewRemediationDnsRecord(PrerequisitesNewDnsRecordHint("@", "example.com", "A", "1.2.3.4", "300")))
	var r map[string]any
	_ = json.Unmarshal(b, &r)
	rec := r["record"].(map[string]any)
	if r["kind"] != "dns_record" || rec["value"] != "1.2.3.4" {
		t.Fatal(string(b))
	}
	if _, ok := rec["purpose"]; ok {
		t.Fatal("an absent caption must not serialize as null")
	}

	// Go-side: the whole result keeps serde's skip_serializing_if shape.
	b, _ = json.Marshal(prereqWarning("k"))
	if string(b) != `{"key":"k","state":"unsatisfied","severity":"warning","title":"","detail":"","observed":[]}` {
		t.Fatal(string(b))
	}
}
