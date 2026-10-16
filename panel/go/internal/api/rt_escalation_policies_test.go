package api

import "testing"

const rtEscalationPoliciesTUUID = "550e8400-e29b-41d4-a716-446655440000"

func TestRtEscalationPoliciesValidateRoute(t *testing.T) {
	ok := []string{
		"all_channels",
		"on_call_schedule:" + rtEscalationPoliciesTUUID,
		"user:" + rtEscalationPoliciesTUUID,
		"webhook:https://hooks.example.com/abc",
	}
	for _, r := range ok {
		if err := rtEscalationPoliciesValidateRoute(r); err != nil {
			t.Errorf("%s rejected: %v", r, err)
		}
	}
	bad := []string{
		"garbage", "phone:555-0100", // unknown shape
		"on_call_schedule:not-a-uuid", "user:also-not", // bad uuid
		"webhook:ftp://nope", "webhook:", // non-http webhook
	}
	for _, r := range bad {
		if rtEscalationPoliciesValidateRoute(r) == nil {
			t.Errorf("%s accepted", r)
		}
	}
}

func rtEscalationPoliciesTSteps(pairs ...any) []EscalationStep {
	out := []EscalationStep{}
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, EscalationStep{AfterMinutes: int32(pairs[i].(int)), Route: pairs[i+1].(string)})
	}
	return out
}

func TestRtEscalationPoliciesValidateInputRejectsEmptySteps(t *testing.T) {
	if rtEscalationPoliciesValidateInput(&rtEscalationPoliciesPolicyInput{Name: "test", Steps: nil}) == nil {
		t.Fatal()
	}
}

func TestRtEscalationPoliciesValidateInputRejectsFirstStepWithNonzeroAfterMinutes(t *testing.T) {
	if rtEscalationPoliciesValidateInput(&rtEscalationPoliciesPolicyInput{Name: "test", Steps: rtEscalationPoliciesTSteps(5, "all_channels")}) == nil {
		t.Fatal()
	}
}

func TestRtEscalationPoliciesValidateInputRejectsNonIncreasingAfterMinutes(t *testing.T) {
	in := &rtEscalationPoliciesPolicyInput{Name: "test", Steps: rtEscalationPoliciesTSteps(0, "all_channels", 5, "all_channels", 5, "all_channels")}
	if rtEscalationPoliciesValidateInput(in) == nil {
		t.Fatal()
	}
}

func TestRtEscalationPoliciesValidateInputAcceptsWellFormedThreeStepChain(t *testing.T) {
	in := &rtEscalationPoliciesPolicyInput{Name: "On-call escalation", Steps: rtEscalationPoliciesTSteps(
		0, "on_call_schedule:"+rtEscalationPoliciesTUUID,
		5, "user:"+rtEscalationPoliciesTUUID,
		15, "all_channels",
	)}
	if err := rtEscalationPoliciesValidateInput(in); err != nil {
		t.Fatal(err)
	}
}

func TestRtEscalationPoliciesValidateInputRejectsMoreThanTenSteps(t *testing.T) {
	var s []any
	for i := 0; i < 11; i++ {
		s = append(s, i*5, "all_channels")
	}
	if rtEscalationPoliciesValidateInput(&rtEscalationPoliciesPolicyInput{Name: "test", Steps: rtEscalationPoliciesTSteps(s...)}) == nil {
		t.Fatal()
	}
}
