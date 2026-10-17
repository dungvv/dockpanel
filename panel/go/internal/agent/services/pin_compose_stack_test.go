package services

import (
	"slices"
	"testing"
)

// compose-stack-pin-e2e.sh C7: Go map iteration is randomised per range, so
// the same YAML must still yield the same service order every time.
func TestPinComposeStackServiceOrderIsDeterministic(t *testing.T) {
	yaml := "services:\n"
	for _, k := range []string{"zeta", "alpha", "mike", "bravo", "yankee", "charlie", "xray", "delta"} {
		yaml += "  " + k + ":\n    image: x:1\n"
	}
	var first []string
	for i := 0; i < 50; i++ {
		s, err := ComposeParseCompose(yaml, nil)
		if err != nil {
			t.Fatal(err)
		}
		keys := make([]string, len(s))
		for j := range s {
			keys[j] = s[j].Key
		}
		if first == nil {
			first = keys
		} else if !slices.Equal(first, keys) {
			t.Fatalf("order changed between parses: %v vs %v", first, keys)
		}
	}
}
