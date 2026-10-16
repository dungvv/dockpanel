package api

import "testing"

func TestRtPrometheusTokenPrefixIsStableLength(t *testing.T) {
	tok := rtPrometheusGenerateToken()
	if tok[:5] != "dpms_" || len(tok[:14]) != 14 {
		t.Fatalf("bad token %q", tok)
	}
	// Indices 5..14 must be hex — that's the prefix stored for display.
	for _, c := range tok[5:14] {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			t.Fatalf("non-hex prefix %q", tok[5:14])
		}
	}
}

func TestRtPrometheusTokenIsSufficientlyLong(t *testing.T) {
	// "dpms_" + two dashless UUIDs = 5 + 32 + 32.
	if n := len(rtPrometheusGenerateToken()); n != 69 {
		t.Fatalf("len = %d", n)
	}
}
