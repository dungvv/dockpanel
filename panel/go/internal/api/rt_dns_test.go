package api

import "testing"

func TestDnsDigArgRejectsOptionInjection(t *testing.T) {
	cases := []struct {
		s     string
		under bool
		want  bool
	}{
		// A leading dash/plus would let dig parse the value as an option (e.g. -f<file>).
		{"-fFILE", true, false},
		{"+short", true, false},
		{"-x", false, false},
		{"", true, false},
		// Escaping the charset (spaces, slashes, shell metachars) is rejected.
		{"a b", true, false},
		{"a/b", true, false},
		{"a;b", true, false},
		// Underscore only where allowed (query names vs health-check domains).
		{"_dmarc.example.com", true, true},
		{"_dmarc.example.com", false, false},
		// Normal names pass.
		{"example.com", true, true},
		{"sub.example.com", false, true},
		{"mail-1.example.com", false, true},
	}
	for _, c := range cases {
		if got := rtDnsIsSafeDigArg(c.s, c.under); got != c.want {
			t.Errorf("rtDnsIsSafeDigArg(%q, %v) = %v, want %v", c.s, c.under, got, c.want)
		}
	}
}
