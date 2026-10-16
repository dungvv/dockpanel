package api

import "testing"

func stacksDecode(t *testing.T, s string) any {
	t.Helper()
	v, err := agentDecodeJSON([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The stored value wins; a NULL row is read the way the agent always inferred
// it — a non-blank address means Let's Encrypt.
func TestStacksEffectiveTlsModePrefersTheStoredValue(t *testing.T) {
	cases := []struct {
		mode, email *string
		want        string
	}{
		{new("none"), new("ops@example.com"), "none"},
		{new("acme"), nil, "acme"},
		{new("provided"), new("ops@example.com"), "provided"},
		// A NULL row derives from the address.
		{nil, new("ops@example.com"), "acme"},
		{nil, new("  "), "none"},
		{nil, new(""), "none"},
		{nil, nil, "none"},
		// An unknown word (cannot reach the column) falls back, never panics.
		{new("bogus"), new("ops@example.com"), "acme"},
		{new("bogus"), nil, "none"},
	}
	for i, c := range cases {
		if got := rtStacksEffectiveTlsMode(c.mode, c.email); got != c.want {
			t.Errorf("case %d: got %s want %s", i, got, c.want)
		}
	}
}

func TestStacksRequestedTlsModeNormalisesAndRefuses(t *testing.T) {
	for _, in := range []*string{nil, new("")} {
		if m, err := rtStacksRequestedTlsMode(in); m != nil || err != nil {
			t.Fatal(m, err)
		}
	}
	if m, err := rtStacksRequestedTlsMode(new(" Acme ")); err != nil || *m != "acme" {
		t.Fatal(m, err)
	}
	if m, err := rtStacksRequestedTlsMode(new("provided")); err != nil || *m != "provided" {
		t.Fatal(m, err)
	}
	if _, err := rtStacksRequestedTlsMode(new("letsencrypt")); err == nil {
		t.Fatal("accepted letsencrypt")
	}
}

// The agent reports a refused TLS leg inside a 200; only an explicit
// `ssl: true` counts as served over HTTPS.
func TestStacksProvidedTlsRefusalReadsTheAgentAnswer(t *testing.T) {
	if r := rtStacksProvidedTlsRefusal(stacksDecode(t, `{"ssl": true}`)); r != nil {
		t.Fatal(*r)
	}
	// The agent's real shape: the flag is a boolean, the sentence the warning.
	if r := rtStacksProvidedTlsRefusal(stacksDecode(t, `{"ssl": false, "tls_refused": true, "proxy_warning": "no such alias"}`)); r == nil || *r != "no such alias" {
		t.Fatal(r)
	}
	if r := rtStacksProvidedTlsRefusal(stacksDecode(t, `{"proxy_warning": "Traefik"}`)); r == nil || *r != "Traefik" {
		t.Fatal(r)
	}
	if rtStacksProvidedTlsRefusal(stacksDecode(t, `{}`)) == nil {
		t.Fatal("empty answer must be a refusal")
	}
}
