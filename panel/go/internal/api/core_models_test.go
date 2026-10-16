package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUpdateChannelValidate(t *testing.T) {
	for _, ok := range []string{"stable", "candidate", "hold"} {
		if UpdateChannelValidate(ok) != nil {
			t.Fatal(ok)
		}
	}
	for _, bad := range []string{"", "nightly", "STABLE", "stable "} {
		if UpdateChannelValidate(bad) == nil {
			t.Fatal(bad)
		}
	}
}

func TestUserSkipsSecretsAndKeepsNulls(t *testing.T) {
	b, _ := json.Marshal(User{PasswordHash: "h", TotpSecret: sp("s")})
	s := string(b)
	for _, leak := range []string{"password_hash", "totp_secret", "reset_token", "recovery_codes", "oauth_id", "email_token", "reset_expires"} {
		if strings.Contains(s, leak) {
			t.Fatal(leak)
		}
	}
	if !strings.Contains(s, `"oauth_provider":null`) {
		t.Fatal("Option without skip_serializing_if serialises as null", s)
	}
}

func TestConfigCORSOrigins(t *testing.T) {
	if got := configCORSOrigins("", ""); len(got) != 0 {
		t.Fatal("CORS origins empty when no config set")
	}
	if got := configCORSOrigins("", "https://panel.example.com"); len(got) != 1 || got[0] != "https://panel.example.com" {
		t.Fatal(got)
	}
	if got := configCORSOrigins(" a , ,b ", "https://x"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatal(got)
	}
}
