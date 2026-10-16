package api

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRtSettingsSensitivePredicate(t *testing.T) {
	for _, k := range []string{"smtp_password", "pdns_api_key", "ai_diagnosis_api_key", "oauth_google_client_secret"} {
		if !rtSettingsIsSensitiveKey(k) {
			t.Fatal(k)
		}
	}
	if rtSettingsIsSensitiveKey("smtp_host") {
		t.Fatal()
	}
	// Every sensitive key is writable (else it could never be set).
	for _, k := range rtSettingsSensitiveKeys {
		found := false
		for _, a := range rtSettingsAllowedKeys {
			found = found || a == k
		}
		if !found {
			t.Fatal(k)
		}
	}
}

func TestRtSettingsSMTPPushWarning(t *testing.T) {
	p := &rtSettingsSMTPPush{configured: []string{"a"}}
	if p.warning() != nil {
		t.Fatal("every host took it")
	}
	p.failed = [][2]string{{"b", "refused"}}
	p.notAsked = [][2]string{{"c", "offline"}}
	want := "SMTP settings saved, but they reached only 1 of 3 servers — rejected by b (refused); never reached c (offline). " +
		"Mail sent from the others will keep using whatever they were last given; save SMTP again once they are back online."
	if w := p.warning(); w == nil || *w != want {
		t.Fatal(*w)
	}
}

func TestRtSettingsUptime(t *testing.T) {
	f := filepath.Join(t.TempDir(), "uptime")
	_ = os.WriteFile(f, []byte("90061.5 1.0\n"), 0o644)
	if got := rtSettingsUptime(f); got != "1 days, 1h 1m" {
		t.Fatal(got)
	}
	_ = os.WriteFile(f, []byte("3720 1\n"), 0o644)
	if got := rtSettingsUptime(f); got != "1h 2m" {
		t.Fatal(got)
	}
	if rtSettingsUptime(f+"x") != "unknown" {
		t.Fatal()
	}
}

func TestDBRtSettingsWhitelistMaskAndValidation(t *testing.T) {
	e := rtIdentityTestEnv(t)
	tok := e.setupAdmin(t, "admin@x.test", "correct-horse")
	A := []string{"Authorization", "Bearer " + tok}
	for body, code := range map[string]int{
		`{"jwt_secret":"x"}`:                        400,
		`{"allowed_panel_ips":"10.0.0.0/8, nope"}`:  400,
		`{"logo_url":"javascript:alert(1)"}`:        400,
		`{"base_url":"panel.example.com"}`:          400,
		`{"retention_activity_days":"0"}`:           400,
		`{"accent_color":"red"}`:                    400,
		`{"oauth_github_client_secret":"s3cr3t!!"}`: 200,
	} {
		var m map[string]any
		_ = json.Unmarshal([]byte(body), &m)
		if w, out := e.do(t, "PUT", "/api/settings", m, A...); w.Code != code {
			t.Fatal(body, w.Code, out)
		}
	}
	stored, _ := queryScalar[string](context.Background(), e.st.DB, "SELECT value FROM settings WHERE key = 'oauth_github_client_secret'")
	if stored == "s3cr3t!!" {
		t.Fatal("encrypted at rest")
	}
	if _, out := e.do(t, "GET", "/api/settings", nil, A...); out["oauth_github_client_secret"] != "********" {
		t.Fatal(out)
	}
	// The mask sentinel never overwrites the real secret.
	_, _ = e.do(t, "PUT", "/api/settings", map[string]any{"oauth_github_client_secret": "********"}, A...)
	if again, _ := queryScalar[string](context.Background(), e.st.DB, "SELECT value FROM settings WHERE key = 'oauth_github_client_secret'"); again != stored {
		t.Fatal("mask overwrote the secret")
	}
	// Export never carries secrets.
	if _, out := e.do(t, "GET", "/api/settings/export", nil, A...); jsonGet(out, "settings", "oauth_github_client_secret") != nil {
		t.Fatal(out)
	}
	// Branding is public and lists configured providers.
	if w, out := e.do(t, "GET", "/api/branding", nil); w.Code != 200 || out["panel_name"] != "DockPanel" {
		t.Fatal(w.Code, out)
	}
}
