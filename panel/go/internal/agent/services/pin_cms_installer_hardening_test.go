package services

import "testing"

// tests/cms-installer-hardening-pin-e2e.sh F3/F4: the two .env dialects need
// DIFFERENT escape sets, and both writers quote unconditionally.
func TestPinCmsInstallerHardeningEnvQuoting(t *testing.T) {
	// phpdotenv (Laravel): `\`, `"` and `$` all escaped; `#` and space kept
	// literal inside the quotes.
	for in, want := range map[string]string{
		`a\b`:      `"a\\b"`,
		`a"b`:      `"a\"b"`,
		`a$b`:      `"a\$b"`,
		"p#ss":     `"p#ss"`,
		"two word": `"two word"`,
		`#\"$ x`:   `"#\\\"\$ x"`,
	} {
		if got := cmsQuoteLaravelEnvValue(in); got != want {
			t.Errorf("laravel %q: got %s want %s", in, got, want)
		}
	}
	// CI4's own DotEnv: only `\` and `"` escaped — `$` must stay bare.
	for in, want := range map[string]string{
		`a\b`:  `"a\\b"`,
		`a"b`:  `"a\"b"`,
		`a$b`:  `"a$b"`,
		"a b":  `"a b"`,
		`\"$#`: `"\\\"$#"`,
	} {
		if got := cmsQuoteCi4EnvValue(in); got != want {
			t.Errorf("ci4 %q: got %s want %s", in, got, want)
		}
	}
	// Unconditional: a value with no space or special char is still quoted.
	if got := cmsReplaceEnvLine("DB_PASSWORD=\n", "DB_PASSWORD", "plain"); got != "DB_PASSWORD=\"plain\"\n" {
		t.Errorf("laravel writer did not quote a plain value: %q", got)
	}
	if got := cmsSetCiEnv("# app.baseURL = ''\n", "app.baseURL", "https://example.com/"); got != "app.baseURL = \"https://example.com/\"\n" {
		t.Errorf("ci4 writer did not quote a plain value: %q", got)
	}
}
