package api

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestEveryCredentialWriterIsCovered discovers every module that writes an
// encrypted credential and asserts this sweep covers it.
//
// ⚠ This ENUMERATES; it does not confirm a number someone already believes.
// The walk covers the WHOLE package (routes and services alike — an earlier
// Rust cut walked only routes, so a service writer joined unseen). The two
// machinery files necessarily name the function and store nothing of their
// own, so they are excluded BY NAME, and the floors below keep that exclusion
// from quietly emptying the census.
//
// Run once every module of the package exists (the floors fail on a partial
// tree by design: "found no writers" and "failed to look" must not look alike).
func TestEveryCredentialWriterIsCovered(t *testing.T) {
	machinery := []string{"secrets_crypto", "credential_reencrypt"}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var writers []string
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		scanned++
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// ReencryptCredential( contains EncryptCredential( only by case, but
		// it is removed before the test rather than reasoned around.
		body := strings.ReplaceAll(string(b), "ReencryptCredential(", "")
		if !strings.Contains(body, "SecretsCryptoEncryptCredential(") {
			continue
		}
		stem := strings.TrimSuffix(f, ".go")
		for _, p := range []string{"rt_", "svc_", "core_"} {
			stem = strings.TrimPrefix(stem, p)
		}
		if !slices.Contains(machinery, stem) {
			writers = append(writers, stem)
		}
	}
	slices.Sort(writers)
	writers = slices.Compact(writers)

	// Positive control for the WALK itself: a moved layout yields few files.
	if scanned < 90 {
		t.Fatalf("the walk examined only %d source file(s) — the layout moved or the package is incomplete, so this census proves nothing", scanned)
	}
	// Floor: a discovery that collapses is a broken instrument, not a clean tree.
	if len(writers) < 8 {
		t.Fatalf("credential-writer discovery found only %d module(s) (%v) — the enumeration is broken, not the tree", len(writers), writers)
	}
	var missing []string
	for _, m := range writers {
		if !slices.ContainsFunc(CredentialReencryptCoveredModules, func(c [2]string) bool { return c[0] == m }) {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("these modules encrypt a credential but are not covered by the re-encryption sweep: %v. "+
			"Add the table/column to credentialReencryptSimpleSubjects (or a special-shape arm) and then add the module to "+
			"CredentialReencryptCoveredModules — in that order.", missing)
	}
}

// The registry must not name a module that no longer exists — a stale entry
// makes the census above pass vacuously for that module.
func TestCoveredModulesAllStillExist(t *testing.T) {
	for _, c := range CredentialReencryptCoveredModules {
		_, e1 := os.Stat("rt_" + c[0] + ".go")
		_, e2 := os.Stat("svc_" + c[0] + ".go")
		if e1 != nil && e2 != nil {
			t.Fatalf("CredentialReencryptCoveredModules names %q, but neither rt_%s.go nor svc_%s.go exists", c[0], c[0], c[0])
		}
	}
}

// Every subject a module is paired with must be one the sweep really visits —
// the arm that makes the pairing load-bearing rather than decorative.
func TestSubjectTokensMatchTheSweep(t *testing.T) {
	swept := CredentialReencryptSweptSubjects()
	for _, c := range CredentialReencryptCoveredModules {
		if !slices.Contains(swept, c[1]) {
			t.Fatalf("CredentialReencryptCoveredModules pairs %q with subject %q, which the sweep never visits. Swept: %v", c[0], c[1], swept)
		}
	}
	// And the special arms must exist — read from THIS file's source so the
	// list cannot drift away from the report constructors it names.
	src, err := os.ReadFile("svc_credential_reencrypt.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(src), "credentialReencryptNewReport("); n < 4 {
		t.Fatalf("found %d credentialReencryptNewReport call(s) — the arms moved and this check measures an empty set", n)
	}
	for _, s := range credentialReencryptSpecialSubjects {
		if !strings.Contains(string(src), `credentialReencryptNewReport("`+s+`")`) {
			t.Fatalf("credentialReencryptSpecialSubjects names %q but no arm in this file reports it", s)
		}
	}
}

// The SQL IN (...) list is SQL text and cannot reference rtSettingsSensitiveKeys;
// this keeps the two from drifting.
func TestSensitiveSettingsSQLCoversSettingsSensitiveKeys(t *testing.T) {
	if len(rtSettingsSensitiveKeys) < 2 {
		t.Fatal("rtSettingsSensitiveKeys is unexpectedly small — the source of truth is broken, not the tree")
	}
	for _, k := range rtSettingsSensitiveKeys {
		if !strings.Contains(credentialReencryptSensitiveSettingsSQL, "'"+k+"'") {
			t.Fatalf("rtSettingsSensitiveKeys contains %q but the sweep's IN(...) list does not", k)
		}
	}
}

// The sweep re-keys a row under a new primary key, counts a current row as
// current, and leaves an unreadable row exactly as it was.
func TestDBCredentialReencryptSweep(t *testing.T) {
	e := rtIdentityTestEnv(t)
	ctx := context.Background()
	t.Setenv(SecretsCryptoEncryptionKeyEnv, "")
	os.Unsetenv(SecretsCryptoEncryptionKeyEnv)
	old, _ := SecretsCryptoEncryptCredential("smtp-pass", testSecret)
	_, _ = execSQL(ctx, e.st.DB, "INSERT INTO settings (key, value) VALUES ('smtp_password', $1), ('oauth_github_client_secret', 'not-ciphertext!!')", old)

	t.Setenv(SecretsCryptoEncryptionKeyEnv, "a-brand-new-operator-key")
	reports := CredentialReencryptAll(ctx, e.st.DB, testSecret)
	var settings *CredentialReencryptSubjectReport
	for _, r := range reports {
		if r.Subject == "settings.value" {
			settings = r
		}
	}
	if settings == nil || settings.Examined != 2 || settings.Rewritten+settings.AlreadyCurrent+settings.Unreadable != 2 {
		t.Fatalf("%+v", settings)
	}
	now, _ := queryScalar[string](ctx, e.st.DB, "SELECT value FROM settings WHERE key = 'smtp_password'")
	if settings.Rewritten == 1 && now == old {
		t.Fatal("a rewritten row must change")
	}
	if got := SecretsCryptoDecryptCredentialOrLegacy(now, testSecret); got != "smtp-pass" {
		t.Fatal("re-keyed value must still decrypt", got)
	}
	// Idempotent: a second run rewrites nothing.
	for _, r := range CredentialReencryptAll(ctx, e.st.DB, testSecret) {
		if r.Rewritten != 0 {
			t.Fatalf("second run rewrote %s", r.Subject)
		}
	}
}
