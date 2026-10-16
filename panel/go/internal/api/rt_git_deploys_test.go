package api

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func rtGitDeploysTestValue(t *testing.T, s string) any {
	t.Helper()
	var v any
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRtGitDeploysAnEmbeddedCredentialNeverReachesAReaderWhoDoesNotOwnIt(t *testing.T) {
	cases := [][2]string{
		// The workaround operators reach for when a private HTTPS clone fails (#119).
		{"https://ghp_secret123@github.com/me/app.git", "https://•••@github.com/me/app.git"},
		{"https://user:ghp_secret123@github.com/me/app.git", "https://•••@github.com/me/app.git"},
		// TWO '@' in the authority: the boundary is the LAST one (rfind vs find).
		{"https://me@corp.com:ghp_secret123@github.com/me/app.git", "https://•••@github.com/me/app.git"},
		// Nothing to hide — untouched.
		{"https://github.com/me/app.git", "https://github.com/me/app.git"},
		// An '@' in the PATH is not userinfo.
		{"https://git.example.com/~user@host/app.git", "https://git.example.com/~user@host/app.git"},
		// scp-style SSH remotes carry no scheme and no secret.
		{"git@github.com:me/app.git", "git@github.com:me/app.git"},
	}
	for _, c := range cases {
		if got := rtGitDeploysMaskRepoCredentials(c[0]); got != c[1] {
			t.Errorf("%s: got %s want %s", c[0], got, c[1])
		}
	}
}

func TestRtGitDeploysABlankFieldIsStoredAsNullNotAsAnEmptyString(t *testing.T) {
	for _, s := range []string{"", "   "} {
		if rtGitDeploysBlankToNone(&s) != nil {
			t.Errorf("%q should be nil", s)
		}
	}
	if rtGitDeploysBlankToNone(nil) != nil {
		t.Error("nil should stay nil")
	}
	v := "prisma-migrate"
	if got := rtGitDeploysBlankToNone(&v); got == nil || *got != v {
		t.Errorf("got %v", got)
	}
}

func TestRtGitDeploysAPreviewIsTornDownInTheSpaceItWasCreatedIn(t *testing.T) {
	if n, s := rtGitDeploysPreviewCleanupTarget("dockpanel-git-pr.myapp-pr-feature-x"); n != "myapp-pr-feature-x" || s != "preview" {
		t.Errorf("scoped: %s %s", n, s)
	}
	if n, s := rtGitDeploysPreviewCleanupTarget("dockpanel-git-myapp-pr-feature-x"); n != "myapp-pr-feature-x" || s != "preview_legacy" {
		t.Errorf("legacy: %s %s", n, s)
	}
}

func TestRtGitDeploysTheTwoStoredShapesAreNeverTheSameString(t *testing.T) {
	legacy := "dockpanel-git-myapp-pr-feature-x"
	scoped := "dockpanel-git-" + rtGitDeploysPreviewScopePrefix + "myapp-pr-feature-x"
	if legacy == scoped {
		t.Fatal("shapes collide")
	}
	if isValidName(rtGitDeploysStripContainerPrefix(scoped)) {
		t.Error("scoped name must not be a valid deploy name")
	}
	if !isValidName(rtGitDeploysStripContainerPrefix(legacy)) {
		t.Error("legacy name is a valid deploy name")
	}
}

func rtGitDeploysTestBody(env any) map[string]any {
	return rtGitDeploysBuildDeployBody(rtGitDeploysDeployBody{
		Name: "app", ImageTag: "dockpanel-git-app:abc", ContainerPort: 3000, HostPort: 30001,
		EnvVars: env, Scope: "deploy",
	})
}

func TestRtGitDeploysDeployBodySendsTheKeyTheAgentReads(t *testing.T) {
	// GH #94: the agent reads "env"; sending the "env_vars" alias too would be
	// rejected as a duplicate field.
	body := rtGitDeploysTestBody(rtGitDeploysTestValue(t, `{"APP_KEY":"secret"}`))
	if body["env"].(map[string]any)["APP_KEY"] != "secret" {
		t.Errorf("env = %v", body["env"])
	}
	if _, ok := body["env_vars"]; ok {
		t.Error("must not also send the alias")
	}
}

func TestRtGitDeploysOptionalFieldsAreOmittedNotNulled(t *testing.T) {
	body := rtGitDeploysTestBody(map[string]any{})
	for _, k := range []string{"domain", "memory_mb", "cpu_percent", "ssl_email", "tls_mode", "tls_certificate", "volumes"} {
		if _, ok := body[k]; ok {
			t.Errorf("%s should be absent, not null", k)
		}
	}
}

func TestRtGitDeploysDeclaredVolumesAreSent(t *testing.T) {
	body := rtGitDeploysBuildDeployBody(rtGitDeploysDeployBody{
		Name: "app", ImageTag: "dockpanel-git-app:abc", ContainerPort: 3000, HostPort: 30001,
		EnvVars: map[string]any{}, Scope: "deploy", Volumes: []string{"/data", "/app/uploads"},
	})
	if !reflect.DeepEqual(body["volumes"], []string{"/data", "/app/uploads"}) {
		t.Errorf("volumes = %v", body["volumes"])
	}
}

func TestRtGitDeploysProvidedModeSendsTheAliasAndWithholdsTheAcmeAddress(t *testing.T) {
	body := rtGitDeploysBuildDeployBody(rtGitDeploysDeployBody{
		Name: "app", ImageTag: "dockpanel-git-app:abc", ContainerPort: 3000, HostPort: 30001,
		EnvVars: map[string]any{}, Domain: rtGitDeploysPtr("app.example.com"),
		SslEmail:       rtGitDeploysDeployTLSEmail("provided", rtGitDeploysPtr("ops@example.com")),
		TlsMode:        rtGitDeploysPtr("provided"),
		TlsCertificate: rtGitDeploysPtr("wildcard-2026"),
		Scope:          "deploy",
	})
	if body["tls_mode"] != "provided" || body["tls_certificate"] != "wildcard-2026" {
		t.Errorf("body = %v", body)
	}
	if _, ok := body["ssl_email"]; ok {
		t.Error("provided mode must not also send an ACME address")
	}
}

func TestRtGitDeploysAcmeModeStillSendsTheAddress(t *testing.T) {
	body := rtGitDeploysBuildDeployBody(rtGitDeploysDeployBody{
		Name: "app", ImageTag: "dockpanel-git-app:abc", ContainerPort: 3000, HostPort: 30001,
		EnvVars: map[string]any{}, Domain: rtGitDeploysPtr("app.example.com"),
		SslEmail: rtGitDeploysDeployTLSEmail("acme", rtGitDeploysPtr("ops@example.com")),
		TlsMode:  rtGitDeploysPtr("acme"),
		Scope:    "deploy",
	})
	if body["tls_mode"] != "acme" || body["ssl_email"] != "ops@example.com" {
		t.Errorf("body = %v", body)
	}
	if _, ok := body["tls_certificate"]; ok {
		t.Error("tls_certificate should be absent")
	}
}

func TestRtGitDeploysDeployURLReportsHTTPSForAcmeAndProvidedOnly(t *testing.T) {
	for mode, want := range map[string]string{
		"acme": "https://app.example.com", "provided": "https://app.example.com", "none": "http://app.example.com",
	} {
		if got := rtGitDeploysDeployURL("app.example.com", mode); got != want {
			t.Errorf("%s: %s", mode, got)
		}
	}
}

func TestRtGitDeploysEnvScalarsAreStringifiedRatherThanFailingTheDeploy(t *testing.T) {
	env := rtGitDeploysEnvObject(rtGitDeploysTestValue(t, `{"PORT":8080,"DEBUG":true,"NAME":"app"}`))
	want := map[string]any{"PORT": "8080", "DEBUG": "true", "NAME": "app"}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("env = %v", env)
	}
}

func TestRtGitDeploysEnvValuesWithNoEnvRepresentationAreDropped(t *testing.T) {
	env := rtGitDeploysEnvObject(rtGitDeploysTestValue(t, `{"GOOD":"keep","NULLED":null,"NESTED":{"a":1},"LIST":[1,2]}`))
	if !reflect.DeepEqual(env, map[string]any{"GOOD": "keep"}) {
		t.Errorf("env = %v", env)
	}
}

func TestRtGitDeploysANonObjectEnvColumnYieldsAnEmptyMap(t *testing.T) {
	for _, v := range []any{nil, "oops"} {
		if env := rtGitDeploysEnvObject(v); len(env) != 0 || env == nil {
			t.Errorf("%v → %v", v, env)
		}
	}
}

func TestRtGitDeploysStripPrefixFromStoredPreviewName(t *testing.T) {
	if got := rtGitDeploysStripContainerPrefix("dockpanel-git-myapp-pr-feat-x"); got != "myapp-pr-feat-x" {
		t.Error(got)
	}
}

func TestRtGitDeploysStripPrefixIsIdempotentAndSafeOnBare(t *testing.T) {
	if got := rtGitDeploysStripContainerPrefix("myapp-pr-feat-x"); got != "myapp-pr-feat-x" {
		t.Error(got)
	}
	// Only ONE prefix is stripped.
	if got := rtGitDeploysStripContainerPrefix("dockpanel-git-dockpanel-git-x"); got != "dockpanel-git-x" {
		t.Error(got)
	}
}

func TestRtGitDeploysValidCronAcceptsWhatTheSchedulerRuns(t *testing.T) {
	// Must NOT be stricter than deploy_scheduler::matches_field.
	for _, c := range []string{
		"* * * * *", "*/5 * * * *", "0 3 * * *", "0 0 1,15 * *", "0 9-17 * * 1-5",
		"* * * * * *",    // 6-field: scheduler reads first 5
		"*/5,30 * * * *", // step mixed with a number
		"1,,5 * * * *",   // empty comma segment: scheduler skips it
	} {
		if !rtGitDeploysIsValidCron(c) {
			t.Errorf("%q should be valid", c)
		}
	}
}

func TestRtGitDeploysValidCronRejectsMalformed(t *testing.T) {
	for _, c := range []string{"", "* * * *", "abc * * * *", "*/0 * * * *", "@daily"} {
		if rtGitDeploysIsValidCron(c) {
			t.Errorf("%q should be rejected", c)
		}
	}
}

func TestRtGitDeploysDNSLabelMakesValidPreviewSlugs(t *testing.T) {
	for in, want := range map[string]string{
		"feature_login":   "feature-login", // '_' would fail domain validation
		"feature/JIRA-42": "feature-jira-42",
		"--weird__":       "weird",
		"###":             "preview", // nothing alphanumeric remains
		"Main":            "main",
	} {
		if got := rtGitDeploysDNSLabel(in); got != want {
			t.Errorf("%q → %q want %q", in, got, want)
		}
	}
}
