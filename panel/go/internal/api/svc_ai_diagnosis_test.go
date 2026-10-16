package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAiDiagnosisRedactsEnvStyleSecrets(t *testing.T) {
	out := aiDiagnosisRedact("DB_PASSWORD=hunter2\nDEPLOY_TOKEN: ghp_abcdEFGH1234\nPORT=3000")
	if strings.Contains(out, "hunter2") || strings.Contains(out, "ghp_abcdEFGH1234") {
		t.Fatalf("secret leaked: %q", out)
	}
	if !strings.Contains(out, "PORT=3000") {
		t.Fatalf("ordinary line lost: %q", out)
	}
}

func TestAiDiagnosisRedactsBearerTokens(t *testing.T) {
	out := aiDiagnosisRedact("curl -H 'Authorization: Bearer sk-live-abc123XYZ789' https://api.example.com")
	if strings.Contains(out, "sk-live-abc123XYZ789") || !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("got %q", out)
	}
}

func TestAiDiagnosisRedactsConnectionStringPasswords(t *testing.T) {
	out := aiDiagnosisRedact("postgres://dockpanel:S3cretPass!@127.0.0.1:5432/dockpanel")
	if strings.Contains(out, "S3cretPass!") {
		t.Fatalf("got %q", out)
	}
	if !strings.Contains(out, "postgres://dockpanel:[REDACTED]@127.0.0.1:5432/dockpanel") {
		t.Fatalf("got %q", out)
	}
}

func TestAiDiagnosisRedactsPrivateKeyBlocks(t *testing.T) {
	out := aiDiagnosisRedact("before\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\ndef456\n-----END OPENSSH PRIVATE KEY-----\nafter")
	for _, want := range []string{"[REDACTED PRIVATE KEY]", "before", "after"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
	if strings.Contains(out, "abc123") {
		t.Fatalf("key body leaked: %q", out)
	}
}

func TestAiDiagnosisLeavesOrdinaryOutputUntouched(t *testing.T) {
	log := "Step 4/9 : RUN npm install\n---> Running in abc123\nnpm ERR! code ENOENT"
	if got := aiDiagnosisRedact(log); got != log {
		t.Fatalf("got %q", got)
	}
}

func aiDiagnosisTestJSON(s string) any {
	var v any
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

func TestAiDiagnosisExtractErrorMessage(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"nested openai/anthropic/gemini shape", `{"error": {"message": "invalid api key", "type": "authentication_error"}}`, "invalid api key"},
		// Confirmed live against api.x.ai: a plain string, not an object with
		// .message. Without this fallback every xAI error reports "unknown error".
		{"flat xai shape", `{"code": "invalid-argument", "error": "Incorrect API key provided."}`, "Incorrect API key provided."},
		{"neither shape", `{"something_else": "not an error field"}`, "unknown error"},
	}
	for _, c := range cases {
		if got := aiDiagnosisExtractErrorMessage(aiDiagnosisTestJSON(c.body)); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// Closes the gap between "redact() works" and "build_prompt actually calls it
// on the field that reaches the wire".
func TestAiDiagnosisBuildPromptRedactsTheOutputField(t *testing.T) {
	p := aiDiagnosisBuildPrompt(&AiDiagnosisFailureContext{
		SiteName: "example.com", CommitHash: "abc1234", CommitMessage: "test",
		ImageTag: "example:latest", Output: "DB_PASSWORD=hunter2\nbuild failed",
	})
	if strings.Contains(p, "hunter2") || !strings.Contains(p, "build failed") {
		t.Fatalf("got %q", p)
	}
}

func TestAiDiagnosisTruncatesFromTheHeadKeepingTheTail(t *testing.T) {
	p := aiDiagnosisBuildPrompt(&AiDiagnosisFailureContext{
		SiteName: "example.com", CommitHash: "abc1234", CommitMessage: "test",
		ImageTag: "example:latest", Output: strings.Repeat("x", aiDiagnosisMaxOutputChars+500) + "TAIL_MARKER",
	})
	if !strings.Contains(p, "TAIL_MARKER") || !strings.Contains(p, "earlier characters truncated") {
		t.Fatal("tail not kept or truncation not announced")
	}
}
