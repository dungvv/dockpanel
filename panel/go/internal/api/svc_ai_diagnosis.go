package api

// Port of panel/backend/src/services/ai_diagnosis.rs.
//
// BYO-API-key LLM root-cause diagnosis for failed Git Deploy builds.
//
// Default-off (`ai_diagnosis_enabled`, see routes::settings::ALLOWED_KEYS).
// The operator supplies their own API key for one of four providers —
// Anthropic, OpenAI, Gemini, or Grok (xAI) — and triggers a diagnosis by hand
// per failed deploy from the Git Deploys page. Nothing here runs on a
// schedule or fires automatically: every call is a deliberate, operator-paid
// request.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"
)

// aiDiagnosisMaxOutputChars: failure output is truncated to this many
// *characters from the end* before it goes into the prompt — the failing step
// is almost always the tail of a build log, and this keeps the request small
// regardless of provider.
const aiDiagnosisMaxOutputChars = 8000

// AiDiagnosisConfig is the decrypted provider configuration.
type AiDiagnosisConfig struct {
	Provider string
	Model    string
	APIKey   string
}

// AiDiagnosisLoadConfig reads the 4 `ai_diagnosis_*` settings and decrypts
// the stored key.
//
// Returns (nil, nil) when the feature is off or incompletely configured, so
// every caller gives one clear "not configured" error instead of a confusing
// provider-specific failure two steps downstream.
func AiDiagnosisLoadConfig(ctx context.Context, db Querier, jwtSecret string) (*AiDiagnosisConfig, error) {
	rows, err := queryAll[Tup2[string, string]](ctx, db,
		"SELECT key, value FROM settings WHERE key IN "+
			"('ai_diagnosis_enabled', 'ai_diagnosis_provider', 'ai_diagnosis_model', 'ai_diagnosis_api_key')")
	if err != nil {
		return nil, internalError("ai diagnosis config", err)
	}
	get := func(k string) string {
		for _, r := range rows {
			if r.A == k {
				return r.B
			}
		}
		return ""
	}
	if get("ai_diagnosis_enabled") != "true" {
		return nil, nil
	}
	provider := get("ai_diagnosis_provider")
	model := get("ai_diagnosis_model")
	apiKeyEnc := get("ai_diagnosis_api_key")
	if provider == "" || model == "" || apiKeyEnc == "" {
		return nil, nil
	}
	return &AiDiagnosisConfig{
		Provider: provider,
		Model:    model,
		APIKey:   SecretsCryptoDecryptCredentialOrLegacy(apiKeyEnc, jwtSecret),
	}, nil
}

var aiDiagnosisPatterns = []*regexp.Regexp{
	// KEY=value / KEY: value style env/config lines, key name implies a secret.
	regexp.MustCompile(`(?i)([A-Za-z0-9_.\-]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDENTIAL)[A-Za-z0-9_.\-]*)\s*[:=]\s*("?)([^\s"'` + "`" + `]{3,})("?)`),
	// Authorization: Bearer/Basic <token>
	regexp.MustCompile(`(?i)(Authorization\s*:\s*(?:Bearer|Basic)\s+)([A-Za-z0-9\-_.~+/=]{8,})`),
	// postgres://user:password@host, mysql://user:pass@host, redis://:pass@host, etc.
	regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://[^:/\s]+:)([^@/\s]+)(@)`),
	// PEM private key blocks (SSH deploy keys, TLS keys) — drop the whole block.
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
}

// aiDiagnosisRedact strips common secret shapes out of build/deploy output
// before it leaves the box for a third-party API. A failed build's log is
// exactly where a leaked env var, DB password, or CI token ends up printed —
// redaction happens unconditionally, with no setting to turn it off, because
// the person who can turn it off is not the one whose secret would leak.
func aiDiagnosisRedact(text string) string {
	p := aiDiagnosisPatterns
	out := p[3].ReplaceAllLiteralString(text, "[REDACTED PRIVATE KEY]")
	out = p[0].ReplaceAllString(out, "${1}=${2}[REDACTED]${4}")
	out = p[1].ReplaceAllString(out, "${1}[REDACTED]")
	out = p[2].ReplaceAllString(out, "${1}[REDACTED]${3}")
	return out
}

// AiDiagnosisFailureContext is what a failed deploy contributes to the prompt.
type AiDiagnosisFailureContext struct {
	SiteName      string
	CommitHash    string
	CommitMessage string
	ImageTag      string
	Output        string
}

func aiDiagnosisBuildPrompt(c *AiDiagnosisFailureContext) string {
	redacted := aiDiagnosisRedact(c.Output)
	body := redacted
	if count := utf8.RuneCountInString(redacted); count > aiDiagnosisMaxOutputChars {
		skip := count - aiDiagnosisMaxOutputChars
		body = fmt.Sprintf("...[%d earlier characters truncated]...\n%s", skip, string([]rune(redacted)[skip:]))
	}
	return fmt.Sprintf("You are helping a system administrator diagnose a failed deployment on their "+
		"self-hosted server-management panel. Some values below may already be redacted "+
		"as [REDACTED] — do not ask for them back, work with what's shown.\n\n"+
		"Site: %s\nCommit: %s (%s)\nImage tag: %s\n\n"+
		"Build/deploy failure output (most recent lines last):\n```\n%s\n```\n\n"+
		"In plain terms, answer two things: (1) what most likely caused this failure, "+
		"and (2) the specific, concrete fix to try next. Keep it short — a sysadmin is "+
		"going to act on this immediately, not read an essay.",
		c.SiteName, c.CommitHash, c.CommitMessage, c.ImageTag, body)
}

// AiDiagnosisExplainFailure asks the configured provider for a diagnosis.
func AiDiagnosisExplainFailure(ctx context.Context, config *AiDiagnosisConfig, c *AiDiagnosisFailureContext) (string, error) {
	prompt := aiDiagnosisBuildPrompt(c)
	client := &http.Client{Timeout: 45 * time.Second}
	switch config.Provider {
	case "anthropic":
		return aiDiagnosisCallAnthropic(ctx, client, config, prompt)
	case "openai":
		return aiDiagnosisCallOpenAICompatible(ctx, client, "https://api.openai.com/v1/chat/completions", config, prompt)
	case "grok":
		return aiDiagnosisCallOpenAICompatible(ctx, client, "https://api.x.ai/v1/chat/completions", config, prompt)
	case "gemini":
		return aiDiagnosisCallGemini(ctx, client, config, prompt)
	default:
		return "", apiErr(http.StatusBadRequest, "Unknown AI diagnosis provider: "+config.Provider)
	}
}

// aiDiagnosisSnippet: body text from a failed provider call, truncated so a
// verbose HTML error page or a pathological response can't blow up our own
// error payload — this text reaches the operator, never the API key.
func aiDiagnosisSnippet(body string) string {
	r := []rune(body)
	if len(r) > 500 {
		return string(r[:500]) + "..."
	}
	return body
}

// aiDiagnosisExtractErrorMessage pulls a human-readable message out of a
// failed provider response. Anthropic, OpenAI, and Gemini all nest it as
// `error.message` (an object) — but xAI's error responses, confirmed live
// against api.x.ai (not assumed from docs), are the flat shape
// {"error": "<string>", "code": "..."} despite xAI's SUCCESS responses being
// otherwise OpenAI-shaped. Try the nested form first, then the flat string, so
// no provider falls through to "unknown error" for what is otherwise a
// perfectly good message.
func aiDiagnosisExtractErrorMessage(body any) string {
	if s, ok := jsonStr(jsonGet(body, "error", "message")); ok {
		return s
	}
	if s, ok := jsonStr(jsonGet(body, "error")); ok {
		return s
	}
	return "unknown error"
}

// aiDiagnosisPost sends a JSON POST and decodes the JSON answer. sendFail
// and parseFail build the provider-specific sentences.
func aiDiagnosisPost(ctx context.Context, client *http.Client, url string, header http.Header, payload any,
	sendFail, parseFail func(error) string) (int, any, error) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return 0, nil, apiErr(http.StatusBadGateway, sendFail(err))
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, apiErr(http.StatusBadGateway, sendFail(err))
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	var body any
	if err := dec.Decode(&body); err != nil {
		return 0, nil, apiErr(http.StatusBadGateway, parseFail(err))
	}
	return resp.StatusCode, body, nil
}

func aiDiagnosisStatus(code int) string { return fmt.Sprintf("%d %s", code, http.StatusText(code)) }

func aiDiagnosisCallAnthropic(ctx context.Context, client *http.Client, config *AiDiagnosisConfig, prompt string) (string, error) {
	h := http.Header{}
	h.Set("x-api-key", config.APIKey)
	h.Set("anthropic-version", "2023-06-01")
	status, body, err := aiDiagnosisPost(ctx, client, "https://api.anthropic.com/v1/messages", h,
		map[string]any{
			"model":      config.Model,
			"max_tokens": 1024,
			"messages":   []any{map[string]any{"role": "user", "content": prompt}},
		},
		func(e error) string { return fmt.Sprintf("Could not reach Anthropic: %v", e) },
		func(e error) string { return fmt.Sprintf("Anthropic returned an unreadable response: %v", e) })
	if err != nil {
		return "", err
	}
	if status < 200 || status > 299 {
		return "", apiErr(http.StatusBadGateway, fmt.Sprintf("Anthropic API error (%s): %s",
			aiDiagnosisStatus(status), aiDiagnosisSnippet(aiDiagnosisExtractErrorMessage(body))))
	}
	if s, ok := jsonStr(jsonGet(body, "content", 0, "text")); ok {
		return s, nil
	}
	return "", apiErr(http.StatusBadGateway, "Anthropic response had no text content")
}

func aiDiagnosisCallOpenAICompatible(ctx context.Context, client *http.Client, url string, config *AiDiagnosisConfig, prompt string) (string, error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+config.APIKey)
	status, body, err := aiDiagnosisPost(ctx, client, url, h,
		map[string]any{
			"model":      config.Model,
			"messages":   []any{map[string]any{"role": "user", "content": prompt}},
			"max_tokens": 1024,
		},
		func(e error) string { return fmt.Sprintf("Could not reach %s: %v", url, e) },
		func(e error) string { return fmt.Sprintf("Provider returned an unreadable response: %v", e) })
	if err != nil {
		return "", err
	}
	if status < 200 || status > 299 {
		return "", apiErr(http.StatusBadGateway, fmt.Sprintf("Provider API error (%s): %s",
			aiDiagnosisStatus(status), aiDiagnosisSnippet(aiDiagnosisExtractErrorMessage(body))))
	}
	if s, ok := jsonStr(jsonGet(body, "choices", 0, "message", "content")); ok {
		return s, nil
	}
	return "", apiErr(http.StatusBadGateway, "Provider response had no message content")
}

func aiDiagnosisCallGemini(ctx context.Context, client *http.Client, config *AiDiagnosisConfig, prompt string) (string, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", config.Model)
	h := http.Header{}
	h.Set("x-goog-api-key", config.APIKey)
	status, body, err := aiDiagnosisPost(ctx, client, url, h,
		map[string]any{
			"contents": []any{map[string]any{"parts": []any{map[string]any{"text": prompt}}}},
		},
		func(e error) string { return fmt.Sprintf("Could not reach Gemini: %v", e) },
		func(e error) string { return fmt.Sprintf("Gemini returned an unreadable response: %v", e) })
	if err != nil {
		return "", err
	}
	if status < 200 || status > 299 {
		return "", apiErr(http.StatusBadGateway, fmt.Sprintf("Gemini API error (%s): %s",
			aiDiagnosisStatus(status), aiDiagnosisSnippet(aiDiagnosisExtractErrorMessage(body))))
	}
	if s, ok := jsonStr(jsonGet(body, "candidates", 0, "content", "parts", 0, "text")); ok {
		return s, nil
	}
	return "", apiErr(http.StatusBadGateway, "Gemini response had no text content")
}
