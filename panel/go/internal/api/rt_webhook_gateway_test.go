package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strings"
	"testing"
)

// Ported from webhook_gateway.rs `signature_verdict_tests`.

const (
	rtWebhookGatewayTestBody   = `{"action":"opened","number":7}`
	rtWebhookGatewayTestHeader = "x-hub-signature-256"
	rtWebhookGatewayTestSecret = "s3cr3t-shared-with-github"
)

// sign builds the signature a correctly-configured sender would send, under
// an arbitrary key — including the empty one.
func rtWebhookGatewaySign(h func() hash.Hash, prefix string, key []byte, body string) string {
	mac := hmac.New(h, key)
	mac.Write([]byte(body))
	return prefix + hex.EncodeToString(mac.Sum(nil))
}

func rtWebhookGatewaySha256(key []byte, body string) string {
	return rtWebhookGatewaySign(sha256.New, "sha256=", key, body)
}

// The handler builds this map from request headers with lower-cased names,
// which is why the lookup lower-cases the configured header name.
func rtWebhookGatewayHeaders(pairs ...[2]string) map[string]any {
	m := map[string]any{}
	for _, p := range pairs {
		m[p[0]] = p[1]
	}
	return m
}

func rtWebhookGatewayClassify(mode string, secret, header *string, presented ...[2]string) rtWebhookGatewaySignatureVerdict {
	return rtWebhookGatewayClassifySignature(mode, secret, header, rtWebhookGatewayHeaders(presented...), []byte(rtWebhookGatewayTestBody))
}

func rtWebhookGatewaySptr(s string) *string { return &s }

func rtWebhookGatewayRecorded(v rtWebhookGatewaySignatureVerdict) string {
	r := v.recorded()
	switch {
	case r == nil:
		return "none"
	case *r:
		return "true"
	default:
		return "false"
	}
}

// ── The two states that used to be one ──────────────────────────────────

func TestWebhookGatewayNoVerificationConfiguredAttestsNothing(t *testing.T) {
	v := rtWebhookGatewayClassify("none", nil, nil)
	if v != rtWebhookGatewayVerdictNotConfigured {
		t.Fatal(v)
	}
	if rtWebhookGatewayRecorded(v) != "none" {
		t.Fatal("an endpoint that never claimed to verify records no attestation")
	}
	if _, rej := v.rejection(); rej {
		t.Fatal("must accept")
	}
}

func TestWebhookGatewayVerifyingModeWithNoSecretIsRejectedNotWavedThrough(t *testing.T) {
	// The shape a raw API call could store: mode set, secret absent. It used
	// to be indistinguishable from "not configured" — and pass.
	v := rtWebhookGatewayClassify("hmac_sha256", nil, rtWebhookGatewaySptr(rtWebhookGatewayTestHeader), [2]string{rtWebhookGatewayTestHeader, "sha256=deadbeef"})
	if v != rtWebhookGatewayVerdictUnverifiable || rtWebhookGatewayRecorded(v) != "false" {
		t.Fatal(v)
	}
	if _, rej := v.rejection(); !rej {
		t.Fatal("an endpoint that cannot verify must not accept")
	}
}

func TestWebhookGatewayVerifyingModeWithNoHeaderIsRejected(t *testing.T) {
	if v := rtWebhookGatewayClassify("hmac_sha256", rtWebhookGatewaySptr(rtWebhookGatewayTestSecret), nil); v != rtWebhookGatewayVerdictUnverifiable {
		t.Fatal(v)
	}
}

// ── The empty key: the shape the form used to post ──────────────────────

func TestWebhookGatewayEmptySecretDoesNotAuthenticateAnEmptyKeySignature(t *testing.T) {
	// HMAC accepts a zero-length key, so an endpoint stored with
	// verify_secret = "" used to let anyone who guessed it produce a valid
	// signature — and be RECORDED as authentic before being relayed.
	forged := rtWebhookGatewaySha256(nil, rtWebhookGatewayTestBody)
	v := rtWebhookGatewayClassify("hmac_sha256", rtWebhookGatewaySptr(""), rtWebhookGatewaySptr(rtWebhookGatewayTestHeader), [2]string{rtWebhookGatewayTestHeader, forged})
	if v == rtWebhookGatewayVerdictValid {
		t.Fatal("an empty secret must never attest anything")
	}
	if v != rtWebhookGatewayVerdictUnverifiable || rtWebhookGatewayRecorded(v) != "false" {
		t.Fatal(v)
	}
}

func TestWebhookGatewayWhitespaceOnlySecretIsAbsentToo(t *testing.T) {
	v := rtWebhookGatewayClassify("hmac_sha256", rtWebhookGatewaySptr("   "), rtWebhookGatewaySptr(rtWebhookGatewayTestHeader), [2]string{rtWebhookGatewayTestHeader, "sha256=00"})
	if v != rtWebhookGatewayVerdictUnverifiable {
		t.Fatal(v)
	}
}

func TestWebhookGatewayBlankHeaderNameIsAbsentToo(t *testing.T) {
	if v := rtWebhookGatewayClassify("hmac_sha256", rtWebhookGatewaySptr(rtWebhookGatewayTestSecret), rtWebhookGatewaySptr("")); v != rtWebhookGatewayVerdictUnverifiable {
		t.Fatal(v)
	}
}

// ── Verification still works, which is what makes the above meaningful ──

func TestWebhookGatewayCorrectlySignedSha256DeliveryIsValid(t *testing.T) {
	sig := rtWebhookGatewaySha256([]byte(rtWebhookGatewayTestSecret), rtWebhookGatewayTestBody)
	v := rtWebhookGatewayClassify("hmac_sha256", rtWebhookGatewaySptr(rtWebhookGatewayTestSecret), rtWebhookGatewaySptr(rtWebhookGatewayTestHeader), [2]string{rtWebhookGatewayTestHeader, sig})
	if v != rtWebhookGatewayVerdictValid || rtWebhookGatewayRecorded(v) != "true" {
		t.Fatal(v)
	}
	if _, rej := v.rejection(); rej {
		t.Fatal("must accept")
	}
}

func TestWebhookGatewayCorrectlySignedSha1DeliveryIsValid(t *testing.T) {
	sig := rtWebhookGatewaySign(sha1.New, "sha1=", []byte(rtWebhookGatewayTestSecret), rtWebhookGatewayTestBody)
	v := rtWebhookGatewayClassify("hmac_sha1", rtWebhookGatewaySptr(rtWebhookGatewayTestSecret), rtWebhookGatewaySptr("x-hub-signature"), [2]string{"x-hub-signature", sig})
	if v != rtWebhookGatewayVerdictValid {
		t.Fatal(v)
	}
}

func TestWebhookGatewaySignatureUnderWrongKeyIsInvalidNotUnverifiable(t *testing.T) {
	// Both are rejections, but different facts with different sentences: one
	// endpoint is misconfigured, the other is being signed badly.
	sig := rtWebhookGatewaySha256([]byte("someone-elses-secret"), rtWebhookGatewayTestBody)
	v := rtWebhookGatewayClassify("hmac_sha256", rtWebhookGatewaySptr(rtWebhookGatewayTestSecret), rtWebhookGatewaySptr(rtWebhookGatewayTestHeader), [2]string{rtWebhookGatewayTestHeader, sig})
	if v != rtWebhookGatewayVerdictInvalid || rtWebhookGatewayRecorded(v) != "false" {
		t.Fatal(v)
	}
	if msg, _ := v.rejection(); msg != "Invalid webhook signature" {
		t.Fatal(msg)
	}
}

func TestWebhookGatewayMissingSignatureHeaderOnConfiguredEndpointIsInvalid(t *testing.T) {
	v := rtWebhookGatewayClassify("hmac_sha256", rtWebhookGatewaySptr(rtWebhookGatewayTestSecret), rtWebhookGatewaySptr(rtWebhookGatewayTestHeader), [2]string{"content-type", "application/json"})
	if v != rtWebhookGatewayVerdictInvalid {
		t.Fatal(v)
	}
}

func TestWebhookGatewaySignatureThatIsNotHexIsInvalidRatherThanAPanic(t *testing.T) {
	v := rtWebhookGatewayClassify("hmac_sha256", rtWebhookGatewaySptr(rtWebhookGatewayTestSecret), rtWebhookGatewaySptr(rtWebhookGatewayTestHeader), [2]string{rtWebhookGatewayTestHeader, "sha256=not-hex-at-all"})
	if v != rtWebhookGatewayVerdictInvalid {
		t.Fatal(v)
	}
}

func TestWebhookGatewayAlgorithmPrefixIsOptional(t *testing.T) {
	bare := strings.TrimPrefix(rtWebhookGatewaySha256([]byte(rtWebhookGatewayTestSecret), rtWebhookGatewayTestBody), "sha256=")
	v := rtWebhookGatewayClassify("hmac_sha256", rtWebhookGatewaySptr(rtWebhookGatewayTestSecret), rtWebhookGatewaySptr(rtWebhookGatewayTestHeader), [2]string{rtWebhookGatewayTestHeader, bare})
	if v != rtWebhookGatewayVerdictValid {
		t.Fatal(v)
	}
}

func TestWebhookGatewayConfiguredHeaderNameIsMatchedCaseInsensitively(t *testing.T) {
	sig := rtWebhookGatewaySha256([]byte(rtWebhookGatewayTestSecret), rtWebhookGatewayTestBody)
	v := rtWebhookGatewayClassify("hmac_sha256", rtWebhookGatewaySptr(rtWebhookGatewayTestSecret), rtWebhookGatewaySptr("X-Hub-Signature-256"), [2]string{rtWebhookGatewayTestHeader, sig})
	if v != rtWebhookGatewayVerdictValid {
		t.Fatal(v)
	}
}

func TestWebhookGatewayBodyThatDiffersByOneByteDoesNotVerify(t *testing.T) {
	sig := rtWebhookGatewaySha256([]byte(rtWebhookGatewayTestSecret), rtWebhookGatewayTestBody)
	v := rtWebhookGatewayClassifySignature("hmac_sha256", rtWebhookGatewaySptr(rtWebhookGatewayTestSecret), rtWebhookGatewaySptr(rtWebhookGatewayTestHeader),
		rtWebhookGatewayHeaders([2]string{rtWebhookGatewayTestHeader, sig}), []byte(`{"action":"opened","number":8}`))
	if v != rtWebhookGatewayVerdictInvalid {
		t.Fatal(v)
	}
}

// ── Fail-closed on anything this build does not understand ──────────────

func TestWebhookGatewayModeThisBuildCannotComputeIsRejected(t *testing.T) {
	// Reachable by a hand-edited row, or an older binary against a database a
	// newer one wrote. The safe-looking default would be "no verification".
	v := rtWebhookGatewayClassify("hmac_sha512", rtWebhookGatewaySptr(rtWebhookGatewayTestSecret), rtWebhookGatewaySptr(rtWebhookGatewayTestHeader), [2]string{rtWebhookGatewayTestHeader, "sha512=00"})
	if v != rtWebhookGatewayVerdictUnverifiable || rtWebhookGatewayRecorded(v) != "false" {
		t.Fatal(v)
	}
}

// ── The mapping itself, so a new variant cannot be added unclassified ───

func TestWebhookGatewayOnlyAnEndpointThatAskedForNothingRecordsNoAttestation(t *testing.T) {
	want := map[rtWebhookGatewaySignatureVerdict][2]any{
		rtWebhookGatewayVerdictNotConfigured: {"none", false},
		rtWebhookGatewayVerdictValid:         {"true", false},
		// Every rejection is recorded FALSE, which is the writer the column
		// never had: the 401 used to return above the INSERT.
		rtWebhookGatewayVerdictInvalid:      {"false", true},
		rtWebhookGatewayVerdictUnverifiable: {"false", true},
	}
	for v, w := range want {
		_, rej := v.rejection()
		if got := [2]any{rtWebhookGatewayRecorded(v), rej}; got != w {
			t.Fatalf("%d: got %v want %v", v, got, w)
		}
	}
}

// Go-side additions: the helpers the Rust got from serde_json / http.

func TestWebhookGatewayRouteAdmits(t *testing.T) {
	route := func(path, value *string) *rtWebhookGatewayWebhookRoute {
		return &rtWebhookGatewayWebhookRoute{FilterPath: path, FilterValue: value}
	}
	body := `{"action":"opened","pr":{"labels":["a","b"]},"a/b":"slash"}`
	cases := []struct {
		r    *rtWebhookGatewayWebhookRoute
		body string
		want bool
	}{
		{route(nil, nil), body, true},
		{route(rtWebhookGatewaySptr("/action"), nil), body, true},
		{route(rtWebhookGatewaySptr("/action"), rtWebhookGatewaySptr("opened")), body, true},
		{route(rtWebhookGatewaySptr("/action"), rtWebhookGatewaySptr("closed")), body, false},
		{route(rtWebhookGatewaySptr("/pr/labels/1"), rtWebhookGatewaySptr("b")), body, true},
		{route(rtWebhookGatewaySptr("/pr/labels/01"), rtWebhookGatewaySptr("b")), body, false},
		{route(rtWebhookGatewaySptr("/a~1b"), rtWebhookGatewaySptr("slash")), body, true},
		{route(rtWebhookGatewaySptr("action"), rtWebhookGatewaySptr("")), body, true}, // no leading slash → None → ""
		{route(rtWebhookGatewaySptr("/missing"), rtWebhookGatewaySptr("x")), body, false},
		{route(rtWebhookGatewaySptr("/action"), rtWebhookGatewaySptr("x")), "not json", true},
	}
	for i, c := range cases {
		if got := rtWebhookGatewayRouteAdmits(c.r, c.body); got != c.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
}

func TestWebhookGatewayTruncateKeepsUTF8(t *testing.T) {
	s := strings.Repeat("a", 1999) + "é"
	if got := rtWebhookGatewayTruncate(s); got != strings.Repeat("a", 1999) {
		t.Fatal(len(got))
	}
	if got := rtWebhookGatewayLossyUTF8([]byte{'a', 0xff, 'b'}); got != "a�b" {
		t.Fatal(got)
	}
	if _, ok := rtWebhookGatewayHeaderStr("café"); ok {
		t.Fatal("non-ASCII header value is not a str")
	}
}
