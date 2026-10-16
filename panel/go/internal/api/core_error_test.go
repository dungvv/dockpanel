package api

import (
	"net/http"
	"strings"
	"testing"
)

func body(t *testing.T, err error) (int, map[string]any) {
	t.Helper()
	ae, ok := err.(*ApiError)
	if !ok {
		t.Fatalf("not an ApiError: %#v", err)
	}
	m, _ := ae.Body.(map[string]any)
	return ae.Status, m
}

func st500(body string) error { return &AgentError{Kind: AgentErrStatus, Code: 500, Msg: body} }

func TestFailedOrderRecognisedByLabel(t *testing.T) {
	// ⚠ PROVISION-SHAPED: labelled, and NO renewal wrapper, so only the label
	// arm can explain it.
	got, ok := acmeOrderFailure(st500(`{"error":"The CA did not validate the challenge: no valid A record","code":"acme_order_failed"}`))
	if !ok || got != "The CA did not validate the challenge: no valid A record" {
		t.Fatalf("%q %v", got, ok)
	}
}

func TestFailedOrderRecognisedOnUnupdatedAgent(t *testing.T) {
	got, ok := acmeOrderFailure(st500(`{"error":"Renewal failed: challenge did not validate"}`))
	if !ok || got != "challenge did not validate" {
		t.Fatalf("%q %v", got, ok)
	}
}

func TestInternalAgentFaultIsStillIncidentID(t *testing.T) {
	if _, ok := acmeOrderFailure(st500(`{"error":"Failed to write cert: No space left on device (os error 28)"}`)); ok {
		t.Fatal("an internal fault must not read as an order failure")
	}
}

func TestLocalFaultOnRenewDoorOfUpdatedAgentKeepsWrapper(t *testing.T) {
	// The fallback is deliberately wide; this records what it costs.
	if _, ok := acmeOrderFailure(st500(`{"error":"Renewal failed: Failed to write cert: No space left on device"}`)); !ok {
		t.Fatal("wrapper must be recognised")
	}
}

func TestA4xxIsNotAnOrderFailure(t *testing.T) {
	e := &AgentError{Kind: AgentErrStatus, Code: 400, Msg: `{"error":"Renewal failed: bad domain","code":"acme_order_failed"}`}
	if _, ok := acmeOrderFailure(e); ok {
		t.Fatal("4xx already passes through with its own status")
	}
}

func TestTransportFailureIsNotAnOrderFailure(t *testing.T) {
	if _, ok := acmeOrderFailure(agentErr(AgentErrConnection, "refused")); ok {
		t.Fatal()
	}
}

func TestAgent4xxKeepsStatusAndSaysWhy(t *testing.T) {
	s, b := body(t, agentError("Backup analysis", &AgentError{Kind: AgentErrStatus, Code: 400, Msg: `{"error":"Path must be within /var/backups/"}`}))
	if s != 400 || b["error"] != "Path must be within /var/backups/" {
		t.Fatal(s, b)
	}
	if _, has := b["code"]; has {
		t.Fatal("a refusal is not an unreachable agent")
	}
}

func TestForeignCertificateRefusalKeepsItsCode(t *testing.T) {
	s, b := body(t, agentError("SSL provisioning", &AgentError{Kind: AgentErrStatus, Code: 422,
		Msg: `{"error":"The certificate on example.com was not issued by DockPanel (issuer: DigiCert Inc).","code":"foreign_certificate"}`}))
	if s != 422 || b["error"] != "The certificate on example.com was not issued by DockPanel (issuer: DigiCert Inc)." || b["code"] != CodeForeignCertificate {
		t.Fatal(s, b)
	}
}

func TestAgent412IsPreserved(t *testing.T) {
	s, b := body(t, agentError("WAF configure", &AgentError{Kind: AgentErrStatus, Code: 412, Msg: `{"error":"WAF not installed. Install it from the Services page first."}`}))
	if s != http.StatusPreconditionFailed || !strings.Contains(b["error"].(string), "WAF not installed") {
		t.Fatal(s, b)
	}
}

func TestSuccessFalseMessageShapeIsUnderstood(t *testing.T) {
	s, b := body(t, agentError("WAF nginx config", &AgentError{Kind: AgentErrStatus, Code: 400, Msg: `{"success":false,"message":"Nginx config test failed: unicode.mapping"}`}))
	if s != 400 || !strings.Contains(b["error"].(string), "Nginx config test failed") {
		t.Fatal(s, b)
	}
}

func TestAgent5xxStaysGenericWithIncidentID(t *testing.T) {
	s, b := body(t, agentError("Restore", st500(`{"error":"/etc/dockpanel/secret.key missing"}`)))
	msg := b["error"].(string)
	if s != 502 || !strings.HasPrefix(msg, "Operation failed. Reference: ") || strings.Contains(msg, "secret.key") {
		t.Fatal(s, msg)
	}
}

func TestOnlyTransportFailureIsMarkedUnreachable(t *testing.T) {
	s, b := body(t, agentError("Anything", agentErr(AgentErrConnection, "no such file")))
	if s != 502 || b["code"] != CodeAgentUnreachable {
		t.Fatal(s, b)
	}
	if _, b = body(t, agentError("Anything", agentErr(AgentErrCircuitOpen, "5 failures"))); b["code"] != CodeAgentUnreachable {
		t.Fatal(b)
	}
	// A parse failure is ours, not evidence the agent is down.
	if _, b = body(t, agentError("Anything", agentErr(AgentErrParse, "bad json"))); b["code"] != nil {
		t.Fatal(b)
	}
}

func TestBareTextBodySurvives(t *testing.T) {
	s, b := body(t, agentError("Anything", &AgentError{Kind: AgentErrStatus, Code: 404, Msg: "no such site"}))
	if s != 404 || b["error"] != "no such site" {
		t.Fatal(s, b)
	}
}

func TestLongAgentMessageIsBounded(t *testing.T) {
	_, b := body(t, agentError("Anything", &AgentError{Kind: AgentErrStatus, Code: 400, Msg: strings.Repeat("x", maxAgentMsg*3)}))
	if n := len([]rune(b["error"].(string))); n > maxAgentMsg+1 {
		t.Fatal(n)
	}
}

func TestThreeMarkersAreDistinct(t *testing.T) {
	codes := []string{CodeSessionInvalid, CodeReauthRequired, CodeAgentUnreachable, CodeForeignCertificate}
	for i := range codes {
		for j := i + 1; j < len(codes); j++ {
			if codes[i] == codes[j] {
				t.Fatal(codes[i])
			}
		}
	}
}

func TestErrCodedKeepsSentenceBesideMarker(t *testing.T) {
	s, b := body(t, apiErrCoded(401, "Session revoked. Please log in again.", CodeSessionInvalid))
	if s != 401 || b["code"] != CodeSessionInvalid || b["error"] != "Session revoked. Please log in again." {
		t.Fatal(s, b)
	}
}

func TestBareErrCarriesNoMarker(t *testing.T) {
	// Every credential refusal is minted with apiErr; a default code would
	// start logging users out again.
	if _, b := body(t, apiErr(401, "Current password is incorrect")); b["code"] != nil {
		t.Fatal(b)
	}
}

func TestDNSProviderRefusalRecognisedByOwnLabel(t *testing.T) {
	e := st500(`{"error":"Cloudflare refused to create the challenge record: [{\"code\":10000}]","code":"dns_provider_failed"}`)
	if got, ok := dnsProviderFailure(e); !ok || got != `Cloudflare refused to create the challenge record: [{"code":10000}]` {
		t.Fatal(got, ok)
	}
	// ⭐ The CA reader must NOT claim it.
	if _, ok := acmeOrderFailure(e); ok {
		t.Fatal("a provider refusal must not read as a CA decline")
	}
}

func TestDeclinedOrderIsNotProviderRefusal(t *testing.T) {
	e := st500(`{"error":"The CA did not validate the DNS-01 challenge: incorrect TXT value","code":"acme_order_failed"}`)
	if _, ok := dnsProviderFailure(e); ok {
		t.Fatal()
	}
	if _, ok := acmeOrderFailure(e); !ok {
		t.Fatal()
	}
}

func TestRenewalWrapperIsNotProviderRefusal(t *testing.T) {
	if _, ok := dnsProviderFailure(st500(`{"error":"Renewal failed: challenge did not validate"}`)); ok {
		t.Fatal()
	}
}

func TestUnlabelledDNS01FaultIsIncidentID(t *testing.T) {
	e := st500(`{"error":"Write cert: No space left on device (os error 28)"}`)
	if _, ok := dnsProviderFailure(e); ok {
		t.Fatal()
	}
	if _, ok := acmeOrderFailure(e); ok {
		t.Fatal()
	}
}

func TestDockerDaemonPrefixIsStripped(t *testing.T) {
	if _, b := body(t, agentError("Anything", &AgentError{Kind: AgentErrStatus, Code: 409, Msg: `{"error":"Error response from daemon: name already in use"}`})); b["error"] != "name already in use" {
		t.Fatal(b)
	}
}

func TestAgentActionableOnly4xx(t *testing.T) {
	if c, m, ok := agentActionable(&AgentError{Kind: AgentErrStatus, Code: 403, Msg: `{"error":"no"}`}); !ok || c != 403 || m != "no" {
		t.Fatal(c, m, ok)
	}
	if _, _, ok := agentActionable(st500("x")); ok {
		t.Fatal()
	}
}

func TestInternalErrorHidesDetail(t *testing.T) {
	s, b := body(t, internalError("ctx", "pq: relation \"secret_table\" does not exist"))
	if s != 500 || strings.Contains(b["error"].(string), "secret_table") || !strings.HasPrefix(b["error"].(string), "Internal error (ref: ") {
		t.Fatal(s, b)
	}
}

func TestPaginate(t *testing.T) {
	p := func(v int64) *int64 { return &v }
	if l, o := paginate(nil, nil); l != 100 || o != 0 {
		t.Fatal(l, o)
	}
	if l, o := paginate(p(50), p(10)); l != 50 || o != 10 {
		t.Fatal(l, o)
	}
	if l, _ := paginate(p(500), nil); l != 200 {
		t.Fatal(l)
	}
	if l, _ := paginate(p(0), nil); l != 1 {
		t.Fatal(l)
	}
	if _, o := paginate(nil, p(-5)); o != 0 {
		t.Fatal(o)
	}
}
