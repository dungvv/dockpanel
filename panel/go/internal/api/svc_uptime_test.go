package api

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Deliberately credential-shaped: a health endpoint's query string is where
// people put tokens.
const uptimeTestSecretURL = "http://127.0.0.1:9/internal/health?api_key=SUPERSECRET123"

func TestUptimeAFailedCheckDoesNotRepublishTheMonitorURL(t *testing.T) {
	_, err := (&http.Client{Timeout: 5 * time.Second}).Get(uptimeTestSecretURL)
	if err == nil {
		t.Fatal("port 9 on loopback must refuse the connection")
	}
	// POSITIVE CONTROL, load-bearing: the exact string once stored and
	// published. If the client stops printing the URL this fails loudly
	// rather than the assertions below passing for an unrelated reason.
	if raw := err.Error(); !strings.Contains(raw, "SUPERSECRET123") {
		t.Fatalf("control failed — the client no longer prints the URL: %s", raw)
	}
	d := uptimeDescribeCheckError(err, uptimeTestSecretURL)
	for _, leak := range []string{"SUPERSECRET123", "internal/health", "127.0.0.1"} {
		if strings.Contains(d, leak) {
			t.Errorf("%q published: %s", leak, d)
		}
	}
	// ...and it still says something an operator can act on.
	if len(d) <= len("error sending request") {
		t.Errorf("message reduced to nothing: %s", d)
	}
}

// The TLS-mismatch source chain names the host in a lower layer; the scrub
// removes it while keeping the operator's half.
func TestUptimeTheScrubRemovesTheHostATLSMismatchPrints(t *testing.T) {
	out := uptimeRedactMonitorTarget(
		"error sending request: client error (Connect): invalid peer certificate: certificate not valid for name \"status.example.com\"; certificate is only valid for DnsName(\"*.other.example\")",
		"https://status.example.com/healthz?token=abc")
	if strings.Contains(out, "status.example.com") {
		t.Errorf("host survived the scrub: %s", out)
	}
	if !strings.Contains(out, "invalid peer certificate") {
		t.Errorf("the operator's half was destroyed: %s", out)
	}
}

// Longest-first: the host is a substring of the URL, so redacting it first
// would strand the path and query beside the marker.
func TestUptimeTheScrubTakesTheWholeURLBeforeTheBareHost(t *testing.T) {
	out := uptimeRedactMonitorTarget("error sending request for url (https://status.example.com/healthz?token=abc)",
		"https://status.example.com/healthz?token=abc")
	if strings.Contains(out, "token=abc") || strings.Contains(out, "healthz") {
		t.Errorf("url survived: %s", out)
	}
}
