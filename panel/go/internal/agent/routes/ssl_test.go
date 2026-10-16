package routes

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// The absence of `runtime` is a cross-crate contract: the panel's stack
// renewal payload is an email and nothing else, and must parse (a required
// runtime would 422 every stack renewal, weekly, on every install).
func TestAPayloadWithoutRuntimeParsesAndAsksForNoReRender(t *testing.T) {
	var b sslRenewRequest
	if err := json.Unmarshal([]byte(`{"email":"ops@example.com"}`), &b); err != nil {
		t.Fatal(err)
	}
	if b.Email != "ops@example.com" || b.Runtime != nil || b.Root != nil || b.ProxyPort != nil || b.PhpSocket != nil || b.Profile != nil {
		t.Fatalf("%+v", b)
	}
	req := httptest.NewRequest("POST", "/ssl/x.example/renew", strings.NewReader(`{"email":"ops@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	if !nginxDecodeStrict(httptest.NewRecorder(), req, &b, "email") {
		t.Fatal("strict decode refused the stack payload")
	}
}

func TestAPayloadCarryingRuntimeStillDescribesAVhost(t *testing.T) {
	var b sslRenewRequest
	json.Unmarshal([]byte(`{"email":"ops@example.com","runtime":"php","root":"/var/www/x","php_socket":"unix:/run/php/php8.3-fpm.sock","profile":"classic"}`), &b)
	if b.Runtime == nil || *b.Runtime != "php" || *b.Root != "/var/www/x" || *b.Profile != "classic" {
		t.Fatalf("%+v", b)
	}
}

func TestCaOrInternalLabelsOnlyWhatTheCaOrProviderSaid(t *testing.T) {
	cases := []struct {
		err    string
		status int
		code   any
		msg    string
	}{
		{services.SslCaDeclined + "no", 500, "acme_order_failed", "no"},
		{services.SslDNSProviderDeclined + "token", 500, "dns_provider_failed", "token"},
		{services.SslForeignCertRefused + "theirs", 422, "foreign_certificate", "theirs"},
		{"disk full", 500, nil, "disk full"},
	}
	for _, c := range cases {
		status, body := sslCaOrInternal(errors.New(c.err))
		if status != c.status || body["code"] != c.code || body["error"] != c.msg {
			t.Errorf("%q -> %d %v", c.err, status, body)
		}
	}
}

func webMux() *http.ServeMux {
	r := &Router{State: &State{}, Auth: http.NewServeMux(), Public: http.NewServeMux()}
	registerSsl(r)
	registerSslRegistry(r)
	registerNginx(r)
	return r.Auth
}

// axum lets the static segment win; the Go dispatcher must agree.
func TestSslDispatchKeepsStaticSegmentPrecedence(t *testing.T) {
	mux := webMux()
	for path, want := range map[string]int{
		"/ssl/status/bad_domain":         400, // status handler, invalid domain
		"/ssl/bad_domain/renewal-info":   400, // missing email query → 400 too
		"/ssl/a.example/unknown":         404,
		"/ssl/status/renewal-info?email": 400,
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("GET %s: %d, want %d (%s)", path, rec.Code, want, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/ssl/status/bad_domain", nil))
	if !strings.Contains(rec.Body.String(), "Invalid domain format") {
		t.Errorf("status handler not reached: %s", rec.Body)
	}
}

func TestMissingRequiredFieldIs422(t *testing.T) {
	mux := webMux()
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/nginx/sites/a.example", `{"root":"/var/www"}`},
		{"PUT", "/nginx/sites/a.example", `{"runtime":null}`},
		{"POST", "/ssl/provision/a.example", `{"email":"x@y.z"}`},
		{"POST", "/ssl/registry", `{"alias":"a"}`},
	} {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s %s %s: %d", c.method, c.path, c.body, rec.Code)
		}
	}
}

func TestDisableSiteAnswersInPlainText(t *testing.T) {
	rec := httptest.NewRecorder()
	webMux().ServeHTTP(rec, httptest.NewRequest("POST", "/nginx/sites/bad_domain/disable", nil))
	if rec.Code != 400 || rec.Body.String() != "Invalid domain" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("%d %q %s", rec.Code, rec.Body, rec.Header())
	}
}
