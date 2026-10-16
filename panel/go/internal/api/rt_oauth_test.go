package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Google's `sub` is a JSON string and must lose its quotes; GitHub's numeric
// id keeps its digits exactly (decoded with UseNumber).
func TestRtOauthStringifyID(t *testing.T) {
	if rtOauthStringifyID("1234567890") != "1234567890" {
		t.Fatal()
	}
	if got := rtOauthStringifyID(json.Number("9007199254740993")); got != "9007199254740993" {
		t.Fatal(got)
	}
}

func TestRtOauthRedirectURIAndProviders(t *testing.T) {
	if rtOauthRedirectURI("https://p.test", "github") != "https://p.test/api/auth/oauth/github/callback" {
		t.Fatal()
	}
	for _, p := range rtOauthProviders {
		if rtOauthGetProvider(p) == nil {
			t.Fatalf("%s is offered but unknown", p)
		}
	}
	if rtOauthGetProvider("facebook") != nil {
		t.Fatal()
	}
}

func TestDBRtOauthStateIsBoundToTheBrowser(t *testing.T) {
	e := rtIdentityTestEnv(t)
	e.st.Config.BaseURL = "https://p.test"
	ctx := context.Background()
	_, _ = execSQL(ctx, e.st.DB, "INSERT INTO settings (key, value) VALUES ('oauth_github_client_id', 'cid'), ('oauth_github_client_secret', 'sec')")

	if w, _ := e.do(t, "GET", "/api/auth/oauth/facebook", nil); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w, _ := e.do(t, "GET", "/api/auth/oauth/gitlab", nil); w.Code != 400 {
		t.Fatal("not configured", w.Code)
	}
	w, _ := e.do(t, "GET", "/api/auth/oauth/github", nil, "X-Forwarded-Proto", "https")
	loc := w.Header().Get("Location")
	if w.Code != 307 || !strings.HasPrefix(loc, "https://github.com/login/oauth/authorize?client_id=cid&redirect_uri=https%3A%2F%2Fp.test%2Fapi%2Fauth%2Foauth%2Fgithub%2Fcallback&scope=user%3Aemail&state=") {
		t.Fatal(w.Code, loc)
	}
	state := loc[strings.Index(loc, "state=")+6 : strings.Index(loc, "&response_type")]
	if c := w.Header().Get("Set-Cookie"); c != "oauth_csrf="+state+"; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600" {
		t.Fatal(c)
	}

	cb := func(q, cookie string) int {
		r := httptest.NewRequest("GET", "/api/auth/oauth/github/callback?"+q, nil)
		if cookie != "" {
			r.Header.Set("Cookie", cookie)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, r)
		return rec.Code
	}
	if cb("code=x", "") != 400 {
		t.Fatal("missing state is an extractor rejection")
	}
	if cb("code=x&state=garbage", "oauth_csrf=garbage") != 400 {
		t.Fatal("a state the server never issued")
	}
	// Login-CSRF handoff: a real state, presented by a browser without the
	// cookie — consumed and refused.
	if cb("code=x&state="+state, "") != 400 {
		t.Fatal("no cookie")
	}
	if cb("code=x&state="+state, "oauth_csrf="+state) != 400 {
		t.Fatal("a state is single-use")
	}
	// A state issued for another provider.
	e.st.OAuthStates["s2"] = OAuthState{Provider: "google", Created: time.Now()}
	if cb("code=x&state=s2", "oauth_csrf=s2") != 400 {
		t.Fatal("provider binding")
	}
	// Expired.
	e.st.OAuthStates["s3"] = OAuthState{Provider: "github", Created: time.Now().Add(-11 * time.Minute)}
	if cb("code=x&state=s3", "oauth_csrf=s3") != 400 {
		t.Fatal("expiry")
	}
	// Provider error is surfaced.
	if cb("error=access_denied&state=x", "") != 400 {
		t.Fatal()
	}
}
