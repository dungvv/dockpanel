package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The periodic update check must never swap a binary itself again; it may
// only ASK the panel and hand a version string to the shared launcher.
// Forbidden fragments are assembled, because this test greps phone_home.go.
func TestPhoneHomeUpdateCheckDelegatesTheSwapAndNeverPerformsOne(t *testing.T) {
	src, err := os.ReadFile("phone_home.go")
	if err != nil {
		t.Fatal(err)
	}
	var code []string
	for _, l := range strings.Split(string(src), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "//") {
			code = append(code, l)
		}
	}
	c := strings.Join(code, "\n")
	for _, bad := range []string{"os." + "Rename", "os." + "Executable", "sha" + "256", "os." + "Exit"} {
		if strings.Contains(c, bad) {
			t.Errorf("the update check must not do its own binary swap, found: %s", bad)
		}
	}
	if !strings.Contains(c, "PhoneHomeStartAgentSelfUpdate(target)") {
		t.Error("the check must hand the work to the shared launcher")
	}
	if !strings.Contains(c, "if resp.StatusCode < 200 || resp.StatusCode >= 300") {
		t.Error("a non-2xx must never be parsed as a version answer")
	}
	if !strings.Contains(c, `"Bearer "+serverToken`) {
		t.Error("the version query must authenticate")
	}
}

func TestPhoneHomeFetchTargetRefusesErrorBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		w.Write([]byte(`{"target_version":" v1.2.3 "}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	if _, err := phoneHomeFetchTarget(ctx, srv.Client(), srv.URL, "bad"); err == nil {
		t.Fatal("a 401 must be an error, not an answer")
	}
	got, err := phoneHomeFetchTarget(ctx, srv.Client(), srv.URL, "tok")
	if err != nil || got != "v1.2.3" {
		t.Fatalf("got %q, %v", got, err)
	}
}
