package routes

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// registry-ollama-arg-validation-pin-e2e.sh: a value that lands in a docker /
// ollama argv slot where a flag is expected must never start with '-'.
// (registry-login and `docker rmi --help` are covered by
// TestDockerAppsRoutesValidateBeforeActing.)
func TestPinRegistryOllamaArgValidationLogoutRefusesALeadingDash(t *testing.T) {
	w := dockerRoutesDo("POST", "/apps/registry-logout", `{"server":"--help"}`)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "Invalid registry server") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// Both ollama handlers (pull and delete) take the model through this one helper
// before `docker exec … ollama pull|rm <model>`.
func TestPinRegistryOllamaArgValidationModelRefusesALeadingDash(t *testing.T) {
	for _, m := range []string{"-x", "--insecure", " -x"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"model":"`+m+`"}`))
		r.Header.Set("Content-Type", "application/json")
		if _, ok := dockerAppsOllamaModel(w, r); ok || w.Code != 400 {
			t.Errorf("%q accepted (%d)", m, w.Code)
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"model":"llama3:8b"}`))
	r.Header.Set("Content-Type", "application/json")
	if got, ok := dockerAppsOllamaModel(w, r); !ok || got != "llama3:8b" {
		t.Fatalf("control model refused: %q %d", got, w.Code)
	}
}
