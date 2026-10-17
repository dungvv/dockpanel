package routes

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// tests/agent-refusal-status-pin-e2e.sh §1: every file-service refusal the
// caller can fix answers 4xx with its sentence intact; a genuine fault is
// still a 5xx (the panel replaces a 5xx with an incident id).
func TestPinAgentRefusalStatusFilesStatus(t *testing.T) {
	for msg, want := range map[string]int{
		"File not found: /var/www/x/a":           http.StatusNotFound,
		"Source does not exist":                  http.StatusNotFound,
		"Path does not exist":                    http.StatusNotFound,
		"Path already exists":                    http.StatusConflict,
		"Destination already exists":             http.StatusConflict,
		"File too large (max 2MB)":               http.StatusRequestEntityTooLarge,
		"File is binary or not readable as text": http.StatusUnsupportedMediaType,
		"permission denied":                      http.StatusInternalServerError,
	} {
		rec := httptest.NewRecorder()
		filesStatus(rec, errors.New(msg))
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != want || body["error"] != msg {
			t.Errorf("%q: got %d %q, want %d with the sentence intact", msg, rec.Code, body["error"], want)
		}
	}
}
