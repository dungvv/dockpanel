package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tests/upload-refusal-pin-e2e.sh §B: the agent's upload handler ANSWERS an
// oversize body (JSON 413 with the reason) instead of letting the body limit
// refuse it unexplained — the panel would relay that as a bare 413.
func TestPinUploadRefusalAgentAnswersAnOversizeBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/files/example.com/upload",
		strings.NewReader(`{"path":"","content":"`+strings.Repeat("A", maxBody)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("domain", "example.com")
	rec := httptest.NewRecorder()
	serverUtilsFileUpload(rec, req)
	var m map[string]string
	if rec.Code != http.StatusRequestEntityTooLarge || json.Unmarshal(rec.Body.Bytes(), &m) != nil ||
		!strings.Contains(m["error"], "1.5 MB") {
		t.Fatalf("got %d %q, want a JSON 413 that states the 1.5 MB limit", rec.Code, rec.Body.String())
	}
}
