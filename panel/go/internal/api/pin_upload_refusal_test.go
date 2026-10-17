package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tests/upload-refusal-pin-e2e.sh §B/§D: an upload body the extractor refuses
// as too large is answered with a CODED 413 the SPA can branch on and a
// sentence the operator can act on — routed on the rejection's STATUS — and
// any other rejection stays a 400.
func TestPinUploadRefusalOversizeBodyIsACoded413(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/sites/x/files/upload",
		strings.NewReader(`{"content":"`+strings.Repeat("A", maxJSONBody)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	var b rtFilesUploadBody
	err := decodeJSON(req, &b)
	if err == nil {
		t.Fatal("an oversize body must be rejected by the extractor")
	}
	s, m := body(t, rtFilesUploadRejection(err))
	if s != http.StatusRequestEntityTooLarge || m["code"] != CodePayloadTooLarge {
		t.Fatalf("oversize upload: got %d %v, want a 413 coded %q", s, m, CodePayloadTooLarge)
	}
	if msg, _ := m["error"].(string); !strings.Contains(msg, "too large") || !strings.Contains(msg, "1.5 MB") {
		t.Fatalf("the refusal does not say why or state the limit: %q", msg)
	}
	// A non-size rejection is not dressed up as a size refusal.
	s, m = body(t, rtFilesUploadRejection(rejection(http.StatusBadRequest, "Failed to parse")))
	if s != http.StatusBadRequest || m["code"] != nil {
		t.Fatalf("a malformed body: got %d %v, want an uncoded 400", s, m)
	}
}
