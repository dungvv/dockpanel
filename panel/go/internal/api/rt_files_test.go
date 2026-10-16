package api

import (
	"strings"
	"testing"
)

// b64Len is the base64 length for n bytes: four chars per three bytes, padded.
func rtFilesTestB64Len(n int) int { return (n + 2) / 3 * 4 }

func TestRtFilesAPayloadAtTheLimitIsAccepted(t *testing.T) {
	if rtFilesExceedsUploadLimit(strings.Repeat("A", rtFilesTestB64Len(rtFilesUploadMaxFileBytes))) {
		t.Fatal("a file of exactly the advertised limit must upload")
	}
}

func TestRtFilesAPayloadOverTheLimitIsRefused(t *testing.T) {
	if !rtFilesExceedsUploadLimit(strings.Repeat("A", rtFilesTestB64Len(rtFilesUploadMaxFileBytes+1))) {
		t.Fatal("one byte over the advertised limit must be refused")
	}
}

func TestRtFilesAnEmptyPayloadIsNotTooLarge(t *testing.T) {
	if rtFilesExceedsUploadLimit("") {
		t.Fatal("empty refused")
	}
}

// The advertised limit has to fit INSIDE the request-body envelope that
// rejects before this module runs, or the check is unreachable and the
// product refuses in silence.
func TestRtFilesTheAdvertisedLimitFitsInsideTheBodyEnvelope(t *testing.T) {
	carryable := maxJSONBody / 4 * 3
	if rtFilesUploadMaxFileBytes > carryable {
		t.Fatalf("advertised %d exceeds the %d bytes a %d-byte body can carry", rtFilesUploadMaxFileBytes, carryable, maxJSONBody)
	}
}
