package services

import (
	"context"
	"testing"
)

// The validator runs before the installed check, so a bad reference is
// refused whether or not syft is present.
func TestSbomRejectsBadImageRefs(t *testing.T) {
	for _, b := range []string{"", "  ", "img;rm -rf /", "img$(whoami)", "img|cat"} {
		if _, err := SbomScannerGenerateSbom(context.Background(), b); err == nil ||
			(err.Error() != "Invalid image reference" && err.Error() != "Image reference contains disallowed characters") {
			t.Errorf("should reject: %q (%v)", b, err)
		}
	}
	for _, g := range []string{"nginx:latest", "ghcr.io/owner/repo:1.2.3", "image@sha256:abcd"} {
		if err := imageScannerValidRef(g); err != nil {
			t.Errorf("should accept: %q", g)
		}
	}
}
