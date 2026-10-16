package api

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func imageScansResult(c, h, m uint32) *rtImageScansImageScanResult {
	return &rtImageScansImageScanResult{Image: "x", Scanner: "grype", CriticalCount: c, HighCount: h, MediumCount: m, ScannedAt: "now"}
}

func TestImageScansGateThresholds(t *testing.T) {
	clean, med, high, crit := imageScansResult(0, 0, 0), imageScansResult(0, 0, 1), imageScansResult(0, 1, 0), imageScansResult(1, 0, 0)
	cases := []struct {
		gate string
		r    *rtImageScansImageScanResult
		want bool
	}{
		{"none", crit, false},
		{"critical", crit, true},
		{"critical", high, false},
		{"high", high, true},
		{"high", crit, true},
		{"high", med, false},
		{"medium", med, true},
		{"medium", clean, false},
	}
	for _, c := range cases {
		if got := rtImageScansExceedsThreshold(c.gate, c.r); got != c.want {
			t.Errorf("gate %s: got %v", c.gate, got)
		}
	}
}

func TestImageScansValidatesGate(t *testing.T) {
	for _, g := range []string{"none", "critical", "high", "medium"} {
		if !rtImageScansValidGate(g) {
			t.Errorf("rejected %q", g)
		}
	}
	for _, g := range []string{"low", "", "bogus"} {
		if rtImageScansValidGate(g) {
			t.Errorf("accepted %q", g)
		}
	}
}

func TestImageScansStateKeyUnchangedForShortImages(t *testing.T) {
	if got := rtImageScansStateKey("nginx:1.27"); got != "image:nginx:1.27" {
		t.Fatal(got)
	}
}

func TestImageScansStateKeyFitsTheColumnForADigestPinnedReference(t *testing.T) {
	// The shape that overflowed alerts.state_key VARCHAR(100).
	image := "registry.example.com/org/long-project-name/service@sha256:" + strings.Repeat("a", 64)
	if len(image) <= 100 {
		t.Fatal("fixture must exceed the column")
	}
	key := rtImageScansStateKey(image)
	if len(key) > 100 || !strings.HasPrefix(key, "image:") {
		t.Fatalf("%d chars: %s", len(key), key)
	}
}

func TestImageScansStateKeyDoesNotCollideForLongImagesSharingAPrefix(t *testing.T) {
	base := "registry.example.com/org/long-project-name/service@sha256:"
	if rtImageScansStateKey(base+strings.Repeat("a", 64)) == rtImageScansStateKey(base+strings.Repeat("b", 64)) {
		t.Fatal("collided")
	}
}

func TestImageScansStateKeyTruncatesByCharNotByte(t *testing.T) {
	// A multi-byte character at the boundary must not be split; VARCHAR(100)
	// counts characters, so the bound is on runes.
	key := rtImageScansStateKey("registry.example.com/" + strings.Repeat("☃", 60))
	if !strings.HasPrefix(key, "image:") || len([]rune(key)) > 100 || !utf8.ValidString(key) {
		t.Fatal(key)
	}
}
