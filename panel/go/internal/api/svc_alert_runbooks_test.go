package api

import (
	"strings"
	"testing"
)

func TestAlertRunbooksExcerptShortStringReturnsUnchanged(t *testing.T) {
	if got := AlertRunbooksExcerpt("Short blurb.", 280); got != "Short blurb." {
		t.Fatalf("got %q", got)
	}
}

func TestAlertRunbooksExcerptTruncatesAtSentenceBoundary(t *testing.T) {
	s := "First sentence. Second sentence is much longer and should be cut off because we want a short preview."
	out := AlertRunbooksExcerpt(s, 50)
	if !strings.HasSuffix(out, "…") || !strings.HasPrefix(out, "First sentence.") {
		t.Fatalf("got %q", out)
	}
}

func TestAlertRunbooksExcerptStripsMarkdownHeadings(t *testing.T) {
	out := AlertRunbooksExcerpt("# Title\n\nProse line one. Prose line two.", 280)
	if strings.Contains(out, "#") || !strings.Contains(out, "Prose line one") {
		t.Fatalf("got %q", out)
	}
}
