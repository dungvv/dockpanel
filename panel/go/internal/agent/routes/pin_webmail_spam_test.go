package routes

import (
	"strings"
	"testing"
)

// tests/webmail-spam-pin-e2e.sh §3 (and mail-smtp-dkim §F): the /webmail/
// fragment re-declares the header set with framing narrowed to same-origin.
// Without it the location inherits the panel's X-Frame-Options DENY /
// frame-ancestors 'none' and Roundcube renders an empty inbox.
func TestPinWebmailSpamFragmentRedeclaresSameOriginFraming(t *testing.T) {
	b := mailWebmailNginxBlock(8888)
	for _, want := range []string{
		`add_header Content-Security-Policy "frame-ancestors 'self'" always;`,
		`add_header X-Frame-Options "SAMEORIGIN" always;`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("fragment lacks %q", want)
		}
	}
	for _, l := range strings.Split(b, "\n") {
		if strings.Contains(l, "add_header") && (strings.Contains(l, "'none'") || strings.Contains(l, "DENY")) {
			t.Errorf("fragment refuses framing: %q", l)
		}
	}
}
