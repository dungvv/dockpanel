package api

import "testing"

// backend-hot-file-audit §A: a Cloudflare record id is exactly 32 hex chars;
// anything path-shaped (the "../../../zones/OTHER/dns_records/RECID" reroute)
// or off-length is refused before it reaches the outbound CF URL.
func TestPinBackendHotFileAuditCfRecordID(t *testing.T) {
	if !rtDnsIsHex32("0123456789abcdef0123456789ABCDEF") {
		t.Error("a 32-char hex id must be accepted")
	}
	for _, bad := range []string{
		"",
		"0123456789abcdef0123456789abcde",   // 31
		"0123456789abcdef0123456789abcdef0", // 33
		"../../../zones/OTHER/dns_records/x",
		"..%2F..%2Fzones%2Fabcdef0123456789",
		"0123456789abcdef0123456789abcdeg",
	} {
		if rtDnsIsHex32(bad) {
			t.Errorf("rtDnsIsHex32(%q) = true, want false", bad)
		}
	}
}

// §B: the compliance report escapes every HTML-significant character in
// scan-derived text (file paths from hosted sites) before interpolation.
func TestPinBackendHotFileAuditHTMLEscape(t *testing.T) {
	got := rtSecurityHTMLEscape(`/var/www/<img src=x onerror="alert('x')">&`)
	want := `/var/www/&lt;img src=x onerror=&quot;alert(&#39;x&#39;)&quot;&gt;&amp;`
	if got != want {
		t.Errorf("rtSecurityHTMLEscape = %q, want %q", got, want)
	}
}
