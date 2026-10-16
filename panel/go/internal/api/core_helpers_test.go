package api

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ── suspend / restore ──────────────────────────────────────────────────────

func sp(s string) *string { return &s }

func TestEveryRecordedRoleComesBackAsItself(t *testing.T) {
	for _, r := range AssignableRoles {
		if got := roleToRestore(sp(r), nil); got == nil || *got != r {
			t.Fatalf("%s: un-suspending must return the recorded role, not a substitute", r)
		}
	}
}

func TestUnknownPriorRoleIsNeverGuessed(t *testing.T) {
	// ⚠ THE ARM THIS EXISTS FOR: no ordering of roles makes a guess safe.
	if roleToRestore(nil, nil) != nil || roleToRestore(sp(""), nil) != nil {
		t.Fatal("no stash must not mean a default role")
	}
}

func TestLeftoverPasswordDigestIsRefused(t *testing.T) {
	digest := strings.Repeat("deadbeef", 8)
	if len(digest) != 64 || roleToRestore(&digest, nil) != nil {
		t.Fatal("a 64-hex digest must be refused, not written into a CHECK-constrained column")
	}
	if roleToRestore(sp("suspended"), nil) != nil {
		t.Fatal("'suspended' is a status, never a role to restore")
	}
}

func TestDeniedRoleIsNotRestored(t *testing.T) {
	deny := []string{"admin", "reseller"}
	if roleToRestore(sp("admin"), deny) != nil || roleToRestore(sp("reseller"), deny) != nil {
		t.Fatal()
	}
	// The control that keeps the above from passing vacuously.
	if r := roleToRestore(sp("user"), deny); r == nil || *r != "user" {
		t.Fatal()
	}
	if r := roleToRestore(sp("client"), deny); r == nil || *r != "client" {
		t.Fatal()
	}
}

// ── agent token hashing ────────────────────────────────────────────────────

func TestHashAgentToken(t *testing.T) {
	if hashAgentToken("test-token-123") != hashAgentToken("test-token-123") || hashAgentToken("token-a") == hashAgentToken("token-b") {
		t.Fatal()
	}
	if h := hashAgentToken(""); len(h) != 64 {
		t.Fatal(h)
	}
	if hashAgentToken("hello") != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatal("SHA-256 known value")
	}
}

// ── SSRF ───────────────────────────────────────────────────────────────────

func TestValidatedHostIsTheHostAClientWouldConnectTo(t *testing.T) {
	for _, c := range []struct {
		in   string
		host string
		port uint16
	}{
		{"http://[2001:db8::1]:8443/", "[2001:db8::1]", 8443},
		{"http://example.com:8443/path", "example.com", 8443},
		{"https://198.51.100.7:9000/admin", "198.51.100.7", 9000},
		{"https://Example.COM/", "example.com", 443},
		{"http://2130706433/", "127.0.0.1", 80},
		{"http://0x7f000001/", "127.0.0.1", 80},
		{"http://0177.0.0.1/", "127.0.0.1", 80},
	} {
		h, p, err := urlAuthority(c.in)
		if err != nil || h != c.host || p != c.port {
			t.Fatalf("%s → %s %d %v", c.in, h, p, err)
		}
	}
	// The userinfo construct is REFUSED, not host-extracted.
	for _, u := range []string{"http://192.0.2.1:x@127.0.0.1/", "https://198.51.100.7:tok@10.0.0.5:8080/admin"} {
		if _, _, err := urlAuthority(u); err == nil {
			t.Fatal(u)
		}
	}
}

func TestUserinfoSpoofedInternalHostIsRejected(t *testing.T) {
	for _, u := range []string{"http://192.0.2.1:x@127.0.0.1/", "http://192.0.2.1:80@169.254.169.254/latest/meta-data/", "https://198.51.100.7:tok@10.0.0.5:8080/admin"} {
		if validateURLNotInternal(context.Background(), u) == nil {
			t.Fatal(u)
		}
	}
}

func TestAlternateEncodingsAndV6EmbeddingsAreRejected(t *testing.T) {
	for _, u := range []string{
		"http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/", "http://[::1]/",
		"http://[::ffff:169.254.169.254]/", "http://[64:ff9b::7f00:1]/", "http://[2002:7f00:1::]/",
	} {
		if validateURLNotInternal(context.Background(), u) == nil {
			t.Fatal(u)
		}
	}
}

func TestCredentialsAndBadSchemesRefused(t *testing.T) {
	for _, u := range []string{"https://user:tok@example.com/hook", "", "ftp://example.com/", "file:///etc/passwd", "not a url"} {
		if validateURLNotInternal(context.Background(), u) == nil {
			t.Fatal(u)
		}
	}
}

func TestRepoURLAuthority(t *testing.T) {
	for _, c := range []struct {
		in   string
		host string
		port uint16
	}{
		{"https://github.com/owner/repo.git", "github.com", 443},
		{"https://x-access-token:ghp_abc@github.com/owner/repo.git", "github.com", 443},
		{"ssh://git@10.0.0.1:2222/owner/repo.git", "10.0.0.1", 2222},
		{"git@github.com:owner/repo.git", "github.com", 22},
	} {
		h, p, err := repoURLAuthority(c.in)
		if err != nil || h != c.host || p != c.port {
			t.Fatalf("%s → %s %d %v", c.in, h, p, err)
		}
	}
	for _, u := range []string{"ftp://example.com/repo.git", ""} {
		if _, _, err := repoURLAuthority(u); err == nil {
			t.Fatal(u)
		}
	}
}

func TestRepoURLInternalTargetsRejected(t *testing.T) {
	ctx := context.Background()
	for _, u := range []string{"https://TOKEN@10.0.0.5/owner/repo.git", "ssh://git@169.254.169.254/owner/repo.git", "git@127.0.0.1:owner/repo.git", "git@100.64.0.1:owner/repo.git"} {
		if validateRepoURLNotInternal(ctx, u) == nil {
			t.Fatal(u)
		}
	}
	// Credentials alone must NOT refuse here (TEST-NET literal, no DNS).
	if err := validateRepoURLNotInternal(ctx, "https://x-access-token:ghp_abc@198.51.100.7/owner/repo.git"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"ftp://example.com/repo.git", "file:///etc/passwd", ""} {
		if validateRepoURLNotInternal(ctx, u) == nil {
			t.Fatal(u)
		}
	}
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestV4InternalRanges(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.169.254", "0.0.0.0", "100.64.0.1"} {
		if !v4IsInternal(ip(s)) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "100.63.255.255", "100.128.0.1"} {
		if v4IsInternal(ip(s)) {
			t.Fatal(s)
		}
	}
}

func TestV6Internal(t *testing.T) {
	for _, s := range []string{"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "fc00::1", "fd00:ec2::254", "fe80::1", "::1", "::"} {
		if !v6IsInternal(ip(s)) {
			t.Fatal(s)
		}
	}
	if v6IsInternal(ip("2606:4700:4700::1111")) || ipIsInternal(ip("2001:4860:4860::8888")) {
		t.Fatal("public v6")
	}
}

func TestValidatingResolverLiterals(t *testing.T) {
	ctx := context.Background()
	for _, h := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "localhost", "foo.localhost"} {
		if _, err := resolveAllValidated(ctx, h); err == nil {
			t.Fatalf("%s must be refused, not handed to the dialer", h)
		}
		if c, err := validatingDialContext(ctx, "tcp", net.JoinHostPort(h, "80")); err == nil {
			c.Close()
			t.Fatalf("dial %s must be refused before connecting", h)
		}
	}
	for _, h := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		a, err := resolveAllValidated(ctx, h)
		if err != nil || len(a) != 1 || a[0] != ip(h) {
			t.Fatal(h, err)
		}
	}
}

func TestPanelIPAllowlist(t *testing.T) {
	yes := [][2]string{
		{"203.0.113.4", "203.0.113.4"}, {"2001:db8::1", "2001:db8::1"}, {"2001:0db8::0001", "2001:db8::1"},
		{"10.0.0.0/8", "10.11.12.13"}, {"192.168.1.0/24", "192.168.1.255"}, {"2001:db8::/32", "2001:db8:dead:beef::1"},
		{"0.0.0.0/0", "8.8.8.8"}, {"::/0", "2001:db8::1"}, {"8.8.8.8/32", "8.8.8.8"},
		{" 203.0.113.4 , 10.0.0.0/8 ", "10.1.1.1"}, {"203.0.113.4,10.0.0.0/8", "203.0.113.4"},
	}
	no := [][2]string{
		{"203.0.113.4", "203.0.113.5"}, {"10.0.0.0/8", "11.0.0.1"}, {"192.168.1.0/24", "192.168.2.1"}, {"2001:db8::/32", "2001:db9::1"},
		{"8.8.8.8/32", "8.8.8.9"}, {"8.8.8.8/33", "8.8.8.8"}, {"2001:db8::/129", "2001:db8::1"},
		{"0.0.0.0/0", "2001:db8::1"}, {"::/0", "8.8.8.8"}, {"203.0.113.4,10.0.0.0/8", "8.8.8.8"}, {",,", "8.8.8.8"},
		{"10.0.0.0/8", ""}, {"10.0.0.0/8", "not-an-ip"}, {"0.0.0.0/0", ""}, {"not-an-ip", "8.8.8.8"}, {"10.0.0.0/abc", "10.0.0.1"},
	}
	for _, c := range yes {
		if !panelIPAllowed(c[0], c[1]) {
			t.Fatal(c)
		}
	}
	for _, c := range no {
		if panelIPAllowed(c[0], c[1]) {
			t.Fatal(c)
		}
	}
	for _, g := range []string{"203.0.113.4", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32", "0.0.0.0/0"} {
		if !validPanelIPEntry(g) {
			t.Fatal(g)
		}
	}
	for _, b := range []string{"", "not-an-ip", "10.0.0.0/33", "2001:db8::/129", "10.0.0.0/", "10.0.0.0/-1"} {
		if validPanelIPEntry(b) {
			t.Fatal(b)
		}
	}
}

// ── certificates ───────────────────────────────────────────────────────────

func jv(s string) any {
	var v any
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

func TestFullLetsEncryptRDNIsOurs(t *testing.T) {
	for _, iss := range []string{"CN=YR2, O=Let's Encrypt, C=US", "CN=R3, O=Let's Encrypt, C=US", "CN=R11, O=LET'S ENCRYPT, C=US", "CN=R10, O=Lets Encrypt, C=US"} {
		if p := certProvenance(map[string]any{"has_cert": true, "issuer": iss}); p.Kind != CertDockPanelIssued {
			t.Fatal(iss)
		}
	}
}

func TestBareCommonNameDoesNotProveLetsEncrypt(t *testing.T) {
	if p := certProvenance(jv(`{"has_cert":true,"issuer":"YR2"}`)); p != (CertProvenance{Kind: CertForeign, Issuer: "YR2"}) {
		t.Fatal(p)
	}
}

func TestEveryOtherCAIsForeign(t *testing.T) {
	for _, iss := range []string{"CN=ZeroSSL RSA Domain Secure Site CA, O=ZeroSSL, C=AT", "CN=Cloudflare Origin Certificate, O=CloudFlare, Inc., C=US",
		"CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US", "CN=Acme Corp Internal Issuing CA, O=Acme Corp"} {
		if p := certProvenance(map[string]any{"has_cert": true, "issuer": iss}); p != (CertProvenance{Kind: CertForeign, Issuer: iss}) {
			t.Fatal(iss)
		}
	}
}

func TestNoAnswerIsUnknown(t *testing.T) {
	for _, s := range []string{`{"has_cert":false}`, `{"has_cert":true}`, `{"has_cert":true,"issuer":"   "}`, `null`} {
		if p := certProvenance(jv(s)); p.Kind != CertUnknown {
			t.Fatal(s)
		}
	}
}

func TestRenewalCollapseTreatsUnknownAsPermission(t *testing.T) {
	asRenewal := func(v any) *string {
		if p := certProvenance(v); p.Kind == CertForeign {
			return &p.Issuer
		}
		return nil
	}
	if asRenewal(jv(`{"has_cert":false}`)) != nil || asRenewal(jv(`{"has_cert":true,"issuer":"CN=YR2, O=Let's Encrypt, C=US"}`)) != nil {
		t.Fatal()
	}
	if r := asRenewal(jv(`{"has_cert":true,"issuer":"CN=Cloudflare Origin Certificate, O=CloudFlare, Inc., C=US"}`)); r == nil {
		t.Fatal()
	}
}

func TestParseAgentCertExpiry(t *testing.T) {
	// THE regression: time::OffsetDateTime's Display, what the agent sends.
	got := parseAgentCertExpiry("2026-10-23 09:41:07.0 +00:00:00")
	if got == nil || !got.Equal(time.Date(2026, 10, 23, 9, 41, 7, 0, time.UTC)) {
		t.Fatal(got)
	}
	if parseAgentCertExpiry("2026-10-23 09:41:07 +00:00:00") == nil {
		t.Fatal("without fraction")
	}
	if g := parseAgentCertExpiry("2026-10-23 11:41:07.0 +02:00:00"); g == nil || g.Hour() != 9 || g.Location() != time.UTC {
		t.Fatal("must be converted to UTC, not read as wall time")
	}
	for _, s := range []string{"2026-10-23 09:41:07.0 UTC", "2026-10-23T09:41:07Z"} {
		if parseAgentCertExpiry(s) == nil {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"", "   ", "not a date", "2026-10-23"} {
		if parseAgentCertExpiry(s) != nil {
			t.Fatal(s)
		}
	}
}

func TestDNS01LastResortRungSitsBelowShortlivedMargin(t *testing.T) {
	if dns01LastResortDays(sp("shortlived")) != 1 || dns01LastResortDays(nil) != DNS01LastResortDays || dns01LastResortDays(sp("classic")) != 7 {
		t.Fatal()
	}
}

func TestRenewalPlanWithoutDB(t *testing.T) {
	// Branches decided before any query.
	if p := renewalPlan(context.Background(), nil, &Site{}, nil); p.Kind != RenewHTTP01 || !p.RecordChallenge {
		t.Fatal(p)
	}
	if p := renewalPlan(context.Background(), nil, &Site{SSLChallenge: sp("http-01")}, nil); p.Kind != RenewHTTP01 || p.RecordChallenge {
		t.Fatal(p)
	}
}

// ── provisioning logs ──────────────────────────────────────────────────────

func TestProvisionLogs(t *testing.T) {
	p := NewProvisionLogs()
	id, owner, stranger := uuid.New(), uuid.New(), uuid.New()
	p.Register(id, owner, 8)
	if _, _, _, err := p.Open(id, owner, "gone"); err != nil {
		t.Fatal("owner can read its own log")
	}
	if _, _, _, err := p.Open(id, stranger, "gone"); err == nil {
		t.Fatal("a stranger cannot read someone else's log")
	}
	// Absent and forbidden are indistinguishable — status AND body.
	forbidden := func() error { _, _, _, e := p.Open(id, stranger, "gone"); return e }()
	absent := func() error { _, _, _, e := p.Open(uuid.New(), stranger, "gone"); return e }()
	if forbidden.Error() != absent.Error() {
		t.Fatal(forbidden, absent)
	}

	// A step emitted through the map reaches an attached reader.
	_, ch, unsub, _ := p.Open(id, owner, "gone")
	defer unsub()
	p.Emit(id, ProvisionStep{Step: "s", Label: "l", Status: "done"})
	if got := <-ch; got.Step != "s" {
		t.Fatal(got)
	}
	// Removing the entry closes the reader, or the SSE stream hangs.
	p.Remove(id)
	if _, open := <-ch; open {
		t.Fatal("dropping the entry must close the receiver")
	}
	if p.Emit(id, ProvisionStep{}) {
		t.Fatal("emit after removal goes nowhere")
	}
}

func TestOwnerlessLogIsRefused(t *testing.T) {
	p := NewProvisionLogs()
	id := uuid.New()
	p.logs[id] = &provisionLog{tx: NewBroadcast[ProvisionStep](8), created: time.Now()}
	if _, _, _, err := p.Open(id, uuid.New(), "gone"); err == nil {
		t.Fatal("a log with no recorded owner must not be readable")
	}
}

func TestProvisionSweepPrunesOwnersEveryTick(t *testing.T) {
	p := NewProvisionLogs()
	a, b := uuid.New(), uuid.New()
	p.Register(a, uuid.New(), 1)
	p.Register(b, uuid.New(), 1)
	p.Remove(b) // the feature's own terminal removal leaves the owner row
	p.sweep(time.Now(), time.Hour)
	if _, ok := p.owners[b]; ok {
		t.Fatal("owner of a removed log must be pruned even when the TTL evicted nothing")
	}
	p.sweep(time.Now().Add(2*time.Hour), time.Hour)
	if len(p.logs) != 0 || len(p.owners) != 0 {
		t.Fatal("TTL eviction")
	}
}

func TestJSONAccessors(t *testing.T) {
	v, _ := agentDecodeJSON([]byte(`{"a":{"b":[1,2.5,"x",true,9007199254740993]}}`))
	if n, ok := jsonI64(jsonGet(v, "a", "b", 0)); !ok || n != 1 {
		t.Fatal()
	}
	if _, ok := jsonI64(jsonGet(v, "a", "b", 1)); ok {
		t.Fatal("as_i64 of a float is None")
	}
	if f, _ := jsonF64(jsonGet(v, "a", "b", 1)); f != 2.5 {
		t.Fatal()
	}
	if s, _ := jsonStr(jsonGet(v, "a", "b", 2)); s != "x" {
		t.Fatal()
	}
	if n, _ := jsonI64(jsonGet(v, "a", "b", 4)); n != 9007199254740993 {
		t.Fatal("large integers must not lose precision")
	}
	if jsonGet(v, "a", "zz", 0) != nil || jsonGet(v, "a", "b", 9) != nil {
		t.Fatal()
	}
}

func TestCFHeaders(t *testing.T) {
	if h := cfHeaders("tok", nil); h.Get("Authorization") != "Bearer tok" {
		t.Fatal(h)
	}
	h := cfHeaders("key", sp("me@example.com"))
	if h.Get("X-Auth-Email") != "me@example.com" || h.Get("X-Auth-Key") != "key" || h.Get("Authorization") != "" {
		t.Fatal(h)
	}
	if !slices.Equal(cfHeaders("a\nb", nil).Values("Authorization"), nil) {
		t.Fatal("an invalid header value is dropped")
	}
}
