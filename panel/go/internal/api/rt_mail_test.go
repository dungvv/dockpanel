package api

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// ⚠ THE ARM THIS MODULE EXISTS FOR. Both of these were ACCEPTED before, and
// each produced a concrete, measured effect: `@d` voided the domain's
// catch-all (same virtual_mailbox_maps key), and `..@d` put the maildir one
// level ABOVE the domain directory. If this test ever goes green on those
// inputs again, both are back.
func TestMailTheDegenerateLocalPartsAreRefused(t *testing.T) {
	for _, a := range []string{"@example.com", ".@example.com", "..@example.com", "...@example.com"} {
		if rtMailIsWellformedAddress(a, "") {
			t.Errorf("%q must be refused: an empty or all-dots local part is a path component and a map key, not a mailbox", a)
		}
		// The control that gives the assertion above its meaning: the OLD
		// check passes every one of them.
		if !rtMailIsValidMailAddress(a, "") {
			t.Errorf("%q must still satisfy the character-set check", a)
		}
	}
}

// The other half: refusing the degenerate forms must not refuse real mail.
func TestMailOrdinaryAddressesAreStillAccepted(t *testing.T) {
	for _, a := range []string{"user@example.com", "first.last@example.com", "user+tag@example.com",
		"u@example.com", "under_score-dash@sub.example.co.uk", "0@1.com",
		// Dots beside other characters are fine — only NOTHING but dots is a path problem.
		"a..b@example.com", ".leading@example.com", "trailing.@example.com"} {
		if !rtMailIsWellformedAddress(a, "") {
			t.Errorf("%q must still be accepted", a)
		}
	}
}

func TestMailTheStructuralRulesHold(t *testing.T) {
	// No '@' at all, more than one '@', empty domain.
	for _, a := range []string{"nobody", "a@b.com@c.com", "user@", "@", ""} {
		if rtMailIsWellformedAddress(a, "") {
			t.Errorf("%q must be refused", a)
		}
	}
	// The character set is still enforced through this door...
	if rtMailIsWellformedAddress("usér@example.com", "") || rtMailIsWellformedAddress("a/b@example.com", "") {
		t.Error("character set not enforced")
	}
	// ...unless the caller allows the character, as the catch-all door does.
	if !rtMailIsWellformedAddress("a/b@example.com", "/") {
		t.Error("extra_allowed ignored")
	}
}

// A list is checked ELEMENT BY ELEMENT.
func TestMailEveryElementOfADestinationListMustBeAnAddress(t *testing.T) {
	for _, ok := range []string{"a@b.com", "a@b.com,c@d.com", " a@b.com , c@d.com "} {
		if !rtMailIsWellformedAddressList(ok, "") {
			t.Errorf("%q must be accepted", ok)
		}
	}
	// Both orders — the old check accepted each, because it only asked whether
	// an '@' appeared SOMEWHERE in the string.
	for _, bad := range []string{"root,a@b.com", "a@b.com,root", "a@b.com,@b.com", "", ","} {
		if rtMailIsWellformedAddressList(bad, "") {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestMailDovecotHashIsArgon2idSchemeAndVerifies(t *testing.T) {
	pw := "correct horse battery staple"
	stored, err := rtMailDovecotPasswordHash(pw)
	if err != nil {
		t.Fatal(err)
	}
	// Dovecot scheme label + PHC string (exactly what gets written to the dovecot users file).
	if !strings.HasPrefix(stored, "{ARGON2ID}$argon2id$") {
		t.Fatalf("expected an {ARGON2ID} PHC credential, got: %s", stored)
	}
	phc := strings.TrimPrefix(stored, "{ARGON2ID}")
	if ok, err := verifyPassword(pw, phc); err != nil || !ok {
		t.Fatalf("correct password must verify: %v %v", ok, err)
	}
	if ok, _ := verifyPassword("wrong password", phc); ok {
		t.Fatal("wrong password must be rejected")
	}
}

func TestMailDovecotHashUsesARandomSalt(t *testing.T) {
	a, _ := rtMailDovecotPasswordHash("same-password")
	b, _ := rtMailDovecotPasswordHash("same-password")
	if a == b {
		t.Fatal("each hash must use a fresh random salt")
	}
}

// Not in the Rust suite as a unit test, but the scheme choice is the Rocky fix
// (s268) and cheap to pin: no ARGON2ID → BLF-CRYPT; unknown → strong default.
func TestMailDovecotSchemeFollowsTheAgent(t *testing.T) {
	h, _ := rtMailDovecotPasswordHashFor("pw-123456", []string{"BLF-CRYPT", "SHA512-CRYPT"})
	if !strings.HasPrefix(h, "{BLF-CRYPT}$2") || !bcryptVerify("pw-123456", strings.TrimPrefix(h, "{BLF-CRYPT}")) {
		t.Fatal(h)
	}
	for _, s := range [][]string{nil, {"argon2id"}} {
		if h, _ := rtMailDovecotPasswordHashFor("pw-123456", s); !strings.HasPrefix(h, "{ARGON2ID}") {
			t.Fatal(s, h)
		}
	}
}

func TestMailCertVerdict(t *testing.T) {
	tr, fa := true, false
	cases := []struct {
		name      string
		enabled   bool
		wildcard  *bool
		challenge *string
		issuer    *string
		blocker   rtMailMailCertBlocker
		refuse    bool
	}{
		// The ordinary shape the mail entitlement is BUILT on: refusing it would
		// break the documented order rather than protect anything.
		{"ordinary same-name site still gets its certificate", true, &fa, new("http-01"), nil, 0, false},
		// The case that leads the harm, and the one the issuer probe is blind to.
		{"a wildcard is refused even though the issuer looks like ours", true, &tr, new("dns-01"), nil, rtMailMailCertBlockerWildcard, true},
		// ssl_wildcard is three-state on purpose.
		{"dns-01 alone refuses when the wildcard flag was never recorded", true, nil, new("dns-01"), nil, rtMailMailCertBlockerWildcard, true},
		// The case the columns are blind to.
		{"a foreign certificate is refused on the issuer alone", true, &fa, new("http-01"), new("DigiCert Inc"), rtMailMailCertBlockerForeign, true},
		// Neither input alone is sufficient — the pair that proves it.
		{"wildcard caught only by the columns", true, &tr, nil, nil, rtMailMailCertBlockerWildcard, true},
		{"foreign caught only by the issuer", true, nil, nil, new("Let's Encrypt"), rtMailMailCertBlockerForeign, true},
		// A site not serving TLS has nothing here to lose.
		{"a site not serving TLS does not block the mail host", false, &tr, new("dns-01"), new("DigiCert Inc"), 0, false},
	}
	for _, c := range cases {
		b, refuse := rtMailMailCertVerdict(c.enabled, c.wildcard, c.challenge, c.issuer)
		if refuse != c.refuse || (refuse && b != c.blocker) {
			t.Errorf("%s: got (%v, %v)", c.name, b, refuse)
		}
	}
}

func TestMailDnsblAnswerReadsTheAnswer(t *testing.T) {
	if rtMailDnsblAnswer(nil) != 0 {
		t.Error("no A record is not listed")
	}
	if rtMailDnsblAnswer([]net.IP{net.IPv4(127, 0, 0, 2)}) != 1 {
		t.Error("127.0.0.2 is a listing")
	}
	// RFC 5782 refusal range is an A record — and must not read as a listing.
	if rtMailDnsblAnswer([]net.IP{net.IPv4(127, 255, 255, 254)}) != -1 {
		t.Error("127.255.255.x is a refusal")
	}
}

// TestDBNetQueriesRunAgainstTheSchema runs the hand-ported SQL of the net group
// (mail, tls_certificates, dns, cdn, ssl) against a migrated database: every
// struct scan, every caller-predicate bind and every ownership refusal.
func TestDBNetQueriesRunAgainstTheSchema(t *testing.T) {
	pool := scratchDB(t)
	ctx := context.Background()
	migs, _ := EmbeddedMigrations()
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal(err)
	}
	admin, err := queryScalar[uuid.UUID](ctx, pool, "INSERT INTO users (email, password_hash, role) VALUES ('ad@b.c', 'h', 'admin') RETURNING id")
	if err != nil {
		t.Fatal(err)
	}
	stranger, _ := queryScalar[uuid.UUID](ctx, pool, "INSERT INTO users (email, password_hash, role) VALUES ('u@b.c', 'h', 'user') RETURNING id")
	serverID, err := AgentEnsureLocalServer(ctx, pool, "agent-token", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	st := NewAppState(pool, &Config{JWTSecret: testSecret}, NewAgentClient("/x", "agent-token"), nil, ctx)
	st.Agents = NewAgentRegistry(st.Agent, pool, testSecret)
	st.Agents.SetLocalServerID(serverID)
	adm, usr := &Claims{Sub: admin, Role: "admin"}, &Claims{Sub: stranger, Role: "user"}

	// ── mail ──
	md, err := queryOne[rtMailMailDomain](ctx, pool,
		"INSERT INTO mail_domains (domain, dkim_private_key, dkim_public_key, server_id) "+
			"VALUES ($1, $2, $3, $4) RETURNING id, domain, dkim_selector, dkim_public_key, catch_all, enabled, created_at",
		"example.com", nil, nil, serverID)
	if err != nil {
		t.Fatal(err)
	}
	if d, sel, _, sid, err := rtMailMailDomainIdentity(ctx, pool, md.ID, adm); err != nil || d != "example.com" || sel == "" || sid == nil || *sid != serverID {
		t.Fatal(d, sel, sid, err)
	}
	if _, _, _, _, err := rtMailMailDomainIdentity(ctx, pool, md.ID, usr); err == nil {
		t.Fatal("a stranger must not see the domain")
	}
	if d, sid, _, err := rtMailMailDomainAgentForCaller(ctx, st, md.ID, adm); err != nil || d != "example.com" || sid != serverID {
		t.Fatal(d, sid, err)
	}
	acc, err := queryOne[rtMailMailAccount](ctx, pool,
		"INSERT INTO mail_accounts (domain_id, email, password_hash, display_name, quota_mb) "+
			"VALUES ($1, $2, $3, $4, $5) "+
			"RETURNING id, domain_id, email, display_name, quota_mb, enabled, forward_to, "+
			"autoresponder_enabled, autoresponder_subject, autoresponder_body, created_at",
		md.ID, "a@example.com", "{ARGON2ID}x", nil, int32(1024))
	if err != nil {
		t.Fatal(err)
	}
	if e, _, _, err := rtMailMailAccountAgentForCaller(ctx, st, md.ID, acc.ID, adm); err != nil || e != "a@example.com" {
		t.Fatal(e, err)
	}
	if _, _, _, err := rtMailMailAccountAgentForCaller(ctx, st, uuid.New(), acc.ID, adm); err == nil {
		t.Fatal("a mismatched (domain, account) pair must 404")
	}
	al, err := queryOne[rtMailMailAlias](ctx, pool, "INSERT INTO mail_aliases (domain_id, source_email, destination_email) "+
		"VALUES ($1, $2, $3) RETURNING *", md.ID, "x@example.com", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if s, _, _, err := rtMailMailAliasAgentForCaller(ctx, st, md.ID, al.ID, adm); err != nil || s != "x@example.com" {
		t.Fatal(s, err)
	}
	p, err := rtMailMailSyncPayload(ctx, pool, serverID)
	if err != nil || len(p["domains"].([]any)) != 1 || len(p["accounts"].([]any)) != 1 || len(p["aliases"].([]any)) != 1 {
		t.Fatal(p, err)
	}

	// ── tls_certificates ──
	row, err := queryOne[rtTlsCertificatesTlsCertificate](ctx, pool,
		"INSERT INTO tls_certificates (user_id, server_id, alias, dns_names, issuer, not_before, "+
			"not_after, fingerprint_sha256, cert_path, key_path) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) "+
			"RETURNING id, user_id, server_id, alias, dns_names, issuer, not_before, not_after, "+
			"fingerprint_sha256, cert_path, key_path, created_at, updated_at",
		admin, serverID, "corp", []string{}, nil, nil, nil, nil, "/c", "/k")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rtTlsCertificatesOwnedCertificate(ctx, pool, row.ID, stranger); err == nil {
		t.Fatal("not the owner")
	}
	if id, err := rtTlsCertificatesCertificateIdForAlias(ctx, pool, "corp", admin, serverID); err != nil || id != row.ID {
		t.Fatal(id, err)
	}
	if refs, err := rtTlsCertificatesReferencingStacks(ctx, pool, row.ID); err != nil || len(refs) != 0 {
		t.Fatal(refs, err)
	}

	// ── dns / cdn ──
	z, err := queryOne[rtDnsDnsZone](ctx, pool,
		"INSERT INTO dns_zones (user_id, domain, provider, cf_zone_id, cf_api_token, cf_api_email) "+
			"VALUES ($1, $2, 'cloudflare', $3, $4, $5) RETURNING *", admin, "example.com", "0123456789abcdef0123456789abcdef", "enc", nil)
	if err != nil || z.Provider != "cloudflare" {
		t.Fatal(z, err)
	}
	if _, err := queryOne[rtCdnCdnZone](ctx, pool,
		"INSERT INTO cdn_zones (user_id, domain, provider, api_key, pull_zone_id, origin_url, cdn_hostname) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *", admin, "example.com", "bunnycdn", "enc", nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	// ── ssl: the contact rescue reads the panel-wide setting ──
	if _, err := rtSslResolveAcmeContact(ctx, pool, "admin@dockpanel.test"); err == nil {
		t.Fatal("reserved TLD with no rescue must refuse")
	}
	_, _ = execSQL(ctx, pool, "INSERT INTO settings (key, value) VALUES ('acme_contact_email', $1) "+
		"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()", " ops@example.com ")
	if got, err := rtSslResolveAcmeContact(ctx, pool, "admin@dockpanel.test"); err != nil || got != "ops@example.com" {
		t.Fatal(got, err)
	}
	if p := rtSslResolveProfile(ctx, pool, nil); p != nil {
		t.Fatal(*p)
	}
}
