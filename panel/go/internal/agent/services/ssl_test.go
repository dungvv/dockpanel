package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type sslFixtureOpts struct {
	sans []string
	cn   string
	isCA bool
}

// sslSelfSigned returns (cert PEM, key PEM) for a self-signed leaf.
func sslSelfSigned(t *testing.T, o sslFixtureOpts) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: o.cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     o.sans,
	}
	if o.isCA {
		tpl.IsCA, tpl.BasicConstraintsValid = true, true
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
}

func sslSans(t *testing.T, sans ...string) string {
	c, _ := sslSelfSigned(t, sslFixtureOpts{sans: sans})
	return c
}

// ── certificate coverage ────────────────────────────────────────────────

func TestAnExactNameIsAcceptedCaseAndTrailingDotInsensitively(t *testing.T) {
	p := sslSans(t, "Shop.Example.com")
	for _, d := range []string{"shop.example.com", "SHOP.EXAMPLE.COM."} {
		if _, err := SslCertCoversDomain(p, d); err != nil {
			t.Error(d, err)
		}
	}
}

func TestACertificateForAnotherSiteIsRefusedAndNamesWhatItCovers(t *testing.T) {
	_, err := SslCertCoversDomain(sslSans(t, "www.example.com", "example.com"), "shop.example.com")
	if err == nil || !strings.Contains(err.Error(), "www.example.com") || !strings.Contains(err.Error(), "shop.example.com") {
		t.Fatal(err)
	}
}

func TestAWildcardCoversExactlyOneLabel(t *testing.T) {
	p := sslSans(t, "*.example.com", "example.com")
	if _, err := SslCertCoversDomain(p, "app.example.com"); err != nil {
		t.Error(err)
	}
	if _, err := SslCertCoversDomain(p, "example.com"); err != nil {
		t.Error(err)
	}
	if _, err := SslCertCoversDomain(p, "app.staging.example.com"); err == nil {
		t.Error("two labels below must not be covered")
	}
	if _, err := SslCertCoversDomain(sslSans(t, "*.example.com"), "example.com"); err == nil {
		t.Error("bare wildcard covered the apex")
	}
	if sslDNSNameCovers("w*.example.com", "www.example.com") || sslDNSNameCovers("*.com", "example.com") {
		t.Error("partial / TLD wildcard accepted")
	}
}

func TestTheCommonNameIsAFallbackOnlyWhenNoSanIsPresent(t *testing.T) {
	cnOnly, _ := sslSelfSigned(t, sslFixtureOpts{cn: "legacy.example.com"})
	if _, err := SslCertCoversDomain(cnOnly, "legacy.example.com"); err != nil {
		t.Error(err)
	}
	if _, err := SslCertCoversDomain(cnOnly, "other.example.com"); err == nil {
		t.Error("other accepted")
	}
	both, _ := sslSelfSigned(t, sslFixtureOpts{sans: []string{"real.example.com"}, cn: "cn.example.com"})
	if _, err := SslCertCoversDomain(both, "real.example.com"); err != nil {
		t.Error(err)
	}
	if _, err := SslCertCoversDomain(both, "cn.example.com"); err == nil {
		t.Error("CN honoured despite SAN")
	}
}

// `openssl req -x509` stamps CA:TRUE — set BY HAND here, as in the Rust suite.
func TestASelfSignedCertificateMarkedCaIsStillAccepted(t *testing.T) {
	c, _ := sslSelfSigned(t, sslFixtureOpts{sans: []string{"staging.example.com"}, isCA: true})
	if _, err := SslCertCoversDomain(c, "staging.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyTheFirstCertificateBlockIsAsked(t *testing.T) {
	wrong, right := sslSans(t, "wrong.example.com"), sslSans(t, "right.example.com")
	if _, err := SslCertCoversDomain(wrong+right, "right.example.com"); err == nil {
		t.Error("[wrong, right] accepted")
	}
	if _, err := SslCertCoversDomain(right+wrong, "right.example.com"); err != nil {
		t.Error(err)
	}
}

func TestAPrivateKeyInTheCertificateFieldIsRefused(t *testing.T) {
	c, k := sslSelfSigned(t, sslFixtureOpts{sans: []string{"shop.example.com"}})
	_, err := SslCertCoversDomain(k+c, "shop.example.com")
	if err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatal(err)
	}
}

func TestUnreadableInputIsRefusedRatherThanInstalled(t *testing.T) {
	for _, in := range []string{"not a certificate at all", "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"} {
		if _, err := SslCertCoversDomain(in, "shop.example.com"); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

// ── ACME account persistence ────────────────────────────────────────────

func TestExactlyOneOfManyConcurrentWritersWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dir", "acme-account.json")
	var mu sync.Mutex
	var written []int
	adopted := 0
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out, err := sslPersistAccountCredentials(path, fmt.Sprintf(`{"account":%d}`, i))
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if out == sslWritten {
				written = append(written, i)
			} else {
				adopted++
			}
		}(i)
	}
	wg.Wait()
	if len(written) != 1 || adopted != 11 {
		t.Fatalf("written=%v adopted=%d", written, adopted)
	}
	if b, _ := os.ReadFile(path); string(b) != fmt.Sprintf(`{"account":%d}`, written[0]) {
		t.Fatalf("file holds %s", b)
	}
}

func TestAnExistingAccountIsAdoptedNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme-account.json")
	if o, _ := sslPersistAccountCredentials(path, `{"account":"first"}`); o != sslWritten {
		t.Fatal()
	}
	if o, _ := sslPersistAccountCredentials(path, `{"account":"second"}`); o != sslAdopted {
		t.Fatal()
	}
	if b, _ := os.ReadFile(path); string(b) != `{"account":"first"}` {
		t.Fatal(string(b))
	}
}

func TestTheAccountFileIsOwnerOnlyFromCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme-account.json")
	sslPersistAccountCredentials(path, "{}")
	fi, _ := os.Stat(path)
	if m := fi.Mode().Perm(); m != 0o600 {
		t.Fatalf("got %o", m)
	}
}

// The on-disk format must stay instant-acme's so either agent reads the
// other's account.
func TestCredentialsJsonMatchesInstantAcme(t *testing.T) {
	dir := "https://acme-v02.api.letsencrypt.org/directory"
	js, _ := json.MarshalIndent(sslAccountCredentials{ID: "https://ca/acct/1", KeyPkcs8: "AAA", Directory: &dir}, "", "  ")
	want := "{\n  \"id\": \"https://ca/acct/1\",\n  \"key_pkcs8\": \"AAA\",\n  \"directory\": \"https://acme-v02.api.letsencrypt.org/directory\"\n}"
	if string(js) != want {
		t.Fatalf("got\n%s", js)
	}
	if d, ok := sslLegacyDirectory(json.RawMessage(`{"newOrder":"https://acme-v02.api.letsencrypt.org/acme/new-order"}`)); !ok || d != dir {
		t.Fatal(d)
	}
}

// ── registered certificates ─────────────────────────────────────────────

func TestTheAliasGrammarIsADnsLabel(t *testing.T) {
	for _, good := range []string{"a", "wildcard-2026", "0", strings.Repeat("x", 64)} {
		if !SslIsValidCertAlias(good) {
			t.Errorf("%q refused", good)
		}
	}
	for _, bad := range []string{"", "-lead", "trail-", "Upper", "dot.inside", "under_score", "../etc", "sp ace", strings.Repeat("x", 65)} {
		if SslIsValidCertAlias(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	c, k := SslRegistryPaths("wildcard-2026")
	if !strings.HasPrefix(c, SslRegistryDir) || !strings.HasSuffix(c, "/fullchain.pem") || !strings.HasSuffix(k, "/privkey.pem") ||
		strings.HasPrefix(SslRegistryDir, "/etc/dockpanel/ssl/") || !nginxIsSafePath(c) {
		t.Fatal(c, k)
	}
}

func TestMetadataDescribesTheLeaf(t *testing.T) {
	c := sslSans(t, "Shop.Example.com", "*.example.com")
	m, err := SslCertMetadataOf(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.DNSNames, ",") != "shop.example.com,*.example.com" || !m.NotBefore.Before(m.NotAfter) ||
		len(m.FingerprintSha256) != 64 || strings.ToLower(m.FingerprintSha256) != m.FingerprintSha256 {
		t.Fatalf("%+v", m)
	}
	o, _ := SslCertMetadataOf(sslSans(t, "shop.example.com"))
	if o.FingerprintSha256 == m.FingerprintSha256 {
		t.Fatal("fingerprints collide")
	}
}

func TestMetadataRefusesAKeyWhereACertificateBelongs(t *testing.T) {
	c, k := sslSelfSigned(t, sslFixtureOpts{sans: []string{"a.example.com"}})
	if _, err := SslCertMetadataOf(k + c); err == nil || !strings.Contains(err.Error(), "private key block") {
		t.Fatal(err)
	}
	for _, in := range []string{"", "not pem at all"} {
		if _, err := SslCertMetadataOf(in); err == nil || !strings.Contains(err.Error(), "no certificate was found") {
			t.Fatal(err)
		}
	}
}

func TestAGeneratedPairMatchesAndASecondKeyDoesNot(t *testing.T) {
	c, k := sslSelfSigned(t, sslFixtureOpts{sans: []string{"a.example.com"}})
	if err := SslKeyMatchesCert(c, k); err != nil {
		t.Fatal(err)
	}
	_, stranger := sslSelfSigned(t, sslFixtureOpts{sans: []string{"a.example.com"}})
	if err := SslKeyMatchesCert(c, stranger); err == nil || err.Error() != "the private key does not belong to this certificate" {
		t.Fatal(err)
	}
	issuer, _ := sslSelfSigned(t, sslFixtureOpts{sans: []string{"ca.example.com"}})
	if err := SslKeyMatchesCert(c+issuer, k); err != nil {
		t.Fatal(err)
	}
	if SslKeyMatchesCert(issuer+c, k) == nil {
		t.Fatal("chain judged by a later block")
	}
	// PKCS#1 RSA keys are a kind nginx serves.
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"r.example.com"}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &rk.PublicKey, rk)
	rc := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	rkp := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)}))
	if err := SslKeyMatchesCert(rc, rkp); err != nil {
		t.Fatal(err)
	}
}

func TestKeyMatchingRefusesWhatItCannotRead(t *testing.T) {
	c, k := sslSelfSigned(t, sslFixtureOpts{sans: []string{"a.example.com"}})
	if err := SslKeyMatchesCert("", k); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Fatal(err)
	}
	for _, key := range []string{"", c} {
		if err := SslKeyMatchesCert(c, key); err == nil || !strings.Contains(err.Error(), "no private key") {
			t.Fatal(err)
		}
	}
}

// ── foreign issuer ──────────────────────────────────────────────────────

func sslStatus(has bool, issuer *string) SslCertStatus {
	return SslCertStatus{Domain: "example.com", HasCert: has, Issuer: issuer}
}

func sp(s string) *string { return &s }

func TestForeignIssuerDecision(t *testing.T) {
	for _, i := range []string{"DigiCert Inc", "Cloudflare Origin CA"} {
		if got, ok := sslForeignIssuerOf(sslStatus(true, sp(i))); !ok || got != i {
			t.Error(i)
		}
	}
	// Both spellings: the apostrophe is a typographic hazard, not a fact.
	for _, i := range []string{"Let's Encrypt", "Lets Encrypt", "C=US, O=Let's Encrypt, CN=R11", "LET'S ENCRYPT"} {
		if _, ok := sslForeignIssuerOf(sslStatus(true, sp(i))); ok {
			t.Error(i)
		}
	}
	// Doubt proceeds; it never refuses.
	for _, st := range []SslCertStatus{sslStatus(false, nil), sslStatus(false, sp("DigiCert Inc")), sslStatus(true, nil), sslStatus(true, sp("")), sslStatus(true, sp("   "))} {
		if _, ok := sslForeignIssuerOf(st); ok {
			t.Errorf("%+v refused", st)
		}
	}
	msg := sslForeignCertRefusal("example.com", "DigiCert Inc")
	if !strings.HasPrefix(msg, SslForeignCertRefused) || !strings.Contains(msg, "DigiCert Inc") || !strings.Contains(msg, "example.com") {
		t.Fatal(msg)
	}
}

// ── wire formats the Rust agent produced ────────────────────────────────

func TestTimeFormatsMatchTheRustCrates(t *testing.T) {
	ts := time.Date(2026, 1, 14, 9, 5, 3, 0, time.UTC)
	if got := sslTimeDisplay(ts); got != "2026-01-14 9:05:03.0 +00:00:00" {
		t.Error(got)
	}
	if got := sslTimeDisplay(ts.Add(500 * time.Millisecond)); got != "2026-01-14 9:05:03.5 +00:00:00" {
		t.Error(got)
	}
	if got := SslRFC3339(ts); got != "2026-01-14T09:05:03+00:00" {
		t.Error(got)
	}
	if got := sslChronoRFC3339(ts.Add(1500*time.Microsecond), "Z"); got != "2026-01-14T09:05:03.001500Z" {
		t.Error(got)
	}
	b, _ := json.Marshal(SslUtcTime(ts))
	if string(b) != `"2026-01-14T09:05:03Z"` {
		t.Error(string(b))
	}
}

func TestIssuerStringIsInDistinguishedNameOrder(t *testing.T) {
	name := pkix.Name{Country: []string{"US"}, Organization: []string{"Let's Encrypt"}, CommonName: "R11"}
	raw, _ := asn1MarshalName(name)
	if got := sslNameString(raw); got != "C=US, O=Let's Encrypt, CN=R11" {
		t.Fatal(got)
	}
}

func asn1MarshalName(n pkix.Name) ([]byte, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: n, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return c.RawIssuer, nil
}

func TestCertIdentifierUsesAkiAndRawSerial(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Serial with the high bit set: DER needs a leading 0x00, which must be kept.
	tpl := &x509.Certificate{SerialNumber: big.NewInt(0x87654321), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		AuthorityKeyId: []byte{0x69, 0x88, 0x5B, 0x6B}, SubjectKeyId: []byte{1}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := sslCertIdentifier(der)
	if err != nil {
		t.Fatal(err)
	}
	if id != "aYhbaw.AIdlQyE" {
		t.Fatal(id)
	}
}
