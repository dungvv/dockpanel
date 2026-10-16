package services

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flosch/pongo2/v6"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/sitelock"
)

const (
	sslAcmeAccountPath = "/etc/dockpanel/ssl/acme-account.json"
	sslDir             = "/etc/dockpanel/ssl"
	sslAcmeWebroot     = "/var/www/acme"
	sslLetsEncryptURL  = "https://acme-v02.api.letsencrypt.org/directory"
)

// SslWriteKeyFile writes a secret (a TLS private key) with 0600 applied AT
// CREATION, closing the write-then-chmod window where a root-written key sat
// 0644 under the default umask. The trailing chmod re-tightens an existing
// file (the create mode is ignored when it already exists).
func SslWriteKeyFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("Failed to open key file: %v", nginxIOErr(err))
	}
	_, werr := f.WriteString(content)
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("Failed to write key: %v", nginxIOErr(werr))
	}
	_ = os.Chmod(path, 0o600)
	return nil
}

// sslNormaliseDNSName: trim, drop ONE trailing root dot, ASCII-lowercase.
// Both sides go through it — is_valid_domain permits uppercase.
func sslNormaliseDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// sslDNSNameCovers: a wildcard covers EXACTLY ONE leftmost label (RFC 6125).
// Permissive is how a panel reports TLS browsers reject; strict would refuse
// working certificates. `*.com` and `w*.example.com` are not accepted.
func sslDNSNameCovers(name, domain string) bool {
	if name == domain {
		return true
	}
	base, ok := strings.CutPrefix(name, "*.")
	if !ok || base == "" || strings.Contains(base, "*") || !strings.Contains(base, ".") {
		return false
	}
	label, rest, ok := strings.Cut(domain, ".")
	return ok && label != "" && !strings.Contains(label, "*") && rest == base
}

var sslOIDCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// sslPresentedDNSNames: SAN dNSNames, with the Common Name only as a FALLBACK
// when there are none — what browsers do, so CN=other, SAN=real is refused
// for `other`.
func sslPresentedDNSNames(cert *x509.Certificate) []string {
	names := make([]string, 0, len(cert.DNSNames))
	for _, n := range cert.DNSNames {
		names = append(names, sslNormaliseDNSName(n))
	}
	if len(names) > 0 {
		return names
	}
	for _, a := range cert.Subject.Names {
		if a.Type.Equal(sslOIDCommonName) {
			if s, ok := a.Value.(string); ok {
				names = append(names, sslNormaliseDNSName(s))
			}
		}
	}
	return names
}

// sslPemBlocks iterates PEM blocks, failing on a block that is present but
// unreadable (pem.Decode would silently skip it).
func sslPemBlocks(data []byte) ([]*pem.Block, error) {
	var out []*pem.Block
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			if bytes.Contains(data, []byte("-----BEGIN")) {
				return out, errors.New("invalid PEM encoding")
			}
			return out, nil
		}
		out = append(out, block)
		data = rest
	}
}

// SslCertCoversDomain checks that an uploaded certificate names the site it is
// installed for and returns the names it presents. Three load-bearing calls:
//  1. Only the FIRST CERTIFICATE block is asked — nginx binds it as the leaf
//     (measured: [wrong, right] + wrong.key passes `nginx -t` and serves wrong).
//  2. A non-certificate block is refused outright: a key-then-cert paste once
//     landed a key in a 0644 fullchain.pem and blinded the expiry ladder.
//  3. No is_ca() filter: `openssl req -x509` stamps CA:TRUE on every
//     self-signed staging certificate.
func SslCertCoversDomain(certPEM, domain string) ([]string, error) {
	want := sslNormaliseDNSName(domain)
	blocks, err := sslPemBlocks([]byte(certPEM))
	if err != nil {
		return nil, fmt.Errorf("the certificate could not be read: %v", err)
	}
	var leaf []string
	haveLeaf := false
	for _, b := range blocks {
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("the certificate field contains a %s block. Paste only the certificate here, with "+
				"its chain if it has one — the private key belongs in its own field, where it is "+
				"stored with the permissions a key needs and where this site's expiry can still "+
				"be read.", strings.ToLower(b.Type))
		}
		if !haveLeaf {
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("the certificate could not be read: %v", err)
			}
			leaf, haveLeaf = sslPresentedDNSNames(cert), true
		}
	}
	if !haveLeaf {
		return nil, errors.New("no certificate was found in the certificate field.")
	}
	for _, n := range leaf {
		if sslDNSNameCovers(n, want) {
			return leaf, nil
		}
	}
	presented := "no host name at all"
	if len(leaf) > 0 {
		presented = strings.Join(leaf, ", ")
	}
	return nil, fmt.Errorf("this certificate is for %s, not %s. A certificate has to name the site it "+
		"secures or browsers reject it whatever the panel says — check that you pasted the "+
		"certificate for %s and not for another site.", presented, want, want)
}

// SslProvisionOpts controls an ACME order. nil means "classic, no prior cert".
type SslProvisionOpts struct {
	// ACME profile ("classic", "tlsserver", "shortlived"); nil = CA default.
	Profile *string
	// PEM of the certificate being replaced (RFC 9773 ARI `replaces` hint).
	ReplacesPem *string
	// Order even though the installed certificate was demonstrably issued by
	// somebody else. ⛔ FALSE IS THE SAFE VALUE, AND nil OPTS MEANS FALSE:
	// the callers passing nil (compose deploy, git build) never asked the
	// issuer question, so they must fail CLOSED. Set only where a human was
	// told what will be destroyed (`dockpanel ssl provision --force`).
	ReplaceForeign bool
}

// SslCertInfo is a freshly issued certificate.
type SslCertInfo struct {
	CertPath string  `json:"cert_path"`
	KeyPath  string  `json:"key_path"`
	Expiry   *string `json:"expiry"`
	// The profile requested for this order (nil if none).
	Profile *string `json:"profile"`
}

// SslProfileInfo is one ACME profile advertised by the CA.
type SslProfileInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// SslUtcTime serialises like chrono's DateTime<Utc> (RFC 3339, `Z`,
// fractional seconds in 0/3/6/9 digits).
type SslUtcTime time.Time

// MarshalJSON implements json.Marshaler.
func (t SslUtcTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(sslChronoRFC3339(time.Time(t), "Z"))
}

// SslAriSuggestion is an RFC 9773 renewal window plus when to re-check.
type SslAriSuggestion struct {
	RenewalAt     SslUtcTime `json:"renewal_at"`
	RenewalBefore SslUtcTime `json:"renewal_before"`
	RecheckAt     SslUtcTime `json:"recheck_at"`
}

// SslCertStatus describes the certificate installed for a domain.
type SslCertStatus struct {
	Domain        string  `json:"domain"`
	HasCert       bool    `json:"has_cert"`
	Issuer        *string `json:"issuer"`
	NotAfter      *string `json:"not_after"`
	DaysRemaining *int64  `json:"days_remaining"`
}

// sslPersisted is the outcome of persisting freshly-minted account credentials.
type sslPersisted int

const (
	// sslWritten: these credentials are now on disk.
	sslWritten sslPersisted = iota
	// sslAdopted: someone else's were already there; the caller MUST adopt them.
	sslAdopted
)

// sslPersistAccountCredentials writes credentials only if no account file
// exists. O_EXCL makes create-or-fail atomic in the kernel, so of any number
// of racing writers exactly one is told Written. 0600 at creation: this key
// can order and revoke every certificate on the box.
func sslPersistAccountCredentials(path, js string) (sslPersisted, error) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return sslAdopted, nil
	}
	if err != nil {
		return 0, fmt.Errorf("Failed to save ACME account: %v", nginxIOErr(err))
	}
	_, werr := f.WriteString(js)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return 0, fmt.Errorf("Failed to save ACME account: %v", nginxIOErr(werr))
	}
	return sslWritten, nil
}

// sslAccountCredentials is instant-acme's AccountCredentials JSON, kept
// byte-compatible so accounts created by the Rust agent keep working (and
// vice versa): key_pkcs8 is base64url (no padding) PKCS#8 DER.
type sslAccountCredentials struct {
	ID        string          `json:"id"`
	KeyPkcs8  string          `json:"key_pkcs8"`
	Directory *string         `json:"directory"`
	Urls      json.RawMessage `json:"urls,omitempty"`
}

// sslDirectory is the subset of the ACME directory this file uses directly
// (x/crypto/acme does not expose renewalInfo).
type sslDirectory struct {
	NewNonce    string `json:"newNonce"`
	NewOrder    string `json:"newOrder"`
	RenewalInfo string `json:"renewalInfo"`
	Meta        struct {
		Profiles map[string]string `json:"profiles"`
	} `json:"meta"`
}

// SslAccount is a loaded ACME account (Rust: instant_acme::Account).
type SslAccount struct {
	client *acme.Client
	key    *ecdsa.PrivateKey
	id     string
	dir    sslDirectory
}

func sslHTTPGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

func sslFetchDirectory(ctx context.Context, url string) (sslDirectory, error) {
	var d sslDirectory
	resp, err := sslHTTPGet(ctx, url)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return d, fmt.Errorf("directory request failed: HTTP %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(&d)
	return d, err
}

func sslNewAccount(ctx context.Context, key *ecdsa.PrivateKey, id, directoryURL string) (*SslAccount, error) {
	dir, err := sslFetchDirectory(ctx, directoryURL)
	if err != nil {
		return nil, err
	}
	c := &acme.Client{Key: key, DirectoryURL: directoryURL, KID: acme.KeyID(id)}
	if _, err := c.Discover(ctx); err != nil {
		return nil, err
	}
	return &SslAccount{client: c, key: key, id: id, dir: dir}, nil
}

// sslLegacyDirectory recovers a directory URL from credentials written by an
// old instant-acme that stored endpoint URLs instead of the directory URL.
// Only the Let's Encrypt hosts are recognised.
func sslLegacyDirectory(urls json.RawMessage) (string, bool) {
	var u map[string]any
	if json.Unmarshal(urls, &u) != nil {
		return "", false
	}
	order, _ := u["newOrder"].(string)
	for _, host := range []string{"https://acme-v02.api.letsencrypt.org/", "https://acme-staging-v02.api.letsencrypt.org/"} {
		if strings.HasPrefix(order, host) {
			return host + "directory", true
		}
	}
	return "", false
}

// sslStoredAccount reads the stored account; nil when no file exists.
func sslStoredAccount(ctx context.Context) (*SslAccount, error) {
	if !nginxExists(sslAcmeAccountPath) {
		return nil, nil
	}
	b, err := os.ReadFile(sslAcmeAccountPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read ACME account: %v", nginxIOErr(err))
	}
	var creds sslAccountCredentials
	if err := json.Unmarshal(b, &creds); err != nil {
		return nil, fmt.Errorf("Failed to parse ACME account: %v", err)
	}
	der, err := base64.RawURLEncoding.DecodeString(creds.KeyPkcs8)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse ACME account: %v", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	key, ok := k.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("Failed to load ACME account: key rejected")
	}
	dirURL := ""
	switch {
	case creds.Directory != nil:
		dirURL = *creds.Directory
	case len(creds.Urls) > 0:
		if dirURL, ok = sslLegacyDirectory(creds.Urls); !ok {
			return nil, errors.New("Failed to load ACME account: unrecognised legacy server URLs")
		}
	default:
		return nil, errors.New("Failed to load ACME account: no server URLs found")
	}
	acct, err := sslNewAccount(ctx, key, creds.ID, dirURL)
	if err != nil {
		return nil, fmt.Errorf("Failed to load ACME account: %v", err)
	}
	return acct, nil
}

// sslAccountInit serialises load-or-create inside this process.
var sslAccountInit sync.Mutex

// SslLoadOrCreateAccount loads the ACME account or creates one.
//
// ⛔ THE INVARIANT: the account returned is ALWAYS the one whose credentials
// are on disk. A certificate issued under a key nowhere on disk can never be
// renewed: every renewal sends an ARI `replaces` hint, the CA answers
// `unauthorized`, and the site goes dark at expiry behind a panel that
// reported success. It used to happen with no operator mistake: two sites
// created together each created a DIFFERENT account and the second write
// clobbered the first (measured: two creations 443 ms apart). The mutex
// covers this process; O_EXCL covers a second process (the loser adopts).
func SslLoadOrCreateAccount(email string) (*SslAccount, error) {
	sslAccountInit.Lock()
	defer sslAccountInit.Unlock()
	ctx := context.Background()

	acct, err := sslStoredAccount(ctx)
	if err != nil {
		return nil, err
	}
	if acct != nil {
		slog.Info("Loaded existing ACME account")
		return acct, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed to create ACME account: %v", err)
	}
	c := &acme.Client{Key: key, DirectoryURL: sslLetsEncryptURL}
	reg, err := c.Register(ctx, &acme.Account{Contact: []string{"mailto:" + email}}, acme.AcceptTOS)
	if err != nil {
		return nil, fmt.Errorf("Failed to create ACME account: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to serialize ACME creds: %v", err)
	}
	dirURL := sslLetsEncryptURL
	js, err := json.MarshalIndent(sslAccountCredentials{ID: reg.URI, KeyPkcs8: base64.RawURLEncoding.EncodeToString(der), Directory: &dirURL}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("Failed to serialize ACME creds: %v", err)
	}
	outcome, err := sslPersistAccountCredentials(sslAcmeAccountPath, string(js))
	if err != nil {
		return nil, err
	}
	if outcome == sslWritten {
		slog.Info("Created new ACME account for " + email)
		acct, err := sslNewAccount(ctx, key, reg.URI, dirURL)
		if err != nil {
			return nil, fmt.Errorf("Failed to load ACME account: %v", err)
		}
		return acct, nil
	}
	// Another PROCESS wrote first. Returning ours would issue under a key
	// nowhere on disk — adopt the stored one.
	slog.Warn("An ACME account was written by another process first — adopting it and " +
		"abandoning the one just created, so every certificate is issued under the " +
		"account whose key is on disk")
	acct, err = sslStoredAccount(ctx)
	if err != nil {
		return nil, err
	}
	if acct == nil {
		return nil, errors.New("ACME account file disappeared between creation and read")
	}
	return acct, nil
}

// SslCaDeclined marks an error the CERTIFICATE AUTHORITY produced, as opposed
// to this machine. Marked POSITIVELY: an unmarked arm defaults to "this
// machine's fault" and keeps its incident id, the safe direction — the
// inverse would send someone to check DNS while their disk is full.
const SslCaDeclined = "[ca] "

// SslDNSProviderDeclined marks a refusal by the DNS provider (DNS-01 door):
// the operator's to fix (commonly a token without DNS:Edit), but not
// something the CA said. Also marked positively.
const SslDNSProviderDeclined = "[dns] "

// SslForeignCertRefused marks a refusal, not a fault: someone else's
// certificate is installed and will not be overwritten. Without the marker the
// panel turns the most actionable sentence this door produces into an
// incident id.
const SslForeignCertRefused = "[foreign] "

// ── raw ACME requests x/crypto/acme does not offer (ARI `replaces`) ─────

type sslProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

func (p sslProblem) Error() string {
	s := "API error"
	if p.Detail != "" {
		s += ": " + p.Detail
	}
	if p.Type != "" {
		s += " (" + p.Type + ")"
	}
	return s
}

func sslB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *SslAccount) nonce(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, a.dir.NewNonce, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", errors.New("no nonce received from ACME CA")
	}
	return n, nil
}

// postJWS sends an ES256/kid-signed ACME POST, retrying once on badNonce.
func (a *SslAccount) postJWS(ctx context.Context, url string, payload any) (*http.Response, []byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := a.nonce(ctx)
	if err != nil {
		return nil, nil, err
	}
	for attempt := 0; ; attempt++ {
		prot, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": a.id, "nonce": nonce, "url": url})
		input := sslB64(prot) + "." + sslB64(body)
		digest := sha256.Sum256([]byte(input))
		r, s, err := ecdsa.Sign(rand.Reader, a.key, digest[:])
		if err != nil {
			return nil, nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		jws, _ := json.Marshal(map[string]string{"protected": sslB64(prot), "payload": sslB64(body), "signature": sslB64(sig)})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jws))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/jose+json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode/100 == 2 {
			return resp, data, nil
		}
		var p sslProblem
		_ = json.Unmarshal(data, &p)
		if p.Type == "urn:ietf:params:acme:error:badNonce" && attempt == 0 {
			if n := resp.Header.Get("Replay-Nonce"); n != "" {
				nonce = n
				continue
			}
		}
		if p.Type == "" && p.Detail == "" {
			p.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, nil, p
	}
}

type sslIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// newOrder creates an order (with optional profile and ARI replaces) and
// returns it via x/crypto for the rest of the flow.
func (a *SslAccount) newOrder(ctx context.Context, names []string, profile, replaces *string) (*acme.Order, error) {
	if replaces != nil && a.dir.RenewalInfo == "" {
		return nil, errors.New("unsupported: ACME renewal information (ARI)")
	}
	payload := map[string]any{}
	ids := make([]sslIdentifier, len(names))
	for i, n := range names {
		ids[i] = sslIdentifier{"dns", n}
	}
	payload["identifiers"] = ids
	if profile != nil {
		payload["profile"] = *profile
	}
	if replaces != nil {
		payload["replaces"] = *replaces
	}
	resp, data, err := a.postJWS(ctx, a.dir.NewOrder, payload)
	if err != nil {
		return nil, err
	}
	loc := resp.Header.Get("Location")
	var state struct {
		Replaces *string `json:"replaces"`
	}
	_ = json.Unmarshal(data, &state)
	if loc == "" {
		return nil, errors.New("no order URL received")
	}
	// Per RFC 9773 the server MUST reflect an accepted `replaces`.
	if replaces != nil && (state.Replaces == nil || *state.Replaces != *replaces) {
		found := "None"
		if state.Replaces != nil {
			found = fmt.Sprintf("Some(%q)", *state.Replaces)
		}
		return nil, fmt.Errorf("replaces field mismatch: expected Some(%q), found %s", *replaces, found)
	}
	return a.client.GetOrder(ctx, loc)
}

// sslStatusDebug renders an ACME status like Rust's Debug of the enum.
func sslStatusDebug(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// sslReplacesHint turns opts into (profile, replaces) for newOrder.
func sslReplacesHint(domain string, opts *SslProvisionOpts) (profile, replaces *string) {
	if opts == nil {
		return nil, nil
	}
	profile = opts.Profile
	if opts.ReplacesPem != nil {
		if id, err := sslCertIdentifierFromPem([]byte(*opts.ReplacesPem)); err == nil {
			replaces = &id
		} else {
			slog.Warn(fmt.Sprintf("ARI replaces skipped (%s): %v", domain, err))
		}
	}
	return profile, replaces
}

// sslFinalize generates the certificate key and CSR (empty subject, SANs =
// identifiers, like instant-acme), finalizes, and returns (key PEM, chain PEM).
func (a *SslAccount) finalize(ctx context.Context, order *acme.Order) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	var names []string
	for _, id := range order.Identifiers {
		names = append(names, id.Value)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		return "", "", err
	}
	ders, _, err := a.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return "", "", err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	var chain bytes.Buffer
	for _, d := range ders {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), chain.String(), nil
}

func sslForeignGate(domain, label string, opts *SslProvisionOpts) error {
	if opts != nil && opts.ReplaceForeign {
		return nil
	}
	if issuer, ok := SslForeignInstalledIssuer(domain); ok {
		slog.Warn(fmt.Sprintf("Refusing ACME %sorder for %s: installed certificate is from %s", label, domain, issuer))
		return errors.New(sslForeignCertRefusal(domain, issuer))
	}
	return nil
}

// SslProvisionCert issues a Let's Encrypt certificate via HTTP-01 (webroot
// /var/www/acme). Cancelling ctx abandons the order (Rust: dropping the future).
func SslProvisionCert(ctx context.Context, account *SslAccount, domain string, opts *SslProvisionOpts) (*SslCertInfo, error) {
	slog.Info("Provisioning SSL for " + domain)
	// ⛔ THE CHOKE POINT, asked before the order: the damage is done by the
	// write below, and a refused order costs nothing.
	if err := sslForeignGate(domain, "", opts); err != nil {
		return nil, err
	}
	profile, replaces := sslReplacesHint(domain, opts)
	order, err := account.newOrder(ctx, []string{domain}, profile, replaces)
	if err != nil {
		return nil, fmt.Errorf("%sThe CA refused the certificate order: %v", SslCaDeclined, err)
	}
	if order.Status != acme.StatusPending && order.Status != acme.StatusReady {
		return nil, fmt.Errorf("%sThe CA returned an unexpected order status: %s", SslCaDeclined, sslStatusDebug(order.Status))
	}

	challengeDir := sslAcmeWebroot + "/.well-known/acme-challenge"
	if order.Status == acme.StatusPending {
		for _, u := range order.AuthzURLs {
			authz, err := account.client.GetAuthorization(ctx, u)
			if err != nil {
				return nil, fmt.Errorf("%sThe CA would not return an authorization: %v", SslCaDeclined, err)
			}
			switch authz.Status {
			case acme.StatusValid:
				continue
			case acme.StatusPending:
			default:
				return nil, fmt.Errorf("%sThe CA returned an unexpected authorization status: %s", SslCaDeclined, sslStatusDebug(authz.Status))
			}
			var chal *acme.Challenge
			for _, c := range authz.Challenges {
				if c.Type == "http-01" {
					chal = c
					break
				}
			}
			if chal == nil {
				return nil, errors.New("No HTTP-01 challenge found")
			}
			keyAuth, err := account.client.HTTP01ChallengeResponse(chal.Token)
			if err != nil {
				return nil, err
			}
			if err := os.MkdirAll(challengeDir, 0o755); err != nil {
				return nil, fmt.Errorf("Failed to create challenge dir: %v", nginxIOErr(err))
			}
			if err := os.WriteFile(challengeDir+"/"+chal.Token, []byte(keyAuth), 0o644); err != nil {
				return nil, fmt.Errorf("Failed to write challenge file: %v", nginxIOErr(err))
			}
			slog.Info("Challenge file written for " + domain)
			if _, err := account.client.Accept(ctx, chal); err != nil {
				return nil, fmt.Errorf("%sThe CA would not accept the challenge as ready: %v", SslCaDeclined, err)
			}
		}
	}

	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := account.client.WaitOrder(wctx, order.URI); err != nil {
		return nil, fmt.Errorf("%sThe CA did not validate the challenge: %v", SslCaDeclined, err)
	}
	fctx, fcancel := context.WithTimeout(ctx, 60*time.Second)
	defer fcancel()
	keyPEM, chainPEM, err := account.finalize(fctx, order)
	if err != nil {
		return nil, fmt.Errorf("%sThe CA would not finalize the order: %v", SslCaDeclined, err)
	}

	info, err := sslSaveCert(domain, keyPEM, chainPEM, "Failed to create cert dir", "Failed to write cert")
	if err != nil {
		return nil, err
	}
	if entries, err := os.ReadDir(challengeDir); err == nil {
		for _, e := range entries {
			_ = os.Remove(challengeDir + "/" + e.Name())
		}
	}
	info.Profile = profile
	slog.Info("SSL certificate provisioned for " + domain)
	return info, nil
}

func sslSaveCert(domain, keyPEM, chainPEM, mkdirMsg, writeMsg string) (*SslCertInfo, error) {
	certDir := sslDir + "/" + domain
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return nil, fmt.Errorf("%s: %v", mkdirMsg, nginxIOErr(err))
	}
	certPath, keyPath := certDir+"/fullchain.pem", certDir+"/privkey.pem"
	if err := os.WriteFile(certPath, []byte(chainPEM), 0o644); err != nil {
		return nil, fmt.Errorf("%s: %v", writeMsg, nginxIOErr(err))
	}
	// 0600 at creation — no world-readable window.
	if err := SslWriteKeyFile(keyPath, keyPEM); err != nil {
		return nil, err
	}
	return &SslCertInfo{CertPath: certPath, KeyPath: keyPath, Expiry: sslCertExpiry(certPath)}, nil
}

// sslHeaderValueOK mirrors http::HeaderValue::from_str (visible ASCII or tab).
func sslHeaderValueOK(v string) bool {
	for i := 0; i < len(v); i++ {
		if b := v[i]; !(b >= 32 && b < 127 || b == '\t') {
			return false
		}
	}
	return true
}

const sslCfAPI = "https://api.cloudflare.com/client/v4"

// SslProvisionCertDNS01 issues via DNS-01 through Cloudflare; wildcard adds
// `*.{domain}`. For a wildcard, domain is the zone APEX whose directory every
// sibling vhost points at — an unguarded order would replace an unbounded
// number of sites' certificate, so the foreign gate matters MORE here.
func SslProvisionCertDNS01(ctx context.Context, account *SslAccount, domain, cfZoneID, cfAPIToken string, cfAPIEmail *string,
	wildcard bool, opts *SslProvisionOpts) (*SslCertInfo, error) {
	label := "dns01"
	if wildcard {
		label = "wildcard"
	}
	slog.Info(fmt.Sprintf("Provisioning SSL (%s) for %s", label, domain))
	if err := sslForeignGate(domain, label+" ", opts); err != nil {
		return nil, err
	}
	names := []string{domain}
	if wildcard {
		names = append(names, "*."+domain)
	}
	profile, replaces := sslReplacesHint(domain, opts)
	order, err := account.newOrder(ctx, names, profile, replaces)
	if err != nil {
		return nil, fmt.Errorf("%sThe CA refused the certificate order: %v", SslCaDeclined, err)
	}
	if order.Status != acme.StatusPending && order.Status != acme.StatusReady {
		return nil, fmt.Errorf("%sThe CA returned an unexpected order status: %s", SslCaDeclined, sslStatusDebug(order.Status))
	}

	httpc := &http.Client{Timeout: 15 * time.Second}
	headers := http.Header{}
	if cfAPIEmail != nil {
		if !sslHeaderValueOK(*cfAPIEmail) {
			return nil, fmt.Errorf("%sThe Cloudflare account email for this zone is not a usable header value", SslDNSProviderDeclined)
		}
		if !sslHeaderValueOK(cfAPIToken) {
			return nil, fmt.Errorf("%sThe Cloudflare API key for this zone is not a usable header value", SslDNSProviderDeclined)
		}
		headers.Set("X-Auth-Email", *cfAPIEmail)
		headers.Set("X-Auth-Key", cfAPIToken)
	} else {
		if !sslHeaderValueOK("Bearer " + cfAPIToken) {
			return nil, fmt.Errorf("%sThe Cloudflare API token for this zone is not a usable header value", SslDNSProviderDeclined)
		}
		headers.Set("Authorization", "Bearer "+cfAPIToken)
	}

	var created []string
	cleanup := func() { sslCleanupCfRecords(httpc, cfZoneID, headers, created) }

	if order.Status == acme.StatusPending {
		for _, u := range order.AuthzURLs {
			authz, err := account.client.GetAuthorization(ctx, u)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("%sThe CA would not return an authorization: %v", SslCaDeclined, err)
			}
			switch authz.Status {
			case acme.StatusValid:
				continue
			case acme.StatusPending:
			default:
				cleanup()
				return nil, fmt.Errorf("%sThe CA returned an unexpected authorization status: %s", SslCaDeclined, sslStatusDebug(authz.Status))
			}
			var chal *acme.Challenge
			for _, c := range authz.Challenges {
				if c.Type == "dns-01" {
					chal = c
					break
				}
			}
			if chal == nil {
				cleanup()
				return nil, fmt.Errorf("%sThe CA offered no DNS-01 challenge for this domain", SslCaDeclined)
			}
			txt, err := account.client.DNS01ChallengeRecord(chal.Token)
			if err != nil {
				cleanup()
				return nil, err
			}
			recordName := "_acme-challenge." + domain
			slog.Info(fmt.Sprintf("DNS-01: creating TXT %s = %s", recordName, txt))

			body, _ := json.Marshal(map[string]any{"type": "TXT", "name": recordName, "content": txt, "ttl": 120})
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/zones/%s/dns_records", sslCfAPI, cfZoneID), bytes.NewReader(body))
			for k, v := range headers {
				req.Header[k] = v
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := httpc.Do(req)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("%sCloudflare could not be reached to publish the challenge record: %v", SslDNSProviderDeclined, err)
			}
			var rj map[string]any
			derr := json.NewDecoder(resp.Body).Decode(&rj)
			resp.Body.Close()
			if derr != nil {
				cleanup()
				return nil, fmt.Errorf("%sCloudflare returned a response that could not be read: %v", SslDNSProviderDeclined, derr)
			}
			if ok, _ := rj["success"].(bool); !ok {
				cleanup()
				errs, _ := json.Marshal(rj["errors"])
				return nil, fmt.Errorf("%sCloudflare refused to create the challenge record: %s", SslDNSProviderDeclined, errs)
			}
			if res, ok := rj["result"].(map[string]any); ok {
				if id, ok := res["id"].(string); ok {
					created = append(created, id)
				}
			}
			// Cloudflare is fast, but ACME servers cache.
			time.Sleep(10 * time.Second)
			if _, err := account.client.Accept(ctx, chal); err != nil {
				cleanup()
				return nil, fmt.Errorf("%sThe CA would not accept the challenge as ready: %v", SslCaDeclined, err)
			}
		}
	}

	wctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	_, pollErr := account.client.WaitOrder(wctx, order.URI)
	// Always clean up the TXT records.
	cleanup()
	if pollErr != nil {
		return nil, fmt.Errorf("%sThe CA did not validate the DNS-01 challenge: %v", SslCaDeclined, pollErr)
	}
	fctx, fcancel := context.WithTimeout(ctx, 120*time.Second)
	defer fcancel()
	keyPEM, chainPEM, err := account.finalize(fctx, order)
	if err != nil {
		return nil, fmt.Errorf("%sThe CA would not finalize the order: %v", SslCaDeclined, err)
	}
	// The base domain names the directory.
	info, err := sslSaveCert(domain, keyPEM, chainPEM, "Create cert dir", "Write cert")
	if err != nil {
		return nil, err
	}
	info.Profile = profile
	slog.Info(fmt.Sprintf("SSL (%s) provisioned for %s", label, domain))
	return info, nil
}

func sslCleanupCfRecords(httpc *http.Client, zoneID string, headers http.Header, ids []string) {
	for _, rid := range ids {
		req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/zones/%s/dns_records/%s", sslCfAPI, zoneID, rid), nil)
		for k, v := range headers {
			req.Header[k] = v
		}
		resp, err := httpc.Do(req)
		if err != nil {
			slog.Warn(fmt.Sprintf("DNS-01: failed to clean up TXT %s: %v", rid, err))
			continue
		}
		resp.Body.Close()
		slog.Info("DNS-01: cleaned up TXT record " + rid)
	}
}

// sslFirstPemCert parses the FIRST PEM block (whatever its label) as a
// certificate, like x509_parser::parse_x509_pem + parse_x509.
func sslFirstPemCert(data []byte) (*x509.Certificate, *pem.Block, bool) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, block, false
	}
	return cert, block, true
}

// sslTimeDisplay formats like the `time` crate's OffsetDateTime Display,
// which is what the Rust agent put on the wire for expiry dates:
// "2026-01-14 9:05:03.0 +00:00:00".
func sslTimeDisplay(t time.Time) string {
	t = t.UTC()
	frac := strings.TrimRight(fmt.Sprintf("%09d", t.Nanosecond()), "0")
	if frac == "" {
		frac = "0"
	}
	return fmt.Sprintf("%04d-%02d-%02d %d:%02d:%02d.%s +00:00:00",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), frac)
}

// sslChronoRFC3339 formats like chrono's RFC 3339 with SecondsFormat::AutoSi
// (no fraction, or 3/6/9 digits) and the given UTC suffix ("Z" for serde,
// "+00:00" for to_rfc3339()).
func sslChronoRFC3339(t time.Time, utc string) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	switch ns := t.Nanosecond(); {
	case ns == 0:
	case ns%1_000_000 == 0:
		s += fmt.Sprintf(".%03d", ns/1_000_000)
	case ns%1_000 == 0:
		s += fmt.Sprintf(".%06d", ns/1_000)
	default:
		s += fmt.Sprintf(".%09d", ns)
	}
	return s + utc
}

func sslCertExpiry(certPath string) *string {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return nil
	}
	cert, _, ok := sslFirstPemCert(b)
	if !ok {
		return nil
	}
	s := sslTimeDisplay(cert.NotAfter)
	return &s
}

// sslOIDAbbrev mirrors x509-parser's abbreviations for the issuer string.
var sslOIDAbbrev = map[string]string{
	"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
	"0.9.2342.19200300.100.1.25": "DC", "1.2.840.113549.1.9.1": "Email",
	"2.5.4.5": "serialNumber", "2.5.4.9": "street", "2.5.4.4": "surname", "2.5.4.42": "givenName",
	"2.5.4.12": "title", "2.5.4.17": "postalCode", "2.5.4.97": "organizationIdentifier",
}

// sslNameString renders a distinguished name in order, like x509-parser's
// Display: "C=US, O=Let's Encrypt, CN=R11" (multi-valued RDNs joined " + ").
func sslNameString(raw []byte) string {
	var seq pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &seq); err != nil || len(rest) > 0 {
		return "<X509Error: Invalid X.509 name>"
	}
	rdns := make([]string, 0, len(seq))
	for _, rdn := range seq {
		attrs := make([]string, 0, len(rdn))
		for _, a := range rdn {
			k, ok := sslOIDAbbrev[a.Type.String()]
			if !ok {
				k = a.Type.String()
			}
			var v string
			switch val := a.Value.(type) {
			case string:
				v = val
			default:
				enc, _ := asn1.Marshal(val)
				v = strings.ToUpper(hex.EncodeToString(enc))
			}
			attrs = append(attrs, k+"="+v)
		}
		rdns = append(rdns, strings.Join(attrs, " + "))
	}
	return strings.Join(rdns, ", ")
}

// SslForeignInstalledIssuer returns the issuer of the certificate installed
// for domain ONLY when it proves DockPanel did not put it there. ⛔ The last
// gate before an ACME order overwrites a file, placed at the two writers
// because their 26 reachable callers are not a list anyone can keep. It reads
// the exact path both writers write, from the same domain. ok=false covers
// "we do not know" too — every caller must treat that as PERMISSION TO
// PROCEED; refusing on doubt is how a site ends up with no certificate.
// Mirrors panel/backend helpers.rs::cert_provenance (both spellings of the
// CA's name are deliberate).
func SslForeignInstalledIssuer(domain string) (string, bool) {
	return sslForeignIssuerOf(SslGetCertStatus(domain))
}

func sslForeignIssuerOf(st SslCertStatus) (string, bool) {
	if !st.HasCert || st.Issuer == nil {
		return "", false
	}
	issuer := strings.TrimSpace(*st.Issuer)
	if issuer == "" {
		return "", false
	}
	l := strings.ToLower(issuer)
	if strings.Contains(l, "let's encrypt") || strings.Contains(l, "lets encrypt") {
		return "", false
	}
	return issuer, true
}

// sslForeignCertRefusal is the one spelling of the refusal.
func sslForeignCertRefusal(domain, issuer string) string {
	return fmt.Sprintf("%sRefusing to issue a Let's Encrypt certificate for %s: the certificate already "+
		"installed there was issued by %s, not by DockPanel, and ordering would overwrite "+
		"it. Renew it wherever it was issued, or pass --force if you intend to replace it.", SslForeignCertRefused, domain, issuer)
}

// SslGetCertStatus describes the certificate installed for domain.
func SslGetCertStatus(domain string) SslCertStatus {
	certPath := fmt.Sprintf("%s/%s/fullchain.pem", sslDir, domain)
	st := SslCertStatus{Domain: domain}
	if !nginxExists(certPath) {
		return st
	}
	st.HasCert = true
	b, err := os.ReadFile(certPath)
	if err != nil {
		return st
	}
	cert, _, ok := sslFirstPemCert(b)
	if !ok {
		return st
	}
	issuer := sslNameString(cert.RawIssuer)
	notAfter := sslTimeDisplay(cert.NotAfter)
	days := (cert.NotAfter.Unix() - time.Now().Unix()) / 86400
	st.Issuer, st.NotAfter, st.DaysRemaining = &issuer, &notAfter, &days
	return st
}

// SslListCertStatus lists every certificate this host holds, issued by the
// panel or not — the diagnostics scanner raised findings about certificates
// no screen could list. Reports disk only; the panel decides ownership.
func SslListCertStatus() []SslCertStatus {
	out := []SslCertStatus{}
	entries, err := os.ReadDir(sslDir)
	if err != nil {
		return out // a fresh box has never issued one
	}
	for _, e := range entries {
		// The ACME account material lives beside the certificates.
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if st := SslGetCertStatus(e.Name()); st.HasCert {
			out = append(out, st)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// SslEnableSslForSite switches a site's vhost to the HTTPS template and, for a
// WordPress site still advertising plain HTTP, moves its canonical URL too.
// Every path that gives a site a certificate funnels through here, and the
// per-site lock taken once here makes all of them mutually exclusive.
func SslEnableSslForSite(set *pongo2.TemplateSet, domain string, siteConfig *NginxSiteConfig) (WordpressCanonicalUrlOutcome, error) {
	defer sitelock.LockSite(domain)()

	sslCfg := *siteConfig
	tr := true
	cert, key := fmt.Sprintf("%s/%s/fullchain.pem", sslDir, domain), fmt.Sprintf("%s/%s/privkey.pem", sslDir, domain)
	sslCfg.Ssl, sslCfg.SslCert, sslCfg.SslKey = &tr, &cert, &key

	rendered, err := NginxRenderSiteConfig(set, domain, &sslCfg)
	if err != nil {
		return WordpressCanonicalUrlUntouched, fmt.Errorf("Template render error: %v", err)
	}
	// A disabled site gets its parked body updated, so the certificate is in
	// it on re-enable; writing into service used to bring it back online.
	target := NginxVhostTargetFor(domain)
	tmp := target.Path + ".tmp"
	if err := os.WriteFile(tmp, []byte(rendered), 0o644); err != nil {
		return WordpressCanonicalUrlUntouched, fmt.Errorf("Failed to write nginx config: %v", nginxIOErr(err))
	}
	if err := os.Rename(tmp, target.Path); err != nil {
		return WordpressCanonicalUrlUntouched, fmt.Errorf("Failed to rename nginx config: %v", nginxIOErr(err))
	}
	if !target.Live {
		slog.Info(fmt.Sprintf("Site %s is disabled: its parked configuration now carries the certificate, "+
			"and nginx was not reloaded", domain))
		// Moving WordPress to HTTPS now would point it at a name answering 503.
		return WordpressCanonicalUrlUntouched, nil
	}

	test, err := NginxTestConfig()
	if err != nil {
		return WordpressCanonicalUrlUntouched, fmt.Errorf("Failed to test nginx: %v", err)
	}
	if !test.Success {
		// Roll back to the non-SSL render.
		fallback, err := NginxRenderSiteConfig(set, domain, siteConfig)
		if err != nil {
			return WordpressCanonicalUrlUntouched, fmt.Errorf("Rollback render error: %v", err)
		}
		_ = os.WriteFile(target.Path, []byte(fallback), 0o644)
		_ = NginxReload()
		return WordpressCanonicalUrlUntouched, fmt.Errorf("SSL nginx config invalid: %s", test.Stderr)
	}
	if err := NginxReload(); err != nil {
		return WordpressCanonicalUrlUntouched, fmt.Errorf("Nginx reload failed: %v", err)
	}
	slog.Info("Nginx updated with SSL for " + domain)

	// The certificate is live either way; a URL that could not be moved is
	// reported, never a failure of the enable.
	canonical := WordpressPromoteSiteUrlToHttps(domain)
	if canonical == WordpressCanonicalUrlPromoted {
		slog.Info(fmt.Sprintf("WordPress canonical URL for %s moved to HTTPS", domain))
	} else if msg, failed := canonical.Failure(); failed {
		slog.Warn(fmt.Sprintf("Could not move WordPress canonical URL for %s to HTTPS: %s", domain, msg))
	}
	return canonical, nil
}

// ── ACME profiles + ARI (RFC 9773) ──────────────────────────────────────

// SslListProfiles lists the CA's advertised profiles (empty = unsupported).
func SslListProfiles(account *SslAccount) []SslProfileInfo {
	out := []SslProfileInfo{}
	for n, d := range account.dir.Meta.Profiles {
		out = append(out, SslProfileInfo{Name: n, Description: d})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// sslRetryAfter parses Retry-After (delay-seconds or HTTP-date).
func sslRetryAfter(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	if secs, err := strconv.ParseUint(v, 10, 64); err == nil {
		return time.Now().Add(time.Duration(secs) * time.Second), true
	}
	t, err := http.ParseTime(v)
	return t, err == nil
}

// SslFetchAri fetches the ARI suggestion for the certificate at certPemPath;
// nil when unparseable, unsupported, or on transient failure (callers fall
// back to a static threshold).
func SslFetchAri(account *SslAccount, certPemPath string) *SslAriSuggestion {
	b, err := os.ReadFile(certPemPath)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil
	}
	id, err := sslCertIdentifier(block.Bytes)
	if err != nil || account.dir.RenewalInfo == "" {
		return nil
	}
	resp, err := sslHTTPGet(context.Background(), account.dir.RenewalInfo+"/"+id)
	if err != nil {
		slog.Debug(fmt.Sprintf("ARI fetch failed (%s): %v", certPemPath, err))
		return nil
	}
	defer resp.Body.Close()
	retryAt, ok := sslRetryAfter(resp.Header.Get("Retry-After"))
	if !ok || resp.StatusCode/100 != 2 {
		slog.Debug(fmt.Sprintf("ARI fetch failed (%s): HTTP %d", certPemPath, resp.StatusCode))
		return nil
	}
	var info struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil
	}
	delay := time.Until(retryAt)
	if delay < 0 {
		delay = 0
	}
	return &SslAriSuggestion{
		RenewalAt:     SslUtcTime(info.SuggestedWindow.Start.UTC()),
		RenewalBefore: SslUtcTime(info.SuggestedWindow.End.UTC()),
		RecheckAt:     SslUtcTime(time.Now().UTC().Add(delay)),
	}
}

// sslCertIdentifierFromPem builds the ARI identifier from the first PEM block.
func sslCertIdentifierFromPem(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", errors.New("no PEM certificate found")
	}
	id, err := sslCertIdentifier(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("cert identifier: %v", err)
	}
	return id, nil
}

// sslCertIdentifier is RFC 9773's base64url(AKI keyIdentifier) + "." +
// base64url(DER serial content bytes, as encoded — not a big-integer re-encoding).
func sslCertIdentifier(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %v", err)
	}
	if len(cert.AuthorityKeyId) == 0 {
		return "", errors.New("certificate does not contain an Authority Key Identifier (AKI) extension")
	}
	in := cryptobyte.String(cert.RawTBSCertificate)
	var tbs, serial cryptobyte.String
	if !in.ReadASN1(&tbs, cbasn1.SEQUENCE) ||
		!tbs.SkipOptionalASN1(cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.ReadASN1(&serial, cbasn1.INTEGER) {
		return "", errors.New("failed to parse certificate: malformed serial")
	}
	return sslB64(cert.AuthorityKeyId) + "." + sslB64(serial), nil
}

// ── Registered certificates (#104) ──────────────────────────────────────

// SslRegistryDir holds certificates registered BY NAME: one directory per
// alias with the same fullchain.pem + privkey.pem pair. A SIBLING root, not a
// subdirectory of the per-domain tree, and the placement is the design: the
// per-domain walks (cert listing, diagnostics, security scanner) treat every
// directory as a domain; unexpose deletes a domain's own directory; and the
// per-domain renew door (walked weekly since v2.161.0) can never reach a
// certificate the operator supplied. /etc/dockpanel is already writable.
const SslRegistryDir = "/etc/dockpanel/ssl-registry"

// SslCertMetadata is what a registered certificate says about itself.
type SslCertMetadata struct {
	// Names the leaf presents, through the same SAN-then-CN rule.
	DNSNames  []string  `json:"dns_names"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// SHA-256 of the leaf DER, lowercase hex (openssl's, minus the colons).
	FingerprintSha256 string `json:"fingerprint_sha256"`
}

// SslIsValidCertAlias: a DNS-label shape — lowercase letters, digits, inner
// hyphens, 1–64 bytes. It becomes a directory name and is spliced into a
// vhost, so it must pass the renderer's path check and can never spell `..`.
// Uppercase is refused, not folded: the panel stores the alias lowercase.
func SslIsValidCertAlias(alias string) bool {
	n := len(alias)
	if n == 0 || n > 64 {
		return false
	}
	edge := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	if !edge(alias[0]) || !edge(alias[n-1]) {
		return false
	}
	for i := 0; i < n; i++ {
		if !edge(alias[i]) && alias[i] != '-' {
			return false
		}
	}
	return true
}

// SslRegistryPaths returns (cert, key) for alias. One spelling for the
// uploader, the vhost renderer and the delete guard.
func SslRegistryPaths(alias string) (string, string) {
	return fmt.Sprintf("%s/%s/fullchain.pem", SslRegistryDir, alias), fmt.Sprintf("%s/%s/privkey.pem", SslRegistryDir, alias)
}

// SslCertMetadataOf describes the FIRST certificate block of a PEM (the leaf
// nginx binds). A pasted key is refused with the same sentence family.
func SslCertMetadataOf(certPEM string) (SslCertMetadata, error) {
	if !strings.Contains(certPEM, "-----BEGIN") {
		return SslCertMetadata{}, errors.New("no certificate was found in the certificate field.")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return SslCertMetadata{}, errors.New("the certificate could not be read: invalid PEM encoding")
	}
	if block.Type != "CERTIFICATE" {
		return SslCertMetadata{}, fmt.Errorf("the certificate field contains a %s block. Paste only the certificate here, with "+
			"its chain if it has one — the private key belongs in its own field, where it is "+
			"stored with the permissions a key needs.", strings.ToLower(block.Type))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return SslCertMetadata{}, fmt.Errorf("the certificate could not be read: %v", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return SslCertMetadata{
		DNSNames:          sslPresentedDNSNames(cert),
		Issuer:            sslNameString(cert.RawIssuer),
		NotBefore:         cert.NotBefore.UTC(),
		NotAfter:          cert.NotAfter.UTC(),
		FingerprintSha256: hex.EncodeToString(sum[:]),
	}, nil
}

// SslRFC3339 formats like chrono's DateTime::to_rfc3339 ("+00:00" suffix).
func SslRFC3339(t time.Time) string { return sslChronoRFC3339(t, "+00:00") }

// SslKeyMatchesCert: does this private key belong to this certificate? nginx
// only answers at `nginx -t`, and a registered certificate may have no vhost
// yet — a mismatched pair would look healthy until the first claim reloaded
// nginx into a refusal. Compares the key's public half with the leaf's.
func SslKeyMatchesCert(certPEM, keyPEM string) error {
	blocks, err := sslPemBlocks([]byte(certPEM))
	if err != nil {
		return fmt.Errorf("the certificate could not be read: %v", err)
	}
	var leafDER []byte
	for _, b := range blocks {
		if b.Type == "CERTIFICATE" {
			leafDER = b.Bytes
			break
		}
	}
	if leafDER == nil {
		return errors.New("no certificate was found in the certificate field.")
	}
	kblocks, err := sslPemBlocks([]byte(keyPEM))
	if err != nil {
		return fmt.Errorf("the private key could not be read: %v", err)
	}
	var kb *pem.Block
	for _, b := range kblocks {
		if b.Type == "PRIVATE KEY" || b.Type == "RSA PRIVATE KEY" || b.Type == "EC PRIVATE KEY" {
			kb = b
			break
		}
	}
	if kb == nil {
		return errors.New("no private key was found in the private key field. Paste the PEM-encoded key " +
			"(a PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY block) that was generated with " +
			"this certificate.")
	}
	var key any
	switch kb.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
	default:
		key, err = x509.ParseECPrivateKey(kb.Bytes)
	}
	signer, ok := key.(crypto.Signer)
	if err != nil || !ok {
		if err == nil {
			err = errors.New("unsupported key type")
		}
		return fmt.Errorf("the private key is not a kind nginx can serve with: %v", err)
	}
	cert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("the certificate could not be read: %v", err)
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return errors.New("the private key could not be compared against the certificate; it is not a kind " +
			"nginx can serve with")
	}
	if !pub.Equal(cert.PublicKey) {
		return errors.New("the private key does not belong to this certificate")
	}
	return nil
}
