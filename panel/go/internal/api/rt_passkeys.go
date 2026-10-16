package api

// Port of panel/backend/src/routes/passkeys.rs — WebAuthn registration and
// authentication (ES256 / P-256 only, attestation "none").

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// ─── Challenge State ───────────────────────────────────────────

// rtPasskeysChallenge is one outstanding ceremony. Registration challenges
// carry the user they were issued to; authentication challenges carry nothing.
type rtPasskeysChallenge struct {
	Registration bool
	UserID       uuid.UUID
	UserEmail    string
	Created      time.Time
}

// In-memory challenge store with 5-minute TTL, keyed by the base64url
// challenge (Rust AppState.passkey_challenges — module-owned here).
var (
	rtPasskeysChallengesMu sync.Mutex
	rtPasskeysChallenges   = map[string]rtPasskeysChallenge{}
)

// rtPasskeysPurgeExpired purges expired challenges (>5 min old). Called on
// each operation. Also enforces a max size of 10,000 entries to prevent
// memory exhaustion via rapid challenge generation.
func rtPasskeysPurgeExpired() {
	rtPasskeysChallengesMu.Lock()
	defer rtPasskeysChallengesMu.Unlock()
	now := time.Now()
	for k, c := range rtPasskeysChallenges {
		if now.Sub(c.Created) >= 300*time.Second {
			delete(rtPasskeysChallenges, k)
		}
	}
	if len(rtPasskeysChallenges) > 10_000 {
		excess := len(rtPasskeysChallenges) - 5_000
		for k := range rtPasskeysChallenges {
			if excess == 0 {
				break
			}
			delete(rtPasskeysChallenges, k)
			excess--
		}
	}
}

func rtPasskeysStoreChallenge(key string, c rtPasskeysChallenge) {
	rtPasskeysChallengesMu.Lock()
	rtPasskeysChallenges[key] = c
	rtPasskeysChallengesMu.Unlock()
}

func rtPasskeysTakeChallenge(key string) (rtPasskeysChallenge, bool) {
	rtPasskeysChallengesMu.Lock()
	defer rtPasskeysChallengesMu.Unlock()
	c, ok := rtPasskeysChallenges[key]
	if ok {
		delete(rtPasskeysChallenges, key)
	}
	return c, ok
}

// ─── Request / Response types ──────────────────────────────────

type rtPasskeysCredentialDescriptor struct {
	Type       string    `json:"type"`
	ID         string    `json:"id"`
	Transports *[]string `json:"transports"`
}

type rtPasskeysCreationOptions struct {
	Rp struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	Challenge        string `json:"challenge"`
	PubKeyCredParams []struct {
		Type string `json:"type"`
		Alg  int32  `json:"alg"`
	} `json:"pubKeyCredParams"`
	Timeout                uint64 `json:"timeout"`
	Attestation            string `json:"attestation"`
	AuthenticatorSelection struct {
		AuthenticatorAttachment *string `json:"authenticatorAttachment"`
		ResidentKey             string  `json:"residentKey"`
		RequireResidentKey      bool    `json:"requireResidentKey"`
		UserVerification        string  `json:"userVerification"`
	} `json:"authenticatorSelection"`
	ExcludeCredentials []rtPasskeysCredentialDescriptor `json:"excludeCredentials"`
}

type rtPasskeysRequestOptions struct {
	Challenge        string                           `json:"challenge"`
	Timeout          uint64                           `json:"timeout"`
	RpID             string                           `json:"rpId"`
	AllowCredentials []rtPasskeysCredentialDescriptor `json:"allowCredentials"`
	UserVerification string                           `json:"userVerification"`
}

type rtPasskeysRegisterCompleteRequest struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Response struct {
		AttestationObject string `json:"attestationObject"`
		ClientDataJSON    string `json:"clientDataJson"`
	} `json:"response"`
	Name       *string   `json:"name"`
	Transports *[]string `json:"transports"`
}

type rtPasskeysAuthCompleteRequest struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Response struct {
		AuthenticatorData string  `json:"authenticatorData"`
		ClientDataJSON    string  `json:"clientDataJson"`
		Signature         string  `json:"signature"`
		UserHandle        *string `json:"userHandle"`
	} `json:"response"`
}

func rtPasskeysRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("POST /api/auth/passkey/register/begin", h(rtPasskeysRegisterBegin))
	r.Handle("POST /api/auth/passkey/register/complete", h(rtPasskeysRegisterComplete))
	r.Handle("POST /api/auth/passkey/auth/begin", h(rtPasskeysAuthBegin))
	r.Handle("POST /api/auth/passkey/auth/complete", h(rtPasskeysAuthComplete))
	r.Handle("GET /api/auth/passkeys", h(rtPasskeysListPasskeys))
	r.Handle("DELETE /api/auth/passkeys/{id}", h(rtPasskeysDeletePasskey))
	r.Handle("PUT /api/auth/passkeys/{id}", h(rtPasskeysRenamePasskey))
}

// ─── Helpers ───────────────────────────────────────────────────

// rtPasskeysB64 is base64 URL_SAFE_NO_PAD with the base64 crate's strictness:
// no padding, no non-canonical trailing bits, and no embedded CR/LF (which
// Go's decoder would otherwise silently skip).
func rtPasskeysB64Decode(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("invalid byte")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

func rtPasskeysGenerateChallenge() []byte {
	c := make([]byte, 32)
	_, _ = rand.Read(c)
	return c
}

// rtPasskeysHostStr is url::Url::parse(s).host_str(): the lower-cased host
// of an absolute URL with an authority, IPv6 kept in brackets.
func rtPasskeysHostStr(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	h := u.Hostname()
	if h == "" {
		return "", false
	}
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return strings.ToLower(h), true
}

func rtPasskeysNoRP() error {
	return apiErr(http.StatusBadRequest, "Cannot determine relying party — request has neither an Origin nor a Host header")
}

// rtPasskeysRPID extracts the RP ID for WebAuthn.
//
// ⚠ SECURITY: prefers server-side BASE_URL config (trusted) — but when it is
// unset (a legitimate, common configuration for IP-based access) this falls
// back to the client-supplied Origin header. That fallback does NOT, by
// itself, prevent RP ID manipulation. What actually prevents exploitation is
// downstream and unconditional: the complete handlers compare the CLIENT's
// signed clientDataJSON.origin — set by the browser from the page's real
// origin and covered by the authenticator's signature — against what this
// returned. An attacker who can only forge HTTP headers fails that comparison
// every time.
//
// What DOES fail closed: a request with NEITHER an Origin NOR a Host header
// has no signal left (no browser-driven ceremony omits both), so this refuses
// instead of falling back to a hardcoded "localhost".
func rtPasskeysRPID(r *http.Request, st *AppState) (string, error) {
	if st.Config.BaseURL != "" {
		if h, ok := rtPasskeysHostStr(st.Config.BaseURL); ok {
			return h, nil
		}
	}
	if o := r.Header.Values("Origin"); len(o) > 0 {
		if h, ok := rtPasskeysHostStr(o[0]); ok {
			return h, nil
		}
	}
	if r.Host != "" {
		h, _, _ := strings.Cut(r.Host, ":")
		return h, nil
	}
	return "", rtPasskeysNoRP()
}

// rtPasskeysRPOrigin extracts the origin for the clientDataJSON.origin
// comparison. Same trust model and the same fail-closed rule as rtPasskeysRPID.
func rtPasskeysRPOrigin(r *http.Request, st *AppState) (string, error) {
	if st.Config.BaseURL != "" {
		return strings.TrimRight(st.Config.BaseURL, "/"), nil
	}
	if o := r.Header.Values("Origin"); len(o) > 0 {
		return strings.TrimRight(o[0], "/"), nil
	}
	if r.Host != "" {
		h, _, _ := strings.Cut(r.Host, ":")
		return "https://" + h, nil
	}
	return "", rtPasskeysNoRP()
}

// rtPasskeysParseAuthData parses attestation authData:
// rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ [AT: aaguid(16) ‖ credIdLen(2) ‖
// credId ‖ COSE key]. Returns (credential_id, cose_key_cbor, aaguid).
func rtPasskeysParseAuthData(authData []byte) ([]byte, []byte, [16]byte, error) {
	var aaguid [16]byte
	if len(authData) < 37 {
		return nil, nil, aaguid, errors.New("authData too short")
	}
	if authData[32]&0x40 == 0 {
		return nil, nil, aaguid, errors.New("No attested credential data in authData")
	}
	if len(authData) < 55 {
		return nil, nil, aaguid, errors.New("authData too short for attested data")
	}
	copy(aaguid[:], authData[37:53])
	credIDLen := int(binary.BigEndian.Uint16(authData[53:55]))
	if len(authData) < 55+credIDLen+1 {
		return nil, nil, aaguid, errors.New("authData too short for credential ID")
	}
	credID := append([]byte(nil), authData[55:55+credIDLen]...)
	cose := append([]byte(nil), authData[55+credIDLen:]...)
	return credID, cose, aaguid, nil
}

// rtPasskeysCBORInt is ciborium's Integer → i128 → `as i32` (truncating), for
// a decoded CBOR value; ok=false when it is not an integer.
func rtPasskeysCBORInt(v any) (int32, bool) {
	switch k := v.(type) {
	case uint64:
		return int32(uint32(k)), true
	case int64:
		return int32(uint32(k)), true
	}
	return 0, false
}

// rtPasskeysParseCOSEP256 parses a COSE key (CBOR map) and extracts the P-256
// public key: -2 (x) and -3 (y), 32 bytes each, which must be on the curve.
// Trailing bytes after the first CBOR item are ignored, as ciborium's
// from_reader did.
func rtPasskeysParseCOSEP256(b []byte) (*ecdsa.PublicKey, error) {
	var value any
	if _, err := cbor.UnmarshalFirst(b, &value); err != nil {
		return nil, fmt.Errorf("CBOR parse error: %v", err)
	}
	m, ok := value.(map[any]any)
	if !ok {
		return nil, errors.New("COSE key is not a map")
	}
	var x, y []byte
	for k, v := range m {
		ki, ok := rtPasskeysCBORInt(k)
		if !ok {
			continue
		}
		switch ki {
		case -2:
			if bs, ok := v.([]byte); ok {
				x = bs
			}
		case -3:
			if bs, ok := v.([]byte); ok {
				y = bs
			}
		}
	}
	if x == nil {
		return nil, errors.New("Missing x coordinate in COSE key")
	}
	if y == nil {
		return nil, errors.New("Missing y coordinate in COSE key")
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, errors.New("Invalid coordinate length")
	}
	// Uncompressed point: 0x04 || x || y — rejected unless on the curve.
	point := append(append([]byte{0x04}, x...), y...)
	pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("Invalid P-256 key: %v", err)
	}
	return pk, nil
}

// rtPasskeysParseDERSignature is p256 Signature::from_der: a strict DER
// SEQUENCE { INTEGER r, INTEGER s } with both scalars in [1, n-1].
func rtPasskeysParseDERSignature(der []byte) (*big.Int, *big.Int, error) {
	var inner cryptobyte.String
	in := cryptobyte.String(der)
	r, s := new(big.Int), new(big.Int)
	if !in.ReadASN1(&inner, asn1.SEQUENCE) || !in.Empty() ||
		!inner.ReadASN1Integer(r) || !inner.ReadASN1Integer(s) || !inner.Empty() {
		return nil, nil, errors.New("malformed DER signature")
	}
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return nil, nil, errors.New("signature scalar out of range")
	}
	return r, s, nil
}

// rtPasskeysCounterRegressed: whether an assertion's signature counter says
// the authenticator was cloned.
//
// WebAuthn L2 §7.2 applies the comparison when *either* side is non-zero.
// This panel tested both with `&&` until v2.86.0, which exempted the one shape
// that matters: a stored counter above zero presented with **zero**. That is
// the cheapest forgery — send 0 and be waved through, and the accepted
// assertion then writes 0 back, so the real device's next login looks like a
// fresh increment. Authenticators with no counter (synced passkeys) report
// zero on both sides forever; `||` still exempts them.
func rtPasskeysCounterRegressed(stored, presented int64) bool {
	return (stored > 0 || presented > 0) && presented <= stored
}

func rtPasskeysRecordAttempt(st *AppState, ip string) {
	st.LoginMu.Lock()
	st.LoginAttempts[ip] = append(st.LoginAttempts[ip], time.Now())
	st.LoginMu.Unlock()
}

// rtPasskeysClientData decodes clientDataJSON (base64url → any JSON).
func rtPasskeysClientData(encoded string) ([]byte, any, error) {
	raw, err := rtPasskeysB64Decode(encoded)
	if err != nil {
		return nil, nil, apiErr(http.StatusBadRequest, "Invalid clientDataJSON encoding")
	}
	var cd any
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, nil, apiErr(http.StatusBadRequest, "Invalid clientDataJSON")
	}
	return raw, cd, nil
}

func rtPasskeysStr(v any, key string) string {
	s, _ := jsonStr(jsonGet(v, key))
	return s
}

// ─── Registration Endpoints ────────────────────────────────────

// rtPasskeysRegisterBegin — POST /api/auth/passkey/register/begin.
//
// Guarded by rtAuthRequireEnrolmentProof: a session alone is not enough to
// plant a credential that outlives every reset this panel offers. Checked
// HERE rather than at complete because this is the only place a registration
// challenge is constructed, and asking again after the browser's own WebAuthn
// dialog would prompt twice for one act.
//
// The body is optional by design — the first request carries no proof, and
// the refusal it earns tells the card which fields to collect. With no
// Content-Type at all it reads as "no proof" (axum's Option<Json<T>>), rather
// than a 415 carrying no code the client could branch on.
func rtPasskeysRegisterBegin(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	proof := &rtAuthEnrolmentProof{}
	if len(r.Header.Values("Content-Type")) > 0 {
		if err := decodeJSON(r, proof); err != nil {
			return err
		}
	}
	ctx := r.Context()
	rtPasskeysPurgeExpired()

	user, err := queryOne[User](ctx, st.DB, "SELECT * FROM users WHERE id = $1", claims.Sub)
	if err != nil {
		return internalError("passkey register", err)
	}

	if err := rtAuthRequireEnrolmentProof(ctx, st, claims, &user, proof); err != nil {
		// A rejected proof is worth a trail; a bare challenge is not an event.
		if proof.Code != nil || proof.CurrentPassword != nil {
			ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "passkey.reauth_failed", new("passkey"), nil, nil, nil, claims.KeyID)
			SecurityHardeningAuditLog(ctx, st.DB, "passkey.reauth_failed", &claims.Email, nil, new("passkey"), nil, nil, nil, "warning", claims.KeyID)
		}
		return err
	}

	rpID, err := rtPasskeysRPID(r, st)
	if err != nil {
		return err
	}

	// Existing passkeys to exclude
	existing, err := queryAll[Tup2[string, *string]](ctx, st.DB, "SELECT credential_id, transports FROM passkeys WHERE user_id = $1", claims.Sub)
	if err != nil {
		return internalError("passkey register", err)
	}
	exclude := make([]rtPasskeysCredentialDescriptor, 0, len(existing))
	for _, e := range existing {
		d := rtPasskeysCredentialDescriptor{Type: "public-key", ID: e.A}
		if e.B != nil {
			t := strings.Split(*e.B, ",")
			d.Transports = &t
		}
		exclude = append(exclude, d)
	}

	challenge := base64.RawURLEncoding.EncodeToString(rtPasskeysGenerateChallenge())
	rtPasskeysStoreChallenge(challenge, rtPasskeysChallenge{Registration: true, UserID: claims.Sub, UserEmail: claims.Email, Created: time.Now()})

	var opts rtPasskeysCreationOptions
	opts.Rp.Name, opts.Rp.ID = "DockPanel", rpID
	opts.User.ID = base64.RawURLEncoding.EncodeToString(claims.Sub[:])
	opts.User.Name, opts.User.DisplayName = claims.Email, claims.Email
	opts.Challenge = challenge
	opts.PubKeyCredParams = append(opts.PubKeyCredParams, struct {
		Type string `json:"type"`
		Alg  int32  `json:"alg"`
	}{"public-key", -7}) // ES256 (P-256)
	opts.Timeout = 300_000 // 5 minutes
	opts.Attestation = "none"
	opts.AuthenticatorSelection.ResidentKey = "preferred"
	opts.AuthenticatorSelection.UserVerification = "preferred"
	opts.ExcludeCredentials = exclude

	writeJSON(w, http.StatusOK, map[string]any{"publicKey": opts})
	return nil
}

// rtPasskeysRegisterComplete — POST /api/auth/passkey/register/complete.
func rtPasskeysRegisterComplete(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtPasskeysRegisterCompleteRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	rtPasskeysPurgeExpired()

	rpID, err := rtPasskeysRPID(r, st)
	if err != nil {
		return err
	}
	rpOrigin, err := rtPasskeysRPOrigin(r, st)
	if err != nil {
		return err
	}

	_, cd, err := rtPasskeysClientData(body.Response.ClientDataJSON)
	if err != nil {
		return err
	}
	if rtPasskeysStr(cd, "type") != "webauthn.create" {
		return apiErr(http.StatusBadRequest, "Invalid ceremony type")
	}

	// Verify challenge (consumed whatever happens next)
	ch, ok := rtPasskeysTakeChallenge(rtPasskeysStr(cd, "challenge"))
	if !ok {
		return apiErr(http.StatusBadRequest, "Unknown or expired challenge")
	}
	// It must be a registration challenge for this user
	if !ch.Registration {
		return apiErr(http.StatusBadRequest, "Wrong challenge type")
	}
	if ch.UserID != claims.Sub {
		return apiErr(http.StatusBadRequest, "Challenge user mismatch")
	}

	if rtPasskeysStr(cd, "origin") != rpOrigin {
		return apiErr(http.StatusBadRequest, "Origin mismatch")
	}

	// Decode attestationObject (CBOR)
	attBytes, err := rtPasskeysB64Decode(body.Response.AttestationObject)
	if err != nil {
		return apiErr(http.StatusBadRequest, "Invalid attestationObject encoding")
	}
	var att any
	if _, err := cbor.UnmarshalFirst(attBytes, &att); err != nil {
		return apiErr(http.StatusBadRequest, "Invalid attestationObject CBOR")
	}
	var authData []byte
	if m, ok := att.(map[any]any); ok {
		if b, ok := m["authData"].([]byte); ok {
			authData = b
		}
	}
	if authData == nil {
		return apiErr(http.StatusBadRequest, "Missing authData in attestation")
	}

	// Verify rpIdHash.
	//
	// ⚠ The bound is 37, not 32, and the difference is a panic: authData is
	// rpIdHash(32) ‖ flags(1) ‖ signCount(4), so admitting a 32-byte buffer
	// lets the next line index [32] out of bounds — with an attacker-chosen
	// payload, because SHA256(rp_id) is public. The twin in auth complete has
	// always used 37; the asymmetry between the two doors WAS the bug.
	want := sha256.Sum256([]byte(rpID))
	if len(authData) < 37 || string(authData[:32]) != string(want[:]) {
		return apiErr(http.StatusBadRequest, "RP ID hash mismatch")
	}

	flags := authData[32]
	if flags&0x01 == 0 {
		return apiErr(http.StatusBadRequest, "User not present")
	}

	credID, cose, aaguid, err := rtPasskeysParseAuthData(authData)
	if err != nil {
		slog.Warn("Passkey authData parse error: " + err.Error())
		return apiErr(http.StatusBadRequest, "Invalid attestation data")
	}
	if _, err := rtPasskeysParseCOSEP256(cose); err != nil {
		slog.Warn("Passkey invalid public key: " + err.Error())
		return apiErr(http.StatusBadRequest, "Invalid credential key")
	}

	signCount := int64(binary.BigEndian.Uint32(authData[33:37]))

	// Whether THIS ceremony's authenticator performed user verification (PIN,
	// fingerprint, face) rather than mere presence. Recorded once, here,
	// because UV is a property of the ceremony — nothing else this row holds
	// can answer it later. Auth complete re-checks this bit on every future
	// login for this credential, but ONLY if it is true here (grandfathering).
	uvCapable := flags&0x04 != 0

	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)
	aaguidHex := hex.EncodeToString(aaguid[:])
	var transports *string
	if body.Transports != nil {
		t := strings.Join(*body.Transports, ",")
		transports = &t
	}
	name := "My Passkey"
	if body.Name != nil {
		name = *body.Name
	}

	// Limit: max 10 passkeys per user
	count, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM passkeys WHERE user_id = $1", claims.Sub)
	if err != nil {
		return internalError("passkey count", err)
	}
	if count >= 10 {
		return apiErr(http.StatusBadRequest, "Maximum 10 passkeys per account")
	}

	passkeyID, err := queryScalar[uuid.UUID](ctx, st.DB,
		"INSERT INTO passkeys (user_id, credential_id, public_key_cbor, sign_count, name, transports, aaguid, uv_capable) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
		claims.Sub, credIDB64, cose, signCount, name, transports, aaguidHex, uvCapable)
	if err != nil {
		return internalError("store passkey", err)
	}

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "passkey.registered", new("passkey"), &name, nil, nil, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "passkey.registered", &claims.Email, nil, new("passkey"), &name, nil, nil, "warning", claims.KeyID)

	// Tell the OWNER, not the admins. A planted credential is durable mainly
	// because it is silent: the activity log is not a surface anyone watches,
	// and no reset removes the row. A nil user here would notify every
	// administrator — everyone except the person affected.
	NotificationsNotifyPanel(ctx, st.DB, &claims.Sub, "New passkey added",
		fmt.Sprintf("A passkey named \"%s\" was added to your account. If this wasn't you, remove it in My Account and change your password.", name),
		"warning", "security", new("/account"))

	slog.Info(fmt.Sprintf("Passkey registered for user %s (%s)", claims.Email, credIDB64))

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": passkeyID, "name": name})
	return nil
}

// ─── Authentication Endpoints ──────────────────────────────────

// rtPasskeysAuthBegin — POST /api/auth/passkey/auth/begin.
func rtPasskeysAuthBegin(st *AppState, w http.ResponseWriter, r *http.Request) error {
	// Refuse before handing out a challenge, so an excluded address gets the
	// same answer here as at the password door.
	if err := rtAuthEnforcePanelIPAllowlist(r.Context(), st, r); err != nil {
		return err
	}
	rtPasskeysPurgeExpired()

	rpID, err := rtPasskeysRPID(r, st)
	if err != nil {
		return err
	}
	challenge := base64.RawURLEncoding.EncodeToString(rtPasskeysGenerateChallenge())
	rtPasskeysStoreChallenge(challenge, rtPasskeysChallenge{Created: time.Now()})

	writeJSON(w, http.StatusOK, map[string]any{"publicKey": rtPasskeysRequestOptions{
		Challenge: challenge, Timeout: 300_000, RpID: rpID,
		AllowCredentials: []rtPasskeysCredentialDescriptor{}, // empty = discoverable credential
		UserVerification: "preferred",
	}})
	return nil
}

// rtPasskeysAuthComplete — POST /api/auth/passkey/auth/complete: finish the
// ceremony and issue a session.
func rtPasskeysAuthComplete(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var body rtPasskeysAuthCompleteRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	rtPasskeysPurgeExpired()

	// The IP allowlist gates the panel, not one handler: this door mints the
	// same session cookie as the password door, so it owes the same check.
	if err := rtAuthEnforcePanelIPAllowlist(ctx, st, r); err != nil {
		return err
	}
	rpID, err := rtPasskeysRPID(r, st)
	if err != nil {
		return err
	}
	rpOrigin, err := rtPasskeysRPOrigin(r, st)
	if err != nil {
		return err
	}

	// Rate limit passkey auth: reuse login_attempts (same IP-based)
	ip := rtAuthRealIP(r)
	st.LoginMu.Lock()
	entry := rtAuthRetain(st.LoginAttempts[ip], time.Now(), 900*time.Second)
	st.LoginAttempts[ip] = entry
	limited := len(entry) >= 5
	st.LoginMu.Unlock()
	if limited {
		return apiErr(http.StatusTooManyRequests, "Too many login attempts. Try again in 15 minutes.")
	}

	clientData, cd, err := rtPasskeysClientData(body.Response.ClientDataJSON)
	if err != nil {
		return err
	}
	if rtPasskeysStr(cd, "type") != "webauthn.get" {
		return apiErr(http.StatusBadRequest, "Invalid ceremony type")
	}
	ch, ok := rtPasskeysTakeChallenge(rtPasskeysStr(cd, "challenge"))
	if !ok {
		return apiErr(http.StatusBadRequest, "Unknown or expired challenge")
	}
	// The challenge must be one THIS door issued. No attack is known through
	// this gap — the account comes from credential_id, so a registration
	// challenge buys its holder only the session they could already mint —
	// but register complete has always rejected the wrong variant, and a third
	// variant added later would otherwise be accepted here by default.
	if ch.Registration {
		return apiErr(http.StatusBadRequest, "Wrong challenge type")
	}
	if rtPasskeysStr(cd, "origin") != rpOrigin {
		return apiErr(http.StatusBadRequest, "Origin mismatch")
	}

	// Look up the credential
	credID := body.ID
	pk, err := queryOpt[Tup5[uuid.UUID, uuid.UUID, []byte, int64, bool]](ctx, st.DB,
		"SELECT id, user_id, public_key_cbor, sign_count, uv_capable FROM passkeys WHERE credential_id = $1", credID)
	if err != nil {
		return internalError("passkey lookup", err)
	}
	if pk == nil {
		rtPasskeysRecordAttempt(st, ip)
		return apiErr(http.StatusUnauthorized, "Unknown credential")
	}
	passkeyID, userID, cose, storedCount, uvCapable := pk.A, pk.B, pk.C, pk.D, pk.E

	authData, err := rtPasskeysB64Decode(body.Response.AuthenticatorData)
	if err != nil {
		return apiErr(http.StatusBadRequest, "Invalid authenticatorData encoding")
	}
	want := sha256.Sum256([]byte(rpID))
	if len(authData) < 37 || string(authData[:32]) != string(want[:]) {
		return apiErr(http.StatusBadRequest, "RP ID hash mismatch")
	}
	flags := authData[32]
	if flags&0x01 == 0 {
		return apiErr(http.StatusBadRequest, "User not present")
	}

	// Read the signature counter. The regression test it feeds runs AFTER the
	// signature is verified — see below for why that order is the whole point.
	newCount := int64(binary.BigEndian.Uint32(authData[33:37]))

	// Verify signature: sig over (authData || SHA256(clientDataJSON))
	cdHash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), authData...), cdHash[:]...)

	pub, err := rtPasskeysParseCOSEP256(cose)
	if err != nil {
		slog.Error("Passkey stored key invalid: " + err.Error())
		return apiErr(http.StatusInternalServerError, "Authentication failed")
	}
	sigBytes, err := rtPasskeysB64Decode(body.Response.Signature)
	if err != nil {
		return apiErr(http.StatusBadRequest, "Invalid signature encoding")
	}
	// WebAuthn signatures are DER-encoded
	sr, ss, err := rtPasskeysParseDERSignature(sigBytes)
	if err != nil {
		return apiErr(http.StatusUnauthorized, "Invalid signature format")
	}
	digest := sha256.Sum256(signed)
	if !ecdsa.Verify(pub, digest[:], sr, ss) {
		rtPasskeysRecordAttempt(st, ip)
		return apiErr(http.StatusUnauthorized, "Signature verification failed")
	}

	// Require user verification back from any credential that proved it could
	// give one. Deliberately AFTER the signature verify: flags lives inside
	// authData, which is exactly what the signature covers, so trusting the
	// UV bit first would let an attacker learn this credential's UV
	// requirement from forged, unauthenticated assertions.
	//
	// uv_capable is read from the credential's OWN registration ceremony,
	// never assumed — a credential registered before the column existed, or
	// whose authenticator never demonstrated a PIN/biometric at enrolment, is
	// left as possession-only as it always was. That is the grandfathering:
	// only a credential that has ALREADY proven it can verify its holder is
	// asked to prove it again.
	if uvCapable && flags&0x04 == 0 {
		slog.Warn("Passkey UV requirement not met for credential " + credID)
		rtPasskeysRecordAttempt(st, ip)
		email, _ := queryScalarOpt[string](ctx, st.DB, "SELECT email FROM users WHERE id = $1", userID)
		SecurityHardeningAuditLog(ctx, st.DB, "passkey.uv_not_provided", email, &ip, new("passkey"), &credID, nil, nil, "warning", nil)
		return apiErr(http.StatusUnauthorized, "This passkey requires verification (PIN, fingerprint, or face) that wasn't provided")
	}

	// Check sign counter (anti-cloning) — deliberately AFTER the signature,
	// which is where WebAuthn L2 §7.2 puts it and what makes this refusal mean
	// anything. Above the verify, it fired on forged authData carrying a
	// garbage signature — everything needed is public (challenges, rpIdHash,
	// the UP bit) except a credential id a passive observer has — and it
	// returned WITHOUT recording an attempt: an unthrottled probe, and wiring
	// an alert to it would have built a fabricated-alert writer.
	if rtPasskeysCounterRegressed(storedCount, newCount) {
		slog.Warn(fmt.Sprintf("Passkey counter regression for credential %s: stored=%d, new=%d", credID, storedCount, newCount))
		rtPasskeysRecordAttempt(st, ip)
		// audit_log, never record_suspicious_event: that auto-activates
		// system-wide lockdown at five events in ten minutes, so a cloned key
		// could lock every non-admin out by simply continuing to fail.
		email, _ := queryScalarOpt[string](ctx, st.DB, "SELECT email FROM users WHERE id = $1", userID)
		d := fmt.Sprintf("stored=%d, presented=%d", storedCount, newCount)
		SecurityHardeningAuditLog(ctx, st.DB, "passkey.counter_regression", email, &ip, new("passkey"), &credID, &d, nil, "warning", nil)
		return apiErr(http.StatusUnauthorized, "Credential may be cloned")
	}

	// Update counter. `AND $1 > sign_count` closes the window between the read
	// above and this write: with two assertions in flight the lower one could
	// otherwise land last and walk the stored counter backwards.
	_, _ = execSQL(ctx, st.DB, "UPDATE passkeys SET sign_count = $1 WHERE id = $2 AND $1 > sign_count", newCount, passkeyID)

	user, err := queryOpt[User](ctx, st.DB, "SELECT * FROM users WHERE id = $1", userID)
	if err != nil {
		return internalError("passkey user lookup", err)
	}
	if user == nil {
		return apiErr(http.StatusUnauthorized, "User not found")
	}
	if user.Role == "suspended" {
		return apiErr(http.StatusForbidden, "Account suspended")
	}
	// Check approval (field not in User model, query DB directly)
	if approved, err := queryScalarOpt[bool](ctx, st.DB, "SELECT COALESCE(approved, TRUE) FROM users WHERE id = $1", user.ID); err == nil && approved != nil && !*approved {
		return apiErr(http.StatusForbidden, "Account pending admin approval")
	}
	if user.Role != "admin" && SecurityHardeningIsLockedDown(ctx, st.DB) {
		return apiErr(http.StatusServiceUnavailable, "System is in lockdown mode")
	}

	st.LoginMu.Lock()
	delete(st.LoginAttempts, ip)
	st.LoginMu.Unlock()

	// Passkey login skips the separate TOTP step (the passkey IS the second
	// factor) — and since uv_capable that claim is enforced rather than
	// assumed (the UV check above).
	_, cookie, jti, err := rtAuthIssueSession(st, user, r)
	if err != nil {
		return err
	}
	_, _ = execSQL(ctx, st.DB, "INSERT INTO user_sessions (user_id, jti, ip_address, user_agent) VALUES ($1, $2, $3, $4)",
		user.ID, jti, ip, rtAuthUserAgent(r))

	ActivityLogActivity(ctx, st.DB, user.ID, user.Email, "auth.passkey_login", nil, nil, nil, &ip, nil)
	SecurityHardeningAuditLog(ctx, st.DB, "passkey_login", &user.Email, &ip, new("user"), nil, nil, nil, "info", nil)

	slog.Info("Passkey login for user " + user.Email)

	w.Header().Set("Set-Cookie", cookie)
	writeJSON(w, http.StatusOK, map[string]any{"user": map[string]any{"id": user.ID, "email": user.Email, "role": user.Role}})
	return nil
}

// ─── Passkey Management ────────────────────────────────────────

// rtPasskeysListPasskeys — GET /api/auth/passkeys.
func rtPasskeysListPasskeys(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	rows, err := queryAll[Tup6[uuid.UUID, string, *string, *string, time.Time, bool]](r.Context(), st.DB,
		"SELECT id, name, transports, aaguid, created_at, uv_capable FROM passkeys WHERE user_id = $1 ORDER BY created_at", claims.Sub)
	if err != nil {
		return internalError("list passkeys", err)
	}
	items := make([]any, 0, len(rows))
	for _, p := range rows {
		items = append(items, map[string]any{
			"id": p.A, "name": p.B, "transports": p.C, "aaguid": p.D, "created_at": p.E, "uvCapable": p.F,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": items})
	return nil
}

// rtPasskeysDeletePasskey — DELETE /api/auth/passkeys/{id}.
func rtPasskeysDeletePasskey(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	n, err := execSQL(ctx, st.DB, "DELETE FROM passkeys WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("delete passkey", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Passkey not found")
	}
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "passkey.deleted", new("passkey"), nil, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "passkey.deleted", &claims.Email, ip, new("passkey"), nil, nil, nil, "warning", claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtPasskeysRenamePasskey — PUT /api/auth/passkeys/{id}.
func rtPasskeysRenamePasskey(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	name, _ := jsonStr(jsonGet(body, "name"))
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 255 {
		return apiErr(http.StatusBadRequest, "Name must be 1-255 characters")
	}
	n, err := execSQL(ctx, st.DB, "UPDATE passkeys SET name = $1 WHERE id = $2 AND user_id = $3", name, id, claims.Sub)
	if err != nil {
		return internalError("rename passkey", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Passkey not found")
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "passkey.renamed", new("passkey"), &name, nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}
