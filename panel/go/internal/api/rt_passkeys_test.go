package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// This file had no tests at all in Rust until v2.86.0. The pure-function
// truth tables are ported below; the guard ORDER and the byte bound that used
// to panic are pinned by the virtual-authenticator handler test at the end
// (Rust: src/bin/passkey_virtual_authenticator.rs + tests/*.sh).

// ── counter_regressed: the whole truth table ────────────────────────────

func TestRtPasskeysCounterNeverIncrementedIsNotAClone(t *testing.T) {
	// Counterless authenticators (synced passkeys) report zero forever.
	if rtPasskeysCounterRegressed(0, 0) {
		t.Fatal()
	}
}

func TestRtPasskeysFirstIncrementFromZeroIsAccepted(t *testing.T) {
	for _, n := range []int64{1, 42, math.MaxUint32} {
		if rtPasskeysCounterRegressed(0, n) {
			t.Fatal(n)
		}
	}
}

func TestRtPasskeysNormalIncrementIsAccepted(t *testing.T) {
	for _, c := range [][2]int64{{1, 2}, {41, 42}, {math.MaxUint32 - 1, math.MaxUint32}} {
		if rtPasskeysCounterRegressed(c[0], c[1]) {
			t.Fatal(c)
		}
	}
}

func TestRtPasskeysZeroPresentedAgainstALiveCounterIsAClone(t *testing.T) {
	// THE REGRESSION v2.86.0 CLOSED: the old `&&` waved every one through.
	for _, s := range []int64{1, 42, math.MaxUint32} {
		if !rtPasskeysCounterRegressed(s, 0) {
			t.Fatal(s)
		}
	}
}

func TestRtPasskeysRepeatOrRewindIsAClone(t *testing.T) {
	for _, c := range [][2]int64{{42, 42}, {42, 41}, {42, 1}} {
		if !rtPasskeysCounterRegressed(c[0], c[1]) {
			t.Fatal(c)
		}
	}
}

// ── parse_auth_data: the length ladder ──────────────────────────────

func rtPasskeysTestAuthData(flags byte, extra []byte) []byte {
	v := make([]byte, 32)
	for i := range v {
		v[i] = 0xAA
	}
	v = append(v, flags, 0, 0, 0, 1)
	return append(v, extra...)
}

func TestRtPasskeysAuthDataShorterThanTheFixedHeaderIsRejected(t *testing.T) {
	for _, n := range []int{0, 1, 31, 32, 36} {
		if _, _, _, err := rtPasskeysParseAuthData(make([]byte, n)); err == nil {
			t.Fatalf("a %d-byte authData must not parse: the fixed header is 37 bytes", n)
		}
	}
}

func TestRtPasskeysAttestedCredentialDataFlagIsRequired(t *testing.T) {
	if _, _, _, err := rtPasskeysParseAuthData(rtPasskeysTestAuthData(0x01, nil)); err == nil {
		t.Fatal()
	}
}

func TestRtPasskeysAttestedFlagWithoutThePayloadIsRejected(t *testing.T) {
	if _, _, _, err := rtPasskeysParseAuthData(rtPasskeysTestAuthData(0x41, nil)); err == nil {
		t.Fatal()
	}
}

func TestRtPasskeysCredentialIDLengthBeyondTheBufferIsRejected(t *testing.T) {
	extra := append(make([]byte, 16), 0x00, 0xFF, 1, 2, 3, 4)
	if _, _, _, err := rtPasskeysParseAuthData(rtPasskeysTestAuthData(0x41, extra)); err == nil {
		t.Fatal("attacker-chosen length must not panic or parse")
	}
}

func TestRtPasskeysWellFormedAttestedDataParsesAndSplitsCorrectly(t *testing.T) {
	aaguid := make([]byte, 16)
	for i := range aaguid {
		aaguid[i] = 0xBB
	}
	extra := append(append(append([]byte{}, aaguid...), 0x00, 0x04, 9, 8, 7, 6), 0xA0)
	cred, cose, ag, err := rtPasskeysParseAuthData(rtPasskeysTestAuthData(0x41, extra))
	if err != nil || string(cred) != string([]byte{9, 8, 7, 6}) || string(ag[:]) != string(aaguid) || string(cose) != string([]byte{0xA0}) {
		t.Fatal(cred, cose, ag, err)
	}
}

// ── parse_cose_p256_key ─────────────────────────────────────────────

var (
	rtPasskeysP256Gx = []byte{0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5,
		0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
		0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96}
	rtPasskeysP256Gy = []byte{0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A,
		0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
		0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5}
)

func rtPasskeysTestCOSE(x, y []byte) []byte {
	b, _ := cbor.Marshal(map[int]any{1: 2, -1: 1, -2: x, -3: y})
	return b
}

func TestRtPasskeysAValidP256COSEKeyParses(t *testing.T) {
	if _, err := rtPasskeysParseCOSEP256(rtPasskeysTestCOSE(rtPasskeysP256Gx, rtPasskeysP256Gy)); err != nil {
		t.Fatal(err)
	}
}

func TestRtPasskeysCOSEKeyThatIsNotAMapIsRejected(t *testing.T) {
	b, _ := cbor.Marshal(7)
	if _, err := rtPasskeysParseCOSEP256(b); err == nil {
		t.Fatal()
	}
}

func TestRtPasskeysCOSEKeyMissingACoordinateIsRejected(t *testing.T) {
	b, _ := cbor.Marshal(map[int]any{-2: rtPasskeysP256Gx})
	if _, err := rtPasskeysParseCOSEP256(b); err == nil {
		t.Fatal()
	}
}

func TestRtPasskeysCOSEKeyWithShortCoordinatesIsRejected(t *testing.T) {
	x, y := make([]byte, 31), make([]byte, 31)
	if _, err := rtPasskeysParseCOSEP256(rtPasskeysTestCOSE(x, y)); err == nil {
		t.Fatal()
	}
}

func TestRtPasskeysAPointNotOnTheCurveIsRejected(t *testing.T) {
	x, y := make([]byte, 32), make([]byte, 32)
	for i := range x {
		x[i], y[i] = 0xAA, 0xBB
	}
	if _, err := rtPasskeysParseCOSEP256(rtPasskeysTestCOSE(x, y)); err == nil {
		t.Fatal("a key no signature could ever verify against must not be stored")
	}
}

func TestRtPasskeysGarbageBytesAreRejectedRatherThanPanicking(t *testing.T) {
	for _, b := range [][]byte{{}, {0xFF, 0xFF, 0xFF}} {
		if _, err := rtPasskeysParseCOSEP256(b); err == nil {
			t.Fatal(b)
		}
	}
}

// ── added: DER signature strictness, RP derivation ──────────────────

func TestRtPasskeysDERSignatureStrictness(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d := sha256.Sum256([]byte("m"))
	sig, _ := ecdsa.SignASN1(rand.Reader, k, d[:])
	if _, _, err := rtPasskeysParseDERSignature(sig); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, sig[:len(sig)-1], append(append([]byte{}, sig...), 0), {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01}} {
		if _, _, err := rtPasskeysParseDERSignature(bad); err == nil {
			t.Fatalf("%x must be refused", bad)
		}
	}
}

func TestRtPasskeysRPDerivationFailsClosed(t *testing.T) {
	st := testState()
	r := httptest.NewRequest("POST", "/", nil)
	r.Host = ""
	if _, err := rtPasskeysRPID(r, st); err == nil {
		t.Fatal("neither Origin nor Host → refused, never a hardcoded localhost")
	}
	r.Header.Set("Origin", "https://Panel.Example.com:8443/")
	if id, _ := rtPasskeysRPID(r, st); id != "panel.example.com" {
		t.Fatal(id)
	}
	if o, _ := rtPasskeysRPOrigin(r, st); o != "https://Panel.Example.com:8443" {
		t.Fatal(o)
	}
	// BASE_URL wins over any header.
	st.Config.BaseURL = "https://real.example/"
	if id, _ := rtPasskeysRPID(r, st); id != "real.example" {
		t.Fatal(id)
	}
	if o, _ := rtPasskeysRPOrigin(r, st); o != "https://real.example" {
		t.Fatal(o)
	}
}

func TestRtPasskeysChallengeStoreCap(t *testing.T) {
	rtPasskeysChallengesMu.Lock()
	saved := rtPasskeysChallenges
	rtPasskeysChallenges = map[string]rtPasskeysChallenge{}
	rtPasskeysChallengesMu.Unlock()
	defer func() { rtPasskeysChallenges = saved }()
	for i := 0; i < 10_001; i++ {
		rtPasskeysStoreChallenge(strconv.Itoa(i), rtPasskeysChallenge{Created: time.Now()})
	}
	rtPasskeysPurgeExpired()
	if n := len(rtPasskeysChallenges); n > 10_000 {
		t.Fatal(n)
	}
}

// ── Virtual authenticator (port of src/bin/passkey_virtual_authenticator.rs) ──
//
// Independent of the server's own parsing: it holds P-256 keypairs and builds
// the exact bytes a browser + authenticator would (CBOR attestation object,
// authenticatorData, DER-signed assertions), then talks to the handlers.

const (
	rtPasskeysUP = 0x01
	rtPasskeysUV = 0x04
	rtPasskeysAT = 0x40
)

type rtPasskeysVirtualAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
}

func rtPasskeysNewVirtual() *rtPasskeysVirtualAuthenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &rtPasskeysVirtualAuthenticator{key: k, credID: id}
}

func (a *rtPasskeysVirtualAuthenticator) credB64() string {
	return base64.RawURLEncoding.EncodeToString(a.credID)
}

func (a *rtPasskeysVirtualAuthenticator) cose() []byte {
	pt, _ := a.key.PublicKey.Bytes() // 0x04 || x || y
	b, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: pt[1:33], -3: pt[33:65]})
	return b
}

func (a *rtPasskeysVirtualAuthenticator) regAuthData(rpHash [32]byte, uv bool, count uint32) []byte {
	flags := byte(rtPasskeysUP | rtPasskeysAT)
	if uv {
		flags |= rtPasskeysUV
	}
	out := append(append([]byte{}, rpHash[:]...), flags)
	out = binary.BigEndian.AppendUint32(out, count)
	out = append(out, make([]byte, 16)...) // aaguid — unchecked by the server
	out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
	out = append(out, a.credID...)
	return append(out, a.cose()...)
}

func (a *rtPasskeysVirtualAuthenticator) assertAuthData(rpHash [32]byte, uv bool, count uint32) []byte {
	flags := byte(rtPasskeysUP)
	if uv {
		flags |= rtPasskeysUV
	}
	out := append(append([]byte{}, rpHash[:]...), flags)
	return binary.BigEndian.AppendUint32(out, count)
}

func (a *rtPasskeysVirtualAuthenticator) sign(authData, clientData []byte) []byte {
	h := sha256.Sum256(clientData)
	d := sha256.Sum256(append(append([]byte{}, authData...), h[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, a.key, d[:])
	return sig
}

func rtPasskeysClientDataJSON(ty, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]string{"type": ty, "challenge": challenge, "origin": origin})
	return b
}

type rtPasskeysHarness struct {
	e      *rtIdentityEnv
	t      *testing.T
	origin string
	rpHash [32]byte
	token  string
	pw     string
}

func (h *rtPasskeysHarness) authHdr() []string {
	return []string{"Cookie", "token=" + h.token, "X-Requested-With", "XMLHttpRequest", "Origin", h.origin}
}

func (h *rtPasskeysHarness) registerBegin(proof map[string]any) (int, string) {
	w, out := h.e.do(h.t, "POST", "/api/auth/passkey/register/begin", proof, h.authHdr()...)
	ch, _ := jsonStr(jsonGet(out, "publicKey", "challenge"))
	return w.Code, ch
}

func (h *rtPasskeysHarness) register(a *rtPasskeysVirtualAuthenticator, uv bool, name string, mutate func(cd *map[string]string, ad *[]byte)) (int, map[string]any) {
	code, ch := h.registerBegin(map[string]any{"current_password": h.pw})
	if code != 200 {
		h.t.Fatal("register/begin", code)
	}
	cd := map[string]string{"type": "webauthn.create", "challenge": ch, "origin": h.origin}
	ad := a.regAuthData(h.rpHash, uv, 1)
	if mutate != nil {
		mutate(&cd, &ad)
	}
	cdb, _ := json.Marshal(cd)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	w, out := h.e.do(h.t, "POST", "/api/auth/passkey/register/complete", map[string]any{
		"id": a.credB64(), "rawId": a.credB64(), "name": name,
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(att),
			"clientDataJson":    base64.RawURLEncoding.EncodeToString(cdb),
		},
	}, h.authHdr()...)
	return w.Code, out
}

func (h *rtPasskeysHarness) login(a *rtPasskeysVirtualAuthenticator, uv bool, count uint32, ip string, mutate func(cd *map[string]string, ad *[]byte, sig *[]byte)) (*httptest.ResponseRecorder, map[string]any) {
	w, out := h.e.do(h.t, "POST", "/api/auth/passkey/auth/begin", nil, "Origin", h.origin, "X-Real-IP", ip)
	if w.Code != 200 {
		h.t.Fatal("auth/begin", w.Code)
	}
	ch, _ := jsonStr(jsonGet(out, "publicKey", "challenge"))
	cd := map[string]string{"type": "webauthn.get", "challenge": ch, "origin": h.origin}
	ad := a.assertAuthData(h.rpHash, uv, count)
	cdb, _ := json.Marshal(cd)
	sig := a.sign(ad, cdb)
	if mutate != nil {
		mutate(&cd, &ad, &sig)
		cdb, _ = json.Marshal(cd)
	}
	return h.e.do(h.t, "POST", "/api/auth/passkey/auth/complete", map[string]any{
		"id": a.credB64(), "rawId": a.credB64(),
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(ad),
			"clientDataJson":    base64.RawURLEncoding.EncodeToString(cdb),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
			"userHandle":        nil,
		},
	}, "Origin", h.origin, "X-Real-IP", ip)
}

func TestDBRtPasskeysVirtualAuthenticator(t *testing.T) {
	e := rtIdentityTestEnv(t)
	tok := e.setupAdmin(t, "admin@x.test", "correct-horse")
	// No BASE_URL: the Origin-header fallback, as the Rust harness relied on.
	h := &rtPasskeysHarness{e: e, t: t, origin: "https://127.0.0.1", rpHash: sha256.Sum256([]byte("127.0.0.1")), token: tok, pw: "correct-horse"}

	// Enrolment needs proof: the bare challenge is a 403 reauth_required
	// offering the password.
	w, out := e.do(t, "POST", "/api/auth/passkey/register/begin", nil, h.authHdr()...)
	if w.Code != 403 || out["code"] != CodeReauthRequired {
		t.Fatal("a session alone must not plant a credential", w.Code, out)
	}
	if code, _ := h.registerBegin(map[string]any{"current_password": "wrong"}); code != 403 {
		t.Fatal("wrong password", code)
	}

	// A0: credential A registers WITH user verification.
	a := rtPasskeysNewVirtual()
	if code, out := h.register(a, true, "Virtual UV key", nil); code != 200 {
		t.Fatal("A0", code, out)
	}
	// A1: login WITHOUT UV on a UV-capable credential is refused.
	if w, _ := h.login(a, false, 2, "10.0.0.2", nil); w.Code != 401 || !strings.Contains(w.Body.String(), "requires verification") {
		t.Fatal("A1 enforcement is not working", w.Code, w.Body.String())
	}
	// A2: WITH UV succeeds and issues a session.
	if w, _ := h.login(a, true, 2, "10.0.0.3", nil); w.Code != 200 || rtIdentityCookieToken(t, w) == "" {
		t.Fatal("A2", w.Code, w.Body.String())
	}

	// B0/B1: a possession-only credential keeps working without UV
	// (grandfathering — nothing that worked yesterday stops today).
	b := rtPasskeysNewVirtual()
	if code, out := h.register(b, false, "Virtual legacy key", nil); code != 200 {
		t.Fatal("B0", code, out)
	}
	if w, _ := h.login(b, false, 2, "10.0.0.4", nil); w.Code != 200 {
		t.Fatal("B1 grandfathering broken", w.Code, w.Body.String())
	}

	// ── Attack cases ──
	// Replay of the same counter (B is now at 2) → clone, after the signature.
	if w, _ := h.login(b, false, 2, "10.0.0.5", nil); w.Code != 401 || !strings.Contains(w.Body.String(), "cloned") {
		t.Fatal("counter replay", w.Code, w.Body.String())
	}
	// Zero presented against a live counter → clone.
	if w, _ := h.login(b, false, 0, "10.0.0.5", nil); w.Code != 401 || !strings.Contains(w.Body.String(), "cloned") {
		t.Fatal("counter zero", w.Code)
	}
	// A forged authData with a garbage signature never reaches the counter
	// check (it would otherwise be an unthrottled clone oracle).
	if w, _ := h.login(b, false, 0, "10.0.0.6", func(_ *map[string]string, _ *[]byte, sig *[]byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		d := sha256.Sum256([]byte("x"))
		*sig, _ = ecdsa.SignASN1(rand.Reader, k, d[:])
	}); w.Code != 401 || !strings.Contains(w.Body.String(), "Signature verification failed") {
		t.Fatal("bad signature", w.Code, w.Body.String())
	}
	// Wrong origin in the signed clientData.
	if w, _ := h.login(b, false, 9, "10.0.0.7", func(cd *map[string]string, _ *[]byte, _ *[]byte) { (*cd)["origin"] = "https://evil.test" }); w.Code != 400 {
		t.Fatal("origin", w.Code)
	}
	// Wrong ceremony type.
	if w, _ := h.login(b, false, 9, "10.0.0.7", func(cd *map[string]string, _ *[]byte, _ *[]byte) { (*cd)["type"] = "webauthn.create" }); w.Code != 400 {
		t.Fatal("type", w.Code)
	}
	// RP ID hash for another site.
	if w, _ := h.login(b, false, 9, "10.0.0.7", func(_ *map[string]string, ad *[]byte, _ *[]byte) { (*ad)[0] ^= 0xFF }); w.Code != 400 {
		t.Fatal("rpIdHash", w.Code)
	}
	// User-present bit cleared.
	if w, _ := h.login(b, false, 9, "10.0.0.7", func(_ *map[string]string, ad *[]byte, _ *[]byte) { (*ad)[32] = 0 }); w.Code != 400 {
		t.Fatal("UP", w.Code)
	}
	// A registration challenge presented at the authentication door.
	_, regCh := h.registerBegin(map[string]any{"current_password": h.pw})
	if w, _ := h.login(b, false, 9, "10.0.0.7", func(cd *map[string]string, _ *[]byte, _ *[]byte) { (*cd)["challenge"] = regCh }); w.Code != 400 || !strings.Contains(w.Body.String(), "Wrong challenge type") {
		t.Fatal("challenge type", w.Code, w.Body.String())
	}
	// Unknown credential is counted against the IP: five failures lock it.
	ghost := rtPasskeysNewVirtual()
	for i := 0; i < 5; i++ {
		if w, _ := h.login(ghost, true, 1, "10.0.0.8", nil); w.Code != 401 {
			t.Fatal(i, w.Code)
		}
	}
	if w, _ := h.e.do(t, "POST", "/api/auth/passkey/auth/complete", map[string]any{
		"id": "x", "rawId": "x", "response": map[string]any{"authenticatorData": "", "clientDataJson": "", "signature": ""},
	}, "Origin", h.origin, "X-Real-IP", "10.0.0.8"); w.Code != 429 {
		t.Fatal("lockout", w.Code)
	}

	// Registration attacks: a 32-byte authData must be refused, never panic.
	c := rtPasskeysNewVirtual()
	if code, _ := h.register(c, true, "short", func(_ *map[string]string, ad *[]byte) { *ad = (*ad)[:32] }); code != 400 {
		t.Fatal("short authData", code)
	}
	if code, _ := h.register(c, true, "origin", func(cd *map[string]string, _ *[]byte) { (*cd)["origin"] = "https://evil.test" }); code != 400 {
		t.Fatal("register origin", code)
	}
	// An authentication challenge cannot complete a registration.
	w, out = e.do(t, "POST", "/api/auth/passkey/auth/begin", nil, "Origin", h.origin, "X-Real-IP", "10.0.0.9")
	authCh, _ := jsonStr(jsonGet(out, "publicKey", "challenge"))
	if code, _ := h.register(c, true, "wrongtype", func(cd *map[string]string, _ *[]byte) { (*cd)["challenge"] = authCh }); code != 400 {
		t.Fatal("register challenge type", code)
	}
	// Another user's registration challenge is refused.
	hash, _ := hashPassword("other-password")
	_, _ = execSQL(context.Background(), e.st.DB, "INSERT INTO users (email, password_hash, role, email_verified) VALUES ('o@x.test', $1, 'user', TRUE)", hash)
	lw, _ := e.do(t, "POST", "/api/auth/login", map[string]any{"email": "o@x.test", "password": "other-password"}, "X-Real-IP", "10.0.1.1")
	other := &rtPasskeysHarness{e: e, t: t, origin: h.origin, rpHash: h.rpHash, token: rtIdentityCookieToken(t, lw), pw: "other-password"}
	_, otherCh := other.registerBegin(map[string]any{"current_password": "other-password"})
	if code, out := h.register(c, true, "steal", func(cd *map[string]string, _ *[]byte) { (*cd)["challenge"] = otherCh }); code != 400 || out["error"] != "Challenge user mismatch" {
		t.Fatal("challenge user binding", code, out)
	}

	// Cleanup path: list + delete.
	w, out = e.do(t, "GET", "/api/auth/passkeys", nil, h.authHdr()...)
	list, _ := jsonArr(out["passkeys"])
	if w.Code != 200 || len(list) != 2 {
		t.Fatal(w.Code, out)
	}
	for _, p := range list {
		id, _ := jsonStr(jsonGet(p, "id"))
		if w, _ := e.do(t, "DELETE", "/api/auth/passkeys/"+id, nil, other.authHdr()...); w.Code != 404 {
			t.Fatal("another user cannot delete it", w.Code)
		}
		if w, _ := e.do(t, "DELETE", "/api/auth/passkeys/"+id, nil, h.authHdr()...); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
}
