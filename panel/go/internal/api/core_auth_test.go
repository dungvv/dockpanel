package api

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func testState() *AppState {
	return NewAppState(nil, &Config{JWTSecret: testSecret}, nil, nil, context.Background())
}

func mint(t *testing.T, c Claims) string {
	t.Helper()
	tok, err := encodeJWT(&c, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func freshClaims(role string) Claims {
	now := uint64(time.Now().Unix())
	jti := uuid.NewString()
	return Claims{Sub: uuid.New(), Email: "a@b.c", Role: role, Exp: now + 7200, Iat: now, Jti: &jti}
}

func TestSessionInvalidIs401CarryingMarker(t *testing.T) {
	s, b := body(t, sessionInvalid("Invalid or expired token"))
	if s != 401 || b["code"] != CodeSessionInvalid || b["error"] != "Invalid or expired token" {
		t.Fatal(s, b)
	}
}

func TestSentenceIsNotReplacedByMarker(t *testing.T) {
	if _, b := body(t, sessionInvalid("Session revoked. Please log in again.")); b["error"] != "Session revoked. Please log in again." {
		t.Fatal(b)
	}
}

func TestPlain401CarriesNoMarker(t *testing.T) {
	// An agent presenting a bad token is not a browser losing a session.
	if s, b := body(t, apiErr(401, "Invalid token")); s != 401 || b["code"] != nil {
		t.Fatal(s, b)
	}
}

func TestClaimsSerialiseLikeSerde(t *testing.T) {
	c := Claims{Sub: uuid.MustParse("00000000-0000-0000-0000-000000000001"), Email: "e", Role: "admin", Exp: 2, Iat: 1}
	tok := mint(t, c)
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	want := `{"sub":"00000000-0000-0000-0000-000000000001","email":"e","role":"admin","exp":2,"iat":1,"jti":null,"key_id":null}`
	if string(payload) != want {
		t.Fatalf("%s", payload)
	}
}

func TestDecodeJWTValidation(t *testing.T) {
	c := freshClaims("user")
	got, err := decodeJWT(mint(t, c), testSecret)
	if err != nil || got.Sub != c.Sub || *got.Jti != *c.Jti {
		t.Fatal(err)
	}
	if _, err := decodeJWT(mint(t, c), "another-secret-another-secret-xx"); err == nil {
		t.Fatal("wrong key must fail")
	}
	// jsonwebtoken (leeway 0) accepts exp == now and rejects exp < now.
	c.Exp = uint64(time.Now().Unix()) - 1
	if _, err := decodeJWT(mint(t, c), testSecret); err == nil {
		t.Fatal("expired must fail")
	}
	// Only HS256.
	other := freshClaims("user")
	hs512, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, &other).SignedString([]byte(testSecret))
	if _, err := decodeJWT(hs512, testSecret); err == nil {
		t.Fatal("HS512 must be refused")
	}
	// Missing a required claim (iat) fails to decode, as serde did.
	noIat, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": uuid.NewString(), "email": "e", "role": "user", "exp": time.Now().Unix() + 60}).SignedString([]byte(testSecret))
	if _, err := decodeJWT(noIat, testSecret); err == nil {
		t.Fatal("missing iat must fail")
	}
	// Tokens from before key_id existed still decode.
	old, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": uuid.NewString(), "email": "e", "role": "user", "exp": time.Now().Unix() + 60, "iat": time.Now().Unix()}).SignedString([]byte(testSecret))
	if c, err := decodeJWT(old, testSecret); err != nil || c.KeyID != nil || c.Jti != nil {
		t.Fatal(err)
	}
}

func TestAuthUserRefusals(t *testing.T) {
	st := testState()
	check := func(name string, wantStatus int, wantCode any, mk func() (string, string, string, bool)) {
		t.Helper()
		method, bearer, cookie, csrf := mk()
		r := httptest.NewRequest(method, "/api/x", nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		if cookie != "" {
			r.Header.Set("Cookie", "theme=dark; token="+cookie)
		}
		if csrf {
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		_, err := st.authUser(r)
		if wantStatus == 0 {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			return
		}
		s, b := body(t, err)
		if s != wantStatus || b["code"] != wantCode {
			t.Fatalf("%s: %d %v", name, s, b)
		}
	}
	good := mint(t, freshClaims("user"))
	check("no credential", 401, CodeSessionInvalid, func() (string, string, string, bool) { return "GET", "", "", false })
	check("bearer ok", 0, nil, func() (string, string, string, bool) { return "POST", good, "", false })
	check("cookie GET ok", 0, nil, func() (string, string, string, bool) { return "GET", "", good, false })
	check("cookie POST without CSRF header", 403, nil, func() (string, string, string, bool) { return "POST", "", good, false })
	check("cookie POST with CSRF header", 0, nil, func() (string, string, string, bool) { return "POST", "", good, true })
	check("garbage", 401, CodeSessionInvalid, func() (string, string, string, bool) { return "GET", "garbage", "", false })
	check("suspended", 403, nil, func() (string, string, string, bool) { return "GET", mint(t, freshClaims("suspended")), "", false })

	revoked := freshClaims("user")
	st.blacklistAdd(*revoked.Jti)
	check("blacklisted", 401, CodeSessionInvalid, func() (string, string, string, bool) { return "GET", mint(t, revoked), "", false })

	old := freshClaims("user")
	old.Iat -= 100
	st.setSessionsRevokedAt(int64(old.Iat) + 50)
	check("issued before revoke-all", 401, CodeSessionInvalid, func() (string, string, string, bool) { return "GET", mint(t, old), "", false })
}

func TestAdminAndResellerExtractorsKeepInnerRejection(t *testing.T) {
	st := testState()
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Cookie", "token="+mint(t, freshClaims("admin")))
	if s, _ := body(t, func() error { _, e := st.adminUser(r); return e }()); s != 403 {
		t.Fatal("CSRF 403 must propagate, not flatten to 401")
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+mint(t, freshClaims("user")))
	if _, b := body(t, func() error { _, e := st.adminUser(r); return e }()); b["error"] != "Admin access required" {
		t.Fatal(b)
	}
	if _, b := body(t, func() error { _, e := st.resellerUser(r); return e }()); b["error"] != "Admin or reseller access required" {
		t.Fatal(b)
	}
	r.Header.Set("Authorization", "Bearer "+mint(t, freshClaims("reseller")))
	if _, err := st.resellerUser(r); err != nil {
		t.Fatal(err)
	}
}

func TestServerScopeNeedsAuthWithHeader(t *testing.T) {
	st := testState()
	st.Agents = NewAgentRegistry(NewAgentClient("/nonexistent", "t"), nil, testSecret)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Server-Id", uuid.NewString())
	_, _, err := st.serverScope(r)
	if s, b := body(t, err); s != 401 || b["code"] != CodeSessionInvalid {
		t.Fatal(s, b)
	}
	// No header and no local server registered yet → 503.
	r = httptest.NewRequest("GET", "/", nil)
	_, _, err = st.serverScope(r)
	if s, _ := body(t, err); s != 503 {
		t.Fatal(s)
	}
	id := uuid.New()
	st.Agents.SetLocalServerID(id)
	got, a, err := st.serverScope(r)
	if err != nil || got != id {
		t.Fatal(err)
	}
	if _, local := a.(*AgentClient); !local {
		t.Fatal("default scope must be the local agent")
	}
}

func TestAgentRateLimit(t *testing.T) {
	st := testState()
	id := uuid.New()
	for i := 0; i < 120; i++ {
		if err := st.agentRateLimit(id); err != nil {
			t.Fatalf("request %d refused", i+1)
		}
	}
	if s, _ := body(t, st.agentRateLimit(id)); s != 429 {
		t.Fatal(s)
	}
}

func TestArgon2CrateVectors(t *testing.T) {
	// From argon2-0.5.3/tests/phc_strings.rs: hashes of "password".
	for _, h := range []string{
		"$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo",
		"$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
	} {
		if ok, err := verifyPassword("password", h); !ok || err != nil {
			t.Fatalf("%s: %v %v", h, ok, err)
		}
		if ok, err := verifyPassword("sassword", h); ok || err != nil {
			t.Fatalf("%s accepted a wrong password", h)
		}
	}
}

func TestDummyHashIsVerifiableNotMerelyParseable(t *testing.T) {
	const dummy = "$argon2id$v=19$m=19456,t=2,p=1$ZHVtbXlzYWx0MTIzNA$K1PqGlDJpiBFSguVJXKDBIuXQ5baiAOXSgWAGkuJYxk"
	if ok, err := verifyPassword("whatever-the-caller-typed", dummy); ok || err != nil {
		t.Fatal(ok, err)
	}
	if _, err := verifyPassword("x", "not-a-phc"); err != errBadPHC {
		t.Fatal(err)
	}
}

func TestHashPasswordIsArgon2Default(t *testing.T) {
	h, err := hashPassword("correct horse")
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatal(h, err)
	}
	if ok, _ := verifyPassword("correct horse", h); !ok {
		t.Fatal("round trip")
	}
	if ok, _ := verifyPassword("wrong", h); ok {
		t.Fatal("wrong password accepted")
	}
}

func TestBcrypt(t *testing.T) {
	h, err := bcryptHash("pw", 4)
	if err != nil || !strings.HasPrefix(h, "$2b$04$") || !bcryptVerify("pw", h) || bcryptVerify("px", h) {
		t.Fatal(h, err)
	}
	long := strings.Repeat("a", 100)
	h, err = bcryptHash(long, 4)
	if err != nil || !bcryptVerify(long[:72]+"zzz", h) {
		t.Fatal("passwords past 72 bytes are truncated, as the Rust crate did")
	}
}
