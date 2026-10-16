package api

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ── login_credential_tests ─────────────────────────────────────────────────

// The mechanism behind the OAuth-only 500: rt_oauth creates accounts with an
// empty password_hash, and an empty string is not a PHC string.
func TestRtAuthEmptyPasswordHashCannotBeParsed(t *testing.T) {
	if _, err := verifyPassword("x", ""); err == nil {
		t.Fatal("if this ever parses, the empty-hash branch in login is dead code and the reason for it has changed")
	}
}

// Control: the assertion above is about the EMPTY string specifically.
func TestRtAuthARealHashStillParses(t *testing.T) {
	if _, err := verifyPassword("x", rtAuthDummyPasswordHash); err != nil {
		t.Fatal(err)
	}
}

// A dummy hash that did not parse would turn an enumeration fix into a failure
// on the same input. The verify must COMPLETE and must not match.
func TestRtAuthDummyHashIsVerifiableNotMerelyParseable(t *testing.T) {
	ok, err := verifyPassword("whatever-the-caller-typed", rtAuthDummyPasswordHash)
	if err != nil || ok {
		t.Fatal(ok, err)
	}
}

// ── TOTP (totp-rs SHA1/6/skew 1/30s semantics) ─────────────────────────────

func rtAuthTestCode(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(base32.StdEncoding.EncodeToString(secret), at,
		totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRtAuthTotpAcceptsOneStepEitherSideOnly(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 20)
	tp, err := rtAuthNewTotp(rtAuthB32.EncodeToString(secret), "a@b.c")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if !tp.checkCurrent(rtAuthTestCode(t, secret, now.Add(d))) {
			t.Fatalf("skew 1 must accept the code at %v", d)
		}
	}
	// Two steps away is outside the window (unless it collides by chance).
	far := rtAuthTestCode(t, secret, now.Add(-90*time.Second))
	near := map[string]bool{}
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second, 60 * time.Second} {
		near[rtAuthTestCode(t, secret, now.Add(d))] = true
	}
	if !near[far] && tp.checkCurrent(far) {
		t.Fatal("a code three steps old must be refused")
	}
	// totp-rs compares the raw string: no trimming, exact length.
	code := rtAuthTestCode(t, secret, now)
	for _, bad := range []string{" " + code, code + "\n", code[:5], code + "0", ""} {
		if tp.checkCurrent(bad) {
			t.Fatalf("%q must be refused", bad)
		}
	}
}

func TestRtAuthTotpConstructionErrorsMatchTotpRs(t *testing.T) {
	if _, err := rtAuthNewTotp(rtAuthB32.EncodeToString(make([]byte, 15)), "a@b.c"); err == nil {
		t.Fatal("a secret under 128 bits is refused")
	}
	if _, err := rtAuthNewTotp(rtAuthB32.EncodeToString(make([]byte, 16)), "a:b@c"); err == nil {
		t.Fatal("an account name with ':' is refused")
	}
	if _, err := rtAuthNewTotp("not base32!", "a@b.c"); err == nil {
		t.Fatal("bad base32 is refused")
	}
	if _, err := rtAuthNewTotp(rtAuthB32.EncodeToString(make([]byte, 20)), "a@b.c"); err != nil {
		t.Fatal(err)
	}
}

func TestRtAuthOtpauthURLMatchesTotpRs(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, 20)
	tp, _ := rtAuthNewTotp(rtAuthB32.EncodeToString(secret), "me+x@example.com")
	want := "otpauth://totp/DockPanel:me%2Bx%40example.com?secret=" + rtAuthB32.EncodeToString(secret) + "&issuer=DockPanel"
	if got := tp.url(); got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	if strings.Contains(rtAuthB32.EncodeToString(secret), "=") {
		t.Fatal("secret is unpadded base32")
	}
}

func TestRtAuthQRSVGShape(t *testing.T) {
	svg, err := rtAuthQRSVG("otpauth://totp/DockPanel:a%40b.c?secret=AAAA&issuer=DockPanel")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(svg, `<?xml version="1.0" standalone="yes"?><svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="`) ||
		!strings.HasSuffix(svg, `"/></svg>`) || !strings.Contains(svg, `fill="#fff"/><path fill="#000" d="M`) {
		t.Fatal(svg[:200])
	}
	i := strings.Index(svg, `width="`) + len(`width="`)
	w, err := strconv.Atoi(svg[i : i+strings.Index(svg[i:], `"`)])
	if err != nil || w < 200 {
		t.Fatalf("min_dimensions(200,200): width %d", w)
	}
}

func TestRtAuthURLEncodeIsUrlencodingCrate(t *testing.T) {
	if got := rtAuthURLEncode("a b/c:d@e~f-g.h_i"); got != "a%20b%2Fc%3Ad%40e~f-g.h_i" {
		t.Fatal(got)
	}
}

func TestRtAuthRecoveryCodesAre64Bit(t *testing.T) {
	codes := rtAuthGenerateRecoveryCodes()
	if len(codes) != 10 {
		t.Fatal(len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 16 || seen[c] {
			t.Fatalf("16 hex chars, unique: %q", c)
		}
		seen[c] = true
	}
}

func TestRtAuthRecoveryCodesRemainingFailsClosed(t *testing.T) {
	if rtAuthRecoveryCodesRemaining(nil) != 0 || rtAuthRecoveryCodesRemaining(new("{corrupt")) != 0 {
		t.Fatal()
	}
	if rtAuthRecoveryCodesRemaining(new(`["a","b"]`)) != 2 {
		t.Fatal()
	}
}

// The limiter counts failures only and locks at 5 within 5 minutes.
func TestRtAuthTwofaRateLimiter(t *testing.T) {
	st := testState()
	id := uuid.New()
	for i := 0; i < 5; i++ {
		if err := rtAuthTwofaRateLimitCheck(st, id); err != nil {
			t.Fatalf("attempt %d refused early", i)
		}
		rtAuthTwofaRateLimitRecord(st, id)
	}
	err := rtAuthTwofaRateLimitCheck(st, id)
	if ae, ok := err.(*ApiError); !ok || ae.Status != 429 || !strings.Contains(ae.Error(), "Try again in 5 minutes") {
		t.Fatal(err)
	}
	// An expired window rolls over.
	st.TwofaAttempts[id] = RateWindow{Count: 9, Start: time.Now().Add(-301 * time.Second)}
	if rtAuthTwofaRateLimitCheck(st, id) != nil {
		t.Fatal("expired window must not refuse")
	}
	rtAuthTwofaRateLimitRecord(st, id)
	if st.TwofaAttempts[id].Count != 1 {
		t.Fatal("record rolls the window")
	}
	rtAuthTwofaRateLimitClear(st, id)
	if _, ok := st.TwofaAttempts[id]; ok {
		t.Fatal()
	}
}

func TestRtAuthTwoFaTokenRequiresPurposeAndExpiry(t *testing.T) {
	st := testState()
	tok, _ := rtAuthMintTwoFaToken(st, uuid.New())
	c, err := rtAuthDecodeTwoFaToken(tok, testSecret)
	if err != nil || c.Purpose != "2fa" {
		t.Fatal(err)
	}
	// A full session JWT has no `purpose` → must not decode as a temp token.
	if _, err := rtAuthDecodeTwoFaToken(mint(t, freshClaims("admin")), testSecret); err == nil {
		t.Fatal("a session token is not a 2FA token")
	}
	if _, err := rtAuthDecodeTwoFaToken(tok, "another-secret-another-secret-xx"); err == nil {
		t.Fatal("wrong key")
	}
}

func TestRtAuthCookieSecureFlagFollowsForwardedProto(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if rtAuthCookieSecureFlag(r) != "" {
		t.Fatal()
	}
	r.Header.Set("X-Forwarded-Proto", "HTTPS")
	if rtAuthCookieSecureFlag(r) != "; Secure" {
		t.Fatal()
	}
}

// ── DB-backed handler tests (DATABASE_URL) ─────────────────────────────────

type rtIdentityEnv struct {
	st *AppState
	h  http.Handler
}

func rtIdentityTestEnv(t *testing.T) *rtIdentityEnv {
	t.Helper()
	pool := scratchDB(t)
	ctx := context.Background()
	migs, _ := EmbeddedMigrations()
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal(err)
	}
	securityHardeningAuditDir = t.TempDir()
	st := NewAppState(pool, &Config{JWTSecret: testSecret}, NewAgentClient("/nonexistent.sock", "tok"), nil, ctx)
	st.Agents = NewAgentRegistry(st.Agent, pool, testSecret)
	rt := &Router{St: st, mux: http.NewServeMux()}
	for _, reg := range []func(*Router){rtAuthRegister, rtPasskeysRegister, rtOauthRegister, rtUsersRegister,
		rtApiKeysRegister, rtTeamsRegister, rtSettingsRegister, rtBrandingAssetsRegister, rtSecretsRegister} {
		reg(rt)
	}
	return &rtIdentityEnv{st: st, h: rt}
}

// do sends a JSON request; hdr pairs are header name/value.
func (e *rtIdentityEnv) do(t *testing.T, method, path string, body any, hdr ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, rd)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func rtIdentityCookieToken(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range w.Result().Header.Values("Set-Cookie") {
		if v, ok := strings.CutPrefix(c, "token="); ok {
			tok, _, _ := strings.Cut(v, ";")
			if tok != "" {
				return tok
			}
		}
	}
	t.Fatal("no token cookie")
	return ""
}

func (e *rtIdentityEnv) setupAdmin(t *testing.T, email, pw string) string {
	t.Helper()
	if w, _ := e.do(t, "POST", "/api/auth/setup", map[string]any{"email": email, "password": pw}); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	w, _ := e.do(t, "POST", "/api/auth/login", map[string]any{"email": email, "password": pw}, "X-Real-IP", "203.0.113.9")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	return rtIdentityCookieToken(t, w)
}

func TestDBRtAuthSetupLoginLockoutAndEnumeration(t *testing.T) {
	e := rtIdentityTestEnv(t)
	tok := e.setupAdmin(t, "admin@x.test", "correct-horse")

	// Setup is one-shot.
	if w, _ := e.do(t, "POST", "/api/auth/setup", map[string]any{"email": "b@x.test", "password": "longenough"}); w.Code != 403 {
		t.Fatal("second setup must be refused", w.Code)
	}
	// /me with the cookie (Bearer also works).
	if w, out := e.do(t, "GET", "/api/auth/me", nil, "Authorization", "Bearer "+tok); w.Code != 200 || out["email"] != "admin@x.test" {
		t.Fatal(w.Code, out)
	}

	// An unknown account and a wrong password answer identically (no oracle),
	// and an SSO account (empty hash) does too — never a 500.
	_, _ = execSQL(context.Background(), e.st.DB, "INSERT INTO users (email, password_hash, role, oauth_provider) VALUES ('sso@x.test', '', 'user', 'github')")
	for _, email := range []string{"nobody@x.test", "admin@x.test", "sso@x.test"} {
		w, out := e.do(t, "POST", "/api/auth/login", map[string]any{"email": email, "password": "wrong-password"}, "X-Real-IP", "198.51.100."+strconv.Itoa(len(email)))
		if w.Code != 401 || out["error"] != "Invalid credentials" {
			t.Fatal(email, w.Code, out)
		}
	}

	// Five failures from one IP lock it out — even the right password.
	ip := "192.0.2.77"
	for i := 0; i < 5; i++ {
		if w, _ := e.do(t, "POST", "/api/auth/login", map[string]any{"email": "admin@x.test", "password": "nope-nope"}, "X-Real-IP", ip); w.Code != 401 {
			t.Fatal(i, w.Code)
		}
	}
	if w, _ := e.do(t, "POST", "/api/auth/login", map[string]any{"email": "admin@x.test", "password": "correct-horse"}, "X-Real-IP", ip); w.Code != 429 {
		t.Fatal("locked out", w.Code)
	}

	// Logout blacklists the jti: the token stops working.
	if w, _ := e.do(t, "POST", "/api/auth/logout", nil, "Authorization", "Bearer "+tok); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w, _ := e.do(t, "GET", "/api/auth/me", nil, "Authorization", "Bearer "+tok); w.Code != 401 {
		t.Fatal("logged-out token must die", w.Code)
	}
}

func TestDBRtAuthAllowlistAndSuspensionGateEveryDoor(t *testing.T) {
	e := rtIdentityTestEnv(t)
	e.setupAdmin(t, "admin@x.test", "correct-horse")
	ctx := context.Background()
	_, _ = execSQL(ctx, e.st.DB, "INSERT INTO settings (key, value) VALUES ('allowed_panel_ips', '10.0.0.0/8')")
	// Fails CLOSED with no X-Real-IP.
	if w, _ := e.do(t, "POST", "/api/auth/login", map[string]any{"email": "admin@x.test", "password": "correct-horse"}); w.Code != 403 {
		t.Fatal("no client ip → refused", w.Code)
	}
	if w, _ := e.do(t, "POST", "/api/auth/passkey/auth/begin", nil, "X-Real-IP", "8.8.8.8", "Origin", "https://p.test"); w.Code != 403 {
		t.Fatal("passkey door honours the allowlist", w.Code)
	}
	if w, _ := e.do(t, "POST", "/api/auth/login", map[string]any{"email": "admin@x.test", "password": "correct-horse"}, "X-Real-IP", "10.1.2.3"); w.Code != 200 {
		t.Fatal("CIDR match admits", w.Code)
	}
	_, _ = execSQL(ctx, e.st.DB, "DELETE FROM settings WHERE key = 'allowed_panel_ips'")

	hash, _ := hashPassword("user-password")
	_, _ = execSQL(ctx, e.st.DB, "INSERT INTO users (email, password_hash, role, email_verified) VALUES ('u@x.test', $1, 'suspended', TRUE)", hash)
	if w, _ := e.do(t, "POST", "/api/auth/login", map[string]any{"email": "u@x.test", "password": "user-password"}, "X-Real-IP", "10.9.9.9"); w.Code != 403 {
		t.Fatal("suspended", w.Code)
	}
	// Forgot-password answers a suspended account like any other address.
	if w, out := e.do(t, "POST", "/api/auth/forgot-password", map[string]any{"email": "u@x.test"}); w.Code != 200 || out["ok"] != true {
		t.Fatal(w.Code, out)
	}
	if tok, _ := queryScalar[*string](ctx, e.st.DB, "SELECT reset_token FROM users WHERE email = 'u@x.test'"); tok != nil {
		t.Fatal("a suspended account gets no reset token")
	}
	// Lockdown keeps non-admins out.
	_, _ = execSQL(ctx, e.st.DB, "UPDATE users SET role = 'user' WHERE email = 'u@x.test'")
	SecurityHardeningActivateLockdown(ctx, e.st.DB, "test", "test")
	if w, _ := e.do(t, "POST", "/api/auth/login", map[string]any{"email": "u@x.test", "password": "user-password"}, "X-Real-IP", "10.9.9.8"); w.Code != 503 {
		t.Fatal("lockdown", w.Code)
	}
	if w, _ := e.do(t, "POST", "/api/auth/login", map[string]any{"email": "admin@x.test", "password": "correct-horse"}, "X-Real-IP", "10.9.9.7"); w.Code != 200 {
		t.Fatal("admins can always get in", w.Code)
	}
}

func TestDBRtAuthTwoFactorFlow(t *testing.T) {
	e := rtIdentityTestEnv(t)
	tok := e.setupAdmin(t, "admin@x.test", "correct-horse")
	auth := []string{"Authorization", "Bearer " + tok}

	w, out := e.do(t, "POST", "/api/auth/2fa/setup", nil, auth...)
	if w.Code != 200 || !strings.HasPrefix(out["qr_svg"].(string), "<?xml") {
		t.Fatal(w.Code, out)
	}
	secretB32 := out["secret"].(string)
	secret, _ := rtAuthB32.DecodeString(secretB32)
	if len(secret) != 20 {
		t.Fatal("160-bit secret")
	}
	stored, _ := queryScalar[string](context.Background(), e.st.DB, "SELECT totp_secret FROM users WHERE email = 'admin@x.test'")
	if stored == secretB32 {
		t.Fatal("the secret is encrypted at rest")
	}

	if w, _ := e.do(t, "POST", "/api/auth/2fa/enable", map[string]any{"code": "000000"}, auth...); w.Code != 401 {
		t.Fatal("a wrong code does not enable", w.Code)
	}
	w, out = e.do(t, "POST", "/api/auth/2fa/enable", map[string]any{"code": rtAuthTestCode(t, secret, time.Now())}, auth...)
	if w.Code != 200 {
		t.Fatal(w.Code, out)
	}
	codes := out["recovery_codes"].([]any)

	// Login now yields a temp token, not a session.
	w, out = e.do(t, "POST", "/api/auth/login", map[string]any{"email": "admin@x.test", "password": "correct-horse"}, "X-Real-IP", "10.0.0.1")
	if w.Code != 200 || out["requires_2fa"] != true {
		t.Fatal(w.Code, out)
	}
	temp := out["temp_token"].(string)

	// A session token is not accepted as a temp token.
	if w, _ := e.do(t, "POST", "/api/auth/2fa/verify", map[string]any{"temp_token": tok, "code": "123456"}); w.Code != 401 {
		t.Fatal(w.Code)
	}
	// A recovery code is accepted once, then consumed.
	rc := codes[0].(string)
	if w, _ := e.do(t, "POST", "/api/auth/2fa/verify", map[string]any{"temp_token": temp, "code": rc}); w.Code != 200 {
		t.Fatal("recovery code", w.Code)
	}
	if w, _ := e.do(t, "POST", "/api/auth/2fa/verify", map[string]any{"temp_token": temp, "code": rc}); w.Code != 401 {
		t.Fatal("a recovery code is single-use", w.Code)
	}
	if w, out := e.do(t, "GET", "/api/auth/2fa/status", nil, auth...); w.Code != 200 || out["recovery_codes_remaining"] != float64(9) {
		t.Fatal(out)
	}

	// The disable door is rate-limited on the shared counter: after 5 bad
	// codes even a good one is refused.
	for i := 0; i < 4; i++ {
		if w, _ := e.do(t, "POST", "/api/auth/2fa/disable", map[string]any{"code": "999999"}, auth...); w.Code != 401 {
			t.Fatal(i, w.Code)
		}
	}
	if w, _ := e.do(t, "POST", "/api/auth/2fa/disable", map[string]any{"code": rtAuthTestCode(t, secret, time.Now())}, auth...); w.Code != 429 {
		t.Fatal("5 failures (1 from verify + 4 here) lock the disable door", w.Code)
	}
}

func TestDBRtUsersOtherAdminAndLastAdminGuards(t *testing.T) {
	e := rtIdentityTestEnv(t)
	tok := e.setupAdmin(t, "admin@x.test", "correct-horse")
	auth := []string{"Authorization", "Bearer " + tok, "X-Real-IP", "10.0.0.1"}
	ctx := context.Background()

	w, out := e.do(t, "POST", "/api/users", map[string]any{"email": "peer@x.test", "password": "longenough", "role": "admin"}, auth...)
	if w.Code != 201 {
		t.Fatal(w.Code, out)
	}
	peer := out["id"].(string)
	for _, c := range []struct{ m, p string }{
		{"PUT", "/api/users/" + peer}, {"POST", "/api/users/" + peer + "/toggle-suspend"},
		{"POST", "/api/users/" + peer + "/reset-password"}, {"DELETE", "/api/users/" + peer},
	} {
		if w, _ := e.do(t, c.m, c.p, map[string]any{"password": "anotherlongone"}, auth...); w.Code != 403 {
			t.Fatal(c, "another admin is a peer, not a subordinate", w.Code)
		}
	}
	if w, _ := e.do(t, "POST", "/api/users", map[string]any{"email": "x@x.test", "password": "longenough", "role": "suspended"}, auth...); w.Code != 400 {
		t.Fatal("suspended is not assignable", w.Code)
	}
	me, _ := queryScalar[uuid.UUID](ctx, e.st.DB, "SELECT id FROM users WHERE email = 'admin@x.test'")
	if w, _ := e.do(t, "PUT", "/api/users/"+me.String(), map[string]any{"role": "user"}, auth...); w.Code != 400 {
		t.Fatal("cannot change your own role", w.Code)
	}

	// Delete re-points servers rather than cascading them away.
	w, out = e.do(t, "POST", "/api/users", map[string]any{"email": "u@x.test", "password": "longenough"}, auth...)
	uid := out["id"].(string)
	_, _ = execSQL(ctx, e.st.DB, "INSERT INTO servers (user_id, name, agent_token, status) VALUES ($1, 'box', 't', 'online')", uid)
	if w, out := e.do(t, "DELETE", "/api/users/"+uid, nil, auth...); w.Code != 200 || len(out["reassigned_servers"].([]any)) != 1 {
		t.Fatal(w.Code, out)
	}
	if owner, _ := queryScalar[uuid.UUID](ctx, e.st.DB, "SELECT user_id FROM servers WHERE name = 'box'"); owner != me {
		t.Fatal("the machine changed hands")
	}
}
