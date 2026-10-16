package api

// Port of panel/backend/src/routes/auth.rs — setup, login, logout, register,
// email verification, password reset, TOTP 2FA, session management, GDPR
// export, and the enrolment-proof gate the passkey door uses.
//
// revoke_all_user_sessions lives in core_auth.go (st.revokeAllUserSessions).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// rtAuthDummyPasswordHash is a real Argon2 PHC string verified against on the
// paths where there is no stored hash to verify against, so that "no such
// account" and "this account signs in with an identity provider" cost what a
// real verification costs. Package-level so a test can assert it parses — the
// branches that use it must not be the ones that fail.
const rtAuthDummyPasswordHash = "$argon2id$v=19$m=19456,t=2,p=1$ZHVtbXlzYWx0MTIzNA$K1PqGlDJpiBFSguVJXKDBIuXQ5baiAOXSgWAGkuJYxk"

func rtAuthRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("GET /api/auth/setup-status", h(rtAuthSetupStatus))
	r.Handle("POST /api/auth/setup", h(rtAuthSetup))
	r.Handle("POST /api/auth/login", h(rtAuthLogin))
	r.Handle("POST /api/auth/logout", h(rtAuthLogout))
	r.Handle("GET /api/auth/me", h(rtAuthMe))
	r.Handle("POST /api/auth/register", h(rtAuthRegisterUser))
	r.Handle("POST /api/auth/verify-email", h(rtAuthVerifyEmail))
	r.Handle("POST /api/auth/forgot-password", h(rtAuthForgotPassword))
	r.Handle("POST /api/auth/reset-password", h(rtAuthResetPassword))
	r.Handle("POST /api/auth/change-password", h(rtAuthChangePassword))
	r.Handle("POST /api/auth/revoke-all", h(rtAuthRevokeAllSessions))
	r.Handle("GET /api/auth/sessions", h(rtAuthListSessions))
	r.Handle("DELETE /api/auth/sessions/{id}", h(rtAuthRevokeSession))
	r.Handle("GET /api/auth/export-my-data", h(rtAuthExportMyData))
	r.Handle("POST /api/auth/2fa/setup", h(rtAuthTwofaSetup))
	r.Handle("POST /api/auth/2fa/enable", h(rtAuthTwofaEnable))
	r.Handle("POST /api/auth/2fa/verify", h(rtAuthTwofaVerify))
	r.Handle("POST /api/auth/2fa/disable", h(rtAuthTwofaDisable))
	r.Handle("POST /api/auth/2fa/recovery-codes", h(rtAuthTwofaRegenerateRecoveryCodes))
	r.Handle("GET /api/auth/2fa/status", h(rtAuthTwofaStatus))
}

// rtAuthGenerateToken generates a secure random token and its SHA-256 hash.
func rtAuthGenerateToken() (string, string) {
	token := strings.ReplaceAll(uuid.NewString(), "-", "")
	return token, rtAuthHashToken(token)
}

// rtAuthHashToken hashes a token with SHA-256 for DB comparison.
func rtAuthHashToken(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

// rtAuthRealIP is the client IP for rate limiting: X-Real-IP (set by nginx
// from $remote_addr — trustworthy), trimmed, else "unknown". Do NOT trust
// X-Forwarded-For: it can be forged by the client to bypass the limit.
func rtAuthRealIP(r *http.Request) string {
	if v := r.Header.Values("X-Real-Ip"); len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return "unknown"
}

// rtAuthUserAgent is the User-Agent header, or nil.
func rtAuthUserAgent(r *http.Request) *string {
	if v := r.Header.Values("User-Agent"); len(v) > 0 {
		return &v[0]
	}
	return nil
}

type rtAuthSetupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type rtAuthLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// rtAuthSetupStatus — GET /api/auth/setup-status: is setup needed (no users)?
func rtAuthSetupStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	count, err := queryScalar[int64](r.Context(), st.DB, "SELECT COUNT(*) FROM users")
	if err != nil {
		return internalError("check setup status", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"needs_setup": count == 0})
	return nil
}

// rtAuthSetup — POST /api/auth/setup: create the initial admin. Only works
// when no users exist.
func rtAuthSetup(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var body rtAuthSetupRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	// Fast path: reject if setup already completed (avoids expensive Argon2 hash)
	count, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM users")
	if err != nil {
		return internalError("initial setup", err)
	}
	if count > 0 {
		return apiErr(http.StatusForbidden, "Setup already completed")
	}

	if body.Email == "" || len(body.Email) > 254 || !strings.Contains(body.Email, "@") {
		return apiErr(http.StatusBadRequest, "Valid email address is required")
	}
	if len(body.Password) < 8 {
		return apiErr(http.StatusBadRequest, "Password must be at least 8 characters")
	}

	hash, err := hashPassword(body.Password)
	if err != nil {
		return internalError("initial setup", err)
	}

	// Atomic check-and-insert to prevent TOCTOU race.
	//
	// `email_verified` is TRUE here, and that is the whole difference between
	// this door and `register`. This is the bootstrap door: it runs once, only
	// while the table is empty, for the person who already has the box. It
	// issues no email_token and sends no mail, so there is no ceremony to
	// complete and nobody to complete it against.
	//
	// Leaving it FALSE made the first administrator of every install a latent
	// lockout: login refuses an unverified account whenever smtp_host is merely
	// NON-EMPTY, so the gate armed the moment the operator configured mail —
	// against their own account — and both exits (the token door, which this
	// user has no token for, and reset_password, which needs mail) needed the
	// mail being configured. Reported as #100 by an operator who reinstalled to
	// get back in.
	user, err := queryOpt[User](ctx, st.DB,
		"INSERT INTO users (email, password_hash, role, email_verified) "+
			"SELECT $1, $2, 'admin', TRUE "+
			"WHERE NOT EXISTS (SELECT 1 FROM users) "+
			"RETURNING *", body.Email, hash)
	if err != nil {
		return internalError("initial setup", err)
	}
	if user == nil {
		return apiErr(http.StatusForbidden, "Setup already completed")
	}

	slog.Info("Initial admin created: " + user.Email)

	// Now that we have an admin user, register the local server (deferred from startup)
	if st.Agents.LocalServerID() == nil {
		localID, _ := AgentEnsureLocalServer(ctx, st.DB, st.Config.AgentToken, st.Config.JWTSecret)
		if localID != uuid.Nil {
			st.Agents.SetLocalServerID(localID)
			slog.Info(fmt.Sprintf("Local server registered after setup: %s", localID))
		}
	}

	writeJSON(w, http.StatusCreated, map[string]any{"id": user.ID, "email": user.Email, "role": user.Role})
	return nil
}

// rtAuthLogin — POST /api/auth/login: authenticate and return the JWT in an
// HttpOnly cookie.
func rtAuthLogin(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var body rtAuthLoginRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	ip := rtAuthRealIP(r)

	// Rate limit: max 5 attempts per 15 minutes
	st.LoginMu.Lock()
	now := time.Now()
	entry := rtAuthRetain(st.LoginAttempts[ip], now, 900*time.Second)
	st.LoginAttempts[ip] = entry
	if len(entry) >= 5 {
		st.LoginMu.Unlock()
		return apiErr(http.StatusTooManyRequests, "Too many login attempts. Try again in 15 minutes.")
	}
	st.LoginMu.Unlock()

	// GAP 68: IP whitelist check — block login from non-whitelisted IPs
	if err := rtAuthEnforcePanelIPAllowlist(ctx, st, r); err != nil {
		return err
	}

	userOpt, err := queryOpt[User](ctx, st.DB, "SELECT * FROM users WHERE email = $1", body.Email)
	if err != nil {
		return internalError("login", err)
	}

	// Constant-time: always run Argon2 verify, even for non-existent users
	// (prevents a timing attack).
	if userOpt == nil {
		// Run dummy verify to equalize timing, then fail
		_, _ = verifyPassword(body.Password, rtAuthDummyPasswordHash)
		rtAuthRecordLoginAttempt(st, ip)
		// Log failed login with email only (no user ID available).
		//
		// This is the branch that matters for detection and it is the one that
		// was never recorded: it used to pass the nil uuid, which
		// fk_activity_logs_user rejects, so the insert failed silently for every
		// release this endpoint existed. Credential stuffing and username
		// probing are, by definition, attempts against emails that do not exist
		// — GET /api/security/login-audit could not show them because there was
		// nothing to show.
		ActivityLogActivitySystem(ctx, st.DB, body.Email, "auth.login_failed", nil, nil, new("unknown_user"), &ip, nil)
		SecurityHardeningAuditLog(ctx, st.DB, "auth.login_failed", &body.Email, &ip, nil, nil, new("unknown_user"), nil, "warning", nil)
		return apiErr(http.StatusUnauthorized, "Invalid credentials")
	}
	user := userOpt

	// An account created through an identity provider has no password at all
	// — rt_oauth stores the empty string — and an empty string is not a PHC
	// string. Answering that with a 500 made this door an oracle ("this
	// address exists and signs in with SSO"), and the early return skipped the
	// rate limit and the activity log — an unauthenticated, unthrottled,
	// unlogged enumeration channel. Having no password is failing to present
	// one, so it is answered exactly like a wrong password, at the same cost:
	// the dummy verify runs first, or the status oracle would simply become a
	// timing oracle.
	var verified bool
	if user.PasswordHash == "" {
		_, _ = verifyPassword(body.Password, rtAuthDummyPasswordHash)
	} else {
		ok, err := verifyPassword(body.Password, user.PasswordHash)
		if err != nil {
			return apiErr(http.StatusInternalServerError, "Password hash error")
		}
		verified = ok
	}
	if !verified {
		rtAuthRecordLoginAttempt(st, ip)
		// Log failed login attempt (never log password)
		ActivityLogActivity(ctx, st.DB, user.ID, user.Email, "auth.login_failed", nil, nil, nil, &ip, nil)
		SecurityHardeningAuditLog(ctx, st.DB, "auth.login_failed", &user.Email, &ip, nil, nil, nil, nil, "warning", nil)
		return apiErr(http.StatusUnauthorized, "Invalid credentials")
	}

	// Success — clear rate limit for this IP
	st.LoginMu.Lock()
	delete(st.LoginAttempts, ip)
	st.LoginMu.Unlock()

	// Block login for suspended accounts (parity with the passkey path).
	// Without this, suspension is bypassable by logging in again.
	if user.Role == "suspended" {
		return apiErr(http.StatusForbidden, "Account suspended")
	}

	// Block login if email not verified and SMTP is configured
	if !user.EmailVerified && rtAuthSMTPConfigured(ctx, st) {
		return apiErr(http.StatusForbidden, "Email not verified. Check your inbox.")
	}

	// Feature 9: Block non-admin logins during lockdown
	if user.Role != "admin" && SecurityHardeningIsLockedDown(ctx, st.DB) {
		return apiErr(http.StatusServiceUnavailable, "System is in lockdown mode. Only admins can login.")
	}

	// Feature 8: Block login if user is not approved
	if approved, err := queryScalarOpt[bool](ctx, st.DB, "SELECT COALESCE(approved, TRUE) FROM users WHERE id = $1", user.ID); err == nil && approved != nil && !*approved {
		return apiErr(http.StatusForbidden, "Account pending admin approval")
	}

	// If 2FA is enabled, return a temporary token instead of a full session
	if user.TotpEnabled {
		temp, err := rtAuthMintTwoFaToken(st, user.ID)
		if err != nil {
			return internalError("login", err)
		}
		// Empty cookie header (no session yet)
		w.Header().Set("Set-Cookie", "")
		writeJSON(w, http.StatusOK, map[string]any{"requires_2fa": true, "temp_token": temp})
		return nil
	}

	_, cookie, jti, err := rtAuthIssueSession(st, user, r)
	if err != nil {
		return err
	}

	// Record session
	_, _ = execSQL(ctx, st.DB, "INSERT INTO user_sessions (user_id, jti, ip_address, user_agent) VALUES ($1, $2, $3, $4)",
		user.ID, jti, ip, rtAuthUserAgent(r))

	// Feature 1: Geo-IP alert on login from new/suspicious IP
	// Feature 7: Write to immutable audit log
	go rtAuthLoginBackground(context.WithoutCancel(ctx), st, user.Email, ip)

	// Check if 2FA is enforced
	enforce, err := queryScalarOpt[string](ctx, st.DB, "SELECT COALESCE(value, 'false') FROM settings WHERE key = 'enforce_2fa'")
	enforce2fa := err == nil && enforce != nil && *enforce == "true"

	resp := map[string]any{"user": map[string]any{"id": user.ID, "email": user.Email, "role": user.Role}}
	// If 2FA enforced but user hasn't set it up, include flag in response
	if enforce2fa && !user.TotpEnabled {
		resp["twofa_required"] = true
	}
	w.Header().Set("Set-Cookie", cookie)
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// rtAuthLoginBackground is the detached geo-IP/audit work after a login.
func rtAuthLoginBackground(ctx context.Context, st *AppState, email, ip string) {
	// Check if lockdown is active (Feature 9): log but don't block admin logins
	if SecurityHardeningIsLockedDown(ctx, st.DB) {
		SecurityHardeningAuditLog(ctx, st.DB, "login.during_lockdown", &email, &ip, nil, nil, nil, nil, "warning", nil)
	}

	geo := SecurityHardeningLookupGeoIP(ctx, ip)

	// Write immutable audit log
	SecurityHardeningAuditLog(ctx, st.DB, "login", &email, &ip, new("user"), nil, nil, geo, "info", nil)

	if SecurityHardeningGetSettingBool(ctx, st.DB, "security_geo_alert_enabled", true) {
		// "Have we seen this address before?" has to be asked of a record that
		// outlives the answer. It used to count user_sessions, which retention
		// truncates at 24 hours — so every address became new again the day
		// after it was last used and alerted for ever (25 identical "Login from
		// new IP" notifications from 5 addresses, 14 of them our own deploy
		// script's loopback). security_audit_log records every login with its
		// address and a DELETE trigger refuses to age it out. The `<= 1` holds
		// because the row for this login was written a few lines above.
		known, err := queryScalarOpt[int64](ctx, st.DB,
			"SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'login' AND actor_email = $1 AND actor_ip = $2", email, ip)
		isNewIP := err != nil || known == nil || *known <= 1
		if geo != nil && (isNewIP || geo.Proxy || geo.Hosting) {
			SecurityHardeningAlertSuspiciousIP(ctx, st.DB, "Login", email, ip, geo)
		}
	}
}

// rtAuthRetain drops entries older than window (Vec::retain).
func rtAuthRetain(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < window {
			out = append(out, t)
		}
	}
	return out
}

// rtAuthRateLimitPush is the register/forgot/reset limiter shape: retain the
// window, refuse at max, else record this attempt.
func rtAuthRateLimitPush(st *AppState, key string, window time.Duration, max int, msg string) error {
	st.LoginMu.Lock()
	defer st.LoginMu.Unlock()
	now := time.Now()
	entry := rtAuthRetain(st.LoginAttempts[key], now, window)
	if len(entry) >= max {
		st.LoginAttempts[key] = entry
		return apiErr(http.StatusTooManyRequests, msg)
	}
	st.LoginAttempts[key] = append(entry, now)
	return nil
}

func rtAuthSMTPConfigured(ctx context.Context, st *AppState) bool {
	v, err := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'smtp_host'")
	return err == nil && v != nil && *v != ""
}

// rtAuthRequestIsHTTPS: this request arrived over HTTPS, directly or via a
// reverse proxy that set X-Forwarded-Proto. Browsers reject Secure cookies on
// plain HTTP, so Secure is set only when the connection is actually encrypted
// (#47 — HTTP-on-IP installs were stuck in a login bounce).
func rtAuthRequestIsHTTPS(r *http.Request) bool {
	v := r.Header.Values("X-Forwarded-Proto")
	return len(v) > 0 && strings.EqualFold(v[0], "https")
}

// rtAuthCookieSecureFlag ties Secure strictly to the actual connection scheme
// as seen by nginx (X-Forwarded-Proto $scheme). Do NOT key off BASE_URL:
// setup.sh writes BASE_URL=https://<domain> when a domain is supplied, but the
// panel vhost is served over plain HTTP until TLS is added, and a Secure cookie
// on that HTTP response is silently dropped, bouncing the very first login
// (#71). The API only listens on 127.0.0.1 behind nginx, so the scheme can
// only come from the proxy header.
func rtAuthCookieSecureFlag(r *http.Request) string {
	if rtAuthRequestIsHTTPS(r) {
		return "; Secure"
	}
	return ""
}

// rtAuthEnforcePanelIPAllowlist enforces allowed_panel_ips for a request
// about to establish a session.
//
// **Call this from every door that can mint one.** The allowlist gates access
// to the panel, not one handler: until v2.47.0 it lived inline in login alone,
// so the passkey and OAuth doors answered from anywhere while issuing the same
// cookie. Fails CLOSED when the proxy sends no X-Real-IP — an allowlist that
// cannot identify the caller must not admit them (panelIPAllowed).
func rtAuthEnforcePanelIPAllowlist(ctx context.Context, st *AppState, r *http.Request) error {
	ips, err := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'allowed_panel_ips'")
	if err != nil {
		return internalError("login ip whitelist", err)
	}
	if ips != nil && strings.TrimSpace(*ips) != "" {
		// Until v2.46.0 this compared the header to each entry as a STRING, so
		// CIDR ranges never matched and an operator who entered one locked
		// themselves out instead of restricting access.
		if !panelIPAllowed(*ips, r.Header.Get("X-Real-Ip")) {
			return apiErr(http.StatusForbidden, "Access denied: IP not whitelisted")
		}
	}
	return nil
}

// rtAuthIssueSession issues a JWT session token + cookie for a user. Returns
// (token, cookie, jti) so callers can record the session. Used by the
// password, 2FA and passkey doors.
func rtAuthIssueSession(st *AppState, user *User, r *http.Request) (string, string, string, error) {
	now := time.Now()
	jti := uuid.NewString()
	claims := Claims{
		Sub: user.ID, Email: user.Email, Role: user.Role,
		Iat: uint64(now.Unix()), Exp: uint64(now.Add(2 * time.Hour).Unix()),
		Jti: &jti,
	}
	token, err := encodeJWT(&claims, st.Config.JWTSecret)
	if err != nil {
		return "", "", "", internalError("login", err)
	}
	cookie := fmt.Sprintf("token=%s; Path=/; HttpOnly%s; SameSite=Lax; Max-Age=7200", token, rtAuthCookieSecureFlag(r))
	return token, cookie, jti, nil
}

func rtAuthRecordLoginAttempt(st *AppState, ip string) {
	st.LoginMu.Lock()
	st.LoginAttempts[ip] = append(st.LoginAttempts[ip], time.Now())
	st.LoginMu.Unlock()
}

// rtAuthBlacklistJTIs adds JTIs to the in-memory blacklist and persists them
// (GAP 66: survives restart).
func rtAuthBlacklistJTIs(ctx context.Context, st *AppState, jtis []string) {
	if len(jtis) == 0 {
		return
	}
	st.blacklistAdd(jtis...)
	for _, j := range jtis {
		_, _ = execSQL(ctx, st.DB, "INSERT INTO token_blacklist (jti, expires_at) VALUES ($1, NOW() + INTERVAL '2 hours') ON CONFLICT DO NOTHING", j)
	}
}

// rtAuthLogout — POST /api/auth/logout: clear the cookie and blacklist the JTI.
func rtAuthLogout(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if claims, err := st.authUser(r); err == nil && claims.Jti != nil {
		jti := *claims.Jti
		rtAuthBlacklistJTIs(r.Context(), st, []string{jti})
		_, _ = execSQL(r.Context(), st.DB, "DELETE FROM user_sessions WHERE jti = $1", jti)
	}
	w.Header().Set("Set-Cookie", fmt.Sprintf("token=; Path=/; HttpOnly%s; SameSite=Lax; Max-Age=0", rtAuthCookieSecureFlag(r)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtAuthMe — GET /api/auth/me.
func rtAuthMe(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": c.Sub, "email": c.Email, "role": c.Role})
	return nil
}

// ─── SaaS Registration & Password Reset ────────────────────────────────────

type rtAuthRegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// rtAuthRegisterUser — POST /api/auth/register: self-registration (creates an
// unverified account). Named …User because rtAuthRegister is the registrar.
func rtAuthRegisterUser(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var body rtAuthRegisterRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	// Feature 9/11: Block registration during lockdown
	if SecurityHardeningIsLockedDown(ctx, st.DB) {
		return apiErr(http.StatusServiceUnavailable, "System is in lockdown mode. Registration disabled.")
	}

	// Check if self-registration is enabled (default: disabled)
	reg, err := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'self_registration_enabled'")
	if err != nil {
		return internalError("register user", err)
	}
	if reg == nil || *reg != "true" {
		return apiErr(http.StatusForbidden, "Registration is disabled")
	}

	// Rate limit: 3 registrations per IP per hour
	ip := rtAuthRealIP(r)
	if err := rtAuthRateLimitPush(st, "register:"+ip, time.Hour, 3, "Too many registration attempts. Try again later."); err != nil {
		return err
	}

	if body.Email == "" || len(body.Email) > 254 || !strings.Contains(body.Email, "@") {
		return apiErr(http.StatusBadRequest, "Valid email address is required")
	}
	if len(body.Password) < 8 {
		return apiErr(http.StatusBadRequest, "Password must be at least 8 characters")
	}

	// Check email uniqueness — return generic success to prevent account enumeration
	existing, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM users WHERE email = $1", body.Email)
	if err != nil {
		return internalError("register user", err)
	}
	if existing != nil {
		writeJSON(w, http.StatusCreated, map[string]any{"message": "Account created. Check your email to verify."})
		return nil
	}

	hash, err := hashPassword(body.Password)
	if err != nil {
		return internalError("register user", err)
	}
	token, tokenHash := rtAuthGenerateToken()

	user, err := queryOne[User](ctx, st.DB,
		"INSERT INTO users (email, password_hash, role, email_verified, email_token) "+
			"VALUES ($1, $2, 'user', FALSE, $3) RETURNING *", body.Email, hash, tokenHash)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			// Generic error to prevent account enumeration (race condition path)
			return apiErr(http.StatusInternalServerError, "Registration failed. Please try again.")
		}
		return internalError("register user", err)
	}

	// Use the configured BASE_URL — never derive from request headers (attacker-controlled)
	baseURL := st.Config.BaseURL

	// Check if SMTP is configured — if not, auto-verify (self-hosted convenience)
	if !rtAuthSMTPConfigured(ctx, st) {
		slog.Info("SMTP not configured — auto-verifying " + body.Email)
		_, _ = execSQL(ctx, st.DB, "UPDATE users SET email_verified = TRUE, email_token = NULL, updated_at = NOW() WHERE id = $1", user.ID)
	} else if err := EmailSendVerificationEmail(ctx, st.DB, body.Email, token, baseURL); err != nil {
		// Don't auto-verify — user must retry or admin must verify manually
		slog.Warn(fmt.Sprintf("Failed to send verification email to %s: %v", body.Email, err))
	} else {
		slog.Info("Verification email sent to " + body.Email)
	}

	ActivityLogActivity(ctx, st.DB, user.ID, user.Email, "auth.register", nil, nil, nil, &ip, nil)

	// Feature 1/7: Geo-IP alert and immutable audit log on registration
	go func(ctx context.Context, email string) {
		geo := SecurityHardeningLookupGeoIP(ctx, ip)
		SecurityHardeningAuditLog(ctx, st.DB, "register", &email, &ip, new("user"), nil, nil, geo, "info", nil)
		// Alert admins about new registration (especially from proxy/datacenter IPs)
		if SecurityHardeningGetSettingBool(ctx, st.DB, "security_geo_alert_enabled", true) && geo != nil {
			SecurityHardeningAlertSuspiciousIP(ctx, st.DB, "Registration", email, ip, geo)
		}
		// Feature 4: Record as suspicious if from proxy/datacenter
		if geo != nil && (geo.Proxy || geo.Hosting) {
			d := fmt.Sprintf("Registration from %s/%s (%s)", geo.Country, geo.City, geo.ISP)
			SecurityHardeningRecordSuspiciousEvent(ctx, st.DB, "register.proxy_ip", &email, &ip, &d)
		}
	}(context.WithoutCancel(ctx), user.Email)

	// Feature 8: If approval mode is on, set user as unapproved
	if SecurityHardeningGetSettingBool(ctx, st.DB, "security_approval_required", false) {
		_, _ = execSQL(ctx, st.DB, "UPDATE users SET approved = FALSE WHERE id = $1", user.ID)
		writeJSON(w, http.StatusCreated, map[string]any{
			"id": user.ID, "email": user.Email,
			"message":          "Account created. Awaiting admin approval.",
			"pending_approval": true,
		})
		return nil
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id": user.ID, "email": user.Email, "message": "Account created. Check your email to verify.",
	})
	return nil
}

type rtAuthVerifyEmailRequest struct {
	Token string `json:"token"`
}

// rtAuthVerifyEmail — POST /api/auth/verify-email.
func rtAuthVerifyEmail(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var body rtAuthVerifyEmailRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB,
		"UPDATE users SET email_verified = TRUE, email_token = NULL, updated_at = NOW() "+
			"WHERE email_token = $1 AND email_verified = FALSE", rtAuthHashToken(body.Token))
	if err != nil {
		return internalError("verify email", err)
	}
	if n == 0 {
		return apiErr(http.StatusBadRequest, "Invalid or expired verification token")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Email verified successfully"})
	return nil
}

type rtAuthForgotPasswordRequest struct {
	Email string `json:"email"`
}

// rtAuthForgotPassword — POST /api/auth/forgot-password.
func rtAuthForgotPassword(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var body rtAuthForgotPasswordRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	// Rate limit: 3 requests per email per 15 minutes
	if err := rtAuthRateLimitPush(st, "forgot:"+strings.ToLower(body.Email), 900*time.Second, 3,
		"Too many password reset requests. Try again later."); err != nil {
		return err
	}

	// Always return success to prevent email enumeration
	success := map[string]any{"ok": true, "message": "If an account exists with that email, a reset link has been sent."}

	user, err := queryOpt[User](ctx, st.DB, "SELECT * FROM users WHERE email = $1", body.Email)
	if err != nil {
		return internalError("forgot password", err)
	}
	// A suspended account gets no reset token: every other door already
	// refuses it. ⚠ Return the SAME success body, never an error — a refusal
	// here would turn this enumeration-proof handler into an oracle that also
	// discloses WHICH addresses are suspended.
	if user == nil || user.Role == "suspended" {
		writeJSON(w, http.StatusOK, success)
		return nil
	}

	token, tokenHash := rtAuthGenerateToken()
	expires := time.Now().Add(time.Hour)
	if _, err := execSQL(ctx, st.DB, "UPDATE users SET reset_token = $1, reset_expires = $2, updated_at = NOW() WHERE id = $3",
		tokenHash, expires, user.ID); err != nil {
		return internalError("forgot password", err)
	}

	// Use the configured BASE_URL — never derive from request headers (attacker-controlled)
	if err := EmailSendResetEmail(ctx, st.DB, body.Email, token, st.Config.BaseURL); err != nil {
		slog.Warn(fmt.Sprintf("Could not send reset email to %s: %v", body.Email, err))
	}
	writeJSON(w, http.StatusOK, success)
	return nil
}

type rtAuthResetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// rtAuthResetPassword — POST /api/auth/reset-password.
func rtAuthResetPassword(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var body rtAuthResetPasswordRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	// Rate limit: 5 attempts per IP per 15 minutes
	if err := rtAuthRateLimitPush(st, "reset:"+rtAuthRealIP(r), 900*time.Second, 5, "Too many reset attempts. Try again later."); err != nil {
		return err
	}
	if len(body.Password) < 8 {
		return apiErr(http.StatusBadRequest, "Password must be at least 8 characters")
	}

	user, err := queryOpt[User](ctx, st.DB, "SELECT * FROM users WHERE reset_token = $1 AND reset_expires > $2",
		rtAuthHashToken(body.Token), time.Now())
	if err != nil {
		return internalError("reset password", err)
	}
	// A token minted before the account was suspended answers with the
	// sentence an unknown token gets, so it stays silent about why.
	if user == nil || user.Role == "suspended" {
		return apiErr(http.StatusBadRequest, "Invalid or expired reset token")
	}

	hash, err := hashPassword(body.Password)
	if err != nil {
		return internalError("reset password", err)
	}
	if _, err := execSQL(ctx, st.DB,
		"UPDATE users SET password_hash = $1, reset_token = NULL, reset_expires = NULL, "+
			"email_verified = TRUE, updated_at = NOW() WHERE id = $2", hash, user.ID); err != nil {
		return internalError("reset password", err)
	}

	// Invalidate ALL sessions for this user (no current session to preserve)
	jtis, _ := queryAll[string](ctx, st.DB, "DELETE FROM user_sessions WHERE user_id = $1 RETURNING jti", user.ID)
	rtAuthBlacklistJTIs(ctx, st, jtis)

	ActivityLogActivity(ctx, st.DB, user.ID, user.Email, "auth.password_reset", nil, nil, nil, nil, nil)
	SecurityHardeningAuditLog(ctx, st.DB, "auth.password_reset", &user.Email, nil, nil, nil, nil, nil, "warning", nil)

	NotificationsNotifyPanel(ctx, st.DB, &user.ID, "Password reset", "Your password was reset successfully", "warning", "security", new("/account"))

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Password reset successfully"})
	return nil
}

// ─── Two-Factor Authentication (TOTP) ─────────────────────────────────────

// rtAuthTwoFaClaims is the temporary 2FA token (5-minute expiry). Field order
// matches the serde struct; all three are required on decode.
type rtAuthTwoFaClaims struct {
	Sub     uuid.UUID `json:"sub"`
	Purpose string    `json:"purpose"`
	Exp     uint64    `json:"exp"`
}

func (c *rtAuthTwoFaClaims) UnmarshalJSON(b []byte) error {
	var aux struct {
		Sub     *uuid.UUID `json:"sub"`
		Purpose *string    `json:"purpose"`
		Exp     *uint64    `json:"exp"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if aux.Sub == nil || aux.Purpose == nil || aux.Exp == nil {
		return errors.New("missing required claim")
	}
	*c = rtAuthTwoFaClaims{Sub: *aux.Sub, Purpose: *aux.Purpose, Exp: *aux.Exp}
	return nil
}

func (c *rtAuthTwoFaClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(int64(c.Exp), 0)), nil
}
func (c *rtAuthTwoFaClaims) GetIssuedAt() (*jwt.NumericDate, error)  { return nil, nil }
func (c *rtAuthTwoFaClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c *rtAuthTwoFaClaims) GetIssuer() (string, error)              { return "", nil }
func (c *rtAuthTwoFaClaims) GetSubject() (string, error)             { return c.Sub.String(), nil }
func (c *rtAuthTwoFaClaims) GetAudience() (jwt.ClaimStrings, error)  { return nil, nil }

// rtAuthMintTwoFaToken mints the 5-minute "2fa"-purpose token (HS256). Shared
// by the password door and the OAuth callback.
func rtAuthMintTwoFaToken(st *AppState, sub uuid.UUID) (string, error) {
	c := &rtAuthTwoFaClaims{Sub: sub, Purpose: "2fa", Exp: uint64(time.Now().Add(5 * time.Minute).Unix())}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(st.Config.JWTSecret))
}

// rtAuthDecodeTwoFaToken verifies HS256 + exp (leeway 0).
func rtAuthDecodeTwoFaToken(token, secret string) (*rtAuthTwoFaClaims, error) {
	c := &rtAuthTwoFaClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}), jwt.WithoutClaimsValidation())
	if _, err := p.ParseWithClaims(token, c, func(*jwt.Token) (any, error) { return []byte(secret), nil }); err != nil {
		return nil, err
	}
	if int64(c.Exp) < time.Now().Unix() {
		return nil, jwt.ErrTokenExpired
	}
	return c, nil
}

// rtAuthGenerateRecoveryCodes generates 10 recovery codes (16 hex chars each).
//
// ⚠ These were 4 bytes — **32 bits** — stored as an UNSALTED SHA-256, a fast
// hash: exhaustible in seconds by anyone holding a copy of the users table,
// which is precisely the situation 2FA exists to survive. Widened to 8 bytes /
// 64 bits. The hash is deliberately NOT changed to Argon2: matching is by
// hash, so already-issued codes would split across two schemes, and a
// migration cannot re-hash values it cannot read. Older 8-character codes
// keep working — rtAuthTryRecoveryCode compares hashes, never length.
func rtAuthGenerateRecoveryCodes() []string {
	codes := make([]string, 10)
	for i := range codes {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		codes[i] = hex.EncodeToString(b)
	}
	return codes
}

// The 2FA challenge limiter — 5 attempts per 5 minutes, keyed on the user.
//
// It lived inline in twofa_verify alone, so it guarded the login door only.
// twofa_disable checks the SAME 6-digit code against the SAME secret to make
// the change that switches the factor OFF, and it could be guessed without
// limit (skew 1 → 3 of 10^6 codes live at any instant; nothing above the
// handler limits /api/). Three small functions rather than one guard because
// the success path has to CLEAR the counter, and only the handler knows when.
func rtAuthTwofaRateLimitCheck(st *AppState, userID uuid.UUID) error {
	st.TwofaMu.Lock()
	defer st.TwofaMu.Unlock()
	if e, ok := st.TwofaAttempts[userID]; ok {
		el := uint64(time.Since(e.Start) / time.Second)
		if el < 300 && e.Count >= 5 {
			mins := (300 - el + 59) / 60
			return apiErr(http.StatusTooManyRequests, fmt.Sprintf("Too many attempts. Try again in %d minutes.", mins))
		}
	}
	return nil
}

// rtAuthTwofaRateLimitRecord records one failed attempt, rolling the window
// if it has expired.
func rtAuthTwofaRateLimitRecord(st *AppState, userID uuid.UUID) {
	st.TwofaMu.Lock()
	defer st.TwofaMu.Unlock()
	now := time.Now()
	e, ok := st.TwofaAttempts[userID]
	if !ok {
		e = RateWindow{Count: 0, Start: now}
	}
	if now.Sub(e.Start) >= 300*time.Second {
		e = RateWindow{Count: 1, Start: now}
	} else {
		e.Count++
	}
	st.TwofaAttempts[userID] = e
}

// rtAuthTwofaRateLimitClear clears the counter after a code was accepted.
func rtAuthTwofaRateLimitClear(st *AppState, userID uuid.UUID) {
	st.TwofaMu.Lock()
	delete(st.TwofaAttempts, userID)
	st.TwofaMu.Unlock()
}

// rtAuthTotp is TOTP::new(SHA1, 6 digits, skew 1, step 30, secret,
// issuer "DockPanel", account email) — including its construction errors:
// a secret shorter than 128 bits, or an issuer/account name containing ':'.
type rtAuthTotp struct {
	secret  []byte
	account string
}

var rtAuthB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// rtAuthNewTotp builds the checker from the stored base32 secret
// (Secret::Encoded(..).to_bytes() + TOTP::new).
func rtAuthNewTotp(secretB32, account string) (*rtAuthTotp, error) {
	secret, err := rtAuthB32.DecodeString(strings.TrimRight(secretB32, "="))
	if err != nil {
		return nil, errors.New("could not parse base32 secret")
	}
	if len(secret) < 16 {
		return nil, fmt.Errorf("the length of the shared secret MUST be at least 128 bits. %d bits is not enough", len(secret)*8)
	}
	if strings.Contains(account, ":") {
		return nil, fmt.Errorf("account name must not contain a colon. %q contains it", account)
	}
	return &rtAuthTotp{secret: secret, account: account}, nil
}

// checkCurrent is TOTP::check_current: an exact (untrimmed) 6-digit match at
// the current step or one step either side, compared in constant time.
func (t *rtAuthTotp) checkCurrent(code string) bool {
	if len(code) != 6 || strings.TrimSpace(code) != code {
		return false
	}
	ok, err := totp.ValidateCustom(code, base32.StdEncoding.EncodeToString(t.secret), time.Now(),
		totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	return err == nil && ok
}

// rtAuthURLEncode is urlencoding::encode: everything but ALPHA / DIGIT /
// "-" / "." / "_" / "~" is percent-encoded.
func rtAuthURLEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// url is TOTP::get_url for SHA1/6/30 with issuer "DockPanel".
func (t *rtAuthTotp) url() string {
	issuer := rtAuthURLEncode("DockPanel")
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, rtAuthURLEncode(t.account), rtAuthB32.EncodeToString(t.secret), issuer)
}

// rtAuthQRSVG renders content as the SVG the qrcode crate emitted for
// `.render::<svg::Color>().min_dimensions(200, 200)`: EC level M, a 4-module
// quiet zone, square modules sized to reach at least 200px, a white
// background rect and one black path of M…h…v…H…V… rects.
func rtAuthQRSVG(content string) (string, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", err
	}
	q.DisableBorder = true
	bm := q.Bitmap()
	n := uint32(len(bm))
	const qz = 4
	width := n + 2*qz
	unit := (200 + width - 1) / width
	if unit < 1 {
		unit = 1
	}
	real := width * unit
	var b strings.Builder
	fmt.Fprintf(&b, `<?xml version="1.0" standalone="yes"?><svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="%d" height="%d" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect x="0" y="0" width="%d" height="%d" fill="#fff"/><path fill="#000" d="`,
		real, real, real, real, real, real)
	for y := uint32(0); y < n; y++ {
		for x := uint32(0); x < n; x++ {
			if bm[y][x] {
				l, t := (x+qz)*unit, (y+qz)*unit
				fmt.Fprintf(&b, "M%d %dh%dv%dH%dV%d", l, t, unit, unit, l, t)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}

// rtAuthReauthMaxSessionAgeSecs is how stale a session may be before an account that
// can present *nothing* is asked to sign in again. Deliberately far shorter
// than the cookie's own Max-Age (7200s): a window at or above the cookie
// lifetime is satisfied by every live session by construction and would
// guard nothing.
const rtAuthReauthMaxSessionAgeSecs int64 = 300

// rtAuthEnrolmentProof is proof presented when enrolling a new authenticator.
// Both fields are optional because the *first* request carries neither —
// that request IS the challenge, and the refusal it earns tells the client
// which fields to collect.
type rtAuthEnrolmentProof struct {
	Code            *string `json:"code" serde:"default"`
	CurrentPassword *string `json:"current_password" serde:"default"`
}

// rtAuthReauthRequired is the refusal that asks a caller to re-present a
// credential. `methods` is a LIST, never a single chosen value: an account
// holding both a password and an authenticator must be offered both.
func rtAuthReauthRequired(msg string, methods []string, provider *string) error {
	return apiErrJSON(http.StatusForbidden, map[string]any{
		"error": msg, "code": CodeReauthRequired, "methods": methods, "provider": provider,
	})
}

// rtAuthRequireEnrolmentProof requires proof of identity before this account
// may enrol a new authenticator.
//
// **Why enrolment and not removal.** A passkey is the only credential this
// panel mints that survives every remediation it offers: resetting the
// password, clearing 2FA and revoking every session all leave the passkeys row
// intact, and passkey sign-in skips the 2FA step. A session hijacker who
// enrols one converts a transient compromise into a permanent, 2FA-free door.
// The door to guard is the one that PLANTS the credential.
//
// **Why any one factor, and not the strongest.** The guide tells a sole admin
// who lost both authenticator and recovery codes to register a passkey — the
// documented way back. Demanding a TOTP code would refuse exactly those
// accounts at the door that repairs them. Against the threat being closed (a
// hijacker with a cookie but neither password nor authenticator), a password
// is just as unanswerable as a code.
//
// **Why a freshness fallback rather than a refusal.** An identity-provider
// account has an empty password hash and may hold no authenticator, so it can
// present nothing. Refusing would bar it from passkeys permanently. It falls
// back to session age instead — a real but weaker bound: it stops a cookie
// replayed from another machine and buys little against script injection on
// the panel's own origin. Not equivalence.
func rtAuthRequireEnrolmentProof(ctx context.Context, st *AppState, claims *Claims, user *User, proof *rtAuthEnrolmentProof) error {
	hasPassword := user.PasswordHash != ""
	hasTotp := user.TotpEnabled

	// Nothing to present. Fall back to how recently this session
	// authenticated: iat is stamped once when the session is minted and there
	// is no refresh route that would re-stamp it.
	if !hasPassword && !hasTotp {
		age := time.Now().Unix() - int64(claims.Iat)
		if age <= rtAuthReauthMaxSessionAgeSecs {
			return nil
		}
		label := "your identity provider"
		if user.OAuthProvider != nil {
			label = *user.OAuthProvider
		}
		return rtAuthReauthRequired(fmt.Sprintf("For security, sign in again with %s before adding a passkey.", label),
			[]string{"oauth"}, user.OAuthProvider)
	}

	// Checked before any verification so a locked-out caller is refused
	// without spending an Argon2 hash on them.
	if err := rtAuthTwofaRateLimitCheck(st, user.ID); err != nil {
		return err
	}

	passed := false
	if hasPassword && proof.CurrentPassword != nil && *proof.CurrentPassword != "" {
		// Unreachable on an empty hash, so unlike login this cannot parse an
		// empty string and fail internally.
		if ok, err := verifyPassword(*proof.CurrentPassword, user.PasswordHash); err == nil {
			passed = ok
		}
	}

	if !passed && hasTotp && proof.Code != nil && *proof.Code != "" {
		candidate := *proof.Code
		if user.TotpSecret != nil {
			secret := SecretsCryptoDecryptCredentialOrLegacy(*user.TotpSecret, st.Config.JWTSecret)
			if t, err := rtAuthNewTotp(secret, user.Email); err == nil {
				passed = t.checkCurrent(candidate)
			}
		}
		// The recovery codes are the fallback for a lost authenticator, and
		// this is one of the doors that repairs the account.
		if !passed {
			ok, err := rtAuthTryRecoveryCode(ctx, st, user, candidate)
			if err != nil {
				return err
			}
			passed = ok
		}
	}

	if passed {
		rtAuthTwofaRateLimitClear(st, user.ID)
		return nil
	}

	// Only an ATTEMPT counts against the limiter. The bare challenge request
	// carries no proof, and five visits to the account page must not lock the
	// user out of /auth/2fa/disable and the recovery-code reissue route, which
	// share this counter.
	if proof.Code != nil || proof.CurrentPassword != nil {
		rtAuthTwofaRateLimitRecord(st, user.ID)
	}

	methods := []string{}
	if hasPassword {
		methods = append(methods, "password")
	}
	if hasTotp {
		methods = append(methods, "totp")
	}
	var msg string
	switch {
	case hasPassword && hasTotp:
		msg = "Confirm your password, or enter a code from your authenticator app or a recovery code, to add a passkey."
	case hasPassword:
		msg = "Confirm your password to add a passkey."
	default:
		msg = "Enter a code from your authenticator app, or one of your recovery codes, to add a passkey."
	}
	return rtAuthReauthRequired(msg, methods, nil)
}

// rtAuthRecoveryCodesRemaining is how many unused recovery codes an account
// holds. 0 for both "never enrolled" and "corrupted JSON": this feeds a
// warning, and a warning that fails closed is the safe direction.
func rtAuthRecoveryCodesRemaining(stored *string) int {
	if stored == nil {
		return 0
	}
	var v []string
	if json.Unmarshal([]byte(*stored), &v) != nil {
		return 0
	}
	return len(v)
}

// rtAuthLoadUser is `SELECT * FROM users WHERE id = $1` fetch_one, any error →
// internalError(context).
func rtAuthLoadUser(ctx context.Context, st *AppState, id uuid.UUID, what string) (*User, error) {
	u, err := queryOne[User](ctx, st.DB, "SELECT * FROM users WHERE id = $1", id)
	if err != nil {
		return nil, internalError(what, err)
	}
	return &u, nil
}

// rtAuthTwofaSetup — POST /api/auth/2fa/setup: generate a TOTP secret and QR.
func rtAuthTwofaSetup(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	user, err := rtAuthLoadUser(ctx, st, claims.Sub, "2FA setup")
	if err != nil {
		return err
	}
	if user.TotpEnabled {
		return apiErr(http.StatusBadRequest, "2FA is already enabled")
	}

	// Secret::generate_secret: 160 random bits.
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return internalError("2FA setup", err)
	}
	secretB32 := rtAuthB32.EncodeToString(raw)
	t, err := rtAuthNewTotp(secretB32, user.Email)
	if err != nil {
		return internalError("2FA setup", err)
	}
	otpauthURL := t.url()

	svg, err := rtAuthQRSVG(otpauthURL)
	if err != nil {
		return internalError("2FA setup", err)
	}

	// Encrypt and store secret in DB (not yet enabled)
	enc, err := SecretsCryptoEncryptCredential(secretB32, st.Config.JWTSecret)
	if err != nil {
		return apiErr(http.StatusInternalServerError, "Encryption failed: "+err.Error())
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE users SET totp_secret = $1, updated_at = NOW() WHERE id = $2", enc, claims.Sub); err != nil {
		return internalError("2FA setup", err)
	}

	writeJSON(w, http.StatusOK, map[string]any{"secret": secretB32, "otpauth_url": otpauthURL, "qr_svg": svg})
	return nil
}

type rtAuthTwoFaVerifyRequest struct {
	Code string `json:"code"`
}

// rtAuthTwofaEnable — POST /api/auth/2fa/enable: verify a code and enable 2FA.
func rtAuthTwofaEnable(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtAuthTwoFaVerifyRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	user, err := rtAuthLoadUser(ctx, st, claims.Sub, "2FA enable")
	if err != nil {
		return err
	}
	if user.TotpEnabled {
		return apiErr(http.StatusBadRequest, "2FA is already enabled")
	}
	if user.TotpSecret == nil {
		return apiErr(http.StatusBadRequest, "Call /api/auth/2fa/setup first")
	}

	// Decrypt TOTP secret (with legacy plaintext fallback)
	secret := SecretsCryptoDecryptCredentialOrLegacy(*user.TotpSecret, st.Config.JWTSecret)
	t, err := rtAuthNewTotp(secret, user.Email)
	if err != nil {
		return internalError("2FA enable", err)
	}
	if !t.checkCurrent(body.Code) {
		return apiErr(http.StatusUnauthorized, "Invalid 2FA code")
	}

	codes := rtAuthGenerateRecoveryCodes()
	// Hash each code for storage (one-way, no reversible encryption needed)
	hashed := make([]string, len(codes))
	for i, c := range codes {
		hashed[i] = rtAuthHashToken(c)
	}
	hashedJSON, _ := json.Marshal(hashed)

	if _, err := execSQL(ctx, st.DB, "UPDATE users SET totp_enabled = TRUE, recovery_codes = $1, updated_at = NOW() WHERE id = $2",
		string(hashedJSON), claims.Sub); err != nil {
		return internalError("2FA enable", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "auth.2fa_enabled", nil, nil, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "auth.2fa_enabled", &claims.Email, ip, nil, nil, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "recovery_codes": codes, "message": "2FA enabled successfully. Save your recovery codes!",
	})
	return nil
}

type rtAuthTwoFaLoginRequest struct {
	TempToken string `json:"temp_token"`
	Code      string `json:"code"`
}

// rtAuthTwofaVerify — POST /api/auth/2fa/verify: complete login with a code.
func rtAuthTwofaVerify(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var body rtAuthTwoFaLoginRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	tc, err := rtAuthDecodeTwoFaToken(body.TempToken, st.Config.JWTSecret)
	if err != nil {
		return apiErr(http.StatusUnauthorized, "Invalid or expired 2FA token")
	}
	if tc.Purpose != "2fa" {
		return apiErr(http.StatusUnauthorized, "Invalid token purpose")
	}
	userID := tc.Sub

	// Rate limit: max 5 failed 2FA attempts per 5 minutes
	if err := rtAuthTwofaRateLimitCheck(st, userID); err != nil {
		return err
	}

	user, err := rtAuthLoadUser(ctx, st, userID, "2FA verify")
	if err != nil {
		return err
	}

	// Block suspended accounts at 2FA redemption too — closes the window where
	// a temp token was minted just before suspension.
	if user.Role == "suspended" {
		return apiErr(http.StatusForbidden, "Account suspended")
	}

	// This is a second request, holding a 5-minute bearer token, and it is what
	// actually emits the session cookie. Re-checking means the temp token
	// cannot be carried to an address the allowlist excludes, or redeemed
	// after a lockdown began.
	if err := rtAuthEnforcePanelIPAllowlist(ctx, st, r); err != nil {
		return err
	}
	if user.Role != "admin" && SecurityHardeningIsLockedDown(ctx, st.DB) {
		return apiErr(http.StatusServiceUnavailable, "System is in lockdown mode")
	}

	// No secret here does NOT mean the server is broken: an admin can reset
	// this account's 2FA (users reset_2fa) while a temp token is still live.
	// They no longer need a second factor at all, so the honest answer is
	// "start again", not a 500.
	if user.TotpSecret == nil {
		return apiErr(http.StatusUnauthorized, "Two-factor authentication is no longer set up on this account. Sign in again.")
	}
	secret := SecretsCryptoDecryptCredentialOrLegacy(*user.TotpSecret, st.Config.JWTSecret)
	t, err := rtAuthNewTotp(secret, user.Email)
	if err != nil {
		return internalError("2FA verify", err)
	}

	if !t.checkCurrent(body.Code) {
		// Try recovery codes
		used, err := rtAuthTryRecoveryCode(ctx, st, user, body.Code)
		if err != nil {
			return err
		}
		if !used {
			rtAuthTwofaRateLimitRecord(st, userID)
			return apiErr(http.StatusUnauthorized, "Invalid 2FA code")
		}
	}

	// Successful verification — clear rate limit
	rtAuthTwofaRateLimitClear(st, userID)

	_, cookie, jti, err := rtAuthIssueSession(st, user, r)
	if err != nil {
		return err
	}
	_, _ = execSQL(ctx, st.DB, "INSERT INTO user_sessions (user_id, jti, ip_address, user_agent) VALUES ($1, $2, $3, $4)",
		user.ID, jti, rtAuthRealIP(r), rtAuthUserAgent(r))

	w.Header().Set("Set-Cookie", cookie)
	writeJSON(w, http.StatusOK, map[string]any{"user": map[string]any{"id": user.ID, "email": user.Email, "role": user.Role}})
	return nil
}

// rtAuthTryRecoveryCode uses a recovery code. True if a code matched and was
// consumed.
func rtAuthTryRecoveryCode(ctx context.Context, st *AppState, user *User, code string) (bool, error) {
	if user.RecoveryCodes == nil {
		return false, nil
	}
	var hashed []string
	if json.Unmarshal([]byte(*user.RecoveryCodes), &hashed) != nil {
		return false, apiErr(http.StatusInternalServerError, "Recovery codes corrupted")
	}
	codeHash := rtAuthHashToken(code)
	// Constant-time scan of all codes to prevent timing-based brute force
	matched := -1
	for i, h := range hashed {
		if subtle.ConstantTimeCompare([]byte(h), []byte(codeHash)) == 1 {
			matched = i
		}
	}
	if matched < 0 {
		return false, nil
	}
	remaining := append(hashed[:matched:matched], hashed[matched+1:]...)
	updated, _ := json.Marshal(remaining)
	if _, err := execSQL(ctx, st.DB, "UPDATE users SET recovery_codes = $1, updated_at = NOW() WHERE id = $2", string(updated), user.ID); err != nil {
		return false, internalError("2FA verify", err)
	}
	return true, nil
}

type rtAuthTwoFaCodeRequest struct {
	Code string `json:"code"`
}

// rtAuthTwofaCodeOrRecovery is the shared body of disable/regenerate: load
// the secret, rate-limit, accept a live code OR a recovery code.
func rtAuthTwofaCodeOrRecovery(ctx context.Context, st *AppState, claims *Claims, user *User, code, what string) error {
	if err := rtAuthTwofaRateLimitCheck(st, claims.Sub); err != nil {
		return err
	}
	if user.TotpSecret == nil {
		return apiErr(http.StatusInternalServerError, "2FA secret missing")
	}
	secret := SecretsCryptoDecryptCredentialOrLegacy(*user.TotpSecret, st.Config.JWTSecret)
	t, err := rtAuthNewTotp(secret, user.Email)
	if err != nil {
		return internalError(what, err)
	}
	if !t.checkCurrent(code) {
		ok, err := rtAuthTryRecoveryCode(ctx, st, user, code)
		if err != nil {
			return err
		}
		if !ok {
			rtAuthTwofaRateLimitRecord(st, claims.Sub)
			return apiErr(http.StatusUnauthorized,
				"Invalid 2FA code. Enter a code from your authenticator app, or one of your recovery codes.")
		}
	}
	rtAuthTwofaRateLimitClear(st, claims.Sub)
	return nil
}

// rtAuthTwofaDisable — POST /api/auth/2fa/disable: requires a current TOTP
// code OR a recovery code; the latter is the only route back for a lost
// authenticator.
//
// Accepting only a live code made losing the authenticator a dead end: the
// recovery codes let you IN, and then nothing you held could turn 2FA off or
// re-enrol a new device. The codes exist to be the fallback; refusing them at
// the one door that repairs the account is a lockout wearing a safeguard's
// clothes. Same limiter as the login door — this route REMOVES the factor, so
// it is the more attractive of the two to guess at.
func rtAuthTwofaDisable(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtAuthTwoFaCodeRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	user, err := rtAuthLoadUser(ctx, st, claims.Sub, "2FA disable")
	if err != nil {
		return err
	}
	if !user.TotpEnabled {
		return apiErr(http.StatusBadRequest, "2FA is not enabled")
	}
	if err := rtAuthTwofaCodeOrRecovery(ctx, st, claims, user, body.Code, "2FA disable"); err != nil {
		return err
	}

	if _, err := execSQL(ctx, st.DB,
		"UPDATE users SET totp_enabled = FALSE, totp_secret = NULL, recovery_codes = NULL, updated_at = NOW() WHERE id = $1", claims.Sub); err != nil {
		return internalError("2FA disable", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "auth.2fa_disabled", nil, nil, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "auth.2fa_disabled", &claims.Email, ip, nil, nil, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "2FA has been disabled"})
	return nil
}

// rtAuthTwofaRegenerateRecoveryCodes — POST /api/auth/2fa/recovery-codes.
//
// Recovery codes were written once, at enrolment, and consumed one at a time:
// after ten recovery logins the fallback was silently gone. Worse, every
// account that enrolled before v2.83.0 holds ten codes it was NEVER SHOWN.
// This repairs them WITHOUT losing the enrolment, with a live TOTP code (no
// administrator needed) or a recovery code — the same authority twofa_disable
// accepts, for the gentler of the two things it permits.
func rtAuthTwofaRegenerateRecoveryCodes(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtAuthTwoFaCodeRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	user, err := rtAuthLoadUser(ctx, st, claims.Sub, "2FA recovery codes")
	if err != nil {
		return err
	}
	if !user.TotpEnabled {
		return apiErr(http.StatusBadRequest, "2FA is not enabled — recovery codes are issued when you enrol")
	}
	if err := rtAuthTwofaCodeOrRecovery(ctx, st, claims, user, body.Code, "2FA recovery codes"); err != nil {
		return err
	}

	// Replaces the whole set, so any code still outstanding — including one
	// just spent getting in here — stops working. That is the point: the old
	// set is the one the user could not read.
	codes := rtAuthGenerateRecoveryCodes()
	hashed := make([]string, len(codes))
	for i, c := range codes {
		hashed[i] = rtAuthHashToken(c)
	}
	hashedJSON, _ := json.Marshal(hashed)
	if _, err := execSQL(ctx, st.DB, "UPDATE users SET recovery_codes = $1, updated_at = NOW() WHERE id = $2",
		string(hashedJSON), claims.Sub); err != nil {
		return internalError("2FA recovery codes", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "auth.2fa_recovery_codes_regenerated", nil, nil, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "auth.2fa_recovery_codes_regenerated", &claims.Email, ip, nil, nil, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "recovery_codes": codes,
		"message": "New recovery codes issued. The previous set no longer works.",
	})
	return nil
}

// rtAuthTwofaStatus — GET /api/auth/2fa/status.
//
// recovery_codes_remaining rides along so the page can say how many are LEFT
// (they were never counted anywhere the user could see). `enforced` rides
// along because this is the only 2FA read a NON-ADMIN can make: the layout's
// "2FA is required" banner used to ask the admin-only GET /api/settings and
// swallowed the 403, so it only ever rendered for admins. Whether the panel
// should also REFUSE the login is a separate, still-untaken product decision
// (OAuth accounts with no password, the bootstrap admin, non-browser callers);
// until then enforce_2fa refuses nothing — login sets twofa_required and
// issues the cookie regardless.
func rtAuthTwofaStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	row, err := queryOne[Tup2[bool, *string]](ctx, st.DB, "SELECT totp_enabled, recovery_codes FROM users WHERE id = $1", claims.Sub)
	if err != nil {
		return internalError("2FA status", err)
	}
	// settings.value is TEXT NOT NULL: present or absent; absent = never on.
	enforced, err := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'enforce_2fa'")
	if err != nil {
		return internalError("2FA status", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":                  row.A,
		"enforced":                 enforced != nil && *enforced == "true",
		"recovery_codes_remaining": rtAuthRecoveryCodesRemaining(row.B),
	})
	return nil
}

// ─── Password Change & Session Revocation ───────────────────────────────

// rtAuthChangePassword — POST /api/auth/change-password.
func rtAuthChangePassword(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	current, ok := jsonStr(jsonGet(body, "current_password"))
	if !ok {
		return apiErr(http.StatusBadRequest, "Current password required")
	}
	newPass, ok := jsonStr(jsonGet(body, "new_password"))
	if !ok {
		return apiErr(http.StatusBadRequest, "New password required")
	}
	if len(newPass) < 8 {
		return apiErr(http.StatusBadRequest, "Password must be at least 8 characters")
	}

	hash, err := queryScalarOpt[string](ctx, st.DB, "SELECT password_hash FROM users WHERE id = $1", claims.Sub)
	if err != nil {
		return internalError("change password", err)
	}
	if hash == nil {
		return apiErr(http.StatusNotFound, "User not found")
	}
	// OAuth users have no password hash — they must use their OAuth provider
	if *hash == "" {
		return apiErr(http.StatusBadRequest, "OAuth users cannot change passwords. Use your OAuth provider instead.")
	}
	okPw, err := verifyPassword(current, *hash)
	if err != nil {
		return apiErr(http.StatusInternalServerError, "Password hash error")
	}
	if !okPw {
		return apiErr(http.StatusUnauthorized, "Current password is incorrect")
	}

	newHash, err := hashPassword(newPass)
	if err != nil {
		return internalError("change password", err)
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2", newHash, claims.Sub); err != nil {
		return internalError("change password", err)
	}

	// Invalidate all other sessions for this user (keep current session)
	if claims.Jti != nil {
		others, _ := queryAll[string](ctx, st.DB, "DELETE FROM user_sessions WHERE user_id = $1 AND jti != $2 RETURNING jti", claims.Sub, *claims.Jti)
		rtAuthBlacklistJTIs(ctx, st, others)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "auth.password_change", nil, nil, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "auth.password_change", &claims.Email, ip, nil, nil, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Password changed successfully"})
	return nil
}

// rtAuthRevokeAllSessions — POST /api/auth/revoke-all (admin only): forces
// re-login for everyone.
func rtAuthRevokeAllSessions(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	now := time.Now().UTC()
	// Store a timestamp marker — auth middleware checks this to invalidate older tokens
	_, _ = execSQL(ctx, st.DB,
		"INSERT INTO settings (key, value, updated_at) VALUES ('sessions_revoked_at', $1, NOW()) "+
			"ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()", now.Format("2006-01-02T15:04:05.999999999-07:00"))
	// Update the in-memory cache so the auth middleware enforces immediately
	st.setSessionsRevokedAt(now.Unix())

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "auth.revoke_all", nil, nil, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "auth.revoke_all", &claims.Email, ip, nil, nil, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "All sessions revoked. Users will need to re-login."})
	return nil
}

// ─── Session Management ─────────────────────────────────────────────────────

// rtAuthListSessions — GET /api/auth/sessions.
func rtAuthListSessions(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	rows, err := queryAll[Tup6[uuid.UUID, string, *string, *string, time.Time, time.Time]](r.Context(), st.DB,
		"SELECT id, jti, ip_address, user_agent, created_at, last_seen_at "+
			"FROM user_sessions WHERE user_id = $1 ORDER BY last_seen_at DESC", claims.Sub)
	if err != nil {
		return internalError("list sessions", err)
	}
	current := ""
	if claims.Jti != nil {
		current = *claims.Jti
	}
	out := make([]any, 0, len(rows))
	for _, s := range rows {
		out = append(out, map[string]any{
			"id": s.A, "ip_address": s.C, "user_agent": s.D, "created_at": s.E, "last_seen_at": s.F,
			"is_current": s.B == current,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
	return nil
}

// rtAuthRevokeSession — DELETE /api/auth/sessions/{id}.
func rtAuthRevokeSession(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// The JTI for this session (must belong to the current user)
	jti, err := queryScalarOpt[string](ctx, st.DB, "SELECT jti FROM user_sessions WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("revoke session", err)
	}
	if jti == nil {
		return apiErr(http.StatusNotFound, "Session not found")
	}
	// Blacklist so the JWT is immediately invalid (GAP 66: persisted)
	rtAuthBlacklistJTIs(ctx, st, []string{*jti})
	_, _ = execSQL(ctx, st.DB, "DELETE FROM user_sessions WHERE id = $1", id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtAuthExportMyData — GET /api/auth/export-my-data (GDPR).
func rtAuthExportMyData(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	user, err := queryOne[Tup5[string, string, *string, bool, time.Time]](ctx, st.DB,
		"SELECT email, role, oauth_provider, totp_enabled, created_at FROM users WHERE id = $1", claims.Sub)
	if err != nil {
		return internalError("export user data", err)
	}
	sites, _ := queryAll[Tup2[string, string]](ctx, st.DB, "SELECT domain, runtime FROM sites WHERE user_id = $1", claims.Sub)
	activity, _ := queryAll[Tup3[string, *string, time.Time]](ctx, st.DB,
		"SELECT action, target_name, created_at FROM activity_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100", claims.Sub)
	sessions, _ := queryAll[Tup3[*string, *string, time.Time]](ctx, st.DB,
		"SELECT ip_address, user_agent, created_at FROM user_sessions WHERE user_id = $1", claims.Sub)
	// Passkeys belong here for the same reason sessions do, and more urgently:
	// a session can be revoked, a passkey survives every reset the panel
	// offers. Exporting the revocable credential while omitting the permanent
	// one would leave this the only self-service surface that cannot show a
	// user what signs in as them.
	passkeys, _ := queryAll[Tup2[string, time.Time]](ctx, st.DB, "SELECT name, created_at FROM passkeys WHERE user_id = $1", claims.Sub)

	siteOut := make([]any, 0, len(sites))
	for _, s := range sites {
		siteOut = append(siteOut, map[string]any{"domain": s.A, "runtime": s.B})
	}
	actOut := make([]any, 0, len(activity))
	for _, a := range activity {
		actOut = append(actOut, map[string]any{"action": a.A, "target": a.B, "at": a.C})
	}
	sessOut := make([]any, 0, len(sessions))
	for _, s := range sessions {
		sessOut = append(sessOut, map[string]any{"ip": s.A, "user_agent": s.B, "at": s.C})
	}
	pkOut := make([]any, 0, len(passkeys))
	for _, p := range passkeys {
		pkOut = append(pkOut, map[string]any{"name": p.A, "at": p.B})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"email": user.A, "role": user.B, "oauth_provider": user.C, "2fa_enabled": user.D, "created_at": user.E,
		},
		"sites":           siteOut,
		"recent_activity": actOut,
		"sessions":        sessOut,
		"passkeys":        pkOut,
		"exported_at":     time.Now().UTC(),
	})
	return nil
}
