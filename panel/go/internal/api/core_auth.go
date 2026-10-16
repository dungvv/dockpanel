package api

// Port of panel/backend/src/auth.rs (the AuthUser/AdminUser/ResellerUser/
// ServerScope extractors, agent-token auth, the agent rate limiter) plus the
// password-hash primitives the Rust routes took from the argon2/bcrypt crates
// and routes/auth.rs::revoke_all_user_sessions (session infrastructure that
// suspendAccount needs).
//
// Extractors are plain functions: call them first in a handler, in the same
// order the Rust handler listed its extractors, and return their error.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// sessionInvalid: the caller has no usable session — the only refusal that
// entitles the frontend to navigate someone to /login. Every such refusal is
// minted here so "which 401s mean log in again" has one answer in one place.
// A handler's own 401 must never use this; the agent-token refusals below
// deliberately don't either (an agent is not a browser and has no session).
func sessionInvalid(msg string) error {
	return apiErrCoded(http.StatusUnauthorized, msg, CodeSessionInvalid)
}

// Claims is the JWT payload. Field order and null-serialisation match serde
// (jti/key_id are emitted as null, not omitted).
type Claims struct {
	Sub   uuid.UUID `json:"sub"`
	Email string    `json:"email"`
	Role  string    `json:"role"`
	Exp   uint64    `json:"exp"`
	Iat   uint64    `json:"iat"`
	// JWT ID for token blacklisting on logout. #[serde(default)].
	Jti *string `json:"jti"`
	// The api_keys.id this session authenticated with, so a request made
	// through a dp_ key (an MCP tool call, a CLI invocation) is attributable in
	// the audit trail. nil on the JWT path; #[serde(default)] so tokens issued
	// before the field existed still decode.
	KeyID *uuid.UUID `json:"key_id"`
}

// UnmarshalJSON enforces serde's required fields: sub/email/role/exp/iat
// must be present (a token missing one fails to decode → invalid).
func (c *Claims) UnmarshalJSON(b []byte) error {
	var aux struct {
		Sub   *uuid.UUID `json:"sub"`
		Email *string    `json:"email"`
		Role  *string    `json:"role"`
		Exp   *uint64    `json:"exp"`
		Iat   *uint64    `json:"iat"`
		Jti   *string    `json:"jti"`
		KeyID *uuid.UUID `json:"key_id"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if aux.Sub == nil || aux.Email == nil || aux.Role == nil || aux.Exp == nil || aux.Iat == nil {
		return errors.New("missing required claim")
	}
	*c = Claims{Sub: *aux.Sub, Email: *aux.Email, Role: *aux.Role, Exp: *aux.Exp, Iat: *aux.Iat, Jti: aux.Jti, KeyID: aux.KeyID}
	return nil
}

// jwt.Claims plumbing; validation itself is done in decodeJWT, by hand, so
// the boundary is jsonwebtoken's (leeway 0, valid while exp >= now).
func (c *Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(int64(c.Exp), 0)), nil
}
func (c *Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(int64(c.Iat), 0)), nil
}
func (c *Claims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c *Claims) GetIssuer() (string, error)              { return "", nil }
func (c *Claims) GetSubject() (string, error)             { return c.Sub.String(), nil }
func (c *Claims) GetAudience() (jwt.ClaimStrings, error)  { return nil, nil }

// encodeJWT signs claims with HS256 (jsonwebtoken Header::default()).
func encodeJWT(c *Claims, secret string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(secret))
}

// decodeJWT verifies an HS256 token and its expiry (validate_exp, leeway 0).
func decodeJWT(token, secret string) (*Claims, error) {
	c := &Claims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}), jwt.WithoutClaimsValidation())
	if _, err := p.ParseWithClaims(token, c, func(*jwt.Token) (any, error) { return []byte(secret), nil }); err != nil {
		return nil, err
	}
	if int64(c.Exp) < time.Now().Unix() {
		return nil, jwt.ErrTokenExpired
	}
	return c, nil
}

// bearerToken is `Authorization: Bearer <t>` (exact, case-sensitive prefix).
func bearerToken(r *http.Request) (string, bool) {
	return strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// cookieToken is the first `token=` entry of the Cookie header.
func cookieToken(r *http.Request) (string, bool) {
	for _, s := range strings.Split(r.Header.Get("Cookie"), ";") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(s), "token="); ok {
			return v, true
		}
	}
	return "", false
}

// authUser is the AuthUser extractor: Bearer header first, else the `token`
// cookie.
func (st *AppState) authUser(r *http.Request) (*Claims, error) {
	bearer, hasBearer := bearerToken(r)

	// A dp_-prefixed bearer is a long-lived API key (routes/api_keys.rs), not
	// a session JWT. Decoding it as Claims would always fail, so without this
	// branch every API-key request would 401 for the wrong reason.
	if hasBearer && strings.HasPrefix(bearer, "dp_") {
		return st.authenticateAPIKey(r.Context(), bearer)
	}

	token := bearer
	if !hasBearer {
		t, ok := cookieToken(r)
		if !ok {
			return nil, sessionInvalid("Authentication required")
		}
		token = t
		// CSRF: cookie auth on mutating methods requires X-Requested-With.
		// Bearer auth is exempt — a cross-origin form cannot send it.
		switch r.Method {
		case "POST", "PUT", "DELETE", "PATCH":
			if _, ok := r.Header["X-Requested-With"]; !ok {
				return nil, apiErr(http.StatusForbidden, "Missing CSRF header")
			}
		}
	}

	claims, err := decodeJWT(token, st.Config.JWTSecret)
	if err != nil {
		return nil, sessionInvalid("Invalid or expired token")
	}
	if claims.Jti != nil && st.isBlacklisted(*claims.Jti) {
		return nil, sessionInvalid("Token has been revoked")
	}
	// Global session revocation (revoke-all / Panic Button).
	if ts, ok := st.sessionsRevokedAt(); ok && int64(claims.Iat) < ts {
		return nil, sessionInvalid("Session revoked. Please log in again.")
	}
	// A suspended account's token must not authenticate. Pre-suspension
	// tokens are killed by the blacklist sweep on suspend; this is
	// defence-in-depth against a suspended-role token ever being minted.
	if claims.Role == "suspended" {
		return nil, apiErr(http.StatusForbidden, "Account suspended")
	}
	return claims, nil
}

// authenticateAPIKey authenticates a dp_ key and builds the same Claims a
// JWT would, so it works on every authUser-gated handler. A key has no jti
// and is never on the blacklist — it is revoked by deleting its row, or by
// having been minted before a global revocation (the created_at check).
//
// Failures deliberately do NOT use sessionInvalid: a key is not a browser
// session that can be lost, so a bad key gets a plain 401.
func (st *AppState) authenticateAPIKey(ctx context.Context, key string) (*Claims, error) {
	sum := sha256.Sum256([]byte(key))
	type keyRow struct {
		ID        uuid.UUID `db:"id"`
		UserID    uuid.UUID `db:"user_id"`
		CreatedAt time.Time `db:"created_at"`
	}
	row, err := queryOpt[keyRow](ctx, st.DB, "SELECT id, user_id, created_at FROM api_keys WHERE key_hash = $1", hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, internalError("api_key lookup", err)
	}
	if row == nil {
		return nil, apiErr(http.StatusUnauthorized, "Invalid or expired token")
	}
	// Parity with the JWT path's revocation check: "Revoke all sessions" and
	// the Panic Button promise a total logout, and a key minted before that
	// moment is exactly what an incident responder means to kill.
	if ts, ok := st.sessionsRevokedAt(); ok && row.CreatedAt.Unix() < ts {
		return nil, apiErr(http.StatusUnauthorized, "Key revoked. Mint a new one.")
	}
	type userRow struct {
		Email string `db:"email"`
		Role  string `db:"role"`
	}
	u, err := queryOpt[userRow](ctx, st.DB, "SELECT email, role FROM users WHERE id = $1", row.UserID)
	if err != nil {
		return nil, internalError("api_key user lookup", err)
	}
	if u == nil {
		return nil, apiErr(http.StatusUnauthorized, "Invalid or expired token")
	}
	if u.Role == "suspended" {
		return nil, apiErr(http.StatusForbidden, "Account suspended")
	}
	// Best-effort bookkeeping — a failed UPDATE must not fail the request
	// that is itself proof the key still works.
	_, _ = execSQL(ctx, st.DB, "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1", row.ID)

	now := uint64(time.Now().Unix())
	keyID := row.ID
	return &Claims{
		Sub: row.UserID, Email: u.Email, Role: u.Role, KeyID: &keyID,
		// A key has no session lifetime; exp must still be in the future
		// because consumers of Claims expect it. Never re-validated against a
		// signature, so not a forgeable expiry.
		Exp: now + 315_360_000, // ~10 years
		Iat: now,
	}, nil
}

// adminUser is the AdminUser extractor. The inner rejection propagates
// verbatim — flattening it hid "Missing CSRF header" (403) and "Invalid or
// expired token" behind a generic 401 on every admin endpoint.
func (st *AppState) adminUser(r *http.Request) (*Claims, error) {
	c, err := st.authUser(r)
	if err != nil {
		return nil, err
	}
	if c.Role != "admin" {
		return nil, apiErr(http.StatusForbidden, "Admin access required")
	}
	return c, nil
}

// resellerUser allows role admin OR reseller.
func (st *AppState) resellerUser(r *http.Request) (*Claims, error) {
	c, err := st.authUser(r)
	if err != nil {
		return nil, err
	}
	if c.Role != "admin" && c.Role != "reseller" {
		return nil, apiErr(http.StatusForbidden, "Admin or reseller access required")
	}
	return c, nil
}

// serverScope is the ServerScope extractor: X-Server-Id selects the target
// server (which must belong to the authenticated user); absent, the local one.
//
// Ported literally: the token is decoded as a JWT only (a dp_ key reads as
// "no user" here), with no blacklist check — exactly what the Rust did.
func (st *AppState) serverScope(r *http.Request) (uuid.UUID, AgentHandle, error) {
	var userID *uuid.UUID
	tok, ok := bearerToken(r)
	if !ok {
		tok, ok = cookieToken(r)
	}
	if ok {
		if c, err := decodeJWT(tok, st.Config.JWTSecret); err == nil {
			userID = &c.Sub
		}
	}

	// Any form Uuid::parse_str takes (hyphenated, simple, braced, urn); an
	// unparseable header reads as absent, as it did in Rust.
	if sid, err := uuid.Parse(r.Header.Get("X-Server-Id")); err == nil {
		if userID == nil {
			return uuid.Nil, nil, sessionInvalid("Authentication required when X-Server-Id is provided")
		}
		owns, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB, "SELECT id FROM servers WHERE id = $1 AND user_id = $2", sid, *userID)
		if err != nil {
			return uuid.Nil, nil, apiErr(http.StatusInternalServerError, "Server lookup failed")
		}
		if owns == nil {
			return uuid.Nil, nil, apiErr(http.StatusForbidden, "Server not found or access denied")
		}
		a, err := st.Agents.ForServer(r.Context(), sid)
		if err != nil {
			return uuid.Nil, nil, apiErr(http.StatusBadGateway, err.Error())
		}
		return sid, a, nil
	}
	local := st.Agents.LocalServerID()
	if local == nil {
		return uuid.Nil, nil, apiErr(http.StatusServiceUnavailable, "Local server not yet registered")
	}
	return *local, st.Agents.Local(), nil
}

// authenticateAgent authenticates an AGENT-originated request by its servers
// row token and returns the server id. A different credential from every
// extractor above: a random hex string issued at install time, never a user
// JWT. Hash lookup first, plaintext fallback for rows predating hashing.
//
// The single implementation, because /api/agent/version once demanded a JWT
// from a caller that structurally cannot hold one and 401'd for four releases.
func (st *AppState) authenticateAgent(r *http.Request) (uuid.UUID, error) {
	token, ok := strings.CutPrefix(r.Header.Get("authorization"), "Bearer ")
	if !ok {
		return uuid.Nil, apiErr(http.StatusUnauthorized, "Missing authorization")
	}
	id, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB, "SELECT id FROM servers WHERE agent_token_hash = $1", hashAgentToken(token))
	if err != nil {
		return uuid.Nil, internalError("unknown", err)
	}
	if id != nil {
		return *id, nil
	}
	id, err = queryScalarOpt[uuid.UUID](r.Context(), st.DB, "SELECT id FROM servers WHERE agent_token = $1 AND agent_token_hash IS NULL", token)
	if err != nil {
		return uuid.Nil, internalError("unknown", err)
	}
	if id == nil {
		return uuid.Nil, apiErr(http.StatusUnauthorized, "Invalid token")
	}
	return *id, nil
}

// agentRateLimit is the per-server limit shared by agent routes: 120/minute.
func (st *AppState) agentRateLimit(serverID uuid.UUID) error {
	st.AgentRateMu.Lock()
	defer st.AgentRateMu.Unlock()
	now := time.Now()
	e, ok := st.AgentRateLimits[serverID]
	if !ok || now.Sub(e.Start) >= 60*time.Second {
		// A fresh entry counts this request (Rust inserted (0, now) and then
		// fell into the window check, which reset it to (1, now)).
		st.AgentRateLimits[serverID] = RateWindow{Count: 1, Start: now}
		return nil
	}
	e.Count++
	st.AgentRateLimits[serverID] = e
	if e.Count > 120 {
		return apiErr(http.StatusTooManyRequests, "Rate limit exceeded")
	}
	return nil
}

// revokeAllUserSessions (routes/auth.rs) deletes a user's sessions and
// blacklists their JTIs in memory and in the DB (2h, the token lifetime).
func (st *AppState) revokeAllUserSessions(ctx context.Context, userID uuid.UUID) {
	jtis, _ := queryAll[string](ctx, st.DB, "DELETE FROM user_sessions WHERE user_id = $1 RETURNING jti", userID)
	if len(jtis) == 0 {
		return
	}
	st.blacklistAdd(jtis...)
	for _, j := range jtis {
		_, _ = execSQL(ctx, st.DB, "INSERT INTO token_blacklist (jti, expires_at) VALUES ($1, NOW() + INTERVAL '2 hours') ON CONFLICT DO NOTHING", j)
	}
}

// ── Password hashing (argon2 0.5 / bcrypt 0.15 crate compatible) ───────────

// Argon2::default(): argon2id, v=19, m=19456 KiB, t=2, p=1, 32-byte output,
// 16-byte random salt, PHC string with unpadded standard base64.
const (
	argonMemory  = 19456
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
)

var phcB64 = base64.RawStdEncoding

// hashPassword is Argon2::default().hash_password(pw, SaltString::generate).
func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		phcB64.EncodeToString(salt), phcB64.EncodeToString(key)), nil
}

// errBadPHC is PasswordHash::new failing — callers answer 500 "Password hash
// error", exactly as the Rust did.
var errBadPHC = errors.New("invalid password hash")

// verifyPassword is PasswordHash::new + Argon2::default().verify_password:
// (false, nil) for a wrong password, errBadPHC for an unparseable hash. The
// parameters are taken from the hash itself. Supports argon2id and argon2i
// (golang.org/x/crypto has no argon2d; such a hash reads as errBadPHC).
func verifyPassword(pw, phc string) (bool, error) {
	parts := strings.Split(phc, "$")
	// "", alg, [v=19], params, salt, hash
	if len(parts) < 5 || parts[0] != "" {
		return false, errBadPHC
	}
	alg, rest := parts[1], parts[2:]
	if strings.HasPrefix(rest[0], "v=") {
		if rest[0] != "v=19" {
			return false, errBadPHC
		}
		rest = rest[1:]
	}
	if len(rest) != 3 {
		return false, errBadPHC
	}
	var m, t uint64
	var p uint64
	for _, kv := range strings.Split(rest[0], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return false, errBadPHC
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return false, errBadPHC
		}
		switch k {
		case "m":
			m = n
		case "t":
			t = n
		case "p":
			p = n
		}
	}
	salt, err1 := phcB64.DecodeString(rest[1])
	want, err2 := phcB64.DecodeString(rest[2])
	if err1 != nil || err2 != nil || m == 0 || t == 0 || p == 0 || p > 255 || len(want) < 4 {
		return false, errBadPHC
	}
	var got []byte
	switch alg {
	case "argon2id":
		got = argon2.IDKey([]byte(pw), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	case "argon2i":
		got = argon2.Key([]byte(pw), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	default:
		return false, errBadPHC
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// bcryptHash is bcrypt::hash(pw, cost) from the Rust bcrypt 0.15 crate:
// $2b$ prefix, and passwords past 72 bytes truncated rather than refused
// (x/crypto refuses them; the first 72 bytes are all either one uses).
func bcryptHash(pw string, cost int) (string, error) {
	b := []byte(pw)
	if len(b) > 72 {
		b = b[:72]
	}
	h, err := bcrypt.GenerateFromPassword(b, cost)
	if err != nil {
		return "", err
	}
	return "$2b$" + strings.TrimPrefix(string(h), "$2a$"), nil
}

// bcryptVerify checks a $2a$/$2b$/$2y$ hash (legacy credentials).
func bcryptVerify(pw, hash string) bool {
	b := []byte(pw)
	if len(b) > 72 {
		b = b[:72]
	}
	if len(hash) > 4 && (strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$")) {
		hash = "$2a$" + hash[4:]
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), b) == nil
}
