package api

// Port of panel/backend/src/routes/oauth.rs — Google/GitHub/GitLab sign-in.

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

type rtOauthCallbackQuery struct {
	Code             *string `json:"code"`
	State            string  `json:"state"`
	Error            *string `json:"error"`
	ErrorDescription *string `json:"error_description"`
}

// rtOauthProvider is an OAuth provider configuration.
type rtOauthProvider struct {
	AuthURL, TokenURL, UserinfoURL, Scopes string
}

// rtOauthProviders — the providers this panel can be configured for. Named
// once so the settings UI offers exactly the set rtOauthGetProvider accepts:
// a card for a provider the backend does not know would be a control that
// cannot work.
var rtOauthProviders = []string{"google", "github", "gitlab"}

// rtOauthHTTP is reqwest::Client::new(): no overall timeout, follows
// redirects.
var rtOauthHTTP = &http.Client{}

// rtOauthRedirectURI is the redirect URI this panel sends to the provider,
// and therefore the one an operator must register at the provider's console.
// One function because there are three users: authorize sends it, callback
// re-sends it for the token exchange (the provider rejects a mismatch), and
// the settings UI displays it. A screen that guessed it from the browser's own
// origin would be confidently wrong whenever BASE_URL differs, and the
// resulting redirect_uri_mismatch names neither side.
func rtOauthRedirectURI(baseURL, provider string) string {
	return fmt.Sprintf("%s/api/auth/oauth/%s/callback", baseURL, provider)
}

// rtOauthStringifyID: Value::to_string() keeps a JSON string's quote
// characters — fine for GitHub/GitLab's numeric `id`, but it corrupted
// Google's `sub` (a JSON string) into `"1234567890"` quotes included. Strings
// are taken as their content; anything else as its JSON text.
func rtOauthStringifyID(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func rtOauthGetProvider(name string) *rtOauthProvider {
	switch name {
	case "google":
		return &rtOauthProvider{"https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token",
			"https://www.googleapis.com/oauth2/v3/userinfo", "openid email profile"}
	case "github":
		return &rtOauthProvider{"https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token",
			"https://api.github.com/user", "user:email"}
	case "gitlab":
		return &rtOauthProvider{"https://gitlab.com/oauth/authorize", "https://gitlab.com/oauth/token",
			"https://gitlab.com/api/v4/user", "read_user"}
	}
	return nil
}

func rtOauthRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("GET /api/settings/oauth-redirects", h(rtOauthRedirectURIs))
	r.Handle("GET /api/auth/oauth/{provider}", h(rtOauthAuthorize))
	r.Handle("GET /api/auth/oauth/{provider}/callback", h(rtOauthCallback))
}

// rtOauthRedirectURIs — GET /api/settings/oauth-redirects (admin only).
//
// Returns only what GET /api/settings cannot. base_url is reported so the UI
// can say *why* when it is empty: an unset BASE_URL silently makes every
// redirect URI relative, which no provider accepts, and the operator sees a
// login button that fails at the provider without ever being told the panel
// does not know its own address.
func rtOauthRedirectURIs(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	base := st.Config.BaseURL
	uris := map[string]any{}
	for _, p := range rtOauthProviders {
		uris[p] = rtOauthRedirectURI(base, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"base_url": base, "base_url_configured": base != "", "redirect_uris": uris,
	})
	return nil
}

// rtOauthAuthorize — GET /api/auth/oauth/{provider}: redirect to the provider.
func rtOauthAuthorize(st *AppState, w http.ResponseWriter, r *http.Request) error {
	name := r.PathValue("provider")
	provider := rtOauthGetProvider(name)
	if provider == nil {
		return apiErr(http.StatusBadRequest, "Unknown OAuth provider")
	}
	clientID, err := queryScalarOpt[string](r.Context(), st.DB, "SELECT value FROM settings WHERE key = $1", "oauth_"+name+"_client_id")
	if err != nil {
		return internalError("authorize", err)
	}
	if clientID == nil || *clientID == "" {
		return apiErr(http.StatusBadRequest, name+" OAuth not configured")
	}

	// Generate CSRF state token
	csrf := uuid.NewString()
	st.OAuthMu.Lock()
	st.OAuthStates[csrf] = OAuthState{Provider: name, Created: time.Now()}
	st.OAuthMu.Unlock()

	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&state=%s&response_type=code",
		provider.AuthURL, rtAuthURLEncode(*clientID), rtAuthURLEncode(rtOauthRedirectURI(st.Config.BaseURL, name)),
		rtAuthURLEncode(provider.Scopes), rtAuthURLEncode(csrf))

	// Bind `state` to THIS browser via a short-lived cookie mirroring the
	// server-side entry. Without it a valid state only proves "some /authorize
	// call happened". Login-CSRF: an attacker starts their own flow, captures
	// the provider's redirect back (a real code+state for the ATTACKER's
	// account) without following it, and hands that URL to a victim — whose
	// browser would then be logged into the attacker's account. The callback
	// requires this cookie to be present and to match query.state.
	w.Header().Set("Set-Cookie", fmt.Sprintf("oauth_csrf=%s; HttpOnly%s; SameSite=Lax; Path=/; Max-Age=600", csrf, rtAuthCookieSecureFlag(r)))
	w.Header().Set("Location", authURL)
	w.WriteHeader(http.StatusTemporaryRedirect)
	return nil
}

// rtOauthCallback — GET /api/auth/oauth/{provider}/callback.
func rtOauthCallback(st *AppState, w http.ResponseWriter, r *http.Request) error {
	name := r.PathValue("provider")
	var query rtOauthCallbackQuery
	if err := decodeQuery(r, &query); err != nil {
		return err
	}
	ctx := r.Context()

	// This door mints the same session cookie as the password and passkey
	// doors and owed the same gates (IP allowlist here, lockdown per-user
	// below). With SSO configured, both used to be skipped here.
	if err := rtAuthEnforcePanelIPAllowlist(ctx, st, r); err != nil {
		return err
	}

	// OAuth error response from provider
	if query.Error != nil {
		desc := "Unknown error"
		if query.ErrorDescription != nil {
			desc = *query.ErrorDescription
		}
		return apiErr(http.StatusBadRequest, fmt.Sprintf("OAuth error: %s — %s", *query.Error, desc))
	}
	if query.Code == nil {
		return apiErr(http.StatusBadRequest, "Missing authorization code")
	}
	code := *query.Code

	provider := rtOauthGetProvider(name)
	if provider == nil {
		return apiErr(http.StatusBadRequest, "Unknown OAuth provider")
	}

	// The state must be in the server-side map — proves SOME /authorize call
	// issued it, nothing about WHO presents it. None of these failure branches
	// calls record_suspicious_event, deliberately: it auto-activates
	// system-wide lockdown at five events in ten minutes, and this endpoint is
	// reachable with no account at all (`?state=garbage`), so it would let any
	// anonymous visitor lock every non-admin out. A 400 is the right ceiling.
	st.OAuthMu.Lock()
	entry, ok := st.OAuthStates[query.State]
	delete(st.OAuthStates, query.State)
	st.OAuthMu.Unlock()
	if !ok || entry.Provider != name || time.Since(entry.Created) >= 600*time.Second {
		return apiErr(http.StatusBadRequest, "Invalid or expired OAuth state")
	}

	// The browser presenting this callback must be the one authorize set the
	// csrf cookie for, naming the SAME state — this turns "a valid flow
	// happened" into "this browser's flow". Missing/mismatched means a
	// non-browser replay of a captured URL, or the login-CSRF handoff.
	var csrfCookie *string
	for _, s := range strings.Split(r.Header.Get("Cookie"), ";") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(s), "oauth_csrf="); ok {
			csrfCookie = &v
			break
		}
	}
	if csrfCookie == nil || *csrfCookie != query.State {
		return apiErr(http.StatusBadRequest, "Invalid or expired OAuth state")
	}

	// Read client credentials
	idKey, secretKey := "oauth_"+name+"_client_id", "oauth_"+name+"_client_secret"
	creds, err := queryAll[Tup2[string, string]](ctx, st.DB, "SELECT key, value FROM settings WHERE key IN ($1, $2)", idKey, secretKey)
	if err != nil {
		return internalError("callback", err)
	}
	credMap := map[string]string{}
	for _, c := range creds {
		credMap[c.A] = c.B
	}
	clientID, secretEnc := credMap[idKey], credMap[secretKey]
	if clientID == "" || secretEnc == "" {
		return apiErr(http.StatusBadRequest, "OAuth not fully configured")
	}
	// Decrypt the client secret (with legacy plaintext fallback)
	clientSecret := SecretsCryptoDecryptCredentialOrLegacy(secretEnc, st.Config.JWTSecret)
	redirectURI := rtOauthRedirectURI(st.Config.BaseURL, name)

	// Exchange code for token
	form := url.Values{
		"client_id": {clientID}, "client_secret": {clientSecret}, "code": {code},
		"redirect_uri": {redirectURI}, "grant_type": {"authorization_code"},
	}
	treq, _ := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenURL, strings.NewReader(form.Encode()))
	treq.Header.Set("Accept", "application/json")
	treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenData, err := rtOauthDoJSON(treq)
	if err != nil {
		return upstreamError(name+" OAuth token exchange", err)
	}
	accessToken, ok := jsonStr(jsonGet(tokenData, "access_token"))
	if !ok {
		return apiErr(http.StatusBadGateway, "No access_token in OAuth response")
	}

	// Fetch user info
	ureq, _ := http.NewRequestWithContext(ctx, http.MethodGet, provider.UserinfoURL, nil)
	ureq.Header.Set("Authorization", "Bearer "+accessToken)
	ureq.Header.Set("User-Agent", "DockPanel")
	userinfo, err := rtOauthDoJSON(ureq)
	if err != nil {
		return upstreamError(name+" OAuth userinfo fetch", err)
	}
	info, _ := userinfo.(map[string]any)

	// Extract email based on provider
	var email *string
	if s, ok := info["email"].(string); ok && (name == "google" || name == "gitlab" || name == "github") {
		email = &s
	}
	if name == "github" && (email == nil || *email == "") {
		// GitHub might not return email in profile if it's private
		email = nil
		ereq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
		ereq.Header.Set("Authorization", "Bearer "+accessToken)
		ereq.Header.Set("User-Agent", "DockPanel")
		if resp, err := rtOauthHTTP.Do(ereq); err == nil {
			var emails []any
			_ = json.NewDecoder(resp.Body).Decode(&emails)
			resp.Body.Close()
			for _, e := range emails {
				primary, _ := jsonBool(jsonGet(e, "primary"))
				verified, _ := jsonBool(jsonGet(e, "verified"))
				if primary && verified {
					if s, ok := jsonStr(jsonGet(e, "email")); ok {
						email = &s
					}
					break
				}
			}
		}
	}
	if email == nil {
		return apiErr(http.StatusBadGateway, "Could not retrieve email from OAuth provider")
	}

	// Reject an explicitly-unverified email before it can auto-link to (or
	// auto-log-into) an existing account by email match alone. Absent means
	// allow: GitLab's user endpoint and GitHub's profile path don't return the
	// field at all; Google's OIDC userinfo reliably does.
	if v, ok := info["email_verified"].(bool); ok && !v {
		return apiErr(http.StatusBadGateway, "OAuth provider reports this email address is not verified")
	}

	oauthID := ""
	if v, ok := info["id"]; ok {
		oauthID = rtOauthStringifyID(v)
	} else if v, ok := info["sub"]; ok {
		oauthID = rtOauthStringifyID(v)
	}
	if oauthID == "" {
		return apiErr(http.StatusBadGateway, "OAuth provider did not return a user ID")
	}

	// Find or create user
	user, err := queryOpt[User](ctx, st.DB, "SELECT * FROM users WHERE email = $1", *email)
	if err != nil {
		return internalError("callback", err)
	}
	ip := clientIP(r)
	const conflictMsg = "An account with this email exists, linked to a different sign-in method. " +
		"Log in with your existing method and link this one in Settings."

	if user != nil {
		// Four-way: auto-link an OAuth-only account with no provider yet;
		// allow a plain login when already linked to THIS provider account;
		// reject a provider-account swap under a matching provider NAME; reject
		// everything else (a password holder with no link, or an account linked
		// to a DIFFERENT provider). The old code only tested
		// oauth_provider.is_none() on the reject branch, so once ANY provider
		// was linked, a second provider reporting the same email logged
		// straight in.
		switch {
		case user.OAuthProvider == nil && user.PasswordHash == "":
			_, _ = execSQL(ctx, st.DB, "UPDATE users SET oauth_provider = $1, oauth_id = $2 WHERE id = $3", name, oauthID, user.ID)
			ActivityLogActivity(ctx, st.DB, user.ID, user.Email, "auth.oauth_link", new("user"), &name, nil, ip, nil)
			SecurityHardeningAuditLog(ctx, st.DB, "auth.oauth_link", &user.Email, ip, new("user"), &name, nil, nil, "info", nil)
			user.OAuthProvider = &name
		case user.OAuthProvider == nil || *user.OAuthProvider != name:
			return apiErr(http.StatusConflict, conflictMsg)
		case user.OAuthID == nil || *user.OAuthID != oauthID:
			// The provider NAME matches, but the provider's own permanent
			// account id does not. oauth_id is only ever written together
			// with oauth_provider, so a genuine returning login cannot land
			// here. The realistic way in is the email changing hands AT THE
			// PROVIDER (a departed employee's mailbox reassigned to a new
			// hire) — who would otherwise silently inherit the departed
			// employee's dockpanel account and role.
			return apiErr(http.StatusConflict, conflictMsg)
		}
	} else {
		// Auto-create user — behind TWO gates, because there are two ways to
		// open this door and until s275 they disagreed: self_registration
		// defaults CLOSED (absent = disabled) while oauth_auto_create defaulted
		// OPEN. An EXPLICIT self_registration_enabled=false now closes this
		// path too (off means off, whichever door); an install that never set
		// the row keeps today's behaviour, so no OAuth deployment breaks.
		selfReg, err := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'self_registration_enabled'")
		if err != nil {
			return internalError("self-registration setting", err)
		}
		if selfReg != nil && *selfReg == "false" {
			return apiErr(http.StatusForbidden, "Registration is disabled. Contact your administrator.")
		}
		autoCreate, err := queryScalarOpt[string](ctx, st.DB, "SELECT value FROM settings WHERE key = 'oauth_auto_create'")
		if err != nil {
			return internalError("oauth auto-create setting", err)
		}
		if autoCreate != nil && *autoCreate == "false" {
			return apiErr(http.StatusForbidden, "OAuth auto-registration is disabled. Contact your administrator.")
		}

		// A THIRD gate: register marks a new account unapproved when
		// security_approval_required is on, and this door omitted the column
		// entirely — DEFAULT TRUE admitted it on the spot, and it never
		// surfaced in Security → Approvals. Written into the INSERT so the row
		// is never briefly approved.
		approvalRequired := SecurityHardeningGetSettingBool(ctx, st.DB, "security_approval_required", false)

		nu, err := queryOne[User](ctx, st.DB,
			"INSERT INTO users (email, password_hash, role, email_verified, oauth_provider, oauth_id, approved) "+
				"VALUES ($1, '', 'user', true, $2, $3, $4) RETURNING *", *email, name, oauthID, !approvalRequired)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate key") {
				return apiErr(http.StatusConflict, "Email already registered")
			}
			return internalError("callback", err)
		}
		slog.Info(fmt.Sprintf("OAuth user created: %s via %s", *email, name))
		ActivityLogActivity(ctx, st.DB, nu.ID, nu.Email, "auth.oauth_register", new("user"), &name, nil, ip, nil)
		SecurityHardeningAuditLog(ctx, st.DB, "auth.oauth_register", &nu.Email, ip, new("user"), &name, nil, nil, "info", nil)
		user = &nu
	}

	// Suspended accounts are blocked here too (parity with password/passkey).
	if user.Role == "suspended" {
		return apiErr(http.StatusForbidden, "Account suspended")
	}

	// Approval parity: of the three ways in, approval was enforced at two.
	// COALESCE as the other two — a row predating the column reads approved.
	if approved, err := queryScalarOpt[bool](ctx, st.DB, "SELECT COALESCE(approved, TRUE) FROM users WHERE id = $1", user.ID); err == nil && approved != nil && !*approved {
		return apiErr(http.StatusForbidden, "Account pending admin approval")
	}

	// Lockdown, same rule and admin escape hatch as the other two doors;
	// checked here because the exemption is per-user.
	if user.Role != "admin" && SecurityHardeningIsLockedDown(ctx, st.DB) {
		return apiErr(http.StatusServiceUnavailable, "System is in lockdown mode")
	}

	// If 2FA is enabled, issue a temporary token and redirect to the challenge
	if user.TotpEnabled {
		temp, err := rtAuthMintTwoFaToken(st, user.ID)
		if err != nil {
			return internalError("oauth 2fa token encode", err)
		}
		ActivityLogActivity(ctx, st.DB, user.ID, user.Email, "auth.oauth_login_2fa_required", new("user"), &name, nil, nil, nil)
		w.Header().Set("Location", "/login?oauth_2fa="+temp)
		w.WriteHeader(http.StatusFound)
		return nil
	}

	// Issue JWT session (no 2FA required)
	now := uint64(time.Now().Unix())
	jti := uuid.NewString()
	token, err := encodeJWT(&Claims{Sub: user.ID, Email: user.Email, Role: user.Role, Iat: now, Exp: now + 7200, Jti: &jti}, st.Config.JWTSecret)
	if err != nil {
		return internalError("oauth session token encode", err)
	}

	// Record the session so it is visible AND — critically — revocable: the
	// DELETE user_sessions RETURNING jti → blacklist sweeps can only reach a
	// session that has a row.
	var realIP *string
	if v := r.Header.Values("X-Real-Ip"); len(v) > 0 {
		s := strings.TrimSpace(v[0])
		realIP = &s
	}
	_, _ = execSQL(ctx, st.DB, "INSERT INTO user_sessions (user_id, jti, ip_address, user_agent) VALUES ($1, $2, $3, $4)",
		user.ID, jti, realIP, rtAuthUserAgent(r))

	ActivityLogActivity(ctx, st.DB, user.ID, user.Email, "auth.oauth_login", new("user"), &name, nil, realIP, nil)
	SecurityHardeningAuditLog(ctx, st.DB, "auth.oauth_login", &user.Email, realIP, new("user"), &name, nil, nil, "info", nil)

	// Secure only when the request actually arrived over HTTPS (#47, #71 —
	// must NOT key off BASE_URL).
	w.Header().Set("Set-Cookie", fmt.Sprintf("token=%s; HttpOnly%s; SameSite=Lax; Path=/; Max-Age=7200", token, rtAuthCookieSecureFlag(r)))
	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusFound)
	return nil
}

// rtOauthDoJSON sends req and decodes the body as JSON whatever the status
// (reqwest's .json() does not look at the status either).
func rtOauthDoJSON(req *http.Request) (any, error) {
	resp, err := rtOauthHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var v any
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
