package api

// Port of panel/backend/src/routes/ssl.rs.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

func rtSslRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("POST /api/sites/{id}/ssl", h(rtSslProvision))
	r.Handle("GET /api/sites/{id}/ssl", h(rtSslStatus))
	r.Handle("POST /api/sites/{id}/ssl/dns01", h(rtSslProvisionDns01))
	r.Handle("POST /api/ssl/{id}/renew", h(rtSslRenew))
	r.Handle("DELETE /api/ssl/{id}", h(rtSslRevoke))
	r.Handle("GET /api/ssl/profiles", h(rtSslProfiles))
	r.Handle("GET /api/preflight/dns", h(rtSslPreflightDns))
	r.Handle("GET /api/sites/{id}/preflight", h(rtSslPreflightSite))
	r.Handle("POST /api/ssl/default-profile", h(rtSslSetDefaultProfile))
	r.Handle("GET /api/ssl/contact-email", h(rtSslGetContactEmail))
	r.Handle("POST /api/ssl/contact-email", h(rtSslSetContactEmail))
}

// rtSslAcmeFailureOr answers a failed certificate order with the reason, and
// everything else the way it was answered before.
//
// s386 gave the operator a sentence for a certificate this product must not
// touch. It left the commoner failure untouched: a domain that IS ours but
// cannot answer the challenge from this box — it points somewhere else, port
// 80 is closed, the apex of a wildcard lives elsewhere — where the agent runs a
// real order, loses it, and the operator gets a reference number after two
// minutes of spinner. The reference described nothing; the agent had already
// said exactly what went wrong.
//
// Both doors share this, and provisioning is the one that fires more often.
//
// A 422 rather than a 4xx passthrough because nothing about the REQUEST was
// malformed: the panel asked correctly and the world declined.
func rtSslAcmeFailureOr(domain, context string, e error) error {
	if reason, ok := acmeOrderFailure(e); ok {
		slog.Warn(context+" was declined", "domain", domain, "reason", reason)
		// ⚠ Says what happened and nothing about WHY. The compatibility path
		// for an agent nobody has updated recognises a renewal by its wrapper
		// alone, and that wrapper is put on local faults too. So this sentence
		// has to be true when the CA declined a challenge, when it refused a
		// rate-limited order, and when the agent's own disk filled up — which
		// means it may not name a cause, and must never say "try again": on a
		// rate limit that is the one instruction that makes it worse. The hint
		// below is conditional for the same reason.
		reason = strings.TrimRight(reason, ". ")
		return apiErr(http.StatusUnprocessableEntity, fmt.Sprintf(
			"A certificate for %s could not be issued: %s. If that is a "+
				"validation failure, check that %s resolves to this server and that "+
				"port 80 is reachable from the internet.", domain, reason, domain))
	}
	return agentError(context, e)
}

// rtSslDns01FailureOr answers a failed DNS-01 order with the reason, and
// everything else the way it was answered before.
//
// The THIRD ACME door, and it must not borrow the sentence the other two
// share. That one offers "check that the domain resolves here and that port 80
// is reachable" — advice this door's own button contradicts, because an
// operator chooses DNS-01 precisely WHEN port 80 cannot be reached.
//
// Three parties can fail on this door and the panel keeps them apart, most
// specific first. The DNS provider refusing to publish `_acme-challenge` is
// the commonest real failure and almost always a token missing `DNS:Edit`; the
// CA declining is the same class the sibling handles; anything unlabelled is
// this machine's fault and keeps its incident id.
//
// ⚠ Both hints are CONDITIONAL and neither says "try again". A declined order
// arrives here for a rate limit too, and on a rate limit "try again" is the
// one instruction that makes it worse (#663).
func rtSslDns01FailureOr(ordered, zone string, wildcard bool, e error) error {
	// What was actually ORDERED, which on a wildcard is not the site the
	// operator is looking at: the order is placed against the ZONE apex.
	subject := ordered
	if wildcard {
		subject = "*." + ordered
	}

	if reason, ok := dnsProviderFailure(e); ok {
		slog.Warn("DNS-01 SSL was refused by the DNS provider", "domain", ordered, "reason", reason)
		reason = strings.TrimRight(reason, ". ")
		return apiErr(http.StatusUnprocessableEntity, fmt.Sprintf(
			"The DNS-01 challenge for %s could not be completed: %s. If "+
				"Cloudflare rejected the change, check that the credentials for the %s "+
				"zone may edit its DNS records — a scoped token needs the DNS:Edit permission.", subject, reason, zone))
	}

	if reason, ok := acmeOrderFailure(e); ok {
		slog.Warn("DNS-01 SSL was declined", "domain", ordered, "reason", reason)
		reason = strings.TrimRight(reason, ". ")
		return apiErr(http.StatusUnprocessableEntity, fmt.Sprintf(
			"A certificate for %s could not be issued: %s. If that is a "+
				"validation failure, check that the _acme-challenge TXT record for %s "+
				"can be published in the %s zone.", subject, reason, subject, zone))
	}

	return agentError("DNS-01 SSL", e)
}

// rtSslPutFullVhost PUTs the site's complete vhost body.
//
// After an SSL provision/renew, re-render the FULL nginx vhost from the site's
// current DB config. The agent's SSL provision/renew only renders a SUBSET
// (WAF / CSP / Permissions-Policy / rate-limit / custom_nginx / bot-protection
// all default off), so without this a renewal silently strips a hardened
// site's security directives. rtSitesBuildNginxBody is the same canonical
// builder every other config-rebuild path uses. Best-effort: a failure leaves
// the site on the agent's (functional, SSL-enabled) subset config and is
// logged. The single writer behind all three rebuild entry points below, so a
// door can never re-render a *partial* vhost by picking the wrong helper.
func rtSslPutFullVhost(ctx context.Context, agent AgentHandle, site *Site) {
	if _, err := agent.Put(ctx, "/nginx/sites/"+site.Domain, rtSitesBuildNginxBody(site)); err != nil {
		slog.Warn(fmt.Sprintf("Full vhost rebuild after SSL op failed for %s: %v", site.Domain, err))
	}
}

// rtSslRebuildVhostForDomain re-renders a site's full vhost after an SSL write
// that only knew the certificate.
//
// ⛔ The agent's /ssl/provision* and /ssl/{domain}/renew routes do NOT patch a
// vhost: they RE-RENDER it from the SiteConfig the caller handed in, with every
// limit and hardening field None. So an SSL write from a door that does not
// hold the site's row publishes a vhost with no rate limit, no upload cap, no
// custom nginx and no WAF/CSP — and, when that door also *guesses* the
// runtime, a PHP site re-rendered as a static one (403 on every PHP request).
// Measured at s398: adding a mail domain for a name that also had a website
// converted that website to static and dropped its limit_req_zone.
//
// ⚠ Resolved by (domain, server_id), NEVER by domain alone: sites.domain is
// unique only per server, so a name-only lookup on a fleet can hand back
// another host's row.
//
// A domain with no site row is not an error: a mail domain need not be a
// site, and there is then no vhost of ours to put back.
func rtSslRebuildVhostForDomain(ctx context.Context, db Querier, agent AgentHandle, domain string, serverID uuid.UUID) {
	site, err := queryOpt[Site](ctx, db, "SELECT * FROM sites WHERE domain = $1 AND server_id = $2", domain, serverID)
	switch {
	case err != nil:
		slog.Warn(fmt.Sprintf("Vhost rebuild after SSL write: could not load a site for %s: %v", domain, err))
	case site != nil:
		rtSslPutFullVhost(ctx, agent, site)
		slog.Info(fmt.Sprintf("Rebuilt %s's vhost after an SSL write that did not carry the site's settings", domain))
	}
}

// rtSslRebuildVhostForSite is the same compensation for a caller that holds
// the site id and a pool but no AppState — the auto-SSL task spawned by site
// creation. Deliberately does NOT promote the canonical URL: that door's own
// success path already handles it.
func rtSslRebuildVhostForSite(ctx context.Context, db Querier, agent AgentHandle, siteID uuid.UUID) {
	site, err := queryOpt[Site](ctx, db, "SELECT * FROM sites WHERE id = $1", siteID)
	switch {
	case err != nil:
		slog.Warn(fmt.Sprintf("Vhost rebuild after SSL op: could not load site %s: %v", siteID, err))
	case site != nil:
		rtSslPutFullVhost(ctx, agent, site)
	}
}

// rtSslRebuildVhostAfterSsl re-renders the full vhost and, for an SSL site,
// promotes the canonical URL.
func rtSslRebuildVhostAfterSsl(ctx context.Context, st *AppState, agent AgentHandle, siteID uuid.UUID) {
	site, err := queryOne[Site](ctx, st.DB, "SELECT * FROM sites WHERE id = $1", siteID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Vhost rebuild after SSL op: could not load site %s: %v", siteID, err))
		return
	}
	rtSslPutFullVhost(ctx, agent, &site)

	// This rebuild is the SECOND way a vhost can turn into an HTTPS one. The
	// agent promotes a WordPress site's canonical URL inside its SSL enable,
	// but a WILDCARD certificate never goes through it — the agent leaves those
	// to be applied per-site from here. Without this the site would serve
	// HTTPS, redirect to it, and go on telling every visitor to use HTTP.
	// Idempotent: the agent reports `untouched` when there is nothing to move.
	if site.SSLEnabled {
		if _, err := agent.Post(ctx, fmt.Sprintf("/wordpress/%s/promote-https", site.Domain), nil); err != nil {
			slog.Warn(fmt.Sprintf("Canonical URL promotion after SSL op failed for %s: %v", site.Domain, err))
		}
	}
}

// rtSslProvisionQuery is ProvisionQuery.
type rtSslProvisionQuery struct {
	// Optional ACME profile override ("classic" / "tlsserver" / "shortlived").
	// When omitted, falls back to the acme_default_profile setting, which
	// itself defaults to "classic".
	Profile *string `json:"profile"`
	// The operator's explicit intent to replace a certificate this product did
	// not issue, after seeing the refusal that names its issuer. Mirrors the
	// CLI's --force and, like it, is the only way past the agent writer's
	// foreign-certificate refusal — never a default, never inferred.
	Force bool `json:"force" serde:"default"`
}

// rtSslCallerSite loads the site through SiteCallerPredicate (404 otherwise).
func rtSslCallerSite(r *http.Request, st *AppState, id, caller uuid.UUID, ctxName string) (*Site, error) {
	site, err := queryOpt[Site](r.Context(), st.DB, "SELECT s.* FROM sites s WHERE "+SiteCallerPredicate, id, caller)
	if err != nil {
		return nil, internalError(ctxName, err)
	}
	if site == nil {
		return nil, apiErr(http.StatusNotFound, "Site not found")
	}
	return site, nil
}

// rtSslRateCheck: per-user ACME rate limiting, max 10 certificates per hour.
func rtSslRateCheck(r *http.Request, st *AppState, userID uuid.UUID, ctxName string) error {
	n, err := queryScalar[int64](r.Context(), st.DB,
		"SELECT COUNT(*) FROM sites WHERE user_id = $1 AND ssl_enabled = true "+
			"AND updated_at > NOW() - INTERVAL '1 hour'", userID)
	if err != nil {
		return internalError(ctxName, err)
	}
	if n >= 10 {
		return apiErr(http.StatusTooManyRequests, "Rate limit: max 10 SSL certificates per hour. Try again later.")
	}
	return nil
}

// rtSslSiteAgentBody is the {email, runtime, proxy_port, php_socket, root}
// body the agent needs to render the vhost it enables SSL on.
func rtSslSiteAgentBody(email string, site *Site) map[string]any {
	b := map[string]any{"email": email, "runtime": site.Runtime}
	if site.ProxyPort != nil {
		b["proxy_port"] = *site.ProxyPort
	}
	if site.PHPVersion != nil {
		b["php_socket"] = fmt.Sprintf("unix:/run/php/php%s-fpm.sock", *site.PHPVersion)
	}
	if site.RootPath != nil {
		b["root"] = *site.RootPath
	}
	return b
}

func rtSslExpiryOf(result any) *time.Time {
	if s, ok := jsonStr(jsonGet(result, "expiry")); ok {
		return parseAgentCertExpiry(s)
	}
	return nil
}

func rtSslStrOr(v any, def string) string {
	if s, ok := jsonStr(v); ok {
		return s
	}
	return def
}

// POST /api/sites/{id}/ssl — Provision SSL certificate for a site.
func rtSslProvision(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var q rtSslProvisionQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	ctx := r.Context()

	site, err := rtSslCallerSite(r, st, id, c.Sub, "provision")
	if err != nil {
		return err
	}

	// Issuing writes a certificate and rewrites the vhost for this domain on
	// whichever host the handle points at. The predicate above already
	// answered WHICH SITE from the row; the host has to come from the same place.
	agent, err := agentForSiteServer(ctx, st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}

	if site.Status != "active" {
		return apiErr(http.StatusBadRequest, "Site must be active before provisioning SSL")
	}
	if site.SSLEnabled {
		return apiErr(http.StatusConflict, "SSL is already enabled")
	}
	if err := rtSslRateCheck(r, st, c.Sub, "provision rate check"); err != nil {
		return err
	}

	// DNS pre-flight, via the shared prerequisite checker — the SAME call the
	// create-site form and the SSL panel use to render their guidance, so what
	// we enforce here and what we advised there can never drift apart.
	//
	// Only a *blocking* verdict refuses. The s252 audit drove a
	// Cloudflare-proxied domain end to end and issuance SUCCEEDED, because
	// Cloudflare forwards the ACME challenge to the origin. Such a domain
	// resolves to Cloudflare's addresses, so the pre-v2.28.0 guard would have
	// refused a configuration that demonstrably works. It now warns and lets
	// the order proceed; only a domain that resolves to nothing at all — where
	// HTTP-01 cannot possibly complete — is still refused.
	dns := PrerequisitesCheckDnsPointsHere(ctx, site.Domain)
	if dns.Blocks() {
		return apiErr(http.StatusPreconditionFailed, dns.Detail)
	}

	// Get admin email for ACME registration. Validated first — an address in
	// a reserved TLD makes the CA refuse the account contact, and that failure
	// is invisible everywhere downstream (s252 F4).
	userEmail, err := queryScalar[string](ctx, st.DB, "SELECT email FROM users WHERE id = $1", c.Sub)
	if err != nil {
		return internalError("provision", err)
	}
	email, err := rtSslResolveAcmeContact(ctx, st.DB, userEmail)
	if err != nil {
		return apiErr(http.StatusPreconditionFailed, err.Error())
	}

	profile := rtSslResolveProfile(ctx, st.DB, q.Profile)

	// Build agent request
	agentBody := rtSslSiteAgentBody(email, site)
	if profile != nil {
		agentBody["profile"] = *profile
	}
	if q.Force {
		agentBody["force"] = true
	}

	// Call agent to provision SSL
	result, err := agent.Post(ctx, "/ssl/provision/"+site.Domain, agentBody)
	if err != nil {
		return rtSslAcmeFailureOr(site.Domain, "SSL provisioning", err)
	}

	// Parse expiry from agent response
	sslExpiry := rtSslExpiryOf(result)
	if sslExpiry == nil {
		slog.Warn(fmt.Sprintf("Could not parse SSL expiry for site %s (domain: %s). Raw value: %v", id, site.Domain, jsonGet(result, "expiry")))
	}
	certPath := rtSslStrOr(jsonGet(result, "cert_path"), "")
	keyPath := rtSslStrOr(jsonGet(result, "key_path"), "")

	// Update site in DB. The provenance columns are written HERE, at issuance,
	// beside ssl_profile, because this is the only moment anything knows which
	// challenge answered. HTTP-01 orders exactly one identifier, so the subject
	// is the site's own domain and the certificate is never a wildcard.
	if _, err := execSQL(ctx, st.DB,
		"UPDATE sites SET ssl_enabled = true, ssl_cert_path = $1, ssl_key_path = $2, "+
			"ssl_expiry = $3, ssl_profile = $4, "+
			"ssl_challenge = 'http-01', ssl_cert_subject = $6, ssl_wildcard = FALSE, "+
			"ssl_dns_zone_id = NULL, "+
			"ssl_renewal_at = NULL, ssl_renewal_checked_at = NULL, "+
			"updated_at = NOW() WHERE id = $5",
		certPath, keyPath, sslExpiry, profile, id, site.Domain); err != nil {
		return internalError("provision", err)
	}

	slog.Info("SSL provisioned for " + site.Domain)

	rtSslRebuildVhostAfterSsl(ctx, st, agent, id)

	// GAP 15: Auto-activate paused monitors now that SSL/DNS is working
	_, _ = execSQL(ctx, st.DB,
		"UPDATE monitors SET enabled = TRUE WHERE site_id = $1 AND enabled = FALSE AND status = 'pending'", id)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"domain":      site.Domain,
		"ssl_enabled": true,
		"expiry":      sslExpiry,
	})
	return nil
}

// POST /api/sites/{id}/ssl/dns01 — Provision SSL via DNS-01 challenge
// (Cloudflare). Supports wildcard certificates when wildcard=true.
func rtSslProvisionDns01(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
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

	site, err := rtSslCallerSite(r, st, id, c.Sub, "dns01 provision")
	if err != nil {
		return err
	}

	// The DNS-01 path issues for this domain and rebuilds its vhost, same as
	// the HTTP-01 one above — so it needs the same host, from the same row.
	agent, err := agentForSiteServer(ctx, st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}

	if site.Status != "active" {
		return apiErr(http.StatusBadRequest, "Site must be active")
	}
	if site.SSLEnabled {
		return apiErr(http.StatusConflict, "SSL is already enabled")
	}
	if err := rtSslRateCheck(r, st, c.Sub, "dns01 rate check"); err != nil {
		return err
	}

	wildcard, _ := jsonBool(jsonGet(body, "wildcard"))
	// The operator's explicit intent to replace a certificate this product
	// did not issue — see rtSslProvisionQuery.Force on the HTTP-01 sibling.
	force, _ := jsonBool(jsonGet(body, "force"))

	// Find the matching Cloudflare DNS zone for this domain. Uses
	// longest-suffix match to handle multi-part TLDs (e.g., example.co.uk).
	zones, err := queryAll[rtDnsDnsZone](ctx, st.DB,
		"SELECT * FROM dns_zones WHERE user_id = $1 AND provider = 'cloudflare'", c.Sub)
	if err != nil {
		return internalError("dns01 zone lookup", err)
	}
	var zone *rtDnsDnsZone
	for i := range zones {
		z := &zones[i]
		if site.Domain == z.Domain || strings.HasSuffix(site.Domain, "."+z.Domain) {
			// max_by_key keeps the LAST of equal maxima.
			if zone == nil || len(z.Domain) >= len(zone.Domain) {
				zone = z
			}
		}
	}
	if zone == nil {
		return apiErr(http.StatusPreconditionFailed, "No Cloudflare DNS zone found for this domain. Add it in DNS management first.")
	}
	if zone.CfZoneID == nil {
		return apiErr(http.StatusPreconditionFailed, "Zone has no Cloudflare zone ID")
	}
	if zone.CfAPIToken == nil {
		return apiErr(http.StatusPreconditionFailed, "Zone has no Cloudflare API token")
	}
	// Decrypt the at-rest token before handing it to the agent for the DNS-01
	// challenge — this consumer serialises the token into the agent request
	// body, not via cfHeaders.
	cfAPIToken := SecretsCryptoDecryptCredentialOrLegacy(*zone.CfAPIToken, st.Config.JWTSecret)

	// Get admin email for ACME
	userEmail, err := queryScalar[string](ctx, st.DB, "SELECT email FROM users WHERE id = $1", c.Sub)
	if err != nil {
		return internalError("dns01 email", err)
	}
	email, err := rtSslResolveAcmeContact(ctx, st.DB, userEmail)
	if err != nil {
		return apiErr(http.StatusPreconditionFailed, err.Error())
	}

	// For wildcard, provision against the zone domain; for a single domain,
	// against the site domain.
	provisionDomain := site.Domain
	if wildcard {
		provisionDomain = zone.Domain
	}

	var profileOverride *string
	if s, ok := jsonStr(jsonGet(body, "profile")); ok {
		profileOverride = &s
	}
	profile := rtSslResolveProfile(ctx, st.DB, profileOverride)

	agentBody := map[string]any{
		"email":        email,
		"cf_zone_id":   *zone.CfZoneID,
		"cf_api_token": cfAPIToken,
		"cf_api_email": zone.CfAPIEmail,
		"wildcard":     wildcard,
	}
	if profile != nil {
		agentBody["profile"] = *profile
	}
	if force {
		agentBody["force"] = true
	}

	// ⛔ THE SAME BUDGET AS EVERY OTHER DNS-01 DOOR. This is the door that
	// ISSUES a wildcard — the exact order rtSslDns01OrderTimeoutSecs derives
	// its 300s from — and it was the one caller still passing a bare literal
	// 180, so issuing a wildcard could report a false failure while the agent
	// went on to succeed. A budget below the agent's own wait is not a
	// timeout, it is a guaranteed false failure.
	result, err := agent.PostLong(ctx, "/ssl/provision-dns01/"+provisionDomain, agentBody, rtSslDns01OrderTimeoutSecs)
	if err != nil {
		return rtSslDns01FailureOr(provisionDomain, zone.Domain, wildcard, err)
	}

	// Parse response
	sslExpiry := rtSslExpiryOf(result)
	certPath := rtSslStrOr(jsonGet(result, "cert_path"), "")
	keyPath := rtSslStrOr(jsonGet(result, "key_path"), "")

	// Update site in DB. provisionDomain — NOT site.Domain — is what was
	// ordered: for a wildcard it is the Cloudflare ZONE, and the certificate
	// covers {zone} and *.{zone}. Recording the zone ROW as well as its name
	// means the renewal reaches for the credential that issued this
	// certificate instead of re-deriving a zone from a text subject, which is
	// how a stale string could otherwise select a different tenant's token.
	if _, err := execSQL(ctx, st.DB,
		"UPDATE sites SET ssl_enabled = true, ssl_cert_path = $1, ssl_key_path = $2, "+
			"ssl_expiry = $3, ssl_profile = $4, "+
			"ssl_challenge = 'dns-01', ssl_cert_subject = $6, ssl_wildcard = $7, "+
			"ssl_dns_zone_id = $8, "+
			"ssl_renewal_at = NULL, ssl_renewal_checked_at = NULL, "+
			"updated_at = NOW() WHERE id = $5",
		certPath, keyPath, sslExpiry, profile, id, provisionDomain, wildcard, zone.ID); err != nil {
		return internalError("dns01 update", err)
	}

	rtSslRebuildVhostAfterSsl(ctx, st, agent, id)

	label, action := "SSL (DNS-01)", "site.ssl.dns01"
	if wildcard {
		label, action = "Wildcard SSL (DNS-01)", "site.ssl.wildcard"
	}
	slog.Info(fmt.Sprintf("%s provisioned for %s", label, site.Domain))
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, action, new("site"), &site.Domain, nil, nil, c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"domain":      site.Domain,
		"wildcard":    wildcard,
		"ssl_enabled": true,
		"expiry":      sslExpiry,
	})
	return nil
}

type rtSslPreflightQuery struct {
	Domain string `json:"domain"`
}

// GET /api/preflight/dns?domain=… — Evaluate the DNS prerequisite for a domain.
//
// The create-site form calls this before the user commits, and the SSL panel
// calls it to explain a gated button. Same checker the provision guard uses,
// so the advice and the enforcement cannot disagree.
func rtSslPreflightDns(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.authUser(r); err != nil {
		return err
	}
	var q rtSslPreflightQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, PrerequisitesCheckDnsPointsHere(r.Context(), q.Domain))
	return nil
}

// rtSslResultJSON is (`.ok()`, `.err()`) of a Result<String, String>.
func rtSslResultJSON(v string, err error) (any, any) {
	if err != nil {
		return nil, err.Error()
	}
	return v, nil
}

// GET /api/sites/{id}/preflight — Evaluate an existing site's prerequisites.
func rtSslPreflightSite(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	domain, err := queryScalarOpt[string](ctx, st.DB, "SELECT s.domain FROM sites s WHERE "+SiteCallerPredicate, id, c.Sub)
	if err != nil {
		return internalError("site preflight", err)
	}
	if domain == nil {
		return apiErr(http.StatusNotFound, "Site not found")
	}

	dns := PrerequisitesCheckDnsPointsHere(ctx, *domain)
	// The ACME contact is a prerequisite for issuance too, and it is the one
	// the user cannot discover by looking at their DNS.
	_, cerr := rtSslResolveAcmeContact(ctx, st.DB, c.Email)
	_, problem := rtSslResultJSON("", cerr)

	writeJSON(w, http.StatusOK, map[string]any{
		"domain":               *domain,
		"dns":                  dns,
		"acme_contact_ok":      cerr == nil,
		"acme_contact_problem": problem,
	})
	return nil
}

// GET /api/sites/{id}/ssl — Get SSL status for a site.
func rtSslStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	site, err := rtSslCallerSite(r, st, id, c.Sub, "status")
	if err != nil {
		return err
	}

	// A read, so a wrong host is not destructive — but it is still dishonest:
	// asking this box about a certificate that lives on another one returns
	// "no certificate" for a site that has a perfectly good one.
	agent, err := agentForSiteServer(ctx, st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}

	// Also fetch live status from agent
	var agentStatus any
	if v, err := agent.Get(ctx, "/ssl/status/"+site.Domain); err == nil {
		agentStatus = v
	}

	// ⚠ agentStatus asks the agent about {SSL_DIR}/{site.domain}/, so for a
	// site served by a zone WILDCARD it reports has_cert: false — the
	// certificate is real and is installed under the zone's name. The
	// provenance below is what tells those two cases apart.
	//
	// WHO ISSUED IT, decided ONCE, here — not re-derived by every display. The
	// site detail page used to assert "Enabled (Let's Encrypt)" over every
	// enabled certificate, including one uploaded from a commercial CA that the
	// panel had just DECLINED to renew. ⛔ Derived from the agentStatus ALREADY
	// IN HAND (no extra round trip), and computed HERE rather than shipped as a
	// raw issuer string for the client to match on — a second copy of that test
	// in TypeScript is a severed pair from the day it lands.
	//
	// `unknown` is a first-class answer and MUST NOT be rendered as a CA name:
	// an unreachable agent and a wildcard child both arrive here, and both held
	// a real certificate.
	prov := CertProvenance{Kind: CertUnknown}
	if agentStatus != nil {
		prov = certProvenance(agentStatus)
	}
	var provenance string
	var issuer any
	switch prov.Kind {
	case CertForeign:
		provenance, issuer = "foreign", prov.Issuer
	case CertDockPanelIssued:
		provenance = "dockpanel"
	default:
		provenance = "unknown"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ssl_enabled":  site.SSLEnabled,
		"cert_path":    site.SSLCertPath,
		"key_path":     site.SSLKeyPath,
		"expiry":       site.SSLExpiry,
		"challenge":    site.SSLChallenge,
		"cert_subject": site.SSLCertSubject,
		"wildcard":     site.SSLWildcard,
		"agent_status": agentStatus,
		"provenance":   provenance,
		"issuer":       issuer,
	})
	return nil
}

// rtSslDns01OrderTimeoutSecs is how long a DNS-01 order may take, at every
// layer, in seconds.
//
// Derived from the agent's own arithmetic rather than guessed: the agent
// sleeps 10s per authorization for DNS propagation — TWO of them for a
// wildcard, which orders {subject} and *.{subject} — then polls readiness on a
// 120s retry policy and polls for the certificate on another 120s. That is
// ~260s of budgeted waiting before any slack.
//
// ⛔ Every caller must use THIS constant. The three renewal doors disagreed
// (60s, 60s and 120s), so a DNS-01 renewal timed out at every door while the
// agent went on to succeed, and the panel recorded a failure, skipped the
// expiry write and wrote a cooldown row. A budget below the agent's own wait
// is not a timeout, it is a guaranteed false failure.
const rtSslDns01OrderTimeoutSecs = 300

// rtSslRenewOverDns01 renews a certificate over DNS-01, against the name it
// was actually issued for.
//
// ⚠ This reuses the agent's EXISTING /ssl/provision-dns01/{domain} route
// rather than a renewal route of its own. That route has been a renewal since
// v2.6.7: it orders {domain} (+ *.{domain} when wildcard) and writes over the
// existing directory, which is exactly a re-issue in place. It also skips the
// vhost enable for a wildcard, leaving that to the panel. Reusing it is why
// this fix reaches every installed agent as it stands: "an agent is only
// updated when somebody updates it, so a fix that lives only in the agent does
// not arrive."
//
// ⚠ The zone is taken by ID, decided by the caller from what was RECORDED at
// issuance. It is never re-derived from a text subject here, because an
// unattended loop has no actor to scope a zone lookup to, and resolving one by
// bare domain would hand one account's Cloudflare token to a renewal running
// for another account's site.
func rtSslRenewOverDns01(ctx context.Context, db Querier, jwtSecret string, agent AgentHandle, subject string,
	wildcard bool, zoneID, ownerID uuid.UUID, profile *string) (any, error) {
	zone, err := queryOpt[rtDnsDnsZone](ctx, db, "SELECT * FROM dns_zones WHERE id = $1", zoneID)
	if err != nil {
		return nil, fmt.Errorf("DNS zone lookup failed: %v", err)
	}
	if zone == nil {
		return nil, fmt.Errorf("the Cloudflare zone this certificate was issued against no longer exists")
	}
	if zone.CfZoneID == nil {
		return nil, fmt.Errorf("the %s zone has no Cloudflare zone ID", zone.Domain)
	}
	if zone.CfAPIToken == nil {
		return nil, fmt.Errorf("the %s zone has no Cloudflare API token", zone.Domain)
	}
	cfAPIToken := SecretsCryptoDecryptCredentialOrLegacy(*zone.CfAPIToken, jwtSecret)

	// The ACME contact belongs to the site's OWNER, not to whoever triggered
	// this — the unattended doors have no one to attribute it to, and the
	// interactive one is reachable by an administrator acting on another
	// account's site.
	ownerEmail, err := queryScalarOpt[string](ctx, db, "SELECT email FROM users WHERE id = $1", ownerID)
	if err != nil {
		return nil, fmt.Errorf("owner lookup failed: %v", err)
	}
	if ownerEmail == nil {
		return nil, fmt.Errorf("the site's owner account has no email address on file")
	}
	email, err := rtSslResolveAcmeContact(ctx, db, *ownerEmail)
	if err != nil {
		return nil, err
	}

	agentBody := map[string]any{
		"email":        email,
		"cf_zone_id":   *zone.CfZoneID,
		"cf_api_token": cfAPIToken,
		"cf_api_email": zone.CfAPIEmail,
		"wildcard":     wildcard,
	}
	if profile != nil {
		agentBody["profile"] = *profile
	}

	result, err := agent.PostLong(ctx, "/ssl/provision-dns01/"+subject, agentBody, rtSslDns01OrderTimeoutSecs)
	if err != nil {
		// s388's three-party classification, reused: name Cloudflare or the CA
		// when either of them is what refused, and stay this machine's fault
		// otherwise. ⛔ Deliberately NOT rtSslAcmeFailureOr, whose sentence
		// tells the operator to check port 80 — on the door reached precisely
		// because port 80 cannot work.
		if m, ok := dnsProviderFailure(err); ok {
			return nil, fmt.Errorf("%s", m)
		}
		if m, ok := acmeOrderFailure(err); ok {
			return nil, fmt.Errorf("%s", m)
		}
		return nil, fmt.Errorf("the DNS-01 order for %s did not complete: %v", subject, err)
	}
	return result, nil
}

// rtSslRecordRenewalProvenance writes down what a SUCCESSFUL renewal actually
// installed.
//
// Two of the four plans change what is true about the row and must say so:
//   - HTTP01{RecordChallenge} — nothing was recorded, this pass was the one
//     degraded attempt, and it succeeded. Recording it here is what makes the
//     rule terminate instead of degrading for ever.
//   - LastResortHTTP01 — a DNS-01 certificate we could not re-order over
//     DNS-01, downgraded on purpose inside its last week. The installed
//     certificate really is single-name HTTP-01 now, so the row has to agree.
//
// ⚠ Called only after success. A FAILED HTTP-01 attempt on an unrecorded row
// must leave it unrecorded — the likeliest reason it failed is that the site
// cannot answer HTTP-01, which is exactly the case that made DNS-01 the right
// door.
func rtSslRecordRenewalProvenance(ctx context.Context, db Querier, siteID uuid.UUID, domain string, plan RenewalPlan) {
	// ⛔ TWO DIFFERENT QUESTIONS. "Does this renewal change what is RECORDED
	// about provenance?" is true for only two plans. "Did this renewal install
	// a certificate at the site's OWN directory?" is true for ALL THREE HTTP-01
	// plans — including the ordinary recorded one, by far the commonest. Gating
	// the path on the provenance question left rows already stamped http-01
	// with a stale path permanently uncorrectable. Dns01 still returns: a
	// wildcard's path names the ZONE, which is correct.
	var recordProvenance bool
	var losing *string
	switch plan.Kind {
	case RenewHTTP01:
		recordProvenance = plan.RecordChallenge
	case RenewLastResortHTTP01:
		recordProvenance, losing = true, &plan.Losing
	default:
		return
	}

	// ⭐ THE PATH FOLLOWS THE CERTIFICATE. No renewal door writes
	// ssl_cert_path, yet every door re-renders the vhost from that column
	// moments later. Both plans reaching this point ordered HTTP-01 for
	// domain, so the agent wrote /etc/dockpanel/ssl/{domain}/. For a row whose
	// stored path names a DIFFERENT directory (a wildcard child naming the
	// zone) the panel otherwise renewed the certificate and then pointed nginx
	// back at the un-renewed wildcard — the site went dark at the wildcard's
	// real expiry behind a panel reporting a successful renewal (s392 Shape B).
	// Writing it HERE fixes all four doors at once: every one of them calls
	// this before its rebuild.
	_, _ = execSQL(ctx, db,
		"UPDATE sites SET ssl_cert_path = $2, ssl_key_path = $3, "+
			"updated_at = NOW() WHERE id = $1",
		siteID, fmt.Sprintf("/etc/dockpanel/ssl/%s/fullchain.pem", domain), fmt.Sprintf("/etc/dockpanel/ssl/%s/privkey.pem", domain))

	// The provenance half, only for the two plans that change what is TRUE
	// about it. An ordinary recorded HTTP-01 renewal already says http-01.
	if recordProvenance {
		_, _ = execSQL(ctx, db,
			"UPDATE sites SET ssl_challenge = 'http-01', ssl_cert_subject = $2, "+
				"ssl_wildcard = FALSE, ssl_dns_zone_id = NULL, updated_at = NOW() WHERE id = $1",
			siteID, domain)
	}

	if losing != nil {
		// Say exactly what was lost. The defect was never the downgrade itself —
		// it was that the downgrade happened in silence and the panel then
		// reported a successful renewal.
		// ⚠ "warning", not "warn": the readers (Warnings tile, level filter,
		// badge) all spell it long, and a short spelling is a row nothing can
		// count, filter or colour.
		SystemLogLogEvent(ctx, db, "warning", "ssl",
			domain+": DNS-01 certificate downgraded to a single name",
			new(fmt.Sprintf("The certificate covered %s and could not be re-ordered over DNS-01 "+
				"before it expired, so a single-name HTTP-01 certificate for %s was "+
				"issued instead. Any other name that certificate covered is no longer "+
				"covered. Restore it from the site's SSL tab once a Cloudflare zone with an "+
				"API token is available.", *losing, domain)))
	}
}

// POST /api/ssl/{id}/renew — Force-renew SSL certificate (admin only).
func rtSslRenew(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	// ⚠ This read used to be `WHERE id = $1` with no caller and no server
	// term. AdminUser is not a superuser here — an administrator's reach stops
	// at the local box and the machines they registered themselves — so the
	// shared predicate makes the row decide, and that is what then makes it
	// safe to take the host from the row as well.
	site, err := rtSslCallerSite(r, st, id, c.Sub, "ssl renew")
	if err != nil {
		return err
	}
	out, err := rtSslRenewForSite(r.Context(), st, site, c.Sub, c.Email)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// rtSslRenewForSite renews the certificate for a site the caller has ALREADY
// been authorised to reach, and returns the {ok, domain} body.
//
// Split out of renew so the Diagnostics "Fix" button can reach a renewal that
// actually happens. It takes a Site the caller resolved through
// SiteCallerPredicate, so the authorisation decision stays with the row and
// stays in ONE place: reuse carries the mechanism, never the gate.
func rtSslRenewForSite(ctx context.Context, st *AppState, site *Site, actorID uuid.UUID, actorEmail string) (map[string]any, error) {
	id := site.ID

	if !site.SSLEnabled {
		return nil, apiErr(http.StatusBadRequest, "SSL is not enabled for this site")
	}

	// Renewing writes a certificate and rebuilds the vhost, both named by
	// domain on whichever host this handle points at. The row names that host.
	agent, err := agentForSiteServer(ctx, st, site.ServerID, site.Domain)
	if err != nil {
		return nil, err
	}

	// WHICH CHALLENGE ISSUED THIS CERTIFICATE decides which door renews it,
	// and that decision has to come BEFORE the foreign-certificate check below.
	var daysRemaining *int64
	if site.SSLExpiry != nil {
		d := int64(time.Until(*site.SSLExpiry) / (24 * time.Hour))
		daysRemaining = &d
	}
	plan := renewalPlan(ctx, st.DB, site, daysRemaining)

	// ⛔ RENEWING IS REPLACING. The agent writes the same fullchain/privkey an
	// uploaded certificate occupies, so "renew" aimed at a certificate this
	// product did not issue DESTROYS it and puts a 90-day Let's Encrypt
	// certificate in its place. A positive foreign issuer is a refusal WITH A
	// SENTENCE, asked once here, where every deliberate renewal passes.
	//
	// ⛔ THE NAME CHECKED MUST BE THE NAME THE ORDER IS ABOUT TO OVERWRITE. A
	// DNS-01 renewal orders against subject — the zone apex for a wildcard —
	// and site.Domain typically has no certificate directory of its own then.
	// Skipped for Refuse, which never reaches an agent order.
	subjectDomain := site.Domain
	if plan.Kind == RenewDNS01 {
		subjectDomain = plan.Subject
	}
	if plan.Kind != RenewRefuse {
		if issuer := foreignCertIssuer(ctx, agent, subjectDomain); issuer != nil {
			return nil, apiErr(http.StatusUnprocessableEntity, fmt.Sprintf(
				"The certificate on %s was not issued by DockPanel (issuer: %s). DockPanel "+
					"renews only the Let's Encrypt certificates it issued itself, and renewing "+
					"this one would replace it. Install a replacement under the site's SSL tab "+
					"instead, or renew it wherever it was issued.", subjectDomain, *issuer))
		}
	}

	// Agent renew needs the same context as provision so it can rebuild the
	// nginx config after issuing the new cert.
	ownerEmail, err := queryScalar[string](ctx, st.DB, "SELECT email FROM users WHERE id = $1", site.UserID)
	if err != nil {
		return nil, internalError("ssl renew email", err)
	}
	email, err := rtSslResolveAcmeContact(ctx, st.DB, ownerEmail)
	if err != nil {
		return nil, apiErr(http.StatusPreconditionFailed, err.Error())
	}

	agentBody := rtSslSiteAgentBody(email, site)
	if site.SSLProfile != nil {
		agentBody["profile"] = *site.SSLProfile
	}

	var result any
	switch plan.Kind {
	case RenewRefuse:
		// A precondition that is not an agent failure — the sibling refusals in
		// provision_dns01 are PRECONDITION_FAILED with a plain sentence.
		return nil, apiErr(http.StatusPreconditionFailed, plan.Reason)
	case RenewDNS01:
		result, err = rtSslRenewOverDns01(ctx, st.DB, st.Config.JWTSecret, agent, plan.Subject, plan.Wildcard, plan.ZoneID, site.UserID, site.SSLProfile)
		if err != nil {
			return nil, apiErr(http.StatusUnprocessableEntity, err.Error())
		}
	default: // RenewHTTP01, RenewLastResortHTTP01
		result, err = agent.PostLong(ctx, fmt.Sprintf("/ssl/%s/renew", site.Domain), agentBody, rtSslDns01OrderTimeoutSecs)
		if err != nil {
			return nil, rtSslAcmeFailureOr(site.Domain, "SSL renewal", err)
		}
	}

	// Update expiry from the renew response and clear stale ARI hints so the
	// next auto-heal cycle refetches them. ⚠ The provenance columns move WITH
	// the certificate (rtSslRecordRenewalProvenance) — an unrecorded row
	// records itself here, which is what makes the whole rule converge.
	if expiry := rtSslExpiryOf(result); expiry != nil {
		_, _ = execSQL(ctx, st.DB,
			"UPDATE sites SET ssl_expiry = $1, ssl_renewal_at = NULL, "+
				"ssl_renewal_checked_at = NULL, updated_at = NOW() WHERE id = $2", *expiry, id)
	}
	rtSslRecordRenewalProvenance(ctx, st.DB, id, site.Domain, plan)

	rtSslRebuildVhostAfterSsl(ctx, st, agent, id)

	slog.Info(fmt.Sprintf("SSL renewed for %s by %s", site.Domain, actorEmail))
	ActivityLogActivity(ctx, st.DB, actorID, actorEmail, "ssl.renew", new("site"), &site.Domain, nil, nil, nil)

	return map[string]any{"ok": true, "domain": site.Domain}, nil
}

// DELETE /api/ssl/{id} — Revoke and delete SSL certificate (admin only).
func rtSslRevoke(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// Same scoped read as renew, and this is the worse half: it deletes the
	// certificate files through the agent and then blanks every ssl_* column,
	// so an id outside the caller's boundary was a cross-boundary write.
	site, err := rtSslCallerSite(r, st, id, c.Sub, "ssl revoke")
	if err != nil {
		return err
	}
	if !site.SSLEnabled {
		return apiErr(http.StatusBadRequest, "SSL is not enabled for this site")
	}

	// The deletion names the site by domain and lands on whichever host this
	// handle points at, so it has to be the host the row names.
	agent, err := agentForSiteServer(ctx, st, site.ServerID, site.Domain)
	if err != nil {
		return err
	}
	if _, err := agent.Delete(ctx, "/ssl/"+site.Domain); err != nil {
		return agentError("SSL deletion", err)
	}

	// Clear SSL fields in DB
	if _, err := execSQL(ctx, st.DB,
		"UPDATE sites SET ssl_enabled = false, ssl_cert_path = NULL, ssl_key_path = NULL, "+
			"ssl_expiry = NULL, ssl_profile = NULL, "+
			"ssl_challenge = NULL, ssl_cert_subject = NULL, ssl_wildcard = NULL, "+
			"ssl_dns_zone_id = NULL, ssl_renewal_at = NULL, "+
			"ssl_renewal_checked_at = NULL, updated_at = NOW() WHERE id = $1", id); err != nil {
		return internalError("ssl revoke", err)
	}

	// ⛔ AFTER the clear, never before. The agent's teardown removes the cert
	// directory while the enabled vhost still names it — and `nginx -t` is
	// WHOLE-SERVER, so from that moment every site edit on the box fails and
	// the next restart leaves nginx down for every tenant. Placement is
	// load-bearing: the body builder emits the certificate keys only under
	// ssl_enabled, which the statement above has just made false, and this
	// helper re-reads the row — so it now writes a plain HTTP vhost.
	rtSslRebuildVhostAfterSsl(ctx, st, agent, id)

	slog.Info(fmt.Sprintf("SSL revoked for %s by %s", site.Domain, c.Email))
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "ssl.revoke", new("site"), &site.Domain, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "ssl.revoke", &c.Email, ip, new("site"), &site.Domain, nil, nil, "warning", c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": site.Domain})
	return nil
}

// ── ACME profile + default-profile admin surface ─────────────────────────

// rtSslURLEncode is urlencoding::encode: everything but [A-Za-z0-9-_.~] is
// percent-encoded, space as %20.
func rtSslURLEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func rtSslSetting(ctx context.Context, db Querier, key, errCtx string) (*string, error) {
	v, err := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = '"+key+"'")
	if err != nil {
		return nil, internalError(errCtx, err)
	}
	return v, nil
}

// GET /api/ssl/profiles — List ACME profiles advertised by the CA.
//
// Requires an admin (the ACME account is a panel-wide resource). Returns the
// server directory's profile list plus the currently configured default. When
// the CA doesn't support the profiles extension, `profiles` is empty; callers
// should hide the dropdown.
func rtSslProfiles(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	// Use the admin's own email for ACME directory lookup. Safe because we
	// only read the server directory; no order is created.
	list, err := agent.Get(ctx, "/ssl/profiles?email="+rtSslURLEncode(c.Email))
	if err != nil {
		return agentError("ACME profiles", err)
	}
	def, err := rtSslSetting(ctx, st.DB, "acme_default_profile", "read default profile")
	if err != nil {
		return err
	}
	contact, err := rtSslSetting(ctx, st.DB, "acme_contact_email", "read acme contact")
	if err != nil {
		return err
	}

	// Tell the operator, up front, which address will actually reach the CA
	// and whether their own is usable — the whole point of F4 is that this was
	// invisible until every certificate had already failed.
	eff, problem := rtSslResultJSON(rtSslResolveAcmeContact(ctx, st.DB, c.Email))

	writeJSON(w, http.StatusOK, map[string]any{
		"profiles":           list,
		"default":            def,
		"contact_email":      contact,
		"login_email":        c.Email,
		"login_email_usable": rtSslValidateAcmeContact(c.Email) == nil,
		"effective_contact":  eff,
		"contact_problem":    problem,
	})
	return nil
}

// GET /api/ssl/contact-email — Report the ACME contact situation.
//
// Deliberately does NOT touch the agent, unlike profiles. The whole point of
// this surface is to be readable when issuance is broken, and a bad contact is
// one of the reasons the agent's ACME directory call fails — putting it behind
// that call would hide it exactly when it is needed.
func rtSslGetContactEmail(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	contact, err := rtSslSetting(ctx, st.DB, "acme_contact_email", "read acme contact")
	if err != nil {
		return err
	}
	eff, problem := rtSslResultJSON(rtSslResolveAcmeContact(ctx, st.DB, c.Email))
	writeJSON(w, http.StatusOK, map[string]any{
		"contact_email":      contact,
		"login_email":        c.Email,
		"login_email_usable": rtSslValidateAcmeContact(c.Email) == nil,
		"effective_contact":  eff,
		"contact_problem":    problem,
	})
	return nil
}

type rtSslContactEmailReq struct {
	Email *string `json:"email"`
}

// rtSslDebugOpt is Rust's `{:?}` of an Option<String>: None / Some("…").
func rtSslDebugOpt(v *string) string {
	if v == nil {
		return "None"
	}
	var b strings.Builder
	b.WriteString(`Some("`)
	for _, c := range *v {
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case 0:
			b.WriteString(`\0`)
		default:
			if unicode.IsControl(c) {
				b.WriteString(`\u{` + strconv.FormatInt(int64(c), 16) + `}`)
			} else {
				b.WriteRune(c)
			}
		}
	}
	b.WriteString(`")`)
	return b.String()
}

// POST /api/ssl/contact-email — Set the panel-wide fallback ACME contact.
//
// Used when the operator's own login address cannot be a Let's Encrypt
// contact (a reserved TLD, a typo). Pass {"email": null} to clear it.
func rtSslSetContactEmail(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var body rtSslContactEmailReq
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	if body.Email != nil && strings.TrimSpace(*body.Email) != "" {
		e := strings.TrimSpace(*body.Email)
		// Validate before storing: a rescue address that is itself invalid
		// would just move the silent failure one level down.
		if err := rtSslValidateAcmeContact(e); err != nil {
			return apiErr(http.StatusBadRequest, err.Error())
		}
		if _, err := execSQL(ctx, st.DB,
			"INSERT INTO settings (key, value) VALUES ('acme_contact_email', $1) "+
				"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()", e); err != nil {
			return internalError("set acme contact", err)
		}
	} else if _, err := execSQL(ctx, st.DB, "DELETE FROM settings WHERE key = 'acme_contact_email'"); err != nil {
		return internalError("clear acme contact", err)
	}

	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "ssl.contact_email", nil, nil, new("email="+rtSslDebugOpt(body.Email)), nil, c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "contact_email": body.Email})
	return nil
}

type rtSslDefaultProfileReq struct {
	Profile *string `json:"profile"`
}

// POST /api/ssl/default-profile — Set the panel-wide default ACME profile.
// Pass {"profile": null} or omit to reset to CA default.
func rtSslSetDefaultProfile(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var body rtSslDefaultProfileReq
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	if body.Profile != nil && *body.Profile != "" {
		if _, err := execSQL(ctx, st.DB,
			"INSERT INTO settings (key, value) VALUES ('acme_default_profile', $1) "+
				"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()", *body.Profile); err != nil {
			return internalError("set default profile", err)
		}
	} else if _, err := execSQL(ctx, st.DB, "DELETE FROM settings WHERE key = 'acme_default_profile'"); err != nil {
		return internalError("clear default profile", err)
	}

	ActivityLogActivity(ctx, st.DB, c.Sub, c.Email, "ssl.default_profile", nil, nil, new("profile="+rtSslDebugOpt(body.Profile)), nil, c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "default": body.Profile})
	return nil
}

// rtSslNonPublicTLDs are the top-level labels reserved by RFC 2606 / RFC 6761
// / RFC 8375, plus the conventional private-network ones. None of these appear
// on the Public Suffix List, so Let's Encrypt refuses an account contact in
// any of them.
var rtSslNonPublicTLDs = []string{
	"test", "local", "localhost", "internal", "invalid", "example",
	"localdomain", "lan", "home", "corp", "intranet", "private", "arpa", "onion",
}

// rtSslValidateAcmeContact checks that an address is usable as an ACME account
// contact.
//
// This is deliberately not a general-purpose email validator — it only
// rejects what Let's Encrypt itself rejects, so we never refuse an address the
// CA would have accepted.
func rtSslValidateAcmeContact(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("no contact address is set")
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("\"%s\" is not a valid email address", email)
	}
	domain := parts[1]
	noPublic := fmt.Errorf("\"%s\" has no valid public domain — Let's Encrypt will reject it as a contact address", email)
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return noPublic
	}
	tld := rtTlsCertificatesASCIILower(domain[strings.LastIndex(domain, ".")+1:])
	if len(tld) < 2 {
		return noPublic
	}
	for i := 0; i < len(tld); i++ {
		if !(tld[i] >= 'a' && tld[i] <= 'z') {
			return noPublic
		}
	}
	if slices.Contains(rtSslNonPublicTLDs, tld) {
		return fmt.Errorf("\"%s\" uses the reserved .%s domain, which Let's Encrypt rejects as a contact address", email, tld)
	}
	return nil
}

// rtSslResolveAcmeContact resolves the Let's Encrypt account contact for an
// issuance.
//
// The panel used to hand claims.email straight to the agent, unvalidated. An
// operator who registered the panel with e.g. admin@dockpanel.test therefore
// had EVERY certificate fail at the CA with a contact-validation error that
// surfaced neither in the UI nor in journalctl (s252 F4).
//
// Order: the user's own address when it is usable, otherwise the panel-wide
// acme_contact_email setting as a rescue. Keeping the user's address first
// means installs that already work are completely unaffected.
func rtSslResolveAcmeContact(ctx context.Context, db Querier, userEmail string) (string, error) {
	userErr := rtSslValidateAcmeContact(userEmail)
	if userErr == nil {
		return strings.TrimSpace(userEmail), nil
	}
	fallback, err := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = 'acme_contact_email'")
	if err == nil && fallback != nil && strings.TrimSpace(*fallback) != "" && rtSslValidateAcmeContact(*fallback) == nil {
		return strings.TrimSpace(*fallback), nil
	}
	return "", fmt.Errorf("Cannot request a certificate: %v. "+
		"Set a valid contact address under Settings → SSL (ACME contact email), "+
		"or sign in with an account whose email uses a real domain.", userErr)
}

// rtSslResolveProfile resolves the profile to use for an operation: explicit
// override > stored default > nil (CA picks its default).
func rtSslResolveProfile(ctx context.Context, db Querier, override *string) *string {
	if override != nil && *override != "" {
		return override
	}
	v, err := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = 'acme_default_profile'")
	if err != nil || v == nil || *v == "" {
		return nil
	}
	return v
}
