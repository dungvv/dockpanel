package routes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// sslCaOrInternal splits an issuance failure into "the CA said so", "the DNS
// provider said so", "a refusal" and "this machine broke", labelling only the
// first three. The panel hides every 5xx behind an incident id (right for an
// unwritable directory) — the label is how it tells a declined challenge
// apart without widening that rule. Unmarked = internal, the safe default.
func sslCaOrInternal(err error) (int, map[string]any) {
	e := err.Error()
	if reason, ok := strings.CutPrefix(e, services.SslCaDeclined); ok {
		return http.StatusInternalServerError, map[string]any{"error": reason, "code": "acme_order_failed"}
	}
	if reason, ok := strings.CutPrefix(e, services.SslDNSProviderDeclined); ok {
		return http.StatusInternalServerError, map[string]any{"error": reason, "code": "dns_provider_failed"}
	}
	// A REFUSAL IS NOT A FAULT: a 4xx carries the sentence to the operator.
	if reason, ok := strings.CutPrefix(e, services.SslForeignCertRefused); ok {
		return http.StatusUnprocessableEntity, map[string]any{"error": reason, "code": "foreign_certificate"}
	}
	return http.StatusInternalServerError, map[string]any{"error": e}
}

type sslProvisionRequest struct {
	Email     string  `json:"email"`
	Runtime   string  `json:"runtime"`
	Root      *string `json:"root"`
	ProxyPort *uint16 `json:"proxy_port"`
	PhpSocket *string `json:"php_socket"`
	// "classic" / "tlsserver" / "shortlived"; nil lets the CA pick.
	Profile *string `json:"profile"`
	// On renewal: the PEM being replaced (RFC 9773 `replaces` hint).
	ReplacesPem *string `json:"replaces_pem"`
	// ⛔ Defaults to FALSE, so an older panel fails closed at the writer.
	Force bool `json:"force"`
}

// sslProvision: POST /ssl/provision/{domain}.
func sslProvision(st *State, w http.ResponseWriter, r *http.Request) {
	var b sslProvisionRequest
	if !nginxDecodeStrict(w, r, &b, "email", "runtime") {
		return
	}
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	account, err := services.SslLoadOrCreateAccount(b.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	opts := &services.SslProvisionOpts{Profile: b.Profile, ReplacesPem: b.ReplacesPem, ReplaceForeign: b.Force}
	info, err := services.SslProvisionCert(r.Context(), account, domain, opts)
	if err != nil {
		status, body := sslCaOrInternal(err)
		writeJSON(w, status, body)
		return
	}
	cfg := &services.NginxSiteConfig{Runtime: b.Runtime, Root: b.Root, ProxyPort: b.ProxyPort, PhpSocket: b.PhpSocket}
	canonical, err := services.SslEnableSslForSite(st.Templates, domain, cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "domain": domain, "cert_path": info.CertPath, "key_path": info.KeyPath,
		"expiry": info.Expiry, "profile": info.Profile,
		// So the panel can say out loud that HTTPS is served but HTTP advertised.
		"canonical_url": canonical,
	})
}

// sslListCertificates: GET /ssl/certificates — expiry metadata only, no key
// material or paths.
func sslListCertificates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, services.SslListCertStatus())
}

// sslStatus: GET /ssl/status/{domain}.
func sslStatus(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	writeJSON(w, http.StatusOK, services.SslGetCertStatus(domain))
}

type sslCustomCertRequest struct {
	Domain      string `json:"domain"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

// sslSiteConfigFromVhost mirrors the Rust heuristic: proxy if the vhost has a
// proxy_pass, its port being the last :-separated
// piece of the first proxy_pass line, as a port.
func sslSiteConfigFromVhost(content string) *services.NginxSiteConfig {
	root := "/var/www"
	cfg := &services.NginxSiteConfig{Runtime: "php", Root: &root}
	if !strings.Contains(content, "proxy_pass") {
		return cfg
	}
	cfg.Runtime = "proxy"
	for _, l := range nginxLines(content) {
		if !strings.Contains(l, "proxy_pass") {
			continue
		}
		parts := strings.Split(l, ":")
		if p, err := strconv.ParseUint(strings.TrimSpace(strings.TrimRight(parts[len(parts)-1], ";")), 10, 16); err == nil {
			port := uint16(p)
			cfg.ProxyPort = &port
		}
		break
	}
	return cfg
}

// sslUpload: POST /ssl/upload — install a custom certificate.
func sslUpload(st *State, w http.ResponseWriter, r *http.Request) {
	var b sslCustomCertRequest
	if !nginxDecodeStrict(w, r, &b, "domain", "certificate", "private_key") {
		return
	}
	if !isValidDomain(b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	if b.Domain == "" || b.Certificate == "" || b.PrivateKey == "" {
		writeErr(w, http.StatusBadRequest, "Domain, certificate, and private key required")
		return
	}
	if !strings.Contains(b.PrivateKey, "BEGIN") {
		writeErr(w, http.StatusBadRequest, "Invalid PEM format")
		return
	}
	// Ask what the certificate NAMES before anything is written: a cert for
	// another site passes `nginx -t` and only the browser complains. A 400,
	// so the sentence reaches the operator (a 5xx becomes an incident id).
	covered, err := services.SslCertCoversDomain(b.Certificate, b.Domain)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sslDir := "/etc/dockpanel/ssl/" + b.Domain
	if err := os.MkdirAll(sslDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to create SSL dir: "+nginxErrText(err))
		return
	}
	certPath, keyPath := sslDir+"/fullchain.pem", sslDir+"/privkey.pem"
	if err := os.WriteFile(certPath, []byte(b.Certificate), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to write cert: "+nginxErrText(err))
		return
	}
	// 0600 at creation — no window where the key is group/world-readable.
	if err := services.SslWriteKeyFile(keyPath, b.PrivateKey); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	content, _ := os.ReadFile(fmt.Sprintf("%s/%s.conf", services.NginxSitesDir(), b.Domain))
	canonical, err := services.SslEnableSslForSite(st.Templates, b.Domain, sslSiteConfigFromVhost(string(content)))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Failed to enable SSL: %v", err))
		return
	}
	// Return the expiry now: a second round trip that failed used to leave
	// the panel's column NULL — invisible to countdown, alerts and healer.
	status := services.SslGetCertStatus(b.Domain)
	slog.Info(fmt.Sprintf("Custom SSL certificate uploaded for %s (certificate names: %s)", b.Domain, strings.Join(covered, ", ")))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "cert_path": certPath, "key_path": keyPath,
		"expiry": status.NotAfter, "issuer": status.Issuer, "canonical_url": canonical,
	})
}

type sslRenewRequest struct {
	Email string `json:"email"`
	// Absent when the caller cannot describe the vhost (a Compose stack or
	// Docker app): then nginx is only reloaded — see sslRenew.
	Runtime   *string `json:"runtime"`
	Root      *string `json:"root"`
	ProxyPort *uint16 `json:"proxy_port"`
	PhpSocket *string `json:"php_socket"`
	Profile   *string `json:"profile"`
}

// sslRenew: POST /ssl/{domain}/renew — re-issue with the existing cert as the
// ARI `replaces` hint (certbot never knew these certs).
func sslRenew(st *State, w http.ResponseWriter, r *http.Request) {
	var b sslRenewRequest
	if !nginxDecodeStrict(w, r, &b, "email") {
		return
	}
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	slog.Info("Renewing SSL certificate for " + domain)
	account, err := services.SslLoadOrCreateAccount(b.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Missing/unreadable is fine: the renewal is then a fresh issuance.
	var replaces *string
	if pemBytes, err := os.ReadFile(fmt.Sprintf("/etc/dockpanel/ssl/%s/fullchain.pem", domain)); err == nil {
		s := string(pemBytes)
		replaces = &s
	}
	// ⛔ replace_foreign is NEVER set on a renewal: there is no renewal that
	// needs to replace a stranger's certificate.
	opts := &services.SslProvisionOpts{Profile: b.Profile, ReplacesPem: replaces}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	info, err := services.SslProvisionCert(ctx, account, domain, opts)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeErr(w, http.StatusGatewayTimeout, "Certificate renewal timed out after 120s")
			return
		}
		slog.Error(fmt.Sprintf("renew failed for %s: %v", domain, err))
		status, body := sslCaOrInternal(err)
		// Every agent ever shipped wraps this route's error; newer panels
		// recognise renewals by it.
		if msg, ok := body["error"].(string); ok {
			body["error"] = "Renewal failed: " + msg
		}
		writeJSON(w, status, body)
		return
	}

	// `runtime` means "I can describe this vhost": rebuild it. Without it
	// (a stack or Docker app, whose proxy port is derived elsewhere), an
	// invented SiteConfig would take a working proxy off the air — so only
	// reload. A failed reload is NOT a failed renewal: the cert is written,
	// and an error would make the panel re-order weekly, burning rate limit.
	var canonical *services.WordpressCanonicalUrlOutcome
	if b.Runtime != nil {
		cfg := &services.NginxSiteConfig{Runtime: *b.Runtime, Root: b.Root, ProxyPort: b.ProxyPort, PhpSocket: b.PhpSocket}
		if outcome, err := services.SslEnableSslForSite(st.Templates, domain, cfg); err != nil {
			slog.Warn(fmt.Sprintf("Nginx reload after renewal failed for %s: %v", domain, err))
		} else {
			canonical = &outcome
		}
	} else if err := services.NginxReload(); err != nil {
		slog.Warn(fmt.Sprintf("Nginx reload after in-place renewal failed for %s: %v", domain, err))
	}
	slog.Info("SSL certificate renewed for " + domain)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "domain": domain, "expiry": info.Expiry, "profile": info.Profile, "canonical_url": canonical,
	})
}

// sslQueryEmail is the required `email` query field (axum: 400 when missing).
func sslQueryEmail(w http.ResponseWriter, r *http.Request) (string, bool) {
	e := nginxQueryStr(r, "email")
	if e == nil {
		http.Error(w, "Failed to deserialize query string: missing field `email`", http.StatusBadRequest)
		return "", false
	}
	return *e, true
}

// sslProfiles: GET /ssl/profiles?email= — ACME profiles the CA advertises.
func sslProfiles(w http.ResponseWriter, r *http.Request) {
	email, ok := sslQueryEmail(w, r)
	if !ok {
		return
	}
	account, err := services.SslLoadOrCreateAccount(email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, services.SslListProfiles(account))
}

// sslRenewalInfo: GET /ssl/{domain}/renewal-info?email= — always JSON;
// `suggestion: null` = no ARI at the CA or no cert on disk.
func sslRenewalInfo(w http.ResponseWriter, r *http.Request) {
	email, ok := sslQueryEmail(w, r)
	if !ok {
		return
	}
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	account, err := services.SslLoadOrCreateAccount(email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	suggestion := services.SslFetchAri(account, fmt.Sprintf("/etc/dockpanel/ssl/%s/fullchain.pem", domain))
	writeJSON(w, http.StatusOK, map[string]any{"suggestion": suggestion})
}

// sslRevoke: DELETE /ssl/{domain} — filesystem teardown only (short-lived
// certs make revocation moot). A shared wildcard directory is left alone.
func sslRevoke(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	slog.Info("Deleting SSL certificate for " + domain)
	dir := "/etc/dockpanel/ssl/" + domain
	if nginxExists(dir) {
		if services.OwnershipCertDirInUseElsewhere(domain) {
			slog.Warn(fmt.Sprintf("Leaving %s in place — another vhost still points at it "+
				"(a shared wildcard). Removing it would make `nginx -t` fail for "+
				"that site and leave nginx down at the next restart.", dir))
		} else if err := os.RemoveAll(dir); err != nil {
			writeErr(w, http.StatusInternalServerError, "Failed to remove cert dir: "+nginxErrText(err))
			return
		}
	}
	// `certbot delete` used to run here. No tree issues via certbot anymore,
	// so any lineage is the OPERATOR's (and carries all its SANs + renewal
	// config) — say so and leave it alone.
	if renewal := fmt.Sprintf("/etc/letsencrypt/renewal/%s.conf", domain); nginxExists(renewal) {
		slog.Warn(fmt.Sprintf("A certbot lineage named %s exists at %s and was NOT "+
			"touched — the panel did not issue it. Remove it with `certbot delete "+
			"--cert-name %s` if it really is stale.", domain, renewal, domain))
	}
	slog.Info("SSL certificate deleted for " + domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": domain})
}

type sslDns01ProvisionRequest struct {
	Email       string  `json:"email"`
	CfZoneID    string  `json:"cf_zone_id"`
	CfAPIToken  string  `json:"cf_api_token"`
	CfAPIEmail  *string `json:"cf_api_email"`
	Wildcard    bool    `json:"wildcard"`
	Profile     *string `json:"profile"`
	ReplacesPem *string `json:"replaces_pem"`
	// ⛔ Defaults to FALSE (fail closed).
	Force bool `json:"force"`
}

// sslProvisionDNS01: POST /ssl/provision-dns01/{domain} — DNS-01 via
// Cloudflare. The door an operator reaches BECAUSE HTTP-01 cannot work, so
// declined orders and token-scope refusals carry their sentences.
func sslProvisionDNS01(st *State, w http.ResponseWriter, r *http.Request) {
	var b sslDns01ProvisionRequest
	if !nginxDecodeStrict(w, r, &b, "email", "cf_zone_id", "cf_api_token", "wildcard") {
		return
	}
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	account, err := services.SslLoadOrCreateAccount(b.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	opts := &services.SslProvisionOpts{Profile: b.Profile, ReplacesPem: b.ReplacesPem, ReplaceForeign: b.Force}
	info, err := services.SslProvisionCertDNS01(r.Context(), account, domain, b.CfZoneID, b.CfAPIToken, b.CfAPIEmail, b.Wildcard, opts)
	if err != nil {
		status, body := sslCaOrInternal(err)
		writeJSON(w, status, body)
		return
	}
	// Wildcards are applied per-site by the backend.
	var canonical *services.WordpressCanonicalUrlOutcome
	if !b.Wildcard {
		siteConf := fmt.Sprintf("%s/%s.conf", services.NginxSitesDir(), domain)
		if nginxExists(siteConf) {
			content, _ := os.ReadFile(siteConf)
			outcome, err := services.SslEnableSslForSite(st.Templates, domain, sslSiteConfigFromVhost(string(content)))
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			canonical = &outcome
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "domain": domain, "wildcard": b.Wildcard, "cert_path": info.CertPath, "key_path": info.KeyPath,
		"expiry": info.Expiry, "profile": info.Profile, "canonical_url": canonical,
	})
}

// registerSsl mounts src/routes/ssl.rs. axum lets a static segment win over
// a parameter (`/ssl/status/{domain}` vs `/ssl/{domain}/renewal-info`,
// `/ssl/provision/{domain}` vs `/ssl/{domain}/renew`); Go's mux refuses such
// overlapping patterns, so the two-segment routes dispatch here in the same
// precedence.
func registerSsl(r *Router) {
	st := r.State
	r.Handle("GET /ssl/certificates", sslListCertificates)
	r.Handle("GET /ssl/profiles", sslProfiles)
	r.Handle("POST /ssl/upload", func(w http.ResponseWriter, req *http.Request) { sslUpload(st, w, req) })
	r.Handle("DELETE /ssl/{domain}", sslRevoke)
	r.Handle("GET /ssl/{a}/{b}", func(w http.ResponseWriter, req *http.Request) {
		a, b := req.PathValue("a"), req.PathValue("b")
		switch {
		case a == "status":
			req.SetPathValue("domain", b)
			sslStatus(w, req)
		case b == "renewal-info":
			req.SetPathValue("domain", a)
			sslRenewalInfo(w, req)
		default:
			http.NotFound(w, req)
		}
	})
	r.Handle("POST /ssl/{a}/{b}", func(w http.ResponseWriter, req *http.Request) {
		a, b := req.PathValue("a"), req.PathValue("b")
		switch {
		case a == "provision":
			req.SetPathValue("domain", b)
			sslProvision(st, w, req)
		case a == "provision-dns01":
			req.SetPathValue("domain", b)
			sslProvisionDNS01(st, w, req)
		case b == "renew":
			req.SetPathValue("domain", a)
			sslRenew(st, w, req)
		default:
			http.NotFound(w, req)
		}
	})
}
