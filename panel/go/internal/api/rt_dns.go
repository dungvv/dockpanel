package api

// Port of panel/backend/src/routes/dns.rs.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const rtDnsCFAPI = "https://api.cloudflare.com/client/v4"

// rtDnsDnsZone is the dns_zones row; the credentials are never serialized.
type rtDnsDnsZone struct {
	ID         uuid.UUID `db:"id" json:"id"`
	UserID     uuid.UUID `db:"user_id" json:"user_id"`
	Domain     string    `db:"domain" json:"domain"`
	Provider   string    `db:"provider" json:"provider"`
	CfZoneID   *string   `db:"cf_zone_id" json:"cf_zone_id"`
	CfAPIToken *string   `db:"cf_api_token" json:"-"`
	CfAPIEmail *string   `db:"cf_api_email" json:"-"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
}

type rtDnsCreateZoneRequest struct {
	Domain     string  `json:"domain"`
	Provider   *string `json:"provider"` // "cloudflare" (default) or "powerdns"
	CfZoneID   *string `json:"cf_zone_id"`
	CfAPIToken *string `json:"cf_api_token"`
	CfAPIEmail *string `json:"cf_api_email"`
}

// rtDnsRecordRequest is both CreateRecordRequest and UpdateRecordRequest
// (identical shapes in the Rust source).
type rtDnsRecordRequest struct {
	Rtype    string  `json:"type"`
	Name     string  `json:"name"`
	Content  string  `json:"content"`
	TTL      *uint32 `json:"ttl"`
	Proxied  *bool   `json:"proxied"`
	Priority *uint16 `json:"priority"`
}

func rtDnsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/dns/zones", h(rtDnsListZones))
	r.Handle("POST /api/dns/zones", h(rtDnsCreateZone))
	r.Handle("DELETE /api/dns/zones/{id}", h(rtDnsDeleteZone))
	r.Handle("GET /api/dns/zones/{id}/records", h(rtDnsListRecords))
	r.Handle("POST /api/dns/zones/{id}/records", h(rtDnsCreateRecord))
	r.Handle("PUT /api/dns/zones/{id}/records/{record_id}", h(rtDnsUpdateRecord))
	r.Handle("DELETE /api/dns/zones/{id}/records/{record_id}", h(rtDnsDeleteRecord))
	r.Handle("POST /api/dns/propagation", h(rtDnsCheckPropagation))
	r.Handle("POST /api/dns/health-check", h(rtDnsDnsHealthCheck))
	r.Handle("GET /api/dns/zones/{id}/dnssec", h(rtDnsDnssecStatus))
	r.Handle("GET /api/dns/zones/{id}/changelog", h(rtDnsDnsChangelog))
	r.Handle("GET /api/dns/zones/{id}/analytics", h(rtDnsDnsAnalytics))
	r.Handle("GET /api/dns/zones/{id}/cf/settings", h(rtDnsCfZoneSettings))
	r.Handle("PUT /api/dns/zones/{id}/cf/settings", h(rtDnsCfUpdateSetting))
	r.Handle("POST /api/dns/zones/{id}/cf/cache/purge", h(rtDnsCfPurgeCache))
}

// rtDnsGetZone loads a zone by id. DNS management is admin-only (every
// handler calls requireAdmin), so any admin may manage any zone — we no
// longer scope by user_id (that scoping made the admin-gated read endpoints
// unusable on a zone created by a different admin).
func rtDnsGetZone(st *AppState, r *http.Request, zoneID uuid.UUID) (rtDnsDnsZone, error) {
	z, err := queryOpt[rtDnsDnsZone](r.Context(), st.DB, "SELECT * FROM dns_zones WHERE id = $1", zoneID)
	if err != nil {
		return rtDnsDnsZone{}, internalError("unknown", err)
	}
	if z == nil {
		return rtDnsDnsZone{}, apiErr(http.StatusNotFound, "DNS zone not found")
	}
	return *z, nil
}

// rtDnsAdminZone is the common prologue: AuthUser, Path(id), require_admin,
// get_zone.
func rtDnsAdminZone(st *AppState, r *http.Request) (*Claims, rtDnsDnsZone, error) {
	c, err := st.authUser(r)
	if err != nil {
		return nil, rtDnsDnsZone{}, err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return nil, rtDnsDnsZone{}, err
	}
	if err := requireAdmin(c.Role); err != nil {
		return nil, rtDnsDnsZone{}, err
	}
	z, err := rtDnsGetZone(st, r, id)
	return c, z, err
}

// ── HTTP helpers ────────────────────────────────────────────────────────

// rtDnsResp is a sent reqwest response: status plus the body (or the error
// reading it, which .json()/.text() would have surfaced).
type rtDnsResp struct {
	Status  int
	Raw     []byte
	ReadErr error
}

func (x rtDnsResp) ok() bool { return x.Status >= 200 && x.Status < 300 }

// json is reqwest's .json(): read + strict decode.
func (x rtDnsResp) json() (any, error) {
	if x.ReadErr != nil {
		return nil, fmt.Errorf("error decoding response body: %v", x.ReadErr)
	}
	v, err := agentDecodeJSON(x.Raw)
	if err != nil {
		return nil, fmt.Errorf("error decoding response body: %s", err.(*AgentError).Msg)
	}
	return v, nil
}

// jsonOrNull is `.json().await.unwrap_or_default()`.
func (x rtDnsResp) jsonOrNull() any {
	v, _ := x.json()
	return v
}

// rtDnsSend is a reqwest::Client::new() request (no timeout of its own). The
// error is a send failure only.
func rtDnsSend(r *http.Request, method, u string, h http.Header, body any) (rtDnsResp, error) {
	resp, raw, err := rtCdnSend(r.Context(), method, u, h, body, 0)
	if resp == nil {
		return rtDnsResp{}, err
	}
	return rtDnsResp{Status: resp.StatusCode, Raw: raw, ReadErr: err}, nil
}

// rtDnsValueString is serde_json::Value's Display (compact JSON).
func rtDnsValueString(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSuffix(buf.String(), "\n")
}

// ── Cloudflare helpers ──────────────────────────────────────────────────

func rtDnsCfClient(token string, email *string) (http.Header, error) {
	h := cfHeaders(token, email)
	if len(h) == 0 {
		return nil, apiErr(http.StatusBadRequest, "Invalid Cloudflare credentials")
	}
	h.Set("Content-Type", "application/json")
	return h, nil
}

func rtDnsCfZoneClient(z rtDnsDnsZone) (http.Header, error) {
	return rtDnsCfClient(rtDnsDeref(z.CfAPIToken), z.CfAPIEmail)
}

func rtDnsDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// rtDnsCfSuccess is `v.get("success").and_then(as_bool).unwrap_or(false)`.
func rtDnsCfSuccess(v any) bool {
	b, _ := jsonBool(jsonGet(v, "success"))
	return b
}

// rtDnsGetOr is `v.get(k).cloned().unwrap_or(def)` (a present null stays null).
func rtDnsGetOr(v any, k string, def any) any { return rtCdnPointerOr(v, def, k) }

// ── PowerDNS helpers ────────────────────────────────────────────────────

// rtDnsPdnsSettings gets PowerDNS settings from DB.
func rtDnsPdnsSettings(st *AppState, r *http.Request) (string, string, error) {
	rows, err := queryAll[Tup2[string, string]](r.Context(), st.DB,
		"SELECT key, value FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key')")
	if err != nil {
		return "", "", internalError("unknown", err)
	}
	var u, keyEnc string
	for _, row := range rows {
		switch row.A {
		case "pdns_api_url":
			u = row.B
		case "pdns_api_key":
			keyEnc = row.B
		}
	}
	if u == "" || keyEnc == "" {
		return "", "", apiErr(http.StatusBadRequest, "PowerDNS not configured. Set API URL and API Key in Settings.")
	}
	// Decrypt the API key (with legacy plaintext fallback)
	return u, SecretsCryptoDecryptCredentialOrLegacy(keyEnc, st.Config.JWTSecret), nil
}

// rtDnsPdnsClient builds the headers for the PowerDNS API.
func rtDnsPdnsClient(apiKey string) (http.Header, error) {
	if !headerValueOK(apiKey) {
		return nil, apiErr(http.StatusBadRequest, "Invalid PowerDNS API key")
	}
	h := http.Header{}
	h.Set("X-API-Key", apiKey)
	h.Set("Content-Type", "application/json")
	return h, nil
}

// rtDnsFqdn ensures domain ends with a dot (FQDN) for PowerDNS.
func rtDnsFqdn(domain string) string {
	if strings.HasSuffix(domain, ".") {
		return domain
	}
	return domain + "."
}

// rtDnsStripDot strips the trailing dot(s) from an FQDN for display.
func rtDnsStripDot(name string) string { return strings.TrimRight(name, ".") }

// rtDnsIsSafeDigArg: a DNS name/domain is safe to pass as a POSITIONAL `dig`
// argument only if dig cannot parse it as an option: non-empty, no leading
// '-'/'+', and a conservative charset. allowUnderscore covers query names
// like `_dmarc` / `_acme-challenge`.
func rtDnsIsSafeDigArg(s string, allowUnderscore bool) bool {
	if s == "" || s[0] == '-' || s[0] == '+' {
		return false
	}
	for _, c := range s {
		if !(isASCIIAlnum(c) || c == '.' || c == '-' || (allowUnderscore && c == '_')) {
			return false
		}
	}
	return true
}

// rtDnsPdnsRecordID creates a synthetic record ID for PowerDNS records
// (name|type|content). URL-safe: hex-encode the composite key.
func rtDnsPdnsRecordID(name, rtype, content string) string {
	return hex.EncodeToString([]byte(name + "\x00" + rtype + "\x00" + content))
}

// rtDnsPdnsParseRecordID parses a synthetic PowerDNS record ID back to
// (name, type, content).
func rtDnsPdnsParseRecordID(id string) (string, string, string, error) {
	bad := apiErr(http.StatusBadRequest, "Invalid record ID")
	b, err := hex.DecodeString(id)
	if err != nil || !utf8.Valid(b) {
		return "", "", "", bad
	}
	parts := strings.SplitN(string(b), "\x00", 3)
	if len(parts) != 3 {
		return "", "", "", bad
	}
	return parts[0], parts[1], parts[2], nil
}

// rtDnsStrOr is `.and_then(as_str).unwrap_or(def)`.
func rtDnsStrOr(v any, def string) string {
	if s, ok := jsonStr(v); ok {
		return s
	}
	return def
}

// rtDnsPdnsFlattenRecords flattens PowerDNS rrsets into individual records
// matching the Cloudflare format.
func rtDnsPdnsFlattenRecords(rrsets []any) []any {
	records := []any{}
	for _, rrset := range rrsets {
		name := rtDnsStrOr(jsonGet(rrset, "name"), "")
		rtype := rtDnsStrOr(jsonGet(rrset, "type"), "")
		ttl, ok := jsonU64(jsonGet(rrset, "ttl"))
		if !ok {
			ttl = 3600
		}
		// Skip SOA and internal records
		if rtype == "SOA" {
			continue
		}
		recs, _ := jsonArr(jsonGet(rrset, "records"))
		for _, rec := range recs {
			content := rtDnsStrOr(jsonGet(rec, "content"), "")
			if disabled, _ := jsonBool(jsonGet(rec, "disabled")); disabled {
				continue
			}
			// Extract priority from MX/SRV content (PowerDNS includes it in content)
			var priority any
			clean := content
			if rtype == "MX" {
				if p, rest, found := strings.Cut(content, " "); found {
					if n, err := strconv.ParseUint(p, 10, 16); err == nil {
						priority = n
					}
					clean = rest
				}
			}
			records = append(records, map[string]any{
				"id":       rtDnsPdnsRecordID(name, rtype, content),
				"type":     rtype,
				"name":     rtDnsStripDot(name),
				"content":  rtDnsStripDot(clean),
				"ttl":      ttl,
				"priority": priority,
			})
		}
	}
	return records
}

// rtDnsPdnsZoneURL is `{pdns_url}/api/v1/servers/localhost/zones/{zone_fqdn}`.
func rtDnsPdnsZoneURL(pdnsURL, zoneFqdn string) string {
	return fmt.Sprintf("%s/api/v1/servers/localhost/zones/%s", pdnsURL, zoneFqdn)
}

// rtDnsRecName builds the record name as FQDN.
func rtDnsRecName(name, domain, zoneFqdn string) string {
	switch {
	case name == "@" || name == domain:
		return zoneFqdn
	case strings.HasSuffix(name, domain):
		return rtDnsFqdn(name)
	default:
		return rtDnsFqdn(name + "." + domain)
	}
}

// rtDnsRecContent: PowerDNS includes priority in content for MX.
func rtDnsRecContent(b rtDnsRecordRequest) string {
	switch b.Rtype {
	case "MX":
		p := uint16(10)
		if b.Priority != nil {
			p = *b.Priority
		}
		return fmt.Sprintf("%d %s", p, rtDnsFqdn(b.Content))
	case "CNAME", "NS":
		return rtDnsFqdn(b.Content)
	}
	return b.Content
}

// rtDnsCfRecordBody is the Cloudflare create/update record body.
func rtDnsCfRecordBody(b rtDnsRecordRequest) map[string]any {
	ttl := uint32(1)
	if b.TTL != nil {
		ttl = *b.TTL
	}
	m := map[string]any{"type": b.Rtype, "name": b.Name, "content": b.Content, "ttl": ttl}
	if slices.Contains([]string{"A", "AAAA", "CNAME"}, b.Rtype) {
		m["proxied"] = b.Proxied != nil && *b.Proxied
	}
	if b.Rtype == "MX" {
		p := uint16(10)
		if b.Priority != nil {
			p = *b.Priority
		}
		m["priority"] = p
	}
	return m
}

// rtDnsFindRRSet returns the records of the first rrset matching name+type
// (found=false when there is none).
func rtDnsFindRRSet(rrsets []any, name, rtype string) ([]any, bool) {
	for _, rrset := range rrsets {
		if rtDnsStrOr(jsonGet(rrset, "name"), "") == name && rtDnsStrOr(jsonGet(rrset, "type"), "") == rtype {
			recs, _ := jsonArr(jsonGet(rrset, "records"))
			return recs, true
		}
	}
	return nil, false
}

func rtDnsRRSets(zoneData any) []any {
	a, _ := jsonArr(jsonGet(zoneData, "rrsets"))
	return a
}

// rtDnsIsHex32 — CF zone and record IDs are 32-char lowercase hex.
func rtDnsIsHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func rtDnsIsDuplicate(err error) bool { return strings.Contains(err.Error(), "duplicate") }

// ── Route handlers ──────────────────────────────────────────────────────

// GET /api/dns/zones — List DNS zones.
func rtDnsListZones(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	zones, err := queryAll[rtDnsDnsZone](r.Context(), st.DB, "SELECT * FROM dns_zones ORDER BY domain LIMIT 500")
	if err != nil {
		return internalError("list zones", err)
	}
	out := make([]any, 0, len(zones))
	for _, z := range zones {
		out = append(out, map[string]any{
			"id":         z.ID,
			"domain":     z.Domain,
			"provider":   z.Provider,
			"cf_zone_id": z.CfZoneID,
			"created_at": z.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// POST /api/dns/zones — Add a DNS zone.
func rtDnsCreateZone(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtDnsCreateZoneRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	provider := "cloudflare"
	if body.Provider != nil {
		provider = *body.Provider
	}
	domain := strings.TrimSpace(body.Domain)
	if domain == "" {
		return apiErr(http.StatusBadRequest, "Domain is required")
	}
	if !isValidDomain(domain) {
		return apiErr(http.StatusBadRequest, "Invalid domain name")
	}

	switch provider {
	case "cloudflare":
		cfZoneID := strings.TrimSpace(rtDnsDeref(body.CfZoneID))
		cfAPIToken := strings.TrimSpace(rtDnsDeref(body.CfAPIToken))
		if cfZoneID == "" || cfAPIToken == "" {
			return apiErr(http.StatusBadRequest, "Cloudflare Zone ID and API token are required")
		}
		// CF zone IDs are 32-char lowercase hex; validate to keep untrusted input
		// out of the Cloudflare API URL path.
		if !rtDnsIsHex32(cfZoneID) {
			return apiErr(http.StatusBadRequest, "Invalid Cloudflare Zone ID")
		}

		// Validate CF credentials
		headers, err := rtDnsCfClient(cfAPIToken, body.CfAPIEmail)
		if err != nil {
			return err
		}
		resp, err := rtDnsSend(r, "GET", fmt.Sprintf("%s/zones/%s", rtDnsCFAPI, cfZoneID), headers, nil)
		if err != nil {
			return upstreamError("Cloudflare API", err)
		}
		cfResp, err := resp.json()
		if err != nil {
			return upstreamError("Cloudflare response", err)
		}
		if !rtDnsCfSuccess(cfResp) {
			errs := rtDnsGetOr(cfResp, "errors", nil)
			return apiErr(http.StatusBadRequest, "Cloudflare rejected credentials: "+rtDnsValueString(errs))
		}

		// Encrypt the Cloudflare API token at rest (mirrors the pdns_api_key /
		// smtp_password pattern). Read paths decrypt via cfHeaders.
		tokenEnc, err := SecretsCryptoEncryptCredential(cfAPIToken, st.Config.JWTSecret)
		if err != nil {
			return internalError("encrypt cf token", err)
		}
		var email *string
		if body.CfAPIEmail != nil {
			email = new(strings.TrimSpace(*body.CfAPIEmail))
		}
		zone, err := queryOne[rtDnsDnsZone](r.Context(), st.DB,
			"INSERT INTO dns_zones (user_id, domain, provider, cf_zone_id, cf_api_token, cf_api_email) "+
				"VALUES ($1, $2, 'cloudflare', $3, $4, $5) RETURNING *",
			c.Sub, domain, cfZoneID, tokenEnc, email)
		if err != nil {
			if rtDnsIsDuplicate(err) {
				return apiErr(http.StatusConflict, "Zone already exists")
			}
			return internalError("create zone", err)
		}

		slog.Info(fmt.Sprintf("DNS zone added (cloudflare): %s by %s", zone.Domain, c.Email))
		ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "dns.zone.create", new("dns"), &zone.Domain, nil, nil, c.KeyID)

		writeJSON(w, http.StatusCreated, map[string]any{
			"id":         zone.ID,
			"domain":     zone.Domain,
			"provider":   zone.Provider,
			"cf_zone_id": zone.CfZoneID,
			"created_at": zone.CreatedAt,
		})
		return nil
	case "powerdns":
		pdnsURL, pdnsKey, err := rtDnsPdnsSettings(st, r)
		if err != nil {
			return err
		}
		headers, err := rtDnsPdnsClient(pdnsKey)
		if err != nil {
			return err
		}
		zoneFqdn := rtDnsFqdn(domain)

		// Create zone in PowerDNS
		pdnsBody := map[string]any{
			"name":         zoneFqdn,
			"kind":         "Native",
			"nameservers":  []any{},
			"soa_edit_api": "DEFAULT",
		}
		resp, err := rtDnsSend(r, "POST", pdnsURL+"/api/v1/servers/localhost/zones", headers, pdnsBody)
		if err != nil {
			return upstreamError("PowerDNS API", err)
		}
		// 409 = zone already exists in PowerDNS, we can still track it
		if !resp.ok() && resp.Status != 409 {
			slog.Warn("PowerDNS error (create zone): " + string(resp.Raw))
			return apiErr(http.StatusBadGateway, "PowerDNS request failed")
		}

		zone, err := queryOne[rtDnsDnsZone](r.Context(), st.DB,
			"INSERT INTO dns_zones (user_id, domain, provider) "+
				"VALUES ($1, $2, 'powerdns') RETURNING *",
			c.Sub, domain)
		if err != nil {
			if rtDnsIsDuplicate(err) {
				return apiErr(http.StatusConflict, "Zone already exists")
			}
			return internalError("create zone", err)
		}

		slog.Info(fmt.Sprintf("DNS zone added (powerdns): %s by %s", zone.Domain, c.Email))
		ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "dns.zone.create", new("dns"), &zone.Domain, new("powerdns"), nil, c.KeyID)

		writeJSON(w, http.StatusCreated, map[string]any{
			"id":         zone.ID,
			"domain":     zone.Domain,
			"provider":   "powerdns",
			"created_at": zone.CreatedAt,
		})
		return nil
	default:
		return apiErr(http.StatusBadRequest, "Unsupported provider. Use 'cloudflare' or 'powerdns'.")
	}
}

// DELETE /api/dns/zones/{id} — Remove a DNS zone.
func rtDnsDeleteZone(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, zone, err := rtDnsAdminZone(st, r)
	if err != nil {
		return err
	}

	// If PowerDNS, delete the zone from the authoritative server FIRST and fail
	// closed: only drop our tracking row once the zone is actually gone, so a
	// transient PowerDNS error can't orphan an authoritative zone (panel says
	// deleted, server still answers).
	if zone.Provider == "powerdns" {
		pdnsURL, pdnsKey, err := rtDnsPdnsSettings(st, r)
		if err != nil {
			return err
		}
		headers, err := rtDnsPdnsClient(pdnsKey)
		if err != nil {
			return err
		}
		resp, err := rtDnsSend(r, "DELETE", rtDnsPdnsZoneURL(pdnsURL, rtDnsFqdn(zone.Domain)), headers, nil)
		if err != nil {
			return upstreamError("PowerDNS delete zone", err)
		}
		// 2xx = deleted; 404 = already absent — both are acceptable end states.
		if !resp.ok() && resp.Status != 404 {
			slog.Warn(fmt.Sprintf("PowerDNS delete-zone error (%s): %s", zone.Domain, resp.Raw))
			return apiErr(http.StatusBadGateway, "PowerDNS request failed; zone not deleted")
		}
	}

	if _, err := execSQL(r.Context(), st.DB, "DELETE FROM dns_zones WHERE id = $1", zone.ID); err != nil {
		return internalError("delete zone", err)
	}
	slog.Info("DNS zone removed: " + zone.Domain)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// GET /api/dns/zones/{id}/records — List DNS records.
func rtDnsListRecords(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, zone, err := rtDnsAdminZone(st, r)
	if err != nil {
		return err
	}

	switch zone.Provider {
	case "cloudflare":
		headers, err := rtDnsCfZoneClient(zone)
		if err != nil {
			return err
		}
		resp, err := rtDnsSend(r, "GET", fmt.Sprintf("%s/zones/%s/dns_records?per_page=100&order=type", rtDnsCFAPI, rtDnsDeref(zone.CfZoneID)), headers, nil)
		if err != nil {
			return upstreamError("Cloudflare API", err)
		}
		cfResp, err := resp.json()
		if err != nil {
			return upstreamError("Cloudflare response", err)
		}
		if !rtDnsCfSuccess(cfResp) {
			return apiErr(http.StatusBadGateway, "Failed to fetch DNS records from Cloudflare")
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"records":  rtDnsGetOr(cfResp, "result", []any{}),
			"domain":   zone.Domain,
			"provider": "cloudflare",
		})
		return nil
	case "powerdns":
		pdnsURL, pdnsKey, err := rtDnsPdnsSettings(st, r)
		if err != nil {
			return err
		}
		headers, err := rtDnsPdnsClient(pdnsKey)
		if err != nil {
			return err
		}
		resp, err := rtDnsSend(r, "GET", rtDnsPdnsZoneURL(pdnsURL, rtDnsFqdn(zone.Domain)), headers, nil)
		if err != nil {
			return upstreamError("PowerDNS API", err)
		}
		if !resp.ok() {
			slog.Warn("PowerDNS error (list records): " + string(resp.Raw))
			return apiErr(http.StatusBadGateway, "PowerDNS request failed")
		}
		pdnsResp, err := resp.json()
		if err != nil {
			return upstreamError("PowerDNS response", err)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"records":  rtDnsPdnsFlattenRecords(rtDnsRRSets(pdnsResp)),
			"domain":   zone.Domain,
			"provider": "powerdns",
		})
		return nil
	default:
		return apiErr(http.StatusBadRequest, "Unknown DNS provider")
	}
}

var rtDnsRecordTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"}

// POST /api/dns/zones/{id}/records — Create a DNS record.
func rtDnsCreateRecord(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtDnsRecordRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	zone, err := rtDnsGetZone(st, r, id)
	if err != nil {
		return err
	}

	if !slices.Contains(rtDnsRecordTypes, body.Rtype) {
		return apiErr(http.StatusBadRequest, "Unsupported record type: "+body.Rtype)
	}
	details := new(body.Rtype + " " + body.Name)

	switch zone.Provider {
	case "cloudflare":
		headers, err := rtDnsCfZoneClient(zone)
		if err != nil {
			return err
		}
		resp, err := rtDnsSend(r, "POST", fmt.Sprintf("%s/zones/%s/dns_records", rtDnsCFAPI, rtDnsDeref(zone.CfZoneID)), headers, rtDnsCfRecordBody(body))
		if err != nil {
			return upstreamError("Cloudflare API", err)
		}
		cfResp, err := resp.json()
		if err != nil {
			return upstreamError("Cloudflare response", err)
		}
		if !rtDnsCfSuccess(cfResp) {
			return apiErr(http.StatusUnprocessableEntity, "Cloudflare error: "+rtDnsValueString(rtDnsGetOr(cfResp, "errors", nil)))
		}
		ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "dns.record.create", new("dns"), &zone.Domain, details, nil, c.KeyID)
		writeJSON(w, http.StatusCreated, rtDnsGetOr(cfResp, "result", nil))
		return nil
	case "powerdns":
		pdnsURL, pdnsKey, err := rtDnsPdnsSettings(st, r)
		if err != nil {
			return err
		}
		headers, err := rtDnsPdnsClient(pdnsKey)
		if err != nil {
			return err
		}
		zoneFqdn := rtDnsFqdn(zone.Domain)
		ttl := uint32(3600)
		if body.TTL != nil {
			ttl = *body.TTL
		}
		recName := rtDnsRecName(body.Name, zone.Domain, zoneFqdn)
		content := rtDnsRecContent(body)

		// First, get existing records for this name+type to merge
		getResp, err := rtDnsSend(r, "GET", rtDnsPdnsZoneURL(pdnsURL, zoneFqdn), headers, nil)
		if err != nil {
			return upstreamError("PowerDNS API", err)
		}
		existing := []any{}
		if getResp.ok() {
			if recs, found := rtDnsFindRRSet(rtDnsRRSets(getResp.jsonOrNull()), recName, body.Rtype); found && recs != nil {
				existing = recs
			}
		}
		// Add the new record
		existing = append(existing, map[string]any{"content": content, "disabled": false})

		patch := map[string]any{"rrsets": []any{map[string]any{
			"name":       recName,
			"type":       body.Rtype,
			"ttl":        ttl,
			"changetype": "REPLACE",
			"records":    existing,
		}}}
		resp, err := rtDnsSend(r, "PATCH", rtDnsPdnsZoneURL(pdnsURL, zoneFqdn), headers, patch)
		if err != nil {
			return upstreamError("PowerDNS API", err)
		}
		if !resp.ok() {
			slog.Warn("PowerDNS record error: " + string(resp.Raw))
			return apiErr(http.StatusUnprocessableEntity, "PowerDNS rejected the record")
		}

		ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "dns.record.create", new("dns"), &zone.Domain, details, nil, c.KeyID)

		writeJSON(w, http.StatusCreated, map[string]any{
			"id":      rtDnsPdnsRecordID(recName, body.Rtype, content),
			"type":    body.Rtype,
			"name":    rtDnsStripDot(recName),
			"content": rtDnsStripDot(body.Content),
			"ttl":     ttl,
		})
		return nil
	default:
		return apiErr(http.StatusBadRequest, "Unknown DNS provider")
	}
}

// rtDnsRecordPrologue: AuthUser, Path((id, record_id)), [Json], require_admin,
// get_zone, then the record_id length check.
func rtDnsRecordPrologue(st *AppState, r *http.Request, body any) (*Claims, rtDnsDnsZone, string, error) {
	c, err := st.authUser(r)
	if err != nil {
		return nil, rtDnsDnsZone{}, "", err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return nil, rtDnsDnsZone{}, "", err
	}
	recordID := r.PathValue("record_id")
	if body != nil {
		if err := decodeJSON(r, body); err != nil {
			return nil, rtDnsDnsZone{}, "", err
		}
	}
	if err := requireAdmin(c.Role); err != nil {
		return nil, rtDnsDnsZone{}, "", err
	}
	zone, err := rtDnsGetZone(st, r, id)
	if err != nil {
		return nil, rtDnsDnsZone{}, "", err
	}
	if recordID == "" || len(recordID) > 256 {
		return nil, rtDnsDnsZone{}, "", apiErr(http.StatusBadRequest, "Invalid record ID")
	}
	return c, zone, recordID, nil
}

// PUT /api/dns/zones/{id}/records/{record_id} — Update a DNS record.
func rtDnsUpdateRecord(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var body rtDnsRecordRequest
	c, zone, recordID, err := rtDnsRecordPrologue(st, r, &body)
	if err != nil {
		return err
	}
	details := new(body.Rtype + " " + body.Name)

	switch zone.Provider {
	case "cloudflare":
		// CF record IDs are 32-char lowercase hex, same as cf_zone_id. record_id
		// is interpolated unescaped into the outbound URL below — without this
		// check a "../../../zones/OTHER/dns_records/RECID"-shaped id (percent-
		// encoded to survive the reverse proxy) reroutes the request, carrying
		// this zone's own decrypted token, to an arbitrary Cloudflare API path.
		if !rtDnsIsHex32(recordID) {
			return apiErr(http.StatusBadRequest, "Invalid record ID")
		}
		headers, err := rtDnsCfZoneClient(zone)
		if err != nil {
			return err
		}
		resp, err := rtDnsSend(r, "PUT", fmt.Sprintf("%s/zones/%s/dns_records/%s", rtDnsCFAPI, rtDnsDeref(zone.CfZoneID), recordID), headers, rtDnsCfRecordBody(body))
		if err != nil {
			return upstreamError("Cloudflare API", err)
		}
		cfResp, err := resp.json()
		if err != nil {
			return upstreamError("Cloudflare response", err)
		}
		if !rtDnsCfSuccess(cfResp) {
			return apiErr(http.StatusUnprocessableEntity, "Cloudflare error: "+rtDnsValueString(rtDnsGetOr(cfResp, "errors", nil)))
		}
		ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "dns.record.update", new("dns"), &zone.Domain, details, nil, c.KeyID)
		writeJSON(w, http.StatusOK, rtDnsGetOr(cfResp, "result", nil))
		return nil
	case "powerdns":
		pdnsURL, pdnsKey, err := rtDnsPdnsSettings(st, r)
		if err != nil {
			return err
		}
		headers, err := rtDnsPdnsClient(pdnsKey)
		if err != nil {
			return err
		}
		zoneFqdn := rtDnsFqdn(zone.Domain)

		// Parse the old record from the ID
		oldName, oldType, oldContent, err := rtDnsPdnsParseRecordID(recordID)
		if err != nil {
			return err
		}
		ttl := uint32(3600)
		if body.TTL != nil {
			ttl = *body.TTL
		}
		newName := rtDnsRecName(body.Name, zone.Domain, zoneFqdn)
		newContent := rtDnsRecContent(body)

		// Get current rrsets for the old name+type
		getResp, err := rtDnsSend(r, "GET", rtDnsPdnsZoneURL(pdnsURL, zoneFqdn), headers, nil)
		if err != nil {
			return upstreamError("PowerDNS API", err)
		}
		rrsets := rtDnsRRSets(getResp.jsonOrNull())
		newRec := map[string]any{"content": newContent, "disabled": false}

		var patchRRSets []any
		if oldName != newName || oldType != body.Rtype {
			// If name+type changed, delete old and create new.
			// Remove old record from its rrset.
			oldRecords := []any{}
			recs, _ := rtDnsFindRRSet(rrsets, oldName, oldType)
			for _, rec := range recs {
				if rtDnsStrOr(jsonGet(rec, "content"), "") != oldContent {
					oldRecords = append(oldRecords, rec)
				}
			}
			if len(oldRecords) == 0 {
				patchRRSets = append(patchRRSets, map[string]any{"name": oldName, "type": oldType, "changetype": "DELETE"})
			} else {
				patchRRSets = append(patchRRSets, map[string]any{"name": oldName, "type": oldType, "ttl": ttl, "changetype": "REPLACE", "records": oldRecords})
			}

			// Add to new rrset
			newRecords := []any{}
			if recs, found := rtDnsFindRRSet(rrsets, newName, body.Rtype); found && recs != nil {
				newRecords = recs
			}
			newRecords = append(newRecords, newRec)
			patchRRSets = append(patchRRSets, map[string]any{"name": newName, "type": body.Rtype, "ttl": ttl, "changetype": "REPLACE", "records": newRecords})
		} else {
			// Same name+type, just replace content in the rrset
			records := []any{}
			recs, _ := rtDnsFindRRSet(rrsets, oldName, oldType)
			for _, rec := range recs {
				if rtDnsStrOr(jsonGet(rec, "content"), "") == oldContent {
					records = append(records, newRec)
				} else {
					records = append(records, rec)
				}
			}
			if len(records) == 0 {
				records = append(records, newRec)
			}
			patchRRSets = append(patchRRSets, map[string]any{"name": newName, "type": body.Rtype, "ttl": ttl, "changetype": "REPLACE", "records": records})
		}

		resp, err := rtDnsSend(r, "PATCH", rtDnsPdnsZoneURL(pdnsURL, zoneFqdn), headers, map[string]any{"rrsets": patchRRSets})
		if err != nil {
			return upstreamError("PowerDNS API", err)
		}
		if !resp.ok() {
			slog.Warn("PowerDNS record error: " + string(resp.Raw))
			return apiErr(http.StatusUnprocessableEntity, "PowerDNS rejected the record")
		}

		ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "dns.record.update", new("dns"), &zone.Domain, details, nil, c.KeyID)

		writeJSON(w, http.StatusOK, map[string]any{
			"id":      rtDnsPdnsRecordID(newName, body.Rtype, newContent),
			"type":    body.Rtype,
			"name":    rtDnsStripDot(newName),
			"content": rtDnsStripDot(body.Content),
			"ttl":     ttl,
		})
		return nil
	default:
		return apiErr(http.StatusBadRequest, "Unknown DNS provider")
	}
}

// DELETE /api/dns/zones/{id}/records/{record_id} — Delete a DNS record.
func rtDnsDeleteRecord(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, zone, recordID, err := rtDnsRecordPrologue(st, r, nil)
	if err != nil {
		return err
	}
	ip := clientIP(r)

	switch zone.Provider {
	case "cloudflare":
		// Same discipline as update — CF record IDs are 32-char lowercase hex;
		// record_id is unescaped in the outbound URL below.
		if !rtDnsIsHex32(recordID) {
			return apiErr(http.StatusBadRequest, "Invalid record ID")
		}
		headers, err := rtDnsCfZoneClient(zone)
		if err != nil {
			return err
		}
		resp, err := rtDnsSend(r, "DELETE", fmt.Sprintf("%s/zones/%s/dns_records/%s", rtDnsCFAPI, rtDnsDeref(zone.CfZoneID), recordID), headers, nil)
		if err != nil {
			return upstreamError("Cloudflare API", err)
		}
		cfResp, err := resp.json()
		if err != nil {
			return upstreamError("Cloudflare response", err)
		}
		if !rtDnsCfSuccess(cfResp) {
			return apiErr(http.StatusUnprocessableEntity, "Cloudflare error: "+rtDnsValueString(rtDnsGetOr(cfResp, "errors", nil)))
		}
	case "powerdns":
		pdnsURL, pdnsKey, err := rtDnsPdnsSettings(st, r)
		if err != nil {
			return err
		}
		headers, err := rtDnsPdnsClient(pdnsKey)
		if err != nil {
			return err
		}
		zoneFqdn := rtDnsFqdn(zone.Domain)
		recName, recType, recContent, err := rtDnsPdnsParseRecordID(recordID)
		if err != nil {
			return err
		}

		// Get current rrset
		getResp, err := rtDnsSend(r, "GET", rtDnsPdnsZoneURL(pdnsURL, zoneFqdn), headers, nil)
		if err != nil {
			return upstreamError("PowerDNS API", err)
		}
		remaining := []any{}
		recs, _ := rtDnsFindRRSet(rtDnsRRSets(getResp.jsonOrNull()), recName, recType)
		for _, rec := range recs {
			if rtDnsStrOr(jsonGet(rec, "content"), "") != recContent {
				remaining = append(remaining, rec)
			}
		}
		patchRRSet := map[string]any{"name": recName, "type": recType, "changetype": "DELETE"}
		if len(remaining) > 0 {
			patchRRSet["changetype"] = "REPLACE"
			patchRRSet["ttl"] = 3600
			patchRRSet["records"] = remaining
		}
		resp, err := rtDnsSend(r, "PATCH", rtDnsPdnsZoneURL(pdnsURL, zoneFqdn), headers, map[string]any{"rrsets": []any{patchRRSet}})
		if err != nil {
			return upstreamError("PowerDNS API", err)
		}
		if !resp.ok() {
			slog.Warn("PowerDNS record error: " + string(resp.Raw))
			return apiErr(http.StatusUnprocessableEntity, "PowerDNS rejected the record")
		}
	default:
		return apiErr(http.StatusBadRequest, "Unknown DNS provider")
	}

	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "dns.record.delete", new("dns"), &zone.Domain, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(r.Context(), st.DB, "dns.record.delete", &c.Email, ip, new("dns"), &zone.Domain, nil, nil, "warning", c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtDnsDig runs dig and returns its trimmed stdout ("" if it could not run),
// like `safe_command("dig").output().await.ok().map(stdout)`.
func rtDnsDig(r *http.Request, args ...string) string {
	out, _ := safeCommand(r.Context(), "dig", args...).Output()
	return strings.TrimSpace(strings.ToValidUTF8(string(out), "�"))
}

// POST /api/dns/propagation — Check DNS propagation across multiple public resolvers.
func rtDnsCheckPropagation(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	name, ok := jsonStr(jsonGet(body, "name"))
	if !ok {
		return apiErr(http.StatusBadRequest, "name required")
	}
	rtype := rtDnsStrOr(jsonGet(body, "type"), "A")

	// Reject anything dig could parse as an option (leading -/+) or that escapes
	// the conservative DNS charset. See rtDnsIsSafeDigArg + its unit test.
	if !rtDnsIsSafeDigArg(name, true) {
		return apiErr(http.StatusBadRequest, "Invalid DNS name")
	}
	if !slices.Contains(rtDnsRecordTypes, rtype) {
		return apiErr(http.StatusBadRequest, "Invalid record type")
	}

	resolvers := [][2]string{
		{"8.8.8.8", "Google"},
		{"1.1.1.1", "Cloudflare"},
		{"9.9.9.9", "Quad9"},
		{"208.67.222.222", "OpenDNS"},
		{"8.26.56.26", "Comodo"},
	}
	results := []any{}
	propagated := 0
	for _, res := range resolvers {
		value := rtDnsDig(r, "@"+res[0], "+short", "+time=3", "+tries=1", rtype, name)
		shown := value
		if value == "" {
			shown = "No response"
		} else {
			propagated++
		}
		results = append(results, map[string]any{
			"resolver": res[0],
			"label":    res[1],
			"value":    shown,
			"found":    value != "",
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name":             name,
		"type":             rtype,
		"results":          results,
		"propagated":       propagated,
		"total":            len(resolvers),
		"fully_propagated": propagated == len(resolvers),
	})
	return nil
}

// ── DNS Health Check ────────────────────────────────────────────────────

func rtDnsRunDig(r *http.Request, domain, rtype string) string {
	return rtDnsDig(r, "+short", "+time=3", "+tries=1", rtype, domain)
}

// POST /api/dns/health-check — Run DNS health checks on a domain.
func rtDnsDnsHealthCheck(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	domain, ok := jsonStr(jsonGet(body, "domain"))
	if !ok {
		return apiErr(http.StatusBadRequest, "domain required")
	}
	// Reject anything dig could parse as an option, or that escapes the DNS charset.
	if len(domain) > 253 || !rtDnsIsSafeDigArg(domain, false) {
		return apiErr(http.StatusBadRequest, "Invalid domain")
	}

	pick := func(cond bool, a, b string) string {
		if cond {
			return a
		}
		return b
	}
	var checks []map[string]any

	// 1. SOA record
	soa := rtDnsRunDig(r, domain, "SOA")
	checks = append(checks, map[string]any{
		"check":  "SOA Record",
		"status": pick(soa != "", "pass", "fail"),
		"detail": pick(soa == "", "No SOA record found", soa),
	})

	// 2. NS records
	ns := rtDnsRunDig(r, domain, "NS")
	nsCount := 0
	for _, l := range strings.Split(ns, "\n") {
		if l != "" {
			nsCount++
		}
	}
	nsStatus := "fail"
	if nsCount >= 2 {
		nsStatus = "pass"
	} else if nsCount == 1 {
		nsStatus = "warn"
	}
	checks = append(checks, map[string]any{
		"check":  "NS Records",
		"status": nsStatus,
		"detail": fmt.Sprintf("%d nameserver(s) found", nsCount),
	})

	// 3. A record exists
	a := rtDnsRunDig(r, domain, "A")
	checks = append(checks, map[string]any{
		"check":  "A Record",
		"status": pick(a != "", "pass", "info"),
		"detail": pick(a == "", "No A record — domain won't resolve to an IP", a),
	})

	// 4. MX record
	mx := rtDnsRunDig(r, domain, "MX")
	checks = append(checks, map[string]any{
		"check":  "MX Record",
		"status": pick(mx != "", "pass", "info"),
		"detail": pick(mx == "", "No MX record — domain can't receive email", mx),
	})

	// 5. SPF
	hasSPF := strings.Contains(rtDnsRunDig(r, domain, "TXT"), "v=spf1")
	checks = append(checks, map[string]any{
		"check":  "SPF Record",
		"status": pick(hasSPF, "pass", "warn"),
		"detail": pick(hasSPF, "SPF configured", "No SPF record — email authentication missing"),
	})

	// 6. DNSSEC
	hasDNSSEC := rtDnsDig(r, "+dnssec", "+short", "DNSKEY", domain) != ""
	checks = append(checks, map[string]any{
		"check":  "DNSSEC",
		"status": pick(hasDNSSEC, "pass", "info"),
		"detail": pick(hasDNSSEC, "DNSSEC is active", "DNSSEC not configured (optional)"),
	})

	pass, fail := 0, 0
	for _, ch := range checks {
		switch ch["status"] {
		case "pass":
			pass++
		case "fail":
			fail++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"domain": domain,
		"checks": checks,
		"pass":   pass,
		"fail":   fail,
		"total":  len(checks),
	})
	return nil
}

// ── DNSSEC Status ───────────────────────────────────────────────────────

// GET /api/dns/zones/{id}/dnssec — Get DNSSEC status for a zone.
func rtDnsDnssecStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, zone, err := rtDnsAdminZone(st, r)
	if err != nil {
		return err
	}
	if zone.Provider != "cloudflare" {
		writeJSON(w, http.StatusOK, map[string]any{
			"supported": false,
			"message":   "DNSSEC management only available for Cloudflare zones",
		})
		return nil
	}
	headers, err := rtDnsCfZoneClient(zone)
	if err != nil {
		return err
	}
	resp, err := rtDnsSend(r, "GET", fmt.Sprintf("%s/zones/%s/dnssec", rtDnsCFAPI, rtDnsDeref(zone.CfZoneID)), headers, nil)
	if err != nil {
		return apiErr(http.StatusBadGateway, err.Error())
	}
	data, err := resp.json()
	if err != nil {
		return apiErr(http.StatusBadGateway, err.Error())
	}
	result := rtDnsGetOr(data, "result", map[string]any{})
	status := rtDnsStrOr(jsonGet(result, "status"), "unknown")
	writeJSON(w, http.StatusOK, map[string]any{
		"supported": true,
		"status":    status,
		"active":    status == "active",
		"ds_record": jsonGet(result, "ds"),
		"key_tag":   jsonGet(result, "key_tag"),
		"algorithm": jsonGet(result, "algorithm"),
	})
	return nil
}

// ── DNS Changelog ───────────────────────────────────────────────────────

// GET /api/dns/zones/{id}/changelog — Get DNS change history.
func rtDnsDnsChangelog(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, zone, err := rtDnsAdminZone(st, r)
	if err != nil {
		return err
	}
	entries, err := queryAll[Tup4[string, string, *string, time.Time]](r.Context(), st.DB,
		"SELECT action, COALESCE(user_email, ''), details, created_at FROM activity_logs "+
			"WHERE action LIKE 'dns.%' AND target_name = $1 ORDER BY created_at DESC LIMIT 50",
		zone.Domain)
	if err != nil {
		return internalError("dns changelog", err)
	}
	logs := make([]any, 0, len(entries))
	for _, e := range entries {
		logs = append(logs, map[string]any{"action": e.A, "user": e.B, "details": e.C, "time": e.D})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": logs})
	return nil
}

// ── DNS Analytics ───────────────────────────────────────────────────────

// GET /api/dns/zones/{id}/analytics — Get DNS query analytics (Cloudflare only).
func rtDnsDnsAnalytics(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, zone, err := rtDnsAdminZone(st, r)
	if err != nil {
		return err
	}
	if zone.Provider != "cloudflare" {
		writeJSON(w, http.StatusOK, map[string]any{
			"supported": false,
			"message":   "Analytics only available for Cloudflare zones",
		})
		return nil
	}
	headers, err := rtDnsCfZoneClient(zone)
	if err != nil {
		return err
	}

	// Fetch DNS analytics for last 24 hours
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour).Format("2006-01-02T15:04:05Z")
	until := now.Format("2006-01-02T15:04:05Z")
	resp, err := rtDnsSend(r, "GET", fmt.Sprintf("%s/zones/%s/dns_analytics/report?since=%s&until=%s&metrics=queryCount,responseTimeAvg&dimensions=queryType",
		rtDnsCFAPI, rtDnsDeref(zone.CfZoneID), since, until), headers, nil)
	if err != nil {
		return apiErr(http.StatusBadGateway, err.Error())
	}
	data, err := resp.json()
	if err != nil {
		return apiErr(http.StatusBadGateway, err.Error())
	}
	if !resp.ok() {
		// Analytics API might not be available on free plans
		writeJSON(w, http.StatusOK, map[string]any{
			"supported": true,
			"available": false,
			"message":   "DNS analytics not available (may require paid Cloudflare plan)",
		})
		return nil
	}

	result := rtDnsGetOr(data, "result", map[string]any{})
	totals := rtDnsGetOr(result, "totals", map[string]any{})
	rows, _ := jsonArr(jsonGet(result, "data"))
	totalQueries, _ := jsonU64(jsonGet(totals, "queryCount"))
	avgResponse, _ := jsonF64(jsonGet(totals, "responseTimeAvg"))

	byType := make([]any, 0, len(rows))
	for _, row := range rows {
		dims, _ := jsonArr(jsonGet(row, "dimensions"))
		metrics, _ := jsonArr(jsonGet(row, "metrics"))
		var t string
		if len(dims) > 0 {
			t = rtDnsStrOr(dims[0], "")
		}
		var q uint64
		if len(metrics) > 0 {
			q, _ = jsonU64(metrics[0])
		}
		byType = append(byType, map[string]any{"type": t, "queries": q})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"supported":       true,
		"available":       true,
		"total_queries":   totalQueries,
		"avg_response_ms": rtDnsF64(math.Round(avgResponse*1000.0) / 1000.0),
		"by_type":         byType,
		"period":          "24h",
	})
	return nil
}

// rtDnsF64 renders an f64 the way serde_json does: always with a fractional
// part ("0.0", "1.5"), never as a bare integer.
type rtDnsF64 float64

func (f rtDnsF64) MarshalJSON() ([]byte, error) {
	v := float64(f)
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return []byte("null"), nil
	}
	if v == math.Trunc(v) && math.Abs(v) < 1e16 {
		return []byte(strconv.FormatFloat(v, 'f', 1, 64)), nil
	}
	return []byte(strconv.FormatFloat(v, 'g', -1, 64)), nil
}

// ── Cloudflare Zone Settings ───────────────────────────────────────────

var rtDnsCfAllowedSettings = []string{"security_level", "development_mode", "ssl", "always_use_https", "min_tls_version"}

// GET /api/dns/zones/{id}/cf/settings — Get Cloudflare zone settings.
func rtDnsCfZoneSettings(st *AppState, w http.ResponseWriter, r *http.Request) error {
	_, zone, err := rtDnsAdminZone(st, r)
	if err != nil {
		return err
	}
	if zone.Provider != "cloudflare" {
		writeJSON(w, http.StatusOK, map[string]any{
			"supported": false,
			"message":   "Settings management only available for Cloudflare zones",
		})
		return nil
	}
	zoneID := rtDnsDeref(zone.CfZoneID)
	headers, err := rtDnsCfZoneClient(zone)
	if err != nil {
		return err
	}

	results := map[string]any{}
	for _, key := range rtDnsCfAllowedSettings {
		resp, err := rtDnsSend(r, "GET", fmt.Sprintf("%s/zones/%s/settings/%s", rtDnsCFAPI, zoneID, key), headers, nil)
		if err != nil {
			return apiErr(http.StatusBadGateway, err.Error())
		}
		data, err := resp.json()
		if err != nil {
			return apiErr(http.StatusBadGateway, err.Error())
		}
		if res, ok := jsonObj(jsonGet(data, "result")); ok {
			if v, ok := res["value"]; ok {
				results[key] = v
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"supported": true, "settings": results})
	return nil
}

// rtDnsCfFirstError is errors[0].message, or def.
func rtDnsCfFirstError(data any, def string) string {
	return rtDnsStrOr(jsonGet(data, "errors", 0, "message"), def)
}

// PUT /api/dns/zones/{id}/cf/settings — Update a Cloudflare zone setting.
func rtDnsCfUpdateSetting(st *AppState, w http.ResponseWriter, r *http.Request) error {
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
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	zone, err := rtDnsGetZone(st, r, id)
	if err != nil {
		return err
	}
	ip := clientIP(r)

	if zone.Provider != "cloudflare" {
		return apiErr(http.StatusBadRequest, "Only available for Cloudflare zones")
	}
	setting, ok := jsonStr(jsonGet(body, "setting"))
	if !ok {
		return apiErr(http.StatusBadRequest, "Missing 'setting' field")
	}
	obj, _ := jsonObj(body)
	value, ok := obj["value"]
	if !ok {
		return apiErr(http.StatusBadRequest, "Missing 'value' field")
	}

	// Whitelist allowed settings
	if !slices.Contains(rtDnsCfAllowedSettings, setting) {
		return apiErr(http.StatusBadRequest, fmt.Sprintf("Setting '%s' not allowed. Allowed: %s", setting, strings.Join(rtDnsCfAllowedSettings, ", ")))
	}

	// Validate values
	v, isStr := jsonStr(value)
	switch setting {
	case "security_level":
		if !slices.Contains([]string{"off", "essentially_off", "low", "medium", "high", "under_attack"}, v) {
			return apiErr(http.StatusBadRequest, "Invalid security_level value")
		}
	case "development_mode":
		if !isStr || (v != "on" && v != "off") {
			return apiErr(http.StatusBadRequest, "development_mode must be 'on' or 'off'")
		}
	case "ssl":
		if !slices.Contains([]string{"off", "flexible", "full", "strict"}, v) {
			return apiErr(http.StatusBadRequest, "Invalid ssl value. Use: off, flexible, full, strict")
		}
	case "always_use_https":
		if !isStr || (v != "on" && v != "off") {
			return apiErr(http.StatusBadRequest, "always_use_https must be 'on' or 'off'")
		}
	case "min_tls_version":
		if !slices.Contains([]string{"1.0", "1.1", "1.2", "1.3"}, v) {
			return apiErr(http.StatusBadRequest, "Invalid min_tls_version. Use: 1.0, 1.1, 1.2, 1.3")
		}
	}

	headers, err := rtDnsCfZoneClient(zone)
	if err != nil {
		return err
	}
	resp, err := rtDnsSend(r, "PATCH", fmt.Sprintf("%s/zones/%s/settings/%s", rtDnsCFAPI, rtDnsDeref(zone.CfZoneID), setting), headers, map[string]any{"value": value})
	if err != nil {
		return apiErr(http.StatusBadGateway, err.Error())
	}
	data, err := resp.json()
	if err != nil {
		return apiErr(http.StatusBadGateway, err.Error())
	}
	if !resp.ok() {
		return apiErr(http.StatusBadGateway, rtDnsCfFirstError(data, "Unknown Cloudflare error"))
	}

	slog.Info(fmt.Sprintf("CF setting updated: %s=%s for zone %s", setting, rtDnsValueString(value), zone.Domain))
	action := "dns.cf.setting." + setting
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, action, new("dns_zone"), &zone.Domain, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(r.Context(), st.DB, action, &c.Email, ip, new("dns_zone"), &zone.Domain, nil, nil, "warning", c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "setting": setting, "value": value})
	return nil
}

// ── Cloudflare Cache Purge ─────────────────────────────────────────────

// POST /api/dns/zones/{id}/cf/cache/purge — Purge Cloudflare cache.
func rtDnsCfPurgeCache(st *AppState, w http.ResponseWriter, r *http.Request) error {
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
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	zone, err := rtDnsGetZone(st, r, id)
	if err != nil {
		return err
	}
	if zone.Provider != "cloudflare" {
		return apiErr(http.StatusBadRequest, "Cache purge only available for Cloudflare zones")
	}
	headers, err := rtDnsCfZoneClient(zone)
	if err != nil {
		return err
	}

	// Build purge request: either purge_everything or specific files
	var purge any = map[string]any{"purge_everything": true}
	if files, ok := jsonArr(jsonGet(body, "files")); ok {
		if len(files) == 0 || len(files) > 30 {
			return apiErr(http.StatusBadRequest, "Provide 1-30 URLs to purge")
		}
		purge = map[string]any{"files": files}
	}

	resp, err := rtDnsSend(r, "POST", fmt.Sprintf("%s/zones/%s/purge_cache", rtDnsCFAPI, rtDnsDeref(zone.CfZoneID)), headers, purge)
	if err != nil {
		return apiErr(http.StatusBadGateway, err.Error())
	}
	data, err := resp.json()
	if err != nil {
		return apiErr(http.StatusBadGateway, err.Error())
	}
	if !resp.ok() {
		return apiErr(http.StatusBadGateway, rtDnsCfFirstError(data, "Cloudflare cache purge failed"))
	}

	purgeType := "full"
	if obj, ok := jsonObj(body); ok {
		if _, has := obj["files"]; has {
			purgeType = "selective"
		}
	}
	slog.Info(fmt.Sprintf("CF cache purge (%s) for zone %s", purgeType, zone.Domain))
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, "dns.cf.cache.purge."+purgeType, new("dns_zone"), &zone.Domain, nil, nil, c.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "purge_type": purgeType})
	return nil
}
