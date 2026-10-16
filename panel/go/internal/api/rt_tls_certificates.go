package api

// Port of panel/backend/src/routes/tls_certificates.rs.
//
// The named certificate registry (GitHub #104).
//
// A certificate is registered ONCE, under an alias the operator chooses, and a
// Compose stack refers to it by that alias when it claims a domain. The PEM
// pair never passes through this table: the agent parses it, checks the key
// belongs to it, writes it under /etc/dockpanel/ssl-registry/<alias>/, and
// hands back the metadata that is recorded here — names, issuer, validity,
// fingerprint and the two paths. Postgres holds no key material.
//
// Why this is not the single-site upload with a second caller: that door
// writes into /etc/dockpanel/ssl/{domain}/, the directory every scheduled
// renewer treats as its own and the stack teardown deletes. A certificate that
// several stacks share, and that must survive any one of them being removed,
// cannot live in a directory named after one domain.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// rtTlsCertificatesProvidedTlsMinAgent is the agent release whose deploy path
// honours tls_mode/tls_certificate and serves /ssl/registry. ⛔ FROZEN at the
// release that shipped it — a version bump must not move it.
const rtTlsCertificatesProvidedTlsMinAgent = "2.160.0"

// rtTlsCertificatesStackRenewalMinAgent is the agent release whose per-domain
// SSL renew route accepts a request with NO `runtime` field — the in-place
// branch a Compose stack's renewal needs.
//
// ⛔ The route is deliberately NOT spelled out here. `sibling-parity` builds
// its render-door census with `grep -rl` over RAW SOURCE, which cannot tell a
// comment from a call: writing the literal path in this doc block enrols this
// file as an agent-SSL caller it is not.
//
// The panel cannot describe a stack's vhost as a SiteConfig (the published
// port lives in the compose YAML, which only the agent parses), so the stack
// renewal in the security scanner omits `runtime` and the agent reloads
// instead of re-rendering. An agent older than this parses `runtime` as
// required and answers 422 — on every weekly scan, for ever.
// ⛔ FROZEN at the release that shipped it, same rule as its neighbour.
const rtTlsCertificatesStackRenewalMinAgent = "2.161.0"

// Upper bounds on the PEM bodies, checked before anything is sent to the
// agent. A full chain with three intermediates is well under 16 KB; a key is a
// few KB. Generous enough to never refuse a real certificate, tight enough
// that the endpoint cannot be used to push arbitrary bulk at the agent's disk.
const (
	rtTlsCertificatesMaxCertBytes = 65536
	rtTlsCertificatesMaxKeyBytes  = 16384
)

func rtTlsCertificatesRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/tls-certificates", h(rtTlsCertificatesList))
	r.Handle("POST /api/tls-certificates", h(rtTlsCertificatesCreate))
	r.Handle("PUT /api/tls-certificates/{id}", h(rtTlsCertificatesReplace))
	r.Handle("DELETE /api/tls-certificates/{id}", h(rtTlsCertificatesRemove))
}

// rtTlsCertificatesIsValidCertAlias is the alias grammar, shared with the
// agent (which validates it again before it becomes a directory name): a
// DNS-label shape, 1–64 characters, lowercase letters, digits and inner
// hyphens. Anything that passes here also satisfies nginx's safe-path rule,
// which is why the two sides may agree on it by text.
func rtTlsCertificatesIsValidCertAlias(alias string) bool {
	if len(alias) == 0 || len(alias) > 64 {
		return false
	}
	for i := 0; i < len(alias); i++ {
		b := alias[i]
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return alias[0] != '-' && alias[len(alias)-1] != '-'
}

// rtTlsCertificatesRequireAgentAtLeast refuses unless the agent reports a
// version at or above min.
//
// 412 PRECONDITION_FAILED with an "update that server's agent" sentence, so
// the operator learns what to do rather than what went wrong. Reads /health,
// the route every agent has always carried — servers.agent_version is NULL for
// the local box, so the column cannot be the source.
//
// An unreadable version FAILS CLOSED. The port-check gate degrades when it
// cannot tell, because the worst case there is one more probe; here the worst
// case is an older agent that ignores the fields it does not know, infers "no
// TLS" from the absent address, and writes a provided-certificate domain as a
// plain-HTTP vhost — behind the HSTS header its previous vhost already sent.
// That silent downgrade is exactly the outage this feature exists to prevent.
func rtTlsCertificatesRequireAgentAtLeast(ctx context.Context, agent AgentHandle, min, what string) error {
	var reported *string
	if v, err := agent.Get(ctx, "/health"); err == nil {
		if s, ok := jsonStr(jsonGet(v, "version")); ok {
			reported = &s
		}
	}
	if reported != nil {
		have, need := PanelUpdateSemverKey(reported), PanelUpdateSemverKey(&min)
		if slices.Compare(have[:], need[:]) >= 0 {
			return nil
		}
	}
	shown := "no readable version"
	if reported != nil {
		shown = *reported
	}
	return apiErr(http.StatusPreconditionFailed, fmt.Sprintf(
		"%s needs an agent of %s or later, and the agent on that server reports %s. "+
			"Update that server's agent to %s or later, then retry.", what, min, shown, min))
}

const rtTlsCertificatesCertSelect = "SELECT id, user_id, server_id, alias, dns_names, issuer, not_before, " +
	"not_after, fingerprint_sha256, cert_path, key_path, created_at, " +
	"updated_at FROM tls_certificates"

type rtTlsCertificatesTlsCertificate struct {
	ID                uuid.UUID  `db:"id"`
	UserID            uuid.UUID  `db:"user_id"`
	ServerID          uuid.UUID  `db:"server_id"`
	Alias             string     `db:"alias"`
	DNSNames          []string   `db:"dns_names"`
	Issuer            *string    `db:"issuer"`
	NotBefore         *time.Time `db:"not_before"`
	NotAfter          *time.Time `db:"not_after"`
	FingerprintSHA256 *string    `db:"fingerprint_sha256"`
	CertPath          string     `db:"cert_path"`
	KeyPath           string     `db:"key_path"`
	CreatedAt         time.Time  `db:"created_at"`
	UpdatedAt         time.Time  `db:"updated_at"`
}

// rtTlsCertificatesAgentCertMetadata is what the agent's registry upload
// answers with, read once so create and replace read the same fields the same
// way.
type rtTlsCertificatesAgentCertMetadata struct {
	DNSNames          []string
	Issuer            *string
	NotBefore         *time.Time
	NotAfter          *time.Time
	FingerprintSHA256 *string
	CertPath          *string
	KeyPath           *string
}

func rtTlsCertificatesReadAgentMetadata(v any) rtTlsCertificatesAgentCertMetadata {
	strField := func(k string) *string {
		if s, ok := jsonStr(jsonGet(v, k)); ok {
			return &s
		}
		return nil
	}
	timeField := func(k string) *time.Time {
		if s, ok := jsonStr(jsonGet(v, k)); ok {
			return parseAgentCertExpiry(s)
		}
		return nil
	}
	names := []string{}
	if arr, ok := jsonArr(jsonGet(v, "dns_names")); ok {
		for _, n := range arr {
			if s, ok := jsonStr(n); ok {
				names = append(names, s)
			}
		}
	}
	return rtTlsCertificatesAgentCertMetadata{
		DNSNames:          names,
		Issuer:            strField("issuer"),
		NotBefore:         timeField("not_before"),
		NotAfter:          timeField("not_after"),
		FingerprintSHA256: strField("fingerprint_sha256"),
		CertPath:          strField("cert_path"),
		KeyPath:           strField("key_path"),
	}
}

type rtTlsCertificatesStackRef = Tup3[uuid.UUID, string, *string]

// rtTlsCertificatesReferencingStacks: the stacks that point at a registered
// certificate: (id, name, domain).
func rtTlsCertificatesReferencingStacks(ctx context.Context, db Querier, certID uuid.UUID) ([]rtTlsCertificatesStackRef, error) {
	rows, err := queryAll[rtTlsCertificatesStackRef](ctx, db,
		"SELECT id, name, domain FROM docker_stacks WHERE tls_certificate_id = $1 ORDER BY name", certID)
	if err != nil {
		return nil, internalError("tls certificate references", err)
	}
	return rows, nil
}

func rtTlsCertificatesStacksJSON(stacks []rtTlsCertificatesStackRef) []any {
	out := make([]any, 0, len(stacks))
	for _, s := range stacks {
		out = append(out, map[string]any{"id": s.A, "name": s.B, "domain": s.C})
	}
	return out
}

// rtTlsCertificatesCertJSON is one row as the API presents it. days_left and
// status use the same ladder the certificate dashboard uses for sites, so the
// page renders one vocabulary. renewal_failing is always false: nothing renews
// a registered certificate, so the rung that says "the machinery failed" would
// describe machinery that was never pointed at it.
func rtTlsCertificatesCertJSON(row rtTlsCertificatesTlsCertificate, inUseBy []rtTlsCertificatesStackRef) map[string]any {
	var daysLeft *int64
	if row.NotAfter != nil {
		d := int64(time.Until(*row.NotAfter) / (24 * time.Hour))
		daysLeft = &d
	}
	names := row.DNSNames
	if names == nil {
		names = []string{}
	}
	return map[string]any{
		"id":                 row.ID,
		"user_id":            row.UserID,
		"server_id":          row.ServerID,
		"alias":              row.Alias,
		"dns_names":          names,
		"issuer":             row.Issuer,
		"not_before":         row.NotBefore,
		"not_after":          row.NotAfter,
		"fingerprint_sha256": row.FingerprintSHA256,
		"cert_path":          row.CertPath,
		"key_path":           row.KeyPath,
		"days_left":          daysLeft,
		"status":             rtMonitorsExpiryStatus(daysLeft, false),
		"in_use_by":          rtTlsCertificatesStacksJSON(inUseBy),
		"created_at":         row.CreatedAt,
		"updated_at":         row.UpdatedAt,
	}
}

// rtTlsCertificatesCheckPemSizes validates the two PEM bodies before anything
// leaves the panel. The agent parses them properly; this only refuses the
// shapes that cannot be right.
func rtTlsCertificatesCheckPemSizes(certificate, privateKey string) error {
	if strings.TrimSpace(certificate) == "" || strings.TrimSpace(privateKey) == "" {
		return apiErr(http.StatusBadRequest, "Both the certificate and the private key are required")
	}
	if len(certificate) > rtTlsCertificatesMaxCertBytes {
		return apiErr(http.StatusBadRequest, "Certificate too large (max 64KB)")
	}
	if len(privateKey) > rtTlsCertificatesMaxKeyBytes {
		return apiErr(http.StatusBadRequest, "Private key too large (max 16KB)")
	}
	return nil
}

// rtTlsCertificatesOwnedCertificate loads one certificate the caller owns, by id.
func rtTlsCertificatesOwnedCertificate(ctx context.Context, db Querier, id, userID uuid.UUID) (rtTlsCertificatesTlsCertificate, error) {
	row, err := queryOpt[rtTlsCertificatesTlsCertificate](ctx, db, rtTlsCertificatesCertSelect+" WHERE id = $1 AND user_id = $2", id, userID)
	if err != nil {
		return rtTlsCertificatesTlsCertificate{}, internalError("load tls certificate", err)
	}
	if row == nil {
		return rtTlsCertificatesTlsCertificate{}, apiErr(http.StatusNotFound, "Certificate not found")
	}
	return *row, nil
}

// rtTlsCertificatesCertificateIdForAlias resolves a registered certificate by
// alias for a stack claim: the row's id.
//
// Scoped to the caller AND the server, because the alias is unique per server
// only — the same name may be registered on two fleet members with different
// certificates behind it, and a stack must resolve the one on its own host.
func rtTlsCertificatesCertificateIdForAlias(ctx context.Context, db Querier, alias string, userID, serverID uuid.UUID) (uuid.UUID, error) {
	found, err := queryScalarOpt[uuid.UUID](ctx, db,
		"SELECT id FROM tls_certificates WHERE alias = $1 AND user_id = $2 AND server_id = $3", alias, userID, serverID)
	if err != nil {
		return uuid.Nil, internalError("resolve tls certificate alias", err)
	}
	if found == nil {
		return uuid.Nil, apiErr(http.StatusBadRequest, fmt.Sprintf("no registered certificate named %s on this server", alias))
	}
	return *found, nil
}

// GET /api/tls-certificates — the registry on the scoped server.
func rtTlsCertificatesList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	rows, err := queryAll[rtTlsCertificatesTlsCertificate](r.Context(), st.DB,
		rtTlsCertificatesCertSelect+" WHERE user_id = $1 AND server_id = $2 ORDER BY alias", c.Sub, serverID)
	if err != nil {
		return internalError("list tls certificates", err)
	}
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		inUseBy, err := rtTlsCertificatesReferencingStacks(r.Context(), st.DB, row.ID)
		if err != nil {
			return err
		}
		out = append(out, rtTlsCertificatesCertJSON(row, inUseBy))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

type rtTlsCertificatesCreateCertificateRequest struct {
	Alias       string `json:"alias"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

// rtTlsCertificatesASCIILower is str::to_ascii_lowercase (non-ASCII untouched —
// strings.ToLower would fold e.g. the Kelvin sign into a passing 'k').
func rtTlsCertificatesASCIILower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func rtTlsCertificatesAudit(st *AppState, r *http.Request, c *Claims, action, alias string) {
	ip := clientIP(r)
	ActivityLogActivity(r.Context(), st.DB, c.Sub, c.Email, action, new("tls_certificate"), &alias, nil, ip, c.KeyID)
	SecurityHardeningAuditLog(r.Context(), st.DB, action, &c.Email, ip, new("tls_certificate"), &alias, nil, nil, "warning", c.KeyID)
}

// POST /api/tls-certificates — register a certificate on the scoped server.
//
// Order: grammar and sizes here → the agent gate → the agent parses, matches
// the key, and writes the pair → only then the row. A refusal at any step
// leaves nothing behind on either side.
func rtTlsCertificatesCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body rtTlsCertificatesCreateCertificateRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}

	alias := rtTlsCertificatesASCIILower(strings.TrimSpace(body.Alias))
	if !rtTlsCertificatesIsValidCertAlias(alias) {
		return apiErr(http.StatusBadRequest,
			"Alias must be 1-64 lowercase letters, digits or hyphens, starting and ending with a letter or digit")
	}
	if err := rtTlsCertificatesCheckPemSizes(body.Certificate, body.PrivateKey); err != nil {
		return err
	}

	// Asked BEFORE the agent writes anything. The unique key on the INSERT
	// below is the backstop for a race, not the door: a 409 that had already
	// put a pair on the disk would describe something other than what happened.
	taken, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB,
		"SELECT id FROM tls_certificates WHERE server_id = $1 AND alias = $2", serverID, alias)
	if err != nil {
		return internalError("create tls certificate", err)
	}
	if taken != nil {
		return apiErr(http.StatusConflict, fmt.Sprintf("a certificate named %s is already registered on this server", alias))
	}

	if err := rtTlsCertificatesRequireAgentAtLeast(r.Context(), agent, rtTlsCertificatesProvidedTlsMinAgent, "Registering a certificate"); err != nil {
		return err
	}

	uploaded, err := agent.Post(r.Context(), "/ssl/registry", map[string]any{
		"alias":       alias,
		"certificate": body.Certificate,
		"private_key": body.PrivateKey,
		"replace":     false,
		"must_cover":  []any{},
	})
	if err != nil {
		return agentError("Certificate registration", err)
	}
	meta := rtTlsCertificatesReadAgentMetadata(uploaded)
	if meta.CertPath == nil || meta.KeyPath == nil {
		return apiErr(http.StatusBadGateway, "The agent registered the certificate but did not report where it wrote it")
	}

	row, err := queryOne[rtTlsCertificatesTlsCertificate](r.Context(), st.DB,
		"INSERT INTO tls_certificates (user_id, server_id, alias, dns_names, issuer, not_before, "+
			"not_after, fingerprint_sha256, cert_path, key_path) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) "+
			"RETURNING id, user_id, server_id, alias, dns_names, issuer, not_before, not_after, "+
			"fingerprint_sha256, cert_path, key_path, created_at, updated_at",
		c.Sub, serverID, alias, meta.DNSNames, meta.Issuer, meta.NotBefore, meta.NotAfter,
		meta.FingerprintSHA256, *meta.CertPath, *meta.KeyPath)
	if err != nil {
		// The agent only reaches this point for a NEW alias on its disk, so a
		// unique violation here means the panel row exists without the pair
		// having been on disk — a registry entry removed by hand. Name it.
		if strings.Contains(err.Error(), "tls_certificates_server_id_alias_key") {
			return apiErr(http.StatusConflict, fmt.Sprintf("a certificate named %s is already registered on this server", alias))
		}
		return internalError("create tls certificate", err)
	}

	rtTlsCertificatesAudit(st, r, c, "tls_certificate.create", row.Alias)

	writeJSON(w, http.StatusCreated, rtTlsCertificatesCertJSON(row, nil))
	return nil
}

type rtTlsCertificatesReplaceCertificateRequest struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

// PUT /api/tls-certificates/{id} — replace the pair behind an alias.
//
// must_cover carries every domain a stack currently serves under this alias,
// so a renewal that dropped a name is refused BEFORE the old pair is
// overwritten — the agent checks coverage first and writes nothing on a refusal.
func rtTlsCertificatesReplace(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtTlsCertificatesReplaceCertificateRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}
	if err := rtTlsCertificatesCheckPemSizes(body.Certificate, body.PrivateKey); err != nil {
		return err
	}

	row, err := rtTlsCertificatesOwnedCertificate(r.Context(), st.DB, id, c.Sub)
	if err != nil {
		return err
	}
	inUseBy, err := rtTlsCertificatesReferencingStacks(r.Context(), st.DB, row.ID)
	if err != nil {
		return err
	}
	mustCover := []string{}
	for _, s := range inUseBy {
		if s.C != nil {
			mustCover = append(mustCover, *s.C)
		}
	}

	agent, err := agentForSiteServer(r.Context(), st, &row.ServerID, row.Alias)
	if err != nil {
		return err
	}
	if err := rtTlsCertificatesRequireAgentAtLeast(r.Context(), agent, rtTlsCertificatesProvidedTlsMinAgent, "Replacing a registered certificate"); err != nil {
		return err
	}

	uploaded, err := agent.Post(r.Context(), "/ssl/registry", map[string]any{
		"alias":       row.Alias,
		"certificate": body.Certificate,
		"private_key": body.PrivateKey,
		"replace":     true,
		"must_cover":  mustCover,
	})
	if err != nil {
		return agentError("Certificate replacement", err)
	}
	meta := rtTlsCertificatesReadAgentMetadata(uploaded)

	// The paths are keyed on the alias and do not move on a replace; keep the
	// stored ones unless the agent reports new ones.
	certPath, keyPath := row.CertPath, row.KeyPath
	if meta.CertPath != nil {
		certPath = *meta.CertPath
	}
	if meta.KeyPath != nil {
		keyPath = *meta.KeyPath
	}
	updated, err := queryOne[rtTlsCertificatesTlsCertificate](r.Context(), st.DB,
		"UPDATE tls_certificates SET dns_names = $1, issuer = $2, not_before = $3, not_after = $4, "+
			"fingerprint_sha256 = $5, cert_path = $6, key_path = $7, updated_at = NOW() "+
			"WHERE id = $8 "+
			"RETURNING id, user_id, server_id, alias, dns_names, issuer, not_before, not_after, "+
			"fingerprint_sha256, cert_path, key_path, created_at, updated_at",
		meta.DNSNames, meta.Issuer, meta.NotBefore, meta.NotAfter, meta.FingerprintSHA256, certPath, keyPath, row.ID)
	if err != nil {
		return internalError("replace tls certificate", err)
	}

	rtTlsCertificatesAudit(st, r, c, "tls_certificate.replace", updated.Alias)

	writeJSON(w, http.StatusOK, rtTlsCertificatesCertJSON(updated, inUseBy))
	return nil
}

// DELETE /api/tls-certificates/{id} — remove a registered certificate.
//
// Refused with a 409 naming the stacks while any still points at it: the FK is
// SET NULL, so the database would let the delete through and the next redeploy
// of those stacks would find no certificate to serve. The agent's own 409 (a
// vhost on disk still references the directory) passes through the same way.
func rtTlsCertificatesRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(c.Role); err != nil {
		return err
	}

	row, err := rtTlsCertificatesOwnedCertificate(r.Context(), st.DB, id, c.Sub)
	if err != nil {
		return err
	}
	inUseBy, err := rtTlsCertificatesReferencingStacks(r.Context(), st.DB, row.ID)
	if err != nil {
		return err
	}
	if len(inUseBy) > 0 {
		names := make([]string, 0, len(inUseBy))
		for _, s := range inUseBy {
			names = append(names, s.B)
		}
		return apiErr(http.StatusConflict, fmt.Sprintf(
			"Certificate %s is still used by %d stack(s): %s. Change their TLS mode or "+
				"certificate first.", row.Alias, len(names), strings.Join(names, ", ")))
	}

	// Same refusal for nginx stream TCP proxies: their server{} files carry
	// ssl_certificate paths into this directory, and deleting the pair under a
	// live listener makes the NEXT `nginx -t` on the box fail — every vhost
	// write, not just this proxy's.
	proxyRefs, err := queryAll[string](r.Context(), st.DB,
		"SELECT name FROM tcp_proxies WHERE certificate_id = $1 ORDER BY name", row.ID)
	if err != nil {
		return internalError("tls certificate tcp proxy references", err)
	}
	if len(proxyRefs) > 0 {
		return apiErr(http.StatusConflict, fmt.Sprintf(
			"Certificate %s is still used by %d TCP proxy listener(s): %s. Remove them or "+
				"disable remote access first.", row.Alias, len(proxyRefs), strings.Join(proxyRefs, ", ")))
	}

	agent, err := agentForSiteServer(r.Context(), st, &row.ServerID, row.Alias)
	if err != nil {
		return err
	}
	if _, err := agent.Delete(r.Context(), "/ssl/registry/"+row.Alias); err != nil {
		var ae *AgentError
		if errors.As(err, &ae) && ae.Kind == AgentErrStatus && ae.Code == 404 {
			// The pair is already gone from the disk — removed by hand, or the
			// box was reinstalled. The row is the only thing left to clear, and
			// refusing to clear it would make this certificate undeletable for ever.
			slog.Warn(fmt.Sprintf("Certificate %s was not on the agent's disk; removing the row alone", row.Alias))
		} else {
			return agentError("Certificate removal", err)
		}
	}

	if _, err := execSQL(r.Context(), st.DB, "DELETE FROM tls_certificates WHERE id = $1", row.ID); err != nil {
		return internalError("delete tls certificate", err)
	}

	rtTlsCertificatesAudit(st, r, c, "tls_certificate.delete", row.Alias)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "alias": row.Alias})
	return nil
}
