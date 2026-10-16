package api

// Port of panel/backend/src/helpers.rs — shared helpers used across route
// modules and services — plus serde_json::Value accessors for agent results.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Site / stack ownership ─────────────────────────────────────────────────

// SiteCallerPredicate is the one predicate that decides whether a caller may
// act on a site. Binds $1 = site id, $2 = the caller's own id.
//
// Two ways to satisfy it: own the row, or be an administrator of the machine
// the row runs on (is_local is this box; sv.user_id a member this same admin
// registered) — it stops at the hardware the reader operates.
//
// ⚠ The admin arm reads users.role from the DATABASE, deliberately, not the
// token's claim: a JWT asserts whatever role it was minted with until it
// expires, so trusting it would leave a demoted account acting as an admin for
// the rest of its session.
const SiteCallerPredicate = "s.id = $1 AND (s.user_id = $2 OR EXISTS (" +
	"SELECT 1 FROM users u, servers sv WHERE u.id = $2 AND u.role = 'admin' " +
	"AND sv.id = s.server_id AND (sv.is_local OR sv.user_id = u.id)))"

// StackCallerPredicate is the same shape for docker_stacks (GH #64: a
// database can be owned by a stack instead of a site).
const StackCallerPredicate = "st.id = $1 AND (st.user_id = $2 OR EXISTS (" +
	"SELECT 1 FROM users u, servers sv WHERE u.id = $2 AND u.role = 'admin' " +
	"AND sv.id = st.server_id AND (sv.is_local OR sv.user_id = u.id)))"

// siteDomainForCaller resolves a site the caller may act on and returns its
// domain. It replaced six drifted private copies of one query (exactly one of
// which had become server-scoped) — a guard duplicated per module is a guard
// that gets widened in one module.
//
// ⚠ The non-admin arm must NOT become server-scoped: no non-admin owns a
// servers row, so filtering by server would hide a client's own site whenever
// it lives elsewhere, by returning empty rather than an error. And a caller's
// scope being local says nothing about where the SITE is — use
// siteAgentForCaller for anything that then talks to an agent.
func siteDomainForCaller(ctx context.Context, st *AppState, siteID uuid.UUID, c *Claims) (string, error) {
	d, err := queryScalarOpt[string](ctx, st.DB, "SELECT s.domain FROM sites s WHERE "+SiteCallerPredicate, siteID, c.Sub)
	if err != nil {
		return "", internalError("resolve site for caller", err)
	}
	if d == nil {
		return "", apiErr(http.StatusNotFound, "Site not found")
	}
	return *d, nil
}

// siteAgentForCaller resolves a site the caller may act on AND the agent for
// the host it actually runs on. "Which server did the caller select" and
// "which server is this site on" are different questions; the row is the
// authority. A host that will not resolve is REFUSED, never replaced with this
// one — substituting writes one tenant's files onto another machine.
func siteAgentForCaller(ctx context.Context, st *AppState, siteID uuid.UUID, c *Claims) (string, AgentHandle, error) {
	type row struct {
		Domain   string     `db:"domain"`
		ServerID *uuid.UUID `db:"server_id"`
	}
	r, err := queryOpt[row](ctx, st.DB, "SELECT s.domain, s.server_id FROM sites s WHERE "+SiteCallerPredicate, siteID, c.Sub)
	if err != nil {
		return "", nil, internalError("resolve site agent for caller", err)
	}
	if r == nil {
		return "", nil, apiErr(http.StatusNotFound, "Site not found")
	}
	a, err := agentForSiteServer(ctx, st, r.ServerID, r.Domain)
	if err != nil {
		return "", nil, err
	}
	return r.Domain, a, nil
}

// agentForSiteServer resolves the agent for the server a row names, refusing
// rather than substituting. The nil arm is real: a row older than the fleet
// backfill, and guessing a host for it is exactly what must not happen.
func agentForSiteServer(ctx context.Context, st *AppState, serverID *uuid.UUID, domain string) (AgentHandle, error) {
	if serverID == nil {
		slog.Warn(fmt.Sprintf("Refusing to act on %s: its row names no server", domain))
		return nil, apiErr(http.StatusConflict, "This site is not associated with a server")
	}
	a, err := st.Agents.ForServer(ctx, *serverID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Refusing to act on %s: its server %s is unreachable (%v) — acting through a different host would touch another machine's files", domain, serverID, err))
		return nil, apiErr(http.StatusBadGateway, "The server this site lives on is unreachable")
	}
	return a, nil
}

// siteIDForOwnedDomain is which of the caller's OWN sites carries domain.
//
// ⚠ NOT a claim check and must never be used as one —
// domain_claim::ensure_claimable is the single answer to "may this domain be
// taken". Owner-scoped (not SiteCallerPredicate): callers write a row onto the
// site they get back.
func siteIDForOwnedDomain(ctx context.Context, db Querier, domain string, userID uuid.UUID) *uuid.UUID {
	wanted := strings.ToLower(strings.TrimRight(strings.TrimSpace(domain), "."))
	if wanted == "" {
		return nil
	}
	id, _ := queryScalarOpt[uuid.UUID](ctx, db, "SELECT id FROM sites WHERE lower(domain) = $1 AND user_id = $2", wanted, userID)
	return id
}

// ── Suspension: the role an account gets back ──────────────────────────────
//
// Suspending overwrites users.role, the only record of what the account was,
// so the previous value is stashed in its own column (prior_role) until
// un-suspension. It used to live in users.reset_token — which the public
// password-reset flow also writes, so a suspended account could erase its own
// stash by asking for a reset. Both suspend paths go through these functions
// rather than private copies of the query.

// AssignableRoles (routes/users.rs ASSIGNABLE_ROLES) — the roles an admin may
// assign and an un-suspend may restore.
var AssignableRoles = [4]string{"admin", "reseller", "user", "client"}

// suspendAccount suspends an account, recording its role, and cuts its live
// sessions. Returns rows changed, so a caller tells "suspended" from "declined".
//
// ONE statement, deliberately: Postgres evaluates every SET right-hand side
// against the OLD row, so `prior_role = role` takes the pre-update value and
// there is no window where role is overwritten but nothing remembers it.
// `AND role <> 'suspended'` stops a re-suspend overwriting a good stash with
// the word "suspended". **Revoking sessions is part of suspending**: a token
// minted as `user` keeps saying `user` for two hours, and the billing webhook
// never revoked, so a billing suspension did nothing for up to two hours.
//
// extraPredicate is appended to the WHERE clause (the billing webhook refuses
// to touch a privileged account). It MUST be a compile-time constant — never
// anything caller-supplied (Rust enforced &'static str).
func suspendAccount(ctx context.Context, st *AppState, id uuid.UUID, extraPredicate string) (int64, error) {
	n, err := execSQL(ctx, st.DB, "UPDATE users SET prior_role = role, role = 'suspended', updated_at = NOW() "+
		"WHERE id = $1 AND role <> 'suspended'"+extraPredicate, id)
	if err != nil {
		return 0, internalError("suspend account", err)
	}
	if n > 0 {
		st.revokeAllUserSessions(ctx, id)
	}
	return n, nil
}

// roleToRestore is the pure authorisation decision of an un-suspend: nil
// means *leave the account suspended and say so* — never a default. An
// unrecognised stash (a retired role, a leftover reset-token digest) is
// treated as no stash: users.role has a CHECK constraint, and a rejected
// write is a 500 on the button an admin presses to undo their own action.
func roleToRestore(stashed *string, deny []string) *string {
	if stashed == nil || !slices.Contains(AssignableRoles[:], *stashed) || slices.Contains(deny, *stashed) {
		return nil
	}
	r := *stashed
	return &r
}

// unsuspendAccount gives back the role held before suspension, or nil when
// the account was left suspended (prior role unknown, or one deny forbids).
//
// **It never guesses.** An earlier draft fell back to the least-privileged
// role; but reseller management is scoped `AND role = 'user'`, so an account
// handed `client` drops out of its reseller's reach — there is no ordering of
// these roles that makes a guess safe. deny mirrors suspendAccount's
// predicate: the billing webhook must not RESTORE a privileged role either,
// or a webhook secret becomes a privilege-restoration primitive.
//
// Reads prior_role with a narrow SELECT, never SELECT *: User is loaded by
// thirteen queries including login, and keeping the column out of it means a
// pre-migration database degrades THIS call alone.
func unsuspendAccount(ctx context.Context, st *AppState, id uuid.UUID, deny []string) (*string, error) {
	stashed, err := queryScalarOpt[*string](ctx, st.DB, "SELECT prior_role FROM users WHERE id = $1", id)
	if err != nil {
		return nil, internalError("read prior role", err)
	}
	var s *string
	if stashed != nil {
		s = *stashed
	}
	role := roleToRestore(s, deny)
	if role == nil {
		return nil, nil
	}
	// Clear the stash in the statement that consumes it (a leftover would be
	// re-applied by a later un-suspend). `AND role = 'suspended'` makes this
	// idempotent for the billing webhook, which hears "unsuspend" whatever
	// state the account is in.
	if _, err := execSQL(ctx, st.DB, "UPDATE users SET role = $1, prior_role = NULL, updated_at = NOW() "+
		"WHERE id = $2 AND role = 'suspended'", *role, id); err != nil {
		return nil, internalError("unsuspend account", err)
	}
	return role, nil
}

// hashAgentToken is SHA-256 hex. Agent tokens are high-entropy, so no slow
// hash is needed.
func hashAgentToken(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

// cfHeaders builds Cloudflare API headers: email set → Global API Key auth
// (X-Auth-Email + X-Auth-Key), else Bearer. The stored token is encrypted at
// rest; this is the single choke point every CF caller funnels through, so it
// decrypts here (a legacy/fresh plaintext passes through unchanged).
func cfHeaders(token string, email *string) http.Header {
	token = SecretsCryptoDecryptCredentialFromEnv(token)
	h := http.Header{}
	if email != nil {
		if headerValueOK(*email) && headerValueOK(token) {
			h.Set("X-Auth-Email", *email)
			h.Set("X-Auth-Key", token)
		}
	} else if headerValueOK("Bearer " + token) {
		h.Set("Authorization", "Bearer "+token)
	}
	return h
}

// headerValueOK is HeaderValue::from_str: visible ASCII, space and tab only.
func headerValueOK(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// ── SSRF guard ─────────────────────────────────────────────────────────────

// v4IsInternal: loopback / private / link-local / CGNAT / unspecified /
// broadcast — an address an SSRF guard must reject.
func v4IsInternal(a netip.Addr) bool {
	o := a.As4()
	return o[0] == 127 || o[0] == 10 || (o[0] == 172 && o[1]&0xf0 == 16) || (o[0] == 192 && o[1] == 168) ||
		a == netip.AddrFrom4([4]byte{}) || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) ||
		o[0] == 169 || // link-local/metadata block (broad; matches the original guard)
		(o[0] == 100 && o[1]&0xc0 == 0x40) // CGNAT 100.64.0.0/10
}

// v6IsInternal: loopback / unspecified / ULA / link-local, OR an internal v4
// embedded via a transition mechanism. Four embeddings reach the same v4 and
// only ::ffff: was normalised; http://[64:ff9b::7f00:1]/ (NAT64, 127.0.0.1)
// passed until this was added:
//
//	::ffff:a.b.c.d    IPv4-mapped  — low 32 bits
//	64:ff9b::a.b.c.d  NAT64 WKP    — low 32 bits
//	::a.b.c.d         IPv4-compat  — low 32 bits (deprecated, still routed)
//	2002:a.b.c.d::/16 6to4         — bits [16..48]
func v6IsInternal(a netip.Addr) bool {
	b := a.As16()
	if a == netip.IPv6Loopback() || a == netip.IPv6Unspecified() {
		return true
	}
	low := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	zero10 := slices.Equal(b[:10], make([]byte, 10))
	mapped := zero10 && b[10] == 0xff && b[11] == 0xff
	nat64 := b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && slices.Equal(b[4:12], make([]byte, 8))
	compat := zero10 && b[10] == 0 && b[11] == 0
	if (mapped || nat64 || compat) && v4IsInternal(low) {
		return true
	}
	if b[0] == 0x20 && b[1] == 0x02 && v4IsInternal(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})) {
		return true
	}
	return b[0]&0xfe == 0xfc || (b[0] == 0xfe && b[1]&0xc0 == 0x80) // ULA fc00::/7, link-local fe80::/10
}

func ipIsInternal(a netip.Addr) bool {
	if a.Is4() {
		return v4IsInternal(a)
	}
	return v6IsInternal(a)
}

// parseIP is Rust's IpAddr::from_str: dotted-quad v4 or a v6 literal (no
// zone). "::ffff:1.2.3.4" stays a v6 address, as in Rust.
func parseIP(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a, true
}

// ipEntryCovers: a plain IP or CIDR entry covers client. Families must match;
// anything unparseable covers nothing (a typo denies rather than admits).
func ipEntryCovers(entry string, client netip.Addr) bool {
	entry = strings.TrimSpace(entry)
	n, bits, ok := strings.Cut(entry, "/")
	if !ok {
		ip, ok := parseIP(entry)
		return ok && ip == client
	}
	nw, ok := parseIP(strings.TrimSpace(n))
	b, err := strconv.ParseUint(strings.TrimSpace(bits), 10, 32)
	if !ok || err != nil || nw.Is4() != client.Is4() || b > uint64(nw.BitLen()) {
		return false
	}
	p, _ := nw.Prefix(int(b))
	return p.Contains(client)
}

// panelIPAllowed: client covered by any entry of a comma-separated panel IP
// allowlist. The caller decides what an EMPTY list means (no restriction).
func panelIPAllowed(list, client string) bool {
	c, ok := parseIP(strings.TrimSpace(client))
	if !ok {
		// No usable client address (no x-real-ip from the proxy) and a
		// non-empty allowlist: an allowlist that cannot identify the caller
		// must fail CLOSED.
		return false
	}
	for _, e := range strings.Split(list, ",") {
		if e = strings.TrimSpace(e); e != "" && ipEntryCovers(e, c) {
			return true
		}
	}
	return false
}

// validPanelIPEntry: an entry panelIPAllowed can match. Rejecting malformed
// ones at write time stops a typo silently locking every admin out.
func validPanelIPEntry(entry string) bool {
	entry = strings.TrimSpace(entry)
	n, bits, ok := strings.Cut(entry, "/")
	if !ok {
		_, ok := parseIP(entry)
		return ok
	}
	ip, ok := parseIP(strings.TrimSpace(n))
	b, err := strconv.ParseUint(strings.TrimSpace(bits), 10, 32)
	return ok && err == nil && b <= uint64(ip.BitLen())
}

// hostResolvesInternalBlocking: a redirect target is internal (literal IP,
// localhost, or resolving to any internal IP). Fails CLOSED: an unresolvable
// target is treated as internal so a redirect is never followed blindly.
func hostResolvesInternalBlocking(host string, port uint16) bool {
	h := strings.Trim(host, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip, ok := parseIP(h); ok {
		return ipIsInternal(ip)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", h)
	if err != nil {
		return true
	}
	for _, a := range addrs {
		if ipIsInternal(a.Unmap()) || ipIsInternal(a) {
			return true
		}
	}
	return false
}

// lookupValidated resolves bare and rejects the whole name when ANY address
// is internal (split-horizon / rebind).
func lookupValidated(ctx context.Context, bare string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", bare)
	if err != nil || len(addrs) == 0 {
		return nil, errors.New("unresolved")
	}
	for _, a := range addrs {
		if ipIsInternal(a) {
			return nil, errors.New("internal")
		}
	}
	return addrs, nil
}

// validateURLNotInternal is the SSRF guard for operator-supplied URLs.
//
// Parsed rather than string-sliced: the old "strip scheme, cut at / then :"
// extracted the WRONG host from a userinfo authority — for
// http://example.com:x@169.254.169.254/ it tested example.com while every
// client connects to 169.254.169.254. A real parse also normalises alternate
// IPv4 encodings (2130706433, 0x7f000001, octal), so a literal host is
// authoritative and never depends on the resolver agreeing.
func validateURLNotInternal(ctx context.Context, rawURL string) error {
	// urlAuthority decides WHAT host to check — the one a client would dial;
	// everything below only decides whether it is internal.
	host, _, err := urlAuthority(rawURL)
	if err != nil {
		return err
	}
	bare := strings.Trim(host, "[]")
	if ip, ok := parseIP(bare); ok {
		if ipIsInternal(ip) {
			return errors.New("URL points to a private/internal address")
		}
		return nil
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return errors.New("URL points to a local address")
	}
	if _, err := lookupValidated(ctx, host); err != nil {
		if err.Error() == "internal" {
			return errors.New("URL resolves to a private/internal address")
		}
		return errors.New("URL hostname could not be resolved")
	}
	return nil
}

// validateHostNotInternal is the guard for a BARE host (tcp/ping monitors):
// without it a tcp monitor at 10.0.0.1:3306 is an internal port scanner the
// HTTP lane already forbids. Same address set as validateURLNotInternal.
func validateHostNotInternal(ctx context.Context, host string, port uint16) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("Host is required")
	}
	bare := strings.Trim(host, "[]")
	if ip, ok := parseIP(bare); ok {
		if ipIsInternal(ip) {
			return errors.New("Host points to a private/internal address")
		}
		return nil
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return errors.New("Host points to a local address")
	}
	if _, err := lookupValidated(ctx, bare); err != nil {
		if err.Error() == "internal" {
			return errors.New("Host resolves to a private/internal address")
		}
		return errors.New("Host could not be resolved")
	}
	return nil
}

// resolveAllValidated returns EVERY address DNS answers for host after
// rejecting the whole name if any is internal — the shared core of
// resolveValidated and validatingDialContext, so the rule lives once.
func resolveAllValidated(ctx context.Context, host string) ([]netip.Addr, error) {
	bare := strings.Trim(host, "[]")
	if ip, ok := parseIP(bare); ok {
		if ipIsInternal(ip) {
			return nil, errors.New("points to a private/internal address")
		}
		return []netip.Addr{ip}, nil
	}
	lower := strings.ToLower(bare)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return nil, errors.New("points to a local address")
	}
	addrs, err := lookupValidated(ctx, bare)
	if err != nil {
		if err.Error() == "internal" {
			return nil, errors.New("resolves to a private/internal address")
		}
		return nil, errors.New("hostname could not be resolved")
	}
	return addrs, nil
}

// resolveValidated resolves host:port, checked like the validators above,
// and returns the ONE address that check approved — so the caller dials THAT
// address instead of resolving again. Check-then-reconnect let a rebinding
// (or very low TTL) DNS answer differently between guard and connection.
func resolveValidated(ctx context.Context, host string, port uint16) (netip.AddrPort, error) {
	addrs, err := resolveAllValidated(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addrs[0], port), nil
}

// validatingDialContext (Rust ValidatingResolver) makes validation and
// resolution the same lookup for EVERY connection, redirect hops included —
// pinning one hostname cannot cover a redirect to a different host. Use it
// as an http.Transport's DialContext.
func validatingDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := resolveAllValidated(ctx, host)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New(err.Error())}
	}
	var d net.Dialer
	var last error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// pinnedTransport is pinned_client: a transport whose connections to host
// are hard-pinned to the address resolveValidated just approved. The request
// keeps the original URL for Host, SNI and certificate validation — only the
// TCP destination changes. Other hosts (redirects) go through
// validatingDialContext. Build a fresh one per call: the point is that its
// answer is fixed to an address checked moments earlier.
func pinnedTransport(ctx context.Context, host string, port uint16) (*http.Transport, error) {
	ap, err := resolveValidated(ctx, host, port)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	target := net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(int(port)))
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == target {
			var d net.Dialer
			return d.DialContext(ctx, network, ap.String())
		}
		return validatingDialContext(ctx, network, addr)
	}
	return tr, nil
}

// whatwgIPv4 applies the WHATWG URL host rule the Rust url crate implements
// for special schemes: a host whose last label is a number is an IPv4 address
// in any encoding (decimal, 0x hex, leading-0 octal, 1–4 parts). ok=false
// means "not an IPv4 host"; err means "ends in a number but invalid" (the url
// crate rejects the whole URL).
func whatwgIPv4(host string) (string, bool, error) {
	parts := strings.Split(host, ".")
	if parts[len(parts)-1] == "" && len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	isNum := func(s string) bool {
		if s == "" {
			return false
		}
		if h, ok := strings.CutPrefix(strings.ToLower(s), "0x"); ok {
			for _, c := range h {
				if !strings.ContainsRune("0123456789abcdef", c) {
					return false
				}
			}
			return true
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	if !isNum(last) {
		return "", false, nil
	}
	if len(parts) > 4 {
		return "", false, errors.New("bad ipv4")
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		base, digits := 10, p
		if h, ok := strings.CutPrefix(strings.ToLower(p), "0x"); ok {
			base, digits = 16, h
		} else if len(p) > 1 && p[0] == '0' {
			base, digits = 8, p[1:]
		}
		if digits == "" {
			if base == 10 {
				return "", false, errors.New("bad ipv4")
			}
			nums[i] = 0
			continue
		}
		n, err := strconv.ParseUint(digits, base, 64)
		if err != nil {
			return "", false, errors.New("bad ipv4")
		}
		nums[i] = n
	}
	for _, n := range nums[:len(nums)-1] {
		if n > 255 {
			return "", false, errors.New("bad ipv4")
		}
	}
	if nums[len(nums)-1] >= 1<<(8*(5-len(nums))) {
		return "", false, errors.New("bad ipv4")
	}
	v := nums[len(nums)-1]
	for i, n := range nums[:len(nums)-1] {
		v += n << (8 * (3 - i))
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String(), true, nil
}

// parseAuthority parses rawURL and returns (url, host as url::Url::host_str
// would render it — brackets kept on IPv6, special-scheme IPv4 normalised).
func parseAuthority(rawURL string, special bool) (*url.URL, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Opaque != "" {
		return nil, "", errors.New("invalid")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return u, "", nil
	}
	if strings.Contains(host, ":") {
		a, err := netip.ParseAddr(host)
		if err != nil || a.Zone() != "" {
			return nil, "", errors.New("invalid")
		}
		return u, "[" + a.String() + "]", nil
	}
	if special {
		if v4, ok, err := whatwgIPv4(host); err != nil {
			return nil, "", err
		} else if ok {
			host = v4
		}
	}
	if p := u.Port(); p != "" {
		if _, err := strconv.ParseUint(p, 10, 16); err != nil {
			return nil, "", errors.New("invalid")
		}
	}
	return u, host, nil
}

func portOr(u *url.URL, def uint16) uint16 {
	if p, err := strconv.ParseUint(u.Port(), 10, 16); err == nil {
		return uint16(p)
	}
	switch u.Scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return def
}

// urlAuthority returns the (host, port) a client would actually connect to —
// pure, so it is pinned by equality without a resolver. Rejects a parse
// failure, a non-http(s) scheme, and ANY credentials in the authority: the
// userinfo construct is the only thing that let client and validator disagree
// about the host, and nothing this guard protects legitimately carries one.
func urlAuthority(rawURL string) (string, uint16, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", 0, errors.New("URL is required")
	}
	u, host, err := parseAuthority(rawURL, true)
	if err != nil {
		return "", 0, errors.New("URL is not valid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", 0, errors.New("URL must use http or https")
	}
	if u.User != nil {
		return "", 0, errors.New("URL must not contain credentials")
	}
	if host == "" {
		return "", 0, errors.New("URL has no hostname")
	}
	return host, portOr(u, 80), nil
}

// repoURLAuthority is the SSRF host/port extraction for git_deploys.repo_url,
// tolerant of the two shapes urlAuthority cannot take: scp-like git@host:path
// and a userinfo authority carrying a legitimate access token
// (https://x-access-token:TOKEN@github.com/…). Schemes mirror the agent's
// is_valid_repo_url.
func repoURLAuthority(rawURL string) (string, uint16, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", 0, errors.New("Repository URL is required")
	}
	// scp-like is always git@host:path (never a port, always user "git").
	if rest, ok := strings.CutPrefix(rawURL, "git@"); ok {
		host, _, _ := strings.Cut(rest, ":")
		host, _, _ = strings.Cut(host, "/")
		if host == "" {
			return "", 0, errors.New("Repository URL has no hostname")
		}
		return host, 22, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" {
		return "", 0, errors.New("Repository URL is not valid")
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "ssh" {
		return "", 0, errors.New("Repository URL must use https, http, ssh, or git@host:path")
	}
	_, host, err := parseAuthority(rawURL, u.Scheme != "ssh")
	if err != nil {
		return "", 0, errors.New("Repository URL is not valid")
	}
	if host == "" {
		return "", 0, errors.New("Repository URL has no hostname")
	}
	// Credentials are deliberately NOT rejected (unlike urlAuthority): a
	// repo_url legitimately carries a PAT this way, and the host extracted is
	// what git clone dials either way. The url crate has no ssh default → 22.
	return host, portOr(u, 22), nil
}

// validateRepoURLNotInternal: repoURLAuthority + validateHostNotInternal, so
// the two guards agree on what "internal" means.
func validateRepoURLNotInternal(ctx context.Context, rawURL string) error {
	host, port, err := repoURLAuthority(rawURL)
	if err != nil {
		return err
	}
	return validateHostNotInternal(ctx, host, port)
}

// ── Public address ─────────────────────────────────────────────────────────

// detectPublicIP: ipify.org (5s), else the local address of a UDP "connect".
func detectPublicIP(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(b))
	}
	c, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

var publicIPCache struct {
	sync.Mutex
	ip string
	at time.Time
}

// detectPublicIPCached caches for 5 minutes: the DNS preflight runs as the
// user types a domain, and uncached a single form would issue dozens of
// external requests and get rate-limited. A failure is never cached — a blip
// would otherwise pin an empty address and silently disable every DNS check.
func detectPublicIPCached(ctx context.Context) string {
	publicIPCache.Lock()
	if publicIPCache.ip != "" && time.Since(publicIPCache.at) < 300*time.Second {
		ip := publicIPCache.ip
		publicIPCache.Unlock()
		return ip
	}
	publicIPCache.Unlock()
	ip := detectPublicIP(ctx)
	if ip != "" {
		publicIPCache.Lock()
		publicIPCache.ip, publicIPCache.at = ip, time.Now()
		publicIPCache.Unlock()
	}
	return ip
}

// publicIPForServer is the address to PUBLISH IN DNS for a resource on
// serverID. detectPublicIP is the PANEL's address; using it unconditionally
// pointed a fleet member's new site at the panel, and the delete path (which
// removes a record only when content == server_ip) left a dangling A record —
// a subdomain-takeover surface. nil (never the panel's address) when the
// host cannot be resolved: publishing is exactly where substituting another
// machine's address is confidently, externally wrong.
func publicIPForServer(ctx context.Context, db *pgxpool.Pool, serverID *uuid.UUID) *string {
	if serverID == nil {
		slog.Warn("Auto-DNS: no server recorded for this resource — refusing to publish a record rather than guessing a host")
		return nil
	}
	type row struct {
		IP      *string `db:"ip_address"`
		IsLocal bool    `db:"is_local"`
	}
	r, _ := queryOpt[row](ctx, db, "SELECT ip_address, is_local FROM servers WHERE id = $1", *serverID)
	switch {
	case r == nil:
		slog.Warn(fmt.Sprintf("Auto-DNS: server %s no longer exists — refusing to publish a record", serverID))
		return nil
	case r.IsLocal:
		// The local row often carries a LAN address (whatever the agent saw of
		// itself), so detect outbound for this box.
		if ip := detectPublicIPCached(ctx); ip != "" {
			return &ip
		}
		return nil
	case r.IP != nil && strings.TrimSpace(*r.IP) != "":
		ip := strings.TrimSpace(*r.IP)
		return &ip
	default:
		slog.Warn(fmt.Sprintf("Auto-DNS: server %s has no recorded ip_address — refusing to publish a record. The panel's own address would point this name at the wrong machine.", serverID))
		return nil
	}
}

// ── Certificates ───────────────────────────────────────────────────────────

// stripZeroOffsetSeconds rewrites a trailing +HH:MM:00 offset to +HH:MM; ok
// is false when the string doesn't end in a zero-seconds offset. Only `:00`
// is dropped, so a genuinely sub-minute offset is never silently shifted.
func stripZeroOffsetSeconds(s string) (string, bool) {
	if len(s) < 9 {
		return "", false
	}
	t := s[len(s)-9:]
	dig := func(c byte) bool { return c >= '0' && c <= '9' }
	if (t[0] == '+' || t[0] == '-') && dig(t[1]) && dig(t[2]) && t[3] == ':' && dig(t[4]) && dig(t[5]) && t[6] == ':' && t[7] == '0' && t[8] == '0' {
		return s[:len(s)-3], true
	}
	return "", false
}

// parseAgentCertExpiry parses the agent's certificate expiry string.
//
// The agent renders x509 not_after with time::OffsetDateTime's Display —
// "2026-10-23 09:41:07.0 +00:00:00", never a literal UTC. Every panel call
// site once parsed "%Y-%m-%d %H:%M:%S%.f UTC", which cannot match, so
// sites.ssl_expiry stayed NULL forever and starved the SSL countdown, the
// expiry alerts (their query needs ssl_expiry IS NOT NULL) and ARI renewal
// bookkeeping. Tolerant by design — panel and agent version separately — so
// RFC 3339 and the legacy UTC spelling are accepted too.
func parseAgentCertExpiry(raw string) *time.Time {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	norm := s
	if n, ok := stripZeroOffsetSeconds(s); ok {
		norm = n
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999999 -07:00", "2006-01-02 15:04:05 -07:00"} {
		if t, err := time.Parse(layout, norm); err == nil {
			t = t.UTC()
			return &t
		}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		t = t.UTC()
		return &t
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999999 UTC", "2006-01-02 15:04:05 UTC"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// DNS01LastResortDays: days before expiry at which a DNS-01 certificate we
// cannot re-order over DNS-01 stops being refused and is deliberately
// downgraded instead. Refusing is right while there is time to fix the cause
// and WRONG at the end: refusing to expiry takes the apex AND every sibling
// down at once, enlarging the blast radius of the defect it guards. ⚠ This is
// the DEFAULT, not the rung — see dns01LastResortDays.
const DNS01LastResortDays int64 = 7

// dns01LastResortDays is the rung for one site's ACME profile. ⚠ A single
// constant was arithmetically unreachable for `shortlived` (~160h certs, so
// days_remaining never exceeds six): the Refuse rung was dead code and every
// such site took the silent downgrade. The rung must sit STRICTLY BELOW the
// profile's renewal margin (auto_healer::fallback_renewal_margin) — read the
// two together.
func dns01LastResortDays(profile *string) int64 {
	if profile != nil && *profile == "shortlived" {
		return 1
	}
	return DNS01LastResortDays
}

// RenewalPlanKind is what a renewal door should DO, decided before any order.
type RenewalPlanKind int

const (
	// RenewHTTP01: renew over HTTP-01. RecordChallenge is true when nothing
	// was recorded and this pass also writes the provenance down — what makes
	// the rule CONVERGE (absence is also what a non-wildcard DNS-01 cert looks
	// like, so requiring positive evidence is the only form that terminates).
	RenewHTTP01 RenewalPlanKind = iota
	// RenewDNS01: renew over DNS-01 against the name actually ordered.
	RenewDNS01
	// RenewRefuse: DNS-01 cert whose zone we cannot reach, time on the clock.
	RenewRefuse
	// RenewLastResortHTTP01: inside the last-resort window — downgrade on
	// purpose, record it, and say exactly what was lost (Losing), never silently.
	RenewLastResortHTTP01
)

// RenewalPlan is helpers::RenewalPlan; fields are set per Kind.
type RenewalPlan struct {
	Kind            RenewalPlanKind
	RecordChallenge bool      // RenewHTTP01
	Subject         string    // RenewDNS01
	Wildcard        bool      // RenewDNS01
	ZoneID          uuid.UUID // RenewDNS01
	Reason          string    // RenewRefuse
	Losing          string    // RenewLastResortHTTP01
}

// renewalPlan decides how site must be renewed, from what was RECORDED at
// issuance.
//
// ⚠ It deliberately does not consult the stored certificate path. "The cert
// directory is not the site's own domain" is not proof of a shared zone
// certificate: the rename rewrite is scoped to the site's own old directory
// (a wildcard child renamed out of its zone keeps naming the zone, correctly),
// and rows renamed on ≤ v2.144.x still carry a stale path whose name can be
// handed to the NEXT site that claims it. Neither shape is distinguishable in
// SQL from a genuine wildcard child; acting on it would refuse to renew
// healthy sites for ever.
func renewalPlan(ctx context.Context, db Querier, site *Site, daysRemaining *int64) RenewalPlan {
	switch {
	case site.SSLChallenge == nil:
		return RenewalPlan{Kind: RenewHTTP01, RecordChallenge: true}
	case *site.SSLChallenge == "http-01":
		return RenewalPlan{Kind: RenewHTTP01}
	}
	subject := site.Domain
	if site.SSLCertSubject != nil {
		subject = *site.SSLCertSubject
	}
	wildcard := site.SSLWildcard != nil && *site.SSLWildcard
	names := subject
	if wildcard {
		names = fmt.Sprintf("%s and *.%s", subject, subject)
	}

	// The zone that ISSUED it, never one re-derived from a text subject — that
	// could select a different tenant's Cloudflare token.
	var zone *uuid.UUID
	if site.SSLDNSZoneID != nil {
		zone, _ = queryScalarOpt[uuid.UUID](ctx, db, "SELECT id FROM dns_zones WHERE id = $1 AND provider = 'cloudflare' "+
			"AND cf_zone_id IS NOT NULL AND cf_api_token IS NOT NULL", *site.SSLDNSZoneID)
	} else {
		// Legacy row: the SITE OWNER's zones — never the actor's, never the
		// first admin's, never an unscoped domain match. Handing one admin's
		// token to a job renewing another account's site is a disclosure.
		zone, _ = queryScalarOpt[uuid.UUID](ctx, db, "SELECT id FROM dns_zones WHERE user_id = $1 AND provider = 'cloudflare' "+
			"AND cf_zone_id IS NOT NULL AND cf_api_token IS NOT NULL AND domain = $2", site.UserID, subject)
	}
	if zone != nil {
		return RenewalPlan{Kind: RenewDNS01, Subject: subject, Wildcard: wildcard, ZoneID: *zone}
	}
	// No reachable zone: refuse while repairable, downgrade once it is not.
	if daysRemaining != nil && *daysRemaining <= dns01LastResortDays(site.SSLProfile) {
		return RenewalPlan{Kind: RenewLastResortHTTP01, Losing: names}
	}
	return RenewalPlan{Kind: RenewRefuse, Reason: fmt.Sprintf(
		"The certificate for %s was issued over DNS-01 and covers %s. Renewing it "+
			"needs the Cloudflare zone it was issued against, and this site's owner has "+
			"no Cloudflare zone for %s with an API token. Add it under DNS management, "+
			"or install a replacement certificate under the site's SSL tab.",
		site.Domain, names, subject)}
}

// CertProvenanceKind is what the installed certificate's issuer proves.
//
// ⛔ Three states, not an Option, because the two callers collapse the middle
// one in OPPOSITE directions. For RENEWAL, Unknown must read as "ours" (an
// unreachable agent is not evidence of a foreign cert; refusing on doubt ends
// in a lapsed certificate on a dark site). For a BADGE, Unknown reading as
// "ours" is exactly the lie — "Enabled (Let's Encrypt)" every time the agent
// hiccups, looking correct in testing because the agent is up.
type CertProvenanceKind int

const (
	// CertForeign: positive identification that somebody else issued it.
	CertForeign CertProvenanceKind = iota
	// CertDockPanelIssued: a Let's Encrypt issuer — the agent's ACME client
	// is pinned to LE production, so that is proof this product issued it.
	CertDockPanelIssued
	// CertUnknown: no answer to act on (agent silent, has_cert:false — which a
	// zone-wildcard child reports for its own name — or no issuer).
	CertUnknown
)

// CertProvenance carries the issuer string for CertForeign.
type CertProvenance struct {
	Kind   CertProvenanceKind
	Issuer string
}

// certProvenance reads provenance out of an agent /ssl/status/{domain}
// payload the caller already holds (one round trip, not two).
//
// ⚠ Recognition runs on the issuer's O= component: the agent sends the whole
// RDN ("CN=YR2, O=Let's Encrypt, C=US"). If the agent's rendering ever
// narrowed to the CN, every certificate this product issued would read as
// foreign and every renewal door would refuse.
func certProvenance(status any) CertProvenance {
	if b, _ := jsonBool(jsonGet(status, "has_cert")); !b {
		return CertProvenance{Kind: CertUnknown}
	}
	issuer, ok := jsonStr(jsonGet(status, "issuer"))
	issuer = strings.TrimSpace(issuer)
	if !ok || issuer == "" {
		return CertProvenance{Kind: CertUnknown}
	}
	l := strings.ToLower(issuer)
	// Both spellings: the apostrophe is a typographic hazard, not a fact.
	if strings.Contains(l, "let's encrypt") || strings.Contains(l, "lets encrypt") {
		return CertProvenance{Kind: CertDockPanelIssued}
	}
	return CertProvenance{Kind: CertForeign, Issuer: issuer}
}

// foreignCertIssuer is the installed cert's issuer ONLY when it proves
// DockPanel did not put it there. nil means "ours" OR "we do not know" — every
// caller must treat nil as PERMISSION TO PROCEED; refusing because a socket
// flapped ends in an expired certificate and a dark site.
func foreignCertIssuer(ctx context.Context, agent AgentHandle, domain string) *string {
	status, err := agent.Get(ctx, "/ssl/status/"+domain)
	if err != nil {
		return nil
	}
	if p := certProvenance(status); p.Kind == CertForeign {
		return &p.Issuer
	}
	return nil
}

// requireLocalAgentScope refuses, at the mint, a stream whose transport can
// only reach the panel's own agent when the caller has a different server
// selected. Terminal and log-stream tickets are signed with the SELECTED
// server's agent token, but the browser dials window.location.host and nginx
// pins that path to the LOCAL agent socket — so every fleet member failed,
// dishonestly ("Connection lost", endless retries).
//
// It deliberately does NOT proxy the stream: a backend proxy would deliver a
// member-signed ticket to the member's agent, which would honour its `domain`
// query parameter — unbound by the ticket, and empty means a root login
// shell. Removing the two things that confine that to the panel host, before
// the domain is bound into the ticket, would widen it to the whole fleet.
func requireLocalAgentScope(ctx context.Context, st *AppState, scopedServerID uuid.UUID, feature string) error {
	local := st.Agents.LocalServerID()
	if local == nil || *local == scopedServerID {
		return nil
	}
	which := scopedServerID.String()
	if name, _ := queryScalarOpt[string](ctx, st.DB, "SELECT name FROM servers WHERE id = $1", scopedServerID); name != nil {
		which = *name
	}
	return apiErr(http.StatusNotImplemented, fmt.Sprintf(
		"%s runs on the panel host only. \"%s\" is a fleet member, and the panel cannot yet stream to one. "+
			"Switch back to the panel server to use it.", feature, which))
}

// ── serde_json::Value accessors (agent results are decoded with UseNumber) ──

// jsonGet walks object keys (string) and array indices (int); nil when any
// step is absent — Value::get chained.
func jsonGet(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			a, ok := v.([]any)
			if !ok || k < 0 || k >= len(a) {
				return nil
			}
			v = a[k]
		default:
			return nil
		}
	}
	return v
}

func jsonStr(v any) (string, bool)         { s, ok := v.(string); return s, ok }
func jsonBool(v any) (bool, bool)          { b, ok := v.(bool); return b, ok }
func jsonArr(v any) ([]any, bool)          { a, ok := v.([]any); return a, ok }
func jsonObj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

// jsonI64 is Value::as_i64: integers only (a float never converts).
func jsonI64(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

// jsonU64 is Value::as_u64.
func jsonU64(v any) (uint64, bool) {
	if n, ok := v.(json.Number); ok {
		u, err := strconv.ParseUint(string(n), 10, 64)
		return u, err == nil
	}
	if i, ok := jsonI64(v); ok && i >= 0 {
		return uint64(i), true
	}
	return 0, false
}

// jsonF64 is Value::as_f64: any number.
func jsonF64(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	}
	if i, ok := jsonI64(v); ok {
		return float64(i), true
	}
	return 0, false
}
