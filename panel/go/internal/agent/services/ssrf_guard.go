// SSRF guard for `repo_url` at the point this process actually dials it.
//
// The panel backend checks the same class of URL, but on the PANEL host at
// write time. A git deploy's repo_url is stored, then dialed later by THIS
// process on a DIFFERENT host via a plain `git clone`/`git fetch`
// subprocess, so a DNS answer that differs between the two vantage points
// sails through the panel's check. A subprocess has no hook to pin the
// resolved IP, so the best available guard is resolve-then-check right before
// the spawn — same accepted residual (a same-host, same-instant TOCTOU window
// is far narrower than the unbounded cross-host gap this closes).
//
// Ported from panel/backend helpers.rs; keep the internal-address rule set in
// sync with it.
package services

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ssrfGuardV4IsInternal: loopback / private / link-local / unspecified /
// broadcast / the metadata block (169.x) / CGNAT (100.64.0.0/10).
func ssrfGuardV4IsInternal(o [4]byte) bool {
	return o[0] == 127 || // loopback
		o[0] == 10 || (o[0] == 172 && o[1]&0xf0 == 16) || (o[0] == 192 && o[1] == 168) || // private
		o == [4]byte{} || o == [4]byte{255, 255, 255, 255} ||
		o[0] == 169 || // link-local/metadata block (broad; matches the original guard)
		(o[0] == 100 && o[1]&0xC0 == 0x40) // CGNAT
}

// ssrfGuardV6IsInternal: loopback / unspecified / ULA (fc00::/7) /
// link-local (fe80::/10), OR an internal IPv4 embedded via a transition
// mechanism (IPv4-mapped, NAT64 well-known, IPv4-compatible, 6to4).
func ssrfGuardV6IsInternal(b [16]byte) bool {
	var seg [8]uint16
	for i := range seg {
		seg[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	if b == [16]byte{} || b == [16]byte{15: 1} { // :: and ::1
		return true
	}
	low := [4]byte{b[12], b[13], b[14], b[15]}
	zero1to4 := seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0
	isMapped := seg[0] == 0 && zero1to4 && seg[5] == 0xffff
	isNat64 := seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0
	isV4Compat := seg[0] == 0 && zero1to4 && seg[5] == 0
	if (isMapped || isNat64 || isV4Compat) && ssrfGuardV4IsInternal(low) {
		return true
	}
	if seg[0] == 0x2002 && ssrfGuardV4IsInternal([4]byte{b[2], b[3], b[4], b[5]}) {
		return true
	}
	return seg[0]&0xfe00 == 0xfc00 || seg[0]&0xffc0 == 0xfe80
}

func ssrfGuardIPIsInternal(ip netip.Addr) bool {
	if ip.Is4() {
		return ssrfGuardV4IsInternal(ip.As4())
	}
	return ssrfGuardV6IsInternal(ip.As16())
}

// ssrfGuardParseLegacyIPv4 accepts the inet_aton forms getaddrinfo (and so
// git) and the WHATWG URL host parser resolve but a strict parser rejects:
// 1–4 parts, each decimal / 0-octal / 0x-hex, last part filling the
// remaining bytes, one optional trailing dot (2130706433, 0177.0.0.1,
// 0x7f.1, 127.1, 127.0.0.1.). The Rust guard gets this from getaddrinfo /
// the url crate; Go's resolver does not, so it is explicit here.
func ssrfGuardParseLegacyIPv4(s string) (netip.Addr, bool) {
	s = strings.TrimSuffix(s, ".")
	parts := strings.Split(s, ".")
	if s == "" || len(parts) > 4 {
		return netip.Addr{}, false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		base, digits := 10, p
		switch {
		case len(p) > 1 && (p[:2] == "0x" || p[:2] == "0X"):
			base, digits = 16, p[2:]
			if digits == "" {
				digits = "0"
			}
		case len(p) > 1 && p[0] == '0':
			base, digits = 8, p[1:]
		}
		v, err := strconv.ParseUint(digits, base, 32)
		if p == "" || err != nil {
			return netip.Addr{}, false
		}
		vals[i] = v
	}
	var n uint64
	for i, v := range vals[:len(vals)-1] {
		if v > 255 {
			return netip.Addr{}, false
		}
		n |= v << (24 - 8*i)
	}
	last := vals[len(vals)-1]
	if last >= 1<<(8*(5-len(vals))) {
		return netip.Addr{}, false
	}
	n |= last
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), true
}

// ssrfGuardLookup is the resolver (a var so tests can stand in for DNS,
// e.g. a CNAME that lands on a private address).
var ssrfGuardLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ssrfGuardValidateHostNotInternal resolves host and rejects it if it (or
// ANY address it resolves to) is internal. port is unused by the Go resolver
// (kept for parity with the Rust signature).
func ssrfGuardValidateHostNotInternal(host string, _ uint16) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("Host is required")
	}
	bare := strings.Trim(host, "[]")
	if ip, err := netip.ParseAddr(bare); err == nil {
		if ssrfGuardIPIsInternal(ip) {
			return fmt.Errorf("Host points to a private/internal address")
		}
		return nil
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return fmt.Errorf("Host points to a local address")
	}
	var addrs []netip.Addr
	if ip, ok := ssrfGuardParseLegacyIPv4(bare); ok {
		addrs = []netip.Addr{ip} // what getaddrinfo would have returned
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var err error
		if addrs, err = ssrfGuardLookup(ctx, bare); err != nil || len(addrs) == 0 {
			return fmt.Errorf("Host could not be resolved")
		}
	}
	for _, a := range addrs {
		if ssrfGuardIPIsInternal(a.Unmap()) || ssrfGuardIPIsInternal(a) {
			return fmt.Errorf("Host resolves to a private/internal address")
		}
	}
	return nil
}

// ssrfGuardRepoURLAuthority extracts (host, port) from a repo_url in any of
// the shapes accepted: https://, http://, ssh://, and scp-like git@host:path
// (no scheme, always user git, port 22).
func ssrfGuardRepoURLAuthority(raw string) (string, uint16, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, fmt.Errorf("Repository URL is required")
	}
	if rest, ok := strings.CutPrefix(raw, "git@"); ok {
		host, _, _ := strings.Cut(rest, ":")
		host, _, _ = strings.Cut(host, "/")
		if host == "" {
			return "", 0, fmt.Errorf("Repository URL has no hostname")
		}
		return host, 22, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "", 0, fmt.Errorf("Repository URL is not valid")
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "ssh" {
		return "", 0, fmt.Errorf("Repository URL must use https, http, ssh, or git@host:path")
	}
	host := u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("Repository URL has no hostname")
	}
	port := uint16(22)
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return "", 0, fmt.Errorf("Repository URL is not valid")
		}
		port = uint16(n)
	} else if u.Scheme == "http" {
		port = 80
	} else if u.Scheme == "https" {
		port = 443
	}
	return host, port, nil
}

// SsrfGuardValidateRepoURLNotInternal is the SSRF guard for a git repo_url
// at the point THIS process is about to dial it. Call it immediately before
// spawning `git clone`/`git fetch` — not earlier — so the resolve is as close
// to the actual connection as this process can get.
func SsrfGuardValidateRepoURLNotInternal(raw string) error {
	host, port, err := ssrfGuardRepoURLAuthority(raw)
	if err != nil {
		return err
	}
	return ssrfGuardValidateHostNotInternal(host, port)
}
