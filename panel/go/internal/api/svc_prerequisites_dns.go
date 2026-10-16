package api

// Port of services/prerequisites/dns.rs — the DNS vertical (v2.28.0), "does
// this domain point here yet?". The prerequisite behind every HTTP-01
// certificate, and the single most common reason a new user's site doesn't work.

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// prerequisitesSplitRecordName splits a domain into the (host, apex-ish) pair
// used to spell a DNS record.
//
// Deliberately a heuristic, not a Public Suffix List lookup: the cost of being
// wrong is cosmetic. `example.co.uk` will be described as host `example` under
// `co.uk`, which is wrong — which is exactly why every result also carries the
// unambiguous `fqdn` spelling, and the copy tells the user to use whichever
// field their provider asks for.
func prerequisitesSplitRecordName(domain string) (string, string) {
	var labels []string
	for _, l := range strings.Split(domain, ".") {
		if l != "" {
			labels = append(labels, l)
		}
	}
	if len(labels) <= 2 {
		// Apex: example.com
		return "@", domain
	}
	return strings.Join(labels[:len(labels)-2], "."), strings.Join(labels[len(labels)-2:], ".")
}

// prerequisitesLooksLikeADomain rejects anything that isn't plausibly a
// hostname before we do network work.
func prerequisitesLooksLikeADomain(domain string) bool {
	if domain == "" || len(domain) > 253 || !strings.Contains(domain, ".") ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	for _, c := range domain {
		if !(c < 128 && (isASCIIAlnum(c) || c == '.' || c == '-')) {
			return false
		}
	}
	return true
}

// PrerequisitesCheckDnsPointsHere: does `domain` resolve to the address this
// panel is reachable at?
//
// Severity is assigned from *consequence*, calibrated by the s252 fresh-box audit:
//
//   - Nothing resolves → Blocking. HTTP-01 cannot possibly complete; the CA
//     has nowhere to connect. Gating here saves a guaranteed-failed order.
//   - Resolves somewhere else → Warning, NOT blocking. A Cloudflare-proxied
//     ("orange cloud") domain issued successfully, because Cloudflare forwards
//     `/.well-known/acme-challenge/` to the origin. That configuration resolves
//     to Cloudflare's addresses and is indistinguishable from "pointed at the
//     wrong server" by IP alone — blocking it would refuse a setup we have
//     direct evidence works.
func PrerequisitesCheckDnsPointsHere(ctx context.Context, domain string) PrerequisitesPrereqResult {
	check := PrerequisitesCopyDnsPointsHereCheck
	domain = strings.ToLower(strings.TrimRight(strings.TrimSpace(domain), "."))

	if !prerequisitesLooksLikeADomain(domain) {
		return check.Result(PrerequisitesCopyDnsEnterADomain, nil)
	}

	serverIP := detectPublicIPCached(ctx)
	if serverIP == "" {
		// We don't know our own address, so we cannot judge theirs. Say so
		// plainly rather than inventing a verdict.
		return check.Result(PrerequisitesCopyDnsNoPublicIp, nil)
	}

	host, apex := prerequisitesSplitRecordName(domain)
	recordType := "A"
	if ip, err := netip.ParseAddr(serverIP); err == nil && ip.Is6() {
		recordType = "AAAA"
	}
	hint := PrerequisitesNewDnsRecordHint(host, domain, recordType, serverIP, "Auto (or 300)")

	var resolved []string
	if addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain); err == nil {
		for _, a := range addrs {
			resolved = append(resolved, a.IP.String())
		}
	}

	if len(resolved) == 0 {
		return check.Result(PrerequisitesCopyDnsNotResolving, [][2]string{{"domain", domain}}).
			WithExpected(serverIP).
			WithRemediation(PrerequisitesNewRemediationDnsRecord(hint))
	}

	if slices.Contains(resolved, serverIP) {
		return check.Result(PrerequisitesCopyDnsPointsHere, [][2]string{{"domain", domain}, {"server_ip", serverIP}}).
			WithExpected(serverIP).
			WithObserved(resolved)
	}

	// An apex and a subdomain differ in the advice, not in the verdict:
	// someone pointing `www` has to edit the `www` record, and telling them to
	// point "the domain" here sends them to change the wrong one.
	outcome := PrerequisitesCopyDnsPointsElsewhere
	if host != "@" {
		outcome = PrerequisitesCopyDnsPointsElsewhereSubdomain
	}
	return check.Result(outcome, [][2]string{
		{"domain", domain},
		{"resolved", strings.Join(resolved, ", ")},
		{"server_ip", serverIP},
		{"apex", apex},
	}).
		WithExpected(serverIP).
		WithObserved(resolved).
		WithRemediation(PrerequisitesNewRemediationDnsRecord(hint))
}
