package api

// Port of services/prerequisites/mail.rs — the mail vertical, "will anyone
// accept mail from this domain?"
//
// What was already here, and why it wasn't enough: the old
// `GET /api/mail/domains/{id}/dns-check` verified **existence, not
// correctness**. MX passed on *any* MX (including Google Workspace — precisely
// the configuration under which this server's mail goes nowhere); SPF passed
// on any `v=spf1` string, even one ending `include:sendgrid.net -all` that
// forbids us; DKIM passed on `contains("p=")`, never compared to our key; the
// mail host's A record was not checked at all. An operator could see "All DNS
// records verified" on a domain whose mail was being rejected — a check that
// certifies the broken state.
//
// And the records we told them to create were wrong: two independent
// spellings (the DNS tab and the auto-DNS writer) disagreed on the address,
// the A name, the MX target, the SPF policy and the DKIM selector, and the
// manual one read the agent's HOSTNAME where it wanted an IP.
// PrerequisitesMailRecords is now the single source all three paths call: a
// value spelled in two places is a value that is wrong in one of them.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// PrerequisitesDefaultDkimSelector is the DKIM selector DockPanel uses when a
// domain doesn't record its own.
const PrerequisitesDefaultDkimSelector = "dockpanel"

// PrerequisitesMailDkimTxtValue turns a stored DKIM public key (PEM) into its
// DNS TXT value.
func PrerequisitesMailDkimTxtValue(publicKeyPEM string) string {
	r := strings.NewReplacer("-----BEGIN PUBLIC KEY-----", "", "-----END PUBLIC KEY-----", "", "\n", "", "\r", "")
	return "v=DKIM1; k=rsa; p=" + r.Replace(publicKeyPEM)
}

// PrerequisitesMailRecords is the complete set of DNS records a mail domain
// needs, values filled in.
//
// THE single source of truth: the DNS tab renders this, the auto-DNS writer
// publishes this, and PrerequisitesCheckMailDnsPublished verifies this.
// serverIP must be a real address, never the agent's hostname.
//
// Why the mail host is the apex and not `mail.<domain>`: it is what this
// product deploys. The auto-DNS writer publishes `A <domain>` and
// `MX <domain> → <domain>`, so describing a different topology would report
// every auto-configured domain as broken; and auto-SSL issues a certificate
// for `<domain>` over HTTP-01, which needs the apex A record. Postfix's
// `myhostname` is never pinned, so neither topology is enforced by the mail
// stack — which is why the check accepts both while we only ever *advise* one.
func PrerequisitesMailRecords(domain, selector string, dkimPublicKey *string, serverIP string) []PrerequisitesDnsRecordHint {
	records := []PrerequisitesDnsRecordHint{
		PrerequisitesNewDnsRecordHint("@", domain, "A", serverIP, "300").
			WithPurpose("The address other mail servers connect to. Must not be proxied."),
		PrerequisitesNewDnsRecordHint("@", domain, "MX", "10 "+domain, "300").
			WithPurpose("Where mail for this domain is delivered."),
		PrerequisitesNewDnsRecordHint("@", domain, "TXT", fmt.Sprintf("v=spf1 a mx ip4:%s ~all", serverIP), "300").
			WithPurpose("SPF — authorises this server to send mail for the domain."),
		PrerequisitesNewDnsRecordHint("_dmarc", "_dmarc."+domain, "TXT",
			"v=DMARC1; p=quarantine; rua=mailto:postmaster@"+domain, "300").
			WithPurpose("DMARC — tells receivers what to do when SPF or DKIM fails."),
	}
	if dkimPublicKey != nil && strings.TrimSpace(*dkimPublicKey) != "" {
		records = append(records, PrerequisitesNewDnsRecordHint(
			selector+"._domainkey", selector+"._domainkey."+domain, "TXT",
			PrerequisitesMailDkimTxtValue(*dkimPublicKey), "300").
			WithPurpose("DKIM — the public key receivers use to verify our signature."))
	}
	return records
}

// prerequisitesMailRecordSatisfies: whether a published value satisfies the
// record we asked for.
//
// Deliberately looser than equality for the *policy* records, and strict for
// the *key* record. `v=spf1 a mx ip4:1.2.3.4 include:sendgrid.net -all` is a
// better SPF record than the one we suggest, and reporting it as missing would
// be wrong and infuriating. But a DKIM record carrying somebody else's key is
// not a stricter setup, it is a broken one — exactly what `contains("p=")`
// could not tell apart.
func prerequisitesMailRecordSatisfies(expected *PrerequisitesDnsRecordHint, found, serverIP string) bool {
	found = prerequisitesMailStripQuotes(found)
	expectedValue := strings.TrimSpace(expected.Value)
	last := func(s string) (string, bool) {
		f := strings.Fields(s)
		if len(f) == 0 {
			return "", false
		}
		return f[len(f)-1], true
	}

	switch {
	case expected.RecordType == "A":
		return found == expectedValue
	case expected.RecordType == "MX":
		// Any MX naming this server counts, whatever its preference — a backup
		// MX at a different priority is a valid setup, not a fault.
		//
		// `mail.<domain>` is accepted alongside the apex we advise. Not laxity:
		// the DNS tab told people to use it for years, it is conventional, and
		// it works — Postfix accepts mail for any virtual domain regardless of
		// the MX hostname, provided it resolves here.
		apex, _ := last(expectedValue)
		apex = strings.TrimRight(apex, ".")
		h, ok := last(found)
		if !ok {
			return false
		}
		h = strings.TrimRight(h, ".")
		return prerequisitesMailEqASCIIFold(apex, h) || prerequisitesMailEqASCIIFold("mail."+apex, h)
	case expected.RecordType == "TXT" && strings.HasPrefix(expectedValue, "v=spf1"):
		if !strings.HasPrefix(found, "v=spf1") {
			return false
		}
		if strings.Contains(found, serverIP) {
			return true
		}
		// `a`/`mx` authorise us indirectly and `include:` delegates to a
		// provider; we cannot resolve the operator's full intent, so accept
		// them rather than cry wolf.
		for _, m := range strings.Fields(found) {
			if m == "a" || m == "mx" || strings.HasPrefix(m, "include:") {
				return true
			}
		}
		return false
	case expected.RecordType == "TXT" && strings.HasPrefix(expectedValue, "v=DMARC1"):
		return strings.HasPrefix(found, "v=DMARC1")
	case expected.RecordType == "TXT" && strings.HasPrefix(expectedValue, "v=DKIM1"):
		// Compare key material only, ignoring the whitespace and quoting that
		// providers introduce when splitting long TXT strings.
		squash := func(s string) string {
			return strings.Map(func(r rune) rune {
				if unicode.IsSpace(r) || r == '"' {
					return -1
				}
				return r
			}, s)
		}
		want := squash(expectedValue)
		key := want
		if parts := strings.Split(want, "p="); len(parts) > 1 {
			key = parts[1]
		}
		return key != "" && strings.Contains(squash(found), key)
	default:
		return found == expectedValue
	}
}

// prerequisitesMailEqASCIIFold is eq_ignore_ascii_case.
func prerequisitesMailEqASCIIFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// prerequisitesMailStripQuotes: a TXT value served in chunks arrives as
// `"part1" "part2"` — join it back before comparing, or a long DKIM key never
// matches.
func prerequisitesMailStripQuotes(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), `" "`, "")
	return strings.TrimSpace(strings.Trim(s, `"`))
}

// prerequisitesMailLookup looks one record up. ok=false means we could not
// ask — never "not published".
//
// The distinction is the whole reason for the flag: a box without `dig`
// installed would otherwise report every record as missing and send the
// operator to their registrar to re-create records that are already correct.
func prerequisitesMailLookup(ctx context.Context, record *PrerequisitesDnsRecordHint) ([]string, bool) {
	// Defence in depth. isValidDomain already guards what reaches
	// `mail_domains`, but this is callable from anywhere, and a name that dig
	// parses as an option is a command-injection primitive.
	if !rtDnsIsSafeDigArg(record.Fqdn, true) {
		return nil, false
	}
	switch record.RecordType {
	case "A", "MX", "TXT":
	default:
		return nil, false
	}
	out, err := safeCommand(ctx, "dig", "+short", "+time=3", "+tries=1", record.RecordType, record.Fqdn).Output()
	if err != nil {
		return nil, false
	}
	found := []string{}
	for _, l := range strings.Split(rtWebhookGatewayLossyUTF8(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			found = append(found, l)
		}
	}
	return found, true
}

// PrerequisitesCheckMailDnsPublished: are this mail domain's DNS records
// actually published, and do they point at *this* server?
//
// Warning, never Blocking, and that follows the governing rule rather than
// timidity: nothing in the panel is gated on this. Mail already flows without
// these records — badly. There is no control to disable, so there is nothing
// to block; what there is, is a domain quietly landing in spam folders with
// nothing anywhere in the product saying so.
func PrerequisitesCheckMailDnsPublished(ctx context.Context, domain, selector string, dkimPublicKey *string, serverIP string) PrerequisitesPrereqResult {
	check := PrerequisitesCopyMailDnsCheck
	if serverIP == "" {
		return check.Result(PrerequisitesCopyMailDnsNoPublicIp, nil)
	}

	wanted := PrerequisitesMailRecords(domain, selector, dkimPublicKey, serverIP)
	checked := make([]PrerequisitesDnsRecordHint, 0, len(wanted))
	missing := []string{}
	observed := []string{}
	unreadable := 0

	for _, record := range wanted {
		found, ok := prerequisitesMailLookup(ctx, &record)
		if !ok {
			unreadable++
			checked = append(checked, record)
			continue
		}
		present := false
		for _, f := range found {
			if prerequisitesMailRecordSatisfies(&record, f, serverIP) {
				present = true
				break
			}
		}
		if !present {
			missing = append(missing, record.RecordType+" "+record.Fqdn)
		}
		if len(found) > 0 {
			observed = append(observed, fmt.Sprintf("%s %s: %s", record.RecordType, record.Fqdn, strings.Join(found, " / ")))
		}
		checked = append(checked, record.WithPresent(present))
	}

	// Every lookup failed — that is a broken `dig`, not a broken domain.
	if unreadable == len(checked) {
		return check.Result(PrerequisitesCopyMailDnsUnreadable, nil).
			WithRemediation(PrerequisitesNewRemediationDnsRecords(checked))
	}

	if len(missing) == 0 {
		return check.Result(PrerequisitesCopyMailDnsAllPublished, [][2]string{{"domain", domain}}).
			WithObserved(observed)
	}

	outcome := PrerequisitesCopyMailDnsMissingSome
	if len(missing) == len(checked) {
		outcome = PrerequisitesCopyMailDnsMissingAll
	}
	return check.Result(outcome, [][2]string{
		{"domain", domain},
		{"count", strconv.Itoa(len(missing))},
		{"total", strconv.Itoa(len(checked))},
		{"missing", strings.Join(missing, ", ")},
	}).
		WithExpected(serverIP).
		WithObserved(observed).
		WithRemediation(PrerequisitesNewRemediationDnsRecords(checked))
}

// PrerequisitesMailCheckDkimKeyPresent: a domain whose DKIM keys never
// generated can't sign anything.
//
// Surfaced separately because the fix is different in kind: an action in
// DockPanel, not a record at the registrar. Domain creation logs a warning
// and stores the domain anyway when generation fails, so this state is
// reachable and otherwise invisible.
func PrerequisitesMailCheckDkimKeyPresent(domain string, dkimPublicKey *string) PrerequisitesPrereqResult {
	outcome := PrerequisitesCopyMailDkimMissing
	if dkimPublicKey != nil && strings.TrimSpace(*dkimPublicKey) != "" {
		outcome = PrerequisitesCopyMailDkimReady
	}
	return PrerequisitesCopyMailDkimCheck.Result(outcome, [][2]string{{"domain", domain}})
}

// PrerequisitesMailEvaluate evaluates the mail prerequisites for one domain.
func PrerequisitesMailEvaluate(ctx context.Context, domain, selector string, dkimPublicKey *string, serverIP string) []PrerequisitesPrereqResult {
	return []PrerequisitesPrereqResult{
		PrerequisitesMailCheckDkimKeyPresent(domain, dkimPublicKey),
		PrerequisitesCheckMailDnsPublished(ctx, domain, selector, dkimPublicKey, serverIP),
	}
}
