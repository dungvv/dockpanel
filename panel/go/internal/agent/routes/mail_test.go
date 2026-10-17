package routes

import (
	"strings"
	"testing"
)

// Between s268 and s270 the value on the line was inet:127.0.0.1:8891 while
// the old code matched a literal Unix socket. Whatever is there, Rspamd's
// milter must end up beside it.
func TestMailAppendsBesideWhateverMilterIsAlreadyThere(t *testing.T) {
	for _, existing := range []string{mailOpendkimMilter, "unix:opendkim/opendkim.sock", "inet:localhost:8891"} {
		cf := "mydomain = x\nsmtpd_milters = " + existing + "\nnon_smtpd_milters = " + existing + "\n"
		out, ok := mailAddMilter(cf, mailRspamdMilter)
		if !ok {
			t.Fatal("milter keys present")
		}
		for _, k := range []string{"smtpd_milters", "non_smtpd_milters"} {
			if !strings.Contains(out, k+" = "+existing+", "+mailRspamdMilter) {
				t.Errorf("got: %s", out)
			}
		}
		if !strings.HasSuffix(out, "\n") {
			t.Error("trailing newline lost")
		}
	}
}

func TestMailAddMilterIsIdempotent(t *testing.T) {
	cf := "smtpd_milters = " + mailOpendkimMilter + "\nnon_smtpd_milters = " + mailOpendkimMilter + "\n"
	once, _ := mailAddMilter(cf, mailRspamdMilter)
	twice, _ := mailAddMilter(once, mailRspamdMilter)
	if once != twice || strings.Count(twice, mailRspamdMilter) != 2 {
		t.Fatalf("once=%q twice=%q", once, twice)
	}
}

// No milter list means mail was never installed: report absence, never a
// silent no-op. Comments and lookalike keys are not the setting.
func TestMailAddMilterAbsentCommentedOrLookalikeKeys(t *testing.T) {
	for _, cf := range []string{"mydomain = example.com\n", "", "# smtpd_milters = inet:127.0.0.1:8891\n", "smtpd_milters_extra = x\n"} {
		if _, ok := mailAddMilter(cf, mailRspamdMilter); ok {
			t.Errorf("%q treated as having a milter list", cf)
		}
	}
}

func TestMailFillsAnEmptyListWithoutALeadingComma(t *testing.T) {
	out, _ := mailAddMilter("smtpd_milters =\n", mailRspamdMilter)
	if !strings.Contains(out, "smtpd_milters = "+mailRspamdMilter) || strings.Contains(out, ", ") {
		t.Fatalf("got: %s", out)
	}
}

// ── Sender identity ──

func mailTestDomain(name string, enabled bool) mailSyncDomain {
	return mailSyncDomain{Domain: name, Enabled: enabled}
}

func mailTestAccount(email string, enabled bool) mailSyncAccount {
	return mailSyncAccount{Email: email, PasswordHash: "{PLAIN}x", QuotaMb: 100, Enabled: enabled}
}

// mailOwnersOf looks a sender up the way Postfix does: full address, then @domain.
func mailOwnersOf(table, sender string) (string, bool) {
	find := func(key string) (string, bool) {
		for _, l := range strings.Split(table, "\n") {
			if k, v, ok := strings.Cut(l, "\t"); ok && k == key {
				return v, true
			}
		}
		return "", false
	}
	if v, ok := find(sender); ok {
		return v, true
	}
	if _, d, ok := strings.Cut(sender, "@"); ok {
		return find("@" + d)
	}
	return "", false
}

// An absent key is REFUSAL: the armed restriction is an allow-list.
func mailMaySendAs(table, login, sender string) bool {
	v, ok := mailOwnersOf(table, sender)
	if !ok {
		return false
	}
	for _, o := range strings.Split(v, ",") {
		if o == login {
			return true
		}
	}
	return false
}

func mailTwoTenants() mailSyncRequest {
	return mailSyncRequest{
		Domains:  []mailSyncDomain{mailTestDomain("tenant-a.com", true), mailTestDomain("tenant-b.com", true)},
		Accounts: []mailSyncAccount{mailTestAccount("sales@tenant-a.com", true), mailTestAccount("info@tenant-b.com", true)},
	}
}

func TestMailSenderLoginMap(t *testing.T) {
	two := mailTwoTenants()
	tt := mailBuildSenderLoginMap(&two)
	type c struct {
		login, sender string
		want          bool
	}
	for _, x := range []c{
		{"sales@tenant-a.com", "sales@tenant-a.com", true}, // a mailbox may send as itself
		{"info@tenant-b.com", "info@tenant-b.com", true},
		{"sales@tenant-a.com", "info@tenant-b.com", false}, // never as another tenant's domain
		{"sales@tenant-a.com", "ceo@tenant-b.com", false},
		{"info@tenant-b.com", "sales@tenant-a.com", false},
		{"sales@tenant-a.com", "no-such-mailbox@tenant-b.com", false}, // invented local part
		{"sales@tenant-a.com", "anyone@external.example", false},      // no hosted domain
		{"sales@tenant-a.com", "orders@shop.tenant-a.com", false},     // never-added subdomain
	} {
		if got := mailMaySendAs(tt, x.login, x.sender); got != x.want {
			t.Errorf("%s as %s: got %v", x.login, x.sender, got)
		}
	}
	if _, ok := mailOwnersOf(tt, "no-such-mailbox@tenant-b.com"); !ok {
		t.Error("an invented local part at a hosted domain must still be owned")
	}
	for _, s := range []string{"anyone@external.example", "orders@shop.tenant-a.com"} {
		if _, ok := mailOwnersOf(tt, s); ok {
			t.Errorf("%s must be unlisted", s)
		}
	}
}

func TestMailADomainWithNoMailboxIsOwnedByNobody(t *testing.T) {
	req := mailTwoTenants()
	req.Domains = append(req.Domains, mailTestDomain("parked.com", true))
	tt := mailBuildSenderLoginMap(&req)
	if v, _ := mailOwnersOf(tt, "anyone@parked.com"); v != mailNoAuthorisedSender {
		t.Fatalf("owner %q", v)
	}
	if mailMaySendAs(tt, "sales@tenant-a.com", "anyone@parked.com") || mailMaySendAs(tt, "info@tenant-b.com", "anyone@parked.com") {
		t.Fatal("parked domain sendable")
	}
}

func TestMailADisabledMailboxOwnsNeitherItselfNorItsDomain(t *testing.T) {
	req := mailSyncRequest{Domains: []mailSyncDomain{mailTestDomain("tenant-a.com", true)}, Accounts: []mailSyncAccount{mailTestAccount("sales@tenant-a.com", false)}}
	tt := mailBuildSenderLoginMap(&req)
	if strings.Contains(tt, "sales@tenant-a.com\tsales@tenant-a.com") {
		t.Fatal("disabled mailbox listed")
	}
	if v, _ := mailOwnersOf(tt, "sales@tenant-a.com"); v != mailNoAuthorisedSender {
		t.Fatalf("owner %q", v)
	}
}

// ends_with("@example.com") is exact-domain: the wildcard row is where a
// relaxed test would leak (found by mutation).
func TestMailASubdomainIsNotItsParentDomain(t *testing.T) {
	req := mailSyncRequest{
		Domains:  []mailSyncDomain{mailTestDomain("example.com", true), mailTestDomain("mail.example.com", true)},
		Accounts: []mailSyncAccount{mailTestAccount("a@example.com", true), mailTestAccount("b@mail.example.com", true)},
	}
	tt := mailBuildSenderLoginMap(&req)
	if mailMaySendAs(tt, "b@mail.example.com", "a@example.com") || mailMaySendAs(tt, "a@example.com", "anything@mail.example.com") ||
		mailMaySendAs(tt, "b@mail.example.com", "invented@example.com") {
		t.Fatal("subdomain crossing")
	}
}

func TestMailMailboxesWithinOneDomainMaySendAsEachOther(t *testing.T) {
	req := mailSyncRequest{Domains: []mailSyncDomain{mailTestDomain("tenant-a.com", true)},
		Accounts: []mailSyncAccount{mailTestAccount("sales@tenant-a.com", true), mailTestAccount("ceo@tenant-a.com", true)}}
	if !mailMaySendAs(mailBuildSenderLoginMap(&req), "sales@tenant-a.com", "invoices@tenant-a.com") {
		t.Fatal("same-domain send refused")
	}
}

// Every line must be key<TAB>value or postmap builds a table that takes smtpd down.
func TestMailEveryLineIsAWellFormedTwoColumnRow(t *testing.T) {
	req := mailTwoTenants()
	req.Domains = append(req.Domains, mailTestDomain("disabled.com", false))
	tt := mailBuildSenderLoginMap(&req)
	if tt == "" || strings.Contains(tt, "@disabled.com") {
		t.Fatalf("table: %q", tt)
	}
	for _, l := range strings.Split(tt, "\n") {
		cols := strings.Split(l, "\t")
		if len(cols) != 2 || cols[0] == "" || cols[1] == "" || strings.Contains(cols[1], ",,") {
			t.Errorf("bad row %q", l)
		}
	}
}

// Go-side checks of parsers the Rust file left untested.
func TestMailLocalPartAndHelpers(t *testing.T) {
	for addr, want := range map[string]bool{"a@x.com": true, "..@x.com": false, "@x.com": false, "a@": false, "a": false, ".a@x": true} {
		if mailLocalPartIsSafe(addr) != want {
			t.Errorf("%q", addr)
		}
	}
	if !mailParseDovecotV24("2.4.1 (7c1fbd5ea6)") || mailParseDovecotV24("2.3.21") || mailParseDovecotV24("") {
		t.Error("dovecot version")
	}
	if mailWebmailPortFrom(mailWebmailNginxBlock(9001)) != 9001 || mailWebmailPortFrom("") != 8888 {
		t.Error("webmail port")
	}
	if c, d, msg := mailParseRate("100/hour"); c != 100 || d != 36 || msg != "" {
		t.Error("rate")
	}
	if mailBackupEmailHint("john_x.com_1700000000.tar.gz") != "john@x.com" {
		t.Error("backup hint")
	}
	q := mailParseQueue("-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------\nA1B2C3D4E5*    1234 Mon Mar 15 10:00:00  sender@example.com\n                                         rcpt@example.org\n\n-- 1 Kbytes in 1 Request.\n")
	if len(q) != 1 || q[0].ID != "A1B2C3D4E5" || q[0].Status != "active" || q[0].Size != "1234" ||
		q[0].Sender != "sender@example.com" || q[0].ArrivalTime != "Mon Mar 15 10:00:00" ||
		q[0].Recipients != "rcpt@example.org" {
		t.Errorf("queue: %+v", q)
	}
	// Two entries, a deferral reason line, several recipients.
	q = mailParseQueue("-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------\n" +
		"AAAA111111!    900 Tue Mar 16 09:00:00  a@example.com\n" +
		"(connect to mx.example.net[1.2.3.4]:25: Connection timed out)\n" +
		"                                         first.recipient@example.org\n" +
		"                                         x@y.io\n\n" +
		"BBBB222222     100 Tue Mar 16 09:01:00  b@example.com\n" +
		"                                         z@example.org\n\n-- 2 Kbytes in 2 Requests.\n")
	if len(q) != 2 || q[0].Status != "hold" || q[0].Recipients != "first.recipient@example.org, x@y.io" ||
		q[1].ID != "BBBB222222" || q[1].Status != "deferred" || q[1].Recipients != "z@example.org" {
		t.Errorf("multi-entry queue: %+v", q)
	}
}
