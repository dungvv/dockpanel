package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func secWrite(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func secRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ── parse/modify sshd config (Include-blindness) ──

func TestSecurityParseSshConfigReadsPlainMainFile(t *testing.T) {
	main := filepath.Join(t.TempDir(), "sshd_config")
	secWrite(t, main, "Port 2222\nPasswordAuthentication no\nPermitRootLogin no\n")
	port, pw, root := securityParseSshConfigAt(main)
	if port != 2222 || pw || root {
		t.Fatalf("got %d %v %v", port, pw, root)
	}
}

// Include appears BEFORE the main file's commented `#Port 22` and a drop-in
// sets the real value; "first obtained value wins".
func TestSecurityParseSshConfigIncludeDropInWinsOverLaterMainDefault(t *testing.T) {
	dir := t.TempDir()
	drop := filepath.Join(dir, "sshd_config.d")
	os.MkdirAll(drop, 0o755)
	secWrite(t, filepath.Join(drop, "port.conf"), "Port 1571\n")
	main := filepath.Join(dir, "sshd_config")
	secWrite(t, main, "Include "+drop+"/*.conf\n\n#Port 22\n")
	if port, _, _ := securityParseSshConfigAt(main); port != 1571 {
		t.Fatalf("got %d", port)
	}
}

func TestSecurityParseSshConfigFirstIncludedFileWinsLexically(t *testing.T) {
	dir := t.TempDir()
	drop := filepath.Join(dir, "sshd_config.d")
	os.MkdirAll(drop, 0o755)
	secWrite(t, filepath.Join(drop, "20-second.conf"), "Port 4000\n")
	secWrite(t, filepath.Join(drop, "10-first.conf"), "Port 3000\n")
	main := filepath.Join(dir, "sshd_config")
	secWrite(t, main, "Include "+drop+"/*.conf\n")
	if port, _, _ := securityParseSshConfigAt(main); port != 3000 {
		t.Fatalf("got %d", port)
	}
}

// Extra: a relative Include resolves against the main file's directory.
func TestSecurityParseSshConfigRelativeInclude(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "d"), 0o755)
	secWrite(t, filepath.Join(dir, "d", "a.conf"), "PermitRootLogin no\n")
	main := filepath.Join(dir, "sshd_config")
	secWrite(t, main, "include\td/*.conf\nPermitRootLogin yes\n")
	if _, _, root := securityParseSshConfigAt(main); root {
		t.Fatal("drop-in must win")
	}
}

func TestSecurityParseSshConfigMissingMainFileReturnsDefaults(t *testing.T) {
	port, pw, root := securityParseSshConfigAt(filepath.Join(t.TempDir(), "does-not-exist"))
	if port != 22 || !pw || !root {
		t.Fatalf("got %d %v %v", port, pw, root)
	}
}

func TestSecurityModifySshdConfigWritesToTheFileThatActuallyGovernsTheKey(t *testing.T) {
	dir := t.TempDir()
	drop := filepath.Join(dir, "sshd_config.d")
	os.MkdirAll(drop, 0o755)
	portConf := filepath.Join(drop, "port.conf")
	secWrite(t, portConf, "Port 1571\n")
	main := filepath.Join(dir, "sshd_config")
	secWrite(t, main, "Include "+drop+"/*.conf\n\n#Port 22\n")
	if err := securityModifySshdConfigAt(main, "Port", "2022"); err != nil {
		t.Fatal(err)
	}
	if c := secRead(t, portConf); !strings.Contains(c, "Port 2022") {
		t.Fatalf("must edit the governing drop-in, got %q", c)
	}
	if c := secRead(t, main); !strings.Contains(c, "#Port 22") {
		t.Fatalf("main's commented default must be untouched, got %q", c)
	}
	if port, _, _ := securityParseSshConfigAt(main); port != 2022 {
		t.Fatalf("effective port %d", port)
	}
}

func TestSecurityModifySshdConfigFallsBackToMainFileWhenNothingGovernsTheKey(t *testing.T) {
	main := filepath.Join(t.TempDir(), "sshd_config")
	secWrite(t, main, "# nothing here\n")
	if err := securityModifySshdConfigAt(main, "PermitRootLogin", "no"); err != nil {
		t.Fatal(err)
	}
	if c := secRead(t, main); !strings.Contains(c, "PermitRootLogin no") {
		t.Fatal(c)
	}
}

func TestSecurityModifySshdConfigReplacesActiveDirectiveInGoverningFileNotMain(t *testing.T) {
	dir := t.TempDir()
	drop := filepath.Join(dir, "sshd_config.d")
	os.MkdirAll(drop, 0o755)
	pwConf := filepath.Join(drop, "50-cloud-init.conf")
	secWrite(t, pwConf, "PasswordAuthentication no\n")
	main := filepath.Join(dir, "sshd_config")
	secWrite(t, main, "Include "+drop+"/*.conf\n")
	if err := securityModifySshdConfigAt(main, "PasswordAuthentication", "yes"); err != nil {
		t.Fatal(err)
	}
	if c := secRead(t, pwConf); !strings.Contains(c, "PasswordAuthentication yes") {
		t.Fatal(c)
	}
	if c := secRead(t, main); strings.Contains(c, "PasswordAuthentication") {
		t.Fatal("must not append a shadowed directive into main")
	}
}

func TestSecurityModifySshdConfigMissingMainFails(t *testing.T) {
	if err := securityModifySshdConfigAt(filepath.Join(t.TempDir(), "nope"), "Port", "22"); err == nil {
		t.Fatal("expected error")
	}
}

// ── firewalld rich-rule helpers ──

func TestSecurityRichRuleSpecMatchesWhatParseRichRuleDisplayReadsBack(t *testing.T) {
	to, action, from := securityParseRichRuleDisplay(FirewallRichRuleSpec("8080", "tcp", "deny", ""))
	if to != "8080/tcp" || action != "DENY IN" || from != "Anywhere" {
		t.Fatal(to, action, from)
	}
	to, action, from = securityParseRichRuleDisplay(FirewallRichRuleSpec("22", "tcp", "allow", "10.0.0.5"))
	if to != "22/tcp" || action != "ALLOW IN" || from != "10.0.0.5" {
		t.Fatal(to, action, from)
	}
}

func TestSecurityRichRuleSpecPicksIpv6FamilyFromAColonAddress(t *testing.T) {
	if s := FirewallRichRuleSpec("443", "tcp", "deny", "fd00::1"); !strings.Contains(s, `family="ipv6"`) {
		t.Fatal(s)
	}
}

// ── extra coverage ──

func TestSecurityParseUfwStatus(t *testing.T) {
	st := securityParseUfwStatus("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n" +
		"To                         Action      From\n--                         ------      ----\n" +
		"22/tcp                     ALLOW IN    Anywhere\n80/tcp                     ALLOW IN    192.168.1.0/24\n" +
		"443                        DENY        Anywhere\n22/tcp (v6)                ALLOW IN    Anywhere (v6)\n")
	if !st.Active || st.DefaultPolicy != "deny (incoming), allow (outgoing), disabled (routed)" || len(st.Rules) != 3 {
		t.Fatalf("%+v", st)
	}
	if r := st.Rules[1]; r.Number != 2 || r.To != "80/tcp" || r.Action != "ALLOW IN" || r.From != "192.168.1.0/24" {
		t.Fatalf("%+v", r)
	}
	if r := st.Rules[2]; r.Action != "DENY" || r.From != "Anywhere" {
		t.Fatalf("%+v", r)
	}
	if empty := securityParseUfwStatus(""); empty.Rules == nil {
		t.Fatal("rules must serialize as [] not null")
	}
}

func TestSecurityAddFirewallRuleValidation(t *testing.T) {
	empty, bad := "", "1.2.3.4; rm -rf /"
	for _, c := range []struct {
		proto, action string
		from          *string
	}{{"tcp", "reject", nil}, {"icmp", "allow", nil}, {"tcp", "allow", &empty}, {"tcp", "allow", &bad}} {
		err := SecurityAddFirewallRule(80, c.proto, c.action, c.from)
		if err == nil || !strings.HasPrefix(err.Error(), "Invalid") {
			t.Errorf("%+v: %v", c, err)
		}
	}
	if err := SecurityRemoveFirewallRule(0); err == nil {
		t.Error("rule 0 accepted")
	}
}

func TestSecurityFail2banValidation(t *testing.T) {
	for _, j := range []string{"ssh d", "a;b", "../x", "jail\n"} {
		if securityValidJail(j) {
			t.Errorf("jail %q accepted", j)
		}
	}
	for _, ip := range []string{"", "1.2.3.4 ", "1.2.3.4/24", "-h", "a::1"} {
		if securityValidBanIP(ip) {
			t.Errorf("ip %q accepted", ip)
		}
	}
	if !securityValidJail("nginx-http_auth") || !securityValidBanIP("2001:4860::8888") /* hex-letter IPv6 is refused, as in Rust */ {
		t.Error("valid input rejected")
	}
	if err := SecurityFail2banBan("bad jail", "1.2.3.4"); err == nil || err.Error() != "Invalid jail name" {
		t.Error(err)
	}
	if _, err := SecurityFail2banBannedIps("x;y"); err == nil {
		t.Error("bad jail accepted")
	}
}

func TestSecurityParseLoginAudit(t *testing.T) {
	got := securityParseLoginAudit([]string{
		"Mar 18 12:34:56 host sshd[1]: Accepted publickey for alice from 1.2.3.4 port 5678 ssh2",
		"Mar 18 12:35:00 host sshd[2]: Failed password for invalid user admin from 5.6.7.8 port 22",
		"Mar 18 12:36:00 host CRON[3]: session opened",
	})
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if g := got[0]; g.User != "admin" || g.IP != "5.6.7.8" || g.Method != "password" || g.Success || g.Time != "Mar 18 12:35:00" {
		t.Fatalf("%+v", g)
	}
	if g := got[1]; g.User != "alice" || g.IP != "1.2.3.4" || g.Method != "publickey" || !g.Success {
		t.Fatalf("%+v", g)
	}
}

func TestSecurityApplyFixRefusals(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	secWrite(t, victim, "x")
	// A symlink whose literal path claims /var/www would still canonicalize
	// outside it; here the link lives outside too, so must be refused.
	link := filepath.Join(dir, "link")
	os.Symlink(victim, link)
	for _, c := range [][2]string{{"remove_file", link}, {"quarantine_file", victim}, {"remove_file", "/var/www/../etc/passwd"}} {
		if _, err := SecurityApplyFix(c[0], c[1]); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatal("victim was touched")
	}
	if _, err := SecurityApplyFix("nope", ""); err == nil || err.Error() != "Unknown fix type: nope" {
		t.Error(err)
	}
	if _, err := SecurityApplyFix("block_port", "70000"); err == nil || err.Error() != "Invalid port" {
		t.Error(err)
	}
}
