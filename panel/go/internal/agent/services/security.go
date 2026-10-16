package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// SecurityUfwMissing is named so the route can match it instead of guessing
// at its wording. Both firewall handlers used to sort errors with ad-hoc
// substring tests, so this sentence fell to the 5xx arm and was replaced by
// an incident id. It is reachable on every RHEL-family box: rules listed from
// firewalld each get a delete button whose backing command is ufw, which the
// panel never installs there.
const SecurityUfwMissing = "ufw is not installed"

type SecurityLoginEntry struct {
	Time    string `json:"time"`
	User    string `json:"user"`
	IP      string `json:"ip"`
	Method  string `json:"method"`
	Success bool   `json:"success"`
}

type SecurityFirewallStatus struct {
	Active        bool                   `json:"active"`
	DefaultPolicy string                 `json:"default_policy"`
	Rules         []SecurityFirewallRule `json:"rules"`
}

type SecurityFirewallRule struct {
	Number int    `json:"number"`
	To     string `json:"to"`
	Action string `json:"action"`
	From   string `json:"from"`
}

type SecurityFail2banStatus struct {
	Running bool               `json:"running"`
	Jails   []SecurityJailInfo `json:"jails"`
}

type SecurityJailInfo struct {
	Name        string `json:"name"`
	BannedCount uint32 `json:"banned_count"`
}

type SecurityOverview struct {
	FirewallActive      bool   `json:"firewall_active"`
	FirewallRulesCount  int    `json:"firewall_rules_count"`
	Fail2banRunning     bool   `json:"fail2ban_running"`
	Fail2banBannedTotal uint32 `json:"fail2ban_banned_total"`
	SshPort             uint16 `json:"ssh_port"`
	SshPasswordAuth     bool   `json:"ssh_password_auth"`
	SshRootLogin        bool   `json:"ssh_root_login"`
	SslCertsCount       int    `json:"ssl_certs_count"`
}

// securityExec runs bin within d. err wraps context.DeadlineExceeded on
// timeout, and is any other error when the process could not run at all.
func securityExec(d time.Duration, bin string, args ...string) (safecmd.Output, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return safecmd.Exec(ctx, bin, args...)
}

func securityLossy(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

// Which firewall-cmd removal an entry needs, so SecurityRemoveFirewallRule
// can resolve a bare display number back to the right command — firewalld
// has no ufw-style numbered-rule identity of its own.
type securityFirewalldKind int

const (
	securityKindService securityFirewalldKind = iota
	securityKindPort
	securityKindRich // raw is the exact --list-rich-rules line, so removal round-trips
)

type securityFirewalldEntry struct {
	rule        SecurityFirewallRule
	kind        securityFirewalldKind
	name, proto string // service name / port+proto / raw rich rule (in name)
}

// securityFirewalldEntries: services, ports AND rich rules in ONE
// continuously-numbered list — the numbers the Security page shows must be
// the numbers removal resolves, or "delete rule 3" deletes the wrong thing
// the moment a rich rule exists.
func securityFirewalldEntries() []securityFirewalldEntry {
	zone := strings.TrimSpace(securityFwOut("--get-default-zone"))
	var entries []securityFirewalldEntry
	n := 0
	for _, item := range strings.Fields(securityFwOut("--zone", zone, "--list-services")) {
		n++
		entries = append(entries, securityFirewalldEntry{
			rule: SecurityFirewallRule{Number: n, To: item + " (service)", Action: "ALLOW IN", From: "Anywhere"},
			kind: securityKindService, name: item,
		})
	}
	for _, item := range strings.Fields(securityFwOut("--zone", zone, "--list-ports")) {
		n++
		port, proto, ok := strings.Cut(item, "/")
		if !ok {
			port, proto = item, "tcp"
		}
		entries = append(entries, securityFirewalldEntry{
			rule: SecurityFirewallRule{Number: n, To: item, Action: "ALLOW IN", From: "Anywhere"},
			kind: securityKindPort, name: port, proto: proto,
		})
	}
	for _, line := range LogsLines([]byte(securityFwOut("--zone", zone, "--list-rich-rules"))) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		n++
		to, action, from := securityParseRichRuleDisplay(line)
		entries = append(entries, securityFirewalldEntry{
			rule: SecurityFirewallRule{Number: n, To: to, Action: action, From: from},
			kind: securityKindRich, name: line,
		})
	}
	return entries
}

// securityParseRichRuleDisplay: display (to, action, from) for one
// --list-rich-rules line. Only understands the port+protocol(+source) shape
// FirewallRichRuleSpec writes; not a general parser.
func securityParseRichRuleDisplay(line string) (string, string, string) {
	action := "ALLOW IN"
	if strings.Contains(line, "reject") || strings.Contains(line, " drop") || strings.HasSuffix(line, "drop") {
		action = "DENY IN"
	}
	to := "(rich rule)"
	p, ok1 := securityQuotedAfter(line, `port="`)
	pr, ok2 := securityQuotedAfter(line, `protocol="`)
	if ok1 && ok2 {
		to = p + "/" + pr
	}
	from, ok := securityQuotedAfter(line, `address="`)
	if !ok {
		from = "Anywhere"
	}
	return to, action, from
}

func securityQuotedAfter(line, marker string) (string, bool) {
	i := strings.Index(line, marker)
	if i < 0 {
		return "", false
	}
	rest := line[i+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// securityFirewalldStatus reports firewalld in the ufw shape: the default
// zone's target as the policy, its services/ports/rich rules as the rules.
func securityFirewalldStatus() SecurityFirewallStatus {
	zone := strings.TrimSpace(securityFwOut("--get-default-zone"))
	target := strings.TrimSpace(securityFwOut("--zone", zone, "--get-target"))
	rules := []SecurityFirewallRule{}
	for _, e := range securityFirewalldEntries() {
		rules = append(rules, e.rule)
	}
	policy := "deny"
	if strings.EqualFold(target, "ACCEPT") {
		policy = "allow"
	}
	return SecurityFirewallStatus{
		Active:        true,
		DefaultPolicy: fmt.Sprintf("%s (incoming), allow (outgoing) — firewalld zone '%s'", policy, zone),
		Rules:         rules,
	}
}

func securityFwOut(args ...string) string {
	out, err := securityExec(30*time.Second, "firewall-cmd", args...)
	if err != nil {
		return ""
	}
	return securityLossy(out.Stdout)
}

// SecurityGetFirewallStatus is the firewall state for the Security page. It
// used to only run `ufw status verbose`, so a correctly firewalled RHEL box
// (firewalld) reported no firewall at all.
func SecurityGetFirewallStatus() (SecurityFirewallStatus, error) {
	if FirewallDetect() == FirewallFirewalld {
		return securityFirewalldStatus(), nil
	}
	out, err := securityExec(30*time.Second, "ufw", "status", "verbose")
	if err != nil {
		// ufw not installed, timed out, or errored — inactive.
		return SecurityFirewallStatus{Rules: []SecurityFirewallRule{}}, nil
	}
	return securityParseUfwStatus(securityLossy(out.Stdout)), nil
}

func securityParseUfwStatus(stdout string) SecurityFirewallStatus {
	st := SecurityFirewallStatus{Active: strings.Contains(stdout, "Status: active"), Rules: []SecurityFirewallRule{}}
	lines := LogsLines([]byte(stdout))
	// "Default: deny (incoming), allow (outgoing), disabled (routed)"
	for _, l := range lines {
		if strings.HasPrefix(l, "Default:") {
			rest := l
			for strings.HasPrefix(rest, "Default:") {
				rest = rest[len("Default:"):]
			}
			st.DefaultPolicy = strings.TrimSpace(rest)
			break
		}
	}
	// Rules follow the "--" separator line.
	inRules, n := false, 0
	for _, line := range lines {
		if strings.HasPrefix(line, "--") {
			inRules = true
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !inRules || trimmed == "" || strings.Contains(trimmed, "(v6)") { // (v6): IPv6 duplicates
			continue
		}
		n++
		//   22/tcp                     ALLOW IN    Anywhere
		//   443                        DENY IN     Anywhere
		parts := strings.Fields(trimmed)
		if len(parts) < 3 {
			continue
		}
		action, fromIdx := parts[1], 2
		if parts[2] == "IN" || parts[2] == "OUT" {
			action, fromIdx = parts[1]+" "+parts[2], 3
		}
		from := "Anywhere"
		if fromIdx < len(parts) {
			from = strings.Join(parts[fromIdx:], " ")
		}
		st.Rules = append(st.Rules, SecurityFirewallRule{Number: n, To: parts[0], Action: action, From: from})
	}
	return st
}

// SecurityAddFirewallRule adds an allow/deny rule for port/proto, optionally
// source-restricted (from != nil; an empty source is refused).
func SecurityAddFirewallRule(port uint16, proto, action string, from *string) error {
	actionLower := strings.ToLower(action)
	if actionLower != "allow" && actionLower != "deny" {
		return fmt.Errorf("Invalid action '%s': must be 'allow' or 'deny'", action)
	}
	protoLower := strings.ToLower(proto)
	if protoLower != "tcp" && protoLower != "udp" {
		return fmt.Errorf("Invalid protocol '%s': must be 'tcp' or 'udp'", proto)
	}
	// Source: ASCII alphanumerics, dots, colons, slashes only.
	if from != nil {
		ok := *from != ""
		for _, c := range *from {
			if !(c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') || c == '.' || c == ':' || c == '/') {
				ok = false
			}
		}
		if !ok {
			return fmt.Errorf("Invalid source address: %s", *from)
		}
	}
	portStr := strconv.Itoa(int(port))

	// This used to always shell to ufw, which isn't installed in the RHEL
	// family; every mutating action failed there.
	if FirewallDetect() == FirewallFirewalld {
		var ok bool
		if actionLower == "allow" && from == nil {
			ok = FirewallAddPort(portStr, protoLower)
		} else {
			src := ""
			if from != nil {
				src = *from
			}
			ok = FirewallAddRichRule(portStr, protoLower, actionLower, src)
		}
		if !ok {
			return fmt.Errorf("firewall-cmd failed to add the rule")
		}
		return nil
	}

	args := []string{actionLower}
	if from != nil {
		args = append(args, "from", *from, "to", "any", "port", portStr, "proto", protoLower)
	} else {
		args = append(args, portStr+"/"+protoLower)
	}
	out, err := securityExec(30*time.Second, "ufw", args...)
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("ufw command timed out")
	}
	if err != nil {
		return errors.New(SecurityUfwMissing)
	}
	if !out.Success() {
		return fmt.Errorf("ufw failed: %s %s", securityLossy(out.Stderr), securityLossy(out.Stdout))
	}
	return nil
}

// SecurityRemoveFirewallRule deletes a rule by its display number — the same
// number SecurityGetFirewallStatus reported.
func SecurityRemoveFirewallRule(ruleNum int) error {
	if ruleNum <= 0 {
		return fmt.Errorf("Rule number must be >= 1")
	}
	if FirewallDetect() == FirewallFirewalld {
		for _, e := range securityFirewalldEntries() {
			if e.rule.Number != ruleNum {
				continue
			}
			var ok bool
			switch e.kind {
			case securityKindService:
				ok = FirewallRemoveService(e.name)
			case securityKindPort:
				ok = FirewallRemovePort(e.name, e.proto)
			default:
				ok = FirewallRemoveRichRuleRaw(e.name)
			}
			if !ok {
				return fmt.Errorf("firewall-cmd failed to remove rule %d", ruleNum)
			}
			return nil
		}
		return fmt.Errorf("No firewall rule numbered %d", ruleNum)
	}
	out, err := securityExec(30*time.Second, "ufw", "--force", "delete", strconv.Itoa(ruleNum))
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("ufw command timed out")
	}
	if err != nil {
		return errors.New(SecurityUfwMissing)
	}
	if !out.Success() {
		return fmt.Errorf("ufw delete failed: %s %s", securityLossy(out.Stderr), securityLossy(out.Stdout))
	}
	return nil
}

// SecurityGetFail2banStatus lists active jails and their banned counts.
func SecurityGetFail2banStatus() (SecurityFail2banStatus, error) {
	out, err := securityExec(30*time.Second, "fail2ban-client", "status")
	if err != nil || !out.Success() {
		// fail2ban not installed, timed out, or not running
		return SecurityFail2banStatus{Jails: []SecurityJailInfo{}}, nil
	}
	// "`- Jail list:	sshd, nginx-http-auth"
	var names []string
	for _, l := range LogsLines(out.Stdout) {
		if _, after, ok := strings.Cut(l, "Jail list:"); ok {
			after, _, _ = strings.Cut(after, "Jail list:")
			for _, s := range strings.Split(strings.TrimSpace(after), ",") {
				if s = strings.TrimSpace(s); s != "" {
					names = append(names, s)
				}
			}
			break
		}
	}
	jails := []SecurityJailInfo{}
	for _, name := range names {
		jo, err := securityExec(10*time.Second, "fail2ban-client", "status", name)
		if errors.Is(err, context.DeadlineExceeded) {
			return SecurityFail2banStatus{}, fmt.Errorf("Jail query for %s timed out", name)
		}
		if err != nil {
			return SecurityFail2banStatus{}, fmt.Errorf("Failed to query jail %s: %v", name, err)
		}
		var banned uint32
		for _, l := range LogsLines(jo.Stdout) {
			if _, after, ok := strings.Cut(l, "Currently banned:"); ok {
				after, _, _ = strings.Cut(after, "Currently banned:")
				if v, err := strconv.ParseUint(strings.TrimSpace(after), 10, 32); err == nil {
					banned = uint32(v)
				}
				break
			}
		}
		jails = append(jails, SecurityJailInfo{Name: name, BannedCount: banned})
	}
	return SecurityFail2banStatus{Running: true, Jails: jails}, nil
}

// securityExpandIncludeArg expands one Include argument (a path, or a glob
// with one `*` in the final component) to the files it matches, sorted
// lexically — the order OpenSSH processes a glob's matches in.
func securityExpandIncludeArg(dir, arg string) []string {
	path := arg
	if !strings.HasPrefix(arg, "/") {
		path = strings.TrimSuffix(dir, "/") + "/" + arg
	}
	parent, name := filepath.Split(strings.TrimRight(path, "/"))
	if name == "" || name == ".." || name == "." {
		return nil
	}
	if !strings.Contains(name, "*") {
		if _, err := os.Stat(path); err == nil {
			return []string{path}
		}
		return nil
	}
	if parent == "" {
		parent = "./"
	}
	prefix, suffix, _ := strings.Cut(name, "*")
	ents, err := os.ReadDir(parent)
	if err != nil {
		return nil
	}
	var matches []string
	for _, e := range ents {
		f := e.Name()
		if len(f) >= len(prefix)+len(suffix) && strings.HasPrefix(f, prefix) && strings.HasSuffix(f, suffix) {
			matches = append(matches, parent+f)
		}
	}
	sort.Strings(matches)
	return matches
}

type securitySshdLine struct{ path, line string }

// securityLinearizedSshdLines returns sshd_config and its Include'd drop-ins
// in the order sshd evaluates directives: each Include is spliced in place,
// one level deep (a deeper Include falls through as an unknown line).
// OpenSSH's rule is "the first obtained value wins", so callers scan in
// order and stop at the first match per keyword — reading only the main file
// silently ignores every drop-in overriding it (cloud-init images and this
// project's own port.conf both do).
func securityLinearizedSshdLines(mainPath string) []securitySshdLine {
	content, err := os.ReadFile(mainPath)
	if err != nil {
		return nil
	}
	dir := filepath.Dir(mainPath)
	var out []securitySshdLine
	for _, line := range LogsLines(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			kw, rest := trimmed, ""
			if i := strings.IndexFunc(trimmed, unicode.IsSpace); i >= 0 {
				_, w := utf8.DecodeRuneInString(trimmed[i:])
				kw, rest = trimmed[:i], trimmed[i+w:]
			}
			if strings.EqualFold(kw, "include") {
				for _, arg := range strings.Fields(rest) {
					for _, m := range securityExpandIncludeArg(dir, arg) {
						if inc, err := os.ReadFile(m); err == nil {
							for _, l := range LogsLines(inc) {
								out = append(out, securitySshdLine{m, l})
							}
						}
					}
				}
				continue
			}
		}
		out = append(out, securitySshdLine{mainPath, line})
	}
	return out
}

// SecurityParseSshConfig reads /etc/ssh/sshd_config and its Includes:
// (port, password_auth_enabled, root_login_enabled).
func SecurityParseSshConfig() (uint16, bool, bool) {
	return securityParseSshConfigAt("/etc/ssh/sshd_config")
}

func securityParseSshConfigAt(mainPath string) (uint16, bool, bool) {
	port, pw, root := uint16(22), true, true
	var portSet, pwSet, rootSet bool
	for _, l := range securityLinearizedSshdLines(mainPath) {
		trimmed := strings.TrimSpace(l.line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}
		switch {
		case parts[0] == "Port" && !portSet:
			if p, err := strconv.ParseUint(parts[1], 10, 16); err == nil {
				port, portSet = uint16(p), true
			}
		case parts[0] == "PasswordAuthentication" && !pwSet:
			pw, pwSet = strings.EqualFold(parts[1], "yes"), true
		case parts[0] == "PermitRootLogin" && !rootSet:
			root, rootSet = !strings.EqualFold(parts[1], "no"), true
		}
	}
	return port, pw, root
}

func securityCountSslCerts() int {
	ents, err := os.ReadDir("/etc/dockpanel/ssl")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() {
			n++
		}
	}
	return n
}

// SecurityGetSecurityOverview aggregates firewall, fail2ban, SSH, SSL.
func SecurityGetSecurityOverview() (SecurityOverview, error) {
	var (
		wg             sync.WaitGroup
		fw             SecurityFirewallStatus
		f2b            SecurityFail2banStatus
		fwErr, f2bErr  error
		sshPort        uint16
		sshPw, sshRoot bool
		ssl            int
	)
	wg.Add(4)
	go func() { defer wg.Done(); fw, fwErr = SecurityGetFirewallStatus() }()
	go func() { defer wg.Done(); f2b, f2bErr = SecurityGetFail2banStatus() }()
	go func() { defer wg.Done(); sshPort, sshPw, sshRoot = SecurityParseSshConfig() }()
	go func() { defer wg.Done(); ssl = securityCountSslCerts() }()
	wg.Wait()
	if fwErr != nil {
		fw = SecurityFirewallStatus{}
	}
	if f2bErr != nil {
		f2b = SecurityFail2banStatus{}
	}
	var total uint32
	for _, j := range f2b.Jails {
		total += j.BannedCount
	}
	return SecurityOverview{
		FirewallActive: fw.Active, FirewallRulesCount: len(fw.Rules),
		Fail2banRunning: f2b.Running, Fail2banBannedTotal: total,
		SshPort: sshPort, SshPasswordAuth: sshPw, SshRootLogin: sshRoot, SslCertsCount: ssl,
	}, nil
}

// SecurityDisableSshPasswordAuth sets PasswordAuthentication no.
func SecurityDisableSshPasswordAuth() error {
	if err := securityModifySshdConfig("PasswordAuthentication", "no"); err != nil {
		return err
	}
	return securityRestartSshd()
}

// SecurityEnableSshPasswordAuth sets PasswordAuthentication yes.
func SecurityEnableSshPasswordAuth() error {
	if err := securityModifySshdConfig("PasswordAuthentication", "yes"); err != nil {
		return err
	}
	return securityRestartSshd()
}

// SecurityDisableSshRootLogin sets PermitRootLogin no.
func SecurityDisableSshRootLogin() error {
	if err := securityModifySshdConfig("PermitRootLogin", "no"); err != nil {
		return err
	}
	return securityRestartSshd()
}

// SecurityChangeSshPort moves sshd to port. The firewall rule for the new
// port is opened (in whichever firewall runs) BEFORE sshd restarts — it used
// to be a discarded `ufw allow`, so on firewalld the next SSH connection had
// nowhere to land.
func SecurityChangeSshPort(port uint16) error {
	if port == 0 {
		return fmt.Errorf("Invalid port")
	}
	p := strconv.Itoa(int(port))
	if err := securityModifySshdConfig("Port", p); err != nil {
		return err
	}
	if !FirewallAllowTcp(p) {
		return fmt.Errorf("Could not open port %d in the firewall — refusing to move SSH there, "+
			"it would lock you out. Open it manually, then retry.", port)
	}
	FirewallReload()
	return securityRestartSshd()
}

func securityModifySshdConfig(key, value string) error {
	return securityModifySshdConfigAt("/etc/ssh/sshd_config", key, value)
}

// securityModifySshdConfigAt edits key across sshd_config and its Includes:
// in the file that actually governs it (first active directive in sshd's
// order, else the first commented one), else appended to the main file.
// Writing the main file unconditionally reported success while a drop-in
// (matched by the stock `Include sshd_config.d/*.conf` near the top) kept
// winning — "first obtained value wins".
func securityModifySshdConfigAt(mainPath, key, value string) error {
	lines := securityLinearizedSshdLines(mainPath)
	if len(lines) == 0 {
		if _, err := os.Stat(mainPath); err != nil {
			return fmt.Errorf("Failed to read %s: not found", mainPath)
		}
	}
	isCommented := func(t string) bool {
		return strings.HasPrefix(t, "#"+key) || strings.HasPrefix(t, "# "+key)
	}
	target := ""
	for _, l := range lines {
		t := strings.TrimSpace(l.line)
		if strings.HasPrefix(t, key) {
			target = l.path
			break
		}
		if target == "" && isCommented(t) {
			target = l.path
		}
	}
	if target == "" {
		target = mainPath
	}
	content, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("Failed to read %s: %v", target, err)
	}
	found := false
	var out []string
	for _, line := range LogsLines(content) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, key) || isCommented(t) {
			out = append(out, key+" "+value)
			found = true
		} else {
			out = append(out, line)
		}
	}
	if !found {
		out = append(out, key+" "+value)
	}
	// Atomic write: temp file beside the target, then rename.
	tmp := filepath.Join(filepath.Dir(target), filepath.Base(target)+".tmp")
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("Failed to write %s: %v", target, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("Failed to rename %s: %v", target, err)
	}
	slog.Info(fmt.Sprintf("SSH config updated: %s %s (in %s)", key, value, target))
	return nil
}

func securityRestartSshd() error {
	out, err := securityExec(30*time.Second, "systemctl", "restart", "sshd")
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("sshd restart timed out")
	}
	if err != nil {
		return fmt.Errorf("Failed to restart sshd: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("sshd restart failed: %s", securityLossy(out.Stderr))
	}
	slog.Info("sshd restarted")
	return nil
}

// securityValidJail: ASCII alphanumerics, '-' and '_' (empty passes, as in Rust).
func securityValidJail(jail string) bool {
	for _, c := range jail {
		if !(c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// securityValidBanIP: non-empty, ASCII digits, '.' and ':' only.
func securityValidBanIP(ip string) bool {
	if ip == "" {
		return false
	}
	for _, c := range ip {
		if !(c >= '0' && c <= '9' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

func securityFail2banSet(jail, ip, verb, failMsg string) error {
	if !securityValidJail(jail) {
		return fmt.Errorf("Invalid jail name")
	}
	if !securityValidBanIP(ip) {
		return fmt.Errorf("Invalid IP address")
	}
	out, err := securityExec(30*time.Second, "fail2ban-client", "set", jail, verb, ip)
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("fail2ban-client timed out")
	}
	if err != nil {
		return fmt.Errorf("fail2ban-client failed: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("%s: %s", failMsg, securityLossy(out.Stderr))
	}
	return nil
}

// SecurityFail2banUnban unbans ip from jail.
func SecurityFail2banUnban(jail, ip string) error {
	if err := securityFail2banSet(jail, ip, "unbanip", "Unban failed"); err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("Unbanned %s from jail %s", ip, jail))
	return nil
}

// SecurityFail2banBan bans ip in jail.
func SecurityFail2banBan(jail, ip string) error {
	if err := securityFail2banSet(jail, ip, "banip", "Ban failed"); err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("Banned %s in jail %s", ip, jail))
	return nil
}

// SecurityFail2banBannedIps lists a jail's banned IPs.
func SecurityFail2banBannedIps(jail string) ([]string, error) {
	if !securityValidJail(jail) {
		return nil, fmt.Errorf("Invalid jail name")
	}
	out, err := securityExec(30*time.Second, "fail2ban-client", "status", jail)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("fail2ban-client timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("fail2ban-client failed: %v", err)
	}
	ips := []string{}
	for _, l := range LogsLines(out.Stdout) {
		if _, after, ok := strings.Cut(l, "Banned IP list:"); ok {
			after, _, _ = strings.Cut(after, "Banned IP list:")
			ips = append(ips, strings.Fields(after)...)
			break
		}
	}
	return ips, nil
}

// SecurityGetLoginAudit parses recent SSH login attempts from the auth log.
// RHEL logs to /var/log/secure, not auth.log; a missing file is a real error
// (it used to be swallowed into an empty list, making a RHEL host look
// identical to a quiet one).
func SecurityGetLoginAudit() ([]SecurityLoginEntry, error) {
	path := LogsResolveAuthLogPath()
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to read %s: %v", path, err)
	}
	return securityParseLoginAudit(LogsLines(content)), nil
}

func securityParseLoginAudit(lines []string) []SecurityLoginEntry {
	entries := []SecurityLoginEntry{}
	// Mar 18 12:34:56 host sshd[1234]: Accepted publickey for user from 1.2.3.4 port 5678
	// Mar 18 12:34:56 host sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 5678
	for i, seen := len(lines)-1, 0; i >= 0 && seen < 500; i, seen = i-1, seen+1 {
		line := lines[i]
		if !strings.Contains(line, "sshd[") {
			continue
		}
		success := strings.Contains(line, "Accepted")
		failed := strings.Contains(line, "Failed password") || strings.Contains(line, "Failed publickey")
		if !success && !failed {
			continue
		}
		ip := "unknown"
		if parts := strings.Split(line, " from "); len(parts) > 1 {
			if f := strings.Fields(parts[1]); len(f) > 0 {
				ip = f[0]
			}
		}
		sep := " for "
		if strings.Contains(line, "invalid user") {
			sep = "invalid user "
		}
		user := "unknown"
		if parts := strings.Split(line, sep); len(parts) > 1 {
			user, _, _ = strings.Cut(parts[1], " from")
		}
		t := "unknown"
		if len(line) >= 15 {
			t = line[:15]
		}
		method := "unknown"
		if strings.Contains(line, "publickey") {
			method = "publickey"
		} else if strings.Contains(line, "password") {
			method = "password"
		}
		entries = append(entries, SecurityLoginEntry{Time: t, User: user, IP: ip, Method: method, Success: success})
		if len(entries) >= 50 {
			break
		}
	}
	return entries
}

// SecuritySetupPanelJail creates a fail2ban jail for the panel login
// endpoint (repeated 401s on /api/auth/login in the nginx access logs).
func SecuritySetupPanelJail() error {
	filter := "[Definition]\nfailregex = ^<HOST> .* \"POST /api/auth/login HTTP/.*\" 401\nignoreregex =\n"
	if err := os.WriteFile("/etc/fail2ban/filter.d/dockpanel.conf", []byte(filter), 0o644); err != nil {
		return fmt.Errorf("Failed to write filter: %v", err)
	}
	jail := "[dockpanel]\nenabled = true\nfilter = dockpanel\nport = http,https\nlogpath = /var/log/nginx/*.access.log\nmaxretry = 5\nfindtime = 600\nbantime = 3600\n"
	if err := os.WriteFile("/etc/fail2ban/jail.d/dockpanel.conf", []byte(jail), 0o644); err != nil {
		return fmt.Errorf("Failed to write jail config: %v", err)
	}
	out, err := securityExec(30*time.Second, "systemctl", "restart", "fail2ban")
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("fail2ban restart timed out")
	}
	if err != nil {
		return fmt.Errorf("Failed to restart fail2ban: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("fail2ban restart failed: %s", securityLossy(out.Stderr))
	}
	slog.Info("DockPanel Fail2Ban jail created and activated")
	return nil
}

// SecurityPanelJailStatus reports whether the panel jail is configured.
func SecurityPanelJailStatus() bool {
	_, err := os.Stat("/etc/fail2ban/jail.d/dockpanel.conf")
	return err == nil
}

// securityCanonicalize mirrors std::fs::canonicalize: absolute, every
// symlink resolved, the path must exist.
func securityCanonicalize(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// SecurityApplyFix applies a recommended fix for a security finding.
func SecurityApplyFix(fixType, target string) (string, error) {
	switch fixType {
	case "block_port":
		p, err := strconv.ParseUint(target, 10, 16)
		if err != nil {
			return "", fmt.Errorf("Invalid port")
		}
		if err := SecurityAddFirewallRule(uint16(p), "tcp", "deny", nil); err != nil {
			return "", err
		}
		return fmt.Sprintf("Port %d/tcp blocked", p), nil
	case "disable_password_auth":
		if err := SecurityDisableSshPasswordAuth(); err != nil {
			return "", err
		}
		return "SSH password authentication disabled", nil
	case "disable_root_login":
		if err := SecurityDisableSshRootLogin(); err != nil {
			return "", err
		}
		return "SSH root login disabled", nil
	case "remove_file", "quarantine_file":
		// Canonicalize first so a symlink cannot point the removal outside
		// /var/www.
		canonical, err := securityCanonicalize(target)
		if err != nil {
			return "", fmt.Errorf("Cannot resolve path %s: %v", target, err)
		}
		if !strings.HasPrefix(canonical, "/var/www/") {
			if fixType == "remove_file" {
				return "", fmt.Errorf("Can only remove files under /var/www")
			}
			return "", fmt.Errorf("Can only quarantine files under /var/www")
		}
		if fixType == "remove_file" {
			if err := os.Remove(canonical); err != nil {
				return "", fmt.Errorf("Failed to remove %s: %v", canonical, err)
			}
			return "File removed: " + canonical, nil
		}
		const qdir = "/var/lib/dockpanel/quarantine"
		_ = os.MkdirAll(qdir, 0o755)
		qpath := fmt.Sprintf("%s/%d_%s", qdir, time.Now().Unix(), filepath.Base(canonical))
		if err := os.Rename(canonical, qpath); err != nil {
			return "", fmt.Errorf("Failed to quarantine %s: %v", canonical, err)
		}
		return fmt.Sprintf("File quarantined: %s -> %s", canonical, qpath), nil
	}
	return "", fmt.Errorf("Unknown fix type: %s", fixType)
}
