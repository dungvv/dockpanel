package cli

// logs, php, security and ssl commands — each small enough to share a file.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// urlenc escapes only the characters the agent's query parsing trips on.
func urlenc(s string) string {
	return strings.NewReplacer("%", "%25", " ", "%20", "&", "%26", "=", "%3D", "+", "%2B", "#", "%23").Replace(s)
}

func printLines(entries []any) {
	for _, e := range entries {
		if line, ok := str(e); ok {
			fmt.Println(line)
		}
	}
}

func cmdLogs(token string, domain *string, logType string, lines int64, filter, search *string) error {
	if search != nil {
		result, err := agentGet(fmt.Sprintf("/logs/search?pattern=%s&type=%s", urlenc(*search), logType), token)
		if err != nil {
			return err
		}
		entries, ok := arr(result)
		if !ok {
			return errors.New("Expected array from /logs/search")
		}
		if len(entries) == 0 {
			fmt.Println("No matches found.")
		} else {
			printLines(entries)
			fmt.Printf("\n%d match(es)\n", len(entries))
		}
		return nil
	}

	path := fmt.Sprintf("/logs?type=%s&lines=%d", logType, lines)
	if domain != nil {
		path = fmt.Sprintf("/logs/%s?type=%s&lines=%d", *domain, logType, lines)
	}
	if filter != nil {
		path += "&filter=" + urlenc(*filter)
	}
	result, err := agentGet(path, token)
	if err != nil {
		return err
	}
	entries, ok := arr(result)
	if !ok {
		return errors.New("Expected array from /logs")
	}
	if len(entries) == 0 {
		fmt.Println("No log entries.")
	} else {
		printLines(entries)
	}
	return nil
}

func cmdPHPList(token, output string) error {
	result, err := agentGet("/php/versions", token)
	if err != nil {
		return err
	}
	if output == "json" {
		fmt.Println(pretty(result))
		return nil
	}
	versions, ok := arr(get(result, "versions"))
	if !ok {
		return errors.New("Expected versions array from /php/versions")
	}
	fmt.Printf("\x1b[1m%-10s %-12s %-12s %-30s\x1b[0m\n", "VERSION", "INSTALLED", "FPM", "SOCKET")
	for _, v := range versions {
		installed, fpm := isTrue(get(v, "installed")), isTrue(get(v, "fpm_running"))
		instColor, fpmColor, fpmText, socket := "\x1b[90m", "\x1b[90m", "stopped", "-"
		if installed {
			instColor, socket = "\x1b[32m", strOr(get(v, "socket"), "-")
		}
		if fpm {
			fpmColor, fpmText = "\x1b[32m", "running"
		}
		fmt.Printf("%-10s %s%-12s\x1b[0m %s%-12s\x1b[0m %-30s\n", strOr(get(v, "version"), "-"), instColor, yesNo(installed), fpmColor, fpmText, socket)
	}
	return nil
}

func cmdPHPInstall(token, version string) error {
	switch version {
	case "8.1", "8.2", "8.3", "8.4", "8.5":
	default:
		return fmt.Errorf("Invalid PHP version '%s'. Supported: 8.1, 8.2, 8.3, 8.4, 8.5", version)
	}
	fmt.Printf("Installing PHP %s...\n", version)
	result, err := agentPost("/php/install", map[string]any{"version": version}, token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to install PHP %s: %s", version, strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Printf("\x1b[32m✓\x1b[0m %s\n", strOr(get(result, "message"), "Installed successfully"))
	return nil
}

func onOff(on bool, onColor, offColor, onText, offText string) string {
	if on {
		return onColor + onText
	}
	return offColor + offText
}

func cmdSecurityOverview(token, output string) error {
	o, err := agentGet("/security/overview", token)
	if err != nil {
		return err
	}
	if output == "json" {
		fmt.Println(pretty(o))
		return nil
	}
	fmt.Println("\x1b[1mSecurity Overview\x1b[0m")
	fmt.Printf("  Firewall:    %s\x1b[0m\n", onOff(isTrue(get(o, "firewall_active")), "\x1b[32m", "\x1b[31m", "active", "inactive"))
	fmt.Printf("  Fail2ban:    %s\x1b[0m\n", onOff(isTrue(get(o, "fail2ban_running")), "\x1b[32m", "\x1b[31m", "active", "inactive"))
	fmt.Printf("  SSH root:    %s\x1b[0m\n", onOff(isTrue(get(o, "ssh_root_login")), "\x1b[31m", "\x1b[32m", "enabled", "disabled"))
	fmt.Printf("  SSH password:%s\x1b[0m\n", onOff(isTrue(get(o, "ssh_password_auth")), "\x1b[33m", "\x1b[32m", " enabled", " disabled"))
	return nil
}

func cmdSecurityScan(token, output string) error {
	fmt.Println("Running security scan...")
	result, err := agentPostEmpty("/security/scan", token)
	if err != nil {
		return err
	}
	if output == "json" {
		fmt.Println(pretty(result))
		return nil
	}
	findings, _ := arr(get(result, "findings"))

	// The agent's ScanResult has no overall risk_level — derive it from the
	// highest severity returned ("critical"/"warning"/"info"). Ties keep the
	// last one seen, like Rust's max_by_key.
	rank := map[string]int{"critical": 3, "warning": 2, "info": 1}
	risk, best := "info", -1
	for _, f := range findings {
		if s, ok := str(get(f, "severity")); ok && rank[s] >= best {
			risk, best = s, rank[s]
		}
	}
	riskColor := map[string]string{"critical": "\x1b[31m", "warning": "\x1b[33m", "info": "\x1b[32m"}[risk]
	if riskColor == "" {
		riskColor = "\x1b[90m"
	}
	fmt.Println("\x1b[1mScan Results\x1b[0m")
	fmt.Printf("  Risk level:  %s%s\x1b[0m\n", riskColor, risk)

	if len(findings) == 0 {
		fmt.Println("  \x1b[32mNo issues found.\x1b[0m")
		return nil
	}
	fmt.Println()
	for _, f := range findings {
		sev := strOr(get(f, "severity"), "info")
		color := "\x1b[90m"
		switch sev {
		case "critical":
			color = "\x1b[31m"
		case "warning":
			color = "\x1b[33m"
		}
		fmt.Printf("  %s[%s]\x1b[0m %s\n", color, sev, strOr(get(f, "title"), "-"))
	}
	fmt.Printf("\n%d finding(s)\n", len(findings))
	return nil
}

func cmdFirewallList(token, output string) error {
	fw, err := agentGet("/security/firewall", token)
	if err != nil {
		return err
	}
	if output == "json" {
		fmt.Println(pretty(fw))
		return nil
	}
	state := "\x1b[31mdisabled\x1b[0m"
	if isTrue(get(fw, "active")) {
		state = "\x1b[32menabled\x1b[0m"
	}
	fmt.Printf("\x1b[1mFirewall:\x1b[0m %s\n", state)

	rules, ok := arr(get(fw, "rules"))
	if !ok {
		return nil
	}
	if len(rules) == 0 {
		fmt.Println("  No rules configured.")
		return nil
	}
	fmt.Printf("\n\x1b[1m%-6s %-12s %-10s %-20s\x1b[0m\n", "#", "TO", "ACTION", "FROM")
	for _, r := range rules {
		num := "-"
		if n, ok := u64(get(r, "number")); ok {
			num = strconv.FormatUint(n, 10)
		}
		action := strOr(get(r, "action"), "-")
		color := "\x1b[31m"
		if strings.Contains(strings.ToLower(action), "allow") {
			color = "\x1b[32m"
		}
		fmt.Printf("%-6s %-12s %s%-10s\x1b[0m %-20s\n", num, strOr(get(r, "to"), "-"), color, action, strOr(get(r, "from"), "anywhere"))
	}
	fmt.Printf("\n%d rule(s)\n", len(rules))
	return nil
}

func cmdFirewallAdd(token string, port int64, proto, action string, from *string) error {
	if action != "allow" && action != "deny" {
		return fmt.Errorf("Invalid action '%s'. Use: allow or deny", action)
	}
	if proto != "tcp" && proto != "udp" {
		return fmt.Errorf("Invalid protocol '%s'. Use: tcp or udp", proto)
	}
	body := map[string]any{"port": port, "proto": proto, "action": action}
	suffix := ""
	if from != nil {
		body["from"] = *from
		suffix = " from " + *from
	}
	result, err := agentPost("/security/firewall/rules", body, token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to add rule: %s", strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Printf("\x1b[32m✓\x1b[0m Firewall rule added: %s %s/%d%s\n", action, proto, port, suffix)
	return nil
}

func cmdFirewallRemove(token string, number int64) error {
	fmt.Printf("Removing firewall rule #%d...\n", number)
	result, err := agentDelete(fmt.Sprintf("/security/firewall/rules/%d", number), token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to remove rule: %s", strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Println("\x1b[32m✓\x1b[0m Firewall rule removed")
	return nil
}

func cmdSSLStatus(token, domain string) error {
	st, err := agentGet("/ssl/status/"+domain, token)
	if err != nil {
		return err
	}
	if !isTrue(get(st, "has_cert")) {
		fmt.Printf("No SSL certificate for %s\n", domain)
		return nil
	}
	days := i64Or(get(st, "days_remaining"), 0)
	color := "\x1b[31m"
	if days > 30 {
		color = "\x1b[32m"
	} else if days > 7 {
		color = "\x1b[33m"
	}
	fmt.Printf("\x1b[1mSSL Certificate: %s\x1b[0m\n", domain)
	fmt.Printf("  Issuer:      %s\n", strOr(get(st, "issuer"), "unknown"))
	fmt.Printf("  Expires:     %s\n", strOr(get(st, "not_after"), "unknown"))
	fmt.Printf("  Remaining:   %s%d days\x1b[0m\n", color, days)
	return nil
}

// cmdSSLProvision orders a Let's Encrypt certificate.
//
// THE ISSUER QUESTION ("is the installed cert ours to replace?") IS NOT ASKED
// HERE, DELIBERATELY: the agent asks it in the code every ACME order passes
// through. A second copy here would be the one that drifts, standing over an
// operator's purchased certificate. This command only owes --force, and the
// agent's refusal reaches the operator verbatim via the client's error lift.
func cmdSSLProvision(token, domain, email, runtime string, proxyPort *int64, force bool) error {
	fmt.Printf("Provisioning SSL for %s...\n", domain)
	body := map[string]any{"email": email, "runtime": runtime}
	// Sent only when asked for; absent reads as false at the agent (and at older agents).
	if force {
		body["force"] = true
	}
	if proxyPort != nil {
		body["proxy_port"] = *proxyPort
	}
	result, err := agentPost("/ssl/provision/"+domain, body, token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to provision SSL: %s", strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Println("\x1b[32m✓\x1b[0m SSL certificate provisioned")
	fmt.Printf("  Domain:      %s\n", domain)
	fmt.Printf("  Certificate: %s\n", strOr(get(result, "cert_path"), "unknown"))
	fmt.Printf("  Expires:     %s\n", strOr(get(result, "expiry"), "unknown"))
	return nil
}
