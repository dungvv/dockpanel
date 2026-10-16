// Shared command filtering for terminal input and cron commands.
//
// Provides blocklist-based filtering to prevent dangerous commands from being
// executed through the web terminal or cron system.
package services

import (
	"fmt"
	"strings"
)

// commandFilterBlockedPatterns are blocked in terminal and cron contexts.
var commandFilterBlockedPatterns = []string{
	// Destructive filesystem operations
	"rm -rf /", "rm -rf /*", "mkfs", "dd if=", "> /dev/",
	"chmod 777 /", "chown", "passwd", "shadow",
	// Shell chaining / injection
	"|sh", "|bash", "| sh", "| bash",
	";sh", ";bash", "; sh", "; bash",
	"`", "$(", "eval ", "exec ",
	// Encoding tricks
	"base64", "xxd", "openssl enc", "printf '\\x",
	// Scripting interpreters used for injection (not for legitimate site use)
	"perl", "ruby", "node -e", "php -r",
	"python -c", "python2 -c", "python3 -c",
	"python -m http", "python3 -m http",
	// Network exfiltration
	"nc ", "ncat ", "socat ", "telnet ",
	"curl", "wget",
	// Sensitive files
	"/etc/passwd", "/etc/shadow", "/etc/sudoers",
	// Shell operators ("; " blocks chaining, but && and || are allowed in cron for legitimate use)
	"; ",
	// Write to system paths
	"> /etc/", "> /root/", "> /var/",
	"< /etc/", "< /root/",
	// System control
	"shutdown", "reboot", "init ",
	// User management
	"useradd", "userdel", "usermod", "adduser", "addgroup",
	// Null bytes
	"\\x", "\\0",
}

// commandFilterTerminalBlockedPatterns are additionally blocked in the web
// terminal (these are OK in crons which run non-interactively as root).
var commandFilterTerminalBlockedPatterns = []string{
	// Privilege escalation
	"su ", "su\t", "sudo ",
	// Package management (can install backdoors)
	"apt ", "apt-get ", "dpkg ", "yum ", "dnf ", "snap ",
	// Service manipulation
	"systemctl ", "service ",
	// Kernel modules
	"insmod ", "modprobe ", "rmmod ", "kexec ",
	// Container / namespace / capability escape
	"docker ", "nsenter ", "unshare ", "chroot ", "pivot_root ", "capsh ", "mknod ", "debugfs ",
	// Disk/mount operations
	"mount ", "umount ", "fdisk ", "parted ",
	// SSH key manipulation
	"ssh-keygen", "authorized_keys",
	// Cron manipulation (bypass the managed cron system)
	"crontab",
	// Process signals to other processes
	"kill ", "killall ", "pkill ",
	// Shell operators (blocked in terminal but allowed in cron)
	"||", "&&",
	// Network config
	"iptables", "ip6tables", "nft ", "ufw ",
	// Reading other sites.
	//
	// READ THE SCOPE LIMIT BELOW BEFORE TREATING THIS AS A TENANT BOUNDARY.
	//
	// `/var/www/` alone matched only the ABSOLUTE spelling, and the site
	// shell's own cwd is INSIDE /var/www, so `cat ../other-site.com/wp-config.php`
	// (another tenant's DB credentials) walked past it. `..` closes that
	// spelling; every path a site shell needs is at or below its cwd.
	//
	// Blunt on purpose: a SUBSTRING match, so `echo "done..."` is refused too.
	// The narrower "../" still admits a bare `cd ..`, after which every path is
	// an ordinary relative name. A pattern one command steps around is worse
	// than a blunt one, because it reads as protection.
	//
	// SITE terminals only: the terminal route tests is_site_terminal first,
	// so an administrator's server shell still takes `cd ..` normally.
	"/var/www/", "..",
}

// THE SCOPE LIMIT OF THE TWO PATTERNS ABOVE (Rust: _SITE_SHELL_IS_NOT_A_SANDBOX).
//
// This blocklist is a speed bump, not a tenant boundary, and cannot be made
// into one. There is no filesystem confinement behind it: the site-shell
// spawn does setgid/setuid/umask/chdir and starts `bash --restricted` — no
// chroot, no mount namespace. Every site tree resolves to the same www-data
// uid, so mode bits cannot separate tenants; rbash forbids slashes in command
// NAMES, not arguments.
//
// The same bound applies to every KEYWORD in both lists, and deeper than the
// quote/backslash evasion commandFilterNormalizeForBlocklist closes: the
// terminal filters one completed line at a time against a REAL, PERSISTENT
// shell, so `X=$'\143url'` then `$X --version` passes both lines individually.
// No per-line substring check can see a relationship between two lines.
// Blocking bare assignment syntax has real false-positive cost
// (`FOO=bar wp cache flush`); the real fix is egress control or a per-site
// uid/namespace — a different change.

// commandFilterNormalizeForBlocklist reduces ordinary shell quoting/escaping
// so keyword matching sees what the shell will actually run.
//
// `cu”rl` and `w\get` contain no curl/wget SUBSTRING, but `bash
// --restricted` (terminal) and `bash -c` (cron) remove the quotes/backslash
// before exec and run the real binary (reproduced live).
//
// Deliberately NOT a shell parser — it only deletes quote/backslash chars, so
// it can only make MORE things match, never fewer. ANSI-C escapes,
// arithmetic/parameter expansion and prior-line variables remain open (see
// the scope note above).
func commandFilterNormalizeForBlocklist(cmd string) string {
	var out strings.Builder
	out.Grow(len(cmd))
	rs := []rune(cmd)
	for i := 0; i < len(rs); i++ {
		switch c := rs[i]; c {
		case '\'', '"': // quote-splitting: cu''rl / "cu"'rl' → curl
		case '\\':
			// Outside single quotes bash drops the backslash and keeps the
			// next char literally; a trailing lone backslash is dropped.
			if i+1 < len(rs) {
				i++
				out.WriteRune(rs[i])
			}
		default:
			out.WriteRune(c)
		}
	}
	return out.String()
}

func commandFilterContainsAny(s string, pats []string) bool {
	for _, p := range pats {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// commandFilterRunsArePairs reports whether every run of ch has length
// exactly 2 (or there are none).
func commandFilterRunsArePairs(s string, ch byte) bool {
	for i := 0; i < len(s); {
		if s[i] != ch {
			i++
			continue
		}
		start := i
		for i < len(s) && s[i] == ch {
			i++
		}
		if i-start != 2 {
			return false
		}
	}
	return true
}

// CommandFilterIsSafeCronCommand checks if a command string is safe for cron
// execution. Rejects shell metacharacters and dangerous patterns.
func CommandFilterIsSafeCronCommand(cmd string) bool {
	if cmd == "" || len(cmd) > 4096 || strings.ContainsAny(cmd, "\x00\n\r") {
		return false
	}
	// A bare `;` always chains and was never the legitimate case (only
	// &&/|| are) — reject it outright, same as backtick/$(. The old "| "/"|/"
	// checks passed "id|whoami"; a bare `|` chains just as effectively, so
	// reject any run of `|` whose length isn't exactly 2.
	if strings.Contains(cmd, "`") || strings.Contains(cmd, "$(") || strings.Contains(cmd, ";") ||
		strings.Contains(cmd, "<(") || strings.Contains(cmd, "<<") {
		return false
	}
	if !commandFilterRunsArePairs(cmd, '|') {
		return false
	}
	// A bare `&` backgrounds a command and, mid-string, chains exactly like
	// `;`/`|` — `id&whoami` runs both. Only a PAIRED `&&` is legitimate.
	if !commandFilterRunsArePairs(cmd, '&') {
		return false
	}
	lower := strings.ToLower(commandFilterNormalizeForBlocklist(cmd))
	return !commandFilterContainsAny(lower, commandFilterBlockedPatterns)
}

// CommandFilterIsSafeTerminalCommand checks if a terminal input line is safe.
// Applies both the base blocklist and terminal-specific blocks.
func CommandFilterIsSafeTerminalCommand(cmd string) bool {
	if strings.TrimSpace(cmd) == "" {
		return true // empty input is fine (just pressing Enter)
	}
	lower := strings.ToLower(commandFilterNormalizeForBlocklist(cmd))
	if commandFilterContainsAny(lower, commandFilterBlockedPatterns) {
		return false
	}
	return !commandFilterContainsAny(lower, commandFilterTerminalBlockedPatterns)
}

// commandFilterSuspiciousPatterns trigger real-time alerting: they indicate
// potential attack activity even on server terminals where they aren't
// blocked (e.g. admin running su, useradd).
var commandFilterSuspiciousPatterns = []string{
	"useradd", "adduser", "usermod", "chpasswd", "passwd",
	"su ", "su\t", "sudo ",
	"rm -rf /", "rm -rf /*",
	"curl|bash", "curl | bash", "wget|bash", "wget | bash",
	"curl -s|sh", "curl -sL|bash", "| sh", "| bash",
	"chmod 777", "chmod 4", // setuid
	"/etc/shadow", "/etc/sudoers",
	"ssh-keygen", "authorized_keys",
	"nc -l", "ncat -l", // listeners
	"python -m http.server", "python3 -m http.server",
	"base64 -d", "base64 --decode",
	"crontab -e", "crontab -r",
}

// CommandFilterIsSafeHookCommand validates a command for docker exec hooks
// (git deploy post-deploy commands). Rejects shell metacharacters and
// dangerous patterns but allows general commands.
func CommandFilterIsSafeHookCommand(command string) bool {
	if strings.TrimSpace(command) == "" {
		return false
	}
	if strings.ContainsAny(command, "\n\r\x00") {
		return false
	}
	if strings.ContainsAny(command, "`$|;&<>\\!{}") {
		return false
	}
	// Normalized like every sibling — otherwise `r'm' -rf /` passes and then
	// `sh -c` (git_build run_hook) strips the quotes and runs exactly that.
	lower := strings.ToLower(commandFilterNormalizeForBlocklist(command))
	return !commandFilterContainsAny(lower, []string{"rm -rf /", "mkfs", "dd if=", "> /dev/", "eval ", "exec ",
		"/etc/shadow", "/etc/passwd", "shutdown", "reboot"})
}

// CommandFilterIsSuspiciousCommand reports whether a command should trigger
// an alert, even if allowed on server terminals.
func CommandFilterIsSuspiciousCommand(cmd string) bool {
	if strings.TrimSpace(cmd) == "" {
		return false
	}
	lower := strings.ToLower(commandFilterNormalizeForBlocklist(cmd))
	return commandFilterContainsAny(lower, commandFilterSuspiciousPatterns)
}

// CommandFilterIsSafeExecStart validates a command for a systemd ExecStart
// directive. Only allows whitelisted prefixes and rejects injection chars.
func CommandFilterIsSafeExecStart(command, runtime string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("Command cannot be empty")
	}
	// Newlines would inject systemd unit directives.
	if strings.ContainsAny(command, "\n\r") {
		return fmt.Errorf("Command must not contain newlines")
	}
	if strings.Contains(command, "\x00") {
		return fmt.Errorf("Command must not contain null bytes")
	}
	// '%' blocks systemd specifier injection (%h=home, %u=user, %t=runtime dir).
	for _, ch := range []rune{'`', '$', '|', ';', '&', '<', '>', '\\', '!', '{', '}', '%'} {
		if strings.ContainsRune(command, ch) {
			return fmt.Errorf("Command must not contain '%c'", ch)
		}
	}
	var allowed []string
	switch runtime {
	case "node":
		allowed = []string{"node ", "npm ", "npx ", "yarn ", "pnpm ",
			"node\t", "npm\t", "npx\t", "yarn\t", "pnpm\t"}
	case "python":
		allowed = []string{"python ", "python3 ", "gunicorn ", "uvicorn ", "flask ", "django",
			"python\t", "python3\t", "gunicorn\t", "uvicorn\t", "flask\t"}
	}
	// Known prefix OR a bare filename ("server.js", "app.py") is OK.
	if len(allowed) > 0 {
		lower := strings.ToLower(command)
		hasPrefix := false
		for _, p := range allowed {
			if strings.HasPrefix(lower, p) {
				hasPrefix = true
				break
			}
		}
		bare := !strings.Contains(command, " ") && !strings.Contains(command, "/")
		if !hasPrefix && !bare {
			return fmt.Errorf("Command for %s runtime must start with an allowed prefix or be a bare filename", runtime)
		}
	}
	if strings.Contains(command, "..") {
		return fmt.Errorf("Command must not contain '..'")
	}
	return nil
}
