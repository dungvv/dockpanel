#!/usr/bin/env bash
# Regression pins for the s454 dockpanel-fanout run over the agent's
# services/security.rs + routes/security.rs — now the Go port,
# panel/go/internal/agent/services/security.go + routes/security.go
# (workflow wf_ec0595a4-efd; project_dockpanel_tech_debt ledger p193).
#
#   S1  parse_ssh_config()/modify_sshd_config() only ever read/wrote
#       /etc/ssh/sshd_config, never following an `Include` directive into
#       /etc/ssh/sshd_config.d/*.conf. OpenSSH's own rule is "the first
#       obtained value wins", and the stock `Include` line ships BEFORE the
#       main file's own commented defaults — live-verified on this exact box:
#       GET /security/overview reported ssh_port:22 while sshd actually
#       listened on 1571 (port.conf), and 50-cloud-init.conf silently
#       overrode PasswordAuthentication the same way. A write through the
#       old code path would report success while sshd kept the old value.
#   S2  add_firewall_rule/remove_firewall_rule/apply_fix("block_port") shelled
#       to `ufw` unconditionally, even though get_firewall_status and
#       change_ssh_port had already been fixed (s265) to detect firewalld.
#       Live-verified 424/UFW_MISSING on this exact box (firewalld active,
#       ufw not installed) — a first-class setup.sh target (RHEL family).
#   S3  get_login_audit() hardcoded /var/log/auth.log and swallowed a missing
#       file into an empty Vec (Ok(vec![])) — indistinguishable from a
#       genuinely quiet RHEL host, which logs the same events to
#       /var/log/secure instead. Two sibling hardcodes found in the same
#       sweep: diagnostics.rs's brute-force scan (silently never fires on
#       RHEL) and routes/logs.rs's log-sizes listing (cosmetic).
#   S4  Completeness critic, off the original menu: is_safe_hook_command
#       (command_filter.rs, gates git-deploy post_deploy_cmd/pre_build_cmd at
#       the sh -c sink in routes/git_build.rs::run_hook) was the one function
#       in this file NOT routed through normalize_for_blocklist — executed
#       proof: is_safe_hook_command("r'm' -rf /") returned true, and `sh -c
#       "r'm' -rf /"` runs `rm -rf /`. The backend's independent copy,
#       is_safe_shell_command (routes/mod.rs), had no normalization at all.
#
# Behaviour a test can call directly (the sshd parser/writer, the hook and
# shell validators) is pinned by Go tests, run here with `go test`; the arms
# left as source checks pin wiring (which function calls which).
#
# Pure source analysis except where noted; no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Strip comments and the test module, so a pin can never be satisfied (or
# tripped) by prose describing the very thing it forbids.
# (Go keeps its tests in *_test.go, so no test-module cut is needed.)
code()  { grep -vE '^[[:space:]]*(//|\*|/\*)' "$1"; }
has()   { [ -n "$(code "$1" | grep -F -- "$2")" ]; }
hasre() { [ -n "$(code "$1" | grep -E -- "$2")" ]; }

# One named function's body, comment-stripped. NEVER pipe this straight into
# `grep -q` — a producer this long can still be writing when `-q` closes the
# read end on its first match, and under `pipefail` that SIGPIPE (not the
# match) becomes the `if`'s exit status. `bodyhas`/`bodyhasre` avoid it the
# same way `has`/`hasre` above do: grep without `-q` drains the pipe fully,
# so the producer never gets closed out from under it.
fnbody()    { code "$1" | awk "/$2/,/^}/"; }
bodyhas()   { [ -n "$(fnbody "$1" "$2" | grep -F -- "$3")" ]; }
bodyhasre() { [ -n "$(fnbody "$1" "$2" | grep -E -- "$3")" ]; }

GA=panel/go/internal/agent
SEC_SVC=$GA/services/security.go
FIREWALL=$GA/services/firewall.go
LOGS_SVC=$GA/services/logs.go
DIAG=$GA/services/diagnostics.go
AGENT_LOGS_ROUTE=$GA/routes/logs.go

for f in "$SEC_SVC" "$FIREWALL" "$LOGS_SVC" "$DIAG" "$AGENT_LOGS_ROUTE"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

echo "── 1. S1: SSH config parsing/writing follows Include drop-ins ──"

# 'linearizes sshd_config + Includes' retired: covered by TestSecurityParseSshConfigIncludeDropInWinsOverLaterMainDefault (panel/go/internal/agent/services/security_test.go)
# 'path-parameterized for testability' retired (obsolete in Go): the tests call securityParseSshConfigAt directly, so it existing is compiler-enforced
# 'parse reads through the linearized view' retired: covered by TestSecurityParseSshConfigFirstIncludedFileWinsLexically + TestSecurityParseSshConfigRelativeInclude (security_test.go)
# 'modify resolves the governing file' retired: covered by TestSecurityModifySshdConfigWritesToTheFileThatActuallyGovernsTheKey + TestSecurityModifySshdConfigReplacesActiveDirectiveInGoverningFileNotMain (security_test.go)
# 'first obtained value wins' retired: covered by TestSecurityParseSshConfigIncludeDropInWinsOverLaterMainDefault (security_test.go)
if (cd panel/go && go test ./internal/agent/services/ -count=1 \
      -run '^TestSecurity(ParseSshConfig|ModifySshdConfig)' >/dev/null 2>&1); then
  ok "the sshd parser/writer Go tests pass: Includes followed, first value wins, writes land in the governing file"
else
  bad "the sshd Include Go tests fail — Include-blindness (or last-match-wins) may be back"
fi

# The public entry points still go through the tested Include-aware bodies.
if bodyhas "$SEC_SVC" "^func SecurityParseSshConfig\\(" "securityParseSshConfigAt(" \
   && bodyhas "$SEC_SVC" "^func securityModifySshdConfig\\(" "securityModifySshdConfigAt("; then
  ok "SecurityParseSshConfig / securityModifySshdConfig delegate to the tested Include-aware _At bodies"
else
  bad "a public sshd entry point no longer calls its tested _At body — the Go tests above no longer cover what runs"
fi

echo
echo "── 2. S2: firewall rule add/remove/block-port speak firewalld too ──"

if bodyhas "$SEC_SVC" "^func SecurityAddFirewallRule\\(" "if FirewallDetect() == FirewallFirewalld {"; then
  ok "SecurityAddFirewallRule branches on the detected firewall"
else
  bad "SecurityAddFirewallRule no longer checks for firewalld — back to a ufw-only 424 on RHEL"
fi

if bodyhas "$SEC_SVC" "^func SecurityRemoveFirewallRule\\(" "if FirewallDetect() == FirewallFirewalld {"; then
  ok "SecurityRemoveFirewallRule branches on the detected firewall"
else
  bad "SecurityRemoveFirewallRule no longer checks for firewalld"
fi

for fn in FirewallAddPort FirewallRemovePort FirewallRemoveService FirewallRichRuleSpec FirewallAddRichRuleRaw FirewallRemoveRichRuleRaw; do
  if has "$FIREWALL" "func $fn("; then
    ok "firewall.go exposes $fn"
  else
    bad "firewall.go is missing $fn — firewalld parity primitive lost"
  fi
done

if has "$SEC_SVC" "func securityFirewalldEntries(" \
   && bodyhas "$SEC_SVC" "^func securityFirewalldStatus\\(" "securityFirewalldEntries()" \
   && bodyhas "$SEC_SVC" "^func SecurityRemoveFirewallRule\\(" "securityFirewalldEntries()"; then
  ok "firewalld_status and remove_firewall_rule share one numbered entry list (services+ports+rich rules)"
else
  bad "securityFirewalldEntries is gone (or no longer shared by status and remove) — the numbers the Security page shows and the ones remove_firewall_rule resolves can drift apart again"
fi

echo
echo "── 3. S3: the auth log path is RHEL-aware, and a missing file is a real error ──"

if has "$LOGS_SVC" "func LogsResolveAuthLogPath() string"; then
  ok "logs.go exposes a shared LogsResolveAuthLogPath()"
else
  bad "LogsResolveAuthLogPath is gone"
fi

if bodyhas "$SEC_SVC" "^func SecurityGetLoginAudit\\(" "path := LogsResolveAuthLogPath()"; then
  ok "SecurityGetLoginAudit resolves the auth log path instead of hardcoding /var/log/auth.log"
else
  bad "SecurityGetLoginAudit hardcodes the Debian-only auth log path again"
fi

if [ -n "$(fnbody "$SEC_SVC" "^func SecurityGetLoginAudit\\(" | tr '\n\t' '  ' | grep -E 'content, err := os\.ReadFile\(path\) +if err != nil \{ +return nil, fmt\.Errorf\(')" ]; then
  ok "SecurityGetLoginAudit propagates a read failure as an Err, not a silent empty Vec"
else
  bad "SecurityGetLoginAudit swallows a missing/unreadable log into Ok(vec![]) again — indistinguishable from a genuinely quiet host"
fi

# Go's spelling of unwrap_or_default: discarding the read's error. Positive
# anchor first, so an absent function cannot pass the absence check.
if ! bodyhas "$SEC_SVC" "^func SecurityGetLoginAudit\\(" "os.ReadFile(path)"; then
  bad "SecurityGetLoginAudit no longer reads the auth log at all — re-scope this pin"
elif bodyhasre "$SEC_SVC" "^func SecurityGetLoginAudit\\(" ', _ :?= os\.ReadFile\(|return \[\]SecurityLoginEntry\{\}, nil'; then
  bad "SecurityGetLoginAudit discards the read error — the silent-empty-success path may be back"
else
  ok "SecurityGetLoginAudit has no silent empty-result fallback on the auth log read"
fi

# Two sibling hardcodes found in the same sweep — same fix, different files.
if has "$DIAG" 'LogsResolveAuthLogPath()'; then
  ok "diagnostics.go's brute-force scan uses the RHEL-aware path"
else
  bad "diagnostics.go still hardcodes /var/log/auth.log — its brute-force finding silently never fires on RHEL"
fi

if has "$AGENT_LOGS_ROUTE" 'services.LogsResolveAuthLogPath()'; then
  ok "routes/logs.go's log-sizes listing uses the RHEL-aware path"
else
  bad "routes/logs.go's log-sizes listing still hardcodes /var/log/auth.log"
fi

# No stray direct hardcode of the Debian-only path anywhere in the agent
# (Go) non-comment code, outside the one place that still legitimately
# needs the literal string: LogsResolveAuthLogPath's own existence probe.
STRAY=""
while IFS= read -r f; do
  [ -z "$f" ] && continue
  [ "$f" = "$LOGS_SVC" ] && continue
  if has "$f" '"/var/log/auth.log"'; then
    STRAY="$STRAY $f"
  fi
done <<EOF
$(grep -rl '/var/log/auth\.log' "$GA" panel/go/cmd/dockpanel-agent --include="*.go" 2>/dev/null | grep -v '_test\.go$' || true)
EOF
if [ -z "$STRAY" ]; then
  ok "no other agent Go file still hardcodes the Debian-only auth log path"
else
  bad "these files still hardcode /var/log/auth.log directly:$STRAY"
fi

echo
echo "── 4. S4: hook/shell command validators close the quote-split bypass ──"

# is_safe_hook_command-normalizes arm retired: covered by TestCommandFilterHookCommandQuoteSplitEvasionRejected (panel/go/internal/agent/services/command_filter_test.go)
if (cd panel/go && go test ./internal/agent/services/ -count=1 \
      -run '^(TestCommandFilterHookCommandQuoteSplitEvasionRejected|TestCommandFilterNormalizeForBlocklist)$' >/dev/null 2>&1); then
  ok "CommandFilterIsSafeHookCommand refuses r'm' -rf / and its quote-split siblings (Go test)"
else
  bad "CommandFilterIsSafeHookCommand no longer normalizes — r'm' -rf / bypasses the blocklist and sh -c runs it for real"
fi

# backend normalize_for_blocklist-exists arm retired (obsolete in Go): isSafeShellCommand calling it is compiler-enforced, its behaviour is tested below
# is_safe_shell_command-normalizes arm retired: covered by TestShellCommandRejectsQuoteSplitEvasion (panel/go/internal/api/core_router_test.go)
if (cd panel/go && go test ./internal/api/ -count=1 -run '^TestShellCommandRejectsQuoteSplitEvasion$' >/dev/null 2>&1); then
  ok "the API's isSafeShellCommand refuses the same quote-split bypass (Go test)"
else
  bad "isSafeShellCommand no longer normalizes — same quote-split bypass as command_filter had"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
