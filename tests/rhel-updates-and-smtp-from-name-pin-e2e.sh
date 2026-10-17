#!/usr/bin/env bash
# Regression pins for the s460 rotation: services/smtp.rs + routes/smtp.rs
# (never a PRIMARY finder/skeptic target) and routes/updates.rs (same),
# LOC-ranked and pre-selection-checked per feedback_dockpanel_audit_scope.
#
#   Topic 1 (routes/updates.rs) — the whole System Updates feature
#     (list/count/apply) was 100% hardcoded to apt/apt-get, with zero use of
#     this project's own pkg.rs dual-family abstraction. On an RHEL-family
#     agent (a platform this project explicitly supports and tests
#     elsewhere), list_updates/update_count silently returned "0 updates" —
#     read as fully patched — because apt-family commands simply don't
#     exist there. Fixed: dnf/yum check-update support (exit code 0/100/
#     other correctly distinguished — check-update's exit status is NOT a
#     plain success/failure boolean), a 3-token line parser requiring a
#     name.arch dot (rejects a false-positive 3-word non-package line —
#     caught by this pin suite's own mutation test on the parser), an
#     rpm -qa lookup for current-version display, and a needs-restarting -r
#     fallback for reboot_required on RHEL (no /var/run/reboot-required
#     there). apply_updates now selects apt-get/dnf/yum via pkg::installer()
#     instead of a hardcoded apt-get binary.
#   Topic 2 (services/smtp.rs) — two CONFIRMED findings in configure():
#     (a) from_name was validated for injection and pushed fleet-wide by the
#     backend, but never written into the msmtp config or the PHP
#     sendmail_path ini — a "From Name" the UI promises applies "to all
#     sites on this server" had no effect on any real application mail,
#     only the one-off admin Test Email. Fixed: msmtp's from_full_name
#     directive (verified against `man msmtp` on this box — envelope `from`
#     is address-only; from_full_name is the separate directive that names
#     the display name msmtp adds to an auto-generated From header).
#     (b) Every SMTP settings save unconditionally truncated
#     /var/log/msmtp.log via fs::write(path, "") — the frontend always
#     re-PUTs all 7 smtp_* keys on Save (even an unrelated field edit),
#     which pushes to every online fleet member, wiping the mail relay log
#     on every save, including the save an operator makes while debugging a
#     mail problem using that exact log. Fixed: only create the file when
#     it doesn't already exist.
#   Off-menu, completeness-critic-found — routes/php.rs had the textually
#     identical vulnerable pattern v2.213.0 (the immediately prior ship) had
#     just fixed in pkg.rs: wrapping safe_command_unsandboxed(...).output()
#     in a caller-side tokio::time::timeout only kills the LOCAL systemd-run
#     waiter on expiry, leaving the actual privileged apt/dnf transaction
#     running orphaned in its own transient unit forever. Three live sites
#     (install_version, uninstall_version's purge, its apt autoremove
#     follow-up), all using the same 300s INSTALL_TIMEOUT-equal duration as
#     pkg.rs's own fixed sites. Fixed: converted to
#     UnsandboxedCommand::output_with_timeout(), which also stops the named
#     transient unit on timeout.
#
# Go subjects: panel/go/internal/agent/routes/updates.go (updatesList,
# updatesCount, updatesApply, updatesRpmCheckUpdate, updatesParseRpmUpdateLine,
# updatesRebootRequired), panel/go/internal/agent/services/smtp.go
# (SmtpConfigure) and panel/go/internal/agent/routes/php.go
# (phpInstallVersion, phpUninstallVersion; the Rust output_with_timeout is
# safecmd's (*Unsandboxed).OutputWithTimeout).
#
# Pure source analysis, plus `go test -run` for the parser's unit tests (§2).

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Strip comments. Go: `/* … */` blocks and `//` at line start or after
# whitespace (a `http://` inside a string literal survives). Go tests live in
# _test.go files, so there is no in-file test module to cut.
code()      { perl -0777 -pe 's{/\*.*?\*/}{}gs; s{(^|[ \t])//[^\n]*}{$1}gm' "$1"; }
has()       { [ -n "$(code "$1" | grep -F -- "$2")" ]; }
hasre()     { [ -n "$(code "$1" | grep -E -- "$2")" ]; }
# Body of a top-level Go func: from `func NAME(` to the next top-level item.
fnbody()    { code "$1" | FN="$2" perl -0777 -ne 'my $n=$ENV{FN}; print $1 if /(\nfunc \Q$n\E\(.*?)(?=\n(?:func |const |var |type )|\z)/s'; }
bodyhas()   { [ -n "$(fnbody "$1" "$2" | grep -F -- "$3")" ]; }
bodyhasre() { [ -n "$(fnbody "$1" "$2" | grep -E -- "$3")" ]; }
count()     { code "$1" | grep -Fc -- "$2"; }

UPDATES=panel/go/internal/agent/routes/updates.go
UPDATES_TEST=panel/go/internal/agent/routes/updates_test.go
SMTP=panel/go/internal/agent/services/smtp.go
PHP=panel/go/internal/agent/routes/php.go

for f in "$UPDATES" "$UPDATES_TEST" "$SMTP" "$PHP"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

echo "── 1. Topic 1: routes/updates.go gains a dnf/yum path via pkg.go ──"
if has "$UPDATES" '"github.com/ovexro/dockpanel/panel/go/internal/agent/services"' && has "$UPDATES" 'services.PkgMgrRpm'; then
  ok "updates.go imports the pkg.go dual-family abstraction"
else
  bad "updates.go no longer imports services' PkgMgr/PkgInstaller — RHEL path may be gone"
fi
if bodyhasre "$UPDATES" updatesRpmCheckUpdate 'out\.ExitCode != 0 && out\.ExitCode != 100'; then
  ok "updatesRpmCheckUpdate distinguishes check-update's 0/100/error exit codes"
else
  bad "updatesRpmCheckUpdate no longer distinguishes 0 (no updates) from 100 (updates) from a real error"
fi
# parse-dot arm retired: covered by TestUpdatesSkipsSectionHeadersAndTheMetadataBanner ("Security: 3 patches") (panel/go/internal/agent/routes/updates_test.go)
if bodyhas "$UPDATES" updatesList 'services.PkgManager() == services.PkgMgrRpm'; then
  ok "updatesList branches on PkgMgrRpm"
else
  bad "updatesList no longer branches on PkgMgrRpm — may be apt-only again"
fi
if bodyhas "$UPDATES" updatesCount 'services.PkgManager() == services.PkgMgrRpm'; then
  ok "updatesCount branches on PkgMgrRpm"
else
  bad "updatesCount no longer branches on PkgMgrRpm — may be apt-only again"
fi
if bodyhas "$UPDATES" updatesApply 'services.PkgGetInstaller()' && bodyhas "$UPDATES" updatesApply 'safecmd.NewUnsandboxed(inst.Bin())'; then
  ok "updatesApply selects its binary via services.PkgGetInstaller() rather than a hardcoded apt-get"
else
  bad "updatesApply no longer calls services.PkgGetInstaller() — may have regressed to hardcoded apt-get"
fi
if bodyhasre "$UPDATES" updatesApply 'NewUnsandboxed\("apt(-get)?"'; then
  bad "updatesApply still hardcodes safecmd.NewUnsandboxed(\"apt-get\") — the RHEL branch may be dead code"
else
  ok "updatesApply no longer hardcodes the apt-get binary directly"
fi
if bodyhas "$UPDATES" updatesRebootRequired '"needs-restarting", "-r"'; then
  ok "updatesRebootRequired has an RHEL fallback (needs-restarting -r)"
else
  bad "updatesRebootRequired lost its RHEL fallback — reboot banner will never show on RPM boxes"
fi

echo
echo "── 2. Topic 1 control: the new RPM parser is unit-tested, not just source-shaped ──"
GOT=$(cd panel/go && go test ./internal/agent/routes/ -count=1 -v \
  -run '^(TestUpdatesParsesARealDnfCheckUpdateLine|TestUpdatesSkipsSectionHeadersAndTheMetadataBanner)$' 2>&1)
if grep -qF -- '--- PASS: TestUpdatesParsesARealDnfCheckUpdateLine' <<<"$GOT"; then
  ok "updatesParseRpmUpdateLine has a passing Go unit test for a real dnf line"
else
  bad "no passing unit test for updatesParseRpmUpdateLine (TestUpdatesParsesARealDnfCheckUpdateLine)"
fi
if grep -qF -- '--- PASS: TestUpdatesSkipsSectionHeadersAndTheMetadataBanner' <<<"$GOT"; then
  ok "updatesParseRpmUpdateLine has a passing unit test for non-package lines"
else
  bad "no passing unit test guarding against section-header false positives"
fi

echo
echo "── 3. Topic 2: services/smtp.go — from_name reaches msmtp via from_full_name ──"
if bodyhas "$SMTP" SmtpConfigure 'from_full_name'; then
  ok "SmtpConfigure writes msmtp's from_full_name directive"
else
  bad "SmtpConfigure no longer writes from_full_name — from_name is dead again"
fi
if bodyhas "$SMTP" SmtpConfigure 'if fromName != "" {'; then
  ok "SmtpConfigure guards on fromName being empty before emitting the directive"
else
  bad "SmtpConfigure's empty-fromName guard is missing"
fi
# Control: from_full_name must be INSIDE the account block (after `from`,
# before `user`), not in `defaults` — msmtp scopes it per-account like `from`.
# The template is a raw string with a REAL newline between the two lines,
# so this checks adjacency by line number rather than a single-line regex.
FROM_LINE=$(grep -n '^from[[:space:]]*%s$' "$SMTP" | head -1 | cut -d: -f1)
NAME_LINE=$(grep -n '^%suser[[:space:]]' "$SMTP" | head -1 | cut -d: -f1)
ACCT_LINE=$(grep -n '^account[[:space:]]*default$' "$SMTP" | head -1 | cut -d: -f1)
if [ -n "$FROM_LINE" ] && [ -n "$NAME_LINE" ] && [ -n "$ACCT_LINE" ] \
   && [ "$NAME_LINE" -eq $((FROM_LINE + 1)) ] && [ "$ACCT_LINE" -lt "$FROM_LINE" ]; then
  ok "from_full_name is emitted immediately after from, inside the account block"
else
  bad "from_full_name's placement in the config template changed (from=$FROM_LINE, name=$NAME_LINE) — re-verify it is still inside the account block"
fi

echo
echo "── 4. Topic 2: services/smtp.go — msmtp.log is no longer truncated on every save ──"
SMTP_FN=$(fnbody "$SMTP" SmtpConfigure)
if perl -0777 -ne 'exit !/const logPath = "\/var\/log\/msmtp\.log"\s*\n\s*if _, err := os\.Stat\(logPath\); err != nil \{\s*\n\s*_ = os\.WriteFile\(logPath,/' <<<"$SMTP_FN"; then
  ok "SmtpConfigure only creates msmtp.log when it does not already exist"
else
  bad "SmtpConfigure no longer guards the msmtp.log write — may truncate on every save again"
fi
# Control: exactly one write to this path, and it must be the guarded one —
# a regression that adds a second unconditional write (by const or literal,
# WriteFile or an O_TRUNC open) would slip past a has()-only check.
WRITE_COUNT=$(code "$SMTP" | grep -cE 'os\.(WriteFile|OpenFile|Create)\((logPath|"/var/log/msmtp\.log")')
if [ "$WRITE_COUNT" -eq 1 ]; then
  ok "exactly one write to msmtp.log in the file (the guarded one)"
else
  bad "found $WRITE_COUNT writes to msmtp.log, expected 1 — an unguarded second write may have been added"
fi

echo
echo "── 5. Off-menu: routes/php.go uses OutputWithTimeout at its 3 privileged-transaction sites ──"
if bodyhas "$PHP" phpInstallVersion '.OutputWithTimeout(300 * time.Second)'; then
  ok "phpInstallVersion() uses OutputWithTimeout"
else
  bad "phpInstallVersion() does not use OutputWithTimeout — orphaned-unit fix not propagated"
fi
if [ "$(fnbody "$PHP" phpUninstallVersion | grep -cF '.OutputWithTimeout(300 * time.Second)')" -ge 2 ]; then
  ok "phpUninstallVersion() uses OutputWithTimeout (covers both the purge and the autoremove follow-up)"
else
  bad "phpUninstallVersion() does not use OutputWithTimeout at both sites — orphaned-unit fix not propagated"
fi
# Control: zero instances of the OLD double-wrap shape anywhere in the file —
# a caller-side deadline (context.WithTimeout / WithDeadline) around a plain
# (*Unsandboxed).Output(ctx) kills only the LOCAL systemd-run waiter, leaving
# the privileged transaction running orphaned in its transient unit.
OLD_PATTERN_COUNT=$(code "$PHP" | grep -cE 'context\.With(Timeout|Deadline)\(' || true)
if [ "${OLD_PATTERN_COUNT:-0}" -eq 0 ]; then
  ok "no caller-side context deadline wrapping a plain safecmd.NewUnsandboxed(...).Output() in php.go"
else
  bad "found $OLD_PATTERN_COUNT caller-side context deadlines in php.go — the orphaned-unit bug may still exist somewhere"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
