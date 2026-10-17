#!/usr/bin/env bash
# Regression pins for s270 — the webmail and the spam filter nobody had driven.
#
# s268 drove Postfix/Dovecot/OpenDKIM on the RHEL family and stopped there.
# Driving the remaining two on a Rocky 9.8 box found that neither worked, and
# that the oldest un-root-caused defect on the books was a delivery problem
# rather than the bug everyone had been hunting.
#
#   W1  rspamd is NOT in EPEL. On a stock Rocky 9 with epel AND crb enabled,
#       `dnf install rspamd` answers "Unable to find a match: rspamd", so the
#       panel's Spam Filter button could never work on any RHEL box. Upstream
#       publishes an rpm repo; it must be added on the RPM family ONLY, because
#       Debian and Ubuntu package rspamd themselves and that path already works
#       (#95c — the fix for one family is the defect on the other).
#
#   W2  Even once installed, Postfix never consulted it — on EVERY family.
#       `rspamd_install` (now mailRspamdInstall) wired the milter by replacing the literal
#       `smtpd_milters = unix:opendkim/...`, which s268 stopped writing when it
#       moved OpenDKIM's milter to a loopback port. A string replace with an absent
#       needle returns the string unchanged, so main.cf was rewritten
#       byte-identical and the handler reported success. #96e, one ship later.
#
#   W3  s262's webmail fix reached NO existing box. The /webmail/ nginx
#       fragment is written only on the Install click, and update.sh carried a
#       hand-copied mirror frozen at the v2.10.1 shape — without the header
#       re-declaration — whose "heal" therefore WROTE the shape that makes
#       Roundcube render an empty inbox, and whose guard skipped every box that
#       already had sub_filter. Repaired by derivation: one generator in the
#       agent, reconciled at startup, and the shell mirror deleted.
#
# Pure source analysis over the Go agent (panel/go/internal/agent/routes/mail.go,
# services/pkg.go, cmd/dockpanel-agent/main.go) plus scripts/update.sh. Arms
# that assert behaviour a test can call directly are Go tests (named inline).

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Strip comments, so a pin can never be satisfied (or tripped) by prose
# describing the very thing it forbids. Go: `/* … */` blocks and `//` at line
# start or after whitespace (a `http://` inside a string literal survives).
# Go tests live in _test.go files, so there is no in-file test module to cut.
code()  { perl -0777 -pe 's{/\*.*?\*/}{}gs; s{(^|[ \t])//[^\n]*}{$1}gm' "$1"; }
has()   { [ -n "$(code "$1" | grep -F -- "$2")" ]; }
hasre() { [ -n "$(code "$1" | grep -E -- "$2")" ]; }
# Body of a top-level Go func: from `func NAME(` to the next top-level item.
fnbody() { code "$1" | FN="$2" perl -0777 -ne 'my $n=$ENV{FN}; print $1 if /(\nfunc \Q$n\E\(.*?)(?=\n(?:func |const |var |type )|\z)/s'; }

# The same idea for shell: strip full-line `#` comments. Without this, the
# comment that explains WHY the mirror was deleted trips the pin forbidding
# the mirror — a pin matching prose about the thing it forbids, which is how
# this suite first went red against correct code.
shcode() { grep -vE '^[[:space:]]*#' "$1"; }

MAIL=panel/go/internal/agent/routes/mail.go
PKG=panel/go/internal/agent/services/pkg.go
MAIN=panel/go/cmd/dockpanel-agent/main.go
UPDATE=scripts/update.sh

for f in "$MAIL" "$PKG" "$MAIN" "$UPDATE"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

echo "── 1. W2: the Rspamd milter is DERIVED, never matched as a literal ──"

RSPAMD_FN=$(fnbody "$MAIL" mailRspamdInstall)
[ -n "$RSPAMD_FN" ] || { echo "could not extract mailRspamdInstall — every arm below would be vacuous"; exit 1; }

# The heart of it. Any literal opendkim endpoint inside the rspamd wiring means
# the edit can be orphaned again by a change to mailOpendkimMilter.
if grep -qE 'strings\.Replace(All)?\(|smtpd_milters = (unix|inet):' <<<"$RSPAMD_FN"; then
  bad "mailRspamdInstall still string-replaces a literal smtpd_milters value — the s268→s270 defect"
else
  ok "no literal smtpd_milters replace remains"
fi

if grep -qF "mailAddMilter(mainCf, mailRspamdMilter)" <<<"$RSPAMD_FN"; then
  ok "mailRspamdInstall derives the edit via mailAddMilter"
else
  bad "mailRspamdInstall no longer calls mailAddMilter — how is the milter wired?"
fi

# A guard so the pins above cannot go vacuous if the function is renamed away.
if hasre "$MAIL" '^func mailAddMilter\('; then
  ok "mailAddMilter exists"
else
  bad "mailAddMilter is gone — the two pins above are now vacuous"
fi

# Anchored on the declaration's `=`: a bare substring match stays satisfied
# by `mailRspamdMilterX`, which the negative sweep caught.
if hasre "$MAIL" '^[[:space:]]*mailRspamdMilter[[:space:]]*=[[:space:]]*"'; then
  ok "mailRspamdMilter is a named constant beside mailOpendkimMilter"
else
  bad "mailRspamdMilter constant missing — the endpoint is a magic string again"
fi

# The silent no-op is the actual defect: writing a file back unchanged and
# reporting success. Absent keys must reach the caller as an error. (That
# mailAddMilter reports absence is TestMailAddMilterAbsentCommentedOrLookalikeKeys;
# this arm pins that the handler acts on it.)
if perl -0777 -ne 'exit !/newCf, ok := mailAddMilter\(mainCf, mailRspamdMilter\)\s*\n\s*if !ok \{\s*\n\s*writeErr\([^\n]*\n\s*return\n/' <<<"$RSPAMD_FN"; then
  ok "a missing milter list is an error, not a silent no-op write"
else
  bad "mailAddMilter returning ok=false no longer fails the request — the silent path is back"
fi

if hasre "$MAIL" '^smtpd_milters = ` \+ mailOpendkimMilter \+ `$'; then
  ok "main.cf's milter lines are written from the mailOpendkimMilter constant"
else
  bad "the postfix template no longer interpolates mailOpendkimMilter"
fi

echo "── 2. W1: the Rspamd repo is added on the RPM family ONLY ──"

if hasre "$PKG" '^[[:space:]]*PkgRepoRspamd$'; then
  ok "pkg.go knows PkgRepoRspamd"
else
  bad "PkgRepoRspamd is gone — rspamd cannot be installed on RHEL"
fi

if has "$PKG" "rspamd.com/rpm-stable/centos-"; then
  ok "the upstream rpm repo is the one wired"
else
  bad "the rspamd repo URL changed or vanished"
fi

# The family gate is the #95c protection: Debian must not be routed through
# PkgAddRepo at all, or a probe failure there breaks the family that works.
if perl -0777 -ne 'exit !/if services\.PkgManager\(\) == services\.PkgMgrRpm[^\n]*\{\s*\n\s*if err := services\.PkgAddRepo\(services\.PkgRepoRspamd\)/' <<<"$RSPAMD_FN"; then
  ok "the repo add is gated on the RPM family explicitly"
else
  bad "the RPM-family gate is gone — a probe failure could add a repo on Debian"
fi

# remove_repo arm retired: covered by TestPkgRspamdCleanupIsExactlyTheOneRepoFile (panel/go/internal/agent/services/pkg_test.go)

echo "── 3. W3: ONE generator for the /webmail/ fragment, and it heals ──"

if hasre "$MAIL" '^func mailWebmailNginxBlock\('; then
  ok "mailWebmailNginxBlock is the single source of the fragment"
else
  bad "mailWebmailNginxBlock is gone — the pins below are vacuous"
fi

# frame-ancestors arm retired: covered by TestPinWebmailSpamFragmentRedeclaresSameOriginFraming (panel/go/internal/agent/routes/pin_webmail_spam_test.go)
# X-Frame-Options arm retired: covered by TestPinWebmailSpamFragmentRedeclaresSameOriginFraming (panel/go/internal/agent/routes/pin_webmail_spam_test.go)

HEAL_FN=$(fnbody "$MAIL" HealWebmailNginx)
if [ -n "$HEAL_FN" ] && grep -qF 'desired := mailWebmailNginxBlock(port)' <<<"$HEAL_FN"; then
  ok "HealWebmailNginx exists and rewrites from the one generator"
else
  bad "no heal function — a fix to the fragment reaches no existing install"
fi

if has "$MAIN" "routes.HealWebmailNginx("; then
  ok "the heal runs at agent startup, so an upgrade is enough"
else
  bad "HealWebmailNginx is never called from cmd/dockpanel-agent/main.go — it can never run"
fi

# Healing must never CREATE the fragment for someone who has no webmail: the
# read of the existing fragment must bail out before any write.
read_at=$(grep -nE 'os\.ReadFile\(mailWebmailNginxConf\)' <<<"$HEAL_FN" | head -1 | cut -d: -f1)
bail_at=$(grep -nE '^[[:space:]]*return$' <<<"$HEAL_FN" | head -1 | cut -d: -f1)
write_at=$(grep -nE 'os\.WriteFile\(mailWebmailNginxConf' <<<"$HEAL_FN" | head -1 | cut -d: -f1)
if [ -n "$read_at" ] && [ -n "$bail_at" ] && [ -n "$write_at" ] \
   && [ "$bail_at" -le $((read_at + 2)) ] && [ "$bail_at" -lt "$write_at" ] \
   && sed -n "$((read_at + 1))p" <<<"$HEAL_FN" | grep -qF 'err != nil'; then
  ok "the heal is a no-op when webmail was never installed"
else
  bad "the heal no longer checks the fragment exists — it may install a proxy to nothing"
fi

echo "── 4. W3: the shell mirror is GONE, not merely updated ──"

# The mirror is the drift source. Correcting it would only reset the clock;
# deleting it is what closes the class (#96e — derivation, not correction).
if shcode "$UPDATE" | grep -cE '^[[:space:]]*location /webmail/' >/dev/null; then
  bad "update.sh spells out the /webmail/ fragment again — a second copy that will rot"
else
  ok "update.sh contains no copy of the fragment"
fi

if shcode "$UPDATE" | grep -cE 'sub_filter|proxy_redirect / /webmail/' >/dev/null; then
  bad "update.sh still carries fragment internals — the mirror is back"
else
  ok "update.sh carries no fragment internals"
fi

echo
printf 'webmail/spam pins: \033[0;32m%d passed\033[0m, ' "$PASS"
if [ "$FAIL" -gt 0 ]; then
  printf '\033[0;31m%d failed\033[0m\n' "$FAIL"
  exit 1
fi
printf '0 failed\n'
exit 0
