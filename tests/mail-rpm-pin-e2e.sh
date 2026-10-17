#!/usr/bin/env bash
# Regression pins for s268 — the mail vertical on the RHEL family.
#
# Mail was refused on RPM boxes from s266 to s268 with an honest reason: nothing
# past the packages had been driven there. Driving it on two real Rocky 9.8
# boxes found FIVE defects, and the refusal's own premise was wrong in both
# directions — it claimed the packages installed (they did not) and warned about
# a Debian failure mode that cannot occur on RHEL.
#
#   R1  EPEL's opendkim needs libmilter.so.1.0 (sendmail-milter) and
#       libmemcached.so.11 (libmemcached-awesome), both CRB-only. setup.sh
#       enabled EPEL and never CRB, which EPEL itself requires — so the mail
#       install died on "nothing provides", while a name-availability probe
#       reported all four packages available. That probe is where the false
#       "the packages install" claim came from.
#   R2  The OpenDKIM config wrote TrustAnchorFile /usr/share/dns/root.key, a
#       Debian path (dns-root-data). OpenDKIM treats a missing anchor as FATAL:
#       status=78/CONFIG, the daemon never starts, nothing is ever signed.
#   R3  s262 removed `-f` from the drop-in because Debian's unit is
#       Type=forking. EPEL's is Type=simple, where a backgrounding daemon makes
#       systemd reap the parent and log "Deactivated successfully" while the
#       unit goes INACTIVE — a failure that does not even register as failed.
#   R4  The milter socket lived in Postfix's chroot (/var/spool/postfix/...),
#       which exists only because DEBIAN chroots smtpd. RHEL does not (master.cf
#       column 5 = n), and SELinux forbids it outright: dkim_milter_t is denied
#       search on postfix_spool_t.
#   R5  /var/vmail is created by the installer so it inherits var_t, which
#       dovecot_t may not write. Every message was deferred and never delivered
#       while both services were active and the panel called the stack healthy.
#   R6  Rocky 9.8 ships Dovecot 2.3.16 built WITHOUT Argon2, so the {ARGON2ID}
#       hashes the panel writes fail with "Unknown scheme ARGON2ID" and no
#       mailbox can be opened — s259's finding on a different family. Argon2 is
#       a BUILD OPTION, not a version, and our own comment said ">= 2.3.11".
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

AGENT_MAIL=panel/go/internal/agent/routes/mail.go
BACKEND_MAIL=panel/go/internal/api/rt_mail.go
PKG=panel/go/internal/agent/services/pkg.go

for f in "$AGENT_MAIL" "$BACKEND_MAIL" "$PKG"; do
  [ -f "$f" ] || { echo "FATAL: missing subject $f"; exit 1; }
done
SETUP=scripts/setup.sh

# Production code only. These files carry long comments that NAME the very
# strings being forbidden, and a scanner that cannot tell a guard from a use
# convicts the explanation instead of the defect (#94c). Strip comment lines
# before searching for a forbidden token.
#
# `has`/`hasnt` take the whole pipeline into ONE command substitution rather
# than piping into `grep -q`. Under `set -o pipefail`, `code f | grep -q X`
# returns FAILURE even when X matches: grep -q exits at the first hit, the
# upstream grep dies of SIGPIPE (141), and pipefail propagates that. The first
# draft of this suite reported 7 false failures that way — and a harness lying
# about pins is indistinguishable from pins failing, which is how you end up
# "fixing" correct code.
#
# Go keeps unit tests in separate _test.go files, so the subjects are already
# production-only (the Rust-era `#[cfg(test)]` cut-off has no Go meaning: the
# tests that call the plain hash function live in rt_mail_test.go).
code()  { grep -vE '^[[:space:]]*(//|\*|/\*)' "$1"; }
# Body of a top-level Go func, comment lines stripped.
fnbody() { code "$1" | awk -v fn="$2" 'index($0, "func " fn "(") == 1 {i=1; next} i && /^}/ {exit} i {print}'; }
has()   { [ -n "$(code "$1" | grep -F -- "$2")" ]; }
hasre() { [ -n "$(code "$1" | grep -E -- "$2")" ]; }

echo "── 1. R1: CRB is enabled wherever EPEL is ──"

# Pin the PAIRING, not the literal command: EPEL without CRB is the defect, and
# a future rewrite that keeps EPEL and drops CRB must fail here.
if grep -q 'epel-release' "$SETUP"; then
  if grep -qE 'set-enabled (crb|powertools)' "$SETUP"; then
    ok "setup.sh enables CRB/PowerTools alongside EPEL"
  else
    bad "setup.sh enables EPEL but never CRB — EPEL requires it, and opendkim's deps live there"
  fi
else
  bad "setup.sh no longer enables EPEL at all — this pin can no longer see the pairing"
fi

# Both repo ids must be attempted: `crb` is EL9+, `powertools` is EL8.
if grep -qE 'set-enabled crb' "$SETUP" && grep -qE 'set-enabled powertools' "$SETUP"; then
  ok "both CRB repo ids are attempted (crb on EL9+, powertools on EL8)"
else
  bad "only one CRB repo id is attempted — the other EL generation is left broken"
fi

echo "── 2. R2: no Debian-only DNS trust anchor is written unconditionally ──"

if has "$AGENT_MAIL" 'TrustAnchorFile /usr/share/dns/root.key'; then
  bad "the Debian-only anchor path is written unconditionally again — opendkim exits 78/CONFIG on RHEL"
else
  ok "no hardcoded /usr/share/dns/root.key in the emitted OpenDKIM config"
fi

# The durable half: whatever anchor is emitted must be existence-checked first.
if has "$AGENT_MAIL" 'TrustAnchorFile'; then
  if has "$AGENT_MAIL" 'root.key' \
     && [ -n "$(fnbody "$AGENT_MAIL" mailWriteOpendkimConfig | grep -A1 -F 'if mailExists(p) {' | grep -F '"TrustAnchorFile " + p')" ]; then
    ok "the trust anchor is emitted only when the file exists"
  else
    bad "a TrustAnchorFile is emitted with no existence check — a missing anchor is FATAL to opendkim"
  fi
else
  ok "no TrustAnchorFile emitted at all (also safe)"
fi

echo "── 3. R3+R4: the OpenDKIM arrangement does not depend on the distro's unit or chroot ──"

# R4: the socket must not live under Postfix's spool. Assert on the emitted
# CONFIG VALUE, not on a constant name a rename could dodge.
# In Go the Socket line is `"Socket " + mailOpendkimSocket`, so the value is the
# constant's; both must be read, or the absence check below sees nothing.
sockconst=$(code "$AGENT_MAIL" | grep -E '^[[:space:]]*mailOpendkimSocket[[:space:]]*=')
if [ -z "$sockconst" ] || ! has "$AGENT_MAIL" '"Socket " + mailOpendkimSocket'; then
  bad "could not read the emitted Socket value — the chroot arm would measure nothing"
elif hasre "$AGENT_MAIL" 'Socket (local:)?/?var/spool/postfix' || grep >/dev/null -c 'var/spool/postfix' <<< "$sockconst"; then
  bad "the milter socket is back inside Postfix's chroot — SELinux denies dkim_milter_t search on postfix_spool_t"
else
  ok "the milter socket is not inside Postfix's chroot"
fi

# And Postfix must be pointed at the SAME endpoint. A drift between these two is
# the failure that looks like "opendkim is running but nothing is signed".
sock=$(code "$AGENT_MAIL" | grep -oE 'inet:[0-9]+@127\.0\.0\.1' | head -1 | sed 's/inet:\([0-9]*\)@.*/\1/')
milter=$(code "$AGENT_MAIL" | grep -oE 'inet:127\.0\.0\.1:[0-9]+' | head -1 | sed 's/.*://')
if [ -n "$sock" ] && [ "$sock" = "$milter" ]; then
  ok "OpenDKIM's Socket port ($sock) and Postfix's milter port ($milter) agree"
else
  bad "OpenDKIM listens on '${sock:-?}' but Postfix is pointed at '${milter:-?}' — nothing would be signed"
fi

# R3: the drop-in must own Type as well as ExecStart, so the packaged unit's
# choice cannot decide whether `-f` is right.
if has "$AGENT_MAIL" 'Type=simple' && has "$AGENT_MAIL" 'opendkim -f -x'; then
  ok "the drop-in pins Type=simple AND passes -f (one arrangement correct on both families)"
else
  bad "the drop-in leaves Type to the packaged unit — Debian is forking, EPEL is simple, and the wrong pairing fails SILENTLY"
fi

# P1: Postfix must be told to listen on every interface. The RHEL package
# ships `inet_interfaces = localhost`, so without this no mail can ever arrive.
if has "$AGENT_MAIL" 'inet_interfaces=all'; then
  ok "the installer sets inet_interfaces=all (RHEL ships localhost)"
else
  bad "nothing sets inet_interfaces — Postfix binds 127.0.0.1:25 only on RHEL and no mail can arrive"
fi

echo "── 4. R5: /var/vmail is given an SELinux type Dovecot may write ──"

if has "$AGENT_MAIL" 'mail_spool_t'; then
  ok "the installer labels /var/vmail mail_spool_t"
else
  bad "nothing labels /var/vmail — it inherits var_t and dovecot_t cannot write a single maildir"
fi

# It must be CALLED, not merely defined — the exact mutation that slipped
# through s265's pin review twice (#92c).
if hasre "$AGENT_MAIL" '^[[:space:]]+mailLabelVmailForSelinux\(\)[[:space:]]*$'; then
  ok "the labelling helper is actually called from the installer"
else
  bad "mailLabelVmailForSelinux is defined but never called — the pin would sit green through the regression"
fi

echo "── 5. R6: mailbox passwords are hashed in a scheme the target box can verify ──"

if has "$BACKEND_MAIL" 'func rtMailDovecotPasswordHashFor('; then
  ok "a scheme-aware hash function exists"
else
  bad "mailbox passwords are hashed with no regard for what the box's Dovecot supports"
fi

# Count the CALL SITES: creation and password-change both mint hashes, and a
# change that reverts to Argon2id locks a working mailbox out (#92b).
# Exclude the definition line and the internal delegation inside
# rtMailDovecotPasswordHashFor, which legitimately calls the plain function.
# (Which scheme it picks is TestMail* in panel/go/internal/api/rt_mail_test.go.)
raw=$(code "$BACKEND_MAIL" | grep -nE 'rtMailDovecotPasswordHash\(' \
      | grep -vE 'func rtMailDovecotPasswordHash\(' \
      | grep -vE 'return rtMailDovecotPasswordHash\(password\)' | wc -l)
aware=$(code "$BACKEND_MAIL" | grep -cE 'rtMailDovecotPasswordHashFor\(' )
aware=$((aware - 1))  # minus its own definition
if [ "$raw" -eq 0 ] && [ "$aware" -ge 2 ]; then
  ok "every mailbox-password call site ($aware) goes through the scheme-aware path"
else
  bad "$raw call site(s) still hash unconditionally; only $aware are scheme-aware — creation AND change must both be"
fi

# The agent has to actually report the schemes, or the backend is choosing blind.
if has "$AGENT_MAIL" 'password_schemes' && has "$AGENT_MAIL" 'doveadm'; then
  ok "the agent reports its Dovecot's supported schemes from doveadm"
else
  bad "the agent does not report supported schemes — the backend cannot choose correctly"
fi

echo "── 6. The apt-only call sites the s266 conversion missed ──"

# mail.rs had TWO raw apt-get call sites after s266 converted the installers.
# Positive anchor: the installer goes through the family-aware PkgInstall.
stray_apt=$(code "$AGENT_MAIL" | grep -n 'apt-get')
if ! has "$AGENT_MAIL" 'services.PkgInstall('; then
  bad "the mail routes no longer call services.PkgInstall — the apt-get absence check below would measure nothing"
elif [ -n "$stray_apt" ]; then
  bad "mail.go still shells apt-get directly, so the path is Debian-only:${stray_apt}"
else
  ok "no raw apt-get call site left in the mail routes"
fi

# The Redis UNIT name differs from its package name on RPM. Translate or the
# enable/restart silently targets a unit that does not exist.
if hasre "$AGENT_MAIL" 'systemctl.*"enable", "rspamd", "redis-server"'; then
  bad "rspamd's installer enables the literal unit redis-server — that unit does not exist on the RHEL family"
elif ! has "$AGENT_MAIL" 'redisUnit := services.PkgServiceName("redis-server")' \
     || ! has "$AGENT_MAIL" '"systemctl", "enable", "rspamd", redisUnit'; then
  bad "the rspamd installer no longer enables a translated Redis unit"
else
  ok "the Redis unit name is translated rather than hardcoded"
fi

echo "── 7. mailStatus cannot call a crash-looping stack healthy ──"

# `configured` was added at s262 for this class; s268 found opendkim excluded
# from the summary entirely, so a milter in a restart loop read as running.
if has "$AGENT_MAIL" 'running := postfix && dovecot && opendkim && configured'; then
  ok "mailStatus's running verdict includes OpenDKIM"
else
  bad "mailStatus omits OpenDKIM from its running verdict — a DKIM milter in a restart loop reads as healthy"
fi

echo "── 8. The mail log path is not a Debian hardcode ──"

if has "$AGENT_MAIL" '"-n", "5000", "/var/log/mail.log"'; then
  bad "mailLogs tails the Debian-only path — the RHEL family writes /var/log/maillog and the page reads all zeros"
elif ! has "$AGENT_MAIL" '"tail", "-n", "5000", mailLogPath()'; then
  bad "mailLogs no longer tails the resolved mailLogPath()"
else
  ok "mailLogs resolves the log path instead of hardcoding Debian's"
fi

if has "$AGENT_MAIL" '/var/log/maillog'; then
  ok "the RHEL log name is among the candidates"
else
  bad "nothing ever looks for /var/log/maillog"
fi

echo "── 9. The refusal matches what was actually verified ──"

# A refusal that stops being true is worse than no refusal (pkg.go's own words).
# The blanket family ban is gone; what remains must be a real precondition.
if has "$PKG" 'not supported on RHEL-family distributions yet'; then
  bad "the blanket RHEL mail refusal is back, but the vertical has been driven end to end there"
else
  ok "no blanket RHEL-family mail refusal"
fi

# The refusal is fully retired, so the CRB hint has to live where the real
# failure surfaces. A precondition PROBE is explicitly not acceptable here: the
# first attempt used one and refused a box where the packages were installable,
# because dnf inside the agent's sandbox fails on /var/log/dnf.log.
if [ -n "$(code "$PKG" | grep -F 'nothing provides')" ] \
   && [ -n "$(code "$PKG" | grep -F 'set-enabled crb')" ]; then
  ok "a CRB hint is attached to the real package-manager failure"
else
  bad "nothing explains 'nothing provides' — the operator gets a raw dnf error with no action"
fi
if [ -n "$(code "$AGENT_MAIL" | grep -F 'services.PkgExplainPackageFailure(')" ]; then
  ok "the mail installer routes its package failure through the explainer"
else
  bad "the explainer exists but the mail installer does not call it"
fi
if ! has "$PKG" 'func PkgMailRefusalReason() string {'; then
  bad "PkgMailRefusalReason is gone — the availability-probe check below would measure nothing"
elif [ -n "$(fnbody "$PKG" PkgMailRefusalReason | grep -E 'Available\(|available\(')" ]; then
  bad "PkgMailRefusalReason gates on an availability probe again — it cannot run reliably inside the agent sandbox and refuses good boxes"
else
  ok "no availability-probe gate in front of the mail installer"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
