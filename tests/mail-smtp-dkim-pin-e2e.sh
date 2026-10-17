#!/usr/bin/env bash
# Regression pins for the s262 SMTP drill.
#
# Two real Vultr boxes, two real dockpanel.dev domains, two real Let's Encrypt
# certificates, and the first message this product has ever been asked to
# actually deliver. What that found:
#
#   A. THE MAIL INSTALLER HAD NEVER COMPLETED. `POST /api/mail/install` died at
#      "Failed to write opendkim.conf: Read-only file system" — the agent runs
#      ProtectSystem=strict and /etc/opendkim.conf is a bare file in /etc, the
#      one mail path the unit's ReadWritePaths does not cover. Everything from
#      that line on never ran: the DKIM tables, the milter socket directory,
#      and the service enable. apt's postinst started the daemons anyway, so
#      the box looked healthy.
#   B. NOTHING HAD EVER BEEN DKIM-SIGNED. OpenDKIM's KeyTable and SigningTable
#      were written empty and no code anywhere else ever wrote them. Keys were
#      generated, published in real DNS, and verified green by the panel's own
#      dns-check — while every delivered message carried zero DKIM-Signature
#      headers. Proven on the wire, then fixed and re-proven: dkim=pass.
#   C. THE MAIL PORTS WERE NEVER OPENED. setup.sh allows 80/443/panel; the mail
#      installer started Postfix and Dovecot behind a firewall that dropped
#      every packet to 25/587/993/143.
#   D. THE HELO NAME WAS NEVER SET, costing six Rspamd points before any
#      content was read — and setting it without narrowing mydestination makes
#      Postfix treat a hosted mail domain as local and bounce real mailboxes.
#   E. A RE-RUN OF THE INSTALLER ERASED every domain, mailbox and password by
#      truncating the map files — and since the install returned 500, re-running
#      it was the ordinary thing to do.
#   F. DOVECOT WAS NEVER GIVEN THE BOX'S CERTIFICATE, so Roundcube could not log
#      in at all ("unknown ca"), and the panel's own frame-ancestors 'none'
#      applies to the webmail it installs.
#
# No running panel needed.
#   run: bash tests/mail-smtp-dkim-pin-e2e.sh
#
# Subjects (Go): panel/go/internal/agent/routes/mail.go and the agent unit
# panel/go/internal/agent/services/dockpanel-agent.service (go:embed). Arms
# that assert behaviour a test can call directly live in
# panel/go/internal/agent/routes/pin_mail_smtp_dkim_test.go.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAIL="$REPO/panel/go/internal/agent/routes/mail.go"
AGENT_UNIT="$REPO/panel/go/internal/agent/services/dockpanel-agent.service"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

for f in "$MAIL" "$AGENT_UNIT"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

# Strip comments per language. s261 shipped a stripper that removed `//` from
# SHELL files and ate every http:// URL, reporting two false failures against
# correct code — a comment-blind pin needs a comment model that matches the file.
# Go: `/* … */` blocks, and `//` only at line start or after whitespace (so a
# `http://` inside a string literal survives).
strip_go()    { perl -0777 -pe 's{/\*.*?\*/}{}gs; s{(^|[ \t])//[^\n]*}{$1}gm' "$1"; }
strip_shell() { sed -E 's/(^|[[:space:]])#.*$//' "$1"; }

CODE="$(strip_go "$MAIL")"
# systemd units comment with '#', same as shell.
UNIT="$(strip_shell "$AGENT_UNIT")"

has()  { grep -qF -- "$2" <<<"$1"; }
hasre(){ grep -qE -- "$2" <<<"$1"; }
# Body of a top-level Go func: from `func NAME(` to the next top-level item.
fnbody() { FN="$2" perl -0777 -ne 'my $n=$ENV{FN}; print $1 if /(\nfunc \Q$n\E\(.*?)(?=\n(?:func |const |var |type )|\z)/s' <<<"$1"; }

echo "── A. the installer must not write a path the sandbox refuses ──"
if hasre "$CODE" 'mailOpendkimConf[[:space:]]*=[[:space:]]*"/etc/dockpanel/opendkim\.conf"'; then
  ok "OpenDKIM config lives under /etc/dockpanel (inside ReadWritePaths)"
else
  bad "mailOpendkimConf is no longer the ReadWritePaths-safe path"
fi
# Absence over the whole comment-stripped file; the arm above is its anchor.
if has "$CODE" '"/etc/opendkim.conf"'; then
  bad "installer names /etc/opendkim.conf again — EROFS under ProtectSystem=strict"
else
  ok "nothing writes the distro /etc/opendkim.conf"
fi
if hasre "$CODE" 'ExecStart=/usr/sbin/opendkim (-f )?-x " \+ mailOpendkimConf'; then
  ok "systemd drop-in points opendkim at our config"
else
  bad "drop-in missing — daemon would read the stock config"
fi
# s262 pinned `-f` ABSENT, correctly for Debian, whose packaged unit is
# Type=forking. s268 measured EPEL's unit as Type=simple, where a flagless
# ExecStart makes opendkim background itself, systemd reap the parent, and the
# unit go INACTIVE while logging "Deactivated successfully" — a failure that
# does not register as failed. So the invariant is not the flag, it is the
# AGREEMENT between the Type the drop-in declares and the flag it passes.
dropin_type=$(grep -oE 'Type=[a-z]+\\nExecStart=' <<<"$CODE" | head -1 | sed 's/Type=//; s/\\nExecStart=//')
dropin_f=$(grep -cE 'ExecStart=/usr/sbin/opendkim -f ' <<<"$CODE")
if [ "$dropin_type" = "simple" ] && [ "$dropin_f" -ge 1 ]; then
  ok "drop-in declares Type=simple and passes -f — they agree, on both families"
elif [ "$dropin_type" = "forking" ] && [ "$dropin_f" -eq 0 ]; then
  ok "drop-in declares Type=forking and omits -f — they agree"
elif [ -z "$dropin_type" ]; then
  bad "the drop-in does not declare Type, so whether -f is right depends on the DISTRO's unit"
else
  ok "no -f flag (unit is Type=forking)"
fi

echo "── B. every domain must be bound to its key ──"
if has "$CODE" 'func mailRebuildDkimTables() error'; then
  ok "mailRebuildDkimTables() exists"
else
  bad "mailRebuildDkimTables() gone — nothing populates the DKIM tables"
fi
for caller in 'DKIM keys generated for %s but tables not rebuilt' \
              'DKIM keys removed for %s but tables not rebuilt'; do
  if has "$CODE" "$caller"; then
    ok "table rebuild wired into: ${caller:5:24}…"
  else
    bad "a key-mutating path no longer rebuilds the tables"
  fi
done
# B-keytable retired: covered by TestPinMailSmtpDkimTablesAreDerivedFromTheKeysOnDisk (panel/go/internal/agent/routes/pin_mail_smtp_dkim_test.go)
# B-signingtable retired: covered by TestPinMailSmtpDkimTablesAreDerivedFromTheKeysOnDisk (panel/go/internal/agent/routes/pin_mail_smtp_dkim_test.go)
# The rebuild must read the tables from that same derivation, not a copy.
if has "$(fnbody "$CODE" mailRebuildDkimTables)" 'mailDkimTableLines(mailDkimKeysDir)'; then
  ok "mailRebuildDkimTables writes what mailDkimTableLines derives from disk"
else
  bad "mailRebuildDkimTables no longer derives the tables from the keys on disk"
fi

echo "── C. the ports the mail stack listens on must be opened ──"
if has "$CODE" 'func mailOpenMailPorts()' && has "$(fnbody "$CODE" mailInstall)" 'mailOpenMailPorts()'; then
  ok "mailOpenMailPorts() exists and is called by the installer"
else
  bad "mail ports are no longer opened — inbound mail cannot arrive"
fi
# C-ports (25/587/993/143) retired: covered by TestPinMailSmtpDkimMailPortsCoverEveryListener (panel/go/internal/agent/routes/pin_mail_smtp_dkim_test.go)

echo "── D. HELO name, and the mydestination trap it opens ──"
if has "$CODE" '"myhostname="+host'; then
  ok "myhostname set from the panel vhost"
else
  bad "myhostname unset — HFILTER_HELO_5 costs 3 spam points"
fi
if has "$CODE" '"mydestination=localhost"' && hasre "$CODE" '^mydestination = localhost$'; then
  ok "mydestination narrowed to localhost in BOTH the postconf call and main.cf"
else
  bad "mydestination not narrowed — a hosted domain becomes local and bounces"
fi

echo "── E. a re-run must never erase hosted mail ──"
if hasre "$CODE" 'for _, p := range \[\]string\{mailPostfixVirtualDomains' && hasre "$CODE" 'if !mailExists\(p\) \{'; then
  ok "map files are created only when absent"
else
  bad "map files truncated unconditionally — a re-run erases every mailbox"
fi
if has "$CODE" '!strings.HasPrefix(t, "#") && strings.HasPrefix(t, "submission")'; then
  ok "submission guard tests for an ACTIVE entry, not the commented stock line"
else
  bad "submission guard back to substring match — re-runs duplicate the service"
fi

echo "── F. TLS the clients can actually verify ──"
if has "$CODE" 'func mailPanelTlsPaths()'; then
  ok "mailPanelTlsPaths() exists"
else
  bad "mailPanelTlsPaths() gone — Dovecot falls back to snakeoil"
fi
if has "$CODE" 'ssl_cert = <%s'; then
  ok "Dovecot is handed the real certificate when the box has one"
else
  bad "Dovecot ssl_cert no longer wired — Roundcube gets 'unknown ca'"
fi
# F-frame-ancestors retired: covered by TestPinWebmailSpamFragmentRedeclaresSameOriginFraming (panel/go/internal/agent/routes/pin_webmail_spam_test.go)

echo "── G. honest status ──"
if has "$(fnbody "$CODE" mailStatus)" '"configured": configured'; then
  ok "mailStatus reports whether the install actually configured the box"
else
  bad "mailStatus back to package-presence only — a failed install reads healthy"
fi

echo "── H. invariants this fix must not break ──"
if has "$UNIT" 'ProtectSystem=strict'; then
  ok "agent unit still hardened with ProtectSystem=strict"
else
  bad "sandbox weakened — the fix was supposed to work WITHIN it"
fi
# The fix must not have quietly bought its way out by widening the sandbox.
if hasre "$UNIT" '^ReadWritePaths=.*/etc/opendkim\.conf'; then
  bad "ReadWritePaths widened to /etc/opendkim.conf instead of relocating the config"
else
  ok "ReadWritePaths NOT widened for opendkim"
fi
# The property that matters is that Postfix can REACH the milter, not the
# mechanism. A unix socket under Postfix's spool is group-owned, so it needs
# gpasswd AND the unsandboxed escape (/etc/group is read-only to the agent). A
# loopback port needs neither — and is what s268 moved to, because the spool
# socket is a Debian-chroot artifact that SELinux forbids on RHEL. Accept
# either, reject a spool socket with no group grant.
if hasre "$CODE" 'mailOpendkimSocket[[:space:]]*=[[:space:]]*"inet:[0-9]+@127\.0\.0\.1"'; then
  ok "milter is a loopback port — reachable from inside Postfix's chroot and out, no group needed"
elif has "$CODE" 'mailUnsandboxed("gpasswd"'; then
  ok "group edit uses the documented unsandboxed escape (/etc/group is read-only)"
else
  bad "milter socket is group-owned but nothing adds postfix to the group — Postfix cannot reach it"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
