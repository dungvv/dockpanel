#!/usr/bin/env bash
# mail-authorisation-pin-e2e.sh — s348 / GitHub #106
#
# Pins the boundary that decides who may read and write a mail domain.
#
# WHY THIS SUITE EXISTS, measured rather than asserted: before it, the mail
# authorisation predicate had NO test coverage of any kind. Stripping the
# administrator role term out of the mail-domain caller predicate (now
# `rtMailMailDomainCallerPredicate`, panel/go/internal/api/rt_mail.go) — the single term
# that stood between any authenticated caller and every mailbox in the fleet —
# was run against the whole corpus at s348 and produced **0 red across 59 pin
# suites and 338 unit tests**. 397 checks, none of which noticed. A SQL string
# has no type and no unit test can reach it without a database, so the only thing
# that can guard it is a suite like this one.
#
#   §A  the ADMINISTRATOR arm — the role comes from the database, exactly one
#       role is admitted, and the server-ownership terms survive.
#   §B  the SITE-OWNER arm (#106) — the entitlement itself. The server term and
#       the distinct-owner quantifier are the two clauses that make it safe, and
#       both are one deletion away from a silent cross-tenant grant.
#   §C  the DOORS — which handlers a site owner reaches, and which must stay shut.
#       `rtMailUpdateDomain` writes `catch_all`, a mail-interception primitive; the
#       arm below is what stops a future session opening it "for symmetry".
#   §D  the ADDRESS SHAPE — the local part is a filesystem path component and a
#       Postfix map key, on both sides of the panel/agent seam.
#   §E  rtMailCreateDomain NAMES the account it grants mailboxes to.
#
# Pure source analysis: no box, no network, no build.

set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

MAIL="$REPO/panel/go/internal/api/rt_mail.go"
AGENT="$REPO/panel/go/internal/agent/routes/mail.go"

for f in "$MAIL" "$AGENT"; do
  [ -f "$f" ] || { echo "FATAL: missing subject $f"; exit 1; }
done

# Strip comments before measuring. A pin greps RAW SOURCE, so without this every
# arm below would match the sentence that DESCRIBES the check rather than the
# check — and this file's subjects are unusually heavily commented, precisely
# because the reasoning is the load-bearing part. Go comments: whole-line `//`
# and `/* */` blocks, plus trailing `//` not inside a URL or string.
code() {
  perl -0777 -pe '
    s{/\*.*?\*/}{}gs;
    s{^\s*//.*$}{}gm;
    s{(\s)//[^"\n]*$}{$1}gm;
  ' "$1"
}

has()         { grep -qE -- "$2" <<< "$1"; }
occurrences() { grep -oE -- "$2" <<< "$1" | wc -l; }

# Go keeps tests in separate _test.go files, so the subjects above ARE production
# code; the Rust-era `#[cfg(test)]` stripper has no Go meaning.

# The concatenation of every Go string literal in a text: a SQL string built as
# "a " + "b" + ... is measured as the string the database actually receives,
# rather than however it happens to be wrapped in the source.
golits() { perl -0777 -ne 'my $o=""; while (/"((?:[^"\\\n]|\\.)*)"/g) { $o .= $1 } print $o' <<< "$1"; }

# The VALUE of a `const NAME = "..." + "..."` (up to the first line that does
# not end in `+`), concatenated.
const_value() {
  golits "$(awk -v n="$2" 'index($0, "const " n " =") == 1 {i=1} i {print} i && !/\+[[:space:]]*$/ {exit}' <<< "$1")"
}

# The body of one top-level func (or method), bounded by its closing `}` at
# column 0 — never a fixed `-A n` window, which is not a function and has
# printed confident greens from the following function's text (lesson #131).
fnbody() {
  awk -v fn="$2" '
    !inb && (index($0, "func " fn "(") == 1 || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) {inb=1; next}
    inb && /^}/ {exit}
    inb {print}
  ' <<< "$1"
}

# The extractor a Go handler applies: its FIRST auth call. st.authUser is
# AuthUser; st.adminUser and rtMailAdminScope (AdminUser + ServerScope) are
# AdminUser. A later mention in the body cannot answer this question.
extractor_of() {
  fnbody "$1" "$2" | grep -oE 'st\.authUser\(|st\.adminUser\(|rtMailAdminScope\(' | head -1 \
    | sed -e 's/st\.authUser(/AuthUser/' -e 's/st\.adminUser(/AdminUser/' -e 's/rtMailAdminScope(/AdminUser/'
}

M=$(code "$MAIL")
A=$(code "$AGENT")
[ -n "$M" ] && [ -n "$A" ] || { echo "FATAL: comment stripper emptied a subject"; exit 1; }

PRED=$(const_value "$M" rtMailMailDomainCallerPredicate)

echo
echo "§A  the administrator arm"
if [ -z "$PRED" ]; then
  bad "§A: could not extract the mail authorisation predicate — every arm in §A and §B would pass having measured nothing"
else
  ok "extracted the mail authorisation predicate ($(printf '%s' "$PRED" | wc -c) chars)"

  # The role is read from the users TABLE, not from the token. A JWT keeps
  # asserting whatever role it was minted with until it expires, so a demoted
  # account would keep administering mail for the rest of its session. This
  # matters more now than it did: the handlers no longer take an admin-only
  # extractor, so the database is the ONLY thing deciding.
  if has "$PRED" "FROM users u" && has "$PRED" "u\.role = 'admin'"; then
    ok "the administrator arm reads the role from the users table"
  else
    bad "the administrator arm no longer tests the role against the users table — a demoted account keeps its access until its token expires"
  fi

  # EXACTLY ONE admitted role. A presence test cannot see a widening: the arm
  # this replaces asked only whether the administrator comparison was present,
  # and `role == "admin" || role == "client"` still contains it. Count.
  n=$(occurrences "$PRED" "u\.role[[:space:]]*=[[:space:]]*'")
  if [ "$n" -eq 1 ]; then
    ok "exactly one role is admitted by the predicate"
  else
    bad "the predicate compares users.role $n times — a second admitted role is a second class of caller reaching every mailbox on the server"
  fi

  # The administrator's reach stops at hardware they operate.
  if has "$PRED" 'sv\.is_local' && has "$PRED" 'sv\.user_id = u\.id'; then
    ok "the administrator arm stops at servers this administrator operates"
  else
    bad "the administrator arm lost its server-ownership terms — one administrator now reaches another administrator's fleet member"
  fi

  # ⚠ THE ARM FOR THE REGRESSION THAT LOOKS LIKE A TIDY-UP. A row naming no
  # server must stay reachable (agentForSiteServer answers 409 by name, and
  # rtMailSyncMailConfig's precondition counts exactly these rows) — but it must be
  # reachable only to an ADMINISTRATOR. As a free-standing first disjunct it
  # carried no caller term at all, which was harmless while every door was
  # admin-only and is a grant to every site owner in the installation now that
  # they are not. Presence alone is not enough; it must sit INSIDE the arm.
  if ! has "$PRED" 'md\.server_id IS NULL'; then
    bad "the no-server arm was deleted — a mail domain naming no server now 404s instead of reporting the 409 that tells the operator to backfill it"
  elif [[ "$PRED" =~ md\.id\ =\ \$1\ AND\ \(md\.server_id\ IS\ NULL ]]; then
    bad "the no-server arm is a free-standing disjunct again — it carries no caller term, so every authenticated caller reaches any mail domain that names no server"
  elif [ "$(printf '%s' "$PRED" | grep -bo "u.role" | head -1 | cut -d: -f1)" -lt \
          "$(printf '%s' "$PRED" | grep -bo 'md.server_id IS NULL' | head -1 | cut -d: -f1)" ]; then
    ok "the no-server arm is admitted inside the administrator arm, not in front of it"
  else
    bad "the no-server arm appears before the role test — it is not gated by it"
  fi
fi

echo
echo "§B  the site-owner arm (#106) — the entitlement"
if [ -n "$PRED" ]; then
  if has "$PRED" 'FROM sites s' && has "$PRED" 's\.user_id = \$2'; then
    ok "a mail domain is reachable by the owner of the site of the same name"
  else
    bad "the site-owner arm is gone — #106 is not implemented, or ownership stopped being what grants it"
  fi

  # ⚠⚠ THE SINGLE MOST IMPORTANT ARM IN THIS FILE. `sites` is UNIQUE on
  # (domain, server_id) and NOT on domain; so is `mail_domains`. Without the
  # server term, an administrator creating a mail domain on ANY machine in the
  # fleet hands every mailbox on it to whoever holds a site of that name on some
  # OTHER machine — an account with no relationship to that server at all. The
  # deletion is one clause and it has no symptom.
  if has "$PRED" 's\.server_id = md\.server_id'; then
    ok "the site-owner arm requires the site and the mail domain to be on the SAME server"
  else
    bad "the site-owner arm lost its server term — a site on one machine now grants its owner the mailboxes of a same-named mail domain on ANY OTHER machine in the fleet"
  fi

  # Case folding is one-sided (mail_domains is lowercased by its only writer;
  # sites.domain has been only since the domain-claim module), so the fold alone
  # would let two rows differing in case both match. The quantifier is what makes
  # that fail CLOSED instead of open. A normalising migration was rejected: the
  # unique index is on the raw column, so a bulk lowercase raises a duplicate key
  # on exactly the installs that have the problem, and a failed migration aborts
  # startup.
  if has "$PRED" 'lower\(s\.domain\) = md\.domain'; then
    ok "the site side is case-folded onto the mail domain's stored form"
  else
    bad "the case fold is gone — a legacy mixed-case site no longer matches its own mail domain"
  fi

  if has "$PRED" 'NOT EXISTS' && has "$PRED" 's2\.user_id <> \$2'; then
    ok "the arm refuses when any OTHER account owns a case-variant of the name"
  else
    bad "the distinct-owner quantifier is gone — with case folding on one side only, two accounts holding different casings of one name both satisfy the arm, and it fails OPEN"
  fi
fi

echo
echo "§C  the doors"
# Open to a site owner: the CRUD the reporter asked for, the list that feeds it,
# and the DNS read the page fires on every domain click (without it a client's
# DNS tab paints blank and silently, which is the one screen they need to publish
# DKIM and SPF).
for h in rtMailListDomains rtMailDomainDns rtMailListAccounts rtMailCreateAccount rtMailUpdateAccount \
         rtMailDeleteAccount rtMailListAliases rtMailCreateAlias rtMailDeleteAlias; do
  e=$(extractor_of "$M" "$h")
  case "$e" in
    AuthUser) ok "$h is reachable by a site owner" ;;
    "")       bad "$h: could not read an extractor from its signature — the arm measured nothing" ;;
    *)        bad "$h took $e — the #106 entitlement does not reach it" ;;
  esac
done

# ⚠ These must STAY shut, and the reasons are not symmetric with the list above.
# `rtMailUpdateDomain` is the only writer of `catch_all`, which redirects a whole
# domain's mail; `rtMailCreateDomain` mints the entitlement itself; `rtMailDeleteDomain`
# destroys mailboxes; the two DNS-verification endpoints reach the network on the
# caller's behalf. Each is one word away from being opened "for consistency".
for h in rtMailCreateDomain rtMailUpdateDomain rtMailDeleteDomain rtMailDnsCheck rtMailPreflight; do
  e=$(extractor_of "$M" "$h")
  case "$e" in
    AdminUser) ok "$h remains administrator-only" ;;
    "")        bad "$h: could not read an extractor from its signature — the arm measured nothing" ;;
    *)         bad "$h now takes $e — a site owner reaches a door that was deliberately left shut" ;;
  esac
done

# The list query's two branches must be parenthesised against each other. AND
# binds tighter than OR in SQL, so an unparenthesised pair silently attaches any
# appended term to the second disjunct alone — which is how the previous shape
# would have absorbed the owner branch while appearing to carry it.
# ⚠ The list and the per-row predicate are TWO COPIES OF ONE RULE. The list
# cannot bind `$1` to a row id, so its owner test is inlined rather than shared —
# and an inlined copy is precisely the thing that drifts. Asserting that each
# copy merely "mentions sites" is not enough: flipping `s.user_id = $2` to `<> $2`
# in the list alone leaves both mentions intact and returns every mail domain the
# caller does NOT own. Measured SURVIVING when this arm was written that way.
#
# So the two are compared to each other, normalised. Drift in either direction
# fails, and neither can be widened without the other noticing.
norm()         { tr -s ' \n\\' ' ' <<< "$1" | sed 's/^ *//; s/ *$//'; }
owner_clause() { grep -oE 'EXISTS \( ?SELECT 1 FROM sites s WHERE.*s2\.user_id <> \$2\)' <<< "$(norm "$1")"; }

LD=$(golits "$(fnbody "$M" rtMailListDomains)")
if [ -z "$LD" ]; then
  bad "§C: could not extract rtMailListDomains"
else
  # The list has an ADMINISTRATOR branch of its own — it is the only place the
  # `ServerScope`-scoped fleet-wide read still happens — and that branch has its
  # own role test, separate from the predicate's. Stripping it shows every mail
  # domain on the scoped server to any authenticated caller, and the owner-clause
  # comparison below cannot see it. Measured SURVIVING before this arm existed.
  ln=$(occurrences "$LD" "u\.role[[:space:]]*=[[:space:]]*'")
  if [ "$ln" -eq 1 ]; then
    ok "the domain list's administrator branch admits exactly one role"
  else
    bad "the domain list tests users.role $ln times — at 0 every authenticated caller receives the administrator's fleet-scoped list; above 1 a second class of caller does"
  fi

  LC=$(owner_clause "$LD")
  PC=$(owner_clause "$PRED")
  if [ -z "$LC" ] || [ -z "$PC" ]; then
    bad "§C: could not extract the owner clause from the list ($([ -n "$LC" ] && echo found || echo missing)) or the predicate ($([ -n "$PC" ] && echo found || echo missing)) — the comparison below would pass having compared nothing"
  elif [ "$LC" = "$PC" ]; then
    ok "the domain list applies the owner test VERBATIM as the per-row predicate does"
  else
    bad "the domain list's owner test has drifted from the predicate's — one of them now answers a different question about who owns a mail domain"
    printf '      list:      %s\n' "$(printf '%s' "$LC" | cut -c1-90)"
    printf '      predicate: %s\n' "$(printf '%s' "$PC" | cut -c1-90)"
  fi
fi

echo
echo "§D  the address shape, on both sides of the seam"
# The character-set check tests the WHOLE STRING for non-emptiness, never the
# local part. Every call site must go through the structural check instead, or
# `@example.com` collides with the domain's catch-all key in virtual_mailbox_maps
# and `..@example.com` resolves one level above the domain's maildir.
MP="$M"
if [ -z "$MP" ] || ! has "$MP" 'const rtMailMailDomainCallerPredicate'; then
  bad "§D: the comment stripper removed production code — every count below would be measured against a truncated subject"
else
  n=$(occurrences "$MP" 'rtMailIsWellformedAddress\(|rtMailIsWellformedAddressList\(')
  if [ "$n" -ge 8 ]; then
    ok "every mail address door goes through the structural check ($n uses in production code)"
  else
    bad "only $n structural address checks in production mail-route code — 8 are expected (2 definitions, 1 internal call, and the 5 doors: catch-all, account address, forward, alias source, alias destination)"
  fi

  # The bare character-set check must not be reachable from a door any more. It
  # is kept only as the inner half of the structural check, so more than one
  # production use means a door skipped the structure.
  b=$(occurrences "$MP" 'rtMailIsValidMailAddress\(')
  if [ "$b" -le 2 ] && [ "$b" -ge 1 ]; then
    ok "the bare character-set check is no longer used as a door's validator ($b production uses)"
  else
    bad "$b production uses of the character-set-only check — a door is validating an address without checking it has a local part (or the check vanished and this count measured nothing)"
  fi
fi

# §D panel-local-part retired: covered by TestMailTheDegenerateLocalPartsAreRefused (panel/go/internal/api/rt_mail_test.go)

# The agent builds the path, so the agent checks independently. A panel-side
# guard alone is one direct agent call away from irrelevant. (Its verdicts are
# TestMailLocalPartAndHelpers in panel/go/internal/agent/routes/mail_test.go;
# this arm pins that the sync actually calls it at both doors.)
if has "$A" 'func mailLocalPartIsSafe\(' && [ "$(occurrences "$A" 'mailLocalPartIsSafe\((acc\.Email|a\.Source)\)')" -ge 2 ]; then
  ok "the agent independently refuses the same local parts, on accounts and alias sources"
else
  bad "the agent no longer checks the local part it joins into /var/vmail and writes as a Postfix map key"
fi

echo
echo "§E  the grant is disclosed"
CD=$(golits "$(fnbody "$M" rtMailCreateDomain)")
if [ -z "$CD" ]; then
  bad "§E: could not extract rtMailCreateDomain"
elif has "$CD" 'FROM sites s JOIN users u' && has "$CD" "u\.role <> 'admin'"; then
  ok "creating a mail domain names the non-administrator it hands the mailboxes to"
else
  bad "creating a mail domain no longer reports who it grants — the claim guard only covers the other direction, so this write is a silent entitlement grant"
fi

echo
echo "──────────────────────────────────────────"
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" -eq 0 ]
