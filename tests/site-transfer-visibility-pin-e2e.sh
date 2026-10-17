#!/usr/bin/env bash
# site-transfer-visibility-pin-e2e.sh — s314 / v2.71.0 (D3 added v2.71.1)
#
# Pins the fix for a handover that was a ONE-WAY DOOR, and for the reason the
# role it created could not be used at all.
#
# v2.69.0 shipped `client` + an admin-only site Transfer. Ownership is a single
# axis, so `list` and every per-site read are `WHERE user_id = $1` with no role
# branch — correct, and the whole reason the role needed no other change. But it
# meant that the instant an admin handed a site over, the row left their list,
# the detail page answered 404, and the Transfer control — rendered ONLY on that
# page — became unreachable. There was no way back through the panel. The guide
# and the handler's own doc comment both promised the opposite. Reported from the
# field on #51 by the operator who had just used the feature.
#
#   §A  the admin all-sites READ exists, is admin-gated, is server-scoped, and is
#       a narrow PROJECTION — never `Site`, which is FromRow over `SELECT *` and
#       is bound at three dozen call sites.
#   §B  and ownership is NOT widened anywhere else. This is the arm that matters
#       in the long run: the temptation, next time, is to add `OR role='admin'`
#       to the reads themselves. Subject list COMPUTED, never written here.
#   §C  the way back is REACHABLE — the all-sites list can transfer, and the
#       recipient is PICKED, not typed.
#   §D  the cross-account server-id leak is closed at both ends.
#   §E  the two prose surfaces that promised admin visibility no longer do, and
#       do describe the way back.
#
# Backend subjects are the Go API: panel/go/internal/api/rt_sites.go
# (rtSitesListForAdmin, rtSitesList, route registration) and core_helpers.go
# (SiteCallerPredicate, siteDomainForCaller), ported from the Rust
# routes/sites.rs, routes/mod.rs and helpers.rs.
#
# Pure source analysis: no box, no network, no build.
#
# ⚠ §A and §C1/§C2 are arms over subjects that DID NOT EXIST at v2.70.0, so "red
# at the previous tag" is trivially true for them and proves little (lesson
# #222). The load-bearing ones are §B (a NEGATIVE arm, green at both tags, whose
# job is to go red on a future widening) and §D/§E (red at v2.70.0 on the real
# defect). §B was MUTATION-TESTED at HEAD instead — see the note above it.
#
# ⚠ Every arm whose subject is a STATEMENT reads the file WHOLE (lesson #230):
# `grep -E` is line-based and this suite's subjects — a Rust fn signature, a SQL
# string, a JSX attribute — are all routinely written across lines. (Rust era:
# a fn signature; Go: a concatenated SQL string.)
#
# NO PIPES INTO `grep -q` — under `set -o pipefail` grep -q closes the pipe on
# its first match and the arm goes red on correct code. Every arm uses a
# here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

API=panel/go/internal/api
SITES=$API/rt_sites.go
MOD=$API/rt_sites.go
SITESTSX=panel/frontend/src/pages/Sites.tsx
DETAIL=panel/frontend/src/pages/SiteDetail.tsx
SRVCTX=panel/frontend/src/context/ServerContext.tsx
AUTHCTX=panel/frontend/src/context/AuthContext.tsx
GUIDE=docs/guides/roles-and-ownership.md

for f in "$SITES" "$MOD" "$SITESTSX" "$DETAIL" "$SRVCTX" "$AUTHCTX" "$GUIDE"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT. Copied from the FIXED stripper (lesson #136): the
# naive s{/\*.*?\*/}{}gs deletes real code because `/*` occurs inside string
# literals, and a truncated subject makes an ABSENCE arm pass on code the
# stripper merely removed — failure in the reassuring direction.
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
    s{^\s*///.*$}{}gm;
  ' "$1"
}

subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }

# The body of one top-level Go func (or method), bounded by its own column-0
# closing brace. A fixed `grep -A n` window is not a function (lesson #131/#172).
# In Go the auth gate is a call in the body (st.adminUser / st.authUser), not an
# extractor in the signature, so the old Rust `fnsig` has no Go counterpart.
fnbody() {
  awk -v name="$2" '
    !inside && (index($0, "func " name "(") == 1 || $0 ~ ("^func [(][^)]*[)] " name "[(]")) { inside=1 }
    inside { print }
    inside && /^}/ { exit }
  ' <<< "$1"
}

S=$(subj "$SITES") || bad "rt_sites.go stripped to nothing"

echo "== §A  the admin all-sites read: gated, scoped, and a projection =="

A_BODY=$(fnbody "$S" rtSitesListForAdmin)
A_SIG="$A_BODY"

if [ -z "$A_SIG" ]; then
  bad "A1 sites::list_for_admin exists"
  bad "A2 list_for_admin is ADMIN-gated (AdminUser, not AuthUser)"
  bad "A3 list_for_admin is server-scoped and deliberately NOT user-scoped"
  bad "A4 list_for_admin returns a narrow projection, never Site"
else
  ok "A1 sites::list_for_admin exists (Go: rtSitesListForAdmin)"

  # AdminUser, and NOT AuthUser. An AuthUser gate here would hand every
  # account every site on the box — the exact inversion this route must not be.
  if grep -qE 'st\.adminUser\(r\)' <<< "$A_SIG" && ! grep -qE 'st\.authUser\(' <<< "$A_SIG"; then
    ok "A2 list_for_admin is ADMIN-gated (AdminUser, not AuthUser)"
  else
    bad "A2 list_for_admin is ADMIN-gated (AdminUser, not AuthUser)"
  fi

  # Server-scoped yes; user-scoped no. Both halves matter: without the server
  # scope a fleet admin sees another box's rows, and WITH a user scope the route
  # is pointless because it returns exactly what `list` already did.
  if grep -qE 'st\.serverScope\(r\)' <<< "$A_SIG" \
  && grep -qE 's\.server_id = \$1' <<< "$A_BODY" \
  && ! grep -qE 'user_id = \$' <<< "$A_BODY"; then
    ok "A3 list_for_admin is server-scoped and deliberately NOT user-scoped"
  else
    bad "A3 list_for_admin is server-scoped and deliberately NOT user-scoped"
  fi

  # The projection is a SEPARATE struct. `Site` is scanned from `SELECT *`; a
  # field with no column breaks every `Site`-typed binding in the package at
  # runtime, and a Site carrying an owner would eventually be handed to a
  # handler whose whole job is to ask "is this yours?".
  if grep -qE 'queryAll\[rtSitesAdminSiteRow\]' <<< "$A_SIG" \
  && grep -qE '^type rtSitesAdminSiteRow struct' <<< "$S" \
  && ! grep -qE 'query(All|One|Opt)\[Site\]' <<< "$A_SIG"; then
    ok "A4 list_for_admin returns a narrow projection, never Site"
  else
    bad "A4 list_for_admin returns a narrow projection, never Site"
  fi
fi

# Registered, and at an admin-namespaced path. Read whole: a .route(...) call
# routinely wraps.
M=$(subj "$MOD") || bad "rt_sites.go stripped to nothing"
if grep -qE 'r\.Handle\("GET /api/admin/sites",[[:space:]]*h\(rtSitesListForAdmin\)\)' <<< "$M"; then
  ok "A5 GET /api/admin/sites is registered to sites::list_for_admin"
else
  bad "A5 GET /api/admin/sites is registered to sites::list_for_admin"
fi

echo "== §B  site access has ONE definition, and its admin arm is bounded =="

# s315 REWROTE this section, and the reason matters more than the arms.
#
# §B used to assert that `list`, `get_one` and `remove` each still contained the
# token `user_id = $`. Its own comment said it existed because "the temptation,
# next time, is to add OR role='admin' to the reads themselves" — and it could not
# have caught that. Every realistic widening ADDS a disjunct and leaves the token
# in place. Reproduced: the mutation this suite recorded as proof of non-vacuity
# (` OR $1 = $1` appended to get_one) left ALL FOUR arms green.
#
# The s314 ledger claimed a mutation test had proven the arm. It had proven the
# DELETION case, which the arm does catch; the arm exists for the WIDENING case,
# which it did not. Write down what a reader thinks the pin proves, then mutate
# THAT.
#
# B-remove was worse: it stayed green through the s315 change while measuring
# nothing, because `remove`'s body contains an unrelated `user_id = $` (the
# reseller slot release). A file-wide token search inside a function is the same
# false green as a file-wide search inside a file.
#
# So the invariant is no longer "every reader spells a predicate". It is: there is
# exactly ONE predicate, it lives in one place, its admin arm is bounded by the
# machine, and it trusts the database rather than the token.

HELPERS=$API/core_helpers.go
[ -f "$HELPERS" ] || bad "MISSING SUBJECT FILE: $HELPERS"
H=$(subj "$HELPERS") || bad "core_helpers.go stripped to nothing"
HRAW=$(perl -0777 -pe 's/\s+/ /g' "$HELPERS")

# B1  ONE definition of the predicate, and it is in core_helpers.go (and
# nowhere else in the package — Go's flat package would compile a second one
# under a different name just as happily).
NDEF=$(grep -c '^const SiteCallerPredicate = ' <<< "$H")
NDEF_ALL=$(grep -lE '^const SiteCallerPredicate|SiteCallerPredicate *= *"' "$API"/*.go 2>/dev/null | grep -vc '_test\.go$')
if [ "$NDEF" -eq 1 ] && [ "$NDEF_ALL" -eq 1 ]; then
  ok "B1 the site-access predicate is defined exactly once, in core_helpers.go"
else
  bad "B1 the site-access predicate is defined exactly once, in core_helpers.go (found $NDEF there, $NDEF_ALL files)"
fi

# B2  NOBODY carries an owner-only site lookup any more. Eight private helpers
# used to — two `site_domain`, four `get_site_domain`, two `get_site` — and one of
# the eight had drifted into being server-scoped while the others were not.
# CONTROL first: the replacement must be present, or a zero below means the tree
# moved rather than that the class is closed (lesson #143 / asserting a zero).
API_SRC=$(ls "$API"/*.go | grep -v '_test\.go$')
NUSE=$(grep -c 'SiteCallerPredicate\|siteDomainForCaller' $API_SRC 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
NOLD=$(grep -c 'FROM sites WHERE id = \$1 AND user_id = \$2' $API_SRC 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
if [ "$NUSE" -lt 12 ]; then
  bad "B2 CONTROL failed: only $NUSE references to the shared resolver — the arm below would be vacuous"
elif [ "$NOLD" -eq 0 ]; then
  ok "B2 no module carries its own owner-only site lookup ($NUSE share the one predicate)"
else
  bad "B2 no module carries its own owner-only site lookup — $NOLD copies came back"
fi

# B3  The admin arm is bounded by the MACHINE. Without both tokens the predicate
# reads "any administrator, any site on this panel", which is a different and
# much larger grant than the one that was decided.
if grep -qE 'sv\.is_local' <<< "$HRAW" && grep -qE 'sv\.user_id = u\.id' <<< "$HRAW"; then
  ok "B3 the admin arm is bounded to the local box or a server that admin registered"
else
  bad "B3 the admin arm is bounded to the local box or a server that admin registered"
fi

# B4  The role is read from the DATABASE, not from the token. A JWT keeps
# asserting the role it was minted with, so a demoted account would otherwise go
# on acting as an administrator until its session expired.
if grep -qE "u\.role = 'admin'" <<< "$HRAW"; then
  ok "B4 the admin arm reads users.role from the database"
else
  bad "B4 the admin arm reads users.role from the database"
fi
# FLATTENED (#383). A formatter can break a long field-access chain at the `.`,
# which a line-oriented pattern reads as absence — silently, in the reassuring
# direction. Flatten $H (the COMMENT-STRIPPED text), never $HRAW: HRAW carries
# the doc comment explaining why the token's claim is NOT read, and would pin
# this arm permanently red on correct code. Go spells the claim c.Role /
# claims.Role (Claims.Role in core_auth.go).
# The failure message also used to be the SUCCESS sentence, so a red described the
# state it was complaining about the absence of. A red that misnames its cause is
# a red nobody can act on.
HFLAT=$(tr '\n' ' ' <<< "$H" | tr -s ' ')
if grep -qE '(claims|\bc) *\. *[Rr]ole' <<< "$HFLAT"; then
  bad "B5 core_helpers.go still consults the token's role claim to decide site access — a demoted account keeps its old reach until the session expires"
else
  ok "B5 core_helpers.go decides site access without consulting the token's role claim"
fi

# B6  The admin's OWN Sites page is not widened. The window onto other people's
# sites is the all-sites toggle (§A); conflating the two would make an operator's
# own list unreadable on a busy box, and it is not what was asked for.
LIST_BODY=$(fnbody "$S" rtSitesList)
if [ -z "$LIST_BODY" ]; then
  bad "B6 sites::list exists"
elif grep -qE 'user_id = \$1 AND server_id = \$2' <<< "$LIST_BODY"; then
  ok "B6 sites::list is still scoped to the caller AND the server"
else
  bad "B6 sites::list is still scoped to the caller AND the server — the admin's own page was widened"
fi

echo "== §C  the way back is reachable, and the recipient is picked =="

ST=$(subj "$SITESTSX") || bad "Sites.tsx stripped to nothing"
DT=$(subj "$DETAIL")    || bad "SiteDetail.tsx stripped to nothing"

if grep -qE '"/admin/sites"' <<< "$ST"; then
  ok "C1 Sites.tsx fetches the admin all-sites view"
else
  bad "C1 Sites.tsx fetches the admin all-sites view"
fi

# Transfer must be reachable from the LIST, not only from the detail page. That
# is the entire defect: a control rendered only on a page the admin can no
# longer open can give a site away and never take it back.
if grep -qE 'sites/\$\{transferFor\.id\}/transfer' <<< "$ST"; then
  ok "C2 Sites.tsx can transfer a site it does not own (the way back)"
else
  bad "C2 Sites.tsx can transfer a site it does not own (the way back)"
fi

# Picked, not typed, on BOTH surfaces. `transfer` answers 404 on an unknown
# address, so a text field can only fail after the fact.
if grep -qE 'transferTargets\.map' <<< "$DT" \
&& ! grep -qE 'type="email"[^>]*transferEmail|transferEmail[^>]*type="email"' <<< "$(perl -0777 -pe 's/\s+/ /g' <<< "$DT")"; then
  ok "C3 SiteDetail picks the recipient from the account list, not free text"
else
  bad "C3 SiteDetail picks the recipient from the account list, not free text"
fi

echo "== §D  the cross-account server-id leak is closed at both ends =="

SC=$(subj "$SRVCTX")  || bad "ServerContext.tsx stripped to nothing"
AC=$(subj "$AUTHCTX") || bad "AuthContext.tsx stripped to nothing"

# The self-heal: an account whose server list cannot back the stored id must
# DROP it. Without this branch a client inherits the admin's server id from
# localStorage and ServerScope refuses every request.
#
# ⚠ SCOPED TO fetchServers, and that scoping is the whole arm. The file-wide
# version of this check was GREEN at v2.70.0 — on the defect — because
# `setActiveServerId` has always had a removeItem for the manual clear path. It
# matched the wrong occurrence and tested nothing. Caught by running the suite
# at the previous tag, which is the only reason it is written this way.
FETCH=$(perl -0777 -ne 'print $1 if /const fetchServers\s*=\s*useCallback\(async \(\)\s*=>\s*\{(.*?)\n\s*\}, \[\]\);/s' <<< "$SC")
if [ -z "$FETCH" ]; then
  bad "D1 ServerContext clears a stored server id its own list cannot back — fetchServers closure not found"
elif grep -qE 'removeItem\("dp-active-server"\)' <<< "$FETCH"; then
  ok "D1 ServerContext clears a stored server id its own list cannot back"
else
  bad "D1 ServerContext clears a stored server id its own list cannot back"
fi

# And the source: the value must not survive a sign-out into the next account.
# Scoped to the logout closure rather than the file, so the arm cannot be
# satisfied by an unrelated removeItem elsewhere in the context.
LOGOUT=$(perl -0777 -ne 'print $1 if /const logout\s*=\s*\(\)\s*=>\s*\{(.*?)\n\s*\};/s' <<< "$AC")
if [ -z "$LOGOUT" ]; then
  bad "D2 AuthContext drops the selected server on logout — logout closure not found"
elif grep -qE 'removeItem\("dp-active-server"\)' <<< "$LOGOUT"; then
  ok "D2 AuthContext drops the selected server on logout"
else
  bad "D2 AuthContext drops the selected server on logout"
fi

# And the self-heal must run when the ACCOUNT changes, not only at boot. Signing
# in is an SPA state change, not a remount, so an effect keyed on mount alone
# leaves the previous account's selection in place until the 60s poll — long
# enough for a client's first screen to fail on a fix that had already shipped.
EFFECT=$(perl -0777 -ne 'print $1 if /useEffect\(\(\)\s*=>\s*\{\s*fetchServers\(\);(.*?)\}, \[([^\]]*)\]\);/s' <<< "$SC")
DEPS=$(perl -0777 -ne 'print $1 if /fetchServers\(\);.*?\}, \[([^\]]*)\]\);/s' <<< "$SC")
if grep -qE 'user\?\.id' <<< "$DEPS"; then
  ok "D3 the server list is re-read when the signed-in account changes"
else
  bad "D3 the server list is re-read when the signed-in account changes"
fi

echo "== §E  the prose no longer promises what the code does not do =="

# Read WHOLE: the retired claim was a sentence spanning two lines, which is
# exactly what a line-wise grep cannot see (lesson #230). SDOC is the Go
# rt_sites.go, which carries the ported transfer doc comment.
G=$(perl -0777 -pe 's/\s+/ /g' "$GUIDE")
SDOC=$(perl -0777 -pe 's/\s+/ /g' "$SITES")

# ⚠ These are ABSENCE arms, so they match COMMENTS as readily as code
# (feedback_source_pin_prose_trap). Neither the guide nor rt_sites.go may spell the
# retired sentence, even to say it was retired — both were reworded to describe
# it instead.
if ! grep -qE 'admins see everything' <<< "$G"; then
  ok "E1 the guide no longer promises an admin sees every site"
else
  bad "E1 the guide no longer promises an admin sees every site"
fi

if grep -qE 'All sites on this server' <<< "$G"; then
  ok "E2 the guide names the control that makes a transfer reversible"
else
  bad "E2 the guide names the control that makes a transfer reversible"
fi

if ! grep -qE 'sees them by being' <<< "$SDOC"; then
  ok "E3 transfer's doc comment no longer claims the role preserves the view"
else
  bad "E3 transfer's doc comment no longer claims the role preserves the view"
fi

# The reseller row promised sub-accounts' SITES; the dashboard returns a COUNT.
if ! grep -qE 'Its own sub-accounts and their sites' <<< "$G"; then
  ok "E4 the guide no longer promises a reseller sees its sub-accounts' sites"
else
  bad "E4 the guide no longer promises a reseller sees its sub-accounts' sites"
fi

echo
echo "site-transfer-visibility: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
