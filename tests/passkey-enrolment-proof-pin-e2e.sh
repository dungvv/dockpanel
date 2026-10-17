#!/usr/bin/env bash
# passkey-enrolment-proof-pin-e2e.sh — s327
#
# ONE PROPERTY: a session alone cannot plant a credential that outlives every
# reset the panel offers.
#
#   §A  THE GUARD IS ON THE ENROLMENT DOOR, BEFORE THE CREDENTIAL IS MINTED.
#       ← the headline
#       `register_begin` (Go: rtPasskeysRegisterBegin) was `AuthUser` and nothing else. A hijacked session
#       could enrol a passkey, and passkey sign-in deliberately skips the 2FA
#       step, so the result was a PERMANENT 2FA-free door. Nothing evicts it:
#       `reset_password`, the s326 `reset_2fa` and `revoke_all_user_sessions`
#       all leave the row in `passkeys` untouched and immediately usable, and
#       rotating the JWT secret does not help because the credential mints fresh
#       tokens under the new one. Only deleting the account removes it.
#
#   §B  THE REFUSAL IS MACHINE-DISTINGUISHABLE, AND IT IS NOT A 401.
#       The frontend intercepts EVERY 401 globally, navigates to /login and
#       throws a fixed "Unauthorized" before the body is parsed. A 401 here
#       would log the user out of the page they are standing on the first time
#       they mistyped a password, and destroy the challenge on the way.
#
#   §C  EVERY ACCOUNT SHAPE CAN ANSWER.
#       The branches are NON-EXCLUSIVE on purpose. The security-hardening guide
#       tells a sole administrator who lost both authenticator and recovery
#       codes to register a passkey — that is the documented way back. Demanding
#       a TOTP code here would refuse exactly those accounts at exactly the door
#       that repairs them, which is the correction `twofa_disable` already had
#       to be given (Go: rtAuthRequireEnrolmentProof). And an identity-provider account has an EMPTY password hash
#       by construction, so a naive "confirm your password" would bar it from
#       passkeys permanently — a subtraction wearing a safeguard's clothes.
#
#   §D  THE NUMBERS. Every arm here extracts with a CAPTURE GROUP and owes a
#       mutation that CHANGES the number (s326 #302: `grep -oE '[0-9]+' | head -1`
#       over `[u8; 8]` returns the 8 in `u8`, so a cross-tree arm compared 16
#       against a hardcoded 16 and passed on EVERY tree).
#
#   §E  THE FRONTEND CAN ACTUALLY SHOW IT.
#
#   §F  ENROLMENT IS NOT SILENT. Silence is what makes a planted credential
#       durable; the activity log is not a surface anyone watches.
#
#   §G  CONTEXT — arms green at BOTH tags, so a harness measuring nothing cannot
#       read as a pass. Each owes its own mutation (s324 #292).
#
# ⚠ NOT SHIPPED, DELIBERATELY, and G2 pins that: a "last remaining factor" guard
# on `delete_passkey` (Go: rtPasskeysDeletePasskey). The census killed it. The traced attacker ADDS a
# credential and never deletes one; the handler is `AuthUser`-gated so lost
# hardware cannot reach it at all; no account can reach zero doors by deleting a
# passkey (`oauth_provider` is only ever set, never cleared, and a password hash
# is only ever overwritten with a real one); and the one real lockout shape has
# three recovery paths. Refusing the delete would take the recovery path away
# from the accounts most likely to need it — the same argument the panel already
# writes above `reset_2fa`.
#
# RUN AGAINST v2.84.0: the §G arms are green by design and each was killed by
# its own mutation. Everything else is RED there.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=============================================="
echo "  Passkey enrolment proof — source pins (s327)"
echo "=============================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

# Strip comments before matching, or an arm can be satisfied by the prose that
# NARRATES it — and this ship writes long comments into the very files it pins.
# ⚠ Copied from the FIXED stripper (s294): a block comment is recognised only
# where one is written, or a `/*` inside a string literal eats the file.
code() {
  [ -f "$1" ] || return 0
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
    s{\{/\*.*?\*/\}}{}gs;
  ' "$1"
}

raw() { [ -f "$1" ] && cat "$1" || true; }
has() { grep -qE -- "$2" <<< "$1"; }
hasf() { grep -qF -- "$2" <<< "$1"; }

# A Go function body, bounded on ITS OWN braces, anchored on `func NAME(` (or a
# method `func (x *T) NAME(`) so a rename to a longer name cannot survive on the
# prefix (s325 #299).
fnbody() {
  awk -v fn="$2" '
    (index($0, "func " fn "(") == 1 || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) && !started { started=1 }
    started {
      n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth += n - m; print
      if (opened || n>0) opened=1
      if (opened && depth<=0) exit
    }
  ' <<< "$1"
}

# The TSX twin. ⚠ `fnbody` CANNOT be used on a React component: it anchors on
# `func NAME(` at column 0, and `export function TwoFactorCard() {` is neither.
# (The Rust-era fnbody anchored on `fn NAME(` — "function" ends in `on`, not `fn`.) E5 was written with `fnbody`
# first, extracted an EMPTY body, and therefore passed on every possible tree.
# It was caught only by running the suite against the previous tree and asking
# why a supposedly-new property was already green (s326 #302, #303).
tsxbody() {
  awk -v fn="$2" '
    index($0, "function " fn "(") && !started { started=1 }
    started {
      n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth += n - m; print
      if (opened || n>0) opened=1
      if (opened && depth<=0) exit
    }
  ' <<< "$1"
}

PASSKEYS=panel/go/internal/api/rt_passkeys.go
AUTH=panel/go/internal/api/rt_auth.go
ERRFILE=panel/go/internal/api/core_error.go
CARDS=panel/frontend/src/components/AccountSecurity.tsx
APITS=panel/frontend/src/api.ts
GUIDE=docs/guides/security-hardening.md

PASSKEYS_C=$(code "$PASSKEYS")
AUTH_C=$(code "$AUTH")
ERR_C=$(code "$ERRFILE")
CARDS_C=$(code "$CARDS")
APITS_C=$(code "$APITS")
GUIDE_R=$(raw "$GUIDE")

BEGIN_BODY=$(fnbody "$PASSKEYS_C" "rtPasskeysRegisterBegin")
COMPLETE_BODY=$(fnbody "$PASSKEYS_C" "rtPasskeysRegisterComplete")
PROOF_BODY=$(fnbody "$AUTH_C" "rtAuthRequireEnrolmentProof")
REFUSAL_BODY=$(fnbody "$AUTH_C" "rtAuthReauthRequired")

# Every arm below greps one of these bodies; an empty one makes the absence arms
# green on any tree (s327 #308).
if [ -z "$BEGIN_BODY" ] || [ -z "$COMPLETE_BODY" ] || [ -z "$PROOF_BODY" ] || [ -z "$REFUSAL_BODY" ]; then
  bad "FATAL a body extracted EMPTY (begin=${#BEGIN_BODY} complete=${#COMPLETE_BODY} proof=${#PROOF_BODY} refusal=${#REFUSAL_BODY}) — every arm below would be vacuous"
  echo; printf '  PASS %d   FAIL %d\n' "$PASS" "$FAIL"; exit 1
fi

# ── §A the guard is on the enrolment door ───────────────────────────────────
echo "── §A the guard is on the door that plants the credential ──"

if has "$BEGIN_BODY" 'rtAuthRequireEnrolmentProof\('; then
  ok "A1 the enrolment door demands a proof"
else
  bad "A1 rtPasskeysRegisterBegin does not call rtAuthRequireEnrolmentProof — a session alone can plant a permanent credential"
fi

# ORDER, not presence: a guard placed after the challenge is minted still
# satisfies A1 while guarding nothing.
G_OFF=$(grep -n 'rtAuthRequireEnrolmentProof(' <<< "$BEGIN_BODY" | head -1 | cut -d: -f1)
C_OFF=$(grep -n 'rtPasskeysGenerateChallenge()' <<< "$BEGIN_BODY" | head -1 | cut -d: -f1)
if [ -n "$G_OFF" ] && [ -n "$C_OFF" ] && [ "$G_OFF" -lt "$C_OFF" ]; then
  ok "A2 the guard runs before a challenge is minted (line $G_OFF < $C_OFF)"
else
  bad "A2 the guard does not precede rtPasskeysGenerateChallenge (guard=${G_OFF:-none} challenge=${C_OFF:-none}) — a refused caller still gets a challenge"
fi

# A3 is a MEMBERSHIP test, never a count. A count is satisfied by the very
# defect it guards (s326 #303): one guarded handler plus one unguarded one still
# totals two. Keyed on CONSTRUCTION-and-store, because rtPasskeysRegisterComplete
# reads the same variant (`ch.Registration`) and would otherwise be discovered as a member
# that legitimately holds no guard.
MEMBERS=""
while IFS= read -r fname; do
  b=$(fnbody "$PASSKEYS_C" "$fname")
  hasf "$b" 'rtPasskeysChallenge{Registration: true' || continue
  hasf "$b" 'rtPasskeysStoreChallenge(' || continue
  MEMBERS="$MEMBERS $fname"
    # ⚠ The character class MUST admit digits. Written `[a-z_]+` first, which
    # silently skipped any handler whose name carries one — a `rtPasskeysRegisterBeginV2`
    # was invisible, so the sweep reported "1 handler, all guarded" with an
    # unguarded second one sitting beside it. Found by the mutation that adds
    # exactly that handler (s326 #302: the dangerous extractor is the one that
    # fails GREEN).
done < <(grep -oE '^func (\([^)]*\) )?[A-Za-z0-9_]+\(' <<< "$PASSKEYS_C" | sed -E 's/^func (\([^)]*\) )?([A-Za-z0-9_]+)\(/\2/' | sort -u)
MEMBERS=$(echo $MEMBERS)
N_MEMBERS=$(wc -w <<< "$MEMBERS")

# An arm that ENUMERATES its own subjects must assert the enumeration first, or
# a broken pattern reads as a clean sweep (s295 #143).
if [ "$N_MEMBERS" -ge 1 ]; then
  ok "A3a discovered $N_MEMBERS handler(s) that mint a registration challenge:$MEMBERS"
else
  bad "A3a discovered NO registration-challenge handler — the pattern broke and A3b is vacuous"
fi

UNGUARDED=""
for f in $MEMBERS; do
  b=$(fnbody "$PASSKEYS_C" "$f")
  has "$b" 'rtAuthRequireEnrolmentProof\(' || UNGUARDED="$UNGUARDED $f"
done
if [ "$N_MEMBERS" -ge 1 ] && [ -z "$UNGUARDED" ]; then
  ok "A3b every handler that mints a registration challenge is guarded"
else
  bad "A3b unguarded registration-challenge handler(s):${UNGUARDED:- none-discovered}"
fi

# ── §B the refusal is machine-distinguishable and is not a 401 ──────────────
echo
echo "── §B the refusal can be told apart, and does not log the user out ──"

if has "$REFUSAL_BODY" '"code": CodeReauthRequired'; then
  ok "B1 the refusal carries the shared marker constant"
else
  bad "B1 the refusal does not reference CodeReauthRequired — an inline literal drifts from the client's copy"
fi

# PLACE, not threshold. "at least one occurrence" is satisfied by the defect: a
# second copy pasted into rt_auth.go passes a count and breaks the single source.
# Shipped (non-test) Go only: a test asserting the wire value is not a second source.
OWNERS=$(grep -rlF --include='*.go' --exclude='*_test.go' '"reauth_required"' panel/go 2>/dev/null | sort | tr '\n' ' ')
OWNERS=$(echo $OWNERS)
if [ "$OWNERS" = "$ERRFILE" ]; then
  ok "B2 the marker literal is defined in exactly one place ($ERRFILE)"
else
  bad "B2 the marker literal lives in: ${OWNERS:-nowhere} — expected only $ERRFILE"
fi

if has "$REFUSAL_BODY" 'http\.StatusForbidden' && ! has "$REFUSAL_BODY" 'http\.StatusUnauthorized'; then
  ok "B3 the refusal is FORBIDDEN, never UNAUTHORIZED"
else
  bad "B3 the refusal uses UNAUTHORIZED (or no FORBIDDEN) — the session is still valid here and only this one ACTION is refused, which is what 403 means (until v2.87.0 there was a second reason: api.ts discarded every 401 body and navigated to /login; that is fixed, and 403 is now correct on the merits alone)"
fi

if hasf "$CARDS_C" 'reauth_required'; then
  ok "B4 both trees agree on the marker"
else
  bad "B4 the account card does not branch on the marker — the challenge cannot be rendered"
fi

# ── §C every account shape can answer ───────────────────────────────────────
echo
echo "── §C every account shape can answer ──"

if has "$PROOF_BODY" 'verifyPassword\('; then
  ok "C1 a password account may answer with its password"
else
  bad "C1 no password branch — an account with no authenticator cannot enrol at all"
fi

# Scoped to THIS body: three other handlers call the same helper, so a file-wide
# grep passes on a tree where this door never learned about recovery codes.
if has "$PROOF_BODY" 'rtAuthTryRecoveryCode\('; then
  ok "C2 a recovery code is accepted, not only a live TOTP code"
else
  bad "C2 this door does not accept a recovery code — the lost-authenticator account is refused at the door that repairs it"
fi

# The branches must be NON-EXCLUSIVE: two independent appends into one list, not
# an if/else that picks a single method.
if has "$PROOF_BODY" 'methods = append\(methods, "password"\)' && has "$PROOF_BODY" 'methods = append\(methods, "totp"\)' \
   && ! has "$PROOF_BODY" '\} else if hasTotp \{'; then
  ok "C3 an account holding both factors is offered both"
else
  bad "C3 the offered methods are chosen exclusively — the sole admin the guide points at loses the documented way back"
fi

if has "$PROOF_BODY" 'user\.PasswordHash != ""' && has "$PROOF_BODY" 'claims\.Iat'; then
  ok "C4 an account that can present nothing falls back to session freshness"
else
  bad "C4 no freshness fallback — an identity-provider account with an empty password hash is barred from passkeys permanently"
fi

# Three claims, because the guide is the only place the OAuth branch's WEAKNESS
# is stated, and because the sole-administrator bullet is the thing the
# non-exclusive branches in C3 exist to keep true.
GUIDE_OK=1
grep -qiE 'Adding a passkey asks you to confirm' <<< "$GUIDE_R" || GUIDE_OK=0
grep -qiE 'sign in again' <<< "$GUIDE_R" || GUIDE_OK=0
grep -qiE 'register a passkey' <<< "$GUIDE_R" || GUIDE_OK=0
if [ "$GUIDE_OK" -eq 1 ]; then
  ok "C5 the guide describes the new door, names the provider re-sign-in, and still points a sole admin at a passkey"
else
  bad "C5 the guide does not describe re-authentication, or dropped the sole-administrator escape hatch"
fi

# ── §D the numbers, extracted with capture groups ───────────────────────────
echo
echo "── §D the numbers (capture-group extracted; each owes a mutation) ──"

if has "$AUTH_C" 'const rtAuthReauthMaxSessionAgeSecs'; then
  ok "D1 the freshness window is a named constant"
else
  bad "D1 no rtAuthReauthMaxSessionAgeSecs — an inline magic number has nowhere to be pinned"
fi

# ⚠ BOTH numbers are read from source with a capture group. Comparing an
# extracted constant against a hardcoded twin passes on every possible tree —
# that is exactly how s326's B7 shipped green while reading the `8` out of `u8`.
WINDOW=$(sed -nE 's/.*const rtAuthReauthMaxSessionAgeSecs[^=]*=[[:space:]]*([0-9_]+).*/\1/p' <<< "$AUTH_C" | head -1 | tr -d _)
LIFETIME=$(sed -nE 's/.*Max-Age=([0-9]+).*/\1/p' <<< "$(fnbody "$AUTH_C" "rtAuthIssueSession")" | head -1)
if [ -n "$WINDOW" ] && [ -n "$LIFETIME" ] && [ "$WINDOW" -gt 0 ] && [ $((WINDOW * 4)) -le "$LIFETIME" ]; then
  ok "D2 the freshness window (${WINDOW}s) is materially shorter than the session it lives inside (${LIFETIME}s)"
else
  bad "D2 window=${WINDOW:-unread} lifetime=${LIFETIME:-unread} — a window at or above the cookie lifetime is satisfied by every live session, so it guards nothing"
fi

# The bare challenge carries no proof. Counting it would let five visits to the
# account page lock the user out of /auth/2fa/disable and the reissue route,
# which share this counter keyed on user id alone.
# Go shape: the record call is the sole statement of an `if` on "a proof field
# was presented" — the line directly above it must be that condition.
RECORD_LINE=$(grep -n 'rtAuthTwofaRateLimitRecord(' <<< "$PROOF_BODY" | head -1 | cut -d: -f1)
ATTEMPTED_LINE=$(grep -nE 'if proof\.Code != nil \|\| proof\.CurrentPassword != nil \{' <<< "$PROOF_BODY" | tail -1 | cut -d: -f1)
if [ -n "$RECORD_LINE" ] && [ -n "$ATTEMPTED_LINE" ] && [ $((ATTEMPTED_LINE + 1)) -eq "$RECORD_LINE" ] \
   && [ "$(grep -c 'rtAuthTwofaRateLimitRecord(' <<< "$PROOF_BODY")" -eq 1 ]; then
  ok "D3 only a presented proof counts against the limiter"
else
  bad "D3 the limiter is recorded unconditionally — opening the account page would burn the shared 2FA counter"
fi

if has "$PROOF_BODY" 'rtAuthTwofaRateLimitRecord\(' && has "$PROOF_BODY" 'rtAuthTwofaRateLimitClear\('; then
  ok "D4 failures are counted and a success clears the counter"
else
  bad "D4 the limiter never clears (or never records) — five lifetime fumbles become a permanent lockout"
fi

# ── §E the frontend can show it ─────────────────────────────────────────────
echo
echo "── §E the frontend can actually render the challenge ──"

# ⚠ Keyed on the ASSIGNMENT, not on `code?: string`. That declaration text also
# appears in the constructor signature and in two unrelated `(data as { code?:
# string })` casts, so an arm grepping it survived deleting the field outright —
# four matches, none of which said the class carries anything.
if has "$APITS_C" 'this\.code = code' && has "$APITS_C" 'this\.body = body'; then
  ok "E1 ApiError carries the code and body off the wire"
else
  bad "E1 ApiError drops the code — the card cannot tell this refusal from any other failure"
fi

# ⚠ REWRITTEN s329. This arm read `res.status === 401` AND `window.location.href
# = "/login"` — two literals that v2.87.0's rewrite of the interceptor KEPT, so
# it would have reported "not quietly changed" on the very tree that changed it.
# A context arm whose subject can be rewritten underneath it is measuring the
# spelling, not the property.
#
# What §B actually depends on is no longer "a 401 always logs you out" — it is
# that a 401 logs you out ONLY when the backend says the session is gone. That
# is what makes the 403 above a decision on the merits rather than a way around
# this module, so that is what is pinned.
if has "$APITS_C" 'res\.status === 401' && hasf "$APITS_C" 'CODE_SESSION_INVALID'; then
  ok "E2 the 401 interceptor still gates its redirect on the session marker"
else
  bad "E2 the 401 interceptor no longer distinguishes a dead session from a refused credential — §B's 403 stops being a merits choice and becomes load-bearing again"
fi

# PLACE, not count: "at least one call in the cards file" is satisfied by a tree
# holding a copy in BOTH files.
CALLERS=$(grep -rlF '"/auth/passkey/register/begin' panel/frontend/src 2>/dev/null | sort | tr '\n' ' ')
CALLERS=$(echo $CALLERS)
if [ "$CALLERS" = "$CARDS" ]; then
  ok "E3 the enrolment call lives in exactly one place ($CARDS)"
else
  bad "E3 the enrolment call lives in: ${CALLERS:-nowhere} — expected only $CARDS"
fi

# Widths read from the shared predicate with a capture group, as a SET.
WIDTHS=$(grep -oE 'v\.length === [0-9]+' <<< "$CARDS_C" | sed -E 's/.*=== ([0-9]+)/\1/' | sort -n | tr '\n' ' ')
WIDTHS=$(echo $WIDTHS)
if [ "$WIDTHS" = "6 8 16" ]; then
  ok "E4 the code field accepts every issued width ($WIDTHS)"
else
  bad "E4 accepted widths are '${WIDTHS:-none}', expected '6 8 16' — 8 is the pre-v2.84.0 recovery width and those codes are still valid"
fi

TWOFA_CARD=$(tsxbody "$CARDS_C" "TwoFactorCard")
# An extraction that came back EMPTY must fail, not pass: an absence arm over
# nothing is green by construction.
if [ -z "$TWOFA_CARD" ]; then
  bad "E5 could not extract TwoFactorCard — the arm below would pass by examining nothing"
elif ! has "$TWOFA_CARD" '=== 16'; then
  ok "E5 the width predicate has one definition, at module scope"
else
  bad "E5 the width rule is re-inlined inside TwoFactorCard — two copies is how one card silently stops accepting a width"
fi

# ── §F enrolment is not silent ──────────────────────────────────────────────
echo
echo "── §F a new credential announces itself ──"

if has "$COMPLETE_BODY" 'NotificationsNotifyPanel\('; then
  ok "F1 a successful enrolment notifies"
else
  bad "F1 enrolment is silent — a planted credential is durable precisely because nobody is told"
fi

if has "$COMPLETE_BODY" 'NotificationsNotifyPanel\(ctx, st\.DB, &claims\.Sub,'; then
  ok "F2 the notification goes to the owner, not to every administrator"
else
  bad "F2 the notification target is not the owner — nil notifies all admins, i.e. everyone except the victim"
fi

# ── §G context ──────────────────────────────────────────────────────────────
echo
echo "── §G context (green at both tags; each owes its own mutation) ──"

DELETE_BODY=$(fnbody "$PASSKEYS_C" "rtPasskeysDeletePasskey")
UNGUARDED_READ=""
N_READ=0
for f in rtPasskeysAuthBegin rtPasskeysAuthComplete rtPasskeysListPasskeys rtPasskeysDeletePasskey rtPasskeysRenamePasskey; do
  b=$(fnbody "$PASSKEYS_C" "$f")
  [ -n "$b" ] && N_READ=$((N_READ+1))
  has "$b" 'rtAuthRequireEnrolmentProof' && UNGUARDED_READ="$UNGUARDED_READ $f"
done
if [ "$N_READ" -ne 5 ]; then
  bad "G1 only $N_READ/5 non-enrolment handlers extracted — the absence check would be vacuous"
elif [ -z "$UNGUARDED_READ" ]; then
  ok "G1 (context) the guard is on the enrolment door and only there"
else
  bad "G1 the proof check leaked onto:${UNGUARDED_READ} — a login door has no prior session to be fresh, and reads plant nothing"
fi

# The deliberate NON-ship, pinned so a later reader does not "helpfully" add it.
if has "$DELETE_BODY" 'AND user_id = \$2' && ! hasf "$DELETE_BODY" 'COUNT(*) FROM passkeys'; then
  ok "G2 (context) deletion is still caller-scoped and did NOT grow a last-factor refusal"
else
  bad "G2 rtPasskeysDeletePasskey lost its owner predicate, or grew a last-factor guard the census refuted"
fi

if hasf "$COMPLETE_BODY" 'Challenge user mismatch'; then
  ok "G3 (context) a challenge cannot be completed by another account — which is what makes guarding begin alone sufficient"
else
  bad "G3 rtPasskeysRegisterComplete no longer refuses a foreign challenge — the single choke point in §A is no longer legitimate"
fi

echo
echo "=============================================="
printf '  PASS %d   FAIL %d\n' "$PASS" "$FAIL"
echo "=============================================="
[ "$FAIL" -eq 0 ]
