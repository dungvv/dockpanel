#!/usr/bin/env bash
# passkey-ceremony-pin-e2e.sh — s328
#
# ONE PROPERTY: the WebAuthn ceremony's own checks are arranged so that each one
# means what it says.
#
# Until v2.86.0 the passkeys route (Rust `passkeys.rs`, now
# panel/go/internal/api/rt_passkeys.go) had NO tests of any kind — no `cfg(test)` module,
# and not one assertion in any of the 46 pin suites touching origin, rpIdHash,
# user-presence, the signature counter or the signature itself. Five live checks,
# zero coverage. This suite pins the properties that are facts about ARRANGEMENT;
# the ones that are facts about a return value are unit tests in the file itself,
# because a truth table that executes cannot be vacuous the way a grep can.
#
#   §A  NEITHER DOOR INDEXES PAST ITS OWN LENGTH GUARD.
#       ← the headline defect this release fixes
#       `authData` is rpIdHash(32) ‖ flags(1) ‖ signCount(4). `rtPasskeysRegisterComplete`
#       bounded it at 32 and then read index [32], so a 32-byte buffer passed the
#       guard and panicked the handler — and the payload is attacker-chosen,
#       because it only has to equal SHA256(rp_id), which is public. The twin in
#       `rtPasskeysAuthComplete` always used 37. The ASYMMETRY between the two doors was
#       the bug, which is why §A is a membership test over both and not a check
#       of one.
#
#   §B  THE CLONE CHECK RUNS AFTER THE SIGNATURE.
#       WebAuthn L2 §7.2 orders it that way and the reason is operational. Above
#       the verify, the branch fires on forged `authData` with a garbage
#       signature — `rtPasskeysAuthBegin` hands out challenges unauthenticated, rpIdHash
#       is public and the UP bit is a constant — so the one refusal in this file
#       that says "clone" was reachable by a stranger AND returned without
#       recording an attempt, unlike both its siblings. That is also why the
#       detector stayed mute: an alert wired to a branch an outsider can trigger
#       is a fabricated-alert writer, so the reorder had to land first and the
#       audit row second. B4 pins that it is `SecurityHardeningAuditLog` and NOT
#       `SecurityHardeningRecordSuspiciousEvent`, which auto-activates system-wide lockdown at
#       five events in ten minutes — routing a credential failure through it
#       would let a cloned key black the panel out for every non-admin.
#
#   §C  THE COUNTER RULE IS A NAMED FUNCTION, AND IT IS THE SPEC'S RULE.
#       The spec applies the comparison when EITHER side is non-zero. This panel
#       tested both with `&&` from `adce010` until v2.86.0, exempting the one
#       shape that matters: a stored counter above zero presented with ZERO —
#       the cheapest forgery there is, and one whose acceptance writes the zero
#       back. Pinned as a free function so the truth table can be executed.
#
#   §D  BOTH COMPLETE-DOORS CHECK WHICH CEREMONY THE CHALLENGE CAME FROM.
#       `rtPasskeysRegisterComplete` has since the feature landed; `rtPasskeysAuthComplete` bound
#       it to `_challenge_data` (Rust) and discarded it. No attack is known — this door
#       derives the account from the credential row, never from the challenge's
#       binding — so D is a symmetry pin, not a vulnerability pin.
#
#   §E  THE COUNTER WRITE CANNOT WALK BACKWARDS.
#
#   §F  THE FILE HAS EXECUTABLE COVERAGE AT ALL.
#
#   §G  CONTEXT — arms green at BOTH tags, so a harness measuring nothing cannot
#       read as a pass. Each owes its own mutation.
#
# ⚠ s443: §G4 pinned a deliberate NON-ship for many sessions — the UV bit
# (0x04) was never tested, so a passkey was possession-only while passkey
# login skipped 2FA. That gap is CLOSED as of s443: a new `uv_capable` column
# is populated at registration from the ceremony's own UV bit, and
# `rtPasskeysAuthComplete` now requires that bit back on every future login — but ONLY
# from a credential that proved it could give one. G4 below pins the
# ENFORCEMENT now; §I pins the storage + grandfathering it depends on. See
# TestDBRtPasskeysVirtualAuthenticator (panel/go/internal/api/rt_passkeys_test.go,
# once a Cargo bin) + `tests/passkey-uv-enforcement-e2e.sh` for the live
# end-to-end proof this source-only file cannot give.
#
# RUN AGAINST v2.85.0: the §G arms are green by design and each was killed by its
# own mutation. Everything else is RED there. §G4 and §I are s443 additions —
# RED before that ship, by construction.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=============================================="
echo "  Passkey ceremony — source pins (s328)"
echo "=============================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

# Strip comments before matching. This ship writes long comments into the very
# file it pins — they name `SecurityHardeningRecordSuspiciousEvent`, `< 37` and
# the predicate itself — so an arm over RAW source would be satisfied by its own
# prose, and an ABSENCE arm would be falsely RED. ⚠ Copied from the FIXED
# stripper (s294): a block comment is recognised only where one is written, or a
# `/*` inside a string literal eats the file. Go `//` line comments are stripped
# by the second rule.
code() {
  [ -f "$1" ] || return 0
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

has()  { grep -qE -- "$2" <<< "$1"; }
hasf() { grep -qF -- "$2" <<< "$1"; }
cnt()  { grep -cF -- "$2" <<< "$1"; }

# A function body, bounded on ITS OWN braces, anchored on `func NAME(` (or a
# method `func (x *T) NAME(`) so a rename to a longer name cannot survive on the
# prefix (s325 #299). ⚠ An extraction that comes back EMPTY must be an ERROR,
# never an absence (s327 #308): an absence arm over an empty string is green on
# every possible tree.
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

PK="panel/go/internal/api/rt_passkeys.go"
PK_C=$(code "$PK")

if [ -z "$PK_C" ]; then
  bad "FATAL could not read or strip $PK — every arm below would be vacuous"
  echo; printf '  PASS %d   FAIL %d\n' "$PASS" "$FAIL"; exit 1
fi

REG_BODY=$(fnbody "$PK_C" "rtPasskeysRegisterComplete")
AUTH_BODY=$(fnbody "$PK_C" "rtPasskeysAuthComplete")

# The enumeration guard for everything below (s295 #143). An empty body makes
# every absence arm over it green on any tree whatsoever.
if [ -n "$REG_BODY" ] && [ -n "$AUTH_BODY" ]; then
  ok "A0 both ceremony handlers extracted (rtPasskeysRegisterComplete $(wc -l <<< "$REG_BODY")L, rtPasskeysAuthComplete $(wc -l <<< "$AUTH_BODY")L)"
else
  bad "A0 a handler body extracted EMPTY — every arm below is vacuous; fix fnbody before reading any result in this file"
  echo; printf '  PASS %d   FAIL %d\n' "$PASS" "$FAIL"; exit 1
fi

echo
echo "── §A neither door indexes past its own length guard ──"

# A1 — MEMBERSHIP, not a count. Discover every handler that reads the flags byte
# at a fixed offset, then assert each one bounds the buffer at the full 37-byte
# header first. Written this way because the defect was ONE of two doors being
# wrong: a count of correct guards would have been satisfied by the good twin.
INDEXERS=""
for f in rtPasskeysRegisterComplete rtPasskeysAuthComplete; do
  b=$(fnbody "$PK_C" "$f")
  hasf "$b" 'authData[32]' && INDEXERS="$INDEXERS $f"
done
INDEXERS=$(echo $INDEXERS)
N_IDX=$(wc -w <<< "$INDEXERS")

if [ "$N_IDX" -ge 2 ]; then
  ok "A1 discovered $N_IDX handlers that index the flags byte:$INDEXERS"
else
  bad "A1 discovered only $N_IDX flags-byte reader(s) — the pattern broke and A2 is vacuous"
fi

# ORDER as well as presence: the guard must precede the first [32] read.
UNGUARDED=""
for f in $INDEXERS; do
  b=$(fnbody "$PK_C" "$f")
  g=$(grep -nF 'len(authData) < 37' <<< "$b" | head -1 | cut -d: -f1)
  i=$(grep -nF 'authData[32]' <<< "$b" | head -1 | cut -d: -f1)
  { [ -n "$g" ] && [ "$g" -lt "$i" ]; } || UNGUARDED="$UNGUARDED $f"
done
if [ "$N_IDX" -ge 2 ] && [ -z "$UNGUARDED" ]; then
  ok "A2 every handler that reads authData[32] bounds the buffer at 37 first"
else
  bad "A2 handler(s) index the flags byte behind a short guard:${UNGUARDED:- none-discovered} — a 32-byte authData panics the handler"
fi

# A3 — the absence, stated directly. The old bound must be gone from the file.
if ! has "$PK_C" 'len\(authData\) < 3[0-6]\b'; then
  ok "A3 no door bounds authData below 37 — the header is 32+1+4 and the guard must cover all of it"
else
  bad "A3 a door still bounds authData short of 37 then reads index [32] — that is the panic"
fi

echo
echo "── §B the clone check runs after the signature ──"

VERIFY_LN=$(grep -n 'ecdsa.Verify(' <<< "$AUTH_BODY" | head -1 | cut -d: -f1)
COUNTER_LN=$(grep -n 'rtPasskeysCounterRegressed(' <<< "$AUTH_BODY" | head -1 | cut -d: -f1)

if [ -n "$VERIFY_LN" ] && [ -n "$COUNTER_LN" ]; then
  ok "B1 both landmarks found in rtPasskeysAuthComplete (verify at +${VERIFY_LN}, counter at +${COUNTER_LN})"
else
  bad "B1 could not locate ecdsa.Verify(${VERIFY_LN:-missing}) or rtPasskeysCounterRegressed(${COUNTER_LN:-missing}) — B2 would be vacuous"
fi

if [ -n "$VERIFY_LN" ] && [ -n "$COUNTER_LN" ] && [ "$COUNTER_LN" -gt "$VERIFY_LN" ]; then
  ok "B2 the counter regression test runs AFTER signature verification, so reaching it costs the private key"
else
  bad "B2 the counter test precedes signature verification — it fires on forged authData, unthrottled, and any alert on it is writable by a stranger"
fi

# B3 — the branch must cost the caller something. Its two siblings in this
# handler both push to LoginAttempts (via rtPasskeysRecordAttempt); the counter
# branch did not, which is what made it an unthrottled probe. The helper itself
# is checked too, or a gutted helper satisfies the call-site arm.
CB=$(awk '/rtPasskeysCounterRegressed\(/{f=1} f{print} f&&/^\t}$/{exit}' <<< "$AUTH_BODY")
RA=$(fnbody "$PK_C" "rtPasskeysRecordAttempt")
if [ -n "$CB" ] && hasf "$CB" 'rtPasskeysRecordAttempt(st, ip)' && hasf "$RA" 'st.LoginAttempts[ip] = append('; then
  ok "B3 a detected clone records a login attempt, like every other credential refusal in this handler"
else
  bad "B3 the clone branch does not record an attempt — it is a free retry, and free retries are how a counter gets probed"
fi

# ⚠ Scoped to the CLONE BRANCH, never to the handler. The handler already calls
# SecurityHardeningAuditLog for the successful login, so a handler-wide arm here
# is satisfied by that unrelated call and stays green while the detector is mute
# (s327 #310: key on the act, not on a token that appears elsewhere).
if [ -n "$CB" ] && hasf "$CB" 'SecurityHardeningAuditLog(' && ! hasf "$CB" 'SecurityHardeningRecordSuspiciousEvent'; then
  ok "B4 the clone branch itself writes an audit row, and not through SecurityHardeningRecordSuspiciousEvent"
else
  bad "B4 the clone detector is mute, or it routes through SecurityHardeningRecordSuspiciousEvent — which auto-locks the panel at 5 events in 10 minutes, so a failing cloned key would black out every non-admin"
fi

echo
echo "── §C the counter rule is the spec's rule, and it is testable ──"

PRED=$(fnbody "$PK_C" "rtPasskeysCounterRegressed")
if [ -n "$PRED" ]; then
  ok "C1 rtPasskeysCounterRegressed is a named function, so its truth table can be executed rather than grepped"
else
  bad "C1 rtPasskeysCounterRegressed does not exist — the rule is inlined again and only a grep can reach it"
fi

# C2 retired: covered by TestRtPasskeysZeroPresentedAgainstALiveCounterIsAClone (+ the other TestRtPasskeys*Counter*/Increment/Rewind tests) (panel/go/internal/api/rt_passkeys_test.go), executed in §F

# C3 — the call site must USE the predicate, not carry a second copy of the rule.
if [ -n "$COUNTER_LN" ] && ! has "$AUTH_BODY" 'newCount <=? storedCount|storedCount >=? newCount'; then
  ok "C3 rtPasskeysAuthComplete delegates to the predicate instead of re-inlining the comparison"
else
  bad "C3 rtPasskeysAuthComplete inlines the counter comparison again (or no longer calls the predicate) — two copies of one rule, and the tests only cover one"
fi

echo
echo "── §D both complete-doors check which ceremony issued the challenge ──"

UNCHECKED=""
for f in rtPasskeysRegisterComplete rtPasskeysAuthComplete; do
  b=$(fnbody "$PK_C" "$f")
  hasf "$b" 'ch.Registration' || UNCHECKED="$UNCHECKED $f"
done
if [ -z "$UNCHECKED" ]; then
  ok "D1 both complete-doors inspect the challenge variant"
else
  bad "D1 door(s) accept a challenge without checking which ceremony minted it:$UNCHECKED"
fi

if has "$AUTH_BODY" 'if ch\.Registration \{' && hasf "$AUTH_BODY" 'Wrong challenge type'; then
  ok "D2 rtPasskeysAuthComplete requires an authentication challenge specifically"
else
  bad "D2 rtPasskeysAuthComplete no longer pins the variant — a registration challenge satisfies the login door"
fi

if hasf "$AUTH_BODY" 'ch, ok := rtPasskeysTakeChallenge(' && ! has "$AUTH_BODY" '_, ok :?= rtPasskeysTakeChallenge\('; then
  ok "D3 the challenge is consumed, not bound-and-discarded"
else
  bad "D3 rtPasskeysAuthComplete discards the taken challenge again — the variant it carries is unread"
fi

echo
echo "── §E the stored counter cannot walk backwards ──"

if hasf "$AUTH_BODY" 'AND $1 > sign_count'; then
  ok "E1 the counter write is conditional, closing the read/write window between two assertions in flight"
else
  bad "E1 the counter write is unconditional — a lower assertion landing last rewinds the stored counter, which is the state the clone check exists to notice"
fi

echo
echo "── §F the file has executable coverage at all ──"

# Was: a `#[cfg(test)]` module exists in passkeys.rs with >= 12 `#[test]`s. In
# Go the tests live beside the file, so the honest form is to RUN them.
F_OUT=$(cd panel/go && go test ./internal/api/ -run '^TestRtPasskeys' -count=1 -v 2>&1)
F_RC=$?
N_TESTS=$(grep -c -- '^--- PASS: TestRtPasskeys' <<< "$F_OUT")
if [ "$F_RC" -eq 0 ] && [ "$N_TESTS" -ge 1 ]; then
  ok "F1 rt_passkeys_test.go's TestRtPasskeys* unit tests run and pass — the route had none from adce010 until v2.86.0"
else
  bad "F1 go test -run '^TestRtPasskeys' failed (rc=$F_RC) — every property in this file is grep-only again"
  grep -E -- '^--- FAIL|FAIL' <<< "$F_OUT" | head -10 | sed 's/^/      /'
fi

if [ "$N_TESTS" -ge 12 ]; then
  ok "F2 $N_TESTS executable tests cover the ceremony's pure functions"
else
  bad "F2 only $N_TESTS executable tests passed — the truth table or the parser edges were dropped"
fi

echo
echo "── §G context: green at BOTH tags, each killed by its own mutation ──"

UP_MISSING=""
for f in rtPasskeysRegisterComplete rtPasskeysAuthComplete; do
  b=$(fnbody "$PK_C" "$f")
  hasf "$b" 'flags&0x01 == 0' || UP_MISSING="$UP_MISSING $f"
done
if [ -z "$UP_MISSING" ]; then
  ok "G1 (context) both doors still require the user-present bit"
else
  bad "G1 door(s) stopped requiring user presence:$UP_MISSING"
fi

ORIGIN_MISSING=""
for f in rtPasskeysRegisterComplete rtPasskeysAuthComplete; do
  b=$(fnbody "$PK_C" "$f")
  hasf "$b" 'Origin mismatch' || ORIGIN_MISSING="$ORIGIN_MISSING $f"
done
if [ -z "$ORIGIN_MISSING" ]; then
  ok "G2 (context) both doors still pin the origin"
else
  bad "G2 door(s) stopped pinning the origin:$ORIGIN_MISSING"
fi

RP_MISSING=""
for f in rtPasskeysRegisterComplete rtPasskeysAuthComplete; do
  b=$(fnbody "$PK_C" "$f")
  hasf "$b" 'RP ID hash mismatch' || RP_MISSING="$RP_MISSING $f"
done
if [ -z "$RP_MISSING" ]; then
  ok "G3 (context) both doors still compare the RP ID hash"
else
  bad "G3 door(s) stopped comparing the RP ID hash:$RP_MISSING"
fi

# G4 — s443: the UV bit is now checked in auth complete, conditioned on the
# credential's OWN uv_capable column (never unconditional — that would be the
# retroactive lockout the header describes G4 used to pin the ABSENCE of).
if hasf "$AUTH_BODY" 'uvCapable && flags&0x04 == 0'; then
  ok "G4 (context) rtPasskeysAuthComplete requires UV back, but only from a credential gated on its own uv_capable value — not unconditionally"
else
  bad "G4 the UV enforcement branch is missing or no longer conditioned on uv_capable — either the check regressed, or it went back to unconditional (which locks out every possession-only key)"
fi

echo
echo "── §I passkey UV enforcement is stored, ordered, and grandfathered (s443) ──"

if grep -qF 'ADD COLUMN uv_capable BOOLEAN NOT NULL DEFAULT FALSE' panel/go/internal/api/migrations/*.sql 2>/dev/null; then
  ok "I1 a migration adds uv_capable, defaulting FALSE — every pre-existing row is grandfathered as unenforced"
else
  bad "I1 no migration adds 'uv_capable BOOLEAN NOT NULL DEFAULT FALSE' — without a FALSE default, existing possession-only credentials would be enforced retroactively"
fi

if hasf "$REG_BODY" 'uvCapable := flags&0x04 != 0'; then
  ok "I2 rtPasskeysRegisterComplete derives uv_capable from the SAME ceremony's own UV bit, not assumed"
else
  bad "I2 rtPasskeysRegisterComplete no longer computes uv_capable from the registration ceremony's flags"
fi

if hasf "$REG_BODY" 'INSERT INTO passkeys (user_id, credential_id, public_key_cbor, sign_count, name, transports, aaguid, uv_capable)' \
   && hasf "$REG_BODY" 'aaguidHex, uvCapable)'; then
  ok "I3 the INSERT persists uv_capable alongside the rest of the credential row"
else
  bad "I3 the passkeys INSERT no longer stores uv_capable — I2's derived value has nowhere to land"
fi

if hasf "$AUTH_BODY" 'SELECT id, user_id, public_key_cbor, sign_count, uv_capable FROM passkeys WHERE credential_id = $1' \
   && hasf "$AUTH_BODY" 'uvCapable := pk.A, pk.B, pk.C, pk.D, pk.E'; then
  ok "I4 rtPasskeysAuthComplete's own credential lookup reads uv_capable back — the enforcement branch has a real value to check, not a default"
else
  bad "I4 rtPasskeysAuthComplete's SELECT no longer fetches uv_capable — G4's condition would read an undeclared or defaulted value"
fi

# I5 — ORDER. Reusing §B's landmark technique: the UV check must run AFTER the
# signature verify, for the identical reason the counter check does (the flags
# byte lives inside authData, which the signature covers — trusting it before
# verification lets an attacker learn a credential's UV requirement from a
# forged, unauthenticated assertion).
UV_LN=$(grep -nF 'uvCapable && flags&0x04 == 0' <<< "$AUTH_BODY" | head -1 | cut -d: -f1)
if [ -n "$VERIFY_LN" ] && [ -n "$UV_LN" ] && [ "$UV_LN" -gt "$VERIFY_LN" ]; then
  ok "I5 the UV requirement is checked AFTER signature verification (verify at +${VERIFY_LN}, UV check at +${UV_LN})"
else
  bad "I5 could not confirm the UV check runs after signature verification (verify=${VERIFY_LN:-missing}, UV=${UV_LN:-missing}) — checking it earlier leaks the requirement to an unauthenticated caller"
fi

# I6 — the refusal costs the caller something, matching §B3's precedent for the
# clone-check branch, and does NOT route through the panel-wide lockout trigger.
UVB=$(awk '/uvCapable && flags&0x04 == 0/{f=1} f{print} f&&/^\t}$/{exit}' <<< "$AUTH_BODY")
if [ -n "$UVB" ] && hasf "$UVB" 'rtPasskeysRecordAttempt(st, ip)' && hasf "$UVB" 'SecurityHardeningAuditLog(' && ! hasf "$UVB" 'SecurityHardeningRecordSuspiciousEvent'; then
  ok "I6 a UV-not-provided refusal records a login attempt and an audit row, without routing through SecurityHardeningRecordSuspiciousEvent"
else
  bad "I6 the UV-refusal branch is missing the login-attempt record, the audit row, or wrongly routes through SecurityHardeningRecordSuspiciousEvent (which auto-locks the panel at 5 events in 10 minutes)"
fi

# I7 — CONTEXT, the deliberate non-change. register begin's own hint stays
# "preferred": forcing "required" would fail registration outright for any
# PIN-less roaming key, closing the documented sole-admin recovery path
# (rtAuthRequireEnrolmentProof's own doc comment) that this whole file exists to
# protect. UV is captured from whatever the authenticator actually did, never
# demanded at enrolment time.
RB=$(fnbody "$PK_C" "rtPasskeysRegisterBegin")
if [ -n "$RB" ] && hasf "$RB" 'UserVerification = "preferred"' && ! hasf "$RB" '"required"'; then
  ok "I7 (context) rtPasskeysRegisterBegin still only PREFERS user verification — deliberate, see the header; demanding it would break PIN-less-key recovery"
else
  bad "I7 rtPasskeysRegisterBegin's user_verification hint changed — if it now REQUIRES UV, PIN-less roaming keys can no longer enrol at all, including the documented sole-admin recovery path"
fi

LB=$(fnbody "$PK_C" "rtPasskeysListPasskeys")
if hasf "$LB" '"uvCapable": p.F' && hasf "$LB" 'created_at, uv_capable FROM passkeys'; then
  ok "I8 rtPasskeysListPasskeys exposes uv_capable to the account owner, so a possession-only key is visible as such rather than a hidden distinction"
else
  bad "I8 rtPasskeysListPasskeys no longer reports uv_capable — the account owner has no way to tell a verified key from a possession-only one"
fi

echo
echo "── §H the RP ID/origin derivation fails closed instead of defaulting to localhost (s435) ──"
#
# s429's completeness critic found the RP ID/origin derivation's OWN doc comment
# overstated what it did: when BASE_URL is unset (a legitimate, common
# "IP-based access" configuration, not a misconfiguration), both fell through
# Origin -> Host -> a hardcoded "localhost"/"https://localhost" literal that
# satisfied nothing but let the ceremony proceed anyway. Non-exploitable as
# reported (the complete handlers' origin check is bound to the browser's OWN
# signed clientDataJSON.origin — §G2 pins that comparison exists) — but "fail
# closed to match what the comment claims" was still owed. Fixed: the ONLY
# remaining fallback (neither Origin nor Host present, which no real
# browser-driven ceremony produces) now refuses instead of defaulting.
# The rtPasskeysRPID refusal is also executed by TestRtPasskeysRPDerivationFailsClosed.

RPID_BODY=$(fnbody "$PK_C" "rtPasskeysRPID")
RPORIGIN_BODY=$(fnbody "$PK_C" "rtPasskeysRPOrigin")
NORP_BODY=$(fnbody "$PK_C" "rtPasskeysNoRP")

if [ -n "$RPID_BODY" ] && [ -n "$RPORIGIN_BODY" ] && [ -n "$NORP_BODY" ]; then
  ok "H0 both header-derivation functions (and their shared refusal) extracted"
else
  bad "H0 could not extract rtPasskeysRPID / rtPasskeysRPOrigin / rtPasskeysNoRP — every arm below is vacuous"
fi

if hasf "$PK_C" 'func rtPasskeysRPID(r *http.Request, st *AppState) (string, error) {' \
   && hasf "$PK_C" 'func rtPasskeysRPOrigin(r *http.Request, st *AppState) (string, error) {'; then
  ok "H1 both functions are fallible ((string, error)), not an infallible string that must always produce SOME value"
else
  bad "H1 one or both header-derivation functions no longer return (string, error) — a fallible signature is what makes 'refuse' expressible at all"
fi

if hasf "$RPID_BODY" 'localhost' || hasf "$RPORIGIN_BODY" 'localhost'; then
  bad "H2 a literal 'localhost' string is back in one of the derivation functions — the fail-closed fix this section pins has regressed"
else
  ok "H2 neither derivation function contains a 'localhost' literal"
fi

# The final statement of each body (the line before its closing brace) must be
# the refusal, and the refusal must be a 400.
last_stmt() { grep -vE '^\s*$' <<< "$1" | tail -2 | head -1; }
if has "$(last_stmt "$RPID_BODY")" 'return "", rtPasskeysNoRP\(\)' \
   && has "$(last_stmt "$RPORIGIN_BODY")" 'return "", rtPasskeysNoRP\(\)' \
   && hasf "$NORP_BODY" 'apiErr(http.StatusBadRequest'; then
  ok "H3 both functions' final fallback is an explicit 400 error, not a default value"
else
  bad "H3 one or both functions' final fallback is not an explicit error — re-read them, a silent default may have come back"
fi

# H4 — every CALL SITE must actually propagate the failure. A function turned
# fallible but called with its error discarded (`x, _ :=`) would satisfy H0-H3
# while still never refusing anything in practice.
prop_calls() { perl -0777 -ne "\$n=()=/:= $1\(r, st\)\n\s*if err != nil \{\n\s*return err\n/g; print \$n" <<< "$PK_C"; }
RPID_CALLS=$(prop_calls rtPasskeysRPID)
RPORIGIN_CALLS=$(prop_calls rtPasskeysRPOrigin)
RPID_ALL=$(grep -cE 'rtPasskeysRPID\(r, st\)' <<< "$PK_C")
RPORIGIN_ALL=$(grep -cE 'rtPasskeysRPOrigin\(r, st\)' <<< "$PK_C")
if [ "$RPID_CALLS" -eq 4 ] && [ "$RPORIGIN_CALLS" -eq 2 ] && [ "$RPID_ALL" -eq 4 ] && [ "$RPORIGIN_ALL" -eq 2 ]; then
  ok "H4 all 6 call sites propagate the error (4 x rp_id, 2 x rp_origin) — a refusal actually reaches the caller"
else
  bad "H4 expected 4 rp_id + 2 rp_origin call sites returning the error, found $RPID_CALLS/$RPID_ALL + $RPORIGIN_CALLS/$RPORIGIN_ALL — a call site may be swallowing the error instead of refusing"
fi

echo
echo "=============================================="
printf '  PASS %d   FAIL %d\n' "$PASS" "$FAIL"
echo "=============================================="
[ "$FAIL" -eq 0 ]
