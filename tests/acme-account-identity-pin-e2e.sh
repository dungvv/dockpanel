#!/usr/bin/env bash
# Regression pins for the s399 ACME-account-identity ship.
#
# THE DEFECT: `load_or_create_account` (Go: services.SslLoadOrCreateAccount) was a check-then-act with a network round
# trip in the middle. Two sites created together on a fresh box each spawn an
# auto-SSL task; both saw no account file, both created a DIFFERENT account at
# Let's Encrypt, and the second write clobbered the first. Measured on a
# throwaway box: two "Created new ACME account" lines 443 ms apart, after which
# every certificate issued inside that window answered 422 to renewal for ever
# (the CA rejects the ARI `replaces` hint as unauthorized, and `provision_cert`
# has no path that retries without it), while one issued after the window
# renewed 200.
#
# THE INVARIANT THESE ARMS EXIST TO HOLD: the account handed back is always the
# one whose credentials are on disk.
#
# Why these are pins and not only unit tests: the unit tests in
# `panel/go/internal/agent/services/ssl_test.go` cover
# `sslPersistAccountCredentials` — the CROSS-PROCESS half — directly (so the old
# §B source arms over it are retired to those tests). They cannot see
# the IN-PROCESS half, because the serialising lock lives in a function whose
# other half is a round trip to Let's Encrypt. §A is that half.
#
# ⚠ Arms are scoped to a FUNCTION BODY, never the file, and each subject is
# FLOORED: an `fnbody` whose anchor stops matching yields an EMPTY subject and
# every `hasnt` beneath it then passes green for a file that no longer contains
# the code at all. §Z plants each defect back into a copy and asserts the
# matching arm goes RED — the only execution an arm's failure branch ever gets
# before it matters.
#
# Static analysis over source text: offline, deterministic, same verdict on an
# air-gapped runner.
#   run: bash tests/acme-account-identity-pin-e2e.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
ok()  { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31m✗\033[0m %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3', got '$2'"; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "missing: $3" ;; esac; }
hasnt(){ case "$2" in *"$3"*) bad "$1" "present but must not be: $3" ;; *) ok "$1" ;; esac; }

# ugrep's --ignore-files shim honours .gitignore, so use the real binary.
G=/usr/bin/grep

ASSL=panel/go/internal/agent/services/ssl.go

# Comments blanked (a pin greps RAW source, so an explanation satisfies it),
# then whitespace removed, so a multi-line statement flattens to the token it
# compiles to. Go keeps its tests in _test.go files, so ssl.go IS production.
squash() { tr -d ' \t\n\\'; }
fnbody() { awk -v p="$2" 'index($0,p){f=1} f{print} f && /^}$/{exit}' "$1"; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
PRODSRC="$TMP/ssl.prod.go"
[ -f "$ASSL" ] || { bad "SETUP" "subject missing: $ASSL"; exit 1; }
awk '/^[[:space:]]*\/\//{print "";next}{print}' "$ASSL" > "$PRODSRC"

# ── the arms, as ONE function so §Z can point them at a mutated copy ─────────
# $1 = a comment-blanked copy of agent services/ssl.go
run_arms() {
  local src="$1"
  local LOAD
  LOAD=$(fnbody "$src" 'func SslLoadOrCreateAccount(')

  # ⛔ FLOOR THE SUBJECT FIRST. Everything below is meaningless if the anchor
  # stopped matching, and `hasnt` would report green on an empty string.
  local NL_LOAD
  NL_LOAD=$(printf '%s' "$LOAD" | wc -l | tr -d ' ')
  if [ "$NL_LOAD" -lt 15 ]; then
    bad "A0 subject floor" "SslLoadOrCreateAccount body is $NL_LOAD lines — the anchor stopped matching, every arm below is vacuous"
    return
  fi
  ok "A0 subject floor — SslLoadOrCreateAccount body is $NL_LOAD lines"
  # B0 retired: covered by the persistence tests named at §B below.

  local LOADQ
  LOADQ=$(printf '%s' "$LOAD" | squash)

  # ── A: the IN-PROCESS half ────────────────────────────────────────────────
  has "A1 the load-or-create is serialised process-wide" "$LOADQ" "sslAccountInit.Lock()"
  has "A2 the lock is a real mutex, declared beside the function that holds it" "$(squash < "$src")" "varsslAccountInitsync.Mutex"

  # A3 is the one that matters most and is the easiest to get wrong: a lock
  # taken AFTER the existence check serialises nothing. Compare POSITIONS, not
  # presence — presence is A1's claim and passes for the broken ordering too.
  local LOCK_AT READ_AT
  LOCK_AT=$(printf '%s\n' "$LOAD" | $G -n 'sslAccountInit.Lock()' | head -1 | cut -d: -f1)
  READ_AT=$(printf '%s\n' "$LOAD" | $G -n 'sslStoredAccount(' | head -1 | cut -d: -f1)
  if [ -n "$LOCK_AT" ] && [ -n "$READ_AT" ] && [ "$LOCK_AT" -lt "$READ_AT" ]; then
    ok "A3 the lock is taken BEFORE the account file is read (lock=$LOCK_AT read=$READ_AT)"
  else
    bad "A3 lock ordering" "the lock must precede the read or it serialises nothing (lock=${LOCK_AT:-none} read=${READ_AT:-none})"
  fi

  hasnt "A4 the clobbering write is gone from the load path" "$LOADQ" "os.WriteFile(sslAcmeAccountPath"
  has   "A5 persistence goes through the atomic writer" "$LOADQ" "sslPersistAccountCredentials(sslAcmeAccountPath"
  # A6: losing the cross-process race must RE-READ. Returning the minted account
  # is the defect wearing the fix's clothes — it compiles, it logs, and it
  # issues certificates under a key that is nowhere on disk. Only Written may
  # return the minted account.
  has "A6 only a WRITTEN outcome returns the minted account" "$LOADQ" "ifoutcome==sslWritten{"
  local ADOPT_ARM
  ADOPT_ARM=$(printf '%s\n' "$LOAD" | awk '/outcome == sslWritten/{f=1;next} f && /^\t}$/{g=1;next} g{print}')
  case "$(printf '%s' "$ADOPT_ARM" | squash)" in
    *"acct,err=sslStoredAccount(ctx)"*) ok "A7 the Adopted path re-reads from disk" ;;
    *) bad "A7 the Adopted path re-reads from disk" "it must call sslStoredAccount() again, not return the account it just minted" ;;
  esac

  # ── B: the CROSS-PROCESS half ─────────────────────────────────────────────
  # B1 retired: covered by TestExactlyOneOfManyConcurrentWritersWins (panel/go/internal/agent/services/ssl_test.go)
  # B2 retired: covered by TestAnExistingAccountIsAdoptedNeverOverwritten (panel/go/internal/agent/services/ssl_test.go)
  # B3 retired: covered by TestAnExistingAccountIsAdoptedNeverOverwritten (panel/go/internal/agent/services/ssl_test.go)
  # B4 retired: covered by TestTheAccountFileIsOwnerOnlyFromCreation (panel/go/internal/agent/services/ssl_test.go)

  # ── C: DERIVED, not counted. #748: a threshold over a population cannot name
  # the member that left, so enumerate the writers and check the set itself.
  local WRITERS
  WRITERS=$($G -n 'sslAcmeAccountPath' "$src" \
            | $G -E 'os\.WriteFile|OpenFile|Chmod|sslPersistAccountCredentials\(' | wc -l | tr -d ' ')
  eq "C1 exactly one call site writes the account path" "$WRITERS" "1"
}

echo "── A + C: the account handed back is the one whose key is on disk ──"
run_arms "$PRODSRC"

# ── Z: every arm above has now printed its own failure at least once ─────────
#
# A green arm is a claim, not a measurement. Each mutation below is the real
# defect — the shape the code actually had, or the shape a plausible "cleanup"
# would produce — and the arm named beside it MUST go red. An arm that stays
# green here is decoration and must be deleted or rewritten.
echo
echo "── Z: plant each defect back and watch the matching arm go red ──"
# $1 label · $2 the arm that MUST go red · $3+ a command reading PRODSRC on stdin
mutate_and_expect() {
  local label="$1" expect_arm="$2"; shift 2
  local copy="$TMP/mut.go"
  "$@" < "$PRODSRC" > "$copy"
  if cmp -s "$copy" "$PRODSRC"; then
    bad "Z:$label" "the mutation changed NOTHING — the pattern no longer matches, so this check is vacuous"
    return
  fi
  local out sp sf
  sp=$PASS; sf=$FAIL
  # ⚠ Strip ANSI before matching. The arms colour the ✗, so a literal "✗ A1"
  # never matches — the reset sequence sits between the mark and the name. The
  # first draft of this harness reported all six arms as unfalsifiable when
  # every one of them had fired correctly.
  out=$(PASS=0; FAIL=0; run_arms "$copy" 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g')
  PASS=$sp; FAIL=$sf
  if ! printf '%s' "$out" | $G -qE "✗ ${expect_arm}( |\$)"; then
    bad "Z:$label" "expected arm '$expect_arm' to fail and it did not. Arms said: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-300)"
    return
  fi
  # ⛔ An arm that goes red whenever ANY sibling does has not been shown to test
  # its own claim. Where a mutation names an arm that must STAY GREEN, assert it
  # — that is what separates "A3 fired" from "A3 is independent of A1".
  if [ -n "${MUST_STAY_GREEN:-}" ] && ! printf '%s' "$out" | $G -qE "✓ ${MUST_STAY_GREEN}( |\$)"; then
    bad "Z:$label" "$expect_arm went red, but so did ${MUST_STAY_GREEN}, which had to stay green — the mutation is too broad to attribute"
    return
  fi
  ok "Z:$label → $expect_arm went red${MUST_STAY_GREEN:+, $MUST_STAY_GREEN stayed green}"
}

m_drop_lock()    { sed -E 's|^[[:space:]]*sslAccountInit\.Lock\(\)[[:space:]]*$||'; }
m_keep_minted()  { sed -E 's|if outcome == sslWritten \{|if outcome == sslWritten \|\| outcome == sslAdopted {|'; }
m_no_reread()    { sed -E 's|^[[:space:]]*acct, err = sslStoredAccount\(ctx\)[[:space:]]*$|	err = nil|'; }
m_rename_anchor(){ sed -E 's|func SslLoadOrCreateAccount\(|func SslLoadOrCreateAcct(|'; }
# ⛔ The ORDERING mutation must MOVE the lock, not delete it. Deleting it also
# kills A1, so a deleting mutation cannot tell whether A3 checks ordering or is
# merely a second copy of A1. This one re-emits the lock AFTER the read, so A1
# stays green and only A3 may fail.
m_lock_after()   { awk '/^[[:space:]]*sslAccountInit\.Lock\(\)[[:space:]]*$/ { lock = $0; next }
                        /key, err := ecdsa\.GenerateKey/ && lock { print lock; lock = "" }
                        { print }'; }

mutate_and_expect "the lock is removed entirely"             "A1" m_drop_lock
MUST_STAY_GREEN=A1 mutate_and_expect "the lock is MOVED below the check" "A3" m_lock_after
# (B1/B4 mutations retired with their arms — the Go unit tests above are the
#  falsifiable check for create-exclusive and 0600.)
mutate_and_expect "losing the race keeps the minted account" "A6" m_keep_minted
MUST_STAY_GREEN=A6 mutate_and_expect "the Adopted path stops re-reading" "A7" m_no_reread
mutate_and_expect "the anchor is renamed (subject vanishes)" "A0" m_rename_anchor

echo
echo "──────────────────────────────────────────"
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
