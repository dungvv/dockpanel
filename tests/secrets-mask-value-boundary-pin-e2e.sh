#!/usr/bin/env bash
# secrets-mask-value-boundary-pin-e2e.sh — s442
#
# ONE PROPERTY: masking a secret's value for display never panics, regardless
# of what characters that value contains.
#
# The API's `mask_value` (then routes/secrets.rs; now rtSecretsMaskValue in
# `panel/go/internal/api/rt_secrets.go`) sliced the first 4
# BYTES (`&value[..4]`) of any value longer than 4 bytes. Rust panics if a
# byte-slice boundary doesn't land on a UTF-8 char boundary — reachable from
# any secret value containing a multi-byte character (a pasted passphrase,
# API key, or credential with non-ASCII content). Hit from every masking
# call site: `create_secret`'s response (after the row is already committed,
# so the secret is saved but the caller never sees it), `update_secret`'s
# response, and every subsequent `list_secrets` call with `reveal=false` —
# so a single boundary-violating secret in a vault permanently breaks that
# vault's default masked listing until the offending secret is deleted via
# `reveal=true` (which skips mask_value entirely).
#
# Fix: walk `.chars()` instead of bytes. A char boundary can't be straddled
# by construction — `.chars().take(4)` always stops on one.
#
# §A mask_value walks chars, not raw byte-index slicing.
# §B mask_value is still reachable from all 3 call sites the finder counted.
# §C the fix threshold (4-or-fewer fully masked, more gets a 4-char prefix)
#    is preserved — this is a boundary-safety fix, not a behavior change.
# §D executed unit tests exist for the exact panic scenario (multi-byte value
#    straddling the old byte offset) and the all-multibyte case — run here
#    with `go test`. (Go byte-slicing does not panic, it silently yields
#    invalid UTF-8; the property pinned is the same: a char-boundary-safe mask.)

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  secrets mask_value UTF-8 boundary — source pins (s442)"
echo "=================================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

code() {
  [ -f "$1" ] || return 0
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^[ \t]*//.*$}{}gm;
    s{[ \t]+//[^"`\n]*$}{}gm;
  ' "$1"
}

has()  { grep -qE -- "$2" <<< "$1"; }

# One Go func (or method) body, bounded by its own closing `}` at column 0.
fnbody() {
  awk -v fn="$2" '
    !started && (index($0, "func " fn "(") == 1 || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) {
      started=1; print
      o=gsub(/\{/,"{"); c=gsub(/\}/,"}"); if (o>0 && o==c) exit
      next
    }
    started { print; if ($0 == "}") exit }
  ' <<< "$1"
}

SECRETS=panel/go/internal/api/rt_secrets.go
SECRETS_C=$(code "$SECRETS")
MASK_BODY=$(fnbody "$SECRETS_C" "rtSecretsMaskValue")

# ── §A the mask walks characters, not bytes ──────────────────────────────
echo "── §A rtSecretsMaskValue walks chars, not byte indices ──"

if [ -n "$MASK_BODY" ]; then
  ok "A1 rtSecretsMaskValue exists"
else
  bad "A1 rtSecretsMaskValue is missing — every arm below measures nothing"
fi

# A2/A3/A4 retired: covered by TestRtSecretsMultibyteValueStraddlingTheOldByteOffset,
# TestRtSecretsAllMultibyteValue and TestRtSecretsASCIIValuesKeepTheFourCharPrefix
# (panel/go/internal/api/rt_secrets_test.go) — the char-boundary walk and the
# 4-character prefix are behaviour, asserted by calling the function (and run in §D).

# ── §B every known call site still reaches the mask ──────────────────────
echo "── §B rtSecretsMaskValue's call-site count is unchanged (3) ──"

# Go keeps tests in rt_secrets_test.go, so the whole (comment-stripped) file
# is production code.
CALL_COUNT=$(grep -c 'rtSecretsMaskValue(' <<< "$SECRETS_C")
# 3 call sites + 1 definition = 4 occurrences of the identifier.
if [ "$CALL_COUNT" -eq 4 ]; then
  ok "B1 rtSecretsMaskValue appears 4 times (1 definition + 3 call sites), matching the finder's exhaustiveness claim"
else
  bad "B1 rtSecretsMaskValue appears $CALL_COUNT times, expected 4 — a call site was added, removed, or the fix moved the definition"
fi

# ── §C the masking threshold behavior is unchanged ────────────────────────
# C1/C2 retired: covered by TestRtSecretsShortValuesAreFullyMasked and
# TestRtSecretsASCIIValuesKeepTheFourCharPrefix (panel/go/internal/api/rt_secrets_test.go).

# ── §D executed tests cover the exact panic scenario ──────────────────────
echo "── §D the unit tests for the exact byte-offset-4 input exist AND pass ──"

TESTS='^(TestRtSecretsMultibyteValueStraddlingTheOldByteOffset|TestRtSecretsAllMultibyteValue|TestRtSecretsShortValuesAreFullyMasked|TestRtSecretsASCIIValuesKeepTheFourCharPrefix)$'
GT=$(cd panel/go && go test ./internal/api/ -run "$TESTS" -count=1 -v 2>&1)
NPASS=$(grep -c -- '--- PASS' <<< "$GT")
if [ "$NPASS" -eq 4 ] && grep -q '^ok' <<< "$GT"; then
  ok "D1 all 4 mask tests ran and passed (straddling offset, all-multibyte, short, ASCII prefix)"
else
  bad "D1 expected 4 passing mask tests, got $NPASS — $(grep -E -- '--- FAIL|^FAIL|cannot|no tests' <<< "$GT" | head -3 | tr '\n' ' ')"
fi

# D2 retired (obsolete in Go): a dedicated `mod mask_value_tests` is a Rust #[cfg(test)] layout; Go tests live in rt_secrets_test.go and D1 runs them.

if grep -qE '日|本|語' panel/go/internal/api/rt_secrets_test.go; then
  ok "D3 the tests use real multi-byte (non-ASCII) literals, not just an assertion of intent"
else
  bad "D3 no multi-byte literal found — the panic scenario may not actually be exercised"
fi

echo
echo "=================================================="
echo "  PASS=$PASS FAIL=$FAIL"
echo "=================================================="

[ "$FAIL" -eq 0 ]
