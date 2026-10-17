#!/usr/bin/env bash
# cli-password-args-pin-e2e.sh — s441
#
# ONE PROPERTY: an operator-chosen database password never has to be typed
# as a bare CLI argument.
#
# `dockpanel db create` and `dockpanel backup db-create` took a required
# clap `--password <VALUE>` flag (CWE-214): the value lands in shell history
# and stays visible to any local user via `ps`/`/proc/<pid>/cmdline` for the
# life of the process. `iac.rs`'s own password print is a DIFFERENT case
# (a server-GENERATED password, printed after the fact — nothing prior ever
# existed to leak); these two took a HUMAN-CHOSEN secret in as an argument,
# the inverse shape.
#
# Fix: `--password` becomes optional, a new `--password-stdin` reads one
# line from stdin instead, and a shared `resolve_password` helper falls
# back to an interactive masked prompt (via `rpassword`, which reads
# /dev/tty directly so it isn't confused by stdin redirection) when neither
# flag is given. `--password` still works for scripts that already use it
# — this closes the door on it being the ONLY way, not on it existing.
#
# Go port: the flags are cli.go's passwordFlags + spec.conflicts on `db
# create` / `backup db-create`; the helper is db.go::resolvePassword, the
# masked prompt is promptTTY (golang.org/x/term on /dev/tty, rpassword's
# equivalent); the commands are cmdDBCreate (db.go) and cmdDBBackupCreate
# (backup.go). §A-§C are now Go unit tests
# (panel/go/internal/cli/pin_cli_password_args_test.go).
#
# §A `password` is optional (`Option<String>`) on both commands, not a bare
#    required `String` — the shape that forced argv exposure.
# §B `--password-stdin` exists on both and conflicts with `--password`
#    (clap `conflicts_with`, so a caller can't send contradictory input).
# §C the shared `resolve_password` helper exists and implements all three
#    tiers: explicit value, stdin line, interactive prompt.
# §D both command functions actually CALL `resolve_password` — position:
#    before the password is embedded in the outgoing request body, so the
#    resolved (not raw) value is what gets sent.
# §E the CLI crate depends on `rpassword` for the masked prompt.
# §F docs no longer document `--password` as the only/required path.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  CLI password args — source pins (s441)"
echo "=================================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

code() {
  [ -f "$1" ] || return 0
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

has()  { grep -qE -- "$2" <<< "$1"; }

fnbody() {
  awk -v fn="$2" '
    !started && (index($0, "func " fn "(") == 1 || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) { started=1 }
    started {
      n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth += n - m; print
      if (opened || n>0) opened=1
      if (opened && depth<=0) exit
    }
  ' <<< "$1"
}

offset() {
  local body="$1" needle="$2"
  local head="${body%%"$needle"*}"
  if [ "$head" = "$body" ]; then
    echo -1
  else
    echo "${#head}"
  fi
}

before() {
  local body="$1" first="$2" second="$3"
  local o1 o2
  o1=$(offset "$body" "$first")
  o2=$(offset "$body" "$second")
  [ "$o1" != -1 ] && [ "$o2" != -1 ] && [ "$o1" -lt "$o2" ]
}

CLI=panel/go/internal/cli
DB=$CLI/db.go
DB_C=$(code "$DB")
BACKUP=$CLI/backup.go
BACKUP_C=$(code "$BACKUP")

RESOLVE_BODY=$(fnbody "$DB_C" "resolvePassword")
PROMPT_BODY=$(fnbody "$DB_C" "promptTTY")
CMD_DB_CREATE_BODY=$(fnbody "$DB_C" "cmdDBCreate")
CMD_DB_BACKUP_CREATE_BODY=$(fnbody "$BACKUP_C" "cmdDBBackupCreate")

# ── §A password is optional, not a bare required value ──────────────────
# A1 retired: covered by TestPinCliPasswordArgsFlags (panel/go/internal/cli/pin_cli_password_args_test.go)
# A2 retired: covered by TestPinCliPasswordArgsFlags (panel/go/internal/cli/pin_cli_password_args_test.go)

# ── §B --password-stdin exists and conflicts with --password ────────────
# B1 retired: covered by TestPinCliPasswordArgsFlags (panel/go/internal/cli/pin_cli_password_args_test.go)
# B2 retired: covered by TestPinCliPasswordArgsFlags + TestPinCliPasswordArgsConflictRejected (panel/go/internal/cli/pin_cli_password_args_test.go)
# B3 retired: covered by TestPinCliPasswordArgsFlags (panel/go/internal/cli/pin_cli_password_args_test.go)
# B4 retired: covered by TestPinCliPasswordArgsFlags (panel/go/internal/cli/pin_cli_password_args_test.go)

# ── §C resolvePassword implements all three resolution tiers ───────────
echo "── §C resolvePassword: explicit value, stdin, interactive prompt ──"

# C1 retired: covered by TestPinCliPasswordArgsResolve (panel/go/internal/cli/pin_cli_password_args_test.go)
# C2 retired: covered by TestPinCliPasswordArgsResolve (panel/go/internal/cli/pin_cli_password_args_test.go)
# C3 retired: covered by TestPinCliPasswordArgsResolve (panel/go/internal/cli/pin_cli_password_args_test.go)

if has "$RESOLVE_BODY" 'promptTTY\(prompt\)' \
  && has "$PROMPT_BODY" 'os\.OpenFile\("/dev/tty"' && has "$PROMPT_BODY" 'term\.ReadPassword\('; then
  ok "C4 the fallback tier is an interactive masked prompt on /dev/tty (promptTTY → term.ReadPassword)"
else
  bad "C4 no interactive masked-prompt fallback — a caller with neither flag would get... what?"
fi

# C5 retired: covered by TestPinCliPasswordArgsResolve (panel/go/internal/cli/pin_cli_password_args_test.go)

# ── §D both commands actually CALL resolvePassword ───────────────────────
echo "── §D cmdDBCreate / cmdDBBackupCreate resolve before sending ──"

if has "$CMD_DB_CREATE_BODY" 'resolvePassword\(password, fromStdin,'; then
  ok "D1 cmdDBCreate calls resolvePassword"
else
  bad "D1 cmdDBCreate never calls resolvePassword — the optional-flag plumbing is decorative"
fi

if before "$CMD_DB_CREATE_BODY" "resolvePassword" 'map[string]any{' \
  && has "$CMD_DB_CREATE_BODY" '"password": pw'; then
  ok "D2 resolvePassword runs before the request body is built, and the body sends the resolved value"
else
  bad "D2 resolvePassword runs after (or the request body doesn't use its result) — position wrong"
fi

if has "$CMD_DB_BACKUP_CREATE_BODY" 'resolvePassword\(password, fromStdin,'; then
  ok "D3 cmdDBBackupCreate calls resolvePassword"
else
  bad "D3 cmdDBBackupCreate never calls resolvePassword"
fi

if before "$CMD_DB_BACKUP_CREATE_BODY" "resolvePassword" 'map[string]any{' \
  && has "$CMD_DB_BACKUP_CREATE_BODY" '"password": +pw'; then
  ok "D4 resolvePassword runs before the request body is built, and the body sends the resolved value"
else
  bad "D4 resolvePassword runs after (or the request body doesn't use its result) — position wrong"
fi

# ── §E the module actually depends on the masked-prompt package ──────────
echo "── §E go.mod declares the prompt dependency ──"

if grep -qE '^[[:space:]]*golang\.org/x/term v' panel/go/go.mod; then
  ok "E1 panel/go/go.mod depends on golang.org/x/term (rpassword's equivalent)"
else
  bad "E1 no golang.org/x/term dependency in panel/go/go.mod — C4 above would not even compile"
fi

# ── §F docs reflect the new, safer default ────────────────────────────────
echo "── §F docs no longer document --password as the only path ──"

DOC=docs/cli-reference.md
if [ -f "$DOC" ] && grep -q -- "--password-stdin" "$DOC"; then
  ok "F1 $DOC documents --password-stdin"
else
  bad "F1 $DOC does not mention --password-stdin"
fi

if [ -f "$DOC" ] && ! grep -qE '\| `--password` \| Yes \|' "$DOC"; then
  ok "F2 $DOC no longer lists --password as Required"
else
  bad "F2 $DOC's db create table still marks --password as Required"
fi

echo
echo "=================================================="
echo "  PASS=$PASS FAIL=$FAIL"
echo "=================================================="

[ "$FAIL" -eq 0 ]
