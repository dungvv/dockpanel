#!/usr/bin/env bash
#
# DockPanel — installation-mode compatibility pins (traefik-first install).
#
# The invariant: a FRESH setup.sh run resolves to `traefik`, while update.sh
# treats a MISSING or invalid mode marker as legacy `nginx`. The asymmetry is the
# whole point — every box that predates the marker is an nginx one, so the update
# path must never infer traefik from an existing container or setting.
#
# Source analysis only: offline, deterministic, no /etc, no root, no box.
#   run: bash tests/traefik-first-install-pin-e2e.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

SETUP=scripts/setup.sh
UPDATE=scripts/update.sh

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

# Comments blanked (kept at full height, so line numbers stay true). A pin that
# greps RAW source is satisfied by a paragraph of prose explaining the very line
# it is about (s338); these assertions are about CODE.
code() { awk '/^[[:space:]]*#/ { print ""; next } { print }' "$1"; }

# assert_contains <label> <file> <needle> — the whole point of the arm, phrased
# as a substring the script must contain. `grep -c` (not -q): under pipefail a
# -q match exits at the first hit and SIGPIPEs the producer, reading as failure.
assert_contains() {
    local label="$1" file="$2" needle="$3"
    if [ "$(code "$file" | grep -cF -- "$needle")" -gt 0 ]; then
        ok "$label"
    else
        bad "$label — missing in $file: $needle"
    fi
}

# assert_absent <label> <file> <needle> — a claim the mode logic must NOT carry.
assert_absent() {
    local label="$1" file="$2" needle="$3"
    if [ "$(code "$file" | grep -cF -- "$needle")" -gt 0 ]; then
        bad "$label — present in $file but must not be: $needle"
    else
        ok "$label"
    fi
}

echo "── fresh install defaults to traefik ──"
assert_contains "setup.sh names the marker path"      "$SETUP" 'INSTALLATION_MODE_FILE="${CONFIG_DIR}/installation-mode"'
assert_contains "setup.sh defaults fresh install to traefik" "$SETUP" 'INSTALLATION_MODE="${INSTALLATION_MODE:-traefik}"'
assert_contains "setup.sh validates only traefik|nginx" "$SETUP" 'traefik|nginx)'
assert_contains "setup.sh exposes installation_mode()"       "$SETUP" 'installation_mode()'
assert_contains "setup.sh exposes write_installation_mode()" "$SETUP" 'write_installation_mode()'
assert_contains "setup.sh exposes is_legacy_nginx_install()" "$SETUP" 'is_legacy_nginx_install()'

echo "── update falls back to legacy nginx ──"
assert_contains "update.sh reads the marker"          "$UPDATE" 'installation-mode'
assert_contains "update.sh resolves missing markers to nginx" "$UPDATE" "printf 'nginx'"
assert_contains "update.sh warns on a missing/invalid marker" "$UPDATE" 'treating as legacy nginx'
assert_contains "update.sh validates only traefik|nginx"      "$UPDATE" 'traefik|nginx)'
assert_contains "update.sh exposes is_legacy_nginx_install()" "$UPDATE" 'is_legacy_nginx_install()'

# The mode must be resolved from the MARKER, never inferred from a running
# container or an existing service — the defect this marker exists to prevent.
# Scoped to the mode helpers, NOT the whole file: update.sh legitimately inspects
# containers everywhere else (backup, health checks, service restarts), and a
# whole-file pin would block that. Only these two functions may not consult one.
mode_helpers() { # <file> <fn> <fn>
    local file="$1" start end fn
    for fn in "$2" "$3"; do
        start=$(code "$file" | grep -n "^$fn() {" | head -1 | cut -d: -f1)
        [ -n "$start" ] || continue
        end=$(code "$file" | tail -n "+$start" | grep -n '^}' | head -1 | cut -d: -f1)
        code "$file" | tail -n "+$start" | head -n "$end"
    done
}

for fn in installation_mode is_legacy_nginx_install; do
    body=$(mode_helpers "$UPDATE" "$fn" "$fn")
    if [ -z "$body" ]; then
        bad "update.sh $fn() is extractable for behavioural check"
    elif printf '%s\n' "$body" | grep -qE '\b(docker|systemctl|podman)\b'; then
        bad "update.sh $fn() must not consult a container or service"
    else
        ok "update.sh $fn() resolves from the marker alone"
    fi
done

assert_absent   "update.sh does not default the marker to traefik"          "$UPDATE" 'INSTALLATION_MODE:-traefik'

echo "── behavioral: mode helper with nonexistent marker ──"
# Extract and execute the helpers in a subshell with no marker. Verifies:
# 1. stdout is exactly 'nginx' (command substitution captures nothing else)
# 2. is_legacy_nginx_install() succeeds
# 3. No unset var expansion under nounset
HELPER_TMP=$(mktemp -d)
trap 'rm -rf "$HELPER_TMP"' EXIT
HELPER_MARKER="$HELPER_TMP/installation-mode"

(
    set -euo pipefail
    CONFIG_DIR="$HELPER_TMP"
    INSTALLATION_MODE_FILE="$HELPER_MARKER"
    # update.sh's installation_mode() calls warn on a missing marker; stub it so
    # the extracted function runs standalone. The stub mirrors update.sh: to stderr.
    warn() { printf '%s\n' "$*" >&2; }

    # Extract installation_mode and is_legacy_nginx_install from update.sh
    eval "$(sed -n '/^installation_mode() {/,/^}/p' "$UPDATE")"
    eval "$(sed -n '/^is_legacy_nginx_install() {/,/^}/p' "$UPDATE")"

    mode=$(installation_mode)
    [ "$mode" = "nginx" ] || { printf 'expected nginx, got: %s\n' "$mode" >&2; exit 1; }
    is_legacy_nginx_install || { printf 'is_legacy_nginx_install failed\n' >&2; exit 1; }
    printf 'nginx'
) > "$HELPER_TMP/result" 2>"$HELPER_TMP/err"

if [ "$(cat "$HELPER_TMP/result")" = "nginx" ] && [ -z "$(cat "$HELPER_TMP/err")" ]; then
    ok "update helper with missing marker outputs exactly 'nginx' and succeeds"
elif [ "$(cat "$HELPER_TMP/result")" = "nginx" ]; then
    # Stderr not empty: warning is acceptable if it doesn't break command substitution
    ok "update helper with missing marker outputs exactly 'nginx' (warning on stderr)"
else
    bad "update helper with missing marker — expected 'nginx', got: $(cat "$HELPER_TMP/result")"
fi

# The marker helper must be defined BEFORE any consumer reads it — a value
# available only after the restart it is meant to gate is no use.
SETUP_MARKER_LN=$(code "$SETUP" | grep -nF 'INSTALLATION_MODE_FILE="${CONFIG_DIR}/installation-mode"' | head -1 | cut -d: -f1)
UPDATE_MARKER_LN=$(code "$UPDATE" | grep -nF 'INSTALLATION_MODE_FILE=' | head -1 | cut -d: -f1)
UPDATE_RESTART_LN=$(code "$UPDATE" | grep -nF 'systemctl stop dockpanel-agent dockpanel-api' | head -1 | cut -d: -f1)
if [ -n "$SETUP_MARKER_LN" ] && [ -n "$UPDATE_MARKER_LN" ] && [ -n "$UPDATE_RESTART_LN" ] \
   && [ "$UPDATE_MARKER_LN" -lt "$UPDATE_RESTART_LN" ]; then
    ok "update.sh resolves the mode before any service is stopped (mode L$UPDATE_MARKER_LN, stop L$UPDATE_RESTART_LN)"
else
    bad "update.sh must resolve the mode before any service is stopped (mode=${UPDATE_MARKER_LN:-none}, stop=${UPDATE_RESTART_LN:-none})"
fi

echo "──────────────────────────────────────────"
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
