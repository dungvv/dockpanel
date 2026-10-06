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
assert_absent   "update.sh does not infer traefik from a container/service" "$UPDATE" 'docker ps'
assert_absent   "update.sh does not default the marker to traefik"          "$UPDATE" 'INSTALLATION_MODE:-traefik'

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