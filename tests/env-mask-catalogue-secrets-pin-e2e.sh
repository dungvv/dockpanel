#!/usr/bin/env bash
# env-mask-catalogue-secrets-pin-e2e.sh — s447
#
# Pins docker_apps.rs's `GET /apps/{id}/env` mask gap named in
# [[project_dockpanel_tech_debt_p185]] §B: the route's mask condition was a
# substring heuristic (PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|AUTH) that never
# consulted the catalogue's own `secret: true` flag, so a declared-secret
# name that doesn't happen to contain one of those substrings was returned
# in the clear. 8 such names measured at HEAD before the fix: DB_PASS,
# POSTGRES_PWD, SURREAL_PASS, GOTIFY_DEFAULTUSER_PASS, PLEX_CLAIM,
# DATABASE_URL, CLICKHOUSE_DATABASE_URL, REDASH_DATABASE_URL.
#
# Fix: `catalogue_secret_env(name)` (now DockerAppsCatalogueSecretEnv in
# panel/go/internal/agent/services/docker_apps.go, mirroring
# DockerAppsCatalogueNonSecretEnv) OR'd into the route's mask condition
# (dockerAppsIsSensitive in panel/go/internal/agent/routes/docker_apps.go).
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  docker_apps.rs env mask — catalogue secret coverage (s447)"
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
flat() { tr '\n' ' ' <<< "$1" | tr -s ' '; }

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

SERVICES=panel/go/internal/agent/services/docker_apps.go
ROUTES=panel/go/internal/agent/routes/docker_apps.go
[ -f "$SERVICES" ] || { bad "SETUP subject missing: $SERVICES"; exit 1; }
[ -f "$ROUTES" ] || { bad "SETUP subject missing: $ROUTES"; exit 1; }
SERVICES_SRC=$(code "$SERVICES")
ROUTES_SRC=$(code "$ROUTES")

# ── §A DockerAppsCatalogueSecretEnv exists and reads the catalogue's own flag ─

CSE=$(flat "$(fnbody "$SERVICES_SRC" "DockerAppsCatalogueSecretEnv")")
if [ -z "$CSE" ]; then
  bad "A0 could not extract DockerAppsCatalogueSecretEnv from services/docker_apps.go"
else
  ok "A0 DockerAppsCatalogueSecretEnv extracted"
  if has "$CSE" 'v\.Secret'; then
    ok "A1 DockerAppsCatalogueSecretEnv reads the catalogue's own Secret flag"
  else
    bad "A1 DockerAppsCatalogueSecretEnv doesn't read v.Secret — not actually checking the catalogue"
  fi
fi

# ── §B GET /env ORs the catalogue check into the mask condition ─────────────
# The Go route's mask decision is factored into dockerAppsIsSensitive, which
# dockerAppsGetEnv calls per key.

GETENV=$(flat "$(fnbody "$ROUTES_SRC" "dockerAppsGetEnv")")
SENS=$(flat "$(fnbody "$ROUTES_SRC" "dockerAppsIsSensitive")")
if [ -z "$GETENV" ] || [ -z "$SENS" ]; then
  bad "B0 could not extract dockerAppsGetEnv / dockerAppsIsSensitive from routes/docker_apps.go"
else
  ok "B0 dockerAppsGetEnv and dockerAppsIsSensitive extracted"
  if has "$GETENV" 'dockerAppsIsSensitive\(' && has "$SENS" 'DockerAppsCatalogueSecretEnv\('; then
    ok "B1 GET /env's mask decision calls DockerAppsCatalogueSecretEnv"
  else
    bad "B1 GET /env never reaches DockerAppsCatalogueSecretEnv — the route and the fix are disconnected"
  fi
  if has "$SENS" '\|\| services\.DockerAppsCatalogueSecretEnv\(k\)'; then
    ok "B2 DockerAppsCatalogueSecretEnv is OR'd in (widens masking, never narrows the substring heuristic)"
  else
    bad "B2 DockerAppsCatalogueSecretEnv is not OR'd into dockerAppsIsSensitive — verify by hand it can't narrow the mask instead of widening it"
  fi
fi

# ── §C the 8 measured names are declared secret and masked ──────────────────
# C:* retired: covered by TestPinEnvMaskCatalogueSecretsTheMeasuredNamesAreMasked (panel/go/internal/agent/routes/pin_env_mask_catalogue_secrets_test.go)

echo
echo "=================================================="
echo "  PASS=$PASS FAIL=$FAIL"
echo "=================================================="

[ "$FAIL" -eq 0 ]
