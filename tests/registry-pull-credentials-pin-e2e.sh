#!/usr/bin/env bash
# registry-pull-credentials-pin-e2e.sh — s447
#
# Pins the docker_apps.rs finding named in [[project_dockpanel_tech_debt_p185]]
# §C: `GET /apps/registries` read a literal `/root/.docker/config.json`, but
# every `docker` CLI invocation runs through `safe_command`, which points
# `DOCKER_CONFIG` at `crate::safe_cmd::DOCKER_CONFIG_DIR`
# (`/var/lib/dockpanel/docker`) — so a login always landed somewhere the
# route never looked, and the panel's "Configured registries" list was
# always empty. Separately, every bollard `create_image` pull (template
# deploy, app update, change-image, and compose deploy) passed
# `credentials: None` regardless, so a private-image deploy failed even
# immediately after a successful login.
#
# Fix: `list_registries` reads `DOCKER_CONFIG_DIR`; a new
# `registry_credentials_for(image)` helper (now
# panel/go/internal/agent/services/docker_apps.go DockerAppsRegistryCredentialsFor) looks up
# saved credentials by the image's parsed registry and is wired into all 4
# production `create_image` call sites (3 in docker_apps.rs, 1 in
# compose.rs). A 5th `create_image` call exists only in a `#[cfg(test)]`
# probe helper and is deliberately excluded — it pulls a public test image
# and needs no credentials.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  docker_apps.rs registry pull credentials (s447)"
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
COMPOSE=panel/go/internal/agent/services/compose.go
for f in "$SERVICES" "$ROUTES" "$COMPOSE"; do
  [ -f "$f" ] || { bad "SETUP subject missing: $f"; exit 1; }
done
SERVICES_SRC=$(code "$SERVICES")
ROUTES_SRC=$(code "$ROUTES")

# ── §A list_registries reads the config DOCKER_CONFIG actually points at ────

LISTREG=$(flat "$(fnbody "$ROUTES_SRC" "dockerAppsListRegistries")")
if [ -z "$LISTREG" ]; then
  bad "A0 could not extract dockerAppsListRegistries"
elif has "$LISTREG" 'safecmd\.DockerConfigDir'; then
  ok "A1 dockerAppsListRegistries reads safecmd.DockerConfigDir, not a hardcoded /root path"
else
  bad "A1 dockerAppsListRegistries still reads a path other than safecmd.DockerConfigDir — logins land somewhere this route never looks"
fi

# ── §B DockerAppsRegistryCredentialsFor exists and is reachable outside this file ─

RCF=$(flat "$(fnbody "$SERVICES_SRC" "DockerAppsRegistryCredentialsFor")")
if [ -z "$RCF" ]; then
  bad "B0 could not extract DockerAppsRegistryCredentialsFor"
else
  ok "B0 DockerAppsRegistryCredentialsFor extracted"
  if has "$RCF" 'safecmd\.DockerConfigDir' && has "$RCF" 'json:"auths"'; then
    ok "B1 DockerAppsRegistryCredentialsFor reads safecmd.DockerConfigDir's config.json auths map"
  else
    bad "B1 DockerAppsRegistryCredentialsFor doesn't read the same auths map docker login writes"
  fi
fi
# B2 retired (obsolete in Go): pub(crate) visibility has no Go analogue — the
# helper is an exported identifier and compose.go calling it (C3) only
# compiles because it is.

# ── §C every production pull passes real credentials ───────────────────────
# Go wraps bollard's create_image as DockerAppsPullImage(ctx, docker, image,
# creds); docker.ImagePull is called only inside that wrapper. Test code lives
# in _test.go files, so the whole file is production code.

PULL_DEFS=$(grep -c '^func DockerAppsPullImage(' <<< "$SERVICES_SRC")
RAW_PULLS=$(grep -c 'docker\.ImagePull(' <<< "$SERVICES_SRC")
if [ "$PULL_DEFS" -eq 1 ] && [ "$RAW_PULLS" -eq 1 ]; then
  ok "C0 docker.ImagePull is reached in docker_apps.go only through DockerAppsPullImage"
else
  bad "C0 docker_apps.go has $RAW_PULLS direct docker.ImagePull call(s) / $PULL_DEFS wrapper definition(s), expected 1/1 — a pull bypasses the credentials parameter"
fi
SITES=$(grep -E 'DockerAppsPullImage\(' <<< "$SERVICES_SRC" | grep -v '^func ')
CI_COUNT=$(grep -c . <<< "$SITES")
WIRED=$(grep -c 'DockerAppsRegistryCredentialsFor(' <<< "$SITES")
if [ "$CI_COUNT" -eq 3 ]; then
  ok "C1 docker_apps.go has 3 production pull sites"
else
  bad "C1 docker_apps.go has $CI_COUNT production pull sites, expected 3 — this suite's count needs updating"
fi
if [ "$CI_COUNT" -gt 0 ] && [ "$WIRED" -eq "$CI_COUNT" ]; then
  ok "C2 every one of the $CI_COUNT pull sites passes DockerAppsRegistryCredentialsFor"
else
  bad "C2 only $WIRED of $CI_COUNT pull sites pass DockerAppsRegistryCredentialsFor — a pull still passes nil"
fi

COMPOSE_SRC=$(code "$COMPOSE")
DEPLOY_SVC=$(flat "$(fnbody "$COMPOSE_SRC" "composeDeployService")")
if has "$DEPLOY_SVC" 'DockerAppsPullImage\([^)]*DockerAppsRegistryCredentialsFor'; then
  ok "C3 compose.go composeDeployService passes DockerAppsRegistryCredentialsFor, not nil"
else
  bad "C3 compose.go composeDeployService still pulls with nil credentials"
fi

echo
echo "=================================================="
echo "  PASS=$PASS FAIL=$FAIL"
echo "=================================================="

[ "$FAIL" -eq 0 ]
