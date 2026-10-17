#!/usr/bin/env bash
# update-connection-resilience-pin-e2e.sh — s447
#
# Pins the docker_apps finding named in [[project_dockpanel_tech_debt_p185]]
# §A: Update / change-image / edit-env recreate a container between
# `remove_container` and `create_container`, and until this fix every one of
# those calls ran on the request's own (cancellable) lifetime — agent-side
# (dockerAppsUpdate, dockerAppsUpdateEnv, dockerAppsChangeImage in
# panel/go/internal/agent/routes/docker_apps.go) AND, for two of the three
# doors, backend-side too (rtDockerAppsUpdateEnv / rtDockerAppsUpdateImage in
# panel/go/internal/api/rt_docker_apps.go; rtDockerAppsUpdateApp already
# detached). A dropped connection (demo.dockpanel.dev is Cloudflare-proxied
# with a ~100s origin budget, well inside the 900s these calls are allowed)
# cancelled the in-flight call mid-recreate: the app container vanishes, only
# its bind-mounted data survives.
#
# Fix (Rust: `tokio::spawn(...).await`; Go port): run the recreate on
# `context.WithoutCancel(r.Context())` (or a `go func()` on
# context.Background()), so a cut connection cannot cancel it.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  docker_apps recreate doors — connection resilience (s447)"
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
flat() { tr '\n' ' ' <<< "$1" | tr -s ' '; }

fnbody() {
  awk -v fn="$2" '
    (index($0, "func " fn "(") || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) && !started { started=1 }
    started {
      n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth += n - m; print
      if (opened || n>0) opened=1
      if (opened && depth<=0) exit
    }
  ' <<< "$1"
}

AGENT_ROUTES=panel/go/internal/agent/routes/docker_apps.go
BACKEND_ROUTES=panel/go/internal/api/rt_docker_apps.go
[ -f "$AGENT_ROUTES" ] || { bad "SETUP subject missing: $AGENT_ROUTES"; exit 1; }
[ -f "$BACKEND_ROUTES" ] || { bad "SETUP subject missing: $BACKEND_ROUTES"; exit 1; }
AGENT_SRC=$(code "$AGENT_ROUTES")
BACKEND_SRC=$(code "$BACKEND_ROUTES")

# ── §A whole-file control: agent routes detach >= 3 recreate calls ─────────

AGENT_DETACH_COUNT=$(grep -c 'context.WithoutCancel(r.Context())' <<< "$AGENT_SRC")
if [ "$AGENT_DETACH_COUNT" -ge 3 ]; then
  ok "A1 agent routes/docker_apps.go has $AGENT_DETACH_COUNT context.WithoutCancel(r.Context()) sites (>= 3)"
else
  bad "A1 agent routes/docker_apps.go has only $AGENT_DETACH_COUNT context.WithoutCancel(r.Context()) sites, expected >= 3"
fi

# ── §B each of the 3 agent handlers detaches its recreate call ─────────────

for PAIR in dockerAppsUpdate:DockerAppsUpdateApp dockerAppsUpdateEnv:DockerAppsUpdateEnv dockerAppsChangeImage:DockerAppsChangeContainerImage; do
  FN=${PAIR%%:*}; CALL=${PAIR#*:}
  BODY=$(flat "$(fnbody "$AGENT_SRC" "$FN")")
  if [ -z "$BODY" ]; then
    bad "B:$FN could not extract agent handler"
  elif has "$BODY" "services\.$CALL\(context\.WithoutCancel\(r\.Context\(\)\)"; then
    ok "B:$FN runs services.$CALL on a context the dropped connection cannot cancel"
  else
    bad "B:$FN calls services.$CALL on the request context (or not at all) — a dropped connection cancels it mid-recreate"
  fi
done

# ── §C both backend doors detach too (update_app already did) ──────────────

BODY=$(flat "$(fnbody "$BACKEND_SRC" rtDockerAppsUpdateApp)")
if [ -z "$BODY" ]; then
  bad "C:rtDockerAppsUpdateApp could not extract backend handler"
elif has "$BODY" 'go func\(\) \{[[:space:]]+ctx := context\.Background\(\)'; then
  ok "C:rtDockerAppsUpdateApp runs its long agent call in a goroutine on context.Background()"
else
  bad "C:rtDockerAppsUpdateApp no longer detaches its agent call — a browser disconnect cancels the backend leg mid-recreate"
fi

BODY=$(flat "$(fnbody "$BACKEND_SRC" rtDockerAppsRecreate)")
if [ -z "$BODY" ]; then
  bad "C:rtDockerAppsRecreate could not extract backend helper"
elif has "$BODY" 'ctx = context\.WithoutCancel\(ctx\).*result, err := call\(ctx\)'; then
  ok "C:rtDockerAppsRecreate detaches ctx (WithoutCancel) before the agent call"
else
  bad "C:rtDockerAppsRecreate runs the agent call on a cancellable ctx — a browser disconnect cancels the backend leg mid-recreate"
fi

for FN in rtDockerAppsUpdateEnv rtDockerAppsUpdateImage; do
  BODY=$(flat "$(fnbody "$BACKEND_SRC" "$FN")")
  if [ -z "$BODY" ]; then
    bad "C:$FN could not extract backend handler"
  elif has "$BODY" 'rtDockerAppsRecreate\(ctx, st, agent' && ! has "$BODY" 'agent\.(Put|Post)Long\(r\.Context\(\)'; then
    ok "C:$FN routes its long agent call through the detaching rtDockerAppsRecreate"
  else
    bad "C:$FN awaits the agent call on the request context — a browser disconnect cancels the backend leg mid-recreate"
  fi
done

echo
echo "=================================================="
echo "  PASS=$PASS FAIL=$FAIL"
echo "=================================================="

[ "$FAIL" -eq 0 ]
