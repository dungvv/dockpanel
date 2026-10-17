#!/usr/bin/env bash
# container-ownership-pin-e2e.sh — s475
#
# The `dockpanel.user.id` Docker label was never a missing primitive — deploy_app
# (Go: DockerAppsDeployApp in panel/go/internal/agent/services/docker_apps.go)
# stamps it on every container, and list_deployed_apps (DockerAppsListDeployedApps) reads it straight back
# onto DeployedApp.user_id in every /apps response. Two counters just ignored it:
#
#   §A  deploy's own quota check summed the TARGET SERVER's whole container list,
#       any user, against the CALLER's personal cap — someone else's containers
#       on a shared box counted against your limit, and your own containers on a
#       different server didn't.
#   §B  policy_usage (GET .../{user_id}/usage) summed the ENTIRE FLEET, any user,
#       so two different users' policies read back the identical number.
#   §C  list_policies never carried a usage figure at all — the frontend's
#       "Containers" column showed only the configured max, never what was used.
#
# All three now go through the SAME label already on every container. §D pins
# the shared helper fails closed on a missing/malformed label (excluded, not
# folded into anyone's total or some shared bucket). §E pins the primitive
# itself is not quietly removed out from under the counters that now depend on
# it. §F pins the fix has an actual visible surface, not just a backend field
# nothing reads.
#
# Pure source analysis: no box, no network, no build.
#
# Arms are written against the CAPABILITY (a per-user filter is consulted) not
# today's exact spelling, per lesson #122 in project_dockpanel_lessons.
#
# NO PIPES INTO `grep -q`. Under `set -o pipefail` grep -q closes the pipe on
# its first match, the upstream dies of SIGPIPE (141), and pipefail reports the
# whole pipeline failed — so an arm goes red on correct code. Every arm here
# feeds grep a here-string via the `has()`/`count()` helpers.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33m-\033[0m SKIP %s\n' "$1"; }

BACKEND=panel/go/internal/api/rt_docker_apps.go
AGENT=panel/go/internal/agent/services/docker_apps.go
FRONTEND=panel/frontend/src/pages/ContainerPolicies.tsx

for f in "$BACKEND" "$AGENT" "$FRONTEND"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT — see ownership-delete-pin-e2e.sh's own header for
# why the naive `/\*.*?\*/` block-comment strip is unsafe (it eats string
# literals containing `/*`); a block comment is only recognised on its own
# lines. Go line comments: whole-line `//`, and trailing `//` only when
# preceded by whitespace (so `https://` inside a literal survives).
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^[ \t]*//.*$}{}gm;
    s{[ \t]+//[^"`\n]*$}{}gm;
  ' "$1"
}

stripper_self_check() {
  local bad_files=0 f raw_decls stripped_decls
  for f in "$@"; do
    [ -f "$f" ] || continue
    raw_decls=$(grep -cE '^func ' "$f" || true)
    stripped_decls=$(grep -cE '^func ' <<< "$(code "$f")" || true)
    if [ "$raw_decls" != "$stripped_decls" ]; then
      bad "STRIPPER ATE CODE in $f: $raw_decls func declarations before, $stripped_decls after"
      bad_files=$((bad_files+1))
    fi
  done
  [ "$bad_files" -eq 0 ] && ok "comment stripper preserves every func declaration in all $# subjects"
}

subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }
has()   { grep -qE -- "$2" <<< "$1"; }

# Only DEAD-CODE markers belong here (lesson #133 — ordinary code is not one).
live() {
  ! grep -qE -- '(if false|&& false|\|\| true|_ = unused)' <<< "$1"
}

# The body of one top-level Go func (or method), bounded by its own closing
# `}` at column 0 (lesson #131 — a fixed -A window is not a function).
fnbody() {
  awk -v name="$2" '
    !inside && (index($0, "func " name "(") == 1 || $0 ~ ("^func \\([^)]*\\) " name "\\(")) { inside=1; next }
    inside { if ($0 == "}") exit; print }
  ' <<< "$1"
}

echo
echo "container-ownership-pin-e2e — a per-user quota must count what that user owns, fleet-wide"
echo

echo "§0 the harness measures its own preprocessing"
stripper_self_check "$BACKEND" "$AGENT"

echo
echo "§A deploy's own cap check is scoped to the caller, fleet-wide"
if ! BE=$(subj "$BACKEND"); then
  skip "§A — $BACKEND produced no code after stripping"
else
  DEPLOY=$(fnbody "$BE" "rtDockerAppsDeploy")
  if [ -z "$DEPLOY" ]; then
    bad "A0 could not isolate func rtDockerAppsDeploy in $BACKEND — subject lost"
  else
    if has "$DEPLOY" 'rtDockerAppsCountOwnedBy\(appsJSON, *claims\.Sub\)' && live "$DEPLOY"; then
      ok "A1 deploy's target-server count is filtered to the calling user (rtDockerAppsCountOwnedBy), not every container on the box"
    else
      bad "A1 deploy must filter its container count by claims.Sub — an unfiltered length lets any user's containers count against another user's cap"
    fi
    if has "$DEPLOY" 'OnlineFleet\(' && has "$DEPLOY" 'rtDockerAppsCountOwnedBy\(peer, *claims\.Sub\)' && live "$DEPLOY"; then
      ok "A2 deploy also folds in the caller's containers on every OTHER online server, not just the target"
    else
      bad "A2 deploy must walk the rest of the fleet too — a user confined to a per-server check can exceed their real cap by spreading across servers"
    fi
  fi

  echo
  echo "§B policy_usage answers for the requested user, not the whole fleet"
  USAGE=$(fnbody "$BE" "rtDockerAppsPolicyUsage")
  if [ -z "$USAGE" ]; then
    bad "B0 could not isolate func rtDockerAppsPolicyUsage in $BACKEND — subject lost"
  elif has "$USAGE" 'rtDockerAppsFleetUsageByUser' && has "$USAGE" 'byUser\[userID\]' && live "$USAGE"; then
    ok "B1 rtDockerAppsPolicyUsage derives its count from a per-user map keyed on the requested user_id"
  else
    bad "B1 rtDockerAppsPolicyUsage must scope its count to the requested user_id — summing the whole fleet answers every caller identically"
  fi

  echo
  echo "§C list_policies carries a real per-row usage figure"
  LIST=$(fnbody "$BE" "rtDockerAppsListPolicies")
  if [ -z "$LIST" ]; then
    bad "C0 could not isolate func rtDockerAppsListPolicies in $BACKEND — subject lost"
  elif has "$LIST" 'rtDockerAppsFleetUsageByUser' && has "$LIST" '"used"' && live "$LIST"; then
    ok "C1 rtDockerAppsListPolicies embeds a live 'used' count per row, from one shared fleet walk rather than N per-policy ones"
  else
    bad "C1 rtDockerAppsListPolicies must embed a per-user used count — the frontend has nothing to render a usage bar from otherwise"
  fi

  echo
  echo "§D the shared counter fails closed on a missing/malformed owner"
  # D1 retired: covered by TestPinContainerOwnershipOwnerFailsClosed (panel/go/internal/api/pin_container_ownership_test.go)
fi

echo
echo "§E the attribution primitive itself is still being written and read"
if ! AG=$(subj "$AGENT"); then
  skip "§E — $AGENT produced no code after stripping"
else
  DEPLOY_APP=$(fnbody "$AG" "DockerAppsDeployApp")
  if [ -n "$DEPLOY_APP" ] && has "$DEPLOY_APP" 'labels\["dockpanel\.user\.id"\] = \*userID' && live "$DEPLOY_APP"; then
    ok "E1 DockerAppsDeployApp still stamps dockpanel.user.id on every container it creates"
  else
    bad "E1 DockerAppsDeployApp must still stamp dockpanel.user.id — every counter above depends entirely on this label existing"
  fi

  LIST_APPS=$(fnbody "$AG" "DockerAppsListDeployedApps")
  if [ -n "$LIST_APPS" ] && has "$LIST_APPS" 'Labels\["dockpanel\.user\.id"\]' && has "$LIST_APPS" 'UserID' && live "$LIST_APPS"; then
    ok "E2 DockerAppsListDeployedApps still reads dockpanel.user.id back onto DeployedApp.UserID in every /apps response"
  else
    bad "E2 DockerAppsListDeployedApps must still surface user_id — the backend has no other way to learn who owns a container"
  fi
fi

echo
echo "§F the fix has a visible surface, not just a backend field nothing reads"
if ! FE=$(subj "$FRONTEND"); then
  skip "§F — $FRONTEND produced no code after stripping"
else
  if has "$FE" 'used: number' && has "$FE" 'p\.used'; then
    ok "F1 ContainerPolicies.tsx declares AND renders the used figure the backend now computes correctly"
  else
    bad "F1 ContainerPolicies.tsx must both declare and render the used field — a correct backend count nobody displays fixes nothing a reporter can see"
  fi
fi

echo
if [ "$SKIP" -gt 0 ]; then
  echo "container-ownership pin: $PASS passed, $FAIL failed, $SKIP skipped"
else
  echo "container-ownership pin: $PASS passed, $FAIL failed"
fi
[ "$FAIL" -eq 0 ] || exit 1
