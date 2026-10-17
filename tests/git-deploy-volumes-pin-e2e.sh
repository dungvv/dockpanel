#!/usr/bin/env bash
#
# Regression pin for GIT DEPLOY PERSISTENT VOLUMES (#118).
#
# WHAT HAPPENED. A Git Deploy container got no volume and no bind mount, and
# every deploy replaced the container — so anything the app wrote to its own
# filesystem (uploads, a SQLite database, a cache) was destroyed on the NEXT
# deploy. The failure was silent and delayed: everything worked until the
# second deploy, by which point the loss looked unrelated. Reported as a real
# data-loss incident, not a feature request.
#
# WHY THE FIX WAS BIGGER THAN A FIELD. The header that carried this as unbuilt
# work (the agent's services/git_build — Go: panel/go/internal/agent/services/
# git_build.go) named six constraints, and
# each one is a distinct way a naive patch destroys data rather than saving
# it:
#
#   1. TWO `HostConfig` literals exist in this file (base + blue-green). Binds
#      added to only one mount on deploy and UN-mount on the next blue-green
#      update.
#   2. Blue-green runs the old and new container against the SAME host paths
#      for the length of a health check — silent corruption for a
#      single-writer database like SQLite. Any declared volume must force the
#      slower stop/recreate path instead.
#   3. Preview environments must NEVER inherit volumes — a throwaway PR
#      container gaining durable storage defeats the point of "throwaway".
#   4. Delete-time cleanup must derive what to remove from the container's
#      OWN binds (read before it is removed), never from its name alone — a
#      name match is not proof of ownership, the exact class of bug
#      `docker_apps::owned_app_dir` exists to prevent (Go: gitBuildOwnedDataDir).
#   5. The field is container-path only, host side derived — a free-form
#      host path would be a container-escape surface under this agent's
#      `ProtectSystem=strict` sandbox.
#   6. A deploy that ADDS a volume to an already-running container must
#      rescue whatever is already sitting in that container's writable
#      layer before the recreate deletes it — the exact shape of #110,
#      generalised from `docker_apps::migrate_unmounted_volumes`
#      (Go: DockerAppsMigrateUnmountedVolumes).
#
# Ship 1-5 without 6 and the FIRST deploy after the fix destroys the files
# the fix exists to save. Pure source analysis: no box, no network, no build,
# no Docker daemon.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

AG=panel/go/internal/agent
GIT_SVC=$AG/services/git_build.go
GIT_ROUTE=$AG/routes/git_build.go
APPS_SVC=$AG/services/docker_apps.go
BACKEND=panel/go/internal/api/rt_git_deploys.go
for f in "$GIT_SVC" "$GIT_ROUTE" "$APPS_SVC" "$BACKEND"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

# Strip whole-line comments only — a block-comment stripper is what deleted 485
# lines of real code until s294, and a trailing-// strip eats "https://" inside
# Go strings; this deliberately does the narrow, safe thing.
code() { grep -vE '^[[:space:]]*//' "$1"; }

SVC_CODE=$(code "$GIT_SVC")
SVC_FLAT=$(printf '%s' "$SVC_CODE" | tr -d ' \t\n')
ROUTE_CODE=$(code "$GIT_ROUTE")
ROUTE_FLAT=$(printf '%s' "$ROUTE_CODE" | tr -d ' \t\n')
APPS_CODE=$(code "$APPS_SVC")
APPS_FLAT=$(printf '%s' "$APPS_CODE" | tr -d ' \t\n')
BACKEND_CODE=$(code "$BACKEND")
BACKEND_FLAT=$(printf '%s' "$BACKEND_CODE" | tr -d ' \t\n')

echo "§0 the subjects parse (a truncated subject must not read as a clean sweep)"

for pair in "GIT_SVC:GitBuildDeployOrUpdate" "GIT_SVC:GitBuildCleanupContainer" "GIT_ROUTE:gitBuildDeploy" "BACKEND:rtGitDeploysBuildDeployBody"; do
  var="${pair%%:*}"; needle="${pair##*:}"
  case "$var" in
    GIT_SVC) hay="$SVC_FLAT" ;;
    GIT_ROUTE) hay="$ROUTE_FLAT" ;;
    BACKEND) hay="$BACKEND_FLAT" ;;
  esac
  case "$hay" in
    *"func${needle}("*) ok "$needle is still defined in $var" ;;
    *) bad "$needle is MISSING from $var — every arm below is meaningless" ;;
  esac
done

echo
echo "§1 fresh deploy: binds are built under gitBuildDataDir, create -> canonicalize -> verify -> seed -> chown"

case "$SVC_FLAT" in
  *'if!strings.HasPrefix(resolved,gitBuildDataDir+"/"){returnnil,fmt.Errorf("Volumepath%sescapesallowedprefixaftercanonicalization"'*)
    ok "the fresh-deploy path checks the canonicalised prefix against gitBuildDataDir" ;;
  *) bad "the fresh-deploy prefix check against gitBuildDataDir is missing or reordered" ;;
esac

CREATE_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'os.MkdirAll(hostDir, ' | head -1 | cut -d: -f1)
CANON_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'filepath.EvalSymlinks(hostDir)' | head -1 | cut -d: -f1)
ESCAPE_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'escapes allowed prefix' | head -1 | cut -d: -f1)
SEED_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'DockerAppsSeedVolumeFromImage(ctx, docker, image, vol' | head -1 | cut -d: -f1)
CHOWN_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'DockerAppsChownTo(resolved, owner)' | head -1 | cut -d: -f1)
if [ -n "$CREATE_AT" ] && [ -n "$CANON_AT" ] && [ -n "$ESCAPE_AT" ] && [ -n "$SEED_AT" ] && [ -n "$CHOWN_AT" ] \
   && [ "$CANON_AT" -gt "$CREATE_AT" ] && [ "$ESCAPE_AT" -gt "$CANON_AT" ] \
   && [ "$SEED_AT" -gt "$ESCAPE_AT" ] && [ "$CHOWN_AT" -gt "$ESCAPE_AT" ]; then
  ok "create -> canonicalize -> prefix-check -> seed/chown, in that order"
else
  bad "ordering broken (create=$CREATE_AT canon=$CANON_AT escape=$ESCAPE_AT seed=$SEED_AT chown=$CHOWN_AT)"
fi

case "$SVC_FLAT" in
  *'DockerAppsSeedVolumeFromImage(ctx,docker,image,vol,resolved)'*)
    ok "a fresh volume is seeded from the image's own shipped files" ;;
  *) bad "DockerAppsSeedVolumeFromImage is not called on the fresh-deploy path" ;;
esac

echo
echo "§2 blue-green is refused for ANY deploy with a declared volume"

case "$SVC_FLAT" in
  *'ifhasNginx&&len(volumes)==0{'*'returngitBuildBlueGreenUpdate('*)
    ok "blue-green requires hasNginx AND an empty volumes list" ;;
  *) bad "blue-green's gate no longer checks len(volumes) == 0 — the SQLite-corruption guard is gone" ;;
esac

# Positive control on the pin itself: the OLD gate (hasNginx alone) must not
# also satisfy the check above by coincidence.
if grep -qE 'ifhasNginx\{[^}]*gitBuildBlueGreenUpdate\(' <<< "$SVC_FLAT"; then
  bad "an UNGUARDED 'if hasNginx {' immediately preceding the blue-green call still exists"
else
  ok "no unguarded hasNginx branch precedes the blue-green call"
fi

echo
echo "§3 an existing container's binds are read before deciding, and a newly added path is migrated before removal"

case "$SVC_FLAT" in
  *'ifinfo,err:=docker.ContainerInspect(ctx,existing.id,client.ContainerInspectOptions{});err==nil&&info.Container.HostConfig!=nil{existingBinds=info.Container.HostConfig.Binds}'*)
    ok "the OLD container's binds are read via a fresh inspect" ;;
  *) bad "the existing container's binds are no longer inspected before recreate" ;;
esac

# A cleared/edited volumes list must filter the OLD binds down to what is still
# declared — dropping this filter would carry a REMOVED path's bind forward
# forever, or (the more dangerous direction) leak a stale bind whose directory
# no longer matches what the operator asked for.
case "$SVC_FLAT" in
  *'keptBinds:=gitBuildKeptBinds(existingBinds,volumes)'*'iflen(parts)>1&&nginxContains(declared,parts[1]){'*)
    ok "kept binds are filtered against the CURRENTLY declared volumes list" ;;
  *) bad "old binds are no longer filtered against the current volumes list" ;;
esac

MIGRATE_CALL_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'DockerAppsMigrateUnmountedVolumes(' | head -1 | cut -d: -f1)
REMOVE_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'docker.ContainerRemove(ctx, existing.id' | awk -F: '$1 > '"${MIGRATE_CALL_AT:-999999}"' {print $1; exit}')
STOP_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'docker.ContainerStop(ctx, existing.id' | head -1 | cut -d: -f1)
if [ -n "$STOP_AT" ] && [ -n "$MIGRATE_CALL_AT" ] && [ -n "$REMOVE_AT" ] \
   && [ "$MIGRATE_CALL_AT" -gt "$STOP_AT" ] && [ "$REMOVE_AT" -gt "$MIGRATE_CALL_AT" ]; then
  ok "migration runs AFTER stop and BEFORE remove (line $STOP_AT < $MIGRATE_CALL_AT < $REMOVE_AT)"
else
  bad "migration is not sandwiched between stop and remove (stop=$STOP_AT migrate=$MIGRATE_CALL_AT remove=$REMOVE_AT)"
fi

case "$SVC_FLAT" in
  *'DockerAppsMigrateUnmountedVolumes(ctx,gitBuildDataDir,docker,existing.id,name,imageTag,unmounted,migrateConfig)'*)
    ok "migration targets gitBuildDataDir, not DockerAppsAppDataDir" ;;
  *) bad "the git-deploy migration call no longer targets gitBuildDataDir" ;;
esac

case "$SVC_FLAT" in
  *'iferr!=nil{returnGitBuildDeployResult{},fmt.Errorf("Abortingdeployof%swithoutremovingtherunningcontainer:'*)
    ok "a migration failure ABORTS before ContainerRemove ever runs" ;;
  *) bad "a migration failure no longer aborts the recreate — #118's own regression risk" ;;
esac

echo
echo "§4 delete-time cleanup derives the volume directory from the container's OWN binds, never the name alone"

case "$SVC_FLAT" in
  *'funcgitBuildOwnedDataDir(namestring,binds[]string)*string{'*)
    ok "gitBuildOwnedDataDir exists as its own ownership-proof function" ;;
  *) bad "gitBuildOwnedDataDir is missing — cleanup would have to guess the path from the name" ;;
esac

INSPECT_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'docker.ContainerInspect(ctx, containerName, ' | head -1 | cut -d: -f1)
OWNED_CALL_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'gitBuildOwnedDataDir(name' | head -1 | cut -d: -f1)
CLEANUP_REMOVE_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'Removed git container' | head -1 | cut -d: -f1)
if [ -n "$INSPECT_AT" ] && [ -n "$OWNED_CALL_AT" ] && [ -n "$CLEANUP_REMOVE_AT" ] \
   && [ "$OWNED_CALL_AT" -gt "$INSPECT_AT" ] && [ "$OWNED_CALL_AT" -lt "$CLEANUP_REMOVE_AT" ]; then
  ok "ownership is captured in the PRE-removal inspect, before the container is gone"
else
  bad "ownership capture is not positioned before removal (inspect=$INSPECT_AT owned=$OWNED_CALL_AT remove=$CLEANUP_REMOVE_AT)"
fi

# The "container already missing" arm must NOT guess a directory from the name
# — that is precisely the cross-tenant-delete shape #4 exists to close. In Go
# that arm is the `} else {` of the inspect; it must set domain/port only.
NONE_ARM=$(printf '%s\n' "$SVC_CODE" | awk -v from="${OWNED_CALL_AT:-999999}" 'NR > from && /^\t\} else \{/ {p=1; next} p && /^\t\}/ {exit} p')
if [ -n "$NONE_ARM" ] && grep -qF 'domain, hostPort = knownDomain, knownPort' <<< "$NONE_ARM" && ! grep -qF 'dataDir' <<< "$NONE_ARM"; then
  ok "the container-missing arm leaves the volume dir nil, not a name-derived guess"
else
  bad "the container-missing arm no longer leaves the volume dir unset (or could not be read)"
fi

echo
echo "§5 previews are refused a volumes list at the AGENT boundary, not just by backend convention"

case "$ROUTE_FLAT" in
  *'ifscope!=services.OwnershipGitScopeDeploy&&len(b.Volumes)>0{'*)
    ok "the agent route itself refuses volumes for any scope but Deploy" ;;
  *) bad "the agent no longer enforces the preview/volumes exclusion — a backend bug would be the only thing left standing between a preview and durable storage" ;;
esac

# Go: the preview body literal names no Volumes (zero value), and the body
# builder only sends "volumes" when the list is non-empty.
PREVIEW_BODY=$(printf '%s\n' "$BACKEND_CODE" | awk '/deployBody := rtGitDeploysBuildDeployBody\(rtGitDeploysDeployBody\{/{p=1} p{print} p && /^\t*\}\)$/{exit}')
if grep -qF 'Scope:          "preview"' <<< "$PREVIEW_BODY" && ! grep -qF 'Volumes' <<< "$PREVIEW_BODY" \
   && grep -qF 'iflen(b.Volumes)>0{body["volumes"]=b.Volumes}' <<< "$BACKEND_FLAT"; then
  ok "the backend's own preview deploy call site sends no volumes list"
else
  bad "the backend's preview call site passes Volumes (or could not be read, or the body builder sends an empty list)"
fi

echo
echo "§6 the volume path validator rejects traversal before it ever reaches the filesystem"
# §6 agent arm retired: covered by TestGitBuildVolumePathRejectsTraversalAndFreeFormHosts (panel/go/internal/agent/routes/git_build_test.go)
# §6 backend arm retired: covered by TestPinGitDeployVolumesBackendPathValidatorRejectsTraversal (panel/go/internal/api/pin_git_deploy_volumes_test.go)

echo
echo "§7 migrate_unmounted_volumes was GENERALISED, not duplicated — one implementation, two callers"

case "$APPS_FLAT" in
  *'funcDockerAppsMigrateUnmountedVolumes(ctxcontext.Context,dataDirstring,docker*client.Client,containerID,name,imagestring,missing[]string,hc*container.HostConfig)'*)
    ok "DockerAppsMigrateUnmountedVolumes takes dataDir as a parameter (no longer hardcoded to the apps dir)" ;;
  *) bad "DockerAppsMigrateUnmountedVolumes's signature no longer takes a dataDir parameter — a duplicate may have been written instead" ;;
esac

N_DEFS=$(cat $AG/services/*.go | grep -vE '^[[:space:]]*//' | grep -ciE '^func [a-z]*MigrateUnmountedVolumes\(')
if [ "$N_DEFS" -eq 1 ]; then
  ok "exactly one definition of MigrateUnmountedVolumes exists across the agent's services"
else
  bad "found $N_DEFS definitions of MigrateUnmountedVolumes — the logic drifted into a duplicate"
fi

DOCKER_APPS_CALLS=$(printf '%s\n' "$APPS_CODE" | grep -c 'DockerAppsMigrateUnmountedVolumes(ctx, DockerAppsAppDataDir,')
if [ "$DOCKER_APPS_CALLS" -ge 3 ]; then
  ok "docker_apps.go's own 3 call sites (update app / change image / update env) still pass DockerAppsAppDataDir"
else
  bad "fewer than 3 docker_apps.go call sites pass DockerAppsAppDataDir to DockerAppsMigrateUnmountedVolumes (found $DOCKER_APPS_CALLS)"
fi

echo
echo "§8 unit tests exist where a mistake would otherwise be silent — and pass"

gotest() {
  local pkg="$1" re="$2" label="$3"
  local out; out=$(cd panel/go && go test "./$pkg/" -count=1 -run "^($re)\$" -v 2>&1)
  local want; want=$(tr '|' '\n' <<< "$re" | grep -c .)
  local got; got=$(grep -cE '^--- PASS' <<< "$out")
  if [ "$got" -eq "$want" ] && ! grep -qE '^(--- FAIL|FAIL)' <<< "$out"; then
    ok "$label ($got/$want passed)"
  else
    bad "$label: $got/$want passed — $(grep -E '^(--- FAIL|FAIL|.*undefined)' <<< "$out" | head -3 | tr '\n' ' ')"
  fi
}
gotest internal/agent/services 'TestGitBuildCleanupOnlyDeletesWhatThisDeploysOwnBindsProve' \
  "agent service unit test passes: TestGitBuildCleanupOnlyDeletesWhatThisDeploysOwnBindsProve"
gotest internal/agent/routes 'TestGitBuildVolumePathRejectsTraversalAndFreeFormHosts|TestGitBuildValidateVolumesRejectsDuplicatesAndOverLimit' \
  "agent route unit tests pass: TestGitBuildVolumePathRejectsTraversalAndFreeFormHosts, TestGitBuildValidateVolumesRejectsDuplicatesAndOverLimit"
gotest internal/api 'TestRtGitDeploysDeclaredVolumesAreSent|TestPinGitDeployVolumesBackendPathValidatorRejectsTraversal' \
  "backend unit tests pass: TestRtGitDeploysDeclaredVolumesAreSent, TestPinGitDeployVolumesBackendPathValidatorRejectsTraversal"

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32mPASS %d  FAIL 0\033[0m\n' "$PASS"
else
  printf '\033[0;31mPASS %d  FAIL %d\033[0m\n' "$PASS" "$FAIL"
fi
exit $((FAIL > 0))
