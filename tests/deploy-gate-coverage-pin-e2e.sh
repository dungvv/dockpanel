#!/usr/bin/env bash
# deploy-gate-coverage-pin-e2e.sh — s369
#
# THE GUARD HAS TO COVER THE CLASS, NOT THE DOOR IT WAS WRITTEN FOR.
#
# `image_scans::preflight_gate` is the CVE deploy gate. Until v2.122.0 exactly
# one handler called it — the template deploy — while `SECURITY.md`, the README
# and the Settings toggle all said "deploys" without qualification. Changing an
# app's image, deploying a Compose file, and creating or editing a stack each
# put an operator-chosen image on a host and asked the threshold nothing.
#
# The same was true of `container_policies.allowed_images`, whose own help text
# says "Restrict which Docker images a user can deploy" and which was read by
# that one handler only — and compared against the catalogue id rather than an
# image.
#
# So this suite does NOT list the doors that were fixed. That would be an
# instance arm wearing a class arm's comment (lesson #545 — v2.120.0's foreign
# key arm named `users` and could not see the two bare keys pointing at
# `servers`). It DERIVES the door set:
#
#   A = agent service files that call `docker.ContainerCreate(`
#   B = agent route handlers that call something in A
#   C = the agent route PATHS bound to the handlers in B
#   D = backend functions that post to a path in C
#
# and asserts that every member of D consults the gate, or is a NAMED exemption
# whose reason is written in the source. A new door joins D by existing.
#
# Go port (panel/go/internal/agent, panel/go/internal/api): the gate is
# rt_image_scans.go::rtImageScansPreflightGate / rtImageScansPreflightGateImage.
# The Go backend often posts to the agent from a helper or a spawned task
# rather than the handler (rtDockerAppsDeployTask, rtGitDeploysComposeDeploy,
# rtStacksRestorePrevious), so a door that does not itself reach the gate is
# gated iff EVERY function that calls it does — one hop up the call graph.
#
# ⚠ Never put the row loop on the right-hand side of a pipe: the loop runs in a
# subshell and `ok`/`bad` increment counters that die at the closing brace, so
# the suite prints marks and reports a stale PASS (lesson #548).

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=============================================="
echo "  deploy-gate coverage — source pins (s369)"
echo "=============================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

G=/usr/bin/grep

AGENT_SVC=panel/go/internal/agent/services
AGENT_ROUTES=panel/go/internal/agent/routes/docker_apps.go
BE_ROUTES=panel/go/internal/api
SCANS=$BE_ROUTES/rt_image_scans.go

for f in "$AGENT_ROUTES" "$SCANS" "$BE_ROUTES/rt_docker_apps.go" "$BE_ROUTES/rt_stacks.go" "$BE_ROUTES/core_router.go"; do
  [ -f "$f" ] || { echo "  FATAL: $f missing — wrong tree?"; exit 1; }
done

# ── §0 discovery, with floors ───────────────────────────────────────────────
# A discovery that silently returns nothing makes every arm below pass by
# looking at zero subjects (lesson #143).
echo "── §0 discovering the doors ──"

# A: agent service files that create a container.
CREATORS=$($G -rl "\.ContainerCreate(" "$AGENT_SVC" --include=*.go --exclude=*_test.go | sort -u)
CREATORS_N=$(printf '%s\n' "$CREATORS" | $G -c . || true)
if [ "$CREATORS_N" -ge 2 ]; then
  ok "found $CREATORS_N agent service file(s) that create containers (>= 2 known to exist)"
else
  bad "only $CREATORS_N agent service file(s) create containers — the scan broke; every arm below is vacuous"
fi

# C: the agent route paths whose handlers reach those services. Read off the
# agent's own route table so a renamed or added route is picked up.
# Anchored at the end: `/apps/update-check` and `/apps/{id}/update-limits` are
# routes that never create a container, and a loose `update` match would drag
# them in and then report them ungated for ever.
AGENT_PATHS=$($G -oE 'r\.Handle\("[A-Z]+ /apps[^"]*"' "$AGENT_ROUTES" \
              | $G -oE '/apps[^"]*' \
              | $G -E '(deploy|change-image|/update)$' | sort -u)
AGENT_PATHS_N=$(printf '%s\n' "$AGENT_PATHS" | $G -c . || true)
if [ "$AGENT_PATHS_N" -ge 3 ]; then
  ok "found $AGENT_PATHS_N container-creating agent route(s) (>= 3 known to exist)"
else
  bad "only $AGENT_PATHS_N container-creating agent route(s) — the route-table scan broke"
fi
printf '     %s\n' $AGENT_PATHS

# D: backend functions that post to one of those paths. Matched on the SHAPE,
# because the backend builds them with holes ("/apps/"+cid+"/update").
DOORS=()
PATHS_F=$(mktemp); DOORS_F=$(mktemp)
trap 'rm -f "$PATHS_F" "$DOORS_F"' EXIT
printf '%s\n' $AGENT_PATHS > "$PATHS_F"

# The finder runs from a quoted heredoc, never from `python3 -c '...'` inside
# the shell: a regex full of quotes and braces does not survive that trip, and
# the failure is silent — the pattern arrives mangled, matches nothing, and the
# arm below reports a clean tree (lesson #547).
python3 - "$PATHS_F" > "$DOORS_F" <<'PYEOF'
import re, sys, glob
paths = [l.strip() for l in open(sys.argv[1]) if l.strip()]
# A {hole} is either inside one literal (fmt.Sprintf "%s") or a `"+x+"` splice.
HOLE = '(?:[^"]*|"\\s*\\+[^+"]*\\+\\s*")'
def to_pattern(p):
    # Anchored on both quotes so ".../update" does not also match
    # ".../update-limits", which creates no container.
    parts = re.split(r"\{[^}]*\}", p)
    return re.compile('"' + HOLE.join(re.escape(x) for x in parts) + '"')

pats = [to_pattern(p) for p in paths]
for f in sorted(glob.glob("panel/go/internal/api/rt_*.go")):
    if f.endswith("_test.go"):
        continue
    src = re.sub(r"^\s*//.*$", "", open(f).read(), flags=re.M)  # prose is not a door (#149)
    fn = None
    for line in src.split("\n"):
        m = re.match(r"func (?:\([^)]*\) )?(\w+)\(", line)
        if m:
            fn = m.group(1)
            continue
        if fn and any(p.search(line) for p in pats):
            print(f + "|" + fn)
            fn = None
PYEOF
while IFS='|' read -r file fn; do
  [ -n "$file" ] && DOORS+=("$file|$fn")
done < <(sort -u "$DOORS_F")
DOORS_N=${#DOORS[@]}
if [ "$DOORS_N" -ge 4 ]; then
  ok "found $DOORS_N backend door(s) that put an image on a host (>= 4 known to exist)"
else
  bad "only $DOORS_N backend door(s) discovered — the caller scan broke; §1 is vacuous"
fi
for d in "${DOORS[@]}"; do printf '     %s\n' "${d/|/ :: }"; done

# The one door that must NOT gate, and why. An exemption is a product decision,
# so it has to be written down in the source it exempts — this arm checks that
# the reason is there, not merely that the name is on a list. (The gate's doc
# names it by its route-level name, update_app.)
EXEMPT_FN="rtDockerAppsUpdateApp"
EXEMPT_DOC_NAME="update_app"
EXEMPT_WHY="re-pulls the SAME reference"

# ── §1 every door consults the gate ─────────────────────────────────────────
echo
echo "── §1 every container-creating door consults the CVE deploy gate ──"
UNGATED=""
GATED_N=0

# A door may reach the gate through a wrapper — `git_deploys` does, because two
# background tasks needed the same checks. An arm that greps for the gate's own
# name would call those doors ungated the moment someone extracts a helper
# (lesson #150: extracting a helper moves the subject of every pin that
# measured it). So build the set of functions that REACH the gate, one hop.
GATE_REACHING="rtImageScansPreflightGate|rtImageScansPreflightGateImage"
while IFS= read -r wrapper; do
  [ -n "$wrapper" ] && GATE_REACHING="$GATE_REACHING|$wrapper"
done < <(
  cat $BE_ROUTES/rt_*.go | $G -vE '^[[:space:]]*//' | $G -hB 40 -E 'rtImageScansPreflightGate(Image)?\(' \
    | $G -oE '^func (\([^)]*\) )?[A-Za-z_]+' | $G -oE '[A-Za-z_]+$' | sort -u \
    | $G -vE '^(rtImageScansPreflightGate|rtImageScansPreflightGateImage)$'
)

ALL_SRC=$(cat $(ls $BE_ROUTES/*.go | $G -v '_test\.go$') | $G -vE '^[[:space:]]*//')
fnbody_of() {
  perl -0777 -ne 'print $1 if /\n(func (?:\([^)]*\) )?\Q'"$1"'\E\(.*?\n\})\n/s' <<< "$ALL_SRC"
}
callers_of() {
  # Top-level funcs whose body calls $1 (excluding its own definition).
  awk -v fn="$1" '
    /^func / { cur = $0; sub(/^func (\([^)]*\) )?/, "", cur); sub(/\(.*/, "", cur) }
    cur != fn && index($0, fn "(") && !/^func / { print cur }
  ' <<< "$ALL_SRC" | sort -u
}
reaches_gate() { $G -qE "($GATE_REACHING)\(" <<< "$(fnbody_of "$1")"; }

for d in "${DOORS[@]}"; do
  file=${d%%|*}; fn=${d##*|}
  body=$(fnbody_of "$fn")
  if [ -z "$body" ]; then
    bad "could not extract $fn from $file — the extractor broke, not the code"
    continue
  fi
  if reaches_gate "$fn"; then
    GATED_N=$((GATED_N+1))
  elif [ "$fn" = "$EXEMPT_FN" ]; then
    :
  else
    callers=$(callers_of "$fn")
    all=1
    [ -z "$callers" ] && all=0
    for c in $callers; do reaches_gate "$c" || all=0; done
    if [ "$all" -eq 1 ]; then
      GATED_N=$((GATED_N+1))
      printf '     %s gated via every caller: %s\n' "$fn" "$(echo $callers)"
    else
      UNGATED="$UNGATED ${file##*/}::$fn"
    fi
  fi
done
if [ -z "$UNGATED" ]; then
  ok "all $GATED_N non-exempt doors call rtImageScansPreflightGate/…GateImage (directly, via a wrapper, or in every caller)"
else
  bad "door(s) that run an operator-chosen image WITHOUT asking the gate —$UNGATED — the threshold an operator set does not apply there (#545)"
fi

# Exact, not >=: an arm that asks for "at least one" survives deleting one
# (lesson #546). Go: deploy task, change-image, compose deploy, the git
# deploys' shared compose helper, stacks create/update/restore-previous.
EXPECTED_GATED=7
if [ "$GATED_N" -eq "$EXPECTED_GATED" ]; then
  ok "exactly $EXPECTED_GATED doors call the gate, as expected"
else
  bad "expected $EXPECTED_GATED gated doors, found $GATED_N — a door was added or a call removed; update this number deliberately"
fi

# ── §2 the exemption is justified in the source it exempts ──────────────────
echo
echo "── §2 the one exemption states its reason where it applies ──"
GATE_DOC=$(perl -0777 -ne 'print $& if /\/\/ rtImageScansPreflightGateImage is the gate itself.*?\nfunc rtImageScansPreflightGateImage\(/s' "$SCANS")
if [ -z "$GATE_DOC" ]; then
  bad "could not read rtImageScansPreflightGateImage's doc block — §2 is vacuous"
elif $G -qF "$EXEMPT_WHY" <<< "$GATE_DOC" && $G -qF "$EXEMPT_DOC_NAME" <<< "$GATE_DOC" \
     && ! reaches_gate "$EXEMPT_FN" && [ -n "$(fnbody_of "$EXEMPT_FN")" ]; then
  ok "the doc names $EXEMPT_DOC_NAME and why it is exempt (it re-pulls the same reference), and $EXEMPT_FN indeed does not gate"
else
  bad "rtImageScansPreflightGateImage no longer explains why $EXEMPT_DOC_NAME ($EXEMPT_FN) is exempt — an undocumented exemption is indistinguishable from a missed door"
fi

# ── §3 allowed_images is compared against an IMAGE, not a catalogue id ──────
echo
echo "── §3 the allowed-images policy judges an image ──"
DEPLOY_BODY=$(fnbody_of rtDockerAppsDeploy)
if [ -z "$DEPLOY_BODY" ]; then
  bad "could not extract rtDockerAppsDeploy — §3 is vacuous"
else
  if $G -qE 'strings\.Contains\([^)]*TemplateID' <<< "$DEPLOY_BODY"; then
    bad "allowed_images is matched with a substring test over TemplateID again — the field says images and a substring test admits evil/nginx-backdoor"
  else
    ok "allowed_images is no longer a substring test over the catalogue id"
  fi
  if $G -qE 'rtDockerAppsImageAllowedBy\(' <<< "$DEPLOY_BODY"; then
    ok "rtDockerAppsDeploy judges the resolved image through rtDockerAppsImageAllowedBy"
  else
    bad "rtDockerAppsDeploy no longer calls rtDockerAppsImageAllowedBy — the policy stopped reading the image"
  fi
fi

POLICY_N=$($G -vhE '^[[:space:]]*//' $BE_ROUTES/rt_docker_apps.go $BE_ROUTES/rt_stacks.go | $G -c "rtDockerAppsEnforceAllowedImages(")
# 1 definition + 4 call sites.
if [ "$POLICY_N" -eq 5 ]; then
  ok "rtDockerAppsEnforceAllowedImages is defined once and called at all 4 image-taking doors"
else
  bad "expected 5 rtDockerAppsEnforceAllowedImages occurrences (1 def + 4 doors), found $POLICY_N"
fi

# ── §4 the published claim does not outrun the code ─────────────────────────
echo
echo "── §4 what SECURITY.md and the README promise is what the code does ──"
SEC_LINE=$($G -n "soft deploy gate" SECURITY.md | head -1)
if [ -z "$SEC_LINE" ]; then
  bad "SECURITY.md no longer describes the deploy gate — check what replaced it"
elif $G -qE "every door|change-image|changing an app" <<< "$SEC_LINE"; then
  ok "SECURITY.md names the doors the gate covers rather than saying 'deploys'"
else
  bad "SECURITY.md claims the gate refuses 'deploys' without naming which doors — it did that while covering one of six"
fi
if $G -qE "template deploys, image changes, compose deploys and stacks" README.md; then
  ok "README enumerates the covered doors"
else
  bad "README no longer enumerates the covered doors"
fi
if $G -qE "Updating an app is deliberately exempt" docs/guides/image-scanning.md; then
  ok "the guide discloses the update exemption"
else
  bad "the guide no longer discloses that Update is exempt — the one thing an operator would otherwise assume is covered"
fi

# ── §5 compose images are parsed, not grepped ───────────────────────────────
echo
echo "── §5 the gate's input comes from a parse ──"
CORE_SRC=$($G -vE '^[[:space:]]*//' "$BE_ROUTES/core_router.go")
CI=$(perl -0777 -ne 'print $1 if /\n(func composeImages\(.*?\n\})\n/s' <<< "$CORE_SRC")
CD=$(perl -0777 -ne 'print $1 if /\n(func composeDoc\(.*?\n\})\n/s' <<< "$CORE_SRC")
if [ -z "$CI" ]; then
  bad "composeImages is gone — the compose doors have nothing to gate on"
elif $G -qF 'composeDoc(src)' <<< "$CI" && $G -qF 'yaml.NewDecoder(' <<< "$CD"; then
  ok "composeImages deserialises the document via composeDoc/yaml.NewDecoder (a string scan is bypassable with anchors)"
else
  bad "composeImages no longer parses the YAML — anchors and aliases would hide an image from the gate"
fi

# ── §6 the buttons that PRODUCE the scans pass a name, not a container id ───
#
# `/api/apps/{name}/scan` and `/api/apps/{name}/sbom` resolve the image by
# matching the agent's `name` field. Every other `/api/apps/{container_id}/…`
# route takes the hex id, and `Apps.tsx` passed that hex id to these two — so
# "Rescan now", "Download SBOM" and the empty-state "Scan now" answered 404 for
# every app from 2026-04-15 until v2.122.0. The gate reads the rows these
# buttons write, so a gate with no way to produce a scan is a gate with nothing
# to read.
echo
echo "── §6 the app-keyed scan surface is keyed by NAME ──"
APPS_TSX=panel/frontend/src/pages/Apps.tsx
BAD_KEY=$($G -c "rescanApp(matchedApp.container_id\|downloadSbom(matchedApp.container_id" "$APPS_TSX" || true)
GOOD_KEY=$($G -c "rescanApp(matchedApp.name\|downloadSbom(matchedApp.name" "$APPS_TSX" || true)
if [ "$BAD_KEY" -eq 0 ] && [ "$GOOD_KEY" -eq 4 ]; then
  ok "all 4 scan/SBOM buttons pass the app NAME to a name-keyed route"
else
  bad "scan/SBOM buttons: $GOOD_KEY pass a name (expected 4), $BAD_KEY pass a container id (expected 0) — a hex id matches no app name and the route 404s"
fi
# Control: the hex id is still used where it belongs, so the grep above can fire
# in both directions rather than being green because the file changed shape.
if [ "$($G -c 'matchedApp.container_id' "$APPS_TSX" || true)" -ge 0 ] \
   && [ "$($G -c 'container_id' "$APPS_TSX" || true)" -ge 5 ]; then
  ok "control: container_id is still present in Apps.tsx, so the arm above is not green by absence"
else
  bad "control: container_id has vanished from Apps.tsx — §6 may be green because the file changed shape, not because it is correct"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
