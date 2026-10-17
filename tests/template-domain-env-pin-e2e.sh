#!/usr/bin/env bash
# Regression pins for the s363 fix to GitHub #111 — a template's URL-shaped env
# vars are filled in from the domain the operator claimed, and the Apps env
# editor can compose an arbitrary key.
#
# The DERIVATION itself is covered by unit tests in
# panel/go/internal/agent/services/docker_apps_test.go (ported from the
# mutation-proved Rust ones). This suite pins the things a unit
# test cannot reach: the frontend affordance, the entry gate, the validation
# parity on the door the new affordance makes reachable, and the both-ends
# payload contract between the React client and the agent DTO (the client cast
# is unvalidated, so a key rename is invisible to tsc).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
ok()   { printf '\033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '\033[31m✗\033[0m %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
eq()   { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3', got '$2'"; }

# ugrep's --ignore-files shim honours .gitignore, so every count below uses the
# real binary explicitly (dockpanel-ops-p2, s357).
G=/usr/bin/grep

APPS=panel/frontend/src/pages/Apps.tsx
AGENT=panel/go/internal/agent/services/docker_apps.go
AGENT_ROUTES=panel/go/internal/agent/routes/docker_apps.go
API=panel/go/internal/api/rt_docker_apps.go

for f in "$APPS" "$AGENT" "$AGENT_ROUTES" "$API"; do
  [ -f "$f" ] || { bad "SETUP" "$f missing"; exit 1; }
done

echo "── A. The catalogue mechanism ─────────────────────────────────────────"

# A1 is an ENUMERATION arm, so it asserts its own subject list first: a census
# that silently reads zero rows prints green (lesson #143).
# Each gofmt'd entry opens with `{"<id>", []dockerAppsDomainVar{` at one tab;
# the inner pairs are indented deeper, so they cannot inflate this.
ENTRIES=$($G -cE '^	\{"[a-z0-9-]+", \[\]dockerAppsDomainVar\{' <<<"$(sed -n '/^var dockerAppsTemplateDomainEnv /,/^}/p' "$AGENT")")
[ "${ENTRIES:-0}" -ge 6 ] && ok "A1 dockerAppsTemplateDomainEnv enumerates $ENTRIES templates" \
  || bad "A1" "expected >=6 keyed templates, extracted $ENTRIES — the window read nothing"

# A2 retired: covered by TestN8nGetsAllFourOfItsURLVarsFromTheClaimedDomain (panel/go/internal/agent/services/docker_apps_test.go)
# A3 retired: covered by TestN8nGetsAllFourOfItsURLVarsFromTheClaimedDomain (panel/go/internal/agent/services/docker_apps_test.go)
# A4 retired: covered by TestADerivedURLNeverCarriesTheContainerPort (panel/go/internal/agent/services/docker_apps_test.go)
# A4-control retired: covered by TestADerivedURLNeverCarriesTheContainerPort (panel/go/internal/agent/services/docker_apps_test.go) — the test evaluates every derived value, so it cannot be vacuous

echo "── B. The deploy path actually consults it ────────────────────────────"

DEPLOY_FN=$(sed -n '/^func DockerAppsDeployApp(/,/^}/p' "$AGENT")
# B1: severed-pair guard. A keyed list nothing reads is the
# GPU_RECOMMENDED_TEMPLATES / stable-diffusion-webui shape, which sat unnoticed
# for 19 releases.
eq "B1 DockerAppsDeployApp derives from the claimed domain" \
   "$($G -c 'dockerAppsDomainEnvFor(' <<<"$DEPLOY_FN")" "1"

# B2: the merge helper is reached by the deploy rather than orphaned by a later
# refactor (the #150 shape — extracting a helper moves the subject).
eq "B2 DockerAppsDeployApp builds its env through the merge helper" \
   "$($G -c 'dockerAppsMergeDeployEnv(' <<<"$DEPLOY_FN")" "1"

# B3: the flag the deploy form reads is emitted by the converter.
eq "B3 the serialized template carries the derived flag" \
   "$($G -cE 'DomainDerived: +dockerAppsIsDomainDerived\(' "$AGENT")" "1"

echo "── C. The editor can compose a key (the actual #111 gap) ──────────────"

# C1: an add-row control exists in the Apps env editor.
eq "C1 Apps env editor offers Add variable" \
   "$($G -c 'setEnvEditRows(\[\.\.\.envEditRows, { key: "", value: "" }\])' "$APPS")" "1"

# C2: the key is an INPUT, not the read-only div it used to be. Keyed on the
# operation's syntax rather than a token that also appears in prose (lesson #149).
eq "C2 the key is editable" \
   "$($G -c 'n\[i\] = { \.\.\.n\[i\], key: e\.target\.value };' "$APPS")" "1"

# C3: a row can be removed.
eq "C3 a variable can be removed" \
   "$($G -c 'setEnvEditRows(envEditRows\.filter((_, j) => j !== i))' "$APPS")" "1"

# C4 ABSENCE: the Edit button must not be gated on the container already having
# variables — that gate is half of why a key could never be added.
GATED=$($G -c '!envEditing && envVars\.length > 0' "$APPS")
eq "C4 Edit is not gated on existing variables" "$GATED" "0"
# POSITIVE CONTROL for C4: the emptiness test still exists for the READ view,
# so the pattern shape is live and the zero above is a real zero.
EMPTYVIEW=$($G -c 'envVars\.length === 0' "$APPS")
[ "$EMPTYVIEW" -ge 1 ] && ok "C4-control the empty-state branch is still present ($EMPTYVIEW)" \
  || bad "C4-control" "no emptiness test anywhere — C4's zero may be vacuous"

# C5: a blank key never reaches the wire.
eq "C5 blank rows are dropped before sending" \
   "$($G -c 'envEditRows\.filter(r => r\.key\.trim() !== "")' "$APPS")" "1"

# C6: duplicates are refused rather than silently collapsed onto the last value.
eq "C6 duplicate names are refused" "$($G -c 'Duplicate variable name' "$APPS")" "1"

echo "── D. Validation parity on the door this makes reachable ──────────────"

# D1..D3: the PUT /env door had none of these until the editor could compose an
# arbitrary key. Asserted on the handler's own body, not the file, so the
# deploy door's identical checks cannot satisfy them.
ENVFN=$(sed -n '/^func rtDockerAppsUpdateEnv(/,/^}/p' "$API")
eq "D1 PUT /env caps the variable count"  "$($G -c 'Too many environment variables' <<<"$ENVFN")" "1"
eq "D2 PUT /env caps the value size"      "$($G -c 'Environment variable value too large' <<<"$ENVFN")" "1"
eq "D3 PUT /env refuses a name with '='"  "$($G -c "may not contain" <<<"$ENVFN")" "1"

echo "── E. Both-ends payload contract ──────────────────────────────────────"

# The client casts the response and posts a bare object, so neither tsc nor
# encoding/json catches a key rename on either side. Pin the wire name at both ends.
eq "E1 client posts the env under its wire name" \
   "$($G -c 'api\.put(`/apps/\${envTarget}/env`, { env: payload })' "$APPS")" "1"
eq "E2 agent DTO reads the same wire name" \
   "$(sed -n '/^func dockerAppsUpdateEnv(/,/^}/p' "$AGENT_ROUTES" | $G -cE 'Env +map\[string\]string +`json:"env"`')" "1"

echo
echo "PASS $PASS · FAIL $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
