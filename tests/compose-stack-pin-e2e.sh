#!/usr/bin/env bash
# compose-stack-pin-e2e.sh — s296 / v2.54.0
#
# DockPanel's "Compose" support does not run `docker compose`. It creates each
# service directly through the Docker API, which is what lets the panel apply
# its own sandboxing — and which means every convenience `docker compose` gives
# for free has to be reproduced deliberately. Until v2.54.0 almost none of it
# was, and the result was a feature that could not work: no user-defined
# network, so `postgresql://app:pw@database:5432` never resolved, so every
# multi-service package the panel ships died on boot while reporting success.
#
#   §A  A STACK IS A NETWORK. Every service is attached to one, and answers to
#       its compose service key on it. This is the arm that fails if the whole
#       defect is reintroduced.
#   §B  A STACK IS A NAMESPACE. Container, volume and network names are scoped
#       by stack, so the `db` service of two packages can coexist.
#   §C  THE PARSER DOES NOT SILENTLY DISCARD WHAT THE AUTHOR WROTE. `command:`,
#       `depends_on:`, `labels:` and long-form `ports:` were all parsed away by
#       a struct that did not declare them — which turned a queue worker into a
#       second copy of the web server. `dockpanel.*` labels are still ours.
#   §D  "RUNNING" MEANS RUNNING. `create` + `start` returning Ok is not a
#       status, and a 200 carrying N failures is not a successful deploy.
#   §E  A STACK'S DOMAIN GOES THROUGH THE ONE DOOR (v2.52.0) AND ITS TEARDOWN
#       THROUGH THE OWNERSHIP GUARD (v2.53.0). A new domain-claiming path that
#       neither registers with nor honours those is how a domain gets two owners.
#   §F  A FAILED EDIT DOES NOT REPLACE THE ONLY COPY. `docker_stacks` has no
#       history table; the stored YAML is it.
#   §G  A CRASHED CONTAINER IS VISIBLE. It is the only one anybody opens the
#       logs page for.
#   §H  THE UPDATE BANNER IS A COMPARISON, NOT A PRESENCE TEST (GitHub #98).
#
# Subjects are the Go tree (panel/go/internal/agent/{services/compose.go,
# routes/docker_apps.go, routes/logs.go} and panel/go/internal/api/
# {rt_stacks,svc_domain_claim,svc_telemetry_collector,rt_telemetry,rt_update,
# rt_git_deploys,core_router}.go). Arms whose property is pure parser
# behaviour are retired to the Go unit tests that assert it.
#
# Pure source analysis: no box, no network, no build.
#
# Arms are written against the CAPABILITY a regression must use, not today's
# spelling (lesson #122), and were attacked after they went green (lesson #132).
#
# NO PIPES INTO `grep -q`. Under `set -o pipefail` grep -q closes the pipe on its
# first match, the upstream dies of SIGPIPE (141), and pipefail reports the whole
# pipeline failed — so an arm goes red on correct code, non-deterministically.
# Every arm here feeds grep a here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33m-\033[0m SKIP %s\n' "$1"; }

COMPOSE=panel/go/internal/agent/services/compose.go
APPS_ROUTE=panel/go/internal/agent/routes/docker_apps.go
LOGS_ROUTE=panel/go/internal/agent/routes/logs.go
STACKS_BE=panel/go/internal/api/rt_stacks.go
CLAIM=panel/go/internal/api/svc_domain_claim.go
TELE_COLL=panel/go/internal/api/svc_telemetry_collector.go
TELE_ROUTE=panel/go/internal/api/rt_telemetry.go
UPDATE_ROUTE=panel/go/internal/api/rt_update.go
APPS_TSX=panel/frontend/src/pages/Apps.tsx
GITDEP=panel/go/internal/api/rt_git_deploys.go
BE_ROUTER=panel/go/internal/api/core_router.go

for f in "$COMPOSE" "$APPS_ROUTE" "$LOGS_ROUTE" "$STACKS_BE" "$CLAIM" \
         "$TELE_COLL" "$TELE_ROUTE" "$UPDATE_ROUTE" "$APPS_TSX"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT.
#
# The obvious `s{/\*.*?\*/}{}gs` shipped in four suites before s294 and was
# DELETING CODE: `/*` occurs inside string literals, so it opened a "block
# comment" that ran to the next `*/`. A truncated subject makes an ABSENCE arm
# pass on code the stripper merely removed, which is the worst way for a pin to
# be wrong. So a block comment is recognised only where one is actually written.
# Go line comments: whole-line `//`, and trailing `//` only after whitespace (a
# `https://` literal survives).
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^[ \t]*//.*$}{}gm;
    s{[ \t]+//[^"`\n]*$}{}gm;
  ' "$1"
}

# The stripper is code, and code can be wrong. Measure it before trusting
# anything downstream: every `func` declaration must survive the strip.
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

# An arm whose subject could not be extracted must SKIP, not print a confident
# green next to a red about the same subject.
subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }

has()   { grep -qE -- "$2" <<< "$1"; }
count() { grep -cE -- "$2" <<< "$1" || true; }

# Only DEAD-CODE markers belong here (lesson #133).
live() {
  ! grep -qE -- '(if false|&& false|\|\| true|_ = unused)' <<< "$1"
}

# The body of one top-level Go func (or method), bounded by its own closing `}`
# at column 0. A fixed `-A <n>` window is NOT a function (lesson #131).
fnbody() {
  awk -v name="$2" '
    !inside && (index($0, "func " name "(") == 1 || $0 ~ ("^func \\([^)]*\\) " name "\\(")) { inside=1; next }
    inside { if ($0 == "}") exit; print }
  ' <<< "$1"
}

# Assert a window both matches and is live, in one place so no arm forgets.
derives() {
  local w="$1" pat="$2"
  [ -n "$w" ] && grep -qE -- "$pat" <<< "$w" && live "$w"
}

# First 1-indexed line of $2 within $1, or 0. Used where the DEFECT IS THE
# ORDER — a pin that only checks both statements exist passes on the bug.
lineof() {
  local n
  n=$(grep -nE -- "$2" <<< "$1" | head -1 | cut -d: -f1)
  printf '%s' "${n:-0}"
}

C=$(subj "$COMPOSE")      || C=""
AR=$(subj "$APPS_ROUTE")  || AR=""
LR=$(subj "$LOGS_ROUTE")  || LR=""
SB=$(subj "$STACKS_BE")   || SB=""
CL=$(subj "$CLAIM")       || CL=""
TC=$(subj "$TELE_COLL")   || TC=""
TR=$(subj "$TELE_ROUTE")  || TR=""
UR=$(subj "$UPDATE_ROUTE")|| UR=""

echo
echo "compose-stack-pin-e2e — a stack is a network, a namespace, and an honest status"
echo

# ── stripper self-check ────────────────────────────────────────────────
echo "§0 the harness measures its own preprocessing"
stripper_self_check "$COMPOSE" "$APPS_ROUTE" "$LOGS_ROUTE" "$STACKS_BE" "$CLAIM" \
                    "$TELE_COLL" "$TELE_ROUTE" "$UPDATE_ROUTE"

# ── §A a stack is a network ────────────────────────────────────────────
echo
echo "§A a stack is a network, and a service answers to its compose key on it"
if [ -z "$C" ]; then
  skip "§A — $COMPOSE could not be read"
else
  DS=$(fnbody "$C" "composeDeployService")
  if derives "$DS" 'NetworkingConfig:[[:space:]]*netConfig'; then
    ok "A1 the container is created WITH a network attachment"
  else
    bad "A1 no NetworkingConfig — every service lands on the default bridge, where sibling names do not resolve"
  fi
  if derives "$DS" 'Aliases:[[:space:]]*svc\.Aliases'; then
    ok "A2 the attachment registers aliases (the names siblings were configured with)"
  else
    bad "A2 attached with no alias — the network exists but 'database' still does not resolve"
  fi
  DC=$(fnbody "$C" "ComposeDeployCompose")
  ENS=$(lineof "$DC" 'ComposeEnsureStackNetwork\(')
  DEP=$(lineof "$DC" 'composeDeployService\(')
  if derives "$DC" 'ComposeEnsureStackNetwork\(' && [ "$ENS" -gt 0 ] && [ "$DEP" -gt "$ENS" ]; then
    ok "A3 the network is created before any service is deployed"
  else
    bad "A3 nothing creates the network before the services — the attachment above fails on every service"
  fi
  # A4 retired: covered by TestServiceKeyIsKeptAndBecomesANetworkAlias (panel/go/internal/agent/services/compose_test.go)
  if derives "$C" '^func ComposeRemoveStackNetwork\('; then
    ok "A5 the network is torn down with the stack"
  else
    bad "A5 nothing removes the network — one leaks per stack, forever"
  fi
  RSN=$(fnbody "$C" "ComposeRemoveStackNetwork")
  if derives "$RSN" 'Labels\["dockpanel\.managed"\] != "true"'; then
    ok "A6 the teardown refuses a network it cannot prove is ours"
  else
    bad "A6 the teardown removes a network by NAME alone"
  fi
fi

# ── §B a stack is a namespace ──────────────────────────────────────────
echo
echo "§B container, volume and network names are scoped by stack"
if [ -z "$C" ]; then
  skip "§B — $COMPOSE could not be read"
else
  # B1 retired: covered by TestContainerNamesAreScopedByStack (panel/go/internal/agent/services/compose_test.go)
  # B2 retired: covered by TestNetworksAreScopedByStack (panel/go/internal/agent/services/compose_test.go)
  DS=$(fnbody "$C" "composeDeployService")
  if derives "$DS" 'composeScopedVolume\('; then
    ok "B3 named volumes are resolved through the stack scope"
  else
    bad "B3 bare named volumes — a second stack from the same package mounts the first one's database"
  fi
  # The safety half of B3: scoping a volume must never orphan data that is
  # already in one. Renaming a volume does not move what is inside it.
  SV=$(fnbody "$C" "composeScopedVolume")
  if derives "$SV" 'VolumeInspect\(ctx, vol,'; then
    ok "B4 an existing volume is reused rather than renamed out from under its data"
  else
    bad "B4 the scoping renames unconditionally — an upgraded install loses sight of its data"
  fi
  # B5 retired: covered by TestAnAuthorChosenContainerNameBecomesAnAliasNotTheDockerName (panel/go/internal/agent/services/compose_test.go)
fi

# ── §C the parser keeps what the author wrote ──────────────────────────
echo
echo "§C nothing the author wrote is discarded in silence"
if [ -z "$C" ]; then
  skip "§C — $COMPOSE could not be read"
else
  # C-command retired: covered by TestCommandSurvivesParsing (panel/go/internal/agent/services/compose_test.go)
  # C-depends_on retired: covered by TestDependsOnLongFormIsUnderstood (panel/go/internal/agent/services/compose_test.go)
  # C-labels retired: covered by TestAuthorLabelsSurviveButThePanelNamespaceDoesNot (panel/go/internal/agent/services/compose_test.go)
  DS=$(fnbody "$C" "composeDeployService")
  if derives "$DS" 'Cmd:[[:space:]]*svc\.Command'; then
    ok "C4 a parsed command actually reaches the container"
  else
    bad "C4 command is parsed and then not applied — the worker runs the image's default CMD"
  fi
  # C5 retired: covered by TestLongFormPortsArePublished (panel/go/internal/agent/services/compose_test.go)
  # C6 retired: covered by TestAuthorLabelsSurviveButThePanelNamespaceDoesNot (panel/go/internal/agent/services/compose_test.go)
  # C7 retired: covered by TestPinComposeStackServiceOrderIsDeterministic (panel/go/internal/agent/services/pin_compose_stack_test.go)
  # C8 retired: covered by TestDependenciesOrderTheDeploy (panel/go/internal/agent/services/compose_test.go)
fi

# ── §D "running" means running ─────────────────────────────────────────
echo
echo "§D a service is 'running' because it is, not because start() returned Ok"
if [ -z "$C" ]; then
  skip "§D — $COMPOSE could not be read"
else
  DS=$(fnbody "$C" "composeDeployService")
  if derives "$DS" 'if f := composeConfirmRunning\(.*\); f != nil \{'; then
    ok "D1 the deploy confirms the container stayed up"
  else
    bad "D1 'running' is asserted from create+start alone — a crash-on-boot reports success"
  fi
  CR=$(fnbody "$C" "composeConfirmRunning")
  if derives "$CR" 'ContainerInspect\('; then
    ok "D2 the confirmation reads the container's real state"
  else
    bad "D2 the confirmation does not inspect anything"
  fi
  if derives "$CR" 'composeTailLogs\('; then
    ok "D3 a failure carries the container's own output, so it can be diagnosed"
  else
    bad "D3 the failure says only that it failed"
  fi
fi
if [ -z "$SB" ]; then
  skip "§D backend — $STACKS_BE could not be read"
else
  # The agent reports per-service failure INSIDE a 200, so an HTTP-status check
  # is not a deploy check.
  if derives "$SB" '^func rtStacksDeployedServiceStates\('; then
    ok "D4 the backend has a way to ask whether anything actually came up"
  else
    bad "D4 the backend reads only the HTTP status, which is 200 for a total failure"
  fi
  CRE=$(fnbody "$SB" "rtStacksCreate")
  if derives "$CRE" 'rtStacksDeployedServiceStates\('; then
    ok "D5 create refuses to keep a stack where nothing came up"
  else
    bad "D5 a stack whose every service failed is still saved as a stack"
  fi
fi

# ── §E one door owns a domain; one guard takes it down ─────────────────
echo
echo "§E a stack's domain is claimed through the one door and released through the guard"
if [ -z "$SB" ] || [ -z "$CL" ]; then
  skip "§E — subject unreadable"
else
  CRE=$(fnbody "$SB" "rtStacksCreate")
  UPD=$(fnbody "$SB" "rtStacksUpdate")
  if derives "$CRE" 'DomainClaimEnsureClaimable|rtStacksClaimStackDomain'; then
    ok "E1 create claims the domain before writing anything"
  else
    bad "E1 a stack can take a domain a site or app already holds"
  fi
  if derives "$UPD" 'DomainClaimEnsureClaimable|rtStacksClaimStackDomain'; then
    ok "E2 update claims too — an edit is a second chance to collide"
  else
    bad "E2 the edit path claims nothing"
  fi
  # A holder the claim system cannot SEE is a holder that does not exist: the
  # next site to want this domain would be told it is free.
  FO=$(fnbody "$CL" "DomainClaimFindOccupant")
  if derives "$FO" 'FROM docker_stacks'; then
    ok "E3 the claim check can see a stack as a holder"
  else
    bad "E3 stacks write vhosts but are invisible to the claim check — two owners, one domain"
  fi
  if derives "$CL" '^func DomainClaimHolderStack\(id uuid\.UUID\)' && derives "$UPD" 'DomainClaimHolderStack\(id\)'; then
    ok "E4 a stack may re-claim its own domain across an edit"
  else
    bad "E4 no self-exclusion — a stack collides with itself on the second edit"
  fi
fi
if [ -z "$AR" ]; then
  skip "§E agent — $APPS_ROUTE could not be read"
else
  SA=$(fnbody "$AR" "dockerAppsStackAction")
  if derives "$SA" 'dockerAppsUnexposeDomain\('; then
    ok "E5 removing a stack takes its vhost and certificates down with it"
  else
    bad "E5 the vhost outlives the stack, pointing at a port nothing answers on"
  fi
  UD=$(fnbody "$AR" "dockerAppsUnexposeDomain")
  if derives "$UD" 'services\.OwnershipAppVhost\('; then
    ok "E6 the vhost delete proves the vhost is still this stack's"
  else
    bad "E6 the vhost is deleted on the name alone — a site that took the domain over loses its config"
  fi
  if derives "$UD" 'OwnershipCertDirInUseElsewhere\('; then
    ok "E7 the certificate delete honours a shared wildcard lineage"
  else
    bad "E7 removing one stack can break every other vhost sharing that certificate"
  fi
  # Writing a vhost to an upstream that is already dead hands the operator a
  # 502 and a certificate for it.
  CD=$(fnbody "$AR" "dockerAppsComposeDeploy")
  RUNCHK=$(lineof "$CD" 'Status == "running"')
  EXPOSE=$(lineof "$CD" 'dockerAppsExposeDomain\(')
  if derives "$CD" 'Status == "running"' && [ "$RUNCHK" -gt 0 ] && [ "$EXPOSE" -gt "$RUNCHK" ]; then
    ok "E8 a domain is only fronted onto a stack that came up"
  else
    bad "E8 a vhost is written even when every service failed"
  fi
fi

# ── §F a failed edit does not replace the only copy ────────────────────
echo
echo "§F the stored YAML is the only copy, so it outlives a failed redeploy"
if [ -z "$SB" ]; then
  skip "§F — $STACKS_BE could not be read"
else
  UPD=$(fnbody "$SB" "rtStacksUpdate")
  if derives "$UPD" 'rtStacksRestorePrevious\('; then
    ok "F1 a failed redeploy puts the previous definition back"
  else
    bad "F1 a failed redeploy leaves the stack down with no way back"
  fi
  # THE DEFECT IS THE ORDER. Both statements existed before; the write simply
  # ran first and unconditionally.
  GUARD=$(lineof "$UPD" 'running == 0')
  WRITE=$(lineof "$UPD" 'UPDATE docker_stacks SET yaml')
  if [ "$GUARD" -gt 0 ] && [ "$WRITE" -gt 0 ] && [ "$GUARD" -lt "$WRITE" ] && live "$UPD"; then
    ok "F2 the YAML is persisted only AFTER the new definition is known to run"
  else
    bad "F2 the YAML write is not gated behind the did-it-run check (guard@$GUARD write@$WRITE)"
  fi
  # The escape-vector validator guarded the endpoint nothing calls.
  CRE=$(fnbody "$SB" "rtStacksCreate")
  if derives "$CRE" 'validateComposeYAML\('; then
    ok "F3 create runs the container-escape validator"
  else
    bad "F3 the endpoint the UI posts to skips the validator entirely"
  fi
fi

# ── §G a crashed container is visible ──────────────────────────────────
echo
echo "§G the container you need the logs of is the one that stopped"
if [ -z "$LR" ]; then
  skip "§G — $LOGS_ROUTE could not be read"
else
  DCN=$(fnbody "$LR" "logsDockerContainers")
  if derives "$DCN" '"ps", "-a"'; then
    ok "G1 the log picker lists stopped containers too"
  else
    bad "G1 'docker ps' without -a — a crashed service is missing from the one page that explains it"
  fi
fi
if [ -f "$APPS_TSX" ]; then
  # The stack table had no logs affordance at all, which is why reports about
  # stacks arrive with no detail in them.
  if grep -qE 'handleLogs\(svc\.container_id\)' "$APPS_TSX"; then
    ok "G2 a stack service has a Logs control"
  else
    bad "G2 a stack service cannot be inspected from the panel"
  fi
else
  skip "§G2 — $APPS_TSX could not be read"
fi

# ── §H the update banner is a comparison (GitHub #98) ──────────────────
echo
echo "§H 'an update is available' is a comparison, not a non-empty string"
if [ -z "$TR" ] || [ -z "$TC" ] || [ -z "$UR" ]; then
  skip "§H — subject unreadable"
else
  # Both read paths derive `update_available` from one helper, which compares.
  SM=$(fnbody "$TR" "rtTelemetrySettingsMap")
  SM_CMP=0; derives "$SM" 'avail = TelemetryCollectorIsNewerRelease\(kv\.B, Version\)' && SM_CMP=1
  US=$(fnbody "$TR" "rtTelemetryUpdateStatus")
  if [ "$SM_CMP" = 1 ] && derives "$US" 'rtTelemetrySettingsMap\(' && derives "$US" '"update_available"\] = has'; then
    ok "H1 the read path compares the advertised version against this binary"
  else
    bad "H1 the banner renders from presence — any stored value, however old, shows an update"
  fi
  GC=$(fnbody "$TR" "rtTelemetryGetConfig")
  if [ -z "$GC" ]; then
    skip "H2 — rtTelemetryGetConfig not found"
  elif [ "$SM_CMP" = 1 ] && derives "$GC" 'rtTelemetrySettingsMap\(' && derives "$GC" '"update_available"\] = avail'; then
    ok "H2 the config payload carries the same derived answer"
  else
    bad "H2 the Telemetry page's own consumers still test presence"
  fi
  # update.sh never touches the settings table, so after an upgrade the row
  # still advertises the version now running. Nothing else closes that window.
  RUN=$(fnbody "$TC" "TelemetryCollectorRun")
  RECON=$(lineof "$RUN" 'telemetryCollectorReconcileStoredUpdate\(')
  SLEEP=$(lineof "$RUN" 'time\.After\(|time\.Sleep\(|NewTicker\(')
  if [ "$RECON" -gt 0 ] && [ "$SLEEP" -gt 0 ] && [ "$RECON" -lt "$SLEEP" ]; then
    ok "H3 the stored advertisement is reconciled on boot, before anything sleeps"
  else
    bad "H3 no boot reconcile — every upgrade advertises itself for the whole poll interval (recon@$RECON sleep@$SLEEP)"
  fi
  # H4 retired: covered by TestRtUpdateApplyRefusesATargetNoNewerThanTheRunningPanel (panel/go/internal/api/rt_update_test.go)
  # ABSENCE ARM. The old comparator dropped a non-numeric segment and shifted
  # the rest, so 2.53.0-rc.1 parsed as [2,53,1] and outranked its own GA. An
  # absence arm is worthless unless its subject was really read (lesson #143):
  # the comparator that replaced it must be visible in the same file first.
  if ! derives "$TC" '^func TelemetryCollectorIsNewerRelease\('; then
    bad "H5 TelemetryCollectorIsNewerRelease is not where this arm looks — the absence below would be vacuous"
  elif ! has "$TC" 'func [A-Za-z]*[cC]ompareVersions\(' && ! has "$TR" 'func [A-Za-z]*[cC]ompareVersions\('; then
    ok "H5 the segment-dropping comparator is gone, not merely bypassed"
  else
    bad "H5 a compareVersions is still present — a second, wrong answer to the same question"
  fi
fi

# ── I. a compose git-deploy may not report a deploy that did not happen (s395) ──
#
# Two defects, one shape: the panel wrote `status = 'running'` for work the agent
# had not done.
#
#  * The compose engine SKIPS any service it cannot resolve to a registry image,
#    so a repository with a Dockerfile — the one whose compose file builds from
#    source — deployed without its application while the row said running.
#  * `deploy_compose` reports per-service outcomes INSIDE a 200 and never errors
#    for a service that failed to start, so both callers took the HTTP status as
#    the answer. With no teardown in the engine, the SECOND compose deploy of the
#    same deployment collides with its own container names and every service
#    fails — still reported as running.
I_GD=$(subj "$GITDEP")  || { bad "I0 could not extract $GITDEP"; I_GD=""; }
I_RT=$(subj "$BE_ROUTER") || { bad "I0 could not extract $BE_ROUTER"; I_RT=""; }
if [ -n "$I_GD" ] && [ -n "$I_RT" ]; then
  ok "I0 subjects extracted (rt_git_deploys ${#I_GD}, core_router ${#I_RT} chars)"

  # I1 retired: covered by TestServicesWithoutAnImageAreNamed (panel/go/internal/api/core_router_test.go) — blank, `~` and `null` image lines all count as no image

  # The name occurs exactly twice, its declaration and its one call, so
  # deleting the call reads 1 and goes red.
  D=$(count "$I_GD" 'rtGitDeploysDroppedServiceRefusal\(')
  if [ "$D" = "2" ]; then
    ok "I2 the compose door refuses a file whose services name no image (declared once, called once)"
  else
    bad "I2 expected the no-image refusal declared once and called once, found $D occurrences — a compose file that builds from source would deploy without those services again"
  fi

  # BOTH compose deploy call sites, counted. There are two, they diverged once
  # already, and fixing one is half a fix that reads exactly like a whole one.
  # In Go both go through rtGitDeploysComposeDeploy, which reads the outcome.
  N=$(count "$I_GD" 'rtGitDeploysComposeDeploy\(ctx, agent,')
  CDB=$(fnbody "$I_GD" "rtGitDeploysComposeDeploy")
  RAW=$(count "$I_GD" '"/apps/compose/deploy"')
  if [ "$N" = "2" ] && derives "$CDB" 'return rtGitDeploysComposeOutcome\(res\)' && [ "$RAW" = "1" ]; then
    ok "I3 both compose deploy call sites read the per-service outcome (2, through one dispatch)"
  else
    bad "I3 expected 2 compose call sites through rtGitDeploysComposeDeploy reading the outcome and 1 raw dispatch, found $N / $RAW — a 200 whose services all failed would be written as status='running'"
  fi

  # The reader is SHARED with the stacks door rather than copied, so the two
  # paths cannot drift apart again.
  M=$(count "$I_GD" 'rtStacksDeployedServiceStates\(')
  if [ "$M" = "1" ]; then
    ok "I4 the per-service reader is the stacks one, not a second copy"
  else
    bad "I4 expected exactly 1 use of the shared per-service reader, found $M"
  fi

  # An empty report is NOT a failure: an agent reporting no services cannot be
  # told from one too old to report them. Getting this backwards would fail every
  # deploy against an older agent.
  if has "$I_GD" 'total > 0 && running == 0'; then
    ok "I5 only a report of services that ALL failed counts as a failure"
  else
    bad "I5 the empty-report guard is gone — a deploy against an agent that reports no services would be recorded as failed"
  fi
fi

echo
echo "== §J  compose_validate is honest about what deploy_service silently drops =="

# s449: `user:`/`healthcheck:`/`entrypoint:` have no field on this deployer —
# the deploy has never read any of the three — but `compose_validate`
# said a stack declaring one was simply "valid", with no warning that the
# directive would be dropped on the floor at deploy time.
# [[project_dockpanel_tech_debt_p185]] carry I.
if [ -n "$AR" ]; then
  CV=$(fnbody "$AR" "dockerAppsComposeValidate")
  if [ -z "$CV" ]; then
    bad "J0 could not extract dockerAppsComposeValidate"
  else
    ok "J0 dockerAppsComposeValidate extracted"
    for flag in UserIgnored HealthcheckIgnored EntrypointIgnored; do
      if has "$CV" "svc\\.$flag"; then
        ok "J1 dockerAppsComposeValidate reads svc.$flag"
      else
        bad "J1 dockerAppsComposeValidate does not read svc.$flag — the author gets no warning that this directive is dropped"
      fi
    done
  fi
else
  bad "J $APPS_ROUTE is readable"
fi

# J2 retired: covered by TestUserHealthcheckAndEntrypointAreFlaggedAsIgnoredWhenDeclared and
# TestUserHealthcheckAndEntrypointAreNotFlaggedWhenAbsent (panel/go/internal/agent/services/compose_test.go)

# ── summary ────────────────────────────────────────────────────────────
echo
if [ "$SKIP" -gt 0 ]; then
  echo "compose-stack pin: $PASS passed, $FAIL failed, $SKIP skipped"
else
  echo "compose-stack pin: $PASS passed, $FAIL failed"
fi
[ "$FAIL" -eq 0 ] || exit 1
