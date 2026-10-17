#!/usr/bin/env bash
# expected-stop-pin-e2e.sh — s391 / v2.144.0
#
# Pins the fix for an EXPECTED container stop publishing a CRITICAL incident on
# the operator's PUBLIC status page.
#
#   §A  the severity the engine FIRES and the severity the product DECLARES are
#       the same string. This is the arm that would have caught the original
#       defect: the runbook defaults (svc_alert_runbook_defaults.go) have always listed container_down
#       under "Info" and the runbook attached to every one of those
#       notifications says "we don't page on it", while the engine raised it at
#       "critical" — which is the exact string the incident branch gates on. The
#       arm derives BOTH sides and compares them, so it fails whichever one drifts.
#   §B  the suppression sits at the CHECK, never in the fire funnel. The
#       `alert_state` row is stamped 'firing' immediately above the fire and the
#       branch is guarded by `!alertEngineFiringState(...)`, so a funnel-level skip would
#       stamp a row claiming a page that never went out and then suppress every
#       future container_down for that name — the tombstone this engine's own
#       comment records as having run for four months.
#   §C  the expectation is cleared from OBSERVATION, ABOVE the state ladder and
#       on `not exited/dead` — never inside the recovery arm, which is
#       `running && health != unhealthy` and sits UNDER the unhealthy arm. A
#       container that comes back up with a failing healthcheck (the ordinary
#       case for something stopped because it was misbehaving) never reaches
#       that arm, would keep its expectation for ever, and would be silenced
#       when it finally died.
#   §D  the clear cannot touch the auto-sleep clock. rtDockerAppsWakeContainer writes
#       is_sleeping/last_woken_at/last_activity_at together, and that statement
#       is the obvious one to copy — but the engine runs every 120s against every
#       running container, so copying it would bump `last_activity_at` for ever
#       and silently disable auto-sleep, whose idle test is that column alone.
#   §E  every deliberate stop path records, and every start path clears —
#       including the STACK path, where one click stops N containers.
#   §F  the caller's container id is CANONICALISED before it is used as a key.
#       isValidContainerID accepts any 1-64 hex string and Docker resolves a
#       prefix, so the short id `docker ps` prints stops the container fine and
#       would otherwise write a row the engine can never match.
#   §G  the suppression predicate is membership and nothing broader (narrowing).
#   §H  the migration carries the server term in its UNIQUE and does NOT backfill.
#   §I  the SPA stops calling the panel's own deliberate action a crash.
#
# Pure source analysis: no box, no network, no build. Subjects are the Go API
# (panel/go/internal/api) — the shipped backend since the Go port.
#
# NO PIPES INTO `grep -q` — under `set -o pipefail` grep -q closes the pipe on
# its first match and the arm goes red on correct code. Every arm uses a
# here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

GOAPI=panel/go/internal/api
ENGINE=$GOAPI/svc_alert_engine.go
HEALER=$GOAPI/svc_auto_healer.go
APPS=$GOAPI/rt_docker_apps.go
STACKS=$GOAPI/rt_stacks.go
GIT=$GOAPI/rt_git_deploys.go
SVC=$GOAPI/svc_expected_stops.go
DEFAULTS=$GOAPI/svc_alert_runbook_defaults.go
MIG=$GOAPI/migrations/20260822000000_container_expected_stops.sql
SPA=panel/frontend/src/pages/Apps.tsx

for f in "$ENGINE" "$HEALER" "$APPS" "$STACKS" "$GIT" "$SVC" "$DEFAULTS" "$MIG" "$SPA"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT. Copied from the FIXED stripper (lesson #136): the
# naive s{/\*.*?\*/}{}gs deletes real code because `/*` occurs inside string
# literals. Every arm below reads a stripped subject, so the explanatory prose in
# these files — which necessarily quotes the very shapes being pinned — cannot
# satisfy an arm (the s386 trap, which shipped a suite 43/43 green over the
# headline defect restored).
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}
subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }

# SQL comments are `--`, which the Go stripper does not touch.
sqlsubj() { sed -E 's/^[[:space:]]*--.*$//' "$1"; }

# The body of one top-level func (or method), bounded by the NEXT top-level
# func. The signature line itself is skipped, so a top-level statement sits at
# brace depth 0.
fnbody() {
  awk -v name="$2" '
    /^func / {
      if (index($0, "func " name "(") || $0 ~ ("^func \\([^)]*\\) " name "\\(")) { inside=1; next }
      inside=0
    }
    inside { print }
  ' <<< "$1"
}

# Whitespace-squeezed (spaces AND tabs — gofmt indents with tabs), so reflowing a call across lines cannot retire an
# arm (lesson #585/#638 — it has happened twice).
flat() { tr -d ' \t\n' <<< "$1"; }

# Brace depth immediately BEFORE the first occurrence of fixed-string $2 in
# body $1 (relative to where $1 itself starts — this file's fnbody() already
# skips the signature line, so a top-level statement sits at depth 0). A
# text-presence check alone cannot tell live code from the identical text
# sitting inside a dead branch (`if false { ... }`) — both contain the same
# text in the same relative order. This can: the extra `{` from a wrapper
# pushes everything inside it one level deeper. Prints -1 if $2 is absent.
depth_before() {
  local off
  off=$(grep -boF -- "$2" <<< "$1" | head -1 | cut -d: -f1)
  if [ -z "$off" ]; then echo -1; return; fi
  local prefix="${1:0:$off}"
  local opens closes
  opens=$(tr -cd '{' <<< "$prefix" | wc -c)
  closes=$(tr -cd '}' <<< "$prefix" | wc -c)
  echo $((opens - closes))
}

echo "== §A  the severity FIRED and the severity DECLARED are the same string =="

if EG=$(subj "$ENGINE"); then
  CH=$(fnbody "$EG" alertEngineCheckContainerHealth)
  CHF=$(flat "$CH")

  if [ -n "$CH" ]; then
    ok "A0-control alertEngineCheckContainerHealth extracted, $(wc -l <<< "$CH") lines"
  else
    bad "A0-control alertEngineCheckContainerHealth extracted"
  fi

  # DERIVED on both sides. The declared value is read out of the defaults table
  # rather than spelled here, so this arm goes red if EITHER side moves.
  # Go table rows are positional {AlertType, Severity, RunbookMd}; the struct
  # field order is asserted too, so a reorder cannot make this read the wrong
  # column.
  DECLARED=""
  if perl -0777 -ne 'exit(/struct\s*\{\s*AlertType\s+string\s+Severity\s+string/s ? 0 : 1)' "$DEFAULTS"; then
    DECLARED=$(perl -0777 -ne '
      while (/\{\s*"container_down"\s*,\s*"([a-z]+)"/gs) { print "$1\n" }
      while (/AlertType:\s*"container_down"\s*,\s*Severity:\s*"([a-z]+)"/gs) { print "$1\n" }
    ' "$DEFAULTS" | head -1)
  fi
  FIRED=$(perl -0777 -ne 'while (/FireAlertWithRetry\([^;]*?"container_down",name,"([a-z]+)",/gs) { print "$1\n" }' <<< "$CHF" | head -1)

  if [ -n "$DECLARED" ]; then
    ok "A1-control the declared severity was parsed out of svc_alert_runbook_defaults.go: '$DECLARED'"
  else
    bad "A1-control the declared severity was parsed out of svc_alert_runbook_defaults.go — parsed nothing"
  fi
  if [ -n "$FIRED" ]; then
    ok "A2-control the fired severity was parsed out of the engine: '$FIRED'"
  else
    bad "A2-control the fired severity was parsed out of the engine — parsed nothing"
  fi
  if [ -n "$DECLARED" ] && [ "$DECLARED" = "$FIRED" ]; then
    ok "A3 container_down is fired at the severity the product declares ($FIRED)"
  else
    bad "A3 container_down is fired at the severity the product declares — declared '$DECLARED', fired '$FIRED'"
  fi

  # The incident branch gates on this exact string, so the regression has a name.
  if [ "$FIRED" = "critical" ]; then
    bad "A4 container_down is not raised at the severity that opens a PUBLIC incident"
  else
    ok "A4 container_down is not raised at the severity that opens a PUBLIC incident"
  fi

  echo
  echo "== §B  the suppression is at the CHECK, never in the fire funnel =="

  FWR=$(fnbody "$EG" alertEngineFireAlertWithRetry)
  if grep -qF 'NotificationsTryFireAlert(' <<< "$FWR"; then
    ok "B1-control the fire funnel was extracted and is non-empty"
    if grep -qiE 'expected_?stop' <<< "$FWR"; then
      bad "B2 the expectation is NOT consulted at the fire — it is, and every alert_state stamp beside a fire then claims a page that never went out"
    else
      ok "B2 the expectation is not consulted at the fire"
    fi
  else
    bad "B1-control the fire funnel was extracted and is non-empty"
  fi

  # The skip must precede the alert_state stamp, or the row is written 'firing'
  # while nothing is sent and the key is deaf for ever. Ordering by line number
  # with BOTH anchors asserted present (lesson #582).
  # Anchored on the SKIP ITSELF — the predicate guarding a bare `continue` — and
  # not on "the last occurrence of the predicate". The first cut used the latter
  # and passed over its own mutation: deleting the skip left the CLEAR guard as
  # the last match, which is also above the stamp (#626, an arm that inspects the
  # wrong token cannot fail). Found by the mutation run, not by review.
  NSKIP=$(grep -oF 'ifexpectedStopped[name]{continue}' <<< "$CHF" | wc -l)
  if [ "$NSKIP" -eq 1 ]; then
    ok "B3a the exited arm carries exactly one unconditional skip"
  else
    bad "B3a the exited arm carries exactly one unconditional skip — found $NSKIP"
  fi
  # The skip's line = the first predicate use AFTER the ladder opens, so this
  # cannot silently fall back onto the clear guard above it.
  SKIPLINE=$(awk '/state == "exited" \|\| state == "dead"/{seen=1} seen && /expectedStopped\[name\]/{print NR; exit}' <<< "$CH")
  STAMP=$(grep -n "INSERT INTO alert_state" <<< "$CH" | head -1 | cut -d: -f1)
  if [ -n "$SKIPLINE" ] && [ -n "$STAMP" ] && [ "$SKIPLINE" -lt "$STAMP" ]; then
    ok "B3b the skip precedes the alert_state stamp (skip $SKIPLINE < stamp $STAMP)"
  else
    bad "B3b the skip precedes the alert_state stamp (skip '$SKIPLINE', stamp '$STAMP')"
  fi

  echo
  echo "== §C  cleared from OBSERVATION, above the ladder, not gated on health =="

  CLEAR=$(grep -n 'ExpectedStopsClearIfOlderThan(' <<< "$CH" | head -1 | cut -d: -f1)
  LADDER=$(grep -n 'state == "exited" || state == "dead"' <<< "$CH" | head -1 | cut -d: -f1)
  if [ -n "$CLEAR" ] && [ -n "$LADDER" ] && [ "$CLEAR" -lt "$LADDER" ]; then
    ok "C1 the clear runs ABOVE the state ladder (clear $CLEAR < ladder $LADDER)"
  else
    bad "C1 the clear runs ABOVE the state ladder (clear '$CLEAR', ladder '$LADDER')"
  fi

  # Keyed on liveness, not on health. `running` alone would miss restarting /
  # paused / created, and `running && healthy` would miss the unhealthy comeback.
  if grep -qF 'ifstate!="exited"&&state!="dead"&&expectedStopped[name]{ExpectedStopsClearIfOlderThan(' <<< "$CHF"; then
    ok "C2 the clear is keyed on not-exited/not-dead, not on running-and-healthy"
  else
    bad "C2 the clear is keyed on not-exited/not-dead, not on running-and-healthy"
  fi

  NCLEAR=$(grep -oF 'ExpectedStopsClearIfOlderThan(' <<< "$CHF" | wc -l)
  if [ "$NCLEAR" -eq 1 ]; then
    ok "C3 exactly one clear site in the health check"
  else
    bad "C3 exactly one clear site in the health check — found $NCLEAR"
  fi
else
  for a in A0 A1 A2 A3 A4 B1 B2 B3 C1 C2 C3; do bad "$a $ENGINE is readable"; done
fi

echo
echo "== §D  the clear cannot move the auto-sleep clock =="

if SV=$(subj "$SVC"); then
  CLEARFN=$(fnbody "$SV" ExpectedStopsClearIfOlderThan)
  if grep -qF 'DELETE FROM container_expected_stops' <<< "$CLEARFN"; then
    ok "D1-control the clear statement was extracted"
    BUMPS=""
    for col in last_activity_at last_woken_at total_sleeps is_sleeping; do
      if grep -qF "$col" <<< "$CLEARFN"; then BUMPS="$BUMPS $col"; fi
    done
    if [ -z "$BUMPS" ]; then
      ok "D2 the clear writes none of the auto-sleep columns"
    else
      bad "D2 the clear writes none of the auto-sleep columns — found:$BUMPS"
    fi
  else
    bad "D1-control the clear statement was extracted"
  fi

  # Positive control for D2: those column names DO occur elsewhere in the tree,
  # so "found none" above is a real absence and not a pattern that cannot match.
  if AP=$(subj "$APPS"); then
    if grep -qF 'last_activity_at' <<< "$AP"; then
      ok "D3-control last_activity_at is present elsewhere, so D2's absence is real"
    else
      bad "D3-control last_activity_at is present elsewhere, so D2's absence is real"
    fi
  fi
else
  for a in D1 D2 D3; do bad "$a $SVC is readable"; done
fi

echo
echo "== §E  every deliberate stop records, every start clears =="

if AP=$(subj "$APPS"); then
  for fn in rtDockerAppsStopApp rtDockerAppsSleepContainer; do
    B=$(flat "$(fnbody "$AP" "$fn")")
    if grep -qF 'ExpectedStopsRecord(' <<< "$B"; then
      ok "E1 $fn records the expectation"
    else
      bad "E1 $fn records the expectation"
    fi
  done
  for fn in rtDockerAppsStartApp rtDockerAppsRestartApp rtDockerAppsWakeContainer; do
    B=$(flat "$(fnbody "$AP" "$fn")")
    if grep -qF 'ExpectedStopsClear(' <<< "$B"; then
      ok "E2 $fn clears the expectation"
    else
      bad "E2 $fn clears the expectation"
    fi
  done

  # An expectation recorded before the stop succeeded would mark a RUNNING
  # container. Assert the record sits after the agent call in rtDockerAppsStopApp.
  SB=$(fnbody "$AP" rtDockerAppsStopApp)
  POST=$(grep -n 'agentError("Container stop"' <<< "$SB" | head -1 | cut -d: -f1)
  REC=$(grep -n 'ExpectedStopsRecord(' <<< "$SB" | head -1 | cut -d: -f1)
  if [ -n "$POST" ] && [ -n "$REC" ] && [ "$POST" -lt "$REC" ]; then
    ok "E3 rtDockerAppsStopApp records only after the stop succeeded (post $POST < record $REC)"
  else
    bad "E3 rtDockerAppsStopApp records only after the stop succeeded (post '$POST', record '$REC')"
  fi
else
  bad "E $APPS is readable"
fi

if ST=$(subj "$STACKS"); then
  SA=$(flat "$(fnbody "$ST" rtStacksAction)")
  if grep -qF 'ExpectedStopsRecord(' <<< "$SA" && grep -qF 'ExpectedStopsClear(' <<< "$SA"; then
    ok "E4 the stack path both records and clears — one click stops N containers"
  else
    bad "E4 the stack path both records and clears — one click stops N containers"
  fi
else
  bad "E4 $STACKS is readable"
fi

# s449: a NEW class of door, per this suite's own instruction above — the 3
# recreate handlers (update_app, update_image, update_env) now record too, but
# with the OPPOSITE ordering from E3/E7b's "record only after the stop
# succeeded": these interrupt a container ON PURPOSE via the agent's own
# remove-then-create, so the healer must be blind to that gap from the moment
# it OPENS, not after — record before the call, clear unconditionally once it
# returns (success or failure), or a refused/failed recreate leaves a
# container that never actually stopped marked expected-stopped forever.
# [[project_dockpanel_tech_debt_p185]] carry G.
#
# Go port: update_app (rtDockerAppsUpdateApp) still wraps its agent call
# inline; update_env / update_image now hand their agent call as a closure to
# the shared rtDockerAppsRecreate, which owns record → call → clear. So the
# ordering is asserted once on the helper (E8-helper) and each of those two
# handlers is asserted to route its agent call THROUGH the helper's closure.
if AP=$(subj "$APPS"); then
  E8_OK=0
  UB=$(fnbody "$AP" rtDockerAppsUpdateApp)
  RECPOS=$(grep -n 'ExpectedStopsRecord(' <<< "$UB" | head -1 | cut -d: -f1)
  CALLPOS=$(grep -nF 'agent.PostLong(ctx, "/apps/"+cid+"/update"' <<< "$UB" | head -1 | cut -d: -f1)
  CLEARPOS=$(grep -n 'ExpectedStopsClear(' <<< "$UB" | head -1 | cut -d: -f1)
  if [ -n "$RECPOS" ] && [ -n "$CALLPOS" ] && [ -n "$CLEARPOS" ] \
     && [ "$RECPOS" -lt "$CALLPOS" ] && [ "$CALLPOS" -lt "$CLEARPOS" ]; then
    ok "E8 rtDockerAppsUpdateApp records before the recreate call and clears after it (record $RECPOS < call $CALLPOS < clear $CLEARPOS)"
    E8_OK=$((E8_OK + 1))
  else
    bad "E8 rtDockerAppsUpdateApp ordering wrong (record '$RECPOS', call '$CALLPOS', clear '$CLEARPOS') — recording after the call would mark a still-running container; clearing before it would un-suppress the healer mid-recreate"
  fi

  HB=$(fnbody "$AP" rtDockerAppsRecreate)
  HREC=$(grep -n 'ExpectedStopsRecord(' <<< "$HB" | head -1 | cut -d: -f1)
  HCALL=$(grep -nE 'result, err := call\(ctx\)' <<< "$HB" | head -1 | cut -d: -f1)
  HCLR=$(grep -n 'ExpectedStopsClear(' <<< "$HB" | head -1 | cut -d: -f1)
  HERR=$(grep -n 'if err != nil' <<< "$HB" | head -1 | cut -d: -f1)
  if [ -n "$HREC" ] && [ -n "$HCALL" ] && [ -n "$HCLR" ] && [ -n "$HERR" ] \
     && [ "$HREC" -lt "$HCALL" ] && [ "$HCALL" -lt "$HCLR" ] && [ "$HCLR" -lt "$HERR" ]; then
    ok "E8-helper rtDockerAppsRecreate records before the call and clears after it, ahead of the error check (record $HREC < call $HCALL < clear $HCLR < err $HERR)"
  else
    bad "E8-helper rtDockerAppsRecreate ordering wrong (record '$HREC', call '$HCALL', clear '$HCLR', err-check '$HERR') — a clear gated on success leaves a failed recreate's container expected-stopped forever"
  fi

  declare -A RECREATE_CALL_ANCHOR=(
    [rtDockerAppsUpdateEnv]='agent.PutLong(ctx, "/apps/"+cid+"/env"'
    [rtDockerAppsUpdateImage]='agent.PostLong(ctx, "/apps/"+cid+"/change-image"'
  )
  for fn in rtDockerAppsUpdateEnv rtDockerAppsUpdateImage; do
    RB=$(fnbody "$AP" "$fn")
    ANCHOR="${RECREATE_CALL_ANCHOR[$fn]}"
    VIA=$(grep -n 'rtDockerAppsRecreate(' <<< "$RB" | head -1 | cut -d: -f1)
    CALLPOS=$(grep -nF "$ANCHOR" <<< "$RB" | head -1 | cut -d: -f1)
    if [ -n "$VIA" ] && [ -n "$CALLPOS" ] && [ "$((VIA + 1))" -eq "$CALLPOS" ] \
       && [ "$(grep -cE 'agent\.(Put|Post)Long\(' <<< "$RB")" -eq 1 ]; then
      ok "E8 $fn runs its only recreate call inside rtDockerAppsRecreate's closure (helper $VIA, call $CALLPOS)"
      E8_OK=$((E8_OK + 1))
    else
      bad "E8 $fn does not route its recreate call through rtDockerAppsRecreate (helper '$VIA', call '$CALLPOS' via anchor '$ANCHOR') — the call runs outside the record/clear window"
    fi
  done
  if [ "$E8_OK" -eq 3 ]; then
    ok "E8-summary all 3 recreate doors record-before/clear-after around their agent call"
  else
    bad "E8-summary only $E8_OK/3 recreate doors correctly ordered — the auto-healer can revive a container mid-migrate"
  fi
else
  bad "E8 $APPS is readable"
fi

# ⛔ THE LIST ABOVE IS A LITERAL, AND A LITERAL CANNOT SEE A DOOR IT DOES NOT
# NAME. `rtGitDeploysStop` shipped 2026-03-18, this table arrived 2026-08-22,
# and E1-E5 were green for the whole gap because a fifth door is unrepresentable
# in an assertion that enumerates four.
#
# ⚠ HONEST SCOPE (measured on a box at s397, both versions): closing that fifth
# door changes NO observable behaviour today. `/apps` keeps only containers with
# `dockpanel.app.template` and a git container has none, so neither the healer
# nor the alert engine can see one. E7 pins a door that is correct and currently
# inert — which is worth pinning, because the day `/apps` includes git
# containers the pin is what stops the door regressing unnoticed. Every
# NEW deliberate stop path owes an arm here in the same commit. A derived census
# was attempted and is NOT available: the three doors post the agent call in
# three different shapes (a computed `agent_path`, an inline `format!`, a
# literal), and only ONE of the three modules persists a status column at all —
# so any repo-wide grep would report a confident, false, all-clear.
if GD=$(subj "$GIT"); then
  GB=$(fnbody "$GD" rtGitDeploysStop)
  # FLOOR the subject: an fnbody whose pattern stops matching yields an EMPTY
  # string, under which every `grep -q` below fails OPEN in the wrong direction.
  if [ "$(wc -l <<< "$GB")" -lt 8 ]; then
    bad "E7 rtGitDeploysStop body resolved ($(wc -l <<< "$GB") lines — subject lost)"
  else
    GBF=$(flat "$GB")
    if grep -qF 'ExpectedStopsRecord(' <<< "$GBF"; then
      ok "E7 rtGitDeploysStop records the expectation"
    else
      bad "E7 rtGitDeploysStop records the expectation"
    fi

    # Same ordering assertion as E3, for the same reason: recorded before the
    # agent call succeeds would mark a container that is still running.
    POSTG=$(grep -n 'agentError("Stop container"' <<< "$GB" | head -1 | cut -d: -f1)
    RECG=$(grep -n 'ExpectedStopsRecord(' <<< "$GB" | head -1 | cut -d: -f1)
    if [ -n "$POSTG" ] && [ -n "$RECG" ] && [ "$POSTG" -lt "$RECG" ]; then
      ok "E7b rtGitDeploysStop records only after the stop succeeded (post $POSTG < record $RECG)"
    else
      bad "E7b rtGitDeploysStop records only after the stop succeeded (post '$POSTG', record '$RECG')"
    fi
  fi

  GS=$(fnbody "$GD" rtGitDeploysStart)
  if [ "$(wc -l <<< "$GS")" -lt 8 ]; then
    bad "E7c rtGitDeploysStart body resolved ($(wc -l <<< "$GS") lines — subject lost)"
  elif grep -qF 'ExpectedStopsClear(' <<< "$(flat "$GS")"; then
    ok "E7c rtGitDeploysStart clears the expectation"
  else
    bad "E7c rtGitDeploysStart clears the expectation"
  fi

  # The KEY is the whole fix. The stored name is bare; the healer matches the
  # agent's container name. A record under the wrong key is silently inert — it
  # writes a row nothing ever reads, which looks exactly like working.
  #
  # ⛔ SCOPED TO THE HELPER'S OWN BODY, and this arm was FILE-scoped when first
  # written: dropping the prefix left it GREEN, because
  # the PR-preview name builder ("dockpanel-git-" + name + "-pr-" + slug) far away CONTAINS
  # the literal once whitespace is squeezed. Twelve occurrences of the prefix
  # live in this file. A whole-file `has` here is unfalsifiable.
  # Go: the helper is a one-line func, so its body IS its signature line —
  # scoped to that one line (fnbody skips the signature line).
  KB=$(grep -E '^func rtGitDeploysExpectedStopKey\(' <<< "$GD")
  if [ "$(grep -c . <<< "$KB")" -ne 1 ]; then
    bad "E7d rtGitDeploysExpectedStopKey resolved ($(grep -c . <<< "$KB") definitions — subject lost)"
  elif grep -qF 'func rtGitDeploysExpectedStopKey(name string) string { return "dockpanel-git-" + name }' <<< "$KB"; then
    ok "E7d the recorded key carries the agent's dockpanel-git- prefix"
  else
    bad "E7d the recorded key carries the agent's dockpanel-git- prefix"
  fi

  # ...and that `stop()` actually routes its key through that helper, rather
  # than spelling a bare name inline. E7d alone would pass with the helper
  # correct and unused — the #732 shape this whole session exists to not repeat.
  if grep -qF 'containerName:=rtGitDeploysExpectedStopKey(config.Name)ExpectedStopsRecord(ctx,st.DB,config.ServerID,containerName,' <<< "$(flat "$GB")"; then
    ok "E7e rtGitDeploysStop derives its key through rtGitDeploysExpectedStopKey"
  else
    bad "E7e rtGitDeploysStop derives its key through rtGitDeploysExpectedStopKey"
  fi
else
  bad "E7 $GIT is readable"
fi

if HL=$(subj "$HEALER"); then
  HF=$(flat "$HL")
  if grep -qF 'ExpectedStopsRecord(ctx,db,*c.ServerID,c.ContainerName,ExpectedStopsReasonAutoSleep,' <<< "$HF"; then
    ok "E5 the auto-sleep leg records the expectation"
  else
    bad "E5 the auto-sleep leg records the expectation"
  fi
  # The restart leg must READ it, or the panel restarts the operator's own Stop
  # within 120s — silently, now that the spurious alert is gone.
  if grep -qF 'if_,expected:=expectedStopped[name];expected{continue}' <<< "$HF"; then
    ok "E6 the auto-heal restart leg skips a container stopped on purpose"
  else
    bad "E6 the auto-heal restart leg skips a container stopped on purpose"
  fi
else
  for a in E5 E6; do bad "$a $HEALER is readable"; done
fi

echo
echo "== §F  the caller's container id is canonicalised before it becomes a key =="

if AP=$(subj "$APPS"); then
  RC=$(flat "$(fnbody "$AP" rtDockerAppsResolveContainerName)")
  if grep -qF 'iflen(hits)==1{return&hits[0]}returnnil}' <<< "$RC"; then
    ok "F1 an ambiguous id prefix resolves to nothing rather than to the first hit"
  else
    bad "F1 an ambiguous id prefix resolves to nothing rather than to the first hit"
  fi

  # No writer may key on the raw path parameter. Extracted paren-balanced so a
  # reflowed call cannot hide from the arm.
  RAWKEY=$(perl -0777 -ne '
    while (/ExpectedStops(?:Record|Clear)\s*(\((?:[^()]++|(?1))*\))/gs) {
      my $c = $1; $c =~ s/\s+//g;
      print "$c\n" if $c =~ /,cid[,)]/;
    }
  ' <<< "$AP" | wc -l)
  NCALLS=$(perl -0777 -ne '
    while (/ExpectedStops(?:Record|Clear)\s*(\((?:[^()]++|(?1))*\))/gs) { print "x\n" }
  ' <<< "$AP" | wc -l)
  if [ "$NCALLS" -ge 5 ]; then
    ok "F2-control found $NCALLS record/clear call sites to inspect"
  else
    bad "F2-control found $NCALLS record/clear call sites to inspect — too few, the extractor is not matching"
  fi
  if [ "$RAWKEY" -eq 0 ]; then
    ok "F3 no writer keys on the raw path parameter"
  else
    bad "F3 no writer keys on the raw path parameter — $RAWKEY call site(s) do"
  fi
fi

echo
echo "== §G  the suppression is membership and nothing broader =="

if EG=$(subj "$ENGINE"); then
  NPRED=$(grep -oF 'expectedStopped[' <<< "$(flat "$EG")" | wc -l)
  if [ "$NPRED" -eq 2 ]; then
    ok "G1 exactly two uses of the predicate — one clear guard, one skip"
  else
    bad "G1 exactly two uses of the predicate — one clear guard, one skip — found $NPRED"
  fi
fi

echo
echo "== §H  the migration carries the server term and does not backfill =="

if MG=$(sqlsubj "$MIG"); then
  MGF=$(flat "$MG")
  if grep -qF 'UNIQUE(server_id,container_name)' <<< "$MGF"; then
    ok "H1 the UNIQUE carries the server term"
  else
    bad "H1 the UNIQUE carries the server term"
  fi
  if grep -qF 'REFERENCESservers(id)ONDELETECASCADE' <<< "$MGF"; then
    ok "H2 rows die with their server"
  else
    bad "H2 rows die with their server"
  fi
  if grep -qF 'INSERTINTOcontainer_expected_stops' <<< "$MGF"; then
    bad "H3 the migration does NOT backfill — it does, which would silence containers that are down right now"
  else
    ok "H3 the migration does not backfill"
  fi
fi

echo
echo "== §I  the SPA stops calling a deliberate stop a crash =="

if SP=$(subj "$SPA"); then
  SPAF=$(flat "$SP")
  if grep -qF 'stoppedApps.filter(a=>!a.expected_stop_reason)' <<< "$SPAF"; then
    ok "I1 the crashed list excludes containers the panel stopped"
  else
    bad "I1 the crashed list excludes containers the panel stopped"
  fi
  if grep -qF 'intentionallyStopped' <<< "$SPAF"; then
    ok "I2 the deliberate stops are rendered as their own group"
  else
    bad "I2 the deliberate stops are rendered as their own group"
  fi
fi

echo
echo "== §J  a REMOVED container's expectation dies with it =="

# §C clears from OBSERVING a container alive, so it can only ever reach one that
# still exists. A REMOVED container is never observed again in any state, so its
# row outlives it and the NEXT container of that name inherits the silence —
# `container_down` skipped, the auto-heal restart leg skipped, and the Apps page
# calling it "stopped on purpose" and naming whoever stopped the container that
# is gone. Remove-and-redeploy under the same name is the supported way to
# rebuild an app and keep its data, so that container is the repair loop's own.
#
# Two mechanisms, and they cover different failures. The DOORS clear exactly and
# with no window, which is the only thing that helps when a container is removed
# and replaced inside one 120s sweep. The engine's SWEEP is the only thing that
# can see a removal the panel did not perform, or a door added later — which is
# how this defect got here, since §E's list of doors is hardcoded and removal was
# never in it.
#
# ⚠ Every door arm below DERIVES BOTH SIDES from the subject and carries a
# floor, so it cannot go quiet when the population grows (#707/#708: a count of
# a rule's OBSERVANCE cannot see a violation).

# The top-level fn names of a subject, in order.
fnnames() {
  awk '
    match($0, /^func (\([^)]*\) )?[A-Za-z0-9_]+\(/) {
      s = substr($0, RSTART, RLENGTH); sub(/^func (\([^)]*\) )?/, "", s); sub(/\(.*/, "", s); print s
    }
  ' <<< "$1"
}

if SV=$(subj "$SVC"); then
  ABS=$(fnbody "$SV" ExpectedStopsClearAbsent)
  ABSF=$(flat "$ABS")
  if [ "${#ABS}" -ge 150 ] && grep -qF 'DELETEFROMcontainer_expected_stops' <<< "$ABSF"; then
    ok "J1-control ExpectedStopsClearAbsent extracted (${#ABS} chars) and deletes from the table"

    # ⛔ THE INVERSION GUARD, and it is the whole reason this arm exists.
    # `container_name <> ALL('{}')` is TRUE for every row, so a sweep handed an
    # empty listing deletes every expectation on the host — and the next sweep
    # then fires container_down for every container the operator deliberately
    # stopped, which is the exact defect v2.144.0 shipped this table to remove.
    # An empty listing is the one observation that cannot tell "nothing is here"
    # from "I can see nothing".
    if grep -qF 'iflen(observed)==0{return}' <<< "$ABSF"; then
      ok "J2 the sweep refuses an EMPTY observation"
    else
      bad "J2 the sweep refuses an EMPTY observation — an empty listing would clear the whole host"
    fi

    # Same race ExpectedStopsClearIfOlderThan carries: one snapshot, walked with awaited
    # calls, so a stop recorded inside that window is NEWER than the evidence.
    if grep -qF 'stopped_at<$' <<< "$ABSF"; then
      ok "J3 the sweep will not discard an expectation newer than its own evidence"
    else
      bad "J3 the sweep will not discard an expectation newer than its own evidence"
    fi

    # §D's rule applies here too: this runs every 120s against every member, so
    # touching the auto-sleep clock would silently disable auto-sleep for ever.
    BUMPS=""
    for col in last_activity_at last_woken_at total_sleeps is_sleeping; do
      if grep -qF "$col" <<< "$ABS"; then BUMPS="$BUMPS $col"; fi
    done
    if [ -z "$BUMPS" ]; then
      ok "J4 the sweep writes none of the auto-sleep columns"
    else
      bad "J4 the sweep writes none of the auto-sleep columns — found:$BUMPS"
    fi
  else
    for a in J1-control J2 J3 J4; do bad "$a ExpectedStopsClearAbsent extracted from $SVC"; done
  fi
else
  for a in J1-control J2 J3 J4; do bad "$a $SVC is readable"; done
fi

if EG=$(subj "$ENGINE"); then
  CH2=$(fnbody "$EG" alertEngineCheckContainerHealth)
  CH2F=$(flat "$CH2")
  NABS=$(grep -oF 'ExpectedStopsClearAbsent(ctx,db,serverID,observedNames,observedAt)' <<< "$CH2F" | wc -l)
  if [ "$NABS" -eq 1 ]; then
    ok "J5 the engine runs the absence sweep exactly once"
  else
    bad "J5 the engine runs the absence sweep exactly once — found $NABS"
  fi

  # ONE observation, read by both sweeps. A second binding of the listing would
  # let the expectation sweep be fed a filtered subset while the arm above still
  # counted one call — and every name missing from that subset would be deleted.
  # Go keeps the listing as a set (observed, read by the alert_state sweep) and
  # a slice (observedNames, handed to ExpectedStopsClearAbsent), both bound once
  # and filled in ONE loop over the agent's array — so the slice is the set.
  NOBS=$(grep -oF 'observedNames:=' <<< "$CH2F" | wc -l)
  NAPP=$(grep -oE 'observedNames=' <<< "$CH2F" | wc -l)
  FILL=$(grep -cF 'observed[n]=trueobservedNames=append(observedNames,n)' <<< "$CH2F")
  if [ "$NOBS" -eq 1 ] && [ "$NAPP" -eq 1 ] && [ "$FILL" -eq 1 ]; then
    ok "J6 the host's listing is bound once and both sweeps read that one binding"
  else
    bad "J6 the host's listing is bound once and both sweeps read that one binding — bindings $NOBS, reassignments $NAPP, joint fill $FILL"
  fi
else
  for a in J5 J6; do bad "$a $ENGINE is readable"; done
fi

# ── The doors. Both sides derived from the subject, with a floor. ────────────
if ST=$(subj "$STACKS"); then
  SDOORS=0; SCLEARS=0; SMISSING=""
  while read -r fn; do
    [ -n "$fn" ] || continue
    B=$(flat "$(fnbody "$ST" "$fn")")
    case "$B" in
      *'"action":"remove"'*)
        SDOORS=$((SDOORS+1))
        case "$B" in
          *'ExpectedStopsClear('*|*'rtStacksClearRemoved('*) SCLEARS=$((SCLEARS+1)) ;;
          *) SMISSING="$SMISSING $fn" ;;
        esac
        ;;
    esac
  done <<< "$(fnnames "$ST")"

  if [ "$SDOORS" -ge 3 ]; then
    ok "J7-control found $SDOORS stack doors that ask the agent to REMOVE containers"
    if [ "$SDOORS" -eq "$SCLEARS" ]; then
      ok "J8 every stack removal door forgets the expectations ($SCLEARS/$SDOORS)"
    else
      bad "J8 every stack removal door forgets the expectations ($SCLEARS/$SDOORS) — missing:$SMISSING"
    fi
  else
    bad "J7-control found $SDOORS stack removal doors — too few, the extractor is not matching"
  fi
  # Go: the doors share rtStacksClearRemoved, so J8 is only as good as that
  # helper actually clearing every container the agent reports removed.
  CRB=$(flat "$(fnbody "$ST" rtStacksClearRemoved)")
  if grep -qF 's=="removed"{ifname,ok:=jsonStr(jsonGet(r,"name"));ok{ExpectedStopsClear(ctx,db,serverID,name)' <<< "$CRB"; then
    ok "J8b rtStacksClearRemoved clears the expectation of every container reported removed"
  else
    bad "J8b rtStacksClearRemoved clears the expectation of every container reported removed"
  fi
else
  for a in J7-control J8; do bad "$a $STACKS is readable"; done
fi

if AP=$(subj "$APPS"); then
  ADOORS=0; ACLEARS=0; AMISSING=""
  while read -r fn; do
    [ -n "$fn" ] || continue
    B=$(flat "$(fnbody "$AP" "$fn")")
    case "$B" in
      *'.Delete(ctx,"/apps/"+cid)'*)
        ADOORS=$((ADOORS+1))
        case "$B" in
          *'ExpectedStopsClear('*) ACLEARS=$((ACLEARS+1)) ;;
          *) AMISSING="$AMISSING $fn" ;;
        esac
        ;;
    esac
  done <<< "$(fnnames "$AP")"

  if [ "$ADOORS" -ge 1 ]; then
    ok "J9-control found $ADOORS app door(s) that DELETE the container itself"
    if [ "$ADOORS" -eq "$ACLEARS" ]; then
      ok "J10 every app removal door forgets the expectation ($ACLEARS/$ADOORS)"
    else
      bad "J10 every app removal door forgets the expectation ($ACLEARS/$ADOORS) — missing:$AMISSING"
    fi
  else
    bad "J9-control found $ADOORS app removal doors — too few, the extractor is not matching"
  fi

  # ORDERING, not presence. The name has to be read while the container still
  # exists — the agent's removal response carries the freed domain, never the
  # name — and the row must not be cleared until the removal has succeeded, or a
  # refusal would un-suppress a container that is still deliberately stopped.
  RB=$(fnbody "$AP" rtDockerAppsRemoveApp)
  RES=$(grep -n 'rtDockerAppsResolveContainerName(' <<< "$RB" | head -1 | cut -d: -f1)
  DEL=$(grep -nF '.Delete(ctx, "/apps/"+cid)' <<< "$RB" | head -1 | cut -d: -f1)
  CLR=$(grep -n 'ExpectedStopsClear(' <<< "$RB" | head -1 | cut -d: -f1)
  if [ -n "$RES" ] && [ -n "$DEL" ] && [ -n "$CLR" ] && [ "$RES" -lt "$DEL" ] && [ "$DEL" -lt "$CLR" ]; then
    ok "J11 rtDockerAppsRemoveApp resolves BEFORE the removal and clears AFTER it (resolve $RES < delete $DEL < clear $CLR)"
  else
    bad "J11 rtDockerAppsRemoveApp resolves BEFORE the removal and clears AFTER it (resolve '$RES', delete '$DEL', clear '$CLR')"
  fi
else
  for a in J9-control J10 J11; do bad "$a $APPS is readable"; done
fi

echo "== §K  container_sleep_config survives the SAME recreate this file's own migration named (s436) =="
#
# This file's own migration (MIG, 20260822000000_container_expected_stops.sql,
# §1 "THE KEY") documents that update_app/change_container_image/update_env
# "all stop, remove and re-create the container, which mints a NEW id and
# keeps the name" — and fixed container_expected_stops by keying on
# (server_id, container_name) instead of container_id BECAUSE of exactly this.
# container_sleep_config is still keyed on container_id alone (no change to
# that table's schema), so it needed the OTHER half of the same fix: re-point
# the existing row at the new id when a recreate happens, or the row goes
# permanently unreachable and auto-sleep silently stops working with no error
# and no UI indication — the live bug tracked in tech_debt p4 since s238.

if AP=$(subj "$APPS"); then
  RK=$(fnbody "$AP" rtDockerAppsRekeySleepConfig)
  RKF=$(flat "$RK")

  if [ -n "$RK" ]; then
    ok "K0-control rtDockerAppsRekeySleepConfig extracted, $(wc -l <<< "$RK") lines"
  else
    bad "K0-control could not extract rtDockerAppsRekeySleepConfig — every arm below is vacuous"
  fi

  # K1 — the UPDATE sets container_id from the NEW value and matches on the OLD
  # one, in that placeholder order ($1=new, $2=old). Checked as one flattened
  # string so reflowing the query across lines cannot retire this arm.
  if grep -qF 'UPDATEcontainer_sleep_configSETcontainer_id=$1WHEREcontainer_id=$2' <<< "$RKF"; then
    ok "K1 rtDockerAppsRekeySleepConfig's UPDATE sets container_id from \$1 (new) and matches \$2 (old)"
  else
    bad "K1 rtDockerAppsRekeySleepConfig's UPDATE does not match the expected SET \$1 / WHERE \$2 shape — re-read it, the bind order may have been swapped"
  fi

  # K2 — the bind ARGS agree with K1's placeholder order: newID first (-> $1),
  # oldID second (-> $2), and the signature names them (oldID, newID) so the
  # callers' (cid, newID) lands the right way round. A swap would compile, run,
  # and silently re-key every row to the OLD id — the exact inverse of the fix.
  if grep -qF 'container_id=$2",newID,oldID)' <<< "$RKF" \
     && grep -qE '^func rtDockerAppsRekeySleepConfig\(ctx context\.Context, db \*pgxpool\.Pool, oldID, newID string\)' <<< "$AP"; then
    ok "K2 bind order is newID then oldID, matching \$1/\$2, under an (oldID, newID) signature"
  else
    bad "K2 bind order / signature does not match execSQL(..., newID, oldID) under (oldID, newID) — \$1/\$2 would receive the wrong values even if K1 is green"
  fi

  # K3 — every recreate path actually invokes the re-key, reading the NEW id
  # from the agent's own response rather than assuming one. Go: update_app does
  # it inline; update_env/update_image do it via rtDockerAppsRecreate, so the
  # helper must re-key AND each of those handlers must go through the helper.
  #
  # K4 — LIVENESS by absolute brace depth (fnbody skips the signature line, so a
  # top-level statement is depth 0). Text presence cannot tell a real call from
  # the identical text inside a dead branch; an extra wrapper shifts the depth.
  # Baselines: update_app's re-key sits in `go func() {` → `} else {` (if at 2,
  # call at 3); the helper's at top level (if at 0, call at 1); the two
  # handlers call the helper at top level (0).
  REKEY_IF='if newID, ok := jsonStr(jsonGet(result, "container_id")); ok {'
  CALLED=""; LIVE=""
  UB=$(fnbody "$AP" rtDockerAppsUpdateApp)
  if grep -qF 'ifnewID,ok:=jsonStr(jsonGet(result,"container_id"));ok{rtDockerAppsRekeySleepConfig(ctx,db,cid,newID)}' <<< "$(flat "$UB")"; then
    CALLED="$CALLED rtDockerAppsUpdateApp"
    [ "$(depth_before "$UB" "$REKEY_IF")" = 2 ] && [ "$(depth_before "$UB" 'rtDockerAppsRekeySleepConfig(')" = 3 ] && LIVE="$LIVE rtDockerAppsUpdateApp"
  fi
  HB=$(fnbody "$AP" rtDockerAppsRecreate)
  HELPER_OK=0
  if grep -qF 'ifnewID,ok:=jsonStr(jsonGet(result,"container_id"));ok{rtDockerAppsRekeySleepConfig(ctx,st.DB,cid,newID)}' <<< "$(flat "$HB")"; then
    HELPER_OK=1
    [ "$(depth_before "$HB" "$REKEY_IF")" = 0 ] && [ "$(depth_before "$HB" 'rtDockerAppsRekeySleepConfig(')" = 1 ] && HELPER_OK=2
  fi
  for f in rtDockerAppsUpdateEnv rtDockerAppsUpdateImage; do
    b=$(fnbody "$AP" "$f")
    if [ "$HELPER_OK" -ge 1 ] && grep -qF 'result,err:=rtDockerAppsRecreate(ctx,st,agent,serverID,cid,' <<< "$(flat "$b")"; then
      CALLED="$CALLED $f"
      [ "$HELPER_OK" -eq 2 ] && [ "$(depth_before "$b" 'rtDockerAppsRecreate(')" = 0 ] && LIVE="$LIVE $f"
    fi
  done
  CALLED=$(echo $CALLED)
  N_CALLED=$(wc -w <<< "$CALLED")
  if [ "$N_CALLED" -eq 3 ]; then
    ok "K3 all 3 recreate handlers (update_app, update_image, update_env) re-key the sleep config with the agent's returned container_id"
  else
    bad "K3 only $N_CALLED/3 recreate handlers re-key the sleep config (found:${CALLED:- none}; helper re-keys: $HELPER_OK) — a container recreated through the missing handler(s) still orphans its sleep config"
  fi

  LIVE=$(echo $LIVE)
  N_LIVE=$(wc -w <<< "$LIVE")
  if [ "$N_LIVE" -eq 3 ]; then
    ok "K4 all 3 re-key paths sit at their baseline brace depth — live, not wrapped in extra dead code"
  else
    bad "K4 only $N_LIVE/3 re-key paths sit at their baseline brace depth (found:${LIVE:- none}) — one or more may be wrapped in an extra dead/conditional branch while text-only K3 still reports it present"
  fi
else
  for a in K0-control K1 K2 K3 K4; do bad "$a $APPS is readable"; done
fi

echo
printf 'expected-stop: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

