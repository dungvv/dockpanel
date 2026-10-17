#!/usr/bin/env bash
# unattended-host-scope-pin-e2e.sh — s298 / v2.56.0
#
# An unattended service must name the host it acts on.
#
# DockPanel's multi-server migration reached every HTTP route and NOT ONE
# background service. `AppState` carries both handles — `Agents *AgentRegistry`
# ("dispatches to local or remote agents by server id") and `Agent *AgentClient`
# ("the legacy single-agent accessor") — and all twelve background services were
# spawned with the legacy one. Each queries rows across the whole fleet and acts
# on whichever machine the panel happens to run on.
#
# For the disk healer that is destruction, not routing. `auto_clean_disk` (Go:
# autoHealerAutoCleanDisk in panel/go/internal/api/svc_auto_healer.go) read
# ONE firing `disk` row with no `server_id` predicate and sent the fixes to the
# local agent. `alert_state` is keyed per server, so ANY member crossing its
# threshold made the panel host clean and prune ITSELF while the full machine was
# never touched. Driven on a two-box fleet against the released v2.55.0: member
# at 93%, panel host at 18% with its own disk never measured, and forty seconds
# after auto-healing was enabled the panel host lost a tenant's container and its
# image — an app the panel had itself put to sleep.
#
#   §A  THE HOST IS NAMED. The row carries a server_id; the action resolves that
#       server's agent; an unreachable agent is REFUSED, never silently swapped
#       for the local one — the fallback was the whole defect.
#   §B  RECOVERY COMPLETES RATHER THAN BEING CONSUMED. A raw UPDATE to 'ok'
#       skipped resolve_alert, so the `alerts` row stayed firing for ever and the
#       engine, seeing state already 'ok', never took its recovery branch again.
#       Retention only purges status='resolved', so the row was unpurgeable too.
#   §C  THE RECLAIM CANNOT REACH WHAT THE PANEL MANAGES. `system prune -af
#       --volumes` removes every stopped container — and a SLEEPING app is a
#       stopped container. Removing it detached its volumes, which the same
#       command reclaimed, and `-a` took the locally built image with no registry
#       to restore from.
#   §D  DESTRUCTION IS CONSENTED TO SEPARATELY, AND THE COOLDOWN CAN EXIST. The
#       hourly gate counted `activity_logs` rows written with the nil uuid,
#       which violates fk_activity_logs_user — every insert failed, the count was
#       always 0, and the prune ran every 120 SECONDS (measured 19:16:13,
#       19:18:13, 19:20:13, 19:22:13).
#   §E  RETENTION KEEPS THE ONLY RECORD OF WHAT IT DID NOT DELETE.
#
# Pure source analysis: no box, no network, no build. The subjects are the Go
# port (panel/go — the only tree that is built and shipped); arm ids and intent
# are unchanged from the Rust originals, and each Rust idiom is mapped to the
# Go shape it became (`Uuid::nil()` → `uuid.Nil`, `for_server(` →
# `.ForServer(`, `log_activity_on_server(` → `ActivityLogActivityOnServer(`,
# a main.rs spawn → a `spawnSupervised` line in core_state.go). Arms that are
# better as unit tests were retired to Go tests and say so where they stood.
#
# Arms key on the CAPABILITY a regression must use, not today's spelling
# (lesson #122). Where an arm could be satisfied by the prose NARRATING a check,
# it keys on the syntax of the operation (lesson #149). An arm that requires a
# key requires a VALUE (lesson #155) — `grep 'scope: "'` is not a check.
#
# NO PIPES INTO `grep -q`: under pipefail grep -q closes the pipe on first match
# and the arm goes red on correct code. Every arm feeds grep a here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33m-\033[0m SKIP %s\n' "$1"; }

API=panel/go/internal/api
AH=$API/svc_auto_healer.go
MAIN=$API/core_state.go
DIAG=panel/go/internal/agent/services/diagnostics.go
SET=$API/rt_settings.go
SETTSX=panel/frontend/src/pages/Settings.tsx
AGENT=$API/svc_agent.go

for f in "$AH" "$MAIN" "$DIAG" "$SET" "$SETTSX" "$AGENT"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT. Copied from the FIXED stripper (lesson #136).
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

# The stripper is code, and code can be wrong. Measure it before trusting it.
FUNC_RE='^func ([(][^)]*[)] )?[A-Za-z_][A-Za-z0-9_]*[[(]'
stripper_self_check() {
  local bad_files=0 f raw stripped
  for f in "$@"; do
    [ -f "$f" ] || continue
    raw=$(grep -cE "$FUNC_RE" "$f" || true)
    stripped=$(grep -cE "$FUNC_RE" <<< "$(code "$f")" || true)
    if [ "$raw" != "$stripped" ]; then
      bad "STRIPPER ATE CODE in $f: $raw func declarations before, $stripped after"
      bad_files=$((bad_files+1))
    fi
  done
  [ "$bad_files" -eq 0 ] && ok "comment stripper preserves every func declaration in all $# subjects"
}

subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }
has()   { grep -qE -- "$2" <<< "$1"; }
count() { grep -cE -- "$2" <<< "$1" || true; }

# `has` is LINE-oriented, but signatures and multi-line SQL string literals
# wrap (Go spells a long statement as `"…"+` fragments, one per line). An arm
# keyed on a construct that spans lines matches nothing — and it
# fails in whichever direction the arm is written, so a PRESENCE arm goes red on
# correct code (noisy, survivable) while an ABSENCE arm goes GREEN on the defect
# (silent, not survivable). Caught at s301: three §G arms measured nothing and
# only the red told me. Flatten a WINDOW, never a whole subject — flattening the
# subject is window bleed by construction (p31).
flat() { tr '\n\t' '  ' <<< "$1" | tr -s ' '; }

# The flattened signature of one function: enough lines to cover a wrapped
# parameter list, anchored on the paren so `func Run` cannot latch onto `func RunScan`.
# Bounded on the line that opens the body (`{` at end of line), never a fixed
# window that runs into the body.
sig() { flat "$(awk -v re="^func ([(][^)]*[)] )?$2[[(]" '!f && $0 ~ re {f=1} f {print; if (/\{[[:space:]]*$/) exit}' <<< "$1")"; }

# Every statement matching a pattern, each flattened onto its own line, so a
# line-oriented `has`/`count` can measure multi-line SQL without bleeding across
# statements. `--` separates grep's windows; it becomes the line break.
stmt() { grep -A "${3:-3}" -E -- "$2" <<< "$1" | tr '\n\t' '  ' | sed 's/ -- /\n/g' | tr -s ' '; }

# Extract one function body by brace balance. A fixed `-A n` window is NOT a
# function (lesson: p31) — a regression that moves a line past the window makes
# the arm silently measure nothing.
# Go: `func Name(` or a method `func (x *T) Name(`, matched on the WHOLE name.
fnbody() {
  local src="$1" name="$2"
  awk -v fn="$name" '
    !started && ($0 ~ ("^func " fn "[[(]") || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) { started=1 }
    started {
      n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth += n - m; print
      if (opened || n>0) opened=1
      if (opened && depth<=0) exit
    }
  ' <<< "$src"
}

echo
echo "unattended-host-scope-pin-e2e — s298 / v2.56.0 · §F s299 · §G s300+s301"
echo "=============================================="
echo
echo "§0 harness self-check"
stripper_self_check "$AH" "$MAIN" "$DIAG" "$SET" "$AGENT"

AH_S=$(subj "$AH")   || { bad "cannot read $AH"; AH_S=""; }
MAIN_S=$(subj "$MAIN") || { bad "cannot read $MAIN"; MAIN_S=""; }
DIAG_S=$(subj "$DIAG") || { bad "cannot read $DIAG"; DIAG_S=""; }
SET_S=$(subj "$SET")   || { bad "cannot read $SET"; SET_S=""; }
TSX_S=$(subj "$SETTSX")|| { bad "cannot read $SETTSX"; TSX_S=""; }
AGENT_S=$(subj "$AGENT") || { bad "cannot read $AGENT"; AGENT_S=""; }

CLEAN=$(fnbody "$AH_S" "autoHealerAutoCleanDisk")
[ -n "$CLEAN" ] || bad "could not extract autoHealerAutoCleanDisk — every §A/§B arm below is meaningless"

echo
echo "§A the host is named"

# A1 — the firing query must carry server_id. The defect was its ABSENCE, so the
# arm requires the predicate, not merely the word.
if has "$CLEAN" "server_id[^\n]*IS NOT NULL|a\.server_id|WHERE a\.alert_type"; then
  ok "A1 autoHealerAutoCleanDisk's firing query is server-aware"
else
  bad "A1 autoHealerAutoCleanDisk selects firing disk alerts with NO server_id — the s298 defect"
fi

# A2 — it must resolve the agent for THAT server, not use a handed-in local one.
if has "$CLEAN" "agents\.ForServer\(ctx, serverID\)"; then
  ok "A2 autoHealerAutoCleanDisk resolves the agent via agents.ForServer(ctx, serverID)"
else
  bad "A2 autoHealerAutoCleanDisk does not call ForServer — it acts on whatever agent it was handed"
fi

# A3 — the signature must not accept a bare local client (the old shape).
if has "$AH_S" "^func autoHealerAutoCleanDisk\([^)]*\*AgentRegistry"; then
  ok "A3 autoHealerAutoCleanDisk takes the *AgentRegistry, not a single AgentClient"
else
  bad "A3 autoHealerAutoCleanDisk still takes a single AgentClient — it cannot reach another host"
fi

# A4 — the spawn site (core_state.go, Rust: main.rs) must actually hand the
# healer the registry. A4 is the arm that
# fails if the fix exists but is never wired (the s297 shape).
if has "$MAIN_S" "spawnSupervised\(.*AutoHealerRun\(ctx, db, agents\)"; then
  ok "A4 core_state.go spawns AutoHealerRun WITH the registry"
else
  bad "A4 auto_healer is spawned without the registry — the fix is unreachable"
fi

# A5 — the alert_state reset must be scoped. Unscoped, healing one host cleared
# every other server's disk state and its cooldown clock.
RESET=$(flat "$(grep -A 3 "UPDATE alert_state SET current_state = 'ok'" <<< "$CLEAN" || true)")
if [ -n "$RESET" ] && has "$RESET" "WHERE server_id = \\\$1"; then
  ok "A5 the alert_state reset is scoped to the server that was healed"
else
  bad "A5 the alert_state reset is fleet-wide — it clears servers nobody healed"
fi

# A6 — an unreachable agent must be REFUSED. Falling back to the local agent is
# the defect itself, so the arm requires the refusal, not just an error branch.
if has "$CLEAN" "continue" && has "$CLEAN" "Refusing to act on a different host|NOT cleaning"; then
  ok "A6 an unreachable agent is refused rather than swapped for the local one"
else
  bad "A6 no explicit refusal when the target server's agent is unreachable"
fi

echo
echo "§B recovery completes rather than being consumed"

# B1 — resolve_alert (Go: NotificationsResolveAlert) is the ONLY writer of
# alerts.status='resolved'.
if has "$CLEAN" "NotificationsResolveAlert\("; then
  ok "B1 autoHealerAutoCleanDisk completes recovery through NotificationsResolveAlert"
else
  bad "B1 autoHealerAutoCleanDisk resets alert_state without NotificationsResolveAlert — alerts rows stay firing for ever"
fi

# B2 — the activity row must not be written with the nil uuid: that insert
# violates fk_activity_logs_user, which is what killed the cooldown.
if has "$CLEAN" "uuid\.Nil"; then
  bad "B2 autoHealerAutoCleanDisk logs activity as uuid.Nil — the insert fails and the cooldown never engages"
else
  ok "B2 autoHealerAutoCleanDisk does not log activity as the nil uuid"
fi

# B3 — and it must write SOMETHING, or the gate it reads can never be satisfied.
# Either writer satisfies that: the capability is "a row exists for the gate to
# count", not one spelling of it. Keyed on the bare `log_activity(` alone, this
# arm went red when s304 moved the call to the `_on_server` variant so the host
# could travel in `server_id` instead of squatting in `target_name` — correct
# code, red arm, which is the failure the suite header warns about. §J8 pins the
# stronger property: that this writer and its cooldown agree on the SAME key.
if has "$CLEAN" "ActivityLogActivity(OnServer)?\("; then
  ok "B3 autoHealerAutoCleanDisk still records the action it gates itself on"
else
  bad "B3 no activity record written — the cooldown query can never find a row"
fi

echo
echo "§C the reclaim cannot reach what the panel manages"

# C1 — the unscoped prune must be gone from the WHOLE tree, not just this file.
# Positive control first: the same grep must still see the scoped reclaim's own
# `"image", "prune"` call, or a zero below proves only that the walk read nothing.
PRUNE_CTL=$(grep -rn --include='*.go' -- '"image", *"prune"' panel/go 2>/dev/null | wc -l | tr -d ' ')
PRUNE_HITS=$(grep -rn --include='*.go' -- '"system", *"prune"' panel/go 2>/dev/null | grep -c -- '--volumes' || true)
if [ "$PRUNE_CTL" -lt 1 ]; then
  bad "C1 CONTROL FAILED — the tree walk found no '\"image\", \"prune\"' call at all, so its zero below proves nothing"
elif [ "$PRUNE_HITS" = "0" ]; then
  ok "C1 no 'docker system prune ... --volumes' anywhere in the tree"
else
  bad "C1 $PRUNE_HITS site(s) still run 'docker system prune --volumes' — it deletes sleeping apps"
fi

# C2 — the scoped replacement exists and is reachable by id.
if has "$DIAG_S" '"docker-reclaim"'; then
  ok "C2 the scoped docker-reclaim fix exists"
else
  bad "C2 no docker-reclaim fix — the disk heal has nothing safe to call"
fi

# The reclaim arm: from its `case` label to the next `case` of the same switch.
RECLAIM=$(awk '/^\tcase "docker-reclaim"/{f=1; print; next} f&&/^\tcase /{exit} f{print}' <<< "$DIAG_S")

# ⚠ C3 and C4 are ABSENCE arms. An absence arm over an EMPTY subject is
# vacuously true, so both printed a confident GREEN against v2.55.0 — where
# `docker-reclaim` does not exist at all — directly under a red saying the
# subject could not be extracted. That is the #143 shape (an arm that
# enumerates its own subject must assert the enumeration FIRST), and it was
# caught only by running this suite RED against the previous tag. They SKIP
# now, because "the reclaim does not reclaim volumes" is not a fact about a
# reclaim that has not been written.
if [ -z "$RECLAIM" ]; then
  skip "C3 docker-reclaim arm not extractable — no subject to measure"
  skip "C4 docker-reclaim arm not extractable — no subject to measure"
else
  # C3 — volumes are never reclaimed: an unattached volume is indistinguishable
  # from one whose container the panel stopped on purpose.
  if has "$RECLAIM" "[-][-]volumes"; then
    bad "C3 docker-reclaim passes --volumes — a slept app's data is reclaimable again"
  else
    ok "C3 docker-reclaim never reclaims volumes"
  fi

  # C4 — image prune must not be -a: -a removes images backing STOPPED
  # containers, which is exactly the slept-app case, and a locally built image
  # cannot be pulled back.
  if has "$RECLAIM" '"image", *"prune", *"-af"|"image", *"prune", *"-a"'; then
    bad "C4 docker-reclaim prunes images with -a — it takes locally built images with no registry"
  else
    ok "C4 docker-reclaim prunes only dangling images"
  fi
fi

# C5 — the OLD id must not resurrect the old behaviour for an older panel.
if has "$DIAG_S" 'case "docker-reclaim", *"docker-prune":|case "docker-prune", *"docker-reclaim":'; then
  ok "C5 the legacy docker-prune id routes to the scoped reclaim"
else
  bad "C5 docker-prune is not routed to the scoped reclaim — an older panel gets the destructive path back by name"
fi

echo
echo "§D consent is explicit and the cooldown can exist"

# D1 — the setting must be writable through the API, or the control is dead.
if has "$SET_S" '"auto_heal_docker_reclaim"'; then
  ok "D1 auto_heal_docker_reclaim is an allowed settings key"
else
  bad "D1 auto_heal_docker_reclaim is not in the allowed settings keys — the UI control cannot save"
fi

# D2 — default OFF. Requires the VALUE, not just the key (lesson #155).
# Go shape: true ONLY for a stored literal "true" — a missing row (nil) is false.
GATE=$(fnbody "$AH_S" "autoHealerReclaimEnabled")
if [ -n "$GATE" ] && has "$GATE" 'return v != nil && \*v == "true"$'; then
  ok "D2 docker reclamation defaults to OFF"
else
  bad "D2 autoHealerReclaimEnabled does not default to false — destruction is opt-OUT"
fi

# D3 — the reclaim must actually be gated on it, or the setting is decoration.
if has "$CLEAN" "autoHealerReclaimEnabled\("; then
  ok "D3 the reclaim step is gated on the operator's consent"
else
  bad "D3 the reclaim runs without consulting autoHealerReclaimEnabled"
fi

# D4 — an operator control must exist. Requires the api.put VALUE, not the word.
if has "$TSX_S" "auto_heal_docker_reclaim"; then
  ok "D4 Settings exposes a control for docker reclamation"
else
  bad "D4 no operator control for auto_heal_docker_reclaim — a DB-only switch"
fi

# D5 — the consent text must not still promise only log cleaning.
if has "$TSX_S" "Logs are cleaned when disk exceeds 90%"; then
  bad "D5 the Auto-Healing panel still claims a 90% threshold and log-only cleaning"
else
  ok "D5 the Auto-Healing consent text no longer misstates what runs"
fi

echo
echo "§E retention keeps the only record of what it did not delete"

# E1/E2 — the unlink path must match the writer, which nests per resource.
if has "$AH_S" '"/var/backups/dockpanel/databases/%s/%s", e\.C, e\.B\)' && has "$AH_S" 'SELECT id, filename, db_name, server_id FROM'; then
  ok "E1 the database retention path nests per database, as the writer does"
else
  bad "E1 the database retention path omits db_name — it unlinks a path that never exists"
fi

if has "$AH_S" '"/var/backups/dockpanel/volumes/%s/%s", e\.C, e\.B\)' && has "$AH_S" 'SELECT id, filename, container_name, server_id FROM'; then
  ok "E2 the volume retention path nests per container, as the writer does"
else
  bad "E2 the volume retention path omits container_name — it unlinks a path that never exists"
fi

# E3 — the row must not be deleted unconditionally after a discarded unlink.
if has "$AH_S" "^func autoHealerPrunePolicyBackup\("; then
  ok "E3 policy retention goes through a single guarded retire step"
else
  bad "E3 no autoHealerPrunePolicyBackup — the DELETE is not guarded by the unlink result"
fi

# E4 retired: covered by TestPinUnattendedHostScopePrunePolicyBackupKeepsRowOnFailedUnlink (panel/go/internal/api/pin_unattended_host_scope_test.go)
# E5 retired: covered by TestPinUnattendedHostScopePrunePolicyBackupRefusesOtherServer (panel/go/internal/api/pin_unattended_host_scope_test.go)

# E6 — retention must be per resource. OFFSET over a policy's whole history kept
# n backups in TOTAL across every database it covered.
if has "$AH_S" "PARTITION BY database_id" && has "$AH_S" "PARTITION BY container_id"; then
  ok "E6 policy retention_count is applied per resource, not per policy"
else
  bad "E6 policy retention still uses a policy-wide OFFSET — most resources keep zero backups"
fi

# E7–E9 (s370) — THE THIRD SIBLING. §E was written for the two POLICY sweeps and
# the SITE sweep (backup_schedules → backups) was left with neither guard: it
# unlinked a local path, discarded the result, and deleted the row anyway. The
# rule, the helper and this very section all existed; nothing asserted the third
# caller. On a fleet install every site backup living on a member host had its
# only record destroyed while the archive stayed on that host — and `total_pruned`
# counted it, so the log reported archives it had never touched.
RC_S=$(fnbody "$AH_S" "autoHealerRunRetentionCleanup")
if [ -n "$RC_S" ]; then
  # E7 — all THREE sweeps must retire through the one guarded step.
  PPB_CALLS=$(count "$RC_S" 'autoHealerPrunePolicyBackup\(')
  if [ "$PPB_CALLS" -ge 3 ]; then
    ok "E7 all three retention sweeps retire through the guarded step ($PPB_CALLS call sites)"
  else
    bad "E7 only $PPB_CALLS of 3 retention sweeps are guarded — one deletes rows on its own"
  fi

  # E8 — the site sweep must NAME THE HOST. `backups` carries no server of its
  # own, so the owning host is the site's: the join must select it, not just the
  # domain it needs for the path.
  if has "$RC_S" 's\.server_id'; then
    ok "E8 the site retention sweep selects the owning server, not just the domain"
  else
    bad "E8 the site sweep joins sites without server_id — it cannot tell whose host the archive is on"
  fi

  # E9 — ABSENCE arm: no sweep may delete a backups row directly again.
  # Positive control first: an absence arm with no control cannot tell "clean"
  # from "the pattern never ran" (#480). `DELETE FROM ` must still match the
  # several unguarded purges in this function that are legitimately direct
  # (token_blacklist, notifications, terminal shares).
  DEL_ANY=$(count "$RC_S" 'DELETE FROM ')
  if [ "$DEL_ANY" -lt 1 ]; then
    bad "E9 CONTROL FAILED — 'DELETE FROM ' matched nothing, so the absence arm below proves nothing"
  elif has "$RC_S" 'DELETE FROM backups WHERE id'; then
    bad "E9 a backups row is deleted directly again, bypassing the remote-host guard"
  else
    ok "E9 no direct DELETE of a backups row ($DEL_ANY other purges still matched — control non-vacuous)"
  fi
else
  skip "E7/E8/E9 — autoHealerRunRetentionCleanup body not extractable"
fi

echo
echo "§F the scheduled and webhook paths name the host too (s299)"

DEPS=$API/svc_deploy_scheduler.go
PREV=$API/svc_preview_cleanup.go
GITD=$API/rt_git_deploys.go
DEPR=$API/rt_deploy.go
MET=$API/svc_metrics_collector.go

for f in "$DEPS" "$PREV" "$GITD" "$DEPR" "$MET"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

DEPS_S=$(subj "$DEPS" || true)
PREV_S=$(subj "$PREV" || true)
GITD_S=$(subj "$GITD" || true)
DEPR_S=$(subj "$DEPR" || true)
MET_S=$(subj "$MET" || true)

# F1/F2 — the scheduler's two fleet-wide SELECTs must name the server. Both were
# `SELECT id, name, ... FROM git_deploys` with no server_id at all, so the row
# could not say which machine it meant even in principle.
if [ -n "$DEPS_S" ]; then
  SCHED=$(fnbody "$DEPS_S" "deploySchedulerCheckSchedules")
  if [ -z "$SCHED" ]; then
    skip "F1/F2/F14/F15 — deploySchedulerCheckSchedules body not extractable"
  else
    if [ "$(count "$SCHED" "SELECT[^;]*server_id[^;]*FROM git_deploys")" -ge 2 ]; then
      ok "F1/F2 both scheduler queries (cron + one-time) select server_id"
    else
      bad "F1/F2 a scheduler query still reads git_deploys without server_id — the row cannot name its host"
    fi

    # F14 — the one-time clear is the ONLY thing between a scheduled deploy and
    # an unbounded redeploy loop: a successful run leaves the row 'running',
    # which the one-time SELECT does not exclude. It used to be swallowed
    # with `.ok()` (Rust); the Go port checks both the error and rows affected.
    if has "$SCHED" 'n, err := execSQL\(ctx, db, "UPDATE git_deploys SET scheduled_deploy_at = NULL' && has "$SCHED" 'if n != 1 \{'; then
      ok "F14 the one-time schedule clear is checked before deploying"
    else
      bad "F14 the one-time schedule clear is unchecked — an uncleared row redeploys every tick"
    fi

    # F15 — reachability BEFORE the clear. Clearing first discards the
    # operator's only copy of a one-time instruction for a server we then
    # decline to deploy to. Order matters, so measure the order.
    F15_RESOLVE=$(grep -n "agents\.ForServer(" <<< "$SCHED" | head -1 | cut -d: -f1)
    F15_CLEAR=$(grep -n "scheduled_deploy_at = NULL" <<< "$SCHED" | head -1 | cut -d: -f1)
    if [ -n "$F15_RESOLVE" ] && [ -n "$F15_CLEAR" ] && [ "$F15_RESOLVE" -lt "$F15_CLEAR" ]; then
      ok "F15 the one-time path checks the server is reachable BEFORE clearing the schedule"
    else
      bad "F15 the one-time schedule is cleared before the server is known reachable — an unreachable member loses it silently"
    fi
  fi
else
  skip "F1/F2/F14/F15 — svc_deploy_scheduler.go not extractable"
fi

# F3/F4/F5 — trigger_deploy_task (Go: rtGitDeploysTriggerDeployTask) is where
# the host was decided. It took an AgentClient and wrapped it
# `AgentHandle::Local(agent)` three lines before fetching the row that carries
# server_id. The Go shape of forcing the local agent is `.Local()` / `st.Agent`.
if [ -n "$GITD_S" ]; then
  TDT=$(fnbody "$GITD_S" "rtGitDeploysTriggerDeployTask")
  if [ -z "$TDT" ]; then
    skip "F3/F4/F5 — rtGitDeploysTriggerDeployTask body not extractable"
  else
    if has "$TDT" '\.Local\(\)|st\.Agent[^s]'; then
      bad "F3 rtGitDeploysTriggerDeployTask still forces the LOCAL agent — every scheduled deploy runs on the panel host"
    else
      ok "F3 rtGitDeploysTriggerDeployTask no longer forces the local agent"
    fi

    if has "$TDT" "agents\.ForServer\(ctx, config\.ServerID\)"; then
      ok "F4 rtGitDeploysTriggerDeployTask resolves the agent from the ROW's own server_id"
    else
      bad "F4 rtGitDeploysTriggerDeployTask does not resolve agents.ForServer(ctx, config.ServerID)"
    fi

    # The refusal must be a refusal: an early return, not a fallback.
    if has "$TDT" "Refusing to act on a different host"; then
      ok "F5 an unreachable deploy server is refused, never swapped for the local one"
    else
      bad "F5 rtGitDeploysTriggerDeployTask has no explicit refusal when the server is unreachable"
    fi
  fi
else
  skip "F3/F4/F5 — rt_git_deploys.go not extractable"
fi

# F6/F7 — the spawn sites. A migration is not done when the callee is done
# (lesson #156): grep the SPAWN, not just the call.
if [ -n "$MAIN_S" ]; then
  if has "$MAIN_S" "spawnSupervised\(.*DeploySchedulerRun\(ctx, db, agents\)"; then
    ok "F6 core_state.go spawns DeploySchedulerRun with the REGISTRY"
  else
    bad "F6 deploy_scheduler is still spawned with the legacy single-agent handle"
  fi
  if has "$MAIN_S" "spawnSupervised\(.*PreviewCleanupRun\(ctx, db, agents\)"; then
    ok "F7 core_state.go spawns PreviewCleanupRun with the REGISTRY"
  else
    bad "F7 preview_cleanup is still spawned with the legacy single-agent handle"
  fi
else
  skip "F6/F7 — core_state.go not extractable"
fi

# F8/F9 — preview teardown. git_previews carries its own server_id since
# 20260818000000, but the sweep still reads the deploy's copy through the JOIN —
# that is the one the teardown's authority derives from, and this arm pins it.
if [ -n "$PREV_S" ]; then
  if [ "$(count "$PREV_S" "d\.server_id")" -ge 2 ]; then
    ok "F8 both preview sweeps carry the git deploy's server_id through the JOIN"
  else
    bad "F8 a preview sweep still selects rows that cannot name their host"
  fi
  if has "$PREV_S" "agents\.ForServer\(" && has "$PREV_S" "Refusing to act on a different host"; then
    ok "F9 preview teardown resolves that server and refuses when unreachable"
  else
    bad "F9 preview teardown still tears down containers on whichever host the panel runs on"
  fi
else
  skip "F8/F9 — svc_preview_cleanup.go not extractable"
fi

# F10 — the git-deploy webhook. Unauthenticated by design (it carries a secret,
# not a session), so it has no ServerScope and reached for the local agent.
if [ -n "$GITD_S" ]; then
  WH=$(fnbody "$GITD_S" "rtGitDeploysWebhook")
  if [ -z "$WH" ]; then
    skip "F10 — rtGitDeploysWebhook body not extractable"
  elif has "$WH" "Agents\.ForServer\(ctx, config\.ServerID\)" && ! has "$WH" '\.Local\(\)|st\.Agent[^s]'; then
    ok "F10 the git-deploy webhook deploys on the server the deployment lives on"
  else
    bad "F10 a webhook push still builds and replaces containers on the panel host"
  fi
else
  skip "F10 — rt_git_deploys.go not extractable"
fi

# F11 — the SITE deploy webhook, same shape, different file. sites.server_id is
# NOT NULL, and the handler used to select only `domain`.
if [ -n "$DEPR_S" ]; then
  if has "$DEPR_S" "SELECT domain, server_id FROM sites" && has "$DEPR_S" "Agents\.ForServer\(ctx, siteServerID\)"; then
    ok "F11 the site webhook resolves the site's own server"
  else
    bad "F11 the site webhook still deploys a remote tenant's site onto the panel host"
  fi
else
  skip "F11 — rt_deploy.go not extractable"
fi

# F12 — the guard that makes all of the above safe on a SINGLE-server install.
# `AgentEnsureLocalServer` returns uuid.Nil until an admin exists, so the cached
# local id can be nil; the local row has no agent_url, so the DB fallthrough
# would return NotFound and every threaded service would refuse to act on its
# own box. This arm is the difference between a fix and an outage.
if [ -n "$AGENT_S" ]; then
  FS=$(fnbody "$AGENT_S" "ForServer")
  if [ -z "$FS" ]; then
    skip "F12 — ForServer body not extractable"
  elif has "$(flat "$FS")" 'case rw\.IsLocal: return r\.local, nil' && has "$FS" 'SELECT agent_url, agent_token, cert_fingerprint, is_local FROM servers'; then
    ok "F12 ForServer returns the LOCAL handle for the local row even when the cached id is unset"
  else
    bad "F12 ForServer cannot recognise the local server from the DB — a single-server install would refuse every threaded action"
  fi
else
  skip "F12 — svc_agent.go not extractable"
fi

# F13 — the laundering step. The server_id a reading is stored under decides
# which machine every downstream threshold and heal is about.
#
# ⚠ RE-POINTED at s302, and the reason is the point. This arm used to require the
# literal `FROM servers WHERE is_local = true` INSIDE the collector, because s299
# fixed the laundering by making that one lookup ask for the right row. s302
# removed the lookup altogether: the collector now iterates `online_fleet` (Go:
# agents.OnlineFleet) and
# takes each id from the member it just read, so there is no single "local" id to
# derive and the whole class of derivation is gone. The property is unchanged and
# is now stronger; only its home moved. Per lesson #150 a re-pointed arm owes a
# companion proving the caller still REACHES the new home — F13c below — or a
# resolver nothing calls would satisfy it.
if [ -n "$MET_S" ]; then
  if has "$(stmt "$MET_S" 'INSERT INTO metrics_history' 1)" 'server_id\) VALUES .*disk, m\.ID\)'; then
    ok "F13 metrics_collector labels each reading with the server it was read from"
  else
    bad "F13 metrics_collector does not stamp readings per member — readings can be stored against the wrong machine"
  fi
  if has "$MET_S" "ORDER BY created_at ASC LIMIT 1"; then
    bad "F13b the oldest-row derivation is still present in metrics_collector"
  else
    ok "F13b the oldest-row derivation is gone"
  fi
  if has "$MET_S" 'agents\.OnlineFleet\(ctx\)'; then
    ok "F13c the collector actually reaches the fleet primitive it takes its ids from"
  else
    bad "F13c the collector never calls OnlineFleet — F13's ids come from somewhere unproven"
  fi
else
  skip "F13 — svc_metrics_collector.go not extractable"
fi

# F13d — and the primitive those ids come from must not itself launder. This is
# the assertion that moved out of the collector: whoever resolves "which server"
# must not do it by row age.
if [ -n "$AGENT_S" ]; then
  OF=$(flat "$(fnbody "$AGENT_S" "OnlineFleet")")
  if [ -z "$OF" ]; then
    bad "F13d could not extract OnlineFleet — the arm measured nothing"
  elif has "$OF" 'ORDER BY created_at'; then
    bad "F13d OnlineFleet orders the fleet by row age — the laundering moved rather than left"
  elif has "$OF" 'is_local'; then
    ok "F13d OnlineFleet resolves each server by identity, never by row age"
  else
    bad "F13d OnlineFleet does not name is_local — nothing distinguishes the panel row while iterating"
  fi
else
  skip "F13d — svc_agent.go not extractable"
fi


echo
echo "§G the last background services name their host (s300 backups + s301 scanners)"

# s300 threaded the backup family and landed with NO arms at all; s301 finished
# the scanners. Both are pinned here, because the two halves share one hazard:
# a fix that POPULATES a column is the first thing that ever runs the mechanisms
# written against it, and those mechanisms have never been exercised.
BS=$API/svc_backup_scheduler.go
BPE=$API/svc_backup_policy_executor.go
BV=$API/svc_backup_verifier.go
DS=$API/svc_drill_scheduler.go
TC=$API/svc_telemetry_collector.go
BO=$API/rt_backup_orchestrator.go
SS=$API/svc_security_scanner.go
SSR=$API/rt_security_scans.go
IS=$API/svc_image_scanner.go
ISR=$API/rt_image_scans.go
SB=$API/rt_sboms.go
AE=$API/svc_alert_engine.go

for f in "$BS" "$BPE" "$BV" "$DS" "$TC" "$BO" "$SS" "$SSR" "$IS" "$ISR" "$SB" "$AE"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

BS_S=$(subj "$BS" || true);   BPE_S=$(subj "$BPE" || true); BV_S=$(subj "$BV" || true)
DS_S=$(subj "$DS" || true);   TC_S=$(subj "$TC" || true);   BO_S=$(subj "$BO" || true)
SS_S=$(subj "$SS" || true);   SSR_S=$(subj "$SSR" || true); IS_S=$(subj "$IS" || true)
ISR_S=$(subj "$ISR" || true); SB_S=$(subj "$SB" || true);   AE_S=$(subj "$AE" || true)

# ── the backup family (s300) ───────────────────────────────────────────────
if [ -n "$BS_S" ]; then
  if has "$(sig "$BS_S" BackupSchedulerRun)" "\*AgentRegistry" && has "$BS_S" "agents\.ForServer\("; then
    ok "G1 backup_scheduler resolves each site's own server"
  else
    bad "G1 backup_scheduler still backs up every site through one agent"
  fi
else
  skip "G1 — svc_backup_scheduler.go not extractable"
fi

if [ -n "$BPE_S" ]; then
  if has "$BPE_S" "agents\.ForServer\(" && has "$(sig "$BPE_S" BackupPolicyExecutorRun)" "\*AgentRegistry"; then
    ok "G2 backup_policy_executor resolves the host per row"
  else
    bad "G2 backup_policy_executor still writes every policy backup to the panel"
  fi
else
  skip "G2 — svc_backup_policy_executor.go not extractable"
fi

if [ -n "$BV_S" ]; then
  if has "$BV_S" "agents\.ForServer\(" && has "$(sig "$BV_S" BackupVerifierRun)" "\*AgentRegistry"; then
    ok "G3 backup_verifier reads each archive on the host that wrote it"
  else
    bad "G3 backup_verifier still verifies every archive on the panel"
  fi
else
  skip "G3 — svc_backup_verifier.go not extractable"
fi

# G4 — the #164 arm for the backup half. Populating drill_scheduler's server_id
# ARMS a per-server concurrency guard that has never once engaged, and the db
# drill INSERTs a 'running' row immediately before the volume drill counts them.
# Without an age bound one stranded row disables DR for that machine for ever.
if [ -n "$DS_S" ]; then
  GUARD=$(fnbody "$DS_S" "drillSchedulerHasRunningDrillForServer")
  if [ -z "$GUARD" ]; then
    skip "G4 — drillSchedulerHasRunningDrillForServer not extractable"
  elif has "$GUARD" "started_at > NOW\(\) - INTERVAL"; then
    ok "G4 the drill concurrency guard is age-bounded, so one stranded drill cannot disable DR for ever"
  else
    bad "G4 the drill guard has no age bound — arming it makes a crashed drill permanent"
  fi
else
  skip "G4 — svc_drill_scheduler.go not extractable"
fi

# G5 — telemetry_collector is local BY INTENT. The arm requires that intent to be
# STATED (it takes the registry and asks it for the local agent), not merely to
# coincide with a legacy handle nobody revisited.
if [ -n "$TC_S" ]; then
  if has "$(sig "$TC_S" TelemetryCollectorRun)" "\*AgentRegistry" && has "$TC_S" "agents\.Local\(\)"; then
    ok "G5 telemetry_collector states local-by-intent through the registry"
  else
    bad "G5 telemetry_collector's locality is an accident of the legacy handle again"
  fi
else
  skip "G5 — svc_telemetry_collector.go not extractable"
fi

# G6 — the laundering shape (s299's metrics_collector defect, verbatim): resolve
# the real server, discard it, then stamp the row from an arbitrary online row.
# Positive anchor: the file must still resolve hosts at all, or the absence
# below is a fact about an empty subject.
if [ -n "$BO_S" ] && ! has "$BO_S" "agentForSiteServer\("; then
  bad "G6 backup_orchestrator no longer resolves a server at all — the absence arm below proves nothing"
elif [ -n "$BO_S" ]; then
  if has "$BO_S" "FROM servers WHERE status = 'online' LIMIT 1"; then
    bad "G6 backup_orchestrator still stamps server_id from an arbitrary online server"
  else
    ok "G6 the arbitrary-online-server stamp is gone from backup_orchestrator"
  fi
else
  skip "G6 — rt_backup_orchestrator.go not extractable"
fi

# ── the scanners (s301) ────────────────────────────────────────────────────
# G7/G8 — both scanners take a MACHINE as their subject, so the arm requires the
# fleet LOOP, not merely a registry in the signature.
if [ -n "$SS_S" ]; then
  if has "$(sig "$SS_S" SecurityScannerRun)" "\*AgentRegistry" && has "$SS_S" "agents\.OnlineFleet\(ctx\)"; then
    ok "G7 security_scanner sweeps the fleet instead of the panel alone"
  else
    bad "G7 security_scanner still scans only the panel host — members are never scanned at all"
  fi
else
  skip "G7 — svc_security_scanner.go not extractable"
fi

if [ -n "$IS_S" ]; then
  if has "$(sig "$IS_S" ImageScannerRun)" "\*AgentRegistry" && has "$IS_S" "agents\.OnlineFleet\(ctx\)"; then
    ok "G8 image_scanner sweeps the fleet instead of the panel alone"
  else
    bad "G8 image_scanner still sweeps only the panel's images"
  fi
else
  skip "G8 — svc_image_scanner.go not extractable"
fi

if [ -n "$MAIN_S" ]; then
  for pair in "SecurityScannerRun:G9" "ImageScannerRun:G10" "AlertEngineRun:G11"; do
    svc=${pair%%:*}; id=${pair##*:}
    if has "$MAIN_S" "spawnSupervised\(.*${svc}\(ctx, db, agents\)"; then
      ok "$id core_state.go spawns $svc with the REGISTRY"
    else
      bad "$id $svc is still spawned with the legacy single-agent handle — the fix exists but is never wired"
    fi
  done
else
  skip "G9/G10/G11 — core_state.go not extractable"
fi

# G12 — THE arming arm. The upsert's arbiter named a column the INSERT never
# supplied, and a NULL never conflict-matches, so DO UPDATE had never executed:
# the file-integrity alarm saw the FIRST change to a watched file and was deaf
# to every change after it. Key on the INSERT's column list, since the ON
# CONFLICT clause was already correct and is not what was broken.
for pair in "SS_S:G12a:security_scanner" "SSR_S:G12b:the manual trigger route"; do
  var=${pair%%:*}; rest=${pair#*:}; id=${rest%%:*}; who=${rest##*:}
  src=${!var}
  if [ -z "$src" ]; then skip "$id — subject not extractable"; continue; fi
  INS=$(stmt "$src" 'INSERT INTO file_integrity_baselines' 2)
  if [ -z "$INS" ]; then
    skip "$id — baseline INSERT not found in $who"
  elif has "$INS" 'file_integrity_baselines \(server_id, file_path'; then
    ok "$id the baseline upsert in $who supplies server_id, so ON CONFLICT can match"
  else
    bad "$id the baseline upsert in $who still omits server_id — DO UPDATE can never fire"
  fi
done

# G13 — the comparison read. `server_id IS NULL` was not a filter but the absence
# of one; once the column is real it matches nothing and the alarm goes SILENT.
# Both halves of the change have to move together or the mechanism flips from
# always-false-positive to always-quiet.
for pair in "SS_S:G13a:security_scanner" "SSR_S:G13b:the manual trigger route"; do
  var=${pair%%:*}; rest=${pair#*:}; id=${rest%%:*}; who=${rest##*:}
  src=${!var}
  if [ -z "$src" ]; then skip "$id — subject not extractable"; continue; fi
  if has "$(stmt "$src" 'FROM file_integrity_baselines' 2)" 'server_id IS NULL'; then
    bad "$id the baseline comparison in $who still reads the NULL bucket — it will match nothing"
  else
    ok "$id the baseline comparison in $who is keyed by server"
  fi
done

# G14 — the cadence gate. Fleet-wide, the first host scanned satisfied it for
# every other host; counting rows of ANY status meant one failed scan bought a
# whole week of no security scanning.
if [ -n "$SS_S" ]; then
  GATE=$(stmt "$SS_S" 'SELECT COUNT\(\*\) FROM security_scans')
  if [ -z "$GATE" ]; then
    skip "G14 — cadence gate not extractable"
  elif has "$GATE" 'server_id = \$1' && has "$GATE" "status = 'completed'"; then
    ok "G14 the weekly gate is per server and only a COMPLETED scan satisfies it"
  else
    bad "G14 the weekly cadence gate is still fleet-wide or still counts failed scans"
  fi
else
  skip "G14 — svc_security_scanner.go not extractable"
fi

# G15 — the scan record itself. This route resolved the correct agent and threw
# the id away: the s299 laundering shape, in an HTTP handler.
if [ -n "$SSR_S" ]; then
  if has "$(stmt "$SSR_S" 'INSERT INTO security_scans' 1)" 'security_scans \(server_id, scan_type'; then
    ok "G15 the manual scan route records the host it scanned"
  else
    bad "G15 the manual scan route still files every member's scan under no server"
  fi
else
  skip "G15 — rt_security_scans.go not extractable"
fi

# G16 — the readers. If these keep reading the NULL bucket while the writers
# start binding, the Security page empties out and the posture card disappears.
if [ -n "$SSR_S" ]; then
  READS=$(stmt "$SSR_S" 'FROM security_scans' 2)
  NULLREADS=$(count "$READS" 'server_id IS NULL')
  if [ -z "$READS" ]; then
    bad "G16 no security_scans reader found — the absence arm below proves nothing"
  elif [ "$NULLREADS" -eq 0 ]; then
    ok "G16 no security_scans reader is still pinned to the NULL bucket"
  else
    bad "G16 $NULLREADS security_scans reader(s) still filter server_id IS NULL — the scan history will read empty"
  fi
else
  skip "G16 — rt_security_scans.go not extractable"
fi

# G17 — the image write + its retention. An unscoped 30-row trim makes a busy
# host evict a quiet host's ONLY row, so a scanned server's badge goes blank.
if [ -n "$ISR_S" ]; then
  if has "$(stmt "$ISR_S" 'INSERT INTO image_scan_findings')" '\(server_id, image, scanner'; then
    ok "G17a image scan results record the host that produced them"
  else
    bad "G17a image scan results are still stored keyed on the bare image"
  fi
  TRIM=$(stmt "$ISR_S" 'DELETE FROM image_scan_findings' 2)
  if [ -z "$TRIM" ]; then
    skip "G17b — history trim not extractable"
  elif has "$TRIM" 'server_id = \$1'; then
    ok "G17b the 30-row history trim is per (server, image)"
  else
    bad "G17b the history trim is still per image — one host evicts another's only result"
  fi
else
  skip "G17 — rt_image_scans.go not extractable"
fi

# G18 — the deploy gate. The scan that decides has to be a scan of the machine
# that will run the image; reading by image alone let a clean scan on one host
# wave a vulnerable image onto another.
if [ -n "$ISR_S" ]; then
  # s369: the gate was split so every door that runs an image can call it, and
  # the scan lookup moved into `preflight_gate_image` (Go:
  # rtImageScansPreflightGateImage). The arm follows the code
  # to where the query now lives — and G18b below pairs with it, asserting the
  # original entry point still REACHES it, which is the half that stops a
  # follow-the-code repoint from quietly measuring nothing (lesson #150).
  GATE=$(fnbody "$ISR_S" "rtImageScansPreflightGateImage")
  if [ -z "$GATE" ]; then
    skip "G18 — rtImageScansPreflightGateImage not extractable"
  elif has "$GATE" 'serverID uuid\.UUID' && has "$GATE" 'server_id = \$1'; then
    ok "G18 the deploy gate reads a scan of the deploy TARGET"
  else
    bad "G18 the deploy gate still reads whichever host scanned that image last"
  fi
  ENTRY=$(fnbody "$ISR_S" "rtImageScansPreflightGate")
  if [ -z "$ENTRY" ]; then
    skip "G18b — rtImageScansPreflightGate not extractable"
  elif has "$ENTRY" 'rtImageScansPreflightGateImage\(ctx, db, serverID'; then
    ok "G18b the template entry point still reaches the scoped gate"
  else
    bad "G18b rtImageScansPreflightGate no longer calls rtImageScansPreflightGateImage — G18 is measuring a function nothing calls"
  fi
else
  skip "G18 — rt_image_scans.go not extractable"
fi

# G19 — the badge feed. This was the one handler in its module with no scope at
# all, and the client keys its response by image, so a fleet-wide DISTINCT ON
# collapsed every host's result into one with no duplicate and no error.
if [ -n "$ISR_S" ]; then
  LR=$(fnbody "$ISR_S" "rtImageScansListRecent")
  if [ -z "$LR" ]; then
    skip "G19 — rtImageScansListRecent not extractable"
  elif has "$LR" "serverID, _, err := st\.serverScope\(r\)" && has "$LR" 'server_id = \$1'; then
    ok "G19 the Apps badge feed is server-scoped"
  else
    bad "G19 rtImageScansListRecent is still fleet-wide — badges collapse across hosts, last writer wins"
  fi
else
  skip "G19 — rt_image_scans.go not extractable"
fi

# G20 — THE 42P10 ARM, and the reason this migration and this writer are one
# change. An ON CONFLICT arbiter that matches no unique index does not degrade:
# Postgres raises 42P10 at EXECUTION time, so a composite key shipped without
# this edit turns every SBOM generation into a 500. Verified by running the old
# statement against the migrated schema.
if [ -n "$SB_S" ]; then
  UP=$(stmt "$SB_S" 'INSERT INTO image_sbom' 4)
  if [ -z "$UP" ]; then
    skip "G20 — SBOM upsert not extractable"
  elif has "$UP" 'ON CONFLICT \(server_id, image\)'; then
    ok "G20 the SBOM upsert's arbiter names the composite key the table actually has"
  else
    bad "G20 the SBOM upsert names an arbiter with no matching unique index — every generate 500s (42P10)"
  fi
else
  skip "G20 — rt_sboms.go not extractable"
fi

# G21 — alert_engine's three AGENT-driven checks. Its DB-driven checks were
# already per-server; only the ones that ask a machine what it has were blind.
if [ -n "$AE_S" ]; then
  OLDEST=$(count "$AE_S" 'FROM servers ORDER BY created_at ASC LIMIT 1')
  if ! has "$AE_S" 'FROM servers'; then
    bad "G21 alert_engine reads no servers rows at all — the absence below proves nothing"
  elif [ "$OLDEST" -eq 0 ]; then
    ok "G21 the oldest-row 'local server' derivation is gone from alert_engine"
  else
    bad "G21 alert_engine still derives 'the local server' by row age in $OLDEST place(s)"
  fi
  if has "$AE_S" "agents\.OnlineFleet\(ctx\)" && has "$AE_S" "alertEngineCheckContainerHealth\(ctx, db, member\)"; then
    ok "G22 alert_engine runs its agent-driven checks once per online server"
  else
    bad "G22 alert_engine still asks the panel's agent and labels the answer with another server"
  fi
else
  skip "G21/G22 — svc_alert_engine.go not extractable"
fi

# G23 — the corollary arm (#164): two bugs that cancel are two bugs. alert_engine
# mislabelled the row and the healer ignored the label, so the restart landed on
# the right host BY ACCIDENT. Correct ids end the accident, which is why this
# must be true in the same commit as G22 and not one release later.
if [ -n "$AH_S" ]; then
  RESTART=$(fnbody "$AH_S" "autoHealerAutoRestartServices")
  if [ -z "$RESTART" ]; then
    skip "G23 — autoHealerAutoRestartServices not extractable"
  else
    if has "$RESTART" "agents\.ForServer\(" && has "$(sig "$AH_S" autoHealerAutoRestartServices)" "\*AgentRegistry"; then
      ok "G23 autoHealerAutoRestartServices restarts a service on the host it died on"
    else
      bad "G23 autoHealerAutoRestartServices still posts every restart to the local agent"
    fi
    UNSCOPED=$(count "$RESTART" "alert_type = 'service_down'")
    SCOPED=$(count "$RESTART" 'server_id = \$1')
    if [ "$UNSCOPED" -gt 0 ] && [ "$SCOPED" -ge 3 ]; then
      ok "G24 its alert_state reads and writes are scoped to the server ($SCOPED predicates)"
    else
      bad "G24 alert_state statements in autoHealerAutoRestartServices are still fleet-wide (scoped=$SCOPED)"
    fi
    if has "$RESTART" 'target_name = \$1 AND server_id = \$2'; then
      ok "G25 the restart cooldown counts attempts on THIS server"
    else
      bad "G25 the cooldown is still keyed on the bare service name — two hosts share one budget"
    fi
    if has "$RESTART" "ActivityLogActivityOnServer\(" && ! has "$RESTART" "uuid\.Nil"; then
      ok "G26 the heal is recorded against the server's owner, so the cooldown row can exist at all"
    else
      bad "G26 the heal record still uses the nil uuid — it violates the user FK, so the cooldown stays dead"
    fi
    # G27 — the field names. A missing JSON field reads as an empty string, so
    # asking for the wrong one fails silently and for ever. The agent's payload
    # carries `status` and `container_id`; the alert engine reads the correct
    # name for the same payload 900 lines away in the same subsystem.
    if has "$RESTART" 'Agent\.Get\(ctx, "/apps"\)' && has "$RESTART" 'jsonGet\(c, "container_id"\)' \
       && has "$RESTART" 'jsonGet\(c, "status"\)' && ! has "$RESTART" 'jsonGet\(c, "state"\)'; then
      ok "G27 the container leg reads the field names the agent actually sends"
    else
      bad "G27 the container leg still reads fields the /apps payload has never had — it can never fire"
    fi
  fi
else
  skip "G23–G27 — svc_auto_healer.go not extractable"
fi

# G28 — the NEGATIVE arm, and the reason it runs over STRIPPED source. The
# registry offers an Option-taking resolver that answers a missing id with the
# LOCAL agent, silently; no background service may use it. Two subjects carry
# comments that spell the name precisely to say they are NOT using it, so an arm
# over raw source would fire on the prose narrating the decision — the #149 trap,
# and the reason `subj` is used here rather than the file.
# Background services are the svc_*.go files (non-test) of the flat api package.
BG_FILES=$(find "$API" -maxdepth 1 -name 'svc_*.go' ! -name '*_test.go' -type f 2>/dev/null | sort)
BG_COUNT=$(grep -c '\.go$' <<< "$BG_FILES" || true)
if [ "${BG_COUNT:-0}" -lt 10 ]; then
  bad "G28 only $BG_COUNT service files enumerated — the absence arm below cannot mean anything"
elif ! has "$AGENT_S" '^func \(r \*AgentRegistry\) ForServerOrLocal\('; then
  bad "G28 ForServerOrLocal is no longer defined in svc_agent.go — the pattern below matches nothing by construction; re-point it"
else
  OFFENDERS=0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ "$f" = "$API/svc_agent.go" ] && continue
    if grep -qE -- '\.ForServerOrLocal\(' <<< "$(code "$f")"; then
      bad "G28 $f calls the resolver that silently substitutes the local agent"
      OFFENDERS=$((OFFENDERS+1))
    fi
  done <<< "$BG_FILES"
  if [ "$OFFENDERS" -eq 0 ]; then
    ok "G28 no background service resolves its agent through the silently-local convenience path ($BG_COUNT files)"
  fi
fi

echo
echo "§H the panel host is watched too, and the legacy handle has an allow-list (s302)"

# The class this section pins is the one the previous four releases each fixed an
# instance of without ever stating: a check whose driving data is written by only
# ONE kind of host is structurally blind to the other kind. Two stores were
# involved. The scalar columns on `servers` are written only by the check-in
# handler, which only a phoning-home MEMBER reaches, so the panel's own row was
# NULL for ever and its cpu/memory/disk thresholds never evaluated. The history
# table was written only against the local id, so no member had a trend alert, an
# uptime sparkline or a scrape series.
#
# H5 is the arm that matters most and the one nobody had: it is a CLASS arm over
# the SPAWN SITES, not a per-service arm. Four releases in a row shipped a
# per-defect arm and left a sibling on the legacy handle; an allow-list of one
# goes red the moment a new service joins it, or an old one is missed.
MC=$API/svc_metrics_collector.go
SM=$API/svc_server_monitor.go
MN=$API/core_state.go
AG=$API/svc_agent.go

for f in "$MC" "$SM" "$MN" "$AG"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

MC_S=$(subj "$MC" || true); SM_S=$(subj "$SM" || true)
MN_S=$(subj "$MN" || true); AG_S=$(subj "$AG" || true)

# H1 — the collector takes the REGISTRY. Keyed on the flattened signature: a
# parameter list can wrap, and a line-oriented `has` over raw source measures nothing
# (lesson #168 — and as a PRESENCE arm this fails loudly rather than green).
if [ -n "$MC_S" ]; then
  MC_RUN=$(sig "$MC_S" "MetricsCollectorRun")
  if has "$MC_RUN" '\*AgentRegistry'; then
    ok "H1 MetricsCollectorRun takes the *AgentRegistry"
  else
    bad "H1 MetricsCollectorRun does not take the AgentRegistry — it cannot reach any host but its own"
  fi
else
  skip "H1 — svc_metrics_collector.go not extractable"
fi

# H2 — and actually iterates it.
if [ -n "$MC_S" ]; then
  if has "$MC_S" 'agents\.OnlineFleet\(ctx\)'; then
    ok "H2 metrics_collector iterates the online fleet"
  else
    bad "H2 metrics_collector never iterates the fleet — members get no history rows"
  fi
else
  skip "H2 — svc_metrics_collector.go not extractable"
fi

# H3 — every history row is stamped with the server it was READ FROM. The defect
# shape was a single lookup of the local id bound into every insert, so the arm
# asserts that lookup is gone from this subject AND that a per-member id is bound.
if [ -n "$MC_S" ]; then
  if has "$MC_S" 'is_local = true'; then
    bad "H3 metrics_collector still resolves one 'local' id — every reading lands on that one server"
  elif has "$(stmt "$MC_S" 'INSERT INTO metrics_history' 1)" 'server_id\) VALUES .*disk, m\.ID\)'; then
    ok "H3 metrics_collector stamps each reading with the server it was read from"
  else
    bad "H3 metrics_collector binds no per-member id to its history writes"
  fi
else
  skip "H3 — svc_metrics_collector.go not extractable"
fi

# H4 — the panel row's scalar columns get a writer at last. Flattened: the UPDATE
# is a multi-line SQL string literal, so a line-oriented match would find only its
# first fragment.
if [ -n "$MC_S" ]; then
  MC_UPD=$(flat "$MC_S")
  if has "$MC_UPD" 'UPDATE servers SET .*cpu_usage = \$2' && has "$MC_S" 'if m\.IsLocal \{'; then
    ok "H4 the local server's scalar columns are written by the collector"
  else
    bad "H4 nothing writes the panel row's cpu/memory/disk — its thresholds can never evaluate"
  fi
else
  skip "H4 — svc_metrics_collector.go not extractable"
fi

# H5 — THE CLASS ARM. NO spawn may hold the legacy single-agent handle.
#
# This arm used to allow exactly one, and named it: the healer, "whose SSL and
# auto-sleep legs are a recorded remainder". That remainder was the defect. Held
# on the panel own handle, `auto_renew_ssl` walked every site in the FLEET and
# asked this box to renew certificates for domains it does not serve — so on a
# member the validation could not succeed and the certificate expired on a live
# site, unattended, every two minutes, needing no attacker. Both legs now take
# the registry and resolve per row, so the allow-list is retired rather than
# decremented: an allow-list that outlives its reason is how the next service
# quietly joins it.
# Go: every background service is a `spawnSupervised(...)` line in
# core_state.go; the legacy handle is `st.Agent` / `Agents.Local()` /
# `agents.Local()`. The spawn list is asserted first (#143).
if [ -n "$MN_S" ]; then
  SPAWNS=$(grep -E 'spawnSupervised\(shutdown, "' <<< "$MN_S" || true)
  SPAWN_N=$(grep -c . <<< "$SPAWNS" || true)
  LEGACY=$(count "$SPAWNS" 'st\.Agent([^s]|$)|[Aa]gents\.Local\(\)|, agent\)')
  if [ "$SPAWN_N" -lt 15 ]; then
    bad "H5 only $SPAWN_N background spawns enumerated — the class arm below cannot mean anything"
  elif [ "$LEGACY" -eq 0 ]; then
    ok "H5 none of the $SPAWN_N background spawns holds the legacy local agent handle — every spawn resolves per row"
  else
    bad "H5 $LEGACY spawn(s) hold the legacy local agent handle — that service acts on THIS box no matter which host its rows name"
  fi
else
  skip "H5 — core_state.go not extractable"
fi

# H6 — the offline sweep states its exemption instead of inheriting it from a
# NULL. `status = 'online'` gates online_fleet and the alert engine's own query,
# so a local row that can be swept offline drops the panel out of every
# fleet-iterating service at once.
if [ -n "$SM_S" ]; then
  if has "$(flat "$SM_S")" "UPDATE servers SET status = 'offline'.*is_local = false"; then
    ok "H6 the offline sweep exempts the local row explicitly"
  else
    bad "H6 the offline sweep does not name is_local — the exemption rests on a NULL comparison nobody stated"
  fi
else
  skip "H6 — svc_server_monitor.go not extractable"
fi

# H7 — the shared fleet primitive carries the flag the collector branches on.
#
# ⚠ The window is bounded by the struct's own closing brace, NOT by `-A n`. The
# first draft used `grep -A 12` and printed a confident GREEN against v2.58.0,
# where the field does not exist: twelve lines after a six-line struct run into
# `ensure_local_server`, whose body contains `WHERE is_local = true`. (Go:
# AgentFleetMember, bounded the same way.) A fixed
# window is not a declaration (p31), and the only reason this was caught is that
# the arm was run against the previous tag and required to be red (#158).
if [ -n "$AG_S" ]; then
  AG_FLEET=$(flat "$(awk '/^type AgentFleetMember struct/{f=1} f{print; if(/^\}/) exit}' <<< "$AG_S")")
  if [ -z "$AG_FLEET" ]; then
    bad "H7 could not extract the AgentFleetMember declaration — the arm cannot mean anything"
  elif has "$AG_FLEET" 'IsLocal[[:space:]]+bool'; then
    ok "H7 AgentFleetMember carries IsLocal"
  else
    bad "H7 AgentFleetMember has no IsLocal — nothing can tell the panel row from a member while iterating"
  fi
else
  skip "H7 — svc_agent.go not extractable"
fi

# H8 — the fleet reads are concurrent. Serial round trips over N hosts inside a
# 30-second interval fall behind. (Rust: join_all; Go: one goroutine per member
# under a sync.WaitGroup, inside the fleet loop.)
if [ -n "$MC_S" ]; then
  MC_RUNB=$(flat "$(fnbody "$MC_S" MetricsCollectorRun)")
  if has "$MC_RUNB" 'var wg sync\.WaitGroup for i := range fleet \{ wg\.Add\(1\) go func\(\)' && has "$MC_RUNB" 'wg\.Wait\(\)'; then
    ok "H8 the fleet is read concurrently, so a large fleet cannot outrun the tick"
  else
    bad "H8 the collector reads the fleet serially — N round trips inside a 30s interval"
  fi
else
  skip "H8 — svc_metrics_collector.go not extractable"
fi

echo
echo "§I the nil uuid is not a user (s303 / v2.60.0) — THE CLASS, not four instances"

# Four writers reached for `Uuid::nil()` (Go: `uuid.Nil`) as "no user". `activity_logs.user_id` is
# nullable with an FK to `users`, so a nil is a non-NULL value naming a row that
# does not exist: the insert is rejected with 23503 and `log_activity` (Go:
# ActivityLogActivity) swallows it
# into a warn. None of the four ever recorded anything, and TWO of them read their
# own rows back as a rate limit — a COUNT(*) that could only return 0 standing in
# for a cooldown.
#
# §B2 and G26 already pin this for auto_clean_disk and auto_restart_services, one
# function each. That is exactly the per-instance shape lesson #170 says cannot
# hold a class: both were green while three siblings were broken. I1 is the class
# arm — it reads EVERY backend source file, so a new writer is covered the day it
# is written rather than the day someone remembers to add an arm.

# The subject list must be asserted before it is trusted: an arm that enumerates
# its own subjects and finds none prints green having examined nothing (#143).
api_sources() { find "$API" -maxdepth 1 -name '*.go' ! -name '*_test.go' -type f | sort; }
NIL_FILES=$(api_sources | wc -l | tr -d ' ')
if [ "$NIL_FILES" -lt 40 ]; then
  bad "I0 only $NIL_FILES backend sources found — I1 would examine almost nothing; refusing to trust it"
else
  ok "I0 the class arm's subject list holds $NIL_FILES backend sources"

  # Every log_activity* call site, flattened onto one line each so a wrapped
  # argument list is measured whole and cannot bleed into its neighbour.
  NIL_CALLS=0
  NIL_BAD=""
  while IFS= read -r f; do
    FS=$(code "$f")
    has "$FS" 'ActivityLogActivity' || continue
    CALLW=$(stmt "$FS" 'ActivityLogActivity(OnServer|System)?\(' 12)
    NIL_CALLS=$((NIL_CALLS + $(count "$CALLW" 'ActivityLogActivity(OnServer|System)?\(')))
    if has "$CALLW" 'ActivityLogActivity(OnServer|System)?\([^)]*uuid\.Nil'; then
      NIL_BAD="$NIL_BAD $f"
    fi
  done < <(api_sources)

  # …and the calls themselves must be plausible, or the loop above matched nothing.
  if [ "$NIL_CALLS" -lt 100 ]; then
    bad "I1 only $NIL_CALLS ActivityLogActivity call sites matched — the extraction is broken, not the code clean"
  elif [ -n "$NIL_BAD" ]; then
    bad "I1 activity written as the nil uuid in:$NIL_BAD — those rows violate fk_activity_logs_user and are never stored"
  else
    ok "I1 none of the $NIL_CALLS ActivityLogActivity call sites names the nil uuid as a user"
  fi

  # I1b — and the call site is not the only way in. `auth.rs` passed the class
  # arm above for eight releases by routing the same sentinel through a
  # one-line helper (`fn zero_uuid() -> Uuid { Uuid::nil() }`), so the grep saw
  # `zero_uuid()` and found nothing to complain about. A pattern that launders
  # itself through a name is still the pattern. This forbids the FACTORY: a
  # function whose entire body hands back a nil uuid (Go:
  # `func zeroUUID() uuid.UUID { return uuid.Nil }`).
  #
  # The legitimate nils in the tree are error-path returns and comparisons
  # inside larger functions, which this cannot match by construction.
  NIL_FACTORY=""
  while IFS= read -r f; do
    FS=$(code "$f")
    has "$FS" 'uuid\.Nil' || continue
    if has "$(flat "$FS")" 'func [A-Za-z_][A-Za-z0-9_]*\(\) *uuid\.UUID *\{ *return uuid\.Nil *\}'; then
      NIL_FACTORY="$NIL_FACTORY $f"
    fi
  done < <(api_sources)

  if [ -n "$NIL_FACTORY" ]; then
    bad "I1b a nil-uuid factory is defined in:$NIL_FACTORY — it launders the sentinel past the class arm above"
  else
    ok "I1b no helper exists whose whole job is to hand back a nil uuid"
  fi
fi

# I2 — the writer that IS a cooldown. It must name a real owner and stamp the
# host, exactly as auto_restart_services has since v2.58.0 (G26 is its twin).
SSL=$(fnbody "$AH_S" "autoHealerAutoRenewSsl")
if [ -z "$SSL" ]; then
  bad "I2 could not extract autoHealerAutoRenewSsl — every §I SSL arm below is meaningless"
else
  if has "$(flat "$SSL")" 'ActivityLogActivityOnServer\(' && ! has "$SSL" 'uuid\.Nil'; then
    ok "I2 the SSL renewal attempt is recorded against the site's owner and server"
  else
    bad "I2 the SSL renewal record still uses the nil uuid — the anti-CA-hammering cooldown stays dead"
  fi

  # I3 — a gate must read something its own subject writes. This is the severed
  # pair stated directly: the action counted and the action logged are one string.
  if has "$SSL" "action = 'auto_heal.renew_ssl'" && has "$SSL" '"auto_heal.renew_ssl"'; then
    ok "I3 autoHealerAutoRenewSsl records the very action its cooldown counts"
  else
    bad "I3 the SSL cooldown counts an action this function never writes — it can never engage"
  fi

  # I4 — the failure alert names the site's own server. `ORDER BY created_at ASC
  # LIMIT 1` over `servers` is the laundering shape §G outlawed for the healer;
  # it resolves to the panel's own row, so a member's cert failure was filed
  # against the panel and hidden from the picker that would show it.
  if has "$(flat "$SSL")" 'ORDER BY created_at ASC LIMIT 1'; then
    bad "I4 autoHealerAutoRenewSsl still stamps its alert with the oldest servers row instead of the site's server"
  else
    ok "I4 autoHealerAutoRenewSsl does not resolve a server by taking the oldest row"
  fi
fi

# I5 — auto-sleep genuinely has no user to name, so it must say so in the way the
# schema sanctions (NULL) rather than by inventing a uuid.
SLEEP=$(fnbody "$AH_S" "autoHealerAutoSleepIdleContainers")
if [ -z "$SLEEP" ]; then
  bad "I5 could not extract autoHealerAutoSleepIdleContainers"
elif has "$(flat "$SLEEP")" 'ActivityLogActivitySystem\('; then
  ok "I5 stopping a customer's container leaves an audit row with no invented user"
else
  bad "I5 auto-sleep still writes its audit row with a user that does not exist — stopping a container leaves no record"
fi

# I6 — the login branch that matters. A failed login against an address with no
# account is what credential stuffing and user enumeration look like; it was the
# ONLY failure branch that named a nil uuid, so the panel recorded the one case
# that is not enumeration and dropped the one that is.
AUTH=$API/rt_auth.go
AUTH_S=$(subj "$AUTH" || true)
if [ -z "$AUTH_S" ]; then
  bad "I6 could not read $AUTH"
else
  # Go: `uuid.Nil` also appears in this file as a plain comparison
  # (`localID != uuid.Nil`), which is not a user; what is forbidden is the
  # sentinel reaching an activity writer, or a helper that launders it.
  if has "$AUTH_S" 'ActivityLogActivitySystem\(ctx, st\.DB, body\.Email, "auth\.login_failed"' \
     && ! has "$AUTH_S" 'zero_?[Uu][Uu][Ii][Dd]\(' \
     && ! has "$(stmt "$AUTH_S" 'ActivityLogActivity(OnServer)?\(' 6)" 'ActivityLogActivity(OnServer)?\([^)]*uuid\.Nil'; then
    ok "I6 a login against a non-existent account is recorded"
  else
    bad "I6 login failures against unknown accounts still write a nil uuid — the enumeration signature is invisible"
  fi
fi

# I7 — and it must be READABLE. The write landing is worth nothing if the audit
# surface cannot name the account or the origin: the login writers pass no
# target_name, so the column this reader used to select as "user" was NULL on
# every row it has ever returned.
SECR=$API/rt_security.go
SECR_S=$(subj "$SECR" || true)
if [ -z "$SECR_S" ]; then
  bad "I7 could not read $SECR"
else
  # Bounded on the function's own braces, not a fixed window: the columns live
  # on the SELECT line and the recognisable token on the WHERE line below it, so
  # a `grep -A n` anchored on either one misses the other (p31, and this arm
  # printed a false RED against a correct fix before it was written this way).
  AUDQ=$(flat "$(fnbody "$SECR_S" "rtSecurityLoginAudit")")
  if [ -z "$AUDQ" ]; then
    bad "I7 could not locate the login-audit query — the arm would measure nothing"
  elif ! has "$AUDQ" 'auth.login_failed'; then
    bad "I7 rtSecurityLoginAudit no longer reads auth.login_failed — the arm is measuring the wrong function"
  elif has "$AUDQ" 'user_email' && has "$AUDQ" 'ip_address'; then
    ok "I7 the login-audit feed carries the account and the origin of each attempt"
  else
    bad "I7 the login-audit query still omits user_email/ip_address — every row renders anonymous"
  fi
fi

# I8 — the reader side of the same severed pair. The writer has stamped
# server_id since v2.58.0 and its own cooldown reads it back; this suppression
# query was left on the bare service name, and every host has an `nginx`.
if [ -n "$AE_S" ]; then
  HEALQ=$(stmt "$AE_S" "action = 'auto_heal.restart_service'" 5)
  if [ -z "$HEALQ" ]; then
    bad "I8 could not locate the heal-suppression query in svc_alert_engine.go"
  elif has "$HEALQ" 'server_id = \$2'; then
    ok "I8 a heal on one host does not suppress the same service's alert on another"
  else
    bad "I8 the heal-suppression count is still fleet-wide — healing nginx on one server mutes nginx on all of them"
  fi
else
  skip "I8 — svc_alert_engine.go not extractable"
fi

# I9 — the fourth writer, and the one the obvious audit misses: written
# `.unwrap_or_else(uuid::Uuid::nil)`, with no parentheses, so a `Uuid::nil()`
# grep does not find it. It fed a NOT NULL column with a foreign key.
# Go shape of the defect: the local-server lookup's nil result defaulted to
# uuid.Nil instead of being refused. The anchor proves the lookup is still here.
WH=$API/rt_whmcs.go
WH_S=$(subj "$WH" || true)
if [ -z "$WH_S" ]; then
  bad "I9 could not read $WH"
elif ! has "$WH_S" "SELECT id FROM servers WHERE is_local = true LIMIT 1"; then
  bad "I9 the local-server lookup is gone from rt_whmcs.go — this arm is measuring nothing"
elif has "$WH_S" 'uuid\.Nil' || ! has "$WH_S" 'if sourceID == nil \{'; then
  bad "I9 whmcs still defaults a missing local server to the nil uuid — an FK violation surfaced as a 500"
else
  ok "I9 a missing local server is reported, not laundered into a sentinel uuid"
fi

# I9b (s311) — the same file, the same shape one level up: an UNATTENDED external
# caller mutating a column that is also the account's only record of what it was.
# `role` doubles as the status column, so `SET role = 'suspended'` overwrites it,
# and the unsuspend arm restores everyone to 'user'. An admin round-tripped
# through billing therefore comes back as a plain user with nobody left able to
# promote them — and it is reachable, because the provision arm adopts an
# EXISTING user by email with no role filter, so the operator's own account maps
# here the moment their address is also a billing contact. The panel's own twin
# in users.rs stashes the prior role first; this path has no equivalent.
#
# Keyed on the UPDATE's own predicate, not on a comment or a helper name: the
# guard has to be in the statement or it is not a guard.
# ⚠ REPOINTED s316 — the subject MOVED, and this arm's own "measuring nothing"
# guard is what caught it. `role` used to be the stash as well as the status, and
# the deny-list below was the whole compensation; the stash now has its own
# column (`users.prior_role`) and both suspenders share one statement in
# `helpers::suspend_account` (Go: suspendAccount in core_helpers.go). An arm
# still grepping whmcs.rs for the UPDATE would
# have been measuring an absent subject — lesson #150, extracting a helper moves
# the subject of every pin that measured it. So the arm follows the code, and is
# paired with the check that the caller still REACHES it.
#
# The deny-list is KEPT on purpose even though the stash now exists: it guards a
# different hazard, a lapsed invoice suspending the operator out of their own panel.
if [ -z "$WH_S" ]; then
  : # already reported by I9
elif ! has "$WH_S" 'suspendAccount\(ctx, st, '; then
  bad "I9b whmcs no longer reaches the shared suspend statement — this arm is measuring nothing"
elif has "$WH_S" "role NOT IN \\('admin', 'reseller'\\)"; then
  ok "I9b the billing webhook cannot overwrite a privileged role"
else
  bad "I9b the billing webhook suspends any role — an admin round trip demotes them permanently"
fi

# I9c (s316) — the OTHER direction, which never had a guard at all. The unsuspend
# arm restored every account to a hardcoded 'user', so one billing round trip
# promoted a `client` into the role that may claim new domains and demoted an
# `admin` in the same statement. It has to give back what was recorded.
if [ -z "$WH_S" ]; then
  : # already reported by I9
elif has "$WH_S" "UPDATE users SET role = 'user'"; then
  bad "I9c the billing webhook still restores every unsuspended account to 'user'"
elif ! has "$WH_S" 'unsuspendAccount\(ctx, st, '; then
  bad "I9c whmcs does not reach the shared unsuspend statement — this arm is measuring nothing"
else
  ok "I9c the billing webhook gives back the role it recorded, not a hardcoded one"
fi

# I10 — the structural guarantee behind all of the above. `user_id` is an Option
# (Go: *uuid.UUID) in exactly one place, the private writer (activityWriteRow), so a caller must choose between
# naming a user and declaring there is none. Re-introducing a nil-defaulting
# public helper is what this arm exists to catch.
ACT=$API/svc_activity.go
ACT_S=$(subj "$ACT" || true)
if [ -z "$ACT_S" ]; then
  bad "I10 could not read $ACT"
else
  if has "$(sig "$ACT_S" "ActivityLogActivitySystem")" 'userEmail' \
     && ! has "$(sig "$ACT_S" "ActivityLogActivitySystem")" '[uU]serID'; then
    ok "I10 the no-user writer takes no user id at all, so there is nothing to pass a sentinel into"
  else
    bad "I10 ActivityLogActivitySystem still accepts a user id — the sentinel can come straight back"
  fi
fi

# ── §J the panel stops lying (s304) ────────────────────────────────────────
#
# Five places where DockPanel told the operator something untrue. The unifying
# shape is a SECOND READER that disagrees with the first, or a first reader that
# never existed at all.

echo
echo "§J the panel stops lying (s304)"

TERM_R=$API/rt_terminal.go
LOGS_R=$API/rt_logs.go
ACTR=$API/rt_activity.go
ACTTSX=panel/frontend/src/pages/Activity.tsx
HELP=$API/core_helpers.go

for f in "$TERM_R" "$LOGS_R" "$ACTR" "$ACTTSX" "$HELP"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

TERM_S=$(subj "$TERM_R" || true)
# No LOGS_S: J5 stopped naming logs.rs (Go: rt_logs.go) when it adopted J4's source-derived
# enumeration, and each arm now reads its own subject inside the loop. `$LOGS_R`
# stays in the missing-subject-file check above — logs.rs is still a subject, it
# is simply no longer one this file names by hand.
ACTR_S=$(subj "$ACTR" || true)
ACTTSX_S=$(subj "$ACTTSX" || true)
HELP_S=$(subj "$HELP" || true)

# Call sites of a function, definition excluded — the definition line is the one
# that carries `func`. Counting raw occurrences would let a pin pass on a helper
# nobody calls.
callsites() { grep -E -- "$2" <<< "$1" | grep -vcE '^func[[:space:]]' || true; }

# J1 — the public share viewer decides expiry itself. It used to compute the
# remaining seconds, clamp a negative to zero and render the content anyway, so
# an unauthenticated URL served root terminal output for as long as the row
# survived — and only a once-a-day retention sweep removed it. A sweep is a
# housekeeper, not an access control.
if [ -z "$TERM_S" ]; then
  bad "J1 could not read $TERM_R"
else
  VS=$(fnbody "$TERM_S" "rtTerminalViewShared")
  if [ -z "$VS" ]; then
    bad "J1 could not extract rtTerminalViewShared — the arm measured nothing"
  elif has "$(flat "$VS")" ':= rtTerminalShareLifetime\(\*raw, time\.Now\(\)\.Unix\(\)\) if !ok \{ return apiErr\(http\.StatusNotFound'; then
    ok "J1 the public share viewer refuses an expired share instead of rendering it"
  else
    bad "J1 rtTerminalViewShared no longer rejects on the shared lifetime decision — an expired share renders"
  fi
fi

# J2 — and BOTH readers reach that decision through the same function. The defect
# was precisely that they disagreed: the operator's list skipped an expired share
# while the public viewer showed it, so the panel reported a share as gone while
# the URL still served it.
if [ -z "$TERM_S" ]; then
  skip "J2 — terminal routes not extractable"
elif [ "$(callsites "$TERM_S" 'rtTerminalShareLifetime\(')" -ge 2 ]; then
  ok "J2 the operator's list and the public viewer share one expiry rule, so they cannot drift"
else
  bad "J2 fewer than two callers of the shared expiry rule — a reader has its own copy again"
fi

# J3 — the public route takes no authentication, so the id is the only
# credential and gets the shape check the revoke path always had.
if [ -z "$TERM_S" ]; then
  skip "J3 — terminal routes not extractable"
elif has "$(flat "$(fnbody "$TERM_S" "rtTerminalViewShared")")" 'if !rtTerminalValidShareID\(id\) \{'; then
  ok "J3 the unauthenticated viewer validates the share id before querying"
else
  bad "J3 rtTerminalViewShared no longer validates the share id"
fi

# J4 — both streaming tickets refuse at the MINT when a fleet member is selected.
# The ticket is signed with the selected server's agent token while the browser
# can only reach the panel's own agent, so the receiving agent rejected it and
# the UI blamed the network: the terminal said "Connection lost" and the log
# viewer reconnected every three seconds for ever.
#
# ⚠ s305: this arm USED TO ITERATE A HARDCODED TWO-ELEMENT LIST. That is the
# mock-that-supplies-its-own-target shape — an arm which enumerates its own
# subjects can never see a subject that was never added to it, so a THIRD mint
# of this class would have been invisible to it for ever. The subjects are now
# derived FROM SOURCE: a streaming ticket mint is a route handler whose name
# ends `Token` and whose body resolves a per-server scope (Go: the
# `st.serverScope(r)` call is the ServerScope extractor). `iac`'s API-token
# pair and `rotateToken` are correctly excluded because they take no scope.
# Per lesson #143 an arm that enumerates its own subjects must ASSERT the
# enumeration first, or an empty list prints green having measured nothing.
#
# GREEN AT BOTH TAGS BY DESIGN — this is a HARDENING of an arm that already
# passed, not a new defect, so it cannot satisfy required-red (#172/#180).
# MUTATION-TESTED instead, and the mutation is the whole justification: append a
# third `_token` handler taking a per-server scope and omitting the guard, then
# run both versions. The old hardcoded arm prints TWO GREENS and never mentions
# it; this one enumerates THREE and goes red on the new one. Do not "simplify"
# it back to a literal list.
MINTS=$(for f in "$API"/rt_*.go; do
  [[ "$f" == *_test.go ]] && continue
  perl -0777 -ne 'while (/^func (rt[A-Za-z0-9]*Token)\(st \*AppState, w http\.ResponseWriter, r \*http\.Request\) error \{\n(.*?)^\}/gms) {
    my ($n,$b)=($1,$2); next unless $b =~ /st\.serverScope\(r\)/; print "$ARGV:$n\n"; }' "$f"
done | sort)
MINT_N=$(printf '%s\n' "$MINTS" | grep -c . || true)
if [ "$MINT_N" -lt 2 ]; then
  bad "J4 enumerated only $MINT_N scoped ticket mints — the enumeration is broken, not the code (expected at least the terminal and log-stream mints)"
else
  ok "J4 enumerated $MINT_N streaming ticket mints from source, not from a list this arm carries"
  while IFS=: read -r file fn; do
    [ -n "$fn" ] || continue
    src=$(subj "$file" || true)
    if [ -z "$src" ]; then
      bad "J4 could not read $file"
      continue
    fi
    BODY=$(flat "$(fnbody "$src" "$fn")")
    if [ -z "$BODY" ]; then
      bad "J4 could not extract $fn — the arm measured nothing"
    elif has "$BODY" 'requireLocalAgentScope\('; then
      ok "J4 $fn refuses a fleet member at the mint, before any socket is dialled"
    else
      bad "J4 $fn mints a ticket for any selected server again — that stream fails as a network error"
    fi
  done <<< "$MINTS"
fi

# J5 — and it can only do that because it keeps the id. `ServerScope` resolved it
# and both handlers bound it to `_server_id` (Go: `_, agent, err :=
# st.serverScope(r)`) and threw it away; the knowledge to
# answer honestly was already in the handler.
#
# ⚠ s321: THIS ARM USED TO ITERATE A HARDCODED TWO-ELEMENT LIST — three lines
# below the s305 paragraph above that forbids exactly that, and says so in the
# imperative. It judged two handlers by name while the token it forbids is spelled
# at 267 sites across 25 modules, so a THIRD mint of this class would have been
# invisible to it for ever. That is lesson #267: a warning comment protects the
# arm it sits in, not the file, and "the lesson is already written here" is
# evidence the file needs auditing rather than evidence it is safe.
#
# It now reuses J4's source-derived `$MINTS`, so both arms judge the same
# enumeration and a new mint is seen by BOTH the day it is added. Today that
# resolves to the same two handlers the list named, so this is a HARDENING of an
# arm that already passed — it cannot satisfy required-red (#172/#180) and is
# MUTATION-TESTED instead, exactly as J4 was. Per lesson #143 the enumeration is
# asserted BEFORE anything is judged, and a subject that cannot be read or
# extracted is reported as measuring nothing rather than skipped in silence —
# the previous `continue` on an empty source was that silent skip.
if [ "$MINT_N" -lt 2 ]; then
  bad "J5 enumerated only $MINT_N scoped ticket mints — the enumeration is broken, not the code (expected at least the terminal and log-stream mints)"
else
  ok "J5 judges the same $MINT_N mints J4 enumerated from source, not a list this arm carries"
  while IFS=: read -r file fn; do
    [ -n "$fn" ] || continue
    src=$(subj "$file" || true)
    if [ -z "$src" ]; then
      bad "J5 could not read $file"
      continue
    fi
    SIG=$(fnbody "$src" "$fn")
    if [ -z "$SIG" ]; then
      bad "J5 could not extract $fn — the arm measured nothing"
    elif ! has "$SIG" ':?= st\.serverScope\(r\)'; then
      bad "J5 $fn no longer resolves the scope at all — the arm measured nothing"
    elif has "$SIG" '^[[:space:]]*_, [A-Za-z_]+, err :?= st\.serverScope\(r\)'; then
      bad "J5 $fn discards the resolved server id again — it cannot tell which host was selected"
    else
      ok "J5 $fn keeps the resolved server id rather than discarding it"
    fi
  done <<< "$MINTS"
fi

# J6 — the audit feed can say which host. `activity_logs.server_id` has been
# written since v2.58.0 and stamped by the healer's own writers since v2.60.0,
# and was read only by this file's cooldown gates: the struct never declared it,
# so `SELECT *` dropped it and the one surface an operator reads showed nothing.
# Cross-tree by construction — a backend-only arm would pass on a dead column.
if [ -z "$ACTR_S" ] || [ -z "$ACTTSX_S" ]; then
  bad "J6 could not read both trees"
else
  B_OK=0; F_OK=0
  has "$(flat "$(awk '/^type rtActivityActivityLog struct/{f=1} f{print; if(/^\}/) exit}' <<< "$ACTR_S")")" 'json:"server_id"' && B_OK=1
  has "$(flat "$(grep -A 16 -E 'interface ActivityEntry' <<< "$ACTTSX_S" || true)")" 'server_id' && F_OK=1
  if [ "$B_OK" = 1 ] && [ "$F_OK" = 1 ]; then
    ok "J6 the host travels from the audit row to the audit page in both trees"
  else
    bad "J6 the audit feed lost the host again (backend=$B_OK frontend=$F_OK) — a stamp with no reader"
  fi
fi

# J7 — and it renders a NAME. The column holds a uuid; a feed that prints one is
# no more legible than a feed that prints nothing.
if [ -z "$ACTR_S" ]; then
  skip "J7 — activity route not extractable"
elif has "$(flat "$ACTR_S")" 'LEFT JOIN servers' && has "$ACTR_S" 'json:"server_name"' && has "$(flat "$ACTTSX_S")" 'server_name'; then
  ok "J7 the audit feed resolves the host to its name in both trees"
else
  bad "J7 the audit feed no longer resolves the host name — the operator reads a uuid"
fi

# J8 — THE SEVERED PAIR. `auto_heal.clean_logs` spent the operator-facing
# `target_name` column on the server's uuid because the hourly cooldown keyed on
# it. Writer and reader must agree, and they must agree on `server_id` — moving
# one without the other silently disarms the gate and the prune returns to every
# 120 seconds, which is the defect v2.60.0 fixed elsewhere in this same file.
if [ -z "$AH_S" ]; then
  skip "J8 — auto_healer not extractable"
else
  ACD=$(flat "$(fnbody "$AH_S" "autoHealerAutoCleanDisk")")
  READER_OK=0; WRITER_OK=0
  has "$ACD" "auto_heal\.clean_logs' AND server_id" && READER_OK=1
  has "$ACD" 'ActivityLogActivityOnServer\(ctx, db, userID, "auto-healer", "auto_heal\.clean_logs",.*new\(serverID\)' && WRITER_OK=1
  if [ "$READER_OK" = 1 ] && [ "$WRITER_OK" = 1 ]; then
    ok "J8 the clean_logs cooldown and its writer agree on server_id, so the gate survives the rename"
  else
    bad "J8 clean_logs writer/reader disagree (reader=$READER_OK writer=$WRITER_OK) — the hourly gate is disarmed"
  fi
fi

# J9 — TRIPWIRE, and the reason this ship stopped where it did. A backend
# WebSocket proxy would carry a member-signed ticket to the member's own agent,
# which honours it — including the `domain` query parameter the ticket does NOT
# bind, and which an empty value turns into a root login shell. Two independent
# things confine that to the panel today: nginx points both stream paths at the
# local socket, and the local agent rejects a ticket signed elsewhere. A proxy
# removes both at once. Bind the domain into the signed ticket FIRST.
# Go: a WebSocket handler is a `websocket.Accept(` call (coder/websocket).
UPGRADES=$(grep -rlE --include='*.go' 'websocket\.Accept\(' panel/go/internal/api | grep -v '_test\.go$' | sort | tr '\n' ' ')
if [ "$(printf '%s' "$UPGRADES" | wc -w)" -eq 1 ] && [[ "$UPGRADES" == *ws_metrics* ]]; then
  ok "J9 still exactly one WebSocket handler (rt_ws_metrics.go) — no stream proxy has been added"
else
  bad "J9 a new WebSocket handler exists ($UPGRADES) — bind the domain into the terminal ticket BEFORE proxying, or an empty domain is a root shell on every host"
fi


# J10 — s305, and this is the arm the old hardcoded J4 could never have been.
# A raw browser stream cannot carry the selected server: the fetch wrapper in
# `api.ts` is the ONLY thing in the client that sends that header, and neither
# the WebSocket nor the EventSource constructor takes headers at all. So the
# backend's scope extractor resolves EVERY such stream to the panel's own agent
# whatever the picker says. Two of the three surfaces of this class were fixed
# by naming it at the mint; the dashboard's metrics socket was left, and it wrote
# the PANEL's cpu/memory/disk into the same state the server-scoped poll fills,
# so the tiles changed machine on the 3s reconnect timer with the badge still
# reading "Live".
#
# The rule, keyed on the capability rather than today's spelling: a component
# that opens a raw socket must prove which host it is describing — either it
# obtains its URL from a signed ticket (guarded server-side, see J4) or it
# consults the server selection before opening (guarded client-side). Neither
# means an unscoped socket.
WSFILES=$(grep -rlE 'new WebSocket\(' panel/frontend/src --include=*.tsx --include=*.ts | sort)
WS_N=$(printf '%s\n' "$WSFILES" | grep -c . || true)
if [ "$WS_N" -lt 3 ]; then
  bad "J10 found only $WS_N raw WebSocket openers in the client — the enumeration is broken, not the code (terminal, logs and the dashboard all open one)"
else
  ok "J10 enumerated $WS_N raw WebSocket openers from source"
  while read -r f; do
    [ -n "$f" ] || continue
    FSRC=$(subj "$f" || true)
    if [ -z "$FSRC" ]; then
      bad "J10 could not read $f"
    elif has "$FSRC" 'token' || has "$FSRC" 'isLocal'; then
      ok "J10 $(basename "$f") proves its host — ticket-guarded or selection-guarded"
    else
      bad "J10 $(basename "$f") opens a raw socket without a ticket or a server-selection gate — it will stream the PANEL host under whatever server is selected"
    fi
  done <<< "$WSFILES"
fi

# J11 — the other half of the same class. Server-Sent Events are a raw browser
# stream too, so an SSE handler that resolves a per-server agent has exactly the
# dashboard socket's defect. Today all six read user-owned rows by id and touch
# no agent, which is why none of them was affected; this arm makes that a
# property rather than a coincidence. Go: an SSE handler is a route handler
# that sets `text/event-stream` or hands off to a `…ServeSSE(` helper; it is
# per-server scoped when it calls `st.serverScope(r)`.
#
# GREEN AT BOTH TAGS BY DESIGN — a tripwire for a regression that does not exist
# yet cannot be red at the previous tag (#180). MUTATION-TESTED instead: append
# an SSE handler taking a per-server scope and this arm names it and fails.
# A future session re-deriving this as a false green should read that sentence
# before deleting a tripwire.
sse_handlers() {
  for f in "$API"/rt_*.go; do
    [[ "$f" == *_test.go ]] && continue
    perl -0777 -ne 'while (/^func (rt[A-Za-z0-9]+)\(st \*AppState, w http\.ResponseWriter, r \*http\.Request\) error \{\n(.*?)^\}/gms) {
      my ($n,$b)=($1,$2); next unless $b =~ /text\/event-stream|ServeSSE\(/;
      print "$ARGV:$n", ($b =~ /st\.serverScope\(/ ? " SCOPED" : ""), "\n"; }' "$f"
  done
}
SSE_LIST=$(sse_handlers)
SSE_SCOPED=$(grep ' SCOPED$' <<< "$SSE_LIST" | sed 's/ SCOPED$//' | tr '\n' ' ' || true)
SSE_ALL=$(grep -c . <<< "$SSE_LIST" || true)
if [ "$SSE_ALL" -lt 3 ]; then
  bad "J11 enumerated only $SSE_ALL SSE handlers — the enumeration is broken, not the code"
elif [ -z "$SSE_SCOPED" ]; then
  ok "J11 none of the $SSE_ALL SSE handlers resolves a per-server agent, so no event stream can describe the wrong host"
else
  bad "J11 an SSE handler now resolves a per-server agent ($SSE_SCOPED) — a browser event stream cannot send the server header, so it will read the PANEL host"
fi

echo
echo "----------------------------------------------"
printf '  PASS %d   FAIL %d   SKIP %d\n' "$PASS" "$FAIL" "$SKIP"
echo
[ "$FAIL" -eq 0 ] || exit 1
