#!/usr/bin/env bash
# drill-ws-backup-scope-pin-e2e.sh — s465
#
# dockpanel-fanout, batched small-file tail of the panel API's routes/services
# (Rust era; the arms below now read the Go port in panel/go/internal/api —
# drill_scheduler.rs → svc_drill_scheduler.go, ws_metrics.rs → rt_ws_metrics.go,
# backup_orchestrator.rs → rt_backup_orchestrator.go, backup_destinations.rs →
# rt_backup_destinations.go, services/agent.rs → svc_agent.go)
# (drill_scheduler.rs, deploy_scheduler.rs, alert_runbooks.rs,
# alert_runbook_defaults.rs / prometheus.rs, prometheus_exporter.rs,
# metrics_collector.rs, ws_metrics.rs, system_logs.rs / agent_checkin.rs,
# agent_updates.rs, sboms.rs, chain_report.rs, branding_assets.rs — see
# feedback_dockpanel_audit_scope). Found and fixed 5 real, independently
# skeptic-verified issues (4 on-menu + 1 off-menu completeness-critic find):
#
#   §A drill_scheduler.rs + backup_orchestrator.rs: a scheduled OR on-demand
#      backup drill fired the agent call via plain `post` (60s total-round-trip
#      cap), but the agent-side restore it triggers is budgeted 220s (mariadb)
#      to 360s (volume: 300s restore + 60s probe) — several multiples of the
#      cap. Any drill against a non-trivial backup was killed by the client and
#      recorded `status = 'failed'`, a false DR-failure signal on a healthy
#      backup. Fixed both the scheduled (`enqueue_drill`) and on-demand
#      (`trigger_drill`) paths via `post_long(..., DRILL_TIMEOUT_SECS)`, the
#      same fix pattern `DB_RESTORE_TIMEOUT_SECS` already established for the
#      real (non-drill) restore path in this same file. Confirmed dormant on
#      this box (0 rows in backup_policies/backup_drills/database_backups/
#      volume_backups, drill_enabled defaults off) but reachable the instant a
#      real policy enables drills.
#   §B drill_scheduler.rs: `tick()` stamped `last_drill_at = NOW()`
#      unconditionally BEFORE calling `dispatch_policy_drills`, which has four
#      early-return paths (no backups tied to the policy, local server id
#      unknown, target server unreachable, another drill already running) that
#      make zero agent calls and insert zero `backup_drills` rows. A policy
#      whose server has been down for weeks read as "last drilled Xm ago" on
#      every cron tick — the one case a DR-verification timestamp most needs to
#      flag was the case it hid. Fixed: `dispatch_policy_drills` now returns
#      whether it actually enqueued a drill, and `tick()` only stamps
#      `last_drill_at` when it did.
#   §C ws_metrics.rs: the live-metrics websocket validated the JWT (expiry,
#      blacklist, global session revocation, admin role) ONLY at handshake,
#      before `ws.on_upgrade`. The 5s streaming loop never re-checked any of
#      it — logout, the panic button, and `POST /auth/revoke-all` all closed
#      the door to NEW connections but left an ALREADY-OPEN socket streaming
#      the full process/network/GPU/system feed for as long as the underlying
#      TCP connection stayed alive, unbounded even by the token's own nominal
#      expiry. This directly undermined the panic button's own stated intent
#      (its comment in this same file). Fixed: a shared `claims_now_invalid`
#      check, re-run every loop tick, closes the socket the instant any of the
#      handshake conditions would now reject it.
#   §D backup_orchestrator.rs: `chain_report_json`/`chain_report_pdf` (via
#      `build_chain_report`) and `list_all_backups` accepted a caller-supplied
#      backup id / listed the whole fleet with NO ownership scoping — gated
#      only by `AdminUser`, a pure role check. Any admin could pull another
#      admin's full chain-of-trust report (site domain, db/container:volume
#      names, filenames, hash chain, every verification and drill) as JSON or
#      PDF, and `list_all_backups` was the exact discovery channel for the
#      backup ids needed to do it. Identical bug class already fixed once in
#      this same file for `list_volume_backups`/`restore_volume_backup`
#      (v2.184.0) — just missed for these two. Fixed: every query now joins
#      `servers` and requires `is_local OR user_id = caller`, mirroring the
#      v2.184.0 remedy exactly.
#   §E (off-menu, completeness critic) backup_destinations.rs: `update()`,
#      `remove()`, and `test_connection()` all queried/mutated a destination by
#      bare `id`, gated only by `AdminUser` — asymmetric with `create()` in the
#      same file, which already scopes `server_id` by `is_local OR user_id`.
#      A second admin (DockPanel genuinely supports multiple admin accounts)
#      could overwrite another admin's S3/SFTP destination config with their
#      own credentials — the next scheduled backup for any policy pointing at
#      it would silently upload the target server's data into the SECOND
#      admin's bucket, a backup-exfiltration primitive, with no activity-log
#      entry on this route to notice it by. `list()` had the identical gap
#      (found independently while fixing the other three — a bare
#      unscoped `SELECT *`) and was fixed the same way. Fixed: all four now
#      scope by the same `is_local OR user_id = caller` predicate `create`
#      already established.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  Drill timeout / ws revocation / backup ownership scope — source pins (s465)"
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
    s{^\s*///.*$}{}gm;
  ' "$1"
}

has()    { grep -qE -- "$2" <<< "$1"; }
lacks()  { ! grep -qE -- "$2" <<< "$1"; }
count()  { grep -cE -- "$2" <<< "$1"; }

# Go: `func NAME(` or a method `func (r *T) NAME(`.
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

API=panel/go/internal/api
AGENT_SVC=$API/svc_agent.go
DRILL_SCHED=$API/svc_drill_scheduler.go
BACKUP_ORCH=$API/rt_backup_orchestrator.go
WS_METRICS=$API/rt_ws_metrics.go
BACKUP_DEST=$API/rt_backup_destinations.go
for f in "$AGENT_SVC" "$DRILL_SCHED" "$BACKUP_ORCH" "$WS_METRICS" "$BACKUP_DEST"; do
  [ -f "$f" ] || { echo "missing file: $f"; exit 1; }
done
AGENT_SVC_C=$(code "$AGENT_SVC")
DRILL_SCHED_C=$(code "$DRILL_SCHED")
BACKUP_ORCH_C=$(code "$BACKUP_ORCH")
WS_METRICS_C=$(code "$WS_METRICS")
BACKUP_DEST_C=$(code "$BACKUP_DEST")

# A discarded AdminUser binding: Rust `AdminUser(_claims)` → Go `_, err := st.adminUser(r)`.
DISCARDED_CLAIMS='_, err :?= st\.adminUser\(r\)'
BOUND_CLAIMS='claims, err := st\.adminUser\(r\)'

# ── §A drill timeout: post -> post_long(DRILL_TIMEOUT_SECS) ────────────────
echo "── §A svc_drill_scheduler.go + rt_backup_orchestrator.go: drills use a timeout sized for the restore, not the round trip ──"

if has "$AGENT_SVC_C" '^const AgentDrillTimeoutSecs = 420$'; then
  ok "A1 AgentDrillTimeoutSecs constant defined (420s, > the 360s volume-drill worst case)"
else
  bad "A1 AgentDrillTimeoutSecs constant missing or changed"
fi

ENQUEUE_BODY=$(fnbody "$DRILL_SCHED_C" "drillSchedulerEnqueueDrill")
if has "$ENQUEUE_BODY" 'agent\.PostLong\(bg, agentPath, body, AgentDrillTimeoutSecs\)'; then
  ok "A2 scheduled path (drillSchedulerEnqueueDrill) calls PostLong with AgentDrillTimeoutSecs"
else
  bad "A2 scheduled path no longer uses post_long/DRILL_TIMEOUT_SECS — regressed to the 60s cap"
fi

# Go: rtBackupOrchestratorTriggerDrill maps all 3 drill paths into one
# rtBackupOrchestratorDispatch call carrying AgentDrillTimeoutSecs, and the
# dispatcher turns a non-zero timeout into PostLong.
TRIGGER_BODY=$(fnbody "$BACKUP_ORCH_C" "rtBackupOrchestratorTriggerDrill")
DISPATCH_HELPER=$(fnbody "$BACKUP_ORCH_C" "rtBackupOrchestratorDispatch")
TRIGGER_DRILL_PATHS=$(grep -oE '"/backups/drill/(site|db|volume)"' <<< "$TRIGGER_BODY" | sort -u | wc -l | tr -d ' ')
if [ "$TRIGGER_DRILL_PATHS" -eq 3 ] \
   && has "$TRIGGER_BODY" '"drill", AgentDrillTimeoutSecs\)' \
   && has "$DISPATCH_HELPER" 'return agent\.PostLong\(ctx, paths\[backupType\], body, timeout\)'; then
  ok "A3 on-demand path (rtBackupOrchestratorTriggerDrill) dispatches all 3 drill types via PostLong with AgentDrillTimeoutSecs"
else
  bad "A3 on-demand drill path: $TRIGGER_DRILL_PATHS/3 drill paths, or the AgentDrillTimeoutSecs → PostLong hand-off is gone"
fi

# Positive control: the real (non-drill) DB restore timeout constant is untouched.
if has "$AGENT_SVC_C" '^const AgentDBRestoreTimeoutSecs = 270$'; then
  ok "A4 (control) AgentDBRestoreTimeoutSecs unchanged at 270s"
else
  bad "A4 (control) AgentDBRestoreTimeoutSecs was touched — verify this wasn't accidentally altered"
fi

# ── §B last_drill_at: stamped only after a drill actually enqueues ─────────
echo "── §B svc_drill_scheduler.go: last_drill_at only advances when a drill actually dispatched ──"

DISPATCH_BODY=$(fnbody "$DRILL_SCHED_C" "drillSchedulerDispatchPolicyDrills")
if has "$DISPATCH_BODY" '^func drillSchedulerDispatchPolicyDrills\(.*\) bool \{'; then
  ok "B1 drillSchedulerDispatchPolicyDrills returns bool"
else
  bad "B1 drillSchedulerDispatchPolicyDrills no longer returns bool — regressed"
fi

if has "$DISPATCH_BODY" 'dispatched := false' && has "$DISPATCH_BODY" '^\s*return dispatched$'; then
  ok "B2 drillSchedulerDispatchPolicyDrills tracks and returns whether it actually enqueued a drill"
else
  bad "B2 the dispatched-tracking logic is missing"
fi

TICK_BODY=$(fnbody "$DRILL_SCHED_C" "drillSchedulerTick")
if has "$TICK_BODY" 'if drillSchedulerDispatchPolicyDrills\(ctx, db, agents, p\) \{'; then
  ok "B3 drillSchedulerTick gates the last_drill_at UPDATE on drillSchedulerDispatchPolicyDrills actually returning true"
else
  bad "B3 drillSchedulerTick no longer gates on drillSchedulerDispatchPolicyDrills' return value"
fi

if [ -z "$TICK_BODY" ]; then
  bad "B4 drillSchedulerTick did not extract — the absence check would see nothing"
elif lacks "$TICK_BODY" '^\s*drillSchedulerDispatchPolicyDrills\('; then
  ok "B4 the old unconditional (unguarded) dispatch call is gone"
else
  bad "B4 an unconditional drillSchedulerDispatchPolicyDrills call still exists — the stamp could run unconditionally again"
fi

# Positive control: the UPDATE statement itself is unchanged.
if has "$TICK_BODY" 'UPDATE backup_policies SET last_drill_at = NOW\(\) WHERE id = \$1'; then
  ok "B5 (control) the last_drill_at UPDATE statement text is unchanged"
else
  bad "B5 (control) the UPDATE statement was altered — verify the fix didn't change its shape"
fi

# ── §C ws_metrics.rs: per-tick revocation/expiry recheck ────────────────────
echo "── §C rt_ws_metrics.go: the live-metrics socket re-validates every tick, not just at handshake ──"

if has "$WS_METRICS_C" '^func rtWsMetricsClaimsNowInvalid\('; then
  ok "C1 rtWsMetricsClaimsNowInvalid helper exists"
else
  bad "C1 rtWsMetricsClaimsNowInvalid helper missing"
fi

CLAIMS_INVALID_BODY=$(fnbody "$WS_METRICS_C" "rtWsMetricsClaimsNowInvalid")
if has "$CLAIMS_INVALID_BODY" 'int64\(c\.Exp\) < time\.Now\(\)\.Unix\(\)'; then
  ok "C2 rtWsMetricsClaimsNowInvalid checks the token's own expiry, not just revocation"
else
  bad "C2 the expiry check is missing — exposure would still be unbounded past the token's own exp"
fi

if has "$CLAIMS_INVALID_BODY" 'st\.isBlacklisted\(\*c\.Jti\)' && has "$CLAIMS_INVALID_BODY" 'st\.sessionsRevokedAt\(\)'; then
  ok "C3 rtWsMetricsClaimsNowInvalid checks both the token blacklist and global session revocation"
else
  bad "C3 blacklist/global-revocation checks missing from rtWsMetricsClaimsNowInvalid"
fi

HANDLE_SOCKET_BODY=$(fnbody "$WS_METRICS_C" "rtWsMetricsHandleSocket")
# s466 CORR: in Rust a 5th param, shutdown_rx, was threaded through; the Go port
# reads shutdown from st.Shutdown instead. Check the signature and that the
# per-tick call sits inside the streaming loop.
LOOP_BODY=$(awk '/^loop:/{f=1} f' <<< "$HANDLE_SOCKET_BODY")
if has "$HANDLE_SOCKET_BODY" '^func rtWsMetricsHandleSocket\(st \*AppState, .*claims \*Claims\)' && has "$LOOP_BODY" 'if rtWsMetricsClaimsNowInvalid\(st, claims\) \{'; then
  ok "C4 rtWsMetricsHandleSocket takes state+claims and calls rtWsMetricsClaimsNowInvalid every loop iteration"
else
  bad "C4 handle_socket no longer threads state/claims through to a per-tick check"
fi

if has "$WS_METRICS_C" 'rtWsMetricsHandleSocket\(st, conn, agent, claims\)'; then
  ok "C5 the handshake hands state+claims to rtWsMetricsHandleSocket"
else
  bad "C5 the handshake no longer passes state/claims to rtWsMetricsHandleSocket"
fi

# Positive control: the handshake's own original checks are all still present.
if has "$WS_METRICS_C" 'Token has been revoked' && has "$WS_METRICS_C" 'Session revoked\. Please log in again\.' && has "$WS_METRICS_C" 'Admin access required'; then
  ok "C6 (control) the handshake's own blacklist/revocation/admin-role checks are unchanged"
else
  bad "C6 (control) a handshake-time check was removed — verify this wasn't accidentally dropped"
fi

# ── §D backup_orchestrator.rs: chain-report + list-all-backups ownership scope ─
echo "── §D rt_backup_orchestrator.go: chain-report and list-all-backups scoped to owned/local servers ──"

BUILD_CHAIN_BODY=$(fnbody "$BACKUP_ORCH_C" "rtBackupOrchestratorBuildChainReport")
if has "$BUILD_CHAIN_BODY" '^func rtBackupOrchestratorBuildChainReport\(.*callerID uuid\.UUID\)'; then
  ok "D1 rtBackupOrchestratorBuildChainReport takes a callerID parameter"
else
  bad "D1 rtBackupOrchestratorBuildChainReport has no callerID parameter — still unscoped"
fi

SCOPE_JOINS=$(count "$BUILD_CHAIN_BODY" 'JOIN servers sv ON sv\.id = .*server_id.* AND \(sv\.is_local OR sv\.user_id = \$2\)')
if [ "$SCOPE_JOINS" -eq 3 ]; then
  ok "D2 all 3 per-kind queries (site/database/volume) join servers and scope by is_local OR user_id"
else
  bad "D2 expected 3 ownership-scoped server joins in rtBackupOrchestratorBuildChainReport, found $SCOPE_JOINS"
fi

# Go: JSON and PDF share rtBackupOrchestratorChainArgs, which binds claims and
# is the one caller of the builder.
CHAIN_ARGS_BODY=$(fnbody "$BACKUP_ORCH_C" "rtBackupOrchestratorChainArgs")
CHAIN_CALLERS=$(count "$BACKUP_ORCH_C" 'rtBackupOrchestratorBuildChainReport\(r\.Context\(\), st, kind, id, claims\.Sub\)')
TOTAL_CHAIN_CALLS=$(count "$BACKUP_ORCH_C" 'rtBackupOrchestratorBuildChainReport\(')
if [ "$CHAIN_CALLERS" -eq 1 ] && [ "$TOTAL_CHAIN_CALLS" -eq 2 ] \
   && has "$CHAIN_ARGS_BODY" 'rtBackupOrchestratorBuildChainReport\(r\.Context\(\), st, kind, id, claims\.Sub\)'; then
  ok "D3 the one builder call (rtBackupOrchestratorChainArgs) passes claims.Sub as callerID"
else
  bad "D3 expected exactly 1 builder call, passing claims.Sub, in rtBackupOrchestratorChainArgs (found $CHAIN_CALLERS of $((TOTAL_CHAIN_CALLS-1)))"
fi

if has "$CHAIN_ARGS_BODY" "$BOUND_CLAIMS"; then
  ok "D4 rtBackupOrchestratorChainArgs binds claims (not the discarded _)"
else
  bad "D4 rtBackupOrchestratorChainArgs discards claims"
fi

JSON_BODY=$(fnbody "$BACKUP_ORCH_C" "rtBackupOrchestratorChainReportJSON")
PDF_BODY=$(fnbody "$BACKUP_ORCH_C" "rtBackupOrchestratorChainReportPDF")
if has "$JSON_BODY" 'rtBackupOrchestratorChainArgs\(st, r\)' && has "$PDF_BODY" 'rtBackupOrchestratorChainArgs\(st, r\)' \
   && lacks "$JSON_BODY" "$DISCARDED_CLAIMS" && lacks "$PDF_BODY" "$DISCARDED_CLAIMS"; then
  ok "D5 chain-report JSON and PDF both resolve through the claims-binding rtBackupOrchestratorChainArgs"
else
  bad "D5 a chain-report handler bypasses rtBackupOrchestratorChainArgs or discards claims"
fi

LIST_ALL_BODY=$(fnbody "$BACKUP_ORCH_C" "rtBackupOrchestratorListAllBackups")
if has "$LIST_ALL_BODY" 'server_id IS NULL OR srv\.is_local OR srv\.user_id = \$5' \
  && has "$LIST_ALL_BODY" 'server_id IS NULL OR srv\.is_local OR srv\.user_id = \$3'; then
  ok "D6 rtBackupOrchestratorListAllBackups scopes both the SELECT and COUNT queries by is_local OR user_id"
else
  bad "D6 rtBackupOrchestratorListAllBackups ownership scoping missing from one or both queries"
fi

if has "$LIST_ALL_BODY" "$BOUND_CLAIMS" && lacks "$LIST_ALL_BODY" "$DISCARDED_CLAIMS"; then
  ok "D7 rtBackupOrchestratorListAllBackups binds claims (not the discarded _)"
else
  bad "D7 rtBackupOrchestratorListAllBackups still discards claims"
fi

# Positive control: the v2.184.0 sibling fix this mirrors is still intact.
LVB_BODY=$(fnbody "$BACKUP_ORCH_C" "rtBackupOrchestratorListVolumeBackups")
if has "$LVB_BODY" 'sv\.is_local OR sv\.user_id = \$1'; then
  ok "D8 (control) list_volume_backups' own v2.184.0 ownership scope is unchanged"
else
  bad "D8 (control) the sibling fix this session's remedy mirrors was itself altered"
fi

# ── §E backup_destinations.rs: list/update/remove/test_connection scoped ────
echo "── §E rt_backup_destinations.go: destination management scoped to owned/local servers ──"

LIST_DEST_BODY=$(fnbody "$BACKUP_DEST_C" "rtBackupDestinationsList")
if has "$LIST_DEST_BODY" 'server_id IS NULL OR s\.is_local OR s\.user_id = \$1' && has "$LIST_DEST_BODY" "$BOUND_CLAIMS"; then
  ok "E1 list() is ownership-scoped and binds claims"
else
  bad "E1 list() is missing the ownership scope or still discards claims"
fi

UPDATE_DEST_BODY=$(fnbody "$BACKUP_DEST_C" "rtBackupDestinationsUpdate")
if has "$UPDATE_DEST_BODY" 'bd\.server_id IS NULL OR s\.is_local OR s\.user_id = \$2' && has "$UPDATE_DEST_BODY" "$BOUND_CLAIMS"; then
  ok "E2 update() has an ownership pre-check and binds claims"
else
  bad "E2 update() is missing the ownership pre-check or still discards claims"
fi

REMOVE_DEST_BODY=$(fnbody "$BACKUP_DEST_C" "rtBackupDestinationsRemove")
if has "$REMOVE_DEST_BODY" 'bd\.server_id IS NULL OR s\.is_local OR s\.user_id = \$2' && has "$REMOVE_DEST_BODY" "$BOUND_CLAIMS"; then
  ok "E3 remove() has an ownership pre-check and binds claims"
else
  bad "E3 remove() is missing the ownership pre-check or still discards claims"
fi

TEST_CONN_BODY=$(fnbody "$BACKUP_DEST_C" "rtBackupDestinationsTestConnection")
if has "$TEST_CONN_BODY" 'bd\.server_id IS NULL OR s\.is_local OR s\.user_id = \$2' && has "$TEST_CONN_BODY" "$BOUND_CLAIMS"; then
  ok "E4 test_connection() scopes its destination lookup by ownership and binds claims"
else
  bad "E4 test_connection() is missing the ownership scope or still discards claims"
fi

# Positive control: create()'s own pre-existing ownership check (the pattern
# the other four now mirror) is unchanged.
CREATE_DEST_BODY=$(fnbody "$BACKUP_DEST_C" "rtBackupDestinationsCreate")
if has "$CREATE_DEST_BODY" 'is_local OR user_id = \$2'; then
  ok "E5 (control) create()'s own server-ownership check is unchanged"
else
  bad "E5 (control) create()'s ownership check was altered"
fi

# Positive control: DESTINATION_CALLER_PREDICATE (the narrower READ-scope
# constant used by selectable()/backup_schedules.rs) was deliberately left
# untouched — this fix mirrors create()'s broader is_local-inclusive
# MANAGEMENT predicate instead, not this one.
if has "$BACKUP_DEST_C" '^const rtBackupDestinationsDestinationCallerPredicate = "\(bd\.server_id IS NULL OR s\.user_id = \$1\)"$'; then
  ok "E6 (control) rtBackupDestinationsDestinationCallerPredicate is unchanged"
else
  bad "E6 (control) rtBackupDestinationsDestinationCallerPredicate was altered — this session deliberately left it alone"
fi

echo
echo "=================================================="
echo "  PASS=$PASS FAIL=$FAIL"
echo "=================================================="

[ "$FAIL" -eq 0 ]
