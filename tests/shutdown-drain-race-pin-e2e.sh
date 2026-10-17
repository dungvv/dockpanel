#!/usr/bin/env bash
# shutdown-drain-race-pin-e2e.sh — s466
#
# Standing carry from s465 (project_dockpanel_tech_debt_p204): the demo
# deploy's own `systemctl stop dockpanel-api` triggered the graceful-shutdown
# watchdog (then main.rs::shutdown_signal, GRACEFUL_SHUTDOWN_TIMEOUT = 20s;
# now panel/go/internal/api/core_state.go::Serve, gracefulShutdownTimeout)
# for the FIRST time in 12 sessions of monitoring — a real forced exit
# (`os.Exit(1)`, systemd `status=1/FAILURE`), not another clean non-trigger.
#
# Root cause: the graceful drain (axum's with_graceful_shutdown then,
# http.Server.Shutdown now) waits for every IN-FLIGHT connection to close on
# its OWN; a WebSocket or SSE handler that only exits when the CLIENT
# disconnects (or, for the provision-log SSE streams, when the underlying job
# finishes) can hold that drain open past the 20s window. http.Server.Shutdown
# does not cancel hijacked or still-streaming handlers either.
#
# Fixed by threading a shutdown broadcast into every long-lived connection
# handler. In the Go port that broadcast is a context:
#
#   §A AppState.Shutdown context.Context — the SAME ctx spawnSupervised hands
#      every background service (core_state.go::Serve), created before
#      NewAppState so the state can hold it, and cancelled the instant the OS
#      signal arrives (not after the drain that waits on its subscribers).
#   §B (the Rust helpers::shutdown_signal_fut — retired: ctx.Done() IS the
#      shared future in Go.)
#   §C rt_ws_metrics.go::rtWsMetricsHandleSocket — the ONLY websocket.Accept
#      site in the api. Its per-tick fetch/send/recv cycle runs under a ctx
#      cancelled by st.Shutdown (context.AfterFunc), not just a check at the
#      top of the loop: a single agent.Get already budgets up to 60s, which
#      alone exceeds the 20s drain window.
#   §D Every SSE handler (the complete set — every function that sets
#      Content-Type text/event-stream) selects on st.Shutdown.Done():
#      rtNotificationsStream (the PROCESS-LIFETIME notification broadcast —
#      it would otherwise never end; every admin tab holds one), plus the
#      provision-log-shaped streams rtSitesServeSSE (shared by the sites
#      provision log and rtSystemInstallLog), rtGitDeploysServeSSE,
#      rtDockerAppsServeSSE and rtMigrationProgress.
#
# Adversarially reviewed via a 3-lens skeptic workflow (correctness,
# completeness-vs-independent-grep, blast-radius) before shipping — see
# project_dockpanel_tech_debt_p205 for the verdicts.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  Graceful-shutdown drain race — source pins (s466)"
echo "=================================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

# Go comments out (whole-line // and /* */ blocks), code intact.
code() {
  [ -f "$1" ] || return 0
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

has()    { grep -qE -- "$2" <<< "$1"; }
lacks()  { ! grep -qE -- "$2" <<< "$1"; }
count()  { grep -cE -- "$2" <<< "$1"; }

# One Go func (plain or method) by name, brace-depth bounded.
fnbody() {
  awk -v fn="$2" '
    !started && (index($0, "func " fn "(") == 1 || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) { started=1 }
    started {
      n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth += n - m; print
      if (opened || n>0) opened=1
      if (opened && depth<=0) exit
    }
  ' <<< "$1"
}

API=panel/go/internal/api
CORE=$API/core_state.go
CORE_C=$(code "$CORE")
WS_METRICS=$API/rt_ws_metrics.go
WS_METRICS_C=$(code "$WS_METRICS")
NOTIFICATIONS_C=$(code "$API/rt_notifications.go")
SITES_C=$(code "$API/rt_sites.go")
GIT_DEPLOYS_C=$(code "$API/rt_git_deploys.go")
DOCKER_APPS_C=$(code "$API/rt_docker_apps.go")
SYSTEM_C=$(code "$API/rt_system.go")
MIGRATION_C=$(code "$API/rt_migration.go")

for f in "$CORE" "$WS_METRICS"; do [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"; done

SERVE_BODY=$(fnbody "$CORE_C" "Serve")
[ -n "$SERVE_BODY" ] || bad "could not bound func Serve() in $CORE — every §A arm below is unreachable"

# ── §A AppState carries a shutdown broadcast ────────────────────────────────
echo "── §A core_state.go: AppState carries the same shutdown ctx every background service gets ──"

if has "$CORE_C" '^[[:space:]]*Shutdown context\.Context$'; then
  ok "A1 AppState has a Shutdown context.Context field"
else
  bad "A1 AppState is missing the Shutdown context.Context field"
fi

CHANNEL_RE='shutdown, cancelShutdown := context\.WithCancel\(context\.Background\(\)\)'
CHANNEL_LINE=$(grep -nE "$CHANNEL_RE" <<< "$SERVE_BODY" | head -1 | cut -d: -f1)
STATE_LITERAL_LINE=$(grep -nE 'st := NewAppState\(db, cfg, agent, agents, shutdown\)' <<< "$SERVE_BODY" | head -1 | cut -d: -f1)
CHANNEL_COUNT=$(count "$CORE_C" "$CHANNEL_RE")

if [ "$CHANNEL_COUNT" -eq 1 ]; then
  ok "A2 the shutdown ctx is created exactly once (no leftover duplicate declaration)"
else
  bad "A2 expected exactly 1 'shutdown, cancelShutdown := context.WithCancel(...)', found $CHANNEL_COUNT"
fi

if [ -n "$CHANNEL_LINE" ] && [ -n "$STATE_LITERAL_LINE" ] && [ "$CHANNEL_LINE" -lt "$STATE_LITERAL_LINE" ]; then
  ok "A3 the shutdown ctx is created BEFORE NewAppState(..., shutdown) (so the state can hold it)"
else
  bad "A3 the shutdown ctx is not created before 'st := NewAppState(db, cfg, agent, agents, shutdown)'"
fi

NEWSTATE_BODY=$(fnbody "$CORE_C" "NewAppState")
if has "$NEWSTATE_BODY" 'Shutdown:[[:space:]]+shutdown,'; then
  ok "A4 NewAppState stores the shutdown ctx in AppState.Shutdown"
else
  bad "A4 NewAppState no longer stores the shutdown ctx into AppState.Shutdown"
fi

# Positive control: the pre-existing background-service wiring is untouched.
if has "$SERVE_BODY" 'spawnSupervised\(shutdown, "backup_scheduler",' && has "$SERVE_BODY" 'spawnSupervised\(shutdown, "cleanup",'; then
  ok "A5 (control) spawnSupervised still wires background services to the same shutdown ctx"
else
  bad "A5 (control) spawnSupervised's shutdown wiring was altered"
fi

# ── A6/A7: the CRITICAL fix-of-the-fix — where the broadcast actually fires ─
#
# The first cut of this fix (caught by an adversarial skeptic workflow before
# shipping) sent the broadcast AFTER the drain returned. The drain does not
# return until every in-flight connection's handler has ended — so a handler
# racing itself against the broadcast was waiting on a signal that could only
# be sent once it, and every sibling connection, had already closed some
# OTHER way. Circular: a no-op for its own stated purpose. The real fix fires
# the broadcast the instant the OS signal arrives, BEFORE the drain starts.
SIG_ARM=$(awk '/case s := <-sig:/{f=1} f' <<< "$SERVE_BODY")
if has "$SERVE_BODY" 'signal\.Notify\(sig, os\.Interrupt, syscall\.SIGTERM\)' && [ -n "$SIG_ARM" ]; then
  ok "A6 Serve() subscribes to SIGINT/SIGTERM and has a 'case s := <-sig:' shutdown arm"
else
  bad "A6 Serve() no longer has the signal.Notify + 'case s := <-sig:' shutdown arm"
fi

CANCEL_REL=$(grep -nE '^[[:space:]]*cancelShutdown\(\)$' <<< "$SIG_ARM" | head -1 | cut -d: -f1)
WATCHDOG_REL=$(grep -nE 'go func\(\) \{' <<< "$SIG_ARM" | head -1 | cut -d: -f1)
DRAIN_REL=$(grep -nE 'srv\.Shutdown\(' <<< "$SIG_ARM" | head -1 | cut -d: -f1)
if [ -n "$CANCEL_REL" ] && [ -n "$WATCHDOG_REL" ] && [ -n "$DRAIN_REL" ] \
  && [ "$CANCEL_REL" -lt "$WATCHDOG_REL" ] && [ "$WATCHDOG_REL" -lt "$DRAIN_REL" ]; then
  ok "A7 in the signal arm, cancelShutdown() fires BEFORE the watchdog and BEFORE srv.Shutdown()'s drain — not after it"
else
  bad "A7 cancelShutdown() is not ordered before the watchdog and srv.Shutdown() in the signal arm — the circular-wait bug may have returned"
fi

# Control: nothing after the drain starts claims to (re)send the broadcast.
POST_DRAIN=$(awk '/srv\.Shutdown\(/{f=1} f' <<< "$SERVE_BODY")
if [ -n "$POST_DRAIN" ] && lacks "$POST_DRAIN" 'cancelShutdown\(\)|Sending shutdown signal to background services'; then
  ok "A8 (control) Serve() no longer sends the shutdown broadcast itself post-drain"
else
  bad "A8 (control) a post-drain cancelShutdown()/'sending shutdown signal' reappeared (or srv.Shutdown is gone)"
fi

# ── §B helpers::shutdown_signal_fut ─────────────────────────────────────────
# B1 retired (obsolete in Go): the Rust shutdown_signal_fut helper (and its `+ use<>` capture opt-out) has no Go analogue; ctx.Done() is the shared future.
# B2 retired (obsolete in Go): subscribe-then-recv on a broadcast is replaced by selecting on st.Shutdown.Done(), pinned per handler in §C/§D.

# ── §C ws_metrics: the metrics websocket races shutdown mid-cycle ──────────
echo "── §C rt_ws_metrics.go: rtWsMetricsHandleSocket races its whole per-tick cycle against shutdown ──"

if has "$WS_METRICS_C" 'rtWsMetricsHandleSocket\(st, conn, agent, claims\)'; then
  ok "C1 the handler hands AppState (and with it st.Shutdown) to rtWsMetricsHandleSocket"
else
  bad "C1 the handler no longer passes st into rtWsMetricsHandleSocket"
fi

HANDLE_SOCKET_BODY=$(fnbody "$WS_METRICS_C" "rtWsMetricsHandleSocket")
if has "$HANDLE_SOCKET_BODY" 'ctx, cancel := context\.WithCancel\(' && has "$HANDLE_SOCKET_BODY" 'context\.AfterFunc\(st\.Shutdown, cancel\)'; then
  ok "C2 rtWsMetricsHandleSocket derives its cycle ctx from st.Shutdown (context.AfterFunc)"
else
  bad "C2 rtWsMetricsHandleSocket no longer ties its cycle ctx to st.Shutdown"
fi

if has "$HANDLE_SOCKET_BODY" 'agent\.Get\(ctx, p\)' && has "$HANDLE_SOCKET_BODY" 'conn\.Write\(ctx,' && has "$HANDLE_SOCKET_BODY" 'case <-ctx\.Done\(\):'; then
  ok "C3 the per-tick fetch, send and 5s wait all run under the shutdown-cancelled ctx"
else
  bad "C3 the per-tick fetch/send/wait is no longer raced against shutdown"
fi

# Positive control: the 4 concurrent agent fetches this loop exists to make
# are unchanged — this fix restructures control flow, not the payload.
AGENT_GET_CALLS=$(grep -oE '"/(system/info|system/processes|system/network|apps/gpu-info)"' <<< "$HANDLE_SOCKET_BODY" | sort -u | wc -l | tr -d ' ')
if [ "$AGENT_GET_CALLS" -eq 4 ] && has "$HANDLE_SOCKET_BODY" 'results := make\(\[\]any, 4\)'; then
  ok "C4 (control) all 4 agent endpoints are still fetched per tick"
else
  bad "C4 (control) expected 4 agent endpoints fetched in rtWsMetricsHandleSocket, found $AGENT_GET_CALLS"
fi

# C5 — adversarial-review follow-up: the trailing close-frame send is timed,
# so a black-holed peer can't stall this connection's own handler (and with
# it, the drain wait for it) past the shutdown signal that just fired.
CLOSE_TAIL=$(awk '/conn\.Close\(websocket\.StatusNormalClosure/{f=1} f' <<< "$HANDLE_SOCKET_BODY")
if has "$CLOSE_TAIL" 'case <-time\.After\(2 \* time\.Second\):' && has "$CLOSE_TAIL" 'conn\.CloseNow\(\)'; then
  ok "C5 the trailing close-frame send is bounded by a 2s timeout (then CloseNow), not a bare call"
else
  bad "C5 the trailing close-frame send is unbounded again — a black-holed peer could stall this connection's own drain"
fi

# ── §D every SSE stream ends on shutdown too ───────────────────────────────
echo "── §D every SSE handler races its stream against shutdown ──"

# A body races shutdown if it selects on st.Shutdown.Done() directly, or on a
# channel it assigned from it.
races() {
  has "$1" 'case <-st\.Shutdown\.Done\(\):' \
    || { has "$1" 'shutdown = st\.Shutdown\.Done\(\)' && has "$1" 'case <-shutdown:'; }
}
sse_arm() { # id file-content func label
  local b; b=$(fnbody "$2" "$3")
  if [ -z "$b" ]; then bad "$1 could not find func $3"
  elif ! has "$b" 'text/event-stream'; then bad "$1 $3 no longer serves text/event-stream — re-derive this arm"
  elif races "$b"; then ok "$1 $3 ($4) selects on st.Shutdown.Done()"
  else bad "$1 $3 ($4) is missing the shutdown race"; fi
}
sse_arm D1 "$NOTIFICATIONS_C" rtNotificationsStream "the process-lifetime notification feed"
sse_arm D2 "$SITES_C"         rtSitesServeSSE       "sites provision log"
sse_arm D3 "$GIT_DEPLOYS_C"   rtGitDeploysServeSSE  "git deploy log"
sse_arm D4 "$DOCKER_APPS_C"   rtDockerAppsServeSSE  "docker app deploy log"

INSTALL_BODY=$(fnbody "$SYSTEM_C" "rtSystemInstallLog")
if has "$INSTALL_BODY" 'rtSitesServeSSE\(st, w, r, history, live\)'; then
  ok "D5 rtSystemInstallLog streams through rtSitesServeSSE (raced in D2)"
else
  bad "D5 rtSystemInstallLog no longer streams through the shutdown-raced rtSitesServeSSE"
fi
sse_arm D6 "$MIGRATION_C"     rtMigrationProgress   "migration progress"

# Package-wide completeness control: every func that sets text/event-stream
# races shutdown — a new SSE handler added without the race is caught here.
SSE_REPORT=$(for f in "$API"/rt_*.go; do
  code "$f" | awk -v F="$(basename "$f")" '
    /^func /{ if (fn != "" && sse) print F, fn, raced; fn=$0; sse=0; raced=0 }
    /text\/event-stream/ { sse=1 }
    /case <-st\.Shutdown\.Done\(\):|shutdown = st\.Shutdown\.Done\(\)/ { raced=1 }
    END { if (fn != "" && sse) print F, fn, raced }'
done)
SSE_SITES=$(grep -c . <<< "$SSE_REPORT")
SHUTDOWN_RACED=$(grep -c ' 1$' <<< "$SSE_REPORT")
if [ "$SSE_SITES" -eq 5 ] && [ "$SHUTDOWN_RACED" -eq 5 ]; then
  ok "D7 (package-wide control) all 5 text/event-stream funcs race shutdown — no gap, no drift"
else
  bad "D7 (package-wide control) SSE funcs=$SSE_SITES, shutdown-raced=$SHUTDOWN_RACED — mismatch, investigate: $(grep ' 0$' <<< "$SSE_REPORT" | tr '\n' ';')"
fi

echo
echo "=================================================="
echo "  PASS=$PASS FAIL=$FAIL"
echo "=================================================="

[ "$FAIL" -eq 0 ]
