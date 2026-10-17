#!/usr/bin/env bash
# graceful-shutdown-timeout-pin-e2e.sh
#
# THE SENTENCE THIS SUITE EXISTS TO PROVE:
#
#   "SIGTERM forces the process to exit within a bound no matter what happens
#    downstream of it, WITHOUT ever bounding the server's normal lifetime."
#
# THE DEFECT (measured on a real deploy). `axum::serve(...)
# .with_graceful_shutdown(shutdown_signal())` waits for EVERY in-flight
# connection to finish before returning. An open SSE stream or a WebSocket
# terminal session (this panel serves both, indefinitely) never closes on its
# own, so a plain SIGTERM idled the full ~90s systemd default TimeoutStopSec
# before systemd force-killed the process.
#
# A FIRST FIX ATTEMPT WAS WRONG, AND THIS SUITE EXISTS TO STOP IT RECURRING.
# Wrapping the WHOLE `axum::serve(...).with_graceful_shutdown(...)` future in
# `tokio::time::timeout(N, ...)` looks plausible but is a critical regression:
# that future runs for the server's entire uptime (it does not resolve until
# BOTH the shutdown signal fires AND every connection drains), so timing out
# the whole thing kills the process ~N seconds after every single boot,
# whether or not a shutdown was ever requested. Caught by adversarial review
# before shipping — never by this file's own author reading the diff twice.
#
# THE ACTUAL FIX. Leave `axum::serve(...).with_graceful_shutdown(shutdown_signal())`
# bare and unbounded (that is correct — it MUST run for the server's whole
# life). Instead, arm a watchdog INSIDE `shutdown_signal()`, AFTER it has
# already resolved (ctrl_c or SIGTERM received): `tokio::spawn` a task that
# sleeps `GRACEFUL_SHUTDOWN_TIMEOUT` then calls `std::process::exit(1)`. The
# watchdog's clock only starts once the signal has fired, and a genuine hard
# process exit (not merely dropping a future) is required because axum spawns
# each connection onto its own independent task that dropping the orchestrator
# future does not cancel, and the unconditional `shutdown_db.close().await`
# that runs afterward is itself unbounded.
#
# So the mutations this suite must survive fall into two families: (1)
# RE-UNBOUNDING mutations — remove the watchdog, let its branch fall silent,
# swap the hard exit for a soft return — and (2) THE EXACT REGRESSION ABOVE —
# re-wrapping axum::serve(...).with_graceful_shutdown(...) in a timeout that
# bounds the whole server lifetime instead of just the post-signal drain.
# Mutation-tested against both the pre-fix revision and a synthetic
# reintroduction of the wrong first attempt: every arm below is required to
# go RED against at least one of them.
#
# THE GO PORT (panel/go/internal/api/core_state.go::Serve). There is no
# separate shutdown_signal(): Serve() runs `go func() { served <- srv.Serve(ln) }()`
# and selects on that vs `case s := <-sig:`. The watchdog lives INSIDE the
# signal arm: `go func() { time.Sleep(gracefulShutdownTimeout); slog.Warn(...);
# os.Exit(1) }()`, then `srv.Shutdown(context.Background())` drains. Same two
# mutation families, Go shapes:
#
#   §A  the watchdog is armed AFTER the signal resolves, inside the
#       `case s := <-sig:` arm — never from boot
#   §B  the bound is a small, named, finite constant (gracefulShutdownTimeout),
#       shared by the sleep and the log message — not unbounded, not duplicated
#   §C  the watchdog actually calls os.Exit(...) — a real hard exit, not a
#       log-only no-op
#   §D  NEGATIVE CONTROL: srv.Serve(ln) is NOT bounded by any timeout,
#       deadline or AfterFunc in Serve() — the Go analogue of the
#       whole-lifetime-wrap regression from the first fix attempt
#   §E  the `case err := <-served:` arm still logs "API server error: ..." —
#       the fix must not have touched the server's own error handling
#   §F  the watchdog is a goroutine (`go func`), not slept inline — inline
#       would delay srv.Shutdown()'s drain from even starting
#
# Pure source analysis over panel/go/internal/api/core_state.go: no box, no
# network, no build required.
#
# NO PIPES INTO `grep -q`. Under `set -o pipefail` grep -q closes the pipe on
# its first match, the upstream dies of SIGPIPE (141), and pipefail reports
# the whole pipeline failed — so an arm would go red on correct code,
# non-deterministically. Every arm here feeds grep a here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

CORE_GO=panel/go/internal/api/core_state.go

[ -f "$CORE_GO" ] || bad "MISSING SUBJECT FILE: $CORE_GO"

# Go comments out (whole-line // and /* */ blocks), CODE INTACT.
code() {
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}
subj()  { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }
has()   { grep -qE -- "$2" <<< "$1"; }
count() { grep -cE -- "$2" <<< "$1" || true; }
flat()  { tr -s '[:space:]' ' ' <<< "$1"; }
# One function's body, bounded by its OWN closing brace in column 0 — not the
# whole file.
fn_body() { awk -v pat="$1" '$0 ~ pat {f=1} f {print} f && /^\}/ {exit}' <<< "$2"; }

FULL_S=$(subj "$CORE_GO" || true)
FULL_FLAT=$(flat "$FULL_S")

SERVE_FN=$(fn_body '^func Serve[(]' "$FULL_S")
SERVE_FLAT=$(flat "$SERVE_FN")
# The post-signal arm of Serve()'s select — everything from `case s := <-sig:`.
SIG_ARM=$(awk '/case s := <-sig:/{f=1} f' <<< "$SERVE_FN")
SIG_FLAT=$(flat "$SIG_ARM")

if [ -z "$SERVE_FN" ]; then
  bad "could not bound func Serve() in $CORE_GO — every arm below is unreachable"
fi
if [ -z "$SIG_ARM" ]; then
  bad "could not find the 'case s := <-sig:' arm in Serve() — every §A/§B/§C/§F arm below is unreachable"
fi

echo "§A  the watchdog is armed AFTER the signal resolves, inside the signal arm of Serve()"

# A1 — a `go func() {` watchdog sleeping on gracefulShutdownTimeout sits
# INSIDE the `case s := <-sig:` arm, and no watchdog sleep exists before it.
# Ordering matters: the clock starts once the signal has ALREADY fired, not
# from process start.
if [ -z "$SIG_ARM" ]; then
  bad "A1 SKIPPED: could not find the signal arm"
else
  PRE_SIG=$(awk '/case s := <-sig:/{exit} {print}' <<< "$SERVE_FN")
  SPAWN_LN=$(grep -n 'go func() {' <<< "$SIG_ARM" | head -1 | cut -d: -f1)
  SLEEP_LN=$(grep -n 'time.Sleep(gracefulShutdownTimeout)' <<< "$SIG_ARM" | head -1 | cut -d: -f1)
  if [ -z "${SPAWN_LN:-}" ] || [ -z "${SLEEP_LN:-}" ]; then
    bad "A1 could not locate the 'go func() {' watchdog or its gracefulShutdownTimeout sleep inside the signal arm"
  elif has "$PRE_SIG" 'gracefulShutdownTimeout'; then
    bad "A1 gracefulShutdownTimeout is used BEFORE the signal arm — the bound may now start from process start"
  elif [ "$SPAWN_LN" -lt "$SLEEP_LN" ]; then
    ok "A1 a goroutine watchdog sleeping on gracefulShutdownTimeout sits inside 'case s := <-sig:' — its clock starts once the signal has already fired"
  else
    bad "A1 the watchdog sleep is not inside its goroutine in the signal arm"
  fi
fi

echo "§B  the bound is a small, named, finite constant, shared by the sleep and the log"

# B1 — a plain, finite `N * time.Second` constant exists, N is small.
if has "$FULL_FLAT" 'const gracefulShutdownTimeout = [0-9]+ \* time\.Second'; then
  DUR_N=$(grep -oE 'const gracefulShutdownTimeout = [0-9]+ \* time\.Second' <<< "$FULL_FLAT" \
            | grep -oE '[0-9]+' | tail -1)
  if [ -n "${DUR_N:-}" ] && [ "$DUR_N" -gt 0 ] 2>/dev/null && [ "$DUR_N" -le 30 ] 2>/dev/null; then
    ok "B1 gracefulShutdownTimeout is a finite constant of ${DUR_N}s (0 < N <= 30) — short enough to exit well inside systemd's kill window"
  else
    bad "B1 gracefulShutdownTimeout is ${DUR_N:-unknown}s — not a short bound any more"
  fi
else
  bad "B1 no finite 'const gracefulShutdownTimeout = N * time.Second' found — the bound may be missing or dynamic"
fi

# B2 — the SAME constant drives both the watchdog's sleep and the warning it
# logs on firing, via .Seconds(). Independently-spelled durations could drift.
if [ -z "$SIG_ARM" ]; then
  bad "B2 SKIPPED: could not find the signal arm"
elif has "$SIG_FLAT" 'gracefulShutdownTimeout\.Seconds\(\)' \
  && [ "$(count "$SIG_ARM" 'gracefulShutdownTimeout')" -ge 2 ]; then
  ok "B2 the logged duration reads .Seconds() off the same constant the watchdog sleeps on — no duplicated literal to drift"
else
  bad "B2 the watchdog's log message no longer derives from the same named constant it sleeps on"
fi

echo "§C  the watchdog actually calls os.Exit — a real hard exit"

# C1 — after the sleep, the watchdog calls os.Exit(...), not just a log. A
# soft log-only "watchdog" would not save us from a hung handler or a stalled
# drain. It must also log first (an operator needs to see WHY the process
# just vanished), so both must be present, log before exit.
if [ -z "$SIG_ARM" ]; then
  bad "C1 SKIPPED: could not find the signal arm"
else
  WD=$(awk '/go func\(\) \{/{f=1} f{print} f && /^[[:space:]]*\}\(\)/{exit}' <<< "$SIG_ARM")
  WARN_LN=$(grep -n 'slog.Warn(' <<< "$WD" | head -1 | cut -d: -f1)
  EXIT_LN=$(grep -n 'os.Exit(' <<< "$WD" | head -1 | cut -d: -f1)
  if [ -z "${WARN_LN:-}" ] || [ -z "${EXIT_LN:-}" ]; then
    bad "C1 could not find both a slog.Warn and an os.Exit inside the watchdog goroutine — it may be a no-op"
  elif [ "$WARN_LN" -lt "$EXIT_LN" ]; then
    ok "C1 the watchdog logs via slog.Warn THEN calls os.Exit — an operator sees why, and the process actually terminates"
  else
    bad "C1 os.Exit appears before the warning is logged, or the ordering could not be established"
  fi
fi

echo "§D  NEGATIVE CONTROL: srv.Serve(ln) is never bounded by a timeout"

# D1 — THE EXACT REGRESSION THIS SUITE MUST CATCH. Go's analogue of wrapping
# axum::serve in tokio::time::timeout is bounding the server goroutine (or
# the select that waits on it) with a deadline/AfterFunc/time.After that runs
# from boot: the process would exit ~N seconds after every start, shutdown or
# not. Positive anchor: the server goroutine itself must be found.
if [ -z "$SERVE_FN" ] || ! has "$SERVE_FN" 'go func\(\) \{ served <- srv\.Serve\(ln\) \}\(\)'; then
  bad "D1 could not find 'go func() { served <- srv.Serve(ln) }()' in Serve() — the negative check below would be vacuous"
elif has "$SERVE_FN" 'context\.WithTimeout|context\.WithDeadline|time\.AfterFunc|case <-time\.After\(|WriteTimeout|IdleTimeout:.*gracefulShutdownTimeout' \
  || has "$(awk '/case s := <-sig:/{exit} {print}' <<< "$SERVE_FN")" 'os\.Exit'; then
  bad "D1 Serve() bounds the server's lifetime with a timeout/deadline (or exits before the signal arm) — this would force-exit the process ~N seconds after every single boot"
else
  ok "D1 srv.Serve(ln) runs unbounded; the only timer is the post-signal watchdog — the server's normal lifetime is unbounded, as it must be"
fi

echo "§E  the original bare error-handling shape around the server is still there"

# E1 — the server-error arm `case err := <-served:` still logs the same
# message. Adding the watchdog to the signal arm must not have touched it.
if [ -z "$SERVE_FN" ]; then
  bad "E1 SKIPPED: could not bound Serve()"
elif has "$SERVE_FLAT" 'case err := <-served: slog\.Error\(fmt\.Sprintf\("API server error: %v", err\)\)'; then
  ok "E1 the 'case err := <-served: slog.Error(\"API server error: ...\")' shape is intact"
else
  bad "E1 the original server-error handling around srv.Serve is gone or no longer logs the same message"
fi

echo "§F  the watchdog is spawned as an independent goroutine, not slept inline"

# F1 — `go func() {` precedes the sleep/warn/exit body, so the signal arm
# proceeds straight to srv.Shutdown() and the drain begins in parallel with
# the watchdog's countdown. Sleeping inline would delay the drain from even
# starting until the full bound elapsed.
if [ -z "$SIG_ARM" ]; then
  bad "F1 SKIPPED: could not find the signal arm"
elif has "$SIG_FLAT" 'go func\(\) \{ time\.Sleep\(gracefulShutdownTimeout\)' \
  && has "$SIG_FLAT" '\}\(\) if err := srv\.Shutdown\('; then
  ok "F1 the watchdog's sleep+warn+exit body is a goroutine — srv.Shutdown()'s drain starts in parallel"
else
  bad "F1 the watchdog's sleep is not in its own goroutine ahead of srv.Shutdown() — the drain may be delayed from ever starting"
fi

echo
echo "PASS $PASS / FAIL $FAIL"
[ "$FAIL" -eq 0 ]
