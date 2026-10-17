#!/usr/bin/env bash
# Regression pins for s269 — the CPU number that measured the caller, not the box.
#
# The dashboard gauge read 99% on a box `top` reported 94.6% idle, while the
# 24-hour chart built from the SAME endpoint read 9.7%. Nothing was wrong with
# the box; the number was an artefact of how it was asked for.
#
#   C1  CPU percentage is a delta over a window. `/system/info` refreshed CPU
#       inside the handler, so the window was "time since whichever unrelated
#       caller last hit this endpoint". Five callers share it (metrics collector
#       every 30 s, the dashboard WebSocket loop every ~5 s, the dashboard REST
#       tick, the backup scheduler, the Docker-apps page), so each corrupted the
#       others' windows. The value was never a property of the system.
#   C2  The handler walked every process in /proc on each call — measured at
#       ~70 ms of CPU with 583 processes — purely to obtain a COUNT. That walk
#       landed inside the next caller's window, so the endpoint was the largest
#       consumer in its own measurement. The self-inflicted floor is
#       walk_ms / (gap_ms * cores) * 100: ~2% on a 12-core box at a 250 ms gap,
#       ~28% on a single core, and higher still once the WebSocket loop's
#       concurrent /system/processes call (two more full walks) lands in the
#       same window.
#   C3  Below sysinfo's MINIMUM_CPU_UPDATE_INTERVAL (200 ms) a refresh is
#       SKIPPED, not rejected — so closely-spaced callers silently received a
#       value computed for an older window, with no error anywhere.
#   C4  phone_home built `System::new_all()` then `refresh_all()` back to back
#       and read global_cpu_usage() off it: a window consisting almost entirely
#       of its own /proc walk. On an idle 12-core box whose true usage was 4.5%,
#       consecutive runs returned 4.5%–22.1%. That value lands in
#       servers.cpu_usage, which the Servers page shows and the alert engine
#       compares against CPU thresholds.
#
# The fix is structural: one sampler owns the window. A dedicated task with its
# own CPU-only System refreshes on a fixed cadence and publishes to an atomic;
# handlers read it. These pins hold that shape, because the defect returns the
# moment any handler refreshes CPU for itself again.
#
# Go port: services/cpu_sampler.go (CpuSampler: a goroutine reading the
# aggregate /proc/stat line via gopsutil cpu.Times(false) every
# CpuSamplerSampleInterval, publishing to an atomic). In Go terms the
# forbidden per-request shapes are cpu.Percent/cpu.Times in a handler
# (sysinfo's refresh_cpu/global_cpu_usage) and process.Processes() in
# /system/info or phone_home (refresh_processes / System::new_all).
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Strip whole-line Go comments, so a pin can never be satisfied (or tripped)
# by prose describing the very thing it forbids.
code()  { grep -vE '^[[:space:]]*(//|\*|/\*)' "$1"; }
has()   { [ -n "$(code "$1" | grep -F -- "$2")" ]; }
hasre() { [ -n "$(code "$1" | grep -E -- "$2")" ]; }
# One Go func (plain or method) by name: from its `func` line to the first
# closing brace in column 0.
fnb()   { code "$1" | awk -v fn="$2" '!f && (index($0, "func " fn "(") == 1 || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) {f=1} f {print} f && /^\}/ {exit}'; }

AG=panel/go/internal/agent
SAMPLER=$AG/services/cpu_sampler.go
SYSROUTE=$AG/routes/system.go
APPSTATE=$AG/routes/state.go
MAIN=panel/go/cmd/dockpanel-agent/main.go
PHONE=$AG/services/phone_home.go
COLLECTOR=panel/go/internal/api/svc_metrics_collector.go

for f in "$SAMPLER" "$SYSROUTE" "$APPSTATE" "$MAIN" "$PHONE" "$COLLECTOR"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

# gopsutil's CPU-delta calls: the Go spelling of sysinfo's refresh_cpu /
# global_cpu_usage.
CPU_DELTA_RE='cpu\.(Percent|PercentWithContext|Times|TimesWithContext)\('

echo "── 1. C1: no handler computes CPU from its own request timing ──"

# The heart of it. A refresh inside the handler re-creates the defect exactly,
# whatever else changes around it.
if hasre "$SYSROUTE" "$CPU_DELTA_RE"; then
  bad "routes/system.go computes a CPU delta in the handler again — the window is back to 'time since some other caller'"
else
  ok "routes/system.go does not refresh CPU per request"
fi

if [ -n "$(fnb "$SYSROUTE" systemHandleInfo | grep -F 's.Cpu.Usage()')" ]; then
  ok "routes/system.go reads the sampled value"
else
  bad "routes/system.go no longer reads the sampler — where is cpu_usage coming from?"
fi

# Any OTHER agent route computing CPU for itself is the same bug wearing a
# different URL, so pin the whole routes tree rather than the one file.
STRAY=$(for f in "$AG"/routes/*.go; do
  case "$f" in (*_test.go|"$SYSROUTE") continue ;; esac
  hasre "$f" "$CPU_DELTA_RE" && echo "$f"
done)
if [ -z "$STRAY" ]; then
  ok "no other agent route computes CPU usage on its own"
else
  bad "these routes compute CPU themselves, re-opening the per-caller window: $STRAY"
fi

echo
echo "── 2. C2: the endpoint is not the biggest consumer in its own measurement ──"

# Scope this to the /system/info HANDLER. The sibling /system/processes
# endpoint must walk /proc — that is the data it returns. The defect is the
# *info* handler paying that cost to obtain a count, inside the window the next
# caller measures.
info_body() { fnb "$SYSROUTE" systemHandleInfo; }
if [ -n "$(info_body | grep -E 'process\.(Processes|NewProcess|Pids)')" ]; then
  bad "systemHandleInfo walks every process again (~70 ms of CPU per call) — that walk lands inside the next caller's window"
else
  ok "systemHandleInfo does not walk every process"
fi
# Guard the guard: if the handler is renamed the extraction silently matches
# nothing and the pin above would pass vacuously.
if [ -n "$(info_body)" ] && [ -n "$(code "$SYSROUTE" | grep -F 'r.State.systemHandleInfo')" ]; then
  ok "the /system/info handler (systemHandleInfo) was located for scoped inspection"
else
  bad "could not locate the systemHandleInfo handler — the scoped pins above are vacuous"
fi

if [ -n "$(info_body | grep -F 'services.CpuSamplerProcessCount()')" ]; then
  ok "the process count comes from a cheap /proc listing"
else
  bad "process_count is sourced some other way — check it does not refresh per-process stats"
fi

# The sampler must not reintroduce the cost it exists to remove: one sample is
# the aggregate /proc/stat line and does not appear in its own numbers.
SAMPLE_PATH="$(fnb "$SAMPLER" Spawn; fnb "$SAMPLER" cpuSamplerRead)"
if grep -qF 'cpu.Times(false)' <<< "$SAMPLE_PATH" && ! grep -qE 'cpu\.Times\(true\)|cpu\.Percent' <<< "$SAMPLE_PATH"; then
  ok "the sampler reads only the aggregate CPU line (cpu.Times(false))"
else
  bad "the sampler reads more than the aggregate CPU line — it will show up in its own measurement"
fi
if [ -z "$(fnb "$SAMPLER" Spawn)" ]; then
  bad "could not locate CpuSampler.Spawn — the no-process-walk pin is vacuous"
elif grep -qE 'process\.|ReadDir|CpuSamplerProcessCount' <<< "$SAMPLE_PATH"; then
  bad "the sampler walks processes — it now contaminates the window it owns"
else
  ok "the sampler does not walk processes"
fi

echo
echo "── 3. C3: the window is fixed, and above the interval sysinfo silently skips ──"

if has "$SAMPLER" "CpuSamplerSampleInterval"; then
  ok "the sampling window is a named constant, not an incidental gap"
else
  bad "no CpuSamplerSampleInterval — the window is implicit again"
fi

# Pin the INVARIANT (window > the 200 ms floor the Rust sampler inherited
# from sysinfo's MINIMUM_CPU_UPDATE_INTERVAL), not the literal value, so
# tuning the cadence is allowed and breaking the guarantee is not.
check_duration_above_200ms() {
  local name="$1" line ms
  line=$(code "$SAMPLER" | grep -E "^const $name = [0-9]+ \* time\.(Second|Millisecond)" | head -1)
  if [ -z "$line" ]; then bad "$name is not a Duration literal — cannot verify it clears the 200 ms threshold"; return; fi
  ms=$(printf '%s' "$line" | sed -n 's/.*= \([0-9]*\) \* time\..*/\1/p')
  case "$line" in *time.Second*) ms=$((ms * 1000)) ;; esac
  if [ -n "$ms" ] && [ "$ms" -gt 200 ]; then
    ok "$name is ${ms}ms — above the 200ms threshold"
  else
    bad "$name is '${ms:-unparsed}'ms — at or below 200ms the delta is noise / a stale window"
  fi
}
check_duration_above_200ms "CpuSamplerSampleInterval"
check_duration_above_200ms "cpuSamplerPrimeDelay"

if has "$MAIN" "services.NewCpuSampler()" && hasre "$MAIN" '^[[:space:]]*cpu\.Spawn\(\)'; then
  ok "main.go creates and spawns the sampler"
else
  bad "the sampler is never spawned — every reader gets 0.0 forever"
fi
if hasre "$APPSTATE" '^[[:space:]]*Cpu[[:space:]]+\*services\.CpuSampler'; then
  ok "State carries the sampler so handlers can read it without refreshing"
else
  bad "State has no sampler handle"
fi

echo
echo "── 4. C4: the fleet check-in reports a measurement, not its own /proc walk ──"

if hasre "$PHONE" "$CPU_DELTA_RE"; then
  bad "phone_home computes its own CPU delta — that number is mostly its own work, and it drives the Servers page and CPU alerts"
else
  ok "phone_home does not compute CPU for itself"
fi
if [ -n "$(fnb "$PHONE" phoneHomeCollectSystemInfo | grep -F '"cpu_usage":' | grep -F 'c.Usage()')" ]; then
  ok "phone_home reports the sampled value"
else
  bad "phone_home no longer reports the sampled value"
fi
# System::new_all()/refresh_all() was the specific pairing that produced
# 4.5%-22.1% on an idle box; the Go equivalent is a full process walk.
if hasre "$PHONE" 'process\.(Processes|Pids)\('; then
  bad "phone_home walks every process again — a full /proc walk whose cost becomes the CPU reading"
else
  ok "phone_home does not walk every process"
fi

echo
echo "── 5. the gauge and the chart still share one source ──"

# They diverged visibly (99% vs 9.7%) and that divergence was the tell. Both
# must keep reading the same endpoint, or a future defect can hide in the gap.
if has "$COLLECTOR" "/system/info" && has "$COLLECTOR" "cpu_usage"; then
  ok "the history collector still reads cpu_usage from /system/info"
else
  bad "the 24h chart no longer shares a source with the gauge — they can now disagree undetectably"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
