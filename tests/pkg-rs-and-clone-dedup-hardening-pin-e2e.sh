#!/usr/bin/env bash
# Regression pins for the s459 small-carries bundle: a session picked
# specifically because it had been declined at the opener 3 sessions running
# (the standing rotation kept winning instead) — no finder/skeptic fan-out
# this time, just implementing already-diagnosed carries.
#
#   F1  pkg.rs had 4 sites wrapping the SANDBOXED safe_command(...) builder
#       in a tokio::time::timeout with no kill_on_drop(true) — the
#       established timeout-orphan class this project has now fixed 9x
#       elsewhere, never swept in this specific file's safe_command() (as
#       opposed to safe_command_unsandboxed()) call sites: installed_php_
#       version, php_streams, run_ok, which. Fixed: kill_on_drop(true) added
#       to each.
#   F2  The harder, 9-session-carried fix: safe_command_unsandboxed()'s
#       systemd-run --wait timeout only ever killed the LOCAL waiting
#       client — the remote transient unit it started runs in its own
#       cgroup, fully decoupled, and kept running orphaned forever on
#       timeout (live-proven in a prior session). Fixed: a new
#       UnsandboxedCommand::output_with_timeout() in safe_cmd.rs assigns the
#       transient unit a caller-known name via --unit=NAME (composes with
#       --collect, which only means "GC on exit", not naming), and on
#       timeout fires a best-effort, un-awaited `systemctl stop --no-block
#       <unit>` before returning an operator-actionable error naming the
#       unit. All 6 of pkg.rs's safe_command_unsandboxed(...) call sites
#       (enable_php_stream, transact's main transaction, transact's
#       autoremove, refresh_index, escape_hatch_works, add_repo) converted
#       from an external tokio::time::timeout wrapper to this method.
#       spawn_streaming() (the live-log-streaming path) deliberately left
#       untouched — different completion semantics, out of scope.
#   F3  routes/nginx.rs::clone_site reimplemented, inline, the exact same
#       rsync+chown-split logic as services/staging.rs::clone_files (a
#       second implementation of the same "clone a site's files" feature,
#       carried as known duplication since s456). Fixed: clone_site now
#       delegates the copy+chown work to clone_files, keeping only its own
#       du -sb size computation and JSON response as route-specific code.
#   F4  install-agent.sh's firewall-port-opening step checked `command -v
#       ufw` before checking firewalld's actual active state — the inverse
#       of the check order setup.sh's own detect_firewall() already uses,
#       and the same split-brain class (s265) this project has fixed
#       everywhere else: a box with ufw merely INSTALLED but firewalld
#       ACTUALLY ENFORCING would silently configure the firewall nobody is
#       using. Fixed: check `firewall-cmd --state` first, matching setup.sh.
#
# REPOINTED TO THE GO PORT (panel/go): pkg.rs → internal/agent/services/pkg.go,
# safe_cmd.rs → internal/agent/safecmd/safecmd.go, routes/nginx.rs →
# internal/agent/routes/nginx.go, staging.rs → services/staging.go. F1's
# kill_on_drop(true) is, in Go, a child built with safecmd.Exec on a ctx from
# context.WithTimeout (exec.CommandContext SIGKILLs it at the deadline — see
# TestPinTimeoutOrphanKillOnDropKillsTheChild). F2's output_with_timeout is
# (*Unsandboxed).OutputWithTimeout; insert_unit_arg's argv behaviour is pinned
# by the Go test TestUnitArgPlacementAndNames.
#
# Pure source analysis (plus one `go test`); no box, no network.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Strip comment lines (Go tests live in *_test.go, so no test module to cut).
code() { grep -vE '^[[:space:]]*(//|\*|/\*)' "$1"; }
has()   { [ -n "$(code "$1" | grep -F -- "$2")" ]; }
hasre() { [ -n "$(code "$1" | grep -E -- "$2")" ]; }

# One Go function's body, comment-stripped, keyed on its LITERAL signature
# prefix ("func Name(" or "func (u *T) Name("). Go methods are top-level, so
# the column-0 `}` bounds them exactly — the Rust impl-block over-capture
# caveat is gone.
fnbody()    { code "$1" | awk -v fn="$2" 'index($0, fn) == 1 {f=1} f {print} f && /^}/ {exit}'; }
bodyhas()   { [ -n "$(fnbody "$1" "$2" | grep -F -- "$3")" ]; }
bodyhasre() { [ -n "$(fnbody "$1" "$2" | grep -E -- "$3")" ]; }

GA=panel/go/internal/agent
PKG=$GA/services/pkg.go
SAFE_CMD=$GA/safecmd/safecmd.go
NGINX_ROUTE=$GA/routes/nginx.go
STAGING=$GA/services/staging.go
INSTALL_AGENT_SH=scripts/install-agent.sh

for f in "$PKG" "$SAFE_CMD" "$NGINX_ROUTE" "$STAGING" "$INSTALL_AGENT_SH"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

echo "── 1. F1: the 4 sandboxed safecmd.Exec sites in pkg.go run on a deadline ctx (the Go kill_on_drop) ──"
for fn in "func PkgInstalledPhpVersion(" "func PkgPhpStreams(" "func pkgRunOK(" "func pkgWhich("; do
  if bodyhasre "$PKG" "$fn" 'ctx, cancel := context\.WithTimeout\(' && bodyhasre "$PKG" "$fn" 'safecmd\.Exec\(ctx, '; then
    ok "${fn#func }) builds its child on a context.WithTimeout ctx"
  else
    bad "${fn#func }) runs its child without a deadline ctx — a timeout no longer kills it"
  fi
done
# Whole-file count control: exactly 4 sandboxed safecmd.Exec/Command sites in
# pkg.go and 4 context.WithTimeout — a site added without a deadline, or one
# silently dropped, changes one of these counts.
SB_COUNT=$(code "$PKG" | grep -Ec 'safecmd\.(Exec|Command)\(')
WT_COUNT=$(code "$PKG" | grep -Fc 'context.WithTimeout(')
if [ "$SB_COUNT" -eq 4 ] && [ "$WT_COUNT" -eq 4 ]; then
  ok "pkg.go has exactly 4 sandboxed child sites and 4 context.WithTimeout deadlines"
else
  bad "pkg.go has $SB_COUNT sandboxed child sites and $WT_COUNT WithTimeout deadlines, expected 4/4 — a site was added or removed"
fi

echo
echo "── 2. F2: safecmd.go has OutputWithTimeout() + insertUnitArg(), used everywhere ──"
OWT='func (u *Unsandboxed) OutputWithTimeout('
if has "$SAFE_CMD" "$OWT"; then
  ok "(*Unsandboxed).OutputWithTimeout exists"
else
  bad "OutputWithTimeout is missing"
fi
# insert_unit_arg signature arm retired (obsolete in Go): the method's shape is compiler-checked at its one caller
# insert_unit_arg scans-for-'--' arm retired: covered by TestUnitArgPlacementAndNames (panel/go/internal/agent/safecmd/safecmd_test.go)
# insert_unit_arg inserts --unit= arm retired: covered by TestUnitArgPlacementAndNames (safecmd_test.go)
if (cd panel/go && go test ./internal/agent/safecmd/ -count=1 -run '^TestUnitArgPlacementAndNames$' >/dev/null 2>&1); then
  ok "insertUnitArg places --unit=<unique name> immediately before the -- separator, whatever the env prefix (Go test)"
else
  bad "TestUnitArgPlacementAndNames fails — the unit naming may have regressed to a fixed-index insert"
fi
if bodyhas "$SAFE_CMD" "$OWT" 'binary, unit := u.insertUnitArg()'; then
  ok "OutputWithTimeout actually calls insertUnitArg on its own argv"
else
  bad "OutputWithTimeout no longer calls insertUnitArg — the unit-naming fix may be dead code"
fi
if bodyhas "$SAFE_CMD" "$OWT" '"systemctl", "stop", "--no-block", unit)'; then
  ok "the timeout branch runs systemctl stop --no-block on the named unit"
else
  bad "the timeout branch no longer stops the named unit — the remote-unit-orphan bug may have regressed"
fi
# The stop must be fire-and-forget (a goroutine, not run inline) so cleanup
# can never delay/mask the timeout error itself. Scoped to OutputWithTimeout's
# own body — SpawnStreaming has unrelated goroutines.
if [ -n "$(fnbody "$SAFE_CMD" "$OWT" | tr '\n\t' '  ' | grep -E 'go func\(\) \{[^}]*"systemctl", "stop", "--no-block", unit\)')" ]; then
  ok "the systemctl stop runs in a detached goroutine (fire-and-forget, does not block the timeout error)"
else
  bad "the systemctl stop no longer looks detached — may now block the caller on cleanup"
fi
# SpawnStreaming must be untouched — explicitly out of scope for this fix.
SPAWN_STREAMING_KOD=$(code "$SAFE_CMD" | grep -Fc 'func (u *Unsandboxed) SpawnStreaming(')
if [ "$SPAWN_STREAMING_KOD" -eq 1 ]; then
  ok "SpawnStreaming() is still present, unduplicated (control: out-of-scope surface untouched)"
else
  bad "SpawnStreaming() count is $SPAWN_STREAMING_KOD, expected 1 — check for accidental duplication/removal"
fi

echo
echo "── 3. F2: every safecmd.NewUnsandboxed(...) call site in pkg.go routes through OutputWithTimeout ──"
USC_COUNT=$(code "$PKG" | grep -Fc 'safecmd.NewUnsandboxed(')
OWT_COUNT=$(code "$PKG" | grep -Fc 'OutputWithTimeout(')
if [ "$USC_COUNT" -eq 6 ] && [ "$OWT_COUNT" -eq 6 ]; then
  ok "6 safecmd.NewUnsandboxed(...) call sites, 6 OutputWithTimeout(...) call sites — 1:1"
else
  bad "NewUnsandboxed count=$USC_COUNT, OutputWithTimeout count=$OWT_COUNT (expected 6/6) — a call site may have been added, removed, or left on the old external-timeout pattern"
fi
# Control: no leftover instance of the OLD pattern — an Unsandboxed run via
# plain .Output(ctx) under an external deadline, which kills only the local
# waiter. (The 6/6 count above is this absence arm's positive anchor.)
if hasre "$PKG" '\.Output\(ctx\)'; then
  bad "found an Unsandboxed .Output(ctx) in pkg.go — an external timeout there kills only the waiter; route it through OutputWithTimeout"
else
  ok "no leftover external-timeout-wrapping-raw-Output() pattern in pkg.go"
fi
for anchor in \
  "func PkgEnablePhpStream(" \
  "func pkgTransact(" \
  "func PkgRefreshIndex(" \
  "func pkgEscapeHatchWorks(" \
  "func PkgAddRepo("
do
  if bodyhasre "$PKG" "$anchor" 'OutputWithTimeout\('; then
    ok "${anchor#func }) now uses OutputWithTimeout"
  else
    bad "${anchor#func }) no longer calls OutputWithTimeout — may have regressed to the old pattern"
  fi
done

echo
echo "── 4. F3: nginx.go cloneSite delegates to staging.go StagingCloneFiles ──"
CS='func (n nginxRoutes) cloneSite('
if bodyhas "$NGINX_ROUTE" "$CS" "services.StagingCloneFiles(ctx, b.SourceDomain, b.TargetDomain)"; then
  ok "cloneSite calls services.StagingCloneFiles"
else
  bad "cloneSite no longer calls services.StagingCloneFiles — the dedup may have regressed"
fi
if bodyhasre "$NGINX_ROUTE" "$CS" '"rsync"'; then
  bad "cloneSite still has its own inline rsync call — the duplicate implementation was not actually removed"
else
  ok "cloneSite no longer runs its own inline rsync (control: real dedup, not just an added delegate call)"
fi
if bodyhasre "$NGINX_ROUTE" "$CS" 'www-data:www-data'; then
  bad "cloneSite still has its own inline chown-to-www-data logic — the duplicate implementation was not actually removed"
else
  ok "cloneSite no longer runs its own inline chown (control: chown logic now lives only in StagingCloneFiles)"
fi
# StagingCloneFiles itself must be untouched — the delegation target.
if hasre "$STAGING" '^func StagingCloneFiles\(ctx context\.Context, src, dst string\) \(string, error\)'; then
  ok "staging.go StagingCloneFiles signature is unchanged (control: delegation target untouched)"
else
  bad "staging.go StagingCloneFiles signature changed — re-check the delegation call still matches"
fi
# cloneSite's own post-copy work must still be present.
if bodyhas "$NGINX_ROUTE" "$CS" '"du", "-sb", targetDir'; then
  ok "cloneSite still computes size via du (control: route-specific tail preserved)"
else
  bad "cloneSite's own du -sb size computation is missing"
fi
echo
echo "── 5. F4: install-agent.sh checks firewalld's ACTIVE STATE before ufw ──"
if hasre "$INSTALL_AGENT_SH" 'firewall-cmd --state'; then
  ok "install-agent.sh checks firewall-cmd --state (actually enforcing), not just command -v"
else
  bad "install-agent.sh no longer checks firewall-cmd --state"
fi
# Order matters: the firewall-cmd branch must appear BEFORE the ufw branch
# in the firewall-port-opening block, so a box with both installed but only
# firewalld running is handled correctly.
FW_BLOCK_FILE=$(mktemp)
awk '/# Allow agent port through firewall/,/^fi$/' "$INSTALL_AGENT_SH" > "$FW_BLOCK_FILE"
FIREWALLD_LINE=$(grep -n 'firewall-cmd --state' "$FW_BLOCK_FILE" | head -1 | cut -d: -f1)
UFW_LINE=$(grep -n 'ufw allow' "$FW_BLOCK_FILE" | head -1 | cut -d: -f1)
rm -f "$FW_BLOCK_FILE"
if [ -n "$FIREWALLD_LINE" ] && [ -n "$UFW_LINE" ] && [ "$FIREWALLD_LINE" -lt "$UFW_LINE" ]; then
  ok "the firewalld --state check appears BEFORE the ufw allow line (correct precedence)"
else
  bad "could not confirm firewalld is checked before ufw (firewalld_line=$FIREWALLD_LINE, ufw_line=$UFW_LINE) — re-verify by hand"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
