#!/usr/bin/env bash
# Regression pins for the s429 dockpanel-fanout follow-up: a cron/shell-command
# chaining bypass (root RCE) and an unauthenticated Dozzle-sidecar access gap.
#
# 1. CRON/SHELL-COMMAND CHAINING BYPASS (CRITICAL). is_safe_cron_command
#    (the agent's services/command_filter) and the backend's
#    is_safe_shell_command (the backend's routes/mod, shared by cron,
#    pre_build_cmd, post_deploy_cmd) only rejected "; " (semicolon+space) and
#    verb-anchored "|sh"/"|bash"/"| sh"/"| bash" — a bare `;` or bare `|` with
#    no trailing space/verb ("id;whoami", "id|whoami") passed both filters
#    cleanly. The command reaches `crontab -u root -` (root's real crontab)
#    and POST /crons/run executes it via `bash -c` immediately, as the agent
#    (unsandboxed root). Reachable by an ordinary NON-ADMIN site owner via
#    SITE_CALLER_PREDICATE, not just an admin. Verified live with real PoC
#    strings by both the finder and an independent skeptic before the fix
#    landed. Fix: reject any bare `;`, and reject any run of `|` whose length
#    isn't exactly 2 — `&&`/`||` remain explicitly allowed (the whole reason
#    this isn't a blanket metacharacter ban). Mutation-tested: the paired Rust
#    unit tests (command_filter.rs, routes/mod.rs) were confirmed red against
#    the pre-fix logic before being confirmed green against the fix.
#
# 2. DOZZLE SIDECAR: UNAUTHENTICATED ACCESS TO EVERY CONTAINER ON THE SHARED
#    HOST (CRITICAL). The v2.179.0 docker-socket-proxy sidecar correctly
#    restricts WHAT Dozzle can ask the Docker daemon (deny-by-default ACL,
#    CONTAINERS=1/EVENTS=1/INFO=1 only) but nothing gated WHO could reach
#    Dozzle itself. Deploying the template with a domain — the panel's own
#    advertised one-click, DNS-automated primary use case — produced a fully
#    public page that lists and inspects every container on the shared Docker
#    host, including plaintext env vars (DB passwords, JWT secrets, ...) for
#    every OTHER project sharing the box. Proven with real evidence from this
#    box's own running containers during the audit. Dozzle's own real auth
#    (verified against its own docs, not guessed) needs either a mounted
#    users.yml with a bcrypt hash inside, or forward-proxy headers — no
#    pure-env-var auth exists, so the fix cannot be "add a required env var
#    to the template." Fixed by forcing nginx auth_basic on the domain at
#    deploy time for any TEMPLATE_SIDECAR-backed app, reusing the same
#    htpasswd mechanism Sites' own password-protect feature already uses.
#
# These are SOURCE pins and need no running panel.
#
# 3. THE #1 FIX WAS ITSELF INCOMPLETE (s430 dockpanel-fanout completeness
#    critic, CRITICAL, found HOURS after the fix above shipped). `;` and `|`
#    were closed but the third POSIX chaining operator, bare `&`, was never
#    checked by either function — "id&whoami" passed both gates clean, with
#    the identical reachability (non-admin site owner -> save cron -> run now
#    -> `bash -c` as the agent). Proven by compiling and executing standalone
#    copies of both functions outside the repo, with the `;`/`|` REJECT
#    behavior kept as controls to prove the reproduction was faithful to the
#    patched source. Same remedy shape: reject any run of `&` whose length
#    isn't exactly 2 (`&&` stays legitimate). Mutation-tested the same way as
#    fix #1: a targeted in-place revert (not a whole-file git stash, since the
#    new tests live in the same two files as the fix) confirmed both new
#    tests red against the disabled guard, then green against the restored one.
#
# Go port: CommandFilterIsSafeCronCommand in
# panel/go/internal/agent/services/command_filter.go, isSafeShellCommand in
# panel/go/internal/api/core_router.go, the Dozzle protection in
# panel/go/internal/api/rt_docker_apps.go::rtDockerAppsDeployTask. The filter
# behaviour is pinned by running the ported Go regression tests; the source
# arms that only restated it are retired to those tests.
#
#   run: bash tests/chain-operator-bypass-pin-e2e.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CMDFILTER="$REPO/panel/go/internal/agent/services/command_filter.go"
BACKEND_MOD="$REPO/panel/go/internal/api/core_router.go"
DOCKER_APPS_BACKEND="$REPO/panel/go/internal/api/rt_docker_apps.go"
for f in "$CMDFILTER" "$BACKEND_MOD" "$DOCKER_APPS_BACKEND"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
has()   { grep -q  -- "$2" "$1" 2>/dev/null && ok "$3" || bad "$3"; }
hasE()  { grep -qE -- "$2" "$1" 2>/dev/null && ok "$3" || bad "$3"; }
hasNot()  { grep -q  -- "$2" "$1" 2>/dev/null && bad "$3" || ok "$3"; }
# Run named Go tests; pass only if every one of them ran and passed.
gotest() {
  local pkg="$1" re="$2" label="$3" out want got
  out=$(cd "$REPO/panel/go" && go test "./$pkg/" -count=1 -run "^($re)\$" -v 2>&1)
  want=$(tr '|' '\n' <<< "$re" | grep -c .)
  got=$(grep -cE '^--- PASS' <<< "$out")
  if [ "$got" -eq "$want" ] && ! grep -qE '^(--- FAIL|FAIL)' <<< "$out"; then
    ok "$label ($got/$want passed)"
  else
    bad "$label: $got/$want passed — $(grep -E '^(--- FAIL|FAIL|.*undefined)' <<< "$out" | head -3 | tr '\n' ' ')"
  fi
}

echo "== A. cron chaining bypass: bare ; and bare | are rejected, && / || kept =="

# A1 retired: covered by TestCommandFilterCronBareChainOperatorsRejectedPairedKept (panel/go/internal/agent/services/command_filter_test.go) — bare ; rejected
# A2 retired: covered by TestCommandFilterCronBareChainOperatorsRejectedPairedKept (panel/go/internal/agent/services/command_filter_test.go) — runs of | must be exactly a pair
gotest internal/agent/services 'TestCommandFilterCronBareChainOperatorsRejectedPairedKept' \
  "the bypass PoC strings (id;whoami, id|whoami, a|||b) are refused and && / || kept — regression test passes"

echo
echo "== B. backend isSafeShellCommand carries the identical fix (cron/pre_build_cmd/post_deploy_cmd save-time gate) =="

# B1 retired: covered by TestShellCommandRejectsBareChainOperators (panel/go/internal/api/core_router_test.go) — bare ; rejected
# B2 retired: covered by TestShellCommandRejectsBareChainOperators (panel/go/internal/api/core_router_test.go) — runs of | must be exactly a pair
gotest internal/api 'TestShellCommandRejectsBareChainOperators' \
  "the backend refuses the same ; | & PoC strings and keeps && / || — regression test passes"

echo
echo "== B2. the & bypass the first fix missed: bare & is now rejected, && kept =="

# B2-agent-scan retired: covered by TestCommandFilterCronBareAmpersandRejectedPairedKept (panel/go/internal/agent/services/command_filter_test.go)
# B2-backend-scan / B2-backend-test retired: covered by TestShellCommandRejectsBareChainOperators (panel/go/internal/api/core_router_test.go), which carries the & PoC strings (run in §B)
gotest internal/agent/services 'TestCommandFilterCronBareAmpersandRejectedPairedKept' \
  "the & bypass PoC strings (id&whoami, a&&&b) are refused and && kept — regression test passes"

echo
echo "== C. Dozzle sidecar: forced nginx password-protection on deploy =="

has "$DOCKER_APPS_BACKEND" 'var rtDockerAppsSidecarTemplates = \[\]string{"dozzle"}' \
  "the deploy handler names dozzle as a sidecar-backed template needing forced protection"
has "$DOCKER_APPS_BACKEND" 'agent.Post(ctx, "/nginx/password-protect"' \
  "deploying a sidecar template calls the agent's nginx password-protect endpoint directly"
hasE "$DOCKER_APPS_BACKEND" 'isSidecar = isSidecar \|\| t == j\.template' \
  "the protection call is gated on the deployed template actually being in rtDockerAppsSidecarTemplates"
hasE "$DOCKER_APPS_BACKEND" '^[[:space:]]*if isSidecar && j\.domain != nil \{' \
  "protection is only attempted when a domain is actually being bound"
has "$DOCKER_APPS_BACKEND" 'SystemLogLogEvent(ctx, db, "warning", "api",' \
  "the generated credentials are also logged to System Logs as a durable backup, not shown once with no recovery path"
hasE "$DOCKER_APPS_BACKEND" 'emit\("auth", "Password-protecting the app", "error"' \
  "a failed protection call surfaces as an explicit error step, not a silent no-op"

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
