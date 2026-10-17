#!/usr/bin/env bash
# git-clone-ssrf-pin-e2e.sh — s442
#
# ONE PROPERTY: before THIS process (the agent, panel/go/internal/agent) invokes a `git clone`/
# subprocess against a caller-supplied `repo_url`, it resolves that host
# itself and refuses an internal/private address.
#
# The panel API's own repo_url check (helpers.rs::validate_repo_url_not_internal,
# Go: panel/go/internal/api core_helpers) already
# checks `git_deploys.repo_url` — but it runs on the PANEL host, at WRITE
# time. The actual clone is dispatched later (immediately, on a scheduled
# pull, or on a redeploy — an unbounded interval) to THIS process, on a
# DIFFERENT host, via a plain `git clone`/`git fetch` subprocess with no
# validation of its own. A DNS answer that differs between "how the panel
# resolved this hostname" and "how this fleet member resolves it right now"
# sails straight through untouched — the two checks don't even share a
# network vantage point, let alone a moment in time. This is the exact class
# `helpers.rs`'s `resolve_validated`/`pinned_client` were built to close for
# `reqwest` call sites; a subprocess `git clone` has no equivalent hook, so
# the guard here is the same resolve-then-check pattern the codebase already
# accepts for `check_tcp`/`check_ping` (see ssrf_guard.rs's own module docs
# for the full reasoning and its accepted residual TOCTOU window; Go:
# panel/go/internal/agent/services/ssrf_guard.go).
#
# Reachable via THREE independent code paths, all agent-side and none
# previously guarded: `POST /git/clone` -> git_build.go::GitBuildCloneOrPull,
# `POST /deploy/run` -> deploy.go::DeployCloneOrPull, and `POST /deploy/atomic`
# -> deploy.go::DeployAtomic (its own inline clone, not a clone_or_pull
# call at all).
#
# §A the ssrf_guard module exists, is registered, and carries every
#    internal-address range this class of guard needs (including the cloud
#    metadata block, the most commonly abused SSRF target).
# §B the guard parses with net/url (https/http/ssh repo_urls; the scp-like
#    git@host:path shorthand is hand-parsed).
# §C all three reachable clone paths call the guard.
# §D position: the guard runs BEFORE the git subprocess is spawned, in
#    every one of the three functions.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  agent git-clone SSRF/DNS-rebind guard — source pins (s442)"
echo "=================================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

code() {
  [ -f "$1" ] || return 0
  perl -0777 -pe '
    s{/\*.*?\*/}{}gs;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

has()  { grep -qE -- "$2" <<< "$1"; }

fnbody() {
  awk -v fn="$2" '
    !started && (index($0, "func " fn "(") || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) { started=1 }
    started {
      n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth += n - m; print
      if (opened || n>0) opened=1
      if (opened && depth<=0) exit
    }
  ' <<< "$1"
}

offset() {
  local body="$1" needle="$2"
  local head="${body%%"$needle"*}"
  if [ "$head" = "$body" ]; then
    echo -1
  else
    echo "${#head}"
  fi
}

before() {
  local body="$1" first="$2" second="$3"
  local o1 o2
  o1=$(offset "$body" "$first")
  o2=$(offset "$body" "$second")
  [ "$o1" != -1 ] && [ "$o2" != -1 ] && [ "$o1" -lt "$o2" ]
}

S=panel/go/internal/agent/services
GUARD=$S/ssrf_guard.go
GUARD_C=$(code "$GUARD")
GITBUILD=$S/git_build.go
GITBUILD_C=$(code "$GITBUILD")
DEPLOY=$S/deploy.go
DEPLOY_C=$(code "$DEPLOY")

GB_CLONE_BODY=$(fnbody "$GITBUILD_C" "GitBuildCloneOrPull")
DEP_CLONE_BODY=$(fnbody "$DEPLOY_C" "DeployCloneOrPull")
DEP_ATOMIC_BODY=$(fnbody "$DEPLOY_C" "DeployAtomic")

# ── §A the guard module exists and covers the internal-address ranges ────
echo "── §A ssrf_guard exists and knows the ranges that matter most ──"

if [ -f "$GUARD" ]; then
  ok "A1 $GUARD exists"
else
  bad "A1 $GUARD is missing — every arm below measures nothing"
fi

if has "$GUARD_C" '^func SsrfGuardValidateRepoURLNotInternal\(raw string\) error'; then
  ok "A2 SsrfGuardValidateRepoURLNotInternal is an exported entry point"
else
  bad "A2 no exported SsrfGuardValidateRepoURLNotInternal in ssrf_guard.go"
fi

# A3-A6 retired: covered by TestSsrfGuardV4InternalRanges + TestSsrfGuardV6InternalRanges (panel/go/internal/agent/services/ssrf_guard_test.go) — loopback/private/link-local/169.254 metadata/CGNAT/IPv6
# A7 retired: covered by TestSsrfGuardResolvedPrivateAddressesRejected (panel/go/internal/agent/services/ssrf_guard_test.go) — a hostname resolving internal is refused
# ── §B the guard can parse repo_url ───────────────────────────────────────
echo "── §B ssrf_guard parses repo_url with net/url ──"

if has "$GUARD_C" '"net/url"' && has "$GUARD_C" 'url\.Parse\(raw\)'; then
  ok "B1 ssrf_guard.go parses the repo_url authority with net/url"
else
  bad "B1 ssrf_guard.go no longer parses with net/url — host extraction may be hand-rolled"
fi

# B2 retired: covered by TestSsrfGuardRepoURLAuthorityParsesEveryShape (panel/go/internal/agent/services/ssrf_guard_test.go) — git@host:path shorthand

# C1 retired (obsolete in Go): every .go file in package services is compiled in; there is no mod.rs registration to forget

# ── §D all three reachable clone paths call the guard, in position ────────
echo "── §D all 3 reachable clone paths call the guard BEFORE spawning git ──"

GUARD_CALL='if err := SsrfGuardValidateRepoURLNotInternal\(repoURL\); err != nil \{'
if has "$GB_CLONE_BODY" "$GUARD_CALL"; then
  ok "D1 git_build.go::GitBuildCloneOrPull calls the guard"
else
  bad "D1 git_build.go::GitBuildCloneOrPull does not call the guard"
fi

if before "$GB_CLONE_BODY" "SsrfGuardValidateRepoURLNotInternal" "deployRun("; then
  ok "D2 git_build.go::GitBuildCloneOrPull validates before spawning the git subprocess"
else
  bad "D2 git_build.go::GitBuildCloneOrPull's guard runs after (or never before) the subprocess spawn"
fi

if has "$DEP_CLONE_BODY" "$GUARD_CALL"; then
  ok "D3 deploy.go::DeployCloneOrPull calls the guard"
else
  bad "D3 deploy.go::DeployCloneOrPull does not call the guard"
fi

if before "$DEP_CLONE_BODY" "SsrfGuardValidateRepoURLNotInternal" "deployRun("; then
  ok "D4 deploy.go::DeployCloneOrPull validates before spawning the git subprocess"
else
  bad "D4 deploy.go::DeployCloneOrPull's guard runs after (or never before) the subprocess spawn"
fi

if has "$DEP_ATOMIC_BODY" "$GUARD_CALL"; then
  ok "D5 deploy.go::DeployAtomic calls the guard (its own inline clone, not a clone_or_pull call)"
else
  bad "D5 deploy.go::DeployAtomic does not call the guard — its inline clone would stay unguarded"
fi

if before "$DEP_ATOMIC_BODY" "SsrfGuardValidateRepoURLNotInternal" "deployRun("; then
  ok "D6 deploy.go::DeployAtomic validates before spawning the git subprocess"
else
  bad "D6 deploy.go::DeployAtomic's guard runs after (or never before) the subprocess spawn"
fi

echo
echo "=================================================="
echo "  PASS=$PASS FAIL=$FAIL"
echo "=================================================="

[ "$FAIL" -eq 0 ]
