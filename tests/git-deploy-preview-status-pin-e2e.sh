#!/usr/bin/env bash
#
# Regression pin for GitHub #109's echo and the s484 Mode B research pass —
# "PR/branch preview deployments have no GitHub status link-back."
#
# `handle_preview_deploy` (git_deploys.rs) has always been a fully-built preview
# system: an isolated container per branch, a subdomain, TTL auto-cleanup, and
# hardened ownership since v2.53-2.55. Regular and scheduled deploys have called
# `set_github_status` at 9 sites since it existed — a pending status when the
# work starts, success or failure when it ends — so GitHub's own commit/PR view
# shows a status check with a link to the result. The preview path never called
# it at all: a preview built, deployed, and got a subdomain, but the one place a
# pusher would look — GitHub's own UI — never heard about any of it.
#
# This is a s484 research-pass finding, not a reporter's own report: the initial
# research framed "no preview-env concept at all" as the gap (wrong — the whole
# preview system already existed), and grep-first verification against current
# source found the real, narrow gap is exactly this missing call.
#
# Five call sites had to gain the wiring, and this pin holds each of them: a
# pending status before the clone starts, a failure status on clone failure, on
# build failure, on the TLS-readiness refusal, and on the final deploy call's own
# failure — plus a success status when the deploy succeeds. All six share ONE
# target URL, computed once up front from the SAME `deploy_url` helper every
# other call site uses, so a preview link can never carry a hardcoded scheme.
#
# Go port: panel/go/internal/api/rt_git_deploys.go::rtGitDeploysHandlePreviewDeploy.
# The Go port routes all six calls through ONE local `status(sha, state)`
# closure that holds the token guard and the shared githubTarget, so the arms
# below count closure call sites and pin the closure's single
# rtGitDeploysSetGithubStatus call instead of six inline guarded calls.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

ROUTE=panel/go/internal/api/rt_git_deploys.go
[ -f "$ROUTE" ] || { echo "missing $ROUTE"; exit 1; }

# Whole-line Go comments only (a trailing-// strip would eat "https://…").
strip() { grep -vE '^[[:space:]]*//' "$1"; }
SRC=$(strip "$ROUTE")

has()  { grep -q  -- "$2" <<< "$1"; }
hasE() { grep -qE -- "$2" <<< "$1"; }
# Bounded to ONE func body via brace balance, not a bare /pat/,/^}/ range —
# the body holds nested closures (`go func() {`) that a naive stop mis-reads.
fnbody() {
  awk -v fn="$2" '
    BEGIN { depth = 0; found = 0 }
    !found && index($0, "func " fn "(") == 1 { found = 1 }
    found {
      print
      n = gsub(/\{/, "{"); depth += n
      n = gsub(/\}/, "}"); depth -= n
      if (depth <= 0 && depth_started) exit
      if (depth > 0) depth_started = 1
    }
  ' <<< "$1"
}

HPD=$(fnbody "$SRC" rtGitDeploysHandlePreviewDeploy)
# Call sites of the local status closure (not its own `status := func(` line).
CALLS=$(grep -oE '(^|[^A-Za-z0-9_.])status\((commitHash|"HEAD"), "[a-z]+"\)' <<< "$HPD")

echo
echo "§1 the preview path can even find the function"

if [ -n "$HPD" ]; then
  ok "rtGitDeploysHandlePreviewDeploy is present and readable"
else
  bad "could not read rtGitDeploysHandlePreviewDeploy's body — every other arm means nothing"
fi

echo
echo "§2 a status call exists at every outcome, not just one"

status_calls=$(grep -c . <<< "$CALLS")
if [ "$status_calls" -ge 6 ]; then
  ok "at least 6 status call sites inside the preview path (found $status_calls)"
else
  bad "expected >= 6 status(…) calls inside rtGitDeploysHandlePreviewDeploy, found $status_calls"
fi

if hasE "$CALLS" '"pending"'; then
  ok "a pending status is posted before the clone starts"
else
  bad "no pending status call — GitHub never learns a preview started"
fi

if hasE "$CALLS" '"success"'; then
  ok "a success status is posted when the deploy succeeds"
else
  bad "no success status call on the deploy-success path"
fi

failure_calls=$(grep -c '"failure"' <<< "$CALLS")
if [ "$failure_calls" -ge 4 ]; then
  ok "a failure status is posted on at least 4 distinct failure paths (found $failure_calls)"
else
  bad "expected >= 4 failure-status calls (clone/build/tls-refusal/deploy), found $failure_calls"
fi

echo
echo "§3 every call carries a real link, built the one way this file allows"

if hasE "$HPD" 'githubTarget = rtGitDeploysPtr\(rtGitDeploysDeployURL\(\*previewDomain, mode\)\)'; then
  ok "the target URL is computed once via rtGitDeploysDeployURL(), not re-derived per call site"
else
  bad "githubTarget is not built through rtGitDeploysDeployURL() — a hardcoded scheme could creep back in"
fi

set_calls=$(grep -c 'rtGitDeploysSetGithubStatus(' <<< "$HPD")
if [ "$set_calls" -eq 1 ] && hasE "$HPD" 'rtGitDeploysSetGithubStatus\([^)]*, githubTarget\)'; then
  ok "every status call goes through the one closure that passes the shared githubTarget"
else
  bad "expected exactly 1 rtGitDeploysSetGithubStatus(…, githubTarget) (inside the status closure), found $set_calls — a call site may bypass the shared target/guard"
fi

echo
echo "§4 the token is only ever read from config, and only sent when present"

if hasE "$HPD" 'hasToken := cfg\.GithubToken != nil && \*cfg\.GithubToken != ""'; then
  ok "the token is read from config once, and its non-empty check is computed alongside"
else
  bad "the GitHub token is not sourced from cfg.GithubToken (with a non-empty check) — check for a different origin"
fi

CLOSURE=$(awk '/status := func\(sha, state string\) \{/{p=1} p{print} p && /^\t\}/{exit}' <<< "$HPD")
if grep -qF 'if hasToken {' <<< "$CLOSURE" && grep -qF 'rtGitDeploysSetGithubStatus(*cfg.GithubToken' <<< "$CLOSURE"; then
  ok "the status closure (the only caller) guards on a non-empty token before sending"
else
  bad "the status closure no longer guards on hasToken — a call could fire with no token"
fi

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
