#!/usr/bin/env bash
#
# Regression pin for issue #91 — "Migration from cPanel: Request failed (524)".
#
# Analysing a control-panel archive was done INLINE in the HTTP request. Walking
# a real cPanel account is minutes of work, and every gateway between the browser
# and the handler gives up sooner: Cloudflare at 100s, the nginx the installer
# writes at 300s, and the panel's own tower TimeoutLayer at 300s. The agent call
# was budgeted 600s. So the request was guaranteed to be torn down for exactly
# the archives the wizard exists to import, and the work carried on afterwards
# with nothing able to come back and report it.
#
# The reporter's error string is this repository's own: a Cloudflare error page
# carries no JSON, `res.json()` falls back to `{}`, and api.ts renders
# "Request failed (<status>)". Nothing about the analysis ever reached him.
#
# Four things had to become true, and this pin holds each of them:
#
#   1  The route ACCEPTS the job. It inserts the row, spawns, and answers 202 —
#      so no gateway is holding anything open, and raising a timeout somewhere is
#      no longer a thing anyone can be tempted to do instead.
#
#   2  The AGENT owns the ceiling on its own work, and the panel's budget sits
#      above it. Unpacking had no limit on either side of the socket, so the only
#      way the operation could end was a gateway hanging up. A caller timeout
#      below the callee's does not bound anything the callee did not already
#      bound — it only decides which side describes the outcome, and picks the
#      one that does not know it.
#
#   3  The verdict is DURABLE. It lives in the migrations row, not in the
#      request, so it survives the tab. What it cannot survive is the process,
#      because the work runs in a spawned task — hence a boot-time sweep, on the
#      argument that nothing is running at boot, so anything still claiming to be
#      is stale.
#
#   4  The browser POLLS the row and can pick up a run it did not start. Making
#      the state durable and then not reading it back would leave the operator
#      watching a run they can no longer see, which is the complaint.
#
# Go port: panel/go/internal/api/rt_migration.go (rtMigrationAnalyze,
# rtMigrationFinalizeAnalyzingOnStartup), called on boot from core_state.go's
# Serve; the agent's budget is panel/go/internal/agent/services/migration.go
# (migrationExtractTimeout, MigrationAnalyze); the request ceiling is
# core_router.go's traceTimeout (the tower TimeoutLayer's port).
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

ROUTE=panel/go/internal/api/rt_migration.go
SVC=panel/go/internal/agent/services/migration.go
MAIN=panel/go/internal/api/core_state.go
ROUTER=panel/go/internal/api/core_router.go
TSX=panel/frontend/src/pages/Migration.tsx
SETUP=scripts/setup.sh
for f in "$ROUTE" "$SVC" "$MAIN" "$ROUTER" "$TSX" "$SETUP"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

# Strip // line comments from the SUBJECT FILES before matching.
#
# Not for this suite's own header — that text is never searched. It is for the
# comments in the sources below, which explain these fixes at length and name the
# exact strings the arms look for. The negative arm in §1 forbids returning the
# agent's error to the caller; a future comment saying "this used to return
# agent_error" would satisfy it and report the fix as present while it was being
# removed. That is not hypothetical: it happened to update-rollback's negative
# pins, tripped by the paragraph written to explain them (lesson #110f).
#
# Measured: stripping changes no verdict at this commit. It is here for the edit
# that adds the comment, which is the edit it has to survive.
# Whole-line comments plus trailing `// …` not preceded by ':' (keeps "http://").
strip() { sed -E 's#^[[:space:]]*//.*$##; s#([^:])//.*#\1#' "$1"; }

SRC_ROUTE=$(strip "$ROUTE")
SRC_SVC=$(strip "$SVC")
SRC_MAIN=$(strip "$MAIN")
SRC_ROUTER=$(strip "$ROUTER")
SRC_TSX=$(strip "$TSX")
SRC_SETUP=$(sed 's:#.*::' "$SETUP")

# Match against text already in a variable, via a here-string — never a pipeline.
# `strip f | grep -q x` looks equivalent and is not: grep -q closes the pipe on
# its first match, the upstream sed takes SIGPIPE (141), and under `pipefail` the
# whole pipeline reports failure. Whether an arm went green then depended on which
# process finished first. See the same note in backup-lands-pin-e2e.sh, where it
# cost a rewrite.
has()  { grep -q  -- "$2" <<< "$1"; }
hasE() { grep -qE -- "$2" <<< "$1"; }
# One Go func's body, so an arm cannot be satisfied by a sibling.
fnbody() { awk "/^func (\\([^)]*\\) )?$2\\(/,/^}/" <<< "$1"; }

ANALYZE=$(fnbody "$SRC_ROUTE" rtMigrationAnalyze)

echo
echo "§1 the analysis is accepted, not performed"

if [ -n "$ANALYZE" ]; then
  ok "the analyze handler is present and readable"
else
  bad "could not read the analyze fn body — this pin's other arms mean nothing"
fi

if has "$ANALYZE" 'writeJSON(w, http.StatusAccepted, migration)'; then
  ok "analyze answers 202 Accepted"
else
  bad "analyze does not answer 202 — the caller is being made to wait for the work"
fi

if hasE "$ANALYZE" '^[[:space:]]*go func\(\) \{'; then
  ok "the work is handed to a spawned goroutine"
else
  bad "analyze has no go func() — the agent call is still inline in the request"
fi

# Order matters, not mere presence: an agent call ABOVE the spawn is still inline.
spawn_line=$(grep -nE '^[[:space:]]*go func\(\) \{' <<< "$ANALYZE" | head -1 | cut -d: -f1)
call_line=$(grep -n 'agent\.PostLong(' <<< "$ANALYZE" | head -1 | cut -d: -f1)
if [ -n "$spawn_line" ] && [ -n "$call_line" ] && [ "$call_line" -gt "$spawn_line" ]; then
  ok "the agent call sits inside the spawn, not in front of it"
else
  bad "the agent call is not inside the spawn (spawn@${spawn_line:-none} call@${call_line:-none})"
fi

# Negative: the handler must not convert an agent failure into a response, because
# by then there is no response left to convert it into. The reason belongs in the
# row, which is the only place anything reads it from now on. (Positive anchor:
# the agent call above was found in this same body.)
if [ -n "$call_line" ] && hasE "$ANALYZE" 'agentError\('; then
  bad "analyze still returns the agent error to the caller — that path answered before 202 existed"
elif [ -n "$call_line" ]; then
  ok "an agent failure is recorded rather than returned"
else
  bad "no agent call found in analyze — the negative arm has no subject"
fi

if has "$ANALYZE" "status = 'failed'" && has "$ANALYZE" '"error"'; then
  ok "the failure path writes the reason into the row"
else
  bad "nothing writes a failure reason — a failed analysis would poll forever"
fi

if has "$ANALYZE" "status = 'analyzed'" && has "$ANALYZE" 'inventory = \$1'; then
  ok "the success path writes the inventory into the row"
else
  bad "the success path does not store the inventory"
fi

echo
echo "§2 the agent owns the ceiling, and the panel's budget sits above it"

agent_budget=$(grep -oE 'const migrationExtractTimeout = [0-9]+ \* time\.Second' <<< "$SRC_SVC" | grep -oE '[0-9]+')
if [ -n "$agent_budget" ]; then
  ok "the agent declares its own extraction budget (${agent_budget}s)"
else
  bad "the agent has no extraction budget — unpacking is unbounded on the side doing the work"
fi

MA=$(fnbody "$SRC_SVC" MigrationAnalyze)
# Both extraction attempts — `tar xzf` and the plain-tar retry — must be bounded.
# The fallback is the path a non-gzip archive takes, so leaving it unbounded
# leaves the case that most needs a limit without one. Go: each attempt is the
# ctx-bound `extract(...)` closure, and each is followed by its own deadline
# check that hands off to the timeout branch — counted as calls, not mentions.
bounded=$(grep -cE '^[[:space:]]*out2?, err :?= extract\("x(z)?f"\)$' <<< "$MA")
deadline_checks=$(grep -cE '^[[:space:]]*if ctx\.Err\(\) != nil \{$' <<< "$MA")
if [ "$bounded" -eq 2 ] && [ "$deadline_checks" -eq 2 ] \
   && has "$MA" 'return safecmd.Exec(ctx, "tar", flags,'; then
  ok "both extraction attempts run under the extraction context"
else
  bad "$bounded of 2 extraction attempts (with $deadline_checks deadline checks) are bounded — the other can run forever"
fi

# And they must share ONE deadline. Two fresh budgets make the real worst case
# double the constant, which puts it back above the panel's budget — so the panel
# wins the race again and writes the contentless message this whole design exists
# to avoid.
if [ "$(grep -c 'context.WithTimeout(ctx, migrationExtractTimeout)' <<< "$MA")" -eq 1 ]; then
  ok "the two attempts share one deadline, so the constant is the true ceiling"
else
  bad "each attempt gets a fresh budget (or none) — the real worst case is twice the constant"
fi

# Rust needed kill_on_drop(true); in Go the child is spawned with
# exec.CommandContext under that ctx (safecmd.Exec), so expiry kills tar rather
# than merely abandoning it.
if grep -qF 'exec.CommandContext(ctx, binary, args...)' panel/go/internal/agent/safecmd/safecmd.go \
   && has "$MA" 'safecmd.Exec(ctx, "tar"'; then
  ok "a timed-out extraction is actually killed, not merely abandoned"
else
  bad "tar is not bound to the extraction context — a timed-out tar keeps running and keeps filling the disk"
fi

# Scoped to the timeout branches: both call timedOut(…), and timedOut removes the
# scratch tree — a file-wide RemoveAll count would be satisfied by unrelated cleanups.
TIMEDOUT=$(awk '/timedOut := func\(check string\) error \{/,/^\t\}/' <<< "$MA")
timeout_arms=$(grep -cE 'return MigrationInventory\{\}, timedOut\(' <<< "$MA")
if [ "$timeout_arms" -ge 2 ] && grep -qF 'os.RemoveAll(extractDir)' <<< "$TIMEDOUT"; then
  ok "each timeout branch removes its scratch directory ($timeout_arms of them, via timedOut)"
else
  bad "$timeout_arms timeout branch(es) clean up — a stopped extraction leaves its tree in /tmp"
fi

panel_budget=$(grep -oE 'const rtMigrationAnalyzeAgentTimeoutSecs uint64 = [0-9]+' <<< "$SRC_ROUTE" | grep -oE '[0-9]+$')
if [ -n "$panel_budget" ] && [ -n "$agent_budget" ] && [ "$panel_budget" -gt "$agent_budget" ]; then
  ok "the panel allows ${panel_budget}s, above the agent's ${agent_budget}s, so the agent errors first"
else
  bad "panel budget '${panel_budget:-none}' does not exceed agent budget '${agent_budget:-none}'"
fi

if has "$ANALYZE" 'rtMigrationAnalyzeAgentTimeoutSecs'; then
  ok "the analyze call uses that budget rather than a bare number"
else
  bad "analyze does not pass the declared budget to the agent call"
fi

echo
echo "§3 the verdict survives the process that produced it"

if has "$SRC_ROUTE" 'func rtMigrationFinalizeAnalyzingOnStartup('; then
  ok "a boot-time sweep for in-flight rows exists"
else
  bad "nothing closes out rows left mid-run by a restart — they stay 'analyzing' forever"
fi

SWEEP=$(fnbody "$SRC_ROUTE" rtMigrationFinalizeAnalyzingOnStartup)
if hasE "$SWEEP" '"analyzing"' && hasE "$SWEEP" '"importing"'; then
  ok "the sweep covers import as well as analysis — both have always spawned"
else
  bad "the sweep misses one of the two spawned states"
fi

# The two are not the same kind of interrupted work and must not be told the same
# thing. Analysis only reads the archive; an import writes vhosts, site rows and
# database containers one selection at a time, so "nothing was left half-done,
# start it again" is false there and the advice is unfollowable.
if [ "$(grep -c 'The panel restarted' <<< "$SWEEP")" -ge 2 ]; then
  ok "each swept status gets its own account of what the restart left behind"
else
  bad "one sentence covers both — it cannot be true of an import that mutates as it goes"
fi

if has "$(fnbody "$SRC_MAIN" Serve)" 'rtMigrationFinalizeAnalyzingOnStartup('; then
  ok "Serve calls the sweep on boot"
else
  bad "the sweep exists but nothing calls it"
fi

echo
echo "§4 the browser polls the row, and can pick up a run it did not start"

if hasE "$SRC_TSX" 'status === "analyzing"'; then
  ok "the page branches on the accepted-but-unfinished state"
else
  bad "the page still expects the inventory to come back from the POST"
fi

if has "$SRC_TSX" 'setInterval' && hasE "$SRC_TSX" 'api\.get<MigrationRecord>\(`/migration/'; then
  ok "it polls the record"
else
  bad "there is no poll loop reading the record back"
fi

if has "$SRC_TSX" 'clearInterval'; then
  ok "the poll loop is cleared on teardown"
else
  bad "the poll loop is never cleared — it outlives the page"
fi

# A transient failure is not an answer, but a 404 or a 403 is. Treating every
# error as "try again" turns a record that is gone into a spinner that never
# stops — the same "told nothing while waiting" this issue was reported for.
if hasE "$SRC_TSX" 'e\.status === 40[34]'; then
  ok "the poll gives up on an answer that will not change"
else
  bad "every poll failure is treated as transient — a deleted record spins forever"
fi

if hasE "$SRC_TSX" 'result as \{ error\?: string \}'; then
  ok "a failed analysis renders the reason the server recorded"
else
  bad "the page does not read the failure reason out of the row"
fi

# Pinned as the two facts, not as one expression: the page looks for a run still
# analysing, and it does not adopt one belonging to a different server. The list
# endpoint is per-user and not per-server, so without the second the wizard would
# present another machine's run — with that machine's filesystem path in the field.
# Anchored on CODE, not on the comment above the effect: `strip` has already
# removed every `//` line by this point, so a comment anchor matches nothing and
# the extraction comes back empty — which reads as both arms failing.
RESUME=$(awk '/const isAdmin = /,/\}, \[isAdmin\]\)/' <<< "$SRC_TSX")
[ -n "$RESUME" ] || bad "could not extract the resume effect — the arms below mean nothing"
if has "$RESUME" 'm.status === "analyzing"'; then
  ok "an analysis already running is picked back up on mount"
else
  bad "a reload abandons a running analysis — durable state nothing reads"
fi
if has "$RESUME" 'dp-active-server' && has "$RESUME" 'm.server_id'; then
  ok "the resumed run is scoped to the server being looked at"
else
  bad "the resume adopts any of this user's runs, on any server in the fleet"
fi

# The admin redirect used to sit above the hooks. That was survivable when every
# hook was a useState; this page now runs effects, and a conditional return in
# front of them makes the hook count differ between renders.
#
# The needle has to catch a hook bound to a plain identifier — `const x =
# useRef(...)` — not just a `const [a, b] =` destructure and a bare `useEffect(`.
# The narrower version matched neither the `useRef` already in this file nor any
# `useMemo`/`useCallback` a later edit might add, so moving one below the guard
# left the arm green over exactly the crash it names.
guard_line=$(grep -n 'if (!isAdmin) return <Navigate' <<< "$SRC_TSX" | head -1 | cut -d: -f1)
last_hook=$(grep -nE '^  (const [^=]+= *)?use(State|Effect|Ref|Callback|Memo|Context|Reducer)\(|^  const \[' <<< "$SRC_TSX" | tail -1 | cut -d: -f1)
if [ -n "$guard_line" ] && [ -n "$last_hook" ] && [ "$guard_line" -gt "$last_hook" ]; then
  ok "every hook runs before the admin redirect (guard@$guard_line, last hook@$last_hook)"
else
  bad "a hook runs after the admin redirect (guard@${guard_line:-none}, last hook@${last_hook:-none})"
fi

echo
echo "§5 the gateway numbers this was designed against have not moved"

# Not decoration: if either of these grows past the agent's budget, holding the
# request open becomes viable again and someone will propose it. If either
# SHRINKS, the async path is the only thing keeping the feature alive. Either way
# the design above needs re-reading, and a failing arm is how that gets noticed.
# Compared against a literal, NOT against the agent budget read above. Tying a
# premise arm to a value the fix introduces makes it fail on the pre-fix tree for
# a reason that has nothing to do with the premise — which is how a suite starts
# reporting a problem with the code when the problem is with the arm.
layer=$(grep -oE 'traceTimeout\([0-9]+\*time\.Second, ' <<< "$SRC_ROUTER" | head -1 | grep -oE '[0-9]+')
if [ "${layer:-0}" = "300" ]; then
  ok "the panel's own request ceiling is still 300s, well under any real analysis"
else
  bad "the request ceiling reads '${layer:-none}', not 300s — recheck this pin's premise"
fi

if hasE "$SRC_SETUP" 'proxy_read_timeout 300s'; then
  ok "the installer's nginx still cuts /api off at 300s"
else
  bad "the installed nginx read timeout changed — recheck this pin's premise"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
