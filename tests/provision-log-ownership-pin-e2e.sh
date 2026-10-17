#!/usr/bin/env bash
#
# Regression pin for the provisioning-log keyspace that anyone could read.
#
# `state.provision_logs` is ONE process-wide map shared by nine unrelated
# features — service installs, mail installs, system updates, site provisioning,
# backups, restores, container deploys, git deploys, migration imports. It is a
# single flat keyspace: nothing distinguishes a site id from a deploy id, so any
# endpoint that looks a caller-supplied uuid up in it reaches every other
# feature's stream unless it proves ownership itself.
#
# Five endpoints did that five different ways, and the divergence is the defect:
#
#   A  system::install_log took `AdminUser(_claims)` — the claims DISCARDED —
#      and did a bare lookup. Despite its path it is the panel's GENERAL progress
#      stream: the UI points backup, restore, site-deploy, mail-install and
#      system-update ids at it, so it could not authorize by feature and
#      authorized by nothing.
#
#   B  git_deploys::deploy_log consulted the owner table but fell through when
#      the id was absent, on the stated grounds that "the NOT_FOUND below handles
#      missing deploys". It does not: absent-from-owners and absent-from-logs are
#      different questions. Only 3 of 16 creation sites ever recorded an owner, so
#      absent was the COMMON case — and this route needs only `AuthUser`.
#
#   C  That stream deliberately carries a credential. sites.rs emits the
#      generated CMS admin password in cleartext on its "credentials" step,
#      justified by a comment claiming "the provisioning stream is owner-scoped" —
#      true of the endpoint its author was looking at, false of the siblings.
#
#   MEASURED on a throwaway box running the released v2.49.0 (s291): three
#   accounts attached to one site's provisioning stream. Owner, an unrelated
#   tenant with role "user", and a second admin all received the SAME 1458 bytes
#   containing the same cleartext WordPress admin password.
#
#   D  The two readers that DID check both exempted `role == "admin"`, while
#      /api/sites is user_id-scoped — so admin was never a licence to read
#      another tenant's log, and the exemption reopened A by another door.
#
#   E  A refused stream rendered as SUCCESS. ProvisionLog.tsx turned any error
#      with no steps yet into done + onComplete — a green check over an empty log.
#
# The fix is structural: ownership is carried by the KEY. `register_provision_log`
# creates a log and its owner under one lock scope; `open_provision_log` is the
# only way to read one and refuses an id whose owner is not recorded.
#
# Go port (panel/go/internal/api): the map and owner table are the unexported
# `logs`/`owners` fields of *ProvisionLogs (core_state.go), with Register/Open/
# Emit/Remove/Forget/Has methods and sweep() as the pruner. The api package is
# flat, so unexported does NOT stop another file in it from reaching the fields
# — §1 still has to check that nothing outside core_state.go does.
#
# ── WHY THE ARMS ARE SHAPED THE WAY THEY ARE ────────────────────────────────
#
# The first version of this suite was reviewed and found to be spelling-bound,
# and the review MEASURED the evasions rather than asserting them. It hunted
# `logs.insert(` and `logs.get(&` — incidental local-variable names — across a
# hardcoded list of 8 files. A new ownerless writer spelled
# `state.provision_logs.lock()…insert(…)`, or a new unchecked reader whose guard
# was called `guard` instead of `logs`, or ANY provisioning stream added to one
# of the other 55 route files, all passed it 30/30 green.
#
# So the negative arms no longer look for statements. They look for the two
# capabilities you cannot avoid naming:
#
#   * to touch the map at all you must name `st.ProvisionLogs` (or its
#     `.logs`/`.owners` fields)
#   * to serve its contents to a client you must call `.Subscribe()`
#
# Both are checked across EVERY non-test file in internal/api, and both are checked by what a
# violation must contain rather than by how somebody happened to write it.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

API=panel/go/internal/api
STATE=$API/core_state.go
PROVLOG_TSX=panel/frontend/src/components/ProvisionLog.tsx

for f in "$STATE" "$PROVLOG_TSX"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

# Strip comments from the SUBJECT FILES before matching.
#
# Not this suite's own header — that text is never searched. It is the sources
# that are the trap, and on this change an unusually loaded one: the fix's own
# comments spell `register_provision_log` and `open_provision_log` in prose, and
# the negative arms forbid literals a commented-out copy of the old block would
# reproduce exactly.
#
# `//` alone is not enough. The review MEASURED both evasions: wrapping
# deploy.rs's registration in `/* … */` left its positive arm green while that
# feature created an ownerless log, and reverting ProvisionLog.tsx with the
# pinned strings left only inside `/* … */` kept both §6 arms green. Block
# comments are the idiomatic way to disable a multi-line Rust call and a normal
# TSX comment form, so they are stripped too.
# A `/*` inside a string literal (a Dockerfile glob, a regex) is DATA, not a
# comment opener — the naive form deleted 485 lines of git_build.rs and 118 of
# agent/routes/nginx.rs, and a truncated subject makes an ABSENCE arm pass on
# code the stripper merely removed. Likewise `//` only opens a comment at the
# start of a line: stripping it anywhere ate the `//` of every `https://` URL.
strip() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

# Every api source file except the one that owns the map, comments stripped. ALL
# of them — the previous (Rust) version read 8 of 63 route files, so plausible
# future homes for a provisioning stream were unscanned.
ROUTE_FILES=$(ls "$API"/*.go | grep -v '_test\.go$' | grep -v '/core_state\.go$')
NROUTES=$(printf '%s\n' $ROUTE_FILES | wc -l)
SRC_ROUTES=""
for f in $ROUTE_FILES; do SRC_ROUTES+=$(strip "$f")$'\n'; done

SRC_STATE=$(strip "$STATE")
SRC_TSX=$(strip "$PROVLOG_TSX")

# Here-strings, never pipelines: `grep -q` closing a pipe kills the upstream
# with SIGPIPE and `pipefail` turns that into a failed arm non-deterministically.
has()  { grep -q  -- "$2" <<< "$1"; }
hasE() { grep -qE -- "$2" <<< "$1"; }
cnt()  { grep -c  -- "$2" <<< "$1" || true; }
cntE() { grep -cE -- "$2" <<< "$1" || true; }
fnbody() { awk "/^func $2\\(/,/^}/" <<< "$1"; }

# Every awk range extraction anchors on an incidental spelling. If one stops
# matching, the variable is EMPTY and every arm reading it goes red blaming the
# code — indistinguishable from the regression.
readable() { [ -n "$2" ] || bad "could not extract $1 — the arms reading it mean nothing"; }

if [ "$NROUTES" -ge 50 ]; then
  ok "scanning all $NROUTES api source files"
else
  bad "only $NROUTES api source files found — the scan lost its subjects"
fi

echo
echo "§1 the map cannot be touched except through the two helpers"

# THE structural arm. You cannot reach the map without naming it, so enumerate
# every occurrence and allow exactly the method calls and the bare value (an
# argument or alias handed to an emitter). Anything else — notably a field
# reach `st.ProvisionLogs.logs` — is direct access.
forms=$(grep -ohE "st\.ProvisionLogs[.a-zA-Z_]*" <<< "$SRC_ROUTES" | sort -u)
illegal=$(grep -vE "^st\.ProvisionLogs(\.(Register|Emit|Remove|Forget|Has|Open))?$" <<< "$forms" || true)
if [ -n "$forms" ] && [ -z "$illegal" ]; then
  ok "every mention of the map outside core_state.go is a method call or the bare value ($(wc -l <<< "$forms") forms)"
else
  bad "the api package reaches the map directly: ${illegal:-<no mentions at all — the scan is vacuous>}"
fi

# Aliases (`logs := st.ProvisionLogs`) evade the form check above, so the
# unexported fields themselves must not be named outside core_state.go. The
# positive control: core_state.go itself does name them.
if hasE "$SRC_STATE" 'p\.owners\[id\]' && hasE "$SRC_STATE" 'p\.logs\[id\]'; then
  if hasE "$SRC_ROUTES" '\.(logs|owners)\b'; then
    bad "a file outside core_state.go touches the logs/owners fields: $(grep -ohE '[A-Za-z_.]*\.(logs|owners)\b' <<< "$SRC_ROUTES" | sort -u | tr '\n' ' ')"
  else
    ok "no file outside core_state.go manipulates the log map or the owner table itself"
  fi
else
  bad "CONTROL: core_state.go no longer names p.logs[id]/p.owners[id] — the absence arm cannot be trusted"
fi

echo
echo "§2 no route can serve the map's contents to a client"

# The capability arm. A provisioning stream is a Broadcast subscription, and the
# only way to obtain one is `.Subscribe()`. ProvisionLogs.Open is the sole place
# that may. The legitimate exception never touches provisioning logs: the
# notifications SSE (st.Notif). (Go's graceful shutdown is a context, not a
# subscribed channel, so the Rust shutdown_tx exemption has no counterpart.)
subs=$(grep -ohE "[a-zA-Z_.]*\.Subscribe\(\)" <<< "$SRC_ROUTES" | sort -u)
rogue=$(grep -vE "^st\.Notif\.Subscribe\(\)$" <<< "$subs" || true)
if [ -z "$rogue" ]; then
  ok "the only Subscribe() outside core_state.go is the notifications channel"
else
  bad "a route subscribes to a provisioning channel itself: $(tr '\n' ' ' <<< "$rogue")"
fi

if has "$(fnbody "$SRC_STATE" '\(p \*ProvisionLogs\) Open')" 'l.tx.Subscribe()'; then
  ok "ProvisionLogs.Open is where subscription happens"
else
  bad "ProvisionLogs.Open no longer subscribes — the readers cannot be going through it"
fi

echo
echo "§3 every creation site records an owner"

# Exact counts, not ">= 1". The previous version accepted one registration per
# file, so git_deploys could lose 3 of its 4 and stay green — which is how the
# pre-change ratio (3 of 16) could be re-established one site at a time. Adding a
# provisioning log to a feature is expected to change the number here.
# Go: mail install and uninstall share rtMailRunInstall, so mail's two Rust
# registrations are one call site (17 → 16).
census="backups:2 deploy:1 sites:1 migration:1 git_deploys:4 mail:1 system:4 docker_apps:2"
total=0
for e in $census; do
  f=${e%%:*}; want=${e##*:}
  got=$(cntE "$(strip "$API/rt_$f.go")" 'ProvisionLogs\.Register\(')
  total=$((total+got))
  if [ "$got" -eq "$want" ]; then
    ok "rt_$f.go registers $got of $want"
  else
    bad "rt_$f.go registers $got owners, expected $want — a creation site lost its owner, or a new one needs adding here"
  fi
done
all=$(cntE "$SRC_ROUTES" 'ProvisionLogs\.Register\(')
if [ "$total" -eq 16 ] && [ "$all" -eq 16 ]; then
  ok "16 creation sites, all owned"
else
  bad "$total registrations across the census ($all package-wide), expected 16"
fi

echo
echo "§4 every reader proves ownership"

READERS="sites:rtSitesProvisionLog docker_apps:rtDockerAppsDeployLog git_deploys:rtGitDeploysDeployLog system:rtSystemInstallLog migration:rtMigrationProgress"
for pair in $READERS; do
  file=${pair%%:*}; fn=${pair##*:}
  body=$(fnbody "$(strip "$API/rt_$file.go")" "$fn")
  readable "$file::$fn" "$body"
  [ -n "$body" ] || continue
  if hasE "$body" 'st\.ProvisionLogs\.Open\([a-zA-Z]+, (claims|c)\.Sub,'; then
    ok "$file::$fn reads the map through the owner check"
  else
    bad "$file::$fn reaches the map without proving ownership"
  fi
done

# Narrow claim, deliberately. This says only that no reader carries the
# `claims.role != "admin"` COMPARISON (Go: `.Role != "admin"`) that let both
# broken readers skip the ownership test. `requireAdmin(claims.Role)` NARROWS a route and is fine —
# migration::progress does exactly that and must keep it. Three of these five
# were already green before the fix (sites and migration never had the
# exemption; install_log's defect was a different shape, covered below), so
# treat this as a guard against reintroduction, not as evidence any of them is
# correct — §4's first loop is what establishes that.
for pair in $READERS; do
  file=${pair%%:*}; fn=${pair##*:}
  body=$(fnbody "$(strip "$API/rt_$file.go")" "$fn")
  [ -n "$body" ] || continue
  if hasE "$body" '\.Role *[!=]= *"admin"'; then
    bad "$file::$fn exempts admins from the ownership test"
  else
    ok "$file::$fn carries no admin exemption"
  fi
done

SYS_LOG=$(fnbody "$(strip "$API/rt_system.go")" 'rtSystemInstallLog')
readable "system::rtSystemInstallLog" "$SYS_LOG"
if [ -n "$SYS_LOG" ]; then
  if hasE "$SYS_LOG" 'adminUser\(|rtSystemAdminScope\('; then
    bad "install_log is gated by role again — it must be owner-gated, per key"
  else
    ok "install_log no longer answers on the strength of the admin role alone"
  fi
  if hasE "$SYS_LOG" 'claims, err := st\.authUser\(r\)'; then
    ok "install_log binds the caller it has to compare against"
  else
    bad "install_log discards its claims — there is nothing to check ownership against"
  fi
fi

echo
echo "§5 the door itself fails closed"

# Behaviour, not spelling. What matters is that the owner lookup is a total
# comparison: absence of an owner row must be a refusal, not a pass.
OPEN_FN=$(fnbody "$SRC_STATE" '\(p \*ProvisionLogs\) Open')
readable "ProvisionLogs.Open body" "$OPEN_FN"
if [ -n "$OPEN_FN" ]; then
  if hasE "$OPEN_FN" 'owner, owned := p\.owners\[id\]' && hasE "$OPEN_FN" 'if !ok \|\| !owned \|\| owner != caller \{'; then
    ok "the owner comparison treats absence as a mismatch"
  else
    bad "the owner comparison changed shape — check that a missing owner cannot pass"
  fi
fi
# (Rust's map_or(true…)/unwrap_or(true…)/is_none_or/None => idiom arms retired
# (obsolete in Go): those Option combinators have no Go spelling; the comma-ok
# shape above is the one total form and the tests below execute it.)

# The header delegates the door's behaviour to these unit tests, so the arm has
# to prove they RUN — so it runs them (Go ports of
# an_ownerless_log_is_refused_not_served / a_stranger_cannot_read_someone_elses_log).
if command -v go >/dev/null 2>&1; then
  for t in TestOwnerlessLogIsRefused TestProvisionLogs; do
    out=$(cd panel/go && go test ./internal/api/ -run "^$t\$" -count=1 -v 2>&1)
    if grep -q -- "--- PASS: $t " <<< "$out"; then
      ok "$t runs and passes"
    else
      bad "$t is missing or failing: $(tail -3 <<< "$out" | tr '\n' ' ')"
    fi
  done
else
  bad "go toolchain not found — cannot execute the owner-door tests"
fi

echo
echo "§6 the owner map stays bounded"

# §6 arms retired: covered by TestProvisionSweepPrunesOwnersEveryTick (panel/go/internal/api/core_helpers_test.go)
#   (owner pruning not gated on a TTL eviction; owners pruned against live logs).
# poisoned-lock arm retired (obsolete in Go): sync.Mutex has no poisoning, so
#   there is no `if let Ok(lock)` give-up path for the pruner to take.
if hasE "$(strip panel/go/internal/api/core_helpers_test.go)" '^func TestProvisionSweepPrunesOwnersEveryTick\(' \
   && hasE "$SRC_STATE" 'st\.ProvisionLogs\.sweep\(now, time\.Hour\)'; then
  ok "the periodic cleanup calls ProvisionLogs.sweep, whose owner pruning TestProvisionSweepPrunesOwnersEveryTick pins"
else
  bad "the cleanup tick no longer sweeps provisioning logs (or the pruning test is gone) — the owner map grows unbounded"
fi

echo
echo "§7 a refused stream is not drawn as a completed one"

if has "$SRC_TSX" 'setSevered(true)'; then
  ok "a stream that ends before reporting anything is marked, not assumed complete"
else
  bad "an empty stream is silently treated as success — every arm above becomes invisible in the UI"
fi

if hasE "$SRC_TSX" 'isComplete *=.*!severed'; then
  ok "the severed case is excluded from the success state"
else
  bad "severed is not excluded from isComplete — the green check comes back"
fi

# Without the delay the component unmounts before its own message paints: every
# mount but the PHP picker clears the gating state inside onComplete, so a
# synchronous call replaced the false green check with nothing at all.
# Extracted as a block: grep is line-oriented, so a multi-line pattern spanning
# the two statements silently never matched and reported the code broken.
ONERR=$(awk '/es\.onerror = \(\) => \{/,/^    \};/' <<< "$SRC_TSX")
readable "es.onerror block" "$ONERR"
if [ -n "$ONERR" ]; then
  # Anchoring on "no line STARTS with onComplete" passed the pre-fix code, which
  # called it mid-line inside the state updater. Require instead that the block's
  # single mention of onComplete is the deferred one.
  mentions=$(cnt "$ONERR" 'onComplete')
  if has "$ONERR" 'setTimeout(() => onComplete' && [ "$mentions" -eq 1 ]; then
    ok "the severed path defers onComplete, so its message can render first"
  else
    bad "onComplete fires synchronously on a severed stream ($mentions mention(s)) — the warning never reaches the screen"
  fi
fi

# A retry reuses this component on a new url; without a reset the previous run's
# verdict and steps survive into it.
if hasE "$SRC_TSX" 'setSevered\(false\)'; then
  ok "state is reset per stream, so a retry is not judged by the last attempt"
else
  bad "severed is never cleared — one refused stream pins the component to 'Progress unavailable' forever"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
