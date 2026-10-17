#!/usr/bin/env bash
# Regression pin for PER-SITE BANDWIDTH QUOTA / TRAFFIC ACCOUNTING (GH #84).
#
# A monthly byte accumulator built from the agent's nginx access-log, crossing
# a daily logrotate rotation, feeding a per-site MB/mo quota that auto-disables
# a site when exceeded and auto-recovers it (new month, quota raised/removed,
# or a manual re-enable). The invariants this suite exists to protect:
#
#   - the checkpoint offset NEVER advances past an incomplete trailing log
#     line — doing so would both corrupt the running byte sum (parsing a
#     truncated size field) AND permanently skip that request's bytes forever
#   - a site is suspended for quota at most ONCE per over-quota episode (the
#     bandwidth_suspended_at guard), not re-suspended (and re-notified) on
#     every 5-minute scheduler tick while it stays over
#   - a human re-enabling a bandwidth-suspended site clears the flag, so the
#     scheduler's "still suspended" branch doesn't shadow a fresh quota check
#   - only ONE rotation is reconciled per poll — an inode neither the current
#     file nor `.1` matches is left unrecovered by design, not guessed at
#
# Pure source analysis: no box, no network, no DB. The byte-accounting math
# itself (partial-line handling, rotation-crossing, first-poll bounding) is
# covered by the TestReadAndAdvance* / TestParseLogLineSize* Go tests in
# panel/go/internal/agent/routes/nginx_test.go — this suite pins the WIRING
# and the enforcement state machine around it, not the arithmetic.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

AGENT_NGINX_GO=panel/go/internal/agent/routes/nginx.go
SCHEDULER_GO=panel/go/internal/api/svc_traffic_accounting_scheduler.go
SITES_GO=panel/go/internal/api/rt_sites.go
MODELS_GO=panel/go/internal/api/core_models.go
MAIN_GO=panel/go/internal/api/core_state.go
MIGRATION=panel/go/internal/api/migrations/20260908000000_bandwidth_quota.sql
SITE_DETAIL_TSX=panel/frontend/src/pages/SiteDetail.tsx

for f in "$AGENT_NGINX_GO" "$SCHEDULER_GO" "$SITES_GO" "$MODELS_GO" "$MAIN_GO" \
         "$MIGRATION" "$SITE_DETAIL_TSX"; do
  [ -f "$f" ] || { echo "missing file: $f"; exit 1; }
done

# Whitespace-insensitive substring check — a boolean `grep -q` at the end of a
# pipeline under `set -o pipefail` SIGPIPEs the producer and reports failure
# for a successful match; this idiom (matching against a variable, not a
# pipe) avoids that class entirely.
must_contain() {
  local flat="$1" needle="$2" desc="$3"
  local flat_needle
  flat_needle=$(printf '%s' "$needle" | tr -d ' \t\n')
  case "$flat" in
    *"$flat_needle"*) ok "$desc" ;;
    *) bad "$desc — pattern not found (whitespace-insensitive): $needle" ;;
  esac
}

AGENT_FLAT=$(tr -d ' \t\n' < "$AGENT_NGINX_GO")
SCHED_FLAT=$(tr -d ' \t\n' < "$SCHEDULER_GO")
SITES_FLAT=$(tr -d ' \t\n' < "$SITES_GO")

# ── §1 — schema: the accumulator, the checkpoint, and the two Site columns ──
echo "── §1 migration adds the checkpoint table, the accumulator table, and the two site columns ──"
MIG_FLAT=$(tr -d ' \t\n' < "$MIGRATION")
must_contain "$MIG_FLAT" 'ALTERTABLEsitesADDCOLUMNIFNOTEXISTSbandwidth_quota_mbINT;' \
  "sites.bandwidth_quota_mb is added, nullable (unlimited by default)"
must_contain "$MIG_FLAT" 'ALTERTABLEsitesADDCOLUMNIFNOTEXISTSbandwidth_suspended_atTIMESTAMPTZ;' \
  "sites.bandwidth_suspended_at is added"
must_contain "$MIG_FLAT" 'CREATETABLEIFNOTEXISTSsite_traffic_offsets(site_idUUIDPRIMARYKEYREFERENCESsites(id)ONDELETECASCADE,log_inodeBIGINTNOTNULL,log_sizeBIGINTNOTNULL,' \
  "site_traffic_offsets exists with one row per site, keyed by site_id"
must_contain "$MIG_FLAT" 'CREATETABLEIFNOTEXISTSsite_traffic_usage(site_idUUIDNOTNULLREFERENCESsites(id)ONDELETECASCADE,year_monthTEXTNOTNULL,bytes_usedBIGINTNOTNULLDEFAULT0,' \
  "site_traffic_usage exists, one row per site per calendar month"
must_contain "$MIG_FLAT" 'PRIMARYKEY(site_id,year_month)' \
  "site_traffic_usage's primary key is (site_id, year_month) — an upsert target, not a append-only log"

must_contain "$(tr -d ' \t\n' < "$MODELS_GO")" \
  'BandwidthQuotaMB*int32`json:"bandwidth_quota_mb"db:"bandwidth_quota_mb"`' \
  "the Site model struct carries bandwidth_quota_mb (SELECT s.* needs every column named)"
must_contain "$(tr -d ' \t\n' < "$MODELS_GO")" \
  'BandwidthSuspendedAt*time.Time`json:"bandwidth_suspended_at"db:"bandwidth_suspended_at"`' \
  "the Site model struct carries bandwidth_suspended_at"

# ── §2 — the agent route exists exactly once, and never advances past a partial line ──
echo "── §2 the delta endpoint is wired once, and offset-advance is partial-line-safe ──"
route_sites=$(grep -c 'r.Handle("GET /nginx/site-traffic-delta/{domain}", n.siteTrafficDelta)' "$AGENT_NGINX_GO" || true)
if [ "$route_sites" -eq 1 ]; then
  ok "site-traffic-delta is registered exactly once"
else
  bad "expected exactly 1 registration of site-traffic-delta, found $route_sites"
fi

# The invariant the whole feature's correctness rests on (the returned offset
# stops at the last COMPLETE newline, never raw EOF) is behaviour, so it is
# asserted by calling nginxReadAndAdvance directly:
# §2-last-newline retired: covered by TestReadAndAdvanceLeavesAPartialTrailingLineUnconsumed (panel/go/internal/agent/routes/nginx_test.go)
# §2-offset-from-complete retired: covered by TestReadAndAdvanceSumsCompleteLinesFromTheGivenOffset (panel/go/internal/agent/routes/nginx_test.go)

must_contain "$AGENT_FLAT" 'rotatedFile:=logFile+".1"' \
  "rotation crossing reads the delaycompress-preserved .1 predecessor, not a guess at .2.gz+"
must_contain "$AGENT_FLAT" 'ifino,ok:=nginxInode(rotatedFile);ok&&ino==*lastInode{' \
  "the rotated predecessor is only trusted when ITS inode matches the caller's old checkpoint (not just any .1 file)"

# ── §3 — the scheduler enforces the quota exactly once per over-quota episode ──
echo "── §3 quota enforcement is suspend-once, not suspend-every-tick ──"
must_contain "$SCHED_FLAT" 'ifsite.Enabled&&site.BandwidthSuspendedAt==nil{' \
  "the over-quota check only runs when the site is enabled AND not already bandwidth-suspended"
must_contain "$SCHED_FLAT" 'ifused>int64(quotaMB)*1024*1024{trafficAccountingSchedulerSuspend(ctx,db,agent,site,used,quotaMB)}' \
  "trafficAccountingSchedulerSuspend fires only once the accumulated usage actually exceeds the quota"

# Mutation-test the guard itself: with `BandwidthSuspendedAt == nil`
# dropped from the condition, a site already suspended this month would be
# re-evaluated (and re-notified) on every single tick while still over quota.
cp "$SCHEDULER_GO" /tmp/bwq-sched-backup.go
python3 - "$SCHEDULER_GO" <<'PYEOF'
import sys
path = sys.argv[1]
src = open(path).read()
needle = "if site.Enabled && site.BandwidthSuspendedAt == nil {"
replacement = "if site.Enabled {"
if needle not in src:
    sys.exit(2)
open(path, "w").write(src.replace(needle, replacement, 1))
PYEOF
if [ $? -eq 0 ]; then
  if grep -q 'if site.Enabled && site.BandwidthSuspendedAt == nil {' "$SCHEDULER_GO"; then
    bad "MUTATION did not apply — suspend-once guard mutation test is broken"
  else
    ok "MUTATION applied: dropped the BandwidthSuspendedAt == nil guard"
  fi
  cp /tmp/bwq-sched-backup.go "$SCHEDULER_GO"
  if grep -q 'if site.Enabled && site.BandwidthSuspendedAt == nil {' "$SCHEDULER_GO"; then
    ok "MUTATION reverted — suspend-once guard restored"
  else
    bad "failed to revert the suspend-once guard mutation — $SCHEDULER_GO is left mutated"
  fi
else
  bad "could not locate the suspend-once guard to mutation-test"
fi
rm -f /tmp/bwq-sched-backup.go

# ── §4 — auto-recovery: new month, quota raised/removed, and a manual re-enable ──
echo "── §4 three independent recovery paths, all clearing bandwidth_suspended_at ──"
must_contain "$SCHED_FLAT" '}elseifsite.BandwidthSuspendedAt!=nil&&trafficAccountingSchedulerMonthKey(*site.BandwidthSuspendedAt)!=ym{trafficAccountingSchedulerRecover(ctx,db,agent,site,"newbillingmonth")}' \
  "the scheduler auto-recovers a bandwidth-suspended site once a new calendar month starts"
must_contain "$SCHED_FLAT" 'ifsite.BandwidthQuotaMB==nil{' \
  "the quota check has a nil-quota branch (quota removed while still suspended)"
must_contain "$SCHED_FLAT" 'ifsite.BandwidthSuspendedAt!=nil{trafficAccountingSchedulerRecover(ctx,db,agent,site,"quotaremoved")}' \
  "removing the quota (setting it back to unlimited) lifts a standing bandwidth suspension immediately"

# The bug this session found and fixed: toggle_enabled (now rtSitesToggleEnabled) used to leave a stale
# bandwidth_suspended_at behind on manual re-enable, which would shadow the
# scheduler's over-quota check forever (it only runs when the flag is None).
if grep -q '^func rtSitesToggleEnabled(' "$SITES_GO"; then
  TOGGLE_BODY=$(awk '/^func rtSitesToggleEnabled\(/,/^}/' "$SITES_GO")
  case "$(printf '%s' "$TOGGLE_BODY" | tr -d ' \t\n')" in
    *'bandwidth_suspended_at=CASEWHEN$1THENNULLELSEbandwidth_suspended_atEND'*)
      ok "toggle_enabled clears bandwidth_suspended_at when a human sets enabled=true" ;;
    *)
      bad "toggle_enabled no longer clears bandwidth_suspended_at on manual re-enable — a manually-re-enabled site would never be re-checked against its quota" ;;
  esac
else
  bad "toggle_enabled function not found in $SITES_GO"
fi

# Mutation-test that exact clearing clause.
cp "$SITES_GO" /tmp/bwq-sites-backup.go
python3 - "$SITES_GO" <<'PYEOF'
import sys
path = sys.argv[1]
src = open(path).read()
needle = '"UPDATE sites SET enabled = $1, bandwidth_suspended_at = CASE WHEN $1 THEN NULL ELSE bandwidth_suspended_at END, "+\n\t\t\t"updated_at = NOW() WHERE id = $2",'
replacement = '"UPDATE sites SET enabled = $1, updated_at = NOW() WHERE id = $2",'
if needle not in src:
    sys.exit(2)
open(path, "w").write(src.replace(needle, replacement, 1))
PYEOF
if [ $? -eq 0 ]; then
  if grep -q 'bandwidth_suspended_at = CASE WHEN \$1' "$SITES_GO"; then
    bad "MUTATION did not apply — toggle_enabled clear-flag mutation test is broken"
  else
    ok "MUTATION applied: toggle_enabled no longer clears bandwidth_suspended_at"
  fi
  cp /tmp/bwq-sites-backup.go "$SITES_GO"
  if grep -q 'bandwidth_suspended_at = CASE WHEN \$1' "$SITES_GO"; then
    ok "MUTATION reverted — toggle_enabled's flag-clearing restored"
  else
    bad "failed to revert the toggle_enabled mutation — $SITES_GO is left mutated"
  fi
else
  bad "could not locate toggle_enabled's UPDATE to mutation-test"
fi
rm -f /tmp/bwq-sites-backup.go

# ── §5 — quota edits recover a suspended site in the SAME request, not a 5-minute wait ──
echo "── §5 update_limits recovers a suspended site inline when the new quota clears it ──"
must_contain "$SITES_FLAT" 'recovering:=falseifsite.BandwidthSuspendedAt!=nil{' \
  "update_limits computes a recovering flag from the CURRENT suspension state before writing"
must_contain "$SITES_FLAT" 'ifq:=body.BandwidthQuotaMB;q!=nil&&*q<1{returnapiErr(http.StatusBadRequest,"Bandwidthquotamustbeatleast1MB")}' \
  "bandwidth_quota_mb is validated (>= 1) the same way rate_limit and the other limits are"
must_contain "$SITES_FLAT" 'ifrecovering{if_,err:=agent.Post(ctx,"/nginx/sites/"+site.Domain+"/enable",nil);err!=nil{' \
  "when recovering, update_limits actually calls the agent to re-enable nginx, not just the DB row"

# ── §6 — routes and scheduler are wired exactly once ──
echo "── §6 single registration: route, scheduler module, scheduler spawn ──"
n=$(cat panel/go/internal/api/*.go | grep -c '"GET /api/sites/{id}/bandwidth-usage"' || true)
if [ "$n" -eq 1 ]; then ok "bandwidth-usage route is registered exactly once"; else bad "expected exactly 1 registration of bandwidth-usage, found $n"; fi
# §6-mod-declared-once retired (obsolete in Go): internal/api is one flat package; a duplicate func is a compile error
n=$(grep -c 'TrafficAccountingSchedulerRun(ctx, db, agents)' "$MAIN_GO" || true)
if [ "$n" -eq 1 ]; then ok "TrafficAccountingSchedulerRun is spawned exactly once in core_state.go"; else bad "expected exactly 1 spawnSupervised call, found $n"; fi

# ── §7 — frontend: the quota control exists and the disabled banner explains why ──
echo "── §7 frontend surfaces the quota control and a bandwidth-specific disabled reason ──"
FE_FLAT=$(perl -0777 -pe 's{/\*.*?\*/}{}gs' "$SITE_DETAIL_TSX" | tr -d ' \t\n')
must_contain "$FE_FLAT" 'value={bandwidthQuota}onChange={(e)=>setBandwidthQuota(e.target.value)}' \
  "the Resource Limits form has a bandwidth quota input bound to state"
must_contain "$FE_FLAT" 'bandwidth_quota_mb:bandwidthQuota?parseInt(bandwidthQuota):null,' \
  "saving Resource Limits sends bandwidth_quota_mb in the PUT body"
must_contain "$FE_FLAT" 'site.bandwidth_suspended_at?' \
  "the disabled banner branches on bandwidth_suspended_at rather than a single generic message"

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
