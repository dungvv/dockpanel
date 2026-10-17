#!/usr/bin/env bash
# backend-hot-file-audit-pin-e2e.sh — s463
#
# The Rust backend's src/{routes,services} had never had its own exhaustion
# status directly re-verified (agent crate: s461, CLI src: s462). A LOC-rank +
# two-direction pre-selection check (git-log + memory-mention grep, filtering
# a cosmetic mass-commit that touches nearly every backend file) surfaced 5
# files with genuinely zero prior dedicated scrutiny: dns.rs, security.rs +
# security_hardening.rs, update.rs + panel_update.rs. A full finder/skeptic/
# critics fan-out found 4 real, independently-verified defects across those
# files plus one off-menu completeness-critic find in databases.rs:
#
#   §A dns.rs `update_record`/`delete_record` interpolated an unvalidated
#      `record_id` path segment straight into the outbound Cloudflare API
#      URL — a "../../../zones/OTHER/dns_records/RECID"-shaped id (percent-
#      encoded to survive the reverse proxy) reroutes the request, carrying
#      the zone's own decrypted CF token, to an arbitrary Cloudflare API
#      path. PowerDNS's record_id is a different, safely-parsed hex-encoded
#      composite (pdns_parse_record_id) — unaffected, left alone.
#   §B security.rs `compliance_report` built an HTML report by raw
#      format!-interpolating scan-derived title/description/remediation
#      with no escaping, served as text/html and opened in a new tab by the
#      frontend's own "Download Report" link — a stored XSS reachable the
#      moment a compromised hosted site names a file with HTML in its path
#      (malware/secrets scans record raw filesystem paths verbatim).
#   §C (off-menu, completeness critic) databases.rs `create()` authorizes
#      via the fleet-wide SITE_CALLER_PREDICATE (any site an admin manages,
#      including a tenant's site on the local box) but every OTHER handler
#      — list/credentials/remove/get_db_info (the chokepoint for 11 more
#      handlers)/pitr_config — required strict self-ownership, so a database
#      an admin creates on a site they don't personally own becomes
#      permanently unmanageable by its own creator. Same bug-class shape
#      this file family has been fixed for 5 times before.
#   §D panel_update.rs `build_fleet_plan` scoped fleet-update plans to
#      `servers.user_id = caller` with no admin-widening — a fleet-wide
#      update run silently skipped every server a DIFFERENT admin had
#      registered, reporting success with no indication the plan was
#      incomplete. Sibling call sites (servers.rs::list, dashboard.rs) had
#      already established the admin-widened convention; this one never got
#      it.
#   §E update.rs `apply_fleet`'s `include_panel` path reached
#      `start_panel_update` with only a shape check on target_version —
#      none of `apply_update`'s direction/advertised-match guard
#      (`reject_apply_target`), so it could downgrade the panel to any
#      syntactically-valid version, not merely a stale-advertised one.
#   §F panel_update.rs `start_panel_update`'s concurrent-apply guard was
#      read-check-then-later-write, with the multi-minute create_snapshot
#      pipeline running entirely inside the gap — two requests within that
#      window both passed the check and both spawned their own snapshot +
#      detached update.sh.
#   §G panel_update.rs `rollback_to_snapshot` had no in-flight check at
#      all, so `/api/update/rollback` could race update.sh's binary swap
#      against restore-snapshot.sh's binary swap on the same files.
#
# Go port (panel/go/internal/api): dns.rs → rt_dns.go (rtDnsUpdateRecord /
# rtDnsDeleteRecord, rtDnsIsHex32, rtDnsPdnsParseRecordID); security.rs →
# rt_security.go (rtSecurityComplianceReport, rtSecurityHTMLEscape);
# databases.rs → rt_databases.go (rtDatabasesList/Credentials/Remove/
# GetDbInfo/PitrConfig, the shared rtDatabasesCallerPredicate, create's
# rtDatabasesResolveOwner + SiteCallerPredicate); panel_update.rs →
# svc_panel_update.go (PanelUpdateBuildFleetPlan / StartPanelUpdate /
# RollbackToSnapshot, a mutex-guarded PanelUpdateStateHandle); update.rs →
# rt_update.go (rtUpdateApplyFleet, rtUpdateRejectApplyTarget,
# rtUpdateRollback). The pure predicates (§A record-id shape, §B escaping)
# are Go tests in pin_backend_hot_file_audit_test.go.
#
# Read-only/authz-widening changes mostly; the one behavior addition beyond
# tightening is the databases handlers' admin-visibility widening, which grants
# nothing create() didn't already grant — it makes read/manage consistent
# with what create() already authorized.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  Backend hot-file audit — source pins (s463)"
echo "=================================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

code() {
  [ -f "$1" ] || return 0
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

has()    { grep -qE -- "$2" <<< "$1"; }
lacks()  { ! grep -qE -- "$2" <<< "$1"; }
count()  { grep -oE -- "$2" <<< "$1" | wc -l | tr -d ' '; }
flat()   { tr -s '[:space:]' ' ' <<< "$1"; }
# Line of the first match of $2 in $1 (0 = absent).
lineof() { local n; n=$(grep -nE -- "$2" <<< "$1" | head -1 | cut -d: -f1); echo "${n:-0}"; }

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
DNS=$API/rt_dns.go
DNS_C=$(code "$DNS")
SECURITY=$API/rt_security.go
SECURITY_C=$(code "$SECURITY")
DATABASES=$API/rt_databases.go
DATABASES_C=$(code "$DATABASES")
PANEL_UPDATE=$API/svc_panel_update.go
PANEL_UPDATE_C=$(code "$PANEL_UPDATE")
UPDATE=$API/rt_update.go
UPDATE_C=$(code "$UPDATE")

for f in "$DNS" "$SECURITY" "$DATABASES" "$PANEL_UPDATE" "$UPDATE"; do [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"; done

UPDATE_RECORD_BODY=$(fnbody "$DNS_C" "rtDnsUpdateRecord")
DELETE_RECORD_BODY=$(fnbody "$DNS_C" "rtDnsDeleteRecord")
COMPLIANCE_BODY=$(fnbody "$SECURITY_C" "rtSecurityComplianceReport")
DB_LIST_BODY=$(fnbody "$DATABASES_C" "rtDatabasesList")
DB_CREDENTIALS_BODY=$(fnbody "$DATABASES_C" "rtDatabasesCredentials")
DB_REMOVE_BODY=$(fnbody "$DATABASES_C" "rtDatabasesRemove")
DB_GET_INFO_BODY=$(fnbody "$DATABASES_C" "rtDatabasesGetDbInfo")
DB_PITR_CONFIG_BODY=$(fnbody "$DATABASES_C" "rtDatabasesPitrConfig")
DB_CREATE_BODY=$(fnbody "$DATABASES_C" "rtDatabasesCreate")
DB_RESOLVE_OWNER_BODY=$(fnbody "$DATABASES_C" "rtDatabasesResolveOwner")
BUILD_FLEET_PLAN_BODY=$(fnbody "$PANEL_UPDATE_C" "PanelUpdateBuildFleetPlan")
START_UPDATE_BODY=$(fnbody "$PANEL_UPDATE_C" "PanelUpdateStartPanelUpdate")
ROLLBACK_BODY=$(fnbody "$PANEL_UPDATE_C" "PanelUpdateRollbackToSnapshot")
APPLY_FLEET_BODY=$(fnbody "$UPDATE_C" "rtUpdateApplyFleet")
ROLLBACK_ROUTE_BODY=$(fnbody "$UPDATE_C" "rtUpdateRollback")

# ── §A rt_dns.go: record_id validated before URL interpolation ──────────
echo "── §A rt_dns.go: CF record_id is allowlisted (32-char hex) before use ──"
# The predicate itself (32 hex, path-shaped ids refused) is
# TestPinBackendHotFileAuditCfRecordID (panel/go/internal/api/pin_backend_hot_file_audit_test.go);
# these arms pin that each Cloudflare arm calls it BEFORE building the URL.

cf_guard() { # id body label
  local g u
  g=$(lineof "$2" 'if !rtDnsIsHex32\(recordID\) \{')
  u=$(lineof "$2" 'dns_records/%s", rtDnsCFAPI, rtDnsDeref\(zone\.CfZoneID\), recordID\)')
  if [ "$g" -gt 0 ] && [ "$u" -gt 0 ] && [ "$g" -lt "$u" ]; then
    ok "$1 $3 validates record_id via rtDnsIsHex32 before interpolating it into the Cloudflare URL"
  else
    bad "$1 $3's cloudflare arm no longer validates record_id shape before the URL (guard line $g, URL line $u)"
  fi
}
cf_guard A1 "$UPDATE_RECORD_BODY" rtDnsUpdateRecord
cf_guard A2 "$DELETE_RECORD_BODY" rtDnsDeleteRecord

# Positive control: the PowerDNS arm's record_id (a hex-encoded composite of
# variable length, decoded via rtDnsPdnsParseRecordID) must NOT be forced
# through the same fixed-32-hex check — it was never the bug and a blanket
# fix would break every PowerDNS record update/delete.
if has "$UPDATE_RECORD_BODY" 'rtDnsPdnsParseRecordID\(recordID\)'; then
  ok "A3 (control) rtDnsUpdateRecord's powerdns arm still parses record_id via rtDnsPdnsParseRecordID"
else
  bad "A3 (control) powerdns record parsing regressed"
fi

# ── §B rt_security.go: compliance report escapes scan-derived HTML ──────
echo "── §B rt_security.go: rtSecurityComplianceReport HTML-escapes findings before interpolation ──"

# B1 retired: covered by TestPinBackendHotFileAuditHTMLEscape (panel/go/internal/api/pin_backend_hot_file_audit_test.go)

COMPLIANCE_FLAT=$(flat "$COMPLIANCE_BODY")
if has "$COMPLIANCE_FLAT" 'color, rtSecurityHTMLEscape\(f\.A\), rtSecurityHTMLEscape\(f\.B\), rtSecurityHTMLEscape\(f\.C\), remediation\)'; then
  ok "B2 severity/title/description are escaped before interpolation"
else
  bad "B2 one of severity/title/description is no longer escaped — regressed"
fi

if has "$COMPLIANCE_BODY" 'remediation = rtSecurityHTMLEscape\(\*f\.E\)'; then
  ok "B3 remediation is escaped when present, not interpolated raw"
else
  bad "B3 remediation is no longer escaped"
fi

# Negative control: no scan-derived field reaches the HTML unescaped — every
# use of title/description/remediation goes through the escaper.
if [ -n "$COMPLIANCE_BODY" ] \
  && [ "$(count "$COMPLIANCE_BODY" 'f\.B')" = "$(count "$COMPLIANCE_BODY" 'rtSecurityHTMLEscape\(f\.B\)')" ] \
  && [ "$(count "$COMPLIANCE_BODY" 'f\.C')" = "$(count "$COMPLIANCE_BODY" 'rtSecurityHTMLEscape\(f\.C\)')" ] \
  && [ "$(count "$COMPLIANCE_BODY" 'f\.E\b')" = "$(( $(count "$COMPLIANCE_BODY" 'rtSecurityHTMLEscape\(\*f\.E\)') + $(count "$COMPLIANCE_BODY" 'f\.E != nil') ))" ] \
  && lacks "$COMPLIANCE_BODY" 'f\.D'; then
  ok "B4 (control) no raw title/description/remediation/file_path is interpolated anywhere in the report"
else
  bad "B4 (control) a scan-derived field reaches the report HTML without rtSecurityHTMLEscape"
fi

# ── §C rt_databases.go: read/manage handlers admin-widened to match create ─
echo "── §C rt_databases.go: list/credentials/remove/getDbInfo/pitrConfig admin-widened ──"

ADMIN_WIDEN_RE="u\.role = 'admin'.*sv\.is_local OR sv\.user_id = u\.id"
SHARED_PRED=$(flat "$(awk '/^const rtDatabasesCallerPredicate = /{f=1} f{print} f && !/\+ *$/{exit}' <<< "$DATABASES_C")")
widened() { has "$(flat "$1")" "$ADMIN_WIDEN_RE" \
  || { has "$1" '"WHERE "\+rtDatabasesCallerPredicate' && has "$SHARED_PRED" "$ADMIN_WIDEN_RE"; }; }
for pair in "DB_LIST_BODY:C1:rtDatabasesList" "DB_CREDENTIALS_BODY:C2:rtDatabasesCredentials" "DB_REMOVE_BODY:C3:rtDatabasesRemove" "DB_GET_INFO_BODY:C4:rtDatabasesGetDbInfo"; do
  var="${pair%%:*}"; rest="${pair#*:}"; id="${rest%%:*}"; name="${rest#*:}"
  body="${!var}"
  if [ -n "$body" ] && widened "$body"; then
    ok "$id $name() carries the admin-widening EXISTS clause"
  else
    bad "$id $name() is missing the admin-widening EXISTS clause — creator/reader mismatch regressed"
  fi
done

if has "$(flat "$DB_PITR_CONFIG_BODY")" "$ADMIN_WIDEN_RE"; then
  ok "C5 rtDatabasesPitrConfig's inline ownership check carries the same admin-widening"
else
  bad "C5 rtDatabasesPitrConfig's inline check is missing the admin-widening"
fi

# Positive control: create's own predicate (the source of truth these were
# widened to match) must still be there, unchanged.
if has "$DB_CREATE_BODY" 'rtDatabasesResolveOwner\(' && has "$DB_RESOLVE_OWNER_BODY" 'SiteCallerPredicate'; then
  ok "C6 (control) create still authorizes through SiteCallerPredicate (rtDatabasesResolveOwner)"
else
  bad "C6 (control) create's own predicate regressed"
fi

# ── §D svc_panel_update.go: fleet plan sees the whole fleet for admins ──
echo "── §D svc_panel_update.go: PanelUpdateBuildFleetPlan admin-widened, mirroring servers/dashboard ──"

if has "$BUILD_FLEET_PLAN_BODY" '^func PanelUpdateBuildFleetPlan\([^)]*isAdmin bool'; then
  ok "D1 PanelUpdateBuildFleetPlan takes an isAdmin parameter"
else
  bad "D1 PanelUpdateBuildFleetPlan has no isAdmin parameter — still owner-only"
fi

if has "$BUILD_FLEET_PLAN_BODY" '\(\$2 OR user_id = \$1\)' && has "$BUILD_FLEET_PLAN_BODY" 'userID, isAdmin\)'; then
  ok "D2 the fleet-plan query widens to (\$2 OR user_id = \$1) with \$2 = isAdmin"
else
  bad "D2 the fleet-plan query still hard-scopes to a single admin's own servers"
fi

if has "$APPLY_FLEET_BODY" 'PanelUpdateBuildFleetPlan\(r\.Context\(\), st\.DB, c\.Sub, c\.Role == "admin"'; then
  ok "D3 rtUpdateApplyFleet passes the caller's admin status through to PanelUpdateBuildFleetPlan"
else
  bad "D3 rtUpdateApplyFleet no longer threads admin status into PanelUpdateBuildFleetPlan"
fi

# ── §E rt_update.go: apply-fleet's include_panel path enforces direction ─
echo "── §E rt_update.go: rtUpdateApplyFleet(include_panel) reuses rtUpdateRejectApplyTarget ──"

if has "$APPLY_FLEET_BODY" 'if body\.IncludePanel \{' && has "$APPLY_FLEET_BODY" 'rtUpdateRejectApplyTarget\('; then
  ok "E1 rtUpdateApplyFleet calls rtUpdateRejectApplyTarget when include_panel is set"
else
  bad "E1 rtUpdateApplyFleet's include_panel path still skips the direction/advertised-match guard"
fi

if has "$APPLY_FLEET_BODY" '"update_available_version"'; then
  ok "E2 rtUpdateApplyFleet reads the same advertised-version row apply checks"
else
  bad "E2 rtUpdateApplyFleet does not consult the advertised-version row"
fi

# Positive control: apply's own guard (the logic being reused) is unchanged.
if has "$UPDATE_C" '^func rtUpdateRejectApplyTarget\('; then
  ok "E3 (control) rtUpdateRejectApplyTarget itself is still defined and reused by apply-fleet"
else
  bad "E3 (control) rtUpdateRejectApplyTarget regressed"
fi

# ── §F svc_panel_update.go: StartPanelUpdate reserves InFlight atomically ─
echo "── §F svc_panel_update.go: PanelUpdateStartPanelUpdate closes the create_snapshot TOCTOU ──"

# The guard block: from the first h.mu.Lock() to the function-level
# h.mu.Unlock() that follows the reservation (the early-return Unlock is
# indented inside the if, so it doesn't end the block).
GUARD_BLOCK=$(awk '/h\.mu\.Lock\(\)/{f=1} f{print} f && /^\th\.mu\.Unlock\(\)/{exit}' <<< "$START_UPDATE_BODY")
LOCK_LN=$(lineof "$START_UPDATE_BODY" 'h\.mu\.Lock\(\)')
SNAP_LN=$(lineof "$START_UPDATE_BODY" 'PanelSnapshotCreateSnapshot\(')
if [ "$LOCK_LN" -gt 0 ] && [ "$SNAP_LN" -gt 0 ] && [ "$LOCK_LN" -lt "$SNAP_LN" ]; then
  ok "F1 the concurrent-apply guard takes the state lock up front, before the create_snapshot pipeline"
else
  bad "F1 PanelUpdateStartPanelUpdate no longer locks the state before create_snapshot — TOCTOU reopened"
fi

if has "$GUARD_BLOCK" 'PanelUpdateErrAlreadyInFlight' && has "$GUARD_BLOCK" 'h\.s = PanelUpdateUpdateState\{Kind: "in_flight"'; then
  ok "F2 the guard checks AND reserves InFlight inside the same lock hold"
else
  bad "F2 the reservation is not inside the same lock hold as the check — race window reopened"
fi

SNAP_FAIL=$(awk '/PanelSnapshotCreateSnapshot\(/{f=1} f{print} f && /PanelUpdateErrSnapshot/{exit}' <<< "$START_UPDATE_BODY")
if has "$SNAP_FAIL" 'if err != nil \{' && has "$SNAP_FAIL" 'h\.set\(panelUpdateIdle\(\)\)'; then
  ok "F3 a failed snapshot releases the reservation back to Idle"
else
  bad "F3 no release-on-snapshot-failure path found — a failed attempt could permanently lock the guard"
fi

# ── §G svc_panel_update.go: rollback gets an in-flight guard ────────────
echo "── §G svc_panel_update.go: PanelUpdateRollbackToSnapshot no longer races a concurrent apply ──"

if has "$ROLLBACK_BODY" '^func PanelUpdateRollbackToSnapshot\([^)]*h \*PanelUpdateStateHandle'; then
  ok "G1 PanelUpdateRollbackToSnapshot takes the PanelUpdateStateHandle"
else
  bad "G1 PanelUpdateRollbackToSnapshot has no handle parameter — still unguarded"
fi

RB_GUARD=$(lineof "$ROLLBACK_BODY" 'h\.s = PanelUpdateUpdateState\{Kind: "in_flight"')
RB_SPAWN=$(lineof "$ROLLBACK_BODY" 'PanelSnapshotSpawnRestore\(')
if has "$ROLLBACK_BODY" 'PanelUpdateErrAlreadyInFlight' && [ "$RB_GUARD" -gt 0 ] && [ "$RB_SPAWN" -gt 0 ] && [ "$RB_GUARD" -lt "$RB_SPAWN" ]; then
  ok "G2 PanelUpdateRollbackToSnapshot checks and reserves InFlight before calling PanelSnapshotSpawnRestore"
else
  bad "G2 PanelUpdateRollbackToSnapshot no longer reserves InFlight before the restore — race reopened"
fi

if has "$ROLLBACK_ROUTE_BODY" 'PanelUpdateRollbackToSnapshot\([^,]*, PanelUpdateState, st\.DB,'; then
  ok "G3 the rollback route threads the shared state handle through to PanelUpdateRollbackToSnapshot"
else
  bad "G3 the rollback route does not pass the shared PanelUpdateState handle — the guard is dead"
fi

echo
echo "=================================================="
echo "  PASS=$PASS FAIL=$FAIL"
echo "=================================================="

[ "$FAIL" -eq 0 ]
