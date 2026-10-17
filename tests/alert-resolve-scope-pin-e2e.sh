#!/usr/bin/env bash
# alert-resolve-scope-pin-e2e.sh — s355 / v2.109.0
#
# Pins the fix for a recovery path that resolved alerts it was never told about,
# and for an alert type that could not be resolved at all.
#
#   §A  `alerts` carries the entity key, and the unresolvable rows were retired.
#   §B  `NotificationsResolveAlert` is SCOPED BY THAT KEY, refuses to run unscoped, sends
#       nothing when it resolved nothing, and honours the per-type mute. This is
#       the section that matters: `alert_state` is keyed
#       (server_id, alert_type, state_key) and this UPDATE was keyed only
#       (user_id, server_id, alert_type), so one container recovering resolved
#       every other container's firing alert on that server — and because their
#       `alert_state` rows stayed 'firing', a transition-triggered engine never
#       re-announced them. The outages went silent permanently.
#   §C  every PER-ENTITY caller actually passes a key. A scoped UPDATE that all
#       its callers feed `""` is the same bug with more steps. The call list is
#       COMPUTED with a paren-balanced match, never a fixed `grep -A` window
#       (lessons #131/#172), and the enumeration is asserted before it is
#       trusted (#143).
#   §D  `slow_response` has a RESOLVE path. v2.107.0 gave it title-keyed dedup
#       and no clearing counterpart, so one slow check fired a row that stayed
#       'firing' for ever — visible to `check_escalations` through
#       idx_alerts_escalation_sweep, and read by the dedup guard itself, so the
#       stuck row also blinded every future slow-response check on that monitor.
#   §H  a SUCCESSFUL renewal clears the `ssl_renewal_failure` alerts that said
#       one had not happened — and clears ONLY those. `ssl_expiry` learned to
#       resolve long ago; this type never did, so a certificate that failed, was
#       fixed and then renewed left a critical row firing for up to seven days
#       while `check_escalations` re-paged it every thirty minutes and the
#       resolved-only purge never collected it. §H also pins the OTHER half: the
#       three standing conditions must NOT be cleared, because `DNS01_DOWNGRADED`
#       is raised on that same success path and `NotificationsFireAlertDeduped` windows on
#       `created_at` regardless of status, so resolving it would swallow its own
#       re-fire.
#   §I  a disabled alert type is not a fired alert. `try_fire_alert` returned
#       `Ok(())` (Rust era; now `NotificationsTryFireAlert`) whether it recorded a row or found the type switched off, so the
#       caller published a `visible_on_status_page` incident for an alert the
#       operator had silenced, and stamped the SSL ladder's rung for a page that
#       never went out.
#   §E  reopening an incident CLEARS `resolved_at`, on BOTH write paths, and
#       `postmortem` still keeps it. The stamp survived a reopen, so the public
#       status page rendered "Resolved <n> ago" over a live `investigating`.
#
# Pure source analysis: no box, no network, no build. Subjects are the Go API
# (panel/go/internal/api: svc_*.go / rt_*.go / migrations); identifiers follow
# its PORTING.md prefixes (resolve_alert -> NotificationsResolveAlert, etc.).
# The mutation record below was taken against the original Rust subjects; the
# arms were repointed to the Go code's shape when the Rust tree was retired.
#
# MUTATION-TESTED at HEAD — 7 mutations, 7 kills, each by the arm it names, with
# the control asserted to print a real summary first (an empty one is not a pass,
# lesson #461) and every tree restored byte-identical:
#   drop `state_key = $4` from a resolve_alert arm        -> B1 red, counts 2 of 3
#   delete the `resolved == 0` early return               -> B3 red
#   pass `""` at the container resolve call site          -> C2 red, prints it
#   repoint the slow_response resolve at another type     -> D1 red
#   revert the POST reopen branch to the unconditional UPDATE -> E2 red
#   widen the PUT reopen arm to include "postmortem"      -> E1 red
#   add a SEPARATE `Some("postmortem")` clearing arm      -> E3 red
#
# ⚠ E3 was REWRITTEN because the mutation run caught it (#442 — the mutation run
# is the test OF the suite). Its first cut anchored on
# `"postmortem"[^)]*=> ", resolved_at = NULL"`, which cannot cross the `)` a real
# over-reach puts in the way: it stayed GREEN under the widened-arm mutation and
# only E1's exact-string arm caught that by accident. Restated as a property of
# the clearing SITES, it is killed by an isolating mutation that leaves E1's and
# E2's strings byte-identical.
#
# NO PIPES INTO `grep -q` — under `set -o pipefail` grep -q closes the pipe on
# its first match and the arm goes red on correct code. Every arm uses a
# here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

API=panel/go/internal/api
NOTIF=$API/svc_notifications.go
ENGINE=$API/svc_alert_engine.go
HEALER=$API/svc_auto_healer.go
UPTIME=$API/svc_uptime.go
SCANNER=$API/svc_security_scanner.go
STOPS=$API/svc_expected_stops.go
INC=$API/rt_incidents.go
MIG=$API/migrations/20260813000000_alert_state_key.sql

for f in "$NOTIF" "$ENGINE" "$HEALER" "$UPTIME" "$SCANNER" "$STOPS" "$INC" "$MIG"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT. Copied from the FIXED stripper (lesson #136): the
# naive s{/\*.*?\*/}{}gs deletes real code because `/*` occurs inside string
# literals, and a truncated subject makes an ABSENCE arm pass on code the
# stripper merely removed — failure in the reassuring direction.
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }

# The body of one top-level Go func (plain or method), from the line after its
# `func` line to the gofmt-guaranteed closing `}` in column 0. A fixed
# `grep -A n` window is not a function (lesson #131/#172).
fnbody() {
  awk -v name="$2" '
    index($0, "func " name "(") == 1 || $0 ~ ("^func \\([^)]*\\) " name "\\(") { inside=1; next }
    inside && /^}$/ { exit }
    inside { print }
  ' <<< "$1"
}

# Every call to $2 in file $1, one per line, arguments PAREN-BALANCED and
# whitespace-flattened. Immune to gofmt reflowing a call across lines — the
# defect class that published 813 routes against a real 821 (lesson #462).
calls() {
  perl -0777 -ne '
    my $n = shift @ARGV;
    while (/\b\Q'"$2"'\E\s*(\((?:[^()]++|(?1))*\))/gs) {
      my $c = $1; $c =~ s/\s+/ /g; print "$c\n";
    }
  ' "$1"
}

echo "== §A  the entity key exists on alerts, and the dead rows were retired =="

if M=$(subj "$MIG"); then
  if grep -qE 'ALTER TABLE alerts ADD COLUMN IF NOT EXISTS state_key' <<< "$M"; then
    ok "A1 migration adds alerts.state_key"
  else
    bad "A1 migration adds alerts.state_key"
  fi

  # NOT NULL DEFAULT '' rather than nullable: `alert_state.state_key` already
  # uses '' for "about the whole server", so the two tables agree on the absent
  # value. A nullable column would silently match nothing under plain `=`.
  if grep -qE "state_key VARCHAR\(100\) NOT NULL DEFAULT ''" <<< "$M"; then
    ok "A2 the key is NOT NULL DEFAULT '' — same absent-value convention as alert_state"
  else
    bad "A2 the key is NOT NULL DEFAULT '' — same absent-value convention as alert_state"
  fi

  if grep -qE "alert_type = 'slow_response'" <<< "$M" \
  && grep -qE "SET status = 'resolved'" <<< "$M"; then
    ok "A3 migration retires the slow_response rows that could never resolve"
  else
    bad "A3 migration retires the slow_response rows that could never resolve"
  fi

  # The retirement must stay scoped to the one type that had no resolver. A
  # general "resolve every firing alert" sweep would clear live outages.
  if grep -qE 'UPDATE alerts' <<< "$M" \
  && [ "$(grep -cE 'UPDATE alerts' <<< "$M")" -eq 1 ]; then
    ok "A4 exactly ONE corrective UPDATE, scoped to slow_response — not a general sweep"
  else
    bad "A4 exactly ONE corrective UPDATE, scoped to slow_response — not a general sweep"
  fi
else
  for a in A1 A2 A3 A4; do bad "$a migration $MIG is readable"; done
fi

if N=$(subj "$NOTIF"); then
  FIRE=$(fnbody "$N" NotificationsTryFireAlert)
  if [ -n "$FIRE" ] && grep -qE 'INSERT INTO alerts .*state_key' <<< "$FIRE"; then
    ok "A5 NotificationsTryFireAlert records the key it will later be resolved by"
  else
    bad "A5 NotificationsTryFireAlert records the key it will later be resolved by"
  fi
else
  bad "A5 $NOTIF is readable"
fi

echo
echo "== §B  NotificationsResolveAlert is scoped, refuses to run unscoped, and stays quiet =="

if N=$(subj "$NOTIF"); then
  BODY=$(fnbody "$N" NotificationsResolveAlert)

  if [ -z "$BODY" ]; then
    for b in B1 B2 B3 B4; do bad "$b NotificationsResolveAlert body could not be extracted"; done
  else
    # THE headline arm. Count the UPDATE arms and require EVERY one to carry the
    # key — asserting the enumeration first (#143), because "0 of 0 arms are
    # unscoped" is the shape that passes on a deleted subject.
    ARMS=$(grep -cE "UPDATE alerts SET status = 'resolved'" <<< "$BODY")
    SCOPED=$(grep -cE 'state_key = \$4' <<< "$BODY")
    if [ "$ARMS" -ge 3 ] && [ "$SCOPED" -eq "$ARMS" ]; then
      ok "B1 all $ARMS resolve arms scope by state_key (none resolves a sibling entity)"
    else
      bad "B1 all resolve arms scope by state_key — found $ARMS arms, $SCOPED scoped"
    fi

    # Both ids NULL *and* an empty key would match every server-wide alert the
    # user has. That case must refuse, not guess.
    if grep -qE 'refusing to resolve unscoped' <<< "$BODY"; then
      ok "B2 no server, no site and no key is a REFUSAL, not an unscoped UPDATE"
    else
      bad "B2 no server, no site and no key is a REFUSAL, not an unscoped UPDATE"
    fi

    # "Resolved: X" for something that was never firing is a false all-clear,
    # and two auto_healer callers reach here without checking first.
    if grep -qE 'resolved, err := execSQL\(' <<< "$BODY" \
    && grep -qE 'if resolved == 0 \{' <<< "$BODY"; then
      ok "B3 a recovery notice is sent only if something was actually resolved"
    else
      bad "B3 a recovery notice is sent only if something was actually resolved"
    fi

    # A muted type that pages on recovery is still a page.
    if grep -qE 'notificationsIsTypeMuted\(' <<< "$BODY"; then
      ok "B4 the recovery notice honours the per-type mute"
    else
      bad "B4 the recovery notice honours the per-type mute"
    fi
  fi

  # The mute must be SINGLE-SOURCED. It drifted apart once already: applied on
  # the firing path, skipped on the resolve path.
  USERS=$(grep -cE '\bnotificationsIsTypeMuted\(' <<< "$N")
  if grep -qE '^func notificationsIsTypeMuted\(' <<< "$N" && [ "$USERS" -ge 3 ]; then
    ok "B5 notificationsIsTypeMuted is one function used by both the firing and resolving paths"
  else
    bad "B5 notificationsIsTypeMuted is one function used by both paths — $USERS references"
  fi
else
  for b in B1 B2 B3 B4 B5; do bad "$b $NOTIF is readable"; done
fi

echo
echo "== §C  every per-entity caller passes a real key =="

# ⚠ `expected_stops` added at v2.157.0. It was a TWELFTH production caller that
# this enumeration could not see for as long as it has existed, and its title
# matches C2's own `Container '` selector — so the arm that checks every
# per-entity caller passes a real key was silently checking eleven of twelve.
# It is correctly keyed; that is luck, not coverage.
ALLCALLS=$( { calls "$ENGINE" NotificationsResolveAlert
              calls "$HEALER" NotificationsResolveAlert
              calls "$STOPS" NotificationsResolveAlert
              calls "$UPTIME" NotificationsResolveAlert; } 2>/dev/null )
NCALLS=$(grep -c . <<< "$ALLCALLS")

# Assert the enumeration BEFORE trusting it (#143): an empty call list would
# make every arm below vacuously green.
if [ "$NCALLS" -ge 12 ]; then
  ok "C1 enumeration is sound — $NCALLS NotificationsResolveAlert call sites found"
else
  bad "C1 enumeration is sound — only $NCALLS NotificationsResolveAlert call sites found (expected >= 12)"
fi

# A call about a NAMED entity that also passes a literal "" is the original bug
# reintroduced at the call site: the UPDATE is scoped, and scoped to nothing.
ENTITY=$(grep -E "service_down|container_down|container_crashloop|container_unhealthy|Container '|slow_response" <<< "$ALLCALLS")
NENT=$(grep -c . <<< "$ENTITY")
UNKEYED=$(grep -E ', "", ' <<< "$ENTITY")
NUNKEYED=$(grep -c . <<< "$UNKEYED")

if [ "$NENT" -ge 4 ] && [ "$NUNKEYED" -eq 0 ]; then
  ok "C2 all $NENT per-entity resolve calls pass a real key, none passes \"\""
else
  bad "C2 per-entity resolve calls pass a real key — $NENT found, $NUNKEYED pass \"\""
  while IFS= read -r c; do [ -n "$c" ] && printf '        unkeyed: %.120s\n' "$c"; done <<< "$UNKEYED"
fi

echo
echo "== §D  slow_response can be resolved =="

if U=$(subj "$UPTIME"); then
  SLOWRESOLVE=$(grep -E '"slow_response"' <<< "$(calls "$UPTIME" NotificationsResolveAlert)")
  if [ -n "$SLOWRESOLVE" ]; then
    ok "D1 svc_uptime.go resolves slow_response when the response time recovers"
  else
    bad "D1 svc_uptime.go resolves slow_response when the response time recovers"
  fi

  # Dedup keyed on the monitor's id, not on the title. The title carries the
  # monitor NAME, so a rename raised a second firing alert for the same subject
  # and made the first unreachable.
  #
  # Was a single INSERT ... WHERE NOT EXISTS (state_key = $5::text); s414
  # split firing into a guard-SELECT + NotificationsTryFireAlert so the
  # firing half honours mutes/escalation like every other alert type. The
  # guard's own WHERE clause is what this pins now.
  if grep -qE "AND state_key = \\\$2\\)" <<< "$U"; then
    ok "D2 the slow_response dedup guard keys on state_key, not on the title"
  else
    bad "D2 the slow_response dedup guard keys on state_key, not on the title"
  fi

  # Fire and resolve must agree on the key or the resolve silently matches
  # nothing — a green build with the bug intact.
  NKEY=$(grep -cE '\bm\.ID\.String\(\)' <<< "$U")
  if [ "$NKEY" -ge 2 ]; then
    ok "D3 fire and resolve use the SAME key expression ($NKEY uses of m.ID.String())"
  else
    bad "D3 fire and resolve use the same key expression — only $NKEY use(s) of m.ID.String()"
  fi
else
  for d in D1 D2 D3; do bad "$d $UPTIME is readable"; done
fi

echo
echo "== §E  reopening an incident clears the resolution stamp, on both paths =="

if I=$(subj "$INC"); then
  # PUT path: the switch case must name all three live statuses.
  if perl -0777 -ne 'exit(/case "investigating", "identified", "monitoring":\s*resolvedAtClause = ", resolved_at = NULL"/ ? 0 : 1)' <<< "$I"; then
    ok "E1 the PUT path clears resolved_at for all three live statuses"
  else
    bad "E1 the PUT path clears resolved_at for all three live statuses"
  fi

  # POST path: the sibling that would have been left behind. Both endpoints
  # write this column, so fixing one leaves the defect reachable.
  if perl -0777 -ne 'exit(/switch req\.Status \{\s*case "investigating", "identified", "monitoring":\s*sql = "UPDATE managed_incidents SET status = \$2, resolved_at = NULL, updated_at = NOW\(\)/ ? 0 : 1)' <<< "$I"; then
    ok "E2 the POST path clears resolved_at for all three live statuses"
  else
    bad "E2 the POST path clears resolved_at for all three live statuses"
  fi

  # The arm that stops an over-broad fix: `postmortem` FOLLOWS a resolution, so
  # clearing the stamp there would destroy the very timestamp a postmortem is
  # written about.
  #
  # Stated as a property of the CLEARING SITES themselves rather than as one
  # spelled-out match arm. In Go the case label sits on the line ABOVE the
  # clearing assignment, so each clearing site is read together with the
  # `case` that governs it, and every clearer must have one. The first cut of this arm anchored on
  # `"postmortem"[^)]*=> ", resolved_at = NULL"`, which cannot cross the `)` that
  # a real over-reach puts in the way — so it stayed GREEN under the very
  # mutation it names, and only E1's exact-string arm caught it by accident
  # (lesson #442: the mutation run is the test OF the suite).
  NCLEAR=$(grep -cE 'resolved_at = NULL' <<< "$I")
  CLEARERS=$(perl -0777 -ne 'while (/^[ \t]*(case [^\n]*:)[ \t]*\n[^\n]*resolved_at = NULL[^\n]*/gm) { print "$1\n" }' <<< "$I")
  NCASED=$(grep -c . <<< "$CLEARERS")
  TAINTED=$(grep -c 'postmortem' <<< "$CLEARERS")
  if [ "$NCLEAR" -ge 2 ] && [ "$NCASED" -eq "$NCLEAR" ] && [ "$TAINTED" -eq 0 ]; then
    ok "E3 postmortem KEEPS its resolution stamp — $NCLEAR clearing sites, none mentions it"
  else
    bad "E3 postmortem KEEPS its resolution stamp — $NCLEAR clearing sites ($NCASED under a case label), $TAINTED mention it"
  fi
else
  for e in E1 E2 E3; do bad "$e $INC is readable"; done
fi

echo
echo "── s378 §F: a maintenance window silences the engine, not just the monitors ──"

# The panel offers a button labelled *Silence Alerts*, and the guide said "no
# alerts fire during the window". `svc_uptime.go` honoured it; this engine — which
# owns 14 of the 19 alert types — had never read the table, so `offline`,
# `service_down` and `container_down`, the three a planned maintenance is
# CERTAIN to cause, were exactly the ones that still paged.
#
# The arms below pin WHERE the check happens, not merely THAT it happens. That
# distinction is the whole fix: `alertEngineCheckServerOffline` selects the servers with
# no firing row and then writes one, so a guard at the FIRE would leave the row
# claiming the operator was paged while nothing was sent, and the condition
# would never page again. §F5 is the arm that forbids that regression.

if EG=$(subj "$ENGINE"); then
  # The Rust `run` loop body is the Go per-tick function.
  RUNBODY=$(fnbody "$EG" alertEngineTick)

  # F1 — loaded ONCE per tick, like svc_uptime.go does it, not per server per type.
  # Floored on the whole file too: a second loader elsewhere is the same regression.
  NLOAD=$(grep -c 'alertEngineMaintenanceUsers(ctx, db)' <<< "$RUNBODY")
  NLOADALL=$(grep -c 'alertEngineMaintenanceUsers(' <<< "$EG")
  if [ "$NLOAD" -eq 1 ] && [ "$NLOADALL" -eq 2 ]; then
    ok "F1 the tick loads the open-window set exactly once"
  else
    bad "F1 the tick loads the open-window set exactly once — found $NLOAD in the tick, $NLOADALL references in the file (expected 1 + the definition)"
  fi

  # F2/F3 — DERIVED, not listed. Every top-level check the tick calls with the
  # pool must both TAKE the set and USE it. Taking it and not using it is the
  # half-edit a signature-only arm cannot see (lesson #600).
  GUARDED=""; UNGUARDED=""
  for fn in alertEngineCheckResourceThresholds alertEngineCheckServerOffline alertEngineCheckSslExpiry alertEngineCheckStackSslExpiry alertEngineCheckRegisteredCertExpiry; do
    B=$(fnbody "$EG" "$fn")
    if grep -qE 'if maint\[[A-Za-z.]+\] \{' <<< "$B"; then GUARDED="$GUARDED $fn"; else UNGUARDED="$UNGUARDED $fn"; fi
  done
  NTAKE=$(grep -cE '^func alertEngineCheck[A-Za-z]+\(ctx context\.Context, db \*pgxpool\.Pool, maint map\[uuid\.UUID\]bool\)' <<< "$EG")
  if [ "$NTAKE" -eq 5 ]; then
    ok "F2 all five pool-driven checks take the open-window set"
  else
    bad "F2 all five pool-driven checks take the open-window set — found $NTAKE"
  fi
  if [ -z "$UNGUARDED" ]; then
    ok "F3 each of them SKIPS on it:$GUARDED"
  else
    bad "F3 each of them SKIPS on it — takes the set but never reads it:$UNGUARDED"
  fi

  # F4 — the fleet loop guards BEFORE the first per-member check, not after.
  # Ordering asserted by line number with both anchors present (lesson #582);
  # a guard below the call is a guard that has already paged.
  GLINE=$(grep -n 'if maint\[member\.UserID\] {' <<< "$RUNBODY" | head -1 | cut -d: -f1)
  CLINE=$(grep -n 'alertEngineCheckGpuThresholds(' <<< "$RUNBODY" | head -1 | cut -d: -f1)
  if [ -n "$GLINE" ] && [ -n "$CLINE" ] && [ "$GLINE" -lt "$CLINE" ]; then
    ok "F4 the fleet loop skips a silenced owner before any per-member check (guard $GLINE < call $CLINE)"
  else
    bad "F4 the fleet loop skips a silenced owner before any per-member check (guard '$GLINE', call '$CLINE')"
  fi

  # F5 — ABSENCE arm with a positive control. The suppression must NOT migrate
  # into the fire funnel: every caller that stamps `alert_state` does so beside
  # its fire, so a funnel-level skip converts a deferral into permanent silence.
  FWR=$(fnbody "$EG" alertEngineFireAlertWithRetry)
  if grep -q 'NotificationsTryFireAlert(' <<< "$FWR"; then
    ok "F5-control the fire funnel was extracted and is non-empty"
    if grep -q 'maint' <<< "$FWR"; then
      bad "F5 the window is NOT consulted at the fire — it is, and every stamp beside a fire then claims a page that never went out"
    else
      ok "F5 the window is not consulted at the fire, so a held alert is deferred and not marked sent"
    fi
  else
    bad "F5-control the fire funnel was extracted and is non-empty"
  fi
else
  for a in F1 F2 F3 F4 F5; do bad "$a $ENGINE is readable"; done
fi

# F6 — the one-shot producers are deliberately NOT suppressed, because nothing
# re-raises them afterwards. Derived over the whole services tree rather than
# asserted against a list, so a new suppression site anywhere shows up here.
#
# ⚠ NOT `git grep`: this suite must run from a `git worktree` or an unpacked
# archive, where it enumerates nothing and the arm goes red on correct code.
# The enumeration is asserted non-empty first, so "found none" can never be
# mistaken for either a pass or a real absence.
# The Go api package is flat: the services tree is its svc_*.go files (tests
# excluded — a fixture naming the table is not a suppression site).
SVCDIR=$API
SVCFILES=$(ls "$SVCDIR"/svc_*.go 2>/dev/null | grep -v '_test\.go$')
ALLSVC=$( [ -n "$SVCFILES" ] && /usr/bin/grep -lE '^func ' $SVCFILES 2>/dev/null | wc -l)
ALLSVC=${ALLSVC:-0}
SUPPRESSORS=$( [ -n "$SVCFILES" ] && /usr/bin/grep -l 'maintenance_windows' $SVCFILES 2>/dev/null | sort | paste -sd' ' -)
if [ "$ALLSVC" -lt 10 ]; then
  bad "F6-control the services tree enumerated $ALLSVC files — the scan found nothing to measure"
else
  ok "F6-control the services tree enumerated $ALLSVC files"
  if [ "$SUPPRESSORS" = "$SVCDIR/svc_alert_engine.go $SVCDIR/svc_uptime.go" ]; then
    ok "F6 exactly the two standing-condition services suppress: $SUPPRESSORS"
  else
    bad "F6 exactly the two standing-condition services suppress — found: ${SUPPRESSORS:-none}"
  fi
fi

echo
echo "── s401 §G: the DEDUP guard is keyed per condition, not per site ────────────"

# §C asserts that every per-entity caller of `NotificationsResolveAlert` passes a real key,
# and states the principle it was written for: a scoped query all of whose
# callers feed the whole-server key is the same bug with more steps. That is
# exactly what `NotificationsFireAlertDeduped` was — the OTHER function keyed on
# `state_key`, whose callers were never enumerated.
#
# All eight of its call sites raise `ssl_renewal_failure`, covering FIVE
# different conditions, and every one passed the whole-server key. The guard
# dedups on (alert_type, site_id, state_key), so the five collapsed into one
# subject and whichever fired first muted the other four for twelve hours —
# four of the five being `critical`.
#
# The pairing that made it fatal is sequential, not coincidental: while a DNS-01
# zone is unreachable `RenewalPlan::Refuse` re-alerts every twelve hours, and the
# downgrade it ends in fires only once that same refusal reaches the last week —
# so a warning is ALWAYS inside the window hiding the critical, and the alert
# naming which hostnames stopped being covered could never reach anybody.
#
# ⚠ The fix must NOT key on the loop. Two comments in the subjects say the
# scanner and the healer deliberately share a bucket for the same certificate
# (the security scanner's "Deduped per site so the six-hourly scan cannot stack up
# duplicates alongside the auto-healer's own alert"), so the SAME condition in
# both loops must keep collapsing to one alert. G4 pins that direction; without
# it a "fix" that keyed per call site would pass G2 and G3 and reintroduce the
# flood the dedup exists to stop.

DEDUP_H=$(calls "$HEALER" NotificationsFireAlertDeduped 2>/dev/null)
DEDUP_S=$(calls "$SCANNER" NotificationsFireAlertDeduped 2>/dev/null)
DEDUP_ALL=$(printf '%s\n%s\n' "$DEDUP_H" "$DEDUP_S" | grep -c .)

# Assert the enumeration BEFORE trusting it (#143, and §C1's own precedent): an
# empty call list makes every arm below vacuously green, which is precisely how
# this defect survived two suites that both mention `fire_alert_deduped`.
if [ "$DEDUP_ALL" -ge 8 ]; then
  ok "G1 enumeration is sound — $DEDUP_ALL NotificationsFireAlertDeduped call sites found"
else
  bad "G1 enumeration is sound — only $DEDUP_ALL NotificationsFireAlertDeduped call sites found (expected >= 8)"
fi

# G2 is C2 for the other keyed function. A dedup guard scoped by a key that every
# caller leaves empty is scoped to nothing.
UNKEYED_D=$(printf '%s\n%s\n' "$DEDUP_H" "$DEDUP_S" | grep -E '"ssl_renewal_failure", ""')
NUNKEYED_D=$(grep -c . <<< "$UNKEYED_D")
if [ "$NUNKEYED_D" -eq 0 ]; then
  ok "G2 no NotificationsFireAlertDeduped call passes the whole-server key for a per-certificate condition"
else
  bad "G2 NotificationsFireAlertDeduped calls pass a real key — $NUNKEYED_D pass the empty key"
  while IFS= read -r c; do [ -n "$c" ] && printf '        unkeyed: %.140s\n' "$c"; done <<< "$UNKEYED_D"
fi

# G3: the conditions are distinct SUBJECTS. Counting the keys rather than
# asserting a fixed list means a sixth condition must pick a key of its own
# instead of borrowing one, and the count moves when it does. Only the
# per-site keys (the named constants) — the stack/docker-app arms key on a
# domain-bearing helper and are a different population (§H8).
KEYS=$(printf '%s\n%s\n' "$DEDUP_H" "$DEDUP_S" \
       | grep -oE '"ssl_renewal_failure", NotificationsSslRenewalKey[A-Za-z0-9]+' \
       | sed -E 's/.*NotificationsSslRenewalKey//' | sort -u)
NKEYS=$(grep -c . <<< "$KEYS")
if [ "$NKEYS" -eq 5 ]; then
  ok "G3 the five renewal conditions are five dedup subjects: $(paste -sd' ' - <<< "$KEYS")"
else
  bad "G3 the five renewal conditions are five dedup subjects — found $NKEYS: $(paste -sd' ' - <<< "$KEYS")"
fi

# G4 — the still-member direction, and the one a per-call-site "fix" would fail.
# Each condition raised by BOTH loops must carry the SAME key in both, or the
# six-hourly scan stacks a duplicate on top of the healer's alert for one cert.
SHARED_OK=1
for k in Failed Dns01Declined Dns01Downgraded; do
  inh=$(grep -cE "NotificationsSslRenewalKey$k\b" <<< "$DEDUP_H")
  ins=$(grep -cE "NotificationsSslRenewalKey$k\b" <<< "$DEDUP_S")
  if [ "$inh" -lt 1 ] || [ "$ins" -lt 1 ]; then
    SHARED_OK=0
    printf '        %s: healer=%s scanner=%s\n' "$k" "$inh" "$ins"
  fi
done
if [ "$SHARED_OK" -eq 1 ]; then
  ok "G4 every condition both loops raise shares one key, so one certificate is still one alert"
else
  bad "G4 every condition both loops raise shares one key — a loop-scoped key would reflood"
fi

# G5: one home for the keys. An inline literal at a call site is how a sixth
# condition quietly rejoins an existing subject, and it is invisible to G3
# because a literal that matches an existing key changes no count.
# Go has no module: the keys are one `const ( ... )` block of
# NotificationsSslRenewalKey* names in svc_notifications.go.
KEYDEFS=$(grep -cE '^[[:space:]]*NotificationsSslRenewalKey[A-Za-z0-9]+ = "' "$NOTIF")
INLINE=$(printf '%s\n%s\n' "$DEDUP_H" "$DEDUP_S" | grep -E '"ssl_renewal_failure", "' | grep -c .)
# ⚠ 5 -> 6 at v2.156.0, in the same commit as the key that moved it. The sixth is
# MAIL_HOST_CONFLICT, raised from the mail routes when a mail host's certificate is
# deliberately NOT issued because issuing it would overwrite a wildcard or a
# foreign certificate. It is NOT a healer/scanner subject, so G3 above is
# untouched and still counts five conditions in those two loops — the two arms
# measure different populations and only this one moves when a key is added
# elsewhere. Reusing BLOCKED instead would have kept this number at five and
# given two opposite messages about the same site one dedup subject, which is the
# suppression defect v2.154.0 shipped to fix.
if [ "$KEYDEFS" -eq 6 ] && [ "$INLINE" -eq 0 ]; then
  ok "G5 all six keys are named constants in one const block, and no call site inlines a literal"
else
  bad "G5 all six keys are named constants in one const block — $KEYDEFS defined, $INLINE inline literal(s) at call sites"
fi

echo
echo "== §H  a successful renewal clears the alerts that said none happened, and only those =="

if N=$(subj "$NOTIF"); then
  RES=$(fnbody "$N" NotificationsResolveSslRenewalFailure)
  # FLOOR the body before trusting any absence arm below it. An empty extraction
  # would make H3 and H4 pass over nothing at all (#461).
  RESLINES=$(grep -c . <<< "$RES")
  if [ "$RESLINES" -ge 8 ]; then
    ok "H1 NotificationsResolveSslRenewalFailure body extracted — $RESLINES lines"

    # It must decide through the TESTED predicate over the WHOLE key list, not a
    # hand-written subset. A literal list here would compile, behave identically
    # today, and silently stop tracking `renewal_success_clears` — whose unit
    # tests are the only thing that says which keys belong.
    if grep -qE 'range NotificationsSslRenewalKeyAll\b' <<< "$RES" \
    && grep -qE 'NotificationsRenewalSuccessClears\(' <<< "$RES"; then
      ok "H2 the resolver filters the whole key list through NotificationsRenewalSuccessClears"
    else
      bad "H2 the resolver filters the whole key list through NotificationsRenewalSuccessClears — a hand-written subset drifts from the tested predicate"
    fi

    # ⚠ THE SCOPING ARM. `NotificationsResolveAlert` picks its arm on `serverID != nil`
    # FIRST, so a server id here builds `WHERE server_id = $2` and misses every
    # row the SCANNER raised — that loop fires with `nil` while the healer's
    # FAILED fires with a server id. The same logical alert exists in two
    # shapes and only the site arm matches both.
    RESCALL=$(calls "$NOTIF" NotificationsResolveAlert | grep -F 'ssl_renewal_failure' || true)
    if [ -n "$RESCALL" ] && grep -qE '^\( *ctx, *db, *userID, *nil, *&siteID,' <<< "$RESCALL"; then
      ok "H3 the resolve is scoped by site with serverID nil, so it matches rows from BOTH loops"
    else
      bad "H3 the resolve is scoped by site with serverID nil — a server id misses every scanner-raised row (got: ${RESCALL:-no call found})"
    fi

    # The three standing conditions must not be reachable from this body. Naming
    # any of them here is the regression: DNS01_DOWNGRADED is RAISED on the same
    # success path, so resolving it lets the re-fire land inside its own dedup
    # window and disappear.
    STANDING=0
    for k in Dns01Downgraded Declined MailHostConflict; do
      # Dns01Declined does not share the NotificationsSslRenewalKeyDeclined
      # prefix, and \b stops Declined matching a longer name.
      if grep -qE "NotificationsSslRenewalKey${k}\b" <<< "$RES"; then
        STANDING=$((STANDING+1))
        printf '     names %s\n' "$k"
      fi
    done
    if [ "$STANDING" -eq 0 ]; then
      ok "H4 the resolver names none of the three standing conditions"
    else
      bad "H4 the resolver names none of the three standing conditions — $STANDING named, and a success does not disprove them"
    fi
  else
    for a in H1 H2 H3 H4; do bad "$a NotificationsResolveSslRenewalFailure body is too small to test ($RESLINES lines) — the resolver is missing or was renamed"; done
  fi

  # H5 retired: covered by TestNotificationsAnUnrecognisedKeyIsLeftAlone (panel/go/internal/api/svc_notifications_test.go)

  # ALL must list every constant BY NAME, or a key added later is silently never
  # considered by `NotificationsRenewalSuccessClears`.
  #
  # ⚠ MEMBERSHIP, not length. The first cut of this arm compared the declared
  # array length against KEYDEFS — which the compiler already enforces, so
  # it tested nothing the build did not: dropping MAIL_HOST_CONFLICT and
  # duplicating DECLINED to hold the length at six passed G5, H2, H6 AND the
  # unit tests. Matched on the whole line (`^\s*NAME,$`) so one name cannot
  # satisfy another, and scoped to the array literal's own range because a
  # bare grep for a key name is satisfied by its own const declaration.
  ALLBLOCK=$(sed -n '/^var NotificationsSslRenewalKeyAll = \[[0-9]*\]string{/,/^}/p' "$NOTIF")
  KEYNAMES=$(grep -oE '^[[:space:]]*NotificationsSslRenewalKey[A-Za-z0-9]+ = "' "$NOTIF" | grep -oE 'NotificationsSslRenewalKey[A-Za-z0-9]+')
  NKEYNAMES=$(grep -c . <<< "$KEYNAMES")
  MEMBER_BAD=0
  if [ "$NKEYNAMES" -ge 5 ] && [ -n "$ALLBLOCK" ]; then
    while IFS= read -r k; do
      [ -n "$k" ] || continue
      n=$(grep -cE "^[[:space:]]*${k},[[:space:]]*$" <<< "$ALLBLOCK")
      if [ "$n" -ne 1 ]; then
        MEMBER_BAD=$((MEMBER_BAD+1))
        printf '     %s listed %s time(s)\n' "$k" "$n"
      fi
    done <<< "$KEYNAMES"
    if [ "$MEMBER_BAD" -eq 0 ]; then
      ok "H6 NotificationsSslRenewalKeyAll lists each of the $NKEYNAMES constants exactly once"
    else
      bad "H6 NotificationsSslRenewalKeyAll lists each of the $NKEYNAMES constants exactly once — $MEMBER_BAD wrong, so a key the resolver never considers"
    fi
  else
    bad "H6 NotificationsSslRenewalKeyAll membership — extraction broke ($NKEYNAMES names, ALL block ${ALLBLOCK:+present}${ALLBLOCK:-absent})"
  fi
else
  for a in H1 H2 H3 H4 H6; do bad "$a $NOTIF is readable"; done
fi

# Both renewal-SUCCESS paths must call it. A guard on one loop only is the drift
# shape this project keeps finding: the scanner is the ONLY automatic renewal on
# a stock install, and the healer is the one that ticks every two minutes.
for pair in "HEALER:$HEALER" "SCANNER:$SCANNER"; do
  label=${pair%%:*}; file=${pair#*:}
  if F=$(subj "$file"); then
    if grep -qE 'NotificationsResolveSslRenewalFailure\(' <<< "$F"; then
      ok "H7 the $label renewal-success path clears the renewal alerts"
    else
      bad "H7 the $label renewal-success path clears the renewal alerts — this loop renews and never resolves"
    fi
  else
    bad "H7 $file is readable"
  fi
done

# ⭐ H8 — THE STACK RENEWAL'S FIRE AND RESOLVE, WHICH H7 STRUCTURALLY CANNOT SEE.
#
# H7 greps the WHOLE FILE for `NotificationsResolveSslRenewalFailure`, so the SITE arm
# satisfies it for the whole module — classic sibling satisfaction. The Compose
# stack arm added at v2.161.0 cannot use that resolver at all: it takes a
# non-optional `site_id` (a stack has none) and iterates a fixed key array that
# cannot hold a domain-bearing composite. It therefore fires and resolves through
# `NotificationsResolveAlert` with its own key, and if those two spellings ever drift the
# alert fires and never clears — thirty-minute escalations for a week about a
# certificate that is already healthy. That is the exact defect
# `NotificationsResolveSslRenewalFailure` was written for, reached by a different door.
#
# So this arm reads the stack function's OWN body, and requires the key to come
# from the SHARED function on both sides — a literal on either side is drift
# waiting to happen.
if S=$(subj "$SCANNER"); then
  STACKFN=$(fnbody "$S" securityScannerRenewStackCertificate)
  STACKLINES=$(grep -c . <<< "$STACKFN")
  # Floor: an empty or mis-anchored body would satisfy every absence below and
  # print green for a function that no longer exists (lesson #143).
  if [ "$STACKLINES" -ge 40 ]; then
    ok "H8 securityScannerRenewStackCertificate body extracted — $STACKLINES lines"

    KEYUSES=$(grep -oF 'SecurityScannerStackRenewalStateKey(domain)' <<< "$STACKFN" | wc -l | tr -d ' ')
    if [ "$KEYUSES" = "2" ]; then
      ok "H8a the stack alert's key is computed once and used by BOTH the fire and the resolve"
    else
      bad "H8a the stack alert's key is computed once and used by BOTH the fire and the resolve" \
          "expected 2 uses of SecurityScannerStackRenewalStateKey(domain), got $KEYUSES — a hand-spelled key on either side is a fire that never clears"
    fi

    if grep -qF 'NotificationsResolveAlert(' <<< "$STACKFN"; then
      ok "H8b the stack renewal-success path clears its own alert"
    else
      bad "H8b the stack renewal-success path clears its own alert" \
          "this loop renews and never resolves — the alert escalates every 30 minutes for a week after a success"
    fi
  else
    bad "H8 securityScannerRenewStackCertificate body extracted" \
        "got $STACKLINES lines, expected >= 40 — the anchor has moved and §H8 is measuring nothing"
  fi
else
  bad "H8 $SCANNER is readable" "subject empty"
fi

echo
echo "== §I  a disabled alert type is not a fired alert =="

if N=$(subj "$NOTIF"); then
  FIRE2=$(fnbody "$N" NotificationsTryFireAlert)
  FIRELINES=$(grep -c . <<< "$FIRE2")
  if [ "$FIRELINES" -ge 20 ]; then
    ok "I1 NotificationsTryFireAlert body extracted — $FIRELINES lines"

    # The signature must carry the answer. `Result<(), String>` (the Rust
    # original) cannot express "nothing was recorded", which is the whole defect.
    #
    # ⚠ Read off NotificationsTryFireAlert's OWN declaration. The first cut was
    # two independent whole-file greps, and a sibling declaration satisfied the
    # second. #797.
    SIG=$(grep -E '^func NotificationsTryFireAlert\(' <<< "$N" | head -1 | sed -E 's/.*\)[[:space:]]*(\([^()]*\))[[:space:]]*\{$/\1/')
    if [ -n "$SIG" ] && [ "$SIG" = "(bool, error)" ]; then
      ok "I2 NotificationsTryFireAlert's own signature returns whether it recorded anything"
    else
      bad "I2 NotificationsTryFireAlert's own signature returns whether it recorded anything — got '${SIG:-no declaration found}'"
    fi

    # ⚠ THE POSITIVE HALF. I3 only asserts what the disabled path returns, so a
    # function that answers `false, nil` on EVERY path — nothing ever recorded,
    # the SSL ladder never advancing, no incident ever raised — would satisfy it.
    # A guard is not proven by its refusals. (`return false, fmt.Errorf(...)` on
    # the INSERT's own error path is an error, not a "not recorded" answer.)
    INSLINE=$(grep -nE 'INSERT INTO alerts' <<< "$FIRE2" | head -1 | cut -d: -f1)
    TRUE_AFTER=$(grep -nE 'return true, nil$' <<< "$FIRE2" | awk -F: -v i="${INSLINE:-0}" '$1 > i' | grep -c .)
    FALSE_AFTER=$(grep -nE 'return false, nil$' <<< "$FIRE2" | awk -F: -v i="${INSLINE:-0}" '$1 > i' | grep -c .)
    if [ -n "$INSLINE" ] && [ "$TRUE_AFTER" -ge 1 ] && [ "$FALSE_AFTER" -eq 0 ]; then
      ok "I6 every path past the alerts INSERT reports a real fire ($TRUE_AFTER true, $FALSE_AFTER false)"
    else
      bad "I6 every path past the alerts INSERT reports a real fire — INSERT at ${INSLINE:-absent}, $TRUE_AFTER 'return true, nil' and $FALSE_AFTER 'return false, nil' after it"
    fi

    # The Rust arm also forbade a leftover `Ok(())`; Go's (bool, error)
    # signature (I2) makes a unit return uncompilable, so what remains is the
    # disabled path's own answer. Asserted on the RESULT of the enabled check,
    # not the call alone — grepping for the call would be satisfied even if
    # its result were thrown away (#797).
    if perl -0777 -ne 'exit(/if !NotificationsIsAlertEnabled\([^)]*\) \{\s*return false, nil\s*\}/ ? 0 : 1)' <<< "$FIRE2"; then
      ok "I3 the disabled path returns false, nil — a suppressed alert does not read as fired"
    else
      bad "I3 the disabled path must return false, nil — a suppressed alert still reads as fired"
    fi
  else
    for a in I1 I2 I3 I6; do bad "$a NotificationsTryFireAlert body is too small to test ($FIRELINES lines)"; done
  fi
else
  for a in I1 I2 I3 I6; do bad "$a $NOTIF is readable"; done
fi

if E=$(subj "$ENGINE"); then
  RETRY=$(fnbody "$E" alertEngineFireAlertWithRetry)
  RETRYLINES=$(grep -c . <<< "$RETRY")
  if [ "$RETRYLINES" -ge 20 ]; then
    # POSITIONAL, not a window (#172): the suppressed arm has to come BEFORE the
    # incident write, or the incident is created either way and the public status
    # page still publishes an alert the operator switched off. And it must
    # return FALSE, not true — read as one block, so a `return true` there
    # cannot satisfy it.
    SUPP=$(grep -nE 'if err == nil && !fired \{' <<< "$RETRY" | head -1 | cut -d: -f1)
    INCID=$(grep -nE 'INSERT INTO managed_incidents' <<< "$RETRY" | head -1 | cut -d: -f1)
    if [ -n "$SUPP" ] && [ -n "$INCID" ] && [ "$SUPP" -lt "$INCID" ] \
       && perl -0777 -ne 'exit(/if err == nil && !fired \{\s*return false\s*\}/ ? 0 : 1)' <<< "$RETRY"; then
      ok "I4 the suppressed arm returns false before any incident is written (line $SUPP < $INCID)"
    else
      bad "I4 the suppressed arm returns false before any incident is written — suppressed at ${SUPP:-absent}, incident at ${INCID:-absent}"
    fi

    # The SSL ladder gates `last_warned_day` on this answer, so a `true` for
    # the suppressed case consumes a rung for a page that never went out and
    # `alertEngineSslDecision` only ever fires a TIGHTER one afterwards. The
    # fired case is its OWN branch (`if err == nil {` reached only once
    # `!fired` has returned) and is the one that answers true.
    if grep -qE '^[[:space:]]*if err == nil \{$' <<< "$RETRY" && grep -qE '^[[:space:]]*return true$' <<< "$RETRY"; then
      ok "I5 the fired and suppressed cases are distinct branches"
    else
      bad "I5 the fired and suppressed cases are distinct branches — a single err == nil branch cannot tell them apart"
    fi
  else
    for a in I4 I5; do bad "$a alertEngineFireAlertWithRetry body is too small to test ($RETRYLINES lines)"; done
  fi
else
  for a in I4 I5; do bad "$a $ENGINE is readable"; done
fi

echo
printf 'alert-resolve-scope: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
