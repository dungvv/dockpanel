#!/usr/bin/env bash
# monitors-honest-reads-pin-e2e.sh — s407 / v2.159.0
#
# Pins two properties of the monitoring routes, both of which had failed in the
# same direction: the reassuring answer.
#
#   §A  the four reads in `rt_monitors.go` REPORT a failed query instead of
#       answering it with an empty list. All four discarded the error, so a
#       failure rendered as an emptiness the operator cannot tell from a real
#       one: "No SSL certificates found" on the certificate page, a public
#       status page with no monitors on it, an empty response chart, and — the
#       consequential one — a maintenance list showing no windows while
#       `svc_uptime.go` was still skipping every monitor a live window covers.
#   §B  the certificate ladder can say RENEWAL FAILED. Every rung was a
#       function of the clock, so a certificate whose renewal is failing read
#       `ok` until its last month. v2.157.0 made `ssl_renewal_failure` resolve
#       itself on a successful renewal, which sharpened the gap rather than
#       closing it: a failure that is fixed now disappears, and one that is not
#       had no rung to appear in.
#   §C  the rung's SOURCE. The keys come from the shared list filtered through
#       the shared predicate, never re-listed here — a second copy of that
#       classification is free to drift from the first. Scoped to firing rows
#       only, because `resolve_alert` clears only firing rows and an
#       acknowledged alert would pin the rung on for ever.
#       (Ported to Go: the api is panel/go/internal/api; §B's ladder ORDER is
#       now a unit test, TestPinMonitorsHonestReadsLadder.)
#   §D  every ladder call site passes the new argument, including the host-scan
#       half that must pass `false` — those certificates have no site row, so
#       nothing can raise a renewal alert against them.
#   §E  the page renders the rung, and stops reporting a failed read as an
#       empty list.
#
# Pure source analysis: no box, no network, no build.
#
# ⚠ EVERY arm reads STRIPPED source. This ship wrote long comments into both
# subjects, and they name the very literals these arms match — `renewal_failed`,
# the firing status, the predicate's own name. Against raw text most of §B and
# §C would be satisfied by the prose that describes them and would stay green
# with the code deleted (the trap in feedback_source_pin_prose_trap).
#
# NO PIPES INTO `grep -q` — under `set -o pipefail` grep -q closes the pipe on
# its first match and the arm goes red on correct code.
#
# MUTATION-TESTED at HEAD — see the run recorded in the ship's ledger.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

MON=panel/go/internal/api/rt_monitors.go
NOTIF=panel/go/internal/api/svc_notifications.go
CERTS=panel/frontend/src/pages/Certificates.tsx

for f in "$MON" "$NOTIF" "$CERTS"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT. The naive block-comment strip deletes real code
# because the opener occurs inside string literals, and a truncated subject
# makes an ABSENCE arm pass on code the stripper merely removed.
# Go adds trailing `// ...` comments; those are stripped only when nothing
# after the `//` could close a string, so a "https://" literal survives.
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
    s{[ \t]+//[^"`\n]*$}{}gm;
  ' "$1"
}

subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }

# The body of one top-level Go func, bounded by its closing `}` at column 0
# (gofmt guarantees it). A fixed `grep -A n` window is not a function.
fnbody() {
  awk -v name="$2" '
    /^func / {
      if (index($0, "func " name "(") == 1 || $0 ~ ("^func \\([^)]*\\) " name "\\(")) { inside=1; next }
    }
    inside && /^}/ { inside=0 }
    inside { print }
  ' <<< "$1"
}

# Every call to $2 in text $1, one per line, arguments PAREN-BALANCED and
# whitespace-flattened. Immune to gofmt reflowing a call across lines.
calls() {
  perl -0777 -ne '
    while (/\b\Q'"$2"'\E\s*(\((?:[^()]++|(?1))*\))/gs) {
      my $c = $1; $c =~ s/\s+/ /g; print "$c\n";
    }
  ' <<< "$1"
}

M=$(subj "$MON") || { bad "rt_monitors.go stripped to nothing"; M=""; }
N=$(subj "$NOTIF") || { bad "svc_notifications.go stripped to nothing"; N=""; }
C=$(subj "$CERTS") || { bad "Certificates.tsx stripped to nothing"; C=""; }

echo "== §A  a failed read is reported, not answered with an empty list =="

# ⛔ CONTROL, AND ITS NUMBER IS THE ARM. Every §A arm below is scoped to a
# function body; a body that stops being found yields the empty string and every
# assertion over it passes for a file that no longer contains the code. This
# floors the whole subject first, and PRINTS the count so an implausible one is
# visible rather than merely ticked.
A_LINES=$(wc -l <<< "$M")
if [ "$A_LINES" -ge 600 ]; then
  ok "A-control rt_monitors.go stripped subject is $A_LINES lines"
else
  bad "A-control rt_monitors.go stripped subject is only $A_LINES lines — subject lost"
fi

# The four reads, and the distinct context each one reports under. A shared
# context string would make one arm satisfiable by another's site.
for pair in \
  "rtMonitorsResponseChart:response chart points" \
  "rtMonitorsStatusPage:status page monitors" \
  "rtMonitorsCertificateDashboard:certificate list" \
  "rtMonitorsListMaintenance:maintenance windows"
do
  fn=${pair%%:*}; ctx=${pair#*:}
  B=$(fnbody "$M" "$fn")
  BL=$(wc -l <<< "$B")
  if [ "$BL" -lt 5 ]; then
    bad "A-body $fn — body extracted as $BL lines, subject lost"
    continue
  fi
  # POSITIVE: the body reaches a fallible read AND maps its error under its own
  # name. Not "does not swallow" — that it REPORTS.
  if grep -qF 'queryAll[' <<< "$B" && grep -qF "internalError(\"$ctx\"" <<< "$B"; then
    ok "A1 $fn reports a failed read as \"$ctx\" ($BL-line body)"
  else
    bad "A1 $fn reports a failed read as \"$ctx\" ($BL-line body)"
  fi
done

# REFUSAL, whole-file: the swallow is gone from every read in the file, not just
# the four above. Whole-file is the strongest form of this one — the literal
# must appear nowhere. Go's two shapes of Rust's `.unwrap_or_default()` on a
# list read: the error blanked (`x, _ := queryAll[...]`), or caught and
# answered with an empty value (`if err != nil { x = []T{} }` / `= nil`).
if perl -0777 -ne 'exit(/_\s*:?=\s*queryAll\[/ || /err != nil \{\s*\w+ = (?:\[\][\w.\[\], ]*\{\}|nil)\s*\}/ ? 0 : 1)' <<< "$M"; then
  bad "A2 no list read in rt_monitors.go discards its error"
else
  ok "A2 no list read in rt_monitors.go discards its error"
fi

# CONTROL for A2: an absence arm needs a positive control, or it cannot tell
# "the swallow is gone" from "the reads are gone".
A_READS=$(grep -cE 'query(All|Opt|One|Scalar|ScalarOpt)\[' <<< "$M")
if [ "$A_READS" -ge 10 ]; then
  ok "A2-control rt_monitors.go still performs $A_READS reads"
else
  bad "A2-control rt_monitors.go performs only $A_READS reads — A2 may be vacuous"
fi

echo "== §B  the ladder can say the renewal is failing =="

# B-control retired: covered by TestPinMonitorsHonestReadsLadder (panel/go/internal/api/pin_monitors_honest_reads_test.go)
# B1 retired: covered by TestPinMonitorsHonestReadsLadder (panel/go/internal/api/pin_monitors_honest_reads_test.go) — it calls rtMonitorsExpiryStatus(*int64, bool), so a ladder without the renewal argument does not compile
# B2 retired: covered by TestPinMonitorsHonestReadsLadder (panel/go/internal/api/pin_monitors_honest_reads_test.go)
# B3 retired: covered by TestPinMonitorsHonestReadsLadder (panel/go/internal/api/pin_monitors_honest_reads_test.go) — (-1, true) must be "expired"
# B4 retired: covered by TestPinMonitorsHonestReadsLadder (panel/go/internal/api/pin_monitors_honest_reads_test.go) — renewal_failed at nil/3/20/300 days
# B5 retired: covered by TestPinMonitorsHonestReadsLadder (panel/go/internal/api/pin_monitors_honest_reads_test.go) — all five clock rungs with the flag false
if (cd panel/go && go test ./internal/api/ -run '^TestPinMonitorsHonestReadsLadder$' -count=1 >/dev/null 2>&1); then
  ok "B-test TestPinMonitorsHonestReadsLadder passes (ladder order + all six rungs)"
else
  bad "B-test TestPinMonitorsHonestReadsLadder fails or did not build"
fi

echo "== §C  where the rung's truth comes from =="

H=$(fnbody "$M" "rtMonitorsRenewalFailingSites")
HL=$(wc -l <<< "$H")
if [ "$HL" -ge 15 ]; then
  ok "C-control rtMonitorsRenewalFailingSites body is $HL lines"
else
  bad "C-control rtMonitorsRenewalFailingSites body is $HL lines — subject lost"
fi

# POSITIVE: the key set is DERIVED from the shared list through the shared
# predicate. This is the arm that matters — a re-listed literal set here would
# be a second classification of the same six keys, free to drift from the one in
# svc_notifications.go the moment a key is added.
if grep -qF 'range NotificationsSslRenewalKeyAll' <<< "$H" && grep -qF 'NotificationsRenewalSuccessClears(' <<< "$H"; then
  ok "C1 the keys are filtered from the shared list by the shared predicate"
else
  bad "C1 the keys are filtered from the shared list by the shared predicate"
fi

# REFUSAL + BOUNDARY: the three standing conditions are never named in this
# file. `DECLINED` is somebody else's certificate, `MAIL_HOST_CONFLICT` is a
# renewal deliberately refused, `DNS01_DOWNGRADED` is one that succeeded with
# fewer names — rendering any of them as a failure reports one the panel did not
# have. Naming any key here at all is the drift C1 exists to prevent.
STANDING=""
for k in 'SslRenewalKeyDeclined' 'SslRenewalKeyMailHostConflict' 'SslRenewalKeyDns01Downgraded' '"declined"' '"dns01_downgraded"' '"mail_host_conflict"'; do
  grep -qF "$k" <<< "$M" && STANDING="$STANDING $k"
done
if [ -z "$STANDING" ]; then
  ok "C2 rt_monitors.go re-lists no renewal key of its own"
else
  bad "C2 rt_monitors.go names renewal keys directly:$STANDING"
fi

# CONTROL for C2: the shared list really does carry those keys, so C2 is an
# assertion about THIS file rather than about a vocabulary that no longer exists.
K_ALL=$(grep -cE 'SslRenewalKey(Declined|MailHostConflict|Dns01Downgraded)\b' <<< "$N")
if [ "$K_ALL" -ge 3 ]; then
  ok "C2-control svc_notifications.go carries the standing keys on $K_ALL lines"
else
  bad "C2-control svc_notifications.go carries the standing keys on $K_ALL lines"
fi

# POSITIVE: firing rows only, and by site. `ResolveAlert` clears only firing
# rows, so an acknowledged alert is never resolved by a later success — reading
# it here would pin the rung on permanently for anyone who acknowledged before
# fixing the cause.
if grep -qF "status = 'firing'" <<< "$H"; then
  ok "C3 the lookup reads firing rows only"
else
  bad "C3 the lookup reads firing rows only"
fi
if grep -qF 'site_id = ANY($1)' <<< "$H"; then
  ok "C4 the lookup is scoped by the site ids it was given"
else
  bad "C4 the lookup is scoped by the site ids it was given"
fi

# POSITIVE: the helper's failure is reported like every other read in §A. A
# lookup that answers "not failing" when it could not read is the same defect
# this whole ship is about, one layer in.
if grep -qF 'internalError("renewal failure lookup"' <<< "$H"; then
  ok "C5 a failed lookup is reported, not read as \"not failing\""
else
  bad "C5 a failed lookup is reported, not read as \"not failing\""
fi

# ⛔ C6 IS THE ARM THAT SURVIVES THE MUTATION THE REST OF §C SURVIVES. C1-C5 are
# every one of them still true when this lookup returns an empty set on every
# path — keys still filtered, rows still firing-scoped, failure still reported —
# while the rung becomes unreachable for every certificate in the product.
# Asserted on the body's TAIL: the loop that fills `out` from the query's rows
# must be immediately followed by the final `return out, nil`, so returning an
# empty (or freshly reset) set goes red however carefully the query above it
# is preserved.
H_LAST=$(grep -v '^[[:space:]]*$' <<< "$H" | tail -1)
if perl -0777 -ne 'exit(/for _, (\w+) := range rows \{\s*out\[\1\] = true\s*\}\s*return out, nil\s*\z/ ? 0 : 1)' <<< "$H"; then
  ok "C6 the returned set is built from the rows the query read — \"$(sed 's/^[[:space:]]*//' <<< "$H_LAST")\""
else
  bad "C6 the returned set is built from the rows the query read — got \"$(sed 's/^[[:space:]]*//' <<< "$H_LAST")\""
fi

echo "== §D  every ladder call site passes the second axis =="

# `calls` prints the ARGUMENT LIST of each occurrence, one per line — and the
# DECLARATION is an occurrence too. Its parameter list is the one carrying the
# type annotation, so that is what separates it from the three real call sites.
# ⚠ The first cut of this section matched on the function NAME and asserted a
# count of 3; it reported 4 and made D1 and D3 match nothing at all — two
# vacuous arms hiding behind a control whose number said so.
SITES=$(calls "$M" "rtMonitorsExpiryStatus" | grep -vF '*int64')
N_SITES=$(grep -c . <<< "$SITES")
# ⛔ READ THIS NUMBER. Five call sites: the per-caller list's own sites, the
# admin list's sites, the host-scan half, the OFFLINE half (since v2.162.0,
# lists a stack's certificate from `docker_stacks.ssl_expiry` when the agent
# cannot be asked at all), and — since s413 — the per-caller list's own
# Docker Compose stacks. A count that drifts means a caller was added or
# lost, and every arm below would still be describing only the ones it can see.
if [ "$N_SITES" -eq 5 ]; then
  ok "D-control the ladder has $N_SITES call sites"
else
  bad "D-control the ladder has $N_SITES call sites — expected 5"
fi

# REFUSAL: no call site takes the clock alone. The compiler already refuses a
# one-argument call, so this arm's real job is to stay honest about the SHAPE
# the other §D arms match against — it goes red if `calls` ever stops resolving
# argument lists and starts printing something else.
ONE_ARG=$(grep -cx '(days)' <<< "$SITES")
if [ "$ONE_ARG" -eq 0 ]; then
  ok "D1 no call site passes the clock alone"
else
  bad "D1 $ONE_ARG call site(s) pass the clock alone"
fi

# POSITIVE: two of the five consult the SITE lookup (`failing`), by site id.
N_LOOKUP=$(grep -cx '(days, failing\[c\.A\])' <<< "$SITES")
if [ "$N_LOOKUP" -eq 2 ]; then
  ok "D2 both site-backed lists consult the lookup ($N_LOOKUP sites)"
else
  bad "D2 both site-backed lists consult the lookup — found $N_LOOKUP"
fi

# POSITIVE: three of the five are stack-facing — none backed by a `sites` row.
# The host-scan and offline halves used to pass a literal `false` here,
# unconditionally, for every stack on every host: `ssl_renewal_failure` alerts
# for a stack carry `site_id = NULL` (there is no sites row to name), the
# panel's per-site lookup filters `site_id = ANY(...)`, and NULL can never
# satisfy that, so the rung was unreachable for a stack no matter how long its
# renewal had been failing (s411's register, closed s412). They now consult
# their own lookup — `failing_stacks`, queried by server + the same
# `stack_renewal_state_key` `security_scanner::renew_stack_certificate` fires
# the alert under. The per-caller list's own stacks (s413) reuse the identical
# call shape, scoped by USER instead of server (`renewal_failing_stacks_for_user`
# — this endpoint has no server scope of its own) — same lookup pattern, same
# key function, so the same substring still matches all three. This arm
# asserts the SUBSTRING rather than `grep -cx` on the whole call: an exact
# match on a long, wrapped call is a hostage to how gofmt happens to break
# it, and `calls()` already normalises internal whitespace to prove that
# fragility isn't needed to tell a real lookup from a bare `false`.
N_STACK_LOOKUP=$(grep -c 'failingStacks\[SecurityScannerStackRenewalStateKey(' <<< "$SITES")
N_FALSE=$(grep -cx '(days, false)' <<< "$SITES")
if [ "$N_STACK_LOOKUP" -eq 3 ] && [ "$N_FALSE" -eq 0 ]; then
  ok "D3 all three stack-facing lists consult a real lookup — none still hardcodes false ($N_STACK_LOOKUP sites)"
else
  bad "D3 all three stack-facing lists consult a real lookup, none hardcoded — lookup=$N_STACK_LOOKUP false=$N_FALSE"
fi
# The offline half's OWN arm. `stale` is the one thing that row carries and no
# other row does, and it is the honest half of the bargain: a row assembled from
# the panel's stored date must never be mistaken for a live read of the box.
if [ "$(grep -cE '"stale": +true,' <<< "$M")" -eq 1 ]; then
  ok "D3b the offline half marks its rows as the panel's record, not a live read"
else
  bad "D3b the offline half does not mark its rows stale — an operator cannot tell a stored date from a fresh one"
fi

# POSITIVE: the two site-backed lists actually CALL the lookup, so D2's value
# came from the query rather than from a literal. One declaration plus two
# calls; the declaration is again the occurrence carrying the type annotation.
LOOKUPS=$(calls "$M" "rtMonitorsRenewalFailingSites" | grep -vF '[]uuid.UUID')
N_CALLS=$(grep -c . <<< "$LOOKUPS")
if [ "$N_CALLS" -eq 2 ]; then
  ok "D4 both lists call the lookup ($N_CALLS call sites)"
else
  bad "D4 both lists call the lookup — found $N_CALLS"
fi

# POSITIVE, same shape as D4 for the s413 user-scoped stack sibling: one
# declaration plus exactly one real call (`certificate_dashboard` is its only
# caller — `certificate_dashboard_for_admin` has its own inline, server-scoped
# lookup instead, by design, since it has a server to scope by and this
# function does not).
STACK_LOOKUPS=$(calls "$M" "rtMonitorsRenewalFailingStacksForUser" | grep -vF '[]string')
N_STACK_CALLS=$(grep -c . <<< "$STACK_LOOKUPS")
if [ "$N_STACK_CALLS" -eq 1 ]; then
  ok "D5 the user-scoped stack lookup is declared once and called once ($N_STACK_CALLS call site)"
else
  bad "D5 the user-scoped stack lookup is declared once and called once — found $N_STACK_CALLS"
fi

echo "== §E  the page shows the rung, and stops calling a failure an emptiness =="

E_LINES=$(wc -l <<< "$C")
if [ "$E_LINES" -ge 150 ]; then
  ok "E-control Certificates.tsx stripped subject is $E_LINES lines"
else
  bad "E-control Certificates.tsx stripped subject is only $E_LINES lines — subject lost"
fi

# POSITIVE: the rung has a badge. Without this entry the status falls through
# the map's default and renders as "Unknown" — the page would receive the answer
# and decline to show it.
if grep -qE 'renewal_failed: \{.*label: "Renewal failed"' <<< "$C"; then
  ok "E1 the page renders a Renewal failed badge"
else
  bad "E1 the page renders a Renewal failed badge"
fi

# POSITIVE: the count line asks about the error FIRST. On failure the list is
# still empty, so this line used to answer "No SSL certificates found" — the
# page's most reassuring sentence — beside the banner saying the read had failed.
if grep -qF 'Certificate list unavailable' <<< "$C"; then
  ok "E2 a failed read is reported as unavailable, not as zero certificates"
else
  bad "E2 a failed read is reported as unavailable, not as zero certificates"
fi

E_UNAVAIL=$(grep -n 'Certificate list unavailable' <<< "$C" | head -1 | cut -d: -f1)
E_NONE=$(grep -n 'No SSL certificates found' <<< "$C" | head -1 | cut -d: -f1)
if [ -n "$E_UNAVAIL" ] && [ -n "$E_NONE" ] && [ "$E_UNAVAIL" -lt "$E_NONE" ]; then
  ok "E3 the failure branch is decided before the empty one (line $E_UNAVAIL before $E_NONE)"
else
  bad "E3 the failure branch is decided before the empty one"
fi

# POSITIVE: a later success retracts the failure. Without this the banner and
# E2's line both outlive the request they describe, and toggling the admin
# checkbox is the ordinary way to reach that state.
R=$(perl -0777 -ne 'print $1 if /\.then\(\(data\)\s*=>\s*\{(.*?)\}\)/s' <<< "$C")
if grep -qF 'setError("")' <<< "$R"; then
  ok "E4 a successful reload clears the previous failure"
else
  bad "E4 a successful reload clears the previous failure"
fi

echo
printf 'PASS %d  FAIL %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
