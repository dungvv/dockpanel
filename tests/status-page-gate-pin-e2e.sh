#!/usr/bin/env bash
# status-page-gate-pin-e2e.sh — s313 / v2.70.0
#
# Pins the fix for a panel that published its own alert engine's output to the
# internet from first boot, with no operator action, while the documented switch
# governed a different endpoint and the guide promised a 404.
#
#   §A  the GATE exists and FAILS CLOSED. Absent setting, unreadable setting,
#       any value that is not the literal "true" — all off. A decision to
#       publish operational state is never made by a default.
#   §B  EVERY route on the public /api/status-page surface reaches it. This is
#       the arm that matters, and it is the arm the old code would have failed:
#       four routes answered unauthenticated and exactly one checked anything.
#       The subject list is COMPUTED from the router, never written here — a
#       class arm that hardcodes its own members cannot see the fifth route
#       somebody adds next year (lesson #181).
#   §C  the public config read is DETERMINISTIC. An unordered LIMIT 1 over a
#       table that could hold duplicates let two readers of one flag disagree,
#       so an operator could untick "Enabled", get a 200, and still publish.
#   §D  one config row per operator — a real ON CONFLICT target, and the unique
#       index that makes it mean anything.
#
# Pure source analysis: no box, no network, no build.
#
# ⚠ §A2 and §B are ABSENCE arms over a subject that DID NOT EXIST at v2.69.0, so
# "red at the previous tag" cannot test them (lesson #222) — there was no gate to
# fail to call. Both were MUTATION-TESTED at HEAD instead: deleting the
# require_enabled call from incidents::subscribe turns §B red and names the
# handler; flipping the gate's unwrap_or(false) to (true) turns §A2 red.
#
# Ported to Go (panel/go/internal/api): the gate is svc_public_status.go
# (PublicStatusIsEnabled / PublicStatusRequireEnabled), the routes are
# rt_monitors.go / rt_incidents.go, and the router is each file's own
# rt*Register — `r.Handle("METHOD /api/status-page...", h(rtX))`. Auth in Go
# is a call in the body (st.authUser / st.adminUser), not an extractor in the
# signature.
#
# NO PIPES INTO `grep -q` — under `set -o pipefail` grep -q closes the pipe on
# its first match and the arm goes red on correct code, non-deterministically.
# Every arm feeds grep a here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

API=panel/go/internal/api
GATE=$API/svc_public_status.go
INC=$API/rt_incidents.go
MON=$API/rt_monitors.go

for f in "$GATE" "$INC" "$MON"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT. Copied from the FIXED stripper (lesson #136): the
# naive s{/\*.*?\*/}{}gs deletes real code, because `/*` occurs inside string
# literals, and a truncated subject makes an ABSENCE arm pass on code the
# stripper merely removed — failure in the reassuring direction.
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
# (gofmt guarantees it). A fixed `grep -A n` window is not a function
# (lesson #131/#172).
fnbody() {
  awk -v name="$2" '
    /^func / {
      if (index($0, "func " name "(") == 1 || $0 ~ ("^func \\([^)]*\\) " name "\\(")) { inside=1; next }
    }
    inside && /^}/ { inside=0 }
    inside { print }
  ' <<< "$1"
}

# The DECLARATION line of one top-level Go func (gofmt keeps it on one line).
fnsig() {
  awk -v name="$2" '
    /^func / && (index($0, "func " name "(") == 1 || $0 ~ ("^func \\([^)]*\\) " name "\\(")) { print }
  ' <<< "$1"
}

echo "== §A  the gate exists, and it fails closed =="

if [ ! -f "$GATE" ]; then
  bad "A1 svc_public_status.go exists (the one place the publish decision is made)"
  bad "A2 the gate fails closed — absent or unreadable setting is OFF"
elif G=$(subj "$GATE"); then
  if grep -qE '^func PublicStatusRequireEnabled\(' <<< "$G" \
  && grep -qE '^func PublicStatusIsEnabled\(' <<< "$G"; then
    ok "A1 svc_public_status.go exposes PublicStatusIsEnabled + PublicStatusRequireEnabled"
  else
    bad "A1 svc_public_status.go exposes PublicStatusIsEnabled + PublicStatusRequireEnabled"
  fi

  # Both halves must be present: the query's error path collapses to nil, and
  # the decision reads nil as false. Either one defaulting the other way
  # republishes the page. (The decision's value table is also unit-tested:
  # TestPublicStatus* in svc_public_status_test.go.)
  ISEN=$(fnbody "$G" PublicStatusIsEnabled)
  MEANS=$(fnbody "$G" publicStatusMeansEnabled)
  if perl -0777 -ne 'exit(/if err != nil \{\s*v = nil\s*\}\s*return publicStatusMeansEnabled\(v\)/ ? 0 : 1)' <<< "$ISEN" \
  && grep -qE 'return value != nil && \*value == "true"$' <<< "$MEANS" \
  && ! grep -qE 'return true' <<< "$ISEN$MEANS"; then
    ok "A2 the gate fails closed — query error and absent row both read OFF"
  else
    bad "A2 the gate fails closed — query error and absent row both read OFF"
  fi
fi
# A3 retired (obsolete in Go): services/mod.rs registration has no Go meaning — package api is flat and an unresolved PublicStatus* call does not compile

echo "== §B  every public status-page route reaches the gate =="

# Subject list COMPUTED from the router. Never written here.
ROUTES=$(grep -hoE 'r\.Handle\("[A-Z]+ /api/status-page[^"]*", *h\(rt[A-Za-z]+\)\)' "$API"/rt_*.go || true)
HANDLERS=$(grep -oE 'h\(rt[A-Za-z]+\)' <<< "$ROUTES" | sed -E 's/^h\((.*)\)$/\1/' | sort -u || true)
NHANDLERS=$(grep -c . <<< "$HANDLERS" || true)

# An arm that enumerates its own subjects must assert the enumeration FIRST
# (lesson #143) — an empty list makes every check below pass having examined
# nothing. Four public + six admin handlers exist today; anything under 6 means
# the extraction broke, not that the surface shrank.
if [ "$NHANDLERS" -lt 6 ]; then
  bad "B0 router enumeration produced $NHANDLERS status-page handlers — extraction is broken, arms below are vacuous"
else
  ok "B0 router enumeration found $NHANDLERS status-page handlers"

  UNGUARDED=""
  for h in $HANDLERS; do
    src=$(grep -lE "^func $h\(" "$API"/rt_*.go | grep -v '_test\.go$' | head -1)
    [ -n "$src" ] || { UNGUARDED="$UNGUARDED $h(no-file)"; continue; }
    S=$(subj "$src") || { UNGUARDED="$UNGUARDED $h(unreadable)"; continue; }

    SIG=$(fnsig "$S" "$h")
    BODY=$(fnbody "$S" "$h")
    [ -n "$SIG" ] || { UNGUARDED="$UNGUARDED $h(no-fn)"; continue; }

    # Authenticated is fine — the gate is for the routes that answer to anybody.
    # In Go that is the body's FIRST statement: `x, err := st.adminUser(r)`.
    FIRST=$(grep -vE '^[[:space:]]*$' <<< "$BODY" | head -1)
    if grep -qE 'st\.(adminUser|authUser)\(r\)' <<< "$FIRST"; then continue; fi
    if grep -qE 'PublicStatusRequireEnabled\(' <<< "$BODY"; then continue; fi
    UNGUARDED="$UNGUARDED $h"
  done

  if [ -z "$UNGUARDED" ]; then
    ok "B1 every unauthenticated /api/status-page route calls PublicStatusRequireEnabled"
  else
    bad "B1 status-page routes that are neither authenticated nor gated:$UNGUARDED"
  fi
fi

# Named arms for the three that were open, so a regression says WHICH one.
if S=$(subj "$INC"); then
  for fn in rtIncidentsPublicStatusPage rtIncidentsSubscribe rtIncidentsUnsubscribe; do
    B=$(fnbody "$S" "$fn")
    if [ -n "$B" ] && grep -qE 'PublicStatusRequireEnabled\(' <<< "$B"; then
      ok "B2 $fn is gated"
    else
      bad "B2 $fn is gated"
    fi
  done
fi

if S=$(subj "$MON"); then
  B=$(fnbody "$S" rtMonitorsStatusPage)
  # The documented endpoint always failed closed, but on its own inline copy of
  # the check. Two copies of one decision is how the surface drifted apart in the
  # first place, so it must read the shared gate now.
  if [ -n "$B" ] && grep -qE 'PublicStatusRequireEnabled\(' <<< "$B" \
     && ! grep -qE "status_page_enabled" <<< "$B"; then
    ok "B3 rtMonitorsStatusPage reads the shared gate, not its own copy"
  else
    bad "B3 rtMonitorsStatusPage reads the shared gate, not its own copy"
  fi
fi

echo "== §C  the public read is deterministic =="

if S=$(subj "$INC"); then
  B=$(fnbody "$S" rtIncidentsPublicStatusPage)
  if [ -n "$B" ] && grep -qE 'FROM status_page_config ORDER BY' <<< "$B"; then
    ok "C1 the public config read is ordered"
  else
    bad "C1 the public config read is ordered"
  fi
  # The specific shape that let two readers disagree.
  if [ -n "$B" ] && ! grep -qE 'FROM status_page_config LIMIT 1' <<< "$B"; then
    ok "C2 no unordered LIMIT 1 over status_page_config"
  else
    bad "C2 no unordered LIMIT 1 over status_page_config"
  fi
fi

echo "== §D  one config row per operator =="

if S=$(subj "$INC"); then
  B=$(fnbody "$S" rtIncidentsUpdateConfig)
  if [ -n "$B" ] && grep -qE 'INSERT INTO status_page_config \(user_id\) VALUES \(\$1\) ON CONFLICT \(user_id\) DO NOTHING' <<< "$B"; then
    ok "D1 rtIncidentsUpdateConfig names a real conflict target"
  else
    bad "D1 rtIncidentsUpdateConfig names a real conflict target"
  fi
  # A targetless clause on this table can only absorb a uuid PK collision, so it
  # reads as a guard and is inert.
  if [ -n "$B" ] && ! grep -qE 'INSERT INTO status_page_config[^"]*ON CONFLICT DO NOTHING' <<< "$B"; then
    ok "D2 no targetless ON CONFLICT on status_page_config"
  else
    bad "D2 no targetless ON CONFLICT on status_page_config"
  fi
fi

# Read each migration WHOLE, not line-wise: `CREATE UNIQUE INDEX ... ON
# status_page_config(user_id)` is written across two lines, and a line-based
# grep reported the migration missing when it was sitting right there. An arm
# that cannot see a correct migration would have sent the next reader looking
# for a bug in the wrong place.
MIGS=$(for m in $API/migrations/*.sql; do
  perl -0777 -ne 'exit(1) unless /CREATE\s+UNIQUE\s+INDEX[^;]*?status_page_config\s*\(user_id\)/si' "$m" \
    && printf '%s\n' "$m"
done)
if [ -n "$MIGS" ]; then
  ok "D3 a migration makes status_page_config.user_id unique"
  # The index is what makes D1 fire; a dedupe that runs after it would deadlock
  # on its own duplicates, so assert the migration removes them first.
  if grep -qE 'DELETE FROM status_page_config' $MIGS; then
    ok "D4 that migration dedupes before adding the constraint"
  else
    bad "D4 that migration dedupes before adding the constraint"
  fi
else
  bad "D3 a migration makes status_page_config.user_id unique"
  bad "D4 that migration dedupes before adding the constraint"
fi

echo "== §E  the guide no longer promises what the code did not do =="

GUIDE=docs/guides/status-page.md
if [ -f "$GUIDE" ]; then
  if grep -qE 'off by default' "$GUIDE" && grep -qE 'master switch' "$GUIDE"; then
    ok "E1 the guide states the switch is off by default and is the master"
  else
    bad "E1 the guide states the switch is off by default and is the master"
  fi
  # The guide told operators a disabled page 404s. It was false for 4.5 months,
  # and an operator who read it had no reason to check. Saying so is the fix.
  if grep -qE 'Upgrade note \(v2\.70\.0\)' "$GUIDE"; then
    ok "E2 the guide discloses that the promise was previously untrue"
  else
    bad "E2 the guide discloses that the promise was previously untrue"
  fi
else
  bad "E1 docs/guides/status-page.md exists"
  bad "E2 docs/guides/status-page.md exists"
fi

echo "== §F  the public surface does not republish what it must not ==="

# v2.149.0. Two leaks on the SAME unauthenticated response, both of them
# over-disclosure rather than a missing gate — the gate above was working.
#
#   §F1/F2/F3  a monitor's own URL. The HTTP client's error (Rust's
#              `reqwest::Error`, Go's `*url.Error`) prints the URL, and that string became `incidents.cause`,
#              `managed_incidents.description` and the "Auto-detected: …"
#              timeline entry — two of which this endpoint publishes, while
#              the guide states URLs are not published and the OTHER public
#              handler drops the URL deliberately.
#   §F4        `author_email`. The timeline was serialized whole, and the
#              struct carries the operator's address.
#
# F2 WAS the arm the Rust unit tests could not replace (they exercised
# `redact_monitor_target` directly). The Go port's
# TestUptimeAFailedCheckDoesNotRepublishTheMonitorURL calls
# uptimeDescribeCheckError on a real dial failure, whose cause chain names
# 127.0.0.1 even after the *url.Error is unwrapped — so deleting the scrub call
# turns that test red, and F2 retires to it.

UPT=$API/svc_uptime.go

if [ ! -f "$UPT" ]; then
  bad "F0 $UPT exists"
elif U=$(subj "$UPT"); then
  HTTPBODY=$(fnbody "$U" uptimeCheckHTTP)
  DESCBODY=$(fnbody "$U" uptimeDescribeCheckError)
  REDBODY=$(fnbody "$U" uptimeRedactMonitorTarget)

  # FLOOR the three function subjects. An fnbody whose pattern stops matching
  # yields an EMPTY subject, and every absence arm below it then passes green
  # for a file that no longer contains the code at all.
  if [ "${#HTTPBODY}" -ge 600 ] && [ "${#DESCBODY}" -ge 100 ] && [ "${#REDBODY}" -ge 200 ]; then
    ok "F0 function subjects resolved (uptimeCheckHTTP ${#HTTPBODY}c, uptimeDescribeCheckError ${#DESCBODY}c, uptimeRedactMonitorTarget ${#REDBODY}c)"

    # The failing arm of the check must not hand the client error's own text
    # straight to the caller — that string is what gets stored and published.
    if grep -qE 'uptimeDescribeCheckError\(err, m\.URL\)' <<< "$HTTPBODY" \
    && ! grep -qE 'uptimeStr\(err\.Error\(\)\)' <<< "$HTTPBODY"; then
      ok "F1 uptimeCheckHTTP renders its error through uptimeDescribeCheckError, not the client's raw text"
    else
      bad "F1 uptimeCheckHTTP renders its error through uptimeDescribeCheckError, not the client's raw text"
    fi

    # F2 retired: covered by TestUptimeAFailedCheckDoesNotRepublishTheMonitorURL (panel/go/internal/api/svc_uptime_test.go)

    # Go's equivalent of reqwest's without_url(): unwrap the *url.Error, whose
    # own Error() is `Get "<url>": ...`, down to its cause.
    if grep -qE 'var ue \*url\.Error' <<< "$DESCBODY" \
    && grep -qE 'errors\.As\(err, &ue\)' <<< "$DESCBODY" \
    && grep -qE 'err = ue\.Err' <<< "$DESCBODY"; then
      ok "F3 uptimeDescribeCheckError still strips the error's own URL slot"
    else
      bad "F3 uptimeDescribeCheckError still strips the error's own URL slot"
    fi
  else
    bad "F0 function subjects resolved — extraction is broken, F1/F3 would be vacuous"
    bad "F1 uptimeCheckHTTP renders its error through uptimeDescribeCheckError"
    bad "F3 uptimeDescribeCheckError still strips the error's own URL slot"
  fi
fi

if I=$(subj "$INC"); then
  PUBBODY=$(fnbody "$I" rtIncidentsPublicStatusPage)
  if [ "${#PUBBODY}" -ge 1500 ]; then
    # `rtIncidentsIncidentUpdate` is `SELECT *` over a table with an author_email
    # column, so serializing the slice whole publishes it. The projection names
    # its fields.
    if ! grep -qE '"updates": +updates\b' <<< "$PUBBODY" \
    && grep -qE '"updates": +pub\b' <<< "$PUBBODY" \
    && grep -qF 'pub = append(pub, map[string]any{"id": u.ID, "status": u.Status, "message": u.Message, "created_at": u.CreatedAt})' <<< "$PUBBODY"; then
      ok "F4 the public timeline is projected field by field, not serialized whole"
    else
      bad "F4 the public timeline is projected field by field, not serialized whole"
    fi

    if ! grep -qiE 'author_?email' <<< "$PUBBODY"; then
      ok "F5 author_email is named nowhere in the public handler"
    else
      bad "F5 author_email is named nowhere in the public handler"
    fi
  else
    bad "F4 rtIncidentsPublicStatusPage subject resolved (${#PUBBODY}c) — arms would be vacuous"
    bad "F5 rtIncidentsPublicStatusPage subject resolved"
  fi
fi

echo "== §G  the public read is scoped to ONE tenant (s418) =="

# v2.171.0. §A-§F all guarded WHETHER the page publishes and WHAT fields it
# publishes — none of them checked WHOSE data it publishes. Every query below
# `status_page_config`'s ORDER BY was unscoped: on any multi-tenant/reseller
# install, one tenant's components/incidents/legacy-incidents were served to
# every anonymous visitor of every OTHER tenant's /status page. Confirmed
# live-reachable on this box before the fix (10 real incident rows, 1 user).
#
# Each arm names the ONE query it pins, not a bag of substrings, so a
# regression says which query lost its scope.

if I=$(subj "$INC"); then
  PUBBODY=$(fnbody "$I" rtIncidentsPublicStatusPage)
  if [ "${#PUBBODY}" -ge 1500 ]; then
    if grep -qE 'SELECT user_id, title, description' <<< "$PUBBODY" \
    && grep -qE 'ownerID = &cfg\.UserID' <<< "$PUBBODY"; then
      ok "G1 the config read carries user_id forward as ownerID"
    else
      bad "G1 the config read carries user_id forward as ownerID"
    fi

    if grep -qE 'FROM status_page_components WHERE user_id = \$1' <<< "$PUBBODY"; then
      ok "G2 the components read is scoped to ownerID"
    else
      bad "G2 the components read is scoped to ownerID"
    fi

    if grep -qE 'WHERE cm\.component_id = \$1 AND m\.user_id = \$2 AND m\.enabled = TRUE' <<< "$PUBBODY"; then
      ok "G3 the per-component monitor-status read is ALSO scoped (defense in depth — the component is already owner-scoped, but a monitor linked cross-tenant into it must not leak status)"
    else
      bad "G3 the per-component monitor-status read is ALSO scoped"
    fi

    if grep -qE 'FROM managed_incidents WHERE user_id = \$1 AND visible_on_status_page = TRUE' <<< "$PUBBODY"; then
      ok "G4 the managed-incidents read is scoped to ownerID"
    else
      bad "G4 the managed-incidents read is scoped to ownerID"
    fi

    if grep -qE 'FROM incidents i JOIN monitors m ON m\.id = i\.monitor_id "' <<< "$PUBBODY" \
    && grep -qE 'WHERE m\.user_id = \$1 AND i\.started_at > NOW\(\)' <<< "$PUBBODY"; then
      ok "G5 the legacy auto-detected-incidents read is scoped to ownerID"
    else
      bad "G5 the legacy auto-detected-incidents read is scoped to ownerID"
    fi

    # The negative control: NONE of the three data queries may be reachable
    # with no ownerID in hand. Each must sit directly inside an
    # `if ownerID != nil {` — no brace between the guard and the query — which
    # is what makes G2-G5 real gates rather than filters bolted on after an
    # unscoped fetch already ran.
    G6MISS=""
    for q in 'FROM status_page_components WHERE' 'FROM managed_incidents WHERE' 'FROM incidents i JOIN monitors m'; do
      Q="$q" perl -0777 -ne 'exit(/if ownerID != nil \{[^{}]*\Q$ENV{Q}\E/ ? 0 : 1)' <<< "$PUBBODY" || G6MISS="$G6MISS [$q]"
    done
    if [ -z "$G6MISS" ]; then
      ok "G6 the components/incidents queries are structurally UNREACHABLE without an ownerID, not merely filtered"
    else
      bad "G6 queries reachable without an ownerID:$G6MISS"
    fi
  else
    bad "G1 rtIncidentsPublicStatusPage subject resolved (${#PUBBODY}c) — G1-G6 would be vacuous"
    bad "G2 components read scoped"; bad "G3 monitor-status read scoped"
    bad "G4 managed-incidents read scoped"; bad "G5 legacy-incidents read scoped"
    bad "G6 queries structurally gated on owner_id"
  fi
fi

echo "== §H  the subscriber list and its fan-out are ALSO scoped (s427) =="

# v2.180.0. §G scoped every READ of the public page to one tenant. The
# subscriber table (and the worker that mails it) was the one piece of this
# surface §G never touched — s418's own fan-out found it, deferred it, and it
# sat as a documented, zero-owner-column carry until now. Same failure shape as
# §G: a real address list, readable/mailable across every tenant on the
# install, not just the one whose page a visitor actually subscribed through.

NOTICES=$API/svc_status_notices.go
UPT=$API/svc_uptime.go

if G=$(subj "$GATE"); then
  if grep -qE '^func PublicStatusResolveCurrentStatusPageOwner\(' <<< "$G"; then
    ok "H1 svc_public_status.go exposes PublicStatusResolveCurrentStatusPageOwner"
  else
    bad "H1 svc_public_status.go exposes PublicStatusResolveCurrentStatusPageOwner"
  fi

  # The fallback that makes this reachable even before an admin has ever
  # visited status-page settings — see PublicStatusResolveCurrentStatusPageOwner's own
  # doc comment for why `status_page_enabled` can be true with zero config rows.
  RCSPO=$(fnbody "$G" PublicStatusResolveCurrentStatusPageOwner)
  if [ "${#RCSPO}" -ge 200 ] && grep -qE 'FROM users ORDER BY created_at ASC' <<< "$RCSPO"; then
    ok "H2 the owner resolver falls back to the install's first user when no config row exists"
  else
    bad "H2 the owner resolver falls back to the install's first user when no config row exists"
  fi
fi

if I=$(subj "$INC"); then
  SUBBODY=$(fnbody "$I" rtIncidentsSubscribe)
  UNSUBBODY=$(fnbody "$I" rtIncidentsUnsubscribe)
  LISTBODY=$(fnbody "$I" rtIncidentsListSubscribers)

  if [ "${#SUBBODY}" -ge 300 ] && [ "${#UNSUBBODY}" -ge 100 ] && [ "${#LISTBODY}" -ge 100 ]; then
    ok "H3 function subjects resolved (subscribe ${#SUBBODY}c, unsubscribe ${#UNSUBBODY}c, list_subscribers ${#LISTBODY}c)"

    if grep -qE 'PublicStatusResolveCurrentStatusPageOwner\(' <<< "$SUBBODY" \
    && grep -qE 'INSERT INTO status_page_subscribers \(owner_id, email' <<< "$SUBBODY"; then
      ok "H4 subscribe resolves and stamps an owner_id on the new row"
    else
      bad "H4 subscribe resolves and stamps an owner_id on the new row"
    fi

    if grep -qE 'PublicStatusResolveCurrentStatusPageOwner\(' <<< "$UNSUBBODY" \
    && grep -qE 'WHERE email = \$1 AND owner_id IS NOT DISTINCT FROM \$2' <<< "$UNSUBBODY"; then
      ok "H5 unsubscribe only removes the row for the page the visitor is looking at"
    else
      bad "H5 unsubscribe only removes the row for the page the visitor is looking at"
    fi

    # The negative control: list_subscribers must not be install-wide. Before
    # s427 this endpoint had no WHERE clause at all — any admin's JWT could
    # read every OTHER tenant's subscriber email list.
    if grep -qE 'WHERE owner_id = \$1' <<< "$LISTBODY" \
    && grep -qE 'WHERE owner_id = \$1 [^"]*", claims\.Sub\)' <<< "$LISTBODY"; then
      ok "H6 list_subscribers is scoped to the calling admin's own owner_id"
    else
      bad "H6 list_subscribers is scoped to the calling admin's own owner_id"
    fi
  else
    bad "H3 subscribe/unsubscribe/list_subscribers subjects resolved — H4-H6 would be vacuous"
    bad "H4 subscribe stamps owner_id"; bad "H5 unsubscribe scoped"; bad "H6 list_subscribers scoped"
  fi
fi

echo "== §I  the notify fan-out cannot reach a subscriber of a DIFFERENT tenant (s427) =="

if [ ! -f "$NOTICES" ]; then
  bad "I1 $NOTICES exists"
  bad "I2 enqueue requires an owner_id"
  bad "I3 the worker's subscriber SELECT is scoped to owner_id"
else
  N=$(subj "$NOTICES")
  if perl -0777 -ne 'exit(/^type StatusNoticesStatusNotice struct \{[^}]*\n\s*OwnerID +uuid\.UUID\n/m ? 0 : 1)' <<< "$N"; then
    ok "I1 StatusNotice carries an owner_id field"
  else
    bad "I1 StatusNotice carries an owner_id field"
  fi

  ENQSIG=$(fnsig "$N" StatusNoticesEnqueue)
  if grep -qE 'ownerID uuid\.UUID\)' <<< "$ENQSIG"; then
    ok "I2 enqueue() requires an owner_id — a call site missing it cannot compile"
  else
    bad "I2 enqueue() requires an owner_id — a call site missing it cannot compile"
  fi

  # The one query that actually enforces isolation between two tenants' mail.
  # H4-H6 prove the DATA is tagged; this proves the FAN-OUT respects the tag.
  if grep -qE 'WHERE owner_id = \$1 AND verified = TRUE AND notify_incidents = TRUE' <<< "$N" \
  && grep -qE '^[[:space:]]*notice\.OwnerID, statusNoticesMaxSubscriberFanout\)' <<< "$N"; then
    ok "I3 the worker's subscriber SELECT is scoped to the notice's own owner_id"
  else
    bad "I3 the worker's subscriber SELECT is scoped to the notice's own owner_id"
  fi
fi

# Every real producer must pass its OWN tenant's id, never a borrowed one.
# Named per call site so a regression says which producer stopped scoping.
if U=$(subj "$UPT"); then
  DOWNCALLS=$(grep -c 'uptimeNotifyStatusSubscribers(m\.Name, "investigating"' <<< "$U" || true)
  UPCALLS=$(grep -c 'uptimeNotifyStatusSubscribers(m\.Name, "resolved"' <<< "$U" || true)
  if grep -qE 'uptimeNotifyStatusSubscribers\(m\.Name, "investigating".*, m\.UserID\)$' <<< "$U" \
  && [ "${DOWNCALLS:-0}" -eq 1 ]; then
    ok "I4 the down-transition call passes the monitor's own user_id"
  else
    bad "I4 the down-transition call passes the monitor's own user_id"
  fi
  if grep -qE 'uptimeNotifyStatusSubscribers\(m\.Name, "resolved".*, m\.UserID\)$' <<< "$U" \
  && [ "${UPCALLS:-0}" -eq 1 ]; then
    ok "I4b the recovery call passes the monitor's own user_id"
  else
    bad "I4b the recovery call passes the monitor's own user_id"
  fi
  if grep -qE 'ownerID uuid\.UUID\)' <<< "$(fnsig "$U" uptimeNotifyStatusSubscribers)"; then
    ok "I5 uptimeNotifyStatusSubscribers requires an owner_id"
  else
    bad "I5 uptimeNotifyStatusSubscribers requires an owner_id"
  fi
fi

if I=$(subj "$INC"); then
  # Named per call site rather than one loose substring match: a `grep -q`
  # over the whole file passes the instant ANY ONE of the three happens to
  # match, so a regression in two of three sites would read as healthy.
  CALLSITES=$(grep -E 'rtIncidentsNotifySubscribers\(' <<< "$I" | grep -vE '^func rtIncidentsNotifySubscribers\(')
  NCALLS=$(grep -c . <<< "$CALLSITES" 2>/dev/null || echo 0)
  if [ "$NCALLS" -eq 3 ]; then
    ok "I6 exactly 3 rtIncidentsNotifySubscribers call sites found (a 4th needs its own arm here)"
  else
    bad "I6 expected 3 rtIncidentsNotifySubscribers call sites, found $NCALLS — I7-I9 would be vacuous or miscounted"
  fi

  if grep -qE 'rtIncidentsNotifySubscribers\(incident\.Title, status, rtIncidentsStrOr\(req\.Description, ""\), incident\.UserID\)$' <<< "$(fnbody "$I" rtIncidentsCreate)"; then
    ok "I7 create_incident passes the just-inserted incident's own user_id"
  else
    bad "I7 create_incident passes the just-inserted incident's own user_id"
  fi

  if grep -qE 'rtIncidentsNotifySubscribers\(incident\.Title, updateStatus, \*req\.Message, incident\.UserID\)$' <<< "$(fnbody "$I" rtIncidentsUpdate)"; then
    ok "I8 the PUT update path passes the already-fetched incident's own user_id"
  else
    bad "I8 the PUT update path passes the already-fetched incident's own user_id"
  fi

  PU=$(fnbody "$I" rtIncidentsPostUpdate)
  if grep -qE 'owner, err := queryOpt\[Tup2\[string, uuid\.UUID\]\]\(ctx, st\.DB, "SELECT title, user_id FROM managed_incidents WHERE id = \$1", id\)' <<< "$PU" \
  && grep -qE 'rtIncidentsNotifySubscribers\(owner\.A, req\.Status, req\.Message, owner\.B\)$' <<< "$PU"; then
    ok "I9 the POST update path fetches THIS incident's own owner before enqueuing, then passes it"
  else
    bad "I9 the POST update path fetches THIS incident's own owner before enqueuing, then passes it"
  fi
fi

echo "== §J  the schema backs the scoping, not just the query strings =="

SUBMIG=$(for m in $API/migrations/*.sql; do
  grep -qE 'ALTER TABLE status_page_subscribers' "$m" && grep -qE 'ADD COLUMN IF NOT EXISTS owner_id' "$m" \
    && printf '%s\n' "$m"
done)
if [ -n "$SUBMIG" ]; then
  ok "J1 a migration adds status_page_subscribers.owner_id"
  if grep -qE 'UNIQUE \(owner_id, email\)' $SUBMIG; then
    ok "J2 that migration replaces the global email-only uniqueness with (owner_id, email)"
  else
    bad "J2 that migration replaces the global email-only uniqueness with (owner_id, email)"
  fi
  # The negative control for J2: the OLD single-column constraint must actually
  # be dropped, not just shadowed by a new one sitting alongside it.
  if grep -qE 'DROP CONSTRAINT IF EXISTS status_page_subscribers_email_key' $SUBMIG; then
    ok "J3 the old install-wide UNIQUE(email) constraint is dropped"
  else
    bad "J3 the old install-wide UNIQUE(email) constraint is dropped"
  fi
else
  bad "J1 a migration adds status_page_subscribers.owner_id"
  bad "J2 replaces global uniqueness with (owner_id, email)"
  bad "J3 drops the old UNIQUE(email) constraint"
fi

echo "== §K  rt_monitors.go's OWN public status-page route is ALSO scoped (s430) =="

# v2.185.0. §G scoped incidents.rs::public_status_page's four queries at
# v2.171.0 (s418) — but a SIBLING public, unauthenticated status-page route
# lives in monitors.rs, created FROM SCRATCH two releases later (v2.173.0),
# with the identical unscoped shape §G had just fixed one file over:
# `SELECT ... FROM monitors WHERE enabled = true` with no owner filter,
# behind a comment reading "no user filter — this is public." No frontend
# caller ever reaches it, which is exactly why it went unnoticed while its
# twin got fixed and pinned. Same failure shape as §G, same remedy: resolve
# the status page's owner and require it before the query can run at all.

if S=$(subj "$MON"); then
  SPBODY=$(fnbody "$S" rtMonitorsStatusPage)
  if [ "${#SPBODY}" -ge 200 ]; then
    if grep -qE 'ownerID := PublicStatusResolveCurrentStatusPageOwner\(ctx, st\.DB\)' <<< "$SPBODY"; then
      ok "K1 rtMonitorsStatusPage resolves the same owner the rt_incidents.go sibling uses"
    else
      bad "K1 rtMonitorsStatusPage resolves ownerID via PublicStatusResolveCurrentStatusPageOwner"
    fi

    if grep -qE 'FROM monitors WHERE enabled = true AND user_id = \$1' <<< "$SPBODY"; then
      ok "K2 the monitors read is scoped to owner_id, not a flat enabled-only filter"
    else
      bad "K2 the monitors read is scoped to owner_id"
    fi

    # Negative control matching §G6: the query must be structurally
    # unreachable with no owner_id in hand, not merely filtered after an
    # unscoped fetch already ran.
    if perl -0777 -ne 'exit(/if ownerID != nil \{[^{}]*FROM monitors WHERE enabled = true AND user_id = \$1/ ? 0 : 1)' <<< "$SPBODY" \
    && grep -qE '^[[:space:]]*var monitors \[\]row$' <<< "$SPBODY"; then
      ok "K3 the monitors query is structurally UNREACHABLE without an owner_id"
    else
      bad "K3 the monitors query is structurally gated on owner_id"
    fi

    # Regression control: the OLD unscoped query text must be gone, not just
    # supplemented by a new scoped one sitting alongside it.
    if ! grep -qE 'FROM monitors WHERE enabled = true ORDER BY' "$MON"; then
      ok "K4 the old unscoped query string is gone, not left as a second live path"
    else
      bad "K4 the old unscoped query string is gone"
    fi
  else
    bad "K1 rtMonitorsStatusPage subject resolved (${#SPBODY}c) — K1-K4 would be vacuous"
    bad "K2 monitors read scoped"; bad "K3 query structurally gated"; bad "K4 old query removed"
  fi
else
  bad "K1 rt_monitors.go resolved as a subject"; bad "K2 monitors read scoped"
  bad "K3 query structurally gated"; bad "K4 old query removed"
fi

echo
printf 'status-page-gate: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
