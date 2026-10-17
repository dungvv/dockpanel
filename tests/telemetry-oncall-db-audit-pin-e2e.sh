#!/usr/bin/env bash
# telemetry-oncall-db-audit-pin-e2e.sh — s464
#
# dockpanel-fanout on the telemetry routes + telemetry collector — now the Go
# port, panel/go/internal/api/rt_telemetry.go + svc_telemetry_collector.go
# (the s463 exhaustion
# check's standing next candidate — see feedback_dockpanel_audit_scope_p2).
# Found and fixed 3 real, independently-verified issues:
#
#   §A rt_telemetry.go's `preview` endpoint (and the frontend Preview modal)
#      asserted "This is exactly what would be sent" over a `system` block
#      built from the AGENT's full host-fingerprint endpoint (hostname, OS,
#      kernel, memory, disk, cpu, uptime, services) — but the function that
#      actually POSTs to the external endpoint, telemetryCollectorSendPendingEvents, never
#      receives an AgentClient at all and builds its own tiny
#      {dockpanel_version, installation_id} system object. The false claim
#      existed in TWO independent places: the backend JSON `note` field and
#      a separately hardcoded frontend footer (Telemetry.tsx). Direction of
#      the error is over-claiming what leaves the box, not under-claiming —
#      not a live PII leak, but a false transparency claim on a
#      privacy-sensitive opt-in feature, live-reachable regardless of the
#      telemetry_enabled toggle (preview has no gate on it).
#   §B (off-menu, completeness critic) rt_on_call.go's rtOnCallValidateMembersExist
#      only checked submitted member UUIDs existed (`SELECT COUNT(*) ...
#      WHERE id = ANY($1)`), with no ownership term — the exact sibling gap
#      rt_escalation_policies.go's validateUserRoutes closed for `user:`
#      escalation routes at s437, missed here because a schedule's member
#      list is a different path into the same paging sink. An admin could
#      add ANY other user's UUID (discoverable via GET /api/users, which
#      lists every user on the install) as a rotation member of a schedule
#      they own; pages routed at that schedule deliver to the victim's real
#      email/Slack/Discord/PagerDuty/webhook with no consent.
#   §C (setup critic, re-scoped) the agent's DatabaseRemoveDatabase force-removes
#      a container (with volumes) by id with no check that the container is
#      actually dockpanel-managed — unlike its sibling `require_managed()`/
#      `is_managed_labels()` in docker_apps (v2.15.0), which this module
#      never had. Reachability is defense-in-depth only: every caller of
#      `/databases/{cid}` DELETE sources `container_id` from the panel's own
#      `databases` row, written once from this module's own create response,
#      never from user input — confirmed unchanged since s297
#      (project_dockpanel_tech_debt_p26.md). NOTE: that memory's own citation
#      ("ensure_managed... defined in routes/docker_apps, 19 call sites")
#      does not match current code — grepped, zero hits anywhere in the
#      backend. The real, current primitive is `is_managed_labels`/
#      `require_managed` in the agent's services/docker_apps (now
#      panel/go/internal/agent/services/docker_apps.go), scoped
#      to Docker Apps only. The underlying gap (no managed-label check on
#      this destructive-by-id path) is real; the citation was stale.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  Telemetry / on-call / db-remove audit — source pins (s464)"
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
    s{^\s*///.*$}{}gm;
  ' "$1"
}

has()    { grep -qE -- "$2" <<< "$1"; }
lacks()  { ! grep -qE -- "$2" <<< "$1"; }

fnbody() {
  awk -v fn="$2" '
    (index($0, "func " fn "(") || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) && !started { started=1 }
    started {
      n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth += n - m; print
      if (opened || n>0) opened=1
      if (opened && depth<=0) exit
    }
  ' <<< "$1"
}

TELEMETRY_BE=panel/go/internal/api/rt_telemetry.go
TELEMETRY_BE_C=$(code "$TELEMETRY_BE")
TELEMETRY_FE=panel/frontend/src/pages/Telemetry.tsx
ON_CALL=panel/go/internal/api/rt_on_call.go
ON_CALL_C=$(code "$ON_CALL")
DB_AGENT=panel/go/internal/agent/services/database.go
DB_AGENT_C=$(code "$DB_AGENT")

VALIDATE_MEMBERS_BODY=$(fnbody "$ON_CALL_C" "rtOnCallValidateMembersExist")
REMOVE_DB_BODY=$(fnbody "$DB_AGENT_C" "DatabaseRemoveDatabase")
CREATE_DB_BODY=$(fnbody "$DB_AGENT_C" "DatabaseCreateDatabase")

# ── §A rt_telemetry.go + Telemetry.tsx: preview's false claim reworded ─────
echo "── §A preview's \"exactly what would be sent\" claim narrowed to match the real payload ──"

if [ -f "$TELEMETRY_BE" ] && has "$TELEMETRY_BE_C" '"note":' && lacks "$TELEMETRY_BE_C" 'This is exactly what would be sent to the configured endpoint'; then
  ok "A1 backend preview note no longer claims the whole system block is sent"
else
  bad "A1 backend preview note still asserts the old false claim"
fi

if has "$TELEMETRY_BE_C" 'dockpanel_version.*installation_id' ; then
  ok "A2 backend note names what actually IS sent (dockpanel_version, installation_id)"
else
  bad "A2 backend note no longer names the real outbound system fields"
fi

if [ -f "$TELEMETRY_FE" ] && lacks "$(cat "$TELEMETRY_FE")" 'This is exactly what would be sent\. All PII has been stripped\.'; then
  ok "A3 frontend Preview-modal footer no longer carries the old unqualified claim"
else
  bad "A3 frontend Preview-modal footer still asserts the old false claim"
fi

if [ -f "$TELEMETRY_FE" ] && has "$(cat "$TELEMETRY_FE")" 'local diagnostic context'; then
  ok "A4 frontend footer now flags the system block as local-only context"
else
  bad "A4 frontend footer no longer distinguishes local context from the real payload"
fi

# Positive control: telemetryCollectorSendPendingEvents's real (small) system object is
# unchanged — the fix narrows the CLAIM, not the payload (widening the
# payload would be the arming move the skeptic flagged against).
SEND_PENDING_BODY=$(fnbody "$(code panel/go/internal/api/svc_telemetry_collector.go)" "telemetryCollectorSendPendingEvents")
if has "$SEND_PENDING_BODY" 'dockpanel_version' && lacks "$SEND_PENDING_BODY" 'hostname|system-info|AgentClient'; then
  ok "A5 (control) telemetryCollectorSendPendingEvents' real payload is still just {dockpanel_version, installation_id} — not widened"
else
  bad "A5 (control) telemetryCollectorSendPendingEvents' payload shape changed — verify this wasn't accidentally widened"
fi

# ── §B rt_on_call.go: schedule members are self-or-managed, not just existing ─
echo "── §B rt_on_call.go: rtOnCallValidateMembersExist enforces self-or-managed ownership ──"

if has "$VALIDATE_MEMBERS_BODY" 'ownerID uuid\.UUID'; then
  ok "B1 rtOnCallValidateMembersExist takes an ownerID parameter"
else
  bad "B1 rtOnCallValidateMembersExist has no ownerID parameter — still existence-only"
fi

if has "$VALIDATE_MEMBERS_BODY" 'id = \$2 OR reseller_id = \$2'; then
  ok "B2 the member query requires self-or-managed (id = \$2 OR reseller_id = \$2)"
else
  bad "B2 the member query no longer carries the ownership term — regressed to existence-only"
fi

CALL_SITES=$(grep -c 'rtOnCallValidateMembersExist(r\.Context(), st\.DB, input\.Members, claims\.Sub)' <<< "$ON_CALL_C")
if [ "$CALL_SITES" -eq 2 ]; then
  ok "B3 both create and update schedule handlers pass claims.Sub as ownerID"
else
  bad "B3 expected 2 call sites passing claims.Sub, found $CALL_SITES"
fi

# Positive control: the existence check itself (the thing being extended,
# not replaced) is still there.
if has "$VALIDATE_MEMBERS_BODY" 'SELECT COUNT\(\*\) FROM users WHERE id = ANY\(\$1\)'; then
  ok "B4 (control) the underlying existence check is still present"
else
  bad "B4 (control) the existence check itself regressed"
fi

# ── §C agent services/database.go: DatabaseRemoveDatabase refuses an unmanaged container ─
echo "── §C agent services/database.go: DatabaseRemoveDatabase requires dockpanel.managed=true ──"

BEFORE_STOP=$(awk '{print} /ContainerStop/{exit}' <<< "$REMOVE_DB_BODY")

if has "$BEFORE_STOP" 'ContainerInspect\('; then
  ok "C1 DatabaseRemoveDatabase inspects the container before touching it"
else
  bad "C1 DatabaseRemoveDatabase no longer inspects the container before stop/remove"
fi

if has "$BEFORE_STOP" 'dockpanel\.managed'; then
  ok "C2 DatabaseRemoveDatabase checks the dockpanel.managed label before the stop/remove call"
else
  bad "C2 no dockpanel.managed check found ahead of stop/remove — guard regressed or reordered after the destructive call"
fi

if has "$REMOVE_DB_BODY" 'not a dockpanel-managed container'; then
  ok "C3 DatabaseRemoveDatabase returns a clear refusal error for an unmanaged container"
else
  bad "C3 the refusal error is missing"
fi

# Positive control: DatabaseCreateDatabase still labels its own containers
# dockpanel.managed=true — the thing the new guard checks for.
if has "$CREATE_DB_BODY" '"dockpanel\.managed":[[:space:]]*"true"'; then
  ok "C4 (control) DatabaseCreateDatabase still labels new containers dockpanel.managed=true"
else
  bad "C4 (control) DatabaseCreateDatabase no longer sets the managed label — the new guard would reject every legitimate removal"
fi

echo
echo "=================================================="
echo "  PASS=$PASS FAIL=$FAIL"
echo "=================================================="

[ "$FAIL" -eq 0 ]
