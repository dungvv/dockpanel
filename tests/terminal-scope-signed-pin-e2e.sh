#!/usr/bin/env bash
# terminal-scope-signed-pin-e2e.sh — s317 / v2.75.0
#
# THE SENTENCE THIS SUITE EXISTS TO PROVE, written out so a mutation can be aimed
# at it rather than at whatever the arms happen to catch:
#
#   "The shell a terminal ticket opens is decided by the ownership check the
#    panel performed when it minted the ticket — carried inside the signature —
#    not by a parameter the browser sends to the agent."
#
# THE DEFECT. The panel resolved a site's domain under an ownership predicate and
# returned it BESIDE the signed ticket, while the agent read the domain from the
# `?domain=` query string. An empty domain there opens a root shell with no
# privilege drop (no setuid to www-data, no restricted shell). So a non-admin who
# owned a single site minted an ownership-checked, site-scoped ticket, then dialled
# the agent with the domain omitted and got an unrestricted root shell on the host.
# The panel's "Admin access required for server terminal" check only fires when the
# ticket is minted with no site at all — it never travelled to the agent.
#
# So the mutations this suite must survive are WIDENING mutations — move the scope
# back out of the signature, or make the agent trust the query param again — not
# deletions. Every arm below was mutation-tested to redden ALONE.
#
#   §A  the panel binds the scope INTO the signed ticket
#   §B  the agent takes the scope FROM the ticket, not the query param
#   §C  the two ends agree on the server-shell marker
#
# Subjects are the Go ports: panel/go/internal/api/rt_terminal.go (rtTerminalWsToken,
# the share handlers) and panel/go/internal/agent/routes/terminal.go
# (terminalWsHandler, terminalOpenPtyShell).
#
# Pure source analysis: no box, no network, no build.
#
# NO PIPES INTO `grep -q`. Under `set -o pipefail` grep -q closes the pipe on its
# first match, the upstream dies of SIGPIPE (141), and pipefail reports the whole
# pipeline failed — so an arm goes red on correct code, non-deterministically.
# Every arm here feeds grep a here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

BE=panel/go/internal/api/rt_terminal.go
AG=panel/go/internal/agent/routes/terminal.go

for f in "$BE" "$AG"; do [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"; done

# Comments out, CODE INTACT. The `/*` in a string-literal trap and the reason:
# this suite asserts the ABSENCE of a query-param read that the fix's OWN comments
# legitimately discuss.
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}
subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }
has()   { grep -qE -- "$2" <<< "$1"; }
count() { grep -cE -- "$2" <<< "$1" || true; }

# One function's body, bounded by its OWN closing brace in column 0.
fn_body() { awk -v pat="$1" '$0 ~ pat {f=1} f {print} f && /^\}/ {exit}' <<< "$2"; }
flat() { tr '\n' ' ' <<< "$1" | tr -s ' \t' ' '; }
# Order predicate: does `first` appear before `second` in `body`?
before() {
  local body="$1" first="$2" second="$3" a b
  a=$(grep -nE -- "$first" <<< "$body" | head -1 | cut -d: -f1)
  b=$(grep -nE -- "$second" <<< "$body" | head -1 | cut -d: -f1)
  [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}

BE_S=$(subj "$BE" || true)
AG_S=$(subj "$AG" || true)

MINT=$(fn_body '^func rtTerminalWsToken[(]' "$BE_S")
MINT_FLAT=$(flat "$MINT")

echo "§A  the panel binds the scope INTO the signed ticket"

# A1 — the signed claims carry a scope. The Go mint signs a jwt.MapClaims
# literal that is then HS256'd, so a key there is a key the agent can trust.
if [ -z "$MINT" ]; then
  bad "A1 SKIPPED: could not bound rtTerminalWsToken in $BE"
elif has "$MINT_FLAT" 'ticket := jwt\.MapClaims\{[^}]*"scope": *scope,[^}]*\}' \
  && has "$MINT_FLAT" 'jwt\.NewWithClaims\(jwt\.SigningMethodHS256, ticket\)'; then
  ok "A1 the signed terminal ticket carries a scope"
else
  bad "A1 the signed ticket has no scope field — the shell decision is not in the signature"
fi

# A2 — and it is set from the ownership-resolved domain, not from anything the
# caller sent. The mint reads `domain` (the SiteCallerPredicate result) and
# falls back to the server marker. Keyed on the decision, not the field name.
if [ -z "$MINT" ]; then
  bad "A2 SKIPPED: could not bound rtTerminalWsToken in $BE"
elif has "$MINT_FLAT" 'scope := rtTerminalServerShellScope if domain != nil \{ scope = \*domain \}' \
  && has "$MINT_FLAT" 'd, err := queryScalarOpt\[string\]\(ctx, st\.DB, "SELECT s\.domain FROM sites s WHERE "\+SiteCallerPredicate, siteID, c\.Sub\)' \
  && has "$MINT_FLAT" 'domain = d \}'; then
  ok "A2 the scope is set from the ownership-resolved domain, server marker as the only fallback"
else
  bad "A2 the ticket scope is not derived from the resolved domain — an attacker-supplied value could reach it"
fi

# A3 — the ownership check still gates the site branch (the scope is only as good
# as the resolution behind it). SiteCallerPredicate must still bind the domain.
if [ -z "$MINT" ]; then
  bad "A3 SKIPPED: could not bound rtTerminalWsToken in $BE"
elif has "$MINT" 'SiteCallerPredicate' && has "$MINT" 'not owned by you'; then
  ok "A3 the site domain is still resolved under the ownership predicate before it becomes the scope"
else
  bad "A3 the ownership resolution behind the scope is gone — the signed scope would certify nothing"
fi

echo "§B  the agent takes the scope FROM the ticket, not the query param"

# B1 retired: covered by TestTerminalValidateTicket (panel/go/internal/agent/routes/terminal_test.go) — the agent decodes the signed scope (nil when absent, "@server" when signed)

WS=$(fn_body '^func terminalWsHandler[(]' "$AG_S")

# B2 — THE ARM THAT MATTERS. The domain the shell opens under is chosen from the
# TICKET scope, and the query param is used ONLY on the no-scope (legacy) branch.
# A regression that reads `?domain=` up front, before the scope, is the defect.
if [ -z "$WS" ]; then
  bad "B2 SKIPPED: could not bound terminalWsHandler"
elif before "$WS" 'ticketScope, ok = terminalValidateTicket\(' 'var domain string' \
  && has "$(flat "$WS")" 'var domain string switch \{ case ticketScope != nil && \*ticketScope == terminalServerShellScope: domain = "" case ticketScope != nil: domain = \*ticketScope default: domain = q\.Get\("domain"\)'; then
  ok "B2 the shell's domain is chosen from the signed scope; the query param is not read up front"
else
  bad "B2 the domain is bound from the query param, not the ticket scope — the escalation is restored"
fi

# B3 — the legacy fallback to the query param is confined to the no-scope branch
# AND announces itself. An unscoped root shell that is silent is how this would
# hide on a mixed-version fleet.
N=$(count "$WS" 'q\.Get\("domain"\)')
if [ -n "$WS" ] && [ "$N" = "1" ] && before "$WS" 'default:' 'q\.Get\("domain"\)' \
  && has "$(flat "$WS")" 'domain = q\.Get\("domain"\) if domain == "" \{ slog\.Warn\('; then
  ok "B3 the query param is read once, only on the no-scope legacy branch, and it is logged"
else
  bad "B3 the query param is read outside the legacy branch (${N} reads) or an unscoped root shell is silent"
fi

echo "§C  the two ends agree on the server-shell marker"

# C1 — both files define the SAME marker string. If they drift, an admin server
# shell minted by the panel is treated as a site named '@server' by the agent, or
# worse a site scope is mistaken for the server shell.
BE_MARK=$(grep -oE 'const rtTerminalServerShellScope = "[^"]+"' <<< "$BE_S" | grep -oE '"[^"]+"' | head -1)
AG_MARK=$(grep -oE 'const terminalServerShellScope = "[^"]+"' <<< "$AG_S" | grep -oE '"[^"]+"' | head -1)
if [ -n "$BE_MARK" ] && [ "$BE_MARK" = "$AG_MARK" ]; then
  ok "C1 both ends agree the server-shell marker is $BE_MARK"
else
  bad "C1 the server-shell marker differs: panel=${BE_MARK:-none} agent=${AG_MARK:-none}"
fi

# C2 — the marker is not a legal domain, so it can never collide with a site's
# name. The agent's own domain validation rejects it (contains '@', or '/').
if [ -n "$BE_MARK" ]; then
  m=${BE_MARK//\"/}
  if [[ "$m" == *@* || "$m" == */* ]]; then
    ok "C2 the server-shell marker ($BE_MARK) is not a valid domain, so no site can claim it"
  else
    bad "C2 the server-shell marker ($BE_MARK) could be a real domain — a site of that name would open a root shell"
  fi
else
  bad "C2 SKIPPED: no marker found to check"
fi

DROP=$(fn_body '^func terminalOpenPtyShell[(]' "$AG_S")
DROP_FLAT=$(flat "$DROP")

# C3 — the agent still drops privilege for a site scope: a non-empty domain must
# reach the credential-switching path. Guards against a fix that carries the
# scope but forgets to act on it.
if [ -z "$AG_S" ]; then
  bad "C3 SKIPPED: $AG did not yield source"
elif has "$AG_S" 'isSite := domain != ""' \
  && has "$AG_S" 'terminalOpenPtyShell\(cwd, cols, rows, isSite\)' \
  && has "$DROP_FLAT" 'if site \{.*attrs\.Credential = &syscall\.Credential\{Uid: uid, Gid: gid, Groups: groups\}'; then
  ok "C3 a site-scoped shell still drops to the site's user"
else
  bad "C3 the privilege drop for a site shell is gone"
fi

# C4 — and the drop must be VERIFIED, not merely attempted.
#
# ⚠ WHY C3 IS NOT ENOUGH, written down because C3 reads as though it were.
# In the Rust era all three of setgid/initgroups/setuid once had their results
# discarded (until v2.88.0), so a tree where `setuid` FAILS and the child falls
# through to `execv` would have passed a C3-shaped arm while handing the SITE'S
# OWNER a root shell in their own webroot (#321: name the PROPERTY, not two
# tokens a rewrite keeps).
#
# The property: a failed privilege drop must not yield a running shell. In Go,
# SysProcAttr.Credential makes the child abort the exec if any of
# setgid/setgroups/setuid fails, and the parent then asks the KERNEL who the
# child is (/proc/<pid>/status: real+effective uid, real gid) and kills it on a
# mismatch — the half that cannot be fooled by a return code nobody read.
CREDS=$(fn_body '^func terminalCredsAre[(]' "$AG_S")
if [ -z "$DROP" ] || [ -z "$CREDS" ]; then
  bad "C4 SKIPPED: could not bound terminalOpenPtyShell / terminalCredsAre"
elif has "$DROP_FLAT" 'if !terminalCredsAre\(cmd\.Process\.Pid, uid, gid\) \{ _ = s\.f\.Close\(\) _ = cmd\.Process\.Kill\(\) _ = cmd\.Wait\(\) return nil, nil, ' \
  && before "$DROP" 'pty\.StartWithAttrs\(cmd, size, attrs\)' 'terminalCredsAre\(' \
  && has "$CREDS" '/proc/%d/status' \
  && has "$CREDS" 'want\("Uid:", \[\]int\{1, 2\}, uid\)'; then
  ok "C4 a FAILED privilege drop never yields a shell, and the result is re-read from the kernel"
else
  bad "C4 the privilege drop is not verified — a failed setuid could hand a ROOT shell to the site's owner"
fi

echo "§D  a terminal share is scoped to the admin who created it (s428)"
#
# THE DEFECT THIS SECTION CLOSES. `list_shares` (GET /api/terminal/shares) ran
# `SELECT key, value FROM settings WHERE key LIKE 'terminal_share_%'` with no
# owner filter at all — on a multi-admin/reseller install, any admin could
# enumerate every OTHER admin's shares and, via the exposed share_id, read
# their root terminal output through the unauthenticated public viewer.
# `revoke_share` had the same gap: any admin could DELETE any admin's share by
# id alone. Both are settings-table rows (no dedicated owner column), so the
# fix threads the creating admin's id through the existing pipe-delimited
# value string share_lifetime already parses.

# D1 — share_output stores the CREATING ADMIN's id alongside the timestamp,
# not just content. Three pipe-delimited fields, the middle one bound from
# claims — not two.
SO=$(fn_body '^func rtTerminalShareOutput[(]' "$BE_S")
if [ -n "$SO" ] && has "$SO" 'value := strconv\.FormatInt\(time\.Now\(\)\.Unix\(\), 10\) \+ "\|" \+ c\.Sub\.String\(\) \+ "\|" \+ content'; then
  ok "D1 share_output stores the creating admin's id in the share value"
else
  bad "D1 share_output does not store an owner — every admin's shares are indistinguishable"
fi

# D2 retired: covered by TestRtTerminalShareLifetime (panel/go/internal/api/rt_terminal_test.go) — share_lifetime parses the owner field (and fails closed to "" on a pre-owner row)

# D3 — THE ARM THAT MATTERS. list_shares skips any share whose owner is not
# the calling admin's own id.
LIST=$(fn_body '^func rtTerminalListShares[(]' "$BE_S")
LIST_FLAT=$(flat "$LIST")
if [ -n "$LIST" ] && has "$LIST" 'me := c\.Sub\.String\(\)' \
  && has "$LIST_FLAT" 'owner, _, ok := rtTerminalShareLifetime\(kv\.B, now\) if !ok \|\| owner != me \{ continue \}'; then
  ok "D3 list_shares skips any share not owned by the calling admin"
else
  bad "D3 list_shares returns every admin's shares — any admin can enumerate another's root terminal output"
fi

# D4 — revoke_share's DELETE is scoped to the calling admin's own share, not
# just the share id. A key match alone lets any admin revoke — or, paired with
# a D3 regression, first enumerate then read via the share_id — another
# admin's share.
REVOKE=$(fn_body '^func rtTerminalRevokeShare[(]' "$BE_S")
if [ -n "$REVOKE" ] && has "$(flat "$REVOKE")" "split_part\(value, '\|', 2\) = \\\$2\", \"terminal_share_\"\+id, c\.Sub\.String\(\)\)"; then
  ok "D4 revoke_share's DELETE is scoped to the calling admin's own share"
else
  bad "D4 revoke_share can delete any admin's share by id alone — no ownership check"
fi

# D5 — view_shared (the public, unauthenticated link) must NOT gain an owner
# check — its whole design is "the id is the credential." In Go, auth is a call
# in the body (st.authUser / st.adminUser), so the body is the subject; the
# id-validation call is the positive anchor proving the body was extracted.
VIEW=$(fn_body '^func rtTerminalViewShared[(]' "$BE_S")
if [ -n "$VIEW" ] && has "$VIEW" 'rtTerminalValidShareID\(id\)' \
  && ! has "$VIEW" 'st\.(authUser|adminUser)\(|requireAdmin\(|claims|c\.Sub'; then
  ok "D5 view_shared stays unauthenticated — the link itself remains the only credential"
else
  bad "D5 view_shared gained an auth requirement, or its body could not be found — legitimate share links would break"
fi

echo
echo "PASS $PASS / FAIL $FAIL"
[ "$FAIL" -eq 0 ]
