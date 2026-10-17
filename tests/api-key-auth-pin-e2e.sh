#!/usr/bin/env bash
# api-key-auth-pin-e2e.sh — s467
#
# Wires the panel's previously-unwired `dp_`-prefixed API key scaffold
# (now panel/go/internal/api/rt_api_keys.go) into the authUser extractor
# (core_auth.go: (*AppState).authUser -> authenticateAPIKey), so it
# authenticates like a session JWT on every authUser-gated handler — the
# missing half that let the CLI (now panel/go/internal/cli/backend.go) restore a site's DATABASE as well as
# its files, which the agent alone structurally cannot do (no DB
# credentials). Full design: project_dockpanel_tech_debt_p198. Full account
# of what shipped, including three fixes a 3-lens adversarial skeptic
# workflow caught before shipping: project_dockpanel_tech_debt_p206.
#
# What the skeptic caught, each pinned below:
#   §A5 — a bad/expired key must NOT use the `session_invalid()` marker (that
#     means "your BROWSER session died, go log in"; a `dp_` key is a
#     session-less bearer credential, same class as an agent token).
#   §A6/A7 — "Revoke all sessions" and the Panic Button both promise a total
#     logout; a `dp_` key must die too if it was minted BEFORE that
#     revocation fired (comparing its own `created_at`, since it has no
#     `iat` of its own to re-derive).
#   §B — the hot-path lookup column (`key_hash`) needs an index, or every
#     API-key request forces a sequential scan of the whole table.
#   §C — the CLI's SSE-stream reader must decide pass/fail from the
#     TERMINAL "complete" step's own status only, matching the panel UI's
#     own rule — not from whether ANY earlier step carried status="error"
#     (the restore handler emits a non-fatal advisory that way on purpose).
#   §C (byte safety) — decoding UTF-8 per raw chunk, before a full frame has
#     arrived, can corrupt a multi-byte character split across a chunk
#     boundary.
#   §D — the CLI's domain→site-id lookup (GET /api/sites, owner-only) is
#     narrower than the restore endpoints it feeds (SITE_CALLER_PREDICATE:
#     owner OR admin-of-host) — needs a GET /api/admin/sites fallback.
#
# Live-fire proof, not just these source pins: a throwaway Vultr VPS ran the
# real published v2.220.0 install, swapped in these locally-built api+cli
# binaries, and drove every one of the above through the CLI's own restore
# command — see project_dockpanel_tech_debt_p206 for the full transcript
# (marker-row DB restore, revoked-key-then-remint, the files-only-metadata/
# real-DB-dump-in-archive scenario that reproduced the false "Restore
# failed" bug pre-fix, and an admin's key restoring a site owned by a
# DIFFERENT user via the admin-sites fallback).
#
# GO PORT: §A reads panel/go/internal/api/core_auth.go, §B the shipped
# migrations copy panel/go/internal/api/migrations, §C/§D the Go CLI
# (internal/cli/backend.go followProgress/loadBackendToken, internal/cli/
# backup.go cmdBackupRestoreViaBackend).
#
# No running panel needed.
#   run: bash tests/api-key-auth-pin-e2e.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  dp_ API-key auth wiring — source pins (s467)"
echo "=================================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

# Strip line (`//`, `///`) and block (`/* ... */`, one line only) comments so
# a doc comment mentioning a pinned literal can't satisfy an assertion the
# real code doesn't.
code() {
  [ -f "$1" ] || return 0
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
    s{^\s*///.*$}{}gm;
  ' "$1"
}

has()   { grep -qE -- "$2" <<< "$1"; }
lacks() { ! grep -qE -- "$2" <<< "$1"; }

# Extract one function's body by brace depth, so an arm scoped to a function
# can't be satisfied by an unrelated occurrence elsewhere in the same file.
fnbody() {
  awk -v fn="$2" '
    (index($0, "func " fn "(") == 1 || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) && !started { started=1 }
    started {
      n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth += n - m; print
      if (opened || n>0) opened=1
      if (opened && depth<=0) exit
    }
  ' <<< "$1"
}

AUTH=panel/go/internal/api/core_auth.go
AUTH_C=$(code "$AUTH")
MIGRATIONS_GLOB=$(ls panel/go/internal/api/migrations/*api_keys_hash*.sql 2>/dev/null | head -1)
MIGRATION_C=$([ -n "$MIGRATIONS_GLOB" ] && code "$MIGRATIONS_GLOB" || echo "")
BACKEND_CLIENT=panel/go/internal/cli/backend.go
BACKEND_CLIENT_C=$(code "$BACKEND_CLIENT")
BACKUP=panel/go/internal/cli/backup.go
BACKUP_C=$(code "$BACKUP")

# ── §A auth.rs: the dp_ branch and authenticate_api_key() ──────────────────
echo "── §A core_auth.go: dp_-prefixed bearer tokens authenticate as an API key, not a JWT ──"

FRP_BODY=$(fnbody "$AUTH_C" "authUser")
if has "$FRP_BODY" 'if hasBearer && strings\.HasPrefix\(bearer, "dp_"\) \{' \
  && has "$FRP_BODY" 'return st\.authenticateAPIKey\(r\.Context\(\), bearer\)'; then
  ok "A1 (*AppState).authUser detects a dp_-prefixed bearer token"
else
  bad "A1 the dp_-prefix detection branch is missing from (*AppState).authUser"
fi

DP_CHECK_LINE=$(grep -nE 'strings\.HasPrefix\(bearer, "dp_"\)' <<< "$FRP_BODY" | head -1 | cut -d: -f1)
COOKIE_FALLBACK_LINE=$(grep -nE '^\s*token := bearer$' <<< "$FRP_BODY" | head -1 | cut -d: -f1)
if [ -n "$DP_CHECK_LINE" ] && [ -n "$COOKIE_FALLBACK_LINE" ] && [ "$DP_CHECK_LINE" -lt "$COOKIE_FALLBACK_LINE" ]; then
  ok "A2 the dp_ check runs BEFORE the JWT/cookie-fallback logic (an early return, not a fallback)"
else
  bad "A2 the dp_ check is not positioned before the JWT/cookie path — it would never be reached, or would run after a wasted decode attempt"
fi

if has "$AUTH_C" '^func \(st \*AppState\) authenticateAPIKey\(ctx context\.Context, key string\) \(\*Claims, error\)'; then
  ok "A3 authenticateAPIKey() exists with the expected signature"
else
  bad "A3 authenticateAPIKey() is missing or its signature changed"
fi

AAK_BODY=$(fnbody "$AUTH_C" "authenticateAPIKey")

if [ -n "$AAK_BODY" ] && lacks "$AAK_BODY" 'sessionInvalid\('; then
  ok "A4 authenticateAPIKey() never uses the sessionInvalid() marker (a key is not a browser session)"
else
  bad "A4 authenticateAPIKey() is missing or calls sessionInvalid() — a bad/revoked key would wrongly redirect a browser to /login"
fi

# Control: session_invalid() itself still exists and is still used by the JWT
# path — proves A4 passes because the call was REMOVED from this function
# specifically, not because the whole helper was deleted project-wide.
if has "$AUTH_C" '^func sessionInvalid\(msg string\) error' && has "$FRP_BODY" 'sessionInvalid\("Authentication required"\)'; then
  ok "A4-control sessionInvalid() still exists and still gates the JWT/cookie path"
else
  bad "A4-control sessionInvalid() itself was removed or the JWT path no longer uses it"
fi

if has "$AAK_BODY" 'SELECT id, user_id, created_at FROM api_keys WHERE key_hash = \$1'; then
  ok "A5 the key lookup selects id, user_id AND created_at (created_at feeds the revocation check below)"
else
  bad "A5 the key-lookup query is missing created_at — the revocation check below cannot compare against a mint time"
fi

if has "$AAK_BODY" 'st\.sessionsRevokedAt\(\)' \
  && has "$AAK_BODY" 'row\.CreatedAt\.Unix\(\) < ts'; then
  ok "A6 a key minted BEFORE the last 'revoke all sessions'/Panic Button fire is refused"
else
  bad "A6 the sessions_revoked_at check is missing — a stolen/leaked key would survive an incident-response logout that explicitly promises to kill it"
fi

if has "$AAK_BODY" 'u\.Role == "suspended"'; then
  ok "A7 a suspended account's key stops authenticating (parity with the JWT path)"
else
  bad "A7 the suspended-account check is missing from the API-key path"
fi

if has "$AAK_BODY" 'UPDATE api_keys SET last_used_at = NOW\(\) WHERE id = \$1'; then
  ok "A8 last_used_at is updated on successful authentication"
else
  bad "A8 last_used_at bookkeeping is missing"
fi

# ── §B migrations: the hot-path lookup column is indexed ───────────────────
echo
echo "── §B migrations: api_keys.key_hash (the actual WHERE-clause column) is indexed ──"

if [ -n "$MIGRATIONS_GLOB" ]; then
  ok "B0 found the api_keys-hash-index migration file ($(basename "$MIGRATIONS_GLOB"))"
else
  bad "B0 no migration file matching *api_keys_hash*.sql exists"
fi

if has "$MIGRATION_C" 'CREATE UNIQUE INDEX idx_api_keys_hash ON api_keys\(key_hash\);'; then
  ok "B1 a UNIQUE index on api_keys(key_hash) exists — without it, every dp_ request sequential-scans the whole table"
else
  bad "B1 the key_hash index is missing or not UNIQUE"
fi

# ── §C backend_client.rs: pass/fail is decided by the TERMINAL step alone ──
echo
echo "── §C CLI backend.go: followProgress() and byte-safe SSE framing ──"

LT_BODY=$(fnbody "$BACKEND_CLIENT_C" "loadBackendToken")
if has "$LT_BODY" 'token := strings\.TrimSpace\(raw\)' && has "$LT_BODY" 'if token == "" \{'; then
  ok "C1 loadBackendToken() rejects an empty/whitespace-only token file instead of treating it as configured"
else
  bad "C1 loadBackendToken() no longer guards against an empty token file"
fi

FP_BODY=$(fnbody "$BACKEND_CLIENT_C" "followProgress")

if [ -n "$FP_BODY" ] && lacks "$FP_BODY" 'saw_?[Ee]rror|anyError|hadError'; then
  ok "C2 followProgress() has no cross-step 'saw_error' latch left over from the fixed defect"
else
  bad "C2 a saw_error-shaped latch is back — an earlier advisory-only error step would again fail a successful restore"
fi

# The terminal check must read `status` (this event's own field) at the
# `step_name == "complete"` branch — not a variable accumulated from earlier
# events. Scoped to the tail of the function so an unrelated status==\"error\"
# comparison elsewhere in the file can't satisfy this.
COMPLETE_BRANCH=$(awk '/"step"\), ""\) == "complete"/{f=1} f' <<< "$FP_BODY")
if has "$COMPLETE_BRANCH" 'if status == "error"'; then
  ok "C3 the complete-event branch decides pass/fail from THIS event's own status"
else
  bad "C3 the complete-event branch does not check its own status field"
fi

if has "$FP_BODY" 'var buf \[\]byte' \
  && has "$FP_BODY" 'buf = append\(buf, chunk\[:n\]\.\.\.\)' \
  && has "$FP_BODY" 'frame := strings\.ToValidUTF8\(string\(buf\[:pos\+2\]\)' \
  && lacks "$FP_BODY" 'string\(chunk'; then
  ok "C4 raw bytes are buffered across chunks and decoded only once a complete frame has arrived (chunk boundaries can split a multi-byte char)"
else
  bad "C4 a raw chunk is decoded independently before a full frame has been assembled — a split multi-byte character would corrupt a printed message"
fi

# ── §D backup.rs: domain resolution matches the restore endpoint's own scope ─
echo
echo "── §D CLI backup.go: domain→site-id resolution falls back to the admin-sites listing ──"

RESTORE_VIA_BACKEND_BODY=$(fnbody "$BACKUP_C" "cmdBackupRestoreViaBackend")

if has "$RESTORE_VIA_BACKEND_BODY" 'backendGet\("/api/admin/sites", token\)'; then
  ok "D1 cmdBackupRestoreViaBackend falls back to GET /api/admin/sites"
else
  bad "D1 no /api/admin/sites fallback — an admin's key can restore a site it doesn't own via the API, but the CLI's own domain lookup would 404 first"
fi

# Order: the owner-scoped lookup, then the `if !ok {` it failed, then the
# admin listing inside it.
L_OWN=$(grep -nE 'siteID, ok := findID\(sites, "domain", domain\)' <<< "$RESTORE_VIA_BACKEND_BODY" | head -1 | cut -d: -f1)
L_IFNOT=$(awk -v from="${L_OWN:-999999}" 'NR > from && /^[[:space:]]*if !ok \{/ {print NR; exit}' <<< "$RESTORE_VIA_BACKEND_BODY")
L_ADMIN=$(grep -nE '/api/admin/sites' <<< "$RESTORE_VIA_BACKEND_BODY" | head -1 | cut -d: -f1)
if [ -n "$L_OWN" ] && [ -n "$L_IFNOT" ] && [ -n "$L_ADMIN" ] && [ "$L_OWN" -lt "$L_IFNOT" ] && [ "$L_IFNOT" -lt "$L_ADMIN" ]; then
  ok "D2 the fallback is conditioned on the owner-scoped lookup coming up empty, not run unconditionally"
else
  bad "D2 no owned/not-owned branch found — cannot confirm the fallback is actually gated"
fi

echo
echo "──────────────────────────────────────────"
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" -eq 0 ]
