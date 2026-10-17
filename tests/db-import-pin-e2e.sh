#!/usr/bin/env bash
# Regression pins for the s385 ship — the database-import door, and the two
# silences either side of it.
#
# Issue #121 asked for two things. v2.137.0 answered the upload half; this is
# the other one: "there is currently no database import feature". There wasn't
# a door — but the machinery behind it had been built and hardened for the
# migration wizard, so what shipped is a door, not an importer:
#
#   * THE INTAKE PATTERN IS THE WIZARD'S, NOT THE FILE MANAGER'S. A dump travels
#     base64-in-JSON through two HTTP services capped at 2 MiB each, so uploads
#     top out near 1.5 MB and no real dump fits. The operator places the file and
#     the panel takes a NAME — never a free-text path, so there is no
#     arbitrary-file-to-DB-exec surface to guard: every name the operator can
#     pick came out of a listing of one per-database directory the agent pins.
#   * A TIMEOUT IS NOT A FAILURE, AND MUST NOT BE REPORTED AS ONE. The agent
#     gives a restore 600s; the panel's own `TimeoutLayer` cuts every request at
#     300s. A handler that waited 600 would be killed by its own server and
#     answer a bodyless 504. §C pins the constant BELOW the server's ceiling by
#     deriving BOTH numbers from source, and §D pins that the timeout arm exists
#     at all — without it `agentError` maps the timeout to an incident id, which
#     is #121's defect wearing a different hat.
#   * THE LISTING NOW REPORTS WHAT IT CANNOT USE. It used to `continue` past any
#     file that was not .sql.gz, so an operator who copied `dump.sql` into the
#     directory saw an empty list and had nowhere to learn why. That is lesson
#     #647 — a limitation the product will not speak at the moment it bites is,
#     from the operator's chair, an undocumented one.
#
# §G is this session's other find and is a genuine class arm: `warning-500` and
# `ok-500` were used in three places and defined nowhere, so a one-shot API-token
# warning and the "this device" marker on the session-revocation screen rendered
# with no colour at all. Both sides of that arm are derived from source — the
# palette from index.css, the usage from the SPA — so mutating either goes red.
#
# Go port: panel side is panel/go/internal/api (rt_databases.go,
# rt_backup_orchestrator.go, svc_agent.go, core_router.go), agent side is
# panel/go/internal/agent/{services,routes}/database_backup.go, CLI is
# panel/go/internal/cli/backup.go. Arms over the pure importability rule moved
# to TestPinDbImportBlockedReason (panel/go/internal/api/pin_db_import_test.go).
#
# Every arm is static analysis over source text: offline and deterministic, so it
# judges a MUTATED tree the same way on an air-gapped runner (lesson #641).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
ok()  { printf '\033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '\033[31m✗\033[0m %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3', got '$2'"; }

# ugrep's --ignore-files shim honours .gitignore, so every count below uses the
# real binary explicitly (dockpanel-ops-p2, s357).
G=/usr/bin/grep
flat() { tr -d ' \t\n' < "$1"; }
# One Go function by brace balance (`func Name(` or a method `func (x *T) Name(`).
fnbody() {
  awk -v fn="$2" '
    (index($0, "func " fn "(") || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) && !started { started=1 }
    started {
      n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth += n - m; print
      if (opened || n>0) opened=1
      if (opened && depth<=0) exit
    }
  ' "$1"
}

DBS=panel/go/internal/api/rt_databases.go
ROUTER=$DBS   # Go registers the routes in rtDatabasesRegister, in the same file
ORCH=panel/go/internal/api/rt_backup_orchestrator.go
AGENTSVC=panel/go/internal/api/svc_agent.go
MAIN=panel/go/internal/api/core_router.go
ABACKUP=panel/go/internal/agent/services/database_backup.go
AROUTES=panel/go/internal/agent/routes/database_backup.go
ADBROUTE=panel/go/internal/agent/routes/database.go
BACKUPS=panel/go/internal/agent/services/backups.go
PAGE=panel/frontend/src/pages/Databases.tsx
CLI=panel/go/internal/cli/backup.go
CSS=panel/frontend/src/index.css
SPA=panel/frontend/src

for f in "$DBS" "$ROUTER" "$ORCH" "$AGENTSVC" "$MAIN" "$ABACKUP" "$AROUTES" \
         "$ADBROUTE" "$BACKUPS" "$PAGE" "$CLI" "$CSS"; do
  [ -f "$f" ] || { bad "SETUP" "$f missing"; exit 1; }
done
[ -d "$SPA" ] || { bad "SETUP" "$SPA missing"; exit 1; }

# An arm that measures an empty subject prints green for every absence below, so
# each subject is asserted before it is measured (lesson #143).
for pair in "$DBS:1000" "$ABACKUP:500" "$PAGE:1000" "$CSS:100"; do
  f=${pair%:*}; min=${pair##*:}
  n=$(wc -l < "$f")
  [ "$n" -ge "$min" ] || { bad "SETUP" "$f has $n lines, expected >= $min"; exit 1; }
done

echo "── A. The door exists, on both halves ────────────────────────────────────────"

eq "A1 the dump listing is registered" \
   "$(flat "$ROUTER" | $G -c '"GET/api/databases/{id}/dumps",h(rtDatabasesDumps))')" "1"
eq "A2 the import door is registered" \
   "$(flat "$ROUTER" | $G -c '"POST/api/databases/{id}/import",h(rtDatabasesImport))')" "1"

# A door nothing reaches is not a door. Keyed on the SPA's call, not on a button
# label, because labels get reworded and a reworded label is not a regression.
eq "A3 the SPA asks for the listing" \
   "$(flat "$PAGE" | $G -c '/databases/\${database.id}/dumps')" "1"
eq "A4 the SPA posts the import" \
   "$(flat "$PAGE" | $G -c '/databases/\${database.id}/import')" "1"

echo "── B. It reuses the hardened path instead of opening a new one ───────────────"

# The whole reason this shipped small: the agent already pins the directory per
# database, validates every identifier it puts on an argv, passes the password by
# environment and reads the child's exit status. Composing that route is the
# feature. Writing a second importer would re-open all of it.
if flat "$DBS" | $G -q '"/db-backups/%s/restore/%s",info.Name,filename'; then
  ok "B1 the panel composes the agent's existing restore route"
else
  bad "B1 the panel composes the agent's existing restore route" \
      "no /db-backups/{name}/restore/{filename} — a second import path would need its own review"
fi

# ⛔ The security arm. `databaseBackupIsSafeFilename` (whose extension list is
# databaseBackupHasDumpExt) is what `DatabaseBackupGetBackupPath` opens a file
# through; widening it to admit a plain .sql would send an ungzipped dump into
# `gunzip -c` on the restore path AND make traversal charset changes cheap. The
# listing was taught to EXPLAIN the rejection precisely so nobody is tempted to
# relax the gate instead.
GATE=$(fnbody "$ABACKUP" databaseBackupHasDumpExt)
GATE_EXTS=$(printf '%s' "$GATE" | $G -oP 'range \[\]string\{\K[^}]+' | $G -oP '"\K\.[^"]+' || true)
GATE_N=$(printf '%s\n' "$GATE_EXTS" | $G -c . || true)
[ "$GATE_N" -ge 4 ] && ok "B2a the filename gate was located and lists $GATE_N accepted forms" \
  || bad "B2a the filename gate was located and lists $GATE_N accepted forms" \
         "extraction failed — B2b below would pass against nothing"
# Every accepted form must be a gzipped one, because `DatabaseBackupRestoreMysql` pipes the
# file through `gunzip -c` unconditionally and never captures gunzip's stderr.
# Admitting a plain .sql here would fail at the far end of a pipe with the
# message "truncated/corrupt archive", which is the wrong diagnosis.
eq "B2b the filename gate admits only gzipped forms" \
   "$(printf '%s\n' "$GATE_EXTS" | $G -vc '\.gz' || true)" "0"

# No new agent route: the count is what keeps the published route figure honest,
# and a fresh importer on the agent is exactly the thing this design avoided.
# Control first: the router is located (its reset-password route is visible),
# so a zero below is about the importer, not about reading an empty file.
eq "B3a the agent's database router is read (control)" \
   "$(flat "$ADBROUTE" | $G -c '"POST/databases/reset-password",databaseResetPassword)')" "1"
eq "B3 no second importer was added to the agent's database router" \
   "$(flat "$ADBROUTE" | $G -c '/databases/import"')" "0"

# ⛔ THE LAYERING, and it is load-bearing in both directions. The AGENT answers only
# "is this a backup file at all" — if it also decided importability, every encrypted
# backup would be labelled broken in `dockpanel backup db-list`, which is a BACKUP
# listing. Whether a backup can enter a given database depends on the engine and on
# encryption, which only the PANEL knows. Both halves pinned so neither drifts back.
eq "B4a the agent's listing gate is databaseBackupIsSafeFilename itself, not a second opinion" \
   "$(flat "$ABACKUP" | $G -c 'if!databaseBackupIsSafeFilename(e.Name()){reason:=databaseBackupUnusableReason(dbName,e.Name())')" "1"
eq "B4b the agent does not decide importability (that would mislabel every .enc backup)" \
   "$($G -ciE 'func [a-z]*importable' "$ABACKUP")" "0"
# B4c retired: covered by TestPinDbImportBlockedReason (panel/go/internal/api/pin_db_import_test.go)

# ⛔ ANNOTATING WITHOUT ENFORCING IS A UI THAT ASKS NICELY. The listing greys a file out;
# the import door must refuse the identical set, from the identical call, or a direct
# POST walks past the greyed-out state into a decompression pipe.
LISTED=$(perl -0777 -ne '$c++ while /rtDatabasesImportBlockedReason\(filename,\s*info\.Engine\)/gs; END{print $c+0}' "$DBS")
[ "$LISTED" -ge 2 ] && ok "B4d the same rule is used by BOTH the listing and the door ($LISTED call sites)" \
  || bad "B4d the same rule is used by BOTH the listing and the door ($LISTED call sites)" \
         "fewer than 2 call sites — annotate-only leaves the door open to a direct POST"

# B4e retired: covered by TestPinDbImportBlockedReason (panel/go/internal/api/pin_db_import_test.go)
# B4f retired: covered by TestPinDbImportBlockedReason (panel/go/internal/api/pin_db_import_test.go)

echo "── C. The wait is bounded BELOW the server's own ceiling ─────────────────────"

# ⛔ Both numbers are derived from their real declarations, never restated here.
# An arm that reads the same literal the code reads cannot fail; this one goes
# red if either side moves, which is the only version worth having.
eq "C1 the restore budget is declared exactly once" \
   "$($G -cE '^const AgentDBRestoreTimeoutSecs = ' "$AGENTSVC")" "1"

BUDGET=$($G -oP '^const AgentDBRestoreTimeoutSecs = \K[0-9_]+' "$AGENTSVC" | tr -d _)
CEILING=$($G -oP 'return traceTimeout\(\K[0-9_]+(?=\*time\.Second)' "$MAIN" | tr -d _)
if [ -n "$BUDGET" ] && [ -n "$CEILING" ]; then
  ok "C2 both budgets were derived from source (agent wait ${BUDGET}s, server ceiling ${CEILING}s)"
else
  bad "C2 both budgets were derived from source" \
      "derivation failed — budget='$BUDGET' ceiling='$CEILING'; the comparison below would be vacuous"
fi
if [ -n "$BUDGET" ] && [ -n "$CEILING" ] && [ "$BUDGET" -lt "$CEILING" ]; then
  ok "C3 the panel stops waiting before its own server kills the request"
else
  bad "C3 the panel stops waiting before its own server kills the request" \
      "wait ${BUDGET}s is not below the ${CEILING}s traceTimeout — the handler's own message can never reach the operator"
fi

# Both database-restore call sites, including the one that was already wrong: a 60s
# `post` against an operation the agent gives 600s reported "timed out" while the restore
# went on succeeding. Slurped, because gofmt'd code is free to wrap a call this long and a
# line-anchored arm would not see it (#645).
n=$(perl -0777 -ne '$c++ while /const budget = AgentDBRestoreTimeoutSecs\b.*?\.PostLong\(tctx,\s*fmt\.Sprintf\("\/db-backups\/%s\/restore\/%s",[^)]*\),\s*agentBody,\s*budget\s*\+\s*60\)/gs; END{print $c+0}' "$DBS")
[ "$n" -ge 1 ] && ok "C4 rt_databases.go (import) dispatches on the shared restore budget" \
  || bad "C4 rt_databases.go (import) dispatches on the shared restore budget" \
         "no PostLong(..., budget+60) — a bare .Post caps this at 60s on both transports"
n=$(perl -0777 -ne '$c++ while /\.PostLong\(ctx,\s*fmt\.Sprintf\("\/db-backups\/%s\/restore\/%s",[^)]*\),\s*body,\s*AgentDBRestoreTimeoutSecs\)/gs; END{print $c+0}' "$ORCH")
[ "$n" -ge 1 ] && ok "C4b rt_backup_orchestrator.go (restore_db_backup) waits on the shared restore budget" \
  || bad "C4b rt_backup_orchestrator.go (restore_db_backup) waits on the shared restore budget" \
         "no PostLong(... AgentDBRestoreTimeoutSecs)"

# The literal must not creep back in beside the constant it replaced.
eq "C5 neither restore site hard-codes a second budget" \
   "$(cat "$DBS" "$ORCH" | $G -cE 'PostLong\(.*, *[0-9_]+ *\)')" "0"

echo "── D. A timeout is reported as a timeout, not as a failure ───────────────────"

# ⛔ THE CLASS ARM OF THIS SHIP, and the first version of it was WRONG in a way only
# an adversarial read caught. It matched `Err(AgentError::Request(_))` (Go: an
# AgentError of Kind AgentErrRequest) and called that
# "the timeout". It is not: the local client also mints Request for a URI that would not
# build and for a connection dropped mid-flight, and the REMOTE client never mints it for
# a timeout at all — it maps every failure, timeouts included, to Connection. So the arm
# was dead code on every fleet install, and locally it announced "still running" about
# work that had never been sent. Taking the timeout HERE makes Elapsed unambiguous on
# both transports.
n=$(perl -0777 -ne '$c++ while /tctx, cancel := context\.WithTimeout\(ctx, budget\*time\.Second\).*?errors\.Is\(tctx\.Err\(\), context\.DeadlineExceeded\)/gs; END{print $c+0}' "$DBS")
[ "$n" -ge 1 ] && ok "D1 the import times itself, so a timeout is unambiguous on both transports" \
  || bad "D1 the import times itself, so a timeout is unambiguous on both transports" \
         "no context.WithTimeout(budget) deadline judged by tctx.Err() around the agent call — the verdict would be read off an ambiguous error variant"

# The inner budget must be LARGER, or the inner clock fires first and we are back to
# reading someone else's error variant.
if flat "$DBS" | $G -q 'agentBody,budget+60)'; then
  ok "D1b the agent's own clock is set beyond ours, so ours is the one that fires"
else
  bad "D1b the agent's own clock is set beyond ours, so ours is the one that fires" \
      "the inner post_long budget is not greater than the outer timeout"
fi

# The refuted shape must not come back.
eq "D1c the verdict is never read off the error variant again" \
   "$(flat "$DBS" | $G -c 'AgentErrRequest')" "0"

if flat "$DBS" | $G -q 'NOTcancelled'; then
  ok "D2 the timeout sentence says the import was not cancelled"
else
  bad "D2 the timeout sentence says the import was not cancelled" \
      "the operator is not told the work continues, so the safe-looking action is to import again"
fi

eq "D3 the timeout answers 504, not a generic failure" \
   "$(flat "$DBS" | $G -c 'apiErr(http.StatusGatewayTimeout,')" "1"

# The SPA must not paint it red either — "still running" and "did not happen" are
# different facts and the operator acts differently on each. 524 is Cloudflare's cut at
# 100s, which arrives as an HTML body api.ts cannot read, so it needs naming explicitly.
if flat "$PAGE" | $G -q 'e.status===504||e.status===524'; then
  ok "D4 the SPA tells 'still running' apart from 'failed', including behind Cloudflare"
else
  bad "D4 the SPA tells 'still running' apart from 'failed', including behind Cloudflare" \
      "no 504/524 branch — a timeout renders in the error channel and reads as a failed import"
fi

# ⛔ A restore fails on the CONTENT of the file the caller named — truncated, not
# gzipped, wrong engine, SQL the database rejects. Those are caller-fixable answers, and
# the panel preserves an agent's sentence only for 4xx. Answering 5xx turned psql's
# "relation already exists" into an incident id on BOTH callers of that route.
eq "D5 a failed restore answers 4xx so its reason survives the panel" \
   "$(fnbody "$AROUTES" databaseBackupRestore | $G -v '^\s*//' | tr -d ' \t\n' | $G -c 'os.Remove(restorePath)}iferr!=nil{writeErr(w,http.StatusUnprocessableEntity,err.Error())')" "1"
eq "D5b the reason-destroying 5xx does not come back" \
   "$(fnbody "$AROUTES" databaseBackupRestore | $G -v '^\s*//' | tr -d ' \t\n' | $G -c 'os.Remove(restorePath)}iferr!=nil{writeErr(w,http.StatusInternalServerError')" "0"

echo "── E. The listing explains what it will not import (lesson #647) ─────────────"

# The old shape was a bare `continue` on the extension test, which is why a file
# could sit in the directory, be invisible, and have no explanation anywhere.
# Go: the listing is a backupsListDir callback where `return false` DROPS an
# entry. Exactly one drop is legitimate — the stray-subdirectory one — so the
# body is pinned to that single drop, anchored on the IsDir test.
LISTING=$(fnbody "$ABACKUP" DatabaseBackupListDbBackups | tr -d ' \t\n')
case "$LISTING" in
  *'ife.IsDir(){returnfalse}'*) ok "E1a the listing body was located (its one legitimate drop is the subdirectory one)" ;;
  *) bad "E1a the listing body was located" "no IsDir drop in DatabaseBackupListDbBackups — E1 would measure nothing" ;;
esac
eq "E1 no file is dropped from the listing without a reason" \
   "$($G -o 'returnfalse' <<< "$LISTING" | $G -c . || true)" "1"

eq "E2 the rejection is carried on the listing itself" \
   "$(flat "$BACKUPS" | $G -c 'Unsupported\*string`json:"unsupported')" "1"

# Omitted when absent, or the site- and volume-backup responses change shape for
# every consumer that never asked about dumps.
if flat "$BACKUPS" | $G -q 'Unsupported\*string`json:"unsupported,omitempty"`'; then
  ok "E3 the new field is omitted when absent, so sibling responses are unchanged"
else
  bad "E3 the new field is omitted when absent, so sibling responses are unchanged" \
      "no omitempty on `unsupported` — site and volume backup JSON changes for everyone"
fi

# E4 retired: covered by TestUnusableReasonNamesTheFileAndTheFix (panel/go/internal/agent/services/database_backup_test.go)
# E4b retired: covered by TestPinDbImportBlockedReason (panel/go/internal/api/pin_db_import_test.go)

# The agent's fallback sentence must not advertise a form the panel refuses — two
# sentences on one screen contradicting each other is worse than either alone.
# ⚠ -F, because an unescaped '.' in this pattern is a wildcard and matched the very
# mutation this arm exists to catch — the arm passed against the defect (#532's family:
# the instrument's own syntax is a hypothesis too).
eq "E4c the agent's fallback does not claim .enc is importable" \
   "$($G -Fc 'and their .enc forms' "$ABACKUP" || true)" "0"

# Both surfaces that render the listing. A reason produced and not displayed is
# the same defect one layer up.
if flat "$PAGE" | $G -q '{d.unsupported||d.import_blocked}'; then
  ok "E5 the SPA renders BOTH verdicts — not a backup, and cannot go in this database"
else
  bad "E5 the SPA renders BOTH verdicts" "a reason is produced and the page drops it"
fi

# ⛔ The empty state is a positive claim about a directory. Rendering it after a FAILED
# read fabricates that claim from a read that never happened — the exact ambiguity the
# component was written to remove, reintroduced one level up.
if flat "$PAGE" | $G -q '{!loading&&!error&&importable.length===0'; then
  ok "E5b the empty state stays silent when the listing could not be read"
else
  bad "E5b the empty state stays silent when the listing could not be read" \
      "'Nothing here to import' renders under the error banner, asserting something nobody measured"
fi
if flat "$CLI" | $G -q 'ifreason,ok:=str(get(b,"unsupported"));ok{'; then
  ok "E6 the CLI renders the reason"
else
  bad "E6 the CLI renders the reason" "dockpanel backup db-list still hides the rejected file's reason"
fi

echo "── F. Ownership and traversal ────────────────────────────────────────────────"

# Both are required for the credential-auth census to score this handler, and
# both are load-bearing: rtDatabasesGetDbInfo scopes to the caller's own databases, and
# the host must come from the site's row because `dockpanel-db-{name}` is unique
# only per machine and this call hands over the tenant's decrypted password.
IMPORT_BODY=$(fnbody "$DBS" rtDatabasesImport)
case "$IMPORT_BODY" in
  *'rtDatabasesGetDbInfo(ctx, st, id, claims.Sub)'*) ok "F1 the import scopes to the caller's own database" ;;
  *) bad "F1 the import scopes to the caller's own database" "no rtDatabasesGetDbInfo in the handler body" ;;
esac
case "$IMPORT_BODY" in
  *'agentForSiteServer(ctx, st, info.SiteServerID'*) ok "F2 the import resolves the host from the site's row" ;;
  *) bad "F2 the import resolves the host from the site's row" "no agentForSiteServer in the handler body" ;;
esac
case "$IMPORT_BODY" in
  *'!strings.Contains(filename, "..")'*) ok "F3 the filename is refused traversal before it becomes a URL path" ;;
  *) bad "F3 the filename is refused traversal before it becomes a URL path" "no '..' guard in the handler body" ;;
esac

echo "── H. The tenancy boundary this door would otherwise cross ──────────────────"

# ⛔ THE MOST IMPORTANT ARM HERE, and it exists because the first cut of this feature
# was tenant-reachable and an adversarial review broke it in four steps:
#
#   1. The dump directory is keyed by DATABASE NAME (`/var/backups/dockpanel/databases/
#      {name}`), not by id or owner.
#   2. Deleting a database removes its container and CASCADE-deletes its
#      `database_backups` rows — but NOTHING removes the dumps from disk, so they become
#      orphans no row references and no retention sweep can reach.
#   3. `databases.name` is unique only per SITE: the global constraint was dropped in
#      `20260312000000_data_integrity.sql`. So a second tenant may take a freed name.
#   4. An ad-hoc DB backup is written UNENCRYPTED.
#
# Row-scoping cannot close that, because files with no row are exactly what this door is
# for. `requireAdmin` closes it and costs nothing real: placing a file in that directory
# needs root, there is no per-site SFTP, and an admin can already read /var/backups.
for fn in rtDatabasesDumps rtDatabasesImport; do
  BODY=$(fnbody "$DBS" "$fn")
  if [ -z "$BODY" ]; then
    bad "H1 the $fn handler body was located" "extraction failed — H2 would pass vacuously"
  else
    ok "H1 the $fn handler body was located"
    case "$BODY" in
      *"if err := requireAdmin(claims.Role); err != nil {"*)
        ok "H2 $fn is admin-gated, so a reused database name cannot expose a former tenant's dumps" ;;
      *)
        bad "H2 $fn is admin-gated" \
            "no requireAdmin — a tenant taking a freed database name would list and import its previous holder's unencrypted dumps" ;;
    esac
  fi
done

# The UI must not offer a control the server will refuse; an operator who can see it and
# cannot use it learns only that the product is broken.
if flat "$PAGE" | $G -q 'constisAdmin=user?.role==="admin"'; then
  ok "H3 the SPA gates the Import control on the same role the server checks"
else
  bad "H3 the SPA gates the Import control on the same role the server checks" \
      "the button is rendered for everyone and the server answers 403"
fi

# ⛔ A filename with a space has the right extension and passes every obvious check, then
# breaks while the HTTP request line is BUILT — a failure the panel could describe only
# as a transport error. Refused here, where the answer can still be about the file.
IMPORT_BODY=$(fnbody "$DBS" rtDatabasesImport)
case "$IMPORT_BODY" in
  *"!rtDatabasesIsASCIIAlnum(c) && c != '-' && c != '_' && c != '.'"*)
    ok "H4 the filename charset is checked where a sentence can still explain it" ;;
  *) bad "H4 the filename charset is checked where a sentence can still explain it" \
         "only traversal is refused, so 'my dump.sql.gz' fails inside the transport" ;;
esac

# A fired event nobody can subscribe to reaches nobody. The subscription list is a fixed
# array of checkboxes — there is no free-text field — so an event missing from it is
# unreachable through any control.
eq "H5 the import event is subscribable through the Extensions UI" \
   "$($G -c '"database.imported"' panel/frontend/src/pages/Extensions.tsx)" "1"

# On a fleet, two databases can share a name on different machines. An audit row that
# does not say WHICH machine cannot answer the only question asked after a bad import.
case "$IMPORT_BODY" in
  *'ActivityLogActivityOnServer('*'info.SiteServerID'*) ok "H6 the audit row records the machine the import ran on" ;;
  *) bad "H6 the audit row records the machine the import ran on" \
         "ActivityLogActivity leaves server_id NULL — two same-named databases on a fleet are indistinguishable" ;;
esac

echo "── G. Every colour the SPA asks for is a colour the theme defines ────────────"

# ⛔ CLASS ARM, and it found three live defects when it was written: `warning-500`
# and `ok-500` were used in Settings.tsx and AccountSecurity.tsx and defined
# nowhere, so a one-shot API-token warning and the "this device" marker on the
# session-revocation screen rendered with no colour at all. Tailwind emits
# nothing for an undefined token and says nothing about it — the source looks
# styled and the pixel is not, which is unreviewable by reading either side
# alone. Both halves are derived: the palette from the stylesheet, the usage from
# the pages, so mutating either one turns this red.
PALETTE=$($G -oP '(?<=--color-)[a-z]+(?=-\d)' "$CSS" | sort -u)
PALETTE_N=$(printf '%s\n' "$PALETTE" | $G -c . || true)
[ "$PALETTE_N" -ge 4 ] && ok "G1 derived $PALETTE_N colour families from the theme" \
  || bad "G1 derived $PALETTE_N colour families from the theme" "too few — G2 below would pass vacuously"

USED=$(find "$SPA" \( -name '*.ts' -o -name '*.tsx' \) -print0 | sort -z | xargs -0 cat |
  $G -ohP '(?<![\w-])(?:bg|text|border|ring|from|to|via|divide|outline|decoration|shadow|fill|stroke|accent|caret)-[a-z]+-(?:50|\d00)(?![\w-])' |
  sed -E 's/^[a-z]+-([a-z]+)-.*/\1/' | sort -u)
USED_N=$(printf '%s\n' "$USED" | $G -c . || true)
[ "$USED_N" -ge 4 ] && ok "G2 found $USED_N colour families in use across the SPA" \
  || bad "G2 found $USED_N colour families in use across the SPA" "the enumeration is empty, so G3 measures nothing"

UNDEFINED=$(comm -23 <(printf '%s\n' "$USED") <(printf '%s\n' "$PALETTE") | tr '\n' ' ' | sed 's/ *$//')
if [ -z "$UNDEFINED" ]; then
  ok "G3 no page asks for a colour the theme does not define"
else
  bad "G3 no page asks for a colour the theme does not define" \
      "undefined and therefore invisible: $UNDEFINED"
fi

# The two that were broken, pinned by name so they cannot silently return.
eq "G4 the API-token warning uses a defined family" \
   "$($G -c 'warning-[0-9]' panel/frontend/src/pages/Settings.tsx)" "0"
eq "G5 the current-session marker uses a defined family" \
   "$($G -c -- '-ok-[0-9]' panel/frontend/src/components/AccountSecurity.tsx)" "0"

echo
echo "── db-import: $PASS passed, $FAIL failed ─────────────────────────────────────"
[ "$FAIL" -eq 0 ]
