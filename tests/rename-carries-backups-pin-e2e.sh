#!/usr/bin/env bash
#
# Regression pin for "a rename takes the backups with it" — s389.
#
# THE DEFECT. Renaming a site migrated the webroot, the vhost, the parked vhost,
# the certificates, the nginx logs, the PHP-FPM pools, the fail2ban jail and the
# redirect configs — ten numbered steps — and left every backup tree behind under
# the old name. That is worse than a disk leak, because the panel's own table
# stores a filename and NO path: every reader rebuilds the directory from the
# LIVE domain. So the instant a rename completed, every archive the site had
# became unrestorable and undownloadable while the panel went on listing it, and
# the nightly retention sweep then resolved the new name, got NotFound, treated
# it as "already gone", deleted the row and counted it as pruned. Records
# destroyed, files stranded, success logged.
#
# TWO REFUSALS came with the fix, and both are pinned because both are the kind
# of guard that is easy to delete for looking over-cautious:
#
#   * A destination that already holds files is refused BEFORE anything moves.
#     Not hypothetical — every completed site delete manufactures one, because
#     the panel writes a pre-delete archive and records no row for it while the
#     cascade takes the rows that would have named it.
#   * A site with backups will not rename onto an agent too old to carry them,
#     because such an agent answers success and leaks anyway.
#
# ⛔ EVERY ARM HERE IS SCOPED TO ONE FUNCTION BODY. A file-scoped arm on this
# subject is worthless: the agent's nginx routes hold many other renames and the
# tree paths live in a helper ABOVE the handler, so a whole-file `has` would be
# satisfied by a sibling however the carry itself is rewritten. Every subject is
# also floored on its post-strip size, because a `fnbody` whose pattern stops
# matching yields an EMPTY subject and every absence arm beneath it then passes
# green for code that is no longer there.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { printf '\033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '\033[31m✗\033[0m %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3', got '$2'"; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "missing: $3" ;; esac; }
hasnt(){ case "$2" in *"$3"*) bad "$1" "present but must not be: $3" ;; *) ok "$1" ;; esac; }
before() { # $1 label, $2 subject, $3 earlier, $4 later
  local a b
  a=$(printf '%s' "$2" | $G -boF -- "$3" | head -1 | cut -d: -f1)
  b=$(printf '%s' "$2" | $G -boF -- "$4" | head -1 | cut -d: -f1)
  if [ -z "$a" ] || [ -z "$b" ]; then
    bad "$1" "could not locate both landmarks (earlier='${a:-none}' later='${b:-none}') — the arm measured nothing"
  elif [ "$a" -lt "$b" ]; then
    ok "$1"
  else
    bad "$1" "the earlier landmark sits at $a, AFTER the later one at $b"
  fi
}

# ugrep's --ignore-files shim honours .gitignore, so use the real binary.
G=/usr/bin/grep

# Whitespace (Go indents with TABS) is dropped, and so is Go's `"+"` string-concatenation seam, so a
# SQL literal split across lines reads as the one statement it is.
subj()   { sed -E -e 's://.*$::' -e 's:^[[:space:]]*--.*$::' "$1" | tr -d ' \t\n\\' | sed 's/"+"//g'; }
subjin() { sed -E -e 's://.*$::' -e 's:^[[:space:]]*--.*$::' | tr -d ' \t\n\\' | sed 's/"+"//g'; }
fnbody() { awk -v p="$2" 'index($0,p){f=1} f{print} f && /^}$/{exit}' "$1"; }
occ()    { printf '%s' "$1" | $G -oF -- "$2" | wc -l | tr -d ' '; }

# The Go port (panel/go) is what ships.
API=panel/go/internal/api
ANGINX=panel/go/internal/agent/routes/nginx.go
BSITES=$API/rt_sites.go
BDBR=$API/rt_databases.go
BSCHED=$API/svc_backup_scheduler.go
BDASH=$API/rt_dashboard.go
BORCH=$API/rt_backup_orchestrator.go
BEXEC=$API/svc_backup_policy_executor.go

for f in "$ANGINX" "$BSITES" "$BDBR" "$BSCHED" "$BDASH" "$BORCH" "$BEXEC"; do
  [ -f "$f" ] || { bad "SETUP" "$f missing"; exit 1; }
done

# Whole-file floors first, then every function-body subject is floored too.
for pair in "$ANGINX:40000" "$BSITES:60000" "$BDBR:20000" \
            "$BSCHED:6000" "$BDASH:9000" "$BORCH:35000" "$BEXEC:12000"; do
  f=${pair%:*}; min=${pair##*:}
  n=$(subj "$f" | wc -c)
  [ "$n" -ge "$min" ] || { bad "SETUP" "$f has $n chars of code, expected >= $min"; exit 1; }
done

F_ANGINX=$(subj "$ANGINX")
F_UNDO=$(fnbody   "$ANGINX" "func nginxUndoBackupCarry("        | subjin)
F_RENAME=$(fnbody "$ANGINX" "func (n nginxRoutes) renameSite(" | subjin)
F_BSITES=$(subj "$BSITES")
F_BRENAME=$(fnbody "$BSITES" "func rtSitesRenameDomain(" | subjin)
F_BREMOVE=$(fnbody "$BSITES" "func rtSitesRemove("      | subjin)
F_PURGE=$(fnbody  "$BDBR"   "func rtDatabasesPurgeDumpsIfUnclaimed(" | subjin)
F_SCHED=$(subj "$BSCHED")
F_DASH=$(subj "$BDASH")
F_ORCH=$(subj "$BORCH")
F_EXEC=$(subj "$BEXEC")

for pair in "F_UNDO:200" "F_RENAME:5000" \
            "F_BRENAME:2000" "F_BREMOVE:4000" \
            "F_PURGE:600"; do
  v=${pair%:*}; min=${pair##*:}
  n=$(printf '%s' "${!v}" | wc -c)
  [ "$n" -ge "$min" ] || { bad "SETUP" "$v resolved $n chars, expected >= $min — the pattern stopped matching"; exit 1; }
done

echo "── §A  the two domain-keyed trees are named in ONE place"
# A1-A3 retired: covered by TestPinRenameCarriesBackupsTreesAreTheArchiveRootAndWpSnapshots (panel/go/internal/agent/routes/pin_rename_carries_backups_test.go)

echo "── §B  the handler actually uses them, and the result of the move is READ"
eq  "B1 the handler resolves the trees once"  "$(occ "$F_RENAME" 'nginxDomainBackupTrees(oldDomain,newDomain)')" 1
# ⭐ THE ARM THAT MATTERS. Discarding the error here (Rust `.ok()`, Go `_ =`) is
# the whole defect wearing the fix's clothes: it moves what it can, discards
# ENOTEMPTY, and answers success.
has "B2 the move is matched, not discarded"   "$F_RENAME" 'iferr:=os.Rename(oldTree,newTree);err!=nil{'
hasnt "B3 and never swallowed"                "$F_RENAME" '_=os.Rename(oldTree,newTree)'
has "B4 a moved tree is remembered so it can be put back" "$F_RENAME" 'carried=append(carried,t)'
has "B5 a moved tree is re-hardened, because rename preserves the source mode" "$F_RENAME" 'services.BackupsSecureBackupTree()'

echo "── §C  the refusals"
# Two in the handler: the step-0 precondition and the errno split on the move.
eq  "C1 two caller-fixable refusals, not one" "$(occ "$F_RENAME" 'http.StatusConflict')" 2
has "C2 a collision is refused"               "$F_RENAME" 'nginxDirIsOccupied(t[1])'
# Anchored on the `if` and the opening brace, so the whole condition is pinned
# rather than a substring of it. A substring arm is satisfied by
# `if false && <the same condition>`, which disables the refusal while leaving
# every literal in place — found by mutation, not by reading.
has "C3 only when there is something to move" "$F_RENAME" 'ifnginxExists(t[0])&&nginxDirIsOccupied(t[1]){'
# ⛔ The precondition is worthless below the first move: by then the cheap
# refusal is gone and the webroot has already changed name.
before "C4 the precondition runs BEFORE the webroot moves" "$F_RENAME" \
  'nginxDirIsOccupied(t[1])' 'os.Rename(oldDir,newDir)'
# C5-C6 retired: covered by TestPinRenameCarriesBackupsOnlyNotFoundIsFree (panel/go/internal/agent/routes/pin_rename_carries_backups_test.go)

echo "── §D  the rollback is symmetric"
# 1 definition + 2 call sites: the carry's own failure, and the nginx -t tail
# that BOTH failure branches (test error, test refused) fall through to — in
# Rust those were two calls, in Go the success branch returns early and the
# two failures share one. Counted, not merely present.
eq  "D1 the undo is wired at every abort"     "$(occ "$F_ANGINX" 'nginxUndoBackupCarry(')" 3
before "D1b the nginx -t tail undoes the carry before either failure answers" "$F_RENAME" \
  'rollback()nginxUndoBackupCarry(carried,oldDomain)restored:=' 'Failedtotestconfig'
before "D1c and only after the success branch has returned" "$F_RENAME" \
  'iferr==nil&&out.Success{' 'rollback()nginxUndoBackupCarry(carried,oldDomain)restored:='
# D2 retired: covered by TestPinRenameCarriesBackupsUndoIsMostRecentFirst (panel/go/internal/agent/routes/pin_rename_carries_backups_test.go)
has "D3 and never silently"                   "$F_UNDO" 'slog.Error('

echo "── §E  the panel keeps the rows in step with the files"
has "E1 a minimum agent is named"             "$F_BRENAME" 'rtSitesBackupCarryMinAgent'
has "E2 the gate reads the agent's own answer, not a column that is NULL on the local agent" \
    "$F_BRENAME" 'agent.Get(ctx,"/health")'
# ⛔ Scoped so a site with NOTHING to lose still renames on any agent version.
has "E3 the refusal is gated on the site having backups" "$F_BRENAME" 'SELECTCOUNT(*)FROMbackupsWHEREsite_id=$1'
has "E4 the rows are re-prefixed to match the moved files" "$F_BRENAME" 'UPDATEbackupsSETfilename=$1||substring(filenamefrom$3)'
# ⛔ The agent answers this endpoint with a bare ARRAY. Reading a `backups` key
# would make the check report "nothing left behind" for every input it can see —
# an assertion that cannot fail is worse than no assertion.
has "E5 the leftover check reads the array the agent actually sends" "$F_BRENAME" 'left,_:=jsonArr(v)'
hasnt "E6 not a key that is never there"      "$F_BRENAME" 'jsonGet(v,"backups")'
# ⛔ FROZEN ON PURPOSE, and this is the only thing standing between the gate and a
# routine release bump. `rtSitesBackupCarryMinAgent` is a historical fact — the release
# in which the carry shipped — and it happens to equal the version of that release,
# so it looks exactly like the ten other places a version bump rewrites. Sed it
# forward and the panel starts refusing renames on agents that carry backups
# perfectly well, with no other symptom. It moves only if the carry itself changes.
eq  "E7 the minimum agent is frozen at the release that shipped the carry" \
    "$($G -oF -- 'constrtSitesBackupCarryMinAgent="2.142.0"' <<< "$F_BSITES" | wc -l | tr -d ' ')" 1

echo "── §F  a failed upload is RECORDED, so retention can still reach the file"
hasnt "F1 the scheduler no longer drops the row" "$F_SCHED" 'dontrecordinDBsincetheuploadfailed'
has "F2 the exhausted upload is carried past the INSERT" "$F_SCHED" 'uploadFailed=&lastErr'
has "F3 and the run still fails afterwards"   "$F_SCHED" 'ifuploadFailed!=nil{'
# ⛔ The ordering IS the fix. Returning before the INSERT restores the defect
# with every literal in this file still present.
before "F4 the row is written BEFORE the run reports failure" "$F_SCHED" \
  'INSERTINTObackups(' 'ifuploadFailed!=nil{'
has "F5 the destination is recorded whatever the upload did" "$F_SCHED" 'uploadedRemote,row.DestID,'
# Rust's literal was a conditional bind; in Go a gated destination would need a
# branch on the upload result, and the scheduler has none.
hasnt "F6 and not only when it succeeded"     "$F_SCHED" 'ifuploadedRemote{'

echo "── §G  a local-only archive does not read as a fresh backup"
# The row unit F adds would otherwise silence three staleness readers, which is
# a narrowing of an existing alarm — the site whose destination is down is
# exactly the one they exist to name.
has "G1 the dashboard tile"       "$F_DASH" '(b.destination_idISNULLORb.uploaded)'
has "G2 the backup-health list"   "$F_ORCH" '(b.destination_idISNULLORb.uploaded)'
has "G3 the 48-hour notification" "$F_EXEC" '(b.destination_idISNULLORb.uploaded)'

echo "── §H  site delete takes the database dumps with it"
has "H1 the delete holds the NAME, not just the container" "$F_BREMOVE" '"SELECTname,container_idFROMdatabasesWHEREsite_id=$1",'
hasnt "H2 and no longer only the container"  "$F_BREMOVE" '"SELECTcontainer_idFROMdatabasesWHEREsite_id=$1'
has "H3 the purge is reached from site delete" "$F_BREMOVE" 'rtDatabasesPurgeDumpsIfUnclaimed('
# ⛔ THE ONLY GUARD, AND IT IS SILENT WHEN WRONG. The probe has no
# self-exclusion term, so above the cascade every row answers the question about
# ITSELF: nothing is purged, and the log line reads exactly like a correct
# decision. No error, no failing request, no symptom.
before "H4 the purge runs AFTER the cascade" "$F_BREMOVE" \
  'DELETEFROMsitesWHEREid=$1' 'rtDatabasesPurgeDumpsIfUnclaimed('
has "H5 doubt still keeps the files"         "$F_PURGE" 'iferr!=nil{shared=true}'
has "H6 and the probe still asks about this host" "$F_PURGE" 'WHEREd.name=$1AND(COALESCE(s.server_id,st.server_id)=$2ORCOALESCE(s.server_id,st.server_id)ISNULL))'

echo "── §I  the one database name that collides with its own route"
# I1-I3 retired: covered by TestDeleteDbBackupsDumpReachesThePurge (panel/go/internal/agent/routes/data_routes_test.go)
# — Go's mux routes DELETE /db-backups/dump to the purge with db_name="dump", so
# the separate static handler (and its delegation) no longer exists.

printf '\n%s\n' "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
