#!/usr/bin/env bash
# Regression pins for the "timeout doesn't actually stop the thing"
# kill_on_drop gap found in the s450 pkg.rs fan-out's completeness-critic
# stage (project_dockpanel_tech_debt, ledger p189 — dockpanel-fanout run
# wf_2ad3e1e8-ab5).
#
# safe_command() (the Rust agent's safe_cmd.rs:36) was a bare
# tokio::process::Command — it sets no kill_on_drop. Six call sites across
# four files wrapped its .output() in tokio::time::timeout(...) without ever
# calling .kill_on_drop(true) on the Command first: when the timeout fires
# and the future is dropped, tokio's documented default leaves the child
# process running, orphaned, reparented to PID 1 — NOT bounded by the timeout
# that looked like it would stop it. Reproduced live during the audit: an
# orphaned `git fetch`/`git clone` leaves `.git/index.lock`, and the very
# next deploy/clone attempt on the same site — including an operator's
# natural immediate retry — fails instantly with a generic, non-actionable
# "Another git process seems to be running" error instead of succeeding or
# reporting the true cause.
#
# The exact same class was already fixed, correctly, in THREE other files
# (security_scanner.rs, database.rs, migration.rs, and git_build.rs's OWN
# docker-build call three lines below its unpatched git fetch) — this suite
# originally pinned the six sites the p189 fixes missed:
#   git_build.rs  : git fetch (clone_or_pull's pull branch)
#   git_build.rs  : git clone (clone_or_pull's fresh-clone branch)
#   deploy.rs     : git fetch (its OWN, independent clone_or_pull — a second
#                   implementation of the same idea, not a call into git_build.rs)
#   deploy.rs     : git clone (same function, fresh-clone branch)
#   backups.rs    : tar czf under a 300s timeout
#   remote_backup.rs : curl to S3 under a caller-supplied timeout (s3_curl,
#                   the one runner shared by test_s3/list_s3/delete_s3/upload)
#
# s451 CORRECTION + EXTENSION: this suite's own header, above, claimed
# database_backup.rs was among the "already fixed" files. That claim was
# FALSE — a s451 dockpanel-fanout finder/skeptic pair (rotation target
# database_backup.rs, per feedback_dockpanel_audit_scope) found only
# dump_mongo (1 of 6 privileged subprocess functions) actually had
# kill_on_drop(true); dump_mysql/dump_postgres/restore_mysql/
# restore_postgres/restore_mongo did not — meaning this pin suite provided
# ZERO real coverage for those five functions despite its own text asserting
# they were covered. Now fixed (9 call sites: dump_mysql and dump_postgres
# each spawn 2 children — docker+gzip; restore_mysql and restore_postgres
# each spawn 2 — gunzip+docker; restore_mongo spawns 1 — docker) and pinned
# in section F below, function-scoped rather than whole-file-anchored: the
# gzip/gunzip Command builders are byte-identical between the mysql and
# postgres functions, so a whole-file anchor on that text would alias across
# both sites (one fixed, one regressed, and the check would still pass) —
# the exact "pin greps raw source, matches comments/duplicate-code too" trap
# this project's own memory already names.
#
# The same critic pass found an UNRELATED file with the identical bug,
# off the original menu: the agent's routes/mail.rs's mailbox_backup/
# mailbox_restore (tar czf/xzf under a 300s timeout) — invisible to every
# earlier "grep services/ for kill_on_drop" sweep because mail.rs inlines
# its subprocess logic directly in the route handler, not a service module.
# Fixed and pinned in section G below.
#
# pkg.rs/safe_cmd.rs's OWN systemd-run-backed timeout (a harder, separate
# problem — killing the LOCAL waiter does not stop the REMOTE transient unit,
# proven live during the same audit) is explicitly OUT of scope here — see
# project_dockpanel_tech_debt ledger p189 for why that one is a sized carry,
# not a same-session fix.
#
# ─────────────────────────────────────────────────────────────────────────────
# THE GO PORT (panel/go). Every binary is Go now, and the Rust kill_on_drop(true)
# annotation has no spelling there: the equivalent is that the child is built
# with exec.CommandContext — safecmd.Command(ctx, …) — on a ctx that carries a
# DEADLINE. When it expires the runtime SIGKILLs and reaps the child, which is
# exactly the property the Rust annotation bought. So the premise flips:
#   §A  safecmd.Command uses exec.CommandContext, and a Go test proves a
#       timed-out child is really killed (TestPinTimeoutOrphanKillOnDropKillsTheChild).
#       The shared runners (deployRun, backupsRun, the database-backup pipe
#       helpers) derive their ctx from context.WithTimeout.
#   §B-§J every site the Rust suite named reaches the child through a
#       deadline-carrying ctx: either a runner given a non-zero timeout, or a
#       safecmd.Exec/Command(ctx, …) whose function created ctx with
#       context.WithTimeout BEFORE the call. context.Background() alone —
#       the Go shape of "timeout wrapper without kill_on_drop" — fails.
# Function bodies are bounded by `^func ` / `^}`, so sibling functions with
# byte-identical builders cannot alias (the s451 trap).
#
# pkg.go/safecmd's systemd-run-backed Unsandboxed runner (cancelling ctx kills
# only the LOCAL systemd-run waiter, not the transient unit) remains out of
# scope, as before.
#
# These are SOURCE pins (plus `go test` for §A) and need no running panel.
#   run: bash tests/timeout-orphan-kill-on-drop-pin-e2e.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GA="$REPO/panel/go/internal/agent"
GIT_BUILD_SVC="$GA/services/git_build.go"
DEPLOY_SVC="$GA/services/deploy.go"
BACKUPS_SVC="$GA/services/backups.go"
REMOTE_BACKUP_SVC="$GA/services/remote_backup.go"
DATABASE_BACKUP_SVC="$GA/services/database_backup.go"
MAIL_ROUTE="$GA/routes/mail.go"
WORDPRESS_SVC="$GA/services/wordpress.go"
WORDPRESS_ROUTE="$GA/routes/wordpress.go"
BACKUPS_ROUTE="$GA/routes/backups.go"
SAFE_CMD="$GA/safecmd/safecmd.go"

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# One Go function's body (from `func Name(` / `func (r T) Name(` to its column-0 `}`).
fnbody() {
  awk -v fn="$2" 'index($0, "func " fn "(") == 1 || $0 ~ ("^func \\([^)]*\\) " fn "[(]") {f=1} f {print} f && /^}/ {exit}' "$1" 2>/dev/null
}

# The call that carries ANCHOR (the anchor may sit on a continuation line, so
# the three lines before it are part of the window) must reach the child
# through a deadline: a runner handed a non-zero timeout, or a safecmd call /
# `run(` closure whose enclosing function called context.WithTimeout earlier.
siteIsBounded() {
  local file="$1" anchor="$2" label="$3" res
  if [ ! -f "$file" ]; then bad "$label ($file does not exist)"; return; fi
  res=$(awk -v anchor="$anchor" '
    /^func / { wt = 0; b1 = b2 = b3 = "" }
    index($0, "context.WithTimeout(") { wt = 1 }
    index($0, anchor) { printf "%s\t%s %s %s %s\n", (wt ? "WT" : "NOWT"), b3, b2, b1, $0; found = 1; exit }
    { b3 = b2; b2 = b1; b1 = $0 }
  ' "$file")
  if [ -z "$res" ]; then
    bad "$label (anchor not found — re-scope this pin)"
  elif grep -cE 'deployRun\(ctx, [1-9][0-9]*\*time\.Second|backupsRun\(([1-9][0-9]*\*time\.Second|timeout),' <<< "$res" >/dev/null; then
    ok "$label"
  elif grep -cE '^WT	.*(safecmd\.(Exec|Command)\(ctx, |run\("wp )' <<< "$res" >/dev/null; then
    ok "$label"
  else
    bad "$label"
  fi
}

# A body must create a deadline ctx and build every named child on it.
bodyBuildsOnDeadline() {
  local body="$1" label="$2"; shift 2
  if [ -z "$body" ]; then bad "$label (could not isolate the function body — re-scope this pin)"; return; fi
  if ! grep -cE 'ctx, cancel :?= context\.WithTimeout\(' <<< "$body" >/dev/null; then bad "$label (no context.WithTimeout)"; return; fi
  local pat
  for pat in "$@"; do
    if ! grep -cE -- "$pat" <<< "$body" >/dev/null; then bad "$label (missing: $pat)"; return; fi
  done
  ok "$label"
}

echo "== A. the Go kill_on_drop: safecmd.Command is exec.CommandContext, and an expired ctx really kills the child =="
if fnbody "$SAFE_CMD" Command | grep -c 'exec\.CommandContext(ctx, binary, args\.\.\.)' >/dev/null; then
  ok "safecmd.Command builds with exec.CommandContext — the ctx's deadline is what stops the child"
else
  bad "safecmd.Command no longer uses exec.CommandContext — no ctx timeout below kills anything"
fi
if (cd "$REPO/panel/go" && go test ./internal/agent/safecmd/ -count=1 \
      -run '^(TestPinTimeoutOrphanKillOnDropKillsTheChild|TestRunReportsExitCodeAndTimeout)$' >/dev/null 2>&1); then
  ok "a child whose ctx expires is SIGKILLed and reaped, not orphaned (TestPinTimeoutOrphanKillOnDropKillsTheChild)"
else
  bad "TestPinTimeoutOrphanKillOnDropKillsTheChild fails — a timed-out child keeps running"
fi
bodyBuildsOnDeadline "$(fnbody "$DEPLOY_SVC" deployRun)" \
  "deployRun (git_build.go + deploy.go's runner) wraps its ctx in context.WithTimeout and builds on it" \
  'safecmd\.Command\(ctx, bin, args\.\.\.\)'
bodyBuildsOnDeadline "$(fnbody "$BACKUPS_SVC" backupsRun)" \
  "backupsRun (backups.go + remote_backup.go's runner) wraps its ctx in context.WithTimeout and builds on it" \
  'safecmd\.Exec\(ctx, bin, args\.\.\.\)'

echo
echo "== B. git_build.go GitBuildCloneOrPull: both network legs are deadline-bounded =="
siteIsBounded "$GIT_BUILD_SVC" '"fetch", "origin", branch)' \
  "git_build.go's git fetch (pull branch) runs under a timeout that kills it"
siteIsBounded "$GIT_BUILD_SVC" '"clone", "--branch", branch, "--single-branch", "--depth", "50", repoURL, repoDir)' \
  "git_build.go's git clone (fresh-clone branch) runs under a timeout that kills it"

echo
echo "== C. deploy.go's OWN, independent DeployCloneOrPull: both network legs are deadline-bounded =="
siteIsBounded "$DEPLOY_SVC" 'deployGit("-C", siteDir, "fetch", "origin", branch)' \
  "deploy.go's git fetch (pull branch) runs under a timeout that kills it"
siteIsBounded "$DEPLOY_SVC" 'deployGit("clone", "--branch", branch, "--single-branch", "--depth", "50", repoURL, staging)' \
  "deploy.go's git clone (fresh-clone branch) runs under a timeout that kills it"

echo
echo "== D. backups.go: the staged tar under its 300s timeout is deadline-bounded =="
siteIsBounded "$BACKUPS_SVC" 'backupsRun(300*time.Second, "tar", tarArgs...)' \
  "backups.go's tar czf runs under a timeout that kills it"

echo
echo "== E. remote_backup.go: remoteBackupS3Curl (the one runner behind test/list/delete/upload) is deadline-bounded =="
siteIsBounded "$REMOTE_BACKUP_SVC" 'backupsRun(timeout, "curl", full...)' \
  "remote_backup.go's S3 curl runs under a timeout that kills it"

echo
echo "== F. database_backup.go: all 9 privileged child-process builders are deadline-bounded =="
# The Go port shares one pipe helper per direction, so the four mysql/postgres
# functions are pinned as (a) each routes through its helper with its own
# client argv, (b) each helper builds BOTH children on its deadline ctx.
PD=$(fnbody "$DATABASE_BACKUP_SVC" databaseBackupPipedDump)
PR=$(fnbody "$DATABASE_BACKUP_SVC" databaseBackupPipedRestore)
bodyBuildsOnDeadline "$PD" "the dump pipe's docker exec is built on the dump deadline" 'safecmd\.Command\(ctx, "docker", '
bodyBuildsOnDeadline "$PD" "the dump pipe's gzip is built on the dump deadline" 'safecmd\.Command\(ctx, "gzip"\)'
bodyBuildsOnDeadline "$PR" "the restore pipe's gunzip is built on the restore deadline" 'safecmd\.Command\(ctx, "gunzip", '
bodyBuildsOnDeadline "$PR" "the restore pipe's docker exec is built on the restore deadline" 'safecmd\.Command\(ctx, "docker", '
for pair in 'DatabaseBackupDumpMysql|databaseBackupPipedDump\(|"mariadb-dump"' \
            'DatabaseBackupDumpPostgres|databaseBackupPipedDump\(|"--no-owner", "--no-acl", "--clean", "--if-exists"' \
            'DatabaseBackupRestoreMysql|databaseBackupPipedRestore\(|"mariadb", "-u", user, dbName' \
            'DatabaseBackupRestorePostgres|databaseBackupPipedRestore\(|"psql", "-v", "ON_ERROR_STOP=1", "--single-transaction", "-U", user, "-d", dbName'; do
  fn=${pair%%|*}; rest=${pair#*|}; helper=${rest%%|*}; argv=${rest#*|}
  B=$(fnbody "$DATABASE_BACKUP_SVC" "$fn")
  if [ -n "$B" ] && grep -cE -- "$helper" <<< "$B" >/dev/null && grep -cF -- "$argv" <<< "$B" >/dev/null; then
    ok "$fn's child processes go through the deadline-bounded pipe helper"
  else
    bad "$fn no longer routes its client through the deadline-bounded pipe helper — re-scope this pin"
  fi
done
bodyBuildsOnDeadline "$(fnbody "$DATABASE_BACKUP_SVC" DatabaseBackupRestoreMongo)" \
  "DatabaseBackupRestoreMongo's docker exec (mongorestore) is built on its deadline" \
  'safecmd\.Command\(ctx, "docker", "exec", "-i", containerName,' '"mongorestore", "--db", dbName, "--archive", "--gzip", "--drop"'

echo
echo "== G. mail.go: the mailbox backup/restore tar children are deadline-bounded (inlined in a route handler) =="
siteIsBounded "$MAIL_ROUTE" '"tar", "czf", file,' \
  "mail.go's mailMailboxBackup tar czf runs under a timeout that kills it"
siteIsBounded "$MAIL_ROUTE" '"tar", "xzf", file, "-C", maildir)' \
  "mail.go's mailMailboxRestore tar xzf runs under a timeout that kills it"

echo
echo "== H. wordpress.go: the single wp-cli choke point + its own 5 other subprocess sites are deadline-bounded =="
siteIsBounded "$WORDPRESS_SVC" 'safecmd.Exec(ctx, wordpressWpCli, argv...)' \
  "wordpress.go's WordpressWpAtRoot (the single wp-cli choke point) runs under a timeout that kills it"
siteIsBounded "$WORDPRESS_SVC" '"--dbname="+dbName' \
  "wordpress.go's WordpressInstall wp config create runs under a timeout that kills it"
siteIsBounded "$WORDPRESS_SVC" '"--admin_password="+adminPass' \
  "wordpress.go's WordpressInstall wp core install runs under a timeout that kills it"
siteIsBounded "$WORDPRESS_SVC" '"tar", "czf", snapshotPath, "-C", "/var/www"' \
  "wordpress.go's update snapshot tar czf runs under a timeout that kills it"
siteIsBounded "$WORDPRESS_SVC" '"tar", "xzf", snapshotPath, "-C", "/var/www"' \
  "wordpress.go's WordpressRollbackFromSnapshot tar xzf runs under a timeout that kills it"
siteIsBounded "$WORDPRESS_SVC" '"-u", "www-data", wordpressWpCli, "eval"' \
  "wordpress.go's WordpressHealthCheck sudo wp-cli eval runs under a timeout that kills it"

echo
echo "== J. backups.go (services): the 4 sibling tar sites are deadline-bounded =="
siteIsBounded "$BACKUPS_SVC" '"xzf", archive,' \
  "backups.go's backupsExtractPayload tar xzf runs under a timeout that kills it"
siteIsBounded "$BACKUPS_SVC" '"--exclude", BackupsPayloadDir,' \
  "backups.go's restore tar xzf (into the live webroot) runs under a timeout that kills it"
siteIsBounded "$BACKUPS_SVC" '"tar", "tzf", fpath)' \
  "backups.go's list-files tar tzf runs under a timeout that kills it"
siteIsBounded "$BACKUPS_SVC" '"xzf", backupPath,' \
  "backups.go's restore-single-file tar xzf (into the live webroot) runs under a timeout that kills it"

echo
echo "== K. routes/backups.go: the post-restore chown no longer hands the application .git =="
CRT=$(fnbody "$BACKUPS_ROUTE" backupsChownRestoredTree)
if [ -n "$CRT" ] && grep -c 'e.Name() == ".git"' <<< "$CRT" >/dev/null && grep -c '"chown", "-R", "root:root", gitDir' <<< "$CRT" >/dev/null; then
  ok "routes/backups.go defines backupsChownRestoredTree, and it names .git explicitly (skips it in the www-data chown, re-secures it to root)"
else
  bad "routes/backups.go's backupsChownRestoredTree is missing or no longer handles .git — re-scope this pin"
fi
if grep -c 'backupsChownRestoredTree("/var/www/" + domain)' "$BACKUPS_ROUTE" >/dev/null 2>&1; then
  ok "restore calls backupsChownRestoredTree instead of a blanket chown -R"
else
  bad "restore no longer visibly calls backupsChownRestoredTree — re-scope this pin"
fi

echo
echo "== I. reachability: the routes that reach every fixed site still exist =="
if grep -q 'services\.GitBuildCloneOrPull(' "$GA/routes/git_build.go" 2>/dev/null; then
  ok "routes/git_build.go still reaches GitBuildCloneOrPull"
else
  bad "routes/git_build.go no longer visibly reaches GitBuildCloneOrPull — re-scope this pin"
fi
if grep -q 'services\.DeployCloneOrPull(' "$GA/routes/deploy.go" 2>/dev/null; then
  ok "routes/deploy.go still reaches its own DeployCloneOrPull"
else
  bad "routes/deploy.go no longer visibly reaches DeployCloneOrPull — re-scope this pin"
fi
if grep -qE 'services\.DatabaseBackup(Dump|Restore)(Mysql|Postgres|Mongo)\(' "$GA/routes/database_backup.go" 2>/dev/null; then
  ok "routes/database_backup.go still reaches the dump/restore functions"
else
  bad "routes/database_backup.go no longer visibly reaches the dump/restore functions — re-scope this pin"
fi
if grep -q '"POST /mail/backup", mailMailboxBackup' "$MAIL_ROUTE" 2>/dev/null && grep -q '"POST /mail/restore", mailMailboxRestore' "$MAIL_ROUTE" 2>/dev/null; then
  ok "mail.go's route table still registers /mail/backup and /mail/restore"
else
  bad "mail.go's route table no longer visibly registers /mail/backup or /mail/restore — re-scope this pin"
fi
if grep -q '"POST /wordpress/{domain}/install"' "$WORDPRESS_ROUTE" 2>/dev/null \
  && grep -q '"POST /wordpress/{domain}/update-with-rollback"' "$WORDPRESS_ROUTE" 2>/dev/null \
  && grep -q '"POST /wordpress/{domain}/harden"' "$WORDPRESS_ROUTE" 2>/dev/null; then
  ok "wordpress.go's route table still registers install, update-with-rollback, and harden"
else
  bad "wordpress.go's route table no longer visibly registers install, update-with-rollback, or harden — re-scope this pin"
fi
if grep -q '"GET /backups/{domain}/browse/{filename}"' "$BACKUPS_ROUTE" 2>/dev/null \
  && grep -q '"POST /backups/{domain}/restore-file/{filename}"' "$BACKUPS_ROUTE" 2>/dev/null; then
  ok "routes/backups.go's route table still registers browse and restore-file"
else
  bad "routes/backups.go's route table no longer visibly registers browse or restore-file — re-scope this pin"
fi
echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
