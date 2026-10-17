#!/usr/bin/env bash
# cli-io-crate-audit-pin-e2e.sh — s462
#
# The Rust CLI's commands/{db.rs, backup.rs, iac.rs} (now
# panel/go/internal/cli/{db.go, backup.go, iac.go}) — the 3 files the s461
# dockpanel-fanout explicitly excluded ("already partially checked" — true
# only for the s440/441 CWE-214 pass). A full finder/skeptic/critics run
# this session found 7 real, independently-verified defects across those
# 3 files plus one off-menu completeness-critic find:
#
#   §A db.rs `rand_byte()` silently returned 0 on /dev/urandom failure —
#      would produce the fully predictable password "aaaaaaaaaaaaaaaa" for
#      a real database with no error surfaced anywhere.
#   §B backup.rs `cmd_backup_verify`'s database lane hardcoded
#      `db_type: "postgres"` — a mysql/mariadb backup could never be
#      successfully verified through the CLI; it always attempted (and
#      failed) a Postgres restore against it.
#   §C backup.rs `cmd_backup_health` folded every top-level entry under
#      /var/backups/dockpanel into "site backups", including the agent's
#      own databases/volumes/wp-snapshots/snapshots roots and an unrelated
#      ops db/ dump directory — live-reproduced ~9x/~50000x off on this box.
#   §D iac.rs `cmd_apply` silently dropped every firewall rule in an
#      exported file — no create, no update, no message, ever.
#   §E iac.rs `cmd_apply` silently no-op'd `ssl: true` when no --email was
#      given — site creation still printed a bare success tick.
#   §F iac.rs `cmd_apply --dry-run` unconditionally reported every cron as
#      "to create", even when byte-identical to what's already scheduled —
#      the one resource type that DOES reconcile on a real apply, so the
#      dry-run plan was actively wrong, not just incomplete.
#   §G (off-menu, completeness critic) agent/services/remote_backup.rs's
#      `run_sftp()` had no `kill_on_drop(true)` — its sibling `s3_curl()`,
#      ~280 lines earlier in the SAME file, already carried this exact fix
#      (v2.204.0) for the same reason: a timed-out/dropped future otherwise
#      leaves sftp/sshpass running detached against the remote host.
#
# Go port names: randByte (db.go), cmdBackupVerify / cmdBackupHealth /
# isSiteBackupDir / countFiles (backup.go), cmdApply (iac.go), the --db-type
# flag in cli.go, and agent services/remote_backup.go's remoteBackupRunSftp /
# remoteBackupS3Curl, where kill_on_drop(true) becomes "the child runs under
# a timeout context" (safecmd.Command(ctx, ...) / backupsRun).
#
# Read-only display/plan-time paths mostly; the one behavior change beyond
# messaging is db_type now being a real, caller-supplied value instead of
# a hardcoded literal, and rand_byte's caller now handling failure instead
# of silently proceeding with a zero byte.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=================================================="
echo "  CLI/agent io-crate audit — source pins (s462)"
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
flat()   { tr -s '[:space:]' ' ' <<< "$1"; }

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

CLI=panel/go/internal/cli
DB=$CLI/db.go
DB_C=$(code "$DB")
BACKUP=$CLI/backup.go
BACKUP_C=$(code "$BACKUP")
IAC=$CLI/iac.go
IAC_C=$(code "$IAC")
MAIN=$CLI/cli.go
MAIN_C=$(code "$MAIN")
SVC=panel/go/internal/agent/services
REMOTE_BACKUP=$SVC/remote_backup.go
REMOTE_BACKUP_C=$(code "$REMOTE_BACKUP")
BACKUPS_C=$(code "$SVC/backups.go")

for f in "$DB" "$BACKUP" "$IAC" "$MAIN" "$REMOTE_BACKUP"; do [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"; done

RAND_BYTE_BODY=$(fnbody "$DB_C" "randByte")
VERIFY_BODY=$(fnbody "$BACKUP_C" "cmdBackupVerify")
HEALTH_BODY=$(fnbody "$BACKUP_C" "cmdBackupHealth")
APPLY_BODY=$(fnbody "$IAC_C" "cmdApply")
SFTP_BODY=$(fnbody "$REMOTE_BACKUP_C" "remoteBackupRunSftp")
S3_CURL_BODY=$(fnbody "$REMOTE_BACKUP_C" "remoteBackupS3Curl")
BACKUPS_RUN_BODY=$(fnbody "$BACKUPS_C" "backupsRun")

# ── §A db.go randByte no longer silently zero-fallbacks ─────────────────
echo "── §A db.go: randByte surfaces /dev/urandom failure instead of returning 0 ──"

if has "$RAND_BYTE_BODY" '^func randByte\(\) \(byte, error\)'; then
  ok "A1 randByte's signature returns (byte, error), not a bare byte"
else
  bad "A1 randByte no longer returns (byte, error) — a failure has nowhere to go but silent 0"
fi

# Both failure points (open, read) must return a non-nil error; no path may
# hand back 0 with a nil error.
ERR_RETURNS=$(grep -cE 'return 0, fmt\.Errorf\(' <<< "$RAND_BYTE_BODY")
if [ "$ERR_RETURNS" -ge 2 ] && lacks "$RAND_BYTE_BODY" 'return 0, nil|_, _ = |, _ := os\.Open|_ = io\.ReadFull'; then
  ok "A2 randByte returns an error from both the open and the read failure — no silent swallow"
else
  bad "A2 randByte swallows an open/read failure again (error returns found: $ERR_RETURNS)"
fi

IAC_PW_LOOP=$(grep -A4 'b, err := randByte()' <<< "$APPLY_BODY")
if has "$IAC_PW_LOOP" 'if err != nil \{' && has "$APPLY_BODY" 'failed to generate a random password'; then
  ok "A3 iac.go's password-generation loop handles randByte's error and reports it"
else
  bad "A3 iac.go's password loop does not handle randByte's error — still assumes it can't fail"
fi

# ── §B backup.go cmdBackupVerify: db_type is a real parameter ───────────
echo "── §B backup.go: cmdBackupVerify's db_type is caller-supplied, not hardcoded ──"

if has "$VERIFY_BODY" '^func cmdBackupVerify\([^)]*dbType string\)'; then
  ok "B1 cmdBackupVerify takes a dbType parameter"
else
  bad "B1 cmdBackupVerify has no dbType parameter — still hardcoded"
fi

if [ -n "$VERIFY_BODY" ] && lacks "$VERIFY_BODY" '"db_type": "postgres"'; then
  ok "B2 the database-verify body no longer hardcodes db_type to postgres"
else
  bad "B2 still sends a hardcoded postgres db_type — mysql/mariadb verify still always fails"
fi

if has "$VERIFY_BODY" '"db_type": dbType'; then
  ok "B3 the database-verify body forwards the real db_type value"
else
  bad "B3 the database-verify body does not forward db_type"
fi

MAIN_FLAT=$(flat "$MAIN_C")
if has "$MAIN_FLAT" '\{long: "db-type", def: "postgres", help: "Database type, only used when --type database' \
  && has "$MAIN_FLAT" 'cmdBackupVerify\(c\.token, c\.str\("type"\), c\.args\[0\], c\.args\[1\], c\.str\("db-type"\)\)'; then
  ok "B4 cli.go declares --db-type on backup verify and threads it through dispatch"
else
  bad "B4 cli.go does not wire a db-type flag through to cmdBackupVerify"
fi

# ── §C backup.go cmdBackupHealth: scoped to real site-backup dirs ───────
echo "── §C backup.go: cmdBackupHealth excludes non-site subsystem directories ──"

# C1 retired: covered by TestPinCliIoCrateAuditSiteBackupDirs (panel/go/internal/cli/pin_cli_io_crate_audit_test.go)
# C2 retired: covered by TestPinCliIoCrateAuditSiteBackupDirs (panel/go/internal/cli/pin_cli_io_crate_audit_test.go)
# C3 retired: covered by TestPinCliIoCrateAuditSiteBackupDirs (panel/go/internal/cli/pin_cli_io_crate_audit_test.go)

if has "$HEALTH_BODY" 'countFiles\(backupRoot, true\)' && has "$HEALTH_BODY" 'countDirs\(backupRoot, true\)'; then
  ok "C4 the site-backup file and dir counts pass onlySiteDirs=true"
else
  bad "C4 the site-backup counts do not scope to onlySiteDirs"
fi

# Positive controls: databases/ and volumes/ counts were never polluted by
# this bug (they scan their own already-scoped root) and must stay unscoped.
if has "$HEALTH_BODY" 'countFiles\(backupRoot\+"/databases", false\)' \
  && has "$HEALTH_BODY" 'countFiles\(backupRoot\+"/volumes", false\)'; then
  ok "C5 (control) databases/volumes counts remain unscoped — they were never the bug"
else
  bad "C5 (control) databases/volumes count scoping regressed"
fi

# ── §D iac.go cmdApply: firewall is no longer a silent no-op ────────────
echo "── §D iac.go: cmdApply surfaces that firewall rules are export-only ──"

if has "$APPLY_BODY" 'm\["firewall"\]'; then
  ok "D1 cmdApply inspects the desired firewall section"
else
  bad "D1 cmdApply never reads desired[\"firewall\"] at all"
fi

if has "$APPLY_BODY" 'does not create, update, or remove firewall rules'; then
  ok "D2 cmdApply prints an explicit firewall-not-applied warning"
else
  bad "D2 no firewall-not-applied warning found — still silent"
fi

# ── §E iac.go cmdApply: ssl-with-no-email is no longer a silent no-op ───
echo "── §E iac.go: cmdApply warns when ssl requested but no --email given ──"

if has "$APPLY_BODY" 'no --email was given'; then
  ok "E1 cmdApply warns when ssl:true has no email to provision with"
else
  bad "E1 cmdApply still silently no-ops an ssl request with no --email"
fi

# ── §F iac.go cmdApply --dry-run: crons are diffed, not all-create ──────
echo "── §F iac.go: dry-run cron plan diffs against current state ──"

if has "$APPLY_BODY" 'currentCrons'; then
  ok "F1 cmdApply builds a currentCrons lookup from /iac/export's own current state"
else
  bad "F1 no currentCrons lookup — dry-run still has nothing to diff against"
fi

if has "$APPLY_BODY" 'already exists, unchanged'; then
  ok "F2 an unchanged cron is reported as existing, not \"to create\""
else
  bad "F2 dry-run still cannot report an unchanged cron as anything but \"to create\""
fi

# ── §G remote_backup.go: the sftp child dies with its timeout ───────────
echo "── §G agent remote_backup.go: remoteBackupRunSftp no longer orphans its child on timeout ──"

# kill_on_drop(true) → the child is started under a timeout context, so the
# deadline kills sftp/sshpass instead of leaving it running detached.
if has "$SFTP_BODY" 'ctx, cancel := context\.WithTimeout\(context\.Background\(\), timeout\)' \
  && has "$SFTP_BODY" 'safecmd\.Command\(ctx, prog, finalArgs\.\.\.\)'; then
  ok "G1 remoteBackupRunSftp runs sftp/sshpass via safecmd.Command under its timeout ctx"
else
  bad "G1 remoteBackupRunSftp's child is not bound to its timeout ctx — a timed-out transfer orphans sftp/sshpass"
fi

# Positive control: the sibling s3 curl fix (v2.204.0) must still be there.
if has "$S3_CURL_BODY" 'backupsRun\(timeout, "curl",' \
  && has "$BACKUPS_RUN_BODY" 'context\.WithTimeout\(context\.Background\(\), timeout\)' \
  && has "$BACKUPS_RUN_BODY" 'safecmd\.Exec\(ctx,'; then
  ok "G2 (control) remoteBackupS3Curl's curl still runs under a timeout ctx (backupsRun)"
else
  bad "G2 (control) remoteBackupS3Curl's timeout-kill regressed"
fi

echo
echo "=================================================="
echo "  PASS=$PASS FAIL=$FAIL"
echo "=================================================="

[ "$FAIL" -eq 0 ]
