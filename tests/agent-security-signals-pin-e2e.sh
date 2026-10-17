#!/usr/bin/env bash
# agent-security-signals-pin-e2e.sh — s330 / v2.88.0
#
# THE SENTENCE THIS SUITE EXISTS TO PROVE, written out so a mutation can be aimed
# at it rather than at whatever the arms happen to catch:
#
#   "The agent's security controls must not answer with silence: a backup of the
#    panel database is readable only by root, an input line is judged the same
#    whatever WebSocket frame shape carried it, a REFUSED command is reported,
#    a failed privilege drop never reaches execv, and 'no SSH keys' means the
#    agent LOOKED and found none."
#
# THE DEFECTS. Four, all realized, all measured on the demo box at v2.87.0:
#
#  1. `/var/backups/dockpanel` was 0755 and every writer's redirect left the dumps
#     0644. 17 of 17 files were readable as www-data — the uid EVERY hosted site's
#     PHP runs as — and the newest was a full pg_dump carrying `servers.agent_token`
#     in cleartext. That token is the Bearer credential for every agent endpoint
#     AND the HMAC key the agent verifies its own root-PTY tickets with. A web
#     shell on any hosted site was therefore root on the panel host and on every
#     server it manages.
#  2. Terminal input was reconstructed and classified inside the `{"type":"input"}`
#     arm only. The raw-text arm ran the BLOCK half and only for site terminals,
#     so a scripted client — the only kind that sends raw frames, since Terminal.tsx
#     sends JSON at all seven senders — produced ZERO intrusion signal, on a ROOT
#     shell. Measured: JSON frame -> 1 event, raw frame -> 0, same command.
#  3. A REFUSED command `break`s before the classifier, so the strongest thing the
#     product can observe reached nothing but the agent's own journal.
#  4. `list_ssh_keys` (now serverUtilsListSSHKeys) read /root/.ssh/authorized_keys with an in-process
#     `read_to_string(...).unwrap_or_default()` while the unit's `ProtectHome=yes`
#     binds an inaccessible dir over /root. It answered 200 with an EMPTY LIST on a
#     box with three live root keys — a false all-clear, on every install, since the
#     handlers landed (2026-03-15) the day after ProtectHome did (2026-03-13).
#
# So the mutations this suite must survive are RE-SILENCING mutations — put the
# classifier back behind one frame shape, let a refusal fall through, discard a
# read error, loosen a mode — not deletions. Every arm below was mutation-tested
# to redden ALONE, and every arm was run against v2.87.0 in a git worktree and
# required to be RED there.
#
#   §A  a backup of the panel database is root-only
#   §B  input is judged the same whatever frame shape carried it
#   §C  a refusal is reported, and does NOT arm the auto-lockdown
#   §D  the root shell's environment and privilege drop survive to execv
#   §E  "no SSH keys" means the agent looked
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

# The Go port (panel/go). Behaviour that a test can call directly is pinned by
# Go tests now; the arms left here are the WIRING a unit test cannot see.
TERM_RS=panel/go/internal/agent/routes/terminal.go
BACKUPS=panel/go/internal/agent/services/backups.go
MAIN_RS=panel/go/cmd/dockpanel-agent/main.go
SEC_RS=panel/go/internal/agent/routes/security.go
UTILS=panel/go/internal/agent/routes/server_utils.go
HEALER=panel/go/internal/api/svc_auto_healer.go
SETUP=scripts/setup.sh
UPDATE=scripts/update.sh

for f in "$TERM_RS" "$BACKUPS" "$MAIN_RS" "$SEC_RS" "$UTILS" "$HEALER" "$SETUP" "$UPDATE"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT. Copied from the FIXED stripper (lesson #136): a bare
# `s{/\*.*?\*/}{}gs` deleted real code whenever a string literal contained `/*`,
# and an ABSENCE arm then passed on code the stripper had merely removed.
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
flat()  { tr '\n\t' '  ' <<< "$1" | tr -s ' '; }  # Go indents with tabs
# One function's body, bounded by its OWN closing brace in column 0.
fn_body() { awk -v pat="$1" '$0 ~ pat {f=1} f {print} f && /^\}/ {exit}' <<< "$2"; }

TERM_S=$(subj "$TERM_RS" || true)
BACKUPS_S=$(subj "$BACKUPS" || true)
UTILS_S=$(subj "$UTILS" || true)
HEALER_S=$(subj "$HEALER" || true)

echo "§A  a backup of the panel database is root-only"

# A1 — the retrofit exists and runs at startup. Fixing only the writers would
# leave every install that ALREADY holds a backup exposed for ever, which is the
# s280 install-template delivery shape.
if [ -z "$BACKUPS_S" ]; then
  bad "A1 SKIPPED: $BACKUPS did not yield source"
elif has "$BACKUPS_S" '^func BackupsSecureBackupTree\(\)' && has "$(subj "$MAIN_RS")" 'services\.BackupsSecureBackupTree\(\)'; then
  ok "A1 the backup tree is re-secured at every agent start, so existing installs are repaired"
else
  bad "A1 nothing repairs a backup tree that is already world-readable — new writes alone do not reach an existing install"
fi

# A2 retired: covered by TestAWorldReadableBackupTreeIsRepaired (panel/go/internal/agent/services/backups_test.go)
# A3 retired: covered by TestSecureTreeDoesNotFollowASymlinkOutOfTheTree (panel/go/internal/agent/services/backups_test.go)
if (cd panel/go && go test ./internal/agent/services/ -count=1 \
      -run '^(TestAWorldReadableBackupTreeIsRepaired|TestSecureTreeDoesNotFollowASymlinkOutOfTheTree)$' >/dev/null 2>&1); then
  ok "A2/A3 the Go tests pinning 0700/0600 and the symlink refusal pass"
else
  bad "A2/A3 the backup-tree Go tests fail — the modes or the symlink guard regressed"
fi

# A4 — EVERY writer, not just the one that was found first. Three produce these
# files: this agent, the panel's auto-healer, and the root crontab line setup.sh
# installs. A fix to one instance of a pattern owes a grep for the pattern.
# ⚠ A4c/A4d ARE SCOPED TO THE BACKUP BLOCK, NOT TO THE FILE. The first draft
# grepped each script file-wide for `umask 077` — and setup.sh ALREADY contained
# three, all guarding `mktemp` calls, so A4c printed GREEN at v2.87.0 over a
# backup cron that wrote 0644. It was a false green hiding inside a batch of
# nineteen reds, where attention goes to the reds (s302). The window below is
# anchored on the block's own BACKUP_DIR assignment, and an empty extraction
# FAILS rather than passes.
# ⚠ TWO correct spellings, and which one is correct depends on the file.
#
# In setup.sh the umask sits inside the `cat > "$BACKUP_SCRIPT" <<'BKEOF'`
# heredoc — a standalone child script, where a bare top-level `umask 077` is
# right and governs only that script.
#
# In update.sh a BARE umask is the REGRESSION, not the fix: v2.88.0 set it at
# top-level scope in an 1100-line installer, so it governed every later `mkdir`
# and redirect and would have created /opt/dockpanel/frontend and the ACME
# challenge directory 0700. s331 scoped it into the subshell that performs the
# dump redirect, which moved this arm's subject (lesson #150 — let the arm
# follow the code). Both forms are accepted here because both protect the dump;
# that a bare one in update.sh is separately FORBIDDEN is pinned by
# upgrade-reach-pin-e2e.sh §A, which is the arm that owns that distinction.
# ⚠ The window is bounded by the OPERATION, not by a line count. It used to be
# `grep -B 6 -A 12` around the BACKUP_DIR assignment, and s331 pushed update.sh's
# dump past +12 simply by documenting the fix above it — so the arm reported the
# dump unprotected while it was protected on the very next line. A fixed -A n
# window is not a block (lesson #172); it silently stops measuring its subject
# the moment anyone writes a comment.
umask_near_backup_block() {
  local f="$1" win
  # From the backup block's own start to the dump it performs, inclusive.
  # Backward context stays a small fixed count — in setup.sh's generated script
  # the umask is the line immediately BEFORE the assignment, and that adjacency
  # is structural. Only the FORWARD span is operation-bounded, because that is
  # the direction commentary grows in.
  win=$( { grep -B 8 -- 'BACKUP_DIR="/var/backups/dockpanel/db"' "$f" 2>/dev/null || true
           awk '/BACKUP_DIR="\/var\/backups\/dockpanel\/db"/{inside=1}
                inside{print}
                inside && /pg_dump/{exit}' "$f"; } )
  [ -n "$win" ] || return 2
  grep -qE 'pg_dump' <<< "$win" || return 2
  grep -qE '^\s*umask 077\s*$|umask 077; docker exec' <<< "$win"
}
A4=0
has "$(flat "$(fn_body '^func securityDbBackup[(]' "$(subj "$SEC_RS")")")" 'os\.OpenFile\(filename, [^)]*0o600\)' || { bad "A4a the agent's own /security/db-backup still creates the dump with the default mode"; A4=1; }
has "$(flat "$HEALER_S")" 'umask 077; docker exec dockpanel-postgres pg_dump' || { bad "A4b the panel's auto-healer dump still lands 0644 (the > redirect creates 0666 \& ~umask)"; A4=1; }
umask_near_backup_block "$SETUP"; case $? in
  0) ;;
  2) bad "A4c could not find the backup block in $SETUP — the reader is broken, not the tree"; A4=1 ;;
  *) bad "A4c setup.sh's installed backup cron still writes a world-readable dump"; A4=1 ;;
esac
umask_near_backup_block "$UPDATE"; case $? in
  0) ;;
  2) bad "A4d could not find the backup block in $UPDATE — the reader is broken, not the tree"; A4=1 ;;
  *) bad "A4d update.sh's pre-upgrade dump still lands world-readable"; A4=1 ;;
esac
[ "$A4" -eq 0 ] && ok "A4 all four writers (agent, auto-healer, setup.sh cron, update.sh) create the dump root-only"

echo "§B  input is judged the same whatever frame shape carried it"

# B1 — THE ARM THAT MATTERS. There is ONE reconstruct-and-classify path and BOTH
# input arms reach it. A unit test cannot assert this: it calls
# terminalObserveInput directly and would stay green with an arm reverted to its
# own inline loop. In Go the one path is the `forward` closure, and both the
# raw-text arm and the {"type":"input"} arm must call it.
if [ -z "$TERM_S" ]; then
  bad "B1 SKIPPED: $TERM_RS did not yield source"
else
  N=$(count "$TERM_S" '!forward\((text|data)\)')
  FWD=$(awk '/forward := func\(data string\) bool \{/{f=1} f{print} f && /^\t\}$/{exit}' <<< "$TERM_S")
  if [ "$N" -eq 2 ] && has "$FWD" 'terminalObserveInput\(data, '; then
    ok "B1 both the JSON-frame arm and the raw-text arm go through the one terminalObserveInput path"
  else
    bad "B1 $N of 2 input arms call forward (or forward no longer classifies) — a frame shape is being classified differently again, which is the v2.87.0 defect"
  fi
fi

# B2 retired: covered by TestTerminalARootShellIsObservedToo (panel/go/internal/agent/routes/terminal_test.go)
# B3 retired: covered by TestTerminalTheBlockHalfIsStillSiteOnly (panel/go/internal/agent/routes/terminal_test.go)
if (cd panel/go && go test ./internal/agent/routes/ -count=1 \
      -run '^(TestTerminalARootShellIsObservedToo|TestTerminalTheBlockHalfIsStillSiteOnly|TestTerminalFrameShapeDoesNotChangeWhatIsObserved|TestTerminalARefusedCommandIsReported)$' >/dev/null 2>&1); then
  ok "B2/B3 the Go tests pinning the ungated suspicious half and the site-only block half pass"
else
  bad "B2/B3 the terminal observation Go tests fail"
fi

echo "§C  a refusal is reported, and does NOT arm the auto-lockdown"

# C1 — a refused command reaches the panel's intrusion channel at all. It used to
# `break` before the classifier and produce one tracing::warn on a target with no
# consumer outside the agent's own journal.
if [ -z "$TERM_S" ]; then
  bad "C1 SKIPPED: $TERM_RS did not yield source"
elif has "$TERM_S" 'terminalWriteSuspiciousEvent\("terminal\.blocked_command"'; then
  ok "C1 a refused command is written to the panel's intrusion channel, not only to the journal"
else
  bad "C1 a REFUSED command is still reported to nobody — the strongest observation the product can make is silent"
fi

# C2 — and it is a DISTINCT event type, because the ingest must be able to tell
# the two apart. Keyed on the property (two different type strings reach the
# writer), not on one literal.
if [ -z "$TERM_S" ]; then
  bad "C2 SKIPPED: $TERM_RS did not yield source"
else
  N=$(count "$TERM_S" 'terminalWriteSuspiciousEvent\("terminal\.(blocked|suspicious)_command"')
  if [ "$N" -eq 2 ]; then
    ok "C2 a refusal and an allowed-but-suspicious line are distinguishable event types"
  else
    bad "C2 found $N of 2 distinct terminal event types — the ingest cannot separate a refusal from a suspicious run"
  fi
fi

# C3 — THE ARM AGAINST MY OWN REMEDY. `record_suspicious_event_at` counts EVERY
# row in suspicious_events inside the window toward `security_lockdown_threshold`
# (5 in 10 minutes) and a trip blocks every non-admin for 24h. TERMINAL_BLOCKED_
# PATTERNS contains a bare ".." SUBSTRING — its own comment admits `echo "done..."`
# is refused — so a tenant produces refusals BY ACCIDENT. Counting them would turn
# a deliberately blunt blocklist into a self-inflicted outage: a remedy that ARMS
# an escalation, which is this project's second most common failure.
if [ -z "$HEALER_S" ]; then
  bad "C3 SKIPPED: $HEALER did not yield source"
else
  ING=$(fn_body '^func autoHealerSecurityIngestSuspiciousEvents[(]' "$HEALER_S")
  ING_FLAT=$(flat "$ING")
  if [ -z "$ING" ]; then
    bad "C3 SKIPPED: could not bound autoHealerSecurityIngestSuspiciousEvents"
  elif has "$ING_FLAT" 'if eventType != "terminal\.blocked_command" \{ locked = SecurityHardeningRecordSuspiciousEventAt\('; then
    ok "C3 a refusal is audited but does NOT count toward auto-lockdown — a blunt blocklist cannot lock the panel out"
  else
    bad "C3 refusals feed the auto-lockdown counter — 5 accidental '..' refusals in 10 minutes would block every non-admin for 24h"
  fi
fi

# C4 — but it is still AUDITED, i.e. the operator can see it. audit_log writes
# security_audit_log, which is what SecurityHardening.tsx renders. A fix that made
# refusals invisible in a different way would be no fix at all.
if [ -z "$HEALER_S" ]; then
  bad "C4 SKIPPED: $HEALER did not yield source"
else
  ING=$(fn_body '^func autoHealerSecurityIngestSuspiciousEvents[(]' "$HEALER_S")
  if has "$(flat "$ING")" '\} SecurityHardeningAuditLog\(ctx, db, eventType'; then
    ok "C4 every ingested event still reaches the audit log the panel renders"
  else
    bad "C4 the ingest no longer audits — a refusal would be silent again, by a different route"
  fi
fi

echo "§D  the root shell's environment and privilege drop survive to execv"

# D1 retired (obsolete in Go): the defect was putenv storing a pointer to a
# CString freed before execv. Go has no fork-child code at all — the child's
# environment is cmd.Env, a []string copied by the runtime into the exec — so
# there is no pointer to dangle. (HOME=/root is set in terminalOpenPtyShell.)

# D2 — the privilege drop is CHECKED. A failed setuid (EAGAIN at RLIMIT_NPROC is
# the reachable one, since www-data also runs every PHP-FPM worker) used to fall
# through to execv and hand the SITE'S OWNER a root shell in their own webroot.
# In Go the drop is SysProcAttr.Credential, which the runtime applies in the
# child and ABORTS the exec on failure — so the property is that the site path
# sets the credential on the SAME attrs that start the PTY.
if [ -z "$TERM_S" ]; then
  bad "D2 SKIPPED: $TERM_RS did not yield source"
else
  BODY=$(fn_body '^func terminalOpenPtyShell[(]' "$TERM_S")
  BODY_FLAT=$(flat "$BODY")
  if [ -z "$BODY" ]; then
    bad "D2 SKIPPED: could not bound terminalOpenPtyShell"
  elif has "$BODY_FLAT" 'if site \{ .*attrs\.Credential = &syscall\.Credential\{Uid: uid, Gid: gid, Groups: groups\}' \
    && [ "$(count "$BODY" 'pty\.StartWithAttrs\(cmd, size, attrs\)')" -eq 2 ]; then
    ok "D2 the site shell's uid/gid/groups drop is applied by the runtime on the attrs that start the PTY — a failed drop aborts the exec"
  else
    bad "D2 the privilege drop is no longer on the attrs the PTY starts with — a site terminal could exec a ROOT shell for the site's owner"
  fi
fi

# D3 — and the result is re-read from the kernel, which is the half that cannot be
# fooled by a return code nobody read.
if [ -z "$TERM_S" ]; then
  bad "D3 SKIPPED: $TERM_RS did not yield source"
else
  BODY_FLAT=$(flat "$(fn_body '^func terminalOpenPtyShell[(]' "$TERM_S")")
  CREDS_FLAT=$(flat "$(fn_body '^func terminalCredsAre[(]' "$TERM_S")")
  if has "$BODY_FLAT" 'if !terminalCredsAre\(cmd\.Process\.Pid, uid, gid\) \{[^}]*cmd\.Process\.Kill\(\)[^}]*return nil, nil' \
    && has "$CREDS_FLAT" '/proc/%d/status' && has "$CREDS_FLAT" 'want\("Uid:", \[\]int\{1, 2\}, uid\)'; then
    ok "D3 the agent asks the kernel who the child actually is (real+effective uid) before handing over the shell"
  else
    bad "D3 nothing confirms the drop actually happened"
  fi
fi

echo "§E  \"no SSH keys\" means the agent looked"

# E1 — the read no longer swallows its error. This is the false all-clear: the
# panel's only view of who can SSH in as root answered 200 with an empty list on
# a box with three live keys, on every install, because ProtectHome=yes hides
# /root from the agent and the error became an empty string. Keyed on the
# OPERATION: every SSH handler reads through the checked helper and returns on
# its error, and none of them touches the file in-process.
if [ -z "$UTILS_S" ]; then
  bad "E1 SKIPPED: $UTILS did not yield source"
else
  BODY=$(fn_body '^func serverUtilsListSSHKeys[(]' "$UTILS_S")
  BODY_FLAT=$(flat "$BODY")
  SSH_FNS=$(printf '%s\n%s\n%s\n' \
    "$BODY" \
    "$(fn_body '^func serverUtilsAddSSHKey[(]' "$UTILS_S")" \
    "$(fn_body '^func serverUtilsRemoveSSHKey[(]' "$UTILS_S")")
  N_RAW=$(count "$SSH_FNS" 'os\.(ReadFile|WriteFile|Open|OpenFile|Create)\(')
  # occurrences, not lines: flat() makes the three bodies one line.
  N_CHK=$(grep -oE 'serverUtilsReadAuthorizedKeys\(r\.Context\(\)\) if err != nil \{ writeErr\(' <<< "$(flat "$SSH_FNS")" | wc -l | tr -d ' ')
  if [ -z "$BODY" ]; then
    bad "E1 SKIPPED: could not bound serverUtilsListSSHKeys"
  elif [ "$N_CHK" -eq 3 ] && [ "$N_RAW" -eq 0 ]; then
    ok "E1 an unreadable authorized_keys propagates as an error in all 3 handlers; only an ABSENT one is an empty list"
  else
    bad "E1 an SSH handler still turns a failed read into 'root has no keys' ($N_CHK/3 checked reads, $N_RAW raw in-process fs calls) — a false all-clear on root access"
  fi
fi

# E2 — and the read actually escapes the sandbox, or E1 only changes 200-with-a-lie
# into a permanent 500. ⚠ ReadWritePaths= and BindPaths= do NOT override
# ProtectHome=yes — both were measured in a transient unit and both still hide the
# file — so an unsandboxed command is the fix that works without loosening the
# sandbox `agent_unit.go` exists to protect.
if [ -z "$UTILS_S" ]; then
  bad "E2 SKIPPED: $UTILS did not yield source"
else
  RD=$(fn_body '^func serverUtilsReadAuthorizedKeys[(]' "$UTILS_S")
  WR=$(fn_body '^func serverUtilsWriteAuthorizedKeys[(]' "$UTILS_S")
  if has "$(flat "$RD")" 'safecmd\.NewUnsandboxed\("cat"\)' && has "$(flat "$WR")" 'safecmd\.NewUnsandboxed\("install"\)' \
    && ! has "$RD" 'os\.(ReadFile|Open)\('; then
    ok "E2 both the read and the write run outside the agent's ProtectHome sandbox"
  else
    bad "E2 an in-process fs call still touches /root/.ssh — ProtectHome=yes makes it answer ENOENT for a file that exists"
  fi
fi

# E3 — remove must NOT treat an unreadable file as empty. THE ORDER OF THE
# TWO FIXES MATTERS: on a failed read the old code filtered every line out of an
# empty string and wrote back "\n", i.e. it DELETED EVERY ROOT SSH KEY. Neither
# the read error nor the absent case (nil) may fall through to the write.
if [ -z "$UTILS_S" ]; then
  bad "E3 SKIPPED: $UTILS did not yield source"
else
  BODY_FLAT=$(flat "$(fn_body '^func serverUtilsRemoveSSHKey[(]' "$UTILS_S")")
  if [ -z "$BODY_FLAT" ]; then
    bad "E3 SKIPPED: could not bound serverUtilsRemoveSSHKey"
  elif has "$BODY_FLAT" 'cur, err := serverUtilsReadAuthorizedKeys\(r\.Context\(\)\) if err != nil \{ [^}]*return \} if cur == nil \{ [^}]*return \} newContent := '; then
    ok "E3 a remove on an unreadable or absent key file refuses instead of truncating it to nothing"
  else
    bad "E3 serverUtilsRemoveSSHKey can still reach its write with an empty buffer — that WIPES every root SSH key on the box"
  fi
fi

# E4 — the written file is 0600 and owned by root, because sshd ignores an
# authorized_keys that is group- or world-writable and would silently stop
# honouring every key.
if [ -z "$UTILS_S" ]; then
  bad "E4 SKIPPED: $UTILS did not yield source"
else
  WR_FLAT=$(flat "$(fn_body '^func serverUtilsWriteAuthorizedKeys[(]' "$UTILS_S")")
  if has "$WR_FLAT" '"-m", "600"' && has "$WR_FLAT" 'os\.OpenFile\(staging, [^)]*0o600\)'; then
    ok "E4 the installed key file is 0600, and so is the staging copy it is built in"
  else
    bad "E4 the key file or its staging copy is not 0600 — sshd ignores a loose authorized_keys"
  fi
fi

echo
echo "PASS $PASS / FAIL $FAIL"
[ "$FAIL" -eq 0 ]
