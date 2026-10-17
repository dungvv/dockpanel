#!/usr/bin/env bash
#
# Regression pin for "does the backup actually LAND, and does the panel tell the
# truth about it?" — the six defects of s289.
#
# Every one of them had the same shape: a green check over a broken thing. s288
# fixed the credential path and proved Test Connection, and stopped there; none of
# these is reachable by reading Test Connection's result, and four of the six make
# the panel state something FALSE about data protection.
#
#   A  The panel capped every agent call at 60s while the agent budgets 600s for
#      the same upload, so an off-site copy that took longer than a minute (a 12MB
#      archive on a slow uplink was enough to measure) had the panel give up while
#      curl/scp kept running. The bytes landed; the panel retried the whole file
#      twice more, recorded it local-only, tripped the per-run destination breaker
#      so every LATER site/database/volume skipped off-siting too, and raised an
#      incident saying the backups "exist only on this server".
#
#   B  `backup_scheduler` (now svc_backup_scheduler.go) computed its upload result into a discarded `_`-prefixed
#      binding and inserted five columns, omitting `uploaded` and `destination_id`
#      — the two the migration added for exactly this. So every per-site scheduled
#      backup that DID go off-site was filed as local-only. Measured on a live box:
#      the SFTP copy sat at the destination while its row read uploaded=f.
#
#   C  Nothing installed `sshpass`, which is the only path a password-authenticated
#      SFTP destination can take — and password is the mode the form offers first.
#      s288 measured SFTP as working only because the test rig had apt-installed
#      sshpass itself, so the product's own gap was invisible to the test.
#
#   D  `--fail` fails on 4xx/5xx and says nothing about 3xx, and without `-L` curl
#      does not follow a redirect: it transfers nothing and EXITS 0. A bucket in
#      the wrong region answers 301, so upload_s3 returned Ok, the agent answered
#      success, and the panel lit the "remote" badge for an object that was never
#      written. Measured: "1 successes, 0 failures, 0 not uploaded off-site"
#      against an empty bucket.
#
#   E  Nothing created the SFTP remote directory and `test_sftp` never touched
#      `remote_path`, so Test passed while every scp failed "No such file or
#      directory". The default is /backups, which exists on almost no server.
#
#   F  S3 Test HEADed the bucket ROOT while upload PUTs into the PREFIX — different
#      permission, different path. Read-only and prefix-scoped keys both read green.
#
# and the one s339 added:
#
#   G  Both SFTP operations were SSH **exec** requests (`ssh host "mkdir -p ..."`,
#      then `scp`). `ForceCommand internal-sftp` — OpenSSH's own documented way to
#      run a chrooted, SFTP-only account — replaces the requested command with the
#      SFTP subsystem, so the mkdir was discarded and no such destination could
#      complete a backup (issue #102). The refusal arrives on STDOUT, so an error
#      built from stderr alone showed the operator nothing but ssh's known-hosts
#      banner. scp had to go too, not just move: OpenSSH 9.0 switched it to the
#      SFTP protocol, so a modern box transfers fine while RHEL 8 and Ubuntu 20.04
#      still speak legacy `scp -t` and would keep failing after a mkdir-only fix.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# The Go port (panel/go) is what ships.
API=panel/go/internal/api
EXEC=$API/svc_backup_policy_executor.go
SCHED=$API/svc_backup_scheduler.go
RB=panel/go/internal/agent/services/remote_backup.go
RBR=panel/go/internal/agent/routes/remote_backup.go
SETUP=scripts/setup.sh
for f in "$EXEC" "$SCHED" "$RB" "$RBR" "$SETUP"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

# Strip // line comments so a prose mention of a flag cannot satisfy an arm.
# This pin's whole subject is code that LOOKS right, and its own header names
# every string it greps for — without this, the header would pass the suite.
# (Deliberately not stripping /* */: none of the Go files this reads uses a
# block comment outside svc_guidance.go/rt_backup_destinations.go, whose arms
# are absence/presence of strings no block comment there mentions, and a naive
# block stripper has already swallowed a whole file here once.)
strip() { sed 's://.*::' "$1"; }

SRC_EXEC=$(strip "$EXEC")
SRC_SCHED=$(strip "$SCHED")
SRC_RB=$(strip "$RB")
SRC_RBR=$(strip "$RBR")

# Match against text already held in a variable, via a HERE-STRING — never a
# pipeline.
#
# `code "$f" | grep -q ...` is the obvious spelling and it is wrong here:
# `grep -q` closes the pipe the moment it matches, the upstream `sed` dies of
# SIGPIPE with status 141, and `set -o pipefail` then reports the whole pipeline
# as FAILED. Whether an arm went green depended on whether sed had finished
# writing before grep bailed — the same source scored differently run to run, and
# the first draft of this suite reported a real fix as missing for exactly that
# reason. A here-string is a single command, so there is no upstream to kill.
has()  { grep -q  -- "$2" <<< "$1"; }
hasE() { grep -qE -- "$2" <<< "$1"; }
# Body of one Go func, so an arm cannot be satisfied by a sibling function.
fnbody() { awk "/^func $2\(/,/^}/" <<< "$1"; }

echo
echo "§1 the upload call sites outlive the agent's own upload budget (A)"

# The agent's own budget, read from the upload functions rather than from a bare
# `600` literal — the refactor that fixed D moved the timeout into the shared
# runners' argument lists, and an arm pinned to the old spelling reports a
# problem with the code when the problem is with the arm.
if hasE "$(fnbody "$SRC_RB" RemoteBackupUploadS3)" '600\*time\.Second' && hasE "$(fnbody "$SRC_RB" RemoteBackupUploadSftp)" '600\*time\.Second'; then
  ok "the agent still budgets 600s for both uploads"
else
  bad "the agent's upload budget moved — this pin's numbers need rechecking"
fi

for f in "$EXEC" "$SCHED"; do
  n=$(basename "$f")
  src=$(strip "$f")
  if has "$src" 'agent.PostLong(ctx, "/backups/upload"'; then
    ok "$n uploads via PostLong, not the 60s Post"
  else
    bad "$n uses plain Post for /backups/upload — 60s cap over a 600s operation"
  fi
  # Pull the digits out of the argument list. Anchoring on `$` matched nothing,
  # because the captured text ends in `)` — an arm that silently extracts an
  # empty string reports "none" and looks like a real failure of the code.
  t=$(grep -oE 'PostLong\(ctx, "/backups/upload", [A-Za-z_]+, [0-9]+' <<< "$src" | grep -oE '[0-9]+' | tail -1)
  if [ -n "$t" ] && [ "$t" -gt 600 ]; then
    ok "$n allows ${t}s — longer than the agent's 600s, so the agent errors first"
  else
    bad "$n passes '${t:-none}' — must exceed the agent's 600s budget"
  fi
done

echo
echo "§2 a scheduled backup records WHERE its bytes went (B)"

# Assert the CAPABILITY (both columns are in the list), never the list itself.
# The first cut of this arm froze the whole column list terminated by
# `destination_id)`, so #114's correct fix — appending sha256_hash/previous_hash,
# which this arm has no opinion about — turned it red with the false verdict
# "omits uploaded/destination_id" while both were plainly still there. A pin that
# freezes a list guarantees the next legitimate addition looks like a regression,
# and it cannot notice the asymmetry it was supposed to be watching for.
SCHED_INSERT=$(grep -F 'INSERT INTO backups (' <<< "$SRC_SCHED" | head -1)
# The argument list of that same exec: the lines after the INSERT up to `); err`.
SCHED_ARGS=$(awk '/INSERT INTO backups \(/{f=1} f{print} f&&/\); err != nil/{exit}' <<< "$SRC_SCHED" | tail -n +2)
if [ -z "$SCHED_INSERT" ]; then
  bad "the scheduler's INSERT could not be isolated — the arm examined nothing"
elif hasE "$SCHED_INSERT" 'uploaded' && hasE "$SCHED_INSERT" 'destination_id'; then
  ok "the scheduler's INSERT carries uploaded + destination_id"
else
  bad "the scheduler's INSERT omits uploaded/destination_id — the badge cannot light"
fi

# Go refuses an unused local, so the Rust `_uploaded_remote` trap becomes:
# the upload result is computed into a name and that name reaches the INSERT.
if [ -z "$SCHED_ARGS" ]; then
  bad "the scheduler INSERT's argument list could not be isolated — the arm examined nothing"
elif hasE "$SRC_SCHED" '^[[:space:]]+uploadedRemote = true' && hasE "$SCHED_ARGS" '[ ,]uploadedRemote,'; then
  ok "the upload result is bound to a name that is actually read"
else
  bad "the upload result no longer reaches the INSERT — every off-site copy files as local-only again"
fi

# Pinned as a CAPABILITY, not as a literal.
#
# The previous spelling of this arm was an exact match on
# `bind(if uploaded_remote { ... } else { None })`, and s389's correct fix — making
# the bind unconditional — therefore reported as a regression. That is the same
# freeze-a-literal failure this file's own §B comment above already describes.
#
# What actually has to hold: the destination is recorded whatever the upload did.
# `uploaded = FALSE` alone cannot mean "off-site failed" — the manual path binds
# no destination and a schedule with none writes FALSE too — so the only predicate
# that identifies a failed off-site copy is the PAIR (destination_id IS NOT NULL
# AND NOT uploaded), which is what the policy executor already writes.
DEST_BIND=$(grep -oE '[^ ,]*DestID[^ ,]*' <<< "$SCHED_ARGS" | head -1)
if [ -z "$DEST_BIND" ]; then
  bad "the scheduler binds no destination_id at all — a scheduled off-site copy records no destination"
elif [ "$DEST_BIND" != row.DestID ] || grep >/dev/null -ciE 'if uploaded' <<< "$SCHED_ARGS"; then
  bad "destination_id is bound only when the upload succeeded, so a failed off-site copy cannot be told from a schedule that never had a destination: $DEST_BIND"
else
  ok "destination_id is bound from the schedule's own destination whatever the upload did"
fi

# dest_id-dead-code retired (obsolete in Go): there is no #[allow(dead_code)]
# in Go, and an unread struct field draws no warning to silence.

echo
echo "§3 no S3 call treats a redirect as a delivered upload (D)"

# --fail is the flag that made a 3xx look like success. It must be gone from
# every S3 invocation, not just the one that was investigated.
if ! has "$SRC_RB" '"--silent", "--show-error"'; then
  bad "the shared curl argument list moved — the --fail absence check below would see nothing"
elif has "$SRC_RB" '"--fail"'; then
  bad "an S3 curl invocation still passes --fail — 3xx will read as success"
else
  ok "no S3 curl invocation passes --fail"
fi

# s3-explicit-2xx retired: covered by TestPinBackupLandsS3OkIsExactly2xx (panel/go/internal/agent/services/pin_backup_lands_test.go)

# All four S3 operations must go through the one runner. Fixing the copy under
# investigation and leaving its siblings is a mistake this file has shipped.
for fn in RemoteBackupUploadS3 RemoteBackupTestS3 RemoteBackupListS3 RemoteBackupDeleteS3; do
  if has "$(fnbody "$SRC_RB" "$fn")" 'remoteBackupS3Curl('; then
    ok "$fn goes through the shared remoteBackupS3Curl runner"
  else
    bad "$fn builds its own curl call — the 3xx bug can return there"
  fi
done

# Following redirects is NOT the fix: a SigV4 signature is bound to the host and
# path it was signed for, and curl downgrades PUT to GET on 301/302.
if hasE "$SRC_RB" '"-L"|--location'; then
  bad "an S3 call follows redirects — the SigV4 signature will not match the new host"
else
  ok "no S3 call follows redirects"
fi

echo
echo "§4 Test Connection exercises what an upload needs (E, F)"

if hasE "$SRC_RBR" 'services\.RemoteBackupTestS3\(bucket, .*, endpoint, access, secret, remoteBackupOr\(d\.PathPrefix, ""\)\)'; then
  ok "the S3 test is handed the same prefix the upload writes to"
else
  bad "the S3 test does not receive path_prefix — it probes a different location"
fi

S3TEST=$(fnbody "$SRC_RB" RemoteBackupTestS3)
if has "$S3TEST" '"PUT"'; then
  ok "the S3 test performs a PUT, the operation an upload performs"
else
  bad "the S3 test does not write — a read-only key will pass it"
fi
if has "$S3TEST" '"DELETE"'; then
  ok "the S3 test removes its own probe object"
else
  bad "the S3 test leaves its probe behind at the destination"
fi
if has "$S3TEST" '"-I"'; then
  bad "the S3 test still HEADs — that is the check that could not see a 301"
else
  ok "the S3 test no longer relies on HEAD"
fi

UPSFTP=$(fnbody "$SRC_RB" RemoteBackupUploadSftp)
SFTPTEST=$(fnbody "$SRC_RB" RemoteBackupTestSftp)

if has "$UPSFTP" 'remoteBackupSftpMkdirScript('; then
  ok "the SFTP upload creates its remote directory"
else
  bad "nothing creates the SFTP remote directory — a transfer will not"
fi

if hasE "$SRC_RBR" 'services\.RemoteBackupTestSftp\(.*remotePath\)'; then
  ok "the SFTP test is handed remote_path"
else
  bad "the SFTP test never receives remote_path — it cannot check the directory"
fi

if has "$SFTPTEST" 'remoteBackupSftpMkdirScript('; then
  ok "the SFTP test creates and probes the directory an upload will use"
else
  bad "the SFTP test does not touch remote_path — green while every upload fails"
fi
if [ -z "$SFTPTEST" ]; then
  bad "RemoteBackupTestSftp did not extract — the connect-and-exit absence check would see nothing"
elif hasE "$SFTPTEST" '"exit(\\n)?"'; then
  bad "the SFTP test is back to connecting and exiting — it proves only auth"
else
  ok "the SFTP test does more than authenticate"
fi

echo
echo "§4b the transport survives a server that only allows SFTP (G)"

# `ForceCommand internal-sftp` is OpenSSH's own documented way to run a chrooted,
# SFTP-only account, and it REPLACES whatever command an exec request carried. Both
# operations used to be exec requests, so the mkdir was silently discarded and no
# such destination could ever complete a backup (issue #102).
for pair in "RemoteBackupUploadSftp:$UPSFTP" "RemoteBackupTestSftp:$SFTPTEST"; do
  fn=${pair%%:*}; body=${pair#*:}
  # Flatten first. grep matches within ONE line, and a formatter wraps a call whose
  # argument list is long — `run_sftp(\n    "ssh",` never puts the callee and its
  # first argument on the same line, so a line-based arm reads a call it cannot
  # see as absent. s339 shipped exactly that: this arm went red against the
  # single-line pre-fix source and stayed GREEN over a transport reverted to ssh.
  flat=$(tr '\n' ' ' <<< "$body" | tr -s ' ')
  if hasE "$flat" 'remoteBackupRunSftp\( *"(ssh|scp)"'; then
    bad "$fn issues an SSH exec request — ForceCommand internal-sftp discards it"
  else
    ok "$fn does not depend on an SSH exec request"
  fi
  if hasE "$flat" 'remoteBackupRunSftp\( *"sftp"'; then
    ok "$fn names the sftp transport explicitly"
  else
    bad "$fn does not call remoteBackupRunSftp with sftp — the transport is not what it claims"
  fi
  if has "$body" '"-b"'; then
    ok "$fn drives the SFTP subsystem in batch mode"
  else
    bad "$fn no longer runs a batch script — the transport moved"
  fi
  # A path reaching a batch line unquoted does not fail: sftp splits it and writes
  # to the wrong place under the source filename, exit 0.
  if has "$body" 'remoteBackupSftpQuote('; then
    ok "$fn quotes the paths it puts in a batch line"
  else
    bad "$fn passes an unquoted path — a space silently redirects the transfer"
  fi
  if has "$body" 'remoteBackupRejectUnquotablePath('; then
    ok "$fn refuses a remote path carrying a line break"
  else
    bad "$fn accepts a newline in remote_path — that appends a second sftp command"
  fi
done

# scp is not merely unused, it must stay gone: OpenSSH < 9.0 speaks legacy `scp -t`,
# which is an exec request and dies the same way. A modern dev box hides this.
if has "$SRC_RB" '"scp"'; then
  bad "scp is back — on OpenSSH < 9.0 it is an exec request and cannot survive ForceCommand"
else
  ok "no scp invocation remains"
fi

# The refusal arrives on STDOUT; an error built from stderr alone showed the
# operator ssh's known-hosts banner as the whole cause of a failed backup.
# command-detail-helper retired: covered by TestDetailReportsARefusalThatArrivedOnStdout (panel/go/internal/agent/services/remote_backup_test.go)
for fn in RemoteBackupUploadSftp RemoteBackupTestSftp; do
  if has "$(fnbody "$SRC_RB" "$fn")" 'remoteBackupCommandDetail('; then
    ok "$fn reports both streams to the operator"
  else
    bad "$fn reports only one stream — the diagnosis is on the other one"
  fi
done

echo
echo "§5 one ssh option builder, not two kept in step by hand (E)"

builders=$(grep -c 'StrictHostKeyChecking=accept-new' <<< "$SRC_RB")
if [ "$builders" -eq 1 ]; then
  ok "the ssh options are built in exactly one place"
else
  bad "$builders ssh option lists — they drifted once already (ConnectTimeout)"
fi

if has "$SRC_RB" 'func remoteBackupSftpOpts('; then
  ok "the shared builder exists"
else
  bad "there is no shared ssh option builder"
fi

# BatchMode-key-only retired: covered by TestBatchmodeIsTurnedOffForPasswordAuthAndOnForKeys (panel/go/internal/agent/services/remote_backup_test.go)
# BatchMode=no-for-password retired: covered by TestBatchmodeIsTurnedOffForPasswordAuthAndOnForKeys (panel/go/internal/agent/services/remote_backup_test.go)

echo
echo "§6 the SFTP upload path's binaries are installed (C)"

SETUP_SRC=$(cat "$SETUP")
if hasE "$SETUP_SRC" 'pkg_install sshpass'; then
  ok "setup.sh installs sshpass"
else
  bad "nothing installs sshpass — password SFTP destinations cannot work"
fi

if hasE "$SETUP_SRC" 'pkg_install .*openssh-client'; then
  ok "setup.sh declares the ssh client"
else
  bad "openssh-client/openssh-clients is an undeclared runtime dependency"
fi

# It must NOT be fatal: sshpass comes from EPEL on RHEL-family, EPEL enablement
# is itself best-effort, and this script runs under `set -e`. Making it mandatory
# would turn "no EPEL" into a failed install for everyone.
if hasE "$SETUP_SRC" 'if ! run "Installing sshpass'; then
  ok "the sshpass install is best-effort, so it cannot abort an install"
else
  bad "the sshpass install is not guarded — a missing package now aborts setup"
fi

# And when it is genuinely absent, the operator must be told which binary.
if has "$SRC_RB" 'sshpass is not installed on this server'; then
  ok "the agent names sshpass and the remedy when it is missing"
else
  bad "a missing sshpass still surfaces as a bare os error 2"
fi

echo
echo "§7 a server that is ALREADY RUNNING can be repaired from the panel (#93)"

# §6 proves a FRESH install gets the binary. That was never the gap: `update.sh`
# upgrades binaries and installs no packages, so a box that predates §6 stays
# broken for ever and its operator was told to run a package manager by hand.
# These arms pin the door that closes it.
SI=panel/go/internal/agent/routes/service_installer.go
SYS=$API/rt_system.go
# Go registers each route next to its handlers; the router file is rt_system.go.
MOD=$API/rt_system.go
# The guidance copy (Rust prerequisites/copy.rs) lives in svc_guidance.go.
CP=$API/svc_guidance.go
for f in "$SI" "$SYS" "$MOD" "$CP"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done
SRC_SI=$(strip "$SI")
SRC_SYS=$(strip "$SYS")
SRC_MOD=$(strip "$MOD")
SRC_CP=$(strip "$CP")

# Both route arms close on the quote. An unanchored `…/sshpass` is also satisfied
# by `…/sshpass_DISABLED`, so renaming the route out of service left them green —
# measured, not guessed.
if hasE "$SRC_SI" '"POST /services/install/sshpass"'; then
  ok "the agent exposes an install route for sshpass"
else
  bad "the agent has no sshpass install route — an existing server cannot be repaired"
fi

# Go registers the installers from the rtSystemServices table:
# "POST /api/services/"+s.path for each {path, name}. Both halves must hold.
if hasE "$SRC_MOD" '\{"install/sshpass", ' \
   && hasE "$SRC_MOD" 'r\.Handle\("POST /api/services/"\+s\.path, h\(rtSystemInstall\(s\.name, "/services/"\+s\.path\)\)\)'; then
  ok "the panel routes through to it"
else
  bad "the agent route is unreachable — nothing on the panel calls it"
fi

# The handler runs a package transaction as root on the target box. It must
# resolve that box from a scope the caller is PROVEN to hold, never from an id
# they can type: the fleet resolver behind the alternative carries no ownership
# predicate at all, so naming a stranger's uuid would install on their machine.
# Go: the table-driven rtSystemInstall resolves its agent via
# rtSystemAdminScope, which is AdminUser + st.serverScope(r).
if hasE "$(fnbody "$SRC_SYS" rtSystemInstall)" 'rtSystemAdminScope\(st, r\)' \
   && hasE "$(fnbody "$SRC_SYS" rtSystemAdminScope)" 'st\.serverScope\(r\)'; then
  ok "the install is bound to a server the caller is proven to own"
else
  bad "the sshpass install resolves its target without proving ownership"
fi

if hasE "$SRC_SI" '"sshpass":[[:space:]]*m\{"installed"'; then
  ok "install-status reports sshpass, so the panel can show it before it is needed"
else
  bad "nothing reports whether sshpass is present — the control cannot render state"
fi

# An empty window makes a presence arm red for a reason that has nothing to do
# with the code — and would make an ABSENCE arm green. So refuse to score an
# empty extraction at all. (Rust needed a pub/private-agnostic variant; Go
# funcs all start `func NAME(`, so this is fnbody.)
fnbody_any() { fnbody "$@"; }
TD=$(fnbody_any "$SRC_RBR" remoteBackupTestDestination)
if [ "$(printf '%s' "$TD" | wc -l)" -lt 20 ]; then
  bad "remoteBackupTestDestination did not extract — every arm below it is measuring nothing"
else
  ok "remoteBackupTestDestination extracted ($(printf '%s' "$TD" | wc -l) lines)"

  # THE defect this ships with the door: the sentence above has existed since s289
  # and never reached anybody. The panel keeps the body of a 4xx and replaces the
  # body of a 5xx with an incident reference, so answering 5xx for a missing
  # package discarded the remedy and told the operator their agent had broken.
  if hasE "$TD" 'http\.StatusFailedDependency'; then
    ok "a missing prerequisite answers 4xx, so its sentence survives the trip"
  else
    bad "the missing-sshpass answer is a 5xx again — the panel will eat the remedy"
  fi

  # ...and it must be that ONE condition, not every SFTP failure. A blanket 4xx
  # would forward real gateway errors as if the caller could act on them.
  #
  # Scoped to the SFTP branch on purpose: test_destination also holds the S3
  # branch, whose own gateway error satisfied a whole-function arm even after the
  # SFTP one had been flipped. An arm must be no broader than the property it
  # defends.
  SFTP_ARM=$(awk '/case "sftp":/,/SFTP connection successful/' <<< "$TD")
  if [ "$(printf '%s' "$SFTP_ARM" | wc -l)" -lt 10 ]; then
    bad "the sftp branch did not extract — the two status arms measure nothing"
  elif hasE "$SFTP_ARM" 'status := http\.StatusBadGateway'; then
    ok "every other SFTP failure is still a gateway error"
  else
    bad "the 4xx is unconditional — genuine agent failures now read as user error"
  fi
fi

# The guidance is generated from this file, so the instruction to run a package
# manager by hand cannot survive here without reappearing on both surfaces.
if hasE "$SRC_CP" '(apt-get|dnf) install sshpass'; then
  bad "the guidance still tells the operator to install it by hand"
else
  ok "the guidance no longer asks the operator to run a package manager"
fi

echo
echo "── 8. the remedy reaches the path nobody is watching ──"

# v2.99.0 taught ONE of the two callers that can hit a missing prerequisite to
# answer a client error, and the sentence it protects is worth least on that one.
# `test_destination` runs while an operator is looking at the screen; `upload`
# runs from the scheduler at 03:00. Both were reachable, both mapped the same
# service error, and only the watched one was fixed — so the unattended failure
# still arrived as an incident reference for a box that merely lacked a package.
ERR=$API/core_error.go
BDST=$API/rt_backup_destinations.go
for f in "$ERR" "$BDST"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done
SRC_ERR=$(strip "$ERR")
SRC_BDST=$(strip "$BDST")

UP=$(fnbody_any "$SRC_RBR" remoteBackupUpload)
if [ "$(printf '%s' "$UP" | wc -l)" -lt 20 ]; then
  bad "remoteBackupUpload did not extract — every arm below it is measuring nothing"
else
  ok "remoteBackupUpload extracted ($(printf '%s' "$UP" | wc -l) lines)"

  # Scoped to upload's OWN sftp branch. The file holds four other arms that map a
  # status, and `upload` itself also holds the S3 branch — a whole-function match
  # is satisfied by any of them, which is how a flipped arm stays green.
  UP_SFTP=$(awk '/case "sftp":/,/"destination": dest/' <<< "$UP")
  if [ "$(printf '%s' "$UP_SFTP" | wc -l)" -lt 10 ]; then
    bad "upload's sftp branch did not extract — its two status arms measure nothing"
  else
    if hasE "$UP_SFTP" 'http\.StatusFailedDependency'; then
      ok "a scheduled upload blocked by a missing package answers 4xx, so its sentence survives"
    else
      bad "the unattended upload path answers 5xx again — the nightly failure loses its remedy"
    fi

    # ...and only for that one condition. A blanket 4xx here would tell an
    # operator to go fix their box when the remote host is the thing that broke.
    if hasE "$UP_SFTP" 'status := http\.StatusInternalServerError'; then
      ok "every other upload failure is still a server error"
    else
      bad "upload's 4xx is unconditional — real transfer failures now read as user error"
    fi
  fi
fi

# The rule itself lives in exactly one place. Two callers deriving "is this a
# client error" independently is how they drift apart, which is the whole shape
# of this section.
# agent-actionable-shared-rule retired: covered by TestAgentActionableOnly4xx (panel/go/internal/api/core_error_test.go)

FLEET=$(fnbody_any "$SRC_BDST" rtBackupDestinationsTestFromWholeFleet)
if [ "$(printf '%s' "$FLEET" | wc -l)" -lt 20 ]; then
  bad "rtBackupDestinationsTestFromWholeFleet did not extract — its arms measure nothing"
else
  ok "rtBackupDestinationsTestFromWholeFleet extracted ($(printf '%s' "$FLEET" | wc -l) lines)"

  if hasE "$FLEET" 'agentActionable\(err\)'; then
    ok "the fleet summariser asks whether the refusal was actionable"
  else
    bad "the fleet summariser stringifies its errors again — a unanimous 4xx dies here"
  fi

  # The defect precisely: a hard-coded gateway status on the nothing-reached exit.
  # Every UI-created destination has a NULL server_id and therefore takes this
  # branch, so this is the common path, not the exotic one.
  #
  # Keyed on the ARGUMENT the exit passes. In Go the nothing-reached block
  # starts from a gateway default, overrides it only when the refusal was
  # unanimous, and returns `apiErr(status, ...)`.
  NOREACH=$(awk '/if len\(reachable\) == 0 \{/,/^\t\}/' <<< "$FLEET")
  if [ "$(printf '%s' "$NOREACH" | wc -l)" -lt 5 ]; then
    bad "the nothing-reached exit did not extract — its status arm measures nothing"
  elif hasE "$NOREACH" 'return apiErr\(status, '; then
    ok "the nothing-reached exit carries a computed status rather than asserting one"
  else
    bad "the nothing-reached exit asserts its own status — a unanimous 4xx is flattened again"
  fi

  # ...but the fallback must survive: a mixed bag, or a genuine agent fault, has
  # no single answer to propagate and must still read as a gateway failure.
  #
  # Keyed on the nothing-reached block, NOT on the token anywhere in the
  # function: this function holds a SECOND gateway status for the
  # no-members-online case, and a whole-function grep stayed green with the
  # fallback deleted. Measured.
  if hasE "$NOREACH" 'status := http\.StatusBadGateway' \
     && hasE "$NOREACH" 'if shared != 0 && unanimous \{'; then
    ok "a fleet with no shared answer still reports a gateway failure"
  else
    bad "the gateway fallback is gone — an agent that genuinely broke now reads as user error"
  fi
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
