#!/usr/bin/env bash
# Regression pins for the s455 dockpanel-fanout run over the agent's
# database service + files route — now panel/go/internal/agent/services/database.go
# (databaseReconcileNetworkIccAt) and panel/go/internal/agent/routes/files.go
# (filesDownload)
# (workflow wf_42ca36ed-5e2; project_dockpanel_tech_debt ledger p194).
#
#   D1  `reconcile_network_icc` (the one-time pre-s242 ICC-hardening migration
#       for the shared `dockpanel-db` bridge) aborted on the FIRST reconnect
#       failure — the network was already torn down and recreated by that
#       point, so every container LATER in the batch than the failure was
#       left with ZERO network attachment (its published port stops
#       routing) and no server-side record of which containers were
#       orphaned. Live-proven against a real, fully disposable Docker
#       network (never the real `dockpanel-db`): two real containers
#       straddling a deliberately-unconnectable id both ended up reconnected
#       after the fix, and the aggregated error named exactly the bad id.
#   D2  the files route's `download_file` (Go: filesDownload) read an entire file into a `Vec<u8>`
#       (`tokio::fs::read`) before sending a single response byte, with no
#       size cap — unlike its sibling `read_file` (2MB cap, same file). The
#       agent is the ONE process per box mediating deploys/backups/terminal/
#       Docker for every tenant, and runs under a 512MB `MemoryMax` cgroup;
#       an ordinary non-admin site owner with any large file in their own
#       webroot (a DB dump, an unrotated log, media) could OOM-kill the
#       shared agent with one GET request. Fixed by streaming instead of
#       buffering — memory use becomes constant regardless of file size, so
#       no arbitrary cap is needed.
#
# Pure source analysis except where noted; no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Strip comments, so a pin can never be satisfied (or tripped) by prose
# describing the very thing it forbids. Go keeps tests in _test.go files, so
# no test module needs cutting.
code()  { grep -vE '^[[:space:]]*(//|\*|/\*)' "$1"; }
has()   { [ -n "$(code "$1" | grep -F -- "$2")" ]; }
hasre() { [ -n "$(code "$1" | grep -E -- "$2")" ]; }

# One named Go function's body, comment-stripped: from the line matching $2 to
# the first closing `}` at column 0. Never pipe this into `grep -q` — see
# security-firewalld-ssh-include-pin-e2e.sh's own header for why (the exact
# SIGPIPE-under-pipefail class this project tracks).
fnbody()    { code "$1" | awk "/$2/,/^}/"; }
bodyhas()   { [ -n "$(fnbody "$1" "$2" | grep -F -- "$3")" ]; }
bodyhasre() { [ -n "$(fnbody "$1" "$2" | grep -E -- "$3")" ]; }

DB_SVC=panel/go/internal/agent/services/database.go
FILES_ROUTE=panel/go/internal/agent/routes/files.go
FILES_SVC=panel/go/internal/agent/services/files.go

for f in "$DB_SVC" "$FILES_ROUTE" "$FILES_SVC"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

echo "── 1. D1: the ICC-network reconcile is best-effort, not abort-on-first-failure ──"

if has "$DB_SVC" "func databaseReconcileNetworkIccAt("; then
  ok "the ICC reconcile is path/network-parameterized for testability (databaseReconcileNetworkIccAt)"
else
  bad "databaseReconcileNetworkIccAt is gone"
fi

if bodyhasre "$DB_SVC" "^func databaseReconcileNetworkIccAt\(" 'if _, err := docker\.NetworkConnect\(.*err != nil \{'; then
  ok "the reconnect loop catches each failure instead of returning on it"
else
  bad "the reconnect loop no longer catches individual failures — abort-on-first-failure may be back"
fi

# "connect_network is still called", "failed.push" and "failed.join" retired:
# covered by TestPinDatabaseIccReconcileReconnectsEveryContainerDespiteOneBadID
# (panel/go/internal/agent/services/pin_database_icc_reconcile_and_file_download_test.go),
# which drives the function against a fake Docker API and asserts every later
# container is reconnected and the error names exactly the failed one.

# The Rust live-Docker regression test was not ported (it needed a daemon); the
# hermetic Go test above replaces it. This arm's point was "that test exists and
# passes", so it is run.
GT=$(cd panel/go && go test ./internal/agent/services/ -run '^TestPinDatabaseIccReconcileReconnectsEveryContainerDespiteOneBadID$' -count=1 -v 2>&1)
if grep -q -- '--- PASS: TestPinDatabaseIccReconcileReconnectsEveryContainerDespiteOneBadID' <<< "$GT"; then
  ok "a regression test for this exact shape (one bad id mid-batch) exists and passes"
else
  bad "the reconnect-loop regression test is gone or failing — $(grep -E -- '--- FAIL|^FAIL|_test.go:|no tests' <<< "$GT" | head -3 | tr '\n' ' ')"
fi

echo
echo "── 2. D2: file download streams instead of buffering the whole file in memory ──"

if bodyhasre "$FILES_ROUTE" "^func filesDownload\(" 'os\.ReadFile\(|io\.ReadAll\('; then
  bad "filesDownload reads the whole file into memory again — the OOM path is back"
else
  ok "filesDownload no longer reads the whole file into a []byte"
fi

if bodyhasre "$FILES_ROUTE" "^func filesDownload\(" 'io\.Copy\(w, f\)'; then
  ok "filesDownload streams the response instead of buffering it"
else
  bad "filesDownload no longer streams — check what replaced io.Copy"
fi

if bodyhas "$FILES_ROUTE" "^func filesDownload\\(" "os.Open(safe)"; then
  ok "filesDownload opens the file for streaming rather than reading it eagerly"
else
  bad "filesDownload no longer opens the file via os.Open — streaming path may be gone"
fi

# "tokio-util is a direct dependency" retired (obsolete in Go): the stream is
# stdlib io.Copy; there is no crate dependency to keep.

# The sibling function's own cap must be untouched — this pin suite is about
# the DOWNLOAD path specifically, not about relaxing the text-editor guard.
if bodyhasre "$FILES_SVC" "^func FilesReadFile\(" '2 ?\* ?1024 ?\* ?1024'; then
  ok "FilesReadFile's own 2MB text-editor cap is still in place, untouched"
else
  bad "FilesReadFile's 2MB cap is gone — unrelated regression"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
