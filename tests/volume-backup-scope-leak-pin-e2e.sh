#!/usr/bin/env bash
# Regression pins for the s430 dockpanel-fanout run on the agent's volume_backup
# route + service and the panel's backup_orchestrator (Rust era; now
# panel/go/internal/agent/services/volume_backup.go and
# panel/go/internal/api/rt_backup_orchestrator.go) — two findings, upheld by an independent skeptic before either fix landed.
#
# 1. CROSS-ADMIN METADATA LEAK (list_volume_backups, confidentiality). The
#    endpoint was a flat `SELECT * FROM volume_backups ... LIMIT/OFFSET`
#    gated only by `AdminUser` — no server_id/user_id scope at all — unlike
#    its own sibling `list_db_backups` two functions above it, which has
#    always scoped by `s.user_id`. DockPanel is multi-tenant at the admin
#    tier (any admin can promote another user to `role='admin'` via
#    `PUT /api/users/{id}`, a routine action, not an edge case), so every
#    OTHER admin's container/volume names, filenames, sizes, sha256 hashes,
#    timestamps, and server_id were visible to any admin who opened this
#    endpoint's own dashboard tile. Does NOT enable cross-tenant RESTORE —
#    restore_volume_backup below it re-derives the target from a DB row
#    gated by an explicit ownership EXISTS predicate, which was already
#    correct and is unchanged. Fix: scope the list the same way restore
#    already scopes its own lookup — join servers and require
#    `sv.is_local OR sv.user_id = $1`.
#
# 2. EMPTY-ARCHIVE VOLUME WIPE (VolumeBackupRestoreVolume, data
#    integrity, prospective). The existing `tar tzf ... || exit 3` guard
#    (added at some prior session for the corrupt/truncated case) is not an
#    emptiness check: a syntactically-valid, gzip-CRC-clean, zero-member
#    archive exits `tar tzf` with 0, so the `rm -rf` still ran and left a
#    live volume wiped with no rollback. Fix: a SECOND, separate `tar tzf |
#    wc -l` re-run (kept apart from the corruption check rather than folded
#    into one pipe, so an early exit on a short-circuiting match can never
#    mask a mid-listing failure as success) requires at least one archive
#    member before the wipe proceeds. Verified with REAL `docker run`
#    executions against scratch Docker volumes, not just source reading:
#    (a) a genuinely empty tar.gz -> guard fires, exit 3, volume untouched;
#    (b) a real non-empty tar.gz -> restores correctly, old content replaced;
#    (c) a truncated/corrupt tar.gz -> still caught by the FIRST guard
#    (regression control — proves the new check didn't weaken the old one).
#
# Section A is a pure SOURCE pin (no box, no network, no build). Section B's
# script arms and section C's one-time docker PoC are now a Go test that runs
# the real restore script with sh+tar against scratch dirs on every pass:
# TestPinVolumeBackupScopeLeakRestoreScriptGuardsTheWipe
# (panel/go/internal/agent/services/pin_volume_backup_scope_leak_test.go).
#
#   run: bash tests/volume-backup-scope-leak-pin-e2e.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ORCH="$REPO/panel/go/internal/api/rt_backup_orchestrator.go"
VOLBACKUP_SVC="$REPO/panel/go/internal/agent/services/volume_backup.go"
for f in "$BACKUP_ORCH" "$VOLBACKUP_SVC"; do
  [ -f "$f" ] || { echo "missing file: $f"; exit 1; }
done
LVB_BODY=$(awk '/^func rtBackupOrchestratorListVolumeBackups\(/,/^}/' "$BACKUP_ORCH")
hasB()  { grep -q  -- "$2" <<< "$1" && ok "$3" || bad "$3"; }

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
has()   { grep -q  -- "$2" "$1" 2>/dev/null && ok "$3" || bad "$3"; }
hasE()  { grep -qE -- "$2" "$1" 2>/dev/null && ok "$3" || bad "$3"; }

echo "== A. list_volume_backups no longer leaks cross-admin, scoped like list_db_backups' sibling =="

hasB "$LVB_BODY" 'claims, err := st.adminUser(r)' \
  "rtBackupOrchestratorListVolumeBackups binds claims (Rust once had AdminUser(_claims), discarding the caller identity it needed)"
hasB "$LVB_BODY" 'JOIN servers sv ON sv.id = vb.server_id AND (sv.is_local OR sv.user_id = $1)' \
  "the list query joins servers and scopes by the same is_local-OR-owns predicate the volume restore already uses"
hasB "$LVB_BODY" 'LIMIT $2 OFFSET $3", claims.Sub, limit, offset)' \
  "claims.Sub is bound as the scope parameter ahead of limit/offset"

echo
echo "== B. restore_volume: an empty-but-valid archive can no longer wipe a live volume with no rollback =="

# B1-B5 (count-before-wipe, gated on >0, distinct empty message, both tar tzf
# present, corruption guard still first) retired: covered by
# TestPinVolumeBackupScopeLeakRestoreScriptGuardsTheWipe (panel/go/internal/agent/services/pin_volume_backup_scope_leak_test.go),
# which executes the script. What the test cannot see is whether the restore
# still RUNS that script — pinned here.
has "$VOLBACKUP_SVC" '"sh", "-c", volumeBackupRestoreScript(filename))' \
  "VolumeBackupRestoreVolume runs the guarded volumeBackupRestoreScript, not an inline rm-then-extract"

# C (docker PoC narrative) retired: the same three cases (empty / real / truncated)
# now run on every pass in TestPinVolumeBackupScopeLeakRestoreScriptGuardsTheWipe.

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
