#!/usr/bin/env bash
# Regression pins for the s456 dockpanel-fanout run over the '.git-blind
# recursive chown' bug class (workflow wf_76c47b26-e5f; project_dockpanel_tech_debt
# ledger p194's own item 14 — "Recommend its own dedicated dockpanel-fanout rep",
# carried since s377/project_dockpanel_tech_debt_p108).
#
#   G1  services/app_process.rs::create_app_service handed a git-deployed
#       Node/Python app's whole site directory to www-data, `.git` included —
#       the app can then write .git/config or .git/hooks/, which
#       deploy.rs::clone_or_pull runs as root on the next deploy.
#   G2  services/staging.rs::clone_files and G3 ::sync_files — same shape,
#       an rsync'd copy of a (possibly git-deployed) site handed over whole.
#   G4  routes/nginx.rs::clone_site — a second, independent implementation of
#       the same clone-a-site feature as staging.rs, same shape.
#   G5  services/migration.rs::import_site_files — same shape for a
#       node/proxy/python import; harmless no-op for php/static (dest nests
#       under `public/`, one level below where clone_or_pull's `.git` lives),
#       fixed uniformly rather than conditioned on runtime.
#   G6  services/cms.rs::chown_site — the shared helper behind 5 CMS
#       installers (Laravel/Drupal/Joomla/Symfony/CodeIgniter); prospective
#       (no caller has a `.git` present at call time today) but the directory
#       becomes www-data-owned afterward, so a future app compromise could
#       plant one.
#
# Completeness-critic finding, off the original topic menu, REALIZED not
# prospective (the mirror-image bug: missing chown, not over-broad chown):
#   G7  routes/backups.rs::restore — the tar-based restore path
#       (services/backups.rs::restore_inner, `--no-same-owner
#       --no-same-permissions`) left the whole restored site root:root,
#       unwritable by the www-data-running app, on DockPanel's flagship
#       documented "Restore a Backup" feature. The git-aware
#       chown_restored_tree helper existed in the same file but was wired
#       only to the separate opt-in Restic restore path.
#   G8  routes/backups.rs::restore_file — same gap, single-file restore path.
#
# Go port (panel/go/internal/agent): G1 services/app_process.go
# (AppProcessCreateAppService's inline split chown), G2/G3/G5 route through the
# shared services/deploy.go::deployHandTreeExceptGit (stagingRsync and
# MigrationImportSiteFiles call it), G4 routes/nginx.go::cloneSite delegates to
# services.StagingCloneFiles, G6 services/cms.go::cmsChownSite, G7/G8
# routes/backups.go::backupsRestore/backupsRestoreFile → backupsChownRestoredTree.
#
# Pure source analysis; no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Strip Go comments (whole-line // and /* */ blocks), so a pin can never be
# satisfied (or tripped) by prose describing the very thing it forbids.
code() {
  perl -0pe 's{/\*.*?\*/}{}gs' "$1" | grep -vE '^[[:space:]]*//'
}
has()   { [ -n "$(code "$1" | grep -F -- "$2")" ]; }
hasre() { [ -n "$(code "$1" | grep -E -- "$2")" ]; }

# One named Go function's (or method's) body, comment-stripped. Never pipe this
# into `grep -q` under pipefail — see security-firewalld-ssh-include-pin-e2e.sh.
fnbody() {
  code "$1" | awk -v fn="$2" '
    !p && (index($0, "func " fn "(") == 1 || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) { p = 1 }
    p { print } p && /^}/ { exit }'
}
bodyhas()   { [ -n "$(fnbody "$1" "$2" | grep -F -- "$3")" ]; }
bodyhasre() { [ -n "$(fnbody "$1" "$2" | grep -E -- "$3")" ]; }

AG=panel/go/internal/agent
APP_PROCESS=$AG/services/app_process.go
STAGING=$AG/services/staging.go
NGINX_ROUTE=$AG/routes/nginx.go
MIGRATION=$AG/services/migration.go
CMS=$AG/services/cms.go
BACKUPS_ROUTE=$AG/routes/backups.go
BACKUPS_SVC=$AG/services/backups.go
DEPLOY=$AG/services/deploy.go

for f in "$APP_PROCESS" "$STAGING" "$NGINX_ROUTE" "$MIGRATION" "$CMS" "$BACKUPS_ROUTE" "$BACKUPS_SVC" "$DEPLOY"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

# Every UPHELD site's fix is the same shape: skip `.git` in the main chown
# loop, then re-secure `.git` to root:root + go-rwx.
assert_split_chown() {
  local file="$1" fn="$2" label="$3"
  if bodyhasre "$file" "$fn" 'e\.Name\(\) == "\.git"'; then
    ok "$label: the chown loop skips .git"
  else
    bad "$label: no .git skip found in $fn — the split-chown fix may be gone"
  fi
  if bodyhasre "$file" "$fn" '"chown", "-R", "root:root", gitDir'; then
    ok "$label: .git is re-secured to root:root"
  else
    bad "$label: .git is no longer re-secured to root:root in $fn"
  fi
  if bodyhasre "$file" "$fn" '"chmod", "-R", "go-rwx", gitDir'; then
    ok "$label: .git's mode is locked down (go-rwx) after re-securing ownership"
  else
    bad "$label: .git is no longer chmod'd go-rwx in $fn"
  fi
}

echo "── 1. G1: app_process.go::AppProcessCreateAppService — .git-aware chown ──"
assert_split_chown "$APP_PROCESS" "AppProcessCreateAppService" "AppProcessCreateAppService"
if bodyhas "$APP_PROCESS" "AppProcessCreateAppService" "www-data:www-data"; then
  ok "AppProcessCreateAppService still chowns the rest of the tree to www-data"
else
  bad "AppProcessCreateAppService no longer chowns to www-data at all"
fi

echo
echo "── 2. G2/G3/G5: the shared deployHandTreeExceptGit helper + its staging/migration callers ──"
# In Go, staging (clone + sync) and migration import share one helper rather
# than three inline copies; pin the helper once and every caller's delegation.
assert_split_chown "$DEPLOY" "deployHandTreeExceptGit" "deployHandTreeExceptGit"
if bodyhas "$STAGING" "stagingRsync" "deployHandTreeExceptGit(ctx, target)"; then
  ok "stagingRsync hands the copied tree over via deployHandTreeExceptGit"
else
  bad "stagingRsync no longer calls deployHandTreeExceptGit — staging copies may hand .git to www-data"
fi
for fn in StagingCloneFiles StagingSyncFiles; do
  if bodyhas "$STAGING" "$fn" "stagingRsync(ctx, source, target)"; then
    ok "$fn routes its copy through stagingRsync (the .git-aware chown)"
  else
    bad "$fn no longer routes through stagingRsync — re-verify its ownership step"
  fi
done
if bodyhas "$MIGRATION" "MigrationImportSiteFiles" "deployHandTreeExceptGit(ctx, dest)"; then
  ok "MigrationImportSiteFiles hands the imported tree over via deployHandTreeExceptGit (uniformly)"
else
  bad "MigrationImportSiteFiles no longer calls deployHandTreeExceptGit"
fi

echo
echo "── 3. G4: routes/nginx.go::cloneSite — delegates to the .git-aware staging copy ──"
# s459: clone_site stopped reimplementing the copy+chown and delegates to the
# staging clone (pkg-rs-and-clone-dedup-hardening-pin-e2e.sh pins the dedup).
if bodyhas "$NGINX_ROUTE" "cloneSite" "services.StagingCloneFiles("; then
  ok "cloneSite: delegates to services.StagingCloneFiles (the .git-aware chown itself is pinned via §2)"
else
  bad "cloneSite: no longer delegates to services.StagingCloneFiles — either the .git-aware fix was removed or it moved to an unaudited third shape; re-verify by hand"
fi

echo
echo "── 4. G6: cms.go::cmsChownSite — one shared-helper fix covers all 5 installers ──"
assert_split_chown "$CMS" "cmsChownSite" "cmsChownSite"
for site in CmsInstallLaravel CmsInstallDrupal CmsInstallJoomla CmsInstallSymfony CmsInstallCodeigniter; do
  if bodyhas "$CMS" "$site" "cmsChownSite("; then
    ok "$site still routes ownership through the shared cmsChownSite helper"
  else
    bad "$site no longer calls cmsChownSite — it may have its own unguarded chown now"
  fi
done

echo
echo "── 5. REFUTED sites: confirmed no-ops must stay untouched (negative controls) ──"
# nginx.go's fastcgi-cache-dir chowns and single-file .env chown are not
# recursive against a site tree — assert the plain one-shot chown shape survives.
if hasre "$NGINX_ROUTE" 'nginxRun\(0, "chown", "www-data:www-data", (cacheDir|envPath)\)'; then
  ok "nginx.go still has plain (non-git-aware) chown calls for the cache-dir/.env sites"
else
  bad "nginx.go's non-site-dir chown calls are gone entirely — re-verify they weren't touched by mistake"
fi
# diagnostics.go's create-root fix only ever runs against a directory it just
# created empty — it should have NO .git-skip logic (there is nothing to skip).
DIAG=$AG/services/diagnostics.go
CREATE_ROOT=$(code "$DIAG" | awk '/case "create-root":/{p=1;print;next} p && /^[[:space:]]*case "/{exit} p')
if ! grep -qF '"chown", "-R", "www-data:www-data", target' <<<"$CREATE_ROOT"; then
  bad "diagnostics.go's create-root arm not found (or lost its chown) — the negative control below would be vacuous"
elif grep -qF '".git"' <<<"$CREATE_ROOT"; then
  bad "diagnostics.go's create-root fix grew a .git guard — it never needed one (always a fresh empty dir)"
else
  ok "diagnostics.go's create-root fix correctly has no .git guard (REFUTED site, left as-is)"
fi

echo
echo "── 6. G7/G8: routes/backups.go — the plain restore paths now re-secure ownership ──"
if bodyhas "$BACKUPS_ROUTE" "backupsRestore" "backupsChownRestoredTree("; then
  ok "backupsRestore now calls backupsChownRestoredTree after a successful file restore"
else
  bad "backupsRestore no longer calls backupsChownRestoredTree — restored sites will come back root-owned"
fi
if bodyhas "$BACKUPS_ROUTE" "backupsRestoreFile" "backupsChownRestoredTree("; then
  ok "backupsRestoreFile now calls backupsChownRestoredTree after a successful single-file restore"
else
  bad "backupsRestoreFile no longer calls backupsChownRestoredTree"
fi
assert_split_chown "$BACKUPS_ROUTE" "backupsChownRestoredTree" "backupsChownRestoredTree"
# The extraction flags that CAUSE the root-ownership are why this fix exists.
if bodyhas "$BACKUPS_SVC" "backupsRestoreInner" "no-same-owner"; then
  ok "backupsRestoreInner still extracts with --no-same-owner (confirms the fix is still needed, not stale)"
else
  bad "backupsRestoreInner no longer passes --no-same-owner — re-verify whether backupsChownRestoredTree calls are still necessary"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
