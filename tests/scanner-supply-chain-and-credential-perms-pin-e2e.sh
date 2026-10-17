#!/usr/bin/env bash
# Regression pins for the s457 dockpanel-fanout run over the agent's
# services/image_scanner.rs + routes/image_scan.rs (workflow
# wf_6a5a4e25-9ee; 2 topics finder/skeptic + completeness/setup critics).
# Repointed to the Go port: panel/go/internal/agent/services/{image_scanner,
# sbom_scanner,cms,wordpress}.go. In Go the kill_on_drop(true) of S3 is a
# child built with safecmd.Exec/Command on a ctx from context.WithTimeout —
# exec.CommandContext SIGKILLs it at the deadline (proven by
# TestPinTimeoutOrphanKillOnDropKillsTheChild in internal/agent/safecmd).
#
#   S1  services/image_scanner.rs::install_grype fetched Anchore's install.sh
#       from the mutable `main` ref and let it resolve "latest" at install
#       time — no tag pinned. (Anchore's install.sh ALREADY sha256-verifies
#       the downloaded archive against its own release checksums.txt
#       unconditionally — read upstream to confirm this session, not assumed
#       — so the gap was reproducibility/pinning, not missing integrity
#       verification.) Fixed: both the script fetch and the installed
#       release are pinned to GRYPE_VERSION via install.sh's own TAG arg.
#   S2  services/sbom_scanner.rs::install_syft — identical shape, same fix,
#       pinned to SYFT_VERSION.
#   S3  Neither scanner's process spawns set kill_on_drop — a timed-out
#       grype/syft child outlives the 180s the caller is told it "timed
#       out", the exact kill_on_drop/timeout-orphan class this project has
#       already fixed five times (docker_apps.rs, pkg.rs, database_backup.rs,
#       wp_vulnerability.rs, backups.rs — s446-453); image_scanner.rs and
#       sbom_scanner.rs were never swept in that arc. Fixed on all 5 spawn
#       sites across both files (2 install spawns + grype's db-update-priming
#       spawn + the two per-scan spawns).
#
# Completeness-critic finding, off the original topic menu:
#   S4  services/wordpress.rs::install and 4 of cms.rs's 5 CMS installers
#       (Laravel/Drupal/Joomla/CodeIgniter — Symfony's install() takes no DB
#       credentials at all, confirmed by its own signature, so it is
#       deliberately NOT wired) wrote a DB-credential-bearing config file
#       (wp-config.php / .env / settings.php / configuration.php) at the
#       process umask's default 644, world-readable, with no chmod anywhere
#       on the install path. wp_vulnerability.rs's own "wp-config-perms"
#       hardening check (chmod 640) already existed but only ran via the
#       separate opt-in POST /wordpress/{domain}/harden pass, never wired
#       into install() itself.
#       ⚠ HONEST SCOPE, live-verified this session (chmod 600/640 vs a
#       same-UID reader on this box: both still readable; only a genuinely
#       different UID was denied — see the fix's own comment in cms.rs and
#       wordpress.rs): this closes reads from any OTHER local OS account.
#       It does NOT and structurally CANNOT isolate one tenant's own
#       www-data-identity PHP-FPM pool or client-role shell from another
#       tenant's credential file, since every site currently shares the
#       identical www-data:www-data identity (nginx.rs hardcodes
#       user=www-data/group=www-data for every pool, and no open_basedir
#       anywhere restricts a pool's own filesystem view). That is the
#       separate, already-tracked per-site-OS-user isolation gap (#64/#85 in
#       project_dockpanel_tech_debt.md), unchanged by this fix — do not cite
#       this pin as evidence it closed cross-tenant isolation.
#
# Deliberately NOT fixed this session (filed as carries, not pinned here):
#   - SSRF-via-arbitrary-registry-host in scan_image()/generate_sbom() —
#     live-verified real (grype opens its own outbound HTTPS connection to
#     an attacker-shaped host:port, no Docker daemon involved) but a naive
#     RFC1918/loopback denylist would break a legitimate self-hosted
#     private-registry use case; needs an explicit allowlist design.
#   - pkg.rs's NodeSource curl|bash installer — same install-script-execution
#     shape but version-scoped in its own URL already and lower priority per
#     the setup critic.
#
# Pure source analysis; no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Strip comment lines. (Go keeps its tests in *_test.go, so there is no
# in-file test module to cut — the Rust-era cfg(test) handling is gone.)
code() { grep -vE '^[[:space:]]*(//|\*|/\*)' "$1"; }
has()   { [ -n "$(code "$1" | grep -F -- "$2")" ]; }
hasre() { [ -n "$(code "$1" | grep -E -- "$2")" ]; }

# One named function's body, comment-stripped. Function-name patterns MUST be
# anchored (^ ... \() — GNU awk's \b silently matches nothing in default ERE
# mode (project_dockpanel_lessons_p182, s456), and several names here
# (install, install_grype, install_syft) are prefixes of no sibling in these
# files, but anchoring is the standing discipline regardless.
fnbody()    { code "$1" | awk "/$2/,/^}/"; }
bodyhas()   { [ -n "$(fnbody "$1" "$2" | grep -F -- "$3")" ]; }
bodyhasre() { [ -n "$(fnbody "$1" "$2" | grep -E -- "$3")" ]; }
countin()   { fnbody "$1" "$2" | grep -Fc -- "$3"; }

GS=panel/go/internal/agent/services
IMAGE_SCANNER=$GS/image_scanner.go
SBOM_SCANNER=$GS/sbom_scanner.go
CMS=$GS/cms.go
WORDPRESS=$GS/wordpress.go

for f in "$IMAGE_SCANNER" "$SBOM_SCANNER" "$CMS" "$WORDPRESS"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

echo "── 1. S1: image_scanner.go ImageScannerInstallGrype — pinned to a tag, not main ──"
if hasre "$IMAGE_SCANNER" '^const imageScannerGrypeVersion = "v[0-9]'; then
  ok "imageScannerGrypeVersion is a pinned version-tag constant"
else
  bad "no pinned imageScannerGrypeVersion constant found"
fi
if bodyhas "$IMAGE_SCANNER" "^func ImageScannerInstallGrype\\(" '/main/install.sh'; then
  bad "install_grype still fetches install.sh from the mutable main ref"
else
  ok "install_grype no longer fetches install.sh from /main/"
fi
if bodyhasre "$IMAGE_SCANNER" "^func ImageScannerInstallGrype\\(" 'anchore/grype/%s/install\.sh \| sh -s -- -b %s %s",' \
   && bodyhasre "$IMAGE_SCANNER" "^func ImageScannerInstallGrype\\(" '^[[:space:]]*imageScannerGrypeVersion, imageScannerGrypeDir, imageScannerGrypeVersion\)'; then
  ok "install_grype fetches install.sh from the pinned GRYPE_VERSION tag ref"
else
  bad "install_grype's install.sh fetch is not pinned to GRYPE_VERSION's ref"
fi
if bodyhasre "$IMAGE_SCANNER" "^func ImageScannerInstallGrype\\(" 'imageScannerGrypeDir, imageScannerGrypeVersion\)$'; then
  ok "install_grype passes GRYPE_VERSION as install.sh's TAG argument"
else
  bad "install_grype no longer pins the installed release via install.sh's TAG arg"
fi

echo
echo "── 2. S3 (grype half): all 3 spawns in image_scanner.go are built on a deadline ctx (the Go kill_on_drop) ──"
if bodyhas "$IMAGE_SCANNER" "^func ImageScannerInstallGrype\\(" 'ictx, cancel := context.WithTimeout(ctx, ' \
   && bodyhas "$IMAGE_SCANNER" "^func ImageScannerInstallGrype\\(" 'safecmd.Exec(ictx, "sh", "-c", cmd)' \
   && bodyhas "$IMAGE_SCANNER" "^func ImageScannerInstallGrype\\(" 'dctx, dcancel := context.WithTimeout(ctx, ' \
   && bodyhas "$IMAGE_SCANNER" "^func ImageScannerInstallGrype\\(" 'safecmd.Command(dctx, imageScannerGrypeBin, "db", "update")'; then
  ok "ImageScannerInstallGrype builds both its spawns (installer + db-update priming) on a deadline ctx"
else
  bad "ImageScannerInstallGrype runs one or both of its spawns without a deadline ctx — a timed-out install can orphan"
fi
if bodyhas "$IMAGE_SCANNER" "^func ImageScannerScanImage\\(" 'sctx, cancel := context.WithTimeout(ctx, ' \
   && bodyhas "$IMAGE_SCANNER" "^func ImageScannerScanImage\\(" 'safecmd.Command(sctx, imageScannerGrypeBin, image,'; then
  ok "ImageScannerScanImage builds the grype invocation on a deadline ctx"
else
  bad "ImageScannerScanImage runs grype without a deadline ctx — a timed-out scan can orphan"
fi

echo
echo "── 3. S2: sbom_scanner.go SbomScannerInstallSyft — pinned to a tag, not main ──"
if hasre "$SBOM_SCANNER" '^const sbomScannerSyftVersion = "v[0-9]'; then
  ok "sbomScannerSyftVersion is a pinned version-tag constant"
else
  bad "no pinned sbomScannerSyftVersion constant found"
fi
if bodyhas "$SBOM_SCANNER" "^func SbomScannerInstallSyft\\(" '/main/install.sh'; then
  bad "install_syft still fetches install.sh from the mutable main ref"
else
  ok "install_syft no longer fetches install.sh from /main/"
fi
if bodyhasre "$SBOM_SCANNER" "^func SbomScannerInstallSyft\\(" 'anchore/syft/%s/install\.sh \| sh -s -- -b %s %s",' \
   && bodyhasre "$SBOM_SCANNER" "^func SbomScannerInstallSyft\\(" '^[[:space:]]*sbomScannerSyftVersion, sbomScannerSyftDir, sbomScannerSyftVersion\)'; then
  ok "install_syft fetches install.sh from the pinned SYFT_VERSION tag ref"
else
  bad "install_syft's install.sh fetch is not pinned to SYFT_VERSION's ref"
fi
if bodyhasre "$SBOM_SCANNER" "^func SbomScannerInstallSyft\\(" 'sbomScannerSyftDir, sbomScannerSyftVersion\)$'; then
  ok "install_syft passes SYFT_VERSION as install.sh's TAG argument"
else
  bad "install_syft no longer pins the installed release via install.sh's TAG arg"
fi

echo
echo "── 4. S3 (syft half): both spawns in sbom_scanner.go are built on a deadline ctx ──"
if bodyhas "$SBOM_SCANNER" "^func SbomScannerInstallSyft\\(" 'ictx, cancel := context.WithTimeout(ctx, ' \
   && bodyhas "$SBOM_SCANNER" "^func SbomScannerInstallSyft\\(" 'safecmd.Exec(ictx, "sh", "-c", cmd)'; then
  ok "SbomScannerInstallSyft builds its spawn on a deadline ctx"
else
  bad "SbomScannerInstallSyft runs its installer without a deadline ctx"
fi
if bodyhas "$SBOM_SCANNER" "^func SbomScannerGenerateSbom\\(" 'sctx, cancel := context.WithTimeout(ctx, ' \
   && bodyhas "$SBOM_SCANNER" "^func SbomScannerGenerateSbom\\(" 'safecmd.Exec(sctx, sbomScannerSyftBin, image,'; then
  ok "SbomScannerGenerateSbom builds the syft invocation on a deadline ctx"
else
  bad "SbomScannerGenerateSbom runs syft without a deadline ctx — a timed-out SBOM run can orphan"
fi

echo
echo "── 5. S4: cms.go — a shared credential-file permission helper, wired into the 4 CMS installers that hold DB creds ──"
if bodyhasre "$CMS" "^func cmsSecureCredentialFile\\(" '"chmod", "640", path\)'; then
  ok "cmsSecureCredentialFile chmods its target to 640"
else
  bad "cmsSecureCredentialFile no longer chmods to 640 — the helper's own body changed shape"
fi
for pair in "CmsInstallLaravel:envFile" "CmsInstallCodeigniter:envFile"; do
  fn="${pair%%:*}"; var="${pair##*:}"
  if bodyhasre "$CMS" "^func $fn\\(" "cmsSecureCredentialFile\\($var\\)"; then
    ok "$fn now secures its .env file's permissions"
  else
    bad "$fn no longer calls cmsSecureCredentialFile on its .env file"
  fi
done
if bodyhas "$CMS" "^func CmsInstallDrupal\\(" 'cmsSecureCredentialFile(siteDir + "/web/sites/default/settings.php")'; then
  ok "CmsInstallDrupal secures drush's generated settings.php"
else
  bad "CmsInstallDrupal no longer secures settings.php's permissions"
fi
if bodyhas "$CMS" "^func CmsInstallJoomla\\(" 'cmsSecureCredentialFile(publicDir + "/configuration.php")'; then
  ok "CmsInstallJoomla secures the generated configuration.php"
else
  bad "CmsInstallJoomla no longer secures configuration.php's permissions"
fi
# Positive control: Symfony's install() takes no db_pass at all (confirmed by
# its own signature) — it must NOT be wired, or a future blanket copy-paste
# would be chmod'ing a file that was never proven to hold credentials here.
if ! bodyhas "$CMS" "^func CmsInstallSymfony\\(" "func CmsInstallSymfony(domain, title string)"; then
  bad "CmsInstallSymfony's signature changed (or it is gone) — this control can no longer see it; re-check whether it now takes DB creds"
elif bodyhas "$CMS" "^func CmsInstallSymfony\\(" "cmsSecureCredentialFile"; then
  bad "CmsInstallSymfony now calls cmsSecureCredentialFile — re-check whether Symfony's .env gained DB creds in this function (if so, this control is stale, not a regression)"
else
  ok "CmsInstallSymfony correctly left unwired (control: its own signature takes no db_pass)"
fi

echo
echo "── 6. S4: wordpress.go WordpressInstall — tightens wp-config.php after wp-cli writes it ──"
if bodyhas "$WORDPRESS" "^func WordpressInstall\\(" '"chmod", "640", path+"/wp-config.php")'; then
  ok "WordpressInstall chmods wp-config.php to 640"
else
  bad "WordpressInstall no longer tightens wp-config.php's permissions"
fi
if bodyhas "$WORDPRESS" "^func WordpressInstall\\(" "wordpressChownSite(path)" \
   && bodyhas "$WORDPRESS" "^func wordpressChownSite\\(" '"chown", "-R", "www-data:www-data", path'; then
  ok "WordpressInstall still chowns the site to www-data:www-data (positive control — the chown wasn't replaced, only supplemented)"
else
  bad "WordpressInstall no longer chowns the site at all — unrelated regression"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
