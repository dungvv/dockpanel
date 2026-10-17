#!/usr/bin/env bash
#
# Regression pin: no site of ANY runtime could ever be created on the RHEL
# family, and PHP sites specifically failed a layer earlier than that too.
#
# TWO independent, stacked defects, found in the same session by trying to
# actually create a PHP site on a real Rocky 9 box.
#
# Defect 1 — the PHP-FPM socket. A carried tech-debt note (many sessions old)
# claimed `settle()` was a false positive on RHEL — it is not;
# `socket_exists()`/`settle()` in php.rs were already RHEL-aware. The real gap
# was one layer downstream: `put_site()` in nginx.rs validated and
# existence-checked `php_socket` as a LITERAL path
# (`/run/php/php{version}-fpm.sock`, Debian-shaped), with no fallback to
# RHEL's actual, unversioned socket (`/run/php-fpm/www.sock`). So on a real
# Rocky/Alma/CentOS box, PHP-FPM would install and report running correctly —
# and creating the very next PHP site was flatly refused with "PHP {version}
# is not installed, or its PHP-FPM service is not running", a false and
# unactionable message (reinstalling PHP cannot fix a path assumption). Fixed
# by `services::pkg::resolve_php_fpm_socket()`, the single place that knows
# both families' socket layouts, which php.rs::socket_exists() and
# nginx.rs::put_site() both now call instead of re-implementing their own
# existence check. sites.rs's hardcoded Debian-shaped string is now just a
# VERSION CARRIER on the wire, not an assertion about the real path — the
# backend cannot know the target's distro, so it was never the right layer.
#
# Defect 2 — found immediately after fixing defect 1, by hitting the NEXT
# wall live: nginx's vhost directory itself. Debian ships
# `sites-available`/`sites-enabled`; the RHEL family's nginx package has
# NEITHER — its `nginx.conf` includes only `conf.d/*.conf`. Roughly 25 call
# sites across a dozen files hardcoded the literal Debian path independently
# (`vhost_paths()` itself, plus every SSL/git-deploy/Docker-app/diagnostics/
# security-scanner/IaC-export/WAF-uninstall reader and writer of a site's
# vhost), so on RHEL EVERY write failed `ENOENT` regardless of runtime —
# static, PHP, Node, Python, proxy, all of them. Fixed by
# `services::nginx::sites_dir_for()`/`vhost_paths_for()`, mirroring the same
# `[ -d /etc/nginx/sites-enabled ]` detection `setup.sh::configure_nginx`
# already used for the PANEL's own vhost, with every other call site
# propagated to the one shared function instead of its own copy.
#
# Live-fire proof, both defects, same Rocky Linux 9.8 box, real command:
#   pre-fix (published v2.172.0):  "PHP 8.3 is not installed..." (defect 1)
#   defect-1-fixed only:           "Failed to write config: No such file
#                                    or directory" (defect 2, freshly exposed)
#   both fixed:                    site created, vhost at
#                                    /etc/nginx/conf.d/{domain}.conf,
#                                    `fastcgi_pass unix:/run/php-fpm/www.sock`,
#                                    `nginx -t` clean, curl returned
#                                    `PHP_WORKS:8.3.33` with
#                                    `X-Powered-By: PHP/8.3.33` over HTTP 200.
# Disable/enable (park/unpark) re-driven on the same site: parked file lands
# at `{domain}.conf.disabled` in the SAME conf.d directory (RHEL has no
# separate sites-available), 503 maintenance page after a reload settles,
# PHP output returns unchanged after re-enable.
#
# Pure source analysis below: no box, no network, no build — the box above
# already proved the mechanism live; this suite pins the STRUCTURE so a
# future refactor cannot silently reintroduce either literal Debian-only
# check.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Go port names: resolve_php_fpm_socket → services.PkgResolvePhpFpmSocket,
# php.rs socket_exists/list_versions → phpSocketExists/phpListVersions,
# nginx put_site → nginxRoutes.putSite, sites_dir(_for)/vhost_paths(_for)/
# parked_dir_for → NginxSitesDir(For)/NginxVhostPaths(For)/NginxParkedDirFor,
# sites.rs's php_socket literal → rtSitesPHPSocket.
AG=panel/go/internal/agent
PKG_GO=$AG/services/pkg.go
PHP_GO=$AG/routes/php.go
NGINX_ROUTE_GO=$AG/routes/nginx.go
NGINX_SVC_GO=$AG/services/nginx.go
SITES_GO=panel/go/internal/api/rt_sites.go
OWNERSHIP_GO=$AG/services/ownership.go
GIT_BUILD_SVC_GO=$AG/services/git_build.go
DOCKER_APPS_ROUTE_GO=$AG/routes/docker_apps.go
DOCKER_APPS_SVC_GO=$AG/services/docker_apps.go
SERVICE_INSTALLER_GO=$AG/routes/service_installer.go
IAC_GO=$AG/routes/iac.go
SECURITY_SCANNER_GO=$AG/services/security_scanner.go
DIAGNOSTICS_GO=$AG/services/diagnostics.go
MAIL_GO=$AG/routes/mail.go
for f in "$PKG_GO" "$PHP_GO" "$NGINX_ROUTE_GO" "$NGINX_SVC_GO" "$SITES_GO" \
         "$OWNERSHIP_GO" "$GIT_BUILD_SVC_GO" "$DOCKER_APPS_ROUTE_GO" "$DOCKER_APPS_SVC_GO" \
         "$SERVICE_INSTALLER_GO" "$IAC_GO" "$SECURITY_SCANNER_GO" "$DIAGNOSTICS_GO" "$MAIL_GO"; do
  [ -f "$f" ] || { echo "MISSING SUBJECT FILE: $f"; exit 1; }
done

# Strip // line comments so an arm can't match its own explanatory prose
# (lesson #149) — the fix's comments deliberately name both families' paths.
strip() { sed 's://.*::' "$1"; }

SRC_PKG=$(strip "$PKG_GO")
SRC_PHP=$(strip "$PHP_GO")
SRC_NGINX_ROUTE=$(strip "$NGINX_ROUTE_GO")
SRC_NGINX_SVC=$(strip "$NGINX_SVC_GO")
SRC_OWNERSHIP=$(strip "$OWNERSHIP_GO")
SRC_MAIL=$(strip "$MAIL_GO")
SRC_SITES=$(strip "$SITES_GO")

# Here-strings, never pipelines: a `grep -q` closing the pipe SIGPIPEs the
# upstream sed, and pipefail turns that into a failed arm non-deterministically.
has()  { grep -qF -- "$2" <<< "$1"; }
hasE() { grep -qE -- "$2" <<< "$1"; }
fnbody() { awk "/$2/,/^}/" <<< "$1"; }
readable() { [ -n "$2" ] || bad "could not extract $1 — the arms reading it mean nothing"; }

# Run Go tests and require each named one to PASS (not merely exist).
gotest() {
  local pkg=$1; shift
  local re out t
  re="^($(IFS='|'; echo "$*"))\$"
  if ! command -v go >/dev/null 2>&1; then bad "go toolchain not found — cannot run $*"; return; fi
  out=$(cd panel/go && go test "$pkg" -run "$re" -count=1 -v 2>&1)
  for t in "$@"; do
    if grep -q -- "--- PASS: $t " <<< "$out"; then
      ok "$t runs and passes"
    else
      bad "$t is missing or failing: $(tail -3 <<< "$out" | tr '\n' ' ')"
    fi
  done
}

echo
echo "§1 one resolver knows both families' socket layouts"

RESOLVER=$(fnbody "$SRC_PKG" '^func PkgResolvePhpFpmSocket\(')
readable "PkgResolvePhpFpmSocket" "$RESOLVER"

if has "$RESOLVER" 'debian := "/run/php/php" + version + "-fpm.sock"'; then
  ok "the resolver checks the Debian versioned path"
else
  bad "the resolver does not check the Debian path — apt boxes would regress"
fi

if has "$RESOLVER" '"/run/php-fpm/www.sock"'; then
  ok "the resolver checks the RHEL unversioned path"
else
  bad "the resolver does not check RHEL's socket — the whole point of the fix"
fi

if hasE "$RESOLVER" 'if PkgInstalledPhpVersion\(\) == version && pkgExists\("/run/php-fpm/www\.sock"\)'; then
  ok "the RHEL branch confirms it's THIS version before trusting the unversioned socket"
else
  bad "no version confirmation on the RHEL branch — every version would claim the one live socket"
fi

echo
echo "§2 the two call sites share the resolver, not their own copies"

SOCKET_EXISTS=$(grep -A3 -E '^func phpSocketExists\(' <<< "$SRC_PHP")
readable "phpSocketExists" "$SOCKET_EXISTS"
if has "$SOCKET_EXISTS" 'return services.PkgResolvePhpFpmSocket(version) != ""'; then
  ok "php.go::phpSocketExists() delegates to the shared resolver"
else
  bad "php.go::phpSocketExists() re-implements its own check — the two can drift apart again"
fi

# The historical bug, pinned as an absence: putSite() must NOT independently
# stat the raw wire-format path as its verdict. It may still strip/parse the
# string to extract a version, but the EXISTENCE question has to go through
# the resolver.
PUT_SITE=$(fnbody "$SRC_NGINX_ROUTE" '^func \(n nginxRoutes\) putSite\(')
readable "putSite" "$PUT_SITE"

if hasE "$PUT_SITE" 'real := services\.PkgResolvePhpFpmSocket\(version\)'; then
  ok "putSite() resolves the real socket instead of trusting the literal path"
else
  bad "putSite() does not call the resolver — RHEL site creation is unfixed"
fi

# Go's spellings of "does this literal path exist": nginxExists/os.Stat/
# pkgExists on the wire string `sp` or the raw cfg.PhpSocket.
if hasE "$PUT_SITE" '(nginxExists|os\.Stat|pkgExists|os\.Lstat)\((sp|\*cfg\.PhpSocket|socketPath)\)'; then
  bad "putSite() still has the old literal-existence check — the RHEL bug is back"
else
  ok "the old Debian-only literal existence check is gone from putSite()"
fi

echo
echo "§3 a resolved RHEL socket naturally skips the Debian-only per-site pool"

# The per-site FPM pool feature (memory/worker limits) is Debian-shaped
# (/etc/php/{version}/fpm/pool.d) and out of scope for this fix. It must
# degrade to the shared pool on RHEL, not error — proven by the guard that
# gates it still matching only a Debian-shaped resolved socket.
POOL_BLOCK=$(awk '/var perSiteSocket \*string/,/if perSiteSocket != nil \{/' <<< "$SRC_NGINX_ROUTE")
readable "the per-site pool block" "$POOL_BLOCK"

if has "$POOL_BLOCK" 'strings.CutPrefix(*cfg.PhpSocket, "unix:/run/php/php")'; then
  ok "the per-site pool block only activates on a Debian-shaped resolved socket"
else
  bad "the per-site pool block's guard changed — verify it still excludes RHEL's resolved socket"
fi

# write_php_pool_config no-op arm retired: covered by TestPinRhelSiteCreationPoolConfigNoopsWithoutPoolD (panel/go/internal/agent/services/pin_rhel_site_creation_test.go)

echo
echo "§4 the backend's hardcoded string is documented as a version carrier"

# rt_sites.go cannot know the target server's distro, so it is correct for it
# to keep sending the Debian-shaped literal — but only if that's understood as
# an input to the resolver, not an assertion of the real path. The Go port
# folded the four construction sites into one documented helper,
# rtSitesPHPSocket; pin the comment on the helper AND that every construction
# site goes through it (a fresh inline literal would carry no such contract).
CARRIER=$(grep -B4 -E '^func rtSitesPHPSocket\(' "$SITES_GO")
if has "$CARRIER" 'VERSION CARRIER'; then
  ok "rtSitesPHPSocket documents the version-carrier contract"
else
  bad "rtSitesPHPSocket no longer documents the version-carrier contract"
fi
carrier_sites=$(grep -cE 'rtSitesPHPSocket\(\*' <<< "$SRC_SITES" || true)
inline=$(grep -E 'unix:/run/php/php' <<< "$SRC_SITES" | grep -vcE '^func rtSitesPHPSocket\(' || true)
if [ "$carrier_sites" -ge 4 ] && [ "$inline" -eq 0 ]; then
  ok "all $carrier_sites php_socket construction sites go through the documented carrier"
else
  bad "only $carrier_sites of the 4 known php_socket construction sites use rtSitesPHPSocket ($inline inline literal(s))"
fi

echo
echo "§5 the version-status API stops advertising a socket that may not be real"

LIST_VERSIONS=$(fnbody "$SRC_PHP" '^func phpListVersions\(')
readable "phpListVersions" "$LIST_VERSIONS"
if has "$LIST_VERSIONS" 'real = services.PkgResolvePhpFpmSocket(v)'; then
  ok "the versions API reports the real resolved socket, not a Debian-only guess"
else
  bad "the versions API still hardcodes the Debian socket path in its response"
fi

echo
echo "§6 the nginx vhost directory itself — no site of ANY runtime worked on RHEL"

# sites_dir_for both-directories arm retired: covered by TestPinRhelSiteCreationSitesDirFor (panel/go/internal/agent/services/pin_rhel_site_creation_test.go)

# Split-for-testability: the pure decision takes a bool so a test needs no
# nginx installed. A version that probed the filesystem directly would pass or
# fail by accident of whether the CI runner has nginx — pin against that
# regression explicitly.
if hasE "$SRC_NGINX_SVC" '^func NginxSitesDir\(\) string \{ return NginxSitesDirFor\(nginxUsesSitesEnabled\(\)\) \}'; then
  ok "the real-filesystem wrapper delegates to the pure, testable decision"
else
  bad "NginxSitesDir() does not delegate to NginxSitesDirFor (or is gone) — the decision is no longer testable without nginx installed"
fi

VHOST_PATHS_FOR=$(fnbody "$SRC_NGINX_SVC" '^func NginxVhostPathsFor\(')
readable "NginxVhostPathsFor" "$VHOST_PATHS_FOR"
if has "$VHOST_PATHS_FOR" 'dir := NginxSitesDirFor(usesSitesEnabled)'; then
  ok "NginxVhostPathsFor shares the same directory decision, not a second copy"
else
  bad "NginxVhostPathsFor re-derives the directory instead of sharing NginxSitesDirFor"
fi
# vhost_paths_for branch arm retired: covered by TestBothPathsComeFromOneFunctionSoTheyCannotDrift + TestTheRhelFamilyHasNoSecondDirectorySoBothPathsShareConfD (panel/go/internal/agent/services/nginx_test.go)
gotest ./internal/agent/services/ TestBothPathsComeFromOneFunctionSoTheyCannotDrift TestTheRhelFamilyHasNoSecondDirectorySoBothPathsShareConfD TestPinRhelSiteCreationSitesDirFor TestPinRhelSiteCreationPoolConfigNoopsWithoutPoolD TestPinRhelSiteCreationParkedDirSharesConfD TestASingleSharedDirectoryIsNotScannedTwice

echo
echo "§7 every other reader/writer of a site's vhost shares the one decision, not its own copy"

# The class of defect: ~25 call sites across a dozen files independently
# hardcoded the Debian path. Each subject below must call through
# NginxSitesDir() — or, s449, through NginxVhostPaths()/NginxVhostTargetFor(),
# which themselves resolve through NginxSitesDirFor and additionally know the
# PARKED path NginxSitesDir() alone does not — rather than spelling
# /etc/nginx/sites-enabled itself. mail.go is a deliberate exception — it
# already tried both literal paths for the PANEL's own vhost before this fix
# existed, which is a different (already-correct) shape.
declare -A PROPAGATION=(
  ["ssl.go (routes)"]="$AG/routes/ssl.go"
  ["ownership.go"]="$OWNERSHIP_GO"
  ["git_build.go (services)"]="$GIT_BUILD_SVC_GO"
  ["docker_apps.go (routes)"]="$DOCKER_APPS_ROUTE_GO"
  ["docker_apps.go (services)"]="$DOCKER_APPS_SVC_GO"
  ["service_installer.go"]="$SERVICE_INSTALLER_GO"
  ["iac.go"]="$IAC_GO"
  ["security_scanner.go"]="$SECURITY_SCANNER_GO"
  ["diagnostics.go"]="$DIAGNOSTICS_GO"
)
for label in "${!PROPAGATION[@]}"; do
  f="${PROPAGATION[$label]}"
  src=$(strip "$f")
  if hasE "$src" '"/etc/nginx/sites-enabled/'; then
    bad "$label still hardcodes the Debian vhost directory literally"
  elif hasE "$src" 'NginxSitesDir\(\)|NginxVhostPaths\(|NginxVhostTargetFor\('; then
    ok "$label reads the vhost directory through the shared decision"
  else
    bad "$label neither hardcodes nor calls NginxSitesDir()/NginxVhostPaths()/NginxVhostTargetFor() — re-derive what changed"
  fi
done

# mail.go is the one file that got this right BEFORE the fix existed — it
# tries both literal paths for the panel's own vhost. Pin that this is still
# true, as a control: if this ever regresses to hardcoding one path, the
# panel's own webmail-domain detection breaks on whichever family it drops.
if hasE "$SRC_MAIL" '"/etc/nginx/sites-enabled/dockpanel-panel.conf"' && hasE "$SRC_MAIL" '"/etc/nginx/conf.d/dockpanel-panel.conf"'; then
  ok "mail.go's pre-existing dual-path check for the panel's own vhost is still intact (control)"
else
  bad "mail.go no longer tries both families for the panel's own vhost"
fi

echo
echo "§8 the parked (disabled) directory: RHEL shares one dir, and a shared-dir scan is not double-counted"

# parked_dir_for RHEL-branch arm retired: covered by TestPinRhelSiteCreationParkedDirSharesConfD (panel/go/internal/agent/services/pin_rhel_site_creation_test.go)

REGISTRY_REFS=$(fnbody "$SRC_OWNERSHIP" '^func ownershipRegistryNeedleReferences\(')
readable "ownershipRegistryNeedleReferences" "$REGISTRY_REFS"
if hasE "$REGISTRY_REFS" 'if parkedDir == liveDir \{'; then
  ok "a shared live/parked directory short-circuits before the second scan"
else
  bad "no guard against scanning the same directory twice — RHEL would double-count every match"
fi
# double-scan unit-test arm: now executed in §6's gotest (TestASingleSharedDirectoryIsNotScannedTwice).

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
