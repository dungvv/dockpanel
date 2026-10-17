#!/usr/bin/env bash
# Regression pins for s261 — the update path, and what driving it exposed.
#
# s260 shipped databases-in-backups. s261 asked the next question: does any of
# that reach the installs people already run? Driving a real v2.31.2 box up to
# v2.34.2 said yes — and the same box showed that git deploy had never worked
# on ANY hardened install, in three separate places, all the same shape: the
# agent runs ProtectSystem=strict + ProtectHome=yes, and the build path writes
# outside ReadWritePaths.
#
#   A. THE AGENT CAN WRITE WHAT ITS BUILD TOOLS NEED. `docker build` creates
#      $HOME/.docker and refuses to run without it; HOME=/root is an empty
#      read-only mount under the sandbox, so every Dockerfile deploy died at
#      "mkdir /root/.docker: read-only file system". The fix is one env var in
#      the shared helper, NOT a per-call-site patch — ~77 docker invocations go
#      through it and the one that got missed is how this stayed hidden.
#      Same shape twice more: nixpacks installed itself into /usr/local/bin and
#      cached into /var/cache/dockpanel, neither writable.
#   B. THE UPDATE'S AGENT CHECK ASKS THE AGENT. It curled an AUTHENTICATED
#      panel endpoint with no token, so it returned 401 and warned on every
#      update on every install — identically whether the agent was alive or
#      dead. A check that cannot distinguish those two states is not a check.
#   C. THE INSTALLER INSTALLS THE VERSION IT WAS GIVEN. install.sh reads
#      DOCKPANEL_VERSION and clones that ref; setup.sh, its only consumer,
#      always fetched releases/latest. `DOCKPANEL_VERSION=v2.31.2 install.sh`
#      built a v2.31.2 tree around v2.34.2 binaries and printed "v2.34.2".
#
# Go port: safecmd → panel/go/internal/agent/safecmd/safecmd.go, git build →
# internal/agent/services/git_build.go, the unit → internal/agent/services/
# dockpanel-agent.service (go:embed), deploy → services/deploy.go, the filler
# page → services/nginx.go (NginxPlaceholderMarker).
#
# These are SOURCE pins and need no running panel. The behavioural proof is in
# /home/ovidiu/dockpanel-update-path-drill-s261.md.
#   run: bash tests/git-deploy-sandbox-pin-e2e.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AG="$REPO/panel/go/internal/agent"
SAFECMD="$AG/safecmd/safecmd.go"
GITBUILD="$AG/services/git_build.go"
UNIT="$AG/services/dockpanel-agent.service"
UPDATE="$REPO/scripts/update.sh"
SETUP="$REPO/scripts/setup.sh"
INSTALL="$REPO/scripts/install.sh"
WEBINSTALL="$REPO/website/client/public/install.sh"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
has()  { grep -q  -- "$2" "$1" 2>/dev/null && ok "$3" || bad "$3"; }
hasE() { grep -qE -- "$2" "$1" 2>/dev/null && ok "$3" || bad "$3"; }
# Comment-blind variants. These pins describe the defects BY NAME in the
# comments that document each fix, so a raw grep would match the prose
# explaining the bug and pass while the code itself regressed.
#
# The comment marker is per-language: stripping `//` from a shell script would
# also eat every `http://` URL — which is exactly how the first draft of this
# file reported two false failures against correct code.
strip_comments() {
    case "$1" in
        *.go) grep -vE '^[[:space:]]*//' "$1" ;;  # whole-line only: "https://" lives in Go strings
        *)    sed -E 's|[[:space:]]*#.*$||'  "$1" ;;
    esac
}
code()   { strip_comments "$1" | grep -cE -- "$2" >/dev/null && ok "$3" || bad "$3"; }
nocode() { strip_comments "$1" | grep -cE -- "$2" >/dev/null && bad "$3" || ok "$3"; }

echo
echo "A. The agent can write what its build tools need"
has  "$SAFECMD" 'const DockerConfigDir = "/var/lib/dockpanel/docker"' \
     "the docker CLI config dir is a fixed path under /var/lib/dockpanel"
code "$SAFECMD" '"DOCKER_CONFIG=" \+ DockerConfigDir' \
     "safecmd's base env sets DOCKER_CONFIG (the env is cleared, so a unit Environment= cannot)"
# Rust had four helper families (async, sync, two unsandboxed); Go has two:
# Command (baseEnv, which Exec/Run and every sync/async caller share) and
# NewUnsandboxed (systemd-run --setenv).
BASEENV=$(strip_comments "$SAFECMD" | awk '/^func baseEnv\(/,/^}/')
CMDFN=$(strip_comments "$SAFECMD" | awk '/^func Command\(/,/^}/')
UNSB=$(strip_comments "$SAFECMD" | awk '/^func NewUnsandboxed\(/,/^}/')
grep -qF '"DOCKER_CONFIG=" + DockerConfigDir' <<<"$BASEENV" && grep -qF 'cmd.Env = baseEnv()' <<<"$CMDFN" \
  && grep -qF '"--setenv=DOCKER_CONFIG=" + DockerConfigDir' <<<"$UNSB" \
     && ok "every helper family sets it — Command (via baseEnv) and the unsandboxed systemd-run path" \
     || bad "every helper family sets it — Command (via baseEnv) and the unsandboxed systemd-run path"
hasE "$UNIT" 'ReadWritePaths=.*/var/lib/dockpanel' \
     "and /var/lib/dockpanel really is writable under the unit's sandbox"
nocode "$UNIT" 'ReadWritePaths=.*(/root|/usr/local/bin)' \
     "the fix did NOT widen the sandbox to /root or /usr/local/bin"

has  "$GITBUILD" 'gitBuildNixpacksBin       = "/var/lib/dockpanel/bin/nixpacks"' \
     "nixpacks installs inside ReadWritePaths, not /usr/local/bin"
has  "$GITBUILD" 'gitBuildNixpacksCacheRoot = "/var/lib/dockpanel/nixpacks-cache"' \
     "its build cache too (/var/cache/dockpanel was never in ReadWritePaths)"
nocode "$GITBUILD" 'mv /tmp/nixpacks /usr/local/bin' \
     "the download no longer moves the binary into a read-only prefix"
nocode "$GITBUILD" '/var/cache/dockpanel/nixpacks' \
     "no code path still points the cache at the unwritable location"
code "$GITBUILD" 'os\.Stat\(gitBuildNixpacksBin\); err == nil && fi\.Mode\(\)\.IsRegular\(\)' \
     "an already-downloaded nixpacks is found again (it is off the agent's PATH)"

echo
echo "B. The update's agent check asks the agent"
code "$UPDATE" 'curl .*--unix-socket .*AGENT_SOCK.*localhost/health' \
     "the check probes the agent's own socket"
nocode "$UPDATE" 'curl.*api/system/info' \
     "it no longer curls an authenticated panel endpoint with no token"
has  "$UPDATE" 'AGENT_SOCK=/run/dockpanel/agent.sock' \
     "the modern socket path is tried first"
has  "$UPDATE" 'AGENT_SOCK=/var/run/dockpanel/agent.sock' \
     "with the legacy path as fallback, so older boxes still probe correctly"
has  "$AG/routes/state.go" 'if r.URL.Path == "/health" {' \
     "and /health is genuinely exempt from the agent's auth middleware"

echo
echo "C. The installer installs the version it was given"
code "$SETUP" 'DOCKPANEL_VERSION' \
     "download_binaries reads the pin instead of ignoring it"
code "$SETUP" 'Pinned release' \
     "and says so, rather than printing a version it did not install"
code "$SETUP" 'releases/latest' \
     "unpinned installs still resolve the latest release"
code "$INSTALL" 'git clone .*-b "\$VERSION"' \
     "install.sh still selects the tree by the same variable"
[ -n "$(diff "$INSTALL" "$WEBINSTALL" 2>&1)" ] \
     && bad "the advertised website copy of install.sh matches scripts/install.sh" \
     || ok "the advertised website copy of install.sh matches scripts/install.sh"

echo
echo "D. The FIRST deploy of a panel-created site (s307)"
# s261 found that git deploy had never worked on a hardened install. s307 found
# that its first run had never worked on ANY install: creating a site writes a
# filler page into the document root, and git refuses a destination that exists
# and is not empty — so the opening deploy of every site the panel itself made
# failed, taking with it every step gated on a successful deploy.
#
# Windows are bound on the declaration's own closing brace, never on a fixed
# -A count, and an empty extraction FAILS rather than passing silently.
DEPLOYSVC="$AG/services/deploy.go"
NGINXSVC="$AG/services/nginx.go"
NGINXROUTE="$AG/routes/nginx.go"
for f in "$DEPLOYSVC" "$NGINXSVC" "$NGINXROUTE"; do [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }; done
fn_body() { perl -0777 -ne 'print $1 if /\n(func '"$2"'\(.*?\n\})\n/s' "$1"; }
nocmt() { grep -vE '^[[:space:]]*//'; }

CLONE_FN="$(fn_body "$DEPLOYSVC" DeployCloneOrPull)"
if [ "$(printf '%s' "$CLONE_FN" | wc -l)" -ge 40 ]; then
  ok "extracted the DeployCloneOrPull body ($(printf '%s' "$CLONE_FN" | wc -l) lines) — the arms below read real code"
else
  bad "could not extract DeployCloneOrPull — every arm below is vacuous"
fi

CLONE_DEST="$(printf '%s' "$CLONE_FN" | nocmt | grep -E 'deployGit\("clone",' || true)"
if [ -n "$CLONE_DEST" ] && ! grep -qE 'siteDir\)' <<< "$CLONE_DEST"; then
  ok "the fresh clone does not target the site directory git will refuse"
else
  bad "the fresh clone targets the populated site directory again — first deploy fails"
fi
printf '%s' "$CLONE_FN" | nocmt | grep -cE 'deploy-staging' >/dev/null \
  && ok "it stages beside the site, where nginx cannot serve a half-finished checkout" \
  || bad "the staging directory is gone — a partial clone is reachable over HTTP"
printf '%s' "$CLONE_FN" | nocmt | grep -cE 'deployForeignEntries\(' >/dev/null \
  && ok "a destination holding files the panel did not write is refused" \
  || bad "nothing checks the destination — a real site can be destroyed by a deploy"
printf '%s' "$CLONE_FN" | grep -cE 'Refusing to deploy into' >/dev/null \
  && ok "and the refusal names what it found instead of failing blank" \
  || bad "the refusal no longer tells the operator which files blocked it"

# The merge must be entry by entry. A whole-directory rename cannot work — the
# destination is non-empty, which is the entire reason this path exists — and
# the entries the clone does NOT supply must survive, or a repository with no
# public/ leaves a static site with no document root at all.
MERGE_FN="$(fn_body "$DEPLOYSVC" deployMergeInto)"
if [ -n "$MERGE_FN" ]; then
  ok "extracted the deployMergeInto body — the arms below read real code"
else
  bad "deployMergeInto is gone — the entries the clone does not supply are unprotected"
fi
printf '%s' "$MERGE_FN" | nocmt | grep -cE 'os\.ReadDir\(from\)' >/dev/null \
  && ok "the merge walks the staged clone entry by entry" \
  || bad "the merge no longer iterates — an unreplaced document root is at risk"
# An ABSENCE arm over a window that does not exist passes having examined
# nothing, which reads exactly like a clean sweep. Assert the subject first.
if [ -z "$MERGE_FN" ]; then
  bad "the whole-destination-wipe arm has no subject to read — it cannot report a catch"
elif printf '%s' "$MERGE_FN" | nocmt | grep -cE 'os\.RemoveAll\(to\)' >/dev/null; then
  bad "the merge clears the whole destination — a repo without public/ loses its document root"
else
  ok "the merge never clears the whole destination, so an unreplaced document root survives"
fi

# CLASS ARM, subjects derived FROM SOURCE. The filler page is WRITTEN when a
# site is created and READ BACK when a deploy decides whether a document root
# holds a real site. If those two ever spell it separately they can drift, and
# a deploy would then either refuse every fresh site or adopt an operator's
# file. Read the sentence out of the constant, then count it across the agent.
MARKER="$(perl -0777 -ne 'print $1 if /const NginxPlaceholderMarker = "([^"]+)"/' "$NGINXSVC")"
if [ -n "$MARKER" ]; then
  ok "the filler page's identifying sentence is declared once, as a constant"
else
  bad "NginxPlaceholderMarker is gone — the writer and the reader can drift apart"
fi
# An empty needle makes `grep -F` match every line, so the count arm would go
# red with a meaningless five-figure number and hide WHY. Guard it explicitly.
if [ -z "$MARKER" ]; then
  bad "the re-inlining arm has no sentence to count — blocked by the missing constant above"
else
  MARKER_N=$(grep -rF --include='*.go' -- "$MARKER" "$AG" 2>/dev/null | wc -l)
  if [ "$MARKER_N" -eq 1 ]; then
    ok "and nothing re-inlines it — $MARKER_N occurrence in panel/go/internal/agent, the declaration"
  else
    bad "the sentence appears $MARKER_N times in panel/go/internal/agent — writer and reader can now disagree"
  fi
fi
code "$NGINXSVC" 'os\.ReadFile\(path\)' \
     "the page is recognised by CONTENT — an operator's own index.html is not ours to delete"
code "$NGINXROUTE" 'services\.NginxPlaceholderPage\(' \
     "and put_site writes it through that same helper rather than a second literal"

# CLASS ARM: every path in this file that materialises a checkout on disk must
# hand it to the user the web server runs as. DeployAtomic always did; the
# non-atomic path never did, so a green deploy left a tree the application
# could not write to. Subjects are the clone invocations, found here rather
# than listed. (Rust needed to cut the file at its #[cfg(test)] module; Go
# tests live in deploy_test.go, so the whole comment-stripped file ships.)
SHIPPED=$(nocmt < "$DEPLOYSVC")
CHOWN_SUBJECTS=$(grep -cE 'deployGit\("clone",' <<< "$SHIPPED")
CHOWN_N=$(grep -cE 'deployHandTreeToWebUser\(' <<< "$SHIPPED")
# The helper is called once per shipped checkout path plus once at its own
# declaration, so the subject count is the callers.
CHOWN_CALLS=$(grep -cE '^\s*deployHandTreeToWebUser\(ctx, ' <<< "$SHIPPED")
if [ "$CHOWN_SUBJECTS" -ge 2 ] && [ "$CHOWN_CALLS" -ge "$CHOWN_SUBJECTS" ]; then
  ok "all $CHOWN_SUBJECTS shipped checkout paths reach deployHandTreeToWebUser"
else
  bad "$CHOWN_SUBJECTS shipped checkout paths but only $CHOWN_CALLS reach the handover — a deploy succeeds and the app cannot write"
fi

# PAIRED WITH THE ABOVE: the ownership work moved into a helper at v2.64.2, and
# an arm that only checks the callers reach it would stay green if the helper
# stopped doing the job. Both halves are pinned: the callers reach it, and it
# still hands the tree over.
HANDOVER="$(fn_body "$DEPLOYSVC" deployHandTreeToWebUser | nocmt)"
if [ "$CHOWN_N" -ge 3 ] \
   && grep -qE '"chown", "-R", "www-data:www-data"' <<< "$HANDOVER"; then
  ok "and deployHandTreeToWebUser still chowns the tree to www-data"
else
  bad "deployHandTreeToWebUser no longer chowns to www-data — every caller is now a no-op"
fi

# THE ESCALATION ARM. v2.64.0 chowned the whole checkout, `.git` included, and
# v2.64.1 then told git to accept a repository it did not own. Together those
# let a compromised site write `.git/config` and have root execute it on the
# next deploy — reproduced end to end with no hook file at all, via one
# `core.fsmonitor` line. The handover must therefore SKIP the repository, and
# take it back for root afterwards. Both halves, because either alone is the
# defect.
if grep -qE 'e\.Name\(\) == "\.git"' <<< "$HANDOVER" \
   && grep -qE '^\s*continue$' <<< "$HANDOVER"; then
  ok "the handover skips .git rather than handing the repository to the web user"
else
  bad "the handover no longer skips .git — the site can write config and hooks that root executes"
fi
if grep -qE '"chown", "-R", "root:root", gitDir\)' <<< "$HANDOVER" \
   && grep -qE '"chmod", "-R", "go-rwx", gitDir\)' <<< "$HANDOVER"; then
  ok "and the repository is taken back for root, unreadable to anyone else"
else
  bad "the repository is not reclaimed as root-only — a checkout inherited from v2.64.x stays writable"
fi

# The site directory carries the sticky bit, or the application can simply
# unlink a root-owned `.git` and leave a repository of its own in its place —
# which would defeat every arm above without touching one of them.
if grep -qE '"chmod", "3775", dir\)' <<< "$HANDOVER"; then
  ok "and the site directory is setgid+sticky, so the site cannot replace .git wholesale"
else
  bad "the site directory is not sticky — the application can unlink .git and plant its own"
fi

# A repository root does not own is DISCARDED, never repaired in place:
# chowning content the web user wrote back to root and then executing it is the
# same defect with an extra step.
if grep -qE 'deployDiscardRepoWeDoNotOwn\(siteDir' <<< "$CLONE_FN" \
   && grep -qE 'os\.RemoveAll\(gitDir\)' <<< "$(fn_body "$DEPLOYSVC" deployDiscardRepoWeDoNotOwn)"; then
  ok "a repository root does not own is discarded before any git runs against it"
else
  bad "a foreign repository is adopted rather than discarded — the escalation survives an upgrade"
fi


# CLASS ARM: git refuses a repository owned by somebody else; the v2.64.1
# "fix" was to declare every chowned path `safe.directory` at command scope,
# which WAS the escalation (see below). Subjects are GIT invocations, found,
# not listed: a `-C` handed to ssh-keygen (DeployGenerateDeployKey) means the
# key's COMMENT, not a directory, so `-C`s are classified by the program run.
CGIT=$(grep -cE '"git", deployGit\("-C",' <<< "$SHIPPED")
COTHER=$(grep -E '"-C",' <<< "$SHIPPED" | grep -cvE '"git", deployGit\("-C",')
CSAFE=$(grep -cE 'safe\.directory' <<< "$SHIPPED")
# ⚠ INVERTED AT v2.64.2, and the inversion is the point. This arm used to demand
# a `safe.directory` on every shipped `git -C`. That demand was the escalation:
# the exception exists to let root operate on a tree somebody else owns, and the
# somebody else here is the web user. The requirement is now the opposite — the
# ownership guard stays switched ON, and the repository is kept root's instead.
# (Go has 3 `git -C` sites, not Rust's 4: list_releases' rev-parse now shares
# deployShortHead with the deploy paths.)
if [ "${CGIT:-0}" -ge 3 ] && [ "${CSAFE:-0}" -eq 0 ]; then
  ok "none of the $CGIT shipped git -C invocations lifts the ownership guard ($COTHER non-git -C excluded by name)"
else
  bad "$CSAFE safe.directory uses across $CGIT shipped git -C invocations — root will run git out of a tree the site controls"
fi

# The suppression pair, on every shipped git invocation. Ownership is the real
# control; this is what protects a site upgrading from v2.64.x, whose repository
# was writable and may already carry a payload. Command scope beats repo config,
# so it is inert from the first deploy after this version.
GITCMDS=$(perl -0777 -ne '$n++ while /"git",\s*/g; print $n+0' <<< "$SHIPPED")
NOEXEC_N=$(perl -0777 -ne '$n++ while /"git",\s*deployGit\(/g; print $n+0' <<< "$SHIPPED")
if [ "$GITCMDS" -ge 4 ] && [ "$NOEXEC_N" -ge "$GITCMDS" ] && grep -qF 'append(append([]string{}, deployGitNoExec...), args...)' <<< "$SHIPPED"; then
  ok "all $GITCMDS shipped git invocations carry deployGitNoExec (via deployGit)"
else
  bad "$GITCMDS shipped git invocations but only $NOEXEC_N go through deployGit — repo config can still execute"
fi
if grep -qE 'core\.hooksPath=' <<< "$SHIPPED" && grep -qE '"core\.fsmonitor="' <<< "$SHIPPED"; then
  ok "and deployGitNoExec suppresses BOTH hooks and fsmonitor — a hook file is not the only vector"
else
  bad "deployGitNoExec no longer covers both vectors; core.fsmonitor alone needs no hook file and no executable bit"
fi

# The reset's exit status is READ. It was not, so a reset that failed — most
# reachably on a branch change over a checkout holding local commits — reported
# a successful deploy over the previous release.
if grep -qE 'if !reset\.Success\(\)' <<< "$SHIPPED"; then
  ok "a failed git reset fails the deploy instead of reporting success"
else
  bad "reset.Success() is never read — a failed reset still reports a successful deploy"
fi

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
