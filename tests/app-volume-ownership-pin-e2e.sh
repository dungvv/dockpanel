#!/usr/bin/env bash
#
# Regression pin for VOLUME OWNERSHIP on one-click app templates, and for the
# nineteenth unresolvable image reference.
#
# WHAT HAPPENED. `deploy_app` creates every declared volume as a directory under
# APP_DATA_DIR, running as root, mode 0755, and bind-mounts it. Nothing chowned
# it. That is correct for most images — they start as root and chown their own
# data directory in their entrypoint, which is exactly what postgres, mysql and
# mongo do before dropping privileges.
#
# It is wrong for an image that declares a non-root `Config.User`, because that
# process starts ALREADY DROPPED and can never chown its way out. It cannot write
# the directory the template just mounted for it.
#
# MEASURED, not argued. Every catalogue image's config blob was read from the
# registry (no pulls) at s342: 42 of 148 images run non-root, and 31 of those
# declare a volume — 21% of the catalogue could not persist a byte. Proven end to
# end on prom/prometheus:v3, whose `Config.User` is the NAME `nobody`:
#
#   root-owned 0755 dir (what deploy_app made)  -> exited 1, "permission denied"
#                                                  on /prometheus/queries.active,
#                                                  ZERO files in the volume
#   chowned to the uid the image itself names   -> running, FIVE files including
#                                                  the WAL and the lock
#
# WHY THE FIX IS SHAPED THE WAY IT IS. `Config.User` is frequently a NAME, and a
# name is defined by the image's own /etc/passwd and by nothing on the host — 24
# of the 31 victims name a user rather than a uid. So the resolver reads
# /etc/passwd out of the image itself, by creating a container and copying the
# file out without ever starting it. The two lazy alternatives are both refused
# on purpose: 0777 would put a world-writable data directory on a host that runs
# other people's containers, and guessing a uid hands one tenant's data to
# another account. When the name cannot be resolved the directory is left
# root-owned and the agent says so — the same state as before, but no longer a
# silent one.
#
# ALSO PINNED HERE: the Readarr template, withdrawn s342. Its image published an
# OCI index with ZERO manifests on both tags, so `docker pull` exited 1 while the
# Sonarr and Radarr controls returned four manifests each, and upstream is
# archived. ⚠ v2.96.0's sweep could not see this class: the manifest request
# returns HTTP 200 with a well-formed index that merely happens to be empty, and
# that sweep classified by error MESSAGE. An absence arm keeps it withdrawn.
#
# WRAP TOLERANCE. Every arm that reads the Go source canonicalises it by
# deleting whitespace first, and no pattern ever spells a CLOSING delimiter —
# that is where a formatter inserts its trailing comma, and spelling one is how
# #384 got shipped into the suite written to pin #384, twice (lessons #384,
# #391). (Subject moved from the Rust services/docker_apps.rs to
# panel/go/internal/agent/services/docker_apps.go.)
#
# PROSE SAFETY. Arms run against COMMENT-STRIPPED source, because this file's own
# header narrates the very tokens it searches for, and the subject file carries a
# comment explaining the withdrawal (lesson #149, [[feedback_source_pin_prose_trap]]).
#
# Pure source analysis: no box, no network, no build, no Docker daemon.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

CATALOGUE=panel/go/internal/agent/services/docker_apps.go
TESTFILE=panel/go/internal/agent/services/docker_apps_test.go
[ -f "$CATALOGUE" ] || { echo "missing $CATALOGUE"; exit 1; }

# Strip line comments only. A block-comment stripper is what deleted 485 lines of
# real code until s294 (a `/*` inside a string literal opened a comment that ran
# to the next `*/`), so this deliberately does the narrow, safe thing: `//` at
# line start or after whitespace, so `https://` inside a literal survives.
code() { sed -E 's:(^|[[:space:]])//.*$::' "$1"; }

CODE=$(code "$CATALOGUE")
# Canonical form: whitespace deleted, so the single-line and the wrapped
# spellings are the same string.
FLAT=$(printf '%s' "$CODE" | tr -d ' \t\n')

# One Go func body out of the comment-stripped source, bounded by its own
# closing `}` at column 0, then flattened.
fnflat() {
  awk -v fn="$1" '
    !s && (index($0, "func " fn "(") == 1) { s=1 }
    s { print; if ($0 == "}") exit }
  ' <<< "$CODE" | tr -d ' \t\n'
}

echo "§0 the subject parses (a truncated subject must not read as a clean sweep)"

DECLS=$(printf '%s\n' "$CODE" | awk '/^var dockerAppsTemplates = /{i=1;next} i&&/^}/{exit} i&&/^\t\tID: +"/{n++} END{print n+0}')
if [ "$DECLS" -ge 100 ]; then
  ok "catalogue parsed: $DECLS template declarations survive the strip"
else
  bad "catalogue did not parse — only $DECLS declarations; every arm below is meaningless"
fi

STRIPPED_LINES=$(printf '%s\n' "$CODE" | wc -l)
RAW_LINES=$(wc -l < "$CATALOGUE")
if [ "$STRIPPED_LINES" -eq "$RAW_LINES" ]; then
  ok "comment strip removed no LINES ($RAW_LINES) — it cannot have eaten a declaration"
else
  bad "comment strip changed the line count ($RAW_LINES -> $STRIPPED_LINES)"
fi

echo
echo "§1 DockerAppsDeployApp works out who the volume belongs to BEFORE it creates one"

DEPLOY=$(fnflat DockerAppsDeployApp)
case "$DEPLOY" in
  *'varvolumeOwner*DockerAppsVolumeOwneriflen(template.Volumes)>0{'*'for_,vol:=rangetemplate.Volumes{'*)
    ok "ownership is resolved once per deploy, before the volume loop, not once per volume" ;;
  *) bad "DockerAppsDeployApp does not resolve a volume owner before the volume loop" ;;
esac

case "$DEPLOY" in
  *'volumeOwner=DockerAppsResolveVolumeOwner(ctx,docker,template.Image)'*)
    ok "the resolver is called with the template's own image" ;;
  *) bad "DockerAppsResolveVolumeOwner is never called on the deploy path" ;;
esac

case "$FLAT" in
  *'info.Config.User'*) ok "the owner comes from the image's own Config.User" ;;
  *) bad "nothing reads Config.User — the uid can only be a guess" ;;
esac

echo
echo "§2 the chown lands AFTER the prefix check, never before"

# The canonicalisation check is what proves the path is one of ours. A chown is
# precisely the operation a symlink escape would want to borrow, so its position
# relative to that check is load-bearing, not stylistic.
ESCAPE_AT=$(printf '%s\n' "$CODE" | grep -n 'escapes allowed prefix' | head -1 | cut -d: -f1)
CHOWN_AT=$(printf '%s\n' "$CODE" | grep -n 'DockerAppsChownTo(resolved, volumeOwner)' | head -1 | cut -d: -f1)
if [ -n "$ESCAPE_AT" ] && [ -n "$CHOWN_AT" ] && [ "$CHOWN_AT" -gt "$ESCAPE_AT" ]; then
  ok "chown at line $CHOWN_AT follows the prefix check at line $ESCAPE_AT"
else
  bad "chown does not follow the prefix check (escape=$ESCAPE_AT chown=$CHOWN_AT)"
fi

case "$DEPLOY" in
  *'resolved,err:=filepath.EvalSymlinks(hostDir)'*'DockerAppsChownTo(resolved,volumeOwner)'*)
    ok "the chown targets the CANONICALISED path, not the path as written" ;;
  *) bad "the chown does not target the canonicalised path" ;;
esac

echo
echo "§3 a NAME is resolved from inside the image — the whole point of the fix"

case "$FLAT" in
  *'dockerAppsReadFileFromImage(ctx,docker,image,"/etc/passwd")'*)
    ok "login names resolve from the image's own /etc/passwd" ;;
  *) bad "nothing reads /etc/passwd from the image; a name can only be guessed" ;;
esac

case "$FLAT" in
  *'dockerAppsReadFileFromImage(ctx,docker,image,"/etc/group")'*)
    ok "group names resolve from the image's own /etc/group" ;;
  *) bad "nothing reads /etc/group from the image" ;;
esac

# The probe must never START the container it creates to read a file out of.
# In Go the probe is dockerAppsCopyOutOfImage, which dockerAppsReadFileFromImage
# (and the volume seeder) call.
PROBE=$(fnflat dockerAppsCopyOutOfImage)
case "$(fnflat dockerAppsReadFileFromImage)" in
  *'dockerAppsCopyOutOfImage('*) PROBE_WIRED=1 ;;
  *) PROBE_WIRED=0 ;;
esac
if [ -z "$PROBE" ] || [ "$PROBE_WIRED" = 0 ]; then
  bad "could not isolate dockerAppsCopyOutOfImage as the file probe — the arm below would pass on nothing"
elif ! grep -q 'ContainerCreate(' <<<"$PROBE"; then
  bad "the probe no longer creates a container — re-read it before trusting the absence arm"
elif grep -q 'ContainerStart' <<<"$PROBE"; then
  bad "the file probe STARTS the container; it must only create and remove it"
else
  ok "the file probe never starts the container it reads from"
fi

case "$PROBE" in
  *'ContainerRemove('*) ok "the probe container is always removed again" ;;
  *) bad "the probe container is never removed — every deploy would leak one" ;;
esac

echo
echo "§4 the two refused shortcuts stay refused"

# 0777 on a multi-tenant host, and a guessed uid, are the two cheap fixes that
# would have made this a one-line change. Neither may appear.
if grep -qE '0o777|0777' <<<"$FLAT"; then
  bad "a world-writable mode appears in the catalogue — that is the refused shortcut"
else
  ok "no world-writable fallback anywhere in the file"
fi

# Recursion is allowed in exactly ONE place and refused everywhere else, and the
# difference is what is underneath rather than a matter of taste.
#
#   the deploy  may be pointed at a directory a previous deployment wrote, so it
#               chowns the directory ITSELF and nothing below it.
#   the migration has just refused to touch a non-empty directory and then filled
#               it with `docker cp`, so every path below it is one it created
#               seconds ago — and it must chown all of them, because `docker cp`
#               writes them as root (#110, s360).
#
# ⚠ THE ARM THIS REPLACES WAS A FALSE GREEN. It grepped for `chown-R`, `WalkDir`
# or one exact `read_dir().map()` spelling, so it printed "the chown is not
# recursive" against a file that had just grown a recursive chown written as an
# ordinary stack walk. An absence arm keyed on three spellings of a thing cannot
# see the fourth (lesson #490). Count the CALL SITES instead — a name has one
# spelling and the compiler enforces it.
#
# "shipping half isolated" retired (obsolete in Go): tests live in
# docker_apps_test.go, so the whole subject file is shipping code.

RECURSIVE_CALLS=$(printf '%s' "$FLAT" | grep -o 'dockerAppsChownMigratedTree(' | wc -l)
if [ "$RECURSIVE_CALLS" -eq 2 ]; then
  ok "the recursive chown has exactly one call site plus its definition"
else
  bad "dockerAppsChownMigratedTree appears $RECURSIVE_CALLS times in shipping code, expected 2 — a second caller means some other path recurses over a directory it did not create"
fi

case "$(fnflat DockerAppsChownTo)" in
  *'os.Chown(path,'*) ok "the DEPLOY path's chown (DockerAppsChownTo) is the non-recursive os.Chown" ;;
  *) bad "DockerAppsChownTo no longer a single non-recursive os.Chown" ;;
esac

if grep -qE 'chown-R|"chown","-R"' <<<"$FLAT"; then
  bad "a shell 'chown -R' appears; recursion must be the walk that refuses to follow symlinks"
else
  ok "no shell chown -R anywhere in the file"
fi

echo
echo "§4b the migration chowns what it wrote, and cannot walk out through a symlink"

# GitHub #110, second act. v2.111.0 rescued the data out of the writable layer and
# then handed it back owned by root, so every non-root image died on its first
# write — n8n on `EACCES .../crash.journal`, then `SQLITE_READONLY`. Reproduced end
# to end at s360 with the real image before any of this was written.
case "$FLAT" in
  *'dockerAppsChownMigratedTree(resolved,owner)'*)
    ok "the migration chowns the whole tree it just created" ;;
  *) bad "the migration does not chown its tree — docker cp wrote it as root, so a non-root app cannot write the data just rescued (#110)" ;;
esac

# "the walk stats without following symlinks" and "entries are lchowned"
# retired: covered by TestTheMigratedChownReachesEveryFileAndNeverFollowsASymlink
# (panel/go/internal/agent/services/docker_apps_test.go)

# The precondition that BOUNDS the recursion. If this refusal ever goes, the walk
# above stops being a walk over files we created and becomes one over somebody
# else's data. The two must never drift apart.
case "$FLAT" in
  *'Refusingtomigrate'*)
    ok "the migration still refuses a non-empty directory — what makes the recursion bounded" ;;
  *) bad "the non-empty refusal is gone, so the recursive chown is no longer bounded by construction" ;;
esac

echo
echo "§4c the repair reaches installs the migration already broke — on ALL three doors"

# v2.113.2 fixed the migration and could not undo it: the migration runs only for a
# volume that is MISSING, and the bad migration is what supplied the mount. So the
# harmed population and the fixed population were disjoint, and the only remedy was
# an operator running chown -R over SSH. This is the half that reaches them.
REPAIR_CALLS=$(printf '%s' "$FLAT" | grep -o 'dockerAppsRepairRootOwnedVolumes(' | wc -l)
if [ "$REPAIR_CALLS" -eq 4 ]; then
  ok "the repair is wired to all three recreate doors (plus its definition)"
else
  bad "dockerAppsRepairRootOwnedVolumes appears $REPAIR_CALLS times in shipping code, expected 4 — DockerAppsUpdateApp, DockerAppsChangeContainerImage and DockerAppsUpdateEnv must ALL call it or one door silently leaves apps broken"
fi

# "the repair reclaims ONLY root-owned paths" retired: covered by TestTheRepairTouchesOnlyRootOwnedPaths
# "the walk opens each entry O_NOFOLLOW" / "stats each entry fd-relative" retired: covered by
#   TestOpenatNofollowRefusesASymlinkEvenThoughItIsOpenedAsADirectory and
#   TestTheRepairNeverFollowsASymlinkStandingWhereADirectoryWasListed
# "the walk skips a root-owned entry with more than one link" retired: covered by
#   TestTheRepairSkipsARootOwnedEntryThatHasMoreThanOneLink
# (all in panel/go/internal/agent/services/docker_apps_test.go)

REPAIR_BODY=$(fnflat dockerAppsRepairRootOwnedVolumes)
if [ -z "$REPAIR_BODY" ]; then
  bad "could not isolate dockerAppsRepairRootOwnedVolumes — the arms below would pass on nothing"
else
  # Root-run images have nothing to repair, and the resolver is what says so.
  case "$REPAIR_BODY" in
    *'owner:=DockerAppsResolveVolumeOwner(ctx,docker,image)ifowner==nil{'*)
      ok "a root-run image is skipped — the resolver's nil is the discriminator" ;;
    *) bad "the repair does not consult DockerAppsResolveVolumeOwner, so it would act on root-run images" ;;
  esac
  # Same prefix discipline as every other writer into the app data dir.
  case "$REPAIR_BODY" in
    *'filepath.EvalSymlinks('*'strings.HasPrefix(resolved,prefix)'*)
      ok "the repair canonicalises and re-checks the app-data prefix" ;;
    *) bad "the repair writes without canonicalising and re-checking the prefix" ;;
  esac
fi

# "root images are recognised" / "an empty Config.User is treated as root"
# retired: covered by TestRootUserSpecsAreRecognisedInEverySpelling (run in §7)
case "$(fnflat DockerAppsResolveVolumeOwner)" in
  *'ifdockerAppsUserSpecIsRoot(spec){returnnil'*) ok "a root image is left completely alone by the resolver" ;;
  *) bad "the resolver does not short-circuit on a root user spec, so every deploy would chown" ;;
esac

echo
echo "§5 the nineteenth dead image reference stays withdrawn"

case "$FLAT" in
  *'ID:"readarr"'*) bad "the Readarr template is back; its image publishes no manifests" ;;
  *) ok "the Readarr template is absent from the catalogue" ;;
esac

case "$FLAT" in
  *'linuxserver/readarr'*) bad "the dead image reference is back in the catalogue" ;;
  *) ok "the dead image reference does not appear in the catalogue" ;;
esac

# Positive control: the sibling LinuxServer templates that DO resolve must still
# be there, or this section would pass by the catalogue having been emptied.
for sibling in 'linuxserver/sonarr' 'linuxserver/radarr'; do
  case "$FLAT" in
    *"$sibling"*) ok "control: $sibling is still present" ;;
    *) bad "control: $sibling vanished — the arms above prove nothing" ;;
  esac
done

echo
echo "§6 the published template count agrees with the catalogue"

# The count is derived, never typed. FEATURES.md owns it; every other surface
# copies from there, and a number copied to a second surface is rot by
# construction unless something checks them together.
N=$DECLS
CLAIMED=$(grep -oE '^\| App templates \| [0-9]+' FEATURES.md | grep -oE '[0-9]+$' | head -1)
if [ -n "$CLAIMED" ] && [ "$N" = "$CLAIMED" ]; then
  ok "catalogue holds $N templates and FEATURES.md claims $CLAIMED"
else
  bad "catalogue holds $N templates but FEATURES.md claims ${CLAIMED:-nothing}"
fi

echo
echo "§7 the resolver's parsing is unit-tested where a mistake is silent"

# The parsers are only worth pinning if their tests still RUN and pass — run them.
UNIT='^(TestRootUserSpecsAreRecognisedInEverySpelling|TestALoginNameResolvesFromTheImagesOwnPasswd|TestTheTarReaderExtractsAFileAndRefusesJunk|TestVolumeOwnerResolvesRealImagesBothWays)$'
GT=$(cd panel/go && go test ./internal/agent/services/ -run "$UNIT" -count=1 -v 2>&1)
for t in TestRootUserSpecsAreRecognisedInEverySpelling TestALoginNameResolvesFromTheImagesOwnPasswd TestTheTarReaderExtractsAFileAndRefusesJunk; do
  if grep -q -- "--- PASS: $t " <<<"$GT"; then
    ok "unit test passes: $t"
  else
    bad "unit test missing or failing: $t"
  fi
done
# The real-image test needs a Docker daemon (DOCKER_TESTS=1); here it must at
# least exist and compile, which a SKIP proves.
if grep -qE -- "--- (PASS|SKIP): TestVolumeOwnerResolvesRealImagesBothWays " <<<"$GT"; then
  ok "unit test present: TestVolumeOwnerResolvesRealImagesBothWays (daemon-gated)"
else
  bad "unit test missing: TestVolumeOwnerResolvesRealImagesBothWays"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32mPASS %d  FAIL 0\033[0m\n' "$PASS"
else
  printf '\033[0;31mPASS %d  FAIL %d\033[0m\n' "$PASS" "$FAIL"
fi
exit $((FAIL > 0))
