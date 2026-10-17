#!/usr/bin/env bash
# container-identity-pin-e2e.sh — s297 / v2.55.0
#
# A container name is not a key anybody owns.
#
# `dockpanel-git-{X}` is written for a deployment called X. It was ALSO written
# for a preview of config C on branch B whenever `{C}-pr-{slug(B)}` spelled X —
# and `is_valid_name` accepts that name, so an admin creates it by ordinary
# means while the branch half is chosen by whoever can push to C's repo. The
# agent resolved the container by NAME ALONE, then blue-greened it: it read the
# domain off the container it had just found, swapped THAT domain's vhost to the
# pushed build, and force-removed the container behind it. The v2.53.0 ownership
# guard authorised the vhost write, correctly — the victim's container really
# was the one behind the victim's vhost. `services::ownership` had five
# primitives and every one of them read a file; the largest thing the agent
# destroys had none.
#
#   §A  TWO NAME SPACES, AND THEY CANNOT INTERSECT. A preview is scoped by a
#       character `is_valid_name` rejects, so no deployment can spell one. The
#       arm that fails if the whole separation is undone.
#   §B  A CONTAINER PROVES IT IS THE ONE ASKED FOR. Not "a container with this
#       name exists" — who does it say it belongs to, and does the answer permit
#       what is about to happen to it.
#   §C  THE STAND-IN SPACE IS NOT A REAL NAME EITHER. `{name}-blue` is a name
#       `is_valid_name` accepts, and the swap force-removed whatever held it.
#   §D  A COMMIT PHASE REPORTS. Destroy-then-rename with both results discarded
#       returned Ok over a half-swapped host and armed the next deploy to take
#       the site down.
#   §E  A MASK IS NOT A VALUE. The edit dialog is seeded from the masked read and
#       posts it back; the container is the only store of the real one.
#   §F  THE v2.53.0 GUARD REACHES THE PATHS IT MISSED. Rename, and the three
#       systemd lifecycle callers.
#   §G  AN UNATTENDED SWEEP DOES NOT ORPHAN WHAT IT FAILED TO REMOVE.
#
# Subjects are the Go tree: panel/go/internal/agent/services/{ownership,
# git_build,docker_apps,app_process}.go, agent/routes/{git_build,docker_apps,
# nginx,http}.go, and panel/go/internal/api/{rt_git_deploys,
# svc_preview_cleanup,core_router}.go. Arms whose property is a pure decision
# (an ownership verdict, a mask merge) are retired to the Go unit tests that
# assert it.
#
# Pure source analysis: no box, no network, no build.
#
# Arms are written against the CAPABILITY a regression must use, not today's
# spelling (lesson #122), and were attacked after they went green (lesson #132).
# Where an arm can be satisfied by the prose that NARRATES a check rather than
# the check, it keys on the syntax of the operation (lesson #149).
#
# NO PIPES INTO `grep -q`. Under `set -o pipefail` grep -q closes the pipe on its
# first match, the upstream dies of SIGPIPE (141), and pipefail reports the whole
# pipeline failed — so an arm goes red on correct code, non-deterministically.
# Every arm here feeds grep a here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33m-\033[0m SKIP %s\n' "$1"; }

OWN=panel/go/internal/agent/services/ownership.go
GB=panel/go/internal/agent/services/git_build.go
GBR=panel/go/internal/agent/routes/git_build.go
DA=panel/go/internal/agent/services/docker_apps.go
DAR=panel/go/internal/agent/routes/docker_apps.go
NGX=panel/go/internal/agent/routes/nginx.go
APROC=panel/go/internal/agent/services/app_process.go
GD=panel/go/internal/api/rt_git_deploys.go
PCL=panel/go/internal/api/svc_preview_cleanup.go
MOD=panel/go/internal/api/core_router.go
AMOD=panel/go/internal/agent/routes/http.go
APPS_TSX=panel/frontend/src/pages/Apps.tsx

for f in "$OWN" "$GB" "$GBR" "$DA" "$DAR" "$NGX" "$APROC" "$GD" "$PCL" "$MOD" "$AMOD" "$APPS_TSX"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT. Copied from the FIXED stripper (lesson #136): the
# naive `s{/\*.*?\*/}{}gs` opened a block comment inside a string literal and ate
# real code, which makes an ABSENCE arm pass on what it merely removed. Go line
# comments: whole-line `//`, and trailing `//` only after whitespace (a
# `https://` literal survives).
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^[ \t]*//.*$}{}gm;
    s{[ \t]+//[^"`\n]*$}{}gm;
  ' "$1"
}

# The stripper is code, and code can be wrong. Measure it before trusting
# anything downstream: every `func` declaration must survive the strip.
stripper_self_check() {
  local bad_files=0 f raw_decls stripped_decls
  for f in "$@"; do
    [ -f "$f" ] || continue
    raw_decls=$(grep -cE '^func ' "$f" || true)
    stripped_decls=$(grep -cE '^func ' <<< "$(code "$f")" || true)
    if [ "$raw_decls" != "$stripped_decls" ]; then
      bad "STRIPPER ATE CODE in $f: $raw_decls func declarations before, $stripped_decls after"
      bad_files=$((bad_files+1))
    fi
  done
  [ "$bad_files" -eq 0 ] && ok "comment stripper preserves every func declaration in all $# subjects"
}

# An arm whose subject could not be extracted must SKIP, not print a confident
# green next to a red about the same subject.
subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }

has()   { grep -qE -- "$2" <<< "$1"; }
count() { grep -cE -- "$2" <<< "$1" || true; }

# Only DEAD-CODE markers belong here (lesson #133).
#
# ⚠ SCOPED TO THE MATCH, not to the whole subject. `git_build` carries an
# auto-generated Dockerfile as a string literal containing `collectstatic
# --noinput || true`, so a whole-subject liveness test reads the ENTIRE FILE as
# dead and every arm over it goes red on correct code — permanently. Judge the
# lines that matched, plus a little context so an `if false {` wrapper two lines
# up is still caught.
live_at() {
  local w="$1" pat="$2" hits
  hits=$(grep -E -B3 -A1 -- "$pat" <<< "$w" || true)
  [ -n "$hits" ] && ! grep -qE -- '(if false|&& false|\|\| true|_ = unused)' <<< "$hits"
}

# The body of one top-level Go func (or method), bounded by its own closing `}`
# at column 0. A fixed `-A <n>` window is NOT a function (lesson #131).
fnbody() {
  awk -v name="$2" '
    !inside && (index($0, "func " name "(") == 1 || $0 ~ ("^func \\([^)]*\\) " name "\\(")) { inside=1; next }
    inside { if ($0 == "}") exit; print }
  ' <<< "$1"
}

derives() {
  local w="$1" pat="$2"
  [ -n "$w" ] && grep -qE -- "$pat" <<< "$w" && live_at "$w" "$pat"
}

# First 1-indexed line of $2 within $1, or 0. Used where the DEFECT IS THE
# ORDER — a pin that only checks both statements exist passes on the bug.
lineof() {
  local n
  n=$(grep -nE -- "$2" <<< "$1" | head -1 | cut -d: -f1)
  printf '%s' "${n:-0}"
}

# LAST 1-indexed line of $2 within $1, or 0. Needed where a construct legitimately
# appears several times and only its position relative to another one is the
# property (D3 below: rollbacks existed before this release, just not on the path
# that needed one).
lastlineof() {
  local n
  n=$(grep -nE -- "$2" <<< "$1" | tail -1 | cut -d: -f1)
  printf '%s' "${n:-0}"
}

O=$(subj "$OWN")   || O=""
G=$(subj "$GB")    || G=""
GR=$(subj "$GBR")  || GR=""
D=$(subj "$DA")    || D=""
DR=$(subj "$DAR")  || DR=""
N=$(subj "$NGX")   || N=""
AP=$(subj "$APROC")|| AP=""
B=$(subj "$GD")    || B=""
P=$(subj "$PCL")   || P=""
M=$(subj "$MOD")   || M=""
AM=$(subj "$AMOD") || AM=""
TSX=$(subj "$APPS_TSX") || TSX=""

echo
echo "container-identity-pin-e2e — a container name is not a key anybody owns"
echo

# ── stripper self-check ────────────────────────────────────────────────
echo "§0 the harness measures its own preprocessing"
stripper_self_check "$OWN" "$GB" "$GBR" "$DA" "$DAR" "$NGX" "$APROC" "$GD" "$PCL" "$MOD" "$AMOD"

# ── §A two name spaces that cannot intersect ───────────────────────────
echo
echo "§A a preview and a deployment cannot spell the same container name"
if [ -z "$O" ] || [ -z "$M" ] || [ -z "$AM" ]; then
  skip "§A — a subject could not be read"
else
  SCOPED=$(fnbody "$O" "Scoped")
  # The separation rests entirely on the scope using a character the name
  # validator rejects. Key on the FUNCTION doing it, not on the character, so a
  # regression that keeps the character and drops the scoping still fails.
  if derives "$SCOPED" 'if s == OwnershipGitScopePreview \{' && derives "$SCOPED" 'return "[^"]*" \+ name'; then
    ok "A1 the preview space is composed by a scope function, not by the bare name"
  else
    bad "A1 previews are not scoped — a pushed branch names a deployment's container again"
  fi
  # ⚠ THE ARM THAT MATTERS MOST, and the one a future change is most likely to
  # break without noticing: BOTH validators must keep rejecting whatever
  # `Scoped` prepends. Derived from the source, not hardcoded, so widening
  # `isValidName` fails here rather than silently re-merging the spaces.
  MARK=$(sed -n 's/.*return "\([^"]*\)" + name.*/\1/p' <<< "$SCOPED" | head -1)
  if [ -z "$MARK" ]; then
    bad "A2 could not read the preview scope marker out of $OWN — the arm below cannot be trusted"
  else
    # Both validators must still be the alphanumeric+underscore+hyphen set…
    BE_OK=1; AG_OK=1
    VALID_RE='!isASCIIAlnum\(c\) && c != ._. && c != .-.'
    grep -qE "$VALID_RE" <<< "$(fnbody "$M" "isValidName")" || BE_OK=0
    grep -qE "$VALID_RE" <<< "$(fnbody "$AM" "isValidName")" || AG_OK=0
    # …and the marker must contain at least one character OUTSIDE it. Computed
    # from the marker actually read out of the source, so a future scope spelled
    # with only legal characters fails here instead of silently re-merging the
    # two spaces.
    OUTSIDE=$(printf '%s' "$MARK" | tr -d 'A-Za-z0-9_-')
    if [ "$BE_OK" = 1 ] && [ "$AG_OK" = 1 ] && [ -n "$OUTSIDE" ]; then
      ok "A2 both validators reject '$OUTSIDE', so no deployment can be named into the '$MARK' space"
    else
      bad "A2 the scope marker '$MARK' is not provably rejected by both validators (backend=$BE_OK agent=$AG_OK outside-chars='$OUTSIDE') — the two spaces can intersect again"
    fi
  fi
  # Cross-tree: the panel must agree with the agent about what a preview is
  # called, or teardown addresses a name nothing holds.
  PFX=$(sed -n 's/^const rtGitDeploysPreviewScopePrefix = "\(.*\)"$/\1/p' <<< "$B")
  if [ -n "$PFX" ] && [ "$PFX" = "${MARK:-}" ] && derives "$B" '\+ rtGitDeploysPreviewScopePrefix \+'; then
    ok "A3 the panel names the preview space explicitly ('$PFX', the agent's own marker) rather than assembling it inline"
  else
    bad "A3 the panel has no preview-space constant matching the agent's marker (panel='$PFX' agent='${MARK:-}') — the two trees can drift apart"
  fi
fi

# ── §A2 the wire carries the scope at every call site ──────────────────
echo
echo "§A' every call the panel makes into the git subsystem says which space it means"
if [ -z "$B" ] || [ -z "$GR" ]; then
  skip "§A' — a subject could not be read"
else
  # The deploy body must declare a scope. ⚠ Go cannot make a struct field
  # REQUIRED the way the Rust `&'a str` with no Default was — an omitted field
  # is "" and the agent reads "" as deploy. A'3 below (every construction names
  # a non-empty scope) is therefore now the only thing enforcing it.
  DB=$(awk '/^type rtGitDeploysDeployBody struct/,/^}/' <<< "$B")
  if derives "$DB" '^[[:space:]]*Scope[[:space:]]+string'; then
    ok "A'1 the deploy body declares a scope field"
  else
    bad "A'1 rtGitDeploysDeployBody has no scope field — an omitted scope is the original defect"
  fi
  BDB=$(fnbody "$B" "rtGitDeploysBuildDeployBody")
  if derives "$BDB" '"scope":[[:space:]]*b\.Scope'; then
    ok "A'2 the scope reaches the wire"
  else
    bad "A'2 the scope is declared but never sent"
  fi
  # Every construction names one. A count arm, because the failure mode is ONE
  # forgotten site, not zero.
  # ⚠ NON-EMPTY, not merely present. `Scope: ""` reads as the default —
  # which is `deploy` — so a field present and blank puts a preview back in the
  # deployment's name space while satisfying any arm that only looks for the
  # key. Field-present-but-empty beat the s295 pin and the s296 pin; it is
  # assumed here rather than discovered again (lesson #149).
  BODIES=$(count "$B" 'rtGitDeploysBuildDeployBody\(rtGitDeploysDeployBody\{')
  SCOPES=$(count "$B" '^[[:space:]]*Scope:[[:space:]]+"[a-z_]+",')
  if [ "$BODIES" -gt 0 ] && [ "$SCOPES" -ge "$BODIES" ]; then
    ok "A'3 all $BODIES deploy-body constructions name a non-empty scope"
  else
    bad "A'3 $BODIES deploy bodies but only $SCOPES carry a non-empty scope"
  fi
  # The preview's own clone and build must be scoped too: they own the image
  # repository and the on-disk checkout, which collide exactly as the container
  # name did.
  HPD=$(fnbody "$B" "rtGitDeploysHandlePreviewDeploy")
  if [ "$(count "$HPD" '"scope":[[:space:]]*"preview"')" -ge 2 ]; then
    ok "A'4 the preview's clone and build are scoped, not only its deploy"
  else
    bad "A'4 the preview clone/build still share the deployment's checkout and image repository"
  fi
  # And the preview's own deploy body names the preview space by that name —
  # the arm above counts every construction, this one names the one that matters.
  if derives "$HPD" '^[[:space:]]*Scope:[[:space:]]+"preview",'; then
    ok "A'4b the preview deploy body asks for the preview space specifically"
  else
    bad "A'4b the preview deploys into whatever space the default resolves to"
  fi
  # And the agent must actually apply it rather than accept and ignore it.
  for h in Clone Build; do
    HB=$(fnbody "$GR" "gitBuild$h")
    if derives "$HB" 'gitBuildScopeOf\(b\.Scope\)\.Scoped\(b\.Name\)'; then
      ok "A'5 /git/$(tr 'A-Z' 'a-z' <<< "$h") resolves the name through the scope"
    else
      bad "A'5 /git/$(tr 'A-Z' 'a-z' <<< "$h") ignores the scope it was sent"
    fi
  done
fi

# ── §B a container proves it is the one asked for ──────────────────────
echo
echo "§B a container is asked who it belongs to, and the answer is honoured"
if [ -z "$O" ] || [ -z "$G" ]; then
  skip "§B — a subject could not be read"
else
  if derives "$O" '^func OwnershipGitContainer\('; then
    ok "B1 ownership has a container primitive at all"
  else
    bad "B1 ownership.go still judges only files — the largest thing the agent destroys has no primitive"
  fi
  FC=$(fnbody "$G" "gitBuildFindContainer")
  if derives "$FC" 'OwnershipGitContainer\('; then
    ok "B2 the resolver returns an ownership verdict, not just a name match"
  else
    bad "B2 gitBuildFindContainer matches on name alone again"
  fi
  # THE HEADLINE ARM. Not "the guard is called" — the guard's answer must ABORT.
  # `let _ = guard(..)` satisfied the s294 and s295 pins and arrived again at
  # s296, so this keys on the refusal returning out of the function.
  DOU=$(fnbody "$G" "GitBuildDeployOrUpdate")
  GUARD_LINE=$(lineof "$DOU" 'owner\.MayDelete\(\)')
  FIRST_REMOVE=$(lineof "$DOU" 'ContainerRemove|gitBuildBlueGreenUpdate')
  if derives "$DOU" '!existing\.owner\.MayDelete\(\)' \
     && derives "$DOU" 'return GitBuildDeployResult\{\}, fmt\.Errorf\("Refusing to deploy' \
     && [ "$GUARD_LINE" -gt 0 ] && [ "$FIRST_REMOVE" -gt 0 ] \
     && [ "$GUARD_LINE" -lt "$FIRST_REMOVE" ]; then
    ok "B3 a deploy REFUSES a container that is not its own, before any branch can touch it (guard@$GUARD_LINE first-destructive@$FIRST_REMOVE)"
  else
    bad "B3 the ownership verdict does not abort the deploy ahead of the destructive branches (guard@$GUARD_LINE first-destructive@$FIRST_REMOVE)"
  fi
  CC=$(fnbody "$G" "GitBuildCleanupContainer")
  CGUARD=$(lineof "$CC" 'OwnershipGitContainer\(')
  CREMOVE=$(lineof "$CC" 'ContainerRemove')
  if derives "$CC" '!owner\.MayDelete\(\)' && [ "$CGUARD" -gt 0 ] && [ "$CREMOVE" -gt 0 ] \
     && [ "$CGUARD" -lt "$CREMOVE" ]; then
    ok "B4 the unattended teardown asks before it removes (ask@$CGUARD remove@$CREMOVE)"
  else
    bad "B4 the teardown removes first and asks afterwards, or not at all (ask@$CGUARD remove@$CREMOVE)"
  fi
  # B5 retired: covered by TestGitContainerOwnership (panel/go/internal/agent/services/ownership_test.go) — unlabelled legacy-space containers are Unknown unless the port matches
  # A container may only be judged later if it was marked earlier.
  if derives "$DOU" 'OwnershipGitKindLabel:[[:space:]]*scope\.Label\(\)'; then
    ok "B6 every container the git path creates records which space it is in"
  else
    bad "B6 nothing writes the kind label, so the legacy-space evidence never exists"
  fi
fi

# ── §C the stand-in space ──────────────────────────────────────────────
echo
echo "§C the blue-green stand-in is not standing on a name a deployment can hold"
if [ -z "$G" ] || [ -z "$D" ] || [ -z "$O" ]; then
  skip "§C — a subject could not be read"
else
  # ABSENCE ARM over BOTH twins. Non-vacuity is established by the subj()/SKIP
  # guard above plus the stripper self-check: these subjects were really read.
  # ⚠ THE PROPERTY, NOT THE SPELLING. Read the constant and require it to
  # contain a character the name validator rejects, the same test §A applies to
  # the preview scope.
  SUF=$(sed -n 's/^const OwnershipBlueSuffix = "\(.*\)"$/\1/p' <<< "$O" | head -1)
  SUF_OUTSIDE=$(printf '%s' "$SUF" | tr -d 'A-Za-z0-9_-')
  if [ -n "$SUF" ] && [ -n "$SUF_OUTSIDE" ] && ! has "$G" '\-blue"' && ! has "$D" '\-blue"'; then
    ok "C1 the stand-in space is marked by '$SUF_OUTSIDE', which no deployment name may contain"
  else
    bad "C1 the stand-in suffix '$SUF' is spellable as a deployment name (outside-chars='$SUF_OUTSIDE') — 'api-blue' is a name isValidName accepts"
  fi
  if derives "$G" 'OwnershipBlueName\(' && derives "$D" 'OwnershipBlueName\('; then
    ok "C2 both twins compose the stand-in through the one function that owns the rule"
  else
    bad "C2 a twin builds the stand-in name itself — that is how the two drifted before"
  fi
  # And what is standing there is asked before it is destroyed, in BOTH twins.
  CBL=$(fnbody "$G" "gitBuildClearBlueLeftover")
  CBL_ASK=$(lineof "$CBL" 'OwnershipBlueLeftover\(')
  CBL_RM=$(lineof "$CBL" 'ContainerRemove')
  if derives "$CBL" 'OwnershipBlueLeftover\(' && derives "$CBL" 'return fmt\.Errorf\(' \
     && [ "$CBL_ASK" -gt 0 ] && [ "$CBL_RM" -gt "$CBL_ASK" ]; then
    ok "C3 the git twin refuses to force-remove a leftover that is not managed"
  else
    bad "C3 the git twin force-removes whatever holds the stand-in name"
  fi
  BGD=$(fnbody "$D" "dockerAppsBlueGreenUpdate")
  BLGUARD=$(lineof "$BGD" 'OwnershipBlueLeftover\(')
  BLREMOVE=$(lineof "$BGD" 'ContainerRemove|dockerAppsStopRemove\(')
  if derives "$BGD" 'OwnershipBlueLeftover\(' && derives "$BGD" 'return DockerAppsUpdateResult\{\}, fmt\.Errorf\("A container named' \
     && [ "$BLGUARD" -gt 0 ] && [ "$BLREMOVE" -gt 0 ] && [ "$BLGUARD" -lt "$BLREMOVE" ]; then
    ok "C4 the docker-app twin asks before it clears (ask@$BLGUARD remove@$BLREMOVE)"
  else
    bad "C4 the docker-app twin still clears first (ask@$BLGUARD remove@$BLREMOVE)"
  fi
fi

# ── §D the commit phase of a swap ──────────────────────────────────────
echo
echo "§D a swap frees the name before it destroys anything, and says when it could not"
# Both twins are sliced from the retired-name assignment onward (a real
# identifier, not a comment — code() already stripped those). Before that point
# every remove is a best-effort rollback of the not-yet-promoted stand-in
# (the git twin's `cleanup` closure, the docker-app twin's `cleanupNew`), and
# keying on the whole body would find one of those first and fail for the
# wrong reason.
commit_phase_arms() {
  local label="$1" body="$2" n_free="$3" n_checked="$4" n_rollback="$5" rollback_pat="$6"
  local commit free destroy checked first last
  commit=$(awk '/^[[:space:]]*retired(Name)? := /{f=1} f{print}' <<< "$body")
  if [ -z "$commit" ]; then
    bad "$n_free could not isolate the $label promotion phase — the arms below would read nothing"
    return
  fi
  # THE DEFECT IS THE ORDER. A pin that only checks both statements exist passes
  # on destroy-then-rename, which is exactly what shipped.
  free=$(lineof "$commit" 'ContainerRename\(')
  destroy=$(lineof "$commit" 'ContainerRemove\(')
  if [ "$free" -gt 0 ] && [ "$destroy" -gt 0 ] && [ "$free" -lt "$destroy" ]; then
    ok "$n_free the $label frees the promoted name by a rename before anything is removed (rename@$free remove@$destroy)"
  else
    bad "$n_free the $label destroys the old container before the name is freed, so a failed removal blocks the promotion (rename@$free remove@$destroy)"
  fi
  # BOTH promotion renames — freeing the name and installing the new one — must
  # be checked. The rollback rename inside the failure branch is deliberately
  # best-effort (`_, _ =`), so this counts rather than forbidding.
  checked=$(count "$commit" 'if _, err := docker\.ContainerRename\(')
  if [ "${checked:-0}" -ge 2 ]; then
    ok "$n_checked the $label error-checks both promotion renames, not best-effort ($checked)"
  else
    bad "$n_checked only ${checked:-0} of the $label's two promotion renames is checked — the other returns Ok over a half-swapped host"
  fi
  # A failed promotion must put traffic back — a rollback AFTER the promotion
  # begins, the only place the half-swapped state can be undone.
  first=$(lineof "$commit" 'ContainerRename\(')
  last=$(lastlineof "$commit" "$rollback_pat")
  if [ "$first" -gt 0 ] && [ "$last" -gt "$first" ]; then
    ok "$n_rollback a $label promotion failure rolls the vhost back to the container still running (rename@$first rollback@$last)"
  else
    bad "$n_rollback every $label rollback happens before the promotion starts, so a half-swapped host stays that way (rename@$first rollback@$last)"
  fi
}
if [ -z "$G" ]; then
  skip "§D — $GB could not be read"
else
  BG=$(fnbody "$G" "gitBuildBlueGreenUpdate")
  # The git twin's rollback is the `swapBack` closure; it must really be the
  # temp→old swap, or calling it after the rename proves nothing.
  if derives "$BG" 'swapBack := func\(\) \{ _ = DockerAppsSwapNginxProxyPort\(domain, tempPort, oldPort\) \}'; then
    commit_phase_arms "git twin" "$BG" D1 D2 D3 'swapBack\(\)'
  else
    bad "D0 the git twin's swapBack rollback is not DockerAppsSwapNginxProxyPort(domain, tempPort, oldPort) — D1-D3 cannot be judged"
  fi
fi
# The docker-app twin got the IDENTICAL fix (s471) — it shared the v2.54.0
# defect via find_free_port/health_check_port/swap_nginx_proxy_port but never
# received the v2.55.0 repair, until then. Same three arms, D4-D6.
if [ -n "$D" ]; then
  BGD_LOCAL=$(fnbody "$D" "dockerAppsBlueGreenUpdate")
  commit_phase_arms "docker-app twin" "$BGD_LOCAL" D4 D5 D6 'DockerAppsSwapNginxProxyPort\(domain, tempPort, oldPort\)'
else
  skip "§D docker-app twin — $DA could not be read"
fi

# ── §E a mask is not a value ───────────────────────────────────────────
echo
echo "§E the mask a read substitutes cannot be written back as the secret"
if [ -z "$D" ] || [ -z "$DR" ]; then
  skip "§E — a subject could not be read"
else
  # Caller-reaches-helper (lesson #150): a merge nothing calls satisfies "the
  # helper exists" while the secret is still destroyed.
  UE=$(fnbody "$D" "DockerAppsUpdateEnv")
  if derives "$UE" 'DockerAppsMergeEnvPreservingMasked\('; then
    ok "E1 DockerAppsUpdateEnv goes through the merge"
  else
    bad "E1 DockerAppsUpdateEnv builds the environment itself again — the mask is written back as the value"
  fi
  # E2 retired: covered by TestAMaskedValueSentBackLeavesTheRealOneAlone (panel/go/internal/agent/services/docker_apps_test.go)
  # The read side must consult the catalogue rather than masking every name that
  # merely CONTAINS a sensitive word — three shipped variables are hostnames and
  # usernames.
  GE=$(fnbody "$DR" "dockerAppsGetEnv")
  SENS=$(fnbody "$DR" "dockerAppsIsSensitive")
  if derives "$GE" 'dockerAppsIsSensitive\(' && derives "$SENS" 'DockerAppsCatalogueNonSecretEnv\(' && derives "$GE" 'services\.DockerAppsEnvMask'; then
    ok "E3 the masking read exempts what the catalogue declares non-secret, and uses the shared token"
  else
    bad "E3 the read masks by substring alone, or re-spells the mask as a literal"
  fi
  # E4 retired: covered by TestTheCatalogueExemptsItsOwnNonSecretsAndNeverItsSecrets (panel/go/internal/agent/services/docker_apps_test.go)
  if [ -n "$TSX" ]; then
    if derives "$TSX" 'ENV_MASK'; then
      ok "E5 the dialog names the mask rather than open-coding it, so the two trees agree"
    else
      bad "E5 the frontend open-codes the mask"
    fi
  else
    skip "E5 — $APPS_TSX could not be read"
  fi
fi

# ── §F the v2.53.0 guard reaches the paths it missed ───────────────────
echo
echo "§F the ownership guard reaches rename and the lifecycle callers, not only create and delete"
if [ -z "$N" ] || [ -z "$AP" ]; then
  skip "§F — a subject could not be read"
else
  RS=$(fnbody "$N" "renameSite")
  if derives "$RS" 'OwnershipCertDirInUseElsewhere\('; then
    ok "F1 the rename asks whether the certificate directory is shared before moving it"
  else
    bad "F1 the rename moves a shared wildcard out from under every sibling vhost"
  fi
  # BOTH ends: the file being deleted and the file being written are separately
  # collidable, and guarding only the source still clobbers a third domain.
  if [ "$(count "$RS" 'OwnershipFail2banJail\(')" -ge 2 ]; then
    ok "F2 the rename asks who owns the jail at both the old and the new name"
  else
    bad "F2 the rename migrates a jail without proving either end belongs to it"
  fi
  if derives "$AP" '^func AppProcessOwnedServiceName\('; then
    ok "F3 there is one answer to 'which unit may I act on for this domain'"
  else
    bad "F3 no owned-unit resolver — the lifecycle callers derive the unit name themselves"
  fi
  # The three callers that stop and restart another tenant's app process.
  USES=$(count "$N" 'AppProcessOwnedServiceName\(domain\)')
  RAW=$(count "$N" '"dockpanel-app-"')
  if [ "$USES" -ge 3 ] && [ "$RAW" -eq 0 ]; then
    ok "F4 all three lifecycle callers resolve an owned unit, and none derives the name itself"
  else
    bad "F4 $USES guarded callers and $RAW raw derivations — a tenant can stop a neighbour's app"
  fi
fi

# ── §G an unattended sweep does not orphan what it failed to remove ────
echo
echo "§G the sweep keeps the only record of anything it could not tear down"
if [ -z "$P" ] || [ -z "$B" ]; then
  skip "§G — a subject could not be read"
else
  CEP=$(fnbody "$P" "previewCleanupCleanupExpiredPreviews")
  # Two loops, and BOTH must bail rather than delete the row anyway. A count arm
  # because the failure mode is one loop, not both.
  if [ "$(count "$CEP" '^[[:space:]]*continue$')" -ge 2 ]; then
    ok "G1 both sweeps keep the row when the teardown failed"
  else
    bad "G1 a sweep still deletes the only record of a container it did not remove"
  fi
  # The documented opt-out has to bind BOTH queries; it bound only one.
  if [ "$(count "$CEP" 'preview_ttl_hours > 0')" -ge 2 ]; then
    ok "G2 the opt-out from automatic cleanup binds both sweeps"
  else
    bad "G2 the stuck sweep still destroys previews on an install that switched auto-cleanup off"
  fi
  # One door for teardown: five call sites had drifted into three spellings.
  DOORS=$(count "$B" 'rtGitDeploysPreviewCleanupBody\(')
  if derives "$B" '^func rtGitDeploysPreviewCleanupBody\(' && [ "$DOORS" -ge 4 ]; then
    ok "G3 every preview teardown in the panel goes through one body ($DOORS occurrences)"
  else
    bad "G3 preview teardown is assembled per call site again ($DOORS through the door)"
  fi
  # Deleting the parent must tear the children down while the rows still name
  # them — the FK cascade is about to remove every one.
  RM=$(fnbody "$B" "rtGitDeploysRemove")
  PREV=$(lineof "$RM" 'FROM git_previews')
  CASCADE=$(lineof "$RM" 'DELETE FROM git_deploys')
  if [ "$PREV" -gt 0 ] && [ "$CASCADE" -gt 0 ] && [ "$PREV" -lt "$CASCADE" ]; then
    ok "G4 previews are torn down before the cascade forgets they exist (read@$PREV cascade@$CASCADE)"
  else
    bad "G4 deleting a deployment leaves its preview containers running with no record (read@$PREV cascade@$CASCADE)"
  fi
  # The teardown must carry what the agent cannot read off a container that is
  # already gone.
  PCB=$(fnbody "$B" "rtGitDeploysPreviewCleanupBody")
  if derives "$PCB" '"domain"' && derives "$PCB" '"host_port"'; then
    ok "G5 the teardown carries the row's own domain and port, so a crashed preview's vhost is still released"
  else
    bad "G5 the teardown tells the agent only a name — a missing container means an orphaned vhost forever"
  fi
fi

# ── §H EVERY teardown door, not the ones a count happens to reach ──────
#
# G3 above counts the call sites that go through the cleanup body and passes at
# four or more. It passed for months while FOUR of the six doors threw the
# teardown's result away and deleted the row regardless — because a count is
# satisfied by the defect: two guarded plus four unguarded is still six. §G
# asserted the two SWEEPS keep the row; nothing asked how many callers existed.
# That is lesson #558 exactly, and this section is the membership test G3 is not:
# every member of a DERIVED population must individually comply.
#
# The population is derived from the operation's own syntax — every post to
# `/git/cleanup` in the panel — and each call site is flattened to one line whose
# bounds come from the code's punctuation (parenthesis balance), never a fixed
# `-A n` window (#172).
echo
echo "§H every preview teardown door checks whether the teardown happened"

# One line per `/git/cleanup` call site: the matching line, extended forward
# until its parentheses balance.
cleanup_stmts() {
  awk '
    { L[NR]=$0 }
    END {
      for (i=1;i<=NR;i++) {
        if (L[i] !~ /"\/git\/cleanup"/) continue
        stmt=""; depth=0
        for (j=i;j<=NR;j++) {
          t=L[j]; sub(/^[ \t]+/,"",t); stmt=stmt " " t
          o=gsub(/\(/,"(",t); c=gsub(/\)/,")",t); depth+=o-c
          if (depth<=0) break
        }
        print stmt
      }
    }
  ' <<< "$1"
}

if [ -z "$P" ] || [ -z "$B" ]; then
  skip "§H — a subject could not be read"
else
  STMTS=$(printf '%s\n%s\n' "$(cleanup_stmts "$B")" "$(cleanup_stmts "$P")" | grep -E '.' || true)
  DOORS_H=$(count "$STMTS" '"/git/cleanup"')
  # A discarded result, in the spellings Go has for it.
  DROPPED=$(count "$STMTS" '(^|[[:space:]])_(, _)? = agent\.|^[[:space:]]*agent\.Post\(')
  # An ABSENCE arm with no positive control cannot tell "no violations" from "the
  # pattern never matched" (#480), so the population is asserted in the same arm.
  if [ "$DOORS_H" -ge 6 ] && [ "$DROPPED" -eq 0 ]; then
    ok "H1 no preview teardown throws its result away ($DOORS_H doors derived, 0 discarded)"
  else
    bad "H1 $DROPPED of $DOORS_H teardown doors discard the result (need >=6 doors and 0 discarded)"
  fi

  # The other direction, because an absence arm only ever sees the spellings it
  # was taught (#494): every door must POSITIVELY read the result. A third way to
  # discard one would leave H1 green and this arm red.
  CHECKED=$(count "$STMTS" '; (e|err) (!=|==) nil \{')
  if [ "$DOORS_H" -ge 6 ] && [ "$CHECKED" -eq "$DOORS_H" ]; then
    ok "H2 every one of the $DOORS_H doors reads the teardown result before acting on it"
  else
    bad "H2 only $CHECKED of $DOORS_H teardown doors read the result at all"
  fi

  # The record is what every list, sweep and delete path starts from, so the row
  # may only be retired by a teardown that reported success.
  ROWKILL=$(printf '%s\n%s\n' "$B" "$P" | grep -E 'DELETE FROM git_previews' || true)
  ROWS=$(count "$ROWKILL" 'DELETE FROM git_previews')
  ROWDROP=$(count "$ROWKILL" '_, _ = execSQL\([^"]*"DELETE FROM git_previews')
  if [ "$ROWS" -ge 4 ] && [ "$ROWDROP" -eq 0 ]; then
    ok "H3 no preview record is retired by a statement that ignored its own result ($ROWS sites)"
  else
    bad "H3 $ROWDROP of $ROWS preview-record deletions run regardless of the outcome"
  fi

  # A refusal is only as good as the layer that can carry it (#556). Both
  # operator-facing doors answered `{"ok": true}` over a failed teardown, which is
  # worse than failing: the operator stops looking, and the record they would have
  # retried with is gone. The refusal must be returned, not logged.
  RMB=$(fnbody "$B" "rtGitDeploysRemove")
  DPB=$(fnbody "$B" "rtGitDeploysDeletePreview")
  RM_REFUSE=$(lineof "$RMB" 'return apiErr\(http\.StatusConflict')
  RM_CASCADE=$(lineof "$RMB" 'DELETE FROM git_deploys')
  DP_TEAR=$(lineof "$DPB" '"/git/cleanup"')
  DP_REFUSE=$(awk -v from="$DP_TEAR" 'NR>from && /return apiErr\(/ {print NR; exit}' <<< "$DPB")
  DP_REFUSE=${DP_REFUSE:-0}
  DP_ROW=$(lineof "$DPB" 'DELETE FROM git_previews')
  if [ "$RM_REFUSE" -gt 0 ] && [ "$RM_CASCADE" -gt 0 ] && [ "$RM_REFUSE" -lt "$RM_CASCADE" ] \
     && [ "$DP_TEAR" -gt 0 ] && [ "$DP_REFUSE" -gt 0 ] && [ "$DP_ROW" -gt 0 ] && [ "$DP_REFUSE" -lt "$DP_ROW" ]; then
    ok "H4 both operator doors refuse before destroying the record (remove@$RM_REFUSE<$RM_CASCADE, delete_preview@$DP_REFUSE<$DP_ROW)"
  else
    bad "H4 an operator door still reports success over a teardown that did not happen (remove@$RM_REFUSE<$RM_CASCADE, delete_preview@$DP_REFUSE<$DP_ROW)"
  fi
fi

# ── summary ────────────────────────────────────────────────────────────
echo
if [ "$SKIP" -gt 0 ]; then
  echo "container-identity pin: $PASS passed, $FAIL failed, $SKIP skipped"
else
  echo "container-identity pin: $PASS passed, $FAIL failed"
fi
[ "$FAIL" -eq 0 ] || exit 1
