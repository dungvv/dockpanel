#!/usr/bin/env bash
# domain-claim-pin-e2e.sh — s294 / v2.52.0
#
# Pins the two halves of one mistake: nothing owned the question "may this domain
# be claimed?", and nothing owned the question "what was here before I wrote?"
#
#   §A  the GUARD exists and is complete — format, reserved, sites, git deploys
#       and, for the first time, DOCKER APPS, whose domain lives only in a
#       container label and which therefore no SQL guard could ever see.
#   §B  EVERY claim path calls it. This is the arm that matters. `sites.rs` (now
#       panel/go/internal/api/rt_sites.go) had a
#       shared helper whose own comment said it existed "so the guard set create()
#       enforces cannot drift" — and two of eleven paths called it.
#   §C  the vhost write is NON-DESTRUCTIVE. Three writers replaced
#       /etc/nginx/sites-enabled/{domain}.conf and, when the whole-server
#       `nginx -t` failed, DELETED it — under a comment promising a restore.
#   §D  the Traefik route key is INJECTIVE. `.`→`-` mapped a.b.com and a-b.com
#       onto one file and one router name.
#
# Pure source analysis over the Go tree (panel/go): no box, no network, no build.
# Pure-function behaviour (normalise, the role gates, occupant messages) is held
# by Go unit tests in panel/go/internal/api/svc_domain_claim_test.go; arms that
# only restated those are retired below with the test that covers them.
#
# The arms are written against the CAPABILITY a regression must use, not today's
# spelling (lesson #122), and were attacked after they went green (lesson #132 —
# budget for the attack finding several, not one).
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

GO=panel/go/internal
CLAIM=$GO/api/svc_domain_claim.go
SITES=$GO/api/rt_sites.go
STAGING=$GO/api/rt_staging.go
MIG=$GO/api/rt_migration.go
GITDEP=$GO/api/rt_git_deploys.go
APPS_BE=$GO/api/rt_docker_apps.go
STACKS=$GO/api/rt_stacks.go
NGINX_ROUTE=$GO/agent/routes/nginx.go
NGINX_SVC=$GO/agent/services/nginx.go
APPS_ROUTE=$GO/agent/routes/docker_apps.go
GIT_BUILD=$GO/agent/services/git_build.go
TRAEFIK=$GO/agent/services/traefik.go

for f in "$CLAIM" "$SITES" "$STAGING" "$MIG" "$GITDEP" "$APPS_BE" "$STACKS" \
         "$NGINX_ROUTE" "$NGINX_SVC" "$APPS_ROUTE" "$GIT_BUILD" "$TRAEFIK"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT.
#
# The obvious `s{/\*.*?\*/}{}gs` is wrong and shipped in four suites before this
# one: `/*` occurs INSIDE string literals (a Dockerfile's
# `COPY --from=builder /app/target/release/*`, a glob, a regex), so it opened a
# "block comment" that ran to the next `*/` and deleted real code. A truncated
# subject makes an ABSENCE arm pass on code that was merely deleted by the
# stripper, which is the worst way for a pin to be wrong.
#
# So a block comment is only recognised where one is actually written: opening at
# the start of a line, closing at the end of one. A `/*` in the middle of a line
# is data. Go's `//` line comments are blanked when they start a line.
code() {
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

# An arm whose subject could not be extracted must SKIP, not print a confident
# green next to a red about the same subject (lesson #122b).
subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }

has()   { grep -qE -- "$2" <<< "$1"; }
count() { grep -cE -- "$2" <<< "$1" || true; }

# Counts OCCURRENCES, not lines — `count()` above is `grep -c`, which counts
# matching LINES, and the natural way to write a widening puts both variants on
# ONE line (`a == x || a == y`). Measured SURVIVING at s347 (#420).
occurrences() { grep -oE -- "$2" <<< "$1" | wc -l | tr -d ' '; }

# Only DEAD-CODE markers belong here (lesson #133: a guard added to make a pin
# stricter is itself new, untested code).
live() {
  ! grep -qE -- '(if false|&& false|\|\| true)' <<< "$1"
}

# The body of one top-level Go func (plain or method), from its `func` line to
# the column-0 `}` that closes it (gofmt guarantees that shape).
#
# A fixed `-A <n>` window is NOT a function (lesson #131): at s293 a per-parser
# arm stayed green because its 60-line window ran on into the next parser.
fnbody() {
  awk -v name="$2" '
    !inside && (index($0, "func " name "(") == 1 || $0 ~ ("^func \\([^)]*\\) " name "\\(")) { inside=1; next }
    inside && /^}/ { exit }
    inside { print }
  ' <<< "$1"
}

# Assert a window both matches and is live, in one place so no arm forgets.
derives() {
  local w="$1" pat="$2"
  [ -n "$w" ] && grep -qE -- "$pat" <<< "$w" && live "$w"
}

flat() { tr '\n\t' '  ' <<< "$1" | tr -s ' '; }

echo "== §A  one guard, and it can see all three kinds of owner =="

if S=$(subj "$CLAIM"); then
  B=$(fnbody "$S" DomainClaimEnsureClaimable)
  if derives "$B" 'isValidDomain\(domain\)'; then
    ok "the guard rejects malformed domains"
  else
    bad "the guard no longer checks domain format"
  fi
  # `isReservedDomainFor`, NOT `isReservedDomain`: BASE_URL is empty on a
  # routine install, so only the header-reading variant knows the panel's host.
  if derives "$B" 'isReservedDomainFor\(domain, r\)'; then
    ok "the guard blocks the panel's own control-plane domain (header variant)"
  else
    bad "the guard no longer blocks reserved domains via the header variant"
  fi
  if has "$B" 'isReservedDomain\(' ; then
    bad "the guard fell back to the BASE_URL-only reserved check"
  else
    ok "the guard does not use the BASE_URL-only reserved check"
  fi

  O=$(fnbody "$S" DomainClaimFindOccupant)
  if derives "$O" 'lower\(domain\) = \$1' && [ "$(count "$O" 'lower\(domain\) = \$1')" -ge 2 ]; then
    ok "both SQL owners are matched case-insensitively"
  else
    bad "a SQL owner query is case-sensitive again (EXAMPLE.com would walk past example.com)"
  fi
  if derives "$O" 'FROM sites'; then
    ok "the guard consults the sites table"
  else
    bad "the guard no longer consults the sites table"
  fi
  if derives "$O" 'FROM git_deploys'; then
    ok "the guard consults git_deploys"
  else
    bad "the guard no longer consults git_deploys"
  fi
  # THE new leg. A Docker app is not a row; the only way to learn its domain is
  # to ask the agent, which has been returning it all along.
  if derives "$O" 'Get\(ctx, "/apps"\)'; then
    ok "the guard asks the agent for Docker-app domains"
  else
    bad "the guard no longer asks the agent for Docker-app domains"
  fi
  if derives "$O" 'DomainClaimOccupantDockerApp'; then
    ok "a Docker app is reported as an occupant"
  else
    bad "a Docker app is no longer reported as an occupant"
  fi
  # FLEET-WIDE. This arm used to pin the opposite property — that ONE agent was
  # asked and that an unreachable one failed the claim closed. Both halves were
  # replaced at s322: the SQL legs are fleet-wide, an app's domain is invisible
  # to SQL, and asking only the caller's host meant a domain held by an app on
  # host B passed a claim made on host A.
  if derives "$O" 'OnlineFleet\(ctx\)'; then
    ok "the Docker-app leg asks every online member, like the SQL legs above it"
  else
    bad "the Docker-app leg is back to asking a single host — a domain held by an app on another member passes"
  fi
  # A member that will not answer is REPORTED, never silently skipped. Failing
  # closed across a whole fleet would let one sick box block every domain claim
  # everywhere, so the trade is deliberate — but it must be audible.
  OFLAT=$(flat "$O")
  if has "$OFLAT" 'Get\(ctx, "/apps"\) if err != nil \{ slog\.Warn\('; then
    ok "a member that cannot be asked is logged by name rather than treated as free"
  else
    bad "the Docker-app leg skips an unreachable member without saying so — that is failing open in silence"
  fi
  # The Go spelling of `unwrap_or`: the error bound to `_`. Bounded to one
  # line, so it cannot leap a statement.
  if has "$O" ', _ :?= .*Get\(ctx, "/apps"\)'; then
    bad "the Docker-app leg swallows agent errors (fails OPEN)"
  else
    ok "the Docker-app leg does not swallow agent errors"
  fi

  # normalise-lowercases retired: covered by TestDomainClaimNormaliseLowercasesAndStripsTheRootDot (panel/go/internal/api/svc_domain_claim_test.go)
  if derives "$B" '^[[:space:]]*domain = DomainClaimNormalise\(domain\)'; then
    ok "the guard normalises before every check (and returns the normalised form)"
  else
    bad "the guard no longer normalises its input first — the case bypass is back"
  fi
fi

echo
echo "== §B  every path that can claim a domain calls it =="

# The anti-drift arm. Each of these is a path that causes a vhost to be written.
# A new one that does not appear here is exactly the regression this suite is for.
GUARD='(DomainClaimEnsureClaimable|rtSitesEnsureDomainAvailable)'
check_calls_guard() {
  local file="$1" fn="$2" label="$3"
  local S B
  S=$(subj "$file") || { bad "$label: subject unreadable"; return; }
  B=$(fnbody "$S" "$fn")
  if [ -z "$B" ]; then
    bad "$label: could not extract func $fn — the arm is not measuring anything"
    return
  fi
  if ! derives "$B" "$GUARD\\("; then
    bad "$label no longer claims through the shared guard"
    return
  fi
  # Calling it is not using it. Probe P2 kept the call and threw the result away
  # and stored the raw body value — the discarded-result class that also beat
  # the s293 draft (lesson #132). The guard returns the NORMALISED domain and an
  # error; in Go "uses its verdict" is: the error is checked and returned, and
  # the domain it returned is bound to a name that is read again.
  local F v; F=$(flat "$B")
  if grep -qE -- "(_|[A-Za-z_][A-Za-z0-9_]*, _) :?= $GUARD\\(" <<< "$F"; then
    bad "$label discards the guard's result instead of using it"
    return
  fi
  v=$(grep -oE -- "[A-Za-z_][A-Za-z0-9_]*, err :?= $GUARD\\(" <<< "$F" | head -1 | cut -d, -f1)
  # The call line plus the three after it: `if err != nil {` / `return err` / `}`.
  local C; C=$(flat "$(grep -E -A3 -- "$GUARD\\(" <<< "$B" | head -4)")
  if [ -z "$v" ] || ! grep -qE -- "\\) if err != nil \\{ return err \\}" <<< "$C"; then
    bad "$label does not propagate the guard's verdict"
  elif [ "$(occurrences "$F" "(^|[^A-Za-z0-9_.])$v([^A-Za-z0-9_]|\$)")" -lt 2 ]; then
    bad "$label discards the normalised domain the guard returned ($v is never read)"
  else
    ok "$label claims through the shared guard, and uses what it returns"
  fi
}

check_calls_guard "$SITES"   rtSitesCreate        "sites::create"
check_calls_guard "$SITES"   rtSitesRenameDomain  "sites::rename_domain"
check_calls_guard "$SITES"   rtSitesCloneSite     "sites::clone_site"
check_calls_guard "$SITES"   rtSitesAddAlias      "sites::add_alias"
check_calls_guard "$STAGING" rtStagingCreate      "staging::create"
check_calls_guard "$GITDEP"  rtGitDeploysCreate   "git_deploys::create"
check_calls_guard "$GITDEP"  rtGitDeploysUpdate   "git_deploys::update"
check_calls_guard "$APPS_BE" rtDockerAppsDeploy   "docker_apps::deploy"

# The two that are not plain handler bodies: the migration import's work happens
# in a spawned task, and the preview path reports rather than rejects.
if S=$(subj "$MIG"); then
  B=$(fnbody "$S" rtMigrationRunImport)
  if derives "$B" 'DomainClaimEnsureClaimable\('; then
    ok "migration::import claims through the shared guard"
  else
    bad "migration::import no longer claims through the shared guard"
  fi
fi
if S=$(subj "$GITDEP"); then
  B=$(fnbody "$S" rtGitDeploysHandlePreviewDeploy)
  if derives "$B" 'DomainClaimFindOccupant\('; then
    ok "the preview path checks the synthesised domain before taking it"
  else
    bad "the preview path takes {branch}.{domain} without checking it"
  fi
  # It must ALSO not trust the webhook caller's Host header to decide what is
  # reserved — that request is unauthenticated. (Positive anchor: it does use
  # the BASE_URL-only check.)
  if has "$B" 'isReservedDomainFor'; then
    bad "the preview path trusts an attacker-supplied Host header for reserved checks"
  elif has "$B" 'isReservedDomain\(candidate\)'; then
    ok "the preview path does not trust the webhook's Host header"
  else
    bad "the preview path no longer checks reserved domains at all"
  fi
fi

# The delegation itself: sites must not have grown its own copy back.
if S=$(subj "$SITES"); then
  E=$(fnbody "$S" rtSitesEnsureDomainAvailable)
  if derives "$E" 'return DomainClaimEnsureClaimable\('; then
    ok "sites' local helper delegates to the shared guard"
  else
    bad "sites' local helper stopped delegating — the guards can drift again"
  fi
fi

echo
echo "== §B2  no claim path keeps a private conflict query =="

# The negative that makes §B stick. A domain-conflict SELECT anywhere but the
# guard means some path can answer the question its own way again.
CONFLICT='"SELECT id FROM (sites|git_deploys) WHERE (lower\()?domain'
# Positive control: the detector must see the guard's own two queries.
if S=$(subj "$CLAIM") && [ "$(count "$S" "$CONFLICT")" -ge 2 ]; then
  ok "the conflict-query detector sees the guard's own queries (positive control)"
else
  bad "the conflict-query detector matches nothing even in the guard — the absence arms below are vacuous"
fi
for f in "$SITES" "$STAGING" "$GITDEP" "$APPS_BE" "$MIG"; do
  if S=$(subj "$f"); then
    n=$(count "$S" "$CONFLICT")
    if [ "$n" -eq 0 ]; then
      ok "$(basename "$f") holds no private domain-conflict query"
    else
      bad "$(basename "$f") has $n private domain-conflict quer(y|ies) again"
    fi
  fi
done

echo
echo "== §C  a write never destroys what it replaced =="

if S=$(subj "$NGINX_SVC"); then
  R=$(fnbody "$S" NginxRestoreOrRemove)
  if [ -z "$R" ]; then
    bad "NginxRestoreOrRemove is gone — nothing can put a replaced vhost back"
  else
    # It must actually WRITE the previous content. A version that only logs, or
    # only removes, satisfies a presence grep and restores nothing.
    if derives "$R" 'os\.WriteFile\(tmp, \[\]byte\(\*previous\)'; then
      ok "NginxRestoreOrRemove writes the previous content back"
    else
      bad "NginxRestoreOrRemove no longer writes the previous content back"
    fi
    if derives "$R" 'os\.Rename\(tmp, configPath\)'; then
      ok "the restore is atomic (tmp + rename), like the write it undoes"
    else
      bad "the restore is no longer atomic"
    fi
  fi
fi

# Every writer: snapshot before, restore after. Named per writer so a
# regression says WHICH one lost it. $2 is a |-separated list of funcs whose
# bodies together make up the writer (the Go port moved the tmp+rename into
# small per-file helpers — dockerAppsWriteVhost, gitBuildWriteVhost — so the
# subject is the handler PLUS the helper it delegates to). Every listed body
# must extract; an empty one reds.
check_writer() {
  local file="$1" fns="$2" label="$3"
  local S B fn part
  S=$(subj "$file") || { bad "$label: subject unreadable"; return; }
  B=""
  for fn in ${fns//|/ }; do
    part=$(fnbody "$S" "$fn")
    if [ -z "$part" ]; then
      bad "$label: could not extract $fn — the arm is not measuring anything"
      return
    fi
    B+="$part"$'\n'
  done
  # A body with no vhost write in it is not the writer, and every arm below
  # would pass on it vacuously.
  if ! derives "$B" 'os\.WriteFile\(tmp, \[\]byte\((rendered|body)\)'; then
    bad "$label: the extracted body writes no vhost — the arm is pointed at the wrong function"
    return
  fi
  if derives "$B" 'os\.ReadFile\(target\.Path\)|previous := gitBuildReadOpt\(target\.Path\)'; then
    ok "$label snapshots the existing vhost before replacing it"
  else
    bad "$label replaces a vhost without reading what was there"
  fi
  if derives "$B" 'NginxRestoreOrRemove\(target\.Path, previous\)'; then
    ok "$label restores through NginxRestoreOrRemove on failure"
  else
    bad "$label no longer restores on failure"
  fi
  # The defect itself: a delete of the SHARED path. Keyed on the property, not on
  # one spelling — probe P8 renamed the variable and walked straight through an
  # arm that grepped one name. So: every os.Remove in these bodies must be
  # cleaning up a tmp/restore file.
  local strays
  strays=$(grep -oE 'os\.Remove(All)?\([^)]*\)' <<< "$B" | grep -cvE '\(tmp\)|\.tmp|\.restore' || true)
  if [ "$strays" -eq 0 ]; then
    ok "$label deletes nothing but its own temporary files"
  else
    bad "$label has $strays delete(s) of something other than a temp file"
  fi
}

check_writer "$NGINX_ROUTE" putSite "put_site"
check_writer "$APPS_ROUTE"  "dockerAppsExposeDomain|dockerAppsWriteVhost" "the Docker-app auto-proxy write"
# git_build's writer returns an error rather than an HTTP response.
check_writer "$GIT_BUILD"   "gitBuildSetupNginxProxy|gitBuildWriteVhost" "the git-deploy writer"

# ...and the extraction must stay reachable. A shared writer nothing calls is a
# refactor that quietly deleted a feature.
ARD=$(subj "$APPS_ROUTE") || ARD=""
if [ -n "$ARD" ]; then
  DEP=$(fnbody "$ARD" dockerAppsDeploy)
  if derives "$DEP" 'dockerAppsExposeDomain\('; then
    ok "the app deploy still reaches the vhost writer"
  else
    bad "the app deploy no longer writes a vhost at all"
  fi
fi

# The comment that lied for as long as the code did. Raw file on purpose: this
# arm is ABOUT a comment. (Anchor: the subject file exists — checked at the top.)
if [ -f "$NGINX_ROUTE" ]; then
  if grep -qE 'remove it and restore' "$NGINX_ROUTE"; then
    bad "the 'remove it and restore' comment is back over code that only removes"
  else
    ok "no comment promises a restore that the code does not perform"
  fi
fi

echo
echo "== §D  the Traefik route key is injective =="

if S=$(subj "$TRAEFIK"); then
  K=$(fnbody "$S" TraefikRouteKey)
  if [ -z "$K" ]; then
    bad "TraefikRouteKey is gone — the route filename mangling is unowned again"
  fi
  # hyphen-escape retired: covered by TestDistinctDomainsGetDistinctKeys (panel/go/internal/agent/services/traefik_test.go)
  # Only the deliberately-kept legacy path may use the ambiguous mangling — and
  # it must still be visible to this detector (exactly one), or the count is vacuous.
  n=$(count "$S" 'ReplaceAll\([^)]*"\.", "-"\)')
  L=$(fnbody "$S" traefikLegacyRouteConfigPath)
  if [ "$n" -eq 1 ] && has "$L" 'ReplaceAll\([^)]*"\.", "-"\)'; then
    ok "the ambiguous mangling survives only in the legacy-cleanup path"
  else
    bad "$n uses of the ambiguous dot-to-hyphen mangling (expected exactly the legacy path's one)"
  fi
  W=$(fnbody "$S" TraefikWriteRouteConfig)
  if derives "$W" 'TraefikRouteKey\(domain\)'; then
    ok "the writer uses the injective key"
  else
    bad "the writer no longer uses the injective key"
  fi
  P=$(fnbody "$S" traefikRouteConfigPath)
  if derives "$P" 'TraefikRouteKey\(domain\)'; then
    ok "the reader derives the same key as the writer"
  else
    bad "reader and writer can disagree about where a route file lives"
  fi
fi

echo
echo "== §E  the guard runs BEFORE the side effects =="

# docker_apps deploy creates a DNS A record inside its background task. A
# domain rejected after that point still leaves a live record behind, so the
# claim has to be settled before the `go` — ordering, which no presence grep
# can see.
if S=$(subj "$APPS_BE"); then
  B=$(fnbody "$S" rtDockerAppsDeploy)
  g=$(grep -nE 'DomainClaimEnsureClaimable\(' <<< "$B" | head -1 | cut -d: -f1)
  s=$(grep -nE '^[[:space:]]*go [A-Za-z(]' <<< "$B" | head -1 | cut -d: -f1)
  if [ -n "$g" ] && [ -n "$s" ] && [ "$g" -lt "$s" ]; then
    ok "the app deploy settles its domain claim before spawning (and before DNS)"
  else
    bad "the app deploy's domain claim no longer precedes the spawned side effects"
  fi
fi

echo
echo "== §F  the client gate lives at the choke point, and no caller can fake it =="

# s312 / GitHub #51. A `client` holds sites and may not bring a NEW domain into
# service. The gate is one check inside the shared guard rather than a role
# check at each creating handler: git_deploys, docker_apps and stacks all
# materialise a served vhost WITHOUT inserting into `sites`.
if S=$(subj "$CLAIM"); then
  B=$(fnbody "$S" DomainClaimEnsureClaimable)
  if [ -z "$B" ]; then
    bad "§F: could not extract DomainClaimEnsureClaimable — the arms are not measuring anything"
  else
    if derives "$B" 'DomainClaimMayClaimNew\(claimantRole, holder\)'; then
      ok "the shared guard consults the claim-permission rule"
    else
      bad "the shared guard no longer consults the claim-permission rule"
    fi
    # Ordering: refusing AFTER the occupancy lookup would let a client probe which
    # domains are free by reading which error comes back.
    g=$(grep -nE 'DomainClaimMayClaimNew' <<< "$B" | head -1 | cut -d: -f1)
    o=$(grep -nE 'DomainClaimFindOccupant' <<< "$B" | head -1 | cut -d: -f1)
    if [ -n "$g" ] && [ -n "$o" ] && [ "$g" -lt "$o" ]; then
      ok "the permission check precedes the occupancy lookup"
    else
      bad "a refused claimant still learns whether the domain was free"
    fi
  fi
  # may_claim_new-keyed-on-New retired: covered by TestDomainClaimAClientMayNotBringANewDomainIntoService + TestDomainClaimAClientMayStillManageTheDomainsItHolds (panel/go/internal/api/svc_domain_claim_test.go)
fi

# The arm that matters most. Every call site must pass a role it READ from the
# request; a literal makes the gate vacuous while leaving every other arm green.
# gofmt keeps these calls on one line; the positive control proves the detector
# still sees them all.
BYPASS=0; CALLS=0
for f in "$SITES" "$STAGING" "$MIG" "$GITDEP" "$APPS_BE" "$STACKS"; do
  S=$(subj "$f") || continue
  CALLS=$((CALLS + $(occurrences "$S" 'DomainClaimEnsureClaimable\(')))
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    BYPASS=$((BYPASS+1))
    bad "$(basename "$f") passes a hardcoded role to the guard: $hit"
  done < <(grep -oE 'DomainClaimEnsureClaimable\(.*"(admin|reseller|user|client)".*' <<< "$S")
done
if [ "$CALLS" -ge 8 ]; then
  ok "the role-literal detector sees $CALLS guard call sites (positive control)"
else
  bad "the role-literal detector sees only $CALLS guard call sites — a multi-line call would walk past it"
fi
[ "$BYPASS" -eq 0 ] && ok "no claim path hardcodes the role the gate reads"

# And the rule must actually be reachable from a real role value: the string the
# gate compares against has to be the same one the database CHECK permits.
MIGR=$(ls $GO/api/migrations/*client_role.sql 2>/dev/null | head -1)
if [ -n "$MIGR" ] && [ -f "$MIGR" ]; then
  if grep -qE "CHECK \(role IN \(.*'client'.*\)\)" "$MIGR"; then
    ok "the database permits the role value the gate refuses on"
  else
    bad "the migration does not admit 'client' — the gate can never fire"
  fi
else
  bad "no client-role migration found — the gate refuses a value no account can hold"
fi

echo "== §G  a mail domain is a domain HOLDER, and only an admin may claim over it =="

# s347 / GitHub #106. Client-scoped mail matches `mail_domains.domain` against the
# domain of a site the caller owns — which makes `sites.domain` an authorisation
# key, and that column is writable by the very account being authorised. Before
# this, the occupancy oracle never asked about mail: so a non-admin could point a
# site they already owned at a name whose mailboxes existed and mint their own
# access to them.

if S=$(subj "$CLAIM"); then
  B=$(fnbody "$S" DomainClaimFindOccupant)
  if [ -z "$B" ]; then
    bad "§G: could not extract DomainClaimFindOccupant"
  else
    if derives "$B" 'mail_domains'; then
      ok "the occupancy oracle asks whether a mail domain holds the name"
    else
      bad "DomainClaimFindOccupant no longer asks about mail domains — a non-admin can claim a name whose mailboxes exist"
    fi

    # Ordering is load-bearing: the guard TOLERATES this occupant for an
    # administrator, so a mail domain reported IN PLACE OF a vhost holder would
    # let an admin claim over a live site, git deploy, stack or app.
    m=$(grep -nE 'mail_domains' <<< "$B" | head -1 | cut -d: -f1)
    a=$(grep -nE '"/apps"' <<< "$B" | head -1 | cut -d: -f1)
    if [ -n "$m" ] && [ -n "$a" ] && [ "$m" -gt "$a" ]; then
      ok "the mail question is asked LAST, after every holder that must always refuse"
    else
      bad "the mail leg no longer runs last — a tolerated occupant can now mask a vhost collision"
    fi

    # Fleet-wide and case-folded, like the SQL legs above it.
    q=$(grep -oE 'SELECT id FROM mail_domains[^"]*' <<< "$B" | head -1)
    if [ -n "$q" ] && ! grep -qE 'server_id' <<< "$q"; then
      ok "the mail leg is fleet-wide, matching the sites/git/stack legs"
    else
      bad "the mail leg grew a server term — a name can be claimed on one host while its mail lives on another"
    fi
    if [ -n "$q" ] && grep -qE 'lower\(domain\)' <<< "$q"; then
      ok "the mail leg folds case rather than trusting the writer's convention"
    else
      bad "the mail comparison is case-sensitive — EXAMPLE.com walks past a row holding example.com"
    fi
  fi

  E=$(fnbody "$S" DomainClaimEnsureClaimable)
  if [ -z "$E" ]; then
    bad "§G: could not extract DomainClaimEnsureClaimable"
  else
    if derives "$E" 'DomainClaimMayClaimMailHeld\(claimantRole\)'; then
      ok "the guard consults the mail-claim rule before tolerating an occupant"
    else
      bad "the guard stopped consulting the mail-claim rule — either every claim is refused, or every claim is allowed"
    fi
    # The tolerance must name exactly ONE occupant. Folding a second into that
    # branch would let an administrator claim over a live vhost, and it would
    # look like a one-word change. OCCURRENCES, not lines (see occurrences()).
    n=$(occurrences "$E" 'DomainClaimOccupant[A-Z][A-Za-z]*')
    if [ "$n" -eq 1 ]; then
      ok "exactly one occupant is tolerated, and it is named explicitly"
    else
      bad "the tolerance branch names $n occupants — it must name only the mail one"
    fi
    if derives "$E" '\*occ != DomainClaimOccupantMailDomain'; then
      ok "the tolerated occupant is the mail domain"
    else
      bad "the tolerance is no longer keyed on the mail occupant"
    fi
  fi

  # mail-gate-admin-only retired: covered by TestDomainClaimOnlyAnAdministratorMayClaimADomainAMailDomainHolds + TestDomainClaimTheMailGateFailsClosedWhereTheClientGateFailsOpen (panel/go/internal/api/svc_domain_claim_test.go)
  # mail-occupant-message retired: covered by TestDomainClaimEveryOccupantNamesWhatHoldsTheDomain (panel/go/internal/api/svc_domain_claim_test.go)
fi

echo
echo "──────────────────────────────────────────"
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" -eq 0 ]
