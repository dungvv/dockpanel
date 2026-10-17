#!/usr/bin/env bash
# app-data-persistence-pin-e2e.sh — s357 / v2.111.0
#
# Pins the fix for GitHub #110: pressing "Update" on a Docker App destroyed the
# app's data, and nothing in the panel said it would.
#
# (Subjects now live in panel/go: internal/agent/services/docker_apps.go —
# DockerAppsMigrateUnmountedVolumes, DockerAppsUpdateApp, … — and the api's
# rt_docker_apps.go / rt_mail.go / rt_system.go.)
#
# The mechanism is worth stating precisely, because the guard that was already
# there is CORRECT and was never the problem. Every recreate path removes the
# container keeping its volumes — "keep the volumes" — and
# a comment above it says data therefore persists. That is true of volumes. It is
# not true of DATA: a container with no mount keeps its state in its own writable
# layer, and `docker rm` deletes the writable layer whatever `v` says. n8n's
# template declared `volumes: &[]` and the `n8nio/n8n:1` image declares no VOLUME
# of its own, so the reporter's workflows, credentials and owner account had
# nowhere to be except the layer that was deleted. Unrecoverable, and silent.
#
#   §A  every path that recreates a managed app container MIGRATES first — it
#       copies anything the template calls persistent out of the writable layer
#       onto a bind mount BEFORE the remove, and ABORTS without removing if that
#       fails. This is what reaches boxes already deployed: declaring the volume
#       fixes the next deploy and does nothing for the container already running.
#   §B  blue-green never runs two containers against one mount. It starts the
#       replacement while the original still serves, cloning the old HostConfig
#       and rewriting only the port bindings — so both held the same host paths
#       for the length of the health check. Postgres/MySQL/Mongo self-protect
#       with a pidfile lock; SQLite does not.
#   §C  the templates whose state lives INSIDE the container declare where it is.
#   §D  the verbs that do real work are long ones. Recreating now copies data and
#       has always pulled an image; the mail installers run apt. On the 60s verb
#       a slow success is reported to the operator as a failure.
#   §E  the "installed but not running" banner names the term that is actually
#       false. The agent computes `running` from FOUR terms and the banner named
#       two, so an operator whose Postfix and Dovecot were both `active` was sent
#       to look at them and learned nothing. #110's reporter hit exactly this.
#
# §A IS A CENSUS, NOT A SPOT CHECK. It enumerates the recreate paths FROM THE
# SOURCE — every fn that both removes and creates a container — and judges each.
# A suite naming today's three would go green on tomorrow's fourth. The
# enumeration is asserted non-empty AND against its expected size before it is
# trusted (lesson #143).
#
# ⚠ A4 PINS THE CAPABILITY, NOT THE CALL, and it is not redundant with A3.
# `migrate_unmounted_volumes` could keep every call site and still be harmless if
# its own body swallowed the copy failure — the arms that ask "does the handler
# call it?" would all stay green while the function returned Ok on a failed copy
# and the caller cheerfully removed the container. That is lesson #472's shape:
# a defect can live somewhere no call-site arm can see.
#
# ⚠ EVERY ARM READS COMMENT-STRIPPED SOURCE. The fix's own comments name
# `migrate_unmounted_volumes`, `#110`, `writable layer` and `post_long` — counted
# raw, several arms would be satisfied by the prose describing them (lesson #469,
# and the source-pin prose trap).
#
# Pure source analysis: no box, no network, no build.
#
# MUTATION-TESTED at HEAD — see the run recorded in the ledger. Each mutation is
# killed by the arm it names, with the control asserted to print a real summary
# first (an empty one is not a pass, lesson #461).
#
# NO PIPES INTO `grep -q` — under `set -o pipefail` grep -q closes the pipe on its
# first match and the arm goes red on correct code (lesson #414). Every arm uses a
# here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

AGENT_SVC=panel/go/internal/agent/services/docker_apps.go
BE_APPS=panel/go/internal/api/rt_docker_apps.go
BE_MAIL=panel/go/internal/api/rt_mail.go
BE_SYS=panel/go/internal/api/rt_system.go
MAIL_TSX=panel/frontend/src/pages/Mail.tsx

for f in "$AGENT_SVC" "$BE_APPS" "$BE_MAIL" "$BE_SYS" "$MAIL_TSX"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT. Copied from the FIXED stripper (lesson #136): the
# naive s{/\*.*?\*/}{}gs deletes real code because `/*` occurs inside string
# literals, and a truncated subject makes an ABSENCE arm pass on code the
# stripper merely removed — failure in the reassuring direction. Go line
# comments: whole-line `//`, and trailing `//` only after whitespace (so a
# `https://` literal survives). Go tests live in _test.go files, so there is no
# test module to cut: §A's census is over shipping code by construction.
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^[ \t]*//.*$}{}gm;
    s{[ \t]+//[^"`\n]*$}{}gm;
  ' "$1"
}

subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }

# The body of one top-level Go func (or method), bounded by its own closing `}`
# at column 0. A fixed `grep -A n` window is not a function (lessons #131/#172).
fnbody() {
  awk -v name="$2" '
    !inside && (index($0, "func " name "(") == 1 || $0 ~ ("^func \\([^)]*\\) " name "\\(")) { inside=1; next }
    inside { if ($0 == "}") exit; print }
  ' <<< "$1"
}

# Names of the top-level funcs in $1 (stripped source) whose body matches $2.
# The enclosing-func map is COMPUTED, never assumed — this is what makes §A a
# census rather than a list.
fns_matching() {
  awk -v pat="$2" '
    /^func / {
      cur=$0
      sub(/^func (\([^)]*\) )?/, "", cur)
      sub(/[(\[].*$/, "", cur)
      next
    }
    /^}/ { cur=""; next }
    cur != "" && $0 ~ pat { if (!seen[cur]++) print cur }
  ' <<< "$1"
}

# First 1-based line number in $1 matching $2, or empty.
lineof() { awk -v pat="$2" '$0 ~ pat { print NR; exit }' <<< "$1"; }

# A container leaves through docker.ContainerRemove directly or through the
# stop+remove helper; both are a remove.
RM_PAT='ContainerRemove[(]|dockerAppsStopRemove[(]'

echo "== §A  every recreate path migrates before it removes =="

if S=$(subj "$AGENT_SVC"); then
  # A recreate path is a function that BOTH removes a container and creates one.
  # Derived from the source, so a fourth one added later is judged automatically.
  removers=$(fns_matching "$S" "$RM_PAT")
  creators=$(fns_matching "$S" 'ContainerCreate[(]')
  recreate=$(comm -12 <(sort <<< "$removers") <(sort <<< "$creators"))
  n_recreate=$(grep -c . <<< "$recreate")

  # EVERY member of the census is either migrating or EXPLICITLY exempt, with the
  # reason written here. A count ("expect 3") would have been satisfied by any
  # three of them and silently stopped judging the rest; worse, an exclusion that
  # is not written down is revocable by whoever next edits the file (lesson #426).
  # The exemptions, each checked against the source below:
  #   dockerAppsBlueGreenUpdate — creates the replacement and removes the ORIGINAL,
  #                           so it does destroy a writable layer. It is exempt
  #                           because DockerAppsUpdateApp refuses to reach it while
  #                           a migration is pending (arm B2); the exemption is
  #                           enforced there, not granted here.
  #   DockerAppsDeployApp   — the remove is collision cleanup before a FIRST create.
  #                           There is no prior data by construction.
  #   dockerAppsCopyOutOfImage — the Go merge of Rust's read_file_from_image and
  #                           seed_volume_from_image: it CREATES a container purely
  #                           so Docker's copy API has a filesystem to read, never
  #                           starts it, and removes it again. Nobody's data was
  #                           ever in it. Enumerated because the census keys on
  #                           remove+create, the right proxy for a recreate path
  #                           and the wrong one for a probe.
  EXEMPT="dockerAppsBlueGreenUpdate DockerAppsDeployApp dockerAppsCopyOutOfImage"

  if [ "$n_recreate" -eq 0 ]; then
    bad "A0 enumeration found ZERO recreate paths — the census examined nothing"
  elif [ "$n_recreate" -lt 4 ]; then
    bad "A0 enumeration found only $n_recreate paths — implausibly few, the census is broken"
  else
    ok "A0 census enumerated $n_recreate remove-and-create paths from source"
  fi

  # An exemption naming a function that no longer exists is an exemption that has
  # stopped being checked — it would silently excuse nothing while a renamed
  # successor went unjudged.
  for e in $EXEMPT; do
    if grep -qx "$e" <<< "$recreate"; then
      ok "A0b exemption '$e' still names a real recreate path"
    else
      bad "A0b exemption '$e' matches no enumerated path — it was renamed or removed; re-adjudicate it"
    fi
  done

  while read -r fn; do
    [ -n "$fn" ] || continue
    case " $EXEMPT " in *" $fn "*) continue ;; esac
    body=$(fnbody "$S" "$fn")
    if [ -z "$body" ]; then
      bad "A1 $fn — extracted an EMPTY body, the arm examined nothing"
      continue
    fi

    # A1 — it migrates at all.
    if grep -q 'DockerAppsMigrateUnmountedVolumes(' <<< "$body"; then
      ok "A1 $fn migrates unmounted volumes"
    else
      bad "A1 $fn removes and recreates a container WITHOUT migrating its data (#110)"
    fi

    # A2 — ORDER. A migration after the remove reads identically to a presence
    # grep and rescues nothing: the data is already gone.
    l_mig=$(lineof "$body" 'DockerAppsMigrateUnmountedVolumes[(]')
    l_rm=$(lineof "$body" "$RM_PAT")
    if [ -n "$l_mig" ] && [ -n "$l_rm" ] && [ "$l_mig" -lt "$l_rm" ]; then
      ok "A2 $fn migrates BEFORE it removes (line $l_mig < $l_rm)"
    else
      bad "A2 $fn does not migrate before removing (migrate=${l_mig:-none} remove=${l_rm:-none})"
    fi

    # A3 — the failure ABORTS. A migration whose error is swallowed is followed by
    # a remove that destroys exactly what the call was there to save. In Go that
    # is the migration's own `err != nil` branch returning, between the call and
    # the remove.
    seg=$(awk -v rm="$RM_PAT" '/DockerAppsMigrateUnmountedVolumes[(]/{f=1} f{print} f && $0 ~ rm {exit}' <<< "$body")
    if [ -z "$seg" ]; then
      bad "A3 $fn — could not isolate the migrate..remove segment, the arm examined nothing"
    elif awk '/DockerAppsMigrateUnmountedVolumes[(]/{f=1} f && /err != nil \{/{g=1} g && /^[[:space:]]*return /{found=1; exit} END{exit !found}' <<< "$seg"; then
      ok "A3 $fn returns on a migration failure instead of removing anyway"
    else
      bad "A3 $fn swallows a migration failure and removes the container regardless"
    fi
  done <<< "$recreate"

  # A4 — THE CAPABILITY, pinned separately from the call (#472). Every call site
  # above can be present and correct while this function quietly returns nil on a
  # failed copy, and no call-site arm can see that.
  mig=$(fnbody "$S" "DockerAppsMigrateUnmountedVolumes")
  if [ -z "$mig" ]; then
    bad "A4 DockerAppsMigrateUnmountedVolumes does not exist as a top-level func"
  else
    # The COPY-FAILURE path specifically, not a count of error paths anywhere in
    # the body. A count is satisfied by the failures that were never in question
    # (mkdir, canonicalize, prefix) while the one that decides whether a remove
    # follows a lost copy is quietly deleted — which is exactly what the
    # mutation run demonstrated against the first cut of this arm.
    cp_branch=$(awk '/if !out\.Success\(\) \{/{f=1} f{print} f&&/^\t\t\}$/{exit}' <<< "$mig")
    if [ -z "$cp_branch" ]; then
      bad "A4 could not isolate the docker-cp failure branch — the arm examined nothing"
    elif grep -q 'return nil, fmt.Errorf(' <<< "$cp_branch"; then
      ok "A4 a failed copy returns an error, so the caller never reaches the remove"
    else
      bad "A4 a failed copy does NOT return an error — the container is removed anyway and the data is gone"
    fi
    # It must decline rather than merge into a directory that already holds data.
    if grep -qE 'dockerAppsDirIsEmpty\(hostDir\); ok && !empty \{' <<< "$mig"; then
      ok "A4b DockerAppsMigrateUnmountedVolumes refuses a non-empty destination"
    else
      bad "A4b DockerAppsMigrateUnmountedVolumes would merge into an existing directory"
    fi
    # The prefix check must survive symlink resolution, as the deploy path's does.
    l_canon=$(lineof "$mig" 'filepath[.]EvalSymlinks[(]')
    l_pref=$(lineof "$mig" 'strings[.]HasPrefix[(]resolved,')
    if [ -n "$l_canon" ] && [ -n "$l_pref" ] && [ "$l_canon" -lt "$l_pref" ]; then
      ok "A4c DockerAppsMigrateUnmountedVolumes re-checks the prefix AFTER canonicalizing"
    else
      bad "A4c DockerAppsMigrateUnmountedVolumes does not re-check its prefix after canonicalizing"
    fi
  fi

  # A5 retired: covered by TestAManagedContainerOutsideTheCatalogueStillDeclaresItsState (panel/go/internal/agent/services/docker_apps_test.go) — both Binds and Mounts spellings
  # A6 retired: covered by TestAManagedContainerOutsideTheCatalogueStillDeclaresItsState (panel/go/internal/agent/services/docker_apps_test.go) — unmanaged and compose containers get nothing
fi

echo "== §B  blue-green never runs two writers against one mount =="

if S=$(subj "$AGENT_SVC"); then
  ua=$(fnbody "$S" "DockerAppsUpdateApp")
  if [ -z "$ua" ]; then
    bad "B0 DockerAppsUpdateApp body is empty — §B examined nothing"
  else
    l_guard=$(lineof "$ua" 'DockerAppsSharesPersistentState')
    l_bg=$(lineof "$ua" 'dockerAppsBlueGreenUpdate[(]')
    if [ -n "$l_guard" ] && [ -n "$l_bg" ] && [ "$l_guard" -lt "$l_bg" ]; then
      ok "B1 DockerAppsUpdateApp consults DockerAppsSharesPersistentState before blue-green"
    else
      bad "B1 DockerAppsUpdateApp reaches blue-green without asking whether state is shared"
    fi
    l_un=$(lineof "$ua" 'len[(]unmounted[)] > 0')
    if [ -n "$l_un" ] && [ -n "$l_bg" ] && [ "$l_un" -lt "$l_bg" ]; then
      ok "B2 DockerAppsUpdateApp declines blue-green when a migration is pending"
    else
      bad "B2 DockerAppsUpdateApp could blue-green a container whose data still needs migrating"
    fi
  fi
  # B3 retired: covered by TestPinAppDataPersistenceEverySharingSpellingCounts (panel/go/internal/agent/services/pin_app_data_persistence_test.go)
fi

echo "== §C  templates whose state lives in the container declare where =="
# C1 retired: covered by TestPinAppDataPersistenceStatefulTemplatesDeclareTheirVolume (panel/go/internal/agent/services/pin_app_data_persistence_test.go)
# C2 retired: covered by TestPinAppDataPersistenceCatalogueEnvShape (panel/go/internal/agent/services/pin_app_data_persistence_test.go)
# C3 retired: covered by TestPinAppDataPersistenceCatalogueEnvShape (panel/go/internal/agent/services/pin_app_data_persistence_test.go)

echo "== §D  the verbs that do real work are long ones =="

if B=$(subj "$BE_APPS"); then
  # Every dispatch to an agent endpoint that recreates a container. Enumerated,
  # not listed: /update, /env and /change-image all copy data now.
  # ⚠ POSITIVE CONTROL FIRST. The first cut of this arm used a pattern with an
  # unbalanced group; grep ERRORED, the capture came back empty, and the arm read
  # that as "no short-verb dispatches found" and printed GREEN. An extraction that
  # failed and an extraction that found nothing are indistinguishable unless you
  # prove the instrument can still find something (lessons #461, #473).
  ctl=$(grep -cE '\.(Post|Put|PostLong|PutLong)\(' <<< "$B")
  if [ "${ctl:-0}" -lt 5 ]; then
    bad "D1-control matched only ${ctl:-0} agent dispatches in the apps route — the grep is broken, every §D verdict below is void"
  else
    ok "D1-control the dispatch grep matches $ctl call sites, so an empty result below means absence"
    # Census the HANDLERS, not the call text: Go builds each path inline as
    # "/apps/"+cid+"/<verb>".
    handlers=$(fns_matching "$B" '"/apps/"[+][a-zA-Z]+[+]"/(update|env|change-image)')
    n_h=$(grep -c . <<< "$handlers")
    # Written-down exemptions, each verified against the agent it dispatches to:
    #   rtDockerAppsAppEnv       — GET /apps/{id}/env. Reads, never recreates.
    #   rtDockerAppsUpdateLimits — POST /apps/{id}/update-limits, which the agent
    #                   serves with `docker update`: an in-place change to cgroup
    #                   limits on the RUNNING container. Nothing is removed.
    # The name-match is deliberately loose (it catches "update-limits" on the word
    # "update"), and an exemption is the honest way to narrow it — a tighter regex
    # would have hidden these two rather than adjudicating them.
    D_EXEMPT="rtDockerAppsAppEnv rtDockerAppsUpdateLimits"
    d_bad=0
    if [ "$n_h" -lt 3 ]; then
      bad "D1 enumerated only $n_h handlers — implausibly few, the census is broken"
      d_bad=1
    else
      ok "D1 census enumerated $n_h app-endpoint handlers"
      for e in $D_EXEMPT; do
        grep -qx "$e" <<< "$handlers" || bad "D1-exempt '$e' matches no handler — re-adjudicate it"
      done
      while read -r h; do
        case " $D_EXEMPT " in *" $h "*) continue ;; esac
        [ -n "$h" ] || continue
        hb=$(fnbody "$B" "$h")
        if [ -z "$hb" ]; then
          bad "D1 $h — empty body, the arm examined nothing"; d_bad=1; continue
        fi
        if grep -qE 'agent\.(Post|Put)\([^,]*"/apps/"' <<< "$hb"; then
          bad "D1 $h dispatches a container recreate on the SHORT verb"
          d_bad=1
        fi
        if ! grep -qE '\.(PostLong|PutLong)\(' <<< "$hb"; then
          bad "D1 $h has no long-verb dispatch at all"
          d_bad=1
        fi
      done <<< "$handlers"
    fi
    [ "$d_bad" -eq 0 ] && ok "D1 all three app-recreate dispatches use a long verb"
  fi

  n_long=$(grep -cE '\.(PostLong|PutLong)\(' <<< "$B")
  if [ "$n_long" -ge 3 ]; then
    ok "D1b $n_long long-verb dispatches present in the apps route"
  else
    bad "D1b only $n_long long-verb dispatches — expected at least 3"
  fi
fi

if M=$(subj "$BE_MAIL"); then
  # A census of the INSTALLERS, keyed on what they do rather than on a list.
  short=$(grep -nE '\.Post\([^,]+, "/mail/(install|uninstall|rspamd/install|webmail/install)"' <<< "$M")
  if [ -z "$short" ]; then
    ok "D2 no mail installer is dispatched on the 60s verb"
  else
    bad "D2 mail installer(s) still on the short verb: $(tr -s ' ' <<< "$short" | head -4)"
  fi
  n_ml=$(grep -cE '\.PostLong\([^,]+, "/mail/(install|uninstall|rspamd/install|webmail/install)"' <<< "$M")
  if [ "$n_ml" -eq 4 ]; then
    ok "D2b all four mail installers use PostLong"
  else
    bad "D2b $n_ml of 4 mail installers use PostLong"
  fi
fi

if Y=$(subj "$BE_SYS"); then
  if grep -qE '\.Post\([^,]+, "/services/install/powerdns"' <<< "$Y"; then
    bad "D3 the PowerDNS installer is still on the 60s verb"
  elif grep -qE '\.PostLong\([^,]+, "/services/install/powerdns"' <<< "$Y"; then
    ok "D3 the PowerDNS installer is dispatched on the long verb"
  else
    bad "D3 no PowerDNS install dispatch found at all — the absence above would be vacuous"
  fi
fi

# D4 retired (obsolete in Go): PutLong is a method of the AgentHandle interface
# (panel/go/internal/api/svc_agent.go), so the compiler refuses any agent client
# that lacks it — the per-client count this arm kept is now a type check.

echo "== §E  the mail banner names the term that is actually false =="

if T=$(subj "$MAIL_TSX"); then
  # The agent computes `running` from four terms. The page must read all four,
  # or it can only ever name the two it was hardcoded with.
  miss=""
  for term in postfix dovecot opendkim configured; do
    grep -q "$term" <<< "$T" || miss="$miss $term"
  done
  if [ -z "$miss" ]; then
    ok 'E1 the mail page reads all four terms behind the running flag'
  else
    bad "E1 the mail page cannot see:$miss — its banner can never name them"
  fi

  # The old sentence sent every operator to the same two services regardless of
  # cause. Its absence is the fix; count occurrences rather than asserting zero
  # blindly, so a reintroduction anywhere in the file is caught.
  n_old=$(grep -cF 'Check Postfix and Dovecot services' <<< "$T")
  if [ "$n_old" -eq 0 ]; then
    ok "E2 the two-of-four sentence is gone"
  else
    bad "E2 the two-of-four sentence is back ($n_old occurrence(s)) — it names half the causes"
  fi
fi

echo
printf 'PASS %d   FAIL %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
