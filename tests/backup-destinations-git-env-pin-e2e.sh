#!/usr/bin/env bash
#
# Regression pins for s288 — issues #93 and #94, two reports of the same shape:
# a feature whose halves were each present and were not connected to each other.
#
#   #94  The panel sent the container environment under the key "env_vars".
#        The agent's DeployRequest declared that field as `env` with a bare
#        #[serde(default)] (Rust era; the Go agent's gitBuildDeployRequest now
#        takes both spellings and refuses a body carrying both), so the unrecognised key was dropped and the
#        recognised one defaulted to empty. Every git deploy — Dockerfile and
#        Nixpacks, first deploy and redeploy, rollback and PR preview — started
#        its container with no environment, and every layer reported success.
#        A fifth call site, auto-rollback, sent no environment under either
#        spelling AND no memory_mb/cpu_percent, so a crashed container came back
#        both unconfigured and unbounded.
#
#   #93  The S3/SFTP destination form was written in Settings, then switched off
#        behind `{false && (` by the commit that moved the Destinations tab to
#        Backup Manager — which carried across the list and the Test button and
#        left create, update and delete with no caller anywhere in the panel.
#        The empty state went on telling operators to "add one via Settings".
#        Underneath, two of the three places that hand a destination to the
#        agent posted the stored CIPHERTEXT as the credential, while the third —
#        Test Connection — decrypted, so a destination verified green and then
#        failed every real upload. And the per-site schedule's destination check
#        inner-joined on a column that is NULL on every destination the panel
#        creates, so it answered 403 for all of them.
#
# ⚠ EVERY CHECK BELOW STRIPS COMMENTS FIRST. The code these pins inspect
# explains these defects in its own comments, naming the very strings under
# test — "env_vars", `{false && (`, "via Settings". A raw-source grep would
# match the prose that documents the trap and pass while the code re-broke.
# See feedback_source_pin_prose_trap and lesson #110f.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# The Go port (panel/go) is what ships; the API package is flat.
API=panel/go/internal/api
GD_RS=$API/rt_git_deploys.go
AGENT_GB=panel/go/internal/agent/routes/git_build.go
BD_RS=$API/rt_backup_destinations.go
BSCHED_RS=$API/svc_backup_scheduler.go
BPOL_RS=$API/svc_backup_policy_executor.go
BSCHEDR_RS=$API/rt_backup_schedules.go
ORCH_TSX=panel/frontend/src/pages/BackupOrchestrator.tsx
SETTINGS_TSX=panel/frontend/src/pages/Settings.tsx
BACKUPS_TSX=panel/frontend/src/pages/Backups.tsx

for f in "$GD_RS" "$AGENT_GB" "$BD_RS" "$BSCHED_RS" "$BPOL_RS" "$BSCHEDR_RS" \
         "$ORCH_TSX" "$SETTINGS_TSX" "$BACKUPS_TSX"; do
  [ -f "$f" ] || { echo "missing file: $f"; exit 1; }
done

# Strip whole-line `//` comments FIRST, then block comments — that order matters
# and the reverse is a live hazard. The sibling suites do it the other way, and a
# doc comment containing `/*` (a path glob such as the agent's backups route with
# a wildcard, which this file's own subject matter has) reads as a block-comment
# opener: the scanner then swallows every remaining line, and each later check
# inspects an empty stream and PASSES for having found nothing wrong. That is the
# failure direction a pin must never have (lesson #100). Stripping line comments
# first means a glob inside one is gone before anything looks for an opener.
#
# `//` is only stripped at the start of a (trimmed) line: stripping it mid-line
# would blank the inside of every string containing a URL.
#
# Several arms below COUNT call sites, and a unit test that exercises the very
# function being counted would inflate the total and fail an arm whose subject
# is correct (#94c). In Go the tests live in separate _test.go files, which no
# arm reads, so there is no in-file test module to drop.
code_of() {
  awk '{ t=$0; sub(/^[ \t]+/,"",t); if (t !~ /^\/\//) print }' "$1" \
    | sed 's:/\*.*\*/::g' \
    | awk '
        /\/\*/ { inblk=1 }
        !inblk { print }
        /\*\// { inblk=0 }
      '
}

# Guard the guard: if stripping ever eats most of a file again, say so loudly
# rather than let the checks below pass on an empty stream.
assert_readable() {
  local raw stripped
  raw=$(wc -l < "$1")
  stripped=$(code_of "$1" | grep -c . || true)
  if [ "$raw" -gt 40 ] && [ "$stripped" -lt $((raw / 4)) ]; then
    bad "comment stripping consumed $1 ($stripped of $raw lines survive) — every check against it would pass vacuously"
    return 1
  fi
  return 0
}

# grep -c, never grep -q: under pipefail a `grep -q` match SIGPIPEs its producer
# and the pipeline reports FAILURE for a SUCCESSFUL match (#103d).
has()    { [ "$(code_of "$1" | grep -cF -- "$2")" -gt 0 ]; }
hasre()  { [ "$(code_of "$1" | grep -cE -- "$2")" -gt 0 ]; }
countre(){ code_of "$1" | grep -cE -- "$2" || true; }
countf() { code_of "$1" | grep -cF -- "$2" || true; }

echo "§0 the source these pins read survives comment stripping"
STRIP_OK=0
for f in "$GD_RS" "$AGENT_GB" "$BD_RS" "$BSCHED_RS" "$BPOL_RS" "$BSCHEDR_RS" \
         "$ORCH_TSX" "$SETTINGS_TSX" "$BACKUPS_TSX"; do
  assert_readable "$f" && STRIP_OK=$((STRIP_OK+1))
done
if [ "$STRIP_OK" -eq 9 ]; then
  ok "all 9 inspected files survive stripping"
fi

echo
echo "§1 the panel spells the environment the way the agent reads it (#94)"

# DISCOVERY, not a restated constant: the accepted spellings are parsed out of
# the agent's struct, and the sent spelling out of the panel's one builder. A
# rename on either side has to survive being compared with the other.
# Go: every map[string]string field of gitBuildDeployRequest, by its json tag.
# The first is the field, the rest are the accepted alternative spellings.
AGENT_ENV_TAGS=$(code_of "$AGENT_GB" \
  | awk '/^type gitBuildDeployRequest struct/,/^}/' \
  | grep -E 'map\[string\]string' \
  | grep -oE 'json:"[a-z_]+"' | sed -E 's/json:"([a-z_]+)"/\1/')
AGENT_FIELD=$(printf '%s\n' "$AGENT_ENV_TAGS" | head -1)
AGENT_ALIASES=$(printf '%s\n' "$AGENT_ENV_TAGS" | tail -n +2)
AGENT_KEYS=$(printf '%s\n%s\n' "$AGENT_FIELD" "$AGENT_ALIASES" | grep -c . || true)

if [ -n "$AGENT_FIELD" ] && [ "$AGENT_KEYS" -ge 2 ]; then
  ok "agent DeployRequest env field discovered: '$AGENT_FIELD' (+$((AGENT_KEYS-1)) alias) "
else
  bad "could not discover the agent's env field and at least one alias — a broken pattern must not read as a clean sweep (#100)"
fi

PANEL_KEY=$(code_of "$GD_RS" \
  | awk '/^func rtGitDeploysBuildDeployBody\(/,/^}/' \
  | grep -oE '"(env|env_vars)":' | grep -oE 'env(_vars)?' | head -1)

if [ -n "$PANEL_KEY" ]; then
  ok "panel rtGitDeploysBuildDeployBody sends the environment as '$PANEL_KEY'"
else
  bad "rtGitDeploysBuildDeployBody sends no env key at all — the deploy body has lost the environment again"
fi

# Both sides must be non-empty BEFORE they are compared. Without this guard the
# comparison passes when neither side was discovered: the accepted-spellings list
# is then two blank lines and `grep -x ""` matches the blank PANEL_KEY. Watched
# it do exactly that against the pre-fix tree, where it was the one arm of this
# section that stayed green while the defect it names was present.
if [ -z "$AGENT_FIELD" ] || [ -z "$PANEL_KEY" ]; then
  bad "cannot compare spellings: agent field='$AGENT_FIELD' panel key='$PANEL_KEY' — one side was not discovered, which is not a pass"
elif printf '%s\n%s\n' "$AGENT_FIELD" "$AGENT_ALIASES" | grep -cx -- "$PANEL_KEY" >/dev/null; then
  ok "'$PANEL_KEY' is a spelling the agent accepts"
else
  bad "the panel sends '$PANEL_KEY' and the agent accepts only: $(printf '%s %s' "$AGENT_FIELD" "$AGENT_ALIASES") — this is #94 exactly"
fi

echo
echo "§2 never both spellings in one body (#94's own fix would break every deploy)"

# §2 exactly-one-env-key retired: covered by TestRtGitDeploysDeployBodySendsTheKeyTheAgentReads (panel/go/internal/api/rt_git_deploys_test.go)
# The agent side of the same rule (a body with both spellings is refused) is the
# explicit `b.Env != nil && b.EnvVars != nil` check in gitBuildDeploy.
if hasre "$AGENT_GB" 'b\.Env != nil && b\.EnvVars != nil'; then
  ok "the agent refuses a body that carries both spellings"
else
  bad "gitBuildDeploy no longer refuses env + env_vars together — which spelling wins is now silent"
fi

echo
echo "§3 every deploy body comes from the one builder (#94's fifth call site)"

DEPLOY_CALLS=$(countf "$GD_RS" '"/git/deploy"')

if [ "$DEPLOY_CALLS" -ge 5 ]; then
  ok "found $DEPLOY_CALLS callers of /git/deploy to account for"
else
  bad "found only $DEPLOY_CALLS /git/deploy callers — the discovery pattern is broken, not the code (#100)"
fi

# Go shape: each caller passes either rtGitDeploysConfigDeployBody(...) (the
# row-built production body) or a local assigned from
# rtGitDeploysBuildDeployBody(rtGitDeploysDeployBody{...}). Anything else is a
# hand-rolled map — how auto-rollback lost env, memory_mb and cpu_percent.
BUILDER_CALLS=0
while IFS= read -r arg; do
  [ -n "$arg" ] || continue
  if [ "$arg" = rtGitDeploysConfigDeployBody ] \
     || hasre "$GD_RS" "$arg :?= rtGitDeploysBuildDeployBody\(rtGitDeploysDeployBody\{"; then
    BUILDER_CALLS=$((BUILDER_CALLS+1))
  fi
done < <(code_of "$GD_RS" | grep -oE '"/git/deploy", [A-Za-z_]+' | sed -E 's/.*, //')

if [ "$BUILDER_CALLS" -eq "$DEPLOY_CALLS" ]; then
  ok "all $DEPLOY_CALLS deploy bodies are built by rtGitDeploysBuildDeployBody"
else
  bad "$DEPLOY_CALLS callers of /git/deploy but $BUILDER_CALLS bodies from rtGitDeploysBuildDeployBody — a body is being hand-rolled again, which is how auto-rollback lost env, memory_mb and cpu_percent"
fi

if [ "$(code_of "$GD_RS" | awk '/^func rtGitDeploysConfigDeployBody\(/,/^}/' | grep -cE 'return rtGitDeploysBuildDeployBody\(rtGitDeploysDeployBody\{')" -eq 1 ]; then
  ok "rtGitDeploysConfigDeployBody itself goes through the builder"
else
  bad "rtGitDeploysConfigDeployBody no longer returns rtGitDeploysBuildDeployBody(...) — the shared production path is hand-rolled"
fi

# Rust enforced "every caller names every field" by DeployBody having no
# Default. A Go struct literal may omit fields and they zero silently, so the
# guarantee is now asserted on the one literal that every production deploy
# (manual, webhook, scheduled, rollback, auto-rollback) goes through. The
# preview literal omits memory/cpu/volumes deliberately and says so.
DB_FIELDS=$(code_of "$GD_RS" | awk '/^type rtGitDeploysDeployBody struct/,/^}/' \
  | grep -oE '^[[:space:]]+[A-Z][A-Za-z]+[[:space:]]' | tr -d ' \t')
CFG_BODY=$(code_of "$GD_RS" | awk '/^func rtGitDeploysConfigDeployBody\(/,/^}/')
NFIELDS=$(printf '%s\n' "$DB_FIELDS" | grep -c . || true)
MISSING=""
for fld in $DB_FIELDS; do
  [ "$(grep -cE "^[[:space:]]+$fld:" <<<"$CFG_BODY")" -gt 0 ] || MISSING="$MISSING $fld"
done
if [ "$NFIELDS" -lt 10 ]; then
  bad "discovered only $NFIELDS rtGitDeploysDeployBody fields — the discovery is broken, not the code (#100)"
elif [ -z "$MISSING" ]; then
  ok "rtGitDeploysConfigDeployBody names all $NFIELDS DeployBody fields — none zeroes silently"
else
  bad "rtGitDeploysConfigDeployBody omits:$MISSING — in Go an omitted field zeroes silently, which is how auto-rollback lost env and limits"
fi

echo
echo "§4 the environment reaching the agent is a map of strings (#94's aftermath)"

# §4 env_object-exists retired: covered by TestRtGitDeploysEnvScalarsAreStringifiedRatherThanFailingTheDeploy (panel/go/internal/api/rt_git_deploys_test.go)
# §4 env-from-coercion retired: covered by TestRtGitDeploysDeployBodySendsTheKeyTheAgentReads (panel/go/internal/api/rt_git_deploys_test.go)

echo
echo "§5 the destination the agent is given has been decrypted (#93, the silent half)"

# Discovery: every site that posts a destination to the agent, versus the one
# helper that decrypts. These must be the same set.
DECRYPT_CALLERS=$(
  # Shell arithmetic, not `| paste -sd+ | bc`: the Rust-era suite piped to bc,
  # which the CI/container image does not ship, so the sum came out empty and
  # this arm failed on a correct tree.
  echo $(( $(countre "$BD_RS"    'rtBackupDestinationsAgentDestinationPayload\(') \
         + $(countre "$BSCHED_RS" 'rtBackupDestinationsAgentDestinationPayload\(') \
         + $(countre "$BPOL_RS"   'rtBackupDestinationsAgentDestinationPayload\(') ))
)

if [ "$DECRYPT_CALLERS" -ge 3 ]; then
  ok "$DECRYPT_CALLERS call sites route through rtBackupDestinationsAgentDestinationPayload"
else
  bad "only $DECRYPT_CALLERS uses of rtBackupDestinationsAgentDestinationPayload — the scheduler and the policy executor must both go through it, or they post ciphertext as the credential while Test Connection reports success"
fi

for f in "$BSCHED_RS" "$BPOL_RS"; do
  if hasre "$f" '\["type"\][[:space:]]*='; then
    bad "$(basename "$f") folds \"type\" into a destination payload by hand — that is the hand-rolled path that skipped the decrypt"
  else
    ok "$(basename "$f") does not hand-roll a destination payload"
  fi
done

if [ "$(code_of "$BD_RS" | awk '/^func rtBackupDestinationsAgentDestinationPayload\(/,/^}/' | grep -cF 'rtBackupDestinationsDecryptConfigSecrets(config)')" -gt 0 ]; then
  ok "the shared helper is the thing that decrypts"
else
  bad "rtBackupDestinationsAgentDestinationPayload is missing or no longer decrypts"
fi

echo
echo "§6 a destination can be attached to a per-site schedule (#93, the 403)"

# Positive anchor first, then: any JOIN onto servers/backup_destinations that is
# not a LEFT JOIN.
if ! hasre "$BSCHEDR_RS" 'FROM backup_destinations bd'; then
  bad "rt_backup_schedules.go no longer selects from backup_destinations — the absence check below would see nothing"
elif [ "$(code_of "$BSCHEDR_RS" | grep -E 'JOIN (servers|backup_destinations)' | grep -cvE 'LEFT JOIN (servers|backup_destinations)' || true)" -gt 0 ]; then
  bad "the destination check still INNER JOINs servers on bd.server_id — that column is NULL on every destination the panel creates, so this answers 403 for all of them"
else
  ok "the destination check no longer inner-joins on a column that is always NULL"
fi

# s351 repointed this arm rather than relaxing it. The rule moved into a shared
# constant next to the route that LISTS the same set, because the writer admitted
# unscoped destinations while the only reader was administrator-only, so a site
# owner was granted a choice nothing could show them. The arm follows the code
# (lesson #150) and keeps asking the same question of it; that the writer still
# REACHES the constant is asserted next door, in client-surface-gating.
DEST_RS=$BD_RS
if hasre "$DEST_RS" 'rtBackupDestinationsDestinationCallerPredicate = .*bd\.server_id IS NULL' \
   && hasre "$BSCHEDR_RS" 'rtBackupDestinationsDestinationCallerPredicate'; then
  ok "an unscoped (shared) destination is accepted"
else
  bad "the check does not accept a NULL server_id — destinations created through the API have no server"
fi

echo
echo "§7 the three mutating endpoints have a caller in the panel (#93)"

# Discovery: the routes as registered, then whether the frontend calls each.
for verb in post put delete; do
  case $verb in
    post)   pat='api\.post\("/backup-destinations"' ; label="create" ;;
    put)    pat='api\.put\(`/backup-destinations/' ; label="update" ;;
    delete) pat='api\.delete<[^>]*>\(`/backup-destinations/|api\.delete\(`/backup-destinations/' ; label="delete" ;;
  esac
  if hasre "$ORCH_TSX" "$pat"; then
    ok "Backup Manager calls $label"
  else
    bad "no caller for $label — the endpoint is registered and unreachable, which is #93"
  fi
done

if hasre "$ORCH_TSX" 'Add Destination'; then
  ok "the Destinations tab offers an Add control"
else
  bad "the Destinations tab has no Add control"
fi

echo
echo "§8 nothing points the operator at a screen that no longer has the control (#93)"

DEST_CALLS_IN_SETTINGS=$(countf "$SETTINGS_TSX" '/backup-destinations')
if [ "$DEST_CALLS_IN_SETTINGS" -eq 0 ]; then
  ok "Settings makes no backup-destination calls"
else
  bad "Settings still has $DEST_CALLS_IN_SETTINGS backup-destination call(s) — the split ownership that produced #93"
fi

if hasre "$SETTINGS_TSX" '\{false && \('; then
  bad "Settings has a {false && (...)} block — a feature switched off in place is a feature nobody can find and nobody deletes"
else
  ok "Settings has no disabled-in-place block"
fi

for f in "$ORCH_TSX" "$BACKUPS_TSX" "$SETTINGS_TSX"; do
  if hasre "$f" '(via|in) \*{0,2}Settings'; then
    bad "$(basename "$f") still sends the operator to Settings for a destination"
  else
    ok "$(basename "$f") does not send the operator to Settings for a destination"
  fi
done

echo
echo "§9 the deep link the guidance layer already used actually lands (#93)"

PREREQ_RS=$API/svc_prerequisites_backups.go
if hasre "$PREREQ_RS" 'backup-orchestrator\?tab=destinations'; then
  ok "the prerequisite remediation links to the destinations tab"
else
  bad "the prerequisite no longer links to the destinations tab"
fi

if hasre "$ORCH_TSX" 'function tabFromSearch' && hasre "$ORCH_TSX" 'URLSearchParams'; then
  ok "the page reads ?tab= — the remediation link lands where it says"
else
  bad "BackupOrchestrator ignores ?tab=, so every link the panel already emits opens Overview instead"
fi

echo
echo "§10 a vault read derives its key — the raw JWT secret is not the vault key (s306)"

# Same shape as #94 at the top of this file, one layer down: the git deploy's
# environment was assembled correctly and never arrived, because the only reader
# of auto-inject secrets unlocked them with the wrong key material. AES-GCM
# authenticates, so a wrong key cannot yield garbage — it yields an Err, which a
# bare `if let Ok` discarded, leaving the agent call and the only log line inside
# an `if !env_pairs.is_empty()` that could not be entered.
#
# THE SUBJECTS ARE DERIVED, NOT LISTED. `secrets_crypto` exposes two families:
# the vault pair `encrypt`/`decrypt`, whose key is `secrets::get_encryption_key`,
# and the `*_credential*` family, whose key IS the JWT secret. Only the first is
# in scope. A hardcoded list of its call sites is precisely the arm that cannot
# see the next one (lesson #182) — this defect sat in a file such a list would
# never have named.
#
# s358 SPLIT THE READ PATH, so this section's subject moved (lesson #150) and
# the shape it used to require of a reader is now itself the defect. A vault
# READ goes through `secrets_crypto::decrypt_vault`, which tries every key
# source a value could have been written under. Deriving ONE source with
# `get_encryption_key` and handing it to the low-level `decrypt` is exactly what
# made adding `SECRETS_ENCRYPTION_KEY` strand every vault secret on an install
# that already held data — so writers must still derive, and readers must not.
#
# Go names (flat api package, no module qualifier): encrypt/decrypt/decrypt_vault
# → SecretsCryptoEncrypt / SecretsCryptoDecrypt / SecretsCryptoDecryptVault;
# get_encryption_key → rtSecretsGetEncryptionKey, a wrapper around
# SecretsCryptoVaultKeyPrimary (either counts as deriving). `func` definition
# lines are not calls and are dropped before matching.
VAULT_CALL='SecretsCrypto(Encrypt|Decrypt)\('
VAULT_SURFACE='SecretsCrypto(Encrypt|Decrypt|DecryptVault)\('
calls_of() { code_of "$1" | grep -vE '^func ' | grep -cE -- "$2" || true; }
VAULT_FILES=()
while IFS= read -r f; do
  [ -n "$f" ] && VAULT_FILES+=("$f")
done < <(grep -rlE "$VAULT_SURFACE" "$API" --include='*.go' 2>/dev/null | grep -v '_test\.go$' | sort)

if [ "${#VAULT_FILES[@]}" -lt 3 ]; then
  bad "enumerated only ${#VAULT_FILES[@]} files on the vault surface — implausible, so every arm below would pass having examined nothing"
else
  ok "enumerated ${#VAULT_FILES[@]} files on the vault surface"

  for f in "${VAULT_FILES[@]}"; do
    writes=$(calls_of "$f" 'SecretsCryptoEncrypt\(')
    if [ "$writes" -gt 0 ]; then
      if [ "$(countre "$f" 'rtSecretsGetEncryptionKey\(|SecretsCryptoVaultKeyPrimary\(')" -gt 0 ]; then
        ok "$(basename "$f") derives the vault key before writing"
      else
        bad "$(basename "$f") writes with the vault cipher without ever deriving the key — its values are unreadable by every other caller"
      fi
    else
      ok "$(basename "$f") does not write to the vault, so it owes no derivation"
    fi
  done

  # THE NEW INVARIANT, as an absence over the whole backend: outside the crypto
  # module itself, nothing may call the SINGLE-SOURCE `decrypt`. That call
  # cannot see a value written under a different key source, which is the
  # one-way door this section now exists to keep shut.
  SINGLE_SOURCE_READ='SecretsCryptoDecrypt\('
  SS_HITS=0
  for f in "${VAULT_FILES[@]}"; do
    case "$f" in */svc_secrets_crypto.go) continue ;; esac
    n=$(calls_of "$f" "$SINGLE_SOURCE_READ")
    if [ "$n" -gt 0 ]; then
      SS_HITS=$((SS_HITS + n))
      bad "$(basename "$f") reads the vault with the single-source cipher — a value written under any other key source is invisible to it"
    fi
  done
  # POSITIVE CONTROL for the absence above: the same matcher, same corpus, must
  # still find the multi-source read. Otherwise "found no violations" and "the
  # grep never ran" are the same output (lesson #480).
  MS_HITS=0
  for f in "${VAULT_FILES[@]}"; do
    MS_HITS=$((MS_HITS + $(calls_of "$f" 'SecretsCryptoDecryptVault\(')))
  done
  if [ "$MS_HITS" -lt 1 ]; then
    bad "control failed: found 0 multi-source vault reads, so the absence arm above proves nothing"
  else
    ok "control: $MS_HITS multi-source vault read(s) found, so the matcher works"
  fi
  if [ "$SS_HITS" -eq 0 ]; then
    ok "no caller outside secrets_crypto reads the vault single-source"
  fi
fi

# The defect itself, as a negative over the whole backend rather than over the
# enumeration above: the vault cipher may never be handed a JWT secret. This is
# the arm that would have been red for the four and a half months the feature
# was advertised and inert.
JWT_AS_VAULT_KEY='SecretsCrypto(Encrypt|Decrypt)\([^)]*,[[:space:]]*\*?[A-Za-z_.]*(jwt_?[sS]ecret|JWTSecret)\)'
JWT_KEYED=0
for f in $(grep -rlE "$VAULT_CALL" "$API" --include='*.go' 2>/dev/null | grep -v '_test\.go$'); do
  n=$(calls_of "$f" "$JWT_AS_VAULT_KEY")
  if [ "$n" -gt 0 ]; then
    JWT_KEYED=$((JWT_KEYED + n))
    bad "$(basename "$f") unlocks the vault with the JWT secret instead of the derived key"
  fi
done
if [ "$JWT_KEYED" -eq 0 ]; then
  ok "no vault read or write is keyed on the JWT secret"
fi

# The working sibling is the reason this is a correctness bug and not a design
# question: the manual Inject button runs the same query against the same rows
# and PUTs the same body to the same agent route. If it ever stops doing so, the
# arm above loses the reference implementation it is measured against.
SECRETS_RS=$API/rt_secrets.go
DEPLOY_RS=$API/rt_deploy.go
for f in "$SECRETS_RS" "$DEPLOY_RS"; do
  [ -f "$f" ] || { bad "missing file: $f"; continue; }
  assert_readable "$f" || continue
  if [ "$(countre "$f" 'auto_inject = TRUE')" -gt 0 ] && [ "$(countre "$f" '/nginx/env/')" -gt 0 ]; then
    ok "$(basename "$f") still selects the auto-inject rows and pushes them to the agent"
  else
    bad "$(basename "$f") no longer performs the auto-inject it is pinned against"
  fi
done

# A skipped secret must be sayable, and the arm has to be keyed on THIS path's
# own diagnostics: `rt_deploy.go` is a large file with warnings all over it, so an
# arm asking only whether the file can warn at all is green on the broken tree
# too — it would have passed for the whole time the feature was dead. The
# `Auto-inject:` prefix belongs to this block alone; the success line reads
# `Auto-injected`, so it cannot satisfy this on its own.
if [ "$(countf "$DEPLOY_RS" '"Auto-inject: ')" -gt 0 ]; then
  ok "rt_deploy.go reports the secrets it could not decrypt"
else
  bad "rt_deploy.go swallows decrypt failures again — an inert auto-inject looks exactly like an empty vault"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
