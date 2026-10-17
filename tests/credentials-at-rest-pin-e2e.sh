#!/usr/bin/env bash
# Regression pins for the s377 ship — the credential promise the project publishes.
#
# `SECURITY.md` and `README.md` both state, without qualification, that every
# stored credential is encrypted at rest with AES-256-GCM. Three columns were
# not: `cdn_zones.api_key`, `git_deploys.github_token` and `servers.agent_token`
# — the last one named in cleartext by `auto_healer`'s own comment about what a
# panel database dump carries. The claim was false on the project's front page,
# and no test could see it, because nothing compared the published sentence with
# the columns.
#
# So this suite pins BOTH ENDS. §A–§C pin each column's writer and its single
# decrypting read site; §D pins the masks on the wire; §E pins the sentence
# against the code, so the promise cannot come back without the columns, and the
# columns cannot regress without the promise going red.
#
# The choke-point shape is the load-bearing one and it is deliberate: every read
# of these three credentials funnels through exactly one function (Go names:
# `cfHeaders`, `rtCdnBunnyHeaders`, the git_deploys commit-status sink,
# `AgentRegistry.ForServer`), so no read site can forget to decrypt. Arms that
# count CALL sites rather than the helper's own name are used throughout —
# a name search is satisfied by the declaration itself, which is how a severed
# filter came back green at s376 (#592).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
ok()  { printf '\033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '\033[31m✗\033[0m %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3', got '$2'"; }

# ugrep's --ignore-files shim honours .gitignore, so every count below uses the
# real binary explicitly (dockpanel-ops-p2, s357).
G=/usr/bin/grep

# The Go port (panel/go/internal/api, one flat package) is what ships.
API=panel/go/internal/api
CDN=$API/rt_cdn.go
GITD=$API/rt_git_deploys.go
SERVERS=$API/rt_servers.go
AGENT=$API/svc_agent.go
HELPERS=$API/core_helpers.go
REENC=$API/svc_credential_reencrypt.go
SETTINGS=$API/rt_settings.go
BACKUP_DEST=$API/rt_backup_destinations.go
AGENT_TREE=panel/go/internal/agent
# Count matching CODE lines: whole-line `//` comments are dropped first, since
# several of these files name the very identifiers under count in their prose.
gc() { $G -v '^[[:space:]]*//' "$2" | $G -c "${@:3}" -- "$1" || true; }

for f in "$CDN" "$GITD" "$SERVERS" "$AGENT" "$HELPERS" "$REENC" "$SETTINGS" "$BACKUP_DEST" README.md SECURITY.md; do
  [ -f "$f" ] || { bad "SETUP" "$f missing"; exit 1; }
done

# An arm that measures an empty subject prints green for every absence below, so
# each subject is asserted before it is measured (lesson #143).
for pair in "$CDN:400" "$GITD:3000" "$SERVERS:400" "$AGENT:800"; do
  f=${pair%:*}; floor=${pair##*:}
  n=$($G -c '' "$f")
  [ "$n" -gt "$floor" ] && ok "S0 subject extracted — $f is $n lines" \
    || bad "S0 subject extracted" "$f is only $n lines (floor $floor) — arms over it examine nothing"
done

echo "── A. cdn_zones.api_key ────────────────────────────────────────────────"

# A1: the WRITER binds the ciphertext variable, not the request field. Keyed on
# the INSERT's argument list, not on the presence of the encrypt call anywhere
# in the file — the call could exist and the argument still carry body.APIKey.
CDN_INS=$(awk '/INSERT INTO cdn_zones/{f=1} f{print} f&&/\)$/{exit}' "$CDN")
eq "A1 the create writer binds the encrypted value" \
   "$($G -c ', apiKeyEnc, ' <<< "$CDN_INS")" "1"
API_KEY_PLAIN=$($G -c 'body\.APIKey' <<< "$CDN_INS")
if [ "$API_KEY_PLAIN" = "0" ]; then
  ok "A1b no writer binds the plaintext api_key"
else
  bad "A1b no writer binds the plaintext api_key" "found $API_KEY_PLAIN — the column would hold cleartext"
fi
eq "A1-control the same bind shape DOES match another column in this file" \
   "$([ "$($G -c 'strings\.TrimSpace(body\.Domain)' <<< "$CDN_INS")" -ge 1 ] && echo yes || echo no)" "yes"

# A2: the single decrypting choke point. Every Bunny caller funnels through
# `rtCdnBunnyHeaders`, so the decrypt lives there rather than at each read site.
eq "A2 rtCdnBunnyHeaders decrypts" \
   "$(awk '/^func rtCdnBunnyHeaders\(/,/^}/' "$CDN" | $G -c 'apiKey = SecretsCryptoDecryptCredentialFromEnv(apiKey)')" "1"
eq "A2b every stored-key Bunny read site goes through the choke point" \
   "$(gc 'rtCdnBunnyHeaders(zone\.APIKey)' "$CDN")" "4"
eq "A2c the Cloudflare half already had its own choke point" \
   "$(gc 'SecretsCryptoDecryptCredentialFromEnv(token)' "$HELPERS")" "1"

echo "── B. git_deploys.github_token ─────────────────────────────────────────"

eq "B1 both writers bind through the shared encrypting helper" \
   "$(gc 'githubTokenEnc, err := rtGitDeploysEncryptStoredToken(body\.GithubToken, ' "$GITD")" "2"
eq "B1-control both writers pass the helper's result to their statement" \
   "$(gc ', githubTokenEnc, ' "$GITD")" "2"
# Every mention of the request field must be the helper call itself.
GH_PLAIN=$($G -v '^[[:space:]]*//' "$GITD" | $G 'body\.GithubToken' | $G -vc 'rtGitDeploysEncryptStoredToken(body\.GithubToken' || true)
if [ "$GH_PLAIN" = "0" ]; then
  ok "B1b no writer binds the plaintext github_token"
else
  bad "B1b no writer binds the plaintext github_token" "found $GH_PLAIN — the column would hold cleartext"
fi

# B2: the sentinel guard. Every handler now returns the masked row, so a client
# that submits the form it was served sends ●●●●●●●● back. Storing that would
# replace a working token with eight circles; encrypting it would be worse, since
# the result looks like a legitimate credential to every later read. v2.48.3
# shipped this class of bug once already.
eq "B2 the mask sentinel is refused by the writer-side helper" \
   "$(gc '\*submitted == rtGitDeploysGithubTokenMask' "$GITD")" "1"
eq "B2b the mask and the guard read the same constant" \
   "$(gc 'rtGitDeploysGithubTokenMask' "$GITD")" "3"

# B3: the single sink. All seven read sites reach the commit-status sink,
# directly or through a spawned task, and the token never leaves the backend.
eq "B3 the sink decrypts" \
   "$(gc 'SecretsCryptoDecryptCredentialFromEnv(token)' "$GITD")" "1"
AGENT_SEES_TOKEN=$($G -rc 'github_token' "$AGENT_TREE" 2>/dev/null | $G -cv ':0$')
if [ "${AGENT_SEES_TOKEN:-0}" = "0" ]; then
  ok "B3b the github token never leaves the backend"
else
  bad "B3b the github token never leaves the backend" "the agent tree references it — the sink is not the only reader"
fi
eq "B3-control the agent tree IS being read (a token name that does appear there)" \
   "$([ "$($G -rc 'agent.token' "$AGENT_TREE" 2>/dev/null | $G -cv ':0$')" -ge 1 ] && echo yes || echo no)" "yes"

echo "── C. servers.agent_token ──────────────────────────────────────────────"

eq "C1 the create writer binds the encrypted value" \
   "$(gc ', agentTokenEnc, agentTokenHash, ' "$SERVERS")" "1"
eq "C1b the rotation writer binds the encrypted value" \
   "$(gc '", newTokenEnc, newHash, id)' "$SERVERS")" "1"
ELS=$(awk '/^func AgentEnsureLocalServer\(/,/^}/' "$AGENT")
eq "C1c both AgentEnsureLocalServer writers bind the encrypted value" \
   "$($G -cE '(enc, hash, \*id\)|\*admin, enc, hash\))' <<< "$ELS")" "2"
eq "C1c-control that enc IS the encrypt call's result" \
   "$($G -c 'enc, err := SecretsCryptoEncryptCredential(agentToken, jwtSecret)' <<< "$ELS")" "1"

# C2: the ONLY consumer of the stored dial-out token. The inbound direction is
# authenticated by `agent_token_hash` and is untouched by this ship — asserted
# here so a future reader does not "helpfully" encrypt the hash too.
eq "C2 ForServer decrypts before dialling" \
   "$(gc 'SecretsCryptoDecryptCredentialOrLegacy(' "$AGENT")" "1"
# TWO reads of the field since v2.145.0 — `ForServer` opens a stored dial-out
# token, and the accessor hands the same key to the UNATTENDED renewal loops so
# they can open the Cloudflare token that issued a DNS-01 certificate. Both are
# struct-field reads, which is what this arm is about; an `std::env::var` here
# would be the second source of truth the field comment forbids.
eq "C2b the key is a struct field, not an environment read" \
   "$(gc 'r\.jwtSecret' "$AGENT")" "2"
eq "C2b-env the key is never re-read from the environment in the agent registry" \
   "$(gc '\(Getenv\|LookupEnv\)("JWT_SECRET")' "$AGENT")" "0"
eq "C2c the inbound path still authenticates on the HASH" \
   "$(gc 'hashAgentToken(' $API/rt_agent_checkin.go)" "1"

# C3: legacy tolerance is what makes this migration-free. `_or_legacy` returns a
# pre-encryption plaintext token unchanged, so an existing fleet keeps dialling.
# If this ever became the strict SecretsCryptoDecryptCredential, every fleet
# member enrolled before this release would stop being reachable.
eq "C3 the dial-out decrypt is the legacy-tolerant variant" \
   "$(gc 'token := SecretsCryptoDecryptCredentialOrLegacy(rw\.AgentToken, r\.jwtSecret)' "$AGENT")" "1"
eq "C3b and the strict variant is not used there" \
   "$(gc 'SecretsCryptoDecryptCredential(' "$AGENT")" "0"

# C4 / the shared premise. Two of the three choke points decrypt with
# `SecretsCryptoDecryptCredentialFromEnv`, which reads JWT_SECRET from the
# process environment, while every WRITER encrypts with `st.Config.JWTSecret`. Those
# must be the same value or every read returns ciphertext where a credential
# belongs — silently, since the legacy fallback returns the input verbatim. They
# are the same by construction, and this arm is what keeps them so: `Config`
# takes the field straight from the variable and the process refuses to start
# without it. `cfHeaders` has depended on this since before the ship; two more
# credentials depend on it now.
eq "C4 Config.JWTSecret IS the JWT_SECRET environment variable" \
   "$(gc 'jwt, ok := os.LookupEnv("JWT_SECRET")' $API/core_config.go)" "1"
eq "C4b and Config is built from exactly that value" \
   "$(gc '^[[:space:]]*JWTSecret:[[:space:]]*jwt,$' $API/core_config.go)" "1"
eq "C4c and the env-reading decrypt reads the same variable" \
   "$(awk '/^func SecretsCryptoDecryptCredentialFromEnv\(/,/^}/' $API/svc_secrets_crypto.go | $G -c 'os.LookupEnv("JWT_SECRET")')" "1"

echo "── D. The wire: every row-returning handler masks ──────────────────────"

# D1: DERIVED, not listed. The population is every handler that returns a
# GitDeploy row; each must mask before it answers. A hand list of handler names
# is the defect this ship is about, one level up.
# Go: a handler returns a GitDeploy row by writeJSON-ing `deploy`/`deploys`;
# each such handler must pass it through rtGitDeploysRevealSecrets, which is
# where the mask lives.
HANDLERS=$(awk '/^func /{name=$2; w=0; m=0}
  /writeJSON\(w, http\.Status[A-Za-z]+, deploys?\)/{w=1}
  /rtGitDeploysRevealSecrets\(st, /{m=1}
  /^}/{ if (w) print (m ? "ok" : "bad"), name; w=0; m=0 }' "$GITD")
RETURNS=$($G -c . <<< "$HANDLERS" || true)
MASKS=$($G -c '^ok ' <<< "$HANDLERS" || true)
eq "D1 every GitDeploy-returning handler masks" "$MASKS" "$RETURNS"
eq "D1b the reveal helper is the thing that masks" \
   "$(awk '/^func rtGitDeploysRevealSecrets\(/,/^}/' "$GITD" | $G -c 'rtGitDeploysMaskGithubToken(d)')" "1"
[ "$RETURNS" -ge 4 ] && ok "D1-control the handler population is $RETURNS, not empty" \
  || bad "D1-control the handler population" "found $RETURNS — the signature grep matched nothing"

echo "── E. The published sentence and the columns are one edit ──────────────"

# E1: the claim. This is the arm that would have caught the original defect: the
# promise is unqualified on two surfaces, so every credential column must be in
# the sweep. It is pinned as a PRESENCE test on the sentence plus a membership
# test on the registry, because the two halves drifted apart silently for months.
eq "E1 README still publishes the at-rest claim" \
   "$($G -c 'Credentials are encrypted at rest with AES-256-GCM' README.md)" "1"
eq "E1b SECURITY.md still publishes it unqualified" \
   "$($G -c 'All stored credentials encrypted with AES-256-GCM' SECURITY.md)" "1"

# E2 (each of the three columns is a swept subject) and E2b (each writing module
# is paired with it in CredentialReencryptCoveredModules) retired: covered by
# TestSubjectTokensMatchTheSweep and TestEveryCredentialWriterIsCovered
# (panel/go/internal/api/svc_credential_reencrypt_test.go) — removing either half
# of a pair fails one of them.
# E3 (the writer census walks the package, not a typed list) retired: covered by
# TestEveryCredentialWriterIsCovered, which globs every non-test .go file with a
# 90-file floor.
# E3b retired (obsolete in Go): "it descends" — the API package is flat, there is
# no subdirectory to descend into.

echo "── F. The re-encryption sweep does not lose a race, or its own history ──"
#
# s428's first-ever audit of this sweep found a real lost-update race: every
# UPDATE below was keyed on id alone, no transaction/lock/CAS, so a normal
# write (a password reset, a token rotation, a settings save) landing between
# the sweep's SELECT and its UPDATE got silently reverted to the STALE value
# the sweep read — worst on `databases` (the panel's stored password stops
# matching the live DB) and `servers` (the panel loses its own dial-out token).
# It also found the vault arm bumping `secrets.version` on EVERY successful
# re-key with no paired `secret_versions` row — not race-dependent, deterministic
# on every non-racing run — desyncing the two the same way `routes::secrets`'
# real edit path never does.

eq "F1 credentialReencryptColumn's UPDATE is CAS-guarded on the value it read" \
   "$(gc 'WHERE %s::text = \$2 AND %s = \$3' "$REENC")" "1"
eq "F2 credentialReencryptSettings's UPDATE is CAS-guarded" \
   "$(gc 'WHERE key = \$2 AND value = \$3' "$REENC")" "1"
eq "F3 credentialReencryptDestinations's UPDATE is CAS-guarded" \
   "$(gc 'WHERE id::text = \$2 AND config = \$3' "$REENC")" "1"
eq "F4 credentialReencryptVaultSecrets's UPDATE is CAS-guarded" \
   "$(gc 'WHERE id::text = \$2 AND encrypted_value = \$3' "$REENC")" "1"

# F5/F6: the guard is CHECKED, not merely present — a CAS clause nobody reads
# the result of protects nothing. Rust had four copies of the check; Go has one
# helper, credentialReencryptRewrite, which all four sweep functions must call.
REWRITE=$(awk '/^func credentialReencryptRewrite\(/,/^}/' "$REENC")
eq "F5 the shared rewrite checks rows affected before counting a rewrite" \
   "$($G -cE 'case n > 0:' <<< "$REWRITE")" "1"
eq "F6 and counts a raced row instead of silently dropping it" \
   "$($G -cF 'report.Raced++' <<< "$REWRITE")" "1"
eq "F5b all four sweep functions write through it" \
   "$(gc 'credentialReencryptRewrite(ctx, db, report, ' "$REENC")" "4"
eq "F5c and none writes around it" \
   "$(gc 'execSQL(' "$REENC")" "1"

VERSION_BUMP=$($G -cF 'version = version + 1' "$REENC")
if [ "$VERSION_BUMP" = "0" ]; then
  ok "F7 reencrypt_vault_secrets no longer bumps secrets.version on every re-key"
else
  bad "F7 reencrypt_vault_secrets no longer bumps secrets.version on every re-key" \
      "found $VERSION_BUMP occurrence(s) — re-keying desyncs version from secret_versions again"
fi

echo "── G. The two duplicated, unenforced secret-key lists ───────────────────"
#
# Both currently matched their source of truth, but neither had a test tying
# them together — the exact severed-pair shape this file's own header says the
# module-level COVERED_MODULES registry already got burned by once, unfixed
# one layer down. The destination keys are read straight from
# rtBackupDestinationsConfigSensitiveKeys (single source of truth, nothing left
# to drift); the settings SQL literal stays hand-copied (it's SQL text) but is
# pinned by a test.

eq "G1 the destination sweep ranges over rtBackupDestinationsConfigSensitiveKeys directly" \
   "$(gc 'for _, key := range rtBackupDestinationsConfigSensitiveKeys {' "$REENC")" "1"
DUP=$(gc '^\(var\|const\) [A-Za-z]*SecretKeys\b\|SensitiveKeys = \[\]string' "$REENC")
if [ "$DUP" = "0" ]; then
  ok "G1b no hand-duplicated destination secret-key list remains in svc_credential_reencrypt.go"
else
  bad "G1b no hand-duplicated destination secret-key list remains" \
      "found $DUP — the two lists can drift again"
fi
eq "G1b-control the source list is declared exactly once" \
   "$(gc '^var rtBackupDestinationsConfigSensitiveKeys = ' "$BACKUP_DEST")" "1"
# G1c retired (obsolete in Go): pub(crate) visibility — the API is one flat
# package, so the sweep sees the list without any visibility change.

eq "G2 rtSettingsSensitiveKeys is declared exactly once, at package level" \
   "$(gc '^var rtSettingsSensitiveKeys = ' "$SETTINGS")" "1"
# G2b retired (obsolete in Go): pub(crate) — same flat package.
# G3 retired: covered by TestSensitiveSettingsSQLCoversSettingsSensitiveKeys (panel/go/internal/api/svc_credential_reencrypt_test.go)

echo
echo "PASS $PASS · FAIL $FAIL"
[ "$FAIL" -eq 0 ]
