#!/usr/bin/env bash
# webhook-secrets-encryption-pin-e2e.sh — s431
#
# Regression pins for the 5 sibling plaintext webhook/verify secrets deferred
# from s430's notification-secrets rollout: `deploy_configs.webhook_secret`,
# `git_deploys.webhook_secret`, `extensions.webhook_secret`,
# `whmcs_config.webhook_secret`, `webhook_endpoints.verify_secret` were all
# plain columns, with zero `secrets_crypto` reference anywhere in the files
# that wrote or read them.
#
# ⚠ The s430 ledger's own design note characterized deploy_configs/git_deploys
# as "compare-only — should be HASHED, mirroring extensions.api_key_hash".
# That was wrong: Deploy.tsx and GitDeploys.tsx read `config.webhook_secret`
# from the GET/list response on EVERY page load to render the webhook URL to
# paste into the git host — not shown once at creation like an API key. A
# hash-only design would have silently broken that display on the very next
# page load after creation. All five subjects here are reversible-encrypt.
#
# ⚠ A second defect a naive port of the s430 pattern would have shipped: three
# of the five columns (deploy_configs.webhook_secret VARCHAR(64),
# git_deploys.webhook_secret VARCHAR(64), webhook_endpoints.verify_secret
# VARCHAR(200)) are sized for the PLAINTEXT. Base64(nonce+ciphertext+tag) is
# longer than the plaintext it wraps — encrypting in place without widening
# would overflow the column and fail every write. Migration
# 20260830010000_widen_webhook_secret_columns.sql widens all three to TEXT.
#
#   (Ported to Go: routes/x.rs → panel/go/internal/api/rt_x.go, services/x.rs →
#   svc_x.go; secrets_crypto::encrypt_credential → SecretsCryptoEncryptCredential,
#   decrypt_credential_or_legacy → SecretsCryptoDecryptCredentialOrLegacy,
#   decrypt_credential_from_env → SecretsCryptoDecryptCredentialFromEnv.)
#
#   §A  rt_webhook_gateway.go: create ENCRYPTS verify_secret before the
#       INSERT; the receiver DECRYPTS it before rtWebhookGatewayClassifySignature.
#       No update route exists for this field (endpoints are delete+recreate).
#   §B  rt_extensions.go create/rotate-secret ENCRYPT webhook_secret, returning
#       the plaintext in the one-time response; test-webhook DECRYPTS before
#       signing. svc_extensions.go's event emitter has no AppState (pool only),
#       so it decrypts via SecretsCryptoDecryptCredentialFromEnv, matching the
#       notifications/uptime s430 precedent.
#   §C  rt_whmcs.go update-config ENCRYPTS (decrypting the prior value first, so
#       the preserve-vs-mint comparison still runs on plaintext); get-config
#       and the inbound webhook receiver DECRYPT.
#   §D  rt_deploy.go set-config ENCRYPTS on write, then decrypts whatever
#       RETURNING * actually gives back (not the freshly-generated local) —
#       ON CONFLICT's DO UPDATE never touches this column, so an
#       update-existing call must show the ORIGINAL secret, not a new one
#       that was never stored. get-config and the webhook receiver DECRYPT.
#   §E  rt_git_deploys.go create ENCRYPTS; list/get/update DECRYPT through
#       rtGitDeploysRevealSecrets beside the github-token mask; the webhook
#       receiver DECRYPTS before the SHA256 hash-compare.
#   §F  svc_credential_reencrypt.go's self-enforcing registry carries all 5 new
#       subjects in credentialReencryptSimpleSubjects and pairs each writer
#       module in CredentialReencryptCoveredModules.
#   §G  the three too-narrow columns are widened to TEXT.
#
# Pure source analysis: no box, no network, no build.
set -uo pipefail
cd "$(dirname "$0")/.."

API=panel/go/internal/api
GATEWAY=$API/rt_webhook_gateway.go
EXTENSIONS=$API/rt_extensions.go
EXT_SVC=$API/svc_extensions.go
WHMCS=$API/rt_whmcs.go
DEPLOY=$API/rt_deploy.go
GITDEPLOYS=$API/rt_git_deploys.go
REENCRYPT=$API/svc_credential_reencrypt.go
MIGDIR=$API/migrations
MIGRATION=$MIGDIR/20260830010000_widen_webhook_secret_columns.sql

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
has()  { grep -qE -- "$2" "$1" 2>/dev/null && ok "$3" || bad "$3"; }
# Multi-line variant: several calls below are formatted with each argument on
# its own line, so the pattern must match ACROSS lines. -z null-separates
# input (the whole file becomes one "line"), -P gives Perl regex where \s
# already spans newlines.
hasml() { grep -qPzo -- "$2" "$1" 2>/dev/null && ok "$3" || bad "$3"; }
count() { grep -oE -- "$2" "$1" 2>/dev/null | wc -l | tr -d ' '; }

echo "== §A  rt_webhook_gateway.go: encrypt on create, decrypt on receive =="

has "$GATEWAY" 'enc, err := SecretsCryptoEncryptCredential\(\*verifySecret, st\.Config\.JWTSecret\)' \
  "A1 create encrypts verify_secret before binding"
has "$GATEWAY" 'token, verifyMode, encryptedVerifySecret, verifyHeader\)' \
  "A2 the INSERT binds the encrypted local, not the raw pointer"
if grep -qE 'token, verifyMode, verifySecret, verifyHeader' "$GATEWAY"; then
  bad "A3 CONTROL: raw verify_secret is no longer bound directly"
else
  ok "A3 CONTROL: raw verify_secret is no longer bound directly"
fi
has "$GATEWAY" 's := SecretsCryptoDecryptCredentialOrLegacy\(\*endpoint\.VerifySecret, st\.Config\.JWTSecret\)' \
  "A4 the receiver decrypts endpoint.VerifySecret"
has "$GATEWAY" 'rtWebhookGatewayClassifySignature\(endpoint\.VerifyMode, decryptedVerifySecret,' \
  "A5 the signature classifier is called with the DECRYPTED value, not the raw field"

echo
echo "== §B  rt_extensions.go + svc_extensions.go: encrypt on write, decrypt on send =="

has "$EXTENSIONS" 'encrypted, err := SecretsCryptoEncryptCredential\(webhookSecret, st\.Config\.JWTSecret\)' \
  "B1 create encrypts the freshly-minted webhook_secret"
has "$EXTENSIONS" 'strings\.TrimSpace\(body\.WebhookURL\), encrypted, apiKeyHash' \
  "B2 create's INSERT binds the encrypted local"
has "$EXTENSIONS" '"webhook_secret": webhookSecret,' \
  "B3 create's one-time response still returns the PLAINTEXT (not the ciphertext)"
has "$EXTENSIONS" 'encrypted, err := SecretsCryptoEncryptCredential\(newSecret, st\.Config\.JWTSecret\)' \
  "B4 rotate-secret encrypts the freshly-minted secret"
has "$EXTENSIONS" '"UPDATE extensions SET webhook_secret = \$1, updated_at = NOW\(\) WHERE id = \$2", encrypted, id' \
  "B5 rotate-secret's UPDATE binds the encrypted local"
has "$EXTENSIONS" 'secret := SecretsCryptoDecryptCredentialOrLegacy\(ext\.C, st\.Config\.JWTSecret\)' \
  "B6 test-webhook decrypts before computing the HMAC signature"
has "$EXT_SVC" 'SecretsCryptoDecryptCredentialFromEnv\(e\.C\)' \
  "B7 the event emitter decrypts via the AppState-free helper (no AppState in this fn)"

echo
echo "== §C  rt_whmcs.go: encrypt on save, decrypt on read + inbound verify =="

has "$WHMCS" 'webhookSecret = SecretsCryptoDecryptCredentialOrLegacy\(\*curSecret, st\.Config\.JWTSecret\)' \
  "C1 update-config decrypts the prior value before the preserve-vs-mint decision"
has "$WHMCS" 'encryptedWebhookSecret, err := SecretsCryptoEncryptCredential\(webhookSecret, st\.Config\.JWTSecret\)' \
  "C2 update-config encrypts before the INSERT/DO UPDATE"
has "$WHMCS" '^\s*encryptedWebhookSecret\); err != nil \{' \
  "C3 the SQL argument list uses the encrypted local"
has "$WHMCS" '"webhook_secret": webhookSecret\}' \
  "C4 the save response still returns PLAINTEXT"
has "$WHMCS" 's := SecretsCryptoDecryptCredentialOrLegacy\(\*cfg\.F, st\.Config\.JWTSecret\)' \
  "C5 get-config decrypts before serializing"
has "$WHMCS" 'expected := SecretsCryptoDecryptCredentialOrLegacy\(\*cfg\.A, st\.Config\.JWTSecret\)' \
  "C6 the inbound webhook receiver decrypts before the constant-time compare"
has "$WHMCS" 'subtle\.ConstantTimeCompare\(\[\]byte\(provided\), \[\]byte\(expected\)\)' \
  "C7 the constant-time compare uses the DECRYPTED local"

echo
echo "== §D  rt_deploy.go: encrypt on write, decrypt what RETURNING * actually holds =="

has "$DEPLOY" 'encryptedWebhookSecret, err := SecretsCryptoEncryptCredential\(webhookSecret, st\.Config\.JWTSecret\)' \
  "D1 set-config encrypts the freshly-minted secret"
has "$DEPLOY" 'autoDeploy, encryptedWebhookSecret, atomicDeploy, keepReleases\)' \
  "D2 the INSERT...ON CONFLICT binds the encrypted local"
SETCFG=$(awk '/^func rtDeploySetConfig\(/,/^}/' "$DEPLOY")
case "$SETCFG" in
  *'config.WebhookSecret = SecretsCryptoDecryptCredentialOrLegacy(config.WebhookSecret, st.Config.JWTSecret)'*)
    ok "D3 set-config decrypts the RETURNING-* value in place (not the pre-write local)" ;;
  *) bad "D3 set-config decrypts the RETURNING-* value in place (not the pre-write local)" ;;
esac
# Ordering/correctness control: ON CONFLICT's DO UPDATE never assigns
# webhook_secret, so an update-existing call must return the ORIGINAL stored
# secret, not the freshly-generated one that was silently discarded.
has "$DEPLOY" 'repo_url = \$2, branch = \$3, deploy_script = \$4, auto_deploy = \$5, atomic_deploy = \$7, keep_releases = \$8, updated_at = NOW\(\)' \
  "D4 CONTROL: DO UPDATE's SET list still omits webhook_secret (confirms decrypt-what-came-back is the correct fix, not a stale assumption)"
hasml "$DEPLOY" 'if config != nil \{\s*config\.WebhookSecret = SecretsCryptoDecryptCredentialOrLegacy\(config\.WebhookSecret' \
  "D5 get-config decrypts before returning"
has "$DEPLOY" 'storedSecret := SecretsCryptoDecryptCredentialOrLegacy\(config\.WebhookSecret, st\.Config\.JWTSecret\)' \
  "D6 the inbound webhook receiver decrypts before the constant-time compare"
has "$DEPLOY" 'subtle\.ConstantTimeCompare\(\[\]byte\(secret\), \[\]byte\(storedSecret\)\)' \
  "D7 the constant-time compare uses the DECRYPTED local, not config.WebhookSecret directly"

echo
echo "== §E  rt_git_deploys.go: encrypt on create, decrypt on every read + inbound verify =="

has "$GITDEPLOYS" 'encryptedWebhookSecret, err := SecretsCryptoEncryptCredential\(webhookSecret, st\.Config\.JWTSecret\)' \
  "E1 create encrypts the freshly-minted secret"
has "$GITDEPLOYS" 'autoDeploy, encryptedWebhookSecret, body\.MemoryMB' \
  "E2 the INSERT binds the encrypted local"
N=$(count "$GITDEPLOYS" 'rtGitDeploysRevealSecrets\(st, &?deploy\)')
if [ "$N" -ge 3 ]; then
  ok "E3 decrypted at create/get_one/update through rtGitDeploysRevealSecrets (>=3 call sites, found $N)"
else
  bad "E3 decrypted at create/get_one/update through rtGitDeploysRevealSecrets (found $N, want >=3)"
fi
hasml "$GITDEPLOYS" 'rtGitDeploysMaskGithubToken\(d\)\s*d\.WebhookSecret = SecretsCryptoDecryptCredentialOrLegacy\(d\.WebhookSecret' \
  "E4a the reveal helper decrypts in the same step that masks github_token"
has "$GITDEPLOYS" 'rtGitDeploysRevealSecrets\(st, &deploys\[i\]\)' \
  "E4 list decrypts each row through it"
has "$GITDEPLOYS" 'stored := SecretsCryptoDecryptCredentialOrLegacy\(config\.WebhookSecret, st\.Config\.JWTSecret\)' \
  "E5 the inbound webhook receiver decrypts before hashing"
has "$GITDEPLOYS" 'sha256\.Sum256\(\[\]byte\(stored\)\)' \
  "E6 the stored-side SHA256 hash is computed over the DECRYPTED value"

echo
echo "== §F  svc_credential_reencrypt.go's registry carries all 5 new subjects =="

for subj in \
  '"webhook_endpoints", "id", "verify_secret"' \
  '"extensions", "id", "webhook_secret"' \
  '"whmcs_config", "id", "webhook_secret"' \
  '"deploy_configs", "id", "webhook_secret"' \
  '"git_deploys", "id", "webhook_secret"'; do
  esc=$(printf '%s' "$subj" | sed 's/[.[\*^$()+?{|]/\\&/g')
  if grep -qE -- "\{$esc\}" "$REENCRYPT"; then
    ok "F1 credentialReencryptSimpleSubjects contains {$subj}"
  else
    bad "F1 credentialReencryptSimpleSubjects contains {$subj}"
  fi
done

for pair in \
  '"webhook_gateway", "webhook_endpoints.verify_secret"' \
  '"extensions", "extensions.webhook_secret"' \
  '"whmcs", "whmcs_config.webhook_secret"' \
  '"deploy", "deploy_configs.webhook_secret"' \
  '"git_deploys", "git_deploys.webhook_secret"'; do
  esc=$(printf '%s' "$pair" | sed 's/[.[\*^$()+?{|]/\\&/g')
  if grep -qE -- "\{$esc\}" "$REENCRYPT"; then
    ok "F2 CredentialReencryptCoveredModules pairs {$pair}"
  else
    bad "F2 CredentialReencryptCoveredModules pairs {$pair}"
  fi
done

echo
echo "== §G  the three plaintext-sized columns are widened to TEXT =="

has "$MIGRATION" 'ALTER TABLE deploy_configs ALTER COLUMN webhook_secret TYPE TEXT' \
  "G1 deploy_configs.webhook_secret widened to TEXT"
has "$MIGRATION" 'ALTER TABLE git_deploys ALTER COLUMN webhook_secret TYPE TEXT' \
  "G2 git_deploys.webhook_secret widened to TEXT"
has "$MIGRATION" 'ALTER TABLE webhook_endpoints ALTER COLUMN verify_secret TYPE TEXT' \
  "G3 webhook_endpoints.verify_secret widened to TEXT"
# Negative control: the original CREATE TABLE migrations must be untouched —
# this is a widen-forward, not an edit to a migration already shipped.
has "$MIGDIR/20260312400000_deploy_configs.sql" 'webhook_secret VARCHAR\(64\) NOT NULL' \
  "G4 CONTROL: the original deploy_configs migration is untouched (widen is a separate forward migration)"
has "$MIGDIR/20260318200000_git_deploys.sql" 'webhook_secret VARCHAR\(64\) NOT NULL' \
  "G5 CONTROL: the original git_deploys migration is untouched"

echo
printf 'webhook-secrets-encryption: \033[0;32m%d passed\033[0m, \033[0;31m%d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
