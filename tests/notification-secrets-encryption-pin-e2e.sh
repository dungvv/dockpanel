#!/usr/bin/env bash
# notification-secrets-encryption-pin-e2e.sh — s430
#
# Regression pins for closing the "cleartext credential hole" a s251-era audit
# flagged and nobody fixed for ~180 sessions: `alert_rules.notify_pagerduty_key`/
# `notify_webhook_url`/`notify_slack_url`/`notify_discord_url` and
# `monitors.alert_slack_url`/`alert_discord_url` were plain columns, with zero
# `secrets_crypto` reference anywhere in the files that wrote or read them.
#
#   §A  rt_alerts.go::rtAlertsUpsertRules ENCRYPTS all four notify_* fields
#       (via SecretsCryptoEncryptCredential, the credential-shaped derivation —
#       NOT the vault's encrypt/decrypt) before they ever reach SQL, on
#       plaintext already validated by the SSRF check above it.
#   §B  rt_alerts.go::rtAlertsGetRules DECRYPTS the same four fields (via
#       SecretsCryptoDecryptCredentialOrLegacy, the migration-safe fallback)
#       before serializing the response — the same-account caller reading their
#       own settings back is the expected case that function exists for.
#   §C  svc_notifications.go::NotificationsGetUserChannels and
#       svc_uptime.go::uptimeSendAlerts — both take only a pool (no
#       AppState/jwt_secret) — decrypt via SecretsCryptoDecryptCredentialFromEnv,
#       matching that function's own documented use case.
#   §D  rt_monitors.go's create/update ENCRYPT alert_slack_url/alert_discord_url;
#       list/create/update DECRYPT them back via the shared
#       rtMonitorsDecryptMonitorAlertURLs helper. create's "inherit from global
#       alert_rules" fallback decrypts BEFORE the SSRF check runs on it.
#   §E  svc_credential_reencrypt.go's self-enforcing registry carries all 6 new
#       subjects in its simple-subjects table and pairs each writer module in
#       its covered-modules table — TestEveryCredentialWriterIsCovered and
#       TestSubjectTokensMatchTheSweep (svc_credential_reencrypt_test.go)
#       assert this mechanically; §E here just pins the specific entries so a
#       regression names which one went missing, not just "a Go test failed".
#
# Pure source analysis: no box, no network, no build.
set -uo pipefail
cd "$(dirname "$0")/.."

API=panel/go/internal/api
ALERTS=$API/rt_alerts.go
MONITORS=$API/rt_monitors.go
NOTIFICATIONS=$API/svc_notifications.go
UPTIME=$API/svc_uptime.go
REENCRYPT=$API/svc_credential_reencrypt.go
for f in "$ALERTS" "$MONITORS" "$NOTIFICATIONS" "$UPTIME" "$REENCRYPT"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
has()  { grep -qE -- "$2" "$1" 2>/dev/null && ok "$3" || bad "$3"; }
count() { grep -oE -- "$2" "$1" 2>/dev/null | wc -l | tr -d ' '; }
# fnbody FILE FUNC — the body of a top-level Go func (or method) named FUNC,
# with // line comments stripped, so prose that names a call cannot satisfy it.
fnbody() {
  awk -v fn="$2" '
    !inside && (index($0, "func " fn "(") == 1 || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) { inside=1 }
    inside { sub(/\/\/.*/, ""); print; if ($0 ~ /^}/) exit }
  ' "$1"
}

echo "== §A  rt_alerts.go::rtAlertsUpsertRules encrypts all four notify_* fields =="

UPSERT=$(fnbody "$ALERTS" rtAlertsUpsertRules)
[ -n "$UPSERT" ] || bad "A0 rtAlertsUpsertRules not found in $ALERTS"
N=$(printf '%s\n' "$UPSERT" | grep -cE 'SecretsCryptoEncryptCredential\(\*v, st\.Config\.JWTSecret\)')
if [ "$N" -ge 1 ]; then
  ok "A1 rtAlertsUpsertRules calls SecretsCryptoEncryptCredential (shared closure, $N call site)"
else
  bad "A1 rtAlertsUpsertRules calls SecretsCryptoEncryptCredential"
fi
uhas() { printf '%s\n' "$UPSERT" | grep >/dev/null -cE -- "$1" && ok "$2" || bad "$2"; }
uhas 'encSlackURL := encryptOpt\(body\.NotifySlackURL\)' \
  "A2 notify_slack_url is routed through the encrypting closure"
uhas 'encDiscordURL := encryptOpt\(body\.NotifyDiscordURL\)' \
  "A3 notify_discord_url is routed through the encrypting closure"
uhas 'encPagerdutyKey := encryptOpt\(body\.NotifyPagerdutyKey\)' \
  "A4 notify_pagerduty_key is routed through the encrypting closure"
uhas 'encWebhookURL := encryptOpt\(body\.NotifyWebhookURL\)' \
  "A5 notify_webhook_url is routed through the encrypting closure"
# The execSQL argument list ($1..$27), from `execSQL(ctx, st.DB, query,` to
# the `); err != nil` that closes it.
ARGS=$(printf '%s\n' "$UPSERT" | awk '/execSQL\(ctx, st\.DB, query,/{on=1} on{print} on && /\); err != nil/{exit}')
if printf '%s\n' "$ARGS" | grep >/dev/null -cE 'encSlackURL, encDiscordURL, body\.CooldownMinutes, encPagerdutyKey, encWebhookURL'; then
  ok "A6 the SQL argument list uses the ENCRYPTED locals, not the raw body fields"
else
  bad "A6 the SQL argument list uses the ENCRYPTED locals, not the raw body fields"
fi
# Negative control: the raw plaintext must not still be what gets bound.
# Positive anchor: the argument block was found (it carries body.CPUThreshold).
if ! printf '%s\n' "$ARGS" | grep >/dev/null -c 'body\.CPUThreshold'; then
  bad "A7 CONTROL: could not locate the execSQL argument list — the pattern is wrong, not the code"
elif printf '%s\n' "$ARGS" | grep >/dev/null -cE 'body\.Notify(Slack|Discord|Webhook)URL|body\.NotifyPagerdutyKey'; then
  bad "A7 CONTROL: a raw body.Notify* field is bound directly again (plaintext bind)"
else
  ok "A7 CONTROL: no raw body.Notify* field is bound directly"
fi

echo
echo "== §B  rt_alerts.go::rtAlertsGetRules decrypts all four before serializing =="

GETR=$(fnbody "$ALERTS" rtAlertsGetRules)
N=$(printf '%s\n' "$GETR" | grep -cE 'rules\[i\]\.Notify(SlackURL|DiscordURL|PagerdutyKey|WebhookURL) = dec\(rules\[i\]\.Notify')
if [ "$N" -ge 4 ] && printf '%s\n' "$GETR" | grep >/dev/null -cE 'SecretsCryptoDecryptCredentialOrLegacy\(\*p, st\.Config\.JWTSecret\)'; then
  ok "B1 rtAlertsGetRules decrypts all 4 fields via SecretsCryptoDecryptCredentialOrLegacy ($N in-place decrypts)"
else
  bad "B1 rtAlertsGetRules decrypts all 4 fields via SecretsCryptoDecryptCredentialOrLegacy (found $N in-place decrypts)"
fi
printf '%s\n' "$GETR" | grep >/dev/null -cE 'rules\[i\]\.NotifySlackURL = dec\(rules\[i\]\.NotifySlackURL\)' \
  && ok "B2 notify_slack_url is decrypted in place" || bad "B2 notify_slack_url is decrypted in place"
printf '%s\n' "$GETR" | grep >/dev/null -cE 'rules\[i\]\.NotifyPagerdutyKey = dec\(rules\[i\]\.NotifyPagerdutyKey\)' \
  && ok "B3 notify_pagerduty_key is decrypted in place" || bad "B3 notify_pagerduty_key is decrypted in place"

echo
echo "== §C  contexts with only a pool decrypt via SecretsCryptoDecryptCredentialFromEnv =="

CHAN=$(fnbody "$NOTIFICATIONS" NotificationsGetUserChannels)
printf '%s\n' "$CHAN" | grep >/dev/null -cE 'SecretsCryptoDecryptCredentialFromEnv\(\*p\)' \
  && ok "C1 NotificationsGetUserChannels decrypts via the AppState-free helper" \
  || bad "C1 NotificationsGetUserChannels decrypts via the AppState-free helper"
# notificationsRuleCols selects notify_email, slack, discord, pagerduty, webhook,
# muted_types — so B..E are the four credential columns.
N=$(printf '%s\n' "$CHAN" | grep -oE 'dec\(rule\.[BCDE]\)' | sort -u | wc -l | tr -d ' ')
if [ "$N" -ge 4 ] && grep -qE 'notificationsRuleCols = "SELECT notify_email, notify_slack_url, notify_discord_url, notify_pagerduty_key, notify_webhook_url' "$NOTIFICATIONS"; then
  ok "C2 NotificationsGetUserChannels decrypts all 4 fields ($N decrypted columns)"
else
  bad "C2 NotificationsGetUserChannels decrypts all 4 fields (found $N, want >=4, or the column order moved)"
fi
SEND=$(fnbody "$UPTIME" uptimeSendAlerts)
printf '%s\n' "$SEND" | grep >/dev/null -cE 'SecretsCryptoDecryptCredentialFromEnv\(\*p\)' \
  && ok "C3 uptimeSendAlerts uses the same AppState-free helper" \
  || bad "C3 uptimeSendAlerts uses the same AppState-free helper"
N=0
for f in 'SlackURL: dec\(m\.AlertSlackURL\)' 'DiscordURL: dec\(m\.AlertDiscordURL\)' 'PagerdutyKey: dec\(pdKey\)' 'WebhookURL: dec\(webhook\)'; do
  printf '%s\n' "$SEND" | grep >/dev/null -cE "$f" && N=$((N+1))
done
if [ "$N" -ge 4 ]; then
  ok "C4 uptimeSendAlerts decrypts pagerduty/webhook/slack/discord ($N uses)"
else
  bad "C4 uptimeSendAlerts decrypts pagerduty/webhook/slack/discord (found $N, want >=4)"
fi

echo
echo "== §D  rt_monitors.go: encrypt on write, decrypt on every read =="

has "$MONITORS" '^func rtMonitorsDecryptMonitorAlertURLs\(' \
  "D1 a shared decrypt helper exists for Monitor's two alert-url fields"
N=$(count "$MONITORS" 'rtMonitorsDecryptMonitorAlertURLs\(')
if [ "$N" -ge 4 ]; then
  ok "D2 the helper is called from list/create/update (>=1 call each, $N total call sites incl. its own definition)"
else
  bad "D2 the helper is called enough times (found $N call sites incl. definition, want >=4)"
fi
CREATE=$(fnbody "$MONITORS" rtMonitorsCreate)
UPDATE=$(fnbody "$MONITORS" rtMonitorsUpdate)
printf '%s\n' "$CREATE" | grep >/dev/null -cE 'encSlack, err := encryptOpt\(slackURL\)' \
  && ok "D3 create() encrypts before the INSERT" || bad "D3 create() encrypts before the INSERT"
printf '%s\n' "$UPDATE" | grep >/dev/null -cE 'encSlack, err := encryptOpt\(body\.AlertSlackURL\)' \
  && ok "D4 update() encrypts before the UPDATE" || bad "D4 update() encrypts before the UPDATE"
printf '%s\n' "$CREATE" | grep >/dev/null -cE 'slackURL = dec\(global\.A\)' \
  && ok "D5 create()'s inherit-from-global fallback decrypts BEFORE the SSRF check runs on it" \
  || bad "D5 create()'s inherit-from-global fallback decrypts BEFORE the SSRF check runs on it"
# Ordering control: the decrypt of the inherited global value must appear
# BEFORE the SSRF validateURLNotInternal call that consumes slackURL.
DECRYPT_LINE=$(printf '%s\n' "$CREATE" | grep -n 'slackURL = dec(global\.A)' | head -1 | cut -d: -f1)
SSRF_LINE=$(printf '%s\n' "$CREATE" | grep -n 'Invalid Slack alert URL' | head -1 | cut -d: -f1)
if [ -n "$DECRYPT_LINE" ] && [ -n "$SSRF_LINE" ] && [ "$DECRYPT_LINE" -lt "$SSRF_LINE" ]; then
  ok "D6 the decrypt (body line $DECRYPT_LINE) runs BEFORE the SSRF check (body line $SSRF_LINE), not after"
else
  bad "D6 decrypt-before-SSRF-check ordering (decrypt=$DECRYPT_LINE ssrf=$SSRF_LINE)"
fi

echo
echo "== §E  svc_credential_reencrypt.go's registry carries all 6 new subjects =="

for subj in \
  '"alert_rules", "id", "notify_pagerduty_key"' \
  '"alert_rules", "id", "notify_webhook_url"' \
  '"alert_rules", "id", "notify_slack_url"' \
  '"alert_rules", "id", "notify_discord_url"' \
  '"monitors", "id", "alert_slack_url"' \
  '"monitors", "id", "alert_discord_url"'; do
  esc=$(printf '%s' "$subj" | sed 's/[.[\*^$()+?{|]/\\&/g')
  if grep -qE -- "\{$esc\}" "$REENCRYPT"; then
    ok "E1 simple subjects contain {$subj}"
  else
    bad "E1 simple subjects contain {$subj}"
  fi
done

for pair in \
  '"alerts", "alert_rules.notify_pagerduty_key"' \
  '"alerts", "alert_rules.notify_webhook_url"' \
  '"alerts", "alert_rules.notify_slack_url"' \
  '"alerts", "alert_rules.notify_discord_url"' \
  '"monitors", "monitors.alert_slack_url"' \
  '"monitors", "monitors.alert_discord_url"'; do
  esc=$(printf '%s' "$pair" | sed 's/[.[\*^$()+?{|]/\\&/g')
  if grep -qE -- "\{$esc\}" "$REENCRYPT"; then
    ok "E2 covered modules pair {$pair}"
  else
    bad "E2 covered modules pair {$pair}"
  fi
done

echo
printf 'notification-secrets-encryption: \033[0;32m%d passed\033[0m, \033[0;31m%d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
