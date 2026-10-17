#!/usr/bin/env bash
# mail-sender-identity-pin-e2e.sh — s352
#
# Pins the binding between a SASL login and the envelope senders it may use.
#
# WHY THIS SUITE EXISTS. Until v2.106.0 nothing tied the authenticated login to
# MAIL FROM, so any mailbox on the box could send as any address on any other
# tenant's hosted domain — and because OpenDKIM's signing table is keyed on the
# sender domain alone (`*@<domain>`), the forgery left the box carrying a VALID
# DKIM signature for the victim's domain, so DMARC passed on both legs. The
# co-tenant population that exploits this is self-service since v2.102.0, when
# nine mail handlers changed from the administrator extractor to the
# authenticated-user one.
#
#   §0  the suite's own subjects exist and its stripper did not eat them.
#   §A  the MAP — built, not borrowed. Reusing either existing Postfix map would
#       manufacture the defect, so the arms here refuse both re-pointings.
#   §B  the WILDCARD row — the load-bearing one. Without a per-domain row the
#       control only covers addresses that are already mailboxes, which is the
#       smaller half of the surface and none of the DKIM-signed part.
#   §C  the ORDER — map, then hash, then the key that names it. Getting this
#       backwards takes smtpd off the air on 25 and 587, so the arms pin the
#       checked postmap and the early return, not merely the calls.
#   §D  the RESTRICTION FORM — authenticated-only, and mynetworks first.
#   §E  the CARRIERS — both paths that reach a box, including the one that
#       reaches a box already running mail.
#   §F  the UNIT TESTS exist and name the property, so deleting the map builder
#       cannot quietly take its coverage with it.
#
# Subjects (Go): panel/go/internal/agent/routes/mail.go (agent) and
# panel/go/internal/api/rt_mail.go (§G, the panel API). Pure source analysis,
# plus `go test -run` for the map builder's unit tests (§F).

set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

AGENT="$REPO/panel/go/internal/agent/routes/mail.go"
AGENT_TEST_FILE="$REPO/panel/go/internal/agent/routes/mail_test.go"

[ -f "$AGENT" ] || { echo "FATAL: missing subject $AGENT"; exit 1; }

# Strip comments before measuring. A pin greps RAW SOURCE, so without this every
# arm below would match the sentence that DESCRIBES the check rather than the
# check itself — and this subject is heavily commented precisely because the
# ordering reasoning is the load-bearing part. The block-comment rule only
# recognises one opening at line start and closing at line end: a `/*` inside a
# string literal once opened a comment that ran for hundreds of lines and made
# every absence arm pass on code the stripper had removed. A `//` comment
# starts at line start or after whitespace, so `http://` in a string survives.
code() {
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{(^|[ \t])//[^\n]*}{$1}gm;
  ' "$1"
}

has()         { grep -qF -- "$2" <<< "$1"; }
hasre()       { grep -qE -- "$2" <<< "$1"; }
occurrences() { grep -oF -- "$2" <<< "$1" | wc -l; }

# Extract a function body by scanning to the next TOP-LEVEL item — NOT to the
# next `}` in column 0.
#
# This subject embeds whole config files as raw string literals, and the Dovecot
# one contains a bare `}` in column 0 (the closing brace of its `passdb {`
# block). A non-greedy `.*?\n\}` stops THERE and hands every later arm a
# truncated function. That is not hypothetical: the first draft of §E reported
# "mail_install does not arm enforcement" about code that arms it on the very
# next line after the truncation point. Same family as a comment stripper that
# opens a block comment on a `/*` inside a string literal — the instrument
# reads the embedded document as if it were code.
# The name is passed through the ENVIRONMENT, not through perl's `-s` switch
# parsing: `-s` without `-n` gives no implicit read loop, so `$_` stays empty and
# the extractor returns nothing for every input. That is a silent empty, and an
# arm fed an empty body reports the absence of whatever it looks for — which is
# why the §0 arms below assert a token from each function's TAIL rather than
# merely that something came back.
fn_body() {
  FN_NAME="$2" perl -0777 -ne '
    my $n = $ENV{FN_NAME};
    if (/(\nfunc \Q$n\E\(.*?)(?=\n(?:func |const |var |type |\z))/s) {
      print $1;
    }
  ' <<< "$1"
}

AGENT_RAW=$(cat "$AGENT")
AGENT_PROD=$(code "$AGENT")

echo "── mail-sender-identity-pin-e2e ─────────────────────────────────────"

# ── §0 the suite measures what it thinks it measures ────────────────────
echo "§0 the instrument"

# An absence arm over a truncated subject passes for the wrong reason, and it
# fails in the reassuring direction. Prove the stripper left the file usable.
raw_lines=$(wc -l <<< "$AGENT_RAW")
code_lines=$(grep -c '[^[:space:]]' <<< "$AGENT_PROD")
if [ "$code_lines" -gt $((raw_lines / 2)) ]; then
  ok "the comment stripper kept over half the file ($code_lines non-blank of $raw_lines lines)"
else
  bad "the comment stripper ate the subject ($code_lines of $raw_lines lines) — every absence arm below is void"
fi
# cfg(test)-split arm retired (obsolete in Go): Go tests live in mail_test.go, never in the production file.
# Positive control: a token that certainly exists must be found by the same
# machinery the absence arms use. Without this an arm can report a clean absence
# because the haystack is empty.
if has "$AGENT_PROD" 'mailEnsureSenderLoginEnforcement'; then
  ok "positive control: the enforcement helper is visible to these arms"
else
  bad "positive control FAILED — the arms below are reading nothing"
fi
# Negative control: a token that certainly does NOT exist must not be found.
if has "$AGENT_PROD" 'zzz_not_a_real_token_zzz'; then
  bad "negative control FAILED — the matcher reports hits that are not there"
else
  ok "negative control: an absent token is reported absent"
fi

# The function extractor must reach the END of a function, not stop at the first
# `}` it meets inside an embedded config string. §E's verdicts are worthless if
# it does, and they fail in BOTH directions: a truncated body reports a call
# absent that is present, and would equally report an absence it never reached.
# So assert a token known to sit near the tail of each subject function.
_inst=$(fn_body "$AGENT_PROD" mailInstall)
_sync=$(fn_body "$AGENT_PROD" mailSyncConfig)
if [ -n "$_inst" ] && has "$_inst" 'Mail server installation complete'; then
  ok "the extractor reaches the end of mailInstall ($(wc -l <<< "$_inst") lines)"
else
  bad "mailInstall extraction is truncated ($(wc -l <<< "$_inst") lines) — §E cannot be believed"
fi
if [ -n "$_sync" ] && has "$_sync" 'Mail config synced'; then
  ok "the extractor reaches the end of mailSyncConfig ($(wc -l <<< "$_sync") lines)"
else
  bad "mailSyncConfig extraction is truncated ($(wc -l <<< "$_sync") lines) — §E cannot be believed"
fi

# ── §A the map is built, not borrowed ───────────────────────────────────
echo "§A the map"

if hasre "$AGENT_PROD" '^[[:space:]]*mailPostfixSenderLogin[[:space:]]*=[[:space:]]*"/etc/postfix/'; then
  ok "a dedicated sender-login map path exists"
else
  bad "no dedicated sender-login map — the control has nothing to read"
fi

# The two re-pointings that would MANUFACTURE the defect. virtual_mailbox_maps
# values are maildir paths, so that one refuses every authenticated send;
# virtual_alias_maps values are forward targets, so a mailbox that sets
# forwarding loses the right to send as itself and the forward target gains it —
# and a tenant could grant another tenant send-as rights by creating an alias.
for wrong in mailPostfixVirtualMailbox mailPostfixVirtualAlias; do
  if hasre "$AGENT_PROD" "smtpd_sender_login_maps=hash:\"[[:space:]]*\+[[:space:]]*$wrong\b"; then
    bad "smtpd_sender_login_maps points at $wrong — that map's VALUES are not login names"
  else
    ok "smtpd_sender_login_maps does not borrow $wrong"
  fi
done

if hasre "$AGENT_PROD" 'smtpd_sender_login_maps=hash:"[[:space:]]*\+[[:space:]]*mailPostfixSenderLogin\)'; then
  ok "the restriction reads the purpose-built map"
else
  bad "the sender-login map is not the one the restriction names"
fi

if has "$AGENT_PROD" 'func mailBuildSenderLoginMap('; then
  ok "the map builder is a named function, so it can be tested without a box"
else
  bad "no map builder function — the table is unreachable from a unit test"
fi

# ── §B the wildcard row ─────────────────────────────────────────────────
# The table is an ALLOW-LIST (postconf(5): the authenticated form refuses a SASL
# client whose MAIL FROM "is not listed in $smtpd_sender_login_maps"). The
# per-domain row is not what stops a forge — it is what keeps a domain's OWN
# logins able to send as their aliases, catch-alls and role addresses. These
# properties are now asserted by calling mailBuildSenderLoginMap directly
# (§F runs the tests), which also catches the unreachable-row mutation (a loop
# filter neutered to "never") that a grep for the push statement could not.
# B-row retired: covered by TestMailMailboxesWithinOneDomainMaySendAsEachOther and TestMailSenderLoginMap (panel/go/internal/agent/routes/mail_test.go)
# B-loop retired: covered by TestMailMailboxesWithinOneDomainMaySendAsEachOther and TestMailEveryLineIsAWellFormedTwoColumnRow (panel/go/internal/agent/routes/mail_test.go)
# B-sentinel retired: covered by TestMailADomainWithNoMailboxIsOwnedByNobody (panel/go/internal/agent/routes/mail_test.go)
# B-exact-domain retired: covered by TestMailASubdomainIsNotItsParentDomain (panel/go/internal/agent/routes/mail_test.go)
# B-disabled retired: covered by TestMailADisabledMailboxOwnsNeitherItselfNorItsDomain (panel/go/internal/agent/routes/mail_test.go)

# ── §C the order ────────────────────────────────────────────────────────
echo "§C map, then hash, then the key"

# A hash: table named by an smtpd restriction is opened when smtpd initialises.
# A missing or stale .db makes smtpd exit fatal and master throttle it — a total
# outage on 25 and 587, not a per-message deferral. So the postmap result must
# be CHECKED, and the keys written only after it.
helper=$(fn_body "$AGENT_PROD" mailEnsureSenderLoginEnforcement)
if perl -0777 -ne 'exit !/out, err := mailExec\("postmap", mailPostfixSenderLogin\)\s*\n\s*if err != nil \{.*?\n\s*return\n.*?if !out\.Success\(\) \{/s' <<< "$helper"; then
  ok "the postmap result is checked, not discarded"
else
  bad "the postmap result is not checked — the restriction can be armed against a map Postfix cannot open"
fi

# FIVE legacy call sites discard their status — install x2 (the two virtual
# maps), sync x2 (the same pair), and the relay's sasl_passwd. The sender-login
# map must never join them, so pin the number rather than the absence: a sixth
# discarding call is either this map losing its check or a new map arriving
# without one, and both deserve a red.
discarded=$(occurrences "$AGENT_PROD" '_, _ = mailExec("postmap"')
if [ "$discarded" -eq 5 ]; then
  ok "exactly the five legacy postmap calls discard their status ($discarded)"
else
  bad "expected 5 status-discarding postmap calls, found $discarded — the sender-login map may have become one of them"
fi

# The early return is the fail-safe. Without it a failed hash still arms the key.
if [ -z "$helper" ]; then
  bad "could not extract the enforcement helper — §C's remaining arms cannot fire"
else
  ok "the enforcement helper was extracted ($(wc -l <<< "$helper") lines)"
  returns=$(grep -cE '^[[:space:]]*return$' <<< "$helper")
  if [ "$returns" -ge 3 ]; then
    ok "every failure path returns before arming the restriction ($returns)"
  else
    bad "only $returns early returns — a failure can fall through and arm the key anyway"
  fi
  # Order within the helper: the map write and hash must precede the keys.
  map_at=$(grep -nF '"postmap"' <<< "$helper" | head -1 | cut -d: -f1)
  key_at=$(grep -nF 'smtpd_sender_restrictions' <<< "$helper" | head -1 | cut -d: -f1)
  if [ -n "$map_at" ] && [ -n "$key_at" ] && [ "$map_at" -lt "$key_at" ]; then
    ok "the map is hashed (line $map_at) before the restriction is written (line $key_at)"
  else
    bad "the restriction is written before the map is hashed — this is the ordering that takes smtpd down"
  fi
  # The trap the refuted premise hid. An allow-list armed against a table with no
  # rows authorises nobody, so it refuses EVERY authenticated submission on the
  # box — 553, no other symptom. `mailInstall` calls this helper with whatever
  # the map file already held, and on a box upgrading into the release that
  # introduced that file it holds nothing. Re-running the installer is the
  # ordinary response to mail looking broken, so without this guard the retry
  # path takes the box's own authenticated mail off the air until the next
  # mailbox change. Pin that the guard exists AND that it precedes the key: a
  # check placed after the arming is decoration.
  empty_at=$(grep -nE 'strings\.TrimSpace\(mapContent\) == ""' <<< "$helper" | head -1 | cut -d: -f1)
  if [ -n "$empty_at" ] && [ -n "$key_at" ] && [ "$empty_at" -lt "$key_at" ]; then
    ok "a map that authorises nobody is refused (line $empty_at) before the restriction is written (line $key_at)"
  else
    bad "nothing stops an empty map from arming the restriction — every authenticated submission on the box would be refused with 553"
  fi
fi

# ── §D the restriction form ─────────────────────────────────────────────
echo "§D the restriction"

# The AUTHENTICATED form. The bare reject_sender_login_mismatch also refuses
# UNAUTHENTICATED inbound mail on 25 whose envelope sender is a hosted address —
# ordinary for a mailing list, a forwarder, or a tenant's external SaaS.
if has "$AGENT_PROD" '"smtpd_sender_restrictions=reject_authenticated_sender_login_mismatch'; then
  ok "the authenticated-only form is used, so inbound port-25 mail is untouched"
else
  bad "the authenticated-only form is not used — legitimate inbound mail can be refused"
fi

# The arm this suite got WRONG first, and the one a source pin could never have
# settled on its own. The first cut wrote `permit_mynetworks, reject_…` on the
# theory that it protected local mail. Driven on a real two-tenant box that
# version accepted every forge: `mynetworks_style = host` still covers
# 127.0.0.0/8, and a permit matches before the reject is reached — so on a
# hosting box, where "from this machine" means "from any tenant's own code",
# the permit disarmed the control completely. It also protected nothing:
# `sendmail` submission is non_smtpd and never reaches these restrictions,
# measured by delivering mail with an unowned -f address after removal.
if hasre "$AGENT_PROD" 'smtpd_sender_restrictions=[^"]*permit_mynetworks'; then
  bad "permit_mynetworks precedes the sender check — it matches first for anything connecting from the box, which on a hosting machine is every tenant's own code, and the control is inert"
else
  ok "no permit_mynetworks in front of the sender check, so a local authenticated session is checked like any other"
fi
if hasre "$AGENT_PROD" 'smtpd_sender_login_maps=proxy:'; then
  bad "the map is opened through proxymap — measured unnecessary (plain hash: works; smtpd opens the table before it chroots)"
else
  ok "the map is a plain hash:, which smtpd opens before chrooting"
fi

# It must be smtpd_sender_restrictions, not the recipient list. Appending to
# smtpd_recipient_restrictions is a guaranteed no-op: permit_sasl_authenticated
# short-circuits it, on both the main.cf value and the submission override.
if hasre "$AGENT_PROD" 'smtpd_recipient_restrictions ?= ?[^"`]*sender_login'; then
  bad "the check was appended to smtpd_recipient_restrictions — permit_sasl_authenticated short-circuits it"
else
  ok "the check is not hidden behind permit_sasl_authenticated in the recipient list"
fi

# ── §E the carriers ─────────────────────────────────────────────────────
echo "§E delivery"

calls=$(occurrences "$AGENT_PROD" 'mailEnsureSenderLoginEnforcement(')
if [ "$calls" -ge 3 ]; then
  ok "the helper is defined and called from both carriers ($calls occurrences)"
else
  bad "only $calls occurrences — one of the two carriers does not arm enforcement"
fi

sync_fn="$_sync"
if [ -n "$sync_fn" ] && has "$sync_fn" 'mailEnsureSenderLoginEnforcement(mailBuildSenderLoginMap(&b))'; then
  ok "mailSyncConfig arms enforcement, so a box already running mail repairs itself on the next mailbox change"
else
  bad "mailSyncConfig does not arm enforcement — no existing install would ever receive this"
fi

# What this carrier is actually for, now that the helper refuses an empty map:
# preserving and re-arming an EXISTING map across an installer re-run. A box with
# no mailboxes has nothing to protect and nobody who can authenticate, and its
# first mailbox goes through mailSyncConfig, which arms it there.
install_fn="$_inst"
if [ -n "$install_fn" ] && has "$install_fn" 'mailEnsureSenderLoginEnforcement(mailReadString(mailPostfixSenderLogin))'; then
  ok "mailInstall re-arms enforcement, so an installer re-run keeps an existing map armed"
else
  bad "mailInstall does not arm enforcement — an installer re-run would leave an existing map unenforced"
fi

# The keys must NOT be added to the appended config block: that block is written
# once and skipped for ever after, so a template edit reaches new installs only.
# The template is a Go raw string that itself splices in a backtick ("`local`"),
# so it is bounded by the closing backtick on a line of its own, and its last
# line is asserted so a truncated block cannot read as a clean absence.
block=$(perl -0777 -ne 'print $1 if /(const mailPostfixConfigTmpl = `.*?\n`\n)/s' <<< "$AGENT_RAW")
if [ -z "$block" ] || ! grep -qF 'non_smtpd_milters' <<< "$block"; then
  bad "could not extract the whole main.cf template block — this arm cannot fire"
elif grep -qF 'smtpd_sender_restrictions' <<< "$block"; then
  bad "the restriction was put in the write-once main.cf block — it would reach no existing install"
else
  ok "the restriction is written by postconf, not frozen into the write-once block"
fi

# ── §F the unit tests ───────────────────────────────────────────────────
echo "§F the property is unit-tested"

# Ported from the Rust tests a_tenant_may_not_send_as_another_tenants_domain +
# an_invented_local_part_at_a_hosted_domain_is_still_owned (TestMailSenderLoginMap),
# a_domain_with_no_mailbox_is_owned_by_nobody, a_subdomain_is_not_its_parent_domain,
# a_disabled_mailbox_owns_neither_itself_nor_its_domain; the last two names
# carry the §B per-domain-row and enabled-domain-loop properties.
GO_TESTS="TestMailSenderLoginMap TestMailADomainWithNoMailboxIsOwnedByNobody TestMailASubdomainIsNotItsParentDomain TestMailADisabledMailboxOwnsNeitherItselfNorItsDomain TestMailMailboxesWithinOneDomainMaySendAsEachOther TestMailEveryLineIsAWellFormedTwoColumnRow"
if [ ! -f "$AGENT_TEST_FILE" ]; then
  bad "no $AGENT_TEST_FILE — §F cannot fire"
else
  GOT=$(cd "$REPO/panel/go" && go test ./internal/agent/routes/ -count=1 -v -run "^($(tr ' ' '|' <<< "$GO_TESTS"))\$" 2>&1)
  if grep -qE '^ok[[:space:]]' <<< "$GOT"; then
    ok "go test ran the map builder's tests and the package passed"
  else
    bad "go test of the map builder's tests did not pass: $(tail -3 <<< "$GOT" | tr '\n' ' ')"
  fi
  for t in $GO_TESTS; do
    if grep -qF -- "--- PASS: $t " <<< "$GOT"; then
      ok "unit test present and passing: $t"
    else
      bad "unit test missing or failing: $t — the map builder lost coverage of that case"
    fi
  done
fi

# ── §G the installer arms the control on the box it just installed ──────
# The agent half can only arm what the panel sends it. Until s354 `mail_install`
# was the ONE writer of mail state that never called the sync, so a box that
# re-ran the installer kept whatever the sender-login table already held — on any
# box upgrading past v2.106.0, nothing — and stayed unprotected until its next
# mailbox or domain change.
#
# What makes that state easy to miss is the agent's own empty-table guard: it
# renders the box SAFE rather than ARMED, so nothing breaks and nothing warns.
# §A-§F can all be green while no install path ever reaches them.
echo "§G the install path applies mail configuration"

BACKEND="$REPO/panel/go/internal/api/rt_mail.go"
if [ ! -f "$BACKEND" ]; then
  bad "§G missing $BACKEND — refusing to report a clean sweep"
else
  BACKEND_CODE=$(code "$BACKEND")
  # In Go install and uninstall share rtMailRunInstall(…, uninstall bool), so
  # the window is that function, and within it the sync must sit AFTER the
  # agent's /mail/install call (the install branch), not in the uninstall one.
  RUN_FN=$(fn_body "$BACKEND_CODE" rtMailRunInstall)
  SYNC_SITES=$(grep -oE 'rtMailSyncMailConfig\(' <<< "$BACKEND_CODE" | wc -l)
  if [ "$(grep -c '[^[:space:]]' <<< "$RUN_FN")" -lt 10 ] || ! has "$(fn_body "$BACKEND_CODE" rtMailMailInstall)" 'rtMailRunInstall(st, w, r, false)'; then
    bad "§G could not extract rtMailRunInstall() as rtMailMailInstall's body — the arm has no subject"
  elif [ "$SYNC_SITES" -lt 5 ]; then
    bad "§G CONTROL only $SYNC_SITES rtMailSyncMailConfig occurrences in the backend — this grep is pointed wrong"
  else
    ok "§G CONTROL the backend still carries $SYNC_SITES rtMailSyncMailConfig occurrences"
    inst_at=$(grep -nF '"/mail/install"' <<< "$RUN_FN" | head -1 | cut -d: -f1)
    uninst_at=$(grep -nF '"/mail/uninstall"' <<< "$RUN_FN" | head -1 | cut -d: -f1)
    sync_at=$(grep -nF 'rtMailSyncMailConfig(' <<< "$RUN_FN" | head -1 | cut -d: -f1)
    if [ -n "$inst_at" ] && [ -n "$sync_at" ] && [ -n "$uninst_at" ] && [ "$uninst_at" -lt "$inst_at" ] && [ "$sync_at" -gt "$inst_at" ]; then
      ok "§G mail install applies mail configuration after a successful install"
    else
      bad "§G mail install never applies mail configuration — a box that re-runs the installer stays unarmed until its next mailbox change"
    fi
  fi
fi

echo
echo "PASS $PASS FAIL $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
