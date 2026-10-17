#!/usr/bin/env bash
# An actionable refusal must survive the trip to the operator.
#
# The panel's rule (agentError in panel/go/internal/api/core_error.go) is deliberate and correct: an
# agent 4xx is an ANSWER and is passed through with its sentence intact, while a
# non-4xx is replaced with "Operation failed. Reference: {uuid}" so an agent
# fault cannot leak internals. Everything this suite pins is the consequence:
# whenever an agent handler answers 5xx for a condition the CALLER can fix, the
# panel destroys the remedy and tells the operator their agent broke — on a
# working agent.
#
# v2.99.0 fixed exactly one instance of this (test_destination's sshpass arm) and
# wrote the rule down in its own comment. A sweep then found the same shape in
# eleven more places, including the unattended nightly backup path fifteen lines
# above the fix. This suite pins each one, and pins BOTH ENDS: a route that maps
# a named constant is a vacuous arm if the service never produces that constant.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

GA=panel/go/internal/agent
R_FILES=$GA/routes/files.go
S_FILES=$GA/services/files.go
R_VOL=$GA/routes/volume_backup.go
S_VOL=$GA/services/volume_backup.go
R_STAGING=$GA/routes/staging.go
S_STAGING=$GA/services/staging.go
R_SEC=$GA/routes/security.go
S_SEC=$GA/services/security.go
R_SMTP=$GA/routes/smtp.go
S_SMTP=$GA/services/smtp.go
ERRRS=panel/go/internal/api/core_error.go
for f in "$R_FILES" "$S_FILES" "$R_VOL" "$S_VOL" "$R_STAGING" \
         "$S_STAGING" "$R_SEC" "$S_SEC" "$R_SMTP" "$S_SMTP" "$ERRRS"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

# Strip // line comments: this suite's whole subject is code whose COMMENTS
# explain the very rule the arms grep for, so without this the prose would
# satisfy the suite. Not stripping /* */ — none of these files use it, and a
# naive block stripper has swallowed a whole file in this repo before.
strip() { sed 's://.*::' "$1"; }
has()  { grep -q  -- "$2" <<< "$1"; }
hasE() { grep -qE -- "$2" <<< "$1"; }
# One function's body, so a sibling handler cannot satisfy an arm.
fnbody() { awk -v fn="$2" 'index($0, "func " fn "(") == 1 {f=1} f {print} f && /^}/ {exit}' <<< "$1"; }

echo "══ an actionable refusal must survive the trip to the operator ══"
echo
echo "── 0. the panel rule these all depend on ──"

# §0 agentError 4xx arm retired: covered by TestAgent4xxKeepsStatusAndSaysWhy + TestAgent5xxStaysGenericWithIncidentID (panel/go/internal/api/core_error_test.go)
# §0 agentActionable 4xx arm retired: covered by TestAgentActionableOnly4xx (panel/go/internal/api/core_error_test.go)
# Both copies are still asserted SEPARATELY — one test per function — so the two
# drifting apart (one rule for a single call, another for a fleet summary) fails.
if (cd panel/go && go test ./internal/api/ -count=1 \
      -run '^(TestAgent4xxKeepsStatusAndSaysWhy|TestAgent5xxStaysGenericWithIncidentID|TestAgentActionableOnly4xx)$' >/dev/null 2>&1); then
  ok "agentError and agentActionable both treat a 4xx from the agent as an answer worth passing through (Go tests)"
else
  bad "agentError's or agentActionable's 4xx boundary changed — the arms below defend nothing"
fi
echo
echo "── 1. file manager: policy refusals are not agent faults ──"

SRC_RF=$(strip "$R_FILES"); SRC_SF=$(strip "$S_FILES")

# BOTH ENDS. The service must still emit these sentences, or the route's match
# is dead code and every arm below it is vacuously green.
for sentence in 'File too large (max 2MB)' 'File is binary or not readable as text' \
                'Path already exists' 'Source does not exist' \
                'Destination already exists' 'Path does not exist'; do
  if has "$SRC_SF" "$sentence"; then
    ok "the file service still refuses with \"$sentence\""
  else
    bad "\"$sentence\" is gone from the service — the route arm for it is vacuous"
  fi
done

# file_status's five status arms retired: covered by TestPinAgentRefusalStatusFilesStatus (panel/go/internal/agent/routes/pin_agent_refusal_status_test.go)
if (cd panel/go && go test ./internal/agent/routes/ -count=1 -run '^TestPinAgentRefusalStatusFilesStatus$' >/dev/null 2>&1); then
  ok "filesStatus answers 404/409/413/415 for the refusals and still 5xx for a genuine fault (Go test)"
else
  bad "filesStatus misclassifies a refusal or a real fault — TestPinAgentRefusalStatusFilesStatus fails"
fi

# All four sites must route through it. Counted, because fixing three of four is
# how this class survived in the first place.
SITES=$(grep -c 'filesStatus(w, err)' <<< "$SRC_RF" || true)
if [ "${SITES:-0}" -ge 4 ]; then
  ok "all $SITES file-manager sites classify their refusals"
else
  bad "only ${SITES:-0} file-manager sites classify — read/create/rename/delete must all four"
fi

echo
echo "── 2. restore paths: an archive that is gone ──"

SRC_RV=$(strip "$R_VOL"); SRC_SV=$(strip "$S_VOL")

if has "$SRC_SV" 'Backup file not found'; then
  ok "the volume service still refuses a vanished archive by name"
else
  bad "\"Backup file not found\" is gone from the service — the route arm is vacuous"
fi
VR=$(fnbody "$SRC_RV" volumeBackupRestore)
if [ "$(printf '%s' "$VR" | wc -l)" -lt 8 ]; then
  bad "the volume restore handler did not extract — its arms measure nothing"
else
  ok "the volume restore handler extracted ($(printf '%s' "$VR" | wc -l) lines)"
  hasE "$VR" 'case "Backup file not found":' && hasE "$VR" 'StatusNotFound' \
    && ok "an archive the panel listed but the host no longer has answers 404" \
    || bad "a vanished archive is a 5xx again — a retry just mints a new incident id"
fi

echo
echo "── 3. staging: the sentence already named the path ──"

SRC_RS=$(strip "$R_STAGING"); SRC_SS=$(strip "$S_STAGING")
if has "$SRC_SS" 'directory not found'; then
  ok "the staging service still names the directory it could not find"
else
  bad "the staging refusal is gone from the service — the route arm is vacuous"
fi
SY=$(fnbody "$SRC_RS" stagingSync)
if [ "$(printf '%s' "$SY" | wc -l)" -lt 8 ]; then
  bad "stagingSync did not extract — its arms measure nothing"
else
  ok "stagingSync extracted ($(printf '%s' "$SY" | wc -l) lines)"
  hasE "$SY" 'StatusNotFound' \
    && ok "a missing document root answers 404, keeping the path it named" \
    || bad "the staging refusal is a 5xx again — and it had spelled the exact path"
  hasE "$SY" 'StatusInternalServerError' \
    && ok "a real sync failure is still a 5xx" \
    || bad "the staging classifier is unconditional"
fi

echo
echo "── 4. firewall + mail: a package the panel will never install there ──"

SRC_SEC=$(strip "$R_SEC"); SRC_SSEC=$(strip "$S_SEC")
SRC_RSM=$(strip "$R_SMTP"); SRC_SSM=$(strip "$S_SMTP")

hasE "$SRC_SSEC" '^const SecurityUfwMissing = "' \
  && ok "the ufw refusal is a named constant, not a sentence to guess at" \
  || bad "SecurityUfwMissing is gone — the route is back to substring-matching prose"
# The constant must be what the service actually returns, or the route's
# equality test never fires. This is the end that was never checked.
USES=$(grep -c 'errors.New(SecurityUfwMissing)' <<< "$SRC_SSEC" || true)
if [ "${USES:-0}" -ge 2 ]; then
  ok "both ufw call paths raise the named constant ($USES)"
else
  bad "only ${USES:-0} ufw path(s) raise the constant — add and delete must both"
fi

# security_status's three status arms (keys on the constant / 424 / still 5xx)
# retired: covered by TestSecurityStatusFor (panel/go/internal/agent/routes/security_test.go)
if (cd panel/go && go test ./internal/agent/routes/ -count=1 -run '^TestSecurityStatusFor$' >/dev/null 2>&1); then
  ok "securityStatusFor maps SecurityUfwMissing to 424 and a genuine firewall fault to 5xx (Go test)"
else
  bad "securityStatusFor misclassifies — the ufw refusal is a 5xx again, or real faults read as user error"
fi
SEC_SITES=$(grep -c 'writeErr(w, securityStatusFor(err.Error()), err.Error())' <<< "$SRC_SEC" || true)
if [ "${SEC_SITES:-0}" -ge 3 ]; then
  ok "all $SEC_SITES security handlers classify (add, delete, apply-fix)"
else
  bad "only ${SEC_SITES:-0} security handler(s) classify — add/delete/apply-fix must all three"
fi

hasE "$SRC_SSM" '^const SmtpMsmtpMissing = "' \
  && ok "the msmtp refusal is a named constant" \
  || bad "SmtpMsmtpMissing is gone — Test Email is back to blaming the operator's relay"
has "$SRC_SSM" 'errors.New(SmtpMsmtpMissing)' \
  && ok "the mail service raises it when the binary is absent" \
  || bad "the service never raises SmtpMsmtpMissing — the route arm is vacuous"
TE=$(fnbody "$SRC_RSM" smtpTestEmail)
if [ "$(printf '%s' "$TE" | wc -l)" -lt 8 ]; then
  bad "smtpTestEmail did not extract — its arms measure nothing"
else
  ok "smtpTestEmail extracted ($(printf '%s' "$TE" | wc -l) lines)"
  hasE "$TE" 'if err\.Error\(\) == services\.SmtpMsmtpMissing \{' && hasE "$TE" 'StatusFailedDependency' \
    && ok "a host with no msmtp answers 4xx instead of implicating the relay" \
    || bad "Test Email is a 5xx again — the operator will go debug their mail provider"
  hasE "$TE" 'StatusInternalServerError' \
    && ok "a genuine send failure is still a 5xx" \
    || bad "the mail classifier is unconditional"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
