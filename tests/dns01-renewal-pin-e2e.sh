#!/usr/bin/env bash
# Regression pins for the s392 ship — a certificate is renewed over the challenge
# that ISSUED it.
#
# ⛔ EVERY ARM READS A COMMENT-STRIPPED SUBJECT. s386's suite printed 43/43 green
# with that ship's headline defect restored, because the explanatory comment above
# the fix quoted the code and satisfied every arm. Stripping is not a style choice
# here; an arm that reads a file any other way is a bug in this file.
#
# WHAT THE SHIP FIXED
#
#   `sites` recorded nothing about which ACME challenge produced a certificate, so
#   all three renewal doors aimed an HTTP-01, single-name order at `site.domain`.
#   For a DNS-01 certificate that is wrong in two directions, both silent:
#
#     SHAPE A — the site IS the Cloudflare zone apex. The certificate directory is
#       named after the site, so `foreign_cert_issuer` finds the wildcard, sees a
#       Let's Encrypt issuer, and returns "not foreign" — permission to proceed.
#       `provision_cert` then overwrites the shared fullchain.pem IN PLACE with a
#       single-name certificate and every sibling vhost in the zone begins serving
#       a certificate that does not cover it. Reachable on a STOCK install:
#       `auto_fix_safe_findings` runs on every security scan with no opt-in.
#
#     SHAPE B — a subdomain under a zone wildcard. There is no certificate at
#       `/etc/dockpanel/ssl/{site.domain}/`, so the guard exits on `has_cert:false`
#       before it ever reads an issuer. The renewal writes an orphan certificate,
#       the panel re-renders the vhost from `ssl_cert_path` and points nginx BACK
#       at the un-renewed wildcard, and stamps the NEW certificate's expiry on the
#       row. The 45-day window never reopens and the site goes dark behind a panel
#       that already reported a successful renewal.
#
# §A is the arm that would have caught it: it derives the subject the ISSUANCE
# door records and the subject the RENEWAL door orders, and fails when they can
# drift apart. An arm pinned to either side alone was green throughout.
#
# Static analysis over the Go source (panel/go): offline, deterministic, same
# verdict on an air-gapped runner (lesson #641). Pure-function arms whose subject
# can be called directly live as Go tests (named where each arm was retired).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
ok()  { printf '\033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '\033[31m✗\033[0m %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3', got '$2'"; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "missing: $3" ;; esac; }
hasnt(){ case "$2" in *"$3"*) bad "$1" "present but must not be: $3" ;; *) ok "$1" ;; esac; }

# ugrep's --ignore-files shim honours .gitignore, so use the real binary.
G=/usr/bin/grep

# Comments blanked (Go `//`, SQL `--`), then every space, tab, newline and
# backslash removed, so a statement flattens to the tokens it compiles to.
subj()   { sed -E -e 's://.*$::' -e 's:^[[:space:]]*--.*$::' "$1" | tr -d ' \t\n\\'; }
subjin() { sed -E -e 's://.*$::' -e 's:^[[:space:]]*--.*$::' | tr -d ' \t\n\\'; }
# ⛔ ONE FUNCTION'S BODY, not the file (#672). A file-scoped `has` asks "does this
# file contain this shape anywhere", which for ordinary code is always yes.
# gofmt closes every top-level func with a column-0 `}`.
fnbody() { awk -v p="$2" 'index($0,p)==1{f=1} f{print} f && /^}$/{exit}' "$1"; }
occ()    { printf '%s' "$1" | $G -oF -- "$2" | wc -l | tr -d ' '; }

GO=panel/go/internal
HELP=$GO/api/core_helpers.go
BSSL=$GO/api/rt_ssl.go
SITES=$GO/api/rt_sites.go
HEAL=$GO/api/svc_auto_healer.go
SCAN=$GO/api/svc_security_scanner.go
AGENT=$GO/api/svc_agent.go
ASSL=$GO/agent/services/ssl.go
ASSLR=$GO/agent/routes/ssl.go
MIGDIR=$GO/api/migrations
MIG="$MIGDIR/20260823000000_ssl_provenance.sql"

for f in "$HELP" "$BSSL" "$SITES" "$HEAL" "$SCAN" "$AGENT" "$ASSL" "$ASSLR" "$MIG"; do
  [ -f "$f" ] || { bad "SETUP" "$f missing"; exit 1; }
done

# An arm over an empty subject prints green for every absence below (#143), so
# every subject is floored on its POST-strip size before anything reads it.
for pair in "$HELP:15000" "$BSSL:20000" "$SITES:60000" "$HEAL:30000" "$SCAN:15000" \
            "$AGENT:15000" "$ASSL:25000" "$ASSLR:9000" "$MIG:900"; do
  f=${pair%:*}; min=${pair##*:}
  n=$(subj "$f" | wc -c)
  [ "$n" -ge "$min" ] || { bad "SETUP" "$f has $n chars of code, expected >= $min"; exit 1; }
done

F_HELP=$(subj "$HELP"); F_BSSL=$(subj "$BSSL"); F_SITES=$(subj "$SITES")
F_HEAL=$(subj "$HEAL"); F_SCAN=$(subj "$SCAN"); F_AGENT=$(subj "$AGENT")
F_ASSL=$(subj "$ASSL"); F_ASSLR=$(subj "$ASSLR"); F_MIG=$(subj "$MIG")

echo "── §A  the door that ISSUES and the door that RENEWS agree on the subject"

# ⭐ THE ARM THAT WOULD HAVE CAUGHT THE ORIGINAL DEFECT. Both halves are DERIVED
# from source and compared: an arm pinned to either side alone stayed green for
# 137 releases while the two disagreed.
#
# The issuance door records the name it ORDERED (`provisionDomain`, which on a
# wildcard is the zone, not the site). The renewal door must order the name the
# row RECORDED (`ssl_cert_subject`). If either side ever names the site's domain
# instead, they have drifted and the wildcard is destroyed again.
has "A1 the DNS-01 door records the name it ordered, not the site" "$F_BSSL" \
    "ssl_challenge='dns-01',ssl_cert_subject=\$6"
# $6 is the sixth bound argument: provisionDomain, then the zone row ($8).
has "A1b bound to provisionDomain — the ZONE on a wildcard" "$F_BSSL" \
    "certPath,keyPath,sslExpiry,profile,id,provisionDomain,wildcard,zone.ID)"
has "A2 the HTTP-01 door records the site's own domain" "$F_BSSL" \
    "ssl_challenge='http-01',ssl_cert_subject=\$6"
F_RENEWDNS=$(fnbody "$BSSL" "func rtSslRenewOverDns01(" | subjin)
[ "$(printf '%s' "$F_RENEWDNS" | wc -c)" -ge 800 ] || \
  { bad "SETUP" "rtSslRenewOverDns01 body extracted to $(printf '%s' "$F_RENEWDNS" | wc -c) chars — arms over it examine nothing"; exit 1; }
has "A3 the renewal orders the RECORDED subject" "$F_RENEWDNS" \
    '"/ssl/provision-dns01/"+subject'
# …and never the site's own domain, which is what the defect did.
hasnt "A3b and never the site's own domain" "$F_RENEWDNS" "site.Domain"

# The agent route this reuses ALREADY existed and already is a renewal — that is
# why the fix reaches an installed fleet with no agent upgrade. Pinned so a
# future edit cannot quietly invent a second route and strand every existing box.
has "A4 the agent route reused here is the one that already shipped" "$F_ASSLR" \
    'casea=="provision-dns01":req.SetPathValue("domain",b)sslProvisionDNS01(st,w,req)'
has "A4-control and it is mounted on the POST /ssl/{a}/{b} dispatcher" "$F_ASSLR" \
    'r.Handle("POST/ssl/{a}/{b}",'
has "A4b and it orders the wildcard SAN off the same flag" "$F_ASSL" \
    'ifwildcard{names=append(names,"*."+domain)}'

echo "── §B  the plan is decided from POSITIVE evidence, never from an absence"

F_PLAN=$(fnbody "$HELP" "func renewalPlan(" | subjin)
[ "$(printf '%s' "$F_PLAN" | wc -c)" -ge 900 ] || \
  { bad "SETUP" "renewalPlan body extracted to $(printf '%s' "$F_PLAN" | wc -c) chars"; exit 1; }

# ⭐ THE RULE THAT CONVERGES. Renewing over HTTP-01 requires the row to SAY
# `http-01`. Absence-of-wildcard-evidence does not converge: a NON-wildcard
# DNS-01 certificate is byte-identical to an HTTP-01 one in every field the panel
# or the agent can read — one identifier, no `*.` SAN, its own directory — and
# that is the population whose operator chose DNS-01 *because port 80 cannot be
# reached*. Under an absence rule the fleet would re-order those over HTTP-01 for
# ever. Under this rule an unrecorded row degrades exactly ONCE and records itself.
# B1 retired: covered by TestRenewalPlanWithoutDB (panel/go/internal/api/core_helpers_test.go)
# B2 retired: covered by TestRenewalPlanWithoutDB (panel/go/internal/api/core_helpers_test.go)
# Everything else — including `dns-01` — falls through to the DNS-01 branch:
# the switch holds exactly those two cases and no default.
has "B3 every other recorded challenge falls through" "$F_PLAN" \
    'case*site.SSLChallenge=="http-01":returnRenewalPlan{Kind:RenewHTTP01}}subject:='

# ⛔ THE FORGED SIGNAL. A draft of the s392 ship derived provenance from the
# stored certificate path and would have branded healthy sites as wildcards and
# refused to renew them for ever. The plan must never read that column.
#
# ⚠ The reason originally written here — "rename_domain writes only the domain
# while the agent MOVES the certificate directory" — was repealed by the very
# release that wrote it: the rename now rewrites that column itself. The signal
# is STILL forged, for two reasons that do survive: the rewrite is scoped to the
# site's own old directory, so a wildcard child renamed out of its zone keeps
# naming the zone; and any row renamed on a build at or below v2.144.x keeps the
# stale path, whose name can be re-claimed by the next site that asks for it.
# Recorded because an arm defended by a dead reason is one refactor from being
# deleted as obsolete.
hasnt "B4 the plan never reads the cert path (rename forges it)" "$F_PLAN" "SSLCertPath"
# POSITIVE CONTROL: the same subject DOES carry the columns it is supposed to read,
# so B4 cannot be passing because the extraction is empty or misspelled.
has "B4-control the plan does read the recorded challenge" "$F_PLAN" "site.SSLChallenge"
has "B4-control2 and the recorded subject" "$F_PLAN" "site.SSLCertSubject"

echo "── §C  whose Cloudflare credential renews whose certificate"

# ⛔ An unattended loop has no actor. Resolving a zone by bare domain would hand
# one account's Cloudflare token to a renewal running for another account's site,
# and every other `dns_zones` read in the tree is scoped `user_id = $2`.
has "C1 the legacy fallback scopes zones to the SITE OWNER" "$F_PLAN" \
    "WHEREuser_id=\$1ANDprovider='cloudflare'"
has "C1b bound to the site's owner, not an actor" "$F_PLAN" "site.UserID,subject)"
# The recorded zone ROW is preferred, so the credential that renews is provably
# the credential that issued and no text subject can select a different tenant's.
has "C2 the recorded zone id is preferred" "$F_PLAN" "ifsite.SSLDNSZoneID!=nil{"
# C2b (the issuance door records zone.ID) is A1b's bound-argument list.
# The unattended loops take the key from the registry field, not the environment.
# One each: the healer opens it at the renewal, the scanner threads it from `run`.
eq "C3 both loops open the token through the registry accessor" \
   "$(( $(occ "$F_HEAL" "agents.JWTSecret()") + $(occ "$F_SCAN" "agents.JWTSecret()") ))" "2"
has "C3b the scanner threads it rather than re-reading it" "$F_SCAN" "jwtSecretstring)"

echo "── §D  refusal is a RUNG, not a terminus"

# For a zone-apex wildcard the OLD silent downgrade at least left the apex
# serving; refusing all the way to expiry takes the apex AND every sibling down
# together. So a refusal that cannot be repaired in time becomes a DELIBERATE,
# recorded, alerted downgrade instead — never worse than the behaviour it replaced.
has "D1 the ladder has a last rung" "$F_HELP" "constDNS01LastResortDaysint64=7"
has "D2 the rung is reached by time remaining" "$F_PLAN" \
    "ifdaysRemaining!=nil&&*daysRemaining<=dns01LastResortDays(site.SSLProfile){"
# D2a is the same token: the rung is chosen PER PROFILE through dns01LastResortDays.

# ⭐ D2b — THE INVARIANT, which is what actually failed: the rung must sit
# STRICTLY BELOW the profile's renewal margin, or Refuse is never returned for
# that profile (it failed for `shortlived` from the day the profile shipped).
# D2b retired: covered by TestPinDns01RenewalRungSitsBelowEveryProfileMargin (panel/go/internal/api/pin_dns01_renewal_test.go)
has "D3 and it names what stops being covered" "$F_PLAN" "returnRenewalPlan{Kind:RenewLastResortHTTP01,Losing:names}"
has "D3b the wildcard's names are spelled out for the operator" "$F_PLAN" \
    'names=fmt.Sprintf("%sand*.%s",subject,subject)'

# ⛔ A DECLINE IS NOT A FAILURE. The renewal-failure alert helpers say "renewal
# failed" and page at critical; both are false when the panel declined on
# purpose. `ssl-correctness` pins the failure helpers' counts for exactly this
# reason, with a comment saying so. These arms pin the other end.
eq "D4 each loop has its own decline helper" \
   "$(( $(occ "$F_HEAL" "funcautoHealerSslDns01DeclinedAlert(") + $(occ "$F_SCAN" "funcsecurityScannerSslDns01DeclinedAlert(") ))" "2"
eq "D5 and its own downgrade helper" \
   "$(( $(occ "$F_HEAL" "funcautoHealerSslDns01DowngradedAlert(") + $(occ "$F_SCAN" "funcsecurityScannerSslDns01DowngradedAlert(") ))" "2"
# The decline warns; the downgrade pages. Getting these the wrong way round is
# the defect `ssl-controls` F13 exists to catch, one layer out.
F_HDECL=$(fnbody "$HEAL" "func autoHealerSslDns01DeclinedAlert(" | subjin)
F_HDOWN=$(fnbody "$HEAL" "func autoHealerSslDns01DowngradedAlert(" | subjin)
[ "$(printf '%s' "$F_HDECL" | wc -c)" -ge 200 ] && [ "$(printf '%s' "$F_HDOWN" | wc -c)" -ge 200 ] || \
  { bad "SETUP" "alert helper bodies extracted too small"; exit 1; }
has "D6 the decline is a warning" "$F_HDECL" '"warning",'
has "D7 the downgrade is critical" "$F_HDOWN" '"critical",'
hasnt "D8 and the downgrade never calls itself a failure" "$F_HDOWN" "renewalfailed"

echo "── §E  the budget is derived from the agent, not guessed"

# ⛔ The three doors disagreed: two used plain `Post` (a hard 60s cap) and the
# interactive one a 120s long post, while a wildcard DNS-01 order budgets
# ~260s inside the agent alone. Every door timed out while the agent SUCCEEDED,
# and the panel recorded a failure and wrote a cooldown row.
has "E1 one budget, named once" "$F_BSSL" "constrtSslDns01OrderTimeoutSecs=300"
# ⭐ WIDENED at s393, from "every renewal door" to EVERY DNS-01 door (the door
# that ISSUES a wildcard had been passing a bare literal 180).
# ⭐ 6 -> 7 at v2.161.0 (the scanner's Compose-stack renewal door) and 7 -> 8 at
# GAP 209 (its Docker-app door). The right-hand side is a typed literal, so a
# new door legitimately moves this arm — bumping it is the repair.
eq "E2 and every DNS-01 door spends THAT budget — issuance included" \
   "$(( $(occ "$F_BSSL" "rtSslDns01OrderTimeoutSecs") + $(occ "$F_HEAL" "rtSslDns01OrderTimeoutSecs") + $(occ "$F_SCAN" "rtSslDns01OrderTimeoutSecs") ))" "8"
# ⛔ A COUNT OF THE CONSTANT'S USES CANNOT SEE A CALLER THAT DOES NOT USE IT
# (#671). E2b asks the complementary question: EVERY long agent call in this
# file spends the shared budget. BOTH SIDES ARE DERIVED FROM THE SUBJECT, so the
# arm cannot become a tautology when the population grows (#701). A regex over
# an argument list is not a parser (#626); count the calls instead.
eq "E2b every long agent call in this file spends THAT budget" \
   "$(occ "$F_BSSL" ",rtSslDns01OrderTimeoutSecs)")" "$(occ "$F_BSSL" "PostLong(")"
# ⭐ DERIVED FROM THE AGENT'S OWN ARITHMETIC, not from a number typed here: the
# per-authorization propagation sleep, and the two poll budgets. If the agent ever
# waits longer than the panel is willing to, this goes red before a fleet does.
AGENT_SLEEP=$(printf '%s' "$F_ASSL" | $G -oE 'time\.Sleep\([0-9]+\*time\.Second\)' | $G -oE '[0-9]+' | sort -rn | head -1)
AGENT_POLL=$(printf '%s' "$F_ASSL" | $G -oE 'context\.WithTimeout\(ctx,[0-9]+\*time\.Second\)' | $G -oE '[0-9]+' | sort -rn | head -1)
[ -n "$AGENT_SLEEP" ] && [ -n "$AGENT_POLL" ] || \
  { bad "SETUP" "could not derive the agent's own waits (sleep='$AGENT_SLEEP' poll='$AGENT_POLL')"; exit 1; }
AGENT_WORST=$(( 2 * AGENT_SLEEP + 2 * AGENT_POLL ))
# ⛔ THE PANEL'S SIDE IS DERIVED TOO — comparing against a literal typed here
# cannot fail however the constant is edited ([[feedback_verifier_shares_source]]).
PANEL_BUDGET=$(printf '%s' "$F_BSSL" | $G -oE 'constrtSslDns01OrderTimeoutSecs=[0-9]+' | $G -oE '[0-9]+$' | head -1)
[ -n "$PANEL_BUDGET" ] || { bad "SETUP" "could not derive the panel's own budget"; exit 1; }
if [ "$PANEL_BUDGET" -ge "$AGENT_WORST" ]; then
  ok "E3 the panel's budget (${PANEL_BUDGET}s) covers the agent's own worst case (${AGENT_WORST}s = 2x${AGENT_SLEEP}s + 2x${AGENT_POLL}s)"
else
  bad "E3 the panel's budget covers the agent's own worst case" \
      "panel ${PANEL_BUDGET}s < agent ${AGENT_WORST}s — a DNS-01 renewal reports a false failure"
fi
# The unattended door must not fall back to the 60s `Post`.
hasnt "E4 the healer no longer spends the 60s quick budget on a certificate order" "$F_HEAL" \
    'agent.Post(ctx,"/ssl/"+domain+"/renew"'
has "E4-control the healer's renewal call is visible to the detector" "$F_HEAL" \
    'agent.PostLong(ctx,"/ssl/"+domain+"/renew",agentBody,rtSslDns01OrderTimeoutSecs)'

echo "── §F  provenance is written where it is known, and only on success"

# All five writers, so a sixth door cannot appear without a decision.
# Counted PER FILE and per value, not lumped.
eq "F1 the DNS-01 door is the only writer of 'dns-01'" \
   "$(occ "$F_BSSL" "ssl_challenge='dns-01',")" "1"
# TWO in this file: the HTTP-01 issuance door, and rtSslRecordRenewalProvenance.
eq "F1b rt_ssl.go writes 'http-01' at the door and at the recorder" \
   "$(occ "$F_BSSL" "ssl_challenge='http-01',")" "2"
eq "F1c and the auto-SSL-on-create door writes it once" \
   "$(occ "$F_SITES" "ssl_challenge='http-01',")" "1"
eq "F2 and the retiring doors CLEAR it" \
   "$(( $(occ "$F_BSSL" "ssl_challenge=NULL,") + $(occ "$F_SITES" "ssl_challenge=NULL,") ))" "2"
# ⛔ ONLY AFTER SUCCESS. A failed HTTP-01 attempt on an unrecorded row must stay
# unrecorded.
eq "F3 every door records provenance after a renewal" \
   "$(( $(occ "$F_BSSL" "rtSslRecordRenewalProvenance(") + $(occ "$F_HEAL" "rtSslRecordRenewalProvenance(") + $(occ "$F_SCAN" "rtSslRecordRenewalProvenance(") ))" "4"
F_REC=$(fnbody "$BSSL" "func rtSslRecordRenewalProvenance(" | subjin)
[ "$(printf '%s' "$F_REC" | wc -c)" -ge 500 ] || \
  { bad "SETUP" "rtSslRecordRenewalProvenance body extracted too small"; exit 1; }
# ⛔ TWO DIFFERENT QUESTIONS. "Does this renewal change what is RECORDED about
# provenance?" is true for two plans. "Did it install a certificate at the site's
# OWN directory?" is true for all THREE HTTP-01 plans. s393's first draft gated
# the path on the provenance question and left the COMMONEST population
# permanently uncorrectable.
has "F4 an HTTP-01 plan records provenance exactly when it was unrecorded" "$F_REC" \
    "caseRenewHTTP01:recordProvenance=plan.RecordChallenge"
has "F4b and the deliberate downgrade" "$F_REC" \
    "caseRenewLastResortHTTP01:recordProvenance,losing=true,&plan.Losing"
has "F4d and only DNS-01 (every other plan) writes nothing — a wildcard's path names the ZONE" "$F_REC" "default:return}"
# The downgrade leaves a durable record the operator can filter for.
has "F5 the downgrade is logged at a level the readers can count" "$F_REC" 'SystemLogLogEvent(ctx,db,"warning",'

# ⭐ s393 — THE PATH FOLLOWS THE CERTIFICATE. Every door re-renders the vhost FROM
# the stored path moments later, so the recorder must move it.
has "F6 the recorder moves the path" "$F_REC" \
    "ssl_cert_path=\$2,ssl_key_path=\$3,"
# ⛔ AND UNGATED. The path write must not sit inside the provenance branch.
case "${F_REC%%ifrecordProvenance*}" in
  *"ssl_cert_path=\$2,ssl_key_path=\$3,"*)
     ok "F6c the path write precedes the provenance branch, so every HTTP-01 plan reaches it" ;;
  *) bad "F6c the path write precedes the provenance branch" \
         "it is gated on provenance — a row already stamped http-01 keeps its stale path for ever" ;;
esac
has "F6b bound to the directory the HTTP-01 order actually wrote" "$F_REC" \
    'fmt.Sprintf("/etc/dockpanel/ssl/%s/fullchain.pem",domain)'
# ⚠ F6b is sound ONLY because `$F_REC` is a `fnbody` extraction (#672).

# ⛔ ORDER, NOT PRESENCE. Recording the path after the rebuild would leave the
# rebuild reading the stale value. Derived by splitting each subject at its
# rebuild and asking what precedes it.
records_before_rebuild() {  # $1 label  $2 subject  $3 rebuild marker
  case "$2" in
    *"$3"*)
      case "${2%%"$3"*}" in
        *"rtSslRecordRenewalProvenance("*)
          ok "F7-$1 records provenance BEFORE it re-renders the vhost" ;;
        *) bad "F7-$1 records provenance BEFORE it re-renders the vhost" \
               "the rebuild runs first, so it re-asserts the stale path" ;;
      esac ;;
    *) bad "F7-$1 subject does not contain $3" "arm is vacuous — re-scope it" ;;
  esac
}
# ⚠ `rtSslRenew` is a thin wrapper that delegates; the body that renews — and
# that the Diagnostics "Fix" button also reaches — is rtSslRenewForSite.
F_RENEW=$(fnbody "$BSSL" "func rtSslRenewForSite(" | subjin)
[ "$(printf '%s' "$F_RENEW" | wc -c)" -ge 2000 ] || \
  { bad "SETUP" "rtSslRenewForSite body extracted to $(printf '%s' "$F_RENEW" | wc -c) chars"; exit 1; }
records_before_rebuild BSSL "$F_RENEW" "rtSslRebuildVhostAfterSsl("
records_before_rebuild HEAL "$F_HEAL" "rtSitesBuildNginxBody("
records_before_rebuild SCAN "$F_SCAN" "rtSitesBuildNginxBody("

# ⛔ s393 — REVOKE RE-RENDERS THE VHOST IT JUST STRIPPED. The agent's teardown
# deletes `/etc/dockpanel/ssl/{domain}/` while the vhost still names it, and
# `nginx -t` is WHOLE-SERVER: every later site edit on the box fails and the next
# restart leaves nginx down for every tenant.
F_REV=$(fnbody "$BSSL" "func rtSslRevoke(" | subjin)
[ "$(printf '%s' "$F_REV" | wc -c)" -ge 700 ] || \
  { bad "SETUP" "rtSslRevoke body extracted to $(printf '%s' "$F_REV" | wc -c) chars"; exit 1; }
has "F8 revoke re-renders the vhost it just stripped of its certificate" "$F_REV" \
    "rtSslRebuildVhostAfterSsl(ctx,st,agent,id)"
has "F8-control the subject really is the revoke door" "$F_REV" "ssl_challenge=NULL,"
# ⛔ AND AFTER THE CLEAR. The body builder emits the certificate keys only under
# ssl_enabled, and this helper re-reads the row — so called BEFORE the clear it
# writes the HTTPS config back naming the deleted directory and is rolled back.
case "${F_REV%%rtSslRebuildVhostAfterSsl(*}" in
  *"ssl_enabled=false,"*) ok "F8b and only after the row has been cleared" ;;
  *) bad "F8b and only after the row has been cleared" \
         "the rebuild precedes the UPDATE — it re-asserts the deleted certificate and is rolled back" ;;
esac

echo "── §G  the migration cannot run before the schema it alters"

# ⛔ The migrator (sqlx-compatible, core_migrate.go) parses a migration's version
# prefix as an i64 and runs them in ASCENDING numeric order. A 13-digit prefix
# sorts BELOW every 14-digit one, so it would run before `initial.sql` —
# `ALTER TABLE sites` against a database with no `sites` table, killing every
# FRESH install while an upgrading box stays green.
BADNAME=0
for m in "$MIGDIR"/*.sql; do
  b=$(basename "$m")
  case "$b" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_*) ;;
    *) BADNAME=$((BADNAME+1)); LASTBAD="$b" ;;
  esac
done
MIGCOUNT=$(find "$MIGDIR" -maxdepth 1 -name '*.sql' | wc -l | tr -d ' ')
[ "$MIGCOUNT" -ge 100 ] || { bad "SETUP" "only $MIGCOUNT migrations found — refusing to judge"; exit 1; }
if [ "$BADNAME" -eq 0 ]; then
  ok "G1 all $MIGCOUNT migration filenames carry a 14-digit version prefix"
else
  bad "G1 every migration filename carries a 14-digit version prefix" \
      "$BADNAME do not, e.g. ${LASTBAD:-?} — the migrator would order it before the schema it alters"
fi

# ⛔ THE BACKFILL'S SOURCE. `activity_logs` is a positive historical fact written
# by the DNS-01 door itself; `ssl_cert_path` is forged by every rename.
has "G2 the backfill reads the activity log" "$F_MIG" "FROMactivity_logs"
has "G2b for the actions the DNS-01 door writes" "$F_MIG" "'site.ssl.dns01','site.ssl.wildcard'"
has "G2c and refuses a domain that is ambiguous across servers" "$F_MIG" "HAVINGcount(*)=1"
# Three-state on purpose: a NOT NULL DEFAULT FALSE would assert "not a wildcard"
# over every legacy apex wildcard — the one row this migration cannot identify.
hasnt "G3 ssl_wildcard is nullable, so 'not recorded' is representable" "$F_MIG" \
    "ssl_wildcardBOOLEANNOTNULL"
has "G3-control the column is added at all" "$F_MIG" "ADDCOLUMNIFNOTEXISTSssl_wildcardBOOLEAN"

echo "── §H  the pin harness can see the code it judges"
# H1 retired (obsolete in Go): Go keeps tests in separate _test.go files, so no production item can sit below a test module and be blinded to a prod-only extraction.

echo
echo "── dns01-renewal: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
