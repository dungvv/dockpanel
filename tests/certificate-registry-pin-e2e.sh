#!/usr/bin/env bash
# certificate-registry-pin-e2e.sh — s408 / v2.160.0 (GitHub #104)
#
# Pins the named certificate registry and the STORED TLS mode on a stack —
# the three points the reporter and the panel settled in writing, plus the
# constraint the panel found on its own:
#
#   §B  the mode is STORED and honoured on every redeploy. Every one of the
#       three bodies the panel sends the agent carries it; an edit that says
#       nothing about TLS keeps what the row says, domain included. Before this
#       an edit forwarded the request's address verbatim, so omitting it took
#       the certificate off a stack that had one — behind a year of HSTS.
#   §C  a provided certificate is refused on an agent too old to honour the
#       mode, fail-closed, by a FROZEN constant read off the agent's own answer.
#   §D  the registry's lifecycle on the panel: uniqueness asked before the
#       agent writes, delete refused while a stack still names the alias, and
#       a pair already gone from the disk not making its row immortal.
#   §E  the migration: a CHECK on the vocabulary, SET NULL and never RESTRICT,
#       the ssl_email-derived backfill, alias unique per server.
#   §F  the agent: the provided arm runs BEFORE the HTTP-first write and never
#       through the per-domain enabler; a missing or unfit certificate leaves
#       the vhost untouched; the registry root is a sibling of the per-domain
#       tree, not inside it; nothing is written before every check passes.
#   §G  the seams: one mode vocabulary across migration, backend, agent and
#       page; the link scheme no longer keyed on the address; the SPA refreshes
#       after the kept-row refusal; the agent's refusal FLAG is a boolean and
#       the panel reads the SENTENCE from the warning beside it.
#
# Pure source analysis over the Go tree (panel/go) and the frontend: no box, no
# network, no build. Pure-function behaviour (the effective mode, the refusal
# reader, the alias grammars, the frozen gate, the agent's intent parser, key
# matching) is held by the Go unit tests named where each arm was retired.
#
# ⚠ EVERY arm reads STRIPPED source. Both trees carry long comments naming the
# literals below — the mode words, the flag, the registry root. Against raw
# text half of §F and §G would be satisfied by the prose describing them.
#
# NO PIPES INTO `grep -q` — under `set -o pipefail` grep -q closes the pipe on
# its first match and the arm goes red on correct code.
#
# MUTATION-TESTED at HEAD — see the run recorded in the ship's ledger.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1 — expected '$3', got '$2'"; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 — missing: $3" ;; esac; }
hasnt() { case "$2" in *"$3"*) bad "$1 — present but must not be: $3" ;; *) ok "$1" ;; esac; }

GO=panel/go/internal
STACKS=$GO/api/rt_stacks.go
TLSC=$GO/api/rt_tls_certificates.go
BMOD=$GO/api/core_router.go
MIG=$GO/api/migrations/20260826000000_tls_certificate_registry.sql
ADA=$GO/agent/routes/docker_apps.go
ASVC=$GO/agent/services/docker_apps.go
AREG=$GO/agent/routes/ssl_registry.go
ASSL=$GO/agent/services/ssl.go
AOWN=$GO/agent/services/ownership.go
AMAIN=$GO/agent/routes/router.go
APPS=panel/frontend/src/pages/Apps.tsx
CERTS=panel/frontend/src/pages/Certificates.tsx
REG=panel/frontend/src/components/RegisteredCertificates.tsx

for f in "$STACKS" "$TLSC" "$BMOD" "$MIG" "$ADA" "$ASVC" "$AREG" "$ASSL" "$AOWN" "$AMAIN" "$APPS" "$CERTS" "$REG"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, CODE INTACT. A block comment only where one is actually
# written (line start to line end, or a whole JSX `{/* … */}`), since `/*`
# occurs inside string literals; Go/TS `//` and SQL `--` line comments blanked.
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
    s{^\s*--.*$}{}gm;
  ' "$1"
}
subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }
# Whitespace, tabs and backslashes removed, and Go's `" +` / `"` string
# continuation joined, so a literal matches however gofmt or prettier wrapped it.
flat() { printf '%s' "$1" | tr -d ' \t\n\\' | sed 's/"+"//g'; }
# Byte offset of the FIRST occurrence of $2 in $1, or -1.
pos() { local t=${1%%"$2"*}; [ "$t" = "$1" ] && echo -1 || echo "${#t}"; }
# Occurrences of the fixed string $2 in $1.
occ() { printf '%s' "$1" | /usr/bin/grep -oF -- "$2" | wc -l | tr -d ' '; }

# The body of one top-level Go func (plain or method), to its column-0 `}`.
fnbody() {
  awk -v name="$2" '
    !inside && (index($0, "func " name "(") == 1 || $0 ~ ("^func \\([^)]*\\) " name "\\(")) { inside=1; next }
    inside && /^}/ { exit }
    inside { print }
  ' <<< "$1"
}
# A body that must be at least $3 lines, or the arm cannot be trusted.
body() {
  local b; b=$(fnbody "$1" "$2"); local n; n=$(wc -l <<< "$b")
  if [ "$n" -ge "$3" ]; then ok "A-body $2 ($n lines)"; else bad "A-body $2 — extracted as $n lines, subject lost"; fi
  printf '%s' "$b"
}
# Both offsets found, and the first before the second.
before() { local a b; a=$(pos "$2" "$3"); b=$(pos "$2" "$4"); if [ "$a" -ge 0 ] && [ "$b" -ge 0 ] && [ "$a" -lt "$b" ]; then ok "$1"; else bad "$1 — offsets $a / $b"; fi; }

S=$(subj "$STACKS") || { bad "rt_stacks.go stripped to nothing"; S=""; }
T=$(subj "$TLSC") || { bad "rt_tls_certificates.go stripped to nothing"; T=""; }
BM=$(subj "$BMOD") || { bad "core_router.go stripped to nothing"; BM=""; }
MG=$(subj "$MIG") || { bad "migration stripped to nothing"; MG=""; }
D=$(subj "$ADA") || { bad "agent routes/docker_apps.go stripped to nothing"; D=""; }
DS=$(subj "$ASVC") || { bad "agent services/docker_apps.go stripped to nothing"; DS=""; }
R=$(subj "$AREG") || { bad "ssl_registry.go stripped to nothing"; R=""; }
L=$(subj "$ASSL") || { bad "agent ssl.go stripped to nothing"; L=""; }
OWN=$(subj "$AOWN") || { bad "ownership.go stripped to nothing"; OWN=""; }
AM=$(subj "$AMAIN") || { bad "agent router.go stripped to nothing"; AM=""; }
AP=$(subj "$APPS") || { bad "Apps.tsx stripped to nothing"; AP=""; }
CT=$(subj "$CERTS") || { bad "Certificates.tsx stripped to nothing"; CT=""; }
RC=$(subj "$REG") || { bad "RegisteredCertificates.tsx stripped to nothing"; RC=""; }

echo "== §A  controls: every subject is floored, and the number is printed =="
for pair in "rt_stacks.go:$S:900" "rt_tls_certificates.go:$T:450" "core_router.go:$BM:800" "migration:$MG:20" \
            "agent routes/docker_apps.go:$D:1300" "agent services/docker_apps.go:$DS:4000" "ssl_registry.go:$R:220" \
            "agent ssl.go:$L:1100" "ownership.go:$OWN:200" "agent router.go:$AM:45" "Apps.tsx:$AP:2000" \
            "Certificates.tsx:$CT:200" "RegisteredCertificates.tsx:$RC:250"; do
  name=${pair%%:*}; rest=${pair#*:}; min=${rest##*:}; text=${rest%:*}
  n=$(wc -l <<< "$text")
  if [ "$n" -ge "$min" ]; then ok "A-control $name stripped subject is $n lines"; else bad "A-control $name stripped subject is only $n lines — subject lost"; fi
done

echo "== §B  the mode is stored and honoured on every redeploy =="
FS=$(flat "$S")
has "B1 the stack select projects the stored mode" "$FS" 's.tls_mode,s.tls_certificate_id,c.aliasAStls_certificate'
eq  "B2-control rt_stacks.go sends the agent exactly three compose deploys" "$(occ "$S" '"/apps/compose/deploy"')" "3"
CRE=$(body "$S" rtStacksCreate 120); UPD=$(body "$S" rtStacksUpdate 180); RES=$(body "$S" rtStacksRestorePrevious 18)
# Scoped to the DEPLOY BODY of each func — the create/update responses in the
# same bodies spell the same keys, and a whole-body `has` was satisfied by them
# with the deploy bodies stripped (caught by mutation, s408).
for pair in "create:$CRE" "update:$UPD" "restore_previous:$RES"; do
  fn=${pair%%:*}; b=$(flat "${pair#*:}")
  db=${b#*\"/apps/compose/deploy\",map\[string\]any\{}; db=${db%%\}*}
  eq "B2-control $fn's deploy body was sliced" "$([ "${#db}" -gt 60 ] && [ "${#db}" -lt 600 ] && echo sized || echo "${#db}")" "sized"
  has "B2 $fn's deploy body carries the mode" "$db" '"tls_mode":'
  has "B2 $fn's deploy body carries the alias" "$db" '"tls_certificate":'
done
FCRE=$(flat "$CRE"); FUPD=$(flat "$UPD"); FRES=$(flat "$RES")
has "B3 create sends the address only for an ACME order" "$FCRE" '"ssl_email":tls.DeployEmail(),'
has "B3 update sends the address only for an ACME order" "$FUPD" '"ssl_email":tls.DeployEmail(),'
has "B3 restore_previous sends the address only for an ACME order" "$FRES" 'varemail*stringiftlsMode=="acme"{email=sslEmail}'
has "B3 …and that gated address is the one restore_previous sends" "$FRES" '"ssl_email":email,'
has "B4 update reads the stored mode off the row" "$FUPD" 'previousMode:=rtStacksEffectiveTlsMode(prev.TlsMode,prev.SslEmail)'
has "B4 update keeps the stored mode when the request names none" "$FUPD" 'casedomain!=nil:mode=previousMode'
has "B4 update keeps the stored domain when the request omits it" "$FUPD" 'requestedDomain:=prev.DomainifbodyDomain!=nil{requestedDomain=*bodyDomain}'
has "B4 a vacated domain resolves to no mode" "$FUPD" 'default:mode="none"'
has "B4 update keeps the stored address when the request omits it" "$FUPD" 'ifsslEmail==nil{sslEmail=prev.SslEmail}'
has "B4 update keeps the stored alias when the request omits it" "$FUPD" 'ifalias==nil{alias=prev.Alias}'
# Go's absent-vs-null: a RawMessage (empty = absent) decoded into **string.
has "B5 the update request tells absent from null for the domain" "$FS" 'Domainjson.RawMessage`json:"domain"'
has "B5 …update holds it as a pointer-to-pointer (nil = absent)" "$FUPD" 'varbodyDomain**string'
has "B5 …and decodes it only when present" "$FUPD" 'iflen(body.Domain)>0{vard*string'
PLAN=$(body "$S" rtStacksPlanTls 30); FPLAN=$(flat "$PLAN")
before "B6 rtStacksPlanTls resolves the alias before gating the agent" "$FPLAN" 'rtTlsCertificatesCertificateIdForAlias(' 'rtTlsCertificatesRequireAgentAtLeast('
before "B6 rtStacksPlanTls gates the agent before asking it about coverage" "$FPLAN" 'rtTlsCertificatesRequireAgentAtLeast(' '/covers"'
has "B6 the coverage question is the agent's, not a copy in the panel" "$FPLAN" '"/ssl/registry/"+lowered+"/covers"'
before "B7 create plans TLS before writing the row" "$FCRE" 'rtStacksPlanTls(' 'INSERTINTOdocker_stacks'
before "B7 update plans TLS before tearing anything down" "$FUPD" 'rtStacksPlanTls(' '"action":"remove"'
# B8 ssl-true-only retired: covered by TestStacksProvidedTlsRefusalReadsTheAgentAnswer (panel/go/internal/api/rt_stacks_test.go)
# B8 sentence-from-warning retired: covered by TestStacksProvidedTlsRefusalReadsTheAgentAnswer (panel/go/internal/api/rt_stacks_test.go)
has "B8 create turns a refused provided deploy into an error" "$FCRE" 'ifreason:=rtStacksProvidedTlsRefusal(deployResult);reason!=nil{'
has "B8 update turns a refused provided deploy into an error" "$FUPD" 'ifreason:=rtStacksProvidedTlsRefusal(deployResult);reason!=nil{'
# B9 retired: covered by TestStacksEffectiveTlsModePrefersTheStoredValue (panel/go/internal/api/rt_stacks_test.go)

echo "== §C  an agent too old to honour the mode is refused, fail-closed =="
FT=$(flat "$T")
# C1 retired: covered by TestTlsCertificatesProvidedTLSGateIsFrozen (panel/go/internal/api/rt_tls_certificates_test.go)
GATE=$(body "$T" rtTlsCertificatesRequireAgentAtLeast 10); FGATE=$(flat "$GATE")
has "C2 the gate reads the agent's own answer, not a column that is NULL on the local box" "$FGATE" 'agent.Get(ctx,"/health")'
has "C2 the gate compares releases, not strings" "$FGATE" 'PanelUpdateSemverKey('
has "C2 a too-old agent is a precondition failure the operator can act on" "$FGATE" 'http.StatusPreconditionFailed'
has "C3 a provided claim goes through the gate" "$FPLAN" 'rtTlsCertificatesProvidedTlsMinAgent'
TCRE=$(body "$T" rtTlsCertificatesCreate 40); FTCRE=$(flat "$TCRE")
before "C3 registering a certificate goes through the gate before the agent is asked to write" "$FTCRE" 'rtTlsCertificatesRequireAgentAtLeast(' '"/ssl/registry"'

echo "== §D  the registry's lifecycle on the panel =="
before "D1 alias uniqueness is asked BEFORE the agent writes anything" "$FTCRE" 'WHEREserver_id=$1ANDalias=$2' '"/ssl/registry"'
TREM=$(body "$T" rtTlsCertificatesRemove 25); FTREM=$(flat "$TREM")
before "D2 delete asks which stacks still name the alias before touching the agent" "$FTREM" 'rtTlsCertificatesReferencingStacks(' '"/ssl/registry/"'
before "D2 the agent's copy goes before the row" "$FTREM" '"/ssl/registry/"' 'DELETEFROMtls_certificates'
has "D2 a referenced certificate is refused with a conflict" "$FTREM" 'http.StatusConflict'
has "D2 a pair already gone from the disk does not make its row immortal" "$FTREM" 'ae.Kind==AgentErrStatus&&ae.Code==404'
TREP=$(body "$T" rtTlsCertificatesReplace 25); FTREP=$(flat "$TREP")
has "D3 a replacement must still cover every domain served under the alias" "$FTREP" '"must_cover":mustCover,'
has "D3 a replacement says so to the agent" "$FTREP" '"replace":true,'
FBM=$(flat "$BM")
eq "D4 the collection routes are registered once" "$(( $(occ "$FT" 'r.Handle("GET/api/tls-certificates",h(rtTlsCertificatesList))') + $(occ "$FT" 'r.Handle("POST/api/tls-certificates",h(rtTlsCertificatesCreate))') ))" "2"
eq "D4 the item routes are registered once" "$(( $(occ "$FT" 'r.Handle("PUT/api/tls-certificates/{id}",h(rtTlsCertificatesReplace))') + $(occ "$FT" 'r.Handle("DELETE/api/tls-certificates/{id}",h(rtTlsCertificatesRemove))') ))" "2"
# Go registers routes in the module (rtTlsCertificatesRegister) by design; the
# Rust-era "no .route( of its own" becomes: the module's registrar is wired
# into the router exactly once.
eq "D4 the module's registrar is wired into the router once" "$(occ "$FBM" 'rtTlsCertificatesRegister,')" "1"

echo "== §E  the migration =="
FMG=$(flat "$MG")
has "E1 the mode column carries the vocabulary as a CHECK" "$FMG" "tls_modeTEXTCHECK(tls_modeIN('none','acme','provided'))"
has "E2 a deleted certificate nulls the reference" "$FMG" 'tls_certificate_idUUIDREFERENCEStls_certificates(id)ONDELETESETNULL'
hasnt "E3 no RESTRICT — a blocking key is a boot that cannot happen" "$FMG" 'RESTRICT'
has "E4 the backfill derives the mode from the only signal that existed" "$FMG" "SETtls_mode=CASEWHENssl_emailISNOTNULLANDssl_email<>''THEN'acme'ELSE'none'END"
has "E4 …and only where nothing is recorded yet" "$FMG" 'WHEREtls_modeISNULL'
has "E5 an alias is unique per server" "$FMG" 'UNIQUE(server_id,alias)'
# E6 was "this migration is the newest on disk", which said what it meant only
# while nothing had landed since — it went red on the first later migration
# (v2.162.0's stack ssl_expiry) with nothing wrong. The DURABLE form of the same
# invariant is that no later migration re-declares what this suite pins above.
#
# ⛔ Reads STRIPPED sql — against raw text this arm would be satisfied, or
# falsely tripped, by a later migration's own PROSE.
# ⛔ Per STATEMENT, not per file. Flattened first, so the two-line ALTER idiom
# still matches.
# ⛔ No `producer | grep -q` — pipefail is on and grep -q SIGPIPEs the producer.
e6_redeclarations() {
  local stmts
  stmts=$(code "$1" | tr -d ' \n\\' | tr ';' '\n')
  printf '%s\n' "$stmts" | /usr/bin/grep -cE 'ALTERTABLEdocker_stacks.*(tls_mode|tls_certificate_id)|(ALTER|DROP)TABLEtls_certificates' || true
}
E6_HITS=0; E6_LATER=0
for _later in $(ls $GO/api/migrations/*.sql | sort | awk -v m="$MIG" '$0 > m'); do
  E6_LATER=$((E6_LATER+1))
  E6_HITS=$(( E6_HITS + $(e6_redeclarations "$_later") ))
done
eq "E6-control later migrations were found to scan" "$([ "$E6_LATER" -gt 0 ] && echo yes || echo none)" "yes"
eq "E6 no later migration re-declares the columns this suite pins" "$E6_HITS" "0"

echo "== §F  the agent honours the mode and keeps the registry apart =="
FD=$(flat "$D")
eq "F1 both deploy requests carry the mode (a nil pointer for an older panel)" "$(occ "$FD" 'TlsMode*string`json:"tls_mode"`')" "2"
eq "F1 both deploy requests carry the alias (a nil pointer for an older panel)" "$(occ "$FD" 'TlsCertificate*string`json:"tls_certificate"`')" "2"
FRQ=$(body "$DS" DockerAppsTlsIntentFromRequest 20); FFRQ=$(flat "$FRQ")
eq "F2-control both deploy handlers resolve their intent through the one parser" "$(occ "$FD" 'services.DockerAppsTlsIntentFromRequest(body.TlsMode,body.SslEmail,body.TlsCertificate,')" "2"
# F2 legacy-presence-rule retired: covered by TestAnOlderPanelThatSendsNoModeKeepsTheAddressRule (panel/go/internal/agent/services/docker_apps_test.go)
# F2 provided-needs-alias retired: covered by TestEachModeNeedsItsOwnField (panel/go/internal/agent/services/docker_apps_test.go)
# F2 provided-refused-through-traefik retired: covered by TestProvidedModeIsRefusedThroughTraefikBeforeAnyContainerExists (panel/go/internal/agent/services/docker_apps_test.go)
EXP=$(body "$D" dockerAppsExposeDomain 150); FEXP=$(flat "$EXP")
before "F3 the provided arm runs BEFORE the HTTP-first write" "$FEXP" 'services.SslRegistryPaths(alias)' 'siteConfig:=dockerAppsProxySiteConfig(port)'
eq "F4 the per-domain enabler is called once — by the ACME arm" "$(occ "$FEXP" 'services.SslEnableSslForSite(')" "1"
before "F4 …and only after the HTTP-first write, so the provided arm never reaches it" "$FEXP" 'siteConfig:=dockerAppsProxySiteConfig(port)' 'services.SslEnableSslForSite('
# The provided slice: from the registry lookup to the HTTP-first write.
PROV=${FEXP#*services.SslRegistryPaths(alias)}; PROV=${PROV%%siteConfig:=dockerAppsProxySiteConfig(port)*}
eq "F7-control the provided slice is non-empty" "$([ "${#PROV}" -gt 800 ] && echo big || echo "${#PROV}")" "big"
before "F5 the provided arm re-asks coverage before it writes" "$PROV" 'services.SslCertCoversDomain(string(pem),domain)' 'dockerAppsWriteVhost(domain,rendered)'
before "F6 a missing certificate refuses before anything is written" "$PROV" '"tls_refused"' 'dockerAppsWriteVhost(domain,rendered)'
eq "F7 three refusals inside the arm: missing, unfit, not reloaded" "$(occ "$PROV" 'response["tls_refused"]=true')" "3"
eq "F7 the flag is a boolean everywhere the agent sets it" "$(occ "$FD" 'response["tls_refused"]=true')" "4"
eq "F7 …and never the sentence" "$(occ "$FD" 'response["tls_refused"]=fmt')" "0"
# The parked branch binds the certificate before the reload ever runs, so the
# order is asked of the LIVE branch: from the reload onward, the refusal flag
# must come before the success key.
LIVE=${PROV#*iferr:=services.NginxReload();err!=nil\{}
eq "F8-control the live branch was sliced" "$([ "${#LIVE}" -gt 200 ] && [ "${#LIVE}" -lt "${#PROV}" ] && echo big || echo "${#LIVE}")" "big"
before "F8 a reload that fails is a refusal, not a success" "$LIVE" '"tls_refused"' 'response["ssl"]=true'
eq "F9 the parked write and the live write both report the certificate bound" "$(occ "$PROV" 'response["ssl"]=true')" "2"
has "F9 a parked write says it is parked" "$PROV" 'response["parked"]=true'
FL=$(flat "$L")
ROOT=$(printf '%s' "$FL" | /usr/bin/grep -oE 'constSslRegistryDir="[^"]+"' | head -1 | sed 's/.*="//; s/"$//')
eq "F10-control the registry root was extracted" "$([ -n "$ROOT" ] && echo yes || echo no)" "yes"
case "$ROOT" in /etc/dockpanel/ssl/*|/etc/dockpanel/ssl) bad "F10 the registry root sits INSIDE the per-domain tree ($ROOT) — every walker would call an alias a domain";; /etc/dockpanel/*) ok "F10 the registry root is a sibling under the agent's writable tree ($ROOT)";; *) bad "F10 the registry root is outside the agent's writable tree ($ROOT)";; esac
RP=$(body "$L" SslRegistryPaths 1); has "F10 registry paths are built from the root, never the per-domain tree" "$(flat "$RP")" 'SslRegistryDir'
FR=$(flat "$R")
REGB=$(body "$R" sslRegistryRegister 60); FREGB=$(flat "$REGB")
before "F11 the certificate is parsed before the key is matched" "$FREGB" 'services.SslCertMetadataOf(' 'services.SslKeyMatchesCert('
before "F11 the key is matched before coverage is asked" "$FREGB" 'services.SslKeyMatchesCert(' 'services.SslCertCoversDomain('
before "F11 coverage is asked before anything is staged" "$FREGB" 'services.SslCertCoversDomain(' 'sslRegistryStagePair('
before "F11 a taken alias is refused before anything is staged" "$FREGB" 'http.StatusConflict' 'sslRegistryStagePair('
RREM=$(body "$R" sslRegistryRemove 20); FRREM=$(flat "$RREM")
before "F12 delete asks which vhosts still name the pair before removing it" "$FRREM" 'services.OwnershipRegistryCertReferences(' 'os.RemoveAll(finalDir)'
has "F12 an absent alias is told apart from an unreadable one" "$FRREM" 'errors.Is(err,fs.ErrNotExist)'
eq "F13 the registry serves exactly three routes" "$(occ "$R" 'r.Handle(')" "3"
has "F13 …the upload" "$FR" 'r.Handle("POST/ssl/registry",sslRegistryRegister)'
has "F13 …the coverage question" "$FR" 'r.Handle("POST/ssl/registry/{alias}/covers",sslRegistryCovers)'
has "F13 …the delete" "$FR" 'r.Handle("DELETE/ssl/registry/{alias}",sslRegistryRemove)'
eq "F13 the registrar is wired into the agent router once" "$(occ "$(flat "$AM")" 'registerSslRegistry,')" "1"
# F14 retired: covered by TestAGeneratedPairMatchesAndASecondKeyDoesNot + TestKeyMatchingRefusesWhatItCannotRead (panel/go/internal/agent/services/ssl_test.go)
UNX=$(body "$D" dockerAppsUnexposeDomain 20)
hasnt "F15 the stack teardown never reaches the registry" "$(flat "$UNX")" 'SslRegistry'
# F16 retired (obsolete in Go): Go tests live in separate _test.go files, so no production item can sit below a test module.

echo "== §G  the seams =="
# One vocabulary, DERIVED from each tree — a word that drifts in one place
# turns the comparison red, and the character class admits an underscore.
V_MIG=$(printf '%s' "$FMG" | /usr/bin/grep -oE "tls_modeIN\([^)]*\)" | /usr/bin/grep -oE "'[a-z_]+'" | tr -d "'" | sort -u | tr '\n' ' ')
V_BE=$(printf '%s' "$FS" | /usr/bin/grep -oE 'varrtStacksTlsModes=\[[0-9]+\]string\{[^}]*\}' | /usr/bin/grep -oE '"[a-z_]+"' | tr -d '"' | sort -u | tr '\n' ' ')
V_AG=$(printf '%s' "$FFRQ" | /usr/bin/grep -oE 'case"[a-z_]+":' | /usr/bin/grep -oE '"[a-z_]+"' | tr -d '"' | sort -u | tr '\n' ' ')
SEL=${AP#*id=\"compose-tls-mode\"}; SEL=${SEL%%</select>*}
V_FE=$(printf '%s' "$SEL" | /usr/bin/grep -oE '<option value="[a-z_]+"' | /usr/bin/grep -oE '"[a-z_]+"' | tr -d '"' | sort -u | tr '\n' ' ')
eq "G1-control the migration's vocabulary was extracted" "$(wc -w <<< "$V_MIG" | tr -d ' ')" "3"
eq "G1 backend and migration agree on the vocabulary" "$V_BE" "$V_MIG"
eq "G1 agent and migration agree on the vocabulary" "$V_AG" "$V_MIG"
eq "G1 the page offers exactly the vocabulary" "$V_FE" "$V_MIG"
FAP=$(flat "$AP")
hasnt "G2 the stack link no longer infers its scheme from the address" "$FAP" 'stack.ssl_email?"https"'
has "G2 the stack link reads the stored mode" "$FAP" 'stack.tls_mode!=="none"?"https":"http"'
has "G3 the mode is sent as a plain word" "$FAP" 'tls_mode:composeTlsMode,'
has "G3 the alias is sent only in provided mode" "$FAP" 'composeTlsMode==="provided"?{tls_certificate:composeTlsCertificate}:{}'
hasnt "G3 the new fields do not take the null-for-empty spelling a sibling pin counts" "$FAP" 'tls_mode:composeTlsMode||null'
DEP=${FAP#*consthandleComposeDeploy=async()=>{}; DEP=${DEP%%consthandleStackAction=*}
eq "G4-control the deploy handler was sliced" "$([ "${#DEP}" -gt 400 ] && echo big || echo "${#DEP}")" "big"
has "G4 a refusal after the stack exists still refreshes the list" "$DEP" 'catch(e){loadApps();'
FCT=$(flat "$CT"); FRC=$(flat "$RC")
has "G5 the page exports its status vocabulary for the registry section" "$FCT" 'exportconstSTATUS_STYLES:Record<string,{bg:string;text:string;label:string}>={'
has "G5 the registry section reuses it rather than a second map" "$FRC" 'import{STATUS_STYLES}from"../pages/Certificates";'
has "G5 …for every row, falling back to unknown" "$FRC" 'STATUS_STYLES[row.status]||STATUS_STYLES.unknown'
eq "G5 the section is rendered once, admin-gated" "$(occ "$FCT" '{isAdmin&&<RegisteredCertificates/>}')" "1"
has "G6 the section lists the registry" "$FRC" 'api.get<RegisteredCertificate[]>("/tls-certificates")'
has "G6 …registers through it" "$FRC" 'api.post("/tls-certificates",{alias:name,certificate:certPem,private_key:keyPem})'
has "G6 …replaces through it" "$FRC" 'api.put(`/tls-certificates/${row.id}`,{certificate:replaceCert,private_key:replaceKey})'
has "G6 …and deletes through it" "$FRC" 'api.delete(`/tls-certificates/${row.id}`)'
has "G7 the page checks the alias grammar the agent enforces" "$FRC" 'ALIAS_RE=/^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;'
# G7 agent-grammar retired: covered by TestTheAliasGrammarIsADnsLabel (panel/go/internal/agent/services/ssl_test.go)
# G7 panel-grammar retired: covered by TestTlsCertificatesAliasGrammarIsADNSLabel (panel/go/internal/api/rt_tls_certificates_test.go)

echo
printf 'PASS %d  FAIL %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
