#!/usr/bin/env bash
# scheme-and-import-pin-e2e.sh — s293 / v2.51.0
#
# Pins two families of defect fixed this release. Pure source analysis over the
# Go tree (panel/go) plus the frontend: no box, no network, no build. The
# migration parsers' path behaviour is held by Go unit tests
# (panel/go/internal/agent/services/pin_scheme_and_import_test.go).
#
# They are one suite because they are one mistake made twice: the panel had two
# ends that disagreed about something each of them already knew.
#
#   §A  the SCHEME. Five places printed or fetched `https://<a user's domain>`
#       while the answer — a certificate, an ssl_email, an `ssl` flag in the very
#       response being read — was in scope. Issue #96.
#   §B  the DOCUMENT ROOT and the ARCHIVE ROOT. The migration importer wrote a
#       site's files one level above the directory its own vhost serves, and
#       resolved the archive root differently from the analyser that produced
#       the paths. Found while triaging issue #51.
#
# The arms are written against the CAPABILITY a regression must use, not the
# spelling the code happens to have today (lesson #122), and were attacked after
# they went green (lesson #125).
#
# NO PIPES INTO `grep -q`. Under `set -o pipefail` grep -q closes the pipe on its
# first match, the upstream dies of SIGPIPE (141), and pipefail reports the whole
# pipeline failed — so an arm goes red on correct code, non-deterministically.
# That bug has now shipped twice (backup-lands at s289, backup-truth at s292).
# Every arm here feeds grep a here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

APPS_UI=panel/frontend/src/pages/Apps.tsx
GO=panel/go/internal
APPS_BE=$GO/api/rt_docker_apps.go
APPS_SVC=$GO/agent/services/docker_apps.go
NGINX_SVC=$GO/agent/services/nginx.go
NGINX_ROUTE=$GO/agent/routes/nginx.go
TRAEFIK=$GO/agent/services/traefik.go
GITDEP=$GO/api/rt_git_deploys.go
SITES=$GO/api/rt_sites.go
MIG_SVC=$GO/agent/services/migration.go
MIG_ROUTE=$GO/agent/routes/migration.go
MIG_BE=$GO/api/rt_migration.go

for f in "$APPS_UI" "$APPS_BE" "$APPS_SVC" "$NGINX_SVC" "$NGINX_ROUTE" "$TRAEFIK" \
         "$GITDEP" "$SITES" "$MIG_SVC" "$MIG_ROUTE" "$MIG_BE"; do
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
# the start of a line, closing at the end of one (or as a whole `{/* … */}` JSX
# comment). A `/*` in the middle of a line is data.
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

# An arm whose subject could not be extracted must SKIP, not print a confident
# green next to a red about the same subject (lesson #122b).
subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }

has()   { grep -qE -- "$2" <<< "$1"; }
count() { grep -cE -- "$2" <<< "$1" || true; }

# The N lines following a marker — the window an arm is allowed to reason about.
win() { grep -A"${3:-20}" -E -- "$2" <<< "$1" || true; }

# A presence grep is not an arm. Every probe that beat the first draft of this
# suite kept the call in the file and made it not happen: `if false { … }`, a
# `&& false` bolted onto the condition. Same escape that beat backup-truth at
# s292 (lesson #125) — dead code satisfies a presence grep. So an arm asserts
# BOTH that the window derives its answer AND that the window is live.
# Only DEAD-CODE markers belong here (#127: when a whole class of arms fails on
# code you have already verified, the harness is wrong, not the subject).
live() {
  ! grep -qE -- '(if false|&& false|\|\| true)' <<< "$1"
}

# The body of one top-level Go func, from its `func` line to the column-0 `}`.
#
# A fixed `-A <n>` window is not a function. Probe P9 removed the directory from
# a parser's database path and the per-parser arm stayed green, because the
# 90-line window ran on into the next parser — whose line still matched.
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

echo "== §A  the scheme is derived, never assumed =="

if S=$(subj "$APPS_UI"); then
  # The link must consume a per-app boolean. Requiring the ternary INSIDE the
  # href template is what stops "compute app.ssl, then ignore it" — the shape
  # that walked through the backup suite at s292.
  if has "$S" 'href=\{`\$\{app\.ssl \? "https" : "http"\}://\$\{app\.domain\}`\}'; then
    ok "the app link picks its scheme from the app's own ssl flag"
  else
    bad "the app link no longer derives its scheme from app.ssl"
  fi
  if has "$S" 'href=\{`https://\$\{app\.'; then
    bad "an app link hardcodes https:// again"
  else
    ok "no app link hardcodes https://"
  fi
  # The opt-out has to reach the wire, not merely exist in component state.
  if has "$S" 'external_tls' && has "$S" 'externalTls'; then
    ok "the deploy form sends external_tls"
  else
    bad "the deploy form no longer sends external_tls"
  fi
  # …and it must suppress the certificate request, not sit beside it.
  if has "$S" '&& !externalTls \? \{ ssl_email'; then
    ok "ticking 'TLS terminated upstream' withholds ssl_email"
  else
    bad "ssl_email is sent even when TLS is terminated upstream"
  fi
fi

if S=$(subj "$APPS_SVC"); then
  if has "$S" 'Ssl +bool +`json:"ssl"`'; then
    ok "DeployedApp carries the served scheme"
  else
    bad "DeployedApp lost its ssl field"
  fi
  # Must be FILLED, not merely declared. A struct field defaulted to false is a
  # different bug wearing the same shape.
  if derives "$S" 'Ssl: +domain != nil && NginxDomainIsHttps\(\*domain\),'; then
    ok "the app list fills ssl by asking what the box serves"
  else
    bad "the app list no longer derives ssl from the served config"
  fi
fi

if S=$(subj "$NGINX_SVC"); then
  # The nginx answer must come from the vhost, and Traefik must be consulted
  # first — when Traefik owns a domain there is no nginx vhost to read, and
  # "no file" would otherwise be reported as "no TLS".
  W=$(fnbody "$S" NginxDomainIsHttps)
  t=$(grep -nE 'TraefikRouteIsTls\(domain\)' <<< "$W" | head -1 | cut -d: -f1)
  r=$(grep -nE 'os\.ReadFile\(' <<< "$W" | head -1 | cut -d: -f1)
  if derives "$W" 'HasPrefix\(line, "listen "\)' && derives "$W" '"443"' \
     && [ -n "$t" ] && [ -n "$r" ] && [ "$t" -lt "$r" ]; then
    ok "NginxDomainIsHttps reads Traefik first, then the nginx vhost's listen line"
  else
    bad "NginxDomainIsHttps no longer derives from the served configuration"
  fi
fi

if S=$(subj "$TRAEFIK"); then
  # One path builder, used by the writer's siblings and both readers, so a
  # rename of the mangling cannot desynchronise them.
  if has "$S" '^func traefikRouteConfigPath\(' && has "$S" '^func TraefikRouteIsTls\('; then
    ok "the Traefik route path has one builder and a TLS reader"
  else
    bad "the Traefik route path builder or its TLS reader is gone"
  fi
  # ok=false means "not proxied by Traefik" and must stay distinguishable from
  # tls=false (the Rust Option<bool>).
  if has "$S" '^func TraefikRouteIsTls\(domain string\) \(tls bool, ok bool\)'; then
    ok "TraefikRouteIsTls keeps 'not mine' distinct from 'no TLS'"
  else
    bad "TraefikRouteIsTls collapsed 'not proxied here' into 'no TLS'"
  fi
fi

if S=$(subj "$APPS_BE"); then
  if has "$S" '"https://" *\+ *(\*?j\.)?domain\b'; then
    bad "the auto-created app monitor hardcodes https again"
  else
    ok "the auto-created app monitor does not hardcode https"
  fi
  # It must read the deploy's own answer: the scheme binding is chosen from
  # hasSSL, hasSSL comes from the agent's result, and the URL interpolates it.
  W=$(win "$S" 'scheme := "http"$' 4)
  if derives "$W" 'if hasSSL \{' && derives "$W" 'scheme = "https"' \
     && has "$S" 'hasSSL, _ := jsonBool\(jsonGet\(result, "ssl"\)\)' \
     && has "$S" 'scheme\+"://"\+domain'; then
    ok "the monitor URL is built from the scheme the deploy reported"
  else
    bad "the monitor URL no longer follows the deploy's reported scheme"
  fi
  if has "$S" 'ExternalTLS bool `json:"external_tls"'; then
    ok "the deploy request can decline a certificate"
  else
    bad "DeployRequest lost external_tls"
  fi
  # Declining must actually suppress the fallback to the operator's address:
  # the email is nil unless the fallback runs inside the !ExternalTLS branch.
  W=$(win "$S" 'var deploySslEmail \*string$' 6)
  if derives "$W" 'if !body\.ExternalTLS \{' && derives "$W" 'deploySslEmail = new\(claims\.Email\)'; then
    ok "external_tls suppresses the ssl_email fallback"
  else
    bad "external_tls no longer gates the ssl_email fallback"
  fi
fi

if S=$(subj "$GITDEP"); then
  # v2.168.0: raw `ssl_email` presence stopped being the truth once
  # `provided` mode could withhold it entirely — the deploy URL takes the
  # EFFECTIVE mode, still resolved in this one place.
  W=$(fnbody "$S" rtGitDeploysDeployURL)
  if derives "$W" 'tlsMode == "acme" \|\| tlsMode == "provided"'; then
    ok "git deploys resolve their URL in one place, from the effective TLS mode"
  else
    bad "rtGitDeploysDeployURL is gone or no longer branches on the effective TLS mode"
  fi
  N=$(count "$S" '"https://" *\+ *\*?[A-Za-z.]*[Dd]omain|"https://%s"[^)]*[Dd]omain')
  if [ "$N" = "0" ]; then
    ok "no git-deploy path hardcodes https://<domain>"
  else
    bad "$N git-deploy path(s) hardcode https://<domain> again"
  fi
  # Taking the finished URL is what prevents a NEW caller reintroducing the
  # hardcode: there is no domain parameter left to build one from.
  if has "$S" '^func rtGitDeploysSetGithubStatus\(.*targetURL \*string\)'; then
    ok "rtGitDeploysSetGithubStatus takes a finished URL, not a domain"
  else
    bad "rtGitDeploysSetGithubStatus takes a domain again — a caller can hardcode the scheme"
  fi
  # Every call site must route through the resolver. In Go each caller passes a
  # *string computed ONCE (domainURL / target / githubTarget). Credit a caller
  # only if it passes one of those, AND every assignment to those names outside
  # the status function itself resolves through rtGitDeploysDeployURL — never
  # by name alone, or a future `target = &domain` would satisfy this arm while
  # reintroducing exactly the hardcoded scheme the resolver exists to prevent.
  CALLS=$(grep -E 'rtGitDeploysSetGithubStatus\(' <<< "$S" | grep -cv '^func ' || true)
  VIA=$(grep -E 'rtGitDeploysSetGithubStatus\(' <<< "$S" | grep -v '^func ' | grep -cE ', (domainURL|target|githubTarget)\)$' || true)
  OUTSIDE=$(awk '/^func rtGitDeploysSetGithubStatus\(/{skip=1} skip && /^}/{skip=0; next} !skip' <<< "$S")
  ASSIGN=$(grep -E '(^|[^A-Za-z.])(domainURL|target|githubTarget) *(:=|=[^=])' <<< "$OUTSIDE" || true)
  UNRESOLVED=$(grep -cvE '= rtGitDeploysPtr\(rtGitDeploysDeployURL\(' <<< "$ASSIGN" || true)
  [ -z "$ASSIGN" ] && UNRESOLVED=1
  if [ "$CALLS" -ge 7 ] && [ "$VIA" -eq "$CALLS" ] && [ "$UNRESOLVED" -eq 0 ]; then
    ok "all $CALLS rtGitDeploysSetGithubStatus callers resolve through rtGitDeploysDeployURL"
  else
    bad "only $VIA of $CALLS rtGitDeploysSetGithubStatus callers pass a resolved URL ($UNRESOLVED assignment(s) bypass rtGitDeploysDeployURL)"
  fi
fi

if S=$(subj "$SITES"); then
  # A domain rename must change the domain and nothing else. Rebuilding the URL
  # from a literal scheme is the defect; preserving the existing one is the fix.
  if has "$S" '"https://" *\+ *newDomain|"https://%s"[^)]*newDomain'; then
    bad "the rename path rewrites monitor URLs to https again"
  else
    ok "the rename path does not rewrite the monitor's scheme"
  fi
  if has "$S" "WHEN url LIKE 'http://%'"; then
    ok "the rename preserves whichever scheme the monitor already had"
  else
    bad "the rename no longer preserves the monitor's existing scheme"
  fi
  # NEGATIVE-CONTROL, deliberately kept. rt_sites.go's OTHER auto-monitor is
  # created disabled and is only ever enabled by the SSL-provisioning paths, so
  # its https:// is correct by construction and must NOT be "fixed". This arm
  # fails if someone deletes the enabled=FALSE that makes it correct.
  if has "$S" "'pending', FALSE, 'http'"; then
    ok "the site-creation monitor is still created disabled (its https is earned)"
  else
    bad "the site-creation monitor is no longer created disabled — its https is now a guess"
  fi
fi

echo
echo "== §B  the importer and the vhost agree on where a site lives =="

if S=$(subj "$NGINX_SVC"); then
  if has "$S" '^func NginxDocumentRootFor\('; then
    ok "there is one answer to 'which directory does nginx serve'"
  else
    bad "NginxDocumentRootFor is gone — the rule is spelled per-caller again"
  fi
  # What it answers: retired to TestPinSchemeAndImportDocumentRootFollowsTheRuntime (panel/go/internal/agent/services/pin_scheme_and_import_test.go)
  # Positive anchor for the re-spelling arms below: the detector sees the rule HERE.
  if has "$S" 'case "proxy", "node", "python":'; then
    ok "the runtime rule is spelled once, in NginxDocumentRootFor (detector positive control)"
  else
    bad "the runtime-rule detector no longer sees the rule even in NginxDocumentRootFor — the arms below are vacuous"
  fi
fi

# Both callers must ASK, rather than each re-deriving the runtime match.
for f in "$NGINX_ROUTE" "$MIG_SVC"; do
  if S=$(subj "$f"); then
    # Bound, not merely called: a discarded `_ = NginxDocumentRootFor(..)`
    # beside a hand-built path satisfies a presence grep (probe P4).
    W=$(grep -E 'NginxDocumentRootFor\(' <<< "$S" || true)
    if [ -n "$W" ] && has "$W" '[A-Za-z]+ :?= (services\.)?NginxDocumentRootFor\(' && ! has "$W" '(^|[^A-Za-z0-9])_ :?= '; then
      ok "$(basename "$f") binds its document root from NginxDocumentRootFor"
    else
      bad "$(basename "$f") derives the document root itself again"
    fi
    if has "$S" '"proxy", "node", "python"'; then
      bad "$(basename "$f") re-spells the runtime rule instead of asking"
    else
      ok "$(basename "$f") does not re-spell the runtime rule"
    fi
  fi
done

if S=$(subj "$MIG_SVC"); then
  # The analyser steps into a nested archive; both importers must step in too.
  A=$(fnbody "$S" MigrationAnalyze)
  N=0
  for fn in MigrationImportSiteFiles MigrationImportDatabase; do
    W=$(fnbody "$S" "$fn")
    derives "$W" 'extractRoot := migrationFindBackupRoot\(migrationDir \+ "-" \+ migrationID\)' && N=$((N+1))
  done
  if [ "$N" -ge 2 ] && derives "$A" 'migrationFindBackupRoot\(extractDir\)'; then
    ok "both importers resolve the archive root the way the analyser did"
  else
    bad "only $N of 2 importers resolve the archive root through migrationFindBackupRoot"
  fi
  if has "$S" 'extractRoot :?= migrationDir \+ "-" \+ migrationID$'; then
    bad "an importer rebuilds the archive root without stepping into the nest"
  else
    ok "no importer rebuilds the archive root by hand"
  fi
  # parser-doc_root-relative retired: covered by TestPinSchemeAndImportParsersEmitArchiveRelativePaths (panel/go/internal/agent/services/pin_scheme_and_import_test.go)
  # parser-no-filesystem-path retired: covered by TestPinSchemeAndImportParsersEmitArchiveRelativePaths (panel/go/internal/agent/services/pin_scheme_and_import_test.go)
  # parser-no-embedded-root retired: covered by TestPinSchemeAndImportParsersEmitArchiveRelativePaths (panel/go/internal/agent/services/pin_scheme_and_import_test.go)
  # relative_to-helper retired: covered by TestMigrationRelativeTo (panel/go/internal/agent/services/migration_test.go)
  # parser-db-carries-directory retired: covered by TestPinSchemeAndImportParsersEmitArchiveRelativePaths (panel/go/internal/agent/services/pin_scheme_and_import_test.go)
fi

if S=$(subj "$MIG_BE"); then
  # Scoped to the IMPORT body. `"runtime": runtime` also appears in the nginx
  # body a few lines up, so an unscoped grep stays green with the import body
  # empty (lesson #125: an arm satisfied by unrelated code is not an arm).
  IMPORT_BODY=$(grep -m1 -A8 -E 'importBody := map\[string\]any\{' <<< "$S" || true)
  if [ -n "$IMPORT_BODY" ] && has "$IMPORT_BODY" '"runtime": +runtime'; then
    ok "the panel tells the importer which runtime the vhost was created with"
  else
    bad "the import request no longer carries the runtime"
  fi
fi

if S=$(subj "$MIG_ROUTE"); then
  # The s288 lesson: a key the sender spells differently from the reader is a
  # silent default, not an error. Pin the reader's key name.
  if has "$S" 'runtime := migrationOr\(body, "runtime",'; then
    ok "the agent reads the same runtime key the panel sends"
  else
    bad "the agent no longer reads the runtime key the panel sends"
  fi
  if has "$S" 'services\.MigrationImportSiteFiles\(.*, runtime\)'; then
    ok "the runtime reaches MigrationImportSiteFiles"
  else
    bad "the runtime does not reach MigrationImportSiteFiles"
  fi
fi

echo
echo "──────────────────────────────────────────"
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" -eq 0 ]
