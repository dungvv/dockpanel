#!/usr/bin/env bash
# Regression pins for this session's dockpanel-fanout run over the agent's
# services/cms.rs + routes/cms.rs (now the Go port,
# panel/go/internal/agent/{services,routes}/cms.go) — a genuine LOC-ranked
# rotation pick (never previously a PRIMARY finder/skeptic target), landed
# on after 32 higher-priority candidates were disqualified by the
# two-direction pre-selection check. 1 topic (finder/skeptic + completeness
# + setup critics).
#
#   F1  services/cms.rs::run_cmd/run_cmd_in (the shared helper every one of
#       the 5 CMS installers routes through for composer/drush/php/curl/
#       unzip) had zero kill_on_drop and zero tokio::time::timeout anywhere
#       — the established timeout-orphan class already fixed 8x elsewhere
#       in this project (docker_apps.rs/pkg.rs/database_backup.rs/
#       wp_vulnerability.rs/backups.rs/security.rs/database.rs/
#       image_scanner.rs), never swept here. Fixed: kill_on_drop(true) +
#       tokio::time::timeout on both helpers, plus ensure_composer()'s and
#       install_joomla()'s own direct curl/unzip calls.
#   F2  Off-menu, setup-critic-found: services/pkg.rs::enable_php_stream was
#       MISCITED by both finder and skeptic as an "already fixed" precedent
#       for F1 — it actually has tokio::time::timeout with ZERO
#       kill_on_drop anywhere in the file (`grep -c kill_on_drop pkg.rs` ->
#       0), because it spawns via safe_command_unsandboxed(), whose
#       UnsandboxedCommand::output()/spawn_streaming() build their own inner
#       tokio::process::Command that no caller can reach to chain
#       .kill_on_drop(true) onto. Fixed AT THE SOURCE in safe_cmd.rs (not
#       per-caller) — this closes the gap for every one of the ~48
#       safe_command_unsandboxed call sites across 8 files, not just
#       enable_php_stream, as a natural consequence of the correct fix
#       location.
#   F3  Laravel .env writer (replace_env_line, consumed by phpdotenv):
#       quoted a value only if it contained a space — never for '#', which
#       phpdotenv's EntryParser treats as an unconditional comment-start in
#       UNQUOTED_STATE (no whitespace precondition), silently truncating
#       everything after it. Fixed: unconditional double-quoting with \\ "
#       $ all escaped (a bare $ inside phpdotenv's DOUBLE_QUOTED_STATE
#       starts variable interpolation unless escaped) — verified against
#       the real vlucas/phpdotenv library (composer require), round-
#       tripping '#', space, '"', "'", '\', '$', and all of them combined
#       in one value.
#   F4  CodeIgniter .env writer (set_ci_env, CI4's OWN DotEnv.php — not
#       phpdotenv): never quoted any value at all. CI4's sanitizeValue()
#       throws an uncaught InvalidArgumentException for any unquoted value
#       containing whitespace, and per the skeptic this fires in
#       Boot::bootWeb() BEFORE CI4 installs its own exception handler — a
#       raw fatal on every request, not a graceful 500. Fixed: unconditional
#       double-quoting, but with a DIFFERENT escape set than F3 (\\ and "
#       only, deliberately leaving $ un-escaped) — CI4's own unquoting
#       regex only recognizes \\ and \" as escapes; a \$ would desync that
#       regex rather than produce a literal $. Verified against CI4's own
#       sanitizeValue()/resolveNestedVariables() source. Residual,
#       CI4-side, unfixable-from-here limitation documented in code: a
#       value containing a literal ${SOME_SET_ENV_VAR} substring still
#       interpolates, since CI4 provides no escape for it at all.
#   F5  ensure_composer() downloaded composer.phar via bare curl with zero
#       integrity check before chmod +x'ing it as the install engine for
#       4/5 CMS installers. Fixed: fetches the sha256 sidecar
#       getcomposer.org itself publishes at <url>.sha256, verifies before
#       chmod — fails closed (removes the phar) on any mismatch or fetch
#       failure.
#   F6  install_joomla() downloaded the release zip via bare curl with zero
#       integrity check. Unlike composer.phar, GitHub does not publish a
#       discrete checksum FILE for release assets — Joomla instead
#       publishes a per-package SHA-256 table inside the release notes'
#       free-text body (confirmed stable across 8 sampled releases incl.
#       betas/RCs). Fixed: switched tag-resolution from the old `curl -sI`
#       HEAD-redirect trick to GitHub's Releases JSON API (one call now
#       yields both tag_name and the checksum table), extracts the SHA-256
#       tied to the EXACT filename about to be downloaded, verifies before
#       unzip — fails closed on any parse/fetch/mismatch failure.
#   F7  install_drupal()'s db_url ("mysql://{user}:{pass}@{host}/{db}",
#       passed as one --db-url= argv to drush) had db_pass validated only
#       for newline/CR/null, and db_host had ZERO validation at all, unlike
#       every other credential field. Empirically verified against PHP's
#       actual parse_url() (which Drupal's Connection::
#       createConnectionOptionsFromUrl() feeds this through with no
#       urldecode() anywhere) that '/' and '?' break parsing outright and
#       '#' does too in the password — but silently TRUNCATES the host into
#       a URL fragment when in db_host, worse than a clean failure.
#       Percent-encoding was investigated and rejected (same parser never
#       decodes escapes, so an encoded char reaches the DB driver as a
#       literal "%23" instead of round-tripping). Fixed: reject '#' '/' '?'
#       in db_pass (added to the existing denylist), new allowlist
#       validation for db_host (previously unvalidated).
#
# Deliberately NOT touched (verified correct/out-of-scope, not re-flagged
# here):
#   - Joomla's --admin-user=/--admin-username= dual flags: confirmed by both
#     finder and skeptic against Joomla's actual setup.xml form definition
#     to be two genuinely distinct required fields, not a redundant pair.
#   - SSRF-via-registry-host in image_scanner.rs/sbom_scanner.rs
#     (completeness critic off-menu find): the SAME finding already
#     deferred in the prior session's ledger, not new — not re-fixed here.
#
# REPOINTED TO GO. kill_on_drop(true) + tokio::time::timeout is, in Go, a
# child built with safecmd.Command/Exec on a ctx from context.WithTimeout
# (exec.CommandContext SIGKILLs it at the deadline — proven by
# TestPinTimeoutOrphanKillOnDropKillsTheChild in internal/agent/safecmd). The
# .env quoting rules (F3/F4) and the db_host allow-list (F7) are pure
# functions, pinned by Go tests run here; the rest stays source-level wiring.
#
# Pure source analysis (plus `go test`); no box, no network.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Strip comment lines (Go tests live in *_test.go — no in-file test module).
code() { grep -vE '^[[:space:]]*(//|\*|/\*)' "$1"; }
has()   { [ -n "$(code "$1" | grep -F -- "$2")" ]; }
hasre() { [ -n "$(code "$1" | grep -E -- "$2")" ]; }

# One Go function's body, keyed on its LITERAL signature prefix
# ("func Name(" / "func (u *T) Name("), bounded by its column-0 `}`.
fnbody()    { code "$1" | awk -v fn="$2" 'index($0, fn) == 1 {f=1} f {print} f && /^}/ {exit}'; }
bodyhas()   { [ -n "$(fnbody "$1" "$2" | grep -F -- "$3")" ]; }
bodyhasre() { [ -n "$(fnbody "$1" "$2" | grep -E -- "$3")" ]; }

GA=panel/go/internal/agent
CMS=$GA/services/cms.go
CMS_ROUTE=$GA/routes/cms.go
PKG=$GA/services/pkg.go
SAFE_CMD=$GA/safecmd/safecmd.go

for f in "$CMS" "$CMS_ROUTE" "$PKG" "$SAFE_CMD"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

echo "── 1. F1: cmsRunCmd/cmsRunCmdIn take a timeout and kill the child at it ──"
RCI="func cmsRunCmdIn("
if bodyhas "$CMS" "$RCI" 'cmd := safecmd.Command(ctx, program, args...)'; then
  ok "cmsRunCmdIn builds its child with safecmd.Command(ctx, …) (exec.CommandContext — the Go kill_on_drop)"
else
  bad "cmsRunCmdIn no longer builds its child on the ctx — a timeout would not kill it"
fi
if bodyhas "$CMS" "$RCI" 'ctx, cancel := context.WithTimeout(context.Background(), timeout)'; then
  ok "cmsRunCmdIn derives that ctx from context.WithTimeout(…, timeout)"
else
  bad "cmsRunCmdIn has no timeout deadline"
fi
if [ "$(fnbody "$CMS" "func cmsRunCmd(" | grep -cE 'safecmd\.|exec\.')" -eq 0 ] \
   && bodyhas "$CMS" "func cmsRunCmd(" 'return cmsRunCmdIn("", program, args, timeout)'; then
  ok "cmsRunCmd delegates to cmsRunCmdIn with its timeout (no second, unguarded spawn)"
else
  bad "cmsRunCmd spawns on its own or drops the timeout — the guard in cmsRunCmdIn no longer covers it"
fi
if hasre "$CMS" '^func cmsRunCmd(In)?\([^)]*timeout time\.Duration\)'; then
  ok "both helpers REQUIRE a timeout argument (the compiler now rejects a call site without one)"
else
  bad "a run helper no longer takes a timeout argument"
fi
# Every call site passes one of the four named timeouts. Counted, so a site
# added or removed shows up. The Go port folds the four `composer
# create-project` calls into cmsCreateProject (ONE cmsRunCmd call), so the
# Rust-era 12 call sites are 9 here plus 4 cmsCreateProject callers. The
# call's timeout may sit on a continuation line, so references are counted
# over the file (const definitions and CmsEnsureComposer's two WithTimeout
# deadlines excluded).
CALL_COUNT=$(code "$CMS" | grep -E 'cmsRunCmd(In)?\(' | grep -vE '^func |return cmsRunCmdIn\("", program, args, timeout\)' | grep -c .)
CP_COUNT=$(code "$CMS" | grep -cE 'cmsCreateProject\("[a-z0-9-]+/[a-z0-9-]+", siteDir\)')
TIMEOUT_ARG_COUNT=$(code "$CMS" | grep -vE '^[[:space:]]*cms(Composer|CliInstall|Download|Quick)Timeout[[:space:]]*=|context\.WithTimeout\(' | grep -oE 'cms(Composer|CliInstall|Download|Quick)Timeout' | wc -l | tr -d ' ')
if [ "$CALL_COUNT" -eq 9 ] && [ "$CP_COUNT" -eq 4 ] && [ "$TIMEOUT_ARG_COUNT" -ge "$CALL_COUNT" ]; then
  ok "all $CALL_COUNT cmsRunCmd(In) call sites (+ $CP_COUNT cmsCreateProject callers) pass a cms*Timeout constant ($TIMEOUT_ARG_COUNT references)"
else
  bad "call-site/timeout-arg count mismatch (calls=$CALL_COUNT, expected 9; create-project callers=$CP_COUNT, expected 4; timeout-refs=$TIMEOUT_ARG_COUNT) — a call site may be missing its timeout, or one was added/removed"
fi

echo
echo "── 2. F1: CmsEnsureComposer()'s direct curl spawns are also guarded ──"
EC="func CmsEnsureComposer("
if bodyhas "$CMS" "$EC" 'safecmd.Exec(ctx, "curl"' && bodyhas "$CMS" "$EC" 'safecmd.Exec(sctx, "curl"'; then
  ok "CmsEnsureComposer runs both curl calls on a ctx (phar + sha256 sidecar)"
else
  bad "CmsEnsureComposer runs a curl without a ctx"
fi
if [ "$(fnbody "$CMS" "$EC" | grep -cE '[a-z]+, [a-z]+ := context\.WithTimeout\(context\.Background\(\), cms(Download|Quick)Timeout\)')" -ge 2 ]; then
  ok "CmsEnsureComposer gives both curl calls a context.WithTimeout deadline"
else
  bad "CmsEnsureComposer has no timeout deadline on one or both curl calls"
fi

echo
echo "── 3. F2: safecmd's Unsandboxed runner builds systemd-run on the caller's ctx centrally ──"
if bodyhas "$SAFE_CMD" "func (u *Unsandboxed) command(" 'exec.CommandContext(ctx, "systemd-run"' \
   && bodyhas "$SAFE_CMD" "func (u *Unsandboxed) Output(" 'Run(ctx, u.command(ctx, c))'; then
  ok "(*Unsandboxed).Output builds the systemd-run waiter with exec.CommandContext — one central place"
else
  bad "(*Unsandboxed).Output no longer builds systemd-run on the ctx — PkgEnablePhpStream (and every other Unsandboxed call site) regresses"
fi
if bodyhas "$SAFE_CMD" "func (u *Unsandboxed) SpawnStreaming(" 'cmd := u.command(ctx, c)'; then
  ok "(*Unsandboxed).SpawnStreaming goes through the same ctx-bound builder"
else
  bad "(*Unsandboxed).SpawnStreaming no longer uses the ctx-bound builder"
fi
# KOD_ON_UNSANDBOXED control retired (obsolete in Go): Unsandboxed exposes no
# per-call kill toggle at all, so "a call site bypasses the central fix by
# chaining its own" cannot be written.
if bodyhas "$PKG" "func PkgEnablePhpStream(" 'safecmd.NewUnsandboxed(inst.Bin())'; then
  ok "PkgEnablePhpStream still spawns via safecmd.NewUnsandboxed (control: it's the same call path the central fix protects)"
else
  bad "PkgEnablePhpStream no longer calls safecmd.NewUnsandboxed — re-check whether this pin's premise still holds"
fi

echo
echo "── 4/5. F3/F4: Laravel and CodeIgniter .env quoting (different escape sets, both unconditional) ──"
# quote_laravel_env_value escapes \ / " / $ arms retired: covered by TestPinCmsInstallerHardeningEnvQuoting (panel/go/internal/agent/services/pin_cms_installer_hardening_test.go)
# replace_env_line quotes unconditionally arm retired: covered by TestPinCmsInstallerHardeningEnvQuoting + TestCmsEnvWritersAndChecksumExtraction (services/cms_test.go)
# quote_ci4_env_value escapes \ / " and NOT $ arms retired: covered by TestPinCmsInstallerHardeningEnvQuoting
# set_ci_env quotes unconditionally arm retired: covered by TestPinCmsInstallerHardeningEnvQuoting + TestCmsEnvWritersAndChecksumExtraction
if (cd panel/go && go test ./internal/agent/services/ -count=1 \
      -run '^(TestPinCmsInstallerHardeningEnvQuoting|TestCmsEnvWritersAndChecksumExtraction)$' >/dev/null 2>&1); then
  ok "phpdotenv quoting escapes \\ \" \$; CI4 quoting escapes \\ \" but leaves \$ bare; both writers quote every value (Go tests)"
else
  bad "the .env quoting Go tests fail — the '#'-truncation, \$-interpolation or CI4 space-crash bug may be back"
fi
# Regression control: the app.baseURL call site used to pre-wrap its own
# value in single quotes BEFORE set_ci_env quoted unconditionally — if that
# wrapping came back, the value would be DOUBLE-quoted. Positive anchor first.
if ! has "$CMS" '{"app.baseURL", "https://" + domain}'; then
  bad "app.baseURL's call site is gone or reshaped — this control can no longer see it; re-scope"
elif hasre "$CMS" "app\.baseURL.*'https"; then
  bad "app.baseURL's call site still pre-wraps in single quotes — now DOUBLE-quoted by cmsSetCiEnv, producing a broken value"
else
  ok "app.baseURL's call site no longer pre-wraps in single quotes (control: no double-quoting regression)"
fi

echo
echo "── 6. F5: CmsEnsureComposer() verifies composer.phar's sha256 before chmod +x ──"
if bodyhas "$CMS" "$EC" 'url+".sha256"'; then
  ok "CmsEnsureComposer fetches the .sha256 sidecar"
else
  bad "CmsEnsureComposer no longer fetches a checksum sidecar"
fi
if bodyhas "$CMS" "$EC" 'actual, err := cmsSha256File(cmsComposer)' && bodyhas "$CMS" "func cmsSha256File(" 'sha256.Sum256(b)'; then
  ok "CmsEnsureComposer computes the downloaded phar's own sha256"
else
  bad "CmsEnsureComposer no longer computes the phar's sha256"
fi
if bodyhas "$CMS" "$EC" 'if actual != expected {'; then
  ok "CmsEnsureComposer compares actual vs. expected before proceeding"
else
  bad "CmsEnsureComposer no longer compares the computed hash against the fetched one"
fi
# Fail-closed control: the mismatch branch removes the phar, returns, and
# never reaches chmod +x.
MISMATCH_BLOCK=$(fnbody "$CMS" "$EC" | awk '/if actual != expected \{/{f=1} f{print} f && /^\t\}/{exit}')
if [ -n "$MISMATCH_BLOCK" ] && [ "$(grep -c 'chmod' <<< "$MISMATCH_BLOCK")" -eq 0 ] \
   && grep -c 'os.Remove(cmsComposer)' <<< "$MISMATCH_BLOCK" >/dev/null && grep -c 'return ' <<< "$MISMATCH_BLOCK" >/dev/null; then
  ok "the mismatch branch removes the phar and returns without chmod +x (fails closed)"
else
  bad "the mismatch branch appears to still chmod +x the phar (or no longer removes it) — would not fail closed"
fi

echo
echo "── 7. F6: CmsInstallJoomla() verifies the release zip's sha256 before unzip ──"
IJ="func CmsInstallJoomla("
if bodyhas "$CMS" "$IJ" "https://api.github.com/repos/joomla/joomla-cms/releases/latest"; then
  ok "CmsInstallJoomla resolves the release via GitHub's JSON API (not the old -sI redirect trick)"
else
  bad "CmsInstallJoomla no longer uses the GitHub Releases API"
fi
if bodyhas "$CMS" "$IJ" "cmsExtractReleaseSha256(body, zipFilename)"; then
  ok "CmsInstallJoomla extracts the published checksum for the exact zip it downloads"
else
  bad "CmsInstallJoomla no longer extracts a checksum from the release notes"
fi
# extract_release_sha256 exact-filename arm retired: covered by TestCmsEnvWritersAndChecksumExtraction (panel/go/internal/agent/services/cms_test.go — the hash must sit on the filename's own line)
JOOMLA_BODY=$(fnbody "$CMS" "$IJ")
MISMATCH_LINE=$(grep -n 'checksum mismatch' <<< "$JOOMLA_BODY" | head -1 | cut -d: -f1)
UNZIP_LINE=$(grep -n 'cmsRunCmd("unzip"' <<< "$JOOMLA_BODY" | head -1 | cut -d: -f1)
if [ -n "$MISMATCH_LINE" ] && [ -n "$UNZIP_LINE" ] && [ "$MISMATCH_LINE" -lt "$UNZIP_LINE" ]; then
  ok "the checksum-mismatch check appears BEFORE unzip in source order (fails closed)"
else
  bad "could not confirm the checksum check precedes unzip (mismatch_line=$MISMATCH_LINE, unzip_line=$UNZIP_LINE) — re-verify by hand"
fi

echo
echo "── 8. F7: routes/cms.go — db_pass rejects '#' '/' '?', db_host gets validation ──"
CI="func cmsInstall("
if bodyhas "$CMS_ROUTE" "$CI" 'strings.ContainsAny(*b.DbPass, "\n\r\x00#/?")'; then
  ok "db_pass validation rejects '#' '/' '?' in addition to newline/CR/null"
else
  bad "db_pass validation no longer rejects '#' '/' '?' — CmsInstallDrupal's db_url could break or silently misparse again"
fi
# 'a dedicated is_valid_db_host validator exists' retired: covered by TestPinCmsInstallerHardeningDbHost (panel/go/internal/agent/routes/pin_cms_installer_hardening_test.go)
if (cd panel/go && go test ./internal/agent/routes/ -count=1 -run '^TestPinCmsInstallerHardeningDbHost$' >/dev/null 2>&1); then
  ok "cmsIsValidDbHost allow-lists hostname/IP[:port] and refuses '#' '/' '?' '@' space (Go test)"
else
  bad "cmsIsValidDbHost accepts a host that would truncate or misparse drush's db_url"
fi
if bodyhas "$CMS_ROUTE" "$CI" 'if b.DbHost != nil && !cmsIsValidDbHost(*b.DbHost) {'; then
  ok "db_host is actually run through cmsIsValidDbHost() in the route body"
else
  bad "db_host is not validated via cmsIsValidDbHost() in cmsInstall"
fi
# Positive control: db_user's existing charset check is untouched.
if bodyhas "$CMS_ROUTE" "$CI" 'if b.DbUser != nil && !cmsIsValidDbIdentifier(*b.DbUser) {'; then
  ok "db_user's existing validation is untouched (control)"
else
  bad "db_user's validation appears to have changed — unintended side effect"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
