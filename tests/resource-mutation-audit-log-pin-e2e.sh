#!/usr/bin/env bash
#
# Regression pin for the RESOURCE-MUTATION AUDIT LOG extension.
#
# WHAT THIS CLOSES. DockPanel already had two logging paths: `activity::
# log_activity(...)` (Go: ActivityLogActivity), which writes to the MUTABLE
# `activity_logs` table (no trigger stops an UPDATE/DELETE on it), and
# `security_hardening::audit_log(...)` (Go: SecurityHardeningAuditLog in
# panel/go/internal/api/svc_security_hardening.go), which writes to the IMMUTABLE `security_audit_log` table (a Postgres
# trigger blocks UPDATE/DELETE on it) plus an append-only tamper-resistant
# file. Before this change, audit_log was only ever called from auth.rs,
# security.rs, git_deploys.rs, passkeys.rs and services/auto_healer.rs — every
# OTHER destructive or privilege-sensitive action (deleting a site or server,
# promoting/demoting a reseller, resetting another user's password or 2FA,
# rotating a secret or server token, disabling SSH password auth, etc.) only
# ever reached the mutable table. DockPanel supports teams/resellers/multiple
# admins, so a compromised admin account or a malicious insider could perform
# one of those actions and then edit or delete the activity_logs row that
# recorded it, leaving zero forensic trace.
#
# THE FIX. 96 call sites across 32 route files were classified (a 7-agent
# survey over every activity::log_activity(...)/log_activity_on_server(...)
# call in the then-Rust backend's routes) as destructive, privilege-changing,
# credential-lifecycle, or infrastructure-topology mutations, and each now
# ALSO writes an immutable audit_log() entry alongside its existing
# log_activity() call — same actor, same target, same details, reusing the
# real caller IP wherever `headers: HeaderMap` could be threaded through
# (adding that parameter to 81 handlers that didn't already have it). A live
# smoke test against this box's real Postgres during development found a
# 97th site the survey's grep pattern couldn't see: auth.rs's login handler
# has a THIRD logging variant, log_activity_system(...), on the "no such
# account" branch — the one call in the whole codebase that uses it, and (per
# its own comment) "the branch that matters for detection", since credential
# stuffing and username enumeration are attempts against emails that don't
# exist. Fixed and added to this pin (§3) as its own targeted assertion,
# distinct from the sibling "wrong password for a real account" branch.
# Ship any of this without a per-site pin and a single reverted call site (or
# a severity silently downgraded from "critical" to "warning" on something
# like site.delete) is invisible until an incident review goes looking for a
# trail that was never guaranteed to survive.
#
# Ported to the Go API (panel/go/internal/api, one flat package): routes/x.rs
# became rt_x.go, and several files now route their audit calls through a
# file-local wrapper (rtSitesAuditSite, rtMailAudit, rtSecurityLogBoth, ...)
# instead of repeating the call. The counts below are therefore AUDIT SITES —
# direct SecurityHardeningAuditLog calls plus calls to a wrapper — so folding
# ten calls into one wrapper does not read as nine dropped events.
#
# Pure source analysis: no box, no network, no build, no Docker/Postgres.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

ROUTES=panel/go/internal/api
MIGRATION=panel/go/internal/api/migrations/20260324000000_security_enhancements.sql

# Strip line comments only — a block-comment stripper is what deleted 485
# lines of real code until s294; this deliberately does the narrow, safe thing.
code() { sed 's://.*$::' "$1"; }

# ── 0. Files exist ──────────────────────────────────────────────────────
FILES="api_keys auth backup_orchestrator backups cdn crons databases dns \
docker_apps extensions git_deploys iac logs mail oauth passkeys \
reseller_dashboard resellers secrets security servers settings sites ssl \
stacks staging system teams tls_certificates users webhook_gateway whmcs"

for f in $FILES; do
  [ -f "$ROUTES/rt_$f.go" ] || { echo "missing $ROUTES/rt_$f.go"; exit 1; }
done
[ -f "$MIGRATION" ] || { echo "missing $MIGRATION"; exit 1; }

# ── 1. Per-file audit-site counts — the count-based backstop ──────────
#
# Each number is the file's TOTAL audit-site count (pre-existing calls + the
# ones this change added). Dropping ANY one of the 96 new calls anywhere shows
# up here as a wrong count for its file, without needing to spell out every
# dynamic event string this file's audit trail also depends on (see §3 for the
# highest-value ones spelled out explicitly).
#
# A WRAPPER is a function whose body makes exactly one audit call and which
# takes an `action string` parameter — it forwards its caller's event, so its
# CALLERS are the audit sites and the wrapper itself is not one. Found to a
# fixpoint, so a wrapper around a wrapper (rtSecuritySSHAction →
# rtSecurityLogBoth) is seen too. Line comments are stripped first.
AUDIT_REPORT=$(python3 - "$ROUTES" <<'PY'
import glob, re, sys, collections
d = sys.argv[1]
CALL = 'SecurityHardeningAuditLog'
funcs = []
for f in sorted(glob.glob(d + '/*.go')):
    if f.endswith('_test.go'):
        continue
    cur = None
    for l in open(f).read().split('\n'):
        l = re.sub(r'//.*$', '', l)
        m = re.match(r'^func (?:\([^)]*\) )?(\w+)\(', l)
        if m:
            cur = [f.split('/')[-1], m.group(1), []]
            funcs.append(cur)
        if cur is not None:
            cur[2].append(l)
            if l == '}':
                cur = None
funcs = [(f, n, '\n'.join(b)) for f, n, b in funcs]
def calls(body, names):
    return sum(len(re.findall(r'\b' + x + r'\(', body)) for x in names)
wrappers = set()
while True:
    new = {n for f, n, b in funcs
           if n != CALL and n not in wrappers
           and calls(b.split('\n', 1)[1] if '\n' in b else '', {CALL} | wrappers) == 1
           and re.search(r'\baction\b[^()]*\bstring\b', b.split('\n', 1)[0])}
    if not new:
        break
    wrappers |= new
counts = collections.Counter()
for f, n, b in funcs:
    if n in wrappers or n == CALL:
        continue
    counts[f] += calls(b, {CALL} | wrappers)
for f, c in sorted(counts.items()):
    print(f"{f}={c}")
print("WRAPPERS=" + " ".join(sorted(wrappers)))
PY
)
# Positive control: the wrapper detector must still see the wrappers it was
# written against, or every count below silently drops their callers.
WRAPPERS=$(printf '%s\n' "$AUDIT_REPORT" | grep '^WRAPPERS=' | cut -d= -f2-)
if [ "$WRAPPERS" = "rtApiKeysLog rtMailAudit rtSecurityLogBoth rtSecuritySSHAction rtSitesAuditSite rtTlsCertificatesAudit" ]; then
  ok "the audit-wrapper detector finds the six known wrappers"
else
  bad "audit-wrapper detector: expected the six known wrappers, found: $WRAPPERS"
fi
audit_sites() { printf '%s\n' "$AUDIT_REPORT" | grep "^rt_$1.go=" | cut -d= -f2; }

check_count() {
  local file="$1" expected="$2"
  local actual
  actual=$(audit_sites "$file")
  if [ "${actual:-0}" -eq "$expected" ]; then
    ok "rt_$file.go has exactly $expected audit site(s)"
  else
    bad "rt_$file.go: expected $expected audit site(s), found ${actual:-0}"
  fi
}

check_count api_keys 3
check_count auth 11
check_count backup_orchestrator 2
check_count backups 2
check_count cdn 1
check_count crons 1
check_count databases 2
# dns: 2, not Rust's 3 — the Go record-delete audits once after the provider
# switch instead of once inside each of its two provider branches.
check_count dns 2
check_count docker_apps 4
check_count extensions 3
check_count git_deploys 2
check_count iac 1
check_count logs 1
check_count mail 7
check_count oauth 3
check_count passkeys 6
check_count reseller_dashboard 2
check_count resellers 5
check_count secrets 1
check_count security 15
check_count servers 5
check_count settings 2
check_count sites 8
check_count ssl 1
check_count stacks 1
check_count staging 2
check_count system 6
check_count teams 1
check_count tls_certificates 3
check_count users 6
check_count webhook_gateway 1
check_count whmcs 2

# ── 2. Grand total — independent of how the per-file counts above sum ──
TOTAL=0
for f in $FILES; do
  n=$(audit_sites "$f")
  TOTAL=$((TOTAL + ${n:-0}))
done
if [ "$TOTAL" -eq 112 ]; then
  ok "grand total audit sites across all 32 files is 112 (13 pre-existing + 97 from this session's own extension + 3 from the later SFTP feature's own enable/disable/reset-password credential-lifecycle events, less the dns record-delete pair the Go port audits once)"
else
  bad "grand total audit sites: expected 112, found $TOTAL"
fi

# ── 3. Targeted content checks — the highest-value / trickiest sites ───
#
# A call-count match doesn't prove the RIGHT event fired with the RIGHT
# severity — a swapped severity or a copy-pasted wrong event_type would still
# leave the count untouched. These spell out the sites where getting it wrong
# would matter most (the four "critical"-severity destructive actions) and
# the trickiest mechanical shapes (dynamic event strings, and the oauth.rs
# sites where the real caller IP was sitting right there and had to be wired
# in, not left as None).
# Each file's code is flattened ONCE into a variable (never piped into a
# boolean grep — a `producer | grep -q` under `set -o pipefail` reads a
# successful early-exit match as a failure the moment grep stops reading
# before the producer finishes writing, the exact SIGPIPE-false-negative
# class this project's own pipefail-sigpipe-pin-e2e.sh exists to catch).
# Whitespace is stripped from both the haystack and every needle below so
# formatting (single-line vs multi-line calls) can't cause a false miss.
SITES_FLAT=$(printf '%s' "$(code "$ROUTES/rt_sites.go")" | tr -d ' \t\n')
SERVERS_FLAT=$(printf '%s' "$(code "$ROUTES/rt_servers.go")" | tr -d ' \t\n')
USERS_FLAT=$(printf '%s' "$(code "$ROUTES/rt_users.go")" | tr -d ' \t\n')
DNS_FLAT=$(printf '%s' "$(code "$ROUTES/rt_dns.go")" | tr -d ' \t\n')
AUTH_FLAT=$(printf '%s' "$(code "$ROUTES/rt_auth.go")" | tr -d ' \t\n')
OAUTH_FLAT=$(printf '%s' "$(code "$ROUTES/rt_oauth.go")" | tr -d ' \t\n')

must_contain() {
  local flat="$1" needle="$2" desc="$3"
  local flat_needle
  flat_needle=$(printf '%s' "$needle" | tr -d ' \t\n')
  case "$flat" in
    *"$flat_needle"*) ok "$desc" ;;
    *) bad "$desc — pattern not found (whitespace-insensitive): $needle" ;;
  esac
}

# The four CRITICAL-severity destructive actions — an attacker (or a script
# bug) silently downgrading one of these to "warning" is exactly the kind of
# regression a count-only check would miss.
must_contain "$SITES_FLAT" 'SecurityHardeningAuditLog(ctx, st.DB, "site.delete", &c.Email, ip, new("site"), &site.Domain, nil, nil, "critical",' "site.delete is audit-logged at severity=critical"
must_contain "$SITES_FLAT" 'details := fmt.Sprintf("%s -> %s (%s)", previousOwner, newOwner, email)' "site.transfer's details name the previous owner, the new owner and their email"
must_contain "$SITES_FLAT" 'SecurityHardeningAuditLog(ctx, st.DB, "site.transfer", &c.Email, clientIP(r), new("site"), &domain, &details, nil, "critical",' "site.transfer is audit-logged at severity=critical"
must_contain "$SERVERS_FLAT" 'SecurityHardeningAuditLog(r.Context(), st.DB, "server.delete", &c.Email, ip, rtServersPtr("server"), &s.Name, nil, nil, "critical",' "server.delete is audit-logged at severity=critical"
must_contain "$SERVERS_FLAT" 'SecurityHardeningAuditLog(r.Context(), st.DB, "server.rotate_token", &c.Email, ip, rtServersPtr("server"), nil, nil, nil, "critical",' "server.rotate_token is audit-logged at severity=critical"

# Dynamic event strings — the action isn't a literal, so the regression to
# guard against is someone "simplifying" the call to a hardcoded half of the
# branch (e.g. always "user.suspend" even on the unsuspend path).
must_contain "$USERS_FLAT" 'SecurityHardeningAuditLog(ctx, st.DB, action, &claims.Email, ip,' "user.suspend/user.unsuspend reuses the shared dynamic \`action\` variable, not a hardcoded literal"
must_contain "$SITES_FLAT" 'rtSitesAuditSite(ctx, st, c, r, "site.waf."+rtSitesWord(enabled, "enabled", "disabled"), site.Domain)' "site.waf.{enabled|disabled} is built from the toggle's own value, not a hardcoded literal"
must_contain "$DNS_FLAT" 'action := "dns.cf.setting." + setting' "dns.cf.setting.{setting} is built from the dynamic setting name"
must_contain "$DNS_FLAT" 'SecurityHardeningAuditLog(r.Context(), st.DB, action, &c.Email, ip,' "…and that dynamic name is what is audit-logged, not a hardcoded literal"

# auth.login_failed has TWO call sites (auth.rs's `login` handler branches on
# whether the email matches a real account), and both were gaps before this
# change (auth.rs already audit-logged successful "login"; neither failure
# branch was covered). A live-verification smoke test against this box's real
# Postgres during development caught the second one: the discovery survey
# grepped for `log_activity(` and `log_activity_on_server(`, and the
# non-existent-account branch calls a THIRD variant, `log_activity_system(`
# (Go: ActivityLogActivitySystem), which was never in scope — so the
# mechanical `audit_log()` pass silently skipped the one call this codebase's
# own comment calls "the branch that matters for detection": credential
# stuffing and username enumeration are, by definition, attempts against
# emails that do not exist, so a login-audit surface fed only by the
# wrong-password-for-a-real-account branch would look complete while missing
# the actual attack signal.
must_contain "$AUTH_FLAT" 'SecurityHardeningAuditLog(ctx, st.DB, "auth.login_failed", &user.Email, &ip,' "auth.login_failed (wrong password, real account) is audit-logged"
must_contain "$AUTH_FLAT" 'SecurityHardeningAuditLog(ctx, st.DB, "auth.login_failed", &body.Email, &ip, nil, nil, new("unknown_user"), nil, "warning",' "auth.login_failed (no such account — the actual enumeration/credential-stuffing signal) is audit-logged"

# oauth.rs (now rt_oauth.go) — all three call sites originally logged
# ip_address/actor_ip as a literal `None` even though the caller IP was
# available in scope for the session-row insert a few lines away. Left as
# nil, every OAuth audit entry would be forensically useless for IP-based
# investigation.
must_contain "$OAUTH_FLAT" 'ip := clientIP(r)' "the OAuth callback computes the real caller IP once, up front"
must_contain "$OAUTH_FLAT" 'ActivityLogActivity(ctx, st.DB, user.ID, user.Email, "auth.oauth_link", new("user"), &name, nil, ip, nil)
			SecurityHardeningAuditLog(ctx, st.DB, "auth.oauth_link", &user.Email, ip,' "auth.oauth_link captures the real caller IP, not nil"
must_contain "$OAUTH_FLAT" 'ActivityLogActivity(ctx, st.DB, nu.ID, nu.Email, "auth.oauth_register", new("user"), &name, nil, ip, nil)
		SecurityHardeningAuditLog(ctx, st.DB, "auth.oauth_register", &nu.Email, ip,' "auth.oauth_register captures the real caller IP, not nil"
must_contain "$OAUTH_FLAT" 'ActivityLogActivity(ctx, st.DB, user.ID, user.Email, "auth.oauth_login", new("user"), &name, nil, realIP, nil)
	SecurityHardeningAuditLog(ctx, st.DB, "auth.oauth_login", &user.Email, realIP,' "auth.oauth_login captures the real caller IP (the same one the session row stores), not nil"

# ── 4. The immutability guarantee this whole feature depends on ────────
MIG_CODE=$(code "$MIGRATION" | tr -d '\n')
case "$MIG_CODE" in
  *'CREATE TRIGGER trg_immutable_audit_log    BEFORE UPDATE OR DELETE ON security_audit_log'*)
    ok "security_audit_log keeps its BEFORE UPDATE OR DELETE immutability trigger" ;;
  *)
    bad "security_audit_log's immutability trigger is missing or was weakened" ;;
esac
case "$MIG_CODE" in
  *"RAISE EXCEPTION 'Security audit log is immutable"*)
    ok "the trigger function still raises on UPDATE/DELETE rather than silently ignoring it" ;;
  *)
    bad "the trigger function no longer raises on UPDATE/DELETE" ;;
esac

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32mPASS %d  FAIL 0\033[0m\n' "$PASS"
else
  printf '\033[0;31mPASS %d  FAIL %d\033[0m\n' "$PASS" "$FAIL"
fi
exit $((FAIL > 0))
