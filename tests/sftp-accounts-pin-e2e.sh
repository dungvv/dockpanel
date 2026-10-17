#!/usr/bin/env bash
# Regression pin for PER-SITE SFTP ACCOUNTS (GH #108).
#
# Real Linux system accounts, a real chroot jail, and a real sshd config
# change — the highest-blast-radius thing this codebase has ever generated on
# its own. The invariants this suite exists to protect:
#
#   - uid/gid allocation goes through a real Postgres SEQUENCE (nextval()),
#     never a MAX(sftp_uid)+1 read — the latter races under two concurrent
#     enables (both can read the same MAX before either commits)
#   - the sshd drop-in is written, validated (`sshd -t`), and RELOADED —
#     never the existing SSH-hardening code's bare `restart_sshd` with no
#     validation, which would risk locking out SSH on a bad Match block
#   - the SFTP password is never piped through stdin or handled by extending
#     the shared `UnsandboxedCommand` primitive — it's hashed in-process
#     (`sha-crypt`) and set via `usermod -p <hash>`, so the plaintext never
#     needs infrastructure this codebase doesn't already have
#   - teardown never deletes a Linux account without first proving (via the
#     owner marker) that the uid actually belongs to the domain being torn
#     down — the same fail-closed shape as every other `owned_*` check
#   - the real site directory is never moved — only bind-mounted into the
#     jail and chowned in place — so no nginx/PHP-FPM/WP-CLI/CMS-installer
#     path anywhere else in the codebase had to change
#   - the backend's `pool_user`/`pool_group` naming convention and the
#     agent's `sftp_username`/`sftp_groupname` functions that actually create
#     the accounts must produce byte-identical names — they are two separate
#     binaries, so nothing but this pin catches a drift between them
#   - no password is ever persisted anywhere in the schema
#
# Pure source analysis: no box, no network, no DB, no real Linux accounts.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Go port: sftp_accounts.rs → panel/go/internal/agent/services/sftp_accounts.go
# (SftpAccounts* / sftpAccounts*), ownership::sftp_user → OwnershipSftpUser,
# sites.rs → api/rt_sites.go (rtSitesEnableSftp/rtSitesDisableSftp/
# rtSitesRemove/rtSitesBuildNginxBody), safe_cmd.rs → agent/safecmd.
MIGRATION=panel/go/internal/api/migrations/20260908110000_sftp_accounts.sql
AGENT_SVC=panel/go/internal/agent/services/sftp_accounts.go
AGENT_ROUTE=panel/go/internal/agent/routes/sftp.go
AGENT_OWNERSHIP=panel/go/internal/agent/services/ownership.go
BACKEND=panel/go/internal/api/rt_sites.go
FRONTEND=panel/frontend/src/pages/SiteDetail.tsx
AGENT_UNIT=panel/go/internal/agent/services/dockpanel-agent.service
SAFE_CMD=panel/go/internal/agent/safecmd/safecmd.go
NGINX_SVC=panel/go/internal/agent/services/nginx.go

for f in "$MIGRATION" "$AGENT_SVC" "$AGENT_ROUTE" "$AGENT_OWNERSHIP" "$BACKEND" "$FRONTEND" "$AGENT_UNIT" "$SAFE_CMD" "$NGINX_SVC"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

# Strip line comments only — a block-comment stripper is what deleted 485
# lines of real code until s294; this deliberately does the narrow, safe thing.
code() { sed 's://.*$::' "$1"; }
flat() { code "$1" | tr -d ' \t\n'; }
# One Go function, `func Name(` through its column-0 closing brace, flattened.
fnflat() { awk -v fn="$2" 'index($0, "func " fn "(") == 1 {f=1} f {print} f && /^}/ {exit}' "$1" | sed 's://.*$::' | tr -d ' \t\n'; }

MIG_FLAT=$(flat "$MIGRATION")
SVC_FLAT=$(flat "$AGENT_SVC")
OWNERSHIP_FLAT=$(flat "$AGENT_OWNERSHIP")
BACKEND_FLAT=$(flat "$BACKEND")
SAFE_CMD_FLAT=$(flat "$SAFE_CMD")

must_contain() {
  local flat="$1" needle="$2" desc="$3"
  local flat_needle
  flat_needle=$(printf '%s' "$needle" | tr -d ' \t\n')
  case "$flat" in
    *"$flat_needle"*) ok "$desc" ;;
    *) bad "$desc — pattern not found (whitespace-insensitive): $needle" ;;
  esac
}

# Run Go tests and require each named one to PASS (not merely exist).
gotest() {
  local pkg=$1; shift
  local re out t
  re="^($(IFS='|'; echo "$*"))\$"
  if ! command -v go >/dev/null 2>&1; then bad "go toolchain not found — cannot run $*"; return; fi
  out=$(cd panel/go && go test "$pkg" -run "$re" -count=1 -v 2>&1)
  for t in "$@"; do
    if grep -q -- "--- PASS: $t " <<< "$out"; then
      ok "$t runs and passes"
    else
      bad "$t is missing or failing: $(tail -3 <<< "$out" | tr '\n' ' ')"
    fi
  done
}

echo "── A: uid/gid allocation is a real sequence, not MAX()+1 ──"
must_contain "$MIG_FLAT" 'CREATE SEQUENCE IF NOT EXISTS sftp_id_seq' \
  "migration creates a real sequence for uid/gid allocation"
must_contain "$(fnflat "$BACKEND" rtSitesEnableSftp)" "SELECT nextval('sftp_id_seq')" \
  "rtSitesEnableSftp allocates via nextval(), not a MAX(sftp_uid)+1 read"
case "$BACKEND_FLAT" in
  *'MAX(sftp_uid)'*) bad "a MAX(sftp_uid) read exists somewhere in rt_sites.go — the race this pin exists to prevent" ;;
  *'sftp_uid'*) ok "no MAX(sftp_uid) read anywhere in rt_sites.go (sftp_uid is still referenced — non-vacuous)" ;;
  *) bad "rt_sites.go never mentions sftp_uid — the absence check above is vacuous" ;;
esac

echo
echo "── B: sshd drop-in is validated before reload, never bare-restarted ──"
must_contain "$SVC_FLAT" 'func sftpAccountsReloadSshdValidated() error' \
  "a dedicated validated-reload function exists"
must_contain "$SVC_FLAT" 'sftpAccountsExec("sshd", "-t")' \
  "sshd -t runs before any reload this module triggers"
must_contain "$SVC_FLAT" 'sftpAccountsExec("systemctl", "reload", "sshd")' \
  "sshd is reloaded, not restarted (a restart would drop live SSH sessions for an unrelated change)"
case "$SVC_FLAT" in
  *[Rr]'estartSshd'*|*'"restart","sshd"'*) bad "sftp_accounts.go calls the existing no-validation restart-sshd path" ;;
  *) ok "sftp_accounts.go never calls the existing no-validation securityRestartSshd path" ;;
esac
must_contain "$SVC_FLAT" 'block := "# Managed by DockPanel' \
  "the Match block is written to its own drop-in file"
must_contain "$SVC_FLAT" '"Match Group " + SftpAccountsGroup' \
  "the sshd block scopes by the shared SftpAccountsGroup, not a per-site Match"

echo
echo "── C: password is hashed in-process, never piped as plaintext ──"
must_contain "$SVC_FLAT" 'crypt.SHA512.New().Generate([]byte(plaintext), salt)' \
  "the password is hashed via SHA-crypt (explicit salt) before ever reaching a command"
must_contain "$SVC_FLAT" 'sftpAccountsUnsandboxed("usermod", "-p", hash, username)' \
  "usermod -p receives the HASH, never the plaintext password"
case "$SVC_FLAT" in
  *'"chpasswd"'*) bad "sftp_accounts.go shells out to chpasswd — this pin assumes the hash-then-usermod path instead" ;;
  *) ok "no chpasswd call anywhere in sftp_accounts.go" ;;
esac
case "$MIG_FLAT" in
  *'sftp_password'*) bad "the migration defines a password-shaped column — none should exist, a Linux account needs no stored password to reset" ;;
  *) ok "no password column anywhere in the migration" ;;
esac

echo
echo "── C2: the salt is sized for SHA-crypt's own 16-character cap, not the generic default ──"
# Live-verified bug (fresh-VPS drive, this session): ShaCrypt::default().hash_
# password() auto-generates a salt via `password_hash`'s generic
# RECOMMENDED_SALT_LEN — 16 RAW BYTES, which base64-encodes to 22 characters.
# SHA-crypt's own spec caps the salt at 16 CHARACTERS; glibc's crypt() (what
# PAM actually calls to verify a real login) truncates an over-long salt when
# recomputing the hash, so it silently computes a DIFFERENT digest than the
# one stored. Not an error anywhere — a correct password fails to
# authenticate, forever, with nothing pointing at the cause. Confirmed on-box
# via Python's own crypt.crypt(): a hash made with the default 16-byte salt
# round-tripped as WRONG. 12 raw bytes -> exactly 16 base64 characters.
# auto-salt / 12-byte-salt / explicit-salt-API arms retired: covered by
# TestTheGeneratedSaltIsAtMostSixteenCharacters + TestAProducedHashVerifiesAgainstThePasswordThatMadeIt
# (panel/go/internal/agent/services/sftp_accounts_test.go) — they measure the
# produced salt and round-trip the hash, which is the property the Rust arms
# approximated by spelling. Executed here so a deleted test cannot pass silently.
gotest ./internal/agent/services/ TestTheGeneratedSaltIsAtMostSixteenCharacters TestAProducedHashVerifiesAgainstThePasswordThatMadeIt TestHashMatchesGlibcKnownAnswer

echo
echo "── D: teardown proves ownership before touching a real Linux account ──"
must_contain "$OWNERSHIP_FLAT" 'func OwnershipSftpUser(uid int32, domain string) OwnershipOwner' \
  "a dedicated ownership check exists for the SFTP uid resource type"
must_contain "$SVC_FLAT" 'if !OwnershipSftpUser(uid, domain).MayDelete() {' \
  "deprovision refuses to proceed unless the marker proves this uid belongs to this domain"
case "$OWNERSHIP_FLAT" in
  *'ownershipByLines(SftpAccountsOwnerMarkerPath(uid),'*) ok "the ownership check reads the SAME marker path provision() writes, not a re-derived one" ;;
  *) bad "OwnershipSftpUser does not read SftpAccountsOwnerMarkerPath — could check the wrong file" ;;
esac

echo
echo "── E: the real site directory is bind-mounted, never moved ──"
must_contain "$SVC_FLAT" 'What=%s\nWhere=%s\nType=none\nOptions=bind' \
  "the mount unit is a bind mount"
must_contain "$SVC_FLAT" 'domain, siteDir, contentDir)' \
  "the bind mount's What= targets the real, unmoved site directory"
case "$SVC_FLAT" in
  *'os.Rename('*|*'"mv"'*) bad "sftp_accounts.go renames/moves a path — the design deliberately avoids restructuring the docroot" ;;
  *) ok "sftp_accounts.go never renames/moves the site directory" ;;
esac
must_contain "$SVC_FLAT" 'sftpAccountsExec("systemd-escape", "--path", "--suffix=mount", contentDir)' \
  "the mount unit name is computed via systemd-escape, not hand-rolled path escaping"

echo
echo "── E2: /var/dockpanel-sftp creation/removal goes through the unsandboxed escape ──"
# Live-verified bug (fresh-VPS drive, this session): the agent's own systemd
# unit runs under ProtectSystem=strict, namespacing its writable set at unit
# START — /var/dockpanel-sftp is a brand-new top-level directory this feature
# creates on first use, so a plain std::fs::create_dir_all/remove_dir_all on
# it fails with a real "Read-only file system (os error 30)" the exact same
# way routes/mail.rs's VMAIL_DIR creation already documents and works around.
# ReadWritePaths listing the directory (added to dockpanel-agent.service)
# only helps on a LATER restart after it already exists once — creation and
# teardown must go through safe_command_unsandboxed regardless.
case "$SVC_FLAT" in
  *'os.MkdirAll(contentDir'*|*'os.Mkdir(contentDir'*) bad "provision() creates the jail content dir via plain os.Mkdir* — hits the live-verified EROFS bug" ;;
  *) ok "provision() does not create the jail content dir via plain os.Mkdir*" ;;
esac
must_contain "$SVC_FLAT" 'sftpAccountsUnsandboxed("mkdir", "-p", contentDir)' \
  "provision() creates the jail content dir via the unsandboxed escape"
case "$SVC_FLAT" in
  *'os.RemoveAll(jail)'*) bad "deprovision() removes the jail tree via plain os.RemoveAll — hits the same live-verified EROFS bug on teardown" ;;
  *) ok "deprovision() does not remove the jail tree via plain os.RemoveAll" ;;
esac
must_contain "$SVC_FLAT" 'sftpAccountsUnsandboxed("rm", "-rf", jail)' \
  "deprovision() removes the jail tree via the unsandboxed escape"
must_contain "$SVC_FLAT" 'safecmd.NewUnsandboxed(bin).Arg(args...)' \
  "sftpAccountsUnsandboxed really is the unsandboxed escape"
must_contain "$(flat "$AGENT_UNIT")" '-/var/dockpanel-sftp' \
  "the agent's systemd unit lists /var/dockpanel-sftp in ReadWritePaths (defense-in-depth for restarts after first use)"

echo
echo "── F: PHP-FPM pool ownership — the actual isolation, both directions ──"
must_contain "$SVC_FLAT" 'owner := username + ":" + groupname
	out, err = sftpAccountsUnsandboxed("chown", "-R", owner, siteDir)' \
  "provision() re-owns the real site directory to the new per-site identity"
must_contain "$SVC_FLAT" 'sftpAccountsUnsandboxed("chown", "-R", "www-data:www-data", siteDir)' \
  "deprovision() reverts the site directory back to www-data"
must_contain "$(fnflat "$BACKEND" rtSitesBuildNginxBody)" 'if site.SFTPEnabled && site.SFTPUID != nil && site.SFTPGID != nil {' \
  "rtSitesBuildNginxBody only sends pool_user/pool_group for SFTP-enabled sites"

echo
echo "── G: the naming convention is duplicated correctly, not merely once ──"
must_contain "$BACKEND_FLAT" 'body["pool_user"] = fmt.Sprintf("sftp%d", *site.SFTPUID)' \
  "backend's pool_user naming matches sftp{uid}"
must_contain "$SVC_FLAT" 'func SftpAccountsUsername(uid int32) string { return fmt.Sprintf("sftp%d", uid) }' \
  "agent's SftpAccountsUsername naming matches sftp{uid}"
must_contain "$BACKEND_FLAT" 'body["pool_group"] = fmt.Sprintf("sftpg%d", *site.SFTPGID)' \
  "backend's pool_group naming matches sftpg{gid}"
must_contain "$SVC_FLAT" 'func SftpAccountsGroupname(gid int32) string { return fmt.Sprintf("sftpg%d", gid) }' \
  "agent's SftpAccountsGroupname naming matches sftpg{gid}"

echo
echo "── H: PHP-FPM pool template actually takes the owner as a parameter ──"
POOL_FLAT=$(fnflat "$NGINX_SVC" NginxWritePhpPoolConfig)
must_contain "$POOL_FLAT" 'poolOwner *[2]string) error {' \
  "NginxWritePhpPoolConfig takes an optional pool owner"
must_contain "$POOL_FLAT" 'user, group := "www-data", "www-data"
	if poolOwner != nil {' \
  "the default pool owner (no SFTP) is still the shared www-data identity"

echo
echo "── I: site deletion tears down SFTP before removing the site directory ──"
DELETE_FLAT=$(fnflat "$BACKEND" rtSitesRemove)
must_contain "$DELETE_FLAT" 'if site.SFTPEnabled && site.SFTPUID != nil && site.SFTPGID != nil {' \
  "rtSitesRemove() checks for an active SFTP account"
must_contain "$DELETE_FLAT" '"/sftp/sites/"+site.Domain+"/disable"' \
  "rtSitesRemove() calls the agent's SFTP disable endpoint"

echo
echo "── I2: rtSitesDisableSftp reverts the PHP-FPM pool BEFORE tearing down the account ──"
# Live-verified bug (fresh-VPS drive, this session): userdel refuses to
# remove a uid with a running process, and the OLD PHP-FPM pool's workers
# are still alive under the SFTP uid until the pool is reverted+reloaded.
# Calling the agent's /sftp/.../disable endpoint (which runs userdel) BEFORE
# reverting the pool silently failed the account/group removal every time —
# "disabled" reported success over a half-torn-down box, with nothing in any
# log pointing at the cause until deprovision()'s userdel/groupdel calls
# were changed from fire-and-forget to logged (§I3 below).
DISABLE_FN_FLAT=$(fnflat "$BACKEND" rtSitesDisableSftp)
if [ -z "$DISABLE_FN_FLAT" ]; then
  bad "could not extract rtSitesDisableSftp() from rt_sites.go — function renamed or moved"
else
  ok "rtSitesDisableSftp() extracted (bounded on its own closing brace)"
fi
PUT_POS=$(printf '%s' "$DISABLE_FN_FLAT" | grep -bo 'agent.Put(ctx,"/nginx/sites/"+site.Domain' | head -1 | cut -d: -f1)
POST_POS=$(printf '%s' "$DISABLE_FN_FLAT" | grep -bo '"/sftp/sites/"+site.Domain+"/disable"' | head -1 | cut -d: -f1)
if [ -z "$PUT_POS" ] || [ -z "$POST_POS" ]; then
  bad "could not locate both the pool-rebuild call and the disable call inside rtSitesDisableSftp() to check their order"
elif [ "$PUT_POS" -lt "$POST_POS" ]; then
  ok "the PHP-FPM pool/vhost rebuild happens before the agent's SFTP disable call"
else
  bad "the agent's SFTP disable call (userdel) happens BEFORE the pool revert — this is the exact live-verified ordering bug (old workers still running as the doomed uid block userdel)"
fi

echo
echo "── I3: userdel/groupdel failures are logged, not silently swallowed ──"
case "$SVC_FLAT" in
  *'_,_=sftpAccountsUnsandboxed("userdel"'*) bad "deprovision() still discards the userdel result with _, _ = ... — a future ordering regression would fail silently again" ;;
  *) ok "deprovision() does not silently discard the userdel result" ;;
esac
must_contain "$SVC_FLAT" 'out, err = sftpAccountsUnsandboxed("userdel", username)
	if err != nil {
		slog.Warn(' \
  "userdel's result is checked and a failure is logged"
must_contain "$SVC_FLAT" 'out, err = sftpAccountsUnsandboxed("groupdel", groupname)
	if err != nil {
		slog.Warn(' \
  "groupdel's result is checked and a failure is logged"

echo
echo "── I4: deprovision() stops this domain's PHP-FPM pool itself — never trusts caller ordering ──"
# Live-verified the SAME bug through a SECOND, independent caller after §I2's
# fix: disable_sftp's pool-revert-then-reload unblocked userdel there, but
# site DELETION's teardown (nginx.rs::delete_site, Go: nginxRoutes.deleteSite) only ever removes the
# PHP-FPM pool CONFIG FILE — it never reloads php-fpm, so an already-running
# worker under the doomed uid is untouched by it, and userdel failed exactly
# the same way through this path with no ordering fix available to share.
#
# The FIRST fix attempt — `pkill -9 -u <uid>` right before userdel — was
# ALSO live-verified insufficient on its own: killing the workers does not
# stop the php-fpm MASTER (root, unaffected by pkill -u) from immediately
# respawning new ones per the pool config still on disk. New PIDs appeared
# between the pkill and the userdel call every time. Only removing the pool
# file and reloading stops the master from wanting workers under this
# identity at all — pkill stays as a second layer, not the fix by itself.
must_contain "$SVC_FLAT" 'poolName := strings.ReplaceAll(domain, ".", "_")' \
  "deprovision() derives this domain's PHP-FPM pool name"
must_contain "$SVC_FLAT" 'poolPath := fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", v, poolName)' \
  "deprovision() locates and removes this domain's PHP-FPM pool config directly"
must_contain "$SVC_FLAT" 'if err := NginxReloadPhpFpm(v); err != nil {' \
  "deprovision() reloads php-fpm after removing the pool config, so the master stops respawning workers under this identity"
must_contain "$SVC_FLAT" 'sftpAccountsUnsandboxed("pkill", "-9", "-u", fmt.Sprint(uid))' \
  "deprovision() also force-kills any remaining process as a second layer, before userdel"
# Both the pool removal AND the pkill must happen BEFORE userdel — a
# mutation reordering either one reproduces a live-verified bug.
DEPROVISION_FN_FLAT=$(fnflat "$AGENT_SVC" SftpAccountsDeprovision)
POOL_REMOVE_POS=$(printf '%s' "$DEPROVISION_FN_FLAT" | grep -bo 'os.Remove(poolPath)' | head -1 | cut -d: -f1)
PKILL_POS=$(printf '%s' "$DEPROVISION_FN_FLAT" | grep -bo '"pkill"' | head -1 | cut -d: -f1)
USERDEL_POS=$(printf '%s' "$DEPROVISION_FN_FLAT" | grep -bo '"userdel",' | head -1 | cut -d: -f1)
if [ -z "$POOL_REMOVE_POS" ] || [ -z "$PKILL_POS" ] || [ -z "$USERDEL_POS" ]; then
  bad "could not locate the pool removal, pkill, and userdel inside SftpAccountsDeprovision() to check their order"
elif [ "$POOL_REMOVE_POS" -lt "$USERDEL_POS" ] && [ "$PKILL_POS" -lt "$USERDEL_POS" ]; then
  ok "both the PHP-FPM pool removal and pkill run before userdel inside SftpAccountsDeprovision()"
else
  bad "userdel does not run strictly after BOTH the pool removal and pkill inside SftpAccountsDeprovision() — this ordering is what the live-verified fix depends on"
fi
echo
echo "── J: the frontend never lets an operator type their own SFTP password ──"
# Bounded on the card's own comment markers — SiteDetail.tsx is thousands of
# lines with several UNRELATED password inputs elsewhere (database, mail
# accounts), so a whole-file substring check would either miss a real bug or
# false-positive on one of those. A fixed line window would silently stop
# covering the card if a future edit made it longer or shorter.
SFTP_CARD=$(awk '/\{\/\* SFTP Access \*\/\}/{f=1} f{print} f&&/\{\/\* WAF \(ModSecurity\) \*\/\}/{exit}' "$FRONTEND")
if [ -z "$SFTP_CARD" ]; then
  bad "could not extract the SFTP Access card from SiteDetail.tsx — markers moved or were renamed"
else
  ok "SFTP Access card block extracted (bounded on its own comment markers)"
fi
CARD_FLAT=$(printf '%s' "$SFTP_CARD" | tr -d ' \t\n')
case "$CARD_FLAT" in
  *'type="password"'*) bad "the SFTP Access card has a free-text password input — passwords should only ever be server-generated" ;;
  *) ok "no free-text password input inside the SFTP Access card" ;;
esac
must_contain "$CARD_FLAT" 'sftp/reset-password' \
  "the card calls the reset-password endpoint (server-generated, never operator-typed)"
must_contain "$CARD_FLAT" 'willnotbeshownagain' \
  "the reveal-once warning is present on the SFTP password panel"

echo
echo "── K: safecmd escapes \$ for every argument through the unsandboxed escape ──"
# Live-verified bug (fresh-VPS drive, this session, first caller to ever pass
# a $-containing argument through this shared primitive): systemd-run turns
# its trailing argv into the transient unit's own ExecStart=, which systemd's
# unit-file grammar subjects to $VAR/${VAR} environment-variable expansion.
# A SHA-crypt hash ($6$salt$hash) silently lost everything from the first
# unset $6 onward — this affects EVERY current and future caller of
# safecmd.NewUnsandboxed (Rust: safe_command_unsandboxed), not just SFTP, since bcrypt/Argon2/SHA-crypt all
# use $ as their MCF field separator. Fixed once, at the shared primitive,
# not worked around per call site.
must_contain "$SAFE_CMD_FLAT" 'func escapeDollar(a string) string' \
  "a dedicated escaping function exists in safecmd.go"
must_contain "$SAFE_CMD_FLAT" 'strings.ReplaceAll(a, "$", "$$")' \
  "the escape doubles a literal \$ (systemd's own escape for it, confirmed on-box to round-trip)"
ARG_FLAT=$(awk 'index($0, "func (u *Unsandboxed) Arg(") == 1 {f=1} f {print} f && /^}/ {exit}' "$SAFE_CMD" | tr -d ' \t\n')
must_contain "$ARG_FLAT" 'u.argv = append(u.argv, escapeDollar(a))' \
  "the escape is applied automatically inside Unsandboxed.Arg() — no caller has to remember to do it"
case "$SAFE_CMD_FLAT" in
  *'u.argv=append(u.argv,a)'*|*'u.argv=append(u.argv,args...)'*)
    bad "safecmd.go still has an Arg() path that appends raw, un-escaped arguments" ;;
  *) ok "no Arg() path in safecmd.go bypasses the \$ escape" ;;
esac
gotest ./internal/agent/safecmd/ TestDollarEscaping

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32mPASS %d  FAIL 0\033[0m\n' "$PASS"
else
  printf '\033[0;31mPASS %d  FAIL %d\033[0m\n' "$PASS" "$FAIL"
fi
exit $((FAIL > 0))
