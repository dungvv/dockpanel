package services

// Per-site SFTP accounts (GH #108).
//
// Each SFTP-enabled site gets its own Linux uid/gid (allocated by the panel),
// which becomes the REAL owner of /var/www/{domain} — the actual per-tenant
// isolation. A separate jail tree /var/dockpanel-sftp/{domain} is the OpenSSH
// ChrootDirectory (root-owned, as OpenSSH requires); its content/ subdirectory
// is bind-mounted (a systemd .mount unit, not fstab) onto the real, UNMOVED
// site directory, so no nginx/PHP-FPM/WP-CLI path changes. Membership in
// SftpAccountsGroup scopes sshd's one Match block to these users.
//
// useradd/groupadd/chown/usermod run unsandboxed (systemd-run):
// /etc/passwd, shadow and group are outside the agent's ReadWritePaths.

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// SftpAccountsGroup is the shared secondary group `Match Group` scopes to.
const SftpAccountsGroup = "sftp_sites"

const sftpAccountsSshdDropin = "/etc/ssh/sshd_config.d/99-dockpanel-sftp.conf"

// SftpAccountsOwnerMarkerDir records which domain owns an allocated uid; read
// by OwnershipSftpUser before any teardown. Outside both the jail and /var/www
// so the SFTP user can never reach or edit it.
const SftpAccountsOwnerMarkerDir = "/etc/dockpanel/sftp-owners"

// SftpAccountsUsername is the Linux user for uid.
func SftpAccountsUsername(uid int32) string { return fmt.Sprintf("sftp%d", uid) }

// SftpAccountsGroupname is the per-site group for gid.
func SftpAccountsGroupname(gid int32) string { return fmt.Sprintf("sftpg%d", gid) }

func sftpAccountsJailRoot(domain string) string { return "/var/dockpanel-sftp/" + domain }

func sftpAccountsJailContentDir(domain string) string {
	return sftpAccountsJailRoot(domain) + "/content"
}

// SftpAccountsOwnerMarkerPath is the owner marker for uid.
func SftpAccountsOwnerMarkerPath(uid int32) string {
	return fmt.Sprintf("%s/%d.owner", SftpAccountsOwnerMarkerDir, uid)
}

func sftpAccountsUnsandboxed(bin string, args ...string) (safecmd.Output, error) {
	return safecmd.NewUnsandboxed(bin).Arg(args...).Output(context.Background())
}

func sftpAccountsExec(bin string, args ...string) (safecmd.Output, error) {
	return safecmd.Exec(context.Background(), bin, args...)
}

// sftpAccountsMountUnitName asks systemd-escape rather than hand-rolling its
// path escaping: a .mount unit's filename MUST match the escaped Where= path.
func sftpAccountsMountUnitName(contentDir string) (string, error) {
	out, err := sftpAccountsExec("systemd-escape", "--path", "--suffix=mount", contentDir)
	if err != nil {
		return "", fmt.Errorf("systemd-escape failed to run: %v", err)
	}
	if !out.Success() {
		return "", fmt.Errorf("systemd-escape failed: %s", nginxLossy(out.Stderr))
	}
	return strings.TrimSpace(nginxLossy(out.Stdout)), nil
}

// SftpAccountsProvision creates the shared group (once), the per-site
// user+group, the jail, the bind-mount unit, and re-owns the site's content.
// Not idempotent on the user/mount steps (the backend runs it once per site).
func SftpAccountsProvision(domain string, uid, gid int32) error {
	username, groupname := SftpAccountsUsername(uid), SftpAccountsGroupname(gid)
	siteDir := "/var/www/" + domain
	if !nginxExists(siteDir) {
		return fmt.Errorf("%s does not exist — cannot enable SFTP", siteDir)
	}

	// 1. Shared group — idempotent, "already exists" ignored.
	_, _ = sftpAccountsUnsandboxed("groupadd", SftpAccountsGroup)

	// 2. Per-site group, then the user. Genuinely new — failures are real.
	out, err := sftpAccountsUnsandboxed("groupadd", "-g", fmt.Sprint(gid), groupname)
	if err != nil {
		return fmt.Errorf("groupadd failed to run: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("groupadd %s (gid %d) failed: %s", groupname, gid, nginxLossy(out.Stderr))
	}
	jail := sftpAccountsJailRoot(domain)
	out, err = sftpAccountsUnsandboxed("useradd", "-u", fmt.Sprint(uid), "-g", groupname, "-G", SftpAccountsGroup,
		"-d", jail, "-s", "/usr/sbin/nologin", username)
	if err != nil {
		return fmt.Errorf("useradd failed to run: %v", err)
	}
	if !out.Success() {
		// Roll back the group: a half-provisioned site makes a retry's
		// groupadd fail on "already exists" and mask the real problem.
		_, _ = sftpAccountsUnsandboxed("groupdel", groupname)
		return fmt.Errorf("useradd %s (uid %d) failed: %s", username, uid, nginxLossy(out.Stderr))
	}

	// 3. Jail tree. /var/dockpanel-sftp did not exist at unit start, so
	// ProtectSystem=strict makes a plain mkdir fail EROFS (live-verified);
	// only the systemd-run escape can create it.
	contentDir := sftpAccountsJailContentDir(domain)
	out, err = sftpAccountsUnsandboxed("mkdir", "-p", contentDir)
	if err != nil {
		return fmt.Errorf("mkdir failed to run: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("Failed to create jail tree %s: %s", contentDir, nginxLossy(out.Stderr))
	}
	_, _ = sftpAccountsUnsandboxed("chown", "root:root", jail)
	_, _ = sftpAccountsUnsandboxed("chmod", "0755", jail)

	// 4. Bind-mount content/ onto the REAL, unmoved site directory.
	unitName, err := sftpAccountsMountUnitName(contentDir)
	if err != nil {
		return err
	}
	unit := fmt.Sprintf("[Unit]\nDescription=DockPanel SFTP jail content mount: %s\n\n[Mount]\nWhat=%s\nWhere=%s\nType=none\nOptions=bind\n\n[Install]\nWantedBy=multi-user.target\n",
		domain, siteDir, contentDir)
	unitPath := "/etc/systemd/system/" + unitName
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("Failed to write mount unit %s: %v", unitPath, nginxIOErr(err))
	}
	_, _ = sftpAccountsExec("systemctl", "daemon-reload")
	out, err = sftpAccountsExec("systemctl", "enable", "--now", unitName)
	if err != nil {
		return fmt.Errorf("Failed to start %s: %v", unitName, err)
	}
	if !out.Success() {
		return fmt.Errorf("Failed to start %s: %s", unitName, nginxLossy(out.Stderr))
	}

	// 5. The isolation itself: re-own the real site directory. The PHP-FPM
	// pool follows on the next vhost rebuild (pool_user/pool_group).
	owner := username + ":" + groupname
	out, err = sftpAccountsUnsandboxed("chown", "-R", owner, siteDir)
	if err != nil {
		return fmt.Errorf("chown failed to run: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("chown -R %s %s failed: %s", owner, siteDir, nginxLossy(out.Stderr))
	}

	// 6. Owner marker LAST, so a marker on disk is never a promise not kept.
	if err := os.MkdirAll(SftpAccountsOwnerMarkerDir, 0o755); err != nil {
		return fmt.Errorf("Failed to create %s: %v", SftpAccountsOwnerMarkerDir, nginxIOErr(err))
	}
	if err := os.WriteFile(SftpAccountsOwnerMarkerPath(uid), []byte("Domain="+domain+"\n"), 0o644); err != nil {
		return fmt.Errorf("Failed to write owner marker for uid %d: %v", uid, nginxIOErr(err))
	}
	if err := sftpAccountsEnsureSshdDropin(); err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("SFTP provisioned for %s: user=%s uid=%d gid=%d", domain, username, uid, gid))
	return nil
}

// SftpAccountsDeprovision tears down everything Provision created.
// lastSftpSite (decided by the backend from its DB) also removes the drop-in.
func SftpAccountsDeprovision(domain string, uid, gid int32, lastSftpSite bool) error {
	if !OwnershipSftpUser(uid, domain).MayDelete() {
		return fmt.Errorf("uid %d does not carry an owner marker naming %s — refusing to tear down "+
			"an account this agent cannot prove belongs to this site", uid, domain)
	}
	username, groupname := SftpAccountsUsername(uid), SftpAccountsGroupname(gid)
	siteDir := "/var/www/" + domain

	// 1. Detach the bind mount FIRST, so a failure leaves the account enabled
	// rather than half-disabled.
	if unitName, err := sftpAccountsMountUnitName(sftpAccountsJailContentDir(domain)); err == nil {
		unitPath := "/etc/systemd/system/" + unitName
		if nginxExists(unitPath) {
			_, _ = sftpAccountsExec("systemctl", "stop", unitName)
			_, _ = sftpAccountsExec("systemctl", "disable", unitName)
			_ = os.Remove(unitPath)
			_, _ = sftpAccountsExec("systemctl", "daemon-reload")
		}
	}

	// 2. Revert content to the shared identity every other site uses.
	if nginxExists(siteDir) {
		_, _ = sftpAccountsUnsandboxed("chown", "-R", "www-data:www-data", siteDir)
	}

	// 3. Remove the jail scaffolding (agent infrastructure, never site data).
	jail := sftpAccountsJailRoot(domain)
	out, err := sftpAccountsUnsandboxed("rm", "-rf", jail)
	if err != nil {
		slog.Warn(fmt.Sprintf("Failed to remove jail tree %s: %v", jail, err))
	} else if !out.Success() {
		slog.Warn(fmt.Sprintf("Failed to remove jail tree %s: %s", jail, nginxLossy(out.Stderr)))
	}

	// 3.5. Remove this domain's PHP-FPM pool and RELOAD before killing
	// anything: the root php-fpm master otherwise respawns workers under this
	// uid from the pool file still on disk (live-verified race with userdel).
	poolName := strings.ReplaceAll(domain, ".", "_")
	for _, v := range []string{"8.1", "8.2", "8.3", "8.4", "8.5"} {
		poolPath := fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", v, poolName)
		if !nginxExists(poolPath) {
			continue
		}
		if err := os.Remove(poolPath); err != nil {
			slog.Warn(fmt.Sprintf("Failed to remove PHP-FPM pool %s before SFTP teardown: %v", poolPath, err))
		}
		if err := NginxReloadPhpFpm(v); err != nil {
			slog.Warn(fmt.Sprintf("Failed to reload php%s-fpm before SFTP teardown: %v", v, err))
		}
	}

	// 4. Kill anything still running as this uid, THEN remove the account.
	// userdel refuses a uid with live processes; making this function clear
	// them itself removes every caller-side ordering requirement (two callers
	// were live-verified to get it wrong).
	_, _ = sftpAccountsUnsandboxed("pkill", "-9", "-u", fmt.Sprint(uid))
	time.Sleep(200 * time.Millisecond)

	// Best-effort but LOGGED: a swallowed failure let "disabled" report
	// success while the account still existed.
	out, err = sftpAccountsUnsandboxed("userdel", username)
	if err != nil {
		slog.Warn(fmt.Sprintf("userdel %s failed to run: %v", username, err))
	} else if !out.Success() {
		slog.Warn(fmt.Sprintf("userdel %s failed (account may still exist): %s", username, nginxLossy(out.Stderr)))
	}
	out, err = sftpAccountsUnsandboxed("groupdel", groupname)
	if err != nil {
		slog.Warn(fmt.Sprintf("groupdel %s failed to run: %v", groupname, err))
	} else if !out.Success() {
		slog.Warn(fmt.Sprintf("groupdel %s failed (group may still exist): %s", groupname, nginxLossy(out.Stderr)))
	}
	_ = os.Remove(SftpAccountsOwnerMarkerPath(uid))

	if lastSftpSite {
		_ = os.Remove(sftpAccountsSshdDropin)
		_ = sftpAccountsReloadSshdValidated()
	}
	slog.Info(fmt.Sprintf("SFTP deprovisioned for %s: user=%s", domain, username))
	return nil
}

// sftpAccountsCryptAlphabet is crypt(3)'s base64 alphabet.
const sftpAccountsCryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// sftpAccountsHash produces a glibc SHA-512-crypt hash. The salt is EXACTLY
// 16 crypt characters: glibc's crypt() (what PAM verifies with) truncates a
// longer salt, recomputes a different digest, and every correct password then
// fails forever (live-verified with a 22-char salt).
func sftpAccountsHash(plaintext string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	salt := []byte("$6$")
	for _, b := range raw {
		salt = append(salt, sftpAccountsCryptAlphabet[b&63])
	}
	return crypt.SHA512.New().Generate([]byte(plaintext), salt)
}

// SftpAccountsSetPassword sets domain's SFTP password. Hashed in-process and
// passed to `usermod -p`: the unsandboxed primitive has no stdin, and a hash
// (unlike plaintext) is not sensitive in argv.
func SftpAccountsSetPassword(uid int32, plaintext string) error {
	username := SftpAccountsUsername(uid)
	hash, err := sftpAccountsHash(plaintext)
	if err != nil {
		return fmt.Errorf("Failed to hash password: %v", err)
	}
	out, err := sftpAccountsUnsandboxed("usermod", "-p", hash, username)
	if err != nil {
		return fmt.Errorf("usermod failed to run: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("usermod -p failed for %s: %s", username, nginxLossy(out.Stderr))
	}
	return nil
}

// sftpAccountsEnsureSshdDropin writes the Match Group drop-in if absent, then
// validates and reloads — never the unvalidated restart path, since a
// malformed Match block would lock out SSH on reload.
func sftpAccountsEnsureSshdDropin() error {
	if nginxExists(sftpAccountsSshdDropin) {
		return nil
	}
	block := "# Managed by DockPanel — per-site SFTP jails (GH #108). Do not edit by hand;\n" +
		"# regenerated the next time a site's SFTP account is enabled/disabled.\n" +
		"Match Group " + SftpAccountsGroup + "\n" +
		"\tChrootDirectory %h\n" +
		"\tForceCommand internal-sftp\n" +
		"\tAllowTcpForwarding no\n" +
		"\tX11Forwarding no\n"
	if err := os.WriteFile(sftpAccountsSshdDropin, []byte(block), 0o644); err != nil {
		return fmt.Errorf("Failed to write %s: %v", sftpAccountsSshdDropin, nginxIOErr(err))
	}
	if err := sftpAccountsReloadSshdValidated(); err != nil {
		_ = os.Remove(sftpAccountsSshdDropin)
		return err
	}
	return nil
}

// sftpAccountsReloadSshdValidated: `sshd -t`, then reload (not restart, so
// live sessions survive). Validates only what is on disk now.
func sftpAccountsReloadSshdValidated() error {
	test, err := sftpAccountsExec("sshd", "-t")
	if err != nil {
		return fmt.Errorf("sshd -t failed to run: %v", err)
	}
	if !test.Success() {
		return fmt.Errorf("sshd config invalid after SFTP drop-in change: %s", nginxLossy(test.Stderr))
	}
	out, err := sftpAccountsExec("systemctl", "reload", "sshd")
	if err != nil {
		return fmt.Errorf("systemctl reload sshd failed to run: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("systemctl reload sshd failed: %s", nginxLossy(out.Stderr))
	}
	return nil
}
