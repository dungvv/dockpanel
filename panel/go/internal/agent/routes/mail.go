package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// ── Request types ───────────────────────────────────────────────────────

type mailSyncDomain struct {
	Domain   string  `json:"domain"`
	Enabled  bool    `json:"enabled"`
	CatchAll *string `json:"catch_all"`
}

type mailSyncAccount struct {
	Email        string  `json:"email"`
	PasswordHash string  `json:"password_hash"`
	QuotaMb      int32   `json:"quota_mb"`
	Enabled      bool    `json:"enabled"`
	ForwardTo    *string `json:"forward_to"`
}

type mailSyncAlias struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type mailSyncRequest struct {
	Domains  []mailSyncDomain  `json:"domains"`
	Accounts []mailSyncAccount `json:"accounts"`
	Aliases  []mailSyncAlias   `json:"aliases"`
}

const (
	mailVmailDir              = "/var/vmail"
	mailPostfixVirtualDomains = "/etc/postfix/virtual_domains"
	mailPostfixVirtualMailbox = "/etc/postfix/virtual_mailbox_maps"
	mailPostfixVirtualAlias   = "/etc/postfix/virtual_alias_maps"
	// mailPostfixSenderLogin: which SASL login may use which envelope sender.
	// Without it any mailbox could send as any address on any other tenant's
	// hosted domain — DKIM-signed with that tenant's key.
	mailPostfixSenderLogin = "/etc/postfix/sender_login_maps"
	mailDovecotUsers       = "/etc/dovecot/users"
	mailDkimKeysDir        = "/etc/dockpanel/dkim"
	// mailOpendkimConf lives under /etc/dockpanel (in ReadWritePaths), not the
	// distro's /etc/opendkim.conf, which ProtectSystem=strict refuses; a
	// systemd drop-in points the daemon here.
	mailOpendkimConf      = "/etc/dockpanel/opendkim.conf"
	mailOpendkimDropinDir = "/etc/systemd/system/opendkim.service.d"
	// OpenDKIM's milter endpoint (OpenDKIM `Socket` syntax) and the matching
	// Postfix smtpd_milters value — a loopback port; see mailWriteOpendkimConfig.
	mailOpendkimSocket = "inet:8891@127.0.0.1"
	mailOpendkimMilter = "inet:127.0.0.1:8891"
	// mailRspamdMilter: kept beside mailOpendkimMilter so neither moves alone.
	mailRspamdMilter = "inet:127.0.0.1:11332"
	mailKeyTable     = "/etc/dockpanel/dkim/key.table"
	mailSigningTable = "/etc/dockpanel/dkim/signing.table"
	// mailRoundcubeImage is deliberately NOT :latest (see mailWebmailInstall).
	mailRoundcubeImage = "roundcube/roundcubemail:1.7.x-apache"

	mailWebmailNginxConf = "/etc/nginx/conf.d/dockpanel-panel.locations/webmail.conf"
	mailWebmailNginxDir  = "/etc/nginx/conf.d/dockpanel-panel.locations"
	mailBackupDir        = "/var/lib/dockpanel/mail-backups"

	// mailNoAuthorisedSender owns a hosted domain with no mailbox. Every login
	// is a full address, so a token with no `@` is unmatchable by construction.
	mailNoAuthorisedSender = "dockpanel-no-authorised-sender"
)

// mailPorts: a listener the firewall drops is not an install.
var mailPorts = []string{"25", "587", "465", "143", "993", "110", "995"}

func registerMail(r *Router) {
	r.Handle("GET /mail/status", mailStatus)
	r.Handle("POST /mail/install", mailInstall)
	r.Handle("POST /mail/dkim/generate", mailDkimGenerate)
	r.Handle("POST /mail/domains/configure", mailDomainConfigure)
	r.Handle("POST /mail/domains/remove", mailDomainRemove)
	r.Handle("POST /mail/sync", mailSyncConfig)
	r.Handle("GET /mail/queue", mailQueueList)
	r.Handle("POST /mail/queue/flush", mailQueueFlush)
	r.Handle("POST /mail/queue/delete", mailQueueDelete)
	r.Handle("POST /mail/rspamd/install", mailRspamdInstall)
	r.Handle("GET /mail/rspamd/status", mailRspamdStatus)
	r.Handle("POST /mail/rspamd/toggle", mailRspamdToggle)
	r.Handle("POST /mail/webmail/install", mailWebmailInstall)
	r.Handle("GET /mail/webmail/status", mailWebmailStatus)
	r.Handle("POST /mail/webmail/remove", mailWebmailRemove)
	r.Handle("POST /mail/relay/configure", mailRelayConfigure)
	r.Handle("GET /mail/relay/status", mailRelayStatus)
	r.Handle("POST /mail/relay/remove", mailRelayRemove)
	r.Handle("GET /mail/logs", mailLogs)
	r.Handle("GET /mail/storage", mailStorageUsage)
	r.Handle("POST /mail/rate-limit/set", mailRateLimitSet)
	r.Handle("GET /mail/rate-limit/status", mailRateLimitStatus)
	r.Handle("POST /mail/rate-limit/remove", mailRateLimitRemove)
	r.Handle("POST /mail/backup", mailMailboxBackup)
	r.Handle("POST /mail/restore", mailMailboxRestore)
	r.Handle("GET /mail/backups", mailMailboxBackups)
	r.Handle("POST /mail/backups/delete", mailMailboxBackupDelete)
	r.Handle("GET /mail/tls/status", mailTlsStatus)
	r.Handle("POST /mail/tls/enforce", mailTlsEnforce)
	r.Handle("POST /mail/uninstall", mailUninstall)
}

// ── small helpers ───────────────────────────────────────────────────────

func mailOk(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

func mailLossy(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

// mailReadString mirrors `read_to_string(..).unwrap_or_default()`: missing,
// unreadable or non-UTF-8 all read as "".
func mailReadString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || !utf8.Valid(b) {
		return ""
	}
	return string(b)
}

func mailExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// mailExec runs a sandboxed command with no timeout (the Rust calls had none).
func mailExec(bin string, args ...string) (safecmd.Output, error) {
	return safecmd.Exec(context.Background(), bin, args...)
}

func mailUnsandboxed(bin string, args ...string) (safecmd.Output, error) {
	return safecmd.NewUnsandboxed(bin).Arg(args...).Output(context.Background())
}

// mailSystemctlWarn runs `systemctl args...` and logs a failure (never fatal).
func mailSystemctlWarn(what string, args ...string) {
	out, err := mailExec("systemctl", args...)
	if err != nil {
		slog.Warn("Failed to execute systemctl " + strings.Join(args, " "))
		return
	}
	if !out.Success() {
		slog.Warn(fmt.Sprintf("Failed to %s: %s", what, mailLossy(out.Stderr)))
	}
}

// mailLines is Rust's `lines()`.
func mailLines(s string) []string { return services.LogsLines([]byte(s)) }

func mailIsDomainChars(s string) bool {
	for _, c := range s {
		if !isASCIIAlnum(c) && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

func mailCharsIn(s, extra string) bool {
	for _, c := range s {
		if !isASCIIAlnum(c) && !strings.ContainsRune(extra, c) {
			return false
		}
	}
	return true
}

// mailWriteFileAtomic writes path via a .tmp sibling + rename.
func mailWriteFileAtomic(path, content string) error {
	return mailWriteFileAtomicMode(path, content, 0o644)
}

// mailWriteFileAtomicMode creates the tmp file fresh with mode, so a secret
// (sasl_passwd) is never on disk world-readable, not even briefly.
func mailWriteFileAtomicMode(path, content string, mode os.FileMode) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// mailWriteDovecotUsers writes the Dovecot passwd-file 0640 root:dovecot.
//
// 0600 root:root was one notch too strict: Dovecot's auth worker drops to the
// `dovecot` user, so every login failed with "Temporary authentication
// failure" while the panel reported success. The group is set on the tmp file
// BEFORE the rename so the real path is never visible with lock-out ownership.
// No dovecot group means no Dovecot, so a failed chown does not lose the write.
func mailWriteDovecotUsers(content string) error {
	tmp := mailDovecotUsers + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o640); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o640); err != nil {
		return err
	}
	_, _ = mailExec("chown", "root:dovecot", tmp)
	return os.Rename(tmp, mailDovecotUsers)
}

// mailFilterLines drops every line for which drop is true and joins with "\n".
func mailFilterLines(content string, drop func(string) bool) string {
	kept := []string{}
	for _, l := range mailLines(content) {
		if !drop(l) {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "\n")
}

// ── Mail server status + installation ───────────────────────────────────

func mailIsServiceActive(name string) bool {
	out, err := mailExec("systemctl", "is-active", "--quiet", name)
	return err == nil && out.Success()
}

// mailIsInstalled: package presence on dpkg and rpm alike (PkgIsInstalled
// maps Debian's three Dovecot packages onto the single RPM `dovecot`).
func mailIsInstalled(pkg string) bool { return services.PkgIsInstalled(pkg) }

func mailStatus(w http.ResponseWriter, _ *http.Request) {
	postfix := mailIsServiceActive("postfix")
	dovecot := mailIsServiceActive("dovecot")
	opendkim := mailIsServiceActive("opendkim")
	postfixInstalled := mailIsInstalled("postfix")
	dovecotInstalled := mailIsInstalled("dovecot-imapd")
	opendkimInstalled := mailIsInstalled("opendkim")
	vmail := mailExists(mailVmailDir)
	schemes := mailDovecotPasswordSchemes()

	// Packages present and services up is what apt's postinst gives for free —
	// not evidence this installer ran. Ask whether the configuration the mail
	// stack depends on is on disk.
	configured := mailExists(mailOpendkimConf) && mailExists(mailDkimKeysDir+"/trusted.hosts") &&
		strings.Contains(mailReadString("/etc/postfix/main.cf"), "DockPanel mail configuration")

	// OpenDKIM counts: a milter in a restart loop still lets mail flow
	// (milter_default_action = accept) — healthy while signing nothing.
	installed := postfixInstalled && dovecotInstalled && opendkimInstalled && configured
	running := postfix && dovecot && opendkim && configured

	type m = map[string]any
	writeJSON(w, http.StatusOK, m{
		"installed":  installed,
		"running":    running,
		"configured": configured,
		"postfix":    m{"installed": postfixInstalled, "running": postfix},
		"dovecot":    m{"installed": dovecotInstalled, "running": dovecot},
		"opendkim":   m{"installed": opendkimInstalled, "running": opendkim},
		"vmail_user": vmail,
		// What THIS box's Dovecot can verify; the panel picks the hash scheme
		// from it (see mailDovecotPasswordSchemes).
		"password_schemes": schemes,
	})
}

const mailPostfixConfigTmpl = `
# DockPanel mail configuration
virtual_mailbox_domains = /etc/postfix/virtual_domains
virtual_mailbox_maps = hash:/etc/postfix/virtual_mailbox_maps
# Nothing is delivered by the local transport. mydestination defaults to
# include $myhostname, and when the panel host is also a hosted mail domain
# that default silently outranks virtual_mailbox_domains: mail for a real
# mailbox is handed to ` + "`local`" + `, which has no such Unix user, and bounces
# "unknown user". A virtual-mailbox host must claim nothing but localhost.
mydestination = localhost
virtual_alias_maps = hash:/etc/postfix/virtual_alias_maps
virtual_mailbox_base = /var/vmail
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000
virtual_transport = lmtp:unix:private/dovecot-lmtp

# SMTP authentication via Dovecot
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
# Trust only this host's own addresses (not the whole subnet) so permit_mynetworks can't let a
# same-subnet neighbour relay unauthenticated on shared-network hosts.
mynetworks_style = host
smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination

# TLS
smtpd_tls_security_level = may
smtpd_tls_auth_only = yes

# SMTP smuggling prevention (CVE-2023-51764)
smtpd_forbid_bare_newline = yes

# OpenDKIM milter
milter_protocol = 6
milter_default_action = accept
smtpd_milters = ` + mailOpendkimMilter + `
non_smtpd_milters = ` + mailOpendkimMilter + `
`

// Dovecot 2.4 (Debian 13, issue #124) needs a different mail/auth block. Two
// Debian 2.4 defaults are silent until LMTP delivers: 20-lmtp.conf's
// `auth_username_format = %{user | username | lower}` (LMTP looked up the
// bare local part and answered "user doesn't exist") — overridden back to the
// identity filter below; and `mail_inbox_path` defaulting to a /var/mail mbox
// spool LMTP cannot create — blanked so INBOX follows mail_path.
const mailDovecotV24 = `mail_driver = maildir
mail_path = /var/vmail/%{user | domain}/%{user | username}
mail_inbox_path =
mail_uid = 5000
mail_gid = 5000
first_valid_uid = 5000

# Authentication
passdb passwd-file {
  passwd_file_path = /etc/dovecot/users
}

userdb passwd-file {
  passwd_file_path = /etc/dovecot/users
  fields {
    uid:default = 5000
    gid:default = 5000
    home:default = /var/vmail/%{user | domain}/%{user | username}
  }
}

protocol lmtp {
  auth_username_format = %{user}
}
`

const mailDovecotV23 = `mail_location = maildir:/var/vmail/%d/%n
mail_uid = 5000
mail_gid = 5000
first_valid_uid = 5000

# Authentication
passdb {
  driver = passwd-file
  args = /etc/dovecot/users
}

userdb {
  driver = passwd-file
  args = /etc/dovecot/users
  default_fields = uid=5000 gid=5000 home=/var/vmail/%d/%n
}
`

const mailDovecotServices = `# LMTP for Postfix delivery
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

# SASL auth for Postfix
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

# SSL
`

func mailInstall(w http.ResponseWriter, _ *http.Request) {
	if why := services.PkgNoInstallerReason("Installing the mail server"); why != "" {
		writeErr(w, http.StatusNotImplemented, why)
		return
	}
	if why := services.PkgMailRefusalReason(); why != "" {
		writeErr(w, http.StatusNotImplemented, why)
		return
	}
	slog.Info("Starting mail server installation...")
	fail := func(msg string) { writeErr(w, http.StatusInternalServerError, msg) }

	// 1. Packages (unsandboxed inside PkgInstall so the package manager can
	// take its own locks). Debian's three Dovecot packages collapse to one on
	// RHEL via the name map.
	if err := services.PkgInstall([]string{"postfix", "dovecot-imapd", "dovecot-pop3d", "dovecot-lmtpd", "opendkim", "opendkim-tools"}); err != nil {
		// `nothing provides …` on RHEL almost always means CRB is off.
		fail("Package install failed: " + services.PkgExplainPackageFailure(err.Error()))
		return
	}

	// 2. vmail user (uid/gid 5000). groupadd/useradd write /etc/passwd etc.,
	// too sensitive for ReadWritePaths — run unsandboxed.
	_, _ = mailUnsandboxed("groupadd", "-g", "5000", "vmail")
	_, _ = mailUnsandboxed("useradd", "-g", "5000", "-u", "5000", "-d", mailVmailDir, "-s", "/usr/sbin/nologin", "-m", "vmail")
	// Created unsandboxed: the unit lists `-/var/vmail` (bound only IF IT
	// EXISTS), so an agent-side mkdir fails EROFS when it is absent.
	_, _ = mailUnsandboxed("mkdir", "-p", mailVmailDir)
	if !mailExists(mailVmailDir) {
		fail(fmt.Sprintf("Failed to create %s — mail cannot be stored", mailVmailDir))
		return
	}
	_, _ = mailUnsandboxed("chown", "-R", "vmail:vmail", mailVmailDir)
	mailLabelVmailForSelinux()

	// 3. Config directories.
	if err := os.MkdirAll(mailDkimKeysDir, 0o755); err != nil {
		fail(fmt.Sprintf("Failed to create DKIM dir: %v", err))
		return
	}
	if err := os.MkdirAll("/etc/dockpanel/mail", 0o755); err != nil {
		fail(fmt.Sprintf("Failed to create mail config dir: %v", err))
		return
	}

	// 4. Postfix main.cf block, appended once.
	mainCf := mailReadString("/etc/postfix/main.cf")
	if !strings.Contains(mainCf, "DockPanel mail configuration") {
		if err := mailWriteFileAtomic("/etc/postfix/main.cf", mainCf+"\n"+mailPostfixConfigTmpl); err != nil {
			fail(fmt.Sprintf("Failed to write main.cf: %v", err))
			return
		}
	}
	// 4a. RHEL ships inet_interfaces = localhost, so NO mail could arrive from
	// another host. postconf, not appended (a second value warns forever).
	_, _ = mailExec("postconf", "inet_interfaces=all")
	// 4b. HELO name: the short OS hostname earns six spam points.
	if host, ok := mailPanelServerName(); ok {
		_, _ = mailExec("postconf", "myhostname="+host)
		// Re-applied: the block above is skipped forever after its first
		// append, and new myhostname + default mydestination bounces mailboxes.
		_, _ = mailExec("postconf", "mydestination=localhost")
		slog.Info(fmt.Sprintf("Postfix myhostname set to %s, mydestination narrowed to localhost", host))
	}
	// 4c. Serve the real certificate where there is one.
	if cert, key, ok := mailPanelTlsPaths(); ok {
		_, _ = mailExec("postconf", "smtpd_tls_cert_file="+cert)
		_, _ = mailExec("postconf", "smtpd_tls_key_file="+key)
	}

	// 5. Submission (587). Test for an ACTIVE entry: the stock file ships it
	// commented, and matching the comment appended a duplicate on every re-run.
	masterCf := mailReadString("/etc/postfix/master.cf")
	active := false
	for _, l := range mailLines(masterCf) {
		t := strings.TrimLeftFunc(l, unicode.IsSpace)
		if !strings.HasPrefix(t, "#") && strings.HasPrefix(t, "submission") && strings.Contains(t, "inet") {
			active = true
		}
	}
	if !active {
		sub := "\nsubmission inet n - y - - smtpd\n  -o syslog_name=postfix/submission\n  -o smtpd_tls_security_level=encrypt\n  -o smtpd_sasl_auth_enable=yes\n  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject\n"
		if err := mailWriteFileAtomic("/etc/postfix/master.cf", masterCf+"\n"+sub); err != nil {
			fail(fmt.Sprintf("Failed to write master.cf: %v", err))
			return
		}
	}

	// 6. Dovecot. `ssl = required` without a trusted cert falls back to
	// snakeoil and every verifying client (Roundcube included) says
	// "unknown ca". 2.4 changed the syntax with no compat mode — detected from
	// the installed binary, not the distro.
	v24 := mailDovecotNeedsV24Syntax()
	tls := "ssl = required\n"
	if cert, key, ok := mailPanelTlsPaths(); ok {
		slog.Info("Dovecot will serve the panel's Let's Encrypt certificate")
		if v24 {
			tls = fmt.Sprintf("ssl = required\nssl_server_cert_file = %s\nssl_server_key_file = %s\n", cert, key)
		} else {
			tls = fmt.Sprintf("ssl = required\nssl_cert = <%s\nssl_key = <%s\n", cert, key)
		}
	}
	mailAuth := mailDovecotV23
	if v24 {
		mailAuth = mailDovecotV24
	}
	dovecotConf := "# DockPanel Dovecot configuration\nprotocols = imap pop3 lmtp\n\n" + mailAuth + "\n" + mailDovecotServices + tls
	if err := mailWriteFileAtomic("/etc/dovecot/conf.d/99-dockpanel.conf", dovecotConf); err != nil {
		fail(fmt.Sprintf("Failed to write dovecot config: %v", err))
		return
	}

	// 7. Map files, created only if missing — NEVER truncated: they hold every
	// domain, mailbox path and password hash, and re-running the installer is
	// the ordinary response to a failed install.
	for _, p := range []string{mailPostfixVirtualDomains, mailPostfixVirtualMailbox, mailPostfixVirtualAlias} {
		if !mailExists(p) {
			if err := mailWriteFileAtomic(p, ""); err != nil {
				fail(fmt.Sprintf("Failed to write %s: %v", p, err))
				return
			}
		}
	}
	if !mailExists(mailDovecotUsers) {
		if err := mailWriteDovecotUsers(""); err != nil {
			fail(fmt.Sprintf("Failed to write dovecot users: %v", err))
			return
		}
	}
	_, _ = mailExec("postmap", mailPostfixVirtualMailbox)
	_, _ = mailExec("postmap", mailPostfixVirtualAlias)

	// 7a. Arm sender-identity enforcement from the first mailbox. Reading the
	// existing map first is what makes a re-run preserve it.
	mailEnsureSenderLoginEnforcement(mailReadString(mailPostfixSenderLogin))

	// 8. OpenDKIM — config and drop-in inside ReadWritePaths (writing the
	// distro path EROFS'd and aborted every install ever made).
	if err := mailWriteOpendkimConfig(); err != nil {
		fail(fmt.Sprintf("Failed to configure OpenDKIM: %v", err))
		return
	}
	if err := mailWriteFileAtomic(mailDkimKeysDir+"/trusted.hosts", "127.0.0.1\nlocalhost\n"); err != nil {
		fail(fmt.Sprintf("Failed to write trusted.hosts: %v", err))
		return
	}

	// 9. Enable and start.
	if out, err := mailExec("systemctl", "enable", "postfix", "dovecot", "opendkim"); err == nil && !out.Success() {
		slog.Warn("Failed to enable mail services: " + mailLossy(out.Stderr))
	}
	for _, svc := range []string{"postfix", "dovecot", "opendkim"} {
		mailSystemctlWarn("restart "+svc, "restart", svc)
	}

	// 10. Bind existing keys (a reinstall restores signing without re-adding).
	if err := mailRebuildDkimTables(); err != nil {
		slog.Warn(fmt.Sprintf("Failed to build DKIM tables: %v", err))
	}
	// 11. A listener the firewall drops is not an installed service.
	mailOpenMailPorts()

	slog.Info("Mail server installation complete")
	mailOk(w, "Mail server installed and configured")
}

// mailUninstall: POST /mail/uninstall — packages and config, NOT /var/vmail.
func mailUninstall(w http.ResponseWriter, _ *http.Request) {
	slog.Info("Starting mail server uninstall...")
	for _, svc := range []string{"postfix", "dovecot", "opendkim"} {
		serviceInstallerSystemctl(120*time.Second, "stop", svc)
		serviceInstallerSystemctl(120*time.Second, "disable", svc)
	}
	// Through PkgRemove: a direct apt-get failed with "Failed to find
	// executable apt-get" on every RPM box.
	if err := services.PkgRemove([]string{"postfix", "dovecot-imapd", "dovecot-pop3d", "dovecot-lmtpd", "opendkim", "opendkim-tools"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Package removal failed: %v", err))
		return
	}
	_ = os.RemoveAll("/etc/dockpanel/mail")
	_ = os.RemoveAll("/etc/dockpanel/dkim")
	slog.Info("Mail server uninstalled (user mail data preserved in /var/vmail)")
	mailOk(w, "Mail server uninstalled. Note: /var/vmail (user mail data) was NOT removed. Delete it manually if no longer needed.")
}

// mailParseDovecotV24 decides from `dovecot --version` output whether the 2.4+
// syntax is needed. Unparseable → false (the syntax every prior install used).
func mailParseDovecotV24(version string) bool {
	f := strings.Fields(version)
	if len(f) == 0 {
		return false
	}
	parts := strings.Split(f[0], ".")
	num := func(i int) uint64 {
		if i >= len(parts) {
			return 0
		}
		n, err := strconv.ParseUint(parts[i], 10, 32)
		if err != nil {
			return 0
		}
		return n
	}
	major, minor := num(0), num(1)
	return major > 2 || major == 2 && minor >= 4
}

// mailDovecotNeedsV24Syntax asks the installed binary (no config needed).
func mailDovecotNeedsV24Syntax() bool {
	out, err := mailExec("dovecot", "--version")
	if err != nil || !out.Success() {
		return false
	}
	return mailParseDovecotV24(mailLossy(out.Stdout))
}

// mailDovecotPasswordSchemes: what THIS box's Dovecot can verify, upper-cased.
// Argon2id is a BUILD option, not a version: Rocky 9.8's 2.3.16 lacks it and
// every login failed "Unknown scheme ARGON2ID". Empty = could not tell.
func mailDovecotPasswordSchemes() []string {
	schemes := []string{}
	out, err := mailExec("doveadm", "pw", "-l")
	if err != nil || !out.Success() {
		return schemes
	}
	for _, s := range strings.Fields(mailLossy(out.Stdout)) {
		if s = strings.ToUpper(strings.TrimSpace(s)); s != "" {
			schemes = append(schemes, s)
		}
	}
	return schemes
}

// mailLabelVmailForSelinux gives /var/vmail the type Dovecot may write.
//
// It inherits var_t from /var; dovecot_t may write mail_spool_t only, so LMTP
// failed mkdir with "Permission denied" and every message deferred forever
// while the panel called mail healthy (Rocky 9.8, s268). A no-op where SELinux
// is off. semanage records the rule durably; restorecon applies it; chcon is
// the fallback when the rule could not be written.
func mailLabelVmailForSelinux() {
	if out, err := mailExec("selinuxenabled"); err != nil || !out.Success() {
		return
	}
	if out, err := mailExec("semanage", "--help"); err != nil || !out.Success() {
		_, _ = services.PkgInstallAvailable([]string{"policycoreutils-python-utils"})
	}
	out, err := mailUnsandboxed("semanage", "fcontext", "-a", "-t", "mail_spool_t", mailVmailDir+"(/.*)?")
	switch {
	case err != nil:
		slog.Warn(fmt.Sprintf("SELinux: semanage unavailable (%v) — falling back to chcon", err))
	case out.Success():
		slog.Info("SELinux: " + mailVmailDir + " recorded as mail_spool_t")
	case strings.Contains(mailLossy(out.Stderr), "already defined"):
		// The normal case on a re-install.
		slog.Info("SELinux: " + mailVmailDir + " fcontext rule already present")
	default:
		slog.Warn(fmt.Sprintf("SELinux: could not record fcontext for %s: %s", mailVmailDir, strings.TrimSpace(mailLossy(out.Stderr))))
	}
	if out, err := mailExec("restorecon", "-R", mailVmailDir); err != nil || !out.Success() {
		_, _ = mailExec("chcon", "-R", "-t", "mail_spool_t", mailVmailDir)
	}
}

// ── OpenDKIM wiring ─────────────────────────────────────────────────────

// mailWriteOpendkimConfig renders OpenDKIM's config and the drop-in that points
// the daemon at it.
//
// The socket is a LOOPBACK port, not a Unix socket in Postfix's spool: that
// arrangement exists only for Debian's chrooted smtpd, and on RHEL SELinux
// denies dkim_milter_t search on postfix_spool_t, so the daemon never started.
// dkim_milter_port_t already covers 8891. TrustAnchorFile is emitted only when
// an anchor exists — a missing one is FATAL (78/CONFIG).
func mailWriteOpendkimConfig() error {
	anchor := ""
	for _, p := range []string{"/usr/share/dns/root.key", "/var/lib/unbound/root.key"} {
		if mailExists(p) {
			anchor = "TrustAnchorFile " + p + "\n"
			break
		}
	}
	conf := "Syslog yes\nUserID opendkim\nUMask 007\n" +
		"Socket " + mailOpendkimSocket + "\n" +
		"PidFile /run/opendkim/opendkim.pid\nOversignHeaders From\n" +
		anchor +
		"KeyTable " + mailKeyTable + "\nSigningTable refile:" + mailSigningTable + "\n" +
		"ExternalIgnoreList " + mailDkimKeysDir + "/trusted.hosts\n" +
		"InternalHosts " + mailDkimKeysDir + "/trusted.hosts\n"
	if err := mailWriteFileAtomic(mailOpendkimConf, conf); err != nil {
		return err
	}
	if err := os.MkdirAll(mailOpendkimDropinDir, 0o755); err != nil {
		return fmt.Errorf("Failed to create %s: %v", mailOpendkimDropinDir, err)
	}
	// The drop-in owns BOTH Type and ExecStart: Debian ships Type=forking,
	// EPEL Type=simple with -f; pinning Type=simple + -f is right on both.
	dropin := "[Service]\nType=simple\nExecStart=\nExecStart=/usr/sbin/opendkim -f -x " + mailOpendkimConf + "\n"
	if err := mailWriteFileAtomic(mailOpendkimDropinDir+"/dockpanel.conf", dropin); err != nil {
		return err
	}
	_, _ = mailExec("systemctl", "daemon-reload")
	return nil
}

// mailDkimTableLines derives key.table / signing.table rows from the key tree
// at dir (domain/selector.private). Idempotent and drift-free by construction.
func mailDkimTableLines(dir string) ([]string, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to read %s: %v", dir, err)
	}
	keyLines, signLines := []string{}, []string{}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
			continue
		}
		domain := e.Name()
		// Defence in depth: this string becomes a config line.
		if domain == "" || !mailIsDomainChars(domain) {
			continue
		}
		keys, err := os.ReadDir(p)
		if err != nil {
			continue
		}
		for _, k := range keys {
			selector, ok := strings.CutSuffix(k.Name(), ".private")
			if !ok || selector == "" || !mailCharsIn(selector, "-_") {
				continue
			}
			keyLines = append(keyLines, fmt.Sprintf("%s._domainkey.%s %s:%s:%s", selector, domain, domain, selector, filepath.Join(p, k.Name())))
			signLines = append(signLines, fmt.Sprintf("*@%s %s._domainkey.%s", domain, selector, domain))
		}
	}
	return keyLines, signLines, nil
}

// mailRebuildDkimTables rebuilds both tables from the keys on disk, then
// restarts OpenDKIM (it reads them at startup only).
func mailRebuildDkimTables() error {
	// /etc/dockpanel is 0700 root, so opendkim cannot even traverse to a key;
	// 0710 + group grants traverse without listing or exposing api.env. Keys
	// can be left root-owned by a chown that raced apt creating the user.
	_, _ = mailExec("chgrp", "opendkim", "/etc/dockpanel")
	_, _ = mailExec("chmod", "0710", "/etc/dockpanel")
	_, _ = mailExec("chown", "-R", "opendkim:opendkim", mailDkimKeysDir)
	_, _ = mailExec("chmod", "0750", mailDkimKeysDir)

	keyLines, signLines, err := mailDkimTableLines(mailDkimKeysDir)
	if err != nil {
		return err
	}
	if err := mailWriteFileAtomic(mailKeyTable, strings.Join(keyLines, "\n")); err != nil {
		return err
	}
	if err := mailWriteFileAtomic(mailSigningTable, strings.Join(signLines, "\n")); err != nil {
		return err
	}
	if out, err := mailExec("systemctl", "restart", "opendkim"); err == nil && !out.Success() {
		slog.Warn("Failed to restart opendkim after table rebuild: " + mailLossy(out.Stderr))
	}
	slog.Info(fmt.Sprintf("DKIM tables rebuilt: %d key(s) across %d entr(ies)", len(keyLines), len(signLines)))
	return nil
}

// mailOpenMailPorts opens the mail ports and says what actually happened (it
// once logged success unconditionally, false on every firewalld box).
func mailOpenMailPorts() {
	failed := services.FirewallAllowTcpPorts(mailPorts)
	if len(failed) == 0 {
		name := map[services.Firewall]string{services.FirewallFirewalld: "Firewalld", services.FirewallUfw: "Ufw", services.FirewallNone: "None"}[services.FirewallDetect()]
		slog.Info(fmt.Sprintf("Mail ports opened in %s: %s", name, strings.Join(mailPorts, ", ")))
	} else {
		slog.Warn(fmt.Sprintf("Mail ports NOT opened: %s — mail will not be deliverable until they are", strings.Join(failed, ", ")))
	}
}

// mailPanelTlsPaths: the panel host's Let's Encrypt cert, when present —
// otherwise Dovecot/Postfix serve snakeoil that verifying clients refuse.
func mailPanelTlsPaths() (string, string, bool) {
	host, ok := mailPanelServerName()
	if !ok {
		return "", "", false
	}
	dir := "/etc/letsencrypt/live/" + host
	cert, key := dir+"/fullchain.pem", dir+"/privkey.pem"
	return cert, key, mailExists(cert) && mailExists(key)
}

// mailPanelServerName reads the panel vhost's server_name; false for `_`
// (IP-based installs) or no vhost.
func mailPanelServerName() (string, bool) {
	for _, conf := range []string{"/etc/nginx/sites-enabled/dockpanel-panel.conf", "/etc/nginx/conf.d/dockpanel-panel.conf"} {
		b, err := os.ReadFile(conf)
		if err != nil || !utf8.Valid(b) {
			continue
		}
		for _, line := range services.LogsLines(b) {
			rest, ok := strings.CutPrefix(strings.TrimSpace(line), "server_name ")
			if !ok {
				continue
			}
			name := strings.TrimSpace(strings.TrimRight(rest, ";"))
			if name != "" && name != "_" {
				if f := strings.Fields(name); len(f) > 0 {
					return f[0], true
				}
			}
		}
	}
	return "", false
}

// ── DKIM / domains ──────────────────────────────────────────────────────

func mailDkimGenerate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Domain   string `json:"domain"`
		Selector string `json:"selector"`
	}
	if !securityDecodeStrict(w, r, &b, "domain", "selector") {
		return
	}
	domain, selector := strings.TrimSpace(b.Domain), strings.TrimSpace(b.Selector)
	if domain == "" || selector == "" {
		writeErr(w, http.StatusBadRequest, "Domain and selector required")
		return
	}
	if strings.ContainsAny(domain, `/\`) || strings.Contains(domain, "..") || !mailIsDomainChars(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	if strings.ContainsAny(selector, `/\`) || strings.Contains(selector, "..") || !mailCharsIn(selector, "-_") {
		writeErr(w, http.StatusBadRequest, "Invalid selector format")
		return
	}
	fail := func(msg string) { writeErr(w, http.StatusInternalServerError, msg) }

	keyDir := mailDkimKeysDir + "/" + domain
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		fail(fmt.Sprintf("Failed to create DKIM dir: %v", err))
		return
	}
	priv, pub := keyDir+"/"+selector+".private", keyDir+"/"+selector+".public"
	out, err := mailExec("openssl", "genrsa", "-out", priv, "2048")
	if err != nil {
		fail(fmt.Sprintf("openssl genrsa failed: %v", err))
		return
	}
	if !out.Success() {
		fail("Failed to generate DKIM private key")
		return
	}
	out, err = mailExec("openssl", "rsa", "-in", priv, "-pubout", "-out", pub)
	if err != nil {
		fail(fmt.Sprintf("openssl rsa failed: %v", err))
		return
	}
	if !out.Success() {
		fail("Failed to extract DKIM public key")
		return
	}
	privKey, err := mailReadUTF8(priv)
	if err != nil {
		fail(fmt.Sprintf("Failed to read private key: %v", err))
		return
	}
	pubKey, err := mailReadUTF8(pub)
	if err != nil {
		fail(fmt.Sprintf("Failed to read public key: %v", err))
		return
	}
	_, _ = mailExec("chmod", "600", priv)
	_, _ = mailExec("chown", "opendkim:opendkim", priv)

	// A keypair + DNS record is not DKIM until the domain is in the tables.
	if err := mailRebuildDkimTables(); err != nil {
		slog.Warn(fmt.Sprintf("DKIM keys generated for %s but tables not rebuilt: %v", domain, err))
	}
	slog.Info(fmt.Sprintf("DKIM keys generated for %s (selector: %s)", domain, selector))
	writeJSON(w, http.StatusOK, map[string]string{"private_key": privKey, "public_key": pubKey, "selector": selector})
}

func mailReadUTF8(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", fmt.Errorf("stream did not contain valid UTF-8")
	}
	return string(b), nil
}

// mailDomainBody decodes {"domain"} and validates it, writing 400 on failure.
func mailDomainBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	var b struct {
		Domain string `json:"domain"`
	}
	if !securityDecodeStrict(w, r, &b, "domain") {
		return "", false
	}
	d := strings.TrimSpace(b.Domain)
	if strings.ContainsAny(d, `/\`) || strings.Contains(d, "..") || !mailIsDomainChars(d) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return "", false
	}
	return d, true
}

func mailDomainConfigure(w http.ResponseWriter, r *http.Request) {
	domain, ok := mailDomainBody(w, r)
	if !ok {
		return
	}
	maildir := mailVmailDir + "/" + domain
	if err := os.MkdirAll(maildir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create maildir: %v", err))
		return
	}
	_, _ = mailExec("chown", "-R", "vmail:vmail", maildir)
	slog.Info("Mail domain configured: " + domain)
	mailOk(w, fmt.Sprintf("Domain %s configured", domain))
}

func mailDomainRemove(w http.ResponseWriter, r *http.Request) {
	domain, ok := mailDomainBody(w, r)
	if !ok {
		return
	}
	_ = os.RemoveAll(mailDkimKeysDir + "/" + domain)
	// Same helper as the add path, so a removed domain stops being signed.
	if err := mailRebuildDkimTables(); err != nil {
		slog.Warn(fmt.Sprintf("DKIM keys removed for %s but tables not rebuilt: %v", domain, err))
	}
	// The maildir is kept (destructive); sync removes it from the maps.
	slog.Info("Mail domain removed: " + domain)
	mailOk(w, fmt.Sprintf("Domain %s removed", domain))
}

// ── Full sync ───────────────────────────────────────────────────────────

// mailLocalPartIsSafe: the local part is a PATH COMPONENT and a MAP KEY.
// `..@x` resolved to /var/vmail itself (and chown -R walked the tree);
// `@x` is byte-identical to the catch-all key and silently replaced it.
func mailLocalPartIsSafe(addr string) bool {
	local, domain, ok := strings.Cut(addr, "@")
	return ok && local != "" && domain != "" && strings.Trim(local, ".") != ""
}

// mailDecodeSync decodes the sync body with serde's missing-field refusal at
// every level (Go would zero-fill a missing `enabled`).
func mailDecodeSync(w http.ResponseWriter, r *http.Request, v *mailSyncRequest) bool {
	var raw json.RawMessage
	if !decodeJSON(w, r, &raw) {
		return false
	}
	fail := func(msg string) bool {
		http.Error(w, "Failed to deserialize the JSON body into the target type: "+msg, http.StatusUnprocessableEntity)
		return false
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return fail("invalid type: expected a JSON object")
	}
	required := map[string][]string{
		"domains":  {"domain", "enabled"},
		"accounts": {"email", "password_hash", "quota_mb", "enabled"},
		"aliases":  {"source", "destination"},
	}
	for _, field := range []string{"domains", "accounts", "aliases"} {
		val, ok := top[field]
		if !ok || string(bytes.TrimSpace(val)) == "null" {
			return fail(fmt.Sprintf("missing field `%s`", field))
		}
		var items []map[string]json.RawMessage
		if err := json.Unmarshal(val, &items); err != nil {
			return fail(err.Error())
		}
		for _, it := range items {
			for _, k := range required[field] {
				if x, ok := it[k]; !ok || string(bytes.TrimSpace(x)) == "null" {
					return fail(fmt.Sprintf("%s: missing field `%s`", field, k))
				}
			}
		}
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fail(err.Error())
	}
	return true
}

const mailAddrChars = "@._-+"

// mailValidateSync returns the first validation error message, or "".
func mailValidateSync(b *mailSyncRequest) string {
	for _, acc := range b.Accounts {
		if !mailCharsIn(acc.Email, mailAddrChars) {
			return "Invalid characters in email address"
		}
		if strings.Count(acc.Email, "@") != 1 {
			return "Invalid email format"
		}
		if !mailLocalPartIsSafe(acc.Email) {
			return "Invalid email local part"
		}
		// Dovecot's users file is ':'-separated.
		if strings.ContainsAny(acc.PasswordHash, ":\n\r\x00\t") {
			return "Invalid characters in password hash"
		}
		if acc.ForwardTo != nil && *acc.ForwardTo != "" && !mailCharsIn(*acc.ForwardTo, mailAddrChars) {
			return "Invalid characters in forward_to address"
		}
	}
	for _, a := range b.Aliases {
		if !mailCharsIn(a.Source, mailAddrChars) || !mailCharsIn(a.Destination, mailAddrChars+",") {
			return "Invalid characters in alias data"
		}
		// An alias source is a virtual_alias_maps KEY too.
		if !mailLocalPartIsSafe(a.Source) {
			return "Invalid alias source local part"
		}
	}
	for _, d := range b.Domains {
		if d.CatchAll != nil && *d.CatchAll != "" && !mailCharsIn(*d.CatchAll, mailAddrChars+"/") {
			return "Invalid characters in catch-all address"
		}
	}
	return ""
}

func mailSyncConfig(w http.ResponseWriter, r *http.Request) {
	var b mailSyncRequest
	if !mailDecodeSync(w, r, &b) {
		return
	}
	if msg := mailValidateSync(&b); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	fail := func(msg string) { writeErr(w, http.StatusInternalServerError, msg) }
	for _, d := range [][2]string{{mailVmailDir, "vmail"}, {"/etc/postfix", "postfix"}, {"/etc/dovecot", "dovecot"}} {
		if err := os.MkdirAll(d[0], 0o755); err != nil {
			fail(fmt.Sprintf("Failed to create %s dir: %v", d[1], err))
			return
		}
	}

	// 1. virtual_domains.
	var domains []string
	for _, d := range b.Domains {
		if d.Enabled {
			domains = append(domains, d.Domain)
		}
	}
	if err := mailWriteFileAtomic(mailPostfixVirtualDomains, strings.Join(domains, "\n")); err != nil {
		fail(fmt.Sprintf("Failed to write virtual_domains: %v", err))
		return
	}

	// 2. virtual_mailbox_maps (email → maildir path) + catch-alls.
	var mailbox []string
	for _, acc := range b.Accounts {
		if !acc.Enabled {
			continue
		}
		if local, dom, ok := strings.Cut(acc.Email, "@"); ok {
			mailbox = append(mailbox, fmt.Sprintf("%s\t%s/%s/", acc.Email, dom, local))
		}
	}
	for _, d := range b.Domains {
		if d.CatchAll != nil && *d.CatchAll != "" && d.Enabled {
			mailbox = append(mailbox, fmt.Sprintf("@%s\t%s", d.Domain, *d.CatchAll))
		}
	}
	if err := mailWriteFileAtomic(mailPostfixVirtualMailbox, strings.Join(mailbox, "\n")); err != nil {
		fail(fmt.Sprintf("Failed to write virtual_mailbox_maps: %v", err))
		return
	}

	// 3. virtual_alias_maps + account forwards.
	var aliases []string
	for _, a := range b.Aliases {
		aliases = append(aliases, a.Source+"\t"+a.Destination)
	}
	for _, acc := range b.Accounts {
		if acc.ForwardTo != nil && *acc.ForwardTo != "" && acc.Enabled {
			aliases = append(aliases, acc.Email+"\t"+*acc.ForwardTo)
		}
	}
	if err := mailWriteFileAtomic(mailPostfixVirtualAlias, strings.Join(aliases, "\n")); err != nil {
		fail(fmt.Sprintf("Failed to write virtual_alias_maps: %v", err))
		return
	}

	// 4. Dovecot users (email:{hash}::::/var/vmail/domain/user::quota).
	var users []string
	for _, a := range b.Accounts {
		if !a.Enabled {
			continue
		}
		maildir := mailVmailDir + "/" + a.Email
		if local, dom, ok := strings.Cut(a.Email, "@"); ok {
			maildir = mailVmailDir + "/" + dom + "/" + local
		}
		users = append(users, fmt.Sprintf("%s:%s::::%s::userdb_quota_rule=*:storage=%dM", a.Email, a.PasswordHash, maildir, a.QuotaMb))
	}
	if err := mailWriteDovecotUsers(strings.Join(users, "\n")); err != nil {
		fail(fmt.Sprintf("Failed to write dovecot users: %v", err))
		return
	}

	// 5. Sender identity — here because this is the only path that runs again
	// on a box already carrying mail, so existing installs self-repair.
	mailEnsureSenderLoginEnforcement(mailBuildSenderLoginMap(&b))

	// 6. Rebuild hashes. 7. Reload.
	_, _ = mailExec("postmap", mailPostfixVirtualMailbox)
	_, _ = mailExec("postmap", mailPostfixVirtualAlias)
	for _, svc := range []string{"postfix", "dovecot"} {
		mailSystemctlWarn("reload "+svc, "reload", svc)
	}

	// 8. Maildirs.
	for _, acc := range b.Accounts {
		if !acc.Enabled {
			continue
		}
		if local, dom, ok := strings.Cut(acc.Email, "@"); ok {
			maildir := mailVmailDir + "/" + dom + "/" + local
			if err := os.MkdirAll(maildir, 0o755); err != nil {
				slog.Warn(fmt.Sprintf("Failed to create maildir %s: %v", maildir, err))
			}
			_, _ = mailExec("chown", "-R", "vmail:vmail", maildir)
		}
	}
	slog.Info(fmt.Sprintf("Mail config synced: %d domains, %d accounts, %d aliases", len(b.Domains), len(b.Accounts), len(b.Aliases)))
	mailOk(w, "Mail configuration synced")
}

// mailBuildSenderLoginMap builds smtpd_sender_login_maps: which SASL login may
// use which envelope sender.
//
// Neither existing map can serve: mailbox-map values are maildir paths, and
// alias-map values are FORWARD TARGETS (a tenant could create
// `sales@theirs -> victim@other` and gain send-as over the victim).
//
// THIS TABLE IS AN ALLOW-LIST (postconf(5), the authenticated form armed
// below): an unlisted sender is REFUSED. Rows: every enabled mailbox owns
// itself; one `@domain` row per enabled domain owned by that domain's enabled
// logins (keeps aliases/catch-alls/role addresses sendable). A domain with no
// enabled mailbox is owned by mailNoAuthorisedSender. Mailboxes in the SAME
// domain may send as each other (same site owner) — the control is per-domain.
func mailBuildSenderLoginMap(b *mailSyncRequest) string {
	lines := []string{}
	for _, acc := range b.Accounts {
		if acc.Enabled {
			lines = append(lines, acc.Email+"\t"+acc.Email)
		}
	}
	for _, d := range b.Domains {
		if !d.Enabled {
			continue
		}
		// An exact-domain test: does not match user@sub.example.com.
		suffix := "@" + d.Domain
		var owners []string
		for _, a := range b.Accounts {
			if a.Enabled && strings.HasSuffix(a.Email, suffix) {
				owners = append(owners, a.Email)
			}
		}
		o := mailNoAuthorisedSender
		if len(owners) > 0 {
			o = strings.Join(owners, ",")
		}
		lines = append(lines, "@"+d.Domain+"\t"+o)
	}
	return strings.Join(lines, "\n")
}

// mailEnsureSenderLoginEnforcement writes the map, rebuilds its hash, and arms
// the restriction — strictly in that order.
//
// A hash: table named by an smtpd restriction is opened at smtpd init: a
// missing/stale .db makes smtpd exit fatal (outage on 25 and 587). So postmap's
// exit status is CHECKED and the keys are written only after it succeeds; any
// failure leaves the box unprotected but still carrying mail.
//
// An EMPTY map is not armed: the restriction is an allow-list, so arming it
// would refuse every authenticated submission (553). Empty means no enabled
// mailbox/domain, so nothing can authenticate; the next sync arms it.
func mailEnsureSenderLoginEnforcement(mapContent string) {
	if err := mailWriteFileAtomic(mailPostfixSenderLogin, mapContent); err != nil {
		slog.Error(fmt.Sprintf("Sender-login map not written (%v) — leaving sender identity unenforced rather "+
			"than arming a restriction against a map that is not there", err))
		return
	}
	out, err := mailExec("postmap", mailPostfixSenderLogin)
	if err != nil {
		slog.Error(fmt.Sprintf("postmap %s could not be run (%v) — leaving sender identity unenforced", mailPostfixSenderLogin, err))
		return
	}
	if !out.Success() {
		slog.Error(fmt.Sprintf("postmap %s failed (exit status: %d) — leaving sender identity "+
			"unenforced; arming the restriction against an unopenable map would take "+
			"smtpd down on 25 and 587. stderr: %s", mailPostfixSenderLogin, out.ExitCode, mailLossy(out.Stderr)))
		return
	}
	if strings.TrimSpace(mapContent) == "" {
		slog.Info("Sender-login map is empty (no enabled mailbox or domain) — writing it but NOT " +
			"arming the restriction. Arming an allow-list against an empty table would refuse " +
			"every authenticated submission on this box. The next mail sync arms it.")
		return
	}
	// postconf, not the install block (appended once, skipped forever).
	_, _ = mailExec("postconf", "smtpd_sender_login_maps=hash:"+mailPostfixSenderLogin)
	// NO permit_mynetworks in front: mynetworks_style=host still covers
	// 127.0.0.0/8, which on a hosting box is every tenant's own code — that
	// version was measured INERT. Local sendmail (PHP mail()) is non_smtpd and
	// never reaches this anyway. The AUTHENTICATED form, so unauthenticated
	// inbound mail on 25 from lists/forwarders is unaffected.
	_, _ = mailExec("postconf", "smtpd_sender_restrictions=reject_authenticated_sender_login_mismatch")
}

// ── Queue ───────────────────────────────────────────────────────────────

type mailQueueItem struct {
	ID          string `json:"id"`
	Sender      string `json:"sender"`
	Size        string `json:"size"`
	ArrivalTime string `json:"arrival_time"`
	Recipients  string `json:"recipients"`
	Status      string `json:"status"`
}

// mailParseQueue parses `mailq` output (sender/size/time carry over between
// entries exactly as the Rust parser did).
func mailParseQueue(stdout string) []mailQueueItem {
	items := []mailQueueItem{}
	var id, sender, size, tm, status string
	var rcpts []string
	flush := func() {
		if id != "" {
			items = append(items, mailQueueItem{id, sender, size, tm, strings.Join(rcpts, ", "), status})
			id, status, rcpts = "", "", nil
		}
	}
	for _, line := range mailLines(stdout) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "-") || t == "" {
			flush()
			continue
		}
		first, _ := utf8.DecodeRuneInString(t)
		// An entry header starts in column 0; recipient and reason lines are
		// indented. (The Rust parser keyed on length instead, so any recipient
		// longer than 10 characters was taken for a queue ID and dropped.)
		indented := line != "" && (line[0] == ' ' || line[0] == '\t')
		if !indented && strings.ContainsAny(t, " \t") && (unicode.IsLetter(first) || unicode.IsNumber(first)) {
			// "A1B2C3D4E5*    1234 Mon Mar 15 10:00:00  sender@example.com"
			i := strings.IndexFunc(t, unicode.IsSpace)
			if i < 0 {
				continue
			}
			head, rest := t[:i], strings.TrimSpace(t[i+1:])
			id = strings.TrimRight(strings.TrimRight(head, "*"), "!")
			switch {
			case strings.Contains(head, "*"):
				status = "active"
			case strings.Contains(head, "!"):
				status = "hold"
			default:
				status = "deferred"
			}
			if j := strings.IndexFunc(rest, unicode.IsSpace); j >= 0 {
				size = rest[:j]
				words := strings.Fields(rest)
				sender = words[len(words)-1]
				tm = strings.Join(words[1:len(words)-1], " ")
			}
		} else if strings.Contains(t, "@") && !strings.Contains(t, " ") {
			rcpts = append(rcpts, t)
		}
	}
	flush()
	return items
}

func mailQueueList(w http.ResponseWriter, _ *http.Request) {
	out, err := mailExec("mailq")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("mailq failed: %v", err))
		return
	}
	stdout := mailLossy(out.Stdout)
	if strings.Contains(stdout, "Mail queue is empty") || strings.TrimSpace(stdout) == "" {
		writeJSON(w, http.StatusOK, map[string]any{"queue": []any{}, "count": 0})
		return
	}
	items := mailParseQueue(stdout)
	writeJSON(w, http.StatusOK, map[string]any{"queue": items, "count": len(items)})
}

func mailQueueFlush(w http.ResponseWriter, _ *http.Request) {
	out, err := mailExec("postqueue", "-f")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("postqueue -f failed: %v", err))
		return
	}
	if !out.Success() {
		writeErr(w, http.StatusInternalServerError, "Flush failed: "+mailLossy(out.Stderr))
		return
	}
	slog.Info("Mail queue flushed")
	mailOk(w, "Queue flushed")
}

func mailQueueDelete(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if !securityDecodeStrict(w, r, &b, "id") {
		return
	}
	id := strings.TrimSpace(b.ID)
	if id == "" || strings.Trim(id, "0123456789abcdefABCDEF") != "" || len(id) > 20 {
		writeErr(w, http.StatusBadRequest, "Invalid queue ID format")
		return
	}
	out, err := mailExec("postsuper", "-d", id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("postsuper -d failed: %v", err))
		return
	}
	if !out.Success() {
		writeErr(w, http.StatusInternalServerError, "Delete failed: "+mailLossy(out.Stderr))
		return
	}
	slog.Info(fmt.Sprintf("Queued message %s deleted", b.ID))
	mailOk(w, "Message deleted from queue")
}

// ── Rspamd ──────────────────────────────────────────────────────────────

// mailAddMilter appends milter to smtpd_milters / non_smtpd_milters, keeping
// whatever endpoint is on the line (a literal match once silently orphaned
// this edit). ok=false when neither key exists — the caller must fail, not
// write the file back unchanged. Idempotent.
func mailAddMilter(mainCf, milter string) (string, bool) {
	found := false
	lines := mailLines(mainCf)
	for i, line := range lines {
		for _, key := range []string{"smtpd_milters", "non_smtpd_milters"} {
			rest, ok := strings.CutPrefix(line, key)
			if !ok {
				continue
			}
			value, ok := strings.CutPrefix(strings.TrimLeftFunc(rest, unicode.IsSpace), "=")
			if !ok {
				continue
			}
			found = true
			value = strings.TrimSpace(value)
			present := false
			for _, m := range strings.Split(value, ",") {
				if strings.TrimSpace(m) == milter {
					present = true
				}
			}
			switch {
			case present:
			case value == "":
				lines[i] = key + " = " + milter
			default:
				lines[i] = key + " = " + value + ", " + milter
			}
			break
		}
	}
	if !found {
		return "", false
	}
	out := strings.Join(lines, "\n")
	if strings.HasSuffix(mainCf, "\n") {
		out += "\n"
	}
	return out, true
}

func mailRspamdInstall(w http.ResponseWriter, _ *http.Request) {
	slog.Info("Installing Rspamd spam filter...")
	// rspamd is not in EPEL. Add upstream's repo on the RPM family ONLY, and
	// only when unreachable — never on Debian, which packages it (#95c).
	if services.PkgManager() == services.PkgMgrRpm && !services.PkgAvailable("rspamd") {
		if err := services.PkgAddRepo(services.PkgRepoRspamd); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Could not add the Rspamd repository: %v", err))
			return
		}
	}
	if err := services.PkgInstall([]string{"rspamd", "redis-server"}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Rspamd install failed: %v", err))
		return
	}
	mainCf := mailReadString("/etc/postfix/main.cf")
	newCf, ok := mailAddMilter(mainCf, mailRspamdMilter)
	if !ok {
		// No milter list means mail was never installed.
		writeErr(w, http.StatusPreconditionFailed, "Postfix has no smtpd_milters setting — install the mail server before the spam filter")
		return
	}
	if newCf != mainCf {
		if err := mailWriteFileAtomic("/etc/postfix/main.cf", newCf); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config write failed: %v", err))
			return
		}
	}
	// The Redis UNIT is `redis-server` on Debian, `redis` on RHEL.
	redisUnit := services.PkgServiceName("redis-server")
	if out, err := mailExec("systemctl", "enable", "rspamd", redisUnit); err == nil && !out.Success() {
		slog.Warn("Failed to enable rspamd/redis: " + mailLossy(out.Stderr))
	}
	for _, svc := range []string{redisUnit, "rspamd"} {
		mailSystemctlWarn("restart "+svc, "restart", svc)
	}
	if out, err := mailExec("systemctl", "reload", "postfix"); err == nil && !out.Success() {
		slog.Warn("Failed to reload postfix: " + mailLossy(out.Stderr))
	}
	slog.Info("Rspamd installed and configured")
	mailOk(w, "Rspamd spam filter installed")
}

func mailRspamdStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"installed": mailIsInstalled("rspamd"),
		"running":   mailIsServiceActive("rspamd"),
		"redis":     mailIsServiceActive(services.PkgServiceName("redis-server")),
	})
}

// mailBodyObject decodes an arbitrary JSON body (Json<Value>) and returns it
// as an object, or nil when it is not one (`.get` on a non-object is None).
func mailBodyObject(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, bool) {
	var raw json.RawMessage
	if !decodeJSON(w, r, &raw) {
		return nil, false
	}
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(raw, &obj)
	return obj, true
}

func mailStr(obj map[string]json.RawMessage, key, def string) string {
	var s string
	if v, ok := obj[key]; ok && json.Unmarshal(v, &s) == nil && string(bytes.TrimSpace(v)) != "null" {
		return s
	}
	return def
}

func mailRspamdToggle(w http.ResponseWriter, r *http.Request) {
	obj, ok := mailBodyObject(w, r)
	if !ok {
		return
	}
	enable := true
	if v, ok := obj["enable"]; ok {
		var b bool
		if json.Unmarshal(v, &b) == nil && string(bytes.TrimSpace(v)) != "null" {
			enable = b
		}
	}
	actions := []string{"stop", "disable"}
	msg := "Rspamd disabled"
	if enable {
		actions, msg = []string{"start", "enable"}, "Rspamd enabled"
	}
	for _, a := range actions {
		mailSystemctlWarn(a+" rspamd", a, "rspamd")
	}
	mailOk(w, msg)
}

// ── Webmail (Roundcube) ─────────────────────────────────────────────────

// mailWebmailNginxBlock is THE single source of the /webmail/ fragment
// (update.sh's hand-copied mirror rotted into the shape that renders the inbox
// empty). Roundcube emits root-anchored URLs, so sub_filter/proxy_redirect
// rewrite them under /webmail/; the header set is re-declared because nginx
// add_header in a location replaces the inherited set, and the panel's
// frame-ancestors 'none' would refuse Roundcube's own same-origin iframe.
func mailWebmailNginxBlock(port uint16) string {
	return fmt.Sprintf("# DockPanel webmail (Roundcube) reverse-proxy — managed by agent, do not edit\n"+
		"# v2.10.1: sub_filter rewrites Roundcube's root-anchored URLs (form action,\n"+
		"# comm_path) under /webmail/ so navigation doesn't land on the panel root.\n"+
		"location /webmail/ {\n"+
		"    proxy_pass http://127.0.0.1:%d/;\n"+
		"    proxy_http_version 1.1;\n"+
		"    proxy_set_header Host $host;\n"+
		"    proxy_set_header X-Real-IP $remote_addr;\n"+
		"    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"+
		"    proxy_set_header X-Forwarded-Proto $scheme;\n"+
		"    proxy_set_header X-Forwarded-Host $host;\n"+
		"    proxy_set_header Accept-Encoding \"\";\n"+
		"    proxy_redirect / /webmail/;\n"+
		"    sub_filter '\"/?_task=' '\"/webmail/?_task=';\n"+
		"    sub_filter_once off;\n"+
		"    sub_filter_types text/html application/json application/javascript text/javascript;\n"+
		"    proxy_read_timeout 300s;\n"+
		"    client_max_body_size 25M;\n"+
		"    # Roundcube's Elastic skin frames itself same-origin. The panel\n"+
		"    # vhost sends X-Frame-Options DENY and frame-ancestors 'none',\n"+
		"    # which this location inherits — the iframe is refused, the list\n"+
		"    # JS throws a SecurityError reaching into it, and the inbox\n"+
		"    # renders empty however much mail is really in it. Re-declare the\n"+
		"    # whole header set here (nginx add_header in a location replaces\n"+
		"    # the inherited set rather than adding to it) with framing\n"+
		"    # narrowed to same-origin, not opened up.\n"+
		"    add_header X-Content-Type-Options \"nosniff\" always;\n"+
		"    add_header X-Frame-Options \"SAMEORIGIN\" always;\n"+
		"    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"+
		"    add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n"+
		"    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"+
		"    add_header Content-Security-Policy \"frame-ancestors 'self'\" always;\n"+
		"    add_header X-XSS-Protection \"1; mode=block\" always;\n"+
		"}\n", port)
}

// mailWriteWebmailNginx writes the fragment, validates with nginx -t and
// reloads; unlinks it on a failed test — never leaves nginx broken.
func mailWriteWebmailNginx(port uint16) (int, string) {
	if err := os.MkdirAll(mailWebmailNginxDir, 0o755); err != nil {
		return http.StatusInternalServerError, fmt.Sprintf("Failed to create %s: %v", mailWebmailNginxDir, err)
	}
	if err := os.WriteFile(mailWebmailNginxConf, []byte(mailWebmailNginxBlock(port)), 0o644); err != nil {
		return http.StatusInternalServerError, fmt.Sprintf("Failed to write %s: %v", mailWebmailNginxConf, err)
	}
	test, err := mailExec("nginx", "-t")
	if err != nil {
		return http.StatusInternalServerError, fmt.Sprintf("nginx -t failed: %v", err)
	}
	if !test.Success() {
		_ = os.Remove(mailWebmailNginxConf)
		stderr := mailLossy(test.Stderr)
		return http.StatusInternalServerError, "nginx config invalid: " + stderr[:min(400, len(stderr))]
	}
	if _, err := mailExec("nginx", "-s", "reload"); err != nil {
		slog.Warn(fmt.Sprintf("nginx reload failed after webmail install: %v", err))
	}
	return 0, ""
}

// mailWebmailPortFrom extracts the proxied port from an existing fragment.
func mailWebmailPortFrom(current string) uint16 {
	for _, l := range mailLines(current) {
		rest, ok := strings.CutPrefix(strings.TrimSpace(l), "proxy_pass http://127.0.0.1:")
		if !ok {
			continue
		}
		p, _, _ := strings.Cut(rest, "/")
		if n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 16); err == nil {
			return uint16(n)
		}
		break
	}
	return 8888
}

// HealWebmailNginx brings an existing /webmail/ fragment up to the current
// template at agent startup. The fragment is written only on Install, so a
// fix to it (s262's re-declared header set) reached no existing box. Rewrites
// only when bytes differ and only when the fragment exists (never installs
// webmail), keeps the box's port, and restores the old bytes if nginx -t fails.
func HealWebmailNginx(ctx context.Context) {
	b, err := os.ReadFile(mailWebmailNginxConf)
	if err != nil || !utf8.Valid(b) {
		return
	}
	current := string(b)
	port := mailWebmailPortFrom(current)
	desired := mailWebmailNginxBlock(port)
	if current == desired {
		return
	}
	if os.WriteFile(mailWebmailNginxConf, []byte(desired), 0o644) != nil {
		return
	}
	if out, err := safecmd.Exec(ctx, "nginx", "-t"); err == nil && out.Success() {
		_, _ = safecmd.Exec(ctx, "nginx", "-s", "reload")
		slog.Info(fmt.Sprintf("Healed the /webmail/ nginx fragment to the current template (port %d)", port))
		return
	}
	_ = os.WriteFile(mailWebmailNginxConf, b, 0o644)
	slog.Warn("Webmail fragment heal failed nginx -t; restored the previous fragment")
}

func mailRemoveWebmailNginx() {
	if !mailExists(mailWebmailNginxConf) {
		return
	}
	_ = os.Remove(mailWebmailNginxConf)
	if out, err := mailExec("nginx", "-t"); err == nil && out.Success() {
		_, _ = mailExec("nginx", "-s", "reload")
	}
}

// mailWebmailInstall: POST /mail/webmail/install — Roundcube via Docker.
// Idempotent: the prior container is removed first so env additions apply.
func mailWebmailInstall(w http.ResponseWriter, r *http.Request) {
	obj, ok := mailBodyObject(w, r)
	if !ok {
		return
	}
	domain := mailStr(obj, "domain", "localhost")
	// Rust: as_u64().unwrap_or(8888) as u16 — integer literals only, truncating.
	port := uint16(8888)
	if v, ok := obj["port"]; ok {
		if n, err := strconv.ParseUint(string(bytes.TrimSpace(v)), 10, 64); err == nil {
			port = uint16(n)
		}
	}
	slog.Info(fmt.Sprintf("Installing Roundcube webmail on port %d...", port))
	_, _ = mailExec("docker", "rm", "-f", "dockpanel-roundcube")

	// Roundcube's SQLite (accounts, identities, contacts) lives here when no
	// external DB is configured; the image declares no volume, so without
	// this bind the `rm -f` above takes it with the container. Same
	// {APP_DATA_DIR}/{app}{path} convention as a template deploy.
	webmailDb := services.DockerAppsAppDataDir + "/roundcube/var/roundcube/db"
	if err := os.MkdirAll(webmailDb, 0o755); err != nil {
		slog.Warn(fmt.Sprintf("Could not create %s for webmail: %v", webmailDb, err))
	}

	args := []string{
		"run", "-d",
		"--name", "dockpanel-roundcube",
		"--restart", "unless-stopped",
		"-p", fmt.Sprintf("127.0.0.1:%d:80", port),
		"-v", webmailDb + ":/var/roundcube/db",
		"-e", "ROUNDCUBEMAIL_DEFAULT_HOST=ssl://" + domain,
		"-e", "ROUNDCUBEMAIL_DEFAULT_PORT=993",
		"-e", "ROUNDCUBEMAIL_SMTP_SERVER=tls://" + domain,
		"-e", "ROUNDCUBEMAIL_SMTP_PORT=587",
		"-e", "ROUNDCUBEMAIL_UPLOAD_MAX_FILESIZE=25M",
		"-e", "ROUNDCUBEMAIL_PROXY_WHITELIST=127.0.0.1",
	}
	if host, ok := mailPanelServerName(); ok {
		args = append(args, "-e", "ROUNDCUBEMAIL_TRUSTED_HOSTS="+host, "-e", "ROUNDCUBEMAIL_FORWARDED_PROTO=https")
	}
	// Pinned off :latest (a surprise MAJOR upgrade on a mail stack); `1.7.x`
	// still receives upstream security rebuilds; `-apache` because the
	// container is published on port 80 and -fpm serves no HTTP.
	args = append(args, "-l", "dockpanel.managed=true", "-l", "dockpanel.app.template=roundcube",
		"-l", "dockpanel.app.name=roundcube", mailRoundcubeImage)
	out, err := mailExec("docker", args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Docker failed: %v", err))
		return
	}
	if !out.Success() {
		stderr := mailLossy(out.Stderr)
		writeErr(w, http.StatusInternalServerError, "Roundcube deploy failed: "+stderr[:min(200, len(stderr))])
		return
	}
	if status, msg := mailWriteWebmailNginx(port); status != 0 {
		writeErr(w, status, msg)
		return
	}
	slog.Info(fmt.Sprintf("Roundcube webmail deployed on port %d, panel-vhost /webmail/ proxy active", port))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "port": port})
}

func mailWebmailStatus(w http.ResponseWriter, _ *http.Request) {
	running := false
	if out, err := mailExec("docker", "inspect", "--format", "{{.State.Running}}", "dockpanel-roundcube"); err == nil {
		running = strings.TrimSpace(mailLossy(out.Stdout)) == "true"
	}
	port := uint64(0)
	if out, err := mailExec("docker", "inspect", "--format", "{{range .NetworkSettings.Ports}}{{range .}}{{.HostPort}}{{end}}{{end}}", "dockpanel-roundcube"); err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(mailLossy(out.Stdout)), 10, 16); err == nil {
			port = n
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"installed": running || port > 0, "running": running, "port": port})
}

func mailWebmailRemove(w http.ResponseWriter, _ *http.Request) {
	_, _ = mailExec("docker", "rm", "-f", "dockpanel-roundcube")
	mailRemoveWebmailNginx()
	mailOk(w, "Roundcube removed")
}

// ── SMTP relay ──────────────────────────────────────────────────────────

func mailIsRelayLine(l string) bool {
	return strings.HasPrefix(l, "relayhost") || strings.HasPrefix(l, "smtp_sasl_") ||
		strings.HasPrefix(l, "smtp_tls_") || strings.Contains(l, "# DockPanel relay")
}

func mailRelayConfigure(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Host     string `json:"host"`
		Port     uint16 `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !securityDecodeStrict(w, r, &b, "host", "port", "username", "password") {
		return
	}
	if b.Host == "" {
		writeErr(w, http.StatusBadRequest, "Relay host required")
		return
	}
	if strings.ContainsAny(b.Host, "\n\r\x00") || strings.ContainsAny(b.Username, "\n\x00") || strings.ContainsAny(b.Password, "\n\x00") {
		writeErr(w, http.StatusBadRequest, "Invalid characters in relay config")
		return
	}
	// Map, postmap, THEN the reference in main.cf.
	sasl := fmt.Sprintf("[%s]:%d %s:%s\n", b.Host, b.Port, b.Username, b.Password)
	if err := mailWriteFileAtomicMode("/etc/postfix/sasl_passwd", sasl, 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Failed to write sasl_passwd: %v", err))
		return
	}
	_, _ = mailExec("chmod", "600", "/etc/postfix/sasl_passwd")
	_, _ = mailExec("postmap", "/etc/postfix/sasl_passwd")

	cleaned := mailFilterLines(mailReadString("/etc/postfix/main.cf"), mailIsRelayLine)
	relay := fmt.Sprintf("\n# DockPanel relay configuration\nrelayhost = [%s]:%d\nsmtp_sasl_auth_enable = yes\n"+
		"smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd\nsmtp_sasl_security_options = noanonymous\n"+
		"smtp_tls_security_level = encrypt\nsmtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt\n", b.Host, b.Port)
	if err := mailWriteFileAtomic("/etc/postfix/main.cf", cleaned+relay); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config write failed: %v", err))
		return
	}
	_, _ = mailExec("systemctl", "reload", "postfix")
	slog.Info(fmt.Sprintf("SMTP relay configured: [%s]:%d", b.Host, b.Port))
	mailOk(w, "SMTP relay configured")
}

// mailConfValue: the text after the first '=' on the first line with prefix,
// trimmed ("" when absent); found reports whether such a line exists.
func mailConfValue(content, prefix string) (string, bool) {
	for _, l := range mailLines(content) {
		if strings.HasPrefix(l, prefix) {
			parts := strings.Split(l, "=")
			if len(parts) < 2 {
				return "", true
			}
			return strings.TrimSpace(parts[1]), true
		}
	}
	return "", false
}

func mailRelayStatus(w http.ResponseWriter, _ *http.Request) {
	relay, _ := mailConfValue(mailReadString("/etc/postfix/main.cf"), "relayhost")
	writeJSON(w, http.StatusOK, map[string]any{"configured": relay != "", "relayhost": relay})
}

func mailRelayRemove(w http.ResponseWriter, _ *http.Request) {
	cleaned := mailFilterLines(mailReadString("/etc/postfix/main.cf"), mailIsRelayLine)
	if err := mailWriteFileAtomic("/etc/postfix/main.cf", cleaned); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config write failed: %v", err))
		return
	}
	_ = os.Remove("/etc/postfix/sasl_passwd")
	_ = os.Remove("/etc/postfix/sasl_passwd.db")
	_, _ = mailExec("systemctl", "reload", "postfix")
	mailOk(w, "SMTP relay removed")
}

// ── Logs & storage ──────────────────────────────────────────────────────

// mailLogPath is where this box's MTA log lives: probed (it is a property of
// the syslog config, not the distro), Debian's name as the fallback.
func mailLogPath() string {
	for _, c := range []string{"/var/log/mail.log", "/var/log/maillog"} {
		if mailExists(c) {
			return c
		}
	}
	return "/var/log/mail.log"
}

type mailLogEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
	Level   string `json:"level"`
}

// mailParseLogs computes stats + the last 50 interesting lines (newest first).
func mailParseLogs(content string) (map[string]uint32, []mailLogEntry) {
	var sent, received, bounced, rejected uint32
	recent := []mailLogEntry{}
	lines := mailLines(content)
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if strings.Contains(line, "status=sent") {
			sent++
		}
		if strings.Contains(line, "status=bounced") {
			bounced++
		}
		if strings.Contains(line, "NOQUEUE: reject") || strings.Contains(line, "status=rejected") {
			rejected++
		}
		if strings.Contains(line, "delivered to maildir") || strings.Contains(line, "lmtp(") {
			received++
		}
		if len(recent) < 50 && (strings.Contains(line, "status=") || strings.Contains(line, "NOQUEUE") || strings.Contains(line, "delivered")) {
			tm := ""
			if len(line) >= 15 {
				tm = line[:15]
			}
			msg := line
			if len(line) > 16 {
				msg = line[16:min(len(line), 200)]
			}
			level := "info"
			if strings.Contains(line, "bounced") || strings.Contains(line, "reject") || strings.Contains(line, "error") {
				level = "error"
			}
			recent = append(recent, mailLogEntry{tm, msg, level})
		}
	}
	return map[string]uint32{"sent": sent, "received": received, "bounced": bounced, "rejected": rejected}, recent
}

// mailLogs: GET /mail/logs. Debian writes mail.log, RHEL maillog — the
// hardcoded Debian name returned zeros on every RHEL box, exactly when an
// operator came looking for missing mail.
func mailLogs(w http.ResponseWriter, _ *http.Request) {
	content := ""
	if out, err := mailExec("tail", "-n", "5000", mailLogPath()); err == nil {
		content = mailLossy(out.Stdout)
	}
	stats, recent := mailParseLogs(content)
	writeJSON(w, http.StatusOK, map[string]any{"stats": stats, "recent": recent})
}

func mailStorageUsage(w http.ResponseWriter, _ *http.Request) {
	usage := []map[string]any{}
	domains, err := os.ReadDir(mailVmailDir)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"accounts": usage})
		return
	}
	for _, d := range domains {
		if !d.IsDir() {
			continue
		}
		users, err := os.ReadDir(filepath.Join(mailVmailDir, d.Name()))
		if err != nil {
			continue
		}
		for _, u := range users {
			if !u.IsDir() {
				continue
			}
			var n uint64
			if out, err := mailExec("du", "-sb", filepath.Join(mailVmailDir, d.Name(), u.Name())); err == nil {
				if f := strings.Fields(mailLossy(out.Stdout)); len(f) > 0 {
					n, _ = strconv.ParseUint(f[0], 10, 64)
				}
			}
			usage = append(usage, map[string]any{
				"email": u.Name() + "@" + d.Name(),
				"bytes": n,
				"mb":    math.Round(float64(n)/1024/1024*10) / 10,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": usage})
}

// ── Rate limiting ───────────────────────────────────────────────────────

func mailIsRateLine(l string) bool {
	return strings.HasPrefix(l, "smtp_destination_rate_delay") || strings.HasPrefix(l, "smtp_extra_recipient_limit") ||
		strings.Contains(l, "# DockPanel rate limit")
}

// mailParseRate turns "N/hour" etc. into (count, delay seconds) or a 400 message.
func mailParseRate(rate string) (uint32, uint32, string) {
	parts := strings.Split(rate, "/")
	if len(parts) != 2 {
		return 0, 0, "Rate format: N/hour or N/day"
	}
	// TrimPrefix: Rust's u32::from_str accepts one leading '+'.
	count, err := strconv.ParseUint(strings.TrimPrefix(parts[0], "+"), 10, 32)
	if err != nil {
		return 0, 0, "Invalid count"
	}
	if count == 0 {
		return 0, 0, "Count must be > 0"
	}
	period := map[string]uint32{"hour": 3600, "day": 86400, "minute": 60}[parts[1]]
	if period == 0 {
		return 0, 0, "Period must be minute, hour, or day"
	}
	return uint32(count), period / uint32(count), ""
}

func mailRateLimitSet(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Rate string `json:"rate"`
	}
	if !securityDecodeStrict(w, r, &b, "rate") {
		return
	}
	if b.Rate == "" {
		writeErr(w, http.StatusBadRequest, "Rate required")
		return
	}
	count, delay, msg := mailParseRate(b.Rate)
	if msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	cleaned := mailFilterLines(mailReadString("/etc/postfix/main.cf"), mailIsRateLine)
	conf := fmt.Sprintf("\n# DockPanel rate limit: %s\nsmtp_destination_rate_delay = %ds\nsmtp_extra_recipient_limit = %d\n", b.Rate, delay, min(count, 50))
	if err := mailWriteFileAtomic("/etc/postfix/main.cf", cleaned+conf); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config write failed: %v", err))
		return
	}
	_, _ = mailExec("systemctl", "reload", "postfix")
	slog.Info(fmt.Sprintf("Mail rate limit set: %s (delay: %ds)", b.Rate, delay))
	mailOk(w, "Rate limit set: "+b.Rate)
}

func mailRateLimitStatus(w http.ResponseWriter, _ *http.Request) {
	configured, rate := false, ""
	for _, l := range mailLines(mailReadString("/etc/postfix/main.cf")) {
		if strings.Contains(l, "# DockPanel rate limit:") {
			configured = true
			if parts := strings.Split(l, ":"); len(parts) > 1 {
				rate = strings.TrimSpace(parts[1])
			}
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": configured, "rate": rate})
}

func mailRateLimitRemove(w http.ResponseWriter, _ *http.Request) {
	cleaned := mailFilterLines(mailReadString("/etc/postfix/main.cf"), mailIsRateLine)
	if err := mailWriteFileAtomic("/etc/postfix/main.cf", cleaned); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config write failed: %v", err))
		return
	}
	_, _ = mailExec("systemctl", "reload", "postfix")
	mailOk(w, "Rate limit removed")
}

// ── Mailbox backup / restore ────────────────────────────────────────────

func mailUnsafePart(s string) bool { return strings.ContainsAny(s, `/\`) || strings.Contains(s, "..") }

func mailMailboxBackup(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Email string `json:"email"`
	}
	if !securityDecodeStrict(w, r, &b, "email") {
		return
	}
	email := strings.TrimSpace(b.Email)
	if email == "" || !strings.Contains(email, "@") {
		writeErr(w, http.StatusBadRequest, "Invalid email")
		return
	}
	user, domain, _ := strings.Cut(email, "@")
	if mailUnsafePart(user) || mailUnsafePart(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid email format")
		return
	}
	if !mailExists("/var/vmail/" + domain + "/" + user) {
		writeErr(w, http.StatusNotFound, "Mailbox directory not found")
		return
	}
	// Tarballs hold plaintext mail: directory 0700, archive 0600.
	_ = os.MkdirAll(mailBackupDir, 0o755)
	_ = os.Chmod(mailBackupDir, 0o700)
	file := fmt.Sprintf("%s/%s_%s_%d.tar.gz", mailBackupDir, user, domain, time.Now().Unix())

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	// `--` so a local part starting with '-' is not a tar flag.
	out, err := safecmd.Exec(ctx, "tar", "czf", file, "-C", "/var/vmail/"+domain, "--", user)
	if ctx.Err() == context.DeadlineExceeded {
		writeErr(w, http.StatusGatewayTimeout, "Backup timed out")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Backup failed: %v", err))
		return
	}
	if !out.Success() {
		writeErr(w, http.StatusInternalServerError, "Backup failed: "+mailLossy(out.Stderr))
		return
	}
	_ = os.Chmod(file, 0o600)
	var size int64
	if fi, err := os.Stat(file); err == nil {
		size = fi.Size()
	}
	slog.Info(fmt.Sprintf("Mailbox backed up: %s -> %s (%d bytes)", email, file, size))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "file": file, "size": size})
}

func mailMailboxRestore(w http.ResponseWriter, r *http.Request) {
	obj, ok := mailBodyObject(w, r)
	if !ok {
		return
	}
	email, file := mailStr(obj, "email", ""), mailStr(obj, "file", "")
	if email == "" || !strings.Contains(email, "@") {
		writeErr(w, http.StatusBadRequest, "Invalid email")
		return
	}
	if file == "" || !strings.HasPrefix(file, mailBackupDir+"/") {
		writeErr(w, http.StatusBadRequest, "Invalid backup file path")
		return
	}
	if strings.Contains(file, "..") {
		writeErr(w, http.StatusBadRequest, "Path traversal not allowed")
		return
	}
	if !mailExists(file) {
		writeErr(w, http.StatusNotFound, "Backup file not found")
		return
	}
	user, domain, _ := strings.Cut(email, "@")
	// Otherwise the tar -C target and the recursive chown could escape
	// /var/vmail into an agent-writable root-daemon config dir.
	if user == "" || domain == "" || mailUnsafePart(user) || mailUnsafePart(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid email format")
		return
	}
	maildir := "/var/vmail/" + domain
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "tar", "xzf", file, "-C", maildir)
	if ctx.Err() == context.DeadlineExceeded {
		writeErr(w, http.StatusGatewayTimeout, "Restore timed out")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Restore failed: %v", err))
		return
	}
	if !out.Success() {
		writeErr(w, http.StatusInternalServerError, "Restore failed: "+mailLossy(out.Stderr))
		return
	}
	_, _ = mailExec("chown", "-R", "vmail:vmail", maildir+"/"+user)
	slog.Info(fmt.Sprintf("Mailbox restored: %s from %s", email, file))
	mailOk(w, fmt.Sprintf("Mailbox %s restored", email))
}

// mailBackupEmailHint parses user_domain_timestamp.tar.gz → user@domain.
func mailBackupEmailHint(name string) string {
	stem := strings.TrimSuffix(name, ".tar.gz")
	i := strings.LastIndex(stem, "_")
	if i < 0 {
		return name
	}
	return strings.Replace(stem[:i], "_", "@", 1)
}

func mailMailboxBackups(w http.ResponseWriter, _ *http.Request) {
	backups := []map[string]any{}
	entries, err := os.ReadDir(mailBackupDir)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"backups": backups})
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		var size int64
		if fi, err := e.Info(); err == nil {
			size = fi.Size()
		}
		backups = append(backups, map[string]any{"file": filepath.Join(mailBackupDir, name), "name": name, "email": mailBackupEmailHint(name), "size": size})
	}
	sort.SliceStable(backups, func(i, j int) bool { return backups[i]["name"].(string) > backups[j]["name"].(string) })
	writeJSON(w, http.StatusOK, map[string]any{"backups": backups})
}

func mailMailboxBackupDelete(w http.ResponseWriter, r *http.Request) {
	obj, ok := mailBodyObject(w, r)
	if !ok {
		return
	}
	file := mailStr(obj, "file", "")
	if file == "" || !strings.HasPrefix(file, mailBackupDir+"/") || strings.Contains(file, "..") {
		writeErr(w, http.StatusBadRequest, "Invalid backup file")
		return
	}
	if err := os.Remove(file); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Delete failed: %v", err))
		return
	}
	mailOk(w, "Backup deleted")
}

// ── TLS enforcement ─────────────────────────────────────────────────────

func mailTlsStatus(w http.ResponseWriter, _ *http.Request) {
	mainCf := mailReadString("/etc/postfix/main.cf")
	smtpd, _ := mailConfValue(mainCf, "smtpd_tls_security_level")
	smtp, _ := mailConfValue(mainCf, "smtp_tls_security_level")
	dovecot, _ := mailConfValue(mailReadString("/etc/dovecot/conf.d/99-dockpanel.conf"), "ssl")
	writeJSON(w, http.StatusOK, map[string]any{
		"inbound_tls":       smtpd,
		"outbound_tls":      smtp,
		"dovecot_ssl":       dovecot,
		"inbound_enforced":  smtpd == "encrypt",
		"outbound_enforced": smtp == "encrypt",
	})
}

func mailTlsEnforce(w http.ResponseWriter, r *http.Request) {
	obj, ok := mailBodyObject(w, r)
	if !ok {
		return
	}
	in, out := mailStr(obj, "inbound", "may"), mailStr(obj, "outbound", "may")
	valid := func(s string) bool { return s == "may" || s == "encrypt" || s == "none" }
	if !valid(in) || !valid(out) {
		writeErr(w, http.StatusBadRequest, "Level must be 'may', 'encrypt', or 'none'")
		return
	}
	cleaned := mailFilterLines(mailReadString("/etc/postfix/main.cf"), func(l string) bool {
		return strings.HasPrefix(l, "smtpd_tls_security_level") || strings.HasPrefix(l, "smtp_tls_security_level")
	})
	conf := fmt.Sprintf("\nsmtpd_tls_security_level = %s\nsmtp_tls_security_level = %s\n", in, out)
	if err := mailWriteFileAtomic("/etc/postfix/main.cf", cleaned+conf); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config write failed: %v", err))
		return
	}
	_, _ = mailExec("systemctl", "reload", "postfix")
	slog.Info(fmt.Sprintf("TLS enforcement: inbound=%s, outbound=%s", in, out))
	mailOk(w, fmt.Sprintf("TLS: inbound=%s, outbound=%s", in, out))
}
