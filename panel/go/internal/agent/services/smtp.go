package services

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// smtpMsmtpConfig: msmtp's default /etc/msmtprc is a bare file at the top of
// /etc, which ProtectSystem=strict makes read-only (and ReadWritePaths cannot
// name a file that does not exist yet), so configure failed with EROFS on
// every install. Same cure as /etc/opendkim.conf: write under /etc/dockpanel
// and point every reader at it explicitly.
const smtpMsmtpConfig = "/etc/dockpanel/msmtprc"

// SmtpMsmtpMissing is a precondition, not a fault: the route answers it 424
// so the panel shows the sentence instead of an incident id. msmtp is
// installed only by configure (apt-get only), so a member offline at save
// time, or any RHEL host, has none.
const SmtpMsmtpMissing = "This server has no msmtp binary, so it cannot send mail yet — your SMTP " +
	"settings are not the problem. Save the SMTP settings again while this server " +
	"is online to install and configure it. On RHEL-family systems the panel " +
	"cannot install msmtp automatically; install it with your package manager."

func smtpEnsureMsmtp() error {
	out, err := safecmd.Exec(context.Background(), "which", "msmtp")
	if err != nil {
		return fmt.Errorf("Failed to check msmtp: %v", err)
	}
	if !out.Success() {
		slog.Info("Installing msmtp...")
		// ponytail: Rust had no timeout here; bounded like every other package install.
		install, err := safecmd.NewUnsandboxed("apt-get").Arg("install", "-y", "msmtp", "msmtp-mta").
			OutputWithTimeout(300 * time.Second)
		if err != nil {
			return fmt.Errorf("Failed to install msmtp: %v", err)
		}
		if !install.Success() {
			return fmt.Errorf("msmtp installation failed: %s", strings.ToValidUTF8(string(install.Stderr), "�"))
		}
	}
	return nil
}

// smtpIsSafeConfigValue rejects newlines/NUL that would allow SMTP header
// injection or config file manipulation.
func smtpIsSafeConfigValue(s string) bool { return !strings.ContainsAny(s, "\n\r\x00") }

// SmtpConfigure configures msmtp system-wide so PHP mail() and sendmail work.
func SmtpConfigure(host string, port uint16, username, password, from, fromName, encryption string) error {
	for _, kv := range [][2]string{{"host", host}, {"username", username}, {"password", password}, {"from", from}, {"from_name", fromName}} {
		if !smtpIsSafeConfigValue(kv[1]) {
			return fmt.Errorf("Invalid %s: contains newline or control characters", kv[0])
		}
	}
	if err := smtpEnsureMsmtp(); err != nil {
		return err
	}
	tls, starttls := "on", "off" // "tls" means implicit TLS, not STARTTLS
	switch encryption {
	case "none":
		tls = "off"
	case "starttls":
		starttls = "on"
	}
	// from_full_name is the only way msmtp puts a display name on the From:
	// header it adds; omitted when blank (msmtp reads "rest of the line").
	fromNameLine := ""
	if fromName != "" {
		fromNameLine = fmt.Sprintf("from_full_name  %s\n", fromName)
	}
	config := fmt.Sprintf(`# DockPanel SMTP configuration — managed automatically
defaults
auth           on
tls            %s
tls_starttls   %s
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

account        default
host           %s
port           %d
from           %s
%suser           %s
password       %s
`, tls, starttls, host, port, from, fromNameLine, username, password)

	// Created 0600 from the outset: create-then-chmod published the password to
	// every local account for the length of the write.
	f, err := os.OpenFile(smtpMsmtpConfig, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err == nil {
		_, err = f.WriteString(config)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		return fmt.Errorf("Failed to write %s: %v", smtpMsmtpConfig, err)
	}
	// The create mode only applies to a NEW file; a 0644 left by an old agent
	// must be repaired, and failing to protect a stored password is fatal.
	if err := os.Chmod(smtpMsmtpConfig, 0o600); err != nil {
		return fmt.Errorf("Failed to restrict %s, which holds the SMTP password: %v", smtpMsmtpConfig, err)
	}

	// PHP must be told where the config is, or mail() falls back to a file
	// that is not there.
	phpIni := []byte("sendmail_path = /usr/bin/msmtp -t --file=" + smtpMsmtpConfig + "\n")
	if _, err := os.Stat("/etc/php/mods-available"); err == nil {
		_ = os.WriteFile("/etc/php/mods-available/msmtp.ini", phpIni, 0o644)
		if entries, err := os.ReadDir("/etc/php"); err == nil {
			for _, e := range entries {
				v := e.Name()
				if strings.HasPrefix(v, "8") || strings.HasPrefix(v, "7") {
					_ = os.WriteFile("/etc/php/"+v+"/fpm/conf.d/99-msmtp.ini", phpIni, 0o644)
					_ = os.WriteFile("/etc/php/"+v+"/cli/conf.d/99-msmtp.ini", phpIni, 0o644)
				}
			}
		}
	}

	// The relay log is written by root (Test Email) and www-data (PHP). 0660
	// root:www-data covers both; the mode only follows a successful chown, so a
	// host without www-data keeps relaying. Only CREATE it — configure runs on
	// every settings save and truncating wiped the history operators debug with.
	const logPath = "/var/log/msmtp.log"
	if _, err := os.Stat(logPath); err != nil {
		_ = os.WriteFile(logPath, nil, 0o644)
	}
	if out, err := safecmd.Exec(context.Background(), "chown", "root:www-data", logPath); err == nil && out.Success() {
		_ = os.Chmod(logPath, 0o660)
	} else {
		slog.Warn("SMTP: no www-data group to own /var/log/msmtp.log, so it stays " +
			"world-writable — PHP relays keep logging, but envelope metadata in " +
			"it is readable by any local account on this host.")
	}
	slog.Info(fmt.Sprintf("SMTP configured: %s:%d from=%s", host, port, from))
	return nil
}

// SmtpSendTest sends a test email via msmtp.
func SmtpSendTest(to, from, fromName string) (string, error) {
	for _, kv := range [][2]string{{"to", to}, {"from", from}, {"from_name", fromName}} {
		if strings.ContainsAny(kv[1], "\r\n\x00") {
			return "", fmt.Errorf("%s must not contain newlines or null bytes", kv[0])
		}
	}
	body := fmt.Sprintf("From: %s <%s>\r\nTo: %s\r\nSubject: DockPanel SMTP Test\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n\r\n"+
		"This is a test email from DockPanel.\r\n"+
		"If you received this, your SMTP configuration is working correctly.\r\n", fromName, from, to)

	// --file is mandatory: the config is not at msmtp's default path.
	ctx := context.Background()
	cmd := safecmd.Command(ctx, "msmtp", "--file", smtpMsmtpConfig, "--read-envelope-from", to)
	cmd.Stdin = strings.NewReader(body)
	out, err := safecmd.Run(ctx, cmd)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			return "", errors.New(SmtpMsmtpMissing)
		}
		return "", fmt.Errorf("Failed to spawn msmtp: %v", err)
	}
	if out.Success() {
		return "Test email sent to " + to, nil
	}
	return "", fmt.Errorf("msmtp failed: %s", strings.ToValidUTF8(string(out.Stderr), "�"))
}
