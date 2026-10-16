package api

// Port of panel/backend/src/services/email.rs (lettre → go-mail).

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	mail "github.com/wneessen/go-mail"
)

// emailSMTPTimeout is lettre's SMTP DEFAULT_TIMEOUT, which the Rust
// transport inherited (it never overrode it).
const emailSMTPTimeout = 60 * time.Second

// EmailSendEmail reads SMTP settings from the DB and sends an email.
// Returns nil if sent, an error carrying the Rust message if SMTP is not
// configured or the send failed.
func EmailSendEmail(ctx context.Context, db Querier, to, subject, bodyHTML string) error {
	// Read SMTP settings from DB
	rows, err := queryAll[Tup2[string, string]](ctx, db, "SELECT key, value FROM settings WHERE key LIKE 'smtp_%'")
	if err != nil {
		return fmt.Errorf("DB error: %v", err)
	}
	get := func(key string) (string, bool) {
		for _, r := range rows {
			if r.A == key {
				return r.B, r.B != ""
			}
		}
		return "", false
	}
	or := func(key, def string) string {
		if v, ok := get(key); ok {
			return v
		}
		return def
	}

	host, ok := get("smtp_host")
	if !ok {
		return errors.New("SMTP not configured")
	}
	port, perr := strconv.ParseUint(or("smtp_port", "587"), 10, 16)
	if perr != nil {
		port = 587
	}
	username, ok := get("smtp_username")
	if !ok {
		return errors.New("SMTP username not configured")
	}
	passwordRaw, ok := get("smtp_password")
	if !ok {
		return errors.New("SMTP password not configured")
	}
	// Decrypt the password (handles legacy plaintext values gracefully)
	password := SecretsCryptoDecryptCredentialFromEnv(passwordRaw)
	fromEmail, ok := get("smtp_from")
	if !ok {
		return errors.New("SMTP from address not configured")
	}
	fromName := or("smtp_from_name", "DockPanel")
	encryption := or("smtp_encryption", "starttls")

	msg := mail.NewMsg()
	if err := msg.From(fmt.Sprintf("%s <%s>", fromName, fromEmail)); err != nil {
		return fmt.Errorf("Invalid from address: %v", err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("Invalid to address: %v", err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextHTML, bodyHTML)

	opts := []mail.Option{
		mail.WithPort(int(port)),
		mail.WithTimeout(emailSMTPTimeout),
		mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
		mail.WithUsername(username),
		mail.WithPassword(password),
	}
	switch encryption {
	case "ssl", "tls":
		// Implicit TLS (lettre Tls::Wrapper), certificate verified against host.
		opts = append(opts, mail.WithSSL())
	default:
		// STARTTLS (default) — required, as lettre's starttls_relay.
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}
	client, err := mail.NewClient(host, opts...)
	if err != nil {
		return fmt.Errorf("SMTP relay error: %v", err)
	}
	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("Failed to send email: %v", err)
	}
	return nil
}

// EmailSendVerificationEmail sends the email verification link.
func EmailSendVerificationEmail(ctx context.Context, db Querier, to, token, baseURL string) error {
	link := fmt.Sprintf("%s/verify-email?token=%s", baseURL, token)
	body := `<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #4f46e5;">Verify your email</h2>
            <p>Click the button below to verify your DockPanel account:</p>
            <p style="margin: 24px 0;">
                <a href="` + link + `" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: 600;">
                    Verify Email
                </a>
            </p>
            <p style="color: #6b7280; font-size: 14px;">Or copy this link: ` + link + `</p>
            <p style="color: #9ca3af; font-size: 12px;">This link expires in 24 hours. If you didn't create an account, ignore this email.</p>
        </div>`
	return EmailSendEmail(ctx, db, to, "Verify your DockPanel account", body)
}

// EmailSendResetEmail sends the password reset link.
func EmailSendResetEmail(ctx context.Context, db Querier, to, token, baseURL string) error {
	link := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token)
	body := `<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #4f46e5;">Reset your password</h2>
            <p>Click the button below to reset your DockPanel password:</p>
            <p style="margin: 24px 0;">
                <a href="` + link + `" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: 600;">
                    Reset Password
                </a>
            </p>
            <p style="color: #6b7280; font-size: 14px;">Or copy this link: ` + link + `</p>
            <p style="color: #9ca3af; font-size: 12px;">This link expires in 1 hour. If you didn't request this, ignore this email.</p>
        </div>`
	return EmailSendEmail(ctx, db, to, "Reset your DockPanel password", body)
}
