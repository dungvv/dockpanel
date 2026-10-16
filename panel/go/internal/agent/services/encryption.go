package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// encryptionValidateBackupPath requires a path within the backup directory
// with no traversal.
func encryptionValidateBackupPath(filepath string) error {
	if !strings.HasPrefix(filepath, "/var/backups/dockpanel/") {
		return fmt.Errorf("Path must be within /var/backups/dockpanel/")
	}
	if strings.Contains(filepath, "..") {
		return fmt.Errorf("Path must not contain '..'")
	}
	return nil
}

// Appended after the ciphertext of every encrypted file: a 32-byte
// HMAC-SHA256 tag over the ciphertext, then this 8-byte marker. AES-256-CBC
// alone has no integrity check — PKCS7 padding bounds only the final block,
// so an earlier bit-flip decrypts silently into corrupted plaintext.
// Encrypt-then-MAC: EncryptionDecryptFile verifies the tag before openssl
// ever sees the ciphertext.
//
// A backup made before the tag existed has no trailer (odds its last 8 bytes
// equal the marker are 1 in 2^64); that absence means "predates the
// integrity tag" and falls back to the old unauthenticated decrypt.
const (
	encryptionMacMagic      = "DPHMAC01"
	encryptionMacTagLen     = 32
	encryptionMacTrailerLen = encryptionMacTagLen + 8
)

// encryptionDeriveMacKey derives a MAC key from the backup passphrase,
// independent of the AES key openssl -pbkdf2 derives internally. Domain-
// separated by a fixed label so the tag can't become an oracle against the
// encryption key.
func encryptionDeriveMacKey(passphrase string) []byte {
	m := hmac.New(sha256.New, []byte(passphrase))
	m.Write([]byte("dockpanel-backup-hmac-v1"))
	return m.Sum(nil)
}

func encryptionComputeTag(passphrase string, ciphertext []byte) []byte {
	m := hmac.New(sha256.New, encryptionDeriveMacKey(passphrase))
	m.Write(ciphertext)
	return m.Sum(nil)
}

// encryptionVerifyTag compares in constant time.
func encryptionVerifyTag(passphrase string, ciphertext, tag []byte) bool {
	return hmac.Equal(encryptionComputeTag(passphrase, ciphertext), tag)
}

// encryptionOpenssl runs openssl with the key on stdin (never argv, which is
// visible in the process list), bounded by 10 minutes.
func encryptionOpenssl(key, verb string, args ...string) (safecmd.Output, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()
	cmd := safecmd.Command(ctx, "openssl", args...)
	cmd.Stdin = strings.NewReader(key)
	out, err := safecmd.Run(ctx, cmd)
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out (10 minutes)", verb)
	}
	if err != nil {
		return out, fmt.Errorf("Failed to run openssl: %v", err)
	}
	return out, nil
}

// EncryptionEncryptFile encrypts a file with AES-256-CBC + PBKDF2 (openssl),
// then appends an HMAC-SHA256 tag over the ciphertext. Returns the path of
// the encrypted file (original + ".enc"); the original is removed.
func EncryptionEncryptFile(filepath, key string) (string, error) {
	if err := encryptionValidateBackupPath(filepath); err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath); err != nil {
		return "", fmt.Errorf("File not found: %s", filepath)
	}
	encPath := filepath + ".enc"
	out, err := encryptionOpenssl(key, "Encryption", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "100000",
		"-in", filepath, "-out", encPath, "-pass", "stdin")
	if err != nil {
		return "", err
	}
	if !out.Success() {
		os.Remove(encPath)
		return "", fmt.Errorf("Encryption failed: %s", strings.ToValidUTF8(string(out.Stderr), "�"))
	}
	ciphertext, err := os.ReadFile(encPath)
	if err != nil {
		return "", fmt.Errorf("Failed to read encrypted file: %v", err)
	}
	if len(ciphertext) == 0 {
		os.Remove(encPath)
		return "", fmt.Errorf("Encryption produced empty output")
	}
	// Tag over the ciphertext as openssl wrote it, so verification needs no
	// knowledge of openssl internals — only the shared passphrase.
	trailer := append(encryptionComputeTag(key, ciphertext), encryptionMacMagic...)
	f, err := os.OpenFile(encPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return "", fmt.Errorf("Failed to open encrypted file to append integrity tag: %v", err)
	}
	if _, err := f.Write(trailer); err != nil {
		f.Close()
		return "", fmt.Errorf("Failed to write integrity tag: %v", err)
	}
	f.Close()
	os.Remove(filepath)
	slog.Info(fmt.Sprintf("File encrypted: %s (%d bytes)", encPath, len(ciphertext)+len(trailer)))
	return encPath, nil
}

// EncryptionDecryptFile decrypts an encrypted file and returns the decrypted
// path. Verify-then-decrypt: a tampered ciphertext is rejected without ever
// running it through openssl. A file with no tag (pre-integrity-fix) is
// decrypted as before, unauthenticated.
func EncryptionDecryptFile(encFilepath, key string) (string, error) {
	if err := encryptionValidateBackupPath(encFilepath); err != nil {
		return "", err
	}
	if _, err := os.Stat(encFilepath); err != nil {
		return "", fmt.Errorf("File not found: %s", encFilepath)
	}
	raw, err := os.ReadFile(encFilepath)
	if err != nil {
		return "", fmt.Errorf("Failed to read encrypted file: %v", err)
	}
	hasTag := len(raw) >= encryptionMacTrailerLen && string(raw[len(raw)-len(encryptionMacMagic):]) == encryptionMacMagic

	// With a tag, decrypt a scratch copy of just the ciphertext (openssl's
	// CBC framing does not tolerate the 40 trailer bytes). Legacy files are
	// decrypted from their own path, unchanged.
	input := encFilepath
	if hasTag {
		split := len(raw) - encryptionMacTrailerLen
		ciphertext, tag := raw[:split], raw[split:split+encryptionMacTagLen]
		if !encryptionVerifyTag(key, ciphertext, tag) {
			return "", fmt.Errorf("Backup integrity check failed — the file may be corrupted or tampered with")
		}
		var rb [8]byte
		_, _ = rand.Read(rb[:])
		input = fmt.Sprintf("%s.%016x.stripped", encFilepath, binary.LittleEndian.Uint64(rb[:]))
		if err := os.WriteFile(input, ciphertext, 0o644); err != nil {
			os.Remove(input)
			return "", fmt.Errorf("Failed to stage ciphertext for decryption: %v", err)
		}
		defer os.Remove(input)
	} else {
		slog.Warn(fmt.Sprintf("Decrypting %s without an integrity tag (backup predates the integrity fix) — cannot verify it wasn't tampered with", encFilepath))
	}

	decPath := encFilepath + ".dec"
	if strings.HasSuffix(encFilepath, ".enc") {
		decPath = strings.TrimSuffix(encFilepath, ".enc")
	}
	out, err := encryptionOpenssl(key, "Decryption", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
		"-in", input, "-out", decPath, "-pass", "stdin")
	if err != nil {
		return "", err
	}
	if !out.Success() {
		os.Remove(decPath)
		return "", fmt.Errorf("Decryption failed: %s", strings.ToValidUTF8(string(out.Stderr), "�"))
	}
	st, err := os.Stat(decPath)
	if err != nil {
		return "", fmt.Errorf("Failed to read decrypted file: %v", err)
	}
	if st.Size() == 0 {
		os.Remove(decPath)
		return "", fmt.Errorf("Decryption produced empty output")
	}
	slog.Info(fmt.Sprintf("File decrypted: %s (%d bytes)", decPath, st.Size()))
	return decPath, nil
}
