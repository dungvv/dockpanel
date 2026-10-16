package services

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestEncryptionTagRoundTrips(t *testing.T) {
	tag := encryptionComputeTag("correct horse battery staple", []byte("some ciphertext bytes"))
	if !encryptionVerifyTag("correct horse battery staple", []byte("some ciphertext bytes"), tag) {
		t.Fatal("round trip failed")
	}
}

func TestEncryptionTagRejectsWrongKey(t *testing.T) {
	tag := encryptionComputeTag("key-a", []byte("some ciphertext bytes"))
	if encryptionVerifyTag("key-b", []byte("some ciphertext bytes"), tag) {
		t.Fatal("wrong key accepted")
	}
}

func TestEncryptionTagRejectsTamperedCiphertext(t *testing.T) {
	tag := encryptionComputeTag("key", []byte("some ciphertext bytes"))
	if encryptionVerifyTag("key", []byte("some tampered!! bytes"), tag) {
		t.Fatal("tampered accepted")
	}
}

func TestEncryptionTagRejectsTruncatedCiphertext(t *testing.T) {
	tag := encryptionComputeTag("key", []byte("some ciphertext bytes"))
	if encryptionVerifyTag("key", []byte("some ciphertext"), tag) {
		t.Fatal("truncated accepted")
	}
	if encryptionVerifyTag("key", []byte("some ciphertext bytes"), tag[:16]) {
		t.Fatal("truncated tag accepted")
	}
}

func TestEncryptionMacKeyIsIndependentPerPassphrase(t *testing.T) {
	if bytes.Equal(encryptionDeriveMacKey("key-a"), encryptionDeriveMacKey("key-b")) {
		t.Fatal("same key for different passphrases")
	}
}

// Byte-compatibility pin with files the Rust agent wrote: tag =
// HMAC(HMAC(pass, "dockpanel-backup-hmac-v1"), ciphertext).
func TestEncryptionTagFormatIsNestedHmac(t *testing.T) {
	k := hmac.New(sha256.New, []byte("pw"))
	k.Write([]byte("dockpanel-backup-hmac-v1"))
	m := hmac.New(sha256.New, k.Sum(nil))
	m.Write([]byte("ct"))
	if got := encryptionComputeTag("pw", []byte("ct")); hex.EncodeToString(got) != hex.EncodeToString(m.Sum(nil)) || len(got) != encryptionMacTagLen {
		t.Fatal("tag format drifted")
	}
}

func TestEncryptionValidateBackupPath(t *testing.T) {
	for _, p := range []string{"/tmp/x", "/var/backups/dockpanel/../../etc/shadow", "/var/backups/dockpanelx/a", "var/backups/dockpanel/a"} {
		if encryptionValidateBackupPath(p) == nil {
			t.Errorf("%q accepted", p)
		}
	}
	if err := encryptionValidateBackupPath("/var/backups/dockpanel/site/a.tar.gz"); err != nil {
		t.Error(err)
	}
}
