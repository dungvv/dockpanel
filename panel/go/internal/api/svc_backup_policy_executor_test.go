package api

import "testing"

// s248 / lesson #70: encrypt and restore MUST derive the backup key from the
// same single source of truth.
func TestBackupPolicyExecutorBackupKeyDerivationIsStable(t *testing.T) {
	jwt := "abcdefghijklmnopqrstuvwxyz0123456789EXTRA"
	if BackupPolicyExecutorDeriveBackupEncryptionKey(jwt) != BackupPolicyExecutorDeriveBackupEncryptionKey(jwt) {
		t.Fatal("same jwt_secret must derive the same key every time")
	}
}

func TestBackupPolicyExecutorBackupKeyDerivationHandlesShortSecret(t *testing.T) {
	_ = BackupPolicyExecutorDeriveBackupEncryptionKey("short") // must not panic
}

func TestBackupPolicyExecutorEncryptAndRestoreDeriveIdenticalKey(t *testing.T) {
	s := "the-process-jwt-secret-value-000000000000"
	if BackupPolicyExecutorDeriveBackupEncryptionKey(s) != BackupPolicyExecutorDeriveBackupEncryptionKey(s) {
		t.Fatal("identical input must give identical output")
	}
}

// A backup written before s434 has encryption_key_version = 1; restore must
// reproduce EXACTLY what v1 wrote.
func TestBackupPolicyExecutorVersion1ReproducesTheExactLegacyFormat(t *testing.T) {
	jwt := "abcdefghijklmnopqrstuvwxyz0123456789EXTRA"
	if got := BackupPolicyExecutorDeriveBackupEncryptionKeyForVersion(1, jwt); got != "backup-enc-abcdefghijklmnopqrstuvwxyz012345" {
		t.Fatal(got)
	}
	if got := BackupPolicyExecutorDeriveBackupEncryptionKeyForVersion(1, "short"); got != "backup-enc-short" {
		t.Fatal(got)
	}
}

func TestBackupPolicyExecutorCurrentVersionConstantMatchesTheDefaultDerivation(t *testing.T) {
	jwt := "some-jwt-secret"
	if BackupPolicyExecutorDeriveBackupEncryptionKeyForVersion(BackupPolicyExecutorCurrentBackupKeyVersion, jwt) != BackupPolicyExecutorDeriveBackupEncryptionKey(jwt) {
		t.Fatal("DeriveBackupEncryptionKey must always mean 'the CURRENT version'")
	}
}

func TestBackupPolicyExecutorVersion1AndVersion2DeriveDifferentKeys(t *testing.T) {
	jwt := "same-jwt-secret-both-versions"
	if BackupPolicyExecutorDeriveBackupEncryptionKeyForVersion(1, jwt) == BackupPolicyExecutorDeriveBackupEncryptionKeyForVersion(2, jwt) {
		t.Fatal("v1 and v2 must not collide")
	}
}

func TestBackupPolicyExecutorUnknownVersionFallsThroughToCurrentNotAPanic(t *testing.T) {
	jwt := "some-jwt-secret"
	if BackupPolicyExecutorDeriveBackupEncryptionKeyForVersion(99, jwt) != BackupPolicyExecutorDeriveBackupEncryptionKey(jwt) {
		t.Fatal("an unrecognised version must derive the current key")
	}
}
