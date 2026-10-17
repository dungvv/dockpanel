package api

import (
	"encoding/hex"
	"testing"
)

// backup-truth §13b: the v2 backup passphrase is the salted HKDF of the JWT
// secret — not the legacy plain-SHA-256 derivation, not a raw slice.
func TestPinBackupTruthV2BackupKeyIsTheSaltedHKDF(t *testing.T) {
	for _, s := range []string{"production-jwt-secret-value", "short"} {
		hkdf := secretsCryptoDeriveKeyWithSalt(s, secretsCryptoBackupSalt)
		legacy := secretsCryptoDeriveKeyLegacy(s, secretsCryptoBackupSalt)
		got := SecretsCryptoDeriveBackupEncryptionKeyV2(s)
		if got != hex.EncodeToString(hkdf[:]) {
			t.Fatalf("v2(%q) is not hex(HKDF(secret, backup salt))", s)
		}
		if got == hex.EncodeToString(legacy[:]) {
			t.Fatalf("v2(%q) equals the legacy SHA-256 derivation", s)
		}
	}
}
