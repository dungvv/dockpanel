package api

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

func TestSecretsRoundtripAndNonces(t *testing.T) {
	enc, err := SecretsCryptoEncrypt("my-secret-api-key-value", "test-jwt-secret-12345")
	if err != nil || enc == "my-secret-api-key-value" || len(enc) <= 20 {
		t.Fatal(enc, err)
	}
	if dec, err := SecretsCryptoDecrypt(enc, "test-jwt-secret-12345"); err != nil || dec != "my-secret-api-key-value" {
		t.Fatal(dec, err)
	}
	if _, err := SecretsCryptoDecrypt(enc, "key2"); err == nil {
		t.Fatal("wrong key")
	}
	e1, _ := SecretsCryptoEncrypt("same", "s")
	e2, _ := SecretsCryptoEncrypt("same", "s")
	if e1 == e2 {
		t.Fatal("random nonce")
	}
}

func TestCredentialRoundtripAndSeparation(t *testing.T) {
	enc, _ := SecretsCryptoEncryptCredential("my-db-password-123", "test-jwt-secret")
	if dec, err := SecretsCryptoDecryptCredential(enc, "test-jwt-secret"); err != nil || dec != "my-db-password-123" {
		t.Fatal(dec, err)
	}
	vault, _ := SecretsCryptoEncrypt("v", "same")
	cred, _ := SecretsCryptoEncryptCredential("v", "same")
	if _, err := SecretsCryptoDecryptCredential(vault, "same"); err == nil {
		t.Fatal("vault ciphertext must not open as a credential")
	}
	if _, err := SecretsCryptoDecrypt(cred, "same"); err == nil {
		t.Fatal("credential ciphertext must not open as vault")
	}
}

func TestBackupKeyV2(t *testing.T) {
	k1 := SecretsCryptoDeriveBackupEncryptionKeyV2("production-jwt-secret-value")
	if k1 != SecretsCryptoDeriveBackupEncryptionKeyV2("production-jwt-secret-value") || len(k1) != 64 {
		t.Fatal(k1)
	}
	if _, err := hex.DecodeString(k1); err != nil {
		t.Fatal("plain hex")
	}
	vault := secretsCryptoDeriveKey("same-jwt-secret")
	cred := secretsCryptoDeriveKeyWithSalt("same-jwt-secret", secretsCryptoCredentialJWTSalt)
	backup, _ := hex.DecodeString(SecretsCryptoDeriveBackupEncryptionKeyV2("same-jwt-secret"))
	if slices.Equal(vault[:], backup) || slices.Equal(cred[:], backup) {
		t.Fatal("three subsystems, three keys")
	}
	secret := "SuperSecretJwtSigningKeyThatMustNeverAppearInABackupPassphrase123"
	k := SecretsCryptoDeriveBackupEncryptionKeyV2(secret)
	if strings.Contains(k, secret[:16]) || strings.Contains(k, strings.ToLower(secret)[:16]) {
		t.Fatal("v2 must contain no substring of jwt_secret")
	}
}

func TestLegacyPlaintextFallback(t *testing.T) {
	if SecretsCryptoDecryptCredentialOrLegacy("my-old-plaintext-password", "s") != "my-old-plaintext-password" || SecretsCryptoDecryptCredentialOrLegacy("", "s") != "" {
		t.Fatal()
	}
}

func TestEnvKeyKeepsUnsetPrimaryInBothChains(t *testing.T) {
	env := "an-operator-supplied-key"
	without := secretsCryptoCredentialKeyCandidates("production-jwt-secret", nil)
	with := secretsCryptoCredentialKeyCandidates("production-jwt-secret", &env)
	if !slices.Contains(with, without[0]) {
		t.Fatal("HKDF(jwt) missing once SECRETS_ENCRYPTION_KEY is set — the data-loss bug")
	}
	if !slices.Contains(SecretsCryptoVaultKeySources("production-jwt-secret", &env), SecretsCryptoVaultKeySources("production-jwt-secret", nil)[0]) {
		t.Fatal("vault chain lost the derived source")
	}
}

func TestEnvKeyTakesPrecedence(t *testing.T) {
	env := "operator-key"
	if secretsCryptoCredentialKeyCandidates("jwt", &env)[0] != secretsCryptoDeriveKeyWithSalt("operator-key", secretsCryptoCredentialEnvSalt) {
		t.Fatal("new writes must use the operator's key")
	}
	if SecretsCryptoVaultKeySources("jwt", &env)[0] != "operator-key" {
		t.Fatal()
	}
}

func TestEmptyEnvKeyIsNotAKey(t *testing.T) {
	empty, real := "", "a-real-key"
	if secretsCryptoNormalizeEnvKey(&empty) != nil || *secretsCryptoNormalizeEnvKey(&real) != "a-real-key" || secretsCryptoNormalizeEnvKey(nil) != nil {
		t.Fatal()
	}
}

func TestCiphertextDistinguishableFromLegacyPlaintext(t *testing.T) {
	real, _ := SecretsCryptoEncryptCredential("pw", "jwt")
	if !secretsCryptoLooksLikeCiphertext(real) || secretsCryptoLooksLikeCiphertext("hunter2") || secretsCryptoLooksLikeCiphertext("not base64 at all !!!") {
		t.Fatal()
	}
}

func TestReencrypt(t *testing.T) {
	cur, _ := SecretsCryptoEncryptCredential("pw", "jwt")
	if r, err := SecretsCryptoReencryptCredential(cur, "jwt"); r != nil || err != nil {
		t.Fatal("already under the primary key: no rewrite")
	}
	foreign, _ := SecretsCryptoEncryptCredential("pw", "a-completely-different-jwt")
	if _, err := SecretsCryptoReencryptCredential(foreign, "jwt"); err == nil {
		t.Fatal("an unreadable value must fail loudly, never be rewritten")
	}
	// A legacy (pre-HKDF) credential is rewritten under the primary key.
	legacy, _ := secretsCryptoSeal(secretsCryptoDeriveKeyLegacy("jwt", secretsCryptoCredentialJWTSalt), "old")
	r, err := SecretsCryptoReencryptCredential(legacy, "jwt")
	if err != nil || r == nil {
		t.Fatal(err)
	}
	if p, _ := SecretsCryptoDecryptCredential(*r, "jwt"); p != "old" {
		t.Fatal(p)
	}
}
