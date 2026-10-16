package api

// Port of panel/backend/src/services/secrets_crypto.rs — AES-256-GCM for the
// Secrets Manager vault and for stored credentials. Ported with the
// foundation because AgentRegistry (the dial-out token) and cfHeaders depend
// on it.
//
// Keys derive from JWT_SECRET (or SECRETS_ENCRYPTION_KEY) with distinct salts
// for separation of concerns. Each value gets a random 12-byte nonce,
// prepended to the ciphertext. Format: base64(nonce || ciphertext || tag).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"unicode/utf8"

	"golang.org/x/crypto/hkdf"
)

// SecretsCryptoEncryptionKeyEnv overrides key derivation for BOTH the
// credential path and the Secrets Manager vault.
const SecretsCryptoEncryptionKeyEnv = "SECRETS_ENCRYPTION_KEY"

var (
	secretsCryptoVaultSalt         = []byte("dockpanel-secrets-v1:")
	secretsCryptoCredentialJWTSalt = []byte("dockpanel-credential-v1:")
	secretsCryptoCredentialEnvSalt = []byte("dockpanel-credential-encryption-v1:")
	secretsCryptoVaultSourceSalt   = []byte("dockpanel-secrets-encryption:")
	secretsCryptoBackupSalt        = []byte("dockpanel-backup-encryption-v2:")
)

// Rust's base64 STANDARD engine rejects non-canonical trailing bits.
var secretsCryptoB64 = base64.StdEncoding.Strict()

// secretsCryptoNormalizeEnvKey treats **set-but-empty as unset**. Not
// cosmetic: `SECRETS_ENCRYPTION_KEY=` (what a half-filled api.env produces)
// once keyed the whole vault off the empty string while the credential path
// treated it as unset. Split out so a test drives THE guard.
func secretsCryptoNormalizeEnvKey(raw *string) *string {
	if raw == nil || *raw == "" {
		return nil
	}
	return raw
}

func secretsCryptoKeyOverride() *string {
	v, ok := os.LookupEnv(SecretsCryptoEncryptionKeyEnv)
	if !ok {
		return nil
	}
	return secretsCryptoNormalizeEnvKey(&v)
}

// Legacy key derivation (SHA-256 only) — kept for decrypting existing data.
func secretsCryptoDeriveKeyLegacy(secret string, salt []byte) [32]byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(secret))
	var k [32]byte
	copy(k[:], h.Sum(nil))
	return k
}

// HKDF-SHA256(salt, secret), info "dockpanel-encryption" — proper
// extract-then-expand, unlike raw SHA-256.
func secretsCryptoDeriveKeyWithSalt(secret string, salt []byte) [32]byte {
	var k [32]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(secret), salt, []byte("dockpanel-encryption")), k[:]); err != nil {
		panic("HKDF expand failed: output length is valid")
	}
	return k
}

// The argument is a vault key SOURCE (SecretsCryptoVaultKeyPrimary's output).
func secretsCryptoDeriveKey(keySource string) [32]byte {
	return secretsCryptoDeriveKeyWithSalt(keySource, secretsCryptoVaultSalt)
}

// secretsCryptoCredentialKeyCandidates is every key a CREDENTIAL ciphertext
// could have been written under, in try order; [0] is what we write with.
//
// ⚠ Deliberately a UNION, never an if/else. Until v2.112.0 it yielded ONE key
// per process: with SECRETS_ENCRYPTION_KEY set it returned HKDF(env), and
// HKDF(jwt) — the key every existing install had actually encrypted with —
// appeared in no arm of the decrypt chain. Setting the variable on a running
// panel was silent, irreversible data loss. envKey is a parameter so the
// ordering is testable without mutating process environment.
func secretsCryptoCredentialKeyCandidates(jwtSecret string, envKey *string) [][32]byte {
	keys := make([][32]byte, 0, 4)
	if envKey != nil {
		keys = append(keys, secretsCryptoDeriveKeyWithSalt(*envKey, secretsCryptoCredentialEnvSalt))
	}
	// UNCONDITIONAL: what production encrypts with when the variable is unset.
	keys = append(keys, secretsCryptoDeriveKeyWithSalt(jwtSecret, secretsCryptoCredentialJWTSalt))
	keys = append(keys, secretsCryptoDeriveKeyLegacy(jwtSecret, secretsCryptoCredentialJWTSalt))
	if envKey != nil {
		keys = append(keys, secretsCryptoDeriveKeyLegacy(*envKey, secretsCryptoCredentialEnvSalt))
	}
	return keys
}

// SecretsCryptoVaultKeySources is every key SOURCE a VAULT ciphertext could
// have been written under — same defect, second subsystem: setting the env var
// once stranded every vault secret (CMS admin passwords, deploy env values).
func SecretsCryptoVaultKeySources(jwtSecret string, envKey *string) []string {
	s := make([]string, 0, 2)
	if envKey != nil {
		s = append(s, *envKey)
	}
	k := secretsCryptoDeriveKeyLegacy(jwtSecret, secretsCryptoVaultSourceSalt)
	return append(s, hex.EncodeToString(k[:])) // UNCONDITIONAL
}

// SecretsCryptoVaultKeyPrimary is the vault key source to ENCRYPT with.
func SecretsCryptoVaultKeyPrimary(jwtSecret string) string {
	return SecretsCryptoVaultKeySources(jwtSecret, secretsCryptoKeyOverride())[0]
}

// SecretsCryptoDeriveBackupEncryptionKeyV2 is the v2 backup passphrase,
// hex(HKDF(jwt_secret, backup salt)). v1 was a literal substring of
// JWT_SECRET — the session signing key — so one leaked backup passphrase
// forged every session. HKDF is one-way: this reveals nothing about the secret.
func SecretsCryptoDeriveBackupEncryptionKeyV2(jwtSecret string) string {
	k := secretsCryptoDeriveKeyWithSalt(jwtSecret, secretsCryptoBackupSalt)
	return hex.EncodeToString(k[:])
}

// secretsCryptoLooksLikeCiphertext: 12-byte nonce + 16-byte tag is the floor.
// This is what lets a failed decrypt be classified ("never encrypted" vs
// "encrypted under a key I cannot derive") instead of swallowed.
func secretsCryptoLooksLikeCiphertext(v string) bool {
	b, err := secretsCryptoB64.DecodeString(v)
	return err == nil && len(b) >= 12+16
}

func secretsCryptoSeal(key [32]byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("Cipher init failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("Cipher init failed: %v", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("Encryption failed: %v", err)
	}
	return secretsCryptoB64.EncodeToString(gcm.Seal(nonce, nonce, []byte(plaintext), nil)), nil
}

func secretsCryptoOpen(key [32]byte, nonce, ct []byte) ([]byte, bool) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	p, err := gcm.Open(nil, nonce, ct, nil)
	return p, err == nil
}

func secretsCryptoUTF8(p []byte) (string, error) {
	if !utf8.Valid(p) {
		return "", errors.New("UTF-8 decode failed: invalid utf-8 sequence")
	}
	return string(p), nil
}

// SecretsCryptoEncrypt encrypts with a vault key source.
func SecretsCryptoEncrypt(plaintext, jwtSecret string) (string, error) {
	return secretsCryptoSeal(secretsCryptoDeriveKey(jwtSecret), plaintext)
}

// SecretsCryptoDecrypt decrypts with one vault key source: HKDF key first,
// then the legacy SHA-256 key for data encrypted before the HKDF migration.
func SecretsCryptoDecrypt(encryptedB64, jwtSecret string) (string, error) {
	combined, err := secretsCryptoB64.DecodeString(encryptedB64)
	if err != nil {
		return "", fmt.Errorf("Base64 decode failed: %v", err)
	}
	if len(combined) < 12 {
		return "", errors.New("Ciphertext too short")
	}
	nonce, ct := combined[:12], combined[12:]
	if p, ok := secretsCryptoOpen(secretsCryptoDeriveKey(jwtSecret), nonce, ct); ok {
		return secretsCryptoUTF8(p)
	}
	if p, ok := secretsCryptoOpen(secretsCryptoDeriveKeyLegacy(jwtSecret, secretsCryptoVaultSalt), nonce, ct); ok {
		return secretsCryptoUTF8(p)
	}
	return "", errors.New("Decryption failed (wrong key or corrupted data)")
}

// SecretsCryptoEncryptCredential encrypts a credential (DB/SMTP password,
// DKIM key, agent token…) under the current primary credential key.
func SecretsCryptoEncryptCredential(plaintext, jwtSecret string) (string, error) {
	return secretsCryptoSeal(secretsCryptoCredentialKeyCandidates(jwtSecret, secretsCryptoKeyOverride())[0], plaintext)
}

// secretsCryptoTryKeys: (plaintext, true, nil) on success; ("", false, nil)
// when well-formed but no key opens it; err when it was never our ciphertext.
// Only the middle case means "encrypted with a key this process cannot derive".
func secretsCryptoTryKeys(encryptedB64 string, keys [][32]byte) (string, bool, error) {
	combined, err := secretsCryptoB64.DecodeString(encryptedB64)
	if err != nil {
		return "", false, fmt.Errorf("Base64 decode failed: %v", err)
	}
	if len(combined) < 12 {
		return "", false, errors.New("Ciphertext too short")
	}
	for _, k := range keys {
		if p, ok := secretsCryptoOpen(k, combined[:12], combined[12:]); ok {
			s, err := secretsCryptoUTF8(p)
			return s, err == nil, err
		}
	}
	return "", false, nil
}

// SecretsCryptoDecryptCredential tries every credential derivation, so a
// panel that gains (or loses) SECRETS_ENCRYPTION_KEY can still read
// everything it wrote before.
func SecretsCryptoDecryptCredential(encryptedB64, jwtSecret string) (string, error) {
	p, ok, err := secretsCryptoTryKeys(encryptedB64, secretsCryptoCredentialKeyCandidates(jwtSecret, secretsCryptoKeyOverride()))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("Decryption failed (wrong key or corrupted data)")
	}
	return p, nil
}

// SecretsCryptoDecryptVault tries every vault key source. Takes the RAW jwt
// secret — deriving one source and handing it to Decrypt is precisely what
// made setting SECRETS_ENCRYPTION_KEY unsurvivable for the vault.
func SecretsCryptoDecryptVault(encryptedB64, jwtSecret string) (string, error) {
	var keys [][32]byte
	for _, src := range SecretsCryptoVaultKeySources(jwtSecret, secretsCryptoKeyOverride()) {
		keys = append(keys, secretsCryptoDeriveKeyWithSalt(src, secretsCryptoVaultSalt), secretsCryptoDeriveKeyLegacy(src, secretsCryptoVaultSalt))
	}
	p, ok, err := secretsCryptoTryKeys(encryptedB64, keys)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("Decryption failed (wrong key or corrupted data)")
	}
	return p, nil
}

// SecretsCryptoReencryptCredential re-encrypts under the CURRENT primary key:
// (nil, nil) when already readable under it, an error when no candidate opens
// it — silently rewriting such a value would destroy the only copy.
func SecretsCryptoReencryptCredential(encryptedB64, jwtSecret string) (*string, error) {
	cands := secretsCryptoCredentialKeyCandidates(jwtSecret, secretsCryptoKeyOverride())
	if _, ok, err := secretsCryptoTryKeys(encryptedB64, cands[:1]); err != nil {
		return nil, err
	} else if ok {
		return nil, nil
	}
	p, ok, err := secretsCryptoTryKeys(encryptedB64, cands)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("no candidate key opens this value")
	}
	s, err := SecretsCryptoEncryptCredential(p, jwtSecret)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// SecretsCryptoReencryptVault is the vault twin of ReencryptCredential.
func SecretsCryptoReencryptVault(encryptedB64, jwtSecret string) (*string, error) {
	primary := SecretsCryptoVaultKeyPrimary(jwtSecret)
	// Single-source read, deliberately: "can the PRIMARY key open this?"
	if _, err := SecretsCryptoDecrypt(encryptedB64, primary); err == nil {
		return nil, nil
	}
	p, err := SecretsCryptoDecryptVault(encryptedB64, jwtSecret)
	if err != nil {
		return nil, err
	}
	s, err := SecretsCryptoEncrypt(p, primary)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// SecretsCryptoDecryptCredentialOrLegacy decrypts, falling back to the value
// itself for legacy unencrypted rows.
//
// ⚠ THE FALLBACK IS LOAD-BEARING AND IT IS ALSO THE FAILURE MODE. Callers use
// the return value AS a password. For a legacy plaintext that is right; for
// our own ciphertext that no key opens it hands back base64 where a password
// belongs (remote auth fails with no panel-side log; TOTP sites hard-fail into
// a 2FA lockout). looksLikeCiphertext separates the cases so a key failure is
// LOUD. The signature stays fail-open on purpose — say what happened, do not
// silently change what callers receive.
func SecretsCryptoDecryptCredentialOrLegacy(value, jwtSecret string) string {
	if value == "" {
		return value
	}
	p, err := SecretsCryptoDecryptCredential(value, jwtSecret)
	if err == nil {
		return p
	}
	if secretsCryptoLooksLikeCiphertext(value) {
		slog.Error(fmt.Sprintf("Stored credential is well-formed ciphertext that NO key derivation opens. "+
			"Returning the stored value verbatim — callers will receive base64 text where a credential belongs, "+
			"and any service they authenticate against will reject it. This almost always means %s was added, "+
			"changed or removed on a panel that already held encrypted data. Restore the previous value to "+
			"recover, then re-key deliberately.", SecretsCryptoEncryptionKeyEnv), "error", err)
	}
	return value
}

// SecretsCryptoDecryptCredentialFromEnv uses JWT_SECRET from the environment,
// for contexts without AppState (email service, notifications).
func SecretsCryptoDecryptCredentialFromEnv(value string) string {
	if value == "" {
		return value
	}
	jwt, ok := os.LookupEnv("JWT_SECRET")
	if !ok {
		return value
	}
	return SecretsCryptoDecryptCredentialOrLegacy(value, jwt)
}
