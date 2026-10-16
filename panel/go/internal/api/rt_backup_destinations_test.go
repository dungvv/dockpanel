package api

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

const rtBackupDestinationsTestJWT = "test-jwt-secret-at-least-32-bytes-long-for-hkdf"

// The shape an edit takes when the operator changed the bucket but left the
// secret masked.
func TestRtBackupDestinationsAMaskedSecretIsCarriedAcrossNotReEncrypted(t *testing.T) {
	stored, err := rtBackupDestinationsEncryptConfigSecrets(map[string]any{"bucket": "old", "secret_key": "s3cr3t"}, rtBackupDestinationsTestJWT)
	if err != nil {
		t.Fatal(err)
	}
	cipher := stored.(map[string]any)["secret_key"].(string)
	if cipher == "s3cr3t" {
		t.Fatal("precondition: it really was encrypted")
	}
	cfg, _ := rtBackupDestinationsEncryptConfigSecrets(map[string]any{"bucket": "new", "secret_key": "********"}, rtBackupDestinationsTestJWT)
	if cfg.(map[string]any)["secret_key"] != "********" {
		t.Fatal("the sentinel is not encrypted")
	}
	rtBackupDestinationsCarryMaskedSecrets(cfg, stored, []string{"secret_key"})
	m := cfg.(map[string]any)
	if m["bucket"] != "new" {
		t.Fatal(m["bucket"])
	}
	// The bug: merging BEFORE encrypting re-encrypted this ciphertext.
	if m["secret_key"] != cipher {
		t.Fatal("stored ciphertext must come out byte-identical")
	}
	if got, err := SecretsCryptoDecryptCredential(cipher, rtBackupDestinationsTestJWT); err != nil || got != "s3cr3t" {
		t.Fatalf("one decrypt must still recover the original: %q %v", got, err)
	}
}

func TestRtBackupDestinationsARotatedSecretReplacesTheStoredOne(t *testing.T) {
	stored, _ := rtBackupDestinationsEncryptConfigSecrets(map[string]any{"secret_key": "old"}, rtBackupDestinationsTestJWT)
	cfg, _ := rtBackupDestinationsEncryptConfigSecrets(map[string]any{"secret_key": "new"}, rtBackupDestinationsTestJWT)
	rtBackupDestinationsCarryMaskedSecrets(cfg, stored, nil)
	if got, _ := SecretsCryptoDecryptCredential(cfg.(map[string]any)["secret_key"].(string), rtBackupDestinationsTestJWT); got != "new" {
		t.Fatal(got)
	}
}

func TestRtBackupDestinationsAMaskWithNothingStoredIsDroppedNeverPassedThrough(t *testing.T) {
	cfg := map[string]any{"host": "h", "password": "********"}
	rtBackupDestinationsCarryMaskedSecrets(cfg, map[string]any{"host": "h"}, []string{"password"})
	if _, ok := cfg["password"]; ok {
		t.Fatal("the mask must not reach the agent as a credential")
	}
}

func TestRtBackupDestinationsTheAgentPayloadCarriesItsType(t *testing.T) {
	p := rtBackupDestinationsAgentDestinationPayload("sftp", map[string]any{"host": "h"}).(map[string]any)
	if p["type"] != "sftp" || p["host"] != "h" {
		t.Fatal(p)
	}
}

func TestRtBackupDestinationsAnEmptySecretIsRefusedNotStored(t *testing.T) {
	if rtBackupDestinationsRejectEmptySecrets(map[string]any{"secret_key": ""}) == nil ||
		rtBackupDestinationsRejectEmptySecrets(map[string]any{"password": ""}) == nil {
		t.Fatal("empty secrets must be refused")
	}
	for _, ok := range []map[string]any{{"secret_key": "AKIAsecret"}, {"secret_key": rtBackupDestinationsMask}, {"host": "h"}} {
		if err := rtBackupDestinationsRejectEmptySecrets(ok); err != nil {
			t.Fatalf("%v: %v", ok, err)
		}
	}
}

func TestRtBackupDestinationsAStoredKeyTheFormDoesNotSendSurvivesAnEdit(t *testing.T) {
	cfg := map[string]any{"host": "h2", "username": "u"}
	rtBackupDestinationsCarryUnmentionedKeys(cfg, map[string]any{"host": "h1", "username": "u", "key_path": "/root/.ssh/id_ed25519"})
	if cfg["key_path"] != "/root/.ssh/id_ed25519" || cfg["host"] != "h2" {
		t.Fatal(cfg)
	}
}

func TestRtBackupDestinationsCreateAndUpdateDoNotEchoTheStoredSecret(t *testing.T) {
	d := rtBackupDestinationsBackupDestination{ID: uuid.Nil, Name: "d", Dtype: "s3",
		Config:    map[string]any{"bucket": "b", "secret_key": "PLAINTEXT-LEGACY", "password": ""},
		CreatedAt: time.Now(), UpdatedAt: time.Now()}
	rtBackupDestinationsMaskConfigSecrets(&d)
	c := d.Config.(map[string]any)
	if c["secret_key"] != rtBackupDestinationsMask || c["bucket"] != "b" {
		t.Fatal(c)
	}
	// An empty stored value is left alone — masking it would claim a credential exists.
	if c["password"] != "" {
		t.Fatal(c["password"])
	}
}
