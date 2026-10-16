package agenttls

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestSelfSignedPairLoadsAndFingerprintsTheDER(t *testing.T) {
	c, k, err := selfSigned()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(c, k); err != nil {
		t.Fatalf("generated pair does not load: %v", err)
	}
	fp, err := FingerprintFromPEM(c)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(c)
	sum := sha256.Sum256(b.Bytes)
	if fp != hex.EncodeToString(sum[:]) || len(fp) != 64 {
		t.Fatalf("fingerprint %q is not lowercase hex sha256 of the DER", fp)
	}
	if _, err := FingerprintFromPEM([]byte("nope")); err == nil {
		t.Fatal("garbage PEM must be an error")
	}
}
