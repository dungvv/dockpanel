// Package agenttls loads (or generates) the self-signed cert used for
// inbound TLS, and exposes the SHA-256 fingerprint of the DER-encoded cert so
// the central panel can pin it (Trust On First Use).
//
// Cert location: /etc/dockpanel/ssl/agent.{crt,key}. install-agent.sh
// generates these at install time via openssl; this generates them at first
// boot if missing (dev / direct-binary installs).
package agenttls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"
)

const (
	sslDir   = "/etc/dockpanel/ssl"
	certPath = sslDir + "/agent.crt"
	keyPath  = sslDir + "/agent.key"
)

// LoadOrGenerate loads the on-disk cert + key, generating a fresh pair if
// either is missing. Returns the TLS config plus the hex SHA-256 fingerprint
// of the cert's DER bytes.
func LoadOrGenerate() (*tls.Config, string, error) {
	if !exists(certPath) || !exists(keyPath) {
		if err := generateSelfSigned(); err != nil {
			return nil, "", err
		}
		slog.Info("Generated agent TLS cert at " + certPath)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", keyPath, err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, "", fmt.Errorf("build TLS config: %w", err)
	}
	fp, err := FingerprintFromPEM(certPEM)
	if err != nil {
		return nil, "", err
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, fp, nil
}

// FingerprintFromPEM is SHA-256 of the first certificate's DER bytes,
// lowercase hex.
func FingerprintFromPEM(data []byte) (string, error) {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return "", errors.New("no certificate in PEM")
		}
		if b.Type == "CERTIFICATE" {
			sum := sha256.Sum256(b.Bytes)
			return hex.EncodeToString(sum[:]), nil
		}
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// generateSelfSigned mirrors rcgen::generate_simple_self_signed: ECDSA P-256,
// SAN dockpanel-agent.
func generateSelfSigned() error {
	certPEM, keyPEM, err := selfSigned()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sslDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", sslDir, err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", keyPath, err)
	}
	_ = os.Chmod(keyPath, 0o600)
	_ = os.Chmod(certPath, 0o644)
	return nil
}

func selfSigned() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("keygen: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	// rcgen defaults: 1975-01-01 .. 4096-01-01, CN "rcgen self signed cert".
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "rcgen self signed cert"},
		NotBefore:    time.Date(1975, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(4096, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{"dockpanel-agent"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}
