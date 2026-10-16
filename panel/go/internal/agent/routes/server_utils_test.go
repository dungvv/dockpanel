package routes

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestServerUtilsValidateKey(t *testing.T) {
	good := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc user@host"
	cases := map[string]string{
		good:                       "",
		good + "\nssh-rsa AAAA":    "SSH key must be a single line",
		"rsa AAAAC3NzaC1lZDI1NTE5": "Invalid SSH key format",
		"ssh-ed25519 short":        "Invalid SSH key: missing key data",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 restrict": "SSH key options not allowed",
		"ssh-rsa AAAAC3NzaC1lZDI1NTE5 command=x":    "SSH key options not allowed",
	}
	for in, want := range cases {
		if got := serverUtilsValidateKey(in); got != want {
			t.Errorf("validate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServerUtilsFingerprintMatchesOpenSSHShape(t *testing.T) {
	raw := []byte("keybytes")
	sum := sha256.Sum256(raw)
	want := "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
	if got := serverUtilsFingerprint(base64.StdEncoding.EncodeToString(raw)); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestServerUtilsRemoveKeyLinesKeepsOthersAndComments(t *testing.T) {
	a := base64.StdEncoding.EncodeToString([]byte("aaaa"))
	b := base64.StdEncoding.EncodeToString([]byte("bbbb"))
	in := "# c\nssh-ed25519 " + a + " one\n\nssh-ed25519 " + b + " two\n"
	got := serverUtilsRemoveKeyLines(in, serverUtilsFingerprint(a))
	if got != "# c\n\nssh-ed25519 "+b+" two" {
		t.Fatalf("got %q", got)
	}
}
