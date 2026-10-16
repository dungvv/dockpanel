package services

import (
	"strings"
	"testing"

	"github.com/GehirnInc/crypt"
)

// glibc's crypt() truncates a SHA-crypt salt to 16 characters on verify, so a
// longer one makes every correct password fail forever.
func TestTheGeneratedSaltIsAtMostSixteenCharacters(t *testing.T) {
	hash, err := sftpAccountsHash("irrelevant-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$6$") {
		t.Fatalf("not sha512-crypt: %s", hash)
	}
	fields := strings.Split(hash, "$")
	if salt := fields[len(fields)-2]; len(salt) > 16 {
		t.Fatalf("salt field %q is %d characters", salt, len(salt))
	}
}

func TestAProducedHashVerifiesAgainstThePasswordThatMadeIt(t *testing.T) {
	hash, err := sftpAccountsHash("a-real-looking-password-123")
	if err != nil {
		t.Fatal(err)
	}
	c := crypt.SHA512.New()
	if err := c.Verify(hash, []byte("a-real-looking-password-123")); err != nil {
		t.Fatal(err)
	}
	if c.Verify(hash, []byte("a-different-password")) == nil {
		t.Fatal("a wrong password verified")
	}
}

// Known-answer check against glibc's own output for crypt("password", "$6$saltsalt$").
func TestHashMatchesGlibcKnownAnswer(t *testing.T) {
	got, err := crypt.SHA512.New().Generate([]byte("password"), []byte("$6$saltsalt"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	if got != want {
		t.Fatalf("got %s", got)
	}
}
