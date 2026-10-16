package services

import (
	"testing"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

func TestCrontabAbsentCrontabIsEmptyNotAnError(t *testing.T) {
	s, err := crontabClassify(safecmd.Output{Stderr: []byte("no crontab for root\n"), ExitCode: 1})
	if err != nil || s != "" {
		t.Fatalf("got %q, %v", s, err)
	}
}

func TestCrontabEveryOtherFailureRefuses(t *testing.T) {
	for _, c := range []struct {
		stderr string
		code   int
	}{{"must be privileged to use -u", 1}, {"", 127}, {"Resource temporarily unavailable", 1}, {"", -1}} {
		if _, err := crontabClassify(safecmd.Output{Stderr: []byte(c.stderr), ExitCode: c.code}); err == nil {
			t.Errorf("%q/%d: expected refusal", c.stderr, c.code)
		}
	}
}

func TestCrontabSuccessReturnsStdout(t *testing.T) {
	s, err := crontabClassify(safecmd.Output{Stdout: []byte("* * * * * x\n")})
	if err != nil || s != "* * * * * x\n" {
		t.Fatalf("got %q, %v", s, err)
	}
}

// A missing binary must not present as a successful empty read — the old
// unwrap_or_default shape wrote "" back as root's complete crontab.
func TestCrontabReaderNeverYieldsEmptyOnAMissingBinary(t *testing.T) {
	if _, err := crontabReadBin("dockpanel-no-such-crontab-binary"); err == nil {
		t.Fatal("a missing crontab binary must not present as a successful empty read")
	}
}
