package cli

import (
	"io"
	"os"
	"slices"
	"strings"
	"testing"
)

// cli-password-args §A/§B: on both password-taking commands --password is an
// optional value flag, --password-stdin is a boolean, and the two conflict.
func TestPinCliPasswordArgsFlags(t *testing.T) {
	for _, path := range [][]string{{"db", "create"}, {"backup", "db-create"}} {
		s := specs[find(t, path...)]
		if s == nil {
			t.Fatalf("%v: no spec", path)
		}
		var pw, stdin *flagDef
		for i := range s.flags {
			switch s.flags[i].long {
			case "password":
				pw = &s.flags[i]
			case "password-stdin":
				stdin = &s.flags[i]
			}
		}
		if pw == nil || pw.required || pw.boolean {
			t.Errorf("%v: --password must exist as an optional value flag, got %+v", path, pw)
		}
		if stdin == nil || !stdin.boolean {
			t.Errorf("%v: --password-stdin must exist as a boolean flag, got %+v", path, stdin)
		}
		if !slices.Contains(s.conflicts, [2]string{"password", "password-stdin"}) {
			t.Errorf("%v: --password must conflict with --password-stdin, conflicts=%v", path, s.conflicts)
		}
	}
}

// The conflict is enforced at parse time, as a usage error.
func TestPinCliPasswordArgsConflictRejected(t *testing.T) {
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	code := Run("test", []string{"db", "create", "x", "--engine", "mysql", "--port", "1", "--password", "a", "--password-stdin"})
	os.Stderr = old
	w.Close()
	out, _ := io.ReadAll(r)
	if code != exitUsage || !strings.Contains(string(out), "cannot be used with") {
		t.Errorf("Run = %d, stderr %q; want usage error naming the conflict", code, out)
	}
}

// §C: explicit value first, then one stdin line (never the prompt when
// --password-stdin is set).
func TestPinCliPasswordArgsResolve(t *testing.T) {
	explicit := "given"
	if got, err := resolvePassword(&explicit, true, "p: "); err != nil || got != "given" {
		t.Errorf("explicit tier: got %q, %v", got, err)
	}

	r, w, _ := os.Pipe()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	io.WriteString(w, "from-stdin\nignored\n")
	w.Close()
	if got, err := resolvePassword(nil, true, "p: "); err != nil || got != "from-stdin" {
		t.Errorf("stdin tier: got %q, %v", got, err)
	}

	r2, w2, _ := os.Pipe()
	os.Stdin = r2
	w2.Close()
	if _, err := resolvePassword(nil, true, "p: "); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty stdin must be refused, got %v", err)
	}
}
