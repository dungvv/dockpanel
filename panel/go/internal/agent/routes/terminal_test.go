package routes

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func terminalKinds(v []terminalObserved) []string {
	out := []string{}
	for _, o := range v {
		out = append(out, map[terminalObservedKind]string{
			terminalBlocked: "blocked", terminalSuspicious: "suspicious", terminalPlain: "plain",
		}[o.Kind])
	}
	return out
}

// Deliver input the way the BROWSER does: one JSON frame per character.
func terminalAsJSONFrames(input string, isSite bool) []string {
	buf := ""
	var all []terminalObserved
	for _, ch := range input {
		all = append(all, terminalObserveInput(string(ch), &buf, isSite)...)
	}
	return terminalKinds(all)
}

// Deliver input the way a SCRIPT does: one raw frame for the whole line.
func terminalAsRawFrame(input string, isSite bool) []string {
	buf := ""
	return terminalKinds(terminalObserveInput(input, &buf, isSite))
}

func terminalEq(t *testing.T, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// THE PROPERTY: the frame shape a client picked does not change what is
// observed. Before v2.88.0 the raw arm ran no classifier at all.
func TestTerminalFrameShapeDoesNotChangeWhatIsObserved(t *testing.T) {
	for _, c := range []struct {
		line   string
		isSite bool
	}{
		{"echo chmod 777\n", true},  // suspicious, allowed
		{"echo chmod 777\n", false}, // ...on the ROOT shell too
		{"sudo id\n", true},         // refused by the site blocklist
		{"sudo id\n", false},        // ...but a server shell may run it
		{"ls -la\n", true},          // ordinary
		{"ls -la\n", false},
	} {
		if j, r := terminalAsJSONFrames(c.line, c.isSite), terminalAsRawFrame(c.line, c.isSite); !reflect.DeepEqual(j, r) {
			t.Errorf("%q (site=%v) classified differently: json=%v raw=%v", c.line, c.isSite, j, r)
		}
	}
}

// The suspicious check must NOT be gated on the terminal kind.
func TestTerminalARootShellIsObservedToo(t *testing.T) {
	terminalEq(t, terminalAsRawFrame("echo chmod 777\n", false), "suspicious")
	terminalEq(t, terminalAsJSONFrames("echo chmod 777\n", false), "suspicious")
}

// A REFUSAL is an observation, not a silence.
func TestTerminalARefusedCommandIsReported(t *testing.T) {
	terminalEq(t, terminalAsRawFrame("sudo id\n", true), "blocked")
	terminalEq(t, terminalAsJSONFrames("sudo id\n", true), "blocked")
}

// Refusing stops the chunk: nothing after the refused newline reaches the
// shell, so nothing after it is judged.
func TestTerminalARefusalEndsTheChunk(t *testing.T) {
	terminalEq(t, terminalAsRawFrame("sudo id\nls -la\n", true), "blocked")
}

// The block half STAYS site-only — a server shell keeps `cd ..`.
func TestTerminalTheBlockHalfIsStillSiteOnly(t *testing.T) {
	terminalEq(t, terminalAsRawFrame("sudo id\n", false), "suspicious")
	terminalEq(t, terminalAsRawFrame("cat ../other-site/wp-config.php\n", true), "blocked")
}

func TestTerminalBackspaceEditsTheLineAndBlankLinesAreNotObserved(t *testing.T) {
	terminalEq(t, terminalAsRawFrame("lsX\x7f -la\n", true), "plain")
	terminalEq(t, terminalAsRawFrame("\n   \n", true))
}

// The honest bound: the line is rebuilt from KEYSTROKES, so cursor movement
// makes the reconstruction diverge from what the shell runs. If this ever
// reports `suspicious`, the reconstructor became cursor-aware and the bound
// documented on terminalObserveInput should be rewritten.
func TestTerminalReconstructionIsNotAnOracle(t *testing.T) {
	assembled := "echo cmod 777" + strings.Repeat("\x1b[D", 7) + "h\n"
	terminalEq(t, terminalAsJSONFrames(assembled, true), "plain")
}

// Ticket validation mirrors jsonwebtoken 10's Validation::new(HS256).
func TestTerminalValidateTicket(t *testing.T) {
	const secret = "agent-token"
	now := time.Unix(1_800_000_000, 0)
	sign := func(c jwt.MapClaims, key string) string {
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"sub": "a@b.c", "purpose": "terminal", "exp": now.Unix() + 30}
	}

	email, record, scope, ok := terminalValidateTicket(secret, sign(base(), secret), now)
	if !ok || email != "a@b.c" || !record || scope != nil {
		t.Fatalf("valid ticket: %v %v %v %v", email, record, scope, ok)
	}
	c := base()
	c["record"], c["scope"] = false, "@server"
	if _, record, scope, ok = terminalValidateTicket(secret, sign(c, secret), now); !ok || record || scope == nil || *scope != "@server" {
		t.Fatalf("record/scope claims not honoured")
	}
	c = base()
	c["exp"] = now.Unix() - 59 // inside the 60 s leeway
	if _, _, _, ok = terminalValidateTicket(secret, sign(c, secret), now); !ok {
		t.Fatal("leeway not applied")
	}

	reject := map[string]func(jwt.MapClaims){
		"expired":       func(c jwt.MapClaims) { c["exp"] = now.Unix() - 61 },
		"no exp":        func(c jwt.MapClaims) { delete(c, "exp") },
		"no sub":        func(c jwt.MapClaims) { delete(c, "sub") },
		"wrong purpose": func(c jwt.MapClaims) { c["purpose"] = "logs" },
		"no purpose":    func(c jwt.MapClaims) { delete(c, "purpose") },
		"aud present":   func(c jwt.MapClaims) { c["aud"] = "x" },
		"record string": func(c jwt.MapClaims) { c["record"] = "no" },
		"scope number":  func(c jwt.MapClaims) { c["scope"] = 1 },
	}
	for name, mut := range reject {
		c := base()
		mut(c)
		if _, _, _, ok := terminalValidateTicket(secret, sign(c, secret), now); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, _, ok := terminalValidateTicket(secret, sign(base(), "other"), now); ok {
		t.Error("wrong key accepted")
	}
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, base()).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, _, _, ok := terminalValidateTicket(secret, none, now); ok {
		t.Error("alg=none accepted")
	}
}
