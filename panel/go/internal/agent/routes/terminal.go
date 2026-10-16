package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/creack/pty"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// TerminalActiveTerminals counts open terminal sessions (the panic button in
// security.go zeroes it after killing every registered shell).
var TerminalActiveTerminals atomic.Uint32

// TerminalPid is one shell this agent spawned. IsRoot is true for a server
// terminal.
type TerminalPid struct {
	Pid    int
	IsRoot bool
}

// TerminalPids is every shell this agent has spawned, so the panic button can
// kill the ones it actually started. Guard with TerminalPidsMu.
//
// The panic button used to run `pkill -u www-data -f bash`, which is a guess
// about which processes are ours, and it guessed wrong in the one direction
// that matters: a SERVER terminal is deliberately kept as root
// (terminalOpenPtyShell), so the single most dangerous shell on the box — the
// one an intruder with a stolen admin session is holding — was the one process
// the emergency control could not reach. A registry is not a guess.
var (
	TerminalPidsMu sync.Mutex
	TerminalPids   []TerminalPid
)

// TerminalRegisterTerminal records a shell this agent spawned.
func TerminalRegisterTerminal(pid int, isRoot bool) {
	TerminalPidsMu.Lock()
	defer TerminalPidsMu.Unlock()
	TerminalPids = append(TerminalPids, TerminalPid{Pid: pid, IsRoot: isRoot})
}

// TerminalForgetTerminal forgets a shell that has already exited.
func TerminalForgetTerminal(pid int) {
	TerminalPidsMu.Lock()
	defer TerminalPidsMu.Unlock()
	kept := TerminalPids[:0]
	for _, p := range TerminalPids {
		if p.Pid != pid {
			kept = append(kept, p)
		}
	}
	TerminalPids = kept
}

var terminalLastConnect atomic.Uint64

const terminalMaxTerminalSessions = 20

// terminalServerShellScope: a ticket whose `scope` is this value authorises the
// root server shell. Any other value is a site domain; the shell drops to
// www-data under that site's root. The panel writes it; it is not a valid
// domain (the `@` fails the domain check), so it cannot be a site's name.
const terminalServerShellScope = "@server"

// terminalBlockedNotice is what the caller is told when the site-terminal
// blocklist refuses a line. One constant so both input arms cannot drift.
const terminalBlockedNotice = "\r\n\x1b[1;31mBlocked:\x1b[0m command not allowed in site terminal\r\n"

// terminalDropFailed is shown when the www-data privilege drop did not hold.
const terminalDropFailed = "dockpanel: refusing to open this shell (privilege drop failed)\r\n"

const (
	terminalSessionTimeout  = 30 * time.Minute
	terminalRecordingDir    = "/var/lib/dockpanel/recordings"
	terminalAuditDir        = "/var/lib/dockpanel/audit"
	terminalSuspiciousPath  = "/var/lib/dockpanel/suspicious-events.jsonl"
	terminalJwtLeewaySecond = 60 // jsonwebtoken's default Validation leeway
)

// terminalReleaseSlot is ACTIVE_TERMINALS.fetch_update(saturating_sub(1)):
// the panic button may have zeroed the counter under us.
func terminalReleaseSlot() {
	for {
		v := TerminalActiveTerminals.Load()
		if v == 0 || TerminalActiveTerminals.CompareAndSwap(v, v-1) {
			return
		}
	}
}

// registerTerminal: the terminal WebSocket bypasses the standard auth
// middleware (the ticket is validated inside the handler via query param).
func registerTerminal(r *Router) {
	st := r.State
	r.HandlePublic("/terminal/ws", func(w http.ResponseWriter, req *http.Request) {
		terminalWsHandler(st, w, req)
	})
}

// terminalText writes a plain-text body. ct=false mirrors axum's
// Response::builder().body(String), which sets no Content-Type.
func terminalText(w http.ResponseWriter, status int, msg string, ct bool) {
	if ct {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header()["Content-Type"] = nil // stop net/http sniffing one in
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

// terminalParseU16 mirrors serde_urlencoded's u16 parse and its error text.
func terminalParseU16(s string) (uint16, string) {
	if s == "" {
		return 0, "cannot parse integer from empty string"
	}
	digits := s
	if len(s) > 1 && s[0] == '+' { // Rust's u16::from_str accepts one leading '+'
		digits = s[1:]
	}
	v, err := strconv.ParseUint(digits, 10, 16)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, "number too large to fit in target type"
		}
		return 0, "invalid digit found in string"
	}
	return uint16(v), ""
}

// terminalUpgradeRejection mirrors axum's WebSocketUpgrade extractor checks
// (HTTP/1.1 path), same order and body text.
func terminalUpgradeRejection(r *http.Request) (int, string) {
	if r.Method != http.MethodGet {
		return http.StatusMethodNotAllowed, "Request method must be `GET`"
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return http.StatusBadRequest, "Connection header did not include 'upgrade'"
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return http.StatusBadRequest, "`Upgrade` header did not include 'websocket'"
	}
	if _, ok := r.Header["Sec-Websocket-Key"]; !ok {
		return http.StatusBadRequest, "`Sec-WebSocket-Key` header missing"
	}
	if !strings.EqualFold(r.Header.Get("Sec-WebSocket-Version"), "13") {
		return http.StatusBadRequest, "`Sec-WebSocket-Version` header did not include '13'"
	}
	return 0, ""
}

// terminalValidateTicket validates the short-lived JWT ticket the API signs
// with the agent token (HS256), with jsonwebtoken 10's Validation semantics:
// `exp` and `sub` required, exp checked with 60 s leeway, nbf NOT checked, any
// parseable `aud` rejected (none is configured). Claims must deserialize as
// {sub: String, purpose: String, record: Option<bool>, scope: Option<String>}
// and purpose must be "terminal". Signature verification in jwt/v5 is
// constant-time (hmac.Equal).
func terminalValidateTicket(secret, ticket string, now time.Time) (email string, record bool, scope *string, ok bool) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(ticket, claims, func(*jwt.Token) (any, error) { return []byte(secret), nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithoutClaimsValidation())
	if err != nil {
		return "", false, nil, false
	}
	// exp: u64, or a finite non-negative float rounded (jsonwebtoken numeric_type).
	expF, isNum := claims["exp"].(float64)
	if !isNum || math.IsInf(expF, 0) || math.IsNaN(expF) || expF < 0 || expF >= math.MaxUint64 {
		return "", false, nil, false
	}
	exp := uint64(math.Round(expF))
	if nowS := uint64(now.Unix()); exp < nowS-terminalJwtLeewaySecond {
		return "", false, nil, false
	}
	if terminalAudParsed(claims["aud"]) {
		return "", false, nil, false
	}
	sub, okSub := claims["sub"].(string)
	purpose, okPurpose := claims["purpose"].(string)
	if !okSub || !okPurpose || purpose != "terminal" {
		return "", false, nil, false
	}
	record = true // absent: an older panel minted it — keep recording
	if v, present := claims["record"]; present && v != nil {
		b, isBool := v.(bool)
		if !isBool {
			return "", false, nil, false
		}
		record = b
	}
	if v, present := claims["scope"]; present && v != nil {
		s, isStr := v.(string)
		if !isStr {
			return "", false, nil, false
		}
		scope = &s
	}
	return sub, record, scope, true
}

// terminalAudParsed: jsonwebtoken rejects a token whose aud parses (a string,
// or an array of strings) when no audience is configured.
func terminalAudParsed(v any) bool {
	switch a := v.(type) {
	case string:
		return true
	case []any:
		for _, e := range a {
			if _, ok := e.(string); !ok {
				return false
			}
		}
		return true
	}
	return false
}

// terminalWsHandler: GET /terminal/ws — WebSocket terminal.
// Auth via ?token= query param (short-lived JWT ticket signed by the API).
func terminalWsHandler(st *State, w http.ResponseWriter, r *http.Request) {
	// axum's get() router: anything but GET/HEAD is a bare 405.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET,HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Extractor order matches the Rust signature: Query, then WebSocketUpgrade.
	q := r.URL.Query()
	cols, rows := uint16(80), uint16(24)
	for _, f := range []struct {
		name string
		dst  *uint16
	}{{"cols", &cols}, {"rows", &rows}} {
		if q.Has(f.name) {
			v, msg := terminalParseU16(q.Get(f.name))
			if msg != "" {
				terminalText(w, http.StatusBadRequest, "Failed to deserialize query string: "+f.name+": "+msg, true)
				return
			}
			*f.dst = v
		}
	}
	if status, msg := terminalUpgradeRejection(r); status != 0 {
		terminalText(w, status, msg, true)
		return
	}

	// Rate limit: max 1 connection per second (prevents rapid reconnect storms)
	now := uint64(time.Now().Unix())
	if terminalLastConnect.Swap(now) == now {
		terminalText(w, http.StatusTooManyRequests, "Too many terminal connections", true)
		return
	}

	// Enforce terminal session limit
	if TerminalActiveTerminals.Add(1)-1 >= terminalMaxTerminalSessions {
		terminalReleaseSlot()
		terminalText(w, http.StatusServiceUnavailable, "Too many terminal sessions", false)
		return
	}

	// Validate JWT ticket (short-lived token signed by the API using the agent
	// token as secret). Current token only — the Rust reads state.token, no
	// rotation grace.
	email, record, ticketScope, ok := "", true, (*string)(nil), false
	if q.Has("token") {
		email, record, ticketScope, ok = terminalValidateTicket(st.Token(), q.Get("token"), time.Now())
	}
	if !ok {
		terminalReleaseSlot()
		terminalText(w, http.StatusUnauthorized, "Unauthorized", false)
		return
	}

	// The scope is the SIGNED decision, not the `?domain=` param. Trusting the
	// param let a site-scoped ticket open a root shell by omitting the domain.
	// `@server` is the root shell (the panel only mints it for an admin, and it
	// is not a valid domain); any other value is a site. A ticket with no scope
	// came from a panel too old to bind it — fall back to the param it
	// expected, and say so, so an unscoped root shell is visible in the log.
	var domain string
	switch {
	case ticketScope != nil && *ticketScope == terminalServerShellScope:
		domain = ""
	case ticketScope != nil:
		domain = *ticketScope
	default:
		domain = q.Get("domain")
		if domain == "" {
			slog.Warn(fmt.Sprintf("Terminal ticket for %s carries no scope (pre-v2.75.0 panel); opening a server shell from the query param", email))
		}
	}

	// Validate domain format (prevent path traversal). Belt and suspenders:
	// the scope is signed, but a directory name still reaches the filesystem.
	if domain != "" && (strings.Contains(domain, "..") || strings.Contains(domain, "/") || strings.Contains(domain, "\x00")) {
		terminalReleaseSlot()
		terminalText(w, http.StatusBadRequest, "Invalid domain", true)
		return
	}

	// Verify site directory exists before upgrading to WebSocket
	if domain != "" {
		if fi, err := os.Stat("/var/www/" + domain); err != nil || !fi.IsDir() {
			terminalReleaseSlot()
			terminalText(w, http.StatusBadRequest, "Site directory not found", true)
			return
		}
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// axum does no Origin check: the browser dials the agent from the
		// panel's origin and the signed ticket is the authentication.
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		// Rust leaked the slot here (on_upgrade never ran); release it.
		terminalReleaseSlot()
		return
	}
	conn.SetReadLimit(64 << 20) // tungstenite's default max message size
	defer conn.CloseNow()
	terminalHandle(conn, domain, email, cols, rows, record)
}

// terminalOpenPtyShell opens a PTY and spawns a shell on its slave side.
// site=true drops privileges to www-data for a site terminal.
//
// The Rust fork()s by hand; Go cannot run code between fork and exec, so each
// child-side step maps onto exec.Cmd/SysProcAttr:
//   - setsid + TIOCSCTTY + dup2 onto 0/1/2: pty.StartWithAttrs (Setsid, Setctty).
//   - close every inherited fd > 2: Go opens all fds O_CLOEXEC and passes only
//     Stdin/Stdout/Stderr.
//   - clearenv + setenv: cmd.Env is replaced wholesale with exactly the Rust's
//     variables (NOT safecmd's base env — the Rust child gets no PATH at all on
//     a server shell; bash --login's /etc/profile sets it).
//   - setgid/initgroups/setuid: SysProcAttr.Credential. Go's child aborts the
//     exec if any of them fails, so a failed drop can never fall through to a
//     root shell; the kernel is then asked who the child really is (below).
//   - PR_SET_NO_NEW_PRIVS: set on a throwaway locked OS thread that the child
//     is cloned from (inherited across fork/exec). umask 077: see below.
func terminalOpenPtyShell(cwd string, cols, rows uint16, site bool) (*os.File, *exec.Cmd, error) {
	attrs := &syscall.SysProcAttr{Setsid: true, Setctty: true}
	env := []string{"TERM=xterm-256color"}
	var shell string
	var args []string
	var uid, gid uint32
	if site {
		// www-data user not found — abort rather than run as root
		u, err := user.Lookup("www-data")
		if err != nil {
			return nil, nil, errors.New("www-data user not found")
		}
		uid64, err1 := strconv.ParseUint(u.Uid, 10, 32)
		gid64, err2 := strconv.ParseUint(u.Gid, 10, 32)
		gids, err3 := u.GroupIds() // initgroups("www-data", gid)
		if err1 != nil || err2 != nil || err3 != nil {
			return nil, nil, errors.New("www-data user not found")
		}
		uid, gid = uint32(uid64), uint32(gid64)
		groups := make([]uint32, 0, len(gids))
		for _, g := range gids {
			n, err := strconv.ParseUint(g, 10, 32)
			if err != nil {
				return nil, nil, errors.New("www-data user not found")
			}
			groups = append(groups, uint32(n))
		}
		attrs.Credential = &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}
		// HOME is the site directory; restricted PATH: only standard user bins,
		// no sbin.
		env = append(env, "HOME="+cwd, "USER=www-data", "PATH=/usr/local/bin:/usr/bin:/bin")
		// Site terminal: bash --restricted (rbash) prevents changing directory
		// with cd, setting/unsetting PATH, commands with /, and redirecting
		// output. --norc/--noprofile stop .bashrc overriding restricted mode.
		// Fallback: plain sh.
		real := []string{"/bin/sh"}
		if _, err := os.Stat("/bin/bash"); err == nil {
			real = []string{"/bin/bash", "--restricted", "--norc", "--noprofile"}
		}
		// Restrict umask so created files aren't world-readable. Go has no
		// per-child umask and unshare(CLONE_FS) is seccomp-blocked in
		// containers, so /bin/sh (already www-data) sets it and execs the shell
		// in place — same pid, same env.
		shell, args = "/bin/sh", append([]string{"-c", `umask 077 && exec "$0" "$@"`}, real...)
	} else {
		// Server terminal — keep root, full bash.
		env = append(env, "HOME=/root")
		shell = "/bin/sh"
		if _, err := os.Stat("/bin/bash"); err == nil {
			shell = "/bin/bash"
		}
		args = []string{"--login"}
	}

	// Background ctx: the session loop owns the child's lifetime (SIGTERM,
	// 500 ms grace, SIGKILL), not a context.
	cmd := safecmd.Command(context.Background(), shell, args...)
	cmd.Env = env
	cmd.Dir = cwd
	size := &pty.Winsize{Rows: rows, Cols: cols}

	if !site {
		ptmx, err := pty.StartWithAttrs(cmd, size, attrs)
		return ptmx, cmd, err
	}

	type started struct {
		f   *os.File
		err error
	}
	ch := make(chan started, 1)
	go func() {
		// Never unlocked: this thread now carries no_new_privs, so the runtime
		// discards it when the goroutine returns.
		runtime.LockOSThread()
		// PR_SET_NO_NEW_PRIVS: prevent any privilege escalation (blocks setuid
		// binaries like su, sudo, pkexec, etc.)
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			ch <- started{nil, fmt.Errorf("prctl: %w", err)}
			return
		}
		f, err := pty.StartWithAttrs(cmd, size, attrs)
		ch <- started{f, err}
	}()
	s := <-ch
	if s.err != nil {
		return nil, nil, s.err
	}
	// Ask the kernel who the child ACTUALLY is rather than trusting the
	// syscall results. This is the arm that cannot be fooled. Start returns
	// only after exec succeeded, and no input reaches the shell before this.
	if !terminalCredsAre(cmd.Process.Pid, uid, gid) {
		_ = s.f.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, nil, errors.New(strings.TrimSuffix(terminalDropFailed, "\r\n"))
	}
	return s.f, cmd, nil
}

// terminalCredsAre checks real+effective uid and real gid of pid via
// /proc/<pid>/status (the Rust: getuid/geteuid/getgid after the drop).
func terminalCredsAre(pid int, uid, gid uint32) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	want := func(key string, idx []int, v uint32) bool {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) >= 3 && f[0] == key {
				for _, i := range idx {
					if f[i] != strconv.FormatUint(uint64(v), 10) {
						return false
					}
				}
				return true
			}
		}
		return false
	}
	return want("Uid:", []int{1, 2}, uid) && want("Gid:", []int{1}, gid)
}

// terminalRfc3339 is chrono's Utc to_rfc3339 (AutoSi fraction, "+00:00").
func terminalRfc3339(t time.Time) string {
	t = t.UTC()
	ns := t.Nanosecond()
	frac := ""
	switch {
	case ns == 0:
	case ns%1_000_000 == 0:
		frac = fmt.Sprintf(".%03d", ns/1_000_000)
	case ns%1_000 == 0:
		frac = fmt.Sprintf(".%06d", ns/1_000)
	default:
		frac = fmt.Sprintf(".%09d", ns)
	}
	return t.Format("2006-01-02T15:04:05") + frac + "+00:00"
}

// terminalJSONLine marshals v like serde_json (sorted keys, no HTML escaping)
// plus a trailing newline.
func terminalJSONLine(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return b.Bytes()
}

func terminalAppend(path string, data []byte) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o666)
	if err != nil {
		return
	}
	_, _ = f.Write(data)
	_ = f.Close()
}

func terminalHandle(conn *websocket.Conn, domain, email string, cols, rows uint16, record bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	send := func(s string) error { return conn.Write(ctx, websocket.MessageText, []byte(s)) }

	// Determine working directory
	cwd := "/root"
	if domain != "" {
		cwd = "/var/www/" + domain
		if _, err := os.Stat(cwd); err != nil {
			_ = send("Site directory not found: " + cwd)
			terminalReleaseSlot()
			return
		}
	}

	// Spawn shell with PTY (drop to www-data for site terminals)
	isSite := domain != ""
	ptmx, cmd, err := terminalOpenPtyShell(cwd, cols, rows, isSite)
	if err != nil {
		_ = send(fmt.Sprintf("Failed to spawn shell: %v", err))
		terminalReleaseSlot()
		return
	}
	pid := cmd.Process.Pid
	TerminalRegisterTerminal(pid, !isSite)
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()

	// PTY output → channel
	out := make(chan []byte, 64)
	go func() {
		defer close(out)
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				select {
				case out <- bytes.Clone(buf[:n]):
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WebSocket input → channel (closed on Close frame or error)
	type wsMsg struct {
		typ  websocket.MessageType
		data []byte
	}
	in := make(chan wsMsg)
	go func() {
		defer close(in)
		for {
			typ, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			select {
			case in <- wsMsg{typ, data}:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Command buffer for audit logging and safety checks
	var cmdBuffer string
	domainStr := domain
	if domainStr == "" {
		domainStr = "server"
	}

	// Session recording — only when the panel's `security_session_recording`
	// toggle allows it (the signed `record` claim). Until v2.46.0 this ran
	// unconditionally and the toggle was inert.
	recordingStart := time.Now()
	var recording *os.File
	if record {
		_ = os.MkdirAll(terminalRecordingDir, 0o777)
		path := fmt.Sprintf("%s/%s.cast", terminalRecordingDir, uuid.New())
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o666); err == nil {
			recording = f
			defer f.Close()
		}
	}

	// Write asciicast v2 header
	if recording != nil {
		_, _ = recording.Write(terminalJSONLine(map[string]any{
			"version":   2,
			"width":     cols,
			"height":    rows,
			"timestamp": time.Now().Unix(),
			"env":       map[string]string{"TERM": "xterm-256color", "SHELL": "/bin/bash"},
			"title":     email + "@" + domainStr,
		}))
	}

	// Write session start to the tamper-resistant audit file
	_ = os.MkdirAll(terminalAuditDir, 0o777)
	nowT := time.Now().UTC()
	terminalAppend(fmt.Sprintf("%s/audit-%s.log", terminalAuditDir, nowT.Format("2006-01-02")),
		[]byte(fmt.Sprintf("%s\tinfo\tterminal.start\t%s\t-\tdomain=%s\n", terminalRfc3339(nowT), email, domainStr)))

	slog.Info("Terminal session started", "target", "terminal_audit", "user", email, "domain", domainStr)

	// Terminal session timeout (30 minutes) — fires even on idle sessions
	timer := time.NewTimer(terminalSessionTimeout)
	defer timer.Stop()

	// Characters are forwarded immediately for echo, but Enter is held until
	// the completed line is judged. ONE path for both frame shapes — see
	// terminalObserveInput. Returns false when the PTY write failed.
	forward := func(data string) bool {
		seen := terminalObserveInput(data, &cmdBuffer, isSite)
		blocked := false
		for _, obs := range seen {
			terminalRecordObservation(obs, email, domainStr)
			blocked = blocked || obs.Kind == terminalBlocked
		}
		if blocked {
			// Send Ctrl+U (kill line) + Ctrl+C to cancel
			_, _ = ptmx.Write([]byte("\x15\x03"))
			_ = send(terminalBlockedNotice)
			return true
		}
		_, err := ptmx.Write([]byte(data))
		return err == nil
	}

loop:
	for {
		select {
		case <-timer.C:
			_ = send("\r\n\x1b[1;33mSession timed out (30 minutes). Reconnect to continue.\x1b[0m\r\n")
			slog.Info("Terminal session timed out", "target", "terminal_audit", "user", email, "domain", domainStr)
			break loop

		case data, ok := <-out: // PTY output → WebSocket
			if !ok {
				out = nil // shell gone: like the Rust, wait for the client/timeout
				continue
			}
			text := strings.ToValidUTF8(string(data), "\uFFFD") // from_utf8_lossy
			if recording != nil {
				// asciicast v2 format: [time, "o", "data"] — the Rust's own
				// minimal escaping, kept byte-identical.
				esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(text)
				_, _ = fmt.Fprintf(recording, "[%.6f, \"o\", \"%s\"]\n", time.Since(recordingStart).Seconds(), esc)
			}
			if send(text) != nil {
				break loop
			}

		case m, ok := <-in: // WebSocket input → PTY
			if !ok {
				break loop
			}
			if m.typ != websocket.MessageText {
				continue
			}
			if !utf8.Valid(m.data) { // tungstenite errors the stream on this
				break loop
			}
			text := string(m.data)
			if !json.Valid(m.data) {
				// Raw text input. NOT gated on the terminal kind and NOT a
				// second copy of the loop: the frame shape a client picked is
				// not a security boundary, and a root shell is where an
				// observation is worth the most.
				if !forward(text) {
					break loop
				}
				continue
			}
			dec := json.NewDecoder(strings.NewReader(text))
			dec.UseNumber()
			var v any
			_ = dec.Decode(&v)
			obj, _ := v.(map[string]any)
			typ, _ := obj["type"].(string)
			switch typ {
			case "input":
				if data, isStr := obj["data"].(string); isStr && !forward(data) {
					break loop
				}
			case "resize":
				_ = pty.Setsize(ptmx, &pty.Winsize{
					Cols: terminalAsU16(obj["cols"], 80),
					Rows: terminalAsU16(obj["rows"], 24),
				})
			}
		}
	}

	// Cleanup: close the PTY, kill the child and reap it to prevent zombies.
	cancel()
	_ = ptmx.Close()
	_ = cmd.Process.Signal(syscall.SIGTERM)
	// Give the process 500ms to exit gracefully after SIGTERM
	select {
	case <-exited:
	case <-time.After(500 * time.Millisecond):
		// Still alive after SIGTERM — force kill and blocking reap
		_ = cmd.Process.Kill()
		<-exited
	}
	TerminalForgetTerminal(pid)
	// Release terminal session slot
	terminalReleaseSlot()
}

// terminalAsU16 is serde_json `v.as_u64().unwrap_or(def) as u16`: only a
// non-negative integer counts (80.0 does not), and `as u16` truncates.
func terminalAsU16(v any, def uint16) uint16 {
	n, ok := v.(json.Number)
	if !ok {
		return def
	}
	u, err := strconv.ParseUint(string(n), 10, 64)
	if err != nil {
		return def
	}
	return uint16(u)
}

type terminalObservedKind int

const (
	// terminalBlocked: the site-terminal blocklist refuses it. Nothing is
	// forwarded to the PTY.
	terminalBlocked terminalObservedKind = iota
	// terminalSuspicious: it runs, and it matches the suspicious list.
	terminalSuspicious
	// terminalPlain: it runs and looks ordinary.
	terminalPlain
)

// terminalObserved is what one completed input line turned out to be.
type terminalObserved struct {
	Kind terminalObservedKind
	Line string
}

// terminalObserveInput reconstructs completed lines from one chunk of terminal
// input and says what each one is.
//
// Every byte that reaches the PTY passes through here, whatever WebSocket
// frame shape carried it. Until v2.88.0 this loop was written twice: the
// {"type":"input"} arm classified, the raw-text arm only ran the BLOCK half
// and only for site terminals. The UI only sends JSON, so the one input path
// with no detection was the one only a non-browser client takes — the client
// an intruder with a stolen admin session uses. Measured at v2.87.0: JSON
// frame → 1 terminal.suspicious_command; raw frame → 0.
//
// ⚠ HONEST BOUND: a line is reconstructed from keystrokes, so anything that
// moves the cursor makes the reconstruction diverge from what the shell runs —
// `echo cmod 777`, seven LEFTs, `h` runs `echo chmod 777` and is measured as
// `echo cmod 777[D…h`, which matches nothing. What this guarantees is
// narrower: the observation no longer depends on which frame shape the caller
// chose. Same family as command_filter's _SITE_SHELL_IS_NOT_A_SANDBOX.
func terminalObserveInput(data string, buf *string, isSite bool) []terminalObserved {
	var out []terminalObserved
	for _, ch := range data {
		switch {
		case ch == '\r' || ch == '\n':
			line := strings.TrimSpace(*buf)
			*buf = ""
			if line == "" {
				continue
			}
			// The block check stays gated on the terminal kind deliberately —
			// an administrator's SERVER shell must keep `cd ..`, which
			// client-role-and-server-ownership-pin-e2e.sh §D pins. Only the
			// SUSPICIOUS half is ungated: a root shell is precisely where an
			// observation is worth the most.
			if isSite && !services.CommandFilterIsSafeTerminalCommand(line) {
				// Refused: the rest of this chunk never reaches the shell, so
				// there is nothing further to observe in it.
				return append(out, terminalObserved{terminalBlocked, line})
			}
			if services.CommandFilterIsSuspiciousCommand(line) {
				out = append(out, terminalObserved{terminalSuspicious, line})
			} else {
				out = append(out, terminalObserved{terminalPlain, line})
			}
		case ch == '\x7f' || ch == '\x08':
			if _, size := utf8.DecodeLastRuneInString(*buf); size > 0 {
				*buf = (*buf)[:len(*buf)-size]
			}
		case !unicode.IsControl(ch):
			*buf += string(ch)
		}
	}
	return out
}

// terminalWriteSuspiciousEvent appends an event to the shared JSONL file for
// backend ingestion.
func terminalWriteSuspiciousEvent(eventType, email, domain, command string) {
	terminalAppend(terminalSuspiciousPath, terminalJSONLine(map[string]string{
		"timestamp":   terminalRfc3339(time.Now()),
		"event_type":  eventType,
		"actor_email": email,
		"domain":      domain,
		"command":     command,
	}))
}

// terminalRecordObservation records one observation: the agent's journal
// always, and the panel's intrusion channel when the line is worth an
// operator's attention.
//
// A REFUSAL is reported (it used to `break` before the classifier and reach
// only the agent journal, which nothing consumes). It is its OWN event type
// on purpose: the backend's record_suspicious_event_at counts every
// suspicious_events row toward security_lockdown_threshold (default 5 in 10
// min, trip blocks every non-admin for 24h), and the site blocklist contains
// a bare ".." substring that tenants trip by accident (`echo "done..."`).
// Counting refusals would turn a blunt blocklist into a self-inflicted outage,
// so the ingest audits this type and does not count it.
func terminalRecordObservation(obs terminalObserved, email, domainStr string) {
	attrs := []any{"target", "terminal_audit", "user", email, "domain", domainStr, "command", obs.Line}
	switch obs.Kind {
	case terminalBlocked:
		slog.Warn("Blocked dangerous terminal command", attrs...)
		terminalWriteSuspiciousEvent("terminal.blocked_command", email, domainStr, obs.Line)
	case terminalSuspicious:
		slog.Warn("SUSPICIOUS terminal command detected", attrs...)
		terminalWriteSuspiciousEvent("terminal.suspicious_command", email, domainStr, obs.Line)
	case terminalPlain:
		slog.Info("Terminal command", attrs...)
	}
}
