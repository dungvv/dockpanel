// Package safecmd is the only way the agent spawns child processes.
//
// Every child starts with an EMPTY environment plus a minimal safe one, so
// inherited LD_PRELOAD / LD_LIBRARY_PATH / a tampered PATH cannot hijack it.
package safecmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// SafePath contains only system directories.
const SafePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// DockerConfigDir is handed to every docker CLI invocation. The agent unit
// runs ProtectHome=yes, so HOME=/root is a read-only empty mount and
// `docker build` aborts creating $HOME/.docker. This dir is in the unit's
// ReadWritePaths. Set here because the env is cleared, so a unit-level
// Environment= would never reach the child.
const DockerConfigDir = "/var/lib/dockpanel/docker"

// CaptureDir stages transient-unit output. It must be writable by PID1:
// /tmp is NOT (on RHEL PID1 runs as init_t and writing tmp_t is denied);
// /var/lib/dockpanel is var_lib_t and in the agent's ReadWritePaths.
const CaptureDir = "/var/lib/dockpanel/run"

// captureDir is CaptureDir in production; tests run unprivileged and point
// it at a scratch dir.
var captureDir = CaptureDir

var captureSeq atomic.Uint64

func baseEnv() []string {
	return []string{
		"PATH=" + SafePath,
		"HOME=/root",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"DOCKER_CONFIG=" + DockerConfigDir,
	}
}

// Command returns an exec.Cmd with a sanitised environment (PATH, HOME,
// LANG, LC_ALL, DOCKER_CONFIG only). Callers needing more (e.g. PGPASSWORD)
// append to cmd.Env. ctx bounds the child's lifetime: cancelling it kills the
// child (the Rust kill_on_drop contract), so always pass one with a timeout
// for anything that can hang.
func Command(ctx context.Context, binary string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = baseEnv()
	return cmd
}

// Output is a finished command's result.
type Output struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int // -1 when killed by a signal
}

// Success reports exit status 0.
func (o Output) Success() bool { return o.ExitCode == 0 }

// Run runs cmd (built with ctx) to completion. err is non-nil when the
// process could not run at all, or when ctx expired (the child was killed —
// a timeout must not read as an ordinary failure). A non-zero exit is
// reported via ExitCode, not err.
func Run(ctx context.Context, cmd *exec.Cmd) (Output, error) {
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	o := Output{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	if ctx.Err() != nil {
		o.ExitCode = -1
		return o, ctx.Err()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		o.ExitCode = ee.ExitCode()
		return o, nil
	}
	return o, err
}

// Exec is Command + Run.
func Exec(ctx context.Context, binary string, args ...string) (Output, error) {
	return Run(ctx, Command(ctx, binary, args...))
}

// escapeDollar doubles every `$`: systemd-run turns the trailing argv into
// the transient unit's ExecStart=, which systemd subjects to $VAR expansion.
// A SHA-crypt hash ($6$salt$hash) would otherwise silently lose everything
// from the first unset $6 onward. systemd's escape for a literal $ is $$.
func escapeDollar(a string) string { return strings.ReplaceAll(a, "$", "$$") }

// Unsandboxed runs a command OUTSIDE the agent's ProtectSystem=strict sandbox
// in a transient systemd unit (PID1 spawns it in its own mount namespace), as
// apt-get/dnf need to write /var/lib/dpkg, /usr, ... .
//
// Never `systemd-run --pipe`: that passes the caller's stdio as fds over
// D-Bus, and on RHEL dbus-broker's SELinux file_receive check denies a pipe
// labelled unconfined_service_t (dontaudit'ed, so nothing is logged) and
// every package operation fails with "Connection reset by peer". Instead PID1
// opens the capture files itself via -p StandardOutput=file:…, and --wait
// still propagates the exit status. Same path on every distro, on purpose.
type Unsandboxed struct {
	argv []string
}

// NewUnsandboxed prepares binary with optional extra env ("K=V"), which
// reaches the inner binary as --setenv=K=V on top of the safe defaults.
func NewUnsandboxed(binary string, extraEnv ...string) *Unsandboxed {
	argv := []string{
		"--quiet", "--wait", "--collect",
		"--setenv=PATH=" + SafePath,
		"--setenv=HOME=/root",
		"--setenv=LANG=C.UTF-8",
		"--setenv=LC_ALL=C.UTF-8",
		"--setenv=DEBIAN_FRONTEND=noninteractive",
		"--setenv=DOCKER_CONFIG=" + DockerConfigDir,
	}
	for _, kv := range extraEnv {
		argv = append(argv, "--setenv="+kv)
	}
	argv = append(argv, "--", binary)
	return &Unsandboxed{argv: argv}
}

// Arg appends arguments to the INNER binary, `$`-escaped for systemd-run.
func (u *Unsandboxed) Arg(args ...string) *Unsandboxed {
	for _, a := range args {
		u.argv = append(u.argv, escapeDollar(a))
	}
	return u
}

func (u *Unsandboxed) command(ctx context.Context, c *capture) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "systemd-run", append(c.properties(), u.argv...)...)
	cmd.Env = []string{"PATH=" + SafePath}
	return cmd
}

// Output runs to completion. Cancelling ctx kills only the local
// systemd-run waiter, NOT the privileged work — use OutputWithTimeout when
// the inner command can hang.
func (u *Unsandboxed) Output(ctx context.Context) (Output, error) {
	c, err := newCapture()
	if err != nil {
		return Output{}, err
	}
	raw, err := Run(ctx, u.command(ctx, c))
	return c.finish(raw), err
}

// insertUnitArg names the transient unit up front (immediately before the
// `--` separator) so a timeout can stop that exact unit.
func (u *Unsandboxed) insertUnitArg() (binary, unit string) {
	sep := -1
	for i, a := range u.argv {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep+1 < len(u.argv) {
		binary = u.argv[sep+1]
	}
	unit = "dockpanel-op-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	u.argv = append(u.argv[:sep], append([]string{"--unit=" + unit}, u.argv[sep:]...)...)
	return binary, unit
}

// OutputWithTimeout runs within timeout and, on expiry, asks systemd to stop
// the transient unit itself: killing the local systemd-run only kills the
// waiter, and a hung apt/dnf transaction would keep running orphaned
// (live-proven). Cleanup is fire-and-forget so it can never delay the
// timeout error.
func (u *Unsandboxed) OutputWithTimeout(timeout time.Duration) (Output, error) {
	binary, unit := u.insertUnitArg()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := u.Output(ctx)
	if ctx.Err() == context.DeadlineExceeded {
		go func() {
			sctx, scancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer scancel()
			_ = Command(sctx, "systemctl", "stop", "--no-block", unit).Run()
		}()
		return out, fmt.Errorf("%s timed out after %ds (unit %s) and was asked to stop in the background",
			binary, int(timeout.Seconds()), unit)
	}
	if err != nil {
		return out, fmt.Errorf("%s could not be run: %w", binary, err)
	}
	return out, nil
}

// StreamingRun is a running Unsandboxed command whose output is streamed.
// Drain Lines until it closes, then call Wait.
type StreamingRun struct {
	Lines <-chan string
	done  chan struct{}
	code  int
	err   error
}

// Wait returns the inner command's exit code once it has finished.
func (s *StreamingRun) Wait() (int, error) {
	<-s.done
	return s.code, s.err
}

// SpawnStreaming starts the command and streams stdout+stderr line by line
// by tailing the capture files (stdout/stderr ordered per stream).
func (u *Unsandboxed) SpawnStreaming(ctx context.Context) (*StreamingRun, error) {
	c, err := newCapture()
	if err != nil {
		return nil, err
	}
	cmd := u.command(ctx, c)
	// systemd-run's OWN stderr must be drained: under --quiet it only speaks
	// when the unit cannot start at all, and that is then the only
	// explanation the user gets; an unread pipe could also block it.
	ownErr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		c.cleanup()
		return nil, err
	}
	lines := make(chan string, 128)
	run := &StreamingRun{Lines: lines, done: make(chan struct{})}
	var finished atomic.Bool
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); tailLines(c.out, lines, &finished) }()
	go func() { defer wg.Done(); tailLines(c.err, lines, &finished) }()
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(ownErr)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	go func() {
		err := cmd.Wait()
		// Set BEFORE joining so each tailer does one final read after the
		// process is gone and cannot lose a trailing line.
		finished.Store(true)
		wg.Wait()
		close(lines)
		c.cleanup()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			run.code = ee.ExitCode()
		} else {
			run.err = err
		}
		close(run.done)
	}()
	return run, nil
}

// tailLines follows a capture file. `finished` is checked BEFORE each read
// so the read that observes it set happens after the writer exited.
func tailLines(path string, out chan<- string, finished *atomic.Bool) {
	var pos int64
	var carry string
	for {
		done := finished.Load()
		if f, err := os.Open(path); err == nil {
			if _, err := f.Seek(pos, io.SeekStart); err == nil {
				if b, err := io.ReadAll(f); err == nil && len(b) > 0 {
					pos += int64(len(b))
					carry += strings.ToValidUTF8(string(b), "�")
					for {
						i := strings.IndexByte(carry, '\n')
						if i < 0 {
							break
						}
						out <- strings.TrimRight(carry[:i], "\r")
						carry = carry[i+1:]
					}
				}
			}
			f.Close()
		}
		if done {
			if carry != "" {
				out <- carry
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

type capture struct{ out, err string }

func ensureCaptureDir() error {
	if err := os.MkdirAll(captureDir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(captureDir, 0o700)
	return nil
}

func newCapture() (*capture, error) {
	if err := ensureCaptureDir(); err != nil {
		return nil, err
	}
	sweepStale()
	base := fmt.Sprintf("%d-%d", os.Getpid(), captureSeq.Add(1))
	c := &capture{out: filepath.Join(captureDir, base+".out"), err: filepath.Join(captureDir, base+".err")}
	for _, p := range []string{c.out, c.err} {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, err
		}
		f.Close()
	}
	return c, nil
}

func sweepStale() {
	entries, err := os.ReadDir(captureDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Hour {
			_ = os.Remove(filepath.Join(captureDir, e.Name()))
		}
	}
}

func (c *capture) properties() []string {
	return []string{"-p", "StandardOutput=file:" + c.out, "-p", "StandardError=file:" + c.err}
}

func (c *capture) cleanup() {
	_ = os.Remove(c.out)
	_ = os.Remove(c.err)
}

func (c *capture) finish(raw Output) Output {
	stdout, _ := os.ReadFile(c.out)
	stderr, _ := os.ReadFile(c.err)
	c.cleanup()
	return Output{Stdout: stdout, Stderr: append(stderr, raw.Stderr...), ExitCode: raw.ExitCode}
}

// DockerEnvFile is a 0600 env file for `docker run --env-file`, so secrets
// never appear in argv (visible in ps). Close removes it.
type DockerEnvFile struct{ path string }

// NewDockerEnvFile writes "K=V" pairs; a value containing a newline is
// refused (it would inject a second variable).
func NewDockerEnvFile(vars ...[2]string) (*DockerEnvFile, error) {
	if err := ensureCaptureDir(); err != nil {
		return nil, err
	}
	var body strings.Builder
	for _, kv := range vars {
		if strings.Contains(kv[1], "\n") {
			return nil, fmt.Errorf("env value for %s must not contain a newline", kv[0])
		}
		body.WriteString(kv[0] + "=" + kv[1] + "\n")
	}
	path := filepath.Join(captureDir, fmt.Sprintf("env-%d-%d", os.Getpid(), captureSeq.Add(1)))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.WriteString(body.String()); err != nil {
		os.Remove(path)
		return nil, err
	}
	return &DockerEnvFile{path: path}, nil
}

// Path is the env file's location.
func (d *DockerEnvFile) Path() string { return d.path }

// Close removes the file; always defer it.
func (d *DockerEnvFile) Close() error { return os.Remove(d.path) }
