package safecmd

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

// tests/timeout-orphan-kill-on-drop-pin-e2e.sh §A: the Go equivalent of the
// Rust kill_on_drop(true) contract. When the ctx handed to Command expires,
// the child is KILLED and reaped — not left running, orphaned to PID 1, still
// holding e.g. .git/index.lock — and Run returns promptly with ctx's error.
func TestPinTimeoutOrphanKillOnDropKillsTheChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	cmd := Command(ctx, "sleep", "30")
	start := time.Now()
	_, err := Run(ctx, cmd)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a timed-out child must surface the deadline, got %v", err)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("Run waited %v — the timeout did not stop the child", el)
	}
	if cmd.ProcessState == nil {
		t.Fatal("the child was not reaped")
	}
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("the child was not killed by the timeout: %v", cmd.ProcessState)
	}
	if err := syscall.Kill(cmd.Process.Pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("pid %d still exists after the timeout (kill(0) = %v)", cmd.Process.Pid, err)
	}
}
