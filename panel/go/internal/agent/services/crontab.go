// Root's crontab, read and written as a whole file.
//
// `crontab` has no partial-update verb: every caller reads the entire file,
// edits lines, and writes the entire file back. That makes the READ the
// dangerous half — an empty read is indistinguishable from "no entries", and
// writing that back deletes every job on the box, belonging to every tenant
// and to the operator.
//
// The cron routes grew a fail-closed reader; the WordPress auto-update twin
// did not and collapsed a failed `crontab -l` into "" — reachable from an
// ordinary authenticated route naming ONE site, with a box-wide blast radius.
// This module is the single reader and the single writer; every crontab
// writer must route through here.
package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// CrontabRead reads root's crontab, failing CLOSED.
//
// ("", nil) means root genuinely has no crontab. Anything that merely LOOKS
// like an empty crontab — a timeout, a spawn failure, a non-zero exit that is
// not the "no crontab for ..." message — is an error, because every caller
// feeds this straight back into CrontabWrite as the complete new content.
//
// `-u root` is explicit rather than implied by the agent's own uid: this
// function names the file it is about to let a caller overwrite.
func CrontabRead() (string, error) {
	return crontabReadBin("crontab")
}

func crontabReadBin(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, bin, "-l", "-u", "root")
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("Refusing to rewrite the crontab: `crontab -l` timed out after 15s")
	}
	if err != nil {
		return "", fmt.Errorf("Refusing to rewrite the crontab: `crontab -l` failed to run: %v", err)
	}
	return crontabClassify(out)
}

// crontabClassify: only success or the "no crontab for" text may become a
// string; every other non-zero exit is refused because the caller's next act
// is a full overwrite.
func crontabClassify(o safecmd.Output) (string, error) {
	if o.Success() {
		return strings.ToValidUTF8(string(o.Stdout), "�"), nil
	}
	stderr := strings.ToLower(strings.ToValidUTF8(string(o.Stderr), "�"))
	if strings.Contains(stderr, "no crontab for") {
		return "", nil
	}
	return "", fmt.Errorf("Refusing to rewrite the crontab: `crontab -l` exited %d (%s). "+
		"Treating that as an empty crontab would delete every existing entry.",
		o.ExitCode, strings.TrimSpace(stderr))
}

// CrontabWrite replaces root's crontab with content.
func CrontabWrite(content string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := safecmd.Command(ctx, "crontab", "-u", "root", "-")
	cmd.Stdin = strings.NewReader(content + "\n")
	out, err := safecmd.Run(ctx, cmd)
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("crontab timed out after 10s")
	}
	if err != nil {
		return fmt.Errorf("Failed to spawn crontab: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("crontab command failed")
	}
	return nil
}
