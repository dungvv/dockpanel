package api

// Port of panel/backend/src/safe_cmd.rs.
//
// Every child process the API spawns MUST be built with safeCommand instead
// of exec.Command: it starts from an EMPTY environment plus a minimal safe
// one, so inherited LD_PRELOAD / LD_LIBRARY_PATH / a tampered PATH cannot
// hijack the child. ctx bounds the child's lifetime (Rust kill_on_drop):
// always pass one with a timeout for anything that can hang.

import (
	"context"
	"os/exec"
)

// safePath contains only system directories.
const safePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// safeCommand returns an exec.Cmd with a sanitised environment (PATH, HOME,
// LANG, LC_ALL only). Append to cmd.Env for extras (e.g. PGPASSWORD).
func safeCommand(ctx context.Context, binary string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=" + safePath, "HOME=/root", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	return cmd
}
