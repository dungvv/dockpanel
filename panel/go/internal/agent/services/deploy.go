package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

const (
	deployWebroot = "/var/www"
	deployKeysDir = "/etc/dockpanel/deploy-keys"
)

// deployErrTimeout is what deployRun returns when its own timeout fired.
var deployErrTimeout = errors.New("timed out")

// deployRun runs bin through safecmd in dir with extra env ("K=V", later
// entries win), bounded by timeout (0 = only ctx). Cancelling the context
// kills the child (Rust kill_on_drop) — a timed-out git fetch left running
// would hold .git/index.lock against every later attempt.
func deployRun(ctx context.Context, timeout time.Duration, dir string, env []string, bin string, args ...string) (safecmd.Output, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := safecmd.Command(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = append(cmd.Env, env...)
	out, err := safecmd.Run(ctx, cmd)
	if errors.Is(err, context.DeadlineExceeded) {
		return out, deployErrTimeout
	}
	return out, err
}

// DeployResult is the outcome of a site deploy.
type DeployResult struct {
	Success    bool
	Output     string
	CommitHash *string
	DurationMs uint64
}

// DeployReleaseInfo is one atomic-deploy release.
type DeployReleaseInfo struct {
	ID         string  `json:"id"`
	Active     bool    `json:"active"`
	CommitHash *string `json:"commit_hash"`
	CreatedAt  string  `json:"created_at"`
}

// DeploySshCommand validates key_path and builds GIT_SSH_COMMAND. Only keys
// under the deploy-keys directory are allowed; host keys are checked against
// the panel's own known_hosts (accept-new), never blindly accepted.
func DeploySshCommand(keyPath string) (string, error) {
	if strings.Contains(keyPath, "..") {
		return "", errors.New("Deploy key path must not contain '..'")
	}
	if !strings.HasPrefix(keyPath, deployKeysDir) {
		return "", fmt.Errorf("Deploy key must be under %s/, got: %s", deployKeysDir, keyPath)
	}
	canon, err := deployCanonicalize(keyPath)
	if err != nil {
		return "", fmt.Errorf("Deploy key not found: %v", nginxIOErr(err))
	}
	base, err := deployCanonicalize(deployKeysDir)
	if err != nil {
		return "", fmt.Errorf("Deploy keys directory not found: %v", nginxIOErr(err))
	}
	if !deployPathStartsWith(canon, base) {
		return "", errors.New("Deploy key path resolved outside the allowed directory")
	}
	return fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/etc/dockpanel/known_hosts", canon), nil
}

// deployCanonicalize is Rust's fs::canonicalize: absolute, symlinks resolved,
// and an error if the path does not exist.
func deployCanonicalize(p string) (string, error) {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	return filepath.Abs(r)
}

// deployPathStartsWith is Path::starts_with: whole components only.
func deployPathStartsWith(p, base string) bool {
	return p == base || strings.HasPrefix(p, strings.TrimSuffix(base, "/")+"/")
}

func deployIsSymlink(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

func deployIsDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// deployForeignEntries lists top-level entries of siteDir the panel cannot
// prove it wrote. Creating a site writes a filler page, so a first deploy
// never meets an empty destination; clearing the way is only defensible for
// files the panel wrote, which is why this asks about CONTENT rather than a
// name (`index.html` is the most ordinary filename there is).
func deployForeignEntries(siteDir string) []string {
	entries, err := os.ReadDir(siteDir)
	if err != nil {
		return nil
	}
	var foreign []string
	for _, e := range entries {
		if !deployPanelOwned(filepath.Join(siteDir, e.Name())) {
			foreign = append(foreign, e.Name())
		}
	}
	sort.Strings(foreign)
	return foreign
}

// deployPanelOwned: did the panel put path there? A directory qualifies only
// when everything below it does; an unreadable one does not — absence of
// proof is not proof.
func deployPanelOwned(path string) bool {
	if !deployIsDir(path) {
		return NginxIsPlaceholderPage(path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !deployPanelOwned(filepath.Join(path, e.Name())) {
			return false
		}
	}
	return true
}

// deployMergeInto moves every top-level entry of from into to. Renaming the
// clone onto the site dir cannot work (non-empty destination); entry by entry,
// anything the clone does NOT supply is left alone, which keeps a document
// root present when a repository ships no public/.
func deployMergeInto(from, to string) ([]string, error) {
	entries, err := os.ReadDir(from)
	if err != nil {
		return nil, fmt.Errorf("Failed to read the staged clone: %v", nginxIOErr(err))
	}
	var moved []string
	for _, e := range entries {
		target := filepath.Join(to, e.Name())
		switch {
		case deployIsSymlink(target):
			err = os.Remove(target)
		case deployIsDir(target):
			err = os.RemoveAll(target)
		default:
			if _, serr := os.Stat(target); serr == nil {
				err = os.Remove(target)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("Failed to replace %s: %v", target, nginxIOErr(err))
		}
		if err := os.Rename(filepath.Join(from, e.Name()), target); err != nil {
			return nil, fmt.Errorf("Failed to move %s into place: %v", e.Name(), nginxIOErr(err))
		}
		moved = append(moved, e.Name())
	}
	return moved, nil
}

// deployGitNoExec is prefixed to every git invocation against a deployed
// tree. Ownership is the real control (`.git` is root's — see
// deployHandTreeToWebUser); this is the belt to those braces for installs
// upgrading from v2.64.0/v2.64.1, whose repositories were handed to www-data
// and may carry a planted hook or core.fsmonitor. Command scope overrides a
// repository's own config. A missing hooksPath means "no hooks", not an error.
var deployGitNoExec = []string{"-c", "core.hooksPath=/var/empty/dockpanel-no-hooks", "-c", "core.fsmonitor="}

func deployGit(args ...string) []string {
	return append(append([]string{}, deployGitNoExec...), args...)
}

func deployOwnedByRoot(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// deployDiscardRepoWeDoNotOwn: git reads a repository's config and hooks/ as
// executable instruction, so root may only operate on its own. A foreign one
// is discarded, not repaired (repairing = chowning what the web user wrote
// back to root and executing it). The caller clones again.
func deployDiscardRepoWeDoNotOwn(siteDir string, out *strings.Builder) {
	gitDir := siteDir + "/.git"
	if _, err := os.Stat(gitDir); err != nil || deployOwnedByRoot(gitDir) {
		return
	}
	out.WriteString("==> This site's repository is not owned by root, so running git against it as root is unsafe. Discarding it and cloning the branch again.\n")
	_ = os.RemoveAll(gitDir)
}

// deployHandTreeToWebUser hands a deployed tree to the web server without
// handing over the repository. PHP-FPM (www-data) must write the app's own
// directory; v2.64.0's recursive chown also gave it `.git`, which git runs as
// root next deploy. So: everything but `.git` is www-data's; `.git` is root's
// and private; the site dir is root:www-data, setgid (new files keep the
// group) and STICKY (the app cannot unlink `.git` and plant its own). `.git`
// is never handed over even momentarily.
func deployHandTreeToWebUser(ctx context.Context, dir string) {
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.Name() == ".git" {
				continue
			}
			_, _ = deployRun(ctx, 0, "", nil, "chown", "-R", "www-data:www-data", filepath.Join(dir, e.Name()))
		}
	}
	_, _ = deployRun(ctx, 0, "", nil, "chown", "root:www-data", dir)
	_, _ = deployRun(ctx, 0, "", nil, "chmod", "3775", dir)
	gitDir := dir + "/.git"
	if _, err := os.Stat(gitDir); err == nil {
		_, _ = deployRun(ctx, 0, "", nil, "chown", "-R", "root:root", gitDir)
		_, _ = deployRun(ctx, 0, "", nil, "chmod", "-R", "go-rwx", gitDir)
	}
}

// deployHandTreeExceptGit is the staging/migration variant: chown everything
// but `.git` to www-data and keep `.git` root's and private — no dir mode
// change.
func deployHandTreeExceptGit(ctx context.Context, dir string) {
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.Name() == ".git" {
				continue
			}
			_, _ = deployRun(ctx, 0, "", nil, "chown", "-R", "www-data:www-data", filepath.Join(dir, e.Name()))
		}
	}
	gitDir := strings.TrimSuffix(dir, "/") + "/.git"
	if _, err := os.Stat(gitDir); err == nil {
		_, _ = deployRun(ctx, 0, "", nil, "chown", "-R", "root:root", gitDir)
		_, _ = deployRun(ctx, 0, "", nil, "chmod", "-R", "go-rwx", gitDir)
	}
}

func deployShortHead(ctx context.Context, dir string) *string {
	out, err := deployRun(ctx, 0, "", nil, "git", deployGit("-C", dir, "rev-parse", "--short", "HEAD")...)
	if err != nil || !out.Success() {
		return nil
	}
	h := strings.TrimSpace(nginxLossy(out.Stdout))
	return &h
}

// DeployCloneOrPull clones or pulls a repository into the site's webroot.
func DeployCloneOrPull(ctx context.Context, domain, repoURL, branch string, keyPath *string) (DeployResult, error) {
	start := time.Now()
	siteDir := deployWebroot + "/" + domain
	gitDir := siteDir + "/.git"
	var buf strings.Builder
	fail := func() (DeployResult, error) {
		return DeployResult{Output: buf.String(), DurationMs: uint64(time.Since(start).Milliseconds())}, nil
	}

	// SSRF: this process is the one that actually dials repo_url.
	if err := SsrfGuardValidateRepoURLNotInternal(repoURL); err != nil {
		return DeployResult{}, err
	}
	env := []string{"GIT_TERMINAL_PROMPT=0"}
	if keyPath != nil {
		ssh, err := DeploySshCommand(*keyPath)
		if err != nil {
			return DeployResult{}, err
		}
		env = append(env, "GIT_SSH_COMMAND="+ssh)
	}

	// Git's `dubious ownership` guard stays on: v2.64.1 lifted it per
	// invocation, which together with v2.64.0's chown made every git-deployed
	// site a www-data-to-root escalation. The repository is kept root's own
	// instead.
	deployDiscardRepoWeDoNotOwn(siteDir, &buf)

	if _, err := os.Stat(gitDir); err == nil {
		fetch, err := deployRun(ctx, 120*time.Second, "", env, "git", deployGit("-C", siteDir, "fetch", "origin", branch)...)
		if errors.Is(err, deployErrTimeout) {
			return DeployResult{}, errors.New("git fetch timed out")
		}
		if err != nil {
			return DeployResult{}, fmt.Errorf("git fetch failed: %v", err)
		}
		buf.WriteString(nginxLossy(fetch.Stdout) + nginxLossy(fetch.Stderr))
		if !fetch.Success() {
			return fail()
		}
		reset, err := deployRun(ctx, 0, "", nil, "git", deployGit("-C", siteDir, "reset", "--hard", "origin/"+branch)...)
		if err != nil {
			return DeployResult{}, fmt.Errorf("git reset failed: %v", err)
		}
		buf.WriteString(nginxLossy(reset.Stdout) + nginxLossy(reset.Stderr))
		// Checked: a failed reset (e.g. the branch changed and the old
		// checkout holds local commits) used to report success over a tree
		// still serving the previous release.
		if !reset.Success() {
			return fail()
		}
	} else {
		// Fresh clone. The destination is not reliably empty — creating a site
		// writes a filler page and git refuses a non-empty destination — so
		// clone to one side and move the result in: a repo shipping no public/
		// still leaves a document root, and anything the panel did not write is
		// refused rather than destroyed.
		if err := os.MkdirAll(siteDir, 0o755); err != nil {
			return DeployResult{}, fmt.Errorf("Failed to create site dir: %v", nginxIOErr(err))
		}
		if foreign := deployForeignEntries(siteDir); len(foreign) > 0 {
			fmt.Fprintf(&buf, "==> Refusing to deploy into %s: it already holds files the panel did not write (%s).\n    Move them aside, or turn on atomic deploys, which build each release in its own directory.\n",
				siteDir, strings.Join(foreign, ", "))
			return fail()
		}
		// Stage beside the site, never inside it: nginx must never see a
		// half-finished checkout.
		staging := fmt.Sprintf("%s/.%s.deploy-staging", deployWebroot, domain)
		_ = os.RemoveAll(staging)
		clone, err := deployRun(ctx, 300*time.Second, "", env, "git",
			deployGit("clone", "--branch", branch, "--single-branch", "--depth", "50", repoURL, staging)...)
		if err != nil {
			_ = os.RemoveAll(staging)
			if errors.Is(err, deployErrTimeout) {
				return DeployResult{}, errors.New("git clone timed out")
			}
			return DeployResult{}, fmt.Errorf("git clone failed: %v", err)
		}
		buf.WriteString(nginxLossy(clone.Stdout) + nginxLossy(clone.Stderr))
		if !clone.Success() {
			_ = os.RemoveAll(staging)
			return fail()
		}
		moved, err := deployMergeInto(staging, siteDir)
		_ = os.RemoveAll(staging)
		if err != nil {
			return DeployResult{}, err
		}
		fmt.Fprintf(&buf, "==> Placed %d entries into %s\n", len(moved), siteDir)

		// Static/PHP sites are served from public/; if the repo supplies none,
		// the filler survives and is what visitors get — say so.
		publicDir := siteDir + "/public"
		if !nginxContains(moved, "public") && deployIsDir(publicDir) && deployPanelOwned(publicDir) {
			buf.WriteString("==> NOTE: this repository has no public/ directory, and static and PHP sites are served from one, so visitors still get the placeholder page. Move the site's files under public/, or use a runtime that proxies to a process.\n")
		}
	}

	deployHandTreeToWebUser(ctx, siteDir)
	return DeployResult{Success: true, Output: buf.String(), CommitHash: deployShortHead(ctx, siteDir),
		DurationMs: uint64(time.Since(start).Milliseconds())}, nil
}

// DeployRunScript runs a deploy script FILE from the site directory. script is
// a relative path inside the site dir (e.g. ".dockpanel/deploy.sh"), NOT bash.
func DeployRunScript(ctx context.Context, domain, script string) (bool, string, error) {
	if strings.TrimSpace(script) == "" {
		return true, "", nil
	}
	siteDir := deployWebroot + "/" + domain
	scriptPath := filepath.Join(siteDir, strings.TrimLeft(script, "/"))
	canonSite, err := deployCanonicalize(siteDir)
	if err != nil {
		return false, "", fmt.Errorf("Site directory not found: %v", nginxIOErr(err))
	}
	canonScript, err := deployCanonicalize(scriptPath)
	if err != nil {
		return false, "", fmt.Errorf("Deploy script not found: %v", nginxIOErr(err))
	}
	if !deployPathStartsWith(canonScript, canonSite) {
		return false, "", errors.New("Deploy script must be within the site directory")
	}
	if strings.Contains(script, "..") {
		return false, "", errors.New("Deploy script path must not contain '..'")
	}
	fi, err := os.Stat(canonScript)
	if err != nil {
		return false, "", fmt.Errorf("Deploy script not accessible: %v", nginxIOErr(err))
	}
	if !fi.Mode().IsRegular() {
		return false, "", errors.New("Deploy script path is not a regular file")
	}
	out, err := deployRun(ctx, 300*time.Second, siteDir, []string{"HOME=" + siteDir, "NODE_ENV=production"}, "bash", canonScript)
	if errors.Is(err, deployErrTimeout) {
		return false, "", errors.New("Deploy script timed out (5 min)")
	}
	if err != nil {
		return false, "", fmt.Errorf("Failed to run deploy script: %v", err)
	}
	return out.Success(), gitBuildTruncate(nginxLossy(out.Stdout)+nginxLossy(out.Stderr), 50_000, "...\n[output truncated]"), nil
}

// deploySwapSymlink points link at target atomically (temp link + rename).
func deploySwapSymlink(target, link, releaseID string) error {
	tmp := link + ".tmp." + releaseID
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("Failed to create symlink: %v", nginxIOErr(err))
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("Failed to swap symlink: %v", nginxIOErr(err))
	}
	return nil
}

// DeployAtomic clones into a new release directory, runs the script, then
// swaps the `current` symlink atomically (Capistrano-style):
//
//	/var/www/{domain}/releases/{timestamp}/  immutable release snapshots
//	/var/www/{domain}/current                symlink to the active release
//	/var/www/{domain}/shared/                persistent dirs (uploads, .env, logs)
func DeployAtomic(ctx context.Context, domain, repoURL, branch string, keyPath, deployScript *string, keepReleases uint32, sharedDirs []string) (DeployResult, error) {
	start := time.Now()
	siteDir := deployWebroot + "/" + domain
	releasesDir := siteDir + "/releases"
	sharedDir := siteDir + "/shared"
	currentLink := siteDir + "/current"
	elapsed := func() uint64 { return uint64(time.Since(start).Milliseconds()) }

	if err := SsrfGuardValidateRepoURLNotInternal(repoURL); err != nil {
		return DeployResult{}, err
	}
	if err := os.MkdirAll(releasesDir, 0o755); err != nil {
		return DeployResult{}, fmt.Errorf("Failed to create releases dir: %v", nginxIOErr(err))
	}
	if err := os.MkdirAll(sharedDir, 0o755); err != nil {
		return DeployResult{}, fmt.Errorf("Failed to create shared dir: %v", nginxIOErr(err))
	}

	releaseID := time.Now().UTC().Format("20060102150405")
	releaseDir := releasesDir + "/" + releaseID
	var buf strings.Builder
	fmt.Fprintf(&buf, "==> Creating release %s\n", releaseID)

	env := []string{"GIT_TERMINAL_PROMPT=0"}
	if keyPath != nil {
		ssh, err := DeploySshCommand(*keyPath)
		if err != nil {
			return DeployResult{}, err
		}
		env = append(env, "GIT_SSH_COMMAND="+ssh)
	}
	clone, err := deployRun(ctx, 300*time.Second, "", env, "git",
		deployGit("clone", "--branch", branch, "--single-branch", "--depth", "1", repoURL, releaseDir)...)
	if errors.Is(err, deployErrTimeout) {
		return DeployResult{}, errors.New("git clone timed out")
	}
	if err != nil {
		return DeployResult{}, fmt.Errorf("git clone failed: %v", err)
	}
	buf.WriteString(nginxLossy(clone.Stdout) + nginxLossy(clone.Stderr))
	if !clone.Success() {
		_ = os.RemoveAll(releaseDir)
		return DeployResult{Output: buf.String(), DurationMs: elapsed()}, nil
	}

	commit := deployShortHead(ctx, releaseDir)
	c := "unknown"
	if commit != nil {
		c = *commit
	}
	fmt.Fprintf(&buf, "==> Commit: %s\n", c)

	// Link shared directories and files into the release.
	for _, shared := range sharedDirs {
		sharedPath := sharedDir + "/" + shared
		releasePath := releaseDir + "/" + shared
		if strings.HasSuffix(shared, "/") || !strings.Contains(shared, ".") {
			_ = os.MkdirAll(sharedPath, 0o755)
		} else {
			// Shared file — create parent and touch.
			_ = os.MkdirAll(filepath.Dir(sharedPath), 0o755)
			if _, err := os.Stat(sharedPath); err != nil {
				_ = os.WriteFile(sharedPath, nil, 0o644)
			}
		}
		if _, err := os.Stat(releasePath); err == nil || deployIsSymlink(releasePath) {
			if deployIsDir(releasePath) {
				_ = os.RemoveAll(releasePath)
			} else {
				_ = os.Remove(releasePath)
			}
		}
		_ = os.MkdirAll(filepath.Dir(releasePath), 0o755)
		_ = os.Symlink(sharedPath, releasePath)
	}
	fmt.Fprintf(&buf, "==> Linked %d shared paths\n", len(sharedDirs))

	// Seed empty shared items from the previous release.
	if len(sharedDirs) > 0 {
		if prev, err := os.Readlink(currentLink); err == nil {
			for _, shared := range sharedDirs {
				oldPath := prev + "/" + shared
				sharedPath := sharedDir + "/" + shared
				if _, err := os.Stat(oldPath); err != nil || deployIsSymlink(oldPath) {
					continue
				}
				empty := true
				if fi, err := os.Stat(sharedPath); err == nil {
					if fi.IsDir() {
						if ents, err := os.ReadDir(sharedPath); err == nil {
							empty = len(ents) == 0
						}
					} else if fi.Mode().IsRegular() {
						empty = fi.Size() == 0
					}
				}
				if empty {
					_, _ = deployRun(ctx, 0, "", nil, "cp", "-a", oldPath, sharedPath)
				}
			}
		}
	}

	// Run the deploy script inside the release directory.
	if deployScript != nil && strings.TrimSpace(*deployScript) != "" {
		buf.WriteString("==> Running deploy script\n")
		scriptPath := filepath.Join(releaseDir, strings.TrimLeft(*deployScript, "/"))
		canonRelease, err1 := deployCanonicalize(releaseDir)
		canonScript, err2 := deployCanonicalize(scriptPath)
		if err1 == nil && err2 == nil {
			if !deployPathStartsWith(canonScript, canonRelease) {
				_ = os.RemoveAll(releaseDir)
				return DeployResult{}, errors.New("Deploy script must be within the release directory")
			}
			out, err := deployRun(ctx, 300*time.Second, releaseDir, []string{
				"HOME=" + releaseDir, "NODE_ENV=production", "RELEASE_DIR=" + releaseDir, "SHARED_DIR=" + sharedDir,
			}, "bash", canonScript)
			if errors.Is(err, deployErrTimeout) {
				return DeployResult{}, errors.New("Deploy script timed out (5 min)")
			}
			if err != nil {
				return DeployResult{}, fmt.Errorf("Failed to run deploy script: %v", err)
			}
			buf.WriteString(nginxLossy(out.Stdout) + nginxLossy(out.Stderr))
			if !out.Success() {
				buf.WriteString("\n==> Deploy script failed, removing release\n")
				_ = os.RemoveAll(releaseDir)
				return DeployResult{Output: buf.String(), CommitHash: commit, DurationMs: elapsed()}, nil
			}
		} else {
			buf.WriteString("==> Deploy script not found, skipping\n")
		}
	}

	if err := deploySwapSymlink(releaseDir, currentLink, releaseID); err != nil {
		return DeployResult{}, err
	}
	fmt.Fprintf(&buf, "==> Activated release %s\n", releaseID)

	// Compatibility symlink public → current/public, so nginx (serving
	// /var/www/{domain}/public) needs no change.
	publicLink := siteDir + "/public"
	publicTarget := siteDir + "/current/public"
	if _, err := os.Stat(publicTarget); err == nil {
		needsUpdate := true
		if deployIsSymlink(publicLink) {
			if t, err := os.Readlink(publicLink); err == nil && t == publicTarget {
				needsUpdate = false
			}
		}
		if needsUpdate {
			if deployIsDir(publicLink) && !deployIsSymlink(publicLink) {
				// First atomic deploy: keep the real public/ as a backup.
				_ = os.Rename(publicLink, sharedDir+"/_pre_atomic_public_backup")
				buf.WriteString("==> Migrated existing public/ to shared/_pre_atomic_public_backup\n")
			} else {
				_ = os.Remove(publicLink)
			}
			_ = os.Symlink(publicTarget, publicLink)
			buf.WriteString("==> Created public → current/public symlink\n")
		}
	}

	// Same split as the non-atomic path: never hand `.git` to www-data.
	deployHandTreeToWebUser(ctx, releaseDir)

	// Keep the N most recent releases.
	if entries, err := os.ReadDir(releasesDir); err == nil {
		var releases []string
		for _, e := range entries {
			if e.IsDir() {
				releases = append(releases, e.Name())
			}
		}
		sort.Strings(releases)
		if len(releases) > int(keepReleases) {
			for _, old := range releases[:len(releases)-int(keepReleases)] {
				fmt.Fprintf(&buf, "==> Removing old release %s\n", old)
				_ = os.RemoveAll(releasesDir + "/" + old)
			}
		}
	}
	buf.WriteString("==> Zero-downtime deploy complete\n")
	return DeployResult{Success: true, Output: buf.String(), CommitHash: commit, DurationMs: elapsed()}, nil
}

// DeployListReleases lists a site's releases, newest first.
func DeployListReleases(ctx context.Context, domain string) ([]DeployReleaseInfo, error) {
	releasesDir := fmt.Sprintf("%s/%s/releases", deployWebroot, domain)
	var active string
	if t, err := os.Readlink(fmt.Sprintf("%s/%s/current", deployWebroot, domain)); err == nil {
		active = filepath.Base(t)
	}
	releases := []DeployReleaseInfo{}
	if _, err := os.Stat(releasesDir); err != nil {
		return releases, nil
	}
	entries, err := os.ReadDir(releasesDir)
	if err != nil {
		return nil, fmt.Errorf("Failed to read releases: %v", nginxIOErr(err))
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := releasesDir + "/" + e.Name()
		info := DeployReleaseInfo{ID: e.Name(), Active: active != "" && active == e.Name()}
		// Birth time (statx), as Rust's Metadata::created; "" when the
		// filesystem does not record one.
		var stx unix.Statx_t
		if unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_BTIME, &stx) == nil && stx.Mask&unix.STATX_BTIME != 0 {
			info.CreatedAt = SslRFC3339(time.Unix(stx.Btime.Sec, int64(stx.Btime.Nsec)).UTC())
		}
		// Reads back because `.git` stays root's. A release still owned by
		// www-data (pre-fix) answers nil rather than being adopted.
		if _, err := os.Stat(path + "/.git"); err == nil {
			info.CommitHash = deployShortHead(ctx, path)
		}
		releases = append(releases, info)
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].ID > releases[j].ID })
	return releases, nil
}

// DeployActivateRelease rolls back to a release by swapping `current`.
func DeployActivateRelease(domain, releaseID string) error {
	if releaseID == "" || len(releaseID) > 20 || strings.Trim(releaseID, "0123456789") != "" {
		return errors.New("Invalid release ID")
	}
	releaseDir := fmt.Sprintf("%s/%s/releases/%s", deployWebroot, domain, releaseID)
	if !deployIsDir(releaseDir) {
		return fmt.Errorf("Release %s not found", releaseID)
	}
	return deploySwapSymlink(releaseDir, fmt.Sprintf("%s/%s/current", deployWebroot, domain), releaseID)
}

// DeployGenerateDeployKey generates an ed25519 deploy key pair for name.
// Returns (public key, private key path).
func DeployGenerateDeployKey(ctx context.Context, name string) (string, string, error) {
	if err := os.MkdirAll(deployKeysDir, 0o755); err != nil {
		return "", "", fmt.Errorf("Failed to create keys dir: %v", nginxIOErr(err))
	}
	keyPath := deployKeysDir + "/" + name
	pubPath := keyPath + ".pub"
	_ = os.Remove(keyPath)
	_ = os.Remove(pubPath)
	out, err := deployRun(ctx, 0, "", nil, "ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "dockpanel-deploy@"+name)
	if err != nil {
		return "", "", fmt.Errorf("ssh-keygen failed: %v", err)
	}
	if !out.Success() {
		return "", "", fmt.Errorf("ssh-keygen failed: %s", nginxLossy(out.Stderr))
	}
	_ = os.Chmod(keyPath, 0o600)
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return "", "", fmt.Errorf("Failed to read public key: %v", nginxIOErr(err))
	}
	return strings.TrimSpace(string(pub)), keyPath, nil
}
