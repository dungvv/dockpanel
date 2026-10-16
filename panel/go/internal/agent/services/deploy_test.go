package services

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func deployTestWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func deployTestGit(t *testing.T, dir string, args ...string) *exec.Cmd {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git must be installed for this test to mean anything")
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	return cmd
}

func deployTestRepo(t *testing.T, dir string) {
	t.Helper()
	_ = deployTestGit(t, dir, "init", "-q", "-b", "main", ".").Run()
	deployTestWrite(t, filepath.Join(dir, "f.txt"), "x")
	_ = deployTestGit(t, dir, "add", "-A").Run()
	_ = deployTestGit(t, dir, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x").Run()
}

// The filler page is recognised through the SAME helper that writes it, and
// an operator's own file is not.
func TestDeployOnlyThePanelsOwnPageIsAdoptable(t *testing.T) {
	root := t.TempDir()
	ours := filepath.Join(root, "public/index.html")
	deployTestWrite(t, ours, NginxPlaceholderPage("example.test"))
	if !deployPanelOwned(ours) || !deployPanelOwned(filepath.Join(root, "public")) {
		t.Fatal("the panel's own page (and a dir of only filler) must read as the panel's")
	}
	theirs := filepath.Join(root, "public/about.html")
	deployTestWrite(t, theirs, "<h1>my real page</h1>")
	if deployPanelOwned(theirs) {
		t.Fatal("an operator's file is never the panel's")
	}
	if deployPanelOwned(filepath.Join(root, "public")) {
		t.Fatal("one foreign file makes the whole directory foreign")
	}
}

// A site directory as put_site leaves it is adoptable in BOTH layouts;
// anything else is named rather than deleted.
func TestDeployAFreshlyCreatedSiteIsAdoptableAndARealOneIsNot(t *testing.T) {
	for _, layout := range []string{"public/index.html", "index.html"} {
		root := t.TempDir()
		deployTestWrite(t, filepath.Join(root, layout), NginxPlaceholderPage("example.test"))
		if f := deployForeignEntries(root); len(f) != 0 {
			t.Fatalf("a site the panel just created must be clonable into (%s): %v", layout, f)
		}
	}
	root := t.TempDir()
	deployTestWrite(t, filepath.Join(root, "public/index.html"), NginxPlaceholderPage("example.test"))
	deployTestWrite(t, filepath.Join(root, "wp-config.php"), "<?php // a real site")
	if f := deployForeignEntries(root); !slices.Equal(f, []string{"wp-config.php"}) {
		t.Fatalf("a real site must be refused, and named: %v", f)
	}
}

// The merge replaces what the clone supplies and LEAVES what it does not.
func TestDeployMergeReplacesWhatItSuppliesAndKeepsWhatItDoesNot(t *testing.T) {
	base := t.TempDir()
	site, staged := filepath.Join(base, "site"), filepath.Join(base, "staged")
	deployTestWrite(t, filepath.Join(site, "public/index.html"), NginxPlaceholderPage("example.test"))
	deployTestWrite(t, filepath.Join(staged, "index.php"), "<?php echo 'app';")
	deployTestWrite(t, filepath.Join(staged, ".git/HEAD"), "ref: refs/heads/main\n")

	moved, err := deployMergeInto(staged, site)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(moved, "index.php") || !slices.Contains(moved, ".git") {
		t.Fatalf("moved = %v; the repository itself must move too", moved)
	}
	if _, err := os.Stat(filepath.Join(site, "index.php")); err != nil {
		t.Fatal("the repository's files land in the site")
	}
	if _, err := os.Stat(filepath.Join(site, "public/index.html")); err != nil {
		t.Fatal("an untouched document root must survive, or nginx serves nothing")
	}
}

// The premise, EXECUTED: real git refuses the destination put_site leaves
// behind. If this stops being true the staging dance is dead code.
func TestDeployGitRefusesTheDestinationANewSiteLeavesBehind(t *testing.T) {
	base := t.TempDir()
	origin := filepath.Join(base, "origin")
	_ = os.MkdirAll(origin, 0o755)
	deployTestRepo(t, origin)
	for _, layout := range []string{"public/index.html", "index.html"} {
		dest := filepath.Join(base, "dest-"+strings.ReplaceAll(layout, "/", "-"))
		deployTestWrite(t, filepath.Join(dest, layout), NginxPlaceholderPage("example.test"))
		out, err := deployTestGit(t, base, "clone", "-q", origin, dest).CombinedOutput()
		if err == nil {
			t.Fatalf("git cloned into a populated web root (%s) — the staging path is now dead code", layout)
		}
		s := strings.ToLower(string(out))
		if !strings.Contains(s, "not an empty directory") && !strings.Contains(s, "already exists") {
			t.Fatalf("unexpected git failure for %s: %s", layout, s)
		}
	}
	empty := filepath.Join(base, "dest-empty")
	_ = os.MkdirAll(empty, 0o755)
	if out, err := deployTestGit(t, base, "clone", "-q", origin, empty).CombinedOutput(); err != nil {
		t.Fatalf("an empty destination must still clone: %s", out)
	}
}

// ── ownership: a repository root does not own ───────────────────────────

func deployTestIsRoot() bool { return os.Geteuid() == 0 }

// deployTestForeignRepo builds a repository in the state v2.64.0/v2.64.1 left
// every git-deployed site in — owned by another uid — with a core.fsmonitor
// payload planted the way a compromised application would (no exec bit, no
// hooks/ dir needed).
func deployTestForeignRepo(t *testing.T) (string, string) {
	t.Helper()
	if !deployTestIsRoot() {
		t.Skip("needs root to chown")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	deployTestRepo(t, dir)
	proof := filepath.Join(dir, "EXECUTED-AS-ROOT")
	deployTestPlant(t, dir, proof)
	if err := exec.Command("chown", "-R", "nobody", dir).Run(); err != nil {
		t.Skip("chown unavailable")
	}
	return dir, proof
}

func deployTestPlant(t *testing.T, dir, proof string) {
	t.Helper()
	cfg, err := os.ReadFile(filepath.Join(dir, ".git/config"))
	if err != nil {
		t.Fatal(err)
	}
	cfg = append(cfg, []byte("[core]\n\tfsmonitor = \"/bin/sh -c 'id -u > "+proof+"'\"\n")...)
	if err := os.WriteFile(filepath.Join(dir, ".git/config"), cfg, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Control: git still refuses a foreign-owned repository, and the
// command-scope safe.directory exception v2.64.1 shipped really did lift it
// and run the payload as root. If this stops reproducing, the arms below
// measure nothing.
func TestDeployTheExceptionV2641ShippedReallyDidRunTheSitesCodeAsRoot(t *testing.T) {
	dir, proof := deployTestForeignRepo(t)
	if err := deployTestGit(t, dir, "-C", dir, "reset", "--hard", "HEAD").Run(); err == nil {
		t.Fatal("git accepted a repository owned by another user — the ownership guard is gone")
	}
	if _, err := os.Stat(proof); err == nil {
		t.Fatal("the guard refused the command and it ran anyway")
	}
	out, err := deployTestGit(t, dir, "-c", "safe.directory="+dir, "-C", dir, "reset", "--hard", "HEAD").CombinedOutput()
	if err != nil {
		t.Fatalf("the v2.64.1 shape no longer runs at all, so this control proves nothing: %s", out)
	}
	if b, _ := os.ReadFile(proof); strings.TrimSpace(string(b)) != "0" {
		t.Fatal("the v2.64.1 shape did not execute the planted payload as root")
	}
}

// deployGitNoExec neutralises a planted payload ON ITS OWN — the repository
// is root's, so the ownership guard is out of the picture (testing against a
// foreign repo would pass for the wrong reason).
func TestDeployTheSuppressionPairNeutralisesAPlantedPayloadByItself(t *testing.T) {
	dir := t.TempDir()
	deployTestRepo(t, dir)
	proof := filepath.Join(dir, "EXECUTED")
	deployTestPlant(t, dir, proof)

	_ = deployTestGit(t, dir, "-C", dir, "reset", "--hard", "HEAD").Run()
	if _, err := os.Stat(proof); err != nil {
		t.Fatal("the payload did not fire even without the pair, so this arm cannot tell whether the pair does anything")
	}
	_ = os.Remove(proof)

	out, err := deployTestGit(t, dir, deployGit("-C", dir, "reset", "--hard", "HEAD")...).CombinedOutput()
	if err != nil {
		t.Fatalf("the shipped invocation failed outright: %s", out)
	}
	if _, err := os.Stat(proof); err == nil {
		t.Fatal("the suppression pair did not stop the repository's own config executing")
	}
}

// A repository root does not own is discarded, not adopted — and loudly.
func TestDeployAForeignRepositoryIsDiscardedRatherThanRepaired(t *testing.T) {
	dir, _ := deployTestForeignRepo(t)
	if deployOwnedByRoot(dir + "/.git") {
		t.Fatal("fixture failed to hand the repository to another uid")
	}
	var out strings.Builder
	deployDiscardRepoWeDoNotOwn(dir, &out)
	if _, err := os.Stat(dir + "/.git"); err == nil {
		t.Fatal("a repository owned by another user was kept")
	}
	if !strings.Contains(out.String(), "not owned by root") {
		t.Fatal("the discard was silent")
	}
}

// After handing a tree over, `.git` is still root's and private, and the
// site dir is setgid + sticky.
func TestDeployHandingTheTreeOverDoesNotHandOverTheRepository(t *testing.T) {
	if !deployTestIsRoot() {
		t.Skip("needs root to chown")
	}
	if err := exec.Command("id", "www-data").Run(); err != nil {
		t.Skip("no www-data user")
	}
	dir := t.TempDir()
	deployTestWrite(t, filepath.Join(dir, ".git/config"), "[core]\n")
	deployTestWrite(t, filepath.Join(dir, "public/index.php"), "<?php\n")

	deployHandTreeToWebUser(context.Background(), dir)

	if !deployOwnedByRoot(dir+"/.git") || !deployOwnedByRoot(dir+"/.git/config") {
		t.Fatal("the repository was handed to the web user — the v2.64.0 defect")
	}
	if fi, _ := os.Stat(dir + "/.git"); fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the repository is accessible beyond root (mode %o)", fi.Mode().Perm())
	}
	fi, _ := os.Stat(dir)
	if fi.Mode()&os.ModeSticky == 0 {
		t.Fatal("the site directory is not sticky")
	}
	if fi.Mode()&os.ModeSetgid == 0 {
		t.Fatal("the site directory is not setgid")
	}
}

func TestDeploySshCommandRefusesKeysOutsideTheDir(t *testing.T) {
	for _, p := range []string{"/etc/dockpanel/deploy-keys/../x", "/root/.ssh/id_rsa"} {
		if _, err := DeploySshCommand(p); err == nil {
			t.Errorf("%q must be refused", p)
		}
	}
}

func TestDeployActivateReleaseValidatesID(t *testing.T) {
	for _, id := range []string{"", "../x", "2024abc", "123456789012345678901"} {
		if err := DeployActivateRelease("example.com", id); err == nil || err.Error() != "Invalid release ID" {
			t.Errorf("%q: %v", id, err)
		}
	}
}
