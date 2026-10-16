package safecmd

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Tests run unprivileged and cannot create /var/lib/dockpanel.
	dir, _ := os.MkdirTemp("", "dockpanel-test-capture")
	captureDir = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func afterSep(argv []string) []string {
	return argv[slices.Index(argv, "--")+1:]
}

func TestCommandEnvIsSanitised(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/evil.so")
	cmd := Command(context.Background(), "env")
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "LD_PRELOAD") {
			t.Fatal("inherited LD_PRELOAD reached the child")
		}
	}
	if !slices.Contains(cmd.Env, "DOCKER_CONFIG="+DockerConfigDir) || !slices.Contains(cmd.Env, "PATH="+SafePath) {
		t.Fatalf("missing safe defaults: %v", cmd.Env)
	}
}

func TestRunReportsExitCodeAndTimeout(t *testing.T) {
	out, err := Exec(context.Background(), "sh", "-c", "echo hi; echo err >&2; exit 3")
	if err != nil || out.ExitCode != 3 || string(out.Stdout) != "hi\n" || string(out.Stderr) != "err\n" {
		t.Fatalf("got %+v, %v", out, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := Exec(ctx, "sleep", "5"); err == nil {
		t.Fatal("a killed-by-timeout child must return an error, not a plain exit code")
	}
}

func TestEscapeHatchPassesNoFileDescriptorsAndWaits(t *testing.T) {
	argv := NewUnsandboxed("dnf").argv
	if slices.Contains(argv, "--pipe") || slices.Contains(argv, "-P") {
		t.Fatal("--pipe passes fds over D-Bus, which SELinux denies on RHEL")
	}
	if !slices.Contains(argv, "--wait") {
		t.Fatal("must wait for the inner command")
	}
	c := &capture{out: "/var/lib/dockpanel/run/x.out", err: "/var/lib/dockpanel/run/x.err"}
	p := c.properties()
	if !slices.Contains(p, "StandardOutput=file:/var/lib/dockpanel/run/x.out") ||
		!slices.Contains(p, "StandardError=file:/var/lib/dockpanel/run/x.err") {
		t.Fatalf("capture properties: %v", p)
	}
}

func TestInnerEnvForwardedAndArgvOrderPreserved(t *testing.T) {
	u := NewUnsandboxed("apt-get", "PGPASSWORD=s3cret").Arg("install").Arg("-y", "redis-server")
	if !slices.Contains(u.argv, "--setenv=PGPASSWORD=s3cret") {
		t.Fatal("extra env not forwarded")
	}
	if got := afterSep(u.argv); !slices.Equal(got, []string{"apt-get", "install", "-y", "redis-server"}) {
		t.Fatalf("inner argv %v", got)
	}
}

func TestDollarEscaping(t *testing.T) {
	u := NewUnsandboxed("usermod").Arg("-p", "$6$abcdefgh$somehashvalue", "someuser")
	if !slices.Contains(u.argv, "$$6$$abcdefgh$$somehashvalue") || slices.Contains(u.argv, "$6$abcdefgh$somehashvalue") {
		t.Fatalf("hash not escaped for systemd-run: %v", u.argv)
	}
	plain := []string{"-u", "30001", "-d", "/var/dockpanel-sftp/example.com", "sftp30001"}
	u = NewUnsandboxed("useradd").Arg(plain...)
	if !slices.Equal(afterSep(u.argv), append([]string{"useradd"}, plain...)) {
		t.Fatal("argument without $ must be unchanged")
	}
}

func TestUnitArgPlacementAndNames(t *testing.T) {
	for _, env := range [][]string{nil, {"PGPASSWORD=s3cret"}, {"PGPASSWORD=s3cret", "MYSQL_PWD=x"}} {
		u := NewUnsandboxed("dnf", env...).Arg("install", "-y", "redis")
		bin, unit := u.insertUnitArg()
		if bin != "dnf" {
			t.Fatalf("binary %q", bin)
		}
		sep := slices.Index(u.argv, "--")
		if u.argv[sep-1] != "--unit="+unit {
			t.Fatalf("--unit must sit right before -- (env %d): %v", len(env), u.argv)
		}
		if !slices.Equal(u.argv[sep+1:], []string{"dnf", "install", "-y", "redis"}) {
			t.Fatalf("inner argv %v", u.argv[sep+1:])
		}
		suffix, ok := strings.CutPrefix(unit, "dockpanel-op-")
		if !ok || len(suffix) != 32 || strings.Trim(suffix, "0123456789abcdef") != "" {
			t.Fatalf("unit name %q", unit)
		}
	}
	_, a := NewUnsandboxed("dnf").insertUnitArg()
	_, b := NewUnsandboxed("dnf").insertUnitArg()
	if a == b {
		t.Fatal("unit names collided")
	}
}

func TestCaptureDirIsWritableByPID1(t *testing.T) {
	if strings.HasPrefix(CaptureDir, "/tmp") || strings.HasPrefix(CaptureDir, "/var/tmp") {
		t.Fatal("init_t cannot write tmp_t on the RHEL family")
	}
}

func TestDockerEnvFile(t *testing.T) {
	f, err := NewDockerEnvFile([2]string{"MYSQL_PWD", "t0psecret"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.Path(), "t0psecret") {
		t.Fatal("secret leaked into the path")
	}
	body, _ := os.ReadFile(f.Path())
	info, _ := os.Stat(f.Path())
	if string(body) != "MYSQL_PWD=t0psecret\n" || info.Mode().Perm() != 0o600 {
		t.Fatalf("body %q mode %v", body, info.Mode().Perm())
	}
	f.Close()
	if _, err := os.Stat(f.Path()); !os.IsNotExist(err) {
		t.Fatal("env file must not outlive Close")
	}

	g, _ := NewDockerEnvFile([2]string{"A", "1"}, [2]string{"B", "2"})
	defer g.Close()
	if body, _ := os.ReadFile(g.Path()); string(body) != "A=1\nB=2\n" {
		t.Fatalf("multi-var body %q", body)
	}
	if _, err := NewDockerEnvFile([2]string{"MYSQL_PWD", "line1\nline2"}); err == nil {
		t.Fatal("an embedded newline must be refused")
	}
}
