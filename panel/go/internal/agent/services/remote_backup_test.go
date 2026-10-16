package services

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

func TestQuotesPathsABatchParserWouldOtherwiseSplit(t *testing.T) {
	for in, want := range map[string]string{
		"/backups":    `"/backups"`,
		"/my backups": `"/my backups"`,
		"/od'brien":   `"/od'brien"`,
		`/say"hi`:     `"/say\"hi"`,
		`/back\slash`: `"/back\\slash"`,
		"/we*ird?":    `"/we*ird?"`,
	} {
		if got := remoteBackupSftpQuote(in); got != want {
			t.Errorf("%q: got %s want %s", in, got, want)
		}
	}
}

func TestMkdirScriptCreatesEveryAncestorShallowestFirst(t *testing.T) {
	for in, want := range map[string]string{
		"/srv/backups/dockpanel": "-mkdir \"/srv\"\n-mkdir \"/srv/backups\"\n-mkdir \"/srv/backups/dockpanel\"\n",
		"/backups":               "-mkdir \"/backups\"\n",
		"backups/nightly":        "-mkdir \"backups\"\n-mkdir \"backups/nightly\"\n",
		"":                       "",
	} {
		if got := remoteBackupSftpMkdirScript(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(remoteBackupSftpMkdirScript("/a/b/c")), "\n") {
		if !strings.HasPrefix(line, "-mkdir ") {
			t.Errorf("unprefixed mkdir: %s", line)
		}
	}
}

func TestRejectsARemotePathThatWouldAppendASecondCommand(t *testing.T) {
	if remoteBackupRejectUnquotablePath("/backups") != nil || remoteBackupRejectUnquotablePath("/my backups") != nil {
		t.Error("plain paths refused")
	}
	if remoteBackupRejectUnquotablePath("/backups\nput /etc/shadow /pub/x") == nil || remoteBackupRejectUnquotablePath("/backups\rrm /pub/x") == nil {
		t.Error("line break accepted")
	}
}

func remoteBackupHasPair(args []string, a, b string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == a && args[i+1] == b {
			return true
		}
	}
	return false
}

func TestBatchmodeIsTurnedOffForPasswordAuthAndOnForKeys(t *testing.T) {
	pw, key := "secret", "/etc/dockpanel/id"
	p := remoteBackupSftpOpts(22, &pw, nil)
	if !remoteBackupHasPair(p, "-o", "BatchMode=no") {
		t.Errorf("password auth must disable BatchMode: %v", p)
	}
	k := remoteBackupSftpOpts(22, nil, &key)
	if !remoteBackupHasPair(k, "-o", "BatchMode=yes") {
		t.Errorf("key auth must keep BatchMode on: %v", k)
	}
	// sftp takes -P for the port; -p is "preserve times".
	if !remoteBackupHasPair(p, "-P", "22") {
		t.Errorf("port flag: %v", p)
	}
}

func TestDetailReportsARefusalThatArrivedOnStdout(t *testing.T) {
	if d := remoteBackupCommandDetail(safecmd.Output{Stdout: []byte("This service allows sftp connections only."), ExitCode: 1}); !strings.Contains(d, "sftp connections only") {
		t.Error(d)
	}
	if d := remoteBackupCommandDetail(safecmd.Output{ExitCode: 1}); d != "no output from sftp" {
		t.Error(d)
	}
	if d := remoteBackupCommandDetail(safecmd.Output{Stdout: []byte("out"), Stderr: []byte("err"), ExitCode: 1}); d != "err | out" {
		t.Error(d)
	}
}

// The S3 credential never reaches argv; it lives in a 0600 curl config.
func TestS3CredentialsGoToA0600ConfigNotArgv(t *testing.T) {
	p, err := remoteBackupCredConfig("unit", "AK", "SK")
	if err != nil {
		t.Skipf("cannot write /tmp: %v", err)
	}
	defer os.Remove(p)
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(p); string(b) != `user = "AK:SK"` {
		t.Fatalf("content %q", b)
	}
}

// End-to-end against a real sshd running ForceCommand internal-sftp. Set
// DOCKPANEL_SFTP_LAB=user:password@host:port:/remote/path to run it; skipped
// (and reported as skipped, never passed) otherwise.
func TestLabUploadAndTestSurviveForceCommand(t *testing.T) {
	spec := os.Getenv("DOCKPANEL_SFTP_LAB")
	if spec == "" {
		t.Skip("needs an sshd running ForceCommand internal-sftp; set DOCKPANEL_SFTP_LAB")
	}
	creds, rest, _ := strings.Cut(spec, "@")
	user, pass, _ := strings.Cut(creds, ":")
	parts := strings.SplitN(rest, ":", 3)
	port, _ := strconv.Atoi(parts[1])
	host, path := parts[0], parts[2]
	if err := RemoteBackupTestSftp(host, uint16(port), user, &pass, nil, path); err != nil {
		t.Fatalf("Test Connection through ForceCommand: %v", err)
	}
	local := filepath.Join(t.TempDir(), "dockpanel-sftp-lab-upload.txt")
	os.WriteFile(local, []byte("s339"), 0o600)
	dest, err := RemoteBackupUploadSftp(local, host, uint16(port), user, &pass, nil, path)
	if err != nil || !strings.Contains(dest, "dockpanel-sftp-lab-upload.txt") {
		t.Fatalf("upload: %v %s", err, dest)
	}
	// An uncreatable path must still FAIL, or the happy arms prove nothing.
	if err := RemoteBackupTestSftp(host, uint16(port), user, &pass, nil, "/proc/nope"); err == nil {
		t.Fatal("an uncreatable remote path must fail")
	}
}

func TestRemoteBackupCredConfigCannotInjectCurlOptions(t *testing.T) {
	if _, err := remoteBackupCredConfig("t", "AK", "secret\noutput = /etc/passwd"); err == nil {
		t.Fatal("a newline in the secret must be refused")
	}
	path, err := remoteBackupCredConfig("t", `A"K`, `s\e"c`)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	b, _ := os.ReadFile(path)
	if string(b) != `user = "A\"K:s\\e\"c"` {
		t.Fatalf("config %q", b)
	}
}
