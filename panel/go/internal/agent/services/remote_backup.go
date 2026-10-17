package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// RemoteBackupSshpassMissing is returned when the binary a password-
// authenticated SFTP destination execs is absent. A named constant because
// the caller must recognise it to answer 4xx: a 5xx makes the panel replace
// the sentence with an incident reference, telling the operator their agent
// broke when the box is simply missing a package.
const RemoteBackupSshpassMissing = "sshpass is not installed on this server, and it is required for " +
	"password-authenticated SFTP destinations. The panel can install it for you from " +
	"Settings, or use an SSH key instead."

func remoteBackupRandU64() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

// remoteBackupTempFile writes a 0600 curl config holding the S3 credentials
// so they never appear in the process listing. Remove it with defer.
func remoteBackupTempFile(label, content string) (string, error) {
	path := fmt.Sprintf("/tmp/.dockpanel-s3-%s-%016x", label, remoteBackupRandU64())
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("Failed to write S3 config: %v", err)
	}
	_ = os.Chmod(path, 0o600)
	return path, nil
}

// remoteBackupCredConfig quotes the keys for curl's config grammar: inside
// "...", backslash and quote are escaped, and a line break would start a new
// curl option (e.g. `output = /etc/...`), so it is refused outright.
func remoteBackupCredConfig(label, accessKey, secretKey string) (string, error) {
	if strings.ContainsAny(accessKey+secretKey, "\r\n\x00") {
		return "", fmt.Errorf("S3 access key and secret key must not contain line breaks")
	}
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace
	return remoteBackupTempFile(label, fmt.Sprintf("user = \"%s:%s\"", esc(accessKey), esc(secretKey)))
}

// remoteBackupCheckS3Endpoint refuses an endpoint that is not http(s) or that
// points at link-local space — the cloud metadata services (169.254.169.254,
// fd00:ec2::254) hand out the instance's own credentials. Private ranges stay
// allowed on purpose: a MinIO on the LAN is a normal destination, and only
// admins can configure one.
func remoteBackupCheckS3Endpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("S3 endpoint must be an http:// or https:// URL")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "metadata.google.internal" || host == "metadata" {
		return fmt.Errorf("S3 endpoint %s points at a cloud metadata service", host)
	}
	ips := []net.IP{net.ParseIP(host)}
	if ips[0] == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil // unresolvable: curl will report it with the real error
		}
		ips = addrs
	}
	for _, ip := range ips {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.Equal(net.ParseIP("fd00:ec2::254")) {
			return fmt.Errorf("S3 endpoint %s resolves to link-local address %s (cloud metadata), refused", host, ip)
		}
	}
	return nil
}

// remoteBackupS3Curl runs curl against the S3 endpoint and returns (status, body).
//
// These calls used --fail, which says nothing about 3xx; without -L curl
// prints the redirect body, transfers nothing and exits 0 — so a bucket in
// the wrong region, or an http:// endpoint redirecting to https, reported an
// upload that never happened (measured: a green policy run against an empty
// bucket). Following redirects is NOT the fix (a SigV4 signature is bound to
// host+path, and curl downgrades PUT to GET on 301/302); requiring an
// explicit 2xx is. One runner for all four operations on purpose — the same
// latent bug sat in every sibling.
func remoteBackupS3Curl(args []string, timeout time.Duration, label string) (int, string, error) {
	// --fail is deliberately absent: it suppresses the body, where S3 puts
	// the reason. The status check replaces it.
	// Only http(s), on the first request and on any redirect: curl would
	// otherwise happily read file:// or speak gopher:// for a crafted endpoint.
	full := append([]string{"--silent", "--show-error", "--proto", "=http,https", "--proto-redir", "=http,https", "-w", "\n%{http_code}"}, args...)
	// The context kills curl on timeout (it must not keep running against the
	// endpoint in the background).
	out, timedOut, err := backupsRun(timeout, "curl", full...)
	if timedOut {
		return 0, "", fmt.Errorf("%s timed out", label)
	}
	if err != nil {
		return 0, "", fmt.Errorf("Failed to run curl: %v", err)
	}
	stdout := backupsLossy(out.Stdout)
	var body, codeStr string
	if i := strings.LastIndex(stdout, "\n"); i >= 0 {
		body, codeStr = strings.TrimSpace(stdout[:i]), strings.TrimSpace(stdout[i+1:])
	} else {
		codeStr = strings.TrimSpace(stdout)
	}
	// curl itself failed (DNS, refused, TLS) — there is no HTTP status.
	code, perr := strconv.ParseUint(codeStr, 10, 16)
	if perr != nil {
		detail := strings.TrimSpace(backupsLossy(out.Stderr))
		if detail == "" {
			detail = body
		}
		return 0, "", fmt.Errorf("%s failed: %s", label, detail)
	}
	return int(code), body, nil
}

// remoteBackupS3Ok is true only for 2xx; a 3xx is not success.
func remoteBackupS3Ok(code int) bool { return code >= 200 && code < 300 }

// remoteBackupS3Detail trims an S3 error body to something a log line can carry.
func remoteBackupS3Detail(code int, body string) string {
	b := strings.TrimSpace(body)
	if b == "" {
		return fmt.Sprintf("HTTP %d", code)
	}
	if r := []rune(b); len(r) > 300 {
		b = string(r[:300])
	}
	return fmt.Sprintf("HTTP %d: %s", code, b)
}

// RemoteBackupUploadS3 uploads a backup file to S3-compatible storage using
// curl --aws-sigv4.
func RemoteBackupUploadS3(fpath, bucket, region, endpoint, accessKey, secretKey, remotePath string) (string, error) {
	if err := remoteBackupCheckS3Endpoint(endpoint); err != nil {
		return "", err
	}
	if _, err := os.Stat(fpath); err != nil {
		return "", fmt.Errorf("Backup file not found: %s", fpath)
	}
	filename := filepath.Base(fpath)
	prefix := strings.Trim(remotePath, "/")
	url := fmt.Sprintf("%s/%s/%s", endpoint, bucket, filename)
	if prefix != "" {
		url = fmt.Sprintf("%s/%s/%s/%s", endpoint, bucket, prefix, filename)
	}
	slog.Info(fmt.Sprintf("Uploading %s to %s", filename, url))

	cfg, err := remoteBackupCredConfig("upload", accessKey, secretKey)
	if err != nil {
		return "", err
	}
	code, body, err := remoteBackupS3Curl([]string{
		"--aws-sigv4", "aws:amz:" + region + ":s3", "-K", cfg,
		"-X", "PUT", "-H", "Content-Type: application/gzip", "-T", fpath, url,
	}, 600*time.Second, "Upload")
	os.Remove(cfg)
	if err != nil {
		return "", err
	}
	if !remoteBackupS3Ok(code) {
		return "", fmt.Errorf("S3 upload failed: %s", remoteBackupS3Detail(code, body))
	}
	slog.Info(fmt.Sprintf("Upload complete: %s (HTTP %d)", filename, code))
	return url, nil
}

// remoteBackupSftpOpts builds the options every SFTP operation shares — one
// copy, so upload and test cannot drift (ConnectTimeout once existed only on
// the test).
//
//   - UserKnownHostsFile=/etc/dockpanel/known_hosts: accept-new pins on first
//     use, and pinning is a WRITE; ~/.ssh cannot be created under
//     ProtectHome=yes. /etc/dockpanel is writable and shared with git deploys.
//     /dev/null or StrictHostKeyChecking=no would discard verification.
//   - BatchMode=yes ONLY for keys: it disables password auth, leaving sshpass
//     nothing to answer. And `sftp -b` sets BatchMode itself, so the password
//     case must say BatchMode=no out loud.
func remoteBackupSftpOpts(port uint16, password, keyPath *string) []string {
	args := []string{
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=/etc/dockpanel/known_hosts",
		"-o", "ConnectTimeout=10",
		"-P", strconv.Itoa(int(port)),
	}
	if keyPath != nil || password == nil {
		args = append(args, "-o", "BatchMode=yes")
	} else {
		args = append(args, "-o", "BatchMode=no")
	}
	if keyPath != nil {
		args = append(args, "-i", *keyPath)
	}
	return args
}

// remoteBackupSftpQuote quotes one path as a single sftp batch argument. A
// batch line is parsed by sftp's tokeniser, not a shell: an unquoted space
// made `put local /backups/my dir/f.tgz` write to /backups/my under the
// source name and exit 0. Double quotes carry spaces, single quotes and globs
// literally; only backslash and double quote need escaping.
func remoteBackupSftpQuote(path string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, ch := range path {
		if ch == '\\' || ch == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(ch)
	}
	b.WriteByte('"')
	return b.String()
}

// remoteBackupRejectUnquotablePath: in a batch script a newline STARTS A NEW
// COMMAND, so a remote_path carrying one appends attacker-chosen sftp
// operations. remote_path arrives unvalidated, so this is the only guard.
func remoteBackupRejectUnquotablePath(path string) error {
	if strings.ContainsAny(path, "\n\r") {
		return errors.New("Remote path may not contain a line break")
	}
	return nil
}

// remoteBackupSftpMkdirScript emits one `-mkdir` per ancestor, shallowest
// first. sftp has no mkdir -p, and a plain mkdir of an EXISTING directory
// fails and aborts the batch; the `-` prefix continues past it.
func remoteBackupSftpMkdirScript(dir string) string {
	absolute := strings.HasPrefix(dir, "/")
	var out, acc strings.Builder
	for _, comp := range strings.Split(dir, "/") {
		if comp == "" {
			continue
		}
		if acc.Len() == 0 {
			if absolute {
				acc.WriteByte('/')
			}
		} else {
			acc.WriteByte('/')
		}
		acc.WriteString(comp)
		out.WriteString("-mkdir " + remoteBackupSftpQuote(acc.String()) + "\n")
	}
	return out.String()
}

// remoteBackupProbeSeq makes each Test Connection's local probe unique, so
// two destinations tested at once cannot delete each other's file.
var remoteBackupProbeSeq atomic.Uint64

// remoteBackupCommandDetail joins both streams: internal-sftp writes its
// refusal ("This service allows sftp connections only.") to STDOUT, leaving
// stderr with only ssh's known-hosts banner (issue #102).
func remoteBackupCommandDetail(out safecmd.Output) string {
	var parts []string
	if e := strings.TrimSpace(backupsLossy(out.Stderr)); e != "" {
		parts = append(parts, e)
	}
	if o := strings.TrimSpace(backupsLossy(out.Stdout)); o != "" {
		parts = append(parts, o)
	}
	if len(parts) == 0 {
		return "no output from sftp"
	}
	return strings.Join(parts, " | ")
}

// remoteBackupRunSftp runs sftp, through `sshpass -e` when a password is the
// credential (the password travels in SSHPASS, never argv). A key beats a
// password when both are supplied. The batch script goes on stdin (`-b -`):
// no temp file under ProtectSystem=strict, no world-readable batch naming the
// destination; the scripts are a few hundred bytes so writing before reading
// cannot deadlock.
func remoteBackupRunSftp(program string, args []string, password, keyPath *string, timeout time.Duration, label string, batchScript *string) (safecmd.Output, error) {
	prog, finalArgs := program, args
	var pwEnv *string
	if password != nil && keyPath == nil {
		prog, finalArgs, pwEnv = "sshpass", append([]string{"-e", program}, args...), password
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := safecmd.Command(ctx, prog, finalArgs...)
	if pwEnv != nil {
		cmd.Env = append(cmd.Env, "SSHPASS="+*pwEnv)
	}
	if batchScript != nil {
		cmd.Stdin = strings.NewReader(*batchScript)
	}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return safecmd.Output{}, fmt.Errorf("%s timed out", label)
	}
	out := safecmd.Output{Stdout: so.Bytes(), Stderr: se.Bytes()}
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out, nil
	case errors.As(err, &ee):
		out.ExitCode = ee.ExitCode()
		return out, nil
	case prog == "sshpass" && (errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist)):
		// Absent sshpass used to surface as an opaque "No such file or
		// directory" 502 on fresh installs; name the binary and the remedy.
		return out, errors.New(RemoteBackupSshpassMissing)
	default:
		return out, fmt.Errorf("Failed to run %s: %v", prog, err)
	}
}

// RemoteBackupUploadSftp uploads a backup file over the SFTP subsystem.
//
// Both the mkdir and the transfer go over SFTP in one connection. They used
// to be SSH exec requests (`ssh mkdir -p`, then scp), which `ForceCommand
// internal-sftp` (chrooted SFTP-only accounts) replaces — so every such
// destination failed (issue #102). scp is gone because legacy `scp -t` (RHEL
// 8, Ubuntu 20.04) fails the same way.
func RemoteBackupUploadSftp(fpath, host string, port uint16, username string, password, keyPath *string, remotePath string) (string, error) {
	if _, err := os.Stat(fpath); err != nil {
		return "", fmt.Errorf("Backup file not found: %s", fpath)
	}
	filename := filepath.Base(fpath)
	dir := strings.TrimRight(remotePath, "/")
	if err := remoteBackupRejectUnquotablePath(dir); err != nil {
		return "", err
	}
	if err := remoteBackupRejectUnquotablePath(fpath); err != nil {
		return "", err
	}
	remoteFile := dir + "/" + filename
	remoteDest := fmt.Sprintf("%s@%s:%s", username, host, remoteFile)
	slog.Info(fmt.Sprintf("Uploading %s via SFTP to %s", filename, remoteDest))

	script := remoteBackupSftpMkdirScript(dir) +
		fmt.Sprintf("put %s %s\n", remoteBackupSftpQuote(fpath), remoteBackupSftpQuote(remoteFile))
	args := append(remoteBackupSftpOpts(port, password, keyPath), "-b", "-", username+"@"+host)
	out, err := remoteBackupRunSftp("sftp", args, password, keyPath, 600*time.Second, "Upload", &script)
	if err != nil {
		return "", err
	}
	if !out.Success() {
		return "", fmt.Errorf("SFTP upload failed: %s", remoteBackupCommandDetail(out))
	}
	slog.Info("SFTP upload complete: " + filename)
	return remoteDest, nil
}

// RemoteBackupTestS3 tests S3 access by doing what an upload does: PUT a tiny
// probe where backups will go, then DELETE it. A HEAD of the bucket root once
// passed read-only keys, keys scoped to another prefix, and 301 buckets — a
// test that connects differently from the upload tests nothing. A failed
// delete is reported: such a destination cannot enforce retention either.
func RemoteBackupTestS3(bucket, region, endpoint, accessKey, secretKey, pathPrefix string) error {
	if err := remoteBackupCheckS3Endpoint(endpoint); err != nil {
		return err
	}
	prefix := strings.Trim(pathPrefix, "/")
	key := fmt.Sprintf(".dockpanel-write-probe-%016x", remoteBackupRandU64())
	if prefix != "" {
		key = prefix + "/" + key
	}
	url := fmt.Sprintf("%s/%s/%s", endpoint, bucket, key)
	cfg, err := remoteBackupCredConfig("test", accessKey, secretKey)
	if err != nil {
		return err
	}
	defer os.Remove(cfg)
	sigv4 := "aws:amz:" + region + ":s3"
	code, body, err := remoteBackupS3Curl([]string{
		"--aws-sigv4", sigv4, "-K", cfg, "-X", "PUT", "-H", "Content-Type: text/plain",
		"--data-binary", "dockpanel write probe", url,
	}, 15*time.Second, "Connection test")
	if err != nil {
		return err
	}
	if !remoteBackupS3Ok(code) {
		return fmt.Errorf("S3 connection test failed: %s", remoteBackupS3Detail(code, body))
	}
	delCode, delBody, err := remoteBackupS3Curl([]string{
		"--aws-sigv4", sigv4, "-K", cfg, "-X", "DELETE", url,
	}, 15*time.Second, "Connection test cleanup")
	if err != nil {
		return err
	}
	if !remoteBackupS3Ok(delCode) && delCode != 404 {
		return fmt.Errorf("S3 write succeeded but the test object could not be removed (%s) — "+
			"retention will not be able to delete old backups either", remoteBackupS3Detail(delCode, delBody))
	}
	return nil
}

// RemoteBackupTestSftp tests SFTP access by doing what an upload does:
// create the directory, write a probe, remove it — over the same transport.
// Connecting and running `exit` passed destinations whose directory did not
// exist (including the /backups default). `put /dev/null` is refused ("not a
// regular file"), so the probe is a real zero-byte file in the agent's
// private tmp.
func RemoteBackupTestSftp(host string, port uint16, username string, password, keyPath *string, remotePath string) error {
	dir := strings.TrimRight(remotePath, "/")
	if err := remoteBackupRejectUnquotablePath(dir); err != nil {
		return err
	}
	probeLocal := filepath.Join(os.TempDir(), fmt.Sprintf(".dockpanel-sftp-probe-%d-%d", os.Getpid(), remoteBackupProbeSeq.Add(1)-1))
	var script string
	if dir == "" {
		// No path to probe: this proves only that the SFTP subsystem opens.
		script = "pwd\n"
	} else {
		if err := os.WriteFile(probeLocal, nil, 0o600); err != nil {
			return fmt.Errorf("Could not stage a local probe file: %v", err)
		}
		remoteProbe := dir + "/.dockpanel-write-probe"
		script = fmt.Sprintf("%sput %s %s\nrm %s\n", remoteBackupSftpMkdirScript(dir),
			remoteBackupSftpQuote(probeLocal), remoteBackupSftpQuote(remoteProbe), remoteBackupSftpQuote(remoteProbe))
	}
	args := append(remoteBackupSftpOpts(port, password, keyPath), "-b", "-", username+"@"+host)
	out, err := remoteBackupRunSftp("sftp", args, password, keyPath, 20*time.Second, "Connection test", &script)
	// Removed on every path — a probe per failed test is a slow leak.
	_ = os.Remove(probeLocal)
	if err != nil {
		return err
	}
	if !out.Success() {
		// Auth and permission failures read differently; pass the raw output through.
		return fmt.Errorf("SFTP test failed: %s", remoteBackupCommandDetail(out))
	}
	return nil
}

// RemoteBackupListS3 lists object keys in a bucket under a prefix.
func RemoteBackupListS3(bucket, region, endpoint, accessKey, secretKey, prefix string) ([]string, error) {
	if err := remoteBackupCheckS3Endpoint(endpoint); err != nil {
		return nil, err
	}
	clean := strings.Trim(prefix, "/")
	url := fmt.Sprintf("%s/%s/?list-type=2", endpoint, bucket)
	if clean != "" {
		url = fmt.Sprintf("%s/%s/?list-type=2&prefix=%s/", endpoint, bucket, clean)
	}
	cfg, err := remoteBackupCredConfig("list", accessKey, secretKey)
	if err != nil {
		return nil, err
	}
	code, body, err := remoteBackupS3Curl([]string{"--aws-sigv4", "aws:amz:" + region + ":s3", "-K", cfg, url}, 30*time.Second, "List")
	os.Remove(cfg)
	if err != nil {
		return nil, err
	}
	if !remoteBackupS3Ok(code) {
		return nil, fmt.Errorf("S3 list failed: %s", remoteBackupS3Detail(code, body))
	}
	// Extract <Key> elements from the XML response.
	keys := []string{}
	parts := strings.Split(body, "<Key>")
	for _, s := range parts[1:] {
		k, _, _ := strings.Cut(s, "</Key>")
		keys = append(keys, k)
	}
	return keys, nil
}

// RemoteBackupDeleteS3 deletes an object. 204 and 404 both mean "it is not
// there", which is what the caller asked for.
func RemoteBackupDeleteS3(bucket, region, endpoint, accessKey, secretKey, key string) error {
	if err := remoteBackupCheckS3Endpoint(endpoint); err != nil {
		return err
	}
	url := fmt.Sprintf("%s/%s/%s", endpoint, bucket, key)
	cfg, err := remoteBackupCredConfig("delete", accessKey, secretKey)
	if err != nil {
		return err
	}
	code, body, err := remoteBackupS3Curl([]string{"--aws-sigv4", "aws:amz:" + region + ":s3", "-K", cfg, "-X", "DELETE", url}, 15*time.Second, "Delete")
	os.Remove(cfg)
	if err != nil {
		return err
	}
	if remoteBackupS3Ok(code) || code == 404 {
		return nil
	}
	return fmt.Errorf("S3 delete failed: %s", remoteBackupS3Detail(code, body))
}
