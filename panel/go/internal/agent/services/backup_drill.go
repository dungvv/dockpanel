package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// BackupDrillDrillResult is the result of an end-to-end drill (extract →
// scratch container → probe → teardown). Distinct from verification: a drill
// RUNS the restored backup.
type BackupDrillDrillResult struct {
	Passed       bool    `json:"passed"`
	HTTPStatus   *int32  `json:"http_status"`
	BodyExcerpt  *string `json:"body_excerpt"`
	ErrorMessage *string `json:"error_message"`
	DurationMs   uint64  `json:"duration_ms"`
}

func backupDrillFailure(start time.Time, msg string) BackupDrillDrillResult {
	return BackupDrillDrillResult{ErrorMessage: &msg, DurationMs: uint64(time.Since(start).Milliseconds())}
}

func backupDrillPass(start time.Time, excerpt string) BackupDrillDrillResult {
	return BackupDrillDrillResult{Passed: true, BodyExcerpt: &excerpt, DurationMs: uint64(time.Since(start).Milliseconds())}
}

func backupDrillTake(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// backupDrillRun runs a command; timedOut distinguishes a fired bound from a
// failure (timeout 0 = unbounded, as in the Rust code).
func backupDrillRun(timeout time.Duration, bin string, args ...string) (out safecmd.Output, err error, timedOut bool) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	out, err = safecmd.Exec(ctx, bin, args...)
	return out, err, errors.Is(ctx.Err(), context.DeadlineExceeded)
}

// BackupDrillDrillSiteBackup extracts the backup to a scratch dir, mounts it
// read-only into a fresh nginx:alpine container with --network none, probes
// it with `docker exec wget`, and tears everything down. Any HTTP response
// (even 403/404) passes: the container booted and the mount worked.
func BackupDrillDrillSiteBackup(domain, filename string) (BackupDrillDrillResult, error) {
	start := time.Now()
	if filename == "" || strings.Contains(filename, "..") || strings.Contains(filename, "/") {
		return BackupDrillDrillResult{}, errors.New("Invalid filename")
	}
	backupPath := fmt.Sprintf("/var/backups/dockpanel/%s/%s", domain, filename)
	if _, err := os.Stat(backupPath); err != nil {
		return BackupDrillDrillResult{}, errors.New("Backup file not found")
	}
	drillID := uuid.NewString()
	scratch := "/var/lib/dockpanel/drills/" + drillID
	container := "dockpanel-drill-" + drillID[:8]

	result := backupDrillRunSite(backupPath, scratch, container, start)

	// Best-effort teardown (`--rm` should already handle the container).
	backupDrillRun(0, "docker", "rm", "-f", container)
	_ = os.RemoveAll(scratch)
	return result, nil
}

func backupDrillRunSite(backupPath, scratch, container string, start time.Time) BackupDrillDrillResult {
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		return backupDrillFailure(start, fmt.Sprintf("scratch dir: %v", err))
	}
	if out, err, _ := backupDrillRun(120*time.Second, "tar", "xzf", backupPath, "-C", scratch, "--no-same-owner", "--no-same-permissions"); err != nil || !out.Success() {
		return backupDrillFailure(start, "tar extract failed")
	}
	// --network none: a malicious backup can't phone home; loopback still works.
	if out, err, _ := backupDrillRun(30*time.Second, "docker",
		"run", "--rm", "-d", "--name", container, "--network", "none",
		"--memory=128m", "--cpus=0.5", "--read-only",
		"--tmpfs", "/var/cache/nginx", "--tmpfs", "/var/run",
		"-v", scratch+":/usr/share/nginx/html:ro", "nginx:alpine"); err != nil || !out.Success() {
		return backupDrillFailure(start, "nginx scratch container failed to start")
	}
	// Alpine nginx binds in ~200ms on a warm node.
	time.Sleep(500 * time.Millisecond)

	// busybox wget: --server-response prints the status line to stderr, -O -
	// the body to stdout, -T 5 caps the probe.
	out, err, timedOut := backupDrillRun(15*time.Second, "docker",
		"exec", container, "wget", "-q", "-O", "-", "--server-response", "-T", "5", "http://localhost/")
	if timedOut {
		return backupDrillFailure(start, "probe timeout")
	}
	if err != nil {
		return backupDrillFailure(start, fmt.Sprintf("docker exec failed: %v", err))
	}
	stderr, stdout := backupsLossy(out.Stderr), backupsLossy(out.Stdout)
	status := backupDrillParseHTTPStatus(stderr)
	r := BackupDrillDrillResult{Passed: status != nil, HTTPStatus: status}
	if stdout != "" {
		ex := backupDrillTake(stdout, 500)
		r.BodyExcerpt = &ex
	}
	// wget exit 0 = 2xx, exit 8 = non-2xx: both mean nginx is serving.
	if status == nil {
		msg := fmt.Sprintf("probe got no HTTP response (wget stderr: %s)", backupDrillTake(stderr, 200))
		r.ErrorMessage = &msg
	}
	r.DurationMs = uint64(time.Since(start).Milliseconds())
	return r
}

// backupDrillParseHTTPStatus returns the code of the first `HTTP/1.x NNN`
// line in busybox wget --server-response stderr.
func backupDrillParseHTTPStatus(stderr string) *int32 {
	for _, line := range strings.Split(stderr, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimLeft(line, " \t\r\v\f"), "HTTP/")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			return nil
		}
		n, err := strconv.ParseInt(f[1], 10, 32)
		if err != nil {
			return nil
		}
		c := int32(n)
		return &c
	}
	return nil
}

// ── Database drills ──
// Beyond verify (schema applied): after restore, sum row counts across user
// tables. Pass = data is queryable post-restore.

func backupDrillIsValidDbName(name string) bool { return backupVerifyIsValidName(name) }

// BackupDrillDrillDbBackup spins a temp engine container, restores the dump,
// then counts tables and rows. Schema-only databases pass with rows == 0 iff
// tables > 0.
func BackupDrillDrillDbBackup(dbType, dbName, filename string) (BackupDrillDrillResult, error) {
	start := time.Now()
	if !backupDrillIsValidDbName(dbName) {
		return BackupDrillDrillResult{}, errors.New("Invalid database name")
	}
	if !backupDrillIsValidDbName(filename) {
		return BackupDrillDrillResult{}, errors.New("Invalid filename")
	}
	backupPath := fmt.Sprintf("/var/backups/dockpanel/databases/%s/%s", dbName, filename)
	if _, err := os.Stat(backupPath); err != nil {
		return BackupDrillDrillResult{}, errors.New("Backup file not found")
	}
	container := "dockpanel-drill-db-" + uuid.NewString()[:8]
	const testPassword = "drill_test_pass_12345"
	var result BackupDrillDrillResult
	switch dbType {
	case "mysql", "mariadb":
		result = backupDrillRunMysql(backupPath, container, dbName, testPassword, start)
	case "postgres", "postgresql":
		result = backupDrillRunPostgres(backupPath, container, dbName, testPassword, start)
	default:
		result = backupDrillFailure(start, "Unsupported DB type for drill: "+dbType)
	}
	backupDrillRun(0, "docker", "rm", "-f", container)
	return result, nil
}

func backupDrillRunMysql(backupPath, container, dbName, password string, start time.Time) BackupDrillDrillResult {
	// Credential via --env-file, never argv.
	runEnv, err := safecmd.NewDockerEnvFile([2]string{"MYSQL_DATABASE", dbName}, [2]string{"MYSQL_ROOT_PASSWORD", password})
	if err != nil {
		return backupDrillFailure(start, fmt.Sprintf("Failed to prepare credentials: %v", err))
	}
	defer runEnv.Close()
	if out, err, _ := backupDrillRun(0, "docker", "run", "-d", "--name", container, "--network", "none",
		"--env-file", runEnv.Path(), "--memory=256m", "--cpus=1.0", "mariadb:11"); err != nil || !out.Success() {
		return backupDrillFailure(start, "mariadb scratch container failed to start")
	}
	execEnv, err := safecmd.NewDockerEnvFile([2]string{"MYSQL_PWD", password})
	if err != nil {
		return backupDrillFailure(start, fmt.Sprintf("Failed to prepare credentials: %v", err))
	}
	defer execEnv.Close()

	if !backupVerifyWaitReady(40, "--env-file", execEnv.Path(), container, "mariadb", "-u", "root", "-e", "SELECT 1") {
		return backupDrillFailure(start, "mariadb container not ready within 40s")
	}
	// The drill is billed as the strongest restore rehearsal: it must not
	// green-light a corrupt backup an operator might then keep as the only copy.
	if !backupVerifyZcatInto(backupPath, 180*time.Second, "--env-file", execEnv.Path(), container, "mariadb", "-u", "root", dbName) {
		return backupDrillFailure(start, "mariadb restore failed")
	}
	scalar := func(sql string) int64 {
		return backupDrillScalar("MYSQL_PWD", password, container, "mariadb", "-u", "root", dbName, "-e", sql, "--batch", "--skip-column-names")
	}
	tables := scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()")
	if tables == 0 {
		return backupDrillFailure(start, "no tables present after restore")
	}
	// table_rows is approximate for InnoDB but answers "is there any data?"
	// more cheaply than COUNT(*) per table.
	rows := scalar("SELECT IFNULL(SUM(table_rows),0) FROM information_schema.tables WHERE table_schema=DATABASE()")
	return backupDrillPass(start, fmt.Sprintf("%d tables, ~%d rows restored", tables, rows))
}

// backupDrillScalar runs a one-value query with its own env file; 0 on any error.
func backupDrillScalar(envKey, password, container string, args ...string) int64 {
	env, err := safecmd.NewDockerEnvFile([2]string{envKey, password})
	if err != nil {
		return 0
	}
	defer env.Close()
	return backupVerifyScalar(append([]string{"--env-file", env.Path(), container}, args...)...)
}

func backupDrillRunPostgres(backupPath, container, dbName, password string, start time.Time) BackupDrillDrillResult {
	runEnv, err := safecmd.NewDockerEnvFile([2]string{"POSTGRES_DB", dbName}, [2]string{"POSTGRES_USER", "drill"}, [2]string{"POSTGRES_PASSWORD", password})
	if err != nil {
		return backupDrillFailure(start, fmt.Sprintf("Failed to prepare credentials: %v", err))
	}
	defer runEnv.Close()
	if out, err, _ := backupDrillRun(0, "docker", "run", "-d", "--name", container, "--network", "none",
		"--env-file", runEnv.Path(), "--memory=256m", "--cpus=1.0", "postgres:16-alpine"); err != nil || !out.Success() {
		return backupDrillFailure(start, "postgres scratch container failed to start")
	}
	execEnv, err := safecmd.NewDockerEnvFile([2]string{"PGPASSWORD", password})
	if err != nil {
		return backupDrillFailure(start, fmt.Sprintf("Failed to prepare credentials: %v", err))
	}
	defer execEnv.Close()

	if !backupVerifyWaitReady(30, "--env-file", execEnv.Path(), container, "psql", "-U", "drill", "-d", dbName, "-c", "SELECT 1") {
		return backupDrillFailure(start, "postgres container not ready within 30s")
	}
	// --single-transaction makes the drill an all-or-nothing rehearsal;
	// ON_ERROR_STOP alone would leave a partial restore to be counted.
	if !backupVerifyZcatInto(backupPath, 180*time.Second, "--env-file", execEnv.Path(), container,
		"psql", "-U", "drill", "-d", dbName, "--quiet", "-v", "ON_ERROR_STOP=1", "--single-transaction") {
		return backupDrillFailure(start, "postgres restore failed")
	}
	scalar := func(sql string) int64 {
		return backupDrillScalar("PGPASSWORD", password, container, "psql", "-U", "drill", "-d", dbName, "-t", "-A", "-c", sql)
	}
	tables := scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'")
	if tables == 0 {
		return backupDrillFailure(start, "no tables present in public schema after restore")
	}
	// ANALYZE populates reltuples (a fresh restore has stats=0); bounded so a
	// giant dump doesn't hold the drill open.
	backupDrillRun(30*time.Second, "docker", "exec", "--env-file", execEnv.Path(), container, "psql", "-U", "drill", "-d", dbName, "-c", "ANALYZE")
	rows := scalar("SELECT COALESCE(SUM(reltuples)::bigint, 0) FROM pg_class WHERE relkind='r' AND relnamespace=(SELECT oid FROM pg_namespace WHERE nspname='public')")
	return backupDrillPass(start, fmt.Sprintf("%d tables, ~%d rows restored", tables, rows))
}

// ── Volume drills ──
// Beyond verify (host-side /tmp extract): restore into a real scratch Docker
// volume through the same driver/mount path real restores use, then read-test
// a sample of files through a fresh mount.

// BackupDrillDrillVolumeBackup runs a scratch volume + restore container +
// probe container.
func BackupDrillDrillVolumeBackup(containerName, filename string) (BackupDrillDrillResult, error) {
	start := time.Now()
	if !backupDrillIsValidDbName(containerName) {
		return BackupDrillDrillResult{}, errors.New("Invalid container name")
	}
	if !backupDrillIsValidDbName(filename) {
		return BackupDrillDrillResult{}, errors.New("Invalid filename")
	}
	backupDir := "/var/backups/dockpanel/volumes/" + containerName
	if _, err := os.Stat(backupDir + "/" + filename); err != nil {
		return BackupDrillDrillResult{}, errors.New("Backup file not found")
	}
	id := uuid.NewString()[:8]
	volume := "dockpanel-drill-vol-" + id
	restoreC := "dockpanel-drill-vrestore-" + id
	probeC := "dockpanel-drill-vprobe-" + id

	result := backupDrillRunVolume(backupDir, filename, volume, restoreC, probeC, start)

	// Containers first (they hold the volume open), then the volume.
	backupDrillRun(0, "docker", "rm", "-f", restoreC)
	backupDrillRun(0, "docker", "rm", "-f", probeC)
	backupDrillRun(0, "docker", "volume", "rm", "-f", volume)
	return result, nil
}

const backupDrillVolumeProbe = `set -e; files=$(find /vol -type f 2>/dev/null | wc -l); bytes=$(du -sb /vol 2>/dev/null | awk '{print $1}'); find /vol -type f 2>/dev/null | head -20 | xargs -r -I{} head -c 1 "{}" > /dev/null; echo "FILES=$files BYTES=$bytes"`

func backupDrillRunVolume(backupDir, filename, volume, restoreC, probeC string, start time.Time) BackupDrillDrillResult {
	if out, err, _ := backupDrillRun(0, "docker", "volume", "create", volume); err != nil || !out.Success() {
		return backupDrillFailure(start, "scratch volume create failed")
	}
	if out, err, _ := backupDrillRun(300*time.Second, "docker",
		"run", "--rm", "--name", restoreC, "--network", "none", "--memory=128m", "--cpus=0.5",
		"-v", volume+":/vol", "-v", backupDir+":/backup:ro", "alpine:3.19",
		"tar", "xzf", "/backup/"+filename, "-C", "/vol", "--no-same-owner", "--no-same-permissions"); err != nil || !out.Success() {
		return backupDrillFailure(start, "tar restore into scratch volume failed")
	}
	// Probe: read-only rootfs, volume mounted RO; counts files, sums bytes and
	// reads 1 byte of up to 20 files — enough to fault filesystem corruption
	// without scanning multi-GB volumes.
	out, err, timedOut := backupDrillRun(60*time.Second, "docker",
		"run", "--rm", "--name", probeC, "--network", "none", "--memory=128m", "--cpus=0.5",
		"--read-only", "--tmpfs", "/tmp", "-v", volume+":/vol:ro", "alpine:3.19",
		"sh", "-c", backupDrillVolumeProbe)
	switch {
	case timedOut:
		return backupDrillFailure(start, "volume probe timeout")
	case err != nil:
		return backupDrillFailure(start, fmt.Sprintf("docker probe error: %v", err))
	case !out.Success():
		return backupDrillFailure(start, "probe failed: "+backupDrillTake(backupsLossy(out.Stderr), 200))
	}
	files, bytes := backupDrillParseVolumeProbe(backupsLossy(out.Stdout))
	if files == 0 {
		return backupDrillFailure(start, "no files in restored volume")
	}
	return backupDrillPass(start, fmt.Sprintf("%d files, %d bytes restored", files, bytes))
}

// backupDrillParseVolumeProbe parses the `FILES=N BYTES=M` line.
func backupDrillParseVolumeProbe(stdout string) (files, bytes int64) {
	for _, tok := range strings.Fields(stdout) {
		if v, ok := strings.CutPrefix(tok, "FILES="); ok {
			files, _ = strconv.ParseInt(v, 10, 64)
		} else if v, ok := strings.CutPrefix(tok, "BYTES="); ok {
			bytes, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return files, bytes
}
