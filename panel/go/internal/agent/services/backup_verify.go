package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// BackupVerifyVerificationResult is the verify endpoints' response.
type BackupVerifyVerificationResult struct {
	Passed       bool                            `json:"passed"`
	ChecksRun    int32                           `json:"checks_run"`
	ChecksPassed int32                           `json:"checks_passed"`
	Details      []BackupVerifyVerificationCheck `json:"details"`
	DurationMs   uint64                          `json:"duration_ms"`
}

// BackupVerifyVerificationCheck is one named check.
type BackupVerifyVerificationCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

// backupVerifyExec runs docker/tar/find with an optional bound (0 = none, as
// in the Rust code). The bool is "ran and exited 0"; a timeout is reported
// separately by the caller where it matters.
func backupVerifyExec(timeout time.Duration, bin string, args ...string) (safecmd.Output, bool) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	out, err := safecmd.Exec(ctx, bin, args...)
	return out, err == nil && out.Success()
}

// backupVerifyZcatInto streams `zcat backupPath` into `docker exec -i …` (direct
// fd pipe, no shell) and reports success only if BOTH ends succeeded: a
// truncated .gz makes zcat fail while the client reads a clean EOF at a
// statement boundary and exits 0 (the EOF-as-success trap) — without the zcat
// check the safety net certifies a corrupt backup. The zcat wait is bounded
// (5s): it exits at once on every non-hang path.
func backupVerifyZcatInto(backupPath string, timeout time.Duration, dockerArgs ...string) bool {
	pr, pw, err := os.Pipe()
	if err != nil {
		return false
	}
	zctx, zcancel := context.WithCancel(context.Background())
	defer zcancel()
	zcat := safecmd.Command(zctx, "zcat", backupPath)
	zcat.Stdout = pw
	if err := zcat.Start(); err != nil {
		pr.Close()
		pw.Close()
		return false
	}
	pw.Close()

	dctx, dcancel := context.WithTimeout(context.Background(), timeout)
	defer dcancel()
	docker := safecmd.Command(dctx, "docker", append([]string{"exec", "-i"}, dockerArgs...)...)
	docker.Stdin = pr
	dockerOK := docker.Run() == nil && dctx.Err() == nil
	pr.Close()

	t := time.AfterFunc(5*time.Second, zcancel)
	defer t.Stop()
	zcatOK := zcat.Wait() == nil && zctx.Err() == nil
	return dockerOK && zcatOK
}

// backupVerifySiteBackupPassed: a site backup is verified only if every
// CRITICAL check passed. has_entry_point is informational (a valid non-web
// backup has no index.*). The old `checks_passed >= checks_run - 1` slack
// certified a non-extractable archive whenever extract_success was the single
// failing check.
func backupVerifySiteBackupPassed(checks []BackupVerifyVerificationCheck) bool {
	for _, c := range checks {
		if c.Name != "has_entry_point" && !c.Passed {
			return false
		}
	}
	return true
}

func backupVerifyTally(checks []BackupVerifyVerificationCheck) (run, passed int32) {
	for _, c := range checks {
		if c.Passed {
			passed++
		}
	}
	return int32(len(checks)), passed
}

func backupVerifyFileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// backupVerifyExtractAndCount extracts into a fresh temp dir and counts files.
func backupVerifyExtractAndCount(backupPath string, checks *[]BackupVerifyVerificationCheck, countMsg string, inspect func(dir string)) error {
	tempDir := "/tmp/dockpanel-verify-" + uuid.NewString()
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		return fmt.Errorf("Temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	_, ok := backupVerifyExec(120*time.Second, "tar", "xzf", backupPath, "-C", tempDir, "--no-same-owner", "--no-same-permissions")
	msg := "Failed to extract archive"
	if ok {
		msg = "Archive extracts cleanly"
	}
	*checks = append(*checks, BackupVerifyVerificationCheck{Name: "extract_success", Passed: ok, Message: msg})
	if !ok {
		return nil
	}
	out, _ := backupVerifyExec(0, "find", tempDir, "-type", "f")
	n := len(LogsLines(out.Stdout))
	*checks = append(*checks, BackupVerifyVerificationCheck{Name: "file_count", Passed: n > 0, Message: fmt.Sprintf(countMsg, n)})
	if inspect != nil {
		inspect(tempDir)
	}
	return nil
}

// BackupVerifyVerifySiteBackup extracts a site backup to a temp dir and checks
// file count and structure.
func BackupVerifyVerifySiteBackup(domain, filename string) (BackupVerifyVerificationResult, error) {
	start := time.Now()
	checks := []BackupVerifyVerificationCheck{}
	backupPath := fmt.Sprintf("/var/backups/dockpanel/%s/%s", domain, filename)
	fi, err := os.Stat(backupPath)
	if err != nil {
		return BackupVerifyVerificationResult{}, errors.New("Backup file not found")
	}
	checks = append(checks, BackupVerifyVerificationCheck{
		Name: "file_exists", Passed: fi.Size() > 100, Message: fmt.Sprintf("Backup file size: %d bytes", fi.Size()),
	})
	err = backupVerifyExtractAndCount(backupPath, &checks, "%d files extracted", func(dir string) {
		hasIndex := backupVerifyFileExists(dir+"/index.php") || backupVerifyFileExists(dir+"/index.html") ||
			backupVerifyFileExists(dir+"/public/index.html") || backupVerifyFileExists(dir+"/public/index.php")
		msg := "No index file found (may be expected for non-web backups)"
		if hasIndex {
			msg = "Entry point found (index.php/html)"
		}
		checks = append(checks, BackupVerifyVerificationCheck{Name: "has_entry_point", Passed: hasIndex, Message: msg})
	})
	if err != nil {
		return BackupVerifyVerificationResult{}, err
	}
	run, passed := backupVerifyTally(checks)
	return BackupVerifyVerificationResult{
		Passed: backupVerifySiteBackupPassed(checks), ChecksRun: run, ChecksPassed: passed,
		Details: checks, DurationMs: uint64(time.Since(start).Milliseconds()),
	}, nil
}

// backupVerifyIsValidName validates a resource name (Unicode alphanumerics
// plus -_. as in the Rust char::is_alphanumeric; '/' is never admitted).
func backupVerifyIsValidName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, c := range name {
		if !unicode.IsLetter(c) && !unicode.IsNumber(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// BackupVerifyVerifyDbBackup restores a database dump into a temporary
// container and checks it applied.
func BackupVerifyVerifyDbBackup(dbType, dbName, filename string) (BackupVerifyVerificationResult, error) {
	start := time.Now()
	checks := []BackupVerifyVerificationCheck{}
	if !backupVerifyIsValidName(dbName) {
		return BackupVerifyVerificationResult{}, errors.New("Invalid database name")
	}
	if !backupVerifyIsValidName(filename) {
		return BackupVerifyVerificationResult{}, errors.New("Invalid filename")
	}
	backupPath := fmt.Sprintf("/var/backups/dockpanel/databases/%s/%s", dbName, filename)
	fi, err := os.Stat(backupPath)
	if err != nil {
		return BackupVerifyVerificationResult{}, errors.New("Backup file not found")
	}
	checks = append(checks, BackupVerifyVerificationCheck{
		Name: "file_exists", Passed: fi.Size() > 30, Message: fmt.Sprintf("Dump file size: %d bytes", fi.Size()),
	})

	container := "dockpanel-verify-" + uuid.NewString()[:8]
	const testPassword = "verify_test_pass_12345"
	var restoreOK bool
	switch dbType {
	case "mysql", "mariadb":
		restoreOK = backupVerifyMysqlRestore(backupPath, container, dbName, testPassword, &checks)
	case "postgres", "postgresql":
		restoreOK = backupVerifyPostgresRestore(backupPath, container, dbName, testPassword, &checks)
	default:
		checks = append(checks, BackupVerifyVerificationCheck{
			Name: "restore", Passed: false, Message: "Unsupported DB type for verification: " + dbType,
		})
	}
	// Cleanup: remove the temporary container.
	backupVerifyExec(0, "docker", "rm", "-f", container)

	run, passed := backupVerifyTally(checks)
	return BackupVerifyVerificationResult{
		Passed: restoreOK && passed == run, ChecksRun: run, ChecksPassed: passed,
		Details: checks, DurationMs: uint64(time.Since(start).Milliseconds()),
	}, nil
}

// backupVerifyWaitReady polls `docker exec … <probe>` once a second.
func backupVerifyWaitReady(tries int, args ...string) bool {
	for range tries {
		time.Sleep(time.Second)
		if _, ok := backupVerifyExec(0, "docker", append([]string{"exec"}, args...)...); ok {
			return true
		}
	}
	return false
}

func backupVerifyScalar(args ...string) int64 {
	out, err := safecmd.Exec(context.Background(), "docker", append([]string{"exec"}, args...)...)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(backupsLossy(out.Stdout)), 10, 64)
	return n
}

func backupVerifyCheck(checks *[]BackupVerifyVerificationCheck, name string, ok bool, yes, no string) {
	msg := no
	if ok {
		msg = yes
	}
	*checks = append(*checks, BackupVerifyVerificationCheck{Name: name, Passed: ok, Message: msg})
}

func backupVerifyMysqlRestore(backupPath, container, dbName, password string, checks *[]BackupVerifyVerificationCheck) bool {
	// Bootstrap credential via --env-file, never `-e KEY=value` argv.
	runEnv, err := safecmd.NewDockerEnvFile([2]string{"MYSQL_DATABASE", dbName}, [2]string{"MYSQL_ROOT_PASSWORD", password})
	if err != nil {
		*checks = append(*checks, BackupVerifyVerificationCheck{Name: "temp_container", Message: fmt.Sprintf("Failed to prepare credentials: %v", err)})
		return false
	}
	defer runEnv.Close()
	if _, ok := backupVerifyExec(0, "docker", "run", "-d", "--name", container, "--env-file", runEnv.Path(), "--memory=256m", "mariadb:11"); !ok {
		*checks = append(*checks, BackupVerifyVerificationCheck{Name: "temp_container", Message: "Failed to start temporary MySQL container"})
		return false
	}
	execEnv, err := safecmd.NewDockerEnvFile([2]string{"MYSQL_PWD", password})
	if err != nil {
		*checks = append(*checks, BackupVerifyVerificationCheck{Name: "temp_container", Message: fmt.Sprintf("Failed to prepare credentials: %v", err)})
		return false
	}
	defer execEnv.Close()

	// Wait for MySQL to be ready (up to 40s).
	ready := backupVerifyWaitReady(40, "--env-file", execEnv.Path(), container, "mariadb", "-u", "root", "-e", "SELECT 1")
	backupVerifyCheck(checks, "temp_container", ready, "Temporary MySQL container ready", "MySQL container failed to start within 40s")
	if !ready {
		return false
	}

	restoreOK := backupVerifyZcatInto(backupPath, 120*time.Second, "--env-file", execEnv.Path(), container, "mariadb", "-u", "root", dbName)
	backupVerifyCheck(checks, "restore_dump", restoreOK, "Dump restored successfully", "Failed to restore dump")
	if !restoreOK {
		return false
	}

	tables := backupVerifyScalar("--env-file", execEnv.Path(), container, "mariadb", "-u", "root", dbName,
		"-e", "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()",
		"--batch", "--skip-column-names")
	*checks = append(*checks, BackupVerifyVerificationCheck{
		Name: "table_count", Passed: tables > 0, Message: fmt.Sprintf("%d tables found after restore", int32(tables)),
	})
	return tables > 0
}

func backupVerifyPostgresRestore(backupPath, container, dbName, password string, checks *[]BackupVerifyVerificationCheck) bool {
	runEnv, err := safecmd.NewDockerEnvFile([2]string{"POSTGRES_DB", dbName}, [2]string{"POSTGRES_USER", "verify"}, [2]string{"POSTGRES_PASSWORD", password})
	if err != nil {
		*checks = append(*checks, BackupVerifyVerificationCheck{Name: "temp_container", Message: fmt.Sprintf("Failed to prepare credentials: %v", err)})
		return false
	}
	defer runEnv.Close()
	if _, ok := backupVerifyExec(0, "docker", "run", "-d", "--name", container, "--env-file", runEnv.Path(), "--memory=256m", "postgres:16-alpine"); !ok {
		*checks = append(*checks, BackupVerifyVerificationCheck{Name: "temp_container", Message: "Failed to start temporary PostgreSQL container"})
		return false
	}
	execEnv, err := safecmd.NewDockerEnvFile([2]string{"PGPASSWORD", password})
	if err != nil {
		*checks = append(*checks, BackupVerifyVerificationCheck{Name: "temp_container", Message: fmt.Sprintf("Failed to prepare credentials: %v", err)})
		return false
	}
	defer execEnv.Close()

	ready := backupVerifyWaitReady(30, "--env-file", execEnv.Path(), container, "psql", "-U", "verify", "-d", dbName, "-c", "SELECT 1")
	backupVerifyCheck(checks, "temp_container", ready, "Temporary PostgreSQL container ready", "PostgreSQL container failed to start within 30s")
	if !ready {
		return false
	}

	// ON_ERROR_STOP + --single-transaction: otherwise psql reports success
	// for a dump whose statements failed and keeps the partial result, so a
	// truncated backup that produced *some* tables would pass the table count.
	restoreOK := backupVerifyZcatInto(backupPath, 120*time.Second, "--env-file", execEnv.Path(), container,
		"psql", "-U", "verify", "-d", dbName, "--quiet", "-v", "ON_ERROR_STOP=1", "--single-transaction")
	backupVerifyCheck(checks, "restore_dump", restoreOK, "Dump restored successfully", "Failed to restore dump")
	if !restoreOK {
		return false
	}

	tables := backupVerifyScalar("--env-file", execEnv.Path(), container, "psql", "-U", "verify", "-d", dbName,
		"-t", "-c", "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'")
	*checks = append(*checks, BackupVerifyVerificationCheck{
		Name: "table_count", Passed: tables > 0, Message: fmt.Sprintf("%d tables found after restore", int32(tables)),
	})
	return tables > 0
}

// BackupVerifyVerifyVolumeBackup extracts a volume backup to a temp dir and
// checks its contents.
func BackupVerifyVerifyVolumeBackup(containerName, filename string) (BackupVerifyVerificationResult, error) {
	start := time.Now()
	checks := []BackupVerifyVerificationCheck{}
	if !backupVerifyIsValidName(containerName) {
		return BackupVerifyVerificationResult{}, errors.New("Invalid container name")
	}
	if !backupVerifyIsValidName(filename) {
		return BackupVerifyVerificationResult{}, errors.New("Invalid filename")
	}
	backupPath := fmt.Sprintf("/var/backups/dockpanel/volumes/%s/%s", containerName, filename)
	fi, err := os.Stat(backupPath)
	if err != nil {
		return BackupVerifyVerificationResult{}, errors.New("Backup file not found")
	}
	checks = append(checks, BackupVerifyVerificationCheck{
		Name: "file_exists", Passed: fi.Size() > 50, Message: fmt.Sprintf("Volume backup size: %d bytes", fi.Size()),
	})
	if err := backupVerifyExtractAndCount(backupPath, &checks, "%d files in volume backup", nil); err != nil {
		return BackupVerifyVerificationResult{}, err
	}
	run, passed := backupVerifyTally(checks)
	return BackupVerifyVerificationResult{
		Passed: passed == run, ChecksRun: run, ChecksPassed: passed,
		Details: checks, DurationMs: uint64(time.Since(start).Milliseconds()),
	}, nil
}
