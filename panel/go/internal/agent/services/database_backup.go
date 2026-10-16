package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

const databaseBackupDir = "/var/backups/dockpanel/databases"

// databaseBackupDumpTimeout bounds every dump and restore (10 minutes).
const databaseBackupDumpTimeout = 600 * time.Second

// databaseBackupIsSafeFilename validates a backup filename (no traversal).
func databaseBackupIsSafeFilename(name string) bool {
	return name != "" && !strings.Contains(name, "/") && !strings.Contains(name, "..") &&
		databaseBackupHasDumpExt(name) && backupsSafeChars(name)
}

func databaseBackupHasDumpExt(name string) bool {
	for _, ext := range []string{".sql.gz", ".archive.gz", ".sql.gz.enc", ".archive.gz.enc"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func databaseBackupDirFor(dbName string) string { return databaseBackupDir + "/" + dbName }

// DatabaseBackupIsDbDirName: names this module will resolve to a directory
// under the dump root.
//
// A destructive operation should not borrow its idea of a legal name from a
// general-purpose route validator that can be widened for unrelated reasons;
// the blast radius here is a directory that gets removed. So the purge owns
// its charset, and the charset admits no dot at all — "." and ".." cannot be
// SPELLED.
//
// ⚠ Deliberately a SUPERSET of the shared validator, never a narrowing: same
// characters plus no rule about the first one, same length. Narrower is how a
// dump door quietly stops answering for an imported database.
func DatabaseBackupIsDbDirName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !backupsIsASCIIAlnum(c) && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// databaseBackupIsMintedDumpName: names this module MINTED, as opposed to
// names it merely accepts.
//
// ⚠ The distinction is the whole safety of the purge. The import door's
// predicate is an EXTENSION test, which an operator's hand-placed dump.sql.gz
// is designed to satisfy; deleting on that basis would take the staged import
// the product tells them to put here. This asks the narrower question: does
// the name have the shape this module writes — `{db}-%Y%m%d-%H%M%S.<ext>`?
func databaseBackupIsMintedDumpName(dbName, name string) bool {
	rest, ok := strings.CutPrefix(name, dbName+"-")
	if !ok {
		return false
	}
	stamp, ext, ok := strings.Cut(rest, ".")
	if !ok || len(stamp) != 15 || stamp[8] != '-' {
		return false
	}
	for i, c := range stamp {
		if i == 8 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	switch ext {
	case "sql.gz", "archive.gz", "sql.gz.enc", "archive.gz.enc":
		return true
	}
	return false
}

// DatabaseBackupPurgeReport is what a purge actually did.
type DatabaseBackupPurgeReport struct {
	Removed    int
	Kept       int
	DirRemoved bool
}

// DatabaseBackupPurgeDir removes a database's dump directory once nothing
// owns it.
//
// Deleting a database always took its container and rows and left the dumps
// behind — unreferenced, unreachable, counted by no retention policy.
//
// ⛔ The caller decides WHETHER: a dump directory is keyed by database NAME
// while the name is unique only per site, so two live databases can share
// it; that check needs the database and lives in the panel.
//
// Deliberately not a recursive delete: it unlinks the files this module
// writes, then removes the directory only if that emptied it, so an
// operator's staged import survives and no future bug in the name guard can
// escalate into erasing a tree.
func DatabaseBackupPurgeDir(dbName string) (DatabaseBackupPurgeReport, error) {
	if !DatabaseBackupIsDbDirName(dbName) {
		return DatabaseBackupPurgeReport{}, errors.New("Invalid database name")
	}
	dir := databaseBackupDirFor(dbName)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return DatabaseBackupPurgeReport{}, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return DatabaseBackupPurgeReport{}, fmt.Errorf("Failed to read dump directory: %v", err)
	}
	var r DatabaseBackupPurgeReport
	for _, e := range entries {
		name := e.Name()
		if e.Type().IsRegular() && databaseBackupIsMintedDumpName(dbName, name) {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				slog.Warn(fmt.Sprintf("Could not remove dump %s: %v", name, err))
				r.Kept++
			} else {
				r.Removed++
			}
		} else {
			r.Kept++
		}
	}
	if r.Kept == 0 {
		r.DirRemoved = os.Remove(dir) == nil
	} else {
		slog.Info(fmt.Sprintf("Dump directory for %s keeps %d item(s) this purge does not own; leaving the directory in place", dbName, r.Kept))
	}
	return r, nil
}

// databaseBackupIsSafeDbIdentifier validates container/db/user names against
// argument injection.
func databaseBackupIsSafeDbIdentifier(name string) bool {
	if name == "" || len(name) > 128 || strings.Contains(name, "..") || strings.Contains(name, "/") || strings.HasPrefix(name, "-") {
		return false
	}
	for _, c := range name {
		if !backupsIsASCIIAlnum(c) && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func databaseBackupCheckIDs(container, db string, user *string) error {
	if !databaseBackupIsSafeDbIdentifier(container) {
		return errors.New("Invalid container name")
	}
	if !databaseBackupIsSafeDbIdentifier(db) {
		return errors.New("Invalid database name")
	}
	if user != nil && !databaseBackupIsSafeDbIdentifier(*user) {
		return errors.New("Invalid username")
	}
	return nil
}

// databaseBackupPipedDump runs `docker exec … <dump>` | gzip > file, with no
// shell. The credential reaches the container via --env-file (never argv,
// which `ps` shows). docker's stderr is drained (a dump writing past the pipe
// buffer would otherwise block and hang until the timeout).
func databaseBackupPipedDump(envKey, password, fpath, failMsg string, dockerArgs ...string) error {
	envFile, err := safecmd.NewDockerEnvFile([2]string{envKey, password})
	if err != nil {
		return fmt.Errorf("Failed to prepare credentials: %v", err)
	}
	defer envFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), databaseBackupDumpTimeout)
	defer cancel()

	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("Failed to spawn docker exec: %v", err)
	}
	docker := safecmd.Command(ctx, "docker", append([]string{"exec", "--env-file", envFile.Path()}, dockerArgs...)...)
	var dockerErr bytes.Buffer
	docker.Stdout, docker.Stderr = pw, &dockerErr
	if err := docker.Start(); err != nil {
		pr.Close()
		pw.Close()
		return fmt.Errorf("Failed to spawn docker exec: %v", err)
	}
	pw.Close()

	file, err := os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		pr.Close()
		cancel()
		_ = docker.Wait()
		return fmt.Errorf("file write error: %v", err)
	}
	gzip := safecmd.Command(ctx, "gzip")
	gzip.Stdin, gzip.Stdout = pr, file
	if err := gzip.Start(); err != nil {
		pr.Close()
		file.Close()
		cancel()
		_ = docker.Wait()
		os.Remove(fpath)
		return fmt.Errorf("Failed to spawn gzip: %v", err)
	}
	pr.Close()

	dockerWaitErr := docker.Wait()
	_ = gzip.Wait()
	closeErr := file.Close()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		// Remove the partial stream so it can never surface as a restorable
		// backup (the Rust mysql/pg paths left it; the mongo path did not).
		os.Remove(fpath)
		return errors.New("Database dump timed out (10 minutes)")
	}
	var ee *exec.ExitError
	if dockerWaitErr != nil && !errors.As(dockerWaitErr, &ee) {
		os.Remove(fpath)
		return fmt.Errorf("docker exec wait error: %v", dockerWaitErr)
	}
	if closeErr != nil {
		os.Remove(fpath)
		return fmt.Errorf("file write error: %v", closeErr)
	}
	if dockerWaitErr != nil {
		os.Remove(fpath)
		return errors.New(failMsg)
	}
	return nil
}

// databaseBackupFinishDump applies the empty-output check and hashes.
func databaseBackupFinishDump(engine, filename, fpath string) (BackupsBackupInfo, error) {
	fi, err := os.Stat(fpath)
	if err != nil {
		return BackupsBackupInfo{}, fmt.Errorf("Failed to read dump metadata: %v", err)
	}
	if fi.Size() < 30 {
		os.Remove(fpath)
		return BackupsBackupInfo{}, errors.New("Database dump produced empty output")
	}
	sum := backupsComputeFileSha256(fpath)
	slog.Info(fmt.Sprintf("%s dump created: %s (%d bytes, hash: %s)", engine, filename, fi.Size(), backupsOrNA(sum)))
	return BackupsBackupInfo{
		Filename: filename, SizeBytes: uint64(fi.Size()),
		CreatedAt: backupsDisplayTime(time.Now()), Sha256: sum,
	}, nil
}

func databaseBackupPrepare(dbName, ext string) (filename, fpath string, err error) {
	dest := databaseBackupDirFor(dbName)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return "", "", fmt.Errorf("Failed to create backup dir: %v", err)
	}
	filename = dbName + "-" + backupsStamp(time.Now()) + ext
	return filename, filepath.Join(dest, filename), nil
}

// DatabaseBackupDumpMysql dumps a MySQL/MariaDB database from its container
// via piped `docker exec` → gzip (no shell interpolation).
func DatabaseBackupDumpMysql(containerName, dbName, user, password string) (BackupsBackupInfo, error) {
	if err := databaseBackupCheckIDs(containerName, dbName, &user); err != nil {
		return BackupsBackupInfo{}, err
	}
	filename, fpath, err := databaseBackupPrepare(dbName, ".sql.gz")
	if err != nil {
		return BackupsBackupInfo{}, err
	}
	if err := databaseBackupPipedDump("MYSQL_PWD", password, fpath,
		"MySQL dump failed (docker exec returned non-zero)",
		containerName, "mariadb-dump", "-u", user,
		"--single-transaction", "--routines", "--triggers", dbName); err != nil {
		return BackupsBackupInfo{}, err
	}
	return databaseBackupFinishDump("MySQL", filename, fpath)
}

// DatabaseBackupDumpPostgres dumps a PostgreSQL database from its container.
func DatabaseBackupDumpPostgres(containerName, dbName, user, password string) (BackupsBackupInfo, error) {
	if err := databaseBackupCheckIDs(containerName, dbName, &user); err != nil {
		return BackupsBackupInfo{}, err
	}
	filename, fpath, err := databaseBackupPrepare(dbName, ".sql.gz")
	if err != nil {
		return BackupsBackupInfo{}, err
	}
	if err := databaseBackupPipedDump("PGPASSWORD", password, fpath,
		"PostgreSQL dump failed (docker exec returned non-zero)",
		containerName, "pg_dump", "-U", user, "-d", dbName,
		// --clean --if-exists so a restore OVERWRITES the target rather than
		// merging into it (without --clean a restore into a non-empty DB
		// silently yields a merge). Pairs with ON_ERROR_STOP +
		// --single-transaction on restore.
		"--no-owner", "--no-acl", "--clean", "--if-exists"); err != nil {
		return BackupsBackupInfo{}, err
	}
	return databaseBackupFinishDump("PostgreSQL", filename, fpath)
}

// DatabaseBackupDumpMongo dumps a MongoDB database. mongodump streams the
// archive straight to the dump file's fd — never buffered in the agent's RAM
// (a multi-GB DB would OOM the shared root agent: a tenant-triggerable
// cross-tenant DoS).
func DatabaseBackupDumpMongo(containerName, dbName string) (BackupsBackupInfo, error) {
	if err := databaseBackupCheckIDs(containerName, dbName, nil); err != nil {
		return BackupsBackupInfo{}, err
	}
	filename, fpath, err := databaseBackupPrepare(dbName, ".archive.gz")
	if err != nil {
		return BackupsBackupInfo{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), databaseBackupDumpTimeout)
	defer cancel()
	runErr := func() error {
		file, err := os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("Failed to create dump file: %v", err)
		}
		defer file.Close()
		cmd := safecmd.Command(ctx, "docker", "exec", containerName, "mongodump", "--db", dbName, "--archive", "--gzip")
		var stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = file, &stderr
		err = cmd.Run()
		var ee *exec.ExitError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &ee):
			return fmt.Errorf("MongoDB dump failed: %s", backupsLossy(stderr.Bytes()))
		default:
			return fmt.Errorf("Failed to run mongodump: %v", err)
		}
	}()
	// On timeout the child is killed but the partial file remains — remove it
	// so it can't later surface as a "restorable" backup. Same on any error.
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		os.Remove(fpath)
		return BackupsBackupInfo{}, errors.New("Database dump timed out (10 minutes)")
	}
	if runErr != nil {
		os.Remove(fpath)
		return BackupsBackupInfo{}, runErr
	}
	return databaseBackupFinishDump("MongoDB", filename, fpath)
}

// databaseBackupExitStatus renders like Rust's ExitStatus Display.
func databaseBackupExitStatus(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Sprintf("exit status: %d", ee.ExitCode())
	}
	return "exit status: 0"
}

// databaseBackupPipedRestore runs gunzip -c file | docker exec -i … and
// returns (gunzipOK, dockerErr, dockerStderr). The truncated-.gz check is
// the caller's: a .gz ending on a statement boundary makes the client exit 0
// on EOF while gunzip fails (the EOF-as-success trap).
func databaseBackupPipedRestore(envKey, password, fpath string, dockerArgs ...string) (timedOut, gunzipOK bool, dockerErr error, stderr []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), databaseBackupDumpTimeout)
	defer cancel()
	pr, pw, perr := os.Pipe()
	if perr != nil {
		return false, false, nil, nil, fmt.Errorf("Failed to spawn gunzip: %v", perr)
	}
	gunzip := safecmd.Command(ctx, "gunzip", "-c", fpath)
	gunzip.Stdout = pw
	if e := gunzip.Start(); e != nil {
		pr.Close()
		pw.Close()
		return false, false, nil, nil, fmt.Errorf("Failed to spawn gunzip: %v", e)
	}
	pw.Close()
	envFile, e := safecmd.NewDockerEnvFile([2]string{envKey, password})
	if e != nil {
		pr.Close()
		cancel()
		_ = gunzip.Wait()
		return false, false, nil, nil, fmt.Errorf("Failed to prepare credentials: %v", e)
	}
	defer envFile.Close()
	docker := safecmd.Command(ctx, "docker", append([]string{"exec", "-i", "--env-file", envFile.Path()}, dockerArgs...)...)
	var errb bytes.Buffer
	docker.Stdin, docker.Stderr = pr, &errb
	if e := docker.Start(); e != nil {
		pr.Close()
		cancel()
		_ = gunzip.Wait()
		return false, false, nil, nil, fmt.Errorf("Failed to spawn docker exec: %v", e)
	}
	pr.Close()
	gzErr := gunzip.Wait()
	dErr := docker.Wait()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return true, false, nil, nil, nil
	}
	var ee *exec.ExitError
	if dErr != nil && !errors.As(dErr, &ee) {
		return false, false, nil, nil, fmt.Errorf("docker exec wait error: %v", dErr)
	}
	if gzErr != nil && !errors.As(gzErr, &ee) {
		return false, false, nil, nil, fmt.Errorf("gunzip wait error: %v", gzErr)
	}
	return false, gzErr == nil, dErr, errb.Bytes(), nil
}

// DatabaseBackupRestoreMysql restores a MySQL/MariaDB database from a dump.
func DatabaseBackupRestoreMysql(containerName, dbName, user, password, fpath string) error {
	if err := databaseBackupCheckIDs(containerName, dbName, &user); err != nil {
		return err
	}
	timedOut, gzOK, dErr, stderr, err := databaseBackupPipedRestore("MYSQL_PWD", password, fpath,
		// `mariadb`, NOT `mysql`: the panel provisions mariadb:11, which
		// dropped the mysql-named client symlinks — `mysql` does not exist in
		// the container and every MySQL restore used to fail.
		containerName, "mariadb", "-u", user, dbName)
	if err != nil {
		return err
	}
	if timedOut {
		return errors.New("Database restore timed out (10 minutes)")
	}
	if !gzOK {
		return errors.New("MySQL restore failed: backup decompression error (truncated/corrupt archive)")
	}
	if dErr != nil {
		msg := strings.TrimSpace(backupsLossy(stderr))
		// Never a bare "restore failed:" — this path can fail with empty
		// stderr (e.g. the client binary is missing).
		if msg == "" {
			return fmt.Errorf("MySQL restore failed: the mariadb client exited with %s and produced no error output", databaseBackupExitStatus(dErr))
		}
		return fmt.Errorf("MySQL restore failed: %s", msg)
	}
	slog.Info(fmt.Sprintf("MySQL database %s restored from %s", dbName, fpath))
	return nil
}

// DatabaseBackupRestorePostgres restores a PostgreSQL database from a dump.
func DatabaseBackupRestorePostgres(containerName, dbName, user, password, fpath string) error {
	if err := databaseBackupCheckIDs(containerName, dbName, &user); err != nil {
		return err
	}
	timedOut, gzOK, dErr, stderr, err := databaseBackupPipedRestore("PGPASSWORD", password, fpath,
		// ON_ERROR_STOP=1 + --single-transaction: fail-and-rollback on ANY
		// statement error instead of psql's continue-on-error exit 0.
		containerName, "psql", "-v", "ON_ERROR_STOP=1", "--single-transaction", "-U", user, "-d", dbName)
	if err != nil {
		return err
	}
	if timedOut {
		return errors.New("Database restore timed out (10 minutes)")
	}
	if !gzOK {
		return errors.New("PostgreSQL restore failed: backup decompression error (truncated/corrupt archive)")
	}
	if dErr != nil {
		return fmt.Errorf("PostgreSQL restore failed: %s", backupsLossy(stderr))
	}
	slog.Info(fmt.Sprintf("PostgreSQL database %s restored from %s", dbName, fpath))
	return nil
}

// DatabaseBackupRestoreMongo restores a MongoDB database. The archive is
// streamed from disk as mongorestore's stdin, never read into RAM (same
// cross-tenant OOM class as the dump path).
func DatabaseBackupRestoreMongo(containerName, dbName, fpath string) error {
	if err := databaseBackupCheckIDs(containerName, dbName, nil); err != nil {
		return err
	}
	file, err := os.Open(fpath)
	if err != nil {
		return fmt.Errorf("Failed to open backup file: %v", err)
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), databaseBackupDumpTimeout)
	defer cancel()
	cmd := safecmd.Command(ctx, "docker", "exec", "-i", containerName,
		"mongorestore", "--db", dbName, "--archive", "--gzip", "--drop")
	var stderr bytes.Buffer
	cmd.Stdin, cmd.Stderr = file, &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("Failed to spawn docker exec: %v", err)
	}
	werr := cmd.Wait()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("Database restore timed out (10 minutes)")
	}
	var ee *exec.ExitError
	if werr != nil && !errors.As(werr, &ee) {
		return fmt.Errorf("docker exec wait error: %v", werr)
	}
	if werr != nil {
		return fmt.Errorf("MongoDB restore failed: %s", backupsLossy(stderr.Bytes()))
	}
	slog.Info(fmt.Sprintf("MongoDB database %s restored from %s", dbName, fpath))
	return nil
}

// DatabaseBackupListDbBackups lists backups for a database name.
//
// Anything the restore path cannot OPEN is REPORTED (Unsupported), not
// skipped: the test is databaseBackupIsSafeFilename itself — the predicate
// DatabaseBackupGetBackupPath enforces — so the listing never offers a name
// the opener refuses. ⚠ This says only "is this a backup file at all";
// whether it can go into a given database is the panel's question.
func DatabaseBackupListDbBackups(dbName string) ([]BackupsBackupInfo, error) {
	return backupsListDir(databaseBackupDirFor(dbName), func(e os.DirEntry, info *BackupsBackupInfo) bool {
		// A stray subdirectory is not a dump and must not be reported as a rejected one.
		if e.IsDir() {
			return false
		}
		if !databaseBackupIsSafeFilename(e.Name()) {
			reason := databaseBackupUnusableReason(dbName, e.Name())
			info.Unsupported = &reason
		}
		return true
	})
}

// databaseBackupUnusableReason tells an operator why a file in the directory
// is not a backup this agent can open, and the command that fixes it. An
// ungzipped dump is the likeliest case (restores pipe through gunzip
// unconditionally); the subtler one is a right-looking name with a refused
// character — a space, from `scp "my dump.sql.gz"` — which used to be listed
// and then fail while the request line was built.
func databaseBackupUnusableReason(dbName, name string) string {
	full := fmt.Sprintf("%s/%s/%s", databaseBackupDir, dbName, name)
	switch {
	case databaseBackupHasDumpExt(name):
		// The extension is right, so it was the charset that failed.
		return fmt.Sprintf("The name contains a character backups cannot use — spaces most often. "+
			"Rename it with: mv '%s' %s/%s/%s", full, databaseBackupDir, dbName, databaseBackupSanitiseSuggestion(name))
	case strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, ".archive") || strings.HasSuffix(name, ".dump"):
		return "Not compressed. Backups are read as .sql.gz — compress it in place with: gzip " + full
	case strings.HasSuffix(name, ".zip"):
		return fmt.Sprintf("ZIP is not supported. Unpack it and gzip the .sql inside: unzip %s && gzip <name>.sql", full)
	case strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") || strings.HasSuffix(name, ".tar"):
		return "This looks like a site archive, not a database dump. A full cPanel/Plesk archive " +
			"goes through Migration instead."
	default:
		return "Not a database dump. Backups are read as .sql.gz or .archive.gz."
	}
}

// databaseBackupSanitiseSuggestion builds a pasteable replacement name with
// the same charset databaseBackupIsSafeFilename enforces.
func databaseBackupSanitiseSuggestion(name string) string {
	var b strings.Builder
	for _, c := range name {
		if backupsIsASCIIAlnum(c) || c == '-' || c == '_' || c == '.' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// DatabaseBackupDeleteDbBackup deletes a database backup file.
func DatabaseBackupDeleteDbBackup(dbName, filename string) error {
	if !databaseBackupIsSafeFilename(filename) {
		return errors.New("Invalid backup filename")
	}
	fpath := filepath.Join(databaseBackupDirFor(dbName), filename)
	if _, err := os.Stat(fpath); err != nil {
		return errors.New("Backup file not found")
	}
	if err := os.Remove(fpath); err != nil {
		return fmt.Errorf("Failed to delete backup: %v", err)
	}
	slog.Info(fmt.Sprintf("Database backup deleted: %s for %s", filename, dbName))
	return nil
}

// DatabaseBackupGetBackupPath returns the full path of a database backup file.
func DatabaseBackupGetBackupPath(dbName, filename string) (string, error) {
	if !databaseBackupIsSafeFilename(filename) {
		return "", errors.New("Invalid backup filename")
	}
	fpath := filepath.Join(databaseBackupDirFor(dbName), filename)
	if _, err := os.Stat(fpath); err != nil {
		return "", errors.New("Backup file not found")
	}
	return fpath, nil
}
