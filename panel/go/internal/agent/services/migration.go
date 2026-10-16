package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

const migrationDir = "/tmp/dockpanel-migration"

// MigrationFetchDir is where a URL-fetched archive is staged — inside the ONE
// subtree systemd grants this unit write access to (ReadWritePaths includes
// /var/backups/dockpanel, not bare /var/backups). A new path outside a
// granted entry fails with EROFS.
const MigrationFetchDir = "/var/backups/dockpanel/migration-fetch"

// migrationMaxFetchBytes: generous for a real cPanel/Plesk/HestiaCP backup,
// bounded so a hostile URL cannot fill the disk with a never-ending response.
const migrationMaxFetchBytes uint64 = 20 * 1024 * 1024 * 1024

// migrationFetchTimeout matches migrationExtractTimeout: bound the thing that
// will never finish, not the one that will.
const migrationFetchTimeout = 1800 * time.Second

// migrationExtractTimeout bounds unpacking one archive — for the WHOLE
// attempt, not per `tar`. Extraction may run twice (gzip, then plain tar); a
// fresh budget each would double the real worst case and the panel's own
// budget (set just above this) would fire first with a contentless message.
// Generous on purpose: the panel no longer holds a request open across this.
const migrationExtractTimeout = 1800 * time.Second

// MigrationFetchArchive downloads url into dest (the caller has validated
// dest is inside MigrationFetchDir and url is not internal). Streams to a
// `.part` sibling with a hard size cap, renaming into place only once the
// whole response has landed, so analyze can never see a partial archive.
func MigrationFetchArchive(ctx context.Context, url, dest string) (uint64, error) {
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return 0, fmt.Errorf("Could not create %s: %v", parent, nginxIOErr(err))
	}
	ctx, cancel := context.WithTimeout(ctx, migrationFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("Fetch failed: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Fetch failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return 0, fmt.Errorf("Fetch failed: HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	gib := migrationMaxFetchBytes / (1024 * 1024 * 1024)
	if resp.ContentLength > 0 && uint64(resp.ContentLength) > migrationMaxFetchBytes {
		return 0, fmt.Errorf("Archive is %d bytes, over the %d GiB fetch limit", resp.ContentLength, gib)
	}

	partPath := dest + ".part"
	f, err := os.Create(partPath)
	if err != nil {
		return 0, fmt.Errorf("Could not create %s: %v", partPath, nginxIOErr(err))
	}
	// Read one byte past the cap so an over-limit body is detected.
	n, err := io.Copy(f, io.LimitReader(resp.Body, int64(migrationMaxFetchBytes)+1))
	if cerr := f.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if uint64(n) > migrationMaxFetchBytes {
		_ = os.Remove(partPath)
		return 0, fmt.Errorf("Archive exceeded the %d GiB fetch limit and was discarded", gib)
	}
	if err != nil {
		_ = os.Remove(partPath)
		return 0, fmt.Errorf("Fetch failed mid-download: %v", err)
	}
	if err := os.Rename(partPath, dest); err != nil {
		return 0, fmt.Errorf("Could not finalize %s: %v", dest, nginxIOErr(err))
	}
	return uint64(n), nil
}

// migrationIsValidID: UUID shape — alphanumeric + hyphens, ≤36 chars.
func migrationIsValidID(id string) bool {
	if id == "" || len(id) > 36 {
		return false
	}
	for _, c := range id {
		if !(c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-')) {
			return false
		}
	}
	return true
}

// MigrationInventory is what analyze found in an archive.
type MigrationInventory struct {
	ID           string                 `json:"id"`
	Source       string                 `json:"source"`
	Sites        []MigrationSite        `json:"sites"`
	Databases    []MigrationDatabase    `json:"databases"`
	MailAccounts []MigrationMailAccount `json:"mail_accounts"`
	Warnings     []string               `json:"warnings"`
}

type MigrationSite struct {
	Domain    string `json:"domain"`
	DocRoot   string `json:"doc_root"`
	SizeBytes uint64 `json:"size_bytes"`
	Runtime   string `json:"runtime"`
	FileCount uint64 `json:"file_count"`
}

type MigrationDatabase struct {
	Name      string `json:"name"`
	File      string `json:"file"`
	SizeBytes uint64 `json:"size_bytes"`
	Engine    string `json:"engine"`
}

type MigrationMailAccount struct {
	Email  string `json:"email"`
	Domain string `json:"domain"`
}

// MigrationAnalyze extracts and analyzes a backup archive.
func MigrationAnalyze(ctx context.Context, backupPath, source string) (MigrationInventory, error) {
	id := uuid.NewString()
	extractDir := migrationDir + "-" + id
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return MigrationInventory{}, fmt.Errorf("Failed to create dir: %v", nginxIOErr(err))
	}

	// Bounded HERE, not only at the caller: a corrupt member or a stalled disk
	// leaves tar waiting forever, and owning the budget lets the panel report
	// WHY it stopped. One deadline for both attempts; the context kills tar.
	slog.Info(fmt.Sprintf("Extracting backup %s to %s", backupPath, extractDir))
	ctx, cancel := context.WithTimeout(ctx, migrationExtractTimeout)
	defer cancel()
	timedOut := func(check string) error {
		_ = os.RemoveAll(extractDir)
		return fmt.Errorf("Extracting %s exceeded %ds and was stopped. The archive is either much larger than this server can unpack in that window, or damaged — check it with `%s` and confirm there is free space under /tmp.",
			backupPath, int(migrationExtractTimeout.Seconds()), check)
	}
	extract := func(flags string) (safecmd.Output, error) {
		return safecmd.Exec(ctx, "tar", flags, backupPath, "-C", extractDir, "--no-same-owner", "--no-same-permissions")
	}

	out, err := extract("xzf")
	if ctx.Err() != nil {
		return MigrationInventory{}, timedOut("tar tzf")
	}
	if err != nil {
		return MigrationInventory{}, fmt.Errorf("Failed to extract: %v", err)
	}
	if !out.Success() {
		stderr := nginxLossy(out.Stderr)
		// Plain tar, inside what is left of the same budget.
		out2, err := extract("xf")
		if ctx.Err() != nil {
			return MigrationInventory{}, timedOut("tar tf")
		}
		if err != nil {
			return MigrationInventory{}, fmt.Errorf("Extraction failed: %v", err)
		}
		if !out2.Success() {
			_ = os.RemoveAll(extractDir)
			return MigrationInventory{}, fmt.Errorf("Failed to extract backup: %s", stderr)
		}
	}

	root := migrationFindBackupRoot(extractDir)
	var inv MigrationInventory
	switch source {
	case "cpanel":
		inv, err = migrationParseCpanel(ctx, id, root)
	case "plesk":
		inv, err = migrationParsePlesk(ctx, id, root)
	case "hestiacp":
		inv, err = migrationParseHestiacp(ctx, id, root)
	default:
		err = fmt.Errorf("Unknown source: %s", source)
	}
	if err != nil {
		_ = os.RemoveAll(extractDir)
		return MigrationInventory{}, err
	}
	return inv, nil
}

// migrationRelativeTo expresses path relative to root for the paths that
// travel to the importer, which joins them onto the archive root and rejects
// anything starting with `/`. nil when path is not inside root.
func migrationRelativeTo(path, root string) *string {
	rel, ok := strings.CutPrefix(path, root)
	if !ok || (rel != "" && !strings.HasPrefix(rel, "/") && !strings.HasSuffix(root, "/")) {
		return nil
	}
	rel = strings.TrimLeft(rel, "/")
	if rel == "" {
		return nil
	}
	return &rel
}

// migrationFindBackupRoot skips a single top-level directory (archives often
// nest everything under one).
func migrationFindBackupRoot(extractDir string) string {
	entries, _ := os.ReadDir(extractDir)
	if len(entries) == 1 && entries[0].IsDir() {
		return filepath.Join(extractDir, entries[0].Name())
	}
	return extractDir
}

func migrationIsDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func migrationSQLName(name string) (string, bool) {
	if !strings.HasSuffix(name, ".sql") && !strings.HasSuffix(name, ".sql.gz") {
		return "", false
	}
	// Rust trim_end_matches strips repeats; harmless to mirror exactly.
	s := name
	for strings.HasSuffix(s, ".gz") {
		s = strings.TrimSuffix(s, ".gz")
	}
	for strings.HasSuffix(s, ".sql") {
		s = strings.TrimSuffix(s, ".sql")
	}
	return s, true
}

func migrationFileSize(dir, name string) uint64 {
	fi, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		return 0
	}
	return uint64(fi.Size())
}

func migrationParseCpanel(ctx context.Context, id, root string) (MigrationInventory, error) {
	inv := MigrationInventory{ID: id, Source: "cpanel", Sites: []MigrationSite{}, Databases: []MigrationDatabase{},
		MailAccounts: []MigrationMailAccount{}, Warnings: []string{}}

	// 1. Sites from homedir/.
	homedir := filepath.Join(root, "homedir")
	if _, err := os.Stat(homedir); err == nil {
		publicHTML := filepath.Join(homedir, "public_html")
		if _, err := os.Stat(publicHTML); err == nil {
			size, count := migrationDirStats(ctx, publicHTML)
			domain := migrationFindCpanelMainDomain(root)
			if domain == "" {
				domain = "main-domain.com"
			}
			inv.Sites = append(inv.Sites, MigrationSite{Domain: domain, DocRoot: "homedir/public_html", SizeBytes: size,
				Runtime: migrationDetectRuntime(publicHTML), FileCount: count})
		}
		// Addon domains / subdomains.
		entries, _ := os.ReadDir(homedir)
		for _, e := range entries {
			name := e.Name()
			switch {
			case name == "public_html", strings.HasPrefix(name, "."), name == "mail", name == "etc",
				name == "tmp", name == "logs", name == "ssl":
				continue
			}
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(homedir, name)
			size, count := migrationDirStats(ctx, p)
			if count > 0 {
				inv.Sites = append(inv.Sites, MigrationSite{Domain: name, DocRoot: "homedir/" + name, SizeBytes: size,
					Runtime: migrationDetectRuntime(p), FileCount: count})
			}
		}
	} else {
		inv.Warnings = append(inv.Warnings, "No homedir/ found in backup")
	}

	// 2. Databases from mysql/.
	mysqlDir := filepath.Join(root, "mysql")
	entries, _ := os.ReadDir(mysqlDir)
	for _, e := range entries {
		if db, ok := migrationSQLName(e.Name()); ok {
			inv.Databases = append(inv.Databases, MigrationDatabase{Name: db, File: "mysql/" + e.Name(),
				SizeBytes: migrationFileSize(mysqlDir, e.Name()), Engine: "mysql"})
		}
	}
	if _, err := os.Stat(filepath.Join(root, "mysql.sql")); err == nil {
		inv.Warnings = append(inv.Warnings, "mysql.sql (user grants) found but not imported — create DB users manually")
	}

	// 3. Mail accounts from etc/{domain}/shadow or passwd.
	etcDir := filepath.Join(root, "etc")
	domains, _ := os.ReadDir(etcDir)
	for _, d := range domains {
		if !d.IsDir() {
			continue
		}
		domain := d.Name()
		accounts := filepath.Join(etcDir, domain, "shadow")
		if _, err := os.Stat(accounts); err != nil {
			accounts = filepath.Join(etcDir, domain, "passwd")
			if _, err := os.Stat(accounts); err != nil {
				continue
			}
		}
		content, err := os.ReadFile(accounts)
		if err != nil {
			continue
		}
		for _, line := range nginxLines(string(content)) {
			user, _, _ := strings.Cut(line, ":")
			user = strings.TrimSpace(user)
			if user != "" && user != "root" {
				inv.MailAccounts = append(inv.MailAccounts, MigrationMailAccount{Email: user + "@" + domain, Domain: domain})
			}
		}
	}

	if len(inv.Sites) == 0 && len(inv.Databases) == 0 {
		inv.Warnings = append(inv.Warnings, "No sites or databases found — backup may be empty or in an unexpected format")
	}
	return inv, nil
}

// migrationParseDirs is the shared Plesk/HestiaCP shape: one dir per domain
// under sitesDir (doc root = docSub if present), SQL dumps under dbDir. Paths
// are relative to the archive root — an absolute doc_root hit the importer's
// own traversal guard and every site failed; a bare db filename resolved one
// level too high and every database failed with "SQL file not found".
func migrationParseDirs(ctx context.Context, id, root, source, sitesDir, docSub, dbDir, beta, empty string) MigrationInventory {
	inv := MigrationInventory{ID: id, Source: source, Sites: []MigrationSite{}, Databases: []MigrationDatabase{},
		MailAccounts: []MigrationMailAccount{}, Warnings: []string{beta}}
	entries, _ := os.ReadDir(filepath.Join(root, sitesDir))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		domain := e.Name()
		docRoot := filepath.Join(root, sitesDir, domain)
		if sub := filepath.Join(docRoot, docSub); migrationExists(sub) {
			docRoot = sub
		}
		size, count := migrationDirStats(ctx, docRoot)
		rel := migrationRelativeTo(docRoot, root)
		if rel == nil {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("Skipped %s: document root is outside the archive", domain))
			continue
		}
		inv.Sites = append(inv.Sites, MigrationSite{Domain: domain, DocRoot: *rel, SizeBytes: size,
			Runtime: migrationDetectRuntime(docRoot), FileCount: count})
	}
	dbs, _ := os.ReadDir(filepath.Join(root, dbDir))
	for _, e := range dbs {
		if db, ok := migrationSQLName(e.Name()); ok {
			inv.Databases = append(inv.Databases, MigrationDatabase{Name: db, File: dbDir + "/" + e.Name(),
				SizeBytes: migrationFileSize(filepath.Join(root, dbDir), e.Name()), Engine: "mysql"})
		}
	}
	if len(inv.Sites) == 0 && len(inv.Databases) == 0 {
		inv.Warnings = append(inv.Warnings, empty)
	}
	return inv
}

func migrationExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func migrationParsePlesk(ctx context.Context, id, root string) (MigrationInventory, error) {
	return migrationParseDirs(ctx, id, root, "plesk", "domains", "httpdocs", "databases",
		"Plesk import is in beta — some items may not be detected",
		"No data found — check that this is a valid Plesk backup"), nil
}

func migrationParseHestiacp(ctx context.Context, id, root string) (MigrationInventory, error) {
	return migrationParseDirs(ctx, id, root, "hestiacp", "web", "public_html", "db",
		"HestiaCP import is in beta — some items may not be detected",
		"No data found — check that this is a valid HestiaCP backup"), nil
}

// migrationFindCpanelMainDomain reads the main domain from cp/ or
// userdata/main; "" when neither names one.
func migrationFindCpanelMainDomain(root string) string {
	if entries, err := os.ReadDir(filepath.Join(root, "cp")); err == nil {
		for _, e := range entries {
			content, err := os.ReadFile(filepath.Join(root, "cp", e.Name()))
			if err != nil {
				continue
			}
			for _, line := range nginxLines(string(content)) {
				if strings.HasPrefix(line, "DNS=") || strings.HasPrefix(line, "DOMAIN=") {
					parts := strings.Split(line, "=")
					if d := strings.TrimSpace(parts[1]); d != "" {
						return d
					}
				}
			}
		}
	}
	if content, err := os.ReadFile(filepath.Join(root, "userdata", "main")); err == nil {
		for _, line := range nginxLines(string(content)) {
			if strings.HasPrefix(line, "main_domain:") {
				return strings.TrimSpace(strings.Split(line, ":")[1])
			}
		}
	}
	return ""
}

func migrationDetectRuntime(dir string) string {
	has := func(f string) bool { return migrationExists(filepath.Join(dir, f)) }
	switch {
	case has("wp-config.php"), has("index.php"), has("artisan"):
		return "php"
	case has("package.json"):
		return "node"
	case has("requirements.txt"), has("manage.py"):
		return "python"
	}
	return "static"
}

// migrationDirStats returns total size and file count of dir.
func migrationDirStats(ctx context.Context, dir string) (uint64, uint64) {
	var size, count uint64
	if out, err := deployRun(ctx, 0, "", nil, "du", "-sb", dir); err == nil {
		if f := strings.Fields(nginxLossy(out.Stdout)); len(f) > 0 {
			size, _ = strconv.ParseUint(f[0], 10, 64)
		}
	}
	if out, err := deployRun(ctx, 0, "", nil, "find", dir, "-type", "f"); err == nil {
		count = uint64(len(nginxLines(nginxLossy(out.Stdout))))
	}
	return size, count
}

// MigrationImportSiteFiles copies a site from an extracted backup into
// /var/www/{domain}/ (its document root for runtime).
func MigrationImportSiteFiles(ctx context.Context, migrationID, domain, sourceDir, runtime string) (string, error) {
	if !migrationIsValidID(migrationID) {
		return "", errors.New("Invalid migration ID format")
	}
	if strings.Contains(sourceDir, "..") || strings.HasPrefix(sourceDir, "/") {
		return "", errors.New("Invalid source directory path")
	}
	if strings.Contains(domain, "..") || strings.Contains(domain, "/") || domain == "" {
		return "", errors.New("Invalid domain name")
	}

	// Resolve the archive root exactly as analyze did: the parsers emit paths
	// relative to migrationFindBackupRoot, and rebuilding the base as the bare
	// extraction dir failed every nested (cPanel full / cpmove) archive.
	extractRoot := migrationFindBackupRoot(migrationDir + "-" + migrationID)
	source := extractRoot + "/" + sourceDir
	// Where nginx will look — public/ for a static or PHP site.
	dest := NginxDocumentRootFor("/var/www/"+domain, runtime)

	if !migrationExists(source) {
		return "", fmt.Errorf("Source directory not found: %s", source)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", fmt.Errorf("Failed to create %s: %v", dest, nginxIOErr(err))
	}
	out, err := deployRun(ctx, 0, "", nil, "rsync", "-a", "--delete", source+"/", dest+"/")
	if err != nil {
		return "", fmt.Errorf("rsync failed: %v", err)
	}
	if !out.Success() {
		// Fall back to cp -a.
		out2, err := deployRun(ctx, 0, "", nil, "cp", "-a", source+"/.", dest)
		if err != nil {
			return "", fmt.Errorf("cp failed: %v", err)
		}
		if !out2.Success() {
			return "", fmt.Errorf("File copy failed: %s", nginxLossy(out2.Stderr))
		}
	}
	// Everything but `.git` to www-data. For node/proxy/python dest IS the
	// site root, where DeployCloneOrPull keeps a root-owned `.git`; for
	// php/static it is a no-op, applied uniformly on purpose.
	deployHandTreeExceptGit(ctx, dest)
	return "Copied files to " + dest, nil
}

// MigrationImportDatabase imports a SQL dump into a DockPanel database
// container. The password reaches the client through the environment
// (MYSQL_PWD, forwarded by name with `docker exec -e`), never argv.
func MigrationImportDatabase(ctx context.Context, migrationID, sqlFile, containerName, dbName, engine, user, password string) (string, error) {
	if !migrationIsValidID(migrationID) {
		return "", errors.New("Invalid migration ID format")
	}
	// Only DockPanel-managed DB containers.
	valid := strings.HasPrefix(containerName, "dockpanel-") && len(containerName) <= 128
	for _, c := range containerName {
		if !(c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_')) {
			valid = false
		}
	}
	if !valid {
		return "", errors.New("Invalid container name — only DockPanel-managed containers are allowed")
	}
	if strings.Contains(sqlFile, "..") || strings.HasPrefix(sqlFile, "/") {
		return "", errors.New("Invalid SQL file path")
	}

	extractRoot := migrationFindBackupRoot(migrationDir + "-" + migrationID)
	sqlPath := extractRoot + "/" + sqlFile
	if !migrationExists(sqlPath) {
		return "", fmt.Errorf("SQL file not found: %s", sqlPath)
	}
	actual := sqlPath
	if strings.HasSuffix(sqlPath, ".gz") {
		out, err := deployRun(ctx, 0, "", nil, "gunzip", "-k", sqlPath)
		if err != nil {
			return "", fmt.Errorf("gunzip failed: %v", err)
		}
		if !out.Success() {
			return "", fmt.Errorf("Failed to decompress: %s", nginxLossy(out.Stderr))
		}
		actual = strings.TrimSuffix(sqlPath, ".gz")
	}
	f, err := os.Open(actual)
	if err != nil {
		return "", fmt.Errorf("Failed to open SQL file: %v", nginxIOErr(err))
	}
	defer f.Close()

	ictx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	args := []string{"exec", "-i"}
	var env []string
	if engine == "mysql" || engine == "mariadb" {
		args = append(args, "-e", "MYSQL_PWD", containerName, "mariadb", "-u", user, dbName)
		env = []string{"MYSQL_PWD=" + password}
	} else {
		args = append(args, containerName, "psql", "-U", user, "-d", dbName)
	}
	cmd := safecmd.Command(ictx, "docker", args...)
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdin = f
	out, err := safecmd.Run(ictx, cmd)
	if errors.Is(err, context.DeadlineExceeded) {
		return "", errors.New("Database import timed out (600s)")
	}
	if err != nil {
		return "", fmt.Errorf("Import command failed: %v", err)
	}
	// Some MySQL warnings are OK — only an actual ERROR fails the import.
	if stderr := nginxLossy(out.Stderr); !out.Success() && strings.Contains(stderr, "ERROR") {
		return "", fmt.Errorf("Database import error: %s", stderr)
	}
	return fmt.Sprintf("Imported %s from %s", dbName, sqlFile), nil
}

// MigrationCleanup removes a migration's extraction directory.
func MigrationCleanup(migrationID string) error {
	if !migrationIsValidID(migrationID) {
		return errors.New("Invalid migration ID format")
	}
	dir := migrationDir + "-" + migrationID
	if migrationExists(dir) {
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("Cleanup failed: %v", nginxIOErr(err))
		}
		slog.Info("Cleaned up migration directory: " + dir)
	}
	return nil
}
