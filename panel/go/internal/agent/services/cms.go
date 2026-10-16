package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

const (
	cmsComposer = "/usr/local/bin/composer"
	cmsSiteRoot = "/var/www"

	// cmsComposerTimeout: create-project/require — full dependency resolution
	// plus a network fetch of every package; the heaviest operation here.
	cmsComposerTimeout = 300 * time.Second
	// cmsCliInstallTimeout: a CLI installer doing DB writes/migrations.
	cmsCliInstallTimeout = 180 * time.Second
	// cmsDownloadTimeout: a single network fetch of a package archive.
	cmsDownloadTimeout = 120 * time.Second
	// cmsQuickTimeout: a quick local/PHP-CLI operation or a metadata curl.
	cmsQuickTimeout = 60 * time.Second
)

func cmsLossy(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

// cmsRunCmdIn runs program (in dir if non-empty), returning trimmed stdout on
// success, or stderr (stdout if stderr is empty — Joomla's CLI prints errors
// there) on failure. The context kills the child on timeout instead of
// orphaning it.
func cmsRunCmdIn(dir, program string, args []string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := safecmd.Command(ctx, program, args...)
	cmd.Env = append(cmd.Env, "HOME=/root", "COMPOSER_HOME=/root/.composer")
	cmd.Dir = dir
	out, err := safecmd.Run(ctx, cmd)
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("%s timed out after %ds", program, int(timeout.Seconds()))
	}
	if err != nil {
		return "", fmt.Errorf("Failed to execute %s: %v", program, err)
	}
	if !out.Success() {
		stderr := strings.TrimSpace(cmsLossy(out.Stderr))
		if stderr == "" {
			return "", fmt.Errorf("%s", strings.TrimSpace(cmsLossy(out.Stdout)))
		}
		return "", fmt.Errorf("%s", stderr)
	}
	return strings.TrimSpace(cmsLossy(out.Stdout)), nil
}

func cmsRunCmd(program string, args []string, timeout time.Duration) (string, error) {
	return cmsRunCmdIn("", program, args, timeout)
}

// cmsSplitHostPort splits host:port; port defaults to 3306.
func cmsSplitHostPort(dbHost string) (string, string) {
	if i := strings.LastIndex(dbHost, ":"); i >= 0 {
		return dbHost[:i], dbHost[i+1:]
	}
	return dbHost, "3306"
}

func cmsValidateDomain(domain string) error {
	if domain == "" || strings.ContainsAny(domain, "/\\\x00") || strings.Contains(domain, "..") {
		return fmt.Errorf("Invalid domain format")
	}
	for _, c := range domain {
		if !(c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') || c == '.' || c == '-') {
			return fmt.Errorf("Invalid domain format")
		}
	}
	return nil
}

// cmsChownSite hands a site directory to www-data WITHOUT handing over .git:
// once the CMS runs as www-data, a compromised app could create one, and
// deploy's clone_or_pull would run its hooks as root.
func cmsChownSite(path string) {
	ctx := context.Background()
	if entries, err := os.ReadDir(path); err == nil {
		for _, e := range entries {
			if e.Name() == ".git" {
				continue
			}
			_, _ = safecmd.Exec(ctx, "chown", "-R", "www-data:www-data", path+"/"+e.Name())
		}
	}
	gitDir := path + "/.git"
	if _, err := os.Stat(gitDir); err == nil {
		_, _ = safecmd.Exec(ctx, "chown", "-R", "root:root", gitDir)
		_, _ = safecmd.Exec(ctx, "chmod", "-R", "go-rwx", gitDir)
	}
}

// cmsSecureCredentialFile tightens a freshly written DB-credential file to
// 640 (umask default is 644). Closes reads from other local accounts; it does
// not isolate tenants, which all share the www-data identity.
func cmsSecureCredentialFile(path string) {
	_, _ = safecmd.Exec(context.Background(), "chmod", "640", path)
}

func cmsIsHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// cmsExtractReleaseSha256 extracts the SHA-256 GitHub release notes publish
// for one specific package file. Joomla documents per-package hashes as a
// markdown table in the release body; matching the exact filename (not a
// generic "ZIP Archive" label) keeps it from cross-matching the sibling
// "Update Packages" table. Only the first backtick token on the SAME line.
func cmsExtractReleaseSha256(body, filename string) (string, bool) {
	idx := strings.Index(body, filename)
	if idx < 0 {
		return "", false
	}
	sameLine, _, _ := strings.Cut(body[idx+len(filename):], "\n")
	_, rest, ok := strings.Cut(sameLine, "`")
	if !ok {
		return "", false
	}
	candidate, _, ok := strings.Cut(rest, "`")
	if !ok || !cmsIsHex64(candidate) {
		return "", false
	}
	return strings.ToLower(candidate), true
}

func cmsSha256File(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// CmsEnsureComposer installs Composer at /usr/local/bin/composer, verifying
// the phar against the `<url>.sha256` sidecar Composer publishes. Fails
// closed: any error removes the possibly-tampered phar so a retry cannot
// silently reuse it.
func CmsEnsureComposer() error {
	if _, err := os.Stat(cmsComposer); err == nil {
		return nil
	}
	const url = "https://getcomposer.org/download/latest-stable/composer.phar"

	ctx, cancel := context.WithTimeout(context.Background(), cmsDownloadTimeout)
	defer cancel()
	out, err := safecmd.Exec(ctx, "curl", "-sS", "-L", "-o", cmsComposer, url)
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("Downloading Composer timed out")
	}
	if err != nil {
		return fmt.Errorf("Download failed: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("Failed to download Composer")
	}

	sctx, scancel := context.WithTimeout(context.Background(), cmsQuickTimeout)
	defer scancel()
	shaOut, err := safecmd.Exec(sctx, "curl", "-sS", "-L", url+".sha256")
	if sctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("Fetching Composer's checksum timed out")
	}
	if err != nil {
		return fmt.Errorf("Failed to fetch Composer's checksum: %v", err)
	}
	if !shaOut.Success() {
		_ = os.Remove(cmsComposer)
		return fmt.Errorf("Failed to fetch Composer's checksum")
	}
	expected := strings.ToLower(strings.TrimSpace(cmsLossy(shaOut.Stdout)))
	if !cmsIsHex64(expected) {
		_ = os.Remove(cmsComposer)
		return fmt.Errorf("Composer's checksum response was not a valid sha256 digest")
	}
	actual, err := cmsSha256File(cmsComposer)
	if err != nil {
		return fmt.Errorf("Failed to read downloaded Composer: %v", err)
	}
	if actual != expected {
		_ = os.Remove(cmsComposer)
		return fmt.Errorf("Composer checksum mismatch: expected %s, got %s", expected, actual)
	}
	_, _ = safecmd.Exec(context.Background(), "chmod", "+x", cmsComposer)
	return nil
}

// cmsCopyFile mirrors std::fs::copy (content + permission bits).
func cmsCopyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, b, fi.Mode().Perm()); err != nil {
		return err
	}
	return os.Chmod(dst, fi.Mode().Perm())
}

func cmsCreateProject(pkg, siteDir string) error {
	_, err := cmsRunCmd(cmsComposer, []string{"create-project", pkg, siteDir + "/", "--no-interaction", "--prefer-dist"}, cmsComposerTimeout)
	return err
}

// CmsInstallLaravel installs Laravel into /var/www/{domain}/.
func CmsInstallLaravel(domain, dbName, dbUser, dbPass, dbHost, title string) (string, error) {
	if err := cmsValidateDomain(domain); err != nil {
		return "", err
	}
	if err := CmsEnsureComposer(); err != nil {
		return "", err
	}
	siteDir := cmsSiteRoot + "/" + domain
	if err := cmsCreateProject("laravel/laravel", siteDir); err != nil {
		return "", err
	}
	envFile := siteDir + "/.env"
	if err := cmsCopyFile(siteDir+"/.env.example", envFile); err != nil {
		return "", fmt.Errorf("Failed to copy .env.example: %v", err)
	}
	raw, err := os.ReadFile(envFile)
	if err != nil {
		return "", fmt.Errorf("Failed to read .env: %v", err)
	}
	host, port := cmsSplitHostPort(dbHost)
	env := string(raw)
	for _, kv := range [][2]string{
		{"APP_NAME", title}, {"APP_URL", "https://" + domain}, {"DB_HOST", host}, {"DB_PORT", port},
		{"DB_DATABASE", dbName}, {"DB_USERNAME", dbUser}, {"DB_PASSWORD", dbPass},
	} {
		env = cmsReplaceEnvLine(env, kv[0], kv[1])
	}
	if err := os.WriteFile(envFile, []byte(env), 0o644); err != nil {
		return "", fmt.Errorf("Failed to write .env: %v", err)
	}
	if _, err := cmsRunCmdIn(siteDir, "php", []string{"artisan", "key:generate", "--force"}, cmsQuickTimeout); err != nil {
		return "", err
	}
	// Migrations may fail — the DB might not be ready.
	_, _ = cmsRunCmdIn(siteDir, "php", []string{"artisan", "migrate", "--force"}, cmsCliInstallTimeout)

	cmsChownSite(siteDir)
	cmsSecureCredentialFile(envFile)
	return "Laravel installed successfully", nil
}

// CmsInstallDrupal installs Drupal into /var/www/{domain}/.
func CmsInstallDrupal(domain, dbName, dbUser, dbPass, dbHost, title, adminUser, adminPass, adminEmail string) (string, error) {
	if err := cmsValidateDomain(domain); err != nil {
		return "", err
	}
	if err := CmsEnsureComposer(); err != nil {
		return "", err
	}
	siteDir := cmsSiteRoot + "/" + domain
	if err := cmsCreateProject("drupal/recommended-project", siteDir); err != nil {
		return "", err
	}
	if _, err := cmsRunCmd(cmsComposer, []string{"require", "drush/drush", "--working-dir=" + siteDir, "--no-interaction"}, cmsComposerTimeout); err != nil {
		return "", err
	}
	// nginx expects public/, Drupal uses web/.
	link := siteDir + "/public"
	if _, err := os.Stat(link); err != nil {
		if err := os.Symlink("web", link); err != nil {
			return "", fmt.Errorf("Failed to create public symlink: %v", err)
		}
	}
	// db_user/db_pass/db_host are validated at the route layer to reject
	// '#', '/', '?': PHP's parse_url() (used by Drupal's
	// createConnectionOptionsFromUrl) breaks on them or, for '#' in the host,
	// silently truncates it. Percent-encoding does not work: Drupal never
	// urldecodes the components.
	dbURL := fmt.Sprintf("mysql://%s:%s@%s/%s", dbUser, dbPass, dbHost, dbName)
	if _, err := cmsRunCmdIn(siteDir, "vendor/bin/drush", []string{
		"site:install", "standard", "--db-url=" + dbURL, "--account-name=" + adminUser,
		"--account-pass=" + adminPass, "--account-mail=" + adminEmail, "--site-name=" + title, "-y",
	}, cmsCliInstallTimeout); err != nil {
		return "", err
	}
	cmsChownSite(siteDir)
	// drush writes settings.php under the recommended-project's web/ docroot.
	cmsSecureCredentialFile(siteDir + "/web/sites/default/settings.php")
	return "Drupal installed successfully", nil
}

// CmsInstallJoomla installs Joomla into /var/www/{domain}/public/.
func CmsInstallJoomla(domain, dbName, dbUser, dbPass, dbHost, title, adminUser, adminPass, adminEmail string) (string, error) {
	if err := cmsValidateDomain(domain); err != nil {
		return "", err
	}
	publicDir := cmsSiteRoot + "/" + domain + "/public"
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		return "", fmt.Errorf("Failed to create directory: %v", err)
	}

	// The Releases API carries both the tag AND the per-package SHA-256 table
	// in `body` (GitHub publishes no discrete checksum file).
	releaseJSON, err := cmsRunCmd("curl", []string{"-sS", "-L", "-H", "Accept: application/vnd.github+json",
		"https://api.github.com/repos/joomla/joomla-cms/releases/latest"}, cmsQuickTimeout)
	if err != nil {
		return "", err
	}
	var release map[string]any
	if err := json.Unmarshal([]byte(releaseJSON), &release); err != nil {
		return "", fmt.Errorf("Failed to parse Joomla release info: %v", err)
	}
	tag, ok := release["tag_name"].(string)
	if !ok {
		return "", fmt.Errorf("Joomla release info missing tag_name")
	}
	tagOK := tag != "" && len(tag) <= 64
	for _, c := range tag {
		if !(c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') || c == '.' || c == '-') {
			tagOK = false
		}
	}
	if !tagOK {
		return "", fmt.Errorf("Unexpected Joomla release tag format: %s", tag)
	}
	body, _ := release["body"].(string)

	zipFilename := fmt.Sprintf("Joomla_%s-Stable-Full_Package.zip", tag)
	expected, ok := cmsExtractReleaseSha256(body, zipFilename)
	if !ok {
		return "", fmt.Errorf("Could not find a published SHA-256 checksum for %s in the release notes", zipFilename)
	}

	// Random suffix prevents symlink attacks on the predictable /tmp path.
	var rb [8]byte
	_, _ = rand.Read(rb[:])
	zipPath := fmt.Sprintf("/tmp/joomla-%s-%016x.zip", domain, binary.LittleEndian.Uint64(rb[:]))
	downloadURL := fmt.Sprintf("https://github.com/joomla/joomla-cms/releases/download/%s/%s", tag, zipFilename)
	if _, err := cmsRunCmd("curl", []string{"-sL", "-o", zipPath, downloadURL}, cmsDownloadTimeout); err != nil {
		return "", err
	}
	// Verify BEFORE extracting — fail closed.
	actual, err := cmsSha256File(zipPath)
	if err != nil {
		return "", fmt.Errorf("Failed to read downloaded Joomla package: %v", err)
	}
	if actual != expected {
		_ = os.Remove(zipPath)
		return "", fmt.Errorf("Joomla package checksum mismatch: expected %s, got %s", expected, actual)
	}
	if _, err := cmsRunCmd("unzip", []string{"-o", zipPath, "-d", publicDir}, cmsDownloadTimeout); err != nil {
		return "", err
	}
	_ = os.Remove(zipPath)

	if _, err := cmsRunCmd("php", []string{
		publicDir + "/installation/joomla.php", "install",
		"--site-name=" + title, "--admin-user=" + adminUser, "--admin-username=" + adminUser,
		"--admin-password=" + adminPass, "--admin-email=" + adminEmail, "--db-type=mysqli",
		"--db-host=" + dbHost, "--db-user=" + dbUser, "--db-pass=" + dbPass, "--db-name=" + dbName,
		"--db-prefix=j_", "--db-encryption=0",
	}, cmsCliInstallTimeout); err != nil {
		return "", err
	}
	cmsChownSite(publicDir)
	cmsSecureCredentialFile(publicDir + "/configuration.php")
	return "Joomla installed successfully", nil
}

// CmsInstallSymfony installs the Symfony skeleton into /var/www/{domain}/.
// title is unused: the skeleton has no site-name concept.
func CmsInstallSymfony(domain, title string) (string, error) {
	if err := cmsValidateDomain(domain); err != nil {
		return "", err
	}
	if err := CmsEnsureComposer(); err != nil {
		return "", err
	}
	siteDir := cmsSiteRoot + "/" + domain
	if err := cmsCreateProject("symfony/skeleton", siteDir); err != nil {
		return "", err
	}
	envFile := siteDir + "/.env"
	if _, err := os.Stat(envFile); err == nil {
		raw, err := os.ReadFile(envFile)
		if err != nil {
			return "", fmt.Errorf("Failed to read .env: %v", err)
		}
		_ = os.WriteFile(envFile, []byte(cmsReplaceEnvLine(string(raw), "APP_ENV", "prod")), 0o644)
	}
	cmsChownSite(siteDir)
	return "Symfony installed successfully", nil
}

// CmsInstallCodeigniter installs CodeIgniter 4 into /var/www/{domain}/.
func CmsInstallCodeigniter(domain, dbName, dbUser, dbPass, dbHost, title string) (string, error) {
	if err := cmsValidateDomain(domain); err != nil {
		return "", err
	}
	if err := CmsEnsureComposer(); err != nil {
		return "", err
	}
	siteDir := cmsSiteRoot + "/" + domain
	if err := cmsCreateProject("codeigniter4/appstarter", siteDir); err != nil {
		return "", err
	}
	envFile := siteDir + "/.env"
	if err := cmsCopyFile(siteDir+"/env", envFile); err != nil {
		return "", fmt.Errorf("Failed to copy env template: %v", err)
	}
	raw, err := os.ReadFile(envFile)
	if err != nil {
		return "", fmt.Errorf("Failed to read .env: %v", err)
	}
	host, port := cmsSplitHostPort(dbHost)
	env := string(raw)
	for _, kv := range [][2]string{
		{"CI_ENVIRONMENT", "production"}, {"database.default.hostname", host},
		{"database.default.database", dbName}, {"database.default.username", dbUser},
		{"database.default.password", dbPass}, {"database.default.DBDriver", "MySQLi"},
		{"database.default.port", port}, {"app.baseURL", "https://" + domain},
	} {
		env = cmsSetCiEnv(env, kv[0], kv[1])
	}
	if err := os.WriteFile(envFile, []byte(env), 0o644); err != nil {
		return "", fmt.Errorf("Failed to write .env: %v", err)
	}
	cmsChownSite(siteDir)
	cmsSecureCredentialFile(envFile)
	return "CodeIgniter installed successfully", nil
}

// cmsQuoteLaravelEnvValue quotes for vlucas/phpdotenv so the value
// round-trips byte-for-byte: a bare `#` starts a comment with no whitespace
// precondition, and `$` inside double quotes interpolates — so `\`, `"` and
// `$` are all backslash-escaped (verified against the real library).
func cmsQuoteLaravelEnvValue(v string) string {
	v = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`).Replace(v)
	return `"` + v + `"`
}

// cmsReplaceEnvLine replaces or adds a KEY=value line (Laravel style).
func cmsReplaceEnvLine(content, key, value string) string {
	prefix := key + "="
	line := key + "=" + cmsQuoteLaravelEnvValue(value)
	found := false
	lines := LogsLines([]byte(content))
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) || strings.HasPrefix(l, "# "+prefix) {
			found = true
			lines[i] = line
		}
	}
	if !found {
		lines = append(lines, line)
	}
	out := strings.Join(lines, "\n")
	if strings.HasSuffix(content, "\n") {
		out += "\n"
	}
	return out
}

// cmsQuoteCi4EnvValue quotes for CodeIgniter 4's OWN DotEnv parser, whose
// sanitizeValue() only understands `\\` and `\"` — escaping `$` would desync
// its regex, so `$` stays bare. Residual: resolveNestedVariables() expands a
// literal `${VAR}` with no escape; safecmd's minimal child env makes that
// theoretical.
func cmsQuoteCi4EnvValue(v string) string {
	v = strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v)
	return `"` + v + `"`
}

// cmsSetCiEnv sets a CodeIgniter .env value, uncommenting if necessary
// (`# database.default.hostname = localhost` or the active form).
func cmsSetCiEnv(content, key, value string) string {
	newLine := key + " = " + cmsQuoteCi4EnvValue(value)
	found := false
	lines := LogsLines([]byte(content))
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if !(strings.HasPrefix(t, "# "+key) || strings.HasPrefix(t, "#"+key) || strings.HasPrefix(t, key)) {
			continue
		}
		after := t
		if strings.HasPrefix(t, "#") {
			after = strings.TrimSpace(strings.TrimLeft(t, "#"))
		}
		if strings.HasPrefix(after, key) && strings.HasPrefix(strings.TrimLeftFunc(after[len(key):], unicode.IsSpace), "=") {
			found = true
			lines[i] = newLine
		}
	}
	if !found {
		lines = append(lines, newLine)
	}
	out := strings.Join(lines, "\n")
	if strings.HasSuffix(content, "\n") {
		out += "\n"
	}
	return out
}
