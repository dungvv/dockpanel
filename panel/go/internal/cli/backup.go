package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func mb(bytes uint64) float64 { return float64(bytes) / 1_048_576.0 }

func cmdBackupCreate(token, domain string) error {
	fmt.Printf("Creating backup for %s...\n", domain)
	result, err := agentPostEmpty("/backups/"+domain+"/create", token)
	if err != nil {
		return err
	}
	fmt.Println("\x1b[32m✓\x1b[0m Backup created")
	fmt.Printf("  File:    %s\n", strOr(get(result, "filename"), "unknown"))
	fmt.Printf("  Size:    %.1f MB\n", mb(u64Or(get(result, "size_bytes"), 0)))
	fmt.Println("  Content: files only")

	// The CLI authenticates to the AGENT, which cannot know which databases
	// belong to this site or hold their credentials. A backup taken here is
	// genuinely less complete than one taken from the panel, so say so.
	fmt.Println("\n\x1b[33m!\x1b[0m This archive contains the site's files but NOT its databases.\n  " +
		"The CLI talks to the agent directly and cannot resolve a site's databases.\n  " +
		"Create the backup from the panel (or the panel API) to include them.")
	return nil
}

func printBackupTable(backups []any, width int, showUnsupported bool) {
	fmt.Printf("\x1b[1m%-*s %-12s %-20s\x1b[0m\n", width, "FILENAME", "SIZE", "CREATED")
	for _, b := range backups {
		fmt.Printf("%-*s %-12s %-20s\n", width, strOr(get(b, "filename"), "-"),
			fmt.Sprintf("%.1f MB", mb(u64Or(get(b, "size_bytes"), 0))), strOr(get(b, "created_at"), "-"))
		if showUnsupported {
			// A file the agent cannot import is REPORTED rather than
			// dropped, so print the reason where the operator is already looking.
			if reason, ok := str(get(b, "unsupported")); ok {
				fmt.Printf("\x1b[33m  ↳ cannot be imported: %s\x1b[0m\n", reason)
			}
		}
	}
}

func cmdBackupList(token, domain, output string) error {
	v, err := agentGet("/backups/"+domain+"/list", token)
	if err != nil {
		return err
	}
	if output == "json" {
		fmt.Println(pretty(v))
		return nil
	}
	backups, ok := arr(v)
	if !ok {
		return errors.New("Expected array from /backups")
	}
	if len(backups) == 0 {
		fmt.Printf("No backups for %s.\n", domain)
		return nil
	}
	printBackupTable(backups, 40, false)
	fmt.Printf("\n%d backup(s)\n", len(backups))
	return nil
}

func cmdBackupRestore(token, domain, filename string) error {
	// Prefer the panel API when a key is configured: it holds the site's
	// database credentials and can restore dumps as well as files. Without a
	// key, fall back to the agent-direct path (files only), unchanged.
	if bt, err := loadBackendToken(); err == nil {
		return cmdBackupRestoreViaBackend(bt, domain, filename)
	}

	fmt.Printf("Restoring %s from %s...\n", domain, filename)
	// An archive with database dumps cannot be fully restored from here; the
	// agent refuses rather than restoring only files, so surface WHY.
	result, err := agentPostEmpty("/backups/"+domain+"/restore/"+filename, token)
	if err != nil {
		e := err.Error()
		if strings.Contains(e, "supplied no database credentials") || strings.Contains(e, "database(s) were NOT") {
			return fmt.Errorf("%s\n\nThis backup contains database dumps, and the CLI cannot restore them — it "+
				"talks to the agent directly and has no access to the site's database credentials. "+
				"Mint an API key from the panel (Settings → API Keys), save it to "+
				"/etc/dockpanel/backend.token, and retry — or restore this backup from the panel instead.", e)
		}
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to restore backup: %s", strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Println("\x1b[32m✓\x1b[0m Backup restored")
	dbs, _ := arr(get(result, "databases_restored"))
	if len(dbs) > 0 {
		fmt.Printf("  Databases restored: %d\n", len(dbs))
	} else if u64Or(get(result, "databases_in_archive"), 0) == 0 {
		fmt.Println("  Content: files only (this archive holds no database)")
	}
	return nil
}

func findID(list []any, key, want string) (string, bool) {
	for _, item := range list {
		if s, ok := str(get(item, key)); ok && s == want {
			return str(get(item, "id"))
		}
	}
	return "", false
}

// cmdBackupRestoreViaBackend resolves domain → site id and filename → backup
// id through the panel API, starts the same async restore as the panel UI,
// then follows its progress stream. No X-Server-Id header is sent, so the
// panel always resolves the LOCAL server — the single-box case this is for.
func cmdBackupRestoreViaBackend(token, domain, filename string) error {
	v, err := backendGet("/api/sites", token)
	if err != nil {
		return err
	}
	sites, ok := arr(v)
	if !ok {
		return errors.New("Expected an array from /api/sites")
	}
	siteID, ok := findID(sites, "domain", domain)
	if !ok {
		// /api/sites lists only sites this account OWNS, but the restore
		// endpoint also admits an admin of the machine. /api/admin/sites
		// covers that gap; a non-admin key's 403 is swallowed so the original
		// "no site found" error still fires.
		if all, err := backendGet("/api/admin/sites", token); err == nil {
			if list, ok2 := arr(all); ok2 {
				siteID, ok = findID(list, "domain", domain)
			}
		}
		if !ok {
			return fmt.Errorf("No site found for domain '%s' via the panel API", domain)
		}
	}

	v, err = backendGet("/api/sites/"+siteID+"/backups", token)
	if err != nil {
		return err
	}
	backups, ok := arr(v)
	if !ok {
		return errors.New("Expected an array from the backups list")
	}
	backupID, ok := findID(backups, "filename", filename)
	if !ok {
		return fmt.Errorf("No backup named '%s' found for %s via the panel API", filename, domain)
	}

	fmt.Printf("Restoring %s from %s (via the panel API — files and databases)...\n", domain, filename)
	started, err := backendPostEmpty("/api/sites/"+siteID+"/backups/"+backupID+"/restore", token)
	if err != nil {
		return err
	}
	restoreID, ok := str(get(started, "restore_id"))
	if !ok {
		return errors.New("Panel API did not return a restore_id")
	}
	if err := followProgress(restoreID, token); err != nil {
		return err
	}
	fmt.Println("\x1b[32m✓\x1b[0m Backup restored")
	return nil
}

func cmdBackupDelete(token, domain, filename string) error {
	fmt.Printf("Deleting backup %s...\n", filename)
	result, err := agentDelete("/backups/"+domain+"/"+filename, token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to delete backup: %s", strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Println("\x1b[32m✓\x1b[0m Backup deleted")
	return nil
}

func cmdDBBackupCreate(token, container, dbName, dbType, user string, password *string, fromStdin bool) error {
	pw, err := resolvePassword(password, fromStdin, "Database password: ")
	if err != nil {
		return err
	}
	fmt.Printf("Creating %s backup for %s...\n", dbType, dbName)
	result, err := agentPost("/db-backups/dump", map[string]any{
		"container_name": container, "db_name": dbName, "db_type": dbType, "user": user, "password": pw,
	}, token)
	if err != nil {
		return err
	}
	fmt.Println("\x1b[32m✓\x1b[0m Database backup created")
	fmt.Printf("  File:    %s\n", strOr(get(result, "filename"), "unknown"))
	fmt.Printf("  Size:    %.1f MB\n", mb(u64Or(get(result, "size_bytes"), 0)))
	return nil
}

func cmdDBBackupList(token, dbName, output string) error {
	v, err := agentGet("/db-backups/"+dbName+"/list", token)
	if err != nil {
		return err
	}
	if output == "json" {
		fmt.Println(pretty(v))
		return nil
	}
	backups, ok := arr(v)
	if !ok {
		return errors.New("Expected array")
	}
	if len(backups) == 0 {
		fmt.Printf("No database backups for %s.\n", dbName)
		return nil
	}
	printBackupTable(backups, 50, true)
	unusable := 0
	for _, b := range backups {
		if _, ok := str(get(b, "unsupported")); ok {
			unusable++
		}
	}
	if unusable > 0 {
		fmt.Printf("\n%d file(s), %d of which cannot be imported\n", len(backups), unusable)
	} else {
		fmt.Printf("\n%d backup(s)\n", len(backups))
	}
	return nil
}

func cmdVolBackupCreate(token, volume, container string) error {
	fmt.Printf("Creating volume backup for %s...\n", volume)
	result, err := agentPost("/volume-backups/create", map[string]any{"volume_name": volume, "container_name": container}, token)
	if err != nil {
		return err
	}
	fmt.Println("\x1b[32m✓\x1b[0m Volume backup created")
	fmt.Printf("  File:    %s\n", strOr(get(result, "filename"), "unknown"))
	fmt.Printf("  Size:    %.1f MB\n", mb(u64Or(get(result, "size_bytes"), 0)))
	return nil
}

func cmdVolBackupList(token, container, output string) error {
	v, err := agentGet("/volume-backups/"+container+"/list", token)
	if err != nil {
		return err
	}
	if output == "json" {
		fmt.Println(pretty(v))
		return nil
	}
	backups, ok := arr(v)
	if !ok {
		return errors.New("Expected array")
	}
	if len(backups) == 0 {
		fmt.Printf("No volume backups for %s.\n", container)
		return nil
	}
	printBackupTable(backups, 50, false)
	fmt.Printf("\n%d backup(s)\n", len(backups))
	return nil
}

func cmdBackupVerify(token, backupType, name, filename, dbType string) error {
	fmt.Printf("Verifying %s backup: %s...\n", backupType, filename)
	var body map[string]any
	switch backupType {
	case "site":
		body = map[string]any{"domain": name, "filename": filename}
	case "database":
		// db_type used to be hardcoded to "postgres", so every mysql/mariadb
		// backup got a Postgres restore attempted and reported FAILED.
		body = map[string]any{"db_type": dbType, "db_name": name, "filename": filename}
	case "volume":
		body = map[string]any{"container_name": name, "filename": filename}
	default:
		return fmt.Errorf("Invalid backup type: %s. Use site, database, or volume.", backupType)
	}
	result, err := agentPost("/backups/verify/"+backupType, body, token)
	if err != nil {
		return err
	}
	passed := isTrue(get(result, "passed"))
	run, good := i64Or(get(result, "checks_run"), 0), i64Or(get(result, "checks_passed"), 0)
	dur := u64Or(get(result, "duration_ms"), 0)
	if passed {
		fmt.Printf("\x1b[32m✓\x1b[0m Verification PASSED (%d/%d checks, %dms)\n", good, run, dur)
	} else {
		fmt.Printf("\x1b[31m✗\x1b[0m Verification FAILED (%d/%d checks, %dms)\n", good, run, dur)
	}
	details, _ := arr(get(result, "details"))
	for _, c := range details {
		icon := "\x1b[31m✗\x1b[0m"
		if isTrue(get(c, "passed")) {
			icon = "\x1b[32m✓\x1b[0m"
		}
		fmt.Printf("  %s %s: %s\n", icon, strOr(get(c, "name"), "-"), strOr(get(c, "message"), "-"))
	}
	return nil
}

const backupRoot = "/var/backups/dockpanel"

// The backup root is not exclusively site-backup domain dirs — the agent also
// writes databases/, volumes/, wp-snapshots/, snapshots/ and dot-staging dirs
// there, and ops tooling drops DB dumps in db/. Counting every top-level dir
// as a site inflated "site backups" ~9x in files and ~50000x in size, so
// dot-dirs and every other subsystem's root are excluded.
var reservedTopLevelDirs = []string{"databases", "volumes", "wp-snapshots", "snapshots", "db"}

func isSiteBackupDir(name string) bool {
	return !strings.HasPrefix(name, ".") && !slices.Contains(reservedTopLevelDirs, name)
}

func isDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func countDirs(dir string, onlySiteDirs bool) int {
	entries, _ := os.ReadDir(dir)
	n := 0
	for _, e := range entries {
		if isDir(filepath.Join(dir, e.Name())) && (!onlySiteDirs || isSiteBackupDir(e.Name())) {
			n++
		}
	}
	return n
}

// countFiles counts regular files one level below each subdirectory of dir.
func countFiles(dir string, onlySiteDirs bool) (int, uint64) {
	entries, _ := os.ReadDir(dir)
	count, size := 0, uint64(0)
	for _, e := range entries {
		sub := filepath.Join(dir, e.Name())
		if !isDir(sub) || (onlySiteDirs && !isSiteBackupDir(e.Name())) {
			continue
		}
		files, _ := os.ReadDir(sub)
		for _, f := range files {
			if info, err := f.Info(); err == nil && info.Mode().IsRegular() {
				count++
				size += uint64(info.Size())
			}
		}
	}
	return count, size
}

// cmdBackupHealth reports local backup counts straight from disk.
func cmdBackupHealth() error {
	siteDirs := countDirs(backupRoot, true)
	dbDirs := countDirs(backupRoot+"/databases", false)
	volDirs := countDirs(backupRoot+"/volumes", false)
	siteCount, siteSize := countFiles(backupRoot, true)
	dbCount, dbSize := countFiles(backupRoot+"/databases", false)
	volCount, volSize := countFiles(backupRoot+"/volumes", false)

	fmt.Print("\x1b[1mBackup Health Overview\x1b[0m\n\n")
	fmt.Printf("  Site backups:     %4d files across %d domains (%.1f MB)\n", siteCount, siteDirs, mb(siteSize))
	fmt.Printf("  Database backups: %4d files across %d databases (%.1f MB)\n", dbCount, dbDirs, mb(dbSize))
	fmt.Printf("  Volume backups:   %4d files across %d containers (%.1f MB)\n", volCount, volDirs, mb(volSize))
	fmt.Println("  ─────────────────────────────────────")
	fmt.Printf("  Total:            %4d files (%.1f MB)\n", siteCount+dbCount+volCount, mb(siteSize+dbSize+volSize))
	return nil
}
