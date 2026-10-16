package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/sitelock"
)

const stagingWebRoot = "/var/www"

func stagingValidateDomain(domain string) error {
	if domain == "" || strings.Contains(domain, "..") || strings.ContainsAny(domain, "/\\\x00") {
		return errors.New("Invalid domain format")
	}
	for _, c := range domain {
		if !stagingIsDomainChar(c) {
			return errors.New("Invalid domain format")
		}
	}
	return nil
}

func stagingIsDomainChar(c rune) bool {
	return c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-')
}

// stagingRsync mirrors source into target (`rsync -a --delete`: permissions,
// timestamps, exact copy), then fixes ownership — everything but `.git`, which
// stays root's: rsync copied the source tree verbatim, and a `.git` handed to
// www-data gives the app config/hooks/ that DeployCloneOrPull runs as root.
func stagingRsync(ctx context.Context, source, target string) error {
	out, err := deployRun(ctx, 0, "", nil, "rsync", "-a", "--delete", source, target)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("Failed to run rsync: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("rsync failed: %s", nginxLossy(out.Stderr))
	}
	deployHandTreeExceptGit(ctx, target)
	return nil
}

// StagingCloneFiles copies src's site files to dst with rsync, creating dst.
// ctx bounds rsync (the caller sets the request-level cap).
func StagingCloneFiles(ctx context.Context, src, dst string) (string, error) {
	if err := stagingValidateDomain(src); err != nil {
		return "", err
	}
	if err := stagingValidateDomain(dst); err != nil {
		return "", err
	}
	// Both sites at once, in a fixed order, through rsync + chown.
	defer sitelock.LockSites(src, dst)()

	source := fmt.Sprintf("%s/%s/", stagingWebRoot, src)
	target := fmt.Sprintf("%s/%s/", stagingWebRoot, dst)
	if _, err := os.Stat(source); err != nil {
		return "", fmt.Errorf("Source directory not found: %s", source)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return "", fmt.Errorf("Failed to create target directory: %v", nginxIOErr(err))
	}
	if err := stagingRsync(ctx, source, target); err != nil {
		return "", err
	}
	return fmt.Sprintf("Cloned %s → %s", source, target), nil
}

// StagingSyncFiles syncs files between two existing site directories.
func StagingSyncFiles(ctx context.Context, src, dst string) (string, error) {
	if err := stagingValidateDomain(src); err != nil {
		return "", err
	}
	if err := stagingValidateDomain(dst); err != nil {
		return "", err
	}
	defer sitelock.LockSites(src, dst)()

	source := fmt.Sprintf("%s/%s/", stagingWebRoot, src)
	target := fmt.Sprintf("%s/%s/", stagingWebRoot, dst)
	if _, err := os.Stat(source); err != nil {
		return "", fmt.Errorf("Source directory not found: %s", source)
	}
	if _, err := os.Stat(target); err != nil {
		return "", fmt.Errorf("Target directory not found: %s", target)
	}
	if err := stagingRsync(ctx, source, target); err != nil {
		return "", err
	}
	return fmt.Sprintf("Synced %s → %s", source, target), nil
}

// StagingSiteDiskUsage returns a site directory's size in bytes.
func StagingSiteDiskUsage(ctx context.Context, domain string) (uint64, error) {
	if err := stagingValidateDomain(domain); err != nil {
		return 0, err
	}
	path := stagingWebRoot + "/" + domain
	if _, err := os.Stat(path); err != nil {
		return 0, nil
	}
	out, err := deployRun(ctx, 0, "", nil, "du", "-sb", path)
	if err != nil {
		return 0, fmt.Errorf("du failed: %v", err)
	}
	if !out.Success() {
		return 0, nil
	}
	fields := strings.Fields(nginxLossy(out.Stdout))
	if len(fields) > 0 {
		if n, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			return n, nil
		}
	}
	return 0, errors.New("Failed to parse du output")
}

// StagingDeleteSiteFiles deletes a site's web directory.
func StagingDeleteSiteFiles(domain string) error {
	if err := stagingValidateDomain(domain); err != nil {
		return err
	}
	defer sitelock.LockSite(domain)()
	path := stagingWebRoot + "/" + domain
	if _, err := os.Stat(path); err == nil {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("Failed to delete %s: %v", path, nginxIOErr(err))
		}
	}
	return nil
}
