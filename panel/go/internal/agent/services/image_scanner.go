// Per-image vulnerability scanner using Anchore's grype.
//
// Surfaces results per Docker image so the panel can badge individual apps
// and gate deploys at a configurable severity threshold. Distinct from the
// full security scan (security_scanner.go) which lumps container vuln counts
// into a single all-server report.

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// The scanner lives inside the DockPanel data dir so it works under the
// hardened agent sandbox (ProtectSystem=strict, ProtectHome=yes) without
// needing write access to /usr/local/bin or $HOME.
const (
	imageScannerGrypeDir     = "/var/lib/dockpanel/scanners"
	imageScannerGrypeBin     = "/var/lib/dockpanel/scanners/grype"
	imageScannerGrypeDBCache = "/var/lib/dockpanel/scanners/grype-db"
)

// Pinned to a known release rather than "latest" so the exact binary we run
// is reviewable and reproducible. Anchore's install.sh already sha256-verifies
// the downloaded archive against its release checksums.txt unconditionally, so
// this pin closes the remaining gap: without a TAG argument the script both
// re-resolves "latest" on every install AND is fetched from the mutable `main`
// ref. Bump deliberately.
const imageScannerGrypeVersion = "v0.118.0"

// ImageScannerImageScanResult is the wire shape of POST /image-scan/scan.
type ImageScannerImageScanResult struct {
	Image           string             `json:"image"`
	Scanner         string             `json:"scanner"`
	CriticalCount   uint32             `json:"critical_count"`
	HighCount       uint32             `json:"high_count"`
	MediumCount     uint32             `json:"medium_count"`
	LowCount        uint32             `json:"low_count"`
	UnknownCount    uint32             `json:"unknown_count"`
	Vulnerabilities []ImageScannerVuln `json:"vulnerabilities"`
	ScannedAt       string             `json:"scanned_at"`
}

// ImageScannerVuln is one finding.
type ImageScannerVuln struct {
	Cve              string  `json:"cve"`
	Severity         string  `json:"severity"`
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     *string `json:"fixed_version"`
	Description      *string `json:"description"`
}

// ImageScannerIsInstalled reports whether the scanner binary is present at
// the managed path.
func ImageScannerIsInstalled() bool {
	_, err := os.Stat(imageScannerGrypeBin)
	return err == nil
}

// imageScannerTruncate keeps the first n characters (not bytes).
func imageScannerTruncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// ImageScannerInstallGrype installs grype via Anchore's official installer
// script into the DockPanel data directory so the hardened agent sandbox can
// read/write it.
func ImageScannerInstallGrype(ctx context.Context) error {
	if ImageScannerIsInstalled() {
		return nil
	}
	if err := os.MkdirAll(imageScannerGrypeDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %v", imageScannerGrypeDir, err)
	}

	// The installer writes the binary to the path passed via `-b`, inside
	// /var/lib/dockpanel (writable under ProtectSystem=strict). Both the
	// script fetch AND the binary download are pinned to the version tag, so
	// nothing here resolves "latest" at install time.
	cmd := fmt.Sprintf("curl -sSfL https://raw.githubusercontent.com/anchore/grype/%s/install.sh | sh -s -- -b %s %s",
		imageScannerGrypeVersion, imageScannerGrypeDir, imageScannerGrypeVersion)

	ictx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ictx, "sh", "-c", cmd)
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("grype install timed out after 180s")
	}
	if err != nil {
		return fmt.Errorf("grype install failed to execute: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("grype install failed: %s", imageScannerTruncate(strings.ToValidUTF8(string(out.Stderr), "�"), 300))
	}

	// Prime the vulnerability database so the first user-facing scan does
	// not stall on a 200 MB download.
	dctx, dcancel := context.WithTimeout(ctx, 180*time.Second)
	defer dcancel()
	c := safecmd.Command(dctx, imageScannerGrypeBin, "db", "update")
	c.Env = append(c.Env, "GRYPE_DB_CACHE_DIR="+imageScannerGrypeDBCache)
	_, _ = safecmd.Run(dctx, c)
	return nil
}

// ImageScannerUninstallGrype removes the grype binary and its cached
// vulnerability database.
func ImageScannerUninstallGrype() error {
	_ = os.Remove(imageScannerGrypeBin)
	_ = os.RemoveAll(imageScannerGrypeDBCache)
	return nil
}

// imageScannerValidRef: the character set Docker accepts for image refs.
// Rejects anything that could break out of the argv slot.
func imageScannerValidRef(image string) error {
	if image == "" || len(image) > 512 {
		return errors.New("Invalid image reference")
	}
	for _, c := range image {
		if !(c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') ||
			strings.ContainsRune(":/.-_@", c)) {
			return errors.New("Image reference contains disallowed characters")
		}
	}
	return nil
}

// ImageScannerScanImage scans a single Docker image. Times out at 180s so a
// hung pull cannot wedge the agent's request handler.
func ImageScannerScanImage(ctx context.Context, image string) (ImageScannerImageScanResult, error) {
	if err := imageScannerValidRef(image); err != nil {
		return ImageScannerImageScanResult{}, err
	}
	if !ImageScannerIsInstalled() {
		return ImageScannerImageScanResult{}, errors.New("Scanner not installed. Install grype first.")
	}

	sctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	c := safecmd.Command(sctx, imageScannerGrypeBin, image, "-o", "json")
	c.Env = append(c.Env, "GRYPE_DB_CACHE_DIR="+imageScannerGrypeDBCache)
	out, err := safecmd.Run(sctx, c)
	if errors.Is(err, context.DeadlineExceeded) {
		return ImageScannerImageScanResult{}, errors.New("Image scan timed out after 180s")
	}
	if err != nil {
		return ImageScannerImageScanResult{}, fmt.Errorf("grype invocation failed: %v", err)
	}
	if !out.Success() {
		return ImageScannerImageScanResult{}, fmt.Errorf("grype scan failed: %s", imageScannerTruncate(strings.ToValidUTF8(string(out.Stderr), "�"), 400))
	}
	return imageScannerParseGrypeOutput(image, strings.ToValidUTF8(string(out.Stdout), "�"))
}

type imageScannerGrypeReport struct {
	Matches *[]struct {
		Vulnerability *struct {
			ID          *string `json:"id"`
			Severity    *string `json:"severity"`
			Description *string `json:"description"`
			Fix         *struct {
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact *struct {
			Name    *string `json:"name"`
			Version *string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
}

func imageScannerParseGrypeOutput(image, jsonStr string) (ImageScannerImageScanResult, error) {
	var report imageScannerGrypeReport
	if err := json.Unmarshal([]byte(jsonStr), &report); err != nil {
		return ImageScannerImageScanResult{}, fmt.Errorf("Failed to parse grype JSON: %v", err)
	}
	res := ImageScannerImageScanResult{Image: image, Scanner: "grype", Vulnerabilities: []ImageScannerVuln{}}

	if report.Matches != nil {
		// Validate the required fields first: serde rejected the whole report
		// when any match lacked one.
		for _, m := range *report.Matches {
			if m.Vulnerability == nil || m.Artifact == nil || m.Vulnerability.ID == nil || m.Vulnerability.Severity == nil ||
				m.Artifact.Name == nil || m.Artifact.Version == nil {
				return ImageScannerImageScanResult{}, errors.New("Failed to parse grype JSON: missing field")
			}
		}
		for _, m := range *report.Matches {
			sev := imageScannerNormalizeSeverity(*m.Vulnerability.Severity)
			switch sev {
			case "critical":
				res.CriticalCount++
			case "high":
				res.HighCount++
			case "medium":
				res.MediumCount++
			case "low":
				res.LowCount++
			default:
				res.UnknownCount++
			}
			var fixed *string
			if m.Vulnerability.Fix != nil && len(m.Vulnerability.Fix.Versions) > 0 {
				fixed = &m.Vulnerability.Fix.Versions[0]
			}
			// Cap stored vulns to keep the payload manageable; counts are
			// still accurate because we counted before truncating.
			if len(res.Vulnerabilities) < 500 {
				res.Vulnerabilities = append(res.Vulnerabilities, ImageScannerVuln{
					Cve:              *m.Vulnerability.ID,
					Severity:         sev,
					Package:          *m.Artifact.Name,
					InstalledVersion: *m.Artifact.Version,
					FixedVersion:     fixed,
					Description:      m.Vulnerability.Description,
				})
			}
		}
	}
	res.ScannedAt = SslRFC3339(time.Now().UTC())
	return res, nil
}

func imageScannerNormalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low", "negligible":
		return "low"
	}
	return "unknown"
}
