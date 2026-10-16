// Per-image SBOM generator using Anchore's syft.
//
// Produces an SPDX 2.3 JSON document describing every package present in a
// Docker image. Different from the per-image vulnerability scanner (grype):
// SBOMs describe *what is installed*, vuln scans describe *what is
// vulnerable*. Operators want both — the SBOM is the supply-chain artifact,
// the vuln scan is the risk assessment.

package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// Same hardened-sandbox-compatible install location used by image_scanner.go.
const (
	sbomScannerSyftDir = "/var/lib/dockpanel/scanners"
	sbomScannerSyftBin = "/var/lib/dockpanel/scanners/syft"
)

// Same pinning rationale as imageScannerGrypeVersion — see that comment.
const sbomScannerSyftVersion = "v1.51.1"

// SbomScannerIsInstalled reports whether the syft binary is present at the
// managed path.
func SbomScannerIsInstalled() bool {
	_, err := os.Stat(sbomScannerSyftBin)
	return err == nil
}

// SbomScannerInstallSyft installs syft via Anchore's official installer
// script into the DockPanel data directory so the hardened agent sandbox can
// read/write it.
func SbomScannerInstallSyft(ctx context.Context) error {
	if SbomScannerIsInstalled() {
		return nil
	}
	if err := os.MkdirAll(sbomScannerSyftDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %v", sbomScannerSyftDir, err)
	}
	cmd := fmt.Sprintf("curl -sSfL https://raw.githubusercontent.com/anchore/syft/%s/install.sh | sh -s -- -b %s %s",
		sbomScannerSyftVersion, sbomScannerSyftDir, sbomScannerSyftVersion)

	ictx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ictx, "sh", "-c", cmd)
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("syft install timed out after 180s")
	}
	if err != nil {
		return fmt.Errorf("syft install failed to execute: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("syft install failed: %s", imageScannerTruncate(strings.ToValidUTF8(string(out.Stderr), "�"), 300))
	}
	return nil
}

// SbomScannerUninstallSyft removes the syft binary.
func SbomScannerUninstallSyft() error {
	_ = os.Remove(sbomScannerSyftBin)
	return nil
}

// SbomScannerGenerateSbom generates an SPDX 2.3 JSON SBOM for a Docker image.
// Returns the raw JSON string so the backend can persist and serve it without
// re-serializing. Times out at 180s so a hung image pull cannot wedge the
// agent's request handler.
func SbomScannerGenerateSbom(ctx context.Context, image string) (string, error) {
	if err := imageScannerValidRef(image); err != nil {
		return "", err
	}
	if !SbomScannerIsInstalled() {
		return "", errors.New("Scanner not installed. Install syft first.")
	}

	sctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	out, err := safecmd.Exec(sctx, sbomScannerSyftBin, image, "-o", "spdx-json", "-q")
	if errors.Is(err, context.DeadlineExceeded) {
		return "", errors.New("SBOM generation timed out after 180s")
	}
	if err != nil {
		return "", fmt.Errorf("syft invocation failed: %v", err)
	}
	if !out.Success() {
		return "", fmt.Errorf("syft failed: %s", imageScannerTruncate(strings.ToValidUTF8(string(out.Stderr), "�"), 400))
	}
	if !utf8.Valid(out.Stdout) {
		return "", errors.New("syft produced non-UTF8 output")
	}
	stdout := string(out.Stdout)

	// Defensive: confirm syft actually emitted SPDX (top-level field present).
	// Avoids storing a corrupt/empty document that would fail later validation.
	if !strings.Contains(stdout, `"spdxVersion"`) {
		return "", errors.New("syft output missing SPDX header — unexpected format")
	}
	return stdout, nil
}
