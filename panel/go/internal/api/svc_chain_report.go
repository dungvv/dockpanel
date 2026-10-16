package api

// Port of panel/backend/src/services/chain_report.rs.
//
// Chain-of-trust report rendering: lazy-install typst CLI on first use, then
// transform a ChainReport JSON into a PDF via the bundled .typ template.
//
// Phase 4 W1.3 shipped site-only in v2.8.1. v2.8.2 extends to db + volume
// (the route handlers + builder are in rt_backup_orchestrator.go) and adds
// SHA-256 pinning of the typst tarball — TLS + github.com is no longer the
// sole trust anchor.

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	chainReportTypstVersion       = "0.13.0"
	chainReportTypstDir           = "/var/lib/dockpanel/typst"
	chainReportTypstBin           = "/var/lib/dockpanel/typst/typst"
	chainReportInstallTimeoutSecs = 120
	chainReportCompileTimeoutSecs = 30

	// Pinned tarball SHA-256s for typst v0.13.0 (verified against
	// github.com/typst/typst/releases/download/v0.13.0/, 2026-04-30).
	// If chainReportTypstVersion is bumped, regenerate these.
	chainReportTypstSHA256X8664Musl   = "cd1148da61d6844e62c330fc6222e988480acafe33b76daec8eb5d221258feb6"
	chainReportTypstSHA256Aarch64Musl = "1a1b3841ee1d84d130c4fd58f1ac8a23acf0d6bf11161c5246f016622cf046e6"
)

// Embedded so the binary is self-contained; written to a tempfile per render.
// A byte-identical copy of panel/backend/templates/chain-report.typ.
//
//go:embed templates/chain-report.typ
var chainReportTemplateTyp string

var chainReportInstallLock sync.Mutex

func chainReportExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// chainReportArch maps GOARCH to the Rust std::env::consts::ARCH spelling
// used in the typst release names.
func chainReportArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	return runtime.GOARCH
}

// ChainReportEnsureTypstInstalled ensures the typst binary is installed on
// the panel host. First call fetches + extracts; subsequent calls are no-ops.
// Returns the binary path.
func ChainReportEnsureTypstInstalled(ctx context.Context) (string, error) {
	bin := chainReportTypstBin
	if chainReportExists(bin) {
		return bin, nil
	}

	chainReportInstallLock.Lock()
	defer chainReportInstallLock.Unlock()
	// Re-check after acquiring lock — another caller may have installed.
	if chainReportExists(bin) {
		return bin, nil
	}

	if err := os.MkdirAll(chainReportTypstDir, 0o755); err != nil {
		return "", fmt.Errorf("create typst dir: %v", err)
	}

	var arch, expectedSHA string
	switch a := chainReportArch(); a {
	case "x86_64":
		arch, expectedSHA = "x86_64", chainReportTypstSHA256X8664Musl
	case "aarch64":
		arch, expectedSHA = "aarch64", chainReportTypstSHA256Aarch64Musl
	default:
		return "", fmt.Errorf("unsupported arch for typst: %s", a)
	}

	// Allow operators to override the pinned digest if they're using a
	// different typst version (e.g. air-gapped mirror). Same env per arch.
	if v, ok := os.LookupEnv("DOCKPANEL_TYPST_SHA256_" + strings.ToUpper(arch)); ok {
		expectedSHA = v
	}

	target := arch + "-unknown-linux-musl"
	url := fmt.Sprintf("https://github.com/typst/typst/releases/download/v%s/typst-%s.tar.xz", chainReportTypstVersion, target)

	// Two-phase install: download to tempfile → verify sha256 → extract.
	// Adds ~30MB temp + a second pass over the bytes; runs once per host.
	// Refusing to extract a tarball whose checksum doesn't match the pin is
	// the whole point — never let `tar` see unverified bytes.
	cmd := fmt.Sprintf("set -euo pipefail; "+
		"tmp=$(mktemp '%[1]s/typst-download.XXXXXX.tar.xz'); "+
		"trap 'rm -f \"$tmp\"' EXIT; "+
		"curl -sSfL --max-time 90 -o \"$tmp\" '%[2]s'; "+
		"actual=$(sha256sum \"$tmp\" | awk '{print $1}'); "+
		"if [ \"$actual\" != '%[3]s' ]; then "+
		"echo \"typst sha256 mismatch: expected %[3]s, got $actual\" >&2; "+
		"exit 99; "+
		"fi; "+
		"tar -xJf \"$tmp\" -C '%[1]s' --strip-components=1 'typst-%[4]s/typst'; "+
		"chmod 755 '%[5]s'",
		chainReportTypstDir, url, expectedSHA, target, chainReportTypstBin)

	tctx, cancel := context.WithTimeout(ctx, chainReportInstallTimeoutSecs*time.Second)
	defer cancel()
	c := safeCommand(tctx, "bash", "-c", cmd)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	err := c.Run()
	if tctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("typst install timed out after %ds", chainReportInstallTimeoutSecs)
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return "", fmt.Errorf("typst install spawn failed: %v", err)
	}
	if err != nil {
		// Surface the sha256 mismatch separately so it doesn't get buried.
		if exitErr.ExitCode() == 99 {
			return "", fmt.Errorf("typst install aborted on sha256 mismatch: %s", strings.ToValidUTF8(stderr.String(), "�"))
		}
		return "", fmt.Errorf("typst install failed: %s", strings.ToValidUTF8(stderr.String(), "�"))
	}

	if !chainReportExists(bin) {
		return "", errors.New("typst install completed but binary missing")
	}

	slog.Info(fmt.Sprintf("typst v%s installed at %s", chainReportTypstVersion, chainReportTypstBin))
	return bin, nil
}

// ChainReportRenderChainReportPdf renders a ChainReport JSON value into PDF
// bytes via typst. Caller is responsible for ensuring data is a valid JSON
// shape consumed by templates/chain-report.typ (see the ChainReport type in
// rt_backup_orchestrator.go).
func ChainReportRenderChainReportPdf(ctx context.Context, data any) ([]byte, error) {
	typstBin, err := ChainReportEnsureTypstInstalled(ctx)
	if err != nil {
		return nil, err
	}

	// Use a per-render tempdir to avoid contention. /tmp is fine — files are
	// small (JSON < 100KB, PDF < 1MB) and cleaned at the end of this fn.
	dir := fmt.Sprintf("/tmp/dockpanel-chainreport-%s", uuid.New())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("tempdir create: %v", err)
	}

	pdf, err := chainReportRenderInner(ctx, typstBin, dir, data)

	// Best-effort cleanup; never block the response on it.
	_ = os.RemoveAll(dir)

	return pdf, err
}

func chainReportRenderInner(ctx context.Context, typstBin, dir string, data any) ([]byte, error) {
	jsonPath := filepath.Join(dir, "data.json")
	typPath := filepath.Join(dir, "chain-report.typ")
	pdfPath := filepath.Join(dir, "out.pdf")

	// serde_json::to_vec_pretty: two-space indent, no HTML escaping.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return nil, fmt.Errorf("serialize chain report: %v", err)
	}
	if err := os.WriteFile(jsonPath, bytes.TrimSuffix(buf.Bytes(), []byte("\n")), 0o644); err != nil {
		return nil, fmt.Errorf("write json: %v", err)
	}
	if err := os.WriteFile(typPath, []byte(chainReportTemplateTyp), 0o644); err != nil {
		return nil, fmt.Errorf("write template: %v", err)
	}

	// typst's --root jails file access to that dir AND treats absolute paths
	// inside the template as relative to it. Pass the JSON path as relative.
	tctx, cancel := context.WithTimeout(ctx, chainReportCompileTimeoutSecs*time.Second)
	defer cancel()
	c := safeCommand(tctx, typstBin, "compile", "--root", dir, "--input", "data_path=data.json", typPath, pdfPath)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	err := c.Run()
	if tctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("typst compile timed out after %ds", chainReportCompileTimeoutSecs)
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return nil, fmt.Errorf("typst compile spawn failed: %v", err)
	}
	if err != nil {
		return nil, fmt.Errorf("typst compile failed: %s", strings.ToValidUTF8(stderr.String(), "�"))
	}

	pdf, err := os.ReadFile(pdfPath)
	if err != nil {
		return nil, fmt.Errorf("read generated pdf: %v", err)
	}
	if len(pdf) < 4 || string(pdf[:4]) != "%PDF" {
		return nil, errors.New("typst produced non-PDF output")
	}
	return pdf, nil
}
