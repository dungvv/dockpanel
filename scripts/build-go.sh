#!/usr/bin/env bash
#
# Build the Go binaries (agent, CLI, MCP server) from panel/go.
#
#   bash scripts/build-go.sh <out-dir> [goarch]
#
# Produces <out-dir>/{dockpanel-agent,dockpanel,dockpanel-mcp}, statically linked
# for linux/<goarch> (default: the host arch). The version stamp comes from
# panel/backend/Cargo.toml, the release's single version source.
#
# When no `go` is on PATH and we run as root, the official toolchain is
# installed to /usr/local/go after verifying Google's published sha256 — the
# same "install the toolchain if missing" contract setup.sh has for rustup.
# An older go (>=1.21) on PATH is fine: GOTOOLCHAIN=auto fetches what go.mod
# needs.

set -euo pipefail

GO_VERSION="1.27.0"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:?usage: build-go.sh <out-dir> [goarch]}"
GOARCH_TARGET="${2:-}"

host_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *) echo "unsupported architecture: $(uname -m)" >&2; return 1 ;;
    esac
}

ensure_go() {
    if command -v go >/dev/null 2>&1; then GO=go; return; fi
    if [ -x /usr/local/go/bin/go ]; then GO=/usr/local/go/bin/go; return; fi
    if [ "$(id -u)" != "0" ]; then
        echo "Go toolchain not found. Install Go >= 1.21 (https://go.dev/dl/) and re-run." >&2
        exit 1
    fi
    local arch tarball tmp
    arch="$(host_arch)"
    tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
    tmp="$(mktemp -d)"
    echo "Installing Go ${GO_VERSION} to /usr/local/go..." >&2
    curl --proto '=https' --tlsv1.2 -fsSL "https://dl.google.com/go/${tarball}" -o "$tmp/$tarball"
    local want got
    want="$(curl --proto '=https' --tlsv1.2 -fsSL "https://dl.google.com/go/${tarball}.sha256")"
    got="$(sha256sum "$tmp/$tarball" | cut -d' ' -f1)"
    if [ -z "$want" ] || [ "$want" != "$got" ]; then
        rm -rf "$tmp"
        echo "Go tarball checksum mismatch (want '$want', got '$got') — refusing to install." >&2
        exit 1
    fi
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tmp/$tarball"
    rm -rf "$tmp"
    GO=/usr/local/go/bin/go
}

ensure_go
VERSION="$(grep '^version' "$REPO_DIR/panel/backend/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

cd "$REPO_DIR/panel/go"
export CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH_TARGET:-$(host_arch)}" GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
AGENT_VERSION_VAR="github.com/ovexro/dockpanel/panel/go/internal/agent/services.AgentVersion"
for bin in dockpanel-agent dockpanel dockpanel-mcp; do
    "$GO" build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X ${AGENT_VERSION_VAR}=${VERSION}" -o "$OUT_DIR/$bin" "./cmd/$bin"
done
echo "Built dockpanel-agent + dockpanel + dockpanel-mcp ${VERSION} (linux/${GOARCH}) into ${OUT_DIR}" >&2
