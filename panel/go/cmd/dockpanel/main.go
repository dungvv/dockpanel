// Command dockpanel is the DockPanel CLI — self-hosted server management.
package main

import (
	"os"

	"github.com/ovexro/dockpanel/panel/go/internal/cli"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "2.242.1"

func main() {
	os.Exit(cli.Run(version, os.Args[1:]))
}
