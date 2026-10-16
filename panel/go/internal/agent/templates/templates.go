// Package templates embeds byte-identical copies of panel/agent/src/templates.
// Edit them only together with the Rust originals (a test compares the two
// while the Rust tree exists).
package templates

import "embed"

// FS holds nginx/{http,https,proxy}.conf.
//
//go:embed nginx/*.conf
var FS embed.FS
