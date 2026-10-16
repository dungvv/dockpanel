package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func find(t *testing.T, path ...string) *cobra.Command {
	t.Helper()
	c, _, err := buildRoot("test").Find(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHelpTextMatchesClap(t *testing.T) {
	got := helpText(find(t, "apps", "deploy"), false)
	want := `Deploy an app from a template

Usage: dockpanel apps deploy [OPTIONS] --name <NAME> --port <PORT> <TEMPLATE>

Arguments:
  <TEMPLATE>  Template ID

Options:
      --name <NAME>            App name
  -o, --output <OUTPUT>        Output format: table (default) or json [default: table]
      --port <PORT>            Host port
      --domain <DOMAIN>        Domain for auto reverse proxy
      --ssl-email <SSL_EMAIL>  Email for Let's Encrypt SSL (requires --domain)
  -h, --help                   Print help
`
	if got != want {
		t.Errorf("help mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestRangeError(t *testing.T) {
	tests := []struct {
		in   string
		max  int64
		want string
	}{
		{"80", 65535, ""},
		{"+80", 65535, ""},
		{"65536", 65535, "65536 is not in 0..=65535"},
		{"-1", 65535, "-1 is not in 0..=65535"},
		{"abc", 65535, "invalid digit found in string"},
		{"", 65535, "cannot parse integer from empty string"},
		{"99999999999999999999", 65535, "number too large to fit in target type"},
	}
	for _, tt := range tests {
		if got := rangeError(tt.in, tt.max); got != tt.want {
			t.Errorf("rangeError(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDecodeChunked(t *testing.T) {
	got := string(decodeChunked([]byte("4\r\nWiki\r\n6\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\n\r\n")))
	if got != "Wikipedia in \r\n\r\nchunks." {
		t.Errorf("decodeChunked = %q", got)
	}
}

func TestListNginxSites(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"b.conf":               "server {\n  server_name b.com www.b.com;\n  proxy_pass http://x;\n  ssl_certificate x;\n}",
		"a.conf":               "server { listen 80; }\nserver_name a.com;\nfastcgi_pass unix:/x;",
		"dup.conf":             "server_name a.com;\nfastcgi_pass unix:/y;", // dedupe keeps one a.com; which file wins is directory order, as in Rust
		"catchall.conf":        "server_name _;",
		"default":              "server_name d.com;",
		"noname.conf.conf":     "root /var/www;",
		"dockpanel-panel.conf": "server_name panel;",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for _, s := range listNginxSites(dir) {
		got = append(got, s.Domain+"/"+s.Runtime+"/"+yesNo(s.SSL))
	}
	want := "a.com/php/no b.com/proxy/yes noname/static/no"
	if strings.Join(got, " ") != want {
		t.Errorf("sites = %v, want %s", got, want)
	}
}
