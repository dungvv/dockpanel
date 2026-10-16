package services

import "testing"

// The three parsers that decide what lands in a credential file or which
// checksum guards a download.
func TestCmsEnvWritersAndChecksumExtraction(t *testing.T) {
	// phpdotenv: `#` comments and `$` interpolates, so both must stay literal.
	if got := cmsReplaceEnvLine("APP_NAME=x\n# DB_PASSWORD=\nOTHER=1\n", "DB_PASSWORD", `p#$"\`); got != "APP_NAME=x\nDB_PASSWORD=\"p#\\$\\\"\\\\\"\nOTHER=1\n" {
		t.Errorf("laravel: %q", got)
	}
	if got := cmsReplaceEnvLine("A=1", "B", "2"); got != "A=1\nB=\"2\"" {
		t.Errorf("laravel append: %q", got)
	}
	// CI4: uncomments, leaves `$` bare, does not match a longer key.
	in := "# database.default.hostname = localhost\ndatabase.default.hostnameX = keep\n"
	if got := cmsSetCiEnv(in, "database.default.hostname", "db$1"); got != "database.default.hostname = \"db$1\"\ndatabase.default.hostnameX = keep\n" {
		t.Errorf("ci4: %q", got)
	}
	sha := "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	body := "| Update | x.zip | `" + "deadbeef" + "` |\n| Full | Joomla_5.1.0-Stable-Full_Package.zip | `" + sha + "` |\n"
	if got, ok := cmsExtractReleaseSha256(body, "Joomla_5.1.0-Stable-Full_Package.zip"); !ok || got != "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" {
		t.Errorf("sha: %q %v", got, ok)
	}
	// The hash must be on the filename's own line.
	if _, ok := cmsExtractReleaseSha256("Joomla_X.zip\n`"+sha+"`", "Joomla_X.zip"); ok {
		t.Error("matched a hash on another line")
	}
	if h, p := cmsSplitHostPort("db.local:3307"); h != "db.local" || p != "3307" {
		t.Error("split")
	}
}
