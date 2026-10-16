package services

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityScannerParseGrepMatchExtractsPathAndLine(t *testing.T) {
	for _, c := range []struct {
		in   string
		path string
		n    uint32
		ok   bool
	}{
		{`/var/www/a.php:42:$key = "AKIA...";`, "/var/www/a.php", 42, true},
		// content may contain colons
		{`/var/www/b.js:7:const u = "redis://x:y@h";`, "/var/www/b.js", 7, true},
		{"no separator here", "", 0, false},
		{"/path/no/lineno:notdigits:x", "", 0, false},
		// REDACTION REGRESSION: an overflowing line number must saturate and
		// stop, never walk into CONTENT and pull the secret into the path.
		{`/var/www/a.php:4294967296:$k="AKIA1234567890ABCDEF":1:x`, "/var/www/a.php", math.MaxUint32, true},
		// a colon INSIDE the path
		{"/var/www/od:d.php:12:secret", "/var/www/od:d.php", 12, true},
	} {
		p, n, ok := securityScannerParseGrepMatch(c.in)
		if p != c.path || n != c.n || ok != c.ok {
			t.Errorf("%q: got %q %d %v", c.in, p, n, ok)
		}
		if strings.Contains(p, "AKIA") {
			t.Errorf("secret leaked into path: %q", p)
		}
	}
}

func TestSecurityScannerScanSecretsFlagsAndRedacts(t *testing.T) {
	const awsID, pwVal = "AKIA1234567890ABCDEF", "Sup3rSecretValue123"
	site := filepath.Join(t.TempDir(), "site")
	nm := filepath.Join(site, "node_modules", "pkg")
	if err := os.MkdirAll(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(site, "app.php"), []byte("<?php\n$aws = \""+awsID+"\";\n$config = ['password' => '"+pwVal+
		"'];\n$dsn = \"mysql://appuser:"+pwVal+"@db.example.com/app\";\n// -----BEGIN RSA PRIVATE KEY-----\n"), 0o644)
	// .env is the CORRECT home for a secret — must NOT be scanned.
	os.WriteFile(filepath.Join(site, ".env"), []byte("AWS_KEY="+awsID+"\n"), 0o644)
	// third-party code — skipped by --exclude-dir
	os.WriteFile(filepath.Join(nm, "evil.php"), []byte(`<?php $k="`+awsID+`";`), 0o644)

	findings := securityScannerScanSecretsIn([]string{site})
	if len(findings) == 0 {
		t.Fatal("expected secret findings, got none")
	}
	for _, f := range findings {
		if f.CheckType != "secret_leak" || f.FilePath == nil || !strings.HasSuffix(*f.FilePath, "app.php") {
			t.Errorf(".env and node_modules must not be scanned: %+v", f)
		}
		for _, s := range []string{f.Title, f.Description, *f.FilePath} {
			if strings.Contains(s, awsID) || strings.Contains(s, pwVal) {
				t.Errorf("secret value leaked: %q", s)
			}
		}
	}
	for _, want := range []string{"AWS access key ID", "hardcoded credential assignment", "database URI with embedded password", "private key (PEM)"} {
		found := false
		for _, f := range findings {
			found = found || strings.Contains(f.Title, want)
		}
		if !found {
			t.Errorf("missing finding: %s", want)
		}
	}
}

func TestSecurityScannerParseOpenPorts(t *testing.T) {
	f := securityScannerParseOpenPorts([]string{
		"State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
		`LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`,
		`LISTEN 0 128 127.0.0.1:6379 0.0.0.0:* users:(("redis",pid=2,fd=3))`,
		`LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("docker-proxy",pid=3,fd=3))`,
		`LISTEN 0 128 [::]:9090 [::]:* users:(("prometheus",pid=4,fd=3))`,
		`LISTEN 0 128 0.0.0.0:9090 0.0.0.0:* users:(("prometheus",pid=4,fd=4))`,
		`LISTEN 0 128 0.0.0.0:40000 0.0.0.0:* users:(("x",pid=5,fd=3))`,
	})
	if len(f) != 1 || f[0].Title != "Unexpected open port: 9090" || f[0].FilePath != nil {
		t.Fatalf("%+v", f)
	}
}

func TestSecurityScannerGrypeFinding(t *testing.T) {
	f, ok := securityScannerGrypeFinding("img", []byte(`{"matches":[{"vulnerability":{"severity":"High"}},{"vulnerability":{"severity":"Low"}},{"vulnerability":"x"}]}`))
	if !ok || f.Severity != "warning" || f.Title != "Image img: 3 vulnerabilities (0 critical, 1 high)" {
		t.Fatalf("%+v", f)
	}
	if _, ok := securityScannerGrypeFinding("img", []byte(`{"matches":[]}`)); ok {
		t.Fatal("no vulns must yield no finding")
	}
	if _, ok := securityScannerGrypeFinding("img", []byte(`not json`)); ok {
		t.Fatal("garbage must yield no finding")
	}
}
