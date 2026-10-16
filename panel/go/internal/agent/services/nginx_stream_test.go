package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlainRenderHasListenProxyPassAndTimeouts(t *testing.T) {
	b := NginxStreamRenderServer(40001, "127.0.0.1:5450", nil, nil)
	for _, w := range []string{"listen 40001;", "proxy_pass 127.0.0.1:5450;", "proxy_connect_timeout", "proxy_timeout"} {
		if !strings.Contains(b, w) {
			t.Error(w)
		}
	}
	if strings.Contains(b, "ssl") || strings.Contains(b, "deny") {
		t.Error("plain proxy must not claim TLS or deny")
	}
}

func TestAllowListRendersAllowLinesThenDenyAll(t *testing.T) {
	b := NginxStreamRenderServer(40003, "127.0.0.1:5432", nil, []string{"203.0.113.0/24", "2001:db8::1"})
	a, d := strings.Index(b, "allow 203.0.113.0/24;"), strings.Index(b, "deny all;")
	if a < 0 || d < 0 || a > d || !strings.Contains(b, "allow 2001:db8::1;") {
		t.Fatal(b)
	}
}

func TestAllowEntriesAreReparsedNotEchoed(t *testing.T) {
	if v, _ := NginxStreamNormalizeAllowEntry(" 10.0.0.0/8 "); v != "10.0.0.0/8" {
		t.Error(v)
	}
	if v, _ := NginxStreamNormalizeAllowEntry("::1"); v != "::1" {
		t.Error(v)
	}
	for _, bad := range []string{"", "all", "10.0.0.0/33", "::/129", "1.2.3.4; deny", "1.2.3.4/x", "a/8", "fe80::1%eth0"} {
		if _, err := NginxStreamNormalizeAllowEntry(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestTlsRenderAddsSslListenAndRegistryPaths(t *testing.T) {
	b := NginxStreamRenderServer(40002, "127.0.0.1:3306", &NginxStreamTlsPaths{
		Cert: "/etc/dockpanel/ssl/registry/x/fullchain.pem", Key: "/etc/dockpanel/ssl/registry/x/privkey.pem"}, nil)
	for _, w := range []string{"listen 40002 ssl;", "ssl_certificate /etc/dockpanel/ssl/registry/x/fullchain.pem;", "ssl_certificate_key /etc/dockpanel/ssl/registry/x/privkey.pem;"} {
		if !strings.Contains(b, w) {
			t.Error(w)
		}
	}
}

func TestProxyNamesThatEscapeTheDirectoryAreRejected(t *testing.T) {
	for _, ok := range []string{"db-main", "a"} {
		if NginxStreamValidateProxyName(ok) != nil {
			t.Error(ok)
		}
	}
	for _, bad := range []string{"../evil", "a b", "Name", "x;y", "-lead", "trail-", "", "a/b", strings.Repeat("a", 49)} {
		if NginxStreamValidateProxyName(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestListenPortsStayInsideTheManagedRange(t *testing.T) {
	if NginxStreamValidateListenPort(NginxStreamListenPortMin) != nil || NginxStreamValidateListenPort(NginxStreamListenPortMax) != nil {
		t.Fatal()
	}
	for _, p := range []uint16{0, 80, 443, 3080, NginxStreamListenPortMin - 1, NginxStreamListenPortMax + 1} {
		if NginxStreamValidateListenPort(p) == nil {
			t.Errorf("accepted %d", p)
		}
	}
}

func TestUpstreamHostsAreStrictlyValidated(t *testing.T) {
	for in, want := range map[string]string{"127.0.0.1": "127.0.0.1", "[::1]": "[::1]", "db.internal": "db.internal"} {
		if got, err := NginxStreamNormalizeUpstreamHost(in); err != nil || got != want {
			t.Errorf("%s -> %s %v", in, got, err)
		}
	}
	for _, bad := range []string{"", " ", "a; rm -rf", "a b", "-x", ".x", "x.", "a..b", "[::1", "999.1.1.1", "::1", "[fe80::1%eth0]"} {
		if _, err := NginxStreamNormalizeUpstreamHost(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if v, _ := NginxStreamNormalizeUpstream("[::1]", 5432); v != "[::1]:5432" {
		t.Error(v)
	}
	if _, err := NginxStreamNormalizeUpstream("127.0.0.1", 0); err == nil {
		t.Error("port 0 accepted")
	}
}

func TestStreamAvailableReadsTheNginxConfSentinel(t *testing.T) {
	dir := t.TempDir()
	with, without := filepath.Join(dir, "with.conf"), filepath.Join(dir, "without.conf")
	os.WriteFile(with, []byte("stream { include /etc/nginx/dockpanel-streams/*.conf; }\nhttp {}\n"), 0o644)
	os.WriteFile(without, []byte("events {} http {}\n"), 0o644)
	if !NginxStreamAvailableAt(with) || NginxStreamAvailableAt(without) || NginxStreamAvailableAt(filepath.Join(dir, "absent.conf")) {
		t.Fatal()
	}
}
