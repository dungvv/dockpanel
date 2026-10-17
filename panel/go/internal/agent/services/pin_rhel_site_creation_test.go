package services

import "testing"

// rhel-site-creation pin (§6): one function knows both families' vhost dirs.
func TestPinRhelSiteCreationSitesDirFor(t *testing.T) {
	if NginxSitesDirFor(true) != "/etc/nginx/sites-enabled" || NginxSitesDirFor(false) != "/etc/nginx/conf.d" {
		t.Fatal(NginxSitesDirFor(true), NginxSitesDirFor(false))
	}
}

// rhel-site-creation pin (§8): RHEL parks in the SAME directory it serves from.
func TestPinRhelSiteCreationParkedDirSharesConfD(t *testing.T) {
	if NginxParkedDirFor(false) != NginxSitesDirFor(false) {
		t.Fatal(NginxParkedDirFor(false))
	}
	if NginxParkedDirFor(true) != "/etc/nginx/sites-available" {
		t.Fatal(NginxParkedDirFor(true))
	}
}

// rhel-site-creation pin (§3): with no Debian pool.d tree (RHEL) the per-site
// pool write degrades to a no-op instead of erroring the site creation.
func TestPinRhelSiteCreationPoolConfigNoopsWithoutPoolD(t *testing.T) {
	if err := NginxWritePhpPoolConfig("a.example", "0.0-pin-absent", 256, 5, nil); err != nil {
		t.Fatal(err)
	}
}
