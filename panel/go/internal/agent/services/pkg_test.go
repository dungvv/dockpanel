package services

import (
	"slices"
	"testing"
)

func TestPkgMapsTheNamesThatActuallyDiffer(t *testing.T) {
	for in, want := range map[string]string{
		"pdns-server":         "pdns",
		"redis-server":        "redis",
		"dovecot-imapd":       "dovecot",
		"dovecot-lmtpd":       "dovecot",
		"unattended-upgrades": "dnf-automatic",
		"libmodsecurity3t64":  "nginx-mod-modsecurity",
	} {
		if got := pkgRpmName(in); got != want {
			t.Errorf("pkgRpmName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPkgCollapsesEveryPhpFpmVersionToTheSingleRpmPackage(t *testing.T) {
	for _, v := range []string{"8.1", "8.2", "8.3", "8.4", "8.5"} {
		if got := pkgRpmName("php" + v + "-fpm"); got != "php-fpm" {
			t.Errorf("php%s-fpm -> %q", v, got)
		}
	}
	if got := pkgRpmName("php-fpm"); got != "php-fpm" {
		t.Errorf("php-fpm -> %q", got)
	}
}

func TestPkgLeavesSharedNamesAlone(t *testing.T) {
	for _, p := range []string{"postfix", "fail2ban", "opendkim", "certbot", "nginx", "nodejs"} {
		if got := pkgRpmName(p); got != p {
			t.Errorf("%q -> %q", p, got)
		}
	}
}

// Both PowerDNS backends were passed through untranslated before s266.
func TestPkgMapsBothPowerdnsBackends(t *testing.T) {
	if got := pkgRpmName("pdns-backend-pgsql"); got != "pdns-backend-postgresql" {
		t.Error(got)
	}
	if got := pkgRpmName("pdns-backend-sqlite3"); got != "pdns-backend-sqlite" {
		t.Error(got)
	}
}

// The WAF installer passes two package names; only one of them was mapped.
func TestPkgMapsEverySpellingOfTheNginxModsecurityModule(t *testing.T) {
	for _, p := range []string{"libmodsecurity3", "libmodsecurity3t64", "libnginx-mod-http-modsecurity"} {
		if got := pkgRpmName(p); got != "nginx-mod-modsecurity" {
			t.Errorf("%q -> %q", p, got)
		}
	}
}

// Translating package names and not unit names installs the right package
// and then enables a unit that is not there.
func TestPkgTranslatesUnitNamesNotJustPackageNames(t *testing.T) {
	if got := pkgRpmServiceName("redis-server"); got != "redis" {
		t.Error(got)
	}
	for _, v := range []string{"8.1", "8.2", "8.3", "8.4", "8.5"} {
		if got := pkgRpmServiceName("php" + v + "-fpm"); got != "php-fpm" {
			t.Errorf("php%s-fpm -> %q", v, got)
		}
	}
}

// A unit whose name is the same on both families must survive unchanged.
func TestPkgLeavesUnitsThatMatchAlone(t *testing.T) {
	for _, u := range []string{"nginx", "fail2ban", "postfix", "dovecot", "opendkim", "docker"} {
		if got := pkgRpmServiceName(u); got != u {
			t.Errorf("%q -> %q", u, got)
		}
	}
}

// The PACKAGE differs across families while the UNIT is `pdns` on both: one
// shared translation cannot express that.
func TestPkgPowerdnsPackageDiffersWhileItsUnitDoesNot(t *testing.T) {
	if got := pkgRpmName("pdns-server"); got != "pdns" {
		t.Error(got)
	}
	if got := pkgRpmServiceName("pdns-server"); got != "pdns-server" {
		t.Error(got)
	}
	if got := pkgRpmServiceName("pdns"); got != "pdns" {
		t.Error(got)
	}
}

// Pinning the maps together stops a future edit "simplifying" one into the other.
func TestPkgTheTwoMapsAreNotInterchangeable(t *testing.T) {
	if pkgRpmName("php8.3-fpm") != "php-fpm" || pkgRpmServiceName("php8.3-fpm") != "php-fpm" {
		t.Error("php8.3-fpm")
	}
	if pkgRpmName("pdns-backend-sqlite3") != "pdns-backend-sqlite" {
		t.Error("package map")
	}
	if pkgRpmServiceName("pdns-backend-sqlite3") != "pdns-backend-sqlite3" {
		t.Error("unit map")
	}
}

// An unmapped mysql ships a PHP with no MySQL driver and no complaint.
func TestPkgMapsThePhpExtensionsWhoseNamesActuallyDiffer(t *testing.T) {
	for in, want := range map[string]string{
		"php8.3-mysql":   "php-mysqlnd",
		"php8.3-zip":     "php-pecl-zip",
		"php8.3-pgsql":   "php-pgsql",
		"php8.3-opcache": "php-opcache",
	} {
		if got := pkgRpmName(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

// A package that is not PHP-shaped must not be mangled by the PHP branch.
func TestPkgThePhpBranchDoesNotCaptureUnrelatedPackages(t *testing.T) {
	for _, p := range []string{"phpmyadmin", "php", "postfix-policyd", "python3-venv"} {
		if got := pkgRpmName(p); got != p {
			t.Errorf("%q should pass through untouched, got %q", p, got)
		}
	}
}

// NodeSource's setup_22.x writes a keyring and two Pin-Priority:600 files
// besides the .sources file — all must be on the cleanup list.
func TestPkgNodesourceCleanupCoversTheKeyringAndBothPinFiles(t *testing.T) {
	paths := pkgRepoArtifactPaths(PkgRepoNodeSource)
	for _, must := range []string{
		"/etc/apt/sources.list.d/nodesource.sources",
		"/usr/share/keyrings/nodesource.gpg",
		"/etc/apt/preferences.d/nodejs",
		"/etc/apt/preferences.d/nsolid",
		"/etc/yum.repos.d/nodesource-nodejs.repo",
		"/etc/yum.repos.d/nodesource-nsolid.repo",
	} {
		if !slices.Contains(paths, must) {
			t.Errorf("NodeSource cleanup list is missing %s", must)
		}
	}
}

// A box that added the repo under an older script still has the .list file.
func TestPkgNodesourceCleanupStillCoversTheLegacyListFilename(t *testing.T) {
	if !slices.Contains(pkgRepoArtifactPaths(PkgRepoNodeSource), "/etc/apt/sources.list.d/nodesource.list") {
		t.Error("legacy nodesource.list missing")
	}
}

func TestPkgCloudflaredCleanupCoversTheKeyringNotJustTheRepoFile(t *testing.T) {
	paths := pkgRepoArtifactPaths(PkgRepoCloudflared)
	for _, must := range []string{
		"/usr/share/keyrings/cloudflare-main.gpg",
		"/etc/apt/sources.list.d/cloudflared.list",
		"/etc/yum.repos.d/cloudflared.repo",
	} {
		if !slices.Contains(paths, must) {
			t.Errorf("missing %s", must)
		}
	}
}

// Rspamd's footprint is exactly one flat repo file.
func TestPkgRspamdCleanupIsExactlyTheOneRepoFile(t *testing.T) {
	if got := pkgRepoArtifactPaths(PkgRepoRspamd); !slices.Equal(got, []string{"/etc/yum.repos.d/rspamd.repo"}) {
		t.Errorf("got %v", got)
	}
}
