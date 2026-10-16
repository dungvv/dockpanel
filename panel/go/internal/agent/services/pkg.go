// Package facts that hold on both package-manager families.
//
// DockPanel supports Debian/Ubuntu AND the RHEL family (Rocky, AlmaLinux,
// CentOS Stream, Fedora), but every package query in the agent used to be
// `dpkg`. On an RPM box there is no `dpkg` at all, so those queries did not
// merely return the wrong answer — they returned false for everything, and
// the Services page reported PHP and Fail2Ban as "not installed" while both
// were installed and running (s265).
//
// There were several hand-rolled copies of is_installed. This module exists
// so there is ONE of them: a fifth copy is how the fourth one got missed.
//
// Package names differ too, so a manager swap alone is not enough —
// `pdns-server` is `pdns`, `redis-server` is `redis`, and the three Debian
// Dovecot packages are one `dovecot`. Callers keep passing the Debian name
// (which is what the installers use) and PkgIsInstalled translates.
//
// Rust Option<String> results are returned as a plain string, "" meaning None.

package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

// pkgInstallTimeout is how long any single package transaction may run.
// Matches the timeout every installer used before this module existed.
const pkgInstallTimeout = 300 * time.Second

// PkgMgr is which package database this box actually has.
type PkgMgr int

const (
	PkgMgrDpkg PkgMgr = iota
	PkgMgrRpm
	// PkgMgrUnknown: neither binary is present. Every query answers false —
	// the same thing the old dpkg-only code did, but now a stated outcome
	// rather than an accident of which distro we happened to be on.
	PkgMgrUnknown
)

// PkgInstaller is the binary that CHANGES the system, which is not the one
// that ANSWERS QUESTIONS about it: `rpm` reads the database, `dnf` (or `yum`
// on an older box) performs the transaction. Keeping the two separate lets a
// box with `rpm` but no `dnf` report packages honestly and still refuse to
// install. PkgInstallerNone is Rust's `None`.
type PkgInstaller int

const (
	PkgInstallerNone PkgInstaller = iota
	PkgInstallerAptGet
	PkgInstallerDnf
	PkgInstallerYum
)

// Bin is the installer's executable name ("" for PkgInstallerNone).
func (i PkgInstaller) Bin() string {
	switch i {
	case PkgInstallerAptGet:
		return "apt-get"
	case PkgInstallerDnf:
		return "dnf"
	case PkgInstallerYum:
		return "yum"
	}
	return ""
}

func (i PkgInstaller) isApt() bool { return i == PkgInstallerAptGet }

var (
	pkgMgrOnce       sync.Once
	pkgMgr           PkgMgr
	pkgInstallerOnce sync.Once
	pkgInstaller     PkgInstaller
	pkgHatchOnce     sync.Once
	pkgHatchOK       bool
)

// PkgManager is detected once per process: the package database does not
// change under a running agent, and every status endpoint calls this.
func PkgManager() PkgMgr {
	pkgMgrOnce.Do(func() {
		switch {
		case pkgWhich("dpkg-query") || pkgWhich("dpkg"):
			pkgMgr = PkgMgrDpkg
		case pkgWhich("rpm"):
			pkgMgr = PkgMgrRpm
		default:
			pkgMgr = PkgMgrUnknown
		}
	})
	return pkgMgr
}

// PkgGetInstaller returns which binary performs transactions here, or
// PkgInstallerNone when nothing can. (Rust: pkg::installer(); renamed because
// the type already owns the name PkgInstaller.)
func PkgGetInstaller() PkgInstaller {
	pkgInstallerOnce.Do(func() {
		// Order matters on the RHEL family: modern boxes carry `yum` as a
		// symlink to `dnf`, so probing dnf first names what is really running
		// instead of its compatibility alias.
		switch {
		case pkgWhich("apt-get"):
			pkgInstaller = PkgInstallerAptGet
		case pkgWhich("dnf"):
			pkgInstaller = PkgInstallerDnf
		case pkgWhich("yum"):
			pkgInstaller = PkgInstallerYum
		default:
			pkgInstaller = PkgInstallerNone
		}
	})
	return pkgInstaller
}

// pkgRpmName is the RPM name for a package the Debian-side code asks about.
//
// Every entry was verified against a real dnf/rpm database on Rocky 9 with
// EPEL enabled (s265, s266) — not inferred from the Debian name. Anything
// absent falls through unchanged, which is right for the many packages that
// share a name (postfix, fail2ban, opendkim, certbot, nginx, nodejs).
func pkgRpmName(debian string) string {
	switch debian {
	case "pdns-server":
		return "pdns"
	// Debian names the backends after the library version; the RHEL family
	// after the database. Unmapped before s266, so the PowerDNS installer
	// would have failed on its very first argument.
	case "pdns-backend-pgsql":
		return "pdns-backend-postgresql"
	case "pdns-backend-sqlite3":
		return "pdns-backend-sqlite"
	case "redis-server":
		return "redis"
	// Debian splits Dovecot per protocol; the RHEL family ships one package.
	case "dovecot-imapd", "dovecot-pop3d", "dovecot-lmtpd":
		return "dovecot"
	// Debian's periodic-upgrade package; dnf's equivalent timer service.
	case "unattended-upgrades":
		return "dnf-automatic"
	// The nginx ModSecurity connector, not the bare library. Debian splits
	// the library from the nginx module and needs both; the RHEL family ships
	// one package pulling the library in, so all three Debian spellings
	// collapse onto it. `libnginx-mod-http-modsecurity` was the half s265's
	// map missed.
	case "libmodsecurity3", "libmodsecurity3t64", "libnginx-mod-http-modsecurity":
		return "nginx-mod-modsecurity"
	}
	return pkgPhpRpmName(debian)
}

// pkgPhpRpmName translates a versioned Debian PHP package (php8.3-fpm,
// php8.3-mysql) to its RHEL spelling.
//
// Debian carries one package per PHP version; the RHEL family has a single
// unversioned set whose version comes from the enabled module stream, so the
// version is dropped here and selected by PkgEnablePhpStream instead.
//
// Two extension names genuinely differ (verified by loading them, s266):
//   - `mysql` is `mysqlnd` — without this a PHP install on RHEL would come up
//     with NO MySQL driver at all, silently, since the extension loop
//     tolerates absences.
//   - `zip` lives in `php-pecl-zip`, outside the main set.
//
// `curl` and `sqlite3` map to php-<name> packages that do not exist —
// deliberately, because php-common provides them. The candidate probe in
// PkgInstallAvailable skips them, which is the correct outcome.
func pkgPhpRpmName(debian string) string {
	rest, ok := strings.CutPrefix(debian, "php")
	if !ok {
		return debian
	}
	ver, ext, ok := strings.Cut(rest, "-")
	if !ok || strings.Trim(ver, "0123456789.") != "" {
		return debian
	}
	switch ext {
	case "fpm", "cli", "pgsql", "gd", "mbstring", "xml", "bcmath", "intl",
		"opcache", "readline", "curl", "sqlite3":
		return "php-" + ext
	case "mysql":
		return "php-mysqlnd"
	case "zip":
		return "php-pecl-zip"
	}
	return debian
}

// PkgEnablePhpStream selects the PHP version on the RHEL family by enabling
// its module stream.
//
// WITHOUT THIS THE PANEL WOULD INSTALL PHP 8.0. Rocky 9's AppStream offers
// streams 8.1–8.3, but a bare `dnf install php-fpm` resolves to the
// non-modular base package — PHP 8.0.30, EOL since November 2023 — while
// PkgIsInstalled reports PHP present. Measured (s266): with the stream
// enabled the same command gives 8.3.31.
//
// Versions above 8.3 need the third-party remi repository, which is not
// wired; callers get the closest available stream and are told which.
func PkgEnablePhpStream(version string) error {
	inst := PkgGetInstaller()
	if inst == PkgInstallerNone {
		return errors.New("No supported package manager found")
	}
	if inst.isApt() {
		return nil
	}
	out, err := safecmd.NewUnsandboxed(inst.Bin()).
		Arg("-y", "module", "enable", "php:"+version).
		OutputWithTimeout(pkgInstallTimeout)
	if err != nil {
		return fmt.Errorf("Enabling the PHP module stream failed: %v", err)
	}
	if !out.Success() {
		return errors.New(pkgTruncChars(string(out.Stderr), 300))
	}
	return nil
}

// PkgInstalledPhpVersion is the major.minor PHP version actually installed,
// on a family where there is only one ("" otherwise).
//
// Needed because PkgIsInstalled deliberately collapses every php{v}-fpm onto
// the single php-fpm package — correct for "is PHP present?", a lie for
// "which versions are present?". Without this the PHP page on RHEL reports
// ALL offered versions installed while none running. Returns "" on apt
// boxes, where the per-version packages answer the question directly.
func PkgInstalledPhpVersion() string {
	if PkgManager() != PkgMgrRpm {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "rpm", "-q", "--qf", "%{VERSION}", "php-fpm")
	if err != nil || !out.Success() {
		return ""
	}
	parts := strings.Split(strings.TrimSpace(string(out.Stdout)), ".")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "." + parts[1]
}

// PkgResolvePhpFpmSocket resolves the real, currently-existing PHP-FPM
// socket for a version across both families ("" when none exists).
//
// Debian ships one socket per version at a fixed path. The RHEL family ships
// exactly one unversioned socket for whichever stream is active. Callers that
// built a nginx vhost used to assume the Debian path unconditionally, making
// PHP sites unreachable on RHEL even though PHP-FPM was running: the php
// route's own socket check knew about the split, but nginx put_site
// re-implemented a Debian-only check. This is the single source of truth.
func PkgResolvePhpFpmSocket(version string) string {
	debian := "/run/php/php" + version + "-fpm.sock"
	if pkgExists(debian) {
		return debian
	}
	if PkgInstalledPhpVersion() == version && pkgExists("/run/php-fpm/www.sock") {
		return "/run/php-fpm/www.sock"
	}
	return ""
}

func pkgExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// PkgPhpStreams lists the PHP module streams this box offers, newest first.
// Empty on apt boxes, where versions come from the archive.
func PkgPhpStreams() []string {
	inst := PkgGetInstaller()
	if inst == PkgInstallerNone || inst.isApt() {
		return []string{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, inst.Bin(), "-q", "module", "list", "php")
	if err != nil || !out.Success() {
		return []string{}
	}
	versions := []string{}
	for _, l := range strings.Split(string(out.Stdout), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "php" && f[1][0] >= '0' && f[1][0] <= '9' {
			versions = append(versions, f[1])
		}
	}
	slices.Sort(versions)
	slices.Reverse(versions)
	return slices.Compact(versions)
}

// PkgIsInstalled reports whether pkg is installed. Takes the Debian name.
//
// For callers iterating PHP versions: on RPM every php{v}-fpm maps to the one
// php-fpm, so true means "some PHP-FPM is installed", not that version.
func PkgIsInstalled(pkg string) bool {
	switch PkgManager() {
	case PkgMgrDpkg:
		// `dpkg -s` exits non-zero for a removed-not-purged package; `-l`
		// prints a line for it with an `rc` state. Requiring `ii` is what
		// distinguishes installed from residual-config.
		return pkgRunOK("dpkg", []string{"-l", pkg}, func(out string) bool { return strings.Contains(out, "ii") })
	case PkgMgrRpm:
		return pkgRunOK("rpm", []string{"-q", pkgRpmName(pkg)}, func(string) bool { return true })
	}
	return false
}

// PkgServiceName is the systemd unit name for a service the Debian-side code
// names.
//
// A package name and a unit name are different strings that coincide on
// Debian, so code translating one and not the other would install `redis`
// and then `systemctl enable redis-server` — a unit that does not exist on
// the RHEL family. Verified against Rocky 9's shipped units (s266).
func PkgServiceName(debianUnit string) string {
	if PkgManager() == PkgMgrRpm {
		return pkgRpmServiceName(debianUnit)
	}
	return debianUnit
}

// pkgRpmServiceName is the pure half of PkgServiceName, testable without a box.
func pkgRpmServiceName(debianUnit string) string {
	// NOTE: `pdns-server` is deliberately absent. It is a PACKAGE name, and
	// Debian's unit for it is already `pdns` — same as RHEL's. Callers pass
	// the DEBIAN UNIT NAME; for PowerDNS that needs no translation.
	if debianUnit == "redis-server" {
		return "redis"
	}
	// One FPM unit for the whole box, unversioned: the version comes from the
	// enabled module stream.
	if strings.HasPrefix(debianUnit, "php") && strings.HasSuffix(debianUnit, "-fpm") {
		return "php-fpm"
	}
	return debianUnit
}

// PkgAvailable reports whether pkg has an installation candidate here.
//
// Lesson #73 (apt): one uninstallable name fails the ENTIRE transaction, so a
// fixed package list is a latent all-or-nothing failure across distros. dnf
// is the same ("Unable to find a match", installs nothing — verified s266),
// so the probe has to exist on both sides.
func PkgAvailable(pkg string) bool {
	switch inst := PkgGetInstaller(); inst {
	case PkgInstallerAptGet:
		// `apt-cache show` exits 0 for an obsolete-but-stanza'd package, so
		// the Candidate line is the only trustworthy signal — and the safe
		// env forces LC_ALL=C.UTF-8, without which apt translates the label
		// and this parse silently matches nothing.
		return pkgRunOK("apt-cache", []string{"policy", pkg}, func(out string) bool {
			for _, l := range strings.Split(out, "\n") {
				if c, ok := strings.CutPrefix(strings.TrimSpace(l), "Candidate:"); ok {
					if c = strings.TrimSpace(c); c != "" && c != "(none)" {
						return true
					}
				}
			}
			return false
		})
	case PkgInstallerDnf, PkgInstallerYum:
		bin, name := inst.Bin(), pkgRpmName(pkg)
		// `list` matches package NAMES only: `php-curl` is PROVIDED BY
		// php-common, so `dnf list --available php-curl` reports nothing
		// while `dnf install php-curl` succeeds. A virtual-provide lookup is
		// the tiebreaker before declaring anything unavailable.
		yes := func(string) bool { return true }
		return pkgRunOK(bin, []string{"-q", "list", "--available", name}, yes) ||
			pkgRunOK(bin, []string{"-q", "list", "--installed", name}, yes) ||
			pkgRunOK(bin, []string{"-q", "repoquery", "--whatprovides", name}, func(out string) bool {
				return strings.TrimSpace(out) != ""
			})
	}
	return false
}

// PkgInstall installs packages, named the Debian way; every name is
// translated for the running family.
//
// Returns the transaction's own stderr on failure rather than a generic
// sentence, because "PHP install failed" without the reason is what sent
// s265 looking at the wrong layer.
func PkgInstall(packages []string) error {
	return pkgTransact(false, packages)
}

// PkgInstallAvailable installs only those packages that have a candidate
// here, and returns the skipped ones. Promoted from install_php so the RHEL
// side inherits #73's protection instead of re-learning it.
func PkgInstallAvailable(packages []string) ([]string, error) {
	var wanted []string
	skipped := []string{}
	for _, p := range packages {
		if PkgAvailable(p) {
			wanted = append(wanted, p)
		} else {
			skipped = append(skipped, p)
		}
	}
	if len(wanted) > 0 {
		if err := PkgInstall(wanted); err != nil {
			return nil, err
		}
	}
	return skipped, nil
}

// PkgRemove removes packages and their now-orphaned dependencies.
func PkgRemove(packages []string) error {
	return pkgTransact(true, packages)
}

func pkgTransact(remove bool, packages []string) error {
	inst := PkgGetInstaller()
	if inst == PkgInstallerNone {
		return errors.New("No supported package manager found (looked for apt-get, dnf, yum)")
	}
	if len(packages) == 0 {
		return nil
	}
	// Checked in the shared helper rather than at each of the ~20 call sites:
	// when N callers share a helper and the helper is where the failure
	// lives, the helper is the call site (#89b).
	if why := PkgPrivilegedOpsReason("Installing or removing packages"); why != "" {
		return errors.New(why)
	}

	rpm := PkgManager() == PkgMgrRpm
	// Translation can COLLAPSE several Debian names onto one RPM package
	// (Dovecot, ModSecurity). Both managers tolerate repeats, but
	// `dovecot dovecot dovecot` in the logged command looks like a bug.
	var names []string
	for _, p := range packages {
		name := p
		if rpm {
			name = pkgRpmName(p)
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}

	var args []string
	switch {
	case !remove && inst.isApt():
		// --force-confnew: take the maintainer's config when one conflicts.
		// dnf has no equivalent knob — it writes .rpmnew and keeps yours — so
		// this policy is deliberately NOT emulated on the RPM side.
		args = []string{"-o", "Dpkg::Options::=--force-confnew", "install", "-y"}
	case !remove:
		args = []string{"install", "-y"}
	case inst.isApt():
		args = []string{"purge", "-y"}
	default:
		args = []string{"remove", "-y"}
	}
	args = append(args, names...)

	// Unsandboxed: a package transaction writes across the whole filesystem,
	// which ProtectSystem=strict exists to prevent.
	out, err := safecmd.NewUnsandboxed(inst.Bin()).Arg(args...).OutputWithTimeout(pkgInstallTimeout)
	if err != nil {
		return err
	}
	if !out.Success() {
		// dnf reports "Unable to find a match" on stdout, apt on stderr.
		// Taking whichever is non-empty keeps the real reason in the message.
		detail := string(out.Stderr)
		if strings.TrimSpace(detail) == "" {
			detail = string(out.Stdout)
		}
		return errors.New(pkgTruncChars(detail, 400))
	}

	// apt leaves orphans behind after a purge; dnf's `remove` already takes
	// unused dependencies with it.
	if remove && inst.isApt() {
		_, _ = safecmd.NewUnsandboxed("apt-get").Arg("autoremove", "-y").OutputWithTimeout(pkgInstallTimeout)
	}
	return nil
}

// PkgRefreshIndex refreshes the package index. apt needs this before a repo
// added moments ago is visible; dnf reads repo metadata on demand.
func PkgRefreshIndex() {
	if PkgGetInstaller() == PkgInstallerAptGet {
		_, _ = safecmd.NewUnsandboxed("apt-get").Arg("update").OutputWithTimeout(pkgInstallTimeout)
	}
}

// pkgEscapeHatchWorks reports whether the privileged escape hatch works here.
//
// THIS WAS THE WALL s266 HIT. The unsandboxed hatch used to pass stdio as fds
// over D-Bus (`systemd-run --pipe`), and on the RHEL family SELinux forbids
// the bus to receive them, so every package operation failed with "Failed to
// start transient service unit: Connection reset by peer". The hatch no
// longer passes descriptors (see safecmd.Unsandboxed). The probe is KEPT
// because it is cheap (cached once) and turns a raw D-Bus string into a
// sentence an operator can act on if some future change closes it again.
func pkgEscapeHatchWorks() bool {
	pkgHatchOnce.Do(func() {
		out, err := safecmd.NewUnsandboxed("true").OutputWithTimeout(30 * time.Second)
		pkgHatchOK = err == nil && out.Success()
	})
	return pkgHatchOK
}

// PkgPrivilegedOpsReason explains that privileged package operations cannot
// run on this box, or "" when they can.
//
// #90b: write down the sentence the operator will read — "the panel cannot
// install packages on this system" is the fact; the D-Bus error is a symptom
// they cannot act on.
func PkgPrivilegedOpsReason(what string) string {
	if pkgEscapeHatchWorks() {
		return ""
	}
	return what + " cannot run on this system: the agent is unable to launch privileged helper " +
		"processes (systemd refused the transient unit it uses to step outside its sandbox). " +
		"This is unexpected — please report it with the output of " +
		"`systemd-run --wait --collect -- /bin/true` run as root. In the meantime, install the " +
		"package with your system package manager and the panel will detect it."
}

// PkgNoInstallerReason explains a feature that has nothing to install with,
// or "" when this box can run it.
//
// A REFUSAL THAT STOPS BEING TRUE IS WORSE THAN NO REFUSAL: installers given
// a real dnf path (s266) dropped their calls rather than keep a message that
// contradicts the code underneath it.
func PkgNoInstallerReason(what string) string {
	if PkgGetInstaller() != PkgInstallerNone {
		return ""
	}
	return what + " is not possible on this box — no supported package manager was found " +
		"(looked for apt-get, dnf and yum). Install one, or install the service with " +
		"your own tooling and the panel will detect the result."
}

// PkgUfwRefusalReason says why the panel will not install UFW here, or "" on
// a box where UFW is the right answer.
//
// DELIBERATELY NOT RETIRED. UFW is installable from EPEL, but RHEL-family
// distros boot with firewalld enforcing, and s265's headline outage was
// setup.sh installing ufw BESIDE it and opening 80/443 in the filter nobody
// consulted — panel unreachable, no ACME challenge, no certificate, under an
// installer printing "installed successfully". The panel opens ports through
// FirewallAddPort, which speaks to whichever filter is running.
func PkgUfwRefusalReason() string {
	if FirewallDetect() == FirewallFirewalld {
		return "This system already runs firewalld, which is the firewall enforcing on RHEL-family " +
			"distributions. Installing UFW alongside it would create a second rule set that is " +
			"not consulted — the panel opens ports through firewalld automatically, so no action " +
			"is needed here."
	}
	if PkgManager() == PkgMgrDpkg {
		return ""
	}
	// rpm box with no firewalld running: still refuse, because UFW is not
	// this family's firewall and installing it invites the same split-brain
	// the moment firewalld is switched on.
	return "UFW is not the firewall used by RHEL-family distributions. Enable firewalld " +
		"(systemctl enable --now firewalld) and the panel will manage ports through it."
}

// PkgMailRefusalReason says why the panel will not install the mail stack,
// or "" where it will.
//
// RETIRED for the RHEL family at s268, because the drill was run end to end
// on Rocky 9.8 (dkim=pass between two real domains). The refusal's premise
// was wrong in both directions: the packages did NOT install (EPEL opendkim
// needs CRB), and what actually broke (/var/vmail labelled var_t, Dovecot
// without Argon2) was nothing it named. What remains is a real precondition
// surfaced by PkgExplainPackageFailure instead.
func PkgMailRefusalReason() string {
	return ""
}

// PkgExplainPackageFailure turns a raw package-manager failure from the mail
// install into something an operator can act on.
//
// This REPLACED a precondition gate: an available("opendkim") probe refused a
// box where the packages were installable, because dnf inside the sandbox
// answers "Read-only file system: '/var/log/dnf.log'". A probe that cannot
// tell "not installable" from "could not run" must not refuse. So the hint is
// attached to the real error: `nothing provides` on RHEL almost always means
// EPEL without CRB.
func PkgExplainPackageFailure(raw string) string {
	if PkgManager() != PkgMgrDpkg && strings.Contains(raw, "nothing provides") {
		return raw + "\n\nThis usually means the CRB repository is not enabled. EPEL requires it, " +
			"and OpenDKIM's dependencies (sendmail-milter, libmemcached-awesome) live there. " +
			"Enable it with `dnf config-manager --set-enabled crb` (`powertools` on EL8) and " +
			"retry — DockPanel's installer does this on new installs."
	}
	return raw
}

// PkgRepo is a third-party repository this module can add.
type PkgRepo int

const (
	PkgRepoNodeSource PkgRepo = iota
	PkgRepoCloudflared
	// PkgRepoRspamd: RHEL-family only — Debian and Ubuntu carry rspamd in
	// their own archives, and adding a repo there would change the family
	// that already works to fix the one that does not.
	PkgRepoRspamd
)

// PkgAddRepo adds a third-party repository for repo, when the running family
// needs one.
//
// Nodesource publishes a per-family setup script. Cloudflare publishes a
// CODENAME-keyed apt repo and a single flat rpm repo; VERSION_CODENAME exists
// on Debian and on no RHEL release, so on the rpm side the codename is not
// part of the question.
func PkgAddRepo(repo PkgRepo) error {
	inst := PkgGetInstaller()
	if inst == PkgInstallerNone {
		return errors.New("No supported package manager found")
	}
	if why := PkgPrivilegedOpsReason("Adding a package repository"); why != "" {
		return errors.New(why)
	}
	var script string
	switch {
	case repo == PkgRepoNodeSource && inst.isApt():
		script = "set -o pipefail; curl -fsSL https://deb.nodesource.com/setup_22.x | bash -"
	case repo == PkgRepoNodeSource:
		script = "set -o pipefail; curl -fsSL https://rpm.nodesource.com/setup_22.x | bash -"
	case repo == PkgRepoCloudflared && inst.isApt():
		codename := PkgOsReleaseValue("VERSION_CODENAME")
		if codename == "" {
			return errors.New("Cannot detect OS codename from /etc/os-release (need VERSION_CODENAME)")
		}
		script = "curl -sL https://pkg.cloudflare.com/cloudflare-main.gpg " +
			"-o /usr/share/keyrings/cloudflare-main.gpg && " +
			"printf 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] " +
			"https://pkg.cloudflare.com/cloudflared %s main\\n' " + codename + " " +
			"> /etc/apt/sources.list.d/cloudflared.list"
	case repo == PkgRepoCloudflared:
		// One flat repo, verified reachable (s266).
		script = "curl -fsSL https://pkg.cloudflare.com/cloudflared-ascii.repo " +
			"-o /etc/yum.repos.d/cloudflared.repo"
	case inst.isApt(): // Rspamd on apt
		// Never reached by design. An explicit error beats silently adding an
		// apt repo the archive already covers.
		return errors.New("Rspamd is packaged by Debian and Ubuntu; no extra repository is needed")
	default: // Rspamd on rpm
		// rspamd is NOT in EPEL (measured s270). Upstream publishes a
		// per-major-version flat repo keyed centos-<major>.
		major, _, _ := strings.Cut(PkgOsReleaseValue("VERSION_ID"), ".")
		if major == "" {
			return errors.New("Cannot detect OS major version from /etc/os-release")
		}
		script = "curl -fsSL https://rspamd.com/rpm-stable/centos-" + major + "/rspamd.repo " +
			"-o /etc/yum.repos.d/rspamd.repo"
	}

	// BASH, NOT SH. On Debian/Ubuntu /bin/sh is dash, which answers
	// `set -o pipefail` with "Illegal option". pipefail is the point: without
	// it a failed curl pipes nothing into `bash -`, which exits 0, and the
	// install proceeds against a repo never added (Lesson #73B).
	out, err := safecmd.NewUnsandboxed("bash").Arg("-c", script).OutputWithTimeout(pkgInstallTimeout)
	if err != nil {
		return fmt.Errorf("Repository setup could not be run: %v", err)
	}
	if !out.Success() {
		// A half-added repo breaks every later transaction (Lesson #73C), so
		// failure must leave nothing behind.
		PkgRemoveRepo(repo)
		return errors.New(pkgTruncChars(string(out.Stderr), 300))
	}
	PkgRefreshIndex()
	return nil
}

// PkgRemoveRepo deletes a repository this module added. Safe when absent.
//
// The list must track upstream's ACTUAL footprint: NodeSource's setup_22.x
// also drops a keyring and two Pin-Priority:600 files, and leaving them after
// "Uninstall" silently keeps deb.nodesource.com preferred for nodejs on every
// later unrelated install.
//
// Deliberately NOT attempted: revoking RPM-imported gpg-pubkey entries. They
// are not files, and matching the right one by heuristic risks revoking a key
// another active repo relies on; deleting the .repo file is what stops it
// being consulted.
func PkgRemoveRepo(repo PkgRepo) {
	for _, p := range pkgRepoArtifactPaths(repo) {
		_ = os.Remove(p)
	}
}

// pkgRepoArtifactPaths is every on-disk artifact PkgAddRepo can leave, shared
// by PkgRemoveRepo and its tests so they cannot drift apart.
func pkgRepoArtifactPaths(repo PkgRepo) []string {
	switch repo {
	case PkgRepoNodeSource:
		return []string{
			// Debian: current (DEB822) + the legacy .list filename upstream's
			// script still self-cleans, for boxes set up with an older script.
			"/etc/apt/sources.list.d/nodesource.sources",
			"/etc/apt/sources.list.d/nodesource.list",
			"/usr/share/keyrings/nodesource.gpg",
			"/etc/apt/preferences.d/nodejs",
			"/etc/apt/preferences.d/nsolid",
			// RPM: both repo defs upstream's setup script can write.
			"/etc/yum.repos.d/nodesource-nodejs.repo",
			"/etc/yum.repos.d/nodesource-nsolid.repo",
		}
	case PkgRepoCloudflared:
		return []string{
			"/etc/apt/sources.list.d/cloudflared.list",
			"/usr/share/keyrings/cloudflare-main.gpg",
			"/etc/yum.repos.d/cloudflared.repo",
		}
	case PkgRepoRspamd:
		return []string{"/etc/yum.repos.d/rspamd.repo"}
	}
	return nil
}

// PkgOsReleaseValue is a value from /etc/os-release, or "" when this release
// does not carry it. VERSION_CODENAME matters and no RHEL release has it.
func PkgOsReleaseValue(key string) string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// pkgRunOK runs a query and applies accept to its stdout when it exits 0.
func pkgRunOK(bin string, args []string, accept func(string) bool) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, bin, args...)
	return err == nil && out.Success() && accept(string(out.Stdout))
}

func pkgWhich(cmd string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "which", cmd)
	return err == nil && out.Success()
}

// pkgTruncChars keeps the first n characters (not bytes) of s.
func pkgTruncChars(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}
