package routes

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// phpAllowedVersions come from distro repos, deb.sury.org or ppa:ondrej/php.
var phpAllowedVersions = []string{"8.1", "8.2", "8.3", "8.4", "8.5"}

// phpCommonExtensions are installed only where the apt source has a candidate
// (8.5 absorbed opcache; one dead name would fail the whole transaction).
var phpCommonExtensions = []string{"mysql", "pgsql", "sqlite3", "curl", "gd", "mbstring",
	"xml", "zip", "bcmath", "intl", "readline", "opcache", "redis", "imagick"}

type phpVersion struct {
	Version    string `json:"version"`
	Installed  bool   `json:"installed"`
	FpmRunning bool   `json:"fpm_running"`
	Socket     string `json:"socket"`
}

type phpInstallRequest struct {
	Version string `json:"version"`
}

type phpInstallResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Version string `json:"version"`
}

func phpAllowed(v string) bool {
	for _, a := range phpAllowedVersions {
		if a == v {
			return true
		}
	}
	return false
}

// phpIsInstalled: on RPM boxes one `php-fpm` package serves every version, so
// pkg's per-name answer said EVERY offered version was installed; there the
// real version is read from the package database instead.
func phpIsInstalled(version string) bool {
	if actual := services.PkgInstalledPhpVersion(); actual != "" {
		return actual == version
	}
	return services.PkgIsInstalled("php" + version + "-fpm")
}

// phpSocketExists delegates to the shared resolver that also backs put_site,
// so the two can never disagree about which family's socket is real.
func phpSocketExists(version string) bool {
	return services.PkgResolvePhpFpmSocket(version) != ""
}

func phpUnit(version string) string { return services.PkgServiceName("php" + version + "-fpm") }

func phpIsFpmRunning(version string) bool {
	out, err := nginxRun(0, "systemctl", "is-active", "--quiet", phpUnit(version))
	return err == nil && out.Success()
}

// phpListVersions: GET /php/versions.
func phpListVersions(w http.ResponseWriter, _ *http.Request) {
	versions := []phpVersion{}
	for _, v := range phpAllowedVersions {
		installed := phpIsInstalled(v)
		real, hasReal := "", false
		if installed {
			real = services.PkgResolvePhpFpmSocket(v)
			hasReal = real != ""
		}
		// Falls back to the Debian-shaped guess when nothing real was found.
		socket := fmt.Sprintf("/run/php/php%s-fpm.sock", v)
		if hasReal {
			socket = real
		}
		versions = append(versions, phpVersion{Version: v, Installed: installed,
			FpmRunning: installed && (phpIsFpmRunning(v) || hasReal), Socket: socket})
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

func phpFail(w http.ResponseWriter, status int, version, msg string) {
	writeJSON(w, status, phpInstallResponse{Message: msg, Version: version})
}

// phpStartFpm enables and starts this version's FPM unit.
func phpStartFpm(version string) {
	_, _ = nginxRun(0, "systemctl", "enable", "--now", phpUnit(version))
}

// phpSettle judges an install by the only fact that decides whether a PHP
// site works: the FPM socket. success=false even with packages installed is
// deliberate — "installed" then "cannot create a PHP site" is the sequence
// this route was reported for.
func phpSettle(version, whatHappened string) phpInstallResponse {
	for i := 0; i < 25; i++ {
		if phpSocketExists(version) {
			return phpInstallResponse{Success: true, Message: fmt.Sprintf("PHP %s %s and PHP-FPM is running", version, whatHappened), Version: version}
		}
		time.Sleep(200 * time.Millisecond)
	}
	unit := phpUnit(version)
	return phpInstallResponse{Version: version, Message: fmt.Sprintf("PHP %s %s, but PHP-FPM did not open its socket, so PHP sites "+
		"on this version will not work yet. Check `systemctl status %s` and "+
		"`journalctl -u %s` on the server.", version, whatHappened, unit, unit)}
}

// phpInstallVersionRpm selects the module stream BEFORE installing: with no
// stream enabled `dnf install php-fpm` resolves to the base package (8.0 on
// Rocky 9, end-of-life) with nothing in the UI to say so.
func phpInstallVersionRpm(w http.ResponseWriter, version string) {
	slog.Info(fmt.Sprintf("Installing PHP %s from its module stream", version))
	if err := services.PkgEnablePhpStream(version); err != nil {
		phpFail(w, http.StatusInternalServerError, version, fmt.Sprintf("Could not select PHP %s: %v", version, err))
		return
	}
	if err := services.PkgInstall([]string{"php" + version + "-fpm", "php" + version + "-cli"}); err != nil {
		phpFail(w, http.StatusInternalServerError, version, fmt.Sprintf("PHP %s install failed: %v", version, err))
		return
	}
	exts := make([]string, len(phpCommonExtensions))
	for i, e := range phpCommonExtensions {
		exts[i] = "php" + version + "-" + e
	}
	skipped, err := services.PkgInstallAvailable(exts)
	if err != nil {
		phpFail(w, http.StatusInternalServerError, version, fmt.Sprintf("PHP %s extension install failed: %v", version, err))
		return
	}
	if len(skipped) > 0 {
		slog.Info(fmt.Sprintf("PHP %s: no candidate for %s", version, strings.Join(skipped, " ")))
	}
	unit := phpUnit(version)
	_, _ = nginxRun(0, "systemctl", "enable", unit)
	_, _ = nginxRun(0, "systemctl", "restart", unit)
	writeJSON(w, http.StatusOK, phpSettle(version, "was installed"))
}

func phpOsRelease(key string) string {
	b, _ := os.ReadFile("/etc/os-release")
	for _, l := range nginxLines(string(b)) {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// phpInstallVersion: POST /php/install.
func phpInstallVersion(w http.ResponseWriter, r *http.Request) {
	var b phpInstallRequest
	if !nginxDecodeStrict(w, r, &b, "version") {
		return
	}
	version := strings.TrimSpace(b.Version)
	if !phpAllowed(version) {
		phpFail(w, http.StatusBadRequest, version, "Invalid version. Allowed: "+strings.Join(phpAllowedVersions, ", "))
		return
	}
	// Already installed is not the question anyone is asking: everything
	// downstream cares about the SOCKET, and an installed-but-stopped unit
	// used to report success while the next site switch failed again.
	if phpIsInstalled(version) {
		phpStartFpm(version)
		writeJSON(w, http.StatusOK, phpSettle(version, "was already installed"))
		return
	}
	// The RHEL family selects a version by module stream; everything below
	// is Debian machinery (this file once failed with "apt-get not found").
	if streams := services.PkgPhpStreams(); len(streams) > 0 {
		offered := false
		for _, s := range streams {
			offered = offered || s == version
		}
		if !offered {
			phpFail(w, http.StatusNotImplemented, version, fmt.Sprintf("PHP %s is not offered by this system's package repositories. "+
				"Available versions here: %s. (Other versions would need the third-party "+
				"remi repository, which DockPanel does not configure.)", version, strings.Join(streams, ", ")))
			return
		}
		phpInstallVersionRpm(w, version)
		return
	}

	// Is php{v}-fpm available from some apt source? If not, add deb.sury.org
	// (Debian) or ppa:ondrej/php (Ubuntu).
	avail, err := nginxRun(0, "bash", "-c", fmt.Sprintf("apt-cache show php%s-fpm 2>/dev/null | grep -q '^Package:'", version))
	if err != nil || !avail.Success() {
		osID, codename := phpOsRelease("ID"), phpOsRelease("VERSION_CODENAME")
		// Each script pre-checks that the repo publishes for this release and
		// verifies the version afterwards; on failure the source is REMOVED —
		// a dead source 404s every later `apt-get update` on the box.
		var repoCmd string
		switch {
		case osID == "debian" && codename != "":
			slog.Info(fmt.Sprintf("Adding deb.sury.org repo for Debian (%s)...", codename))
			repoCmd = fmt.Sprintf("curl -sfI --max-time 15 https://packages.sury.org/php/dists/%[1]s/Release > /dev/null || "+
				"{ echo 'deb.sury.org publishes no PHP packages for Debian %[1]s yet' >&2; exit 42; }; "+
				"apt-get update -qq && apt-get install -y -qq apt-transport-https lsb-release ca-certificates curl gnupg && "+
				"curl -sSLo /usr/share/keyrings/deb.sury.org-php.gpg https://packages.sury.org/php/apt.gpg && "+
				"echo 'deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ %[1]s main' > /etc/apt/sources.list.d/sury-php.list && "+
				"apt-get update -qq && "+
				"{ apt-cache policy php%[2]s-fpm 2>/dev/null | grep -q 'Candidate: [0-9]' || "+
				"{ echo 'php%[2]s-fpm is still unavailable after adding deb.sury.org' >&2; exit 43; }; }", codename, version)
		case osID == "ubuntu" && codename != "":
			slog.Info(fmt.Sprintf("Adding ppa:ondrej/php for Ubuntu (%s)...", codename))
			repoCmd = fmt.Sprintf("curl -sfI --max-time 15 https://ppa.launchpadcontent.net/ondrej/php/ubuntu/dists/%[1]s/Release > /dev/null || "+
				"{ echo 'ppa:ondrej/php publishes no packages for Ubuntu %[1]s yet' >&2; exit 42; }; "+
				"apt-get update -qq && apt-get install -y -qq software-properties-common && "+
				"add-apt-repository -y ppa:ondrej/php && apt-get update -qq && "+
				"{ apt-cache policy php%[2]s-fpm 2>/dev/null | grep -q 'Candidate: [0-9]' || "+
				"{ echo 'php%[2]s-fpm is still unavailable after adding ppa:ondrej/php' >&2; exit 43; }; }", codename, version)
		default:
			phpFail(w, http.StatusBadRequest, version, fmt.Sprintf("Unsupported distro for PHP install: ID='%s'. Install PHP %s manually.", osID, version))
			return
		}
		out, err := safecmd.NewUnsandboxed("bash").Arg("-c", repoCmd).Output(r.Context())
		if err != nil {
			phpFail(w, http.StatusInternalServerError, version, fmt.Sprintf("Failed to configure PHP repo: %v", err))
			return
		}
		if !out.Success() {
			// Roll the source back so a failed attempt can't poison apt.
			_, _ = safecmd.NewUnsandboxed("bash").Arg("-c",
				"rm -f /etc/apt/sources.list.d/sury-php.list "+
					"/etc/apt/sources.list.d/ondrej-ubuntu-php-*.sources "+
					"/etc/apt/sources.list.d/ondrej-ubuntu-php-*.list; "+
					"apt-get update -qq || true").Output(r.Context())
			phpFail(w, http.StatusInternalServerError, version, "Failed to configure PHP repo: "+nginxLossy(out.Stderr))
			return
		}
	}

	// Core first (must succeed), then every extension with a real Candidate
	// (`apt-cache show` is not enough: a stanza can exist with Candidate
	// "(none)", e.g. php-opcache on Ubuntu 26.04).
	installCmd := fmt.Sprintf("set -e; export DEBIAN_FRONTEND=noninteractive; "+
		"apt-get install -y -qq php%[1]s-fpm php%[1]s-cli php%[1]s-common; "+
		"avail=''; "+
		"for e in %[2]s; do "+
		"p=\"php%[1]s-$e\"; "+
		"c=$(apt-cache policy \"$p\" 2>/dev/null | sed -n 's/^  Candidate: //p'); "+
		"if [ -n \"$c\" ] && [ \"$c\" != '(none)' ]; then avail=\"$avail $p\"; fi; "+
		"done; "+
		"if [ -n \"$avail\" ]; then apt-get install -y -qq $avail; fi", version, strings.Join(phpCommonExtensions, " "))
	slog.Info(fmt.Sprintf("Installing PHP %s (core + available extensions)", version))
	// OutputWithTimeout also stops the transient unit the apt transaction
	// runs in; a caller-side timeout cannot reach it (orphaned transactions).
	out, err := safecmd.NewUnsandboxed("bash").Arg("-c", installCmd).OutputWithTimeout(300 * time.Second)
	if err != nil {
		phpFail(w, http.StatusInternalServerError, version, err.Error())
		return
	}
	if !out.Success() {
		phpFail(w, http.StatusInternalServerError, version, fmt.Sprintf("apt install failed:\n%s\n%s", nginxLossy(out.Stdout), nginxLossy(out.Stderr)))
		return
	}
	phpStartFpm(version)
	slog.Info(fmt.Sprintf("PHP %s installed and started", version))
	writeJSON(w, http.StatusOK, phpSettle(version, "was installed with FPM and all available extensions"))
}

// phpListExtensions: GET /php/extensions/{version}.
func phpListExtensions(w http.ResponseWriter, r *http.Request) {
	version := r.PathValue("version")
	if !phpAllowed(version) {
		writeErr(w, http.StatusBadRequest, "Invalid PHP version. Allowed: "+strings.Join(phpAllowedVersions, ", "))
		return
	}
	cmd := safecmd.Command(r.Context(), "php", "-d", "error_reporting=0", "-m")
	cmd.Env = append(cmd.Env, "PATH=/usr/bin:/usr/sbin:/bin")
	out, err := safecmd.Run(r.Context(), cmd)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	installed := []string{}
	for _, l := range nginxLines(nginxLossy(out.Stdout)) {
		if l != "" && !strings.HasPrefix(l, "[") {
			installed = append(installed, strings.ToLower(strings.TrimSpace(l)))
		}
	}
	// The query AND the prefix differ per family (php8.3-gd vs php-gd); an
	// apt-cache on a dnf box fails silently into an empty list.
	var prefix string
	var avail safecmd.Output
	if services.PkgManager() == services.PkgMgrRpm {
		prefix = "php-"
		avail, err = nginxRun(0, "dnf", "-q", "list", "--available", "php-*")
	} else {
		prefix = "php" + version + "-"
		avail, err = nginxRun(0, "apt-cache", "search", "php"+version+"-")
	}
	available := []string{}
	if err == nil {
		for _, l := range nginxLines(nginxLossy(avail.Stdout)) {
			f := strings.Fields(l)
			if len(f) == 0 {
				continue
			}
			pkg, _, _ := strings.Cut(f[0], ".") // dnf prints php-gd.x86_64
			ext, ok := strings.CutPrefix(pkg, prefix)
			if !ok || ext == "" {
				continue
			}
			switch ext {
			case "common", "cli", "fpm", "dev", "dbg", "devel":
				continue
			}
			available = append(available, ext)
		}
	}
	sort.Strings(available)
	dedup := available[:0]
	for i, a := range available {
		if i == 0 || a != available[i-1] {
			dedup = append(dedup, a)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"installed": installed, "available": dedup, "version": version})
}

// phpInstallExtension: POST /php/extensions/install.
func phpInstallExtension(w http.ResponseWriter, r *http.Request) {
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	version, ok := nginxFieldStr(body, "version")
	if !ok {
		version = "8.3"
	}
	extension, _ := nginxFieldStr(body, "extension")
	if !phpAllowed(version) {
		writeErr(w, http.StatusBadRequest, "Invalid PHP version. Allowed: "+strings.Join(phpAllowedVersions, ", "))
		return
	}
	validExt := extension != ""
	for _, c := range extension {
		if !isASCIIAlnum(c) && c != '-' && c != '_' {
			validExt = false
		}
	}
	if !validExt {
		writeErr(w, http.StatusBadRequest, "Invalid extension name")
		return
	}
	pkg := "php" + version + "-" + extension
	slog.Info("Installing PHP extension: " + pkg)
	if err := services.PkgInstall([]string{pkg}); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Install failed: %v", err))
		return
	}
	_, _ = nginxRun(0, "systemctl", "restart", phpUnit(version))
	slog.Info("PHP extension installed: " + pkg)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "package": pkg})
}

// phpUninstallVersion: POST /php/uninstall.
func phpUninstallVersion(w http.ResponseWriter, r *http.Request) {
	var b phpInstallRequest
	if !nginxDecodeStrict(w, r, &b, "version") {
		return
	}
	version := strings.TrimSpace(b.Version)
	if !phpAllowed(version) {
		phpFail(w, http.StatusBadRequest, version, "Invalid version. Allowed: "+strings.Join(phpAllowedVersions, ", "))
		return
	}
	if !phpIsInstalled(version) {
		writeJSON(w, http.StatusOK, phpInstallResponse{Success: true, Message: fmt.Sprintf("PHP %s is not installed", version), Version: version})
		return
	}
	unit := phpUnit(version)
	_, _ = nginxRun(0, "systemctl", "stop", unit)
	_, _ = nginxRun(0, "systemctl", "disable", unit)

	// The glob is family-specific and stays out of pkg's name translation;
	// on RHEL packages are unversioned, so "this version" means PHP.
	slog.Info(fmt.Sprintf("Uninstalling PHP %s...", version))
	rpm := services.PkgManager() == services.PkgMgrRpm
	purge := fmt.Sprintf("apt-get purge -y php%s-* 2>&1", version)
	if rpm {
		purge = "dnf remove -y 'php-*' 2>&1"
	}
	out, err := safecmd.NewUnsandboxed("bash").Arg("-c", purge).OutputWithTimeout(300 * time.Second)
	if err != nil {
		phpFail(w, http.StatusInternalServerError, version, err.Error())
		return
	}
	if !out.Success() {
		phpFail(w, http.StatusInternalServerError, version, fmt.Sprintf("apt purge failed:\n%s\n%s", nginxLossy(out.Stdout), nginxLossy(out.Stderr)))
		return
	}
	// apt leaves orphans; dnf's remove already took them.
	if !rpm {
		_, _ = safecmd.NewUnsandboxed("bash").Arg("-c", "apt-get autoremove -y 2>&1").OutputWithTimeout(300 * time.Second)
	}
	slog.Info(fmt.Sprintf("PHP %s uninstalled", version))
	writeJSON(w, http.StatusOK, phpInstallResponse{Success: true, Message: fmt.Sprintf("PHP %s has been uninstalled", version), Version: version})
}

// registerPhp mounts src/routes/php.rs.
func registerPhp(r *Router) {
	r.Handle("GET /php/versions", phpListVersions)
	r.Handle("POST /php/install", phpInstallVersion)
	r.Handle("POST /php/uninstall", phpUninstallVersion)
	r.Handle("GET /php/extensions/{version}", phpListExtensions)
	r.Handle("POST /php/extensions/install", phpInstallExtension)
}
