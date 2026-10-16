package routes

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type updatesPackageUpdate struct {
	Name           string `json:"name"`
	CurrentVersion string `json:"current_version"`
	NewVersion     string `json:"new_version"`
	Repo           string `json:"repo"`
	Security       bool   `json:"security"`
}

type updatesApplyRequest struct {
	Packages []string `json:"packages"`
}

type updatesUpdateCount struct {
	Count          int  `json:"count"`
	Security       int  `json:"security"`
	RebootRequired bool `json:"reboot_required"`
}

type updatesRebootResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func registerUpdates(r *Router) {
	r.Handle("GET /system/updates", updatesList)
	r.Handle("POST /system/updates/apply", updatesApply)
	r.Handle("GET /system/updates/count", updatesCount)
	r.Handle("POST /system/reboot", updatesSystemReboot)
}

// updatesParseUpgradableLine parses one apt upgradable line.
//
// Format: `package/repo version_new arch [upgradable from: version_old]`
func updatesParseUpgradableLine(line string) (updatesPackageUpdate, bool) {
	if !strings.Contains(line, "upgradable from:") {
		return updatesPackageUpdate{}, false
	}
	name, afterSlash, ok := strings.Cut(line, "/")
	if !ok {
		return updatesPackageUpdate{}, false
	}
	// parts: ["repo", "version_new", "arch", "[upgradable", "from:", "version_old]"]
	parts := strings.Fields(afterSlash)
	if len(parts) < 6 {
		return updatesPackageUpdate{}, false
	}
	return updatesPackageUpdate{
		Name: name,
		// old version is the last element, strip trailing ']'
		CurrentVersion: strings.TrimRight(parts[len(parts)-1], "]"),
		NewVersion:     parts[1],
		Repo:           parts[0],
		Security:       strings.Contains(parts[0], "security"),
	}, true
}

// updatesRpmCheckUpdate runs `check-update`, whose exit status is not a plain
// boolean: 0 = ran fine, nothing to upgrade; 100 = ran fine, updates listed;
// anything else (network down, broken repo) is a real error. Treating
// non-zero as failure would make "0 updates" indistinguishable from a hard
// failure. ok=false only for that real-error case.
func updatesRpmCheckUpdate(bin string) (string, bool) {
	out, err := safecmd.NewUnsandboxed(bin).Arg("check-update").OutputWithTimeout(60 * time.Second)
	if err != nil || (out.ExitCode != 0 && out.ExitCode != 100) {
		return "", false
	}
	return string(out.Stdout), true
}

// updatesParseRpmUpdateLine parses one `dnf`/`yum check-update` line.
//
// Format: `name.arch    version-release    repo`. Section headers, the
// metadata banner and blank lines never have this 3-token shape; requiring
// a digit in the version token guards against a repo name that happened to
// also split into 3 words.
func updatesParseRpmUpdateLine(line string) (updatesPackageUpdate, bool) {
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return updatesPackageUpdate{}, false
	}
	nameArch, version, repo := parts[0], parts[1], parts[2]
	if !strings.ContainsAny(version, "0123456789") {
		return updatesPackageUpdate{}, false
	}
	// A real package token is always `name.arch` — requiring the dot is what
	// rejects a 3-word, digit-containing line that ISN'T a package, such as
	// "Security: 3 patches". Split on the LAST dot (python3.11-libs.x86_64).
	i := strings.LastIndexByte(nameArch, '.')
	if i < 0 {
		return updatesPackageUpdate{}, false
	}
	return updatesPackageUpdate{
		Name:       nameArch[:i],
		NewVersion: version,
		Repo:       repo,
		// dnf/yum don't classify security updates in check-update's output;
		// a real classifier needs `updateinfo list security` cross-referenced,
		// unverified against a live RHEL box — left false rather than ship an
		// unverified parse.
		Security: false,
	}, true
}

// updatesRpmInstalledVersions runs `rpm -qa` once as name -> version-release,
// so the RPM listing can show the CURRENT version the way apt's bracket does
// — cheaper than one `rpm -q` per package.
func updatesRpmInstalledVersions() map[string]string {
	m := map[string]string{}
	// No timeout: the Rust code had none.
	out, err := safecmd.Exec(context.Background(), "rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n")
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(out.Stdout), "\n") {
		if name, ver, ok := strings.Cut(line, " "); ok {
			m[name] = ver
		}
	}
	return m
}

// updatesRebootRequired reports whether the host wants a reboot.
//
// Debian: update-notifier-common drops /var/run/reboot-required. RHEL has no
// such file; `needs-restarting -r` (dnf-utils/yum-utils) exits 1 when a
// reboot is recommended. Neither is guaranteed present, so absence degrades
// to "no reboot needed" rather than an error.
func updatesRebootRequired() bool {
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		return true
	}
	if services.PkgManager() == services.PkgMgrRpm {
		if out, err := safecmd.Exec(context.Background(), "needs-restarting", "-r"); err == nil {
			return out.ExitCode == 1
		}
	}
	return false
}

// updatesRpmBin is dnf/yum, or "" when the RPM box has neither.
func updatesRpmBin() string {
	switch services.PkgGetInstaller() {
	case services.PkgInstallerDnf:
		return "dnf"
	case services.PkgInstallerYum:
		return "yum"
	}
	return ""
}

// GET /system/updates — list available package updates.
func updatesList(w http.ResponseWriter, r *http.Request) {
	packages := []updatesPackageUpdate{}
	if services.PkgManager() == services.PkgMgrRpm {
		bin := updatesRpmBin()
		if bin == "" {
			writeJSON(w, http.StatusOK, packages)
			return
		}
		if stdout, ok := updatesRpmCheckUpdate(bin); ok {
			for _, l := range strings.Split(stdout, "\n") {
				if p, ok := updatesParseRpmUpdateLine(l); ok {
					packages = append(packages, p)
				}
			}
		}
		if len(packages) > 0 {
			installed := updatesRpmInstalledVersions()
			for i := range packages {
				if v, ok := installed[packages[i].Name]; ok {
					packages[i].CurrentVersion = v
				}
			}
		}
		slices.SortStableFunc(packages, func(a, b updatesPackageUpdate) int { return cmp.Compare(a.Name, b.Name) })
		writeJSON(w, http.StatusOK, packages)
		return
	}

	// apt-get update first (output ignored, 60s). Unsandboxed because it
	// writes /var/lib/apt/lists, which ProtectSystem=strict blocks.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	_, _ = safecmd.NewUnsandboxed("apt-get").Arg("update", "-qq").Output(ctx)
	cancel()

	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if out, err := safecmd.Exec(ctx, "apt", "list", "--upgradable"); err == nil {
		for _, l := range strings.Split(string(out.Stdout), "\n") {
			if p, ok := updatesParseUpgradableLine(l); ok {
				packages = append(packages, p)
			}
		}
	}

	// Security first, then alphabetically.
	slices.SortStableFunc(packages, func(a, b updatesPackageUpdate) int {
		if a.Security != b.Security {
			if a.Security {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.Name, b.Name)
	})
	writeJSON(w, http.StatusOK, packages)
}

// updatesNDJSON encodes one NDJSON line. Maps marshal with sorted keys, the
// same order serde_json::json! produces (no preserve_order feature).
func updatesNDJSON(v map[string]any) string {
	b, _ := json.Marshal(v)
	return string(b) + "\n"
}

func updatesDone(success, reboot bool) string {
	return updatesNDJSON(map[string]any{"type": "done", "success": success, "reboot_required": reboot})
}

func updatesLine(line string) string {
	return updatesNDJSON(map[string]any{"type": "line", "line": line})
}

// POST /system/updates/apply — apply package updates with streaming NDJSON.
//
// Each line is {"type":"line","line":"..."}; the final line is
// {"type":"done","success":bool,"reboot_required":bool}.
func updatesApply(w http.ResponseWriter, r *http.Request) {
	var body updatesApplyRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)
	// send returns false once the client is gone.
	send := func(s string) bool {
		if _, err := w.Write([]byte(s)); err != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}

	// Validate package names up-front.
	for _, pkg := range body.Packages {
		if pkg == "" || !updatesAllValid(pkg) {
			send(updatesLine("Invalid package name: " + pkg))
			send(updatesDone(false, false))
			return
		}
	}

	// Wrapped in systemd-run: apt-get/dnf/yum write /var/cache, /var/lib/{dpkg,rpm}
	// and /usr, all blocked by the agent's ProtectSystem=strict sandbox.
	inst := services.PkgGetInstaller()
	if inst == services.PkgInstallerNone {
		send(updatesLine("No supported package manager found"))
		send(updatesDone(false, false))
		return
	}
	cmd := safecmd.NewUnsandboxed(inst.Bin())
	if len(body.Packages) > 0 {
		// apt `install` picks up the candidate version of an installed
		// package, so it doubles as an upgrade. dnf/yum `install` would
		// happily install a MISTYPED name that isn't present at all;
		// `upgrade <name>` only touches something already installed.
		if inst == services.PkgInstallerAptGet {
			cmd.Arg("install", "-y")
		} else {
			cmd.Arg("upgrade", "-y")
		}
		cmd.Arg(body.Packages...)
	} else {
		cmd.Arg("upgrade", "-y")
	}

	// Background, not r.Context(): the Rust task outlived the client, and the
	// transaction must not be cut short by a closed browser tab.
	run, err := cmd.SpawnStreaming(context.Background())
	if err != nil {
		send(updatesLine(fmt.Sprintf("Failed to start apt: %v", err)))
		send(updatesDone(false, false))
		return
	}

	// stdout and stderr both arrive on one channel (the escape hatch tails
	// capture files). Keep draining after a client disconnect so the
	// tailers never block on a full channel.
	connected := true
	for line := range run.Lines {
		if line == "" || !connected {
			continue
		}
		connected = send(updatesLine(line))
	}
	if !connected {
		return
	}

	// Lines closes only after the inner command exited and its output was
	// drained, so this resolves immediately in practice.
	success := false
	waited := make(chan bool, 1)
	go func() {
		code, err := run.Wait()
		waited <- err == nil && code == 0
	}()
	select {
	case success = <-waited:
	case <-time.After(10 * time.Second):
	}

	send(updatesDone(success, updatesRebootRequired()))
}

// updatesAllValid mirrors the Rust per-char check (ASCII alnum or - . + :).
func updatesAllValid(pkg string) bool {
	for _, c := range pkg {
		if !isASCIIAlnum(c) && c != '-' && c != '.' && c != '+' && c != ':' {
			return false
		}
	}
	return true
}

// GET /system/updates/count — quick count of available updates (no apt update).
func updatesCount(w http.ResponseWriter, r *http.Request) {
	count, security := 0, 0
	if services.PkgManager() == services.PkgMgrRpm {
		if bin := updatesRpmBin(); bin != "" {
			if stdout, ok := updatesRpmCheckUpdate(bin); ok {
				for _, l := range strings.Split(stdout, "\n") {
					if _, ok := updatesParseRpmUpdateLine(l); ok {
						count++
					}
				}
				// security classification not implemented for RPM
			}
		}
	} else if out, err := safecmd.Exec(context.Background(), "apt", "list", "--upgradable"); err == nil {
		for _, l := range strings.Split(string(out.Stdout), "\n") {
			if strings.Contains(l, "upgradable from:") {
				count++
				if strings.Contains(l, "security") {
					security++
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, updatesUpdateCount{Count: count, Security: security, RebootRequired: updatesRebootRequired()})
}

// POST /system/reboot — schedule a system reboot in 1 minute.
func updatesSystemReboot(w http.ResponseWriter, r *http.Request) {
	out, err := safecmd.Exec(context.Background(), "shutdown", "-r", "+1", "DockPanel initiated reboot")
	var res updatesRebootResult
	switch {
	case err != nil:
		res = updatesRebootResult{Message: fmt.Sprintf("Failed to execute shutdown: %v", err)}
	case out.Success():
		res = updatesRebootResult{Success: true, Message: "System will reboot in 1 minute"}
	default:
		res = updatesRebootResult{Message: "Reboot command failed: " + string(out.Stderr)}
	}
	writeJSON(w, http.StatusOK, res)
}
