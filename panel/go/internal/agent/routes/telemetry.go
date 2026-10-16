package routes

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type telemetrySystemInfo struct {
	Os                    string                   `json:"os"`
	OsVersion             string                   `json:"os_version"`
	Kernel                string                   `json:"kernel"`
	Arch                  string                   `json:"arch"`
	Hostname              string                   `json:"hostname"`
	TotalMemoryMb         uint64                   `json:"total_memory_mb"`
	TotalDiskMb           uint64                   `json:"total_disk_mb"`
	CpuCount              uint32                   `json:"cpu_count"`
	UptimeSeconds         uint64                   `json:"uptime_seconds"`
	DockpanelAgentVersion string                   `json:"dockpanel_agent_version"`
	Services              []telemetryServiceStatus `json:"services"`
}

type telemetryServiceStatus struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

func registerTelemetry(r *Router) {
	r.Handle("GET /telemetry/system-info", telemetryHandleSystemInfo)
}

// telemetryRun runs a short probe with the Rust 5 s timeout; ok=false on
// timeout or spawn failure (exit status is not checked, as in the Rust).
func telemetryRun(bin string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, bin, args...)
	if err != nil {
		return "", false
	}
	return strings.ToValidUTF8(string(out.Stdout), "�"), true
}

// telemetryLine is Rust's .lines().nth(n).
func telemetryLine(s string, n int) (string, bool) {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if s == "" || n >= len(lines) {
		return "", false
	}
	return strings.TrimSuffix(lines[n], "\r"), true
}

// telemetryHandleSystemInfo: GET /telemetry/system-info — system information
// for telemetry reports.
func telemetryHandleSystemInfo(w http.ResponseWriter, _ *http.Request) {
	osRelease, _ := os.ReadFile("/etc/os-release")
	osName, osVersion := "Linux", ""
	foundName, foundVer := false, false
	for _, l := range strings.Split(string(osRelease), "\n") {
		if !foundName && strings.HasPrefix(l, "NAME=") {
			osName, foundName = strings.Trim(strings.TrimPrefix(l, "NAME="), `"`), true
		}
		if !foundVer && strings.HasPrefix(l, "VERSION_ID=") {
			osVersion, foundVer = strings.Trim(strings.TrimPrefix(l, "VERSION_ID="), `"`), true
		}
	}

	kernel, _ := telemetryRun("uname", "-r")
	arch, _ := telemetryRun("uname", "-m")

	// Hostname, sanitised — no FQDN, first 32 chars (privacy).
	hostname := "unknown"
	if h, ok := telemetryRun("hostname", "-s"); ok {
		short, _, _ := strings.Cut(strings.TrimSpace(h), ".")
		rs := []rune(short)
		if len(rs) > 32 {
			rs = rs[:32]
		}
		hostname = string(rs)
	}

	var totalMem uint64
	if out, ok := telemetryRun("free", "-m"); ok {
		if l, ok := telemetryLine(out, 1); ok {
			if f := strings.Fields(l); len(f) > 1 {
				totalMem, _ = strconv.ParseUint(f[1], 10, 64)
			}
		}
	}

	var totalDisk uint64
	if out, ok := telemetryRun("df", "--output=size", "-BM", "/"); ok {
		if l, ok := telemetryLine(out, 1); ok {
			totalDisk, _ = strconv.ParseUint(strings.TrimRight(strings.TrimSpace(l), "M"), 10, 64)
		}
	}

	cpuCount := uint32(1)
	if out, ok := telemetryRun("nproc"); ok {
		if n, err := strconv.ParseUint(strings.TrimSpace(out), 10, 32); err == nil {
			cpuCount = uint32(n)
		}
	}

	var uptime uint64
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil && v > 0 {
				uptime = uint64(v)
			}
		}
	}

	names := []string{
		"dockpanel-agent", "dockpanel-api", "nginx", "postgresql", "docker",
		"fail2ban", "ufw", "postfix", "dovecot", "redis-server",
	}
	svcs := make([]telemetryServiceStatus, 0, len(names))
	for _, n := range names {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := safecmd.Exec(ctx, "systemctl", "is-active", "--quiet", n)
		cancel()
		svcs = append(svcs, telemetryServiceStatus{Name: n, Active: err == nil && out.Success()})
	}

	writeJSON(w, http.StatusOK, telemetrySystemInfo{
		Os: osName, OsVersion: osVersion, Kernel: strings.TrimSpace(kernel), Arch: strings.TrimSpace(arch),
		Hostname: hostname, TotalMemoryMb: totalMem, TotalDiskMb: totalDisk, CpuCount: cpuCount,
		UptimeSeconds: uptime, DockpanelAgentVersion: services.AgentVersion, Services: svcs,
	})
}
