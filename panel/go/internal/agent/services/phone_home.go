// Phone-home mode: a remote agent checks in with the central panel.

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
)

// Hooks into routes/panel_update.go, which services cannot import (routes
// imports services). routes sets both in its init().
var (
	PhoneHomeStartAgentSelfUpdate             func(target string) error
	PhoneHomeTargetAlreadyFailedDestructively func(target string) (why string, failed bool)
)

// PhoneHomeConfig configures phone-home mode.
type PhoneHomeConfig struct {
	CentralURL  string
	ServerToken string
	ServerID    string
	// CertFingerprint is the SHA-256 hex fingerprint of the agent's TLS cert,
	// sent in every checkin so the panel can pin it (TOFU). Set by main after
	// loading the cert; "" keeps compatibility with panels that don't pin.
	CertFingerprint string
}

// PhoneHomeConfigFromEnv reads the env vars; nil if not configured.
func PhoneHomeConfigFromEnv() *PhoneHomeConfig {
	url, token, id := os.Getenv("DOCKPANEL_CENTRAL_URL"), os.Getenv("DOCKPANEL_SERVER_TOKEN"), os.Getenv("DOCKPANEL_SERVER_ID")
	if url == "" || token == "" || id == "" {
		return nil
	}
	return &PhoneHomeConfig{CentralURL: strings.TrimRight(url, "/"), ServerToken: token, ServerID: id}
}

// PhoneHomeLongOSVersion mirrors sysinfo's long_os_version on Linux:
// "Linux (Ubuntu 24.04)", "Linux (Ubuntu)" or "Linux".
func PhoneHomeLongOSVersion() string {
	name, hasName := phoneHomeOSRelease("NAME=", "DISTRIB_ID=")
	ver, hasVer := phoneHomeOSRelease("VERSION_ID=", "DISTRIB_RELEASE=")
	switch {
	case hasVer:
		if !hasName {
			name = "unknown"
		}
		return "Linux (" + name + " " + ver + ")"
	case hasName:
		return "Linux (" + name + ")"
	}
	return "Linux"
}

func phoneHomeOSRelease(key, lsbKey string) (string, bool) {
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, key); ok {
				return strings.ReplaceAll(v, `"`, ""), true
			}
		}
	}
	// Fallback to /etc/lsb-release where VERSION_ID is absent.
	if b, err := os.ReadFile("/etc/lsb-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, lsbKey); ok {
				return strings.ReplaceAll(v, `"`, ""), true
			}
		}
	}
	return "", false
}

// phoneHomeCollectSystemInfo builds the checkin payload.
//
// cpu supplies the CPU figure. This used to read a CPU delta whose window
// was almost entirely this function's own /proc walk — on an idle 12-core box
// at 4.5 % it returned 4.5–22.1 %. The value lands in servers.cpu_usage,
// which the alert engine compares against thresholds, so a fabricated number
// fires (or withholds) real alerts. Nothing here refreshes processes.
func phoneHomeCollectSystemInfo(c *CpuSampler) map[string]any {
	var total, used uint64
	if vm, err := mem.VirtualMemory(); err == nil {
		total, used = vm.Total, vm.Total-vm.Available
	}
	var diskTotalGB, diskUsedGB int64
	var diskPct float32
	if d, err := disk.Usage("/"); err == nil {
		u := d.Total - d.Free // Free is f_bavail, sysinfo's available_space
		diskTotalGB = int64(math.Round(float64(d.Total) / 1073741824))
		diskUsedGB = int64(math.Round(float64(u) / 1073741824))
		if d.Total > 0 {
			diskPct = float32(u) / float32(d.Total) * 100
		}
	}
	cores, _ := cpu.Counts(true)
	hostname, _ := os.Hostname()
	uptime, _ := host.Uptime()
	return map[string]any{
		"server_id":      "", // filled by caller
		"os_info":        PhoneHomeLongOSVersion(),
		"hostname":       hostname,
		"cpu_cores":      cores,
		"ram_mb":         int64(total / 1048576),
		"disk_gb":        diskTotalGB,
		"disk_used_gb":   diskUsedGB,
		"disk_usage_pct": diskPct,
		"agent_version":  AgentVersion,
		"cpu_usage":      c.Usage(),
		"mem_used_mb":    int64(used / 1048576),
		"uptime_secs":    uptime,
		// Replay prevention: server rejects requests >120s old.
		"timestamp": time.Now().Unix(),
	}
}

// PhoneHomeRun is the phone-home loop: periodically POST system info to the
// central API. Blocks until ctx is cancelled.
func PhoneHomeRun(ctx context.Context, cfg PhoneHomeConfig, c *CpuSampler) {
	slog.Info(fmt.Sprintf("Phone-home enabled: server_id=%s, central=%s", cfg.ServerID, cfg.CentralURL))
	if !phoneHomeSleep(ctx, 5*time.Second) { // let the agent fully start
		return
	}

	// There is no command poller here any more. It could only ever queue one
	// of eleven actions, which named a route this agent does not serve, so it
	// never executed anything — but it carried a forwarder that pasted a
	// caller-supplied string into a request path against a loopback listener
	// serving the WHOLE agent API. Reconciling the vocabularies would have
	// switched that on. Per-host work goes through the panel's per-server
	// resolver, which authenticates, checks ownership and calls the real route.

	go phoneHomeAutoUpdateLoop(ctx, cfg)

	client := &http.Client{}
	checkinURL := cfg.CentralURL + "/api/agent/checkin"
	for {
		info := phoneHomeCollectSystemInfo(c)
		info["server_id"] = cfg.ServerID
		if cfg.CertFingerprint != "" {
			info["cert_fingerprint"] = cfg.CertFingerprint
		}
		body, _ := json.Marshal(info)
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		req, _ := http.NewRequestWithContext(rctx, http.MethodPost, checkinURL, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+cfg.ServerToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		switch {
		case err != nil:
			slog.Warn(fmt.Sprintf("Phone-home checkin error: %v", err))
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			slog.Debug("Phone-home checkin OK")
		default:
			slog.Warn(fmt.Sprintf("Phone-home checkin failed: HTTP %s", resp.Status))
		}
		if resp != nil {
			resp.Body.Close()
		}
		cancel()
		if !phoneHomeSleep(ctx, 60*time.Second) {
			return
		}
	}
}

// phoneHomeAutoUpdateLoop asks the panel every 6 hours whether this agent
// should move, and if so hands the work to the SAME updater the panel-driven
// fleet path uses.
//
// This loop used to download and swap the binary itself: no post-swap
// verification, a .bak nothing read back, staging through /tmp (cross-device
// rename on tmpfs), and a self-restart from inside its own cgroup.
// scripts/agent-self-update.sh does every one of those correctly, is
// checksum-verified, health-verifies, rolls back, and is pinned by tests. So
// nothing in this file touches a binary any more.
func phoneHomeAutoUpdateLoop(ctx context.Context, cfg PhoneHomeConfig) {
	client := &http.Client{}
	versionURL := cfg.CentralURL + "/api/agent/version"
	current := AgentVersion

	// Wait an hour first, so a box that has just been updated is not
	// immediately asked to move again.
	if !phoneHomeSleep(ctx, time.Hour) {
		return
	}
	for {
		target, err := phoneHomeFetchTarget(ctx, client, versionURL, cfg.ServerToken)
		switch {
		case err != nil:
			slog.Warn("Agent auto-update check failed: " + err.Error())
		case target == "":
			slog.Info("Agent auto-update: not enabled by the panel")
		case strings.TrimLeft(target, "v") == current:
			slog.Info("Agent auto-update: already at the panel's target (v" + current + ")")
		default:
			// A failed update leaves the version unchanged, so the comparison
			// stays true for ever. Without this check a target that cannot come
			// up here would repeat download/swap/restart/rollback indefinitely
			// and unattended — and since the rollback restarts this process,
			// at the INITIAL delay (~hourly) on every box. An operator-driven
			// fleet run is not blocked; only the unattended path refuses.
			if why, failed := PhoneHomeTargetAlreadyFailedDestructively(target); failed {
				slog.Warn(fmt.Sprintf("Agent auto-update: NOT retrying %s — an earlier attempt already replaced this binary and had to roll back (%s). Staying on %s. Fix the release, or start a fleet update from the panel to override this.", target, why, current))
			} else {
				slog.Info(fmt.Sprintf("Panel target is %s, running %s — starting self-update", target, current))
				if err := PhoneHomeStartAgentSelfUpdate(target); err != nil {
					slog.Warn("Agent self-update did not start: " + err.Error())
				}
			}
		}
		// Jitter: every agent runs this timer independently, so a fleet
		// restarted together would otherwise all pull from GitHub at once.
		jitter := time.Duration(rand.Uint64N(1800)) * time.Second
		if !phoneHomeSleep(ctx, 6*time.Hour+jitter) {
			return
		}
	}
}

// phoneHomeFetchTarget asks the panel what version this agent should run.
// "" means nothing to do: the panel returns a null target when the operator
// has not enabled auto-update or the channel is on hold — that is how the
// OFF switch reaches a box.
//
// The status check before decoding is the entire point of this function. It
// used to be absent, and an error body is valid JSON: a 401 decoded cleanly,
// the missing field fell back to the running version, and a permanently dead
// auth path looked like a healthy fleet for four releases.
func phoneHomeFetchTarget(ctx context.Context, client *http.Client, versionURL, serverToken string) (string, error) {
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, versionURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+serverToken)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %s", resp.Status)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	s, _ := body["target_version"].(string)
	return strings.TrimSpace(s), nil
}

func phoneHomeSleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
