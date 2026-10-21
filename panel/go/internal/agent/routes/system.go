package routes

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/sensors"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type systemInfo struct {
	Hostname     string   `json:"hostname"`
	Os           string   `json:"os"`
	Kernel       string   `json:"kernel"`
	UptimeSecs   uint64   `json:"uptime_secs"`
	CpuCount     int      `json:"cpu_count"`
	CpuUsage     float32  `json:"cpu_usage"`
	CpuModel     string   `json:"cpu_model"`
	CpuTemp      *float32 `json:"cpu_temp"`
	MemTotalMb   uint64   `json:"mem_total_mb"`
	MemUsedMb    uint64   `json:"mem_used_mb"`
	MemUsagePct  float32  `json:"mem_usage_pct"`
	SwapTotalMb  uint64   `json:"swap_total_mb"`
	SwapUsedMb   uint64   `json:"swap_used_mb"`
	DiskTotalGb  float64  `json:"disk_total_gb"`
	DiskUsedGb   float64  `json:"disk_used_gb"`
	DiskUsagePct float32  `json:"disk_usage_pct"`
	LoadAvg1     float64  `json:"load_avg_1"`
	LoadAvg5     float64  `json:"load_avg_5"`
	LoadAvg15    float64  `json:"load_avg_15"`
	ProcessCount int      `json:"process_count"`
}

type systemProcessInfo struct {
	Pid    uint32  `json:"pid"`
	Name   string  `json:"name"`
	CpuPct float32 `json:"cpu_pct"`
	MemMb  uint64  `json:"mem_mb"`
}

type systemNetworkInfo struct {
	Name    string `json:"name"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
	RxRate  uint64 `json:"rx_rate"`
	TxRate  uint64 `json:"tx_rate"`
}

func registerSystem(r *Router) {
	r.Handle("GET /system/info", r.State.systemHandleInfo)
	r.Handle("GET /system/processes", systemHandleProcesses)
	r.Handle("GET /system/network", r.State.systemHandleNetwork)
	r.Handle("GET /system/disk-io", systemHandleDiskIO)
	r.Handle("GET /system/port-check", systemHandlePortCheck)
	r.Handle("POST /system/cleanup", systemHandleCleanup)
	r.Handle("POST /system/hostname", systemHandleHostname)
}

func (s *State) systemHandleInfo(w http.ResponseWriter, _ *http.Request) {
	// CPU is NOT refreshed here. A per-request refresh measures the interval
	// since whichever unrelated caller last hit this endpoint — and this
	// handler's own work lands inside it — so the answer tracked the request
	// pattern instead of the load. The sampler owns a fixed window.
	var cpuUsage float32
	if s.Cpu != nil {
		cpuUsage = s.Cpu.Usage()
	}
	var memTotal, memUsed, swapTotal, swapUsed uint64
	if vm, err := mem.VirtualMemory(); err == nil {
		memTotal, memUsed = vm.Total, vm.Total-vm.Available // sysinfo: total - available
	}
	if sw, err := mem.SwapMemory(); err == nil {
		swapTotal, swapUsed = sw.Total, sw.Total-sw.Free
	}
	var diskTotal, diskUsed uint64
	if d, err := disk.Usage("/"); err == nil {
		diskTotal, diskUsed = d.Total, d.Total-d.Free // Free = f_bavail (available)
	}
	var la load.AvgStat
	if l, err := load.Avg(); err == nil {
		la = *l
	}
	cpuModel := ""
	if ci, err := cpu.Info(); err == nil && len(ci) > 0 {
		cpuModel = ci[0].ModelName
	}
	cpuCount, _ := cpu.Counts(true)

	// CPU temperature — the highest package/core/tctl reading.
	var cpuTemp *float32
	if temps, _ := sensors.SensorsTemperatures(); len(temps) > 0 {
		for _, t := range temps {
			l := strings.ToLower(t.SensorKey)
			if strings.Contains(l, "core") || strings.Contains(l, "cpu") || strings.Contains(l, "package") || strings.Contains(l, "tctl") {
				v := float32(t.Temperature)
				if cpuTemp == nil || v > *cpuTemp {
					cpuTemp = &v
				}
			}
		}
	}

	hostname, _ := os.Hostname()
	kernel, _ := host.KernelVersion()
	uptime, _ := host.Uptime()
	pct := func(a, b uint64) float32 {
		if b == 0 {
			return 0
		}
		return float32(a) / float32(b) * 100
	}
	writeJSON(w, http.StatusOK, systemInfo{
		Hostname: hostname, Os: services.PhoneHomeLongOSVersion(), Kernel: kernel, UptimeSecs: uptime,
		CpuCount: cpuCount, CpuUsage: cpuUsage, CpuModel: cpuModel, CpuTemp: cpuTemp,
		MemTotalMb: memTotal / 1048576, MemUsedMb: memUsed / 1048576, MemUsagePct: pct(memUsed, memTotal),
		SwapTotalMb: swapTotal / 1048576, SwapUsedMb: swapUsed / 1048576,
		DiskTotalGb: float64(diskTotal) / 1073741824, DiskUsedGb: float64(diskUsed) / 1073741824,
		DiskUsagePct: pct(diskUsed, diskTotal),
		LoadAvg1:     la.Load1, LoadAvg5: la.Load5, LoadAvg15: la.Load15,
		// Counted from /proc directly: a full per-process refresh cost ~70 ms
		// CPU per call and contaminated the CPU window above.
		ProcessCount: services.CpuSamplerProcessCount(),
	})
}

// procSample is one process's line of /proc/<pid>/stat.
type procSample struct {
	name     string
	ticks    uint64 // utime + stime, in clock ticks
	rssPages uint64
}

// procParseStat parses /proc/<pid>/stat. comm sits between the first '(' and
// the LAST ')' because it may itself contain spaces and parentheses.
func procParseStat(line string) (procSample, bool) {
	open, end := strings.IndexByte(line, '('), strings.LastIndexByte(line, ')')
	if open < 0 || end < open {
		return procSample{}, false
	}
	f := strings.Fields(line[end+1:]) // f[0] is field 3 (state)
	if len(f) < 22 {
		return procSample{}, false
	}
	ut, err1 := strconv.ParseUint(f[11], 10, 64)  // field 14
	st, err2 := strconv.ParseUint(f[12], 10, 64)  // field 15
	rss, err3 := strconv.ParseUint(f[21], 10, 64) // field 24
	if err1 != nil || err2 != nil || err3 != nil {
		return procSample{}, false
	}
	return procSample{name: line[open+1 : end], ticks: ut + st, rssPages: rss}, true
}

// procSnapshot reads one stat file per process. gopsutil's per-process
// Percent/Name/MemoryInfo re-read /proc/stat, cpuinfo and cpufreq for every
// process, which made this endpoint cost ~0.6 CPU-seconds per call.
func procSnapshot() map[int32]procSample {
	out := map[int32]procSample{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		if b, err := os.ReadFile("/proc/" + e.Name() + "/stat"); err == nil {
			if s, ok := procParseStat(string(b)); ok {
				out[int32(pid)] = s
			}
		}
	}
	return out
}

// procClockTicks is USER_HZ, fixed at 100 on Linux userspace ABIs.
const procClockTicks = 100

func systemHandleProcesses(w http.ResponseWriter, _ *http.Request) {
	before, t0 := procSnapshot(), time.Now()
	// Brief pause then sample again for accurate CPU readings.
	time.Sleep(200 * time.Millisecond)
	after, secs := procSnapshot(), time.Since(t0).Seconds()
	out := make([]systemProcessInfo, 0, len(after))
	for pid, s := range after {
		prev, ok := before[pid]
		if !ok || s.ticks < prev.ticks {
			continue // started meanwhile, or pid reused
		}
		name := s.name
		if len(name) == 15 { // kernel truncates comm to 15 bytes; take argv[0]
			if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
				if a0, _, _ := strings.Cut(string(b), "\x00"); a0 != "" {
					name = a0[strings.LastIndexByte(a0, '/')+1:]
				}
			}
		}
		pct := float64(s.ticks-prev.ticks) / procClockTicks / secs * 100
		out = append(out, systemProcessInfo{Pid: uint32(pid), Name: name, CpuPct: float32(pct),
			MemMb: s.rssPages * uint64(os.Getpagesize()) / 1048576})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CpuPct > out[j].CpuPct })
	if len(out) > 20 {
		out = out[:20]
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *State) systemHandleNetwork(w http.ResponseWriter, _ *http.Request) {
	counters, _ := gnet.IOCounters(true)
	now := time.Now()
	current := make(map[string][2]uint64, len(counters))
	for _, c := range counters {
		current[c.Name] = [2]uint64{c.BytesRecv, c.BytesSent}
	}

	s.NetMu.Lock()
	defer s.NetMu.Unlock()
	prev := s.NetworkSnp
	s.NetworkSnp = nil

	sub := func(a, b uint64) uint64 {
		if a < b {
			return 0
		}
		return a - b
	}
	ifaces := make([]systemNetworkInfo, 0, len(current))
	for name, cur := range current {
		var rxRate, txRate uint64
		if prev != nil {
			if el := now.Sub(prev.Timestamp).Seconds(); el > 0 {
				if p, ok := prev.Readings[name]; ok {
					rxRate = uint64(float64(sub(cur[0], p[0])) / el)
					txRate = uint64(float64(sub(cur[1], p[1])) / el)
				}
			}
		}
		ifaces = append(ifaces, systemNetworkInfo{Name: name, RxBytes: cur[0], TxBytes: cur[1], RxRate: rxRate, TxRate: txRate})
	}
	s.NetworkSnp = &NetworkSnapshot{Readings: current, Timestamp: now}
	writeJSON(w, http.StatusOK, ifaces)
}

// systemHandleDiskIO: GET /system/disk-io — disk I/O stats from /proc/diskstats.
func systemHandleDiskIO(w http.ResponseWriter, _ *http.Request) {
	r1, w1 := systemReadDiskstats()
	time.Sleep(time.Second)
	r2, w2 := systemReadDiskstats()
	var readRate, writeRate uint64 // sectors * 512 = bytes
	if r2 >= r1 {
		readRate = (r2 - r1) * 512
	}
	if w2 >= w1 {
		writeRate = (w2 - w1) * 512
	}
	writeJSON(w, http.StatusOK, map[string]uint64{
		"read_bytes_sec":  readRate,
		"write_bytes_sec": writeRate,
		"read_total_mb":   (r2 * 512) / (1024 * 1024),
		"write_total_mb":  (w2 * 512) / (1024 * 1024),
	})
}

func systemReadDiskstats() (reads, writes uint64) {
	b, _ := os.ReadFile("/proc/diskstats")
	return systemParseDiskstats(string(b))
}

func systemParseDiskstats(content string) (reads, writes uint64) {
	for _, line := range strings.Split(content, "\n") {
		p := strings.Fields(line)
		if len(p) < 14 {
			continue
		}
		dev := p[2]
		// Only count main block devices, not partitions.
		isMain := (strings.HasPrefix(dev, "sd") && len(dev) == 3) ||
			(strings.HasPrefix(dev, "vd") && len(dev) == 3) ||
			(strings.HasPrefix(dev, "xvd") && len(dev) == 4) ||
			(strings.HasPrefix(dev, "nvme") && strings.Contains(dev, "n") && !strings.Contains(dev, "p"))
		if isMain {
			r, _ := strconv.ParseUint(p[5], 10, 64)  // sectors read
			wr, _ := strconv.ParseUint(p[9], 10, 64) // sectors written
			reads += r
			writes += wr
		}
	}
	return
}

// systemHandleCleanup: POST /system/cleanup — free disk space by clearing
// caches and temp files. A step counts when it could be run at all (Rust
// `.output().is_ok()`), not on its exit status.
func systemHandleCleanup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	freed := []string{}
	// apt cache — unsandboxed because /var/cache/apt is outside the unit's
	// ReadWritePaths and apt-get clean would silently no-op.
	if _, err := safecmd.NewUnsandboxed("apt-get").Arg("clean").Output(ctx); err == nil {
		freed = append(freed, "apt cache")
	}
	if _, err := safecmd.Exec(ctx, "journalctl", "--vacuum-time=3d"); err == nil {
		freed = append(freed, "old journal logs")
	}
	if _, err := safecmd.Exec(ctx, "find", "/tmp", "-type", "f", "-mtime", "+7", "-delete"); err == nil {
		freed = append(freed, "old temp files")
	}
	if _, err := safecmd.Exec(ctx, "docker", "image", "prune", "-f"); err == nil {
		freed = append(freed, "dangling Docker images")
	}

	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	diskAfter := ""
	if out, err := safecmd.Exec(dctx, "df", "-h", "/"); err == nil {
		if l, ok := telemetryLine(strings.ToValidUTF8(string(out.Stdout), "�"), 1); ok {
			diskAfter = l
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"cleaned": freed, "disk_after": diskAfter})
}

// systemHandleHostname: POST /system/hostname — change the server hostname.
func systemHandleHostname(w http.ResponseWriter, r *http.Request) {
	var body any
	if !decodeJSON(w, r, &body) {
		return
	}
	hostname := ""
	if m, ok := body.(map[string]any); ok {
		hostname, _ = m["hostname"].(string)
	}
	if !systemValidHostname(hostname) {
		writeErr(w, http.StatusBadRequest, "Invalid hostname")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, _ = safecmd.Exec(ctx, "hostnamectl", "set-hostname", hostname)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "hostname": hostname})
}

func systemValidHostname(h string) bool {
	if h == "" || len(h) > 63 {
		return false
	}
	for _, c := range h {
		if !isASCIIAlnum(c) && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// systemHandlePortCheck: GET /system/port-check?port=8080 — is this host
// port free to publish on? A port can be held by something DockPanel doesn't
// manage, and only the host knows. Probes 127.0.0.1 because that is exactly
// where docker_apps deploy publishes, so a successful bind is evidence about
// the same address the container will contend for.
func systemHandlePortCheck(w http.ResponseWriter, r *http.Request) {
	port, ok := systemParsePort(r.URL.Query().Get("port"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "port must be 1-65535")
		return
	}
	// Binding and immediately closing is the only honest test.
	free := false
	if l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
		free = true
		l.Close()
	}
	writeJSON(w, http.StatusOK, map[string]any{"port": port, "free": free})
}

// systemParsePort mirrors Rust's u16 parse (an optional leading '+') and > 0.
func systemParsePort(s string) (uint16, bool) {
	s = strings.TrimPrefix(s, "+")
	if s == "" || s[0] == '+' || s[0] == '-' {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint16(n), true
}
