// Whole-system CPU usage, sampled on a fixed cadence.
//
// CPU percentage is a delta over a window, not a readable instant value.
// Refreshing inside the request handler makes the window "time since
// whichever unrelated caller last hit this endpoint" — the agent has five
// such callers (metrics collector every 30 s, dashboard WebSocket every ~5 s,
// dashboard REST tick, backup scheduler, Docker-apps page), so each silently
// corrupted the others' window. Short windows were dominated by the agent's
// own /proc walk (~28 % self-inflicted on a single-core box — how an idle box
// reported ~99 %), and windows under sysinfo's 200 ms minimum silently
// returned a stale value.
//
// So the sampler owns the window: one goroutine, a fixed interval, publishing
// to an atomic that handlers read for free.

package services

import (
	"math"
	"os"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
)

// CpuSamplerSampleInterval is the interval between samples and therefore the
// averaging window of every published value. Must stay comfortably above the
// kernel's tick granularity / sysinfo's 200 ms minimum, below which a delta
// is noise.
const CpuSamplerSampleInterval = 2 * time.Second

// cpuSamplerPrimeDelay primes the first real sample at startup, so a true (if
// short-windowed) reading is published a moment after boot instead of zero.
const cpuSamplerPrimeDelay = 300 * time.Millisecond

// cpuSamplerMinInterval mirrors sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.
const cpuSamplerMinInterval = 200 * time.Millisecond

// CpuSampler is a handle to the latest whole-system CPU usage, 0-100. Free
// to read — the value is a float32 stored as its bit pattern, so readers
// never block the sampler or each other. Share by pointer.
type CpuSampler struct {
	value atomic.Uint32
}

// NewCpuSampler returns a sampler reporting 0 until Spawn's first sample.
func NewCpuSampler() *CpuSampler { return &CpuSampler{} }

// Usage is the latest sample, averaged over the preceding
// CpuSamplerSampleInterval. 0.0 until the first sample lands (~300 ms).
func (c *CpuSampler) Usage() float32 { return math.Float32frombits(c.value.Load()) }

func (c *CpuSampler) publish(u float32) { c.value.Store(math.Float32bits(u)) }

// Spawn starts the sampling loop. Call once, at startup. Reading the
// aggregate /proc/stat line is all one sample costs, so the sampler does not
// meaningfully appear in its own measurement.
func (c *CpuSampler) Spawn() {
	go func() {
		// The first read is the baseline; it has no predecessor to diff
		// against, so it is not a measurement of anything.
		prev, _ := cpuSamplerRead()
		time.Sleep(cpuSamplerPrimeDelay)
		cur, ok := cpuSamplerRead()
		if ok {
			c.publish(cpuSamplerUsage(prev, cur))
			prev = cur
		}
		t := time.NewTicker(CpuSamplerSampleInterval)
		defer t.Stop()
		for range t.C {
			if cur, ok := cpuSamplerRead(); ok {
				c.publish(cpuSamplerUsage(prev, cur))
				prev = cur
			}
		}
	}()
}

func cpuSamplerRead() (cpu.TimesStat, bool) {
	ts, err := cpu.Times(false)
	if err != nil || len(ts) == 0 {
		return cpu.TimesStat{}, false
	}
	return ts[0], true
}

// cpuSamplerUsage is busy/total over the delta, with idle+iowait as idle
// (sysinfo's definition).
func cpuSamplerUsage(a, b cpu.TimesStat) float32 {
	idle := func(t cpu.TimesStat) float64 { return t.Idle + t.Iowait }
	// Guest time is already included in User/Nice on Linux.
	total := func(t cpu.TimesStat) float64 {
		return t.User + t.Nice + t.System + t.Idle + t.Iowait + t.Irq + t.Softirq + t.Steal
	}
	dt := total(b) - total(a)
	if dt <= 0 {
		return 0
	}
	u := (dt - (idle(b) - idle(a))) / dt * 100
	return float32(math.Max(0, math.Min(100, u)))
}

// CpuSamplerProcessCount is the number of running processes, without walking
// every /proc entry's stats. A full sysinfo process refresh was both
// /system/info's dominant cost (~70 ms CPU per call) and the contaminant in
// the CPU window above, so the count comes from listing the directory.
func CpuSamplerProcessCount() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if cpuSamplerAllDigits(e.Name()) {
			n++
		}
	}
	return n
}

func cpuSamplerAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true // Rust's all() on "" is true too
}
