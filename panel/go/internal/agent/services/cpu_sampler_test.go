package services

import (
	"os"
	"runtime"
	"testing"

	"github.com/shirou/gopsutil/v4/cpu"
)

// The whole point of the module: the window is a constant, above the
// threshold below which a delta is skipped/noise.
func TestCpuSamplerSampleIntervalExceedsMinimum(t *testing.T) {
	if CpuSamplerSampleInterval <= cpuSamplerMinInterval || cpuSamplerPrimeDelay <= cpuSamplerMinInterval {
		t.Fatal("sample interval and prime delay must exceed the 200 ms minimum")
	}
}

func TestCpuSamplerUsageRoundTripsThroughTheAtomic(t *testing.T) {
	s := NewCpuSampler()
	if s.Usage() != 0 {
		t.Fatal("a fresh sampler reports 0, not garbage")
	}
	s.publish(37.5)
	if s.Usage() != 37.5 {
		t.Fatal("round trip")
	}
	shared := s // handlers share the pointer
	s.publish(4.25)
	if shared.Usage() != 4.25 {
		t.Fatal("shared handle must see the sampler's writes")
	}
}

func TestCpuSamplerUsageDelta(t *testing.T) {
	a := cpu.TimesStat{User: 10, Idle: 90}
	b := cpu.TimesStat{User: 35, Idle: 165} // +25 busy, +75 idle
	if got := cpuSamplerUsage(a, b); got != 25 {
		t.Fatalf("usage = %v, want 25", got)
	}
	if cpuSamplerUsage(b, b) != 0 {
		t.Fatal("zero window must report 0")
	}
}

func TestCpuSamplerProcessCountIsPlausibleAndDigitFiltered(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc")
	}
	n := CpuSamplerProcessCount()
	if n == 0 {
		t.Fatal("process count returned 0 on a live system")
	}
	all, _ := os.ReadDir("/proc")
	if n >= len(all) {
		t.Fatalf("count (%d) should exclude non-pid entries in /proc (%d)", n, len(all))
	}
}
