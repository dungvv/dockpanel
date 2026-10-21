package routes

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTTLCacheReusesResetsAndExpires(t *testing.T) {
	var runs atomic.Int32
	compute := func() int { time.Sleep(20 * time.Millisecond); return int(runs.Add(1)) }
	c := ttlCache[int]{ttl: 150 * time.Millisecond}

	// Concurrent first callers share one computation.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); c.get(compute) }()
	}
	wg.Wait()
	if got := c.get(compute); got != 1 || runs.Load() != 1 {
		t.Fatalf("within ttl: got %d after %d runs, want 1 run", got, runs.Load())
	}

	c.reset()
	if got := c.get(compute); got != 2 {
		t.Fatalf("after reset: got %d, want a fresh run (2)", got)
	}

	time.Sleep(160 * time.Millisecond)
	if got := c.get(compute); got != 3 {
		t.Fatalf("after expiry: got %d, want a fresh run (3)", got)
	}
}
