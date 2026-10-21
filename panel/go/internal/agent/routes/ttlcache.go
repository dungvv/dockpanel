package routes

import (
	"sync"
	"time"
)

// ttlCache memoizes one expensive result for ttl. The lock is held while
// computing, so concurrent callers (the dashboard polls several endpoints at
// once) share a single run instead of each forking the same commands.
type ttlCache[T any] struct {
	ttl time.Duration
	mu  sync.Mutex
	at  time.Time
	v   T
}

func (c *ttlCache[T]) get(compute func() T) T {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() || time.Since(c.at) >= c.ttl {
		c.v, c.at = compute(), time.Now()
	}
	return c.v
}

// reset forces the next get to recompute (after a change that alters the answer).
func (c *ttlCache[T]) reset() {
	c.mu.Lock()
	c.at = time.Time{}
	c.mu.Unlock()
}
