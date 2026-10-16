package sitelock

import (
	"slices"
	"sync"
	"testing"
	"time"
)

func TestTwoLocksOnTheSameKeySerialize(t *testing.T) {
	var mu sync.Mutex
	var order []string
	push := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }

	started := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer LockSite("same.example")()
		push("first-in")
		close(started)
		time.Sleep(50 * time.Millisecond)
		push("first-out")
	}()
	<-started
	go func() {
		defer wg.Done()
		defer LockSite("same.example")()
		push("second-in")
	}()
	wg.Wait()
	// "second-in" must never precede "first-out".
	if want := []string{"first-in", "first-out", "second-in"}; !slices.Equal(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

func TestDifferentKeysDoNotBlockEachOther(t *testing.T) {
	defer LockSite("a.example")()
	done := make(chan struct{})
	go func() { LockSite("b.example")(); close(done) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("lock on a different key blocked — keys are not independent")
	}
}

func TestLockSitesSameDomainTakesOneLock(t *testing.T) {
	done := make(chan struct{})
	go func() { LockSites("same.example", "same.example")(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("same-key pair self-deadlocked")
	}
}

func TestLockSitesOppositeArgumentOrderDoesNotDeadlock(t *testing.T) {
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 200; i++ {
			wg.Add(2)
			go func() { defer wg.Done(); LockSites("alpha.example", "beta.example")() }()
			go func() { defer wg.Done(); LockSites("beta.example", "alpha.example")() }()
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("LockSites deadlocked on opposite argument order")
	}
}
