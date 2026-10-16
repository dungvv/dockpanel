// Package sitelock is per-site concurrency control (src/site_lock.rs).
//
// A fan-out audit found that WordPress hardening writes wp-config.php while
// update-with-rollback independently snapshots/updates/rolls back the SAME
// tree with no coordination — a concurrent hardening call could be silently
// discarded by a rollback whose snapshot predates it. Backup restore, staging
// sync/clone/delete, git deploy, Docker-app domain expose/unexpose, volume
// restore and single-file restore had the identical gap. This is the one
// shared fix.
//
// Every operation that mutates a site's on-disk files takes LockSite (or
// LockSites for a two-site operation like staging clone/sync) for the FULL
// duration of the mutation. It is intentionally a single in-process
// registry, not per-subsystem locks — two DIFFERENT subsystems touching the
// same site must serialize against each other too.
//
// Do not acquire a second lock from inside a function that already holds one
// for the same key — the mutex is not reentrant and a nested same-key acquire
// deadlocks (git deploy calls blue-green update internally; only the outer
// call takes the lock).
package sitelock

import "sync"

var (
	registryMu sync.Mutex
	registry   = map[string]*sync.Mutex{}
)

func entry(key string) *sync.Mutex {
	// registryMu only guards a map lookup/insert, never a site mutation, so
	// it is held for nanoseconds.
	registryMu.Lock()
	defer registryMu.Unlock()
	m, ok := registry[key]
	if !ok {
		m = &sync.Mutex{}
		registry[key] = m
	}
	return m
}

// LockSite acquires the sole in-process lock for key and returns its unlock
// function: `defer sitelock.LockSite(domain)()`.
//
// key is namespaced by caller convention: a plain domain for every
// WordPress/backup/staging site operation, and "git-deploy:{name}" for git
// deploys, which are keyed by deployment name and would otherwise risk
// colliding with an unrelated domain-keyed lock.
func LockSite(key string) (unlock func()) {
	m := entry(key)
	m.Lock()
	return m.Unlock
}

// LockSites locks two sites (e.g. staging source+target) in a fixed,
// key-sorted order — never argument order — so two concurrent operations
// naming the same pair in opposite directions cannot deadlock.
func LockSites(a, b string) (unlock func()) {
	if a == b {
		return LockSite(a)
	}
	if a > b {
		a, b = b, a
	}
	ua := LockSite(a)
	ub := LockSite(b)
	return func() { ub(); ua() }
}
