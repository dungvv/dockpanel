package routes

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

func registerDiagnostics(r *Router) {
	r.Handle("GET /diagnostics", diagnosticsRun)
	r.Handle("POST /diagnostics/fix", diagnosticsApplyFix)
	r.Handle("GET /diagnostics/recommendations", diagnosticsRecommendations)
}

// GET /diagnostics — Run all diagnostic checks.
func diagnosticsRun(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, services.DiagnosticsRun())
}

// POST /diagnostics/fix — Apply a one-click fix.
func diagnosticsApplyFix(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FixID *string `json:"fix_id"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	// fix_id is a required String in Rust: missing/null is axum's 422.
	if body.FixID == nil {
		http.Error(w, "Failed to deserialize the JSON body into the target type: missing field `fix_id`", http.StatusUnprocessableEntity)
		return
	}
	// Validate fix_id format (action:target)
	if *body.FixID == "" || len(*body.FixID) > 256 {
		writeErr(w, http.StatusBadRequest, "Invalid fix_id")
		return
	}
	msg, err := services.DiagnosticsApplyFix(*body.FixID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": msg})
}

func diagnosticsExec(timeout time.Duration, bin string, args ...string) (safecmd.Output, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return safecmd.Exec(ctx, bin, args...)
}

// diagnosticsLines mirrors Rust str::lines.
func diagnosticsLines(s string) []string {
	if s == "" {
		return nil
	}
	ls := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i, l := range ls {
		ls[i] = strings.TrimSuffix(l, "\r")
	}
	return ls
}

// diagnosticsFirst returns the first line satisfying ok.
func diagnosticsFirst(lines []string, ok func(string) bool) (string, bool) {
	for _, l := range lines {
		if ok(l) {
			return l, true
		}
	}
	return "", false
}

// diagnosticsAfterEq is `l.split('=').nth(1)`.
func diagnosticsAfterEq(l string) (string, bool) {
	parts := strings.Split(l, "=")
	if len(parts) < 2 {
		return "", false
	}
	return parts[1], true
}

// diagnosticsParseFreeM parses `free -m`: the second line's numeric columns
// (unparseable ones skipped, as filter_map did) → total, available.
func diagnosticsParseFreeM(out string) (total, avail uint64) {
	ls := diagnosticsLines(out)
	if len(ls) < 2 {
		return 0, 0
	}
	var parts []uint64
	for i, f := range strings.Fields(ls[1]) {
		if i == 0 {
			continue
		}
		if v, err := strconv.ParseUint(f, 10, 64); err == nil {
			parts = append(parts, v)
		}
	}
	if len(parts) > 0 {
		total = parts[0]
	}
	if len(parts) > 5 {
		avail = parts[5]
	}
	return total, avail
}

// diagnosticsPhpPool returns a pool file's pm.max_children (default 5) and
// memory_limit in MB (default 256). Only the FIRST matching line counts.
func diagnosticsPhpPool(content string) (maxChildren, memory uint32) {
	maxChildren, memory = 5, 256
	ls := diagnosticsLines(content)
	if l, ok := diagnosticsFirst(ls, func(l string) bool { return strings.HasPrefix(l, "pm.max_children") }); ok {
		if v, ok := diagnosticsAfterEq(l); ok {
			if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32); err == nil {
				maxChildren = uint32(n)
			}
		}
	}
	if l, ok := diagnosticsFirst(ls, func(l string) bool { return strings.Contains(l, "memory_limit") }); ok {
		if v, ok := diagnosticsAfterEq(l); ok {
			if n, err := strconv.ParseUint(strings.TrimRight(strings.TrimSpace(v), "M"), 10, 32); err == nil {
				memory = uint32(n)
			}
		}
	}
	return maxChildren, memory
}

// diagnosticsNginxWorkers parses the first uncommented worker_processes
// directive; "auto" or absent → 0.
func diagnosticsNginxWorkers(conf string) uint32 {
	l, ok := diagnosticsFirst(diagnosticsLines(conf), func(l string) bool {
		return strings.Contains(l, "worker_processes") && !strings.HasPrefix(strings.TrimLeftFunc(l, unicode.IsSpace), "#")
	})
	if !ok {
		return 0
	}
	f := strings.Fields(l)
	if len(f) < 2 {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimRight(f[1], ";"), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

type diagnosticsRec map[string]any

// GET /diagnostics/recommendations — Auto-optimization recommendations.
func diagnosticsRecommendations(w http.ResponseWriter, _ *http.Request) {
	recs := []diagnosticsRec{}

	// 1. System memory analysis
	var totalMemMB, availMemMB uint64
	if out, err := diagnosticsExec(5*time.Second, "free", "-m"); err == nil {
		totalMemMB, availMemMB = diagnosticsParseFreeM(strings.ToValidUTF8(string(out.Stdout), "�"))
	}

	// 2. CPU count
	cpus := uint32(1)
	if out, err := diagnosticsExec(3*time.Second, "nproc"); err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(string(out.Stdout)), 10, 32); err == nil {
			cpus = uint32(n)
		}
	}

	// 3. PHP-FPM pool analysis
	if versions, err := os.ReadDir("/etc/php"); err == nil {
		for _, ver := range versions {
			poolDir := filepath.Join("/etc/php", ver.Name(), "fpm/pool.d")
			if _, err := os.Stat(poolDir); err != nil {
				continue
			}
			pools, err := os.ReadDir(poolDir)
			if err != nil {
				continue
			}
			var totalMaxChildren, totalMemoryPerWorker, poolCount uint32
			for _, p := range pools {
				raw, err := os.ReadFile(filepath.Join(poolDir, p.Name()))
				if err != nil || !utf8.Valid(raw) {
					continue
				}
				mc, mem := diagnosticsPhpPool(string(raw))
				totalMaxChildren += mc
				totalMemoryPerWorker += mem
				poolCount++
			}
			if poolCount == 0 {
				continue
			}
			avgMemory := totalMemoryPerWorker / poolCount
			maxPossibleMB := uint64(totalMaxChildren) * uint64(avgMemory)

			// Check if PHP workers could OOM the system. avgMemory == 0 (every
			// pool at memory_limit=0M) divides by zero, as in Rust: the
			// handler panics and the connection is dropped.
			if maxPossibleMB > totalMemMB*80/100 {
				safeWorkers := (totalMemMB * 60 / 100) / uint64(avgMemory)
				recs = append(recs, diagnosticsRec{
					"category": "php",
					"severity": "warning",
					"title":    "PHP workers may exhaust memory",
					"description": fmt.Sprintf("Total max PHP workers (%d) × %dMB = %dMB, but system only has %dMB RAM. Reduce to ~%d total workers or lower memory_limit.",
						totalMaxChildren, avgMemory, maxPossibleMB, totalMemMB, safeWorkers),
					"current":     fmt.Sprintf("%d workers × %dMB", totalMaxChildren, avgMemory),
					"recommended": fmt.Sprintf("%d workers × %dMB", safeWorkers, avgMemory),
				})
			}

			// Suggest OPcache if not configured
			recs = append(recs, diagnosticsRec{
				"category":    "php",
				"severity":    "info",
				"title":       "Ensure OPcache is enabled",
				"description": "OPcache caches compiled PHP bytecode, reducing CPU usage by 50-70% for repeat requests.",
				"current":     "Check with phpinfo()",
				"recommended": "opcache.enable=1, opcache.memory=128MB",
			})
		}
	}

	// 4. Nginx worker analysis
	nginxConfRaw, _ := os.ReadFile("/etc/nginx/nginx.conf")
	nginxConf := ""
	if utf8.Valid(nginxConfRaw) {
		nginxConf = string(nginxConfRaw)
	}
	nginxWorkers := diagnosticsNginxWorkers(nginxConf)
	if nginxWorkers > 0 && nginxWorkers != cpus {
		severity := "info"
		if nginxWorkers < cpus {
			severity = "warning"
		}
		recs = append(recs, diagnosticsRec{
			"category":    "nginx",
			"severity":    severity,
			"title":       "Nginx worker count doesn't match CPU cores",
			"description": fmt.Sprintf("nginx has %d workers but system has %d CPUs. Set to 'auto' or %d.", nginxWorkers, cpus, cpus),
			"current":     fmt.Sprintf("%d workers", nginxWorkers),
			"recommended": fmt.Sprintf("%d workers (or 'auto')", cpus),
		})
	}

	// 5. Swap recommendation
	if availMemMB < totalMemMB/4 && totalMemMB > 0 {
		recs = append(recs, diagnosticsRec{
			"category":    "system",
			"severity":    "warning",
			"title":       "Low available memory",
			"description": fmt.Sprintf("Only %dMB available out of %dMB. Consider adding swap or reducing services.", availMemMB, totalMemMB),
			"current":     fmt.Sprintf("%dMB available", availMemMB),
			"recommended": "Ensure at least 25% memory is free",
		})
	}

	// 6. Gzip recommendation (check if already enabled)
	if !strings.Contains(nginxConf, "gzip on") {
		recs = append(recs, diagnosticsRec{
			"category":    "nginx",
			"severity":    "warning",
			"title":       "Gzip compression not enabled globally",
			"description": "Enable gzip in nginx.conf for 60-80% bandwidth savings on text assets.",
			"current":     "gzip off",
			"recommended": "gzip on; gzip_types text/plain text/css application/json application/javascript;",
		})
	}

	// 7. Disk usage recommendations
	if out, err := diagnosticsExec(5*time.Second, "df", "--output=pcent", "/"); err == nil {
		if ls := diagnosticsLines(strings.ToValidUTF8(string(out.Stdout), "�")); len(ls) > 1 {
			if pct, err := strconv.ParseUint(strings.TrimRight(strings.TrimSpace(ls[1]), "%"), 10, 32); err == nil && pct > 80 {
				severity := "warning"
				if pct > 90 {
					severity = "critical"
				}
				recs = append(recs, diagnosticsRec{
					"category":    "system",
					"severity":    severity,
					"title":       "Disk usage is high",
					"description": fmt.Sprintf("Root partition is %d%% full. Clean up old backups, logs, or Docker images.", pct),
					"current":     fmt.Sprintf("%d%% used", pct),
					"recommended": "Keep below 80%",
				})
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"recommendations": recs,
		"total":           len(recs),
		"system": map[string]any{
			"total_memory_mb":     totalMemMB,
			"available_memory_mb": availMemMB,
			"cpus":                cpus,
		},
	})
}
