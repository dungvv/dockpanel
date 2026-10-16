package api

// Port of panel/backend/src/services/metrics_collector.rs — collects system
// metrics every 30 seconds for the historical charts.
//
// Why this iterates the fleet: per-host telemetry lived in two stores written
// by mutually exclusive halves of the fleet, so every consumer was blind to
// one half.
//
//   - servers.{cpu_usage, mem_used_mb, ram_mb, disk_usage_pct, …} is written
//     ONLY by the check-in handler, reached only by an agent's phone-home loop
//     — which needs an agent.env that only install-agent.sh writes. The panel's
//     own box has none, so its row was NULL in every column, for ever: the
//     CPU/memory/disk alerts never evaluated for the host the API runs on (on a
//     single-server install, the only host), and auto_clean_disk never ran.
//   - metrics_history was written ONLY here, for the is_local id, so members
//     had zero rows: no memory-leak trend, 144 empty uptime buckets, no
//     Prometheus series, blank fleet-overview columns.
//
// So this collector reads every online server through its OWN agent and is the
// single writer of metrics_history for all of them — and, for the local row
// only, also writes the scalar columns a member reports by phoning home.
//
// ⚠ It deliberately does NOT write last_seen_at: server_monitor sweeps that
// column, and `status = 'online'` gates OnlineFleet and the alert engine — a
// two-minute stall in the panel's own agent would drop the panel host out of
// every scanner at once.

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MetricsCollectorRun ticks every 30s (first tick immediately).
func MetricsCollectorRun(ctx context.Context, db *pgxpool.Pool, agents *AgentRegistry) {
	slog.Info("Metrics collector started (30s interval, fleet-wide)")
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	localFailures := 0
	for first := true; ; first = false {
		if !first {
			select {
			case <-t.C:
			case <-ctx.Done():
				slog.Info("Metrics collector shutting down gracefully")
				return
			}
		}

		// Concurrently, not serially: N hosts must not take N round trips
		// inside a 30-second tick.
		fleet := agents.OnlineFleet(ctx)
		results := make([]bool, len(fleet))
		var wg sync.WaitGroup
		for i := range fleet {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i] = metricsCollectorCollectOne(ctx, db, &fleet[i])
			}()
		}
		wg.Wait()

		// The pre-existing "agent unreachable" signal is about the LOCAL agent;
		// an unreachable member is OnlineFleet's business, not this alarm's.
		for i, m := range fleet {
			if !m.IsLocal {
				continue
			}
			if results[i] {
				localFailures = 0
			} else {
				localFailures++
				if localFailures == 3 {
					SystemLogLogEvent(ctx, db, "warning", "metrics_collector", "Agent unreachable for 3+ consecutive checks", nil)
				}
			}
			break
		}

		// Retention is a property of the table, not of a host: unscoped.
		_, _ = execSQL(ctx, db, "DELETE FROM metrics_history WHERE created_at < NOW() - INTERVAL '7 days'")
		_, _ = execSQL(ctx, db, "DELETE FROM gpu_metrics_history WHERE created_at < NOW() - INTERVAL '7 days'")
	}
}

func metricsCollectorF64(v any) float64 {
	f, _ := jsonF64(v)
	return f
}

func metricsCollectorOptI32(v any, isFloat bool) *int32 {
	var n int32
	if isFloat {
		f, ok := jsonF64(v)
		if !ok {
			return nil
		}
		n = int32(f)
	} else {
		i, ok := jsonI64(v)
		if !ok {
			return nil
		}
		n = int32(i)
	}
	return &n
}

// metricsCollectorCollectOne reads one server through its own agent. Returns
// whether the system-info read succeeded.
func metricsCollectorCollectOne(ctx context.Context, db *pgxpool.Pool, m *AgentFleetMember) bool {
	var info, gpuInfo any
	var sysErr, gpuErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); info, sysErr = m.Agent.Get(ctx, "/system/info") }()
	go func() { defer wg.Done(); gpuInfo, gpuErr = m.Agent.Get(ctx, "/apps/gpu-info") }()
	wg.Wait()
	if sysErr != nil {
		slog.Warn("Metrics collector: agent unreachable for " + m.Name + ": " + sysErr.Error())
		return false
	}

	cpu := float32(metricsCollectorF64(jsonGet(info, "cpu_usage")))
	mem := float32(metricsCollectorF64(jsonGet(info, "mem_usage_pct")))
	disk := float32(metricsCollectorF64(jsonGet(info, "disk_usage_pct")))
	if _, err := execSQL(ctx, db,
		"INSERT INTO metrics_history (cpu_pct, mem_pct, disk_pct, server_id) VALUES ($1, $2, $3, $4)",
		cpu, mem, disk, m.ID); err != nil {
		slog.Error("Failed to store metrics for " + m.Name + ": " + err.Error())
	}

	// The local row has no check-in to populate its scalar columns, so this is
	// the only place they can come from — same field names as the check-in
	// payload, same agent endpoint, so the two paths agree.
	if m.IsLocal {
		var memUsedMB, uptimeSecs *int64
		if v, ok := jsonI64(jsonGet(info, "mem_used_mb")); ok {
			memUsedMB = &v
		}
		if v, ok := jsonI64(jsonGet(info, "uptime_secs")); ok {
			uptimeSecs = &v
		}
		ramMB := metricsCollectorOptI32(jsonGet(info, "mem_total_mb"), false)
		cpuCores := metricsCollectorOptI32(jsonGet(info, "cpu_count"), false)
		diskGB := metricsCollectorOptI32(jsonGet(info, "disk_total_gb"), true)
		diskUsedGB := metricsCollectorOptI32(jsonGet(info, "disk_used_gb"), true)
		if _, err := execSQL(ctx, db,
			"UPDATE servers SET "+
				"cpu_usage = $2, "+
				"mem_used_mb = $3, "+
				"ram_mb = COALESCE($4, ram_mb), "+
				"mem_usage_pct = $5, "+
				"disk_usage_pct = $6, "+
				"cpu_cores = COALESCE($7, cpu_cores), "+
				"uptime_secs = $8, "+
				"disk_gb = COALESCE($9, disk_gb), "+
				"disk_used_gb = $10 "+
				"WHERE id = $1",
			m.ID, cpu, memUsedMB, ramMB, mem, disk, cpuCores, uptimeSecs, diskGB, diskUsedGB); err != nil {
			slog.Error("Failed to store local server metrics: " + err.Error())
		}
	}

	// GPU metrics, if any.
	if gpuErr == nil {
		if avail, _ := jsonBool(jsonGet(gpuInfo, "available")); avail {
			gpus, _ := jsonArr(jsonGet(gpuInfo, "gpus"))
			for _, g := range gpus {
				idx, _ := jsonI64(jsonGet(g, "index"))
				var temp, power *float32
				if v, ok := jsonF64(jsonGet(g, "temperature_c")); ok {
					f := float32(v)
					temp = &f
				}
				if v, ok := jsonF64(jsonGet(g, "power_draw_w")); ok {
					f := float32(v)
					power = &f
				}
				if _, err := execSQL(ctx, db,
					"INSERT INTO gpu_metrics_history "+
						"(gpu_index, utilization_pct, memory_used_mb, memory_total_mb, temperature_c, power_draw_w, server_id) "+
						"VALUES ($1, $2, $3, $4, $5, $6, $7)",
					int16(idx),
					float32(metricsCollectorF64(jsonGet(g, "utilization_gpu_pct"))),
					float32(metricsCollectorF64(jsonGet(g, "memory_used_mb"))),
					float32(metricsCollectorF64(jsonGet(g, "memory_total_mb"))),
					temp, power, m.ID); err != nil {
					slog.Error("Failed to store GPU metrics for " + m.Name + ": " + err.Error())
				}
			}
		}
	}
	return true
}
