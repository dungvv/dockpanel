package api

// Port of panel/backend/src/services/prometheus_exporter.rs — Prometheus text
// exposition (v0.0.4) of the latest metrics_history / gpu_metrics_history /
// sites / alerts snapshot. One scrape = a handful of indexed queries; the
// metrics collector writes fresh rows every 30s, well inside the usual
// 15-60s scrape interval.

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PrometheusExporterRender renders the current snapshot. Query failures render
// as missing sections, never as an error (the scrape still answers).
func PrometheusExporterRender(ctx context.Context, db *pgxpool.Pool) string {
	var out strings.Builder
	out.Grow(4096)
	prometheusExporterRenderInfo(&out)
	prometheusExporterRenderSystem(ctx, &out, db)
	prometheusExporterRenderGPU(ctx, &out, db)
	prometheusExporterRenderSites(ctx, &out, db)
	prometheusExporterRenderCertRenewals(&out)
	prometheusExporterRenderAlerts(ctx, &out, db)
	return out.String()
}

func prometheusExporterRenderInfo(out *strings.Builder) {
	out.WriteString("# HELP dockpanel_info DockPanel build information.\n")
	out.WriteString("# TYPE dockpanel_info gauge\n")
	out.WriteString("dockpanel_info{version=\"")
	prometheusExporterPushEscaped(out, Version)
	out.WriteString("\"} 1\n")
}

func prometheusExporterRenderSystem(ctx context.Context, out *strings.Builder, db *pgxpool.Pool) {
	rows, _ := queryAll[Tup5[uuid.UUID, string, float32, float32, float32]](ctx, db,
		"SELECT DISTINCT ON (m.server_id) m.server_id, s.name, "+
			"m.cpu_pct, m.mem_pct, m.disk_pct "+
			"FROM metrics_history m "+
			"JOIN servers s ON s.id = m.server_id "+
			"WHERE m.server_id IS NOT NULL "+
			"ORDER BY m.server_id, m.created_at DESC")
	if len(rows) == 0 {
		return
	}
	out.WriteString("# HELP dockpanel_cpu_percent Current CPU usage (0-100).\n")
	out.WriteString("# TYPE dockpanel_cpu_percent gauge\n")
	for _, r := range rows {
		prometheusExporterWriteServerSample(out, "dockpanel_cpu_percent", r.A, r.B, r.C)
	}
	out.WriteString("# HELP dockpanel_memory_percent Current memory usage (0-100).\n")
	out.WriteString("# TYPE dockpanel_memory_percent gauge\n")
	for _, r := range rows {
		prometheusExporterWriteServerSample(out, "dockpanel_memory_percent", r.A, r.B, r.D)
	}
	out.WriteString("# HELP dockpanel_disk_percent Current disk usage (0-100).\n")
	out.WriteString("# TYPE dockpanel_disk_percent gauge\n")
	for _, r := range rows {
		prometheusExporterWriteServerSample(out, "dockpanel_disk_percent", r.A, r.B, r.E)
	}
}

type prometheusExporterGPURow struct {
	ServerID       uuid.UUID `db:"server_id"`
	Name           string    `db:"name"`
	GPUIndex       int16     `db:"gpu_index"`
	UtilizationPct float32   `db:"utilization_pct"`
	MemoryUsedMB   float32   `db:"memory_used_mb"`
	MemoryTotalMB  float32   `db:"memory_total_mb"`
	TemperatureC   *float32  `db:"temperature_c"`
	PowerDrawW     *float32  `db:"power_draw_w"`
}

func prometheusExporterRenderGPU(ctx context.Context, out *strings.Builder, db *pgxpool.Pool) {
	rows, _ := queryAll[prometheusExporterGPURow](ctx, db,
		"SELECT DISTINCT ON (g.server_id, g.gpu_index) "+
			"g.server_id, s.name, g.gpu_index, "+
			"g.utilization_pct, g.memory_used_mb, g.memory_total_mb, "+
			"g.temperature_c, g.power_draw_w "+
			"FROM gpu_metrics_history g "+
			"JOIN servers s ON s.id = g.server_id "+
			"WHERE g.server_id IS NOT NULL "+
			"ORDER BY g.server_id, g.gpu_index, g.created_at DESC")
	if len(rows) == 0 {
		return
	}
	section := func(metric, help string, val func(r prometheusExporterGPURow) *float32) {
		out.WriteString("# HELP " + metric + " " + help + "\n")
		out.WriteString("# TYPE " + metric + " gauge\n")
		for _, r := range rows {
			if v := val(r); v != nil {
				prometheusExporterWriteGPUSample(out, metric, r.ServerID, r.Name, r.GPUIndex, *v)
			}
		}
	}
	section("dockpanel_gpu_utilization_percent", "GPU compute utilization (0-100).", func(r prometheusExporterGPURow) *float32 { return &r.UtilizationPct })
	section("dockpanel_gpu_vram_used_mb", "GPU VRAM used in MB.", func(r prometheusExporterGPURow) *float32 { return &r.MemoryUsedMB })
	section("dockpanel_gpu_vram_total_mb", "GPU VRAM capacity in MB.", func(r prometheusExporterGPURow) *float32 { return &r.MemoryTotalMB })
	section("dockpanel_gpu_temperature_celsius", "GPU temperature in Celsius.", func(r prometheusExporterGPURow) *float32 { return r.TemperatureC })
	section("dockpanel_gpu_power_draw_watts", "GPU power draw in Watts.", func(r prometheusExporterGPURow) *float32 { return r.PowerDrawW })
}

func prometheusExporterRenderSites(ctx context.Context, out *strings.Builder, db *pgxpool.Pool) {
	rows, _ := queryAll[Tup2[string, int64]](ctx, db,
		"SELECT COALESCE(status, 'unknown') AS status, COUNT(*) "+
			"FROM sites GROUP BY status")
	if len(rows) == 0 {
		return
	}
	out.WriteString("# HELP dockpanel_site_count Sites grouped by status.\n")
	out.WriteString("# TYPE dockpanel_site_count gauge\n")
	for _, r := range rows {
		out.WriteString("dockpanel_site_count{status=\"")
		prometheusExporterPushEscaped(out, r.A)
		fmt.Fprintf(out, "\"} %d\n", r.B)
	}
}

func prometheusExporterRenderCertRenewals(out *strings.Builder) {
	success := AutoHealerSslRenewalsSuccess.Load()
	failure := AutoHealerSslRenewalsFailure.Load()
	out.WriteString("# HELP dockpanel_cert_renewals_total SSL certificate renewal attempts grouped by result.\n")
	out.WriteString("# TYPE dockpanel_cert_renewals_total counter\n")
	fmt.Fprintf(out, "dockpanel_cert_renewals_total{result=\"success\"} %d\n", success)
	fmt.Fprintf(out, "dockpanel_cert_renewals_total{result=\"failure\"} %d\n", failure)
}

func prometheusExporterRenderAlerts(ctx context.Context, out *strings.Builder, db *pgxpool.Pool) {
	rows, _ := queryAll[Tup2[string, int64]](ctx, db,
		"SELECT severity, COUNT(*) FROM alerts WHERE status = 'firing' GROUP BY severity")
	out.WriteString("# HELP dockpanel_alerts_firing Firing alerts grouped by severity.\n")
	out.WriteString("# TYPE dockpanel_alerts_firing gauge\n")
	if len(rows) == 0 {
		// Publish a zero so scrapers can reliably alert on presence.
		out.WriteString("dockpanel_alerts_firing{severity=\"none\"} 0\n")
		return
	}
	for _, r := range rows {
		out.WriteString("dockpanel_alerts_firing{severity=\"")
		prometheusExporterPushEscaped(out, r.A)
		fmt.Fprintf(out, "\"} %d\n", r.B)
	}
}

// ── Label-line writers ──────────────────────────────────────────────────

// prometheusExporterF32 is Rust's `{}` for f32: shortest round-trip, never
// exponent notation.
func prometheusExporterF32(v float32) string {
	return strconv.FormatFloat(float64(v), 'f', -1, 32)
}

func prometheusExporterWriteServerSample(out *strings.Builder, metric string, sid uuid.UUID, name string, v float32) {
	fmt.Fprintf(out, "%s{server_id=\"%s\",server=\"", metric, sid)
	prometheusExporterPushEscaped(out, name)
	out.WriteString("\"} " + prometheusExporterF32(v) + "\n")
}

func prometheusExporterWriteGPUSample(out *strings.Builder, metric string, sid uuid.UUID, name string, idx int16, v float32) {
	fmt.Fprintf(out, "%s{server_id=\"%s\",server=\"", metric, sid)
	prometheusExporterPushEscaped(out, name)
	fmt.Fprintf(out, "\",gpu_index=\"%d\"} %s\n", idx, prometheusExporterF32(v))
}

// prometheusExporterPushEscaped escapes a label value: per the exposition
// spec backslash, double-quote and newline need escapes; all else passes.
func prometheusExporterPushEscaped(out *strings.Builder, s string) {
	for _, c := range s {
		switch c {
		case '\\':
			out.WriteString(`\\`)
		case '"':
			out.WriteString(`\"`)
		case '\n':
			out.WriteString(`\n`)
		default:
			out.WriteRune(c)
		}
	}
}
