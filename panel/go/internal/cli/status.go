package cli

import (
	"errors"
	"fmt"
)

func usageColor(pct float64) string {
	switch {
	case pct > 90:
		return "\x1b[31m"
	case pct > 70:
		return "\x1b[33m"
	default:
		return "\x1b[32m"
	}
}

func cmdStatus(token, output string) error {
	info, err := agentGet("/system/info", token)
	if err != nil {
		return err
	}
	if output == "json" {
		fmt.Println(pretty(info))
		return nil
	}
	g := func(k string) any { return get(info, k) }
	uptime := u64Or(g("uptime_secs"), 0)
	cpuUsage := f64Or(g("cpu_usage"), 0)
	memPct := f64Or(g("mem_usage_pct"), 0)
	diskPct := f64Or(g("disk_usage_pct"), 0)

	fmt.Println("\x1b[1mServer Status\x1b[0m")
	fmt.Printf("  Hostname:    %s\n", strOr(g("hostname"), "unknown"))
	fmt.Printf("  OS:          %s\n", strOr(g("os"), "unknown"))
	fmt.Printf("  Kernel:      %s\n", strOr(g("kernel"), "unknown"))
	fmt.Printf("  Uptime:      %dd %dh %dm\n", uptime/86400, (uptime%86400)/3600, (uptime%3600)/60)
	fmt.Println()
	fmt.Println("\x1b[1mCPU\x1b[0m")
	fmt.Printf("  Model:       %s\n", strOr(g("cpu_model"), "unknown"))
	fmt.Printf("  Cores:       %d\n", u64Or(g("cpu_count"), 0))
	fmt.Printf("  Usage:       %s%.1f%%\x1b[0m\n", usageColor(cpuUsage), cpuUsage)
	fmt.Printf("  Load:        %.2f / %.2f / %.2f\n", f64Or(g("load_avg_1"), 0), f64Or(g("load_avg_5"), 0), f64Or(g("load_avg_15"), 0))
	fmt.Println()
	fmt.Println("\x1b[1mMemory\x1b[0m")
	fmt.Printf("  Used:        %s%d MB\x1b[0m / %d MB (%.1f%%)\n", usageColor(memPct), u64Or(g("mem_used_mb"), 0), u64Or(g("mem_total_mb"), 0), memPct)
	fmt.Println()
	fmt.Println("\x1b[1mDisk\x1b[0m")
	fmt.Printf("  Used:        %s%.1f GB\x1b[0m / %.1f GB (%.1f%%)\n", usageColor(diskPct), f64Or(g("disk_used_gb"), 0), f64Or(g("disk_total_gb"), 0), diskPct)
	fmt.Println()
	fmt.Printf("  Processes:   %d\n", u64Or(g("process_count"), 0))
	return nil
}

func cmdTop(token, output string) error {
	v, err := agentGet("/system/processes", token)
	if err != nil {
		return err
	}
	if output == "json" {
		fmt.Println(pretty(v))
		return nil
	}
	procs, ok := arr(v)
	if !ok {
		return errors.New("Expected array from /system/processes")
	}
	fmt.Printf("\x1b[1m%-8s %-30s %-10s %-10s\x1b[0m\n", "PID", "NAME", "CPU %", "MEM MB")
	for _, p := range procs {
		cpu := f64Or(get(p, "cpu_pct"), 0)
		fmt.Printf("%-8d %-30s %s%-10.1f\x1b[0m %-10.1f\n", u64Or(get(p, "pid"), 0), strOr(get(p, "name"), "-"), usageColor(cpu), cpu, f64Or(get(p, "mem_mb"), 0))
	}
	return nil
}

func cmdServices(token, output string, filter *string) error {
	v, err := agentGet("/services/health", token)
	if err != nil {
		return err
	}
	svcs, ok := arr(v)
	if !ok {
		return errors.New("Expected array from /services/health")
	}
	filtered := []any{}
	for _, s := range svcs {
		if filter == nil || containsFold(strOr(get(s, "name"), ""), *filter) {
			filtered = append(filtered, s)
		}
	}
	if output == "json" {
		fmt.Println(pretty(filtered))
		return nil
	}
	fmt.Printf("\x1b[1m%-25s %-15s\x1b[0m\n", "SERVICE", "STATUS")
	for _, s := range filtered {
		status := strOr(get(s, "status"), "-")
		color := "\x1b[33m"
		switch status {
		case "running":
			color = "\x1b[32m"
		case "stopped", "failed":
			color = "\x1b[31m"
		case "disabled", "not_installed":
			color = "\x1b[90m"
		}
		fmt.Printf("%-25s %s%-15s\x1b[0m\n", strOr(get(s, "name"), "-"), color, status)
	}
	return nil
}

func cmdDiagnose(token, output string) error {
	report, err := agentGet("/diagnostics", token)
	if err != nil {
		return err
	}
	if output == "json" {
		fmt.Println(pretty(report))
		return nil
	}
	fmt.Print("Running diagnostics...\n\n")

	summary := get(report, "summary")
	critical := u64Or(get(summary, "critical"), 0)
	warning := u64Or(get(summary, "warning"), 0)
	info := u64Or(get(summary, "info"), 0)
	total := u64Or(get(summary, "total"), 0)
	if total == 0 {
		fmt.Println("\x1b[32m✓ All checks passed — no issues detected.\x1b[0m")
		return nil
	}

	fmt.Print("Found ")
	if critical > 0 {
		fmt.Printf("\x1b[31m%d critical\x1b[0m", critical)
	}
	if warning > 0 {
		if critical > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("\x1b[33m%d warning\x1b[0m", warning)
	}
	if info > 0 {
		if critical > 0 || warning > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("\x1b[34m%d info\x1b[0m", info)
	}
	fmt.Printf(" (%d total)\n\n", total)

	findings, _ := arr(get(report, "findings"))
	categories := [][2]string{
		{"nginx", "NGINX"}, {"resources", "RESOURCES"}, {"services", "SERVICES"},
		{"ssl", "SSL CERTIFICATES"}, {"logs", "LOG ANALYSIS"}, {"security", "SECURITY"},
	}
	for _, cat := range categories {
		var catFindings []any
		for _, f := range findings {
			if c, ok := str(get(f, "category")); ok && c == cat[0] {
				catFindings = append(catFindings, f)
			}
		}
		if len(catFindings) == 0 {
			continue
		}
		fmt.Printf("\x1b[1m%s\x1b[0m\n", cat[1])
		for _, f := range catFindings {
			icon := "\x1b[34mi\x1b[0m"
			switch strOr(get(f, "severity"), "info") {
			case "critical":
				icon = "\x1b[31m✗\x1b[0m"
			case "warning":
				icon = "\x1b[33m!\x1b[0m"
			}
			fmt.Printf("  %s %s\n", icon, strOr(get(f, "title"), ""))
			fmt.Printf("    %s\n", strOr(get(f, "description"), ""))
			if isTrue(get(f, "fix_available")) {
				if id, ok := str(get(f, "fix_id")); ok {
					fmt.Printf("    \x1b[2m(fixable: %s)\x1b[0m\n", id)
				}
			}
		}
		fmt.Println()
	}
	return nil
}
