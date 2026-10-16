package api

// Port of panel/backend/src/services/alert_runbook_defaults.rs.
//
// Compile-time default runbooks indexed by alert_type. Each entry is the
// source of truth for "what should this alert say if the operator hasn't
// customized it." Consulted by:
//
//  1. AlertRunbooksGetRunbook as a fallback when no DB row exists (so fresh
//     installs still produce useful notification payloads).
//  2. POST /api/alerts/runbooks/apply-defaults to seed missing rows.
//
// Adding a new alert type: add its `.md` file under `panel/backend/runbooks/`
// AND `panel/go/internal/api/runbooks/` (byte-identical copies, a test diffs
// them) and a new entry here. The "Apply Defaults" UX picks it up automatically.

import "embed"

//go:embed runbooks/*.md
var alertRunbookDefaultsFS embed.FS

func alertRunbookDefaultsMD(alertType string) string {
	b, err := alertRunbookDefaultsFS.ReadFile("runbooks/" + alertType + ".md")
	if err != nil {
		panic(err) // include_str! fails the build; a missing embed is the same bug
	}
	return string(b)
}

// AlertRunbookDefaultsDefaultRunbook is one compile-time default.
type AlertRunbookDefaultsDefaultRunbook struct {
	AlertType string
	Severity  string
	RunbookMd string
}

// AlertRunbookDefaultsDefaults is the Rust DEFAULTS slice.
var AlertRunbookDefaultsDefaults = []AlertRunbookDefaultsDefaultRunbook{
	// Critical (paging-grade) — 5 entries
	{"offline", "critical", alertRunbookDefaultsMD("offline")},
	{"service_down", "critical", alertRunbookDefaultsMD("service_down")},
	{"container_crashloop", "critical", alertRunbookDefaultsMD("container_crashloop")},
	{"backup_failure", "critical", alertRunbookDefaultsMD("backup_failure")},
	{"gpu_temperature", "critical", alertRunbookDefaultsMD("gpu_temperature")},
	// Warning (notify-worthy) — 9 entries
	{"cpu", "warning", alertRunbookDefaultsMD("cpu")},
	{"memory", "warning", alertRunbookDefaultsMD("memory")},
	{"disk", "warning", alertRunbookDefaultsMD("disk")},
	{"disk_forecast", "warning", alertRunbookDefaultsMD("disk_forecast")},
	{"ssl_expiry", "warning", alertRunbookDefaultsMD("ssl_expiry")},
	{"container_unhealthy", "warning", alertRunbookDefaultsMD("container_unhealthy")},
	{"gpu_utilization", "warning", alertRunbookDefaultsMD("gpu_utilization")},
	{"gpu_vram", "warning", alertRunbookDefaultsMD("gpu_vram")},
	{"memory_leak", "warning", alertRunbookDefaultsMD("memory_leak")},
	// Info — 1 entry
	{"container_down", "info", alertRunbookDefaultsMD("container_down")},
}

// AlertRunbookDefaultsFindDefault returns the default for alertType, or nil.
func AlertRunbookDefaultsFindDefault(alertType string) *AlertRunbookDefaultsDefaultRunbook {
	for i := range AlertRunbookDefaultsDefaults {
		if AlertRunbookDefaultsDefaults[i].AlertType == alertType {
			return &AlertRunbookDefaultsDefaults[i]
		}
	}
	return nil
}
