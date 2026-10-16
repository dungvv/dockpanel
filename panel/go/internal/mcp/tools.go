package mcp

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const instructions = "Read-only introspection tools for a DockPanel-managed server fleet. Every call " +
	"is attributed in the panel's own audit log to the API key configured for this " +
	"MCP server. v1 has no mutating or destructive tools — everything here only " +
	"reads state."

type noParams struct{}

type siteIDParams struct {
	SiteID string `json:"site_id" jsonschema:"The site's UUID, as returned by list_sites."`
}

type containerIDParams struct {
	ContainerID string `json:"container_id" jsonschema:"The Docker container ID, as returned by list_apps."`
}

type databaseIDParams struct {
	DatabaseID string `json:"database_id" jsonschema:"The database's UUID, as returned by list_databases."`
}

type monitorIDParams struct {
	MonitorID string `json:"monitor_id" jsonschema:"The monitor's UUID, as returned by list_monitors."`
}

type dnsZoneIDParams struct {
	ZoneID string `json:"zone_id" jsonschema:"The DNS zone's UUID, as returned by list_dns_zones."`
}

type paginationParams struct {
	Limit  *uint32 `json:"limit,omitempty" jsonschema:"Maximum rows to return. Server-side default applies if omitted."`
	Offset *uint32 `json:"offset,omitempty" jsonschema:"Skip this many rows (for pagination). Defaults to 0."`
}

type siteScopedPaginationParams struct {
	SiteID string  `json:"site_id" jsonschema:"The site's UUID, as returned by list_sites."`
	Limit  *uint32 `json:"limit,omitempty" jsonschema:"Maximum rows to return. Server-side default applies if omitted."`
	Offset *uint32 `json:"offset,omitempty" jsonschema:"Skip this many rows (for pagination). Defaults to 0."`
}

type auditLogParams struct {
	Limit    *uint32 `json:"limit,omitempty" jsonschema:"Maximum rows to return (server caps at 500). Defaults to 100."`
	Offset   *uint32 `json:"offset,omitempty" jsonschema:"Skip this many rows (for pagination). Defaults to 0."`
	Severity *string `json:"severity,omitempty" jsonschema:"Filter to one severity: info, warning, or critical."`
}

type serverMetricsParams struct {
	ServerID   string  `json:"server_id" jsonschema:"The server's UUID, as returned by list_servers."`
	MetricType *string `json:"metric_type,omitempty" jsonschema:"Which metric series to return (e.g. cpu, memory, disk). Omit for all."`
	Hours      *int32  `json:"hours,omitempty" jsonschema:"How many hours of history to include. Server-side default applies if omitted."`
}

type systemLogsParams struct {
	LogType *string `json:"log_type,omitempty" jsonschema:"One of nginx_access, nginx_error, syslog, auth, php_fpm. Defaults to nginx_access."`
	Lines   *uint32 `json:"lines,omitempty" jsonschema:"Number of lines to return (server caps at 1000). Defaults to 100."`
	Filter  *string `json:"filter,omitempty" jsonschema:"Only return lines containing this substring."`
}

type alertListParams struct {
	Status    *string `json:"status,omitempty" jsonschema:"Filter by alert status (e.g. firing, resolved)."`
	AlertType *string `json:"alert_type,omitempty" jsonschema:"Filter by alert type (e.g. backup_failure, ssl_expiry, cron_failure)."`
	Limit     *uint32 `json:"limit,omitempty" jsonschema:"Maximum rows to return (server caps at 500). Defaults to 100."`
}

type activityListParams struct {
	Limit  *uint32 `json:"limit,omitempty" jsonschema:"Maximum rows to return (server caps at 200). Defaults to 50."`
	Offset *uint32 `json:"offset,omitempty" jsonschema:"Skip this many rows (for pagination). Defaults to 0."`
	Action *string `json:"action,omitempty" jsonschema:"Filter by action category (e.g. site matches site.create, site.delete)."`
}

type incidentListParams struct {
	Limit  *uint32 `json:"limit,omitempty" jsonschema:"Maximum rows to return. Server-side default applies if omitted."`
	Offset *uint32 `json:"offset,omitempty" jsonschema:"Skip this many rows (for pagination). Defaults to 0."`
	Status *string `json:"status,omitempty" jsonschema:"Filter by incident status."`
}

// kv is one optional query pair; a nil value is skipped.
type kv struct {
	k string
	v *string
}

func num[T uint32 | int32](p *T) *string {
	if p == nil {
		return nil
	}
	s := strconv.FormatInt(int64(*p), 10)
	return &s
}

// querySuffix builds "?k=v&..." in the given order, or "" when every value is nil.
func querySuffix(pairs ...kv) string {
	var parts []string
	for _, p := range pairs {
		if p.v != nil {
			parts = append(parts, p.k+"="+url.QueryEscape(*p.v))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "?" + strings.Join(parts, "&")
}

func seg(s string) string { return url.PathEscape(s) }

// add registers one GET-proxy tool. Returning an error (not an "Error: ..."
// string) is what makes the SDK set isError: true, which MCP clients branch on.
func add[In any](s *sdk.Server, name, desc string, path func(In) string) {
	sdk.AddTool(s, &sdk.Tool{Name: name, Description: desc},
		func(ctx context.Context, _ *sdk.CallToolRequest, in In) (*sdk.CallToolResult, any, error) {
			token, err := LoadToken()
			if err != nil {
				return nil, nil, err
			}
			v, err := Get(ctx, path(in), token)
			if err != nil {
				return nil, nil, err
			}
			out, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return nil, nil, err
			}
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: string(out)}}}, nil, nil
		})
}

func fixed(path string) func(noParams) string { return func(noParams) string { return path } }

func pageSuffix(limit, offset *uint32) string {
	return querySuffix(kv{"limit", num(limit)}, kv{"offset", num(offset)})
}

// NewServer builds the v1 read-only tool catalogue. Every tool passes the
// panel API's JSON through unchanged; there are zero mutating tools.
func NewServer(version string) *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{Name: "dockpanel-mcp", Version: version},
		&sdk.ServerOptions{Instructions: instructions})

	// Sites & apps
	add(s, "list_sites", "List every site hosted on this DockPanel instance (domain, runtime, status).", fixed("/api/sites"))
	add(s, "get_site", "Get full detail for one site (runtime, PHP version, SSL, resource limits).",
		func(p siteIDParams) string { return "/api/sites/" + seg(p.SiteID) })
	add(s, "list_apps", "List every Docker app deployed on this instance (name, image, status, ports).", fixed("/api/apps"))
	add(s, "get_app_logs", "Fetch recent log output for one Docker app container.",
		func(p containerIDParams) string { return "/api/apps/" + seg(p.ContainerID) + "/logs" })
	add(s, "get_app_stats", "Get live resource stats (CPU, memory, network) for one Docker app container.",
		func(p containerIDParams) string { return "/api/apps/" + seg(p.ContainerID) + "/stats" })
	add(s, "list_crons", "List scheduled cron jobs configured for one site.",
		func(p siteScopedPaginationParams) string {
			return "/api/sites/" + seg(p.SiteID) + "/crons" + pageSuffix(p.Limit, p.Offset)
		})
	add(s, "list_site_backups", "List backups for one site (metadata only — file listing, not the backup contents; use the panel UI to restore).",
		func(p siteScopedPaginationParams) string {
			return "/api/sites/" + seg(p.SiteID) + "/backups" + pageSuffix(p.Limit, p.Offset)
		})
	add(s, "list_wordpress_sites", "List all WordPress sites across the fleet (version, plugin/theme counts, vulnerability scan status).", fixed("/api/wordpress/sites"))

	// Databases
	add(s, "list_databases", "List every database on this instance (engine, size, owning site).",
		func(p paginationParams) string { return "/api/databases" + pageSuffix(p.Limit, p.Offset) })
	add(s, "get_database_tables", "List the tables in one database, with row counts (schema only — never returns credentials or row contents).",
		func(p databaseIDParams) string { return "/api/databases/" + seg(p.DatabaseID) + "/tables" })

	// Servers & fleet
	add(s, "list_servers", "List every server registered to this DockPanel fleet (hostname, region, agent status).", fixed("/api/servers"))
	add(s, "get_server_metrics", "Get time-series resource metrics (CPU/memory/disk) for one server.",
		func(p serverMetricsParams) string {
			return "/api/servers/" + seg(p.ServerID) + "/metrics" +
				querySuffix(kv{"metric_type", p.MetricType}, kv{"hours", num(p.Hours)})
		})
	add(s, "get_fleet_dashboard", "Get the fleet-wide dashboard overview (server health, resource usage across every registered server).", fixed("/api/dashboard/fleet"))

	// Monitoring & alerting
	add(s, "list_monitors", "List uptime monitors configured on this instance (target, interval, current status).",
		func(p paginationParams) string { return "/api/monitors" + pageSuffix(p.Limit, p.Offset) })
	add(s, "get_monitor_uptime", "Get uptime percentage and check history for one monitor.",
		func(p monitorIDParams) string { return "/api/monitors/" + seg(p.MonitorID) + "/uptime" })
	add(s, "get_status_page", "Read the public status page (component statuses, active incidents) — the same data unauthenticated visitors see.", fixed("/api/status-page/public"))
	add(s, "list_alerts", "List active and recent alerts (backup failures, SSL expiry, cron failures, security scans, and more) across the fleet.",
		func(p alertListParams) string {
			return "/api/alerts" + querySuffix(kv{"status", p.Status}, kv{"alert_type", p.AlertType}, kv{"limit", num(p.Limit)})
		})
	add(s, "get_alerts_summary", "Get a rolled-up count of alerts by severity — the number a dashboard badge would show.", fixed("/api/alerts/summary"))
	add(s, "list_on_call_schedules", "List on-call schedules (rotation members, cadence) configured for this instance.", fixed("/api/on-call/schedules"))
	add(s, "list_escalation_policies", "List escalation policies (ordered notification steps) available to attach to alert rules.", fixed("/api/escalation-policies"))
	add(s, "list_incidents", "List managed incidents (the ones tracked for the public status page), most recent first.",
		func(p incidentListParams) string {
			return "/api/incidents" + querySuffix(kv{"limit", num(p.Limit)}, kv{"offset", num(p.Offset)}, kv{"status", p.Status})
		})

	// Security
	add(s, "get_security_overview", "Get the security overview for this instance (firewall, fail2ban, panel-jail, canary status at a glance).", fixed("/api/security/overview"))
	add(s, "get_security_audit_log", "Read the immutable security audit log — logins, lockdowns, key rotations, "+
		"and (once a mutating tool exists) MCP-originated actions. High-value for an "+
		"agent to self-check what it has already done in this session. Requires an "+
		"admin-scoped key.",
		func(p auditLogParams) string {
			return "/api/security/audit-log" + querySuffix(kv{"limit", num(p.Limit)}, kv{"offset", num(p.Offset)}, kv{"severity", p.Severity})
		})
	add(s, "get_security_posture", "Get the computed security posture score for this instance, with the factors that make it up.", fixed("/api/security/posture"))

	// DNS
	add(s, "list_dns_zones", "List DNS zones managed through this instance.", fixed("/api/dns/zones"))
	add(s, "list_dns_records", "List DNS records in one zone.",
		func(p dnsZoneIDParams) string { return "/api/dns/zones/" + seg(p.ZoneID) + "/records" })

	// Backups
	add(s, "get_backup_orchestrator_health", "Get fleet-wide backup health (coverage, staleness, failure counts across every site and database).", fixed("/api/backup-orchestrator/health"))
	add(s, "list_db_backups", "List database backups across the fleet (metadata only — size, timestamp, status; not the dump contents).",
		func(p paginationParams) string {
			return "/api/backup-orchestrator/db-backups" + pageSuffix(p.Limit, p.Offset)
		})

	// Mail
	add(s, "get_mail_status", "Get the mail server's overall status (Postfix/Dovecot health, queue depth at a glance).", fixed("/api/mail/status"))
	add(s, "list_mail_domains", "List mail domains configured on this instance (DKIM selector, catch-all status).", fixed("/api/mail/domains"))

	// Logs & system
	add(s, "get_system_logs", "Fetch recent system-level logs (nginx access/error, syslog, auth, or php-fpm) with an optional substring filter.",
		func(p systemLogsParams) string {
			return "/api/logs" + querySuffix(kv{"type", p.LogType}, kv{"lines", num(p.Lines)}, kv{"filter", p.Filter})
		})
	add(s, "list_activity", "Get the panel's own recorded activity feed (who did what, across every resource type) — broader than the security audit log, which covers security-relevant events only.",
		func(p activityListParams) string {
			return "/api/activity" + querySuffix(kv{"limit", num(p.Limit)}, kv{"offset", num(p.Offset)}, kv{"action", p.Action})
		})

	// Panel & fleet ops
	add(s, "get_update_status", "Check whether a panel software update is available and what version this instance is currently running.", fixed("/api/update/status"))
	add(s, "list_webhook_endpoints", "List configured outbound webhook endpoints (URL, event subscriptions) — configuration only, never the inbound webhook receiver URLs third parties call into.", fixed("/api/webhook-gateway/endpoints"))
	add(s, "list_git_deploys", "List Git Deploy configurations (repo, branch, deploy target) across the fleet.", fixed("/api/git-deploys"))
	add(s, "list_stacks", "List Docker Compose stacks deployed on this instance.", fixed("/api/stacks"))
	add(s, "list_users", "List panel user accounts (email, role, reseller). Requires an admin-scoped key.", fixed("/api/users"))
	add(s, "get_settings", "Get this instance's panel settings. Secret-shaped values (API keys, passwords, tokens) are "+
		"masked by the panel API itself before this tool ever sees them. Requires an admin-scoped key.", fixed("/api/settings"))
	add(s, "list_resellers", "List reseller accounts and their resource limits. Requires an admin-scoped key.", fixed("/api/resellers"))
	add(s, "get_telemetry_stats", "Get anonymized telemetry stats this instance has recorded about its own usage. Requires an admin-scoped key.", fixed("/api/telemetry/stats"))

	return s
}
