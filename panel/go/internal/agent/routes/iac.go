package routes

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type iacServerExport struct {
	Version   string            `json:"version"`
	Sites     []iacSiteExport   `json:"sites"`
	Databases []iacDbExport     `json:"databases"`
	Apps      []iacAppExport    `json:"apps"`
	Crons     []iacCronExport   `json:"crons"`
	Php       []iacPhpExport    `json:"php"`
	Firewall  iacFirewallExport `json:"firewall"`
}

type iacSiteExport struct {
	Domain     string  `json:"domain"`
	Runtime    string  `json:"runtime"`
	Ssl        bool    `json:"ssl"`
	ProxyPort  *uint16 `json:"proxy_port,omitempty"`
	Root       *string `json:"root,omitempty"`
	PhpVersion *string `json:"php_version,omitempty"`
}

type iacDbExport struct {
	Name   string `json:"name"`
	Engine string `json:"engine"`
	Port   uint16 `json:"port"`
}

type iacAppExport struct {
	Name     string  `json:"name"`
	Template string  `json:"template"`
	Port     *uint16 `json:"port"`
	Domain   *string `json:"domain,omitempty"`
}

type iacCronExport struct {
	ID       string  `json:"id"`
	Schedule string  `json:"schedule"`
	Command  string  `json:"command"`
	Label    *string `json:"label,omitempty"`
}

type iacPhpExport struct {
	Version    string `json:"version"`
	Installed  bool   `json:"installed"`
	FpmRunning bool   `json:"fpm_running"`
}

type iacFirewallExport struct {
	Enabled bool                    `json:"enabled"`
	Rules   []iacFirewallRuleExport `json:"rules"`
}

type iacFirewallRuleExport struct {
	To     string `json:"to"`
	Action string `json:"action"`
}

func registerIac(r *Router) {
	r.Handle("GET /iac/export", iacExport)
}

// iacExport: GET /iac/export — the server's configuration as structured JSON.
// Every source is best-effort: a failing one exports empty.
func iacExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := iacServerExport{Version: "1", Sites: iacScanNginxSites(), Databases: []iacDbExport{}, Apps: []iacAppExport{},
		Crons: iacReadCrontabEntries(ctx), Php: iacCheckPhpVersions(ctx), Firewall: iacFirewallExport{Rules: []iacFirewallRuleExport{}}}

	if dbs, err := services.DatabaseListDatabases(ctx); err == nil {
		for _, db := range dbs {
			out.Databases = append(out.Databases, iacDbExport{Name: db.Name, Engine: db.Engine, Port: db.Port})
		}
	}
	if apps, err := services.DockerAppsListDeployedApps(ctx); err == nil {
		for _, a := range apps {
			out.Apps = append(out.Apps, iacAppExport{Name: strings.TrimPrefix(a.Name, "dockpanel-app-"),
				Template: a.Template, Port: a.Port, Domain: a.Domain})
		}
	}
	if fw, err := services.SecurityGetFirewallStatus(); err == nil {
		out.Firewall.Enabled = fw.Active
		for _, rule := range fw.Rules {
			out.Firewall.Rules = append(out.Firewall.Rules, iacFirewallRuleExport{To: rule.To, Action: rule.Action})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// iacScanNginxSites extracts site configurations from the vhost directory.
func iacScanNginxSites() []iacSiteExport {
	sites := []iacSiteExport{}
	dir := services.NginxSitesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return sites
	}
	for _, e := range entries {
		filename := e.Name()
		// Skip the panel's own config and the default.
		if filename == "dockpanel-panel.conf" || filename == "dockpanel.dev.conf" || filename == "default" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, filename))
		if err != nil {
			continue
		}
		if s, ok := iacParseSite(filename, string(b)); ok {
			sites = append(sites, s)
		}
	}
	// Deduplicate (HTTP + HTTPS blocks for the same domain), keeping SSL.
	sort.SliceStable(sites, func(i, j int) bool { return sites[i].Domain < sites[j].Domain })
	var dedup []iacSiteExport
	for _, s := range sites {
		if n := len(dedup); n > 0 && dedup[n-1].Domain == s.Domain {
			dedup[n-1].Ssl = dedup[n-1].Ssl || s.Ssl
			continue
		}
		dedup = append(dedup, s)
	}
	if dedup == nil {
		return sites
	}
	return dedup
}

func iacParseSite(filename, content string) (iacSiteExport, bool) {
	lines := nginxLines(content)
	domain := strings.ReplaceAll(filename, ".conf", "")
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "server_name") {
			if f := strings.Fields(strings.TrimRight(strings.TrimSpace(strings.TrimPrefix(t, "server_name")), ";")); len(f) > 0 {
				domain = f[0]
			}
			break
		}
	}
	if domain == "_" {
		return iacSiteExport{}, false
	}
	s := iacSiteExport{Domain: domain, Runtime: "static", Ssl: strings.Contains(content, "ssl_certificate")}

	switch {
	case strings.Contains(content, "proxy_pass"):
		// "proxy_pass http://127.0.0.1:PORT;"
		s.Runtime = "proxy"
		for _, l := range lines {
			if strings.Contains(l, "proxy_pass") {
				last := l[strings.LastIndex(l, ":")+1:]
				if p, err := strconv.ParseUint(strings.TrimSpace(strings.TrimRight(last, ";")), 10, 16); err == nil {
					pp := uint16(p)
					s.ProxyPort = &pp
				}
				break
			}
		}
	case strings.Contains(content, "fastcgi_pass") || strings.Contains(content, "php"):
		// PHP version from the socket path — the text after the first "php",
		// up to the first '-' (a literal port of the Rust heuristic).
		s.Runtime = "php"
		for _, l := range lines {
			if strings.Contains(l, "php") && strings.Contains(l, "fpm") {
				if parts := strings.Split(l, "php"); len(parts) > 1 {
					v, _, _ := strings.Cut(parts[1], "-")
					s.PhpVersion = &v
				}
				break
			}
		}
	}

	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "root ") && !strings.Contains(t, "acme") {
			if root := strings.TrimSpace(strings.TrimRight(strings.TrimPrefix(t, "root "), ";")); root != "" {
				s.Root = &root
			}
			break
		}
	}
	return s, true
}

// iacReadCrontabEntries reads DockPanel's entries from the system crontab.
func iacReadCrontabEntries(ctx context.Context) []iacCronExport {
	crons := []iacCronExport{}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "crontab", "-l")
	if err != nil || !out.Success() {
		return crons
	}
	return iacParseCrontab(strings.ToValidUTF8(string(out.Stdout), "�"))
}

func iacParseCrontab(crontab string) []iacCronExport {
	const marker = "# dockpanel:"
	crons := []iacCronExport{}
	for _, line := range nginxLines(crontab) {
		pos := strings.Index(line, marker)
		if pos < 0 {
			continue
		}
		before := strings.TrimSpace(line[:pos])
		after := line[pos+len(marker):]
		var id string
		var label *string
		if i := strings.Index(after, " "); i >= 0 {
			id = after[:i]
			if l := strings.TrimSpace(after[i+1:]); l != "" {
				label = &l
			}
		} else {
			id = strings.TrimSpace(after)
		}
		// First five fields are the schedule, the rest is the command.
		parts := strings.SplitN(before, " ", 6)
		if len(parts) < 6 {
			continue
		}
		crons = append(crons, iacCronExport{ID: id, Schedule: strings.Join(parts[:5], " "), Command: parts[5], Label: label})
	}
	return crons
}

// iacCheckPhpVersions lists installed PHP versions and whether FPM runs.
func iacCheckPhpVersions(ctx context.Context) []iacPhpExport {
	res := []iacPhpExport{}
	for _, v := range []string{"8.1", "8.2", "8.3", "8.4", "8.5"} {
		if !services.PkgIsInstalled("php" + v + "-fpm") {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		out, err := safecmd.Exec(cctx, "systemctl", "is-active", "--quiet", "php"+v+"-fpm")
		cancel()
		res = append(res, iacPhpExport{Version: v, Installed: true, FpmRunning: err == nil && out.Success()})
	}
	return res
}
