package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const nginxSitesDir = "/etc/nginx/sites-enabled"

type siteInfo struct {
	Domain  string `json:"domain"`
	Runtime string `json:"runtime"`
	SSL     bool   `json:"ssl"`
}

// listNginxSites reads site configs straight from nginx's sites-enabled dir.
func listNginxSites(dir string) []siteInfo {
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer d.Close()
	entries, _ := d.ReadDir(-1) // directory order, like Rust's read_dir
	var sites []siteInfo
	for _, e := range entries {
		name := e.Name()
		if name == "dockpanel-panel.conf" || name == "dockpanel.dev.conf" || name == "default" {
			continue
		}
		content, err := readUTF8(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		domain := strings.ReplaceAll(name, ".conf", "")
		for _, l := range strings.Split(content, "\n") {
			l = strings.TrimSpace(l)
			if !strings.HasPrefix(l, "server_name") {
				continue
			}
			rest := strings.TrimRight(strings.TrimSpace(strings.TrimPrefix(l, "server_name")), ";")
			if f := strings.Fields(rest); len(f) > 0 {
				domain = f[0]
			}
			break
		}
		if domain == "_" {
			continue
		}
		runtime := "static"
		if strings.Contains(content, "proxy_pass") {
			runtime = "proxy"
		} else if strings.Contains(content, "fastcgi_pass") || strings.Contains(content, "php") {
			runtime = "php"
		}
		sites = append(sites, siteInfo{domain, runtime, strings.Contains(content, "ssl_certificate")})
	}
	sort.SliceStable(sites, func(i, j int) bool { return sites[i].Domain < sites[j].Domain })
	var out []siteInfo
	for _, s := range sites {
		if len(out) == 0 || out[len(out)-1].Domain != s.Domain {
			out = append(out, s)
		}
	}
	return out
}

func cmdSitesList(token, output string, filter *string) error {
	// Connectivity check: fail the same way every other command does when the agent is down.
	if _, err := agentGet("/system/info", token); err != nil {
		return err
	}
	sites := []siteInfo{}
	for _, s := range listNginxSites(nginxSitesDir) {
		if filter == nil || containsFold(s.Domain, *filter) {
			sites = append(sites, s)
		}
	}
	if output == "json" {
		fmt.Println(pretty(sites))
		return nil
	}
	if len(sites) == 0 {
		fmt.Println("No sites configured.")
		return nil
	}
	fmt.Printf("\x1b[1m%-30s %-10s %-6s\x1b[0m\n", "DOMAIN", "TYPE", "SSL")
	for _, s := range sites {
		fmt.Printf("%-30s %-10s %-6s\n", s.Domain, s.Runtime, yesNo(s.SSL))
	}
	fmt.Printf("\n%d site(s)\n", len(sites))
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func cmdSitesCreate(token, domain, runtime string, proxyPort *int64, ssl bool, sslEmail *string) error {
	if runtime == "proxy" && proxyPort == nil {
		return errors.New("--proxy-port is required for proxy runtime")
	}
	if ssl && sslEmail == nil {
		return errors.New("--ssl-email is required when using --ssl")
	}
	body := map[string]any{"runtime": runtime}
	if proxyPort != nil {
		body["proxy_port"] = *proxyPort
	}
	fmt.Printf("Creating site %s (%s)...\n", domain, runtime)
	result, err := agentPut("/nginx/sites/"+domain, body, token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to create site: %s", strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Printf("\x1b[32m✓\x1b[0m Site created: %s\n", domain)

	if ssl {
		fmt.Println("Provisioning SSL certificate...")
		sslBody := map[string]any{"email": *sslEmail, "runtime": runtime}
		if proxyPort != nil {
			sslBody["proxy_port"] = *proxyPort
		}
		r, err := agentPost("/ssl/provision/"+domain, sslBody, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\x1b[33mwarning:\x1b[0m SSL provisioning failed: %s\n", err)
			fmt.Fprintln(os.Stderr, "  Site created without SSL. Provision manually with:")
			fmt.Fprintf(os.Stderr, "  dockpanel ssl provision %s --email %s\n", domain, *sslEmail)
		} else if isTrue(get(r, "success")) {
			fmt.Printf("\x1b[32m✓\x1b[0m SSL provisioned (expires: %s)\n", strOr(get(r, "expiry"), "unknown"))
		}
	}
	return nil
}

func cmdSitesDelete(token, domain string) error {
	fmt.Printf("Deleting site %s...\n", domain)
	result, err := agentDelete("/nginx/sites/"+domain, token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to delete site: %s", strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Printf("\x1b[32m✓\x1b[0m Site deleted: %s\n", domain)
	return nil
}

func cmdSitesInfo(token, domain string) error {
	info, err := agentGet("/nginx/sites/"+domain, token)
	if err != nil {
		return err
	}
	fmt.Printf("\x1b[1mSite: %s\x1b[0m\n", domain)
	cfg := "\x1b[31mnot found\x1b[0m"
	if isTrue(get(info, "config_exists")) {
		cfg = "\x1b[32mexists\x1b[0m"
	}
	fmt.Printf("  Config:      %s\n", cfg)
	ssl := "\x1b[90mdisabled\x1b[0m"
	if isTrue(get(info, "ssl_enabled")) {
		ssl = "\x1b[32menabled\x1b[0m"
	}
	fmt.Printf("  SSL:         %s\n", ssl)
	if cert, ok := str(get(info, "ssl_cert_path")); ok {
		fmt.Printf("  Certificate: %s\n", cert)
	}
	if exp, ok := str(get(info, "ssl_expiry")); ok {
		fmt.Printf("  Expires:     %s\n", exp)
	}
	return nil
}
