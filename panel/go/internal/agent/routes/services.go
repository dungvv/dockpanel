package routes

import (
	"context"
	"net/http"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type servicesServiceStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

func registerServices(r *Router) {
	r.Handle("GET /services/health", servicesCheckServices)
}

// servicesCheckServices: GET /services/health — status of critical system services.
func servicesCheckServices(w http.ResponseWriter, _ *http.Request) {
	results := []servicesServiceStatus{}
	for _, name := range []string{"nginx", "mysql", "mariadb", "postgresql", "php-fpm", "redis-server", "docker"} {
		results = append(results, servicesCheckSystemdService(name))
	}
	// Also version-specific PHP-FPM services (php8.x-fpm).
	if out, err := safecmd.Exec(context.Background(), "sh", "-c",
		"systemctl list-units --type=service --no-pager --plain 2>/dev/null | grep 'php.*fpm' | awk '{print $1}'"); err == nil {
		for _, line := range services.LogsLines(out.Stdout) {
			t := strings.TrimSpace(line)
			svc := strings.TrimSuffix(t, ".service")
			if svc != "" && svc != "php-fpm" {
				results = append(results, servicesCheckSystemdService(svc))
			}
		}
	}
	writeJSON(w, http.StatusOK, results)
}

func servicesSystemctl(verb, name string) (string, bool) {
	out, err := safecmd.Exec(context.Background(), "systemctl", verb, name)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(out.Stdout), "�")), true
}

func servicesCheckSystemdService(name string) servicesServiceStatus {
	enabled, ran := servicesSystemctl("is-enabled", name)
	if !ran || (enabled != "enabled" && enabled != "static") {
		// Disabled services are intentionally off — don't alert.
		if ran && (enabled == "disabled" || enabled == "masked" || enabled == "indirect") {
			return servicesServiceStatus{name, "disabled"}
		}
		return servicesServiceStatus{name, "not_installed"}
	}
	status := "unknown"
	if active, ok := servicesSystemctl("is-active", name); ok {
		switch active {
		case "active":
			status = "running"
		case "inactive", "dead":
			status = "stopped"
		case "failed":
			status = "failed"
		}
	}
	return servicesServiceStatus{name, status}
}
