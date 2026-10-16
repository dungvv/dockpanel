package services

// Systemd service management for Node.js/Python app processes: a per-site
// unit that runs the app, proxied by nginx.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

const appProcessServicePrefix = "dockpanel-app-"

func appProcessServiceName(domain string) string {
	return appProcessServicePrefix + strings.ReplaceAll(domain, ".", "-")
}

// AppProcessOwnedServiceName returns the unit to act on for domain — only when
// the unit on disk says it runs domain. The name collapses '.' to '-', so
// a.b.com and a-b.com share one unit name; the lifecycle callers (disable,
// enable, .env save) used to stop/restart a neighbour's app. ok=false both
// when there is nothing to act on and when the unit is someone else's.
func AppProcessOwnedServiceName(domain string) (string, bool) {
	svc := appProcessServiceName(domain)
	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", svc)
	if !nginxExists(unitPath) {
		return "", false
	}
	if !OwnershipSystemdUnit(unitPath, domain).MayDelete() {
		slog.Warn(fmt.Sprintf("Not touching %s: %s does not run %s. The unit name collapses "+
			"'.' to '-', so this unit belongs to a different domain.", svc, unitPath, domain))
		return "", false
	}
	return svc, true
}

func appProcessRun(bin string, args ...string) error {
	_, err := safecmd.Exec(context.Background(), bin, args...)
	return err
}

// AppProcessCreateAppService creates and starts the systemd unit for an app.
func AppProcessCreateAppService(domain, command string, port uint16, runtime string) error {
	if err := CommandFilterIsSafeExecStart(command, runtime); err != nil {
		return err
	}
	svc := appProcessServiceName(domain)
	siteDir := "/var/www/" + domain

	// A managed process starts where its code is. This used to hardcode
	// `{site}/public` — a directory the panel created EMPTY — so `node
	// server.js` / `python3 app.py` crash-looped under Restart=always (npm
	// start hid it by re-rooting to the nearest package.json).
	workingDir := NginxDocumentRootFor(siteDir, runtime)

	execStart := command
	switch runtime {
	case "node":
		if !appProcessHasAnyPrefix(command, "node ", "npm ", "npx ", "yarn ", "pnpm ", "/") {
			execStart = "node " + command
		}
	case "python":
		if !appProcessHasAnyPrefix(command, "python", "gunicorn", "uvicorn", "flask", "django", "/") {
			execStart = "python3 " + command
		}
	}

	unit := fmt.Sprintf(`[Unit]
Description=DockPanel App: %[1]s
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=%[2]s
ExecStart=%[3]s
Restart=always
RestartSec=5
Environment=PORT=%[4]d
Environment=NODE_ENV=production
Environment=HOST=0.0.0.0
EnvironmentFile=-/var/www/%[1]s/.env

# Resource limits
MemoryMax=512M
CPUQuota=100%%
LimitNOFILE=65536
TasksMax=512

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
ProtectProc=invisible
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/www/%[1]s

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=%[5]s

[Install]
WantedBy=multi-user.target
`, domain, workingDir, execStart, port, svc)

	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", svc)
	// Mirror of the delete-side collision: writing this unit for a-b.com would
	// silently repoint a.b.com's unit at another tenant's docroot — latent
	// until the next reboot, which is worse.
	if nginxExists(unitPath) && OwnershipSystemdUnit(unitPath, domain) == OwnershipTheirs {
		return fmt.Errorf("The systemd unit name for %s is already taken by another domain "+
			"(%s). Unit names collapse '.' to '-', so these two domains "+
			"share one name; rename one of them.", domain, unitPath)
	}
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("Failed to write service unit: %v", nginxIOErr(err))
	}

	_ = os.MkdirAll(workingDir, 0o755)
	// Everything except `.git`, which stays root's: handing it to www-data
	// gives the app `config`/`hooks/` that the next git deploy runs as root.
	if entries, err := os.ReadDir(siteDir); err == nil {
		for _, e := range entries {
			if e.Name() == ".git" {
				continue
			}
			_ = appProcessRun("chown", "-R", "www-data:www-data", siteDir+"/"+e.Name())
		}
	}
	gitDir := siteDir + "/.git"
	if nginxExists(gitDir) {
		_ = appProcessRun("chown", "-R", "root:root", gitDir)
		_ = appProcessRun("chmod", "-R", "go-rwx", gitDir)
	}

	if err := appProcessRun("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload failed: %v", err)
	}
	if err := appProcessRun("systemctl", "enable", "--now", svc); err != nil {
		return fmt.Errorf("Failed to start service: %v", err)
	}
	slog.Info(fmt.Sprintf("App service created and started: %s (port=%d, runtime=%s)", svc, port, runtime))
	return nil
}

// AppProcessRemoveAppService stops and removes the app's unit — only when the
// unit says it runs domain (the name is not injective; deleting a site used
// to take down the colliding neighbour's app with no way back).
func AppProcessRemoveAppService(domain string) error {
	svc := appProcessServiceName(domain)
	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", svc)
	if !nginxExists(unitPath) {
		return nil
	}
	if !OwnershipSystemdUnit(unitPath, domain).MayDelete() {
		slog.Warn(fmt.Sprintf("Leaving %s in place: it does not run %s. The unit name "+
			"collapses '.' to '-', so this file belongs to a different domain.", unitPath, domain))
		return nil
	}
	_ = appProcessRun("systemctl", "stop", svc)
	_ = appProcessRun("systemctl", "disable", svc)
	_ = os.Remove(unitPath)
	_ = appProcessRun("systemctl", "daemon-reload")
	slog.Info("App service removed: " + svc)
	return nil
}

func appProcessHasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
