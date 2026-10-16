package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

func cmdAppsList(token, output string, filter *string) error {
	v, err := agentGet("/apps", token)
	if err != nil {
		return err
	}
	apps, ok := arr(v)
	if !ok {
		return errors.New("Expected array from /apps")
	}
	// Filter matches name or domain.
	filtered := []any{}
	for _, a := range apps {
		if filter == nil || containsFold(strOr(get(a, "name"), ""), *filter) || containsFold(strOr(get(a, "domain"), ""), *filter) {
			filtered = append(filtered, a)
		}
	}
	if output == "json" {
		fmt.Println(pretty(filtered))
		return nil
	}
	if len(filtered) == 0 {
		fmt.Println("No Docker apps deployed.")
		return nil
	}
	fmt.Printf("\x1b[1m%-14s %-20s %-15s %-25s %-8s %-12s\x1b[0m\n", "CONTAINER", "NAME", "TEMPLATE", "DOMAIN", "PORT", "STATUS")
	for _, a := range filtered {
		port := "-"
		if p, ok := u64(get(a, "port")); ok {
			port = strconv.FormatUint(p, 10)
		}
		status := strOr(get(a, "status"), "-")
		color := "\x1b[31m"
		if status == "running" {
			color = "\x1b[32m"
		}
		fmt.Printf("%-14s %-20s %-15s %-25s %-8s %s%-12s\x1b[0m\n",
			shortID(strOr(get(a, "container_id"), "-")), strOr(get(a, "name"), "-"), strOr(get(a, "template"), "-"),
			strOr(get(a, "domain"), "-"), port, color, status)
	}
	fmt.Printf("\n%d app(s)\n", len(filtered))
	return nil
}

func cmdAppsTemplates(token, output string) error {
	v, err := agentGet("/apps/templates", token)
	if err != nil {
		return err
	}
	if output == "json" {
		fmt.Println(pretty(v))
		return nil
	}
	templates, ok := arr(v)
	if !ok {
		return errors.New("Expected array from /apps/templates")
	}
	if len(templates) == 0 {
		fmt.Println("No templates available.")
		return nil
	}
	fmt.Printf("\x1b[1m%-20s %-30s %-15s\x1b[0m\n", "ID", "IMAGE", "DEFAULT PORT")
	for _, t := range templates {
		port := "-"
		if ps, ok := arr(get(t, "ports")); ok && len(ps) > 0 {
			if p, ok := u64(ps[0]); ok {
				port = strconv.FormatUint(p, 10)
			}
		}
		fmt.Printf("%-20s %-30s %-15s\n", strOr(get(t, "id"), "-"), strOr(get(t, "image"), "-"), port)
	}
	fmt.Printf("\n%d template(s)\n", len(templates))
	return nil
}

func cmdAppsDeploy(token, template, name string, port int64, domain, sslEmail *string) error {
	if sslEmail != nil && domain == nil {
		return errors.New("--ssl-email requires --domain")
	}
	fmt.Printf("Deploying app '%s' from template '%s' on port %d...\n", name, template, port)
	body := map[string]any{"template_id": template, "name": name, "port": port}
	if domain != nil {
		body["domain"] = *domain
	}
	if sslEmail != nil {
		body["ssl_email"] = *sslEmail
	}
	result, err := agentPost("/apps/deploy", body, token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to deploy app: %s", strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Println("\x1b[32m✓\x1b[0m App deployed")
	fmt.Printf("  Name:         %s\n", name)
	fmt.Printf("  Port:         %d\n", port)
	fmt.Printf("  Container:    %s\n", shortID(strOr(get(result, "container_id"), "unknown")))
	if d, ok := str(get(result, "domain")); ok {
		fmt.Printf("  Domain:       %s\n", d)
	}
	if isTrue(get(result, "proxy")) {
		fmt.Println("  Proxy:        \x1b[32mconfigured\x1b[0m")
	}
	if w, ok := str(get(result, "proxy_warning")); ok {
		fmt.Fprintf(os.Stderr, "  \x1b[33mProxy warning:\x1b[0m %s\n", w)
	}
	if isTrue(get(result, "ssl")) {
		fmt.Println("  SSL:          \x1b[32mprovisioned\x1b[0m")
	}
	if w, ok := str(get(result, "ssl_warning")); ok {
		fmt.Fprintf(os.Stderr, "  \x1b[33mSSL warning:\x1b[0m %s\n", w)
	}
	return nil
}

func cmdAppsAction(token, containerID, action string) error {
	// "stoping" is the Rust CLI's own wording; kept for identical output.
	fmt.Printf("%sing container %s...\n", action, shortID(containerID))
	result, err := agentPostEmpty("/apps/"+containerID+"/"+action, token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to %s container: %s", action, strOr(get(result, "message"), "Unknown error"))
	}
	past := map[string]string{"stop": "stopped", "start": "started", "restart": "restarted"}[action]
	fmt.Printf("\x1b[32m✓\x1b[0m Container %s\n", past)
	return nil
}

func cmdAppsRemove(token, containerID string) error {
	fmt.Printf("Removing container %s...\n", shortID(containerID))
	result, err := agentDelete("/apps/"+containerID, token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to remove container: %s", strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Println("\x1b[32m✓\x1b[0m Container removed")
	return nil
}

func cmdAppsLogs(token, containerID string) error {
	result, err := agentGet("/apps/"+containerID+"/logs", token)
	if err != nil {
		return err
	}
	logs := strOr(get(result, "logs"), "")
	if logs == "" {
		fmt.Println("No logs available.")
	} else {
		fmt.Print(logs)
	}
	return nil
}

func cmdAppsCompose(token, file string) error {
	yml, err := readUTF8(file)
	if err != nil {
		return fmt.Errorf("Cannot read %s: %s", file, ioErr(err))
	}
	fmt.Printf("Deploying from %s...\n", file)
	result, err := agentPost("/apps/compose/deploy", map[string]any{"yaml": yml}, token)
	if err != nil {
		return err
	}
	svcs, _ := arr(get(result, "services"))
	for _, s := range svcs {
		fmt.Printf("\x1b[32m✓\x1b[0m Service deployed: %s\n", strOr(get(s, "name"), "-"))
	}
	failed, _ := arr(get(result, "failed"))
	for _, f := range failed {
		fmt.Fprintf(os.Stderr, "\x1b[31m✗\x1b[0m Service failed: %s — %s\n", strOr(get(f, "name"), "-"), strOr(get(f, "error"), "unknown"))
	}
	return nil
}
