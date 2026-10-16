package routes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/sitelock"
)

type dockerAppsDeployRequest struct {
	TemplateID string            `json:"template_id"`
	Name       string            `json:"name"`
	Port       uint16            `json:"port"`
	Env        map[string]string `json:"env"`
	// Optional domain for auto reverse proxy
	Domain *string `json:"domain"`
	// Email for Let's Encrypt SSL (requires domain)
	SslEmail *string `json:"ssl_email"`
	// "none" | "acme" | "provided". Absent = legacy inference from ssl_email.
	TlsMode *string `json:"tls_mode"`
	// Registry alias; provided mode only.
	TlsCertificate *string `json:"tls_certificate"`
	// Memory limit in MB (e.g., 512)
	MemoryMb *uint64 `json:"memory_mb"`
	// CPU limit as percentage (e.g., 50 = 50% of one core)
	CpuPercent *uint64 `json:"cpu_percent"`
	// When true, use Traefik file-based routing instead of nginx
	UseTraefik bool `json:"use_traefik"`
	// User ID for container labeling and isolation
	UserID *string `json:"user_id"`
	// Enable GPU passthrough (requires NVIDIA Container Toolkit)
	GpuEnabled bool `json:"gpu_enabled"`
	// Specific GPU device indices to assign. Empty/absent with gpu_enabled
	// assigns all GPUs. Ignored when gpu_enabled=false.
	GpuIndices []uint32 `json:"gpu_indices"`
}

// dockerAppsErr is the agent's {"error": …} body with an arbitrary status.
func dockerAppsErr(w http.ResponseWriter, status int, msg string) { writeErr(w, status, msg) }

// dockerAppsEnsureManaged rejects the request unless containerID names a
// dockpanel-managed container. WRITE-scope parity with the `list` READ path:
// prevents an admin from acting on the panel's OWN infrastructure containers
// (postgres/api/agent) by id. 403.
func dockerAppsEnsureManaged(w http.ResponseWriter, r *http.Request, containerID string) bool {
	if services.DockerAppsRequireManaged(r.Context(), containerID) != nil {
		writeErr(w, http.StatusForbidden, "Not a dockpanel-managed container")
		return false
	}
	return true
}

// dockerAppsTarget validates the {container_id} path param and the managed
// gate, the preamble of every per-container handler.
func dockerAppsTarget(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("container_id")
	if !isValidContainerID(id) {
		writeErr(w, http.StatusBadRequest, "Invalid container ID")
		return "", false
	}
	return id, dockerAppsEnsureManaged(w, r, id)
}

// dockerAppsTruncate keeps the first n characters (not bytes).
func dockerAppsTruncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func dockerAppsLossy(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

// dockerAppsRun runs a docker/CLI command with a timeout; timedOut reports a
// deadline hit (the Rust tokio::time::timeout arm).
func dockerAppsRun(ctx context.Context, timeout time.Duration, bin string, args ...string) (out safecmd.Output, timedOut bool, err error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err = safecmd.Exec(c, bin, args...)
	return out, errors.Is(err, context.DeadlineExceeded), err
}

// dockerAppsTemplates: GET /apps/templates — all available app templates.
func dockerAppsTemplatesHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, services.DockerAppsListTemplates())
}

// dockerAppsDeploy: POST /apps/deploy — deploy an app from a template,
// optionally with reverse proxy + SSL.
func dockerAppsDeploy(st *State, w http.ResponseWriter, r *http.Request) {
	var body dockerAppsDeployRequest
	if !nginxDecodeStrict(w, r, &body, "template_id", "name", "port") {
		return
	}
	if !isValidName(body.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid app name")
		return
	}
	if body.Domain != nil && !isValidDomain(*body.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}

	// Decide the TLS shape BEFORE the container exists: a request that names
	// a mode it cannot honour is refused with nothing deployed, rather than
	// answered with a running container and a warning.
	tls, err := services.DockerAppsTlsIntentFromRequest(body.TlsMode, body.SslEmail, body.TlsCertificate, body.UseTraefik)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if body.Env == nil {
		body.Env = map[string]string{}
	}
	result, err := services.DockerAppsDeployApp(r.Context(), body.TemplateID, body.Name, body.Port, body.Env, body.Domain,
		body.MemoryMb, body.CpuPercent, body.UserID, body.GpuEnabled, body.GpuIndices)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := map[string]any{
		"success":      true,
		"container_id": result.ContainerID,
		"name":         result.Name,
		"port":         result.Port,
	}
	// Auto reverse proxy: Traefik (file-based dynamic config) or nginx
	if body.Domain != nil {
		dockerAppsExposeDomain(r.Context(), st, *body.Domain, body.Port, tls, body.UseTraefik, response)
	}
	writeJSON(w, http.StatusOK, response)
}

// dockerAppsProxySiteConfig is a reverse-proxy vhost pointing at a local
// port. Built in one place because the same shape is needed to render the
// plain-HTTP config and again to re-render it with SSL, and two literals drift.
func dockerAppsProxySiteConfig(port uint16) *services.NginxSiteConfig {
	return &services.NginxSiteConfig{Runtime: "proxy", ProxyPort: &port}
}

// dockerAppsWriteVhost writes rendered to the vhost target atomically,
// returning the target and the previous body (for rollback).
func dockerAppsWriteVhost(domain, rendered string) (services.NginxVhostTarget, *string, error) {
	target := services.NginxVhostTargetFor(domain)
	var previous *string
	if b, err := os.ReadFile(target.Path); err == nil {
		s := string(b)
		previous = &s
	}
	tmp := target.Path + ".tmp"
	err := os.WriteFile(tmp, []byte(rendered), 0o644)
	if err == nil {
		err = os.Rename(tmp, target.Path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return target, previous, err
}

// dockerAppsExposeDomain puts a domain in front of a local port: write the
// vhost, then secure it the way the request asked.
//
// Shared by template deploys and compose stacks so a stack reaches the same
// code rather than a second copy of it. Failures are reported into response
// as warnings rather than returned: the container is already up, and losing
// the whole deploy over a certificate that can be retried from the panel
// would be the worse trade.
//
// ⚠ The trap this function used to hold: before v2.160.0 the TLS mode was
// INFERRED from whether an address was present, and an ordinary stack YAML
// edit (same domain, no address) rewrote the vhost from the plain proxy
// config — stripping the :443 block from behind a year of HSTS. A hard outage
// with no way back for the visitor. The mode is now STORED by the panel and
// sent on every deploy (DockerAppsTlsIntent); the Provided arm short-circuits
// BEFORE the HTTP-first write below, so a provided domain whose certificate
// cannot be served is left exactly as it was and reported — never degraded to
// HTTP.
//
// Reported as #104; the accepted design points: (1) multiple registered
// certificates, each named at upload time (the registry under SslRegistryDir);
// (2) referenced by alias, never by filesystem path (SslRegistryPaths);
// (3) SAN validation AT CLAIM TIME — ⭐ already exists and is unit-tested as
// SslCertCoversDomain, re-asked in the Provided arm below as defence in depth.
// Renewal suppression for a provided certificate is OUR consideration, not the
// reporter's, and is not binding.
func dockerAppsExposeDomain(ctx context.Context, st *State, domain string, port uint16, tls services.DockerAppsTlsIntent,
	useTraefik bool, response map[string]any) {
	// Held for the duration — this writes the same vhost path
	// SslEnableSslForSite and unexpose also write/delete. Released just
	// before SslEnableSslForSite, which takes the same (non-reentrant) lock
	// itself.
	unlock := sitelock.LockSite(domain)
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()

	if useTraefik {
		// --- Traefik mode: write a dynamic route config file ---
		if tls.Kind == services.DockerAppsTlsProvided {
			// Traefik's file provider has no per-route certificate form the
			// agent writes. Refuse in words and write nothing — a route
			// silently written without TLS would be the HSTS outage above,
			// one proxy over.
			slog.Warn(fmt.Sprintf("Auto-proxy (Traefik): %s asked for registered certificate %s, which only nginx can serve", domain, tls.Alias))
			response["proxy_warning"] = "registered certificates are served by nginx; this server proxies through Traefik"
			response["tls_refused"] = true
			return
		}
		ssl := tls.Kind == services.DockerAppsTlsAcme
		if err := services.TraefikWriteRouteConfig(domain, port, ssl); err != nil {
			slog.Warn(fmt.Sprintf("Auto-proxy (Traefik): failed to write route config for %s: %v", domain, err))
			response["proxy_warning"] = fmt.Sprintf("Traefik config failed: %v", err)
			return
		}
		response["domain"] = domain
		response["proxy"] = "traefik"
		response["tls_mode"] = tls.Mode()
		if ssl {
			response["ssl"] = true
		}
		slog.Info(fmt.Sprintf("Auto-proxy (Traefik): %s → 127.0.0.1:%d (ssl=%t)", domain, port, ssl))
		return
	}

	// --- nginx mode, registered certificate: render HTTPS directly ---
	//
	// Runs BEFORE the HTTP-first write below and never reaches it: a provided
	// domain is either rendered with its certificate or left exactly as it was.
	if tls.Kind == services.DockerAppsTlsProvided {
		alias := tls.Alias
		certPath, keyPath := services.SslRegistryPaths(alias)
		pem, err := os.ReadFile(certPath)
		if err != nil {
			slog.Warn(fmt.Sprintf("Auto-proxy: %s names registered certificate %s, which is not on this server (%v); nothing written", domain, alias, err))
			response["proxy_warning"] = fmt.Sprintf("no certificate named %s is registered on this server, so the vhost for "+
				"%s was left as it was rather than served over plain HTTP. Register the certificate and redeploy.", alias, domain)
			response["tls_refused"] = true
			return
		}
		// Binding point 3, re-asked here: the pair may have been replaced since
		// the claim, and a vhost that serves the wrong name is the quiet
		// failure this whole feature exists to stop.
		if _, err := services.SslCertCoversDomain(string(pem), domain); err != nil {
			slog.Warn(fmt.Sprintf("Auto-proxy: registered certificate %s does not cover %s: %v", alias, domain, err))
			response["proxy_warning"] = fmt.Sprintf("the registered certificate %s cannot serve %s: %v The vhost was left as it was.", alias, domain, err)
			response["tls_refused"] = true
			return
		}
		// Rendered through the ordinary renderer with the registry paths named
		// outright — NOT through SslEnableSslForSite, which hardcodes the
		// per-domain tree.
		cfg := dockerAppsProxySiteConfig(port)
		yes := true
		cfg.Ssl, cfg.SslCert, cfg.SslKey = &yes, &certPath, &keyPath
		rendered, err := services.NginxRenderSiteConfig(st.Templates, domain, cfg)
		if err != nil {
			slog.Warn(fmt.Sprintf("Auto-proxy: failed to render HTTPS config for %s: %v", domain, err))
			response["proxy_warning"] = fmt.Sprintf("Failed to render nginx config: %v", err)
			return
		}
		target, previous, err := dockerAppsWriteVhost(domain, rendered)
		if err != nil {
			slog.Warn(fmt.Sprintf("Auto-proxy: failed to write nginx config for %s: %v", domain, err))
			response["proxy_warning"] = fmt.Sprintf("Failed to write nginx config: %v", err)
			return
		}
		if !target.Live {
			slog.Info(fmt.Sprintf("Auto-proxy: %s is disabled, saved the HTTPS route to its parked configuration and left the maintenance response in service", domain))
			response["proxy_warning"] = fmt.Sprintf("%s is disabled, so the proxy configuration was saved but is not serving. Enable the site to bring it up.", domain)
			// The certificate IS bound — the parked body carries it — so this
			// is not a refused TLS leg, and the panel must not read it as one.
			response["domain"] = domain
			response["ssl"] = true
			response["parked"] = true
			response["tls_mode"] = "provided"
			response["tls_certificate"] = alias
			return
		}
		out, err := services.NginxTestConfig()
		switch {
		case err != nil:
			restored := services.NginxRestoreOrRemove(target.Path, previous)
			slog.Warn(fmt.Sprintf("Auto-proxy: nginx test error for %s: %v", domain, err))
			response["proxy_warning"] = fmt.Sprintf("Nginx test error: %v%s", err, services.NginxRestoreNote(restored))
		case !out.Success:
			restored := services.NginxRestoreOrRemove(target.Path, previous)
			slog.Warn(fmt.Sprintf("Auto-proxy: nginx config test failed for %s: %s", domain, out.Stderr))
			response["proxy_warning"] = fmt.Sprintf("Nginx config test failed: %s%s", out.Stderr, services.NginxRestoreNote(restored))
		default:
			if err := services.NginxReload(); err != nil {
				// On disk and passing the test, but nothing is serving it yet.
				// Answering `ssl: true` would have the panel record a success
				// over a domain still answering as it did before.
				slog.Warn(fmt.Sprintf("Auto-proxy: nginx reload failed after deploy for %s: %v", domain, err))
				response["proxy_warning"] = fmt.Sprintf("the HTTPS vhost for %s was written but nginx did not reload: %v. "+
					"Redeploy the stack, or reload nginx, to bring it into service.", domain, err)
				response["tls_refused"] = true
				return
			}
			response["domain"] = domain
			response["proxy"] = true
			response["ssl"] = true
			response["tls_mode"] = "provided"
			response["tls_certificate"] = alias
			slog.Info(fmt.Sprintf("Auto-proxy: %s → 127.0.0.1:%d over registered certificate %s", domain, port, alias))
		}
		return
	}

	// --- nginx mode: create nginx config pointing to the app's port ---
	// HTTP first; the ACME arm below re-renders with the certificate once it
	// has one.
	siteConfig := dockerAppsProxySiteConfig(port)
	if rendered, err := services.NginxRenderSiteConfig(st.Templates, domain, siteConfig); err != nil {
		slog.Warn(fmt.Sprintf("Auto-proxy: failed to render config for %s: %v", domain, err))
		response["proxy_warning"] = fmt.Sprintf("Failed to render nginx config: %v", err)
	} else if target, previous, err := dockerAppsWriteVhost(domain, rendered); err != nil {
		// Exposing an app on a domain the operator took offline updates that
		// domain's parked body instead of putting it back into service. The
		// snapshot exists because `nginx -t` is a whole-server check.
		slog.Warn(fmt.Sprintf("Auto-proxy: failed to write nginx config for %s: %v", domain, err))
		response["proxy_warning"] = fmt.Sprintf("Failed to write nginx config: %v", err)
	} else if !target.Live {
		slog.Info(fmt.Sprintf("Auto-proxy: %s is disabled, saved the route to its parked configuration and left the maintenance response in service", domain))
		response["proxy_warning"] = fmt.Sprintf("%s is disabled, so the proxy configuration was saved but is not serving. Enable the site to bring it up.", domain)
	} else {
		out, err := services.NginxTestConfig()
		switch {
		case err != nil:
			restored := services.NginxRestoreOrRemove(target.Path, previous)
			slog.Warn(fmt.Sprintf("Auto-proxy: nginx test error for %s: %v", domain, err))
			response["proxy_warning"] = fmt.Sprintf("Nginx test error: %v%s", err, services.NginxRestoreNote(restored))
		case !out.Success:
			restored := services.NginxRestoreOrRemove(target.Path, previous)
			slog.Warn(fmt.Sprintf("Auto-proxy: nginx config test failed for %s: %s", domain, out.Stderr))
			response["proxy_warning"] = fmt.Sprintf("Nginx config test failed: %s%s", out.Stderr, services.NginxRestoreNote(restored))
		default:
			if err := services.NginxReload(); err != nil {
				slog.Warn(fmt.Sprintf("Auto-proxy: nginx reload failed after deploy for %s: %v", domain, err))
			}
			response["domain"] = domain
			response["proxy"] = true
			slog.Info(fmt.Sprintf("Auto-proxy: %s → 127.0.0.1:%d", domain, port))
		}
	}

	// SSL provisioning (only if proxy was set up successfully, nginx mode only)
	if _, ok := response["proxy"]; !ok {
		return
	}
	response["tls_mode"] = tls.Mode()
	if tls.Kind != services.DockerAppsTlsAcme {
		return
	}

	// Wait for DNS propagation before attempting SSL (up to 30 seconds)
	for i := 0; i < 6; i++ {
		if i > 0 {
			time.Sleep(5 * time.Second)
		}
		_, err := net.DefaultResolver.LookupHost(ctx, domain)
		if err == nil {
			slog.Info(fmt.Sprintf("DNS resolved for %s (attempt %d/6)", domain, i+1))
			break
		}
		if i < 5 {
			slog.Info(fmt.Sprintf("Waiting for DNS propagation for %s... (%d/6)", domain, i+1))
			continue
		}
		slog.Warn(fmt.Sprintf("DNS not propagated for %s: %v — trying SSL anyway", domain, err))
	}

	account, err := services.SslLoadOrCreateAccount(tls.Email)
	if err != nil {
		slog.Warn(fmt.Sprintf("Auto-SSL: ACME account failed: %v", err))
		response["ssl_warning"] = fmt.Sprintf("ACME account failed: %v — retry from panel", err)
		response["ssl_pending"] = true
		return
	}
	if _, err := services.SslProvisionCert(ctx, account, domain, nil); err != nil {
		slog.Warn(fmt.Sprintf("Auto-SSL: cert provisioning failed for %s: %v", domain, err))
		response["ssl_warning"] = fmt.Sprintf("SSL provisioning failed: %v — retry from panel", err)
		response["ssl_pending"] = true
		return
	}
	unlock()
	locked = false
	if _, err := services.SslEnableSslForSite(st.Templates, domain, siteConfig); err != nil {
		slog.Warn(fmt.Sprintf("Auto-SSL: enable_ssl_for_site failed for %s: %v", domain, err))
		response["ssl_warning"] = fmt.Sprintf("SSL enable failed: %v — retry from panel", err)
		response["ssl_pending"] = true
		return
	}
	response["ssl"] = true
	slog.Info("Auto-SSL: certificate provisioned for " + domain)
}

// dockerAppsUnexposeDomain takes a domain back down: remove the vhost, the
// certificates and the logs — but only the ones that can still be proved to
// belong to the caller.
//
// Every delete here is conditional on the resource saying so. Before v2.53.0
// they all fired on a label alone, so removing an app whose domain a site had
// since taken over destroyed the SITE's vhost, certificates and logs. Shared
// with the compose-stack teardown so a stack cannot grow a second, unguarded
// copy of the same deletes.
func dockerAppsUnexposeDomain(domain string, hostPort *uint16, response map[string]any) {
	// Held for the full duration — removal must not interleave with a
	// concurrent expose/update on the same domain.
	defer sitelock.LockSite(domain)()

	// Remove the Traefik dynamic route config (if any). The legacy-name leg
	// inside checks ownership itself.
	services.TraefikRemoveRouteConfig(domain)

	// Remove the nginx config — only if it is still fronting THIS container
	// (the only thing in the vhost identifying the app is the proxy_pass to
	// the port the container published).
	//
	// BOTH the live path and the parked one: expose writes whichever one the
	// vhost target picks, so removing only the live path stranded the parked
	// file for good on a removed app whose domain was disabled at the time —
	// the domain became permanently unreclaimable, silently. Same ownership
	// check on each: the parked body is a frozen copy of the same rendered
	// vhost.
	livePath, parkedPath := services.NginxVhostPaths(domain)
	removedVhost := false
	for _, c := range []struct {
		path string
		live bool
	}{{livePath, true}, {parkedPath, false}} {
		if _, err := os.Stat(c.path); err != nil {
			continue
		}
		if services.OwnershipAppVhost(c.path, hostPort).MayDelete() {
			_ = os.Remove(c.path)
			removedVhost = true
			// The parked file is never read by nginx, so removing it owes no
			// reload — only the live path going away needs nginx told.
			if c.live {
				if err := services.NginxReload(); err != nil {
					slog.Warn(fmt.Sprintf("Auto-proxy cleanup: nginx reload failed after removing config for %s: %v", domain, err))
				}
			}
			slog.Info(fmt.Sprintf("Auto-proxy cleanup: removed nginx config for %s (%s)", domain, c.path))
		} else {
			slog.Warn(fmt.Sprintf("Auto-proxy cleanup: LEAVING %s in place — it does not proxy to this container's port. "+
				"Another site or app now serves %s; removing this app must not take it down.", c.path, domain))
			response["proxy_warning"] = fmt.Sprintf("The nginx configuration for %s is serving something else and was left in place.", domain)
		}
	}

	// Remove SSL certificates (panel-provisioned). A DNS-01 wildcard is
	// provisioned once under the zone apex and SHARED by every site in the
	// zone, so this directory is not necessarily this app's to delete.
	//
	// Also gated on removedVhost: a STOPPED (parked) container reports no port
	// in Docker's live listing, so the vhost check cannot prove ownership and
	// leaves the vhost standing — and the in-use scan excludes that same
	// vhost, so without this gate the certificate files were deleted out from
	// under a vhost that still named them, breaking `nginx -t` for the WHOLE
	// server at the next reload.
	sslDir := "/etc/dockpanel/ssl/" + domain
	if _, err := os.Stat(sslDir); err == nil {
		switch {
		case removedVhost && services.OwnershipCertDirInUseElsewhere(domain):
			slog.Warn(fmt.Sprintf("SSL cleanup: LEAVING %s in place — another vhost still points at it. Deleting it would "+
				"break that site at the next nginx reload.", sslDir))
		case removedVhost:
			_ = os.RemoveAll(sslDir)
			slog.Info("SSL cleanup: removed certs for " + domain)
		default:
			slog.Warn(fmt.Sprintf("SSL cleanup: LEAVING %s in place — its vhost was not removed this call (often a "+
				"stopped/parked container, whose port Docker no longer reports), so deleting the certs would orphan a "+
				"vhost that still names them.", sslDir))
		}
	}

	// Let's Encrypt is NOT the panel's namespace and this code never had any
	// business in it: provisioning is ACME into /etc/dockpanel/ssl, so every
	// certbot lineage was created by the operator, out of band (possibly the
	// one Postfix and Dovecot point at). There is no safe narrowing — the
	// delete is gone.

	// Remove nginx logs — only ours to remove if the vhost was ours.
	if removedVhost {
		_ = os.Remove("/var/log/nginx/" + domain + ".access.log")
		_ = os.Remove("/var/log/nginx/" + domain + ".error.log")
	}
}

// dockerAppsList: GET /apps — list all deployed apps.
func dockerAppsList(w http.ResponseWriter, r *http.Request) {
	apps, err := services.DockerAppsListDeployedApps(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, apps)
}

// dockerAppsPowerAction: POST /apps/{container_id}/{stop,start,restart}.
func dockerAppsPowerAction(action func(context.Context, string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := dockerAppsTarget(w, r)
		if !ok {
			return
		}
		if err := action(r.Context(), id); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	}
}

// dockerAppsLogs: GET /apps/{container_id}/logs.
func dockerAppsLogs(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	logs, err := services.DockerAppsGetAppLogs(r.Context(), id, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
}

// dockerAppsUpdate: POST /apps/{container_id}/update — pull the latest image
// and recreate (blue-green when the app has a domain with an nginx proxy).
func dockerAppsUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	// Detached from the request: a dropped connection (the caller relays a
	// browser request through a Cloudflare edge with a ~100s origin budget)
	// must not cancel this mid-recreate — between remove and create the app
	// has no container at all, only its bind-mounted data survives.
	result, err := services.DockerAppsUpdateApp(context.WithoutCancel(r.Context()), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":          true,
		"container_id":     result.ContainerID,
		"blue_green":       result.BlueGreen,
		"migrated_volumes": result.MigratedVolumes,
		"repaired_volumes": result.RepairedVolumes,
	})
}

// dockerAppsSensitivePatterns: env var name substrings whose values are
// masked. Substring and not a whole token, deliberately: an unknown key is
// safer over-masked than under-masked, and `APIKEY` has no separator to anchor
// on. The cost is paid by DockerAppsCatalogueNonSecretEnv, which exempts the
// names our OWN templates declare non-secret.
var dockerAppsSensitivePatterns = []string{"PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL", "AUTH"}

// dockerAppsIsSensitive decides whether GET /apps/{id}/env masks a value.
func dockerAppsIsSensitive(k string) bool {
	upper := strings.ToUpper(k)
	matches := false
	for _, p := range dockerAppsSensitivePatterns {
		if strings.Contains(upper, p) {
			matches = true
			break
		}
	}
	return (matches && !services.DockerAppsCatalogueNonSecretEnv(k)) || services.DockerAppsCatalogueSecretEnv(k)
}

// dockerAppsGetEnv: GET /apps/{container_id}/env — container environment,
// sensitive values masked.
func dockerAppsGetEnv(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	env, err := services.DockerAppsGetAppEnv(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(env))
	for _, kv := range env {
		v := kv[1]
		if dockerAppsIsSensitive(kv[0]) {
			v = services.DockerAppsEnvMask
		}
		out = append(out, map[string]any{"key": kv[0], "value": v})
	}
	writeJSON(w, http.StatusOK, map[string]any{"env": out})
}

// dockerAppsUpdateEnv: PUT /apps/{container_id}/env — update environment
// variables and recreate the container.
func dockerAppsUpdateEnv(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	var body struct {
		Env map[string]string `json:"env"`
	}
	if !nginxDecodeStrict(w, r, &body, "env") {
		return
	}
	// Detached for the same reason as dockerAppsUpdate.
	newID, err := services.DockerAppsUpdateEnv(context.WithoutCancel(r.Context()), id, body.Env)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "container_id": newID})
}

// dockerAppsStats: GET /apps/{container_id}/stats — live resource usage.
func dockerAppsStats(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	// docker stats --no-stream for a single snapshot
	out, timedOut, err := dockerAppsRun(r.Context(), 10*time.Second, "docker", "stats", "--no-stream", "--format",
		"{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.BlockIO}}|{{.PIDs}}", id)
	if timedOut {
		writeErr(w, http.StatusGatewayTimeout, "Timeout")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	parts := strings.Split(strings.TrimSpace(dockerAppsLossy(out.Stdout)), "|")
	if len(parts) < 6 {
		writeJSON(w, http.StatusOK, map[string]any{"error": "Container not running or stats unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cpu_percent":    strings.TrimSpace(strings.TrimRight(parts[0], "%")),
		"memory_usage":   strings.TrimSpace(parts[1]),
		"memory_percent": strings.TrimSpace(strings.TrimRight(parts[2], "%")),
		"network_io":     strings.TrimSpace(parts[3]),
		"block_io":       strings.TrimSpace(parts[4]),
		"pids":           strings.TrimSpace(parts[5]),
	})
}

// dockerAppsShellInfo: GET /apps/{container_id}/shell-info — shell
// availability for a container.
func dockerAppsShellInfo(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	name := ""
	if out, _, err := dockerAppsRun(r.Context(), 15*time.Second, "docker", "inspect", "--format", "{{.Name}}", id); err == nil {
		name = strings.TrimLeft(strings.TrimSpace(dockerAppsLossy(out.Stdout)), "/")
	}
	has := func(shell string) bool {
		out, _, err := dockerAppsRun(r.Context(), 15*time.Second, "docker", "exec", id, "which", shell)
		return err == nil && out.Success()
	}
	hasBash, hasSh := has("bash"), has("sh")
	shell := ""
	if hasBash {
		shell = "/bin/bash"
	} else if hasSh {
		shell = "/bin/sh"
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "has_bash": hasBash, "has_sh": hasSh, "shell": shell})
}

// dockerAppsContainerBlocked: commands that could escape the container.
var dockerAppsContainerBlocked = []string{
	"mount", "nsenter", "chroot", "/proc/1/", "/proc/sysrq", "docker", "kubectl",
	"unshare", "pivot_root", "setns", "capsh", "mknod", "debugfs", "kexec",
}

// dockerAppsExec: POST /apps/{container_id}/exec — execute a command inside
// a container.
func dockerAppsExec(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	command := "ls"
	if s, isStr := nginxField(body, "command").(string); isStr {
		command = s
	}
	if command == "" || len(command) > 1000 {
		writeErr(w, http.StatusBadRequest, "Invalid command")
		return
	}
	lower := strings.ToLower(command)
	for _, p := range dockerAppsContainerBlocked {
		if strings.Contains(lower, p) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("Blocked command: contains '%s'", p))
			return
		}
	}
	out, timedOut, err := dockerAppsRun(r.Context(), 30*time.Second, "docker", "exec", id, "sh", "-c", command)
	if timedOut {
		writeErr(w, http.StatusGatewayTimeout, "Command timed out (30s)")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var exitCode any
	if out.ExitCode >= 0 {
		exitCode = out.ExitCode
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   out.Success(),
		"stdout":    dockerAppsTruncate(dockerAppsLossy(out.Stdout), 50000),
		"stderr":    dockerAppsTruncate(dockerAppsLossy(out.Stderr), 10000),
		"exit_code": exitCode,
	})
}

// dockerAppsVolumes: GET /apps/{container_id}/volumes — volume info and sizes.
func dockerAppsVolumes(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	out, timedOut, err := dockerAppsRun(r.Context(), 15*time.Second, "docker", "inspect", "--format",
		"{{range .Mounts}}{{.Source}}|{{.Destination}}|{{.Type}}\n{{end}}", id)
	if timedOut {
		writeErr(w, http.StatusGatewayTimeout, "Timeout")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	volumes := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSuffix(dockerAppsLossy(out.Stdout), "\n"), "\n") {
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		source, dest, mountType := parts[0], parts[1], parts[2]
		var size uint64
		if du, _, err := dockerAppsRun(r.Context(), 15*time.Second, "du", "-sb", source); err == nil {
			if f := strings.Fields(dockerAppsLossy(du.Stdout)); len(f) > 0 {
				size, _ = strconv.ParseUint(f[0], 10, 64)
			}
		}
		listing := ""
		if ls, _, err := dockerAppsRun(r.Context(), 15*time.Second, "ls", "-la", source); err == nil {
			listing = dockerAppsLossy(ls.Stdout)
		}
		lines := strings.Split(strings.TrimSuffix(listing, "\n"), "\n")
		if listing == "" {
			lines = nil
		}
		if len(lines) > 20 {
			lines = lines[:20]
		}
		volumes = append(volumes, map[string]any{
			"source":      source,
			"destination": dest,
			"type":        mountType,
			"size_bytes":  size,
			"size_mb":     math.Round(float64(size)/1024.0/1024.0*10.0) / 10.0,
			"listing":     strings.Join(lines, "\n"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"volumes": volumes})
}

// dockerAppsRegistryLogin: POST /apps/registry-login — log in to a private
// Docker registry.
func dockerAppsRegistryLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Server   string `json:"server"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !nginxDecodeStrict(w, r, &body, "server", "username", "password") {
		return
	}
	if body.Server == "" || body.Username == "" {
		writeErr(w, http.StatusBadRequest, "Server and username required")
		return
	}
	if !dockerAppsIsValidImageRef(body.Server) {
		writeErr(w, http.StatusBadRequest, "Invalid registry server")
		return
	}
	// Pass the password via stdin to avoid leaking it in process args.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cmd := safecmd.Command(ctx, "docker", "login", body.Server, "-u", body.Username, "--password-stdin")
	cmd.Stdin = strings.NewReader(body.Password)
	out, err := safecmd.Run(ctx, cmd)
	if errors.Is(err, context.DeadlineExceeded) {
		writeErr(w, http.StatusGatewayTimeout, "Login timed out")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !out.Success() {
		writeErr(w, http.StatusUnauthorized, "Login failed: "+dockerAppsTruncate(dockerAppsLossy(out.Stderr), 200))
		return
	}
	slog.Info(fmt.Sprintf("Docker registry login: %s @ %s", body.Username, body.Server))
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "server": body.Server})
}

// dockerAppsListRegistries: GET /apps/registries — configured registries.
func dockerAppsListRegistries(w http.ResponseWriter, _ *http.Request) {
	// `docker login` runs through safecmd, which points DOCKER_CONFIG at this
	// dir — /root/.docker/config.json is never written by a panel login.
	servers := []string{}
	if content, err := os.ReadFile(safecmd.DockerConfigDir + "/config.json"); err == nil {
		var config map[string]any
		if json.Unmarshal(content, &config) == nil {
			if auths, ok := config["auths"].(map[string]any); ok {
				for k := range auths {
					servers = append(servers, k)
				}
			}
		}
	}
	sort.Strings(servers)
	writeJSON(w, http.StatusOK, map[string]any{"registries": servers})
}

// dockerAppsRegistryLogout: POST /apps/registry-logout.
func dockerAppsRegistryLogout(w http.ResponseWriter, r *http.Request) {
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	server, _ := nginxField(body, "server").(string)
	if server == "" {
		writeErr(w, http.StatusBadRequest, "Server required")
		return
	}
	if !dockerAppsIsValidImageRef(server) {
		writeErr(w, http.StatusBadRequest, "Invalid registry server")
		return
	}
	_, _, _ = dockerAppsRun(r.Context(), 30*time.Second, "docker", "logout", server)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// dockerAppsRemove: DELETE /apps/{container_id} — remove a deployed app and
// clean up its proxy.
func dockerAppsRemove(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	// Everything the cleanup below needs to PROVE it owns what it deletes,
	// read while the container still exists. The labels alone are not proof.
	identity := services.DockerAppsGetRemovalIdentity(r.Context(), id)

	if err := services.DockerAppsRemoveApp(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := map[string]any{"success": true}

	// Clean up proxy config (nginx + Traefik) + SSL certs if a domain was set
	// — every delete conditional on the resource saying it belongs to this app.
	if identity.Domain != nil {
		response["domain_removed"] = *identity.Domain
		dockerAppsUnexposeDomain(*identity.Domain, identity.HostPort, response)
	}

	// Clean up persistent volume data — only when this container actually
	// bind-mounts out of that directory. The name label is not proof: a
	// compose service carries a caller-supplied name in the same label while
	// its own data lives under /var/lib/dockpanel/compose. The directory comes
	// from the container's OWN binds, which also catches what the
	// v2.111.0–v2.113.3 migration wrote under the CONTAINER name.
	switch {
	case identity.AppDir != nil:
		if _, err := os.Stat(*identity.AppDir); err == nil {
			_ = os.RemoveAll(*identity.AppDir)
			slog.Info("Volume cleanup: removed " + *identity.AppDir)
		}
	case identity.Name != nil:
		labelDir := services.DockerAppsAppDataDir + "/" + *identity.Name
		if _, err := os.Stat(labelDir); err == nil {
			slog.Warn(fmt.Sprintf("Volume cleanup: LEAVING %s in place — this container had no bind mount under it, so the "+
				"directory belongs to a different app.", labelDir))
		}
	}
	writeJSON(w, http.StatusOK, response)
}

type dockerAppsComposeRequest struct {
	Yaml    string  `json:"yaml"`
	StackID *string `json:"stack_id"`
	// Optional domain to put in front of the stack (deploy only).
	Domain *string `json:"domain"`
	// Email for Let's Encrypt SSL (requires domain).
	SslEmail *string `json:"ssl_email"`
	// "none" | "acme" | "provided". Absent = legacy inference from ssl_email.
	TlsMode *string `json:"tls_mode"`
	// Registry alias; provided mode only.
	TlsCertificate *string `json:"tls_certificate"`
	// Host port the domain proxies to. Defaults to the first published port
	// in the stack, which is the right answer for every package we ship.
	ExposePort *uint16 `json:"expose_port"`
}

// dockerAppsComposeParse: POST /apps/compose/parse — services preview.
func dockerAppsComposeParse(w http.ResponseWriter, r *http.Request) {
	var body dockerAppsComposeRequest
	if !nginxDecodeStrict(w, r, &body, "yaml") {
		return
	}
	svcs, err := services.ComposeParseCompose(body.Yaml, body.StackID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, svcs)
}

// dockerAppsComposeValidate: POST /apps/compose/validate — compose YAML
// validation with detailed feedback.
func dockerAppsComposeValidate(w http.ResponseWriter, r *http.Request) {
	var body dockerAppsComposeRequest
	if !nginxDecodeStrict(w, r, &body, "yaml") {
		return
	}
	errs, warnings, info := []map[string]any{}, []map[string]any{}, []map[string]any{}
	warn := func(svc, msg string) { warnings = append(warnings, map[string]any{"service": svc, "message": msg}) }
	dbImages := []string{"postgres", "mysql", "mariadb", "mongo", "redis"}
	isDB := func(image string) bool {
		for _, db := range dbImages {
			if strings.Contains(image, db) {
				return true
			}
		}
		return false
	}

	if svcs, err := services.ComposeParseCompose(body.Yaml, body.StackID); err != nil {
		errs = append(errs, map[string]any{"message": err.Error()})
	} else {
		info = append(info, map[string]any{"message": fmt.Sprintf("%d service(s) found", len(svcs))})
		for _, svc := range svcs {
			// Check for latest tag
			if strings.HasSuffix(svc.Image, ":latest") || !strings.Contains(svc.Image, ":") {
				warn(svc.Key, "Using ':latest' tag — pin to a specific version for reproducible deploys")
			}
			// Check for exposed privileged ports
			for _, p := range svc.Ports {
				if p.Host < 1024 && p.Host != 80 && p.Host != 443 {
					warn(svc.Key, fmt.Sprintf("Privileged port %d — consider using a higher port", p.Host))
				}
			}
			// Check for missing volumes on databases
			if isDB(svc.Image) && len(svc.Volumes) == 0 {
				warn(svc.Key, "Database service without volumes — data will be lost on container restart")
			}
			// Check for missing restart policy
			if svc.Restart == "" || svc.Restart == "no" {
				info = append(info, map[string]any{"service": svc.Key,
					"message": "No restart policy — container won't auto-restart. Consider 'unless-stopped'"})
			}
			// Check for missing env vars on databases
			if len(svc.Environment) == 0 && isDB(svc.Image) {
				warn(svc.Key, "Database without environment variables — password/root may use defaults")
			}
			// This deployer has no field for user/healthcheck/entrypoint —
			// saying "valid" over a compose file that declares one would
			// silently drop a directive the author wrote and expects honoured.
			if svc.UserIgnored {
				warn(svc.Key, "'user:' is not supported and will be ignored — the image's own default user runs this container")
			}
			if svc.HealthcheckIgnored {
				warn(svc.Key, "'healthcheck:' is not supported and will be ignored — Docker's own healthcheck state will not reflect it")
			}
			if svc.EntrypointIgnored {
				warn(svc.Key, "'entrypoint:' is not supported and will be ignored — the image's own ENTRYPOINT runs unchanged")
			}
		}
	}
	// YAML syntax check
	if strings.Contains(body.Yaml, "\t") {
		warnings = append(warnings, map[string]any{"message": "YAML contains tabs — use spaces for indentation to avoid parse errors"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": len(errs) == 0, "errors": errs, "warnings": warnings, "info": info})
}

// dockerAppsComposeDeploy: POST /apps/compose/deploy — deploy services from a
// parsed compose file, optionally behind a domain with a certificate.
func dockerAppsComposeDeploy(st *State, w http.ResponseWriter, r *http.Request) {
	var body dockerAppsComposeRequest
	if !nginxDecodeStrict(w, r, &body, "yaml") {
		return
	}
	svcs, err := services.ComposeParseCompose(body.Yaml, body.StackID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Domain != nil && !isValidDomain(*body.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}

	// Decided here for the same reason the port is resolved below: a request
	// the agent cannot honour is refused BEFORE any container runs. Compose
	// stacks have no use_traefik of their own — always the nginx arm.
	tls, err := services.DockerAppsTlsIntentFromRequest(body.TlsMode, body.SslEmail, body.TlsCertificate, false)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Resolve which published port the domain should point at before
	// deploying, so a stack that publishes nothing is refused up front.
	var exposePort *uint16
	if body.Domain != nil {
		exposePort = body.ExposePort
		if exposePort == nil {
			for _, s := range svcs {
				if len(s.Ports) > 0 {
					p := s.Ports[0].Host
					exposePort = &p
					break
				}
			}
		}
		if exposePort == nil {
			writeErr(w, http.StatusBadRequest, "This stack publishes no host port, so there is nothing for the domain to point at. "+
				"Add a 'ports:' entry to the service you want reachable.")
			return
		}
	}

	result := services.ComposeDeployCompose(r.Context(), svcs, body.StackID)
	response := map[string]any{"services": result.Services, "network": result.Network}

	// Only front a stack that actually came up. Writing a vhost to a dead
	// upstream would hand the operator a 502 and a certificate for it.
	if body.Domain != nil && exposePort != nil {
		running := false
		for _, s := range result.Services {
			if s.Status == "running" {
				running = true
				break
			}
		}
		if running {
			dockerAppsExposeDomain(r.Context(), st, *body.Domain, *exposePort, tls, false, response)
		} else {
			response["proxy_warning"] = "No service in the stack stayed running, so no vhost was written. Fix the stack and re-apply the domain."
		}
	}
	writeJSON(w, http.StatusOK, response)
}

// dockerAppsStackAction: POST /apps/stack/action — a lifecycle action on all
// containers in a stack.
func dockerAppsStackAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		StackID string `json:"stack_id"`
		Action  string `json:"action"`
		// The domain this stack was exposed on, so `remove` can take the vhost
		// and certificates down with it.
		Domain *string `json:"domain"`
	}
	if !nginxDecodeStrict(w, r, &body, "stack_id", "action") {
		return
	}
	actions := map[string]struct {
		fn   func(context.Context, string) error
		done string
	}{
		"start":   {services.DockerAppsStartApp, "started"},
		"stop":    {services.DockerAppsStopApp, "stopped"},
		"restart": {services.DockerAppsRestartApp, "restarted"},
		"remove":  {services.DockerAppsRemoveApp, "removed"},
	}
	action, ok := actions[body.Action]
	if !ok {
		writeErr(w, http.StatusBadRequest, "Action must be start, stop, restart, or remove")
		return
	}

	apps, err := services.DockerAppsListDeployedApps(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var stack []services.DockerAppsDeployedApp
	for _, a := range apps {
		if a.StackID != nil && *a.StackID == body.StackID {
			stack = append(stack, a)
		}
	}
	if len(stack) == 0 {
		writeErr(w, http.StatusNotFound, "No containers found for this stack")
		return
	}

	// Read the published port while the containers still exist — it is what
	// proves the vhost is this stack's. From HostConfig (via inspect), NOT the
	// list's live port, which reads empty the moment a stack is stopped and
	// would permanently strand its vhost and certificate.
	var stackPort *uint16
	for _, a := range stack {
		if p := services.DockerAppsInspectHostPort(r.Context(), a.ContainerID); p != nil {
			stackPort = p
			break
		}
	}

	results := []map[string]any{}
	for _, a := range stack {
		status := action.done
		var errMsg any
		if err := action.fn(r.Context(), a.ContainerID); err != nil {
			status, errMsg = "failed", err.Error()
		}
		results = append(results, map[string]any{"container_id": a.ContainerID, "name": a.Name, "status": status, "error": errMsg})
	}

	response := map[string]any{"stack_id": body.StackID, "action": body.Action, "results": results}
	if body.Action == "remove" {
		// The stack's own bridge outlives its last container; the removal
		// refuses anything it cannot prove is ours.
		services.ComposeRemoveStackNetwork(r.Context(), &body.StackID)
		// And the vhost, certificates and logs — through the same guarded
		// teardown an app removal uses.
		if body.Domain != nil && isValidDomain(*body.Domain) {
			response["domain_removed"] = *body.Domain
			dockerAppsUnexposeDomain(*body.Domain, stackPort, response)
		}
	}
	writeJSON(w, http.StatusOK, response)
}

// dockerAppsListImages: GET /apps/images — list Docker images.
func dockerAppsListImages(w http.ResponseWriter, r *http.Request) {
	out, timedOut, err := dockerAppsRun(r.Context(), 30*time.Second, "docker", "images", "--format",
		"{{.Repository}}|{{.Tag}}|{{.ID}}|{{.Size}}|{{.CreatedSince}}", "--no-trunc")
	if timedOut {
		writeErr(w, http.StatusGatewayTimeout, "Timeout listing images")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	images := []map[string]any{}
	for _, l := range strings.Split(dockerAppsLossy(out.Stdout), "\n") {
		if l == "" {
			continue
		}
		p := strings.Split(l, "|")
		get := func(i int) string {
			if i < len(p) {
				return p[i]
			}
			return ""
		}
		images = append(images, map[string]any{"repository": get(0), "tag": get(1), "id": get(2), "size": get(3), "created": get(4)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"images": images})
}

// dockerAppsPruneImages: POST /apps/images/prune — remove unused images.
//
// Deliberately NOT `-a`: `-a` widens the sweep from dangling images to every
// image not backing a running container, which reaches git-deploy rollback
// targets and manual snapshots — neither can be re-pulled. The label filter
// is defence in depth; the dropped `-a` is what makes this safe.
func dockerAppsPruneImages(w http.ResponseWriter, r *http.Request) {
	out, timedOut, err := dockerAppsRun(r.Context(), 120*time.Second, "docker", "image", "prune", "-f", "--filter", "label!=dockpanel.managed=true")
	if timedOut {
		writeErr(w, http.StatusGatewayTimeout, "Image prune timed out (120s)")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "output": strings.TrimSpace(dockerAppsLossy(out.Stdout))})
}

// dockerAppsRemoveImage: DELETE /apps/images/{id}.
func dockerAppsRemoveImage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Alphanumeric + : / . - _ only, and never a leading dash — the charset
	// alone still allows "--help", which `docker rmi` reads as a flag.
	valid := id != "" && len(id) <= 256 && !strings.HasPrefix(id, "-")
	for _, c := range id {
		if !isASCIIAlnum(c) && !strings.ContainsRune(":/.-_", c) {
			valid = false
		}
	}
	if !valid {
		writeErr(w, http.StatusBadRequest, "Invalid image ID")
		return
	}
	out, timedOut, err := dockerAppsRun(r.Context(), 60*time.Second, "docker", "rmi", id)
	if timedOut {
		writeErr(w, http.StatusGatewayTimeout, "Image removal timed out (60s)")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !out.Success() {
		writeErr(w, http.StatusConflict, "Cannot remove: "+dockerAppsTruncate(dockerAppsLossy(out.Stderr), 200))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// dockerAppsSnapshotTag force-namespaces a snapshot tag under
// `dockpanel-snapshot:` so a snapshot can never overwrite a system image.
func dockerAppsSnapshotTag(raw *string, now int64) string {
	r := strconv.FormatInt(now, 10)
	if raw != nil {
		r = *raw
	}
	suffix := strings.TrimPrefix(r, "dockpanel-snapshot:")
	var b strings.Builder
	n := 0
	for _, c := range suffix {
		if n == 128 {
			break
		}
		if isASCIIAlnum(c) || c == '-' || c == '_' || c == '.' {
			b.WriteRune(c)
			n++
		}
	}
	if b.Len() == 0 {
		return fmt.Sprintf("dockpanel-snapshot:%d", now)
	}
	return "dockpanel-snapshot:" + b.String()
}

// dockerAppsSnapshot: POST /apps/{container_id}/snapshot — commit container
// to an image.
func dockerAppsSnapshot(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	var body struct {
		Tag *string `json:"tag"`
	}
	if !nginxDecodeStrict(w, r, &body) {
		return
	}
	tag := dockerAppsSnapshotTag(body.Tag, time.Now().Unix())
	out, timedOut, err := dockerAppsRun(r.Context(), 120*time.Second, "docker", "commit", id, tag)
	if timedOut {
		writeErr(w, http.StatusGatewayTimeout, "Snapshot timed out")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !out.Success() {
		writeErr(w, http.StatusInternalServerError, "Snapshot failed: "+dockerAppsLossy(out.Stderr))
		return
	}
	imageID := strings.TrimSpace(dockerAppsLossy(out.Stdout))
	slog.Info(fmt.Sprintf("Container snapshot: %s → %s (%s)", id, tag, imageID))
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "tag": tag, "image_id": imageID})
}

// dockerAppsIsValidImageRef validates that an image reference contains only
// safe characters.
func dockerAppsIsValidImageRef(image string) bool {
	if image == "" || len(image) > 256 || strings.HasPrefix(image, "-") {
		return false
	}
	for _, c := range image {
		if !isASCIIAlnum(c) && !strings.ContainsRune("/:.-_@", c) {
			return false
		}
	}
	return true
}

// dockerAppsChangeImage: POST /apps/{container_id}/change-image — recreate
// the container with a new image while PRESERVING its full runtime config
// (see DockerAppsChangeContainerImage).
func dockerAppsChangeImage(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	image, _ := nginxField(body, "image").(string)
	image = strings.TrimSpace(image)
	if image == "" {
		writeErr(w, http.StatusBadRequest, "image is required")
		return
	}
	if !dockerAppsIsValidImageRef(image) {
		writeErr(w, http.StatusBadRequest, "Invalid image reference: must be <= 256 chars, alphanumeric with / : . - _ @ only, and not start with -")
		return
	}
	// Detached for the same reason as dockerAppsUpdate.
	newID, err := services.DockerAppsChangeContainerImage(context.WithoutCancel(r.Context()), id, image)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "container_id": newID, "image": image})
}

// dockerAppsJSONU64 is serde_json's Value::as_u64.
func dockerAppsJSONU64(v any) *uint64 {
	f, ok := v.(float64)
	if !ok || f < 0 || f != math.Trunc(f) || f > math.MaxUint64 {
		return nil
	}
	u := uint64(f)
	return &u
}

// dockerAppsUpdateLimits: POST /apps/{container_id}/update-limits — update
// CPU/memory limits on a running container.
func dockerAppsUpdateLimits(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	memoryMb := dockerAppsJSONU64(nginxField(body, "memory_mb"))
	cpuPercent := dockerAppsJSONU64(nginxField(body, "cpu_percent"))

	args := []string{"update"}
	if memoryMb != nil {
		args = append(args, fmt.Sprintf("--memory=%dm", *memoryMb), fmt.Sprintf("--memory-swap=%dm", *memoryMb*2)) // swap = 2x memory
	}
	if cpuPercent != nil {
		// cpu_percent maps to --cpus (100% = 1.0 CPU)
		args = append(args, fmt.Sprintf("--cpus=%.2f", float64(*cpuPercent)/100.0))
	}
	args = append(args, id)

	out, timedOut, err := dockerAppsRun(r.Context(), 15*time.Second, "docker", args...)
	if timedOut {
		writeErr(w, http.StatusGatewayTimeout, "Timeout")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !out.Success() {
		writeErr(w, http.StatusInternalServerError, "docker update failed: "+dockerAppsLossy(out.Stderr))
		return
	}
	slog.Info(fmt.Sprintf("Container limits updated: %s (mem: %v MB, cpu: %v%%)", id, memoryMb, cpuPercent))
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "memory_mb": memoryMb, "cpu_percent": cpuPercent})
}

// dockerAppsUpdateCheck: GET /apps/update-check — check all managed
// containers for available image updates.
func dockerAppsUpdateCheck(w http.ResponseWriter, r *http.Request) {
	results, err := services.DockerAppsCheckImageUpdates(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	count := 0
	for _, u := range results {
		if u.UpdateAvailable {
			count++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"updates": results, "updates_available": count})
}

// ─── Ollama model management ────────────────────────────────────────────

// dockerAppsOllamaList: GET /apps/{container_id}/ollama/models.
func dockerAppsOllamaList(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	out, timedOut, err := dockerAppsRun(r.Context(), 15*time.Second, "docker", "exec", id, "ollama", "list")
	if timedOut {
		writeErr(w, http.StatusGatewayTimeout, "Timed out listing models")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !out.Success() {
		writeJSON(w, http.StatusOK, map[string]any{"models": []any{}, "error": strings.TrimSpace(dockerAppsLossy(out.Stderr))})
		return
	}
	models := []map[string]any{}
	for i, line := range strings.Split(dockerAppsLossy(out.Stdout), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" { // skip header row
			continue
		}
		p := strings.Fields(line)
		get := func(i int) string {
			if i < len(p) {
				return p[i]
			}
			return ""
		}
		size := ""
		if len(p) > 2 {
			size = p[2] + " " + get(3)
		}
		modified := ""
		if len(p) > 4 {
			modified = strings.Join(p[4:], " ")
		}
		models = append(models, map[string]any{"name": get(0), "id": get(1), "size": size, "modified": modified})
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": models})
}

// dockerAppsOllamaModel validates the `model` field: alphanumeric, hyphens,
// underscores, colons, slashes, dots; never a leading dash.
func dockerAppsOllamaModel(w http.ResponseWriter, r *http.Request) (string, bool) {
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return "", false
	}
	model, _ := nginxField(body, "model").(string)
	model = strings.TrimSpace(model)
	if model == "" || len(model) > 200 || strings.HasPrefix(model, "-") {
		writeErr(w, http.StatusBadRequest, "Invalid model name")
		return "", false
	}
	for _, c := range model {
		// Rust char::is_alphanumeric is Unicode-aware.
		if !(unicode.IsLetter(c) || unicode.IsNumber(c) || strings.ContainsRune("-_:/.", c)) {
			writeErr(w, http.StatusBadRequest, "Invalid model name characters")
			return "", false
		}
	}
	return model, true
}

// dockerAppsOllamaPull: POST /apps/{container_id}/ollama/pull.
func dockerAppsOllamaPull(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	model, ok := dockerAppsOllamaModel(w, r)
	if !ok {
		return
	}
	// ollama pull can take a long time for large models — 10 minute timeout
	out, timedOut, err := dockerAppsRun(r.Context(), 600*time.Second, "docker", "exec", id, "ollama", "pull", model)
	if timedOut {
		writeErr(w, http.StatusGatewayTimeout, "Model pull timed out (10m). Try a smaller model or pull manually.")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": out.Success(),
		"stdout":  dockerAppsTruncate(dockerAppsLossy(out.Stdout), 50000),
		"stderr":  dockerAppsTruncate(dockerAppsLossy(out.Stderr), 10000),
	})
}

// dockerAppsOllamaDelete: POST /apps/{container_id}/ollama/delete.
func dockerAppsOllamaDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := dockerAppsTarget(w, r)
	if !ok {
		return
	}
	model, ok := dockerAppsOllamaModel(w, r)
	if !ok {
		return
	}
	out, timedOut, err := dockerAppsRun(r.Context(), 30*time.Second, "docker", "exec", id, "ollama", "rm", model)
	if timedOut {
		writeErr(w, http.StatusGatewayTimeout, "Timed out")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	msg := dockerAppsLossy(out.Stderr)
	if out.Success() {
		msg = "Deleted " + model
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": out.Success(), "message": msg})
}

func dockerAppsParseU64(s string) any {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return nil
	}
	return v
}

func dockerAppsParseF64(s string) any {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	return v
}

func dockerAppsOrZero(v any) any {
	if v == nil {
		return uint64(0)
	}
	return v
}

// dockerAppsParseGpuLine parses one `nvidia-smi --query-gpu` CSV row. GPU
// names can theoretically contain ", ", so the index is the first field, the
// 11 metrics are taken from the right, and everything between is the name.
func dockerAppsParseGpuLine(line string) map[string]any {
	p := strings.Split(line, ", ")
	if len(p) < 13 {
		// Fallback: fewer fields than expected
		name := "Unknown"
		if len(p) > 1 {
			name = p[1]
		}
		return map[string]any{
			"index": dockerAppsOrZero(dockerAppsParseU64(p[0])), "name": strings.TrimSpace(name),
			"memory_total_mb": 0, "memory_used_mb": 0, "memory_free_mb": 0,
			"utilization_gpu_pct": 0, "utilization_memory_pct": 0,
			"temperature_c": nil, "power_draw_w": nil, "power_limit_w": nil,
			"fan_speed_pct": nil, "driver_version": "", "performance_state": "",
		}
	}
	e := len(p) - 11 // 11 fields after the name
	return map[string]any{
		"index":                  dockerAppsOrZero(dockerAppsParseU64(p[0])),
		"name":                   strings.TrimSpace(strings.Join(p[1:e], ", ")),
		"memory_total_mb":        dockerAppsOrZero(dockerAppsParseU64(p[e])),
		"memory_used_mb":         dockerAppsOrZero(dockerAppsParseU64(p[e+1])),
		"memory_free_mb":         dockerAppsOrZero(dockerAppsParseU64(p[e+2])),
		"utilization_gpu_pct":    dockerAppsOrZero(dockerAppsParseU64(p[e+3])),
		"utilization_memory_pct": dockerAppsOrZero(dockerAppsParseU64(p[e+4])),
		"temperature_c":          dockerAppsParseU64(p[e+5]),
		"power_draw_w":           dockerAppsParseF64(p[e+6]),
		"power_limit_w":          dockerAppsParseF64(p[e+7]),
		"fan_speed_pct":          dockerAppsParseU64(p[e+8]),
		"driver_version":         strings.TrimSpace(p[e+9]),
		"performance_state":      strings.TrimSpace(p[e+10]),
	}
}

// dockerAppsGpuInfo: GET /apps/gpu-info — GPU utilisation, VRAM,
// temperature, power, per-process usage.
func dockerAppsGpuInfo(w http.ResponseWriter, r *http.Request) {
	out, _, err := dockerAppsRun(r.Context(), 10*time.Second, "nvidia-smi",
		"--query-gpu=index,name,memory.total,memory.used,memory.free,utilization.gpu,utilization.memory,temperature.gpu,power.draw,power.limit,fan.speed,driver_version,pstate",
		"--format=csv,noheader,nounits")
	if err != nil || !out.Success() {
		writeJSON(w, http.StatusOK, map[string]any{
			"available": false, "gpus": []any{}, "gpu_count": 0, "nvidia_toolkit_installed": false, "processes": []any{},
		})
		return
	}
	gpus := []map[string]any{}
	for _, line := range strings.Split(dockerAppsLossy(out.Stdout), "\n") {
		if strings.TrimSpace(line) != "" {
			gpus = append(gpus, dockerAppsParseGpuLine(line))
		}
	}

	// Per-process GPU usage (which PIDs are using which GPU and how much VRAM)
	processes := []map[string]any{}
	if pout, _, err := dockerAppsRun(r.Context(), 10*time.Second, "nvidia-smi",
		"--query-compute-apps=pid,gpu_uuid,used_gpu_memory,name", "--format=csv,noheader,nounits"); err == nil && pout.Success() {
		for _, line := range strings.Split(dockerAppsLossy(pout.Stdout), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			p := strings.Split(line, ", ")
			get := func(i int) string {
				if i < len(p) {
					return strings.TrimSpace(p[i])
				}
				return ""
			}
			pid, _ := strconv.ParseUint(get(0), 10, 64)
			var container any
			if name, ok := dockerAppsResolvePidToContainer(r.Context(), pid); ok {
				container = name
			}
			processes = append(processes, map[string]any{
				"pid":            pid,
				"gpu_uuid":       get(1),
				"vram_used_mb":   dockerAppsOrZero(dockerAppsParseU64(get(2))),
				"process_name":   get(3),
				"container_name": container,
			})
		}
	}

	// Is the NVIDIA Container Toolkit installed?
	tout, _, terr := dockerAppsRun(r.Context(), 5*time.Second, "nvidia-container-cli", "--version")
	toolkit := terr == nil && tout.Success()

	writeJSON(w, http.StatusOK, map[string]any{
		"available": true, "gpus": gpus, "gpu_count": len(gpus), "nvidia_toolkit_installed": toolkit, "processes": processes,
	})
}

// dockerAppsResolvePidToContainer resolves a host PID to a Docker container
// name (if it belongs to one) via its cgroup.
func dockerAppsResolvePidToContainer(ctx context.Context, pid uint64) (string, bool) {
	cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", false
	}
	id := ""
	// Format: "0::/docker/<container_id>" or "0::/system.slice/docker-<id>.scope"
	for _, line := range strings.Split(string(cgroup), "\n") {
		after := ""
		if _, a, ok := strings.Cut(line, "/docker/"); ok {
			after = a
		} else if _, a, ok := strings.Cut(line, "/docker-"); ok {
			after = a
		} else {
			continue
		}
		after = strings.TrimSuffix(after, ".scope")
		r := []rune(after)
		cand := string(r[:min(len(r), 12)])
		if len([]rune(cand)) >= 12 {
			id = cand
			break
		}
	}
	if id == "" {
		return "", false
	}
	out, _, err := dockerAppsRun(ctx, 5*time.Second, "docker", "inspect", "--format", "{{.Name}}", id)
	if err != nil || !out.Success() {
		return "", false
	}
	name := strings.TrimLeft(strings.TrimSpace(dockerAppsLossy(out.Stdout)), "/")
	return name, name != ""
}

func registerDockerApps(r *Router) {
	st := r.State
	r.Handle("GET /apps/templates", dockerAppsTemplatesHandler)
	r.Handle("GET /apps/update-check", dockerAppsUpdateCheck)
	r.Handle("POST /apps/deploy", func(w http.ResponseWriter, req *http.Request) { dockerAppsDeploy(st, w, req) })
	r.Handle("POST /apps/compose/parse", dockerAppsComposeParse)
	r.Handle("POST /apps/compose/validate", dockerAppsComposeValidate)
	r.Handle("POST /apps/compose/deploy", func(w http.ResponseWriter, req *http.Request) { dockerAppsComposeDeploy(st, w, req) })
	r.Handle("POST /apps/stack/action", dockerAppsStackAction)
	r.Handle("GET /apps/registries", dockerAppsListRegistries)
	r.Handle("POST /apps/registry-login", dockerAppsRegistryLogin)
	r.Handle("POST /apps/registry-logout", dockerAppsRegistryLogout)
	r.Handle("GET /apps/images", dockerAppsListImages)
	r.Handle("POST /apps/images/prune", dockerAppsPruneImages)
	r.Handle("DELETE /apps/images/{id}", dockerAppsRemoveImage)
	r.Handle("GET /apps", dockerAppsList)
	r.Handle("DELETE /apps/{container_id}", dockerAppsRemove)
	r.Handle("POST /apps/{container_id}/stop", dockerAppsPowerAction(services.DockerAppsStopApp))
	r.Handle("POST /apps/{container_id}/start", dockerAppsPowerAction(services.DockerAppsStartApp))
	r.Handle("POST /apps/{container_id}/restart", dockerAppsPowerAction(services.DockerAppsRestartApp))
	r.Handle("GET /apps/{container_id}/logs", dockerAppsLogs)
	r.Handle("GET /apps/{container_id}/env", dockerAppsGetEnv)
	r.Handle("PUT /apps/{container_id}/env", dockerAppsUpdateEnv)
	r.Handle("POST /apps/{container_id}/update", dockerAppsUpdate)
	r.Handle("GET /apps/{container_id}/stats", dockerAppsStats)
	r.Handle("GET /apps/{container_id}/shell-info", dockerAppsShellInfo)
	r.Handle("POST /apps/{container_id}/exec", dockerAppsExec)
	r.Handle("GET /apps/{container_id}/volumes", dockerAppsVolumes)
	r.Handle("POST /apps/{container_id}/snapshot", dockerAppsSnapshot)
	r.Handle("POST /apps/{container_id}/change-image", dockerAppsChangeImage)
	r.Handle("POST /apps/{container_id}/update-limits", dockerAppsUpdateLimits)
	r.Handle("GET /apps/gpu-info", dockerAppsGpuInfo)
	r.Handle("GET /apps/{container_id}/ollama/models", dockerAppsOllamaList)
	r.Handle("POST /apps/{container_id}/ollama/pull", dockerAppsOllamaPull)
	r.Handle("POST /apps/{container_id}/ollama/delete", dockerAppsOllamaDelete)
}
