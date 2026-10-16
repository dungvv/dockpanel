package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// ── helpers shared by the web-group route files ─────────────────────────

// nginxDecodeStrict is decodeJSON plus serde's required-field rule: a
// non-Option field that is missing or null is a 422, not a zero value.
func nginxDecodeStrict(w http.ResponseWriter, r *http.Request, v any, required ...string) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		http.Error(w, "Failed to buffer the request body", http.StatusBadRequest)
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if !decodeJSON(w, r, v) {
		return false
	}
	if len(required) == 0 {
		return true
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		http.Error(w, "Failed to deserialize the JSON body into the target type: invalid type, expected a map", http.StatusUnprocessableEntity)
		return false
	}
	for _, f := range required {
		if raw, ok := m[f]; !ok || string(raw) == "null" {
			http.Error(w, fmt.Sprintf("Failed to deserialize the JSON body into the target type: missing field `%s`", f), http.StatusUnprocessableEntity)
			return false
		}
	}
	return true
}

// nginxDecodeValue decodes a body the Rust side took as serde_json::Value.
func nginxDecodeValue(w http.ResponseWriter, r *http.Request) (any, bool) {
	var v any
	return v, decodeJSON(w, r, &v)
}

// nginxField is serde_json's `value.get(key)` (nil for non-objects).
func nginxField(v any, key string) any {
	if m, ok := v.(map[string]any); ok {
		return m[key]
	}
	return nil
}

// nginxFieldStr is `value.get(key).and_then(|v| v.as_str())`.
func nginxFieldStr(v any, key string) (string, bool) {
	s, ok := nginxField(v, key).(string)
	return s, ok
}

// nginxFieldU64 is `as_u64()`: a non-negative integer JSON number.
func nginxFieldU64(v any, key string) (uint64, bool) {
	f, ok := nginxField(v, key).(float64)
	if !ok || f < 0 || f != math.Trunc(f) || f > math.MaxUint64 {
		return 0, false
	}
	return uint64(f), true
}

// nginxFieldI64 is `as_i64()`.
func nginxFieldI64(v any, key string) (int64, bool) {
	f, ok := nginxField(v, key).(float64)
	if !ok || f != math.Trunc(f) || f < math.MinInt64 || f > math.MaxInt64 {
		return 0, false
	}
	return int64(f), true
}

// nginxQueryUint parses an optional unsigned query param like axum's Query
// extractor: a malformed value is a 400.
func nginxQueryUint(w http.ResponseWriter, r *http.Request, key string, bits int) (*uint64, bool) {
	q := r.URL.Query()
	if !q.Has(key) {
		return nil, true
	}
	v, err := strconv.ParseUint(q.Get(key), 10, bits)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to deserialize query string: %s: invalid digit found in string", key), http.StatusBadRequest)
		return nil, false
	}
	return &v, true
}

// nginxQueryStr returns an optional query string param.
func nginxQueryStr(r *http.Request, key string) *string {
	q := r.URL.Query()
	if !q.Has(key) {
		return nil
	}
	v := q.Get(key)
	return &v
}

// nginxPlain answers like axum's `(StatusCode, String)`: a text body.
func nginxPlain(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg)
}

// nginxErrText renders an io error without Go's "op path:" prefix.
func nginxErrText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err.Error()
	}
	return err.Error()
}

func nginxExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func nginxLossy(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

// nginxLines splits like Rust's str::lines.
func nginxLines(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i, p := range parts {
		parts[i] = strings.TrimSuffix(p, "\r")
	}
	return parts
}

// nginxRun runs a command with an optional timeout (0 = none, as in Rust).
func nginxRun(timeout time.Duration, bin string, args ...string) (safecmd.Output, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return safecmd.Exec(ctx, bin, args...)
}

// ── responses ───────────────────────────────────────────────────────────

type nginxResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type nginxTestResponse struct {
	Success bool   `json:"success"`
	Output  string `json:"output"`
}

type nginxSiteStatusResponse struct {
	Domain       string  `json:"domain"`
	ConfigExists bool    `json:"config_exists"`
	SslEnabled   bool    `json:"ssl_enabled"`
	SslCertPath  *string `json:"ssl_cert_path"`
	SslExpiry    *string `json:"ssl_expiry"`
}

func nginxFail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, nginxResponse{Success: false, Message: msg})
}

func nginxOK(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusOK, nginxResponse{Success: true, Message: msg})
}

func nginxJailName(domain string) string { return "nginx-" + strings.ReplaceAll(domain, ".", "-") }

// putSite: PUT /nginx/sites/{domain} — create or update a site's vhost.
func (n nginxRoutes) putSite(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	var cfg services.NginxSiteConfig
	if !nginxDecodeStrict(w, r, &cfg, "runtime") {
		return
	}
	if !isValidDomain(domain) {
		nginxFail(w, http.StatusBadRequest, "Invalid domain format")
		return
	}

	if cfg.Runtime == "node" || cfg.Runtime == "python" {
		if cfg.AppCommand != nil && cfg.ProxyPort != nil {
			if err := services.AppProcessCreateAppService(domain, *cfg.AppCommand, *cfg.ProxyPort, cfg.Runtime); err != nil {
				nginxFail(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create app service: %v", err))
				return
			}
		}
	}

	if cfg.PhpSocket != nil {
		sp := strings.TrimPrefix(*cfg.PhpSocket, "unix:")
		if !strings.HasPrefix(sp, "/run/php/") || strings.Contains(sp, "..") {
			nginxFail(w, http.StatusBadRequest, "PHP socket must be under /run/php/")
			return
		}
	}

	if cfg.Runtime == "php" {
		if cfg.PhpSocket != nil {
			// The panel sends the Debian-shaped path as wire format; the REAL
			// socket on RHEL (/run/php-fpm/www.sock) is resolved here, by the
			// same resolver php.rs uses, so the two routes cannot disagree.
			sp := strings.TrimPrefix(*cfg.PhpSocket, "unix:")
			version := "unknown"
			if rest, ok := strings.CutPrefix(sp, "/run/php/php"); ok {
				if v, ok := strings.CutSuffix(rest, "-fpm.sock"); ok {
					version = v
				}
			}
			real, ok := services.PkgResolvePhpFpmSocket(version)
			if !ok {
				// Settings → Services was a dead end for this; the PHP
				// Version control offers the install itself since v2.49.0.
				nginxFail(w, http.StatusBadRequest, fmt.Sprintf("PHP %s is not installed, or its PHP-FPM service is not "+
					"running. Install it from the PHP Version control on the site — "+
					"it offers any version this server does not have yet.", version))
				return
			}
			s := "unix:" + real
			cfg.PhpSocket = &s
		}

		// Per-site PHP-FPM pool with resource limits.
		var perSiteSocket *string
		if cfg.PhpSocket != nil {
			if rest, ok := strings.CutPrefix(*cfg.PhpSocket, "unix:/run/php/php"); ok {
				if ver, ok := strings.CutSuffix(rest, "-fpm.sock"); ok {
					memory, workers := uint32(256), uint32(5)
					if cfg.PhpMemoryMb != nil {
						memory = *cfg.PhpMemoryMb
					}
					if cfg.PhpMaxWorkers != nil {
						workers = *cfg.PhpMaxWorkers
					}
					var owner *[2]string
					if cfg.PoolUser != nil && cfg.PoolGroup != nil {
						owner = &[2]string{*cfg.PoolUser, *cfg.PoolGroup}
					}
					if err := services.NginxWritePhpPoolConfig(domain, ver, memory, workers, owner); err != nil {
						slog.Warn(fmt.Sprintf("Failed to write PHP pool config for %s: %v", domain, err))
					} else {
						_ = services.NginxReloadPhpFpm(ver)
						// Writing the pool was never enough: the vhost kept the
						// SHARED socket, so the advertised per-site limits did
						// nothing. Switch only once the socket exists — a
						// missing socket would 502 the whole site.
						candidate := fmt.Sprintf("/run/php/php%s-fpm-%s.sock", ver, strings.ReplaceAll(domain, ".", "_"))
						for i := 0; i < 15; i++ {
							if nginxExists(candidate) {
								s := "unix:" + candidate
								perSiteSocket = &s
								break
							}
							time.Sleep(200 * time.Millisecond)
						}
						if perSiteSocket == nil {
							slog.Warn(fmt.Sprintf("Per-site PHP-FPM socket %s did not appear after reload; "+
								"%s stays on the shared pool (per-site PHP limits inactive)", candidate, domain))
						}
					}
				}
			}
		}
		if perSiteSocket != nil {
			slog.Info(fmt.Sprintf("%s now uses its own PHP-FPM pool (%s)", domain, *perSiteSocket))
			cfg.PhpSocket = perSiteSocket
		}
	}

	// The FastCGI cache dir must exist: `nginx -t` mkdir()s it and fails the
	// whole reload if the parent is missing (#54-B).
	if cfg.FastcgiCache != nil && *cfg.FastcgiCache && cfg.Runtime == "php" {
		cacheDir := "/var/cache/nginx/fastcgi/" + strings.ReplaceAll(domain, ".", "_")
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			nginxFail(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create FastCGI cache dir %s: %s. "+
				"Ensure /var/cache/nginx is in the agent's ReadWritePaths.", cacheDir, nginxErrText(err)))
			return
		}
		_, _ = nginxRun(0, "chown", "www-data:www-data", cacheDir)
	}

	rendered, err := services.NginxRenderSiteConfig(n.st.Templates, domain, &cfg)
	if err != nil {
		nginxFail(w, http.StatusInternalServerError, fmt.Sprintf("Template render error: %v", err))
		return
	}

	// Atomic write. `nginx -t` is whole-server, so the failure paths must put
	// back exactly what was here (for four years they deleted instead, and a
	// settings toggle could remove a healthy site's config while some OTHER
	// vhost was broken). A disabled site's write goes to its parked body.
	target := services.NginxVhostTargetFor(domain)
	var previous *string
	if b, err := os.ReadFile(target.Path); err == nil {
		s := string(b)
		previous = &s
	}
	tmp := target.Path + ".tmp"
	err = os.WriteFile(tmp, []byte(rendered), 0o644)
	if err == nil {
		err = os.Rename(tmp, target.Path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		nginxFail(w, http.StatusInternalServerError, "Failed to write config: "+nginxErrText(err))
		return
	}

	if cfg.Root != nil && (!strings.HasPrefix(*cfg.Root, "/var/www/") || strings.Contains(*cfg.Root, "..")) {
		nginxFail(w, http.StatusBadRequest, "Document root must be under /var/www/")
		return
	}
	docRoot := "/var/www/" + domain
	if cfg.Root != nil {
		docRoot = *cfg.Root
	}
	actualRoot := services.NginxDocumentRootFor(docRoot, cfg.Runtime)
	if err := os.MkdirAll(actualRoot, 0o755); err != nil {
		slog.Warn(fmt.Sprintf("Failed to create document root %s: %v", actualRoot, err))
	} else if index := actualRoot + "/index.html"; !nginxExists(index) {
		_ = os.WriteFile(index, []byte(services.NginxPlaceholderPage(domain)), 0o644)
	}

	// A parked body is not in service: nothing to test or reload, and saying
	// "configured and nginx reloaded" would hide that the change is invisible.
	if !target.Live {
		slog.Info(fmt.Sprintf("Site %s is disabled: saved its configuration to %s and left the maintenance response in service", domain, target.Path))
		nginxOK(w, fmt.Sprintf("Site %s is disabled — its configuration was saved and takes effect "+
			"when the site is enabled. Nginx was not reloaded.", domain))
		return
	}

	out, err := services.NginxTestConfig()
	if err != nil {
		// `nginx -t` did not answer: the render is unproven, but neither may
		// the previous config be destroyed by our inability to test.
		restored := services.NginxRestoreOrRemove(target.Path, previous)
		nginxFail(w, http.StatusInternalServerError, fmt.Sprintf("Failed to test config: %v%s", err, services.NginxRestoreNote(restored)))
		return
	}
	if !out.Success {
		restored := services.NginxRestoreOrRemove(target.Path, previous)
		nginxFail(w, http.StatusBadRequest, fmt.Sprintf("Nginx config test failed: %s%s", out.Stderr, services.NginxRestoreNote(restored)))
		return
	}
	if err := services.NginxReload(); err != nil {
		nginxFail(w, http.StatusInternalServerError, fmt.Sprintf("Config valid but reload failed: %v", err))
		return
	}

	// Fail2Ban jail for this site's access log. The jail name collapses '.'
	// to '-' (not injective): writing unconditionally repointed a neighbour's
	// jail at our log, leaving it unprotected while it appeared to exist.
	jail := nginxJailName(domain)
	jailPath := "/etc/fail2ban/jail.d/" + jail + ".conf"
	if nginxExists(jailPath) && services.OwnershipFail2banJail(jailPath, domain) == services.OwnershipTheirs {
		slog.Warn(fmt.Sprintf("Not writing %s for %s: it already watches another "+
			"domain's access log. Jail names collapse '.' to '-', so these two "+
			"domains share one jail file and only the first keeps protection.", jailPath, domain))
	} else {
		jailCfg := fmt.Sprintf("[%s]\nenabled = true\nport = http,https\nfilter = nginx-http-auth\nlogpath = /var/log/nginx/%s.access.log\nmaxretry = 10\nfindtime = 300\nbantime = 3600\n", jail, domain)
		if os.WriteFile(jailPath, []byte(jailCfg), 0o644) == nil {
			_, _ = nginxRun(0, "systemctl", "reload", "fail2ban")
			slog.Info("Auto-configured Fail2Ban jail for " + domain)
		}
	}
	nginxOK(w, fmt.Sprintf("Site %s configured and nginx reloaded", domain))
}

// deleteSite: DELETE /nginx/sites/{domain} — remove a site and its resources.
func (n nginxRoutes) deleteSite(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		nginxFail(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	configPath := fmt.Sprintf("%s/%s.conf", services.NginxSitesDir(), domain)
	if !nginxExists(configPath) {
		nginxFail(w, http.StatusNotFound, "No config found for "+domain)
		return
	}
	if err := os.Remove(configPath); err != nil {
		nginxFail(w, http.StatusInternalServerError, "Failed to remove config: "+nginxErrText(err))
		return
	}
	if err := services.NginxReload(); err != nil {
		nginxFail(w, http.StatusInternalServerError, fmt.Sprintf("Config removed but reload failed: %v", err))
		return
	}

	// Best-effort cleanup; never fails the delete.
	poolName := strings.ReplaceAll(domain, ".", "_")
	cacheDir := "/var/cache/nginx/fastcgi/" + poolName
	if nginxExists(cacheDir) {
		_ = os.RemoveAll(cacheDir)
		slog.Info("Removed FastCGI cache: " + cacheDir)
	}

	// A DNS-01 wildcard lives under the zone apex and every sibling points at
	// it; deleting it here fails the next `nginx -t` box-wide.
	sslDir := "/etc/dockpanel/ssl/" + domain
	if nginxExists(sslDir) {
		if services.OwnershipCertDirInUseElsewhere(domain) {
			slog.Warn(fmt.Sprintf("Leaving %s in place: another vhost still points at it (a wildcard shared across the zone).", sslDir))
		} else if err := os.RemoveAll(sslDir); err != nil {
			slog.Warn(fmt.Sprintf("Failed to remove SSL certs for %s: %v", domain, err))
		} else {
			slog.Info("Removed SSL certs: " + sslDir)
		}
	}

	for _, v := range []string{"8.1", "8.2", "8.3", "8.4", "8.5"} {
		pool := fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", v, poolName)
		if nginxExists(pool) {
			_ = os.Remove(pool)
			slog.Info("Removed PHP pool: " + pool)
		}
	}

	siteDir := "/var/www/" + domain
	if nginxExists(siteDir) {
		if err := os.RemoveAll(siteDir); err != nil {
			slog.Warn(fmt.Sprintf("Failed to remove site files for %s: %v", domain, err))
		} else {
			slog.Info("Removed site files: " + siteDir)
		}
	}
	for _, s := range []string{"access.log", "error.log"} {
		_ = os.Remove(fmt.Sprintf("/var/log/nginx/%s.%s", domain, s))
	}
	if err := services.AppProcessRemoveAppService(domain); err != nil {
		slog.Warn(fmt.Sprintf("Failed to remove app service for %s: %v", domain, err))
	}
	if services.WordpressIsAutoUpdateEnabled(domain) {
		_ = services.WordpressSetAutoUpdate(domain, false)
		slog.Info("Removed WordPress auto-update cron for " + domain)
	}

	// Same non-injective jail name: the file may protect another domain.
	jailPath := "/etc/fail2ban/jail.d/" + nginxJailName(domain) + ".conf"
	if nginxExists(jailPath) {
		if services.OwnershipFail2banJail(jailPath, domain).MayDelete() {
			_ = os.Remove(jailPath)
			_, _ = nginxRun(0, "systemctl", "reload", "fail2ban")
			slog.Info("Removed Fail2Ban jail for " + domain)
		} else {
			slog.Warn(fmt.Sprintf("Leaving %s in place: it does not watch %s's access "+
				"log. Jail names collapse '.' to '-', so this file protects a "+
				"different domain.", jailPath, domain))
		}
	}
	nginxOK(w, fmt.Sprintf("Site %s removed and nginx reloaded", domain))
}

// testNginx: POST /nginx/test.
func (n nginxRoutes) testNginx(w http.ResponseWriter, _ *http.Request) {
	out, err := services.NginxTestConfig()
	if err != nil {
		writeJSON(w, http.StatusOK, nginxTestResponse{Output: fmt.Sprintf("Error: %v", err)})
		return
	}
	o := out.Stderr
	if out.Success {
		o = out.Stdout
	}
	writeJSON(w, http.StatusOK, nginxTestResponse{Success: out.Success, Output: o})
}

// reloadNginx: POST /nginx/reload.
func (n nginxRoutes) reloadNginx(w http.ResponseWriter, _ *http.Request) {
	if err := services.NginxReload(); err != nil {
		nginxFail(w, http.StatusInternalServerError, fmt.Sprintf("Reload failed: %v", err))
		return
	}
	nginxOK(w, "Nginx reloaded")
}

// getSite: GET /nginx/sites/{domain} — site status.
func (n nginxRoutes) getSite(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		nginxFail(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	certPath := fmt.Sprintf("/etc/dockpanel/ssl/%s/fullchain.pem", domain)
	resp := nginxSiteStatusResponse{
		Domain:       domain,
		ConfigExists: nginxExists(fmt.Sprintf("%s/%s.conf", services.NginxSitesDir(), domain)),
		SslEnabled:   nginxExists(certPath),
	}
	if resp.SslEnabled {
		resp.SslCertPath = &certPath
		resp.SslExpiry = services.SslGetCertStatus(domain).NotAfter
	}
	writeJSON(w, http.StatusOK, resp)
}

// nginxCopyDirShallow copies the files directly inside src into dst. Shallow
// on purpose: a certificate directory is a flat set of PEMs.
func nginxCopyDirShallow(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		info, _ := e.Info()
		mode := os.FileMode(0o644)
		if info != nil {
			mode = info.Mode().Perm()
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, mode); err != nil {
			return err
		}
	}
	return nil
}

// nginxDomainBackupTrees are the backup trees keyed by site domain. The
// panel's backups table stores only a filename and rebuilds the path from the
// LIVE domain, so a rename that does not carry these strands every archive.
func nginxDomainBackupTrees(oldDomain, newDomain string) [][2]string {
	root := "/var/backups/dockpanel"
	return [][2]string{
		{root + "/" + oldDomain, root + "/" + newDomain},
		{root + "/wp-snapshots/" + oldDomain, root + "/wp-snapshots/" + newDomain},
	}
}

// nginxDirIsOccupied: only NotFound means free. Any other error answers true,
// rather than moving one tenant's archives onto something unreadable.
func nginxDirIsOccupied(path string) bool {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if err != nil && err != io.EOF {
		return true
	}
	return len(names) > 0
}

// nginxUndoBackupCarry puts carried trees back, newest first. Never silent:
// an archive left under the new name is the exact defect the carry prevents.
func nginxUndoBackupCarry(carried [][2]string, oldDomain string) {
	for i := len(carried) - 1; i >= 0; i-- {
		oldTree, newTree := carried[i][0], carried[i][1]
		if err := os.Rename(newTree, oldTree); err != nil {
			slog.Error(fmt.Sprintf("Rolling back the rename of %s, but %s could not be put back at %s: %s. "+
				"Those archives are on disk under the new name while the panel will look for them under the old one.",
				oldDomain, newTree, oldTree, nginxErrText(err)))
		}
	}
}

// renameSite: POST /nginx/sites/{domain}/rename.
func (n nginxRoutes) renameSite(w http.ResponseWriter, r *http.Request) {
	oldDomain := r.PathValue("domain")
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	if !isValidDomain(oldDomain) {
		nginxFail(w, http.StatusBadRequest, "Invalid old domain format")
		return
	}
	newDomain, _ := nginxFieldStr(body, "new_domain")
	if !isValidDomain(newDomain) {
		nginxFail(w, http.StatusBadRequest, "Invalid new domain format")
		return
	}
	sitesDir := services.NginxSitesDir()
	oldConf := fmt.Sprintf("%s/%s.conf", sitesDir, oldDomain)
	if !nginxExists(oldConf) {
		nginxFail(w, http.StatusNotFound, "No nginx config for "+oldDomain)
		return
	}

	// 0. Refuse before anything moves if a backup tree is occupied at the
	// destination. Every completed site delete manufactures one (a
	// pre-delete archive with no row); merging would put two tenants'
	// archives in one listing, a restore click away.
	backupTrees := nginxDomainBackupTrees(oldDomain, newDomain)
	for _, t := range backupTrees {
		if nginxExists(t[0]) && nginxDirIsOccupied(t[1]) {
			nginxFail(w, http.StatusConflict, fmt.Sprintf("%s already holds files. %s has backups that must move "+
				"there, and merging them would put two sites' archives in one listing. "+
				"Move or delete that directory, then rename again.", t[1], oldDomain))
			return
		}
	}

	// 1. Site directory.
	oldDir, newDir := "/var/www/"+oldDomain, "/var/www/"+newDomain
	if nginxExists(oldDir) {
		if err := os.Rename(oldDir, newDir); err != nil {
			nginxFail(w, http.StatusInternalServerError, "Failed to rename site directory: "+nginxErrText(err))
			return
		}
		slog.Info(fmt.Sprintf("Renamed site dir: %s → %s", oldDir, newDir))
	}

	// 2-3. New vhost. Snapshot the destination first: the claim guard never
	// looks at the filesystem, so an operator's hand-written vhost there was
	// silently overwritten and then bare-deleted on rollback.
	cb, _ := os.ReadFile(oldConf)
	configContent := string(cb)
	newContent := strings.ReplaceAll(configContent, oldDomain, newDomain)
	newConf := fmt.Sprintf("%s/%s.conf", sitesDir, newDomain)
	var displaced *string
	if b, err := os.ReadFile(newConf); err == nil {
		s := string(b)
		displaced = &s
		slog.Warn(fmt.Sprintf("Renaming %s onto %s is replacing an existing vhost "+
			"at %s (%d bytes) that no site, git deploy or Docker app claims.", oldDomain, newDomain, newConf, len(b)))
	}
	if err := os.WriteFile(newConf, []byte(newContent), 0o644); err != nil {
		if nginxExists(newDir) {
			_ = os.Rename(newDir, oldDir)
		}
		nginxFail(w, http.StatusInternalServerError, "Failed to write new config: "+nginxErrText(err))
		return
	}
	// 4. Old vhost.
	_ = os.Remove(oldConf)

	// 4b. A disabled site's real body is parked under the OLD name, where
	// enabling would never look — carry it across.
	_, oldParked := services.NginxVhostPaths(oldDomain)
	_, newParked := services.NginxVhostPaths(newDomain)
	if nginxExists(oldParked) {
		if b, err := os.ReadFile(oldParked); err != nil {
			slog.Warn(fmt.Sprintf("Could not read the parked configuration for disabled site %s: %v", oldDomain, err))
		} else if os.WriteFile(newParked, []byte(strings.ReplaceAll(string(b), oldDomain, newDomain)), 0o644) == nil {
			_ = os.Remove(oldParked)
			slog.Info(fmt.Sprintf("Carried the parked configuration for disabled site %s over to %s", oldDomain, newDomain))
		} else {
			slog.Warn(fmt.Sprintf("Could not carry the parked configuration for disabled site %s "+
				"over to %s — it can still be enabled under its old name", oldDomain, newParked))
		}
	}

	// 5. Certificates. A shared wildcard is COPIED, not moved: moving breaks
	// every sibling; leaving it breaks the renamed vhost we just rewrote.
	oldSSL, newSSL := "/etc/dockpanel/ssl/"+oldDomain, "/etc/dockpanel/ssl/"+newDomain
	if nginxExists(oldSSL) {
		if services.OwnershipCertDirInUseElsewhere(oldDomain) {
			slog.Warn(fmt.Sprintf("%s is referenced by another vhost — copying it to %s instead of "+
				"moving it, so the sites still pointing at it keep working. The copy is a "+
				"snapshot: reissue a certificate for %s before the original expires.", oldSSL, newSSL, newDomain))
			if err := nginxCopyDirShallow(oldSSL, newSSL); err != nil {
				slog.Warn(fmt.Sprintf("Could not copy %s to %s: %v", oldSSL, newSSL, err))
			}
		} else {
			_ = os.Rename(oldSSL, newSSL)
		}
	}

	// 6. Logs.
	for _, s := range []string{"access.log", "error.log"} {
		ol, nl := fmt.Sprintf("/var/log/nginx/%s.%s", oldDomain, s), fmt.Sprintf("/var/log/nginx/%s.%s", newDomain, s)
		if nginxExists(ol) {
			_ = os.Rename(ol, nl)
		}
	}

	// 7. PHP-FPM pools.
	oldPool, newPool := strings.ReplaceAll(oldDomain, ".", "_"), strings.ReplaceAll(newDomain, ".", "_")
	for _, v := range []string{"8.1", "8.2", "8.3", "8.4", "8.5"} {
		op, np := fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", v, oldPool), fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", v, newPool)
		if b, err := os.ReadFile(op); err == nil {
			_ = os.WriteFile(np, []byte(strings.ReplaceAll(string(b), oldDomain, newDomain)), 0o644)
			_ = os.Remove(op)
		}
	}

	// 8. Fail2Ban jail: both halves of the non-injective name — the old file
	// may be another domain's jail, the destination a third domain's.
	oldJail, newJail := nginxJailName(oldDomain), nginxJailName(newDomain)
	oldJailPath, newJailPath := "/etc/fail2ban/jail.d/"+oldJail+".conf", "/etc/fail2ban/jail.d/"+newJail+".conf"
	jailIsOurs := services.OwnershipFail2banJail(oldJailPath, oldDomain).MayDelete()
	destFree := !nginxExists(newJailPath) || services.OwnershipFail2banJail(newJailPath, newDomain).MayDelete()
	if nginxExists(oldJailPath) && !(jailIsOurs && destFree) {
		slog.Warn(fmt.Sprintf("Not migrating %s: ours=%t, destination_free=%t. The jail name collapses '.' to '-', "+
			"so one of these files protects a different domain.", oldJailPath, jailIsOurs, destFree))
	} else if b, err := os.ReadFile(oldJailPath); err == nil {
		updated := strings.ReplaceAll(strings.ReplaceAll(string(b), oldJail, newJail), oldDomain, newDomain)
		_ = os.WriteFile(newJailPath, []byte(updated), 0o644)
		_ = os.Remove(oldJailPath)
		_, _ = nginxRun(0, "systemctl", "reload", "fail2ban")
	}

	// 9. Redirect/auth/htpasswd configs.
	for _, dir := range []string{"/etc/nginx/redirects", "/etc/nginx/auth", "/etc/nginx/htpasswd"} {
		of, nf := fmt.Sprintf("%s/%s.conf", dir, oldDomain), fmt.Sprintf("%s/%s.conf", dir, newDomain)
		if nginxExists(of) {
			_ = os.Rename(of, nf)
		}
		op, np := dir+"/"+oldDomain, dir+"/"+newDomain
		if nginxExists(op) && !strings.HasSuffix(op, ".conf") {
			_ = os.Rename(op, np)
		}
	}

	rollback := func() { _ = os.WriteFile(oldConf, []byte(configContent), 0o644) }

	// 9c. Backup trees, last: the heaviest move and the only one whose
	// failure aborts the rename. Every result is matched — a swallowed
	// ENOTEMPTY is the "reports success while leaking" defect.
	var carried [][2]string
	filesRenamed := 0
	for _, t := range backupTrees {
		oldTree, newTree := t[0], t[1]
		if !nginxExists(oldTree) {
			continue
		}
		_ = os.MkdirAll(filepath.Dir(newTree), 0o755)
		if err := os.Rename(oldTree, newTree); err != nil {
			nginxUndoBackupCarry(carried, oldDomain)
			rollback()
			services.NginxRestoreOrRemove(newConf, displaced)
			if nginxExists(newDir) {
				_ = os.Rename(newDir, oldDir)
			}
			// A destination that filled up is the operator's to clear.
			status := http.StatusInternalServerError
			if errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, fs.ErrExist) {
				status = http.StatusConflict
			}
			nginxFail(w, status, fmt.Sprintf("Could not move %s to %s: %s. The rename was rolled "+
				"back and %s is unchanged.", oldTree, newTree, nginxErrText(err), oldDomain))
			return
		}
		carried = append(carried, t)
		slog.Info(fmt.Sprintf("Carried backups for %s: %s to %s", oldDomain, oldTree, newTree))
	}

	// Archive names carry the domain prefix, and off-site retention selects
	// what it may delete by it — so rename them too.
	if len(carried) > 0 {
		moved := "/var/backups/dockpanel/" + newDomain
		oldPrefix, newPrefix := oldDomain+"-", newDomain+"-"
		if entries, err := os.ReadDir(moved); err == nil {
			for _, e := range entries {
				rest, ok := strings.CutPrefix(e.Name(), oldPrefix)
				if !ok {
					continue
				}
				renamed := newPrefix + rest
				if err := os.Rename(filepath.Join(moved, e.Name()), filepath.Join(moved, renamed)); err != nil {
					slog.Warn(fmt.Sprintf("Could not rename archive %s to %s: %v", e.Name(), renamed, err))
				} else {
					filesRenamed++
				}
			}
		}
		// A moved tree keeps its old modes; the repair otherwise runs only at start.
		services.BackupsSecureBackupTree()
		slog.Info(fmt.Sprintf("Backup carry for %s to %s: %d trees, %d archives renamed", oldDomain, newDomain, len(carried), filesRenamed))
	}

	// 10. Test and reload.
	out, err := services.NginxTestConfig()
	if err == nil && out.Success {
		if err := services.NginxReload(); err != nil {
			nginxFail(w, http.StatusInternalServerError, fmt.Sprintf("Config valid but reload failed: %v", err))
			return
		}
		slog.Info(fmt.Sprintf("Domain renamed: %s → %s", oldDomain, newDomain))
		nginxOK(w, fmt.Sprintf("Domain renamed from %s to %s", oldDomain, newDomain))
		return
	}
	rollback()
	nginxUndoBackupCarry(carried, oldDomain)
	restored := services.NginxRestoreOrRemove(newConf, displaced)
	if nginxExists(newDir) {
		_ = os.Rename(newDir, oldDir)
	}
	if err != nil {
		nginxFail(w, http.StatusInternalServerError, fmt.Sprintf("Failed to test config: %v", err))
		return
	}
	nginxFail(w, http.StatusBadRequest, fmt.Sprintf("Nginx config test failed after rename: %s%s", out.Stderr, services.NginxRestoreNote(restored)))
}

// ── Redirect rules ──────────────────────────────────────────────────────

type nginxRedirectRequest struct {
	Domain       string `json:"domain"`
	Source       string `json:"source"`
	Target       string `json:"target"`
	RedirectType string `json:"redirect_type"`
}

// nginxInsertInclude adds `include <file>;` before the last '}' of the site
// config if not already present.
func nginxInsertInclude(siteConf, includePath string) {
	b, _ := os.ReadFile(siteConf)
	content := string(b)
	if strings.Contains(content, "include "+includePath) {
		return
	}
	if pos := strings.LastIndexByte(content, '}'); pos >= 0 {
		_ = os.WriteFile(siteConf, []byte(content[:pos]+"    include "+includePath+";\n"+content[pos:]), 0o644)
	}
}

// addRedirect: POST /nginx/redirects/add.
func (n nginxRoutes) addRedirect(w http.ResponseWriter, r *http.Request) {
	var b nginxRedirectRequest
	if !nginxDecodeStrict(w, r, &b, "domain", "source", "target", "redirect_type") {
		return
	}
	switch {
	case b.Domain == "" || b.Source == "" || b.Target == "":
		writeErr(w, http.StatusBadRequest, "Missing fields")
		return
	case !isValidDomain(b.Domain):
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	case b.RedirectType != "301" && b.RedirectType != "302":
		writeErr(w, http.StatusBadRequest, "Type must be 301 or 302")
		return
	case !strings.HasPrefix(b.Source, "/"):
		writeErr(w, http.StatusBadRequest, "Source must start with /")
		return
	case strings.ContainsFunc(b.Source, func(c rune) bool { return nginxIsSpace(c) || strings.ContainsRune(";{}\n\r", c) }):
		writeErr(w, http.StatusBadRequest, "Invalid source path characters")
		return
	case strings.ContainsAny(b.Target, "\n\r;{}"):
		writeErr(w, http.StatusBadRequest, "Invalid target URL characters")
		return
	}
	file := fmt.Sprintf("/etc/nginx/redirects/%s.conf", b.Domain)
	_ = os.MkdirAll("/etc/nginx/redirects", 0o755)
	rule := fmt.Sprintf("location = %s { return %s %s; }\n", b.Source, b.RedirectType, b.Target)
	eb, _ := os.ReadFile(file)
	existing := string(eb)
	if err := os.WriteFile(file, []byte(existing+rule), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, nginxErrText(err))
		return
	}
	nginxInsertInclude(fmt.Sprintf("%s/%s.conf", services.NginxSitesDir(), b.Domain), file)

	if out, err := services.NginxTestConfig(); err == nil && out.Success {
		if err := services.NginxReload(); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config saved but nginx reload failed: %v", err))
			return
		}
	} else {
		_ = os.WriteFile(file, []byte(existing), 0o644)
		writeErr(w, http.StatusBadRequest, "Nginx config test failed — redirect reverted")
		return
	}
	slog.Info(fmt.Sprintf("Redirect added: %s → %s (%s)", b.Source, b.Target, b.RedirectType))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// nginxIsSpace is Rust's char::is_whitespace for the ASCII range plus the
// Unicode spaces strings.TrimSpace knows.
func nginxIsSpace(c rune) bool { return strings.TrimSpace(string(c)) == "" }

// listRedirects: GET /nginx/redirects/{domain}.
func (n nginxRoutes) listRedirects(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	b, _ := os.ReadFile(fmt.Sprintf("/etc/nginx/redirects/%s.conf", domain))
	rules := []map[string]any{}
	for _, l := range nginxLines(string(b)) {
		if !strings.Contains(l, "return ") {
			continue
		}
		_, afterLoc, ok := strings.Cut(l, "location = ")
		if !ok {
			continue
		}
		source, _, _ := strings.Cut(afterLoc, " ")
		_, afterRet, _ := strings.Cut(l, "return ")
		parts := strings.Fields(afterRet)
		if len(parts) < 2 {
			continue
		}
		rules = append(rules, map[string]any{"source": source, "target": strings.TrimRight(parts[1], ";"), "type": parts[0]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"redirects": rules})
}

// removeRedirect: POST /nginx/redirects/{domain}/remove.
func (n nginxRoutes) removeRedirect(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	source, _ := nginxFieldStr(body, "source")
	if source == "" {
		writeErr(w, http.StatusBadRequest, "Source required")
		return
	}
	file := fmt.Sprintf("/etc/nginx/redirects/%s.conf", domain)
	b, _ := os.ReadFile(file)
	var kept []string
	for _, l := range nginxLines(string(b)) {
		if !strings.Contains(l, "location = "+source+" ") {
			kept = append(kept, l)
		}
	}
	_ = os.WriteFile(file, []byte(strings.Join(kept, "\n")+"\n"), 0o644)
	if out, err := services.NginxTestConfig(); err == nil && out.Success {
		if err := services.NginxReload(); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config saved but nginx reload failed: %v", err))
			return
		}
	}
	slog.Info(fmt.Sprintf("Redirect removed: %s from %s", source, domain))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ── Password protection (htpasswd) ──────────────────────────────────────

type nginxPasswordProtectRequest struct {
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// passwordProtect: POST /nginx/password-protect.
func (n nginxRoutes) passwordProtect(w http.ResponseWriter, r *http.Request) {
	var b nginxPasswordProtectRequest
	if !nginxDecodeStrict(w, r, &b, "domain", "path", "username", "password") {
		return
	}
	if b.Domain == "" || b.Username == "" || b.Password == "" {
		writeErr(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if !isValidDomain(b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	htDir := "/etc/nginx/htpasswd"
	_ = os.MkdirAll(htDir, 0o755)
	htFile := htDir + "/" + b.Domain

	out, err := nginxRun(0, "openssl", "passwd", "-apr1", b.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	hash := strings.TrimSpace(nginxLossy(out.Stdout))
	if hash == "" {
		writeErr(w, http.StatusInternalServerError, "Failed to generate password hash")
		return
	}
	entry := b.Username + ":" + hash
	eb, _ := os.ReadFile(htFile)
	var lines []string
	for _, l := range nginxLines(string(eb)) {
		if l != "" && !strings.HasPrefix(l, b.Username+":") {
			lines = append(lines, l)
		}
	}
	lines = append(lines, entry)
	if err := os.WriteFile(htFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, nginxErrText(err))
		return
	}

	authDir := "/etc/nginx/auth"
	_ = os.MkdirAll(authDir, 0o755)
	authFile := fmt.Sprintf("%s/%s.conf", authDir, b.Domain)
	path := b.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsFunc(path, func(c rune) bool { return nginxIsSpace(c) || strings.ContainsRune(";{}\n\r", c) }) {
		writeErr(w, http.StatusBadRequest, "Invalid path format")
		return
	}
	block := fmt.Sprintf("location %s {\n    auth_basic \"Restricted\";\n    auth_basic_user_file %s;\n    try_files $uri $uri/ =404;\n}\n", path, htFile)
	ab, _ := os.ReadFile(authFile)
	if !strings.Contains(string(ab), "location "+path+" ") {
		_ = os.WriteFile(authFile, append(ab, block...), 0o644)
	}
	nginxInsertInclude(fmt.Sprintf("%s/%s.conf", services.NginxSitesDir(), b.Domain), authFile)

	if out, err := services.NginxTestConfig(); err == nil && out.Success {
		if err := services.NginxReload(); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config saved but nginx reload failed: %v", err))
			return
		}
	} else {
		writeErr(w, http.StatusBadRequest, "Nginx config test failed")
		return
	}
	slog.Info(fmt.Sprintf("Password protection enabled on %s path %s for user %s", b.Domain, path, b.Username))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// listProtected: GET /nginx/password-protect/{domain}.
func (n nginxRoutes) listProtected(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	ab, _ := os.ReadFile(fmt.Sprintf("/etc/nginx/auth/%s.conf", domain))
	ub, _ := os.ReadFile("/etc/nginx/htpasswd/" + domain)
	paths, users := []string{}, []string{}
	for _, l := range nginxLines(string(ab)) {
		if _, rest, ok := strings.Cut(l, "location "); ok {
			p, _, _ := strings.Cut(rest, " ")
			paths = append(paths, p)
		}
	}
	for _, l := range nginxLines(string(ub)) {
		if l != "" {
			u, _, _ := strings.Cut(l, ":")
			users = append(users, u)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"paths": paths, "users": users})
}

// removeProtection: POST /nginx/password-protect/{domain}/remove.
func (n nginxRoutes) removeProtection(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	path, ok := nginxFieldStr(body, "path")
	if !ok {
		path = "/"
	}
	authFile := fmt.Sprintf("/etc/nginx/auth/%s.conf", domain)
	ab, _ := os.ReadFile(authFile)
	var cleaned strings.Builder
	skip, braces := false, 0
	for _, l := range nginxLines(string(ab)) {
		if strings.Contains(l, "location "+path+" ") {
			skip, braces = true, 0
		}
		if skip {
			braces += strings.Count(l, "{") - strings.Count(l, "}")
			if braces <= 0 && strings.Contains(l, "}") {
				skip = false
			}
			continue
		}
		cleaned.WriteString(l + "\n")
	}
	_ = os.WriteFile(authFile, []byte(cleaned.String()), 0o644)
	if out, err := services.NginxTestConfig(); err == nil && out.Success {
		if err := services.NginxReload(); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config saved but nginx reload failed: %v", err))
			return
		}
	}
	slog.Info(fmt.Sprintf("Password protection removed from %s path %s", domain, path))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ── Domain aliases ──────────────────────────────────────────────────────

type nginxAliasRequest struct {
	Domain string `json:"domain"`
	Alias  string `json:"alias"`
}

// addAlias: POST /nginx/aliases/add.
func (n nginxRoutes) addAlias(w http.ResponseWriter, r *http.Request) {
	var b nginxAliasRequest
	if !nginxDecodeStrict(w, r, &b, "domain", "alias") {
		return
	}
	switch {
	case b.Domain == "" || b.Alias == "":
		writeErr(w, http.StatusBadRequest, "Missing fields")
		return
	case !isValidDomain(b.Domain):
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	case !isValidDomain(b.Alias):
		writeErr(w, http.StatusBadRequest, "Invalid alias domain format")
		return
	}
	siteConf := fmt.Sprintf("%s/%s.conf", services.NginxSitesDir(), b.Domain)
	cb, err := os.ReadFile(siteConf)
	if err != nil {
		writeErr(w, http.StatusNotFound, "Site config not found")
		return
	}
	content := string(cb)
	newContent := strings.ReplaceAll(content, "server_name "+b.Domain+";", "server_name "+b.Domain+" "+b.Alias+";")
	if newContent == content {
		writeErr(w, http.StatusInternalServerError, "Could not find server_name directive")
		return
	}
	tmp := siteConf + ".tmp"
	if err := os.WriteFile(tmp, []byte(newContent), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, nginxErrText(err))
		return
	}
	if err := os.Rename(tmp, siteConf); err != nil {
		_ = os.Remove(tmp)
		writeErr(w, http.StatusInternalServerError, nginxErrText(err))
		return
	}
	if out, err := services.NginxTestConfig(); err == nil && out.Success {
		if err := services.NginxReload(); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config saved but nginx reload failed: %v", err))
			return
		}
	} else {
		_ = os.WriteFile(siteConf, cb, 0o644)
		if err := services.NginxReload(); err != nil {
			slog.Warn(fmt.Sprintf("Nginx reload failed during alias rollback for %s: %v", b.Domain, err))
		}
		writeErr(w, http.StatusBadRequest, "Nginx test failed — alias reverted")
		return
	}
	slog.Info(fmt.Sprintf("Domain alias added: %s → %s", b.Alias, b.Domain))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// listAliases: GET /nginx/aliases/{domain}.
func (n nginxRoutes) listAliases(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	cb, _ := os.ReadFile(fmt.Sprintf("%s/%s.conf", services.NginxSitesDir(), domain))
	aliases := []string{}
	for _, l := range nginxLines(string(cb)) {
		t := strings.TrimSpace(l)
		rest, ok := strings.CutPrefix(t, "server_name ")
		if !ok {
			continue
		}
		for _, name := range strings.Fields(strings.TrimRight(rest, ";")) {
			if name != domain {
				aliases = append(aliases, name)
			}
		}
	}
	sort.Strings(aliases)
	dedup := aliases[:0]
	for i, a := range aliases {
		if i == 0 || a != aliases[i-1] {
			dedup = append(dedup, a)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"aliases": dedup})
}

// removeAlias: POST /nginx/aliases/{domain}/remove.
func (n nginxRoutes) removeAlias(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	alias, _ := nginxFieldStr(body, "alias")
	if alias == "" {
		writeErr(w, http.StatusBadRequest, "Alias required")
		return
	}
	siteConf := fmt.Sprintf("%s/%s.conf", services.NginxSitesDir(), domain)
	cb, err := os.ReadFile(siteConf)
	if err != nil {
		writeErr(w, http.StatusNotFound, "Site config not found")
		return
	}
	newContent := strings.ReplaceAll(strings.ReplaceAll(string(cb), " "+alias, ""), alias+" ", "")
	_ = os.WriteFile(siteConf, []byte(newContent), 0o644)
	if out, err := services.NginxTestConfig(); err == nil && out.Success {
		if err := services.NginxReload(); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Config saved but nginx reload failed: %v", err))
			return
		}
	} else {
		_ = os.WriteFile(siteConf, cb, 0o644)
		if err := services.NginxReload(); err != nil {
			slog.Warn(fmt.Sprintf("Nginx reload failed during alias removal rollback for %s: %v", domain, err))
		}
	}
	slog.Info(fmt.Sprintf("Domain alias removed: %s from %s", alias, domain))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ── Site logs & stats ───────────────────────────────────────────────────

// siteLogs: GET /nginx/site-logs/{domain}?lines=&log_type=.
func (n nginxRoutes) siteLogs(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	lp, ok := nginxQueryUint(w, r, "lines", 64)
	if !ok {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	lines := uint64(200)
	if lp != nil {
		lines = *lp
	}
	lines = min(lines, 1000)
	logFile := fmt.Sprintf("/var/log/nginx/%s.access.log", domain)
	if lt := nginxQueryStr(r, "log_type"); lt != nil && *lt == "error" {
		logFile = fmt.Sprintf("/var/log/nginx/%s.error.log", domain)
	}
	if !nginxExists(logFile) {
		writeJSON(w, http.StatusOK, map[string]any{"logs": "", "lines": 0, "file": logFile})
		return
	}
	out, err := nginxRun(0, "tail", "-n", strconv.FormatUint(lines, 10), logFile)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	content := nginxLossy(out.Stdout)
	writeJSON(w, http.StatusOK, map[string]any{"logs": content, "lines": len(nginxLines(content)), "file": logFile})
}

// lastActivity: GET /nginx/last-activity/{domain} — the access log's mtime as
// seconds ago (constant time, however large the log). null = no log =
// "unknown", never "idle": a silent zero would let the auto-sleep timer stop
// a container it knows nothing about.
func (n nginxRoutes) lastActivity(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	logFile := fmt.Sprintf("/var/log/nginx/%s.access.log", domain)
	var secondsAgo any
	if fi, err := os.Stat(logFile); err == nil {
		if d := time.Since(fi.ModTime()); d >= 0 {
			secondsAgo = uint64(d / time.Second)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "seconds_ago": secondsAgo, "log_file": logFile})
}

// siteStats: GET /nginx/site-stats/{domain} — basic stats from the access log.
func (n nginxRoutes) siteStats(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	logFile := fmt.Sprintf("/var/log/nginx/%s.access.log", domain)
	if !nginxExists(logFile) {
		writeJSON(w, http.StatusOK, map[string]any{"requests": 0, "bandwidth": 0, "unique_ips": 0, "top_pages": []any{}, "status_codes": map[string]any{}})
		return
	}
	out, err := nginxRun(0, "tail", "-n", "10000", logFile)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	requests, bandwidth := uint32(0), uint64(0)
	ips := map[string]bool{}
	pages := map[string]uint32{}
	codes := map[string]uint32{}
	for _, line := range nginxLines(nginxLossy(out.Stdout)) {
		if line == "" {
			continue
		}
		requests++
		ip, _, _ := strings.Cut(line, " ")
		ips[ip] = true
		// combined format: IP - - [date] "METHOD /path HTTP/x" STATUS SIZE "ref" "ua"
		if parts := strings.Split(line, "\" "); len(parts) > 1 {
			fields := strings.Fields(parts[1])
			if len(fields) > 0 {
				codes[fields[0]]++
			}
			if len(fields) > 1 {
				if s, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					bandwidth += s
				}
			}
		}
		if parts := strings.Split(line, "\""); len(parts) > 1 {
			if req := strings.Fields(parts[1]); len(req) > 1 {
				p, _, _ := strings.Cut(req[1], "?")
				if p != "/favicon.ico" && !strings.HasPrefix(p, "/api/") {
					pages[p]++
				}
			}
		}
	}
	type pc struct {
		path  string
		count uint32
	}
	var top []pc
	for p, c := range pages {
		top = append(top, pc{p, c})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].count != top[j].count {
			return top[i].count > top[j].count
		}
		return top[i].path < top[j].path
	})
	topJSON := []map[string]any{}
	for i, t := range top {
		if i == 10 {
			break
		}
		topJSON = append(topJSON, map[string]any{"path": t.path, "count": t.count})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"requests":     requests,
		"bandwidth":    bandwidth,
		"bandwidth_mb": math.Round(float64(bandwidth)/1024/1024*10) / 10,
		"unique_ips":   len(ips),
		"top_pages":    topJSON,
		"status_codes": codes,
	})
}

// nginxParseLogLineSize extracts the response-size field of a combined-format line.
func nginxParseLogLineSize(line string) (uint64, bool) {
	parts := strings.Split(line, "\" ")
	if len(parts) < 2 {
		return 0, false
	}
	f := strings.Fields(parts[1])
	if len(f) < 2 {
		return 0, false
	}
	v, err := strconv.ParseUint(f[1], 10, 64)
	return v, err == nil
}

// nginxReadAndAdvance sums the size field of every COMPLETE line from byte
// offset `from`, returning (sum, new offset). The offset stops at the last
// '\n' actually read: nginx may be mid-write on the final line, and parsing a
// truncated size field would corrupt the total, then skip the line forever.
func nginxReadAndAdvance(path string, from uint64) (uint64, uint64) {
	out, err := nginxRun(0, "tail", "-c", fmt.Sprintf("+%d", from+1), path)
	if err != nil {
		return 0, from
	}
	last := bytes.LastIndexByte(out.Stdout, '\n')
	if last < 0 {
		return 0, from
	}
	complete := out.Stdout[:last+1]
	var sum uint64
	for _, l := range nginxLines(nginxLossy(complete)) {
		if l == "" {
			continue
		}
		if v, ok := nginxParseLogLineSize(l); ok {
			sum += v
		}
	}
	return sum, from + uint64(len(complete))
}

func nginxInode(path string) (uint64, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Ino), true
}

// siteTrafficDelta: GET /nginx/site-traffic-delta/{domain}?last_inode=&last_size=
// — bytes since the caller's checkpoint, crossing at most ONE rotation (the
// `.1` file, kept plain by delaycompress). Stateless: the backend owns the
// checkpoint. An inode matching neither file means an unknown number of
// rotations, and that tail is dropped rather than guessed from .gz history.
func (n nginxRoutes) siteTrafficDelta(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	lastInode, ok := nginxQueryUint(w, r, "last_inode", 64)
	if !ok {
		return
	}
	lastSize, ok := nginxQueryUint(w, r, "last_size", 64)
	if !ok {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	logFile := fmt.Sprintf("/var/log/nginx/%s.access.log", domain)
	cur, ok := nginxInode(logFile)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"inode": 0, "size": 0, "delta_bytes": 0, "rotated": false})
		return
	}
	var delta, offset uint64
	rotated := false
	switch {
	case lastInode == nil || lastSize == nil:
		// First poll ever: nothing to diff against.
		delta, offset = nginxReadAndAdvance(logFile, 0)
	case *lastInode == cur:
		delta, offset = nginxReadAndAdvance(logFile, *lastSize)
	default:
		var carried uint64
		rotatedFile := logFile + ".1"
		if ino, ok := nginxInode(rotatedFile); ok && ino == *lastInode {
			carried, _ = nginxReadAndAdvance(rotatedFile, *lastSize)
		}
		d2, off2 := nginxReadAndAdvance(logFile, 0)
		delta, offset, rotated = carried+d2, off2, true
	}
	writeJSON(w, http.StatusOK, map[string]any{"inode": cur, "size": offset, "delta_bytes": delta, "rotated": rotated})
}

// phpErrors: GET /nginx/php-errors/{domain} — PHP-FPM error log for a site.
// (Rust validates no domain here; ported as is — the paths are fixed names.)
func (n nginxRoutes) phpErrors(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	lp, ok := nginxQueryUint(w, r, "lines", 64)
	if !ok {
		return
	}
	lines := uint64(100)
	if lp != nil {
		lines = *lp
	}
	lines = min(lines, 500)
	pool := strings.ReplaceAll(domain, ".", "_")
	content, found := "", ""
	for _, c := range []string{
		fmt.Sprintf("/var/log/php-fpm/%s.error.log", pool),
		fmt.Sprintf("/var/log/php-fpm/%s.error.log", domain),
		fmt.Sprintf("/var/www/%s/storage/logs/laravel.log", domain),
		"/var/log/php8.3-fpm.log",
		"/var/log/php8.2-fpm.log",
	} {
		if !nginxExists(c) {
			continue
		}
		if out, err := nginxRun(0, "tail", "-n", strconv.FormatUint(lines, 10), c); err == nil {
			if text := nginxLossy(out.Stdout); strings.TrimSpace(text) != "" {
				content, found = text, c
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": content, "file": found, "lines": len(nginxLines(content))})
}

// ── Site cloning ────────────────────────────────────────────────────────

type nginxCloneRequest struct {
	SourceDomain string `json:"source_domain"`
	TargetDomain string `json:"target_domain"`
}

// cloneSite: POST /nginx/clone-site. The copy itself lives in
// services.StagingCloneFiles (also behind POST /staging/clone); the 300s cap
// stays here as the request-level guard.
func (n nginxRoutes) cloneSite(w http.ResponseWriter, r *http.Request) {
	var b nginxCloneRequest
	if !nginxDecodeStrict(w, r, &b, "source_domain", "target_domain") {
		return
	}
	if b.SourceDomain == "" || b.TargetDomain == "" {
		writeErr(w, http.StatusBadRequest, "Source and target domains required")
		return
	}
	if !isValidDomain(b.SourceDomain) || !isValidDomain(b.TargetDomain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()
	if _, err := services.StagingCloneFiles(ctx, b.SourceDomain, b.TargetDomain); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			writeErr(w, http.StatusGatewayTimeout, "Clone timed out (300s)")
			return
		}
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "directory not found") {
			status = http.StatusNotFound
		}
		writeErr(w, status, err.Error())
		return
	}
	targetDir := "/var/www/" + b.TargetDomain
	var size uint64
	if out, err := nginxRun(0, "du", "-sb", targetDir); err == nil {
		if f := strings.Fields(nginxLossy(out.Stdout)); len(f) > 0 {
			size, _ = strconv.ParseUint(f[0], 10, 64)
		}
	}
	slog.Info(fmt.Sprintf("Site cloned: %s → %s (%d bytes)", b.SourceDomain, b.TargetDomain, size))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "size": size})
}

// ── Environment variables ───────────────────────────────────────────────

// getEnv: GET /nginx/env/{domain}.
func (n nginxRoutes) getEnv(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	b, _ := os.ReadFile(fmt.Sprintf("/var/www/%s/.env", domain))
	content := string(b)
	vars := []map[string]any{}
	for _, l := range nginxLines(content) {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.Trim(strings.TrimSpace(v), `"`), "'")
		vars = append(vars, map[string]any{"key": strings.TrimSpace(k), "value": v})
	}
	writeJSON(w, http.StatusOK, map[string]any{"vars": vars, "raw": content})
}

// setEnv: PUT /nginx/env/{domain}.
func (n nginxRoutes) setEnv(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	var content string
	if vars, ok := nginxField(body, "vars").([]any); ok {
		var lines []string
		for _, v := range vars {
			key, ok1 := nginxFieldStr(v, "key")
			val, ok2 := nginxFieldStr(v, "value")
			if !ok1 || !ok2 || key == "" {
				continue
			}
			if strings.ContainsAny(val, ` "`) {
				lines = append(lines, fmt.Sprintf(`%s="%s"`, key, val))
			} else {
				lines = append(lines, key+"="+val)
			}
		}
		content = strings.Join(lines, "\n") + "\n"
	} else {
		content, _ = nginxFieldStr(body, "raw")
	}
	envPath := fmt.Sprintf("/var/www/%s/.env", domain)
	if err := os.WriteFile(envPath, []byte(content), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, nginxErrText(err))
		return
	}
	_, _ = nginxRun(0, "chown", "www-data:www-data", envPath)
	// Restart the app only if the unit at that (non-injective) name is ours.
	if svc, ok := services.AppProcessOwnedServiceName(domain); ok {
		_, _ = nginxRun(0, "systemctl", "restart", svc)
	}
	slog.Info("Environment variables updated for " + domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// disableSite: POST /nginx/sites/{domain}/disable — park the vhost, serve 503.
func (n nginxRoutes) disableSite(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		nginxPlain(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	confPath, backupPath := services.NginxVhostPaths(domain)
	if !nginxExists(confPath) {
		nginxPlain(w, http.StatusNotFound, "No config for "+domain)
		return
	}
	live, err := os.ReadFile(confPath)
	if err != nil {
		nginxPlain(w, http.StatusInternalServerError, "Read config: "+nginxErrText(err))
		return
	}
	if err := os.WriteFile(backupPath, live, 0o644); err != nil {
		nginxPlain(w, http.StatusInternalServerError, "Backup config: "+nginxErrText(err))
		return
	}
	// The maintenance response must answer where the SITE answered — a stub
	// naming `listen 80` did nothing on boxes that bind the server address.
	listeners := services.NginxListenerLines(string(live))
	if strings.TrimSpace(listeners) == "" {
		listeners = "    listen 80;\n    listen [::]:80;\n"
	}
	disabled := fmt.Sprintf(`server {
%[1]s    server_name %[2]s www.%[2]s;
    return 503;
    error_page 503 @maintenance;
    location @maintenance {
        default_type text/html;
        return 503 '<html><body style="font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0"><div style="text-align:center"><h1>Site Disabled</h1><p>%[2]s is currently disabled by the administrator.</p></div></body></html>';
    }
}
`, listeners, domain)
	if err := os.WriteFile(confPath, []byte(disabled), 0o644); err != nil {
		nginxPlain(w, http.StatusInternalServerError, "Write disabled config: "+nginxErrText(err))
		return
	}
	if svc, ok := services.AppProcessOwnedServiceName(domain); ok {
		_, _ = nginxRun(0, "systemctl", "stop", svc)
	}
	if err := services.NginxReload(); err != nil {
		nginxPlain(w, http.StatusInternalServerError, fmt.Sprintf("Nginx reload: %v", err))
		return
	}
	slog.Info("Site disabled: " + domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// enableSite: POST /nginx/sites/{domain}/enable — restore the parked vhost.
func (n nginxRoutes) enableSite(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		nginxPlain(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	confPath, backupPath := services.NginxVhostPaths(domain)
	if !nginxExists(backupPath) {
		nginxPlain(w, http.StatusNotFound, "No disabled config backup for "+domain)
		return
	}
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		nginxPlain(w, http.StatusInternalServerError, "Read disabled config: "+nginxErrText(err))
		return
	}
	// A body parked before v2.68.0 lacks the static denies, and the startup
	// retrofit cannot see `*.conf.disabled`; restoring is the only path by
	// which it is served again, so patch on the way in.
	body := string(backup)
	if patched, ok := services.NginxPatchStaticVhost(body); ok {
		slog.Info(fmt.Sprintf("Retrofitted static denies onto %s while re-enabling it", domain))
		body = patched
	}
	if err := os.WriteFile(confPath, []byte(body), 0o644); err != nil {
		nginxPlain(w, http.StatusInternalServerError, "Restore config: "+nginxErrText(err))
		return
	}
	_ = os.Remove(backupPath)
	if svc, ok := services.AppProcessOwnedServiceName(domain); ok {
		_, _ = nginxRun(0, "systemctl", "restart", svc)
	}
	if err := services.NginxReload(); err != nil {
		nginxPlain(w, http.StatusInternalServerError, fmt.Sprintf("Nginx reload: %v", err))
		return
	}
	slog.Info("Site enabled: " + domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// purgeCache: POST /nginx/sites/{domain}/cache/purge.
func (n nginxRoutes) purgeCache(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		nginxFail(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	cacheDir := "/var/cache/nginx/fastcgi/" + strings.ReplaceAll(domain, ".", "_")
	if !nginxExists(cacheDir) {
		nginxOK(w, "No cache directory found (cache may not be enabled)")
		return
	}
	if err := os.RemoveAll(cacheDir); err != nil {
		slog.Warn(fmt.Sprintf("Failed to purge cache for %s: %v", domain, err))
		nginxFail(w, http.StatusInternalServerError, "Failed to purge cache: "+nginxErrText(err))
		return
	}
	_ = os.MkdirAll(cacheDir, 0o755)
	_, _ = nginxRun(0, "chown", "www-data:www-data", cacheDir)
	slog.Info("FastCGI cache purged for " + domain)
	nginxOK(w, "FastCGI cache purged for "+domain)
}

// ── Redis object cache per site ─────────────────────────────────────────

type nginxRedisEnableBody struct {
	RedisDb   int32   `json:"redis_db"`
	PhpPreset *string `json:"php_preset"`
}

func nginxWp(timeout time.Duration, domain string, args ...string) {
	full := append([]string{"-u", "www-data", "wp"}, args...)
	full = append(full, "--skip-plugins", "--skip-themes", fmt.Sprintf("--path=/var/www/%s/public", domain))
	_, _ = nginxRun(timeout, "sudo", full...)
}

// redisEnable: POST /nginx/sites/{domain}/redis/enable.
func (n nginxRoutes) redisEnable(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	var b nginxRedisEnableBody
	if !nginxDecodeStrict(w, r, &b, "redis_db") {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	redisDb := max(0, min(b.RedisDb, 15))
	if out, err := nginxRun(5*time.Second, "redis-cli", "ping"); err != nil || strings.TrimSpace(nginxLossy(out.Stdout)) != "PONG" {
		writeErr(w, http.StatusPreconditionFailed, "Redis is not running. Install Redis first from the Services page.")
		return
	}
	if b.PhpPreset != nil && *b.PhpPreset == "wordpress" {
		wpConfig := fmt.Sprintf("/var/www/%s/public/wp-config.php", domain)
		if nginxExists(wpConfig) {
			cb, err := os.ReadFile(wpConfig)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "Read wp-config: "+nginxErrText(err))
				return
			}
			var cleaned []string
			for _, l := range nginxLines(string(cb)) {
				if !strings.Contains(l, "WP_REDIS_") && !strings.Contains(l, "WP_CACHE_KEY_SALT") {
					cleaned = append(cleaned, l)
				}
			}
			redisCfg := fmt.Sprintf("// Redis Object Cache (managed by DockPanel)\n"+
				"define('WP_REDIS_HOST', '127.0.0.1');\n"+
				"define('WP_REDIS_PORT', 6379);\n"+
				"define('WP_REDIS_DATABASE', %d);\n"+
				"define('WP_CACHE_KEY_SALT', '%s:');\n"+
				"define('WP_REDIS_TIMEOUT', 1);\n"+
				"define('WP_REDIS_READ_TIMEOUT', 1);\n", redisDb, domain)
			joined := strings.Join(cleaned, "\n")
			var nc string
			if pos := strings.Index(joined, "/* That's all, stop editing!"); pos >= 0 {
				nc = joined[:pos] + "\n" + redisCfg + "\n" + joined[pos:]
			} else if pos := strings.Index(joined, "require_once"); pos >= 0 {
				nc = joined[:pos] + "\n" + redisCfg + "\n" + joined[pos:]
			} else {
				nc = redisCfg + "\n" + joined
			}
			if err := os.WriteFile(wpConfig, []byte(nc), 0o644); err != nil {
				writeErr(w, http.StatusInternalServerError, "Write wp-config: "+nginxErrText(err))
				return
			}
			if !nginxExists(fmt.Sprintf("/var/www/%s/public/wp-content/object-cache.php", domain)) {
				nginxWp(30*time.Second, domain, "plugin", "install", "redis-cache", "--activate")
				nginxWp(15*time.Second, domain, "redis", "enable")
			}
			slog.Info(fmt.Sprintf("WordPress Redis configured for %s (db: %d)", domain, redisDb))
		}
	}
	slog.Info(fmt.Sprintf("Redis object cache enabled for %s (db: %d)", domain, redisDb))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redis_db": redisDb})
}

// redisDisable: POST /nginx/sites/{domain}/redis/disable.
func (n nginxRoutes) redisDisable(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	wpConfig := fmt.Sprintf("/var/www/%s/public/wp-config.php", domain)
	if nginxExists(wpConfig) {
		if cb, err := os.ReadFile(wpConfig); err == nil {
			var cleaned []string
			for _, l := range nginxLines(string(cb)) {
				if !strings.Contains(l, "WP_REDIS_") && !strings.Contains(l, "WP_CACHE_KEY_SALT") &&
					!strings.Contains(l, "// Redis Object Cache (managed by DockPanel)") {
					cleaned = append(cleaned, l)
				}
			}
			_ = os.WriteFile(wpConfig, []byte(strings.Join(cleaned, "\n")), 0o644)
		}
		nginxWp(15*time.Second, domain, "redis", "disable")
	}
	slog.Info("Redis object cache disabled for " + domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// redisPurge: POST /nginx/sites/{domain}/redis/purge — FLUSHDB the site's DB.
func (n nginxRoutes) redisPurge(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	db, ok := nginxFieldI64(body, "redis_db")
	if !ok {
		db = 0
	}
	if db < 0 || db > 15 {
		writeErr(w, http.StatusBadRequest, "Invalid Redis DB (0-15)")
		return
	}
	out, err := nginxRun(5*time.Second, "redis-cli", "-n", strconv.FormatInt(db, 10), "FLUSHDB")
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		writeErr(w, http.StatusGatewayTimeout, "Redis flush timed out")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("redis-cli: %v", err))
	case !out.Success():
		writeErr(w, http.StatusInternalServerError, "redis-cli failed: "+nginxLossy(out.Stderr))
	default:
		slog.Info(fmt.Sprintf("Redis DB %d flushed for %s", db, domain))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": fmt.Sprintf("Redis DB %d flushed for %s", db, domain)})
	}
}

// ── WAF (ModSecurity) ───────────────────────────────────────────────────

// wafConfigure: POST /nginx/sites/{domain}/waf/configure.
func (n nginxRoutes) wafConfigure(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	if !nginxExists("/etc/modsecurity/modsecurity.conf") {
		writeErr(w, http.StatusPreconditionFailed, "WAF not installed. Install it from the Services page first.")
		return
	}
	mode, ok := nginxFieldStr(body, "mode")
	if !ok {
		mode = "detection"
	}
	if mode != "detection" && mode != "prevention" {
		writeErr(w, http.StatusBadRequest, "Mode must be 'detection' or 'prevention'")
		return
	}
	engine := "DetectionOnly"
	if mode == "prevention" {
		engine = "On"
	}
	safe := strings.ReplaceAll(domain, ".", "_")
	logDir := "/var/log/modsecurity"
	_ = os.MkdirAll(logDir, 0o755)
	_ = os.MkdirAll("/etc/modsecurity/sites", 0o755)
	crsDir := "/etc/modsecurity/crs"
	crs := "# OWASP CRS not found — basic protection only"
	if nginxExists(crsDir + "/crs-setup.conf") {
		crs = fmt.Sprintf("Include %s/crs-setup.conf\nInclude %s/rules/*.conf", crsDir, crsDir)
	}
	cfg := fmt.Sprintf("# WAF config for %s (managed by DockPanel)\nInclude /etc/modsecurity/modsecurity.conf\nSecRuleEngine %s\nSecAuditLog %s/%s_audit.log\nSecAuditLogType Serial\n%s\n# Allow larger request bodies for file uploads\nSecRequestBodyLimit 52428800\n",
		domain, engine, logDir, safe, crs)
	cfgPath := fmt.Sprintf("/etc/modsecurity/sites/%s.conf", safe)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "Write config: "+nginxErrText(err))
		return
	}
	slog.Info(fmt.Sprintf("WAF configured for %s (mode: %s)", domain, mode))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": mode, "config_path": cfgPath})
}

// wafLogs: GET /nginx/sites/{domain}/waf/logs?limit= — recent WAF events.
func (n nginxRoutes) wafLogs(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	logPath := fmt.Sprintf("/var/log/modsecurity/%s_audit.log", strings.ReplaceAll(domain, ".", "_"))
	limit := 50
	if v, err := strconv.ParseUint(r.URL.Query().Get("limit"), 10, 64); err == nil {
		limit = int(min(v, math.MaxInt32))
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []any{}, "total": 0})
		return
	}
	// Audit log sections are "--xxx-A--" … "--xxx-Z--"; read backwards.
	events := []map[string]any{}
	lines := nginxLines(nginxLossy(b))
	var current string
	inEvent := false
	for i, taken := len(lines)-1, 0; i >= 0 && taken < 10000; i, taken = i-1, taken+1 {
		line := lines[i]
		if strings.HasPrefix(line, "--") && strings.HasSuffix(line, "-A--") {
			if current != "" {
				if evt, ok := nginxParseModsecEvent(current); ok {
					events = append(events, evt)
					if len(events) >= limit {
						break
					}
				}
				current = ""
			}
			inEvent = true
		}
		if inEvent {
			current = line + "\n" + current
		}
		if strings.HasPrefix(line, "--") && strings.HasSuffix(line, "-Z--") {
			inEvent = false
		}
	}
	if current != "" {
		if evt, ok := nginxParseModsecEvent(current); ok {
			events = append(events, evt)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "total": len(events)})
}

func nginxParseModsecEvent(raw string) (map[string]any, bool) {
	var timestamp, requestLine, uri, clientIP, ruleMsg, severity, action string
	for _, line := range nginxLines(raw) {
		if strings.HasPrefix(line, "[") && timestamp == "" {
			timestamp = line
		}
		for _, m := range []string{"GET ", "POST ", "PUT ", "DELETE "} {
			if rest, ok := strings.CutPrefix(line, m); ok {
				requestLine = line
				uri = ""
				if f := strings.Fields(rest); len(f) > 0 {
					uri = f[0]
				}
				break
			}
		}
		if strings.Contains(line, "client:") || strings.Contains(line, "client ") {
			_, ip, ok := strings.Cut(line, "client:")
			if !ok {
				_, ip, ok = strings.Cut(line, "client ")
			}
			if ok {
				first, _, _ := strings.Cut(strings.TrimSpace(ip), ",")
				clientIP = strings.TrimSpace(first)
			}
		}
		if _, msg, ok := strings.Cut(line, "[msg \""); ok {
			ruleMsg, _, _ = strings.Cut(msg, "\"")
		}
		if _, sev, ok := strings.Cut(line, "[severity \""); ok {
			severity, _, _ = strings.Cut(sev, "\"")
		}
		if strings.Contains(line, "Action:") {
			action = "logged"
			if strings.Contains(line, "Intercepted") {
				action = "blocked"
			}
		}
	}
	if ruleMsg == "" && requestLine == "" {
		return nil, false
	}
	if action == "" {
		action = "logged"
	}
	return map[string]any{"timestamp": timestamp, "client_ip": clientIP, "request": requestLine, "uri": uri,
		"rule_message": ruleMsg, "severity": severity, "action": action}, true
}

// ── Image optimisation ──────────────────────────────────────────────────

// optimizeImages: POST /nginx/sites/{domain}/optimize-images — WebP/AVIF.
func (n nginxRoutes) optimizeImages(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	// Where the site's files are: node/python/proxy at the root, static/php
	// under public/ (a hardcoded public/ reported clean runs over zero files).
	// No runtime = an older backend, keeping the previous behaviour.
	runtime, ok := nginxFieldStr(body, "runtime")
	if !ok {
		runtime = "static"
	}
	siteDir := services.NginxDocumentRootFor("/var/www/"+domain, runtime)
	if !nginxExists(siteDir) {
		writeErr(w, http.StatusNotFound, "Site directory not found")
		return
	}
	format, ok := nginxFieldStr(body, "format")
	if !ok {
		format = "webp"
	}
	if format != "webp" && format != "avif" {
		writeErr(w, http.StatusBadRequest, "Format must be 'webp' or 'avif'")
		return
	}
	quality, ok := nginxFieldU64(body, "quality")
	if !ok {
		quality = 80
	}
	quality = max(1, min(quality, 100))
	tool, pkg := "cwebp", "webp"
	if format == "avif" {
		tool, pkg = "avifenc", "libavif-bin"
	}
	if out, err := nginxRun(3*time.Second, "which", tool); err != nil || !out.Success() {
		if out, err := nginxRun(60*time.Second, "sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y "+pkg); err == nil && out.Success() {
			slog.Info(fmt.Sprintf("Installed %s for image optimization", pkg))
		} else {
			writeErr(w, http.StatusPreconditionFailed, fmt.Sprintf("%s not available. Install '%s' package.", tool, pkg))
			return
		}
	}
	findCmd := fmt.Sprintf("find %s -type f \\( -name '*.jpg' -o -name '*.jpeg' -o -name '*.png' \\) -size +1k 2>/dev/null | head -500", siteDir)
	out, err := nginxRun(30*time.Second, "sh", "-c", findCmd)
	if errors.Is(err, context.DeadlineExceeded) {
		writeErr(w, http.StatusGatewayTimeout, "Find timed out")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Find: %v", err))
		return
	}
	var files []string
	for _, l := range nginxLines(string(out.Stdout)) {
		if l != "" {
			files = append(files, l)
		}
	}
	var converted, skipped uint32
	var saved int64
	for _, f := range files {
		outFile := f + "." + format
		if nginxExists(outFile) {
			skipped++
			continue
		}
		var res safecmd.Output
		var err error
		if format == "avif" {
			res, err = nginxRun(30*time.Second, "avifenc", "--min", "0", "--max", "63", "-a", "end-usage=q",
				"-a", fmt.Sprintf("cq-level=%d", 100-quality), "-a", "tune=ssim", f, outFile)
		} else {
			res, err = nginxRun(30*time.Second, "cwebp", "-q", strconv.FormatUint(quality, 10), f, "-o", outFile)
		}
		if err == nil && res.Success() {
			if a, e1 := os.Stat(f); e1 == nil {
				if b, e2 := os.Stat(outFile); e2 == nil {
					saved += a.Size() - b.Size()
				}
			}
			converted++
		}
	}
	savedMB := float64(saved) / 1048576.0
	slog.Info(fmt.Sprintf("Image optimization for %s: %d/%d converted (%s), %.1fMB saved", domain, converted, len(files), format, savedMB))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "format": format, "quality": quality, "total_images": len(files), "converted": converted,
		"skipped": skipped, "saved_bytes": saved, "saved_mb": fmt.Sprintf("%.1f", savedMB),
	})
}

type nginxRoutes struct{ st *State }

// registerNginx mounts src/routes/nginx.rs.
func registerNginx(r *Router) {
	n := nginxRoutes{st: r.State}
	r.Handle("PUT /nginx/sites/{domain}", n.putSite)
	r.Handle("DELETE /nginx/sites/{domain}", n.deleteSite)
	r.Handle("GET /nginx/sites/{domain}", n.getSite)
	r.Handle("POST /nginx/sites/{domain}/rename", n.renameSite)
	r.Handle("POST /nginx/sites/{domain}/disable", n.disableSite)
	r.Handle("POST /nginx/sites/{domain}/enable", n.enableSite)
	r.Handle("POST /nginx/sites/{domain}/cache/purge", n.purgeCache)
	r.Handle("POST /nginx/sites/{domain}/redis/enable", n.redisEnable)
	r.Handle("POST /nginx/sites/{domain}/redis/disable", n.redisDisable)
	r.Handle("POST /nginx/sites/{domain}/redis/purge", n.redisPurge)
	r.Handle("POST /nginx/sites/{domain}/waf/configure", n.wafConfigure)
	r.Handle("GET /nginx/sites/{domain}/waf/logs", n.wafLogs)
	r.Handle("POST /nginx/sites/{domain}/optimize-images", n.optimizeImages)
	r.Handle("POST /nginx/test", n.testNginx)
	r.Handle("POST /nginx/reload", n.reloadNginx)
	r.Handle("POST /nginx/redirects/add", n.addRedirect)
	r.Handle("GET /nginx/redirects/{domain}", n.listRedirects)
	r.Handle("POST /nginx/redirects/{domain}/remove", n.removeRedirect)
	r.Handle("POST /nginx/password-protect", n.passwordProtect)
	r.Handle("GET /nginx/password-protect/{domain}", n.listProtected)
	r.Handle("POST /nginx/password-protect/{domain}/remove", n.removeProtection)
	r.Handle("POST /nginx/aliases/add", n.addAlias)
	r.Handle("GET /nginx/aliases/{domain}", n.listAliases)
	r.Handle("POST /nginx/aliases/{domain}/remove", n.removeAlias)
	r.Handle("GET /nginx/site-logs/{domain}", n.siteLogs)
	r.Handle("GET /nginx/site-stats/{domain}", n.siteStats)
	r.Handle("GET /nginx/site-traffic-delta/{domain}", n.siteTrafficDelta)
	r.Handle("GET /nginx/last-activity/{domain}", n.lastActivity)
	r.Handle("GET /nginx/php-errors/{domain}", n.phpErrors)
	r.Handle("POST /nginx/clone-site", n.cloneSite)
	r.Handle("GET /nginx/env/{domain}", n.getEnv)
	r.Handle("PUT /nginx/env/{domain}", n.setEnv)
}
