package routes

// The named certificate registry (#104). An operator-supplied certificate is
// registered ONCE under an alias and referenced by that alias from every
// stack claiming a domain under it. The PEM pair lives only on the agent's
// disk (services.SslRegistryDir); the panel keeps metadata and the alias.
//
// Every refusal is a 4xx carrying a sentence (a 5xx reaches the operator as
// an incident id), and NOTHING is written before every check has passed.

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type sslRegistryRegisterRequest struct {
	Alias       string `json:"alias"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	// Overwrite a pair already registered under this alias; off by default
	// so two operators registering one name do not silently race.
	Replace bool `json:"replace"`
	// Domains the new pair must still cover (on a replace, every domain a
	// stack claims through this alias) — dropping one would take that site's
	// TLS down at the next reload.
	MustCover []string `json:"must_cover"`
}

type sslRegistryCoversRequest struct {
	Domain string `json:"domain"`
}

// sslRegistryAliasDirs returns the alias directory and a per-REQUEST staging
// directory beside it (same filesystem, so the final rename is atomic; a fresh
// nonce because every request in this process shares a pid).
func sslRegistryAliasDirs(alias, tag string) (string, string) {
	nonce := strings.ReplaceAll(uuid.NewString(), "-", "")
	return services.SslRegistryDir + "/" + alias, fmt.Sprintf("%s/.%s.%s-%s", services.SslRegistryDir, alias, tag, nonce)
}

// sslRegistrySweepLeftovers removes staging/aside directories a crashed
// request left for this alias (each holds a full key pair). Only entries older
// than any plausibly running request are touched.
func sslRegistrySweepLeftovers(alias string) {
	entries, err := os.ReadDir(services.SslRegistryDir)
	if err != nil {
		return
	}
	tmpPrefix, prevPrefix := "."+alias+".tmp-", "."+alias+".prev-"
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, tmpPrefix) && !strings.HasPrefix(name, prevPrefix) {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > 600*time.Second {
			slog.Warn(fmt.Sprintf("SSL registry: removing leftover %s from an earlier request", name))
			_ = os.RemoveAll(services.SslRegistryDir + "/" + name)
		}
	}
}

// sslRegistryStagePair writes the pair into a fresh staging directory; the
// key via the 0600-at-creation writer, the root owner-only.
func sslRegistryStagePair(tmpDir, certificate, privateKey string) error {
	if err := os.MkdirAll(services.SslRegistryDir, 0o700); err != nil {
		return fmt.Errorf("could not create the registry directory: %s", nginxErrText(err))
	}
	_ = os.Chmod(services.SslRegistryDir, 0o700)
	_ = os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("could not stage the certificate: %s", nginxErrText(err))
	}
	if err := os.WriteFile(tmpDir+"/fullchain.pem", []byte(certificate), 0o644); err != nil {
		return fmt.Errorf("could not write the certificate: %s", nginxErrText(err))
	}
	return services.SslWriteKeyFile(tmpDir+"/privkey.pem", privateKey)
}

// sslRegistryRegister: POST /ssl/registry.
func sslRegistryRegister(w http.ResponseWriter, r *http.Request) {
	var b sslRegistryRegisterRequest
	if !nginxDecodeStrict(w, r, &b, "alias", "certificate", "private_key") {
		return
	}
	alias := b.Alias
	if !services.SslIsValidCertAlias(alias) {
		writeErr(w, http.StatusBadRequest, "the alias must be 1 to 64 lowercase letters, digits or hyphens, starting and ending "+
			"with a letter or digit — a DNS label shape, like wildcard-2026")
		return
	}
	if strings.TrimSpace(b.Certificate) == "" || strings.TrimSpace(b.PrivateKey) == "" {
		writeErr(w, http.StatusBadRequest, "both the certificate and the private key are required")
		return
	}
	if !strings.Contains(b.PrivateKey, "BEGIN") {
		writeErr(w, http.StatusBadRequest, "the private key is not PEM — it should start with a BEGIN line")
		return
	}
	// Both answered before the disk is touched; the second is the check
	// nginx would otherwise make at the first reload after a claim.
	meta, err := services.SslCertMetadataOf(b.Certificate)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := services.SslKeyMatchesCert(b.Certificate, b.PrivateKey); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, d := range b.MustCover {
		if _, err := services.SslCertCoversDomain(b.Certificate, d); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("%s is served under this alias and the new certificate does not cover it: %v", d, err))
			return
		}
	}

	finalDir, tmpDir := sslRegistryAliasDirs(alias, "tmp")
	_, statErr := os.Stat(finalDir)
	exists := statErr == nil
	if exists && !b.Replace {
		writeErr(w, http.StatusConflict, fmt.Sprintf("a certificate named %s is already registered on this server", alias))
		return
	}

	// Stage beside the destination and rename into place, so no reader ever
	// sees a directory holding one file of two.
	sslRegistrySweepLeftovers(alias)
	certPath, keyPath := services.SslRegistryPaths(alias)
	if err := sslRegistryStagePair(tmpDir, b.Certificate, b.PrivateKey); err != nil {
		_ = os.RemoveAll(tmpDir)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// On a replace the incumbent is moved ASIDE (not deleted) so a refusing
	// reload can put it back; a directory cannot be renamed over a non-empty one.
	_, asideDir := sslRegistryAliasDirs(alias, "prev")
	previousKept := false
	if exists {
		_ = os.RemoveAll(asideDir)
		if err := os.Rename(finalDir, asideDir); err != nil {
			_ = os.RemoveAll(tmpDir)
			writeErr(w, http.StatusInternalServerError, "could not move the previous certificate aside: "+nginxErrText(err))
			return
		}
		previousKept = true
	}
	if err := os.Rename(tmpDir, finalDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		if previousKept {
			_ = os.Rename(asideDir, finalDir)
		}
		writeErr(w, http.StatusInternalServerError, "could not install the certificate: "+nginxErrText(err))
		return
	}

	resp := map[string]any{
		"ok": true, "alias": alias, "dns_names": meta.DNSNames, "issuer": meta.Issuer,
		"not_before": services.SslRFC3339(meta.NotBefore), "not_after": services.SslRFC3339(meta.NotAfter),
		"fingerprint_sha256": meta.FingerprintSha256, "cert_path": certPath, "key_path": keyPath,
	}

	// A replaced pair a live vhost names must reach nginx now — otherwise the
	// old cert serves from memory until an unrelated reload, which is where a
	// refused pair would surface as an outage. Test, and put back on "no".
	if previousKept && services.OwnershipRegistryCertInUse(alias) {
		var verdict error
		if out, err := services.NginxTestConfig(); err != nil {
			verdict = err
		} else if !out.Success {
			verdict = errors.New(out.Stderr)
		}
		if verdict != nil {
			restored := os.RemoveAll(finalDir) == nil && os.Rename(asideDir, finalDir) == nil
			slog.Warn(fmt.Sprintf("SSL registry: nginx refused the replaced pair for %s: %v", alias, verdict))
			note := " (and the previous certificate could NOT be put back — check the registry directory)"
			if restored {
				note = " (the previous certificate was put back)"
			}
			writeErr(w, http.StatusBadGateway, fmt.Sprintf("nginx refused the configuration with the replaced certificate: %s%s",
				strings.TrimSpace(verdict.Error()), note))
			return
		}
		if err := services.NginxReload(); err != nil {
			slog.Warn(fmt.Sprintf("SSL registry: nginx reload failed after replacing %s: %v", alias, err))
			resp["warning"] = fmt.Sprintf("the certificate was replaced but nginx did not reload: %v", err)
		} else {
			resp["reloaded"] = true
		}
	}
	if previousKept {
		_ = os.RemoveAll(asideDir)
	}
	slog.Info(fmt.Sprintf("SSL registry: registered %s for %v (expires %s)", alias, meta.DNSNames, resp["not_after"]))
	writeJSON(w, http.StatusCreated, resp)
}

// sslRegistryCovers: POST /ssl/registry/{alias}/covers — does the registered
// certificate name this domain? Asked at claim time and by the deploy path.
func sslRegistryCovers(w http.ResponseWriter, r *http.Request) {
	var b sslRegistryCoversRequest
	if !nginxDecodeStrict(w, r, &b, "domain") {
		return
	}
	alias := r.PathValue("alias")
	if !services.SslIsValidCertAlias(alias) {
		writeErr(w, http.StatusBadRequest, "Invalid certificate alias")
		return
	}
	if !isValidDomain(b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	certPath, _ := services.SslRegistryPaths(alias)
	pemBytes, err := os.ReadFile(certPath)
	if errors.Is(err, fs.ErrNotExist) {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("no certificate named %s is registered on this server", alias))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read the registered certificate: "+nginxErrText(err))
		return
	}
	names, err := services.SslCertCoversDomain(string(pemBytes), b.Domain)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "dns_names": names})
}

// sslRegistryRemove: DELETE /ssl/registry/{alias} — unless a vhost still
// names it (a vhost pointing at a missing pair takes every site down at the
// next `nginx -t`).
func sslRegistryRemove(w http.ResponseWriter, r *http.Request) {
	alias := r.PathValue("alias")
	if !services.SslIsValidCertAlias(alias) {
		writeErr(w, http.StatusBadRequest, "Invalid certificate alias")
		return
	}
	finalDir, _ := sslRegistryAliasDirs(alias, "tmp")
	if _, err := os.Stat(finalDir); errors.Is(err, fs.ErrNotExist) {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("no certificate named %s is registered on this server", alias))
		return
	} else if err != nil {
		// Not "absent": a 404 would have the panel drop its row while the
		// pair stays on disk.
		writeErr(w, http.StatusInternalServerError, "could not read the registered certificate: "+nginxErrText(err))
		return
	}
	refs, err := services.OwnershipRegistryCertReferences(alias)
	if err != nil {
		writeErr(w, http.StatusConflict, fmt.Sprintf("cannot tell whether a vhost still names %s: %v", alias, err))
		return
	}
	if len(refs) > 0 {
		writeErr(w, http.StatusConflict, fmt.Sprintf("the certificate named %s is still referenced by %d vhost file(s) on "+
			"this server (%s); move those domains to another certificate, or remove "+
			"the parked configuration, first", alias, len(refs), strings.Join(refs, ", ")))
		return
	}
	sslRegistrySweepLeftovers(alias)
	if err := os.RemoveAll(finalDir); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not remove the registered certificate: "+nginxErrText(err))
		return
	}
	slog.Info("SSL registry: removed " + alias)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// registerSslRegistry mounts src/routes/ssl_registry.rs.
func registerSslRegistry(r *Router) {
	r.Handle("POST /ssl/registry", sslRegistryRegister)
	r.Handle("POST /ssl/registry/{alias}/covers", sslRegistryCovers)
	r.Handle("DELETE /ssl/registry/{alias}", sslRegistryRemove)
}
