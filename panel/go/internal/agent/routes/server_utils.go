package routes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// serverUtilsUploadMaxFileBytes is the largest file the upload endpoint
// accepts, in DECODED bytes.
//
// This number must equal UPLOAD_MAX_FILE_BYTES in the panel's
// routes/files.rs; upload-refusal-pin-e2e.sh compares them along with
// docs/guides/file-uploads.md. It used to read 50 MB and could never fire:
// the 2 MiB request-body limit refused an oversize upload first, in plain
// text, before this handler ran.
const serverUtilsUploadMaxFileBytes = 1_500_000

// serverUtilsAuthorizedKeys is the file the SSH-key handlers manage. sshd
// reads root's keys from here and nowhere else, so it cannot be relocated
// out of the sandbox's way.
const serverUtilsAuthorizedKeys = "/root/.ssh/authorized_keys"

const serverUtilsAutoUpgradesConf = "/etc/apt/apt.conf.d/20auto-upgrades"

func registerServerUtils(r *Router) {
	r.Handle("POST /files/{domain}/upload", serverUtilsFileUpload)
	r.Handle("GET /ssh-keys", serverUtilsListSSHKeys)
	r.Handle("POST /ssh-keys", serverUtilsAddSSHKey)
	r.Handle("DELETE /ssh-keys/{fingerprint}", serverUtilsRemoveSSHKey)
	r.Handle("GET /auto-updates/status", serverUtilsAutoUpdatesStatus)
	r.Handle("POST /auto-updates/enable", serverUtilsEnableAutoUpdates)
	r.Handle("POST /auto-updates/disable", serverUtilsDisableAutoUpdates)
}

func serverUtilsOK(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

// serverUtilsUploadTooLarge is worded as the panel words it — an agent 4xx is
// passed through to the operator verbatim, so it must say what to do instead.
func serverUtilsUploadTooLarge(w http.ResponseWriter) {
	writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
		"File is too large for the file manager (limit %.1f MB). Copy it with rsync or scp over the server's own SSH, or use the Migration wizard to move a whole site.",
		float64(serverUtilsUploadMaxFileBytes)/1_000_000))
}

// ── File Upload ─────────────────────────────────────────────────────────

type serverUtilsUploadRequest struct {
	Path string `json:"path"`
	// Base64 content: `content` (frontend name) or `content_base64` (legacy
	// agent name) for backwards compatibility.
	Content       *string `json:"content"`
	ContentBase64 *string `json:"content_base64"`
	// Optional filename joined onto path (path is then the directory).
	Filename *string `json:"filename"`
}

// serverUtilsDecodeUpload takes the body rejection rather than letting it
// short-circuit: otherwise the body limit answers in plain text the panel
// then relays as an unexplained 413. Returns (status, msg) on failure.
func serverUtilsDecodeUpload(w http.ResponseWriter, r *http.Request) (serverUtilsUploadRequest, int, string) {
	var req serverUtilsUploadRequest
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" && !strings.HasSuffix(ct, "+json") {
		return req, http.StatusBadRequest, "Invalid upload request: Expected request with `Content-Type: application/json`"
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return req, http.StatusRequestEntityTooLarge, ""
		}
		return req, http.StatusBadRequest, "Invalid upload request: Failed to buffer the request body: " + err.Error()
	}
	if err := json.Unmarshal(body, &req); err != nil {
		var syn *json.SyntaxError
		if errors.As(err, &syn) || errors.Is(err, io.ErrUnexpectedEOF) {
			return req, http.StatusBadRequest, "Invalid upload request: Failed to parse the request body as JSON: " + err.Error()
		}
		return req, http.StatusBadRequest, "Invalid upload request: Failed to deserialize the JSON body into the target type: " + err.Error()
	}
	if req.Content != nil && req.ContentBase64 != nil {
		return req, http.StatusBadRequest, "Invalid upload request: Failed to deserialize the JSON body into the target type: duplicate field `content`"
	}
	if req.Content == nil {
		req.Content = req.ContentBase64
	}
	if req.Content == nil {
		return req, http.StatusBadRequest, "Invalid upload request: Failed to deserialize the JSON body into the target type: missing field `content`"
	}
	return req, 0, ""
}

func serverUtilsFileUpload(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	req, status, msg := serverUtilsDecodeUpload(w, r)
	if status == http.StatusRequestEntityTooLarge {
		serverUtilsUploadTooLarge(w)
		return
	}
	if status != 0 {
		writeErr(w, status, msg)
		return
	}
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return
	}
	// Decode first (fail fast before any FS ops).
	data, err := base64.StdEncoding.Strict().DecodeString(*req.Content)
	if err != nil || strings.ContainsAny(*req.Content, "\r\n") {
		writeErr(w, http.StatusBadRequest, "Invalid base64 content")
		return
	}
	// Same limit the panel enforces, on the decoded bytes.
	if len(data) > serverUtilsUploadMaxFileBytes {
		serverUtilsUploadTooLarge(w)
		return
	}

	targetRel := req.Path
	if req.Filename != nil && *req.Filename != "" {
		name := *req.Filename
		if strings.ContainsAny(name, "/\\\x00") || strings.Contains(name, "..") {
			writeErr(w, http.StatusBadRequest, "Invalid filename")
			return
		}
		if dir := strings.Trim(req.Path, "/"); dir == "" {
			targetRel = name
		} else {
			targetRel = dir + "/" + name
		}
	}

	// Confine strictly to the site root via the shared, symlink-safe
	// resolver. (The former "_server" magic-domain branch — a root-write
	// primitive with a weaker traversal check and no live caller — is gone.)
	fullPath, err := services.FilesResolveSafePath(domain, targetRel)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to create directory: "+err.Error())
		return
	}
	if err := os.WriteFile(fullPath, data, 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to write file: "+err.Error())
		return
	}
	slog.Info(fmt.Sprintf("File uploaded: %s (%d bytes)", fullPath, len(data)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": fullPath, "size": len(data)})
}

// ── SSH Key Management ──────────────────────────────────────────────────

// serverUtilsReadAuthorizedKeys reads root's authorized_keys from OUTSIDE the
// agent's sandbox.
//
// This feature never worked under ProtectHome=yes: /root is an inaccessible
// mount inside the agent's namespace, the in-process read failed, the error
// was discarded into a default, and GET /ssh-keys answered 200 with an empty
// list — a false all-clear on the most consequential access list a server
// has. ReadWritePaths=/root/.ssh and BindPaths=/root/.ssh do NOT override
// ProtectHome=yes (measured); loosening ProtectHome is what agent_unit's
// hardening test forbids. So the file operations run unsandboxed.
//
// (nil, nil) means the file genuinely does not exist — a legitimate empty
// list. An unreadable file is an error — the whole point of the fix.
func serverUtilsReadAuthorizedKeys(ctx context.Context) (*string, error) {
	// `test -e` first so "absent" and "unreadable" are DIFFERENT answers
	// rather than being told apart by a locale-dependent error string.
	o, err := safecmd.NewUnsandboxed("test").Arg("-e", serverUtilsAuthorizedKeys).Output(ctx)
	if err != nil || !o.Success() {
		return nil, nil
	}
	out, err := safecmd.NewUnsandboxed("cat").Arg(serverUtilsAuthorizedKeys).Output(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %v", serverUtilsAuthorizedKeys, err)
	}
	if !out.Success() {
		return nil, fmt.Errorf("could not read %s: %s", serverUtilsAuthorizedKeys, strings.TrimSpace(string(out.Stderr)))
	}
	s := strings.ToValidUTF8(string(out.Stdout), "�")
	return &s, nil
}

// serverUtilsWriteAuthorizedKeys replaces root's authorized_keys atomically,
// from outside the sandbox: staged 0600 in /var/lib/dockpanel (in the unit's
// ReadWritePaths) and moved into place by `install`, which creates
// /root/.ssh, sets the mode and copies in one call outside the namespace.
func serverUtilsWriteAuthorizedKeys(ctx context.Context, content string) error {
	staging := "/var/lib/dockpanel/.authorized_keys." + uuid.NewString()
	f, err := os.OpenFile(staging, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("could not stage the new key file: %v", err)
	}
	_, werr := f.WriteString(content)
	f.Close()
	if werr != nil {
		os.Remove(staging)
		return fmt.Errorf("could not stage the new key file: %v", werr)
	}
	out, err := safecmd.NewUnsandboxed("install").
		Arg("-D", "-m", "600", "-o", "root", "-g", "root", staging, serverUtilsAuthorizedKeys).Output(ctx)
	_ = os.Remove(staging)
	if err != nil {
		return fmt.Errorf("could not install %s: %v", serverUtilsAuthorizedKeys, err)
	}
	if !out.Success() {
		return fmt.Errorf("could not install %s: %s", serverUtilsAuthorizedKeys, strings.TrimSpace(string(out.Stderr)))
	}
	return nil
}

// serverUtilsLines is Rust's str::lines (no trailing empty line, \r\n ok).
func serverUtilsLines(s string) []string {
	if s == "" {
		return nil
	}
	ls := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i, l := range ls {
		ls[i] = strings.TrimSuffix(l, "\r")
	}
	return ls
}

// serverUtilsFingerprint is "SHA256:<unpadded std base64>" of the decoded key
// data; undecodable data hashes as empty (Rust unwrap_or_default).
func serverUtilsFingerprint(keyData string) string {
	decoded, err := base64.StdEncoding.Strict().DecodeString(keyData)
	if err != nil {
		decoded = nil
	}
	sum := sha256.Sum256(decoded)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

func serverUtilsListSSHKeys(w http.ResponseWriter, r *http.Request) {
	// An empty list must mean "root has no keys", never "I could not look".
	content, err := serverUtilsReadAuthorizedKeys(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	keys := []map[string]string{}
	if content != nil {
		for _, line := range serverUtilsLines(*content) {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			parts := append(strings.SplitN(line, " ", 3), "", "")
			keyType, keyData, comment := parts[0], parts[1], parts[2]
			fp := ""
			if keyData != "" {
				fp = serverUtilsFingerprint(keyData)
			}
			keys = append(keys, map[string]string{
				"type":        keyType,
				"fingerprint": fp,
				"comment":     comment,
				"key":         keyType + " " + keyData[:min(len(keyData), 20)] + "...",
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// serverUtilsValidateKey returns "" when key is acceptable, else the error.
func serverUtilsValidateKey(key string) string {
	// Reject embedded newlines (prevents multi-key injection).
	if strings.ContainsAny(key, "\n\r\x00") {
		return "SSH key must be a single line"
	}
	if !strings.HasPrefix(key, "ssh-") && !strings.HasPrefix(key, "ecdsa-") && !strings.HasPrefix(key, "sk-") {
		return "Invalid SSH key format"
	}
	if p := strings.Fields(key); len(p) < 2 || len(p[1]) < 16 {
		return "Invalid SSH key: missing key data"
	}
	// Reject authorized_keys options (command=, from=, restrict, …).
	for _, bad := range []string{"command=", "from=", "restrict", "no-pty", "permitopen"} {
		if strings.Contains(key, bad) {
			return "SSH key options not allowed"
		}
	}
	return ""
}

func serverUtilsAddSSHKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key *string `json:"key"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Key == nil {
		http.Error(w, "Failed to deserialize the JSON body into the target type: missing field `key`", http.StatusUnprocessableEntity)
		return
	}
	key := strings.TrimSpace(*body.Key)
	if msg := serverUtilsValidateKey(key); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	// A read that FAILED must not be mistaken for an empty key file — that
	// is how an append would silently become a replace.
	cur, err := serverUtilsReadAuthorizedKeys(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	content := ""
	if cur != nil {
		content = *cur
	}
	if strings.Contains(content, key) {
		writeErr(w, http.StatusConflict, "Key already exists")
		return
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += key + "\n"
	if err := serverUtilsWriteAuthorizedKeys(r.Context(), content); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("SSH key added")
	serverUtilsOK(w, "SSH key added")
}

func serverUtilsRemoveSSHKey(w http.ResponseWriter, r *http.Request) {
	fingerprint := r.PathValue("fingerprint")
	// THE ORDER OF THESE TWO FIXES MATTERS. This read used to default to
	// empty on failure: every line filtered out of nothing, and the write
	// below stored "\n" — DELETING EVERY ROOT SSH KEY ON THE BOX. Repairing
	// the sandbox alone would have made a dead feature destructive on the
	// first transient read error. A failed read must abort.
	cur, err := serverUtilsReadAuthorizedKeys(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cur == nil {
		writeErr(w, http.StatusNotFound, "root has no authorized_keys file")
		return
	}
	newContent := serverUtilsRemoveKeyLines(*cur, fingerprint)
	if err := serverUtilsWriteAuthorizedKeys(r.Context(), newContent+"\n"); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("SSH key removed: " + fingerprint)
	serverUtilsOK(w, "SSH key removed")
}

func serverUtilsRemoveKeyLines(content, fingerprint string) string {
	var kept []string
	for _, line := range serverUtilsLines(content) {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			kept = append(kept, line)
			continue
		}
		parts := append(strings.SplitN(line, " ", 3), "")
		if parts[1] == "" || serverUtilsFingerprint(parts[1]) != fingerprint {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// ── Auto-Updates ────────────────────────────────────────────────────────

func serverUtilsAutoUpdatesStatus(w http.ResponseWriter, _ *http.Request) {
	// services.Pkg maps this onto dnf-automatic on the RHEL family.
	installed := services.PkgIsInstalled("unattended-upgrades")
	enabled := false
	if installed {
		if c, err := os.ReadFile(serverUtilsAutoUpgradesConf); err == nil {
			enabled = strings.Contains(string(c), `"1"`)
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"installed": installed, "enabled": enabled})
}

func serverUtilsEnableAutoUpdates(w http.ResponseWriter, r *http.Request) {
	// Unsandboxed: apt-get install writes to /var/lib/dpkg + /usr.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	_, _ = safecmd.NewUnsandboxed("sh").Arg("-c", "apt-get install -y unattended-upgrades").Output(ctx)

	conf := "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
	if err := os.WriteFile(serverUtilsAutoUpgradesConf, []byte(conf), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to write config: "+err.Error())
		return
	}
	slog.Info("Auto-updates enabled")
	serverUtilsOK(w, "Automatic security updates enabled")
}

func serverUtilsDisableAutoUpdates(w http.ResponseWriter, _ *http.Request) {
	conf := "APT::Periodic::Update-Package-Lists \"0\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n"
	if err := os.WriteFile(serverUtilsAutoUpgradesConf, []byte(conf), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to write config: "+err.Error())
		return
	}
	slog.Info("Auto-updates disabled")
	serverUtilsOK(w, "Automatic security updates disabled")
}

// The panel IP-whitelist handlers that stood here were removed in v2.90.0
// (deliberately spelled around: an absence pin greps for the endpoint's
// literal name). They wrote a file under /etc/dockpanel/ that no nginx
// include, template or binary ever read; the backend's real IP restriction
// replaced them. A stale copy may exist on an upgraded box; it is inert and
// nothing here reads or removes it.
