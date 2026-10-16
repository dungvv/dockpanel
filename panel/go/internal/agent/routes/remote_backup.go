package routes

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// RemoteBackupDestinationConfig is a remote destination as the panel sends it.
type RemoteBackupDestinationConfig struct {
	Dtype string `json:"type"`
	// S3/R2 fields
	Bucket     *string `json:"bucket"`
	Region     *string `json:"region"`
	Endpoint   *string `json:"endpoint"`
	AccessKey  *string `json:"access_key"`
	SecretKey  *string `json:"secret_key"`
	PathPrefix *string `json:"path_prefix"`
	// SFTP fields
	Host       *string `json:"host"`
	Port       *uint16 `json:"port"`
	Username   *string `json:"username"`
	Password   *string `json:"password"`
	KeyPath    *string `json:"key_path"`
	RemotePath *string `json:"remote_path"`
}

// RemoteBackupUploadRequest is POST /backups/upload.
type RemoteBackupUploadRequest struct {
	Filepath    string                        `json:"filepath"`
	Destination RemoteBackupDestinationConfig `json:"destination"`
}

// RemoteBackupTestRequest is POST /backups/test-destination.
type RemoteBackupTestRequest struct {
	Destination RemoteBackupDestinationConfig `json:"destination"`
}

// RemoteBackupPruneRequest is POST /backups/prune.
type RemoteBackupPruneRequest struct {
	Destination RemoteBackupDestinationConfig `json:"destination"`
	Domain      string                        `json:"domain"`
	Retention   uint                          `json:"retention"`
}

func registerRemoteBackup(r *Router) {
	r.Handle("POST /backups/upload", remoteBackupUpload)
	r.Handle("POST /backups/test-destination", remoteBackupTestDestination)
	r.Handle("POST /backups/prune", remoteBackupPrune)
}

// remoteBackupDecode mirrors serde: the listed top-level fields and
// destination.type are required (missing/null → 422, like axum).
func remoteBackupDecode(w http.ResponseWriter, r *http.Request, v any, required ...string) bool {
	var raw json.RawMessage
	if !decodeJSON(w, r, &raw) {
		return false
	}
	fail := func(msg string) bool {
		http.Error(w, "Failed to deserialize the JSON body into the target type: "+msg, http.StatusUnprocessableEntity)
		return false
	}
	missing := func(m map[string]json.RawMessage, k string) bool {
		val, ok := m[k]
		return !ok || strings.TrimSpace(string(val)) == "null"
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return fail("invalid type: expected a JSON object")
	}
	for _, k := range required {
		if missing(top, k) {
			return fail(fmt.Sprintf("missing field `%s`", k))
		}
	}
	var dest map[string]json.RawMessage
	if err := json.Unmarshal(top["destination"], &dest); err != nil || dest == nil {
		return fail("destination: invalid type: expected a JSON object")
	}
	if missing(dest, "type") {
		return fail("destination: missing field `type`")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fail(err.Error())
	}
	return true
}

func remoteBackupOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

// remoteBackupS3Fields pulls the required S3 fields, answering 400 for the
// first missing one.
func remoteBackupS3Fields(w http.ResponseWriter, d *RemoteBackupDestinationConfig) (bucket, endpoint, access, secret string, ok bool) {
	for _, f := range []struct {
		v    *string
		name string
	}{{d.Bucket, "bucket"}, {d.Endpoint, "endpoint"}, {d.AccessKey, "access_key"}, {d.SecretKey, "secret_key"}} {
		if f.v == nil {
			writeErr(w, http.StatusBadRequest, "Missing "+f.name)
			return "", "", "", "", false
		}
	}
	return *d.Bucket, *d.Endpoint, *d.AccessKey, *d.SecretKey, true
}

func remoteBackupSftpFields(w http.ResponseWriter, d *RemoteBackupDestinationConfig) (host string, port uint16, user, remotePath string, ok bool) {
	if d.Host == nil {
		writeErr(w, http.StatusBadRequest, "Missing host")
		return "", 0, "", "", false
	}
	port = 22
	if d.Port != nil {
		port = *d.Port
	}
	if d.Username == nil {
		writeErr(w, http.StatusBadRequest, "Missing username")
		return "", 0, "", "", false
	}
	return *d.Host, port, *d.Username, remoteBackupOr(d.RemotePath, "/backups"), true
}

// remoteBackupUpload: POST /backups/upload — upload a local backup file.
func remoteBackupUpload(w http.ResponseWriter, r *http.Request) {
	var body RemoteBackupUploadRequest
	if !remoteBackupDecode(w, r, &body, "filepath", "destination") {
		return
	}
	// The prefix check alone is LEXICAL — "/var/backups/dockpanel/../../etc/
	// shadow" passes it and the OS resolves the "..". ProtectSystem=strict
	// blocks writes, not reads, so an unguarded path here would exfiltrate any
	// root-readable file to an attacker-supplied destination.
	if !strings.HasPrefix(body.Filepath, "/var/backups/dockpanel/") || strings.Contains(body.Filepath, "..") {
		writeErr(w, http.StatusBadRequest, "Invalid backup filepath")
		return
	}
	d := &body.Destination
	switch d.Dtype {
	case "s3":
		bucket, endpoint, access, secret, ok := remoteBackupS3Fields(w, d)
		if !ok {
			return
		}
		url, err := services.RemoteBackupUploadS3(body.Filepath, bucket, remoteBackupOr(d.Region, "us-east-1"), endpoint, access, secret, remoteBackupOr(d.PathPrefix, ""))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "url": url})
	case "sftp":
		host, port, user, remotePath, ok := remoteBackupSftpFields(w, d)
		if !ok {
			return
		}
		dest, err := services.RemoteBackupUploadSftp(body.Filepath, host, port, user, d.Password, d.KeyPath, remotePath)
		if err != nil {
			// A scheduled upload runs unattended, so the body IS the whole
			// message an operator gets: a missing package is a 4xx precondition,
			// not "your agent broke".
			status := http.StatusInternalServerError
			if err.Error() == services.RemoteBackupSshpassMissing {
				status = http.StatusFailedDependency
			}
			writeErr(w, status, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "destination": dest})
	default:
		writeErr(w, http.StatusBadRequest, "Unknown destination type: "+d.Dtype)
	}
}

// remoteBackupTestDestination: POST /backups/test-destination.
func remoteBackupTestDestination(w http.ResponseWriter, r *http.Request) {
	var body RemoteBackupTestRequest
	if !remoteBackupDecode(w, r, &body, "destination") {
		return
	}
	d := &body.Destination
	switch d.Dtype {
	case "s3":
		bucket, endpoint, access, secret, ok := remoteBackupS3Fields(w, d)
		if !ok {
			return
		}
		// Same defaults as upload, so the test probes where backups will go.
		if err := services.RemoteBackupTestS3(bucket, remoteBackupOr(d.Region, "us-east-1"), endpoint, access, secret, remoteBackupOr(d.PathPrefix, "")); err != nil {
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "S3 connection successful"})
	case "sftp":
		host, port, user, remotePath, ok := remoteBackupSftpFields(w, d)
		if !ok {
			return
		}
		if err := services.RemoteBackupTestSftp(host, port, user, d.Password, d.KeyPath, remotePath); err != nil {
			// The panel keeps a 4xx body and replaces a 5xx body with an
			// incident id — so a missing package must be 4xx.
			status := http.StatusBadGateway
			if err.Error() == services.RemoteBackupSshpassMissing {
				status = http.StatusFailedDependency
			}
			writeErr(w, status, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "SFTP connection successful"})
	default:
		writeErr(w, http.StatusBadRequest, "Unknown type: "+d.Dtype)
	}
}

// remoteBackupPrune: POST /backups/prune — delete old remote backups, keep
// the N newest. S3 only.
func remoteBackupPrune(w http.ResponseWriter, r *http.Request) {
	var body RemoteBackupPruneRequest
	if !remoteBackupDecode(w, r, &body, "destination", "domain", "retention") {
		return
	}
	d := &body.Destination
	if d.Dtype != "s3" {
		// SFTP pruning would need an SSH client to list+delete remote files;
		// not implemented, prune on the remote server.
		slog.Warn(fmt.Sprintf("Backup pruning skipped for %s destination (domain: %s). Only S3/R2 pruning is supported. "+
			"SFTP backups for '%s' must be pruned manually on the remote server.", d.Dtype, body.Domain, body.Domain))
		writeJSON(w, http.StatusOK, map[string]any{
			"pruned": 0,
			"message": fmt.Sprintf("Automatic pruning is not supported for %s destinations. "+
				"Old backups for '%s' must be pruned manually on the remote server.", d.Dtype, body.Domain),
		})
		return
	}
	bucket, endpoint, access, secret, ok := remoteBackupS3Fields(w, d)
	if !ok {
		return
	}
	region := remoteBackupOr(d.Region, "us-east-1")
	keys, err := services.RemoteBackupListS3(bucket, region, endpoint, access, secret, remoteBackupOr(d.PathPrefix, ""))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// This domain's backups, newest first (timestamps sort lexicographically).
	prefix := body.Domain + "-"
	var mine []string
	for _, k := range keys {
		f := k[strings.LastIndex(k, "/")+1:]
		if strings.HasPrefix(f, prefix) && strings.HasSuffix(f, ".tar.gz") {
			mine = append(mine, k)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(mine)))
	pruned := 0
	if uint(len(mine)) > body.Retention {
		for _, k := range mine[body.Retention:] {
			if err := services.RemoteBackupDeleteS3(bucket, region, endpoint, access, secret, k); err != nil {
				slog.Warn(fmt.Sprintf("Failed to prune %s: %v", k, err))
			} else {
				pruned++
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"pruned": pruned, "total": len(mine)})
}
