package routes

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// Every handler here took serde_json::Value and answered errors as
// (StatusCode, String) — plain-text bodies, kept.

func registerMigration(r *Router) {
	r.Handle("POST /migration/fetch", migrationFetch)
	r.Handle("POST /migration/analyze", migrationAnalyze)
	r.Handle("POST /migration/import-site", migrationImportSite)
	r.Handle("POST /migration/import-database", migrationImportDatabase)
	r.Handle("POST /migration/cleanup", migrationCleanup)
}

// migrationStr is `body[key].as_str()`.
func migrationStr(body any, key string) (string, bool) {
	s, ok := nginxField(body, key).(string)
	return s, ok
}

// migrationRequire answers 400 "<key> required" when key is not a string.
func migrationRequire(w http.ResponseWriter, body any, keys ...string) ([]string, bool) {
	out := make([]string, len(keys))
	for i, k := range keys {
		s, ok := migrationStr(body, k)
		if !ok {
			nginxPlain(w, http.StatusBadRequest, k+" required")
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func migrationOr(body any, key, def string) string {
	if s, ok := migrationStr(body, key); ok {
		return s
	}
	return def
}

// migrationFetch: POST /migration/fetch — download an archive into the
// /var/backups/dockpanel tree analyze already trusts, instead of SFTP.
func migrationFetch(w http.ResponseWriter, r *http.Request) {
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	v, ok := migrationRequire(w, body, "url", "dest")
	if !ok {
		return
	}
	url, dest := v[0], v[1]
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		nginxPlain(w, http.StatusBadRequest, "Only http:// and https:// URLs are supported")
		return
	}
	if err := services.SsrfGuardValidateRepoURLNotInternal(url); err != nil {
		nginxPlain(w, http.StatusBadRequest, "URL rejected: "+err.Error())
		return
	}
	// Reject traversal, then require the resolved directory (the file does
	// not exist yet) to still be inside the one subtree this unit can write.
	if strings.Contains(dest, "..") || strings.Contains(dest, "\x00") {
		nginxPlain(w, http.StatusBadRequest, "Path traversal not allowed")
		return
	}
	if !strings.HasPrefix(dest, services.MigrationFetchDir+"/") {
		nginxPlain(w, http.StatusBadRequest, "Destination must be within "+services.MigrationFetchDir+"/")
		return
	}
	if canon, err := filepath.EvalSymlinks(filepath.Dir(dest)); err == nil {
		if canon != services.MigrationFetchDir && !strings.HasPrefix(canon, services.MigrationFetchDir+"/") {
			nginxPlain(w, http.StatusBadRequest, "Resolved path not in allowed directories")
			return
		}
	}
	n, err := services.MigrationFetchArchive(context.WithoutCancel(r.Context()), url, dest)
	if err != nil {
		nginxPlain(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": dest, "bytes": n})
}

// migrationAnalyze: POST /migration/analyze — extract and analyze a backup.
func migrationAnalyze(w http.ResponseWriter, r *http.Request) {
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	v, ok := migrationRequire(w, body, "path")
	if !ok {
		return
	}
	path, source := v[0], migrationOr(body, "source", "cpanel")
	if strings.Contains(path, "..") || strings.Contains(path, "\x00") {
		nginxPlain(w, http.StatusBadRequest, "Path traversal not allowed")
		return
	}
	// ⚠ NOT /tmp, and the message must not offer it: the unit runs with
	// PrivateTmp=yes, so an archive in the host's /tmp is simply not there and
	// the next line would answer "File not found" for a file plainly on disk.
	if !strings.HasPrefix(path, "/var/backups/") {
		nginxPlain(w, http.StatusBadRequest, "Path must be within /var/backups/ — copy the archive there. (/tmp cannot be used: the agent runs with a private /tmp and cannot see the host's.)")
		return
	}
	canon, err := filepath.EvalSymlinks(path)
	if err == nil {
		canon, err = filepath.Abs(canon)
	}
	if err != nil {
		nginxPlain(w, http.StatusBadRequest, "File not found: "+path)
		return
	}
	if !strings.HasPrefix(canon, "/var/backups/") {
		nginxPlain(w, http.StatusBadRequest, "Resolved path not in allowed directories")
		return
	}
	inv, err := services.MigrationAnalyze(context.WithoutCancel(r.Context()), path, source)
	if err != nil {
		nginxPlain(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

// migrationImportSite: POST /migration/import-site.
func migrationImportSite(w http.ResponseWriter, r *http.Request) {
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	v, ok := migrationRequire(w, body, "migration_id", "domain", "source_dir")
	if !ok {
		return
	}
	// Defaults to the arm put_site takes for anything unrecognised, so an
	// older panel lands files where a static/PHP vhost looks.
	runtime := migrationOr(body, "runtime", "php")
	msg, err := services.MigrationImportSiteFiles(context.WithoutCancel(r.Context()), v[0], v[1], v[2], runtime)
	if err != nil {
		nginxPlain(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

// migrationImportDatabase: POST /migration/import-database.
func migrationImportDatabase(w http.ResponseWriter, r *http.Request) {
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	v, ok := migrationRequire(w, body, "migration_id", "sql_file", "container_name", "db_name")
	if !ok {
		return
	}
	engine, user := migrationOr(body, "engine", "mysql"), migrationOr(body, "user", "root")
	pw, ok := migrationRequire(w, body, "password")
	if !ok {
		return
	}
	msg, err := services.MigrationImportDatabase(context.WithoutCancel(r.Context()), v[0], v[1], v[2], v[3], engine, user, pw[0])
	if err != nil {
		nginxPlain(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

// migrationCleanup: POST /migration/cleanup — remove the extraction dir.
func migrationCleanup(w http.ResponseWriter, r *http.Request) {
	body, ok := nginxDecodeValue(w, r)
	if !ok {
		return
	}
	v, ok := migrationRequire(w, body, "migration_id")
	if !ok {
		return
	}
	if err := services.MigrationCleanup(v[0]); err != nil {
		nginxPlain(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
