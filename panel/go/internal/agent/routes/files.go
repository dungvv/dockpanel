package routes

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type filesRenameBody struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type filesWriteBody struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// filesStatus maps a file-service refusal to a 4xx the panel shows verbatim.
// As 5xx the panel replaced all of them with an incident id, so "New Folder"
// onto an existing name looked like an agent outage.
func filesStatus(w http.ResponseWriter, err error) {
	e := err.Error()
	status := http.StatusInternalServerError
	switch {
	case strings.HasPrefix(e, "File not found") || e == "Source does not exist" || e == "Path does not exist":
		status = http.StatusNotFound
	case e == "Path already exists" || e == "Destination already exists":
		status = http.StatusConflict
	case e == "File too large (max 2MB)":
		status = http.StatusRequestEntityTooLarge
	case e == "File is binary or not readable as text":
		status = http.StatusUnsupportedMediaType
	}
	writeErr(w, status, e)
}

// filesDomain validates the path domain, answering 400 itself.
func filesDomain(w http.ResponseWriter, r *http.Request) (string, bool) {
	d := r.PathValue("domain")
	if !isValidDomain(d) {
		writeErr(w, http.StatusBadRequest, "Invalid domain format")
		return "", false
	}
	return d, true
}

// filesRequiredPath returns ?path=, answering 400 when absent.
func filesRequiredPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	p := nginxQueryStr(r, "path")
	if p == nil {
		writeErr(w, http.StatusBadRequest, "path required")
		return "", false
	}
	return *p, true
}

func filesIsDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// filesList: GET /files/{domain}/list?path=.
func filesList(w http.ResponseWriter, r *http.Request) {
	domain, ok := filesDomain(w, r)
	if !ok {
		return
	}
	rel := "/"
	if p := nginxQueryStr(r, "path"); p != nil {
		rel = *p
	}
	safe, err := services.FilesResolveSafePath(domain, rel)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !filesIsDir(safe) {
		writeErr(w, http.StatusBadRequest, "Not a directory")
		return
	}
	entries, err := services.FilesListDirectory(safe, "/var/www/"+domain)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// filesRead: GET /files/{domain}/read?path=.
func filesRead(w http.ResponseWriter, r *http.Request) {
	domain, ok := filesDomain(w, r)
	if !ok {
		return
	}
	rel, ok := filesRequiredPath(w, r)
	if !ok {
		return
	}
	safe, err := services.FilesResolveSafePath(domain, rel)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	c, err := services.FilesReadFile(safe)
	if err != nil {
		filesStatus(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// filesWrite: PUT /files/{domain}/write.
func filesWrite(w http.ResponseWriter, r *http.Request) {
	var b filesWriteBody
	if !nginxDecodeStrict(w, r, &b, "path", "content") {
		return
	}
	domain, ok := filesDomain(w, r)
	if !ok {
		return
	}
	safe, err := services.FilesResolveSafePath(domain, b.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := services.FilesWriteFile(safe, b.Content); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// filesCreate: POST /files/{domain}/create?path=&type=.
func filesCreate(w http.ResponseWriter, r *http.Request) {
	domain, ok := filesDomain(w, r)
	if !ok {
		return
	}
	rel, ok := filesRequiredPath(w, r)
	if !ok {
		return
	}
	t := nginxQueryStr(r, "type")
	safe, err := services.FilesResolveSafePath(domain, rel)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := services.FilesCreateEntry(safe, t != nil && *t == "dir"); err != nil {
		filesStatus(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// filesRename: POST /files/{domain}/rename. The source may never be the
// site root (a destructive verb).
func filesRename(w http.ResponseWriter, r *http.Request) {
	var b filesRenameBody
	if !nginxDecodeStrict(w, r, &b, "from", "to") {
		return
	}
	domain, ok := filesDomain(w, r)
	if !ok {
		return
	}
	from, err := services.FilesResolveSafeChild(domain, b.From)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	to, err := services.FilesResolveSafePath(domain, b.To)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := services.FilesRenameEntry(from, to); err != nil {
		filesStatus(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// filesDelete: DELETE /files/{domain}/delete?path=.
func filesDelete(w http.ResponseWriter, r *http.Request) {
	domain, ok := filesDomain(w, r)
	if !ok {
		return
	}
	rel, ok := filesRequiredPath(w, r)
	if !ok {
		return
	}
	safe, err := services.FilesResolveSafeChild(domain, rel)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := services.FilesDeleteEntry(safe); err != nil {
		filesStatus(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// filesDownload: GET /files/{domain}/download?path= — streamed, never read
// whole: a site's webroot holds files far past the editor's 2MB cap, the
// route is reachable by the site's own non-admin owner, and the agent runs
// under a 512MB MemoryMax — one request could OOM-kill it.
func filesDownload(w http.ResponseWriter, r *http.Request) {
	domain, ok := filesDomain(w, r)
	if !ok {
		return
	}
	rel, ok := filesRequiredPath(w, r)
	if !ok {
		return
	}
	safe, err := services.FilesResolveSafePath(domain, rel)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if filesIsDir(safe) {
		writeErr(w, http.StatusBadRequest, "Cannot download a directory")
		return
	}
	f, err := os.Open(safe)
	if err != nil {
		writeErr(w, http.StatusNotFound, "File not found")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		writeErr(w, http.StatusNotFound, "File not found")
		return
	}
	name := filepath.Base(safe)
	if name == "" || name == "/" || name == "." {
		name = "download"
	}
	name = strings.NewReplacer(`"`, "", `\`, "", "\n", "", "\r", "").Replace(name)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// registerFiles mounts src/routes/files.rs.
func registerFiles(r *Router) {
	r.Handle("GET /files/{domain}/list", filesList)
	r.Handle("GET /files/{domain}/read", filesRead)
	r.Handle("GET /files/{domain}/download", filesDownload)
	r.Handle("PUT /files/{domain}/write", filesWrite)
	r.Handle("POST /files/{domain}/create", filesCreate)
	r.Handle("POST /files/{domain}/rename", filesRename)
	r.Handle("DELETE /files/{domain}/delete", filesDelete)
}
