package api

// Port of panel/backend/src/routes/files.rs — the file manager.

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

func rtFilesRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/sites/{id}/files", h(rtFilesListDir))
	r.Handle("DELETE /api/sites/{id}/files", h(rtFilesDeleteEntry))
	r.Handle("GET /api/sites/{id}/files/read", h(rtFilesReadFile))
	r.Handle("GET /api/sites/{id}/files/download", h(rtFilesDownloadFile))
	r.Handle("PUT /api/sites/{id}/files/write", h(rtFilesWriteFile))
	r.Handle("POST /api/sites/{id}/files/upload", h(rtFilesUploadFile))
	r.Handle("POST /api/sites/{id}/files/create", h(rtFilesCreateEntry))
	r.Handle("POST /api/sites/{id}/files/rename", h(rtFilesRenameEntry))
}

// rtFilesUploadMaxFileBytes is the largest file the file manager accepts.
//
// A DERIVED number, not a policy choice. An upload is base64-encoded into a
// JSON body capped at 2 MiB (axum's default) on this hop AND on the panel to
// agent hop; base64 costs a third, so 2 MiB of body carries ~1.57 MB of file,
// and the path and filename travel in the same body.
//
// ⚠ RAISING THIS IS NOT A ONE-LINE CHANGE. First: both hops' body limits go
// up per-route (never globally — that hands every unauthenticated caller the
// same buffered allocation); there is a per-site disk quota (there is none);
// and the transport stops being base64-in-JSON (buffered in RAM on both
// hops). Large files: streaming intake; docs/guides/file-uploads.md points at
// rsync. Every surface that states a size must state this one —
// upload-refusal-pin-e2e.sh pins that they agree.
const rtFilesUploadMaxFileBytes = 1_500_000

// rtFilesUploadTooLarge is the one sentence both refusals share — the
// body-limit rejection and the decoded-size check — so the operator cannot
// get two accounts of the same limit.
func rtFilesUploadTooLarge() error {
	return apiErrCoded(http.StatusRequestEntityTooLarge,
		fmt.Sprintf("File is too large for the file manager (limit %.1f MB). Copy it "+
			"with rsync or scp over the server's own SSH, or use the Migration "+
			"wizard to move a whole site.", float64(rtFilesUploadMaxFileBytes)/1_000_000.0),
		CodePayloadTooLarge)
}

// rtFilesExceedsUploadLimit reports whether a base64 payload carries more than
// the file manager accepts. Deliberately an UPPER bound: padding means the true
// decoded length can be up to two bytes less, so a payload within two bytes of
// the limit is refused — rounding against the uploader is the safe direction.
func rtFilesExceedsUploadLimit(content string) bool {
	return len(content)/4*3 > rtFilesUploadMaxFileBytes
}

// rtFilesUploadRejection turns an extractor rejection into an answer the
// operator can act on, keyed on the STATUS (413 = body too big).
func rtFilesUploadRejection(err error) error {
	var pe *plainError
	if errors.As(err, &pe) && pe.Status == http.StatusRequestEntityTooLarge {
		return rtFilesUploadTooLarge()
	}
	msg := err.Error()
	if pe != nil {
		msg = pe.Msg
	}
	return apiErr(http.StatusBadRequest, "Invalid upload request: "+msg)
}

type rtFilesUploadBody struct {
	Path     string `json:"path"`
	Content  string `json:"content"`
	Filename string `json:"filename"`
}

type rtFilesPathQuery struct {
	Path      *string `json:"path"`
	EntryType *string `json:"type"`
}

type rtFilesWriteBody struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type rtFilesRenameBody struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// rtFilesQueryCall is the shared prologue of the ?path= handlers: auth, path,
// query, then the site's own agent.
func rtFilesQueryCall(st *AppState, r *http.Request) (string, AgentHandle, rtFilesPathQuery, error) {
	var q rtFilesPathQuery
	c, err := st.authUser(r)
	if err != nil {
		return "", nil, q, err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return "", nil, q, err
	}
	if err := decodeQuery(r, &q); err != nil {
		return "", nil, q, err
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	return domain, agent, q, err
}

// rtFilesRequiredPath validates a required ?path=.
func rtFilesRequiredPath(q rtFilesPathQuery) (string, error) {
	rel := rtLogsOr(q.Path, "")
	if rel == "" {
		return "", apiErr(http.StatusBadRequest, "path is required")
	}
	if !isSafeRelativePath(rel) {
		return "", apiErr(http.StatusBadRequest, "Invalid path")
	}
	return rel, nil
}

// rtFilesListDir is GET /api/sites/{id}/files?path=
func rtFilesListDir(st *AppState, w http.ResponseWriter, r *http.Request) error {
	domain, agent, q, err := rtFilesQueryCall(st, r)
	if err != nil {
		return err
	}
	rel := rtLogsOr(q.Path, ".")
	if rel != "." && !isSafeRelativePath(rel) {
		return apiErr(http.StatusBadRequest, "Invalid path")
	}
	res, err := agent.Get(r.Context(), fmt.Sprintf("/files/%s/list?path=%s", domain, rtLogsURLEncode(rel)))
	if err != nil {
		return agentError("File manager", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtFilesReadFile is GET /api/sites/{id}/files/read?path=
func rtFilesReadFile(st *AppState, w http.ResponseWriter, r *http.Request) error {
	domain, agent, q, err := rtFilesQueryCall(st, r)
	if err != nil {
		return err
	}
	rel, err := rtFilesRequiredPath(q)
	if err != nil {
		return err
	}
	res, err := agent.Get(r.Context(), fmt.Sprintf("/files/%s/read?path=%s", domain, rtLogsURLEncode(rel)))
	if err != nil {
		return agentError("File manager", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtFilesWriteFile is PUT /api/sites/{id}/files/write — { path, content }
func rtFilesWriteFile(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtFilesWriteBody
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if !isSafeRelativePath(body.Path) {
		return apiErr(http.StatusBadRequest, "Invalid path")
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	res, err := agent.Put(r.Context(), fmt.Sprintf("/files/%s/write", domain), map[string]any{"path": body.Path, "content": body.Content})
	if err != nil {
		return agentError("File manager", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtFilesCreateEntry is POST /api/sites/{id}/files/create?path=&type=file|dir
func rtFilesCreateEntry(st *AppState, w http.ResponseWriter, r *http.Request) error {
	domain, agent, q, err := rtFilesQueryCall(st, r)
	if err != nil {
		return err
	}
	entryType := rtLogsOr(q.EntryType, "file")
	rel, err := rtFilesRequiredPath(q)
	if err != nil {
		return err
	}
	if entryType != "file" && entryType != "dir" {
		return apiErr(http.StatusBadRequest, "type must be file or dir")
	}
	res, err := agent.Post(r.Context(), fmt.Sprintf("/files/%s/create?path=%s&type=%s", domain, rtLogsURLEncode(rel), entryType), nil)
	if err != nil {
		return agentError("File manager", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtFilesRenameEntry is POST /api/sites/{id}/files/rename — { from, to }
func rtFilesRenameEntry(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtFilesRenameBody
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if !isSafeRelativePath(body.From) || !isSafeRelativePath(body.To) {
		return apiErr(http.StatusBadRequest, "Invalid path")
	}
	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), fmt.Sprintf("/files/%s/rename", domain), map[string]any{"from": body.From, "to": body.To})
	if err != nil {
		return agentError("File manager", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtFilesDeleteEntry is DELETE /api/sites/{id}/files?path=
func rtFilesDeleteEntry(st *AppState, w http.ResponseWriter, r *http.Request) error {
	domain, agent, q, err := rtFilesQueryCall(st, r)
	if err != nil {
		return err
	}
	rel, err := rtFilesRequiredPath(q)
	if err != nil {
		return err
	}
	res, err := agent.Delete(r.Context(), fmt.Sprintf("/files/%s/delete?path=%s", domain, rtLogsURLEncode(rel)))
	if err != nil {
		return agentError("File manager", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtFilesDownloadFile is GET /api/sites/{id}/files/download?path=
func rtFilesDownloadFile(st *AppState, w http.ResponseWriter, r *http.Request) error {
	domain, agent, q, err := rtFilesQueryCall(st, r)
	if err != nil {
		return err
	}
	rel, err := rtFilesRequiredPath(q)
	if err != nil {
		return err
	}
	b, cd, err := agent.GetBytes(r.Context(), fmt.Sprintf("/files/%s/download?path=%s", domain, rtLogsURLEncode(rel)))
	if err != nil {
		return agentError("File download", err)
	}
	disposition := ""
	if cd != nil {
		disposition = *cd
	} else {
		// Sanitize exactly as the agent does (strip quote/backslash/CR/LF) so a
		// filename cannot break out of the quoted-string. This fallback fires
		// whenever the agent's own header is undecodable (e.g. a non-ASCII
		// filename), so the two paths must stay consistent.
		name := rel[strings.LastIndex(rel, "/")+1:]
		name = strings.NewReplacer(`"`, "", `\`, "", "\n", "", "\r", "").Replace(name)
		disposition = fmt.Sprintf("attachment; filename=\"%s\"", name)
	}
	w.Header().Set("Content-Disposition", disposition)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
	return nil
}

// rtFilesUploadFile is POST /api/sites/{id}/files/upload.
func rtFilesUploadFile(st *AppState, w http.ResponseWriter, r *http.Request) error {
	c, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	// Taking the REJECTION rather than letting it short-circuit is the point:
	// the body limit refuses an oversize upload in plain text no client of ours
	// can render, so the operator was told nothing at all (#121).
	var body rtFilesUploadBody
	if err := decodeJSON(r, &body); err != nil {
		return rtFilesUploadRejection(err)
	}

	if strings.Contains(body.Path, "..") || strings.HasPrefix(body.Path, "/") {
		return apiErr(http.StatusBadRequest, "Invalid path")
	}
	if !isSafeRelativePath(body.Filename) && body.Filename != "." {
		if strings.Contains(body.Filename, "..") || strings.Contains(body.Filename, "/") {
			return apiErr(http.StatusBadRequest, "Invalid filename")
		}
	}

	// Bounded twice: by the body limit, and here on the DECODED size — the
	// number the operator thinks in. This used to read 100 MB and could never
	// fire against a ~2 MiB body limit.
	if rtFilesExceedsUploadLimit(body.Content) {
		return rtFilesUploadTooLarge()
	}

	// Advisory hygiene only — NOT a security boundary. Tenant isolation is the
	// per-site PHP-FPM pool + site-root confinement; a tenant legitimately runs
	// their own code in their own webroot, so this is deliberately not
	// replicated on write/create.
	lower := strings.ToLower(body.Filename)
	if slices.ContainsFunc([]string{".phar", ".pht", ".phtml", ".shtml", ".htaccess"}, func(ext string) bool { return strings.HasSuffix(lower, ext) }) {
		return apiErr(http.StatusBadRequest, "File type not allowed (dangerous extension)")
	}

	domain, agent, err := siteAgentForCaller(r.Context(), st, id, c)
	if err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), fmt.Sprintf("/files/%s/upload", domain), map[string]any{
		"path": body.Path, "content": body.Content, "filename": body.Filename,
	})
	if err != nil {
		return agentError("File upload", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}
