package routes

import (
	"context"
	"net/http"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

func registerStaging(r *Router) {
	r.Handle("POST /staging/clone", stagingClone)
	r.Handle("POST /staging/sync", stagingSync)
	r.Handle("POST /staging/delete-files", stagingDeleteFiles)
	r.Handle("POST /staging/disk-usage", stagingDiskUsage)
}

type stagingPairRequest struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type stagingDomainRequest struct {
	Domain string `json:"domain"`
}

// stagingDecodePair decodes and validates source/target.
func stagingDecodePair(w http.ResponseWriter, r *http.Request) (stagingPairRequest, bool) {
	var b stagingPairRequest
	if !nginxDecodeStrict(w, r, &b, "source", "target") {
		return b, false
	}
	if !isValidDomain(b.Source) {
		writeErr(w, http.StatusBadRequest, "Invalid source domain")
		return b, false
	}
	if !isValidDomain(b.Target) {
		writeErr(w, http.StatusBadRequest, "Invalid target domain")
		return b, false
	}
	return b, true
}

// stagingClone: POST /staging/clone — copy site files source → target.
func stagingClone(w http.ResponseWriter, r *http.Request) {
	b, ok := stagingDecodePair(w, r)
	if !ok {
		return
	}
	msg, err := services.StagingCloneFiles(context.WithoutCancel(r.Context()), b.Source, b.Target)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

// stagingSync: POST /staging/sync — backs both panel directions (sync AND
// push), neither of which pre-checks the directories, so a missing one is a
// 404 carrying the resolved path rather than a 5xx that hides it.
func stagingSync(w http.ResponseWriter, r *http.Request) {
	b, ok := stagingDecodePair(w, r)
	if !ok {
		return
	}
	msg, err := services.StagingSyncFiles(context.WithoutCancel(r.Context()), b.Source, b.Target)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "directory not found") {
			status = http.StatusNotFound
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

// stagingDeleteFiles: POST /staging/delete-files.
func stagingDeleteFiles(w http.ResponseWriter, r *http.Request) {
	var b stagingDomainRequest
	if !nginxDecodeStrict(w, r, &b, "domain") {
		return
	}
	if !isValidDomain(b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	if err := services.StagingDeleteSiteFiles(b.Domain); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// stagingDiskUsage: POST /staging/disk-usage.
func stagingDiskUsage(w http.ResponseWriter, r *http.Request) {
	var b stagingDomainRequest
	if !nginxDecodeStrict(w, r, &b, "domain") {
		return
	}
	if !isValidDomain(b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	n, err := services.StagingSiteDiskUsage(r.Context(), b.Domain)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bytes": n})
}
