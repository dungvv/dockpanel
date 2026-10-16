package routes

import (
	"net/http"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// imageScanStatus: GET /image-scan/status — whether the scanner binary is
// installed.
func imageScanStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"installed": services.ImageScannerIsInstalled(), "scanner": "grype"})
}

// imageScanInstall: POST /image-scan/install — install grype.
func imageScanInstall(w http.ResponseWriter, r *http.Request) {
	if err := services.ImageScannerInstallGrype(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "grype installed and vulnerability database primed"})
}

// imageScanUninstall: POST /image-scan/uninstall — remove grype and its cache.
func imageScanUninstall(w http.ResponseWriter, _ *http.Request) {
	if err := services.ImageScannerUninstallGrype(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "grype removed"})
}

// imageScanScan: POST /image-scan/scan — scan a single Docker image.
func imageScanScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Image string `json:"image"`
	}
	if !nginxDecodeStrict(w, r, &body, "image") {
		return
	}
	result, err := services.ImageScannerScanImage(r.Context(), body.Image)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func registerImageScan(r *Router) {
	r.Handle("GET /image-scan/status", imageScanStatus)
	r.Handle("POST /image-scan/install", imageScanInstall)
	r.Handle("POST /image-scan/uninstall", imageScanUninstall)
	r.Handle("POST /image-scan/scan", imageScanScan)
}
