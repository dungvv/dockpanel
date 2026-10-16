package routes

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// sbomStatus: GET /sbom/status — whether the syft binary is installed.
func sbomStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"installed": services.SbomScannerIsInstalled(), "scanner": "syft"})
}

// sbomInstall: POST /sbom/install — install syft.
func sbomInstall(w http.ResponseWriter, r *http.Request) {
	if err := services.SbomScannerInstallSyft(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "syft installed"})
}

// sbomUninstall: POST /sbom/uninstall — remove the syft binary.
func sbomUninstall(w http.ResponseWriter, _ *http.Request) {
	if err := services.SbomScannerUninstallSyft(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "syft removed"})
}

// sbomScan: POST /sbom/scan — generate an SPDX SBOM for an image. Returns the
// raw SPDX document inside {"image": …, "spdx": <object>} so the backend can
// persist it without re-parsing.
func sbomScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Image string `json:"image"`
	}
	if !nginxDecodeStrict(w, r, &body, "image") {
		return
	}
	spdx, err := services.SbomScannerGenerateSbom(r.Context(), body.Image)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Decoded to a generic value (numbers kept verbatim) and re-encoded, as
	// serde_json::Value did — object keys come out sorted.
	var parsed any
	dec := json.NewDecoder(strings.NewReader(spdx))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		writeErr(w, http.StatusInternalServerError, "parse SPDX: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"image": body.Image, "spdx": parsed})
}

func registerSbom(r *Router) {
	r.Handle("GET /sbom/status", sbomStatus)
	r.Handle("POST /sbom/install", sbomInstall)
	r.Handle("POST /sbom/uninstall", sbomUninstall)
	r.Handle("POST /sbom/scan", sbomScan)
}
