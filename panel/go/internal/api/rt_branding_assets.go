package api

// Port of panel/backend/src/routes/branding_assets.rs — logo upload/serve.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

var rtBrandingAssetsDir = "/var/lib/dockpanel/branding"

const rtBrandingAssetsMaxLogoBytes = 2 * 1024 * 1024

type rtBrandingAssetsLogoUploadResponse struct {
	LogoURL string `json:"logo_url"`
}

func rtBrandingAssetsRegister(r *Router) {
	st := r.St
	r.Handle("POST /api/branding/logo", func(w http.ResponseWriter, req *http.Request) error {
		return rtBrandingAssetsUploadLogo(st, w, req)
	})
	r.Handle("GET /api/branding/logo/{filename}", func(w http.ResponseWriter, req *http.Request) error {
		return rtBrandingAssetsGetLogo(w, req)
	})
}

// rtBrandingAssetsUploadLogo — POST /api/branding/logo: admin-only image
// upload.
//
// Body: raw image bytes. Content-Type must be one of the allowed types, and
// the magic bytes are checked too so a caller cannot send arbitrary content
// labelled image/png. Returns the relative URL the caller then writes to the
// logo_url setting via PUT /api/settings.
func rtBrandingAssetsUploadLogo(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	// The Bytes extractor: axum's 2 MB default body limit.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(body) > maxJSONBody {
		return rejection(http.StatusRequestEntityTooLarge, "Failed to buffer the request body: length limit exceeded")
	}
	if len(body) == 0 {
		return apiErr(http.StatusBadRequest, "Empty body")
	}
	if len(body) > rtBrandingAssetsMaxLogoBytes {
		return apiErr(http.StatusRequestEntityTooLarge, "Logo too large (max 2 MB)")
	}

	ct := r.Header.Get("Content-Type")
	ct, _, _ = strings.Cut(ct, ";")
	ct = strings.ToLower(strings.TrimSpace(ct))

	kind := rtBrandingAssetsDetectImageKind(body)
	var ext string
	switch {
	case ct == "image/png" && kind == "png":
		ext = "png"
	case (ct == "image/jpeg" || ct == "image/jpg") && kind == "jpeg":
		ext = "jpg"
	case ct == "image/webp" && kind == "webp":
		ext = "webp"
	case ct == "" && kind != "":
		ext = map[string]string{"png": "png", "jpeg": "jpg", "webp": "webp"}[kind]
	default:
		return apiErr(http.StatusBadRequest, "Content-Type must be image/png, image/jpeg, or image/webp and match the file's actual format")
	}

	if err := os.MkdirAll(rtBrandingAssetsDir, 0o755); err != nil {
		return internalError("upload_logo: create dir", err)
	}
	digest := sha256.Sum256(body)
	filename := fmt.Sprintf("logo-%x.%s", digest[:8], ext)
	if err := os.WriteFile(rtBrandingAssetsDir+"/"+filename, body, 0o644); err != nil {
		return internalError("upload_logo: write file", err)
	}

	details := fmt.Sprintf("bytes=%d", len(body))
	ActivityLogActivity(r.Context(), st.DB, claims.Sub, claims.Email, "branding.logo.upload", new("branding"), &filename, &details, nil, claims.KeyID)

	slog.Info(fmt.Sprintf("Branding logo uploaded by %s: %s", claims.Email, filename))
	writeJSON(w, http.StatusOK, rtBrandingAssetsLogoUploadResponse{LogoURL: "/api/branding/logo/" + filename})
	return nil
}

// rtBrandingAssetsGetLogo — GET /api/branding/logo/{filename}: public read.
// No auth: the (unauthenticated) login page renders the logo. The filename is
// restricted to the logo-<hash>.<ext> shape, so no path traversal.
func rtBrandingAssetsGetLogo(w http.ResponseWriter, r *http.Request) error {
	filename := r.PathValue("filename")
	if !rtBrandingAssetsValidLogoFilename(filename) {
		return apiErr(http.StatusNotFound, "Not found")
	}
	b, err := os.ReadFile(rtBrandingAssetsDir + "/" + filename)
	if errors.Is(err, fs.ErrNotExist) {
		return apiErr(http.StatusNotFound, "Not found")
	}
	if err != nil {
		return internalError("get_logo: read file", err)
	}
	ct := "application/octet-stream"
	switch filename[strings.LastIndex(filename, ".")+1:] {
	case "png":
		ct = "image/png"
	case "jpg", "jpeg":
		ct = "image/jpeg"
	case "webp":
		ct = "image/webp"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
	return nil
}

func rtBrandingAssetsValidLogoFilename(name string) bool {
	if !strings.HasPrefix(name, "logo-") {
		return false
	}
	dot := strings.LastIndex(name, ".")
	if dot < 5 {
		return false
	}
	stem, ext := name[5:dot], name[dot+1:]
	if stem == "" || !rtSettingsAllHex(stem) {
		return false
	}
	switch ext {
	case "png", "jpg", "jpeg", "webp":
		return true
	}
	return false
}

func rtBrandingAssetsDetectImageKind(b []byte) string {
	switch {
	case len(b) >= 8 && bytes.Equal(b[:8], []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case len(b) >= 3 && bytes.Equal(b[:3], []byte("\xFF\xD8\xFF")):
		return "jpeg"
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return "webp"
	}
	return ""
}
