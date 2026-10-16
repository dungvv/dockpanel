package api

// Port of panel/backend/src/routes/sboms.rs — per-image SBOM (SPDX 2.3 JSON).
//
// Companion to image_scans: that module reports vulnerabilities (what is
// broken); this one reports composition (what is installed). Same agent
// install pattern, distinct modules so the UI can wire them independently.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtSbomsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/sbom/settings", h(rtSbomsGetSettings))
	r.Handle("POST /api/sbom/install", h(rtSbomsInstallScanner))
	r.Handle("POST /api/sbom/uninstall", h(rtSbomsUninstallScanner))
	r.Handle("POST /api/sbom/generate", h(rtSbomsGenerate))
	// Wildcard, not a single segment: an image reference contains slashes
	// (`ghcr.io/org/app:v1`), so a single segment matched only the bare
	// `name:tag` shape and 404'd for most of the catalogue.
	r.Handle("GET /api/sbom/image/{image...}", h(rtSbomsGetImageSbom))
	r.Handle("GET /api/apps/{name}/sbom", h(rtSbomsDownloadAppSbom))
	r.Handle("POST /api/apps/{name}/sbom", h(rtSbomsGenerateApp))
}

type rtSbomsSbomSettings struct {
	Installed bool `json:"installed"`
}

type rtSbomsGenerateRequest struct {
	Image string `json:"image"`
}

// rtSbomsGetSettings is GET /api/sbom/settings — whether syft is installed.
func rtSbomsGetSettings(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	installed := false
	if v, err := agent.Get(r.Context(), "/sbom/status"); err == nil {
		installed, _ = jsonBool(jsonGet(v, "installed"))
	}
	writeJSON(w, http.StatusOK, rtSbomsSbomSettings{Installed: installed})
	return nil
}

// rtSbomsInstallScanner is POST /api/sbom/install.
func rtSbomsInstallScanner(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	res, err := agent.PostLong(r.Context(), "/sbom/install", nil, 300)
	if err != nil {
		return agentError("install syft", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtSbomsUninstallScanner is POST /api/sbom/uninstall.
func rtSbomsUninstallScanner(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	_, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	res, err := agent.Post(r.Context(), "/sbom/uninstall", nil)
	if err != nil {
		return agentError("uninstall syft", err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// rtSbomsGenerate is POST /api/sbom/generate — SBOM for an arbitrary image.
func rtSbomsGenerate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var body rtSbomsGenerateRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	spdx, err := rtSbomsGenerateAndStore(r.Context(), st.DB, serverID, agent, body.Image)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"image":        body.Image,
		"generated_at": ExtensionsRFC3339(time.Now()),
		"spdx":         spdx,
	})
	return nil
}

// rtSbomsGenerateApp is POST /api/apps/{name}/sbom — SBOM for an app's image.
func rtSbomsGenerateApp(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	image, err := rtImageScansResolveAppImage(r.Context(), agent, r.PathValue("name"))
	if err != nil {
		return err
	}
	if image == nil {
		return apiErr(http.StatusNotFound, "App not found or has no image")
	}
	spdx, err := rtSbomsGenerateAndStore(r.Context(), st.DB, serverID, agent, *image)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"image":        *image,
		"generated_at": ExtensionsRFC3339(time.Now()),
		"spdx":         spdx,
	})
	return nil
}

// rtSbomsDownloadAppSbom is GET /api/apps/{name}/sbom — the latest stored
// SBOM for the app's image as an SPDX JSON download.
func rtSbomsDownloadAppSbom(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, agent, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	name := r.PathValue("name")
	image, err := rtImageScansResolveAppImage(r.Context(), agent, name)
	if err != nil {
		return err
	}
	if image == nil {
		return apiErr(http.StatusNotFound, "App not found or has no image")
	}

	// The app was resolved on the scoped server; the document must be that
	// server's. The filename is built from the app name on THIS host, so an
	// unscoped read handed over another machine's SBOM under this label.
	spdx, err := queryScalarOpt[json.RawMessage](r.Context(), st.DB,
		"SELECT spdx FROM image_sbom WHERE server_id = $1 AND image = $2", serverID, *image)
	if err != nil {
		return internalError("fetch sbom", err)
	}
	if spdx == nil {
		return apiErr(http.StatusNotFound, "No SBOM generated for this image yet")
	}
	body, err := rtSbomsPretty(*spdx)
	if err != nil {
		return internalError("serialize sbom", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+rtSbomsSanitizeFilename(name)+`.spdx.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	return nil
}

// rtSbomsGetImageSbom is GET /api/sbom/image/{ref} — the latest stored SBOM
// for an arbitrary image reference, inline.
func rtSbomsGetImageSbom(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	image := r.PathValue("image")
	row, err := queryOpt[Tup2[json.RawMessage, time.Time]](r.Context(), st.DB,
		"SELECT spdx, generated_at FROM image_sbom WHERE server_id = $1 AND image = $2", serverID, image)
	if err != nil {
		return internalError("fetch sbom", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "No SBOM stored for this image")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"image":        image,
		"generated_at": ExtensionsRFC3339(row.B),
		"spdx":         row.A,
	})
	return nil
}

// ── Internal helpers ────────────────────────────────────────────────────

// rtSbomsSanitizeFilename disallows path separators and control characters
// in the download filename. App names are validated upstream, but this keeps
// Content-Disposition safe even if that constraint changes.
func rtSbomsSanitizeFilename(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// rtSbomsPretty is serde_json::to_vec_pretty of a Value: keys sorted (the
// Value map is a BTreeMap), two-space indent, numbers kept verbatim.
func rtSbomsPretty(raw json.RawMessage) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func rtSbomsGenerateAndStore(ctx context.Context, db *pgxpool.Pool, serverID uuid.UUID, agent AgentHandle, image string) (any, error) {
	response, err := agent.PostLong(ctx, "/sbom/scan", map[string]any{"image": image}, 240)
	if err != nil {
		return nil, agentError("generate sbom", err)
	}
	obj, _ := jsonObj(response)
	spdx, ok := obj["spdx"]
	if !ok {
		return nil, internalError("agent returned no spdx field", "missing field")
	}
	raw, _ := json.Marshal(spdx)

	// ⚠ The arbiter must name the CURRENT primary key, (server_id, image).
	// image_sbom used to be keyed on the bare image so two hosts' documents
	// overwrote each other; an arbiter naming no unique index does not fall
	// back — Postgres raises 42P10 and every generation would be a 500.
	if _, err := execSQL(ctx, db,
		"INSERT INTO image_sbom (server_id, image, format, spdx, generated_at) "+
			"VALUES ($1, $2, 'spdx-json', $3, NOW()) "+
			"ON CONFLICT (server_id, image) DO UPDATE "+
			"SET spdx = EXCLUDED.spdx, generated_at = NOW()",
		serverID, image, json.RawMessage(raw)); err != nil {
		return nil, internalError("store sbom", err)
	}
	return spdx, nil
}
