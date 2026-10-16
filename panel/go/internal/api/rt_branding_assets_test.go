package api

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestRtBrandingAssetsValidLogoFilename(t *testing.T) {
	for _, ok := range []string{"logo-abcdef01.png", "logo-AB.jpeg", "logo-0.webp", "logo-1.jpg"} {
		if !rtBrandingAssetsValidLogoFilename(ok) {
			t.Fatal(ok)
		}
	}
	for _, bad := range []string{"logo-.png", "logo-xyz.png", "logo-ab.gif", "../logo-ab.png", "logo-ab/../x.png", "logo-ab", "x-ab.png", "logo-a.b.png"} {
		if rtBrandingAssetsValidLogoFilename(bad) {
			t.Fatal(bad)
		}
	}
}

func TestRtBrandingAssetsDetectImageKind(t *testing.T) {
	if rtBrandingAssetsDetectImageKind([]byte("\x89PNG\r\n\x1a\nrest")) != "png" ||
		rtBrandingAssetsDetectImageKind([]byte("\xFF\xD8\xFFx")) != "jpeg" ||
		rtBrandingAssetsDetectImageKind([]byte("RIFF\x00\x00\x00\x00WEBPx")) != "webp" ||
		rtBrandingAssetsDetectImageKind([]byte("<svg")) != "" {
		t.Fatal()
	}
}

// Content-Type and magic bytes must agree; an upload lands under its hash.
func TestRtBrandingAssetsUploadChecksMagic(t *testing.T) {
	st := testState()
	rtBrandingAssetsDir = t.TempDir()
	tok := mint(t, freshClaims("admin"))
	up := func(ct string, body []byte) int {
		r := httptest.NewRequest("POST", "/api/branding/logo", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		w := httptest.NewRecorder()
		if err := rtBrandingAssetsUploadLogo(st, w, r); err != nil {
			writeError(w, err)
		}
		return w.Code
	}
	if up("image/png", []byte("<svg onload=alert(1)>")) != 400 || up("image/jpeg", []byte("\x89PNG\r\n\x1a\n")) != 400 || up("image/png", nil) != 400 {
		t.Fatal("mismatch must be refused")
	}
}
