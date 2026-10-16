package services

import "testing"

func TestParsesGrypeSeverities(t *testing.T) {
	json := `{
	  "matches": [
	    {"vulnerability":{"id":"CVE-1","severity":"Critical","description":"x","fix":{"versions":["1.2.3"]}},
	     "artifact":{"name":"libfoo","version":"1.2.0"}},
	    {"vulnerability":{"id":"CVE-2","severity":"High","fix":null},
	     "artifact":{"name":"libbar","version":"2.0.0"}},
	    {"vulnerability":{"id":"CVE-3","severity":"Negligible","fix":null},
	     "artifact":{"name":"libbaz","version":"0.1"}}
	  ]
	}`
	r, err := imageScannerParseGrypeOutput("nginx:latest", json)
	if err != nil {
		t.Fatal(err)
	}
	if r.CriticalCount != 1 || r.HighCount != 1 || r.LowCount != 1 { // Negligible folds into low
		t.Fatalf("%+v", r)
	}
	if len(r.Vulnerabilities) != 3 || r.Vulnerabilities[0].FixedVersion == nil || *r.Vulnerabilities[0].FixedVersion != "1.2.3" {
		t.Fatalf("%+v", r.Vulnerabilities)
	}
}

// Shared by both scanners: these would be caught at the handler boundary too.
func TestRejectsBadImageRefs(t *testing.T) {
	for _, b := range []string{"", "  ", "img;rm -rf /", "img$(whoami)", "img|cat"} {
		if imageScannerValidRef(b) == nil {
			t.Errorf("should reject: %q", b)
		}
	}
	for _, g := range []string{"nginx:latest", "ghcr.io/owner/repo:1.2.3", "image@sha256:abcd"} {
		if err := imageScannerValidRef(g); err != nil {
			t.Errorf("should accept: %q (%v)", g, err)
		}
	}
}
