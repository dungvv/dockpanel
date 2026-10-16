package routes

import (
	"fmt"
	"strings"
	"testing"
)

func TestGitBuildVolumePathRejectsTraversalAndFreeFormHosts(t *testing.T) {
	// `..` must be rejected before MkdirAll ever sees it.
	for _, p := range []string{"../etc/passwd", "/data/../../etc", "data", "/", "", "//data", "/data;rm",
		"/" + strings.Repeat("a", 200)} {
		if gitBuildIsValidVolumePath(p) {
			t.Errorf("%q must be rejected", p)
		}
	}
}

func TestGitBuildVolumePathAllowsOrdinaryContainerPaths(t *testing.T) {
	for _, p := range []string{"/data", "/app/uploads", "/var/lib/app-data", "/a"} {
		if !gitBuildIsValidVolumePath(p) {
			t.Errorf("%q must be allowed", p)
		}
	}
}

func TestGitBuildValidateVolumesRejectsDuplicatesAndOverLimit(t *testing.T) {
	if gitBuildValidateVolumes([]string{"/data", "/data"}) == nil {
		t.Error("duplicates must be rejected")
	}
	var tooMany []string
	for i := 0; i < 11; i++ {
		tooMany = append(tooMany, fmt.Sprintf("/d%d", i))
	}
	if gitBuildValidateVolumes(tooMany) == nil {
		t.Error("11 volumes must be rejected")
	}
	if gitBuildValidateVolumes([]string{"/data", "/uploads"}) != nil || gitBuildValidateVolumes(nil) != nil {
		t.Error("valid lists must pass")
	}
}

func TestGitBuildSafeNginxDomainBlocksInjectionAndTraversal(t *testing.T) {
	for _, d := range []string{"../../../etc/nginx/conf.d/pwn", "x; } server { listen 80 default_server; }",
		`a"b.com`, "a$b.com", "a#b.com", "a b.com", "a/b", ""} {
		if gitBuildIsSafeNginxDomain(d) {
			t.Errorf("%q must be rejected", d)
		}
	}
}

func TestGitBuildSafeNginxDomainAllowsRealAndGrandfatheredHosts(t *testing.T) {
	for _, d := range []string{"app.example.com", "feature-login.app.example.com", "my_app.example.com", "a-b_c.example.com"} {
		if !gitBuildIsSafeNginxDomain(d) {
			t.Errorf("%q must be allowed", d)
		}
	}
}

func TestGitBuildRedactURLHidesTokens(t *testing.T) {
	if got := gitBuildRedactURL("https://ghp_secret@github.com/o/r.git"); strings.Contains(got, "ghp_secret") {
		t.Fatalf("token leaked: %s", got)
	}
	if got := gitBuildRedactURL("git@github.com:o/r.git"); got != "git@github.com:o/r.git" {
		t.Fatalf("scp-style URL changed: %s", got)
	}
}
