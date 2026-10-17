package api

import "testing"

// git-deploy-volumes §6: the backend's friendly volume-path check rejects
// traversal (the agent's gitBuildIsValidVolumePath is the security floor).
func TestPinGitDeployVolumesBackendPathValidatorRejectsTraversal(t *testing.T) {
	for _, p := range []string{"/data/../../etc", "../etc", "/..", "data", "/", "", "//data", "/data;rm"} {
		if rtGitDeploysIsValidVolumePath(p) {
			t.Errorf("%q must be rejected", p)
		}
	}
	for _, p := range []string{"/data", "/app/uploads", "/var/lib/app-data"} {
		if !rtGitDeploysIsValidVolumePath(p) {
			t.Errorf("%q must be accepted", p)
		}
	}
	if msg := rtGitDeploysValidateVolumes([]string{"/data", "/x/../y"}); msg == "" {
		t.Error("a list with a traversal path must be refused")
	}
}
