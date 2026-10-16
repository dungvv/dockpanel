package api

import "testing"

func TestDockerAppsAnEntryMatchesTheReferenceItNames(t *testing.T) {
	for _, c := range [][2]string{
		{"nginx", "nginx"},
		{"nginx", "nginx:1.27"},
		{"nginx", "nginx@sha256:abc"},
		{"nginx:1.27", "nginx:1.27"},
		{"ghcr.io/org/app", "ghcr.io/org/app:v2"},
		{"wordpress, nginx", "nginx:alpine"},
		{"*", "anything/at:all"},
	} {
		if !rtDockerAppsImageAllowedBy(c[0], c[1]) {
			t.Errorf("%q should allow %q", c[0], c[1])
		}
	}
}

// The defect this replaces: a `contains` test let `nginx` admit an unrelated
// image with nginx in its name.
func TestDockerAppsAnEntryDoesNotMatchARepositoryThatMerelyContainsIt(t *testing.T) {
	for _, c := range [][2]string{
		{"nginx", "evil/nginx-backdoor:latest"},
		{"nginx", "nginxinc/nginx-unprivileged"},
		{"nginx", "mynginx:1"},
		{"nginx:1.27", "nginx:1.28"},
		{"", "nginx"},
		{"postgres", "mysql:8"},
	} {
		if rtDockerAppsImageAllowedBy(c[0], c[1]) {
			t.Errorf("%q should not allow %q", c[0], c[1])
		}
	}
}

func TestDockerAppsATrailingSlashStarNamesARepositoryPrefix(t *testing.T) {
	if !rtDockerAppsImageAllowedBy("ghcr.io/myorg/*", "ghcr.io/myorg/api:1") ||
		!rtDockerAppsImageAllowedBy("ghcr.io/myorg/*", "ghcr.io/myorg") {
		t.Fatal("prefix should allow")
	}
	// Not a substring escape: the prefix has to end at a path boundary.
	if rtDockerAppsImageAllowedBy("ghcr.io/myorg/*", "ghcr.io/otherorg/api:1") ||
		rtDockerAppsImageAllowedBy("ghcr.io/myorg/*", "ghcr.io/myorg-evil/api:1") {
		t.Fatal("prefix must not escape")
	}
}
