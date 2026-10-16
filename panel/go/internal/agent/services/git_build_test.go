package services

import "testing"

// A neighbour's directory is not this deploy's, and a prefix that stops
// mid-segment must not match.
func TestGitBuildCleanupOnlyDeletesWhatThisDeploysOwnBindsProve(t *testing.T) {
	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	want := gitBuildDataDir + "/myapp"
	if got := gitBuildOwnedDataDir("myapp", []string{gitBuildDataDir + "/myapp/data:/data"}); str(got) != want {
		t.Fatalf("own bind: got %s", str(got))
	}
	for name, binds := range map[string][]string{
		"neighbour myapp-staging": {gitBuildDataDir + "/myapp-staging/data:/data"},
		"no binds":                nil,
		"substring myapp2":        {gitBuildDataDir + "/myapp2/data:/data"},
	} {
		if got := gitBuildOwnedDataDir("myapp", binds); got != nil {
			t.Errorf("%s: must not be owned, got %s", name, *got)
		}
	}
}

// The kept-binds comparison reads the DESTINATION (second field) only, so a
// :mode suffix does not drop an otherwise-correct bind.
func TestGitBuildKeptBinds(t *testing.T) {
	got := gitBuildKeptBinds([]string{"/h/a:/data:rw", "/h/b:/gone", "/h/c:/up"}, []string{"/data", "/up"})
	if len(got) != 2 || got[0] != "/h/a:/data:rw" || got[1] != "/h/c:/up" {
		t.Fatalf("got %v", got)
	}
}
