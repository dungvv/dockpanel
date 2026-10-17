package routes

import (
	"testing"
)

func TestServiceInstallerPasswordFromURL(t *testing.T) {
	for in, want := range map[string]string{
		"postgresql://dockpanel:s3cret@127.0.0.1:5450/dockpanel": "s3cret",
		"postgresql://dockpanel@127.0.0.1/db":                    "",
		"postgresql://dockpanel:@h/db":                           "",
		"nonsense":                                               "",
	} {
		if got, _ := serviceInstallerPasswordFromURL(in); got != want {
			t.Errorf("%q: got %q", in, got)
		}
	}
}
