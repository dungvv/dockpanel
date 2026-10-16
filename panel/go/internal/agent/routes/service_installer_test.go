package routes

import (
	"os"
	"strings"
	"testing"
)

// The embedded copy must stay byte-identical to the Rust agent's vendored
// asset, and must define the code page modsecurity.conf names.
func TestServiceInstallerUnicodeMappingMatchesRustAsset(t *testing.T) {
	if !strings.Contains(serviceInstallerUnicodeMapping, "20127") || len(serviceInstallerUnicodeMapping) <= 1024 {
		t.Fatal("embedded unicode.mapping is not a usable mapping file")
	}
	want, err := os.ReadFile("../../../../agent/assets/unicode.mapping")
	if err != nil {
		t.Skipf("Rust asset not present: %v", err)
	}
	if string(want) != serviceInstallerUnicodeMapping {
		t.Fatal("routes/unicode.mapping differs from panel/agent/assets/unicode.mapping")
	}
}

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
