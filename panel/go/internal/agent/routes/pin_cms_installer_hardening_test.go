package routes

import "testing"

// tests/cms-installer-hardening-pin-e2e.sh F7: db_host is allow-listed —
// '#' would silently truncate the host into a URL fragment for drush.
func TestPinCmsInstallerHardeningDbHost(t *testing.T) {
	for h, want := range map[string]bool{
		"localhost": true, "db.example.com": true, "10.0.0.5:3307": true, "dockpanel-mysql": true,
		"": false, "evil#frag": false, "h/x": false, "h?x": false, "h@x": false, "a b": false,
	} {
		if got := cmsIsValidDbHost(h); got != want {
			t.Errorf("cmsIsValidDbHost(%q) = %v, want %v", h, got, want)
		}
	}
}
