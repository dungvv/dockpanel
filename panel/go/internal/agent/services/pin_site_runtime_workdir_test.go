package services

import "testing"

// site-runtime-workdir pin (A3): node/python/proxy run from the site root;
// everything else is served from public/. AppProcessCreateAppService derives
// its WorkingDirectory from this, so a drift here brings the crash loop back.
func TestPinSiteRuntimeWorkdirDocumentRootFor(t *testing.T) {
	for rt, want := range map[string]string{
		"node": "/var/www/a.com", "python": "/var/www/a.com", "proxy": "/var/www/a.com",
		"static": "/var/www/a.com/public", "php": "/var/www/a.com/public",
	} {
		if got := NginxDocumentRootFor("/var/www/a.com", rt); got != want {
			t.Errorf("%s: got %q, want %q", rt, got, want)
		}
	}
}

// site-runtime-workdir pin (B3): the Description marker identifies a unit on
// its own, so an edited WorkingDirectory line alone cannot decide ownership.
func TestPinSiteRuntimeWorkdirDescriptionMarkerAlone(t *testing.T) {
	p := ownTmp(t, "[Unit]\nDescription=DockPanel App: a.com\n\n[Service]\nWorkingDirectory=/srv/elsewhere\n")
	if OwnershipSystemdUnit(p, "a.com") != OwnershipOurs || OwnershipSystemdUnit(p, "b.com") != OwnershipTheirs {
		t.Fatal("description marker alone must identify the unit")
	}
}
