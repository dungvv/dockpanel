package services

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func ownTmp(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Mirrors routes.isValidName (services cannot import routes).
var ownIsValidName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`).MatchString

func u16(v uint16) *uint16 { return &v }

func TestAMissingFileIsUnknownAndUnknownMayNotDelete(t *testing.T) {
	if OwnershipSystemdUnit("/nonexistent/unit.service", "a.com") != OwnershipUnknown {
		t.Fatal()
	}
	if OwnershipUnknown.MayDelete() || OwnershipTheirs.MayDelete() || !OwnershipOurs.MayDelete() {
		t.Fatal()
	}
}

func TestTheSystemdCollisionThatMotivatedThisIsRefused(t *testing.T) {
	p := ownTmp(t, "[Unit]\nDescription=DockPanel App: a.b.com\n\n[Service]\nWorkingDirectory=/var/www/a.b.com/public\nExecStart=node server.js\n")
	if OwnershipSystemdUnit(p, "a.b.com") != OwnershipOurs || OwnershipSystemdUnit(p, "a-b.com") != OwnershipTheirs {
		t.Fatal()
	}
}

func TestBothWorkingDirectoryFormsAreOursAndNeitherLeaksToACollision(t *testing.T) {
	newForm := ownTmp(t, "[Service]\nWorkingDirectory=/var/www/a.b.com\nExecStart=node server.js\n")
	oldForm := ownTmp(t, "[Service]\nWorkingDirectory=/var/www/a.b.com/public\nExecStart=node server.js\n")
	for _, p := range []string{newForm, oldForm} {
		if OwnershipSystemdUnit(p, "a.b.com") != OwnershipOurs || OwnershipSystemdUnit(p, "a-b.com") != OwnershipTheirs {
			t.Fatal(p)
		}
	}
	if OwnershipSystemdUnit(newForm, "a.b.co") != OwnershipTheirs {
		t.Fatal("prefix matched")
	}
}

func TestTheFail2banCollisionIsRefusedOnTheSamePair(t *testing.T) {
	p := ownTmp(t, "[nginx-a-b-com]\nenabled = true\nfilter = nginx-http-auth\nlogpath = /var/log/nginx/a.b.com.access.log\nmaxretry = 10\n")
	if OwnershipFail2banJail(p, "a.b.com") != OwnershipOurs || OwnershipFail2banJail(p, "a-b.com") != OwnershipTheirs {
		t.Fatal()
	}
}

func TestTheTraefikLegacyNameNamesADifferentLiveDomain(t *testing.T) {
	p := ownTmp(t, "http:\n  routers:\n    a-b-com:\n      rule: \"Host(`a.b.com`)\"\n      entryPoints:\n        - web\n")
	if OwnershipTraefikRoute(p, "a.b.com") != OwnershipOurs || OwnershipTraefikRoute(p, "a-b.com") != OwnershipTheirs {
		t.Fatal()
	}
}

func TestAVhostProxyingToAnotherPortIsNotThisApps(t *testing.T) {
	p := ownTmp(t, "server {\n  server_name app.example.com;\n  location / {\n    proxy_pass http://127.0.0.1:8080;\n  }\n}\n")
	if OwnershipAppVhost(p, u16(8080)) != OwnershipOurs || OwnershipAppVhost(p, u16(9090)) != OwnershipTheirs || OwnershipAppVhost(p, nil) != OwnershipUnknown {
		t.Fatal()
	}
}

func TestMarkersAreWholeLineSoAPrefixDomainCannotAnswerForALongerOne(t *testing.T) {
	p := ownTmp(t, "[Unit]\nDescription=DockPanel App: example.community\n\n[Service]\nWorkingDirectory=/var/www/example.community/public\n")
	if OwnershipSystemdUnit(p, "example.community") != OwnershipOurs || OwnershipSystemdUnit(p, "example.com") != OwnershipTheirs {
		t.Fatal()
	}
	if OwnershipSystemdUnit(ownTmp(t, "[Unit]\nDescription=Something an operator wrote\n"), "a.com") != OwnershipTheirs {
		t.Fatal()
	}
}

func TestThePreviewScopeCannotSpellAnyLegalDeployName(t *testing.T) {
	scoped := OwnershipGitScopePreview.Scoped("myapp-pr-feature-x")
	if ownIsValidName(scoped) || scoped == OwnershipGitScopeDeploy.Scoped("myapp-pr-feature-x") {
		t.Fatal(scoped)
	}
}

func TestGitContainerOwnership(t *testing.T) {
	deploy := map[string]string{OwnershipGitKindLabel: "deploy"}
	preview := map[string]string{OwnershipGitKindLabel: "preview"}
	cases := []struct {
		labels   map[string]string
		scope    OwnershipGitScope
		exp, act *uint16
		want     OwnershipOwner
	}{
		{deploy, OwnershipGitScopePreview, nil, nil, OwnershipTheirs},
		{deploy, OwnershipGitScopePreviewLegacy, u16(8001), u16(8001), OwnershipTheirs},
		{nil, OwnershipGitScopeDeploy, nil, nil, OwnershipOurs},
		{nil, OwnershipGitScopePreview, nil, nil, OwnershipUnknown},
		{nil, OwnershipGitScopePreviewLegacy, nil, nil, OwnershipUnknown},
		{nil, OwnershipGitScopePreviewLegacy, u16(8001), nil, OwnershipUnknown},
		{nil, OwnershipGitScopePreviewLegacy, u16(8001), u16(7003), OwnershipUnknown},
		{nil, OwnershipGitScopePreviewLegacy, u16(8001), u16(8001), OwnershipOurs},
		{deploy, OwnershipGitScopeDeploy, nil, nil, OwnershipOurs},
		{preview, OwnershipGitScopePreview, nil, nil, OwnershipOurs},
		{preview, OwnershipGitScopeDeploy, nil, nil, OwnershipTheirs},
		{preview, OwnershipGitScopePreviewLegacy, nil, nil, OwnershipOurs},
	}
	for i, c := range cases {
		if got := OwnershipGitContainer(c.labels, c.scope, c.exp, c.act); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}

func TestTheBlueStandInSpaceCannotHoldARealDeployment(t *testing.T) {
	if OwnershipBlueName("dockpanel-app-api") != "dockpanel-app-api.blue" {
		t.Fatal()
	}
	if ownIsValidName("api.blue") || !ownIsValidName("api-blue") {
		t.Fatal()
	}
	if OwnershipBlueLeftover(nil) != OwnershipUnknown || OwnershipBlueLeftover(map[string]string{"com.example.stack": "mine"}).MayDelete() ||
		!OwnershipBlueLeftover(map[string]string{"dockpanel.managed": "true"}).MayDelete() {
		t.Fatal()
	}
}

func TestAnOlderPanelThatSendsNoScopeStillMeansDeploy(t *testing.T) {
	for in, want := range map[string]OwnershipGitScope{"deploy": OwnershipGitScopeDeploy, "": OwnershipGitScopeDeploy, "nonsense": OwnershipGitScopeDeploy,
		"preview": OwnershipGitScopePreview, "preview_legacy": OwnershipGitScopePreviewLegacy} {
		if OwnershipGitScopeFromWire(in) != want {
			t.Error(in)
		}
	}
	if OwnershipGitScopePreviewLegacy.Scoped("a-pr-b") != "a-pr-b" {
		t.Fatal()
	}
}

func ownTree(t *testing.T) (string, string) {
	root := t.TempDir()
	live, parked := filepath.Join(root, "sites-enabled"), filepath.Join(root, "sites-available")
	os.MkdirAll(live, 0o755)
	os.MkdirAll(parked, 0o755)
	return live, parked
}

func TestARegisteredCertificateIsInUseWhileAnyVhostNamesIt(t *testing.T) {
	needle := SslRegistryDir + "/wild/"
	live, parked := ownTree(t)
	if ownershipRegistryNeedleInUse(needle, live, parked) {
		t.Fatal()
	}
	os.WriteFile(filepath.Join(live, "a.example.com.conf"), []byte("server {\n    ssl_certificate "+needle+"fullchain.pem;\n}\n"), 0o644)
	if !ownershipRegistryNeedleInUse(needle, live, parked) || ownershipRegistryNeedleInUse(SslRegistryDir+"/wil/", live, parked) {
		t.Fatal()
	}
	os.Remove(filepath.Join(live, "a.example.com.conf"))
	os.WriteFile(filepath.Join(parked, "b.example.com.parked"), []byte("ssl_certificate_key "+needle+"privkey.pem;\n"), 0o644)
	if !ownershipRegistryNeedleInUse(needle, live, parked) {
		t.Fatal("parked vhost must count")
	}
	os.Remove(filepath.Join(parked, "b.example.com.parked"))
	if ownershipRegistryNeedleInUse(needle, live, parked) {
		t.Fatal()
	}
}

func TestASingleSharedDirectoryIsNotScannedTwice(t *testing.T) {
	needle := SslRegistryDir + "/wild/"
	live, _ := ownTree(t)
	os.WriteFile(filepath.Join(live, "a.example.com.conf"), []byte("ssl_certificate "+needle+"fullchain.pem;"), 0o644)
	refs, err := ownershipRegistryNeedleReferences(needle, live, live)
	if err != nil || len(refs) != 1 {
		t.Fatal(refs, err)
	}
}

func TestAnUnreadableVhostTreeIsAssumedToReferenceIt(t *testing.T) {
	needle := SslRegistryDir + "/wild/"
	live, parked := ownTree(t)
	if !ownershipRegistryNeedleInUse(needle, filepath.Join(live, "nope"), parked) {
		t.Fatal()
	}
	if ownershipRegistryNeedleInUse(needle, live, filepath.Join(parked, "nope")) {
		t.Fatal("a parked tree that never existed holds nothing")
	}
}
