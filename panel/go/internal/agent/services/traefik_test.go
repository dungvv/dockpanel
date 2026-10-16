package services

import (
	"strings"
	"testing"
)

func TestDistinctDomainsGetDistinctKeys(t *testing.T) {
	for _, p := range [][2]string{{"a.b.com", "a-b.com"}, {"x-y.z.com", "x.y.z.com"}, {"a--b.com", "a-b-com"}} {
		if TraefikRouteKey(p[0]) == TraefikRouteKey(p[1]) {
			t.Errorf("%s and %s collide", p[0], p[1])
		}
	}
}

func TestKeysContainNoPathOrYamlSeparators(t *testing.T) {
	for _, d := range []string{"a.b.com", "a-b.com", "hy-phen.example.co.uk"} {
		if k := TraefikRouteKey(d); strings.ContainsAny(k, "./") {
			t.Errorf("%s", k)
		}
	}
	if TraefikRouteKey("app.example.com") != TraefikRouteKey("app.example.com") {
		t.Fatal("unstable")
	}
}

// Why TraefikRemoveRouteConfig may not delete the legacy name on filename
// alone: the legacy name of a hyphen domain IS the live name of a dot domain.
func TestTheLegacyNameOfOneDomainIsTheLiveNameOfAnother(t *testing.T) {
	for _, p := range [][2]string{{"a.b.com", "a-b.com"}, {"my.app.example.com", "my-app.example.com"}, {"web.1.site.io", "web-1.site.io"}} {
		dot, hyphen := p[0], p[1]
		if traefikLegacyRouteConfigPath(hyphen) != traefikRouteConfigPath(dot) {
			t.Errorf("removing %s would not hit %s", hyphen, dot)
		}
		if traefikLegacyRouteConfigPath(hyphen) == traefikRouteConfigPath(hyphen) {
			t.Error("legacy equals own")
		}
	}
}
