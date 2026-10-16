package routes

import "testing"

func TestIacParseCrontab(t *testing.T) {
	got := iacParseCrontab("0 3 * * * /usr/bin/backup --all # dockpanel:abc Nightly backup\n* * * * * other\n5 * * * # dockpanel:short\n")
	if len(got) != 1 || got[0].ID != "abc" || got[0].Schedule != "0 3 * * *" || got[0].Command != "/usr/bin/backup --all" ||
		got[0].Label == nil || *got[0].Label != "Nightly backup" {
		t.Fatalf("got %+v", got)
	}
}

func TestIacParseSite(t *testing.T) {
	s, ok := iacParseSite("a.com.conf", "server {\n  server_name a.com www.a.com;\n  ssl_certificate x;\n  location / {\n    proxy_pass http://127.0.0.1:3000;\n  }\n}\n")
	if !ok || s.Domain != "a.com" || !s.Ssl || s.Runtime != "proxy" || s.ProxyPort == nil || *s.ProxyPort != 3000 {
		t.Fatalf("got %+v", s)
	}
	if _, ok := iacParseSite("default", "server_name _;"); ok {
		t.Fatal("the catch-all must be skipped")
	}
}
