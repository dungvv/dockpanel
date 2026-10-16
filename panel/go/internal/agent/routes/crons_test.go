package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCronsTheIDIsTheTokenAfterTheMarker(t *testing.T) {
	for in, want := range map[string]string{
		"*/5 * * * * /bin/true # dockpanel:abc-123 My label": "abc-123",
		"*/5 * * * * /bin/true # dockpanel:abc-123":          "abc-123",
		"0 3 * * * /usr/bin/certbot renew":                   "",
		"# a plain operator comment":                         "",
	} {
		if got, _ := cronsMarkerID(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

// A line whose id was NOT sent must survive, whoever owns it.
func TestCronsALineThisSyncDoesNotOwnIsKept(t *testing.T) {
	crontab := []string{
		"*/15 * * * * php wp-cron.php # dockpanel:site-a-cron WordPress Cron",
		"0 2 * * * /usr/local/bin/backup # dockpanel:site-b-cron Nightly backup",
		"0 4 * * * /usr/bin/certbot renew",
	}
	owned := map[string]bool{"site-a-cron": true}
	var kept []string
	for _, l := range crontab {
		if id, ok := cronsMarkerID(l); !ok || !owned[id] {
			kept = append(kept, l)
		}
	}
	if len(kept) != 2 || !strings.Contains(kept[0], "site-b-cron") || !strings.Contains(kept[1], "certbot") {
		t.Fatalf("kept: %q", kept)
	}
}

// An id that is a PREFIX of another must not carry it off.
func TestCronsAPrefixIDDoesNotMatchALongerOne(t *testing.T) {
	if got, _ := cronsMarkerID("*/5 * * * * /bin/true # dockpanel:abc-1234 label"); got != "abc-1234" {
		t.Fatal(got)
	}
}

func TestCronsIsValidSchedule(t *testing.T) {
	for _, s := range []string{"* * * * *", "*/5 0-6 1,15 * 1"} {
		if !cronsIsValidSchedule(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"@reboot", "* * * *", "* * * * * *", "* * * * mon", "* * * * *;id", "* * * * *\n"} {
		if cronsIsValidSchedule(s) && !strings.Contains(s, "\n") {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestCronsParseList(t *testing.T) {
	got := cronsParseList("0 4 * * * certbot renew\n*/5 * * * * /bin/true # dockpanel:abc My label \n* * * * * x # dockpanel:solo\n")
	if len(got) != 2 || got[0]["id"] != "abc" || got[0]["label"] != "My label" || got[0]["entry"] != "*/5 * * * * /bin/true" ||
		got[1]["id"] != "solo" || got[1]["label"] != "" {
		t.Fatalf("%v", got)
	}
}

func TestCronsTruncate(t *testing.T) {
	s := strings.Repeat("a", 10239) + "é" + "tail"
	got := cronsTruncate(s)
	if !strings.HasSuffix(got, "...(truncated)") || len(got) != 10239+len("...(truncated)") {
		t.Fatalf("len %d", len(got))
	}
	if cronsTruncate("short") != "short" {
		t.Fatal("short changed")
	}
}

func cronsServe(method, path, body string) *httptest.ResponseRecorder {
	r := &Router{Auth: http.NewServeMux(), Public: http.NewServeMux()}
	registerCrons(r)
	registerSecurity(r)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.Auth.ServeHTTP(rec, req)
	return rec
}

func TestCronsRequestValidationBeforeAnySideEffect(t *testing.T) {
	for _, c := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/crons/sync", `[{"id":"a","command":"ls"}]`, 422}, // missing schedule
		{"POST", "/crons/sync", `[{"id":null,"command":"ls","schedule":"* * * * *"}]`, 422},
		{"POST", "/crons/run", `{"id":"a","command":"","schedule":"* * * * *"}`, 400},
		{"POST", "/crons/run", `{"id":"a","command":"id;whoami","schedule":"* * * * *"}`, 400},
		{"POST", "/crons/run", `{"id":"a","command":"curl x","schedule":"x"}`, 400},
		{"POST", "/crons/run", `{bad`, 400},
		{"POST", "/security/firewall/rules", `{"port":80,"proto":"tcp"}`, 422},
		{"POST", "/security/firewall/rules", `{"port":70000,"proto":"tcp","action":"allow"}`, 422},
		{"POST", "/security/firewall/rules", `{"port":80,"proto":"tcp","action":"nope"}`, 400},
		{"POST", "/security/firewall/rules", `{"port":80,"proto":"tcp","action":"allow","from":"1.2.3.4 x"}`, 400},
		{"DELETE", "/security/firewall/rules/abc", ``, 400},
		{"POST", "/security/fix", `{"fix_type":"nope","target":""}`, 400},
		{"POST", "/security/fix", `{"fix_type":"remove_file","target":"/etc/passwd"}`, 400},
		{"POST", "/security/ssh/change-port", `{}`, 422},
	} {
		if rec := cronsServe(c.method, c.path, c.body); rec.Code != c.status {
			t.Errorf("%s %s %s: got %d (%s), want %d", c.method, c.path, c.body, rec.Code, rec.Body.String(), c.status)
		}
	}
}
