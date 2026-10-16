package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMonitorsExpiryStatusLadder(t *testing.T) {
	d := func(v int64) *int64 { return &v }
	cases := []struct {
		days    *int64
		failing bool
		want    string
	}{
		{d(-1), true, "expired"},
		{nil, true, "renewal_failed"},
		{d(200), true, "renewal_failed"},
		{nil, false, "unknown"},
		{d(7), false, "critical"},
		{d(30), false, "warning"},
		{d(31), false, "ok"},
	}
	for _, c := range cases {
		if got := rtMonitorsExpiryStatus(c.days, c.failing); got != c.want {
			t.Errorf("%v/%v: %s want %s", c.days, c.failing, got, c.want)
		}
	}
}

// TestMonitoringDB exercises the monitoring SQL against a real, migrated
// Postgres — the statements whose parameter types pgx (unlike sqlx) leaves
// to server inference. Gated on DATABASE_URL.
func TestMonitoringDB(t *testing.T) {
	db := scratchDB(t)
	ctx := context.Background()
	migs, err := EmbeddedMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(ctx, db, migs, true); err != nil {
		t.Fatal(err)
	}
	uid, err := queryScalar[uuid.UUID](ctx, db, "INSERT INTO users (email, password_hash, role) VALUES ('a@x.test', 'x', 'admin') RETURNING id")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{JWTSecret: strings.Repeat("s", 64)}
	st := NewAppState(db, cfg, nil, nil, ctx)
	NotificationsInitNotifBroadcast(st.Notif)
	rt := &Router{St: st, mux: http.NewServeMux()}
	for _, reg := range []func(*Router){rtMonitorsRegister, rtIncidentsRegister, rtNotificationsRegister, rtActivityRegister} {
		reg(rt)
	}
	tok, _ := encodeJWT(&Claims{Sub: uid, Email: "a@x.test", Role: "admin", Exp: uint64(time.Now().Add(time.Hour).Unix()), Iat: uint64(time.Now().Unix())}, cfg.JWTSecret)
	call := func(method, path, body string) (int, map[string]any, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, req)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m, w.Body.String()
	}

	code, mon, raw := call("POST", "/api/monitors", `{"url":"hb-1","name":"beat","monitor_type":"heartbeat","custom_headers":{"X-A":"b"}}`)
	if code != 201 || mon["custom_headers"] == nil {
		t.Fatalf("create: %d %s", code, raw)
	}
	if code, _, raw = call("PUT", "/api/monitors/"+mon["id"].(string), `{"check_interval":5,"custom_headers":null}`); code != 200 {
		t.Fatalf("update: %d %s", code, raw)
	}
	for _, p := range []string{"checks", "incidents", "uptime", "chart"} {
		if code, _, raw = call("GET", "/api/monitors/"+mon["id"].(string)+"/"+p, ""); code != 200 {
			t.Fatalf("%s: %d %s", p, code, raw)
		}
	}
	if code, _, raw = call("POST", "/api/monitors/maintenance", `{"starts_at":"2026-01-01T00:00:00Z","ends_at":"2026-01-02T00:00:00Z"}`); code != 200 {
		t.Fatalf("maintenance: %d %s", code, raw)
	}
	if code, _, raw = call("GET", "/api/monitors/certificates", ""); code != 200 {
		t.Fatalf("certs: %d %s", code, raw)
	}

	// Status page off by default → 404 on every public route.
	if code, _, _ = call("GET", "/api/status-page/public", ""); code != 404 {
		t.Fatalf("public page must be gated: %d", code)
	}
	_, _ = execSQL(ctx, db, "INSERT INTO settings (key, value) VALUES ('status_page_enabled', 'true')")
	code, inc, raw := call("POST", "/api/incidents", `{"title":"db down","description":"x"}`)
	if code != 201 {
		t.Fatalf("incident: %d %s", code, raw)
	}
	if code, _, raw = call("PUT", "/api/incidents/"+inc["id"].(string), `{"status":"postmortem","message":"m"}`); code != 200 {
		t.Fatalf("incident update: %d %s", code, raw)
	}
	if code, _, raw = call("POST", "/api/incidents/"+inc["id"].(string)+"/updates", `{"status":"resolved","message":"ok"}`); code != 201 {
		t.Fatalf("post update: %d %s", code, raw)
	}
	if code, _, raw = call("PUT", "/api/status-page/config", `{"logo_url":"","title":"S"}`); code != 200 {
		t.Fatalf("config: %d %s", code, raw)
	}
	code, page, raw := call("GET", "/api/status-page/public", "")
	if code != 200 || len(page["incidents"].([]any)) != 1 {
		t.Fatalf("public page: %d %s", code, raw)
	}
	if code, _, raw = call("POST", "/api/status-page/subscribe", `{"email":"s@x.test"}`); code != 200 {
		t.Fatalf("subscribe: %d %s", code, raw)
	}
	if code, _, raw = call("DELETE", "/api/status-page/unsubscribe", `{"email":"s@x.test"}`); code != 200 {
		t.Fatalf("unsubscribe: %d %s", code, raw)
	}
	if code, _, raw = call("GET", "/api/incidents/summary", ""); code != 200 {
		t.Fatalf("summary: %d %s", code, raw)
	}

	// Fire + resolve through the third (no server, no site) arm.
	fired, err := NotificationsTryFireAlert(ctx, db, uid, nil, nil, "slow_response", "k1", "warning", "t", "m")
	if err != nil || !fired {
		t.Fatalf("fire: %v %v", fired, err)
	}
	NotificationsResolveAlert(ctx, db, uid, nil, nil, "slow_response", "k1", "t", "m")
	if n, _ := queryScalar[int64](ctx, db, "SELECT COUNT(*) FROM alerts WHERE status = 'resolved'"); n != 1 {
		t.Fatalf("resolved = %d", n)
	}
	NotificationsFireAlertDeduped(ctx, db, uid, nil, nil, "slow_response", "k1", "warning", "t", "m", 12)
	a, b, c, d, e, f, g := NotificationsGetThresholds(ctx, db, uid, nil)
	if a != 90 || g != "30,14,7,3,1" {
		t.Fatal(a, b, c, d, e, f, g)
	}

	code, list, raw := call("GET", "/api/notifications/summary", "")
	if code != 200 || list["total"].(float64) < 1 {
		t.Fatalf("notif summary: %d %s", code, raw)
	}
	if code, _, raw = call("GET", "/api/notifications?before=2099-01-01T00:00:00Z&unread=true&category=alert", ""); code != 200 || !strings.HasPrefix(raw, "[{") {
		t.Fatalf("notif list: %d %s", code, raw)
	}
	if code, _, raw = call("DELETE", "/api/notifications/read", ""); code != 200 {
		t.Fatalf("delete read: %d %s", code, raw)
	}
	ActivityLogActivitySystem(ctx, db, "uptime", "x.y", nil, nil, nil, nil, nil)
	if code, _, raw = call("GET", "/api/activity?action=x", ""); code != 200 || !strings.Contains(raw, `"server_name":null`) {
		t.Fatalf("activity: %d %s", code, raw)
	}
}
