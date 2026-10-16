package api

// DB-backed checks for the containers group (rt_docker_apps, rt_stacks,
// rt_tcp_proxies, rt_image_scans, rt_sboms, rt_extensions): every query here
// runs against the real schema. Skipped unless DATABASE_URL is set.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDBContainersGroup(t *testing.T) {
	pool := scratchDB(t)
	ctx := context.Background()
	migs, _ := EmbeddedMigrations()
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal(err)
	}
	admin, _ := queryScalar[uuid.UUID](ctx, pool, "INSERT INTO users (email, password_hash, role) VALUES ('ad@b.c', 'h', 'admin') RETURNING id")
	serverID, err := AgentEnsureLocalServer(ctx, pool, "agent-token", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	st := NewAppState(pool, &Config{JWTSecret: testSecret}, NewAgentClient("/nonexistent", "agent-token"), nil, ctx)
	st.Agents = NewAgentRegistry(st.Agent, pool, testSecret)
	st.Agents.SetLocalServerID(serverID)
	rt := &Router{St: st, mux: http.NewServeMux()}
	for _, reg := range []func(*Router){rtDockerAppsRegister, rtStacksRegister, rtTcpProxiesRegister, rtImageScansRegister, rtSbomsRegister, rtExtensionsRegister} {
		reg(rt)
	}
	now := uint64(time.Now().Unix())
	tok, _ := encodeJWT(&Claims{Sub: admin, Email: "ad@b.c", Role: "admin", Exp: now + 600, Iat: now}, testSecret)
	call := func(method, path string, body any) (int, any) {
		t.Helper()
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rd)
		req.Header.Set("Authorization", "Bearer "+tok)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, req)
		var v any
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		return w.Code, v
	}
	expect := func(code, want int, v any) {
		t.Helper()
		if code != want {
			t.Fatalf("status %d (want %d): %v", code, want, v)
		}
	}

	// ── Extensions ──
	code, v := call("POST", "/api/extensions", map[string]any{"name": " hook ", "webhook_url": "https://93.184.216.34/hook"})
	expect(code, 201, v)
	extID := jsonGet(v, "id").(string)
	code, v = call("GET", "/api/extensions", nil)
	expect(code, 200, v)
	if arr := v.([]any); len(arr) != 1 || jsonGet(arr[0], "version") != "1.0.0" || jsonGet(arr[0], "name") != "hook" {
		t.Fatal(v)
	} else if _, leaked := arr[0].(map[string]any)["webhook_secret"]; leaked {
		t.Fatal("webhook_secret must never serialize")
	}
	code, v = call("PUT", "/api/extensions/"+extID, map[string]any{"enabled": false, "description": "d"})
	expect(code, 200, v)
	code, v = call("PUT", "/api/extensions/"+extID, map[string]any{})
	expect(code, 400, v)
	code, v = call("GET", "/api/extensions/"+extID+"/events", nil)
	expect(code, 200, v)
	code, v = call("POST", "/api/extensions/"+extID+"/rotate-secret", nil)
	expect(code, 200, v)
	code, v = call("DELETE", "/api/extensions/"+extID, nil)
	expect(code, 200, v)
	code, v = call("DELETE", "/api/extensions/"+extID, nil)
	expect(code, 404, v)

	// ── Container policies ──
	code, v = call("POST", "/api/container-policies", map[string]any{"user_id": admin, "allowed_images": "nginx, ghcr.io/org/*"})
	expect(code, 201, v)
	code, v = call("GET", "/api/container-policies", nil)
	expect(code, 200, v)
	if p := jsonGet(v, "policies", 0); jsonGet(p, "max_containers") != float64(10) || jsonGet(p, "user_email") != "ad@b.c" {
		t.Fatal(v)
	}
	if err := rtDockerAppsEnforceAllowedImages(ctx, pool, admin, []string{"nginx:1", "ghcr.io/org/x"}); err != nil {
		t.Fatal(err)
	}
	if err := rtDockerAppsEnforceAllowedImages(ctx, pool, admin, []string{"mysql:8"}); err == nil {
		t.Fatal("mysql is not allowed")
	}
	code, v = call("PUT", "/api/container-policies/"+admin.String(), map[string]any{"allowed_images": "", "max_containers": 5000})
	expect(code, 200, v)
	code, v = call("GET", "/api/container-policies/"+admin.String(), nil)
	expect(code, 200, v)
	if jsonGet(v, "allowed_images") != nil || jsonGet(v, "max_containers") != float64(1000) {
		t.Fatal(v)
	}
	code, v = call("GET", "/api/container-policies/"+admin.String()+"/usage", nil)
	expect(code, 200, v)
	if jsonGet(v, "has_policy") != true || jsonGet(v, "servers_unreachable") != float64(1) {
		t.Fatal(v)
	}
	code, v = call("DELETE", "/api/container-policies/"+admin.String(), nil)
	expect(code, 200, v)

	// ── Sleep ──
	code, v = call("GET", "/api/apps/abc123/sleep-config", nil)
	expect(code, 200, v)
	if jsonGet(v, "sleep_after_minutes") != float64(30) {
		t.Fatal(v)
	}
	_, _ = execSQL(ctx, pool, "INSERT INTO container_sleep_config (container_id, container_name, server_id) VALUES ('abc123', 'n', $1)", serverID)
	code, v = call("POST", "/api/apps/abc123/activity-ping", nil)
	expect(code, 200, v)
	code, v = call("GET", "/api/apps/sleep-status", nil)
	expect(code, 200, v)
	if jsonGet(v, "configs", 0, "container_name") != "n" {
		t.Fatal(v)
	}

	// ── Image scans ──
	code, v = call("PUT", "/api/image-scan/settings", map[string]any{"enabled": true, "on_deploy": true, "deploy_gate": "high", "interval_hours": 12})
	expect(code, 200, v)
	if e, od, g, h, err := rtImageScansReadSettings(ctx, pool); err != nil || !e || !od || g != "high" || h != 12 {
		t.Fatal(e, od, g, h, err)
	}
	if _, err := execSQL(ctx, pool, "INSERT INTO image_scan_findings (server_id, image, scanner, critical_count, high_count, medium_count, low_count, unknown_count, vulnerabilities) "+
		"VALUES ($1, 'bad:1', 'grype', 1, 0, 0, 0, 0, '[]')", serverID); err != nil {
		t.Fatal(err)
	}
	code, v = call("GET", "/api/image-scan/recent", nil)
	expect(code, 200, v)
	if jsonGet(v, 0, "image") != "bad:1" {
		t.Fatal(v)
	}
	if err := rtImageScansPreflightGateImage(ctx, pool, serverID, st.Agent, "bad:1"); err == nil {
		t.Fatal("a critical finding must block under gate=high")
	}

	// ── SBOM ──
	_, _ = execSQL(ctx, pool, "INSERT INTO image_sbom (server_id, image, format, spdx, generated_at) VALUES ($1, 'ghcr.io/o/a:1', 'spdx-json', '{\"b\":1,\"a\":2}', NOW())", serverID)
	code, v = call("GET", "/api/sbom/image/ghcr.io/o/a:1", nil)
	expect(code, 200, v)
	if jsonGet(v, "spdx", "a") != float64(2) {
		t.Fatal(v)
	}

	// ── TCP proxies ──
	if p, err := rtTcpProxiesAllocateListenPort(ctx, st, serverID); err != nil || p != rtTcpProxiesListenPortMin {
		t.Fatal(p, err)
	}
	if _, err := execSQL(ctx, pool, "INSERT INTO tcp_proxies (server_id, user_id, name, kind, listen_port, upstream_host, upstream_port, tls, allow_cidrs) "+
		"VALUES ($1, $2, 'p', 'generic', 40000, '127.0.0.1', 5432, false, $3)", serverID, admin, []string{}); err != nil {
		t.Fatal(err)
	}
	if p, _ := rtTcpProxiesAllocateListenPort(ctx, st, serverID); p != 40001 {
		t.Fatal(p)
	}
	code, v = call("GET", "/api/tcp-proxies?limit=5", nil)
	expect(code, 200, v)
	if jsonGet(v, 0, "listen_port") != float64(40000) || jsonGet(v, 0, "allow_cidrs") == nil {
		t.Fatal(v)
	}

	// ── Stacks ──
	stackID, err := queryScalar[uuid.UUID](ctx, pool, "INSERT INTO docker_stacks (user_id, server_id, name, yaml, service_count) VALUES ($1, $2, 's', 'services: {}', 1) RETURNING id", admin, serverID)
	if err != nil {
		t.Fatal(err)
	}
	code, v = call("GET", "/api/stacks", nil)
	expect(code, 200, v)
	if jsonGet(v, 0, "status") != "removed" || jsonGet(v, 0, "tls_mode") != "none" {
		t.Fatal(v)
	}
	code, v = call("POST", "/api/stacks/"+stackID.String()+"/renew-ssl", nil)
	expect(code, 400, v)
}
