package api

// DB integration tests for the "business" routes (resellers,
// reseller_dashboard, whmcs, webhook_gateway, migration): the Rust modules
// carried no tests of their own except webhook_gateway's verdict suite, so
// these drive the handlers end to end against a migrated scratch database to
// pin the verbatim SQL, status codes and JSON shapes. Gated on DATABASE_URL
// (see core_db_integration_test.go).

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

type rtBizEnv struct {
	t  *testing.T
	st *AppState
	h  http.Handler
}

func (e *rtBizEnv) token(sub uuid.UUID, email, role string) string {
	now := uint64(time.Now().Unix())
	tok, err := encodeJWT(&Claims{Sub: sub, Email: email, Role: role, Exp: now + 600, Iat: now}, testSecret)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

// do sends a request and decodes the JSON answer (nil for an empty body).
func (e *rtBizEnv) do(method, path, tok string, body any, hdr ...string) (int, any) {
	e.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	var out any
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}
	return w.Code, out
}

func rtBizSetup(t *testing.T) (*rtBizEnv, uuid.UUID, uuid.UUID) {
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
	st := NewAppState(pool, &Config{JWTSecret: testSecret}, NewAgentClient("/nonexistent.sock", "agent-token"), nil, ctx)
	st.Agents = NewAgentRegistry(st.Agent, pool, testSecret)
	st.Agents.SetLocalServerID(serverID)
	rt := &Router{St: st, mux: http.NewServeMux()}
	for _, reg := range []func(*Router){rtResellersRegister, rtResellerDashboardRegister, rtWhmcsRegister, rtWebhookGatewayRegister, rtMigrationRegister} {
		reg(rt)
	}
	return &rtBizEnv{t: t, st: st, h: rt}, admin, serverID
}

func TestDBResellersAndResellerDashboard(t *testing.T) {
	e, admin, serverID := rtBizSetup(t)
	ctx := context.Background()
	at := e.token(admin, "ad@b.c", "admin")
	rid, _ := queryScalar[uuid.UUID](ctx, e.st.DB, "INSERT INTO users (email, password_hash, role) VALUES ('r@b.c', 'h', 'user') RETURNING id")

	if c, _ := e.do("POST", "/api/resellers", at, map[string]any{"user_id": admin}); c != 400 {
		t.Fatal("an admin cannot be promoted", c)
	}
	c, b := e.do("POST", "/api/resellers", at, map[string]any{"user_id": rid, "max_users": 1})
	if c != 201 {
		t.Fatal(c, b)
	}
	pid := jsonGet(b, "id").(string)
	if c, _ := e.do("POST", "/api/resellers", at, map[string]any{"user_id": rid}); c != 409 {
		t.Fatal("double create", c)
	}
	if c, b := e.do("GET", "/api/resellers", at, nil); c != 200 || len(b.([]any)) != 1 || jsonGet(b, 0, "email") != "r@b.c" {
		t.Fatal(c, b)
	}
	if c, _ := e.do("PUT", "/api/resellers/"+pid, at, map[string]any{"panel_name": "P", "accent_color": ""}); c != 200 {
		t.Fatal(c)
	}
	if c, b := e.do("GET", "/api/resellers/"+pid, at, nil); c != 200 || jsonGet(b, "panel_name") != "P" || jsonGet(b, "accent_color") != nil || jsonGet(b, "max_users").(float64) != 1 {
		t.Fatal(c, b)
	}
	if c, _ := e.do("GET", "/api/resellers/"+uuid.NewString(), at, nil); c != 404 {
		t.Fatal(c)
	}
	if c, b := e.do("POST", "/api/resellers/"+pid+"/servers", at, map[string]any{"server_id": serverID}); c != 201 || jsonGet(b, "server_id") != serverID.String() {
		t.Fatal(c, b)
	}
	if c, b := e.do("GET", "/api/resellers/"+pid+"/servers", at, nil); c != 200 || len(b.([]any)) != 1 {
		t.Fatal(c, b)
	}

	// The reseller's own side.
	rt := e.token(rid, "r@b.c", "reseller")
	if c, _ := e.do("GET", "/api/resellers", rt, nil); c != 403 {
		t.Fatal("resellers admin routes are admin-only", c)
	}
	if c, b := e.do("GET", "/api/reseller/dashboard", rt, nil); c != 200 || jsonGet(b, "server_count").(float64) != 1 || jsonGet(b, "max_users").(float64) != 1 {
		t.Fatal(c, b)
	}
	if c, _ := e.do("GET", "/api/reseller/dashboard", at, nil); c != 403 {
		t.Fatal("dashboard is reseller-only", c)
	}
	if c, _ := e.do("POST", "/api/reseller/users", rt, map[string]any{"email": "bad", "password": "longenough"}); c != 400 {
		t.Fatal(c)
	}
	c, b = e.do("POST", "/api/reseller/users", rt, map[string]any{"email": "u@b.c", "password": "longenough"})
	if c != 201 || jsonGet(b, "role") != "user" {
		t.Fatal(c, b)
	}
	uid := jsonGet(b, "id").(string)
	if c, b := e.do("POST", "/api/reseller/users", rt, map[string]any{"email": "u2@b.c", "password": "longenough"}); c != 403 {
		t.Fatal("quota of 1 is enforced atomically", c, b)
	}
	if c, b := e.do("GET", "/api/reseller/users", rt, nil); c != 200 || len(b.([]any)) != 1 || jsonGet(b, 0, "site_count").(float64) != 0 {
		t.Fatal(c, b)
	}
	if err := rtResellerDashboardCheckResellerQuota(ctx, e.st.DB, uuid.MustParse(uid), "users"); err == nil {
		t.Fatal("users quota is full")
	}
	if err := rtResellerDashboardCheckResellerQuota(ctx, e.st.DB, uuid.MustParse(uid), "sites"); err != nil {
		t.Fatal("no site cap", err)
	}
	if c, _ := e.do("PUT", "/api/reseller/users/"+uid, rt, map[string]any{"password": "short"}); c != 400 {
		t.Fatal(c)
	}
	// A privileged account carrying this reseller's id is out of reach.
	other, _ := queryScalar[uuid.UUID](ctx, e.st.DB, "INSERT INTO users (email, password_hash, role, reseller_id) VALUES ('x@b.c', 'h', 'admin', $1) RETURNING id", rid)
	if c, _ := e.do("PUT", "/api/reseller/users/"+other.String(), rt, map[string]any{"password": "longenough"}); c != 404 {
		t.Fatal("allow-list keeps admins out", c)
	}
	_, _ = execSQL(ctx, e.st.DB, "UPDATE users SET role = 'client' WHERE id = $1", uid)
	if c, _ := e.do("PUT", "/api/reseller/users/"+uid, rt, map[string]any{"password": "longenough"}); c != 200 {
		t.Fatal("a client sub-account is manageable", c)
	}
	if c, _ := e.do("DELETE", "/api/reseller/users/"+rid.String(), rt, nil); c != 400 {
		t.Fatal("cannot delete self", c)
	}
	if c, b := e.do("DELETE", "/api/reseller/users/"+uid, rt, nil); c != 200 || jsonGet(b, "email") != "u@b.c" {
		t.Fatal(c, b)
	}
	if used, _ := queryScalar[int32](ctx, e.st.DB, "SELECT used_users FROM reseller_profiles WHERE user_id = $1", rid); used != 0 {
		t.Fatal("used_users decremented", used)
	}
	if c, b := e.do("GET", "/api/reseller/servers", rt, nil); c != 200 || len(b.([]any)) != 1 {
		t.Fatal(c, b)
	}

	// Deallocation, demotion, re-promotion keeps the orphan profile.
	if c, _ := e.do("DELETE", "/api/resellers/"+pid+"/servers/"+serverID.String(), at, nil); c != 200 {
		t.Fatal(c)
	}
	if c, _ := e.do("DELETE", "/api/resellers/"+pid+"/servers/"+serverID.String(), at, nil); c != 404 {
		t.Fatal(c)
	}
	_, _ = execSQL(ctx, e.st.DB, "UPDATE users SET role = 'user' WHERE id = $1", rid)
	if c, b := e.do("POST", "/api/resellers", at, map[string]any{"user_id": rid}); c != 201 || jsonGet(b, "id") != pid {
		t.Fatal("re-promotion reuses the kept profile", c, b)
	}
	if c, b := e.do("DELETE", "/api/resellers/"+pid, at, nil); c != 200 || jsonGet(b, "email") != "r@b.c" {
		t.Fatal(c, b)
	}
	if role, _ := queryScalar[string](ctx, e.st.DB, "SELECT role FROM users WHERE id = $1", rid); role != "user" {
		t.Fatal(role)
	}
}

func TestDBWhmcs(t *testing.T) {
	e, admin, _ := rtBizSetup(t)
	ctx := context.Background()
	at := e.token(admin, "ad@b.c", "admin")

	if c, b := e.do("GET", "/api/whmcs/config", at, nil); c != 200 || jsonGet(b, "configured") != false {
		t.Fatal(c, b)
	}
	if c, _ := e.do("POST", "/api/whmcs/webhook", "", map[string]any{"action": "provision"}); c != 404 {
		t.Fatal("not configured", c)
	}
	cfg := map[string]any{"api_url": "https://billing.example", "api_identifier": "ident-123456789", "api_secret": "s", "auto_suspend": false}
	c, b := e.do("PUT", "/api/whmcs/config", at, cfg)
	if c != 200 {
		t.Fatal(c, b)
	}
	secret := jsonGet(b, "webhook_secret").(string)
	// A second save keeps the webhook secret and the explicitly-set flag.
	delete(cfg, "auto_suspend")
	if c, b := e.do("PUT", "/api/whmcs/config", at, cfg); c != 200 || jsonGet(b, "webhook_secret") != secret {
		t.Fatal("the webhook secret survives a save", c, b)
	}
	c, b = e.do("GET", "/api/whmcs/config", at, nil)
	if c != 200 || jsonGet(b, "api_identifier") != "iden...6789" || jsonGet(b, "webhook_secret") != secret || jsonGet(b, "auto_suspend") != false {
		t.Fatal(c, b)
	}

	if c, _ := e.do("POST", "/api/whmcs/webhook", "", map[string]any{"action": "provision", "secret": "wrong"}); c != 401 {
		t.Fatal(c)
	}
	// The advertised query-string form authenticates too.
	c, b = e.do("POST", "/api/whmcs/webhook?secret="+secret, "", map[string]any{"action": "CreateAccount", "service_id": 7, "client_email": "c@b.c"})
	if c != 200 || jsonGet(b, "action") != "provisioned" {
		t.Fatal(c, b)
	}
	// auto_suspend is off: suspend is ignored, not acted on.
	if c, b := e.do("POST", "/api/whmcs/webhook", "", map[string]any{"action": "suspend", "service_id": 7, "secret": secret}); c != 200 || jsonGet(b, "action") != "ignored" {
		t.Fatal(c, b)
	}
	cfg["auto_suspend"] = true
	e.do("PUT", "/api/whmcs/config", at, cfg)
	if c, b := e.do("POST", "/api/whmcs/webhook", "", map[string]any{"action": "suspend", "service_id": 7, "secret": secret}); c != 200 || jsonGet(b, "action") != "suspended" {
		t.Fatal(c, b)
	}
	if role, _ := queryScalar[string](ctx, e.st.DB, "SELECT role FROM users WHERE email = 'c@b.c'"); role != "suspended" {
		t.Fatal(role)
	}
	e.do("POST", "/api/whmcs/webhook", "", map[string]any{"action": "unsuspend", "service_id": 7, "secret": secret})
	if role, _ := queryScalar[string](ctx, e.st.DB, "SELECT role FROM users WHERE email = 'c@b.c'"); role != "user" {
		t.Fatal(role)
	}
	if c, b := e.do("GET", "/api/whmcs/services", at, nil); c != 200 || jsonGet(b, "services", 0, "status") != "active" || jsonGet(b, "services", 0, "site_id") != nil {
		t.Fatal(c, b)
	}

	// App migration stub.
	if c, _ := e.do("POST", "/api/migrations/apps", at, map[string]any{"container_id": "abc", "container_name": "n", "target_server_id": uuid.New()}); c != 404 {
		t.Fatal(c)
	}
	if c, b := e.do("GET", "/api/migrations/apps", at, nil); c != 200 || len(jsonGet(b, "migrations").([]any)) != 0 {
		t.Fatal(c, b)
	}
	if c, _ := e.do("GET", "/api/migrations/apps/"+uuid.NewString(), at, nil); c != 404 {
		t.Fatal(c)
	}
	if c, _ := e.do("DELETE", "/api/whmcs/config", at, nil); c != 200 {
		t.Fatal(c)
	}
}

func TestDBWebhookGateway(t *testing.T) {
	e, admin, _ := rtBizSetup(t)
	ctx := context.Background()
	at := e.token(admin, "ad@b.c", "admin")

	if c, _ := e.do("POST", "/api/webhook-gateway/endpoints", at, map[string]any{"name": "gh", "verify_mode": "hmac_sha256", "verify_secret": " "}); c != 400 {
		t.Fatal("a verifying mode needs a secret", c)
	}
	c, b := e.do("POST", "/api/webhook-gateway/endpoints", at, map[string]any{"name": "gh", "verify_mode": "hmac_sha256", "verify_secret": "k", "verify_header": "X-Sig"})
	if c != 201 || jsonGet(b, "verify_secret_set") != true {
		t.Fatal(c, b)
	}
	if _, leaked := b.(map[string]any)["verify_secret"]; leaked {
		t.Fatal("the secret never rides out")
	}
	id, token := jsonGet(b, "id").(string), jsonGet(b, "token").(string)

	body := []byte(`{"a":1}`)
	if c, _ := e.do("POST", "/api/webhooks/gateway/"+token, "", body, "X-Sig", "sha256=00"); c != 401 {
		t.Fatal(c)
	}
	mac := hmac.New(sha256.New, []byte("k"))
	mac.Write(body)
	c, b = e.do("POST", "/api/webhooks/gateway/"+token, "", body, "X-Sig", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	if c != 200 || jsonGet(b, "forwarded_to").(float64) != 0 {
		t.Fatal(c, b)
	}
	c, b = e.do("GET", "/api/webhook-gateway/endpoints/"+id+"/deliveries?limit=10", at, nil)
	if c != 200 || len(b.([]any)) != 2 {
		t.Fatal(c, b)
	}
	// Newest first: the valid one, then the rejected one recorded FALSE.
	if jsonGet(b, 0, "signature_valid") != true || jsonGet(b, 1, "signature_valid") != false || jsonGet(b, 0, "headers", "x-sig") == nil {
		t.Fatal(b)
	}
	delivery := jsonGet(b, 0, "id").(string)
	if n, _ := queryScalar[int32](ctx, e.st.DB, "SELECT total_received FROM webhook_endpoints WHERE id = $1", id); n != 2 {
		t.Fatal(n)
	}

	if c, _ := e.do("POST", "/api/webhook-gateway/endpoints/"+id+"/routes", at, map[string]any{"name": "r", "destination_url": "http://127.0.0.1/x"}); c != 400 {
		t.Fatal("SSRF guard", c)
	}
	if c, b := e.do("GET", "/api/webhook-gateway/endpoints/"+id+"/routes", at, nil); c != 200 || len(b.([]any)) != 0 {
		t.Fatal(c, b)
	}
	if c, b := e.do("POST", "/api/webhook-gateway/deliveries/"+delivery+"/replay", at, nil); c != 200 || jsonGet(b, "replayed_to").(float64) != 0 {
		t.Fatal(c, b)
	}
	if c, _ := e.do("PUT", "/api/webhook-gateway/endpoints/"+id, at, map[string]any{"enabled": false}); c != 200 {
		t.Fatal(c)
	}
	if c, _ := e.do("POST", "/api/webhooks/gateway/"+token, "", body); c != 404 {
		t.Fatal("a closed door is not found", c)
	}
	if c, _ := e.do("PUT", "/api/webhook-gateway/routes/"+uuid.NewString(), at, map[string]any{"enabled": false}); c != 404 {
		t.Fatal(c)
	}
	other := e.token(uuid.New(), "o@b.c", "admin")
	if c, _ := e.do("GET", "/api/webhook-gateway/endpoints/"+id+"/deliveries", other, nil); c != 404 {
		t.Fatal("scoped to the owner", c)
	}
	if c, _ := e.do("DELETE", "/api/webhook-gateway/endpoints/"+id, at, nil); c != 200 {
		t.Fatal(c)
	}
}

func TestDBMigrationRoutes(t *testing.T) {
	e, admin, serverID := rtBizSetup(t)
	ctx := context.Background()
	at := e.token(admin, "ad@b.c", "admin")

	if c, b := e.do("GET", "/api/migration", at, nil); c != 200 || len(b.([]any)) != 0 {
		t.Fatal(c, b)
	}
	if c, _ := e.do("POST", "/api/migration/analyze", at, map[string]any{"path": "/a", "url": "https://x/y.zip"}); c != 400 {
		t.Fatal(c)
	}
	if c, _ := e.do("POST", "/api/migration/analyze", at, map[string]any{"url": "ftp://x"}); c != 400 {
		t.Fatal(c)
	}
	if c, _ := e.do("POST", "/api/migration/analyze", at, map[string]any{"path": "/a", "source": "cpanel2"}); c != 400 {
		t.Fatal(c)
	}

	// The startup sweep closes out rows a dead process left behind.
	id, _ := queryScalar[uuid.UUID](ctx, e.st.DB,
		"INSERT INTO migrations (user_id, server_id, source, status, backup_path) VALUES ($1, $2, 'cpanel', 'analyzing', '/b') RETURNING id", admin, serverID)
	rtMigrationFinalizeAnalyzingOnStartup(ctx, e.st.DB)
	c, b := e.do("GET", "/api/migration/"+id.String(), at, nil)
	if c != 200 || jsonGet(b, "status") != "failed" || jsonGet(b, "result", "error") == nil || jsonGet(b, "inventory") != nil {
		t.Fatal(c, b)
	}
	if c, _ := e.do("POST", "/api/migration/"+id.String()+"/import", at, map[string]any{"sites": []any{}}); c != 400 {
		t.Fatal("only an analyzed migration imports", c)
	}
	if c, _ := e.do("GET", "/api/migration/"+id.String()+"/progress", at, nil); c != 404 {
		t.Fatal("no active import", c)
	}
	user := e.token(admin, "ad@b.c", "user")
	if c, _ := e.do("GET", "/api/migration", user, nil); c != 403 {
		t.Fatal(c)
	}
	if c, _ := e.do("DELETE", "/api/migration/"+id.String(), at, nil); c != 200 {
		t.Fatal(c)
	}
	if c, _ := e.do("GET", "/api/migration/"+id.String(), at, nil); c != 404 {
		t.Fatal(c)
	}
}

func TestMigrationFetchArchiveExtension(t *testing.T) {
	for in, want := range map[string]string{
		"https://x/a.ZIP?sig=1": ".zip", "https://x/a.tar#frag": ".tar", "https://x/a.tgz": ".tar.gz", "https://x/a": ".tar.gz",
	} {
		if got := rtMigrationFetchArchiveExtension(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}
