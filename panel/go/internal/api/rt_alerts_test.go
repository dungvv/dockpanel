package api

// DB-backed checks for the alerting group (rt_alerts, rt_on_call,
// rt_escalation_policies, and the alert engine / expected-stops SQL). Skipped
// unless DATABASE_URL is set — see core_db_integration_test.go. Their main
// job is proving the sqlx query strings still type-check when pgx lets the
// server infer parameter types.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

type rtAlertsTEnv struct {
	t      *testing.T
	ctx    context.Context
	st     *AppState
	h      http.Handler
	admin  uuid.UUID
	server uuid.UUID
	tok    string
}

func rtAlertsTSetup(t *testing.T) *rtAlertsTEnv {
	pool := scratchDB(t)
	ctx := context.Background()
	migs, _ := EmbeddedMigrations()
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal(err)
	}
	admin, err := queryScalar[uuid.UUID](ctx, pool, "INSERT INTO users (email, password_hash, role) VALUES ('ad@b.c', 'h', 'admin') RETURNING id")
	if err != nil {
		t.Fatal(err)
	}
	server, err := AgentEnsureLocalServer(ctx, pool, "agent-token", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	st := NewAppState(pool, &Config{JWTSecret: testSecret}, NewAgentClient("/x", "agent-token"), nil, ctx)
	st.Agents = NewAgentRegistry(st.Agent, pool, testSecret)
	st.Agents.SetLocalServerID(server)
	rt := &Router{St: st, mux: http.NewServeMux()}
	rtAlertsRegister(rt)
	rtOnCallRegister(rt)
	rtEscalationPoliciesRegister(rt)
	tok, _ := encodeJWT(&Claims{Sub: admin, Email: "ad@b.c", Role: "admin", Exp: uint64(time.Now().Unix() + 600), Iat: uint64(time.Now().Unix())}, testSecret)
	return &rtAlertsTEnv{t, ctx, st, rt, admin, server, tok}
}

func (e *rtAlertsTEnv) do(method, path string, body any) (int, any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, rd)
	r.Header.Set("Authorization", "Bearer "+e.tok)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	var v any
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	return w.Code, v
}

func (e *rtAlertsTEnv) want(method, path string, body any, status int) any {
	e.t.Helper()
	code, v := e.do(method, path, body)
	if code != status {
		e.t.Fatalf("%s %s: %d %v (want %d)", method, path, code, v, status)
	}
	return v
}

func TestDBAlertsRoutes(t *testing.T) {
	e := rtAlertsTSetup(t)

	// Rules: insert, then the UPDATE path (global row → the `$2::uuid IS NULL` arm).
	e.want("PUT", "/api/alert-rules", map[string]any{"cpu_threshold": 70, "notify_slack_url": ""}, 200)
	e.want("PUT", "/api/alert-rules", map[string]any{"cpu_threshold": 75, "muted_types": "cpu"}, 200)
	e.want("PUT", "/api/alert-rules", map[string]any{"muted_types": "nope"}, 400)
	e.want("PUT", "/api/alert-rules/"+e.server.String(), map[string]any{"disk_threshold": 50}, 200)
	e.want("PUT", "/api/alert-rules/"+e.server.String(), map[string]any{"disk_threshold": 60}, 200)
	e.want("PUT", "/api/alert-rules/"+uuid.NewString(), map[string]any{}, 404)
	rules := e.want("GET", "/api/alert-rules", nil, 200).([]any)
	if len(rules) != 2 || jsonGet(rules, 0, "cpu_threshold") != 75.0 || jsonGet(rules, 0, "notify_slack_url") != "" || jsonGet(rules, 1, "disk_threshold") != 60.0 {
		t.Fatal(rules)
	}
	ruleID := jsonGet(rules, 0, "id").(string)

	// Alerts list / summary / ack / resolve and the PUT dispatcher.
	a1, _ := queryScalar[uuid.UUID](e.ctx, e.st.DB, "INSERT INTO alerts (user_id, server_id, alert_type, severity, title, message) VALUES ($1, $2, 'cpu', 'warning', 't', 'm') RETURNING id", e.admin, e.server)
	a2, _ := queryScalar[uuid.UUID](e.ctx, e.st.DB, "INSERT INTO alerts (user_id, alert_type, severity, title, message) VALUES ($1, 'backup_failure', 'critical', 't2', 'm2') RETURNING id", e.admin)
	if l := e.want("GET", "/api/alerts?status=firing&alert_type=cpu", nil, 200).([]any); len(l) != 1 {
		t.Fatal(l)
	}
	if l := e.want("GET", "/api/alerts", nil, 200).([]any); len(l) != 2 {
		t.Fatal("NULL server_id alerts are listed", l)
	}
	e.want("PUT", "/api/alerts/"+a1.String()+"/acknowledge", nil, 200)
	e.want("PUT", "/api/alerts/"+a1.String()+"/acknowledge", nil, 404)
	e.want("PUT", "/api/alerts/"+a2.String()+"/acknowledge", map[string]any{"comment": "  on it  "}, 200)
	if c, _ := queryScalar[*string](e.ctx, e.st.DB, "SELECT acknowledged_comment FROM alerts WHERE id = $1", a2); c == nil || *c != "on it" {
		t.Fatal(c)
	}
	e.want("PUT", "/api/alerts/"+a1.String()+"/resolve", nil, 200)
	e.want("PUT", "/api/alerts/"+a1.String()+"/bogus", nil, 404)
	sum := e.want("GET", "/api/alerts/summary", nil, 200)
	if jsonGet(sum, "resolved") != 1.0 || jsonGet(sum, "acknowledged") != 1.0 || jsonGet(sum, "firing") != 0.0 {
		t.Fatal(sum)
	}
	l := e.want("GET", "/api/alerts?status=acknowledged", nil, 200).([]any)
	if jsonGet(l, 0, "acknowledged_by_email") != "ad@b.c" {
		t.Fatal(l)
	}

	// Runbooks.
	ad := e.want("POST", "/api/alerts/runbooks/apply-defaults", nil, 200)
	if ins, _ := jsonArr(jsonGet(ad, "inserted")); len(ins) != 15 {
		t.Fatal(ad)
	}
	ad = e.want("POST", "/api/alerts/runbooks/apply-defaults", nil, 200)
	if sk, _ := jsonArr(jsonGet(ad, "skipped")); len(sk) != 15 {
		t.Fatal(ad)
	}
	rb := e.want("PUT", "/api/alerts/runbooks/custom", map[string]any{"runbook_md": "x", "severity_default": "info"}, 200)
	if jsonGet(rb, "is_default") != false || jsonGet(rb, "updated_by") != e.admin.String() {
		t.Fatal(rb)
	}
	e.want("PUT", "/api/alerts/runbooks/custom", map[string]any{"runbook_md": "x", "severity_default": "loud"}, 400)
	if l := e.want("GET", "/api/alerts/runbooks", nil, 200).([]any); len(l) != 16 {
		t.Fatal(len(l))
	}
	e.want("DELETE", "/api/alerts/runbooks/offline", nil, 200)
	if rb := e.want("GET", "/api/alerts/runbooks/offline", nil, 200); jsonGet(rb, "is_default") != true || jsonGet(rb, "updated_at") != nil {
		t.Fatal(rb)
	}
	e.want("GET", "/api/alerts/runbooks/nothing", nil, 404)

	// On-call + escalation policies.
	sched := e.want("POST", "/api/on-call/schedules", map[string]any{"name": " rota ", "members": []string{e.admin.String()}, "cadence_days": 7}, 200)
	schedID := jsonGet(sched, "id").(string)
	if jsonGet(sched, "name") != "rota" || jsonGet(sched, "current_on_call", "email") != "ad@b.c" {
		t.Fatal(sched)
	}
	e.want("POST", "/api/on-call/schedules", map[string]any{"name": "x", "members": []string{uuid.NewString()}, "cadence_days": 7}, 400)
	e.want("PUT", "/api/on-call/schedules/"+schedID, map[string]any{"name": "rota2", "members": []string{e.admin.String()}, "cadence_days": 3}, 200)
	if l := e.want("GET", "/api/on-call/whoami", nil, 200).([]any); len(l) != 1 || jsonGet(l, 0, "schedule_name") != "rota2" {
		t.Fatal(l)
	}

	steps := []map[string]any{{"after_minutes": 0, "route": "on_call_schedule:" + schedID}, {"after_minutes": 10, "route": "user:" + e.admin.String()}}
	pol := e.want("POST", "/api/escalation-policies", map[string]any{"name": "p", "steps": steps}, 200)
	polID := jsonGet(pol, "id").(string)
	e.want("POST", "/api/escalation-policies", map[string]any{"name": "p", "steps": []map[string]any{{"after_minutes": 0, "route": "user:" + uuid.NewString()}}}, 400)
	e.want("PUT", "/api/alert-rules/"+ruleID+"/escalation-policy", map[string]any{"policy_id": polID}, 200)
	if p := e.want("GET", "/api/escalation-policies/"+polID, nil, 200); jsonGet(p, "used_by_rule_count") != 1.0 {
		t.Fatal(p)
	}
	// Ported verbatim from Rust, bug included: inside the RETURNING subquery
	// the bare `id` binds to alert_rules.id, so update answers 0 here.
	if p := e.want("PUT", "/api/escalation-policies/"+polID, map[string]any{"name": "p2", "steps": steps}, 200); jsonGet(p, "used_by_rule_count") != 0.0 {
		t.Fatal(p)
	}
	del := e.want("DELETE", "/api/on-call/schedules/"+schedID, nil, 200)
	if jsonGet(del, "policies_rewritten") != 1.0 {
		t.Fatal(del)
	}
	e.want("DELETE", "/api/on-call/schedules/"+schedID, nil, 404)
	if p := e.want("GET", "/api/escalation-policies", nil, 200).([]any); jsonGet(p, 0, "steps", 0, "route") != "all_channels" {
		t.Fatal(p)
	}

	// Deleting the user scrubs `user:` routes.
	rtOnCallScrubDeletedUser(e.ctx, e.st.DB, e.admin)
	if p := e.want("GET", "/api/escalation-policies", nil, 200).([]any); jsonGet(p, 0, "steps", 1, "route") != "all_channels" {
		t.Fatal(p)
	}
	e.want("DELETE", "/api/escalation-policies/"+polID, nil, 200)
	e.want("DELETE", "/api/escalation-policies/"+polID, nil, 404)
}

func TestDBAlertEngineAndExpectedStopsSQL(t *testing.T) {
	e := rtAlertsTSetup(t)
	ctx, db := e.ctx, e.st.DB
	srv := &alertEngineServerMetrics{ID: e.server, UserID: e.admin, Name: "local"}

	// The upsert's `$3 >= $4` needs its ::int4 casts under pgx.
	alertEngineCheckThreshold(ctx, db, srv, "cpu", 95, 90, 2, 60, "t", "m")
	alertEngineCheckThreshold(ctx, db, srv, "cpu", 95, 90, 2, 60, "t", "m")
	if s, _ := queryScalar[string](ctx, db, "SELECT current_state FROM alert_state WHERE server_id = $1 AND alert_type = 'cpu'", e.server); s != "firing" {
		t.Fatal(s)
	}
	alertEngineCheckGpuMetric(ctx, db, e.server, e.admin, "local", "gpu_0_temp", "gpu_temperature", 99, 80, 1, 60, "t", "m")
	if s, _ := queryScalar[string](ctx, db, "SELECT current_state FROM alert_state WHERE server_id = $1 AND state_key = 'gpu_0_temp'", e.server); s != "firing" {
		t.Fatal(s)
	}
	if !alertEngineClaimTrendFire(ctx, db, e.server, "memory_leak", 60) || alertEngineClaimTrendFire(ctx, db, e.server, "memory_leak", 60) {
		t.Fatal("claim once per cooldown")
	}
	alertEngineCheckServerOffline(ctx, db, map[uuid.UUID]bool{})
	alertEngineCheckSslExpiry(ctx, db, map[uuid.UUID]bool{})
	alertEngineCheckEscalations(ctx, db)
	if len(alertEngineMaintenanceUsers(ctx, db)) != 0 {
		t.Fatal()
	}

	now := time.Now().UTC()
	ExpectedStopsRecord(ctx, db, e.server, "web", ExpectedStopsReasonOperatorStop, nil)
	ExpectedStopsRecord(ctx, db, e.server, "gone", ExpectedStopsReasonAutoSleep, nil)
	if got := ExpectedStopsExpectedOnServer(ctx, db, e.server); !got["web"] || !got["gone"] {
		t.Fatal(got)
	}
	ExpectedStopsClearAbsent(ctx, db, e.server, nil, now.Add(time.Minute)) // empty listing: no-op
	ExpectedStopsClearAbsent(ctx, db, e.server, []string{"web"}, now.Add(time.Minute))
	if got := ExpectedStopsReasonsOnServer(ctx, db, e.server); len(got) != 1 || got[0].A != "web" || got[0].B != "operator_stop" {
		t.Fatal(got)
	}
	ExpectedStopsClearIfOlderThan(ctx, db, e.server, "web", now.Add(-time.Hour)) // newer than the evidence: kept
	if len(ExpectedStopsExpectedOnServer(ctx, db, e.server)) != 1 {
		t.Fatal("a stop newer than the observation must survive")
	}
	ExpectedStopsResolveOpenContainerDown(ctx, db, e.server, "web")
	ExpectedStopsClear(ctx, db, e.server, "web")
	if len(ExpectedStopsExpectedOnServer(ctx, db, e.server)) != 0 {
		t.Fatal()
	}

	sid, _ := queryScalar[uuid.UUID](ctx, db, "INSERT INTO on_call_schedules (user_id, name, members, cadence_days, anchor_at) VALUES ($1, 'r', $2, 1, NOW() - INTERVAL '1 day 1 hour') RETURNING id", e.admin, []uuid.UUID{uuid.Nil, e.admin})
	if u := OnCallResolveOnCallUser(ctx, db, sid, time.Now()); u == nil || *u != e.admin {
		t.Fatal(u)
	}
	if u := OnCallRouteToUserIds(ctx, db, "on_call_schedule:"+sid.String()); len(u) != 1 {
		t.Fatal(u)
	}
	if rb := AlertRunbooksGetRunbook(ctx, db, "cpu"); rb == nil || !rb.IsDefault {
		t.Fatal(rb)
	}
}
