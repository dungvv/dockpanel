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

// Omitted keeps, explicit null clears, a value sets — the distinction a
// plain pointer cannot carry.
func TestRtBackupOrchestratorUpdateRequestDoubleOption(t *testing.T) {
	var req rtBackupOrchestratorUpdatePolicyRequest
	if err := decodeJSONBytes([]byte(`{"name":"x","destination_id":null,"server_id":"00000000-0000-0000-0000-000000000001"}`), &req); err != nil {
		t.Fatal(err)
	}
	if !req.DestinationID.Set || req.DestinationID.Val != nil {
		t.Fatal("explicit null must read as set-to-null")
	}
	if !req.ServerID.Set || req.ServerID.Val == nil {
		t.Fatal("a value must read as set")
	}
	req = rtBackupOrchestratorUpdatePolicyRequest{}
	if err := decodeJSONBytes([]byte(`{"name":"x"}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.DestinationID.Set || req.ServerID.Set {
		t.Fatal("omitted must read as unset")
	}
}

func TestRtBackupOrchestratorSlugAndCron(t *testing.T) {
	if got := rtBackupOrchestratorSlug("my site.com/ü!x"); got != "my-site.com-x" {
		t.Fatal(got)
	}
	if !rtBackupOrchestratorIsValidCron5("0 2 * * *") || rtBackupOrchestratorIsValidCron5("0 2 * *") {
		t.Fatal("cron5")
	}
}

// TestDBBackupDataHandlers drives the data group's routes and background
// ticks against a migrated schema: every SQL statement that does not need a
// live agent runs at least once, so a column typo or a scan-type mismatch
// fails here rather than in production.
func TestDBBackupDataHandlers(t *testing.T) {
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
	local, err := AgentEnsureLocalServer(ctx, pool, "agent-token", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	st := NewAppState(pool, &Config{JWTSecret: testSecret}, NewAgentClient("/nonexistent.sock", "agent-token"), nil, ctx)
	st.Agents = NewAgentRegistry(st.Agent, pool, testSecret)
	st.Agents.SetLocalServerID(local)

	must := func(sql string, args ...any) uuid.UUID {
		t.Helper()
		id, err := queryScalar[uuid.UUID](ctx, pool, sql, args...)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return id
	}
	site := must("INSERT INTO sites (user_id, domain, server_id, status) VALUES ($1, 'a.test', $2, 'active') RETURNING id", admin, local)
	enc, _ := SecretsCryptoEncryptCredential("pw", testSecret)
	dbID := must("INSERT INTO databases (site_id, name, engine, db_user, db_password_enc, container_id, port) VALUES ($1, 'blog', 'postgres', 'blog', $2, 'c1', 5433) RETURNING id", site, enc)
	siteBackup := must("INSERT INTO backups (site_id, filename, size_bytes) VALUES ($1, 'a.tar.gz', 10) RETURNING id", site)
	must("INSERT INTO database_backups (database_id, server_id, filename, size_bytes, db_type, db_name) VALUES ($1, $2, 'blog.sql.gz', 5, 'postgres', 'blog') RETURNING id", dbID, local)
	must("INSERT INTO volume_backups (container_id, container_name, server_id, volume_name, filename, size_bytes) VALUES ('cid', 'app', $1, 'data', 'v.tar.gz', 7) RETURNING id", local)

	rt := &Router{St: st, mux: http.NewServeMux()}
	for _, reg := range []func(*Router){rtBackupsRegister, rtBackupDestinationsRegister, rtBackupSchedulesRegister, rtDatabasesRegister, rtBackupOrchestratorRegister} {
		reg(rt)
	}
	now := uint64(time.Now().Unix())
	tok, _ := encodeJWT(&Claims{Sub: admin, Email: "ad@b.c", Role: "admin", Exp: now + 600, Iat: now}, testSecret)
	do := func(method, path, body string, want int) map[string]any {
		t.Helper()
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		} else {
			rd = strings.NewReader("")
		}
		r := httptest.NewRequest(method, path, rd)
		r.Header.Set("Authorization", "Bearer "+tok)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if out == nil {
			out = map[string]any{"_raw": w.Body.String()}
		}
		return out
	}

	// Orchestrator reads.
	if h := do("GET", "/api/backup-orchestrator/health", "", 200); h["sla_unavailable"] != false || h["total_db_backups"] != float64(1) {
		t.Fatal(h)
	}
	if all := do("GET", "/api/backup-orchestrator/all", "", 200); all["total"] != float64(3) {
		t.Fatal(all)
	}
	do("GET", "/api/backup-orchestrator/all?kind=bogus", "", 400)
	do("GET", "/api/backup-orchestrator/all?kind=volume&server_id="+local.String(), "", 200)
	for _, p := range []string{"db-backups", "volume-backups", "verifications", "drills", "storage-history"} {
		do("GET", "/api/backup-orchestrator/"+p, "", 200)
	}
	if rep := do("GET", "/api/backup-orchestrator/chain-report/site/"+siteBackup.String(), "", 200); rep["backup"].(map[string]any)["resource_name"] != "a.test" {
		t.Fatal(rep)
	}
	do("GET", "/api/backup-orchestrator/chain-report/bogus/"+siteBackup.String(), "", 400)

	// Policies.
	pol := do("POST", "/api/backup-orchestrator/policies", `{"name":"p1","retention_count":999}`, 201)
	if pol["retention_count"] != float64(365) {
		t.Fatal(pol)
	}
	pid := pol["id"].(string)
	if up := do("PUT", "/api/backup-orchestrator/policies/"+pid, `{"name":"","destination_id":null}`, 200); up["name"] != "p1" || up["retention_count"] != float64(365) {
		t.Fatal(up)
	}
	do("PUT", "/api/backup-orchestrator/policies/"+pid, `{"name":"x","schedule":"bad"}`, 400)
	do("POST", "/api/backup-orchestrator/policies/protect-all", "", 201)
	do("POST", "/api/backup-orchestrator/policies/protect-all", "", 409)
	do("DELETE", "/api/backup-orchestrator/policies/"+pid, "", 200)
	do("DELETE", "/api/backup-orchestrator/policies/"+pid, "", 404)

	// Destinations: masked on the way out, carried across on edit.
	d := do("POST", "/api/backup-destinations", `{"name":"d","dtype":"s3","config":{"bucket":"b","secret_key":"x"}}`, 201)
	if d["config"].(map[string]any)["secret_key"] != rtBackupDestinationsMask {
		t.Fatal(d)
	}
	did := d["id"].(string)
	do("POST", "/api/backup-destinations", `{"name":"d","dtype":"ftp","config":{}}`, 400)
	do("GET", "/api/backup-destinations", "", 200)
	do("GET", "/api/backup-destinations/selectable", "", 200)
	do("PUT", "/api/backup-destinations/"+did, `{"config":{"bucket":"c","secret_key":"********"}}`, 200)
	stored, _ := queryScalar[map[string]any](ctx, pool, "SELECT config FROM backup_destinations WHERE id = $1", did)
	if got, _ := SecretsCryptoDecryptCredential(stored["secret_key"].(string), testSecret); got != "x" || stored["bucket"] != "c" {
		t.Fatal(stored, got)
	}

	// Schedules.
	do("PUT", "/api/sites/"+site.String()+"/backup-schedule", `{"destination_id":"`+did+`","schedule":"0 2 * *"}`, 400)
	do("PUT", "/api/sites/"+site.String()+"/backup-schedule", `{"destination_id":"`+did+`","schedule":"0 2 * * *"}`, 200)
	do("GET", "/api/sites/"+site.String()+"/backup-schedule", "", 200)
	if s := do("GET", "/api/backup-setup-status", "", 200); s["has_schedule"] != true || s["has_backup"] != true {
		t.Fatal(s)
	}
	if rm := do("DELETE", "/api/backup-destinations/"+did, "", 200); rm["warning"] == nil {
		t.Fatal(rm)
	}
	do("DELETE", "/api/sites/"+site.String()+"/backup-schedule", "", 200)
	do("GET", "/api/sites/"+site.String()+"/backups", "", 200)

	// Databases.
	if raw := do("GET", "/api/databases", "", 200)["_raw"].(string); !strings.Contains(raw, `"remote_allow":[]`) {
		t.Fatal(raw)
	}
	if c := do("GET", "/api/databases/"+dbID.String()+"/credentials", "", 200); c["password"] != "pw" || c["internal_host"] != "dockpanel-db-blog" {
		t.Fatal(c)
	}
	do("GET", "/api/databases/"+dbID.String()+"/pitr", "", 200)
	do("PUT", "/api/databases/"+dbID.String()+"/pitr", `{"pitr_enabled":true,"retention_hours":5000}`, 200)
	if p := do("GET", "/api/databases/"+dbID.String()+"/pitr", "", 200); p["retention_hours"] != float64(720) {
		t.Fatal(p)
	}
	do("POST", "/api/databases/"+dbID.String()+"/pitr/restore", `{}`, 501)
	do("GET", "/api/databases/"+dbID.String()+"/tables/bad;name", "", 400)
	do("DELETE", "/api/databases/"+dbID.String()+"/remote-access", "", 404)
	do("POST", "/api/databases", `{"site_id":"`+site.String()+`","stack_id":"`+site.String()+`","name":"x"}`, 400)
	if n, err := rtDatabasesFindAvailablePort(ctx, st, "postgres"); err != nil || n != 5434 {
		t.Fatal(n, err)
	}
	if ok, err := rtDatabasesReserveResellerDbSlot(ctx, st, admin); err != nil || ok {
		t.Fatal(ok, err)
	}
	if specs := rtBackupsSiteDatabaseSpecs(ctx, pool, testSecret, site); len(specs.Specs) != 1 || specs.Expected() != 1 {
		t.Fatal(specs)
	}

	// Background ticks: no agent is reachable, so only their SQL is under test.
	_, _ = execSQL(ctx, pool, "INSERT INTO backup_policies (user_id, name, verify_after_backup, drill_enabled, drill_schedule) VALUES ($1, 'v', TRUE, TRUE, '* * * * *')", admin)
	if err := backupVerifierTick(ctx, pool, st.Agents); err != nil {
		t.Fatal(err)
	}
	if err := backupPolicyExecutorTick(ctx, pool, st.Agents, testSecret); err != nil {
		t.Fatal(err)
	}
	if err := drillSchedulerTick(ctx, pool, st.Agents); err != nil {
		t.Fatal(err)
	}
	if err := backupSchedulerTick(ctx, pool, st.Agents, testSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := PanelSnapshotListSnapshots(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := PanelSnapshotRetentionSweep(ctx, pool); err != nil {
		t.Fatal(err)
	}
}
