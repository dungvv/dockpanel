package api

// Integration tests against a real PostgreSQL. Skipped unless DATABASE_URL is
// set; each test creates (and drops) its own scratch database, so the URL
// only needs a role with CREATEDB. Example:
//
//	docker network create dpnet
//	docker run -d --rm --name dp-pg --network dpnet -e POSTGRES_PASSWORD=pw postgres:16
//	docker run --rm --network dpnet -v "$PWD/../..":/src -v dp-gomod:/go/pkg/mod -w /src/panel/go \
//	  -e DATABASE_URL=postgres://postgres:pw@dp-pg:5432/postgres golang:1.26 go test ./internal/api/ -run DB -v
//
// Rust drop-in check (RUST_MIGRATED_DATABASE_URL): migrate an EMPTY database
// with the Rust binary first — start the old dockpanel-api once with
// DATABASE_URL pointing at it (it migrates on boot, then stop it), or run any
// `sqlx::migrate!("panel/backend/migrations").set_ignore_missing(true).run(&pool)`
// against it — then point RUST_MIGRATED_DATABASE_URL at that database.
// TestDBRustMigratedDatabaseIsAccepted asserts the Go migrator accepts it
// without applying or rewriting a single row.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// scratchDB creates a fresh database and returns a pool on it.
func scratchDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	name := "dp_go_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	cfg, _ := pgxpool.ParseConfig(url)
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close(ctx)
	})
	return pool
}

type migRow struct {
	Version       int64     `db:"version"`
	Description   string    `db:"description"`
	InstalledOn   time.Time `db:"installed_on"`
	Success       bool      `db:"success"`
	Checksum      []byte    `db:"checksum"`
	ExecutionTime int64     `db:"execution_time"`
}

func migRows(t *testing.T, q Querier) []migRow {
	t.Helper()
	rows, err := queryAll[migRow](context.Background(), q, "SELECT * FROM _sqlx_migrations ORDER BY version")
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestDBMigrateFreshThenIdempotent(t *testing.T) {
	pool := scratchDB(t)
	ctx := context.Background()
	migs, _ := EmbeddedMigrations()
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal(err)
	}
	first := migRows(t, pool)
	if len(first) != len(migs) {
		t.Fatalf("%d rows for %d migrations", len(first), len(migs))
	}
	for i, r := range first {
		m := migs[i]
		if r.Version != m.Version || r.Description != m.Description || !r.Success || !bytes.Equal(r.Checksum, m.Checksum) || r.ExecutionTime <= 0 {
			t.Fatalf("row %+v vs %d %q", r, m.Version, m.Description)
		}
	}
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal(err)
	}
	if again := migRows(t, pool); fmt.Sprint(again) != fmt.Sprint(first) {
		t.Fatal("a second run must not touch _sqlx_migrations")
	}

	// An applied migration whose file changed is refused.
	_, _ = pool.Exec(ctx, "UPDATE _sqlx_migrations SET checksum = '\\x00' WHERE version = $1", migs[3].Version)
	var me *MigrateError
	if err := RunMigrations(ctx, pool, migs, true); !errors.As(err, &me) || me.Kind != MigrateVersionMismatch || me.Version != migs[3].Version {
		t.Fatal(err)
	}
	_, _ = pool.Exec(ctx, "UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2", migs[3].Checksum, migs[3].Version)

	// An applied migration the binary has no file for: tolerated only with
	// ignoreMissing (the rollback case).
	_, _ = pool.Exec(ctx, "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES (99999999999999, 'future', true, '\\x01', 1)")
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal("ignoreMissing must tolerate an unknown applied migration:", err)
	}
	if err := RunMigrations(ctx, pool, migs, false); !errors.As(err, &me) || me.Kind != MigrateVersionMissing {
		t.Fatal(err)
	}

	// A dirty row is refused before anything runs.
	_, _ = pool.Exec(ctx, "UPDATE _sqlx_migrations SET success = false WHERE version = 99999999999999")
	if err := RunMigrations(ctx, pool, migs, true); !errors.As(err, &me) || me.Kind != MigrateDirty ||
		err.Error() != "migration 99999999999999 is partially applied; fix and remove row from `_sqlx_migrations` table" {
		t.Fatal(err)
	}

	// A failing migration rolls back together with its bookkeeping row.
	bad := Migration{Version: 99999999999998, Description: "bad", SQL: "CREATE TABLE zz_ok(); SELECT 1/0;", Checksum: []byte{2}}
	_, _ = pool.Exec(ctx, "DELETE FROM _sqlx_migrations WHERE version = 99999999999999")
	if err := RunMigrations(ctx, pool, append(migs, bad), true); !errors.As(err, &me) || me.Kind != MigrateExecute || me.Version != bad.Version {
		t.Fatal(err)
	}
	var n int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM _sqlx_migrations WHERE version = $1", bad.Version).Scan(&n)
	var exists bool
	_ = pool.QueryRow(ctx, "SELECT to_regclass('zz_ok') IS NOT NULL").Scan(&exists)
	if n != 0 || exists {
		t.Fatal("transactional migration left traces", n, exists)
	}
	// And the advisory lock was released (a second session can take it).
	var db string
	_ = pool.QueryRow(ctx, "SELECT current_database()").Scan(&db)
	var got bool
	if err := pool.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", migrationLockID(db)).Scan(&got); err != nil || !got {
		t.Fatal("advisory lock still held", err)
	}
}

func TestDBRustMigratedDatabaseIsAccepted(t *testing.T) {
	url := os.Getenv("RUST_MIGRATED_DATABASE_URL")
	if url == "" {
		t.Skip("RUST_MIGRATED_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	before := migRows(t, pool)
	if len(before) == 0 {
		t.Fatal("expected a database the Rust binary had migrated")
	}
	migs, _ := EmbeddedMigrations()
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal("the Go migrator must accept a Rust-migrated database:", err)
	}
	if after := migRows(t, pool); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatal("nothing may be re-run or rewritten")
	}
	for i, m := range migs {
		if before[i].Description != m.Description || !bytes.Equal(before[i].Checksum, m.Checksum) {
			t.Fatalf("version %d: Rust wrote %q/%x, Go computes %q/%x", m.Version, before[i].Description, before[i].Checksum, m.Description, m.Checksum)
		}
	}
}

func TestDBQueryHelpersFollowSqlxSemantics(t *testing.T) {
	pool := scratchDB(t)
	ctx := context.Background()
	migs, _ := EmbeddedMigrations()
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal(err)
	}
	uid, err := queryScalar[uuid.UUID](ctx, pool, "INSERT INTO users (email, password_hash, role) VALUES ('a@b.c', 'h', 'admin') RETURNING id")
	if err != nil {
		t.Fatal(err)
	}
	// SELECT * into a struct that lacks columns (prior_role, …): ignored.
	u, err := queryOne[User](ctx, pool, "SELECT * FROM users WHERE id = $1", uid)
	if err != nil || u.ID != uid || u.Email != "a@b.c" || u.CreatedAt.IsZero() {
		t.Fatal(u, err)
	}
	// A struct field with no column is an error, as sqlx's ColumnNotFound…
	if _, err := queryOne[User](ctx, pool, "SELECT id, email FROM users"); err == nil || err.Error() == "" {
		t.Fatal("missing column must fail")
	}
	// …unless it is `db:",default"`.
	type partial struct {
		ID    uuid.UUID `db:"id"`
		Extra string    `db:"extra,default"`
	}
	if p, err := queryOne[partial](ctx, pool, "SELECT id FROM users"); err != nil || p.ID != uid {
		t.Fatal(err)
	}
	if _, err := queryOne[User](ctx, pool, "SELECT * FROM users WHERE id = $1", uuid.New()); !errors.Is(err, ErrRowNotFound) {
		t.Fatal(err)
	}
	if p, err := queryOpt[User](ctx, pool, "SELECT * FROM users WHERE id = $1", uuid.New()); p != nil || err != nil {
		t.Fatal(p, err)
	}
	tup, err := queryAll[Tup2[string, *string]](ctx, pool, "SELECT email, prior_role, role FROM users")
	if err != nil || len(tup) != 1 || tup[0].A != "a@b.c" || tup[0].B != nil {
		t.Fatal(tup, err)
	}
	if s, err := queryScalarOpt[*string](ctx, pool, "SELECT prior_role FROM users WHERE id = $1", uid); err != nil || s == nil || *s != nil {
		t.Fatal("Option<Option<T>>: row present, value NULL", s, err)
	}
	if s, _ := queryScalarOpt[string](ctx, pool, "SELECT email FROM users WHERE id = $1", uuid.New()); s != nil {
		t.Fatal()
	}
	emails, err := queryAll[string](ctx, pool, "SELECT email FROM users")
	if err != nil || len(emails) != 1 {
		t.Fatal(emails, err)
	}

	// uuid[], jsonb, timestamptz.
	members := []uuid.UUID{uid, uuid.New()}
	if _, err := execSQL(ctx, pool, "INSERT INTO on_call_schedules (name, members, cadence_days, user_id) VALUES ('r', $1, 7, $2)", members, uid); err != nil {
		t.Fatal(err)
	}
	sch, err := queryOne[OnCallSchedule](ctx, pool, "SELECT * FROM on_call_schedules")
	if err != nil || len(sch.Members) != 2 || sch.Members[1] != members[1] {
		t.Fatal(sch, err)
	}
	steps := json.RawMessage(`[{"after_minutes":5,"route":"all_channels"}]`)
	if _, err := execSQL(ctx, pool, "INSERT INTO escalation_policies (name, steps, user_id) VALUES ('p', $1, $2)", steps, uid); err != nil {
		t.Fatal(err)
	}
	pol, err := queryOne[EscalationPolicy](ctx, pool, "SELECT * FROM escalation_policies")
	var parsed []EscalationStep
	if err != nil || json.Unmarshal(pol.Steps, &parsed) != nil || len(parsed) != 1 || parsed[0].AfterMinutes != 5 {
		t.Fatal(string(pol.Steps), err)
	}
	if n, err := execSQL(ctx, pool, "UPDATE users SET role = 'admin'"); err != nil || n != 1 {
		t.Fatal(n, err)
	}

	// A transaction is a Querier too.
	tx, _ := pool.Begin(ctx)
	if _, err := queryScalar[int64](ctx, tx, "SELECT count(*) FROM users"); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback(ctx)
}

func TestDBEnsureLocalServerAndAuth(t *testing.T) {
	pool := scratchDB(t)
	ctx := context.Background()
	migs, _ := EmbeddedMigrations()
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal(err)
	}
	if id, err := AgentEnsureLocalServer(ctx, pool, "agent-token", testSecret); err != nil || id != uuid.Nil {
		t.Fatal("no admin yet → deferred", id, err)
	}
	admin, _ := queryScalar[uuid.UUID](ctx, pool, "INSERT INTO users (email, password_hash, role) VALUES ('ad@b.c', 'h', 'admin') RETURNING id")
	id, err := AgentEnsureLocalServer(ctx, pool, "agent-token", testSecret)
	if err != nil || id == uuid.Nil {
		t.Fatal(err)
	}
	if again, _ := AgentEnsureLocalServer(ctx, pool, "agent-token", testSecret); again != id {
		t.Fatal("idempotent")
	}
	stored, _ := queryScalar[string](ctx, pool, "SELECT agent_token FROM servers WHERE id = $1", id)
	if stored == "agent-token" || SecretsCryptoDecryptCredentialOrLegacy(stored, testSecret) != "agent-token" {
		t.Fatal("the local token is encrypted at rest")
	}

	st := NewAppState(pool, &Config{JWTSecret: testSecret}, NewAgentClient("/x", "agent-token"), nil, ctx)
	st.Agents = NewAgentRegistry(st.Agent, pool, testSecret)
	st.Agents.SetLocalServerID(id)

	// Agent-token auth (hash lookup).
	r := newReq("GET", "Bearer agent-token")
	if got, err := st.authenticateAgent(r); err != nil || got != id {
		t.Fatal(got, err)
	}
	if _, err := st.authenticateAgent(newReq("GET", "Bearer nope")); err == nil {
		t.Fatal()
	}

	// dp_ API key → Claims with key_id; revoke-all kills older keys.
	keyID, _ := queryScalar[uuid.UUID](ctx, pool, "INSERT INTO api_keys (user_id, name, key_hash, key_prefix, created_at) VALUES ($1, 'k', $2, 'dp_x', NOW() - INTERVAL '1 hour') RETURNING id", admin, hashAgentToken("dp_secretkey"))
	c, err := st.authUser(newReq("POST", "Bearer dp_secretkey"))
	if err != nil || c.Sub != admin || c.KeyID == nil || *c.KeyID != keyID || c.Role != "admin" {
		t.Fatal(c, err)
	}
	st.setSessionsRevokedAt(time.Now().Unix())
	if _, err := st.authUser(newReq("GET", "Bearer dp_secretkey")); err == nil {
		t.Fatal("a key minted before revoke-all must die")
	}

	// ServerScope with X-Server-Id: ownership checked against the DB.
	tok, _ := encodeJWT(&Claims{Sub: admin, Email: "ad@b.c", Role: "admin", Exp: uint64(time.Now().Unix() + 60), Iat: uint64(time.Now().Unix())}, testSecret)
	sr := newReq("GET", "Bearer "+tok)
	sr.Header.Set("X-Server-Id", id.String())
	if got, a, err := st.serverScope(sr); err != nil || got != id || a == nil {
		t.Fatal(err)
	}
	sr.Header.Set("X-Server-Id", uuid.NewString())
	if _, _, err := st.serverScope(sr); err == nil {
		t.Fatal("a server the user does not own is refused")
	}

	// Suspend → stash + session revocation; unsuspend restores exactly.
	jti := uuid.NewString()
	_, _ = execSQL(ctx, pool, "INSERT INTO user_sessions (user_id, jti) VALUES ($1, $2)", admin, jti)
	if n, err := suspendAccount(ctx, st, admin, ""); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if !st.isBlacklisted(jti) {
		t.Fatal("suspending revokes live sessions")
	}
	if n, _ := suspendAccount(ctx, st, admin, ""); n != 0 {
		t.Fatal("re-suspend must not overwrite the stash")
	}
	if role, err := unsuspendAccount(ctx, st, admin, []string{"admin"}); err != nil || role != nil {
		t.Fatal("a denied role stays suspended", role, err)
	}
	if role, err := unsuspendAccount(ctx, st, admin, nil); err != nil || role == nil || *role != "admin" {
		t.Fatal(role, err)
	}
}

func newReq(method, auth string) *http.Request {
	r := httptest.NewRequest(method, "/", nil)
	r.Header.Set("Authorization", auth)
	return r
}
