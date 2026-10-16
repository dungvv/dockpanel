package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// DB-backed: runs the drift fetchers' SQL against the real schema (no Rust
// counterpart; the Rust tests cover only the pure comparators).
func TestDBDriftBuildReport(t *testing.T) {
	pool := scratchDB(t)
	ctx := context.Background()
	migs, _ := EmbeddedMigrations()
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal(err)
	}
	admin, _ := queryScalar[uuid.UUID](ctx, pool, "INSERT INTO users (email, password_hash, role) VALUES ('ad@b.c', 'h', 'admin') RETURNING id")
	mkServer := func(name string, local bool) uuid.UUID {
		id, err := queryScalar[uuid.UUID](ctx, pool,
			"INSERT INTO servers (user_id, name, agent_token, agent_token_hash, status, is_local) "+
				"VALUES ($1, $2, 't', $3, 'online', $4) RETURNING id", admin, name, uuid.NewString(), local)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	ref, other := mkServer("ref", true), mkServer("other", false)
	for _, s := range []struct {
		srv    uuid.UUID
		domain string
	}{{ref, "a.com"}, {ref, "refonly.com"}, {other, "a.com"}} {
		if _, err := execSQL(ctx, pool, "INSERT INTO sites (user_id, server_id, domain, runtime, status) VALUES ($1, $2, $3, 'static', 'active')",
			admin, s.srv, s.domain); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := execSQL(ctx, pool, "INSERT INTO alert_rules (user_id, server_id, notify_slack_url) VALUES ($1, $2, 'https://x')", admin, ref); err != nil {
		t.Fatal(err)
	}

	rep, err := DriftBuildReport(ctx, pool, ref, []uuid.UUID{other})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Reference.Name != "ref" || rep.ServersCompared != 1 || rep.TotalDriftedServers != 1 || len(rep.Entities) != 4 {
		t.Fatalf("%+v", rep)
	}
	sites := rep.Entities[1].Servers[0]
	if *sites.OnlyReference == nil || (*sites.OnlyReference)[0] != "refonly.com" || len(*sites.ValueDiffs) != 0 {
		t.Fatalf("%+v", sites)
	}
	if ar := rep.Entities[0].Servers[0]; ar.InSync || ar.Note == nil {
		t.Fatalf("%+v", ar)
	}
	if cov := rep.Entities[3].Servers[0]; cov.InSync || cov.Coverage.TotalSites != 1 || cov.ReferenceCoverage.TotalSites != 2 {
		t.Fatalf("%+v", cov)
	}
	b, _ := json.Marshal(rep)
	if strings.Contains(string(b), "https://x") || !strings.Contains(string(b), `"only_here":[]`) {
		t.Fatal(string(b))
	}
}
