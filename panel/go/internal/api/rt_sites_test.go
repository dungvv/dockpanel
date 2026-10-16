package api

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// ── proxy_port validation — s241 H4 (SSRF + firewall-clobber DoS) ──

func TestRtSitesProxyPortRejectsReservedAndOutOfRange(t *testing.T) {
	// Reserved / system / panel ports would enable loopback SSRF and let the
	// auto-firewall `ufw deny` clobber a global allow.
	for _, p := range []int32{22, 25, 80, 443, 3306, 5432, 6379, 3080, 8443, 9443} {
		if rtSitesIsSafeProxyPort(p) {
			t.Errorf("port %d must be rejected", p)
		}
	}
	for _, p := range []int32{80, 1023, 70000, -1} {
		if rtSitesIsSafeProxyPort(p) {
			t.Errorf("out-of-range %d accepted", p)
		}
	}
	// Ordinary high app ports are accepted (incl. the 5000-5999 app range).
	for _, p := range []int32{8080, 3000, 5001, 65535} {
		if !rtSitesIsSafeProxyPort(p) {
			t.Errorf("port %d must be accepted", p)
		}
	}
}

// The rename gate's copy of panel_update::semver_key ordering.
func TestRtSitesSemverAtLeast(t *testing.T) {
	s := func(v string) *string { return &v }
	cases := []struct {
		v    *string
		want bool
	}{
		{nil, false}, {s("2.141.9"), false}, {s("2.9.0"), false}, {s("garbage"), false},
		{s("2.142.0"), true}, {s("v2.142.0-rc.1"), true}, {s("2.200"), true}, {s("3.0.0"), true},
	}
	for _, c := range cases {
		if got := rtSitesSemverAtLeast(c.v, rtSitesBackupCarryMinAgent); got != c.want {
			t.Errorf("%v: got %v", c.v, got)
		}
	}
}

func TestRtLogsURLEncodeMatchesTheUrlencodingCrate(t *testing.T) {
	if got := rtLogsURLEncode("a b+c/d~e_f.g-h?&="); got != "a%20b%2Bc%2Fd~e_f.g-h%3F%26%3D" {
		t.Fatal(got)
	}
}

// DB-backed: the verbatim SQL against the real schema (DATABASE_URL).
func TestDBSitesGroupQueries(t *testing.T) {
	pool := scratchDB(t)
	ctx := context.Background()
	migs, _ := EmbeddedMigrations()
	if err := RunMigrations(ctx, pool, migs, true); err != nil {
		t.Fatal(err)
	}
	var uid, siteID uuid.UUID
	if err := pool.QueryRow(ctx, "INSERT INTO users (email, password_hash) VALUES ('a@x.io', 'x') RETURNING id").Scan(&uid); err != nil {
		t.Fatal(err)
	}
	var srv uuid.UUID
	if err := pool.QueryRow(ctx, "INSERT INTO servers (user_id, name, agent_token) VALUES ($1, 's', 't') RETURNING id", uid).Scan(&srv); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "INSERT INTO sites (user_id, server_id, domain, runtime) VALUES ($1, $2, 'example.com', 'php') RETURNING id", uid, srv).Scan(&siteID); err != nil {
		t.Fatal(err)
	}
	agents := NewAgentRegistry(nil, pool, "secret")

	// Domain claim: the nil-holder ($2::uuid IS NULL) and self-holder arms.
	occ, err := DomainClaimFindOccupant(ctx, pool, agents, "EXAMPLE.com.", DomainClaimHolderNew)
	if err != nil || occ == nil || *occ != DomainClaimOccupantSite {
		t.Fatalf("new claim: %v %v", occ, err)
	}
	if occ, err = DomainClaimFindOccupant(ctx, pool, agents, "example.com", DomainClaimHolderSite(siteID)); err != nil || occ != nil {
		t.Fatalf("self re-claim: %v %v", occ, err)
	}

	// Crons: RETURNING * maps onto the struct.
	cron, err := queryOne[rtCronsCron](ctx, pool,
		"INSERT INTO crons (site_id, label, command, schedule) VALUES ($1, $2, $3, $4) RETURNING *", siteID, "l", "echo", "* * * * *")
	if err != nil || !cron.Enabled || cron.LastRun != nil {
		t.Fatalf("cron: %+v %v", cron, err)
	}

	// Settings reader defaults, then stored values.
	if en, h, err := rtWordpressReadWpScanSettings(ctx, pool); err != nil || en || h != 24 {
		t.Fatalf("defaults: %v %v %v", en, h, err)
	}

	// System log insert + the full Site row read the handlers use.
	SystemLogLogEvent(ctx, pool, "info", "test", "hello", nil)
	if n, _ := queryScalar[int64](ctx, pool, "SELECT COUNT(*) FROM system_logs WHERE source = 'test'"); n != 1 {
		t.Fatalf("system log rows %d", n)
	}
	site, err := queryOpt[Site](ctx, pool, rtSitesSiteForCallerAll, siteID, uid)
	if err != nil || site == nil {
		t.Fatalf("site read: %v", err)
	}
	if b := rtSitesBuildNginxBody(site); b["runtime"] != "php" || b["proxy_port"] != nil {
		t.Fatalf("body %v", b)
	}

	// Transfer's ANY($2) over a []uuid.UUID.
	if _, err := execSQL(ctx, pool, "UPDATE monitors SET user_id = $1 WHERE site_id = ANY($2)", uid, []uuid.UUID{siteID}); err != nil {
		t.Fatal(err)
	}
}
