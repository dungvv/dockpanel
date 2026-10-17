package api

import (
	"bytes"
	"crypto/sha512"
	"testing"
	"testing/fstest"
)

func TestResolveMigrationsLikeSqlx(t *testing.T) {
	fsys := fstest.MapFS{
		"m/20260101000000_add_users_table.sql": {Data: []byte("CREATE TABLE u();")},
		"m/3_second.up.sql":                    {Data: []byte("-- no-transaction\nCREATE INDEX CONCURRENTLY i ON u(x);")},
		"m/3_second.down.sql":                  {Data: []byte("DROP INDEX i;")},
		"m/2_x.sql.sql":                        {Data: []byte("SELECT 1; -- no-transaction")},
		"m/README.md":                          {Data: []byte("ignored")},
		"m/nounderscore.sql":                   {Data: []byte("ignored")},
		"m/sub/9_dir.sql":                      {Data: []byte("ignored: directory entry")},
	}
	got, err := resolveMigrations(fsys, "m")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("%d", len(got))
	}
	if got[0].Version != 2 || got[0].Description != "x" || got[0].NoTx {
		t.Fatalf("trim_end_matches strips repeats; no-transaction is a PREFIX test: %+v", got[0])
	}
	up, down := got[1], got[2]
	if up.Down {
		up, down = down, up
	}
	if up.Version != 3 || up.Description != "second" || !up.NoTx || up.Down || down.Version != 3 || !down.Down {
		t.Fatalf("%+v %+v", up, down)
	}
	last := got[3]
	sum := sha512.Sum384([]byte("CREATE TABLE u();"))
	if last.Version != 20260101000000 || last.Description != "add users table" || !bytes.Equal(last.Checksum, sum[:]) {
		t.Fatalf("%+v", last)
	}
	if _, err := resolveMigrations(fstest.MapFS{"m/abc_x.sql": {Data: []byte("")}}, "m"); err == nil {
		t.Fatal("a non-integer version is an error, as in sqlx")
	}
}

func TestEmbeddedMigrationsResolve(t *testing.T) {
	m, err := EmbeddedMigrations()
	if err != nil || len(m) < 100 {
		t.Fatal(len(m), err)
	}
	if m[0].Version != 20260311000000 || m[0].Description != "initial" {
		t.Fatalf("%+v", m[0].Version)
	}
	for i := 1; i < len(m); i++ {
		if m[i].Version <= m[i-1].Version {
			t.Fatalf("duplicate/unsorted version %d", m[i].Version)
		}
	}
}

func TestMigrationLockIDMatchesSqlx(t *testing.T) {
	// Independently: python3 -c "import zlib; print(0x3d32ad9e*zlib.crc32(b'dockpanel'))"
	if got := migrationLockID("dockpanel"); got != 1424348559980441468 {
		t.Fatal(got)
	}
}
