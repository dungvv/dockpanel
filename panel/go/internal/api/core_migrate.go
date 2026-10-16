package api

// A drop-in replacement for `sqlx::migrate!("./migrations")` (sqlx 0.8.6,
// sqlx-core/src/migrate + sqlx-postgres/src/migrate.rs), so a database first
// migrated by the Rust binary is accepted as-is and vice versa:
//
//   - same `_sqlx_migrations` table and columns;
//   - version/description parsed from the filename exactly as
//     sqlx_core::migrate::resolve_blocking does (`<VERSION>_<DESC>.sql`,
//     description = rest minus the type suffix, `_` → ` `; non-matching files
//     ignored; a non-integer version is an error);
//   - checksum = SHA-384 of the file bytes;
//   - session advisory lock id = 0x3d32ad9e * crc32(current_database());
//   - each migration plus its bookkeeping row in ONE transaction, unless the
//     file STARTS WITH `-- no-transaction` (sqlx 0.8 checks the prefix only);
//   - refuse a dirty (success = false) row and a checksum mismatch, with
//     sqlx's error texts.
//
// The SQL files in migrations/ are byte-identical copies of
// panel/backend/migrations (a test enforces it while that tree exists).

import (
	"context"
	"crypto/sha512"
	"embed"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migration is one resolved migration file.
type Migration struct {
	Version     int64
	Description string
	// Down migrations (*.down.sql) are resolved but never applied by Run.
	Down     bool
	SQL      string
	Checksum []byte
	NoTx     bool
}

// MigrateErrorKind mirrors the sqlx MigrateError variants Run can produce.
type MigrateErrorKind int

const (
	MigrateDirty MigrateErrorKind = iota
	MigrateVersionMissing
	MigrateVersionMismatch
	MigrateExecute
	MigrateSource
)

// MigrateError carries sqlx's message text.
type MigrateError struct {
	Kind    MigrateErrorKind
	Version int64
	Err     error
}

func (e *MigrateError) Error() string {
	switch e.Kind {
	case MigrateDirty:
		return fmt.Sprintf("migration %d is partially applied; fix and remove row from `_sqlx_migrations` table", e.Version)
	case MigrateVersionMissing:
		return fmt.Sprintf("migration %d was previously applied but is missing in the resolved migrations", e.Version)
	case MigrateVersionMismatch:
		return fmt.Sprintf("migration %d was previously applied but has been modified", e.Version)
	case MigrateSource:
		return fmt.Sprintf("while resolving migrations: %v", e.Err)
	default:
		if e.Version != 0 {
			return fmt.Sprintf("while executing migration %d: %v", e.Version, e.Err)
		}
		return fmt.Sprintf("while executing migrations: %v", e.Err)
	}
}

func (e *MigrateError) Unwrap() error { return e.Err }

// resolveMigrations reads every file of dir in fsys, sqlx-style.
func resolveMigrations(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, &MigrateError{Kind: MigrateSource, Err: fmt.Errorf("error reading migration directory %s: %w", dir, err)}
	}
	var out []Migration
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		ver, rest, ok := strings.Cut(name, "_")
		if !ok || !strings.HasSuffix(rest, ".sql") {
			continue // not <VERSION>_<DESCRIPTION>.sql; ignored
		}
		v, err := strconv.ParseInt(ver, 10, 64)
		if err != nil {
			return nil, &MigrateError{Kind: MigrateSource, Err: fmt.Errorf(
				"error parsing migration filename %q; expected integer version prefix (e.g. `01_foo.sql`)", name)}
		}
		suffix, down := ".sql", false
		switch {
		case strings.HasSuffix(rest, ".up.sql"):
			suffix = ".up.sql"
		case strings.HasSuffix(rest, ".down.sql"):
			suffix, down = ".down.sql", true
		}
		desc := rest
		for strings.HasSuffix(desc, suffix) { // Rust trim_end_matches strips repeats
			desc = strings.TrimSuffix(desc, suffix)
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil || !utf8.Valid(b) {
			return nil, &MigrateError{Kind: MigrateSource, Err: fmt.Errorf("error reading contents of migration %s: %v", name, err)}
		}
		sum := sha512.Sum384(b)
		out = append(out, Migration{
			Version:     v,
			Description: strings.ReplaceAll(desc, "_", " "),
			Down:        down,
			SQL:         string(b),
			Checksum:    sum[:],
			NoTx:        strings.HasPrefix(string(b), "-- no-transaction"),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// EmbeddedMigrations resolves the migrations compiled into the binary.
func EmbeddedMigrations() ([]Migration, error) { return resolveMigrations(migrationsFS, "migrations") }

// migrationLockID is sqlx's generate_lock_id (inspired by Rails).
func migrationLockID(database string) int64 {
	return 0x3d32ad9e * int64(crc32.ChecksumIEEE([]byte(database)))
}

// RunMigrations applies migs to the database, holding sqlx's advisory lock.
//
// ignoreMissing must be true for the panel (main.rs set_ignore_missing): it
// supports ROLLBACK, and after an update applied migration N+1 and was rolled
// back, the older binary sees an applied migration it has no file for.
// Strict validation rejected that (VersionMissing), the restored api
// crash-looped under Restart=always into a permanent 502. Migrations are
// additive, so an older binary on a newer schema is safe; missing migrations
// are still applied — only unknown EXTRA ones are tolerated.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migs []Migration, ignoreMissing bool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return &MigrateError{Kind: MigrateExecute, Err: err}
	}
	defer conn.Release()
	c := conn.Conn()

	var db string
	if err := c.QueryRow(ctx, "SELECT current_database()").Scan(&db); err != nil {
		return &MigrateError{Kind: MigrateExecute, Err: err}
	}
	lock := migrationLockID(db)
	// Blocks until acquired, like sqlx.
	if _, err := c.Exec(ctx, "SELECT pg_advisory_lock($1)", lock); err != nil {
		return &MigrateError{Kind: MigrateExecute, Err: err}
	}
	// sqlx unlocks only on success (its process then panics anyway); unlock
	// on every path so a pooled connection never keeps the lock.
	defer func() { _, _ = c.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", lock) }()

	if _, err := c.Exec(ctx, `
CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
);
                `); err != nil {
		return &MigrateError{Kind: MigrateExecute, Err: err}
	}

	var dirty int64
	switch err := c.QueryRow(ctx, "SELECT version FROM _sqlx_migrations WHERE success = false ORDER BY version LIMIT 1").Scan(&dirty); {
	case err == nil:
		return &MigrateError{Kind: MigrateDirty, Version: dirty}
	case !errors.Is(err, pgx.ErrNoRows):
		return &MigrateError{Kind: MigrateExecute, Err: err}
	}

	applied, err := queryAll[Tup2[int64, []byte]](ctx, c, "SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
	if err != nil {
		return &MigrateError{Kind: MigrateExecute, Err: err}
	}
	known := map[int64]bool{}
	for _, m := range migs {
		known[m.Version] = true
	}
	appliedSum := map[int64][]byte{}
	for _, a := range applied {
		if !ignoreMissing && !known[a.A] {
			return &MigrateError{Kind: MigrateVersionMissing, Version: a.A}
		}
		appliedSum[a.A] = a.B
	}

	for _, m := range migs {
		if m.Down {
			continue
		}
		if sum, ok := appliedSum[m.Version]; ok {
			if string(sum) != string(m.Checksum) {
				return &MigrateError{Kind: MigrateVersionMismatch, Version: m.Version}
			}
			continue
		}
		if err := applyMigration(ctx, c, m); err != nil {
			return err
		}
	}
	return nil
}

// applyMigration runs one migration and its bookkeeping row together (in a
// transaction unless NoTx), then records the elapsed time. A no-arg Exec uses
// the simple protocol, so a multi-statement file runs as sqlx ran it.
func applyMigration(ctx context.Context, c *pgx.Conn, m Migration) error {
	start := time.Now()
	exec := func(tx Querier) error {
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			return &MigrateError{Kind: MigrateExecute, Version: m.Version, Err: err}
		}
		if _, err := tx.Exec(ctx, `
    INSERT INTO _sqlx_migrations ( version, description, success, checksum, execution_time )
    VALUES ( $1, $2, TRUE, $3, -1 )
                `, m.Version, m.Description, m.Checksum); err != nil {
			return &MigrateError{Kind: MigrateExecute, Err: err}
		}
		return nil
	}
	if m.NoTx {
		if err := exec(c); err != nil {
			return err
		}
	} else {
		tx, err := c.Begin(ctx)
		if err != nil {
			return &MigrateError{Kind: MigrateExecute, Err: err}
		}
		if err := exec(tx); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return &MigrateError{Kind: MigrateExecute, Err: err}
		}
	}
	// The process may die here and lose the elapsed time — sqlx accepts that
	// risk; the value exists only for lineage/debugging.
	if _, err := c.Exec(ctx, `
    UPDATE _sqlx_migrations
    SET execution_time = $1
    WHERE version = $2
                `, time.Since(start).Nanoseconds(), m.Version); err != nil {
		return &MigrateError{Kind: MigrateExecute, Err: err}
	}
	return nil
}
