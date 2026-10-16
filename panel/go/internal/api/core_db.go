package api

// pgx helpers that let sqlx call sites port mechanically:
//
//	sqlx::query_as::<_, T>(sql).bind(a).fetch_all(&db)      → queryAll[T](ctx, db, sql, a)
//	…fetch_one                                              → queryOne[T]   (pgx.ErrNoRows ≙ RowNotFound)
//	…fetch_optional                                         → queryOpt[T]   (*T, nil when no row)
//	sqlx::query_scalar(…).fetch_one / fetch_optional       → queryScalar[T] / queryScalarOpt[T]
//	sqlx::query(…).execute(&db).rows_affected()             → execSQL
//	query_as::<_, (A, B)>                                   → queryAll[Tup2[A, B]] (fields .A .B)
//
// Struct rows follow sqlx FromRow semantics, which neither pgx RowToStruct
// variant matches: every struct field must have a column (else
// "no column found for name: x"), EXTRA columns are ignored — `SELECT *`
// into a struct that predates a column keeps working, which models.rs relies
// on (users.prior_role is deliberately not in User). Column name = `db` tag,
// else the snake_case field name. `db:"-"` skips a field, `db:"col,default"`
// is #[sqlx(default)] (zero value when the column is absent), an embedded
// struct without a tag is #[sqlx(flatten)].
//
// Types: Uuid→uuid.UUID, DateTime<Utc>→time.Time, Option<T>→*T,
// serde_json::Value→json.RawMessage, i32/i64/f64/bool as such, Vec<String>→[]string.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is satisfied by *pgxpool.Pool, *pgxpool.Conn, pgx.Tx and *pgx.Conn
// — sqlx's `impl Executor` (pool or transaction).
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrRowNotFound is what queryOne/queryScalar return for zero rows (sqlx
// RowNotFound). error.rs has no blanket mapping for it — handlers map it
// themselves (usually to 404 or internalError), so do the same.
var ErrRowNotFound = pgx.ErrNoRows

// Tuple rows, scanned POSITIONALLY like sqlx's tuple FromRow (extra columns
// ignored). Use when the Rust code fetched `(A, B, …)`.
type Tup2[A, B any] struct {
	A A
	B B
}
type Tup3[A, B, C any] struct {
	A A
	B B
	C C
}
type Tup4[A, B, C, D any] struct {
	A A
	B B
	C C
	D D
}
type Tup5[A, B, C, D, E any] struct {
	A A
	B B
	C C
	D D
	E E
}
type Tup6[A, B, C, D, E, F any] struct {
	A A
	B B
	C C
	D D
	E E
	F F
}

type tupleRow interface{ scanTargets() []any }

func (t *Tup2[A, B]) scanTargets() []any          { return []any{&t.A, &t.B} }
func (t *Tup3[A, B, C]) scanTargets() []any       { return []any{&t.A, &t.B, &t.C} }
func (t *Tup4[A, B, C, D]) scanTargets() []any    { return []any{&t.A, &t.B, &t.C, &t.D} }
func (t *Tup5[A, B, C, D, E]) scanTargets() []any { return []any{&t.A, &t.B, &t.C, &t.D, &t.E} }
func (t *Tup6[A, B, C, D, E, F]) scanTargets() []any {
	return []any{&t.A, &t.B, &t.C, &t.D, &t.E, &t.F}
}

type dbField struct {
	index      []int
	hasDefault bool
}

var dbFieldCache sync.Map // reflect.Type → map[string]dbField

func dbSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 && !unicode.IsUpper(rune(s[i-1])) {
				b.WriteByte('_')
			}
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

func dbFields(t reflect.Type) map[string]dbField {
	if m, ok := dbFieldCache.Load(t); ok {
		return m.(map[string]dbField)
	}
	m := map[string]dbField{}
	var walk func(t reflect.Type, prefix []int)
	walk = func(t reflect.Type, prefix []int) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag, hasTag := f.Tag.Lookup("db")
			if !f.IsExported() || tag == "-" {
				continue
			}
			idx := append(append([]int{}, prefix...), i)
			if f.Anonymous && !hasTag && f.Type.Kind() == reflect.Struct {
				walk(f.Type, idx) // #[sqlx(flatten)]
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			if name == "" {
				name = dbSnake(f.Name)
			}
			m[name] = dbField{index: idx, hasDefault: opts == "default"}
		}
	}
	walk(t, nil)
	dbFieldCache.Store(t, m)
	return m
}

var (
	scannerType = reflect.TypeFor[sql.Scanner]()
	timeType    = reflect.TypeFor[time.Time]()
)

// rowKind classifies T: tuple (positional), struct (by name), scalar (col 0).
func rowKind[T any]() string {
	var zero T
	if _, ok := any(&zero).(tupleRow); ok {
		return "tuple"
	}
	t := reflect.TypeFor[T]()
	if t.Kind() == reflect.Struct && t != timeType && !reflect.PointerTo(t).Implements(scannerType) {
		return "struct"
	}
	return "scalar"
}

// scanRows collects rows into []T, stopping after limit rows when limit > 0
// (fetch_optional reads the first row and drops the rest).
func scanRows[T any](rows pgx.Rows, limit int) ([]T, error) {
	defer rows.Close()
	fds := rows.FieldDescriptions()
	kind := rowKind[T]()
	var fields map[string]dbField
	if kind == "struct" {
		fields = dbFields(reflect.TypeFor[T]())
		have := map[string]bool{}
		for _, fd := range fds {
			have[fd.Name] = true
		}
		for name, f := range fields {
			if !have[name] && !f.hasDefault {
				return nil, fmt.Errorf("no column found for name: %s", name)
			}
		}
	}
	out := []T{}
	for rows.Next() {
		var v T
		targets := make([]any, len(fds))
		switch kind {
		case "tuple":
			tt := any(&v).(tupleRow).scanTargets()
			if len(fds) < len(tt) {
				return nil, fmt.Errorf("no column found for index: %d", len(fds))
			}
			for i := range targets {
				if i < len(tt) {
					targets[i] = tt[i]
				} else {
					targets[i] = new(any)
				}
			}
		case "struct":
			rv := reflect.ValueOf(&v).Elem()
			for i, fd := range fds {
				if f, ok := fields[fd.Name]; ok {
					targets[i] = rv.FieldByIndex(f.index).Addr().Interface()
				} else {
					targets[i] = new(any) // sqlx ignores columns the struct lacks
				}
			}
		default:
			if len(fds) == 0 {
				return nil, errors.New("no column found for index: 0")
			}
			targets[0] = &v
			for i := 1; i < len(targets); i++ {
				targets[i] = new(any)
			}
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, err
		}
		out = append(out, v)
		if limit > 0 && len(out) == limit {
			return out, nil
		}
	}
	return out, rows.Err()
}

// queryAll is query_as(…).fetch_all.
func queryAll[T any](ctx context.Context, q Querier, sql string, args ...any) ([]T, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return scanRows[T](rows, 0)
}

// queryOpt is fetch_optional: nil when there is no row.
func queryOpt[T any](ctx context.Context, q Querier, sql string, args ...any) (*T, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	all, err := scanRows[T](rows, 1)
	if err != nil || len(all) == 0 {
		return nil, err
	}
	return &all[0], nil
}

// queryOne is fetch_one: ErrRowNotFound when there is no row.
func queryOne[T any](ctx context.Context, q Querier, sql string, args ...any) (T, error) {
	p, err := queryOpt[T](ctx, q, sql, args...)
	if err == nil && p == nil {
		err = ErrRowNotFound
	}
	if err != nil {
		var zero T
		return zero, err
	}
	return *p, nil
}

// queryScalar is query_scalar(…).fetch_one (first column).
func queryScalar[T any](ctx context.Context, q Querier, sql string, args ...any) (T, error) {
	var v T
	err := q.QueryRow(ctx, sql, args...).Scan(&v)
	return v, err
}

// queryScalarOpt is query_scalar(…).fetch_optional. For a nullable column use
// a pointer T (Rust Option<Option<T>> → **T).
func queryScalarOpt[T any](ctx context.Context, q Querier, sql string, args ...any) (*T, error) {
	var v T
	err := q.QueryRow(ctx, sql, args...).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// execSQL is query(…).execute(…) and returns rows_affected.
func execSQL(ctx context.Context, q Querier, sql string, args ...any) (int64, error) {
	tag, err := q.Exec(ctx, sql, args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
