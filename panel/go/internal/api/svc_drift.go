package api

// Phase 4 W5: fleet configuration-drift detection.
//
// A read-only report answering "is my fleet's operational posture
// consistent?". DockPanel is a single hub DB + thin agents, so every server's
// declared config already lives centrally keyed by `server_id`. Drift is
// therefore a LOCAL cross-`server_id` diff — no remote agent pull,
// offline-tolerant, computed on demand (operator-triggered, no background
// scan).
//
// v1 is REPORT-ONLY. Reconcile/push (source-of-truth → apply to others) is
// deferred to W5.2 — it is net-new cross-server mutation with no existing
// transport ("report, not an enforcement loop"). Desired-vs-actual drift
// against the agent's live `GET /iac/export` is deferred to W5.3.
//
// Four entities in v1, each compared in its most meaningful form:
//   - `alert_rules`     — SINGLETON: one row per server, whole-row posture diff (flagship).
//   - `sites`           — COLLECTION: per-domain inventory asymmetry + per-site config diff.
//   - `crons`           — COLLECTION: per (domain, command) job parity.
//   - `backup_coverage` — SUMMARY: per-server derived coverage (sites total / backed-up / destinations).
//
// The comparators (driftCompareConfig, driftDiffSingleton, driftDiffCollection)
// are pure and unit-tested with in-memory rows; the fetchers project each
// entity's config columns to a JSONB object in SQL so the engine diffs a
// generic JSON object per row.

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Secret-ish columns compared by presence only — the report never surfaces
// the value, only "set" vs "unset", so a rotated secret doesn't read as drift
// and a leaked value never reaches the UI.
var (
	driftAlertSensitive = []string{"notify_slack_url", "notify_discord_url"}
	driftNoSensitive    = []string{}
)

// ─── Wire types ────────────────────────────────────────────────────────────

type DriftServerRef struct {
	ServerID   uuid.UUID  `json:"server_id"`
	Name       string     `json:"name"`
	IsLocal    bool       `json:"is_local"`
	Status     string     `json:"status"`
	LastSeenAt *time.Time `json:"last_seen_at"`
}

type DriftFieldDiff struct {
	Field string `json:"field"`
	// The reference server's value (or the "set"/"unset" token for a sensitive field).
	Reference any `json:"reference"`
	// This server's value (or token).
	Current   any  `json:"current"`
	Sensitive bool `json:"sensitive"`
}

type DriftEntityValueDiff struct {
	// Natural identity of the drifted entity (e.g. a site domain).
	Identity string           `json:"identity"`
	Fields   []DriftFieldDiff `json:"fields"`
}

type DriftCoverageMetrics struct {
	TotalSites   int64 `json:"total_sites"`
	BackedUp     int64 `json:"backed_up"`
	Unprotected  int64 `json:"unprotected"`
	Destinations int64 `json:"destinations"`
}

type DriftServerEntityDrift struct {
	ServerID   uuid.UUID  `json:"server_id"`
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	InSync     bool       `json:"in_sync"`
	Note       *string    `json:"note,omitempty"`
	// SINGLETON
	FieldDiffs *[]DriftFieldDiff `json:"field_diffs,omitempty"`
	// COLLECTION (pointers: an empty-but-present list still serializes)
	OnlyHere      *[]string               `json:"only_here,omitempty"`
	OnlyReference *[]string               `json:"only_reference,omitempty"`
	ValueDiffs    *[]DriftEntityValueDiff `json:"value_diffs,omitempty"`
	// SUMMARY
	Coverage          *DriftCoverageMetrics `json:"coverage,omitempty"`
	ReferenceCoverage *DriftCoverageMetrics `json:"reference_coverage,omitempty"`
}

type DriftEntityDrift struct {
	Entity string `json:"entity"`
	Label  string `json:"label"`
	Mode   string `json:"mode"`
	// Number of compared servers that diverge from the reference for this entity.
	DriftCount int                      `json:"drift_count"`
	Servers    []DriftServerEntityDrift `json:"servers"`
}

type DriftReport struct {
	Reference           DriftServerRef     `json:"reference"`
	GeneratedAt         time.Time          `json:"generated_at"`
	ServersCompared     int                `json:"servers_compared"`
	TotalDriftedServers int                `json:"total_drifted_servers"`
	Entities            []DriftEntityDrift `json:"entities"`
	Note                *string            `json:"note,omitempty"`
}

// ─── Pure comparators (unit-tested, no DB) ─────────────────────────────────

func driftPresenceToken(v any) string {
	switch x := v.(type) {
	case nil:
		return "unset"
	case string:
		if x == "" {
			return "unset"
		}
	}
	return "set"
}

// DriftCompareConfig diffs two config objects field by field. Keys present in
// only one side are diffed against null. Sensitive keys are reduced to a
// presence token so a rotated/differing secret does not read as drift and no
// value is surfaced. Deterministic order (keys sorted). Values are JSON
// decoded with UseNumber, so equality matches serde_json::Value's.
func DriftCompareConfig(reference, current any, sensitive []string) []DriftFieldDiff {
	r, _ := reference.(map[string]any)
	c, _ := current.(map[string]any)

	keySet := map[string]struct{}{}
	for k := range r {
		keySet[k] = struct{}{}
	}
	for k := range c {
		keySet[k] = struct{}{}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := []DriftFieldDiff{}
	for _, k := range keys {
		rv, cv := r[k], c[k]
		if slices.Contains(sensitive, k) {
			rt, ct := driftPresenceToken(rv), driftPresenceToken(cv)
			if rt != ct {
				out = append(out, DriftFieldDiff{Field: k, Reference: rt, Current: ct, Sensitive: true})
			}
		} else if !reflect.DeepEqual(rv, cv) {
			out = append(out, DriftFieldDiff{Field: k, Reference: rv, Current: cv})
		}
	}
	return out
}

type DriftSingletonResult struct {
	InSync     bool
	FieldDiffs *[]DriftFieldDiff
	Note       *string
}

// DriftDiffSingleton compares a reference server's single config row against
// another server's (nil = no row).
func DriftDiffSingleton(reference, current any, sensitive []string) DriftSingletonResult {
	note := func(s string) *string { return &s }
	switch {
	case reference != nil && current != nil:
		diffs := DriftCompareConfig(reference, current, sensitive)
		res := DriftSingletonResult{InSync: len(diffs) == 0}
		if len(diffs) > 0 {
			res.FieldDiffs = &diffs
		}
		return res
	case reference != nil:
		return DriftSingletonResult{Note: note("No explicit configuration here (using defaults) while the reference has one")}
	case current != nil:
		return DriftSingletonResult{Note: note("Configured here but the reference server has none")}
	default:
		return DriftSingletonResult{InSync: true, Note: note("Neither server has explicit configuration (both default)")}
	}
}

// DriftRow is one keyed config row of a COLLECTION entity.
type DriftRow struct {
	Identity string
	Config   any
}

type DriftCollectionResult struct {
	InSync        bool
	OnlyHere      []string
	OnlyReference []string
	ValueDiffs    []DriftEntityValueDiff
}

// DriftDiffCollection compares two keyed collections of config rows. Produces
// three buckets: entities present only here, only on the reference, and
// shared-identity rows whose config differs.
func DriftDiffCollection(reference, current []DriftRow, sensitive []string) DriftCollectionResult {
	// Later duplicates win, as a HashMap collect does.
	rmap := map[string]any{}
	for _, row := range reference {
		rmap[row.Identity] = row.Config
	}
	cmap := map[string]any{}
	for _, row := range current {
		cmap[row.Identity] = row.Config
	}

	onlyHere := []string{}
	for _, row := range current {
		if _, ok := rmap[row.Identity]; !ok {
			onlyHere = append(onlyHere, row.Identity)
		}
	}
	onlyReference := []string{}
	for _, row := range reference {
		if _, ok := cmap[row.Identity]; !ok {
			onlyReference = append(onlyReference, row.Identity)
		}
	}
	slices.Sort(onlyHere)
	onlyHere = slices.Compact(onlyHere)
	slices.Sort(onlyReference)
	onlyReference = slices.Compact(onlyReference)

	shared := []string{}
	for k := range rmap {
		if _, ok := cmap[k]; ok {
			shared = append(shared, k)
		}
	}
	slices.Sort(shared)

	valueDiffs := []DriftEntityValueDiff{}
	for _, id := range shared {
		if fields := DriftCompareConfig(rmap[id], cmap[id], sensitive); len(fields) > 0 {
			valueDiffs = append(valueDiffs, DriftEntityValueDiff{Identity: id, Fields: fields})
		}
	}

	return DriftCollectionResult{
		InSync:        len(onlyHere) == 0 && len(onlyReference) == 0 && len(valueDiffs) == 0,
		OnlyHere:      onlyHere,
		OnlyReference: onlyReference,
		ValueDiffs:    valueDiffs,
	}
}

// DriftCoverageInSync: a server's backup posture is in sync when every one of
// its sites has an enabled backup schedule and at least one destination
// exists (or it has no sites at all — nothing to protect).
func DriftCoverageInSync(m DriftCoverageMetrics) bool {
	return m.TotalSites == 0 || (m.Unprotected == 0 && m.Destinations > 0)
}

// ─── DB fetchers (config projected to JSONB in SQL) ────────────────────────

type driftServerMeta struct {
	name       string
	isLocal    bool
	status     string
	lastSeenAt *time.Time
}

func driftDecode(raw json.RawMessage) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	err := d.Decode(&v)
	return v, err
}

func driftFetchServerMeta(ctx context.Context, db Querier, ids []uuid.UUID) (map[uuid.UUID]driftServerMeta, error) {
	rows, err := queryAll[Tup5[uuid.UUID, string, bool, string, *time.Time]](ctx, db,
		"SELECT id, name, is_local, status, last_seen_at "+
			"FROM servers WHERE id = ANY($1)", ids)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]driftServerMeta, len(rows))
	for _, r := range rows {
		out[r.A] = driftServerMeta{name: r.B, isLocal: r.C, status: r.D, lastSeenAt: r.E}
	}
	return out, nil
}

func driftFetchAlertRules(ctx context.Context, db Querier, ids []uuid.UUID) (map[uuid.UUID]any, error) {
	// NULL server_id (the user's default rule) is excluded by `= ANY`.
	//
	// ⚠ CORRECTNESS (s432 review): `alert_rules` enforces only
	// `UNIQUE(user_id, server_id)`, not `UNIQUE(server_id)` — a caller other
	// than the server's owner can create a stray second row for the same
	// server_id (alerts update_server_rules takes `server_id` straight from
	// the URL path with no ownership check — a real, separate gap). Keying
	// unfiltered rows by server_id would silently pick whichever row Postgres
	// returns last; the join below restores "one row per server_id" by
	// resolving to the row that belongs to the server's registering owner.
	rows, err := queryAll[Tup2[uuid.UUID, json.RawMessage]](ctx, db,
		"SELECT server_id, (to_jsonb(c) - 'server_id') AS config FROM ( "+
			"SELECT ar.server_id, ar.cpu_threshold, ar.cpu_duration, ar.memory_threshold, ar.memory_duration, "+
			"ar.disk_threshold, ar.alert_cpu, ar.alert_memory, ar.alert_disk, ar.alert_offline, "+
			"ar.alert_backup_failure, ar.alert_ssl_expiry, ar.alert_service_health, ar.ssl_warning_days, "+
			"ar.notify_email, ar.notify_slack_url, ar.notify_discord_url, ar.cooldown_minutes, ar.escalation_policy_id "+
			"FROM alert_rules ar JOIN servers s ON s.id = ar.server_id AND s.user_id = ar.user_id "+
			"WHERE ar.server_id = ANY($1) "+
			") c", ids)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]any, len(rows))
	for _, r := range rows {
		v, err := driftDecode(r.B)
		if err != nil {
			return nil, err
		}
		out[r.A] = v
	}
	return out, nil
}

func driftFetchSites(ctx context.Context, db Querier, ids []uuid.UUID) (map[uuid.UUID][]DriftRow, error) {
	rows, err := queryAll[Tup3[uuid.UUID, string, json.RawMessage]](ctx, db,
		"SELECT server_id, domain, (to_jsonb(c) - 'server_id' - 'domain') AS config FROM ( "+
			"SELECT server_id, domain, runtime, proxy_port, php_version, root_path, ssl_enabled, "+
			"ssl_profile, rate_limit, max_upload_mb, php_memory_mb, php_max_workers, custom_nginx, "+
			"php_preset, app_command, enabled, fastcgi_cache, redis_cache, redis_db, waf_enabled, "+
			"waf_mode, csp_policy, permissions_policy, bot_protection "+
			"FROM sites WHERE server_id = ANY($1) "+
			") c", ids)
	if err != nil {
		return nil, err
	}
	return driftGroupByServer(rows)
}

func driftFetchCrons(ctx context.Context, db Querier, ids []uuid.UUID) (map[uuid.UUID][]DriftRow, error) {
	rows, err := queryAll[Tup3[uuid.UUID, string, json.RawMessage]](ctx, db,
		"SELECT s.server_id, (s.domain || ' · ' || cr.command) AS identity, "+
			"jsonb_build_object('schedule', cr.schedule, 'enabled', cr.enabled, 'label', cr.label) AS config "+
			"FROM crons cr JOIN sites s ON cr.site_id = s.id "+
			"WHERE s.server_id = ANY($1)", ids)
	if err != nil {
		return nil, err
	}
	return driftGroupByServer(rows)
}

func driftFetchBackupCoverage(ctx context.Context, db Querier, ids []uuid.UUID) (map[uuid.UUID]DriftCoverageMetrics, error) {
	rows, err := queryAll[Tup4[uuid.UUID, int64, int64, int64]](ctx, db,
		"SELECT s.server_id, "+
			"COUNT(*)::bigint AS total_sites, "+
			"COUNT(bs.id) FILTER (WHERE bs.enabled)::bigint AS backed_up, "+
			"COUNT(DISTINCT bs.destination_id)::bigint AS destinations "+
			"FROM sites s LEFT JOIN backup_schedules bs ON bs.site_id = s.id "+
			"WHERE s.server_id = ANY($1) "+
			"GROUP BY s.server_id", ids)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]DriftCoverageMetrics, len(rows))
	for _, r := range rows {
		out[r.A] = DriftCoverageMetrics{
			TotalSites:   r.B,
			BackedUp:     r.C,
			Unprotected:  max(r.B-r.C, 0),
			Destinations: r.D,
		}
	}
	return out, nil
}

func driftGroupByServer(rows []Tup3[uuid.UUID, string, json.RawMessage]) (map[uuid.UUID][]DriftRow, error) {
	out := map[uuid.UUID][]DriftRow{}
	for _, r := range rows {
		v, err := driftDecode(r.C)
		if err != nil {
			return nil, err
		}
		out[r.A] = append(out[r.A], DriftRow{Identity: r.B, Config: v})
	}
	return out, nil
}

// ─── Report assembly ───────────────────────────────────────────────────────

// DriftBuildReport compares each target server against referenceID across the
// four v1 entities. `targets` (already excluding the reference) are the
// servers rendered under each entity.
//
// ⚠ SECURITY (s432): the fetchers used to take a `user_id` and scope every
// query to that caller's own registered servers — the admin-scoping bug
// servers list / fleet_overview already fix. The one caller,
// rtDriftReport, is admin-gated and validated every id against the
// fleet-wide server list, so the fetchers simply resolve the ids given.
func DriftBuildReport(ctx context.Context, db Querier, referenceID uuid.UUID, targets []uuid.UUID) (*DriftReport, error) {
	allIDs := make([]uuid.UUID, 0, len(targets)+1)
	allIDs = append(allIDs, referenceID)
	allIDs = append(allIDs, targets...)

	meta, err := driftFetchServerMeta(ctx, db, allIDs)
	if err != nil {
		return nil, err
	}
	refMeta := meta[referenceID]
	reference := DriftServerRef{
		ServerID:   referenceID,
		Name:       refMeta.name,
		IsLocal:    refMeta.isLocal,
		Status:     refMeta.status,
		LastSeenAt: refMeta.lastSeenAt,
	}

	alertRules, err := driftFetchAlertRules(ctx, db, allIDs)
	if err != nil {
		return nil, err
	}
	sites, err := driftFetchSites(ctx, db, allIDs)
	if err != nil {
		return nil, err
	}
	crons, err := driftFetchCrons(ctx, db, allIDs)
	if err != nil {
		return nil, err
	}
	coverage, err := driftFetchBackupCoverage(ctx, db, allIDs)
	if err != nil {
		return nil, err
	}

	// Track which target servers drift in ≥1 entity.
	drifted := map[uuid.UUID]struct{}{}
	entities := []DriftEntityDrift{}

	// 1. alert_rules — SINGLETON
	{
		refRow := alertRules[referenceID]
		servers := []DriftServerEntityDrift{}
		driftCount := 0
		for _, t := range targets {
			res := DriftDiffSingleton(refRow, alertRules[t], driftAlertSensitive)
			if !res.InSync {
				driftCount++
				drifted[t] = struct{}{}
			}
			s := driftBaseDrift(t, meta, res.InSync, res.Note)
			s.FieldDiffs = res.FieldDiffs
			servers = append(servers, s)
		}
		entities = append(entities, DriftEntityDrift{
			Entity: "alert_rules", Label: "Alert rules (monitoring posture)", Mode: "singleton",
			DriftCount: driftCount, Servers: servers,
		})
	}

	// 2. sites — COLLECTION
	entities = append(entities, driftBuildCollectionEntity("sites", "Sites (inventory + per-site config)",
		sites, referenceID, targets, meta, driftNoSensitive, drifted))
	// 3. crons — COLLECTION
	entities = append(entities, driftBuildCollectionEntity("crons", "Cron jobs",
		crons, referenceID, targets, meta, driftNoSensitive, drifted))

	// 4. backup_coverage — SUMMARY
	{
		var refCov *DriftCoverageMetrics
		if c, ok := coverage[referenceID]; ok {
			refCov = &c
		}
		servers := []DriftServerEntityDrift{}
		driftCount := 0
		for _, t := range targets {
			cov := coverage[t] // zero metrics when absent
			inSync := DriftCoverageInSync(cov)
			if !inSync {
				driftCount++
				drifted[t] = struct{}{}
			}
			s := driftBaseDrift(t, meta, inSync, nil)
			s.Coverage = &cov
			s.ReferenceCoverage = refCov
			servers = append(servers, s)
		}
		entities = append(entities, DriftEntityDrift{
			Entity: "backup_coverage", Label: "Backup coverage", Mode: "summary",
			DriftCount: driftCount, Servers: servers,
		})
	}

	var note *string
	if len(targets) == 0 {
		n := "Only one server is available — register fleet members to detect drift."
		note = &n
	}

	return &DriftReport{
		Reference:           reference,
		GeneratedAt:         time.Now().UTC(),
		ServersCompared:     len(targets),
		TotalDriftedServers: len(drifted),
		Entities:            entities,
		Note:                note,
	}, nil
}

// driftBaseDrift builds a DriftServerEntityDrift with the common fields
// filled; the caller sets the mode-specific ones.
func driftBaseDrift(serverID uuid.UUID, meta map[uuid.UUID]driftServerMeta, inSync bool, note *string) DriftServerEntityDrift {
	m := meta[serverID]
	return DriftServerEntityDrift{
		ServerID:   serverID,
		Name:       m.name,
		Status:     m.status,
		LastSeenAt: m.lastSeenAt,
		InSync:     inSync,
		Note:       note,
	}
}

func driftBuildCollectionEntity(entity, label string, data map[uuid.UUID][]DriftRow, referenceID uuid.UUID,
	targets []uuid.UUID, meta map[uuid.UUID]driftServerMeta, sensitive []string, drifted map[uuid.UUID]struct{}) DriftEntityDrift {
	refRows := data[referenceID]
	servers := []DriftServerEntityDrift{}
	driftCount := 0
	for _, t := range targets {
		res := DriftDiffCollection(refRows, data[t], sensitive)
		if !res.InSync {
			driftCount++
			drifted[t] = struct{}{}
		}
		s := driftBaseDrift(t, meta, res.InSync, nil)
		s.OnlyHere = &res.OnlyHere
		s.OnlyReference = &res.OnlyReference
		s.ValueDiffs = &res.ValueDiffs
		servers = append(servers, s)
	}
	return DriftEntityDrift{Entity: entity, Label: label, Mode: "collection", DriftCount: driftCount, Servers: servers}
}
