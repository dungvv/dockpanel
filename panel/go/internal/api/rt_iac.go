package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ─── Terraform / Pulumi IaC Provider API ───────────────────────
//
// These endpoints provide a stable API surface for Terraform/Pulumi providers.
//
// ⚠ (s418, corrected) IaC tokens are CRUD-only — created, listed, deleted —
// and do not authenticate anything. Every handler below takes AuthUser (JWT);
// nothing reads a `dpiac_`-prefixed bearer token back against
// `iac_tokens.token_hash` to admit a request ("Authentication via IaC tokens"
// was never true; see FEATURES.md § Withdrawn Claims).
// Resources: sites, databases. (`dns_records` was named here too; no reader
// for it has ever existed.)

func rtIacRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/iac/tokens", h(rtIacListTokens))
	r.Handle("POST /api/iac/tokens", h(rtIacCreateToken))
	r.Handle("DELETE /api/iac/tokens/{id}", h(rtIacDeleteToken))
	r.Handle("GET /api/iac/resources/sites", h(rtIacTfListSites))
	r.Handle("GET /api/iac/resources/databases", h(rtIacTfListDatabases))
	r.Handle("GET /api/autoscale", h(rtIacListAutoscale))
	r.Handle("POST /api/autoscale", h(rtIacCreateAutoscale))
	r.Handle("PUT /api/autoscale/{id}", h(rtIacUpdateAutoscale))
	r.Handle("DELETE /api/autoscale/{id}", h(rtIacDeleteAutoscale))
}

// rtIacCreateToken — POST /api/iac/tokens: create a new IaC token.
func rtIacCreateToken(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()

	obj, _ := body.(map[string]any)
	name, ok := obj["name"].(string)
	if !ok {
		name = "default"
	}
	if name == "" || len(name) > 255 {
		return apiErr(http.StatusBadRequest, "Name must be 1-255 characters")
	}
	scopes, ok := obj["scopes"].(string)
	if !ok {
		scopes = "sites,databases,dns"
	}

	// Generate a secure random token
	rawToken := "dpiac_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	sum := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(sum[:])

	// Limit: max 10 tokens per user
	count, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM iac_tokens WHERE user_id = $1", claims.Sub)
	if err != nil {
		return internalError("iac token count", err)
	}
	if count >= 10 {
		return apiErr(http.StatusBadRequest, "Maximum 10 IaC tokens per user")
	}

	id, err := queryScalar[uuid.UUID](ctx, st.DB,
		"INSERT INTO iac_tokens (user_id, name, token_hash, scopes) VALUES ($1, $2, $3, $4) RETURNING id",
		claims.Sub, name, tokenHash, scopes)
	if err != nil {
		return internalError("create iac token", err)
	}

	ip := clientIP(r)
	targetType := "iac_token"
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "iac.token_created",
		&targetType, &name, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "iac.token_created", &claims.Email, ip,
		&targetType, &name, nil, nil, "warning", claims.KeyID)

	// Return the raw token ONCE — it cannot be retrieved after this
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":     id,
		"name":   name,
		"token":  rawToken,
		"scopes": scopes,
	})
	return nil
}

// rtIacListTokens — GET /api/iac/tokens: list IaC tokens (without revealing
// the token value).
func rtIacListTokens(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	tokens, err := queryAll[Tup5[uuid.UUID, string, string, *time.Time, time.Time]](r.Context(), st.DB,
		"SELECT id, name, scopes, last_used_at, created_at FROM iac_tokens WHERE user_id = $1 ORDER BY created_at",
		claims.Sub)
	if err != nil {
		return internalError("list iac tokens", err)
	}
	items := make([]map[string]any, 0, len(tokens))
	for _, t := range tokens {
		items = append(items, map[string]any{
			"id": t.A, "name": t.B, "scopes": t.C,
			"last_used_at": t.D, "created_at": t.E,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": items})
	return nil
}

// rtIacDeleteToken — DELETE /api/iac/tokens/{id}: revoke an IaC token.
func rtIacDeleteToken(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM iac_tokens WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("delete iac token", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Token not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtIacTfListSites — GET /api/iac/resources/sites: Terraform-compatible site listing.
func rtIacTfListSites(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	sites, err := queryAll[Tup6[uuid.UUID, string, string, string, bool, time.Time]](r.Context(), st.DB,
		"SELECT id, domain, runtime, status, ssl_enabled, created_at "+
			"FROM sites WHERE user_id = $1 ORDER BY domain", claims.Sub)
	if err != nil {
		return internalError("tf list sites", err)
	}
	items := make([]map[string]any, 0, len(sites))
	for _, s := range sites {
		items = append(items, map[string]any{
			"id": s.A, "domain": s.B, "runtime": s.C,
			"status": s.D, "ssl_enabled": s.E, "created_at": s.F,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"resources": items})
	return nil
}

// rtIacTfListDatabases — GET /api/iac/resources/databases: Terraform-compatible database listing.
func rtIacTfListDatabases(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	dbs, err := queryAll[Tup5[uuid.UUID, string, string, *int32, time.Time]](r.Context(), st.DB,
		"SELECT d.id, d.name, d.engine, d.port, d.created_at "+
			"FROM databases d "+
			"JOIN sites s ON d.site_id = s.id "+
			"WHERE s.user_id = $1 ORDER BY d.name", claims.Sub)
	if err != nil {
		return internalError("tf list databases", err)
	}
	items := make([]map[string]any, 0, len(dbs))
	for _, d := range dbs {
		items = append(items, map[string]any{
			"id": d.A, "name": d.B, "engine": d.C,
			"port": d.D, "created_at": d.E,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"resources": items})
	return nil
}

// ─── Horizontal Auto-Scaling ───────────────────────────────────

type rtIacAutoscaleRuleRequest struct {
	ContainerID      *string `json:"container_id"`
	ContainerName    *string `json:"container_name"`
	Enabled          *bool   `json:"enabled"`
	MinReplicas      *int32  `json:"min_replicas"`
	MaxReplicas      *int32  `json:"max_replicas"`
	CPUThresholdUp   *int32  `json:"cpu_threshold_up"`
	CPUThresholdDown *int32  `json:"cpu_threshold_down"`
	CooldownSeconds  *int32  `json:"cooldown_seconds"`
}

// rtIacOr is Option::unwrap_or.
func rtIacOr[T any](p *T, def T) T {
	if p != nil {
		return *p
	}
	return def
}

// rtIacClampOpt is `opt.map(|v| v.max(lo).min(hi))`.
func rtIacClampOpt(p *int32, lo, hi int32) *int32 {
	if p == nil {
		return nil
	}
	v := min(max(*p, lo), hi)
	return &v
}

// rtIacListAutoscale — GET /api/autoscale: list all auto-scaling rules.
func rtIacListAutoscale(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	type row struct {
		ID               uuid.UUID  `db:"id"`
		ContainerID      string     `db:"container_id"`
		ContainerName    string     `db:"container_name"`
		Enabled          bool       `db:"enabled"`
		MinReplicas      int32      `db:"min_replicas"`
		MaxReplicas      int32      `db:"max_replicas"`
		CPUThresholdUp   int32      `db:"cpu_threshold_up"`
		CPUThresholdDown int32      `db:"cpu_threshold_down"`
		CooldownSeconds  int32      `db:"cooldown_seconds"`
		CurrentReplicas  int32      `db:"current_replicas"`
		LastScaleAt      *time.Time `db:"last_scale_at"`
	}
	rules, err := queryAll[row](r.Context(), st.DB,
		"SELECT id, container_id, container_name, enabled, min_replicas, max_replicas, "+
			"cpu_threshold_up, cpu_threshold_down, cooldown_seconds, current_replicas, last_scale_at "+
			"FROM autoscale_rules ORDER BY container_name")
	if err != nil {
		return internalError("list autoscale rules", err)
	}
	items := make([]map[string]any, 0, len(rules))
	for _, x := range rules {
		items = append(items, map[string]any{
			"id": x.ID, "container_id": x.ContainerID, "container_name": x.ContainerName,
			"enabled": x.Enabled, "min_replicas": x.MinReplicas, "max_replicas": x.MaxReplicas,
			"cpu_threshold_up": x.CPUThresholdUp, "cpu_threshold_down": x.CPUThresholdDown,
			"cooldown_seconds": x.CooldownSeconds, "current_replicas": x.CurrentReplicas,
			"last_scale_at": x.LastScaleAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": items})
	return nil
}

// rtIacCreateAutoscale — POST /api/autoscale: create an auto-scaling rule.
func rtIacCreateAutoscale(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtIacAutoscaleRuleRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	if body.ContainerID == nil {
		return apiErr(http.StatusBadRequest, "container_id required")
	}
	cid := *body.ContainerID
	name := rtIacOr(body.ContainerName, cid)

	minR := min(max(rtIacOr(body.MinReplicas, 1), 1), 20)
	maxR := min(max(rtIacOr(body.MaxReplicas, 5), minR), 50)
	up := min(max(rtIacOr(body.CPUThresholdUp, 80), 10), 100)
	down := min(max(rtIacOr(body.CPUThresholdDown, 20), 5), up-5)
	cool := min(max(rtIacOr(body.CooldownSeconds, 300), 60), 3600)

	id, err := queryScalar[uuid.UUID](r.Context(), st.DB,
		"INSERT INTO autoscale_rules (container_id, container_name, enabled, min_replicas, max_replicas, "+
			"cpu_threshold_up, cpu_threshold_down, cooldown_seconds) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "+
			"ON CONFLICT (container_id) DO UPDATE SET "+
			"enabled = $3, min_replicas = $4, max_replicas = $5, "+
			"cpu_threshold_up = $6, cpu_threshold_down = $7, cooldown_seconds = $8, updated_at = NOW() "+
			"RETURNING id",
		cid, name, rtIacOr(body.Enabled, true), minR, maxR, up, down, cool)
	if err != nil {
		return internalError("create autoscale rule", err)
	}

	targetType := "container"
	ActivityLogActivity(r.Context(), st.DB, claims.Sub, claims.Email, "autoscale.rule_created",
		&targetType, &name, nil, nil, claims.KeyID)

	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "id": id})
	return nil
}

// rtIacUpdateAutoscale — PUT /api/autoscale/{id}: update an auto-scaling rule.
func rtIacUpdateAutoscale(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtIacAutoscaleRuleRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB,
		"UPDATE autoscale_rules SET "+
			"enabled = COALESCE($1, enabled), "+
			"min_replicas = COALESCE($2, min_replicas), "+
			"max_replicas = COALESCE($3, max_replicas), "+
			"cpu_threshold_up = COALESCE($4, cpu_threshold_up), "+
			"cpu_threshold_down = COALESCE($5, cpu_threshold_down), "+
			"cooldown_seconds = COALESCE($6, cooldown_seconds), "+
			"updated_at = NOW() "+
			"WHERE id = $7",
		body.Enabled,
		rtIacClampOpt(body.MinReplicas, 1, 20),
		rtIacClampOpt(body.MaxReplicas, 1, 50),
		rtIacClampOpt(body.CPUThresholdUp, 10, 100),
		rtIacClampOpt(body.CPUThresholdDown, 5, 95),
		rtIacClampOpt(body.CooldownSeconds, 60, 3600),
		id)
	if err != nil {
		return internalError("update autoscale rule", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Rule not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtIacDeleteAutoscale — DELETE /api/autoscale/{id}: remove an auto-scaling rule.
func rtIacDeleteAutoscale(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM autoscale_rules WHERE id = $1", id)
	if err != nil {
		return internalError("delete autoscale rule", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Rule not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}
