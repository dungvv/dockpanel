package api

// Port of panel/backend/src/routes/resellers.rs — reseller management (admin).

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func rtResellersRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/resellers", h(rtResellersList))
	r.Handle("POST /api/resellers", h(rtResellersCreate))
	r.Handle("GET /api/resellers/{id}", h(rtResellersGet))
	r.Handle("PUT /api/resellers/{id}", h(rtResellersUpdate))
	r.Handle("DELETE /api/resellers/{id}", h(rtResellersRemove))
	r.Handle("GET /api/resellers/{id}/servers", h(rtResellersListServers))
	r.Handle("POST /api/resellers/{id}/servers", h(rtResellersAllocateServer))
	r.Handle("DELETE /api/resellers/{id}/servers/{server_id}", h(rtResellersDeallocateServer))
}

type rtResellersResellerProfile struct {
	ID               uuid.UUID `json:"id" db:"id"`
	UserID           uuid.UUID `json:"user_id" db:"user_id"`
	PanelName        *string   `json:"panel_name" db:"panel_name"`
	MaxUsers         *int32    `json:"max_users" db:"max_users"`
	MaxSites         *int32    `json:"max_sites" db:"max_sites"`
	MaxDatabases     *int32    `json:"max_databases" db:"max_databases"`
	MaxDiskMB        *int64    `json:"max_disk_mb" db:"max_disk_mb"`
	MaxEmailAccounts *int32    `json:"max_email_accounts" db:"max_email_accounts"`
	UsedUsers        int32     `json:"used_users" db:"used_users"`
	UsedSites        int32     `json:"used_sites" db:"used_sites"`
	UsedDatabases    int32     `json:"used_databases" db:"used_databases"`
	LogoURL          *string   `json:"logo_url" db:"logo_url"`
	AccentColor      *string   `json:"accent_color" db:"accent_color"`
	HideBranding     bool      `json:"hide_branding" db:"hide_branding"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

type rtResellersResellerListItem struct {
	ID            uuid.UUID `json:"id" db:"id"`
	UserID        uuid.UUID `json:"user_id" db:"user_id"`
	Email         string    `json:"email" db:"email"`
	PanelName     *string   `json:"panel_name" db:"panel_name"`
	MaxUsers      *int32    `json:"max_users" db:"max_users"`
	MaxSites      *int32    `json:"max_sites" db:"max_sites"`
	MaxDatabases  *int32    `json:"max_databases" db:"max_databases"`
	UsedUsers     int32     `json:"used_users" db:"used_users"`
	UsedSites     int32     `json:"used_sites" db:"used_sites"`
	UsedDatabases int32     `json:"used_databases" db:"used_databases"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type rtResellersCreateResellerRequest struct {
	UserID       uuid.UUID `json:"user_id"`
	PanelName    *string   `json:"panel_name"`
	MaxUsers     *int32    `json:"max_users"`
	MaxSites     *int32    `json:"max_sites"`
	MaxDatabases *int32    `json:"max_databases"`
	LogoURL      *string   `json:"logo_url"`
	AccentColor  *string   `json:"accent_color"`
	HideBranding *bool     `json:"hide_branding"`
}

type rtResellersUpdateResellerRequest struct {
	PanelName        *string `json:"panel_name"`
	MaxUsers         *int32  `json:"max_users"`
	MaxSites         *int32  `json:"max_sites"`
	MaxDatabases     *int32  `json:"max_databases"`
	MaxDiskMB        *int64  `json:"max_disk_mb"`
	MaxEmailAccounts *int32  `json:"max_email_accounts"`
	LogoURL          *string `json:"logo_url"`
	AccentColor      *string `json:"accent_color"`
	HideBranding     *bool   `json:"hide_branding"`
}

type rtResellersAllocateServerRequest struct {
	ServerID uuid.UUID `json:"server_id"`
}

type rtResellersResellerServer struct {
	ID         uuid.UUID `json:"id" db:"id"`
	ResellerID uuid.UUID `json:"reseller_id" db:"reseller_id"`
	ServerID   uuid.UUID `json:"server_id" db:"server_id"`
	ServerName string    `json:"server_name" db:"server_name"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

func rtResellersStr(s string) *string { return &s }

// rtResellersProfile loads a profile by id: 404 "Reseller profile not found".
func rtResellersProfile(st *AppState, r *http.Request, id uuid.UUID, ctxName string) (*rtResellersResellerProfile, error) {
	p, err := queryOpt[rtResellersResellerProfile](r.Context(), st.DB, "SELECT * FROM reseller_profiles WHERE id = $1", id)
	if err != nil {
		return nil, internalError(ctxName, err)
	}
	if p == nil {
		return nil, apiErr(http.StatusNotFound, "Reseller profile not found")
	}
	return p, nil
}

// GET /api/resellers — List all resellers with their profiles (admin only).
func rtResellersList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	resellers, err := queryAll[rtResellersResellerListItem](r.Context(), st.DB,
		"SELECT rp.id, rp.user_id, u.email, rp.panel_name, "+
			"rp.max_users, rp.max_sites, rp.max_databases, "+
			"rp.used_users, rp.used_sites, rp.used_databases, "+
			"rp.created_at "+
			"FROM reseller_profiles rp "+
			"JOIN users u ON u.id = rp.user_id "+
			"WHERE u.role = 'reseller' "+
			"ORDER BY rp.created_at ASC")
	if err != nil {
		return internalError("list resellers", err)
	}
	writeJSON(w, http.StatusOK, resellers)
	return nil
}

// POST /api/resellers — Promote a user to reseller (admin only).
func rtResellersCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var body rtResellersCreateResellerRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	// Check user exists
	user, err := queryOpt[Tup3[uuid.UUID, string, string]](ctx, st.DB, "SELECT id, email, role FROM users WHERE id = $1", body.UserID)
	if err != nil {
		return internalError("create resellers", err)
	}
	if user == nil {
		return apiErr(http.StatusNotFound, "User not found")
	}
	userID, email, role := user.A, user.B, user.C

	if role == "admin" {
		return apiErr(http.StatusBadRequest, "Cannot promote an admin to reseller")
	}

	// Look for an existing profile UNCONDITIONALLY, not only when the account
	// is still a reseller. `reseller_profiles.user_id` is UNIQUE, and the role
	// and the profile are written by different doors: changing a reseller's
	// role from the Users screen updates `users` and leaves the profile behind.
	// So a demoted reseller keeps an orphan profile, and gating this check on
	// the role meant the next promotion sailed past it, updated the role, hit
	// the unique constraint on INSERT and answered 500 — an account an admin
	// could then never promote.
	existing, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM reseller_profiles WHERE user_id = $1", userID)
	if err != nil {
		return internalError("create resellers", err)
	}

	// Still a reseller AND already has a profile: a genuine double-create.
	if role == "reseller" && existing != nil {
		return apiErr(http.StatusConflict, "Reseller profile already exists")
	}

	ip := clientIP(r)

	// Update user role to reseller (idempotent if already reseller). Clear
	// reseller_id: a reseller is a tenant root and must never remain owned by
	// another reseller, else the parent reseller could manage/delete this
	// newly-promoted reseller (PRIV-03).
	if _, err := execSQL(ctx, st.DB, "UPDATE users SET role = 'reseller', reseller_id = NULL, updated_at = NOW() WHERE id = $1", userID); err != nil {
		return internalError("create resellers", err)
	}

	// Re-promotion of an account that kept its profile through a demotion. The
	// role UPDATE above is the whole of the work; inserting would violate the
	// unique constraint. Its stored quotas and branding are preserved rather
	// than silently replaced by whatever this request happened to carry — an
	// admin restoring a reseller is not asking to reset it.
	if existing != nil {
		slog.Info("Reseller role restored by " + claims.Email + " for " + email + " (profile kept)")
		ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "reseller.create",
			rtResellersStr("reseller"), &email, nil, ip, claims.KeyID)
		SecurityHardeningAuditLog(ctx, st.DB, "reseller.create", &claims.Email, ip,
			rtResellersStr("reseller"), &email, nil, nil, "warning", claims.KeyID)
		writeJSON(w, http.StatusCreated, map[string]any{"id": *existing, "user_id": userID, "email": email})
		return nil
	}

	// Insert reseller profile
	profile, err := queryOne[rtResellersResellerProfile](ctx, st.DB,
		"INSERT INTO reseller_profiles (user_id, panel_name, max_users, max_sites, max_databases, logo_url, accent_color, hide_branding) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, false)) RETURNING *",
		userID, body.PanelName, body.MaxUsers, body.MaxSites, body.MaxDatabases,
		body.LogoURL, body.AccentColor, body.HideBranding)
	if err != nil {
		return internalError("create resellers", err)
	}

	slog.Info("User promoted to reseller by " + claims.Email + ": " + email)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "reseller.create",
		rtResellersStr("reseller"), &email, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "reseller.create", &claims.Email, ip,
		rtResellersStr("reseller"), &email, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusCreated, map[string]any{"id": profile.ID, "user_id": userID, "email": email})
	return nil
}

// GET /api/resellers/{id} — Get reseller profile by profile id (admin only).
func rtResellersGet(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	profile, err := rtResellersProfile(st, r, id, "get resellers")
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, profile)
	return nil
}

// PUT /api/resellers/{id} — Update reseller quotas/branding (admin only).
func rtResellersUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtResellersUpdateResellerRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	// Verify profile exists
	profile, err := rtResellersProfile(st, r, id, "update resellers")
	if err != nil {
		return err
	}

	if _, err := execSQL(ctx, st.DB,
		"UPDATE reseller_profiles SET "+
			"panel_name = CASE WHEN $1 = '' THEN NULL ELSE COALESCE($1, panel_name) END, "+
			"max_users = COALESCE($2, max_users), "+
			"max_sites = COALESCE($3, max_sites), "+
			"max_databases = COALESCE($4, max_databases), "+
			"max_disk_mb = COALESCE($5, max_disk_mb), "+
			"max_email_accounts = COALESCE($6, max_email_accounts), "+
			"logo_url = CASE WHEN $7 = '' THEN NULL ELSE COALESCE($7, logo_url) END, "+
			"accent_color = CASE WHEN $8 = '' THEN NULL ELSE COALESCE($8, accent_color) END, "+
			"hide_branding = COALESCE($9, hide_branding), "+
			"updated_at = NOW() "+
			"WHERE id = $10",
		body.PanelName, body.MaxUsers, body.MaxSites, body.MaxDatabases, body.MaxDiskMB,
		body.MaxEmailAccounts, body.LogoURL, body.AccentColor, body.HideBranding, id); err != nil {
		return internalError("update resellers", err)
	}

	// Get email for activity log
	userEmail, err := queryScalar[string](ctx, st.DB, "SELECT email FROM users WHERE id = $1", profile.UserID)
	if err != nil {
		return internalError("update resellers", err)
	}

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "reseller.update",
		rtResellersStr("reseller"), &userEmail, nil, nil, claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// DELETE /api/resellers/{id} — Demote reseller back to user (admin only).
func rtResellersRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()

	// Get the profile to find user_id
	profile, err := rtResellersProfile(st, r, id, "remove resellers")
	if err != nil {
		return err
	}

	// Get email for logging before we delete
	userEmail, err := queryScalar[string](ctx, st.DB, "SELECT email FROM users WHERE id = $1", profile.UserID)
	if err != nil {
		return internalError("remove resellers", err)
	}

	// Delete reseller profile
	if _, err := execSQL(ctx, st.DB, "DELETE FROM reseller_profiles WHERE id = $1", id); err != nil {
		return internalError("remove resellers", err)
	}

	// Demote user back to regular user
	if _, err := execSQL(ctx, st.DB, "UPDATE users SET role = 'user', updated_at = NOW() WHERE id = $1", profile.UserID); err != nil {
		return internalError("remove resellers", err)
	}

	// Revoke the demoted user's token(s) so a stale role='reseller' claim can't
	// linger in an active JWT (completes the revoke-on-role-change invariant).
	st.revokeAllUserSessions(ctx, profile.UserID)

	// Clear reseller_id on any users that belonged to this reseller
	if _, err := execSQL(ctx, st.DB, "UPDATE users SET reseller_id = NULL, updated_at = NOW() WHERE reseller_id = $1", profile.UserID); err != nil {
		return internalError("remove resellers", err)
	}

	// Delete server allocations
	if _, err := execSQL(ctx, st.DB, "DELETE FROM reseller_servers WHERE reseller_id = $1", profile.UserID); err != nil {
		return internalError("remove resellers", err)
	}

	slog.Info("Reseller demoted by " + claims.Email + ": " + userEmail)
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "reseller.delete",
		rtResellersStr("reseller"), &userEmail, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "reseller.delete", &claims.Email, ip,
		rtResellersStr("reseller"), &userEmail, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": userEmail})
	return nil
}

// GET /api/resellers/{id}/servers — List servers allocated to reseller (admin only).
func rtResellersListServers(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	servers, err := queryAll[rtResellersResellerServer](r.Context(), st.DB,
		"SELECT rs.id, rs.reseller_id, rs.server_id, s.name as server_name, rs.created_at "+
			"FROM reseller_servers rs "+
			"JOIN servers s ON s.id = rs.server_id "+
			"WHERE rs.reseller_id = (SELECT user_id FROM reseller_profiles WHERE id = $1) "+
			"ORDER BY rs.created_at ASC", id)
	if err != nil {
		return internalError("list servers", err)
	}
	writeJSON(w, http.StatusOK, servers)
	return nil
}

// POST /api/resellers/{id}/servers — Allocate server to reseller (admin only).
func rtResellersAllocateServer(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtResellersAllocateServerRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	// Verify reseller profile exists and get user_id
	profile, err := rtResellersProfile(st, r, id, "allocate server")
	if err != nil {
		return err
	}

	// Verify server exists
	serverName, err := queryScalarOpt[string](ctx, st.DB, "SELECT name FROM servers WHERE id = $1", body.ServerID)
	if err != nil {
		return internalError("allocate server", err)
	}
	if serverName == nil {
		return apiErr(http.StatusNotFound, "Server not found")
	}

	// Insert allocation
	row, err := queryOne[rtResellersResellerServer](ctx, st.DB,
		"INSERT INTO reseller_servers (reseller_id, server_id) VALUES ($1, $2) "+
			"RETURNING id, reseller_id, server_id, "+
			"(SELECT name FROM servers WHERE id = $2) as server_name, created_at",
		profile.UserID, body.ServerID)
	if err != nil {
		return internalError("allocate server", err)
	}

	slog.Info("Server " + *serverName + " allocated to reseller " + profile.UserID.String() + " by " + claims.Email)
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "reseller.server.allocate",
		rtResellersStr("server"), serverName, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "reseller.server.allocate", &claims.Email, ip,
		rtResellersStr("server"), serverName, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          row.ID,
		"reseller_id": row.ResellerID,
		"server_id":   row.ServerID,
		"server_name": row.ServerName,
	})
	return nil
}

// DELETE /api/resellers/{id}/servers/{server_id} — Deallocate server from reseller (admin only).
func rtResellersDeallocateServer(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	serverID, err := pathUUID(r, "server_id")
	if err != nil {
		return err
	}
	ctx := r.Context()

	// Get reseller user_id from profile
	profile, err := rtResellersProfile(st, r, id, "deallocate server")
	if err != nil {
		return err
	}

	n, err := execSQL(ctx, st.DB, "DELETE FROM reseller_servers WHERE reseller_id = $1 AND server_id = $2", profile.UserID, serverID)
	if err != nil {
		return internalError("deallocate server", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Server allocation not found")
	}

	slog.Info("Server " + serverID.String() + " deallocated from reseller " + profile.UserID.String() + " by " + claims.Email)
	ip := clientIP(r)
	sid := serverID.String()
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "reseller.server.deallocate",
		rtResellersStr("server"), &sid, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "reseller.server.deallocate", &claims.Email, ip,
		rtResellersStr("server"), &sid, nil, nil, "info", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}
