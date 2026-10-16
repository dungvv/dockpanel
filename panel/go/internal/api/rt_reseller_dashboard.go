package api

// Port of panel/backend/src/routes/reseller_dashboard.rs — the reseller's own
// dashboard, its sub-accounts and its allocated servers.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtResellerDashboardRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/reseller/dashboard", h(rtResellerDashboardDashboard))
	r.Handle("GET /api/reseller/users", h(rtResellerDashboardListUsers))
	r.Handle("POST /api/reseller/users", h(rtResellerDashboardCreateUser))
	r.Handle("PUT /api/reseller/users/{id}", h(rtResellerDashboardUpdateUser))
	r.Handle("DELETE /api/reseller/users/{id}", h(rtResellerDashboardDeleteUser))
	r.Handle("GET /api/reseller/servers", h(rtResellerDashboardListServers))
}

// rtResellerDashboardManageableRoles are the roles a reseller may act on among
// its own sub-accounts.
//
// An ALLOW-LIST, and it must stay one. `admin` and `reseller` are absent by
// construction, so a privileged account that happens to carry a `reseller_id`
// can never be reached through the two handlers that read this. Writing it as
// `role <> 'admin'` would invert that property the first time a new
// privileged role is added.
//
// `suspended` is included deliberately: a reseller must be able to delete an
// account the panel has suspended, and resetting the password of a suspended
// account changes a hash that cannot be used to sign in until an
// administrator restores the role — so including it grants no access the
// suspension withholds.
var rtResellerDashboardManageableRoles = []string{"user", "client", "suspended"}

type rtResellerDashboardResellerDashboardData struct {
	PanelName     *string `json:"panel_name"`
	UsedUsers     int32   `json:"used_users"`
	MaxUsers      *int32  `json:"max_users"`
	UsedSites     int32   `json:"used_sites"`
	MaxSites      *int32  `json:"max_sites"`
	UsedDatabases int32   `json:"used_databases"`
	MaxDatabases  *int32  `json:"max_databases"`
	ServerCount   int64   `json:"server_count"`
}

type rtResellerDashboardResellerUserItem struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Role      string    `json:"role" db:"role"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	SiteCount int64     `json:"site_count" db:"site_count"`
}

type rtResellerDashboardCreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type rtResellerDashboardUpdateUserRequest struct {
	Password *string `json:"password"`
}

type rtResellerDashboardResellerServerItem struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Status    string    `json:"status" db:"status"`
	IPAddress *string   `json:"ip_address" db:"ip_address"`
}

func rtResellerDashboardStr(s string) *string { return &s }

// GET /api/reseller/dashboard — Reseller dashboard data (quota usage + server count).
func rtResellerDashboardDashboard(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.resellerUser(r)
	if err != nil {
		return err
	}
	if claims.Role != "reseller" {
		return apiErr(http.StatusForbidden, "This endpoint is for resellers only (admin: use /api/resellers/{id})")
	}
	ctx := r.Context()

	profile, err := queryOpt[struct {
		PanelName     *string `db:"panel_name"`
		UsedUsers     int32   `db:"used_users"`
		MaxUsers      *int32  `db:"max_users"`
		UsedSites     int32   `db:"used_sites"`
		MaxSites      *int32  `db:"max_sites"`
		UsedDatabases int32   `db:"used_databases"`
		MaxDatabases  *int32  `db:"max_databases"`
	}](ctx, st.DB,
		"SELECT panel_name, used_users, max_users, used_sites, max_sites, "+
			"used_databases, max_databases "+
			"FROM reseller_profiles WHERE user_id = $1", claims.Sub)
	if err != nil {
		return internalError("dashboard", err)
	}
	if profile == nil {
		return apiErr(http.StatusNotFound, "Reseller profile not found")
	}

	serverCount, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM reseller_servers WHERE reseller_id = $1", claims.Sub)
	if err != nil {
		return internalError("dashboard", err)
	}

	writeJSON(w, http.StatusOK, rtResellerDashboardResellerDashboardData{
		PanelName:     profile.PanelName,
		UsedUsers:     profile.UsedUsers,
		MaxUsers:      profile.MaxUsers,
		UsedSites:     profile.UsedSites,
		MaxSites:      profile.MaxSites,
		UsedDatabases: profile.UsedDatabases,
		MaxDatabases:  profile.MaxDatabases,
		ServerCount:   serverCount,
	})
	return nil
}

// GET /api/reseller/users — List users belonging to this reseller.
func rtResellerDashboardListUsers(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.resellerUser(r)
	if err != nil {
		return err
	}
	var users []rtResellerDashboardResellerUserItem
	if claims.Role == "admin" {
		users, err = queryAll[rtResellerDashboardResellerUserItem](r.Context(), st.DB,
			"SELECT u.id, u.email, u.role, u.created_at, "+
				"COALESCE((SELECT COUNT(*) FROM sites WHERE user_id = u.id), 0) as site_count "+
				"FROM users u WHERE u.reseller_id IS NOT NULL "+
				"ORDER BY u.created_at ASC")
	} else {
		users, err = queryAll[rtResellerDashboardResellerUserItem](r.Context(), st.DB,
			"SELECT u.id, u.email, u.role, u.created_at, "+
				"COALESCE((SELECT COUNT(*) FROM sites WHERE user_id = u.id), 0) as site_count "+
				"FROM users u WHERE u.reseller_id = $1 "+
				"ORDER BY u.created_at ASC", claims.Sub)
	}
	if err != nil {
		return internalError("list users", err)
	}
	writeJSON(w, http.StatusOK, users)
	return nil
}

// POST /api/reseller/users — Create a new user under this reseller.
func rtResellerDashboardCreateUser(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.resellerUser(r)
	if err != nil {
		return err
	}
	var body rtResellerDashboardCreateUserRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if claims.Role != "reseller" {
		return apiErr(http.StatusForbidden, "Only resellers can create users via this endpoint")
	}

	// Validate email
	if body.Email == "" || len(body.Email) > 254 || !strings.Contains(body.Email, "@") {
		return apiErr(http.StatusBadRequest, "Invalid email")
	}

	// Validate password
	if len(body.Password) < 8 {
		return apiErr(http.StatusBadRequest, "Password must be at least 8 characters")
	}
	ctx := r.Context()

	// Check email uniqueness
	existing, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM users WHERE email = $1", body.Email)
	if err != nil {
		return internalError("create user", err)
	}
	if existing != nil {
		return apiErr(http.StatusConflict, "Email already registered")
	}

	// Hash password
	hash, err := hashPassword(body.Password)
	if err != nil {
		return internalError("create user", err)
	}

	// Atomically reserve the user-quota slot BEFORE creating (closes the
	// TOCTOU that let concurrent creates exceed max_users).
	// reserveResellerUserSlot both checks and increments in one statement;
	// release it if the INSERT then fails.
	if err := rtResellerDashboardReserveResellerUserSlot(ctx, st, claims.Sub); err != nil {
		return err
	}

	// `email_verified` is TRUE for the same reason as the admin-side door: the
	// reseller types the address and the password, and this handler sends no
	// mail at all. Omitting the column left it FALSE with no `email_token`, so
	// the account could never sign in once SMTP was configured and could never
	// verify — and this path was the worse of the two, because the release
	// valve (`POST /api/security/users/{id}/verify-email`) takes AdminUser, so
	// a reseller could not free the client they had just created.
	row, err := queryOne[Tup2[uuid.UUID, string]](ctx, st.DB,
		"INSERT INTO users (email, password_hash, role, reseller_id, email_verified) "+
			"VALUES ($1, $2, 'user', $3, TRUE) RETURNING id, email",
		body.Email, hash, claims.Sub)
	if err != nil {
		rtResellerDashboardReleaseResellerUserSlot(ctx, st, claims.Sub)
		return internalError("create user", err)
	}
	userID, userEmail := row.A, row.B

	slog.Info(fmt.Sprintf("Reseller %s created user: %s", claims.Email, userEmail))
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "reseller.user.create",
		rtResellerDashboardStr("user"), &userEmail, nil, nil, claims.KeyID)

	writeJSON(w, http.StatusCreated, map[string]any{"id": userID, "email": userEmail, "role": "user"})
	return nil
}

// rtResellerDashboardManagedUser resolves a sub-account the caller may act on.
//
// ⚠ `role = ANY(...)`, not `role = 'user'`, and NOT `role <> 'admin'`.
//
// `list_users` scopes on `reseller_id` alone, so a reseller's table shows
// every account beneath them whatever its role — and it renders Reset Password
// and Delete on every row. The old predicate resolved to nothing for anything
// that was not exactly `user`, and the caller met "User not found" about an
// account listed on the same screen. Both ways in are ordinary admin actions:
// setting an account's role to Client or suspending it (role = 'suspended').
//
// Enumerated rather than negated on purpose: a role added to AssignableRoles
// tomorrow must not silently become something a reseller may act on. `admin`
// and `reseller` are absent by construction, so no widening of this list can
// hand a reseller the password of an administrator who carries their id.
// Kept as one shared helper because update and delete drifted apart from
// list_users once and nothing noticed.
func rtResellerDashboardManagedUser(ctx context.Context, st *AppState, claims *Claims, id uuid.UUID, ctxName string) (*Tup2[uuid.UUID, string], error) {
	var user *Tup2[uuid.UUID, string]
	var err error
	if claims.Role == "admin" {
		user, err = queryOpt[Tup2[uuid.UUID, string]](ctx, st.DB, "SELECT id, email FROM users WHERE id = $1", id)
	} else {
		user, err = queryOpt[Tup2[uuid.UUID, string]](ctx, st.DB,
			"SELECT id, email FROM users "+
				"WHERE id = $1 AND reseller_id = $2 AND role = ANY($3)",
			id, claims.Sub, rtResellerDashboardManageableRoles)
	}
	if err != nil {
		return nil, internalError(ctxName, err)
	}
	if user == nil {
		return nil, apiErr(http.StatusNotFound, "User not found")
	}
	return user, nil
}

// PUT /api/reseller/users/{id} — Update a reseller's user (password only).
func rtResellerDashboardUpdateUser(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.resellerUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtResellerDashboardUpdateUserRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	// Verify user belongs to this reseller (or admin has universal access)
	user, err := rtResellerDashboardManagedUser(ctx, st, claims, id, "update user")
	if err != nil {
		return err
	}

	if body.Password != nil {
		if len(*body.Password) < 8 {
			return apiErr(http.StatusBadRequest, "Password must be at least 8 characters")
		}
		hash, err := hashPassword(*body.Password)
		if err != nil {
			return internalError("update user", err)
		}
		if _, err := execSQL(ctx, st.DB, "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2", hash, id); err != nil {
			return internalError("update user", err)
		}
		// A password reset must evict the user's live token(s) (mirrors the
		// admin users::reset_password fix) — otherwise a stolen session
		// survives the reset.
		st.revokeAllUserSessions(ctx, id)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "reseller.user.update",
		rtResellerDashboardStr("user"), &user.B, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "reseller.user.update", &claims.Email, ip,
		rtResellerDashboardStr("user"), &user.B, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// DELETE /api/reseller/users/{id} — Delete a user under this reseller.
func rtResellerDashboardDeleteUser(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.resellerUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if id == claims.Sub {
		return apiErr(http.StatusBadRequest, "Cannot delete your own account")
	}
	ctx := r.Context()

	// Verify user belongs to this reseller (or admin has universal access)
	user, err := rtResellerDashboardManagedUser(ctx, st, claims, id, "delete user")
	if err != nil {
		return err
	}

	// Revoke the user's live token(s) before deletion — otherwise the
	// stateless JWT keeps authenticating as a now-nonexistent principal until
	// it expires (mirrors users::remove).
	st.revokeAllUserSessions(ctx, id)

	if _, err := execSQL(ctx, st.DB, "DELETE FROM users WHERE id = $1", id); err != nil {
		return internalError("delete user", err)
	}

	// Decrement used_users counter (floor at 0)
	if claims.Role == "reseller" {
		if _, err := execSQL(ctx, st.DB,
			"UPDATE reseller_profiles SET used_users = GREATEST(used_users - 1, 0) WHERE user_id = $1", claims.Sub); err != nil {
			return internalError("delete user", err)
		}
	}

	slog.Info(fmt.Sprintf("Reseller %s deleted user: %s", claims.Email, user.B))
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "reseller.user.delete",
		rtResellerDashboardStr("user"), &user.B, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "reseller.user.delete", &claims.Email, ip,
		rtResellerDashboardStr("user"), &user.B, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": user.B})
	return nil
}

// GET /api/reseller/servers — List servers allocated to this reseller.
func rtResellerDashboardListServers(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.resellerUser(r)
	if err != nil {
		return err
	}
	// Always scope to the calling user's reseller allocations (admin uses
	// /api/resellers/{id}/servers to see a specific reseller's servers).
	servers, err := queryAll[rtResellerDashboardResellerServerItem](r.Context(), st.DB,
		"SELECT s.id, s.name, s.status, s.ip_address "+
			"FROM servers s "+
			"JOIN reseller_servers rs ON rs.server_id = s.id "+
			"WHERE rs.reseller_id = $1 "+
			"ORDER BY s.name ASC", claims.Sub)
	if err != nil {
		return internalError("list servers", err)
	}
	writeJSON(w, http.StatusOK, servers)
	return nil
}

// rtResellerDashboardReserveResellerUserSlot atomically reserves one user slot
// against the reseller's own quota (the reseller owns the profile keyed by
// their own user_id). The conditional UPDATE ... RETURNING makes the check and
// increment a single statement, closing the check-then-increment TOCTOU.
// Mirrors databases::reserve_reseller_db_slot.
func rtResellerDashboardReserveResellerUserSlot(ctx context.Context, st *AppState, resellerID uuid.UUID) error {
	reserved, err := queryScalarOpt[int32](ctx, st.DB,
		"UPDATE reseller_profiles SET used_users = used_users + 1, updated_at = NOW() "+
			"WHERE user_id = $1 AND (max_users IS NULL OR used_users < max_users) "+
			"RETURNING 1", resellerID)
	if err != nil {
		return internalError("reserve reseller user quota", err)
	}
	if reserved != nil {
		return nil
	}
	// 0 rows: profile missing OR quota exhausted — distinguish for the right error.
	hasProfile, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT user_id FROM reseller_profiles WHERE user_id = $1", resellerID)
	if err != nil {
		return internalError("reserve reseller user quota", err)
	}
	if hasProfile != nil {
		return apiErr(http.StatusForbidden, "User quota exceeded — upgrade your reseller plan")
	}
	return apiErr(http.StatusNotFound, "Reseller profile not found")
}

// rtResellerDashboardReleaseResellerUserSlot releases a reserved user slot
// (compensating decrement) when the create fails after the reserve succeeded.
func rtResellerDashboardReleaseResellerUserSlot(ctx context.Context, st *AppState, resellerID uuid.UUID) {
	_, _ = execSQL(context.WithoutCancel(ctx), st.DB,
		"UPDATE reseller_profiles SET used_users = GREATEST(used_users - 1, 0), updated_at = NOW() "+
			"WHERE user_id = $1", resellerID)
}

// rtResellerDashboardCheckResellerQuota is check_reseller_quota: whether the
// user's reseller has quota remaining for a resource type ("users", "sites",
// "databases"). Call before creating sites, databases, or users. nil if
// allowed; direct users (no reseller) are always allowed.
func rtResellerDashboardCheckResellerQuota(ctx context.Context, db Querier, userID uuid.UUID, resource string) error {
	// 1. Find the user's reseller_id
	rid, err := queryScalarOpt[*uuid.UUID](ctx, db, "SELECT reseller_id FROM users WHERE id = $1", userID)
	if err != nil || rid == nil || *rid == nil {
		return nil // No reseller = no quota enforcement
	}

	// 2. Fetch reseller profile quotas
	profile, err := queryOpt[Tup6[int32, *int32, int32, *int32, int32, *int32]](ctx, db,
		"SELECT used_users, max_users, used_sites, max_sites, "+
			"used_databases, max_databases "+
			"FROM reseller_profiles WHERE user_id = $1", **rid)
	if err != nil {
		return internalError("check reseller quota", err)
	}
	if profile == nil {
		return nil // No profile = no quota enforcement
	}

	// 3. Check the specific resource quota
	var used int32
	var max *int32
	switch resource {
	case "users":
		used, max = profile.A, profile.B
	case "sites":
		used, max = profile.C, profile.D
	case "databases":
		used, max = profile.E, profile.F
	default:
		return nil
	}
	if max != nil && used >= *max {
		return apiErr(http.StatusForbidden, fmt.Sprintf("Reseller quota exceeded for %s (%d/%d)", resource, used, *max))
	}
	return nil
}
