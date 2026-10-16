package api

// Port of panel/backend/src/routes/users.rs — admin user management.
// ASSIGNABLE_ROLES lives in core_helpers.go as AssignableRoles (shared with
// unsuspendAccount — deliberately one list, not a copy).

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

type rtUsersCreateUserRequest struct {
	Email    string  `json:"email"`
	Password string  `json:"password"`
	Role     *string `json:"role"`
}

type rtUsersUpdateUserRequest struct {
	Role     *string `json:"role"`
	Password *string `json:"password"`
}

type rtUsersUserResponse struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	Email      string     `json:"email" db:"email"`
	Role       string     `json:"role" db:"role"`
	ResellerID *uuid.UUID `json:"reseller_id" db:"reseller_id"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	SiteCount  int64      `json:"site_count" db:"site_count"`
	// Carried so the user table can offer "Reset 2FA" on the rows that have
	// an enrolment and stay quiet on the rows that do not — not a button that
	// refuses on most of the list.
	TotpEnabled bool `json:"totp_enabled" db:"totp_enabled"`
}

// rtUsersAssignableRolesMsg names AssignableRoles. A unit test asserts it
// mentions every one, since the sentence cannot be built from the list where
// it is used.
const rtUsersAssignableRolesMsg = "Role must be one of: admin, reseller, user, client"

func rtUsersRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("GET /api/users", h(rtUsersList))
	r.Handle("POST /api/users", h(rtUsersCreate))
	r.Handle("PUT /api/users/{id}", h(rtUsersUpdate))
	r.Handle("DELETE /api/users/{id}", h(rtUsersRemove))
	r.Handle("POST /api/users/{id}/toggle-suspend", h(rtUsersToggleSuspend))
	r.Handle("POST /api/users/{id}/reset-password", h(rtUsersResetPassword))
	r.Handle("POST /api/users/{id}/reset-2fa", h(rtUsersReset2fa))
}

// rtUsersIsOtherAdmin: `target` is another administrator — the caller's peer,
// not their subordinate. adminUser is a role check ONLY, so without this any
// two admins are fully interchangeable: reset each other's password, delete
// each other and inherit their whole server fleet (remove's UPDATE servers).
// Multiple administrators is a live, supported configuration. list/create
// are deliberately untouched: seeing the directory or minting a new account
// does not hand over an existing one.
func rtUsersIsOtherAdmin(targetRole string, targetID, callerID uuid.UUID) bool {
	return targetRole == "admin" && targetID != callerID
}

// rtUsersList — GET /api/users (admin only).
func rtUsersList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	users, err := queryAll[rtUsersUserResponse](r.Context(), st.DB,
		"SELECT u.id, u.email, u.role, u.reseller_id, u.created_at, "+
			"COALESCE((SELECT COUNT(*) FROM sites WHERE user_id = u.id), 0) as site_count, "+
			"u.totp_enabled "+
			"FROM users u ORDER BY u.created_at ASC")
	if err != nil {
		return internalError("list users", err)
	}
	writeJSON(w, http.StatusOK, users)
	return nil
}

// rtUsersLoadTarget is `SELECT * FROM users WHERE id = $1` fetch_optional →
// 404 "User not found".
func rtUsersLoadTarget(r *http.Request, st *AppState, id uuid.UUID, what string) (*User, error) {
	u, err := queryOpt[User](r.Context(), st.DB, "SELECT * FROM users WHERE id = $1", id)
	if err != nil {
		return nil, internalError(what, err)
	}
	if u == nil {
		return nil, apiErr(http.StatusNotFound, "User not found")
	}
	return u, nil
}

// rtUsersCreate — POST /api/users (admin only).
func rtUsersCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var body rtUsersCreateUserRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	if body.Email == "" || len(body.Email) > 254 || !strings.Contains(body.Email, "@") {
		return apiErr(http.StatusBadRequest, "Invalid email")
	}
	if len(body.Password) < 8 {
		return apiErr(http.StatusBadRequest, "Password must be at least 8 characters")
	}
	role := "user"
	if body.Role != nil {
		role = *body.Role
	}
	if !slices.Contains(AssignableRoles[:], role) {
		return apiErr(http.StatusBadRequest, rtUsersAssignableRolesMsg)
	}

	existing, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM users WHERE email = $1", body.Email)
	if err != nil {
		return internalError("create users", err)
	}
	if existing != nil {
		return apiErr(http.StatusConflict, "Email already registered")
	}

	hash, err := hashPassword(body.Password)
	if err != nil {
		return internalError("create users", err)
	}

	// email_verified is TRUE because this is an ADMIN-CREATED account: the
	// administrator types the address and password, and no verification mail
	// is ever sent from here. Omitting the column left it FALSE with no
	// email_token — exactly the pair login treats as "unverified" while the
	// verify route can only match WHERE email_token = $1 — so every account
	// this door made could not sign in the moment SMTP existed, and could not
	// fix it (same defect as #100, different door). The address is ASSERTED,
	// not proven — the same trade the other non-self-service doors make.
	user, err := queryOne[User](ctx, st.DB,
		"INSERT INTO users (email, password_hash, role, email_verified) "+
			"VALUES ($1, $2, $3, TRUE) RETURNING *", body.Email, hash, role)
	if err != nil {
		return internalError("create users", err)
	}

	slog.Info(fmt.Sprintf("User created by %s: %s (%s)", claims.Email, user.Email, role))
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "user.create", new("user"), &user.Email, &role, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "user.create", &claims.Email, ip, new("user"), &user.Email, &role, nil, "warning", claims.KeyID)

	// GAP 42: Send welcome email (best-effort, skip silently if SMTP not configured)
	panelURL := st.Config.BaseURL
	welcome := fmt.Sprintf(`<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #4f46e5;">Welcome to DockPanel</h2>
                <p>Your DockPanel account has been created by an administrator.</p>
                <p><strong>Email:</strong> %s</p>
                <p><strong>Panel URL:</strong> <a href="%s">%s</a></p>
                <p>Please log in and change your password at your earliest convenience.</p>
                <p style="color: #9ca3af; font-size: 12px;">If you did not expect this account, please contact your administrator.</p>
            </div>`, user.Email, panelURL, panelURL)
	if err := EmailSendEmail(ctx, st.DB, user.Email, "Welcome to DockPanel", welcome); err != nil {
		slog.Debug(fmt.Sprintf("Welcome email not sent to %s: %v", user.Email, err))
	}

	writeJSON(w, http.StatusCreated, map[string]any{"id": user.ID, "email": user.Email, "role": user.Role})
	return nil
}

// rtUsersUpdate — PUT /api/users/{id}: update role or password (admin only).
func rtUsersUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtUsersUpdateUserRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	target, err := rtUsersLoadTarget(r, st, id, "update users")
	if err != nil {
		return err
	}
	if rtUsersIsOtherAdmin(target.Role, id, claims.Sub) {
		return apiErr(http.StatusForbidden, "Cannot modify another administrator's account")
	}

	if body.Role != nil {
		role := *body.Role
		if !slices.Contains(AssignableRoles[:], role) {
			return apiErr(http.StatusBadRequest, rtUsersAssignableRolesMsg)
		}
		changed := role != target.Role
		// An admin cannot change their OWN role (mirrors the self-guards on
		// toggle_suspend/remove): prevents accidental self-lockout AND closes
		// the re-escalation path where a stale admin token flips itself back.
		if id == claims.Sub && changed {
			return apiErr(http.StatusBadRequest, "Cannot change your own role")
		}
		// Only mutate + revoke on an ACTUAL change — a no-op self-submit must
		// not log the caller out. The last-admin guard is folded into the
		// UPDATE's WHERE so a demotion can never orphan the panel (atomic as a
		// statement, not check-then-act). Clearing reseller_id on promotion
		// keeps a tenant-root from staying owned by another reseller (PRIV-03).
		if changed {
			n, err := execSQL(ctx, st.DB,
				"UPDATE users SET role = $1, "+
					"reseller_id = CASE WHEN $1 IN ('reseller','admin') THEN NULL ELSE reseller_id END, "+
					"updated_at = NOW() "+
					"WHERE id = $2 "+
					"AND ($1 = 'admin' OR role <> 'admin' OR (SELECT COUNT(*) FROM users WHERE role = 'admin') > 1)",
				role, id)
			if err != nil {
				return internalError("update users", err)
			}
			if n == 0 {
				// The user exists (fetched above), so 0 rows means the
				// last-admin guard blocked the demotion.
				return apiErr(http.StatusBadRequest, "Cannot demote the last admin")
			}
			// A role change must take effect immediately: a plain DELETE of
			// user_sessions is a no-op against the stateless JWT.
			st.revokeAllUserSessions(ctx, id)
		}
	}

	if body.Password != nil {
		if len(*body.Password) < 8 {
			return apiErr(http.StatusBadRequest, "Password must be at least 8 characters")
		}
		hash, err := hashPassword(*body.Password)
		if err != nil {
			return internalError("update users", err)
		}
		if _, err := execSQL(ctx, st.DB, "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2", hash, id); err != nil {
			return internalError("update users", err)
		}
		// A password change must evict the user's live token(s).
		st.revokeAllUserSessions(ctx, id)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "user.update", new("user"), &target.Email, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "user.update", &claims.Email, ip, new("user"), &target.Email, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtUsersToggleSuspend — POST /api/users/{id}/toggle-suspend (admin only).
//
// Suspending records the role in users.prior_role; un-suspending gives it
// back. The stash used to live in users.reset_token, which the public reset
// flow also writes — so a suspended account could destroy the record of its
// own role. The statements are suspendAccount/unsuspendAccount, shared with
// the billing webhook so the two cannot drift.
func rtUsersToggleSuspend(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if id == claims.Sub {
		return apiErr(http.StatusBadRequest, "Cannot suspend your own account")
	}
	user, err := rtUsersLoadTarget(r, st, id, "toggle_suspend")
	if err != nil {
		return err
	}
	if rtUsersIsOtherAdmin(user.Role, id, claims.Sub) {
		return apiErr(http.StatusForbidden, "Cannot suspend another administrator's account")
	}

	// An administrator restoring through the panel has no deny-list — they
	// may give back anything recorded, including admin.
	var newRole, action string
	if user.Role == "suspended" {
		role, err := unsuspendAccount(ctx, st, id, nil)
		if err != nil {
			return err
		}
		if role == nil {
			// Only reachable for an account suspended by a build predating
			// prior_role, whose record the reset flow had overwritten.
			// Guessing is the defect this removes, so say what happened and
			// name the way out instead.
			return apiErr(http.StatusConflict,
				"This account was suspended by an older version and the record of its "+
					"previous role was lost, so un-suspending cannot know what to give back. "+
					"Set the role directly from the user editor — that also lifts the suspension.")
		}
		newRole, action = *role, "user.unsuspend"
	} else {
		if _, err := suspendAccount(ctx, st, id, ""); err != nil {
			return err
		}
		newRole, action = "suspended", "user.suspend"
	}

	// Actually revoke the user's live token(s) — a stateless JWT would
	// otherwise carry the old role for up to 2h.
	st.revokeAllUserSessions(ctx, id)

	slog.Info(fmt.Sprintf("%s by %s: %s -> role=%s", action, claims.Email, user.Email, newRole))
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, action, new("user"), &user.Email, &newRole, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, action, &claims.Email, ip, new("user"), &user.Email, &newRole, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "email": user.Email, "role": newRole, "suspended": newRole == "suspended",
	})
	return nil
}

type rtUsersResetPasswordRequest struct {
	Password string `json:"password"`
}

// rtUsersResetPassword — POST /api/users/{id}/reset-password (admin only).
func rtUsersResetPassword(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtUsersResetPasswordRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	if len(body.Password) < 8 {
		return apiErr(http.StatusBadRequest, "Password must be at least 8 characters")
	}
	if len(body.Password) > 128 {
		return apiErr(http.StatusBadRequest, "Password must be at most 128 characters")
	}
	user, err := rtUsersLoadTarget(r, st, id, "reset_password")
	if err != nil {
		return err
	}
	if rtUsersIsOtherAdmin(user.Role, id, claims.Sub) {
		return apiErr(http.StatusForbidden, "Cannot reset another administrator's password")
	}
	hash, err := hashPassword(body.Password)
	if err != nil {
		return internalError("reset_password", err)
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2", hash, id); err != nil {
		return internalError("reset_password", err)
	}
	// A stolen/active session must not survive the reset.
	st.revokeAllUserSessions(ctx, id)

	slog.Info(fmt.Sprintf("Password reset by admin %s for user %s", claims.Email, user.Email))
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "user.reset_password", new("user"), &user.Email, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "user.reset_password", &claims.Email, ip, new("user"), &user.Email, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": user.Email})
	return nil
}

// rtUsersReset2fa — POST /api/users/{id}/reset-2fa: clear a user's 2FA.
//
// The door of last resort: twofa_disable can only be reached by someone who
// can still produce a code, and every account that enrolled before v2.83.0
// holds recovery codes it was never shown — for those accounts both factors
// are gone at once.
//
// ⚠ It refuses to act on the CALLER: resetting your own 2FA from here would
// strip the factor with no code presented, which twofa_disable exists to
// prevent — a hijacked admin session would turn the safeguard off in one
// click.
//
// ⚠ An administrator CAN reset another administrator's 2FA — deliberately
// outside rtUsersIsOtherAdmin. Clearing a factor does not by itself grant
// sign-in (the password is untouched), it is logged as its own action, and it
// is the only recovery path for an admin who lost both authenticator and
// recovery codes.
func rtUsersReset2fa(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if id == claims.Sub {
		return apiErr(http.StatusBadRequest, "Use My Account to change your own 2FA — resetting it here would skip the code check")
	}
	user, err := rtUsersLoadTarget(r, st, id, "reset_2fa")
	if err != nil {
		return err
	}
	// A half-finished enrolment leaves totp_secret set with totp_enabled
	// false, and that also wants clearing.
	if !user.TotpEnabled && user.TotpSecret == nil {
		return apiErr(http.StatusBadRequest, "This user has no two-factor enrolment to reset")
	}
	if _, err := execSQL(ctx, st.DB,
		"UPDATE users SET totp_enabled = FALSE, totp_secret = NULL, recovery_codes = NULL, updated_at = NOW() WHERE id = $1", id); err != nil {
		return internalError("reset_2fa", err)
	}
	// The account's authentication just changed: anything holding a session
	// on it starts again.
	st.revokeAllUserSessions(ctx, id)

	slog.Info(fmt.Sprintf("2FA reset by admin %s for user %s", claims.Email, user.Email))
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "user.reset_2fa", new("user"), &user.Email, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "user.reset_2fa", &claims.Email, ip, new("user"), &user.Email, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": user.Email})
	return nil
}

// rtUsersRemove — DELETE /api/users/{id} (admin only, cannot delete self).
func rtUsersRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if id == claims.Sub {
		return apiErr(http.StatusBadRequest, "Cannot delete your own account")
	}
	user, err := rtUsersLoadTarget(r, st, id, "remove users")
	if err != nil {
		return err
	}
	if rtUsersIsOtherAdmin(user.Role, id, claims.Sub) {
		return apiErr(http.StatusForbidden, "Cannot delete another administrator's account")
	}

	// Revoke BEFORE deletion — otherwise the stateless JWT keeps
	// authenticating as a now-nonexistent principal until it expires.
	st.revokeAllUserSessions(ctx, id)

	// ⚠ THE MACHINE MUST CHANGE HANDS BEFORE THE ACCOUNT GOES, OR EVERY SITE
	// ON IT GOES WITH IT. servers.user_id is ON DELETE CASCADE and
	// sites.server_id is ON DELETE CASCADE: deleting the account that holds a
	// machine deleted EVERY sites row on it — every owner's — and everything
	// keyed on site_id, while the handler answered {"ok": true}. The local row
	// is owned by the FIRST admin, so retiring the founding administrator was
	// the trigger. RE-POINT rather than REFUSE: nothing can re-assign a server
	// today, so a refusal would make the account undeletable. The caller is an
	// admin, so handing them the machine invents no owner; it is reported in
	// the response and the activity log.
	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return internalError("remove users", err)
	}
	defer tx.Rollback(ctx)

	reassigned, err := queryAll[string](ctx, tx, "SELECT name FROM servers WHERE user_id = $1 ORDER BY is_local DESC, name", id)
	if err != nil {
		return internalError("remove users", err)
	}
	if len(reassigned) > 0 {
		if _, err := execSQL(ctx, tx, "UPDATE servers SET user_id = $1 WHERE user_id = $2", claims.Sub, id); err != nil {
			return internalError("remove users", err)
		}
	}
	if _, err := execSQL(ctx, tx, "DELETE FROM users WHERE id = $1", id); err != nil {
		return internalError("remove users", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return internalError("remove users", err)
	}

	// Scrub the on-call references no foreign key can reach (rota membership
	// is a UUID[], escalation routes are strings inside JSONB) — dangling
	// ones page a principal that no longer exists. Strictly AFTER the delete:
	// several FKs to users are NO ACTION, so the DELETE can legitimately fail,
	// and this scrub is irreversible.
	rtOnCallScrubDeletedUser(ctx, st.DB, id)

	slog.Info(fmt.Sprintf("User deleted by %s: %s", claims.Email, user.Email))
	if len(reassigned) > 0 {
		slog.Info(fmt.Sprintf("Reassigned %d server(s) from %s to %s: %s", len(reassigned), user.Email, claims.Email, strings.Join(reassigned, ", ")))
	}
	ip := clientIP(r)
	// The details slot, so the reassignment is in the audit trail and not
	// only in a response the operator may never read.
	var details *string
	if len(reassigned) > 0 {
		details = new("reassigned servers: " + strings.Join(reassigned, ", "))
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "user.delete", new("user"), &user.Email, details, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "user.delete", &claims.Email, ip, new("user"), &user.Email, details, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": user.Email, "reassigned_servers": reassigned})
	return nil
}
