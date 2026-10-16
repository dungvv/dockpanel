package api

// Port of panel/backend/src/routes/teams.rs.

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

type rtTeamsTeam struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	OwnerID   uuid.UUID `json:"owner_id" db:"owner_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type rtTeamsTeamMember struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TeamID   uuid.UUID `json:"team_id" db:"team_id"`
	UserID   uuid.UUID `json:"user_id" db:"user_id"`
	Role     string    `json:"role" db:"role"`
	JoinedAt time.Time `json:"joined_at" db:"joined_at"`
	Email    string    `json:"email" db:"email"`
}

type rtTeamsCreateTeam struct {
	Name string `json:"name"`
}

type rtTeamsInviteRequest struct {
	Email string  `json:"email"`
	Role  *string `json:"role"`
}

type rtTeamsAcceptInvite struct {
	Token string `json:"token"`
}

type rtTeamsUpdateRole struct {
	Role string `json:"role"`
}

type rtTeamsTeamWithOwner struct {
	ID         uuid.UUID `db:"id"`
	Name       string    `db:"name"`
	OwnerID    uuid.UUID `db:"owner_id"`
	CreatedAt  time.Time `db:"created_at"`
	OwnerEmail string    `db:"owner_email"`
}

var rtTeamsMemberRoles = []string{"admin", "developer", "viewer"}

func rtTeamsRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("GET /api/teams", h(rtTeamsList))
	r.Handle("POST /api/teams", h(rtTeamsCreate))
	r.Handle("DELETE /api/teams/{id}", h(rtTeamsRemove))
	r.Handle("POST /api/teams/{id}/invite", h(rtTeamsInvite))
	r.Handle("PUT /api/teams/{id}/members/{member_id}", h(rtTeamsUpdateMember))
	r.Handle("DELETE /api/teams/{id}/members/{member_id}", h(rtTeamsRemoveMember))
	r.Handle("POST /api/teams/accept", h(rtTeamsAcceptInviteHandler))
}

// rtTeamsList — GET /api/teams: teams owned or joined.
func rtTeamsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	// Single query: teams with owner email (eliminates N+1 for owner lookup)
	teams, err := queryAll[rtTeamsTeamWithOwner](ctx, st.DB,
		"SELECT DISTINCT t.id, t.name, t.owner_id, t.created_at, ou.email as owner_email "+
			"FROM teams t "+
			"LEFT JOIN team_members tm ON tm.team_id = t.id "+
			"JOIN users ou ON ou.id = t.owner_id "+
			"WHERE t.owner_id = $1 OR tm.user_id = $1 "+
			"ORDER BY t.created_at DESC", claims.Sub)
	if err != nil {
		return internalError("list teams", err)
	}

	// Batch fetch all members for all teams in one query
	ids := make([]uuid.UUID, 0, len(teams))
	for _, t := range teams {
		ids = append(ids, t.ID)
	}
	var members []rtTeamsTeamMember
	if len(ids) > 0 {
		members, err = queryAll[rtTeamsTeamMember](ctx, st.DB,
			"SELECT tm.id, tm.team_id, tm.user_id, tm.role, tm.joined_at, u.email "+
				"FROM team_members tm JOIN users u ON u.id = tm.user_id "+
				"WHERE tm.team_id = ANY($1) ORDER BY tm.joined_at ASC", ids)
		if err != nil {
			return internalError("list teams", err)
		}
	}
	byTeam := map[uuid.UUID][]rtTeamsTeamMember{}
	for _, m := range members {
		byTeam[m.TeamID] = append(byTeam[m.TeamID], m)
	}

	out := make([]any, 0, len(teams))
	for _, t := range teams {
		ms := byTeam[t.ID]
		if ms == nil {
			ms = []rtTeamsTeamMember{}
		}
		out = append(out, map[string]any{
			"id": t.ID, "name": t.Name, "owner_id": t.OwnerID, "owner_email": t.OwnerEmail,
			"created_at": t.CreatedAt, "members": ms, "is_owner": t.OwnerID == claims.Sub,
		})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// rtTeamsCreate — POST /api/teams.
func rtTeamsCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtTeamsCreateTeam
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 100 {
		return apiErr(http.StatusBadRequest, "Name must be 1-100 characters")
	}

	// Limit teams per user (10)
	count, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM teams WHERE owner_id = $1", claims.Sub)
	if err != nil {
		return internalError("create teams", err)
	}
	if count >= 10 {
		return apiErr(http.StatusBadRequest, "Team limit reached (10)")
	}

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return internalError("create teams", err)
	}
	defer tx.Rollback(ctx)
	team, err := queryOne[rtTeamsTeam](ctx, tx, "INSERT INTO teams (name, owner_id) VALUES ($1, $2) RETURNING *", name, claims.Sub)
	if err != nil {
		return internalError("create teams", err)
	}
	// Add owner as member with 'owner' role
	if _, err := execSQL(ctx, tx, "INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, 'owner')", team.ID, claims.Sub); err != nil {
		return internalError("create teams", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return internalError("create teams", err)
	}

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "team.create", new("team"), &name, nil, nil, claims.KeyID)
	writeJSON(w, http.StatusCreated, team)
	return nil
}

// rtTeamsRemove — DELETE /api/teams/{id} (owner only).
func rtTeamsRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	team, err := queryOpt[rtTeamsTeam](ctx, st.DB, "SELECT * FROM teams WHERE id = $1 AND owner_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("remove teams", err)
	}
	if team == nil {
		return apiErr(http.StatusNotFound, "Team not found or not owner")
	}
	if _, err := execSQL(ctx, st.DB, "DELETE FROM teams WHERE id = $1", id); err != nil {
		return internalError("remove teams", err)
	}
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "team.delete", new("team"), &team.Name, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "team.delete", &claims.Email, ip, new("team"), &team.Name, nil, nil, "warning", claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtTeamsInvite — POST /api/teams/{id}/invite (owner/admin only).
func rtTeamsInvite(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	teamID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtTeamsInviteRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	role, err := rtTeamsGetMemberRole(ctx, st, teamID, claims.Sub)
	if err != nil {
		return err
	}
	if role != "owner" && role != "admin" {
		return apiErr(http.StatusForbidden, "Only owners and admins can invite members")
	}

	// Bound invite volume per team. Each invite sends an email to an
	// arbitrary, caller-supplied recipient, so an uncapped endpoint is an SMTP
	// spam / phishing amplifier — cap both burst rate and total team size.
	recent, err := queryScalar[int64](ctx, st.DB,
		"SELECT COUNT(*) FROM team_invites WHERE team_id = $1 AND created_at > NOW() - INTERVAL '1 hour'", teamID)
	if err != nil {
		return internalError("invite", err)
	}
	if recent >= 20 {
		return apiErr(http.StatusTooManyRequests, "Invite limit reached for this team (max 20/hour)")
	}
	members, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM team_members WHERE team_id = $1", teamID)
	if err != nil {
		return internalError("invite", err)
	}
	if members >= 50 {
		return apiErr(http.StatusBadRequest, "Team member limit reached (50)")
	}

	email := strings.ToLower(strings.TrimSpace(body.Email))
	if email == "" || !strings.Contains(email, "@") {
		return apiErr(http.StatusBadRequest, "Valid email required")
	}
	inviteRole := "viewer"
	if body.Role != nil {
		inviteRole = *body.Role
	}
	if !slices.Contains(rtTeamsMemberRoles, inviteRole) {
		return apiErr(http.StatusBadRequest, "Role must be admin, developer, or viewer")
	}

	existing, err := queryScalarOpt[uuid.UUID](ctx, st.DB,
		"SELECT tm.id FROM team_members tm JOIN users u ON u.id = tm.user_id "+
			"WHERE tm.team_id = $1 AND u.email = $2", teamID, email)
	if err != nil {
		return internalError("invite", err)
	}
	if existing != nil {
		return apiErr(http.StatusConflict, "User is already a member")
	}

	token := strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := execSQL(ctx, st.DB, "INSERT INTO team_invites (team_id, email, role, token) VALUES ($1, $2, $3, $4)",
		teamID, email, inviteRole, rtAuthHashToken(token)); err != nil {
		return internalError("invite", err)
	}

	teamName, err := queryScalar[string](ctx, st.DB, "SELECT name FROM teams WHERE id = $1", teamID)
	if err != nil {
		return internalError("invite", err)
	}

	inviteURL := fmt.Sprintf("%s/teams/accept?token=%s", st.Config.BaseURL, token)
	_ = EmailSendEmail(ctx, st.DB, email, fmt.Sprintf("Invitation to join %s on DockPanel", teamName),
		fmt.Sprintf("<h2>You've been invited!</h2>"+
			"<p>%s has invited you to join <strong>%s</strong> as a <strong>%s</strong>.</p>"+
			"<p><a href=\"%s\" style=\"padding:10px 20px;background:#4F46E5;color:#fff;text-decoration:none;border-radius:6px\">Accept Invitation</a></p>"+
			"<p>This invitation expires in 7 days.</p>",
			rtTeamsEsc(claims.Email), rtTeamsEsc(teamName), inviteRole, inviteURL))

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Invitation sent"})
	return nil
}

// rtTeamsAcceptInviteHandler — POST /api/teams/accept.
func rtTeamsAcceptInviteHandler(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtTeamsAcceptInvite
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	inv, err := queryOpt[Tup4[uuid.UUID, uuid.UUID, string, string]](ctx, st.DB,
		"SELECT id, team_id, email, role FROM team_invites "+
			"WHERE token = $1 AND expires_at > NOW()", rtAuthHashToken(body.Token))
	if err != nil {
		return internalError("accept invite", err)
	}
	if inv == nil {
		return apiErr(http.StatusBadRequest, "Invalid or expired invitation")
	}
	inviteID, teamID, invitedEmail, role := inv.A, inv.B, inv.C, inv.D

	// Bind the invite to its intended recipient — otherwise anyone holding the
	// token (e.g. a forwarded invite email) could redeem it as the invited role.
	if !rtTeamsEqualFoldASCII(invitedEmail, claims.Email) {
		return apiErr(http.StatusForbidden, "This invitation was issued to a different email address")
	}

	// Add user as team member + delete invite atomically
	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return internalError("accept invite", err)
	}
	defer tx.Rollback(ctx)
	if _, err := execSQL(ctx, tx,
		"INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3) "+
			"ON CONFLICT (team_id, user_id) DO UPDATE SET role = $3", teamID, claims.Sub, role); err != nil {
		return internalError("accept invite", err)
	}
	if _, err := execSQL(ctx, tx, "DELETE FROM team_invites WHERE id = $1", inviteID); err != nil {
		return internalError("accept invite", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return internalError("accept invite", err)
	}

	teamName, err := queryScalar[string](ctx, st.DB, "SELECT name FROM teams WHERE id = $1", teamID)
	if err != nil {
		return internalError("accept invite", err)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "team.join", new("team"), &teamName, nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "team": teamName})
	return nil
}

// rtTeamsTargetRole is the role of member_id within team_id, or 404.
func rtTeamsTargetRole(ctx context.Context, st *AppState, memberID, teamID uuid.UUID, what string) (string, error) {
	role, err := queryScalarOpt[string](ctx, st.DB, "SELECT role FROM team_members WHERE id = $1 AND team_id = $2", memberID, teamID)
	if err != nil {
		return "", internalError(what, err)
	}
	if role == nil {
		return "", apiErr(http.StatusNotFound, "Member not found")
	}
	return *role, nil
}

// rtTeamsUpdateMember — PUT /api/teams/{id}/members/{member_id}.
func rtTeamsUpdateMember(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	teamID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	memberID, err := pathUUID(r, "member_id")
	if err != nil {
		return err
	}
	var body rtTeamsUpdateRole
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	caller, err := rtTeamsGetMemberRole(ctx, st, teamID, claims.Sub)
	if err != nil {
		return err
	}
	if caller != "owner" && caller != "admin" {
		return apiErr(http.StatusForbidden, "Insufficient permissions")
	}
	if !slices.Contains(rtTeamsMemberRoles, body.Role) {
		return apiErr(http.StatusBadRequest, "Role must be admin, developer, or viewer")
	}
	// Can't change owner's role
	target, err := rtTeamsTargetRole(ctx, st, memberID, teamID, "update member")
	if err != nil {
		return err
	}
	if target == "owner" {
		return apiErr(http.StatusForbidden, "Cannot change owner's role")
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE team_members SET role = $1 WHERE id = $2", body.Role, memberID); err != nil {
		return internalError("update member", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtTeamsRemoveMember — DELETE /api/teams/{id}/members/{member_id}.
func rtTeamsRemoveMember(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	teamID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	memberID, err := pathUUID(r, "member_id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	caller, err := rtTeamsGetMemberRole(ctx, st, teamID, claims.Sub)
	if err != nil {
		return err
	}
	if caller != "owner" && caller != "admin" {
		return apiErr(http.StatusForbidden, "Insufficient permissions")
	}
	// Can't remove owner
	target, err := rtTeamsTargetRole(ctx, st, memberID, teamID, "remove member")
	if err != nil {
		return err
	}
	if target == "owner" {
		return apiErr(http.StatusForbidden, "Cannot remove the team owner")
	}
	if _, err := execSQL(ctx, st.DB, "DELETE FROM team_members WHERE id = $1", memberID); err != nil {
		return internalError("remove member", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtTeamsEsc is a minimal HTML-text escape for values interpolated into
// invite email bodies (team name, inviter email), so a crafted team name
// cannot inject markup into the outbound HTML email.
func rtTeamsEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#x27;").Replace(s)
}

// rtTeamsEqualFoldASCII is str::eq_ignore_ascii_case.
func rtTeamsEqualFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func rtTeamsGetMemberRole(ctx context.Context, st *AppState, teamID, userID uuid.UUID) (string, error) {
	role, err := queryScalarOpt[string](ctx, st.DB, "SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2", teamID, userID)
	if err != nil {
		return "", internalError("remove member", err)
	}
	if role == nil {
		return "", apiErr(http.StatusForbidden, "Not a member of this team")
	}
	return *role, nil
}
