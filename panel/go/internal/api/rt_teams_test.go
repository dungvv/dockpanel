package api

import (
	"context"
	"testing"
)

func TestRtTeamsEscAndCaseFold(t *testing.T) {
	if rtTeamsEsc(`<b a="x">'&`) != "&lt;b a=&quot;x&quot;&gt;&#x27;&amp;" {
		t.Fatal(rtTeamsEsc(`<b a="x">'&`))
	}
	if !rtTeamsEqualFoldASCII("A@B.c", "a@b.C") || rtTeamsEqualFoldASCII("a@b.c", "a@b.cc") {
		t.Fatal()
	}
}

// An invite is bound to the address it was issued to: a forwarded token is
// refused for anyone else.
func TestDBRtTeamsInviteIsBoundToItsRecipient(t *testing.T) {
	e := rtIdentityTestEnv(t)
	tok := e.setupAdmin(t, "admin@x.test", "correct-horse")
	ctx := context.Background()
	A := []string{"Authorization", "Bearer " + tok}
	w, team := e.do(t, "POST", "/api/teams", map[string]any{"name": "ops"}, A...)
	if w.Code != 201 {
		t.Fatal(w.Code, team)
	}
	tid := team["id"].(string)
	if w, _ := e.do(t, "POST", "/api/teams/"+tid+"/invite", map[string]any{"email": "Invitee@X.test", "role": "owner"}, A...); w.Code != 400 {
		t.Fatal("owner is not invitable", w.Code)
	}
	// Plant an invite with a known token (the real one only travels by mail).
	_, _ = execSQL(ctx, e.st.DB, "INSERT INTO team_invites (team_id, email, role, token) VALUES ($1, 'invitee@x.test', 'viewer', $2)", tid, rtAuthHashToken("tok123"))
	hash, _ := hashPassword("other-password")
	_, _ = execSQL(ctx, e.st.DB, "INSERT INTO users (email, password_hash, role, email_verified) VALUES ('eve@x.test', $1, 'user', TRUE)", hash)
	lw, _ := e.do(t, "POST", "/api/auth/login", map[string]any{"email": "eve@x.test", "password": "other-password"}, "X-Real-IP", "10.0.1.1")
	eve := []string{"Authorization", "Bearer " + rtIdentityCookieToken(t, lw)}
	if w, _ := e.do(t, "POST", "/api/teams/accept", map[string]any{"token": "tok123"}, eve...); w.Code != 403 {
		t.Fatal("a forwarded invite must not be redeemable", w.Code)
	}
	if w, _ := e.do(t, "POST", "/api/teams/"+tid+"/invite", map[string]any{"email": "x@x.test"}, eve...); w.Code != 403 {
		t.Fatal("non-members cannot invite", w.Code)
	}
	if w, _ := e.do(t, "DELETE", "/api/teams/"+tid, nil, eve...); w.Code != 404 {
		t.Fatal("only the owner deletes", w.Code)
	}
}
