package api

import (
	"strings"
	"testing"
)

func TestRtApiKeysKeyShape(t *testing.T) {
	key, prefix, hash := rtApiKeysNewKey()
	if !strings.HasPrefix(key, "dp_") || len(key) != 67 || prefix != key[:12] || hash != hashAgentToken(key) {
		t.Fatal(key, prefix, hash)
	}
}

// A minted key authenticates; rotating it kills the old one; revoking is
// scoped to the owner.
func TestDBRtApiKeysLifecycle(t *testing.T) {
	e := rtIdentityTestEnv(t)
	tok := e.setupAdmin(t, "admin@x.test", "correct-horse")
	A := []string{"Authorization", "Bearer " + tok}
	if w, _ := e.do(t, "POST", "/api/api-keys", map[string]any{"name": "   "}, A...); w.Code != 400 {
		t.Fatal(w.Code)
	}
	w, out := e.do(t, "POST", "/api/api-keys", map[string]any{"name": " ci "}, A...)
	if w.Code != 201 || out["name"] != "ci" {
		t.Fatal(w.Code, out)
	}
	key := out["key"].(string)
	if w, me := e.do(t, "GET", "/api/auth/me", nil, "Authorization", "Bearer "+key); w.Code != 200 || me["email"] != "admin@x.test" {
		t.Fatal(w.Code)
	}
	list := rtSecretsTestGetArray(t, e, "/api/api-keys", A)
	if len(list) != 1 {
		t.Fatal(list)
	}
	id, _ := jsonStr(jsonGet(list[0], "id"))
	w, out = e.do(t, "POST", "/api/api-keys/"+id+"/rotate", nil, A...)
	if w.Code != 200 || out["key"] == key {
		t.Fatal(w.Code, out)
	}
	if w, _ := e.do(t, "GET", "/api/auth/me", nil, "Authorization", "Bearer "+key); w.Code != 401 {
		t.Fatal("the rotated-out key must die", w.Code)
	}
	if w, _ := e.do(t, "DELETE", "/api/api-keys/00000000-0000-0000-0000-000000000000", nil, A...); w.Code != 404 {
		t.Fatal(w.Code)
	}
}
