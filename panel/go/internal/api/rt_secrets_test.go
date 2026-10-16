package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// The exact scenario byte-slicing panicked on: offset 4 lands mid-character.
func TestRtSecretsMultibyteValueStraddlingTheOldByteOffset(t *testing.T) {
	if got := rtSecretsMaskValue("aa日BBBB"); got != "aa日B••••••••" {
		t.Fatal(got)
	}
}

func TestRtSecretsAllMultibyteValue(t *testing.T) {
	if got := rtSecretsMaskValue("日本語です"); got != "日本語で••••••••" {
		t.Fatal(got)
	}
}

func TestRtSecretsShortValuesAreFullyMasked(t *testing.T) {
	for _, v := range []string{"", "ab", "abcd"} {
		if got := rtSecretsMaskValue(v); got != "••••••••" {
			t.Fatal(v, got)
		}
	}
}

func TestRtSecretsASCIIValuesKeepTheFourCharPrefix(t *testing.T) {
	if rtSecretsMaskValue("abcde") != "abcd••••••••" || rtSecretsMaskValue("supersecretvalue") != "supe••••••••" {
		t.Fatal()
	}
}

// The vault key is DERIVED from the JWT secret and never equal to it; AES-GCM
// is authenticated, so the wrong key yields Err, not plausible rubbish.
func TestRtSecretsTheVaultKeyIsNotTheJWTSecret(t *testing.T) {
	jwt := "0123456789abcdef0123456789abcdef"
	key := rtSecretsGetEncryptionKey(jwt)
	if key == jwt {
		t.Fatal("the vault key must not be the JWT secret itself")
	}
	sealed, err := SecretsCryptoEncrypt("hunter2", key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := SecretsCryptoDecrypt(sealed, key); err != nil || got != "hunter2" {
		t.Fatal(got, err)
	}
	if _, err := SecretsCryptoDecrypt(sealed, jwt); err == nil {
		t.Fatal("the JWT secret must not open the vault")
	}
}

func TestRtSecretsUpdateVaultDistinguishesAbsentFromNull(t *testing.T) {
	var a, b, c rtSecretsUpdateVaultRequest
	_ = decodeJSONBytes([]byte(`{"name":"x"}`), &a)
	_ = decodeJSONBytes([]byte(`{"site_id":null}`), &b)
	id := uuid.New()
	_ = decodeJSONBytes([]byte(`{"site_id":"`+id.String()+`"}`), &c)
	if a.SiteIDPresent || !b.SiteIDPresent || b.SiteID != nil || !c.SiteIDPresent || c.SiteID == nil || *c.SiteID != id {
		t.Fatal(a, b, c)
	}
}

func TestDBRtSecretsOwnershipAndVersionIDOR(t *testing.T) {
	e := rtIdentityTestEnv(t)
	tok := e.setupAdmin(t, "admin@x.test", "correct-horse")
	ctx := context.Background()
	hash, _ := hashPassword("other-password")
	_, _ = execSQL(ctx, e.st.DB, "INSERT INTO users (email, password_hash, role, email_verified) VALUES ('o@x.test', $1, 'user', TRUE)", hash)
	lw, _ := e.do(t, "POST", "/api/auth/login", map[string]any{"email": "o@x.test", "password": "other-password"}, "X-Real-IP", "10.0.1.1")
	otok := rtIdentityCookieToken(t, lw)
	A := []string{"Authorization", "Bearer " + tok}
	O := []string{"Authorization", "Bearer " + otok}

	w, v := e.do(t, "POST", "/api/secrets/vaults", map[string]any{"name": "mine"}, A...)
	if w.Code != 201 {
		t.Fatal(w.Code, v)
	}
	vid := v["id"].(string)
	w, s := e.do(t, "POST", "/api/secrets/vaults/"+vid+"/secrets", map[string]any{"key": "DB_PASS", "value": "s3cr3t-value"}, A...)
	if w.Code != 201 || s["value"] != "s3cr••••••••" {
		t.Fatal(w.Code, s)
	}
	sid := s["id"].(string)
	if got := rtSecretsTestGetArray(t, e, "/api/secrets/vaults/"+vid+"/secrets?reveal=true", A); len(got) != 1 || jsonGet(got[0], "value") != "s3cr3t-value" {
		t.Fatal("reveal decrypts", got)
	}
	// The other user cannot reach the vault at all.
	if w, _ := e.do(t, "GET", "/api/secrets/vaults/"+vid+"/pull", nil, O...); w.Code != 404 {
		t.Fatal("pull", w.Code)
	}
	// Cross-vault IDOR: their own vault id + my secret id reads nothing.
	w, ov := e.do(t, "POST", "/api/secrets/vaults", map[string]any{"name": "theirs"}, O...)
	if w.Code != 201 {
		t.Fatal(w.Code)
	}
	w2 := rtSecretsTestGetArray(t, e, "/api/secrets/vaults/"+ov["id"].(string)+"/secrets/"+sid+"/versions", O)
	if len(w2) != 0 {
		t.Fatal("cross-vault version history must be empty", w2)
	}
	if got := rtSecretsTestGetArray(t, e, "/api/secrets/vaults/"+vid+"/secrets/"+sid+"/versions", A); len(got) != 1 {
		t.Fatal(got)
	}
	// Linking a vault to a site the caller cannot reach is refused.
	if w, _ := e.do(t, "PUT", "/api/secrets/vaults/"+vid, map[string]any{"site_id": uuid.NewString()}, A...); w.Code != 404 {
		t.Fatal("unreachable site", w.Code)
	}
	// Explicit null unlinks; absent leaves alone.
	if w, out := e.do(t, "PUT", "/api/secrets/vaults/"+vid, map[string]any{"site_id": nil}, A...); w.Code != 200 || out["site_id"] != nil {
		t.Fatal(w.Code, out)
	}
}

func rtSecretsTestGetArray(t *testing.T, e *rtIdentityEnv, path string, hdr []string) []any {
	t.Helper()
	r, _ := e.do(t, "GET", path, nil, hdr...)
	if r.Code != 200 {
		t.Fatal(path, r.Code, r.Body.String())
	}
	var out []any
	_ = json.Unmarshal(r.Body.Bytes(), &out)
	return out
}
