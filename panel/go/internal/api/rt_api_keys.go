package api

// Port of panel/backend/src/routes/api_keys.rs — long-lived dp_ API keys.
// Authentication with them lives in core_auth.go (authenticateAPIKey).

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type rtApiKeysCreateKeyRequest struct {
	Name string `json:"name"`
}

type rtApiKeysApiKeyInfo struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	Name       string     `json:"name" db:"name"`
	KeyPrefix  string     `json:"key_prefix" db:"key_prefix"`
	LastUsedAt *time.Time `json:"last_used_at" db:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

func rtApiKeysRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("GET /api/api-keys", h(rtApiKeysList))
	r.Handle("POST /api/api-keys", h(rtApiKeysCreate))
	r.Handle("DELETE /api/api-keys/{id}", h(rtApiKeysRevoke))
	r.Handle("POST /api/api-keys/{id}/rotate", h(rtApiKeysRotate))
}

// rtApiKeysNewKey generates dp_<64 hex>, its 12-char prefix and SHA-256 hex.
func rtApiKeysNewKey() (key, prefix, hash string) {
	raw := strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	key = "dp_" + raw
	return key, key[:12], rtAuthHashToken(key)
}

// rtApiKeysList — GET /api/api-keys: the caller's keys.
func rtApiKeysList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	keys, err := queryAll[rtApiKeysApiKeyInfo](r.Context(), st.DB,
		"SELECT id, name, key_prefix, last_used_at, created_at FROM api_keys "+
			"WHERE user_id = $1 ORDER BY created_at DESC", claims.Sub)
	if err != nil {
		return internalError("list api_keys", err)
	}
	writeJSON(w, http.StatusOK, keys)
	return nil
}

// rtApiKeysCreate — POST /api/api-keys: returns the full key ONCE.
func rtApiKeysCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtApiKeysCreateKeyRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 100 {
		return apiErr(http.StatusBadRequest, "Name must be 1-100 characters")
	}

	// Limit 10 per user
	count, err := queryScalar[int64](ctx, st.DB, "SELECT COUNT(*) FROM api_keys WHERE user_id = $1", claims.Sub)
	if err != nil {
		return internalError("create api_keys", err)
	}
	if count >= 10 {
		return apiErr(http.StatusBadRequest, "Maximum 10 API keys per account")
	}

	key, prefix, keyHash := rtApiKeysNewKey()
	if _, err := execSQL(ctx, st.DB, "INSERT INTO api_keys (user_id, name, key_hash, key_prefix) VALUES ($1, $2, $3, $4)",
		claims.Sub, name, keyHash, prefix); err != nil {
		return internalError("create api_keys", err)
	}

	rtApiKeysLog(ctx, st, r, claims, "api_key.created", name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"key": key, "prefix": prefix, "name": name, "message": "Save this key — it won't be shown again.",
	})
	return nil
}

func rtApiKeysLog(ctx context.Context, st *AppState, r *http.Request, claims *Claims, action, name string) {
	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, action, new("api_key"), &name, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, action, &claims.Email, ip, new("api_key"), &name, nil, nil, "info", claims.KeyID)
}

// rtApiKeysOwnedName is the key's name when it belongs to the caller, else 404.
func rtApiKeysOwnedName(ctx context.Context, st *AppState, id, userID uuid.UUID, what string) (string, error) {
	name, err := queryScalarOpt[string](ctx, st.DB, "SELECT name FROM api_keys WHERE id = $1 AND user_id = $2", id, userID)
	if err != nil {
		return "", internalError(what, err)
	}
	if name == nil {
		return "", apiErr(http.StatusNotFound, "API key not found")
	}
	return *name, nil
}

// rtApiKeysRevoke — DELETE /api/api-keys/{id}.
func rtApiKeysRevoke(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// Fetch key name before deleting for activity log
	name, err := rtApiKeysOwnedName(ctx, st, id, claims.Sub, "revoke")
	if err != nil {
		return err
	}
	n, err := execSQL(ctx, st.DB, "DELETE FROM api_keys WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("revoke", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "API key not found")
	}
	rtApiKeysLog(ctx, st, r, claims, "api_key.revoked", name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtApiKeysRotate — POST /api/api-keys/{id}/rotate: atomically replace the
// old key with a new one (same id and name, new hash + prefix + timestamp).
func rtApiKeysRotate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	name, err := rtApiKeysOwnedName(ctx, st, id, claims.Sub, "rotate")
	if err != nil {
		return err
	}
	key, prefix, keyHash := rtApiKeysNewKey()
	if _, err := execSQL(ctx, st.DB,
		"UPDATE api_keys SET key_hash = $1, key_prefix = $2, created_at = NOW() WHERE id = $3 AND user_id = $4",
		keyHash, prefix, id, claims.Sub); err != nil {
		return internalError("rotate", err)
	}
	rtApiKeysLog(ctx, st, r, claims, "api_key.rotated", name)
	writeJSON(w, http.StatusOK, map[string]any{
		"key": key, "prefix": prefix, "name": name,
		"message": "Key rotated — save the new key, the old one is now invalid.",
	})
	return nil
}
