package api

// Port of panel/backend/src/routes/secrets.rs — the Secrets Manager vault.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
)

type rtSecretsSecretVault struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	UserID      uuid.UUID  `json:"user_id" db:"user_id"`
	Name        string     `json:"name" db:"name"`
	Description *string    `json:"description" db:"description"`
	SiteID      *uuid.UUID `json:"site_id" db:"site_id"`
	ServerID    *uuid.UUID `json:"server_id" db:"server_id"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

type rtSecretsSecretEntry struct {
	ID          uuid.UUID `json:"id"`
	VaultID     uuid.UUID `json:"vault_id"`
	Key         string    `json:"key"`
	Value       string    `json:"value"` // Decrypted on read, masked by default
	Description *string   `json:"description"`
	SecretType  string    `json:"secret_type"`
	AutoInject  bool      `json:"auto_inject"`
	Version     int32     `json:"version"`
	UpdatedBy   *string   `json:"updated_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type rtSecretsSecretRow struct {
	ID             uuid.UUID `db:"id"`
	VaultID        uuid.UUID `db:"vault_id"`
	Key            string    `db:"key"`
	EncryptedValue string    `db:"encrypted_value"`
	Description    *string   `db:"description"`
	SecretType     string    `db:"secret_type"`
	AutoInject     bool      `db:"auto_inject"`
	Version        int32     `db:"version"`
	UpdatedBy      *string   `db:"updated_by"`
	CreatedAt      time.Time `db:"created_at"`
	UpdatedAt      time.Time `db:"updated_at"`
}

func (row *rtSecretsSecretRow) entry(value string) rtSecretsSecretEntry {
	return rtSecretsSecretEntry{
		ID: row.ID, VaultID: row.VaultID, Key: row.Key, Value: value, Description: row.Description,
		SecretType: row.SecretType, AutoInject: row.AutoInject, Version: row.Version,
		UpdatedBy: row.UpdatedBy, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

type rtSecretsSecretVersion struct {
	ID         uuid.UUID `json:"id" db:"id"`
	SecretID   uuid.UUID `json:"secret_id" db:"secret_id"`
	Version    int32     `json:"version" db:"version"`
	ChangedBy  *string   `json:"changed_by" db:"changed_by"`
	ChangeType string    `json:"change_type" db:"change_type"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

type rtSecretsCreateVaultRequest struct {
	Name        string     `json:"name"`
	Description *string    `json:"description"`
	SiteID      *uuid.UUID `json:"site_id"`
}

// rtSecretsUpdateVaultRequest. SiteIDPresent is the outer Option of the Rust
// Option<Option<Uuid>>, deliberately: the COALESCE shape the other two fields
// use can SET a value and never CLEAR one — the client sends null for "none",
// the handler folds it back onto the stored value, and the save answers green
// having changed nothing. A link that cannot be removed is worse here than a
// name that cannot be blanked: it decides whose site gets the secrets.
// Absent key = leave the link alone. Explicit null = unlink.
type rtSecretsUpdateVaultRequest struct {
	Name          *string    `json:"name"`
	Description   *string    `json:"description"`
	SiteID        *uuid.UUID `json:"site_id"`
	SiteIDPresent bool       `json:"-"`
}

func (u *rtSecretsUpdateVaultRequest) UnmarshalJSON(b []byte) error {
	type plain rtSecretsUpdateVaultRequest
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		return err
	}
	_, p.SiteIDPresent = keys["site_id"]
	*u = rtSecretsUpdateVaultRequest(p)
	return nil
}

type rtSecretsCreateSecretRequest struct {
	Key         string  `json:"key"`
	Value       string  `json:"value"`
	Description *string `json:"description"`
	SecretType  *string `json:"secret_type"`
	AutoInject  *bool   `json:"auto_inject"`
}

type rtSecretsUpdateSecretRequest struct {
	Value       *string `json:"value"`
	Description *string `json:"description"`
	AutoInject  *bool   `json:"auto_inject"`
}

type rtSecretsPaginationQuery struct {
	Limit  *int64 `json:"limit"`
	Offset *int64 `json:"offset"`
	Reveal *bool  `json:"reveal"` // If true, show actual values (default: masked)
}

var rtSecretsValidTypes = []string{"env", "api_key", "password", "certificate", "custom"}

func rtSecretsRegister(r *Router) {
	st := r.St
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(st, w, req) }
	}
	r.Handle("GET /api/secrets/vaults", h(rtSecretsListVaults))
	r.Handle("POST /api/secrets/vaults", h(rtSecretsCreateVault))
	r.Handle("DELETE /api/secrets/vaults/{vault_id}", h(rtSecretsDeleteVault))
	r.Handle("PUT /api/secrets/vaults/{vault_id}", h(rtSecretsUpdateVault))
	r.Handle("GET /api/secrets/vaults/{vault_id}/secrets", h(rtSecretsListSecrets))
	r.Handle("POST /api/secrets/vaults/{vault_id}/secrets", h(rtSecretsCreateSecret))
	r.Handle("PUT /api/secrets/vaults/{vault_id}/secrets/{secret_id}", h(rtSecretsUpdateSecret))
	r.Handle("DELETE /api/secrets/vaults/{vault_id}/secrets/{secret_id}", h(rtSecretsDeleteSecret))
	r.Handle("GET /api/secrets/vaults/{vault_id}/secrets/{secret_id}/versions", h(rtSecretsListVersions))
	r.Handle("POST /api/secrets/vaults/{vault_id}/inject/{site_id}", h(rtSecretsInjectToSite))
	r.Handle("GET /api/secrets/vaults/{vault_id}/pull", h(rtSecretsPull))
	r.Handle("GET /api/secrets/vaults/{vault_id}/export", h(rtSecretsExportVault))
	r.Handle("POST /api/secrets/vaults/{vault_id}/import", h(rtSecretsImportVault))
}

// rtSecretsAssertSiteReachable: a vault may only be linked to a site the
// caller may already reach. The deploy-time injector matches vaults to sites
// on `v.site_id = $1` ALONE, with no owner test — safe only while nothing can
// write the column. Validating on the write side keeps that join sound, with
// the same predicate the rest of the panel uses for "which sites a caller
// sees".
func rtSecretsAssertSiteReachable(ctx context.Context, st *AppState, siteID, userID uuid.UUID) error {
	found, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT s.id FROM sites s WHERE "+SiteCallerPredicate, siteID, userID)
	if err != nil {
		return internalError("verify vault site", err)
	}
	if found == nil {
		return apiErr(http.StatusNotFound, "That site does not exist, or it belongs to another account.")
	}
	return nil
}

// rtSecretsGetEncryptionKey derives the vault key to WRITE with. Provisioning
// paths that generate credentials (site creation writing the CMS admin
// password into the site's vault) must encrypt with the SAME key the Secrets
// Manager decrypts with.
//
// ⚠ READERS MUST NOT USE THIS. A value written before SECRETS_ENCRYPTION_KEY
// was set is not readable under it; decrypt through SecretsCryptoDecryptVault,
// which tries every source. Handing this single string to a decrypt is what
// made setting that variable a one-way door for the whole vault.
func rtSecretsGetEncryptionKey(jwtSecret string) string {
	return SecretsCryptoVaultKeyPrimary(jwtSecret)
}

// rtSecretsMaskValue walks chars, not bytes: byte-slicing value[:4] panicked
// whenever offset 4 was not a UTF-8 boundary (a pasted passphrase), on every
// masking call site.
func rtSecretsMaskValue(value string) string {
	rs := []rune(value)
	if len(rs) <= 4 {
		return "••••••••"
	}
	return string(rs[:4]) + "••••••••"
}

// ── Vault CRUD ──────────────────────────────────────────────────────────────

// rtSecretsListVaults — GET /api/secrets/vaults.
func rtSecretsListVaults(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	vaults, err := queryAll[rtSecretsSecretVault](r.Context(), st.DB,
		"SELECT * FROM secret_vaults WHERE user_id = $1 ORDER BY created_at DESC LIMIT 200", claims.Sub)
	if err != nil {
		return internalError("list vaults", err)
	}
	writeJSON(w, http.StatusOK, vaults)
	return nil
}

// rtSecretsCreateVault — POST /api/secrets/vaults.
func rtSecretsCreateVault(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var req rtSecretsCreateVaultRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if req.Name == "" || len(req.Name) > 100 {
		return apiErr(http.StatusBadRequest, "Name must be 1-100 characters")
	}
	if req.SiteID != nil {
		if err := rtSecretsAssertSiteReachable(ctx, st, *req.SiteID, claims.Sub); err != nil {
			return err
		}
	}
	vault, err := queryOne[rtSecretsSecretVault](ctx, st.DB,
		"INSERT INTO secret_vaults (user_id, name, description, site_id) VALUES ($1, $2, $3, $4) RETURNING *",
		claims.Sub, req.Name, req.Description, req.SiteID)
	if err != nil {
		return internalError("create vault", err)
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "vault.create", new("vault"), &req.Name, nil, nil, claims.KeyID)
	writeJSON(w, http.StatusCreated, vault)
	return nil
}

// rtSecretsDeleteVault — DELETE /api/secrets/vaults/{id}.
func rtSecretsDeleteVault(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "vault_id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM secret_vaults WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("delete vault", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Vault not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtSecretsUpdateVault — PUT /api/secrets/vaults/{id}.
func rtSecretsUpdateVault(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "vault_id")
	if err != nil {
		return err
	}
	var req rtSecretsUpdateVaultRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if req.Name != nil && (*req.Name == "" || len(*req.Name) > 100) {
		return apiErr(http.StatusBadRequest, "Name must be 1-100 characters")
	}
	if req.SiteID != nil {
		if err := rtSecretsAssertSiteReachable(ctx, st, *req.SiteID, claims.Sub); err != nil {
			return err
		}
	}
	// $5 carries "was the key present at all", so an explicit null unlinks
	// while an absent key leaves the link untouched. COALESCE cannot express
	// that.
	vault, err := queryOpt[rtSecretsSecretVault](ctx, st.DB,
		"UPDATE secret_vaults SET name = COALESCE($1, name), description = COALESCE($2, description), "+
			"site_id = CASE WHEN $5 THEN $6::uuid ELSE site_id END, "+
			"updated_at = NOW() WHERE id = $3 AND user_id = $4 RETURNING *",
		req.Name, req.Description, id, claims.Sub, req.SiteIDPresent, req.SiteID)
	if err != nil {
		return internalError("update vault", err)
	}
	if vault == nil {
		return apiErr(http.StatusNotFound, "Vault not found")
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "vault.update", new("vault"), &vault.Name, nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, vault)
	return nil
}

// ── Secret CRUD ─────────────────────────────────────────────────────────────

// rtSecretsVerifyVault verifies vault ownership.
func rtSecretsVerifyVault(ctx context.Context, st *AppState, vaultID, userID uuid.UUID) error {
	exists, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM secret_vaults WHERE id = $1 AND user_id = $2", vaultID, userID)
	if err != nil {
		return internalError("delete vault", err)
	}
	if exists == nil {
		return apiErr(http.StatusNotFound, "Vault not found")
	}
	return nil
}

// rtSecretsDecryptOr is decrypt_vault(..).unwrap_or(def).
func rtSecretsDecryptOr(enc, jwt, def string) string {
	v, err := SecretsCryptoDecryptVault(enc, jwt)
	if err != nil {
		return def
	}
	return v
}

// rtSecretsListSecrets — GET /api/secrets/vaults/{vault_id}/secrets.
func rtSecretsListSecrets(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	vaultID, err := pathUUID(r, "vault_id")
	if err != nil {
		return err
	}
	var params rtSecretsPaginationQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	ctx := r.Context()
	if err := rtSecretsVerifyVault(ctx, st, vaultID, claims.Sub); err != nil {
		return err
	}
	// Read path: every key source, not just the one we would write with.
	jwt := st.Config.JWTSecret
	reveal := params.Reveal != nil && *params.Reveal

	rows, err := queryAll[rtSecretsSecretRow](ctx, st.DB, "SELECT * FROM secrets WHERE vault_id = $1 ORDER BY key ASC", vaultID)
	if err != nil {
		return internalError("list secrets", err)
	}
	entries := make([]rtSecretsSecretEntry, 0, len(rows))
	for i := range rows {
		var value string
		if reveal {
			value = rtSecretsDecryptOr(rows[i].EncryptedValue, jwt, "••••••••")
		} else {
			value = rtSecretsMaskValue(rtSecretsDecryptOr(rows[i].EncryptedValue, jwt, ""))
		}
		entries = append(entries, rows[i].entry(value))
	}
	writeJSON(w, http.StatusOK, entries)
	return nil
}

// rtSecretsCreateSecret — POST /api/secrets/vaults/{vault_id}/secrets.
func rtSecretsCreateSecret(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	vaultID, err := pathUUID(r, "vault_id")
	if err != nil {
		return err
	}
	var req rtSecretsCreateSecretRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if err := rtSecretsVerifyVault(ctx, st, vaultID, claims.Sub); err != nil {
		return err
	}
	if req.Key == "" || len(req.Key) > 200 {
		return apiErr(http.StatusBadRequest, "Key must be 1-200 characters")
	}
	if req.Value == "" {
		return apiErr(http.StatusBadRequest, "Value cannot be empty")
	}
	secretType := "env"
	if req.SecretType != nil {
		secretType = *req.SecretType
	}
	if !slices.Contains(rtSecretsValidTypes, secretType) {
		return apiErr(http.StatusBadRequest, "Invalid secret_type")
	}

	encrypted, err := SecretsCryptoEncrypt(req.Value, rtSecretsGetEncryptionKey(st.Config.JWTSecret))
	if err != nil {
		return apiErr(http.StatusInternalServerError, err.Error())
	}
	autoInject := req.AutoInject != nil && *req.AutoInject
	row, err := queryOne[rtSecretsSecretRow](ctx, st.DB,
		"INSERT INTO secrets (vault_id, key, encrypted_value, description, secret_type, auto_inject, updated_by) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
		vaultID, req.Key, encrypted, req.Description, secretType, autoInject, claims.Email)
	if err != nil {
		return internalError("create secret", err)
	}

	// Record initial version
	_, _ = execSQL(ctx, st.DB,
		"INSERT INTO secret_versions (secret_id, version, encrypted_value, changed_by, change_type) VALUES ($1, 1, $2, $3, 'create')",
		row.ID, encrypted, claims.Email)

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "secret.create", new("secret"), &req.Key, nil, nil, claims.KeyID)
	writeJSON(w, http.StatusCreated, row.entry(rtSecretsMaskValue(req.Value)))
	return nil
}

// rtSecretsUpdateSecret — PUT /api/secrets/vaults/{vault_id}/secrets/{secret_id}.
func rtSecretsUpdateSecret(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	vaultID, err := pathUUID(r, "vault_id")
	if err != nil {
		return err
	}
	secretID, err := pathUUID(r, "secret_id")
	if err != nil {
		return err
	}
	var req rtSecretsUpdateSecretRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if err := rtSecretsVerifyVault(ctx, st, vaultID, claims.Sub); err != nil {
		return err
	}
	key := rtSecretsGetEncryptionKey(st.Config.JWTSecret)

	current, err := queryOpt[rtSecretsSecretRow](ctx, st.DB, "SELECT * FROM secrets WHERE id = $1 AND vault_id = $2", secretID, vaultID)
	if err != nil {
		return internalError("update secret", err)
	}
	if current == nil {
		return apiErr(http.StatusNotFound, "Secret not found")
	}
	newVersion := current.Version + 1

	if req.Value != nil {
		encrypted, err := SecretsCryptoEncrypt(*req.Value, key)
		if err != nil {
			return apiErr(http.StatusInternalServerError, err.Error())
		}
		// Save old version
		_, _ = execSQL(ctx, st.DB,
			"INSERT INTO secret_versions (secret_id, version, encrypted_value, changed_by, change_type) "+
				"VALUES ($1, $2, $3, $4, 'update')", secretID, newVersion, encrypted, claims.Email)
		if _, err := execSQL(ctx, st.DB,
			"UPDATE secrets SET encrypted_value = $2, version = $3, updated_by = $4, "+
				"description = COALESCE($5, description), auto_inject = COALESCE($6, auto_inject), "+
				"updated_at = NOW() WHERE id = $1",
			secretID, encrypted, newVersion, claims.Email, req.Description, req.AutoInject); err != nil {
			return internalError("update secret", err)
		}
	} else {
		// Update metadata only
		if _, err := execSQL(ctx, st.DB,
			"UPDATE secrets SET description = COALESCE($2, description), "+
				"auto_inject = COALESCE($3, auto_inject), updated_at = NOW() WHERE id = $1",
			secretID, req.Description, req.AutoInject); err != nil {
			return internalError("update secret", err)
		}
	}

	row, err := queryOne[rtSecretsSecretRow](ctx, st.DB, "SELECT * FROM secrets WHERE id = $1", secretID)
	if err != nil {
		return internalError("update secret", err)
	}
	writeJSON(w, http.StatusOK, row.entry(rtSecretsMaskValue(rtSecretsDecryptOr(row.EncryptedValue, st.Config.JWTSecret, ""))))
	return nil
}

// rtSecretsDeleteSecret — DELETE /api/secrets/vaults/{vault_id}/secrets/{secret_id}.
func rtSecretsDeleteSecret(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	vaultID, err := pathUUID(r, "vault_id")
	if err != nil {
		return err
	}
	secretID, err := pathUUID(r, "secret_id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := rtSecretsVerifyVault(ctx, st, vaultID, claims.Sub); err != nil {
		return err
	}
	n, err := execSQL(ctx, st.DB, "DELETE FROM secrets WHERE id = $1 AND vault_id = $2", secretID, vaultID)
	if err != nil {
		return internalError("delete secret", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Secret not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtSecretsListVersions — GET …/secrets/{secret_id}/versions.
func rtSecretsListVersions(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	vaultID, err := pathUUID(r, "vault_id")
	if err != nil {
		return err
	}
	secretID, err := pathUUID(r, "secret_id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := rtSecretsVerifyVault(ctx, st, vaultID, claims.Sub); err != nil {
		return err
	}
	// Scoped to the ownership-verified vault: without the JOIN a caller who
	// owns ANY vault could pass their vault_id + another tenant's secret_id
	// and read that secret's version history (cross-vault IDOR).
	versions, err := queryAll[rtSecretsSecretVersion](ctx, st.DB,
		"SELECT sv.id, sv.secret_id, sv.version, sv.changed_by, sv.change_type, sv.created_at "+
			"FROM secret_versions sv JOIN secrets s ON s.id = sv.secret_id AND s.vault_id = $2 "+
			"WHERE sv.secret_id = $1 ORDER BY sv.version DESC", secretID, vaultID)
	if err != nil {
		return internalError("list versions", err)
	}
	writeJSON(w, http.StatusOK, versions)
	return nil
}

// ── Inject into Site ────────────────────────────────────────────────────────

// rtSecretsInjectToSite — POST /api/secrets/vaults/{vault_id}/inject/{site_id}.
func rtSecretsInjectToSite(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	vaultID, err := pathUUID(r, "vault_id")
	if err != nil {
		return err
	}
	siteID, err := pathUUID(r, "site_id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := rtSecretsVerifyVault(ctx, st, vaultID, claims.Sub); err != nil {
		return err
	}

	// This writes DECRYPTED secrets into a site's nginx env on whichever host
	// the handle points at. Taking that from the caller's selection meant one
	// tenant's secrets could land on a machine their site does not run on —
	// a misdispatch here is a disclosure, not a wrong answer. The row names
	// the host.
	domain, agent, err := siteAgentForCaller(ctx, st, siteID, claims)
	if err != nil {
		return err
	}

	rows, err := queryAll[rtSecretsSecretRow](ctx, st.DB, "SELECT * FROM secrets WHERE vault_id = $1 AND auto_inject = TRUE ORDER BY key", vaultID)
	if err != nil {
		return internalError("inject to site", err)
	}
	if len(rows) == 0 {
		return apiErr(http.StatusBadRequest, "No auto-inject secrets in this vault")
	}
	pairs := make([]any, 0, len(rows))
	for _, row := range rows {
		value, err := SecretsCryptoDecryptVault(row.EncryptedValue, st.Config.JWTSecret)
		if err != nil {
			return apiErr(http.StatusInternalServerError, err.Error())
		}
		pairs = append(pairs, map[string]any{"key": row.Key, "value": value})
	}

	if _, err := agent.Put(ctx, "/nginx/env/"+domain, map[string]any{"vars": pairs}); err != nil {
		return agentError("Inject secrets", err)
	}

	ip := clientIP(r)
	details := fmt.Sprintf("%d secrets", len(rows))
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "secrets.inject", new("site"), &domain, &details, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "secrets.inject", &claims.Email, ip, new("site"), &domain, &details, nil, "warning", claims.KeyID)

	ExtensionsFireEvent(st.DB, "secrets.injected", map[string]any{"site_id": siteID, "domain": domain, "count": len(rows)})

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "injected": len(rows), "domain": domain})
	return nil
}

// ── Pull (all secrets as env pairs, for the CLI) ────────────────────────────

// rtSecretsPull — GET /api/secrets/vaults/{vault_id}/pull.
func rtSecretsPull(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	vaultID, err := pathUUID(r, "vault_id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := rtSecretsVerifyVault(ctx, st, vaultID, claims.Sub); err != nil {
		return err
	}
	rows, err := queryAll[rtSecretsSecretRow](ctx, st.DB, "SELECT * FROM secrets WHERE vault_id = $1 ORDER BY key", vaultID)
	if err != nil {
		return internalError("pull", err)
	}
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"key": row.Key, "value": rtSecretsDecryptOr(row.EncryptedValue, st.Config.JWTSecret, ""), "type": row.SecretType,
		})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// ── GAP 17: Vault Export (encrypted backup) ─────────────────────────────────

// rtSecretsExportVault — GET /api/secrets/vaults/{vault_id}/export: values
// stay encrypted (portable to another DockPanel with the same key).
func rtSecretsExportVault(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	vaultID, err := pathUUID(r, "vault_id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := rtSecretsVerifyVault(ctx, st, vaultID, claims.Sub); err != nil {
		return err
	}
	vault, err := queryOne[rtSecretsSecretVault](ctx, st.DB, "SELECT * FROM secret_vaults WHERE id = $1", vaultID)
	if err != nil {
		return internalError("export vault", err)
	}
	rows, err := queryAll[rtSecretsSecretRow](ctx, st.DB, "SELECT * FROM secrets WHERE vault_id = $1 ORDER BY key", vaultID)
	if err != nil {
		return internalError("export vault", err)
	}
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"key": row.Key, "encrypted_value": row.EncryptedValue, "description": row.Description,
			"secret_type": row.SecretType, "auto_inject": row.AutoInject, "version": row.Version,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vault_name": vault.Name, "vault_description": vault.Description,
		"exported_at": time.Now().UTC(), "secret_count": len(out), "secrets": out,
	})
	return nil
}

// rtSecretsImportVault — POST /api/secrets/vaults/{vault_id}/import.
func rtSecretsImportVault(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	vaultID, err := pathUUID(r, "vault_id")
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var data any
	_ = dec.Decode(&data)
	ctx := r.Context()
	if err := rtSecretsVerifyVault(ctx, st, vaultID, claims.Sub); err != nil {
		return err
	}
	arr, ok := jsonArr(jsonGet(data, "secrets"))
	if !ok {
		return apiErr(http.StatusBadRequest, "Missing 'secrets' array")
	}
	imported := 0
	for _, s := range arr {
		key, _ := jsonStr(jsonGet(s, "key"))
		enc, _ := jsonStr(jsonGet(s, "encrypted_value"))
		var desc *string
		if d, ok := jsonStr(jsonGet(s, "description")); ok {
			desc = &d
		}
		secretType, ok := jsonStr(jsonGet(s, "secret_type"))
		if !ok {
			secretType = "env"
		}
		autoInject, _ := jsonBool(jsonGet(s, "auto_inject"))
		if key == "" || enc == "" {
			continue
		}
		if _, err := execSQL(ctx, st.DB,
			"INSERT INTO secrets (vault_id, key, encrypted_value, description, secret_type, auto_inject, updated_by) "+
				"VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (vault_id, key) DO UPDATE SET "+
				"encrypted_value = EXCLUDED.encrypted_value, updated_at = NOW()",
			vaultID, key, enc, desc, secretType, autoInject, claims.Email); err == nil {
			imported++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "imported": imported})
	return nil
}
