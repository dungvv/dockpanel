package api

// Port of panel/backend/src/routes/extensions.rs — admin CRUD for webhook
// extensions, test delivery and secret rotation.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtExtensionsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/extensions", h(rtExtensionsList))
	r.Handle("POST /api/extensions", h(rtExtensionsCreate))
	r.Handle("PUT /api/extensions/{id}", h(rtExtensionsUpdate))
	r.Handle("DELETE /api/extensions/{id}", h(rtExtensionsRemove))
	r.Handle("POST /api/extensions/{id}/test", h(rtExtensionsTestWebhook))
	r.Handle("POST /api/extensions/{id}/rotate-secret", h(rtExtensionsRotateSecret))
	r.Handle("GET /api/extensions/{id}/events", h(rtExtensionsEvents))
}

// rtExtensionsValidateWebhookURL: extension webhook destinations go through
// the ONE shared SSRF guard, same as every other outbound URL. A second,
// hand-rolled copy with a weaker classifier (and the userinfo-spoof bug)
// accepted a spoofed URL at write time and then silently dropped every
// delivery. Delegating keeps the `webhook_url`-worded error.
func rtExtensionsValidateWebhookURL(ctx context.Context, url string) string {
	if err := validateURLNotInternal(ctx, url); err != nil {
		return "webhook_url: " + err.Error()
	}
	return ""
}

// rtExtensionsExtension is the extensions row. webhook_secret and
// api_key_hash are never serialized.
type rtExtensionsExtension struct {
	ID                 uuid.UUID  `db:"id" json:"id"`
	UserID             uuid.UUID  `db:"user_id" json:"user_id"`
	Name               string     `db:"name" json:"name"`
	Description        string     `db:"description" json:"description"`
	Author             string     `db:"author" json:"author"`
	Version            string     `db:"version" json:"version"`
	WebhookURL         string     `db:"webhook_url" json:"webhook_url"`
	WebhookSecret      string     `db:"webhook_secret" json:"-"`
	APIKeyHash         *string    `db:"api_key_hash" json:"-"`
	APIKeyPrefix       *string    `db:"api_key_prefix" json:"api_key_prefix"`
	Enabled            bool       `db:"enabled" json:"enabled"`
	EventSubscriptions string     `db:"event_subscriptions" json:"event_subscriptions"`
	APIScopes          string     `db:"api_scopes" json:"api_scopes"`
	LastWebhookAt      *time.Time `db:"last_webhook_at" json:"last_webhook_at"`
	LastWebhookStatus  *int32     `db:"last_webhook_status" json:"last_webhook_status"`
	CreatedAt          time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt          time.Time  `db:"updated_at" json:"updated_at"`
}

type rtExtensionsExtensionEvent struct {
	ID             uuid.UUID `db:"id" json:"id"`
	ExtensionID    uuid.UUID `db:"extension_id" json:"extension_id"`
	EventType      string    `db:"event_type" json:"event_type"`
	Payload        string    `db:"payload" json:"payload"`
	ResponseStatus *int32    `db:"response_status" json:"response_status"`
	ResponseBody   *string   `db:"response_body" json:"response_body"`
	DurationMs     *int32    `db:"duration_ms" json:"duration_ms"`
	DeliveredAt    time.Time `db:"delivered_at" json:"delivered_at"`
}

type rtExtensionsCreateExtensionRequest struct {
	Name               string `json:"name"`
	Description        string `json:"description" serde:"default"`
	Author             string `json:"author" serde:"default"`
	Version            string `json:"version" serde:"default"` // default "1.0.0", pre-set before decoding
	WebhookURL         string `json:"webhook_url"`
	EventSubscriptions string `json:"event_subscriptions" serde:"default"`
	APIScopes          string `json:"api_scopes" serde:"default"`
}

type rtExtensionsUpdateExtensionRequest struct {
	Name               *string `json:"name"`
	Description        *string `json:"description"`
	WebhookURL         *string `json:"webhook_url"`
	Enabled            *bool   `json:"enabled"`
	EventSubscriptions *string `json:"event_subscriptions"`
	APIScopes          *string `json:"api_scopes"`
}

// rtExtensionsList is GET /api/extensions (admin only).
func rtExtensionsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	rows, err := queryAll[rtExtensionsExtension](r.Context(), st.DB,
		"SELECT id, user_id, name, description, author, version, webhook_url, "+
			"webhook_secret, api_key_hash, api_key_prefix, enabled, event_subscriptions, "+
			"api_scopes, last_webhook_at, last_webhook_status, created_at, updated_at "+
			"FROM extensions ORDER BY created_at DESC")
	if err != nil {
		return internalError("list extensions", err)
	}
	writeJSON(w, http.StatusOK, rows)
	return nil
}

// rtExtensionsCreate is POST /api/extensions (admin only). Returns the API
// key + webhook secret ONCE.
func rtExtensionsCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	body := rtExtensionsCreateExtensionRequest{Version: "1.0.0"}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 100 {
		return apiErr(http.StatusBadRequest, "Name must be 1-100 characters")
	}
	if msg := rtExtensionsValidateWebhookURL(ctx, body.WebhookURL); msg != "" {
		return apiErr(http.StatusBadRequest, msg)
	}

	// Generate dpx_ API key (same pattern as dp_ keys).
	raw := strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	apiKey := "dpx_" + raw
	apiKeyPrefix := apiKey[:12]
	sum := sha256.Sum256([]byte(apiKey))
	apiKeyHash := hex.EncodeToString(sum[:])

	webhookSecret := "whsec_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	// Encrypted at rest: test_webhook and ExtensionsEmitEvent both need the
	// plaintext back to sign outbound HMAC deliveries with it.
	encrypted, err := SecretsCryptoEncryptCredential(webhookSecret, st.Config.JWTSecret)
	if err != nil {
		return apiErr(http.StatusInternalServerError, fmt.Sprintf("Encryption failed: %v", err))
	}

	extID := uuid.New()
	if _, err := execSQL(ctx, st.DB,
		"INSERT INTO extensions "+
			"(id, user_id, name, description, author, version, webhook_url, webhook_secret, "+
			"api_key_hash, api_key_prefix, enabled, event_subscriptions, api_scopes) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, $11, $12)",
		extID, claims.Sub, name, body.Description, body.Author, body.Version,
		strings.TrimSpace(body.WebhookURL), encrypted, apiKeyHash, apiKeyPrefix,
		body.EventSubscriptions, body.APIScopes); err != nil {
		return internalError("create extensions", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "extension.created",
		new("extension"), new(name), nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "extension.created", new(claims.Email), ip,
		new("extension"), new(name), nil, nil, "info", claims.KeyID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             extID,
		"name":           name,
		"api_key":        apiKey,
		"api_key_prefix": apiKeyPrefix,
		"webhook_secret": webhookSecret,
		"message":        "Save these credentials — they won't be shown again.",
	})
	return nil
}

// rtExtensionsUpdate is PUT /api/extensions/{id} (admin only).
func rtExtensionsUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtExtensionsUpdateExtensionRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	existing, err := queryScalarOpt[string](ctx, st.DB, "SELECT name FROM extensions WHERE id = $1", id)
	if err != nil {
		return internalError("update extensions", err)
	}
	if existing == nil {
		return apiErr(http.StatusNotFound, "Extension not found")
	}

	// Build the dynamic UPDATE from the provided fields.
	type set struct {
		col string
		val any
	}
	var sets []set
	if body.Name != nil {
		name := strings.TrimSpace(*body.Name)
		if name == "" || len(name) > 100 {
			return apiErr(http.StatusBadRequest, "Name must be 1-100 characters")
		}
		sets = append(sets, set{"name", name})
	}
	if body.Description != nil {
		sets = append(sets, set{"description", *body.Description})
	}
	if body.WebhookURL != nil {
		if msg := rtExtensionsValidateWebhookURL(ctx, *body.WebhookURL); msg != "" {
			return apiErr(http.StatusBadRequest, msg)
		}
		sets = append(sets, set{"webhook_url", strings.TrimSpace(*body.WebhookURL)})
	}
	if body.Enabled != nil {
		sets = append(sets, set{"enabled", *body.Enabled})
	}
	if body.EventSubscriptions != nil {
		sets = append(sets, set{"event_subscriptions", *body.EventSubscriptions})
	}
	if body.APIScopes != nil {
		sets = append(sets, set{"api_scopes", *body.APIScopes})
	}
	if len(sets) == 0 {
		return apiErr(http.StatusBadRequest, "No fields to update")
	}

	parts := make([]string, 0, len(sets)+1)
	args := []any{id}
	for i, s := range sets {
		parts = append(parts, s.col+" = $"+strconv.Itoa(i+2))
		args = append(args, s.val)
	}
	parts = append(parts, "updated_at = NOW()")
	sql := fmt.Sprintf("UPDATE extensions SET %s WHERE id = $1", strings.Join(parts, ", "))
	if _, err := execSQL(ctx, st.DB, sql, args...); err != nil {
		return internalError("update extensions", err)
	}

	updatedName := *existing
	if body.Name != nil {
		updatedName = *body.Name
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "extension.updated",
		new("extension"), new(updatedName), nil, nil, claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtExtensionsRemove is DELETE /api/extensions/{id} (admin only).
func rtExtensionsRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()

	extName, err := queryScalarOpt[string](ctx, st.DB, "SELECT name FROM extensions WHERE id = $1", id)
	if err != nil {
		return internalError("remove extensions", err)
	}
	if extName == nil {
		return apiErr(http.StatusNotFound, "Extension not found")
	}

	// Delete events first (FK cascade would handle this, but be explicit).
	_, _ = execSQL(ctx, st.DB, "DELETE FROM extension_events WHERE extension_id = $1", id)

	n, err := execSQL(ctx, st.DB, "DELETE FROM extensions WHERE id = $1", id)
	if err != nil {
		return internalError("remove extensions", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Extension not found")
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "extension.deleted",
		new("extension"), extName, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "extension.deleted", new(claims.Email), ip,
		new("extension"), extName, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtExtensionsTestWebhook is POST /api/extensions/{id}/test — send a test
// event to an extension's webhook.
func rtExtensionsTestWebhook(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()

	ext, err := queryOpt[Tup3[string, string, string]](ctx, st.DB,
		"SELECT name, webhook_url, webhook_secret FROM extensions WHERE id = $1", id)
	if err != nil {
		return internalError("test webhook", err)
	}
	if ext == nil {
		return apiErr(http.StatusNotFound, "Extension not found")
	}
	name, webhookURL := ext.A, ext.B
	secret := SecretsCryptoDecryptCredentialOrLegacy(ext.C, st.Config.JWTSecret)

	deliveryID := uuid.NewString()
	payloadStr := extensionsJSON(map[string]any{
		"event":       "test",
		"timestamp":   ExtensionsRFC3339(time.Now()),
		"delivery_id": deliveryID,
		"data": map[string]any{
			"message":      "This is a test event from DockPanel.",
			"extension":    name,
			"triggered_by": claims.Email,
		},
	})
	signature := ExtensionsSign(secret, payloadStr)

	// SSRF re-validation at send time, PINNED to the address it approves —
	// parity with the delivery path in svc_extensions and webhook_gateway.
	//
	// ⚠ This route had neither at first, and it is the worse place to lack
	// them: the response body comes back to the caller below, so a stored
	// webhook_url that 3xx-redirects to an internal address was a read oracle
	// rather than a blind probe. webhook_url is vetted when WRITTEN, which is
	// not the same instant as when it is resolved.
	host, port, err := urlAuthority(webhookURL)
	if err != nil {
		return apiErr(http.StatusBadRequest, "Webhook URL failed validation: "+err.Error())
	}
	tr, err := pinnedTransport(ctx, host, port)
	if err != nil {
		return apiErr(http.StatusBadRequest, "Webhook URL failed validation: "+err.Error())
	}

	started := time.Now()
	var status *int32
	var respBody string
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, strings.NewReader(payloadStr))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DockPanel-Event", "test")
		req.Header.Set("X-DockPanel-Delivery", deliveryID)
		req.Header.Set("X-DockPanel-Signature", "sha256="+signature)
		var resp *http.Response
		if resp, err = ExtensionsWebhookClient(tr).Do(req); err == nil {
			s := int32(resp.StatusCode)
			status = &s
			respBody = extensionsReadBody(resp)
			resp.Body.Close()
		}
	}
	duration := int32(time.Since(started).Milliseconds())
	if err != nil {
		respBody = fmt.Sprintf("Request failed: %v", err)
	}

	_, _ = execSQL(ctx, st.DB,
		"INSERT INTO extension_events (extension_id, event_type, payload, response_status, response_body, duration_ms) "+
			"VALUES ($1, 'test', $2, $3, $4, $5)",
		id, payloadStr, status, respBody, duration)
	_, _ = execSQL(ctx, st.DB,
		"UPDATE extensions SET last_webhook_at = NOW(), last_webhook_status = $1 WHERE id = $2",
		status, id)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            status != nil && *status < 400,
		"status":        status,
		"duration_ms":   duration,
		"response_body": respBody,
	})
	return nil
}

// rtExtensionsRotateSecret is POST /api/extensions/{id}/rotate-secret.
func rtExtensionsRotateSecret(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()

	extName, err := queryScalarOpt[string](ctx, st.DB, "SELECT name FROM extensions WHERE id = $1", id)
	if err != nil {
		return internalError("rotate secret", err)
	}
	if extName == nil {
		return apiErr(http.StatusNotFound, "Extension not found")
	}

	newSecret := "whsec_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	encrypted, err := SecretsCryptoEncryptCredential(newSecret, st.Config.JWTSecret)
	if err != nil {
		return apiErr(http.StatusInternalServerError, fmt.Sprintf("Encryption failed: %v", err))
	}
	if _, err := execSQL(ctx, st.DB,
		"UPDATE extensions SET webhook_secret = $1, updated_at = NOW() WHERE id = $2", encrypted, id); err != nil {
		return internalError("rotate secret", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "extension.rotate_secret",
		new("extension"), extName, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "extension.rotate_secret", new(claims.Email), ip,
		new("extension"), extName, nil, nil, "info", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"webhook_secret": newSecret})
	return nil
}

// rtExtensionsEvents is GET /api/extensions/{id}/events — recent deliveries.
func rtExtensionsEvents(st *AppState, w http.ResponseWriter, r *http.Request) error {
	if _, err := st.adminUser(r); err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()

	exists, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM extensions WHERE id = $1", id)
	if err != nil {
		return internalError("events", err)
	}
	if exists == nil {
		return apiErr(http.StatusNotFound, "Extension not found")
	}
	rows, err := queryAll[rtExtensionsExtensionEvent](ctx, st.DB,
		"SELECT id, extension_id, event_type, payload, response_status, response_body, "+
			"duration_ms, delivered_at "+
			"FROM extension_events WHERE extension_id = $1 "+
			"ORDER BY delivered_at DESC LIMIT 50", id)
	if err != nil {
		return internalError("events", err)
	}
	writeJSON(w, http.StatusOK, rows)
	return nil
}
