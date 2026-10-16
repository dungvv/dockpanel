package api

// Port of panel/backend/src/routes/webhook_gateway.rs — receive, inspect,
// route and forward webhooks. Inbound deliveries are HMAC-verified
// (constant-time) against the endpoint's secret; outbound forwarding is
// SSRF-guarded at creation AND re-pinned at forward time.

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func rtWebhookGatewayRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	// Public endpoint (no auth)
	r.Handle("POST /api/webhooks/gateway/{token}", h(rtWebhookGatewayReceiveWebhook))

	r.Handle("GET /api/webhook-gateway/endpoints", h(rtWebhookGatewayListEndpoints))
	r.Handle("POST /api/webhook-gateway/endpoints", h(rtWebhookGatewayCreateEndpoint))
	r.Handle("PUT /api/webhook-gateway/endpoints/{id}", h(rtWebhookGatewaySetEndpointEnabled))
	r.Handle("DELETE /api/webhook-gateway/endpoints/{id}", h(rtWebhookGatewayDeleteEndpoint))
	r.Handle("GET /api/webhook-gateway/endpoints/{id}/deliveries", h(rtWebhookGatewayListDeliveries))
	r.Handle("GET /api/webhook-gateway/endpoints/{id}/routes", h(rtWebhookGatewayListRoutes))
	r.Handle("POST /api/webhook-gateway/endpoints/{id}/routes", h(rtWebhookGatewayCreateRoute))
	r.Handle("PUT /api/webhook-gateway/routes/{route_id}", h(rtWebhookGatewaySetRouteEnabled))
	r.Handle("DELETE /api/webhook-gateway/routes/{route_id}", h(rtWebhookGatewayDeleteRoute))
	r.Handle("POST /api/webhook-gateway/deliveries/{delivery_id}/replay", h(rtWebhookGatewayReplayDelivery))
}

// ── Types ───────────────────────────────────────────────────────────────────

type rtWebhookGatewayWebhookEndpoint struct {
	ID          uuid.UUID `json:"id" db:"id"`
	UserID      uuid.UUID `json:"user_id" db:"user_id"`
	Name        string    `json:"name" db:"name"`
	Description *string   `json:"description" db:"description"`
	Token       string    `json:"token" db:"token"`
	// The shared secret this endpoint verifies signatures with. It used to
	// ride out to the browser on every list of the Webhook Gateway screen:
	// the struct is returned straight to the client and nothing suppressed the
	// field. The SPA never displayed it, which is why it went unnoticed — it
	// was on the wire, not on the page.
	VerifySecret   *string    `json:"-" db:"verify_secret"`
	VerifyMode     string     `json:"verify_mode" db:"verify_mode"`
	VerifyHeader   *string    `json:"verify_header" db:"verify_header"`
	Enabled        bool       `json:"enabled" db:"enabled"`
	TotalReceived  int32      `json:"total_received" db:"total_received"`
	LastReceivedAt *time.Time `json:"last_received_at" db:"last_received_at"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
	// Not a column. Whether this endpoint holds a secret it could actually
	// verify with, which is what the operator needs to know and what the
	// secret itself must never be used to answer. Endpoints stored before the
	// presence check can hold a verifying mode with no secret, and there is no
	// update route — the only repair is delete and recreate — so the screen
	// has to be able to say so.
	VerifySecretSet bool `json:"verify_secret_set" db:"verify_secret_set,default"`
}

type rtWebhookGatewayWebhookDelivery struct {
	ID                uuid.UUID       `json:"id" db:"id"`
	EndpointID        uuid.UUID       `json:"endpoint_id" db:"endpoint_id"`
	Method            string          `json:"method" db:"method"`
	Headers           json.RawMessage `json:"headers" db:"headers"`
	Body              *string         `json:"body" db:"body"`
	QueryString       *string         `json:"query_string" db:"query_string"`
	SourceIP          *string         `json:"source_ip" db:"source_ip"`
	SignatureValid    *bool           `json:"signature_valid" db:"signature_valid"`
	Forwarded         bool            `json:"forwarded" db:"forwarded"`
	ForwardStatus     *int32          `json:"forward_status" db:"forward_status"`
	ForwardResponse   *string         `json:"forward_response" db:"forward_response"`
	ForwardDurationMs *int32          `json:"forward_duration_ms" db:"forward_duration_ms"`
	ReceivedAt        time.Time       `json:"received_at" db:"received_at"`
}

type rtWebhookGatewayWebhookRoute struct {
	ID              uuid.UUID       `json:"id" db:"id"`
	EndpointID      uuid.UUID       `json:"endpoint_id" db:"endpoint_id"`
	Name            string          `json:"name" db:"name"`
	DestinationURL  string          `json:"destination_url" db:"destination_url"`
	FilterPath      *string         `json:"filter_path" db:"filter_path"`
	FilterValue     *string         `json:"filter_value" db:"filter_value"`
	ExtraHeaders    json.RawMessage `json:"extra_headers" db:"extra_headers"`
	RetryCount      int32           `json:"retry_count" db:"retry_count"`
	RetryDelaySecs  int32           `json:"retry_delay_secs" db:"retry_delay_secs"`
	Enabled         bool            `json:"enabled" db:"enabled"`
	TotalForwarded  int32           `json:"total_forwarded" db:"total_forwarded"`
	LastForwardedAt *time.Time      `json:"last_forwarded_at" db:"last_forwarded_at"`
	LastStatus      *int32          `json:"last_status" db:"last_status"`
	CreatedAt       time.Time       `json:"created_at" db:"created_at"`
}

// deriveVerifySecretSet answers the presence question from the stored
// secret, then lets the secret itself be dropped from the response. Blank
// counts as absent: a blank secret is what the form used to post when the
// operator picked a verification mode and left the field empty, and it
// verifies nothing.
func (e *rtWebhookGatewayWebhookEndpoint) deriveVerifySecretSet() {
	e.VerifySecretSet = e.VerifySecret != nil && strings.TrimSpace(*e.VerifySecret) != ""
}

type rtWebhookGatewayCreateEndpointRequest struct {
	Name         string  `json:"name"`
	Description  *string `json:"description"`
	VerifyMode   *string `json:"verify_mode"`
	VerifySecret *string `json:"verify_secret"`
	VerifyHeader *string `json:"verify_header"`
}

type rtWebhookGatewayCreateRouteRequest struct {
	Name           string  `json:"name"`
	DestinationURL string  `json:"destination_url"`
	FilterPath     *string `json:"filter_path"`
	FilterValue    *string `json:"filter_value"`
	// Option<serde_json::Value>: absent and null both mean None.
	ExtraHeaders   json.RawMessage `json:"extra_headers" serde:"default"`
	RetryCount     *int32          `json:"retry_count"`
	RetryDelaySecs *int32          `json:"retry_delay_secs"`
}

// rtWebhookGatewaySetEnabledRequest is the one field either toggle accepts.
// Deliberately not a partial-update body: an endpoint's verification settings
// are fixed at creation on purpose, and a struct that could carry them would
// make this door look like the place to change them.
type rtWebhookGatewaySetEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

type rtWebhookGatewayPaginationQuery struct {
	Limit  *int64 `json:"limit"`
	Offset *int64 `json:"offset"`
}

func rtWebhookGatewayStr(s string) *string { return &s }

// rtWebhookGatewayBlankIsAbsent trims and treats "" as absent.
func rtWebhookGatewayBlankIsAbsent(s *string) *string {
	if s == nil {
		return nil
	}
	t := strings.TrimSpace(*s)
	if t == "" {
		return nil
	}
	return &t
}

// rtWebhookGatewayOwnedEndpoint is the shared ownership check: 404 "Endpoint not found".
func rtWebhookGatewayOwnedEndpoint(ctx context.Context, st *AppState, id, userID uuid.UUID, ctxName string) error {
	found, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM webhook_endpoints WHERE id = $1 AND user_id = $2", id, userID)
	if err != nil {
		return internalError(ctxName, err)
	}
	if found == nil {
		return apiErr(http.StatusNotFound, "Endpoint not found")
	}
	return nil
}

// ── Endpoint CRUD ───────────────────────────────────────────────────────────

// GET /api/webhook-gateway/endpoints — List endpoints.
func rtWebhookGatewayListEndpoints(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	endpoints, err := queryAll[rtWebhookGatewayWebhookEndpoint](r.Context(), st.DB,
		"SELECT * FROM webhook_endpoints WHERE user_id = $1 ORDER BY created_at DESC LIMIT 500", claims.Sub)
	if err != nil {
		return internalError("list endpoints", err)
	}
	for i := range endpoints {
		endpoints[i].deriveVerifySecretSet()
	}
	writeJSON(w, http.StatusOK, endpoints)
	return nil
}

// POST /api/webhook-gateway/endpoints — Create an endpoint.
func rtWebhookGatewayCreateEndpoint(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var req rtWebhookGatewayCreateEndpointRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.Name == "" || len(req.Name) > 100 {
		return apiErr(http.StatusBadRequest, "Name must be 1-100 characters")
	}

	token := strings.ReplaceAll(uuid.NewString(), "-", "")
	verifyMode := "none"
	if req.VerifyMode != nil {
		verifyMode = *req.VerifyMode
	}
	if !slices.Contains([]string{"none", "hmac_sha256", "hmac_sha1"}, verifyMode) {
		return apiErr(http.StatusBadRequest, "Invalid verify_mode")
	}

	// Blank is absent. The form posts "" for a field the operator left empty,
	// so taking the strings as they arrive is how an endpoint came to be
	// stored asking for HMAC verification it had no secret to perform —
	// displayed as `hmac_sha256`, verifying nothing.
	verifySecret := rtWebhookGatewayBlankIsAbsent(req.VerifySecret)
	verifyHeader := rtWebhookGatewayBlankIsAbsent(req.VerifyHeader)

	// A verification mode is a promise the endpoint cannot keep without both
	// halves, and there is no update route to add the missing half later, so
	// the only moment this can be caught is here.
	if verifyMode != "none" && (verifySecret == nil || verifyHeader == nil) {
		return apiErr(http.StatusBadRequest, "Signature verification needs both a secret and the header carrying the signature")
	}

	// Encrypted at rest: this is the HMAC key the panel re-derives a signature
	// with on every inbound delivery, so it must stay recoverable rather than
	// hashed — same shape as alert_rules/monitors' notification secrets.
	var encryptedVerifySecret *string
	if verifySecret != nil {
		enc, err := SecretsCryptoEncryptCredential(*verifySecret, st.Config.JWTSecret)
		if err != nil {
			return apiErr(http.StatusInternalServerError, "Encryption failed: "+err.Error())
		}
		encryptedVerifySecret = &enc
	}
	ctx := r.Context()

	endpoint, err := queryOne[rtWebhookGatewayWebhookEndpoint](ctx, st.DB,
		"INSERT INTO webhook_endpoints (user_id, name, description, token, verify_mode, verify_secret, verify_header) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
		claims.Sub, req.Name, req.Description, token, verifyMode, encryptedVerifySecret, verifyHeader)
	if err != nil {
		return internalError("create endpoint", err)
	}
	endpoint.deriveVerifySecretSet()

	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "webhook_endpoint.create",
		rtWebhookGatewayStr("webhook"), &req.Name, &token, nil, claims.KeyID)

	writeJSON(w, http.StatusCreated, endpoint)
	return nil
}

// DELETE /api/webhook-gateway/endpoints/{id} — Delete an endpoint.
func rtWebhookGatewayDeleteEndpoint(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	n, err := execSQL(ctx, st.DB, "DELETE FROM webhook_endpoints WHERE id = $1 AND user_id = $2", id, claims.Sub)
	if err != nil {
		return internalError("delete endpoint", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Endpoint not found")
	}

	ip := clientIP(r)
	idStr := id.String()
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "webhook_endpoint.delete",
		rtWebhookGatewayStr("webhook"), &idStr, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "webhook_endpoint.delete", &claims.Email, ip,
		rtWebhookGatewayStr("webhook"), &idStr, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// PUT /api/webhook-gateway/endpoints/{id} — Open or close the public door.
//
// `enabled` is what the inbound receiver reads before it will look at a
// request at all, and until this handler existed nothing could write it.
// Shutting a public door therefore meant deleting the endpoint — which
// cascades away every delivery and every route attached to it. Closing a door
// and discarding its history are different operations.
func rtWebhookGatewaySetEndpointEnabled(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req rtWebhookGatewaySetEnabledRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	n, err := execSQL(ctx, st.DB,
		"UPDATE webhook_endpoints SET enabled = $1, updated_at = NOW() WHERE id = $2 AND user_id = $3",
		req.Enabled, id, claims.Sub)
	if err != nil {
		return internalError("set endpoint enabled", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Endpoint not found")
	}

	action := "webhook_endpoint.disable"
	if req.Enabled {
		action = "webhook_endpoint.enable"
	}
	idStr := id.String()
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, action,
		rtWebhookGatewayStr("webhook"), &idStr, nil, nil, claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": req.Enabled})
	return nil
}

// ── Deliveries (Inspector) ──────────────────────────────────────────────────

// GET /api/webhook-gateway/endpoints/{id}/deliveries — List deliveries.
func rtWebhookGatewayListDeliveries(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var params rtWebhookGatewayPaginationQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	ctx := r.Context()

	// Verify ownership
	if err := rtWebhookGatewayOwnedEndpoint(ctx, st, id, claims.Sub, "list deliveries"); err != nil {
		return err
	}

	limit, offset := paginate(params.Limit, params.Offset)
	deliveries, err := queryAll[rtWebhookGatewayWebhookDelivery](ctx, st.DB,
		"SELECT * FROM webhook_deliveries WHERE endpoint_id = $1 ORDER BY received_at DESC LIMIT $2 OFFSET $3",
		id, limit, offset)
	if err != nil {
		return internalError("list deliveries", err)
	}
	writeJSON(w, http.StatusOK, deliveries)
	return nil
}

// POST /api/webhook-gateway/deliveries/{delivery_id}/replay — Replay a delivery to its matching routes.
func rtWebhookGatewayReplayDelivery(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	deliveryID, err := pathUUID(r, "delivery_id")
	if err != nil {
		return err
	}
	ctx := r.Context()

	delivery, err := queryOpt[rtWebhookGatewayWebhookDelivery](ctx, st.DB,
		"SELECT d.* FROM webhook_deliveries d "+
			"JOIN webhook_endpoints e ON e.id = d.endpoint_id AND e.user_id = $1 "+
			"WHERE d.id = $2", claims.Sub, deliveryID)
	if err != nil {
		return internalError("replay delivery", err)
	}
	if delivery == nil {
		return apiErr(http.StatusNotFound, "Delivery not found")
	}

	routes, err := queryAll[rtWebhookGatewayWebhookRoute](ctx, st.DB,
		"SELECT * FROM webhook_routes WHERE endpoint_id = $1 AND enabled = TRUE", delivery.EndpointID)
	if err != nil {
		return internalError("replay delivery", err)
	}

	body := ""
	if delivery.Body != nil {
		body = *delivery.Body
	}
	forwarded := 0

	// A replay is the same delivery arriving a second time, so it obeys the
	// same routing decision. This loop used to hand the body to every enabled
	// route whatever its filter said, while the inbound path skipped the ones
	// that did not match — so replaying sent the payload to destinations the
	// operator had deliberately excluded, each with that route's stored
	// headers attached and its retry budget behind it.
	bg := context.WithoutCancel(ctx)
	for _, route := range routes {
		if !rtWebhookGatewayRouteAdmits(&route, body) {
			continue
		}
		forwarded++
		go rtWebhookGatewayForwardToRoute(bg, st.DB, route, body, deliveryID)
	}

	// Replaying re-sends an externally-supplied body to third parties under
	// the panel's own credentials. It was the one forwarding action in this
	// module that left no trace at all.
	idStr := deliveryID.String()
	details := fmt.Sprintf("%d route(s)", forwarded)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "webhook_delivery.replay",
		rtWebhookGatewayStr("webhook"), &idStr, &details, nil, claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "replayed_to": forwarded})
	return nil
}

// ── Routes CRUD ─────────────────────────────────────────────────────────────

// GET /api/webhook-gateway/endpoints/{id}/routes — List routes.
func rtWebhookGatewayListRoutes(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := rtWebhookGatewayOwnedEndpoint(ctx, st, id, claims.Sub, "list routes"); err != nil {
		return err
	}
	routes, err := queryAll[rtWebhookGatewayWebhookRoute](ctx, st.DB,
		"SELECT * FROM webhook_routes WHERE endpoint_id = $1 ORDER BY created_at ASC", id)
	if err != nil {
		return internalError("list routes", err)
	}
	writeJSON(w, http.StatusOK, routes)
	return nil
}

// POST /api/webhook-gateway/endpoints/{id}/routes — Create a route.
func rtWebhookGatewayCreateRoute(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req rtWebhookGatewayCreateRouteRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if err := rtWebhookGatewayOwnedEndpoint(ctx, st, id, claims.Sub, "create route"); err != nil {
		return err
	}

	if req.DestinationURL == "" {
		return apiErr(http.StatusBadRequest, "destination_url required")
	}

	// SSRF protection: block internal destination URLs
	if err := validateURLNotInternal(ctx, req.DestinationURL); err != nil {
		return apiErr(http.StatusBadRequest, "Invalid destination URL: "+err.Error())
	}

	extraHeaders := json.RawMessage(`{}`)
	if len(req.ExtraHeaders) > 0 && string(req.ExtraHeaders) != "null" {
		extraHeaders = req.ExtraHeaders
	}
	retryCount := int32(3)
	if req.RetryCount != nil {
		retryCount = *req.RetryCount
	}
	retryDelay := int32(5)
	if req.RetryDelaySecs != nil {
		retryDelay = *req.RetryDelaySecs
	}

	route, err := queryOne[rtWebhookGatewayWebhookRoute](ctx, st.DB,
		"INSERT INTO webhook_routes (endpoint_id, name, destination_url, filter_path, filter_value, extra_headers, retry_count, retry_delay_secs) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
		id, req.Name, req.DestinationURL, req.FilterPath, req.FilterValue, extraHeaders,
		max(min(retryCount, 10), 0), max(min(retryDelay, 300), 1))
	if err != nil {
		return internalError("create route", err)
	}
	writeJSON(w, http.StatusCreated, route)
	return nil
}

// DELETE /api/webhook-gateway/routes/{route_id} — Delete a route.
func rtWebhookGatewayDeleteRoute(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	routeID, err := pathUUID(r, "route_id")
	if err != nil {
		return err
	}
	n, err := execSQL(r.Context(), st.DB,
		"DELETE FROM webhook_routes r USING webhook_endpoints e "+
			"WHERE r.id = $1 AND r.endpoint_id = e.id AND e.user_id = $2", routeID, claims.Sub)
	if err != nil {
		return internalError("delete route", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Route not found")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// PUT /api/webhook-gateway/routes/{route_id} — Stop or resume forwarding.
//
// The outbound half of the same severance. A route is an arbitrary external
// destination with the operator's own headers attached and a retry budget,
// and stopping data leaving the box for a third party used to mean deleting
// the route and its counters with it. Ownership is enforced through the
// parent endpoint, the same shape delete_route uses.
func rtWebhookGatewaySetRouteEnabled(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	routeID, err := pathUUID(r, "route_id")
	if err != nil {
		return err
	}
	var req rtWebhookGatewaySetEnabledRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	n, err := execSQL(ctx, st.DB,
		"UPDATE webhook_routes r SET enabled = $1 FROM webhook_endpoints e "+
			"WHERE r.id = $2 AND r.endpoint_id = e.id AND e.user_id = $3",
		req.Enabled, routeID, claims.Sub)
	if err != nil {
		return internalError("set route enabled", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Route not found")
	}

	action := "webhook_route.disable"
	if req.Enabled {
		action = "webhook_route.enable"
	}
	idStr := routeID.String()
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, action,
		rtWebhookGatewayStr("webhook"), &idStr, nil, nil, claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": req.Enabled})
	return nil
}

// ── Public Inbound Webhook Receiver ─────────────────────────────────────────

// rtWebhookGatewayHeaderStr is http::HeaderValue::to_str: only visible ASCII
// and tab are a string; anything else is skipped like Rust skipped it.
func rtWebhookGatewayHeaderStr(v string) (string, bool) {
	for i := 0; i < len(v); i++ {
		if c := v[i]; c != '\t' && (c < 32 || c == 127 || c >= 128) {
			return "", false
		}
	}
	return v, true
}

// rtWebhookGatewayHeadersJSON collects request headers like the Rust
// HeaderMap loop: lower-case names, later values of a repeated header
// overwrite earlier ones, `host` included (Go moves it out of r.Header).
func rtWebhookGatewayHeadersJSON(r *http.Request) map[string]any {
	out := map[string]any{}
	if r.Host != "" {
		if v, ok := rtWebhookGatewayHeaderStr(r.Host); ok {
			out["host"] = v
		}
	}
	for name, values := range r.Header {
		for _, value := range values {
			if v, ok := rtWebhookGatewayHeaderStr(value); ok {
				out[strings.ToLower(name)] = v
			}
		}
	}
	return out
}

// rtWebhookGatewayLossyUTF8 is String::from_utf8_lossy.
func rtWebhookGatewayLossyUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			sb.WriteRune(utf8.RuneError)
		} else {
			sb.Write(b[:size])
		}
		b = b[size:]
	}
	return sb.String()
}

// POST /api/webhooks/gateway/{token} — Receive an inbound webhook (public, no auth).
func rtWebhookGatewayReceiveWebhook(st *AppState, w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	// Bytes extractor: axum's default 2 MB body limit.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(body) > maxJSONBody {
		return rejection(http.StatusRequestEntityTooLarge, "Failed to buffer the request body: length limit exceeded")
	}
	ctx := r.Context()

	// Find endpoint by token
	endpoint, err := queryOpt[rtWebhookGatewayWebhookEndpoint](ctx, st.DB,
		"SELECT * FROM webhook_endpoints WHERE token = $1 AND enabled = TRUE", token)
	if err != nil {
		return internalError("receive webhook", err)
	}
	if endpoint == nil {
		return apiErr(http.StatusNotFound, "Invalid webhook endpoint")
	}

	bodyStr := rtWebhookGatewayLossyUTF8(body)

	// Extract source IP
	var sourceIP *string
	if v := r.Header.Values("X-Forwarded-For"); len(v) > 0 {
		if s, ok := rtWebhookGatewayHeaderStr(v[0]); ok {
			sourceIP = &s
		}
	} else if v := r.Header.Values("X-Real-Ip"); len(v) > 0 {
		if s, ok := rtWebhookGatewayHeaderStr(v[0]); ok {
			sourceIP = &s
		}
	}

	// Collect headers as JSON
	headersJSON := rtWebhookGatewayHeadersJSON(r)

	var decryptedVerifySecret *string
	if endpoint.VerifySecret != nil {
		s := SecretsCryptoDecryptCredentialOrLegacy(*endpoint.VerifySecret, st.Config.JWTSecret)
		decryptedVerifySecret = &s
	}
	verdict := rtWebhookGatewayClassifySignature(endpoint.VerifyMode, decryptedVerifySecret, endpoint.VerifyHeader, headersJSON, body)

	// Record the delivery BEFORE deciding whether to accept it. The rejection
	// used to return above the INSERT, so `signature_valid = FALSE` had no
	// writer at all and the guide's promise that "failed verifications are
	// logged" was false. A rejected delivery is the one an operator most needs
	// to see — it is the only evidence that something is signing badly, or not
	// signing at all.
	//
	// The trade-off is stated rather than hidden: a caller who knows the
	// endpoint token can now cause a row to be written without knowing the
	// secret. That was already true for an endpoint verifying nothing, the
	// rows carry the same retention sweep as any other delivery, and nothing
	// is forwarded.
	deliveryID, err := queryScalar[uuid.UUID](ctx, st.DB,
		"INSERT INTO webhook_deliveries (endpoint_id, method, headers, body, source_ip, signature_valid) "+
			"VALUES ($1, 'POST', $2, $3, $4, $5) RETURNING id",
		endpoint.ID, headersJSON, bodyStr, sourceIP, verdict.recorded())
	if err != nil {
		return internalError("receive webhook", err)
	}

	// Counts every delivery this endpoint recorded, so the "Received" column
	// and the delivery list below it answer for the same population.
	_, _ = execSQL(ctx, st.DB,
		"UPDATE webhook_endpoints SET total_received = total_received + 1, last_received_at = NOW() WHERE id = $1",
		endpoint.ID)

	// Reject anything the endpoint asked to verify and could not vouch for —
	// including a delivery it had no secret to check, which used to pass.
	if reason, rejected := verdict.rejection(); rejected {
		return apiErr(http.StatusUnauthorized, reason)
	}

	// Forward to all enabled routes (async, fire-and-forget)
	routes, err := queryAll[rtWebhookGatewayWebhookRoute](ctx, st.DB,
		"SELECT * FROM webhook_routes WHERE endpoint_id = $1 AND enabled = TRUE", endpoint.ID)
	if err != nil {
		routes = nil
	}

	// Counted as the loop spawns, not as the query returns: a route the filter
	// excludes is not a route this delivery was sent to.
	forwarded := 0
	bg := context.WithoutCancel(ctx)
	for _, route := range routes {
		if !rtWebhookGatewayRouteAdmits(&route, bodyStr) {
			continue
		}
		forwarded++
		go rtWebhookGatewayForwardToRoute(bg, st.DB, route, bodyStr, deliveryID)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"delivery_id":  deliveryID,
		"forwarded_to": forwarded,
	})
	return nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// rtWebhookGatewaySignatureVerdict is what an endpoint's configuration says
// one delivery's signature is worth.
//
// The distinction that matters is between *not asked to verify* and *asked to
// verify and unable to*. Collapsing those two into one "none" is what let an
// endpoint advertise `hmac_sha256` on the list while passing every unsigned
// request straight through to its forwarding routes.
type rtWebhookGatewaySignatureVerdict int

const (
	// The endpoint asks for no verification. There is nothing to attest, and
	// the delivery records no attestation.
	rtWebhookGatewayVerdictNotConfigured rtWebhookGatewaySignatureVerdict = iota
	// Verification ran and the request satisfied it.
	rtWebhookGatewayVerdictValid
	// Verification ran and the request did not satisfy it.
	rtWebhookGatewayVerdictInvalid
	// The endpoint asks for verification it cannot perform — no secret, no
	// header, or a mode this build does not implement. Never a pass: a
	// promise that cannot be kept is not the same as no promise.
	rtWebhookGatewayVerdictUnverifiable
)

// recorded is the value written to webhook_deliveries.signature_valid. NULL
// only where the endpoint never claimed to verify anything, so a NULL in that
// column means "not checked" and can no longer mean "could not check".
func (v rtWebhookGatewaySignatureVerdict) recorded() *bool {
	t, f := true, false
	switch v {
	case rtWebhookGatewayVerdictNotConfigured:
		return nil
	case rtWebhookGatewayVerdictValid:
		return &t
	default:
		return &f
	}
}

// rejection is the sentence sent back to the caller, or ok=false to accept
// the delivery. It travels as a 401 so it reaches the sender intact — error
// sentences pass through only on a 4xx.
func (v rtWebhookGatewaySignatureVerdict) rejection() (string, bool) {
	switch v {
	case rtWebhookGatewayVerdictInvalid:
		return "Invalid webhook signature", true
	case rtWebhookGatewayVerdictUnverifiable:
		return "This endpoint requires signature verification but has no usable secret. " +
			"Delete it and create it again with a secret and a signature header.", true
	default:
		return "", false
	}
}

// rtWebhookGatewayClassifySignature grades one delivery against the
// endpoint's verification settings.
//
// Split out from the handler so the decision can be tested without a
// database or a socket — every way this can be wrong is a way an unsigned
// request gets treated as a signed one. headers holds lower-case names.
func rtWebhookGatewayClassifySignature(verifyMode string, verifySecret, verifyHeader *string, headers map[string]any, body []byte) rtWebhookGatewaySignatureVerdict {
	if verifyMode == "none" {
		return rtWebhookGatewayVerdictNotConfigured
	}

	// Blank is absent, exactly as at creation. A blank secret is not a weak
	// secret: HMAC accepts a zero-length key, so an endpoint stored with
	// `verify_secret = ""` used to verify signatures against the empty key —
	// and anyone who guessed that could compute one, be recorded
	// `signature_valid = true`, and be relayed onward as authentic.
	secret := rtWebhookGatewayBlankIsAbsent(verifySecret)
	headerName := rtWebhookGatewayBlankIsAbsent(verifyHeader)
	if secret == nil || headerName == nil {
		return rtWebhookGatewayVerdictUnverifiable
	}

	presented, _ := headers[strings.ToLower(*headerName)].(string)

	var ok bool
	switch verifyMode {
	case "hmac_sha256":
		ok = rtWebhookGatewayVerifyHMAC(sha256.New, "sha256=", *secret, body, presented)
	case "hmac_sha1":
		ok = rtWebhookGatewayVerifyHMAC(sha1.New, "sha1=", *secret, body, presented)
	default:
		// A mode this build cannot compute is a promise it cannot keep.
		return rtWebhookGatewayVerdictUnverifiable
	}
	if ok {
		return rtWebhookGatewayVerdictValid
	}
	return rtWebhookGatewayVerdictInvalid
}

// rtWebhookGatewayVerifyHMAC: the algorithm prefix is optional; a non-hex
// signature is invalid; the compare is constant-time (hmac.Equal).
func rtWebhookGatewayVerifyHMAC(h func() hash.Hash, prefix, secret string, body []byte, signatureHeader string) bool {
	sig := strings.TrimPrefix(signatureHeader, prefix)
	expected, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(h, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), expected)
}

// rtWebhookGatewayJSONPointer is serde_json's Value::pointer (RFC 6901).
func rtWebhookGatewayJSONPointer(v any, pointer string) (any, bool) {
	if pointer == "" {
		return v, true
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}
	for _, tok := range strings.Split(pointer[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch t := v.(type) {
		case map[string]any:
			next, ok := t[tok]
			if !ok {
				return nil, false
			}
			v = next
		case []any:
			if strings.HasPrefix(tok, "+") || (strings.HasPrefix(tok, "0") && len(tok) != 1) {
				return nil, false
			}
			i, err := strconv.ParseUint(tok, 10, 64)
			if err != nil || i >= uint64(len(t)) {
				return nil, false
			}
			v = t[i]
		default:
			return nil, false
		}
	}
	return v, true
}

// rtWebhookGatewayRouteAdmits: whether a route's filter admits this body.
//
// One definition, called from both the inbound path and the replay path —
// the inline copy in the inbound loop had no counterpart in replay, which is
// how the two came to disagree about where a delivery goes.
//
// A route with no filter takes everything, and a body that will not parse as
// JSON is admitted rather than dropped. The filter selects destinations; it
// is not a security control, and nothing here should be read as one.
func rtWebhookGatewayRouteAdmits(route *rtWebhookGatewayWebhookRoute, body string) bool {
	if route.FilterPath == nil || route.FilterValue == nil {
		return true
	}
	var parsed any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return true
	}
	got := ""
	if v, ok := rtWebhookGatewayJSONPointer(parsed, *route.FilterPath); ok {
		got, _ = v.(string)
	}
	return got == *route.FilterValue
}

// rtWebhookGatewayClient builds the forwarding client around a PINNED
// transport: 30s timeout, and do NOT follow redirects — the SSRF check only
// vets the original destination_url, so a public destination returning a 3xx
// to http://127.0.0.1 / 169.254.169.254 would otherwise bypass it and
// exfiltrate the internal response.
func rtWebhookGatewayClient(tr *http.Transport) *http.Client {
	return &http.Client{
		Transport:     tr,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// rtWebhookGatewayTruncate is String::truncate(2000), backed off to a rune
// boundary (Rust would panic mid-character; the column must stay valid UTF-8).
func rtWebhookGatewayTruncate(s string) string {
	const limit = 2000
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func rtWebhookGatewayForwardToRoute(ctx context.Context, db *pgxpool.Pool, route rtWebhookGatewayWebhookRoute, body string, deliveryID uuid.UUID) {
	// Re-validate destination URL at forward time to prevent DNS rebinding
	// SSRF: an attacker could register a route pointing to a public IP, then
	// change DNS to resolve to an internal IP before the webhook fires.
	//
	// Pinned ONCE here and the resulting client reused for every retry below —
	// this loop runs up to 11 attempts spread over exponential backoff that can
	// span minutes, and a client that looked the host up again on each attempt
	// would widen the validate/connect race to that whole window.
	blocked := func(e error) {
		slog.Warn(fmt.Sprintf("Webhook route %s destination blocked at forward time (DNS rebinding?): %v", route.ID, e))
		_, _ = execSQL(ctx, db,
			"UPDATE webhook_deliveries SET forwarded = TRUE, forward_status = 0, "+
				"forward_response = $2 WHERE id = $1",
			deliveryID, fmt.Sprintf("Blocked: destination URL failed validation: %v", e))
	}
	host, port, err := urlAuthority(route.DestinationURL)
	if err != nil {
		blocked(err)
		return
	}
	tr, err := pinnedTransport(ctx, host, port)
	if err != nil {
		blocked(err)
		return
	}
	client := rtWebhookGatewayClient(tr)
	defer client.CloseIdleConnections()

	var lastStatus, lastDuration int32
	lastResponse := ""
	retries := max(min(route.RetryCount, 10), 0)

	var extra map[string]any
	_ = json.Unmarshal(route.ExtraHeaders, &extra)

	for attempt := int32(0); attempt <= retries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(uint64(route.RetryDelaySecs)*(uint64(1)<<min(attempt-1, 5))) * time.Second
			time.Sleep(delay)
		}

		start := time.Now()
		resp, err := func() (*http.Response, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, route.DestinationURL, strings.NewReader(body))
			if err != nil {
				return nil, err
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("X-Webhook-Delivery", deliveryID.String())
			req.Header.Add("X-Webhook-Attempt", strconv.Itoa(int(attempt)+1))
			// Apply extra headers
			for k, v := range extra {
				if val, ok := v.(string); ok {
					req.Header.Add(k, val)
				}
			}
			return client.Do(req)
		}()
		if err == nil {
			lastStatus = int32(resp.StatusCode)
			lastDuration = int32(time.Since(start).Milliseconds())
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			lastResponse = rtWebhookGatewayTruncate(rtWebhookGatewayLossyUTF8(raw))
			if lastStatus >= 200 && lastStatus < 300 {
				break // Success
			}
		} else {
			lastStatus = 0
			lastDuration = int32(time.Since(start).Milliseconds())
			lastResponse = rtWebhookGatewayTruncate(err.Error())
		}
	}

	// Update delivery record
	_, _ = execSQL(ctx, db,
		"UPDATE webhook_deliveries SET forwarded = TRUE, forward_status = $2, "+
			"forward_response = $3, forward_duration_ms = $4 WHERE id = $1",
		deliveryID, lastStatus, lastResponse, lastDuration)

	// Update route stats
	_, _ = execSQL(ctx, db,
		"UPDATE webhook_routes SET total_forwarded = total_forwarded + 1, "+
			"last_forwarded_at = NOW(), last_status = $2 WHERE id = $1",
		route.ID, lastStatus)
}
