package api

// Port of panel/backend/src/services/extensions.rs — signed webhook delivery
// to extensions, plus the bridge to webhook-gateway routes.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ExtensionsWebhookClient is the client every extension-webhook send path
// (EmitEvent, FireEvent's bridge, and rt_extensions' test_webhook) builds
// fresh, PINNED, per delivery around pinnedTransport rather than sharing one
// client whose own resolver would re-resolve the destination a second,
// independent time after the SSRF check already ran.
func ExtensionsWebhookClient(tr *http.Transport) *http.Client {
	return &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
		// Do NOT follow redirects: webhook_url / dest_url are vetted only at
		// write time, so a public URL 3xx-redirecting to an internal address
		// would exfiltrate to / probe it. Parity with notifications +
		// webhook_gateway.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// extensionsActiveDeliveries caps concurrent webhook deliveries across all
// extensions.
var extensionsActiveDeliveries atomic.Int32

const extensionsMaxConcurrentDeliveries = 20

// extensionsJSON is serde_json::to_string: no HTML escaping, no newline.
func extensionsJSON(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// ExtensionsRFC3339 is chrono's to_rfc3339(): "+00:00" rather than "Z", and
// the fraction (if any) in 3/6/9 digits (SecondsFormat::AutoSi).
func ExtensionsRFC3339(t time.Time) string {
	t = t.UTC()
	layout := "2006-01-02T15:04:05"
	switch ns := t.Nanosecond(); {
	case ns == 0:
	case ns%1_000_000 == 0:
		layout += ".000"
	case ns%1_000 == 0:
		layout += ".000000"
	default:
		layout += ".000000000"
	}
	return t.Format(layout) + "+00:00"
}

// extensionsReadBody is resp.text() truncated to 1024 characters.
func extensionsReadBody(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	r := []rune(strings.ToValidUTF8(string(b), "�"))
	if len(r) > 1024 {
		r = r[:1024]
	}
	return string(r)
}

// ExtensionsSign is the hex HMAC-SHA256 of payload under secret. (The Rust
// error arm for an invalid HMAC key is unreachable — HMAC takes any key
// length — and has no Go counterpart.)
func ExtensionsSign(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// ExtensionsEmitEvent emits an event to all enabled extensions
// (fire-and-forget per delivery).
func ExtensionsEmitEvent(ctx context.Context, db *pgxpool.Pool, eventType string, data any) {
	// Rate limit: skip if too many deliveries in flight.
	if active := extensionsActiveDeliveries.Load(); active >= extensionsMaxConcurrentDeliveries {
		slog.Warn(fmt.Sprintf("extension webhook rate limit hit (%d in-flight), skipping %s", active, eventType))
		return
	}

	exts, err := queryAll[Tup3[uuid.UUID, string, string]](ctx, db,
		"SELECT id, webhook_url, webhook_secret FROM extensions WHERE enabled = TRUE")
	if err != nil {
		return
	}

	deliveryID := uuid.NewString()
	payloadStr := extensionsJSON(map[string]any{
		"event":       eventType,
		"timestamp":   ExtensionsRFC3339(time.Now()),
		"delivery_id": deliveryID,
		"data":        data,
	})

	for _, e := range exts {
		extID, webhookURL := e.A, e.B
		// No AppState here (fire-and-forget delivery path), so the JWT secret
		// comes from the environment rather than the config — same shape as
		// notifications' channel lookup / uptime alerts.
		secret := SecretsCryptoDecryptCredentialFromEnv(e.C)

		extensionsActiveDeliveries.Add(1)
		go func() {
			defer extensionsActiveDeliveries.Add(-1)
			ctx := context.Background()
			started := time.Now()
			signature := ExtensionsSign(secret, payloadStr)

			blocked := func(err error) {
				slog.Warn(fmt.Sprintf("Extension %s webhook blocked at send time (SSRF?): %v", extID, err))
				_, _ = execSQL(ctx, db,
					"INSERT INTO extension_events (extension_id, event_type, payload, response_body, duration_ms) "+
						"VALUES ($1, $2, $3, 'Blocked: webhook URL failed SSRF validation', 0)",
					extID, eventType, payloadStr)
			}
			// SSRF re-validation at send time (DNS-rebind defense — parity with
			// webhook_gateway::forward_to_route), pinned to the address it
			// approves rather than validated-then-reconnected.
			host, port, err := urlAuthority(webhookURL)
			if err != nil {
				blocked(err)
				return
			}
			tr, err := pinnedTransport(ctx, host, port)
			if err != nil {
				blocked(err)
				return
			}

			var status *int32
			var body string
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, strings.NewReader(payloadStr))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-DockPanel-Event", eventType)
				req.Header.Set("X-DockPanel-Delivery", deliveryID)
				req.Header.Set("X-DockPanel-Signature", "sha256="+signature)
				var resp *http.Response
				if resp, err = ExtensionsWebhookClient(tr).Do(req); err == nil {
					s := int32(resp.StatusCode)
					status = &s
					body = extensionsReadBody(resp)
					resp.Body.Close()
				}
			}
			if err != nil {
				body = fmt.Sprintf("Delivery failed: %v", err)
			}
			duration := int32(time.Since(started).Milliseconds())

			_, _ = execSQL(ctx, db,
				"INSERT INTO extension_events (extension_id, event_type, payload, response_status, response_body, duration_ms) "+
					"VALUES ($1, $2, $3, $4, $5, $6)",
				extID, eventType, payloadStr, status, body, duration)
			_, _ = execSQL(ctx, db,
				"UPDATE extensions SET last_webhook_at = NOW(), last_webhook_status = $1 WHERE id = $2",
				status, extID)

			if status != nil && *status >= 400 {
				slog.Warn(fmt.Sprintf("Extension webhook failed: ext=%s event=%s status=%d", extID, eventType, *status))
			}
		}()
	}
}

// ExtensionsFireEvent emits an event from route handlers (fire-and-forget).
// GAP 7+21: also forwards the event to webhook-gateway routes with
// filter_path="/event" whose filter_value matches eventType.
func ExtensionsFireEvent(db *pgxpool.Pool, eventType string, data any) {
	go func() {
		ctx := context.Background()
		ExtensionsEmitEvent(ctx, db, eventType, data)

		routes, _ := queryAll[Tup5[uuid.UUID, string, json.RawMessage, int32, int32]](ctx, db,
			"SELECT r.id, r.destination_url, r.extra_headers, r.retry_count, r.retry_delay_secs "+
				"FROM webhook_routes r JOIN webhook_endpoints e ON e.id = r.endpoint_id AND e.enabled = TRUE "+
				"WHERE r.enabled = TRUE AND r.filter_path = '/event' AND r.filter_value = $1",
			eventType)
		if len(routes) == 0 {
			return
		}

		payloadStr := extensionsJSON(map[string]any{
			"event":     eventType,
			"timestamp": ExtensionsRFC3339(time.Now()),
			"data":      data,
		})

		for _, rt := range routes {
			go extensionsForwardRoute(db, rt.A, rt.B, rt.C, rt.D, rt.E, payloadStr)
		}
	}()
}

func extensionsForwardRoute(db *pgxpool.Pool, routeID uuid.UUID, dest string, extraHeaders json.RawMessage, retryCount, retryDelay int32, payload string) {
	ctx := context.Background()
	// SSRF re-validation at send time (parity with webhook_gateway; the client
	// refuses redirects). Skip the whole retry chain if it fails.
	//
	// Pinned ONCE, before the retry loop, and the SAME client reused for every
	// attempt — re-resolving dest's host on each of up to 6 attempts spread
	// over exponential backoff would widen the validate/connect gap to however
	// long the whole chain runs.
	host, port, err := urlAuthority(dest)
	if err != nil {
		slog.Warn(fmt.Sprintf("Extension webhook route dest blocked at send time (SSRF?): %v", err))
		return
	}
	tr, err := pinnedTransport(ctx, host, port)
	if err != nil {
		slog.Warn(fmt.Sprintf("Extension webhook route dest blocked at send time (SSRF?): %v", err))
		return
	}
	client := ExtensionsWebhookClient(tr)

	var headers map[string]any
	_ = json.Unmarshal(extraHeaders, &headers)

	var lastStatus int32
	for attempt := int32(0); attempt <= min(max(retryCount, 0), 5); attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(int64(max(retryDelay, 0))<<min(attempt-1, 4)) * time.Second)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest, strings.NewReader(payload))
		if err != nil {
			lastStatus = 0
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			if s, ok := v.(string); ok {
				req.Header.Add(k, s) // reqwest's .header() appends
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			lastStatus = 0
			continue
		}
		resp.Body.Close()
		lastStatus = int32(resp.StatusCode)
		if lastStatus >= 200 && lastStatus < 300 {
			break
		}
	}

	_, _ = execSQL(ctx, db,
		"UPDATE webhook_routes SET total_forwarded = total_forwarded + 1, "+
			"last_forwarded_at = NOW(), last_status = $2 WHERE id = $1",
		routeID, lastStatus)
}
