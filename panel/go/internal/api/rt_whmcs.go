package api

// Port of panel/backend/src/routes/whmcs.rs — WHMCS billing integration
// (config, the provisioning webhook with its own shared-secret auth, service
// map) and the app-migration-between-servers stub.

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtWhmcsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/whmcs/config", h(rtWhmcsGetConfig))
	r.Handle("PUT /api/whmcs/config", h(rtWhmcsUpdateConfig))
	r.Handle("DELETE /api/whmcs/config", h(rtWhmcsDeleteConfig))
	r.Handle("POST /api/whmcs/webhook", h(rtWhmcsWebhook))
	r.Handle("GET /api/whmcs/services", h(rtWhmcsListServices))
	// App migration between servers
	r.Handle("GET /api/migrations/apps", h(rtWhmcsListMigrations))
	r.Handle("POST /api/migrations/apps", h(rtWhmcsStartMigration))
	r.Handle("GET /api/migrations/apps/{id}", h(rtWhmcsMigrationStatus))
}

func rtWhmcsStr(s string) *string { return &s }

// ─── WHMCS Configuration ───────────────────────────────────────

type rtWhmcsWhmcsConfigRequest struct {
	APIURL        string `json:"api_url"`
	APIIdentifier string `json:"api_identifier"`
	APISecret     string `json:"api_secret"`
	AutoProvision *bool  `json:"auto_provision"`
	AutoSuspend   *bool  `json:"auto_suspend"`
	AutoTerminate *bool  `json:"auto_terminate"`
}

// rtWhmcsMaskIdentifier shows only the first 4 + last 4 chars.
func rtWhmcsMaskIdentifier(ident string) string {
	if len(ident) > 8 {
		return ident[:4] + "..." + ident[len(ident)-4:]
	}
	return strings.Repeat("*", len(ident))
}

// GET /api/whmcs/config — Get WHMCS integration configuration.
func rtWhmcsGetConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}

	cfg, err := queryOpt[Tup6[string, string, bool, bool, bool, *string]](r.Context(), st.DB,
		"SELECT api_url, api_identifier, auto_provision, auto_suspend, auto_terminate, webhook_secret "+
			"FROM whmcs_config LIMIT 1")
	if err != nil {
		return internalError("whmcs config", err)
	}
	if cfg == nil {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false})
		return nil
	}
	// Integrations.tsx builds the webhook URL to paste into WHMCS from this
	// field on every load, so it must decrypt, not stay masked.
	var webhook *string
	if cfg.F != nil {
		s := SecretsCryptoDecryptCredentialOrLegacy(*cfg.F, st.Config.JWTSecret)
		webhook = &s
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured":     true,
		"api_url":        cfg.A,
		"api_identifier": rtWhmcsMaskIdentifier(cfg.B),
		"auto_provision": cfg.C,
		"auto_suspend":   cfg.D,
		"auto_terminate": cfg.E,
		"webhook_secret": webhook,
	})
	return nil
}

// PUT /api/whmcs/config — Configure WHMCS integration.
func rtWhmcsUpdateConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtWhmcsWhmcsConfigRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}

	if body.APIURL == "" || len(body.APIURL) > 512 {
		return apiErr(http.StatusBadRequest, "Invalid API URL")
	}
	if body.APIIdentifier == "" || len(body.APIIdentifier) > 255 {
		return apiErr(http.StatusBadRequest, "Invalid API identifier")
	}
	if body.APISecret == "" || len(body.APISecret) > 1024 {
		return apiErr(http.StatusBadRequest, "Invalid API secret")
	}
	ctx := r.Context()

	// Encrypt the API secret
	encryptedSecret, err := SecretsCryptoEncryptCredential(body.APISecret, st.Config.JWTSecret)
	if err != nil {
		return apiErr(http.StatusInternalServerError, "Encryption failed: "+err.Error())
	}

	// An omitted flag means "leave it as it is", not "true"; and the webhook
	// secret an operator has already wired into WHMCS must survive a save.
	//
	// The panel's own WHMCS form posts only the three API fields, so a save
	// that defaulted the flags would silently re-enable billing-driven
	// suspension for an operator who had turned it off through the API — and
	// make the `auto_suspend` gate on the webhook's suspend/unsuspend arms
	// unreliable in exactly the case it was added for.
	//
	// (Before 20260809120000_whmcs_config_singleton.sql the upsert below could
	// never execute — no arbiter matched its ON CONFLICT target — so no save
	// ever succeeded. This read is what makes the first real save preserve
	// rather than clobber.)
	//
	// The read is REQUIRED to succeed. Falling back to defaults when the
	// database is merely unreachable would reintroduce the clobber it exists to
	// prevent, at the one moment we cannot tell a fresh install from a blip.
	current, err := queryOpt[Tup4[bool, bool, bool, *string]](ctx, st.DB,
		"SELECT auto_provision, auto_suspend, auto_terminate, webhook_secret "+
			"FROM whmcs_config LIMIT 1")
	if err != nil {
		return internalError("read current whmcs config", err)
	}
	curProvision, curSuspend, curTerminate := true, true, false
	var curSecret *string
	if current != nil {
		curProvision, curSuspend, curTerminate, curSecret = current.A, current.B, current.C, current.D
	}

	// The column holds ciphertext; decrypt what "already have one" reads back
	// so the preserve-vs-mint decision compares plaintext, and so an
	// operator's already-configured WHMCS hook keeps matching.
	//
	// Mint a webhook secret only when there is not one already. Regenerating it
	// on every save would silently break the hook the operator had configured
	// in WHMCS.
	var webhookSecret string
	if curSecret != nil {
		webhookSecret = SecretsCryptoDecryptCredentialOrLegacy(*curSecret, st.Config.JWTSecret)
	} else {
		webhookSecret = strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	encryptedWebhookSecret, err := SecretsCryptoEncryptCredential(webhookSecret, st.Config.JWTSecret)
	if err != nil {
		return apiErr(http.StatusInternalServerError, "Encryption failed: "+err.Error())
	}

	pick := func(v *bool, def bool) bool {
		if v != nil {
			return *v
		}
		return def
	}
	if _, err := execSQL(ctx, st.DB,
		"INSERT INTO whmcs_config (id, api_url, api_identifier, api_secret_encrypted, auto_provision, auto_suspend, auto_terminate, webhook_secret) "+
			"VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7) "+
			"ON CONFLICT ((true)) DO UPDATE SET "+
			"api_url = $1, api_identifier = $2, api_secret_encrypted = $3, "+
			"auto_provision = $4, auto_suspend = $5, auto_terminate = $6, "+
			"webhook_secret = $7, updated_at = NOW()",
		body.APIURL, body.APIIdentifier, encryptedSecret,
		pick(body.AutoProvision, curProvision), pick(body.AutoSuspend, curSuspend), pick(body.AutoTerminate, curTerminate),
		encryptedWebhookSecret); err != nil {
		return internalError("save whmcs config", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "whmcs.configured",
		rtWhmcsStr("settings"), nil, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "whmcs.configured", &claims.Email, ip,
		rtWhmcsStr("settings"), nil, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "webhook_secret": webhookSecret})
	return nil
}

// DELETE /api/whmcs/config — Remove WHMCS integration.
func rtWhmcsDeleteConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()

	_, _ = execSQL(ctx, st.DB, "DELETE FROM whmcs_config")

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "whmcs.removed",
		rtWhmcsStr("settings"), nil, nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "whmcs.removed", &claims.Email, ip,
		rtWhmcsStr("settings"), nil, nil, nil, "warning", claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// ─── WHMCS Webhook Receiver ───────────────────────────────────

type rtWhmcsWhmcsWebhookPayload struct {
	Action      string  `json:"action"`
	ServiceID   *int32  `json:"service_id"`
	ClientEmail *string `json:"client_email"`
	Domain      *string `json:"domain"`
	Plan        *string `json:"plan"`
	Secret      *string `json:"secret"`
}

// rtWhmcsWhmcsWebhookQuery: the secret may also arrive in the query string.
//
// The panel has always PRINTED the hook URL with the secret as a query
// parameter (Integrations.tsx), but the handler only ever read it from the
// JSON body — so the address the operator was told to paste into WHMCS
// authenticated nothing and answered 401. Accepting both makes the advertised
// URL work without dropping the body form, which is what a caller that can
// shape its own payload should still prefer.
type rtWhmcsWhmcsWebhookQuery struct {
	Secret *string `json:"secret"`
}

func rtWhmcsOr(p *string, def string) string {
	if p != nil {
		return *p
	}
	return def
}

// POST /api/whmcs/webhook — Receive provisioning hooks from WHMCS.
// Query is extracted before the JSON body, as in Rust.
func rtWhmcsWebhook(st *AppState, w http.ResponseWriter, r *http.Request) error {
	var q rtWhmcsWhmcsWebhookQuery
	if err := decodeQuery(r, &q); err != nil {
		return err
	}
	var body rtWhmcsWhmcsWebhookPayload
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	// Verify webhook secret
	cfg, err := queryOpt[Tup4[*string, bool, bool, bool]](ctx, st.DB,
		"SELECT webhook_secret, auto_provision, auto_suspend, auto_terminate FROM whmcs_config LIMIT 1")
	if err != nil {
		return internalError("whmcs webhook", err)
	}
	if cfg == nil {
		return apiErr(http.StatusNotFound, "WHMCS not configured")
	}
	autoProvision, autoSuspend, autoTerminate := cfg.B, cfg.C, cfg.D

	if cfg.A == nil {
		// Reject webhooks when no secret is configured (prevents open-access window)
		return apiErr(http.StatusUnauthorized, "Webhook secret not configured")
	}
	expected := SecretsCryptoDecryptCredentialOrLegacy(*cfg.A, st.Config.JWTSecret)
	// Body first, query string second — see rtWhmcsWhmcsWebhookQuery.
	provided := ""
	if body.Secret != nil {
		provided = *body.Secret
	} else if q.Secret != nil {
		provided = *q.Secret
	}
	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
		return apiErr(http.StatusUnauthorized, "Invalid webhook secret")
	}

	var serviceID int32
	if body.ServiceID != nil {
		serviceID = *body.ServiceID
	}
	a := body.Action

	mappedUser := func() *uuid.UUID {
		m, err := queryScalarOpt[*uuid.UUID](ctx, st.DB, "SELECT user_id FROM whmcs_service_map WHERE whmcs_service_id = $1", serviceID)
		if err != nil || m == nil {
			return nil
		}
		return *m
	}

	switch {
	case (a == "provision" || a == "CreateAccount") && autoProvision:
		// Create user + site for new WHMCS service
		email := rtWhmcsOr(body.ClientEmail, "user@example.com")
		plan := rtWhmcsOr(body.Plan, "basic")

		// Check if user already exists
		existing, _ := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM users WHERE email = $1", email)

		var userID uuid.UUID
		if existing != nil {
			userID = *existing
		} else {
			// Create user with random password (they'll use password reset)
			hash, err := hashPassword(uuid.NewString())
			if err != nil {
				return internalError("whmcs provision", err)
			}
			userID, err = queryScalar[uuid.UUID](ctx, st.DB,
				"INSERT INTO users (email, password_hash, role, email_verified, approved) "+
					"VALUES ($1, $2, 'user', true, true) RETURNING id", email, hash)
			if err != nil {
				return internalError("whmcs create user", err)
			}
		}

		// Map service. `users.plan` was withdrawn with the Stripe billing
		// routes it existed to serve — the WHMCS plan name lives only here, in
		// `whmcs_service_map.plan`, which is what Integrations.tsx reads.
		_, _ = execSQL(ctx, st.DB,
			"INSERT INTO whmcs_service_map (whmcs_service_id, user_id, plan, status) "+
				"VALUES ($1, $2, $3, 'active') ON CONFLICT (whmcs_service_id) DO UPDATE SET status = 'active'",
			serviceID, userID, plan)

		slog.Info(fmt.Sprintf("WHMCS provisioned service %d for %s", serviceID, email))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": "provisioned", "user_id": userID})
		return nil

	case (a == "suspend" || a == "SuspendAccount") && autoSuspend:
		if userID := mappedUser(); userID != nil {
			// `role` doubles as the status column, so suspending OVERWRITES the
			// only record of what the account was. It now stashes through the
			// same helper the panel uses. The deny-list is KEPT regardless,
			// because it guards a different hazard the stash does not touch: a
			// lapsed invoice must never suspend the operator out of their own
			// panel. Reachable — the provision arm adopts an EXISTING user by
			// email with no role filter, so the operator's own account maps here
			// the moment their address is also a billing contact.
			changed, err := suspendAccount(ctx, st, *userID, " AND role NOT IN ('admin', 'reseller')")
			if err != nil {
				changed = 0
			}

			_, _ = execSQL(ctx, st.DB, "UPDATE whmcs_service_map SET status = 'suspended' WHERE whmcs_service_id = $1", serviceID)

			if changed == 0 {
				slog.Warn(fmt.Sprintf("WHMCS suspend for service %d changed no user row — the mapped "+
					"account is already suspended or holds a privileged role", serviceID))
			} else {
				slog.Info(fmt.Sprintf("WHMCS suspended service %d", serviceID))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": "suspended"})
		return nil

	// Gated on `auto_suspend`, like its twin above. Without the flag test an
	// operator who deliberately turned billing-driven suspension OFF still got
	// billing-driven UN-suspension — and since un-suspending rewrites the role,
	// that was the half that could change a privilege. Suspend and unsuspend
	// are one setting's two directions.
	case (a == "unsuspend" || a == "UnsuspendAccount") && autoSuspend:
		if userID := mappedUser(); userID != nil {
			// Gives back the role recorded when the account was suspended.
			//
			// ⚠ The deny-list is not symmetry for its own sake. The suspend arm
			// refuses to touch a privileged account — but the panel can suspend
			// one, and then this arm would have handed `admin` straight back,
			// turning a webhook secret into a privilege-restoration primitive
			// that leaves no activity-log row. Billing may return an ordinary
			// account to service; it may not re-grant an operator role.
			role, err := unsuspendAccount(ctx, st, *userID, []string{"admin", "reseller"})
			switch {
			case err != nil:
				slog.Warn(fmt.Sprintf("WHMCS unsuspend for service %d failed to read or write the role", serviceID))
			case role != nil:
				_, _ = execSQL(ctx, st.DB, "UPDATE whmcs_service_map SET status = 'active' WHERE whmcs_service_id = $1", serviceID)
				slog.Info(fmt.Sprintf("WHMCS unsuspended service %d as %s", serviceID, *role))
			default:
				// The service map is deliberately NOT marked active here: the
				// account is still suspended, and saying otherwise would leave
				// billing and the panel disagreeing with nothing to reconcile them.
				slog.Warn(fmt.Sprintf("WHMCS unsuspend for service %d left the account suspended — "+
					"either no previous role was recorded, or it is one billing may not restore", serviceID))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": "unsuspended"})
		return nil

	case (a == "terminate" || a == "TerminateAccount") && autoTerminate:
		if mappedUser() != nil {
			// Don't delete user — just mark terminated
			_, _ = execSQL(ctx, st.DB, "UPDATE whmcs_service_map SET status = 'terminated' WHERE whmcs_service_id = $1", serviceID)
			slog.Info(fmt.Sprintf("WHMCS terminated service %d", serviceID))
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": "terminated"})
		return nil
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": "ignored"})
	return nil
}

// GET /api/whmcs/services — List WHMCS service mappings.
func rtWhmcsListServices(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	services, err := queryAll[Tup6[int32, *uuid.UUID, *uuid.UUID, string, string, time.Time]](r.Context(), st.DB,
		"SELECT whmcs_service_id, user_id, site_id, plan, status, created_at "+
			"FROM whmcs_service_map ORDER BY created_at DESC LIMIT 100")
	if err != nil {
		return internalError("list whmcs services", err)
	}
	items := make([]any, 0, len(services))
	for _, s := range services {
		items = append(items, map[string]any{
			"whmcs_service_id": s.A,
			"user_id":          s.B,
			"site_id":          s.C,
			"plan":             s.D,
			"status":           s.E,
			"created_at":       s.F,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": items})
	return nil
}

// ─── App Migration Between Servers ─────────────────────────────

type rtWhmcsMigrateRequest struct {
	ContainerID    string    `json:"container_id"`
	ContainerName  string    `json:"container_name"`
	TargetServerID uuid.UUID `json:"target_server_id"`
}

// POST /api/migrations/apps — Start migrating a container to another server.
func rtWhmcsStartMigration(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtWhmcsMigrateRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}

	if body.ContainerID == "" || len(body.ContainerID) > 64 {
		return apiErr(http.StatusBadRequest, "Invalid container ID")
	}
	ctx := r.Context()

	// Verify target server exists and user owns it
	target, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM servers WHERE id = $1", body.TargetServerID)
	if err != nil {
		return internalError("verify target server", err)
	}
	if target == nil {
		return apiErr(http.StatusNotFound, "Target server not found")
	}

	// Get source server (local)
	sourceID, err := queryScalarOpt[uuid.UUID](ctx, st.DB, "SELECT id FROM servers WHERE is_local = true LIMIT 1")
	if err != nil {
		return internalError("get local server", err)
	}

	// Guarded like `target` above, rather than laundered into a sentinel.
	// `app_migrations.source_server_id` is NOT NULL with a foreign key to
	// `servers(id)`, so a nil-UUID sentinel answered a panel with no local
	// server row with an opaque 500 from a constraint violation instead of
	// saying what was wrong.
	if sourceID == nil {
		return apiErr(http.StatusConflict, "This panel has no local server registered, so there is nothing to migrate from")
	}
	sourceServerID := *sourceID

	if sourceServerID == body.TargetServerID {
		return apiErr(http.StatusBadRequest, "Source and target servers are the same")
	}

	migID, err := queryScalar[uuid.UUID](ctx, st.DB,
		"INSERT INTO app_migrations (container_id, container_name, source_server_id, target_server_id, status, started_at) "+
			"VALUES ($1, $2, $3, $4, 'in_progress', NOW()) RETURNING id",
		body.ContainerID, body.ContainerName, sourceServerID, body.TargetServerID)
	if err != nil {
		return internalError("create migration", err)
	}

	// No background task exists anywhere in the tree to do the actual
	// container export/transfer/import this would need — the row above is
	// written once and never updated again. It is permanently stuck at
	// `status='in_progress'`. See FEATURES.md §Withdrawn Claims ("App Migration").

	details := fmt.Sprintf("to server %s", body.TargetServerID)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "migration.started",
		rtWhmcsStr("container"), &body.ContainerName, &details, nil, claims.KeyID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":           true,
		"migration_id": migID,
		"status":       "in_progress",
	})
	return nil
}

// GET /api/migrations/apps — List all app migrations.
func rtWhmcsListMigrations(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	rows, err := queryAll[struct {
		ID             uuid.UUID  `db:"id"`
		ContainerID    string     `db:"container_id"`
		ContainerName  string     `db:"container_name"`
		SourceServerID uuid.UUID  `db:"source_server_id"`
		TargetServerID uuid.UUID  `db:"target_server_id"`
		Status         string     `db:"status"`
		ProgressPct    int32      `db:"progress_pct"`
		ErrorMessage   *string    `db:"error_message"`
		StartedAt      *time.Time `db:"started_at"`
		CompletedAt    *time.Time `db:"completed_at"`
	}](r.Context(), st.DB,
		"SELECT id, container_id, container_name, source_server_id, target_server_id, "+
			"status, progress_pct, error_message, started_at, completed_at "+
			"FROM app_migrations ORDER BY created_at DESC LIMIT 50")
	if err != nil {
		return internalError("list migrations", err)
	}
	items := make([]any, 0, len(rows))
	for _, m := range rows {
		items = append(items, map[string]any{
			"id":               m.ID,
			"container_id":     m.ContainerID,
			"container_name":   m.ContainerName,
			"source_server_id": m.SourceServerID,
			"target_server_id": m.TargetServerID,
			"status":           m.Status,
			"progress_pct":     m.ProgressPct,
			"error_message":    m.ErrorMessage,
			"started_at":       m.StartedAt,
			"completed_at":     m.CompletedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"migrations": items})
	return nil
}

// GET /api/migrations/apps/{id} — Get migration status.
func rtWhmcsMigrationStatus(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	mig, err := queryOpt[Tup5[string, string, string, int32, *string]](r.Context(), st.DB,
		"SELECT container_name, status, COALESCE(error_message, ''), progress_pct, "+
			"CASE WHEN completed_at IS NOT NULL THEN to_char(completed_at, 'YYYY-MM-DD HH24:MI:SS') END "+
			"FROM app_migrations WHERE id = $1", id)
	if err != nil {
		return internalError("migration status", err)
	}
	if mig == nil {
		return apiErr(http.StatusNotFound, "Migration not found")
	}
	var errMsg *string
	if mig.C != "" {
		errMsg = &mig.C
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"container_name": mig.A,
		"status":         mig.B,
		"error_message":  errMsg,
		"progress_pct":   mig.D,
		"completed_at":   mig.E,
	})
	return nil
}
