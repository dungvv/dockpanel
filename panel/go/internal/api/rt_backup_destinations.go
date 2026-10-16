package api

// Port of panel/backend/src/routes/backup_destinations.rs.

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

func rtBackupDestinationsRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/backup-destinations", h(rtBackupDestinationsList))
	r.Handle("POST /api/backup-destinations", h(rtBackupDestinationsCreate))
	r.Handle("GET /api/backup-destinations/selectable", h(rtBackupDestinationsSelectable))
	r.Handle("PUT /api/backup-destinations/{id}", h(rtBackupDestinationsUpdate))
	r.Handle("DELETE /api/backup-destinations/{id}", h(rtBackupDestinationsRemove))
	r.Handle("POST /api/backup-destinations/{id}/test", h(rtBackupDestinationsTestConnection))
}

// rtBackupDestinationsDestinationCallerPredicate is which destinations a caller
// may send a site's backups to. `$1` is the caller.
//
// The writer decided this first: backup_schedules' set_schedule accepts an
// unscoped destination from any authenticated caller, on the grounds that
// destinations are created and deleted through admin-only routes, so a site
// owner can upload to one but never read it. The only route that could tell a
// caller WHICH destinations those are stayed admin-only, so a non-admin's
// picker was empty. Reader and writer now interpolate this one string, so the
// set a caller may CHOOSE from cannot drift from the set the writer ACCEPTS.
//
// Requires `LEFT JOIN servers s ON bd.server_id = s.id` in scope.
const rtBackupDestinationsDestinationCallerPredicate = "(bd.server_id IS NULL OR s.user_id = $1)"

// rtBackupDestinationsSelectableDestination is the subset a non-admin needs to
// pick one: enough to choose, nothing to steal. `config` holds the bucket
// credentials and is absent BY CONSTRUCTION rather than by a masking pass.
type rtBackupDestinationsSelectableDestination struct {
	ID    uuid.UUID `json:"id" db:"id"`
	Name  string    `json:"name" db:"name"`
	Dtype string    `json:"dtype" db:"dtype"`
}

// rtBackupDestinationsBackupDestination: `encryption_enabled` and
// `encryption_key` are dead schema columns from the original per-destination
// encryption design and are excluded BY CONSTRUCTION. The design that shipped
// encrypts per-POLICY (`backup_policies.encrypt`) with one key derived from
// the JWT secret — never per-destination.
type rtBackupDestinationsBackupDestination struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Dtype     string    `json:"dtype" db:"dtype"`
	Config    any       `json:"config" db:"config"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type rtBackupDestinationsCreateDestinationRequest struct {
	Name   string `json:"name"`
	Dtype  string `json:"dtype"`
	Config any    `json:"config"`
	// Which server this destination belongs to, or nil for one shared by the
	// whole fleet. The column was nullable but nothing ever wrote it, so NULL
	// was the default rather than a declaration. Absent still means shared,
	// but now because the caller said so.
	ServerID *uuid.UUID `json:"server_id" serde:"default"`
}

type rtBackupDestinationsUpdateDestinationRequest struct {
	Name   *string `json:"name"`
	Config *any    `json:"config"`
}

// rtBackupDestinationsList is GET /api/backup-destinations (admin).
func rtBackupDestinationsList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	// Scoped the same way create scopes a destination's server_id (is_local OR
	// user_id = caller) — a bare SELECT * handed every admin the
	// name/type/server of every OTHER admin's destinations.
	dests, err := queryAll[rtBackupDestinationsBackupDestination](r.Context(), st.DB,
		"SELECT bd.* FROM backup_destinations bd LEFT JOIN servers s ON bd.server_id = s.id "+
			"WHERE (bd.server_id IS NULL OR s.is_local OR s.user_id = $1) "+
			"ORDER BY bd.created_at DESC LIMIT 200", claims.Sub)
	if err != nil {
		return internalError("list backup_destinations", err)
	}
	// Mask secret keys in response.
	for i := range dests {
		rtBackupDestinationsMaskConfigSecrets(&dests[i])
	}
	writeJSON(w, http.StatusOK, dests)
	return nil
}

// rtBackupDestinationsSelectable is GET /api/backup-destinations/selectable —
// the destinations this caller may schedule a site backup to, id/name/type.
// AuthUser deliberately: the predicate does the deciding, so there is no role
// branch to keep in step.
func rtBackupDestinationsSelectable(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	dests, err := queryAll[rtBackupDestinationsSelectableDestination](r.Context(), st.DB,
		"SELECT bd.id, bd.name, bd.dtype FROM backup_destinations bd "+
			"LEFT JOIN servers s ON bd.server_id = s.id "+
			"WHERE "+rtBackupDestinationsDestinationCallerPredicate+" "+
			"ORDER BY bd.name ASC LIMIT 200", claims.Sub)
	if err != nil {
		return internalError("list selectable backup_destinations", err)
	}
	writeJSON(w, http.StatusOK, dests)
	return nil
}

// rtBackupDestinationsCreate is POST /api/backup-destinations.
func rtBackupDestinationsCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	var body rtBackupDestinationsCreateDestinationRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if body.Dtype != "s3" && body.Dtype != "sftp" {
		return apiErr(http.StatusBadRequest, "Type must be s3 or sftp")
	}
	if strings.TrimSpace(body.Name) == "" {
		return apiErr(http.StatusBadRequest, "Name is required")
	}
	if err := rtBackupDestinationsRejectEmptySecrets(body.Config); err != nil {
		return err
	}
	// Encrypt sensitive fields in config before storing.
	encrypted, err := rtBackupDestinationsEncryptConfigSecrets(body.Config, st.Config.JWTSecret)
	if err != nil {
		return err
	}

	// Refuse a server the caller does not operate, rather than storing an id
	// that silently widens where this destination's credentials get sent.
	if body.ServerID != nil {
		owned, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB,
			"SELECT id FROM servers WHERE id = $1 AND (is_local OR user_id = $2)", *body.ServerID, claims.Sub)
		if err != nil {
			return internalError("resolve destination server", err)
		}
		if owned == nil {
			return apiErr(http.StatusNotFound, "Server not found or access denied")
		}
	}

	dest, err := queryOne[rtBackupDestinationsBackupDestination](r.Context(), st.DB,
		"INSERT INTO backup_destinations (name, dtype, config, server_id) VALUES ($1, $2, $3, $4) RETURNING *",
		strings.TrimSpace(body.Name), body.Dtype, rtBackupDestinationsJSONArg(encrypted), body.ServerID)
	if err != nil {
		return internalError("create backup_destinations", err)
	}
	slog.Info(fmt.Sprintf("Backup destination created: %s (%s)", dest.Name, dest.Dtype))
	rtBackupDestinationsMaskConfigSecrets(&dest)
	writeJSON(w, http.StatusCreated, dest)
	return nil
}

// rtBackupDestinationsJSONArg binds a serde_json::Value as JSON text: Go nil
// would be SQL NULL, but serde binds Value::Null as the JSON literal null.
func rtBackupDestinationsJSONArg(v any) any {
	b, _ := json.Marshal(v)
	return json.RawMessage(b)
}

// rtBackupDestinationsUpdate is PUT /api/backup-destinations/{id}.
func rtBackupDestinationsUpdate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtBackupDestinationsUpdateDestinationRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}

	// Ownership check — this used to accept a bare `id`, so a second admin
	// could overwrite ANOTHER admin's destination with their own credentials
	// and the next scheduled backup would upload the target's data into the
	// second admin's bucket — an exfiltration primitive.
	owned, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB,
		"SELECT bd.id FROM backup_destinations bd LEFT JOIN servers s ON bd.server_id = s.id "+
			"WHERE bd.id = $1 AND (bd.server_id IS NULL OR s.is_local OR s.user_id = $2)", id, claims.Sub)
	if err != nil {
		return internalError("update backup_destinations", err)
	}
	if owned == nil {
		return apiErr(http.StatusNotFound, "Destination not found")
	}

	// ENCRYPT FIRST, THEN carry the masked values across. Merging first copied
	// the stored, ALREADY-ENCRYPTED secret into the config and encrypted it a
	// SECOND time; one decrypt then yielded ciphertext and the destination
	// authenticated with gibberish.
	var encryptedConfig any
	if body.Config != nil {
		incoming := *body.Config
		// An empty secret is refused rather than stored: it used to overwrite
		// a working credential with nothing.
		if err := rtBackupDestinationsRejectEmptySecrets(incoming); err != nil {
			return err
		}
		// Whatever arrived as plaintext gets encrypted exactly once. Masked
		// fields are left as the sentinel by design.
		cfg, err := rtBackupDestinationsEncryptConfigSecrets(incoming, st.Config.JWTSecret)
		if err != nil {
			return err
		}
		var stillMasked []string
		if o, ok := cfg.(map[string]any); ok {
			for k, v := range o {
				if s, ok := v.(string); ok && s == rtBackupDestinationsMask {
					stillMasked = append(stillMasked, k)
				}
			}
		}

		// This UPDATE REPLACES the whole config column, and the form sends a
		// fixed key set per transport — so a stored key the form does not know
		// (`key_path`) was silently erased by an unrelated edit.
		existing, err := queryOpt[rtBackupDestinationsConfigRow](r.Context(), st.DB, "SELECT config FROM backup_destinations WHERE id = $1", id)
		if err != nil {
			return internalError("update backup_destinations", err)
		}
		if existing != nil {
			if len(stillMasked) > 0 {
				rtBackupDestinationsCarryMaskedSecrets(cfg, existing.A, stillMasked)
			}
			rtBackupDestinationsCarryUnmentionedKeys(cfg, existing.A)
		}
		encryptedConfig = rtBackupDestinationsJSONArg(cfg)
	}

	dest, err := queryOpt[rtBackupDestinationsBackupDestination](r.Context(), st.DB,
		"UPDATE backup_destinations SET "+
			"name = COALESCE($1, name), "+
			"config = COALESCE($2, config), "+
			"updated_at = NOW() "+
			"WHERE id = $3 RETURNING *", body.Name, encryptedConfig, id)
	if err != nil {
		return internalError("update backup_destinations", err)
	}
	if dest == nil {
		return apiErr(http.StatusNotFound, "Destination not found")
	}
	rtBackupDestinationsMaskConfigSecrets(dest)
	writeJSON(w, http.StatusOK, dest)
	return nil
}

type rtBackupDestinationsConfigRow struct {
	A any `db:"config"`
}

// rtBackupDestinationsRemove is DELETE /api/backup-destinations/{id}.
func rtBackupDestinationsRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	// Ownership check — same gap and same fix as update.
	owned, err := queryScalarOpt[uuid.UUID](r.Context(), st.DB,
		"SELECT bd.id FROM backup_destinations bd LEFT JOIN servers s ON bd.server_id = s.id "+
			"WHERE bd.id = $1 AND (bd.server_id IS NULL OR s.is_local OR s.user_id = $2)", id, claims.Sub)
	if err != nil {
		return internalError("remove backup_destinations", err)
	}
	if owned == nil {
		return apiErr(http.StatusNotFound, "Destination not found")
	}

	// Check for dependent backup schedules.
	dependent, err := queryScalar[int64](r.Context(), st.DB,
		"SELECT COUNT(*) FROM backup_schedules WHERE destination_id = $1", id)
	if err != nil {
		return internalError("remove backup_destinations", err)
	}
	n, err := execSQL(r.Context(), st.DB, "DELETE FROM backup_destinations WHERE id = $1", id)
	if err != nil {
		return internalError("remove backup_destinations", err)
	}
	if n == 0 {
		return apiErr(http.StatusNotFound, "Destination not found")
	}

	// Nullify destination_id on dependent schedules (FK is SET NULL).
	resp := map[string]any{"ok": true}
	if dependent > 0 {
		resp["warning"] = fmt.Sprintf("%d backup schedule(s) were using this destination and are now unassigned", dependent)
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// rtBackupDestinationsTestConnection is POST /api/backup-destinations/{id}/test
// — test FROM the host that will actually use this destination.
//
// It used to post through the panel's own local agent unconditionally, so the
// DECRYPTED credential was handed to the PANEL host for a destination a fleet
// member was going to use, and the green "connection OK" was a statement
// about the panel's egress rather than the member's. The scheduled path
// (backup_policy_executor) always resolved agents.ForServer per row and
// refused rather than falling back to local; the button an operator PRESSES
// is the surface that never adopted that rule.
func rtBackupDestinationsTestConnection(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.adminUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	// Ownership-scoped, same predicate create/update/remove use — a bare
	// `WHERE id = $1` handed a caller the DECRYPTED credential of a
	// destination another admin created.
	row, err := queryOpt[Tup4[string, string, any, *uuid.UUID]](r.Context(), st.DB,
		"SELECT bd.name, bd.dtype, bd.config, bd.server_id FROM backup_destinations bd "+
			"LEFT JOIN servers s ON bd.server_id = s.id "+
			"WHERE bd.id = $1 AND (bd.server_id IS NULL OR s.is_local OR s.user_id = $2)", id, claims.Sub)
	if err != nil {
		return internalError("test connection", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Destination not found")
	}
	name, dtype, config, serverID := row.A, row.B, row.C, row.D

	agentBody := map[string]any{"destination": rtBackupDestinationsAgentDestinationPayload(dtype, config)}

	// A NULL server_id means "no host has claimed this destination", NOT "the
	// panel owns it". Reading it as "test from the panel" would re-spell the
	// exact defect this handler fixes, so an unclaimed destination is tested
	// from every online member instead — the panel's own box is in that fleet,
	// so a single-server install gets the identical answer.
	if serverID == nil {
		return rtBackupDestinationsTestFromWholeFleet(st, w, r, name, agentBody)
	}

	// Refuse rather than substitute: answering with a different host's
	// reachability is how a destination gets green-lit for the wrong machine.
	agent, err := st.Agents.ForServer(r.Context(), *serverID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Refusing to test destination %s: its server %s is unreachable (%v) — "+
			"testing from another host would answer a question nobody asked", name, serverID, err))
		return apiErr(http.StatusBadGateway, "The server this destination belongs to is unreachable")
	}

	serverName, _ := queryScalarOpt[string](r.Context(), st.DB, "SELECT name FROM servers WHERE id = $1", *serverID)

	result, err := agent.Post(r.Context(), "/backups/test-destination", agentBody)
	if err != nil {
		return agentError("Backup destination test", err)
	}
	// The agent's own {"success", "message"} is passed through unchanged and
	// the host is added beside it.
	if obj, ok := result.(map[string]any); ok {
		obj["ok"] = true
		obj["server"] = serverName
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

// rtBackupDestinationsTestFromWholeFleet tests an unclaimed destination from
// every online member, reporting per host.
//
// Partial stays partial: one member that cannot reach the bucket is a real
// problem but does not make the destination broken for the hosts that can.
// The request fails only when NOTHING reached it; anything else is a 200
// carrying the names in `warning`.
func rtBackupDestinationsTestFromWholeFleet(st *AppState, w http.ResponseWriter, r *http.Request, destName string, agentBody any) error {
	fleet := st.Agents.OnlineFleet(r.Context())
	if len(fleet) == 0 {
		return apiErr(http.StatusBadGateway, "No server is online to test this destination from")
	}

	reachable := []string{}
	var failed []Tup2[string, string]
	// A refusal every member agrees on keeps its own status; `unanimous`
	// drops the moment one member fails for a reason the operator cannot act
	// on, or for a different one than the rest.
	shared := 0
	unanimous := true
	for _, m := range fleet {
		if _, err := m.Agent.Post(r.Context(), "/backups/test-destination", agentBody); err != nil {
			slog.Warn(fmt.Sprintf("Destination %s: %s could not reach it: %v", destName, m.Name, err))
			if status, msg, ok := agentActionable(err); ok {
				if shared == 0 {
					shared = status
				}
				if shared != status {
					unanimous = false
				}
				failed = append(failed, Tup2[string, string]{m.Name, msg})
			} else {
				unanimous = false
				failed = append(failed, Tup2[string, string]{m.Name, err.Error()})
			}
			continue
		}
		reachable = append(reachable, m.Name)
	}

	if len(reachable) == 0 {
		parts := make([]string, len(failed))
		for i, f := range failed {
			parts[i] = f.A + ": " + f.B
		}
		// Every host refused for the same fixable thing → answer with THAT.
		// A mixed bag, or any genuine agent fault, still reads 502.
		status := http.StatusBadGateway
		if shared != 0 && unanimous {
			status = shared
		}
		return apiErr(status, fmt.Sprintf("No server could reach \"%s\" — %s", destName, strings.Join(parts, "; ")))
	}

	// Counted by difference from the hosts actually asked, so there is no
	// second predicate to drift from OnlineFleet's. A server never asked is
	// not a pass: its answer is still unknown.
	asked := make([]uuid.UUID, len(fleet))
	for i, m := range fleet {
		asked[i] = m.ID
	}
	notAsked, err := queryAll[Tup2[string, string]](r.Context(), st.DB,
		"SELECT name, status FROM servers WHERE NOT (id = ANY($1)) ORDER BY name", asked)
	if err != nil {
		notAsked = nil
	}

	listed := func(v []Tup2[string, string]) string {
		s := make([]string, len(v))
		for i, e := range v {
			s[i] = fmt.Sprintf("%s (%s)", e.A, e.B)
		}
		return strings.Join(s, ", ")
	}
	var parts []string
	if len(failed) > 0 {
		parts = append(parts, "could not reach it: "+listed(failed))
	}
	if len(notAsked) > 0 {
		parts = append(parts, "not tested: "+listed(notAsked))
	}

	failedJSON := make([]any, len(failed))
	for i, f := range failed {
		failedJSON[i] = map[string]any{"server": f.A, "error": f.B}
	}
	notAskedJSON := make([]any, len(notAsked))
	for i, n := range notAsked {
		notAskedJSON[i] = map[string]any{"server": n.A, "status": n.B}
	}
	resp := map[string]any{
		"ok":        len(parts) == 0,
		"shared":    true,
		"reachable": reachable,
		"failed":    failedJSON,
		"not_asked": notAskedJSON,
	}
	if len(parts) > 0 {
		resp["warning"] = fmt.Sprintf("Reached from %d of %d servers — %s.",
			len(reachable), len(reachable)+len(failed)+len(notAsked), strings.Join(parts, "; "))
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// rtBackupDestinationsAgentDestinationPayload is the `destination` object the
// agent's /backups/* handlers expect: the stored config with its secrets
// decrypted and `type` folded in.
//
// Everything that hands a destination to the agent must come through here.
// The per-site scheduler and the policy executor used to post the row's
// config straight out of the database — the CIPHERTEXT as the S3 secret key
// — while Test Connection decrypted, so a destination verified green and then
// every actual upload authenticated with an encrypted blob.
func rtBackupDestinationsAgentDestinationPayload(dtype string, config any) any {
	d := rtBackupDestinationsDecryptConfigSecrets(config)
	if obj, ok := d.(map[string]any); ok {
		obj["type"] = dtype
		return obj
	}
	return map[string]any{"type": dtype}
}

// rtBackupDestinationsCarryMaskedSecrets replaces each still-masked key in cfg
// with the value already stored for it, VERBATIM — the stored value is
// ciphertext, and re-encrypting it is the bug this makes impossible to write.
// A masked key with nothing stored is dropped so the mask never reaches the
// agent as if it were a credential.
func rtBackupDestinationsCarryMaskedSecrets(cfg, existing any, maskedKeys []string) {
	obj, ok1 := cfg.(map[string]any)
	stored, ok2 := existing.(map[string]any)
	if !ok1 || !ok2 {
		return
	}
	for _, k := range maskedKeys {
		if v, ok := stored[k]; ok {
			obj[k] = v
		} else {
			delete(obj, k)
		}
	}
}

// rtBackupDestinationsCarryUnmentionedKeys carries across any stored key the
// incoming config does not mention (`key_path`). Keys the caller DID send win,
// including one sent as JSON null.
func rtBackupDestinationsCarryUnmentionedKeys(cfg, existing any) {
	obj, ok1 := cfg.(map[string]any)
	stored, ok2 := existing.(map[string]any)
	if !ok1 || !ok2 {
		return
	}
	for k, v := range stored {
		if _, ok := obj[k]; !ok {
			obj[k] = v
		}
	}
}

// rtBackupDestinationsConfigSensitiveKeys are the sensitive keys within a
// destination config. Shared with credential_reencrypt so a third secret key
// added here is re-keyed on rotation too.
var rtBackupDestinationsConfigSensitiveKeys = []string{"secret_key", "password"}

// rtBackupDestinationsMask is the sentinel the list endpoint substitutes for a
// stored secret, and the only value that means "keep what is already there".
const rtBackupDestinationsMask = "********"

// rtBackupDestinationsMaskConfigSecrets replaces every stored secret with the
// mask. create/update returned RETURNING * verbatim, so a rename echoed the
// stored credential — the REAL secret on any row predating encryption.
func rtBackupDestinationsMaskConfigSecrets(dest *rtBackupDestinationsBackupDestination) {
	obj, ok := dest.Config.(map[string]any)
	if !ok {
		return
	}
	for _, key := range rtBackupDestinationsConfigSensitiveKeys {
		if s, ok := obj[key].(string); ok && s != "" {
			obj[key] = rtBackupDestinationsMask
		}
	}
}

// rtBackupDestinationsRejectEmptySecrets refuses an empty string for a secret:
// "" is skipped by the encryptor and is not the mask, so it travelled into the
// config column and REPLACED a working credential with nothing.
func rtBackupDestinationsRejectEmptySecrets(config any) error {
	obj, ok := config.(map[string]any)
	if !ok {
		return nil
	}
	for _, key := range rtBackupDestinationsConfigSensitiveKeys {
		if s, ok := obj[key].(string); ok && s == "" {
			return apiErr(http.StatusBadRequest, key+" cannot be empty — leave the field masked to keep the stored value, or type a new one")
		}
	}
	return nil
}

// rtBackupDestinationsCloneJSON deep-copies a decoded JSON object/array.
func rtBackupDestinationsCloneJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = rtBackupDestinationsCloneJSON(e)
		}
		return m
	case []any:
		return slices.Clone(t)
	}
	return v
}

// rtBackupDestinationsEncryptConfigSecrets encrypts the sensitive fields.
func rtBackupDestinationsEncryptConfigSecrets(config any, jwtSecret string) (any, error) {
	cfg := rtBackupDestinationsCloneJSON(config)
	if obj, ok := cfg.(map[string]any); ok {
		for _, key := range rtBackupDestinationsConfigSensitiveKeys {
			if s, ok := obj[key].(string); ok && s != "" && s != "********" {
				enc, err := SecretsCryptoEncryptCredential(s, jwtSecret)
				if err != nil {
					return nil, apiErr(http.StatusInternalServerError, fmt.Sprintf("Encryption failed: %v", err))
				}
				obj[key] = enc
			}
		}
	}
	return cfg, nil
}

// rtBackupDestinationsDecryptConfigSecrets decrypts the sensitive fields,
// falling back to plaintext for legacy unencrypted values.
func rtBackupDestinationsDecryptConfigSecrets(config any) any {
	cfg := rtBackupDestinationsCloneJSON(config)
	if obj, ok := cfg.(map[string]any); ok {
		for _, key := range rtBackupDestinationsConfigSensitiveKeys {
			if s, ok := obj[key].(string); ok && s != "" {
				obj[key] = SecretsCryptoDecryptCredentialFromEnv(s)
			}
		}
	}
	return cfg
}
