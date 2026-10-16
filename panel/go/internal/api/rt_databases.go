package api

// Port of panel/backend/src/routes/databases.rs.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

func rtDatabasesRegister(r *Router) {
	h := func(f func(*AppState, http.ResponseWriter, *http.Request) error) Handler {
		return func(w http.ResponseWriter, req *http.Request) error { return f(r.St, w, req) }
	}
	r.Handle("GET /api/databases", h(rtDatabasesList))
	r.Handle("POST /api/databases", h(rtDatabasesCreate))
	r.Handle("DELETE /api/databases/{id}", h(rtDatabasesRemove))
	r.Handle("GET /api/databases/{id}/credentials", h(rtDatabasesCredentials))
	r.Handle("GET /api/databases/{id}/tables", h(rtDatabasesTables))
	r.Handle("GET /api/databases/{id}/tables/{table}", h(rtDatabasesTableSchema))
	r.Handle("GET /api/databases/{id}/indexes/{table}", h(rtDatabasesTableIndexes))
	r.Handle("GET /api/databases/{id}/foreign-keys", h(rtDatabasesForeignKeys))
	r.Handle("GET /api/databases/{id}/schema-overview", h(rtDatabasesSchemaOverview))
	r.Handle("POST /api/databases/{id}/query", h(rtDatabasesQuery))
	r.Handle("GET /api/databases/{id}/pitr", h(rtDatabasesPitrConfig))
	r.Handle("PUT /api/databases/{id}/pitr", h(rtDatabasesUpdatePitrConfig))
	r.Handle("POST /api/databases/{id}/pitr/restore", h(rtDatabasesPitrRestore))
	r.Handle("POST /api/databases/{id}/reset-password", h(rtDatabasesResetPassword))
	r.Handle("GET /api/databases/{id}/dumps", h(rtDatabasesDumps))
	r.Handle("POST /api/databases/{id}/import", h(rtDatabasesImport))
	r.Handle("POST /api/databases/{id}/remote-access", h(rtDatabasesRemoteAccessEnable))
	r.Handle("DELETE /api/databases/{id}/remote-access", h(rtDatabasesRemoteAccessDisable))
}

// rtDatabasesMaxDatabasesPerUser is a hard per-account cap on total databases,
// independent of any reseller quota. Bounds how much of the shared host-wide
// DB port pool + host RAM a single tenant can consume.
const rtDatabasesMaxDatabasesPerUser int64 = 25

// rtDatabasesIsReservedDbName: since v2.20.0 the tenant `{name}` becomes a
// real postgres role that OWNS database `{name}`, so a name matching the
// cluster's own superuser / template DBs or system schemas must be rejected.
// Case-insensitive.
func rtDatabasesIsReservedDbName(name string) bool {
	switch strings.ToLower(name) {
	case "postgres", "template0", "template1", "mysql", "sys", "information_schema", "performance_schema":
		return true
	}
	return false
}

// rtDatabasesSQLError converts an agent error to a user-facing error for SQL
// operations. Unlike agentError, this passes through the actual SQL message.
func rtDatabasesSQLError(e error) error {
	var ae *AgentError
	if errors.As(e, &ae) && ae.Kind == AgentErrStatus {
		// Try to extract the "error" field from the agent JSON response.
		msg := ae.Msg
		var v map[string]any
		if json.Unmarshal([]byte(ae.Msg), &v) == nil {
			if s, ok := v["error"].(string); ok {
				msg = s
			}
		}
		// Strip the Docker-daemon infra prefix so only the DB engine's SQL
		// diagnostic is surfaced (don't leak container/daemon internals).
		msg = strings.TrimPrefix(msg, "Error response from daemon: ")
		return apiErr(http.StatusBadRequest, msg)
	}
	return agentError("SQL query", e)
}

type rtDatabasesListQuery struct {
	Limit  *int64 `json:"limit"`
	Offset *int64 `json:"offset"`
}

type rtDatabasesCreateDbRequest struct {
	// Exactly one of site_id / stack_id must be set — see rtDatabasesResolveOwner.
	SiteID  *uuid.UUID `json:"site_id"`
	StackID *uuid.UUID `json:"stack_id"`
	Name    string     `json:"name"`
	Engine  *string    `json:"engine"`
}

type rtDatabasesDatabase struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	SiteID      *uuid.UUID `json:"site_id" db:"site_id"`
	StackID     *uuid.UUID `json:"stack_id" db:"stack_id"`
	Name        string     `json:"name" db:"name"`
	Engine      string     `json:"engine" db:"engine"`
	DbUser      string     `json:"db_user" db:"db_user"`
	ContainerID *string    `json:"container_id" db:"container_id"`
	Port        *int32     `json:"port" db:"port"`
	// Public TCP listen port when remote access is on — NULL otherwise.
	// `default` lets queries that predate the column (create's RETURNING)
	// still hydrate the struct.
	RemotePort *int32 `json:"remote_port" db:"remote_port,default"`
	// The server's public address and whether the listener terminates TLS —
	// what a remote client actually needs to connect.
	RemoteHost  *string   `json:"remote_host" db:"remote_host,default"`
	RemoteTLS   bool      `json:"remote_tls" db:"remote_tls,default"`
	RemoteAllow []string  `json:"remote_allow" db:"remote_allow,default"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// rtDatabasesNormalize gives an absent remote_allow the Vec::default() shape.
func rtDatabasesNormalize(d *rtDatabasesDatabase) {
	if d.RemoteAllow == nil {
		d.RemoteAllow = []string{}
	}
}

// rtDatabasesList is GET /api/databases — all databases for the current user.
func rtDatabasesList(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	serverID, _, err := st.serverScope(r)
	if err != nil {
		return err
	}
	var params rtDatabasesListQuery
	if err := decodeQuery(r, &params); err != nil {
		return err
	}
	limit, offset := paginate(params.Limit, params.Offset)

	// Same admin-widening create() grants — without it, a database an admin
	// creates on a tenant's site via the local-box arm becomes invisible to
	// its own creator (v2.216.0 audit finding).
	//
	// LEFT JOIN both possible owner tables and COALESCE: a row has exactly
	// one non-null owner FK (chk_databases_owner), so one query covers
	// site-owned and stack-owned databases without a UNION.
	dbs, err := queryAll[rtDatabasesDatabase](r.Context(), st.DB,
		"SELECT d.id, d.site_id, d.stack_id, d.name, d.engine, d.db_user, d.container_id, d.port, "+
			"(SELECT p.listen_port FROM tcp_proxies p WHERE p.database_id = d.id) AS remote_port, "+
			"(SELECT sv.ip_address FROM tcp_proxies p JOIN servers sv ON sv.id = p.server_id "+
			"WHERE p.database_id = d.id) AS remote_host, "+
			"COALESCE((SELECT p.tls FROM tcp_proxies p WHERE p.database_id = d.id), FALSE) AS remote_tls, "+
			"COALESCE((SELECT p.allow_cidrs FROM tcp_proxies p WHERE p.database_id = d.id), '{}') AS remote_allow, "+
			"d.created_at "+
			"FROM databases d "+
			"LEFT JOIN sites s ON d.site_id = s.id "+
			"LEFT JOIN docker_stacks st ON d.stack_id = st.id "+
			"WHERE (COALESCE(s.user_id, st.user_id) = $1 OR EXISTS (SELECT 1 FROM users u, servers sv "+
			"WHERE u.id = $1 AND u.role = 'admin' AND sv.id = COALESCE(s.server_id, st.server_id) "+
			"AND (sv.is_local OR sv.user_id = u.id))) "+
			"AND COALESCE(s.server_id, st.server_id) = $2 ORDER BY d.created_at DESC LIMIT $3 OFFSET $4",
		claims.Sub, serverID, limit, offset)
	if err != nil {
		return internalError("list databases", err)
	}
	for i := range dbs {
		rtDatabasesNormalize(&dbs[i])
	}
	writeJSON(w, http.StatusOK, dbs)
	return nil
}

// rtDatabasesResolveOwner resolves the host + a caller-facing label for a
// database's owner — a site or a stack (GH #64), exactly one of which the
// caller must supply. The label only names agentForSiteServer's refusal log.
func rtDatabasesResolveOwner(ctx context.Context, st *AppState, siteID, stackID *uuid.UUID, userID uuid.UUID) (*uuid.UUID, string, error) {
	switch {
	case siteID != nil && stackID == nil:
		row, err := queryOpt[Tup2[*uuid.UUID, string]](ctx, st.DB,
			"SELECT s.server_id, s.domain FROM sites s WHERE "+SiteCallerPredicate, *siteID, userID)
		if err != nil {
			return nil, "", internalError("resolve database owner", err)
		}
		if row == nil {
			return nil, "", apiErr(http.StatusNotFound, "Site not found")
		}
		return row.A, row.B, nil
	case siteID == nil && stackID != nil:
		row, err := queryOpt[Tup2[*uuid.UUID, string]](ctx, st.DB,
			"SELECT st.server_id, st.name FROM docker_stacks st WHERE "+StackCallerPredicate, *stackID, userID)
		if err != nil {
			return nil, "", internalError("resolve database owner", err)
		}
		if row == nil {
			return nil, "", apiErr(http.StatusNotFound, "Stack not found")
		}
		return row.A, row.B, nil
	}
	return nil, "", apiErr(http.StatusBadRequest, "Specify exactly one of site_id or stack_id")
}

func rtDatabasesIsASCIIAlnum(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// rtDatabasesCreate is POST /api/databases.
func rtDatabasesCreate(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	var body rtDatabasesCreateDbRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()

	// Verify ownership — and take the host from the same row. A misdispatch
	// leaves a `databases` row naming a container that does not exist on the
	// owner's machine while the wrong machine keeps the container and port.
	// The row that decides WHICH OWNER has to decide WHICH HOST too.
	ownerServerID, ownerLabel, err := rtDatabasesResolveOwner(ctx, st, body.SiteID, body.StackID, claims.Sub)
	if err != nil {
		return err
	}
	agent, err := agentForSiteServer(ctx, st, ownerServerID, ownerLabel)
	if err != nil {
		return err
	}

	// Hard per-account cap (independent of reseller quota), counting both
	// site-owned and stack-owned rows.
	dbCount, err := queryScalar[int64](ctx, st.DB,
		"SELECT COUNT(*) FROM databases d "+
			"LEFT JOIN sites s ON d.site_id = s.id "+
			"LEFT JOIN docker_stacks st ON d.stack_id = st.id "+
			"WHERE COALESCE(s.user_id, st.user_id) = $1", claims.Sub)
	if err != nil {
		return internalError("create databases", err)
	}
	if dbCount >= rtDatabasesMaxDatabasesPerUser {
		return apiErr(http.StatusForbidden, fmt.Sprintf("Database limit reached (%d per account)", rtDatabasesMaxDatabasesPerUser))
	}

	// Validate name.
	if body.Name == "" || len(body.Name) > 63 {
		return apiErr(http.StatusBadRequest, "Invalid database name")
	}
	for _, c := range body.Name {
		if !rtDatabasesIsASCIIAlnum(c) && c != '_' {
			return apiErr(http.StatusBadRequest, "Database name must be alphanumeric with underscores")
		}
	}
	// ⛔ The AGENT is the authority on this name and its isValidName demands
	// an alphanumeric FIRST character; without this the operator got the
	// agent's own refusal for a form the product had just validated.
	//
	// ⚠ The 63 above must not be "aligned" to the agent's 64: a PostgreSQL
	// identifier is 63 bytes, so 63 is the cross-engine cap.
	if !rtDatabasesIsASCIIAlnum(rune(body.Name[0])) {
		return apiErr(http.StatusBadRequest, "Database name must start with a letter or a number")
	}
	if rtDatabasesIsReservedDbName(body.Name) {
		return apiErr(http.StatusBadRequest, "Database name is reserved (system/admin name)")
	}

	// Check uniqueness per-owner (site OR stack).
	existing, err := queryScalarOpt[uuid.UUID](ctx, st.DB,
		"SELECT id FROM databases WHERE site_id IS NOT DISTINCT FROM $1 "+
			"AND stack_id IS NOT DISTINCT FROM $2 AND name = $3", body.SiteID, body.StackID, body.Name)
	if err != nil {
		return internalError("create databases", err)
	}
	if existing != nil {
		return apiErr(http.StatusConflict, "Database name already exists for this owner")
	}

	engine := "postgres"
	if body.Engine != nil {
		engine = *body.Engine
	}
	if engine != "postgres" && engine != "mysql" && engine != "mariadb" {
		return apiErr(http.StatusBadRequest, "Engine must be postgres, mysql, or mariadb")
	}

	// Generate password and find available port.
	password := strings.ReplaceAll(uuid.New().String(), "-", "")
	port, err := rtDatabasesFindAvailablePort(ctx, st, engine)
	if err != nil {
		return err
	}

	encryptedPassword, err := SecretsCryptoEncryptCredential(password, st.Config.JWTSecret)
	if err != nil {
		return apiErr(http.StatusInternalServerError, fmt.Sprintf("Encryption failed: %v", err))
	}

	// Atomically reserve one slot against the caller's reseller quota (if
	// any). Released on any failure below.
	reservedQuota, err := rtDatabasesReserveResellerDbSlot(ctx, st, claims.Sub)
	if err != nil {
		return err
	}

	// Insert the record first to atomically claim the port (unique index
	// prevents races). container_id is empty until the agent creates it.
	dbRecord, err := queryOne[rtDatabasesDatabase](ctx, st.DB,
		"INSERT INTO databases (site_id, stack_id, name, engine, db_user, db_password_enc, container_id, port) "+
			"VALUES ($1, $2, $3, $4, $5, $6, '', $7) "+
			"RETURNING id, site_id, stack_id, name, engine, db_user, container_id, port, created_at",
		body.SiteID, body.StackID, body.Name, engine, body.Name, encryptedPassword, port)
	if err != nil {
		if reservedQuota {
			rtDatabasesReleaseResellerDbSlot(ctx, st, claims.Sub)
		}
		if s := err.Error(); strings.Contains(s, "unique") || strings.Contains(s, "duplicate") {
			return apiErr(http.StatusConflict, "Port or database name conflict, please retry")
		}
		return internalError("create databases", err)
	}
	rtDatabasesNormalize(&dbRecord)

	// Call agent to create the container. `stack_id` tells the agent to join
	// the stack's own private bridge network instead of the shared,
	// ICC-disabled `dockpanel-db` bridge — single-tenant by construction, and
	// every panel-side operation reaches the container via `docker exec`.
	var stackID *string
	if body.StackID != nil {
		stackID = new(body.StackID.String())
	}
	result, err := agent.Post(ctx, "/databases", map[string]any{
		"name":     body.Name,
		"engine":   engine,
		"password": password,
		"port":     port,
		"stack_id": stackID,
	})
	if err != nil {
		// Clean up the record + release the reserved quota slot.
		_, _ = execSQL(ctx, st.DB, "DELETE FROM databases WHERE id = $1", dbRecord.ID)
		if reservedQuota {
			rtDatabasesReleaseResellerDbSlot(ctx, st, claims.Sub)
		}
		return agentError("Database creation", err)
	}
	containerID, _ := jsonStr(jsonGet(result, "container_id"))

	if _, err := execSQL(ctx, st.DB, "UPDATE databases SET container_id = $1 WHERE id = $2", containerID, dbRecord.ID); err != nil {
		return internalError("create databases", err)
	}

	slog.Info(fmt.Sprintf("Database created: %s (%s, port %d)", body.Name, engine, port))
	writeJSON(w, http.StatusCreated, dbRecord)
	return nil
}

// rtDatabasesCallerPredicate is the admin-widened ownership term shared by
// credentials/remove/getDbInfo (v2.216.0 audit note on list). `$1` is the
// database id, `$2` the caller.
const rtDatabasesCallerPredicate = "d.id = $1 AND (COALESCE(s.user_id, st.user_id) = $2 OR EXISTS (SELECT 1 FROM users u, servers sv " +
	"WHERE u.id = $2 AND u.role = 'admin' AND sv.id = COALESCE(s.server_id, st.server_id) " +
	"AND (sv.is_local OR sv.user_id = u.id)))"

// rtDatabasesCredentials is GET /api/databases/{id}/credentials.
func rtDatabasesCredentials(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	row, err := queryOpt[Tup5[string, string, string, *int32, *string]](r.Context(), st.DB,
		"SELECT d.name, d.engine, d.db_password_enc, d.port, d.container_id "+
			"FROM databases d "+
			"LEFT JOIN sites s ON d.site_id = s.id "+
			"LEFT JOIN docker_stacks st ON d.stack_id = st.id "+
			"WHERE "+rtDatabasesCallerPredicate, id, claims.Sub)
	if err != nil {
		return internalError("credentials", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Database not found")
	}
	name, engine, passwordEnc := row.A, row.B, row.C

	// Decrypt password (with legacy plaintext fallback for pre-encryption records).
	password := SecretsCryptoDecryptCredentialOrLegacy(passwordEnc, st.Config.JWTSecret)
	host := "127.0.0.1"
	if row.E != nil {
		host = "dockpanel-db-" + name
	}
	port := int32(5432)
	if row.D != nil {
		port = *row.D
	}
	var cs string
	switch engine {
	case "mysql", "mariadb":
		cs = fmt.Sprintf("mysql://%s:%s@127.0.0.1:%d/%s", name, password, port, name)
	default:
		cs = fmt.Sprintf("postgresql://%s:%s@127.0.0.1:%d/%s", name, password, port, name)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host":              "127.0.0.1",
		"port":              port,
		"database":          name,
		"username":          name,
		"password":          password,
		"engine":            engine,
		"connection_string": cs,
		"internal_host":     host,
	})
	return nil
}

// rtDatabasesRemove is DELETE /api/databases/{id}.
func rtDatabasesRemove(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()

	// Verify ownership — and take the host from the same row. Dispatching to
	// the wrong machine either destroys a same-named `dockpanel-db-{name}`
	// container belonging to somebody else's tenant, or misses while the real
	// container is orphaned on its own host with its row already gone.
	row, err := queryOpt[Tup5[uuid.UUID, string, *string, *uuid.UUID, string]](ctx, st.DB,
		"SELECT d.id, d.name, d.container_id, COALESCE(s.server_id, st.server_id), "+
			"COALESCE(s.domain, st.name) FROM databases d "+
			"LEFT JOIN sites s ON d.site_id = s.id "+
			"LEFT JOIN docker_stacks st ON d.stack_id = st.id "+
			"WHERE "+rtDatabasesCallerPredicate, id, claims.Sub)
	if err != nil {
		return internalError("remove databases", err)
	}
	if row == nil {
		return apiErr(http.StatusNotFound, "Database not found")
	}
	name, containerID, ownerServerID, ownerLabel := row.B, row.C, row.D, row.E

	agent, err := agentForSiteServer(ctx, st, ownerServerID, ownerLabel)
	if err != nil {
		return err
	}

	// Its remote-access stream proxy goes FIRST: close the public listener
	// (and its firewall rule) before the container dies, or the port stays
	// open proxying into a dead container for the rest of the delete.
	proxy, err := queryOpt[Tup2[string, int32]](ctx, st.DB,
		"SELECT name, listen_port FROM tcp_proxies WHERE database_id = $1", id)
	if err != nil {
		return internalError("lookup database tcp proxy", err)
	}
	if proxy != nil {
		// Abort, like remote_access_disable: deleting past a failed removal
		// would drop the row and leave a public listener nobody can see.
		if _, err := agent.Delete(ctx, fmt.Sprintf("/nginx/streams/%s?listen_port=%d", proxy.A, proxy.B)); err != nil {
			return agentError("Database remote access removal", err)
		}
		_, _ = execSQL(ctx, st.DB, "DELETE FROM tcp_proxies WHERE database_id = $1", id)
	}

	// Remove container via agent (must succeed before DB deletion).
	if containerID != nil {
		if _, err := agent.Delete(ctx, "/databases/"+*containerID); err != nil {
			return agentError("Database removal", err)
		}
	}

	if _, err := execSQL(ctx, st.DB, "DELETE FROM databases WHERE id = $1", id); err != nil {
		return internalError("remove databases", err)
	}

	// Decrement reseller database counter.
	_, _ = execSQL(ctx, st.DB,
		"UPDATE reseller_profiles SET used_databases = GREATEST(used_databases - 1, 0), updated_at = NOW() "+
			"WHERE user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL)", claims.Sub)

	rtDatabasesPurgeDumpsIfUnclaimed(ctx, st, agent, name, ownerServerID)

	slog.Info("Database deleted: " + name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
	return nil
}

// rtDatabasesPurgeDumpsIfUnclaimed removes a database's dump directory, but
// only once nothing else can claim it.
//
// ⛔ ORDERING IS THE ONLY GUARD, and getting it wrong is silent. The `shared`
// probe has no self-exclusion term, so every row still present answers about
// ITSELF: call this before the row is gone and nothing is ever purged while
// the log reads like correct behaviour. Call it only AFTER the row (or the
// cascade that takes it) has committed.
func rtDatabasesPurgeDumpsIfUnclaimed(ctx context.Context, st *AppState, agent AgentHandle, name string, siteServerID *uuid.UUID) {
	// The dump directory is named for the DATABASE only, while the name is
	// unique only per SITE, so two live databases on this host can share one
	// directory; purging on the first delete would take the survivor's backups.
	//
	// ⚠ A row whose owner names no server is counted as possibly-here. Doubt
	// keeps the files; only positive evidence that nothing else claims the
	// name removes them — the reverse trades a disclosed leak for silent loss.
	shared, err := queryScalar[bool](ctx, st.DB,
		"SELECT EXISTS(SELECT 1 FROM databases d "+
			"LEFT JOIN sites s ON s.id = d.site_id "+
			"LEFT JOIN docker_stacks st ON st.id = d.stack_id "+
			"WHERE d.name = $1 AND (COALESCE(s.server_id, st.server_id) = $2 "+
			"OR COALESCE(s.server_id, st.server_id) IS NULL))", name, siteServerID)
	if err != nil {
		shared = true
	}
	if shared {
		slog.Info(fmt.Sprintf("Keeping the dump directory for %s: another database on this server still uses that name", name))
		return
	}
	v, err := agent.Delete(ctx, "/db-backups/"+name)
	if err != nil {
		// Best-effort on purpose: the database IS deleted by now, and failing
		// the request over leftover files would misreport a destructive
		// operation that succeeded.
		slog.Warn(fmt.Sprintf("Could not purge dump directory for %s: %v", name, err))
		return
	}
	removed, _ := jsonU64(jsonGet(v, "removed"))
	kept, _ := jsonU64(jsonGet(v, "kept"))
	dirRemoved, _ := jsonBool(jsonGet(v, "dir_removed"))
	slog.Info(fmt.Sprintf("Purged dump directory for %s: %d file(s) removed, %d kept, directory removed: %v", name, removed, kept, dirRemoved))
}

// rtDatabasesDbInfo is what rtDatabasesGetDbInfo returns.
type rtDatabasesDbInfo struct {
	Name, Engine, Password string
	Port                   int32
	SiteServerID           *uuid.UUID
}

// rtDatabasesGetDbInfo fetches database info with an ownership check — and
// the id of the server the owner actually runs on.
//
// Callers used to answer WHICH DATABASE from this row and take WHICH HOST
// from ServerScope, which falls back to the LOCAL agent whenever the caller
// owns no `servers` row — always, for a non-admin. This returns the DECRYPTED
// password, which each caller forwards to its agent for a `docker exec -e
// MYSQL_PWD=…`; a misdispatch handed one tenant's live credential to a host
// their database does not run on. Each caller now resolves its handle from
// SiteServerID via agentForSiteServer, which REFUSES rather than substitutes.
// The shared chokepoint for 11 callers.
func rtDatabasesGetDbInfo(ctx context.Context, st *AppState, id, userID uuid.UUID) (*rtDatabasesDbInfo, error) {
	row, err := queryOpt[Tup6[string, string, string, *int32, *string, *uuid.UUID]](ctx, st.DB,
		"SELECT d.name, d.engine, d.db_password_enc, d.port, d.container_id, "+
			"COALESCE(s.server_id, st.server_id) "+
			"FROM databases d "+
			"LEFT JOIN sites s ON d.site_id = s.id "+
			"LEFT JOIN docker_stacks st ON d.stack_id = st.id "+
			"WHERE "+rtDatabasesCallerPredicate, id, userID)
	if err != nil {
		return nil, internalError("remove databases", err)
	}
	if row == nil {
		return nil, apiErr(http.StatusNotFound, "Database not found")
	}
	// Security (H1, v2.19.0): every exec/reset path resolves the container by
	// the (NON-unique) name `dockpanel-db-{name}`. A row with an EMPTY
	// container_id has not yet been confirmed by the agent; refusing it closes
	// the cross-tenant reset/query race for every caller at once.
	if row.E == nil || *row.E == "" {
		return nil, apiErr(http.StatusNotFound, "Database not found")
	}
	port := int32(5432)
	if row.D != nil {
		port = *row.D
	}
	return &rtDatabasesDbInfo{
		Name: row.A, Engine: row.B,
		Password:     SecretsCryptoDecryptCredentialOrLegacy(row.C, st.Config.JWTSecret),
		Port:         port,
		SiteServerID: row.F,
	}, nil
}

// rtDatabasesInfoAndAgent is getDbInfo + the owner's own agent.
func rtDatabasesInfoAndAgent(ctx context.Context, st *AppState, id uuid.UUID, c *Claims) (*rtDatabasesDbInfo, AgentHandle, error) {
	info, err := rtDatabasesGetDbInfo(ctx, st, id, c.Sub)
	if err != nil {
		return nil, nil, err
	}
	agent, err := agentForSiteServer(ctx, st, info.SiteServerID, info.Name)
	if err != nil {
		return nil, nil, err
	}
	return info, agent, nil
}

func (i *rtDatabasesDbInfo) queryBody(sql string) map[string]any {
	return map[string]any{
		"container": "dockpanel-db-" + i.Name,
		"engine":    i.Engine,
		"user":      i.Name,
		"password":  i.Password,
		"database":  i.Name,
		"sql":       sql,
	}
}

func rtDatabasesRunQuery(ctx context.Context, w http.ResponseWriter, agent AgentHandle, body map[string]any) error {
	res, err := agent.Post(ctx, "/databases/query", body)
	if err != nil {
		return rtDatabasesSQLError(err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

func rtDatabasesIsMy(engine string) bool { return engine == "mysql" || engine == "mariadb" }

// rtDatabasesTables is GET /api/databases/{id}/tables.
func rtDatabasesTables(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	info, agent, err := rtDatabasesInfoAndAgent(r.Context(), st, id, claims)
	if err != nil {
		return err
	}
	sql := "SELECT t.table_name, t.table_type, " +
		"pg_catalog.pg_size_pretty(pg_catalog.pg_total_relation_size(quote_ident(t.table_name))) AS size " +
		"FROM information_schema.tables t " +
		"WHERE t.table_schema = 'public' ORDER BY t.table_name"
	if rtDatabasesIsMy(info.Engine) {
		sql = "SELECT table_name, table_type, table_rows, " +
			"ROUND((data_length + index_length) / 1024, 1) AS size_kb " +
			"FROM information_schema.tables WHERE table_schema = DATABASE() " +
			"ORDER BY table_name"
	}
	return rtDatabasesRunQuery(r.Context(), w, agent, info.queryBody(sql))
}

// rtDatabasesIsSafeTableName is the one charset any table name is
// interpolated under.
//
// /databases/query has no bind-parameter channel — the statement is handed
// verbatim to `mariadb -e` / `psql -c` — so this predicate is the only thing
// between a path segment and that statement. It admits no quote, backslash or
// shell metacharacter. ONE function on purpose: two copies with two charsets
// is the bug this file already shipped once.
func rtDatabasesIsSafeTableName(table string) bool {
	if table == "" || len(table) > 128 {
		return false
	}
	for _, c := range table {
		if !rtDatabasesIsASCIIAlnum(c) && c != '_' {
			return false
		}
	}
	return true
}

// rtDatabasesTableSchema is GET /api/databases/{id}/tables/{table}.
func rtDatabasesTableSchema(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	table := r.PathValue("table")
	if !rtDatabasesIsSafeTableName(table) {
		return apiErr(http.StatusBadRequest, "Invalid table name")
	}
	info, agent, err := rtDatabasesInfoAndAgent(r.Context(), st, id, claims)
	if err != nil {
		return err
	}
	// Interpolated, not bound: the agent has never had a `params` field, so a
	// `$1`/`?` placeholder reached the engine unbound and every column listing
	// 400'd invisibly. table_indexes always interpolated and always worked.
	sql := fmt.Sprintf("SELECT column_name, data_type, character_maximum_length, is_nullable, column_default "+
		"FROM information_schema.columns "+
		"WHERE table_schema = 'public' AND table_name = '%s' "+
		"ORDER BY ordinal_position", table)
	if rtDatabasesIsMy(info.Engine) {
		sql = fmt.Sprintf("SELECT column_name, column_type, is_nullable, column_default, column_key, extra "+
			"FROM information_schema.columns "+
			"WHERE table_schema = DATABASE() AND table_name = '%s' "+
			"ORDER BY ordinal_position", table)
	}
	return rtDatabasesRunQuery(r.Context(), w, agent, info.queryBody(sql))
}

type rtDatabasesSQLQueryRequest struct {
	SQL string `json:"sql"`
}

// rtDatabasesQuery is POST /api/databases/{id}/query.
func rtDatabasesQuery(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtDatabasesSQLQueryRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if strings.TrimSpace(body.SQL) == "" {
		return apiErr(http.StatusBadRequest, "Query is empty")
	}
	if len(body.SQL) > 10_000 {
		return apiErr(http.StatusBadRequest, "Query too long (max 10KB)")
	}
	// The host comes from the owner's row, never the caller's switcher: this
	// body carries the tenant's DECRYPTED password.
	info, agent, err := rtDatabasesInfoAndAgent(r.Context(), st, id, claims)
	if err != nil {
		return err
	}
	return rtDatabasesRunQuery(r.Context(), w, agent, info.queryBody(body.SQL))
}

// rtDatabasesTableIndexes is GET /api/databases/{id}/indexes/{table}.
func rtDatabasesTableIndexes(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	table := r.PathValue("table")
	if !rtDatabasesIsSafeTableName(table) {
		return apiErr(http.StatusBadRequest, "Invalid table name")
	}
	info, agent, err := rtDatabasesInfoAndAgent(r.Context(), st, id, claims)
	if err != nil {
		return err
	}
	sql := fmt.Sprintf("SELECT indexname AS index_name, indexdef AS definition "+
		"FROM pg_indexes "+
		"WHERE schemaname = 'public' AND tablename = '%s' "+
		"ORDER BY indexname", table)
	if rtDatabasesIsMy(info.Engine) {
		sql = fmt.Sprintf("SELECT index_name, GROUP_CONCAT(column_name ORDER BY seq_in_index) AS columns, "+
			"non_unique, index_type "+
			"FROM information_schema.statistics "+
			"WHERE table_schema = DATABASE() AND table_name = '%s' "+
			"GROUP BY index_name, non_unique, index_type "+
			"ORDER BY index_name", table)
	}
	return rtDatabasesRunQuery(r.Context(), w, agent, info.queryBody(sql))
}

// rtDatabasesForeignKeys is GET /api/databases/{id}/foreign-keys.
func rtDatabasesForeignKeys(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	info, agent, err := rtDatabasesInfoAndAgent(r.Context(), st, id, claims)
	if err != nil {
		return err
	}
	sql := "SELECT " +
		"tc.table_name AS source_table, " +
		"kcu.column_name AS source_column, " +
		"ccu.table_name AS target_table, " +
		"ccu.column_name AS target_column, " +
		"tc.constraint_name, " +
		"rc.update_rule, rc.delete_rule " +
		"FROM information_schema.table_constraints tc " +
		"JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name " +
		"JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name = ccu.constraint_name " +
		"JOIN information_schema.referential_constraints rc ON tc.constraint_name = rc.constraint_name " +
		"WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public' " +
		"ORDER BY tc.table_name, kcu.column_name"
	if rtDatabasesIsMy(info.Engine) {
		sql = "SELECT kcu.table_name AS source_table, kcu.column_name AS source_column, " +
			"kcu.referenced_table_name AS target_table, kcu.referenced_column_name AS target_column, " +
			"rc.constraint_name, rc.update_rule, rc.delete_rule " +
			"FROM information_schema.key_column_usage kcu " +
			"JOIN information_schema.referential_constraints rc " +
			"ON kcu.constraint_name = rc.constraint_name AND kcu.constraint_schema = rc.constraint_schema " +
			"WHERE kcu.table_schema = DATABASE() AND kcu.referenced_table_name IS NOT NULL " +
			"ORDER BY kcu.table_name, kcu.column_name"
	}
	return rtDatabasesRunQuery(r.Context(), w, agent, info.queryBody(sql))
}

// rtDatabasesSchemaOverview is GET /api/databases/{id}/schema-overview —
// tables + foreign keys in a single call for the visual browser.
func rtDatabasesSchemaOverview(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	// Both queries go through this one handle, so it has to be the owner's
	// own host — otherwise the decrypted password leaves twice over.
	info, agent, err := rtDatabasesInfoAndAgent(r.Context(), st, id, claims)
	if err != nil {
		return err
	}
	tablesSQL := "SELECT t.table_name, t.table_type, " +
		"pg_stat_user_tables.n_live_tup AS table_rows, " +
		"pg_total_relation_size(quote_ident(t.table_name))/1024 AS size_kb " +
		"FROM information_schema.tables t " +
		"LEFT JOIN pg_stat_user_tables ON pg_stat_user_tables.relname = t.table_name " +
		"WHERE t.table_schema = 'public' ORDER BY t.table_name"
	fkSQL := "SELECT tc.table_name AS source_table, kcu.column_name AS source_column, " +
		"ccu.table_name AS target_table, ccu.column_name AS target_column, " +
		"tc.constraint_name " +
		"FROM information_schema.table_constraints tc " +
		"JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name " +
		"JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name = ccu.constraint_name " +
		"WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public'"
	if rtDatabasesIsMy(info.Engine) {
		tablesSQL = "SELECT table_name, table_type, table_rows, " +
			"ROUND((data_length + index_length) / 1024, 1) AS size_kb " +
			"FROM information_schema.tables WHERE table_schema = DATABASE() " +
			"ORDER BY table_name"
		fkSQL = "SELECT kcu.table_name AS source_table, kcu.column_name AS source_column, " +
			"kcu.referenced_table_name AS target_table, kcu.referenced_column_name AS target_column, " +
			"rc.constraint_name " +
			"FROM information_schema.key_column_usage kcu " +
			"JOIN information_schema.referential_constraints rc " +
			"ON kcu.constraint_name = rc.constraint_name AND kcu.constraint_schema = rc.constraint_schema " +
			"WHERE kcu.table_schema = DATABASE() AND kcu.referenced_table_name IS NOT NULL"
	}

	// Execute both queries concurrently.
	var tables, fks any
	var tErr, fErr error
	var wg sync.WaitGroup
	wg.Go(func() { tables, tErr = agent.Post(r.Context(), "/databases/query", info.queryBody(tablesSQL)) })
	wg.Go(func() { fks, fErr = agent.Post(r.Context(), "/databases/query", info.queryBody(fkSQL)) })
	wg.Wait()
	if tErr != nil {
		return rtDatabasesSQLError(tErr)
	}
	if fErr != nil {
		fks = map[string]any{"columns": []any{}, "rows": []any{}}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tables":       tables,
		"foreign_keys": fks,
		"engine":       info.Engine,
	})
	return nil
}

// rtDatabasesReserveResellerDbSlot atomically reserves one database slot
// against the caller's reseller quota: true if reserved (release on later
// failure), false if the user has no reseller, 403 if exhausted. The
// conditional UPDATE ... RETURNING closes the check-then-increment TOCTOU.
func rtDatabasesReserveResellerDbSlot(ctx context.Context, st *AppState, userID uuid.UUID) (bool, error) {
	reserved, err := queryScalarOpt[int32](ctx, st.DB,
		"UPDATE reseller_profiles SET used_databases = used_databases + 1, updated_at = NOW() "+
			"WHERE user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL) "+
			"AND (max_databases IS NULL OR used_databases < max_databases) "+
			"RETURNING 1", userID)
	if err != nil {
		return false, internalError("reserve reseller quota", err)
	}
	if reserved != nil {
		return true, nil // slot reserved + counter incremented atomically
	}
	// 0 rows: either no reseller/profile (nothing to enforce), or the quota
	// condition failed (exhausted).
	hasProfile, err := queryScalarOpt[uuid.UUID](ctx, st.DB,
		"SELECT rp.user_id FROM reseller_profiles rp "+
			"WHERE rp.user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL)", userID)
	if err != nil {
		return false, internalError("reserve reseller quota", err)
	}
	if hasProfile != nil {
		return false, apiErr(http.StatusForbidden, "Reseller database quota exceeded")
	}
	return false, nil
}

// rtDatabasesReleaseResellerDbSlot is the compensating decrement.
func rtDatabasesReleaseResellerDbSlot(ctx context.Context, st *AppState, userID uuid.UUID) {
	_, _ = execSQL(ctx, st.DB,
		"UPDATE reseller_profiles SET used_databases = GREATEST(used_databases - 1, 0), updated_at = NOW() "+
			"WHERE user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL)", userID)
}

// rtDatabasesFindAvailablePort finds the first unused port in the engine's
// range. Ranges are wide so the per-account cap leaves ample headroom.
func rtDatabasesFindAvailablePort(ctx context.Context, st *AppState, engine string) (int32, error) {
	start, end := int32(5433), int32(5700)
	if rtDatabasesIsMy(engine) {
		start, end = 3307, 3600
	}
	p, err := queryScalarOpt[int32](ctx, st.DB,
		"SELECT s.port FROM generate_series($1::int, $2::int) AS s(port) "+
			"WHERE s.port NOT IN (SELECT port FROM databases WHERE port IS NOT NULL) "+
			"LIMIT 1", start, end)
	if err != nil {
		return 0, internalError("query", err)
	}
	if p == nil {
		return 0, apiErr(http.StatusInternalServerError, "No available ports for database")
	}
	return *p, nil
}

// ─── Point-in-Time Recovery (PITR) ─────────────────────────────

type rtDatabasesPitrConfigRequest struct {
	PitrEnabled    *bool  `json:"pitr_enabled"`
	RetentionHours *int32 `json:"retention_hours"`
}

// rtDatabasesPitrConfig is GET /api/databases/{id}/pitr.
func rtDatabasesPitrConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// Verify ownership — admin-widened; the owner is a site or a stack.
	owned, err := queryScalarOpt[string](ctx, st.DB,
		"SELECT name FROM databases WHERE id = $1 AND ("+
			"site_id IN (SELECT s.id FROM sites s WHERE s.user_id = $2 OR EXISTS "+
			"(SELECT 1 FROM users u, servers sv WHERE u.id = $2 AND u.role = 'admin' "+
			"AND sv.id = s.server_id AND (sv.is_local OR sv.user_id = u.id))) "+
			"OR stack_id IN (SELECT st.id FROM docker_stacks st WHERE st.user_id = $2 OR EXISTS "+
			"(SELECT 1 FROM users u, servers sv WHERE u.id = $2 AND u.role = 'admin' "+
			"AND sv.id = st.server_id AND (sv.is_local OR sv.user_id = u.id))))", id, claims.Sub)
	if err != nil {
		return internalError("pitr config", err)
	}
	if owned == nil {
		return apiErr(http.StatusNotFound, "Database not found")
	}
	cfg, err := queryOpt[Tup5[bool, int32, *time.Time, *time.Time, int64]](ctx, st.DB,
		"SELECT pitr_enabled, retention_hours, last_backup_at, last_wal_at, backup_size_bytes "+
			"FROM db_pitr_config WHERE database_id = $1", id)
	if err != nil {
		return internalError("pitr config", err)
	}
	if cfg == nil {
		writeJSON(w, http.StatusOK, map[string]any{"pitr_enabled": false, "retention_hours": 24})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pitr_enabled":      cfg.A,
		"retention_hours":   cfg.B,
		"last_backup_at":    cfg.C,
		"last_wal_at":       cfg.D,
		"backup_size_bytes": cfg.E,
	})
	return nil
}

// rtDatabasesUpdatePitrConfig is PUT /api/databases/{id}/pitr.
func rtDatabasesUpdatePitrConfig(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if _, _, err := st.serverScope(r); err != nil {
		return err
	}
	var body rtDatabasesPitrConfigRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	ctx := r.Context()
	// Ownership + container-readiness check (getDbInfo enforces the H1 guard).
	// No agent call on this path — only the intent flag is persisted.
	info, err := rtDatabasesGetDbInfo(ctx, st, id, claims.Sub)
	if err != nil {
		return err
	}
	enabled := body.PitrEnabled != nil && *body.PitrEnabled
	hours := int32(24)
	if body.RetentionHours != nil {
		hours = *body.RetentionHours
	}
	hours = min(max(hours, 1), 720)

	// NOTE (v2.19.0): the previous implementation ran `ALTER SYSTEM SET
	// archive_mode='on'` with no inverse, so archiving was un-revertable and
	// grew WAL without bound. That container mutation is removed; only the
	// intent flag is persisted until real, symmetric WAL archiving exists
	// (pitr_restore returns 501 until then).
	if _, err := execSQL(ctx, st.DB,
		"INSERT INTO db_pitr_config (database_id, pitr_enabled, retention_hours) "+
			"VALUES ($1, $2, $3) "+
			"ON CONFLICT (database_id) DO UPDATE SET "+
			"pitr_enabled = $2, retention_hours = $3, updated_at = NOW()", id, enabled, hours); err != nil {
		return internalError("update pitr config", err)
	}
	action := "database.pitr_disabled"
	if enabled {
		action = "database.pitr_enabled"
	}
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, action,
		new("database"), new(info.Name), nil, nil, claims.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// rtDatabasesPitrRestore is POST /api/databases/{id}/pitr/restore.
func rtDatabasesPitrRestore(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if _, _, err := st.serverScope(r); err != nil {
		return err
	}
	var body any
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if _, err := rtDatabasesGetDbInfo(r.Context(), st, id, claims.Sub); err != nil {
		return err
	}
	// Honesty (v2.19.0): point-in-time restore was never functional and used
	// to LIE — it wrote a restore-point marker (no rollback) and returned
	// {ok:true}. An explicit 501 until real PITR is implemented.
	return apiErr(http.StatusNotImplemented, "Point-in-time restore is not yet implemented")
}

// rtDatabasesResetPassword is POST /api/databases/{id}/reset-password —
// generates a new password, updates the container via the agent, then stores
// it encrypted and returns it.
func rtDatabasesResetPassword(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// The host MUST come from the owner's row: container names are unique only
	// per host, so the wrong machine would reset ANY same-named container for
	// a tenant who has nothing to do with the caller, while the panel row is
	// updated regardless. The agent's mysql branch authenticates AS THE TENANT
	// with old_password, so that value is load-bearing.
	info, agent, err := rtDatabasesInfoAndAgent(ctx, st, id, claims)
	if err != nil {
		return err
	}
	newPassword := strings.ReplaceAll(uuid.New().String(), "-", "")

	if _, err := agent.Post(ctx, "/databases/reset-password", map[string]any{
		"container":    "dockpanel-db-" + info.Name,
		"engine":       info.Engine,
		"user":         info.Name,
		"old_password": info.Password,
		"new_password": newPassword,
	}); err != nil {
		return agentError("Database password reset", err)
	}

	encrypted, err := SecretsCryptoEncryptCredential(newPassword, st.Config.JWTSecret)
	if err != nil {
		return apiErr(http.StatusInternalServerError, fmt.Sprintf("Encryption failed: %v", err))
	}
	if _, err := execSQL(ctx, st.DB, "UPDATE databases SET db_password_enc = $1 WHERE id = $2", encrypted, id); err != nil {
		return internalError("reset password", err)
	}

	ip := clientIP(r)
	ActivityLogActivity(ctx, st.DB, claims.Sub, claims.Email, "database.password_reset",
		new("database"), new(info.Name), nil, ip, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "database.password_reset", new(claims.Email), ip,
		new("database"), new(info.Name), nil, nil, "warning", claims.KeyID)
	slog.Info("Database password reset: " + info.Name)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "password": newPassword})
	return nil
}

// rtDatabasesDumps is GET /api/databases/{id}/dumps — what is sitting in this
// database's dump directory.
//
// The intake pattern is the migration wizard's: the operator puts the dump on
// the server and the panel takes it by NAME (base64-in-JSON tops out ~1.5 MB).
//
// ⛔ ADMIN ONLY — a security boundary. The directory is keyed by DATABASE
// NAME, which is reusable and unique only per site, so a tenant reusing a
// previous tenant's name would see (and import) that tenant's leftover,
// unencrypted dumps. Row-scoping cannot fix it: the point of this door is
// files that have no row.
func rtDatabasesDumps(st *AppState, w http.ResponseWriter, r *http.Request) error {
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
	info, agent, err := rtDatabasesInfoAndAgent(r.Context(), st, id, claims)
	if err != nil {
		return err
	}
	listing, err := agent.Get(r.Context(), "/db-backups/"+info.Name+"/list")
	if err != nil {
		return agentError("Database dump listing", err)
	}

	// The agent answers "is this a backup at all"; whether it can go into
	// THIS database depends on the engine, so it is annotated here and the
	// import handler enforces the identical rule.
	entries, ok := listing.([]any)
	if !ok {
		// A shape we do not recognise is not an empty directory, and must not
		// render as one — the empty state is a positive claim about the disk.
		writeJSON(w, http.StatusOK, listing)
		return nil
	}
	for _, e := range entries {
		filename, _ := jsonStr(jsonGet(e, "filename"))
		if _, ok := jsonStr(jsonGet(e, "unsupported")); ok {
			continue // Already explained: not a backup file at all.
		}
		if reason := rtDatabasesImportBlockedReason(filename, info.Engine); reason != "" {
			if m, ok := e.(map[string]any); ok {
				m["import_blocked"] = reason
			}
		}
	}
	writeJSON(w, http.StatusOK, entries)
	return nil
}

// rtDatabasesImportBlockedReason says why a real backup still cannot be
// imported into THIS database ("" = it can). A pure function so the listing
// and the import door are the same call and cannot drift apart.
func rtDatabasesImportBlockedReason(filename, engine string) string {
	if strings.HasSuffix(filename, ".enc") {
		// A backup the PANEL took and encrypted with its own key; the import
		// door has no key to offer. Name the door that CAN open it.
		return "Encrypted panel backup. Restore it from Backup Manager, which holds the key."
	}
	// `.archive.gz` is MongoDB's dump format; fed to psql it fails deep inside
	// the pipe on content rather than at the door.
	isMongo := engine == "mongo" || engine == "mongodb"
	if strings.HasSuffix(filename, ".archive.gz") && !isMongo {
		return fmt.Sprintf("MongoDB archive format. This database is %s, which reads .sql.gz.", engine)
	}
	if strings.HasSuffix(filename, ".sql.gz") && isMongo {
		return "SQL dump. This database is MongoDB, which reads .archive.gz."
	}
	return ""
}

type rtDatabasesImportDbRequest struct {
	Filename string `json:"filename"`
}

// rtDatabasesImport is POST /api/databases/{id}/import — import a dump the
// operator placed on the server. The importer is the agent's existing
// /db-backups/{db}/restore/{filename}; this is only the door onto it.
//
// ⛔ Admin only, for the reason on rtDatabasesDumps.
func rtDatabasesImport(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var body rtDatabasesImportDbRequest
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := requireAdmin(claims.Role); err != nil {
		return err
	}
	ctx := r.Context()

	// The agent's is_safe_filename is the real gate, but this name is about
	// to go into an HTTP request line, where a merely UNUSUAL character (a
	// space) broke far from anything that could explain it. Checked HERE,
	// where the answer can still be a sentence about the file.
	filename := strings.TrimSpace(body.Filename)
	charsetOK := filename != "" && len(filename) <= 255 && !strings.Contains(filename, "..")
	for _, c := range filename {
		if !rtDatabasesIsASCIIAlnum(c) && c != '-' && c != '_' && c != '.' {
			charsetOK = false
		}
	}
	if !charsetOK {
		return apiErr(http.StatusBadRequest, "That filename cannot be used. Backup names may contain letters, digits, "+
			"dash, underscore and dot only — rename the file on the server and try again.")
	}

	info, err := rtDatabasesGetDbInfo(ctx, st, id, claims.Sub)
	if err != nil {
		return err
	}
	// The same rule the listing shows, ENFORCED.
	if reason := rtDatabasesImportBlockedReason(filename, info.Engine); reason != "" {
		return apiErr(http.StatusBadRequest, reason)
	}
	// Host from the owner's row, never the caller's scope: this hands the
	// tenant's decrypted password to whichever agent answers.
	agent, err := agentForSiteServer(ctx, st, info.SiteServerID, info.Name)
	if err != nil {
		return err
	}

	agentBody := map[string]any{
		"container_name": "dockpanel-db-" + info.Name,
		"db_type":        info.Engine,
		"user":           info.Name,
		"password":       info.Password,
	}

	// ⛔ The timeout is taken HERE rather than read off the returned error:
	// the error kinds conflate timeouts with URI and connection failures (the
	// remote client maps every failure to a connection error), which told
	// fleet operators their agent was offline while the import ran fine. Our
	// own deadline is unambiguous on both transports; the inner budget is
	// larger so the inner clock can never be the one that fires.
	const budget = AgentDBRestoreTimeoutSecs
	tctx, cancel := context.WithTimeout(ctx, budget*time.Second)
	defer cancel()
	result, err := agent.PostLong(tctx, fmt.Sprintf("/db-backups/%s/restore/%s", info.Name, filename), agentBody, budget+60)
	if err != nil {
		if errors.Is(tctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			slog.Warn("import outlasted the panel's request timeout; the agent is still running it",
				"database", info.Name, "filename", filename)
			// Deliberately NOT reported as a failure: the operator's natural
			// response to "failed" is to run it again, on top of a database
			// that is mid-write.
			return apiErr(http.StatusGatewayTimeout, fmt.Sprintf(
				"The import is still running on the server — it was NOT cancelled and "+
					"must not be started again. A dump that takes longer than %ds "+
					"outlasts the panel's request timeout, so there is nothing left here to "+
					"watch it with. Browse the tables in a few minutes to see it finish.", budget))
		}
		return agentError("Database import", err)
	}

	ip := clientIP(r)
	ActivityLogActivityOnServer(ctx, st.DB, claims.Sub, claims.Email, "database.import",
		new("database"), new(info.Name), new(filename), ip, info.SiteServerID, claims.KeyID)
	SecurityHardeningAuditLog(ctx, st.DB, "database.import", new(claims.Email), ip,
		new("database"), new(info.Name), new(filename), nil, "info", claims.KeyID)
	ExtensionsFireEvent(st.DB, "database.imported", map[string]any{
		"database":    info.Name,
		"database_id": id.String(),
		"filename":    filename,
	})
	slog.Info(fmt.Sprintf("Database import completed: %s from %s", info.Name, filename))

	writeJSON(w, http.StatusOK, result)
	return nil
}

// ─── Remote access (nginx stream TCP proxy) ───────────────────────────────

type rtDatabasesRemoteAccessRequest struct {
	TLS           bool       `json:"tls" serde:"default"`
	CertificateID *uuid.UUID `json:"certificate_id"`
	// Source IPs/CIDRs allowed to connect; empty means anyone.
	AllowCIDRs []string `json:"allow_cidrs" serde:"default"`
}

// rtDatabasesProxyNameForDb is the proxy's nginx-side name: `db-` plus the
// database name rewritten into the stream slug alphabet ([a-z0-9-]),
// truncated to the 48-char cap with any trailing '-' a cut left stripped.
func rtDatabasesProxyNameForDb(name string) string {
	slug := []rune("db-" + strings.ToLower(strings.ReplaceAll(name, "_", "-")))
	if len(slug) > 48 {
		slug = slug[:48]
	}
	return strings.TrimRight(string(slug), "-")
}

// rtDatabasesOwnedDbForRemoteAccess loads a caller-owned database row with
// its owner's server — the same LEFT JOIN + COALESCE shape as remove(),
// because acting on the wrong host is the defect this ordering prevents.
func rtDatabasesOwnedDbForRemoteAccess(ctx context.Context, st *AppState, id, userID uuid.UUID) (*Tup5[string, *int32, *string, *uuid.UUID, *string], error) {
	row, err := queryOpt[Tup5[string, *int32, *string, *uuid.UUID, *string]](ctx, st.DB,
		"SELECT d.name, d.port, d.container_id, COALESCE(s.server_id, st.server_id), "+
			"sv.ip_address FROM databases d "+
			"LEFT JOIN sites s ON d.site_id = s.id "+
			"LEFT JOIN docker_stacks st ON d.stack_id = st.id "+
			"LEFT JOIN servers sv ON sv.id = COALESCE(s.server_id, st.server_id) "+
			"WHERE d.id = $1 AND (COALESCE(s.user_id, st.user_id) = $2 OR EXISTS "+
			"(SELECT 1 FROM users u WHERE u.id = $2 AND u.role = 'admin' "+
			"AND (sv.is_local OR sv.user_id = u.id)))", id, userID)
	if err != nil {
		return nil, internalError("resolve database for remote access", err)
	}
	if row == nil {
		return nil, apiErr(http.StatusNotFound, "Database not found")
	}
	return row, nil
}

// rtDatabasesRemoteAccessEnable is POST /api/databases/{id}/remote-access —
// publish the database on a public TCP port through nginx's stream module.
// The upstream is the container's existing loopback binding; the agent reads
// it off the container, so what is on the wire is a container id, not a
// guessed port.
func rtDatabasesRemoteAccessEnable(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	// Option<Json<T>>: no Content-Type header at all means "no body"; any
	// Content-Type is decoded (and refused) exactly as Json<T> would be.
	var body rtDatabasesRemoteAccessRequest
	if len(r.Header.Values("Content-Type")) > 0 {
		if err := decodeJSON(r, &body); err != nil {
			return err
		}
	}
	ctx := r.Context()

	row, err := rtDatabasesOwnedDbForRemoteAccess(ctx, st, id, claims.Sub)
	if err != nil {
		return err
	}
	name, port, containerID, serverID, serverIP := row.A, row.B, row.C, row.D, row.E
	if containerID == nil || *containerID == "" {
		return apiErr(http.StatusConflict, "Database has no container yet — wait for creation to finish")
	}
	if port == nil {
		return apiErr(http.StatusConflict, "Database has no bound port")
	}
	if serverID == nil {
		return apiErr(http.StatusConflict, "Database is not associated with a server")
	}
	agent, err := agentForSiteServer(ctx, st, serverID, "database "+name)
	if err != nil {
		return err
	}
	allow := body.AllowCIDRs
	if allow == nil {
		allow = []string{}
	}

	p, err := rtTcpProxiesCreateProxy(ctx, st, agent, *serverID, claims.Sub,
		rtDatabasesProxyNameForDb(name), "database", "127.0.0.1", *port,
		body.TLS, body.CertificateID, &id, containerID, claims.Role == "admin", allow)
	if err != nil {
		return err
	}

	slog.Info(fmt.Sprintf("Database remote access enabled: %s on :%d", name, p.ListenPort))
	ActivityLogActivityOnServer(ctx, st.DB, claims.Sub, claims.Email, "database.remote_access_enabled",
		new("database"), new(name), new(fmt.Sprintf("port %d", p.ListenPort)), nil, serverID, claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"proxy_id":    p.ID,
		"host":        serverIP,
		"listen_port": p.ListenPort,
		"upstream":    fmt.Sprintf("%s:%d", p.UpstreamHost, p.UpstreamPort),
		"tls":         p.TLS,
	})
	return nil
}

// rtDatabasesRemoteAccessDisable is DELETE /api/databases/{id}/remote-access
// — remove the stream file, close the firewall port, drop the row.
func rtDatabasesRemoteAccessDisable(st *AppState, w http.ResponseWriter, r *http.Request) error {
	claims, err := st.authUser(r)
	if err != nil {
		return err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	row, err := rtDatabasesOwnedDbForRemoteAccess(ctx, st, id, claims.Sub)
	if err != nil {
		return err
	}
	name, serverID := row.A, row.D
	if serverID == nil {
		return apiErr(http.StatusConflict, "Database is not associated with a server")
	}
	agent, err := agentForSiteServer(ctx, st, serverID, "database "+name)
	if err != nil {
		return err
	}

	proxy, err := queryOpt[Tup3[uuid.UUID, string, int32]](ctx, st.DB,
		"SELECT id, name, listen_port FROM tcp_proxies WHERE database_id = $1 AND server_id = $2", id, *serverID)
	if err != nil {
		return internalError("lookup database tcp proxy", err)
	}
	if proxy == nil {
		return apiErr(http.StatusNotFound, "Remote access is not enabled for this database")
	}
	pid, pname, pport := proxy.A, proxy.B, proxy.C

	// File + firewall first, row last — the row is the record of an open port.
	if _, err := agent.Delete(ctx, fmt.Sprintf("/nginx/streams/%s?listen_port=%d", pname, pport)); err != nil {
		return agentError("Database remote access removal", err)
	}
	if _, err := execSQL(ctx, st.DB, "DELETE FROM tcp_proxies WHERE id = $1", pid); err != nil {
		return internalError("delete database tcp proxy", err)
	}

	slog.Info(fmt.Sprintf("Database remote access disabled: %s (port %d)", name, pport))
	ActivityLogActivityOnServer(ctx, st.DB, claims.Sub, claims.Email, "database.remote_access_disabled",
		new("database"), new(name), new(fmt.Sprintf("port %d", pport)), nil, serverID, claims.KeyID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": pname})
	return nil
}
