package routes

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/moby/moby/client"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// DatabaseCreateDbRequest is POST /databases.
type DatabaseCreateDbRequest struct {
	Name     string  `json:"name"`
	Engine   string  `json:"engine"`
	Password string  `json:"password"`
	Port     *uint16 `json:"port"`
	// GH #64: when set, the container joins this stack's own private network
	// instead of the shared dockpanel-db bridge.
	StackID *string `json:"stack_id"`
}

// DatabaseQueryDbRequest is POST /databases/query.
type DatabaseQueryDbRequest struct {
	Container string `json:"container"`
	Engine    string `json:"engine"`
	User      string `json:"user"`
	Password  string `json:"password"`
	Database  string `json:"database"`
	Sql       string `json:"sql"`
}

// DatabaseResetPasswordRequest is POST /databases/reset-password.
type DatabaseResetPasswordRequest struct {
	Container   string `json:"container"`
	Engine      string `json:"engine"`
	User        string `json:"user"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func registerDatabase(r *Router) {
	r.Handle("POST /databases", databaseCreate)
	r.Handle("GET /databases", databaseList)
	r.Handle("POST /databases/query", databaseQueryDb)
	r.Handle("POST /databases/reset-password", databaseResetPassword)
	r.Handle("DELETE /databases/{container_id}", databaseRemove)
}

func databaseEngineOK(e string) bool { return e == "mysql" || e == "mariadb" || e == "postgres" }

// databasePasswordOK: non-empty, ≤128 bytes, no CR/LF/NUL.
func databasePasswordOK(pw string) bool {
	return pw != "" && len(pw) <= 128 && !strings.ContainsAny(pw, "\n\r\x00")
}

// databaseContainerOK: only dockpanel-db-<valid name>.
func databaseContainerOK(c string) bool {
	suffix, ok := strings.CutPrefix(c, "dockpanel-db-")
	return ok && isValidName(suffix)
}

// databaseFindFreePort finds a port using both a TCP bind check AND the ports
// Docker containers already publish, to avoid races.
func databaseFindFreePort(ctx context.Context, engine string) (uint16, error) {
	base := uint16(3307)
	if engine == "postgres" {
		base = 5433
	}
	used := map[uint16]bool{}
	if docker, err := client.New(client.FromEnv); err == nil {
		if res, err := docker.ContainerList(ctx, client.ContainerListOptions{All: true}); err == nil {
			for _, c := range res.Items {
				for _, p := range c.Ports {
					if p.PublicPort != 0 {
						used[p.PublicPort] = true
					}
				}
			}
		}
		docker.Close()
	}
	for port := base; port < base+100; port++ {
		if used[port] {
			continue
		}
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			l.Close()
			return port, nil
		}
	}
	return 0, fmt.Errorf("No free port available for database")
}

// databaseCreate: POST /databases — create a database container.
func databaseCreate(w http.ResponseWriter, r *http.Request) {
	var body DatabaseCreateDbRequest
	if !securityDecodeStrict(w, r, &body, "name", "engine", "password") {
		return
	}
	if !isValidName(body.Name) {
		writeErr(w, http.StatusBadRequest, "Invalid database name")
		return
	}
	if !databaseEngineOK(body.Engine) {
		writeErr(w, http.StatusBadRequest, "Engine must be mysql, mariadb, or postgres")
		return
	}
	if !databasePasswordOK(body.Password) {
		writeErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	var port uint16
	if body.Port != nil {
		port = *body.Port
	} else {
		p, err := databaseFindFreePort(r.Context(), body.Engine)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		port = p
	}
	db, err := services.DatabaseCreateDatabase(r.Context(), body.Name, body.Engine, body.Password, port, body.StackID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "container_id": db.ContainerID, "name": db.Name, "port": db.Port, "engine": db.Engine,
	})
}

// databaseRemove: DELETE /databases/{container_id}.
func databaseRemove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("container_id")
	if !isValidContainerID(id) {
		writeErr(w, http.StatusBadRequest, "Invalid container ID")
		return
	}
	if err := services.DatabaseRemoveDatabase(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// databaseList: GET /databases — list managed database containers.
func databaseList(w http.ResponseWriter, r *http.Request) {
	dbs, err := services.DatabaseListDatabases(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, dbs)
}

// databaseQueryDb: POST /databases/query — run SQL inside a database container.
func databaseQueryDb(w http.ResponseWriter, r *http.Request) {
	var body DatabaseQueryDbRequest
	if !securityDecodeStrict(w, r, &body, "container", "engine", "user", "password", "database", "sql") {
		return
	}
	switch {
	case len(body.Sql) > 10_000:
		writeErr(w, http.StatusBadRequest, "Query too long (max 10KB)")
	case strings.TrimSpace(body.Sql) == "":
		writeErr(w, http.StatusBadRequest, "Query is empty")
	case !databaseContainerOK(body.Container):
		writeErr(w, http.StatusBadRequest, "Invalid container name")
	case !databaseEngineOK(body.Engine):
		writeErr(w, http.StatusBadRequest, "Engine must be mysql, mariadb, or postgres")
	case !isValidName(body.User):
		writeErr(w, http.StatusBadRequest, "Invalid username")
	case !isValidName(body.Database):
		writeErr(w, http.StatusBadRequest, "Invalid database name")
	case !databasePasswordOK(body.Password):
		writeErr(w, http.StatusBadRequest, "Invalid password")
	default:
		res, err := services.DatabaseExecuteQuery(body.Container, body.Engine, body.User, body.Password, body.Database, body.Sql)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// serde_json::json! — keys come out sorted, as a Go map's do.
		writeJSON(w, http.StatusOK, map[string]any{
			"columns": res.Columns, "rows": res.Rows, "row_count": res.RowCount,
			"execution_time_ms": res.ExecutionTimeMs, "truncated": res.Truncated,
		})
	}
}

// databaseResetPassword: POST /databases/reset-password.
func databaseResetPassword(w http.ResponseWriter, r *http.Request) {
	var body DatabaseResetPasswordRequest
	if !securityDecodeStrict(w, r, &body, "container", "engine", "user", "old_password", "new_password") {
		return
	}
	switch {
	case !databaseContainerOK(body.Container):
		writeErr(w, http.StatusBadRequest, "Invalid container name")
		return
	case !databaseEngineOK(body.Engine):
		writeErr(w, http.StatusBadRequest, "Engine must be mysql, mariadb, or postgres")
		return
	case !isValidName(body.User):
		writeErr(w, http.StatusBadRequest, "Invalid username")
		return
	}
	for _, p := range [][2]string{{"old_password", body.OldPassword}, {"new_password", body.NewPassword}} {
		if !databasePasswordOK(p[1]) {
			writeErr(w, http.StatusBadRequest, "Invalid "+p[0])
			return
		}
	}
	if err := services.DatabaseResetPassword(body.Container, body.Engine, body.User, body.OldPassword, body.NewPassword); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}
