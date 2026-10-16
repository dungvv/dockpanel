package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
)

const databaseDbNetwork = "dockpanel-db"

// DatabaseDbContainer is one managed database container.
type DatabaseDbContainer struct {
	ContainerID string `json:"container_id"`
	Name        string `json:"name"`
	Port        uint16 `json:"port"`
	Engine      string `json:"engine"`
	Status      string `json:"status"`
}

func databaseDocker() (*client.Client, error) {
	docker, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("Docker connect failed: %v", err)
	}
	return docker, nil
}

func databaseIsMysql(engine string) bool { return engine == "mysql" || engine == "mariadb" }

// DatabaseCreateDatabase creates a database container (MySQL/MariaDB or
// PostgreSQL).
//
// stackID, when set (GH #64: standalone DB for a Docker Stack), puts the
// container on that stack's OWN private bridge network instead of the shared,
// ICC-disabled dockpanel-db bridge. Host-port publishing doesn't care which
// bridge the container is on, and every panel-side operation reaches it via
// `docker exec`, so nothing else changes; a stack's network is single-tenant
// by construction, so this adds no cross-tenant exposure.
func DatabaseCreateDatabase(ctx context.Context, name, engine, password string, port uint16, stackID *string) (DatabaseDbContainer, error) {
	docker, err := databaseDocker()
	if err != nil {
		return DatabaseDbContainer{}, err
	}
	defer docker.Close()

	var networkMode string
	if stackID != nil {
		networkMode = ComposeStackNetworkName(stackID)
		if err := ComposeEnsureStackNetwork(ctx, docker, networkMode, stackID); err != nil {
			return DatabaseDbContainer{}, err
		}
	} else {
		// The shared DB bridge must exist AND have ICC disabled (H2: block
		// cross-tenant lateral movement between DB containers).
		if err := databaseEnsureNetwork(ctx, docker); err != nil {
			return DatabaseDbContainer{}, err
		}
		networkMode = databaseDbNetwork
	}

	// M1: postgres's bootstrap superuser gets a random, immediately-discarded
	// password; the tenant NEVER connects as superuser — a NON-superuser owner
	// role named {name} is provisioned after start.
	adminPassword := strings.ReplaceAll(uuid.NewString(), "-", "")

	var image, containerPort string
	var env []string
	if databaseIsMysql(engine) {
		image, containerPort = "mariadb:11", "3306/tcp"
		env = []string{
			"MYSQL_DATABASE=" + name, "MYSQL_USER=" + name,
			"MYSQL_PASSWORD=" + password, "MYSQL_RANDOM_ROOT_PASSWORD=yes",
		}
	} else {
		image, containerPort = "postgres:16-alpine", "5432/tcp"
		// POSTGRES_USER is deliberately NOT {name}: that made the tenant the
		// cluster SUPERUSER (M1: COPY..TO PROGRAM RCE foothold).
		env = []string{"POSTGRES_DB=" + name, "POSTGRES_PASSWORD=" + adminPassword}
	}

	// Pull image if needed; failures are warnings (a local image still works).
	if pull, err := docker.ImagePull(ctx, image, client.ImagePullOptions{}); err != nil {
		slog.Warn(fmt.Sprintf("Image pull warning: %v", err))
	} else {
		for _, err := range pull.JSONMessages(ctx) {
			if err != nil {
				slog.Warn(fmt.Sprintf("Image pull warning: %v", err))
			}
		}
		pull.Close()
	}

	containerName := "dockpanel-db-" + name
	cport := network.MustParsePort(containerPort)
	labels := map[string]string{
		"dockpanel.managed":   "true",
		"dockpanel.db.name":   name,
		"dockpanel.db.engine": engine,
	}
	// For operator visibility only: stack teardown removes this container by
	// databases.stack_id, not by label.
	if stackID != nil {
		labels["dockpanel.stack_id"] = *stackID
	}
	created, err := docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: containerName,
		Config: &container.Config{
			Image:        image,
			Env:          env,
			ExposedPorts: network.PortSet{cport: {}},
			Labels:       labels,
		},
		HostConfig: &container.HostConfig{
			PortBindings:  network.PortMap{cport: {{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: strconv.Itoa(int(port))}}},
			NetworkMode:   container.NetworkMode(networkMode),
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
			Resources: container.Resources{
				Memory: 256 * 1024 * 1024,
				// 2 cores, like app containers, so one tenant's heavy query/dump
				// cannot starve co-tenants on the shared host.
				CPUPeriod: 100_000,
				CPUQuota:  200_000,
			},
		},
	})
	if err != nil {
		return DatabaseDbContainer{}, fmt.Errorf("Failed to create container: %v", err)
	}
	removeIt := func() {
		// The engine's data dir is an anonymous image VOLUME; take it too.
		_, _ = docker.ContainerRemove(context.Background(), created.ID, client.ContainerRemoveOptions{RemoveVolumes: true, Force: true})
	}
	if _, err := docker.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		removeIt()
		return DatabaseDbContainer{}, fmt.Errorf("Failed to start container: %v", err)
	}

	// M1: provision the NON-superuser postgres tenant owner. Without it the
	// container has no usable tenant login, so tear it down and surface the
	// error. MariaDB is already DB-scoped/non-root.
	if !databaseIsMysql(engine) {
		if err := databaseProvisionPostgresTenantRole(containerName, name, adminPassword, password); err != nil {
			removeIt()
			return DatabaseDbContainer{}, err
		}
	}

	slog.Info(fmt.Sprintf("Database container created: %s (%s, port %d)", containerName, engine, port))
	return DatabaseDbContainer{ContainerID: created.ID, Name: containerName, Port: port, Engine: engine, Status: "running"}, nil
}

// DatabaseRemoveDatabase removes a database container.
//
// Refuses a container this module didn't create (dockpanel.managed=true) —
// defense in depth, the same boundary every other destructive-by-id surface
// carries: a stray unmanaged container would otherwise be force-removed with
// its volumes.
func DatabaseRemoveDatabase(ctx context.Context, containerID string) error {
	docker, err := databaseDocker()
	if err != nil {
		return err
	}
	defer docker.Close()
	info, err := docker.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return fmt.Errorf("Failed to inspect container: %v", err)
	}
	if cfg := info.Container.Config; cfg == nil || cfg.Labels["dockpanel.managed"] != "true" {
		return errors.New("not a dockpanel-managed container")
	}
	t := 10
	_, _ = docker.ContainerStop(ctx, containerID, client.ContainerStopOptions{Timeout: &t}) // ignore if already stopped
	if _, err := docker.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{RemoveVolumes: true, Force: true}); err != nil {
		return fmt.Errorf("Failed to remove container: %v", err)
	}
	slog.Info("Database container removed: " + containerID)
	return nil
}

// DatabaseListDatabases lists all DockPanel-managed database containers.
func DatabaseListDatabases(ctx context.Context) ([]DatabaseDbContainer, error) {
	docker, err := databaseDocker()
	if err != nil {
		return nil, err
	}
	defer docker.Close()
	res, err := docker.ContainerList(ctx, client.ContainerListOptions{
		All: true, Filters: make(client.Filters).Add("label", "dockpanel.managed=true"),
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to list containers: %v", err)
	}
	dbs := []DatabaseDbContainer{}
	for _, c := range res.Items {
		if _, ok := c.Labels["dockpanel.db.name"]; !ok {
			continue
		}
		engine, ok := c.Labels["dockpanel.db.engine"]
		if !ok || c.ID == "" {
			continue
		}
		var port uint16
		if len(c.Ports) > 0 {
			port = c.Ports[0].PublicPort
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimLeft(c.Names[0], "/")
		}
		dbs = append(dbs, DatabaseDbContainer{ContainerID: c.ID, Name: name, Port: port, Engine: engine, Status: string(c.State)})
	}
	return dbs, nil
}

// DatabaseQueryResult is a SQL query's result.
type DatabaseQueryResult struct {
	Columns         []string   `json:"columns"`
	Rows            [][]string `json:"rows"`
	RowCount        int        `json:"row_count"`
	ExecutionTimeMs uint64     `json:"execution_time_ms"`
	Truncated       bool       `json:"truncated"`
}

const (
	databaseMaxRows         = 1000
	databaseQueryTimeout    = 15 * time.Second
	databaseQueryTimeoutSec = 15
	databaseMaxOutputBytes  = 5 * 1024 * 1024
)

// databaseEnvFile puts the credential in a --env-file, NOT `-e KEY=value`
// (literal docker argv, world-readable via ps for the child's life).
func databaseEnvFile(engine, password string) (*safecmd.DockerEnvFile, error) {
	key := "PGPASSWORD"
	if databaseIsMysql(engine) {
		key = "MYSQL_PWD"
	}
	f, err := safecmd.NewDockerEnvFile([2]string{key, password})
	if err != nil {
		return nil, fmt.Errorf("Failed to prepare credentials: %v", err)
	}
	return f, nil
}

// DatabaseExecuteQuery executes SQL inside a database container via docker exec.
func DatabaseExecuteQuery(containerName, engine, user, password, database, sql string) (DatabaseQueryResult, error) {
	start := time.Now()
	envFile, err := databaseEnvFile(engine, password)
	if err != nil {
		return DatabaseQueryResult{}, err
	}
	defer envFile.Close()
	args := []string{"exec", "--env-file", envFile.Path(), containerName}
	if databaseIsMysql(engine) {
		args = append(args, "mariadb", "-u", user, database, "-e", sql, "--batch", "--column-names")
	} else {
		args = append(args, "psql", "-U", user, "-d", database, "-c", sql, "--csv")
	}

	ctx, cancel := context.WithTimeout(context.Background(), databaseQueryTimeout)
	defer cancel()
	cmd := safecmd.Command(ctx, "docker", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return DatabaseQueryResult{}, fmt.Errorf("Failed to execute docker exec: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return DatabaseQueryResult{}, fmt.Errorf("Failed to execute docker exec: %v", err)
	}
	if err := cmd.Start(); err != nil {
		return DatabaseQueryResult{}, fmt.Errorf("Failed to execute docker exec: %v", err)
	}
	// Stream stdout with a HARD cap instead of buffering the whole result set:
	// a tenant could otherwise stream hundreds of MB into the shared agent and
	// OOM it. stderr is drained concurrently (bounded) to avoid a pipe-full
	// deadlock.
	errCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(io.LimitReader(stderrPipe, 64*1024))
		_, _ = io.Copy(io.Discard, stderrPipe)
		errCh <- b
	}()
	outBuf, readErr := io.ReadAll(io.LimitReader(stdout, databaseMaxOutputBytes+1))
	overflow := len(outBuf) > databaseMaxOutputBytes
	if overflow {
		_ = cmd.Process.Kill()
	}
	_, _ = io.Copy(io.Discard, stdout)
	errBuf := <-errCh
	waitErr := cmd.Wait()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return DatabaseQueryResult{}, fmt.Errorf("Query timed out (%ds limit)", databaseQueryTimeoutSec)
	}
	if readErr != nil {
		return DatabaseQueryResult{}, fmt.Errorf("read error: %v", readErr)
	}
	if overflow {
		return DatabaseQueryResult{}, fmt.Errorf("Query output too large (max %d MB)", databaseMaxOutputBytes/(1024*1024))
	}
	var ee *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &ee) {
		return DatabaseQueryResult{}, fmt.Errorf("docker exec wait error: %v", waitErr)
	}
	elapsed := uint64(time.Since(start).Milliseconds())
	if waitErr != nil {
		msg := strings.TrimSpace(backupsLossy(errBuf))
		if msg == "" {
			msg = strings.TrimSpace(backupsLossy(outBuf))
		}
		return DatabaseQueryResult{}, errors.New(msg)
	}
	text := backupsLossy(outBuf)
	var cols []string
	var rows [][]string
	if databaseIsMysql(engine) {
		cols, rows = databaseParseTsv(text)
	} else {
		cols, rows = databaseParseCsv(text)
	}
	truncated := len(rows) > databaseMaxRows
	if truncated {
		rows = rows[:databaseMaxRows]
	}
	return DatabaseQueryResult{Columns: cols, Rows: rows, RowCount: len(rows), ExecutionTimeMs: elapsed, Truncated: truncated}, nil
}

// databaseParseTsv parses tab-separated output (MariaDB --batch mode).
func databaseParseTsv(output string) ([]string, [][]string) {
	lines := LogsLines([]byte(output))
	if len(lines) == 0 || lines[0] == "" {
		return []string{}, [][]string{}
	}
	cols := strings.Split(lines[0], "\t")
	rows := [][]string{}
	for _, l := range lines[1:] {
		if l != "" {
			rows = append(rows, strings.Split(l, "\t"))
		}
	}
	return cols, rows
}

// databaseParseCsv parses PostgreSQL --csv output per RFC 4180 (quoted
// fields with embedded commas, newlines and doubled quotes).
func databaseParseCsv(output string) ([]string, [][]string) {
	records := [][]string{}
	var field strings.Builder
	record := []string{}
	inQuotes := false
	rs := []rune(output)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if inQuotes {
			if c == '"' {
				if i+1 < len(rs) && rs[i+1] == '"' {
					i++
					field.WriteRune('"')
				} else {
					inQuotes = false
				}
			} else {
				field.WriteRune(c)
			}
			continue
		}
		switch c {
		case '"':
			inQuotes = true
		case ',':
			record = append(record, field.String())
			field.Reset()
		case '\n':
			record = append(record, field.String())
			field.Reset()
			records = append(records, record)
			record = []string{}
		case '\r': // skip CR
		default:
			field.WriteRune(c)
		}
	}
	// Last field/record.
	if field.Len() > 0 || len(record) > 0 {
		record = append(record, field.String())
		allEmpty := true
		for _, f := range record {
			if f != "" {
				allEmpty = false
			}
		}
		if !allEmpty || len(record) > 1 {
			records = append(records, record)
		}
	}
	if len(records) == 0 {
		return []string{}, [][]string{}
	}
	// A PostgreSQL command tag (INSERT/UPDATE/…) is not CSV data.
	if len(records) == 1 && len(records[0]) == 1 {
		for _, p := range []string{"INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "TRUNCATE", "GRANT", "REVOKE"} {
			if strings.HasPrefix(records[0][0], p) {
				return []string{}, [][]string{}
			}
		}
	}
	return records[0], records[1:]
}

// databaseMysqlStringEscape escapes for a single-quoted MariaDB literal. The
// engines differ: MariaDB treats `\` as an escape, so it is doubled (first,
// so the ” from the quote pass is never re-escaped); PostgreSQL runs with
// standard_conforming_strings=on, where doubling would STORE two backslashes.
func databaseMysqlStringEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", "''")
}

// databasePgStringEscape escapes for a single-quoted PostgreSQL literal.
func databasePgStringEscape(s string) string { return strings.ReplaceAll(s, "'", "''") }

// DatabaseResetPassword resets a database user's password inside a running
// container. Both engines authenticate AS THE TENANT and let the server
// change its own account, so oldPassword decides whether the reset happens.
//
// ⚠ The MariaDB arm once connected as root with no credential, assuming
// unix-socket auth — never true of a container created here
// (MYSQL_RANDOM_ROOT_PASSWORD), so every reset died on ERROR 1045. `SET
// PASSWORD` needs no privilege beyond being the account.
//
// The exact flag and env spellings are deliberately not written in this
// comment: an e2e pin greps the tree for them.
func DatabaseResetPassword(containerName, engine, user, oldPassword, newPassword string) error {
	var args []string
	if databaseIsMysql(engine) {
		// SET PASSWORD with no FOR clause targets CURRENT_USER() — the same
		// '{user}'@'%' row the old ALTER USER named.
		sql := fmt.Sprintf("SET PASSWORD = PASSWORD('%s');", databaseMysqlStringEscape(newPassword))
		args = []string{containerName, "mariadb", "-u", user, "-e", sql}
	} else {
		// ⚠ Honest scope limit: postgres:16-alpine's pg_hba trusts loopback,
		// so oldPassword is decorative here. Not "fixed" by forcing a
		// non-loopback connection: the tenant boundary is the panel's
		// ownership check, and enforcing it here would break permanently once
		// a tenant changes their password in the SQL console.
		sql := fmt.Sprintf("ALTER USER \"%s\" WITH PASSWORD '%s';", strings.ReplaceAll(user, `"`, `""`), databasePgStringEscape(newPassword))
		args = []string{containerName, "psql", "-U", user, "-d", user, "-c", sql}
	}
	envFile, err := databaseEnvFile(engine, oldPassword)
	if err != nil {
		return err
	}
	defer envFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), databaseQueryTimeout)
	defer cancel()
	out, err := safecmd.Exec(ctx, "docker", append([]string{"exec", "--env-file", envFile.Path()}, args...)...)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("Password reset timed out (%ds limit)", databaseQueryTimeoutSec)
	}
	if err != nil {
		return fmt.Errorf("Failed to execute docker exec: %v", err)
	}
	if !out.Success() {
		stderr := strings.TrimSpace(backupsLossy(out.Stderr))
		// A rejected login means the panel's stored credential is stale (a
		// tenant can cause that via the SQL console); the bare "Access
		// denied" never says the panel is the stale party.
		if strings.Contains(stderr, "Access denied") || strings.Contains(stderr, "password authentication failed") {
			return fmt.Errorf("Password reset failed: the database rejected the current password stored by "+
				"the panel, so the two are out of sync (this happens if the password was "+
				"changed outside the panel, e.g. via the SQL console). Original error: %s", stderr)
		}
		return fmt.Errorf("Password reset failed: %s", stderr)
	}
	slog.Info(fmt.Sprintf("Database password reset for user '%s' in container '%s'", user, containerName))
	return nil
}

// databaseProvisionPostgresTenantRole provisions the NON-superuser tenant
// owner role (M1) once a fresh postgres container is up, as the bootstrap
// superuser over the in-container socket, after waiting for readiness.
func databaseProvisionPostgresTenantRole(containerName, dbName, adminPassword, tenantPassword string) error {
	envFile, err := safecmd.NewDockerEnvFile([2]string{"PGPASSWORD", adminPassword})
	if err != nil {
		return fmt.Errorf("Failed to prepare credentials: %v", err)
	}
	defer envFile.Close()

	ready := false
	for range 30 {
		time.Sleep(time.Second)
		out, err := safecmd.Exec(context.Background(), "docker", "exec", "--env-file", envFile.Path(), containerName,
			"psql", "-U", "postgres", "-d", dbName, "-c", "SELECT 1")
		if err == nil && out.Success() {
			ready = true
			break
		}
	}
	if !ready {
		return errors.New("PostgreSQL did not become ready within 30s")
	}
	sql := databaseTenantRoleSQL(dbName, tenantPassword)
	out, err := safecmd.Exec(context.Background(), "docker", "exec", "--env-file", envFile.Path(), containerName,
		"psql", "-U", "postgres", "-d", dbName, "-v", "ON_ERROR_STOP=1",
		"-c", sql[0], "-c", sql[1], "-c", sql[2])
	if err != nil {
		return fmt.Errorf("Failed to provision tenant role: %v", err)
	}
	if !out.Success() {
		return fmt.Errorf("Failed to provision tenant role: %s", strings.TrimSpace(backupsLossy(out.Stderr)))
	}
	return nil
}

// databaseTenantRoleSQL: create the role NOSUPERUSER (no COPY..TO PROGRAM /
// pg_read_server_files — the M1 RCE foothold), give it the database, and give
// it the public schema (PG15+ no longer grants PUBLIC CREATE). Identifiers
// are validated to [A-Za-z0-9_-] upstream; only the password needs escaping.
func databaseTenantRoleSQL(dbName, password string) [3]string {
	pw := strings.ReplaceAll(password, "'", "''")
	return [3]string{
		fmt.Sprintf("CREATE ROLE \"%s\" LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE;", dbName, pw),
		fmt.Sprintf("ALTER DATABASE \"%s\" OWNER TO \"%s\";", dbName, dbName),
		fmt.Sprintf("ALTER SCHEMA public OWNER TO \"%s\";", dbName),
	}
}

// databaseEnsureNetwork makes sure the shared dockpanel-db bridge exists AND
// has inter-container communication disabled. No consumer connects over this
// network (all use the 127.0.0.1-published port), so ICC off blocks a
// compromised tenant DB from reaching siblings (H2). Installs whose network
// predates ICC=false are reconciled (ICC is create-time immutable).
func databaseEnsureNetwork(ctx context.Context, docker *client.Client) error {
	res, err := docker.NetworkInspect(ctx, databaseDbNetwork, client.NetworkInspectOptions{})
	if err != nil {
		return databaseCreateDbNetworkAt(ctx, docker, databaseDbNetwork)
	}
	if res.Network.Options["com.docker.network.bridge.enable_icc"] == "false" {
		return nil
	}
	attached := make([]string, 0, len(res.Network.Containers))
	for id := range res.Network.Containers {
		attached = append(attached, id)
	}
	return databaseReconcileNetworkIccAt(ctx, docker, databaseDbNetwork, attached)
}

func databaseCreateDbNetworkAt(ctx context.Context, docker *client.Client, name string) error {
	if _, err := docker.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver:  "bridge",
		Options: map[string]string{"com.docker.network.bridge.enable_icc": "false"},
	}); err != nil {
		return fmt.Errorf("Failed to create network: %v", err)
	}
	slog.Info(fmt.Sprintf("Created Docker network: %s (enable_icc=false)", name))
	return nil
}

// databaseReconcileNetworkIccAt recreates the network with ICC disabled,
// reconnecting every attached container.
//
// Best-effort, not abort-on-first-failure: the network is already torn down,
// so a container the loop never REACHES has ZERO network attachment — a
// silent outage for a tenant who may have nothing to do with this request.
// Known residual: once this returns, the icc_off check short-circuits on every
// future call, so a container that failed to reconnect needs the manual
// command in the error.
func databaseReconcileNetworkIccAt(ctx context.Context, docker *client.Client, name string, attached []string) error {
	// Published 127.0.0.1 ports are re-established from HostConfig on reconnect.
	for _, cid := range attached {
		_, _ = docker.NetworkDisconnect(ctx, name, client.NetworkDisconnectOptions{Container: cid, Force: true})
	}
	if _, err := docker.NetworkRemove(ctx, name, client.NetworkRemoveOptions{}); err != nil {
		return fmt.Errorf("Failed to remove legacy DB network for ICC reconcile: %v", err)
	}
	if err := databaseCreateDbNetworkAt(ctx, docker, name); err != nil {
		return err
	}
	var failed []string
	for _, cid := range attached {
		if _, err := docker.NetworkConnect(ctx, name, client.NetworkConnectOptions{Container: cid, EndpointConfig: &network.EndpointSettings{}}); err != nil {
			slog.Error(fmt.Sprintf("Failed to reconnect %s to hardened DB network: %v", cid, err))
			failed = append(failed, cid)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("Reconciled %s to enable_icc=false, but %d of %d container(s) failed to "+
			"reconnect and are now offline (no network attached): %s. Reconnect manually: "+
			"`docker network connect %s <container>`.", name, len(failed), len(attached), strings.Join(failed, ", "), name)
	}
	slog.Info(fmt.Sprintf("Reconciled %s to enable_icc=false (%d container(s) reconnected)", name, len(attached)))
	return nil
}
