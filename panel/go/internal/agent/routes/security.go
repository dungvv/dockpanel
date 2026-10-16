package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

func registerSecurity(r *Router) {
	r.Handle("GET /security/overview", securityOverview)
	r.Handle("GET /security/firewall", securityFirewallStatus)
	r.Handle("POST /security/firewall/rules", securityAddRule)
	r.Handle("DELETE /security/firewall/rules/{number}", securityDeleteRule)
	r.Handle("GET /security/fail2ban", securityFail2banStatus)
	r.Handle("POST /security/scan", securityRunScan)
	r.Handle("POST /security/ssh/disable-password", securitySshAction(services.SecurityDisableSshPasswordAuth))
	r.Handle("POST /security/ssh/enable-password", securitySshAction(services.SecurityEnableSshPasswordAuth))
	r.Handle("POST /security/ssh/disable-root", securitySshAction(services.SecurityDisableSshRootLogin))
	r.Handle("POST /security/ssh/change-port", securitySshChangePort)
	r.Handle("POST /security/fail2ban/unban", securityBanHandler(services.SecurityFail2banUnban))
	r.Handle("POST /security/fail2ban/ban", securityBanHandler(services.SecurityFail2banBan))
	r.Handle("GET /security/fail2ban/{jail}/banned", securityFail2banBanned)
	r.Handle("POST /security/fix", securityApplyFix)
	r.Handle("GET /security/login-audit", securityLoginAudit)
	r.Handle("POST /security/panel-jail/setup", securitySetupPanelJail)
	r.Handle("GET /security/panel-jail/status", securityPanelJailStatus)
	// Security hardening (post-incident features)
	r.Handle("POST /security/kill-terminals", securityKillTerminals)
	r.Handle("GET /security/forensic-snapshot", securityForensicSnapshot)
	r.Handle("POST /security/db-backup", securityDbBackup)
	r.Handle("POST /security/canary/setup", securityCanarySetup)
}

var securitySuccess = map[string]bool{"success": true}

// securityDecodeStrict is decodeJSON plus serde's refusal of a missing/null
// non-Option field (Go's decoder would zero-fill it): 422 like axum. A JSON
// array body checks every element.
func securityDecodeStrict(w http.ResponseWriter, r *http.Request, v any, required ...string) bool {
	var raw json.RawMessage
	if !decodeJSON(w, r, &raw) {
		return false
	}
	fail := func(msg string) bool {
		http.Error(w, "Failed to deserialize the JSON body into the target type: "+msg, http.StatusUnprocessableEntity)
		return false
	}
	var objs []map[string]json.RawMessage
	if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] == '[' {
		if err := json.Unmarshal(raw, &objs); err != nil {
			return fail(err.Error())
		}
	} else {
		var o map[string]json.RawMessage
		if err := json.Unmarshal(raw, &o); err != nil || o == nil {
			return fail("invalid type: expected a JSON object")
		}
		objs = append(objs, o)
	}
	for _, o := range objs {
		for _, k := range required {
			if val, ok := o[k]; !ok || string(bytes.TrimSpace(val)) == "null" {
				return fail(fmt.Sprintf("missing field `%s`", k))
			}
		}
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fail(err.Error())
	}
	return true
}

// securityChronoRfc3339 matches chrono's Utc::now().to_rfc3339(): "+00:00"
// offset and 0/3/6/9 fractional digits (SecondsFormat::AutoSi).
func securityChronoRfc3339(t time.Time) string {
	t = t.UTC()
	ns := t.Nanosecond()
	frac := ""
	switch {
	case ns == 0:
	case ns%1_000_000 == 0:
		frac = fmt.Sprintf(".%03d", ns/1_000_000)
	case ns%1_000 == 0:
		frac = fmt.Sprintf(".%06d", ns/1_000)
	default:
		frac = fmt.Sprintf(".%09d", ns)
	}
	return t.Format("2006-01-02T15:04:05") + frac + "+00:00"
}

func securityOverview(w http.ResponseWriter, _ *http.Request) {
	o, err := services.SecurityGetSecurityOverview()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func securityFirewallStatus(w http.ResponseWriter, _ *http.Request) {
	st, err := services.SecurityGetFirewallStatus()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// securityStatusFor maps a firewall/fix service error to a status: a refusal
// the caller can act on, or a fault only an incident id should describe.
// Matching the named constant (not ad-hoc substrings, which each recognised
// only the refusal its author had in mind) keeps the ufw-missing case — every
// RHEL box — out of the 5xx arm.
func securityStatusFor(e string) int {
	switch {
	case e == services.SecurityUfwMissing:
		return http.StatusFailedDependency
	case strings.HasPrefix(e, "Invalid"), strings.Contains(e, "must be"),
		strings.HasPrefix(e, "Can only"), strings.HasPrefix(e, "Unknown fix type"):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func securityAddRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Port   uint16  `json:"port"`
		Proto  string  `json:"proto"`
		Action string  `json:"action"`
		From   *string `json:"from"`
	}
	if !securityDecodeStrict(w, r, &body, "port", "proto", "action") {
		return
	}
	if err := services.SecurityAddFirewallRule(body.Port, body.Proto, body.Action, body.From); err != nil {
		writeErr(w, securityStatusFor(err.Error()), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, securitySuccess)
}

func securityDeleteRule(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("number")
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid URL: Cannot parse `%s` to a `u64`", raw), http.StatusBadRequest)
		return
	}
	if err := services.SecurityRemoveFirewallRule(int(min(n, 1<<62))); err != nil {
		writeErr(w, securityStatusFor(err.Error()), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, securitySuccess)
}

func securityFail2banStatus(w http.ResponseWriter, _ *http.Request) {
	st, err := services.SecurityGetFail2banStatus()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// securityRunScan: POST /security/scan — full security scan.
func securityRunScan(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, services.SecurityScannerRunFullScan())
}

func securitySshAction(f func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if err := f(); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, securitySuccess)
	}
}

func securitySshChangePort(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Port uint16 `json:"port"`
	}
	if !securityDecodeStrict(w, r, &body, "port") {
		return
	}
	if err := services.SecurityChangeSshPort(body.Port); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, securitySuccess)
}

func securityBanHandler(f func(jail, ip string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Jail string `json:"jail"`
			IP   string `json:"ip"`
		}
		if !securityDecodeStrict(w, r, &body, "jail", "ip") {
			return
		}
		if err := f(body.Jail, body.IP); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, securitySuccess)
	}
}

func securityFail2banBanned(w http.ResponseWriter, r *http.Request) {
	ips, err := services.SecurityFail2banBannedIps(r.PathValue("jail"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ips": ips})
}

func securityApplyFix(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FixType string `json:"fix_type"`
		Target  string `json:"target"`
	}
	if !securityDecodeStrict(w, r, &body, "fix_type", "target") {
		return
	}
	msg, err := services.SecurityApplyFix(body.FixType, body.Target)
	if err != nil {
		writeErr(w, securityStatusFor(err.Error()), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": msg})
}

// securityLoginAudit: GET /security/login-audit — recent SSH logins.
func securityLoginAudit(w http.ResponseWriter, _ *http.Request) {
	entries, err := services.SecurityGetLoginAudit()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func securitySetupPanelJail(w http.ResponseWriter, _ *http.Request) {
	if err := services.SecuritySetupPanelJail(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, securitySuccess)
}

func securityPanelJailStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"active": services.SecurityPanelJailStatus()})
}

// securityKillTerminals: POST /security/kill-terminals (panic button).
//
// Kills the shells this agent actually started, from the registry, rather
// than guessing by user and command name: `pkill -u www-data` alone never
// reached a SERVER terminal, which runs as root on purpose — the shell an
// intruder is most likely holding. Root kills are counted separately because
// that is the fact an operator needs during an incident.
func securityKillTerminals(w http.ResponseWriter, _ *http.Request) {
	TerminalPidsMu.Lock()
	pids := TerminalPids
	TerminalPids = nil
	TerminalPidsMu.Unlock()

	var killed, rootKilled uint32
	for _, p := range pids {
		// SIGKILL, not SIGTERM: a shell that ignores the polite signal is
		// exactly the one worth worrying about.
		if syscall.Kill(int(p.Pid), syscall.SIGKILL) == nil {
			killed++
			if p.IsRoot {
				rootKilled++
			}
		}
	}

	// Backstop for anything spawned inside a site shell that outlived its
	// parent. Deliberately still scoped to bash: every www-data process would
	// take PHP-FPM down with it.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, _ = safecmd.Exec(ctx, "pkill", "-u", "www-data", "-f", "bash")
	cancel()

	// Every registered shell is gone, so zero is fact, not decree. It used to
	// be zeroed WITHOUT the kill, handing an attacker a fresh session quota.
	TerminalActiveTerminals.Store(0)

	slog.Warn(fmt.Sprintf("PANIC: killed %d of %d registered terminal sessions (%d server/root)", killed, len(pids), rootKilled))
	writeJSON(w, http.StatusOK, map[string]any{
		"killed":                  killed,
		"registered":              len(pids),
		"server_terminals_killed": rootKilled,
	})
}

func securityCapture(bin string, args ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, bin, args...)
	if err != nil {
		return nil
	}
	return []byte(strings.ToValidUTF8(string(out.Stdout), "�"))
}

// securityForensicSnapshot: GET /security/forensic-snapshot — capture system
// state for forensics.
func securityForensicSnapshot(w http.ResponseWriter, _ *http.Request) {
	dir := "/var/lib/dockpanel/forensics/snapshot-" + time.Now().UTC().Format("20060102_150405")
	_ = os.MkdirAll(dir, 0o755)
	save := func(name string, b []byte) { _ = os.WriteFile(filepath.Join(dir, name), b, 0o644) }

	save("processes.txt", securityCapture("ps", "auxf"))
	save("network.txt", securityCapture("ss", "-tulnp"))
	save("connections.txt", securityCapture("ss", "-tnp"))
	save("open_files.txt", securityCapture("lsof", "-nP", "+L1"))
	save("journal.txt", securityCapture("journalctl", "--since", "1 hour ago", "--no-pager", "-q"))
	save("who.txt", securityCapture("who"))
	save("last.txt", securityCapture("last", "-20"))
	passwd, _ := os.ReadFile("/etc/passwd")
	save("etc_passwd.txt", passwd)
	var recs []string
	if ents, err := os.ReadDir("/var/lib/dockpanel/recordings"); err == nil {
		for _, e := range ents {
			recs = append(recs, e.Name())
		}
	}
	save("active_recordings.txt", []byte(strings.Join(recs, "\n")))

	slog.Info("Forensic snapshot captured at " + dir)
	writeJSON(w, http.StatusOK, map[string]any{
		"snapshot_dir": dir,
		"timestamp":    securityChronoRfc3339(time.Now()),
		"files": []string{"processes.txt", "network.txt", "connections.txt", "open_files.txt", "journal.txt",
			"who.txt", "last.txt", "etc_passwd.txt", "active_recordings.txt"},
	})
}

// securityDbBackup: POST /security/db-backup — dump DockPanel's own
// PostgreSQL database.
func securityDbBackup(w http.ResponseWriter, r *http.Request) {
	const backupDir = "/var/backups/dockpanel"
	_ = os.MkdirAll(backupDir, 0o755)
	// The dump is the panel's entire database — users, sessions, api_keys and
	// servers.agent_token in cleartext. Root only; MkdirAll leaves 0755.
	_ = os.Chmod(backupDir, 0o700)
	filename := fmt.Sprintf("%s/dockpanel-db-%s.sql.gz", backupDir, time.Now().UTC().Format("20060102_150405"))

	// pg_dump via docker exec, then gzip via stdin/stdout — no shell.
	// The Rust original had no timeout; the request context bounds it here.
	ctx := r.Context()
	dump, err := safecmd.Exec(ctx, "docker", "exec", "dockpanel-postgres", "pg_dump", "-U", "dockpanel", "dockpanel")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("pg_dump failed: %v", err))
		return
	}
	if !dump.Success() {
		writeErr(w, http.StatusInternalServerError, "pg_dump failed: "+strings.ToValidUTF8(string(dump.Stderr), "�"))
		return
	}
	gz := safecmd.Command(ctx, "gzip", "-c")
	gz.Stdin = bytes.NewReader(dump.Stdout)
	gzOut, err := safecmd.Run(ctx, gz)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("gzip wait: %v", err))
		return
	}
	if !gzOut.Success() {
		writeErr(w, http.StatusInternalServerError, "gzip compression failed")
		return
	}

	// Created 0600 BEFORE a byte is written: a default create would leave a
	// window with a full panel DB dump world-readable on a box that also
	// serves other people's PHP.
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("write backup: %v", err))
		return
	}
	_, err = f.Write(gzOut.Stdout)
	f.Close()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("write backup: %v", err))
		return
	}

	// Keep the newest 7 dumps.
	if ents, err := os.ReadDir(backupDir); err == nil {
		var names []string
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "dockpanel-db-") {
				names = append(names, e.Name())
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		for _, n := range names[min(len(names), 7):] {
			_ = os.Remove(filepath.Join(backupDir, n))
		}
	}

	var size int64
	if st, err := os.Stat(filename); err == nil {
		size = st.Size()
	}
	slog.Info(fmt.Sprintf("DockPanel DB backup created: %s (%d bytes)", filename, size))
	writeJSON(w, http.StatusOK, map[string]any{
		"filename":   filename,
		"size_bytes": size,
		"timestamp":  securityChronoRfc3339(time.Now()),
	})
}

// (A one-shot hardening initialiser that used to live here was removed: it
// had no caller, and its only unique act — append-only on the audit
// DIRECTORY — still allowed O_TRUNC rewrites while blocking the retention
// sweep's unlink. A regression check greps for its route path; do not write
// that literal here.)

// SecurityCanaryPlantPaths: where a canary can actually be planted.
//
// The old /etc, /root, /home set could never be written: the unit runs
// ProtectSystem=strict with explicit ReadWritePaths (EROFS elsewhere) and
// ProtectHome=yes — and the endpoint reported success anyway. These are
// inside ReadWritePaths (the agent can plant them) and outside ProtectHome
// (the API process can stat them on its tick). Three are where this product
// keeps its own secrets, which is where someone hunting credentials goes
// first.
var SecurityCanaryPlantPaths = [4][2]string{
	{"/etc/dockpanel/.dockpanel-canary", "Panel credential directory canary"},
	{"/var/lib/dockpanel/.dockpanel-canary", "Panel state directory canary"},
	{"/var/backups/dockpanel/.dockpanel-canary", "Panel database backup canary"},
	{"/var/www/.dockpanel-canary", "Web root canary"},
}

// securityCanarySetup: POST /security/canary/setup. Answers per path; a
// refusal is reported, never swallowed.
func securityCanarySetup(w http.ResponseWriter, _ *http.Request) {
	created, refused := []map[string]string{}, []map[string]string{}
	for _, pd := range SecurityCanaryPlantPaths {
		path, desc := pd[0], pd[1]
		content := "DOCKPANEL CANARY FILE — DO NOT TOUCH\nCreated: " + securityChronoRfc3339(time.Now()) +
			"\nPurpose: Intrusion detection tripwire\nIf you are reading this, security has been alerted.\n"
		// The parent need not exist yet (/var/backups/dockpanel is made by
		// the DB backup task, which may never have run).
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		// Re-arming must work: the previous canary is 0444.
		_ = os.Remove(path)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			slog.Warn(fmt.Sprintf("Canary file %s could NOT be created: %v", path, err))
			refused = append(refused, map[string]string{"path": path, "description": desc, "reason": securityIoReason(err)})
			continue
		}
		// Readable by all (the intruder must read it) but writable by none.
		_ = os.Chmod(path, 0o444)
		created = append(created, map[string]string{"path": path, "description": desc})
		slog.Info("Canary file created: " + path)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"created": created,
		"refused": refused,
		"armed":   len(created),
		"total":   len(SecurityCanaryPlantPaths),
	})
}

// securityIoReason renders an fs error like Rust's io::Error Display
// ("Read-only file system (os error 30)").
func securityIoReason(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		msg := errno.Error()
		if msg != "" {
			msg = strings.ToUpper(msg[:1]) + msg[1:]
		}
		return fmt.Sprintf("%s (os error %d)", msg, int(errno))
	}
	return err.Error()
}
