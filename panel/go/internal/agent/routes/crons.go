package routes

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

// CronsCronRequest is one cron as the panel sends it.
type CronsCronRequest struct {
	ID       string  `json:"id"`
	Command  string  `json:"command"`
	Schedule string  `json:"schedule"`
	Label    *string `json:"label"`
	// Enabled: whether this cron should be in the crontab. The panel sends
	// every cron of the site being synced, enabled or not, because the payload
	// is the authoritative statement of which lines this sync owns. Defaults
	// to true so an older panel still schedules what it sends.
	Enabled *bool `json:"enabled"`
}

func (c CronsCronRequest) enabled() bool { return c.Enabled == nil || *c.Enabled }

// CronsCronResult is the /crons/run response.
type CronsCronResult struct {
	Success  bool    `json:"success"`
	Output   *string `json:"output"`
	ExitCode *int    `json:"exit_code"`
}

const cronsCrontabMarker = "# dockpanel:"

func registerCrons(r *Router) {
	r.Handle("POST /crons/sync", cronsSync)
	r.Handle("POST /crons/run", cronsRun)
	r.Handle("GET /crons/list", cronsList)
	r.Handle("DELETE /crons/remove/{id}", cronsRemove)
}

// cronsSync: POST /crons/sync — write this site's crons to root's crontab.
//
// This sync owns ONLY the lines it was sent. It used to strip every
// `# dockpanel:` line (the marker is panel-wide) and re-add only the synced
// site, so one tenant editing their own cron silently removed every OTHER
// site's jobs box-wide while the panel kept listing them as enabled. The
// payload carries disabled crons too: a line is removed because its id was
// sent and is disabled, never because another site was synced.
func cronsSync(w http.ResponseWriter, r *http.Request) {
	var crons []CronsCronRequest
	if !securityDecodeStrict(w, r, &crons, "id", "command", "schedule") {
		return
	}
	// A FAILED read must not be mistaken for an empty crontab — a transient
	// `crontab -l` timeout used to replace root's whole crontab with one
	// site's jobs.
	existing, err := services.CrontabRead()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	owned := map[string]bool{}
	for _, c := range crons {
		owned[c.ID] = true
	}
	lines := []string{}
	for _, l := range services.LogsLines([]byte(existing)) {
		if id, ok := cronsMarkerID(l); !ok || !owned[id] {
			lines = append(lines, l)
		}
	}

	// A row that fails validation is SKIPPED, not fatal to the whole sync:
	// the panel's own WordPress auto-cron once carried `> /dev/null 2>&1`
	// (blocked by the filter) and a 400-the-batch policy then broke every
	// cron edit on that box forever. Skipping keeps the guard exactly as
	// strong — the command still never reaches the crontab.
	skipped := []string{}
	disabled := 0
	for _, c := range crons {
		if !c.enabled() {
			disabled++ // its line was already dropped above
			continue
		}
		label := ""
		if c.Label != nil {
			label = *c.Label
		}
		why := ""
		switch {
		case !cronsIsValidSchedule(c.Schedule):
			why = fmt.Sprintf("invalid schedule %q", c.Schedule)
		case c.Command == "":
			why = "empty command"
		case !services.CommandFilterIsSafeCronCommand(c.Command):
			why = "command contains disallowed characters or patterns"
		// Not in the Rust original: id and label are written verbatim into
		// root's crontab, so a line break in either would start a new,
		// unfiltered crontab line run as root.
		case strings.ContainsAny(c.ID+label, "\n\r\x00"):
			why = "id or label contains a line break"
		}
		if why != "" {
			slog.Warn(fmt.Sprintf("Cron %s skipped during sync: %s", c.ID, why))
			skipped = append(skipped, c.ID)
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %s %s%s %s", c.Schedule, c.Command, cronsCrontabMarker, c.ID, label))
	}

	if err := services.CrontabWrite(strings.Join(lines, "\n")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	synced := len(crons) - len(skipped) - disabled
	if len(skipped) == 0 {
		slog.Info(fmt.Sprintf("Synced %d cron jobs to system crontab", synced))
	} else {
		slog.Warn(fmt.Sprintf("Synced %d cron jobs; %d skipped as unsafe and NOT scheduled: %s",
			synced, len(skipped), strings.Join(skipped, ", ")))
	}
	// Report skips: a job visible in the UI but absent from the crontab is
	// the shape that never runs and never says why.
	writeJSON(w, http.StatusOK, map[string]any{"synced": synced, "skipped": skipped})
}

// cronsRun: POST /crons/run — execute a cron command now, return output.
func cronsRun(w http.ResponseWriter, r *http.Request) {
	var body CronsCronRequest
	if !securityDecodeStrict(w, r, &body, "id", "command", "schedule") {
		return
	}
	if body.Command == "" {
		writeErr(w, http.StatusBadRequest, "Command cannot be empty")
		return
	}
	if !services.CommandFilterIsSafeCronCommand(body.Command) {
		writeErr(w, http.StatusBadRequest, "Command contains disallowed characters or patterns")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := safecmd.Exec(ctx, "bash", "-c", body.Command)
	if ctx.Err() == context.DeadlineExceeded {
		writeErr(w, http.StatusGatewayTimeout, "Command timed out after 30s")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Failed to execute: %v", err))
		return
	}
	combined := strings.ToValidUTF8(string(out.Stdout), "�")
	if stderr := strings.ToValidUTF8(string(out.Stderr), "�"); stderr != "" {
		combined += "\n--- stderr ---\n" + stderr
	}
	combined = cronsTruncate(combined)
	var code *int
	if out.ExitCode >= 0 {
		c := out.ExitCode
		code = &c
	}
	writeJSON(w, http.StatusOK, CronsCronResult{Success: out.Success(), Output: &combined, ExitCode: code})
}

// cronsTruncate caps output at 10KB. Backs off to a UTF-8 boundary (the Rust
// byte slice would panic mid-character).
func cronsTruncate(s string) string {
	const max = 10240
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...(truncated)"
}

// cronsList: GET /crons/list — dockpanel crons from root's crontab.
// Read-only: a failed read destroys nothing, so it degrades to an empty
// listing rather than a 500; the panel's own rows are the record.
func cronsList(w http.ResponseWriter, _ *http.Request) {
	crontab, err := services.CrontabRead()
	if err != nil {
		slog.Warn("Could not read the crontab to list crons: " + err.Error())
		crontab = ""
	}
	writeJSON(w, http.StatusOK, cronsParseList(crontab))
}

func cronsParseList(crontab string) []map[string]string {
	out := []map[string]string{}
	for _, line := range services.LogsLines([]byte(crontab)) {
		// Format: schedule command # dockpanel:id label
		pos := strings.Index(line, cronsCrontabMarker)
		if pos < 0 {
			continue
		}
		after := line[pos+len(cronsCrontabMarker):]
		id, label := strings.TrimSpace(after), ""
		if sp := strings.IndexByte(after, ' '); sp >= 0 {
			id, label = after[:sp], strings.TrimSpace(after[sp+1:])
		}
		out = append(out, map[string]string{"id": id, "entry": strings.TrimSpace(line[:pos]), "label": label})
	}
	return out
}

// cronsRemove: DELETE /crons/remove/{id}.
func cronsRemove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := services.CrontabRead()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var lines []string
	for _, l := range services.LogsLines([]byte(existing)) {
		if got, ok := cronsMarkerID(l); !ok || got != id {
			lines = append(lines, l)
		}
	}
	if err := services.CrontabWrite(strings.Join(lines, "\n")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"removed": id})
}

// cronsMarkerID: the dockpanel cron id a crontab line carries — the token
// right after the marker. Parsed, not substring-matched, so a line cannot be
// attributed to another cron whose id merely extends it.
func cronsMarkerID(line string) (string, bool) {
	parts := strings.SplitN(line, cronsCrontabMarker, 3)
	if len(parts) < 2 {
		return "", false
	}
	f := strings.Fields(parts[1])
	if len(f) == 0 {
		return "", false
	}
	return f[0], true
}

// cronsIsValidSchedule: 5 fields of digits, *, /, -, and , only.
func cronsIsValidSchedule(schedule string) bool {
	parts := strings.Fields(schedule)
	if len(parts) != 5 {
		return false
	}
	for _, p := range parts {
		for _, c := range p {
			if !(c >= '0' && c <= '9' || c == '*' || c == '/' || c == '-' || c == ',') {
				return false
			}
		}
	}
	return true
}
