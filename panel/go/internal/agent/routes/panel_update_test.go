package routes

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func panelUpdateTestSrc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("panel_update.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func panelUpdateSection(t *testing.T, s, from, to string) string {
	t.Helper()
	i := strings.Index(s, from)
	if i < 0 {
		t.Fatalf("%q not found", from)
	}
	s = s[i:]
	j := strings.Index(s, to)
	if j < 0 {
		t.Fatalf("%q not found after %q", to, from)
	}
	return s[:j]
}

// The embedded copy must not drift from the canonical script.
func TestPanelUpdateEmbeddedScriptMatchesRepoCopy(t *testing.T) {
	want, err := os.ReadFile("../../../../../scripts/agent-self-update.sh")
	if err != nil {
		t.Skip("repo script absent:", err)
	}
	if string(want) != panelUpdateAgentUpdateScript {
		t.Fatal("routes/agent-self-update.sh differs from scripts/agent-self-update.sh — re-copy it")
	}
}

func TestPanelUpdateTargetVersionValidatorMatchesThePanelSide(t *testing.T) {
	for _, good := range []string{"v2.11.7", "2.11.7", "v2.11.7-rc.1", "10.20.30"} {
		if !panelUpdateValidateTargetVersion(good) {
			t.Errorf("%s should be accepted", good)
		}
	}
	for _, bad := range []string{"", "v", "v2.11", "latest", "2.11.7; rm -rf /", "v2.11.7-alpha"} {
		if panelUpdateValidateTargetVersion(bad) {
			t.Errorf("%s should be rejected", bad)
		}
	}
}

// The embedded updater must never `cp` onto the binary it is replacing:
// writing to an executing file fails ETXTBSY, and a restore path that cannot
// restore is not a safety net (lesson #48). Renames only. Copying the live
// binary INTO the backup path is the documented exception, as is the systemd
// unit copied into its rollback backup (s271).
func TestPanelUpdateAgentUpdaterInstallsByRenameNotByCopyOntoTheTarget(t *testing.T) {
	for _, line := range strings.Split(panelUpdateAgentUpdateScript, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "cp ") || strings.HasPrefix(l, "cp -") {
			if strings.Contains(l, `"$AGENT_BIN"`) && !strings.Contains(l, `"$BACKUP"`) {
				t.Errorf("nothing may copy onto the executing binary: %s", l)
			}
		}
	}
	if !strings.Contains(panelUpdateAgentUpdateScript, `mv -f "$STAGED" "$AGENT_BIN"`) {
		t.Error("install must be a rename")
	}
}

// Download, then verify, then install — three separate steps (lesson #25).
func TestPanelUpdateAgentUpdaterVerifiesTheDownloadBeforeInstallingIt(t *testing.T) {
	s := panelUpdateAgentUpdateScript
	if !strings.Contains(s, "sha256sum") {
		t.Error("must checksum the download")
	}
	if !strings.Contains(s, "checksums.txt") {
		t.Error("must fetch the release checksums")
	}
	verifyAt := strings.Index(s, "sha256 mismatch")
	installAt := strings.Index(s, "could not move the new binary into place")
	if verifyAt < 0 || installAt < 0 || verifyAt >= installAt {
		t.Error("the checksum guard must come before the install")
	}
	if strings.Contains(s, `curl -fsSL --max-time 600 "${BASE}/${ASSET}" |`) {
		t.Error("the binary must be materialised to a file, never piped into a consumer")
	}
}

// It restarts the unit it runs under, so PID1 has to own it (lesson #47); a
// scope dies with the caller's session.
func TestPanelUpdateAgentUpdaterRunsUnderAPid1OwnedTransientService(t *testing.T) {
	s := panelUpdateAgentUpdateScript
	if !strings.Contains(s, "systemd-run") || !strings.Contains(s, "--collect") {
		t.Error("needs systemd-run --collect")
	}
	if strings.Contains(s, "--scope") {
		t.Error("a transient service, never a scope")
	}
}

// The rollback branch must not claim it restored anything it did not, nor
// swallow a failed restore (lesson #48/#58).
func TestPanelUpdateTheRollbackBranchNeverSwallowsOrOverclaimsTheRestore(t *testing.T) {
	s := panelUpdateAgentUpdateScript
	i := strings.Index(s, `stage="rollback"`)
	if i < 0 {
		t.Fatal("no rollback branch")
	}
	rb := s[i:]
	if j := strings.Index(rb, `rm -f "$BACKUP"`); j >= 0 {
		rb = rb[:j]
	}
	if strings.Contains(rb, `mv -f "$BACKUP" "$AGENT_BIN" && `+"systemctl restart dockpanel-agent || true") {
		t.Error("a restore must not be suffixed with a status-swallowing || true")
	}
	if !strings.Contains(rb, `if mv -f "$BACKUP" "$AGENT_BIN"`) {
		t.Error("the restore's own status has to be branched on")
	}
	if !strings.Contains(rb, "COULD NOT RESTORE") {
		t.Error("a failed restore needs to say so, loudly, in the verdict")
	}
	if !strings.Contains(rb, "running_version") {
		t.Error("the claim must be checked against what the agent reports afterwards")
	}
}

// A failed run and a run that never happened must be distinguishable after the
// restart wipes this process's memory (lesson #52).
func TestPanelUpdateAgentUpdaterAlwaysWritesAVerdictIncludingOnAbort(t *testing.T) {
	s := panelUpdateAgentUpdateScript
	for _, want := range []string{"trap on_exit EXIT", `write_result false "aborted at stage`, "write_result true"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// Nothing in the spawn path may promote a zero exit status into a success
// claim: the process waited on merely HANDS OFF the work.
func TestPanelUpdateAZeroExitFromTheLauncherIsNeverReportedAsSuccess(t *testing.T) {
	src := panelUpdateTestSrc(t)
	bad := "if status." + "Success() {" // assembled so this test does not match itself
	for _, l := range strings.Split(src, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "//") && strings.Contains(l, bad) {
			t.Errorf("a successful launch is not a successful update: %s", l)
		}
	}
	if !strings.Contains(src, "if !status.Success() {") {
		t.Error("a FAILED launch is still real information and must be recorded")
	}
}

// in_flight must be able to resolve from the verdict file, but only for a
// verdict at least as new as this run's start.
func TestPanelUpdateAnInFlightRunStillSurfacesAVerdictWrittenAfterItStarted(t *testing.T) {
	f := panelUpdateSection(t, panelUpdateTestSrc(t), "func panelUpdateStatus(", "func registerPanelUpdate")
	if !strings.Contains(f, "case panelUpdateInFlight:") {
		t.Error("in_flight must be able to resolve from the verdict file")
	}
	if !strings.Contains(f, "panelUpdateRunHasFinished(") {
		t.Error("and only for a verdict at least as new as this run's start")
	}
}

// The 409 guard and the status endpoint must share one liveness predicate, or
// one failed update makes the box permanently un-updatable.
func TestPanelUpdateTheInFlightGuardAndTheStatusEndpointShareOneLivenessPredicate(t *testing.T) {
	guard := panelUpdateSection(t, panelUpdateTestSrc(t), "func panelUpdateApply(", "func panelUpdateRunUpdateSubprocess(")
	if !strings.Contains(guard, "panelUpdateRunHasFinished(") {
		t.Error("the 409 guard must ask whether the run is actually still running")
	}
	// Negative control: the unconditional form that wedged the lab box.
	if strings.Contains(guard, "s.Kind == panelUpdateInFlight "+"{") {
		t.Error("an in_flight state alone is not evidence that an update is still running")
	}
}

// Whole-second comparison on both sides (see panelUpdateRunHasFinished).
func TestPanelUpdateRunFinishedRecognisesAVerdictWrittenInTheSameSecondAsTheStart(t *testing.T) {
	f := panelUpdateSection(t, panelUpdateTestSrc(t), "func panelUpdateRunHasFinished(", "\n}")
	if strings.Contains(f, "!t.Before("+"startedAt)") || strings.Contains(f, "t.Compare("+"startedAt)") {
		t.Error("comparing a whole-second verdict against a sub-second start wedges fast failures")
	}
	if !strings.Contains(f, "t.Unix() >= startedAt.Unix()") {
		t.Error("the comparison must be at whole-second resolution on both sides")
	}

	// Behavioural check (Go-only): a verdict written within the start's second counts.
	dir := t.TempDir()
	old := panelUpdateAgentUpdateResultPath
	panelUpdateAgentUpdateResultPath = filepath.Join(dir, "r.json")
	t.Cleanup(func() { panelUpdateAgentUpdateResultPath = old })
	start := time.Date(2026, 1, 2, 3, 4, 5, 900_000_000, time.UTC)
	if err := os.WriteFile(panelUpdateAgentUpdateResultPath, []byte(`{"ok":false,"at":"2026-01-02T03:04:05Z","target_version":"v1.2.3","stage":"swap","reason":"boom"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !panelUpdateRunHasFinished(start) {
		t.Error("same-second verdict must count as this run's")
	}
	if panelUpdateRunHasFinished(start.Add(time.Second)) {
		t.Error("an older verdict must not count")
	}
	if why, ok := panelUpdateTargetAlreadyFailedDestructively("1.2.3"); !ok || why != "stage swap: boom" {
		t.Errorf("got %q %v", why, ok)
	}
}

// The unattended path must not repeat a destructive update for ever; only
// stages reached AFTER the swap count.
func TestPanelUpdateATargetThatAlreadyFailedAfterTheSwapIsNotRetriedUnattended(t *testing.T) {
	for _, stage := range []string{"swap", "unit", "restart", "verify-running", "rollback"} {
		if !slices.Contains(panelUpdatePostSwapStages, stage) {
			t.Errorf("%s must count as destructive", stage)
		}
	}
	for _, stage := range []string{"download", "verify", "arch", "probe", "init"} {
		if slices.Contains(panelUpdatePostSwapStages, stage) {
			t.Errorf("%s happens before the swap and is safe to retry", stage)
		}
	}
	// Every stage the updater can record must be classified.
	for _, line := range strings.Split(panelUpdateAgentUpdateScript, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), `stage="`)
		if !ok {
			continue
		}
		stage, _, _ := strings.Cut(rest, `"`)
		if !slices.Contains(panelUpdatePostSwapStages, stage) &&
			!slices.Contains([]string{"init", "probe", "arch", "download", "verify", "complete"}, stage) {
			t.Errorf("unclassified updater stage %q — decide whether it is destructive", stage)
		}
	}
	// The timer, not the shared launcher, consults it.
	if ph, err := os.ReadFile("../services/phone_home.go"); err == nil {
		if !strings.Contains(string(ph), "PhoneHomeTargetAlreadyFailedDestructively(") {
			t.Error("the unattended path must consult the previous verdict")
		}
	} else {
		t.Log("services/phone_home.go absent; skipping the timer-side check")
	}
	launcher := panelUpdateSection(t, panelUpdateTestSrc(t), "func panelUpdateStartAgentSelfUpdate(", "func panelUpdateRunUpdateSubprocess(")
	if strings.Contains(launcher, "panelUpdateTargetAlreadyFailedDestructively(") {
		t.Error("the operator-driven path must NOT be blocked by a previous failure")
	}
}

// Check and claim must be one atomic step: two callers (HTTP + timer) could
// otherwise both observe "no" and both spawn an updater.
func TestPanelUpdateTheInFlightGuardClaimsUnderTheSameLockItChecked(t *testing.T) {
	f := panelUpdateSection(t, panelUpdateTestSrc(t), "func panelUpdateStartAgentSelfUpdate(", "// Materialise the embedded updater")
	check := strings.Index(f, "panelUpdateRunHasFinished(")
	claim := strings.Index(f, "panelUpdateCur = panelUpdateAgentUpdateState{Kind: panelUpdateInFlight")
	if check < 0 || claim < 0 || check >= claim {
		t.Fatal("the guard must check before it claims")
	}
	if strings.Contains(f[check:claim], "panelUpdateMu.Lock()") {
		t.Error("check and claim must happen under ONE lock acquisition")
	}
}

// A full panel install keeps the panel updater; everything else gets the
// agent-only one, and the API binary is the discriminator.
func TestPanelUpdateUpdateModeIsDecidedByWhatTheBoxActuallyHas(t *testing.T) {
	src := panelUpdateTestSrc(t)
	for _, want := range []string{"panelUpdateModeFullPanel", "panelUpdateModeAgentOnly", "panelUpdatePathExists(panelUpdateAPIBin)"} {
		if !strings.Contains(src, want) {
			t.Errorf("missing %q", want)
		}
	}
}
