package api

// Port of services/prerequisites/apps.rs — the Docker-apps vertical, "can
// this container actually start like this?"
//
// The app templates are the most-used surface in the product and their
// failures are the least self-explanatory: the deploy runs for as long as it
// takes to pull the image, and *then* reports `port is already allocated` or
// nothing at all while the container restart-loops on a missing password.
// Every condition checked here is knowable before the pull starts.
//
// Why the checks are pure and the I/O is not: each check takes facts and
// returns a verdict; gathering the facts (three agent calls and a query) lives
// in the route. That split is what makes the interesting cases testable
// without a Docker daemon — the SSL ladder was untestable for exactly as long
// as its decision stayed inside an async DB loop.

import (
	"fmt"
	"strconv"
	"strings"
)

// PrerequisitesAppsAppDeployIntent is what the user is about to deploy.
type PrerequisitesAppsAppDeployIntent struct {
	TemplateID string
	Name       string
	Port       uint16
	Env        map[string]string
	MemoryMB   *uint64
}

// PrerequisitesAppsAppEnvSpec is one environment variable a template declares,
// as the agent reports it.
type PrerequisitesAppsAppEnvSpec struct {
	Name     string
	Label    string
	Default  string
	Required bool
	Secret   bool
}

// PrerequisitesAppsPortHolder is who currently holds a host port, in the user's terms.
type PrerequisitesAppsPortHolder struct {
	Port uint16
	// e.g. "the app `grafana`" or "the site example.com".
	Description string
}

// PrerequisitesAppsHostFacts is everything about the host the checks need,
// gathered once.
type PrerequisitesAppsHostFacts struct {
	UsedPorts []PrerequisitesAppsPortHolder
	// Names of containers DockPanel already manages — the USER-facing names
	// (`<name>`), not the agent's `dockpanel-app-<name>`.
	TakenNames []string
	MemTotalMB *uint64
	MemUsedMB  *uint64
	// The agent's bind probe for the requested port. nil when we couldn't ask
	// — an older fleet agent has no `/system/port-check`, and a check we cannot
	// run must degrade to `unknown`, never to a refusal.
	PortProbeFree *bool
}

func (f *PrerequisitesAppsHostFacts) holderOf(port uint16) *PrerequisitesAppsPortHolder {
	for i := range f.UsedPorts {
		if f.UsedPorts[i].Port == port {
			return &f.UsedPorts[i]
		}
	}
	return nil
}

// nextFreePort is the next port at or above `from` that nothing known is using.
//
// Deliberately deterministic: the preflight re-runs as the user types, and a
// suggestion that changed each time would be worse than none. Only consults
// what we know — the agent probe covers a single port, so a suggestion is a
// starting point, not a promise.
func (f *PrerequisitesAppsHostFacts) nextFreePort(from uint16) (uint16, bool) {
	for p := int(max(from, 1024)); p <= 65000; p++ {
		if f.holderOf(uint16(p)) == nil {
			return uint16(p), true
		}
	}
	return 0, false
}

// PrerequisitesAppsCheckRequiredEnv: every environment variable the template
// *requires* has a value.
//
// The highest-yield check in the vertical. 104 of the shipped templates
// declare at least one variable that is `required` with no default. The deploy
// form marks them with a red asterisk and then lets you submit anyway. The
// agent resolves each variable as "provided, else default" and then **drops it
// entirely if the result is empty** — so `postgres` refuses to initialise,
// `grafana` silently keeps its built-in password, and the user finds out after
// the pull, from container logs.
//
// Blocking, because the template's own author declared it required and the
// fix is to type something into a field that is already on screen.
func PrerequisitesAppsCheckRequiredEnv(intent *PrerequisitesAppsAppDeployIntent, specs []PrerequisitesAppsAppEnvSpec) PrerequisitesPrereqResult {
	var missing []PrerequisitesAppsAppEnvSpec
	for _, s := range specs {
		if !s.Required {
			continue
		}
		// Mirror the agent's own resolution rule exactly: a provided value
		// wins, otherwise the default, and an empty result is omitted.
		provided := strings.TrimSpace(intent.Env[s.Name]) != ""
		if !provided && strings.TrimSpace(s.Default) == "" {
			missing = append(missing, s)
		}
	}

	if len(missing) == 0 {
		return PrerequisitesCopyAppsEnvCheck.Result(PrerequisitesCopyAppsEnvAllPresent, nil)
	}

	names := make([]string, 0, len(missing))
	allSecret := true
	for _, s := range missing {
		names = append(names, fmt.Sprintf("%s (%s)", s.Label, s.Name))
		allSecret = allSecret && s.Secret
	}

	// A set that is entirely passwords and keys gets the Generate wording; one
	// that mixes in ordinary settings cannot promise a button that isn't there.
	outcome := PrerequisitesCopyAppsEnvMissingSettings
	if allSecret {
		outcome = PrerequisitesCopyAppsEnvMissingSecrets
	}
	return PrerequisitesCopyAppsEnvCheck.Result(outcome, [][2]string{
		{"first_label", missing[0].Label},
		{"count", strconv.Itoa(len(missing))},
		{"template_id", intent.TemplateID},
		{"names", strings.Join(names, ", ")},
	}).WithObserved(names)
}

// PrerequisitesAppsCheckPortAvailable: is the requested host port actually free?
//
// `POST /api/apps/deploy` validates only that the port is non-zero. Sites have
// refused colliding ports for years; apps never got the equivalent, so a
// collision surfaced as a Docker error after the pull.
//
// Three sources, in order of authority: the host's own bind probe, then the
// containers DockPanel manages, then the sites it proxies.
func PrerequisitesAppsCheckPortAvailable(intent *PrerequisitesAppsAppDeployIntent, facts *PrerequisitesAppsHostFacts) PrerequisitesPrereqResult {
	port := intent.Port
	if port == 0 {
		return PrerequisitesCopyAppsPortCheck.Result(PrerequisitesCopyAppsPortUnset, nil)
	}

	portStr := strconv.Itoa(int(port))
	from := port
	if from < 65535 {
		from++ // saturating_add(1)
	}
	var suggestion *PrerequisitesRemediation
	if p, ok := facts.nextFreePort(from); ok {
		suggestion = PrerequisitesNewRemediationValue("Use this port instead", strconv.Itoa(int(p)), "port", false)
	}

	// Something DockPanel knows about holds it — we can name what.
	if holder := facts.holderOf(port); holder != nil {
		r := PrerequisitesCopyAppsPortCheck.Result(PrerequisitesCopyAppsPortHeldByKnown,
			[][2]string{{"port", portStr}, {"holder", holder.Description}}).
			WithObserved([]string{holder.Description})
		if suggestion != nil {
			r = r.WithRemediation(suggestion)
		}
		return r
	}

	switch {
	case facts.PortProbeFree == nil:
		return PrerequisitesCopyAppsPortCheck.Result(PrerequisitesCopyAppsPortUnprobeable, [][2]string{{"port", portStr}})
	case *facts.PortProbeFree:
		return PrerequisitesCopyAppsPortCheck.Result(PrerequisitesCopyAppsPortFree, [][2]string{{"port", portStr}})
	default:
		// Nothing of ours holds it, yet the bind failed — so something outside
		// DockPanel does. We can't name it, but the consequence is identical.
		r := PrerequisitesCopyAppsPortCheck.Result(PrerequisitesCopyAppsPortHeldByUnknown, [][2]string{{"port", portStr}})
		if suggestion != nil {
			r = r.WithRemediation(suggestion)
		}
		return r
	}
}

func prerequisitesNameTaken(taken []string, name string) bool {
	for _, n := range taken {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// PrerequisitesAppsCheckNameAvailable: is the app name already taken?
//
// Container names are unique per host, and the deploy form pre-fills the name
// with the template id — so deploying a second Postgres collides by default.
func PrerequisitesAppsCheckNameAvailable(intent *PrerequisitesAppsAppDeployIntent, facts *PrerequisitesAppsHostFacts) PrerequisitesPrereqResult {
	name := strings.TrimSpace(intent.Name)
	if name == "" {
		return PrerequisitesCopyAppsNameCheck.Result(PrerequisitesCopyAppsNameUnset, nil)
	}

	if prerequisitesNameTaken(facts.TakenNames, name) {
		r := PrerequisitesCopyAppsNameCheck.Result(PrerequisitesCopyAppsNameTaken, [][2]string{{"name", name}}).
			WithObserved([]string{name})
		// Suggest name-2, name-3, … rather than a random suffix: predictable,
		// and it matches what someone deploying a second copy would have typed.
		for n := 2; n < 50; n++ {
			candidate := fmt.Sprintf("%s-%d", name, n)
			if !prerequisitesNameTaken(facts.TakenNames, candidate) {
				r = r.WithRemediation(PrerequisitesNewRemediationValue("Use this name instead", candidate, "name", false))
				break
			}
		}
		return r
	}

	return PrerequisitesCopyAppsNameCheck.Result(PrerequisitesCopyAppsNameAvailable, [][2]string{{"name", name}})
}

// PrerequisitesAppsCheckResourceHeadroom: does the server have the memory
// this deploy asks for?
//
// Warning, never blocking. Over-committing memory is normal practice, the
// kernel will page, and the operator may know something we don't about what
// is about to be freed. What is *not* acceptable is finding out from an OOM kill.
func PrerequisitesAppsCheckResourceHeadroom(intent *PrerequisitesAppsAppDeployIntent, facts *PrerequisitesAppsHostFacts) PrerequisitesPrereqResult {
	if facts.MemTotalMB == nil || facts.MemUsedMB == nil || intent.MemoryMB == nil {
		return PrerequisitesCopyAppsMemCheck.Result(PrerequisitesCopyAppsMemNotChecked, nil)
	}
	total, used, want := *facts.MemTotalMB, *facts.MemUsedMB, *intent.MemoryMB
	free := uint64(0)
	if total > used {
		free = total - used
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	vars := [][2]string{{"want", u(want)}, {"total", u(total)}, {"free", u(free)}}

	if want > total {
		return PrerequisitesCopyAppsMemCheck.Result(PrerequisitesCopyAppsMemOverTotal, vars).
			WithExpected(fmt.Sprintf("%d MB total", total)).
			WithObserved([]string{fmt.Sprintf("%d MB requested", want), fmt.Sprintf("%d MB free", free)})
	}
	if want > free {
		return PrerequisitesCopyAppsMemCheck.Result(PrerequisitesCopyAppsMemOverFree, vars).
			WithExpected(fmt.Sprintf("%d MB free", free)).
			WithObserved([]string{fmt.Sprintf("%d MB requested", want)})
	}
	return PrerequisitesCopyAppsMemCheck.Result(PrerequisitesCopyAppsMemFits, vars)
}

// PrerequisitesAppsEvaluate evaluates every Docker-app prerequisite for one
// intended deploy. Order matters only for presentation: the first blocker is
// the one the caller shows against a gated button, so the cheapest thing to
// fix comes first.
func PrerequisitesAppsEvaluate(intent *PrerequisitesAppsAppDeployIntent, specs []PrerequisitesAppsAppEnvSpec, facts *PrerequisitesAppsHostFacts) []PrerequisitesPrereqResult {
	return []PrerequisitesPrereqResult{
		PrerequisitesAppsCheckRequiredEnv(intent, specs),
		PrerequisitesAppsCheckPortAvailable(intent, facts),
		PrerequisitesAppsCheckNameAvailable(intent, facts),
		PrerequisitesAppsCheckResourceHeadroom(intent, facts),
	}
}
