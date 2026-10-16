package api

// Port of panel/backend/src/services/prerequisites/copy.rs — the one registry
// of guidance copy — plus what main.rs's `--emit-guidance` writes from it.
//
// Every sentence the guidance layer says to a user lives here, as data, in
// one file. The checks in the sibling prerequisites modules decide *which*
// outcome a situation is; they do not decide what it says.
//
// # Why this exists
//
// Through v2.29.0 the copy lived inside each check as format strings, and the
// same facts were also written by hand into `docs/`, and the two drifted. The
// audit that opened v2.30.0 found the manual telling operators to publish
// `default._domainkey` while the product has deployed the selector `dockpanel`
// for its entire life — a user who followed the documentation got a DKIM
// record that could never verify.
//
// So the rule is not "keep them in sync". The rule is **there is one copy of
// each fact, and the manual is generated from it** — see
// PrerequisitesCopyManual. A hand-written page cannot contradict the product
// if it does not contain the product's facts.
//
// # The three tiers are one system
//
// Tooltips and callouts are the same content rendered at different
// urgencies. That is why PrerequisitesCopyFields (the passive tier) sits here
// beside PrerequisitesCopyPrereqs (the reactive and blocking tiers), and
// Field.EscalatesTo names the link between them.
//
// # Editing
//
// Change a sentence here and `go test` fails until the generated files are
// regenerated:
//
//	UPDATE_GUIDANCE_DOCS=1 go test ./internal/api -run Guidance
//
// (or `dockpanel-api --emit-guidance <repo-root>`). That failure is the
// mechanism — the reason the docs cannot be out of date. While the Rust tree
// exists, copy.rs and this file must carry the same sentences: both emit the
// same committed artefacts byte for byte.
//
// Uses the shared vocabulary of services/prerequisites/mod.rs (owned by the
// prerequisites port): PrerequisitesPrereqState/Severity and their variants,
// PrerequisitesPrereqResult.

import (
	"fmt"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Shapes
// ─────────────────────────────────────────────────────────────────────────────

// PrerequisitesCopyVar is a value a piece of copy interpolates, with the
// example the manual renders it with. The example is what makes the generated
// page readable (`example.com doesn't resolve yet` rather than `{domain}
// doesn't resolve yet`) and what the round-trip test substitutes to prove no
// placeholder was left unfilled.
type PrerequisitesCopyVar struct {
	Name    string
	Example string
}

// PrerequisitesCopyOutcome is one situation a check can conclude, and what
// the user is told about it.
type PrerequisitesCopyOutcome struct {
	// Stable id, unique within its check. Greppable; the manual anchors on it.
	ID       string
	State    PrerequisitesPrereqState
	Severity PrerequisitesPrereqSeverity
	// The one-line title. May interpolate any of Vars.
	Title string
	// Used instead of Title when the `count` var is anything but "1". Empty
	// means Title is always used. English plurals are the one piece of grammar
	// a copy registry cannot avoid; the alternative is a near-duplicate
	// outcome per number.
	TitlePlural string
	// The explanation, in the user's terms.
	Detail string
	// Doc-facing: what the operator does about it. Empty for outcomes that
	// need nothing done — the manual renders those as "nothing to do".
	Fix  string
	Vars []PrerequisitesCopyVar
}

// Blocks reports whether a control gated on this outcome would be disabled.
// Mirrors PrerequisitesPrereqResult.Blocks, for the manual and for tests.
func (o *PrerequisitesCopyOutcome) Blocks() bool {
	return o.State == PrerequisitesPrereqStateUnsatisfied && o.Severity == PrerequisitesPrereqSeverityBlocking
}

// PrerequisitesCopyPrereq is one prerequisite: everything true of it
// regardless of which outcome it reaches.
type PrerequisitesCopyPrereq struct {
	// The stable key the API and the frontend already use, e.g. `dns.points_here`.
	Key string
	// The vertical this belongs to, as a user would name it.
	Vertical string
	// The question the check answers, in one line.
	Question string
	// Why an operator should care — the consequence, not the mechanism.
	Why string
	// Why this check blocks, warns or merely explains. Recorded because
	// severity here is chosen by consequence rather than by confidence, and
	// that choice is the part most likely to be re-litigated.
	SeverityPolicy string
	// Where in the product this is evaluated and shown.
	Surfaces []string
	Outcomes []*PrerequisitesCopyOutcome
}

// Result builds the runtime result for one outcome, filling its placeholders.
//
// The only way a check produces a PrerequisitesPrereqResult. Expected,
// Observed and Remediation are attached by the caller afterwards — those are
// measured data, not copy, and do not belong in this file.
func (p *PrerequisitesCopyPrereq) Result(outcome *PrerequisitesCopyOutcome, vars [][2]string) PrerequisitesPrereqResult {
	plural := false
	if outcome.TitlePlural != "" {
		for _, v := range vars {
			if v[0] == "count" {
				plural = v[1] != "1"
				break
			}
		}
	}
	template := outcome.Title
	if plural {
		template = outcome.TitlePlural
	}
	return PrerequisitesPrereqResult{
		Key:      p.Key,
		State:    outcome.State,
		Severity: outcome.Severity,
		Title:    prerequisitesCopyFill(template, vars),
		Detail:   prerequisitesCopyFill(outcome.Detail, vars),
		Observed: []string{},
	}
}

// PrerequisitesCopyField is a form field's passive guidance — the quiet tier.
type PrerequisitesCopyField struct {
	// Stable id, e.g. `sites.create.domain`. The frontend keys off it.
	ID string
	// The surface it appears on, as a user would name it.
	Surface string
	// The field's label, spelled exactly as the screen spells it.
	Label string
	// The line under the field. Must stay short. Empty means this entry
	// exists for its (i) alone — the standing line is computed from the
	// form's own state and belongs in the component.
	Help string
	// The longer explanation behind the (i). Empty means no tooltip — most
	// fields don't have one, and inventing one for every field is how a help
	// system becomes noise.
	More string
	// The prerequisite key this field's guidance escalates into when the
	// quiet tier stops being enough. Empty when nothing checks this field.
	EscalatesTo string
}

// prerequisitesCopyFill replaces every `{name}` with its value.
//
// Deliberately not a templating engine. Single-pass, and that matters — a
// sequence of replace calls re-reads its own output, so a value containing
// `{something}` would be substituted again by a later variable. Several values
// are named by the operator (a backup policy, a container), and copy that
// rewrites what the user typed is a small lie of exactly the kind this file
// exists to stop.
//
// An unknown placeholder is left visible rather than dropped: silence is how
// a missing value survives review, and a stray `{name}` on screen fails the
// tests that guard every call site.
func prerequisitesCopyFill(template string, vars [][2]string) string {
	var out strings.Builder
	rest := template
	for {
		start := strings.IndexByte(rest, '{')
		if start < 0 {
			break
		}
		out.WriteString(rest[:start])
		after := rest[start+1:]
		end := strings.IndexByte(after, '}')
		if end < 0 {
			// Unbalanced brace: emit the remainder verbatim rather than
			// looping forever on it.
			out.WriteByte('{')
			out.WriteString(after)
			rest = ""
			break
		}
		name := after[:end]
		found := false
		for _, v := range vars {
			if v[0] == name {
				out.WriteString(v[1])
				found = true
				break
			}
		}
		if !found {
			out.WriteString("{" + name + "}")
		}
		rest = after[end+1:]
	}
	out.WriteString(rest)
	return out.String()
}

// prerequisitesCopyExampleVars is an outcome's vars bound to their examples.
func prerequisitesCopyExampleVars(o *PrerequisitesCopyOutcome) [][2]string {
	vars := make([][2]string, 0, len(o.Vars))
	for _, v := range o.Vars {
		vars = append(vars, [2]string{v.Name, v.Example})
	}
	return vars
}

// ─────────────────────────────────────────────────────────────────────────────
// Export
// ─────────────────────────────────────────────────────────────────────────────

// prerequisitesCopyGeneratedBanner is the header every generated artefact
// carries. It names the Rust source on purpose: both implementations emit the
// same bytes, so the committed files stay identical whichever regenerated them.
const prerequisitesCopyGeneratedBanner = "DO NOT EDIT — generated from panel/backend/src/services/prerequisites/copy.rs"

// PrerequisitesCopyManual renders the registry as the documentation page.
//
// This is the mechanism behind "the manual can never contradict the
// product": the page is not written, it is emitted, from the same data the
// running product renders. A test asserts the committed file matches.
func PrerequisitesCopyManual() string {
	var out strings.Builder
	w := func(s string) { out.WriteString(s) }

	w("<!-- " + prerequisitesCopyGeneratedBanner + " -->\n\n")
	w("# What DockPanel checks before you commit\n\n")
	w("Some things have to be true before a feature can work — a domain has to resolve, a port " +
		"has to be free, a backup has to have somewhere to go. DockPanel checks these for you and " +
		"says so on the screen where it matters, rather than letting the action fail and leaving " +
		"you to work out why.\n\n" +
		"This page is generated from the same source the product renders its messages from, so " +
		"the wording below is the wording you will see.\n\n")

	w("## How to read the three tiers\n\n")
	w("| Tier | What it looks like | What it means |\n" +
		"|---|---|---|\n" +
		"| Passive | A line under a field, or text behind an (i) | Context. Nothing is wrong. |\n" +
		"| Warning | An amber callout | It probably won't work, or it will leave a mess — but " +
		"the choice is yours and the control stays usable. |\n" +
		"| Blocking | A red callout, and the button is disabled | It *will* fail. The gate opens " +
		"by itself once the condition is met. |\n\n" +
		"A check DockPanel could not run never blocks anything and never accuses you of " +
		"anything — it says so and gets out of the way.\n\n")

	currentVertical := ""
	for _, prereq := range PrerequisitesCopyPrereqs {
		if prereq.Vertical != currentVertical {
			w(fmt.Sprintf("## %s\n\n", prereq.Vertical))
			currentVertical = prereq.Vertical
		}

		w(fmt.Sprintf("### %s\n\n", prereq.Question))
		w(fmt.Sprintf("`%s`\n\n", prereq.Key))
		w(fmt.Sprintf("%s\n\n", prereq.Why))
		w(fmt.Sprintf("**When it blocks, and when it only warns.** %s\n\n", prereq.SeverityPolicy))

		w("**Where you see it**\n\n")
		for _, surface := range prereq.Surfaces {
			w(fmt.Sprintf("- %s\n", surface))
		}
		w("\n")

		w("| | What DockPanel says | What to do |\n|---|---|---|\n")
		for _, outcome := range prereq.Outcomes {
			vars := prerequisitesCopyExampleVars(outcome)
			// Derived from the same predicate the product gates on, never
			// re-stated: a manual that decides for itself what counts as
			// blocking is exactly the drift this page exists to end.
			var tier string
			switch {
			case outcome.Blocks():
				tier = "**Blocks**"
			case outcome.State == PrerequisitesPrereqStateSatisfied:
				tier = "OK"
			case outcome.State == PrerequisitesPrereqStateUnknown:
				tier = "Not checked"
			case outcome.Severity == PrerequisitesPrereqSeverityWarning:
				tier = "Warns"
			default:
				tier = "Explains"
			}
			title := prerequisitesCopyFill(outcome.Title, vars)
			detail := strings.ReplaceAll(prerequisitesCopyFill(outcome.Detail, vars), "\n", " ")
			fix := outcome.Fix
			if fix == "" {
				fix = "Nothing."
			}
			w(fmt.Sprintf("| %s | **%s** — %s | %s |\n", tier,
				prerequisitesCopyEscapeTable(title), prerequisitesCopyEscapeTable(detail), prerequisitesCopyEscapeTable(fix)))
		}
		w("\n")
	}

	w("## Field help\n\n")
	w("The quiet tier. These are the explanations under the fields themselves; where a field " +
		"has a check behind it, the same concern reappears as a callout when it stops being " +
		"hypothetical.\n\n")

	currentSurface := ""
	for _, field := range PrerequisitesCopyFields {
		if field.Surface != currentSurface {
			w(fmt.Sprintf("### %s\n\n", field.Surface))
			currentSurface = field.Surface
		}
		if field.Help == "" {
			w(fmt.Sprintf("**%s**\n\n", field.Label))
		} else {
			w(fmt.Sprintf("**%s** — %s\n\n", field.Label, field.Help))
		}
		if field.More != "" {
			w(fmt.Sprintf("%s\n\n", field.More))
		}
		if field.EscalatesTo != "" {
			w(fmt.Sprintf("Checked by `%s`.\n\n", field.EscalatesTo))
		}
	}
	return out.String()
}

// PrerequisitesCopyFrontendModule renders the passive tier as a TypeScript
// module for the frontend.
//
// Generated and committed rather than served, for two reasons: a form's
// helper text must not depend on a network call that can fail, and a string
// the frontend renders should be greppable in the frontend.
func PrerequisitesCopyFrontendModule() string {
	var out strings.Builder
	w := func(s string) { out.WriteString(s) }
	q := prerequisitesCopyDebugStr
	w("// " + prerequisitesCopyGeneratedBanner + "\n")
	w("//\n// The passive tier of the guidance layer: the line under a field, and the\n")
	w("// longer text behind its (i). The reactive and blocking tiers arrive at\n")
	w("// runtime as PrereqResults from the same registry.\n\n")

	w("export interface FieldGuidance {\n")
	w("  /** Surface this field belongs to, as a user would name it. */\n")
	w("  surface: string;\n")
	w("  label: string;\n")
	w("  /** The line under the field. Always shown. */\n")
	w("  help: string;\n")
	w("  /** The longer explanation behind the (i). Empty means no tooltip. */\n")
	w("  more: string;\n")
	w("  /** Prerequisite key this field's guidance escalates into, if any. */\n")
	w("  escalatesTo: string;\n")
	w("}\n\n")

	w("export const FIELD_GUIDANCE = {\n")
	for _, f := range PrerequisitesCopyFields {
		w("  " + q(f.ID) + ": {\n")
		w("    surface: " + q(f.Surface) + ",\n")
		w("    label: " + q(f.Label) + ",\n")
		w("    help: " + q(f.Help) + ",\n")
		w("    more: " + q(f.More) + ",\n")
		w("    escalatesTo: " + q(f.EscalatesTo) + ",\n")
		w("  },\n")
	}
	w("} as const satisfies Record<string, FieldGuidance>;\n\n")
	w("export type FieldGuidanceId = keyof typeof FIELD_GUIDANCE;\n")
	return out.String()
}

// prerequisitesCopyDebugStr is Rust's `{:?}` for a &str: double-quoted, with
// `"`, `\` and control characters escaped and printable Unicode kept as-is.
// It is what makes an em-dash-and-quotes sentence safe to paste into the
// TypeScript module.
func prerequisitesCopyDebugStr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case 0:
			b.WriteString(`\0`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u{%x}`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// prerequisitesCopyEscapeTable: pipes end a markdown table cell early.
func prerequisitesCopyEscapeTable(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

// ─────────────────────────────────────────────────────────────────────────────
// The registry. Every prerequisite outcome, in DNS / Docker apps / Mail /
// Backups order, then PrerequisitesCopyPrereqs (manual order) and
// PrerequisitesCopyFields (the passive tier: the fields where getting it
// wrong costs the user a failed deploy, a lost credential or an afternoon).
// ─────────────────────────────────────────────────────────────────────────────

var PrerequisitesCopyDnsEnterADomain = &PrerequisitesCopyOutcome{
	ID:          "enter_a_domain",
	State:       PrerequisitesPrereqStateUnknown,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Enter a domain",
	TitlePlural: "",
	Detail:      "Once you enter a domain, DockPanel checks whether it already points here.",
	Fix:         "",
	Vars:        nil,
}

var PrerequisitesCopyDnsNoPublicIp = &PrerequisitesCopyOutcome{
	ID:          "no_public_ip",
	State:       PrerequisitesPrereqStateUnknown,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Couldn't determine this server's public address",
	TitlePlural: "",
	Detail:      "DockPanel could not detect its own public IP, so it can't check whether the domain points here. SSL issuance will still be attempted.",
	Fix:         "Nothing, usually — the check is unavailable, not failing. If issuance then fails, confirm the server can reach the internet.",
	Vars:        nil,
}

var PrerequisitesCopyDnsNotResolving = &PrerequisitesCopyOutcome{
	ID:          "not_resolving",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityBlocking,
	Title:       "{domain} doesn't resolve yet",
	TitlePlural: "",
	Detail:      "No DNS record was found for {domain}. Create the record below at whoever manages this domain's DNS, then check again. New records usually appear within a few minutes.",
	Fix:         "Create the A (or AAAA) record DockPanel shows, at whoever manages the domain's DNS. The gate opens by itself once the record goes live.",
	Vars: []PrerequisitesCopyVar{
		{Name: "domain", Example: "example.com"},
	},
}

var PrerequisitesCopyDnsPointsHere = &PrerequisitesCopyOutcome{
	ID:          "points_here",
	State:       PrerequisitesPrereqStateSatisfied,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "{domain} points here",
	TitlePlural: "",
	Detail:      "{domain} resolves to this server ({server_ip}).",
	Fix:         "",
	Vars: []PrerequisitesCopyVar{
		{Name: "domain", Example: "example.com"},
		{Name: "server_ip", Example: "203.0.113.10"},
	},
}

var PrerequisitesCopyDnsPointsElsewhere = &PrerequisitesCopyOutcome{
	ID:          "points_elsewhere",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityWarning,
	Title:       "{domain} points somewhere else",
	TitlePlural: "",
	Detail:      "{domain} resolves to {resolved} rather than this server ({server_ip}).\n\nIf you use Cloudflare's proxy (the orange cloud), this is expected and certificate issuance normally still works — Cloudflare passes the validation request through to this server. You can continue.\n\nOtherwise the domain is pointed at a different host. Update the record below and check again.",
	Fix:         "If the domain is behind a proxy such as Cloudflare, nothing — issuance works through it. Otherwise point the record at this server.",
	Vars: []PrerequisitesCopyVar{
		{Name: "domain", Example: "example.com"},
		{Name: "resolved", Example: "198.51.100.7"},
		{Name: "server_ip", Example: "203.0.113.10"},
	},
}

var PrerequisitesCopyDnsPointsElsewhereSubdomain = &PrerequisitesCopyOutcome{
	ID:          "points_elsewhere_subdomain",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityWarning,
	Title:       "{domain} points somewhere else",
	TitlePlural: "",
	Detail:      "{domain} resolves to {resolved} rather than this server ({server_ip}).\n\nIf you use Cloudflare's proxy (the orange cloud), this is expected and certificate issuance normally still works — Cloudflare passes the validation request through to this server. You can continue.\n\nOtherwise the domain is pointed at a different host. Update the record below and check again — note this is the record for {domain}, not for {apex}.",
	Fix:         "Same as above, with one trap: edit the record for the subdomain itself. Pointing the apex somewhere new does not move a subdomain that has its own record.",
	Vars: []PrerequisitesCopyVar{
		{Name: "domain", Example: "www.example.com"},
		{Name: "resolved", Example: "198.51.100.7"},
		{Name: "server_ip", Example: "203.0.113.10"},
		{Name: "apex", Example: "example.com"},
	},
}

var PrerequisitesCopyDnsPointsHereCheck = &PrerequisitesCopyPrereq{
	Key:            "dns.points_here",
	Vertical:       "DNS",
	Question:       "Does this domain point at this server yet?",
	Why:            "An HTTP-01 certificate order sends the certificate authority to your domain to fetch a file from this server. If the domain resolves nowhere, the CA has nowhere to connect and the order fails — after the panel has already told you the site was created.",
	SeverityPolicy: "Blocking when the domain resolves to nothing at all, because issuance cannot possibly succeed. Only a warning when it resolves somewhere else: a Cloudflare-proxied domain resolves to Cloudflare and is indistinguishable from a misconfigured one by address alone, and issuance through the proxy demonstrably works. Refusing it would block a setup we have evidence is fine.",
	Surfaces: []string{
		"The create-site form, as you type the domain (never blocks creation)",
		"The SSL card on a site, where it gates the Let's Encrypt button",
		"`POST /api/sites/{id}/ssl`, which refuses with 412 for the same reason and in the same words",
	},
	Outcomes: []*PrerequisitesCopyOutcome{
		PrerequisitesCopyDnsEnterADomain,
		PrerequisitesCopyDnsNoPublicIp,
		PrerequisitesCopyDnsNotResolving,
		PrerequisitesCopyDnsPointsHere,
		PrerequisitesCopyDnsPointsElsewhere,
		PrerequisitesCopyDnsPointsElsewhereSubdomain,
	},
}

var PrerequisitesCopyAppsEnvAllPresent = &PrerequisitesCopyOutcome{
	ID:          "all_present",
	State:       PrerequisitesPrereqStateSatisfied,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Required settings are filled in",
	TitlePlural: "",
	Detail:      "Every setting this app needs has a value.",
	Fix:         "",
	Vars:        nil,
}

var PrerequisitesCopyAppsEnvMissingSecrets = &PrerequisitesCopyOutcome{
	ID:          "missing_secrets",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityBlocking,
	Title:       "{first_label} needs a value",
	TitlePlural: "{count} required settings have no value",
	Detail:      "{template_id} needs a value for {names}. These are passwords or keys with no safe default — the container is started without them entirely, which usually means it refuses to start or comes up with no protection at all.\n\nUse Generate to have DockPanel pick a strong value.",
	Fix:         "Press Generate beside the field. DockPanel picks a strong value so there is nothing to invent and nothing to remember.",
	Vars: []PrerequisitesCopyVar{
		{Name: "first_label", Example: "POSTGRES_PASSWORD"},
		{Name: "count", Example: "1"},
		{Name: "template_id", Example: "postgres"},
		{Name: "names", Example: "POSTGRES_PASSWORD (POSTGRES_PASSWORD)"},
	},
}

var PrerequisitesCopyAppsEnvMissingSettings = &PrerequisitesCopyOutcome{
	ID:          "missing_settings",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityBlocking,
	Title:       "{first_label} needs a value",
	TitlePlural: "{count} required settings have no value",
	Detail:      "{template_id} needs a value for {names}. Without it the setting is not passed to the container at all, so the app starts misconfigured — usually failing minutes later, after the image has finished downloading.",
	Fix:         "Fill in the marked fields before deploying.",
	Vars: []PrerequisitesCopyVar{
		{Name: "first_label", Example: "MEILI_MASTER_KEY"},
		{Name: "count", Example: "2"},
		{Name: "template_id", Example: "meilisearch"},
		{Name: "names", Example: "MEILI_MASTER_KEY (MEILI_MASTER_KEY), Environment (MEILI_ENV)"},
	},
}

var PrerequisitesCopyAppsEnvCheck = &PrerequisitesCopyPrereq{
	Key:            "apps.required_env",
	Vertical:       "Docker apps",
	Question:       "Does every setting this app requires have a value?",
	Why:            "104 of the shipped templates declare at least one setting that is required and has no default — database passwords, signing keys, and so on. The agent resolves each setting as \"the value you gave, otherwise the default\", and **drops it entirely when the result is empty**. The variable is not passed as blank; it is not passed at all. Postgres refuses to initialise, Grafana quietly keeps its built-in password, and you find out from container logs several minutes after the image pull finished.",
	SeverityPolicy: "Blocking. The template's own author declared the setting required, and the fix is to type into a field that is already on screen.",
	Surfaces: []string{
		"The Docker app deploy dialog, above the Deploy button",
		"`POST /api/apps/deploy`, which refuses with 412 by calling this same check",
	},
	Outcomes: []*PrerequisitesCopyOutcome{
		PrerequisitesCopyAppsEnvAllPresent,
		PrerequisitesCopyAppsEnvMissingSecrets,
		PrerequisitesCopyAppsEnvMissingSettings,
	},
}

var PrerequisitesCopyAppsPortUnset = &PrerequisitesCopyOutcome{
	ID:          "unset",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityBlocking,
	Title:       "Choose a port",
	TitlePlural: "",
	Detail:      "Pick the host port this app should be reachable on.",
	Fix:         "Enter a port.",
	Vars:        nil,
}

var PrerequisitesCopyAppsPortHeldByKnown = &PrerequisitesCopyOutcome{
	ID:          "held_by_known",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityBlocking,
	Title:       "Port {port} is already in use",
	TitlePlural: "",
	Detail:      "Port {port} is taken by {holder}. Two things cannot publish on the same host port, so this deploy would fail once the image finished downloading.",
	Fix:         "Use the free port DockPanel suggests, or stop whatever holds this one.",
	Vars: []PrerequisitesCopyVar{
		{Name: "port", Example: "5432"},
		{Name: "holder", Example: "the app `pg-old`"},
	},
}

var PrerequisitesCopyAppsPortHeldByUnknown = &PrerequisitesCopyOutcome{
	ID:          "held_by_unknown",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityBlocking,
	Title:       "Port {port} is already in use",
	TitlePlural: "",
	Detail:      "Something on this server is already listening on port {port}. It isn't managed by DockPanel, so it may be another service you installed yourself. Pick a different port, or stop whatever is using this one.",
	Fix:         "Pick a different port. `ss -lntp | grep :{port}` on the server names the process.",
	Vars: []PrerequisitesCopyVar{
		{Name: "port", Example: "5432"},
	},
}

var PrerequisitesCopyAppsPortFree = &PrerequisitesCopyOutcome{
	ID:          "free",
	State:       PrerequisitesPrereqStateSatisfied,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Port {port} is free",
	TitlePlural: "",
	Detail:      "Nothing is listening on port {port}.",
	Fix:         "",
	Vars: []PrerequisitesCopyVar{
		{Name: "port", Example: "5432"},
	},
}

var PrerequisitesCopyAppsPortUnprobeable = &PrerequisitesCopyOutcome{
	ID:          "unprobeable",
	State:       PrerequisitesPrereqStateUnknown,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Couldn't check the port",
	TitlePlural: "",
	Detail:      "DockPanel couldn't ask this server whether port {port} is free, so it will be attempted as-is.",
	Fix:         "Nothing. This happens on a fleet member running an agent older than the port-check route; a check that cannot run must never turn into a refusal.",
	Vars: []PrerequisitesCopyVar{
		{Name: "port", Example: "5432"},
	},
}

var PrerequisitesCopyAppsPortCheck = &PrerequisitesCopyPrereq{
	Key:            "apps.port_available",
	Vertical:       "Docker apps",
	Question:       "Is the host port this app wants actually free?",
	Why:            "Two containers cannot publish on the same host port. The sites surface has refused colliding ports for years; apps never got the equivalent, so a collision surfaced as a Docker error after the image pull rather than before it.",
	SeverityPolicy: "Blocking when something is known to hold the port, because the deploy will certainly fail. Unknown — never a refusal — when the server could not be asked.",
	Surfaces: []string{
		"The Docker app deploy dialog, above the Deploy button",
		"`POST /api/apps/deploy`, which refuses with 412 by calling this same check",
	},
	Outcomes: []*PrerequisitesCopyOutcome{
		PrerequisitesCopyAppsPortUnset,
		PrerequisitesCopyAppsPortHeldByKnown,
		PrerequisitesCopyAppsPortHeldByUnknown,
		PrerequisitesCopyAppsPortFree,
		PrerequisitesCopyAppsPortUnprobeable,
	},
}

var PrerequisitesCopyAppsNameUnset = &PrerequisitesCopyOutcome{
	ID:          "unset",
	State:       PrerequisitesPrereqStateUnknown,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Name this app",
	TitlePlural: "",
	Detail:      "Give the app a name to continue.",
	Fix:         "Enter a name.",
	Vars:        nil,
}

var PrerequisitesCopyAppsNameTaken = &PrerequisitesCopyOutcome{
	ID:          "taken",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityBlocking,
	Title:       "An app called {name} already exists",
	TitlePlural: "",
	Detail:      "This server already runs an app named {name}. Container names have to be unique, so this deploy would be refused. Pick a different name.",
	Fix:         "Use the name DockPanel suggests, or choose your own.",
	Vars: []PrerequisitesCopyVar{
		{Name: "name", Example: "postgres"},
	},
}

var PrerequisitesCopyAppsNameAvailable = &PrerequisitesCopyOutcome{
	ID:          "available",
	State:       PrerequisitesPrereqStateSatisfied,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Name is available",
	TitlePlural: "",
	Detail:      "No other app is called {name}.",
	Fix:         "",
	Vars: []PrerequisitesCopyVar{
		{Name: "name", Example: "postgres"},
	},
}

var PrerequisitesCopyAppsNameCheck = &PrerequisitesCopyPrereq{
	Key:            "apps.name_available",
	Vertical:       "Docker apps",
	Question:       "Is this app name already taken on this server?",
	Why:            "Container names are unique per host, and the deploy form pre-fills the name with the template id — so deploying a second Postgres collides by default.",
	SeverityPolicy: "Blocking. Docker will refuse the name outright.",
	Surfaces: []string{
		"The Docker app deploy dialog, above the Deploy button",
		"`POST /api/apps/deploy`, which refuses with 412 by calling this same check",
	},
	Outcomes: []*PrerequisitesCopyOutcome{
		PrerequisitesCopyAppsNameUnset,
		PrerequisitesCopyAppsNameTaken,
		PrerequisitesCopyAppsNameAvailable,
	},
}

var PrerequisitesCopyAppsMemNotChecked = &PrerequisitesCopyOutcome{
	ID:          "not_checked",
	State:       PrerequisitesPrereqStateUnknown,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Memory not checked",
	TitlePlural: "",
	Detail:      "No memory limit was set for this app, or this server's memory couldn't be read.",
	Fix:         "",
	Vars:        nil,
}

var PrerequisitesCopyAppsMemOverTotal = &PrerequisitesCopyOutcome{
	ID:          "over_total",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityWarning,
	Title:       "That's more memory than this server has",
	TitlePlural: "",
	Detail:      "This app is limited to {want} MB, but the server only has {total} MB in total ({free} MB currently free). The limit will be accepted, but the container can never reach it — and the server will start swapping first.",
	Fix:         "Lower the limit, or resize the server. Nothing stops you deploying as-is.",
	Vars: []PrerequisitesCopyVar{
		{Name: "want", Example: "8192"},
		{Name: "total", Example: "2048"},
		{Name: "free", Example: "1100"},
	},
}

var PrerequisitesCopyAppsMemOverFree = &PrerequisitesCopyOutcome{
	ID:          "over_free",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityWarning,
	Title:       "Less free memory than this app is allowed",
	TitlePlural: "",
	Detail:      "This app is allowed {want} MB but only {free} MB of the server's {total} MB is free right now. It will still start; if it actually uses its full limit, the kernel will have to reclaim memory from something else.",
	Fix:         "Usually nothing — over-committing memory is normal. Worth a second look if the box is already swapping.",
	Vars: []PrerequisitesCopyVar{
		{Name: "want", Example: "1024"},
		{Name: "free", Example: "700"},
		{Name: "total", Example: "2048"},
	},
}

var PrerequisitesCopyAppsMemFits = &PrerequisitesCopyOutcome{
	ID:          "fits",
	State:       PrerequisitesPrereqStateSatisfied,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Enough memory",
	TitlePlural: "",
	Detail:      "{free} MB free, {want} MB requested.",
	Fix:         "",
	Vars: []PrerequisitesCopyVar{
		{Name: "free", Example: "1100"},
		{Name: "want", Example: "512"},
	},
}

var PrerequisitesCopyAppsMemCheck = &PrerequisitesCopyPrereq{
	Key:            "apps.resource_headroom",
	Vertical:       "Docker apps",
	Question:       "Does this server have the memory this app is being given?",
	Why:            "A container whose limit exceeds what the box can supply does not fail at deploy time. It fails later, under load, as an OOM kill — which is the worst possible moment to learn the number was never achievable.",
	SeverityPolicy: "Warning, never blocking. Over-committing memory is ordinary practice, the kernel will page, and the operator may know what is about to be freed. What is not acceptable is finding out from an OOM kill.",
	Surfaces: []string{
		"The Docker app deploy dialog, above the Deploy button",
	},
	Outcomes: []*PrerequisitesCopyOutcome{
		PrerequisitesCopyAppsMemNotChecked,
		PrerequisitesCopyAppsMemOverTotal,
		PrerequisitesCopyAppsMemOverFree,
		PrerequisitesCopyAppsMemFits,
	},
}

var PrerequisitesCopyMailDkimReady = &PrerequisitesCopyOutcome{
	ID:          "ready",
	State:       PrerequisitesPrereqStateSatisfied,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "DKIM signing key is ready",
	TitlePlural: "",
	Detail:      "Outgoing mail for {domain} is signed.",
	Fix:         "",
	Vars: []PrerequisitesCopyVar{
		{Name: "domain", Example: "example.com"},
	},
}

var PrerequisitesCopyMailDkimMissing = &PrerequisitesCopyOutcome{
	ID:          "missing",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityWarning,
	Title:       "No DKIM signing key",
	TitlePlural: "",
	Detail:      "DKIM key generation failed when {domain} was added, so outgoing mail isn't signed and there is no DKIM record to publish. Check that the mail stack is installed, then remove and re-add the domain to retry.",
	Fix:         "Confirm the mail server is installed, then remove and re-add the domain.",
	Vars: []PrerequisitesCopyVar{
		{Name: "domain", Example: "example.com"},
	},
}

var PrerequisitesCopyMailDkimCheck = &PrerequisitesCopyPrereq{
	Key:            "mail.dkim_key",
	Vertical:       "Mail",
	Question:       "Does this domain have a DKIM signing key?",
	Why:            "Without a key there is nothing to sign outgoing mail with and no DKIM record to publish. Adding a domain stores it even when key generation fails, so this state is reachable and would otherwise be invisible.",
	SeverityPolicy: "Warning. Mail still flows; it is simply unsigned, and no control in the panel is gated on it.",
	Surfaces: []string{
		"The Mail domain's DNS tab",
		"`GET /api/mail/domains/{id}/preflight`",
	},
	Outcomes: []*PrerequisitesCopyOutcome{
		PrerequisitesCopyMailDkimReady,
		PrerequisitesCopyMailDkimMissing,
	},
}

var PrerequisitesCopyMailDnsNoPublicIp = &PrerequisitesCopyOutcome{
	ID:          "no_public_ip",
	State:       PrerequisitesPrereqStateUnknown,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Couldn't determine this server's public address",
	TitlePlural: "",
	Detail:      "DockPanel could not determine the public address of the server this domain is on, so it can't tell you which records the domain needs.",
	Fix:         "Nothing to do at the registrar. If the domain is on this server, confirm it can reach the internet; if it is on another server in the fleet, confirm that server's agent is online — its address is recorded when the agent checks in.",
	Vars:        nil,
}

var PrerequisitesCopyMailDnsUnreadable = &PrerequisitesCopyOutcome{
	ID:          "unreadable",
	State:       PrerequisitesPrereqStateUnknown,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Couldn't check DNS",
	TitlePlural: "",
	Detail:      "DockPanel couldn't run DNS lookups on this server, so it can't verify these records. Create them if you haven't already.",
	Fix:         "Create the records shown. They are correct whether or not the lookup ran.",
	Vars:        nil,
}

var PrerequisitesCopyMailDnsAllPublished = &PrerequisitesCopyOutcome{
	ID:          "all_published",
	State:       PrerequisitesPrereqStateSatisfied,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "{domain}'s mail records are published",
	TitlePlural: "",
	Detail:      "MX, SPF, DKIM and DMARC all resolve and point at this server. Mail from this domain can be authenticated.",
	Fix:         "",
	Vars: []PrerequisitesCopyVar{
		{Name: "domain", Example: "example.com"},
	},
}

var PrerequisitesCopyMailDnsMissingAll = &PrerequisitesCopyOutcome{
	ID:          "missing_all",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityWarning,
	Title:       "{domain} has no mail DNS records yet",
	TitlePlural: "",
	Detail:      "{count} of {total} records for {domain} are missing or point somewhere else: {missing}.\n\nUntil they are correct, receiving servers can't verify that this server may send mail for {domain} — messages are likely to be filed as spam or rejected. Create the records below at whoever manages this domain's DNS; DockPanel re-checks automatically.",
	Fix:         "Create every record shown. Each card says whether that record is published or missing, so you never have to re-do the ones already correct.",
	Vars: []PrerequisitesCopyVar{
		{Name: "domain", Example: "example.com"},
		{Name: "count", Example: "5"},
		{Name: "total", Example: "5"},
		{Name: "missing", Example: "A example.com, MX example.com, TXT example.com"},
	},
}

var PrerequisitesCopyMailDnsMissingSome = &PrerequisitesCopyOutcome{
	ID:          "missing_some",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityWarning,
	Title:       "{count} mail record still missing for {domain}",
	TitlePlural: "{count} mail records still missing for {domain}",
	Detail:      "{count} of {total} records for {domain} are missing or point somewhere else: {missing}.\n\nUntil they are correct, receiving servers can't verify that this server may send mail for {domain} — messages are likely to be filed as spam or rejected. Create the records below at whoever manages this domain's DNS; DockPanel re-checks automatically.",
	Fix:         "Create the records marked missing. The published ones need no attention.",
	Vars: []PrerequisitesCopyVar{
		{Name: "domain", Example: "example.com"},
		{Name: "count", Example: "2"},
		{Name: "total", Example: "5"},
		{Name: "missing", Example: "TXT dockpanel._domainkey.example.com, TXT _dmarc.example.com"},
	},
}

var PrerequisitesCopyMailDnsCheck = &PrerequisitesCopyPrereq{
	Key:            "mail.dns_published",
	Vertical:       "Mail",
	Question:       "Are this domain's mail records published, and do they point at this server?",
	Why:            "Mail leaves the server whether or not these records exist — it just doesn't arrive. Receiving servers use SPF, DKIM and DMARC to decide whether to believe a message came from your domain, and a domain missing them lands in spam folders with nothing anywhere saying so.\n\nThis check verifies **correctness, not existence**, which is the whole point of it: through v2.29.0 the older DNS check passed on any MX record at all (including a competitor's), any string beginning `v=spf1` (including one that forbids this server), and any DKIM record containing `p=` (including a stale key from a previous install). Run against `gmail.com` — a domain whose mail goes to Google and whose SPF does not authorise us at all — the old logic reported MX, SPF and DMARC all passing.",
	SeverityPolicy: "Warning, never blocking, and this follows the rule rather than ducking it: nothing in the panel is gated on these records. There is no control to disable, so there is nothing to block.",
	Surfaces: []string{
		"The Mail domain's DNS tab",
		"`GET /api/mail/domains/{id}/preflight`",
		"`GET /api/mail/domains/{id}/dns-check`, the long-standing Check DNS button, which now delegates here",
	},
	Outcomes: []*PrerequisitesCopyOutcome{
		PrerequisitesCopyMailDnsNoPublicIp,
		PrerequisitesCopyMailDnsUnreadable,
		PrerequisitesCopyMailDnsAllPublished,
		PrerequisitesCopyMailDnsMissingAll,
		PrerequisitesCopyMailDnsMissingSome,
	},
}

var PrerequisitesCopyBackupsDestUploads = &PrerequisitesCopyOutcome{
	ID:          "uploads_offsite",
	State:       PrerequisitesPrereqStateSatisfied,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Backups are copied off this server",
	TitlePlural: "",
	Detail:      "'{policy}' uploads to {destination}.",
	Fix:         "",
	Vars: []PrerequisitesCopyVar{
		{Name: "policy", Example: "Nightly"},
		{Name: "destination", Example: "wasabi-eu"},
	},
}

var PrerequisitesCopyBackupsDestDeleted = &PrerequisitesCopyOutcome{
	ID:          "destination_deleted",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityWarning,
	Title:       "This policy's backup destination no longer exists",
	TitlePlural: "",
	Detail:      "'{policy}' is set to upload to a destination that has since been deleted, so its backups are staying on this server. Pick a destination again, or create a new one.",
	Fix:         "Choose a destination on the policy, or re-create the one that was removed.",
	Vars: []PrerequisitesCopyVar{
		{Name: "policy", Example: "Nightly"},
	},
}

var PrerequisitesCopyBackupsDestLocalWithOptions = &PrerequisitesCopyOutcome{
	ID:          "local_only_with_destinations",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityWarning,
	Title:       "Backups never leave this server",
	TitlePlural: "",
	Detail:      "'{policy}' writes its backups to this server's own disk and nowhere else. You already have {available} destination(s) configured — choosing one means these backups survive losing this machine.",
	Fix:         "Edit the policy and pick one of the destinations you have already configured.",
	Vars: []PrerequisitesCopyVar{
		{Name: "policy", Example: "Nightly"},
		{Name: "available", Example: "2"},
	},
}

var PrerequisitesCopyBackupsDestLocalNoOptions = &PrerequisitesCopyOutcome{
	ID:          "local_only_no_destinations",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityWarning,
	Title:       "Backups never leave this server",
	TitlePlural: "",
	Detail:      "'{policy}' writes its backups to this server's own disk and nowhere else. That protects you from a bad deploy or a dropped table, but not from losing the server: disk failure, a deleted instance or a compromised host take the backups with the data.\n\nAdd an S3 or SFTP destination and select it on this policy.",
	Fix:         "Add an S3 or SFTP destination, then select it on the policy.",
	Vars: []PrerequisitesCopyVar{
		{Name: "policy", Example: "Nightly"},
	},
}

var PrerequisitesCopyBackupsDestCheck = &PrerequisitesCopyPrereq{
	Key:            "backups.destination_configured",
	Vertical:       "Backups",
	Question:       "Does this backup policy send its backups anywhere off this server?",
	Why:            "A policy with no destination writes its archives to a directory on the same disk it is insuring. That protects against a bad deploy or a dropped table, and against nothing else: disk failure, a deleted instance, ransomware or a closed provider account take the backups with the data.",
	SeverityPolicy: "Warning, not blocking — and this one is worth defending. Local-only backups are a legitimate choice for a box whose real protection is provider snapshots, and refusing to save the policy would be the panel overriding a decision that is not its to make. What is not legitimate is making that choice by accident and never being told.",
	Surfaces: []string{
		"Backup Manager → Overview",
		"`GET /api/backup-orchestrator/preflight`",
	},
	Outcomes: []*PrerequisitesCopyOutcome{
		PrerequisitesCopyBackupsDestUploads,
		PrerequisitesCopyBackupsDestDeleted,
		PrerequisitesCopyBackupsDestLocalWithOptions,
		PrerequisitesCopyBackupsDestLocalNoOptions,
	},
}

var PrerequisitesCopyBackupsPolicyNothing = &PrerequisitesCopyOutcome{
	ID:          "nothing_to_back_up",
	State:       PrerequisitesPrereqStateUnknown,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Nothing to back up yet",
	TitlePlural: "",
	Detail:      "Once you add a site or a database, DockPanel can back it up on a schedule.",
	Fix:         "",
	Vars:        nil,
}

var PrerequisitesCopyBackupsPolicyRunning = &PrerequisitesCopyOutcome{
	ID:          "running",
	State:       PrerequisitesPrereqStateSatisfied,
	Severity:    PrerequisitesPrereqSeverityInfo,
	Title:       "Scheduled backups are running",
	TitlePlural: "",
	Detail:      "{count} enabled backup policy/policies.",
	Fix:         "",
	Vars: []PrerequisitesCopyVar{
		{Name: "count", Example: "1"},
	},
}

var PrerequisitesCopyBackupsPolicyNone = &PrerequisitesCopyOutcome{
	ID:          "none_enabled",
	State:       PrerequisitesPrereqStateUnsatisfied,
	Severity:    PrerequisitesPrereqSeverityWarning,
	Title:       "Nothing is being backed up on a schedule",
	TitlePlural: "",
	Detail:      "This server hosts {sites} site(s) and has no enabled backup policy, so nothing is backed up automatically. Manual backups still work, but they only exist when somebody remembers.",
	Fix:         "Create a backup policy. \"Protect Everything\" configures sites, databases and volumes in one step.",
	Vars: []PrerequisitesCopyVar{
		{Name: "sites", Example: "3"},
	},
}

var PrerequisitesCopyBackupsPolicyCheck = &PrerequisitesCopyPrereq{
	Key:            "backups.policy_configured",
	Vertical:       "Backups",
	Question:       "Is anything being backed up on a schedule at all?",
	Why:            "Prior to, and distinct from, the destination question — a panel with no enabled policy has nothing to send anywhere. Manual backups still work, but they only exist when somebody remembers.",
	SeverityPolicy: "Warning when the server actually hosts something. A panel with no sites is not neglecting anything, so that reports as unknown rather than as a fault.",
	Surfaces: []string{
		"Backup Manager → Overview",
		"`GET /api/backup-orchestrator/preflight`",
	},
	Outcomes: []*PrerequisitesCopyOutcome{
		PrerequisitesCopyBackupsPolicyNothing,
		PrerequisitesCopyBackupsPolicyRunning,
		PrerequisitesCopyBackupsPolicyNone,
	},
}

// PrerequisitesCopyPrereqs is every prerequisite, in the order the manual presents them.
var PrerequisitesCopyPrereqs = []*PrerequisitesCopyPrereq{
	PrerequisitesCopyDnsPointsHereCheck,
	PrerequisitesCopyAppsEnvCheck,
	PrerequisitesCopyAppsPortCheck,
	PrerequisitesCopyAppsNameCheck,
	PrerequisitesCopyAppsMemCheck,
	PrerequisitesCopyMailDkimCheck,
	PrerequisitesCopyMailDnsCheck,
	PrerequisitesCopyBackupsDestCheck,
	PrerequisitesCopyBackupsPolicyCheck,
}

// PrerequisitesCopyFields is every field whose passive guidance is owned by this
// registry. Not every field in the product: a registry that must grow by one
// entry per input is a registry nobody maintains.
var PrerequisitesCopyFields = []PrerequisitesCopyField{
	{
		ID:      "setup.admin_password",
		Surface: "Create your admin account",
		Label:   "Password",
		// The very first field a new operator ever types into. The 8-character
		// rule was previously enforced only by the browser's native minLength,
		// which rejects the form before any of our own text can explain why.
		Help:        "At least 8 characters. This signs you in to the panel itself — not to any site you host with it.",
		More:        "This is the panel's first account and a full administrator: it can reach every site, database and container on this server. There is no password-reset email configured yet, so store it somewhere you trust before continuing. You can add two-factor authentication straight afterwards from Settings.",
		EscalatesTo: "",
	},
	{
		ID:          "sites.create.domain",
		Surface:     "Create a site",
		Label:       "Domain",
		Help:        "Your site's public domain name (e.g. example.com). It needs to point at this server before HTTPS can be issued — DockPanel checks that for you below.",
		More:        "You can create the site before the domain resolves; only the certificate needs DNS. If you are moving a live site, create it here first, confirm it serves correctly, and change the DNS record last — that way the switchover has no gap.",
		EscalatesTo: "dns.points_here",
	},
	{
		ID:      "sites.create.runtime",
		Surface: "Create a site",
		Label:   "Runtime",
		// Tooltip-only: the line under this select already describes whichever
		// runtime is currently chosen, which is more useful than anything static.
		Help:        "",
		More:        "Static serves files as they are. PHP runs them through PHP-FPM. Node and Python get a managed systemd process with nginx in front. Reverse Proxy is the one to pick when something else already listens on a port — a Docker app, or a service you run yourself — and DockPanel then owns only the front end and the certificate.",
		EscalatesTo: "",
	},
	{
		ID:          "sites.create.admin_password",
		Surface:     "Create a site",
		Label:       "Admin Password",
		Help:        "Leave blank and DockPanel generates one, then stores it in this site's Secrets vault — it is not shown again anywhere else.",
		More:        "Open the site, then Secrets, to read it back. Earlier versions generated this password, used it and discarded it, which left you unable to log in to the site you had just created.",
		EscalatesTo: "",
	},
	{
		ID:          "sites.create.proxy_port",
		Surface:     "Create a site",
		Label:       "Proxy Port",
		Help:        "The local port your application listens on.",
		More:        "The port as seen from the server itself, not a public one. nginx connects to it on 127.0.0.1; nothing needs to be opened in the firewall.",
		EscalatesTo: "",
	},
	{
		ID:          "apps.deploy.name",
		Surface:     "Deploy a Docker app",
		Label:       "Container Name",
		Help:        "Names the container on this server. Must be unique — DockPanel suggests a free one if it isn't.",
		More:        "The container is created as `dockpanel-app-<name>`, so this name is what you will see in `docker ps` minus that prefix.",
		EscalatesTo: "apps.name_available",
	},
	{
		ID:          "apps.deploy.port",
		Surface:     "Deploy a Docker app",
		Label:       "Host Port",
		Help:        "The port on this server the app will answer on. DockPanel checks it is free before the image is pulled.",
		More:        "Published on 127.0.0.1 by default. To expose the app publicly, put a Reverse Proxy site in front of it — that gets you a certificate and a domain instead of a port number.",
		EscalatesTo: "apps.port_available",
	},
	{
		ID:          "apps.deploy.memory",
		Surface:     "Deploy a Docker app",
		Label:       "Memory (MB)",
		Help:        "Hard ceiling for this container. Leave blank for no limit.",
		More:        "A limit above what the server has is accepted but unreachable — the box swaps first. DockPanel warns rather than refuses, because over-committing is ordinary and you may know what is about to be freed.",
		EscalatesTo: "apps.resource_headroom",
	},
	{
		ID:          "backups.policy.destination",
		Surface:     "Backup policy",
		Label:       "Destination",
		Help:        "Where a copy is uploaded after each backup. Leave empty and backups stay on this server's own disk.",
		More:        "A backup on the disk it protects covers a bad deploy or a dropped table, and nothing worse. Destinations are S3-compatible storage or any SFTP server. SFTP destinations that authenticate by PASSWORD need sshpass on the server the backup runs from: fresh installs and servers added through the agent installer get it automatically, but a panel upgraded in place does not, because update.sh upgrades binaries and installs no packages. When it is missing, Test Connection now says so in those words and Settings can install it onto that server for you — you are no longer asked to run a package manager by hand. Key-authenticated SFTP and every S3 destination are unaffected.",
		EscalatesTo: "backups.destination_configured",
	},
	{
		ID:      "mail.domain.records",
		Surface: "Mail domain → DNS",
		Label:   "Required DNS Records",
		// Tooltip-only: the standing line names the domain being viewed.
		Help:        "",
		More:        "These are the records DockPanel publishes for you when it manages the zone, and the ones to create by hand when it doesn't. Verify DNS checks that each points at this server rather than merely that something exists — a domain whose MX belongs to another provider is reported as such, not as a pass.",
		EscalatesTo: "mail.dns_published",
	},
}
