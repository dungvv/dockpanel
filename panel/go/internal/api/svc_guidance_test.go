package api

// Ported from services/prerequisites/copy.rs `tests`.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A value that happens to contain a placeholder must survive intact. Policy
// and container names are typed by the operator; under a replace-in-sequence
// fill, a policy called `{available}` would come back rendered as a number.
func TestGuidanceValueContainingAPlaceholderIsNotSubstitutedAgain(t *testing.T) {
	r := PrerequisitesCopyBackupsDestCheck.Result(PrerequisitesCopyBackupsDestLocalWithOptions,
		[][2]string{{"policy", "{available}"}, {"available", "2"}})
	if !strings.Contains(r.Detail, "'{available}' writes its backups") {
		t.Fatalf("the operator's own text was rewritten: %s", r.Detail)
	}
	if !strings.Contains(r.Detail, "already have 2 destination") {
		t.Fatal(r.Detail)
	}
}

// An unbalanced brace must not hang the renderer.
func TestGuidanceUnterminatedPlaceholderIsEmittedVerbatim(t *testing.T) {
	if got := prerequisitesCopyFill("a {b", [][2]string{{"b", "x"}}); got != "a {b" {
		t.Fatal(got)
	}
	if got := prerequisitesCopyFill("{unknown} tail", nil); got != "{unknown} tail" {
		t.Fatal(got)
	}
}

func TestGuidanceEveryPrereqKeyIsUniqueAndNamespacedByItsVertical(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range PrerequisitesCopyPrereqs {
		if seen[p.Key] {
			t.Errorf("duplicate prerequisite key `%s`", p.Key)
		}
		seen[p.Key] = true
		if !strings.Contains(p.Key, ".") {
			t.Errorf("`%s` must be namespaced, e.g. `dns.points_here`", p.Key)
		}
	}
}

func TestGuidanceOutcomeIDsAreUniqueWithinTheirCheck(t *testing.T) {
	for _, p := range PrerequisitesCopyPrereqs {
		seen := map[string]bool{}
		for _, o := range p.Outcomes {
			if seen[o.ID] {
				t.Errorf("`%s` has two outcomes called `%s`", p.Key, o.ID)
			}
			seen[o.ID] = true
		}
	}
}

// Every placeholder must be declared, or the user is shown a literal
// `{domain}` — the exact class of defect this registry exists to prevent.
func TestGuidanceRenderingAnOutcomeWithItsDeclaredVarsLeavesNoPlaceholder(t *testing.T) {
	for _, p := range PrerequisitesCopyPrereqs {
		for _, o := range p.Outcomes {
			vars := prerequisitesCopyExampleVars(o)
			for label, template := range map[string]string{"title": o.Title, "title_plural": o.TitlePlural, "detail": o.Detail} {
				if rendered := prerequisitesCopyFill(template, vars); strings.Contains(rendered, "{") {
					t.Errorf("`%s`/`%s` %s has an undeclared placeholder: %s", p.Key, o.ID, label, rendered)
				}
			}
		}
	}
}

// A declared var that no template uses is dead weight that will outlive the
// sentence it was written for.
func TestGuidanceEveryDeclaredVarIsActuallyUsed(t *testing.T) {
	for _, p := range PrerequisitesCopyPrereqs {
		for _, o := range p.Outcomes {
			for _, v := range o.Vars {
				needle := "{" + v.Name + "}"
				if !strings.Contains(o.Title, needle) && !strings.Contains(o.TitlePlural, needle) && !strings.Contains(o.Detail, needle) {
					t.Errorf("`%s`/`%s` declares `%s` but never uses it", p.Key, o.ID, v.Name)
				}
			}
		}
	}
}

// A plural title is selected by the `count` var; declaring one without it
// means the plural form can never be reached.
func TestGuidancePluralTitleRequiresACountVar(t *testing.T) {
	for _, p := range PrerequisitesCopyPrereqs {
		for _, o := range p.Outcomes {
			if o.TitlePlural == "" {
				continue
			}
			has := false
			for _, v := range o.Vars {
				has = has || v.Name == "count"
			}
			if !has {
				t.Errorf("`%s`/`%s` has a plural title but no `count` var to select it", p.Key, o.ID)
			}
		}
	}
}

func TestGuidancePluralTitleIsUsedOnlyWhenCountIsNotOne(t *testing.T) {
	one := PrerequisitesCopyAppsEnvCheck.Result(PrerequisitesCopyAppsEnvMissingSecrets, [][2]string{
		{"first_label", "POSTGRES_PASSWORD"}, {"count", "1"}, {"template_id", "postgres"}, {"names", "POSTGRES_PASSWORD"},
	})
	if one.Title != "POSTGRES_PASSWORD needs a value" {
		t.Fatal(one.Title)
	}
	many := PrerequisitesCopyAppsEnvCheck.Result(PrerequisitesCopyAppsEnvMissingSecrets, [][2]string{
		{"first_label", "POSTGRES_PASSWORD"}, {"count", "3"}, {"template_id", "postgres"}, {"names", "a, b, c"},
	})
	if many.Title != "3 required settings have no value" {
		t.Fatal(many.Title)
	}
}

// The runtime result must carry the check's key, not the outcome's id — the
// frontend and every test selector key off the former.
func TestGuidanceRenderedResultCarriesTheCheckKeyAndItsOutcomeTier(t *testing.T) {
	r := PrerequisitesCopyDnsPointsHereCheck.Result(PrerequisitesCopyDnsNotResolving, [][2]string{{"domain", "example.com"}})
	if r.Key != "dns.points_here" || r.Title != "example.com doesn't resolve yet" || !r.Blocks() {
		t.Fatal(r)
	}
	ok := PrerequisitesCopyDnsPointsHereCheck.Result(PrerequisitesCopyDnsPointsHere, [][2]string{{"domain", "example.com"}, {"server_ip", "1.2.3.4"}})
	if ok.Blocks() || ok.Detail != "example.com resolves to this server (1.2.3.4)." {
		t.Fatal(ok)
	}
}

// Outcome.Blocks and PrereqResult.Blocks must agree, or the manual documents
// a gate the product does not apply.
func TestGuidanceManualsNotionOfBlockingMatchesTheRuntimes(t *testing.T) {
	for _, p := range PrerequisitesCopyPrereqs {
		for _, o := range p.Outcomes {
			if o.Blocks() != p.Result(o, prerequisitesCopyExampleVars(o)).Blocks() {
				t.Errorf("`%s`/`%s` is documented differently from how it behaves", p.Key, o.ID)
			}
		}
	}
}

// Every field that claims to escalate must name a check that exists.
func TestGuidanceFieldEscalationsResolveToARealPrerequisite(t *testing.T) {
	for _, f := range PrerequisitesCopyFields {
		if f.EscalatesTo == "" {
			continue
		}
		found := false
		for _, p := range PrerequisitesCopyPrereqs {
			found = found || p.Key == f.EscalatesTo
		}
		if !found {
			t.Errorf("field `%s` escalates to `%s`, which is not a prerequisite", f.ID, f.EscalatesTo)
		}
	}
}

// An entry that says nothing is a row in a registry that looks maintained and isn't.
func TestGuidanceEveryFieldEntrySaysSomething(t *testing.T) {
	for _, f := range PrerequisitesCopyFields {
		if f.Help == "" && f.More == "" {
			t.Errorf("field `%s` has neither a help line nor a tooltip", f.ID)
		}
	}
}

func TestGuidanceFieldIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range PrerequisitesCopyFields {
		if seen[f.ID] {
			t.Errorf("duplicate field id `%s`", f.ID)
		}
		seen[f.ID] = true
	}
}

// The generated TypeScript must be valid to paste into the frontend: the
// Debug-style escaping is what makes an em-dash-and-quotes sentence safe, and
// a stray raw newline would break the module.
func TestGuidanceGeneratedFrontendModuleQuotesEveryString(t *testing.T) {
	ts := PrerequisitesCopyFrontendModule()
	if !strings.Contains(ts, "export const FIELD_GUIDANCE") {
		t.Fatal("no FIELD_GUIDANCE")
	}
	for _, f := range PrerequisitesCopyFields {
		if !strings.Contains(ts, prerequisitesCopyDebugStr(f.ID)+": {") {
			t.Errorf("missing field %s", f.ID)
		}
	}
	for _, line := range strings.Split(ts, "\n") {
		if strings.Count(line, `"`)%2 != 0 {
			t.Errorf("unbalanced quotes in generated line: %s", line)
		}
	}
}

func TestGuidanceManualDocumentsEveryCheckAndEveryOutcome(t *testing.T) {
	md := PrerequisitesCopyManual()
	for _, p := range PrerequisitesCopyPrereqs {
		if !strings.Contains(md, p.Key) {
			t.Errorf("the manual omits `%s`", p.Key)
		}
		for _, o := range p.Outcomes {
			title := prerequisitesCopyEscapeTable(prerequisitesCopyFill(o.Title, prerequisitesCopyExampleVars(o)))
			if !strings.Contains(md, title) {
				t.Errorf("the manual omits `%s`/`%s` (%s)", p.Key, o.ID, title)
			}
		}
	}
}

// guidanceRepoRoot is the repository root, derived from this package's
// directory (go test runs in it) rather than wherever the caller stands.
func guidanceRepoRoot(t *testing.T) string {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// guidanceAssertGenerated asserts a generated artefact matches what the
// registry emits — or rewrites it when UPDATE_GUIDANCE_DOCS is set.
//
// This is the mechanism the whole exercise exists for. It is not a reminder
// to update the docs: it is a failing test that stands between a changed
// sentence and a merge, so the manual physically cannot describe a version
// of the product that no longer exists.
func guidanceAssertGenerated(t *testing.T, relative, expected string) {
	t.Helper()
	path := filepath.Join(guidanceRepoRoot(t), relative)
	if _, update := os.LookupEnv("UPDATE_GUIDANCE_DOCS"); update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(expected), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s is missing (%v). Regenerate it:\n    UPDATE_GUIDANCE_DOCS=1 go test ./internal/api -run Guidance", relative, err)
	}
	found := string(b)
	if found == expected {
		return
	}
	fl, el := strings.Split(found, "\n"), strings.Split(expected, "\n")
	line, f, e := min(len(fl), len(el))+1, "<end of file>", "<more lines>"
	for i := 0; i < min(len(fl), len(el)); i++ {
		if fl[i] != el[i] {
			line, f, e = i+1, fl[i], el[i]
			break
		}
	}
	t.Fatalf("%s is out of date — the copy registry changed and this file did not.\n"+
		"First difference at line %d:\n  committed: %s\n  registry:  %s\n\n"+
		"Regenerate it:\n    UPDATE_GUIDANCE_DOCS=1 go test ./internal/api -run Guidance", relative, line, f, e)
}

func TestGuidanceManualIsCurrent(t *testing.T) {
	guidanceAssertGenerated(t, "docs/guides/prerequisites.md", PrerequisitesCopyManual())
}

func TestGuidanceFrontendModuleIsCurrent(t *testing.T) {
	guidanceAssertGenerated(t, "panel/frontend/src/content/guidance.generated.ts", PrerequisitesCopyFrontendModule())
}

// Every field entry must actually be rendered somewhere: copy that documents
// a screen which does not show it is the failure this registry exists to
// prevent. Deliberately a cross-tree assertion — the backend owns the copy
// and the frontend renders it, so nothing inside either tree alone can catch it.
func TestGuidanceEveryFieldEntryIsRenderedByTheFrontend(t *testing.T) {
	var rendered strings.Builder
	src := filepath.Join(guidanceRepoRoot(t), "panel/frontend/src")
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".tsx") {
			b, _ := os.ReadFile(path)
			rendered.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal("read frontend src: ", err)
	}
	all := rendered.String()
	for _, f := range PrerequisitesCopyFields {
		needle := fmt.Sprintf("%q", f.ID)
		if !strings.Contains(all, needle) {
			t.Errorf("field `%s` is in the registry (and therefore in the manual) but no .tsx renders "+
				"it — either wire it with <FieldHelp id=%s/> or remove the entry", f.ID, needle)
		}
	}
}

// The generated page has to be reachable, or it is a file nobody reads.
func TestGuidanceManualIsListedInTheDocsSummary(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(guidanceRepoRoot(t), "docs/SUMMARY.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "guides/prerequisites.md") {
		t.Fatal("docs/SUMMARY.md must link the generated page, or mdbook will not render it")
	}
}

// A table cell containing a raw pipe silently truncates the row.
func TestGuidanceGeneratedTableRowsHaveAStableColumnCount(t *testing.T) {
	for _, line := range strings.Split(PrerequisitesCopyManual(), "\n") {
		if strings.HasPrefix(line, "| ") && !strings.HasPrefix(line, "|---") {
			if n := strings.Count(line, "|") - strings.Count(line, `\|`); n != 4 {
				t.Errorf("table row has the wrong number of cells: %s", line)
			}
		}
	}
}
