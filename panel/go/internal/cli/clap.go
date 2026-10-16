package cli

// Help, usage and error rendering in clap 4's format (no wrap_help feature:
// lines are never wrapped), so `--help` and usage errors read exactly like the
// Rust CLI. Cobra only does the parsing.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type styler bool

func (s styler) wrap(code, text string) string {
	if !s {
		return text
	}
	return code + text + "\x1b[0m"
}
func (s styler) header(t string) string  { return s.wrap("\x1b[1m\x1b[4m", t) }
func (s styler) literal(t string) string { return s.wrap("\x1b[1m", t) }
func (s styler) invalid(t string) string { return s.wrap("\x1b[33m", t) }
func (s styler) valid(t string) string   { return s.wrap("\x1b[32m", t) }
func (s styler) err(t string) string     { return s.wrap("\x1b[1m\x1b[31m", t) }

// colorEnabled follows anstream's auto detection.
func colorEnabled(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if v := os.Getenv("CLICOLOR_FORCE"); v != "" && v != "0" {
		return true
	}
	return os.Getenv("TERM") != "dumb" && term.IsTerminal(int(f.Fd()))
}

func specOf(c *cobra.Command) *spec {
	if s := specs[c]; s != nil {
		return s
	}
	return &spec{}
}

func valueName(long string) string { return strings.ToUpper(strings.ReplaceAll(long, "-", "_")) }

// display is how clap names an arg in errors: "--port <PORT>" / "<NAME>".
func (f flagDef) display() string {
	if f.boolean {
		return "--" + f.long
	}
	return "--" + f.long + " <" + valueName(f.long) + ">"
}

var (
	outputFlag  = flagDef{long: "output", short: "o", def: "table", help: "Output format: table (default) or json"}
	helpFlag    = flagDef{long: "help", short: "h", boolean: true, help: "Print help"}
	versionFlag = flagDef{long: "version", short: "V", boolean: true, help: "Print version"}
)

// optionList returns a command's options in clap's display order: sorted by
// (display order, short-or-long key). Clap gives a propagated global arg the
// display order it had on the root (0), so -o/--output lands among the first
// local options rather than last. Help (and the root's version) come last.
func optionList(c *cobra.Command) []flagDef {
	s := specOf(c)
	if s.isHelp {
		return nil
	}
	if s.isRoot {
		return []flagDef{outputFlag, helpFlag, versionFlag}
	}
	type entry struct {
		f    flagDef
		ord  int
		key  string
		decl int
	}
	key := func(f flagDef) string {
		if f.short != "" {
			if strings.ToLower(f.short) == f.short {
				return f.short + "0"
			}
			return strings.ToLower(f.short) + "1"
		}
		return f.long
	}
	var list []entry
	shadowed := false
	for i, f := range s.flags {
		list = append(list, entry{f, i, key(f), i})
		shadowed = shadowed || f.long == "output"
	}
	if !shadowed {
		list = append(list, entry{outputFlag, 0, "o0", len(list)})
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].ord != list[j].ord {
			return list[i].ord < list[j].ord
		}
		return list[i].key < list[j].key
	})
	out := make([]flagDef, 0, len(list)+1)
	for _, e := range list {
		out = append(out, e.f)
	}
	return append(out, helpFlag)
}

func visibleSubs(c *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, sc := range c.Commands() {
		if !sc.Hidden {
			out = append(out, sc)
		}
	}
	return out
}

func usageLine(c *cobra.Command, st styler) string {
	s := specOf(c)
	if s.isHelp {
		return st.literal(c.CommandPath()) + " [COMMAND]..."
	}
	parts := []string{st.literal(c.CommandPath()), "[OPTIONS]"}
	for _, f := range s.flags {
		if f.required {
			parts = append(parts, st.literal("--"+f.long)+" <"+valueName(f.long)+">")
		}
	}
	for _, a := range s.args {
		parts = append(parts, "<"+a.name+">")
	}
	if len(visibleSubs(c)) > 0 {
		if s.subRequired {
			parts = append(parts, "<COMMAND>")
		} else {
			parts = append(parts, "[COMMAND]")
		}
	}
	return strings.Join(parts, " ")
}

// smartUsage is clap's usage for errors once some args were given: required
// args plus the ones actually used, without [OPTIONS].
func smartUsage(c *cobra.Command, st styler) string {
	s := specOf(c)
	parts := []string{st.literal(c.CommandPath())}
	for _, f := range s.flags {
		if f.required || c.Flags().Changed(f.long) {
			parts = append(parts, f.display())
		}
	}
	for _, a := range s.args {
		parts = append(parts, "<"+a.name+">")
	}
	return strings.Join(parts, " ")
}

func writeSection(b *strings.Builder, st styler, title string, rows [][2]string) {
	if len(rows) == 0 {
		return
	}
	width := 0
	for _, r := range rows {
		width = max(width, len([]rune(r[0])))
	}
	b.WriteString("\n" + st.header(title) + "\n")
	for _, r := range rows {
		line := "  " + r[0] + strings.Repeat(" ", width-len([]rune(r[0])))
		if r[1] != "" {
			line += "  " + r[1]
		}
		b.WriteString(line + "\n")
	}
}

func helpText(c *cobra.Command, color bool) string {
	st := styler(color)
	s := specOf(c)
	var b strings.Builder
	b.WriteString(c.Short + "\n\n")
	b.WriteString(st.header("Usage:") + " " + usageLine(c, st) + "\n")

	var cmds [][2]string
	for _, sc := range visibleSubs(c) {
		cmds = append(cmds, [2]string{sc.Name(), sc.Short})
	}
	writeSection(&b, st, "Commands:", cmds)

	var args [][2]string
	if s.isHelp {
		args = append(args, [2]string{"[COMMAND]...", "Print help for the subcommand(s)"})
	}
	for _, a := range s.args {
		h := a.help
		if len(a.possible) > 0 {
			h += " [possible values: " + strings.Join(a.possible, ", ") + "]"
		}
		args = append(args, [2]string{"<" + a.name + ">", h})
	}
	writeSection(&b, st, "Arguments:", args)

	var opts [][2]string
	for _, f := range optionList(c) {
		// The padding is computed on the plain text, so style after measuring.
		name := "    "
		if f.short != "" {
			name = "-" + f.short + ", "
		}
		name += "--" + f.long
		if !f.boolean {
			name += " <" + valueName(f.long) + ">"
		}
		h := f.help
		if f.def != "" && !f.boolean {
			h += " [default: " + f.def + "]"
		}
		opts = append(opts, [2]string{name, h})
	}
	writeSection(&b, st, "Options:", opts)
	return b.String()
}

// clapError formats a usage error; usage == "" omits the Usage block.
func clapError(c *cobra.Command, msg string, withUsage bool, usage ...string) string {
	st := styler(colorEnabled(os.Stderr))
	var b strings.Builder
	b.WriteString(st.err("error:") + " " + msg + "\n")
	if withUsage && c != nil {
		u := usageLine(c, st)
		if len(usage) > 0 {
			u = usage[0]
		}
		b.WriteString("\n" + st.header("Usage:") + " " + u + "\n")
	}
	b.WriteString("\nFor more information, try '" + st.literal("--help") + "'.\n")
	return b.String()
}

func usageErr(c *cobra.Command, msg string, withUsage bool, usage ...string) error {
	return &usageError{clapError(c, msg, withUsage, usage...), exitUsage}
}

func quote(st styler, s string) string { return "'" + st.invalid(s) + "'" }

// rangeError mirrors clap's RangedI64ValueParser messages for u16/u32 args.
func rangeError(s string, maxV int64) string {
	v, err := strconv.ParseInt(s, 10, 64)
	switch {
	case err == nil && (v < 0 || v > maxV):
		return fmt.Sprintf("%d is not in 0..=%d", v, maxV)
	case err == nil:
		return ""
	case s == "":
		return "cannot parse integer from empty string"
	case errors.Is(err, strconv.ErrRange) && strings.HasPrefix(s, "-"):
		return "number too small to fit in target type"
	case errors.Is(err, strconv.ErrRange):
		return "number too large to fit in target type"
	}
	return "invalid digit found in string"
}

func argIndex(name string) int {
	for i, a := range rawArgs {
		if a == "--"+name || strings.HasPrefix(a, "--"+name+"=") {
			return i
		}
	}
	return -1
}

// validate does what clap's parser/validator do after pflag has tokenized:
// unexpected positionals, value parsing, conflicts, then missing arguments.
func validate(c *cobra.Command, s *spec, args []string) error {
	st := styler(colorEnabled(os.Stderr))
	if len(visibleSubs(c)) > 0 {
		if len(args) > 0 {
			return usageErr(c, "unrecognized subcommand "+quote(st, args[0]), true)
		}
		return nil
	}
	if len(args) > len(s.args) {
		return usageErr(c, "unexpected argument "+quote(st, args[len(s.args)])+" found", true)
	}
	for _, f := range s.flags {
		if f.max > 0 && c.Flags().Changed(f.long) {
			v, _ := c.Flags().GetString(f.long)
			if e := rangeError(v, f.max); e != "" {
				return usageErr(c, fmt.Sprintf("invalid value %s for '%s': %s", quote(st, v), st.literal(f.display()), e), false)
			}
		}
	}
	for i, a := range args {
		d := s.args[i]
		if d.max > 0 {
			if e := rangeError(a, d.max); e != "" {
				return usageErr(c, fmt.Sprintf("invalid value %s for '%s': %s", quote(st, a), st.literal("<"+d.name+">"), e), false)
			}
		}
		if len(d.possible) > 0 && !slices.Contains(d.possible, a) {
			return usageErr(c, fmt.Sprintf("invalid value %s for '%s'\n  [possible values: %s]", quote(st, a), st.literal("<"+d.name+">"),
				strings.Join(d.possible, ", ")), false)
		}
	}
	for _, pair := range s.conflicts {
		if c.Flags().Changed(pair[0]) && c.Flags().Changed(pair[1]) {
			first, second := findFlag(s, pair[0]), findFlag(s, pair[1])
			if argIndex(pair[1]) < argIndex(pair[0]) {
				first, second = second, first
			}
			return usageErr(c, fmt.Sprintf("the argument '%s' cannot be used with '%s'", st.invalid(first.display()), st.invalid(second.display())),
				true, smartUsage(c, st))
		}
	}

	var missing []string
	used := len(args) > 0
	for _, f := range s.flags {
		if c.Flags().Changed(f.long) {
			used = true
		} else if f.required {
			missing = append(missing, f.display())
		}
	}
	for _, a := range s.args[len(args):] {
		missing = append(missing, "<"+a.name+">")
	}
	if len(missing) == 0 {
		return nil
	}
	var lines []string
	for _, m := range missing {
		lines = append(lines, "  "+st.valid(m))
	}
	usage := usageLine(c, st)
	if used {
		usage = smartUsage(c, st)
	}
	return usageErr(c, "the following required arguments were not provided:\n"+strings.Join(lines, "\n"), true, usage)
}

func findFlag(s *spec, long string) flagDef {
	for _, f := range s.flags {
		if f.long == long {
			return f
		}
	}
	return flagDef{long: long}
}

var (
	reUnknownLong  = regexp.MustCompile(`^unknown flag: (\S+)`)
	reUnknownShort = regexp.MustCompile(`^unknown shorthand flag: '(.)'`)
	reNeedsArg     = regexp.MustCompile(`^flag needs an argument: (?:'(.)' in -.*|--(\S+))$`)
	reBadValue     = regexp.MustCompile(`^invalid argument "(.*)" for "(?:-., )?--(\S+)" flag`)
)

// flagError translates pflag's messages into clap's.
func flagError(c *cobra.Command, err error) error {
	st := styler(colorEnabled(os.Stderr))
	msg := err.Error()
	if m := reUnknownLong.FindStringSubmatch(msg); m != nil {
		return usageErr(c, "unexpected argument "+quote(st, strings.SplitN(m[1], "=", 2)[0])+" found", true)
	}
	if m := reUnknownShort.FindStringSubmatch(msg); m != nil {
		return usageErr(c, "unexpected argument "+quote(st, "-"+m[1])+" found", true)
	}
	if m := reNeedsArg.FindStringSubmatch(msg); m != nil {
		long := m[2]
		if m[1] != "" {
			if f := c.Flags().ShorthandLookup(m[1]); f != nil {
				long = f.Name
			}
		}
		return usageErr(c, fmt.Sprintf("a value is required for '%s' but none was supplied", st.literal(flagDef{long: long}.display())), false)
	}
	if m := reBadValue.FindStringSubmatch(msg); m != nil {
		return usageErr(c, fmt.Sprintf("unexpected value %s for '%s' found; no more were expected", quote(st, m[1]), st.literal("--"+m[2])), true)
	}
	return usageErr(c, msg, true)
}

// missingSubcommand: with no arguments at all clap prints help to stderr
// (arg_required_else_help, exit 2); otherwise it reports the missing command.
func missingSubcommand(c *cobra.Command) error {
	noArgs := c.Flags().NFlag() == 0
	if !c.HasParent() {
		noArgs = len(rawArgs) == 0
	}
	if noArgs {
		return &usageError{helpText(c, colorEnabled(os.Stderr)), exitUsage}
	}
	st := styler(colorEnabled(os.Stderr))
	var names []string
	for _, sc := range visibleSubs(c) {
		names = append(names, st.valid(sc.Name()))
	}
	return usageErr(c, fmt.Sprintf("'%s' requires a subcommand but one was not provided\n  [subcommands: %s]",
		st.invalid(c.CommandPath()), strings.Join(names, ", ")), true)
}

// newHelpCmd is clap's auto-generated `help [COMMAND]...` subcommand.
func newHelpCmd(parent *cobra.Command) *cobra.Command {
	h := &cobra.Command{
		Use:                "help",
		Short:              "Print this message or the help of the given subcommand(s)",
		DisableFlagParsing: true,
		RunE: func(self *cobra.Command, args []string) error {
			target := parent
			for _, a := range args {
				var next *cobra.Command
				for _, sc := range visibleSubs(target) {
					if sc.Name() == a {
						next = sc
					}
				}
				if next == nil {
					st := styler(colorEnabled(os.Stderr))
					return usageErr(self, "unrecognized subcommand "+quote(st, a), true)
				}
				target = next
			}
			fmt.Fprint(os.Stdout, helpText(target, colorEnabled(os.Stdout)))
			return nil
		},
	}
	specs[h] = &spec{isHelp: true}
	return h
}

func genCompletion(root *cobra.Command, shell string, w io.Writer) error {
	switch shell {
	case "bash":
		return root.GenBashCompletionV2(w, true)
	case "zsh":
		return root.GenZshCompletion(w)
	case "fish":
		return root.GenFishCompletion(w, true)
	case "powershell":
		return root.GenPowerShellCompletionWithDesc(w)
	}
	return genElvish(root, w)
}

// genElvish writes a static script in clap_complete's elvish layout (cobra
// has no elvish generator).
func genElvish(root *cobra.Command, w io.Writer) error {
	esc := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	var b strings.Builder
	b.WriteString(`
use builtin;
use str;

set edit:completion:arg-completer[dockpanel] = {|@words|
    fn spaces {|n|
        builtin:repeat $n ' ' | str:join ''
    }
    fn cand {|text desc|
        edit:complex-candidate $text &display=$text' '(spaces (- 14 (wcswidth $text)))$desc
    }
    var command = 'dockpanel'
    for word $words[1..-1] {
        if (str:has-prefix $word '-') {
            break
        }
        set command = $command';'$word
    }
    var completions = [
`)
	var walk func(c *cobra.Command, key string)
	walk = func(c *cobra.Command, key string) {
		b.WriteString("        &'" + key + "'= {\n")
		for _, f := range optionList(c) {
			if f.short != "" {
				b.WriteString("            cand -" + f.short + " '" + esc(f.help) + "'\n")
			}
			b.WriteString("            cand --" + f.long + " '" + esc(f.help) + "'\n")
		}
		subs := visibleSubs(c)
		for _, sc := range subs {
			b.WriteString("            cand " + sc.Name() + " '" + esc(sc.Short) + "'\n")
		}
		b.WriteString("        }\n")
		for _, sc := range subs {
			walk(sc, key+";"+sc.Name())
		}
	}
	walk(root, "dockpanel")
	b.WriteString("    ]\n    $completions[$command]\n}\n")
	_, err := io.WriteString(w, b.String())
	return err
}
