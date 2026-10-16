package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ── YAML <-> JSON value conversion ──────────────────────────────────────────
// The Rust CLI round-trips serde_json::Value through serde_yaml_ng. These
// helpers reproduce its scalar rules (YAML 1.2 core, leading-zero digits stay
// strings) so export output and apply parsing match it.

func isNullScalar(s string) bool {
	return s == "" || s == "~" || s == "null" || s == "Null" || s == "NULL"
}

func parseBoolScalar(s string) (bool, bool) {
	switch s {
	case "true", "True", "TRUE":
		return true, true
	case "false", "False", "FALSE":
		return false, true
	}
	return false, false
}

// digitsButNotNumber: leading zero(s) followed by digits is a string in YAML 1.2.
func digitsButNotNumber(s string) bool {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "-"), "+")
	if len(s) < 2 || s[0] != '0' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

var radixPrefixes = []struct {
	prefix string
	base   int
}{{"0x", 16}, {"0o", 8}, {"0b", 2}}

func parseUnsignedScalar(s string) (uint64, bool) {
	un := strings.TrimPrefix(s, "+")
	for _, r := range radixPrefixes {
		if rest, ok := strings.CutPrefix(un, r.prefix); ok {
			if strings.HasPrefix(rest, "+") || strings.HasPrefix(rest, "-") {
				return 0, false
			}
			if v, err := strconv.ParseUint(rest, r.base, 64); err == nil {
				return v, true
			}
		}
	}
	if strings.HasPrefix(un, "+") || strings.HasPrefix(un, "-") || digitsButNotNumber(s) {
		return 0, false
	}
	v, err := strconv.ParseUint(un, 10, 64)
	return v, err == nil
}

func parseNegativeScalar(s string) (int64, bool) {
	for _, r := range radixPrefixes {
		if rest, ok := strings.CutPrefix(s, "-"+r.prefix); ok {
			if v, err := strconv.ParseInt("-"+rest, r.base, 64); err == nil {
				return v, true
			}
		}
	}
	if digitsButNotNumber(s) {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}

func parseFloatScalar(s string) (float64, bool) {
	un := s
	if rest, ok := strings.CutPrefix(s, "+"); ok {
		if strings.HasPrefix(rest, "+") || strings.HasPrefix(rest, "-") {
			return 0, false
		}
		un = rest
	}
	switch {
	case un == ".inf" || un == ".Inf" || un == ".INF":
		return math.Inf(1), true
	case s == "-.inf" || s == "-.Inf" || s == "-.INF":
		return math.Inf(-1), true
	case s == ".nan" || s == ".NaN" || s == ".NAN":
		return math.NaN(), true
	}
	// Go's ParseFloat also takes hex floats and underscores; Rust's doesn't.
	if strings.ContainsAny(un, "xX_") {
		return 0, false
	}
	f, err := strconv.ParseFloat(un, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

// untaggedScalar types a plain YAML scalar the way serde_yaml_ng does when
// deserializing into serde_json::Value.
func untaggedScalar(s string) any {
	if isNullScalar(s) {
		return nil
	}
	if b, ok := parseBoolScalar(s); ok {
		return b
	}
	if u, ok := parseUnsignedScalar(s); ok {
		return json.Number(strconv.FormatUint(u, 10))
	}
	if i, ok := parseNegativeScalar(s); ok {
		return json.Number(strconv.FormatInt(i, 10))
	}
	if !digitsButNotNumber(s) {
		if f, ok := parseFloatScalar(s); ok {
			if math.IsInf(f, 0) || math.IsNaN(f) {
				return nil // serde_json has no non-finite numbers
			}
			t := strconv.FormatFloat(f, 'g', -1, 64)
			if !strings.ContainsAny(t, ".e") {
				t += ".0" // stays a float: as_u64 must not see it
			}
			return json.Number(t)
		}
	}
	return s
}

// needsQuotes reports whether serde_yaml_ng would single-quote a string so it
// does not read back as another type.
func needsQuotes(s string) bool {
	if isNullScalar(s) || digitsButNotNumber(s) {
		return true
	}
	if _, ok := parseBoolScalar(s); ok {
		return true
	}
	if _, ok := parseUnsignedScalar(s); ok {
		return true
	}
	if _, ok := parseNegativeScalar(s); ok {
		return true
	}
	_, ok := parseFloatScalar(s) // also catches u128-sized decimals
	return ok
}

func parseYAML(src []byte) (any, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	return yamlNodeValue(&doc)
}

func yamlNodeValue(n *yaml.Node) (any, error) {
	switch n.Kind {
	case 0:
		return nil, nil // empty document
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return yamlNodeValue(n.Content[0])
	case yaml.AliasNode:
		return yamlNodeValue(n.Alias)
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlNodeValue(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yaml.AliasNode {
				k = k.Alias
			}
			if k.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d column %d: invalid type: map key must be a string", k.Line, k.Column)
			}
			v, err := yamlNodeValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			out[k.Value] = v // serde reads any scalar key as its raw text
		}
		return out, nil
	default: // ScalarNode
		quoted := n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0
		if quoted || (n.Style&yaml.TaggedStyle != 0 && n.ShortTag() == "!!str") {
			return n.Value, nil
		}
		return untaggedScalar(n.Value), nil
	}
}

func scalarNode(value string, style yaml.Style) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Value: value, Style: style}
}

func stringNode(s string) *yaml.Node {
	switch {
	case strings.Contains(s, "\n"):
		return scalarNode(s, yaml.LiteralStyle)
	case needsQuotes(s):
		return scalarNode(s, yaml.SingleQuotedStyle)
	}
	return scalarNode(s, 0) // the emitter picks plain/quoted like libyaml
}

func valueToYAMLNode(v any) *yaml.Node {
	switch t := v.(type) {
	case nil:
		return scalarNode("null", 0)
	case bool:
		return scalarNode(strconv.FormatBool(t), 0)
	case json.Number:
		return scalarNode(string(t), 0)
	case string:
		return stringNode(t)
	case []any:
		n := &yaml.Node{Kind: yaml.SequenceNode}
		for _, e := range t {
			n.Content = append(n.Content, valueToYAMLNode(e))
		}
		return n
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // serde_json::Map is a BTreeMap
		n := &yaml.Node{Kind: yaml.MappingNode}
		for _, k := range keys {
			n.Content = append(n.Content, stringNode(k), valueToYAMLNode(t[k]))
		}
		return n
	}
	return scalarNode(fmt.Sprint(v), 0)
}

// toYAML matches serde_yaml_ng::to_string: 2-space indent, sequences not
// indented under their key, no line wrapping, no leading "---".
func toYAML(v any) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	enc.CompactSeqIndent()
	if err := enc.Encode(valueToYAMLNode(v)); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ── export / apply ──────────────────────────────────────────────────────────

func cmdExport(token string, output *string) error {
	data, err := agentGet("/iac/export", token)
	if err != nil {
		return err
	}
	y, err := toYAML(data)
	if err != nil {
		return fmt.Errorf("Failed to serialize YAML: %s", err)
	}
	content := "# DockPanel server configuration\n# Generated by: dockpanel export\n# Apply with:   dockpanel apply <file>\n\n" + y
	if output == nil {
		fmt.Print(content)
		return nil
	}
	if err := os.WriteFile(*output, []byte(content), 0o644); err != nil {
		return fmt.Errorf("Failed to write %s: %s", *output, ioErr(err))
	}
	fmt.Fprintf(os.Stderr, "\x1b[32m✓\x1b[0m Exported to %s\n", *output)
	return nil
}

// names collects the string field `key` of every element of list, optionally
// stripping a prefix.
func names(list any, key, stripPrefix string) []string {
	items, _ := arr(list)
	var out []string
	for _, it := range items {
		if s, ok := str(get(it, key)); ok {
			out = append(out, strings.TrimPrefix(s, stripPrefix))
		}
	}
	return out
}

const passwordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func cmdApply(token, file string, dryRun bool, email *string) error {
	src, err := readUTF8(file)
	if err != nil {
		return fmt.Errorf("Cannot read %s: %s", file, ioErr(err))
	}
	desired, err := parseYAML([]byte(src))
	if err != nil {
		return fmt.Errorf("Invalid YAML: %s", err)
	}
	current, err := agentGet("/iac/export", token)
	if err != nil {
		return err
	}

	var planCreate, planSkip []string
	applied, errs := 0, 0
	result := func(err error) {
		if err != nil {
			fmt.Printf("\x1b[31m✗\x1b[0m (%s)\n", err)
			errs++
		} else {
			fmt.Println("\x1b[32m✓\x1b[0m")
			applied++
		}
	}

	// ── Sites ──
	currentDomains := names(get(current, "sites"), "domain", "")
	sites, _ := arr(get(desired, "sites"))
	for _, site := range sites {
		domain := strOr(get(site, "domain"), "")
		if domain == "" {
			continue
		}
		runtime := strOr(get(site, "runtime"), "static")
		if slices.Contains(currentDomains, domain) {
			planSkip = append(planSkip, fmt.Sprintf("site: %s (already exists)", domain))
			continue
		}
		if dryRun {
			switch runtime {
			case "proxy":
				planCreate = append(planCreate, fmt.Sprintf("site: %s (proxy → port %d)", domain, u64Or(get(site, "proxy_port"), 3000)))
			case "php":
				planCreate = append(planCreate, fmt.Sprintf("site: %s (php %s)", domain, strOr(get(site, "php_version"), "8.3")))
			default:
				planCreate = append(planCreate, fmt.Sprintf("site: %s (static)", domain))
			}
			continue
		}

		fmt.Printf("  Creating site %s... ", domain)
		body := map[string]any{"runtime": runtime}
		if p, ok := u64(get(site, "proxy_port")); ok {
			body["proxy_port"] = p
		}
		if root, ok := str(get(site, "root")); ok {
			body["root"] = root
		}
		if ver, ok := str(get(site, "php_version")); ok {
			body["php_socket"] = fmt.Sprintf("unix:/run/php/php%s-fpm.sock", ver)
		}
		if _, err := agentPut("/nginx/sites/"+domain, body, token); err != nil {
			result(err)
			continue
		}
		result(nil)
		if !isTrue(get(site, "ssl")) {
			continue
		}
		if email == nil {
			fmt.Printf("  \x1b[33m!\x1b[0m %s requests ssl but no --email was given — skipping SSL provisioning (re-run with --email to provision it)\n", domain)
			continue
		}
		fmt.Printf("  Provisioning SSL for %s... ", domain)
		var proxyPort any // JSON null when absent, as in the Rust body
		if p, ok := u64(get(site, "proxy_port")); ok {
			proxyPort = p
		}
		sslBody := map[string]any{"email": *email, "runtime": runtime, "proxy_port": proxyPort}
		if _, err := agentPost("/ssl/provision/"+domain, sslBody, token); err != nil {
			fmt.Printf("\x1b[33mskipped\x1b[0m (%s)\n", err)
		} else {
			fmt.Println("\x1b[32m✓\x1b[0m")
		}
	}

	// ── Databases ── (current names carry a "dockpanel-db-" prefix)
	currentDBs := names(get(current, "databases"), "name", "dockpanel-db-")
	dbs, _ := arr(get(desired, "databases"))
	for _, db := range dbs {
		name := strOr(get(db, "name"), "")
		if name == "" {
			continue
		}
		engine := strOr(get(db, "engine"), "postgres")
		port := uint16(u64Or(get(db, "port"), 5432)) // `as u16` truncation, as in Rust
		if slices.Contains(currentDBs, name) {
			planSkip = append(planSkip, fmt.Sprintf("database: %s (already exists)", name))
			continue
		}
		if dryRun {
			planCreate = append(planCreate, fmt.Sprintf("database: %s (%s, port %d)", name, engine, port))
			continue
		}
		var pw []byte
		var entropyErr error
		for range 16 {
			b, err := randByte()
			if err != nil {
				entropyErr = err
				break
			}
			pw = append(pw, passwordCharset[b%62])
		}
		if entropyErr != nil {
			fmt.Printf("\x1b[31m✗\x1b[0m Creating database %s... failed to generate a random password: %s\n", name, entropyErr)
			errs++
			continue
		}
		fmt.Printf("  Creating database %s... ", name)
		if _, err := agentPost("/databases", map[string]any{"name": name, "engine": engine, "password": string(pw), "port": port}, token); err != nil {
			result(err)
		} else {
			fmt.Printf("\x1b[32m✓\x1b[0m (password: %s)\n", pw)
			applied++
		}
	}

	// ── Docker apps ── (current names carry a "dockpanel-app-" prefix)
	currentApps := names(get(current, "apps"), "name", "dockpanel-app-")
	apps, _ := arr(get(desired, "apps"))
	for _, app := range apps {
		name := strOr(get(app, "name"), "")
		if name == "" {
			continue
		}
		template := strOr(get(app, "template"), "")
		port := uint16(u64Or(get(app, "port"), 0))
		if slices.Contains(currentApps, name) {
			planSkip = append(planSkip, fmt.Sprintf("app: %s (already exists)", name))
			continue
		}
		if dryRun {
			planCreate = append(planCreate, fmt.Sprintf("app: %s (template: %s, port %d)", name, template, port))
			continue
		}
		fmt.Printf("  Deploying app %s... ", name)
		body := map[string]any{"template_id": template, "name": name, "port": port}
		if domain, ok := str(get(app, "domain")); ok {
			body["domain"] = domain
			if email != nil {
				body["ssl_email"] = *email
			}
		}
		_, err := agentPost("/apps/deploy", body, token)
		result(err)
	}

	// ── Cron jobs ──
	// Unlike the other resources, crons DO reconcile on a real apply
	// (/crons/sync replaces every entry whose id it's given), so the dry-run
	// plan diffs against what /iac/export reported instead of calling every
	// cron "to create".
	currentCrons := map[string]any{}
	if list, ok := arr(get(current, "crons")); ok {
		for _, c := range list {
			if id, ok := str(get(c, "id")); ok {
				currentCrons[id] = c
			}
		}
	}
	if crons, ok := arr(get(desired, "crons")); ok && len(crons) > 0 {
		if dryRun {
			for _, c := range crons {
				id := strOr(get(c, "id"), "-")
				schedule := strOr(get(c, "schedule"), "")
				command := strOr(get(c, "command"), "")
				existing, found := currentCrons[id]
				switch {
				case !found:
					planCreate = append(planCreate, fmt.Sprintf("cron: %s (%s %s)", id, schedule, command))
				case sameStr(get(existing, "schedule"), schedule) && sameStr(get(existing, "command"), command):
					planSkip = append(planSkip, fmt.Sprintf("cron: %s (already exists, unchanged)", id))
				default:
					planCreate = append(planCreate, fmt.Sprintf("cron: %s (updated — %s %s)", id, schedule, command))
				}
			}
		} else {
			fmt.Printf("  Syncing %d cron job(s)... ", len(crons))
			_, err := agentPost("/crons/sync", crons, token)
			result(err)
		}
	}

	// ── PHP versions ──
	var currentPHP []string
	if list, ok := arr(get(current, "php")); ok {
		for _, p := range list {
			if v, ok := str(get(p, "version")); ok && isTrue(get(p, "installed")) {
				currentPHP = append(currentPHP, v)
			}
		}
	}
	phps, _ := arr(get(desired, "php"))
	for _, php := range phps {
		version := strOr(get(php, "version"), "")
		if version == "" {
			continue
		}
		if slices.Contains(currentPHP, version) {
			planSkip = append(planSkip, fmt.Sprintf("php: %s (already installed)", version))
			continue
		}
		if dryRun {
			planCreate = append(planCreate, "php: "+version)
			continue
		}
		fmt.Printf("  Installing PHP %s... ", version)
		r, err := agentPost("/php/install", map[string]any{"version": version}, token)
		// A 200 carrying `success: false` means "installed but PHP-FPM never
		// came up" — counting it as applied would put a green tick over a PHP
		// that cannot serve a site.
		if err == nil {
			if b, ok := boolean(get(r, "success")); ok && !b {
				err = errors.New(strOr(get(r, "message"), "install did not complete"))
			}
		}
		result(err)
	}

	// ── Firewall ──
	// Exported for reference but never reconciled; say so instead of silently
	// dropping edits a user made to it.
	if m, ok := desired.(map[string]any); ok {
		if fw, present := m["firewall"]; present {
			if rules, _ := arr(get(fw, "rules")); len(rules) > 0 {
				fmt.Printf("\x1b[33m!\x1b[0m This file has a firewall section (%d rule(s)) — "+
					"`apply` does not create, update, or remove firewall rules. Manage them with "+
					"`dockpanel security firewall` instead.\n", len(rules))
			}
		}
	}

	// ── Output ──
	if dryRun {
		fmt.Println("\x1b[1mPlan:\x1b[0m")
		if len(planCreate) == 0 && len(planSkip) == 0 {
			fmt.Println("  No changes needed.")
		} else {
			for _, item := range planCreate {
				fmt.Printf("  \x1b[32m+\x1b[0m %s\n", item)
			}
			for _, item := range planSkip {
				fmt.Printf("  \x1b[90m=\x1b[0m %s\n", item)
			}
			fmt.Printf("\n%d to create, %d existing\n", len(planCreate), len(planSkip))
		}
	} else {
		fmt.Println()
		switch {
		case errs > 0:
			fmt.Printf("\x1b[33m%d applied, %d failed\x1b[0m\n", applied, errs)
		case applied > 0:
			fmt.Printf("\x1b[32m%d applied\x1b[0m\n", applied)
		default:
			fmt.Println("No changes needed.")
		}
	}
	if errs > 0 {
		return fmt.Errorf("%d operation(s) failed", errs)
	}
	return nil
}

func sameStr(v any, want string) bool {
	s, ok := str(v)
	return ok && s == want
}
