// Package cli implements the dockpanel command line, a port of the Rust
// clap-based CLI with the same commands, flags, help text and exit codes.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// flagDef / argDef carry what clap derived from the Rust structs; cobra only
// parses, the help/usage/errors are rendered from these (see clap.go).
type flagDef struct {
	long, short string
	help        string
	def         string // shown as [default: X]
	boolean     bool
	required    bool
	max         int64 // >0: integer value parser with range 0..=max (u16/u32)
}

type argDef struct {
	name     string // value name, e.g. "DOMAIN"
	help     string
	max      int64
	possible []string
}

type spec struct {
	flags       []flagDef
	args        []argDef
	subRequired bool        // clap: non-Option subcommand
	conflicts   [][2]string // pairs of long names
	isHelp      bool
	isRoot      bool
}

var specs = map[*cobra.Command]*spec{}

// rawArgs is the original argv, used to report conflicts in clap's order.
var rawArgs []string

const (
	exitUsage = 2 // clap's exit code for usage errors and help-on-missing-command
	exitApp   = 1
)

// usageError is a clap-style error: text is printed verbatim to stderr.
type usageError struct {
	text string
	code int
}

func (e *usageError) Error() string { return e.text }

// appError wraps a command failure: printed as "error: ..." in red, exit 1.
type appError struct{ err error }

func (e *appError) Error() string { return e.err.Error() }

type ctx struct {
	cmd   *cobra.Command
	args  []string
	token string
}

func (c *ctx) str(name string) string { v, _ := c.cmd.Flags().GetString(name); return v }
func (c *ctx) flag(name string) bool  { v, _ := c.cmd.Flags().GetBool(name); return v }
func (c *ctx) num(name string) int64  { v, _ := strconv.ParseInt(c.str(name), 10, 64); return v }
func (c *ctx) output() string         { return c.str("output") }

// opt is clap's Option<String>: nil unless the flag was given.
func (c *ctx) opt(name string) *string {
	if !c.cmd.Flags().Changed(name) {
		return nil
	}
	v := c.str(name)
	return &v
}

func (c *ctx) optNum(name string) *int64 {
	if !c.cmd.Flags().Changed(name) {
		return nil
	}
	v := c.num(name)
	return &v
}

func (c *ctx) argNum(i int) int64 { v, _ := strconv.ParseInt(c.args[i], 10, 64); return v }

type runFunc func(*ctx) error

func newCmd(name, about string, s spec, run runFunc) *cobra.Command {
	c := &cobra.Command{Use: name, Short: about}
	sp := &s
	for _, f := range s.flags {
		if f.boolean {
			c.Flags().BoolP(f.long, f.short, false, f.help)
		} else {
			c.Flags().StringP(f.long, f.short, f.def, f.help)
		}
	}
	c.Args = func(cmd *cobra.Command, args []string) error { return validate(cmd, sp, args) }
	if run != nil {
		c.RunE = func(cmd *cobra.Command, args []string) error {
			token, err := loadAgentToken()
			if err != nil {
				return &appError{err}
			}
			if err := run(&ctx{cmd, args, token}); err != nil {
				return &appError{err}
			}
			return nil
		}
	} else if s.subRequired {
		c.RunE = func(cmd *cobra.Command, args []string) error { return missingSubcommand(cmd) }
	}
	specs[c] = sp
	return c
}

func add(parent *cobra.Command, children ...*cobra.Command) *cobra.Command {
	parent.AddCommand(children...)
	parent.AddCommand(newHelpCmd(parent))
	return parent
}

func pos(name, help string) argDef { return argDef{name: name, help: help} }

func opt(long, help string) flagDef { return flagDef{long: long, help: help} }

func filterFlag(help string) flagDef { return flagDef{long: "filter", short: "f", help: help} }

func passwordFlags(what string) []flagDef {
	return []flagDef{
		opt("password", what+" password. Prefer --password-stdin or the interactive prompt — a value given here is visible to other local users via `ps`/`/proc` for the life of the process and lands in shell history"),
		{long: "password-stdin", boolean: true, help: "Read the " + lowerFirst(what) + " password from stdin (one line) instead of passing it on the command line"},
	}
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]+('a'-'A')) + s[1:]
}

func withOutput(fn func(c *ctx, out string) error) runFunc {
	return func(c *ctx) error { return fn(c, c.output()) }
}

func buildRoot(version string) *cobra.Command {
	cobra.EnableCommandSorting = false

	root := newCmd("dockpanel", "DockPanel CLI — self-hosted server management", spec{isRoot: true, subRequired: true}, nil)
	root.PersistentFlags().StringP("output", "o", "table", "Output format: table (default) or json")
	root.Flags().BoolP("version", "V", false, "Print version")
	root.CompletionOptions.DisableDefaultCmd = true
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.SetHelpFunc(func(c *cobra.Command, _ []string) { fmt.Fprint(os.Stdout, helpText(c, colorEnabled(os.Stdout))) })
	root.SetFlagErrorFunc(flagError)
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if v, _ := cmd.Flags().GetBool("version"); v {
			fmt.Printf("dockpanel %s\n", version)
			return nil
		}
		return missingSubcommand(cmd)
	}

	idArg := func(help string) spec { return spec{args: []argDef{pos("CONTAINER_ID", help)}} }
	domainArg := spec{args: []argDef{pos("DOMAIN", "Domain name")}}

	sites := add(newCmd("sites", "Manage nginx sites",
		spec{flags: []flagDef{filterFlag("Filter sites by domain substring (case-insensitive)")}},
		func(c *ctx) error { return cmdSitesList(c.token, c.output(), c.opt("filter")) }),
		newCmd("create", "Create a new site", spec{
			args: []argDef{pos("DOMAIN", "Domain name")},
			flags: []flagDef{
				{long: "runtime", def: "static", help: "Runtime type: static, php, or proxy"},
				{long: "proxy-port", max: 65535, help: "Proxy port (required for --runtime proxy)"},
				{long: "ssl", boolean: true, help: "Enable SSL (auto-provision with Let's Encrypt)"},
				opt("ssl-email", "Email for Let's Encrypt (required with --ssl)"),
			},
		}, func(c *ctx) error {
			return cmdSitesCreate(c.token, c.args[0], c.str("runtime"), c.optNum("proxy-port"), c.flag("ssl"), c.opt("ssl-email"))
		}),
		newCmd("delete", "Delete a site", domainArg, func(c *ctx) error { return cmdSitesDelete(c.token, c.args[0]) }),
		newCmd("info", "Show site details", domainArg, func(c *ctx) error { return cmdSitesInfo(c.token, c.args[0]) }),
	)

	db := add(newCmd("db", "Manage databases",
		spec{flags: []flagDef{filterFlag("Filter databases by name substring (case-insensitive)")}},
		func(c *ctx) error { return cmdDBList(c.token, c.output(), c.opt("filter")) }),
		newCmd("create", "Create a new database", spec{
			args: []argDef{pos("NAME", "Database name")},
			flags: append(append([]flagDef{{long: "engine", required: true, help: "Engine: mysql, mariadb, or postgres"}},
				passwordFlags("Root/admin")...),
				flagDef{long: "port", required: true, max: 65535, help: "Host port"}),
			conflicts: [][2]string{{"password", "password-stdin"}},
		}, func(c *ctx) error {
			return cmdDBCreate(c.token, c.args[0], c.str("engine"), c.opt("password"), c.flag("password-stdin"), c.num("port"))
		}),
		newCmd("delete", "Delete a database", idArg("Container ID"), func(c *ctx) error { return cmdDBDelete(c.token, c.args[0]) }),
	)

	appAction := func(name, about, action string) *cobra.Command {
		return newCmd(name, about, idArg("Container ID"), func(c *ctx) error { return cmdAppsAction(c.token, c.args[0], action) })
	}
	apps := add(newCmd("apps", "Manage Docker apps",
		spec{flags: []flagDef{filterFlag("Filter apps by name/domain substring (case-insensitive)")}},
		func(c *ctx) error { return cmdAppsList(c.token, c.output(), c.opt("filter")) }),
		newCmd("templates", "List available app templates", spec{}, withOutput(func(c *ctx, out string) error { return cmdAppsTemplates(c.token, out) })),
		newCmd("deploy", "Deploy an app from a template", spec{
			args: []argDef{pos("TEMPLATE", "Template ID")},
			flags: []flagDef{
				{long: "name", required: true, help: "App name"},
				{long: "port", required: true, max: 65535, help: "Host port"},
				opt("domain", "Domain for auto reverse proxy"),
				opt("ssl-email", "Email for Let's Encrypt SSL (requires --domain)"),
			},
		}, func(c *ctx) error {
			return cmdAppsDeploy(c.token, c.args[0], c.str("name"), c.num("port"), c.opt("domain"), c.opt("ssl-email"))
		}),
		appAction("stop", "Stop a running app", "stop"),
		appAction("start", "Start a stopped app", "start"),
		appAction("restart", "Restart an app", "restart"),
		newCmd("remove", "Remove an app", idArg("Container ID"), func(c *ctx) error { return cmdAppsRemove(c.token, c.args[0]) }),
		newCmd("logs", "View app logs", idArg("Container ID"), func(c *ctx) error { return cmdAppsLogs(c.token, c.args[0]) }),
		newCmd("compose", "Deploy from a docker-compose.yml file", spec{args: []argDef{pos("FILE", "Path to docker-compose.yml")}},
			func(c *ctx) error { return cmdAppsCompose(c.token, c.args[0]) }),
	)

	services := newCmd("services", "Check service health",
		spec{flags: []flagDef{filterFlag("Filter services by name substring (case-insensitive)")}},
		func(c *ctx) error { return cmdServices(c.token, c.output(), c.opt("filter")) })

	ssl := add(newCmd("ssl", "SSL certificate management", spec{subRequired: true}, nil),
		newCmd("status", "Check certificate status", domainArg, func(c *ctx) error { return cmdSSLStatus(c.token, c.args[0]) }),
		newCmd("provision", "Provision Let's Encrypt certificate", spec{
			args: []argDef{pos("DOMAIN", "Domain name")},
			flags: []flagDef{
				{long: "email", required: true, help: "Email for Let's Encrypt"},
				{long: "runtime", def: "static", help: "Site runtime type: static, php, or proxy"},
				{long: "proxy-port", max: 65535, help: "Proxy port (for proxy runtime)"},
				{long: "force", boolean: true, help: "Issue even if the certificate already installed for this domain was obtained somewhere else — it will be REPLACED"},
			},
		}, func(c *ctx) error {
			return cmdSSLProvision(c.token, c.args[0], c.str("email"), c.str("runtime"), c.optNum("proxy-port"), c.flag("force"))
		}),
	)

	domainFile := spec{args: []argDef{pos("DOMAIN", "Domain name"), pos("FILENAME", "Backup filename")}}
	backup := add(newCmd("backup", "Backup management", spec{subRequired: true}, nil),
		newCmd("create", "Create a backup", domainArg, func(c *ctx) error { return cmdBackupCreate(c.token, c.args[0]) }),
		newCmd("list", "List backups for a domain", domainArg, withOutput(func(c *ctx, out string) error { return cmdBackupList(c.token, c.args[0], out) })),
		newCmd("restore", "Restore from a backup", domainFile, func(c *ctx) error { return cmdBackupRestore(c.token, c.args[0], c.args[1]) }),
		newCmd("delete", "Delete a backup", domainFile, func(c *ctx) error { return cmdBackupDelete(c.token, c.args[0], c.args[1]) }),
		newCmd("db-create", "Create a database backup", spec{
			args: []argDef{pos("CONTAINER", "Container name (e.g., dockpanel-db-mydb)"), pos("DB_NAME", "Database name")},
			flags: append([]flagDef{
				{long: "db-type", def: "postgres", help: "Database type: mysql, postgres, mongo"},
				{long: "user", def: "root", help: "Database user"},
			}, passwordFlags("Database")...),
			conflicts: [][2]string{{"password", "password-stdin"}},
		}, func(c *ctx) error {
			return cmdDBBackupCreate(c.token, c.args[0], c.args[1], c.str("db-type"), c.str("user"), c.opt("password"), c.flag("password-stdin"))
		}),
		newCmd("db-list", "List database backups", spec{args: []argDef{pos("DB_NAME", "Database name")}},
			withOutput(func(c *ctx, out string) error { return cmdDBBackupList(c.token, c.args[0], out) })),
		newCmd("vol-create", "Create a volume backup", spec{args: []argDef{pos("VOLUME", "Docker volume name"), pos("CONTAINER", "Container name (for organizing backups)")}},
			func(c *ctx) error { return cmdVolBackupCreate(c.token, c.args[0], c.args[1]) }),
		newCmd("vol-list", "List volume backups", spec{args: []argDef{pos("CONTAINER", "Container name")}},
			withOutput(func(c *ctx, out string) error { return cmdVolBackupList(c.token, c.args[0], out) })),
		newCmd("verify", "Verify a backup", spec{
			args: []argDef{
				pos("NAME", "Resource name (domain for site, db_name for database, container for volume)"),
				pos("FILENAME", "Backup filename"),
			},
			flags: []flagDef{
				{long: "type", required: true, help: "Backup type: site, database, volume"},
				{long: "db-type", def: "postgres", help: "Database type, only used when --type database: mysql, mariadb, or postgres"},
			},
		}, func(c *ctx) error {
			return cmdBackupVerify(c.token, c.str("type"), c.args[0], c.args[1], c.str("db-type"))
		}),
		newCmd("health", "Show backup health overview", spec{}, func(c *ctx) error { return cmdBackupHealth() }),
	)

	logs := newCmd("logs", "View system and site logs", spec{flags: []flagDef{
		{long: "domain", short: "d", help: "Domain for site-specific logs"},
		{long: "type", short: "t", def: "syslog", help: "Log type (syslog, nginx, auth, php, mysql)"},
		{long: "lines", short: "n", def: "50", max: 4294967295, help: "Number of lines"},
		{long: "filter", short: "f", help: "Filter text"},
		{long: "search", short: "s", help: "Search pattern (regex)"},
	}}, func(c *ctx) error {
		return cmdLogs(c.token, c.opt("domain"), c.str("type"), c.num("lines"), c.opt("filter"), c.opt("search"))
	})

	firewall := add(newCmd("firewall", "Firewall management", spec{}, withOutput(func(c *ctx, out string) error { return cmdFirewallList(c.token, out) })),
		newCmd("add", "Add a firewall rule", spec{flags: []flagDef{
			{long: "port", required: true, max: 65535, help: "Port number"},
			{long: "proto", def: "tcp", help: "Protocol: tcp or udp"},
			{long: "action", def: "allow", help: "Action: allow or deny"},
			opt("from", "Source IP/CIDR"),
		}}, func(c *ctx) error {
			return cmdFirewallAdd(c.token, c.num("port"), c.str("proto"), c.str("action"), c.opt("from"))
		}),
		newCmd("remove", "Remove a firewall rule by number", spec{args: []argDef{{name: "NUMBER", help: "Rule number", max: 4294967295}}},
			func(c *ctx) error { return cmdFirewallRemove(c.token, c.argNum(0)) }),
	)
	security := add(newCmd("security", "Security overview and management", spec{}, withOutput(func(c *ctx, out string) error { return cmdSecurityOverview(c.token, out) })),
		newCmd("scan", "Run a security scan", spec{}, withOutput(func(c *ctx, out string) error { return cmdSecurityScan(c.token, out) })),
		firewall,
	)

	php := add(newCmd("php", "PHP version management", spec{}, withOutput(func(c *ctx, out string) error { return cmdPHPList(c.token, out) })),
		newCmd("install", "Install a PHP version", spec{args: []argDef{pos("VERSION", "PHP version (8.1, 8.2, 8.3, 8.4, 8.5)")}},
			func(c *ctx) error { return cmdPHPInstall(c.token, c.args[0]) }),
	)

	// `export` declares its own -O/--output, which shadows the global
	// -o/--output exactly like clap's global-arg propagation does.
	export := newCmd("export", "Export server configuration as YAML (Infrastructure as Code)",
		spec{flags: []flagDef{{long: "output", short: "O", help: "Output file (default: stdout)"}}},
		func(c *ctx) error { return cmdExport(c.token, c.opt("output")) })

	apply := newCmd("apply", "Apply server configuration from YAML file", spec{
		args: []argDef{pos("FILE", "Path to YAML config file")},
		flags: []flagDef{
			{long: "dry-run", boolean: true, help: "Show what would change without applying"},
			opt("email", "Email for Let's Encrypt SSL provisioning"),
		},
	}, func(c *ctx) error { return cmdApply(c.token, c.args[0], c.flag("dry-run"), c.opt("email")) })

	// Completions run before token loading: no agent needed.
	completions := newCmd("completions", "Generate shell completions",
		spec{args: []argDef{{name: "SHELL", help: "Shell to generate completions for", possible: []string{"bash", "elvish", "fish", "powershell", "zsh"}}}}, nil)
	completions.RunE = func(cmd *cobra.Command, args []string) error { return genCompletion(cmd.Root(), args[0], os.Stdout) }

	root.AddCommand(
		newCmd("status", "Show server status (CPU, memory, disk, uptime)", spec{}, withOutput(func(c *ctx, out string) error { return cmdStatus(c.token, out) })),
		sites, db, apps, services, ssl, backup, logs, security,
		newCmd("top", "Show top processes by CPU usage", spec{}, withOutput(func(c *ctx, out string) error { return cmdTop(c.token, out) })),
		php,
		newCmd("diagnose", "Run server diagnostics (nginx, resources, SSL, security, logs)", spec{}, withOutput(func(c *ctx, out string) error { return cmdDiagnose(c.token, out) })),
		export, apply, completions,
	)
	root.SetHelpCommand(newHelpCmd(root))
	return root
}

// Run executes the CLI and returns the process exit code.
func Run(version string, args []string) int {
	rawArgs = args
	root := buildRoot(version)
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return 0
	}
	var ue *usageError
	if errors.As(err, &ue) {
		io.WriteString(os.Stderr, ue.text)
		return ue.code
	}
	var ae *appError
	if !errors.As(err, &ae) {
		// Anything cobra raised on its own is a usage problem.
		io.WriteString(os.Stderr, clapError(nil, err.Error(), false))
		return exitUsage
	}
	fmt.Fprintf(os.Stderr, "\x1b[31merror:\x1b[0m %s\n", err)
	return exitApp
}
