// Compose-stack deployment.
//
// This is not `docker compose`. Each service is created directly through the
// Docker API so the same sandboxing the panel applies to template apps
// (no-new-privileges, cap_drop ALL, a confined bind prefix) applies here too.
// What that hand-rolled path has to reproduce deliberately is everything
// `docker compose` would have done for free — and until v2.54.0 it reproduced
// almost none of it:
//
//   - **A network.** Services were created with no networking config, so every
//     one landed on the default bridge, where container-name DNS does not
//     exist. `postgresql://app:pw@database:5432` could not resolve. A stack now
//     gets its own bridge and each service is attached under its compose
//     service key as a network alias — the name its siblings actually write.
//   - **A namespace.** Container and volume names came straight off the
//     service key, so the `db` service of three packages all wanted
//     `dockpanel-compose-db`. Both are now scoped by stack.
//   - **command, depends_on and long-form ports.** All three were parsed away
//     silently, which turned a `messenger:consume` worker into a second copy
//     of the web server.
//
// A stack whose services cannot see each other looks exactly like a crashing
// image, which is why this went out believing itself healthy: the deploy
// reported `running` on the strength of create + start returning Ok. It now
// waits for the container to still be up and hands back the log tail when it
// is not.

package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"go.yaml.in/yaml/v3"
)

// ComposeService is a parsed docker-compose service definition.
type ComposeService struct {
	// The compose service key (`services:` map key). This — not the container
	// name — is what sibling services resolve, so it is registered as a
	// network alias and must survive parsing intact.
	Key string `json:"key"`
	// The Docker container name. Scoped by stack so two packages that both
	// define a `db` service can coexist on one host.
	Name        string               `json:"name"`
	Image       string               `json:"image"`
	Ports       []ComposePortMapping `json:"ports"`
	Environment map[string]string    `json:"environment"`
	Volumes     []string             `json:"volumes"`
	Restart     string               `json:"restart"`
	// Names this service answers to on the stack network.
	Aliases []string `json:"aliases"`
	// `command:` override, in exec form. nil keeps the image's own CMD.
	Command []string `json:"command"`
	// Service keys this one declares a dependency on — used for start order.
	DependsOn []string `json:"depends_on"`
	// Author-supplied labels. `dockpanel.*` keys are stripped during parsing:
	// the panel's own labels decide what is managed and which stack a
	// container belongs to, and a compose file must not be able to claim
	// either. Everything else is passed through (e.g. a Traefik label block).
	Labels map[string]string `json:"labels"`
	// Whether the compose file declared `user:`, `healthcheck:` or
	// `entrypoint:` — this deployer has no field for any of the three, so they
	// are read ONLY to say so; the deploy silently ignores them. A stack that
	// says "valid" while quietly dropping a directive the author wrote is the
	// honesty gap these three exist to close.
	UserIgnored        bool `json:"user_ignored"`
	HealthcheckIgnored bool `json:"healthcheck_ignored"`
	EntrypointIgnored  bool `json:"entrypoint_ignored"`
}

// ComposePortMapping is one published port.
type ComposePortMapping struct {
	Host      uint16 `json:"host"`
	Container uint16 `json:"container"`
	Protocol  string `json:"protocol"`
}

// ComposeDeployResult is the outcome of a stack deploy.
type ComposeDeployResult struct {
	Services []ComposeServiceDeployResult `json:"services"`
	// The network every service was attached to, so callers can report it.
	Network string `json:"network"`
}

// ComposeServiceDeployResult is one service's outcome.
type ComposeServiceDeployResult struct {
	Name        string  `json:"name"`
	ContainerID string  `json:"container_id"`
	Status      string  `json:"status"`
	Error       *string `json:"error"`
}

// composeFile is the raw docker-compose YAML structure (partial — covers
// common fields). Services are visited in sorted key order: iteration order
// over an unordered map used to start the same YAML's services in a different
// order each deploy.
type composeFile struct {
	Services *map[string]composeServiceDef `yaml:"services"`
}

type composeServiceDef struct {
	Image         *string     `yaml:"image"`
	Ports         []yaml.Node `yaml:"ports"`
	Environment   yaml.Node   `yaml:"environment"`
	Volumes       []string    `yaml:"volumes"`
	Restart       *string     `yaml:"restart"`
	ContainerName *string     `yaml:"container_name"`
	Command       yaml.Node   `yaml:"command"`
	DependsOn     yaml.Node   `yaml:"depends_on"`
	Labels        yaml.Node   `yaml:"labels"`
	// Dangerous fields — parsed so we can explicitly reject them
	Privileged  *bool     `yaml:"privileged"`
	NetworkMode *string   `yaml:"network_mode"`
	Pid         *string   `yaml:"pid"`
	Ipc         *string   `yaml:"ipc"`
	CapAdd      []string  `yaml:"cap_add"`
	Devices     *[]string `yaml:"devices"`
	SecurityOpt []string  `yaml:"security_opt"`
	// Read-only-to-warn: this deployer has no field for any of these three,
	// so they exist here purely so compose_validate can tell the author their
	// directive will be silently dropped, rather than saying "valid" over it.
	User        yaml.Node `yaml:"user"`
	Healthcheck yaml.Node `yaml:"healthcheck"`
	Entrypoint  yaml.Node `yaml:"entrypoint"`
}

// composePresent is serde's Option::is_some for a YAML value: absent and
// explicit null are both None.
func composePresent(n *yaml.Node) bool {
	return n.Kind != 0 && !(n.Kind == yaml.ScalarNode && n.Tag == "!!null")
}

// composeScalarString renders a YAML scalar the way the Rust port matched on
// serde_yaml::Value: strings verbatim, numbers and bools via Display, ok=false
// for anything else.
func composeScalarString(n *yaml.Node) (string, bool) {
	if n.Kind != yaml.ScalarNode {
		return "", false
	}
	switch n.Tag {
	case "!!str":
		return n.Value, true
	case "!!bool":
		var b bool
		if n.Decode(&b) == nil {
			return strconv.FormatBool(b), true
		}
	case "!!int":
		var i int64
		if n.Decode(&i) == nil {
			return strconv.FormatInt(i, 10), true
		}
		var u uint64
		if n.Decode(&u) == nil {
			return strconv.FormatUint(u, 10), true
		}
	case "!!float":
		var f float64
		if n.Decode(&f) == nil {
			s := strconv.FormatFloat(f, 'f', -1, 64)
			if !strings.ContainsAny(s, ".eEnN") && !math.IsInf(f, 0) {
				s += ".0"
			}
			return s, true
		}
	}
	return "", false
}

// composeStringList decodes a sequence of strings (serde Vec<String>).
func composeStringList(n *yaml.Node, what string) ([]string, error) {
	var out []string
	if err := n.Decode(&out); err != nil {
		return nil, fmt.Errorf("Invalid YAML: %s: %v", what, err)
	}
	return out, nil
}

// composeKV parses `key=value` entries, skipping any without `=`.
func composeKV(list []string) map[string]string {
	out := map[string]string{}
	for _, entry := range list {
		if k, v, ok := strings.Cut(entry, "="); ok {
			out[k] = v
		}
	}
	return out
}

// composeMapping walks a mapping node's (key, value) pairs.
func composeMapping(n *yaml.Node, f func(k string, v *yaml.Node)) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		f(n.Content[i].Value, n.Content[i+1])
	}
}

// ComposeStackNetworkName is the Docker network a stack's services share.
func ComposeStackNetworkName(stackID *string) string {
	return "dockpanel-stack-" + composeStackScope(stackID)
}

// composeStackScope is a short, filesystem- and DNS-safe scope token derived
// from the stack id.
func composeStackScope(stackID *string) string {
	if stackID == nil {
		return "adhoc"
	}
	var b strings.Builder
	n := 0
	for _, c := range *stackID {
		if n == 12 {
			break
		}
		if c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			b.WriteRune(c)
			n++
		}
	}
	if b.Len() == 0 {
		return "adhoc"
	}
	return b.String()
}

// ComposeParseCompose parses a docker-compose.yml string into a list of
// services.
//
// stackID scopes the container names. It is threaded through parsing rather
// than applied at deploy time so the preview the operator approves names the
// containers the deploy will actually create.
func ComposeParseCompose(yamlText string, stackID *string) ([]ComposeService, error) {
	var compose composeFile
	if err := yaml.Unmarshal([]byte(yamlText), &compose); err != nil {
		return nil, fmt.Errorf("Invalid YAML: %v", err)
	}
	if compose.Services == nil {
		return nil, errors.New("No 'services' key found in compose file")
	}
	services := *compose.Services
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)

	scope := composeStackScope(stackID)
	var result []ComposeService

	for _, name := range names {
		def := services[name]
		// Reject dangerous Docker options that could escape container isolation
		if def.Privileged != nil && *def.Privileged {
			return nil, fmt.Errorf("Service '%s': privileged mode is not allowed", name)
		}
		if def.NetworkMode != nil {
			if mode := *def.NetworkMode; mode == "host" || strings.HasPrefix(mode, "container:") {
				return nil, fmt.Errorf("Service '%s': network_mode '%s' is not allowed", name, mode)
			}
		}
		if def.Pid != nil && *def.Pid == "host" {
			return nil, fmt.Errorf("Service '%s': pid mode 'host' is not allowed", name)
		}
		if def.Ipc != nil && *def.Ipc == "host" {
			return nil, fmt.Errorf("Service '%s': ipc mode 'host' is not allowed", name)
		}
		for _, c := range def.CapAdd {
			switch strings.ToUpper(c) {
			case "SYS_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "NET_ADMIN", "ALL":
				return nil, fmt.Errorf("Service '%s': capability '%s' is not allowed", name, c)
			}
		}
		if def.Devices != nil {
			return nil, fmt.Errorf("Service '%s': device mounts are not allowed", name)
		}
		// security_opt was once parsed but never checked. The backend's own
		// validate_compose_yaml rejects the same shape before a request
		// reaches the agent, but the agent must not rely on that alone: it is
		// a second machine reachable over its own HTTP API. Same rule, same
		// wording — `unconfined` disables seccomp/AppArmor confinement
		// entirely; `no-new-privileges:true` (what this deployer sets by
		// default) is unaffected.
		for _, opt := range def.SecurityOpt {
			if strings.Contains(strings.ToLower(opt), "unconfined") {
				return nil, fmt.Errorf("Service '%s': security_opt '%s' is not allowed", name, opt)
			}
		}

		// Skip services with a build: context (we don't support building images)
		if def.Image == nil {
			continue
		}
		image := *def.Image

		ports := composeParsePorts(def.Ports)

		environment := map[string]string{}
		switch env := &def.Environment; {
		case !composePresent(env):
		case env.Kind == yaml.MappingNode:
			composeMapping(env, func(k string, v *yaml.Node) {
				if s, ok := composeScalarString(v); ok {
					environment[k] = s
				} else if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
					environment[k] = "Null"
				} else {
					var anyV any
					_ = v.Decode(&anyV)
					environment[k] = fmt.Sprint(anyV)
				}
			})
		case env.Kind == yaml.SequenceNode:
			list, err := composeStringList(env, "environment")
			if err != nil {
				return nil, err
			}
			environment = composeKV(list)
		default:
			return nil, errors.New("Invalid YAML: data did not match any variant of untagged enum EnvironmentDef")
		}

		volumes := def.Volumes
		if volumes == nil {
			volumes = []string{}
		}
		restart := "no"
		if def.Restart != nil {
			restart = *def.Restart
		}

		// The container name is ours; the names the *stack* resolves are the
		// service key and whatever container_name the author wrote. Honouring
		// an author-chosen container_name as the real Docker name is what let
		// one stack collide with another, so it becomes an alias instead.
		containerName := fmt.Sprintf("dockpanel-compose-%s-%s", scope, name)
		aliases := []string{name}
		if def.ContainerName != nil && *def.ContainerName != name {
			aliases = append(aliases, *def.ContainerName)
		}

		var command []string
		switch cmd := &def.Command; {
		case !composePresent(cmd):
		case cmd.Kind == yaml.SequenceNode:
			list, err := composeStringList(cmd, "command")
			if err != nil {
				return nil, err
			}
			command = list
		case cmd.Kind == yaml.ScalarNode:
			command = composeSplitShellCommand(cmd.Value)
		default:
			return nil, errors.New("Invalid YAML: data did not match any variant of untagged enum CommandDef")
		}

		dependsOn := []string{}
		switch dep := &def.DependsOn; {
		case !composePresent(dep):
		case dep.Kind == yaml.SequenceNode:
			list, err := composeStringList(dep, "depends_on")
			if err != nil {
				return nil, err
			}
			dependsOn = list
		case dep.Kind == yaml.MappingNode:
			// Only the keys matter — the conditions describe health gates this
			// deployer does not implement, and claiming otherwise would be
			// worse than ignoring them.
			composeMapping(dep, func(k string, _ *yaml.Node) { dependsOn = append(dependsOn, k) })
			sort.Strings(dependsOn)
		default:
			return nil, errors.New("Invalid YAML: data did not match any variant of untagged enum DependsOnDef")
		}

		// `dockpanel.*` is the panel's namespace. A compose file that could
		// set dockpanel.managed or dockpanel.stack_id would be able to hide a
		// container from the panel or attach it to somebody else's stack.
		labels := map[string]string{}
		switch lab := &def.Labels; {
		case !composePresent(lab):
		case lab.Kind == yaml.MappingNode:
			composeMapping(lab, func(k string, v *yaml.Node) {
				s, _ := composeScalarString(v)
				labels[k] = s
			})
		case lab.Kind == yaml.SequenceNode:
			list, err := composeStringList(lab, "labels")
			if err != nil {
				return nil, err
			}
			labels = composeKV(list)
		default:
			return nil, errors.New("Invalid YAML: data did not match any variant of untagged enum LabelsDef")
		}
		for k := range labels {
			if strings.HasPrefix(k, "dockpanel.") {
				delete(labels, k)
			}
		}

		result = append(result, ComposeService{
			Key:                name,
			Name:               containerName,
			Image:              image,
			Ports:              ports,
			Environment:        environment,
			Volumes:            volumes,
			Restart:            restart,
			Aliases:            aliases,
			Command:            command,
			DependsOn:          dependsOn,
			Labels:             labels,
			UserIgnored:        composePresent(&def.User),
			HealthcheckIgnored: composePresent(&def.Healthcheck),
			EntrypointIgnored:  composePresent(&def.Entrypoint),
		})
	}

	if len(result) == 0 {
		return nil, errors.New("No deployable services found (all services require build context?)")
	}
	return composeOrderByDependencies(result), nil
}

// composeSplitShellCommand splits a shell-form `command:` into argv,
// honouring simple quoting.
//
// Compose hands a shell string to the image's entrypoint verbatim; the Docker
// API wants argv. Anything with real shell syntax in it (pipes, redirection,
// substitution) is passed through `sh -c` rather than mangled into words.
func composeSplitShellCommand(cmd string) []string {
	if strings.ContainsAny(cmd, "|><&;$`") {
		return []string{"sh", "-c", cmd}
	}
	var args []string
	var current strings.Builder
	var quote rune
	for _, c := range cmd {
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0:
			current.WriteRune(c)
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f':
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

// composeOrderByDependencies is a stable topological order over depends_on,
// so a database is created before the service that connects to it.
//
// Cycles and dangling references are not errors — compose files in the wild
// carry both, and refusing to deploy over one would be a worse outcome than
// starting in declaration order. Anything unresolved is appended in the order
// it was declared.
func composeOrderByDependencies(services []ComposeService) []ComposeService {
	known := map[string]bool{}
	for _, s := range services {
		known[s.Key] = true
	}
	pending := make([]int, len(services))
	for i := range services {
		pending[i] = i
	}
	placed := map[string]bool{}
	var order []int

	for len(pending) > 0 {
		before := len(pending)
		var rest []int
		for _, i := range pending {
			ready := true
			for _, d := range services[i].DependsOn {
				if known[d] && !placed[d] {
					ready = false
					break
				}
			}
			if ready {
				placed[services[i].Key] = true
				order = append(order, i)
			} else {
				rest = append(rest, i)
			}
		}
		pending = rest
		if len(pending) == before {
			// A cycle: emit the rest in declaration order and stop.
			order = append(order, pending...)
			break
		}
	}

	out := make([]ComposeService, 0, len(order))
	for _, i := range order {
		out = append(out, services[i])
	}
	return out
}

// composeAsU16 reads a long-form port field (number or numeric string).
func composeAsU16(n *yaml.Node) (uint16, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return 0, false
	}
	switch n.Tag {
	case "!!int":
		var u uint64
		if n.Decode(&u) == nil && u <= math.MaxUint16 {
			return uint16(u), true
		}
	case "!!str":
		if v, err := strconv.ParseUint(n.Value, 10, 16); err == nil {
			return uint16(v), true
		}
	}
	return 0, false
}

func composeParsePorts(ports []yaml.Node) []ComposePortMapping {
	result := []ComposePortMapping{}
	for i := range ports {
		port := &ports[i]
		// Long form — `- target: 80` / `published: 8080` / `protocol: tcp`.
		// This is what `docker compose config` emits, so a file that has been
		// through any compose tooling arrives in this shape; discarding it left
		// the service with no published port and no explanation.
		if port.Kind == yaml.MappingNode {
			var target, published, protocol *yaml.Node
			composeMapping(port, func(k string, v *yaml.Node) {
				switch k {
				case "target":
					target = v
				case "published":
					published = v
				case "protocol":
					protocol = v
				}
			})
			c, cok := composeAsU16(target)
			h, hok := composeAsU16(published)
			if !hok {
				h, hok = c, cok
			}
			proto := "tcp"
			if protocol != nil && protocol.Kind == yaml.ScalarNode && protocol.Tag == "!!str" {
				proto = protocol.Value
			}
			if hok && cok {
				result = append(result, ComposePortMapping{Host: h, Container: c, Protocol: proto})
			}
			continue
		}

		var portStr string
		switch {
		case port.Kind == yaml.ScalarNode && port.Tag == "!!str":
			portStr = port.Value
		case port.Kind == yaml.ScalarNode && (port.Tag == "!!int" || port.Tag == "!!float"):
			s, ok := composeScalarString(port)
			if !ok {
				continue
			}
			portStr = s
		default:
			continue
		}

		// Formats: "8080:80", "8080:80/tcp", "80" (same on host+container)
		mapping, protocol := portStr, "tcp"
		if m, p, ok := strings.Cut(portStr, "/"); ok {
			mapping, protocol = m, p
		}

		if host, cont, ok := strings.Cut(mapping, ":"); ok {
			// Handle IP:host:container format (e.g., "127.0.0.1:8080:80")
			hostPort, containerPort := host, cont
			if strings.Contains(host, ".") || strings.Contains(host, ":") {
				// Has IP prefix, container is the third part
				if hp, cp, ok := strings.Cut(cont, ":"); ok {
					hostPort, containerPort = hp, cp
				} else {
					hostPort, containerPort = cont, cont
				}
			}
			h, err1 := strconv.ParseUint(hostPort, 10, 16)
			c, err2 := strconv.ParseUint(containerPort, 10, 16)
			if err1 == nil && err2 == nil {
				result = append(result, ComposePortMapping{Host: uint16(h), Container: uint16(c), Protocol: protocol})
			}
		} else if p, err := strconv.ParseUint(mapping, 10, 16); err == nil {
			result = append(result, ComposePortMapping{Host: uint16(p), Container: uint16(p), Protocol: protocol})
		}
	}
	return result
}

// ComposeEnsureStackNetwork creates the stack's bridge network if it does
// not already exist. Labelled with the stack id so teardown can prove the
// network is ours before removing it.
func ComposeEnsureStackNetwork(ctx context.Context, docker *client.Client, netName string, stackID *string) error {
	if _, err := docker.NetworkInspect(ctx, netName, client.NetworkInspectOptions{}); err == nil {
		return nil
	}
	labels := map[string]string{"dockpanel.managed": "true"}
	if stackID != nil {
		labels["dockpanel.stack_id"] = *stackID
	}
	if _, err := docker.NetworkCreate(ctx, netName, client.NetworkCreateOptions{Driver: "bridge", Labels: labels}); err != nil {
		return fmt.Errorf("Failed to create stack network %s: %v", netName, err)
	}
	slog.Info("Created Docker network: " + netName)
	return nil
}

// ComposeRemoveStackNetwork removes a stack's network once its containers are
// gone. Best effort by design: Docker refuses to remove a network that still
// has endpoints, which is the correct answer when something is still attached.
func ComposeRemoveStackNetwork(ctx context.Context, stackID *string) {
	netName := ComposeStackNetworkName(stackID)
	docker, err := client.New(client.FromEnv)
	if err != nil {
		return
	}
	defer docker.Close()

	// Only remove a network this stack owns. A network we did not label is a
	// network we did not create.
	info, err := docker.NetworkInspect(ctx, netName, client.NetworkInspectOptions{})
	if err != nil {
		return
	}
	if info.Network.Labels["dockpanel.managed"] != "true" {
		slog.Warn(fmt.Sprintf("Not removing network %s: no dockpanel.managed label", netName))
		return
	}
	if _, err := docker.NetworkRemove(ctx, netName, client.NetworkRemoveOptions{}); err != nil {
		slog.Warn(fmt.Sprintf("Could not remove stack network %s: %v", netName, err))
	} else {
		slog.Info("Removed Docker network: " + netName)
	}
}

// ComposeDeployCompose deploys all services from a parsed compose file. With
// a stack id, every container gets a `dockpanel.stack_id` label.
func ComposeDeployCompose(ctx context.Context, services []ComposeService, stackID *string) ComposeDeployResult {
	netName := ComposeStackNetworkName(stackID)
	failAll := func(msg string) ComposeDeployResult {
		out := ComposeDeployResult{Services: []ComposeServiceDeployResult{}, Network: netName}
		for _, s := range services {
			m := msg
			out.Services = append(out.Services, ComposeServiceDeployResult{Name: s.Name, Status: "failed", Error: &m})
		}
		return out
	}

	docker, err := client.New(client.FromEnv)
	if err != nil {
		return failAll(fmt.Sprintf("Docker connect failed: %v", err))
	}
	defer docker.Close()

	if err := ComposeEnsureStackNetwork(ctx, docker, netName, stackID); err != nil {
		return failAll(err.Error())
	}

	results := []ComposeServiceDeployResult{}
	for i := range services {
		svc := &services[i]
		id, err := composeDeployService(ctx, docker, svc, stackID, netName)
		if err != nil {
			msg := err.error
			results = append(results, ComposeServiceDeployResult{Name: svc.Name, ContainerID: err.containerID, Status: "failed", Error: &msg})
			continue
		}
		results = append(results, ComposeServiceDeployResult{Name: svc.Name, ContainerID: id, Status: "running"})
	}
	return ComposeDeployResult{Services: results, Network: netName}
}

// composeDeployFailure is a service that did not come up. containerID is set
// when the container was created but did not stay running, so the caller can
// still point the operator at it.
type composeDeployFailure struct {
	containerID string
	error       string
}

func composeFail(format string, a ...any) *composeDeployFailure {
	return &composeDeployFailure{error: fmt.Sprintf(format, a...)}
}

// composeScopedVolume resolves a named volume to a stack-scoped one.
//
// Compose namespaces volumes by project; this used to pass the bare name
// through, so two stacks built from the same package silently shared one
// database volume — and since each deploy mints a fresh password, the second
// stack was handed credentials the existing cluster did not have.
//
// A volume that already exists under the bare name is left alone. Renaming it
// would not move the data, it would only hide it.
func composeScopedVolume(ctx context.Context, docker *client.Client, scope, vol string) string {
	scoped := scope + "_" + vol
	if _, err := docker.VolumeInspect(ctx, scoped, client.VolumeInspectOptions{}); err == nil {
		return scoped
	}
	if _, err := docker.VolumeInspect(ctx, vol, client.VolumeInspectOptions{}); err == nil {
		slog.Info(fmt.Sprintf("Reusing existing volume '%s' for this stack (not renaming — the data is in it)", vol))
		return vol
	}
	return scoped
}

// composeAllowedBindPrefix confines host-path binds; composeBlockedPaths are
// refused outright even if a symlink under the prefix resolves to them.
const composeAllowedBindPrefix = "/var/lib/dockpanel/compose/"

var composeBlockedPaths = []string{"/var/run/docker.sock", "/run/docker.sock"}

func composeDeployService(ctx context.Context, docker *client.Client, svc *ComposeService, stackID *string, netName string) (string, *composeDeployFailure) {
	// Pull image (with timeout to prevent hanging on Docker daemon issues).
	// Keep the first pull error: create will fail with "No such image", which
	// points at the wrong thing.
	pctx, cancel := context.WithTimeout(ctx, 300*time.Second)
	var pullError *string
	for _, e := range DockerAppsPullImage(pctx, docker, svc.Image, DockerAppsRegistryCredentialsFor(svc.Image)) {
		slog.Warn(fmt.Sprintf("Image pull warning for %s: %s", svc.Image, e))
		if pullError == nil {
			e := e
			pullError = &e
		}
	}
	timedOut := errors.Is(pctx.Err(), context.DeadlineExceeded)
	cancel()
	if timedOut {
		return "", composeFail("Image pull timed out for %s", svc.Image)
	}

	// Build env vars
	envList := make([]string, 0, len(svc.Environment))
	for k, v := range svc.Environment {
		envList = append(envList, k+"="+v)
	}

	// Port bindings
	portBindings := network.PortMap{}
	exposed := network.PortSet{}
	loop := netip.MustParseAddr("127.0.0.1")
	for _, pm := range svc.Ports {
		p, err := network.ParsePort(fmt.Sprintf("%d/%s", pm.Container, pm.Protocol))
		if err != nil {
			return "", composeFail("Failed to create container %s: invalid port %d/%s", svc.Name, pm.Container, pm.Protocol)
		}
		portBindings[p] = []network.PortBinding{{HostIP: loop, HostPort: strconv.Itoa(int(pm.Host))}}
		exposed[p] = struct{}{}
	}

	// Volume binds — validate that host paths are under the allowed prefix
	// and block mounting the Docker socket.
	var binds []string
	scope := composeStackScope(stackID)
	for _, vol := range svc.Volumes {
		if !strings.Contains(vol, ":") {
			// Shorthand `- /data`: compose would create an anonymous volume.
			// Passing it through as a bind is not possible and silently
			// dropping it loses the persistence the author asked for, so say so.
			slog.Warn(fmt.Sprintf("Service %s: volume '%s' has no host side — anonymous volumes are not supported, "+
				"declare a named volume (e.g. 'data:%s') to persist it", svc.Key, vol, vol))
			continue
		}
		parts := strings.Split(vol, ":")
		hostPath := parts[0]

		// Named volumes (no leading / or .) — scope them to this stack.
		if !strings.HasPrefix(hostPath, "/") && !strings.HasPrefix(hostPath, ".") {
			rest := vol[len(hostPath):]
			binds = append(binds, composeScopedVolume(ctx, docker, scope, hostPath)+rest)
			continue
		}

		// Resolve symlinks and canonicalize the path to prevent symlink-based
		// escapes.
		resolved, err := filepath.EvalSymlinks(hostPath)
		if err == nil {
			resolved, err = filepath.Abs(resolved)
		}
		if err != nil {
			return "", composeFail("Volume mount path does not exist or is inaccessible: %s", hostPath)
		}

		// Block docker socket
		for _, blocked := range composeBlockedPaths {
			if resolved == blocked {
				return "", composeFail("Blocked volume mount: %s is not allowed", hostPath)
			}
		}
		// Only allow paths under the sanctioned prefix
		if !strings.HasPrefix(resolved, composeAllowedBindPrefix) {
			return "", composeFail("Blocked volume mount: host path '%s' must be under %s", hostPath, composeAllowedBindPrefix)
		}
		// Reject path traversal attempts
		if strings.Contains(hostPath, "..") {
			return "", composeFail("Blocked volume mount: path traversal not allowed in '%s'", hostPath)
		}

		// TOCTOU fix: use the resolved (canonicalized) path in the actual
		// mount, not the user-supplied path which could be a symlink.
		containerPath := ""
		if len(parts) > 1 {
			containerPath = parts[1]
		}
		bind := resolved + ":" + containerPath
		if len(parts) > 2 {
			bind += ":" + parts[2]
		}
		binds = append(binds, bind)
	}

	// Restart policy
	restart := container.RestartPolicyDisabled
	switch svc.Restart {
	case "always":
		restart = container.RestartPolicyAlways
	case "unless-stopped":
		restart = container.RestartPolicyUnlessStopped
	case "on-failure":
		restart = container.RestartPolicyOnFailure
	}

	hostConfig := &container.HostConfig{
		Binds:         binds,
		RestartPolicy: container.RestartPolicy{Name: restart},
		SecurityOpt:   []string{"no-new-privileges:true"},
		CapDrop:       []string{"ALL"},
		CapAdd:        []string{"CHOWN", "SETUID", "SETGID", "NET_BIND_SERVICE", "DAC_OVERRIDE", "FOWNER", "SETFCAP"},
	}
	if len(portBindings) > 0 {
		hostConfig.PortBindings = portBindings
	}

	// Author labels first, ours second: the panel's namespace wins even if
	// the filter in parsing were ever loosened.
	labels := map[string]string{}
	for k, v := range svc.Labels {
		labels[k] = v
	}
	labels["dockpanel.managed"] = "true"
	labels["dockpanel.app.template"] = "compose"
	labels["dockpanel.app.name"] = svc.Name
	labels["dockpanel.compose.service"] = svc.Key
	if stackID != nil {
		labels["dockpanel.stack_id"] = *stackID
	}

	config := &container.Config{
		Image:  svc.Image,
		Cmd:    svc.Command,
		Env:    envList,
		Labels: labels,
	}
	if len(exposed) > 0 {
		config.ExposedPorts = exposed
	}

	// Attach to the stack network under the compose service key. Without this
	// the container lands on the default bridge, where the name its siblings
	// were configured with does not resolve.
	netConfig := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{netName: {Aliases: svc.Aliases}},
	}

	cctx, ccancel := context.WithTimeout(ctx, 30*time.Second)
	created, err := docker.ContainerCreate(cctx, client.ContainerCreateOptions{
		Name: svc.Name, Config: config, HostConfig: hostConfig, NetworkingConfig: netConfig,
	})
	ctimedOut := errors.Is(cctx.Err(), context.DeadlineExceeded)
	ccancel()
	if err != nil {
		if ctimedOut {
			return "", composeFail("Create container timed out for %s", svc.Name)
		}
		hint := ""
		if pullError != nil {
			hint = fmt.Sprintf(" (image pull reported: %s)", *pullError)
		}
		return "", composeFail("Failed to create container %s: %v%s", svc.Name, err, hint)
	}

	sctx, scancel := context.WithTimeout(ctx, 30*time.Second)
	_, err = docker.ContainerStart(sctx, created.ID, client.ContainerStartOptions{})
	stimedOut := errors.Is(sctx.Err(), context.DeadlineExceeded)
	scancel()
	if err != nil {
		if stimedOut {
			return "", composeFail("Start container timed out for %s", svc.Name)
		}
		return "", &composeDeployFailure{containerID: created.ID, error: fmt.Sprintf("Failed to start container %s: %v", svc.Name, err)}
	}

	// Start returning Ok means the process was launched, not that it lived.
	// A service that exits on a bad config or an unreachable dependency used
	// to be reported as "running" and the operator was told the stack deployed.
	if f := composeConfirmRunning(ctx, docker, created.ID, svc.Key); f != nil {
		return "", f
	}

	slog.Info(fmt.Sprintf("Compose service deployed: %s (key=%s, image=%s, network=%s)", svc.Name, svc.Key, svc.Image, netName))
	return created.ID, nil
}

// composeConfirmRunning waits for a just-started container to still be up,
// and explains it if not. Polls rather than sleeping a fixed interval: a
// healthy container passes on the first check, and only a failing one pays
// the full wait.
func composeConfirmRunning(ctx context.Context, docker *client.Client, containerID, key string) *composeDeployFailure {
	checks := []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond, 3000 * time.Millisecond, 5000 * time.Millisecond}
	lastState := "unknown"

	for i, d := range checks {
		select {
		case <-ctx.Done():
		case <-time.After(d):
		}

		res, err := docker.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
		if err != nil {
			return &composeDeployFailure{containerID: containerID, error: fmt.Sprintf("Service '%s' could not be inspected after start: %v", key, err)}
		}
		state := res.Container.State
		if state != nil && state.Running {
			return nil
		}

		lastState = "exited"
		exitCode := 0
		if state != nil {
			if state.Status != "" {
				lastState = strings.ToLower(string(state.Status))
			}
			exitCode = state.ExitCode
		}

		// A container that is restarting may yet settle; one that has exited
		// for good will not, so stop waiting on it immediately.
		if lastState != "restarting" || i == len(checks)-1 {
			logs := composeTailLogs(ctx, docker, containerID)
			return &composeDeployFailure{
				containerID: containerID,
				error:       fmt.Sprintf("Service '%s' started and then %s (exit code %d). Last output:\n%s", key, lastState, exitCode, logs),
			}
		}
	}
	return &composeDeployFailure{containerID: containerID, error: fmt.Sprintf("Service '%s' did not stay running (state: %s)", key, lastState)}
}

// composeTailLogs returns the last few lines of a container's output, for a
// failure message.
func composeTailLogs(ctx context.Context, docker *client.Client, containerID string) string {
	out, _ := dockerAppsReadLogs(ctx, docker, containerID, "20")
	if strings.TrimSpace(out) == "" {
		return "(no output)"
	}
	return strings.TrimRight(out, " \t\r\n")
}
