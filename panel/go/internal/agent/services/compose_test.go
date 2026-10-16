package services

import (
	"slices"
	"strings"
	"testing"
)

const composeTTwoService = `
services:
  app:
    image: myapp:1
    depends_on:
      - database
    environment:
      DATABASE_URL: postgresql://app:pw@database:5432/app
    ports:
      - "8085:80"
  database:
    image: postgres:16-alpine
    volumes:
      - pgdata:/var/lib/postgresql/data
`

func composeTParse(t *testing.T, yaml string, stack *string) []ComposeService {
	t.Helper()
	s, err := ComposeParseCompose(yaml, stack)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func composeTFind(services []ComposeService, key string) *ComposeService {
	for i := range services {
		if services[i].Key == key {
			return &services[i]
		}
	}
	return nil
}

func composeTStr(s string) *string { return &s }

func TestServiceKeyIsKeptAndBecomesANetworkAlias(t *testing.T) {
	db := composeTFind(composeTParse(t, composeTTwoService, composeTStr("abc123def456")), "database")
	// The alias is what `postgresql://...@database:5432` resolves against.
	if !slices.Contains(db.Aliases, "database") {
		t.Fatal(db.Aliases)
	}
}

func TestContainerNamesAreScopedByStack(t *testing.T) {
	a := composeTFind(composeTParse(t, composeTTwoService, composeTStr("aaaaaaaa-1111")), "database").Name
	b := composeTFind(composeTParse(t, composeTTwoService, composeTStr("bbbbbbbb-2222")), "database").Name
	if a == b || !strings.HasPrefix(a, "dockpanel-compose-") {
		t.Fatal(a, b)
	}
}

func TestNetworksAreScopedByStack(t *testing.T) {
	if ComposeStackNetworkName(composeTStr("aaaaaaaa-1111")) == ComposeStackNetworkName(composeTStr("bbbbbbbb-2222")) {
		t.Fatal()
	}
}

func TestAnAuthorChosenContainerNameBecomesAnAliasNotTheDockerName(t *testing.T) {
	web := composeTParse(t, "services:\n  web:\n    image: nginx:alpine\n    container_name: my-web\n", composeTStr("abc123"))[0]
	if web.Name == "my-web" || !slices.Contains(web.Aliases, "my-web") || !slices.Contains(web.Aliases, "web") {
		t.Fatal(web)
	}
}

func TestDependenciesOrderTheDeploy(t *testing.T) {
	s := composeTParse(t, composeTTwoService, composeTStr("abc123"))
	db := slices.IndexFunc(s, func(c ComposeService) bool { return c.Key == "database" })
	app := slices.IndexFunc(s, func(c ComposeService) bool { return c.Key == "app" })
	if db >= app {
		t.Fatal("database must be created before app")
	}
}

func TestADependencyCycleStillDeploys(t *testing.T) {
	s := composeTParse(t, "services:\n  a:\n    image: x:1\n    depends_on: [b]\n  b:\n    image: y:1\n    depends_on: [a]\n", nil)
	if len(s) != 2 {
		t.Fatal(s)
	}
}

func TestLongFormPortsArePublished(t *testing.T) {
	s := composeTParse(t, "services:\n  web:\n    image: nginx:alpine\n    ports:\n      - target: 80\n        published: 8080\n        protocol: tcp\n", nil)
	if len(s[0].Ports) != 1 || s[0].Ports[0].Host != 8080 || s[0].Ports[0].Container != 80 {
		t.Fatal(s[0].Ports)
	}
}

func TestShortFormPortsParseEveryShape(t *testing.T) {
	s := composeTParse(t, "services:\n  web:\n    image: x:1\n    ports:\n      - \"8080:80\"\n      - \"127.0.0.1:9090:90/udp\"\n      - 70\n", nil)
	want := []ComposePortMapping{{8080, 80, "tcp"}, {9090, 90, "udp"}, {70, 70, "tcp"}}
	if !slices.Equal(s[0].Ports, want) {
		t.Fatal(s[0].Ports)
	}
}

func TestCommandSurvivesParsing(t *testing.T) {
	cmd := composeTParse(t, "services:\n  worker:\n    image: myapp:1\n    command: php /app/bin/console messenger:consume --all\n", nil)[0].Command
	if cmd == nil || cmd[0] != "php" || !slices.Contains(cmd, "messenger:consume") {
		t.Fatal(cmd)
	}
}

func TestAShellCommandGoesThroughShRatherThanBeingMangled(t *testing.T) {
	argv := composeSplitShellCommand("sh -c 'echo hi' | tee /tmp/x")
	if argv[0] != "sh" || argv[1] != "-c" {
		t.Fatal(argv)
	}
}

func TestDependsOnLongFormIsUnderstood(t *testing.T) {
	s := composeTParse(t, "services:\n  app:\n    image: x:1\n    depends_on:\n      database:\n        condition: service_healthy\n  database:\n    image: postgres:16-alpine\n", nil)
	if !slices.Equal(composeTFind(s, "app").DependsOn, []string{"database"}) {
		t.Fatal()
	}
}

func TestAuthorLabelsSurviveButThePanelNamespaceDoesNot(t *testing.T) {
	labels := composeTParse(t, "services:\n  web:\n    image: nginx:alpine\n    labels:\n      traefik.enable: \"true\"\n      dockpanel.managed: \"false\"\n      dockpanel.stack_id: somebody-elses-stack\n", composeTStr("abc123"))[0].Labels
	if labels["traefik.enable"] != "true" {
		t.Fatal(labels)
	}
	// A compose file must not be able to hide a container from the panel or
	// attach it to another stack.
	for k := range labels {
		if strings.HasPrefix(k, "dockpanel.") {
			t.Fatal(k)
		}
	}
}

func TestDangerousOptionsAreStillRejected(t *testing.T) {
	for _, y := range []string{
		"services:\n  bad:\n    image: x:1\n    privileged: true\n",
		"services:\n  bad:\n    image: x:1\n    network_mode: host\n",
		"services:\n  bad:\n    image: x:1\n    network_mode: \"container:abc\"\n",
		"services:\n  bad:\n    image: x:1\n    pid: host\n",
		"services:\n  bad:\n    image: x:1\n    ipc: host\n",
		"services:\n  bad:\n    image: x:1\n    cap_add: [sys_admin]\n",
		"services:\n  bad:\n    image: x:1\n    devices: []\n",
	} {
		if _, err := ComposeParseCompose(y, nil); err == nil {
			t.Errorf("accepted: %s", y)
		}
	}
}

// security_opt was parsed but never checked; positive control: the panel's
// own no-new-privileges:true default must stay allowed.
func TestSecurityOptUnconfinedIsRejectedButHardeningOptsAreNot(t *testing.T) {
	if _, err := ComposeParseCompose("services:\n  bad:\n    image: x:1\n    security_opt:\n      - seccomp:unconfined\n", nil); err == nil {
		t.Fatal("seccomp:unconfined must be rejected")
	}
	if _, err := ComposeParseCompose("services:\n  bad:\n    image: x:1\n    security_opt:\n      - apparmor:unconfined\n", nil); err == nil {
		t.Fatal("apparmor:unconfined must be rejected")
	}
	if _, err := ComposeParseCompose("services:\n  fine:\n    image: x:1\n    security_opt:\n      - no-new-privileges:true\n", nil); err != nil {
		t.Fatal(err)
	}
}

func TestUserHealthcheckAndEntrypointAreFlaggedAsIgnoredWhenDeclared(t *testing.T) {
	svc := composeTParse(t, "services:\n  full:\n    image: x:1\n    user: \"1000:1000\"\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n    entrypoint: [\"/bin/sh\"]\n", nil)[0]
	if !svc.UserIgnored || !svc.HealthcheckIgnored || !svc.EntrypointIgnored {
		t.Fatal(svc)
	}
}

func TestUserHealthcheckAndEntrypointAreNotFlaggedWhenAbsent(t *testing.T) {
	svc := composeTParse(t, "services:\n  plain:\n    image: x:1\n", nil)[0]
	if svc.UserIgnored || svc.HealthcheckIgnored || svc.EntrypointIgnored {
		t.Fatal(svc)
	}
}

func TestEnvironmentAcceptsBothShapesAndRendersScalars(t *testing.T) {
	m := composeTParse(t, "services:\n  a:\n    image: x:1\n    environment:\n      S: str\n      N: 5\n      B: true\n", nil)[0].Environment
	if m["S"] != "str" || m["N"] != "5" || m["B"] != "true" {
		t.Fatal(m)
	}
	l := composeTParse(t, "services:\n  a:\n    image: x:1\n    environment:\n      - A=1\n      - NOEQ\n", nil)[0].Environment
	if len(l) != 1 || l["A"] != "1" {
		t.Fatal(l)
	}
}

func TestServicesWithoutAnImageAreSkippedAndNoneLeftIsAnError(t *testing.T) {
	if _, err := ComposeParseCompose("services:\n  b:\n    build: .\n", nil); err == nil || !strings.Contains(err.Error(), "No deployable services") {
		t.Fatal(err)
	}
	if _, err := ComposeParseCompose("version: '3'\n", nil); err == nil || !strings.Contains(err.Error(), "No 'services' key") {
		t.Fatal(err)
	}
	if _, err := ComposeParseCompose("services: [\n", nil); err == nil || !strings.HasPrefix(err.Error(), "Invalid YAML") {
		t.Fatal(err)
	}
}
