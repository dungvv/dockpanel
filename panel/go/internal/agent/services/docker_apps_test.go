package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

// minio/minio's default CMD is ["minio"], which prints usage and exits 0 — so
// the container restarts forever at ExitCode 0 rather than serving (#101).
func TestMinioOverridesACmdThatWouldExitInsteadOfServing(t *testing.T) {
	cmd := dockerAppsTemplateCmdOf("minio")
	if !slices.Equal(cmd, []string{"server", "/data", "--console-address", ":9001"}) {
		t.Fatalf("minio must carry startup arguments, got %v", cmd)
	}
	// The served path must be the one the template persists, or the container
	// comes up healthy and silently loses every object on restart.
	minio := dockerAppsTemplateByID("minio")
	if minio == nil {
		t.Fatal("the minio template must exist")
	}
	if !slices.Contains(minio.Volumes, "/data") {
		t.Fatalf("minio serves /data but persists %v", minio.Volumes)
	}
}

// Absence is the default for an image whose entrypoint already serves — but
// absence is NOT proof that a template is fine. The three genuinely still
// without a command are surrealdb, authentik and vllm; §6 of
// app-template-images-pin-e2e.sh explains why a command is the wrong
// instrument for each.
func TestEveryCmdOverrideIsLiveAndWellFormed(t *testing.T) {
	if dockerAppsTemplateCmdOf("minio") == nil || dockerAppsTemplateCmdOf("ghost") != nil || dockerAppsTemplateCmdOf("no-such-template") != nil {
		t.Fatal()
	}
	// Every override must name a real template, or it is dead configuration
	// that looks live.
	for _, e := range dockerAppsTemplateCmd {
		if dockerAppsTemplateByID(e.id) == nil {
			t.Errorf("TEMPLATE_CMD names '%s', which is not in the catalogue", e.id)
		}
		if len(e.args) == 0 {
			t.Errorf("'%s' carries an empty command", e.id)
		}
	}
}

func TestManagedLabelGate(t *testing.T) {
	// Only dockpanel.managed=true passes; panel infra (no such label) and false are rejected.
	if !dockerAppsIsManagedLabels(map[string]string{"dockpanel.managed": "true"}) {
		t.Fatal()
	}
	if dockerAppsIsManagedLabels(map[string]string{"dockpanel.managed": "false"}) {
		t.Fatal()
	}
	// A panel-infra container (e.g. only compose labels) must be rejected.
	if dockerAppsIsManagedLabels(map[string]string{"com.docker.compose.project": "dockpanel"}) {
		t.Fatal()
	}
	if dockerAppsIsManagedLabels(map[string]string{}) || dockerAppsIsManagedLabels(nil) {
		t.Fatal()
	}
}

func dockerAppsTStr(s string) *string { return &s }

// ── What Update does when the image will not pull ────────────────────────

func TestAPullThatWorkedIsNotSecondGuessed(t *testing.T) {
	if dockerAppsDecidePull(nil, dockerAppsTStr("sha256:aaa"), dockerAppsTStr("sha256:aaa")) != dockerAppsPullProceed {
		t.Fatal()
	}
	// Even with nothing resolvable locally: a successful pull put it there,
	// and the inspect that follows is not the authority on that.
	if dockerAppsDecidePull(nil, nil, nil) != dockerAppsPullProceed {
		t.Fatal()
	}
}

func TestADeadTagWithNoLocalCopyLeavesTheContainerAlone(t *testing.T) {
	// The one case that used to destroy the app: the remove succeeds, the
	// create then fails on an image that is nowhere, and nothing puts it back.
	if dockerAppsDecidePull(dockerAppsTStr("manifest unknown"), nil, dockerAppsTStr("sha256:aaa")) != dockerAppsPullRefuseMissing {
		t.Fatal()
	}
}

func TestADeadTagWhoseLocalCopyIsAlreadyRunningIsNotWorthAnOutage(t *testing.T) {
	if dockerAppsDecidePull(dockerAppsTStr("no such host"), dockerAppsTStr("sha256:aaa"), dockerAppsTStr("sha256:aaa")) != dockerAppsPullRefuseNoChange {
		t.Fatal()
	}
}

func TestADeadTagStillAppliesAnUpdateThatIsAlreadyOnDisk(t *testing.T) {
	// An earlier pull succeeded and the container was never recreated, so
	// pressing Update has real work to do even though today's pull failed.
	if dockerAppsDecidePull(dockerAppsTStr("timeout"), dockerAppsTStr("sha256:bbb"), dockerAppsTStr("sha256:aaa")) != dockerAppsPullProceedFromLocal {
		t.Fatal()
	}
}

func TestAnUnreadableRunningImageNeverBlocksAnUpdateItCannotDestroy(t *testing.T) {
	if dockerAppsDecidePull(dockerAppsTStr("timeout"), dockerAppsTStr("sha256:bbb"), nil) != dockerAppsPullProceedFromLocal {
		t.Fatal()
	}
}

// ── Domain-derived template env (GitHub #111) ────────────────────────────

func dockerAppsTTemplate(t *testing.T, id string) *dockerAppsTemplateDef {
	t.Helper()
	tpl := dockerAppsTemplateByID(id)
	if tpl == nil {
		t.Fatalf("template %s missing from the catalogue", id)
	}
	return tpl
}

func TestN8nGetsAllFourOfItsURLVarsFromTheClaimedDomain(t *testing.T) {
	tpl := dockerAppsTTemplate(t, "n8n")
	if len(tpl.EnvVars) != 0 {
		t.Fatal("n8n declaring env vars would change which merge branch fills these in")
	}
	out := dockerAppsMergeDeployEnv(tpl.EnvVars, map[string]string{}, dockerAppsDomainEnvFor("n8n", "n8n.example.com"))
	for _, want := range []string{"N8N_HOST=n8n.example.com", "N8N_PROTOCOL=https", "WEBHOOK_URL=https://n8n.example.com/", "N8N_PROXY_HOPS=1"} {
		if !slices.Contains(out, want) {
			t.Fatalf("missing %s in %v", want, out)
		}
	}
	if len(out) != 4 {
		t.Fatalf("nothing else should be emitted: %v", out)
	}
}

func TestNoDomainMeansNoDerivationAndTheCatalogueDefaultStillStands(t *testing.T) {
	out := dockerAppsMergeDeployEnv(dockerAppsTTemplate(t, "ghost").EnvVars, map[string]string{}, nil)
	if !slices.Contains(out, "url=http://localhost:2368") {
		t.Fatal(out)
	}
	n8n := dockerAppsMergeDeployEnv(dockerAppsTTemplate(t, "n8n").EnvVars, map[string]string{}, nil)
	if len(n8n) != 0 {
		t.Fatal(n8n)
	}
}

func TestAnOperatorValueThatDiffersFromTheDefaultBeatsTheDerivedOne(t *testing.T) {
	out := dockerAppsMergeDeployEnv(dockerAppsTTemplate(t, "ghost").EnvVars,
		map[string]string{"url": "https://cdn.example.net"}, dockerAppsDomainEnvFor("ghost", "blog.example.com"))
	if !slices.Contains(out, "url=https://cdn.example.net") {
		t.Fatalf("operator value must win: %v", out)
	}
	if slices.Contains(out, "url=https://blog.example.com") {
		t.Fatalf("derived value must not also be emitted: %v", out)
	}
}

func TestASubmittedValueStillEqualToTheDefaultIsTreatedAsUntouched(t *testing.T) {
	out := dockerAppsMergeDeployEnv(dockerAppsTTemplate(t, "ghost").EnvVars,
		map[string]string{"url": "http://localhost:2368"}, dockerAppsDomainEnvFor("ghost", "blog.example.com"))
	if !slices.Contains(out, "url=https://blog.example.com") {
		t.Fatal(out)
	}
}

func TestADerivedVarTheOperatorAlsoSentIsEmittedExactlyOnce(t *testing.T) {
	out := dockerAppsMergeDeployEnv(dockerAppsTTemplate(t, "n8n").EnvVars,
		map[string]string{"N8N_HOST": "manual.example.com"}, dockerAppsDomainEnvFor("n8n", "n8n.example.com"))
	var hosts []string
	for _, e := range out {
		if strings.HasPrefix(e, "N8N_HOST=") {
			hosts = append(hosts, e)
		}
	}
	if len(hosts) != 1 || hosts[0] != "N8N_HOST=manual.example.com" {
		t.Fatal(out)
	}
}

func TestEveryDomainDerivedNameExistsOnTheTemplateItIsKeyedTo(t *testing.T) {
	// A severed-pair guard. n8n is the deliberate exception: it declares none
	// of its four, which is the whole reason they are derived.
	for _, e := range dockerAppsTemplateDomainEnv {
		tpl := dockerAppsTTemplate(t, e.templateID)
		if e.templateID == "n8n" {
			continue
		}
		for _, v := range e.vars {
			if !slices.ContainsFunc(tpl.EnvVars, func(ev dockerAppsEnvVarDef) bool { return ev.Name == v.name }) {
				t.Errorf("%s has no env var %s", e.templateID, v.name)
			}
		}
	}
}

func TestEveryDomainDerivedTemplateStillExistsInTheCatalogue(t *testing.T) {
	for _, e := range dockerAppsTemplateDomainEnv {
		dockerAppsTTemplate(t, e.templateID)
	}
}

func TestTheDerivedFlagTheFormReadsMatchesWhatDeployActuallyDerives(t *testing.T) {
	for _, tpl := range dockerAppsTemplates {
		derived := dockerAppsDomainEnvFor(tpl.ID, "example.com")
		for _, ev := range tpl.EnvVars {
			has := slices.ContainsFunc(derived, func(d dockerAppsNameValue) bool { return d.name == ev.Name })
			if dockerAppsIsDomainDerived(tpl.ID, ev.Name) != has {
				t.Errorf("%s.%s flag disagrees with derivation", tpl.ID, ev.Name)
			}
		}
	}
	if dockerAppsIsDomainDerived("postgres", "POSTGRES_PASSWORD") {
		t.Fatal()
	}
}

func TestADerivedURLNeverCarriesTheContainerPort(t *testing.T) {
	for _, e := range dockerAppsTemplateDomainEnv {
		derived := dockerAppsDomainEnvFor(e.templateID, "example.com")
		if len(derived) != len(e.vars) {
			t.Fatal()
		}
		for _, d := range derived {
			if strings.Contains(d.value, "example.com:") || strings.Contains(d.value, "localhost") {
				t.Errorf("%s.%s = %s", e.templateID, d.name, d.value)
			}
		}
	}
}

func TestAMaskedValueSentBackLeavesTheRealOneAlone(t *testing.T) {
	container := []string{"ADMIN_TOKEN=hunter2-the-real-one", "PUID=1000"}
	list, kept := DockerAppsMergeEnvPreservingMasked(map[string]string{"ADMIN_TOKEN": DockerAppsEnvMask, "PUID": "1001"}, container)
	if !slices.Contains(list, "ADMIN_TOKEN=hunter2-the-real-one") {
		t.Fatalf("the real value must survive; got %v", list)
	}
	if slices.ContainsFunc(list, func(kv string) bool { return strings.Contains(kv, DockerAppsEnvMask) }) {
		t.Fatal(list)
	}
	if !slices.Contains(list, "PUID=1001") {
		t.Fatal("edits still apply")
	}
	if !slices.Equal(kept, []string{"ADMIN_TOKEN"}) {
		t.Fatal(kept)
	}
}

func TestAValueThatMerelyLooksLikeTheMaskIsNotResurrected(t *testing.T) {
	list, kept := DockerAppsMergeEnvPreservingMasked(map[string]string{"NEW": DockerAppsEnvMask}, nil)
	if !slices.Equal(list, []string{"NEW=" + DockerAppsEnvMask}) || len(kept) != 0 {
		t.Fatal(list, kept)
	}
}

func TestAContainerEnvEntryWithNoEqualsDoesNotDerailTheMerge(t *testing.T) {
	list, _ := DockerAppsMergeEnvPreservingMasked(map[string]string{"A": DockerAppsEnvMask}, []string{"MALFORMED", "A=1"})
	if !slices.Equal(list, []string{"A=1"}) {
		t.Fatal(list)
	}
}

func TestTheCatalogueExemptsItsOwnNonSecretsAndNeverItsSecrets(t *testing.T) {
	for _, n := range []string{"KEYCLOAK_ADMIN", "NEXTAUTH_URL", "AUTHENTIK_POSTGRESQL__HOST", "AUTHENTIK_REDIS__HOST"} {
		if !DockerAppsCatalogueNonSecretEnv(n) {
			t.Errorf("%s is declared secret:false in the catalogue and must not be masked", n)
		}
	}
	for _, n := range []string{"KEYCLOAK_ADMIN_PASSWORD", "NEXTAUTH_SECRET", "AUTHENTIK_SECRET_KEY", "AUTHENTIK_POSTGRESQL__PASSWORD"} {
		if DockerAppsCatalogueNonSecretEnv(n) {
			t.Errorf("%s must stay masked", n)
		}
	}
	if DockerAppsCatalogueNonSecretEnv("SOME_VENDOR_API_KEY") {
		t.Fatal()
	}
}

// ── Volume ownership ───────────────────────────────────────────

func TestRootUserSpecsAreRecognisedInEverySpelling(t *testing.T) {
	for _, s := range []string{"", "root", "0", "0:0", "root:root", "  root  ", "0:1000"} {
		if !dockerAppsUserSpecIsRoot(s) {
			t.Errorf("%q names root", s)
		}
	}
	for _, s := range []string{"nobody", "472", "nonroot", "65532:65532", "node-red", "1000"} {
		if dockerAppsUserSpecIsRoot(s) {
			t.Errorf("%q does not name root", s)
		}
	}
}

func TestUserSpecsSplitIntoTheirHalves(t *testing.T) {
	cases := []struct {
		spec, user string
		group      *string
	}{
		{"nobody", "nobody", nil},
		{"65532:65532", "65532", dockerAppsTStr("65532")},
		{"node:node", "node", dockerAppsTStr("node")},
		{"1000:staff", "1000", dockerAppsTStr("staff")},
	}
	for _, c := range cases {
		u, g := dockerAppsSplitUserSpec(c.spec)
		if u != c.user || (g == nil) != (c.group == nil) || (g != nil && *g != *c.group) {
			t.Errorf("%q split wrong", c.spec)
		}
	}
}

// The real /etc/passwd out of prom/prometheus:v3, whose Config.User is the
// NAME `nobody` — resolvable only from inside the image.
func TestALoginNameResolvesFromTheImagesOwnPasswd(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/ash\nnobody:x:65534:65534:nobody:/home:/bin/false\n"
	if u, g, ok := dockerAppsPasswdLookup(passwd, "nobody"); !ok || u != 65534 || g != 65534 {
		t.Fatal()
	}
	if u, g, ok := dockerAppsPasswdLookup(passwd, "root"); !ok || u != 0 || g != 0 {
		t.Fatal()
	}
	// A name the image does not define must fail rather than guess.
	if _, _, ok := dockerAppsPasswdLookup(passwd, "grafana"); ok {
		t.Fatal()
	}
	// A bare numeric uid still wants its primary group.
	if g, ok := dockerAppsPasswdGidForUID(passwd, 65534); !ok || g != 65534 {
		t.Fatal()
	}
	if _, ok := dockerAppsPasswdGidForUID(passwd, 472); ok {
		t.Fatal()
	}
}

func TestAGroupNameResolvesFromTheImagesOwnGroupFile(t *testing.T) {
	group := "root:x:0:\nnogroup:x:65534:\nnode-red:x:1000:\n"
	if g, ok := dockerAppsGroupLookup(group, "nogroup"); !ok || g != 65534 {
		t.Fatal()
	}
	if g, ok := dockerAppsGroupLookup(group, "node-red"); !ok || g != 1000 {
		t.Fatal()
	}
	if _, ok := dockerAppsGroupLookup(group, "absent"); ok {
		t.Fatal()
	}
}

// The tar reader has to cope with what `docker cp` actually returns, and must
// stop rather than guess when it is handed something else.
func TestTheTarReaderExtractsAFileAndRefusesJunk(t *testing.T) {
	ustar := func(name, body string) []byte {
		block := make([]byte, 512)
		copy(block, name)
		copy(block[124:], fmt.Sprintf("%011o\x00", len(body)))
		block[156] = '0'
		block = append(block, body...)
		return append(block, make([]byte, int(dockerAppsDivCeil512(uint64(len(body))))-len(body))...)
	}
	body := "nobody:x:65534:65534:nobody:/home:/bin/false\n"
	if got, ok := dockerAppsTarExtractFirstFile(ustar("passwd", body)); !ok || got != body {
		t.Fatal(got)
	}
	// An all-zero block is the end of an archive, not a file.
	if _, ok := dockerAppsTarExtractFirstFile(make([]byte, 1024)); ok {
		t.Fatal()
	}
	// A truncated stream must not panic or return a partial read. The cut has
	// to land INSIDE the body (header 512 + body 44 = 556).
	if _, ok := dockerAppsTarExtractFirstFile(ustar("passwd", body)[:530]); ok {
		t.Fatal()
	}
	if _, ok := dockerAppsTarExtractFirstFile(nil); ok {
		t.Fatal()
	}
}

// Every template whose image runs non-root and declares a volume needed the
// chown, so the catalogue must not quietly lose the volumes that make them
// victims. ⚠ The cases are spelled "id count" rather than as pairs on purpose:
// app-template-images-pin-e2e.sh §6 greps whitespace-stripped source for a
// parenthesised template id followed by a comma. Do not "tidy" this.
func TestTheMeasuredVictimsStillDeclareTheVolumesTheyCouldNotWrite(t *testing.T) {
	for _, c := range []string{"prometheus 1", "grafana 1", "jenkins 1", "mattermost 3", "sonarqube 3", "node-red 1", "surrealdb 1"} {
		id, countStr, _ := strings.Cut(c, " ")
		count, _ := strconv.Atoi(countStr)
		tpl := dockerAppsTTemplate(t, id)
		if len(tpl.Volumes) != count {
			t.Errorf("%s declares %v", id, tpl.Volumes)
		}
	}
}

// dockerAppsGeneratedCatalogue is the catalogue projected to data, so a
// checker never has to parse source. Every defect this file has shipped was
// found by something READING it; a committed artefact plus a test that FAILS
// when it stops matching stands between a changed template and a merge.
//
// The `_generated` text is kept byte-identical to the Rust generator's so the
// one fixture serves both implementations while they coexist.
func dockerAppsGeneratedCatalogue(t *testing.T) string {
	templates := make([]any, 0, len(dockerAppsTemplates))
	for _, tpl := range dockerAppsTemplates {
		envVars := make([]any, 0, len(tpl.EnvVars))
		for _, e := range tpl.EnvVars {
			envVars = append(envVars, map[string]any{
				"name": e.Name, "label": e.Label, "default": e.Default, "required": e.Required, "secret": e.Secret,
			})
		}
		volumes := tpl.Volumes
		if volumes == nil {
			volumes = []string{}
		}
		templates = append(templates, map[string]any{
			"id":             tpl.ID,
			"name":           tpl.Name,
			"category":       tpl.Category,
			"image":          tpl.Image,
			"default_port":   tpl.DefaultPort,
			"container_port": tpl.ContainerPort,
			// Null for all but the handful the catalogue overrides, which is
			// exactly what the container gets.
			"cmd":      dockerAppsTemplateCmdOf(tpl.ID),
			"env_vars": envVars,
			"volumes":  volumes,
		})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{
		"_generated": "Do not edit. Source of truth is TEMPLATES in panel/agent/src/services/docker_apps.rs. " +
			"Regenerate with UPDATE_TEMPLATE_CATALOGUE=1 cargo test -p dockpanel-agent catalogue",
		"count":     len(dockerAppsTemplates),
		"templates": templates,
	}); err != nil {
		t.Fatalf("the catalogue serialises: %v", err)
	}
	return buf.String()
}

// Regenerate with:
//
//	UPDATE_TEMPLATE_CATALOGUE=1 go test ./internal/agent/services -run Catalogue
func TestTheGeneratedCatalogueIsCurrent(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(self), "../../../../../tests/fixtures/app-templates.json")
	expected := dockerAppsGeneratedCatalogue(t)
	const regen = "UPDATE_TEMPLATE_CATALOGUE=1 go test ./internal/agent/services -run Catalogue"

	if os.Getenv("UPDATE_TEMPLATE_CATALOGUE") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(expected), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	found, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("tests/fixtures/app-templates.json is missing (%v). Regenerate it:\n    %s", err, regen)
	}
	if string(found) != expected {
		// Name the first divergence rather than printing two 148-entry
		// documents at each other.
		f, e := strings.Split(string(found), "\n"), strings.Split(expected, "\n")
		line, committed, registry := min(len(f), len(e))+1, "<end of file>", "<more lines>"
		for i := 0; i < min(len(f), len(e)); i++ {
			if f[i] != e[i] {
				line, committed, registry = i+1, f[i], e[i]
				break
			}
		}
		t.Fatalf("tests/fixtures/app-templates.json is out of date — the catalogue changed and this artefact did not.\n"+
			"First difference at line %d:\n  committed: %s\n  registry:  %s\n\nRegenerate it:\n    %s", line, committed, registry, regen)
	}
}

// ── Tar seeding / ownership repair ─────────────────────────────

func dockerAppsTarHeader(name string, size int, kind byte, mode uint32) []byte {
	h := make([]byte, 512)
	copy(h, name)
	copy(h[100:], fmt.Sprintf("%07o\x00", mode))
	copy(h[124:], fmt.Sprintf("%011o\x00", size))
	h[156] = kind
	return h
}

func dockerAppsTarEntryMode(name string, body []byte, kind byte, mode uint32) []byte {
	out := dockerAppsTarHeader(name, len(body), kind, mode)
	out = append(out, body...)
	return append(out, make([]byte, int(dockerAppsDivCeil512(uint64(len(body))))-len(body))...)
}

func dockerAppsTarEntry(name string, body []byte, kind byte) []byte {
	return dockerAppsTarEntryMode(name, body, kind, 0o644)
}

func dockerAppsTarEntryLink(name string, kind byte, linkname string) []byte {
	h := dockerAppsTarHeader(name, 0, kind, 0o644)
	copy(h[157:], linkname)
	return h
}

func dockerAppsTUID(t *testing.T, path string) uint32 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Uid
}

func dockerAppsTOwner(uid uint32) *DockerAppsVolumeOwner {
	return &DockerAppsVolumeOwner{UID: uid, GID: &uid}
}

// The repair must touch root-owned paths and nothing else. SPLIT IN TWO: the
// unprivileged half defends the cheap top-level probe; the root half defends
// the filter itself, that root-owned paths are handed over, and idempotence.
// Root is never load-bearing for a PASS.
func TestTheRepairTouchesOnlyRootOwnedPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "volume")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "mine.db"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "sub", "nested"), []byte("x"), 0o644)

	me := uint32(os.Getuid())
	if me != 0 {
		gid := uint32(os.Getgid())
		n, err := dockerAppsChownRootOwnedEntries(root, &DockerAppsVolumeOwner{UID: me, GID: &gid})
		if err != nil || n != 0 {
			t.Fatalf("a tree with no root-owned path must be left completely alone: %d %v", n, err)
		}
		t.Logf("note: the positive half needs root; skipped for uid %d", me)
		return
	}

	// As root, the target must be an UNPRIVILEGED uid.
	owner := dockerAppsTOwner(4242)
	third := filepath.Join(root, "third-party")
	_ = os.WriteFile(third, []byte("x"), 0o644)
	if err := dockerAppsLchownTo(third, dockerAppsTOwner(12345)); err != nil {
		t.Fatal(err)
	}
	claimed, err := dockerAppsChownRootOwnedEntries(root, owner)
	if err != nil || claimed != 4 {
		t.Fatalf("expected the volume, two files and the subdirectory: %d %v", claimed, err)
	}
	if dockerAppsTUID(t, third) != 12345 {
		t.Fatal("a path owned by a third uid was rewritten")
	}
	if dockerAppsTUID(t, filepath.Join(root, "mine.db")) != 4242 {
		t.Fatal("a root-owned file was not handed to the app")
	}
	if after, _ := dockerAppsChownRootOwnedEntries(root, owner); after != 0 {
		t.Fatalf("a second pass has nothing left to reclaim, got %d", after)
	}
}

// The TOCTOU-closing mechanism: a directory-shaped entry that has become a
// symlink by the moment the walk goes to OPEN it must be refused, not followed.
func TestOpenatNofollowRefusesASymlinkEvenThoughItIsOpenedAsADirectory(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	_ = os.MkdirAll(realDir, 0o755)
	if err := os.Symlink(realDir, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	baseFD, err := dockerAppsOpenatNofollow(unix.AT_FDCWD, base, unix.O_DIRECTORY)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(baseFD)
	fd, err := dockerAppsOpenatNofollow(baseFD, "link", unix.O_DIRECTORY)
	if err == nil {
		unix.Close(fd)
		t.Fatal("O_NOFOLLOW must refuse to open a symlink, not follow it into a directory")
	}
	// ELOOP for a bare O_NOFOLLOW refusal, ENOTDIR when combined with
	// O_DIRECTORY — either is a REFUSAL.
	if !errors.Is(err, unix.ELOOP) && !errors.Is(err, unix.ENOTDIR) {
		t.Fatalf("expected ELOOP or ENOTDIR, got %v", err)
	}
}

func TestTheRepairNeverFollowsASymlinkStandingWhereADirectoryWasListed(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to chown")
	}
	base := t.TempDir()
	root, outside := filepath.Join(base, "volume"), filepath.Join(base, "outside")
	_ = os.MkdirAll(root, 0o755)
	_ = os.MkdirAll(outside, 0o755)
	sentinel := filepath.Join(outside, "shadow")
	_ = os.WriteFile(sentinel, []byte("root-only\n"), 0o644)
	_ = os.Symlink(outside, filepath.Join(root, "escape"))

	if _, err := dockerAppsChownRootOwnedEntries(root, dockerAppsTOwner(4242)); err != nil {
		t.Fatal(err)
	}
	if dockerAppsTUID(t, sentinel) != 0 {
		t.Fatal("the walk followed a symlink out of the volume and chowned a host file")
	}
	// The link itself, being root-owned, IS chowned as a link.
	if dockerAppsTUID(t, filepath.Join(root, "escape")) != 4242 {
		t.Fatal("the symlink entry itself should be chowned as a link")
	}
}

func TestTheRepairSkipsARootOwnedEntryThatHasMoreThanOneLink(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to chown")
	}
	base := t.TempDir()
	root, outside := filepath.Join(base, "volume"), filepath.Join(base, "outside")
	_ = os.MkdirAll(root, 0o755)
	_ = os.MkdirAll(outside, 0o755)
	real := filepath.Join(outside, "passwd")
	_ = os.WriteFile(real, []byte("root:x:0:0::/root:/bin/bash\n"), 0o644)
	if err := os.Link(real, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	// Positive control: an ordinary root-owned file, nlink 1.
	_ = os.WriteFile(filepath.Join(root, "ordinary"), []byte("x"), 0o644)

	if _, err := dockerAppsChownRootOwnedEntries(root, dockerAppsTOwner(4242)); err != nil {
		t.Fatal(err)
	}
	if dockerAppsTUID(t, real) != 0 {
		t.Fatal("a hardlinked entry was chowned, repainting the file's other name outside the volume")
	}
	if dockerAppsTUID(t, filepath.Join(root, "ordinary")) != 4242 {
		t.Fatal("the nlink guard must not suppress an ordinary, non-hardlinked entry")
	}
}

// The migration's chown must reach every file it just wrote, and must not
// walk out of the directory through a symlink. Chowns to the CURRENT uid/gid
// so it runs identically as root and as a non-root CI runner.
func TestTheMigratedChownReachesEveryFileAndNeverFollowsASymlink(t *testing.T) {
	base := t.TempDir()
	root, outside := filepath.Join(base, "volume"), filepath.Join(base, "outside")
	_ = os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	_ = os.MkdirAll(outside, 0o755)
	_ = os.WriteFile(filepath.Join(root, "database.sqlite"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "sub", "nested"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(outside, "untouched"), []byte("x"), 0o644)
	_ = os.Symlink(outside, filepath.Join(root, "link"))

	gid := uint32(os.Getgid())
	touched, err := dockerAppsChownMigratedTree(root, &DockerAppsVolumeOwner{UID: uint32(os.Getuid()), GID: &gid})
	if err != nil {
		t.Fatal(err)
	}
	// The volume, its two files, its subdirectory, and the symlink AS a link.
	if touched != 5 {
		t.Fatalf("expected 5, got %d", touched)
	}
	if _, err := os.Stat(filepath.Join(outside, "untouched")); err != nil {
		t.Fatal("the symlink target must be left alone")
	}
}

func TestSeedingUnpacksTheImageContentWithoutItsLeadingComponent(t *testing.T) {
	dir := t.TempDir()
	// Exactly the shape Docker's copy API returns for /etc/caddy.
	archive := dockerAppsTarEntry("caddy/", nil, '5')
	archive = append(archive, dockerAppsTarEntry("caddy/Caddyfile", []byte(":80\nrespond \"hi\"\n"), '0')...)
	archive = append(archive, dockerAppsTarEntry("caddy/conf.d/extra.conf", []byte("# extra\n"), '0')...)
	archive = append(archive, dockerAppsTarEntryMode("caddy/run.sh", []byte("#!/bin/sh\n"), '0', 0o755)...)

	written, err := dockerAppsTarExtractInto(archive, dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "Caddyfile")); string(b) != ":80\nrespond \"hi\"\n" {
		t.Fatal("the archive's leading component must be stripped")
	}
	if _, err := os.Stat(filepath.Join(dir, "conf.d/extra.conf")); err != nil {
		t.Fatal("nested entries land too")
	}
	// Asserts the executable BIT rather than a full mode (§4 of
	// app-volume-ownership-pin-e2e.sh greps raw source for the world-writable
	// mode and does not exempt test data).
	if fi, _ := os.Stat(filepath.Join(dir, "run.sh")); fi == nil || fi.Mode().Perm()&0o111 == 0 {
		t.Fatal("the archive's executable bit was dropped")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "Caddyfile")); fi.Mode().Perm()&0o111 != 0 {
		t.Fatal("a non-executable entry was made executable")
	}
	// Three, not four: the archive's own root entry strips to nothing.
	if len(written) != 3 {
		t.Fatalf("wrote %v", written)
	}
}

// The archive is built by a THIRD PARTY's image, so this is a security
// property and not a tidiness one.
func TestSeedingRefusesAnArchiveThatTriesToEscapeItsDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dest")
	_ = os.MkdirAll(dir, 0o755)
	archive := dockerAppsTarEntry("x/../escaped.txt", []byte("owned\n"), '0')
	archive = append(archive, dockerAppsTarEntry("x/../../escaped-twice.txt", []byte("owned\n"), '0')...)
	archive = append(archive, dockerAppsTarEntry("x/link", nil, '2')...)
	archive = append(archive, dockerAppsTarEntry("x/hard", nil, '1')...)
	// The positive control.
	archive = append(archive, dockerAppsTarEntry("x/legitimate.conf", []byte("fine\n"), '0')...)

	written, err := dockerAppsTarExtractInto(archive, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(written, []string{filepath.Join(dir, "legitimate.conf")}) {
		t.Fatalf("only the safe member may be written: %v", written)
	}
	for _, p := range []string{filepath.Join(dir, "escaped.txt"), filepath.Join(filepath.Dir(dir), "escaped-twice.txt"),
		filepath.Join(dir, "link"), filepath.Join(dir, "hard"), filepath.Join(filepath.Dir(dir), "escaped.txt")} {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("%s was materialised", p)
		}
	}
}

// POSIX ustar splits a path over 100 bytes across `name` and a `prefix`.
func TestSeedingJoinsTheUstarPrefixFieldForALongPath(t *testing.T) {
	dir := t.TempDir()
	deep := strings.Repeat("d", 90)
	prefix := "very/deep/" + deep
	header := make([]byte, 512)
	copy(header, "leaf.conf")
	copy(header[124:], fmt.Sprintf("%011o\x00", 3))
	header[156] = '0'
	copy(header[345:], prefix)
	archive := append(header, "hi\n"...)
	archive = append(archive, make([]byte, 1024-len(archive))...)

	written, err := dockerAppsTarExtractInto(archive, dir)
	if err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(dir, "deep", deep, "leaf.conf")
	if !slices.Equal(written, []string{expected}) {
		t.Fatalf("the prefix-joined path was dropped or misplaced (wrote %v)", written)
	}
	if b, _ := os.ReadFile(expected); string(b) != "hi\n" {
		t.Fatal()
	}
}

// A hardlink's linkname must resolve only against a path THIS archive already
// wrote — never the host filesystem.
func TestSeedingHardLinksResolveOnlyAgainstThisArchivesOwnEntries(t *testing.T) {
	dir := t.TempDir()
	archive := dockerAppsTarEntry("bin/real", []byte("#!/bin/sh\n"), '0')
	archive = append(archive, dockerAppsTarEntryLink("bin/alias", '1', "bin/real")...)
	archive = append(archive, dockerAppsTarEntryLink("bin/dangling", '1', "/etc/shadow")...)

	written, err := dockerAppsTarExtractInto(archive, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(written, []string{filepath.Join(dir, "real"), filepath.Join(dir, "alias")}) {
		t.Fatalf("wrote %v", written)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "alias")); string(b) != "#!/bin/sh\n" {
		t.Fatal()
	}
	a, _ := os.Stat(filepath.Join(dir, "real"))
	b, _ := os.Stat(filepath.Join(dir, "alias"))
	if !os.SameFile(a, b) {
		t.Fatal("alias must be a hard link to real, not a copy")
	}
	if _, err := os.Lstat(filepath.Join(dir, "dangling")); err == nil {
		t.Fatal("a linkname naming a path outside this archive must not resolve against the host")
	}
}

// The guard that keeps an operator's data safe: seeding only ever fills a
// directory that is empty. Proven on the emptiness test itself.
func TestSeedingWritesIntoADirectoryThatAlreadyHasContentOnlyByRefusing(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "operators-own.conf"), []byte("do not touch\n"), 0o644)
	if empty, ok := dockerAppsDirIsEmpty(dir); !ok || empty {
		t.Fatal("the emptiness test seeding gates on must see existing content")
	}
}

// The container is named for the app; the DATA is named for the app alone.
func TestTheDataDirectoryIsNamedForTheAppAndNotForItsContainer(t *testing.T) {
	if dockerAppsAppDataName(map[string]string{"dockpanel.app.name": "n8n"}, "dockpanel-app-n8n") != "n8n" {
		t.Fatal()
	}
	if dockerAppsAppDataName(nil, "dockpanel-app-ghost") != "ghost" || dockerAppsAppDataName(nil, "something-else") != "something-else" {
		t.Fatal()
	}
	if dockerAppsAppDataName(map[string]string{"dockpanel.app.name": ""}, "dockpanel-app-gitea") != "gitea" {
		t.Fatal("an empty label is not an answer")
	}
	if dockerAppsAppDataName(map[string]string{"dockpanel.app.name": "wiki"}, "dockpanel-app-old") != "wiki" {
		t.Fatal("the label WINS over the container name")
	}
}

func TestRemovalFollowsTheBindAndAcceptsTheDirectoryTheOldMigrationWrote(t *testing.T) {
	eq := func(got *string, want string) bool { return got != nil && *got == want }
	if !eq(dockerAppsOwnedAppDir("n8n", []string{DockerAppsAppDataDir + "/n8n/home/node/.n8n:/home/node/.n8n"}), DockerAppsAppDataDir+"/n8n") {
		t.Fatal()
	}
	legacy := []string{DockerAppsAppDataDir + "/dockpanel-app-n8n/home/node/.n8n:/home/node/.n8n"}
	if !eq(dockerAppsOwnedAppDir("n8n", legacy), DockerAppsAppDataDir+"/dockpanel-app-n8n") {
		t.Fatal()
	}
	// A compose service binds outside the app directory entirely.
	if dockerAppsOwnedAppDir("n8n", []string{"/var/lib/dockpanel/compose/n8n/data:/data"}) != nil {
		t.Fatal()
	}
	// A neighbour's directory is not this app's; a prefix that stops
	// mid-segment must not match.
	if dockerAppsOwnedAppDir("n8n", []string{DockerAppsAppDataDir + "/n8n-staging/data:/data"}) != nil ||
		dockerAppsOwnedAppDir("data", []string{DockerAppsAppDataDir + "/database/x:/x"}) != nil ||
		dockerAppsOwnedAppDir("n8n", nil) != nil {
		t.Fatal()
	}
}

// A managed container the catalogue never heard of still has data worth keeping.
func TestAManagedContainerOutsideTheCatalogueStillDeclaresItsState(t *testing.T) {
	config := &container.Config{Labels: map[string]string{
		"dockpanel.managed": "true", "dockpanel.app.template": "roundcube", "dockpanel.app.name": "roundcube",
	}}
	bare := &container.HostConfig{}
	if got := dockerAppsUnmountedDeclaredVolumes(config, bare); !slices.Equal(got, []string{"/var/roundcube/db"}) {
		t.Fatal(got)
	}
	bound := &container.HostConfig{Binds: []string{DockerAppsAppDataDir + "/roundcube/var/roundcube/db:/var/roundcube/db"}}
	if len(dockerAppsUnmountedDeclaredVolumes(config, bound)) != 0 {
		t.Fatal()
	}
	// A Mounts-spelled mount counts too.
	mounted := &container.HostConfig{Mounts: []mount.Mount{{Target: "/var/roundcube/db"}}}
	if len(dockerAppsUnmountedDeclaredVolumes(config, mounted)) != 0 {
		t.Fatal()
	}
	compose := &container.Config{Labels: map[string]string{"dockpanel.managed": "true", "dockpanel.app.template": "compose"}}
	if len(dockerAppsUnmountedDeclaredVolumes(compose, bare)) != 0 {
		t.Fatal()
	}
	unmanaged := &container.Config{Labels: map[string]string{"dockpanel.app.template": "roundcube"}}
	if len(dockerAppsUnmountedDeclaredVolumes(unmanaged, bare)) != 0 {
		t.Fatal()
	}
}

// The command comes back from the TEMPLATE, not from the departing image.
func TestARecreateReDerivesTheCatalogueCommandFromTheTemplateLabel(t *testing.T) {
	if !slices.Equal(dockerAppsCatalogueCmdFor(map[string]string{"dockpanel.app.template": "ntfy"}), []string{"serve"}) {
		t.Fatal()
	}
	if dockerAppsCatalogueCmdFor(map[string]string{"dockpanel.app.template": "ghost"}) != nil ||
		dockerAppsCatalogueCmdFor(nil) != nil ||
		dockerAppsCatalogueCmdFor(map[string]string{"dockpanel.app.template": "not-a-template"}) != nil {
		t.Fatal()
	}
}

func TestEveryCommandedTemplateIsReachableThroughItsOwnLabel(t *testing.T) {
	for _, e := range dockerAppsTemplateCmd {
		if !slices.Equal(dockerAppsCatalogueCmdFor(map[string]string{"dockpanel.app.template": e.id}), e.args) {
			t.Errorf("'%s' has a catalogue command that a recreate cannot recover", e.id)
		}
	}
}

// ⚠ The template id is deliberately one that does NOT exist: the guard runs
// before the catalogue lookup, so a mutant without it fails on "Unknown
// template" instead of deploying a real container onto whatever box ran it.
func TestAnAppMayNotBeNamedSoItShadowsAnotherAppsDataDirectory(t *testing.T) {
	_, err := DockerAppsDeployApp(context.Background(), "dockpanel-no-such-template", "dockpanel-app-n8n", 8080,
		map[string]string{}, nil, nil, nil, nil, false, nil)
	if err == nil || !strings.Contains(err.Error(), "not an available app name") {
		t.Fatalf("refusal should say why, got: %v", err)
	}
}

// ⚠ No template's own container may be given the host socket or host root;
// only the sidecar (which exists to hold it) mounts the socket, read-only.
func TestNoTemplateVolumeReachesTheDockerSocketOrHostRoot(t *testing.T) {
	for _, tpl := range dockerAppsTemplates {
		for _, v := range tpl.Volumes {
			if v == "/" || strings.Contains(v, "docker.sock") || !strings.HasPrefix(v, "/") || strings.Contains(v, "..") {
				t.Errorf("%s declares unsafe volume %q", tpl.ID, v)
			}
		}
	}
}

// ── TLS intent (ported from routes/docker_apps.rs tls_intent_tests) ──

func dockerAppsTIntent(t *testing.T, mode, email, alias *string, traefik bool) (DockerAppsTlsIntent, bool) {
	t.Helper()
	i, err := DockerAppsTlsIntentFromRequest(mode, email, alias, traefik)
	return i, err == nil
}

func TestAnOlderPanelThatSendsNoModeKeepsTheAddressRule(t *testing.T) {
	s := dockerAppsTStr
	if i, ok := dockerAppsTIntent(t, nil, s("ops@example.com"), nil, false); !ok || i != (DockerAppsTlsIntent{Kind: DockerAppsTlsAcme, Email: "ops@example.com"}) {
		t.Fatal(i)
	}
	if i, ok := dockerAppsTIntent(t, nil, nil, nil, false); !ok || i.Kind != DockerAppsTlsNone {
		t.Fatal()
	}
	if i, ok := dockerAppsTIntent(t, nil, nil, s("wild"), false); !ok || i.Kind != DockerAppsTlsNone {
		t.Fatal("an alias without a mode is ignored")
	}
}

func TestEachModeNeedsItsOwnField(t *testing.T) {
	s := dockerAppsTStr
	if i, ok := dockerAppsTIntent(t, s("none"), s("x@y.z"), nil, false); !ok || i.Kind != DockerAppsTlsNone {
		t.Fatal()
	}
	if i, ok := dockerAppsTIntent(t, s("acme"), s("x@y.z"), nil, false); !ok || i != (DockerAppsTlsIntent{Kind: DockerAppsTlsAcme, Email: "x@y.z"}) {
		t.Fatal()
	}
	if _, ok := dockerAppsTIntent(t, s("acme"), nil, nil, false); ok {
		t.Fatal()
	}
	if _, ok := dockerAppsTIntent(t, s("acme"), s("   "), nil, false); ok {
		t.Fatal()
	}
	if i, ok := dockerAppsTIntent(t, s("provided"), nil, s("wildcard-2026"), false); !ok || i != (DockerAppsTlsIntent{Kind: DockerAppsTlsProvided, Alias: "wildcard-2026"}) {
		t.Fatal()
	}
	for _, bad := range []struct{ mode, email, alias *string }{
		{s("provided"), nil, nil},
		// The alias is a directory name on this box; the grammar is enforced here too.
		{s("provided"), nil, s("../ssl")},
		{s("provided"), nil, s("Upper")},
		{s("letsencrypt"), s("x@y.z"), nil},
	} {
		if _, ok := dockerAppsTIntent(t, bad.mode, bad.email, bad.alias, false); ok {
			t.Errorf("%v should be refused", *bad.mode)
		}
	}
}

// Traefik's file provider has no per-route certificate form — refused at the
// front door, before any container exists.
func TestProvidedModeIsRefusedThroughTraefikBeforeAnyContainerExists(t *testing.T) {
	s := dockerAppsTStr
	if _, ok := dockerAppsTIntent(t, s("provided"), nil, s("wildcard-2026"), true); ok {
		t.Fatal()
	}
	if _, ok := dockerAppsTIntent(t, s("provided"), nil, s("wildcard-2026"), false); !ok {
		t.Fatal("this is a Traefik-specific refusal, not a blanket break of provided")
	}
	if i, ok := dockerAppsTIntent(t, s("none"), nil, nil, true); !ok || i.Kind != DockerAppsTlsNone {
		t.Fatal()
	}
	if i, ok := dockerAppsTIntent(t, s("acme"), s("x@y.z"), nil, true); !ok || i.Kind != DockerAppsTlsAcme {
		t.Fatal()
	}
}

func TestTheAnswerUsesTheSharedVocabulary(t *testing.T) {
	if (DockerAppsTlsIntent{}).Mode() != "none" || (DockerAppsTlsIntent{Kind: DockerAppsTlsAcme}).Mode() != "acme" ||
		(DockerAppsTlsIntent{Kind: DockerAppsTlsProvided}).Mode() != "provided" {
		t.Fatal()
	}
}

func TestImageRefsParseIntoRegistryRepositoryTag(t *testing.T) {
	for _, c := range []struct{ in, reg, repo, tag string }{
		{"redis:7-alpine", "registry-1.docker.io", "library/redis", "7-alpine"},
		{"grafana/grafana:latest", "registry-1.docker.io", "grafana/grafana", "latest"},
		{"ghcr.io/foo/bar:v1", "ghcr.io", "foo/bar", "v1"},
		{"localhost:5000/app", "localhost:5000", "app", "latest"},
		{"nginx@sha256:abc", "registry-1.docker.io", "library/nginx", "latest"},
	} {
		r := dockerAppsParseImageRef(c.in)
		if r.registry != c.reg || r.repository != c.repo || r.tag != c.tag {
			t.Errorf("%s → %+v", c.in, r)
		}
	}
}

// ── Docker-daemon tests (Rust #[ignore]) — run with DOCKER_TESTS=1 ──

func dockerAppsTDocker(t *testing.T) *client.Client {
	t.Helper()
	if os.Getenv("DOCKER_TESTS") == "" {
		t.Skip("requires a Docker daemon; run with DOCKER_TESTS=1")
	}
	d, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestVolumeOwnerResolvesRealImagesBothWays(t *testing.T) {
	docker := dockerAppsTDocker(t)
	ctx := context.Background()
	for _, img := range []string{"prom/prometheus:v3", "grafana/grafana:13.1", "nginx:alpine"} {
		DockerAppsPullImage(ctx, docker, img, nil)
	}
	// A NAME, resolvable only from inside the image.
	p := DockerAppsResolveVolumeOwner(ctx, docker, "prom/prometheus:v3")
	if p == nil || p.UID != 65534 || p.GID == nil || *p.GID != 65534 || p.Spec != "nobody" {
		t.Fatalf("%+v", p)
	}
	// A bare numeric uid, whose primary group still comes from the image.
	if g := DockerAppsResolveVolumeOwner(ctx, docker, "grafana/grafana:13.1"); g == nil || g.UID != 472 {
		t.Fatalf("%+v", g)
	}
	// The control: a root image must resolve to nil so nothing is chowned.
	if DockerAppsResolveVolumeOwner(ctx, docker, "nginx:alpine") != nil {
		t.Fatal()
	}
}

// dockerAppsTRunProbe runs a curlimages/curl container on netName, waits for
// it to exit, and returns its log output — proving the sidecar ACL from the
// same vantage point a real Dozzle container has.
func dockerAppsTRunProbe(t *testing.T, docker *client.Client, netName, name string, args ...string) string {
	ctx := context.Background()
	_, _ = docker.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	DockerAppsPullImage(ctx, docker, "curlimages/curl:latest", nil)
	created, err := docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:             name,
		Config:           &container.Config{Image: "curlimages/curl:latest", Cmd: args},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{netName: {}}},
	})
	if err != nil {
		t.Fatalf("create probe container: %v", err)
	}
	if _, err := docker.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("start probe container: %v", err)
	}
	w := docker.ContainerWait(ctx, created.ID, client.ContainerWaitOptions{})
	select {
	case <-w.Result:
	case <-w.Error:
	}
	logs, _ := DockerAppsGetAppLogs(ctx, created.ID, 50)
	_, _ = docker.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	return logs
}

func TestSidecarActuallyProxiesReadsAndRefusesWrites(t *testing.T) {
	docker := dockerAppsTDocker(t)
	ctx := context.Background()
	app := "sidecartest-s426"
	AppSidecarTeardown(ctx, app)

	sidecar := dockerAppsTemplateSidecarOf("dozzle")
	if sidecar == nil {
		t.Fatal("dozzle must declare a sidecar")
	}
	netName, err := AppSidecarDeploy(ctx, docker, app, sidecar)
	if err != nil || netName != AppSidecarNetworkName(app) {
		t.Fatalf("sidecar deploy must succeed: %v", err)
	}
	id, ok := AppSidecarFind(ctx, docker, app)
	if !ok {
		t.Fatal("the sidecar container must be discoverable by its deterministic name")
	}
	info, err := docker.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil || info.Container.State == nil || !info.Container.State.Running {
		t.Fatal("the sidecar must actually be running")
	}
	read := dockerAppsTRunProbe(t, docker, netName, "sidecar-probe-read",
		"-s", "-o", "/dev/null", "-w", "%{http_code}", "http://dockerproxy:2375/containers/json")
	if strings.TrimSpace(read) != "200" {
		t.Fatalf("CONTAINERS=1 must let a probe list containers through the proxy; got %q", read)
	}
	write := dockerAppsTRunProbe(t, docker, netName, "sidecar-probe-write",
		"-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", "http://dockerproxy:2375/containers/create", "-d", "{}")
	if strings.TrimSpace(write) != "403" {
		t.Fatalf("POST=0 must refuse container creation through the proxy; got %q", write)
	}
	AppSidecarTeardown(ctx, app)
	if _, ok := AppSidecarFind(ctx, docker, app); ok {
		t.Fatal("teardown must remove the sidecar container")
	}
	if _, err := docker.NetworkInspect(ctx, netName, client.NetworkInspectOptions{}); err == nil {
		t.Fatal("teardown must remove the app's private network")
	}
}

// ── The runtime census ──────────────────────────────────────────────────
//
// ⚠ Rows are spelled `id | reason` rather than as pairs ON PURPOSE — see the
// victims test above. Do not "tidy" these into tuples.

// dockerAppsCensusNeedsAServiceTheCensusCannotSupply: templates the census
// cannot judge because they need something no automated run can produce —
// and which the CATALOGUE does not already say so about. Deliberately tiny;
// dockerAppsCensusNeedsOperatorInput derives the large, moving subset.
var dockerAppsCensusNeedsAServiceTheCensusCannotSupply = []string{
	"vllm | an NVIDIA GPU. It exits with `Failed to infer device type` on a CPU-only host, which is what a CI runner " +
		"is. The catalogue already marks it GPU-recommended, so this is the census lacking hardware rather than the " +
		"template being wrong",
}

// dockerAppsCensusNeedsOperatorInput: a required field with no default is
// exactly how the catalogue says "the operator must type this". The census can
// only invent a plausible value, so a failure says nothing about the template.
func dockerAppsCensusNeedsOperatorInput(tpl *dockerAppsTemplateDef) bool {
	return slices.ContainsFunc(tpl.EnvVars, func(e dockerAppsEnvVarDef) bool { return e.Required && e.Default == "" })
}

// dockerAppsCensusKnownBroken: templates that genuinely do NOT work, are not
// fixed, and are recorded here rather than left to turn the census
// permanently red. This list is DEBT, not an exemption — each row says what is
// actually wrong and what it would take. The census still reports when one of
// these starts working.
var dockerAppsCensusKnownBroken = []string{
	"vector | its image ships NOTHING at /etc/vector, so there is nothing to seed, and bare `vector` exits 78 with " +
		"`Config file not found in path`. Needs a starter vector.yaml this panel would author and then own forever, or withdrawal",
	"garage | reads /etc/garage.toml, which is not even under the /etc/garage directory the template mounts, and the " +
		"image ships no config anywhere. Same choice as vector: author a starter garage.toml, or withdraw",
	"erpnext | gunicorn listens on 8000 while the catalogue publishes 8080, so nothing answers — and correcting the " +
		"port alone would only expose the second failure, which is that a frappe bench needs MariaDB, Redis and a site " +
		"that only `bench new-site` creates",
	"authelia | prints its help and exits 0, the same shape as the templates the command table fixes. §6 of " +
		"app-template-images-pin-e2e.sh explains why a command is the wrong instrument here: with one it would sit " +
		"retrying an absent database for ever, which is a SILENT failure replacing a loud one",
	"flowise | an UPSTREAM defect on the tag pinned, not a catalogue mistake: it initialises fully, then dies in " +
		"connect-sqlite3 with `this.db.exec is not a function`. Precisely the decay this census exists to notice — " +
		"nothing in this repository changed",
	"wazuh | the manager is one container of a three-container stack. Its own filebeat dials " +
		"https://wazuh.indexer:9200, a compose service name that resolves to nothing in a single-container deploy — the " +
		"same shape as plausible, and the template asks for no indexer",
}

// dockerAppsCensusAnonymousVolumeDebt: templates known to leave state in an
// ANONYMOUS volume, and what is in it. Every recreate door builds the
// replacement from the original's HostConfig, which knows nothing about
// anonymous volumes, so the replacement gets a brand-new empty one (#110
// arriving through the image). A REPAIR QUEUE, not an exemption; the census
// reports BOTH directions so a stale row cannot sit here.
var dockerAppsCensusAnonymousVolumeDebt = []string{
	"azuracast | the image declares nine paths beneath /var/azuracast plus the MySQL it bundles, while the catalogue " +
		"binds only the parent directory. Station media, listener uploads and the whole database are at stake, and " +
		"whether the parent bind covers the children is exactly what this run answers",
	"localai | models, data, configuration and backends are all declared by the image and none is bound. A downloaded " +
		"model set runs to tens of gigabytes and is fetched again after every recreate",
	"huginn | the image bundles its own MySQL and the catalogue binds nothing at all, so the entire database is " +
		"anonymous and every recreate starts an empty one",
	"gitness | every repository lives under /git, which the image declares and the catalogue does not bind. Only the " +
		"/data path is bound",
	"immich | the image declares /data while the catalogue binds the upload directory alone",
	"mattermost | operator-installed plugins live in the two plugin directories, both declared by the image and " +
		"neither bound",
	"paperless-ngx | the consume drop folder and the export directory are declared by the image and unbound, so a " +
		"document waiting to be ingested does not survive",
	"plausible | the image declares /var/lib/plausible and the catalogue does not bind it",
	"wikijs | page content is declared by the image at a path the catalogue does not bind",
	"filebrowser | the image declares /config, which the catalogue does not bind, so the server's own configuration resets",
	"influxdb | the image declares its configuration directory and the catalogue binds only the data",
	"mongo | the config-server metadata directory is declared by the image; the data directory beside it is bound",
	"buildkite-agent | the image declares /buildkite and the catalogue binds nothing there",
	"sonarqube | scratch space only. The image declares a temp directory, and losing it on a recreate costs nothing — " +
		"recorded so the row is not mistaken for an omission",
	"searxng | a cache directory only, rebuilt on demand. Recorded for the same reason as the row above",
	"erpnext | the bench log directory only. This template cannot start at all for the reason recorded above, so the " +
		"row is about completeness rather than data",
	"surrealdb | a log directory only",
}

func dockerAppsCensusFreePort(t *testing.T) uint16 {
	p, err := DockerAppsFindFreePort()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// dockerAppsCensusSyntheticValue: a value for a required field the catalogue
// gives no default for — leaving it empty would test a deploy the panel does
// not permit.
func dockerAppsCensusSyntheticValue(name string, port uint16) string {
	upper := strings.ToUpper(name)
	has := func(n string) bool { return strings.Contains(upper, n) }
	switch {
	case has("PASSWORD") || has("SECRET") || has("TOKEN") || has("KEY"):
		return "Census0000000000000000000000000000000000000000000000000000000000"
	case has("EMAIL"):
		return "admin@example.com"
	case has("URL") || has("HOST") || has("DOMAIN"):
		return fmt.Sprintf("http://localhost:%d", port)
	case has("PORT"):
		return strconv.Itoa(int(port))
	}
	return "dockpanel-census"
}

func dockerAppsCensusTail(logs string) string {
	lines := strings.Split(logs, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			r := []rune(lines[i])
			return string(r[:min(len(r), 200)])
		}
	}
	return "(no output)"
}

// dockerAppsCensusListens: is anything actually LISTENING on the port, inside
// the container? Deliberately NOT a connect to the published host port:
// docker-proxy completes the TCP handshake with nothing behind it, so a
// connect succeeds against a container running `sleep` (#144).
func dockerAppsCensusListens(pid int, containerPort string) bool {
	portStr, _, _ := strings.Cut(containerPort, "/")
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return false
	}
	needle := fmt.Sprintf(":%04X", port)
	for _, family := range []string{"tcp", "tcp6"} {
		text, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, family))
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(text), "\n") {
			cols := strings.Fields(line)
			// cols[1] is local_address HEXIP:HEXPORT; cols[3] is the state, 0A is LISTEN.
			if i > 0 && len(cols) > 3 && strings.HasSuffix(cols[1], needle) && cols[3] == "0A" {
				return true
			}
		}
	}
	return false
}

// A UDP template has no TCP socket to find, so it is judged on staying up.
func dockerAppsCensusWaitUntilListening(ctx context.Context, docker *client.Client, id, containerPort string) bool {
	if strings.HasSuffix(containerPort, "/udp") {
		return true
	}
	// The budget starts HERE, after the container exists.
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		res, err := docker.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if err != nil {
			return false
		}
		st := res.Container.State
		status := ""
		if st != nil {
			status = string(st.Status)
			if st.Pid != 0 && dockerAppsCensusListens(st.Pid, containerPort) {
				return true
			}
		}
		// A container that has already exited will never start listening.
		if status != "running" && status != "created" && status != "restarting" {
			return false
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func dockerAppsCensusRows(t *testing.T, rows []string) map[string]string {
	out := map[string]string{}
	for _, row := range rows {
		id, why, ok := strings.Cut(row, "|")
		if !ok {
			t.Fatalf("each row is `id | reason`: %q", row)
		}
		out[strings.TrimSpace(id)] = strings.TrimSpace(why)
	}
	return out
}

// THE RUNTIME CENSUS — whether pressing Deploy produces something that works,
// which no source check can answer. It deploys through DockerAppsDeployApp ON
// PURPOSE rather than assembling an equivalent config: a census that builds
// its own approximation measures the approximation.
//
// ⚠ IT CREATES REAL CONTAINERS AND WRITES UNDER DockerAppsAppDataDir. Gated
// behind an explicit variable:
//
//	TEMPLATE_CENSUS=1 go test ./internal/agent/services -run TemplateCensus -v -timeout 0
//
// TEMPLATE_CENSUS_SHARD=2/4 takes one quarter of the catalogue;
// TEMPLATE_CENSUS_PRUNE=1 deletes each image after measuring it;
// TEMPLATE_CENSUS_ONLY=caddy,ghost narrows to named templates.
func TestTemplateCensusEveryOneClickTemplateStillServes(t *testing.T) {
	if os.Getenv("TEMPLATE_CENSUS") == "" {
		t.Skipf("The runtime census deploys real containers and writes under %s; run with TEMPLATE_CENSUS=1", DockerAppsAppDataDir)
	}
	prune := os.Getenv("TEMPLATE_CENSUS_PRUNE") != ""
	shard, shards := 1, 1
	if s := os.Getenv("TEMPLATE_CENSUS_SHARD"); s != "" {
		a, b, ok := strings.Cut(s, "/")
		var e1, e2 error
		shard, e1 = strconv.Atoi(strings.TrimSpace(a))
		shards, e2 = strconv.Atoi(strings.TrimSpace(b))
		if !ok || e1 != nil || e2 != nil {
			t.Fatal("TEMPLATE_CENSUS_SHARD is N/M")
		}
	}
	if shards < 1 || shard < 1 || shard > shards {
		t.Fatalf("TEMPLATE_CENSUS_SHARD must be N/M with 1 <= N <= M, got %d/%d", shard, shards)
	}

	excused := dockerAppsCensusRows(t, dockerAppsCensusNeedsAServiceTheCensusCannotSupply)
	knownBroken := dockerAppsCensusRows(t, dockerAppsCensusKnownBroken)
	anonDebt := dockerAppsCensusRows(t, dockerAppsCensusAnonymousVolumeDebt)
	for _, m := range []map[string]string{excused, knownBroken, anonDebt} {
		for id := range m {
			if dockerAppsTemplateByID(id) == nil {
				t.Fatalf("the census names '%s', which is not in the catalogue", id)
			}
		}
	}
	// A template cannot be both unjudgeable and judged-broken.
	for id := range knownBroken {
		if _, ok := excused[id]; ok {
			t.Fatalf("'%s' is on BOTH census lists; they mean different things", id)
		}
		if dockerAppsCensusNeedsOperatorInput(dockerAppsTemplateByID(id)) {
			t.Fatalf("'%s' is listed as known-broken, but it has a required field with no default — record it outside this list", id)
		}
	}

	var only []string
	if s, ok := os.LookupEnv("TEMPLATE_CENSUS_ONLY"); ok {
		for _, v := range strings.Split(s, ",") {
			v = strings.TrimSpace(v)
			if dockerAppsTemplateByID(v) == nil {
				t.Fatalf("TEMPLATE_CENSUS_ONLY names '%s', which is not in the catalogue", v)
			}
			only = append(only, v)
		}
	}
	var subjects []*dockerAppsTemplateDef
	for i := range dockerAppsTemplates {
		tpl := &dockerAppsTemplates[i]
		if (only != nil && slices.Contains(only, tpl.ID)) || (only == nil && i%shards == shard-1) {
			subjects = append(subjects, tpl)
		}
	}
	if len(subjects) == 0 {
		t.Fatalf("shard %d/%d selected no templates out of %d", shard, shards, len(dockerAppsTemplates))
	}
	t.Logf("census shard %d/%d: %d of %d templates", shard, shards, len(subjects), len(dockerAppsTemplates))

	ctx := context.Background()
	docker, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	defer docker.Close()
	var broken, unexpectedlyFine, anonUnlisted, anonStale []string

	for _, tpl := range subjects {
		name := "census-" + tpl.ID
		port := dockerAppsCensusFreePort(t)
		env := map[string]string{}
		for _, ev := range tpl.EnvVars {
			if ev.Required && ev.Default == "" {
				env[ev.Name] = dockerAppsCensusSyntheticValue(ev.Name, port)
			}
		}
		// Leave nothing behind from an interrupted earlier run.
		_ = DockerAppsRemoveApp(ctx, DockerAppsContainerNamePrefix+name)
		dataDir := DockerAppsAppDataDir + "/" + name
		_ = os.RemoveAll(dataDir)

		var anonymous []string
		deployedOK := false
		var outcome error
		if dep, err := DockerAppsDeployApp(ctx, tpl.ID, name, port, env, nil, nil, nil, nil, false, nil); err != nil {
			outcome = fmt.Errorf("deploy refused: %v", err)
		} else {
			deployedOK = true
			served := dockerAppsCensusWaitUntilListening(ctx, docker, dep.ContainerID, tpl.ContainerPort)
			status := "unknown"
			if res, err := docker.ContainerInspect(ctx, dep.ContainerID, client.ContainerInspectOptions{}); err == nil {
				// Every mount Docker gave the container that is NOT one of our binds.
				for _, m := range res.Container.Mounts {
					if m.Type != mount.TypeBind {
						typ := strings.ToLower(string(m.Type))
						if typ == "" {
							typ = "unknown"
						}
						anonymous = append(anonymous, fmt.Sprintf("%s (%s)", m.Destination, typ))
					}
				}
				if res.Container.State != nil {
					status = string(res.Container.State.Status)
				}
			}
			logs, _ := DockerAppsGetAppLogs(ctx, dep.ContainerID, 12)
			_ = DockerAppsRemoveApp(ctx, dep.ContainerID)
			switch {
			case status != "running":
				outcome = fmt.Errorf("container is %s; last log: %s", status, dockerAppsCensusTail(logs))
			case !served:
				outcome = fmt.Errorf("running but nothing answers on %s; last log: %s", tpl.ContainerPort, dockerAppsCensusTail(logs))
			}
		}
		_ = os.RemoveAll(dataDir)
		if prune {
			_, _ = docker.ImageRemove(ctx, tpl.Image, client.ImageRemoveOptions{})
		}

		// Judged for EVERY template that produced a container, ahead of the
		// operator-input skip: whether data survives an update is answerable
		// even for a template the census cannot configure.
		if deployedOK {
			why, listed := anonDebt[tpl.ID]
			switch {
			case len(anonymous) > 0 && listed:
				t.Logf("  anonvol %s (%s) — recorded: %s", tpl.ID, strings.Join(anonymous, ", "), why)
			case len(anonymous) > 0:
				t.Logf("  ANONVOL %s — %s", tpl.ID, strings.Join(anonymous, ", "))
				anonUnlisted = append(anonUnlisted, tpl.ID+" — "+strings.Join(anonymous, ", "))
			case listed:
				t.Logf("  ANONFIXED %s (recorded: %s)", tpl.ID, why)
				anonStale = append(anonStale, tpl.ID+" — recorded: "+why)
			}
		}

		if dockerAppsCensusNeedsOperatorInput(tpl) {
			if outcome == nil {
				t.Logf("  unjudged %s (serves anyway on a synthetic value)", tpl.ID)
			} else {
				t.Logf("  unjudged %s (needs operator input; %v)", tpl.ID, outcome)
			}
			continue
		}

		why, listed := excused[tpl.ID]
		if !listed {
			why, listed = knownBroken[tpl.ID]
		}
		switch {
		case outcome == nil && !listed:
			t.Logf("  ok      %s", tpl.ID)
		case outcome == nil:
			t.Logf("  SERVES  %s (listed as: %s)", tpl.ID, why)
			unexpectedlyFine = append(unexpectedlyFine, tpl.ID+" — listed as: "+why)
		case listed:
			t.Logf("  listed  %s (%v)", tpl.ID, outcome)
		default:
			t.Logf("  BROKEN  %s — %v", tpl.ID, outcome)
			broken = append(broken, fmt.Sprintf("%s — %v", tpl.ID, outcome))
		}
	}

	if len(broken) > 0 {
		t.Errorf("%d template(s) in this shard cannot start and serve as the catalogue declares them:\n  %s", len(broken), strings.Join(broken, "\n  "))
	}
	if len(unexpectedlyFine) > 0 {
		t.Errorf("%d template(s) are listed as unjudgeable or known-broken but now serve. Good news, and the list is stale — delete the rows:\n  %s",
			len(unexpectedlyFine), strings.Join(unexpectedlyFine, "\n  "))
	}
	if len(anonUnlisted) > 0 {
		t.Errorf("%d template(s) put data in an anonymous volume that no recreate carries across, and are not recorded as doing so. "+
			"Declare the path in the template, or record it with what is actually lost:\n  %s", len(anonUnlisted), strings.Join(anonUnlisted, "\n  "))
	}
	if len(anonStale) > 0 {
		t.Errorf("%d template(s) are recorded as leaving data in an anonymous volume and no longer do. Delete the row:\n  %s",
			len(anonStale), strings.Join(anonStale, "\n  "))
	}
}
