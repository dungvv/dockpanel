package services

// A delete must prove it owns what it deletes.
//
// v2.52.0 fixed the *write* side (a vhost writer that, when the whole-server
// `nginx -t` failed, deleted an innocent site's config). The read side is the
// same shape one step later: a removal that names its target by a key it
// never checked belongs to the thing being removed. Two ways the key lies:
//
//   - It is derived from an identity nobody re-verified (an app's domain label
//     names a vhost that, on pre-v2.52.0 boxes, may belong to a site).
//   - It is not injective: `domain.replace('.', "-")` maps a.b.com and a-b.com
//     onto one name, and both are separately claimable.
//
// The remedy needs no rename or migration: every resource already records its
// own owner because the panel wrote it there (a unit's WorkingDirectory, a
// jail's logpath, a Traefik Host() rule, a vhost's proxy_pass port). So do not
// trust the filename — open the file and ask.
//
// OwnershipUnknown deliberately does NOT permit a delete: a stale config is an
// untidy box, a deleted live one is an unattributable outage.
//
// Containers: a preview of config C on branch B used to be named exactly like
// a deploy named "{C}-pr-{slug(B)}", so a pushed branch could adopt and
// destroy a stranger's production container. Previews are now scoped "pr."
// (`.` is rejected by is_valid_name), and OwnershipGitContainer reads the
// labels the agent wrote at creation.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// OwnershipOwner is who a resource on disk says it belongs to.
type OwnershipOwner int

const (
	// OwnershipOurs: the file names this domain; deleting it is correct.
	OwnershipOurs OwnershipOwner = iota
	// OwnershipTheirs: the file names something else.
	OwnershipTheirs
	// OwnershipUnknown: unreadable or no marker — treated as Theirs.
	OwnershipUnknown
)

// MayDelete is the only question a caller should ask. Unknown is not a maybe.
func (o OwnershipOwner) MayDelete() bool { return o == OwnershipOurs }

func (o OwnershipOwner) String() string {
	return [...]string{"Ours", "Theirs", "Unknown"}[o]
}

// OwnershipGitKindLabel says which of the two disjoint git name spaces a
// container was created in.
const OwnershipGitKindLabel = "dockpanel.git.kind"

// OwnershipBlueSuffix is the blue-green stand-in suffix. It was "-blue", which
// is_valid_name accepts — so `dockpanel-app-api-blue` was both the stand-in for
// `api` and the production container of `api-blue`, and was force-removed on
// every update of `api`. `.` is rejected by is_valid_name.
const OwnershipBlueSuffix = ".blue"

// OwnershipBlueName composes the blue-green stand-in name.
func OwnershipBlueName(containerName string) string { return containerName + OwnershipBlueSuffix }

// OwnershipGitScope is which name space a git request addresses. It selects
// the container name, image repo, checkout dir AND ownership rule together.
type OwnershipGitScope int

const (
	// OwnershipGitScopeDeploy: a configured deployment (unique name per server).
	OwnershipGitScopeDeploy OwnershipGitScope = iota
	// OwnershipGitScopePreview: a branch preview, scoped "pr.".
	OwnershipGitScopePreview
	// OwnershipGitScopePreviewLegacy: a pre-separation preview under its old
	// unscoped name. Cleanup only — nothing may be created here.
	OwnershipGitScopePreviewLegacy
)

// OwnershipGitScopeFromWire parses the wire value; unknown values are Deploy
// so an older panel keeps working unchanged.
func OwnershipGitScopeFromWire(s string) OwnershipGitScope {
	switch s {
	case "preview":
		return OwnershipGitScopePreview
	case "preview_legacy":
		return OwnershipGitScopePreviewLegacy
	}
	return OwnershipGitScopeDeploy
}

// Label is the OwnershipGitKindLabel value written in this space.
func (s OwnershipGitScope) Label() string {
	if s == OwnershipGitScopeDeploy {
		return "deploy"
	}
	return "preview"
}

// Scoped turns the panel's name into the name this space uses. `.` is
// deliberate: is_valid_name rejects it, so no deploy name can spell a preview.
func (s OwnershipGitScope) Scoped(name string) string {
	if s == OwnershipGitScopePreview {
		return "pr." + name
	}
	return name
}

// OwnershipGitContainer decides whether the container carrying labels is one
// a request in scope may act on. expectedPort is what the caller's record says
// it publishes, actualPort what it publishes (Docker never binds one host port
// twice). Unlabelled containers predate the scopes and are read per space:
// Deploy → Ours (an older agent's own; refusing would break every update);
// Preview → Unknown (the space is new); PreviewLegacy → only a matching port
// proves it — every pre-fix container is unlabelled, including the victim's.
func OwnershipGitContainer(labels map[string]string, scope OwnershipGitScope, expectedPort, actualPort *uint16) OwnershipOwner {
	if kind, ok := labels[OwnershipGitKindLabel]; ok {
		if kind == scope.Label() {
			return OwnershipOurs
		}
		return OwnershipTheirs
	}
	switch scope {
	case OwnershipGitScopeDeploy:
		return OwnershipOurs
	case OwnershipGitScopePreview:
		return OwnershipUnknown
	}
	if expectedPort != nil && actualPort != nil && *expectedPort == *actualPort {
		return OwnershipOurs
	}
	return OwnershipUnknown
}

// OwnershipBlueLeftover: may the container at a blue name be force-removed as
// an interrupted swap's leftover? Docker accepts a hand-typed `.`, and an
// operator's own container is not ours — Unknown unless it says it is managed.
func OwnershipBlueLeftover(labels map[string]string) OwnershipOwner {
	if labels["dockpanel.managed"] == "true" {
		return OwnershipOurs
	}
	return OwnershipUnknown
}

// ownershipByLines decides by whether any trimmed line EQUALS a marker.
// Whole-line, because `contains` would let example.com answer for
// example.community.
func ownershipByLines(path string, markers []string) OwnershipOwner {
	b, err := os.ReadFile(path)
	if err != nil {
		return OwnershipUnknown
	}
	for _, line := range nginxLines(string(b)) {
		if nginxContains(markers, strings.TrimSpace(line)) {
			return OwnershipOurs
		}
	}
	return OwnershipTheirs
}

// OwnershipSystemdUnit: does the unit at path run domain's app? ⚠ BOTH
// WorkingDirectory forms are listed: units before v2.123.0 used
// `{domain}/public`, and dropping it would strand every unit on disk at
// upgrade. Either marker alone can be edited away, hence several.
func OwnershipSystemdUnit(path, domain string) OwnershipOwner {
	return ownershipByLines(path, []string{
		"WorkingDirectory=/var/www/" + domain,
		"WorkingDirectory=/var/www/" + domain + "/public",
		"Description=DockPanel App: " + domain,
	})
}

// OwnershipFail2banJail: does the jail at path watch domain's access log?
func OwnershipFail2banJail(path, domain string) OwnershipOwner {
	return ownershipByLines(path, []string{"logpath = /var/log/nginx/" + domain + ".access.log"})
}

// OwnershipSftpUser: does allocated uid belong to domain? The marker is a
// dedicated file sftp_accounts writes last, outside the chroot the account
// can write to.
func OwnershipSftpUser(uid int32, domain string) OwnershipOwner {
	return ownershipByLines(SftpAccountsOwnerMarkerPath(uid), []string{"Domain=" + domain})
}

// OwnershipTraefikRoute: does the Traefik route file at path route domain?
func OwnershipTraefikRoute(path, domain string) OwnershipOwner {
	return ownershipByLines(path, []string{"rule: \"Host(`" + domain + "`)\""})
}

// OwnershipAppVhost: is the vhost at path the one serving the container on
// hostPort? An app's vhost carries nothing saying "an app wrote this" except
// its proxy_pass port. nil port (binding unreadable) is Unknown.
func OwnershipAppVhost(path string, hostPort *uint16) OwnershipOwner {
	if hostPort == nil {
		return OwnershipUnknown
	}
	return ownershipByLines(path, []string{fmt.Sprintf("proxy_pass http://127.0.0.1:%d;", *hostPort)})
}

// OwnershipCertDirInUseElsewhere: is /etc/dockpanel/ssl/{domain} referenced by
// another vhost? A DNS-01 wildcard lives under the zone apex and every sibling
// points at it; deleting it for one site fails the next `nginx -t` and leaves
// nginx down at the next restart for every site. Unreadable → assume shared.
func OwnershipCertDirInUseElsewhere(domain string) bool {
	needle := "/etc/dockpanel/ssl/" + domain + "/"
	own := domain + ".conf"
	dir := NginxSitesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true
	}
	for _, e := range entries {
		if e.Name() == own {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil && strings.Contains(string(b), needle) {
			return true
		}
	}
	return false
}

// OwnershipRegistryCertInUse: is registered certificate alias referenced by any
// vhost, live or parked? A parked one counts — enabling it would bring a
// vhost pointing at a missing pair back into service.
func OwnershipRegistryCertInUse(alias string) bool {
	return ownershipRegistryNeedleInUse(SslRegistryDir+"/"+alias+"/", NginxSitesDir(), NginxParkedDir())
}

// OwnershipRegistryCertReferences lists every vhost file naming alias, so a
// refusal can say WHICH. An error means a tree could not be read; the caller
// must treat it as "in use".
func OwnershipRegistryCertReferences(alias string) ([]string, error) {
	return ownershipRegistryNeedleReferences(SslRegistryDir+"/"+alias+"/", NginxSitesDir(), NginxParkedDir())
}

func ownershipRegistryNeedleInUse(needle, liveDir, parkedDir string) bool {
	refs, err := ownershipRegistryNeedleReferences(needle, liveDir, parkedDir)
	return err != nil || len(refs) > 0
}

// ownershipRegistryNeedleReferences scans both trees whole. An unreadable live
// tree is an error; a parked tree that does not exist holds nothing parked;
// any other parked failure is an error (fail closed). On RHEL live == parked
// and is scanned once.
func ownershipRegistryNeedleReferences(needle, liveDir, parkedDir string) ([]string, error) {
	var found []string
	scan := func(dir string, entries []os.DirEntry) {
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), needle) {
				found = append(found, p)
			}
		}
	}
	live, err := os.ReadDir(liveDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", liveDir, err)
	}
	scan(liveDir, live)
	if parkedDir == liveDir {
		return found, nil
	}
	parked, err := os.ReadDir(parkedDir)
	if os.IsNotExist(err) {
		return found, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", parkedDir, err)
	}
	scan(parkedDir, parked)
	sort.Strings(found)
	return found, nil
}
