package api

// Port of panel/backend/src/services/domain_claim.rs — the one place a domain
// is claimed.
//
// Before this module there were eleven paths that could cause a vhost to be
// written — sites create/rename/clone/alias, staging, migration import, git
// deploy create/update, git preview, and Docker app deploy in both nginx and
// Traefik mode — and each carried its own subset of the guards. What the drift
// cost, measured against v2.51.0:
//
//   - A Docker app's domain lives only in the `dockpanel.app.domain` container
//     label, so NO SQL guard could ever see it — creating or renaming a site
//     onto a domain an app owned passed every check, and the agent then
//     replaced the app's vhost.
//   - docker_apps::deploy checked nothing at all.
//   - git_deploys::update dropped both conflict queries its own create performs.
//   - staging::create — the tenant-reachable one — consulted only `sites`.
//   - Domain comparison was case-sensitive while the reserved check was not,
//     so `EXAMPLE.com` walked past a row holding `example.com`.
//
// So: every path calls DomainClaimEnsureClaimable, and it returns the
// normalised domain the caller must store. tests/domain-claim-pin-e2e.sh
// catches a new domain-introducing surface that does not call it.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type domainClaimHolderKind int

const (
	domainClaimHolderNew domainClaimHolderKind = iota
	domainClaimHolderSite
	domainClaimHolderGitDeploy
	domainClaimHolderStack
)

// DomainClaimHolder is a claim that already exists and must not conflict with
// itself. A rename re-claims a domain its own row may already hold; without
// this the guard would refuse to let a row keep the name it already has.
//
// There is deliberately no App variant: a Docker app cannot re-claim its own
// domain today (a redeploy under an existing name is refused by the name
// check), so an app-holder exclusion would be unreachable. Add it together
// with the app-rename it is for (GitHub #95). No mail variant either: nothing
// renames a mail domain.
type DomainClaimHolder struct {
	kind domainClaimHolderKind
	id   uuid.UUID
}

// DomainClaimHolderNew is a brand-new claim — nothing may hold this domain.
var DomainClaimHolderNew = DomainClaimHolder{}

// DomainClaimHolderSite: the `sites` row with this id may hold it.
func DomainClaimHolderSite(id uuid.UUID) DomainClaimHolder {
	return DomainClaimHolder{domainClaimHolderSite, id}
}

// DomainClaimHolderGitDeploy: the `git_deploys` row with this id may hold it.
func DomainClaimHolderGitDeploy(id uuid.UUID) DomainClaimHolder {
	return DomainClaimHolder{domainClaimHolderGitDeploy, id}
}

// DomainClaimHolderStack: the `docker_stacks` row with this id may hold it.
// Unlike a Docker app, a stack CAN re-claim its own domain: update redeploys
// in place under the same id, so without this a stack could not be edited twice.
func DomainClaimHolderStack(id uuid.UUID) DomainClaimHolder {
	return DomainClaimHolder{domainClaimHolderStack, id}
}

func (h DomainClaimHolder) exclude(k domainClaimHolderKind) *uuid.UUID {
	if h.kind != k {
		return nil
	}
	id := h.id
	return &id
}

// DomainClaimOccupant is what already holds a domain. Carried so the error
// can name it — "in use" with no owner is the sentence that made these
// collisions hard to diagnose.
type DomainClaimOccupant int

const (
	DomainClaimOccupantSite DomainClaimOccupant = iota
	DomainClaimOccupantGitDeploy
	DomainClaimOccupantDockerApp
	DomainClaimOccupantStack
	// DomainClaimOccupantMailDomain is a `mail_domains` row. Unlike every
	// variant above it holds no vhost, so it is not a nginx collision — it is
	// an AUTHORISATION collision, tolerated for an administrator. See
	// DomainClaimMayClaimMailHeld.
	DomainClaimOccupantMailDomain
)

func (o DomainClaimOccupant) String() string {
	return [...]string{"Site", "GitDeploy", "DockerApp", "Stack", "MailDomain"}[o]
}

// Message is the refusal sentence naming the occupant.
func (o DomainClaimOccupant) Message() string {
	switch o {
	case DomainClaimOccupantSite:
		return "Domain already in use by a site"
	case DomainClaimOccupantGitDeploy:
		return "Domain already in use by a git deployment"
	case DomainClaimOccupantDockerApp:
		return "Domain already in use by a Docker app. Rename or remove the app " +
			"first — deploying over it would replace its nginx configuration."
	case DomainClaimOccupantMailDomain:
		return "Domain already in use by a mail domain. Ask an administrator to " +
			"create the site and transfer it to you — claiming a name whose " +
			"mailboxes already exist would hand you those mailboxes."
	default:
		return "Domain already in use by a Compose stack. Change that stack's " +
			"domain or remove it first."
	}
}

// DomainClaimClientRole is the role that holds sites but may not introduce
// new ones (GitHub #51). A constant rather than a literal at each comparison:
// the value also lives in a database CHECK constraint and in the user editor,
// and a role string that means "deny" is the worst thing to typo — a
// misspelling does not fail, it silently grants.
const DomainClaimClientRole = "client"

// DomainClaimMayClaimNew reports whether role may make the claim holder
// describes.
//
// The restriction is on the TRANSITION, not on the resource: New is "a domain
// entering service for the first time". Every other holder re-claims a domain
// on behalf of a row the caller was already authorised for by its handler's
// ownership check.
//
// HERE rather than at each creating handler is the whole design: git_deploys,
// docker_apps and stacks all materialise a served vhost without inserting into
// `sites`, so a role check on the `INSERT INTO sites` paths alone would let a
// client blocked from creating a site deploy a git app on a new domain.
func DomainClaimMayClaimNew(role string, holder DomainClaimHolder) bool {
	return !(role == DomainClaimClientRole && holder.kind == domainClaimHolderNew)
}

// DomainClaimMayClaimMailHeld reports whether role may claim a domain an
// existing MAIL domain already holds. Only an administrator may — the one rule
// here keyed on the role ALONE, and the asymmetry is the point.
//
// Mail is scoped by matching mail_domains.domain against the domain of a site
// the caller owns (GitHub #106), which makes sites.domain an authorisation
// key — and sites.domain is WRITABLE by the account being authorised. Without
// this a non-admin could point their site at a domain whose mailboxes exist
// and be handed every mailbox on it. Not restricted to `client`: a plain user
// may create sites freely, so leaving them out would close the rename door and
// leave the create door open. An administrator pairing a site and its mail on
// one name is what the entitlement is BUILT on, so tolerating it is required.
func DomainClaimMayClaimMailHeld(role string) bool {
	return role == "admin"
}

// DomainClaimNormalise normalises a domain for storage and comparison.
// Hostnames are case-insensitive, but isValidDomain accepts uppercase and the
// (domain, server_id) unique index is a plain varchar, so `EXAMPLE.com` and
// `example.com` were two rows and two vhost files. Callers store what this
// returns.
func DomainClaimNormalise(domain string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(domain), "."))
}

// DomainClaimEnsureClaimable asserts that domain may be claimed anywhere in
// the fleet and returns the normalised form to store.
//
// Order matters: format, then reserved, then ownership — a malformed domain
// is reported as malformed rather than as available.
//
// Fleet-wide, on every leg: the Docker-app leg used to ask only the caller's
// host while the SQL legs were fleet-wide — and an app's domain is invisible
// to SQL, so that leg was the only thing that could ever catch it. An online
// member that will not answer is logged by name and skipped, not treated as a
// refusal: failing closed would let one sick box block every claim
// everywhere, and the collision it would miss needs the unreachable host and
// the claim's target to be the SAME host, whose vhost write then fails anyway.
//
// r supplies the Host header for isReservedDomainFor (Rust passed the HeaderMap).
func DomainClaimEnsureClaimable(ctx context.Context, db Querier, agents *AgentRegistry, domain string, r *http.Request, holder DomainClaimHolder, claimantRole string) (string, error) {
	domain = DomainClaimNormalise(domain)

	if !isValidDomain(domain) {
		return "", apiErr(http.StatusBadRequest, "Invalid domain")
	}
	if !DomainClaimMayClaimNew(claimantRole, holder) {
		return "", apiErr(http.StatusForbidden,
			"This account can manage the domains it holds but cannot bring a new "+
				"one into service. Ask an administrator to create it and transfer it "+
				"to you.")
	}
	if isReservedDomainFor(domain, r) {
		return "", apiErr(http.StatusForbidden, "This domain is reserved and cannot be used")
	}

	occ, err := DomainClaimFindOccupant(ctx, db, agents, domain, holder)
	if err != nil {
		return "", err
	}
	// A mail domain is the one occupant an administrator may claim over (a
	// site and its mailboxes sharing a name is what #106 is built on). It is
	// reported LAST by FindOccupant, so this tolerance can never swallow a
	// real vhost collision.
	if occ != nil && (*occ != DomainClaimOccupantMailDomain || !DomainClaimMayClaimMailHeld(claimantRole)) {
		return "", apiErr(http.StatusConflict, occ.Message())
	}
	return domain, nil
}

// DomainClaimFindOccupant reports who holds domain, if anyone. Separate from
// EnsureClaimable so a caller that must report rather than reject (the
// migration wizard's per-site loop) gets the same answer.
func DomainClaimFindOccupant(ctx context.Context, db Querier, agents *AgentRegistry, domain string, holder DomainClaimHolder) (*DomainClaimOccupant, error) {
	domain = DomainClaimNormalise(domain)
	found := func(o DomainClaimOccupant) (*DomainClaimOccupant, error) { return &o, nil }

	// Sites are checked fleet-wide, which is what create() already did —
	// stricter than the (domain, server_id) index; loosening it here would
	// silently widen what the panel accepts.
	site, err := queryScalarOpt[uuid.UUID](ctx, db,
		"SELECT id FROM sites WHERE lower(domain) = $1 AND ($2::uuid IS NULL OR id <> $2)",
		domain, holder.exclude(domainClaimHolderSite))
	if err != nil {
		return nil, internalError("domain availability", err)
	}
	if site != nil {
		return found(DomainClaimOccupantSite)
	}

	git, err := queryScalarOpt[uuid.UUID](ctx, db,
		"SELECT id FROM git_deploys WHERE lower(domain) = $1 AND ($2::uuid IS NULL OR id <> $2)",
		domain, holder.exclude(domainClaimHolderGitDeploy))
	if err != nil {
		return nil, internalError("domain availability", err)
	}
	if git != nil {
		return found(DomainClaimOccupantGitDeploy)
	}

	// Compose stacks became domain holders in v2.54.0; the leg landed with
	// the feature rather than after it.
	stack, err := queryScalarOpt[uuid.UUID](ctx, db,
		"SELECT id FROM docker_stacks WHERE lower(domain) = $1 AND ($2::uuid IS NULL OR id <> $2)",
		domain, holder.exclude(domainClaimHolderStack))
	if err != nil {
		return nil, internalError("domain availability", err)
	}
	if stack != nil {
		return found(DomainClaimOccupantStack)
	}

	// Docker apps are not rows. The agent reads `dockpanel.app.domain` off
	// each managed container and returns it from GET /apps (one
	// list_containers, quick lane).
	//
	// ⚠ This asked exactly ONE host until v2.80.0 — the caller's — so a domain
	// held by an app on host B passed a claim made on host A. An unreachable
	// member is reported and skipped (see EnsureClaimable), never silently.
	for _, member := range agents.OnlineFleet(ctx) {
		apps, err := member.Agent.Get(ctx, "/apps")
		if err != nil {
			slog.Warn(fmt.Sprintf("Domain availability: could not ask %s about Docker-app domains (%v) — '%s' is being treated as free there", member.Name, err, domain))
			continue
		}
		list, ok := jsonArr(apps)
		if !ok {
			continue
		}
		for _, app := range list {
			ad, ok := jsonStr(jsonGet(app, "domain"))
			if ok && DomainClaimNormalise(ad) == domain {
				return found(DomainClaimOccupantDockerApp)
			}
		}
	}

	// Mail domains hold a name without a vhost, so the two-owners state had no
	// nginx symptom and went unnoticed.
	//
	// ⚠ LAST on purpose, after the fleet loop: EnsureClaimable TOLERATES this
	// occupant for an administrator, which is only sound if a mail domain can
	// never be reported in place of a holder that must always refuse.
	mail, err := queryScalarOpt[uuid.UUID](ctx, db, "SELECT id FROM mail_domains WHERE lower(domain) = $1", domain)
	if err != nil {
		return nil, internalError("domain availability", err)
	}
	if mail != nil {
		return found(DomainClaimOccupantMailDomain)
	}
	return nil, nil
}
