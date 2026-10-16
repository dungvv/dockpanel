package api

// Port of panel/backend/src/services/prerequisites/mod.rs — the prerequisite
// layer, "what you need to do first".
//
// Features declare what must already be true before they can work; a shared
// checker evaluates those conditions and returns STRUCTURED results; the
// frontend renders them at one of three urgencies. One registry of checks and
// one registry of copy (svc_guidance.go), so guidance can't drift the way
// scattered `title` attributes do.
//
// The governing rule: **block only when it would actually fail, warn when it
// probably will, explain passively otherwise.** Over-blocking is its own bad UX.
//
// Why a registry rather than an inline guard: the DNS condition was already
// computed inside `POST /api/sites/{id}/ssl`, which returned a precise 412 —
// but as a prose string, at one call site, at the moment of failure. Nothing
// else could ask "is this domain pointed here yet?" before the user committed
// to an action. Promoting the check to a callable that returns data rather
// than a sentence lets the create-site form, the SSL panel and the 412 share
// one source of truth.
//
// One file per vertical: svc_prerequisites_dns.go (does this domain point
// here?), _apps.go (can this container start with these settings?), _mail.go
// (are this domain's mail records published?), _backups.go (will these
// backups survive losing this machine?). Adding a vertical is a new file plus
// a route; never an edit to an existing check. A check decides *which*
// outcome a situation is; it cannot decide what that outcome says, because
// the words are not in it — that is what lets the manual be generated.

import "encoding/json"

// PrerequisitesPrereqState is whether a prerequisite currently holds.
type PrerequisitesPrereqState string

const (
	// Verified true — the dependent action can proceed.
	PrerequisitesPrereqStateSatisfied PrerequisitesPrereqState = "satisfied"
	// Verified false — the dependent action will fail or half-succeed.
	PrerequisitesPrereqStateUnsatisfied PrerequisitesPrereqState = "unsatisfied"
	// We could not determine it. Never treated as failure: an unknown must
	// not block a user whose setup is fine but whose check we couldn't run.
	PrerequisitesPrereqStateUnknown PrerequisitesPrereqState = "unknown"
)

// PrerequisitesPrereqSeverity is how loudly to present an unmet prerequisite
// — chosen by consequence, not by how confident the check is.
type PrerequisitesPrereqSeverity string

const (
	// The action *will* fail. Gate the control and say why.
	PrerequisitesPrereqSeverityBlocking PrerequisitesPrereqSeverity = "blocking"
	// The action *probably* will, or may leave a mess. Warn, but let them proceed.
	PrerequisitesPrereqSeverityWarning PrerequisitesPrereqSeverity = "warning"
	// Context only. Passive helper text.
	PrerequisitesPrereqSeverityInfo PrerequisitesPrereqSeverity = "info"
)

// PrerequisitesDnsRecordHint is the exact DNS record a user should create,
// with values filled in — the record itself (name, type, value, TTL), never a
// description of a record.
type PrerequisitesDnsRecordHint struct {
	// The host/name field as most DNS UIs want it (`@` for an apex).
	Name string `json:"name"`
	// The same record spelled as a full domain, for the providers that want that.
	Fqdn       string `json:"fqdn"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
	TTL        string `json:"ttl"`
	// Why this record exists, in the user's terms. Optional because the DNS
	// vertical's single record needs no caption; a set of five mail records does.
	Purpose *string `json:"purpose,omitempty"`
	// Whether this particular record was found published. nil when the set
	// was produced without checking (the "here is what to create" case).
	Present *bool `json:"present,omitempty"`
}

// PrerequisitesNewDnsRecordHint is a record with no caption and no observed state.
func PrerequisitesNewDnsRecordHint(name, fqdn, recordType, value, ttl string) PrerequisitesDnsRecordHint {
	return PrerequisitesDnsRecordHint{Name: name, Fqdn: fqdn, RecordType: recordType, Value: value, TTL: ttl}
}

func (h PrerequisitesDnsRecordHint) WithPurpose(purpose string) PrerequisitesDnsRecordHint {
	h.Purpose = &purpose
	return h
}

func (h PrerequisitesDnsRecordHint) WithPresent(present bool) PrerequisitesDnsRecordHint {
	h.Present = &present
	return h
}

// Remediation kinds (serde tag `kind`, snake_case).
const (
	PrerequisitesRemediationDnsRecord  = "dns_record"
	PrerequisitesRemediationDnsRecords = "dns_records"
	PrerequisitesRemediationValue      = "value"
	PrerequisitesRemediationLink       = "link"
)

// PrerequisitesRemediation is the concrete thing that would fix an unmet
// prerequisite.
//
// Deliberately a closed set of SHAPES rather than free prose: every arm is
// something the frontend can render as an action (copy this, click this)
// rather than a sentence the user has to translate into one. Tagged by `kind`
// so the renderer dispatches on data, not on the check's key. Build one with
// the PrerequisitesNewRemediation* constructors; only the fields of its Kind are
// serialized.
type PrerequisitesRemediation struct {
	Kind string
	// dns_record: one DNS record to create. The DNS vertical's shape.
	Record PrerequisitesDnsRecordHint
	// dns_records: a set that must all exist — mail's MX/SPF/DKIM/DMARC, each
	// carrying its own `present` flag so the user sees which one is missing.
	Records []PrerequisitesDnsRecordHint
	// value: something the panel can supply on the user's behalf (the next
	// free port, a generated password). AppliesTo names the form field it
	// belongs in. Secret: never echo this into logs or activity records.
	// link: somewhere else in the product the user has to go (Label, Href).
	Label     string
	Value     string
	AppliesTo string
	Secret    bool
	Href      string
}

func PrerequisitesNewRemediationDnsRecord(record PrerequisitesDnsRecordHint) *PrerequisitesRemediation {
	return &PrerequisitesRemediation{Kind: PrerequisitesRemediationDnsRecord, Record: record}
}

func PrerequisitesNewRemediationDnsRecords(records []PrerequisitesDnsRecordHint) *PrerequisitesRemediation {
	if records == nil {
		records = []PrerequisitesDnsRecordHint{}
	}
	return &PrerequisitesRemediation{Kind: PrerequisitesRemediationDnsRecords, Records: records}
}

func PrerequisitesNewRemediationValue(label, value, appliesTo string, secret bool) *PrerequisitesRemediation {
	return &PrerequisitesRemediation{Kind: PrerequisitesRemediationValue, Label: label, Value: value, AppliesTo: appliesTo, Secret: secret}
}

func PrerequisitesNewRemediationLink(label, href string) *PrerequisitesRemediation {
	return &PrerequisitesRemediation{Kind: PrerequisitesRemediationLink, Label: label, Href: href}
}

// MarshalJSON emits serde's internally tagged shape: `kind` first, then the
// variant's own fields in declaration order.
func (r PrerequisitesRemediation) MarshalJSON() ([]byte, error) {
	switch r.Kind {
	case PrerequisitesRemediationDnsRecord:
		return json.Marshal(struct {
			Kind   string                     `json:"kind"`
			Record PrerequisitesDnsRecordHint `json:"record"`
		}{r.Kind, r.Record})
	case PrerequisitesRemediationDnsRecords:
		return json.Marshal(struct {
			Kind    string                       `json:"kind"`
			Records []PrerequisitesDnsRecordHint `json:"records"`
		}{r.Kind, r.Records})
	case PrerequisitesRemediationValue:
		return json.Marshal(struct {
			Kind      string `json:"kind"`
			Label     string `json:"label"`
			Value     string `json:"value"`
			AppliesTo string `json:"applies_to"`
			Secret    bool   `json:"secret"`
		}{r.Kind, r.Label, r.Value, r.AppliesTo, r.Secret})
	default:
		return json.Marshal(struct {
			Kind  string `json:"kind"`
			Label string `json:"label"`
			Href  string `json:"href"`
		}{PrerequisitesRemediationLink, r.Label, r.Href})
	}
}

// PrerequisitesPrereqResult is the result of evaluating one prerequisite.
// The only way to make one in the product is PrerequisitesCopyPrereq.Result —
// a check cannot invent a sentence because it has no constructor that takes one.
type PrerequisitesPrereqResult struct {
	// Stable identifier, e.g. `dns.points_here`. The frontend keys copy and
	// test selectors off it.
	Key      string                      `json:"key"`
	State    PrerequisitesPrereqState    `json:"state"`
	Severity PrerequisitesPrereqSeverity `json:"severity"`
	// One short line naming the situation.
	Title string `json:"title"`
	// The explanation, in the user's terms — what is true and what to do.
	Detail string `json:"detail"`
	// What we expected to see (the server's address, for DNS).
	Expected *string `json:"expected,omitempty"`
	// What we actually observed.
	Observed []string `json:"observed"`
	// The fix, when there is a concrete one.
	Remediation *PrerequisitesRemediation `json:"remediation,omitempty"`
}

// Blocks reports whether a control gated on this prerequisite should be
// disabled.
//
// This is the ONLY rule for gating a control. Never re-derive it — an
// `unknown` must never block, and a `warning` must never block, however
// confident the check happens to feel.
func (r PrerequisitesPrereqResult) Blocks() bool {
	return r.State == PrerequisitesPrereqStateUnsatisfied && r.Severity == PrerequisitesPrereqSeverityBlocking
}

func (r PrerequisitesPrereqResult) WithExpected(expected string) PrerequisitesPrereqResult {
	r.Expected = &expected
	return r
}

func (r PrerequisitesPrereqResult) WithObserved(observed []string) PrerequisitesPrereqResult {
	if observed == nil {
		observed = []string{}
	}
	r.Observed = observed
	return r
}

func (r PrerequisitesPrereqResult) WithRemediation(rem *PrerequisitesRemediation) PrerequisitesPrereqResult {
	r.Remediation = rem
	return r
}

// PrerequisitesFirstBlocker is the first blocking result in a set, if any.
//
// A surface with several prerequisites gates on the whole set, and should say
// which one it is gating on rather than listing everything at equal urgency.
func PrerequisitesFirstBlocker(results []PrerequisitesPrereqResult) *PrerequisitesPrereqResult {
	for i := range results {
		if results[i].Blocks() {
			return &results[i]
		}
	}
	return nil
}
