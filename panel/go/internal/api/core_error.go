package api

// Port of panel/backend/src/error.rs.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// ApiError is the Rust `(StatusCode, Json<Value>)` pair. Handlers return it
// as an `error`; Router writes it. Body is usually {"error": msg} but a
// handler may hand back any JSON shape, exactly as Rust handlers could.
type ApiError struct {
	Status int
	Body   any
}

func (e *ApiError) Error() string {
	if m, ok := e.Body.(map[string]any); ok {
		if s, ok := m["error"].(string); ok {
			return fmt.Sprintf("%d: %s", e.Status, s)
		}
	}
	return fmt.Sprintf("%d", e.Status)
}

// plainError is an axum extractor rejection: a text/plain body, not JSON
// (a malformed JSON body, a bad query string, an unparseable path param).
type plainError struct {
	Status int
	Msg    string
}

func (e *plainError) Error() string { return fmt.Sprintf("%d: %s", e.Status, e.Msg) }

// CodeAgentUnreachable is the stable machine-readable marker for "the agent
// could not be reached at all".
//
// Clients must branch on this rather than on the bare HTTP status. A 502 from
// this panel can mean *the agent never answered* or *the agent answered and
// something failed inside it*, and only the first justifies telling an
// operator their agent is offline.
const CodeAgentUnreachable = "agent_unreachable"

// CodeReauthRequired is the marker for "re-present a credential before this
// account may enrol a new authenticator".
//
// The status carried alongside it is deliberately **403, never 401**, and it
// stays 403 now that CodeSessionInvalid has made 401 survivable. The session
// is still valid; only this one action is refused, which is what 403 means.
// Do not "restore" this to 401 on the grounds that bodies now survive.
const CodeReauthRequired = "reauth_required"

// CodeSessionInvalid is the marker for "the caller has no usable session".
//
// This is the ONLY thing that entitles the frontend to navigate someone to
// /login, and it is emitted from exactly one place: authUser and its
// serverScope sibling in core_auth.go. The rule behind that is structural —
// **if a handler returned 401, the session was valid**, because the auth
// check had already let the request through. A handler's 401 means the
// credential presented *inside* an authenticated request was refused (a wrong
// password, a wrong TOTP code, a signature that did not verify). Logging
// someone out for that is answering a question nobody asked.
//
// Until v2.87.0 the client could not tell the two apart, navigated to /login
// and threw a fixed "Unauthorized" before the body was ever parsed — every
// sentence written at a 401 site was discarded unread.
const CodeSessionInvalid = "session_invalid"

// CodePayloadTooLarge is the marker for "what you sent will not fit through
// the panel". It exists because the framework's own 413 ("Failed to buffer the
// request body: length limit exceeded", plain text) cannot be rendered — issue
// #121 was a 33 MB upload that produced no explanation at all. Handlers that
// can be handed an oversize body answer with this code and a real sentence.
const CodePayloadTooLarge = "payload_too_large"

// CodeForeignCertificate is the label the agent puts on a provision/renew
// order it declined because a certificate this product did not issue is
// already installed (panel/agent ssl.rs::ca_or_internal). Exported because a
// provision door's apiErrCoded names it, so the frontend's force-retry has
// exactly one string to match. ⚠ Severed pair: the agent carries the same
// literal and cannot share this constant.
const CodeForeignCertificate = "foreign_certificate"

// maxAgentMsg is the longest agent-authored message passed through to a client.
const maxAgentMsg = 400

// The labels the agent puts on certificate failures. ⚠ The agent carries the
// same literals and cannot share a constant with these — a severed pair by
// construction; renaming one side silently returns every failed order to an
// incident id with nothing red.
const (
	acmeOrderFailedCode   = "acme_order_failed"
	dnsProviderFailedCode = "dns_provider_failed"
	// The renewal route's wrapper around the same failure, carried by every
	// agent ever shipped — recognising it is what lets an install nobody has
	// updated get the honest answer today.
	renewalFailurePrefix = "Renewal failed:"
)

// apiErr is error.rs::err — {"error": msg} with status.
func apiErr(status int, msg string) error {
	return &ApiError{Status: status, Body: map[string]any{"error": msg}}
}

// apiErrCoded is error.rs::err_coded — apiErr plus a stable `code` the
// frontend can branch on.
func apiErrCoded(status int, msg, code string) error {
	return &ApiError{Status: status, Body: map[string]any{"error": msg, "code": code}}
}

// apiErrJSON is a Rust handler's bespoke `(StatusCode, Json(json!({...})))`.
func apiErrJSON(status int, body any) error { return &ApiError{Status: status, Body: body} }

// agentMessage extracts the human-facing sentence from an agent error body.
// The agent answers errors in three shapes — {"error": …}, {"success": false,
// "message": …}, and occasionally bare text — so all three are handled.
func agentMessage(body string) string {
	msg := body
	var v any
	if json.Unmarshal([]byte(body), &v) == nil {
		if m, ok := v.(map[string]any); ok {
			// Rust: v.get("error").or_else(|| v.get("message")).and_then(as_str)
			// — "message" is only consulted when "error" is ABSENT.
			f, has := m["error"]
			if !has {
				f, has = m["message"]
			}
			if s, ok := f.(string); has && ok {
				msg = s
			}
		}
	}
	// Don't surface the Docker daemon's framing around an inner diagnostic.
	msg = strings.TrimSpace(strings.TrimPrefix(msg, "Error response from daemon: "))
	if utf8.RuneCountInString(msg) > maxAgentMsg {
		r := []rune(msg)
		return string(r[:maxAgentMsg]) + "…"
	}
	return msg
}

// agentCode is the stable `code` an agent attached to an error body, if any.
// Shared by the label readers so the extraction lives once.
func agentCode(body string) (string, bool) {
	var v map[string]any
	if json.Unmarshal([]byte(body), &v) != nil {
		return "", false
	}
	s, ok := v["code"].(string)
	return s, ok
}

func asAgentStatus(e error) (*AgentError, bool) {
	var ae *AgentError
	if errors.As(e, &ae) && ae.Kind == AgentErrStatus {
		return ae, true
	}
	return nil, false
}

// dnsProviderFailure is the sentence a DNS provider's refusal should reach
// the operator as, or false when this failure is not one.
//
// The label is the ONLY proof accepted here, deliberately. Unlike
// acmeOrderFailure there is no legacy wrapper to recognise — the DNS-01 door
// never had one — and inventing one out of old message prefixes would be
// guessing. An agent older than this panel keeps its incident id here.
func dnsProviderFailure(e error) (string, bool) {
	ae, ok := asAgentStatus(e)
	if !ok || ae.Code < 500 || ae.Code >= 600 {
		return "", false
	}
	if c, ok := agentCode(ae.Msg); ok && c == dnsProviderFailedCode {
		return strings.TrimSpace(agentMessage(ae.Msg)), true
	}
	return "", false
}

// acmeOrderFailure is the sentence an agent's failed ACME order should reach
// the operator as, or false when this failure is not one.
//
// A failed order is the operator's to fix (the domain does not resolve here,
// port 80 is shut, a wildcard's apex lives elsewhere) and is the single most
// likely way an SSL button fails — yet the agent reports it as a 500 and every
// 5xx is hidden by design. It must be identified POSITIVELY rather than by
// widening the rule, because the same route answers 500 for a genuine internal
// fault that an incident id describes correctly. Two proofs, in order: the
// agent's stable label, else the renewal route's wrapper text (the half that
// reaches installs nobody has updated).
func acmeOrderFailure(e error) (string, bool) {
	ae, ok := asAgentStatus(e)
	if !ok || ae.Code < 500 || ae.Code >= 600 {
		return "", false
	}
	c, _ := agentCode(ae.Msg)
	labelled := c == acmeOrderFailedCode
	msg := agentMessage(ae.Msg)
	if labelled || strings.HasPrefix(msg, renewalFailurePrefix) {
		return strings.TrimSpace(strings.TrimPrefix(msg, renewalFailurePrefix)), true
	}
	return "", false
}

// agentActionable is the status and sentence an agent failure should reach
// the caller as, or false when only an incident id should describe it.
//
// agentError is the whole answer when ONE agent call decides the response. A
// fan-out over several members must pick one status, and the way that went
// wrong was stringifying each error and hand-rolling a 502 — throwing away
// precisely the 4xx this module preserves. This exposes the rule per member.
func agentActionable(e error) (int, string, bool) {
	ae, ok := asAgentStatus(e)
	if !ok || ae.Code < 400 || ae.Code >= 500 {
		return 0, "", false
	}
	return ae.Code, agentMessage(ae.Msg), true
}

// agentError converts an agent-call failure into a client-facing error.
//
// The distinction it preserves: a **4xx from the agent is an answer**,
// authored deliberately for whoever asked ("Path must be within
// /var/backups/", "WAF not installed"); collapsing it into a generic 502
// tells the operator their agent is down when it is working perfectly. Only a
// transport failure, an open circuit breaker, or a genuine 5xx is worth hiding
// behind an incident id.
func agentError(context string, e error) error {
	var ae *AgentError
	if !errors.As(e, &ae) {
		// Not an agent failure at all — treat as ours.
		return internalError(context, e)
	}
	switch ae.Kind {
	case AgentErrStatus:
		if ae.Code >= 400 && ae.Code < 500 {
			// The agent refused, and said why. Pass both through.
			msg := agentMessage(ae.Msg)
			slog.Warn(context, "agent_status", ae.Code, "error", msg)
			// A foreign-certificate refusal is the one 4xx a caller may retry
			// with force:true. Every provision/renew door funnels through here,
			// so fixing it here is what makes a door added later inherit it.
			if c, ok := agentCode(ae.Msg); ok && c == CodeForeignCertificate {
				return apiErrCoded(ae.Code, msg, CodeForeignCertificate)
			}
			return apiErr(ae.Code, msg)
		}
		// The agent broke internally. Log it, hand back a reference.
		id := uuid.New()
		slog.Error(context, "incident_id", id.String(), "agent_status", ae.Code, "error", agentMessage(ae.Msg))
		return apiErr(http.StatusBadGateway, "Operation failed. Reference: "+id.String())
	case AgentErrNotFound:
		slog.Warn(context, "error", ae.Msg)
		return apiErr(http.StatusNotFound, ae.Msg)
	case AgentErrConnection, AgentErrCircuitOpen:
		// Nothing answered. This is the only case that means "agent offline".
		id := uuid.New()
		slog.Error(context, "incident_id", id.String(), "error", ae.Error())
		return apiErrCoded(http.StatusBadGateway, "The agent is not responding. Reference: "+id.String(), CodeAgentUnreachable)
	default: // Request, Response, Parse
		id := uuid.New()
		slog.Error(context, "incident_id", id.String(), "error", ae.Error())
		return apiErr(http.StatusBadGateway, "Operation failed. Reference: "+id.String())
	}
}

// upstreamError: a call to a THIRD-PARTY service (Stripe, Cloudflare, …)
// failed. Deliberately separate from agentError — routing these through the
// agent path is what made a Cloudflare outage tell an operator their agent
// was offline. Carries no agent_unreachable marker.
func upstreamError(service string, e any) error {
	id := uuid.New()
	slog.Error(service, "incident_id", id.String(), "error", fmt.Sprint(e))
	return apiErr(http.StatusBadGateway, fmt.Sprintf("%s failed. Reference: %s", service, id))
}

// internalError logs the real error but returns only a generic message with a
// short reference id — never leak DB schema, file paths or SQL to a client.
func internalError(context string, e any) error {
	id := uuid.New()
	slog.Error(context, "incident_id", id.String(), "error", fmt.Sprint(e))
	return apiErr(http.StatusInternalServerError, "Internal error (ref: "+id.String()[:8]+")")
}

// requireAdmin returns nil for "admin", else 403.
func requireAdmin(role string) error {
	if role != "admin" {
		return apiErr(http.StatusForbidden, "Admin access required")
	}
	return nil
}

// paginate clamps limit to [1,200] (default 100) and offset to >= 0.
func paginate(limit, offset *int64) (int64, int64) {
	l, o := int64(100), int64(0)
	if limit != nil {
		l = *limit
	}
	if offset != nil {
		o = *offset
	}
	return min(max(l, 1), 200), max(o, 0)
}
