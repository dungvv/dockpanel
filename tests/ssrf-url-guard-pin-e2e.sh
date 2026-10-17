#!/usr/bin/env bash
# ssrf-url-guard-pin-e2e.sh — s383
#
# One SSRF guard, parsed by a real URL parser, in one place.
#
# `validate_url_not_internal` used to extract the host by string surgery — strip
# the scheme by byte offset, `split('/').next()`, then `split(':').next()`. For a
# userinfo authority that reads the WRONG host: `http://192.0.2.1:x@127.0.0.1/`
# tested `192.0.2.1` (public → PASS) while every HTTP client dials `127.0.0.1`.
# Proven live on v2.135.0: an ordinary account pointed a monitor at
# `http://example.com:x@127.0.0.1:9999/` and read an internal-only service's
# status code back, plus a keyword oracle over its body. A second, hand-rolled
# copy with a strictly weaker classifier sat in `routes/extensions.rs`.
#
#   §A  THE HAND-ROLLED HOST EXTRACTION IS GONE, in BOTH files. A grep over raw
#       source matches the comment that documents its removal, so every arm reads
#       COMMENT-STRIPPED, WHITESPACE-COLLAPSED source and asserts the token
#       SEQUENCE `split('/').next()…split(':').next()` is absent. rustfmt is a
#       second author with commit rights, so whitespace is squeezed from both
#       sides before matching.
#   §B  THE ONE PARSER IS PRESENT (positive control). `url::Url::parse` is the
#       host authority in `helpers.rs`, and `extensions.rs` DELEGATES to the
#       shared helper rather than re-parsing. An arm that only forbids the old
#       shape passes vacuously if the whole function is deleted.
#   §C  THE tcp/ping LANE IS GUARDED TOO. `validate_host_not_internal` exists and
#       is called at create, update and check time — the internal port-scanner
#       lane the HTTP guard alone left open.
#   §D  CONTEXT. Arms green at BOTH tags so a harness measuring nothing cannot
#       read as a pass.
#   §E  s419 (v2.172.0): the uptime HTTP check's redirect-following policy used to
#       re-validate each hop with a BLOCKING, synchronous check
#       (`host_resolves_internal_blocking`) and then let reqwest resolve the
#       hop's hostname AGAIN, independently, to actually connect — the same
#       check-then-reconnect TOCTOU `resolve_validated`/`pinned_client` closed
#       for the INITIAL request at v2.166.0, still open on every redirect hop.
#       Closed by installing `ValidatingResolver` (a `reqwest::dns::Resolve`
#       impl, `helpers.rs`) as the client's DNS resolver via `.dns_resolver`,
#       sharing `resolve_all_validated` with `resolve_validated` so validation
#       and connection are now the SAME lookup on every hop, not two. The
#       synchronous blocking check stays — it is the only thing that catches a
#       redirect `Location` that is already a literal internal IP, which never
#       reaches a `Resolve` impl at all.
#
# Go port (panel/go/internal/api): helpers → core_helpers.go (urlAuthority /
# parseAuthority over net/url, validateURLNotInternal, validateHostNotInternal,
# resolveAllValidated, resolveValidated); ValidatingResolver's job is done by
# validatingDialContext, installed via pinnedTransport's DialContext; the uptime
# client is built in svc_uptime.go::uptimeCheckHTTP with CheckRedirect:
# uptimeCheckRedirect (the synchronous per-hop hostResolvesInternalBlocking).
# The userinfo-spoof behaviour itself is also pinned by
# TestUserinfoSpoofedInternalHostIsRejected (core_helpers_test.go).

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=============================================="
echo "  SSRF URL guard — source pins (s383)"
echo "=============================================="
echo

PASS=0; FAIL=0; SKIP=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

# Strip block and line comments so an arm cannot match the prose that
# documents the very code it forbids.
code() {
  perl -0777 -pe '
    s{/\*.*?\*/}{}gs;
    s{^\s*//.*$}{}gm;
  ' "$1"
}
# One top-level Go func's body.
fnbody() { code "$1" | perl -0777 -ne 'print $1 if /\n(func (?:\([^)]*\) )?\Q'"$2"'\E\(.*?\n\})\n/s'; }

HELPERS=panel/go/internal/api/core_helpers.go
EXT=panel/go/internal/api/rt_extensions.go
MON=panel/go/internal/api/rt_monitors.go
UPT=panel/go/internal/api/svc_uptime.go

for f in "$HELPERS" "$EXT" "$MON" "$UPT"; do
  [ -f "$f" ] || { echo "  FATAL: $f missing — wrong tree?"; exit 1; }
done

# The retired shape's actual fingerprint: cut the PATH at '/' and THEN — within
# the same few statements — cut the PORT at ':', in that exact order (Go:
# strings.Cut/Split/SplitN). Matching the two cuts ANYWHERE, independent of
# order, over-fires on a legitimate use of the same calls for something that
# isn't URL-authority extraction — the scp-like `git@host:path` git-remote
# shorthand (repoURLAuthority), which cuts ':' FIRST, has no userinfo
# ambiguity to get wrong, and genuinely cannot go through net/url. Per the s416
# pin lesson: when a pin fires on a legitimate new shape, tighten the pin to the
# ACTUAL invariant instead of loosening the code to dodge it.
OLD_CHAIN='strings\.(?:Cut|SplitN?)\([^)]*"/"[^)]*\).{0,200}?strings\.(?:Cut|SplitN?)\([^)]*":"'
REV_CHAIN='strings\.(?:Cut|SplitN?)\([^)]*":"[^)]*\).{0,200}?strings\.(?:Cut|SplitN?)\([^)]*"/"'

# Exit 0 = match, 1 = no match, anything else = the matcher itself broke (which
# must never read as "absent"). The pattern travels in the environment so no
# '/' or quote in it can be mangled by the shell or perl's own delimiters.
matches() { code "$1" | RE="$2" perl -0777 -ne 'BEGIN { $re = qr/$ENV{RE}/s } exit(/$re/ ? 0 : 1)'; }

echo "§A  the hand-rolled host extraction is absent in both parsers"
for f in "$HELPERS" "$EXT"; do
  matches "$f" "$OLD_CHAIN"; rc=$?
  if [ "$rc" -eq 0 ]; then
    bad "§A $f: hand-rolled cut-at-'/'…cut-at-':' host extraction is back"
  elif [ "$rc" -eq 1 ]; then
    ok "§A $f: no substring host extraction"
  else
    bad "§A $f: the detector itself failed (rc=$rc) — this arm examined nothing"
  fi
done
# Positive control: the same detector, order reversed, still sees the git@ shorthand.
if matches "$HELPERS" "$REV_CHAIN"; then
  ok "§A [control] the detector still sees the legitimate git@host:path cuts (':' then '/')"
else
  bad "§A [control] the detector cannot see repoURLAuthority's git@ cuts — the absence arms above may be blind"
fi

echo
echo "§B  the one real parser is present (positive control)"
UA=$(fnbody "$HELPERS" urlAuthority)
if grep -qF "parseAuthority(rawURL, true)" <<< "$UA" && grep -qF "url.Parse(rawURL)" <<< "$(fnbody "$HELPERS" parseAuthority)"; then
  ok "§B core_helpers.go parses with net/url (urlAuthority → parseAuthority → url.Parse)"
else
  bad "§B core_helpers.go no longer parses with net/url — the guard may have been gutted"
fi
# rt_extensions.go must DELEGATE, not re-implement: it calls the shared helper
# and does NOT itself parse or resolve the webhook URL.
EXTC=$(code "$EXT")
if grep -qF "validateURLNotInternal(ctx, url)" <<< "$EXTC"; then
  ok "§B rt_extensions.go delegates to the shared validateURLNotInternal"
else
  bad "§B rt_extensions.go no longer delegates to validateURLNotInternal"
fi
if grep -qE "Lookup(Host|IP|NetIP|IPAddr)\(|lookupValidated\(|url\.Parse\(" <<< "$EXTC"; then
  bad "§B rt_extensions.go parses/resolves a host itself again — the weak second copy is regrowing"
else
  ok "§B rt_extensions.go does not resolve a webhook host itself"
fi

echo
echo "§C  the tcp/ping lane is guarded (bare-host SSRF check exists and is wired)"
if grep -qF "func validateHostNotInternal(" <<< "$(code "$HELPERS")"; then
  ok "§C core_helpers.go defines validateHostNotInternal"
else
  bad "§C core_helpers.go no longer defines the bare-host guard"
fi
# Write time (rt_monitors.go, create+update) calls validateHostNotInternal.
# Check time (svc_uptime.go, tcp/ping) calls resolveValidated: the SAME
# internal-address check, returning the one validated address so the connect
# dials THAT address rather than resolving again (s414). Count either name.
UPT_CALLS=$(grep -cE "validateHostNotInternal\(|resolveValidated\(" <<< "$(code "$UPT")")
MON_CALLS=$(grep -cF "validateHostNotInternal(" <<< "$(code "$MON")")
if [ "${UPT_CALLS:-0}" -ge 2 ]; then
  ok "§C svc_uptime.go re-validates the host in the tcp and ping checks ($UPT_CALLS calls)"
else
  bad "§C svc_uptime.go check-time host validation missing ($UPT_CALLS calls, want ≥2)"
fi
if [ "${MON_CALLS:-0}" -ge 2 ]; then
  ok "§C rt_monitors.go validates the tcp/ping host at create and update ($MON_CALLS calls)"
else
  bad "§C rt_monitors.go write-time host validation missing ($MON_CALLS calls, want ≥2)"
fi

echo
echo "§E  the uptime redirect-hop resolver closes the check-then-reconnect gap"

# Isolate the functions' own bodies rather than grepping whole files — a bare
# 'validatingDialContext' match anywhere else (e.g. a comment) would be vacuous.
CHECK_FN=$(fnbody "$UPT" uptimeCheckHTTP)
PINNED_FN=$(fnbody "$HELPERS" pinnedTransport)
if [ -z "$CHECK_FN" ] || [ -z "$PINNED_FN" ]; then
  bad "§E could not isolate uptimeCheckHTTP()/pinnedTransport() — function renamed or removed?"
elif grep -qF 'tr, err := pinnedTransport(ctx, host, port)' <<< "$CHECK_FN" && grep -qF 'Transport: tr' <<< "$CHECK_FN" \
     && grep -qF 'tr.DialContext = func(' <<< "$PINNED_FN" && grep -qF 'return validatingDialContext(ctx, network, addr)' <<< "$PINNED_FN"; then
  ok "§E the uptime HTTP client's transport dials every redirect hop through validatingDialContext"
else
  bad "§E the uptime HTTP client no longer wires validatingDialContext into its DialContext"
fi
# Positive control: the pre-existing synchronous blocking check is STILL on the
# SAME client — proves the dial-time resolver was ADDED, not swapped in to
# replace the only thing that can catch a literal-IP redirect target.
if grep -qF 'CheckRedirect: uptimeCheckRedirect' <<< "$CHECK_FN" \
   && grep -qF 'hostResolvesInternalBlocking(' <<< "$(fnbody "$UPT" uptimeCheckRedirect)"; then
  ok "§E uptimeCheckHTTP's client still runs the synchronous per-hop block too"
else
  bad "§E the synchronous redirect-hop check is gone from the uptime HTTP client"
fi

# validatingDialContext's OWN body must call the real validator, not a stub.
VDC=$(fnbody "$HELPERS" validatingDialContext)
if [ -z "$VDC" ]; then
  bad "§E could not isolate validatingDialContext — renamed or removed?"
elif grep -qF 'resolveAllValidated(' <<< "$VDC"; then
  ok "§E validatingDialContext() calls the real validator, not a stub"
else
  bad "§E validatingDialContext() no longer calls resolveAllValidated"
fi

# The structural security property: the redirect-hop guard and the
# INITIAL-request guard (resolveValidated) share ONE classifier rather than two
# that could quietly drift apart — both callers plus its own `func` line is 3.
CALLS=$(grep -coF 'resolveAllValidated(' <<< "$(code "$HELPERS")")
if [ "${CALLS:-0}" -ge 3 ]; then
  ok "§E resolveAllValidated is the SHARED core for both the initial request and every redirect hop ($CALLS occurrences)"
else
  bad "§E resolveAllValidated is not shared by both guards ($CALLS occurrences, want ≥3 — declaration + 2 callers)"
fi

echo
echo "----------------------------------------------"
printf '  PASS %d   FAIL %d   SKIP %d\n' "$PASS" "$FAIL" "$SKIP"
echo
[ "$FAIL" -eq 0 ] || exit 1
