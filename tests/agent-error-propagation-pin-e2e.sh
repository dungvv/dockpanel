#!/usr/bin/env bash
#
# Pins the fix for issues #90, #91 and #92 — three separate reporters filing
# three separate bugs against one defect: the panel told them "Agent offline —
# the DockPanel agent is not responding" while the agent was answering
# perfectly clearly ("Path must be within /var/backups/ or /tmp/", "WAF not
# installed", a full nginx -t diagnostic).
#
# Two halves produced the lie and both are pinned here:
#   backend  — agent_error() took `impl Display`, so AgentError::Status(code,
#              body) was stringified and every non-2xx became one generic 502.
#              (Now agentError in panel/go/internal/api/core_error.go, whose
#              behaviour is pinned by Go tests in core_error_test.go.)
#   frontend — api.ts rewrote ANY 502 into the "agent offline" sentence.
#
# Plus the WAF half of #92: the installer's unicode.mapping fallback wrote a
# ZERO-BYTE file, which ModSecurity cannot parse, so nginx -t failed the first
# time a site enabled the WAF — after the installer had reported success.
#
# ⚠ Every source check below strips comments before searching. This file's own
# subject matter is spelled out in the comments of the code it inspects, so a
# raw-source grep would credit (or convict) the prose that explains the trap
# rather than the code that avoids it. See feedback_source_pin_prose_trap and
# lesson #110f — that trap has now fired on three separate suites.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ✓ %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  ✗ %s\n' "$1"; }

ERR_RS=panel/go/internal/api/core_error.go
DNS_GO=panel/go/internal/api/rt_dns.go
API_TS=panel/frontend/src/api.ts
SVC_RS=panel/go/internal/agent/routes/service_installer.go
MIG_TSX=panel/frontend/src/pages/Migration.tsx
MAPPING=panel/go/internal/agent/routes/unicode.mapping

# Strip block comments, then whole-line `//` comments. `//` is only stripped at
# the start of a (trimmed) line: stripping it mid-line would blank the inside
# of every string containing a URL and fail in the direction that PASSES.
code_of() {
  sed 's:/\*.*\*/::g' "$1" | awk '
    /\/\*/ { inblk=1 }
    !inblk { t=$0; sub(/^[ \t]+/,"",t); if (t !~ /^\/\//) print }
    /\*\// { inblk=0 }
  '
}

# grep -c, never grep -q: under pipefail a `grep -q` match SIGPIPEs its
# producer and the pipeline reports FAILURE for a SUCCESSFUL match (#103d).
has() { [ "$(code_of "$1" | grep -cF -- "$2")" -gt 0 ]; }
hasre() { [ "$(code_of "$1" | grep -cE -- "$2")" -gt 0 ]; }

echo "§1-§3 the status survives the boundary; only an unreachable agent is reported as unreachable; a 5xx hides its internals"

# §1 'agent_error takes AgentError by value' retired (obsolete in Go): agentError
#   takes `error` and recovers *AgentError with errors.As — the status cannot be
#   stringified away by a type bound; what matters is behaviour, pinned below.
# §1 4xx-branch arm retired: covered by TestAgent4xxKeepsStatusAndSaysWhy (panel/go/internal/api/core_error_test.go)
# §1 from_u16 arm retired: covered by TestAgent412IsPreserved (panel/go/internal/api/core_error_test.go)
# §2 Connection|CircuitOpen arm retired: covered by TestOnlyTransportFailureIsMarkedUnreachable (panel/go/internal/api/core_error_test.go)
# §2 both-body-shapes arm retired: covered by TestSuccessFalseMessageShapeIsUnderstood (panel/go/internal/api/core_error_test.go)
# §3 5xx arm retired: covered by TestAgent5xxStaysGenericWithIncidentID (panel/go/internal/api/core_error_test.go)
if (cd panel/go && go test ./internal/api/ -count=1 \
      -run '^(TestAgent4xxKeepsStatusAndSaysWhy|TestAgent412IsPreserved|TestOnlyTransportFailureIsMarkedUnreachable|TestSuccessFalseMessageShapeIsUnderstood|TestAgent5xxStaysGenericWithIncidentID)$' >/dev/null 2>&1); then
  ok "the agentError Go tests pass (4xx kept with its reason, 412 kept, both body shapes, 5xx generic, only transport = unreachable)"
else
  bad "the agentError Go tests fail — agent refusals are being collapsed or mislabelled again"
fi

# The marker must NOT be reachable from the Status arms. Count its occurrences
# in PRODUCTION code: one definition + one use in the transport arm is the whole
# story. (Go tests live in core_error_test.go, so the file is production-only.)
MARKER_USES=$(code_of "$ERR_RS" | grep -cF 'CodeAgentUnreachable')
if [ "$MARKER_USES" -eq 2 ]; then
  ok "CodeAgentUnreachable appears exactly twice in production code (definition + the one arm that earns it)"
else
  bad "CodeAgentUnreachable appears $MARKER_USES times in production code, expected 2 — a Status or Parse arm may now be claiming the agent is offline"
fi

echo
echo "§4 the frontend stops inferring a cause from a status code"

if hasre "$API_TS" 'code\?: string \}\)\.code === "agent_unreachable"'; then
  ok "api.ts branches on the backend's marker"
else
  bad "api.ts does not branch on the agent_unreachable marker"
fi

# NEGATIVE: the blanket rewrite must be gone from the CODE. The comment above
# it describes the old behaviour on purpose, which is why this reads code only.
if hasre "$API_TS" 'res\.status === 502'; then
  bad "api.ts still keys the 'agent offline' message off a bare 502 — that is the defect in #90/#91/#92"
else
  ok "no bare-502 branch remains in api.ts"
fi

echo
echo "§5 third-party failures are not the agent's fault"

if hasre "$ERR_RS" '^func upstreamError\('; then
  ok "upstream_error exists for third-party calls"
else
  bad "no upstream_error — Stripe/Cloudflare failures have nowhere honest to go"
fi

# rt_dns.go legitimately talks to BOTH: Cloudflare over net/http and the agent
# for the cloudflared service. What is pinned here is that the Cloudflare half
# has somewhere honest to go.
if hasre "$DNS_GO" 'upstreamError\("Cloudflare'; then
  ok "rt_dns.go reports Cloudflare failures as Cloudflare failures"
else
  bad "rt_dns.go no longer routes Cloudflare failures through upstream_error"
fi

echo
echo "§6 the WAF's unicode.mapping cannot be empty (#92)"

if [ -f "$MAPPING" ]; then
  ok "the vendored mapping asset is in the tree"
else
  bad "$MAPPING is missing — the //go:embed will not compile"
fi

SZ=$(wc -c < "$MAPPING" 2>/dev/null || echo 0)
if [ "$SZ" -gt 40000 ]; then
  ok "the mapping asset is a real file ($SZ bytes)"
else
  bad "the mapping asset is $SZ bytes — a truncated mapping fails nginx -t exactly like the empty one did"
fi

if [ "$(grep -cE '^20127' "$MAPPING" 2>/dev/null || echo 0)" -gt 0 ]; then
  ok "the asset defines code page 20127, which modsecurity.conf names"
else
  bad "the asset has no 20127 section — the code page modsecurity.conf asks for is absent"
fi

# Read RAW, deliberately: a //go:embed directive is spelled like a comment and
# code_of would blank it. Anchored on the directive immediately followed by the
# var it fills, so prose mentioning go:embed cannot satisfy it.
if [ "$(grep -A1 -xF '//go:embed unicode.mapping' "$SVC_RS" | grep -cxE 'var serviceInstallerUnicodeMapping string')" -gt 0 ]; then
  ok "the mapping rides the binary instead of depending on distro packaging"
else
  bad "unicode.mapping is not embedded — Debian 13 ships no copy, so the install writes nothing usable"
fi

# NEGATIVE: the zero-byte fallback. Written as a regex over CODE so the comment
# explaining why it was removed cannot satisfy it.
if hasre "$SVC_RS" 'WriteFile\((serviceInstallerMappingPath|"/etc/modsecurity/unicode\.mapping"), (nil|\[\]byte\(""\))'; then
  bad "the empty-file fallback is back — it creates a file ModSecurity cannot parse and reports the install as successful"
elif hasre "$SVC_RS" 'os\.WriteFile\(serviceInstallerMappingPath, \[\]byte\(contents\)'; then
  ok "no zero-byte unicode.mapping fallback (the one write is of the real contents)"
else
  bad "the unicode.mapping write is gone or reshaped — this absence arm can no longer see the code it guards"
fi

if hasre "$SVC_RS" 'strings\.Contains\(string\(b\), "20127"\)'; then
  ok "the installer verifies the mapping it just wrote, rather than assuming it"
else
  bad "the installer does not check unicode.mapping after writing — #45's shape, and the reason #92 shipped as a success"
fi

echo
echo "§7 the migration field asks for a path the agent accepts (#90)"

if hasre "$MIG_TSX" 'placeholder="/var/backups/'; then
  ok "the placeholder suggests an accepted directory"
else
  bad "the Backup File Path placeholder does not suggest /var/backups/"
fi

if hasre "$MIG_TSX" 'placeholder="/home/'; then
  bad "the placeholder still suggests /home/, which routes/migration.go is written to refuse"
else
  ok "the placeholder no longer suggests a path the agent rejects"
fi

if has "$MIG_TSX" '/var/backups/' && has "$MIG_TSX" '/tmp/'; then
  ok "the field states the real constraint to the operator"
else
  bad "the helper text does not state where the archive must live"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
