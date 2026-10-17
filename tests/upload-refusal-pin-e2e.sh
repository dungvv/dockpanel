#!/usr/bin/env bash
# Regression pins for the s384 ship — the panel refuses a file and says why.
#
# Issue #121 reported a ~33 MB upload that "fails silently without displaying a
# clear error message". Both halves of that sentence were true, for two
# independent reasons that had to be fixed together:
#
#   * THE NUMBER WAS A FICTION. An upload is base64 inside a JSON body, and the
#     body is capped at axum's 2 MiB default — on the panel hop AND again on the
#     panel-to-agent hop, a second axum service with the same default. Neither
#     had a limit override anywhere in the tree. So the real ceiling was ~1.5 MB
#     of file, while the panel's own handler advertised 100 MB and the agent's
#     advertised 50 MB. Both of those checks sat BELOW the framework's rejection
#     and could never run: two services, two unreachable numbers.
#   * THE REFUSAL WAS DISCARDED. The framework answers an oversize body with a
#     plain-text 413 that `api.ts` correctly degrades to "Request failed (413)".
#     `Files.tsx` then threw it away in a bare `} catch {`, leaving the operator
#     a self-erasing "0 uploaded, 1 failed" — a count, with no reason.
#
# §A pins the number across FOUR surfaces in three languages, because nothing
# else can hold them together: the two Go services (panel API + agent, both in
# panel/go — formerly two Rust crates), the SPA, and the published guide.
# Behaviour a test can call directly (§A5's envelope arithmetic, §B's
# status-routed refusal, §D's marker on it) is pinned by Go tests run here. §B pins the mechanism that lets a handler answer at all. §C is the
# CLASS arm — it forbids the swallow shape tree-wide rather than naming the two
# pages that had it. §D pins the machine-readable marker. §E pins that the dead
# numbers stay dead.
#
# Every arm is static analysis over source text: offline and deterministic, so
# it judges the MUTATED tree the same way on an air-gapped runner (lesson #641).
# No arm is keyed on a bare identifier, because several of these files spell the
# constant's name in a comment (lesson #627) — the arms key on declaration and
# call shapes instead.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
ok()  { printf '\033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '\033[31m✗\033[0m %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3', got '$2'"; }

# ugrep's --ignore-files shim honours .gitignore, so every count below uses the
# real binary explicitly (dockpanel-ops-p2, s357).
G=/usr/bin/grep

PANEL=panel/go/internal/api/rt_files.go
AGENT=panel/go/internal/agent/routes/server_utils.go
CONST=panel/frontend/src/constants.ts
FILES=panel/frontend/src/pages/Files.tsx
TERM=panel/frontend/src/pages/Terminal.tsx
ERRS=panel/go/internal/api/core_error.go
GUIDE=docs/guides/file-uploads.md
SPA=panel/frontend/src

for f in "$PANEL" "$AGENT" "$CONST" "$FILES" "$TERM" "$ERRS" "$GUIDE"; do
  [ -f "$f" ] || { bad "SETUP" "$f missing"; exit 1; }
done
[ -d "$SPA" ] || { bad "SETUP" "$SPA missing"; exit 1; }

# An arm that measures an empty subject prints green for every absence below, so
# each subject is asserted before it is measured (lesson #143).
for pair in "$PANEL:300" "$AGENT:300" "$FILES:250" "$TERM:700" "$GUIDE:80"; do
  f=${pair%:*}; min=${pair##*:}
  n=$($G -c '' "$f")
  [ "$n" -gt "$min" ] && ok "A0 subject extracted — $f is $n lines" \
    || bad "A0 subject extracted" "$f is only $n lines — arms over it examined nothing"
done

echo "── A. One limit, stated identically on every surface that states one ──────────"

# Read the number from each surface INDEPENDENTLY, then compare. Digit grouping
# differs by language (Go and TS use _, English prose uses ,), so both are
# stripped before comparison. The declaration shape is the anchor — a comment
# mentioning the constant by name must not satisfy this (#627).
num() { printf '%s' "$1" | tr -d '_,'; }

P_NUM=$(num "$($G -oP '^const\s+rtFilesUploadMaxFileBytes\s*=\s*\K[0-9_]+' "$PANEL" | head -1)")
A_NUM=$(num "$($G -oP '^const\s+serverUtilsUploadMaxFileBytes\s*=\s*\K[0-9_]+' "$AGENT" | head -1)")
C_NUM=$(num "$($G -oP 'export\s+const\s+UPLOAD_MAX_FILE_BYTES\s*=\s*\K[0-9_]+' "$CONST" | head -1)")
D_NUM=$(num "$($G -oP '(?<![0-9,])\K[0-9]{1,3}(,[0-9]{3})+(?=\s+to leave room)' "$GUIDE" | head -1)")

[ -n "$P_NUM" ] && ok "A1 panel declares a limit — $P_NUM bytes" \
  || bad "A1 panel declares a limit" "no rtFilesUploadMaxFileBytes declaration in $PANEL"
eq  "A2 agent states the same limit as the panel"     "$A_NUM" "$P_NUM"
eq  "A3 the SPA states the same limit as the panel"   "$C_NUM" "$P_NUM"
eq  "A4 the published guide states the same limit"    "$D_NUM" "$P_NUM"

# The limit must stay BELOW the envelope that rejects before any of it runs,
# or the panel is advertising an unenforceable number again — which is the
# defect this suite exists for, not a smaller version of it.
# A5 retired to Go: covered by TestRtFilesTheAdvertisedLimitFitsInsideTheBodyEnvelope (panel/go/internal/api/rt_files_test.go — against the real maxJSONBody, not a restated 2 MiB)
if (cd panel/go && go test ./internal/api/ -count=1 -run '^TestRtFilesTheAdvertisedLimitFitsInsideTheBodyEnvelope$' >/dev/null 2>&1); then
  ok "A5 the advertised limit fits inside the 2 MiB body envelope"
else
  bad "A5 the advertised limit fits inside the 2 MiB body envelope" \
      "TestRtFilesTheAdvertisedLimitFitsInsideTheBodyEnvelope fails — an oversize body would be refused by the framework, unexplained"
fi

echo "── B. Both upload handlers can ANSWER an oversize body ───────────────────────"

# Taking the rejection instead of letting the extractor short-circuit is the
# only reason a handler runs at all for an oversize body. Whitespace-collapsed,
# because gofmt/prettier reflow and have turned an arm of ours red for a no-op
# before (#585/#638).
flat() { tr -d ' \t\n' < "$1"; }

# B1 (panel) — wiring: the upload handler hands the decode error to the
# rejection router rather than returning it raw.
if flat "$PANEL" | $G -q 'iferr:=decodeJSON(r,&body);err!=nil{returnrtFilesUploadRejection(err)}'; then
  ok "B1 ${PANEL##*/} takes the body rejection rather than short-circuiting on it"
else
  bad "B1 ${PANEL##*/} takes the body rejection rather than short-circuiting on it" \
      "rtFilesUploadFile no longer routes decodeJSON's error through rtFilesUploadRejection — an oversize body is refused in plain text"
fi
# B1 (agent) retired to Go: covered by TestPinUploadRefusalAgentAnswersAnOversizeBody (panel/go/internal/agent/routes/pin_upload_refusal_test.go — drives the real handler with an oversize body)
if (cd panel/go && go test ./internal/agent/routes/ -count=1 -run '^TestPinUploadRefusalAgentAnswersAnOversizeBody$' >/dev/null 2>&1); then
  ok "B1 ${AGENT##*/} takes the body rejection rather than short-circuiting on it"
else
  bad "B1 ${AGENT##*/} takes the body rejection rather than short-circuiting on it" \
      "TestPinUploadRefusalAgentAnswersAnOversizeBody fails — the agent refuses an oversize body unexplained"
fi

# B2 and D2 retired to Go: covered by TestPinUploadRefusalOversizeBodyIsACoded413 (panel/go/internal/api/pin_upload_refusal_test.go — routed on the 413 status, answered with CodePayloadTooLarge and the limit)
if (cd panel/go && go test ./internal/api/ -count=1 -run '^TestPinUploadRefusalOversizeBodyIsACoded413$' >/dev/null 2>&1); then
  ok "B2 the panel routes the rejection on its status, and D2 answers it coded (Go test)"
else
  bad "B2 the panel routes the rejection on its status" "TestPinUploadRefusalOversizeBodyIsACoded413 fails"
fi

echo "── C. CLASS — no user-initiated write discards why it failed ──────────────────"

# Derived, not hand-listed: the whole SPA is searched for the swallow shape
# rather than the two pages that had it. The one-line form is the one that hid
# in the DNS loops, where a per-record `catch {}` left a green "Deleted N
# records" standing over records that were never deleted.
# ⛔ Slurp-mode on purpose. The first cut of this arm was a line-based grep, and
# a mutation that merely moved `catch {}` onto its own line walked straight
# through it — the defect is a SHAPE, and a shape is not a line (#409). This
# form is brace-aware (one level of nesting) and newline-insensitive, verified
# RED against three formattings of the same swallow: one-line, two-line, and
# prettier-reflowed.
SWALLOW=$(find "$SPA" \( -name '*.ts' -o -name '*.tsx' \) -print0 | sort -z |
  while IFS= read -r -d '' f; do
    perl -0777 -ne 'my $c=0; while (/try\s*\{(?:[^{}]|\{[^{}]*\})*?api\.(?:post|put|delete)\((?:[^{}]|\{[^{}]*\})*?\}\s*catch\s*\{\s*\}/gs) { $c++ } print "$c\n"' "$f"
  done | awk '{s+=$1} END {print s+0}')
# The enumeration must be non-empty or the count above is an absence, not a zero.
SPA_FILES=$(find "$SPA" \( -name '*.ts' -o -name '*.tsx' \) | wc -l)
[ "$SPA_FILES" -gt 50 ] && ok "C0 class arm enumerated $SPA_FILES SPA modules" \
  || bad "C0 class arm enumerated $SPA_FILES SPA modules" "too few — C1 below measured almost nothing"
eq "C1 no user-initiated write swallows its failure" "$SWALLOW" "0"

# The two upload doors specifically: each must check the size BEFORE spending
# the upload, and must bind its catch. Keyed on the guard's comparison and on
# the binding, never on the constant's name — both files mention it in prose.
for f in "$FILES" "$TERM"; do
  if flat "$f" | $G -q 'file.size>UPLOAD_MAX_FILE_BYTES'; then
    ok "C2 ${f##*/} refuses an oversize file before uploading it"
  else
    bad "C2 ${f##*/} refuses an oversize file before uploading it" \
        "no size comparison — the operator learns of the limit only after the whole body has travelled"
  fi
done

# A bound catch is what carries the reason. Counting the BARE form inside each
# upload door: the region is delimited by the door's own markers so an unrelated
# bare catch elsewhere in a 900-line page does not fail this arm.
BARE_FILES=$(sed -n '/for (const file of Array.from(files))/,/setUploading(false)/p' "$FILES" | $G -c '} catch {')
eq "C3 the file manager's upload loop binds its catch" "$BARE_FILES" "0"

BARE_TERM=$(sed -n '/reader.onload = async () => {/,/reader.readAsDataURL(file)/p' "$TERM" | $G -c '} catch {')
eq "C4 the terminal's upload binds its catch" "$BARE_TERM" "0"

echo "── D. The refusal carries a marker a client can branch on ────────────────────"

DECL=$(cat panel/go/internal/api/*.go | $G -c '^const CodePayloadTooLarge = ')
eq "D1 the marker is declared exactly once" "$DECL" "1"

# D2 retired: covered by TestPinUploadRefusalOversizeBodyIsACoded413 (see §B above)

echo "── E. The unreachable numbers stay dead ──────────────────────────────────────"

# These two literals were the whole fiction: 100 MB in the panel and 50 MB in
# the agent, both sitting below a 2 MiB framework rejection. Reinstating either
# reinstates a number the product cannot honour.
# Both spellings Go would use. The A1/A2 declarations above are these absence
# arms' positive anchor: the subjects are real files holding the live limit.
eq "E1 the panel's unreachable 100 MB check is gone" "$($G -cE '100 \* 1024 \* 1024|100 << 20' "$PANEL")" "0"
eq "E2 the agent's unreachable 50 MB check is gone"  "$($G -cE '50 \* 1024 \* 1024|50 << 20' "$AGENT")"  "0"

echo
echo "── upload-refusal: $PASS passed, $FAIL failed ────────────────────────────────"
[ "$FAIL" -eq 0 ]
