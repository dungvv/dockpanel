#!/usr/bin/env bash
# Regression pins for s379 — the published documentation that described a
# different product.
#
# Every defect below was live at 200 on docs.dockpanel.dev when it was found.
# None of them could fail a build, because nothing in the tree had ever compared
# a published instruction with the thing it instructs the reader to use.
#
#   P1  `docs/api-reference.md` carried NINE rows naming a path or a method the
#       router does not register, so a reader following the reference got 404 or
#       405. Four of them (`/vol-backups`) named a path segment that has never
#       existed — the real one is `/volume-backup(s)`. Meanwhile
#       `docs/guides/backup-orchestrator.md` and `docs/guides/status-page.md`
#       carried the CORRECT tables, so two published surfaces contradicted each
#       other and the reference was the wrong one.
#       This is a REPEAT: the router (then routes/mod.rs, now
#       panel/go/internal/api/rt_incidents.go) already carries a comment, above the
#       status-page unsubscribe route, recording that the handler doc, the guide
#       prose and the guide's API table had all published DELETE while the route
#       accepted POST only — "every reader who followed the documentation got a
#       405". That time the ROUTE was widened to match the docs. Nothing was
#       added to stop the next one, so there was a next one.
#   P2  `docs/guides/themes.md` advertised six themes by names the panel does
#       not ship (only "Midnight" survived the rename), a `Ctrl+Shift+T` cycle
#       shortcut that has no handler, a dropdown that is a cycle button plus a
#       swatch grid, per-user persistence that is really per-browser
#       localStorage, and a four-level Card Depth control that does not exist.
#   P3  `docs/guides/secrets.md` published seven `dockpanel secrets …` CLI
#       commands. The CLI (then a Rust crate, now panel/go/internal/cli) contains the string "secret" zero times.
#   P4  Two guides sent operators to screens that are not in the product: a
#       "Status Page > Subscribers" admin list whose endpoint has no caller, and
#       a "Settings > Notifications" per-type preference screen with no backing
#       schema.
#
# The shape of the fix is the point: P1 is not a list of nine corrections, it is
# a DERIVED check. It parses the router for the registered (method, path) set
# and the reference for the documented one, and fails on any documented row the
# router does not serve — so row ten is caught by the same arm, without anyone
# noticing it.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

ROUTER_DIR=panel/go/internal/api
APIREF=docs/api-reference.md
THEMES=docs/guides/themes.md
SECRETS=docs/guides/secrets.md
LAYOUT=panel/frontend/src/hooks/useLayoutState.ts
SETTINGS=panel/frontend/src/pages/Settings.tsx
STATUSPAGE=docs/guides/status-page.md
INCIDENTS=docs/guides/incidents.md
NOTIFS=docs/guides/notifications.md

[ -d "$ROUTER_DIR" ] || { echo "missing source dir: $ROUTER_DIR"; exit 1; }
for f in "$APIREF" "$THEMES" "$SECRETS" "$LAYOUT" "$SETTINGS" \
         "$STATUSPAGE" "$INCIDENTS" "$NOTIFS"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

echo
echo "── 1. every documented API row names a route the panel registers ──"

# The Go router is spread over every rt_*.go registrar, each calling
# r.Handle("<METHOD> <path>", ...). The parse below only sees string-literal
# patterns (plus the one table-driven loop it expands, rtSystemServices), so
# measure that: any OTHER non-literal registration would silently narrow it.
# `grep -r` (NOT `git grep`, which enumerates nothing outside a checkout).
STRAY=$(grep -rhE '\.Handle\(' --include=*.go "$ROUTER_DIR" | grep -v '_test\.go' \
  | grep -vE '\.Handle\("(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) /[^"]*",' \
  | grep -vE '^\s*func \(rt \*Router\) Handle\(' \
  | grep -vF 'r.Handle("POST /api/services/"+s.path,' | wc -l)
if [ "$STRAY" -eq 0 ]; then
  ok "every route registration in $ROUTER_DIR is a literal pattern (or the expanded rtSystemServices loop), so parsing them is complete"
else
  bad "$STRAY route registration(s) in $ROUTER_DIR use a non-literal pattern — this suite's parse is now partial"
fi

ROUTE_REPORT=$(python3 - "$ROUTER_DIR" "$APIREF" <<'PY'
import glob, os, re, sys
router_dir, doc_path = sys.argv[1], sys.argv[2]

# r.Handle("<METHOD> <path>", ...) in every non-test Go file of the api package.
routes = {}
for fn in sorted(glob.glob(os.path.join(router_dir, '*.go'))):
    if fn.endswith('_test.go'):
        continue
    src = open(fn).read()
    for m in re.finditer(r'\.Handle\("(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (/[^"]*)",', src):
        routes.setdefault(m.group(2), set()).add(m.group(1))
    # The one table-driven registrar: POST /api/services/<path> per rtSystemServices row.
    if 'r.Handle("POST /api/services/"+s.path,' in src:
        tbl = re.search(r'var rtSystemServices = \[\]struct\{[^}]*\}\{(.*?)\n\}', src, re.S)
        for path in re.findall(r'\{"([^"]+)", "', tbl.group(1) if tbl else ''):
            routes.setdefault('/api/services/' + path, set()).add('POST')

def norm(p):
    # A documented row may carry an example query string; it is not part of the path.
    # Param NAMES differ between the docs ({id}) and the router ({vault_id}) by
    # convention, so compare on shape ({rest...} wildcards included).
    return re.sub(r'\{[^}]*\}', '{}', p.split('?')[0].rstrip('/'))

registered = {}
for p, verbs in routes.items():
    registered.setdefault(norm(p), set()).update(verbs)

rows = []
for i, line in enumerate(open(doc_path).read().splitlines(), 1):
    m = re.match(r'^\|\s*(GET|POST|PUT|DELETE|PATCH)\s*\|\s*`([^`]+)`\s*\|', line)
    if m:
        rows.append((i, m.group(1), m.group(2)))

# Assert both enumerations BEFORE trusting either. An empty or implausibly small
# parse is the failure mode that reads exactly like a clean result.
if len(routes) < 200:
    print(f"ENUM-FAIL router yielded {len(routes)} routes")
    raise SystemExit
if len(rows) < 100:
    print(f"ENUM-FAIL reference yielded {len(rows)} documented rows")
    raise SystemExit

# ServeMux cannot hold some sibling patterns that axum could, so a few
# registrars take one wildcard pattern and dispatch on the segment inside the
# handler (rt_alerts.go: PUT /api/alerts/{a}/{b} serves .../{id}/acknowledge
# and .../{id}/resolve). Fall back to that: a pattern with the SAME number of
# segments whose wildcards cover the documented row's concrete segments.
# Never a trailing {rest...} wildcard — that would match everything.
def wild_verbs(n):
    segs = n.split('/')
    verbs = set()
    for p, v in registered.items():
        ps = p.split('/')
        if len(ps) == len(segs) and '...' not in p and \
           all(a == b or a == '{}' for a, b in zip(ps, segs)):
            verbs |= v
    return verbs

bad = []
via_wild = 0
for ln, meth, path in rows:
    if not path.startswith('/api/'):
        continue          # SPA paths and external URLs are not this arm's subject
    n = norm(path)
    verbs = registered.get(n, set())
    if meth not in verbs and meth in wild_verbs(n):
        via_wild += 1
        continue
    if not verbs and not wild_verbs(n):
        bad.append(f"{doc_path}:{ln} {meth} {path} — no such path in the router")
    elif meth not in verbs:
        have = ",".join(sorted(verbs | wild_verbs(n)))
        bad.append(f"{doc_path}:{ln} {meth} {path} — 405, router registers {have}")

print(f"ENUM-OK {len(routes)} route paths / {len(rows)} documented rows ({via_wild} via a dispatching wildcard)")
for b in bad:
    print("MISMATCH " + b)
PY
)

# `producer | grep -q` is forbidden here: grep -q exits on the first match and
# can SIGPIPE the producer, which under `set -o pipefail` turns a successful
# match into a failed pipeline. Match the variable directly instead.
case "$ROUTE_REPORT" in *ENUM-FAIL*) ENUM_FAILED=1 ;; *) ENUM_FAILED=0 ;; esac
if [ "$ENUM_FAILED" -eq 1 ]; then
  bad "route/reference enumeration failed: $(printf '%s' "$ROUTE_REPORT" | grep '^ENUM-FAIL')"
else
  ENUM=$(printf '%s' "$ROUTE_REPORT" | grep '^ENUM-OK')
  ok "enumeration is non-empty and plausible — ${ENUM#ENUM-OK }"
  MISMATCHES=$(printf '%s' "$ROUTE_REPORT" | grep -c '^MISMATCH')
  if [ "$MISMATCHES" -eq 0 ]; then
    ok "every documented /api row resolves to a registered route AND method"
  else
    bad "$MISMATCHES documented API row(s) name a route the panel does not serve:"
    printf '%s\n' "$ROUTE_REPORT" | grep '^MISMATCH' | sed 's/^MISMATCH /      /'
  fi
fi

echo
echo "── 2. the themes guide names the themes the panel ships ──"

# Derive the shipped ids from the cycle order, which is the list the header
# button walks — not from a hand-kept copy in this file.
SHIPPED=$(grep -oE 'const themeOrder = \[[^]]*\]' "$LAYOUT" | grep -oE '"[a-z-]+"' | tr -d '"')
SHIPPED_N=$(printf '%s\n' "$SHIPPED" | grep -c .)
if [ "$SHIPPED_N" -ge 4 ]; then
  ok "themeOrder enumerates $SHIPPED_N shipped themes"
else
  bad "could not read themeOrder from $LAYOUT (got $SHIPPED_N) — the arms below cannot be trusted"
fi

# The retired names. These are the exact strings the guide published for months
# against a panel that had renamed every one of them but Midnight.
RETIRED_HITS=0
for name in "Nexus Dark" "Nexus Light" "Ocean" "Forest" "Sunset"; do
  if grep -qF "$name" "$THEMES"; then
    bad "themes.md still advertises the retired theme name \"$name\""
    RETIRED_HITS=$((RETIRED_HITS+1))
  fi
done
# Positive control: the pattern shape CAN match this file, so "no hits" above is
# a real absence and not a broken grep.
if grep -qF "Midnight" "$THEMES"; then
  [ "$RETIRED_HITS" -eq 0 ] && ok "themes.md advertises no retired theme name (control: \"Midnight\" still matches)"
else
  bad "positive control failed — \"Midnight\" not found in $THEMES, so the absence checks above prove nothing"
fi

# Every theme and layout the guide puts in its table must be one the panel
# actually ships, compared on the DISPLAYED NAME. The id cannot be derived from
# the name by slugging — the panel shows "Clean Light" for the id `clean` — so
# take the names from the same literal the Settings picker renders.
#
# Read line by line: a `for` over command substitution word-splits "Clean Dark"
# into two labels and then indicts both halves.
SHIPPED_NAMES=$(grep -oE '\{ id: "[a-z-]+", name: "[A-Za-z ]+"' "$SETTINGS" | sed -E 's/.*name: "([A-Za-z ]+)".*/\1/')
SHIPPED_NAMES_N=$(printf '%s\n' "$SHIPPED_NAMES" | grep -c .)
if [ "$SHIPPED_NAMES_N" -ge 6 ]; then
  ok "Settings.tsx enumerates $SHIPPED_NAMES_N shipped theme/layout names"
else
  bad "could not read theme/layout names from $SETTINGS (got $SHIPPED_NAMES_N) — the arm below cannot be trusted"
fi

MISNAMED=0
while IFS= read -r label; do
  [ -n "$label" ] || continue
  # here-string, not a pipe — see the note above on grep -q under pipefail
  if ! grep -qxF "$label" <<<"$SHIPPED_NAMES"; then
    MISNAMED=$((MISNAMED+1))
    bad "themes.md names \"$label\", which the panel does not ship as a theme or layout"
  fi
done <<EOF
$(grep -oE '^\| \*\*[A-Za-z ]+\*\* \|' "$THEMES" | sed -E 's/^\| \*\*([A-Za-z ]+)\*\* \|/\1/')
EOF
[ "$MISNAMED" -eq 0 ] && ok "every theme and layout the guide names is one the panel ships"

# The shortcut never had a handler. Forbid the claim, and prove the file is
# readable by the same grep.
if grep -qF 'Ctrl+Shift+T' "$THEMES"; then
  bad "themes.md publishes a Ctrl+Shift+T shortcut; no such handler exists in the frontend"
else
  ok "themes.md publishes no keyboard shortcut for theme cycling"
fi

# Card Depth was four operator-facing levels for a fixed stylesheet treatment.
if grep -qiE '^\s*[-*]?\s*\*\*(Flat|Subtle|Raised|Elevated)\*\*' "$THEMES"; then
  bad "themes.md still documents an adjustable Card Depth control, which the panel has no setting for"
else
  ok "themes.md documents no Card Depth control"
fi

echo
echo "── 3. the secrets guide publishes no CLI the CLI does not have ──"

CLI_SRC="panel/go/internal/cli panel/go/cmd/dockpanel"
# shellcheck disable=SC2086
CLI_SECRET_HITS=$(grep -ric --include=*.go --exclude=*_test.go 'secret' $CLI_SRC 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
CLI_FN=$(grep -c '^func ' panel/go/internal/cli/cli.go 2>/dev/null)
if [ "${CLI_FN:-0}" -ge 1 ]; then
  ok "CLI source is readable (control: internal/cli/cli.go matches 'func ')"
else
  bad "positive control failed — cannot read panel/go/internal/cli/cli.go, so the arm below proves nothing"
fi
DOC_CLI=$(grep -c 'dockpanel secrets' "$SECRETS")
if [ "$DOC_CLI" -eq 0 ]; then
  ok "secrets.md publishes no 'dockpanel secrets' command (the CLI has no secrets subcommand)"
elif [ "${CLI_SECRET_HITS:-0}" -gt 0 ]; then
  ok "secrets.md publishes $DOC_CLI CLI example(s) and the CLI source does mention secrets"
else
  bad "secrets.md publishes $DOC_CLI 'dockpanel secrets' command(s); the CLI source mentions 'secret' $CLI_SECRET_HITS times"
fi

# The inject endpoint is site-scoped. A guide that omits the site makes the
# reader build a 404, which is how this one read for its whole life.
if grep -qF 'inject/{site_id}' "$SECRETS"; then
  ok "secrets.md documents the inject endpoint with its site segment"
else
  bad "secrets.md documents an inject endpoint without /{site_id} — the router has no such route"
fi

# There is no rollback handler in rt_secrets.go; the version list returns
# metadata only, so an old value cannot even be read back.
if grep -qiE 'roll ?back to a previous version' "$SECRETS"; then
  bad "secrets.md offers rolling back to a previous secret version; no such endpoint exists"
else
  ok "secrets.md does not promise version roll-back"
fi

echo
echo "── 4. a guide that sends the operator to a screen names one that exists ──"

# The endpoint is real and admin-gated; what does not exist is a panel screen.
# So the pin is the PAIR: the docs may name the screen only if something calls it.
SUBS_CALLERS=$(grep -rl 'status-page/subscribers' panel/frontend/src panel/go/internal/cli 2>/dev/null | wc -l)
SUBS_DOC=$(grep -lE '\*\*Status Page\*\* > \*\*Subscribers\*\*' "$STATUSPAGE" "$INCIDENTS" 2>/dev/null | wc -l)
# Control: the frontend really is greppable for sibling status-page calls.
SUBS_CONTROL=$(grep -rl 'status-page' panel/frontend/src 2>/dev/null | wc -l)
if [ "$SUBS_CONTROL" -ge 1 ]; then
  ok "frontend is greppable for status-page callers (control: $SUBS_CONTROL file(s))"
else
  bad "positive control failed — no status-page reference anywhere in the frontend"
fi
if [ "$SUBS_DOC" -eq 0 ] || [ "$SUBS_CALLERS" -gt 0 ]; then
  ok "no guide sends the operator to a Subscribers screen the panel does not render"
else
  bad "$SUBS_DOC guide(s) name a 'Status Page > Subscribers' screen, but no frontend or CLI file calls that endpoint"
fi

# Per-type notification preferences have no screen and no schema.
if grep -qE '\*\*Settings\*\* > \*\*Notifications\*\*' "$NOTIFS"; then
  bad "notifications.md sends the operator to Settings > Notifications, which is not a tab in Settings.tsx"
else
  ok "notifications.md does not send the operator to a Settings > Notifications screen"
fi

# It should still point somewhere real, or the correction is just a deletion.
if grep -qF 'Alert Channels' "$NOTIFS" && grep -qF 'Alert Channels' "$SETTINGS"; then
  ok "notifications.md points at Settings > Alert Channels, which Settings.tsx does render"
else
  bad "notifications.md no longer names a real destination for suppressing external notifications"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
