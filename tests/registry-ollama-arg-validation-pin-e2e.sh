#!/usr/bin/env bash
# registry-ollama-arg-validation-pin-e2e.sh — s439
#
# Pins the agent docker_apps registry_login/ollama_pull/ollama_delete finding
# (now panel/go/internal/agent/routes/docker_apps.go: dockerAppsRegistryLogin,
# dockerAppsRegistryLogout, dockerAppsOllamaPull/Delete via dockerAppsOllamaModel)
# named in [[project_dockpanel_tech_debt_p4]] (long-standing INFO carry: "exec
# denylist substring theater... registry_login/ollama_pull accept an
# arbitrary host") and confirmed still open at HEAD (v2.194.0, ab9a205)
# before this fix. Same DiD shape as the s438 nginx.rs/remote_backup.rs
# closure ([[project_dockpanel_tech_debt_p176]]): every one of these 4
# handlers passes an admin-supplied string straight into a `docker`/`ollama`
# CLI argument via `safe_command(...).args([...])` (no shell, so classic `;`/
# `|` injection is not reachable — args() passes each token verbatim), but
# `safe_command` does nothing to stop the string ITSELF being read as a CLI
# FLAG when it lands in argv right where a flag is expected.
#
#   §A registry_login had ZERO format validation on `body.server` (only an
#      emptiness check) before `docker login <server> -u <user>
#      --password-stdin` — a server starting with `-` is parsed by docker's
#      own arg parser as an option in that position, not the registry host.
#   §B registry_logout had the identical gap on `server` before `docker
#      logout <server>`.
#   §C/§D ollama_pull_model/ollama_delete_model already validated length and
#      character class, but neither rejected a LEADING `-` before `docker
#      exec <container_id> ollama pull/rm <model>` — the same argv-position
#      hazard, just missing the one guard `is_valid_image_ref` (used a few
#      hundred lines away for `change_image`'s `image` field, the established
#      sibling for this exact threat class in this same file) already has.
#
# The fix for §A/§B reuses `is_valid_image_ref` directly (same file, same
# crate, matching the fix-precedent of reusing an existing sibling validator
# instead of inventing a near-duplicate one) rather than a fresh domain
# validator, because a registry server is commonly `host:port` or a bare
# single-label host (`localhost:5000`) — shapes `is_valid_domain` (which
# requires a dot and rejects `:`) would incorrectly reject.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=============================================="
echo "  agent docker_apps registry/ollama arg validation — source pins (s439)"
echo "=============================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

# Strip comments before matching (per [[feedback_source_pin_prose_trap]] —
# this file's own header spells the tokens the arms grep for). Go comments:
# `/* */` blocks on their own lines, whole-line `//`, and trailing `//`
# (only when preceded by whitespace, so `https://` in a literal survives).
code() {
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^[ \t]*//.*$}{}gm;
    s{[ \t]+//[^"`\n]*$}{}gm;
  ' "$1"
}

has()  { grep -qE -- "$2" <<< "$1"; }
flat() { tr '\n' ' ' <<< "$1" | tr -s ' '; }

# One Go func (or method) body, bounded by its own closing `}` at column 0 —
# a window ending at the successor's match position swallows the next
# function's declaration (s323).
fnbody() {
  awk -v fn="$2" '
    !started && (index($0, "func " fn "(") == 1 || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) {
      started=1; print
      o=gsub(/\{/,"{"); c=gsub(/\}/,"}"); if (o>0 && o==c) exit
      next
    }
    started { print; if ($0 == "}") exit }
  ' <<< "$1"
}

APPS=panel/go/internal/agent/routes/docker_apps.go
[ -f "$APPS" ] || { bad "SETUP subject missing: $APPS"; exit 1; }
APPS_SRC=$(code "$APPS")

# ── §A  registry_login validates body.Server before `docker login` ──────────

LOGIN=$(flat "$(fnbody "$APPS_SRC" "dockerAppsRegistryLogin")")
if [ -z "$LOGIN" ]; then
  bad "A0 could not extract dockerAppsRegistryLogin"
else
  ok "A0 dockerAppsRegistryLogin extracted"
  # A1 retired: covered by TestDockerAppsRoutesValidateBeforeActing (panel/go/internal/agent/routes/docker_apps_test.go)
  CHK_AT=$(grep -bo 'dockerAppsIsValidImageRef(body.Server)' <<< "$LOGIN" | head -1 | cut -d: -f1)
  SPAWN_AT=$(grep -bo '"login"' <<< "$LOGIN" | head -1 | cut -d: -f1)
  if [ -n "$CHK_AT" ] && [ -n "$SPAWN_AT" ] && [ "$CHK_AT" -lt "$SPAWN_AT" ]; then
    ok "A2 the dockerAppsIsValidImageRef(body.Server) validation precedes the docker login spawn"
  else
    bad "A2 the validation does not precede the docker login spawn (check@${CHK_AT:-none} spawn@${SPAWN_AT:-none})"
  fi
fi

# ── §B  registry_logout validates server before `docker logout` ─────────────

LOGOUT=$(flat "$(fnbody "$APPS_SRC" "dockerAppsRegistryLogout")")
if [ -z "$LOGOUT" ]; then
  bad "B0 could not extract dockerAppsRegistryLogout"
else
  ok "B0 dockerAppsRegistryLogout extracted"
  # B1 retired: covered by TestPinRegistryOllamaArgValidationLogoutRefusesALeadingDash (panel/go/internal/agent/routes/pin_registry_ollama_arg_validation_test.go)
  CHK_AT=$(grep -bo 'dockerAppsIsValidImageRef(server)' <<< "$LOGOUT" | head -1 | cut -d: -f1)
  SPAWN_AT=$(grep -bo '"logout"' <<< "$LOGOUT" | head -1 | cut -d: -f1)
  if [ -n "$CHK_AT" ] && [ -n "$SPAWN_AT" ] && [ "$CHK_AT" -lt "$SPAWN_AT" ]; then
    ok "B2 the dockerAppsIsValidImageRef(server) validation precedes the docker logout spawn"
  else
    bad "B2 the validation does not precede the docker logout spawn (check@${CHK_AT:-none} spawn@${SPAWN_AT:-none})"
  fi
fi

# ── §C/§D  both ollama handlers route the model through the shared guard ────
# In Go the leading-'-' refusal lives in ONE helper (dockerAppsOllamaModel)
# both handlers call; what the arms pin is that each handler reaches it before
# its spawn. The refusal itself is a test: C1/D1 behaviour retired: covered by
# TestPinRegistryOllamaArgValidationModelRefusesALeadingDash (panel/go/internal/agent/routes/pin_registry_ollama_arg_validation_test.go)

for pair in "C:dockerAppsOllamaPull:pull" "D:dockerAppsOllamaDelete:rm"; do
  id=${pair%%:*}; rest=${pair#*:}; fn=${rest%%:*}; verb=${rest#*:}
  BODY=$(flat "$(fnbody "$APPS_SRC" "$fn")")
  if [ -z "$BODY" ]; then
    bad "${id}0 could not extract $fn"
    continue
  fi
  ok "${id}0 $fn extracted"
  CHK_AT=$(grep -bo 'dockerAppsOllamaModel(w, r)' <<< "$BODY" | head -1 | cut -d: -f1)
  SPAWN_AT=$(grep -bo "\"ollama\", \"$verb\"" <<< "$BODY" | head -1 | cut -d: -f1)
  if [ -n "$CHK_AT" ] && [ -n "$SPAWN_AT" ] && [ "$CHK_AT" -lt "$SPAWN_AT" ]; then
    ok "${id}1 $fn validates the model through dockerAppsOllamaModel before the ollama $verb spawn"
  else
    bad "${id}1 $fn does not route the model through dockerAppsOllamaModel before 'ollama $verb' (check@${CHK_AT:-none} spawn@${SPAWN_AT:-none}) — a model starting with '-' is parsed as a flag"
  fi
done

# ── §E  remove_image rejects a leading '-' in the image id (s447) ──────────
# Same threat class, same file, different call: the charset check at
# `remove_image` allowed every character `docker rmi --help` needs, so
# `DELETE /apps/images/--help` ran that flag and returned success:true with
# no guard at all — 0 hits for `rmi` in this suite before the fix.
# [[project_dockpanel_tech_debt_p185]] §D.

REMOVE_IMG=$(flat "$(fnbody "$APPS_SRC" "dockerAppsRemoveImage")")
if [ -z "$REMOVE_IMG" ]; then
  bad "E0 could not extract dockerAppsRemoveImage"
else
  ok "E0 dockerAppsRemoveImage extracted"
  # E1 retired: covered by TestDockerAppsRoutesValidateBeforeActing (panel/go/internal/agent/routes/docker_apps_test.go)
  CHK_AT=$(grep -bo '!strings.HasPrefix(id, "-")' <<< "$REMOVE_IMG" | head -1 | cut -d: -f1)
  SPAWN_AT=$(grep -bo '"rmi"' <<< "$REMOVE_IMG" | head -1 | cut -d: -f1)
  if [ -n "$CHK_AT" ] && [ -n "$SPAWN_AT" ] && [ "$CHK_AT" -lt "$SPAWN_AT" ]; then
    ok "E2 the leading-'-' validation precedes the docker rmi spawn"
  else
    bad "E2 the validation does not precede the docker rmi spawn (check@${CHK_AT:-none} spawn@${SPAWN_AT:-none})"
  fi
fi

# ── §F  prune_images_all never widens to -a (s449) ──────────────────────────
# Different threat class from §A-E (not an argv-injection guard) but same
# file, same "an admin-reachable docker verb takes an unsafe flag" shape:
# `-a` on `image prune` reaches every image not backing a running container,
# not just dangling ones — including git-deploy rollback targets
# (`dockpanel-git-<name>:<hash>`, no pull fallback) and manual snapshots
# (`dockpanel-snapshot:*`), neither re-pullable. The project's own C4 rule
# for the UNATTENDED reclaim (`tests/unattended-host-scope-pin-e2e.sh`)
# already forbids this; this handler is the MANUAL button and had no such
# guard. [[project_dockpanel_tech_debt_p185]] §E.

PRUNE=$(flat "$(fnbody "$APPS_SRC" "dockerAppsPruneImages")")
if [ -z "$PRUNE" ]; then
  bad "F0 could not extract dockerAppsPruneImages"
else
  ok "F0 dockerAppsPruneImages extracted"
  # Positive anchor first: the absence below is only meaningful if the spawn
  # this arm reads is really there.
  if has "$PRUNE" '"image", *"prune", *"-f"'; then
    ok "F0b the docker image prune spawn is present in the handler"
  else
    bad "F0b no 'docker image prune' spawn found — F1's absence check reads nothing"
  fi
  if has "$PRUNE" '"image", *"prune", *"-af"|"image", *"prune", *"-a"|"--all"'; then
    bad "F1 dockerAppsPruneImages passes -a — it can remove a locally built image with no registry to restore from"
  else
    ok "F1 dockerAppsPruneImages never passes -a"
  fi
  if has "$PRUNE" 'label!=dockpanel\.managed=true'; then
    ok "F2 dockerAppsPruneImages filters on the same dockpanel.managed label as the scoped reclaim"
  else
    bad "F2 dockerAppsPruneImages has no label filter — diverges from the scoped reclaim's own C4 precedent"
  fi
fi

echo
echo "----------------------------------------------"
printf '  PASS %d  FAIL %d\n' "$PASS" "$FAIL"
echo "----------------------------------------------"
echo

[ "$FAIL" -eq 0 ] || exit 1
exit 0
