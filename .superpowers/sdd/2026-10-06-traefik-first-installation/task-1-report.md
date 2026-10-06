# Task 1 report

Status: DONE

## Changed files

- `scripts/setup.sh`: added the installation marker path, fresh-install `traefik` default, validated mode helpers, and explicit marker writer.
- `scripts/update.sh`: added marker reading with invalid/missing fallback to legacy `nginx` before update service changes.
- `tests/traefik-first-install-pin-e2e.sh`: added offline source compatibility assertions.

## Verification

- `bash -n scripts/setup.sh` — PASS
- `bash -n scripts/update.sh` — PASS
- `bash tests/traefik-first-install-pin-e2e.sh` — PASS (14 assertions)
- `git diff --check` — PASS

## Self-review

The setup marker reader uses a guarded two-step command substitution so unreadable marker paths do not abort under `set -e`; update mode detection remains independent of Docker/service presence. The focused test is source-only and does not touch `/etc` or require root.

## Concerns

None.

Commit: `3b5b1751`

---

# Task 1 fix report (review findings)

Status: DONE

Task 1's implementation was cherry-picked from `feat/traefik-first-installation`
(`1d069618`) into a fresh worktree off `main`, then the five review findings
were addressed.

## Findings addressed

1. **update.sh stdout pollution** — `installation_mode()` called `warn`, which
   writes to stdout, so `$(installation_mode)` captured the warning plus the
   mode and `is_legacy_nginx_install()` returned false on markerless installs.
   Fixed by redirecting the warning to stderr (`... >&2`). stdout is now exactly
   the mode.
2. **Behavioral assertion** — added to `tests/traefik-first-install-pin-e2e.sh`:
   extracts `installation_mode`/`is_legacy_nginx_install` from update.sh into a
   subshell with a `mktemp -d` marker path that does not exist, stubs `warn`,
   runs under `set -euo pipefail`, and asserts stdout is exactly `nginx` and
   `is_legacy_nginx_install` succeeds. Offline; no `/etc`; no root; no
   update.sh top-level side effects (functions extracted with `sed`, not
   sourced).
3. **setup.sh contradictory fallback** — the helper's fallback arm read
   `${INSTALLATION_MODE:-nginx}` (defaulting to legacy) while the comment and
   the fresh-install default are `traefik`, and the matched arm then expanded
   the raw `$INSTALLATION_MODE`, aborting under `nounset` when unset. Fixed by
   hoisting `local mode="${INSTALLATION_MODE:-traefik}"` and using `$mode`
   throughout; consistent fresh default and nounset-safe.
4. **Brittle whole-file `docker ps` pin** — replaced with a check scoped to the
   two mode helpers: their bodies are extracted and asserted to contain no
   `docker`/`systemctl`/`podman` reference. Preserves the no-inference contract
   without blocking legitimate container/service code elsewhere in update.sh.
5. **Trailing newline** — added to `tests/traefik-first-install-pin-e2e.sh`.

## Verification

- `bash -n scripts/setup.sh` — PASS
- `bash -n scripts/update.sh` — PASS
- `bash -n tests/traefik-first-install-pin-e2e.sh` — PASS
- `bash tests/traefik-first-install-pin-e2e.sh` — PASS: 16   FAIL: 0
- `git diff --check` — PASS (clean)

## Concerns

None.
