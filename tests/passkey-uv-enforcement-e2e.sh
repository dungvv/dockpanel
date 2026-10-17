#!/bin/bash
# Passkey UV/2FA-skip enforcement — EXECUTE-class, needs a real PostgreSQL.
#
# This is the "virtual-authenticator harness" `tests/passkey-ceremony-pin-e2e.sh`
# §G4 named as the missing piece: a real WebAuthn client+authenticator,
# independent of the server's own code, proving end to end that a passkey
# which demonstrated user verification (PIN/biometric) at registration is
# REQUIRED to demonstrate it again at login, while a possession-only
# credential (registered before this ship, or from an authenticator that
# never verifies) is unaffected — the grandfathering guarantee.
#
# Third EXECUTE-class member of the pin family alongside nginx-headers and
# update-rollback (reference_dockpanel_ops) — needs a database, not pure
# source analysis. The virtual authenticator (once a Cargo binary driving a
# live API) is now the Go test TestDBRtPasskeysVirtualAuthenticator in
# panel/go/internal/api/rt_passkeys_test.go: it does the CBOR/ECDSA work
# against the real router in-process (httptest) over a DATABASE_URL database.
# This wrapper runs it and forwards its exit code.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=============================================="
echo "  Passkey UV enforcement (s443)"
echo "=============================================="
echo

if [ -z "${DATABASE_URL:-}" ]; then
  printf '  \033[33m~\033[0m SKIPPED — DATABASE_URL not set (the harness needs a real PostgreSQL)\n'
  echo "0 passed, 0 failed, 1 skipped"
  exit 0
fi

out=$(cd panel/go && go test ./internal/api/ -run '^TestDBRtPasskeysVirtualAuthenticator$' -count=1 -v 2>&1)
rc=$?
echo "$out" | tail -20
if [ $rc -eq 0 ] && grep -q -- '--- PASS: TestDBRtPasskeysVirtualAuthenticator' <<<"$out"; then
  printf '  \033[32m✓\033[0m virtual authenticator: UV enforced, possession-only grandfathered\n'
  echo "1 passed, 0 failed"
  exit 0
fi
printf '  \033[31m✗\033[0m virtual authenticator harness failed (rc=%s)\n' "$rc"
echo "0 passed, 1 failed"
exit 1
