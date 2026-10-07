#!/usr/bin/env bash
# Pins for nginx stream (TCP proxy) support — module install, the top-level
# `stream {}` include in nginx.conf, and the managed stream directory.
#
# These do NOT need a running panel or root: the include-insertion helper is
# extracted and run against fixtures that reproduce Debian and RHEL
# nginx.conf layouts. Offline; no /etc writes.
#
#   run: bash tests/nginx-stream-pin-e2e.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SETUP="$REPO/scripts/setup.sh"
UPDATE="$REPO/scripts/update.sh"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected [$3], got [$2])"; fi; }
assert_contains() {
    grep -Fq "$2" "$1" && ok "$3" || bad "$3 (missing '$2' in $(basename "$1"))"
}

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
AGENT_STREAM_SVC="$REPO/panel/agent/src/services/nginx_stream.rs"
AGENT_STREAM_ROUTE="$REPO/panel/agent/src/routes/nginx_stream.rs"
BACKEND_TCP="$REPO/panel/backend/src/routes/tcp_proxies.rs"
BACKEND_DB="$REPO/panel/backend/src/routes/databases.rs"
AGENT_DB_SVC="$REPO/panel/agent/src/services/database.rs"
MIGRATION="$(ls "$REPO"/panel/backend/migrations/*_tcp_proxies.sql 2>/dev/null | head -1)"

echo "── S0: files exist ──"
for f in "$AGENT_STREAM_SVC" "$AGENT_STREAM_ROUTE" "$BACKEND_TCP" "$MIGRATION"; do
    [ -n "$f" ] && [ -f "$f" ] && ok "$(basename "$f") exists" || bad "missing: $f"
done

echo "── S1: source pins ──"
assert_contains "$SETUP" 'dockpanel-streams' "setup.sh manages a stream include dir"
assert_contains "$SETUP" 'libnginx-mod-stream' "setup.sh installs the Debian stream module"
assert_contains "$SETUP" 'nginx-mod-stream' "setup.sh installs the RHEL stream module"
assert_contains "$SETUP" 'ensure_stream_include_in' "setup.sh has an extractable include helper"
assert_contains "$SETUP" 'nginx_stream_module_ready' "setup.sh gates the include on module presence"
assert_contains "$UPDATE" 'dockpanel-streams' "update.sh ensures the stream include on upgrades"
assert_contains "$UPDATE" 'ensure_stream_include_in' "update.sh shares the same include helper"
# The include must never be written when the module cannot be loaded — a
# `stream {}` block in a module-less nginx makes `stream` an unknown
# directive and the NEXT restart refuses the whole config. Both scripts must
# keep a backup+restore around the edit.
assert_contains "$SETUP" 'nginx.conf.dockpanel-stream-bak' "setup.sh keeps a rollback copy of nginx.conf"
assert_contains "$UPDATE" 'nginx.conf.dockpanel-stream-bak' "update.sh keeps a rollback copy of nginx.conf"

echo
echo "── S2: include insertion (fixture-driven, extracted from setup.sh) ──"
# Extract the helper (column-0 `}` closes the function; awk body lines are
# indented) and load it into a subshell — scripts are never sourced.
sed -n '/^ensure_stream_include_in()/,/^}/p' "$SETUP" > "$TMP/helper.sh"
if [ -s "$TMP/helper.sh" ]; then ok "helper extracted"; else bad "helper extraction produced nothing"; fi

debian_conf() {
    cat > "$1" <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

http {
    sendfile on;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
}

rhel_conf() {
    cat > "$1" <<'EOF'
user nginx;
worker_processes auto;
pid /run/nginx.pid;
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
}
EOF
}

(
    set -euo pipefail
    . "$TMP/helper.sh"

    # Debian layout: block lands before http {}, exactly once.
    debian_conf "$TMP/debian.conf"
    ensure_stream_include_in "$TMP/debian.conf"
    # RHEL layout: same.
    rhel_conf "$TMP/rhel.conf"
    ensure_stream_include_in "$TMP/rhel.conf"
    # Idempotent: second run is a no-op.
    cp "$TMP/debian.conf" "$TMP/debian.once"
    ensure_stream_include_in "$TMP/debian.conf"
    # Existing unmanaged stream block gets the include inside it.
    cat > "$TMP/existing.conf" <<'EOF'
events { worker_connections 512; }
stream {
    server { listen 9000; proxy_pass 127.0.0.1:9001; }
}
http { include /etc/nginx/conf.d/*.conf; }
EOF
    ensure_stream_include_in "$TMP/existing.conf"
    # No http anchor: append at top level.
    cat > "$TMP/nohttp.conf" <<'EOF'
user nginx;
events { worker_connections 512; }
EOF
    ensure_stream_include_in "$TMP/nohttp.conf"
)

INC='include /etc/nginx/dockpanel-streams/*.conf;'
check "debian: stream block present" \
      "$(grep -cE '^stream \{' "$TMP/debian.conf")" "1"
check "debian: include line present" \
      "$(grep -cF "$INC" "$TMP/debian.conf")" "1"
check "debian: stream block precedes http" \
      "$(awk '/^stream \{/{s=NR} /^http \{/{print (s && s<NR) ? "yes" : "no"; exit}' "$TMP/debian.conf")" "yes"
check "rhel: stream block present" \
      "$(grep -cE '^stream \{' "$TMP/rhel.conf")" "1"
check "rhel: include line present" \
      "$(grep -cF "$INC" "$TMP/rhel.conf")" "1"
check "idempotent: second run adds nothing" \
      "$(grep -cF "$INC" "$TMP/debian.conf")" "1"
check "existing stream block: include inserted inside it" \
      "$(awk '/^stream \{/{f=1; n=NR} f && /dockpanel-streams/ && NR==n+1 {print "yes"; exit}' "$TMP/existing.conf")" \
      "yes"
check "existing stream block: no second block added" \
      "$(grep -cE '^stream \{' "$TMP/existing.conf")" "1"
check "no http anchor: block appended" \
      "$(grep -cE '^stream \{' "$TMP/nohttp.conf")" "1"

echo
echo "── S3: agent service contract ──"
assert_contains "$AGENT_STREAM_SVC" 'STREAM_DIR: &str = "/etc/nginx/dockpanel-streams"' \
    "agent writes into the managed stream dir"
assert_contains "$AGENT_STREAM_SVC" 'restore_or_remove' \
    "stream writes roll back through the vhost rollback path"
assert_contains "$AGENT_STREAM_SVC" 'test_config' \
    "stream writes are gated by nginx -t"
assert_contains "$AGENT_STREAM_SVC" 'container_loopback_port' \
    "database upstreams are read off the container, not the wire"
assert_contains "$AGENT_STREAM_SVC" 'dockpanel.managed' \
    "container upstreams require the managed label"
# The render must never be reachable from the route file — routes delegate.
check "route file has no inline server block" \
      "$(grep -c 'server {' "$AGENT_STREAM_ROUTE")" "0"
assert_contains "$AGENT_STREAM_ROUTE" 'write_stream_proxy' "route delegates writes"
assert_contains "$AGENT_STREAM_ROUTE" 'firewall::add_port' "create opens the firewall port"
assert_contains "$AGENT_STREAM_ROUTE" 'firewall::remove_port' "delete closes the firewall port"

echo
echo "── S4: database remote access contract ──"
assert_contains "$AGENT_DB_SVC" 'host_ip: Some("127.0.0.1".to_string())' \
    "db containers keep loopback-only port bindings"
check "no public host_ip publish added for databases" \
      "$(cat "$AGENT_DB_SVC" "$BACKEND_DB" | grep -cE 'host_ip: Some\("0\.0\.0\.0"')" "0"
assert_contains "$BACKEND_DB" 'remote_access_enable' "backend exposes the enable endpoint"
assert_contains "$BACKEND_DB" 'remote_access_disable' "backend exposes the disable endpoint"
assert_contains "$BACKEND_DB" 'tcp_proxies' "database delete cleans up its stream proxy"
assert_contains "$MIGRATION" 'kind' "tcp_proxies records the proxy kind"
assert_contains "$MIGRATION" 'database_id' "tcp_proxies links proxies to databases"
assert_contains "$MIGRATION" 'ON DELETE CASCADE' "db delete cascades its proxy row"
assert_contains "$BACKEND_TCP" '40000' "backend enforces the managed port range"

echo
echo "── S5: TLS termination contract ──"
assert_contains "$AGENT_STREAM_ROUTE" '/etc/dockpanel/ssl-registry/' \
    "agent restricts cert paths to the managed roots"
assert_contains "$AGENT_STREAM_ROUTE" 'tls requires cert_path' \
    "tls=true refuses without certificate paths"
assert_contains "$AGENT_STREAM_SVC" 'listen {listen_port} ssl;' \
    "TLS listeners render the ssl flag on listen"
assert_contains "$AGENT_STREAM_SVC" 'ssl_certificate_key' \
    "TLS listeners reference the registry key in place"
assert_contains "$BACKEND_TCP" 'tls_certificates' \
    "backend resolves certs from the registry table"
assert_contains "$BACKEND_TCP" 'user_id = $3 OR $4' \
    "certificate lookup is caller-scoped (or admin)"
assert_contains "$REPO/panel/backend/src/routes/tls_certificates.rs" 'tcp_proxies' \
    "cert delete refuses while a stream proxy references it"
# Private key material must never be on the wire or in a log line.
check "agent never logs key paths" \
      "$(cat "$AGENT_STREAM_ROUTE" "$AGENT_STREAM_SVC" | grep -cE 'tracing::(info|warn|error)!\([^)]*key')" "0"
check "backend never sends key material to the agent" \
      "$(grep -c '"private_key"' "$BACKEND_TCP")" "0"

echo
echo "── S6: documentation contract ──"
assert_contains "$REPO/docs/guides/databases.md" 'stream' \
    "databases guide documents the stream module"
assert_contains "$REPO/docs/guides/databases.md" '40000' \
    "databases guide documents the managed port range"
assert_contains "$REPO/docs/guides/databases.md" 'loopback' \
    "databases guide documents the loopback-upstream model"
assert_contains "$REPO/docs/guides/databases.md" 'firewall' \
    "databases guide documents the firewall open/close contract"
assert_contains "$REPO/docs/api-reference.md" 'remote-access' \
    "api reference lists the remote-access endpoints"
assert_contains "$REPO/docs/api-reference.md" 'tcp-proxies' \
    "api reference lists the tcp-proxies endpoints"
assert_contains "$REPO/docs/troubleshooting.md" 'libnginx-mod-stream' \
    "troubleshooting covers the missing-module failure mode"

echo
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
[ "$FAIL" = "0" ]
