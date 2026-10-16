-- TCP proxies terminated by the host nginx stream module: database remote
-- access (kind='database') and operator-defined generic forwards
-- (kind='generic').
--
-- Server-scoped like every other managed resource: listen ports are a
-- per-host pool, so uniqueness is (server_id, …) — two tenants on different
-- boxes may legitimately use the same port number. database_id gets its own
-- concrete FK column (never a polymorphic owner pair), matching how
-- databases.stack_id was added, so ON DELETE CASCADE keeps expressing "the
-- proxy dies with the database".

CREATE TABLE IF NOT EXISTS tcp_proxies (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id      UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id        UUID NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    database_id    UUID REFERENCES databases(id) ON DELETE CASCADE,
    certificate_id UUID REFERENCES tls_certificates(id) ON DELETE SET NULL,
    name           VARCHAR(48) NOT NULL,
    kind           TEXT NOT NULL DEFAULT 'generic' CHECK (kind IN ('generic', 'database')),
    listen_port    INTEGER NOT NULL CHECK (listen_port BETWEEN 40000 AND 44999),
    upstream_host  TEXT NOT NULL,
    upstream_port  INTEGER NOT NULL CHECK (upstream_port BETWEEN 1 AND 65535),
    tls            BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (server_id, name),
    UNIQUE (server_id, listen_port)
);
CREATE INDEX IF NOT EXISTS idx_tcp_proxies_server ON tcp_proxies(server_id);
CREATE INDEX IF NOT EXISTS idx_tcp_proxies_user   ON tcp_proxies(user_id);

-- One remote-access proxy per database, enforced rather than assumed:
-- without this, two enables racing on the same row would both write a
-- stream file and the second would clobber the first silently.
CREATE UNIQUE INDEX IF NOT EXISTS tcp_proxies_database_unique
    ON tcp_proxies(database_id) WHERE database_id IS NOT NULL;
