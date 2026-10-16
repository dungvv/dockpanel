-- Per-site SFTP accounts (GH #108).
--
-- sftp_enabled: opt-in per site, never automatic — enabling it is the one
-- controlled moment DockPanel is allowed to re-own an existing site's content
-- directory (see panel/agent/src/services/sftp_accounts.rs).
--
-- sftp_uid/sftp_gid: allocated once, on enable, from a real sequence rather
-- than a MAX(sftp_uid)+1 query — the latter has a genuine TOCTOU race under
-- concurrent enables (two transactions can read the same MAX before either
-- commits), where a sequence's nextval() is atomic by construction and needs
-- no row locking. Starts at 30000, clear of both normal user uids and the
-- vmail/www-data system range, and is never reused after disable, so a stale
-- reference can never silently resolve to a different site's now-recycled
-- id. The SAME allocated number serves as both uid and gid — a standard
-- "user private group" convention, and it removes any need to reason about
-- uid/gid numeric collision with each other.
CREATE SEQUENCE IF NOT EXISTS sftp_id_seq START WITH 30000;

ALTER TABLE sites ADD COLUMN IF NOT EXISTS sftp_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS sftp_uid INT;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS sftp_gid INT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_sftp_uid ON sites(sftp_uid) WHERE sftp_uid IS NOT NULL;

-- Deliberately NO password column. Setting a Linux account's password
-- (a `usermod -p <hash>` the agent runs as root) needs no PRIOR password,
-- unlike Postgres/MySQL's ALTER USER — so there is nothing for the panel to
-- hold between resets. Every reset generates fresh, sets it via the agent,
-- returns it to the operator once, and stores nothing at all.
