-- Per-site monthly bandwidth accounting + quota enforcement (GH #84).
--
-- bandwidth_quota_mb: NULL = unlimited (the default for every existing site —
-- this feature is opt-in per site, never a silent cap). bandwidth_suspended_at
-- is set the moment traffic_accounting_scheduler auto-disables a site for
-- exceeding its quota, and is the ONLY thing distinguishing an auto-suspension
-- from a manual one: a human re-enabling via the existing toggle clears it, and
-- the scheduler itself clears it (and re-enables) once a new calendar month
-- starts or the quota is raised/removed. `enabled` alone can't carry this
-- distinction — a manually-disabled site would otherwise get swept into the
-- auto-recovery check too.
ALTER TABLE sites ADD COLUMN IF NOT EXISTS bandwidth_quota_mb INT;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS bandwidth_suspended_at TIMESTAMPTZ;

-- Read-checkpoint for the agent's access-log byte offset, one row per site.
-- Rotation crosses an inode change (this box's logrotate uses `create` mode,
-- not `copytruncate`) — the agent's delta endpoint keys off log_inode, not just
-- log_size, so a same-size coincidence right after rotation can't be mistaken
-- for "no new traffic".
CREATE TABLE IF NOT EXISTS site_traffic_offsets (
    site_id UUID PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    log_inode BIGINT NOT NULL,
    log_size BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The durable monthly accumulator. One row per site per UTC calendar month
-- ('YYYY-MM'); bytes_used only ever grows within a month, via the scheduler's
-- periodic delta collection — a fresh month starts a fresh row rather than
-- resetting one in place, so history survives.
CREATE TABLE IF NOT EXISTS site_traffic_usage (
    site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    year_month TEXT NOT NULL,
    bytes_used BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (site_id, year_month)
);
