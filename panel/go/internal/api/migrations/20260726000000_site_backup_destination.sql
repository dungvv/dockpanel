-- Site backups gain the off-site columns the other two backup tables already had.
--
-- `database_backups` and `volume_backups` were created (20260322000000) with
-- `destination_id` + `uploaded`, and the All-Backups view renders a "remote" badge
-- from `uploaded`. `backups` — site file backups, the oldest table — never got
-- them, so the union in routes/backup_orchestrator.rs hardcoded
-- `FALSE AS uploaded` for every site row.
--
-- That was harmless while the backup policy executor ignored its destination
-- entirely. Now that it uploads, a site backup pushed off-site would still have
-- reported itself as local-only — replacing one silent lie with another.

ALTER TABLE backups ADD COLUMN IF NOT EXISTS destination_id UUID REFERENCES backup_destinations(id) ON DELETE SET NULL;
ALTER TABLE backups ADD COLUMN IF NOT EXISTS uploaded BOOLEAN NOT NULL DEFAULT FALSE;
