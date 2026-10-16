-- v2.8.2: extend chain-of-trust integrity hashes to db + volume backups.
-- Mirrors the 20260324000000 site-backup columns. Single transaction so a
-- partial apply can't leave one table chained and the other not.

BEGIN;

ALTER TABLE database_backups ADD COLUMN IF NOT EXISTS sha256_hash VARCHAR(64);
ALTER TABLE database_backups ADD COLUMN IF NOT EXISTS previous_hash VARCHAR(64);
ALTER TABLE database_backups ADD COLUMN IF NOT EXISTS chain_valid BOOLEAN DEFAULT TRUE;

ALTER TABLE volume_backups ADD COLUMN IF NOT EXISTS sha256_hash VARCHAR(64);
ALTER TABLE volume_backups ADD COLUMN IF NOT EXISTS previous_hash VARCHAR(64);
ALTER TABLE volume_backups ADD COLUMN IF NOT EXISTS chain_valid BOOLEAN DEFAULT TRUE;

COMMIT;
