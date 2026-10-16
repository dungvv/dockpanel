-- Site backups can now carry their databases (v2.34.0).
--
-- A backup row has to be able to answer "does this archive contain my content?"
-- long after it was made. `databases_expected` is how many databases the site
-- had when the backup ran; `databases_included` is how many are actually inside
-- the archive. They differ when a dump failed.
--
-- Every pre-existing row defaults to 0/0, which is exactly true of it: archives
-- made before this migration contain files only, and nothing promised otherwise.
ALTER TABLE backups ADD COLUMN IF NOT EXISTS databases_included INT NOT NULL DEFAULT 0;
ALTER TABLE backups ADD COLUMN IF NOT EXISTS databases_expected INT NOT NULL DEFAULT 0;
