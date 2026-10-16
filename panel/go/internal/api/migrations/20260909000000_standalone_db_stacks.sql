-- Let a database be owned by a Docker Stack instead of a Site (GH #64).
--
-- databases.site_id was NOT NULL end-to-end, so a plain Docker Stack (no
-- `sites` row) could never get a panel-managed database. Add a second,
-- mutually-exclusive owner column rather than a generic owner_type/owner_id
-- pair — every other multi-owner-shaped table in this codebase uses concrete
-- nullable FK columns + a CHECK, never a polymorphic pair, and this keeps
-- ON DELETE CASCADE expressible (a stack's databases die with the stack).
ALTER TABLE databases ALTER COLUMN site_id DROP NOT NULL;
ALTER TABLE databases ADD COLUMN stack_id UUID REFERENCES docker_stacks(id) ON DELETE CASCADE;

ALTER TABLE databases ADD CONSTRAINT chk_databases_owner CHECK (
    (site_id IS NOT NULL AND stack_id IS NULL) OR (site_id IS NULL AND stack_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_databases_stack_id ON databases(stack_id);

-- Name uniqueness parallel to the existing databases_site_name_unique(site_id, name).
-- Postgres treats NULL as distinct in a UNIQUE constraint, so site-owned rows
-- (stack_id IS NULL) never collide with each other under this one, and vice versa.
ALTER TABLE databases ADD CONSTRAINT databases_stack_name_unique UNIQUE(stack_id, name);
