-- Allow the 'suspended' role value on users.role.
--
-- toggle_suspend sets role = 'suspended', but the reseller_system migration
-- (20260320000000) re-created chk_users_role as CHECK (role IN ('admin','reseller','user')),
-- dropping 'suspended' — so suspending ANY user failed with a check-constraint violation
-- (HTTP 500) on every install since. Widen the constraint to include 'suspended'.
--
-- Idempotent: DROP IF EXISTS then re-ADD. No existing row violates the widened set.
ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_users_role;
ALTER TABLE users ADD CONSTRAINT chk_users_role
    CHECK (role IN ('admin', 'reseller', 'user', 'suspended'));
