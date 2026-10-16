-- MCP server prep (design: /home/ovidiu/dockpanel-mcp-design.md §5, §4).
--
-- Today an action authenticated with a `dp_` API key is indistinguishable from
-- a browser session in both audit tables — `authenticate_api_key()` (auth.rs)
-- looks up `api_keys.id`, uses it once to bump `last_used_at`, and discards it.
-- Once an MCP tool call (or the CLI) writes through the same routes a human
-- click does, "who did this" needs an answer sqlx can't currently give. Adding
-- the column now, before any MCP tool exists, means v1.1's first mutating tool
-- ships with real attribution from its first call instead of retrofitting one
-- after routes have shipped assuming "human via browser".

ALTER TABLE activity_logs
    ADD COLUMN IF NOT EXISTS api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_activity_logs_api_key ON activity_logs(api_key_id);

ALTER TABLE security_audit_log
    ADD COLUMN IF NOT EXISTS api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_security_audit_log_api_key ON security_audit_log(api_key_id);

-- security_audit_log.actor_email is a free-text string with no FK to `users` —
-- unlike activity_logs.user_id, a row here is only as trustworthy as whatever
-- string the caller passed. Adding a real FK alongside the free-text field
-- (kept for the pre-account/failed-login rows that have no user to name) means
-- a future MCP audit query can join on identity instead of matching on email.
ALTER TABLE security_audit_log
    ADD COLUMN IF NOT EXISTS actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_security_audit_log_actor_user ON security_audit_log(actor_user_id);

-- Scopes column for API keys, added proactively (Ovidiu, s485) so v1.1's
-- mutating-tool tier doesn't reopen a migration on a table every key-minting
-- flow already touches. NULL = unrestricted (today's all-or-nothing behavior,
-- unchanged for every existing key). Same shape as the sibling
-- iac_tokens.scopes (20260328950000_terraform_autoscaling.sql). Unenforced in
-- v1 — no mutating MCP tool exists yet to gate.
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS scopes TEXT;
