-- Escalation sweep support (s251).
--
-- `check_escalations` runs every 60 seconds over the firing, unacknowledged
-- alerts, ordered least-recently-paged first. Its predicate (status +
-- acknowledged_at) matches none of the existing indexes: idx_alerts_user_status
-- leads with user_id, which the sweep does not filter on. A partial index on the
-- exact predicate, keyed by the sweep's ORDER BY expression, keeps the bounded
-- LIMIT query cheap no matter how many resolved or acknowledged rows accumulate
-- around it.
--
-- COALESCE over two immutable timestamptz columns is itself immutable, so it is
-- a legal index expression.
CREATE INDEX IF NOT EXISTS idx_alerts_escalation_sweep
    ON alerts (COALESCE(escalated_at, created_at))
    WHERE status = 'firing' AND acknowledged_at IS NULL;
