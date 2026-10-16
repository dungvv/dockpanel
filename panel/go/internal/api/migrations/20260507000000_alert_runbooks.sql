-- Phase 4 W2: Alert runbooks (per-type markdown attached to fired alerts).
-- Indexed by alert_type (TEXT PK, not FK — alert_type is a free string today).
-- Operator edits survive panel upgrades by construction (apply-defaults uses
-- ON CONFLICT DO NOTHING — never overwrites). DELETE = restore default.

CREATE TABLE IF NOT EXISTS alert_runbooks (
    alert_type TEXT PRIMARY KEY,
    runbook_md TEXT NOT NULL,
    severity_default TEXT NOT NULL CHECK (severity_default IN ('info', 'warning', 'critical')),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
