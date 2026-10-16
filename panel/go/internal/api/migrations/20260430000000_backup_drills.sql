-- Phase 4 W1.2: Backup drills (end-to-end restore probes).
-- Distinct from passive verifications (tar -tvf + checksum) — drills actually
-- restore into a scratch container and HTTP-probe.

CREATE TABLE IF NOT EXISTS backup_drills (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_type VARCHAR(20) NOT NULL, -- site, database, volume
    backup_id UUID NOT NULL,
    server_id UUID REFERENCES servers(id) ON DELETE SET NULL,
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending, running, passed, failed
    http_status INTEGER,
    body_excerpt TEXT,
    error_message TEXT,
    duration_ms INTEGER,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_backup_drills_target ON backup_drills(backup_type, backup_id);
CREATE INDEX IF NOT EXISTS idx_backup_drills_status ON backup_drills(status);
CREATE INDEX IF NOT EXISTS idx_backup_drills_created ON backup_drills(created_at DESC);
