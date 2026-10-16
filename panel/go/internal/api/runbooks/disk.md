# Disk usage high

A filesystem is above the configured threshold (default 85%) and trending toward full.

## Why this fired

The agent samples `df` every minute. Disk-full is uniquely bad — postgres halts, nginx can't write logs, builds fail, panel can't write its own audit log. Catching it at 85% gives time to remediate before that cascade.

## First check

1. From the panel: **System → Disk** for which mount triggered.
2. From the host:
   ```
   df -h
   du -h --max-depth=1 / 2>/dev/null | sort -h | tail -10
   du -h --max-depth=1 /var | sort -h | tail -10
   ```
3. The panel auto-healer can clear `/tmp` and rotate logs — check **System → Auto-healer → Recent actions** before manual cleanup.

## Common causes

- `/var/log` filled by unrotated logs (check `logrotate -d /etc/logrotate.conf`)
- `/var/lib/docker` overlay images and dead containers (`docker system prune -af`)
- Old backups not pruned (retention policy too generous)
- `/var/lib/dockpanel/scanners/` syft+grype databases (auto-healer manages this)
- Database growth (slow query logs, audit logs, abandoned sessions)
- Customer site pile-up (tarballs, stale staging environments)

## Escalation

Wake a human at 95% — that's the cliff where postgres refuses writes and the cascade starts. Prefer expanding the volume to deleting customer data. Ad-hoc deletion of files you don't fully understand is how restoration days happen.
