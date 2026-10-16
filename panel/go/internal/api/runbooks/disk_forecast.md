# Disk fill forecast

Disk usage trend over the last 6 hours predicts full within the configured forecast window (default 24h). This is an early warning, not an emergency yet.

## Why this fired

The agent fits a linear regression on disk usage samples and projects forward. If current usage > 60% AND projected usage at horizon ≥ 100%, the alert fires. The intent is "remediate during business hours, before it pages at 3am."

## First check

1. From the panel: **System → Disk → Forecast** to see the projected fill curve.
2. Identify what's growing fastest:
   ```
   du -h --max-depth=2 /var | sort -h | tail -20
   find /var/log -size +100M -exec ls -lh {} \;
   ```
3. Check whether the trend is one-shot (a backup ran) or continuous (organic growth).

## Common causes

- Organic database growth (largest table needs archive/partition)
- Log rotation paused or broken
- Backup retention policy needs tightening
- Docker images accumulating without prune schedule
- A new customer onboarded recently with high storage demand

## Escalation

This is a warning, not a page. Plan remediation during business hours. If the forecast is <6h until full, treat it as the `disk` runbook (page-grade). Otherwise file as a ticket and address by end of shift.
