# Backup failure

A scheduled backup did not complete successfully. The most recent run for this policy reported `failed`.

## Why this fired

The backup-policy executor ran the schedule and either the agent reported a non-zero exit code, the destination upload failed, or a verification step (sha256 chain) detected drift. Failed backups silently accumulate risk — every day without a fresh artifact is a day closer to a recovery scenario you can't recover from.

## First check

1. From the panel: **Backup Orchestrator → Failures tab → click the failed run** to see the error excerpt.
2. From the host:
   ```
   journalctl -u dockpanel-agent --since "1 hour ago" | grep -i backup
   df -h /var/backups
   ls -lh /var/backups/dockpanel/
   ```
3. If the destination is remote (S3 / B2 / SSH), test creds independently — the agent rotates short-lived tokens and a stale config is the most common silent failure.

## Common causes

- Local disk full at `/var/backups` (tar fails at 100% disk)
- Remote credentials expired or rotated
- Network partition between host and remote destination
- Database password changed but not updated in the backup policy
- Source path no longer exists (site was renamed/deleted but policy still targets it)
- Permission denied on a file the policy is trying to read

## Escalation

Wake a human if a customer-tier site has gone >24h without a successful backup. Run **Backup Orchestrator → "Run drill"** on the most recent successful artifact to confirm it still restores cleanly while you remediate.
