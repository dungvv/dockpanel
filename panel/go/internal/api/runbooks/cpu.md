# CPU usage high

CPU utilization on the server is above the configured threshold (default 80%) sustained over the alert window.

## Why this fired

The agent samples `/proc/stat` every 10s. Sustained high CPU rarely indicates a hardware issue — it usually means a runaway process, a backup job overlap, or organic traffic growth that needs a capacity decision.

## First check

1. From the panel: **System → Processes** sorted by CPU descending.
2. From the host:
   ```
   top -b -n 1 | head -20
   ps -eo pid,pcpu,pmem,comm --sort=-pcpu | head -20
   uptime  # load average over 1/5/15 min
   ```
3. Check if a backup or cron job is running concurrently with traffic peak (**Backup Orchestrator → Schedule** + `crontab -l`).

## Common causes

- Cron job overlap (last run hasn't finished when next run starts)
- PHP-FPM under load — too few workers queues requests, too many starves CPU
- Runaway log shipper or filebeat-style agent on a chatty path
- Crypto-miner intrusion (check unfamiliar binaries in `/tmp`, `/var/tmp`)
- Organic traffic growth — site needs scale-up
- nice 0 build process competing with serving traffic

## Escalation

Wake a human if CPU stays pinned >95% for >15 min with no identified culprit. Consider scaling up or temporarily blocking the abusive client (`fail2ban-client status nginx-limit-req`). For sustained organic growth, plan capacity in business hours — not a 3am page.
