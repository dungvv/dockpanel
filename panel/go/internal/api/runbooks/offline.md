# Server offline

The server stopped checking in with the panel. The agent may be down, the host may be unreachable, or the network path between panel and agent is broken.

## Why this fired

The agent missed its checkin window (default 60s). After the grace period the panel marks the server `offline` and pages.

## First check

1. From the panel: **Servers → click the offline server → "Test connection"**.
2. From a terminal that can reach the host:
   ```
   ssh root@<host> "systemctl status dockpanel-agent --no-pager"
   ssh root@<host> "journalctl -u dockpanel-agent -n 50 --no-pager"
   ping -c 3 <host>
   ```
3. If SSH itself fails, the host is the problem (network, kernel panic, OOM kill). Open the provider console.

## Common causes

- Agent crashed (look for `panicked at` in journalctl)
- Host networking down (provider outage, firewall change, IP rotation)
- Host out of memory and the agent got OOM-killed
- Disk full on `/` — agent can't write its logs and exits
- Clock skew > 5 min between panel and agent (TLS cert validation fails)
- Cert pin mismatch after agent reinstall (panel logs `cert fingerprint mismatch`)

## Escalation

Wake a human if (a) the host is up but the agent won't start after a `systemctl restart dockpanel-agent`, or (b) the host itself is unreachable for >5 minutes and you don't have a known maintenance window.
