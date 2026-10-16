# System service down

A core system service the panel depends on (nginx, php-fpm, mysql, postgresql, redis, docker) is not running.

## Why this fired

The agent's service-health check found the named systemd unit in a `failed`, `inactive`, or `dead` state. Customer sites depending on it are likely returning 5xx.

## First check

1. From the panel: **System → Services → find the service → "Restart"**. Watch the status update.
2. If restart fails, SSH to the host:
   ```
   systemctl status <service> --no-pager
   journalctl -u <service> -n 100 --no-pager
   ```
3. For nginx specifically, check config first:
   ```
   nginx -t
   ```
4. For php-fpm, list all installed pools — multi-version installs have one unit per major:
   ```
   systemctl list-units 'php*-fpm.service'
   ```

## Common causes

- Bad config after a recent edit (`nginx -t` will say so)
- Disk full (`/var/log` filled by an unrotated log)
- Port conflict (another process bound the port — `ss -lntp | grep :<port>`)
- OOM kill (`dmesg | grep -i 'killed process'`)
- Failed dependency (e.g., postgresql failed → keepalived → nginx)
- Permissions broken after a manual chown/chmod

## Escalation

Wake a human if the service won't restart after fixing config and clearing disk. Public-facing 5xx on customer sites is page-grade — don't sit on it past 10 min.
