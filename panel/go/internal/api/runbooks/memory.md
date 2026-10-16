# Memory usage high

Server memory utilization is above the configured threshold (default 85%) sustained over the alert window.

## Why this fired

Sampled from `/proc/meminfo`. High memory by itself isn't fatal — Linux uses free RAM for page cache aggressively. The risk is OOM kill, which strikes the largest non-essential process and can take down PHP-FPM, postgres, or the panel agent itself.

## First check

1. From the panel: **System → Processes** sorted by RSS descending.
2. From the host:
   ```
   free -h
   ps -eo pid,rss,comm --sort=-rss | head -20
   dmesg | grep -i 'killed process' | tail -5  # past OOM kills
   cat /proc/swaps  # is swap configured + in use?
   ```
3. Check PHP-FPM `pm.max_children` — a misconfigured pool can balloon to GB.

## Common causes

- PHP-FPM `pm.max_children` × `memory_limit` exceeds available RAM
- Memory leak in a long-running app (see also: `memory_leak` alert)
- MySQL/postgres `innodb_buffer_pool_size` / `shared_buffers` set too high
- Container without a memory limit eating the host
- Massive log file being read into memory by a tail-style tool
- Page cache reclaimable — verify `available` is genuinely low, not just `free`

## Escalation

Wake a human if available memory is <10% AND swap is full AND a critical process has been OOM-killed. Otherwise this is usually a config tune, not a page. Plan tuning in business hours.
