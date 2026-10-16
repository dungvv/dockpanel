# Memory leak suspected

A process's resident memory has grown monotonically over the last several hours without dropping. This pattern matches a leak — memory acquired but never released.

## Why this fired

The agent's anomaly detector tracks per-process RSS over a rolling window. A leak fires when the trend slope is consistently positive AND total RSS exceeds an absolute floor (so newly-started processes don't trip it). Real leaks don't self-heal; left alone they end in OOM kill.

## First check

1. From the panel: **System → Processes → click the process → "Memory chart"** to confirm the climb.
2. From the host:
   ```
   ps -eo pid,rss,etime,comm --sort=-rss | head -20
   cat /proc/<pid>/status | grep -E 'VmRSS|VmPeak|VmHWM'
   ```
3. Identify whether it's a long-running process (probably leaking) or a forking process tree (probably accumulation, not a leak).

## Common causes

- Web app with circular references the GC can't break (Python, Node)
- Connection pool not bounded — opening forever
- Cache without eviction policy
- Native extension leaking outside the GC's view
- Worker process configured `pm.max_requests=0` (PHP-FPM)
- Buggy version of a recently-upgraded dependency

## Escalation

Wake a human if RSS climb is steeper than 1GB/hour or if the process is critical (postgres, agent itself). Short-term mitigation: schedule a periodic restart (`pm.max_requests=500` for PHP-FPM, systemd `RuntimeMaxSec=` for daemons). Long-term: profile and patch.
