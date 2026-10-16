# Container crashloop

A Docker container has restarted ≥3 times in the last 5 minutes. It is failing fast and being respawned by the restart policy.

## Why this fired

The auto-healer checks each managed container's restart count. Three or more restarts in a short window means the process inside is exiting almost immediately on boot — usually a config error, missing dependency, or unhandled startup exception.

## First check

1. From the panel: **Apps → click the crashing app → "Logs"**. Read the last 200 lines.
2. From a terminal:
   ```
   docker ps -a --format '{{.Names}}\t{{.Status}}' | grep -i restart
   docker logs --tail 200 <container>
   docker inspect <container> --format '{{.State.ExitCode}} {{.State.Error}}'
   ```
3. If the exit code is 137, the kernel OOM-killed it — increase the memory limit in **Apps → app → Resources**.

## Common causes

- Config file or env var missing/wrong (most common)
- Database the app depends on isn't reachable yet (startup order)
- Image was pulled with a broken tag — pin to a known-good digest
- Volume permission issue (UID mismatch between host and container)
- Memory limit too low → OOM kill on first allocation
- Healthcheck fails immediately and restart policy is `on-failure`

## Escalation

Wake a human if the same container keeps crashlooping after one config fix. There may be data corruption in a mounted volume that needs a hands-on operator to triage before another restart compounds the damage.
