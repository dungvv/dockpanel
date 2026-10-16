# Container unhealthy

A Docker container's `HEALTHCHECK` is reporting `unhealthy`. The container is running but its self-reported health probe is failing.

## Why this fired

Docker runs the image's `HEALTHCHECK` instruction (or compose-defined one) on a schedule. After consecutive failures the state flips to `unhealthy`. The container is still up — but something inside has stopped working correctly. This often precedes a crashloop.

## First check

1. From the panel: **Apps → click the unhealthy app → "Health"** to see the last probe output.
2. From a terminal:
   ```
   docker inspect --format '{{json .State.Health}}' <container> | jq
   docker logs --tail 100 <container>
   docker exec <container> <healthcheck-command>  # reproduce manually
   ```

## Common causes

- Internal port the healthcheck probes is bound but app isn't ready yet (start period too short)
- Database the app depends on is slow/disconnected (app accepts but can't serve)
- Disk inside the container is full (look for `tmpfs` or anonymous volume filling)
- Memory pressure — app accepts requests but everything is paging
- Healthcheck command is wrong for the app's current version (after an upgrade)
- The healthcheck endpoint itself is broken (200 OK during deploy was a fluke)

## Escalation

Wake a human if multiple containers in the same compose stack go unhealthy together — that points at an external dependency (database, cache, network) and needs a coordinated fix. Single-container unhealthy is usually self-recoverable; give it 5-10 min before escalating.
