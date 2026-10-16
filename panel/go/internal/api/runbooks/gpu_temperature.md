# GPU temperature critical

A GPU has crossed its temperature threshold. Sustained operation at this temperature risks thermal damage and silent throttling.

## Why this fired

`nvidia-smi` reported a temperature above the configured threshold (default 85°C) for at least one consecutive sample window. The card may already be throttling; left alone it can shut down or accelerate failure of solder joints.

## First check

1. From the panel: **System → GPU** for the live reading + 24h chart. Look for whether utilization is also high (workload-driven heat) or low (cooling failure).
2. From the host:
   ```
   nvidia-smi --query-gpu=index,name,temperature.gpu,utilization.gpu,fan.speed,power.draw --format=csv
   sensors  # for chassis fans
   ```
3. Check airflow physically if you have access — clogged intake fins are the #1 cause on bare-metal.

## Common causes

- Dust-clogged heatsink or filter (bare-metal hosts)
- Fan failure (fan.speed reads 0 in nvidia-smi)
- Ambient room temperature spike (HVAC fault)
- Workload pinned at 100% with no cooling headroom
- Power-limit override pushing the card past its cooling envelope
- Adjacent card heating this one (multi-GPU dense chassis)

## Escalation

Wake a human if temperature stays above threshold for >5 min after pausing the workload. Continued operation risks permanent damage. Throttle workload or shut down the card while you investigate.
