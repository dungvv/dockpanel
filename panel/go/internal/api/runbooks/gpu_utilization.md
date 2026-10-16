# GPU utilization high

A GPU has been at high utilization (default >90%) for a sustained window.

## Why this fired

`nvidia-smi --query-gpu=utilization.gpu` reported above-threshold for the configured window. High utilization is normal during active workloads — this alert is a hint that the card is saturated, queueing inference, or another workload is contending.

## First check

1. From the panel: **System → GPU** for live + 24h chart. Per-process VRAM table shows which container owns the load.
2. From the host:
   ```
   nvidia-smi --query-compute-apps=pid,used_memory,name --format=csv
   nvidia-smi -l 5  # 5s rolling
   ```
3. Check whether two containers are sharing the GPU (`--gpus all` on multiple workloads).

## Common causes

- Inference workload at capacity — needs scale-out or batch tuning
- Training run was scheduled accidentally on a serving GPU
- Crypto-miner workload (look for unfamiliar process names)
- Container without a GPU memory limit eating the whole card
- Idle "warming" workload someone forgot to shut off

## Escalation

This is a warning, not a page (unless paired with `gpu_temperature` — then treat the temperature runbook). Plan capacity tuning during business hours. If utilization is high but customer-facing latency is fine, this is healthy use of paid capacity.
