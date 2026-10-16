# GPU VRAM high

A GPU's video memory is above the configured threshold (default 90%). Out-of-memory on a GPU manifests as silent kernel failures, NaN tensors, or process exits with `CUDA out of memory`.

## Why this fired

`nvidia-smi --query-gpu=memory.used,memory.total` reported VRAM used / total > threshold. Unlike CPU memory, GPU OOM does not invoke a kill — the workload itself raises a CUDA error and dies (or in inference servers, fails the request and continues).

## First check

1. From the panel: **System → GPU** for per-process VRAM breakdown.
2. From the host:
   ```
   nvidia-smi --query-compute-apps=pid,used_memory,name --format=csv,noheader
   nvidia-smi --query-gpu=memory.used,memory.free,memory.total --format=csv
   ```
3. If a single process is using >80% VRAM, that's your candidate to scale down or evict.

## Common causes

- Model loaded at FP32 when FP16 / INT8 would fit in budget
- Batch size set higher than VRAM headroom permits
- Multiple model instances loaded "for warmup" but never unloaded
- Cached KV blocks accumulating without eviction (LLM serving)
- Memory fragmentation — `nvidia-smi --gpu-reset` requires draining first

## Escalation

This is a warning. Customer-facing impact only when the workload tries to allocate more and dies. If VRAM is climbing toward 100% with active workloads still trying to load, evict the lowest-priority workload before it pages.
