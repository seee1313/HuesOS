# Scheduler v2 benchmark and verification methodology

Status: host-level harness committed; physical benchmark thresholds to be
recorded from real Intel/AMD hardware before merge.

## Host benchmark

Run:

```bash
bash scripts/sched-bench-host.sh
```

This is deterministic host evidence: the `huesos-sched` policy suite
(including the 3000-operation randomized EEVDF tree invariant test), kernel
scheduler host tests, and the static gates (safety budget, policy crates,
format). It is **not** bare-metal evidence.

## Metrics defined in `docs/SCHEDULER_V2.md` §22

The physical gate requires, on Intel and AMD hardware with SMT on/off:

- context-switch p50/p95/p99/max, same and different address spaces;
- local and remote wake latency;
- scheduler decision time at 1/16/256/4096 runnable entities;
- preemption-disabled and hard-IRQ maximum duration;
- context switches and IPIs per second;
- EEVDF weighted-share error;
- Job global service error;
- load-balance convergence and migration rate;
- CBS budget error / deadline misses / migration cost;
- IRQ latency and storm behavior;
- SMT throughput and forced-idle cost;
- PCID and XSAVE impact.

## Evidence collection

- Host harness output: attach the log from `scripts/sched-bench-host.sh`.
- QEMU logs: attach serial logs from `scripts/ci-qemu-smoke.sh` (SMP 1/2/4/8)
  and the hardening gates.
- Bare metal: `docs/BARE_METAL_SECURITY_EVIDENCE.md` + collector script.

## Thresholds

Accepted thresholds and baselines are committed in this document only after
they are measured on physical hardware. Until then, no numeric claim about
latency or throughput is made for Scheduler v2.
