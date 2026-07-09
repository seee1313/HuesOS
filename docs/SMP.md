# SMP in HuesOS

This document describes the multi-processor bring-up path as implemented
and verified under QEMU (`-smp 2`).

## Goals

- Boot all application processors (APs) discovered via ACPI MADT.
- Give every CPU its own GDT/TSS, IDT load, scheduler, and syscall MSRs.
- Drive preemption from the **local APIC timer** on every CPU.
- Never place userspace work on a CPU that is not fully online.

## Bring-up sequence

### BSP (during `kmain`, after heap)

1. Parse RSDP → MADT (`huesos-arch::acpi`).
2. `lapic::set_base(phys, hhdm)` — maps the LAPIC page **uncached** into the
   HHDM (Limine base rev 3 does not map MMIO for you).
3. `lapic::init()` — enable software APIC, spurious vector.
4. Calibrate LAPIC timer against PIT once; store
   `lapic::set_timer_initial_count` for APs.
5. For each non-BSP APIC ID:
   - Allocate a 64 KiB stack (kept in `AP_STACKS` for the kernel lifetime).
   - `ap_boot::boot_ap(apic_id, stack_top, ap_entry)`:
     - Copy trampoline to phys `0x8000` (HHDM + identity maps for low 64 KiB).
     - Write `ApBootInfo` at phys `0x7000` (cr3, stack, entry, status).
     - INIT → delay → SIPI → SIPI.
   - Wait (with timeout) for `AP_READY_COUNT` to increase.

### AP trampoline (`ap_trampoline.S` at 0x8000)

Critical details that were historically broken:

| Requirement | Why |
|-------------|-----|
| `SP/ESP = 0x8ff0` before any push | ESP=0 made long-mode entry #PF at `0xfffffffc` → triple fault |
| Far jmp (`0xEA`) into 64-bit CS | Avoid stack-based `retf` for mode switch |
| `EFER.LME \| EFER.NXE` | Kernel PTEs use NX; without NXE the AP dies on first NX page |
| Identity map of low pages | Base rev 3 dropped low 4 GiB identity; after CR3 load the trampoline still executes at phys==virt `0x8xxx` |

### `ap_entry` (Rust)

1. `lapic::init`, allocate `CpuLocal`, `GS_BASE`.
2. Per-CPU `PerCpuGdt::new().load()`, store pointer in `CpuLocal.gdt`.
3. `idt::init()` — without this IDTR is still the real-mode zero table.
4. **`syscall::init(selectors…)`** — STAR/LSTAR/SFMASK are **per logical CPU**.
   Missing this causes `#UD` on the first `syscall` if a user task is
   scheduled on the AP.
5. `scheduler::init()` — idle task + timer callback + mark CPU online.
6. Increment `AP_READY_COUNT`; spin until `APS_MAY_RUN`.
7. Start LAPIC timer with the shared initial count; `STI`; `hlt` idle loop.

### BSP after syscall/scheduler/`init_late`

1. PIC + LAPIC timer + STI on BSP.
2. `smp::release_aps()` sets `APS_MAY_RUN` so APs may unmask timers.

## Scheduling under SMP

- Each CPU has `PER_CPU_SCHEDULERS[lapic_id]` protected by a spinlock.
- Timer IRQ (vector 0x20): **LAPIC EOI** then optional PIC EOI, then
  `timer_callback::tick` → per-CPU `Scheduler::tick` → optional
  `context_switch`.
- `spawn_*` picks the least-loaded **online** CPU (`ONLINE_CPUS` bitmask)
  and, if remote, sends `ipi_reschedule`.

## Failure modes & debugging

```bash
# Serial + exception log
qemu-system-x86_64 ... -smp 2 -serial stdio -d int,cpu_reset -D qemu.log
```

- **AP TIMEOUT (status=0)**: SIPI never reached trampoline (ICR / APIC id /
  UC mapping).
- **Triple fault, ESP=0, EIP≈0x809x**: trampoline stack not set.
- **Triple fault after long mode, IDT=0**: forgot `idt::init` on AP.
- **INVALID OPCODE at user RIP under `-smp 2` only**: syscall MSRs missing
  on AP.
- **Hang in send_ipi under TCG**: unbounded ICR delivery-status poll — keep
  the wait capped (MMIO is extremely slow under TCG).

## What is not done yet

- IOAPIC / full IRQ affinity
- Work-stealing / fair migration heuristics
- Per-AP PIT-free high-precision timer calibration refinements
- Unparking APs for dedicated IRQ threads
