# Supervisor memory protection

## Enabled controls

HuesOS enables the following independently on every logical CPU:

- `EFER.NXE` for non-executable mappings;
- `CR0.WP` so ring0 cannot write read-only pages;
- `CR4.SMEP` when CPUID advertises it, preventing ring0 instruction fetches from user pages;
- `CR4.SMAP` when CPUID advertises it, preventing accidental ring0 data access to user pages.

Unsupported SMEP/SMAP features remain disabled; boot does not assume a particular CPU generation.

## User-copy contract

Only `huesos-syscalls/src/user_memory.rs` may open a supervisor access window. It first validates the complete range against ABI bounds and active page-table permissions, then creates `UserAccessGuard`. The guard:

1. saves and disables local interrupts;
2. executes `STAC` only if SMAP is enabled;
3. performs a bounded, non-blocking copy;
4. executes `CLAC` and restores the previous interrupt state on drop.

Masking interrupts prevents an unrelated IRQ handler from inheriting `EFLAGS.AC`. Every IDT handler also executes a conditional `CLAC` at entry as defense in depth. `IA32_FMASK` clears AC, IF, DF, and TF on syscall entry, so userspace cannot carry an SMAP bypass into ring0.

The current maximum one-shot VMO copy is 1 MiB. A future throughput stage should split large transfers into page-sized guarded chunks so interrupt latency stays bounded without widening the SMAP window.

## Safety boundary

The unavoidable unsafe operations are limited to control-register updates and `STAC`/`CLAC`. CPUID is checked before setting SMEP/SMAP or executing SMAP instructions. Existing CR0/CR4 bits are preserved. No user pointer is created by the protection code itself.

## Verification

CI compiles both the architecture controls and centralized user-copy implementation with warnings denied. Boot smoke must continue to pass user-fault isolation, terminal readiness, and SMP bring-up with no kernel panic. Hardware testing should cover CPUs both with and without SMAP support.
