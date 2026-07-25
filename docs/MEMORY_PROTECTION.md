# Supervisor memory protection

## Enabled controls

HuesOS enables the following independently on every logical CPU inside a single
`cpu::enable_memory_protection` call, which the BSP invokes from
`arch::init_early` and every AP invokes from `smp::ap_entry`:

- `EFER.NXE` for non-executable mappings;
- `CR0.WP` so ring0 cannot write read-only pages;
- `CR4.SMEP` when CPUID advertises it, preventing ring0 instruction fetches from user pages;
- `CR4.SMAP` when CPUID advertises it, preventing accidental ring0 data access to user pages.

Unsupported SMEP/SMAP features remain disabled; boot does not assume a particular CPU generation.

## W^X for kernel data mappings

`huesos_arch::paging::flags::KERNEL_RW` includes `NO_EXECUTE`, so every kernel
data mapping installed through this module — heap pages via
`init::heap_init`, ACPI/RSDP windows via `map_hhdm_range`, and any future
kernel-owned buffer that reuses these helpers — cannot be reached as a
code-execution gadget.

Two exceptions are deliberate and documented in the source:

- `map_identity_range` (used only by the AP trampoline, physical page
  `0x8000`) is *not* NX, because the trampoline itself executes from that
  identity mapping before hopping into the higher-half kernel. Setting NX
  there would #GP the AP on its first instruction.
- The kernel `.text` and `.rodata` sections are mapped by Limine with its
  own flags. `.text` legitimately needs to remain executable. `.rodata`
  and every other non-`.text` load segment (`.data`, `.bss`,
  `.limine_requests`) are additionally hardened by a post-init W^X
  sweep — see below.

EFER.NXE must be set on every CPU that will ever load a page table with the
`NO_EXECUTE` bit; otherwise the bit is reserved and every access to such a
page raises `#GP`. Enabling it in `enable_memory_protection` (rather than
only once on the BSP, as an earlier revision did) is what makes this
uniform.

## Kernel W^X sweep

`huesos-arch::paging::apply_kernel_wx` walks the page-aligned start / end
symbols exported by `scripts/linker.ld` for `.limine_requests`,
`.rodata`, and `.data`/`.bss`, and OR-s `NO_EXECUTE` into every 4 KiB
page-table entry it finds mapped in that range. This complements
`flags::KERNEL_RW`: `KERNEL_RW` handles mappings HuesOS installs itself
after paging init, the sweep handles pages Limine installed at load time
before we owned the mapper.

The sweep is called from `kmain` between `init_paging` and
`init::heap_init`. Failure is logged on early serial and boot
continues — a halt would trade a working hardened kernel for a broken
kernel with the same coverage, which is the wrong tradeoff. Every
existing per-page mapping keeps its PRESENT/WRITABLE/etc. bits; only
`NO_EXECUTE` is added on top.

The linker script deliberately does **not** export `__huesos_text_*`
symbols. `.text` is the only higher-half range that must remain
executable, and having no symbols makes it structurally impossible to
accidentally stamp NX on it from `apply_kernel_wx`.

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
