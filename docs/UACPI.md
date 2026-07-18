# uACPI integration

## Decision

HuesOS uses **uACPI**, not ACPICA, for standards-complete ACPI and AML support. The vendored code is pinned to:

```text
repository: https://github.com/uACPI/uACPI
commit:     9c9b26d6291a1cdd9014cc5bb6b03e596697cbfd
license:    MIT
```

The upstream license, README, headers, sources, and exact revision are stored under `third_party/uacpi/`. Updating the revision requires a dedicated review, host sanitizer run, firmware corpus run, and safety-budget update.

## Current stage: validated table subsystem

The first stage compiles uACPI in `UACPI_BAREBONES_MODE`. uACPI now owns RSDP/XSDT/RSDT traversal, SDT mapping, checksum validation, table lifetime, and MADT discovery. HuesOS keeps its existing typed MADT consumer temporarily, but SMP bring-up is gated on successful uACPI table initialization and an accessible validated `APIC` table.

This staged integration is intentional. Enabling AML before the kernel provides correct mutex, event, work-queue, interrupt, PCI, and SystemIO contracts would replace a small parser with a larger unsound boundary.

## Rust/C boundary

`huesos-uacpi` is the only first-party crate that calls uACPI C APIs. Its current foreign boundary consists of:

- `uacpi_setup_early_table_access`;
- `uacpi_table_subsystem_available`;
- `uacpi_table_find_by_signature`;
- `uacpi_table_unref`.

The host callbacks exported to C are:

- `uacpi_kernel_get_rsdp`;
- `uacpi_kernel_map`;
- `uacpi_kernel_unmap`;
- `uacpi_kernel_log`.

Every unsafe operation has a local contract. Foreign strings are capped at 4096 bytes, table lengths at 16 MiB, null pointers are rejected, and firmware mappings go through the fallible HHDM page-table API.

The early descriptor scratch buffer is static, 16-byte aligned, and protected by a serialization mutex. No `static mut` is introduced.

## Failure policy

uACPI failure is not a kernel panic. If table initialization, checksum validation, or MADT lookup fails, HuesOS emits a serial diagnostic and continues in uniprocessor mode. It never passes an unvalidated ACPI pointer to SMP bring-up.

HHDM unmap is deliberately a no-op during this stage. Firmware mappings are shared boot mappings, may be referenced by the existing MADT consumer, and are retained for the kernel lifetime. Dynamic map accounting will be introduced before AML runtime mappings are enabled.

## Lock ordering

Current barebones initialization runs once during BSP boot:

1. kernel paging initialized;
2. firmware physical ranges mapped;
3. kernel heap initialized;
4. uACPI initialization mutex;
5. fallible kernel page-table mapping as required;
6. table reference acquisition/release;
7. SMP discovery.

No uACPI callback enters userspace, parks, schedules work, or acquires object/scheduler locks.

## Full AML enablement plan

Before removing `UACPI_BAREBONES_MODE`, HuesOS must implement and test:

1. sized allocation/free and zeroed allocation;
2. monotonic nanoseconds, bounded stall, and scheduler sleep;
3. non-recursive mutexes with timeout semantics;
4. semaphore-like events;
5. IRQ-safe spinlocks and interrupt-state restoration;
6. deferred CPU0 work queue and completion barrier;
7. exact-width SystemIO handles;
8. validated PCI configuration handles, initially legacy CF8/CFC and then MCFG ECAM;
9. interrupt install/uninstall integrated with the kernel IRQ router;
10. firmware fatal/breakpoint policy;
11. namespace load/initialize and `_PIC` evaluation;
12. `_PRT`, `_CRS`, `_STA`, `_INI`, reset, sleep, and poweroff;
13. ASan/UBSan host harness and malformed-table/AML corpus.

Only after these contracts pass SMP and real-hardware tests will uACPI become the source for device enumeration, PCI routing, shutdown, VT-d DMAR, and AMD-Vi IVRS discovery.

## Safety budget

This integration adds eight audited Rust unsafe blocks and one `unsafe impl`, all isolated in `huesos-uacpi`. The machine-readable budget is updated in the same reviewed commit. No `unwrap`, `expect`, `panic!`, or `static mut` is added.
