# Fallible paging, ELF loading, and process launch

## Policy

Malformed userspace executables, exhausted physical memory, mapping collisions, and missing startup metadata are recoverable process failures. They must not panic Ring 0. Kernel panic remains reserved for an actual kernel invariant violation from which execution cannot safely continue.

## Error flow

`huesos-elf::Loader` now has an associated mapping error and returns `Result<*mut u8, Error>`. `ElfLoadError<E>::Mapping(E)` preserves the architecture-specific cause instead of collapsing allocation and page-table failures into a generic parse error.

The x86_64 `AddressSpace` boundary is fallible:

- `AddressSpace::new() -> Result<_, UserPageError>`;
- `map_new_user_page() -> Result<PhysFrame, UserPageError>`;
- failed leaf mappings return their freshly allocated frame immediately;
- frame ownership is recorded only after page-table insertion succeeds.

`ProcessRuntime::new` and `spawn_from_elf` propagate these errors through `SpawnError`. A failed launch destroys every page and intermediate table already installed, unregisters the root VMAR and process, and never publishes a runnable scheduler task.

The init image uses the same path. If its trusted embedded image cannot launch, the kernel emits a serial diagnostic and remains in its idle loop rather than panicking or entering a partially initialized userspace.

## Startup record containment

A user task trampoline no longer calls `expect` for its task ID or pending RIP/RSP record. Missing metadata terminates that process with `fault_exit::STARTUP_FAILED`. Reaping also removes an unconsumed startup record, preventing metadata accumulation when a process is killed before its first schedule.

## Kernel mappings

Shared kernel mapping operations now return `KernelPageError`. Heap construction propagates mapping/allocation failure and enters an explicit boot halt before enabling userspace. Firmware-table mapping failure disables ACPI/SMP discovery and continues in uniprocessor mode, preventing an unchecked ACPI pointer walk.

## Ownership and rollback

The ordering for a process launch is:

1. register Process;
2. allocate PML4;
3. register root VMAR;
4. map ELF pages;
5. map stack pages;
6. publish `ProcessRuntime` into Process;
7. create scheduler task.

Failures unwind in reverse order before step 6. No Process handle or task ID is visible during construction. `AddressSpace::destroy` is called only while the new CR3 has never been activated.

## Tests

Host ELF tests continue to cover malformed headers, truncated segments, overflow, and real init loading. New mapping-error tests should use a loader that fails after N pages and assert that `ElfLoadError::Mapping` preserves the injected cause. Kernel/QEMU validation covers release SMP boot, fault probes, Terminal readiness, and PMM frame stability across failed launches.
