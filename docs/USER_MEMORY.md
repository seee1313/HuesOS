# Userspace Memory Safety

## Purpose

Every syscall argument is controlled by a ring-3 process. A raw pointer is not
safe merely because it is non-null: syscall dispatch runs at CPL0, so directly
dereferencing a caller-provided address would make the kernel perform reads or
writes with supervisor privilege. That would permit a process to disclose
kernel memory, corrupt kernel state, or turn an invalid pointer into a kernel
page fault.

HuesOS therefore treats the userspace/kernel copy boundary as an explicit
security boundary. Syscall implementations must not dereference userspace
pointers directly. All access goes through
`huesos-syscalls::user_memory`.

## Address policy

A non-empty userspace range must satisfy all of the following:

1. `address >= USER_ASPACE_BASE` (`0x10000`), preserving the low/null guard.
2. `address < USER_ASPACE_END` (`0x0000_8000_0000_0000`).
3. `address + length` does not overflow.
4. The exclusive end does not exceed `USER_ASPACE_END`.
5. Every 4 KiB page touched by the range is present in the active CR3.
6. Every traversed PML4/PDPT/PD/PT entry has `USER_ACCESSIBLE`.
7. Kernel-to-user copies additionally require `WRITABLE` at every level.

Permissions are effective across the complete x86_64 page-table walk. Checking
only the leaf PTE is insufficient because upper-level entries can remove user
or write permission. The architecture walker also understands 1 GiB and 2 MiB
huge-page leaves, although normal HuesOS process mappings currently use 4 KiB
pages.

A zero-length byte/array range performs no memory access and may use a null
pointer. Required scalar outputs are never zero length and therefore reject
null automatically.

## Copy API

The syscall crate provides these internal operations:

| Function | Direction | Use |
|---|---|---|
| `validate_range` | none | Validate all pages and effective permissions |
| `validate_write` | none | Preflight one scalar output before side effects |
| `validate_write_array` | none | Preflight an output array |
| `read_value` | user → kernel | Snapshot a plain `Copy` ABI record |
| `read_array` | user → kernel | Snapshot an array of plain values |
| `copy_from_user` | user → kernel | Copy bytes into kernel-owned storage |
| `write_value` | kernel → user | Write one possibly unaligned ABI value |
| `write_array` | kernel → user | Write possibly unaligned ABI values |
| `copy_to_user` | kernel → user | Copy bytes into a writable user range |

ABI records are copied once before use. This prevents a second userspace thread
from changing fields between validation and execution (a double-fetch bug).
Syscalls that block or dequeue an object validate every output buffer before
they park or consume the object.

The only raw pointer reads/writes in `huesos-syscalls` are contained in
`user_memory.rs`, with local safety arguments. Direct `from_raw_parts`, raw
pointer assignment, `read_unaligned`, or `copy_nonoverlapping` elsewhere in the
syscall implementation is prohibited.

## Per-call limits

Validation does not make unbounded allocation safe. The first hardened ABI
applies the following limits:

| Operation | Limit |
|---|---:|
| DebugWrite payload | 4 KiB |
| VMO read/write transfer | 1 MiB |
| Channel byte payload | 64 KiB |
| Channel transferred handles | 64 |
| Framebuffer blit temporary source | 64 MiB |
| Process/thread name | 64 bytes |
| VMO object size | 4 GiB |

Kernel temporary buffers use `try_reserve_exact` and return `NoMemory` on
allocation failure instead of relying on infallible growth for an
attacker-controlled size.

## Error and side-effect rules

An invalid address, overflow, missing mapping, wrong page permission, or size
above a syscall transfer limit returns `ErrorCode::InvalidArgs`. The kernel
must not fault.

Output pointers are preflighted before:

- allocating/registering an object;
- adding a handle;
- blocking in a wait queue;
- removing a Channel message or Port packet;
- starting a thread.

This preserves the practical rule that an invalid output pointer does not
consume an event or create a partially reported resource. Revalidation still
occurs at the final copy.

## Current concurrency model

Validated copy helpers now hold the owning Process `user_memory_lock` across
page-table validation and the bounded raw copy. `VmarUnmap` and `VmarProtect`
use the same lock, so kernel copies and VMAR permission mutation cannot overlap
within a process. A global VMAR mutation lock serializes page-table changes
while the architecture layer performs a cross-CPU TLB shootdown before the
syscall returns to userspace.

This locking does not make arbitrary kernel pointer dereferences safe: all
caller pointers must still use `user_memory`, and future pageable/faulting
copies still require the `huesos-extable` recovery path. The exception-table
policy remains the long-term defense for faults that occur despite validation
or for future operations that cannot hold an address-space lock.

## Review checklist for a new syscall

1. Are all raw pointers copied through `user_memory`?
2. Are lengths multiplied/added with checked arithmetic?
3. Is every attacker-controlled allocation bounded?
4. Is an ABI argument record snapshotted exactly once?
5. Are outputs validated before side effects or blocking?
6. Are capability rights checked independently of pointer validation?
7. Can output buffers alias, and does that create a resource leak?
8. Are kernel locks released before touching userspace memory?
9. Does allocation failure return `NoMemory` rather than panic?
10. Are zero-length semantics explicit?

## Runtime smoke coverage

`huesos-init` enables libcanvas's `kernel-smoke-tests` feature and runs three
negative probes before normal VMO/Channel checks. They verify rejection of a
kernel-half input, an unmapped low-userspace output, and a mapped read-only code
page used as an output. Debug and release QEMU boots on one and two CPUs must
print `[init] user pointer guard smoke OK` and must not report a page fault.
The deliberately invalid raw calls remain confined to the feature-gated
libcanvas diagnostics module.

## Future hardening

This layer does not replace the remaining architectural work:

- distinguish CPL3 faults from kernel faults and terminate only the offending
  process;
- add fault-recoverable copies before `VmarUnmap`;
- enable SMEP and SMAP with explicit access windows;
- fuzz syscall pointer/length combinations;
- add QEMU tests that intentionally pass unmapped, read-only, boundary, and
  kernel-half addresses.
