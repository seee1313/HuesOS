# HuesOS Optimization, Safety, and Documentation Program

## Mission

This branch is a systematic hardening pass, not a collection of unrelated
micro-optimizations. Its goals are:

1. reduce boot, syscall, graphics, memory-management, and process-lifecycle
   overhead with measurements before and after each change;
2. remove avoidable Rust `unsafe`, confine unavoidable machine operations to
   narrow audited modules, and document every remaining safety contract;
3. make architecture, invariants, failure behavior, ownership, concurrency,
   ABI, and testing discoverable from source documentation.

Optimization must not weaken isolation, capability checks, pointer validation,
or fault containment. A change is not complete until debug/release SMP boots,
host tests, and the relevant integration workload pass.

## Baseline (2026-07-12)

| Metric | Value |
|---|---:|
| Rust source files | 109 |
| Rust LOC | 17,044 |
| `unsafe { ... }` blocks | 228 |
| `unsafe fn` declarations | 49 |
| `unsafe impl` declarations | 22 |
| `.unwrap()` calls | 17 |
| `.expect()` calls | 26 |
| explicit `panic!` calls | 5 |

Counts include architecture code, FFI adapters, tests, and userspace. Vendored
DoomGeneric C is tracked separately: it is third-party GPL C and is not a
meaningful target for Rust unsafe counts.

## Unsafe policy

"Remove all unsafe" cannot literally apply to an operating-system kernel. The
following operations inherently require an unsafe boundary:

- privileged instructions and control registers;
- port I/O and MMIO;
- context-switch/syscall/interrupt assembly;
- page-table and physical-memory dereference through the HHDM;
- allocator internals that place metadata into free memory;
- FFI with DoomGeneric;
- copying to/from validated userspace pointers.

The enforceable policy is:

1. safe code must never dereference raw user pointers;
2. raw hardware/memory operations live in `huesos-arch`, allocator internals,
   or a dedicated audited boundary module;
3. every unsafe function has a `# Safety` contract;
4. every unsafe block has an adjacent `SAFETY:` explanation describing the
   invariant established by safe callers;
5. broad unsafe blocks are split to the smallest operation possible;
6. unsafe marker traits (`Send`/`Sync`) document why aliasing/concurrency is
   valid;
7. application crates contain no inline syscall assembly; libcanvas owns it;
8. `unsafe_op_in_unsafe_fn` is enabled progressively so unsafe functions do
   not silently make their full body unsafe;
9. new unsafe outside allowlisted modules fails review.

## Optimization rules

- Measure wall-clock ticks, bytes copied, frames allocated, and syscall count.
- Prefer algorithmic reduction over instruction-level tuning.
- Never optimize by removing bounds, rights, W^X, or overflow checks.
- Avoid large attacker-controlled temporary allocations.
- Avoid full-frame work when dirty regions are available.
- Never flush a TLB for an address space that has not been activated.
- Avoid holding spinlocks across context switches, blocking, user copies, or
  long page-table walks.
- Keep interrupt handlers bounded and allocation-free.
- Preserve a serial/fault diagnostic path for every optimized subsystem.

## First hardening checkpoint

The initial implementation pass produced these changes:

| Metric | Baseline | Current | Change |
|---|---:|---:|---:|
| `unsafe` blocks | 228 | 179 | -49 (-21.5%) |
| `unsafe fn` | 49 | 44 | -5 |
| `unsafe impl` | 22 | 22 | unchanged (raw trees removed; two documented `UnsafeCell` boundaries added) |

Key results:

- replaced the raw-pointer scheduler WAVL tree, including manual allocation,
  rotations, recursive destruction, and manual `Send`/`Sync`, with a safe
  `BTreeSet<(vruntime, task_id)>` run queue at the same O(log n) complexity;
- replaced potentially unaligned ACPI pointer dereferences (Rust UB) with
  bounded, checked `read_unaligned` value copies and corrupt-length limits;
- made the private integer syscall trampoline safe while retaining one audited
  inline-assembly block, removing unsafe wrappers throughout libcanvas;
- added a safe optional-handle Channel API and removed raw-handle construction
  from init;
- replaced Doom's multiple `static mut` globals with one documented private
  `UnsafeCell` boundary for its synchronous single-thread callback model;
- added null checks and explicit safety contracts to Doom FFI outputs.

### Clippy and mutable-static checkpoint

Current post-Clippy metrics are 185 unsafe blocks, 46 unsafe functions, 24
unsafe impls, and one `static mut` declaration. The small increase from the
first checkpoint is intentional: functions that dereference caller-owned raw
pointers are now correctly marked unsafe, and implicit unsafe operations inside
unsafe functions became explicit reviewed blocks. Relative to baseline, unsafe
blocks remain down by 43 (18.9%).

The sole remaining `static mut` is the foreign DoomGeneric
`DG_ScreenBuffer` symbol; first-party Rust mutable-static storage is zero.

- added Clippy to the pinned Rust toolchain and a `make clippy` gate covering
  the workspace plus every standalone userspace/driver crate with `-D warnings`;
- removed first-party Rust `static mut` storage from GDT stacks, AP stacks,
  CPU-local slots, syscall publication, Doom state, and Terminal shadow memory;
- retained only the foreign DoomGeneric `DG_ScreenBuffer` declaration, whose
  ownership is controlled by the C engine and accessed through an FFI safety
  contract;
- fixed `TicketLock::try_lock`, which previously consumed a ticket on failure
  and could permanently stall every later lock waiter;
- replaced Clippy-reported unit error types with typed framebuffer/VMO/VMAR
  errors and improved propagation to syscall status codes;
- moved early init probe waits from a potentially missed blocking wake to
  bounded cooperative process polling so a failed diagnostic cannot prevent
  Terminal startup.

## Work packages

### P0 — correctness and resource lifecycle

- Replace permanent strong object-registry retention with explicit strong/weak
  ownership rules for handles, mappings, in-flight channel transfers, IRQ
  registries, scheduler references, and process wait handles.
- Ensure last-reference VMO destruction returns physical frames without freeing
  mapped/in-flight objects.
- Make process/task/address-space teardown incremental and bounded.
- Add counters and repeated create/map/close/exit soak tests.

### P1 — syscall and memory hot paths

- Audit every pointer-bearing syscall for one validated copy boundary.
- Replace infallible allocation/panic paths reachable from userspace with
  `NoMemory`, `Busy`, or `InvalidArgs`.
- Add scatter/gather or mapped-VMO primitives where repeated copies dominate.
- Make VMAR mapping transactional with rollback and fallible page-table APIs.
- Add unmap/protect only after copy-vs-unmap races have a locking/fixup design.

### P1 — graphics and terminal

- Keep the buffered Terminal renderer and add dirty-row upload.
- Remove full-frame temporary allocation from kernel framebuffer blit.
- Copy VMO-to-framebuffer in bounded chunks or directly by physical page.
- Add frame/upload/present counters and Full HD/1440p tests.
- Apply incremental/dirty-cell rendering to Snake in its own focused change.

### P1 — scheduler and SMP

- Separate scheduling-accounting ticks from wall-clock ticks completely.
- Audit task-ID/index lifetime and reclaim finished task metadata.
- Validate process-wide kill/exit across CPUs without premature CR3 teardown.
- Establish lock ordering and document every cross-subsystem callback.
- Add multi-CPU channel/wait/exit stress workloads.

### P2 — safe data structures

- Replace raw-pointer WAVL ownership with an arena/index representation where
  performance measurements permit it.
- Encapsulate buddy/slab free-list raw pointers behind checked private types.
- Replace mutable global application state with `UnsafeCell` wrappers or safe
  synchronization where callbacks can be concurrent.
- Remove unnecessary unsafe annotations and unsafe blocks around safe APIs.

### P2 — build and quality gates

- Add CI for format, host tests, debug/release kernel builds, ISO construction,
  one/two CPU boot assertions, user-pointer probes, fault containment, Doom,
  shutdown, and terminal-return latency.
- Add a repository script that reports unsafe/unwrap/expect/panic counts and
  rejects unexplained regressions.
- Pin third-party source revisions and checksums.

## Documentation standard

Every public subsystem should explain:

- purpose and non-goals;
- ownership/lifetime model;
- concurrency and lock ordering;
- normal and error flow;
- security boundary;
- architecture-specific assumptions;
- invariants required by unsafe code;
- performance characteristics;
- test strategy and known limitations.

Public API items retain concise rustdoc; module-level documents carry design
rationale. Large protocols additionally receive a document under `docs/` and
link back from both implementation sides.

## Required regression matrix

| Test | Debug | Release | 1 CPU | 2 CPU |
|---|---:|---:|---:|---:|
| Host unit suite | yes | yes | n/a | n/a |
| Boot-to-init | yes | yes | yes | yes |
| Invalid user pointer probes | yes | yes | yes | yes |
| Ring-3 #PF/#UD/#GP/#DE isolation | yes | yes | yes | yes |
| DriverManager/keyboard/filesystem | yes | yes | yes | yes |
| Terminal buffered return | yes | yes | yes | yes |
| Doom launch/input/exit | yes | yes | yes | yes |
| Shutdown halt screen | yes | yes | yes | yes |
| Repeated process/VMO lifecycle | yes | yes | yes | yes |

Bare-metal checkpoints target the recorded MSI Modern 15 B5M platform after
QEMU gates pass.

## Completion criteria

- no unexplained unsafe remains;
- unsafe counts decrease or each retained site has a reviewed contract;
- no userspace-controlled operation can panic the kernel on ordinary resource
  failure;
- repeated process/VMO/Canvas workloads have stable free-frame/object counts;
- measured hot paths improve without security regression;
- documentation and tests describe the final behavior, not historical plans.
