# Scudo port — implementation plan (working document)

Status: **in progress**. This is the working plan for replacing
`huesos-user-alloc` with a Scudo-architecture allocator, plus the
kernel primitives it requires (Variant B: kernel primitives first).

## 0. Constraints discovered by reading the tree

| Scudo requires | HuesOS today | Consequence |
|---|---|---|
| `mmap`/`munmap` for Primary+Secondary | Heap is a fixed 18 MiB region, **eagerly** mapped page-by-page for *every* process (`kernel/process.rs:182-195`); no process holds a handle to its own VMAR, so `sys_vmar_map` is unreachable for self-mapping | Need a heap-region syscall |
| Per-thread caches (TSD) bound to TLS | `Thread::create` is only ever called by the launcher; ring-3 services are single-threaded; no TLS | TSD designed but degenerate: exactly one shared cache behind the existing lock discipline |
| Entropy for the header cookie | No `random`/`getrandom`/RDRAND anywhere in ABI or kernel | Need an entropy syscall |
| C++ + libc | `no_std`, no libc, no C++ runtime; MIT vs Apache-2.0-WLE | A literal LLVM vendoring is impossible; this is an **architecture port in Rust** |

## 1. Kernel primitives (prerequisite commits)

### 1a. `SystemGetEntropy = 60`
Fills a user buffer with CSPRNG bytes. Kernel-side source: RDRAND
when CPUID reports it, otherwise a ChaCha20-based DRBG seeded from
TSC + boot entropy. Needed for: Scudo header cookie, guard patterns,
and (later) ASLR.

### 1b. `VmarHeapExtend = 61`
Commits/decommits pages inside the process's own reserved heap
window. This is the `mmap` substitute:

- caller passes `{ offset, len, op }` relative to `USER_HEAP_BASE`;
- kernel maps fresh zeroed frames (`map_new_user_page`) or unmaps and
  frees them (`unmap_user_page`);
- bounds are clamped to `[USER_HEAP_BASE, +USER_HEAP_SIZE)` — the
  syscall can never touch any other part of the address space, so no
  new capability is required and no rights can be escalated.

This also fixes a real waste: today all 18 MiB (4608 frames) are
committed to every process at launch, including processes that never
allocate. After this change the launcher reserves the window but
commits only the first N pages, and the allocator grows on demand.

## 2. Allocator architecture (`huesos-scudo`)

Mirrors upstream Scudo's structure, minus what the platform cannot
support:

- **SizeClassMap** — compile-time table of size classes.
- **Chunk header** — packed 64-bit header carrying state
  (Available/Allocated/Quarantined), class id, request size, offset;
  protected by a **checksum** over (cookie, address, header body).
  Every free/realloc verifies the checksum first: this is what turns
  a heap overflow or double free into a clean typed error instead of
  a corrupted free list. Directly kills bug #1 and #2 from the audit.
- **Primary allocator** — per-class free lists built from
  `TransferBatch`es carved out of region memory obtained via
  `VmarHeapExtend`.
- **Secondary allocator** — large allocations served directly from
  the heap window, cached by a small LRU, with an unmapped **guard
  page** on each side so a linear overflow faults instead of
  corrupting a neighbour.
- **Quarantine** — freed chunks are held (bounded by count+bytes)
  before returning to the free list, so use-after-free hits a
  quarantined header rather than a recycled object.
- **TSD** — a single shared cache today (single-threaded ring-3);
  the interface is the upstream one so adding real per-thread caches
  is a local change once threads exist.

## 3. Safety budget

An allocator cannot exist without `unsafe`. Per CONTRIBUTING §1 this
ships as a dedicated safety-budget commit: justification per unit,
`docs/UNSAFE_AUDIT.md` entry, and the `safety-budget.json` bump in
the same commit. Old `huesos-user-alloc` returns 17 `unsafe` units to
the pool when it is deleted.

## 4. Verification

- host tests for every layer (size class map, checksum, quarantine,
  primary, secondary, integration incl. the audit repros);
- `make audit-check`, `make clippy`, `make test`;
- QEMU boot smoke (`make run`) — available in this environment.
