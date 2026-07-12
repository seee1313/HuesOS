# Kernel Allocator Hardening

## Buddy allocator validation

The buddy allocator stores a `next` pointer in the first bytes of every free
block. This is inherently unsafe, but malformed deallocation input no longer
reaches a free-list write unchecked.

Every release-build deallocation now validates:

- non-zero page count and representable order;
- checked heap-end and allocation-end arithmetic;
- pointer lies entirely inside the heap;
- alignment relative to the heap base and complete buddy block size;
- the range is not already contained in any free block;
- every traversed free-list node is in-range and correctly aligned.

Failures return typed errors: `InvalidPointer`, `DoubleFree`,
`CorruptedFreeList`, or `InvalidSize`. Debug assertions remain useful, but
correctness no longer depends on debug builds.

Free-list traversal validates a node before reading its embedded `next` field.
A corrupted link can therefore be reported when it becomes the head/traversal
node instead of being blindly dereferenced.

## Slab validation

A slab validates slot range, slot-size alignment, pointer alignment, free-list
nodes, checked used-slot accounting, and duplicate presence before linking a
freed slot. Empty slab pages are removed from their cache and returned to the
buddy provider, preventing long-running size classes from permanently pinning
one page per historical slab.

`BuddyProvider` now pairs `allocate_page` with `deallocate_page`, making page
ownership explicit and allowing caches to roll memory back.

## Global allocator behavior

Rust's `GlobalAlloc::dealloc` contract already makes an invalid pointer caller
UB; the kernel adapter cannot return an error to the allocator API. Internally
it still uses checked deallocation and discards the result only at that final
language boundary. Direct kernel allocator users can inspect typed errors.

## Embedded ELF alignment

The hardening pass changed kernel code layout and exposed a separate latent bug:
`include_bytes!` has byte alignment, while `xmas-elf` performs naturally aligned
typed reads. Init happened to be aligned before and panicked in `zero` after an
unrelated layout shift. The embedded init ELF now lives in an explicit 16-byte
aligned static wrapper; boot correctness no longer depends on linker accident.

## Tests

Host tests cover:

- allocate/free/coalesce back to the largest block;
- non-power-of-two heap initialization;
- double buddy free rejection;
- out-of-range pointer rejection;
- slab double-free/unknown-pointer rejection;
- empty slab page return and buddy coalescing.

Clippy runs with warnings denied, followed by the full host/kernel suite and SMP
QEMU boot.
