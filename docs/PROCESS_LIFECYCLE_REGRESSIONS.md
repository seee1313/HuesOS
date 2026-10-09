# Process lifecycle regression coverage

## Purpose

Keep exit observation immutable and task identity generation-safe while testing
actual integrated objects and directory helpers rather than duplicating their
algorithms in a policy-only test. No lifecycle or scheduler implementation is
rewritten by this change.

## Host tests

`make test` includes `huesos-object`, `huesos-lifecycle`, and now explicitly
`huesos-sched`. The added tests cover:

- exit before the first async poll, repeated waits and first-exit-code wins;
- multiple distinct async wakers, repeated Pending polls with waker deduplication,
  wake-on-exit and immutable status after a competing exit;
- cancellation/release of counted blocking waiters before exit;
- eight counted observers coordinated by barriers: exit remains Exited until
  the last registered observer releases its count, then becomes Reaped;
- eight simultaneous exit attempts with exactly one successful transition;
- early and late port subscription delivering the same generation and signed
  exit code, with kernel-reference return on process drop;
- 4096 actual Process exits feeding TaskGraveyard<256>, exact eviction/accounting
  totals and final drain;
- stale koid/generation observation after eviction, and zero-capacity behavior;
- TaskSlotAllocator + TaskDirectory reuse: pending operations block clearing,
  then delayed old-generation wake, consume and duplicate clear are rejected;
- 4096 serial reuse cycles with no stale wake affecting a replacement identity.

Tests use per-test process objects, counters and barriers, not global scheduler
hooks. Host thread scheduling is not a model checker. Directory tests place
stale operations *after* reuse: they do not prove the concurrent
check-to-clear/republication window safe. Slot-generation exhaustion and CPU
migration are separate contracts.

The two generations are different domains: a Process ExitInfo generation is
not a scheduler TaskId generation. The tests preserve each in its own API.

## On-target gate

Init's existing 32/256-exit probe now repeats `wait_exit` and `poll_exit` after
the first successful wait on every process handle. The default QEMU boot smoke
requires both the existing lifecycle marker and:

```text
[init] ProcessWait repeated observation OK
```

The first wait exercises the blocking-capable syscall; whether a specific
iteration actually parks depends on scheduling. A yielding child does not by
itself establish that every iteration blocked. The marker is evidence of
completed calls, not an instrumented blocked-wait count.

Run `make audit-check`, `make clippy`, `make test`, and
`bash scripts/ci-qemu-smoke.sh <debug|release> <1|2> 360` on the pinned toolchain.
Verification results and log paths belong in the commit/PR. Longer 256-exit soak,
bare-metal, faulting output pointers and exhaustive concurrency interleavings
are not implied by a passing default smoke.

## Still open

- Cancellation/drop cleanup of registered async wakers is not addressed.
- Port bind racing exit and full-port delivery failure require separate review;
  the early/late test covers sequential bindings, not those races.
- `observed_exit_generation` currently checks published exit identity, not a
  proof that userspace successfully copied the status. Reaped is a lifecycle
  policy state, not evidence that every stack/page-table/task Arc is gone.
- Exact full-system resource baseline under long SMP storms still needs soak
  diagnostics; the bounded host graveyard test is not a kernel reaper soak.

## Pre-existing reaper integration defect (base 71776eb)

A separate host reproduction against the base helpers performed this sequence:

1. allocate slot/generation and publish the old TaskId;
2. publish WAKE for the old identity (returns Ok(true));
3. free/reallocate the slot without directory clear, as in the current kernel
   reaper's slot-release sequence;
4. publish the replacement generation;
5. take operations for the replacement: actual Ok(1), expected Ok(0).

`TaskDirectory::publish` retains pending bits, and the current kernel reaper
releases the global slot without calling directory clear/drain. This is a
reproduced helper-sequence defect, not an on-target exploit or an assertion
that the full kernel race was triggered. The newly added helper tests use the
sequential drain/clear protocol and do not cover this current integration gap.
No failing reproduction is disguised as a green/ignored regression.

There is also a separate check-then-fetch_or window in publish_operations;
merely zeroing pending bits on publication would not close concurrent reuse.
A publisher can validate the old ID, pause until after reuse/reset, then OR its
bits into the replacement. Clear's empty-bits check is also separate from
concurrent publication. The kernel inbox carries slot indexes, and its consumer
reads the current identity, so later validation of that current identity does
not identify the original operation's generation.

The possible kernel consequence is a spurious wake of a replacement occupant.
Whether all wait sites tolerate that by rechecking their conditions has not
been audited here. Neither memory unsafety/exploitability nor harmlessness is
established.
Fixing publication/reclamation synchronization requires a separate production
change with an explicit protocol and race regressions. No such fix is claimed
by this test PR.
