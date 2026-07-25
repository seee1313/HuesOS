# Async Architecture: Ring 0 + Ring 3 Universal Async

**Status: IMPLEMENTED (foundation). Per-CPU executor and IRQ bridge are follow-ups.**

## Core Principles

### 1. Reactor = Scheduler (drain → wake only)

The scheduler IS the async reactor. There is no separate reactor thread
or event loop. Timer interrupts drain hardware events and wake scheduler
tasks via `wait::notify_tick`. IRQ handlers wake tasks through the same
mechanism. The executor (future polling) runs in task context, not
interrupt context.

```
IRQ / Timer (reactor path)          Task context (executor path)
───────────────────────────          ────────────────────────────
• Drain hardware events              • scope_on / run_sync polls
• Set ready bits / wake_task           ready futures
• Never poll futures                 • park_current() yields to
• Never block                          scheduler when pending
• Allocation-free                    • May allocate in future body
                                        (if caller chooses)
```

### 2. block_on vs spawn: Clear Separation

| | `block_on` / `scope_on` / `run_sync` | `spawn` |
|---|---|---|
| **Lifetime** | Borrows allowed (non-`'static`) | Must be `'static` |
| **Storage** | Stack-pinned (caller's frame) | Inline in executor slot |
| **Concurrency** | Single future, blocks caller | Multiple concurrent tasks |
| **Cancellation** | Drop the future | TaskId-based (future work) |
| **Ring 0 usage** | `async_rt::run_sync(fut)` | Reserved (future: persistent kernel tasks) |
| **Ring 3 usage** | `hues_async::block_on(fut, park)` | `executor.spawn(fut)` |

### 3. Completion / Payload Model

Three strategies for different workloads. Async primitives NEVER "read
into an arbitrary user buffer as the async essence":

#### Inline Metadata (short IPC)
- **PortPacket**: fixed-size 40-byte payload delivered directly.
- **Use case**: IRQ notifications, event signals, short commands.
- **Async primitive**: `port.recv().await` returns inline packet.

#### Shared Ring / Completion Queue (stream I/O)
- **Ring buffer**: pre-allocated, shared between producer (IRQ) and
  consumer (driver task). Producer writes entries; consumer polls
  or awaits completion.
- **Use case**: NVMe completion queue, network RX rings.
- **Async primitive**: `cq.await_entry().await` returns ring entry.

#### Peek & Claim (large IPC / channels)
- **Two-phase**: `peek()` inspects the front message (size, handle
  count, opaque cookie) without dequeueing. `consume(cookie)` dequeues
  only the identified message.
- **Use case**: Channel IPC with handle transfer, bootstrap protocol.
- **Async primitive**: `channel.recv().await` uses peek/consume internally.

```rust
// Peek & Claim in action
async fn handle_bootstrap(channel: &Channel) -> Result<...> {
    let (size, handles, cookie) = channel.peek().await?;
    if size > MAX_BOOTSTRAP_SIZE {
        channel.consume(cookie).await; // discard oversized
        return Err(TooLarge);
    }
    let msg = channel.consume(cookie).await?;
    // msg is the exact message peek identified
    process(msg)
}
```

### 4. Kernel Await / Lock Rules

**Rule 1: Never hold a ranked lock across `.await`.**

All `RankedIrqSafeTicketLock` guards must be dropped before any await
point. The park callback (called when a future returns `Pending`) yields
to the scheduler, which may acquire ranked locks. Holding a lock across
this boundary risks deadlock.

```rust
// WRONG: lock held across await
let guard = some_lock.lock();
let result = channel.recv().await; // DEADLOCK RISK
drop(guard);

// CORRECT: release lock before await
let snapshot = {
    let guard = some_lock.lock();
    guard.snapshot()
}; // lock released here
let result = channel.recv().await; // safe
```

**Rule 2: `run_sync` requires interrupts enabled.**

The park callback uses `park_current()` which disables interrupts
internally. Calling with interrupts already disabled would nest the
disable/enable incorrectly.

**Rule 3: Scheduler lock is never held across await.**

The scheduler's `PER_CPU_SCHEDULERS` lock is released before context
switch. This is already enforced by the existing `park_current()`
implementation.

### 5. Capacity Errors as Policy

When an executor's spawn slots are full, a channel's message queue is
at quota, or a port's packet ring is saturated, the result is a normal
`Err` — never a panic. Callers must handle these as admission control:

- `SpawnError::Full` → retry later or shed load
- `ChannelSendError::QuotaExceeded` → backpressure or drop
- `PortQueueError::QuotaExceeded` → increment drop counter

The safety budget enforces: no `unwrap()`, `expect()`, or `panic!` in
admission paths. These errors are architectural, not exceptional.

## Roadmap

| # | Step | Status |
|---|------|--------|
| 1 | Backend trait + KernelBackend + UserBackend | ✅ Merged (PR #85) |
| 2 | Executor generic over Backend + scope_on | ✅ Merged (PR #85) |
| 3 | Per-CPU async runtime module (async_rt) | ✅ This compare |
| 4 | WaitQueue ↔ Waker bridge | 📋 Future |
| 5 | Async Recv future (channel) | 📋 Future |
| 6 | Async Sleep future (timer) | 📋 Future |
| 7 | sys_waitset_wait (multiplex) | 📋 Future |
| 8 | IRQ → reactor wake (keyboard/NVMe) | 📋 Future |
| 9 | Async ProcessWait future | 📋 Future |
| 10 | Init system on async | 📋 Future |

## References

- [OSDI '23: Theseus OS async](https://www.usenix.org/conference/osdi23)
- [Fuchsia: async in the Zircon kernel](https://fuchsia.dev/fuchsia-src/concepts/kernel/async)
- [Tokio runtime model](https://tokio.rs/tokio/tutorial/async)
