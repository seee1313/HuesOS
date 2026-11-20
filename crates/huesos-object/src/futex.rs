//! Futex wait queues: the kernel half of `Syscall::FutexWait`/`FutexWake`.
//!
//! A futex is a 32-bit word in *user* memory that threads use as an address
//! to sleep and wake on. The kernel never owns the word — it only owns a
//! queue per address, and the correctness of the whole primitive comes from
//! the userspace protocol "read, compare, enqueue, re-read, park".
//!
//! # Why the table lives on the process
//!
//! The canonical key for a futex wait is `(process koid, user address)`:
//! two processes have disjoint address spaces, so the same virtual address
//! in two processes names two unrelated words and must not share a queue.
//! Hanging the table off the [`Process`](crate::Process) object gets that
//! scoping for free and makes teardown automatic: a process that exits
//! drops its object, which drops every queue it ever created. A global
//! table would instead need an explicit "process died, sweep its entries"
//! hook, and a missed sweep would leak kernel memory for every process
//! generation (a real hazard for the restartable `acpi-manager`).
//!
//! # Why entries are removed when the last waiter leaves
//!
//! A queue only has to exist while somebody is waiting on it. Waiters
//! `acquire` before preparing to park and `release` after they are done;
//! `release` drops the map entry when its reference count reaches zero and
//! the entry still points at *that* node (compare by `Arc` identity), so a
//! fresh waiter that raced with the teardown always observes a live queue
//! rather than a detached one. Both the counter bump and the teardown run
//! under the table lock, which is what makes the check-then-remove safe.
//!
//! Wake does **not** keep the queue alive: it clones the [`Arc`], releases
//! the table lock, and only then touches the queue, so a parked thread
//! waking up and tearing its own entry down cannot deadlock against a
//! waker holding the table lock.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::irq_guard::IrqSafeMutex;
use crate::wait::WaitQueue;

/// One futex word's wait queue inside a single process.
pub struct FutexNode {
    /// Threads parked on this word.
    queue: WaitQueue,
    /// Waiters that are between `acquire` and `release`. Guarded by the
    /// owning table's lock, not an atomic: the counter and the map entry it
    /// protects must change together.
    waiters: AtomicUsize,
}

impl FutexNode {
    /// The wait queue to prepare a park on.
    pub fn queue(&self) -> &WaitQueue {
        &self.queue
    }
}

/// Per-process table of futex wait queues keyed by user virtual address.
pub struct FutexTable {
    nodes: IrqSafeMutex<BTreeMap<u64, Arc<FutexNode>>>,
}

impl FutexTable {
    /// Create an empty table. Called once from `Process::new_in_job`.
    pub fn new() -> Self {
        Self {
            nodes: IrqSafeMutex::new(BTreeMap::new()),
        }
    }

    /// Register a waiter for `uaddr` and return its queue.
    ///
    /// The returned `Arc` keeps the node alive for as long as the caller
    /// holds it, which is the whole parking window. Every successful
    /// `acquire` must be paired with exactly one [`Self::release`] — even
    /// on the error paths where the caller decides not to park at all.
    pub fn acquire(&self, uaddr: u64) -> Arc<FutexNode> {
        let mut nodes = self.nodes.lock();
        if let Some(node) = nodes.get(&uaddr) {
            node.waiters.fetch_add(1, Ordering::Relaxed);
            return Arc::clone(node);
        }
        let node = Arc::new(FutexNode {
            queue: WaitQueue::new(),
            waiters: AtomicUsize::new(1),
        });
        nodes.insert(uaddr, Arc::clone(&node));
        node
    }

    /// Drop a waiter registered by [`Self::acquire`], removing the queue
    /// when this was the last one.
    pub fn release(&self, uaddr: u64, node: &Arc<FutexNode>) {
        let mut nodes = self.nodes.lock();
        // `saturating_sub` rather than `fetch_sub`: an unmatched release is a
        // kernel bug, but it must not wrap the counter to `usize::MAX` and
        // strand the entry forever.
        let previous = node
            .waiters
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_sub(1))
            });
        let now_empty = matches!(previous, Ok(0) | Ok(1));
        // Only remove the entry if it is still *this* node: a released and
        // re-acquired address may already have a younger queue.
        if now_empty
            && nodes
                .get(&uaddr)
                .is_some_and(|current| Arc::ptr_eq(current, node))
        {
            nodes.remove(&uaddr);
        }
    }

    /// Wake up to `max_wake` waiters on `uaddr`, returning how many were
    /// woken. A wake with no waiters is `Ok(0)` and wakes nobody — see
    /// `Syscall::FutexWake` for why that is not a lost wakeup.
    pub fn wake(&self, uaddr: u64, max_wake: u32) -> usize {
        if max_wake == 0 {
            return 0;
        }
        let node = {
            let nodes = self.nodes.lock();
            match nodes.get(&uaddr) {
                Some(node) => Arc::clone(node),
                None => return 0,
            }
        };
        // The table lock is released: waking calls into the scheduler and may
        // run a woken thread immediately.
        node.queue.wake_up_to(max_wake as usize)
    }

    /// Number of live queues. Test-only introspection.
    #[cfg(test)]
    pub fn queue_count(&self) -> usize {
        self.nodes.lock().len()
    }
}

impl Default for FutexTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_release_is_balanced_and_removes_the_entry() {
        let table = FutexTable::new();
        let node = table.acquire(0x1000);
        assert_eq!(table.queue_count(), 1);
        table.release(0x1000, &node);
        assert_eq!(table.queue_count(), 0);
    }

    #[test]
    fn shared_address_keeps_the_queue_alive_until_the_last_waiter_leaves() {
        let table = FutexTable::new();
        let first = table.acquire(0x2000);
        let second = table.acquire(0x2000);
        assert!(Arc::ptr_eq(&first, &second));
        table.release(0x2000, &first);
        assert_eq!(table.queue_count(), 1);
        table.release(0x2000, &second);
        assert_eq!(table.queue_count(), 0);
    }

    #[test]
    fn release_does_not_remove_a_younger_queue_at_the_same_address() {
        let table = FutexTable::new();
        let stale = table.acquire(0x3000);
        table.release(0x3000, &stale);
        let fresh = table.acquire(0x3000);
        // A straggling release of the stale node must leave the fresh entry be.
        table.release(0x3000, &stale);
        assert_eq!(table.queue_count(), 1);
        assert!(Arc::ptr_eq(&table.acquire(0x3000), &fresh));
    }

    #[test]
    fn wake_without_waiters_is_zero() {
        let table = FutexTable::new();
        assert_eq!(table.wake(0x4000, 4), 0);
        assert_eq!(table.acquire(0x4000).waiters.load(Ordering::Relaxed), 1);
        assert_eq!(table.wake(0x4000, 0), 0);
    }
}
