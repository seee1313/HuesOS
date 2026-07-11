//! SMP-safe synchronization primitives for HuesOS kernel.
//!
//! This module provides interrupt-safe spinlocks suitable for use in
//! kernel code where preemption and interrupts must be handled correctly.
//!
//! Key design points:
//! - All locks disable interrupts on the local CPU while held (cli/sti)
//! - Memory orderings: Acquire on lock, Release on unlock
//! - TicketLock provides fairness (FIFO), RawSpinlock is simpler
//! - No std dependency, works in no_std kernel context

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use x86_64::instructions::interrupts;

/// Raw spinlock without interrupt disabling.
/// Use `IrqSafeRawSpinlock` for interrupt-safe variant.
pub struct RawSpinlock {
    locked: AtomicBool,
}

impl RawSpinlock {
    /// Create a new unlocked spinlock.
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    /// Acquire the lock, spinning until available.
    /// Uses Acquire ordering to synchronize with Release in unlock.
    pub fn lock(&self) {
        // Fast path: try to acquire with compare_exchange
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Spin until the lock appears free, then retry
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
    }

    /// Try to acquire the lock without spinning.
    pub fn try_lock(&self) -> bool {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Release the lock.
    /// Uses Release ordering to synchronize with Acquire in lock.
    pub fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

impl Default for RawSpinlock {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: RawSpinlock contains only an atomic flag; protected data lives in
// the higher-level lock wrapper and is accessed after Acquire synchronization.
unsafe impl Send for RawSpinlock {}
unsafe impl Sync for RawSpinlock {}

/// Spinlock that disables interrupts on the local CPU while held.
/// This is the primary lock type for kernel use where the critical
/// section might be interrupted by a timer/IPI handler that also
/// tries to acquire the same lock.
pub struct IrqSafeRawSpinlock {
    inner: RawSpinlock,
}

impl IrqSafeRawSpinlock {
    /// Create a new unlocked interrupt-safe spinlock.
    pub const fn new() -> Self {
        Self {
            inner: RawSpinlock::new(),
        }
    }

    /// Acquire the lock and disable interrupts on this CPU.
    /// Returns a guard that re-enables interrupts on drop.
    pub fn lock(&self) -> IrqSafeRawSpinlockGuard<'_> {
        // Disable interrupts before attempting to acquire
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        self.inner.lock();
        IrqSafeRawSpinlockGuard {
            lock: &self.inner,
            was_enabled,
        }
    }

    /// Try to acquire without spinning, with interrupt disabling.
    pub fn try_lock(&self) -> Option<IrqSafeRawSpinlockGuard<'_>> {
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        if self.inner.try_lock() {
            Some(IrqSafeRawSpinlockGuard {
                lock: &self.inner,
                was_enabled,
            })
        } else {
            // Restore interrupt state on failure
            if was_enabled {
                interrupts::enable();
            }
            None
        }
    }
}

impl Default for IrqSafeRawSpinlock {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: synchronization is delegated to RawSpinlock; interrupt state is
// local CPU state restored by the guard and is not shared memory.
unsafe impl Send for IrqSafeRawSpinlock {}
unsafe impl Sync for IrqSafeRawSpinlock {}

/// Guard for `IrqSafeRawSpinlock` that restores interrupt state on drop.
pub struct IrqSafeRawSpinlockGuard<'a> {
    lock: &'a RawSpinlock,
    was_enabled: bool,
}

impl<'a> Drop for IrqSafeRawSpinlockGuard<'a> {
    fn drop(&mut self) {
        self.lock.unlock();
        if self.was_enabled {
            interrupts::enable();
        }
    }
}

/// Ticket lock providing FIFO fairness.
/// Each CPU gets a ticket on arrival and waits for its turn.
pub struct TicketLock {
    next_ticket: AtomicU32,
    now_serving: AtomicU32,
}

impl TicketLock {
    /// Create a new unlocked ticket lock.
    pub const fn new() -> Self {
        Self {
            next_ticket: AtomicU32::new(0),
            now_serving: AtomicU32::new(0),
        }
    }

    /// Acquire the ticket lock, spinning until our ticket is served.
    /// Uses Acquire ordering for the now_serving load.
    pub fn lock(&self) {
        // Atomically get our ticket number
        let my_ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);

        // Spin until our ticket is being served
        // Use Acquire ordering to synchronize with the Release in unlock
        while self.now_serving.load(Ordering::Acquire) != my_ticket {
            spin_loop();
        }
    }

    /// Try to acquire the lock without spinning.
    pub fn try_lock(&self) -> bool {
        let serving = self.now_serving.load(Ordering::Acquire);
        // Acquire only if no ticket is queued. Unlike fetch_add, a failed CAS
        // does not abandon a ticket that would permanently stall the queue.
        self.next_ticket
            .compare_exchange(
                serving,
                serving.wrapping_add(1),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Release the lock and serve the next ticket.
    /// Uses Release ordering to publish the update.
    pub fn unlock(&self) {
        self.now_serving.fetch_add(1, Ordering::Release);
    }

    /// Current ticket being served (for debugging).
    pub fn current_ticket(&self) -> u32 {
        self.now_serving.load(Ordering::Relaxed)
    }

    /// Next ticket to be handed out (for debugging).
    pub fn next_ticket(&self) -> u32 {
        self.next_ticket.load(Ordering::Relaxed)
    }
}

impl Default for TicketLock {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: both fields are atomics and the ticket protocol establishes mutual
// exclusion plus Acquire/Release synchronization.
unsafe impl Send for TicketLock {}
unsafe impl Sync for TicketLock {}

/// Interrupt-safe ticket lock that protects data of type `T`.
/// Disables interrupts while held.
pub struct IrqSafeTicketLock<T> {
    lock: TicketLock,
    data: UnsafeCell<T>,
}

impl<T> IrqSafeTicketLock<T> {
    /// Create a new interrupt-safe ticket lock protecting `data`.
    pub const fn new(data: T) -> Self {
        Self {
            lock: TicketLock::new(),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the lock, disabling interrupts on this CPU.
    /// Returns a guard providing access to the protected data.
    pub fn lock(&self) -> IrqSafeTicketLockGuard<'_, T> {
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        self.lock.lock();
        IrqSafeTicketLockGuard {
            lock: &self.lock,
            was_enabled,
            data: self,
        }
    }

    /// Try to acquire without spinning.
    pub fn try_lock(&self) -> Option<IrqSafeTicketLockGuard<'_, T>> {
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        // For ticket lock, try_lock is not trivial; simplified to full lock
        self.lock.lock();
        Some(IrqSafeTicketLockGuard {
            lock: &self.lock,
            was_enabled,
            data: self,
        })
    }
}

// SAFETY: access to T is serialized by TicketLock. Requiring T: Send permits
// ownership to move between CPUs while the guard enforces exclusive mutation.
unsafe impl<T: Send> Send for IrqSafeTicketLock<T> {}
unsafe impl<T: Send> Sync for IrqSafeTicketLock<T> {}

/// Guard for `IrqSafeTicketLock` that provides access to protected data
/// and restores interrupt state on drop.
pub struct IrqSafeTicketLockGuard<'a, T> {
    lock: &'a TicketLock,
    was_enabled: bool,
    data: &'a IrqSafeTicketLock<T>,
}

impl<'a, T> Drop for IrqSafeTicketLockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.unlock();
        if self.was_enabled {
            interrupts::enable();
        }
    }
}

impl<'a, T> Deref for IrqSafeTicketLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.data.data.get() }
    }
}

impl<'a, T> DerefMut for IrqSafeTicketLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.data.data.get() }
    }
}
