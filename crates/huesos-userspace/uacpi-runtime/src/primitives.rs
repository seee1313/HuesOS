//! Process-local uACPI allocation, time, synchronization, and dispatch hooks.
//!
//! Hardware authority remains in the C fail-closed stubs. These callbacks use
//! only the process heap, the monotonic syscall, cooperative yield, atomics,
//! and bounded fixed-capacity synchronization registries.

use alloc::alloc::{alloc, alloc_zeroed, dealloc};
use core::alloc::Layout;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

const UACPI_STATUS_OK: i32 = 0;
const UACPI_STATUS_TIMEOUT: i32 = 18;
const UACPI_STATUS_DENIED: i32 = 20;
const ALLOCATION_ALIGNMENT: usize = 16;
const SYNC_SLOT_COUNT: usize = 64;
const TICK_NANOSECONDS: u64 = 10_000_000;
const TICK_MILLISECONDS: u64 = 10;
const THREAD_ID: usize = 1;

static DISPATCH_DEPTH: AtomicUsize = AtomicUsize::new(0);
static FALLBACK_TICKS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct MutexSlot {
    allocated: bool,
    locked: bool,
    owner: usize,
}

impl MutexSlot {
    const EMPTY: Self = Self {
        allocated: false,
        locked: false,
        owner: 0,
    };
}

#[derive(Clone, Copy)]
struct EventSlot {
    allocated: bool,
    count: u32,
}

impl EventSlot {
    const EMPTY: Self = Self {
        allocated: false,
        count: 0,
    };
}

#[derive(Clone, Copy)]
struct SpinSlot {
    allocated: bool,
    locked: bool,
}

impl SpinSlot {
    const EMPTY: Self = Self {
        allocated: false,
        locked: false,
    };
}

static MUTEXES: Mutex<[MutexSlot; SYNC_SLOT_COUNT]> =
    Mutex::new([MutexSlot::EMPTY; SYNC_SLOT_COUNT]);
static EVENTS: Mutex<[EventSlot; SYNC_SLOT_COUNT]> =
    Mutex::new([EventSlot::EMPTY; SYNC_SLOT_COUNT]);
static SPINLOCKS: Mutex<[SpinSlot; SYNC_SLOT_COUNT]> =
    Mutex::new([SpinSlot::EMPTY; SYNC_SLOT_COUNT]);

fn allocation_layout(size: usize) -> Option<Layout> {
    Layout::from_size_align(size.max(1), ALLOCATION_ALIGNMENT).ok()
}

/// Whether ACPI interrupt/event dispatch is suppressed in this process.
pub fn dispatch_suppressed() -> bool {
    DISPATCH_DEPTH.load(Ordering::Acquire) != 0
}

/// Allocate one max-align-compatible uACPI object from the process allocator.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_alloc(size: usize) -> *mut c_void {
    let Some(layout) = allocation_layout(size) else {
        return core::ptr::null_mut();
    };
    // SAFETY: layout is valid and the returned pointer is handed to uACPI,
    // which returns it through the matching sized-free callback.
    unsafe { alloc(layout).cast() }
}

/// Allocate one zero-filled max-align-compatible uACPI object.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_alloc_zeroed(size: usize) -> *mut c_void {
    let Some(layout) = allocation_layout(size) else {
        return core::ptr::null_mut();
    };
    // SAFETY: same allocation contract as uacpi_kernel_alloc; alloc_zeroed
    // additionally initializes every byte in the valid layout.
    unsafe { alloc_zeroed(layout).cast() }
}

/// Release an allocation using uACPI's exact size hint.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_free(memory: *mut c_void, size_hint: usize) {
    if memory.is_null() {
        return;
    }
    let Some(layout) = allocation_layout(size_hint) else {
        return;
    };
    // SAFETY: UACPI_SIZED_FREES makes uACPI return the original allocation
    // size. The pointer came from one of the two callbacks above.
    unsafe { dealloc(memory.cast(), layout) };
}

/// Return monotonic time in nanoseconds using the 100 Hz kernel clock.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_get_nanoseconds_since_boot() -> u64 {
    now_ticks().saturating_mul(TICK_NANOSECONDS)
}

/// Perform a bounded sub-millisecond cooperative CPU stall.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_stall(microseconds: u8) {
    let iterations = usize::from(microseconds).saturating_mul(50).max(1);
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}

/// Sleep for at least the requested milliseconds, rounded to scheduler ticks.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_sleep(milliseconds: u64) {
    if milliseconds == 0 {
        return;
    }
    let ticks = milliseconds.div_ceil(TICK_MILLISECONDS).max(1);
    let deadline = now_ticks().saturating_add(ticks);
    while now_ticks() < deadline {
        cooperative_yield();
    }
}

/// Allocate one non-recursive mutex handle from the fixed registry.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_create_mutex() -> *mut c_void {
    let mut slots = MUTEXES.lock();
    for (index, slot) in slots.iter_mut().enumerate() {
        if !slot.allocated {
            *slot = MutexSlot {
                allocated: true,
                locked: false,
                owner: 0,
            };
            return handle_from_index(index);
        }
    }
    core::ptr::null_mut()
}

/// Free one unlocked mutex handle. Invalid handles are ignored fail-closed.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_free_mutex(handle: *mut c_void) {
    let Some(index) = index_from_handle(handle) else {
        return;
    };
    let mut slots = MUTEXES.lock();
    if slots[index].allocated && !slots[index].locked {
        slots[index] = MutexSlot::EMPTY;
    }
}

/// Acquire one non-recursive mutex using uACPI millisecond timeout semantics.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_acquire_mutex(handle: *mut c_void, timeout: u16) -> i32 {
    let Some(index) = index_from_handle(handle) else {
        return UACPI_STATUS_DENIED;
    };
    let deadline = finite_deadline(timeout);
    loop {
        {
            let mut slots = MUTEXES.lock();
            let slot = &mut slots[index];
            if !slot.allocated {
                return UACPI_STATUS_DENIED;
            }
            if !slot.locked {
                slot.locked = true;
                slot.owner = THREAD_ID;
                return UACPI_STATUS_OK;
            }
            if slot.owner == THREAD_ID {
                return UACPI_STATUS_DENIED;
            }
        }
        if timeout == 0 || deadline.is_some_and(|limit| now_ticks() >= limit) {
            return UACPI_STATUS_TIMEOUT;
        }
        cooperative_yield();
    }
}

/// Release a mutex owned by the current userspace thread.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_release_mutex(handle: *mut c_void) {
    let Some(index) = index_from_handle(handle) else {
        return;
    };
    let mut slots = MUTEXES.lock();
    let slot = &mut slots[index];
    if slot.allocated && slot.locked && slot.owner == THREAD_ID {
        slot.locked = false;
        slot.owner = 0;
    }
}

/// Allocate one counted event handle.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_create_event() -> *mut c_void {
    let mut slots = EVENTS.lock();
    for (index, slot) in slots.iter_mut().enumerate() {
        if !slot.allocated {
            *slot = EventSlot {
                allocated: true,
                count: 0,
            };
            return handle_from_index(index);
        }
    }
    core::ptr::null_mut()
}

/// Free an event handle and discard its pending count.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_free_event(handle: *mut c_void) {
    let Some(index) = index_from_handle(handle) else {
        return;
    };
    let mut slots = EVENTS.lock();
    if slots[index].allocated {
        slots[index] = EventSlot::EMPTY;
    }
}

/// Wait for and consume one event count.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_wait_for_event(handle: *mut c_void, timeout: u16) -> bool {
    let Some(index) = index_from_handle(handle) else {
        return false;
    };
    let deadline = finite_deadline(timeout);
    loop {
        {
            let mut slots = EVENTS.lock();
            let slot = &mut slots[index];
            if !slot.allocated {
                return false;
            }
            if slot.count != 0 {
                slot.count -= 1;
                return true;
            }
        }
        if timeout == 0 || deadline.is_some_and(|limit| now_ticks() >= limit) {
            return false;
        }
        cooperative_yield();
    }
}

/// Increment an event count without wrapping.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_signal_event(handle: *mut c_void) {
    let Some(index) = index_from_handle(handle) else {
        return;
    };
    let mut slots = EVENTS.lock();
    let slot = &mut slots[index];
    if slot.allocated {
        slot.count = slot.count.saturating_add(1);
    }
}

/// Reset an event count to zero.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_reset_event(handle: *mut c_void) {
    let Some(index) = index_from_handle(handle) else {
        return;
    };
    let mut slots = EVENTS.lock();
    if slots[index].allocated {
        slots[index].count = 0;
    }
}

/// Return the sole AP-4 userspace thread identity.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_get_thread_id() -> *mut c_void {
    THREAD_ID as *mut c_void
}

/// Suppress ACPI event dispatch and return the previous nesting depth.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_disable_interrupts() -> usize {
    DISPATCH_DEPTH.fetch_add(1, Ordering::AcqRel)
}

/// Restore a nesting depth returned by `uacpi_kernel_disable_interrupts`.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_restore_interrupts(state: usize) {
    DISPATCH_DEPTH.store(state, Ordering::Release);
}

/// Allocate one process-local spin/dispatch lock.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_create_spinlock() -> *mut c_void {
    let mut slots = SPINLOCKS.lock();
    for (index, slot) in slots.iter_mut().enumerate() {
        if !slot.allocated {
            *slot = SpinSlot {
                allocated: true,
                locked: false,
            };
            return handle_from_index(index);
        }
    }
    core::ptr::null_mut()
}

/// Free one unlocked process-local spin/dispatch lock.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_free_spinlock(handle: *mut c_void) {
    let Some(index) = index_from_handle(handle) else {
        return;
    };
    let mut slots = SPINLOCKS.lock();
    if slots[index].allocated && !slots[index].locked {
        slots[index] = SpinSlot::EMPTY;
    }
}

/// Lock one process-local spinlock and suppress ACPI event dispatch.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_lock_spinlock(handle: *mut c_void) -> usize {
    let previous_dispatch = uacpi_kernel_disable_interrupts();
    let Some(index) = index_from_handle(handle) else {
        return previous_dispatch;
    };
    loop {
        {
            let mut slots = SPINLOCKS.lock();
            let slot = &mut slots[index];
            if !slot.allocated {
                return previous_dispatch;
            }
            if !slot.locked {
                slot.locked = true;
                return previous_dispatch;
            }
        }
        core::hint::spin_loop();
    }
}

/// Unlock one process-local spinlock and restore dispatch state.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_unlock_spinlock(handle: *mut c_void, flags: usize) {
    if let Some(index) = index_from_handle(handle) {
        let mut slots = SPINLOCKS.lock();
        if slots[index].allocated {
            slots[index].locked = false;
        }
    }
    uacpi_kernel_restore_interrupts(flags);
}

fn finite_deadline(timeout: u16) -> Option<u64> {
    match timeout {
        0 | u16::MAX => None,
        value => {
            Some(now_ticks().saturating_add(u64::from(value).div_ceil(TICK_MILLISECONDS).max(1)))
        }
    }
}

fn handle_from_index(index: usize) -> *mut c_void {
    (index + 1) as *mut c_void
}

fn index_from_handle(handle: *mut c_void) -> Option<usize> {
    let raw = handle as usize;
    if (1..=SYNC_SLOT_COUNT).contains(&raw) {
        Some(raw - 1)
    } else {
        None
    }
}

#[cfg(not(test))]
fn now_ticks() -> u64 {
    match libcanvas::system::monotonic_ticks() {
        Ok(ticks) => ticks,
        Err(_) => FALLBACK_TICKS.load(Ordering::Acquire),
    }
}

#[cfg(test)]
fn now_ticks() -> u64 {
    FALLBACK_TICKS.load(Ordering::Acquire)
}

fn cooperative_yield() {
    #[cfg(not(test))]
    libcanvas::process::yield_now();
    FALLBACK_TICKS.fetch_add(1, Ordering::AcqRel);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        *MUTEXES.lock() = [MutexSlot::EMPTY; SYNC_SLOT_COUNT];
        *EVENTS.lock() = [EventSlot::EMPTY; SYNC_SLOT_COUNT];
        *SPINLOCKS.lock() = [SpinSlot::EMPTY; SYNC_SLOT_COUNT];
        DISPATCH_DEPTH.store(0, Ordering::Release);
        FALLBACK_TICKS.store(0, Ordering::Release);
    }

    #[test]
    fn allocation_time_mutex_event_and_dispatch_contracts() {
        reset();

        let allocation = uacpi_kernel_alloc(37);
        assert!(!allocation.is_null());
        uacpi_kernel_free(allocation, 37);
        let zeroed = uacpi_kernel_alloc_zeroed(64);
        assert!(!zeroed.is_null());
        uacpi_kernel_free(zeroed, 64);

        assert_eq!(uacpi_kernel_get_nanoseconds_since_boot(), 0);
        uacpi_kernel_sleep(11);
        assert!(uacpi_kernel_get_nanoseconds_since_boot() >= 20_000_000);

        let mutex = uacpi_kernel_create_mutex();
        assert!(!mutex.is_null());
        assert_eq!(uacpi_kernel_acquire_mutex(mutex, 0), UACPI_STATUS_OK);
        assert_eq!(uacpi_kernel_acquire_mutex(mutex, 0), UACPI_STATUS_DENIED);
        uacpi_kernel_release_mutex(mutex);
        assert_eq!(uacpi_kernel_acquire_mutex(mutex, 1), UACPI_STATUS_OK);
        uacpi_kernel_release_mutex(mutex);
        uacpi_kernel_free_mutex(mutex);

        let event = uacpi_kernel_create_event();
        assert!(!event.is_null());
        assert!(!uacpi_kernel_wait_for_event(event, 1));
        uacpi_kernel_signal_event(event);
        uacpi_kernel_signal_event(event);
        assert!(uacpi_kernel_wait_for_event(event, 0));
        uacpi_kernel_reset_event(event);
        assert!(!uacpi_kernel_wait_for_event(event, 0));
        uacpi_kernel_free_event(event);

        let spin = uacpi_kernel_create_spinlock();
        assert!(!spin.is_null());
        let flags = uacpi_kernel_lock_spinlock(spin);
        assert!(dispatch_suppressed());
        uacpi_kernel_unlock_spinlock(spin, flags);
        assert!(!dispatch_suppressed());
        uacpi_kernel_free_spinlock(spin);
    }

    #[test]
    fn fixed_registries_exhaust_without_aliasing() {
        reset();
        let mut handles = [core::ptr::null_mut(); SYNC_SLOT_COUNT];
        for slot in &mut handles {
            *slot = uacpi_kernel_create_event();
            assert!(!slot.is_null());
        }
        assert!(uacpi_kernel_create_event().is_null());
        for handle in handles {
            uacpi_kernel_free_event(handle);
        }
    }

    #[test]
    fn invalid_handles_fail_closed() {
        reset();
        let invalid = (SYNC_SLOT_COUNT + 1) as *mut c_void;
        assert_eq!(uacpi_kernel_acquire_mutex(invalid, 0), UACPI_STATUS_DENIED);
        assert!(!uacpi_kernel_wait_for_event(invalid, 0));
        uacpi_kernel_release_mutex(invalid);
        uacpi_kernel_signal_event(invalid);
    }

    #[test]
    fn allocation_layout_is_bounded_and_max_aligned() {
        assert!(allocation_layout(0).is_some_and(|layout| {
            layout.size() == 1 && layout.align() == ALLOCATION_ALIGNMENT
        }));
        assert!(allocation_layout(usize::MAX).is_none());
    }
}
