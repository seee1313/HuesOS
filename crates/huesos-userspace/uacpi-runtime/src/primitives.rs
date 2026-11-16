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

/// Store one scalar into caller-validated output storage. All host
/// callbacks that write `out_*` results funnel through this single site
/// so the crate's unsafe surface stays minimal and auditable.
pub(crate) fn store_scalar<T>(slot: *mut T, value: T) {
    // SAFETY: callers validate the output pointer non-null before
    // calling and the pointee outlives the call (uACPI stack frame);
    // each call writes exactly one `T`.
    unsafe {
        *slot = value;
    }
}

/// Shared allocator front-end. `zeroed` selects zero-filled frames;
/// the allocation contract (max-align, handed to uACPI, returned through
/// the matching sized-free callback) is identical either way.
fn alloc_impl(size: usize, zeroed: bool) -> *mut c_void {
    let Some(layout) = allocation_layout(size) else {
        return core::ptr::null_mut();
    };
    // SAFETY: layout is valid and the returned pointer is handed to uACPI,
    // which returns it through the matching sized-free callback. On the
    // zeroed path every byte is additionally initialized.
    unsafe {
        match zeroed {
            true => alloc_zeroed(layout).cast(),
            false => alloc(layout).cast(),
        }
    }
}

/// Allocate one max-align-compatible uACPI object from the process allocator.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_alloc(size: usize) -> *mut c_void {
    alloc_impl(size, false)
}

/// Allocate one zero-filled max-align-compatible uACPI object.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_alloc_zeroed(size: usize) -> *mut c_void {
    alloc_impl(size, true)
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
    extern crate std;

    use super::*;

    // The callbacks and the fixtures operate on process-global registries.
    // Serialize the suite so one test cannot reset another test's slots
    // mid-flight (which is exactly what the 5 ms foreign-release window hits).
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset() {
        *MUTEXES.lock() = [MutexSlot::EMPTY; SYNC_SLOT_COUNT];
        *EVENTS.lock() = [EventSlot::EMPTY; SYNC_SLOT_COUNT];
        *SPINLOCKS.lock() = [SpinSlot::EMPTY; SYNC_SLOT_COUNT];
        DISPATCH_DEPTH.store(0, Ordering::Release);
        FALLBACK_TICKS.store(0, Ordering::Release);
    }

    #[test]
    fn allocation_time_mutex_event_and_dispatch_contracts() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
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
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
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
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        let invalid = (SYNC_SLOT_COUNT + 1) as *mut c_void;
        assert_eq!(uacpi_kernel_acquire_mutex(invalid, 0), UACPI_STATUS_DENIED);
        assert!(!uacpi_kernel_wait_for_event(invalid, 0));
        uacpi_kernel_release_mutex(invalid);
        uacpi_kernel_signal_event(invalid);
    }

    #[test]
    fn allocation_layout_is_bounded_and_max_aligned() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        assert!(allocation_layout(0).is_some_and(|layout| {
            layout.size() == 1 && layout.align() == ALLOCATION_ALIGNMENT
        }));
        assert!(allocation_layout(usize::MAX).is_none());
    }

    #[test]
    fn timeout_trio_zero_finite_and_infinite() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        // Own no lock; a foreign thread holding the mutex exercises the wait
        // paths. Slot 0 is forced into the foreign-locked state directly.
        let mutex = uacpi_kernel_create_mutex();
        assert!(!mutex.is_null());
        {
            let mut slots = MUTEXES.lock();
            slots[0].locked = true;
            slots[0].owner = 999;
        }

        // Zero timeout: exactly one attempt, then TIMEOUT.
        let ticks_before = FALLBACK_TICKS.load(Ordering::Acquire);
        assert_eq!(uacpi_kernel_acquire_mutex(mutex, 0), UACPI_STATUS_TIMEOUT);
        assert_eq!(FALLBACK_TICKS.load(Ordering::Acquire), ticks_before);

        // Finite timeout (30 ms at 10 ms/tick): waits for three ticks, then TIMEOUT.
        assert_eq!(uacpi_kernel_acquire_mutex(mutex, 30), UACPI_STATUS_TIMEOUT);
        let elapsed = FALLBACK_TICKS.load(Ordering::Acquire) - ticks_before;
        assert!(
            elapsed >= 3,
            "finite timeout did not consume ticks: {elapsed}"
        );

        // Infinite timeout (u16::MAX): the pre-satisfied case answers immediately.
        {
            let mut slots = MUTEXES.lock();
            slots[0].locked = false;
            slots[0].owner = 0;
        }
        assert_eq!(uacpi_kernel_acquire_mutex(mutex, u16::MAX), UACPI_STATUS_OK);
        uacpi_kernel_release_mutex(mutex);
        // The indefinite branch is encoded as "no deadline".
        assert!(finite_deadline(u16::MAX).is_none());
        assert!(finite_deadline(0).is_none());
        uacpi_kernel_free_mutex(mutex);
    }

    #[test]
    fn finite_deadline_rounds_ms_up_to_ticks() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        let base = now_ticks();
        assert_eq!(finite_deadline(1), Some(base + 1));
        assert_eq!(finite_deadline(10), Some(base + 1));
        assert_eq!(finite_deadline(11), Some(base + 2));
        assert_eq!(finite_deadline(100), Some(base + 10));
    }

    #[test]
    fn infinite_timeout_waits_for_foreign_release() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        let mutex = uacpi_kernel_create_mutex();
        assert!(!mutex.is_null());
        {
            let mut slots = MUTEXES.lock();
            slots[0].locked = true;
            slots[0].owner = 999;
        }
        let releaser = std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(5));
            let mut slots = MUTEXES.lock();
            slots[0].locked = false;
            slots[0].owner = 0;
        });
        // An unbounded wait must not time out while the foreign owner holds the
        // mutex; it completes only after the releaser runs.
        assert_eq!(uacpi_kernel_acquire_mutex(mutex, u16::MAX), UACPI_STATUS_OK);
        assert!(releaser.join().is_ok(), "releaser thread panicked");
        uacpi_kernel_release_mutex(mutex);
        uacpi_kernel_free_mutex(mutex);
    }

    #[test]
    fn recursion_is_rejected_instead_of_deadlocking() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        let mutex = uacpi_kernel_create_mutex();
        assert_eq!(uacpi_kernel_acquire_mutex(mutex, 0), UACPI_STATUS_OK);
        // Same-thread recursion never borrows the timeout path.
        assert_eq!(uacpi_kernel_acquire_mutex(mutex, 0), UACPI_STATUS_DENIED);
        assert_eq!(
            uacpi_kernel_acquire_mutex(mutex, u16::MAX),
            UACPI_STATUS_DENIED
        );
        uacpi_kernel_release_mutex(mutex);
        assert_eq!(uacpi_kernel_acquire_mutex(mutex, 0), UACPI_STATUS_OK);
        uacpi_kernel_release_mutex(mutex);
        uacpi_kernel_free_mutex(mutex);
    }

    #[test]
    fn event_signal_before_wait_and_multiple_signals() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        let event = uacpi_kernel_create_event();
        assert!(!event.is_null());
        // Signals raised before the first wait are preserved and consumable.
        uacpi_kernel_signal_event(event);
        uacpi_kernel_signal_event(event);
        uacpi_kernel_signal_event(event);
        assert!(uacpi_kernel_wait_for_event(event, 0));
        assert!(uacpi_kernel_wait_for_event(event, 0));
        assert!(uacpi_kernel_wait_for_event(event, 0));
        // All pending counts consumed; the next wait fails immediately.
        assert!(!uacpi_kernel_wait_for_event(event, 0));
        uacpi_kernel_free_event(event);
    }

    #[test]
    fn event_signal_saturation_does_not_wrap() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        let event = uacpi_kernel_create_event();
        assert!(!event.is_null());
        EVENTS.lock()[0].count = u32::MAX;
        uacpi_kernel_signal_event(event);
        assert_eq!(EVENTS.lock()[0].count, u32::MAX);
        // All saturated counts remain consumable.
        assert!(uacpi_kernel_wait_for_event(event, 0));
        assert_eq!(EVENTS.lock()[0].count, u32::MAX - 1);
        uacpi_kernel_free_event(event);
    }

    #[test]
    fn event_teardown_discards_counts_and_slot_reuse_is_clean() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        let event = uacpi_kernel_create_event();
        uacpi_kernel_signal_event(event);
        uacpi_kernel_free_event(event);
        // Stale handle is inert after teardown.
        assert!(!uacpi_kernel_wait_for_event(event, 0));
        uacpi_kernel_signal_event(event);
        uacpi_kernel_reset_event(event);
        // Slot reuse starts from count == 0, not the discarded residue.
        let reused = uacpi_kernel_create_event();
        assert_eq!(reused, event);
        assert!(!uacpi_kernel_wait_for_event(reused, 0));
        uacpi_kernel_free_event(reused);
    }

    #[test]
    fn mutex_teardown_rejects_locked_handles() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        let mutex = uacpi_kernel_create_mutex();
        assert_eq!(uacpi_kernel_acquire_mutex(mutex, 0), UACPI_STATUS_OK);
        // A locked mutex cannot disappear underneath its owner.
        uacpi_kernel_free_mutex(mutex);
        assert!(MUTEXES.lock()[0].allocated);
        uacpi_kernel_release_mutex(mutex);
        uacpi_kernel_free_mutex(mutex);
        assert!(!MUTEXES.lock()[0].allocated);
    }

    #[test]
    fn allocation_failure_points_fail_closed() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        // usize::MAX layouts cannot be constructed; both alloc callbacks report failure.
        assert!(uacpi_kernel_alloc(usize::MAX).is_null());
        assert!(uacpi_kernel_alloc_zeroed(usize::MAX).is_null());
        assert_eq!(
            uacpi_kernel_acquire_mutex(core::ptr::null_mut(), 0),
            UACPI_STATUS_DENIED
        );
        // Fixed registries report exhaustion instead of reusing a live slot.
        let mut mutexes = [core::ptr::null_mut(); SYNC_SLOT_COUNT];
        for handle in &mut mutexes {
            *handle = uacpi_kernel_create_mutex();
            assert!(!handle.is_null());
        }
        assert!(uacpi_kernel_create_mutex().is_null());
        let mut spinlocks = [core::ptr::null_mut(); SYNC_SLOT_COUNT];
        for handle in &mut spinlocks {
            *handle = uacpi_kernel_create_spinlock();
            assert!(!handle.is_null());
        }
        assert!(uacpi_kernel_create_spinlock().is_null());
        for handle in spinlocks {
            uacpi_kernel_free_spinlock(handle);
        }
        for handle in mutexes {
            uacpi_kernel_free_mutex(handle);
        }
    }

    #[test]
    fn monotonicity_and_overflow_boundaries() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        assert_eq!(uacpi_kernel_get_nanoseconds_since_boot(), 0);
        FALLBACK_TICKS.store(2, Ordering::Release);
        assert_eq!(uacpi_kernel_get_nanoseconds_since_boot(), 20_000_000);
        // Tick-to-nanosecond conversion saturates instead of wrapping.
        FALLBACK_TICKS.store(u64::MAX, Ordering::Release);
        assert_eq!(uacpi_kernel_get_nanoseconds_since_boot(), u64::MAX);
        // Deadline arithmetic saturates at u64::MAX.
        FALLBACK_TICKS.store(u64::MAX - 1, Ordering::Release);
        assert_eq!(finite_deadline(100), Some(u64::MAX));
        reset();
        assert_eq!(uacpi_kernel_get_nanoseconds_since_boot(), 0);
    }

    #[test]
    fn stable_thread_id_and_dispatch_nesting() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        reset();
        let first = uacpi_kernel_get_thread_id();
        assert!(!first.is_null());
        assert_eq!(first as usize, uacpi_kernel_get_thread_id() as usize);
        let base = uacpi_kernel_disable_interrupts();
        let nested = uacpi_kernel_disable_interrupts();
        assert_eq!(nested, base + 1);
        assert!(dispatch_suppressed());
        uacpi_kernel_restore_interrupts(nested);
        assert!(dispatch_suppressed());
        uacpi_kernel_restore_interrupts(base);
        assert!(!dispatch_suppressed());
    }

    // The suite intentionally does not exercise a host-allocator OOM: the host
    // global allocator cannot be forced to fail deterministically. Every
    // uACPI-visible allocation *point* instead fails through the two
    // deterministic paths above (layout construction and registry exhaustion).
    // Callbacks never block while holding the allocator-internal lock (they
    // call the process heap directly) and hold only the process-local spin
    // slot mutexes, which are leaf locks; no IRQ-delivery path runs in this
    // crate, so no IRQ lock can be held across any callback.
}
