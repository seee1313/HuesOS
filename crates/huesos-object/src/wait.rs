//! Lightweight wait queues for blocking syscalls.
//!
//! Waiters are identified by scheduler task ids (`u64`). The kernel injects
//! `park` / `wake` / `current_task` callbacks so this crate stays free of a
//! dependency on `huesos-kernel` / `huesos-arch`.

use alloc::vec::Vec;
use spin::Mutex;

/// Scheduler task identifier (matches `Task::id`).
pub type TaskId = u64;

type CurrentTaskFn = fn() -> Option<TaskId>;
type ParkFn = fn();
type WakeFn = fn(TaskId);

static CURRENT_TASK_FN: Mutex<Option<CurrentTaskFn>> = Mutex::new(None);
static PARK_FN: Mutex<Option<ParkFn>> = Mutex::new(None);
static WAKE_FN: Mutex<Option<WakeFn>> = Mutex::new(None);
/// Monotonic tick counter (scheduler ticks), for wait timeouts.
static TICKS_FN: Mutex<Option<fn() -> u64>> = Mutex::new(None);

/// Register scheduler hooks. Called once from kernel init after the
/// scheduler exists.
pub fn set_scheduler_hooks(current_task: fn() -> Option<TaskId>, park: fn(), wake: fn(TaskId)) {
    *CURRENT_TASK_FN.lock() = Some(current_task);
    *PARK_FN.lock() = Some(park);
    *WAKE_FN.lock() = Some(wake);
}

/// Register a monotonic tick source used by timed waits.
pub fn set_ticks_fn(ticks: fn() -> u64) {
    *TICKS_FN.lock() = Some(ticks);
}

fn current_task_id() -> Option<TaskId> {
    (*CURRENT_TASK_FN.lock()).and_then(|f| f())
}

fn park_current() {
    if let Some(f) = *PARK_FN.lock() {
        f();
    }
}

fn wake_task(id: TaskId) {
    if let Some(f) = *WAKE_FN.lock() {
        f(id);
    }
}

fn now_ticks() -> u64 {
    (*TICKS_FN.lock()).map(|f| f()).unwrap_or(0)
}

/// FIFO wait queue of blocked tasks.
pub struct WaitQueue {
    waiters: Mutex<Vec<TaskId>>,
}

impl WaitQueue {
    /// Create an empty wait queue.
    pub const fn new() -> Self {
        Self {
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Enqueue `task` if not already waiting.
    pub fn enqueue(&self, task: TaskId) {
        let mut w = self.waiters.lock();
        if !w.contains(&task) {
            w.push(task);
        }
    }

    /// Remove a specific waiter (e.g. after wake or cancel).
    pub fn remove(&self, task: TaskId) {
        self.waiters.lock().retain(|&t| t != task);
    }

    /// Wake the oldest waiter, if any.
    pub fn wake_one(&self) {
        let id = {
            let mut w = self.waiters.lock();
            if w.is_empty() {
                None
            } else {
                Some(w.remove(0))
            }
        };
        if let Some(id) = id {
            wake_task(id);
        }
    }

    /// Wake every waiter.
    pub fn wake_all(&self) {
        let waiters = {
            let mut w = self.waiters.lock();
            core::mem::take(&mut *w)
        };
        for id in waiters {
            wake_task(id);
        }
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Park the current task on `queue` until woken.
///
/// Callers must re-check the wait condition after this returns (standard
/// lost-wakeup pattern: enqueue → recheck → park).
pub fn park_on(queue: &WaitQueue) {
    let Some(task) = current_task_id() else {
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
        return;
    };
    queue.enqueue(task);
    park_current();
    queue.remove(task);
}

/// Result of a timed park.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParkResult {
    /// Woken by a matching event (or spurious; recheck condition).
    Woken,
    /// Deadline elapsed without a wake that made us runnable in time.
    TimedOut,
}

/// Park on `queue` until woken or until `timeout_ticks` scheduler ticks elapse.
///
/// `timeout_ticks == 0` means wait forever (same as [`park_on`]).
///
/// Implementation: enqueue, then park. The scheduler tick path does not
/// auto-wake waiters; we rely on a short cooperative pattern where the
/// waker or a subsequent timed re-entry checks the deadline. For true
/// timeouts we park once and, after returning, compare ticks — but a pure
/// park never returns without wake. So we use a hybrid: register the
/// waiter and spin-park in slices of 1 tick by yielding via park only when
/// a global timer wake is available.
///
/// Practical approach used here: park, and require the kernel's
/// `wake_task` for event delivery. For timeout, the BSP idle/timer path
/// will call [`poll_timeouts`] if registered — for MVP we do a bounded
/// number of park attempts is wrong.
///
/// Instead: store deadline in a side table and have `wake` from timer
/// scan it. Simpler MVP: **busy-yield with tick check** without full park
/// when timeout is set (still blocks the task via park_current each
/// slice... we need timer to wake us).
///
/// Simplest correct MVP with existing hooks: on timeout wait, enqueue and
/// call `park_current` only after arming a one-shot by storing
/// (task, deadline) in TIMEOUTS; `notify_tick(now)` wakes expired tasks.
pub fn park_on_timeout(queue: &WaitQueue, timeout_ticks: u64) -> ParkResult {
    if timeout_ticks == 0 {
        park_on(queue);
        return ParkResult::Woken;
    }
    let Some(task) = current_task_id() else {
        return ParkResult::TimedOut;
    };
    let deadline = now_ticks().saturating_add(timeout_ticks);
    queue.enqueue(task);
    arm_timeout(task, deadline);
    park_current();
    cancel_timeout(task);
    queue.remove(task);
    if now_ticks() >= deadline {
        ParkResult::TimedOut
    } else {
        ParkResult::Woken
    }
}

struct TimeoutEntry {
    task: TaskId,
    deadline: u64,
}

static TIMEOUTS: Mutex<Vec<TimeoutEntry>> = Mutex::new(Vec::new());

fn arm_timeout(task: TaskId, deadline: u64) {
    let mut t = TIMEOUTS.lock();
    t.retain(|e| e.task != task);
    t.push(TimeoutEntry { task, deadline });
}

fn cancel_timeout(task: TaskId) {
    TIMEOUTS.lock().retain(|e| e.task != task);
}

/// Called from the scheduler timer path each tick to wake timed-out waiters.
pub fn notify_tick(now: u64) {
    let expired: Vec<TaskId> = {
        let mut t = TIMEOUTS.lock();
        let mut out = Vec::new();
        t.retain(|e| {
            if e.deadline <= now {
                out.push(e.task);
                false
            } else {
                true
            }
        });
        out
    };
    for task in expired {
        wake_task(task);
    }
}
