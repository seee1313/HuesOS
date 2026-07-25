//! Lightweight wait queues for blocking syscalls.
//!
//! Waiters are identified by scheduler task ids (`u64`). The kernel injects
//! `park` / `wake` / `current_task` callbacks so this crate stays free of a
//! dependency on `huesos-kernel` / `huesos-arch`.

use alloc::vec::Vec;
use core::task::Waker;
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

/// Yield to the scheduler without parking on a wait queue.
///
/// Used by blocking helpers when [`WaitQueue::prepare`] returns `None`
/// (scheduler not yet initialized during early boot). The task stays
/// runnable and simply re-checks on the next poll.
pub fn yield_to_scheduler() {
    park_current();
}

/// FIFO wait queue of blocked tasks.
///
/// Supports two waiter types: scheduler tasks (blocking syscalls)
/// and async wakers (futures). When wake_one/wake_all fires,
/// both types are notified.
pub struct WaitQueue {
    waiters: Mutex<Vec<TaskId>>,
    async_wakers: Mutex<Vec<Waker>>,
}

impl WaitQueue {
    /// Create an empty wait queue.
    pub const fn new() -> Self {
        Self {
            waiters: Mutex::new(Vec::new()),
            async_wakers: Mutex::new(Vec::new()),
        }
    }

    /// Register an async waker. When wake_one/wake_all fires,
    /// the waker is invoked so the future re-polls.
    pub fn register_waker(&self, waker: &Waker) {
        let mut wakers = self.async_wakers.lock();
        for existing in wakers.iter_mut() {
            if existing.will_wake(waker) {
                return;
            }
        }
        wakers.push(waker.clone());
    }

    /// Remove all registered async wakers.
    pub fn clear_wakers(&self) {
        self.async_wakers.lock().clear();
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

    /// Wake the oldest waiter, if any. Also wakes all registered
    /// async wakers so futures re-poll.
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
        let wakers: Vec<Waker> = {
            let mut w = self.async_wakers.lock();
            core::mem::take(&mut *w)
        };
        for waker in wakers {
            waker.wake();
        }
    }

    /// Wake every waiter. Also wakes all registered async wakers.
    pub fn wake_all(&self) {
        let waiters = {
            let mut w = self.waiters.lock();
            core::mem::take(&mut *w)
        };
        for id in waiters {
            wake_task(id);
        }
        let wakers: Vec<Waker> = {
            let mut w = self.async_wakers.lock();
            core::mem::take(&mut *w)
        };
        for waker in wakers {
            waker.wake();
        }
    }

    /// Enqueue the current task in this wait queue **without** parking.
    ///
    /// Returns a [`PreparedWait`] token that the caller must consume by
    /// either [`PreparedWait::park`] (condition still unmet — safe to sleep)
    /// or [`PreparedWait::cancel`] (condition already met — leave the queue).
    ///
    /// # Why this exists
    ///
    /// The classic lost-wakeup race: a caller checks the condition (finds it
    /// unmet), is preempted, a waker fires on an *empty* wait queue and
    /// delivers no wake, then the caller enqueues and parks forever. By
    /// enqueueing **before** re-checking the condition, the waiter is
    /// guaranteed visible to wakers before it decides to sleep.
    ///
    /// Returns `None` if called before the scheduler is ready (early boot).
    pub fn prepare(&self) -> Option<PreparedWait<'_>> {
        let task = current_task_id()?;
        self.enqueue(task);
        Some(PreparedWait { task, queue: self })
    }
}

/// A prepared wait: the current task has been enqueued in a [`WaitQueue`] and
/// must be consumed by [`cancel`](Self::cancel) or [`park`](Self::park).
///
/// The lifetime `'a` ties this token to the wait queue; the queue cannot be
/// dropped while a prepared wait is outstanding.
pub struct PreparedWait<'a> {
    task: TaskId,
    queue: &'a WaitQueue,
}

impl<'a> PreparedWait<'a> {
    /// Cancel the wait: remove ourselves from the queue without sleeping.
    ///
    /// Use this when the re-check after [`WaitQueue::prepare`] found the
    /// condition already satisfied.
    pub fn cancel(self) {
        self.queue.remove(self.task);
    }

    /// Park the current task until woken. Returns when the scheduler delivers
    /// a wake (or spuriously). Caller **must** re-check the condition
    /// afterwards.
    ///
    /// The scheduler's `wake_pending` protocol ensures that a wake arriving
    /// between [`WaitQueue::prepare`] and this call is not lost.
    pub fn park(self) {
        park_current();
        self.queue.remove(self.task);
    }

    /// Park the current task until woken or until `timeout_ticks` scheduler
    /// ticks elapse. `timeout_ticks == 0` waits forever (same as [`park`]).
    pub fn park_timeout(self, timeout_ticks: u64) -> ParkResult {
        if timeout_ticks == 0 {
            self.park();
            return ParkResult::Woken;
        }
        let deadline = now_ticks().saturating_add(timeout_ticks);
        arm_timeout(self.task, deadline);
        park_current();
        cancel_timeout(self.task);
        self.queue.remove(self.task);
        if now_ticks() >= deadline {
            ParkResult::TimedOut
        } else {
            ParkResult::Woken
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
///
/// # Deprecation note
///
/// This helper has a lost-wakeup gap between the caller's condition check
/// and the internal enqueue. New code should use [`WaitQueue::prepare`]
/// followed by [`PreparedWait::park`] (or [`PreparedWait::cancel`]) so the
/// task is visible to wakers *before* it re-checks the condition. This
/// function is retained for callers that cannot use the prepare pattern.
#[doc(hidden)]
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
/// # Deprecation note
///
/// Same lost-wakeup concern as [`park_on`]. New code should use
/// [`WaitQueue::prepare`] followed by [`PreparedWait::park_timeout`].
#[doc(hidden)]
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

// ---------------------------------------------------------------------------
// Async Sleep future (tick-based deadline)
// ---------------------------------------------------------------------------

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// A zero-alloc, stack-pinned future that sleeps until a scheduler tick
/// deadline. The deadline is absolute (compared against monotonic ticks).
///
/// The future relies on the scheduler's timer callback calling
/// [`notify_tick`] which wakes timed-out tasks. On each poll, if the
/// deadline hasn't passed, it wakes itself to ensure re-poll on the
/// next tick.
pub struct Sleep {
    deadline: u64,
}

impl Sleep {
    /// Create a Sleep future with an absolute tick deadline.
    pub fn until(deadline: u64) -> Self {
        Self { deadline }
    }

    /// Create a Sleep future for `ticks` from now.
    pub fn for_ticks(ticks: u64) -> Self {
        Self {
            deadline: now_ticks().saturating_add(ticks),
        }
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if now_ticks() >= self.deadline {
            Poll::Ready(())
        } else {
            // Re-poll on next tick. Spurious wakeups are harmless.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
