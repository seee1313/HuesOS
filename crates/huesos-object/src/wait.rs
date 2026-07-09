//! Lightweight wait queues for blocking syscalls.
//!
//! Waiters are identified by scheduler task ids (`u64`). The kernel injects
//! `park` / `wake` / `current_task` callbacks so this crate stays free of a
//! dependency on `huesos-kernel` / `huesos-arch`.

use alloc::vec::Vec;
use spin::Mutex;

/// Scheduler task identifier (matches `Task::id`).
pub type TaskId = u64;

static CURRENT_TASK_FN: Mutex<Option<fn() -> Option<TaskId>>> = Mutex::new(None);
static PARK_FN: Mutex<Option<fn()>> = Mutex::new(None);
static WAKE_FN: Mutex<Option<fn(TaskId)>> = Mutex::new(None);

/// Register scheduler hooks. Called once from kernel init after the
/// scheduler exists.
pub fn set_scheduler_hooks(
    current_task: fn() -> Option<TaskId>,
    park: fn(),
    wake: fn(TaskId),
) {
    *CURRENT_TASK_FN.lock() = Some(current_task);
    *PARK_FN.lock() = Some(park);
    *WAKE_FN.lock() = Some(wake);
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
        if !w.iter().any(|&t| t == task) {
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
        // No scheduler context (early boot / host tests): spin briefly.
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
        return;
    };
    queue.enqueue(task);
    park_current();
    queue.remove(task);
}
