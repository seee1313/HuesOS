//! Preemptive round-robin scheduler with real context switches, including
//! switching page tables (CR3) and the kernel stack used for interrupts /
//! syscalls (TSS.RSP0) when hopping between kernel and userspace tasks.
//!
//! SMP-aware: each CPU has its own scheduler instance accessed via LAPIC ID.
//! Protected by spinlocks to prevent cross-core race conditions.
//! Task structures are individually heap-allocated (Boxed) to guarantee
//! stable memory addresses and prevent dangling pointers during resizes.
//!
//! Advanced Scheduling Modes:
//! 1. Fair Scheduling (Default out of the box):
//!    - CFS-like scheduling sorted by virtual completion time (vruntime).
//!    - Tasks stored in a custom balanced WAVL-tree.
//!    - Higher weight tasks grow vruntime slower and get proportionally more CPU time.
//! 2. Deadline Scheduling:
//!    - Guaranteed CPU time (capacity) per period.
//!    - High priority: always executed before any Fair tasks.
//!    - Multi-task deadline scheduled via Earliest Deadline First (EDF).

#[path = "scheduler/wavl.rs"]
pub mod wavl;

use crate::task::{Task, TaskKind};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use huesos_object::{KernelObject, Process};
use x86_64::VirtAddr;

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 64;

/// Bitmask of CPUs that have finished scheduler init and may receive tasks.
/// Bit N set => CPU with LAPIC-id N is online for load-balancing.
static ONLINE_CPUS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Hardware-timer-driven monotonic clock. Only CPU 0 advances it, so SMP does
/// not make time run faster. Cooperative yields never affect this clock.
static MONOTONIC_TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Mark the current CPU as online for task placement.
pub fn mark_cpu_online() {
    let id = cpu_id();
    if id < 64 {
        ONLINE_CPUS.fetch_or(1u64 << id, Ordering::SeqCst);
    }
}

/// True if the given LAPIC id has a live scheduler ready for work.
pub fn is_cpu_online(cpu: usize) -> bool {
    if cpu >= 64 {
        return false;
    }
    (ONLINE_CPUS.load(Ordering::SeqCst) & (1u64 << cpu)) != 0
}

/// Saved CPU context for a task.
pub type SchedContext = huesos_arch::context_switch::Context;

/// Scheduling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPolicy {
    /// Fair (CFS-like) scheduling.
    Fair {
        /// Task weight (nice level equivalent).
        weight: u64,
        /// Virtual runtime in tick-scaling.
        vruntime: u64,
    },
    /// Deadline real-time scheduling.
    Deadline {
        /// Execution capacity in ticks per period.
        capacity: u64,
        /// Period in ticks.
        period: u64,
        /// Remaining budget in current period.
        remaining_budget: u64,
        /// Absolute tick when current period ends.
        deadline: u64,
    },
}

static PER_CPU_SCHEDULERS: [spin::Mutex<Scheduler>; MAX_CPUS] =
    [const { spin::Mutex::new(Scheduler::new()) }; MAX_CPUS];

struct Scheduler {
    // Box keeps Context addresses stable while other tasks are appended and
    // the Vec reallocates during a suspended context switch.
    #[allow(clippy::vec_box)]
    tasks: Vec<Box<Task>>,
    current: usize,
    fair_queue: wavl::WavlTree,
    ticks: u64,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            tasks: Vec::new(),
            current: 0,
            fair_queue: wavl::WavlTree::new(),
            ticks: 0,
        }
    }

    fn add_task(&mut self, task: Task) -> u64 {
        let id = task.id;
        let idx = self.tasks.len();
        let policy = task.sched_policy;
        self.tasks.push(Box::new(task));
        if idx > 0 {
            if let SchedPolicy::Fair { vruntime, .. } = policy {
                self.fair_queue.insert(vruntime, id);
            }
        }
        id
    }

    fn apply_task_environment(&self, idx: usize) {
        let task = &self.tasks[idx];
        let stack_top = task.kernel_stack_top();
        if stack_top != 0 {
            huesos_arch::gdt::set_kernel_stack(VirtAddr::new(stack_top));
            huesos_arch::syscall::set_kernel_stack(stack_top);
        }
        if let TaskKind::User { process } = &task.kind {
            huesos_object::set_current_process(Arc::clone(process));
        }
    }

    fn tick(&mut self) -> Option<(*mut SchedContext, *const SchedContext)> {
        self.ticks += 1;

        // 1. Release Deadline tasks whose period has ended
        for idx in 1..self.tasks.len() {
            let t = &mut self.tasks[idx];
            if t.finished.load(Ordering::Relaxed) {
                continue;
            }
            if let SchedPolicy::Deadline {
                capacity,
                period,
                remaining_budget,
                deadline,
            } = &mut t.sched_policy
            {
                if self.ticks >= *deadline {
                    *deadline = self.ticks + *period;
                    *remaining_budget = *capacity;
                }
            }
        }

        // 2. Update stats for currently running task
        if self.current > 0 {
            let task_id = self.tasks[self.current].id;
            let finished = self.tasks[self.current].finished.load(Ordering::Relaxed);
            let blocked = self.tasks[self.current].blocked.load(Ordering::Relaxed);

            match &mut self.tasks[self.current].sched_policy {
                SchedPolicy::Fair { weight, vruntime } => {
                    let delta = (1024 * 1000) / (*weight).max(1);
                    *vruntime += delta;
                    if !finished && !blocked {
                        self.fair_queue.insert(*vruntime, task_id);
                    }
                }
                SchedPolicy::Deadline {
                    remaining_budget, ..
                } => {
                    *remaining_budget = remaining_budget.saturating_sub(1);
                }
            }
        }

        // 3. Pick the next task to run
        let mut next_idx = 0;

        // Try Deadline tasks first (Earliest Deadline First)
        let mut best_deadline = u64::MAX;
        for idx in 1..self.tasks.len() {
            let t = &self.tasks[idx];
            if t.finished.load(Ordering::Relaxed) || t.blocked.load(Ordering::Relaxed) {
                continue;
            }
            if let SchedPolicy::Deadline {
                remaining_budget,
                deadline,
                ..
            } = t.sched_policy
            {
                if remaining_budget > 0 && deadline < best_deadline {
                    best_deadline = deadline;
                    next_idx = idx;
                }
            }
        }

        // If no Deadline task is ready, schedule from Fair queue.
        // Skip tasks that finished or are blocked (parked on a wait queue).
        if next_idx == 0 {
            while let Some(task_id) = self.fair_queue.pop_min() {
                let idx = (task_id & 0xFFFFFFFF) as usize;
                if let Some(task) = self.tasks.get(idx) {
                    if task.finished.load(Ordering::Relaxed) || task.blocked.load(Ordering::Relaxed)
                    {
                        continue;
                    }
                    next_idx = idx;
                    break;
                }
            }
        }

        let old_index = self.current;
        if next_idx == old_index {
            // Keep running the same task
            return None;
        }

        self.current = next_idx;
        self.apply_task_environment(self.current);

        let old_ptr = &raw mut self.tasks[old_index].context;
        let new_ptr = &raw const self.tasks[self.current].context;

        Some((old_ptr, new_ptr))
    }

    fn current_task(&self) -> Option<&Task> {
        self.tasks.get(self.current).map(|t| &**t)
    }
}

/// Return the LAPIC ID of the current CPU via GS_BASE, clamped to MAX_CPUS.
fn cpu_id() -> usize {
    (unsafe { huesos_arch::cpu_local::current_lapic_id() } as usize).min(MAX_CPUS - 1)
}

/// Register the current CPU's scheduler pointer in its `CpuLocal`.
///
/// # Safety
/// Must be called once per CPU after `cpu_local::init_gs_base`.
unsafe fn register_scheduler_ptr(sched: *mut Scheduler) {
    let ptr = huesos_arch::cpu_local::cpu_local_ptr();
    unsafe { (*ptr).scheduler = sched as *mut () };
}

/// Initialize the scheduler for the current CPU and register the timer callback.
/// Called once per CPU.
pub fn init() {
    let cpu = cpu_id();
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    unsafe { register_scheduler_ptr(&mut *guard) };
    guard.add_task(Task::new_idle(
        0,
        *b"idle\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    ));
    drop(guard);

    huesos_arch::timer_callback::set_timer_callback(&|| {
        huesos_arch::interrupts::disable();
        let cpu = cpu_id();
        if cpu == 0 {
            MONOTONIC_TICKS.fetch_add(1, Ordering::SeqCst);
        }
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        let switch_context = guard.tick();
        drop(guard); // Release the lock before performing context switch!

        // Wake any waiters whose timeout expired against hardware time.
        huesos_object::wait::notify_tick(MONOTONIC_TICKS.load(Ordering::SeqCst));

        if let Some((old_ptr, new_ptr)) = switch_context {
            // Safety: interrupts are disabled; pointers point to active Vec
            unsafe {
                huesos_arch::context_switch::context_switch(old_ptr, new_ptr);
            }
        }
        huesos_arch::interrupts::enable();
    });

    mark_cpu_online();
}

/// Yield the current task (cooperative).
pub fn yield_now() {
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    let switch_context = guard.tick();
    drop(guard); // Release the lock before performing context switch!

    if let Some((old_ptr, new_ptr)) = switch_context {
        unsafe {
            huesos_arch::context_switch::context_switch(old_ptr, new_ptr);
        }
    }
    huesos_arch::interrupts::enable();
}

/// Park the current task on a wait queue: mark blocked, drop from the
/// runqueue, and switch away. Returns when [`wake_task`] has cleared
/// `blocked` and requeued the task.
pub fn park_current() {
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    {
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        let idx = guard.current;
        if let Some(task) = guard.tasks.get_mut(idx) {
            task.blocked.store(true, Ordering::SeqCst);
            if let SchedPolicy::Fair { vruntime, .. } = task.sched_policy {
                let id = task.id;
                guard.fair_queue.remove(vruntime, id);
            }
        }
        // Prefer tick(); if it declines to switch (edge case), force idle.
        let switch_context = guard.tick().or_else(|| {
            if guard.current == 0 || guard.tasks.len() <= 1 {
                return None;
            }
            let old = guard.current;
            guard.current = 0;
            guard.apply_task_environment(0);
            let old_ptr = &raw mut guard.tasks[old].context;
            let new_ptr = &raw const guard.tasks[0].context;
            Some((old_ptr, new_ptr))
        });
        drop(guard);
        if let Some((old_ptr, new_ptr)) = switch_context {
            unsafe {
                huesos_arch::context_switch::context_switch(old_ptr, new_ptr);
            }
        }
    }
    huesos_arch::interrupts::enable();
}

/// Wake a previously parked task. Safe to call from IRQ context (port queue).
///
/// Always clears `blocked` and ensures the task is on the fair runqueue.
/// This closes the lost-wakeup race where `wake` arrived after enqueue but
/// before `park_current` set `blocked=true` (swap would early-return and the
/// subsequent park would sleep forever).
pub fn wake_task(task_id: u64) {
    let cpu = (task_id >> 32) as usize;
    if cpu >= MAX_CPUS {
        return;
    }
    let idx = (task_id & 0xFFFF_FFFF) as usize;
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    let Some(task) = guard.tasks.get_mut(idx) else {
        return;
    };
    if task.finished.load(Ordering::Relaxed) {
        task.blocked.store(false, Ordering::SeqCst);
        return;
    }
    task.blocked.store(false, Ordering::SeqCst);
    if let SchedPolicy::Fair { vruntime, .. } = task.sched_policy {
        // insert is idempotent enough if we remove first (wavl may allow dup — remove first)
        let id = task.id;
        let vr = vruntime;
        guard.fair_queue.remove(vr, id);
        guard.fair_queue.insert(vr, id);
    }
    drop(guard);
    if cpu != cpu_id() {
        huesos_arch::lapic::ipi_reschedule(cpu as u8);
    }
}

/// Get current task id for debugging.
pub fn current_task_id() -> Option<u64> {
    let guard = PER_CPU_SCHEDULERS[cpu_id()].lock();
    guard.current_task().map(|t| t.id)
}

/// Monotonic BSP-ish tick counter for wait timeouts (sum of local ticks is
/// fine; we use the current CPU's scheduler ticks).
pub fn global_ticks() -> u64 {
    MONOTONIC_TICKS.load(Ordering::SeqCst)
}

/// Find the best CPU to spawn a task on (online CPU with fewest tasks).
fn find_best_cpu() -> usize {
    let mut best_cpu = cpu_id();
    let mut min_tasks = usize::MAX;
    let mask = ONLINE_CPUS.load(Ordering::SeqCst);

    for (i, scheduler) in PER_CPU_SCHEDULERS.iter().enumerate() {
        if (mask & (1u64 << i)) == 0 {
            continue;
        }
        let guard = scheduler.lock();
        let count = guard.tasks.len();
        // Prefer the least-loaded online CPU that already has at least an idle task.
        if count >= 1 && count < min_tasks {
            min_tasks = count;
            best_cpu = i;
        }
    }
    best_cpu
}

/// Set the scheduling policy for a task by its ID.
pub fn set_sched_policy(task_id: u64, policy: SchedPolicy) {
    huesos_arch::interrupts::disable();
    let cpu = (task_id >> 32) as usize;
    let idx = (task_id & 0xFFFFFFFF) as usize;
    if cpu < MAX_CPUS {
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();

        let mut old_policy = None;
        if let Some(task) = guard.tasks.get(idx) {
            old_policy = Some(task.sched_policy);
        }

        if let Some(SchedPolicy::Fair { vruntime, .. }) = old_policy {
            guard.fair_queue.remove(vruntime, task_id);
        }

        if let Some(task) = guard.tasks.get_mut(idx) {
            task.sched_policy = policy;
        }

        if let SchedPolicy::Fair { vruntime, .. } = policy {
            guard.fair_queue.insert(vruntime, task_id);
        }
    }
    huesos_arch::interrupts::enable();
}

/// Spawn a new kernel thread.
pub fn spawn_kernel_thread(name: &[u8; 32], entry: extern "C" fn() -> !) -> u64 {
    huesos_arch::interrupts::disable();
    let cpu = find_best_cpu();
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    let id = ((cpu as u64) << 32) | (guard.tasks.len() as u64);
    let task = Task::new_kernel(id, *name, entry);
    guard.add_task(task);
    drop(guard);
    huesos_arch::interrupts::enable();

    if cpu != cpu_id() {
        huesos_arch::lapic::ipi_reschedule(cpu as u8);
    }
    id
}

/// Spawn a new userspace task bound to `process`, whose first execution
/// will jump to ring3 via `entry_trampoline`.
pub fn spawn_user_thread(
    name: &[u8; 32],
    process: Arc<Process>,
    entry_point: u64,
    user_rsp: u64,
    cr3: u64,
) -> u64 {
    huesos_arch::interrupts::disable();
    // Prefer the caller's CPU for userspace launches. Early boot services
    // spawned by init must not be stranded on an AP that is still settling
    // under QEMU TCG (missing ready handshake). Kernel threads may still
    // use find_best_cpu for load balance.
    let cpu = cpu_id();
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    let id = ((cpu as u64) << 32) | (guard.tasks.len() as u64);
    crate::process::queue_user_entry(id, entry_point, user_rsp);
    let task = Task::new_user(
        id,
        *name,
        process,
        crate::process::user_entry_trampoline,
        cr3,
    );
    guard.add_task(task);
    drop(guard);
    huesos_arch::interrupts::enable();

    if cpu != cpu_id() {
        huesos_arch::lapic::ipi_reschedule(cpu as u8);
    }
    id
}

/// Mark the currently running task as finished (won't be scheduled again)
/// and switch away from it. Never returns.
pub fn exit_current_task(code: i64) -> ! {
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    let mut process_to_signal: Option<alloc::sync::Arc<huesos_object::Process>> = None;
    let mut reap_id: Option<u64> = None;
    {
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        let current_idx = guard.current;
        if let Some(task) = guard.tasks.get_mut(current_idx) {
            task.finished.store(true, Ordering::Relaxed);
            task.blocked.store(false, Ordering::Relaxed);
            reap_id = Some(task.id);
            if let crate::task::TaskKind::User { process } = &task.kind {
                process_to_signal = Some(alloc::sync::Arc::clone(process));
            }
            if let SchedPolicy::Fair { vruntime, .. } = task.sched_policy {
                let id = task.id;
                guard.fair_queue.remove(vruntime, id);
            }
        }
    }
    if let Some(proc) = process_to_signal {
        proc.set_exit_code(code);
        PROCESS_TEARDOWN.lock().push(proc);
    }
    if let Some(id) = reap_id {
        REAP_QUEUE.lock().push(id);
    }
    loop {
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        let switch_context = guard.tick();
        drop(guard);

        if let Some((old_ptr, new_ptr)) = switch_context {
            unsafe {
                huesos_arch::context_switch::context_switch(old_ptr, new_ptr);
            }
        }
        huesos_arch::interrupts::enable();
        huesos_arch::hlt();
        huesos_arch::interrupts::disable();
    }
}

/// Terminate every thread belonging to the current userspace process and
/// switch away from the faulting thread. This is used for unhandled ring-3
/// exceptions: continuing sibling threads in a potentially corrupted address
/// space would violate process isolation.
pub fn terminate_current_process(code: i64) -> ! {
    huesos_arch::interrupts::disable();
    let current_cpu = cpu_id();
    let process = {
        let guard = PER_CPU_SCHEDULERS[current_cpu].lock();
        guard.current_task().and_then(|task| match &task.kind {
            TaskKind::User { process } => Some(Arc::clone(process)),
            TaskKind::Kernel => None,
        })
    };

    let Some(process) = process else {
        panic!("terminate_current_process called without a userspace process");
    };
    process.set_exit_code(code);
    let process_koid = process.koid();

    for scheduler in &PER_CPU_SCHEDULERS {
        let mut guard = scheduler.lock();
        for idx in 0..guard.tasks.len() {
            let matched = match &guard.tasks[idx].kind {
                TaskKind::User { process } => process.koid() == process_koid,
                TaskKind::Kernel => false,
            };
            if !matched {
                continue;
            }
            let (id, fair_key) = {
                let task = &mut guard.tasks[idx];
                task.finished.store(true, Ordering::SeqCst);
                task.blocked.store(false, Ordering::SeqCst);
                let fair_key = match task.sched_policy {
                    SchedPolicy::Fair { vruntime, .. } => Some(vruntime),
                    SchedPolicy::Deadline { .. } => None,
                };
                (task.id, fair_key)
            };
            if let Some(vruntime) = fair_key {
                guard.fair_queue.remove(vruntime, id);
            }
            REAP_QUEUE.lock().push(id);
        }
    }

    PROCESS_TEARDOWN.lock().push(Arc::clone(&process));
    for cpu in 0..MAX_CPUS {
        if cpu != current_cpu && is_cpu_online(cpu) {
            huesos_arch::lapic::ipi_reschedule(cpu as u8);
        }
    }

    switch_away_from_finished(current_cpu)
}

fn switch_away_from_finished(cpu: usize) -> ! {
    loop {
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        let switch_context = guard.tick();
        drop(guard);

        if let Some((old_ptr, new_ptr)) = switch_context {
            unsafe {
                huesos_arch::context_switch::context_switch(old_ptr, new_ptr);
            }
        }
        huesos_arch::interrupts::enable();
        huesos_arch::hlt();
        huesos_arch::interrupts::disable();
    }
}

/// Task ids waiting for kernel-stack reclamation.
static REAP_QUEUE: spin::Mutex<alloc::vec::Vec<u64>> = spin::Mutex::new(alloc::vec::Vec::new());

/// Processes waiting for address-space / handle-table teardown.
static PROCESS_TEARDOWN: spin::Mutex<alloc::vec::Vec<alloc::sync::Arc<huesos_object::Process>>> =
    spin::Mutex::new(alloc::vec::Vec::new());

/// Drain finished tasks' kernel stacks (frames stay until process Arc drops).
/// Safe to call from a low-priority path; currently invoked from the BSP
/// idle loop opportunistically.
pub fn reap_finished_tasks() {
    let batch = {
        let mut q = REAP_QUEUE.lock();
        core::mem::take(&mut *q)
    };
    for task_id in batch {
        let cpu = (task_id >> 32) as usize;
        let idx = (task_id & 0xFFFF_FFFF) as usize;
        if cpu >= MAX_CPUS {
            continue;
        }
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        // Never reap the currently running task (shouldn't be queued).
        if guard.current == idx {
            REAP_QUEUE.lock().push(task_id);
            continue;
        }
        if let Some(task) = guard.tasks.get_mut(idx) {
            if task.finished.load(Ordering::Relaxed) && !task.kernel_stack.is_empty() {
                // Free the kernel stack Vec's heap allocation.
                task.kernel_stack = alloc::vec::Vec::new();
            }
        }
    }

    // Tear down exited processes (page tables, owned frames, handles).
    let procs = {
        let mut q = PROCESS_TEARDOWN.lock();
        core::mem::take(&mut *q)
    };
    for proc in procs {
        let koid = proc.koid();
        let still_current = (0..MAX_CPUS).any(|cpu| {
            let guard = PER_CPU_SCHEDULERS[cpu].lock();
            guard.current_task().is_some_and(|task| match &task.kind {
                TaskKind::User { process } => process.koid() == koid,
                TaskKind::Kernel => false,
            })
        });
        if still_current {
            // A remote CPU has not yet taken its reschedule IPI. Never destroy
            // page tables while that CPU can still have the process CR3 live.
            PROCESS_TEARDOWN.lock().push(proc);
        } else {
            crate::process::teardown_process(&proc);
        }
    }
}
